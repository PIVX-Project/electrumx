# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Classes for local RPC server and remote client TCP/SSL servers.'''

import codecs
import itertools
import time
from functools import partial

from aiorpcx import ServerSession, JSONRPCAutoDetect, RPCError, JSONRPC

from lib.hash import sha256, hash_to_str
import lib.util as util
from server.daemon import DaemonError

BAD_REQUEST = 1
DAEMON_ERROR = 2
PIVX_SAPLING_MAX_BLOCK_RANGE = 100
PIVX_SAPLING_RPC_CONTRACT = 'pivx.sapling.electrumx.v1'


class Semaphores(object):

    def __init__(self, semaphores):
        self.semaphores = semaphores
        self.acquired = []

    async def __aenter__(self):
        for semaphore in self.semaphores:
            await semaphore.acquire()
            self.acquired.append(semaphore)

    async def __aexit__(self, exc_type, exc_value, traceback):
        for semaphore in self.acquired:
            semaphore.release()


class SessionBase(ServerSession):
    '''Base class of ElectrumX JSON sessions.

    Each session runs its tasks in asynchronous parallelism with other
    sessions.
    '''

    MAX_CHUNK_SIZE = 2016
    session_counter = itertools.count()

    def __init__(self, controller, kind):
        super().__init__(rpc_protocol=JSONRPCAutoDetect)
        self.kind = kind  # 'RPC', 'TCP' etc.
        self.controller = controller
        self.bp = controller.bp
        self.env = controller.env
        self.daemon = self.bp.daemon
        self.client = 'unknown'
        self.client_version = (1, )
        self.anon_logs = self.env.anon_logs
        self.txs_sent = 0
        self.log_me = False
        self.bw_limit = self.env.bandwidth_limit
        self._orig_mr = self.rpc.message_received

    def peer_address_str(self, *, for_log=True):
        '''Returns the peer's IP address and port as a human-readable
        string, respecting anon logs if the output is for a log.'''
        if for_log and self.anon_logs:
            return 'xx.xx.xx.xx:xx'
        return super().peer_address_str()

    def message_received(self, message):
        self.logger.info(f'processing {message}')
        self._orig_mr(message)

    def toggle_logging(self):
        self.log_me = not self.log_me
        if self.log_me:
            self.rpc.message_received = self.message_received
        else:
            self.rpc.message_received = self._orig_mr

    def flags(self):
        '''Status flags.'''
        status = self.kind[0]
        if self.is_closing():
            status += 'C'
        if self.log_me:
            status += 'L'
        status += str(self.concurrency.max_concurrent)
        return status

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        super().connection_made(transport)
        self.session_id = next(self.session_counter)
        context = {'conn_id': f'{self.session_id}'}
        self.logger = util.ConnectionLogger(self.logger, context)
        self.rpc.logger = self.logger
        self.group = self.controller.add_session(self)
        self.logger.info(f'{self.kind} {self.peer_address_str()}, '
                         f'{len(self.controller.sessions):,d} total')

    def connection_lost(self, exc):
        '''Handle client disconnection.'''
        super().connection_lost(exc)
        self.controller.remove_session(self)
        msg = ''
        if self.paused:
            msg += ' whilst paused'
        if self.concurrency.max_concurrent != self.max_concurrent:
            msg += ' whilst throttled'
        if self.send_size >= 1024*1024:
            msg += ('.  Sent {:,d} bytes in {:,d} messages'
                    .format(self.send_size, self.send_count))
        if msg:
            msg = 'disconnected' + msg
            self.logger.info(msg)

    def count_pending_items(self):
        return self.rpc.pending_requests

    def semaphore(self):
        return Semaphores([self.concurrency.semaphore, self.group.semaphore])

    def sub_count(self):
        return 0


class ElectrumX(SessionBase):
    '''A TCP server that handles incoming Electrum connections.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subscribe_headers = False
        self.subscribe_headers_raw = False
        self.subscribe_height = False
        self.notified_height = None
        self.max_response_size = self.env.max_send
        self.max_subs = self.env.max_session_subs
        self.hashX_subs = {}
        self.mempool_statuses = {}
        self.protocol_version = None
        self.set_protocol_handlers((1, 0))

    def sub_count(self):
        return len(self.hashX_subs)

    async def notify_async(self, our_touched):
        changed = {}

        for hashX in our_touched:
            alias = self.hashX_subs[hashX]
            status = await self.address_status(hashX)
            changed[alias] = status

        # Check mempool hashXs - the status is a function of the
        # confirmed state of other transactions.  Note: we cannot
        # iterate over mempool_statuses as it changes size.
        for hashX in set(self.mempool_statuses):
            old_status = self.mempool_statuses[hashX]
            status = await self.address_status(hashX)
            if status != old_status:
                alias = self.hashX_subs[hashX]
                changed[alias] = status

        for alias, status in changed.items():
            if len(alias) == 64:
                method = 'blockchain.scripthash.subscribe'
            else:
                method = 'blockchain.address.subscribe'
            self.send_notification(method, (alias, status))

        if changed:
            es = '' if len(changed) == 1 else 'es'
            self.logger.info('notified of {:,d} address{}'
                             .format(len(changed), es))

    def notify(self, height, touched):
        '''Notify the client about changes to touched addresses (from mempool
        updates or new blocks) and height.

        Return the set of addresses the session needs to be
        asyncronously notified about.  This can be empty if there are
        possible mempool status updates.

        Returns None if nothing needs to be notified asynchronously.
        '''
        height_changed = height != self.notified_height
        if height_changed:
            self.notified_height = height
            if self.subscribe_headers:
                args = (self.subscribe_headers_result(height), )
                self.send_notification('blockchain.headers.subscribe', args)
            if self.subscribe_height:
                args = (height, )
                self.send_notification('blockchain.numblocks.subscribe', args)

        our_touched = touched.intersection(self.hashX_subs)
        if our_touched or (height_changed and self.mempool_statuses):
            return our_touched

        return None

    def height(self):
        '''Return the current flushed database height.'''
        return self.bp.db_height

    def assert_boolean(self, value):
        '''Return param value it is boolean otherwise raise an RPCError.'''
        if value in (False, True):
            return value
        raise RPCError(BAD_REQUEST, f'{value} should be a boolean value')

    def subscribe_headers_result(self, height):
        '''The result of a header subscription for the given height.'''
        if self.subscribe_headers_raw:
            raw_header = self.controller.raw_header(height)
            return {'hex': raw_header.hex(), 'height': height}
        return self.controller.electrum_header(height)

    def headers_subscribe(self, raw=False):
        '''Subscribe to get headers of new blocks.'''
        self.subscribe_headers = True
        self.subscribe_headers_raw = self.assert_boolean(raw)
        self.notified_height = self.height()
        return self.subscribe_headers_result(self.height())

    def numblocks_subscribe(self):
        '''Subscribe to get height of new blocks.'''
        self.subscribe_height = True
        return self.height()

    async def add_peer(self, features):
        '''Add a peer (but only if the peer resolves to the source).'''
        peer_mgr = self.controller.peer_mgr
        return await peer_mgr.on_add_peer(features, self.peer_address())

    def peers_subscribe(self):
        '''Return the server peers as a list of (ip, host, details) tuples.'''
        return self.controller.peer_mgr.on_peers_subscribe(self.is_tor())

    async def address_status(self, hashX):
        '''Returns an address status.

        Status is a hex string, but must be None if there is no history.
        '''
        # Note history is ordered and mempool unordered in electrum-server
        # For mempool, height is -1 if unconfirmed txins, otherwise 0
        history = await self.controller.get_history(hashX)
        mempool = await self.controller.mempool_transactions(hashX)

        status = ''.join('{}:{:d}:'.format(hash_to_str(tx_hash), height)
                         for tx_hash, height in history)
        status += ''.join('{}:{:d}:'.format(hex_hash, -unconfirmed)
                          for hex_hash, tx_fee, unconfirmed in mempool)
        if status:
            status = sha256(status.encode()).hex()
        else:
            status = None

        if mempool:
            self.mempool_statuses[hashX] = status
        else:
            self.mempool_statuses.pop(hashX, None)

        return status

    async def hashX_subscribe(self, hashX, alias):
        # First check our limit.
        if len(self.hashX_subs) >= self.max_subs:
            raise RPCError(BAD_REQUEST, 'your address subscription limit '
                           f'{self.max_subs:,d} reached')

        # Now let the controller check its limit
        self.controller.new_subscription()
        self.hashX_subs[hashX] = alias
        return await self.address_status(hashX)

    async def address_subscribe(self, address):
        '''Subscribe to an address.

        address: the address to subscribe to'''
        hashX = self.controller.address_to_hashX(address)
        return await self.hashX_subscribe(hashX, address)

    async def scripthash_subscribe(self, scripthash):
        '''Subscribe to a script hash.

        scripthash: the SHA256 hash of the script to subscribe to'''
        hashX = self.controller.scripthash_to_hashX(scripthash)
        return await self.hashX_subscribe(hashX, scripthash)

    def block_headers(self, start_height, count):
        '''Return count concatenated block headers as hex for the main chain;
        starting at start_height.

        start_height and count must be non-negative integers.  At most
        MAX_CHUNK_SIZE headers will be returned.
        '''
        start_height = self.controller.non_negative_integer(start_height)
        count = self.controller.non_negative_integer(count)
        count = min(count, self.MAX_CHUNK_SIZE)
        hex_str, n =  self.controller.block_headers(start_height, count)
        return {'hex': hex_str, 'count': n, 'max': self.MAX_CHUNK_SIZE}

    def block_get_chunk(self, index):
        '''Return a chunk of block headers as a hexadecimal string.

        index: the chunk index'''
        index = self.controller.non_negative_integer(index)
        chunk_size = self.controller.coin.CHUNK_SIZE
        start_height = index * chunk_size
        hex_str, n =  self.controller.block_headers(start_height, chunk_size)
        return hex_str

    def is_tor(self):
        '''Try to detect if the connection is to a tor hidden service we are
        running.'''
        peername = self.controller.peer_mgr.proxy_peername()
        if not peername:
            return False
        peer_address = self.peer_address()
        return peer_address and peer_address[0] == peername[0]

    async def replaced_banner(self, banner):
        network_info = await self.controller.daemon_request('getnetworkinfo')
        ni_version = network_info['version']
        major, minor = divmod(ni_version, 1000000)
        minor, revision = divmod(minor, 10000)
        revision //= 100
        daemon_version = '{:d}.{:d}.{:d}'.format(major, minor, revision)
        for pair in [
                ('$SERVER_VERSION', self.controller.short_version()),
                ('$SERVER_SUBVERSION', self.controller.VERSION),
                ('$DAEMON_VERSION', daemon_version),
                ('$DAEMON_SUBVERSION', network_info['subversion']),
                ('$DONATION_ADDRESS', self.env.donation_address),
        ]:
            banner = banner.replace(*pair)
        return banner

    def donation_address(self):
        '''Return the donation address as a string, empty if there is none.'''
        return self.env.donation_address

    async def banner(self):
        '''Return the server banner text.'''
        banner = 'Welcome to Electrum!'

        if self.is_tor():
            banner_file = self.env.tor_banner_file
        else:
            banner_file = self.env.banner_file
        if banner_file:
            try:
                with codecs.open(banner_file, 'r', 'utf-8') as f:
                    banner = f.read()
            except Exception as e:
                self.loggererror(f'reading banner file {banner_file}: {e}')
            else:
                banner = await self.replaced_banner(banner)

        return banner

    def ping(self):
        '''Serves as a connection keep-alive mechanism and for the client to
        confirm the server is still responding.
        '''
        return None

    def server_version(self, client_name=None, protocol_version=None):
        '''Returns the server version as a string.

        client_name: a string identifying the client
        protocol_version: the protocol version spoken by the client
        '''
        if client_name:
            if self.env.drop_client is not None and \
                    self.env.drop_client.match(client_name):
                self.close_after_send = True
                raise RPCError(BAD_REQUEST,
                               f'unsupported client: {client_name}')
            self.client = str(client_name)[:17]
            try:
                self.client_version = tuple(int(part) for part
                                            in self.client.split('.'))
            except Exception:
                pass

        # Find the highest common protocol version.  Disconnect if
        # that protocol version in unsupported.
        ptuple = self.controller.protocol_tuple(protocol_version)

        # From protocol version 1.1, protocol_version cannot be omitted
        if ptuple is None or (ptuple >= (1, 1) and protocol_version is None):
            self.logger.info('unsupported protocol version request {}'
                             .format(protocol_version))
            self.close_after_send = True
            raise RPCError(BAD_REQUEST,
                           f'unsupported protocol version: {protocol_version}')

        self.set_protocol_handlers(ptuple)

        # The return value depends on the protocol version
        if ptuple < (1, 1):
            return self.controller.VERSION
        else:
            return (self.controller.VERSION, self.protocol_version)

    async def transaction_broadcast(self, raw_tx):
        '''Broadcast a raw transaction to the network.

        raw_tx: the raw transaction as a hexadecimal string'''
        # This returns errors as JSON RPC errors, as is natural
        try:
            tx_hash = await self.daemon.sendrawtransaction([raw_tx])
            self.txs_sent += 1
            self.logger.info('sent tx: {}'.format(tx_hash))
            self.controller.sent_tx(tx_hash)
            return tx_hash
        except DaemonError as e:
            error, = e.args
            message = error['message']
            self.logger.info('sendrawtransaction: {}'.format(message))
            raise RPCError(BAD_REQUEST, 'the transaction was rejected by '
                           f'network rules.\n\n{message}\n[{raw_tx}]')

    async def transaction_broadcast_1_0(self, raw_tx):
        '''Broadcast a raw transaction to the network.

        raw_tx: the raw transaction as a hexadecimal string'''
        # An ugly API: current Electrum clients only pass the raw
        # transaction in hex and expect error messages to be returned in
        # the result field.  And the server shouldn't be doing the client's
        # user interface job here.
        try:
            return await self.transaction_broadcast(raw_tx)
        except RPCError as e:
            message = e.message
            if 'non-mandatory-script-verify-flag' in message:
                message = (
                    'Your client produced a transaction that is not accepted '
                    'by the network any more.  Please upgrade to Electrum '
                    '2.5.1 or newer.'
                )

            return message

    def set_protocol_handlers(self, ptuple):
        protocol_version = '.'.join(str(part) for part in ptuple)
        if protocol_version == self.protocol_version:
            return
        self.protocol_version = protocol_version

        controller = self.controller
        handlers = {
            'blockchain.address.get_balance': controller.address_get_balance,
            'blockchain.address.get_history': controller.address_get_history,
            'blockchain.address.get_mempool': controller.address_get_mempool,
            'blockchain.address.listunspent': controller.address_listunspent,
            'blockchain.address.subscribe': self.address_subscribe,
            'blockchain.block.get_chunk': self.block_get_chunk,
            'blockchain.block.get_header': controller.block_get_header,
            'blockchain.estimatefee': controller.estimatefee,
            'blockchain.headers.subscribe': self.headers_subscribe,
            'blockchain.relayfee': controller.relayfee,
            'blockchain.transaction.get_merkle':
            controller.transaction_get_merkle,
            'server.add_peer': self.add_peer,
            'server.banner': self.banner,
            'server.donation_address': self.donation_address,
            'server.features': self.controller.server_features,
            'server.peers.subscribe': self.peers_subscribe,
            'server.version': self.server_version,
        }

        if ptuple < (1, 1):
            # Methods or semantics unique to 1.0 and earlier protocols
            handlers.update({
                'blockchain.numblocks.subscribe': self.numblocks_subscribe,
                'blockchain.utxo.get_address': controller.utxo_get_address,
                'blockchain.transaction.broadcast':
                self.transaction_broadcast_1_0,
                'blockchain.transaction.get': controller.transaction_get_1_0,
            })

        if ptuple >= (1, 1):
            # New handlers as of 1.1, or different semantics
            handlers.update({
                'blockchain.scripthash.get_balance':
                controller.scripthash_get_balance,
                'blockchain.scripthash.get_history':
                controller.scripthash_get_history,
                'blockchain.scripthash.get_mempool':
                controller.scripthash_get_mempool,
                'blockchain.scripthash.listunspent':
                controller.scripthash_listunspent,
                'blockchain.scripthash.subscribe': self.scripthash_subscribe,
                'blockchain.transaction.broadcast': self.transaction_broadcast,
                'blockchain.transaction.get': controller.transaction_get,
            })

        if ptuple >= (1, 2):
            # New handler as of 1.2
            handlers.update({
                'mempool.get_fee_histogram':
                controller.mempool_get_fee_histogram,
                'blockchain.block.headers': self.block_headers,
                'server.ping': self.ping,
            })

        self.electrumx_handlers = handlers

    def request_handler(self, method):
        '''Return the async handler for the given request method.'''
        return self.electrumx_handlers.get(method)


class LocalRPC(SessionBase):
    '''A local TCP RPC server session.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = 'RPC'
        self.max_response_size = 0
        self.protocol_version = 'RPC'

    def request_handler(self, method):
        '''Return the async handler for the given request method.'''
        return self.controller.rpc_handlers.get(method)


class DashElectrumX(ElectrumX):
    '''A TCP server that handles incoming Electrum Dash connections.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mns = set()

    def set_protocol_handlers(self, ptuple):
        super().set_protocol_handlers(ptuple)
        mna_broadcast = (self.masternode_announce_broadcast if ptuple >= (1, 1)
                         else self.masternode_announce_broadcast_1_0)
        self.electrumx_handlers.update({
            'masternode.announce.broadcast': mna_broadcast,
            'masternode.subscribe': self.masternode_subscribe,
        })

    def notify(self, height, touched):
        '''Notify the client about changes in masternode list.'''
        result = super().notify(height, touched)

        for masternode in self.mns:
            status = self.daemon.masternode_list(['status', masternode])
            self.send_notification('masternode.subscribe',
                                   [masternode, status.get(masternode)])
        return result

    # Masternode command handlers
    async def masternode_announce_broadcast(self, signmnb):
        '''Pass through the masternode announce message to be broadcast
        by the daemon.'''
        try:
            return await self.daemon.masternode_broadcast(['relay', signmnb])
        except DaemonError as e:
            error, = e.args
            message = error['message']
            self.logger.info('masternode_broadcast: {}'.format(message))
            raise RPCError(BAD_REQUEST, 'the masternode broadcast was '
                           f'rejected.\n\n{message}\n[{signmnb}]')

    async def masternode_announce_broadcast_1_0(self, signmnb):
        '''Pass through the masternode announce message to be broadcast
        by the daemon.'''
        # An ugly API, like the old Electrum transaction broadcast API
        try:
            return await self.masternode_announce_broadcast(signmnb)
        except RPCError as e:
            return e.message

    async def masternode_subscribe(self, vin):
        '''Returns the status of masternode.'''
        result = await self.daemon.masternode_list(['status', vin])
        if result is not None:
            self.mns.add(vin)
            return result.get(vin)
        return None


class PIVXSaplingElectrumX(ElectrumX):
    '''A TCP server that handles incoming Electrum PIVX connections with
    Sapling shielded transaction support.

    This class provides Sapling-specific RPCs for light wallet support.
    The API is designed to work with pivx-shield library for client-side
    Sapling operations including:
      - Commitment tree management
      - Note decryption using viewing keys
      - Witness generation for spending
      - Nullifier computation and tracking

    Key Design Principles:
      - Server indexes nullifiers and commitments for lookup
      - Server does NOT have access to viewing keys
      - Client performs trial decryption of notes
      - Client maintains commitment tree and witnesses locally
      - Raw transaction hex is provided for client-side parsing
    '''

    def set_protocol_handlers(self, ptuple):
        super().set_protocol_handlers(ptuple)
        # Add Sapling-specific handlers
        self.electrumx_handlers.update({
            'blockchain.sapling.capabilities':
                self.sapling_capabilities,
            'blockchain.sapling.get_capabilities':
                self.sapling_capabilities,
            'server.sapling.capabilities':
                self.sapling_capabilities,
            'blockchain.sapling.get_nullifier_status':
                self.sapling_get_nullifier_status,
            'blockchain.sapling.check_nullifier':
                self.sapling_get_nullifier_status,
            'blockchain.sapling.check_nullifiers':
                self.sapling_check_nullifiers,
            'blockchain.sapling.get_commitment_info':
                self.sapling_get_commitment_info,
            'blockchain.sapling.get_commitment':
                self.sapling_get_commitment_info,
            'blockchain.sapling.get_outputs_by_height':
                self.sapling_get_outputs_by_height,
            'blockchain.sapling.get_outputs':
                self.sapling_get_outputs_by_height,
            'blockchain.sapling.get_block_range':
                self.sapling_get_block_range,
            'blockchain.sapling.get_blocks':
                self.sapling_get_block_range,
            'blockchain.sapling.get_anchor_height':
                self.sapling_get_anchor_height,
            'blockchain.sapling.get_best_anchor':
                self.sapling_get_best_anchor,
            'blockchain.sapling.best_anchor':
                self.sapling_get_best_anchor,
            'blockchain.sapling.get_tree_state':
                self.sapling_get_tree_state,
            'blockchain.sapling.get_treestate':
                self.sapling_get_tree_state,
            'blockchain.sapling.get_witness':
                self.sapling_get_witness,
            'blockchain.sapling.get_witnesses':
                self.sapling_get_witnesses,
        })

    def sapling_capabilities(self):
        '''Return the PIVX Sapling ElectrumX v1 RPC contract.'''
        primary_methods = [
            'blockchain.sapling.capabilities',
            'blockchain.sapling.get_block_range',
            'blockchain.sapling.get_nullifier_status',
            'blockchain.sapling.get_commitment_info',
            'blockchain.sapling.get_best_anchor',
            'blockchain.sapling.get_anchor_height',
            'blockchain.sapling.get_tree_state',
            'blockchain.sapling.get_witness',
            'blockchain.sapling.get_witnesses',
        ]
        aliases = {
            'blockchain.sapling.capabilities': [
                'blockchain.sapling.get_capabilities',
                'server.sapling.capabilities',
            ],
            'blockchain.sapling.get_block_range': [
                'blockchain.sapling.get_blocks',
            ],
            'blockchain.sapling.get_nullifier_status': [
                'blockchain.sapling.check_nullifier',
            ],
            'blockchain.sapling.check_nullifiers': [],
            'blockchain.sapling.get_commitment_info': [
                'blockchain.sapling.get_commitment',
            ],
            'blockchain.sapling.get_outputs_by_height': [
                'blockchain.sapling.get_outputs',
            ],
            'blockchain.sapling.get_best_anchor': [
                'blockchain.sapling.best_anchor',
            ],
            'blockchain.sapling.get_tree_state': [
                'blockchain.sapling.get_treestate',
            ],
        }
        activation_height = getattr(self.controller.coin,
                                    'SAPLING_START_HEIGHT', None)
        return {
            'success': True,
            'contract': PIVX_SAPLING_RPC_CONTRACT,
            'version': 1,
            'coin': getattr(self.controller.coin, 'SHORTNAME', 'PIVX'),
            'network': getattr(self.controller.coin, 'NET', None),
            'sapling_activation_height': activation_height,
            'max_block_range': PIVX_SAPLING_MAX_BLOCK_RANGE,
            'range_response': 'envelope',
            'range_error_types': [
                'invalid_range',
                'daemon_error',
                'method_unavailable',
                'missing_block_hash',
                'missing_block',
                'missing_transaction',
                'index_incomplete',
                'index_error',
                'server_error',
            ],
            'methods': primary_methods,
            'aliases': aliases,
        }

    @staticmethod
    def _sapling_daemon_error(e):
        '''Return a structured error dict from a DaemonError.'''
        error = e.args[0] if e.args else {}
        if isinstance(error, list) and error:
            error = error[0]
        if isinstance(error, dict):
            code = error.get('code')
            message = error.get('message', str(error))
        else:
            code = None
            message = str(error)
        error_type = ('method_unavailable'
                      if code == JSONRPC.METHOD_NOT_FOUND
                      else 'daemon_error')
        return {
            'type': error_type,
            'code': code,
            'message': message,
        }

    @staticmethod
    def _sapling_range_response(start_height, end_height, blocks, complete,
                                error=None, total_sapling_txs=0,
                                block_hashes=None):
        scanned = end_height - start_height + 1
        return {
            'success': complete and error is None,
            'complete': complete,
            'empty': complete and not blocks,
            'contract': PIVX_SAPLING_RPC_CONTRACT,
            'start_height': start_height,
            'end_height': end_height,
            'height_count': scanned,
            'block_count': len(blocks),
            'sapling_tx_count': total_sapling_txs,
            'block_hashes': block_hashes or [],
            'blocks': blocks,
            'error': error,
        }

    def _sapling_range_error_response(self, start_height, end_height, blocks,
                                      error_type, message,
                                      total_sapling_txs=0, block_hashes=None,
                                      **context):
        error = {
            'type': error_type,
            'message': message,
        }
        error.update({key: value for key, value in context.items()
                      if value is not None})
        return self._sapling_range_response(start_height, end_height, blocks,
                                            False, error,
                                            total_sapling_txs,
                                            block_hashes)

    def _sapling_block_hash(self, height):
        '''Return the indexed chain block hash at height as hex.'''
        try:
            block_hashes = self.bp.fs_block_hashes(height, 1)
        except Exception as e:
            self.logger.debug(f'sapling: no indexed block hash for '
                              f'{height}: {e}')
            return None
        if block_hashes:
            return hash_to_str(block_hashes[0])
        return None

    def _sapling_commitment_position(self, commitment_hex):
        '''Return a commitment's indexed global Sapling output position.'''
        try:
            commitment = bytes.fromhex(commitment_hex)
            if len(commitment) != 32:
                return None
        except ValueError:
            return None
        if self.bp is None:
            return None
        info = self.bp.get_commitment_position_info(commitment)
        return None if info is None else info.position

    async def sapling_get_nullifier_status(self, nullifier_hex):
        '''Check if a Sapling nullifier has been spent.

        nullifier_hex: the nullifier as a 64-character hex string

        Returns a dict with:
          - spent: boolean indicating if spent
          - tx_hash: spending transaction hash (if spent)
          - height: block height (if spent)
          - block_hash: block hash at height (if spent)
          - spend_index: index in spending tx's vShieldedSpend (if spent)
        '''
        try:
            nullifier = bytes.fromhex(nullifier_hex)
            if len(nullifier) != 32:
                raise ValueError('nullifier must be 32 bytes')
        except ValueError as e:
            self.logger.warning(f'sapling nullifier status: invalid input: {e}')
            raise RPCError(BAD_REQUEST, f'invalid nullifier: {e}')

        result = self.bp.get_nullifier_spend(nullifier)
        if result:
            tx_hash, height, spend_index = result
            self.logger.debug(f'sapling nullifier spent at height {height}')
            return {
                'spent': True,
                'tx_hash': hash_to_str(tx_hash),
                'height': height,
                'block_hash': self._sapling_block_hash(height),
                'spend_index': spend_index,
            }
        return {'spent': False}

    async def sapling_check_nullifiers(self, nullifiers):
        '''Check spend status for multiple Sapling nullifiers.'''
        if isinstance(nullifiers, dict):
            nullifiers = nullifiers.get('nullifiers')
        if not isinstance(nullifiers, list):
            raise RPCError(BAD_REQUEST, 'nullifiers must be a list')
        if len(nullifiers) > 1000:
            raise RPCError(BAD_REQUEST,
                           'cannot request more than 1000 nullifiers')
        results = {}
        for nullifier_hex in nullifiers:
            results[nullifier_hex] = await self.sapling_get_nullifier_status(
                nullifier_hex)
        return {
            'success': True,
            'contract': PIVX_SAPLING_RPC_CONTRACT,
            'results': results,
        }

    async def sapling_get_commitment_info(self, commitment_hex):
        '''Get information about a Sapling note commitment.

        commitment_hex: the commitment (cmu) as a 64-character hex string

        Returns a dict with:
          - found: boolean indicating if found
          - tx_hash: creating transaction hash (if found)
          - height: block height (if found)
          - block_hash: block hash at height (if found)
          - output_index: index in creating tx's vShieldedOutput (if found)
        '''
        try:
            commitment = bytes.fromhex(commitment_hex)
            if len(commitment) != 32:
                raise ValueError('commitment must be 32 bytes')
        except ValueError as e:
            self.logger.warning(f'sapling commitment info: invalid input: {e}')
            raise RPCError(BAD_REQUEST, f'invalid commitment: {e}')

        result = self.bp.get_commitment_info(commitment)
        if result:
            tx_hash, height, output_index = result
            self.logger.debug(f'sapling commitment found at height {height}')
            return {
                'found': True,
                'tx_hash': hash_to_str(tx_hash),
                'height': height,
                'block_hash': self._sapling_block_hash(height),
                'position': self._sapling_commitment_position(
                    commitment_hex),
                'output_index': output_index,
            }
        return {'found': False}

    async def sapling_get_outputs_by_height(self, start_height,
                                            end_height=None, limit=1000):
        '''Get Sapling shielded outputs in a block height range.

        start_height: starting block height (inclusive)
        end_height: ending block height (inclusive), defaults to start_height
        limit: maximum number of outputs to return (default 1000)

        Returns a list of dicts containing:
          - tx_hash: transaction hash
          - height: block height
          - block_hash: block hash at height
          - position: global Sapling output position
          - output_index: index in vShieldedOutput
          - cmu: note commitment (32-byte hex)
          - ephemeral_key: ephemeral public key (32-byte hex)
          - enc_ciphertext: encrypted note ciphertext (580-byte hex)
          - out_ciphertext: outgoing ciphertext (80-byte hex)

        Light wallets use their incoming viewing key (IVK) to trial-decrypt
        each output's enc_ciphertext to determine if the note belongs to them.
        '''
        start_height = self.controller.non_negative_integer(start_height)
        if end_height is None:
            end_height = start_height
        else:
            end_height = self.controller.non_negative_integer(end_height)

        if end_height < start_height:
            raise RPCError(BAD_REQUEST,
                           'end_height must be >= start_height')
        if end_height - start_height + 1 > PIVX_SAPLING_MAX_BLOCK_RANGE:
            raise RPCError(BAD_REQUEST,
                           'height range must not exceed 100 blocks')

        limit = self.controller.non_negative_integer(limit)
        limit = min(limit, 5000)  # Cap at 5000

        self.logger.info(f'sapling get_outputs_by_height: '
                         f'heights {start_height}-{end_height}, limit={limit}')

        outputs = []
        count = 0

        try:
            for height in range(start_height, end_height + 1):
                if count >= limit:
                    break

                # Get block hash for this height
                block_hash = await self.daemon.daemon_request(
                    'getblockhash', [height])
                if not block_hash:
                    self.logger.debug(f'sapling: no block hash for {height}')
                    continue

                # Get block with transaction data
                block = await self.daemon.daemon_request(
                    'getblock', [block_hash, 2])  # verbosity=2 for full tx data
                if not block or 'tx' not in block:
                    continue

                for tx_data in block['tx']:
                    if count >= limit:
                        break

                    tx_hash = tx_data.get('txid', '')
                    vShieldOut = tx_data.get('vShieldOutput', [])

                    for idx, out in enumerate(vShieldOut):
                        if count >= limit:
                            break
                        outputs.append({
                            'tx_hash': tx_hash,
                            'height': height,
                            'block_hash': block_hash,
                            'position': self._sapling_commitment_position(
                                out.get('cmu', '')),
                            'output_index': idx,
                            'cmu': out.get('cmu', ''),
                            'ephemeral_key': out.get('ephemeralKey', ''),
                            'enc_ciphertext': out.get('encCiphertext', ''),
                            'out_ciphertext': out.get('outCiphertext', ''),
                        })
                        count += 1
        except DaemonError as e:
            error, = e.args
            message = error.get('message', str(error))
            self.logger.error(f'sapling get_outputs_by_height: '
                              f'daemon error: {message}')
            raise RPCError(DAEMON_ERROR, f'daemon error: {message}')

        self.logger.info(f'sapling get_outputs_by_height: '
                         f'returning {len(outputs)} outputs')
        return outputs

    async def sapling_get_block_range(self, start_height, end_height=None):
        '''Get blocks with Sapling transactions in format for pivx-shield.

        start_height: starting block height (inclusive)
        end_height: ending block height (inclusive), defaults to start_height

        Returns a v1 envelope containing:
          - success: true only when the full range was scanned
          - complete: false for daemon/index/method failures
          - empty: true only for a successful range with no Sapling blocks
          - error: structured error object or null
          - blocks: Sapling blocks only, in height order
        '''
        try:
            start_height = self.controller.non_negative_integer(start_height)
            if end_height is None:
                end_height = start_height
            else:
                end_height = self.controller.non_negative_integer(end_height)
        except RPCError as e:
            try:
                display_start = int(start_height)
            except Exception:
                display_start = 0
            display_end = display_start if end_height is None else display_start
            return self._sapling_range_error_response(
                display_start, display_end, [], 'invalid_range', e.message)

        if end_height < start_height:
            return self._sapling_range_error_response(
                start_height, end_height, [], 'invalid_range',
                'end_height must be >= start_height')
        if end_height - start_height + 1 > PIVX_SAPLING_MAX_BLOCK_RANGE:
            return self._sapling_range_error_response(
                start_height, end_height, [], 'invalid_range',
                'height range must not exceed 100 blocks',
                max_block_range=PIVX_SAPLING_MAX_BLOCK_RANGE)

        self.logger.info(f'sapling get_block_range: '
                         f'heights {start_height}-{end_height}')

        blocks = []
        block_hashes = []
        total_sapling_txs = 0

        try:
            for height in range(start_height, end_height + 1):
                # Get block hash for this height
                block_hash = await self.daemon.daemon_request(
                    'getblockhash', [height])
                if not block_hash:
                    self.logger.warning(f'sapling: no block hash for {height}')
                    return self._sapling_range_error_response(
                        start_height, end_height, blocks,
                        'missing_block_hash',
                        'daemon returned no block hash',
                        total_sapling_txs, block_hashes,
                        height=height,
                        method='getblockhash')
                block_hashes.append({
                    'height': height,
                    'block_hash': block_hash,
                })

                # Get block with transaction data (verbosity=2 for decoded tx)
                block = await self.daemon.daemon_request(
                    'getblock', [block_hash, 2])
                if not block or 'tx' not in block:
                    self.logger.warning(f'sapling: missing decoded block '
                                        f'for {height}')
                    return self._sapling_range_error_response(
                        start_height, end_height, blocks,
                        'missing_block',
                        'daemon returned no decoded block transactions',
                        total_sapling_txs, block_hashes,
                        height=height,
                        block_hash=block_hash, method='getblock')

                # Filter to only transactions with Sapling data
                sapling_txs = []
                block_outputs = []
                for tx_index, tx_data in enumerate(block['tx']):
                    # Check if transaction has any Sapling components
                    has_spend = len(tx_data.get('vShieldSpend', [])) > 0
                    has_output = len(tx_data.get('vShieldOutput', [])) > 0

                    if has_spend or has_output:
                        # Get raw transaction hex
                        txid = tx_data.get('txid', '')
                        tx_hex = await self.daemon.daemon_request(
                            'getrawtransaction', [txid])
                        if not tx_hex:
                            return self._sapling_range_error_response(
                                start_height, end_height, blocks,
                                'missing_transaction',
                                'daemon returned no raw transaction',
                                total_sapling_txs, block_hashes,
                                height=height,
                                block_hash=block_hash, txid=txid,
                                method='getrawtransaction')

                        sapling_outputs = []
                        for output_index, output in enumerate(
                                tx_data.get('vShieldOutput', [])):
                            cmu = output.get('cmu', '')
                            try:
                                position = self._sapling_commitment_position(
                                    cmu)
                            except Exception as e:
                                return self._sapling_range_error_response(
                                    start_height, end_height, blocks,
                                    'index_error',
                                    f'Sapling index lookup failed: {e}',
                                    total_sapling_txs, block_hashes,
                                    height=height,
                                    block_hash=block_hash, txid=txid,
                                    tx_index=tx_index,
                                    output_index=output_index,
                                    commitment=cmu)
                            if position is None:
                                return self._sapling_range_error_response(
                                    start_height, end_height, blocks,
                                    'index_incomplete',
                                    'Sapling commitment is not indexed',
                                    total_sapling_txs, block_hashes,
                                    height=height,
                                    block_hash=block_hash, txid=txid,
                                    tx_index=tx_index,
                                    output_index=output_index,
                                    commitment=cmu)
                            output_data = {
                                'position': position,
                                'txid': txid,
                                'tx_index': tx_index,
                                'output_index': output_index,
                                'cmu': cmu,
                                'ephemeral_key':
                                    output.get('ephemeralKey', ''),
                                'enc_ciphertext':
                                    output.get('encCiphertext', ''),
                                'out_ciphertext':
                                    output.get('outCiphertext', ''),
                            }
                            sapling_outputs.append(output_data)
                            block_outputs.append(output_data)
                        sapling_txs.append({
                            'hex': tx_hex,
                            'txid': txid,
                            'outputs': sapling_outputs,
                        })

                # Only include blocks that have Sapling transactions
                if sapling_txs:
                    blocks.append({
                        'height': height,
                        'block_hash': block_hash,
                        'outputs': block_outputs,
                        'txs': sapling_txs,
                    })
                    total_sapling_txs += len(sapling_txs)
        except DaemonError as e:
            error = self._sapling_daemon_error(e)
            self.logger.error(f'sapling get_block_range: daemon error: '
                              f'{error["message"]}')
            return self._sapling_range_response(start_height, end_height,
                                                blocks, False, error,
                                                total_sapling_txs,
                                                block_hashes)
        except Exception as e:
            self.logger.exception(f'sapling get_block_range: index error: {e}')
            return self._sapling_range_error_response(
                start_height, end_height, blocks, 'server_error', str(e),
                total_sapling_txs, block_hashes)

        self.logger.info(f'sapling get_block_range: returning {len(blocks)} '
                         f'blocks with {total_sapling_txs} sapling txs')
        return self._sapling_range_response(start_height, end_height, blocks,
                                            True, None, total_sapling_txs,
                                            block_hashes)

    async def sapling_get_anchor_height(self, anchor_hex):
        '''Get the block height where a Sapling anchor was valid.

        anchor_hex: the anchor (root) as a 64-character hex string

        Returns the block height or null if not found.
        '''
        try:
            anchor = bytes.fromhex(anchor_hex)
            if len(anchor) != 32:
                raise ValueError('anchor must be 32 bytes')
        except ValueError as e:
            self.logger.warning(f'sapling anchor height: invalid input: {e}')
            raise RPCError(BAD_REQUEST, f'invalid anchor: {e}')

        height = self.bp.get_anchor_height(anchor)
        if height is not None:
            self.logger.debug(f'sapling anchor found at height {height}')
        return height

    async def sapling_get_tree_state(self, height=None):
        '''Return Sapling tree state metadata for an indexed height.

        The anchor/root is the PIVX Core final Sapling root reported in the
        decoded block.  tree_size is present when the local Sapling index has a
        matching root entry; otherwise it is null because Core does not expose
        it in getblock output.
        '''
        if height is None:
            height = self.bp.db_height
        else:
            height = self.controller.non_negative_integer(height)

        indexed_height = self.bp.db_height
        if height > indexed_height:
            return {
                'success': False,
                'contract': PIVX_SAPLING_RPC_CONTRACT,
                'error': {
                    'type': 'index_incomplete',
                    'message': 'requested height is above indexed tip',
                    'height': height,
                    'indexed_height': indexed_height,
                },
            }

        try:
            block_hash = await self.daemon.daemon_request(
                'getblockhash', [height])
            if not block_hash:
                return {
                    'success': False,
                    'contract': PIVX_SAPLING_RPC_CONTRACT,
                    'error': {
                        'type': 'missing_block_hash',
                        'message': 'daemon returned no block hash',
                        'height': height,
                        'method': 'getblockhash',
                    },
                }
            block = await self.daemon.daemon_request(
                'getblock', [block_hash, 2])
            if not block:
                return {
                    'success': False,
                    'contract': PIVX_SAPLING_RPC_CONTRACT,
                    'error': {
                        'type': 'missing_block',
                        'message': 'daemon returned no decoded block',
                        'height': height,
                        'block_hash': block_hash,
                        'method': 'getblock',
                    },
                }
        except DaemonError as e:
            error = self._sapling_daemon_error(e)
            error.update({'height': height})
            return {
                'success': False,
                'contract': PIVX_SAPLING_RPC_CONTRACT,
                'error': error,
            }

        root = (block.get('finalsaplingroot') or
                block.get('finalSaplingRoot') or
                block.get('saplingroot'))
        tree_size = None
        if root:
            try:
                root_info = self.bp.get_sapling_root_info(
                    bytes.fromhex(root))
            except Exception:
                root_info = None
            if root_info is not None:
                tree_size, _root_height = root_info

        return {
            'success': True,
            'contract': PIVX_SAPLING_RPC_CONTRACT,
            'height': height,
            'block_hash': block_hash,
            'anchor': root,
            'root': root,
            'tree_size': tree_size,
            'indexed_height': indexed_height,
            'sapling_activation_height': getattr(
                self.controller.coin, 'SAPLING_START_HEIGHT', None),
        }

    async def sapling_get_witness(self, position, anchor_hex=None):
        '''Return an anchor-bound witness for a Sapling note position.

        position: global Sapling output position
        anchor_hex: indexed root to bind the witness to. If omitted, the
                    current indexed root is used.

        Returns a dict with:
          - anchor/root: indexed commitment tree root
          - anchor_height: height where the root was indexed
          - position: note position
          - path: sibling path from note to root
          - commitment: note commitment at position
        '''
        position = self.controller.non_negative_integer(position)
        anchor = None
        if anchor_hex is not None:
            try:
                anchor = bytes.fromhex(anchor_hex)
                if len(anchor) != 32:
                    raise ValueError('anchor must be 32 bytes')
            except ValueError as e:
                self.logger.warning(f'sapling witness: invalid anchor: {e}')
                raise RPCError(BAD_REQUEST, f'invalid anchor: {e}')

        result = self.bp.get_sapling_witness(position, anchor)
        if result is None:
            raise RPCError(BAD_REQUEST, 'witness not found for position '
                           f'{position}')
        return result

    async def sapling_get_witnesses(self, positions, anchor_hex=None):
        '''Return anchor-bound witnesses for multiple Sapling note positions.'''
        if not isinstance(positions, list):
            raise RPCError(BAD_REQUEST, 'positions must be a list')
        if len(positions) > 100:
            raise RPCError(BAD_REQUEST,
                           'cannot request more than 100 witnesses')
        return [await self.sapling_get_witness(position, anchor_hex)
                for position in positions]

    async def sapling_get_best_anchor(self):
        '''Get the current best (most recent) Sapling tree anchor.

        Returns a dict with:
          - anchor: the current tree root as a 64-character hex string
          - height: the current block height
          - block_hash: current indexed tip hash

        This is equivalent to the PIVX Core getbestsaplinganchor RPC.
        '''
        try:
            anchor = await self.daemon.daemon_request(
                'getbestsaplinganchor', [])
            height = self.bp.db_height
            self.logger.debug(f'sapling best anchor at height {height}')
            return {
                'anchor': anchor,
                'height': height,
                'block_hash': self._sapling_block_hash(height),
            }
        except DaemonError as e:
            error, = e.args
            message = error.get('message', str(error))
            self.logger.error(f'sapling get_best_anchor: '
                              f'daemon error: {message}')
            raise RPCError(DAEMON_ERROR, f'daemon error: {message}')
