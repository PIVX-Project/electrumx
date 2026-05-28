# Copyright (c) 2016, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Interface to the blockchain database.'''


import array
import ast
import logging
import os
from struct import pack, unpack
from bisect import bisect_left, bisect_right
from collections import namedtuple

import lib.util as util
from lib.hash import double_sha256, hash_to_str
from server.storage import db_class


UTXO = namedtuple("UTXO", "tx_num tx_pos tx_hash height value")
SaplingOutputInfo = namedtuple("SaplingOutputInfo",
                               "position commitment tx_hash height "
                               "output_index")


class DB(object):
    '''Simple wrapper of the backend database for querying.

    Performs no DB update, though the DB will be cleaned on opening if
    it was shutdown uncleanly.
    '''

    DB_VERSIONS = [6]

    class MissingUTXOError(Exception):
        '''Raised if a mempool tx input UTXO couldn't be found.'''

    class DBError(Exception):
        '''Raised on general DB errors generally indicating corruption.'''

    def __init__(self, env):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.env = env
        self.coin = env.coin

        # Setup block header size handlers
        if self.coin.STATIC_BLOCK_HEADERS:
            self.header_offset = self.coin.static_header_offset
            self.header_len = self.coin.static_header_len
        else:
            self.header_offset = self.dynamic_header_offset
            self.header_len = self.dynamic_header_len

        self.logger.info('switching current directory to {}'
                         .format(env.db_dir))
        os.chdir(env.db_dir)

        self.db_class = db_class(self.env.db_engine)
        self.logger.info('using {} for DB backend'.format(self.env.db_engine))

        # For history compaction
        self.max_hist_row_entries = 12500

        self.utxo_db = None
        self.open_dbs()
        self.clean_db()

        self.logger.info('reorg limit is {:,d} blocks'
                         .format(self.env.reorg_limit))

        self.headers_file = util.LogicalFile('meta/headers', 2, 16000000)
        self.tx_counts_file = util.LogicalFile('meta/txcounts', 2, 2000000)
        self.hashes_file = util.LogicalFile('meta/hashes', 4, 16000000)
        if not self.coin.STATIC_BLOCK_HEADERS:
            self.headers_offsets_file = util.LogicalFile(
                'meta/headers_offsets', 2, 16000000)
            # Write the offset of the genesis block
            if self.headers_offsets_file.read(0, 8) != b'\x00' * 8:
                self.headers_offsets_file.write(0, b'\x00' * 8)

        # tx_counts[N] has the cumulative number of txs at the end of
        # height N.  So tx_counts[0] is 1 - the genesis coinbase
        size = (self.db_height + 1) * 4
        tx_counts = self.tx_counts_file.read(0, size)
        assert len(tx_counts) == size
        self.tx_counts = array.array('I', tx_counts)
        if self.tx_counts:
            assert self.db_tx_count == self.tx_counts[-1]
        else:
            assert self.db_tx_count == 0

    def open_dbs(self):
        '''Open the databases.  If already open they are closed and re-opened.

        When syncing we want to reserve a lot of open files for the
        synchronization.  When serving clients we want the open files for
        serving network connections.
        '''
        def log_reason(message, is_for_sync):
            reason = 'sync' if is_for_sync else 'serving'
            self.logger.info('{} for {}'.format(message, reason))

        # Assume we're serving until we find out otherwise
        for for_sync in [False, True]:
            if self.utxo_db:
                if self.utxo_db.for_sync == for_sync:
                    return
                log_reason('closing DB to re-open', for_sync)
                self.utxo_db.close()
                self.hist_db.close()

            # Open DB and metadata files.  Record some of its state.
            self.utxo_db = self.db_class('utxo', for_sync)
            self.hist_db = self.db_class('hist', for_sync)
            if self.utxo_db.is_new:
                self.logger.info('created new database')
                self.logger.info('creating metadata directory')
                os.mkdir('meta')
                with util.open_file('COIN', create=True) as f:
                    f.write('ElectrumX databases and metadata for {} {}'
                            .format(self.coin.NAME, self.coin.NET).encode())
            else:
                log_reason('opened DB', self.utxo_db.for_sync)

            self.read_utxo_state()
            if self.first_sync == self.utxo_db.for_sync:
                break

        self.read_history_state()

        self.logger.info('DB version: {:d}'.format(self.db_version))
        self.logger.info('coin: {}'.format(self.coin.NAME))
        self.logger.info('network: {}'.format(self.coin.NET))
        self.logger.info('height: {:,d}'.format(self.db_height))
        self.logger.info('tip: {}'.format(hash_to_str(self.db_tip)))
        self.logger.info('tx count: {:,d}'.format(self.db_tx_count))
        self.logger.info('flush count: {:,d}'.format(self.flush_count))
        if self.first_sync:
            self.logger.info('sync time so far: {}'
                             .format(util.formatted_time(self.wall_time)))

    def clean_db(self):
        '''Clean out stale DB items.

        Stale DB items are excess history flushed since the most
        recent UTXO flush (only happens on unclean shutdown), and aged
        undo information.
        '''
        if self.flush_count < self.utxo_flush_count:
            # Might happen at end of compaction as both DBs cannot be
            # updated atomically
            self.utxo_flush_count = self.flush_count
        if self.flush_count > self.utxo_flush_count:
            self.clear_excess_history(self.utxo_flush_count)
        self.clear_excess_undo_info()

    def fs_update_header_offsets(self, offset_start, height_start, headers):
        if self.coin.STATIC_BLOCK_HEADERS:
            return
        offset = offset_start
        offsets = []
        for h in headers:
            offset += len(h)
            offsets.append(pack("<Q", offset))
        # For each header we get the offset of the next header, hence we
        # start writing from the next height
        pos = (height_start + 1) * 8
        self.headers_offsets_file.write(pos, b''.join(offsets))

    def dynamic_header_offset(self, height):
        assert not self.coin.STATIC_BLOCK_HEADERS
        offset, = unpack('<Q', self.headers_offsets_file.read(height * 8, 8))
        return offset

    def dynamic_header_len(self, height):
        return self.dynamic_header_offset(height + 1)\
               - self.dynamic_header_offset(height)

    def fs_update(self, fs_height, headers, block_tx_hashes):
        '''Write headers, the tx_count array and block tx hashes to disk.

        Their first height is fs_height.  No recorded DB state is
        updated.  These arrays are all append only, so in a crash we
        just pick up again from the DB height.
        '''
        blocks_done = len(headers)
        height_start = fs_height + 1
        new_height = fs_height + blocks_done
        prior_tx_count = (self.tx_counts[fs_height] if fs_height >= 0 else 0)
        cur_tx_count = self.tx_counts[-1] if self.tx_counts else 0
        txs_done = cur_tx_count - prior_tx_count

        assert len(block_tx_hashes) == blocks_done
        assert len(self.tx_counts) == new_height + 1
        hashes = b''.join(block_tx_hashes)
        assert len(hashes) % 32 == 0
        assert len(hashes) // 32 == txs_done

        # Write the headers, tx counts, and tx hashes
        offset = self.header_offset(height_start)
        self.headers_file.write(offset, b''.join(headers))
        self.fs_update_header_offsets(offset, height_start, headers)
        offset = height_start * self.tx_counts.itemsize
        self.tx_counts_file.write(offset,
                                  self.tx_counts[height_start:].tobytes())
        offset = prior_tx_count * 32
        self.hashes_file.write(offset, hashes)

    def read_headers(self, start_height, count):
        '''Requires start_height >= 0, count >= 0.  Reads as many headers as
        are available starting at start_height up to count.  This
        would be zero if start_height is beyond self.db_height, for
        example.

        Returns a (binary, n) pair where binary is the concatenated
        binary headers, and n is the count of headers returned.
        '''
        # Read some from disk
        if start_height < 0 or count < 0:
            raise self.DBError('{:,d} headers starting at {:,d} not on disk'
                               .format(count, start_height))
        disk_count = max(0, min(count, self.db_height + 1 - start_height))
        if disk_count:
            offset = self.header_offset(start_height)
            size = self.header_offset(start_height + disk_count) - offset
            return self.headers_file.read(offset, size), disk_count
        return b'', 0

    def fs_tx_hash(self, tx_num):
        '''Return a par (tx_hash, tx_height) for the given tx number.

        If the tx_height is not on disk, returns (None, tx_height).'''
        tx_height = bisect_right(self.tx_counts, tx_num)
        if tx_height > self.db_height:
            tx_hash = None
        else:
            tx_hash = self.hashes_file.read(tx_num * 32, 32)
        return tx_hash, tx_height

    def fs_block_hashes(self, height, count):
        headers_concat, headers_count = self.read_headers(height, count)
        if headers_count != count:
            raise self.DBError('only got {:,d} headers starting at {:,d}, not '
                               '{:,d}'.format(headers_count, start, count))
        offset = 0
        headers = []
        for n in range(count):
            hlen = self.header_len(height + n)
            headers.append(headers_concat[offset:offset + hlen])
            offset += hlen

        return [self.coin.header_hash(header) for header in headers]

    @staticmethod
    def _resolve_limit(limit):
        if limit is None:
            return -1
        assert isinstance(limit, int) and limit >= 0
        return limit

    # -- Undo information

    def min_undo_height(self, max_height):
        '''Returns a height from which we should store undo info.'''
        return max_height - self.env.reorg_limit + 1

    def undo_key(self, height):
        '''DB key for undo information at the given height.'''
        return b'U' + pack('>I', height)

    def read_undo_info(self, height):
        '''Read undo information from a file for the current height.'''
        return self.utxo_db.get(self.undo_key(height))

    def flush_undo_infos(self, batch_put, undo_infos):
        '''undo_infos is a list of (undo_info, height) pairs.'''
        for undo_info, height in undo_infos:
            batch_put(self.undo_key(height), b''.join(undo_info))

    def clear_excess_undo_info(self):
        '''Clear excess undo info.  Only most recent N are kept.'''
        prefix = b'U'
        min_height = self.min_undo_height(self.db_height)
        keys = []
        for key, hist in self.utxo_db.iterator(prefix=prefix):
            height, = unpack('>I', key[-4:])
            if height >= min_height:
                break
            keys.append(key)

        if keys:
            with self.utxo_db.write_batch() as batch:
                for key in keys:
                    batch.delete(key)
            self.logger.info('deleted {:,d} stale undo entries'
                             .format(len(keys)))

    # -- UTXO database

    def read_utxo_state(self):
        state = self.utxo_db.get(b'state')
        if not state:
            self.db_height = -1
            self.db_tx_count = 0
            self.db_tip = b'\0' * 32
            self.db_version = max(self.DB_VERSIONS)
            self.utxo_flush_count = 0
            self.wall_time = 0
            self.first_sync = True
            self.sapling_output_count = 0
        else:
            state = ast.literal_eval(state.decode())
            if not isinstance(state, dict):
                raise self.DBError('failed reading state from DB')
            self.db_version = state['db_version']
            if self.db_version not in self.DB_VERSIONS:
                raise self.DBError('your DB version is {} but this software '
                                   'only handles versions {}'
                                   .format(self.db_version, self.DB_VERSIONS))
            # backwards compat
            genesis_hash = state['genesis']
            if isinstance(genesis_hash, bytes):
                genesis_hash = genesis_hash.decode()
            if genesis_hash != self.coin.GENESIS_HASH:
                raise self.DBError('DB genesis hash {} does not match coin {}'
                                   .format(genesis_hash,
                                           self.coin.GENESIS_HASH))
            self.db_height = state['height']
            self.db_tx_count = state['tx_count']
            self.db_tip = state['tip']
            self.utxo_flush_count = state['utxo_flush_count']
            self.wall_time = state['wall_time']
            self.first_sync = state['first_sync']
            self.sapling_output_count = state.get('sapling_output_count', 0)

    def write_utxo_state(self, batch):
        '''Write (UTXO) state to the batch.'''
        state = {
            'genesis': self.coin.GENESIS_HASH,
            'height': self.db_height,
            'tx_count': self.db_tx_count,
            'tip': self.db_tip,
            'utxo_flush_count': self.utxo_flush_count,
            'wall_time': self.wall_time,
            'first_sync': self.first_sync,
            'db_version': self.db_version,
            'sapling_output_count': self.sapling_output_count,
        }
        batch.put(b'state', repr(state).encode())

    def get_balance(self, hashX):
        '''Returns the confirmed balance of an address.'''
        return sum(utxo.value for utxo in self.get_utxos(hashX, limit=None))

    def get_utxos(self, hashX, limit=1000):
        '''Generator that yields all UTXOs for an address sorted in no
        particular order.  By default yields at most 1000 entries.
        Set limit to None to get them all.
        '''
        limit = self._resolve_limit(limit)
        s_unpack = unpack
        # Key: b'u' + address_hashX + tx_idx + tx_num
        # Value: the UTXO value as a 64-bit unsigned integer
        prefix = b'u' + hashX
        for db_key, db_value in self.utxo_db.iterator(prefix=prefix):
            if limit == 0:
                return
            limit -= 1
            tx_pos, tx_num = s_unpack('<HI', db_key[-6:])
            value, = unpack('<Q', db_value)
            tx_hash, height = self.fs_tx_hash(tx_num)
            yield UTXO(tx_num, tx_pos, tx_hash, height, value)

    def db_utxo_lookup(self, tx_hash, tx_idx):
        '''Given a prevout return a (hashX, value) pair.

        Raises MissingUTXOError if the UTXO is not found.  Used by the
        mempool code.
        '''
        idx_packed = pack('<H', tx_idx)
        hashX, tx_num_packed = self._db_hashX(tx_hash, idx_packed)
        if not hashX:
            # This can happen when the daemon is a block ahead of us
            # and has mempool txs spending outputs from that new block
            raise self.MissingUTXOError

        # Key: b'u' + address_hashX + tx_idx + tx_num
        # Value: the UTXO value as a 64-bit unsigned integer
        key = b'u' + hashX + idx_packed + tx_num_packed
        db_value = self.utxo_db.get(key)
        if not db_value:
            raise self.DBError('UTXO {} / {:,d} in one table only'
                               .format(hash_to_str(tx_hash), tx_idx))
        value, = unpack('<Q', db_value)
        return hashX, value

    def _db_hashX(self, tx_hash, idx_packed):
        '''Return (hashX, tx_num_packed) for the given TXO.

        Both are None if not found.'''
        # Key: b'h' + compressed_tx_hash + tx_idx + tx_num
        # Value: hashX
        prefix = b'h' + tx_hash[:4] + idx_packed

        # Find which entry, if any, the TX_HASH matches.
        for db_key, hashX in self.utxo_db.iterator(prefix=prefix):
            tx_num_packed = db_key[-4:]
            tx_num, = unpack('<I', tx_num_packed)
            hash, height = self.fs_tx_hash(tx_num)
            if hash == tx_hash:
                return hashX, tx_num_packed

        return None, None

    # -- History database

    def clear_excess_history(self, flush_count):
        self.logger.info('DB shut down uncleanly.  Scanning for '
                         'excess history flushes...')

        keys = []
        for key, hist in self.hist_db.iterator(prefix=b''):
            flush_id, = unpack('>H', key[-2:])
            if flush_id > flush_count:
                keys.append(key)

        self.logger.info('deleting {:,d} history entries'.format(len(keys)))

        self.flush_count = flush_count
        with self.hist_db.write_batch() as batch:
            for key in keys:
                batch.delete(key)
            self.write_history_state(batch)

        self.logger.info('deleted excess history entries')

    def write_history_state(self, batch):
        '''Write state to hist_db.'''
        state = {
            'flush_count': self.flush_count,
            'comp_flush_count': self.comp_flush_count,
            'comp_cursor': self.comp_cursor,
        }
        # History entries are not prefixed; the suffix \0\0 ensures we
        # look similar to other entries and aren't interfered with
        batch.put(b'state\0\0', repr(state).encode())

    def read_history_state(self):
        state = self.hist_db.get(b'state\0\0')
        if state:
            state = ast.literal_eval(state.decode())
            if not isinstance(state, dict):
                raise self.DBError('failed reading state from history DB')
            self.flush_count = state['flush_count']
            self.comp_flush_count = state.get('comp_flush_count', -1)
            self.comp_cursor = state.get('comp_cursor', -1)
        else:
            self.flush_count = 0
            self.comp_flush_count = -1
            self.comp_cursor = -1

    def flush_history(self, history):
        self.flush_count += 1
        flush_id = pack('>H', self.flush_count)

        with self.hist_db.write_batch() as batch:
            for hashX in sorted(history):
                key = hashX + flush_id
                batch.put(key, history[hashX].tobytes())
            self.write_history_state(batch)

    def backup_history(self, hashXs):
        # Not certain this is needed, but it doesn't hurt
        self.flush_count += 1
        nremoves = 0

        with self.hist_db.write_batch() as batch:
            for hashX in sorted(hashXs):
                deletes = []
                puts = {}
                for key, hist in self.hist_db.iterator(prefix=hashX,
                                                       reverse=True):
                    a = array.array('I')
                    a.frombytes(hist)
                    # Remove all history entries >= self.tx_count
                    idx = bisect_left(a, self.tx_count)
                    nremoves += len(a) - idx
                    if idx > 0:
                        puts[key] = a[:idx].tobytes()
                        break
                    deletes.append(key)

                for key in deletes:
                    batch.delete(key)
                for key, value in puts.items():
                    batch.put(key, value)
            self.write_history_state(batch)

        return nremoves

    def get_history_txnums(self, hashX, limit=1000):
        '''Generator that returns an unpruned, sorted list of tx_nums in the
        history of a hashX.  Includes both spending and receiving
        transactions.  By default yields at most 1000 entries.  Set
        limit to None to get them all.  '''
        limit = self._resolve_limit(limit)
        for key, hist in self.hist_db.iterator(prefix=hashX):
            a = array.array('I')
            a.frombytes(hist)
            for tx_num in a:
                if limit == 0:
                    return
                yield tx_num
                limit -= 1

    def get_history(self, hashX, limit=1000):
        '''Generator that returns an unpruned, sorted list of (tx_hash,
        height) tuples of confirmed transactions that touched the address,
        earliest in the blockchain first.  Includes both spending and
        receiving transactions.  By default yields at most 1000 entries.
        Set limit to None to get them all.
        '''
        for tx_num in self.get_history_txnums(hashX, limit):
            yield self.fs_tx_hash(tx_num)

    #
    # History compaction
    #

    # comp_cursor is a cursor into compaction progress.
    # -1: no compaction in progress
    # 0-65535: Compaction in progress; all prefixes < comp_cursor have
    #     been compacted, and later ones have not.
    # 65536: compaction complete in-memory but not flushed
    #
    # comp_flush_count applies during compaction, and is a flush count
    #     for history with prefix < comp_cursor.  flush_count applies
    #     to still uncompacted history.  It is -1 when no compaction is
    #     taking place.  Key suffixes up to and including comp_flush_count
    #     are used, so a parallel history flush must first increment this
    #
    # When compaction is complete and the final flush takes place,
    # flush_count is reset to comp_flush_count, and comp_flush_count to -1

    def _flush_compaction(self, cursor, write_items, keys_to_delete):
        '''Flush a single compaction pass as a batch.'''
        # Update compaction state
        if cursor == 65536:
            self.flush_count = self.comp_flush_count
            self.comp_cursor = -1
            self.comp_flush_count = -1
        else:
            self.comp_cursor = cursor

        # History DB.  Flush compacted history and updated state
        with self.hist_db.write_batch() as batch:
            # Important: delete first!  The keyspace may overlap.
            for key in keys_to_delete:
                batch.delete(key)
            for key, value in write_items:
                batch.put(key, value)
            self.write_history_state(batch)

        # If compaction was completed also update the UTXO flush count
        if cursor == 65536:
            self.utxo_flush_count = self.flush_count
            with self.utxo_db.write_batch() as batch:
                self.write_utxo_state(batch)

    def _compact_hashX(self, hashX, hist_map, hist_list,
                       write_items, keys_to_delete):
        '''Compres history for a hashX.  hist_list is an ordered list of
        the histories to be compressed.'''
        # History entries (tx numbers) are 4 bytes each.  Distribute
        # over rows of up to 50KB in size.  A fixed row size means
        # future compactions will not need to update the first N - 1
        # rows.
        max_row_size = self.max_hist_row_entries * 4
        full_hist = b''.join(hist_list)
        nrows = (len(full_hist) + max_row_size - 1) // max_row_size
        if nrows > 4:
            self.logger.info('hashX {} is large: {:,d} entries across '
                             '{:,d} rows'
                             .format(hash_to_str(hashX), len(full_hist) // 4,
                                     nrows))

        # Find what history needs to be written, and what keys need to
        # be deleted.  Start by assuming all keys are to be deleted,
        # and then remove those that are the same on-disk as when
        # compacted.
        write_size = 0
        keys_to_delete.update(hist_map)
        for n, chunk in enumerate(util.chunks(full_hist, max_row_size)):
            key = hashX + pack('>H', n)
            if hist_map.get(key) == chunk:
                keys_to_delete.remove(key)
            else:
                write_items.append((key, chunk))
                write_size += len(chunk)

        assert n + 1 == nrows
        self.comp_flush_count = max(self.comp_flush_count, n)

        return write_size

    def _compact_prefix(self, prefix, write_items, keys_to_delete):
        '''Compact all history entries for hashXs beginning with the
        given prefix.  Update keys_to_delete and write.'''
        prior_hashX = None
        hist_map = {}
        hist_list = []

        key_len = self.coin.HASHX_LEN + 2
        write_size = 0
        for key, hist in self.hist_db.iterator(prefix=prefix):
            # Ignore non-history entries
            if len(key) != key_len:
                continue
            hashX = key[:-2]
            if hashX != prior_hashX and prior_hashX:
                write_size += self._compact_hashX(prior_hashX, hist_map,
                                                  hist_list, write_items,
                                                  keys_to_delete)
                hist_map.clear()
                hist_list.clear()
            prior_hashX = hashX
            hist_map[key] = hist
            hist_list.append(hist)

        if prior_hashX:
            write_size += self._compact_hashX(prior_hashX, hist_map, hist_list,
                                              write_items, keys_to_delete)
        return write_size

    def _compact_history(self, limit):
        '''Inner loop of history compaction.  Loops until limit bytes have
        been processed.
        '''
        keys_to_delete = set()
        write_items = []   # A list of (key, value) pairs
        write_size = 0

        # Loop over 2-byte prefixes
        cursor = self.comp_cursor
        while write_size < limit and cursor < 65536:
            prefix = pack('>H', cursor)
            write_size += self._compact_prefix(prefix, write_items,
                                               keys_to_delete)
            cursor += 1

        max_rows = self.comp_flush_count + 1
        self._flush_compaction(cursor, write_items, keys_to_delete)

        self.logger.info('history compaction: wrote {:,d} rows ({:.1f} MB), '
                         'removed {:,d} rows, largest: {:,d}, {:.1f}% complete'
                         .format(len(write_items), write_size / 1000000,
                                 len(keys_to_delete), max_rows,
                                 100 * cursor / 65536))
        return write_size

    async def compact_history(self, loop):
        '''Start a background history compaction and reset the flush count if
        its getting high.
        '''
        # Do nothing if during initial sync or if a compaction hasn't
        # been initiated
        if self.first_sync or self.comp_cursor == -1:
            return

        self.comp_flush_count = max(self.comp_flush_count, 1)
        limit = 50 * 1000 * 1000

        while self.comp_cursor != -1:
            if self.semaphore.locked:
                self.logger.info('compact_history: waiting on semaphore...')
            async with self.semaphore:
                await loop.run_in_executor(None, self._compact_history, limit)

    def cancel_history_compaction(self):
        if self.comp_cursor != -1:
            self.logger.warning('cancelling in-progress history compaction')
            self.comp_flush_count = -1
            self.comp_cursor = -1

    # -- Sapling shielded database
    #
    # Key prefixes for Sapling data:
    # b'N' + nullifier (32 bytes) -> tx_num (4 bytes) + spend_index (2 bytes)
    # b'C' + commitment (32 bytes) -> tx_num (4 bytes) + output_index (2 bytes)
    #                                 + position (8 bytes)
    # b'P' + position (8 bytes, big-endian) -> tx_num + output_index
    #                                          + commitment
    # b'A' + anchor (32 bytes) -> block_height (4 bytes)
    # b'R' + indexed root (32 bytes) -> tree_size (8 bytes) + height (4 bytes)

    def sapling_nullifier_key(self, nullifier):
        '''Key for looking up a nullifier's spending tx.'''
        return b'N' + nullifier

    def sapling_commitment_key(self, commitment):
        '''Key for looking up a commitment's creating tx.'''
        return b'C' + commitment

    def sapling_anchor_key(self, anchor):
        '''Key for looking up an anchor's block height.'''
        return b'A' + anchor

    def sapling_position_key(self, position):
        '''Key for looking up a Sapling output by global position.'''
        return b'P' + pack('>Q', position)

    def sapling_root_key(self, root):
        '''Key for looking up indexed root metadata.'''
        return b'R' + root

    @staticmethod
    def sapling_leaf_hash(commitment):
        '''Hash a commitment into this index's witness tree leaf.'''
        return double_sha256(b'\x00' + commitment)

    @staticmethod
    def sapling_parent_hash(left, right):
        '''Hash two child nodes in this index's witness tree.'''
        return double_sha256(b'\x01' + left + right)

    @classmethod
    def sapling_empty_node(cls, level):
        '''Return the deterministic empty subtree hash for a level.'''
        node = b'\0' * 32
        for _ in range(level):
            node = cls.sapling_parent_hash(node, node)
        return node

    def get_nullifier_spend(self, nullifier):
        '''Return (tx_hash, height, spend_index) if nullifier is spent.

        Returns None if not spent.
        '''
        key = self.sapling_nullifier_key(nullifier)
        value = self.utxo_db.get(key)
        if value:
            tx_num, spend_index = unpack('<IH', value)
            tx_hash, height = self.fs_tx_hash(tx_num)
            return tx_hash, height, spend_index
        return None

    def get_commitment_info(self, commitment):
        '''Return (tx_hash, height, output_index) for a commitment.

        Returns None if commitment not found.
        '''
        key = self.sapling_commitment_key(commitment)
        value = self.utxo_db.get(key)
        if value:
            tx_num, output_index = unpack('<IH', value[:6])
            tx_hash, height = self.fs_tx_hash(tx_num)
            return tx_hash, height, output_index
        return None

    def get_commitment_position_info(self, commitment):
        '''Return output info for a commitment, including global position.'''
        key = self.sapling_commitment_key(commitment)
        value = self.utxo_db.get(key)
        if value:
            tx_num, output_index = unpack('<IH', value[:6])
            position = None
            if len(value) >= 14:
                position, = unpack('<Q', value[6:14])
            tx_hash, height = self.fs_tx_hash(tx_num)
            return SaplingOutputInfo(position, commitment, tx_hash, height,
                                     output_index)
        return None

    def get_sapling_output_by_position(self, position, pending_outputs=None):
        '''Return Sapling output info by global position.'''
        pending_outputs = pending_outputs or {}
        pending = pending_outputs.get(position)
        if pending:
            tx_num, output_index, commitment = pending
            tx_hash, height = self.fs_tx_hash(tx_num)
            return SaplingOutputInfo(position, commitment, tx_hash, height,
                                     output_index)

        value = self.utxo_db.get(self.sapling_position_key(position))
        if value:
            tx_num, output_index = unpack('<IH', value[:6])
            commitment = value[6:38]
            tx_hash, height = self.fs_tx_hash(tx_num)
            return SaplingOutputInfo(position, commitment, tx_hash, height,
                                     output_index)
        return None

    def iter_sapling_outputs(self, start_position=0, limit=None):
        '''Yield Sapling outputs in canonical global position order.'''
        limit = self._resolve_limit(limit)
        for key, value in self.utxo_db.iterator(prefix=b'P'):
            position, = unpack('>Q', key[1:9])
            if position < start_position:
                continue
            if limit == 0:
                return
            limit -= 1
            tx_num, output_index = unpack('<IH', value[:6])
            commitment = value[6:38]
            tx_hash, height = self.fs_tx_hash(tx_num)
            yield SaplingOutputInfo(position, commitment, tx_hash, height,
                                    output_index)

    def is_nullifier_spent(self, nullifier):
        '''Check if a nullifier has been spent.'''
        return self.get_nullifier_spend(nullifier) is not None

    def get_anchor_height(self, anchor):
        '''Return the block height where an anchor was valid.

        Returns None if anchor not found.
        '''
        key = self.sapling_anchor_key(anchor)
        value = self.utxo_db.get(key)
        if value:
            height, = unpack('<I', value)
            return height
        return None

    def get_sapling_root_info(self, root):
        '''Return (tree_size, height) for an indexed Sapling root.'''
        value = self.utxo_db.get(self.sapling_root_key(root))
        if value:
            tree_size, height = unpack('<QI', value)
            return tree_size, height
        return None

    def sapling_commitments_for_tree(self, tree_size, pending_outputs=None):
        '''Return commitments for the first tree_size global positions.'''
        commitments = []
        for position in range(tree_size):
            info = self.get_sapling_output_by_position(position,
                                                       pending_outputs)
            if info is None:
                raise self.DBError('missing Sapling output position {:,d}'
                                   .format(position))
            commitments.append(info.commitment)
        return commitments

    @classmethod
    def sapling_root_from_commitments(cls, commitments):
        '''Return the indexed witness root for commitments.'''
        if not commitments:
            return cls.sapling_empty_node(0)

        level = 0
        nodes = [cls.sapling_leaf_hash(commitment)
                 for commitment in commitments]
        while len(nodes) > 1:
            next_nodes = []
            empty = cls.sapling_empty_node(level)
            for n in range(0, len(nodes), 2):
                left = nodes[n]
                right = nodes[n + 1] if n + 1 < len(nodes) else empty
                next_nodes.append(cls.sapling_parent_hash(left, right))
            nodes = next_nodes
            level += 1
        return nodes[0]

    @classmethod
    def sapling_witness_path(cls, commitments, position):
        '''Return the Merkle path for position in commitments.'''
        if position < 0 or position >= len(commitments):
            raise IndexError('position outside commitment tree')

        path = []
        index = position
        level = 0
        nodes = [cls.sapling_leaf_hash(commitment)
                 for commitment in commitments]

        while len(nodes) > 1:
            is_right = index & 1
            sibling_index = index - 1 if is_right else index + 1
            if sibling_index < len(nodes):
                sibling = nodes[sibling_index]
            else:
                sibling = cls.sapling_empty_node(level)
            path.append({
                'position': 'left' if is_right else 'right',
                'hash': sibling.hex(),
            })

            next_nodes = []
            empty = cls.sapling_empty_node(level)
            for n in range(0, len(nodes), 2):
                left = nodes[n]
                right = nodes[n + 1] if n + 1 < len(nodes) else empty
                next_nodes.append(cls.sapling_parent_hash(left, right))
            nodes = next_nodes
            index >>= 1
            level += 1

        return path

    def get_sapling_witness(self, position, root=None):
        '''Return an anchor-bound witness for a Sapling output position.'''
        position = self._resolve_limit(position)
        if position < 0:
            raise self.DBError('invalid Sapling output position {:,d}'
                               .format(position))

        if root is None:
            tree_size = self.sapling_output_count
            root = self.sapling_root_from_commitments(
                self.sapling_commitments_for_tree(tree_size))
            height = self.db_height
        else:
            info = self.get_sapling_root_info(root)
            if info is None:
                return None
            tree_size, height = info

        if position >= tree_size:
            return None

        output_info = self.get_sapling_output_by_position(position)
        if output_info is None:
            return None

        commitments = self.sapling_commitments_for_tree(tree_size)
        calculated_root = self.sapling_root_from_commitments(commitments)
        if calculated_root != root:
            raise self.DBError('indexed Sapling root mismatch for witness')

        return {
            'anchor': root.hex(),
            'root': root.hex(),
            'anchor_height': height,
            'position': position,
            'path': self.sapling_witness_path(commitments, position),
            'commitment': output_info.commitment.hex(),
        }

    def flush_sapling_data(self, batch_put, sapling_adds, sapling_spends,
                           anchors, height):
        '''Flush Sapling data to the database.

        sapling_adds: list of (tx_num, output_index, commitment)
        sapling_spends: list of (tx_num, spend_index, nullifier)
        anchors: iterable of (anchor, block_height) pairs
        height: fallback block height for legacy anchor entries
        '''
        pending_outputs = {}
        roots_by_height = {}

        # Store commitments (note creations) in canonical block transaction /
        # Sapling output order.  That iteration order defines global position.
        for sapling_add in sapling_adds:
            if len(sapling_add) == 4:
                tx_num, output_index, cm, output_height = sapling_add
            else:
                tx_num, output_index, cm = sapling_add
                output_height = height
            position = self.sapling_output_count
            self.sapling_output_count += 1
            cm_key = self.sapling_commitment_key(cm)
            cm_value = pack('<IHQ', tx_num, output_index, position)
            batch_put(cm_key, cm_value)
            batch_put(self.sapling_position_key(position),
                      pack('<IH', tx_num, output_index) + cm)
            pending_outputs[position] = (tx_num, output_index, cm)
            roots_by_height[output_height] = position + 1

        for output_height in sorted(roots_by_height):
            tree_size = roots_by_height[output_height]
            commitments = self.sapling_commitments_for_tree(
                tree_size, pending_outputs)
            root = self.sapling_root_from_commitments(commitments)
            batch_put(self.sapling_root_key(root),
                      pack('<QI', tree_size, output_height))

        # Store nullifiers (note spends)
        for tx_num, spend_index, nullifier in sapling_spends:
            nf_key = self.sapling_nullifier_key(nullifier)
            nf_value = pack('<IH', tx_num, spend_index)
            batch_put(nf_key, nf_value)

        # Store anchors with the height of the block that referenced them.
        for anchor_info in anchors:
            if isinstance(anchor_info, tuple):
                anchor, anchor_height = anchor_info
            else:
                anchor, anchor_height = anchor_info, height
            if anchor_height is None:
                anchor_height = height
            anchor_key = self.sapling_anchor_key(anchor)
            batch_put(anchor_key, pack('<I', anchor_height))

    def backup_sapling_data(self, tx_count_start, batch_delete,
                            height_start=None):
        '''Remove Sapling data for transactions >= tx_count_start.

        Used during reorg handling.
        '''
        # We need to iterate and remove entries with tx_num >= tx_count_start
        # This is expensive but reorgs should be rare
        nf_removed = 0
        cm_removed = 0
        pos_removed = 0
        anchor_removed = 0
        root_removed = 0
        min_removed_position = None

        # Remove nullifiers
        for key, value in self.utxo_db.iterator(prefix=b'N'):
            if len(value) >= 4:
                tx_num, = unpack('<I', value[:4])
                if tx_num >= tx_count_start:
                    batch_delete(key)
                    nf_removed += 1

        # Remove commitments
        for key, value in self.utxo_db.iterator(prefix=b'C'):
            if len(value) >= 4:
                tx_num, = unpack('<I', value[:4])
                if tx_num >= tx_count_start:
                    if len(value) >= 14:
                        position, = unpack('<Q', value[6:14])
                        if (min_removed_position is None or
                                position < min_removed_position):
                            min_removed_position = position
                    batch_delete(key)
                    cm_removed += 1

        # Remove global position entries for reverted outputs.
        for key, value in self.utxo_db.iterator(prefix=b'P'):
            if len(value) >= 4:
                tx_num, = unpack('<I', value[:4])
                if tx_num >= tx_count_start:
                    position, = unpack('>Q', key[1:9])
                    if (min_removed_position is None or
                            position < min_removed_position):
                        min_removed_position = position
                    batch_delete(key)
                    pos_removed += 1

        # Remove anchors that were first seen in reverted blocks.  This keeps
        # anchor lookups aligned with the currently indexed branch.
        if height_start is not None:
            for key, value in self.utxo_db.iterator(prefix=b'A'):
                if len(value) >= 4:
                    height, = unpack('<I', value[:4])
                    if height >= height_start:
                        batch_delete(key)
                        anchor_removed += 1

            for key, value in self.utxo_db.iterator(prefix=b'R'):
                if len(value) >= 12:
                    tree_size, height = unpack('<QI', value[:12])
                    if height >= height_start:
                        batch_delete(key)
                        root_removed += 1

        if min_removed_position is not None:
            self.sapling_output_count = min_removed_position

        if (nf_removed or cm_removed or pos_removed or anchor_removed or
                root_removed):
            self.logger.info(f'sapling backup: removed {nf_removed} '
                             f'nullifiers, {cm_removed} commitments, '
                             f'{pos_removed} positions, '
                             f'{anchor_removed} anchors, '
                             f'{root_removed} roots')
