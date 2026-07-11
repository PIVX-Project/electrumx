import asyncio
import logging
import struct
from unittest import mock

import pytest
from aiorpcx import RPCError

from lib.coins import Pivx, PivxTestnet
from server.block_processor import BlockProcessor
from server.db import DB
from server.daemon import Daemon, DaemonError
from server.session import PIVXSaplingElectrumX, PIVX_SAPLING_MAX_BLOCK_RANGE


SAPLING_START = Pivx.SAPLING_START_HEIGHT


class FakeKV:

    def __init__(self):
        self.data = {}

    def get(self, key):
        return self.data.get(key)

    def put(self, key, value):
        self.data[key] = value

    def delete(self, key):
        self.data.pop(key, None)

    def iterator(self, prefix=b'', reverse=False):
        items = [(key, value) for key, value in self.data.items()
                 if key.startswith(prefix)]
        return iter(sorted(items, reverse=reverse))


def make_header(height, root):
    '''A 112-byte Sapling-era header whose finalsaplingroot is root.'''
    return (struct.pack('<I', 11) + b'\x11' * 64
            + struct.pack('<III', 1, 2, 3) + root)


def make_sapling_db(tx_meta=None, height=SAPLING_START, headers=None):
    db = object.__new__(DB)
    db.utxo_db = FakeKV()
    db.logger = mock.Mock()
    db.coin = Pivx
    db.db_height = height
    db.db_tx_count = 0
    db.db_tip = b'\0' * 32
    db.db_version = 6
    db.utxo_flush_count = 0
    db.wall_time = 0
    db.first_sync = False
    db.sapling_output_count = 0
    db.db_sapling_output_count = 0
    tx_meta = tx_meta or {}
    db.fs_tx_hash = lambda tx_num: tx_meta[tx_num]
    db.fs_block_hashes = lambda h, count: [
        bytes.fromhex(f'{n:064x}')[::-1] for n in range(h, h + count)]
    headers = headers or {}

    def read_headers(start, count):
        assert count == 1
        header = headers.get(start)
        if header is None or start > db.db_height:
            return b'', 0
        return header, 1

    db.read_headers = read_headers
    return db


def apply_deletes(db, keys):
    for key in keys:
        db.utxo_db.delete(key)


def test_pivx_sapling_rollback_policy_and_activation_heights():
    assert Pivx.REORG_LIMIT >= 100
    assert Pivx.SAPLING_START_HEIGHT == 2700500
    assert PivxTestnet.SAPLING_START_HEIGHT == 201


def test_sapling_reorg_removes_outputs_spends_and_anchors():
    kept_cm = b'c' * 32
    removed_cm = b'd' * 32
    kept_nf = b'n' * 32
    removed_nf = b'o' * 32
    kept_root = b'a' * 32
    removed_root = b'b' * 32
    tx_meta = {
        50: (b'K' * 32, 149),
        51: (b'L' * 32, 149),
        110: (b'R' * 32, 150),
        111: (b'S' * 32, 150),
    }
    db = make_sapling_db(tx_meta)

    db.flush_sapling_data(
        db.utxo_db.put,
        [(50, 0, kept_cm, 0), (110, 1, removed_cm, 1)],
        [(51, 0, kept_nf), (111, 0, removed_nf)],
        [(kept_root, 149, 1), (removed_root, 150, 2)],
    )
    db.sapling_output_count = 2
    db.db_sapling_output_count = 2

    deletes = []
    db.backup_sapling_data(100, deletes.append, height_start=150)
    apply_deletes(db, deletes)

    assert db.get_commitment_info(kept_cm) == (b'K' * 32, 149, 0)
    assert db.get_nullifier_spend(kept_nf) == (b'L' * 32, 149, 0)
    assert db.get_anchor_height(kept_root) == 149
    assert db.get_sapling_anchor_info(kept_root) == (149, 1)
    assert db.get_commitment_info(removed_cm) is None
    assert db.get_nullifier_spend(removed_nf) is None
    assert db.get_anchor_height(removed_root) is None
    assert db.get_commitment_position_info(kept_cm).position == 0
    assert db.get_commitment_position_info(removed_cm) is None
    assert db.sapling_output_count == 1
    assert db.db_sapling_output_count == 1


def test_reorg_can_respend_nullifier_on_different_branch():
    nullifier = b'x' * 32
    old_tx_hash = b'o' * 32
    new_tx_hash = b'p' * 32
    db = make_sapling_db({
        90: (old_tx_hash, 200),
        95: (new_tx_hash, 201),
    })

    db.flush_sapling_data(db.utxo_db.put, [], [(90, 0, nullifier)], [])
    assert db.get_nullifier_spend(nullifier) == (old_tx_hash, 200, 0)

    deletes = []
    db.backup_sapling_data(90, deletes.append, height_start=200)
    apply_deletes(db, deletes)
    assert db.get_nullifier_spend(nullifier) is None

    db.flush_sapling_data(db.utxo_db.put, [], [(95, 1, nullifier)], [])
    assert db.get_nullifier_spend(nullifier) == (new_tx_hash, 201, 1)


def test_anchor_reused_at_later_height_survives_reorg_of_that_height():
    '''A root first seen at height H, still current at H+n, must survive
    a reorg that reverts H+n (first-seen semantics).'''
    root = b'r' * 32
    db = make_sapling_db()

    db.flush_sapling_data(db.utxo_db.put, [], [], [(root, 100, 5)])
    # The same root appearing later must not overwrite first-seen data
    db.flush_sapling_data(db.utxo_db.put, [], [], [(root, 120, 5)])
    assert db.get_sapling_anchor_info(root) == (100, 5)

    deletes = []
    db.backup_sapling_data(10**9, deletes.append, height_start=110)
    apply_deletes(db, deletes)
    assert db.get_sapling_anchor_info(root) == (100, 5)


class FakeSaplingDaemon:

    def __init__(self, blocks=None):
        self.blocks = blocks

    async def daemon_request(self, method, args):
        if method == 'getblock':
            block_hash, verbosity = args
            assert verbosity == 2
            height = int(block_hash, 16)
            if self.blocks is not None:
                return self.blocks.get(height, {'tx': []})
            return {'tx': [fake_tx(height + 1, ['11' * 32])]}
        if method == 'getrawtransaction':
            txid, = args
            return '03' + txid[-2:]
        if method == 'getnetworkinfo':
            return {
                'version': 5060100,
                'subversion': '/PIVX Core:5.6.1/',
            }
        raise AssertionError(method)


def fake_tx(txid_num, cmus, tx_hex=None):
    tx = {
        'txid': f'{txid_num:064x}',
        'vShieldSpend': [],
        'vShieldOutput': [{
            'cmu': cmu,
            'ephemeralKey': '22' * 32,
            'encCiphertext': '33' * 580,
            'outCiphertext': '44' * 80,
        } for cmu in cmus],
    }
    if tx_hex is not None:
        tx['hex'] = tx_hex
    return tx


def make_session(db=None, daemon=None):
    session = object.__new__(PIVXSaplingElectrumX)
    session.controller = mock.Mock()
    session.controller.non_negative_integer.side_effect = \
        lambda value: int(value)
    session.controller.coin = Pivx
    session.controller.VERSION = 'ElectrumX 1.4.3'
    session.controller.short_version.return_value = '1.4.3'

    async def run_in_executor(func, *args):
        return func(*args)

    session.controller.run_in_executor = run_in_executor
    session.daemon = daemon or FakeSaplingDaemon()
    session.bp = db if db is not None else make_sapling_db(height=10**7)
    session.logger = logging.getLogger('test-pivx-sapling')
    return session


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_daemon_raw_rpc_passthrough_supports_sapling_methods():
    daemon = object.__new__(Daemon)
    calls = []

    async def send_single(method, params=None):
        calls.append((method, params))
        return {'ok': True}

    daemon._send_single = send_single

    result = run(daemon.daemon_request('getblock', ['00' * 32, 2]))

    assert result == {'ok': True}
    assert calls == [('getblock', ['00' * 32, 2])]


def test_client_can_rescan_full_pivx_rollback_boundary_with_hashes():
    tip = 2000
    start = tip - PIVX_SAPLING_MAX_BLOCK_RANGE + 1
    daemon = FakeSaplingDaemon({
        height: {'tx': []}
        for height in range(start, tip + 1)
    })
    session = make_session(daemon=daemon)

    response = run(session.sapling_get_block_range(start, tip))

    assert response['success'] is True
    assert response['complete'] is True
    assert response['empty'] is True
    assert response['start_height'] == start
    assert response['end_height'] == tip
    assert response['height_count'] == PIVX_SAPLING_MAX_BLOCK_RANGE
    assert response['block_hashes'] == [
        {'height': height, 'block_hash': f'{height:064x}'}
        for height in range(start, tip + 1)
    ]
    assert response['blocks'] == []
    assert response['error'] is None

    stale_local_hashes = {
        height: f'{height:064x}'
        for height in range(start, tip + 1)
    }
    stale_local_hashes[start + 7] = 'ff' * 32
    mismatches = [
        item['height']
        for item in response['block_hashes']
        if stale_local_hashes[item['height']] != item['block_hash']
    ]
    assert mismatches == [start + 7]


def test_sapling_range_rejects_more_than_rollback_boundary():
    session = make_session()
    tip = 2000
    start = tip - PIVX_SAPLING_MAX_BLOCK_RANGE

    response = run(session.sapling_get_block_range(start, tip))

    assert response['success'] is False
    assert response['complete'] is False
    assert response['error']['type'] == 'invalid_range'
    assert response['error']['max_block_range'] == PIVX_SAPLING_MAX_BLOCK_RANGE


def test_sapling_range_rejects_heights_above_indexed_tip():
    db = make_sapling_db(height=500)
    session = make_session(db)

    response = run(session.sapling_get_block_range(495, 505))

    assert response['success'] is False
    assert response['complete'] is False
    assert response['error']['type'] == 'index_incomplete'
    assert response['error']['indexed_height'] == 500


def test_outputs_by_height_include_block_hashes_and_positions():
    # Asymmetric bytes so a missing/double reversal cannot pass
    cmu_raw = bytes(range(32))
    cmu_display = cmu_raw[::-1].hex()
    db = make_sapling_db({77: (b'x' * 32, 1234)})
    db.flush_sapling_data(db.utxo_db.put, [(77, 0, cmu_raw, 6)], [], [])
    daemon = FakeSaplingDaemon({1234: {'tx': [fake_tx(1235,
                                                      [cmu_display])]}})
    session = make_session(db, daemon)

    outputs = run(session.sapling_get_outputs_by_height(1234, 1234))

    assert outputs == [{
        'tx_hash': f'{1235:064x}',
        'height': 1234,
        'block_hash': f'{1234:064x}',
        'position': 6,
        'output_index': 0,
        'cmu': cmu_display,
        'ephemeral_key': '22' * 32,
        'enc_ciphertext': '33' * 580,
        'out_ciphertext': '44' * 80,
    }]


def test_outputs_by_height_fails_on_unindexed_commitment():
    # The default daemon serves a commitment the index does not know
    session = make_session()

    with pytest.raises(RPCError, match='not indexed'):
        run(session.sapling_get_outputs_by_height(1234, 1234))


def test_outputs_by_height_rejects_over_limit_and_above_tip():
    db = make_sapling_db(height=500)
    session = make_session(db)

    with pytest.raises(RPCError):
        run(session.sapling_get_outputs_by_height(400, 400, limit=5001))
    with pytest.raises(RPCError):
        run(session.sapling_get_outputs_by_height(499, 501))


def test_sapling_positions_remain_stable_across_restart():
    commitments = [bytes([n]) * 32 for n in range(3)]
    tx_meta = {
        10: (b'a' * 32, 100),
        11: (b'b' * 32, 100),
        12: (b'c' * 32, 101),
    }
    db = make_sapling_db(tx_meta, height=101)

    db.flush_sapling_data(
        db.utxo_db.put,
        [(10, 0, commitments[0], 0),
         (11, 1, commitments[1], 1),
         (12, 0, commitments[2], 2)],
        [],
        [],
    )
    db.sapling_output_count = 3
    db.db_sapling_output_count = 3
    db.write_utxo_state(db.utxo_db)

    restarted = make_sapling_db(tx_meta)
    restarted.utxo_db = db.utxo_db
    restarted.read_utxo_state()

    assert restarted.sapling_output_count == 3
    assert restarted.db_sapling_output_count == 3
    for position, commitment in enumerate(commitments):
        info = restarted.get_commitment_position_info(commitment)
        assert info.position == position


def test_db_synced_past_activation_without_sapling_index_is_rejected():
    '''A pre-Sapling-index DB past activation must force a resync, not
    serve wrong positions.'''
    db = make_sapling_db(height=SAPLING_START + 10)
    state = {
        'genesis': Pivx.GENESIS_HASH,
        'height': SAPLING_START + 10,
        'tx_count': 1000,
        'tip': b'\0' * 32,
        'utxo_flush_count': 1,
        'wall_time': 1,
        'first_sync': False,
        'db_version': 6,
    }
    db.utxo_db.put(b'state', repr(state).encode())

    with pytest.raises(Exception, match='resync'):
        db.read_utxo_state()


class FakeBlockProcessor(BlockProcessor):
    '''BlockProcessor with just enough state for advance_txs and
    advance_sapling_anchor.'''

    def __init__(self):
        self.coin = Pivx
        self.logger = mock.Mock()
        self.tx_hashes = []
        self.history = {}
        self.history_size = 0
        self.tx_count = 0
        self.tx_counts = []
        self.utxo_cache = {}
        self.touched = set()
        self.sapling_cache = {'adds': [], 'spends': [], 'anchors': []}
        self._last_sapling_root = None
        self.sapling_output_count = 0

    def spend_utxo(self, prev_hash, prev_idx):
        raise AssertionError('no transparent spends in this test')


def make_shielded_tx(cmus, nullifiers=()):
    from lib.tx import TxPIVXSapling, SaplingSpend, SaplingOutput
    spends = [SaplingSpend(b'\0' * 32, b'\0' * 32, nf, b'\0' * 32,
                           b'\0' * 192, b'\0' * 64) for nf in nullifiers]
    outputs = [SaplingOutput(b'\0' * 32, cmu, b'\0' * 32, b'\0' * 580,
                             b'\0' * 80, b'\0' * 192) for cmu in cmus]
    return TxPIVXSapling(3, 0, [], [], 0, 0, spends, outputs, b'\0' * 64,
                         b'')


def test_advance_assigns_positions_and_records_first_seen_anchors():
    bp = FakeBlockProcessor()
    root_a = b'A' * 32
    root_b = b'B' * 32
    cm1, cm2, cm3 = (bytes([n]) * 32 for n in (1, 2, 3))

    height = SAPLING_START
    bp.advance_txs([(make_shielded_tx([cm1, cm2]), b'\x01' * 32)])
    bp.advance_sapling_anchor(make_header(height, root_a), height)

    # A block with no Sapling activity repeats the root: not re-recorded
    bp.advance_txs([(make_shielded_tx([]), b'\x02' * 32)])
    bp.advance_sapling_anchor(make_header(height + 1, root_a), height + 1)

    bp.advance_txs([(make_shielded_tx([cm3], [b'\xaa' * 32]),
                     b'\x03' * 32)])
    bp.advance_sapling_anchor(make_header(height + 2, root_b), height + 2)

    adds = bp.sapling_cache['adds']
    assert [(add[2], add[3]) for add in adds] == [
        (cm1, 0), (cm2, 1), (cm3, 2)]
    assert bp.sapling_output_count == 3
    assert bp.sapling_cache['spends'] == [(2, 0, b'\xaa' * 32)]
    assert bp.sapling_cache['anchors'] == [
        (root_a, height, 2), (root_b, height + 2, 3)]


def test_advance_ignores_headers_below_sapling_activation():
    bp = FakeBlockProcessor()
    bp.advance_sapling_anchor(b'\x00' * 80, 2500000)
    bp.advance_sapling_anchor(make_header(100, b'r' * 32), 100)
    assert bp.sapling_cache['anchors'] == []


def test_get_block_range_returns_canonical_output_order_with_positions():
    # Raw index bytes are asymmetric; the daemon serves display-order
    # hex, so this fails if the session reverses zero or two times
    raw_a = bytes(range(0, 32))
    raw_b = bytes(range(32, 64))
    raw_c = bytes(range(64, 96))
    cmu_a = raw_a[::-1].hex()
    cmu_b = raw_b[::-1].hex()
    cmu_c = raw_c[::-1].hex()
    db = make_sapling_db({
        30: (bytes.fromhex('30' * 32), 300),
        31: (bytes.fromhex('31' * 32), 300),
    })
    db.flush_sapling_data(
        db.utxo_db.put,
        [(30, 0, raw_a, 0),
         (30, 1, raw_b, 1),
         (31, 0, raw_c, 2)],
        [],
        [],
    )
    daemon = FakeSaplingDaemon({
        300: {'tx': [fake_tx(30, [cmu_a, cmu_b], tx_hex='beef01'),
                     fake_tx(31, [cmu_c], tx_hex='beef02')]},
    })
    session = make_session(db, daemon)

    response = run(session.sapling_get_block_range(300, 300))

    assert response['success'] is True
    blocks = response['blocks']
    outputs = blocks[0]['outputs']
    assert [(output['position'], output['output_index'], output['cmu'])
            for output in outputs] == [
                (0, 0, cmu_a),
                (1, 1, cmu_b),
                (2, 0, cmu_c),
            ]
    assert [(output['tx_index'], output['txid']) for output in outputs] == [
        (0, f'{30:064x}'),
        (0, f'{30:064x}'),
        (1, f'{31:064x}'),
    ]
    # tx hex comes from the decoded block, not getrawtransaction
    assert [tx['hex'] for tx in blocks[0]['txs']] == ['beef01', 'beef02']


class FailingSaplingDaemon:

    def __init__(self, code=-1, message='daemon exploded',
                 fail_method='getblock', blocks=None):
        self.code = code
        self.message = message
        self.fail_method = fail_method
        self.blocks = blocks or {}

    async def daemon_request(self, method, args):
        if method == self.fail_method:
            raise DaemonError({'code': self.code, 'message': self.message})
        if method == 'getblock':
            block_hash, _verbosity = args
            return self.blocks.get(int(block_hash, 16), {'tx': []})
        if method == 'getrawtransaction':
            txid, = args
            return '03' + txid[-2:]
        raise AssertionError(method)


def test_get_block_range_returns_structured_daemon_failure():
    session = make_session(daemon=FailingSaplingDaemon(
        code=-5, message='block height out of range'))

    response = run(session.sapling_get_block_range(300, 300))

    assert response['success'] is False
    assert response['complete'] is False
    assert response['empty'] is False
    assert response['blocks'] == []
    assert response['error'] == {
        'type': 'daemon_error',
        'code': -5,
        'message': 'block height out of range',
    }


def test_get_block_range_returns_structured_unsupported_method_failure():
    cmu = 'aa' * 32
    db = make_sapling_db({10: (bytes.fromhex('10' * 32), 300)})
    db.flush_sapling_data(db.utxo_db.put,
                          [(10, 0, bytes.fromhex(cmu), 0)], [], [])
    # The decoded block has no per-tx hex, forcing the
    # getrawtransaction fallback, which fails
    daemon = FailingSaplingDaemon(
        code=-32601, message='Method not found',
        fail_method='getrawtransaction',
        blocks={300: {'tx': [fake_tx(10, [cmu])]}})
    session = make_session(db, daemon)

    response = run(session.sapling_get_block_range(300, 300))

    assert response['success'] is False
    assert response['complete'] is False
    assert response['error']['type'] == 'method_unavailable'
    assert response['error']['code'] == -32601


def test_get_block_range_invalid_range_is_structured_failure():
    session = make_session()

    response = run(session.sapling_get_block_range(301, 300))

    assert response['success'] is False
    assert response['complete'] is False
    assert response['blocks'] == []
    assert response['error']['type'] == 'invalid_range'
    assert 'end_height' in response['error']['message']


def test_get_block_range_never_marks_partial_index_incomplete_complete():
    cmu_indexed = 'aa' * 32
    cmu_missing = 'bb' * 32
    db = make_sapling_db({10: (bytes.fromhex('10' * 32), 300)})
    db.flush_sapling_data(
        db.utxo_db.put,
        [(10, 0, bytes.fromhex(cmu_indexed), 0)],
        [],
        [],
    )
    daemon = FakeSaplingDaemon({
        300: {'tx': [fake_tx(10, [cmu_indexed])]},
        301: {'tx': [fake_tx(11, [cmu_missing])]},
    })
    session = make_session(db, daemon)

    response = run(session.sapling_get_block_range(300, 301))

    assert response['success'] is False
    assert response['complete'] is False
    assert response['empty'] is False
    assert len(response['blocks']) == 1
    assert response['blocks'][0]['height'] == 300
    assert response['error']['type'] == 'index_incomplete'
    assert response['error']['height'] == 301
    assert response['error']['commitment'] == cmu_missing


def test_capabilities_include_cake_wallet_method_aliases():
    session = make_session()

    capabilities = run(session.sapling_capabilities())

    assert capabilities['success'] is True
    assert capabilities['contract'] == 'pivx.sapling.electrumx.v1'
    assert capabilities['server_version'] == 'ElectrumX 1.4.3'
    assert capabilities['server_short_version'] == '1.4.3'
    assert capabilities['pivx_core_version'] == '5.6.1'
    assert capabilities['pivx_core_version_number'] == 5060100
    assert capabilities['pivx_core_subversion'] == '/PIVX Core:5.6.1/'
    assert capabilities['reorg_limit'] >= 100
    assert capabilities['response_order'] == 'ascending_height'
    assert capabilities['output_order'] == (
        'pivx_core_block_transaction_vshieldoutput')
    assert capabilities['includes_global_output_positions'] is True
    assert capabilities['block_hashes'] is True
    assert capabilities['structured_errors'] is True
    # Witnesses are client-side; the server serves consensus anchors
    assert capabilities['anchor_bound_witnesses'] is False
    assert capabilities['server_side_witnesses'] is False
    assert capabilities['consensus_anchors'] is True
    assert capabilities['anchor_tree_size'] is True
    assert capabilities['hex_byte_order'] == 'display'
    assert 'blockchain.sapling.get_block_range' in capabilities['methods']
    assert 'blockchain.sapling.get_witness' not in capabilities['methods']
    assert 'blockchain.sapling.get_witnesses' not in capabilities['methods']
    assert capabilities['aliases']['blockchain.sapling.capabilities'] == [
        'blockchain.sapling.get_capabilities',
        'server.sapling.capabilities',
    ]
    assert capabilities['aliases']['blockchain.sapling.get_block_range'] == [
        'blockchain.sapling.get_blocks',
        'get_block_range',
        'sapling.get_block_range',
    ]
    assert capabilities['aliases']['blockchain.sapling.get_nullifier_status'] == [
        'blockchain.sapling.check_nullifier',
        'blockchain.nullifier.get_spend',
    ]
    assert capabilities['aliases']['blockchain.sapling.get_commitment_info'] == [
        'blockchain.sapling.get_commitment',
        'blockchain.commitment.get_info',
    ]
    assert capabilities['aliases']['blockchain.sapling.get_anchor_height'] == [
        'blockchain.anchor.get_height',
    ]
    assert capabilities['aliases']['blockchain.sapling.get_tree_state'] == [
        'blockchain.sapling.get_treestate',
    ]


def test_witness_methods_return_clear_unsupported_error():
    session = make_session()

    with pytest.raises(RPCError, match='witnesses are not supported'):
        run(session.sapling_get_witness(2, 'aa' * 32))
    with pytest.raises(RPCError, match='witnesses are not supported'):
        run(session.sapling_get_witnesses([1, 2]))


def test_tree_state_serves_header_anchor_and_tree_size():
    height = SAPLING_START + 50
    root = bytes(range(32))
    db = make_sapling_db(height=height,
                         headers={height: make_header(height, root)})
    db.flush_sapling_data(db.utxo_db.put, [], [],
                          [(root, height - 3, 7)])
    session = make_session(db)

    state = run(session.sapling_get_tree_state(height))

    assert state['success'] is True
    assert state['height'] == height
    assert state['anchor'] == root[::-1].hex()  # display byte order
    assert state['root'] == state['anchor']
    assert state['tree_size'] == 7
    assert state['anchor_first_height'] == height - 3
    assert state['indexed_height'] == height
    assert state['block_hash'] == f'{height:064x}'


def test_tree_state_rejects_heights_outside_index():
    height = SAPLING_START + 50
    db = make_sapling_db(height=height)
    session = make_session(db)

    above = run(session.sapling_get_tree_state(height + 1))
    assert above['success'] is False
    assert above['error']['type'] == 'index_incomplete'

    below = run(session.sapling_get_tree_state(SAPLING_START - 1))
    assert below['success'] is False
    assert below['error']['type'] == 'invalid_range'


def test_best_anchor_comes_from_indexed_tip_header():
    height = SAPLING_START + 9
    root = b'\x0f' * 32
    db = make_sapling_db(height=height,
                         headers={height: make_header(height, root)})
    db.flush_sapling_data(db.utxo_db.put, [], [], [(root, height, 42)])
    session = make_session(db)

    best = run(session.sapling_get_best_anchor())

    assert best['anchor'] == root[::-1].hex()
    assert best['height'] == height
    assert best['tree_size'] == 42
    assert best['block_hash'] == f'{height:064x}'


def test_best_anchor_fails_when_anchor_index_incomplete():
    height = SAPLING_START + 9
    root = bytes(range(32))
    db = make_sapling_db(height=height,
                         headers={height: make_header(height, root)})
    session = make_session(db)

    with pytest.raises(RPCError, match='resync'):
        run(session.sapling_get_best_anchor())


def test_anchor_height_accepts_display_order_hex():
    root = bytes(range(32))
    db = make_sapling_db()
    db.flush_sapling_data(db.utxo_db.put, [], [], [(root, 123, 4)])
    session = make_session(db)

    # Client passes display-order hex (as shown by PIVX Core RPC)
    assert run(session.sapling_get_anchor_height(root[::-1].hex())) == 123
    # Unknown root
    assert run(session.sapling_get_anchor_height('ee' * 32)) is None
    with pytest.raises(RPCError):
        run(session.sapling_get_anchor_height('zz'))


def test_check_nullifiers_and_status_use_display_order():
    nullifier = bytes(range(32))
    spend_tx_hash = b's' * 32
    db = make_sapling_db({70: (spend_tx_hash, 400)})
    db.flush_sapling_data(db.utxo_db.put, [], [(70, 1, nullifier)], [])
    session = make_session(db)

    display_hex = nullifier[::-1].hex()
    status = run(session.sapling_get_nullifier_status(display_hex))
    assert status['spent'] is True
    assert status['height'] == 400
    assert status['spend_index'] == 1
    assert status['tx_hash'] == spend_tx_hash[::-1].hex()

    batch = run(session.sapling_check_nullifiers(
        [display_hex, 'dd' * 32]))
    assert batch['success'] is True
    assert batch['results'][display_hex]['spent'] is True
    assert batch['results']['dd' * 32]['spent'] is False

    with pytest.raises(RPCError):
        run(session.sapling_check_nullifiers(['not-hex']))
    with pytest.raises(RPCError):
        run(session.sapling_check_nullifiers(['aa' * 32] * 1001))


def test_commitment_info_returns_position_and_display_hashes():
    commitment = bytes(range(32, 64))
    create_tx_hash = b't' * 32
    db = make_sapling_db({80: (create_tx_hash, 500)})
    db.flush_sapling_data(db.utxo_db.put,
                          [(80, 2, commitment, 9)], [], [])
    session = make_session(db)

    info = run(session.sapling_get_commitment_info(commitment[::-1].hex()))
    assert info == {
        'found': True,
        'tx_hash': create_tx_hash[::-1].hex(),
        'height': 500,
        'block_hash': f'{500:064x}',
        'position': 9,
        'output_index': 2,
    }
    assert run(session.sapling_get_commitment_info('ab' * 32)) == {
        'found': False}
