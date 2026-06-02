import asyncio
import logging
from unittest import mock

import pytest
from aiorpcx import RPCError

from lib.coins import Pivx, PivxTestnet
from server.db import DB
from server.daemon import DaemonError
from server.session import PIVXSaplingElectrumX, PIVX_SAPLING_MAX_BLOCK_RANGE


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


def make_sapling_db(tx_meta=None):
    db = object.__new__(DB)
    db.utxo_db = FakeKV()
    db.logger = mock.Mock()
    db.coin = Pivx
    db.db_height = 0
    db.db_tx_count = 0
    db.db_tip = b'\0' * 32
    db.db_version = 6
    db.utxo_flush_count = 0
    db.wall_time = 0
    db.first_sync = False
    db.sapling_output_count = 0
    tx_meta = tx_meta or {}
    db.fs_tx_hash = lambda tx_num: tx_meta[tx_num]
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
    kept_anchor = b'a' * 32
    removed_anchor = b'b' * 32
    tx_meta = {
        50: (b'K' * 32, 149),
        51: (b'L' * 32, 149),
        110: (b'R' * 32, 150),
        111: (b'S' * 32, 150),
    }
    db = make_sapling_db(tx_meta)

    db.flush_sapling_data(
        db.utxo_db.put,
        [(50, 0, kept_cm, 149), (110, 1, removed_cm, 150)],
        [(51, 0, kept_nf), (111, 0, removed_nf)],
        [(kept_anchor, 149), (removed_anchor, 150)],
        150,
    )
    kept_root = DB.sapling_root_from_commitments([kept_cm])
    removed_root = DB.sapling_root_from_commitments([kept_cm, removed_cm])

    deletes = []
    db.backup_sapling_data(100, deletes.append, height_start=150)
    apply_deletes(db, deletes)

    assert db.get_commitment_info(kept_cm) == (b'K' * 32, 149, 0)
    assert db.get_nullifier_spend(kept_nf) == (b'L' * 32, 149, 0)
    assert db.get_anchor_height(kept_anchor) == 149
    assert db.get_commitment_info(removed_cm) is None
    assert db.get_nullifier_spend(removed_nf) is None
    assert db.get_anchor_height(removed_anchor) is None
    assert db.get_sapling_output_by_position(0).commitment == kept_cm
    assert db.get_sapling_output_by_position(1) is None
    assert db.get_sapling_root_info(kept_root) == (1, 149)
    assert db.get_sapling_root_info(removed_root) is None
    assert db.sapling_output_count == 1


def test_reorg_can_respend_nullifier_on_different_branch():
    nullifier = b'x' * 32
    old_tx_hash = b'o' * 32
    new_tx_hash = b'p' * 32
    db = make_sapling_db({
        90: (old_tx_hash, 200),
        95: (new_tx_hash, 201),
    })

    db.flush_sapling_data(db.utxo_db.put, [], [(90, 0, nullifier)], [], 200)
    assert db.get_nullifier_spend(nullifier) == (old_tx_hash, 200, 0)

    deletes = []
    db.backup_sapling_data(90, deletes.append, height_start=200)
    apply_deletes(db, deletes)
    assert db.get_nullifier_spend(nullifier) is None

    db.flush_sapling_data(db.utxo_db.put, [], [(95, 1, nullifier)], [], 201)
    assert db.get_nullifier_spend(nullifier) == (new_tx_hash, 201, 1)


class FakeSaplingDaemon:

    def __init__(self, blocks=None):
        self.blocks = blocks

    async def daemon_request(self, method, args):
        if method == 'getblockhash':
            height, = args
            return f'{height:064x}'
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
        raise AssertionError(method)


def fake_tx(txid_num, cmus):
    return {
        'txid': f'{txid_num:064x}',
        'vShieldSpend': [],
        'vShieldOutput': [{
            'cmu': cmu,
            'ephemeralKey': '22' * 32,
            'encCiphertext': '33' * 580,
            'outCiphertext': '44' * 80,
        } for cmu in cmus],
    }


def make_session(db=None, daemon=None):
    session = object.__new__(PIVXSaplingElectrumX)
    session.controller = mock.Mock()
    session.controller.non_negative_integer.side_effect = lambda value: int(value)
    session.controller.coin = Pivx
    session.daemon = daemon or FakeSaplingDaemon()
    session.bp = db
    session.logger = logging.getLogger('test-pivx-sapling')
    return session


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


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


def test_outputs_by_height_include_block_hashes():
    session = make_session()

    outputs = run(session.sapling_get_outputs_by_height(1234, 1234))

    assert outputs == [{
        'tx_hash': f'{1235:064x}',
        'height': 1234,
        'block_hash': f'{1234:064x}',
        'position': None,
        'output_index': 0,
        'cmu': '11' * 32,
        'ephemeral_key': '22' * 32,
        'enc_ciphertext': '33' * 580,
        'out_ciphertext': '44' * 80,
    }]


def test_sapling_positions_remain_stable_across_restart():
    commitments = [bytes([n]) * 32 for n in range(3)]
    tx_meta = {
        10: (b'a' * 32, 100),
        11: (b'b' * 32, 100),
        12: (b'c' * 32, 101),
    }
    db = make_sapling_db(tx_meta)
    db.db_height = 101

    db.flush_sapling_data(
        db.utxo_db.put,
        [(10, 0, commitments[0], 100),
         (11, 1, commitments[1], 100),
         (12, 0, commitments[2], 101)],
        [],
        [],
        101,
    )
    db.write_utxo_state(db.utxo_db)

    restarted = make_sapling_db(tx_meta)
    restarted.utxo_db = db.utxo_db
    restarted.read_utxo_state()

    assert restarted.sapling_output_count == 3
    for position, commitment in enumerate(commitments):
        info = restarted.get_commitment_position_info(commitment)
        assert info.position == position
        assert restarted.get_sapling_output_by_position(position).commitment == commitment


def test_empty_blocks_do_not_consume_sapling_positions():
    db = make_sapling_db({
        20: (b'd' * 32, 200),
        21: (b'e' * 32, 202),
    })
    first = b'f' * 32
    second = b'g' * 32

    db.flush_sapling_data(db.utxo_db.put, [(20, 0, first, 200)], [], [], 200)
    db.flush_sapling_data(db.utxo_db.put, [], [], [], 201)
    db.flush_sapling_data(db.utxo_db.put, [(21, 0, second, 202)], [], [], 202)

    assert db.get_commitment_position_info(first).position == 0
    assert db.get_commitment_position_info(second).position == 1
    assert db.sapling_output_count == 2


def test_get_block_range_returns_canonical_output_order_with_positions():
    cmu_a = 'aa' * 32
    cmu_b = 'bb' * 32
    cmu_c = 'cc' * 32
    db = make_sapling_db({
        30: (bytes.fromhex('30' * 32), 300),
        31: (bytes.fromhex('31' * 32), 300),
    })
    db.flush_sapling_data(
        db.utxo_db.put,
        [(30, 0, bytes.fromhex(cmu_a), 300),
         (30, 1, bytes.fromhex(cmu_b), 300),
         (31, 0, bytes.fromhex(cmu_c), 300)],
        [],
        [],
        300,
    )
    daemon = FakeSaplingDaemon({
        300: {'tx': [fake_tx(30, [cmu_a, cmu_b]),
                     fake_tx(31, [cmu_c])]},
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


class FailingSaplingDaemon:

    def __init__(self, code=-1, message='daemon exploded',
                 fail_method='getblockhash', blocks=None):
        self.code = code
        self.message = message
        self.fail_method = fail_method
        self.blocks = blocks or {}

    async def daemon_request(self, method, args):
        if method == self.fail_method:
            raise DaemonError({'code': self.code, 'message': self.message})
        if method == 'getblockhash':
            height, = args
            return f'{height:064x}'
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
                          [(10, 0, bytes.fromhex(cmu), 300)], [], [], 300)
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
        [(10, 0, bytes.fromhex(cmu_indexed), 300)],
        [],
        [],
        300,
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

    capabilities = session.sapling_capabilities()

    assert capabilities['success'] is True
    assert capabilities['contract'] == 'pivx.sapling.electrumx.v1'
    assert 'blockchain.sapling.get_block_range' in capabilities['methods']
    assert capabilities['aliases']['blockchain.sapling.capabilities'] == [
        'blockchain.sapling.get_capabilities',
        'server.sapling.capabilities',
    ]
    assert capabilities['aliases']['blockchain.sapling.get_tree_state'] == [
        'blockchain.sapling.get_treestate',
    ]


def verify_indexed_witness(commitment_hex, position, path, root_hex):
    node = DB.sapling_leaf_hash(bytes.fromhex(commitment_hex))
    index = position
    for item in path:
        sibling = bytes.fromhex(item['hash'])
        if item['position'] == 'left':
            node = DB.sapling_parent_hash(sibling, node)
        else:
            node = DB.sapling_parent_hash(node, sibling)
        index >>= 1
    assert index == 0
    return node.hex() == root_hex


def test_sapling_witness_path_verifies_against_requested_anchor():
    commitments = [bytes([n]) * 32 for n in range(1, 5)]
    db = make_sapling_db({
        40: (b'h' * 32, 400),
        41: (b'i' * 32, 400),
        42: (b'j' * 32, 400),
        43: (b'k' * 32, 400),
    })
    db.db_height = 400
    db.flush_sapling_data(
        db.utxo_db.put,
        [(40 + n, 0, commitment, 400)
         for n, commitment in enumerate(commitments)],
        [],
        [],
        400,
    )
    root = DB.sapling_root_from_commitments(commitments)
    session = make_session(db)

    witness = run(session.sapling_get_witness(2, root.hex()))

    assert witness['anchor'] == root.hex()
    assert witness['root'] == root.hex()
    assert witness['anchor_height'] == 400
    assert witness['position'] == 2
    assert witness['commitment'] == commitments[2].hex()
    assert verify_indexed_witness(
        witness['commitment'], witness['position'], witness['path'],
        witness['root'])
