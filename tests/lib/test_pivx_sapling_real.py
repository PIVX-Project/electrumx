#
# Tests of PIVX Sapling transaction parsing with real block data
#
# These tests use actual PIVX mainnet block data containing Sapling transactions
# to verify the DeserializerPIVXSapling correctly parses shielded components.
#

import json
import os
from binascii import unhexlify

import pytest

# Import only the tx module which has minimal dependencies
import lib.tx as lib_tx
from lib.hash import double_sha256

# Go up from tests/lib/ to tests/blocks/
BLOCKS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'blocks')


# PIVX block header is 112 bytes:
# version(4) + prev_hash(32) + merkle_root(32) + time(4) + bits(4) + nonce(4) +
# finalsaplingroot(32)
PIVX_BLOCK_HEADER_SIZE = 112


def load_block_data(filename):
    """Load block test data from JSON file."""
    filepath = os.path.join(BLOCKS_DIR, filename)
    with open(filepath) as f:
        return json.load(f)


def parse_block_transactions(block_hex):
    """Parse transactions from full block hex.
    
    Returns list of (tx, tx_hash) tuples.
    """
    raw_block = unhexlify(block_hex)
    
    # Skip block header (112 bytes for PIVX)
    cursor = PIVX_BLOCK_HEADER_SIZE
    
    # Read varint for transaction count
    tx_count, varint_size = read_varint(raw_block, cursor)
    cursor += varint_size
    
    # Parse each transaction
    parsed_txs = []
    for _ in range(tx_count):
        # Find transaction end by parsing it
        tx_start = cursor
        deser = lib_tx.DeserializerPIVXSapling(raw_block[cursor:])
        tx = deser.read_tx()
        tx_size = deser.cursor
        cursor += tx_size
        
        # Compute tx hash from raw transaction bytes
        raw_tx = raw_block[tx_start:cursor]
        tx_hash = double_sha256(raw_tx)
        parsed_txs.append((tx, tx_hash, raw_tx))
    
    return parsed_txs


def read_varint(data, cursor):
    """Read a Bitcoin-style varint from data at cursor position.
    
    Returns (value, bytes_consumed).
    """
    first_byte = data[cursor]
    if first_byte < 0xfd:
        return first_byte, 1
    elif first_byte == 0xfd:
        return int.from_bytes(data[cursor+1:cursor+3], 'little'), 3
    elif first_byte == 0xfe:
        return int.from_bytes(data[cursor+1:cursor+5], 'little'), 5
    else:
        return int.from_bytes(data[cursor+1:cursor+9], 'little'), 9


class TestDeserializerPIVXSaplingReal:
    """Test PIVX Sapling deserializer with real mainnet data."""

    def test_pivx_mainnet_2703076_block_parse(self):
        """Test parsing PIVX mainnet block 2703076."""
        block_data = load_block_data('pivx_mainnet_2703076.json')
        
        # Parse transactions from full block hex
        parsed_txs = parse_block_transactions(block_data['hex'])
        
        assert len(parsed_txs) == len(block_data['tx'])
        
        # Verify transaction hashes match expected
        for i, (tx, tx_hash, raw_tx) in enumerate(parsed_txs):
            # txids are in display order (reversed)
            expected_hash = bytes.fromhex(block_data['tx'][i])[::-1]
            assert tx_hash == expected_hash, f"TX {i} hash mismatch"

    def test_pivx_sapling_tx_structure(self):
        """Test that parsed Sapling transactions have correct structure."""
        block_data = load_block_data('pivx_mainnet_2703076.json')
        
        # Parse transactions from block
        parsed_txs = parse_block_transactions(block_data['hex'])
        
        for i, (tx, tx_hash, raw_tx) in enumerate(parsed_txs):
            # Verify it's a TxPIVXSapling object
            assert hasattr(tx, 'version')
            assert hasattr(tx, 'tx_type')
            assert hasattr(tx, 'inputs')
            assert hasattr(tx, 'outputs')
            assert hasattr(tx, 'locktime')
            
            # For v3+ transactions, verify Sapling fields exist
            if tx.version >= 3:
                assert hasattr(tx, 'value_balance')
                assert hasattr(tx, 'sapling_spends')
                assert hasattr(tx, 'sapling_outputs')
                assert hasattr(tx, 'binding_sig')
                
                # Verify lists are properly typed
                assert isinstance(tx.sapling_spends, list)
                assert isinstance(tx.sapling_outputs, list)


class TestSaplingComponentParsing:
    """Test individual Sapling component parsing."""

    def test_sapling_spend_parsing(self):
        """Test parsing a raw Sapling spend description."""
        # Create a mock 384-byte spend description
        # cv(32) + anchor(32) + nullifier(32) + rk(32) + zkproof(192) + spend_auth_sig(64)
        cv = bytes(range(32))
        anchor = bytes(range(32, 64))
        nullifier = bytes(range(64, 96))
        rk = bytes(range(96, 128))
        zkproof = bytes(range(192))
        spend_auth_sig = bytes(range(64))
        
        spend_data = cv + anchor + nullifier + rk + zkproof + spend_auth_sig
        assert len(spend_data) == 384
        
        deser = lib_tx.DeserializerPIVXSapling(spend_data)
        spend = deser._read_sapling_spend()
        
        assert spend.cv == cv
        assert spend.anchor == anchor
        assert spend.nullifier == nullifier
        assert spend.rk == rk
        assert spend.zkproof == zkproof
        assert spend.spend_auth_sig == spend_auth_sig

    def test_sapling_output_parsing(self):
        """Test parsing a raw Sapling output description."""
        # Create a mock 948-byte output description
        # cv(32) + cmu(32) + ephemeral_key(32) + enc_ciphertext(580) + out_ciphertext(80) + zkproof(192)
        cv = bytes(range(32))
        cmu = bytes(range(32, 64))
        ephemeral_key = bytes(range(64, 96))
        enc_ciphertext = bytes(580)
        out_ciphertext = bytes(80)
        zkproof = bytes(192)
        
        output_data = cv + cmu + ephemeral_key + enc_ciphertext + out_ciphertext + zkproof
        assert len(output_data) == 948
        
        deser = lib_tx.DeserializerPIVXSapling(output_data)
        output = deser._read_sapling_output()
        
        assert output.cv == cv
        assert output.cmu == cmu
        assert output.ephemeral_key == ephemeral_key
        assert len(output.enc_ciphertext) == 580
        assert len(output.out_ciphertext) == 80
        assert len(output.zkproof) == 192


class TestDIP2TransactionType:
    """Test DIP2 transaction type parsing."""

    def test_version_extraction(self):
        """Test that version and tx_type are correctly extracted from header."""
        # Version 3, type 0 (normal Sapling tx)
        header_v3_t0 = (3).to_bytes(4, 'little')
        deser = lib_tx.DeserializerPIVXSapling(header_v3_t0 + b'\x00' * 100)
        header = deser._read_le_uint32()
        tx_type = header >> 16
        version = header & 0x0000ffff if tx_type else header
        
        assert version == 3
        assert tx_type == 0

    def test_special_tx_type(self):
        """Test parsing of special transaction types (DIP2)."""
        # Version 3, type 1 (special tx)
        # Header = (1 << 16) | 3 = 0x00010003 = 65539
        header_v3_t1 = (65539).to_bytes(4, 'little')
        deser = lib_tx.DeserializerPIVXSapling(header_v3_t1 + b'\x00' * 100)
        header = deser._read_le_uint32()
        tx_type = header >> 16
        version = header & 0x0000ffff
        
        assert tx_type == 1
        assert version == 3


class TestTransparentFallback:
    """Test that transparent-only transactions still work."""

    def test_version2_transparent_tx(self):
        """Test parsing a v2 transparent-only transaction."""
        # Minimal v2 transaction with 0 inputs, 1 output
        raw_tx = bytes.fromhex(
            '02000000'  # version 2
            '00'        # 0 inputs
            '01'        # 1 output
            '00f2052a01000000'  # value: 50 * 1e8 sats
            '01'        # pk_script length = 1
            '6a'        # OP_RETURN
            '00000000'  # locktime
        )
        
        deser = lib_tx.DeserializerPIVXSapling(raw_tx)
        tx = deser.read_tx()
        
        assert tx.version == 2
        assert len(tx.inputs) == 0
        assert len(tx.outputs) == 1
        assert tx.locktime == 0


class TestSaplingSpendAndOutput:
    """Test parsing real Sapling transactions with spends and outputs."""

    def test_pivx_block_5057529_sapling_unshield(self):
        """Test parsing block 5057529 with Sapling spend (unshielding)."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        
        # Parse TX 2 which has Sapling spends and outputs
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        # Verify transaction structure
        assert tx.version == 3
        assert tx.tx_type == 0
        
        # This is an unshielding tx: spends from shielded, outputs to transparent
        assert len(tx.inputs) == 0  # No transparent inputs
        assert len(tx.outputs) == 1  # 1 transparent output
        
        # Sapling components
        assert len(tx.sapling_spends) == 2
        assert len(tx.sapling_outputs) == 2
        
        # Positive value_balance = unshielding (moving shield -> transparent)
        assert tx.value_balance == 502783000  # 5.02783 PIV
        
        # Verify binding signature present
        assert tx.binding_sig is not None
        assert len(tx.binding_sig) == 64

    def test_sapling_spend_nullifiers(self):
        """Test that nullifiers are correctly extracted from spends."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        # Verify nullifier structure (32 bytes each)
        for i, spend in enumerate(tx.sapling_spends):
            assert len(spend.nullifier) == 32
            assert len(spend.cv) == 32
            assert len(spend.anchor) == 32
            assert len(spend.rk) == 32
            assert len(spend.zkproof) == 192
            assert len(spend.spend_auth_sig) == 64
        
        # Check known nullifier values from block
        expected_nf0 = '63c05d0cb13b5e8cc0750dc2d19a0ee4'
        expected_nf1 = '0fc71fe23e15fab378c74f73430faacd'
        assert tx.sapling_spends[0].nullifier.hex()[:32] == expected_nf0
        assert tx.sapling_spends[1].nullifier.hex()[:32] == expected_nf1

    def test_sapling_output_commitments(self):
        """Test that note commitments are correctly extracted from outputs."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        # Verify output structure
        for output in tx.sapling_outputs:
            assert len(output.cv) == 32
            assert len(output.cmu) == 32  # Note commitment
            assert len(output.ephemeral_key) == 32
            assert len(output.enc_ciphertext) == 580
            assert len(output.out_ciphertext) == 80
            assert len(output.zkproof) == 192
        
        # Check known commitment values
        expected_cmu0 = 'a3a5aca593fe65244ea569d93b75951b'
        expected_cmu1 = 'ef4cd7b519316ee74e2bdced95fae4bc'
        assert tx.sapling_outputs[0].cmu.hex()[:32] == expected_cmu0
        assert tx.sapling_outputs[1].cmu.hex()[:32] == expected_cmu1

    def test_txid_computation(self):
        """Test that txid is correctly computed from serialized tx."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        
        parsed_txs = parse_block_transactions(block_data['hex'])
        for i, (tx, tx_hash, raw_tx) in enumerate(parsed_txs):
            computed_txid = tx_hash[::-1].hex()
            expected_txid = block_data['tx'][i]
            assert computed_txid == expected_txid, f"TX {i} hash mismatch"


class TestShieldingTransaction:
    """Test shielding transaction (transparent -> shielded)."""

    def test_block_2703076_shielding_tx_structure(self):
        """Test block 2703076 TX2 is a shielding transaction."""
        block_data = load_block_data('pivx_mainnet_2703076.json')
        
        # TX 2 is the Sapling shielding transaction
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        # Version 3 Sapling transaction
        assert tx.version == 3
        assert tx.tx_type == 0
        
        # Shielding: transparent inputs -> shielded output
        assert len(tx.inputs) == 4  # 4 transparent inputs
        assert len(tx.outputs) == 0  # No transparent outputs
        
        # Sapling: 0 spends, 1 output (shielding)
        assert len(tx.sapling_spends) == 0
        assert len(tx.sapling_outputs) == 1
        
        # Negative value_balance = shielding (value entering the shielded pool)
        assert tx.value_balance < 0
        
        # Binding signature present (required when Sapling data exists)
        assert tx.binding_sig is not None
        assert len(tx.binding_sig) == 64

    def test_shielding_output_fields(self):
        """Test the single Sapling output in shielding transaction."""
        block_data = load_block_data('pivx_mainnet_2703076.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        output = tx.sapling_outputs[0]
        
        # Verify all fields are correct size
        assert len(output.cv) == 32
        assert len(output.cmu) == 32
        assert len(output.ephemeral_key) == 32
        assert len(output.enc_ciphertext) == 580
        assert len(output.out_ciphertext) == 80
        assert len(output.zkproof) == 192
        
        # Verify known commitment value from real tx
        expected_cmu_prefix = 'c8369f9c0369bcc91a48c9e9546c127a'
        assert output.cmu.hex()[:32] == expected_cmu_prefix

    def test_transparent_inputs_in_shielding_tx(self):
        """Test transparent inputs are correctly parsed in shielding tx."""
        block_data = load_block_data('pivx_mainnet_2703076.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        assert len(tx.inputs) == 4
        
        # Each input should have proper structure
        for inp in tx.inputs:
            assert hasattr(inp, 'prev_hash')
            assert hasattr(inp, 'prev_idx')
            assert hasattr(inp, 'script')
            assert hasattr(inp, 'sequence')
            assert len(inp.prev_hash) == 32


class TestUnshieldingTransaction:
    """Test unshielding transaction (shielded -> transparent)."""

    def test_block_5057529_unshielding_tx_structure(self):
        """Test block 5057529 TX2 is an unshielding transaction."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        assert tx.version == 3
        assert tx.tx_type == 0
        
        # Unshielding: shielded spends -> transparent output
        assert len(tx.inputs) == 0  # No transparent inputs
        assert len(tx.outputs) == 1  # 1 transparent output
        
        # Sapling: 2 spends, 2 outputs
        assert len(tx.sapling_spends) == 2
        assert len(tx.sapling_outputs) == 2
        
        # Positive value_balance = unshielding (value leaving shielded pool)
        assert tx.value_balance > 0
        assert tx.value_balance == 502783000  # ~5.02783 PIV

    def test_unshielding_spend_fields(self):
        """Test Sapling spend fields in unshielding transaction."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        for i, spend in enumerate(tx.sapling_spends):
            # Verify all fields are correct size
            assert len(spend.cv) == 32, f"Spend {i} cv wrong size"
            assert len(spend.anchor) == 32, f"Spend {i} anchor wrong size"
            assert len(spend.nullifier) == 32, f"Spend {i} nf wrong size"
            assert len(spend.rk) == 32, f"Spend {i} rk wrong size"
            assert len(spend.zkproof) == 192, f"Spend {i} zkproof wrong size"
            assert len(spend.spend_auth_sig) == 64, f"Spend {i} sig wrong size"

    def test_anchor_consistency(self):
        """Test that all spends in a transaction share the same anchor."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        # In a valid Sapling tx, all spends reference the same Merkle tree root
        anchors = [spend.anchor for spend in tx.sapling_spends]
        assert len(set(anchors)) == 1, "All spends must share same anchor"
        
        # Verify the shared anchor value
        expected_anchor = (
            '997d307dff11f84c9444eb124be3c70e7d8a43e664f0bf2d6634d0a2198ea13e'
        )
        assert anchors[0].hex() == expected_anchor


class TestMixedBlockTransactions:
    """Test parsing blocks with mixed transaction types."""

    def test_block_with_v1_and_v3_transactions(self):
        """Test parsing block with v1 (transparent) and v3 (Sapling) txs."""
        block_data = load_block_data('pivx_mainnet_2703076.json')
        
        parsed_txs = parse_block_transactions(block_data['hex'])
        
        # TX 0: Coinbase (v1)
        assert parsed_txs[0][0].version == 1
        
        # TX 1: Transparent tx (v1)
        assert parsed_txs[1][0].version == 1
        
        # TX 2: Sapling shielding tx (v3)
        assert parsed_txs[2][0].version == 3
        assert len(parsed_txs[2][0].sapling_outputs) == 1

    def test_transparent_tx_has_empty_sapling_data(self):
        """Test that v1 transactions have empty Sapling fields."""
        block_data = load_block_data('pivx_mainnet_2703076.json')
        
        # TX 0 and TX 1 are v1 transparent transactions
        parsed_txs = parse_block_transactions(block_data['hex'])
        for i in [0, 1]:
            tx, tx_hash, raw_tx = parsed_txs[i]
            
            assert tx.version == 1
            # v1 transactions have empty Sapling lists
            assert tx.sapling_spends == []
            assert tx.sapling_outputs == []
            assert tx.value_balance == 0


class TestValueBalance:
    """Test value_balance field semantics."""

    def test_shielding_has_negative_value_balance(self):
        """Shielding (t->z) should have negative value_balance."""
        block_data = load_block_data('pivx_mainnet_2703076.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        # value_balance < 0 means value is entering the shielded pool
        assert tx.value_balance < 0
        # The absolute value should be significant (not just dust)
        assert abs(tx.value_balance) > 1000000  # > 0.01 PIV

    def test_unshielding_has_positive_value_balance(self):
        """Unshielding (z->t) should have positive value_balance."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        # value_balance > 0 means value is leaving the shielded pool
        assert tx.value_balance > 0
        assert tx.value_balance == 502783000


class TestNullifierExtraction:
    """Test nullifier extraction for spend detection."""

    def test_nullifiers_are_unique(self):
        """Test that nullifiers in a transaction are unique."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        nullifiers = [spend.nullifier for spend in tx.sapling_spends]
        assert len(nullifiers) == len(set(nullifiers)), "Nullifiers unique"

    def test_nullifier_known_values(self):
        """Test known nullifier values from real transaction."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        # Known nullifiers from block explorer / daemon
        nf0_hex = tx.sapling_spends[0].nullifier.hex()
        nf1_hex = tx.sapling_spends[1].nullifier.hex()
        
        # Verify they're 32-byte values (64 hex chars)
        assert len(nf0_hex) == 64
        assert len(nf1_hex) == 64
        
        # Verify they're different
        assert nf0_hex != nf1_hex


class TestCommitmentExtraction:
    """Test note commitment extraction for output indexing."""

    def test_commitments_are_unique(self):
        """Test that note commitments in a transaction are unique."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        commitments = [output.cmu for output in tx.sapling_outputs]
        assert len(commitments) == len(set(commitments)), "Commitments unique"

    def test_commitment_known_values(self):
        """Test known commitment values from real transaction."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        # Verify commitments are proper 32-byte values
        for output in tx.sapling_outputs:
            assert len(output.cmu) == 32


class TestTransactionSerialization:
    """Test transaction serialization round-trip."""

    def test_txid_from_serialized_sapling_tx(self):
        """Test that txid is correctly computed for Sapling transactions."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        
        parsed_txs = parse_block_transactions(block_data['hex'])
        for i, (tx, tx_hash, raw_tx) in enumerate(parsed_txs):
            computed_txid = tx_hash[::-1].hex()
            expected_txid = block_data['tx'][i]
            assert computed_txid == expected_txid, f"TX {i} txid mismatch"

    def test_complete_deserialization_no_leftover(self):
        """Test that deserializer consumes entire transaction."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        
        parsed_txs = parse_block_transactions(block_data['hex'])
        for i, (tx, tx_hash, raw_tx) in enumerate(parsed_txs):
            # Re-parse to check cursor position
            deser = lib_tx.DeserializerPIVXSapling(raw_tx)
            deser.read_tx()
            
            # Deserializer should have consumed all bytes
            assert deser.cursor == len(raw_tx), f"TX {i} incomplete parse"


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_sapling_tx(self):
        """Test v3 tx with no Sapling data (all zeros)."""
        # Construct a minimal v3 tx with no Sapling spends/outputs
        raw_tx = bytes.fromhex(
            '03000000'  # version 3, type 0
            '00'        # 0 transparent inputs
            '01'        # 1 transparent output
            '00f2052a01000000'  # value
            '01'        # pk_script length
            '6a'        # OP_RETURN
            '00000000'  # locktime
            '00'        # nExpiryHeight (varint 0)
            '0000000000000000'  # value_balance (0)
            '00'        # 0 Sapling spends
            '00'        # 0 Sapling outputs
            # No binding_sig needed when no Sapling data
        )
        
        deser = lib_tx.DeserializerPIVXSapling(raw_tx)
        tx = deser.read_tx()
        
        assert tx.version == 3
        assert tx.value_balance == 0
        assert len(tx.sapling_spends) == 0
        assert len(tx.sapling_outputs) == 0
        # binding_sig should be empty when no Sapling data
        assert tx.binding_sig == b''

    def test_coinbase_transaction(self):
        """Test parsing a coinbase transaction in Sapling block."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[0]
        
        # Coinbase is v1, no Sapling
        assert tx.version == 1
        assert len(tx.inputs) == 1
        # Coinbase input has null prevout
        assert tx.inputs[0].prev_hash == b'\x00' * 32


class TestBindingSignature:
    """Test binding signature handling."""

    def test_binding_sig_present_with_sapling_data(self):
        """Test binding signature is present when Sapling data exists."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        # Has Sapling data, must have binding_sig
        assert tx.binding_sig is not None
        assert len(tx.binding_sig) == 64

    def test_binding_sig_format(self):
        """Test binding signature is a valid 64-byte signature."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        # Binding signature should be 64 bytes (Schnorr signature)
        assert isinstance(tx.binding_sig, bytes)
        assert len(tx.binding_sig) == 64


class TestEphemeralKeyAndCiphertext:
    """Test ephemeral key and ciphertext extraction for light wallet."""

    def test_ephemeral_key_extraction(self):
        """Test ephemeral key extraction for trial decryption."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        for output in tx.sapling_outputs:
            # Ephemeral key is needed for ECDH with IVK
            assert len(output.ephemeral_key) == 32

    def test_enc_ciphertext_for_trial_decryption(self):
        """Test encrypted ciphertext for trial decryption."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        for output in tx.sapling_outputs:
            # enc_ciphertext contains encrypted (d, v, rcm, memo)
            # 52 bytes + 512 byte memo + 16 byte MAC = 580 bytes
            assert len(output.enc_ciphertext) == 580

    def test_out_ciphertext_for_sender_recovery(self):
        """Test out_ciphertext for outgoing view key recovery."""
        block_data = load_block_data('pivx_mainnet_5057529.json')
        parsed_txs = parse_block_transactions(block_data['hex'])
        tx, tx_hash, raw_tx = parsed_txs[2]
        
        for output in tx.sapling_outputs:
            # out_ciphertext is for sender recovery with OVK
            # 32 (pkd) + 32 (esk) + 16 (MAC) = 80 bytes
            assert len(output.out_ciphertext) == 80


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
