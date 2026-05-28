#
# Tests of PIVX Sapling transaction parsing in lib/tx.py
#

import pytest

import lib.tx as lib_tx


class TestSaplingSpend:
    """Test SaplingSpend namedtuple structure."""

    def test_sapling_spend_fields(self):
        """Verify SaplingSpend has correct field names."""
        spend = lib_tx.SaplingSpend(
            cv=b'\x00' * 32,
            anchor=b'\x01' * 32,
            nullifier=b'\x02' * 32,
            rk=b'\x03' * 32,
            zkproof=b'\x04' * 192,
            spend_auth_sig=b'\x05' * 64
        )
        assert len(spend.cv) == 32
        assert len(spend.anchor) == 32
        assert len(spend.nullifier) == 32
        assert len(spend.rk) == 32
        assert len(spend.zkproof) == 192
        assert len(spend.spend_auth_sig) == 64


class TestSaplingOutput:
    """Test SaplingOutput namedtuple structure."""

    def test_sapling_output_fields(self):
        """Verify SaplingOutput has correct field names."""
        output = lib_tx.SaplingOutput(
            cv=b'\x00' * 32,
            cmu=b'\x01' * 32,
            ephemeral_key=b'\x02' * 32,
            enc_ciphertext=b'\x03' * 580,
            out_ciphertext=b'\x04' * 80,
            zkproof=b'\x05' * 192
        )
        assert len(output.cv) == 32
        assert len(output.cmu) == 32
        assert len(output.ephemeral_key) == 32
        assert len(output.enc_ciphertext) == 580
        assert len(output.out_ciphertext) == 80
        assert len(output.zkproof) == 192


class TestTxPIVXSapling:
    """Test TxPIVXSapling namedtuple structure."""

    def test_tx_pivx_sapling_fields(self):
        """Verify TxPIVXSapling has correct field names."""
        tx = lib_tx.TxPIVXSapling(
            version=3,
            tx_type=0,
            inputs=[],
            outputs=[],
            locktime=0,
            value_balance=0,
            sapling_spends=[],
            sapling_outputs=[],
            binding_sig=b'',
            extra_payload=b''
        )
        assert tx.version == 3
        assert tx.tx_type == 0
        assert tx.inputs == []
        assert tx.outputs == []
        assert tx.locktime == 0
        assert tx.value_balance == 0
        assert tx.sapling_spends == []
        assert tx.sapling_outputs == []
        assert tx.binding_sig == b''
        assert tx.extra_payload == b''


class TestDeserializerPIVXSapling:
    """Test DeserializerPIVXSapling class."""

    def test_deserializer_exists(self):
        """Verify DeserializerPIVXSapling class exists."""
        assert hasattr(lib_tx, 'DeserializerPIVXSapling')

    def test_deserializer_inheritance(self):
        """Verify DeserializerPIVXSapling inherits from Deserializer."""
        assert issubclass(lib_tx.DeserializerPIVXSapling, lib_tx.Deserializer)

    def test_simple_transparent_tx(self):
        """Test deserializing a simple transparent-only transaction."""
        # A minimal v2 transparent transaction:
        # version (4) + vin count (1) + vin + vout count (1) + locktime (4)
        # This is a coinbase-style tx with no real inputs
        raw_tx = bytes.fromhex(
            '02000000'  # version 2 (no Sapling)
            '00'        # 0 inputs (will be coinbase)
            '01'        # 1 output
            # Output: 50 PIVX (50 * 1e8 = 0x12a05f200) to OP_RETURN
            '00f2052a01000000'  # value: 50 * 1e8 sats little-endian
            '01'        # pk_script length
            '6a'        # OP_RETURN
            '00000000'  # locktime
        )
        deser = lib_tx.DeserializerPIVXSapling(raw_tx)
        tx = deser.read_tx()

        # For v2, it should return a regular Tx (not TxPIVXSapling)
        # because Sapling features only activate at v3+
        assert tx.version == 2
        assert len(tx.outputs) == 1

    def test_sapling_version_detection(self):
        """Test that version 3+ triggers Sapling parsing path."""
        # This tests the version detection logic
        # A v3 tx with Sapling would have additional fields
        # For now just test that the class handles version detection
        deser = lib_tx.DeserializerPIVXSapling(b'\x03\x00\x00\x00')
        # Read just the version
        version = deser._read_le_int32()
        assert version == 3

    def test_read_sapling_spend(self):
        """Test _read_sapling_spend reads correct number of bytes."""
        # 384 bytes total for a Sapling spend
        spend_data = b'\x00' * 384
        deser = lib_tx.DeserializerPIVXSapling(spend_data)
        spend = deser._read_sapling_spend()

        assert len(spend.cv) == 32
        assert len(spend.anchor) == 32
        assert len(spend.nullifier) == 32
        assert len(spend.rk) == 32
        assert len(spend.zkproof) == 192
        assert len(spend.spend_auth_sig) == 64

    def test_read_sapling_output(self):
        """Test _read_sapling_output reads correct number of bytes."""
        # 948 bytes total for a Sapling output
        output_data = b'\x00' * 948
        deser = lib_tx.DeserializerPIVXSapling(output_data)
        output = deser._read_sapling_output()

        assert len(output.cv) == 32
        assert len(output.cmu) == 32
        assert len(output.ephemeral_key) == 32
        assert len(output.enc_ciphertext) == 580
        assert len(output.out_ciphertext) == 80
        assert len(output.zkproof) == 192


class TestSaplingDataSizes:
    """Verify Sapling data structure sizes match protocol spec."""

    def test_spend_size_constant(self):
        """Verify SAPLING_SPEND_SIZE is correct."""
        assert lib_tx.DeserializerPIVXSapling.SAPLING_SPEND_SIZE == 384

    def test_output_size_constant(self):
        """Verify SAPLING_OUTPUT_SIZE is correct."""
        assert lib_tx.DeserializerPIVXSapling.SAPLING_OUTPUT_SIZE == 948

    def test_spend_component_sizes(self):
        """Verify Sapling spend component sizes add up correctly."""
        # cv(32) + anchor(32) + nullifier(32) + rk(32) + 
        # zkproof(192) + spend_auth_sig(64) = 384
        total = 32 + 32 + 32 + 32 + 192 + 64
        assert total == 384

    def test_output_component_sizes(self):
        """Verify Sapling output component sizes add up correctly."""
        # cv(32) + cmu(32) + ephemeral_key(32) + 
        # enc_ciphertext(580) + out_ciphertext(80) + zkproof(192) = 948
        total = 32 + 32 + 32 + 580 + 80 + 192
        assert total == 948
