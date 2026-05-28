# Copyright (c) 2016-2017, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# and warranty status of this software.

'''Transaction-related classes and functions.'''


from collections import namedtuple

from lib.hash import double_sha256, hash_to_str
from lib.util import (cachedproperty, unpack_int32_from, unpack_int64_from,
                      unpack_uint16_from, unpack_uint32_from,
                      unpack_uint64_from)


class Tx(namedtuple("Tx", "version inputs outputs locktime")):
    '''Class representing a transaction.'''

    @cachedproperty
    def is_coinbase(self):
        return self.inputs[0].is_coinbase

    # FIXME: add hash as a cached property?


class TxInput(namedtuple("TxInput", "prev_hash prev_idx script sequence")):
    '''Class representing a transaction input.'''

    ZERO = bytes(32)
    MINUS_1 = 4294967295

    @cachedproperty
    def is_coinbase(self):
        return (self.prev_hash == TxInput.ZERO and
                self.prev_idx == TxInput.MINUS_1)

    def __str__(self):
        script = self.script.hex()
        prev_hash = hash_to_str(self.prev_hash)
        return ("Input({}, {:d}, script={}, sequence={:d})"
                .format(prev_hash, self.prev_idx, script, self.sequence))


class TxOutput(namedtuple("TxOutput", "value pk_script")):
    pass


class Deserializer(object):
    '''Deserializes blocks into transactions.

    External entry points are read_tx(), read_tx_and_hash(),
    read_tx_and_vsize() and read_block().

    This code is performance sensitive as it is executed 100s of
    millions of times during sync.
    '''

    def __init__(self, binary, start=0):
        assert isinstance(binary, bytes)
        self.binary = binary
        self.binary_length = len(binary)
        self.cursor = start

    def read_tx(self):
        '''Return a deserialized transaction.'''
        return Tx(
            self._read_le_int32(),  # version
            self._read_inputs(),    # inputs
            self._read_outputs(),   # outputs
            self._read_le_uint32()  # locktime
        )

    def read_tx_and_hash(self):
        '''Return a (deserialized TX, tx_hash) pair.

        The hash needs to be reversed for human display; for efficiency
        we process it in the natural serialized order.
        '''
        start = self.cursor
        return self.read_tx(), double_sha256(self.binary[start:self.cursor])

    def read_tx_and_vsize(self):
        '''Return a (deserialized TX, vsize) pair.'''
        return self.read_tx(), self.binary_length

    def read_tx_block(self):
        '''Returns a list of (deserialized_tx, tx_hash) pairs.'''
        read = self.read_tx_and_hash
        # Some coins have excess data beyond the end of the transactions
        return [read() for _ in range(self._read_varint())]

    def _read_inputs(self):
        read_input = self._read_input
        return [read_input() for i in range(self._read_varint())]

    def _read_input(self):
        return TxInput(
            self._read_nbytes(32),   # prev_hash
            self._read_le_uint32(),  # prev_idx
            self._read_varbytes(),   # script
            self._read_le_uint32()   # sequence
        )

    def _read_outputs(self):
        read_output = self._read_output
        return [read_output() for i in range(self._read_varint())]

    def _read_output(self):
        return TxOutput(
            self._read_le_int64(),  # value
            self._read_varbytes(),  # pk_script
        )

    def _read_byte(self):
        cursor = self.cursor
        self.cursor += 1
        return self.binary[cursor]

    def _read_nbytes(self, n):
        cursor = self.cursor
        self.cursor = end = cursor + n
        assert self.binary_length >= end
        return self.binary[cursor:end]

    def _read_varbytes(self):
        return self._read_nbytes(self._read_varint())

    def _read_varint(self):
        n = self.binary[self.cursor]
        self.cursor += 1
        if n < 253:
            return n
        if n == 253:
            return self._read_le_uint16()
        if n == 254:
            return self._read_le_uint32()
        return self._read_le_uint64()

    def _read_le_int32(self):
        result, = unpack_int32_from(self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_int64(self):
        result, = unpack_int64_from(self.binary, self.cursor)
        self.cursor += 8
        return result

    def _read_le_uint16(self):
        result, = unpack_uint16_from(self.binary, self.cursor)
        self.cursor += 2
        return result

    def _read_le_uint32(self):
        result, = unpack_uint32_from(self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_uint64(self):
        result, = unpack_uint64_from(self.binary, self.cursor)
        self.cursor += 8
        return result


class TxSegWit(namedtuple("Tx", "version marker flag inputs outputs "
                          "witness locktime")):
    '''Class representing a SegWit transaction.'''

    @cachedproperty
    def is_coinbase(self):
        return self.inputs[0].is_coinbase


class DeserializerSegWit(Deserializer):

    # https://bitcoincore.org/en/segwit_wallet_dev/#transaction-serialization

    def _read_witness(self, fields):
        read_witness_field = self._read_witness_field
        return [read_witness_field() for i in range(fields)]

    def _read_witness_field(self):
        read_varbytes = self._read_varbytes
        return [read_varbytes() for i in range(self._read_varint())]

    def _read_tx_parts(self):
        '''Return a (deserialized TX, tx_hash, vsize) tuple.'''
        start = self.cursor
        marker = self.binary[self.cursor + 4]
        if marker:
            tx = super().read_tx()
            tx_hash = double_sha256(self.binary[start:self.cursor])
            return tx, tx_hash, self.binary_length

        # Ugh, this is nasty.
        version = self._read_le_int32()
        orig_ser = self.binary[start:self.cursor]

        marker = self._read_byte()
        flag = self._read_byte()

        start = self.cursor
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        orig_ser += self.binary[start:self.cursor]

        base_size = self.cursor - start
        witness = self._read_witness(len(inputs))

        start = self.cursor
        locktime = self._read_le_uint32()
        orig_ser += self.binary[start:self.cursor]
        vsize = (3 * base_size + self.binary_length) // 4

        return TxSegWit(version, marker, flag, inputs, outputs, witness,
                        locktime), double_sha256(orig_ser), vsize

    def read_tx(self):
        return self._read_tx_parts()[0]

    def read_tx_and_hash(self):
        tx, tx_hash, vsize = self._read_tx_parts()
        return tx, tx_hash

    def read_tx_and_vsize(self):
        tx, tx_hash, vsize = self._read_tx_parts()
        return tx, vsize


class DeserializerAuxPow(Deserializer):
    VERSION_AUXPOW = (1 << 8)

    def read_header(self, height, static_header_size):
        '''Return the AuxPow block header bytes'''
        start = self.cursor
        version = self._read_le_uint32()
        if version & self.VERSION_AUXPOW:
            # We are going to calculate the block size then read it as bytes
            self.cursor = start
            self.cursor += static_header_size # Block normal header
            self.read_tx() # AuxPow transaction
            self.cursor += 32 # Parent block hash
            merkle_size = self._read_varint()
            self.cursor += 32 * merkle_size # Merkle branch
            self.cursor += 4 # Index
            merkle_size = self._read_varint()
            self.cursor += 32 * merkle_size # Chain merkle branch
            self.cursor += 4 # Chain index
            self.cursor += 80 # Parent block header
            header_end = self.cursor
        else:
            header_end = static_header_size
        self.cursor = start
        return self._read_nbytes(header_end)


class DeserializerAuxPowSegWit(DeserializerSegWit, DeserializerAuxPow):
    pass


class DeserializerEquihash(Deserializer):
    def read_header(self, height, static_header_size):
        '''Return the block header bytes'''
        start = self.cursor
        # We are going to calculate the block size then read it as bytes
        self.cursor += static_header_size
        solution_size = self._read_varint()
        self.cursor += solution_size
        header_end = self.cursor
        self.cursor = start
        return self._read_nbytes(header_end)


class DeserializerEquihashSegWit(DeserializerSegWit, DeserializerEquihash):
    pass


class TxJoinSplit(namedtuple("Tx", "version inputs outputs locktime")):
    '''Class representing a JoinSplit transaction.'''

    @cachedproperty
    def is_coinbase(self):
        return self.inputs[0].is_coinbase if len(self.inputs) > 0 else False


class DeserializerZcash(DeserializerEquihash):
    def read_tx(self):
        base_tx =  TxJoinSplit(
            self._read_le_int32(),  # version
            self._read_inputs(),    # inputs
            self._read_outputs(),   # outputs
            self._read_le_uint32()  # locktime
        )
        if base_tx.version >= 2:
            joinsplit_size = self._read_varint()
            if joinsplit_size > 0:
                self.cursor += joinsplit_size * 1802 # JSDescription
                self.cursor += 32 # joinSplitPubKey
                self.cursor += 64 # joinSplitSig
        return base_tx


class TxTime(namedtuple("Tx", "version time inputs outputs locktime")):
    '''Class representing transaction that has a time field.'''

    @cachedproperty
    def is_coinbase(self):
        return self.inputs[0].is_coinbase


class DeserializerTxTime(Deserializer):
    def read_tx(self):
        return TxTime(
            self._read_le_int32(),  # version
            self._read_le_uint32(), # time
            self._read_inputs(),    # inputs
            self._read_outputs(),   # outputs
            self._read_le_uint32(), # locktime
        )


class DeserializerReddcoin(Deserializer):
    def read_tx(self):
        version = self._read_le_int32()
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        locktime = self._read_le_uint32()
        if version > 1:
            time = self._read_le_uint32()
        else:
            time = 0

        return TxTime(version, time, inputs, outputs, locktime)


class DeserializerTxTimeAuxPow(DeserializerTxTime):
    VERSION_AUXPOW = (1 << 8)

    def is_merged_block(self):
        start = self.cursor
        self.cursor = 0
        version = self._read_le_uint32()
        self.cursor = start
        if version & self.VERSION_AUXPOW:
            return True
        return False

    def read_header(self, height, static_header_size):
        '''Return the AuxPow block header bytes'''
        start = self.cursor
        version = self._read_le_uint32()
        if version & self.VERSION_AUXPOW:
            # We are going to calculate the block size then read it as bytes
            self.cursor = start
            self.cursor += static_header_size  # Block normal header
            self.read_tx()  # AuxPow transaction
            self.cursor += 32  # Parent block hash
            merkle_size = self._read_varint()
            self.cursor += 32 * merkle_size  # Merkle branch
            self.cursor += 4  # Index
            merkle_size = self._read_varint()
            self.cursor += 32 * merkle_size  # Chain merkle branch
            self.cursor += 4  # Chain index
            self.cursor += 80  # Parent block header
            header_end = self.cursor
        else:
            header_end = static_header_size
        self.cursor = start
        return self._read_nbytes(header_end)


class DeserializerBitcoinAtom(DeserializerSegWit):
    FORK_BLOCK_HEIGHT = 505888

    def read_header(self, height, static_header_size):
        '''Return the block header bytes'''
        header_len = static_header_size
        if height >= self.FORK_BLOCK_HEIGHT:
            header_len += 4 # flags
        return self._read_nbytes(header_len)


# Decred
class TxInputDcr(namedtuple("TxInput", "prev_hash prev_idx tree sequence")):
    '''Class representing a Decred transaction input.'''

    ZERO = bytes(32)
    MINUS_1 = 4294967295

    @cachedproperty
    def is_coinbase(self):
        # The previous output of a coin base must have a max value index and a
        # zero hash.
        return (self.prev_hash == TxInputDcr.ZERO and
                self.prev_idx == TxInputDcr.MINUS_1)

    def __str__(self):
        prev_hash = hash_to_str(self.prev_hash)
        return ("Input({}, {:d}, tree={}, sequence={:d})"
                .format(prev_hash, self.prev_idx, self.tree, self.sequence))


class TxOutputDcr(namedtuple("TxOutput", "value version pk_script")):
    '''Class representing a transaction output.'''
    pass


class TxDcr(namedtuple("Tx", "version inputs outputs locktime expiry "
                             "witness")):
    '''Class representing transaction that has a time field.'''

    @cachedproperty
    def is_coinbase(self):
        return self.inputs[0].is_coinbase


class DeserializerDecred(Deserializer):

    @staticmethod
    def blake256(data):
        from blake256.blake256 import blake_hash
        return blake_hash(data)

    def read_tx_block(self):
        '''Returns a list of (deserialized_tx, tx_hash) pairs.'''
        read_tx = self.read_tx
        txs = [read_tx() for _ in range(self._read_varint())]
        stxs = [read_tx() for _ in range(self._read_varint())]
        return txs + stxs

    def _read_inputs(self):
        read_input = self._read_input
        return [read_input() for i in range(self._read_varint())]

    def _read_input(self):
        return TxInputDcr(
            self._read_nbytes(32),   # prev_hash
            self._read_le_uint32(),  # prev_idx
            self._read_byte(),       # tree
            self._read_le_uint32(),  # sequence
        )

    def _read_outputs(self):
        read_output = self._read_output
        return [read_output() for _ in range(self._read_varint())]

    def _read_output(self):
        return TxOutputDcr(
            self._read_le_int64(),  # value
            self._read_le_uint16(),  # version
            self._read_varbytes(),  # pk_script
        )

    def _read_witness(self, fields):
        read_witness_field = self._read_witness_field
        assert fields == self._read_varint()
        return [read_witness_field() for _ in range(fields)]

    def _read_witness_field(self):
        value_in = self._read_le_int64()
        block_height = self._read_le_uint32()
        block_index = self._read_le_uint32()
        script = self._read_varbytes()
        return value_in, block_height, block_index, script

    def read_tx(self):
        start = self.cursor
        version = self._read_le_int32()
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        locktime = self._read_le_uint32()
        expiry = self._read_le_uint32()
        no_witness_tx = b'\x01\x00\x01\x00' + self.binary[start+4:self.cursor]
        witness = self._read_witness(len(inputs))
        return TxDcr(
            version,
            inputs,
            outputs,
            locktime,
            expiry,
            witness
        ), DeserializerDecred.blake256(no_witness_tx)


# =============================================================================
# PIVX Sapling Support
# =============================================================================

class SaplingSpend(namedtuple("SaplingSpend",
                              "cv anchor nullifier rk zkproof spend_auth_sig")):
    """Represents a Sapling spend description (384 bytes total).
    
    Fields:
        cv: 32 bytes - Value commitment
        anchor: 32 bytes - Merkle tree root
        nullifier: 32 bytes - Unique nullifier (reveals note is spent)
        rk: 32 bytes - Randomized public key
        zkproof: 192 bytes - Groth16 zero-knowledge proof
        spend_auth_sig: 64 bytes - Spend authorization signature
    """
    pass


class SaplingOutput(namedtuple("SaplingOutput",
                               "cv cmu ephemeral_key enc_ciphertext out_ciphertext zkproof")):
    """Represents a Sapling output description (948 bytes total).
    
    Fields:
        cv: 32 bytes - Value commitment
        cmu: 32 bytes - Note commitment (u-coordinate)
        ephemeral_key: 32 bytes - For ECDH key agreement
        enc_ciphertext: 580 bytes - Encrypted note plaintext
        out_ciphertext: 80 bytes - Encrypted data for sender recovery
        zkproof: 192 bytes - Groth16 zero-knowledge proof
    """
    pass


class TxPIVXSapling(namedtuple("TxPIVXSapling",
                               "version tx_type inputs outputs locktime "
                               "value_balance sapling_spends sapling_outputs "
                               "binding_sig extra_payload")):
    """PIVX transaction with Sapling shielded components.
    
    Fields:
        version: Transaction version (3+ for Sapling)
        tx_type: DIP2-style transaction type (0 for normal)
        inputs: List of transparent inputs
        outputs: List of transparent outputs
        locktime: Transaction locktime
        value_balance: Net value transferred in/out of shielded pool (signed)
        sapling_spends: List of SaplingSpend descriptions
        sapling_outputs: List of SaplingOutput descriptions
        binding_sig: 64-byte binding signature (empty if no shielded components)
        extra_payload: Extra data for special transaction types
    """

    @cachedproperty
    def is_coinbase(self):
        return self.inputs[0].is_coinbase if len(self.inputs) > 0 else False

    @property
    def has_sapling(self):
        """Returns True if transaction has any Sapling components."""
        return bool(self.sapling_spends or self.sapling_outputs)


class DeserializerPIVXSapling(Deserializer):
    """Deserializer for PIVX transactions with full Sapling support.
    
    Handles PIVX transaction format including:
    - Version 1-2: Legacy transparent transactions
    - Version 3+: Sapling-enabled transactions with shielded spends/outputs
    - DIP2-style special transactions (tx_type in upper 16 bits of version)
    
    Sapling component sizes:
    - vShieldedSpend: 384 bytes each
    - vShieldedOutput: 948 bytes each
    - bindingSig: 64 bytes (if any shielded components)
    """
    
    # Size constants for Sapling components
    SAPLING_SPEND_SIZE = 384  # cv(32) + anchor(32) + nullifier(32) + rk(32) + proof(192) + sig(64)
    SAPLING_OUTPUT_SIZE = 948  # cv(32) + cmu(32) + epk(32) + enc(580) + out(80) + proof(192)
    
    def read_tx(self):
        """Deserialize a PIVX transaction with Sapling support."""
        start = self.cursor
        
        # Read header (contains version and potentially tx_type)
        header = self._read_le_uint32()
        tx_type = header >> 16  # Upper 16 bits for DIP2 tx type
        if tx_type:
            version = header & 0x0000ffff
        else:
            version = header
        
        # Handle case where tx_type is set but version < 3
        if tx_type and version < 3:
            version = header
            tx_type = 0
        
        # Read transparent inputs and outputs
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        locktime = self._read_le_uint32()
        
        # Initialize Sapling fields
        value_balance = 0
        sapling_spends = []
        sapling_outputs = []
        binding_sig = b''
        extra_payload = b''
        
        # Parse Sapling components (version >= 3)
        if version >= 3:
            # Skip nExpiryHeight (encoded as varint in PIVX)
            self._read_varint()
            
            # Value balance (signed 64-bit, positive = from shielded to transparent)
            value_balance = self._read_le_int64()
            
            # Read shielded spends
            spend_count = self._read_varint()
            for _ in range(spend_count):
                sapling_spends.append(self._read_sapling_spend())
            
            # Read shielded outputs
            output_count = self._read_varint()
            for _ in range(output_count):
                sapling_outputs.append(self._read_sapling_output())
            
            # Binding signature (64 bytes, only if there are shielded components)
            if sapling_spends or sapling_outputs:
                binding_sig = self._read_nbytes(64)
            
            # Extra payload for special transaction types
            if tx_type > 0:
                payload_size = self._read_varint()
                if payload_size > 0:
                    extra_payload = self._read_nbytes(payload_size)
        
        return TxPIVXSapling(
            version,
            tx_type,
            inputs,
            outputs,
            locktime,
            value_balance,
            sapling_spends,
            sapling_outputs,
            binding_sig,
            extra_payload,
        )
    
    def _read_sapling_spend(self):
        """Read a Sapling spend description (384 bytes)."""
        return SaplingSpend(
            cv=self._read_nbytes(32),              # Value commitment
            anchor=self._read_nbytes(32),          # Merkle tree root
            nullifier=self._read_nbytes(32),       # Nullifier
            rk=self._read_nbytes(32),              # Randomized public key
            zkproof=self._read_nbytes(192),        # Groth16 proof
            spend_auth_sig=self._read_nbytes(64),  # Spend authorization signature
        )
    
    def _read_sapling_output(self):
        """Read a Sapling output description (948 bytes)."""
        return SaplingOutput(
            cv=self._read_nbytes(32),              # Value commitment
            cmu=self._read_nbytes(32),             # Note commitment (u-coordinate)
            ephemeral_key=self._read_nbytes(32),   # Ephemeral public key
            enc_ciphertext=self._read_nbytes(580), # Encrypted note plaintext
            out_ciphertext=self._read_nbytes(80),  # Outgoing ciphertext
            zkproof=self._read_nbytes(192),        # Groth16 proof
        )
