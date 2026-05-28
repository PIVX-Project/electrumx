# PIVX Sapling Support for ElectrumX

## Design Document

**Version:** 1.0  
**Date:** December 2024  
**Author:** ElectrumX PIVX Integration Team

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current State Analysis](#2-current-state-analysis)
3. [PIVX Sapling Overview](#3-pivx-sapling-overview)
4. [Architecture Design](#4-architecture-design)
5. [Database Schema](#5-database-schema)
6. [Block & Transaction Parsing](#6-block--transaction-parsing)
7. [API Design](#7-api-design)
8. [PIVX Core RPC Integration](#8-pivx-core-rpc-integration)
9. [Reorg Handling](#9-reorg-handling)
10. [Performance Considerations](#10-performance-considerations)
11. [Implementation Plan](#11-implementation-plan)

---

## 1. Executive Summary

This document describes the design for integrating PIVX Sapling support into this ElectrumX server fork. The goal is to enable Sapling-aware PIVX light wallets to:

- Discover incoming and outgoing Sapling notes for a given full/viewing key
- Track note spend status via nullifiers
- Get height/anchor info needed for proof construction and verification
- Query balances and transaction history for Sapling accounts/addresses

### Key Design Principles

1. **Server-side privacy**: The server stores commitments, nullifiers, and ciphertexts but never has access to private keys or decrypted note data.
2. **Client-side scanning**: Wallet clients perform trial decryption using their viewing keys.
3. **Consensus alignment**: All indexed data aligns with PIVX Core's canonical chain state.
4. **Performance**: Efficient batch operations and optimized indices for wallet queries.
5. **Reorg safety**: All Sapling data can be rolled back on chain reorganizations.

---

## 2. Current State Analysis

### 2.1 Existing PIVX Support in This Fork

Located in `lib/coins.py`:

```python
class Pivx(Coin):
    NAME = "PIVX"
    SHORTNAME = "PIVX"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("022D2533")
    XPRV_VERBYTES = bytes.fromhex("0221312B")
    GENESIS_HASH = '0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818'
    P2PKH_VERBYTE = bytes.fromhex("1e")
    P2SH_VERBYTE = bytes.fromhex("0d")
    WIF_BYTE = bytes.fromhex("d4")
    STATIC_BLOCK_HEADERS = False
    RPC_PORT = 51470
    ZEROCOIN_HEADER = 112
    ZEROCOIN_START_HEIGHT = 863787
    ZEROCOIN_BLOCK_VERSION = 4
```

**Current limitations:**
- Only handles transparent transactions
- Zerocoin header support exists but no shielded indexing
- No Sapling-specific constants (activation height, etc.)
- Uses base `Deserializer` - not the Sapling-aware variant

### 2.2 Existing Zcash/Sapling Logic

Located in `lib/tx.py`:

```python
class DeserializerZcash(DeserializerEquihash):
    def read_tx(self):
        # Parses Zcash transaction format including:
        # - version/overwinter/sapling flags
        # - vShieldedSpend (384 bytes each)
        # - vShieldedOutput (948 bytes each)
        # - bindingSig (64 bytes)
        # BUT: currently just skips over shielded data
```

**Key observations:**
- Zcash deserializer parses but does not index Sapling data
- vShieldedSpend = 384 bytes (cv + anchor + nullifier + rk + proof + spendAuthSig)
- vShieldedOutput = 948 bytes (cv + cmu + ephemeralKey + encCiphertext + outCiphertext + proof)
- No database storage for commitments or nullifiers

### 2.3 Upstream ElectrumX Status

The upstream `spesmilo/electrumx` repository has a `DeserializerPIVX` class:

```python
class DeserializerPIVX(Deserializer):
    def read_tx(self):
        # Handles PIVX transaction format with:
        # - tx_type (DIP2-style special transactions)
        # - Sapling components (version >= 3)
        # - vShieldedSpend/vShieldedOutput parsing
        # - extraPayload for special transactions
```

### 2.4 Indexer Architecture

The current indexer flow:

```
Prefetcher → BlockProcessor → DB
    ↓              ↓           ↓
  blocks      advance_txs   UTXO/History tables
```

**Key files:**
- `server/block_processor.py`: Block parsing, UTXO management, history tracking
- `server/db.py`: Database operations, UTXO queries, history queries
- `server/session.py`: Client API handlers
- `server/storage.py`: LevelDB/RocksDB abstraction

---

## 3. PIVX Sapling Overview

### 3.1 PIVX Sapling Parameters

Based on PIVX Core v5.6.1 (`PIVX-Project/PIVX` tag `v5.6.1`,
`src/chainparams.cpp`) consensus rules:

| Parameter | Mainnet Value | Testnet Value |
|-----------|---------------|---------------|
| Sapling Activation Height | 2,700,500 | 201 |
| HRP (Bech32m prefix) | `ps` (shielded address) | `ptestsapling` |
| Extended Spending Key | `p-secret-spending-key-main` | `p-secret-spending-key-test` |
| Extended Full Viewing Key | `pxviews` | `pxviewtestsapling` |

### 3.2 Sapling Transaction Structure

A PIVX Sapling transaction (version ≥ 3) contains:

```
Transaction v3/v4:
├── nVersion (4 bytes)
├── tx_type (if DIP2-style, 2 bytes in upper nVersion)
├── vin[] (transparent inputs)
├── vout[] (transparent outputs)
├── nLockTime (4 bytes)
├── nExpiryHeight (4 bytes, if overwinter+)
├── valueBalance (8 bytes, signed)
├── vShieldedSpend[] (each 384 bytes)
│   ├── cv (32 bytes) - value commitment
│   ├── anchor (32 bytes) - merkle tree root
│   ├── nullifier (32 bytes) - unique nullifier
│   ├── rk (32 bytes) - randomized public key
│   ├── zkproof (192 bytes) - Groth16 proof
│   └── spendAuthSig (64 bytes) - signature
├── vShieldedOutput[] (each 948 bytes)
│   ├── cv (32 bytes) - value commitment
│   ├── cmu (32 bytes) - note commitment
│   ├── ephemeralKey (32 bytes) - for ECDH
│   ├── encCiphertext (580 bytes) - encrypted note
│   ├── outCiphertext (80 bytes) - encrypted for sender
│   └── zkproof (192 bytes) - Groth16 proof
├── bindingSig (64 bytes, if shielded components present)
└── extraPayload (varint + data, if tx_type > 0)
```

### 3.3 Sapling Cryptographic Primitives

**Note Commitment (cmu):**
- 32-byte hash: `BLAKE2s-256(rcm || value || g_d || pk_d)`
- Stored in commitment tree at specific position

**Nullifier:**
- 32-byte value: derived from note commitment, position, and spending key
- Reveals when a note is spent (but not which note)

**Viewing Key Operations:**
- Incoming Viewing Key (ivk): Can decrypt notes sent to the address
- Full Viewing Key (fvk): Can decrypt both incoming and outgoing
- Extended Full Viewing Key: fvk + diversifier key (dk)

---

## 4. Architecture Design

### 4.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         PIVX Core Node                           │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────────┐ │
│  │ Block Data  │  │ Sapling RPC │  │ Commitment Tree State    │ │
│  └─────────────┘  └─────────────┘  └──────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ElectrumX Server                            │
│                                                                  │
│  ┌────────────────┐   ┌──────────────────────────────────────┐  │
│  │   Prefetcher   │──▶│         Block Processor              │  │
│  └────────────────┘   │  ┌────────────────────────────────┐  │  │
│                       │  │ Transparent TX Processing      │  │  │
│                       │  ├────────────────────────────────┤  │  │
│                       │  │ Sapling TX Processing (NEW)    │  │  │
│                       │  │  - Extract nullifiers          │  │  │
│                       │  │  - Extract commitments/cmu     │  │  │
│                       │  │  - Store ciphertexts           │  │  │
│                       │  │  - Track positions             │  │  │
│                       │  └────────────────────────────────┘  │  │
│                       └──────────────────────────────────────┘  │
│                                        │                         │
│                                        ▼                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Database Layer                         │   │
│  │  ┌────────────┐  ┌────────────┐  ┌─────────────────────┐ │   │
│  │  │  UTXO DB   │  │ History DB │  │  Sapling DB (NEW)   │ │   │
│  │  └────────────┘  └────────────┘  │  - Nullifiers       │ │   │
│  │                                   │  - Outputs/Cmu      │ │   │
│  │                                   │  - Positions        │ │   │
│  │                                   │  - Anchors          │ │   │
│  │                                   └─────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                        │                         │
│                                        ▼                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Session / API Layer                    │   │
│  │  ┌──────────────────┐  ┌─────────────────────────────┐   │   │
│  │  │ Transparent APIs │  │ Sapling APIs (NEW)          │   │   │
│  │  │ - get_balance    │  │ - get_sapling_outputs       │   │   │
│  │  │ - get_history    │  │ - get_nullifiers            │   │   │
│  │  │ - listunspent    │  │ - get_sapling_tree_state    │   │   │
│  │  │ - subscribe      │  │ - get_sapling_witnesses     │   │   │
│  │  └──────────────────┘  └─────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Light Wallet Client                           │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Client-Side Operations:                                 │    │
│  │  - Trial decryption with viewing key                     │    │
│  │  - Note discovery and balance calculation                │    │
│  │  - Witness construction for spending                     │    │
│  │  - Transaction building                                  │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Data Flow for Sapling Transactions

```
1. Block received from PIVX Core
   │
2. Parse block header (handle variable header size)
   │
3. For each transaction:
   │
   ├─▶ Parse transparent inputs/outputs (existing flow)
   │   └─▶ Update UTXO and history tables
   │
   └─▶ Parse Sapling components (NEW)
       │
       ├─▶ For each vShieldedSpend:
       │   ├─ Extract nullifier (32 bytes)
       │   ├─ Store: nullifier → (txid, height, spend_index)
       │   └─ Mark as "spent" indicator for notes
       │
       └─▶ For each vShieldedOutput:
           ├─ Extract cmu (note commitment, 32 bytes)
           ├─ Extract ephemeralKey (32 bytes)
           ├─ Extract encCiphertext (580 bytes)
           ├─ Extract outCiphertext (80 bytes)
           ├─ Calculate position in global commitment tree
           └─ Store: position → (cmu, epk, enc, out, txid, height, output_index)

4. Update Sapling tree state (anchor tracking)

5. On reorg: Remove Sapling data for disconnected blocks
```

---

## 5. Database Schema

### 5.1 Existing DB Structure

Current ElectrumX uses two LevelDB databases:
- `utxo`: UTXO state, metadata
- `hist`: Address history

Key prefixes:
- `b'u'` + hashX + tx_idx + tx_num → UTXO value
- `b'h'` + compressed_tx_hash + tx_idx + tx_num → hashX
- `b'U'` + height → undo info
- `b'state'` → chain state

### 5.2 New Sapling Tables

We introduce a third database: `sapling` (or extend `utxo` with new prefixes)

#### 5.2.1 Sapling Outputs Table

**Key:** `b'O'` + position (8 bytes, big-endian)

**Value:**
```
┌──────────────────────────────────────────────────────────────┐
│ cmu (32) │ epk (32) │ enc (580) │ out (80) │ txid (32) │     │
│          │          │           │          │           │     │
│          │          │           │          │ height(4) │     │
│          │          │           │          │ idx (2)   │     │
└──────────────────────────────────────────────────────────────┘
Total: 762 bytes
```

**Fields:**
| Field | Size | Description |
|-------|------|-------------|
| cmu | 32 | Note commitment (u-coordinate) |
| epk | 32 | Ephemeral public key for ECDH |
| enc | 580 | Encrypted note plaintext |
| out | 80 | Outgoing cipher (for sender) |
| txid | 32 | Transaction hash |
| height | 4 | Block height (big-endian) |
| idx | 2 | Output index within transaction |

**Index by cmu:** `b'C'` + cmu (32) → tx_num (4) + output_index (2) + position (8)
- Enables lookup of output by commitment and stable global position

**Index by position:** `b'P'` + position (8, big-endian) → tx_num (4) + output_index (2) + cmu (32)
- Defines canonical global Sapling output order
- Positions are assigned by block height, transaction order, then
  `vShieldOutput` order. Blocks with no Sapling outputs do not consume
  positions.

**Index by indexed root:** `b'R'` + root (32) → tree_size (8) + height (4)
- Binds witness responses to the root requested by the client
- Reorg rollback deletes roots and positions from reverted blocks

#### 5.2.2 Sapling Nullifiers Table

**Key:** `b'N'` + nullifier (32 bytes)

**Value:**
```
┌──────────────────────────────────────────────────┐
│ txid (32) │ height (4) │ spend_index (2) │
└──────────────────────────────────────────────────┘
Total: 38 bytes
```

**Fields:**
| Field | Size | Description |
|-------|------|-------------|
| txid | 32 | Transaction hash where nullifier appeared |
| height | 4 | Block height (big-endian) |
| spend_index | 2 | Index within vShieldedSpend |

**Index by height:** `b'X'` + height (4) + nullifier (32) → (empty value)
- Enables efficient reorg rollback

#### 5.2.3 Sapling Tree State Table

**Key:** `b'T'` + height (4 bytes, big-endian)

**Value:**
```
┌────────────────────────────────────────────────────────────────┐
│ anchor (32) │ tree_size (8) │ tree_frontier (variable)         │
└────────────────────────────────────────────────────────────────┘
```

**Fields:**
| Field | Size | Description |
|-------|------|-------------|
| anchor | 32 | Merkle root of commitment tree |
| tree_size | 8 | Total commitments in tree |
| tree_frontier | ~1KB | Incremental Merkle tree frontier |

**Note:** We may rely on PIVX Core for tree state via RPC rather than maintaining our own copy.

#### 5.2.4 Sapling Metadata Table

**Key:** `b'M'` + `b'sapling_state'`

**Value:**
```python
{
    'sapling_height': int,        # Last indexed Sapling height
    'total_outputs': int,         # Total Sapling outputs indexed
    'total_nullifiers': int,      # Total nullifiers indexed
    'latest_anchor': bytes,       # Most recent anchor
}
```

### 5.3 Schema Design Rationale

1. **Position-based output keys**: Sapling commitments form a global ordered set. Position is the natural primary key.

2. **Separate cmu index**: Wallets may want to look up an output by its commitment (e.g., when checking spend status).

3. **Height-based indices**: Enable efficient range queries for sync and reorg.

4. **Nullifier as primary key**: Each nullifier is unique across all time. Direct lookup enables O(1) spend checking.

5. **Minimal server-side data**: We store encrypted ciphertexts, not decrypted notes. Privacy is preserved.

---

## 6. Block & Transaction Parsing

### 6.1 Updated Deserializer

We need to update the PIVX deserializer to extract and expose Sapling data:

```python
# lib/tx.py

@dataclass(kw_only=True, slots=True)
class SaplingSpend:
    """Represents a Sapling spend description."""
    cv: bytes           # 32 bytes - value commitment
    anchor: bytes       # 32 bytes - Merkle tree root
    nullifier: bytes    # 32 bytes - unique nullifier
    rk: bytes           # 32 bytes - randomized public key
    zkproof: bytes      # 192 bytes - Groth16 proof
    spend_auth_sig: bytes  # 64 bytes - signature

@dataclass(kw_only=True, slots=True)
class SaplingOutput:
    """Represents a Sapling output description."""
    cv: bytes           # 32 bytes - value commitment
    cmu: bytes          # 32 bytes - note commitment (u-coordinate)
    ephemeral_key: bytes  # 32 bytes - for ECDH
    enc_ciphertext: bytes  # 580 bytes - encrypted note
    out_ciphertext: bytes  # 80 bytes - for sender recovery
    zkproof: bytes      # 192 bytes - Groth16 proof

@dataclass(kw_only=True, slots=True)
class TxPIVXSapling(Tx):
    """PIVX transaction with Sapling components."""
    tx_type: int                          # DIP2-style tx type
    value_balance: int                    # Net value in/out of shielded pool
    sapling_spends: list[SaplingSpend]    # Shielded spends
    sapling_outputs: list[SaplingOutput]  # Shielded outputs
    binding_sig: bytes                    # Binding signature (64 bytes)
    extra_payload: bytes                  # Extra data for special tx types


class DeserializerPIVXSapling(Deserializer):
    """Deserializer for PIVX transactions with full Sapling support."""
    
    SAPLING_SPEND_SIZE = 384
    SAPLING_OUTPUT_SIZE = 948
    
    def read_tx(self):
        orig_start = self.cursor
        start = self.cursor
        
        # Read header (version + tx_type)
        header = self._read_le_uint32()
        tx_type = header >> 16
        if tx_type:
            version = header & 0x0000ffff
        else:
            version = header
        
        if tx_type and version < 3:
            version = header
            tx_type = 0
        
        # Read transparent parts
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        locktime = self._read_le_uint32()
        
        # Initialize Sapling fields
        value_balance = 0
        sapling_spends = []
        sapling_outputs = []
        binding_sig = b''
        extra_payload = b''
        
        # Sapling components (version >= 3)
        if version >= 3:
            self._read_varint()  # nExpiryHeight size
            value_balance = self._read_le_int64()
            
            # Read shielded spends
            spend_count = self._read_varint()
            for _ in range(spend_count):
                sapling_spends.append(self._read_sapling_spend())
            
            # Read shielded outputs
            output_count = self._read_varint()
            for _ in range(output_count):
                sapling_outputs.append(self._read_sapling_output())
            
            # Binding signature (if any shielded components)
            if sapling_spends or sapling_outputs:
                binding_sig = self._read_nbytes(64)
            
            # Extra payload for special transactions
            if tx_type > 0:
                payload_size = self._read_varint()
                extra_payload = self._read_nbytes(payload_size)
        
        tx = TxPIVXSapling(
            version=version,
            inputs=inputs,
            outputs=outputs,
            locktime=locktime,
            txid=None,
            wtxid=None,
            tx_type=tx_type,
            value_balance=value_balance,
            sapling_spends=sapling_spends,
            sapling_outputs=sapling_outputs,
            binding_sig=binding_sig,
            extra_payload=extra_payload,
        )
        
        tx.txid = tx.wtxid = self.TX_HASH_FN(self.binary[orig_start:self.cursor])
        return tx
    
    def _read_sapling_spend(self):
        return SaplingSpend(
            cv=self._read_nbytes(32),
            anchor=self._read_nbytes(32),
            nullifier=self._read_nbytes(32),
            rk=self._read_nbytes(32),
            zkproof=self._read_nbytes(192),
            spend_auth_sig=self._read_nbytes(64),
        )
    
    def _read_sapling_output(self):
        return SaplingOutput(
            cv=self._read_nbytes(32),
            cmu=self._read_nbytes(32),
            ephemeral_key=self._read_nbytes(32),
            enc_ciphertext=self._read_nbytes(580),
            out_ciphertext=self._read_nbytes(80),
            zkproof=self._read_nbytes(192),
        )
```

### 6.2 Block Processor Updates

Update `server/block_processor.py` to process Sapling data:

```python
class BlockProcessor(server.db.DB):
    
    def __init__(self, env, controller, daemon):
        super().__init__(env)
        # ... existing init ...
        
        # Sapling state
        self.sapling_position = 0  # Current commitment tree position
        self.sapling_outputs_cache = []  # Pending outputs to flush
        self.sapling_nullifiers_cache = []  # Pending nullifiers to flush
    
    def advance_txs(self, txs):
        # ... existing transparent processing ...
        
        # Process Sapling components
        for tx, tx_hash in txs:
            if hasattr(tx, 'sapling_spends'):
                self.process_sapling_tx(tx, tx_hash, self.height)
    
    def process_sapling_tx(self, tx, tx_hash, height):
        """Process Sapling spends and outputs."""
        
        # Process spends (nullifiers)
        for spend_idx, spend in enumerate(tx.sapling_spends):
            self.sapling_nullifiers_cache.append({
                'nullifier': spend.nullifier,
                'txid': tx_hash,
                'height': height,
                'spend_index': spend_idx,
            })
        
        # Process outputs
        for output_idx, output in enumerate(tx.sapling_outputs):
            position = self.sapling_position
            self.sapling_position += 1
            
            self.sapling_outputs_cache.append({
                'position': position,
                'cmu': output.cmu,
                'ephemeral_key': output.ephemeral_key,
                'enc_ciphertext': output.enc_ciphertext,
                'out_ciphertext': output.out_ciphertext,
                'txid': tx_hash,
                'height': height,
                'output_index': output_idx,
            })
    
    def flush_sapling(self, batch):
        """Flush Sapling data to database."""
        batch_put = batch.put
        
        # Flush outputs
        for output in self.sapling_outputs_cache:
            pos_key = b'O' + struct.pack('>Q', output['position'])
            value = (
                output['cmu'] +
                output['ephemeral_key'] +
                output['enc_ciphertext'] +
                output['out_ciphertext'] +
                output['txid'] +
                struct.pack('>I', output['height']) +
                struct.pack('>H', output['output_index'])
            )
            batch_put(pos_key, value)
            
            # Index by cmu
            cmu_key = b'C' + output['cmu']
            batch_put(cmu_key, struct.pack('>Q', output['position']))
            
            # Index by height
            height_key = b'H' + struct.pack('>I', output['height']) + struct.pack('>Q', output['position'])
            batch_put(height_key, b'')
        
        # Flush nullifiers
        for nf in self.sapling_nullifiers_cache:
            nf_key = b'N' + nf['nullifier']
            value = (
                nf['txid'] +
                struct.pack('>I', nf['height']) +
                struct.pack('>H', nf['spend_index'])
            )
            batch_put(nf_key, value)
            
            # Index by height
            height_key = b'X' + struct.pack('>I', nf['height']) + nf['nullifier']
            batch_put(height_key, b'')
        
        # Clear caches
        self.sapling_outputs_cache = []
        self.sapling_nullifiers_cache = []
```

---

## 7. API Design

### 7.0 Production v1 Contract for Cake Wallet

PIVX Sapling clients should start with capability discovery:

```json
{
    "method": "blockchain.sapling.capabilities",
    "params": []
}
```

The response includes `contract: "pivx.sapling.electrumx.v1"`,
`max_block_range`, primary method names, and aliases.  Supported aliases:

| Client need | Primary method | Aliases |
|-------------|----------------|---------|
| Capability probe | `blockchain.sapling.capabilities` | `blockchain.sapling.get_capabilities`, `server.sapling.capabilities` |
| Block range scan | `blockchain.sapling.get_block_range` | `blockchain.sapling.get_blocks` |
| Nullifier status | `blockchain.sapling.get_nullifier_status` | `blockchain.sapling.check_nullifier` |
| Batch nullifier status | `blockchain.sapling.check_nullifiers` | - |
| Commitment info | `blockchain.sapling.get_commitment_info` | `blockchain.sapling.get_commitment` |
| Best anchor | `blockchain.sapling.get_best_anchor` | `blockchain.sapling.best_anchor` |
| Anchor height | `blockchain.sapling.get_anchor_height` | - |
| Tree state | `blockchain.sapling.get_tree_state` | `blockchain.sapling.get_treestate` |
| Witness | `blockchain.sapling.get_witness` | `blockchain.sapling.get_witnesses` for batches |

`blockchain.sapling.get_block_range` returns a v1 envelope, not a bare list:

```json
{
    "success": true,
    "complete": true,
    "empty": false,
    "contract": "pivx.sapling.electrumx.v1",
    "start_height": 2700500,
    "end_height": 2700599,
    "height_count": 100,
    "block_count": 2,
    "sapling_tx_count": 3,
    "blocks": [],
    "error": null
}
```

An empty successful range is represented by `success: true`,
`complete: true`, `empty: true`, and `blocks: []`.  Daemon, index, method, and
partial scan failures are represented by `success: false`, `complete: false`,
and a structured `error` object.  A failed range must never be treated as
complete, even if it includes partial `blocks` scanned before the failure.

### 7.1 New Sapling RPC Methods

#### 7.1.1 `blockchain.sapling.get_outputs`

Get Sapling outputs in a height range for client-side scanning.

**Request:**
```json
{
    "method": "blockchain.sapling.get_outputs",
    "params": {
        "start_height": 2700500,
        "end_height": 2700600,
        "start_position": 0
    }
}
```

**Response:**
```json
{
    "outputs": [
        {
            "position": 0,
            "cmu": "hex...",
            "ephemeral_key": "hex...",
            "enc_ciphertext": "hex...",
            "out_ciphertext": "hex...",
            "txid": "hex...",
            "height": 2700500,
            "block_hash": "hex...",
            "output_index": 0
        },
        ...
    ],
    "total_outputs_in_range": 150,
    "continuation_position": 100
}
```

`blockchain.sapling.get_block_range` returns the same global `position` for
each Sapling output. Blocks include a top-level `outputs` array ordered exactly
as PIVX Core presents transactions in the block and outputs inside each
transaction, and each transaction also includes its own `outputs` array for
callers that prefer grouped data.

Clients should persist the `block_hash` returned for each scanned height.
On resume, rescan from at least the rollback boundary
`max(SAPLING_START_HEIGHT, last_scanned_height - 99)` and compare stored
hashes against returned hashes. A mismatch means local scanned Sapling state is
stale and must be rewound to the last matching height.

#### 7.1.2 `blockchain.sapling.get_witness`

Get an anchor-bound witness for a Sapling output position.

**Request:**
```json
{
    "method": "blockchain.sapling.get_witness",
    "params": [12345, "hex_indexed_root"]
}
```

**Response:**
```json
{
    "anchor": "hex_indexed_root",
    "root": "hex_indexed_root",
    "anchor_height": 2700600,
    "position": 12345,
    "commitment": "hex_cmu",
    "path": [
        {"position": "right", "hash": "hex_sibling"},
        {"position": "left", "hash": "hex_sibling"}
    ]
}
```

`blockchain.sapling.get_witnesses` accepts a list of positions and the same
optional anchor/root, returning one witness object per requested position.

#### 7.1.3 `blockchain.sapling.check_nullifiers`

Check if nullifiers have been spent.

**Request:**
```json
{
    "method": "blockchain.sapling.check_nullifiers",
    "params": {
        "nullifiers": ["hex_nullifier_1", "hex_nullifier_2"]
    }
}
```

**Response:**
```json
{
    "results": {
        "hex_nullifier_1": {
            "spent": true,
            "txid": "hex...",
            "height": 2700550
        },
        "hex_nullifier_2": {
            "spent": false
        }
    }
}
```

#### 7.1.4 `blockchain.sapling.get_tree_state`

Get Sapling commitment tree state at a height.

**Request:**
```json
{
    "method": "blockchain.sapling.get_tree_state",
    "params": {
        "height": 2700500
    }
}
```

**Response:**
```json
{
    "height": 2700500,
    "anchor": "hex_merkle_root",
    "tree_size": 12345,
    "sapling_activation_height": 2700500
}
```

#### 7.1.5 `blockchain.sapling.get_nullifiers`

Get nullifiers published in a height range.

**Request:**
```json
{
    "method": "blockchain.sapling.get_nullifiers",
    "params": {
        "start_height": 2700500,
        "end_height": 2700600
    }
}
```

**Response:**
```json
{
    "nullifiers": [
        {
            "nullifier": "hex...",
            "txid": "hex...",
            "height": 2700510,
            "spend_index": 0
        },
        ...
    ]
}
```

### 7.2 Session Handler Implementation

```python
# server/session.py

class ElectrumXSapling(ElectrumX):
    """Extended session with Sapling support."""
    
    def set_protocol_handlers(self, ptuple):
        super().set_protocol_handlers(ptuple)
        
        # Add Sapling handlers
        self.electrumx_handlers.update({
            'blockchain.sapling.get_outputs': self.sapling_get_outputs,
            'blockchain.sapling.check_nullifiers': self.sapling_check_nullifiers,
            'blockchain.sapling.get_tree_state': self.sapling_get_tree_state,
            'blockchain.sapling.get_nullifiers': self.sapling_get_nullifiers,
        })
    
    async def sapling_get_outputs(self, start_height, end_height, start_position=0, limit=1000):
        """Get Sapling outputs for a height range."""
        return await self.controller.sapling_get_outputs(
            start_height, end_height, start_position, limit
        )
    
    async def sapling_check_nullifiers(self, nullifiers):
        """Check if nullifiers are spent."""
        return await self.controller.sapling_check_nullifiers(nullifiers)
    
    async def sapling_get_tree_state(self, height):
        """Get Sapling tree state at height."""
        return await self.controller.sapling_get_tree_state(height)
    
    async def sapling_get_nullifiers(self, start_height, end_height):
        """Get nullifiers in height range."""
        return await self.controller.sapling_get_nullifiers(start_height, end_height)
```

---

## 8. PIVX Core RPC Integration

### 8.1 Required RPC Calls

| RPC Method | Purpose | Usage |
|------------|---------|-------|
| `getblock` | Get block data | Primary block retrieval |
| `getrawtransaction` | Get raw transaction | Transaction details |
| `getblockcount` | Current height | Sync status |
| `getbestsaplinganchor` | Get current tree root | Latest anchor/tree root |

### 8.2 PIVX-Specific RPC Extensions

PIVX Core provides the following Sapling-related RPCs:

```python
# server/daemon.py

class PIVXDaemon(Daemon):
    """PIVX-specific daemon with Sapling RPC support."""
    
    async def get_best_sapling_anchor(self):
        """Get the current best Sapling merkle tree root."""
        return await self._send_single('getbestsaplinganchor', [])
    
    # Note: PIVX does not have z_gettreestate like Zcash.
    # Witness computation must be done by the wallet client
    # using the commitment tree data indexed by ElectrumX.
        pass
```

### 8.3 Consensus Alignment

To ensure we never deviate from PIVX Core consensus:

1. **Proof verification**: We do NOT verify zk-SNARK proofs in Python. PIVX Core has already validated them.

2. **Commitment tree**: We either:
   - Query PIVX Core for tree state via RPC
   - Maintain our own incremental Merkle tree (more complex)
   
3. **Nullifier set**: We maintain the same nullifier set that PIVX Core maintains.

4. **Reorg handling**: On reorg, we fully re-sync affected blocks.

---

## 9. Reorg Handling

### 9.1 Sapling Reorg Strategy

When a chain reorganization occurs:

```python
def backup_sapling(self, height):
    """Roll back Sapling data from a height."""
    
    # Delete outputs at or above this height
    prefix = b'H' + struct.pack('>I', height)
    for key, _ in self.sapling_db.iterator(prefix=prefix):
        # Extract position from key
        pos = struct.unpack('>Q', key[5:])[0]
        
        # Delete output
        self.sapling_db.delete(b'O' + key[5:])
        
        # Delete cmu index (need to read output first)
        output_data = self.sapling_db.get(b'O' + key[5:])
        if output_data:
            cmu = output_data[:32]
            self.sapling_db.delete(b'C' + cmu)
        
        # Delete height index
        self.sapling_db.delete(key)
    
    # Delete nullifiers at or above this height
    prefix = b'X' + struct.pack('>I', height)
    for key, _ in self.sapling_db.iterator(prefix=prefix):
        nullifier = key[5:]
        self.sapling_db.delete(b'N' + nullifier)
        self.sapling_db.delete(key)
    
    # Update Sapling position counter
    self.sapling_position = self.get_sapling_position_at_height(height - 1)
```

### 9.2 Undo Information

For more efficient reorgs, we can store undo information:

```python
def write_sapling_undo(self, height, outputs_count, nullifiers):
    """Store undo info for Sapling data at a height."""
    undo_key = b'SU' + struct.pack('>I', height)
    undo_value = struct.pack('>I', outputs_count) + b''.join(nullifiers)
    self.sapling_db.put(undo_key, undo_value)
```

---

## 10. Performance Considerations

### 10.1 Storage Estimates

For PIVX mainnet (assuming Sapling adoption similar to Zcash):

| Data Type | Per-Item Size | Estimated Count | Total Size |
|-----------|---------------|-----------------|------------|
| Sapling Output | ~762 bytes | 1M outputs | ~762 MB |
| Nullifier | ~38 bytes | 500K nullifiers | ~19 MB |
| Height Indices | ~12 bytes | 1.5M entries | ~18 MB |
| Cmu Indices | ~40 bytes | 1M entries | ~40 MB |

**Total estimated additional storage: ~850 MB** for mature chain

### 10.2 Query Performance

| Operation | Complexity | Expected Time |
|-----------|------------|---------------|
| Get output by position | O(1) | <1ms |
| Check nullifier spent | O(1) | <1ms |
| Get outputs in height range | O(n) where n = outputs in range | ~10ms/1000 outputs |
| Get nullifiers in height range | O(n) | ~5ms/1000 nullifiers |

### 10.3 Batch Processing

During initial sync, batch writes are critical:

```python
SAPLING_BATCH_SIZE = 10000  # Flush every 10K items

def flush_sapling_if_needed(self):
    if (len(self.sapling_outputs_cache) + len(self.sapling_nullifiers_cache)) >= SAPLING_BATCH_SIZE:
        self.flush_sapling(self.sapling_db.write_batch())
```

### 10.4 Caching

For frequently accessed data:

```python
# LRU cache for recent nullifier lookups
self.nullifier_cache = pylru.lrucache(10000)

# Cache for tree state at recent heights
self.tree_state_cache = pylru.lrucache(100)
```

---

## 11. Implementation Plan

### Phase 1: Core Infrastructure (Week 1-2)

1. **Update Coin Configuration**
   - Add SAPLING_START_HEIGHT, HRP constants
   - Update DESERIALIZER to new Sapling-aware class

2. **Implement Deserializer**
   - Create `DeserializerPIVXSapling`
   - Add `SaplingSpend`, `SaplingOutput`, `TxPIVXSapling` data classes
   - Unit tests for parsing

3. **Database Schema**
   - Create Sapling database (or extend existing)
   - Implement key/value encoding/decoding
   - Add indices

### Phase 2: Indexing (Week 2-3)

4. **Block Processor Updates**
   - Integrate Sapling processing into `advance_txs`
   - Implement `flush_sapling`
   - Position tracking

5. **Reorg Handling**
   - Implement `backup_sapling`
   - Undo information storage
   - Integration with existing reorg flow

6. **State Management**
   - Sapling metadata persistence
   - Recovery from interrupted sync

### Phase 3: API & Integration (Week 3-4)

7. **Session Handlers**
   - Implement `ElectrumXSapling` session class
   - Add RPC method handlers

8. **Controller Updates**
   - Add Sapling query methods
   - Integrate with session handlers

9. **PIVX Core RPC**
   - Implement `PIVXDaemon` if needed
   - Tree state queries (if available)

### Phase 4: Testing & Optimization (Week 4-5)

10. **Unit Tests**
    - Deserializer tests
    - Database operation tests
    - Reorg tests

11. **Integration Tests**
    - End-to-end sync test
    - API response validation
    - Reorg simulation

12. **Performance Testing**
    - Sync speed benchmarks
    - Query latency measurements
    - Memory usage profiling

13. **Documentation**
    - API documentation
    - Wallet developer guide
    - Deployment guide

---

## Appendix A: PIVX Core Reference

### Sapling Activation Heights

From PIVX Core `chainparams.cpp`:

```cpp
// Mainnet
consensus.vUpgrades[Consensus::UPGRADE_V5_0].nActivationHeight = 2700500;

// Testnet  
consensus.vUpgrades[Consensus::UPGRADE_V5_0].nActivationHeight = 201;
```

Source checked against PIVX Core release tag `v5.6.1`
(`src/chainparams.cpp`):
https://github.com/PIVX-Project/PIVX/blob/v5.6.1/src/chainparams.cpp

PIVX ElectrumX keeps the default PIVX `REORG_LIMIT` at 100 blocks. Cake Wallet
clients should be able to rescan the last 100 inclusive heights, with block
hashes in scan responses used to detect stale local branch state.

### Transaction Version Mapping

| Version | Features |
|---------|----------|
| 1 | Legacy transparent only |
| 2 | + Sprout JoinSplit (not used in PIVX) |
| 3 | + Sapling (Overwinter) |
| 4 | Sapling (full) |

---

## Appendix B: Sapling Ciphertext Format

### Encrypted Note Plaintext (580 bytes)

```
┌──────────────────────────────────────────────────────────────┐
│ lead_byte (1) │ diversifier (11) │ value (8) │ rcm (32) │    │
│               │                  │           │          │    │
│                          memo (512 bytes)                    │
└──────────────────────────────────────────────────────────────┘
```

The client decrypts this using:
- `KDF(sharedSecret, ephemeralKey)` → symmetric key
- ChaCha20-Poly1305 AEAD decryption

### Outgoing Ciphertext (80 bytes)

```
┌──────────────────────────────────────────────────────────────┐
│ pkd (32) │ esk (32) │ (16 bytes auth tag included)          │
└──────────────────────────────────────────────────────────────┘
```

Allows sender to recover the note they sent.

---

## Appendix C: Wallet Integration Guide

### Syncing Process

1. **Get current height** from server
2. **Fetch outputs** in batches:
   ```
   GET blockchain.sapling.get_outputs(last_synced + 1, current_height)
   ```
3. **Trial decrypt** each output with viewing key
4. **Store discovered notes** locally
5. **Check nullifiers** for previously discovered notes:
   ```
   GET blockchain.sapling.check_nullifiers([nf1, nf2, ...])
   ```
6. **Update wallet balance**

### Spending a Note

1. **Select note(s)** to spend
2. **Get tree state** at a recent height:
   ```
   GET blockchain.sapling.get_tree_state(height)
   ```
3. **Construct witness** for note's commitment position
4. **Build Sapling spend** with proper anchor
5. **Sign and broadcast** transaction

### Balance Calculation

```
balance = Σ(decrypted note values) - Σ(spent note values)
```

Where spent notes are those whose nullifiers appear in the chain.

---

## Appendix D: Implementation Status

**Last Updated:** December 2024

### Completed Components

#### 1. Transaction Deserializer (`lib/tx.py`)
- ✅ `SaplingSpend` namedtuple (384 bytes: cv, anchor, nullifier, rk, zkproof, spend_auth_sig)
- ✅ `SaplingOutput` namedtuple (948 bytes: cv, cmu, ephemeral_key, enc_ciphertext, out_ciphertext, zkproof)
- ✅ `TxPIVXSapling` namedtuple (includes value_balance, sapling_spends, sapling_outputs, binding_sig)
- ✅ `DeserializerPIVXSapling` class with full Sapling data parsing

#### 2. Coin Configuration (`lib/coins.py`)
- ✅ Added `SAPLING_START_HEIGHT = 2700500` for mainnet
- ✅ Added `SAPLING_START_HEIGHT = 201` for testnet
- ✅ Set `DESERIALIZER = DeserializerPIVXSapling`
- ✅ Set `SESSIONCLS = PIVXSaplingElectrumX`

#### 3. Database Schema (`server/db.py`)
- ✅ Nullifier table: `b'N' + nullifier → tx_num + spend_index`
- ✅ Commitment table: `b'C' + commitment → tx_num + output_index + position`
- ✅ Position table: `b'P' + position → tx_num + output_index + commitment`
- ✅ Anchor table: `b'A' + anchor → block_height`
- ✅ Indexed root table: `b'R' + root → tree_size + height`
- ✅ Methods: `get_nullifier_spend()`, `get_commitment_info()`, `is_nullifier_spent()`
- ✅ Methods: `get_anchor_height()`, `get_sapling_witness()`
- ✅ `flush_sapling_data()` and `backup_sapling_data()` for persistence/reorg

#### 4. Block Processor (`server/block_processor.py`)
- ✅ Extended `advance_txs()` to extract Sapling spends/outputs/anchors
- ✅ Added `sapling_cache` for batch flush optimization
- ✅ Updated `flush()` to persist Sapling data
- ✅ Updated `backup_flush()` to remove Sapling data on reorg
- ✅ Updated `assert_flushed()` to verify Sapling cache is empty

#### 5. API Endpoints (`server/session.py`)
- ✅ `PIVXSaplingElectrumX` session class
- ✅ `blockchain.sapling.get_nullifier_status` - Check if nullifier is spent
- ✅ `blockchain.sapling.get_commitment_info` - Get commitment details
- ✅ `blockchain.sapling.get_notes_for_ivk` - Get notes for viewing key
- ✅ `blockchain.sapling.get_anchor_height` - Get anchor validity height
- ✅ `blockchain.sapling.get_best_anchor` - Get current tree root from daemon

#### 6. Tests (`tests/lib/test_pivx_sapling.py`)
- ✅ `TestSaplingSpend` - Verify spend structure
- ✅ `TestSaplingOutput` - Verify output structure
- ✅ `TestTxPIVXSapling` - Verify transaction structure
- ✅ `TestDeserializerPIVXSapling` - Verify deserializer functionality
- ✅ `TestSaplingDataSizes` - Verify protocol-compliant sizes

### Future Enhancements

#### Short-term
- [ ] Add batch nullifier status check API
- [ ] Add output range query by block height
- [ ] Implement viewing key registration for push notifications
- [ ] Add commitment tree state caching

#### Medium-term
- [ ] Implement client-side witness computation from indexed tree data
- [ ] Add WebSocket subscriptions for Sapling events
- [ ] Implement compact block filters for efficient syncing

#### Long-term
- [ ] Full commitment tree reconstruction for witness generation
- [ ] Shield set analytics (anonymity set size, etc.)
- [ ] Support for additional Sapling-related BIPs

### Notes for Developers

1. **Python Version**: The base codebase uses `collections.Container` which was moved to `collections.abc` in Python 3.10+. You may need to patch `lib/util.py` for newer Python versions.

2. **Testing**: Run syntax validation with `python -m py_compile <file>` since the full test suite requires environment setup.

3. **Database Migration**: Existing PIVX databases will need to resync from Sapling activation height to populate the new indices.

4. **PIVX Core Requirements**: The server requires PIVX Core v5.0+ with Sapling support. The `getbestsaplinganchor` RPC is used to fetch the current tree root.
