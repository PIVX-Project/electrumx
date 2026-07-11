# PIVX Sapling Support for ElectrumX

## Design Document

**Version:** 2.0  
**Date:** July 2026  
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

1. **Server-side privacy**: The server indexes commitments, nullifiers, global output positions and consensus anchors, but never has access to private keys or decrypted note data.
2. **Client-side scanning and witnesses**: Wallet clients perform trial decryption using their viewing keys, build the note commitment tree locally, and compute their own Merkle witnesses. The server does not compute witnesses.
3. **Consensus alignment**: All indexed data aligns with PIVX Core's canonical chain state. Anchors are the consensus `finalsaplingroot` values PIVX Core commits into block headers — never a server-synthesized tree root.
4. **Performance**: Efficient batch operations and optimized indices for wallet queries.
5. **Reorg safety**: All Sapling data can be rolled back on chain reorganizations, and the Sapling index is flushed atomically with the UTXO state so a crash can never leave it ahead of the chain state.

---

## 2. Current State Analysis

### 2.1 PIVX Support in This Fork Before Sapling Integration

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

**Limitations before this work:**
- Only handled transparent transactions
- Zerocoin header support existed but no shielded indexing
- No Sapling-specific constants (activation height, etc.)
- Used the base `Deserializer` - not a Sapling-aware variant

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
release commit `af60f19`, `src/chainparams.cpp`) consensus rules:

| Parameter | Mainnet Value | Testnet Value |
|-----------|---------------|---------------|
| Sapling Activation Height | 2,700,500 | 201 |
| HRP (Bech32m prefix) | `ps` (shielded address) | `ptestsapling` |
| Extended Spending Key | `p-secret-spending-key-main` | `p-secret-spending-key-test` |
| Extended Full Viewing Key | `pxviews` | `pxviewtestsapling` |

### 3.2 Sapling Transaction Structure

A PIVX Sapling transaction (version ≥ 3) follows PIVX Core's
serialization, which wraps the shielded data and the special-transaction
payload in `Optional<T>` fields (a 1-byte presence flag followed by the
payload when the flag is non-zero):

```
Transaction v3+:
├── nVersion (2 bytes) | nType (2 bytes, DIP2-style special tx type)
├── vin[] (transparent inputs)
├── vout[] (transparent outputs)
├── nLockTime (4 bytes)
├── Optional<SaplingTxData> (1 presence byte; PIVX Core always writes
│   the flag for Sapling-version txs)
│   ├── valueBalance (8 bytes, signed)
│   ├── vShieldedSpend[] (each 384 bytes)
│   │   ├── cv (32 bytes) - value commitment
│   │   ├── anchor (32 bytes) - merkle tree root
│   │   ├── nullifier (32 bytes) - unique nullifier
│   │   ├── rk (32 bytes) - randomized public key
│   │   ├── zkproof (192 bytes) - Groth16 proof
│   │   └── spendAuthSig (64 bytes) - signature
│   ├── vShieldedOutput[] (each 948 bytes)
│   │   ├── cv (32 bytes) - value commitment
│   │   ├── cmu (32 bytes) - note commitment
│   │   ├── ephemeralKey (32 bytes) - for ECDH
│   │   ├── encCiphertext (580 bytes) - encrypted note
│   │   ├── outCiphertext (80 bytes) - encrypted for sender
│   │   └── zkproof (192 bytes) - Groth16 proof
│   └── bindingSig (64 bytes, only if any shielded spends/outputs)
└── Optional<vector<uint8>> extraPayload (only when nType > 0:
    1 presence byte, then compact-size length + data)
```

Note: unlike Zcash Overwinter, PIVX transactions have **no
`nExpiryHeight` field**. An earlier revision of this design misread the
`SaplingTxData` presence byte as an "nExpiryHeight varint", which broke
parsing of PIVX v6.0+ special transactions (`nType != 0`, e.g.
deterministic-masternode/LLMQ transactions). See section 6.1.

### 3.3 Sapling Cryptographic Primitives

**Note Commitment (cmu):**
- 32 bytes: the u-coordinate of a windowed Pedersen commitment (on the
  Jubjub curve) to the note contents (value, g_d, pk_d, rcm)
- Stored in the note commitment tree at a specific position
- The commitment tree itself is built with the `MerkleCRH^Sapling`
  Pedersen hash — **not** SHA-256 — which is why this server cannot
  synthesize consensus-valid roots or witnesses and leaves tree
  construction to clients (see section 7)

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
│  ┌─────────────┐  ┌──────────────────────┐  ┌────────────────┐  │
│  │ Block Data  │  │ getblock verbosity=2 │  │ Block Headers  │  │
│  │             │  │ getrawtransaction    │  │ finalsapling-  │  │
│  │             │  │                      │  │ root (v8+)     │  │
│  └─────────────┘  └──────────────────────┘  └────────────────┘  │
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
│                       │  │  - Assign global positions     │  │  │
│                       │  │  - Record consensus anchors    │  │  │
│                       │  │    from headers (first seen)   │  │  │
│                       │  └────────────────────────────────┘  │  │
│                       └──────────────────────────────────────┘  │
│                                        │                         │
│                                        ▼                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Database Layer                         │   │
│  │  ┌────────────┐  ┌────────────┐  ┌─────────────────────┐ │   │
│  │  │  UTXO DB   │  │ History DB │  │ Sapling index (NEW) │ │   │
│  │  └────────────┘  └────────────┘  │  - Nullifiers       │ │   │
│  │                                   │  - Commitments      │ │   │
│  │                                   │  - Positions        │ │   │
│  │                                   │  - Consensus anchors│ │   │
│  │                                   └─────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                        │                         │
│                                        ▼                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Session / API Layer                    │   │
│  │  ┌──────────────────┐  ┌─────────────────────────────┐   │   │
│  │  │ Transparent APIs │  │ Sapling APIs (NEW)          │   │   │
│  │  │ - get_balance    │  │ - get_block_range           │   │   │
│  │  │ - get_history    │  │ - get_outputs_by_height     │   │   │
│  │  │ - listunspent    │  │ - check_nullifiers          │   │   │
│  │  │ - subscribe      │  │ - get_tree_state            │   │   │
│  │  │                  │  │ - get_best_anchor           │   │   │
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
│  │  - Commitment tree construction (Pedersen hash over      │    │
│  │    Jubjub) from the ordered commitment stream            │    │
│  │  - Witness computation, verified against consensus       │    │
│  │    anchors from get_tree_state                           │    │
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
       │   └─ Index: nullifier → (tx_num, spend_index)
       │
       └─▶ For each vShieldedOutput:
           ├─ Assign the next global output position (canonical
           │  block / transaction / vShieldOutput order)
           ├─ Index: commitment → (tx_num, output_index, position)
           └─ Index: position → (tx_num, output_index, commitment)

4. Record the header's finalsaplingroot (consensus anchor) the first
   time it appears, together with the tree size (global output count)
   at which it formed

5. Flush Sapling data atomically with the UTXO state, so a crash can
   never persist output positions ahead of db_height

6. On reorg: remove Sapling data for reverted transactions, delete
   roots first seen at reverted heights, rewind the output count
```

Note that ciphertexts are **not** stored server-side. The index keeps
only nullifiers, commitments, positions and anchors; ephemeral keys and
ciphertexts are fetched from PIVX Core (`getblock` verbosity=2) at
query time.

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

### 5.2 Sapling Index Tables

The Sapling index lives in the existing `utxo` database under four new
key prefixes. It is deliberately minimal: no ciphertexts are duplicated
into the index, and all 32-byte keys are stored in raw little-endian
serialization order (the RPC layer converts to/from display hex, see
section 7.0).

#### 5.2.1 Nullifier Table

**Key:** `b'N'` + nullifier (32 bytes)

**Value:** `tx_num (4) + spend_index (2)`

| Field | Size | Description |
|-------|------|-------------|
| tx_num | 4 | Transaction number; resolved to (tx_hash, height) via the file system index (`fs_tx_hash`) |
| spend_index | 2 | Index within the spending tx's vShieldedSpend |

#### 5.2.2 Commitment Table

**Key:** `b'C'` + commitment (32 bytes)

**Value:** `tx_num (4) + output_index (2) + position (8)`

| Field | Size | Description |
|-------|------|-------------|
| tx_num | 4 | Creating transaction number |
| output_index | 2 | Index within the tx's vShieldedOutput |
| position | 8 | Global Sapling output position |

- Enables lookup of an output by its commitment (cmu) with its stable
  global position.

#### 5.2.3 Position Table

**Key:** `b'P'` + position (8 bytes, big-endian)

**Value:** `tx_num (4) + output_index (2) + commitment (32)`

- Defines canonical global Sapling output order
- Positions are assigned during block advance by block height,
  transaction order, then `vShieldOutput` order. Blocks with no Sapling
  outputs do not consume positions.

#### 5.2.4 Consensus Anchor Table

**Key:** `b'A'` + root (32 bytes)

**Value:** `height (4) + tree_size (8)`

| Field | Size | Description |
|-------|------|-------------|
| height | 4 | First height the root appeared at |
| tree_size | 8 | Number of note commitments in the tree when the root formed |

- `root` is the consensus `finalsaplingroot` from PIVX v8+ block
  headers (header bytes 80:112, raw little-endian serialization order)
- Entries are recorded **first-seen-only** during block advance: an
  existing entry is never overwritten, so the height always reflects
  the root's first appearance (a root repeats while no new shielded
  outputs are mined)
- Reorg rollback deletes roots first seen at reverted heights

#### 5.2.5 State Row

The existing `b'state'` row carries two Sapling fields:

- `sapling_output_count`: the flushed global output count
  (`db_sapling_output_count`). It is written in the same batch as the
  UTXO state, so after a crash the persisted count always matches
  `db_height` and replay cannot double-assign positions.
- `sapling_index_version`: stamped with `DB.SAPLING_INDEX_VERSION`
  (currently 1). Opening a DB that is synced past Sapling activation
  without the current index version raises a `DBError` demanding a
  resync from genesis.

### 5.3 Schema Design Rationale

1. **Position-based canonical order**: Sapling commitments form a global ordered set. The position tables make that order queryable in both directions (position → commitment, commitment → position).

2. **Separate cmu index**: Wallets may want to look up an output by its commitment (e.g., when checking spend status or mapping a decrypted note to its tree position).

3. **Nullifier as primary key**: Each nullifier is unique across all time. Direct lookup enables O(1) spend checking.

4. **Consensus anchors, not synthetic trees**: The server never computes Merkle roots or witnesses. It indexes the roots PIVX Core already committed to in block headers, plus the tree size at which each formed, so a client-built tree can be bounded and verified against consensus.

5. **Minimal server-side data**: We store no ciphertexts; encrypted note data is served from the daemon at query time. Privacy is preserved and the index stays small.

6. **Crash consistency**: All Sapling rows and the output count are flushed in the same write batch as the UTXO state (section 6.2).

---

## 6. Block & Transaction Parsing

### 6.1 Deserializer

`DeserializerPIVXSapling` in `lib/tx.py` extracts and exposes Sapling
data using PIVX Core's actual serialization — in particular its
`Optional<T>` encoding (1-byte presence flag, then the payload):

```python
# lib/tx.py

class SaplingSpend(namedtuple("SaplingSpend",
                              "cv anchor nullifier rk zkproof spend_auth_sig")):
    """Sapling spend description (384 bytes):
    cv(32) anchor(32) nullifier(32) rk(32) zkproof(192) spend_auth_sig(64)"""

class SaplingOutput(namedtuple("SaplingOutput",
                               "cv cmu ephemeral_key enc_ciphertext "
                               "out_ciphertext zkproof")):
    """Sapling output description (948 bytes):
    cv(32) cmu(32) epk(32) enc(580) out(80) zkproof(192)"""

class TxPIVXSapling(namedtuple("TxPIVXSapling",
                               "version tx_type inputs outputs locktime "
                               "value_balance sapling_spends sapling_outputs "
                               "binding_sig extra_payload")):
    """PIVX transaction with Sapling shielded components."""


class DeserializerPIVXSapling(Deserializer):
    SAPLING_SPEND_SIZE = 384
    SAPLING_OUTPUT_SIZE = 948

    def read_tx(self):
        # Read header: int16 nVersion | int16 nType (DIP2-style)
        header = self._read_le_uint32()
        tx_type = header >> 16
        version = (header & 0x0000ffff) if tx_type else header
        if tx_type and version < 3:
            version, tx_type = header, 0

        inputs = self._read_inputs()
        outputs = self._read_outputs()
        locktime = self._read_le_uint32()

        value_balance = 0
        sapling_spends = []
        sapling_outputs = []
        binding_sig = b''
        extra_payload = b''

        if version >= 3:
            # Optional<SaplingTxData>: 1-byte presence flag, then the
            # payload if the flag is non-zero.  PIVX Core always writes
            # the flag for Sapling-version txs.
            if self._read_byte():
                value_balance = self._read_le_int64()
                for _ in range(self._read_varint()):
                    sapling_spends.append(self._read_sapling_spend())
                for _ in range(self._read_varint()):
                    sapling_outputs.append(self._read_sapling_output())
                # Binding signature, only if there are shielded components
                if sapling_spends or sapling_outputs:
                    binding_sig = self._read_nbytes(64)

            # Optional<vector<uint8>> extraPayload for special tx types:
            # 1-byte presence flag, then compact-size length + data
            if tx_type > 0 and self._read_byte():
                extra_payload = self._read_varbytes()

        return TxPIVXSapling(version, tx_type, inputs, outputs, locktime,
                             value_balance, sapling_spends, sapling_outputs,
                             binding_sig, extra_payload)
```

Two points are load-bearing here:

- There is **no "nExpiryHeight varint"** in the PIVX format. An earlier
  revision read one before `valueBalance`; that was a misreading of the
  `Optional<SaplingTxData>` presence byte.
- `extraPayload` is also `Optional`: a presence byte, **then** a
  compact-size length and the data. With both fixed, PIVX v6.0+ special
  transactions (`nType != 0`, e.g. deterministic-masternode/LLMQ txs)
  parse correctly.

### 6.2 Block Processor

`server/block_processor.py` accumulates Sapling data in a cache that is
flushed atomically with the UTXO state:

```python
# BlockProcessor.__init__

# Sapling shielded data cache, flushed atomically with the UTXOs.
# _last_sapling_root tracks the most recent header root so only
# first appearances are recorded as anchors.
self.sapling_cache = {'adds': [], 'spends': [], 'anchors': []}
self._last_sapling_root = None
```

`advance_txs()` assigns global output positions in canonical
block/tx/`vShieldOutput` order as it processes each transaction:

```python
# In the advance_txs() per-tx loop:

# Index Sapling shielded data if present (only txs from a
# Sapling-capable deserializer carry these attributes)
for spend_idx, spend in enumerate(getattr(tx, 'sapling_spends', ())):
    sapling_spends.append((tx_num, spend_idx, spend.nullifier))

for output_idx, output in enumerate(getattr(tx, 'sapling_outputs', ())):
    # Store the commitment (cmu); full output data is
    # fetched from the daemon at query time
    sapling_adds.append((tx_num, output_idx, output.cmu,
                         self.sapling_output_count))
    self.sapling_output_count += 1
```

After each block's outputs are counted, `advance_blocks()` calls
`advance_sapling_anchor()` to record the header's consensus root the
first time it appears, together with the tree size at that point:

```python
def advance_sapling_anchor(self, header, height):
    '''Record the header's finalsaplingroot with the current tree
    size, the first time the root appears.'''
    sapling_start = getattr(self.coin, 'SAPLING_START_HEIGHT', None)
    if (sapling_start is None or height < sapling_start
            or len(header) < 112):
        return
    root = header[80:112]
    if root != self._last_sapling_root:
        self._last_sapling_root = root
        self.sapling_cache['anchors'].append(
            (root, height, self.sapling_output_count))
```

**Flush semantics:** `flush(flush_utxos=True)` writes the cached
adds/spends/anchors via `DB.flush_sapling_data()` in the **same write
batch** as the UTXO state, updates `db_sapling_output_count` to the
in-memory count, and only then writes the state row. A crash therefore
can never persist positions ahead of `db_height` (replay would
double-assign them). `assert_flushed()` verifies the Sapling cache is
empty and the counts match.

**Reorg semantics:** `backup_flush()` calls
`backup_sapling_data(self.tx_count, batch.delete, self.height + 1)` in
the same batch as the UTXO backup, and resets `_last_sapling_root` so
anchor tracking restarts cleanly on the new branch (section 9).

### 6.3 Header Handling

PIVX headers are 80 bytes or 112 bytes depending on era.
`Pivx.static_header_len()` returns 112 for the Zerocoin era
(863,787 ≤ height < 2,153,200) and from Sapling activation
(2,700,500) onwards, and 80 otherwise — including the
Zerocoin-to-Sapling gap (heights 2,153,200–2,700,499).

`Pivx.electrum_header()` decides the extra field by **actual header
size**, not height:

- 80-byte headers carry no extra field
- 112-byte expanded headers expose bytes 80:112 as `acc_checkpoint`
  for block versions below 8, and as `final_sapling_root` for versions
  ≥ 8 (`Pivx.SAPLING_BLOCK_VERSION = 8`)

The `final_sapling_root` in indexed headers is the sole source of
consensus anchors for the Sapling index (sections 5.2.4 and 8).

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
server and PIVX Core version metadata, network, Sapling activation height,
`reorg_limit`, `max_block_range`, response guarantees, primary method names,
and aliases.  Supported aliases:

| Client need | Primary method | Aliases |
|-------------|----------------|---------|
| Capability probe | `blockchain.sapling.capabilities` | `blockchain.sapling.get_capabilities`, `server.sapling.capabilities` |
| Block range scan | `blockchain.sapling.get_block_range` | `blockchain.sapling.get_blocks`, `get_block_range`, `sapling.get_block_range` |
| Nullifier status | `blockchain.sapling.get_nullifier_status` | `blockchain.sapling.check_nullifier`, `blockchain.nullifier.get_spend` |
| Batch nullifier status | `blockchain.sapling.check_nullifiers` | - |
| Commitment info | `blockchain.sapling.get_commitment_info` | `blockchain.sapling.get_commitment`, `blockchain.commitment.get_info` |
| Outputs by height | `blockchain.sapling.get_outputs_by_height` | `blockchain.sapling.get_outputs` |
| Best anchor | `blockchain.sapling.get_best_anchor` | `blockchain.sapling.best_anchor` |
| Anchor height | `blockchain.sapling.get_anchor_height` | `blockchain.anchor.get_height` |
| Tree state | `blockchain.sapling.get_tree_state` | `blockchain.sapling.get_treestate` |

`blockchain.sapling.get_witness` and `blockchain.sapling.get_witnesses`
are **not** part of the advertised contract. The handlers remain
registered, but they respond with an RPC error explaining the
client-side witness flow (section 7.1.9).

The capabilities response also advertises the following guarantees:

- `anchor_bound_witnesses: false`, `server_side_witnesses: false` —
  the server never computes Merkle witnesses. A valid Sapling witness
  requires the Pedersen-hash note commitment tree over Jubjub, which
  clients (e.g. pivx-shield) build locally from the ordered commitment
  stream.
- `consensus_anchors: true`, `anchor_tree_size: true` — anchors are
  consensus `finalsaplingroot` values from block headers, each indexed
  with the tree size at which it formed.
- `hex_byte_order: 'display'` — **all** 32-byte hex values in request
  params and responses (nullifiers, commitments/cmu, anchors, tx
  hashes, block hashes) use PIVX Core RPC display byte order (the
  uint256 `GetHex` convention). The server reverses to raw
  little-endian bytes internally for index keys.
- `range_error_types` — the complete structured error list:
  `invalid_range`, `daemon_error`, `method_unavailable`,
  `missing_block`, `missing_transaction`, `index_incomplete`,
  `index_error`, `server_error`.

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
    "block_hashes": [
        {"height": 2700500, "block_hash": "hex..."},
        {"height": 2700501, "block_hash": "hex..."}
    ],
    "blocks": [],
    "error": null
}
```

An empty successful range is represented by `success: true`,
`complete: true`, `empty: true`, and `blocks: []`.  Daemon, index, method, and
partial scan failures are represented by `success: false`, `complete: false`,
and a structured `error` object.  A failed range must never be treated as
complete, even if it includes partial `blocks` scanned before the failure.

Ranges are served strictly from the server's **indexed chain**: block
hashes come from the server's own header index (`fs_block_hashes`), and
`getblock` is called with that exact hash, so a response can never mix
in blocks from a diverging daemon tip. A range whose end exceeds the
indexed tip fails with a structured `index_incomplete` error carrying
`indexed_height`.

### 7.1 Sapling RPC Methods

#### 7.1.1 `blockchain.sapling.get_block_range`

The primary scan method. Returns blocks containing Sapling transactions
in a height range, in the v1 envelope shown above.

**Request:**
```json
{
    "method": "blockchain.sapling.get_block_range",
    "params": [2700500, 2700599]
}
```

`end_height` defaults to `start_height`. The range may span at most 100
heights (`max_block_range`), and must not extend above the indexed tip
(structured `index_incomplete` error with `indexed_height`).

Each entry in `blocks` covers one block that contains at least one
Sapling transaction:

```json
{
    "height": 2700510,
    "block_hash": "hex...",
    "outputs": [
        {
            "position": 12345,
            "txid": "hex...",
            "tx_index": 1,
            "output_index": 0,
            "cmu": "hex...",
            "ephemeral_key": "hex...",
            "enc_ciphertext": "hex...",
            "out_ciphertext": "hex..."
        }
    ],
    "txs": [
        {"hex": "raw tx hex...", "txid": "hex...", "outputs": [ ... ]}
    ]
}
```

- `position` is the global Sapling output position from the index —
  the client appends `cmu` to its local commitment tree at exactly this
  position.
- The block-level `outputs` array is ordered exactly as PIVX Core
  presents transactions in the block and outputs inside each
  transaction; each transaction also carries its own `outputs` array
  for callers that prefer grouped data.
- Per-tx raw `hex` is taken from `getblock` verbosity=2's per-tx `hex`
  field when present, falling back to `getrawtransaction`.
- The envelope-level `block_hashes` list covers **every** scanned
  height, including heights with no Sapling transactions. Cake Wallet
  should persist these hashes and use them for reorg detection
  (section 9.2).

#### 7.1.2 `blockchain.sapling.get_outputs_by_height`

Get Sapling outputs in a height range as a bare list (no envelope).

**Request:**
```json
{
    "method": "blockchain.sapling.get_outputs_by_height",
    "params": {
        "start_height": 2700500,
        "end_height": 2700599,
        "limit": 1000
    }
}
```

`end_height` defaults to `start_height`; `limit` defaults to 1000. The
call raises an RPC error (no partial results) when:

- `end_height < start_height`
- the range spans more than 100 heights
- `end_height` exceeds the indexed tip
- `limit` exceeds 5000 (limits are rejected, never silently capped)

**Response:**
```json
[
    {
        "tx_hash": "hex...",
        "height": 2700500,
        "block_hash": "hex...",
        "position": 12345,
        "output_index": 0,
        "cmu": "hex...",
        "ephemeral_key": "hex...",
        "enc_ciphertext": "hex...",
        "out_ciphertext": "hex..."
    }
]
```

Like `get_block_range`, block hashes come from the server's own index
and `getblock` is called with that exact hash.

#### 7.1.3 `blockchain.sapling.get_nullifier_status`

Check if a single Sapling nullifier has been spent.

**Request:**
```json
{
    "method": "blockchain.sapling.get_nullifier_status",
    "params": ["hex_nullifier_display_order"]
}
```

**Response (spent):**
```json
{
    "spent": true,
    "tx_hash": "hex...",
    "height": 2700550,
    "block_hash": "hex...",
    "spend_index": 0
}
```

**Response (unspent):** `{"spent": false}`

#### 7.1.4 `blockchain.sapling.check_nullifiers`

Batch spend-status check. Accepts a list of up to **1000** display-order
hex nullifiers (or `{"nullifiers": [...]}`); more than 1000 is rejected
with an RPC error. The lookups run in an executor thread to keep the
event loop free.

**Response:**
```json
{
    "success": true,
    "contract": "pivx.sapling.electrumx.v1",
    "results": {
        "hex_nullifier_1": {
            "spent": true,
            "tx_hash": "hex...",
            "height": 2700550,
            "block_hash": "hex...",
            "spend_index": 0
        },
        "hex_nullifier_2": {"spent": false}
    }
}
```

#### 7.1.5 `blockchain.sapling.get_commitment_info`

Look up a note commitment (cmu, display-order hex).

**Response (found):**
```json
{
    "found": true,
    "tx_hash": "hex...",
    "height": 2700500,
    "block_hash": "hex...",
    "position": 12345,
    "output_index": 0
}
```

**Response (not found):** `{"found": false}`

#### 7.1.6 `blockchain.sapling.get_tree_state`

Return Sapling tree state metadata for an indexed height. Served
**entirely from indexed headers and the anchor table — no daemon
calls**. `height` is optional and defaults to the indexed tip.

**Request:**
```json
{
    "method": "blockchain.sapling.get_tree_state",
    "params": [2700500]
}
```

**Response:**
```json
{
    "success": true,
    "contract": "pivx.sapling.electrumx.v1",
    "height": 2700500,
    "block_hash": "hex...",
    "anchor": "hex_display_order",
    "root": "hex_display_order",
    "anchor_first_height": 2700500,
    "tree_size": 12345,
    "indexed_height": 2812345,
    "sapling_activation_height": 2700500
}
```

- `anchor`/`root` (identical) is the consensus `finalsaplingroot` from
  the indexed block header at `height`, in display hex
- `tree_size` is the number of note commitments in the tree when that
  root formed — a client can check that its locally built tree has
  exactly `tree_size` leaves and the same root
- `anchor_first_height` is the first height the root appeared at

**Errors** (returned as `{"success": false, "error": {...}}`):
- `index_incomplete` when the requested height is above the indexed
  tip (includes `indexed_height`)
- `invalid_range` when the height is below Sapling activation
  (includes `sapling_activation_height`)
- `index_error` / `index_incomplete` if the indexed header carries no
  root or the root is not in the anchor table (should not occur on a
  healthy index)

#### 7.1.7 `blockchain.sapling.get_best_anchor`

Get the best Sapling anchor on the **indexed** chain — no daemon call.

**Response:**
```json
{
    "anchor": "hex_display_order",
    "height": 2812345,
    "block_hash": "hex...",
    "tree_size": 67890
}
```

`height` is the indexed tip. Raises an RPC error if the indexed chain
has not reached Sapling activation.

#### 7.1.8 `blockchain.sapling.get_anchor_height`

Given an anchor (display-order hex), returns the first block height it
appeared at, or `null` if the root is not indexed (e.g. it belonged to
a reorged-away branch).

#### 7.1.9 `blockchain.sapling.get_witness` / `get_witnesses`

**Server-side witnesses are not supported.** Both methods return an RPC
error:

```
server-side witnesses are not supported; build the commitment tree
client-side from global output positions and verify it against
get_tree_state anchors
```

Rationale: a consensus-valid Sapling witness requires the Pedersen-hash
tree over Jubjub. An earlier revision of this server maintained a
synthetic double-SHA256 commitment tree and served "witnesses" from it;
those paths could never satisfy consensus and have been removed. The
supported flow is:

1. Client builds the note commitment tree locally from the ordered
   commitment stream (`get_block_range` global positions)
2. Client verifies its tree root and size against consensus anchors
   from `get_tree_state`
3. Client computes witnesses from its own tree

### 7.2 Session Handler Implementation

```python
# server/session.py

class PIVXSaplingElectrumX(ElectrumX):
    '''Session class with Sapling shielded RPC support.'''

    def set_protocol_handlers(self, ptuple):
        super().set_protocol_handlers(ptuple)
        self.electrumx_handlers.update({
            'blockchain.sapling.capabilities': self.sapling_capabilities,
            'blockchain.sapling.get_block_range':
                self.sapling_get_block_range,
            'blockchain.sapling.get_nullifier_status':
                self.sapling_get_nullifier_status,
            'blockchain.sapling.check_nullifiers':
                self.sapling_check_nullifiers,
            'blockchain.sapling.get_commitment_info':
                self.sapling_get_commitment_info,
            'blockchain.sapling.get_outputs_by_height':
                self.sapling_get_outputs_by_height,
            'blockchain.sapling.get_best_anchor':
                self.sapling_get_best_anchor,
            'blockchain.sapling.get_anchor_height':
                self.sapling_get_anchor_height,
            'blockchain.sapling.get_tree_state':
                self.sapling_get_tree_state,
            # Respond with the explanatory client-side-witness error:
            'blockchain.sapling.get_witness': self.sapling_get_witness,
            'blockchain.sapling.get_witnesses': self.sapling_get_witnesses,
            # ... plus the aliases listed in section 7.0
        })
```

All hex parsing goes through `_parse_sapling_hex32()`, which validates
a 64-character display-order hex string and reverses it to the raw
little-endian bytes used as index keys. Index results are converted
back with `hash_to_str()`, so clients only ever see display byte order.

---

## 8. PIVX Core RPC Integration

### 8.1 Required RPC Calls

| RPC Method | Purpose | Usage |
|------------|---------|-------|
| `getblock` (verbosity=2) | Decoded block + per-tx raw hex | `get_block_range`, `get_outputs_by_height`; always called with the block hash from the server's own index |
| `getrawtransaction` | Raw transaction hex | Fallback when `getblock` omits a per-tx `hex` field |
| `getblockcount` | Current height | Sync status (prefetcher) |
| `getnetworkinfo` | Daemon version metadata | `capabilities` response |

The `getbestsaplinganchor` RPC is **no longer used**. Anchors are read
from the server's own indexed block headers (`finalsaplingroot`) and
the `b'A'` table; `get_tree_state` and `get_best_anchor` make no daemon
calls at all.

### 8.2 Daemon Requirements

No PIVX-specific daemon subclass is needed; the standard `Daemon`
class covers everything. The one hard requirement is `getblock`
verbosity=2 with decoded `vShieldSpend`/`vShieldOutput` arrays, i.e.
PIVX Core v5.0+.

Because the block processor already indexes every commitment, position,
nullifier and anchor, the daemon is only consulted at query time for
data the server deliberately does not store: ciphertexts, ephemeral
keys and raw transaction hex.

### 8.3 Consensus Alignment

To ensure we never deviate from PIVX Core consensus:

1. **Proof verification**: We do NOT verify zk-SNARK proofs in Python. PIVX Core has already validated them.

2. **Commitment tree**: The server maintains **no commitment tree at all**. Anchors are the consensus `finalsaplingroot` values PIVX Core commits into v8+ block headers, indexed with the tree size at which each formed. Clients build the real Pedersen-hash tree locally and verify its root against these anchors — so a server bug can never fabricate an anchor that consensus would reject.

3. **Nullifier set**: We maintain the same nullifier set that PIVX Core maintains.

4. **Reorg handling**: On reorg, Sapling index entries for reverted blocks are removed and the output count rewound (section 9).

5. **Indexed-chain serving**: `getblock` is always called with the block hash from the server's own header index, so RPC responses can never mix in blocks from a daemon tip that has diverged from the index.

---

## 9. Reorg Handling

### 9.1 Sapling Reorg Strategy

PIVX ElectrumX keeps `Pivx.REORG_LIMIT = 100`. That means the index retains
enough undo information for at least the last 100 blocks, unless product policy
explicitly changes this constant and the Cake Wallet rescan window is updated
with it.

When ElectrumX backs up a chain segment, `backup_flush()` calls
`backup_sapling_data(tx_count_start, batch.delete, height_start)` in the
same write batch as the UTXO backup. Sapling rollback removes:

- `b'N' + nullifier` spend entries for reverted transactions
- `b'C' + commitment` commitment entries for reverted transactions
- `b'P' + position` global position entries for reverted outputs
- `b'A' + root` consensus anchor entries first seen at reverted heights
  (roots first seen earlier remain valid anchors of the surviving chain)

After deleting reverted outputs, the database rewinds `sapling_output_count` to
the lowest removed global position. New-branch Sapling outputs can then reuse
those reverted positions in canonical order, while outputs before the fork keep
their original positions. `_last_sapling_root` is also reset so anchor
first-seen tracking restarts cleanly when the new branch advances.

### 9.2 Client Rescan Policy

Cake Wallet should persist the block hash for every scanned height, not just
heights containing shielded outputs. `get_block_range` returns those hashes in
the envelope-level `block_hashes` list. On reconnect or app resume, the client
should request at most the server's advertised `max_block_range`:

```
start = max(SAPLING_START_HEIGHT, last_scanned_height - 99)
end = last_scanned_height
```

If any returned hash differs from the locally stored hash for that height, the
client's scanned Sapling state is stale. The client should rewind local notes,
nullifier observations, its commitment tree, and cached anchors to the last
matching height, then rescan forward from the next height.

---

## 10. Performance Considerations

### 10.1 Storage Estimates

The index stores no ciphertexts, so it is small. Approximate key+value
sizes:

| Data Type | Per-Item Size | Estimated Count | Total Size |
|-----------|---------------|-----------------|------------|
| Nullifier entry (`b'N'`) | ~39 bytes | 500K nullifiers | ~20 MB |
| Commitment entry (`b'C'`) | ~47 bytes | 1M outputs | ~47 MB |
| Position entry (`b'P'`) | ~47 bytes | 1M outputs | ~47 MB |
| Anchor entry (`b'A'`) | ~45 bytes | 1 per block with new shielded outputs | a few MB |

**Total estimated additional storage: ~120 MB** for a mature chain.
Ciphertext data (~660 bytes per output) is served from PIVX Core at
query time rather than duplicated into the index.

### 10.2 Query Performance

| Operation | Complexity | Expected Time |
|-----------|------------|---------------|
| Check nullifier spent | O(1) | <1ms |
| Get commitment info / position | O(1) | <1ms |
| `get_tree_state` / `get_best_anchor` | O(1) header read + anchor lookup | <1ms, no daemon call |
| `get_block_range` / `get_outputs_by_height` | O(blocks) daemon `getblock` calls | dominated by daemon latency |

### 10.3 Batch Processing

The block processor accumulates Sapling adds/spends/anchors in
`sapling_cache` and writes them in the same batch as the UTXO state —
either on the per-block flush once caught up, or when
`check_cache_size()` triggers a UTXO flush during initial sync. No
separate Sapling flush threshold is needed; the cache is small (a few
dozen bytes per shielded output) relative to the UTXO cache it rides
along with.

### 10.4 Concurrency

`check_nullifiers` validates all nullifiers up front and then runs its
up-to-1000 DB and file-system lookups in an executor thread
(`controller.run_in_executor`), keeping the event loop responsive. No
server-side result caching is currently implemented; single lookups are
already O(1) LevelDB gets.

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
   - Extend the UTXO DB with Sapling key prefixes
   - Implement key/value encoding/decoding
   - Add indices

### Phase 2: Indexing (Week 2-3)

4. **Block Processor Updates**
   - Integrate Sapling processing into `advance_txs`
   - Anchor recording from headers (`advance_sapling_anchor`)
   - Position tracking, atomic flush with UTXO state

5. **Reorg Handling**
   - Implement `backup_sapling_data`
   - Output count rewind
   - Integration with existing reorg flow

6. **State Management**
   - Sapling state fields in the state row
   - Index version stamping and enforcement
   - Recovery from interrupted sync

### Phase 3: API & Integration (Week 3-4)

7. **Session Handlers**
   - Implement `PIVXSaplingElectrumX` session class
   - Add RPC method handlers

8. **Controller Updates**
   - Add Sapling query methods
   - Integrate with session handlers

9. **PIVX Core RPC**
   - `getblock` verbosity=2 integration (no PIVX-specific daemon
     subclass needed)
   - Anchors from indexed headers, not daemon RPC

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

Source checked against PIVX Core release tag `v5.6.1`, release commit
`af60f19` (`src/chainparams.cpp`):
https://github.com/PIVX-Project/PIVX/blob/v5.6.1/src/chainparams.cpp

PIVX ElectrumX keeps the default PIVX `REORG_LIMIT` at 100 blocks. Cake Wallet
clients should rescan the last 100 inclusive heights, with envelope-level
`block_hashes` in scan responses used to detect stale local branch state.

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

1. **Probe capabilities** with `blockchain.sapling.capabilities` and
   check `contract`, `max_block_range` and `hex_byte_order`
2. **Fetch blocks** in batches of at most 100 heights:
   ```
   GET blockchain.sapling.get_block_range(last_synced + 1, end)
   ```
3. **Append every cmu** (decrypted or not) to the local Pedersen-hash
   commitment tree at its global `position` — the tree needs all
   commitments, not just the wallet's own
4. **Trial decrypt** each output's `enc_ciphertext` with the viewing key
   and store discovered notes locally
5. **Verify the local tree** against consensus:
   ```
   GET blockchain.sapling.get_tree_state(height)
   ```
   The local tree at `tree_size` leaves must have root == `anchor`
6. **Persist `block_hashes`** for reorg detection (section 9.2)
7. **Check nullifiers** for previously discovered notes:
   ```
   GET blockchain.sapling.check_nullifiers([nf1, nf2, ...])
   ```
8. **Update wallet balance**

### Spending a Note

1. **Select note(s)** to spend
2. **Get tree state** at a recent indexed height:
   ```
   GET blockchain.sapling.get_tree_state(height)
   ```
   and confirm the local tree root at `tree_size` commitments equals
   the returned `anchor`
3. **Compute the witness locally** from the client-side commitment tree
   (the server does not serve witnesses — section 7.1.9)
4. **Build the Sapling spend** using that consensus anchor
5. **Sign and broadcast** the transaction

### Balance Calculation

```
balance = Σ(decrypted note values) - Σ(spent note values)
```

Where spent notes are those whose nullifiers appear in the chain.

---

## Appendix D: Implementation Status

**Last Updated:** July 2026

### Completed Components

#### 1. Transaction Deserializer (`lib/tx.py`)
- ✅ `SaplingSpend` namedtuple (384 bytes: cv, anchor, nullifier, rk, zkproof, spend_auth_sig)
- ✅ `SaplingOutput` namedtuple (948 bytes: cv, cmu, ephemeral_key, enc_ciphertext, out_ciphertext, zkproof)
- ✅ `TxPIVXSapling` namedtuple (includes value_balance, sapling_spends, sapling_outputs, binding_sig, extra_payload)
- ✅ `DeserializerPIVXSapling` with correct PIVX Core `Optional<SaplingTxData>` and `Optional<vector<uint8>> extraPayload` handling (no phantom "nExpiryHeight varint")
- ✅ PIVX v6.0+ special transactions (`nType != 0`, e.g. DMN/LLMQ) parse correctly

#### 2. Coin Configuration (`lib/coins.py`)
- ✅ `SAPLING_START_HEIGHT = 2700500` (mainnet), `201` (testnet)
- ✅ `SAPLING_BLOCK_VERSION = 8`, `EXPANDED_HEADER = 112`, `ZEROCOIN_END_HEIGHT`
- ✅ `static_header_len()` handles the 80-byte Zerocoin-to-Sapling gap
- ✅ `electrum_header()` picks extra fields by actual header size: `acc_checkpoint` (version < 8) or `final_sapling_root` (version >= 8)
- ✅ `DESERIALIZER = DeserializerPIVXSapling`, `SESSIONCLS = PIVXSaplingElectrumX`

#### 3. Database Schema (`server/db.py`)
- ✅ Nullifier table: `b'N' + nullifier → tx_num + spend_index`
- ✅ Commitment table: `b'C' + commitment → tx_num + output_index + position`
- ✅ Position table: `b'P' + position → tx_num + output_index + commitment`
- ✅ Consensus anchor table: `b'A' + root → height + tree_size` (finalsaplingroot from headers, first-seen-only)
- ✅ `SAPLING_INDEX_VERSION = 1` stamped into the state row; a DB synced past Sapling activation without the current version refuses to open and demands a resync
- ✅ Methods: `get_nullifier_spend()`, `is_nullifier_spent()`, `get_commitment_info()`, `get_commitment_position_info()`
- ✅ Methods: `get_sapling_anchor_info()`, `get_anchor_height()`, `get_sapling_root()`
- ✅ `flush_sapling_data()` and `backup_sapling_data()` for persistence/reorg

#### 4. Block Processor (`server/block_processor.py`)
- ✅ Extended `advance_txs()` to index nullifiers, commitments and global output positions in canonical block/tx/vShieldOutput order
- ✅ `advance_sapling_anchor()` records the header's finalsaplingroot first-seen with the tree size
- ✅ `flush()` writes Sapling data atomically with the UTXO state (crash-consistent positions)
- ✅ `backup_flush()` removes Sapling data and rewinds the output count on reorg
- ✅ `assert_flushed()` verifies the Sapling cache is empty and counts match

#### 5. API Endpoints (`server/session.py`)
- ✅ `PIVXSaplingElectrumX` session class
- ✅ `capabilities`, `get_block_range`, `get_nullifier_status`, `check_nullifiers`, `get_commitment_info`, `get_outputs_by_height`, `get_best_anchor`, `get_anchor_height`, `get_tree_state` (plus aliases)
- ✅ All 32-byte hex values in display byte order; indexed-chain-only serving; structured range errors
- ✅ `get_witness`/`get_witnesses` respond with an error directing clients to the client-side tree + consensus-anchor flow

#### 6. Tests
- ✅ `tests/lib/test_pivx_sapling.py` — spend/output/tx structures, deserializer (including special txs and `electrum_header`), protocol sizes
- ✅ `tests/server/test_pivx_sapling_reorg.py` — reorg rollback of outputs/spends/anchors, position stability across restarts, index version enforcement, range/limit rejection, canonical output order

### Future Enhancements

#### Short-term
- [ ] Implement viewing key registration for push notifications
- [ ] Add WebSocket subscriptions for Sapling events

#### Medium-term
- [ ] Implement compact block filters for efficient syncing

#### Long-term
- [ ] Optional server-side Pedersen-hash commitment tree (requires a Jubjub/Pedersen implementation) if serving witnesses ever becomes worthwhile
- [ ] Shield set analytics (anonymity set size, etc.)
- [ ] Support for additional Sapling-related BIPs

### Notes for Developers

1. **Python Version**: The base codebase uses `collections.Container` which was moved to `collections.abc` in Python 3.10+. You may need to patch `lib/util.py` for newer Python versions.

2. **Testing**: Run syntax validation with `python -m py_compile <file>` since the full test suite requires environment setup.

3. **Database Migration**: `DB.SAPLING_INDEX_VERSION = 1` is enforced at open. Any database synced past Sapling activation with an earlier build of this branch (including builds that used the removed synthetic tree / `b'R'` indexed-root table) **must resync from genesis** — the server refuses to open it otherwise.

4. **PIVX Core Requirements**: The server requires PIVX Core v5.0+ with Sapling support and `getblock` verbosity=2. Per-tx raw hex from `getblock` is used when present, with `getrawtransaction` as a fallback. The `getbestsaplinganchor` RPC is no longer used; anchors come from the server's own indexed block headers.
