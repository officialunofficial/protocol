---
mip: 2
title: Tier 2 Light Client Infrastructure
description: Specifies the protocol changes needed to support Tier 2 light client proofs, validator commitments, and finalized historical root verification.
author: christopherwxyz <christopher@unofficial.run>
discussions-to: https://github.com/officialunofficial/protocol/discussions
status: Draft
type: Standards Track
created: 2026-04-02
requires:
  - 1
---

## Abstract

This MIP specifies the Tier 2 light client changes needed to make Makechain state proofs and finalized headers usable for trust-minimized clients.

It has four parts:

1. Restore the public proof allowlist for eight proof key prefixes that are already merkleized in state.
2. Commit validator-set material into block headers via `validators_hash`.
3. Add finalized-chain freshness anchors to mutable proofs.
4. Persist and expose finalized root history so proofs can be verified against finalized historical blocks instead of only the current root.

The proposal is additive where possible. The main intentional breaking change is the block-header schema change required for `validators_hash`.

## Motivation

Makechain already has most of the underlying machinery needed for light clients:

- public state is stored in a merkleized QMDB
- committed blocks are persisted and queryable
- validator epoch material already exists in resolved runtime configuration
- Commonware supports historical MMR proofs and cross-epoch certificate verification

What is missing is protocol-level commitment and lookup plumbing:

- the proof API currently exposes too few public key families
- block headers do not commit validator material
- mutable proofs do not carry explicit freshness anchors
- proof verification rejects all non-current roots, even if they belong to finalized historical blocks

Tier 2 light-client support requires these gaps to be closed in the protocol itself.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### 1. Public Proof Prefix Expansion

#### 1.1 Required public proof prefixes

The public proof allowlist for operation and exclusion proofs MUST include the following raw state-key prefixes:

- `project`
- `ref`
- `account`
- `key`
- `verification`
- `link`
- `reaction`
- `tombstone`

These are in addition to the currently supported public proof prefixes:

- `collaborator`
- `project-name`
- `relay-signer-event`
- `storage-grant`
- `storage-rent-event`

#### 1.2 Covered RPCs

This allowlist applies to:

- `GetOperationProof`
- `GetExclusionProof`
- `VerifyOperationProof`

#### 1.3 Exclusions

The following remain outside the public proof surface:

- `commit`
- `counter`
- `prune-marker`
- non-public metadata helper keys

Rationale:

- `commit` entries are prunable and are not stable public proof targets
- helper and aggregate keys are implementation surfaces, not protocol-facing proof objects

### 2. Validator Commitments in Block Headers

#### 2.1 Header extension

`BlockHeader` MUST gain a `validators_hash` field:

```proto
message BlockHeader {
  Height height = 1;
  uint64 timestamp = 2;
  uint32 version = 3;
  Network chain_id = 4;
  bytes parent_hash = 5;
  bytes state_root = 6;
  RelayCheckpoint relay_checkpoint = 7;
  bytes validators_hash = 8;
}
```

`validators_hash` MUST be exactly 32 bytes and MUST be the BLAKE3 digest of the canonical validator commitment object active for the block.

#### 2.2 Validator commitment payload

The canonical payload SHOULD be:

```proto
message ValidatorSetCommitment {
  uint64 epoch = 1;
  uint64 start_block = 2;
  repeated bytes validators = 3;         // sorted Ed25519 public keys, 32 bytes each
  bytes bls_group_public_key = 4;        // canonical compressed bytes
  bytes bls_public_polynomial = 5;       // canonical Commonware codec bytes
}
```

Hash rule:

```text
validators_hash = BLAKE3(canonical_encode(ValidatorSetCommitment))
```

#### 2.3 Canonicalization rules

- `validators` MUST be sorted lexicographically by raw Ed25519 public key bytes before encoding.
- `epoch` and `start_block` MUST match the resolved epoch artifact active for `block.header.height.block_number`.
- `bls_group_public_key` MUST use the same canonical byte encoding used by the runtime certificate verifier.
- `bls_public_polynomial` MUST use the canonical Commonware codec bytes for the public polynomial.

#### 2.4 Semantics

- every block in the same epoch MUST carry the same `validators_hash`
- the first block in a new epoch MUST switch to the new epoch's `validators_hash`
- a block is malformed if its `validators_hash` does not match the resolved validator commitment for its height

#### 2.5 Commitment lookup RPC

The full validator commitment SHOULD be retrievable by RPC:

```proto
message GetValidatorSetCommitmentRequest {
  oneof selector {
    uint64 block_number = 1;
    bytes validators_hash = 2;
  }
}

message GetValidatorSetCommitmentResponse {
  bytes validators_hash = 1;
  ValidatorSetCommitment commitment = 2;
}
```

This keeps the block header compact while still letting light clients fetch the committed validator material.

### 3. Freshness Anchors for Mutable Proofs

#### 3.1 Problem

Proof validity and proof freshness are different questions.

A collaborator, ref, account, key, verification, link, reaction, tombstone, or project proof may be mathematically valid for an older finalized root while still being too stale for the consuming application.

Tier 2 requires proofs to carry enough finalized-chain context for verifiers to make freshness decisions explicitly.

#### 3.2 Required anchor fields

Operation and exclusion proof payloads MUST include finalized-chain anchor metadata:

- `proof_block_number`
- `proof_block_hash`
- `proof_timestamp`

The anchor block MUST be finalized, and its `state_root` MUST equal the proof root.

The proof root remains the cryptographic verification root. The new fields make the root addressable by block height and timestamp.

#### 3.3 Proof envelope versioning

The current proof envelope version is `1`. This MIP requires proof envelope version `2` for both operation and exclusion proofs.

Version `2` MUST include:

- the proof root
- the proof body
- the finalized anchor metadata above

Servers MAY continue to decode version `1` proofs for backward compatibility, but version `1` proofs do not satisfy Tier 2 freshness requirements for mutable proof use cases.

#### 3.4 Freshness-sensitive proof families

The following proof families SHOULD be treated as freshness-sensitive:

- `project`
- `ref`
- `account`
- `key`
- `verification`
- `link`
- `reaction`
- `tombstone`
- `collaborator`

These proofs MAY verify against historical finalized roots, but consumers MUST be able to apply policies such as:

- maximum age in blocks
- maximum age in seconds
- minimum finalized block number

#### 3.5 Historical verification API

The protocol SHOULD expose verification against a selected finalized block, either by extending `VerifyOperationProof` or by adding a new RPC.

The preferred additive shape is:

```proto
message VerifyOperationProofAtBlockRequest {
  bytes proof = 1;
  bytes key = 2;
  uint64 block_number = 3;
  uint64 max_staleness_blocks = 4;   // 0 = no extra freshness bound
  uint64 min_block_number = 5;       // 0 = no lower bound
}

message VerifyOperationProofAtBlockResponse {
  bool valid = 1;
  string error = 2;
  bytes root = 3;
  uint64 block_number = 4;
  bytes block_hash = 5;
  uint64 timestamp = 6;
}
```

If a new RPC is not added, the existing verification API MUST gain a selector for a specific finalized block or finalized root.

### 4. Finalized Root History

#### 4.1 Requirement

Makechain MUST persist finalized root history in QMDB so a verifier can resolve finalized historical roots without depending on transient in-memory retention.

#### 4.2 Storage layout

This MIP reserves a new queryable, non-merkleized key family:

- `FINALIZED_ROOT` at prefix `0x1B`

Recommended layout:

```text
[0x1B | block_number:8 BE] -> FinalizedRootRecord
```

Suggested value shape:

```proto
message FinalizedRootRecord {
  uint64 block_number = 1;
  bytes block_hash = 2;       // 32 bytes
  bytes state_root = 3;       // 32 bytes
  uint64 timestamp = 4;
  bytes validators_hash = 5;  // 32 bytes
}
```

This record is intentionally compact. Full committed block entries may continue to exist separately.

#### 4.3 Population rules

- a `FinalizedRootRecord` MUST be written when a block becomes finalized and durable
- the record MUST match the finalized block header exactly
- the finalized-root index MUST be append-only by block number

#### 4.4 Root lookup RPC

The protocol SHOULD expose finalized root lookup directly:

```proto
message GetFinalizedRootRequest {
  oneof selector {
    uint64 block_number = 1;
    bytes state_root = 2;
    bytes block_hash = 3;
  }
}

message GetFinalizedRootResponse {
  FinalizedRootRecord record = 1;
}
```

This RPC is the canonical bridge between:

- proofs that carry a root
- headers that commit a root
- freshness policies that depend on block numbers and timestamps

#### 4.5 Historical verification semantics

Once finalized root history exists, proof verification semantics become:

- a proof is structurally valid if its bytes decode
- a proof is cryptographically valid if it verifies against the selected root
- a proof is chain-valid if that root belongs to a finalized block on the canonical chain
- a proof is fresh enough only if it also satisfies the verifier's freshness policy

#### 4.6 Explicit non-goal

This MIP does not require the node to synthesize new historical key-value proofs for arbitrary historical blocks from the latest QMDB snapshot.

Tier 2 requires:

- preserving proofs generated when they were current
- resolving the correct finalized historical root later
- verifying the proof against that finalized historical root

It does not require arbitrary regeneration of historical current-state proofs.

## Rationale

### Why expand the proof allowlist?

The missing proof key families are already part of public protocol state and are already merkleized. The current restriction is therefore an API and policy regression, not a storage or proof-engine limitation.

### Why commit validator material by hash instead of inline?

Putting the full validator set and threshold public material directly into every block header would increase header size and duplicate data across every block in an epoch. A compact hash preserves the header as the commitment surface while keeping full material fetchable by RPC.

### Why anchor proofs to finalized blocks?

The state root alone is not enough for freshness policies. Light-client consumers need a stable mapping from root to finalized block number, block hash, and timestamp.

### Why persist finalized root records separately if committed blocks already exist?

Committed blocks are larger and may be retained primarily for richer historical queries. A compact finalized-root index gives light clients a stable, cheap lookup path for verification and freshness checks.

## Backwards Compatibility

- public proof prefix expansion is additive
- finalized root history and lookup RPCs are additive
- proof envelope version `2` is additive if servers continue to decode version `1`
- `validators_hash` is not backwards compatible at the block-wire level and requires a coordinated protocol-version bump

## Reference Implementation

No complete reference implementation exists yet. The intended implementation targets are:

- Makechain state key allowlist logic
- proof serialization and verification RPCs
- finalized root indexing in QMDB
- block header construction and validation

## Security Considerations

- Expanding the proof surface increases the number of public keys that can be proven, so the allowlist MUST remain limited to intentionally public, stable state families.
- `validators_hash` MUST be computed from a canonical encoding to avoid commitment ambiguity across implementations.
- Proof freshness checks MUST distinguish "proof is valid" from "proof is acceptable for this application." A valid historical proof is not automatically fresh enough for mutable state decisions.
- Finalized root lookup MUST return only canonical finalized-chain roots. Non-finalized roots must not satisfy historical verification APIs that claim finalized semantics.

## Acceptance Criteria

Tier 2 is considered specified when all of the following are true:

- all required public proof key prefixes are accepted by the public proof APIs
- finalized block headers commit validator material via `validators_hash`
- mutable proofs carry explicit finalized-chain anchor metadata
- finalized root history is durable and queryable
- proof verification can target a specified finalized historical block instead of only the current root

## Copyright

Copyright and related rights waived via CC0.
