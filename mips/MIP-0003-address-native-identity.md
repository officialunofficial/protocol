---
mip: 3
title: Address-Native Identity and Removal of MID
description: Replaces MID with owner_address as the sole canonical account identifier, removing onchain registration and relay-injected identity messages.
author: marthendalnunes
discussions-to: https://github.com/officialunofficial/protocol/discussions/18
status: Draft
type: Standards Track
created: 2026-04-03
requires: null
---

## Abstract

This MIP specifies an address-native Makechain variant that removes MID entirely from the protocol and uses `owner_address` as the sole canonical account identifier.

It has five parts:

1. Replace MID-based acting identity with `owner_address` in messages, state, and public APIs.
2. Add `STORAGE_CLAIM` as the explicit settlement-backed storage ingress path.
3. Keep `SIGNER_ADD` and `SIGNER_REMOVE` as the native custody-authorized delegated-key management flow.
4. Disable the current relay-driven identity, ownership-transfer, and signer-management message families.
5. Remove block-level Tempo checkpoint coupling so Tempo is consulted only for `STORAGE_CLAIM` verification.

This proposal is intentionally clean-slate. It defines a dedicated address-native reset variant, not an in-place continuation of the current MID-based network.

## Motivation

The current reset direction removes Tempo from identity allocation and transfer, but still preserves MID as a distinct protocol identity. That leaves an unnecessary second namespace in the system.

MID is costly in several ways:

- users already have a canonical wallet identity in `owner_address`
- MID allocation adds ceremony without clear value once transfer and recovery are removed
- MID permeates message bodies, APIs, proofs, state keys, and social/account surfaces
- relay-driven identity flows and block-level Tempo checkpointing enlarge the protocol surface and replay model
- Makechain should not distinguish between wallet identity and protocol identity without a strong protocol reason

An address-native model is simpler:

- the account is the wallet address
- delegated Ed25519 keys remain the fast offchain signing path
- storage remains the economic gate for quota-bearing writes
- Tempo remains only a settlement source for storage purchases
- post-reset replay verification becomes localized to `STORAGE_CLAIM` instead of every block

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### 1. Activation and Scope

This MIP defines a dedicated address-native protocol variant.

Activation model:

- the RECOMMENDED activation is a clean-slate reset network or dedicated hardfork variant such as `V2AddressNative`
- this MIP is an alternative reset path, not an additive tweak to the MID-preserving reset proposal
- post-reset networks MUST reject MID-based identity semantics for new messages and blocks
- this MIP does not require migration of historical MID allocations, relay checkpoints, or relay-derived identity state
- the first post-reset block MAY be a genesis block with zero user messages
- the initial post-reset state SHOULD contain only protocol metadata needed for chain operation

### 2. Identity Model

Post-reset Makechain becomes address-native.

Required semantics:

- `owner_address` MUST be the sole canonical account identifier
- any valid wallet address MUST be a valid Makechain principal by default
- there is no account-allocation transaction
- there is no native account transfer flow
- there is no recovery flow
- persisted account rows MAY be materialized lazily as needed
- storage is an economic capability, not the identity itself
- storage expiry MUST NOT delete the account identity or historical state

Address-native principal validity applies even before state materialization. Any valid `owner_address` MAY be referenced by address-native account, collaborator, verification, and social-graph operations even if no bookkeeping row or delegated key has yet been materialized for that address. Missing bookkeeping state implies default-zero account state, not an invalid principal.

### 3. Message Model

#### 3.1 `MessageData`

`MessageData.mid` MUST be removed from the post-reset message model and replaced with `owner_address`.

Recommended protobuf shape:

```proto
message MessageData {
  MessageType type = 1;
  reserved 2;              // was mid
  uint32 timestamp = 3;
  Network network = 4;
  bytes owner_address = 5; // 20 bytes

  oneof body {
    ...
    StorageClaimBody storage_claim = 98;
  }
}
```

Required semantics:

- `owner_address` is the acting account for user messages
- the envelope still carries `signer`, `signature`, `hash`, and `data_bytes`
- ordinary user messages MUST be signed by a delegated Ed25519 key registered to `owner_address`
- `STORAGE_CLAIM` is the only bootstrap-style user message and bypasses delegated-key lookup
- `SIGNER_ADD` and `SIGNER_REMOVE` remain envelope-bearing messages, but authority derives from custody signatures verified against `owner_address`

#### 3.2 Concrete wire migration

Wire migrations MUST prefer fresh field numbers over in-place type mutation.

Migration rules:

- implementations MUST NOT change an existing `uint64 mid` field into `bytes owner_address` at the same field number
- old MID-typed field numbers SHOULD be reserved
- new address-native fields SHOULD use fresh field numbers
- relay-driven legacy message types MAY remain decodeable during implementation transition, but they MUST be invalid under address-native version rules
- block-level Tempo checkpoint semantics MUST be removed for the address-native variant

Recommended wire diff in `proto/makechain.proto`:

```proto
message MessageData {
  MessageType type = 1;
  reserved 2;              // was mid
  uint32 timestamp = 3;
  Network network = 4;
  bytes owner_address = 5; // 20 bytes
  oneof body {
    ...
    StorageClaimBody storage_claim = 98;
  }
}

enum MessageType {
  ...
  MESSAGE_TYPE_STORAGE_RENT = 71;   // invalid on address-native networks
  MESSAGE_TYPE_STORAGE_CLAIM = 72;
}
```

Required notes:

- `StorageClaimBody` MUST use a fresh oneof tag instead of overloading `storage_rent = 81`
- `MESSAGE_TYPE_STORAGE_RENT = 71` MAY remain defined for transition safety, but it MUST be rejected on address-native networks
- `KEY_ADD`, `OWNERSHIP_TRANSFER`, `RELAY_SIGNER_ADD`, and `RELAY_SIGNER_REMOVE` MAY remain reserved or decode-only, but they MUST be rejected by post-reset version rules

#### 3.3 Body-level identity rewrites

All protocol-visible MID references MUST become address-based.

This includes at minimum:

- `owner_mid` to `owner_address`
- `author_mid` to `author_address`
- `target_mid` to `target_owner_address`
- `source_mid` to `source_owner_address`
- `request_mid` to `request_owner_address`
- account- and storage-proof RPC selectors moving from MID to `owner_address`

Project ownership semantics MUST also become address-native. Canonical project state MUST store and expose project ownership by `owner_address`, replacing MID-based owner identity in both state and public responses.

Recommended field migrations:

| Message | Old field | Required action | New field |
|--------|-----------|-----------------|-----------|
| `CommitMeta` | `uint64 author_mid = 4` | reserve field 4 | `bytes author_address = 8` |
| `CollaboratorAddBody` | `uint64 target_mid = 2` | reserve field 2 | `bytes target_owner_address = 4` |
| `CollaboratorRemoveBody` | `uint64 target_mid = 2` | reserve field 2 | `bytes target_owner_address = 3` |
| `LinkAddBody` | `uint64 target_mid = 2` | reserve field 2 in `oneof target` | `bytes target_owner_address = 4` |
| `LinkRemoveBody` | `uint64 target_mid = 2` | reserve field 2 in `oneof target` | `bytes target_owner_address = 4` |
| `SignerAddBody` | `uint64 request_mid = 8` | reserve field 8 | `bytes request_owner_address = 13` |

Recommended `SignerAddBody` shape:

```proto
message SignerAddBody {
  bytes key = 1;
  uint32 scope = 2;
  bytes custody_signature = 3;
  reserved 4;
  repeated bytes allowed_projects = 5;
  uint32 custody_key_type = 6;
  uint64 nonce = 7;
  reserved 8;                        // was request_mid
  bytes request_signature = 9;
  uint32 request_key_type = 10;
  uint64 valid_after = 11;
  uint64 valid_before = 12;
  bytes request_owner_address = 13;  // 20 bytes
}
```

`SignerRemoveBody` does not need a new address field because the acting account is already carried by `MessageData.owner_address`.

#### 3.4 Project, account, and key RPC migration

Recommended request/response migrations:

| Message | Old field | Required action | New field |
|--------|-----------|-----------------|-----------|
| `GetProjectResponse` | `uint64 owner_mid = 6` | reserve field 6 | `bytes owner_address = 15` |
| `GetProjectByNameRequest` | `uint64 owner_mid = 1` | reserve field 1 | `bytes owner_address = 4` |
| `SearchProjectsRequest` | `uint64 owner_mid = 2` | reserve field 2 | `bytes owner_address = 6` |
| `ListProjectsRequest` | `uint64 owner_mid = 1` | reserve field 1 | `bytes owner_address = 5` |
| `CollaboratorEntry` | `uint64 mid = 1` | reserve field 1 | `bytes owner_address = 3` |
| `GetAccountRequest` | `uint64 mid = 1` | reserve field 1 | `bytes owner_address = 2` |
| `GetAccountResponse` | `uint64 mid = 1` | reserve field 1 | reuse existing `bytes owner_address = 10` as canonical |
| `KeyEntry` | `uint64 request_mid = 4` | reserve field 4 | `bytes request_owner_address = 5` |
| `GetKeyRequest` | `uint64 mid = 1` | reserve field 1 | `bytes owner_address = 3` |
| `GetKeyResponse` | `uint64 request_mid = 5` | reserve field 5 | `bytes request_owner_address = 6` |
| `ListKeysRequest` | `uint64 mid = 1` | reserve field 1 | `bytes owner_address = 4` |
| `GetAccountActivityRequest` | `uint64 mid = 1` | reserve field 1 | `bytes owner_address = 4` |
| `ListVerificationsRequest` | `uint64 mid = 1` | reserve field 1 | `bytes owner_address = 4` |

Required notes:

- `GetAccountResponse` already has `owner_address = 10`; the address-native reset MUST make that field canonical rather than introducing a second address field
- MID-only filters MUST NOT be overloaded; they MUST be removed or replaced with explicit address fields

#### 3.5 Social, history, and proof RPC migration

Recommended request/response migrations:

| Message | Old field | Required action | New field |
|--------|-----------|-----------------|-----------|
| `ListLinksRequest` | `uint64 mid = 1` | reserve field 1 | `bytes owner_address = 5` |
| `LinkEntry` | `uint64 target_mid = 2` | reserve field 2 | `bytes target_owner_address = 5` |
| `ListLinksByTargetRequest` | `uint64 target_mid = 2` | reserve field 2 | `bytes target_owner_address = 6` |
| `ListReactionsRequest` | `uint64 mid = 1` | reserve field 1 | `bytes owner_address = 6` |
| `ReactionEntry` | `uint64 source_mid = 4` | reserve field 4 | `bytes source_owner_address = 6` |
| `RefLogEntry` | `uint64 mid = 3` | reserve field 3 | `bytes owner_address = 8` |
| `GetStorageQuotaProofRequest` | `uint64 mid = 1` | reserve field 1 | `bytes owner_address = 3` |
| `GetStorageQuotaProofResponse` | `uint64 mid = 1` | reserve field 1 | `bytes owner_address = 13` |

Recommended note:

- `LinkEntry` is already semantically overloaded in reverse-link queries. Implementations SHOULD add `bytes source_owner_address = 6` to `LinkEntry` rather than overloading `target_owner_address` in reverse lookups.

#### 3.6 Deprecated caller identity fields

Deprecated and already ignored `caller_mid` fields do not need `caller_owner_address` replacements.

This includes at minimum:

- `GetProjectRequest.caller_mid`
- `GetProjectByNameRequest.caller_mid`
- `SearchProjectsRequest.caller_mid`
- `GetProjectActivityRequest.caller_mid`
- `GetRefRequest.caller_mid`
- `ListRefsRequest.caller_mid`
- `GetCommitRequest.caller_mid`
- `ListCommitsRequest.caller_mid`
- `ListCollaboratorsRequest.caller_mid`
- `GetRefLogRequest.caller_mid`
- `GetCommitAncestorsRequest.caller_mid`

### 4. Live and Disabled Message Families

#### 4.1 Live identity and storage messages

The post-reset identity and storage message set MUST include:

- `STORAGE_CLAIM`
- existing `SIGNER_ADD`
- existing `SIGNER_REMOVE`

All other user message families remain conceptually available, but they MUST use address-native identity fields.

#### 4.2 Disabled current relay-driven message types

The following current protocol message types MUST be rejected on address-native networks:

- `KEY_ADD`
- `OWNERSHIP_TRANSFER`
- `STORAGE_RENT`
- `RELAY_SIGNER_ADD`
- `RELAY_SIGNER_REMOVE`

Historical enum values MAY remain decodeable during implementation transition, but they MUST be invalid under post-reset version rules.

### 5. `STORAGE_CLAIM`

#### 5.1 Purpose

`STORAGE_CLAIM` proves that a storage-rent purchase settled on Tempo for a specific `owner_address` and should be reflected in Makechain state.

Recommended body shape:

```proto
message StorageClaimBody {
  uint32 units = 1;
  bytes settlement_tx_hash = 2;    // 32 bytes
  uint64 settlement_chain_id = 3;  // EIP-155 chain id
  uint32 settlement_log_index = 4; // receipt-local log position
  bytes actor = 5;                 // 20 bytes
}
```

#### 5.2 Structural validation and authorization

`STORAGE_CLAIM` MUST satisfy all of the following:

- `MessageData.owner_address` is 20 bytes
- the envelope signature is valid
- delegated-key lookup does not apply
- `units > 0`
- `settlement_tx_hash` is 32 bytes
- `settlement_chain_id` equals `host_chain_id(network)`
- `actor` is 20 bytes

#### 5.3 State validation and settlement verification

`STORAGE_CLAIM` state validation MUST satisfy all of the following:

- the storage-claim marker does not already exist
- a finalized settlement event exists at `(settlement_tx_hash, settlement_log_index)`
- the decoded event owner equals `MessageData.owner_address`
- the decoded event units equal `body.units`
- the decoded event actor equals `body.actor` when carried on wire
- the referenced Tempo block is finalized under the network confirmation policy

The first implementation SHOULD use receipt/log RPC verification.

For `STORAGE_CLAIM`, validators SHOULD:

1. fetch the transaction receipt by `settlement_tx_hash`
2. require successful execution
3. require the configured settlement chain
4. require a log at `settlement_log_index`
5. require the log address to equal the configured owner-address settlement contract
6. decode `Rent(actor, owner, units)`
7. require the decoded event to match `owner_address`, `actor`, and `units`
8. require the settlement block to be finalized under the network confirmation policy
9. derive grant expiry as `tempo_block_timestamp + STORAGE_TOTAL_PERIOD`

This MIP does not require receipt proofs or proof-carrying logs in the first version.

#### 5.4 Settlement contract shape

This MIP assumes an owner-address settlement contract instead of MID-keyed storage rent.

Recommended event:

```solidity
event Rent(address indexed actor, address indexed owner, uint256 units);
```

Expected contract responsibilities:

- accept payment or operator credit
- emit `Rent`
- not depend on `MakeRegistry`
- not allocate identities
- not manage Makechain ownership
- not manage Makechain signer state

#### 5.5 Claim identity and expiry

A `STORAGE_CLAIM` MUST be consumed exactly once via a native claim marker.

Recommended deterministic claim identifier:

```text
storage_claim_id =
  H("makechain:storage-claim:v1" ||
    LE(settlement_chain_id, 8) ||
    settlement_tx_hash ||
    LE(settlement_log_index, 4))
```

The storage-claim marker SHOULD live at prefix `0x17` with key layout `[0x17 | claim_id:32]`.

`settlement_log_index` is the zero-based log position within the referenced transaction receipt. It is not Ethereum's block-global `logIndex`.

Grant expiry MUST be derived from the verified Tempo settlement block timestamp plus the protocol storage period, not from Makechain inclusion time.

#### 5.6 Execution

Recommended execution:

```text
apply_storage_claim(sigma, M):
  require storage_claim_marker(claim_id) = bottom
  require settlement proof valid and finalized

  let acct = sigma[account(owner_address)] default_zero
  let active_units = sweep_expired_storage_grants(owner_address, block_timestamp)
  let expires_at = tempo_block_timestamp + STORAGE_TOTAL_PERIOD

  sigma[storage_grant(owner_address, expires_at, claim_id)] <- StorageGrantState { ... }
  sigma[storage_claim_marker(claim_id)] <- 1
  sigma[account(owner_address)] <- acct with {
    storage_units = active_units + body.units,
    created_at = acct.created_at or M.timestamp,
  }
```

### 6. `SIGNER_ADD` and `SIGNER_REMOVE`

#### 6.1 `SIGNER_ADD`

`SIGNER_ADD` remains the native delegated-key registration flow.

Revised semantics:

- it is custody-authorized by `owner_address`
- it does not require an existing delegated key for authorization
- it does not require a pre-existing persisted account row
- it MUST increment the per-account custody nonce on success
- `request_mid` MUST be replaced with `request_owner_address`

Normal first-use flow:

1. `STORAGE_CLAIM`
2. `SIGNER_ADD`
3. ordinary delegated-key user messages

#### 6.2 `SIGNER_REMOVE`

`SIGNER_REMOVE` remains the native delegated-key removal flow.

Revised semantics:

- it is custody-authorized by `owner_address`
- it does not require delegated-key authorization
- it MUST require the target key to exist for `owner_address`
- it MUST increment the per-account custody nonce on success

#### 6.3 EIP-712 domain and typed payloads

This MIP removes Tempo from identity allocation and transfer, but not from the settlement-chain signing domain.

For this reset, `host_chain_id(network)` remains the canonical EIP-155 chain ID of the Tempo settlement chain associated with the Makechain network. The EIP-712 domain remains:

```text
{ name: "Makechain", version: "1", chainId: host_chain_id(network) }
```

This domain applies to:

- `SIGNER_ADD`
- `SIGNER_REMOVE`
- app attribution signatures
- ETH verification claims

The typed payload's `network` field remains part of the signed message body where used. The domain `chainId` and payload `network` together provide settlement-chain and Makechain-network replay protection.

Address-native typed payloads SHOULD be:

```text
SignerAdd(address owner, bytes32 key, uint32 scope, uint64 validAfter,
          uint64 validBefore, uint64 nonce, bytes32[] allowedProjects,
          uint32 network)

SignerRemove(address owner, bytes32 key, uint64 validAfter,
             uint64 validBefore, uint64 nonce, uint32 network)
```

Required semantics:

- `owner` MUST equal `MessageData.owner_address`
- `nonce` MUST match the account's current `custody_nonce`
- `allowedProjects` MUST be bound into the `SignerAdd` signature
- `network` MUST match `MessageData.network`
- unknown or unsupported network identifiers MUST fail closed for custody, app-attribution, and ETH verification-claim signing or verification

#### 6.4 App attribution

App attribution remains part of `SIGNER_ADD`, but becomes address-based.

Required fields:

- `request_owner_address` instead of `request_mid`
- `request_signature` signed by that requesting app's `owner_address`

Recommended EIP-712 type:

```text
SignerRequest(address requestOwner, bytes32 key,
              uint64 validAfter, uint64 validBefore, uint32 network)
```

Required rules:

1. `request_owner_address` must be 20 bytes.
2. `request_signature` must verify directly against `request_owner_address`.
3. App attribution does not require resolving a Makechain account row for `request_owner_address`.
4. Self-request uses the same `owner_address` for both custody and app attribution.

#### 6.5 Structural and state validation

`SIGNER_ADD` structural validation MUST satisfy all of the following:

- `MessageData.owner_address` length is 20 bytes
- `key` length is 32 bytes
- `scope` is valid
- custody signature format is valid
- `request_owner_address` length is 20 bytes
- validity window is non-zero and ordered

`SIGNER_ADD` state validation MUST satisfy all of the following:

- target key is not already registered anywhere
- `nonce == current_custody_nonce(owner_address)`
- custody signature verifies against `owner_address`
- request signature verifies against `request_owner_address`

`SIGNER_REMOVE` structural validation MUST satisfy all of the following:

- `MessageData.owner_address` length is 20 bytes
- `key` length is 32 bytes
- custody signature format is valid
- validity window is non-zero and ordered

`SIGNER_REMOVE` state validation MUST satisfy all of the following:

- target key exists for `owner_address`
- `nonce == current_custody_nonce(owner_address)`
- custody signature verifies against `owner_address`

#### 6.6 Execution

Recommended execution:

```text
apply_signer_add(sigma, M):
  let acct = sigma[account(owner_address)] default_zero
  require key_reverse(body.key) = bottom
  require custody signature valid
  require request signature valid

  sigma[key(owner_address, body.key)] <- KeyState { scope, allowed_projects, ... }
  sigma[key_reverse(body.key)] <- owner_address
  acct.key_count <- acct.key_count + 1
  acct.custody_nonce <- acct.custody_nonce + 1
  sigma[account(owner_address)] <- acct

apply_signer_remove(sigma, M):
  let acct = sigma[account(owner_address)] default_zero
  require key(owner_address, body.key) != bottom
  require custody signature valid

  delete sigma[key(owner_address, body.key)]
  delete sigma[key_reverse(body.key)]
  acct.key_count <- acct.key_count - 1
  acct.custody_nonce <- acct.custody_nonce + 1
  sigma[account(owner_address)] <- acct
```

### 7. Authorization Model

Post-reset Makechain has three relevant authorization classes.

Delegated-key user messages:

- the envelope signer MUST be a registered key for `owner_address`
- signer scope MUST satisfy the required scope for the message type

Settlement-backed bootstrap messages:

- `STORAGE_CLAIM` bypasses delegated-key lookup
- authorization derives from verified finalized settlement data

Custody-authorized user messages:

- `SIGNER_ADD` and `SIGNER_REMOVE` MUST verify wallet authorization directly against `owner_address`

Where the current protocol grants special authority to the canonical project owner, the address-native variant applies the same owner-only semantics using `owner_address` rather than MID. This includes project-owner checks for remove, archive, and owner-level collaborator administration.

There are no relay-derived identity or signer-management messages in normal post-reset operation.

### 8. State Model

#### 8.1 Address-attached account state

Account bookkeeping becomes address-native.

Recommended stored fields:

```text
key_count: uint32
project_count: uint32
storage_units: uint32
custody_nonce: uint64
created_at: uint32
```

Required semantics:

- missing account state implies default-zero state
- there is no ownership-transfer nonce
- account creation is lazy state materialization, not identity allocation
- `created_at` is the first time a bookkeeping row is materialized, not the creation time of the identity

#### 8.2 Address-native key schema

State keys currently keyed by MID MUST be rewritten to use `owner_address`.

Recommended address-native merkleized prefixes:

| Prefix | Entity | Key Layout |
|--------|--------|------------|
| `0x04` | Account | `[0x04 | owner_address:20]` |
| `0x05` | Account metadata | `[0x05 | owner_address:20 | field:1]` |
| `0x06` | Key | `[0x06 | owner_address:20 | pubkey:32]` |
| `0x07` | Key reverse index | `[0x07 | pubkey:32] -> owner_address` |
| `0x09` | Verification | `[0x09 | owner_address:20 | address:*]` |
| `0x0C` | Project name index | `[0x0C | owner_address:20 | name:*]` |
| `0x0F` | Collaborator | `[0x0F | project_id:32 | target_owner_address:20]` |
| `0x10` | Link (forward) | `[0x10 | owner_address:20 | link_type:1 | target:*]` |
| `0x11` | Link (reverse) | `[0x11 | link_type:1 | target:* | owner_address:20]` |
| `0x12` | Reaction (forward) | `[0x12 | owner_address:20 | reaction_type:1 | project_id:32 | commit_hash:32]` |
| `0x13` | Reaction (reverse) | `[0x13 | reaction_type:1 | project_id:32 | commit_hash:32 | owner_address:20]` |
| `0x14` | Counter | `[0x14 | owner_address:20 | counter_type:1]` |
| `0x16` | Storage grant | `[0x16 | owner_address:20 | expires_at:4 | claim_id:32]` |
| `0x17` | Storage claim marker | `[0x17 | claim_id:32]` |

Required notes:

- the reverse-key index MUST continue to enforce delegated-key uniqueness across all accounts
- the project-name index MUST move from `(mid, name)` to `(owner_address, name)`
- the storage-claim marker MUST replace relay-event-based storage-rent deduplication for address-native networks

Removed prefixes or concepts:

- MID allocation metadata such as `next_mid`
- owner reverse index for MID uniqueness
- ownership transfer markers
- relay signer markers
- storage rent relay markers keyed to relay-injected events

#### 8.3 Correctness invariants

The address-native state model MUST preserve these invariants:

- deterministic state roots
- address immutability
- monotonic custody nonces
- atomic forward and reverse key-index updates
- counter consistency
- remove-wins and phantom-tombstone protections for existing 2P sets
- claim idempotence for storage settlement events

### 9. Storage and Quota Semantics

This MIP separates identity from active storage.

Required semantics:

- every valid `owner_address` is a principal even if no state has been materialized
- active storage is the sum of unexpired storage grants for that address
- storage expiry MUST remove only the ability to create or update quota-bound state
- storage expiry MUST NOT delete keys, identity, or historical state
- storage expiry MUST NOT block non-quota-bearing account maintenance operations such as `SIGNER_ADD` and `SIGNER_REMOVE`

Quota-bearing writes remain conceptually unchanged, but become keyed by `owner_address` instead of MID.

### 10. Tempo Verification and Consensus Coupling

#### 10.1 Settlement verification model

Tempo access remains localized to explicit storage-rent claims.

For post-reset operation:

- only `STORAGE_CLAIM` depends on Tempo settlement verification
- identity and signer management do not depend on relay-derived Tempo events
- replay verification for settled storage is message-local rather than block-global

#### 10.2 Removal of block-level Tempo coupling

For post-reset blocks:

- `relay_checkpoint` is not part of canonical address-native block or relay-payload semantics
- `BlockHeader.relay_checkpoint` and `RelayPayload.relay_checkpoint` MUST NOT participate in post-reset block construction or validation
- legacy wire fields MAY remain only for transition compatibility, but they are non-semantic and invalid for address-native blocks
- validators MUST NOT commit a Tempo frontier on each block
- replay verification MUST be message-local for `STORAGE_CLAIM` only

#### 10.3 Execution groups and replay verification

`STORAGE_CLAIM`, `SIGNER_ADD`, and `SIGNER_REMOVE` are account-level messages.

This matches the current execution architecture, where account messages are executed serially before project-group messages.

For post-reset blocks:

- no block-global identity replay verification is performed
- only `STORAGE_CLAIM` uses settlement-backed replay verification
- replay of `STORAGE_CLAIM` uses message-local receipt/log verification against finalized Tempo data

### 11. API and Client Surface

The public account and ownership surface becomes address-primary.

Required API direction:

- account queries MUST be keyed by `owner_address`
- project ownership filters MUST use `owner_address`
- signer attribution fields MUST use `request_owner_address`
- collaborator, link, reaction, and history surfaces MUST expose address-based identities
- storage quota proof queries MUST use `owner_address`

`GetAccount(owner_address)` SHOULD return a default-zero view even when no bookkeeping row has yet been materialized.

### 12. Verification Claims

Verification claims MUST bind directly to address-native identity.

Required changes:

- ETH verification claims bind directly to `owner_address`
- SOL verification challenge strings use `owner_address`, not MID

Recommended address-native ETH typed data:

```text
VerificationClaim(address owner, address ethAddress,
                  uint256 chainId, uint32 verificationType,
                  string network)
```

Required ETH semantics:

- `owner` MUST equal `MessageData.owner_address`
- `VerificationClaim.chainId` MUST equal `host_chain_id(MessageData.network)`
- `VerificationAddBody.chain_id` MUST equal `host_chain_id(MessageData.network)`
- the EIP-712 domain MUST remain `{ name: "Makechain", version: "1", chainId: host_chain_id(network) }`

Recommended SOL challenge string:

```text
makechain:verify:<network>:<owner_address_hex>
```

### 13. Rationale

This proposal pushes the reset model to its simplest coherent form.

Why remove MID entirely:

- once transfer and recovery are removed, MID no longer provides unique protocol value
- using `owner_address` directly aligns user identity, custody authority, and public protocol identity
- it removes an entire class of account-allocation and relay-driven identity machinery

Why add `STORAGE_CLAIM` instead of preserving `STORAGE_RENT`:

- storage settlement remains necessary
- relay-injected storage messages are not necessary
- an explicit user-submitted claim localizes Tempo dependence to the only place it is actually needed

Why keep `SIGNER_ADD` and `SIGNER_REMOVE`:

- they already encode the native custody-authorized delegated-key model
- removing relay signer flows simplifies nonce handling and replay reasoning

Why remove `relay_checkpoint`:

- block-global settlement coupling is unnecessary once identity and signer management are no longer relay-driven
- message-local settlement checks are sufficient for `STORAGE_CLAIM`

### 14. Backwards Compatibility

This MIP is intentionally not backwards compatible.

Effects:

- content-addressed message hashes change because acting identity changes from MID to `owner_address`
- MID-based wire fields, APIs, proofs, and state keys are replaced
- relay-driven identity and signer flows are invalid on post-reset networks
- no legacy MID allocations or relay-derived identity state are migrated

This is expected and acceptable because the proposal targets clean-slate deployment.

### 15. Rejected Alternatives

#### Keep MID but make registration native

Rejected because it preserves a second identity namespace without a strong protocol need.

#### Add a separate account bootstrap transaction

Rejected because addresses are valid principals by default and `STORAGE_CLAIM` only needs to claim storage, not allocate identity.

#### Preserve account transfer

Rejected because transferable identity is the main reason to keep a separate identifier instead of using `owner_address` directly.

#### Keep block-level settlement checkpoints

Rejected because they preserve block-global Tempo coupling that this reset no longer needs.

#### Keep relay-driven signer management as a fallback

Rejected because native custody-authorized signer management already exists and the relay path adds complexity.

### 16. Security Considerations

This proposal simplifies the protocol, but it sharpens a few security boundaries.

Wallet custody becomes the sole root authority:

- there is no native transfer or recovery flow
- loss of wallet authority cannot be repaired at the protocol layer

`STORAGE_CLAIM` must resist redirection and replay:

- the credited `owner_address` must match finalized settlement data
- the same settlement event must be consumable exactly once

Delegated keys must remain globally unique:

- `SIGNER_ADD` must reject a key already registered under another address
- the reverse-key index must remain canonical

Tempo dependence becomes narrower but not zero:

- validators that cannot verify a storage-backed message cannot safely accept it
- implementations should use bounded receipt/header caching and finality-aware verification

Expiry semantics must remain stable:

- delayed claim submission reduces remaining usable storage lifetime because expiry is based on settlement time
- expired storage must not erase identity or historical references

### 17. Acceptance Criteria

This MIP is considered specified when all of the following are true:

- `MessageData` and related protocol-visible identity fields are address-native
- `STORAGE_CLAIM` is defined as the settlement-backed storage ingress path
- `SIGNER_ADD` and `SIGNER_REMOVE` operate directly on address-native account state
- current relay-driven identity messages are rejected on post-reset networks
- `BlockHeader.relay_checkpoint` and `RelayPayload.relay_checkpoint` are not part of canonical post-reset block semantics
- the public API and proof surface are address-primary
- the proposal is clearly scoped as a clean-slate reset rather than an in-place migration

### 18. Copyright

Copyright and related rights waived via CC0.

