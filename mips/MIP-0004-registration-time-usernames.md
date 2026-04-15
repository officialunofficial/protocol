---
mip: 4
title: Registration-Time Usernames for Address-Native Accounts
description: Adds a globally unique, storage-backed username namespace to address-native accounts, assigned at first paid storage activation via STORAGE_CLAIM.
author: marthendalnunes
discussions-to: https://github.com/officialunofficial/protocol/discussions/14
status: Draft
type: Standards Track
created: 2026-04-13
requires: MIP-0003
---

## Abstract

This MIP specifies a username primitive for address-native Makechain networks defined by MIP-0003.

It has six parts:

1. Add a globally unique username namespace keyed to `owner_address`.
2. Extend `STORAGE_CLAIM` so first paid storage activation assigns a username.
3. Rely on the authenticated `STORAGE_CLAIM` envelope to authorize the username field.
4. Enforce that username reservation is immutable while an account has effective active storage.
5. Release usernames when storage fully expires, using Makechain's existing lazy storage-sweep model.
6. Expose persisted username-index state through the existing public operation and exclusion proof model.

This proposal builds on MIP-0003 and does not change the canonical identity model. `owner_address` remains the sole canonical account identifier. Usernames are a storage-backed, human-readable namespace layered on top of address-native identity.

This MIP includes an authorization change under which `STORAGE_CLAIM` becomes an authenticated user message with required scope `SIGNING` under the existing delegated-key scope model. Under this change, `OWNER` and `SIGNING` keys are valid for `STORAGE_CLAIM`, `AGENT` keys are not, and finalized settlement verification remains additionally mandatory.

## Motivation

MIP-0003 makes `owner_address` the sole canonical account identifier, but it does not define a canonical human-readable account handle.

`ACCOUNT_DATA(DISPLAY_NAME)` is not sufficient for this role:

- it is mutable profile metadata, not a unique namespace reservation
- it has no global uniqueness semantics
- it is governed by LWW metadata rules rather than registration rules
- it is not coupled to storage activation or expiry
- it is not exposed as a canonical account handle

A username primitive should instead reflect the storage-backed activation model of Makechain:

- any 20-byte address is already a valid principal
- usernames are not needed for principal validity
- usernames are needed only to reserve a global, human-readable handle
- that reservation should be economically gated by paid storage activation
- that reservation should be released once paid storage fully expires

A separate username-specific signature layer is unnecessary if `STORAGE_CLAIM` itself is owner-authorized at the protocol level. Under MIP-4, the `STORAGE_CLAIM` message body, including `username`, is authenticated by a registered delegated key for `owner_address`, while settlement evidence still proves that the storage credit is valid.

That produces a simpler design:

- settlement verification proves the claim is legitimate
- delegated-key authorization proves the message body, including `username`, was authorized by the account
- no additional username-specific signature mechanism is needed

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### 1. Activation and Scope

This MIP applies only to fresh genesis or reset networks that already include MIP-0003 semantics.

Activation model:

- this MIP is specified only for genesis-time deployment on a network whose canonical identity model is already address-native under MIP-0003
- this MIP is not specified as an in-place hardfork for an already-running MIP-0003 network
- this MIP does not define migration, reconciliation, or grace-period behavior for pre-existing storage-active accounts
- this MIP does not reintroduce MID or any MID-scoped identity concept
- this MIP does not change the MIP-0003 rule that `owner_address` is the sole canonical protocol identity

This MIP normatively amends the `STORAGE_CLAIM` authorization rules for MIP-4 deployments. The following changes take effect as part of MIP-4:

- `STORAGE_CLAIM` becomes an authenticated user message under the ordinary delegated-key scope model
- the envelope signer for `STORAGE_CLAIM` MUST be a registered delegated key for `MessageData.owner_address`
- the required scope for first successful application of `STORAGE_CLAIM` is `SIGNING`
- under the existing scope ordering, `OWNER` and `SIGNING` keys satisfy that requirement, `AGENT` does not
- finalized settlement verification remains additionally mandatory
- duplicate `STORAGE_CLAIM` replay semantics remain anchored to settlement identity: if finalized settlement verification succeeds and `storage_claim_marker(claim_id)` already exists, the message is a valid duplicate claim and execution MUST be an idempotent no-op regardless of current delegated-key state

This scope avoids any need to retrofit usernames onto already-active accounts that were created under a username-less MIP-0003 deployment.

### 2. Username Model

A username is a globally unique, human-readable handle attached to an `owner_address`.

Required semantics:

- a username MUST be globally unique across the active username namespace
- a username MUST map to exactly one `owner_address` while active
- an account MUST have at most one active username
- a username MAY be assigned only by a `STORAGE_CLAIM` that activates paid storage for an account whose effective active storage is zero after required sweep and before applying the new claim
- a `STORAGE_CLAIM` for an account that already has effective active storage MUST NOT assign, replace, or change a username
- while an account has effective active storage, its username reservation MUST remain fixed
- when an account's effective active storage drops to zero after sweep, its username reservation MUST be pruned and become available again

Usernames are not canonical identity. `owner_address` remains canonical. A username is a globally unique, storage-backed namespace reservation.

### 3. Canonical Username Format

Usernames are case-insensitive at the product level but have a single canonical protocol form.

Canonical form:

- the canonical form MUST be lowercase ASCII
- clients MAY accept mixed-case input, but they MUST normalize to lowercase ASCII before signing or submission
- implementations MUST NOT use Unicode normalization or locale-sensitive case folding

Required syntax:

- length MUST be between 3 and 32 characters inclusive
- allowed characters are `a-z`, `0-9`, and `-`

The canonical regex is:

```text
^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$
```

Normalization rule:

```text
normalize_username(raw):
  require raw is ASCII
  let lower = ASCII_lowercase(raw)
  require lower matches canonical username regex
  return lower
```

All consensus-visible username comparisons and persisted username state MUST use the normalized canonical username.

### 4. Canonical Wire Schema

#### 4.1 `StorageClaimBody`

`StorageClaimBody` is extended with a username field.

The canonical protobuf shape is:

```proto
message StorageClaimBody {
  uint32 units = 1;
  bytes settlement_tx_hash = 2;     // 32 bytes
  uint64 settlement_chain_id = 3;
  uint32 settlement_log_index = 4;  // receipt-local log index
  bytes actor = 5;                  // 20 bytes
  string username = 6;              // required iff this claim assigns first username
}
```

Required semantics:

- `username` is used only for first paid storage activation
- `username` does not affect settlement verification
- `username` is authenticated as part of the canonical `MessageData` payload because `STORAGE_CLAIM` is an authenticated delegated-key message under MIP-4
- no additional username-specific signature fields are part of the canonical wire schema

#### 4.2 `STORAGE_CLAIM` Authorization Change

This MIP normatively amends the `STORAGE_CLAIM` authorization rules as follows:

- the message envelope MUST be a valid Ed25519 envelope
- on first successful application of a claim, the envelope signer MUST be a registered delegated key for `MessageData.owner_address`
- on first successful application of a claim, the envelope signer MUST satisfy required scope `SIGNING`
- under the existing scope ordering, `OWNER` and `SIGNING` keys satisfy the requirement and `AGENT` does not
- successful finalized settlement verification remains mandatory
- after successful settlement verification, if `storage_claim_marker(claim_id)` already exists, execution MUST be an idempotent no-op regardless of current delegated-key state

Under this change, the `username` field is authenticated by the same delegated-key authorization that authenticates the rest of the `STORAGE_CLAIM` message body.

#### 4.3 Structural Validation

If `StorageClaimBody.username` is non-empty, all of the following MUST hold:

- `username` is already in canonical lowercase ASCII form
- `username` satisfies the syntax rules in Section 3

If `StorageClaimBody.username` is empty, no username assignment is attempted.

`STORAGE_CLAIM` continues to satisfy all MIP-0003 structural rules for settlement fields.

### 5. State Model

#### 5.1 Username Index

MIP-0003 leaves prefix `0x08` unused. This MIP assigns it to the global username index.

The canonical key is:

- `0x08 Username index`
- key layout: `[0x08 | username:*] -> owner_address`

Required semantics:

- the key suffix MUST be the canonical lowercase username bytes
- the stored value MUST be the canonical 20-byte `owner_address`
- the username index MUST be merkleized state
- global username uniqueness is enforced by this index

#### 5.2 Account State Extension

`AccountState` is extended with the account's active username.

The canonical logical schema delta relative to MIP-0003 is:

```text
AccountState {
  storage_units: uint32
  project_count: uint32
  created_at: uint32
  key_count: uint32
  custody_nonce: uint64
  username: string | null
}
```

Required semantics:

- `username` is `null` when the account has no active username reservation
- if `username != null`, it MUST be the canonical lowercase username
- if `username != null`, the username index entry `[0x08 | username] -> owner_address` MUST exist
- if `username == null`, no active username reservation for that owner may remain

The canonical serialized representation in typed state is:

```text
AccountState {
  storage_units: uint32
  project_count: uint32
  created_at: uint32
  key_count: uint32
  custody_nonce: uint64
  username: string | null
}
```

`username` MUST serialize as either a canonical lowercase JSON string or `null`.

#### 5.3 Effective-State Username Invariants

Because MIP-0003 storage expiry is enforced lazily through sweep-on-access rather than eager background mutation, username invariants are defined over effective execution-time or query-time state after the required sweep or read-time storage derivation.

Required invariants:

- after `sweep_expired_storage_grants_for_owner(owner, t)`, if effective active storage for `owner` is greater than zero, the owner MUST have exactly one username
- after `sweep_expired_storage_grants_for_owner(owner, t)`, if effective active storage for `owner` is zero, the owner MUST have no active username reservation
- no two owners may simultaneously hold the same username in effective swept state
- `AccountState.username` and the username index MUST remain mutually consistent whenever state is reconciled through required sweep

This MIP does not require eager global cleanup of stale username reservations outside the existing lazy-sweep model.

### 6. Validation and Execution

#### 6.1 Duplicate Claim Idempotence

MIP-0003 claim idempotence is preserved with settlement-first replay semantics.

Required rule:

- `STORAGE_CLAIM` MUST first verify finalized settlement evidence and require that the evidence matches `owner_address`, `actor`, and `units`
- after successful settlement verification, if `storage_claim_marker(claim_id)` already exists, the message is a valid duplicate claim and execution MUST be an idempotent no-op
- current delegated-key state MUST NOT cause a settlement-valid duplicate claim to fail once the marker already exists

Duplicate claims therefore remain verified replays anchored to settlement identity rather than to current mutable delegated-key state.

#### 6.2 First-Activation Rule

Username assignment is determined from effective active storage after required sweep and before applying the new claim.

Required algorithm:

1. compute `claim_id`
2. verify finalized settlement evidence
3. if `storage_claim_marker(claim_id)` exists, return no-op
4. verify delegated-key authorization using required scope `SIGNING`
5. sweep expired storage grants for `MessageData.owner_address` at `MessageData.timestamp`
6. compute the resulting pre-claim effective active storage units

Then:

- if pre-claim effective active storage units are greater than zero:
  - `username` MUST be empty
- if pre-claim effective active storage units are zero:
  - `username` MUST be present
  - `username` MUST be structurally valid and canonical

This makes username assignment mandatory for first paid storage activation and forbidden while storage remains active.

#### 6.3 Username Uniqueness and Stale Reservation Reclamation

When a first-activation `STORAGE_CLAIM` attempts to assign username `u`, validators MUST check the username index.

Required behavior:

- if `[0x08 | u]` does not exist, assignment MAY proceed
- if `[0x08 | u]` exists and points to the same `owner_address`, the message MUST be rejected because first-activation username assignment is no longer applicable
- if `[0x08 | u]` exists and points to a different owner, validators MUST sweep that indexed owner using the canonical storage-sweep procedure at `MessageData.timestamp`
- if the indexed owner still has effective active storage after sweep, the message MUST be rejected as username-taken
- if the indexed owner has zero effective active storage after sweep, validators MUST prune that stale username reservation before re-checking uniqueness
- after stale-pruning, if `[0x08 | u]` is absent, assignment MAY proceed

This reclamation is consensus-critical and mandatory, not optional.

Username availability and stale-reservation reclamation use the same `MessageData.timestamp` semantics as other storage-sensitive quota enforcement in Makechain. Accordingly, effective reclamation may occur within the protocol's allowed drift window relative to wall-clock grant expiry.

#### 6.4 Username Release on Sweep

The MIP-0003 storage-sweep logic is extended to release usernames when storage fully expires.

Required sweep behavior for owner `A` at time `t`:

- expired storage grants for `A` MUST be removed
- cached `AccountState.storage_units` MUST be refreshed to the post-sweep effective aggregate
- if the post-sweep effective active storage units for `A` equal zero and `AccountState.username != null`:
  - delete `[0x08 | username]`
  - set `AccountState.username = null`

This applies both:

- when sweeping the claimant during ordinary quota enforcement and `STORAGE_CLAIM` execution
- when sweeping a conflicting indexed owner during stale username reclamation

#### 6.5 `STORAGE_CLAIM` Execution

The canonical execution shape is:

```text
apply_storage_claim(sigma, M):
  let claim_id = storage_claim_id(...)

  require settlement verification succeeds and matches owner, actor, units

  if storage_claim_marker(claim_id) != bottom:
    return sigma

  require delegated-key authorization succeeds for owner_address with required scope SIGNING

  let owner = M.data.owner_address
  let preclaim_units = sweep_expired_storage_grants(owner, M.data.timestamp)
  let acct = sigma[account(owner)] default_zero

  if preclaim_units > 0:
    require body.username == ""
  else:
    require body.username != ""
    let username = normalize_username(body.username)

    if username_index(username) exists for other_owner:
      require other_owner != owner
      let other_units = sweep_expired_storage_grants(other_owner, M.data.timestamp)
      if other_units > 0:
        reject
      require username_index(username) == bottom

    require acct.username == null

  let expires_at = settlement_block_timestamp + STORAGE_TOTAL_PERIOD
  require expires_at > M.data.timestamp

  sigma[storage_grant(owner, expires_at, claim_id)] <- StorageGrantState { ... }
  sigma[storage_claim_marker(claim_id)] <- 1

  sigma[account(owner)] <- acct with {
    storage_units = preclaim_units + body.units,
    created_at = acct.created_at or M.data.timestamp,
    username = if preclaim_units == 0 then username else acct.username,
  }

  if preclaim_units == 0:
    sigma[username_index(username)] <- owner
```

The account snapshot used for username checks and final writeback MUST be loaded after the required claimant sweep, because that sweep may reconcile `AccountState.username`.

Only the normalized username variable MUST be persisted or indexed. Raw `body.username` MUST NOT be written to state. The `normalize_username(body.username)` step in execution is a verification assertion, not permission to silently transform non-canonical wire input. Non-canonical mixed-case usernames MUST be rejected rather than normalized during execution.

#### 6.6 Same-Block Username Claim Interactions

This MIP does not change Makechain's normal block execution semantics.

Required rule:

- username-bearing `STORAGE_CLAIM` messages in the same block are processed using the normal serial account-message execution order
- an earlier valid `STORAGE_CLAIM` MAY sweep a different indexed owner during stale-reservation reclamation and thereby reconcile that owner's stale username state before a later message from that owner is evaluated
- any later `STORAGE_CLAIM` in the same block MUST be evaluated against the post-sweep state produced by earlier successfully applied account messages in that block
- the first valid message that successfully assigns a username MAY succeed
- later conflicting messages in the same block MUST fail ordinary state validation and be dropped
- duplicate same-username claims in one block do not by themselves make the whole block invalid

Example: if owner A's claim sweeps owner B's stale reservation and removes B's username, then B's own later username-bearing `STORAGE_CLAIM` in the same block is evaluated against that already-updated state. This behavior is intended and deterministic.

Implementations MAY add proposer-side or admission-side checks to reduce wasted block space, but block validity semantics remain unchanged.

### 7. Proof Surface

Username proofs authenticate persisted username-index state only.

Required semantics:

- consensus-critical username uniqueness is enforced by direct state lookup during execution
- `STORAGE_CLAIM` does not carry an exclusion proof
- clients MAY preflight persisted username-index state with public inclusion or exclusion proofs
- public proof allowlists MUST be extended to include username index keys under prefix `0x08`

The proof meanings are:

- `GetOperationProof([0x08 | username])` proves that the persisted username-index key exists at the queried root and authenticates its persisted `owner_address` value
- `GetExclusionProof([0x08 | username])` proves that the persisted username-index key does not exist at the queried root

Required note:

- inclusion or exclusion of a username-index key does not by itself prove effective current ownership, effective availability, or post-sweep reservation status under lazy expiry
- execution remains authoritative because a persisted username mapping may become reclaimable only after the indexed owner is swept and reconciled at execution time

### 8. API and Client Surface

The public account surface MUST expose the canonical username separately from mutable profile metadata.

The canonical `GetAccountResponse` delta is:

```proto
message GetAccountResponse {
  reserved 1;               // was mid
  string display_name = 2;
  string avatar = 3;
  string bio = 4;
  string website = 5;
  repeated KeyEntry keys = 6;
  uint32 storage_units = 7;
  uint32 project_count = 8;
  repeated VerificationEntry verifications = 9;
  bytes owner_address = 10;
  uint32 link_count = 11;
  uint32 reaction_count = 12;
  uint64 custody_nonce = 13;
  uint32 max_projects = 14;
  uint32 max_links = 15;
  uint32 max_verifications = 16;
  uint32 max_reactions = 17;
  uint32 max_collaborators_per_project = 18;
  string username = 19;
}
```

Read semantics under lazy expiry MUST be effective semantics, not raw persisted-state semantics:

- account query responses MUST derive effective active storage from active grants at query time, as MIP-0003 already does for `storage_units`
- if effective active storage is zero at query time, `GetAccountResponse.username` MUST be empty even if persisted `AccountState.username` is stale and has not yet been swept
- if effective active storage is nonzero at query time, `GetAccountResponse.username` MUST return the canonical username from account state

`ACCOUNT_DATA(DISPLAY_NAME)` remains mutable profile metadata and is distinct from `username`.

Implementations MAY additionally add convenience RPCs such as username-to-account resolution, but they are not required by this MIP.

### 9. Rationale

This proposal keeps username reservation inside the existing paid storage activation path instead of introducing a parallel account-registration transaction.

Why tie usernames to first paid storage activation:

- any 20-byte address is already a valid principal under MIP-0003
- usernames are not needed to create a principal
- usernames are needed only to reserve a scarce global namespace
- gating that reservation on paid storage gives a clear economic cost and release condition

Why rely on delegated-key authorization rather than a username-specific signature:

- MIP-4 makes `STORAGE_CLAIM` an authenticated owner-authorized message
- once `STORAGE_CLAIM` is signed by a registered `SIGNING` key for `owner_address`, the `username` field is already authenticated as part of the message body
- this avoids introducing a second signature surface just for usernames

Why keep username off the settlement contract:

- username uniqueness is Makechain state, not Tempo settlement state
- adding usernames to settlement events would couple a human-readable namespace to settlement-contract evolution
- this proposal keeps the settlement contract focused on storage rent only

Why use a dedicated state index instead of `ACCOUNT_DATA(DISPLAY_NAME)`:

- usernames need global uniqueness
- usernames need proofability
- usernames need release on storage expiry
- `ACCOUNT_DATA` is LWW metadata and does not provide those semantics

### 10. Backwards Compatibility

This MIP is additive on top of MIP-0003 for new genesis deployments, but not neutral with respect to wire and state schema.

Effects:

- `StorageClaimBody` gains a new field at canonical field number `6`
- `AccountState` gains a new field `username`
- prefix `0x08`, previously unused in MIP-0003, becomes consensus-visible state
- proof allowlists expand to include username index keys
- `GetAccountResponse` gains a new field `username = 19`
- `STORAGE_CLAIM` authorization semantics change from transport-only settlement-backed to delegated-key-authenticated plus settlement-verified on first successful application

This is acceptable because the MIP is specified only for fresh MIP-0003 genesis deployments and not as an in-place upgrade.

### 11. Rejected Alternatives

#### Model username as `ACCOUNT_DATA`

Rejected because `ACCOUNT_DATA` is mutable LWW metadata with no uniqueness or expiry semantics.

#### Add a standalone username-registration message

Rejected because usernames are intended to be reserved at first paid storage activation, which already has a canonical path in MIP-0003.

#### Put username in the Tempo settlement event

Rejected because usernames are Makechain namespace state, not settlement-contract state.

#### Add a username-specific wallet signature to `STORAGE_CLAIM`

Rejected because once `STORAGE_CLAIM` is delegated-key-authorized by `owner_address`, the message body is already authenticated and the extra signature layer adds unnecessary complexity.

#### Keep usernames after all storage expires

Rejected because the proposal explicitly defines usernames as paid-storage-backed namespace reservations.

### 12. Security Considerations

This proposal introduces a globally contended namespace and therefore adds several security-sensitive edges.

Username authorization:

- the username choice is authenticated by the delegated-key-authorized `STORAGE_CLAIM` envelope
- this depends on MIP-4 requiring `STORAGE_CLAIM` to be signed by a registered `SIGNING` key for `owner_address`

Settlement verification:

- `STORAGE_CLAIM` remains settlement-verified
- delegated-key authorization does not replace settlement verification
- storage credit must still be derived only from finalized settlement evidence

Duplicate claim safety:

- existing claim-marker idempotence must be preserved
- duplicate `STORAGE_CLAIM` replays remain subject to full settlement verification before becoming no-ops
- delegated-key authorization applies to first successful application of a claim, not to settlement-valid duplicate replay after the claim marker already exists
- this preserves replay identity anchored to settled claim coordinates rather than to mutable post-claim key state

Stale reservation handling:

- stale username reservations may exist under lazy expiry until a required sweep occurs
- implementations must release usernames only after the indexed owner has been swept to zero effective active storage
- stale-reservation reclamation in execution is consensus-critical and must be deterministic
- username reclamation uses the same storage-sensitive timestamp semantics as existing Makechain quota enforcement and may therefore become effective within the allowed drift window relative to wall-clock expiry

Bootstrap ordering:

- because `STORAGE_CLAIM` requires a registered delegated key, the first-use flow becomes `SIGNER_ADD -> STORAGE_CLAIM -> ordinary messages`
- this is acceptable because `SIGNER_ADD` is already self-authenticating and does not require storage or a pre-existing account row

Denial of service:

- username conflicts may force execution-time sweep of a conflicting indexed owner
- implementations should keep this bounded by reusing existing storage-sweep code paths rather than performing unbounded scans

### 13. Acceptance Criteria

This MIP is considered specified when all of the following are true:

- `STORAGE_CLAIM` carries a canonical username field at wire field number `6` for first paid storage activation
- `STORAGE_CLAIM` is delegated-key-authorized by `owner_address` under MIP-4 with required scope `SIGNING` for first successful application
- duplicate claims with an existing claim marker remain full-evidence-verified idempotent no-ops regardless of current delegated-key state
- first paid storage activation requires a valid username
- subsequent storage claims while effective active storage remains nonzero cannot set or change username
- a global username index is defined in consensus state at prefix `0x08`
- `AccountState.username` is part of the canonical state model and serialized as `string | null`
- `GetAccountResponse.username` is exposed at field number `19`
- username release is defined through required storage sweep when effective active storage reaches zero
- stale conflicting username reservations are deterministically reclaimed after sweeping the indexed owner to zero effective active storage
- same-block username claim interactions, including earlier conflicting-owner sweeps affecting later claims, are handled by normal serial execution and dropping of later invalid messages
- username index keys are available on the public operation and exclusion proof surfaces
- proofs over username index keys are explicitly defined as proofs of persisted state only
- account responses expose canonical username separately from mutable display metadata using effective read-time semantics
- the MIP is clearly scoped to fresh MIP-0003 genesis deployment rather than in-place hardfork activation

### 14. Copyright

Copyright and related rights waived via CC0.

