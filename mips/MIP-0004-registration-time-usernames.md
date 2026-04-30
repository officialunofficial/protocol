---
mip: 4
title: Registration-Time Usernames for Address-Native Accounts
description: Adds a globally unique, storage-backed username namespace to address-native accounts through explicit username messages gated by active storage.
author: marthendalnunes
discussions-to: https://github.com/officialunofficial/protocol/discussions/14
status: Devnet
type: Standards Track
created: 2026-04-13
requires: MIP-0003
---

## Abstract

This MIP specifies storage-backed usernames for address-native Makechain networks defined by MIP-0003.

It has seven parts:

1. Add a globally unique username namespace keyed to `owner_address`.
2. Keep `STORAGE_CLAIM` as settlement-verified raw storage funding only.
3. Add explicit `USERNAME_CREATE` and `USERNAME_UPDATE` messages for username control.
4. Gate quota-bearing account activity on both active storage and an active username.
5. Add a cooldown period after a successful username set before the account may use `USERNAME_UPDATE` again.
6. Release usernames when storage fully expires, using Makechain's lazy storage-sweep model.
7. Expose username-backed account and proof behavior through the canonical API surface.

This proposal builds on MIP-0003 and does not change the canonical identity model. `owner_address` remains the sole canonical account identifier. Usernames are a separate, storage-backed, human-readable namespace layered on top of address-native identity.

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

The merged MIP-4 design separates storage funding from username control. This changes account activation from a single-step model to a two-step flow:

```text
STORAGE_CLAIM -> USERNAME_CREATE -> quota-bearing account activity
```

That separation keeps settlement-backed storage funding simple, makes username lifecycle explicit, and allows accounts to hold raw storage grants before choosing a username.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### 1. Scope and Activation Flow

This MIP defines the canonical username model for Makechain deployments that adopt MIP-4 semantics.

Scope:

- this MIP preserves the MIP-0003 rule that `owner_address` is the sole canonical protocol identity
- this MIP keeps account identity address-native
- this MIP separates raw storage funding from username lifecycle control
- this MIP does not require a username for principal validity, only for quota-bearing use of storage-backed capacity

The canonical activation flow is:

1. fund storage with `STORAGE_CLAIM`
2. claim a canonical username with `USERNAME_CREATE`
3. perform quota-bearing account activity

`STORAGE_CLAIM` remains a settlement-verified user-submitted message. `USERNAME_CREATE` and `USERNAME_UPDATE` are ordinary delegated-key account messages.

### 2. Username Model

A username is a globally unique, human-readable handle attached to an `owner_address`.

Required semantics:

- a username MUST be globally unique across the active username namespace
- a username MUST map to exactly one `owner_address` while active
- an account MUST have at most one active username
- raw active storage grants MAY exist while the account has no active username
- if the account has raw active storage grants but no active username, its usable quota is zero
- `USERNAME_CREATE` claims the first username for an account with active storage and no active username
- `USERNAME_UPDATE` replaces the current username for an account with active storage and an active username
- `USERNAME_UPDATE` MUST be rejected until `USERNAME_CHANGE_COOLDOWN = 7 days` has elapsed since the account's most recent successful username set
- both successful `USERNAME_CREATE` and successful `USERNAME_UPDATE` MUST reset the cooldown clock by persisting `username_last_set_at = MessageData.timestamp`
- when an account's effective active storage drops to zero after required sweep, its username reservation MUST be pruned and become available again
- the cooldown applies only to `USERNAME_UPDATE`; releasing a username does not block a later fresh `USERNAME_CREATE`

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
- the first and last characters MUST be alphanumeric

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

The canonical protobuf schema is:

```proto
message StorageClaimBody {
  uint32 units = 1;
  bytes settlement_tx_hash = 2;     // 32 bytes
  uint64 settlement_chain_id = 3;
  uint32 settlement_log_index = 4;  // receipt-local log index
  bytes actor = 5;                  // 20 bytes
}
```

Required semantics:

- `STORAGE_CLAIM` funds raw storage grants only
- `STORAGE_CLAIM` does not assign, replace, or otherwise carry username state
- `STORAGE_CLAIM` duplicate replay remains anchored to settlement identity through `claim_id`

#### 4.2 `UsernameCreateBody` and `UsernameUpdateBody`

The canonical protobuf schema is:

```proto
message UsernameCreateBody {
  string username = 1;
}

message UsernameUpdateBody {
  string username = 1;
}
```

Required semantics:

- both messages carry only the canonical lowercase username string
- `USERNAME_CREATE` is used for the first active username on an account
- `USERNAME_UPDATE` is used to replace an existing active username

#### 4.3 Authorization

`STORAGE_CLAIM` authorization is settlement-backed, not delegated-key-backed.

Required rules:

- the message envelope MUST be a valid Ed25519 envelope
- finalized settlement verification MUST match `owner_address`, `actor`, and `units`
- if `storage_claim_marker(claim_id)` already exists after successful settlement verification, execution MUST be an idempotent no-op
- first successful application of `STORAGE_CLAIM` does not require delegated-key authorization
- the envelope signer for `STORAGE_CLAIM` is transport-only and gains no account authority from the envelope alone

`USERNAME_CREATE` and `USERNAME_UPDATE` are delegated-key account messages.

Required rules:

- the envelope signer MUST be a registered delegated key for `MessageData.owner_address`
- the required scope is `SIGNING`
- under the existing scope ordering, `OWNER` and `SIGNING` keys satisfy that requirement and `AGENT` does not

#### 4.4 Structural Validation

If `UsernameCreateBody.username` or `UsernameUpdateBody.username` is present, all of the following MUST hold:

- `username` is already in canonical lowercase ASCII form
- `username` satisfies the syntax rules in Section 3

`STORAGE_CLAIM` continues to satisfy all MIP-0003 structural rules for settlement fields.

### 5. State Model

#### 5.1 Username Index

This MIP assigns prefix `0x08` to the global username index.

The canonical key is:

- `0x08 Username index`
- key layout: `[0x08 | username:*] -> owner_address`

Required semantics:

- the key suffix MUST be the canonical lowercase username bytes
- the stored value MUST be the canonical 20-byte `owner_address`
- the username index MUST be merkleized state
- global username uniqueness is enforced by this index

#### 5.2 Account State and Usable Quota

The canonical logical account model includes `username: string | null` and `username_last_set_at: uint32` alongside raw `storage_units`.

Required semantics:

- `AccountState.username` is `null` when the account has no active username reservation
- if `AccountState.username != null`, it MUST be the canonical lowercase username
- if `AccountState.username != null`, the username index entry `[0x08 | username] -> owner_address` MUST exist
- `AccountState.username_last_set_at` is the consensus timestamp of the most recent successful `USERNAME_CREATE` or `USERNAME_UPDATE`, or `0` if no username has ever been set
- raw `storage_units` reflect active storage grants only
- usable quota is derived from raw storage plus username activation
- if the account lacks an active username after required reconciliation, usable quota is zero even if raw storage grants are positive

#### 5.3 Effective-State Username Invariants

Because storage expiry is enforced lazily through sweep-on-access rather than eager background mutation, username invariants are defined over effective execution-time or query-time state after required sweep or read-time derivation.

Required invariants:

- after `sweep_expired_storage_grants_for_owner(owner, t)`, if effective active storage for `owner` is greater than zero and the owner has completed username registration, the owner has exactly one active username
- after `sweep_expired_storage_grants_for_owner(owner, t)`, if effective active storage for `owner` is zero, the owner has no active username reservation
- no two owners may simultaneously hold the same username in effective swept state
- `AccountState.username` and the username index MUST remain mutually consistent whenever state is reconciled through required sweep

### 6. Validation and Execution

#### 6.1 Duplicate Claim Idempotence

MIP-0003 claim idempotence is preserved with settlement-first replay semantics.

Required rule:

- `STORAGE_CLAIM` MUST first verify finalized settlement evidence and require that the evidence matches `owner_address`, `actor`, and `units`
- after successful settlement verification, if `storage_claim_marker(claim_id)` already exists, the message is a valid duplicate claim and execution MUST be an idempotent no-op
- no delegated-key state is consulted for a valid duplicate claim once the marker already exists

Duplicate claims therefore remain verified replays anchored to settlement identity rather than to mutable delegated-key state.

#### 6.2 `STORAGE_CLAIM` Execution

The canonical execution shape is:

```text
apply_storage_claim(sigma, M):
  let claim_id = storage_claim_id(...)

  require settlement verification succeeds and matches owner, actor, units

  if storage_claim_marker(claim_id) != bottom:
    return sigma

  let owner = M.data.owner_address
  let active_units = sweep_expired_storage_grants(owner, M.data.timestamp)
  let acct = sigma[account(owner)] default_zero

  let expires_at = settlement_block_timestamp + STORAGE_TOTAL_PERIOD
  require expires_at > M.data.timestamp

  sigma[storage_grant(owner, expires_at, claim_id)] <- StorageGrantState { ... }
  sigma[storage_claim_marker(claim_id)] <- 1

  sigma[account(owner)] <- acct with {
    storage_units = active_units + body.units,
    created_at = acct.created_at or M.data.timestamp,
  }
```

`STORAGE_CLAIM` does not write username state.

#### 6.3 `USERNAME_CREATE`

`USERNAME_CREATE` claims the first active username for an account.

Required validation:

1. delegated-key authorization with required scope `SIGNING` MUST pass
2. claimant expired storage grants MUST be swept at `MessageData.timestamp`
3. the claimant MUST have active raw storage after sweep
4. the claimant MUST not already have an active username
5. the requested username MUST be canonical and structurally valid
6. the requested username MUST be available after mandatory stale-reservation reclamation

Canonical execution shape:

```text
apply_username_create(sigma, M):
  require delegated-key authorization succeeds for owner_address with required scope SIGNING

  let owner = M.data.owner_address
  let active_units = sweep_expired_storage_grants(owner, M.data.timestamp)
  require active_units > 0

  let acct = sigma[account(owner)] default_zero
  require acct.username == null

  let username = normalize_username(body.username)
  require username_available_after_reclamation(username, owner, M.data.timestamp)

  sigma[account(owner)] <- acct with {
    username = username,
    username_last_set_at = M.data.timestamp,
  }
  sigma[username_index(username)] <- owner
```

#### 6.4 `USERNAME_UPDATE`

`USERNAME_UPDATE` replaces an account's current active username.

Required validation:

1. delegated-key authorization with required scope `SIGNING` MUST pass
2. claimant expired storage grants MUST be swept at `MessageData.timestamp`
3. the claimant MUST have active raw storage after sweep
4. the claimant MUST already have an active username
5. the current username index entry MUST authenticate `[0x08 | current_username] -> owner_address`, otherwise execution MUST fail closed
6. `MessageData.timestamp` MUST be at least `AccountState.username_last_set_at + USERNAME_CHANGE_COOLDOWN`, using saturating `uint32` arithmetic for the comparison
7. the requested username MUST differ from the current username
8. the requested username MUST be canonical and structurally valid
9. the requested username MUST be available after mandatory stale-reservation reclamation

Canonical execution shape:

```text
apply_username_update(sigma, M):
  require delegated-key authorization succeeds for owner_address with required scope SIGNING

  let owner = M.data.owner_address
  let active_units = sweep_expired_storage_grants(owner, M.data.timestamp)
  require active_units > 0

  let acct = sigma[account(owner)]
  let current = acct.username
  require current != null
  require username_index(current) == owner
  require M.data.timestamp >= saturating_add(acct.username_last_set_at,
                                             USERNAME_CHANGE_COOLDOWN)

  let next = normalize_username(body.username)
  require next != current
  require username_available_after_reclamation(next, owner, M.data.timestamp)

  delete sigma[username_index(current)]
  sigma[account(owner)] <- acct with {
    username = next,
    username_last_set_at = M.data.timestamp,
  }
  sigma[username_index(next)] <- owner
```

#### 6.5 Username Uniqueness and Stale Reservation Reclamation

When `USERNAME_CREATE` or `USERNAME_UPDATE` attempts to claim username `u`, validators MUST check the username index.

Required behavior:

- if `[0x08 | u]` does not exist, assignment MAY proceed
- if `[0x08 | u]` exists and points to the same `owner_address`, `USERNAME_CREATE` MUST fail and `USERNAME_UPDATE` MUST fail if `u` equals the current username
- if `[0x08 | u]` exists and points to a different owner, validators MUST sweep that indexed owner using the canonical storage-sweep procedure at `MessageData.timestamp`
- if the indexed owner still has effective active storage after sweep, the message MUST be rejected as username-taken
- if the indexed owner has zero effective active storage after sweep, validators MUST prune that stale username reservation before re-checking uniqueness
- after stale-pruning, if `[0x08 | u]` is absent, assignment MAY proceed

This reclamation is consensus-critical and mandatory, not optional.

#### 6.6 Username Release on Sweep

The storage-sweep logic is extended to release usernames when storage fully expires.

Required sweep behavior for owner `A` at time `t`:

- expired storage grants for `A` MUST be removed
- cached `AccountState.storage_units` MUST be refreshed to the post-sweep effective aggregate
- if the post-sweep effective active storage units for `A` equal zero and `AccountState.username != null`:
  - delete `[0x08 | username]`
  - set `AccountState.username = null`
- `AccountState.username_last_set_at` is retained when sweep releases a username reservation; sweep does not reset the cooldown timestamp

This applies both when sweeping the claimant during ordinary quota enforcement and when sweeping a conflicting indexed owner during stale username reclamation.

#### 6.7 Same-Block Username Interactions

This MIP does not change Makechain's normal block execution semantics.

Required rule:

- `STORAGE_CLAIM`, `USERNAME_CREATE`, and `USERNAME_UPDATE` are processed using the normal serial account-message execution order
- an earlier successful `STORAGE_CLAIM` MAY enable a later `USERNAME_CREATE` in the same block
- an earlier successful `USERNAME_CREATE` or `USERNAME_UPDATE` MAY start or reset the cooldown before a later same-block `USERNAME_UPDATE`
- an earlier successful `USERNAME_UPDATE` MAY free a username before a later same-block claim attempts to take it
- later conflicting messages in the same block MUST fail ordinary state validation and be dropped
- conflicting same-username attempts in one block do not by themselves make the whole block invalid

Implementations MAY add proposer-side or admission-side checks to reduce wasted block space, but block validity semantics remain unchanged.

### 7. Proof Surface

Username proofs authenticate persisted username-index and account state only.

Required semantics:

- consensus-critical username uniqueness is enforced by direct state lookup during execution
- public proof allowlists MUST include username index keys under prefix `0x08`
- clients MAY preflight persisted username-index state with public inclusion or exclusion proofs
- quota proofs MUST authenticate the account row used to derive username-gated usable quota and, when applicable, the matching username-index row

The proof meanings are:

- `GetOperationProof([0x08 | username])` proves that the persisted username-index key exists at the queried root and authenticates its persisted `owner_address` value
- `GetExclusionProof([0x08 | username])` proves that the persisted username-index key does not exist at the queried root
- `GetStorageQuotaProof` proves raw active grants, the account row, and the username-index row required to derive usable quota

Required note:

- inclusion or exclusion of a username-index key does not by itself prove effective current ownership or availability under lazy expiry
- execution remains authoritative because a persisted username mapping may become reclaimable only after the indexed owner is swept and reconciled at execution time

### 8. API and Client Surface

The public account surface MUST expose the canonical username separately from mutable profile metadata.

The canonical protobuf surface includes:

- `GetAccountResponse.username = 21`
- `GetAccountResponse.storage_units` as raw active storage grants
- `GetAccountResponse.max_*` quota fields derived from username-gated usable quota

Read semantics under lazy expiry MUST be effective semantics, not raw persisted-state semantics:

- account query responses MUST derive effective active storage from active grants at query time
- if effective active storage is zero at query time, `GetAccountResponse.username` MUST be empty even if persisted `AccountState.username` is stale and has not yet been swept
- if effective active storage is nonzero but there is no active username, `GetAccountResponse.username` MUST be empty and all username-gated quota fields MUST be zero
- `GetAccountResponse.username` is populated only when the account has both active storage and an active username reservation

`ACCOUNT_DATA(DISPLAY_NAME)` remains mutable profile metadata and is distinct from `username`.

Implementations MAY additionally add convenience RPCs such as username-to-account resolution, but they are not required by this MIP.

### 9. Rationale

This proposal keeps username reservation coupled to storage-backed activation while separating storage funding from username control.

Why use a two-step flow:

- settlement verification and username uniqueness are different concerns
- raw storage funding should remain a settlement-backed protocol path
- username lifecycle should remain explicit and delegated-key-authorized
- accounts can fund storage before choosing a canonical handle

Why gate usable quota on an active username:

- usernames are the scarce namespace resource introduced by MIP-4
- tying quota-bearing activity to an active username makes the namespace economically meaningful
- raw grants can remain visible without automatically enabling account activity

Why add a username-update cooldown:

- it prevents accounts from churning identities with unlimited `USERNAME_UPDATE` messages
- it preserves explicit delegated-key username control without changing the wire schema
- it keeps the mitigation account-local and deterministic under normal timestamp rules

Why keep username off the settlement contract:

- username uniqueness is Makechain state, not Tempo settlement state
- adding usernames to settlement events would couple a human-readable namespace to settlement-contract evolution
- this proposal keeps the settlement contract focused on storage rent only

Why use a dedicated state index instead of `ACCOUNT_DATA(DISPLAY_NAME)`:

- usernames need global uniqueness
- usernames need proofability
- usernames need release on storage expiry
- `ACCOUNT_DATA` is LWW metadata and does not provide those semantics

### 10. Rejected Alternatives

#### Carry username inside `STORAGE_CLAIM`

Rejected because the merged MIP-4 design keeps settlement-backed storage funding separate from username lifecycle control.

#### Model username as `ACCOUNT_DATA`

Rejected because `ACCOUNT_DATA` is mutable LWW metadata with no uniqueness or expiry semantics.

#### Put username in the Tempo settlement event

Rejected because usernames are Makechain namespace state, not settlement-contract state.

#### Allow usable quota without a username

Rejected because MIP-4 intentionally gates quota-bearing activity on both active storage and an active username.

#### Keep usernames after all storage expires

Rejected because the proposal explicitly defines usernames as paid-storage-backed namespace reservations.

#### Add a new cooldown message or protobuf field

Rejected because the cooldown is fully expressible as ordinary account state plus a protocol constant. Extending the wire schema would widen scope without adding new consensus capability.

### 11. Security Considerations

This proposal introduces a globally contended namespace and therefore adds several security-sensitive edges.

Settlement verification:

- `STORAGE_CLAIM` remains settlement-verified
- storage credit must be derived only from finalized settlement evidence
- duplicate `STORAGE_CLAIM` replay remains subject to full settlement verification before becoming a no-op

Username authorization:

- `USERNAME_CREATE` and `USERNAME_UPDATE` require delegated-key scope `SIGNING`
- username lifecycle control is separate from settlement-backed storage funding
- successful username sets start or reset a 7-day cooldown before `USERNAME_UPDATE` may succeed again

Duplicate claim safety:

- existing claim-marker idempotence must be preserved
- duplicate `STORAGE_CLAIM` replays remain settlement-anchored rather than delegated-key-anchored
- mutable delegated-key state cannot invalidate a settlement-valid duplicate claim once the marker exists

Stale reservation handling:

- stale username reservations may exist under lazy expiry until a required sweep occurs
- implementations must release usernames only after the indexed owner has been swept to zero effective active storage
- stale-reservation reclamation in execution is consensus-critical and must be deterministic

Bootstrap ordering:

- first-use flow becomes `STORAGE_CLAIM -> USERNAME_CREATE -> ordinary messages`
- no pre-existing delegated key is required to apply the first successful storage claim
- delegated-key authorization is required before username registration and later username changes

Denial of service:

- username conflicts may force execution-time sweep of a conflicting indexed owner
- implementations should keep this bounded by reusing existing storage-sweep code paths rather than performing unbounded scans
- unlimited rename churn is mitigated by the `USERNAME_UPDATE` cooldown, reducing namespace and identity spam without affecting first registration

### 12. Acceptance Criteria

This MIP is considered specified when all of the following are true:

- `StorageClaimBody` contains only settlement-backed raw storage funding fields and no username field
- `USERNAME_CREATE` and `USERNAME_UPDATE` are part of the canonical protobuf schema
- `STORAGE_CLAIM` remains settlement-verified and duplicate-idempotent, and first successful application does not require delegated-key authorization
- `USERNAME_CREATE` and `USERNAME_UPDATE` are delegated-key-authorized by `owner_address` with required scope `SIGNING`
- a global username index is defined in consensus state at prefix `0x08`
- `AccountState.username` and `AccountState.username_last_set_at` are part of the canonical state model and serialized canonically
- `GetAccountResponse.username` is exposed on the canonical public account surface at field number `21`
- raw active storage grants may exist without an active username
- both successful `USERNAME_CREATE` and `USERNAME_UPDATE` write `username_last_set_at = MessageData.timestamp`
- `USERNAME_UPDATE` is rejected until `USERNAME_CHANGE_COOLDOWN = 7 days` has elapsed since the account's most recent successful username set
- usable quota is zero whenever the account lacks an active username after required reconciliation
- username release is defined through required storage sweep when effective active storage reaches zero
- sweep-time username release does not reset `username_last_set_at` and does not block a later fresh `USERNAME_CREATE`
- stale conflicting username reservations are deterministically reclaimed after sweeping the indexed owner to zero effective active storage
- same-block interactions among `STORAGE_CLAIM`, `USERNAME_CREATE`, and `USERNAME_UPDATE` are handled by normal serial execution and dropping of later invalid messages
- username index keys are available on the public operation and exclusion proof surfaces
- quota proofs authenticate the username-backed usable quota model
- account responses expose canonical username separately from mutable display metadata using effective read-time semantics

### 13. Copyright

Copyright and related rights waived via CC0.
