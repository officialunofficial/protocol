---
mip: 5
title: Merge Requests for Cross-Project Contribution Proposals
description: Adds a protocol-level merge request primitive enabling permissionless contribution proposals from fork descendants to upstream projects.
author: marthendalnunes
discussions-to: https://github.com/officialunofficial/protocol/discussions/15
status: Draft
type: Standards Track
created: 2026-04-13
requires: MIP-0003
---

## Abstract

This MIP specifies a protocol-level merge request primitive that enables a user who is not a project collaborator to propose changes from a fork descendant back to an upstream project, and enables project members to close those proposals without granting the proposer write access.

It has six parts:

1. Add `MERGE_REQUEST_ADD` and `MERGE_REQUEST_REMOVE` as a new tombstone-backed 2P set family.
2. Define dual authorization for `MERGE_REQUEST_REMOVE`: the original requester MAY withdraw without project membership, and a project member with `WRITE+` permission MAY close the request.
3. Preserve fork ancestry in a retained canonical lineage index so merge-request lineage validation does not depend on prunable project rows.
4. Store merge request state under target-project-namespaced keys with a requester reverse index, following existing tombstone-backed 2P-set patterns (tombstones, prune markers, compound proofs).
5. Extend `ProjectState` with a `merge_request_count` counter and apply requester-funded global storage limits with a target-project namespace ceiling.
6. Expose public merge request queries via gRPC and the REST gateway.

This proposal does not change how projects are created, fork authorization or identity derivation, or how commits and refs are updated. It does require `FORK` to persist a retained immediate-parent lineage row for later merge-request validation. Merge resolution remains application-layer: the protocol records the proposal, and acceptance is performed by a project member submitting `COMMIT_BUNDLE` and `REF_UPDATE` messages on the target project, then closing the merge request.

## Motivation

Makechain supports permissionless forking via `FORK`, but it provides no protocol mechanism for a forker to propose their changes from a fork lineage back to the upstream project without receiving collaborator access. The only paths today are:

1. The upstream owner adds the forker as a collaborator, granting broader access than a contribution proposal warrants.
2. The upstream owner manually re-pushes the relevant commits and ref updates.

This gap makes decentralized contribution workflows depend on out-of-band coordination. A protocol-level merge request primitive would:

1. Enable permissionless contribution workflows without granting write access to the upstream project.
2. Provide discoverable, attributable, and verifiable onchain state that any client can index without an off-chain service.
3. Preserve Makechain's thin-consensus principle: the protocol orders metadata, not content merges.
4. Maintain project boundary integrity: project members retain full control over which contributions enter the target project's namespace.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### 1. Scope and Integration

This MIP specifies canonical merge-request behavior for a clean-slate network reset. It assumes no preserved pre-MIP chain state, no activation boundary, and no compatibility obligation with older serialized state or older protobuf field assignments.

It defines new message types, state keys, and validation rules for merge requests without changing project creation, fork authorization, identity derivation, or ref/commit update semantics outside this new primitive.

### 2. Message Types

#### 2.1 MessageType enum

Two new enum values are added to `MessageType` in `proto/makechain.proto`:

```protobuf
// 2P: Merge request set (content-addressed)
MESSAGE_TYPE_MERGE_REQUEST_ADD    = 84;
MESSAGE_TYPE_MERGE_REQUEST_REMOVE = 85;
```

#### 2.2 MessageData body

Two new oneof variants are added to the `body` field of `MessageData`:

```protobuf
MergeRequestAddBody    merge_request_add    = 96;
MergeRequestRemoveBody merge_request_remove = 97;
```

#### 2.3 MergeRequestAddBody

```protobuf
message MergeRequestAddBody {
  bytes project_id          = 1; // Target (upstream) project ID, 32 bytes
  bytes source_project_id   = 2; // Source fork-descendant project ID, 32 bytes
  bytes source_ref          = 3; // Branch/ref name in the fork, 1-254 bytes, no null bytes
  bytes source_commit_hash  = 4; // Head commit of proposed changes, 32 bytes
  bytes target_ref          = 5; // Suggested target ref in upstream, 1-254 bytes, no null bytes
  string title              = 6; // Short description, 1-200 UTF-8 bytes
}
```

Required semantics:

1. `project_id` is the target (upstream) project that the merge request proposes changes to.
2. `source_project_id` is the source project that contains the proposed changes.
3. `source_project_id` MUST identify a project whose retained fork-parent lineage under prefix `0x1A` reaches `project_id` within at most `MAX_FORK_LINEAGE_DEPTH = 256` hops.
4. `source_ref` identifies the branch or ref in the source project that contains the changes.
5. `source_ref` MUST identify an existing ref in `source_project_id` whose current head equals `source_commit_hash` at `MERGE_REQUEST_ADD` execution time.
6. `source_commit_hash` is the head commit in the source project that the requester is offering to merge.
7. `source_commit_hash` is authoritative; `source_ref` is invalid unless it resolves exactly to that hash.
8. `target_ref` is a suggested target ref name in the upstream project. It is advisory only and does not constrain the project member performing the merge.
9. `title` is a short human-readable description of the proposed change.
10. `source_project_id` MUST NOT equal `project_id`.
11. The content-addressed identity is `request_id = Message.hash = H(canonical_encode(MessageData))`, following the same principle as `project_id` for `PROJECT_CREATE`.

#### 2.4 MergeRequestRemoveBody

```protobuf
message MergeRequestRemoveBody {
  bytes project_id = 1; // Target project ID, 32 bytes
  bytes request_id = 2; // Content-addressed MR ID (= Message.hash of the ADD), 32 bytes
}
```

Required semantics:

1. `project_id` is the target project that the merge request belongs to.
2. `request_id` is the original `MERGE_REQUEST_ADD` message hash and therefore the merge request identifier.

### 3. State Model

#### 3.1 MergeRequestState

`MergeRequestState` is stored at `[0x1B | project_id:32 | request_id:32]`.

Canonical serialized schema:

```text
MergeRequestState {
  requester_owner_address: [u8; 20],
  source_project_id:       [u8; 32],
  source_ref:              Vec<u8>,
  source_commit_hash:      [u8; 32],
  target_ref:              Vec<u8>,
  title:                   String,
  added_at:                u32,
}
```

Required semantics:

1. `requester_owner_address` is the canonical `MessageData.owner_address` from the original `MERGE_REQUEST_ADD` message.
2. `source_project_id`, `source_ref`, `source_commit_hash`, `target_ref`, and `title` are carried from `MergeRequestAddBody`.
3. `added_at` is the `MessageData.timestamp` from the `MERGE_REQUEST_ADD` message.
4. This state is merkleized and participates in state-root computation.

This proposal does not add a protocol-level `merged`, `rejected`, `closed_reason`, or `closed_by` field. Closure attribution is available from finalized history by inspecting the `MERGE_REQUEST_REMOVE` message that closed the request.

#### 3.2 Key schema

Three new prefixes are assigned:

| Prefix | Entity | Key Layout |
|--------|--------|-----------|
| `0x1A` | Fork parent (retained lineage) | `[0x1A | project_id:32]` |
| `0x1B` | Merge request (forward) | `[0x1B | project_id:32 | request_id:32]` |
| `0x1C` | Merge request (reverse, by requester) | `[0x1C | requester_owner_address:20 | project_id:32 | request_id:32]` |

Required semantics:

1. For every `FORK` project, `[0x1A | forked_project_id]` MUST store that fork's immediate parent `source_project_id`.
2. Non-fork projects MUST NOT have a `0x1A` lineage row.
3. `fork_lineage(...)` for `MERGE_REQUEST_ADD` MUST follow retained `0x1A` rows, not prunable `ProjectState` rows.
4. If a project row exists and `project.fork_source != None`, that field MUST agree with the retained `0x1A` lineage row for the same `project_id`.
5. The forward key supports prefix scans by target project: `[0x1B | project_id]` returns merge requests targeting a project.
6. The reverse key supports prefix scans by requester owner address: `[0x1C | requester_owner_address]` returns merge requests opened by an account.
7. For every forward entry, the corresponding reverse entry MUST exist, and vice versa.
8. When a merge request active entry is deleted due to `MERGE_REQUEST_REMOVE`, quota pruning, or target-project subtree cleanup, the corresponding reverse entry MUST be deleted in the same state transition.
9. When merge-request state for a target project is deleted as part of project removal or subtree cleanup, implementations MUST delete the project's merge-request forward rows, requester reverse rows, tombstones, and prune markers for this family.
10. Project removal, project pruning, and subtree cleanup MUST NOT delete retained `0x1A` lineage rows.
11. Prefixes `0x1A`, `0x1B`, and `0x1C` MUST be added explicitly to the schema-prefix, queryable-prefix, and merkleized-prefix sets in the implementation.
12. Implementations that define canonical first/last prefix bounds for schema, queryable, or merkleized ranges MUST extend those bounds consistently so that prefixes `0x1A`, `0x1B`, and `0x1C` are included in every intended range-based check or iteration, not only in explicit allowlists.
13. Public proof allowlists MUST be explicitly updated for merge-request proofs on the public proof surface; retained `0x1A` lineage rows are internal canonical state and are not part of the public proof surface.
14. Merge request active keys MUST be added to the 2P-set compound-proof allowlist if compound proofs are supported for this family.

#### 3.3 ProjectState extension

`ProjectState` is extended with one field:

```text
ProjectState {
  owner_address:         [u8; 20],
  status:                ProjectStatus,
  created_at:            u32,
  name:                  String,
  visibility:            Visibility,
  fork_source:           Option<[u8; 32]>,
  ref_count:             u32,
  collaborator_count:    u32,
  commit_count:          u32,
  merge_request_count:   u32,
}
```

Required semantics:

1. `merge_request_count` MUST equal the number of active merge request entries under `[0x1B | project_id]`.
2. Handlers MUST maintain counter accuracy across add, remove, and prune operations.
3. This field is merkleized as part of `ProjectState`.
4. When writing `ProjectState`, `merge_request_count` MUST be present (not conditionally omitted), per Appendix B.2 of the specification.

#### 3.4 No requester counter

This MIP does not add a new `counter_type` under prefix `0x14`.

Requester-based queries MUST be served from the reverse index at prefix `0x1C`, not from a separate per-account counter family.

### 4. Authorization

#### 4.1 MERGE_REQUEST_ADD authorization

```text
authorize_merge_request_add(σ, data, body, signer) -> Ok | Err:
  check_key_scope(σ, data.owner_address, signer, SIGNING)

  let target = get_project_active(σ, body.project_id)
  if target.visibility == PRIVATE:
    check_project_access(σ, data.owner_address, body.project_id, READ)

  let source = get_project_not_removed(σ, body.source_project_id)
  if source.visibility == PRIVATE:
    if source.owner_address != data.owner_address:
      check_project_access(σ, data.owner_address, body.source_project_id, READ)

  require body.source_project_id != body.project_id
  require fork_lineage(body.source_project_id) reaches body.project_id within MAX_FORK_LINEAGE_DEPTH using retained 0x1A lineage rows
  require σ[ref_key(body.source_project_id, body.source_ref)].commit_hash == body.source_commit_hash
  require σ[commit_key(body.source_project_id, body.source_commit_hash)] != ⊥
  return Ok
```

Key authorization properties:

1. The requester does not need any permission on the target project if it is public.
2. The requester does need `READ+` access on the target project if it is private.
3. The requester does need `READ+` access on the source project if it is private and the requester is not the source owner.
4. Authorization is not scoped to target-project collaborators for public projects. Any registered key with `SIGNING` scope may open a merge request against a public project.

#### 4.2 MERGE_REQUEST_REMOVE authorization

```text
authorize_merge_request_remove(σ, data, signer, body, mr) -> Ok | Err:
  check_key_scope(σ, data.owner_address, signer, SIGNING)

  // Path 1: requester withdrawal
  // This path is allowed even if the target project is Removed,
  // provided the active merge-request row still exists.
  if data.owner_address == mr.requester_owner_address:
    return Ok

  // Path 2: target project owner or collaborator with WRITE+
  // Maintainer closure still requires a target project that is not Removed.
  let target = get_project_not_removed(σ, body.project_id)
  if target.owner_address == data.owner_address:
    return Ok

  let collab = σ[collaborator_key(body.project_id, data.owner_address)]
  require collab != ⊥ and collab.permission >= WRITE
  return Ok
```

Key authorization properties:

1. This is the first message type with a dual authorization path.
2. The original requester MAY withdraw their merge request without any permission on the target project, including when the target project has become `Removed`, provided the active merge-request row still exists.
3. A target project owner or collaborator with `WRITE+` permission MAY close any merge request targeting that project only while the target project is not `Removed`.
4. The target project MAY be `Active` or `Archived` for maintainer closure.

### 5. State Transitions

#### 5.1 MERGE_REQUEST_ADD execution

```text
handle_merge_request_add(σ, msg, data, body, signer) -> σ':
  authorize_merge_request_add(σ, data, body, signer)

  let request_id = msg.hash
  let forward_key = merge_request_key(body.project_id, request_id)
  let reverse_key = merge_request_reverse_key(data.owner_address, body.project_id, request_id)
  let existing = σ[forward_key]
  let tombstone_ts = σ[tombstone_key(forward_key)]
  let prune_marker_ts = σ[prune_marker_key(forward_key)]
  let effective_tomb = max(tombstone_ts, prune_marker_ts)

  if effective_tomb != ⊥ and data.timestamp <= effective_tomb:
    return σ

  if existing != ⊥ and data.timestamp < existing.added_at:
    return σ

  let project = get_project_active(σ, body.project_id)

  // Layer 1: Requester global active-entry quota (reject-on-exceed)
  sweep_expired_storage_grants(σ, data.owner_address, data.timestamp)
  let requester_limit = max_merge_requests_per_requester(active_storage_units(data.owner_address))
  let requester_active = count_requester_active_merge_requests(σ, data.owner_address)
  require requester_active + 1 <= requester_limit

  // Layer 2: Target-project namespace ceiling (auto-prune, project-local)
  sweep_expired_storage_grants(σ, project.owner_address, data.timestamp)
  let project_limit = max_merge_requests_per_project(active_storage_units(project.owner_address))
  enforce_project_merge_request_ceiling(σ, body.project_id, project.owner_address, project_limit, pending_adds=1)

  let mr = MergeRequestState {
    requester_owner_address: data.owner_address,
    source_project_id:       body.source_project_id,
    source_ref:              body.source_ref,
    source_commit_hash:      body.source_commit_hash,
    target_ref:              body.target_ref,
    title:                   body.title,
    added_at:                data.timestamp,
  }

  σ[forward_key] <- mr
  σ[reverse_key] <- mr

  if existing == ⊥:
    σ[project_key(body.project_id)].merge_request_count++

  return σ'
```

#### 5.2 MERGE_REQUEST_REMOVE execution

```text
handle_merge_request_remove(σ, data, body, signer) -> σ':
  let forward_key = merge_request_key(body.project_id, body.request_id)
  let mr = σ[forward_key]
  require mr != ⊥

  authorize_merge_request_remove(σ, data, signer, body, mr)

  let tombstone_key = tombstone_key(forward_key)
  let tombstone_ts = σ[tombstone_key]
  let should_record_tombstone = NOT (tombstone_ts != ⊥ and data.timestamp <= tombstone_ts)
  let should_delete_active = data.timestamp >= mr.added_at

  if should_record_tombstone and should_delete_active:
    σ[tombstone_key] <- data.timestamp
    delete σ[forward_key]
    delete σ[merge_request_reverse_key(mr.requester_owner_address, body.project_id, body.request_id)]
    σ[project_key(body.project_id)].merge_request_count--
    return σ'

  if should_record_tombstone and not should_delete_active and tombstone_ts != ⊥:
    σ[tombstone_key] <- data.timestamp
    return σ'

  return σ
```

#### 5.3 Content-addressed identity

`request_id` is content-addressed and derived from the `MERGE_REQUEST_ADD` message hash. Because `MessageData` includes `owner_address`, `timestamp`, and `network`, two `MERGE_REQUEST_ADD` messages with identical body fields but different timestamps produce different `request_id` values.

Consequences:

1. The same requester MAY open multiple merge requests against the same target project.
2. Re-opening a closed merge request requires a fresh `MERGE_REQUEST_ADD` and therefore a new `request_id`.
3. A duplicate submission of the exact same `MERGE_REQUEST_ADD` produces the same `request_id` and follows normal 2P add resolution for that identity.

#### 5.4 Block execution classification

`MERGE_REQUEST_ADD` and `MERGE_REQUEST_REMOVE` are project messages (Phase 2), grouped by target `project_id`.

Required justification:

1. Merge request state is stored under the target project's namespace.
2. Layer 2 pruning and active merge-request state remain target-project-scoped, preserving project-local mutation boundaries.
3. `MERGE_REQUEST_ADD` introduces requester-global Layer 1 quota checks, so adds by the same requester against different target projects are no longer fully independent for scheduling purposes.
4. Merge requests targeting the same project MUST serialize for 2P-set consistency.
5. Phase 2 project grouping remains the chosen classification, but implementations MUST preserve the canonical serial execution order because requester-global Layer 1 quota introduces cross-project admission dependencies.

### 6. Validation

#### 6.1 Structural validation (stateless)

`MERGE_REQUEST_ADD`:

| Field | Constraint |
|-------|-----------|
| `project_id` | 32 bytes |
| `source_project_id` | 32 bytes, MUST NOT equal `project_id` |
| `source_ref` | 1-254 bytes, no `0x00` bytes |
| `source_commit_hash` | 32 bytes |
| `target_ref` | 1-254 bytes, no `0x00` bytes |
| `title` | 1-200 UTF-8 bytes |

`MERGE_REQUEST_REMOVE`:

| Field | Constraint |
|-------|-----------|
| `project_id` | 32 bytes |
| `request_id` | 32 bytes |

#### 6.2 Stateful validation

`MERGE_REQUEST_ADD`:

1. Target project MUST exist and be `Active`.
2. Source project MUST exist and be not `Removed`.
3. `source_project_id` MUST NOT equal `project_id`.
4. The source project's retained fork-lineage chain under prefix `0x1A` MUST reach the target `project_id` within at most `MAX_FORK_LINEAGE_DEPTH = 256` hops.
5. Validation MUST fail if fork-lineage traversal terminates before reaching the target, encounters a cycle, encounters a missing retained intermediate ancestor, or would exceed `MAX_FORK_LINEAGE_DEPTH`.
6. If the source project is private, `data.owner_address` MUST be the source owner or a collaborator with `READ+` permission.
7. If the target project is private, `data.owner_address` MUST be the target owner or a collaborator with `READ+` permission.
8. `source_ref` MUST exist in the source project and MUST resolve exactly to `source_commit_hash` at execution time.
9. `source_commit_hash` MUST exist as a commit in the source project.
10. `MERGE_REQUEST_ADD` MUST satisfy both quota layers after expired grant sweeping with one pending add reserved: (a) the requester's global active-entry limit (reject-on-exceed), and (b) the target project's namespace ceiling (project-local active-plus-tombstone enforcement).

`MERGE_REQUEST_REMOVE`:

1. The merge request identified by `(project_id, request_id)` MUST exist as an active entry.
2. If the remover is the original requester, closure is allowed regardless of whether the target project is `Active`, `Archived`, or `Removed`, provided the active merge-request row still exists.
3. If the remover is not the original requester, the target project MUST be not `Removed`; `Archived` is allowed.
4. Authorization MUST satisfy either requester withdrawal or target-project `WRITE+` maintainer closure.
5. The source project's status is not checked — the source project may have been removed or archived between `MERGE_REQUEST_ADD` and `MERGE_REQUEST_REMOVE` without preventing closure.

### 7. Storage Limits and Pruning

#### 7.1 Effective limit

A new row is added to the effective limits table:

| Resource | Effective Limit |
|----------|-----------------|
| Merge requests per requester (global, active entries only) | `20 + requester_storage_units × 20` |
| Merge requests per target project (active + tombstones, namespace ceiling) | `20 + target_owner_storage_units × 20` |

`requester_storage_units` is the active storage capacity of the requester's account after expired grant sweeping.

`target_owner_storage_units` is the active storage capacity of the target project's canonical owner after expired grant sweeping. This value determines the namespace ceiling for the target project but does not consume the owner's storage budget.

#### 7.2 Storage-sensitive classification

`MERGE_REQUEST_ADD` and `MERGE_REQUEST_REMOVE` are added to the storage-sensitive message type list.

#### 7.3 Quota enforcement

Merge request quota is enforced in two independent layers during `MERGE_REQUEST_ADD` execution:

**Layer 1: Requester global active-entry quota (reject-on-exceed)**

`count_requester_active_merge_requests()` enumerates the requester's active merge requests globally:

1. Scan the reverse index prefix `[0x1C | requester_owner_address]`.
2. For each reverse entry at `[0x1C | requester | project_id | request_id]`, check whether the corresponding forward entry at `[0x1B | project_id | request_id]` exists.
3. Count only entries where the forward row exists. Entries where the forward row has been deleted (by `MERGE_REQUEST_REMOVE` or quota pruning) are not counted.
4. Return the count of active entries.

This count is compared against `max_merge_requests_per_requester(requester_units)`. If `active_count + 1 > limit`, the `MERGE_REQUEST_ADD` is rejected. The requester must close an existing merge request before opening a new one.

The requester can free Layer 1 capacity through the withdrawal path in `MERGE_REQUEST_REMOVE` authorization (comparing `owner_address` with `mr.requester_owner_address`), which requires no target-project membership or permission and remains available even if the target project has become `Removed`, provided the active merge-request row still exists.

**Layer 2: Target-project namespace ceiling (auto-prune, project-local)**

`enforce_project_merge_request_ceiling()` follows the existing tombstone-backed pruning model, scoped to the target project only:

1. Enumerate all active merge requests under `[0x1B | project_id]`.
2. Enumerate all merge-request tombstones under `[0x03 | 0x1B | project_id | ...]`.
3. Construct the counted set as `active entries + tombstones`.
4. Order entries by timestamp ascending, then by active-key lexicographic order.
5. Evaluate quota against `entries.len() + pending_adds`.
6. If `entries.len() + pending_adds <= limit`, return `Ok(())`.
7. Otherwise, prune the oldest entry by writing a prune marker and deleting the corresponding active row and reverse row if they still exist.
8. Repeat pruning until `entries.len() + pending_adds <= limit`.
9. If an active entry is pruned, decrement `ProjectState.merge_request_count`.

Required semantics:

1. **Layer 1 counts only active entries** (via the reverse index). Tombstones are not visible through the reverse index because reverse rows are deleted on close/prune, so tombstones do not count against the requester's quota.
2. **Layer 2 counts active entries + tombstones** (via the target project's active forward prefix `[0x1B | project_id]` plus tombstones under `[0x03 | 0x1B | project_id | ...]`). This bounds the total namespace footprint under the target project, including residual tombstone state.
3. **Layer 1 is enforced first.** If the requester is over their global limit, the add is rejected before any project-local pruning occurs.
4. **Layer 2 auto-pruning is project-local.** It only deletes entries within the target project's namespace, preserving project isolation.
5. `MERGE_REQUEST_ADD` MUST invoke both layers before writing the new active row.
6. Delete-on-prune MUST remove the matching requester reverse row whenever an active forward row is pruned.
7. Prune markers follow the same subsumption rules as existing 2P set types.

#### 7.4 Quota enforcement during add

`MERGE_REQUEST_ADD` sweeps expired storage grants for both the requester's account (Layer 1) and the target project's owner (Layer 2) before reserving quota capacity and writing the new active row. The requester funds their own capacity globally. The target project's namespace ceiling uses the owner's storage units as a scaling parameter but does not consume the owner's storage budget.

### 8. Proof Surface

Public proof exposure for merge requests is enabled in this specification. Implementations MUST update the explicit proof allowlists; it is not sufficient to rely on prefix-range expansion alone.

Required public-proof semantics:

1. `GetOperationProof([0x1B | project_id | request_id])` proves that a merge request exists at the queried root and authenticates its `MergeRequestState` value.
2. `GetExclusionProof([0x1B | project_id | request_id])` proves that a merge request does not exist at the queried root.
3. `GetCompoundProof([0x1B | project_id | request_id])` proves the full 2P-set state for that identity: active row, tombstone row, and prune marker row against a single root.
4. Merge-request active keys MUST be added to the public compound-proof allowlist.
5. Retained fork-lineage rows under prefix `0x1A` are not part of the public proof surface.

### 9. API Surface

Merge request queries are public, including for projects whose `visibility` is `PRIVATE`. This follows Makechain's read model, where `PRIVATE` does not generally gate canonical state reads and is presently enforced only on specific mutation flows such as `FORK`.

#### 9.1 gRPC queries

New RPCs:

| RPC | Description |
|-----|-------------|
| `GetMergeRequest` | Get a single merge request by `(project_id, request_id)` |
| `ListMergeRequests` | List merge requests for a project, with cursor-based pagination and optional requester owner-address filter |
| `ListMergeRequestsByRequester` | List merge requests opened by a specific `owner_address`, with cursor-based pagination |

All queries use the existing pagination pattern (`cursor + limit`, max 200 items per page).

Canonical protobuf request/response messages:

```protobuf
message GetMergeRequestRequest {
  bytes project_id = 1;   // 32 bytes
  bytes request_id = 2;   // 32 bytes
}

message GetMergeRequestResponse {
  MergeRequestSummary merge_request = 1;
}

message ListMergeRequestsRequest {
  bytes project_id = 1;                // 32 bytes
  uint32 limit = 2;
  bytes cursor = 3;                    // Opaque pagination cursor
  bytes requester_owner_address = 4;   // Optional 20-byte owner address filter
}

message ListMergeRequestsResponse {
  repeated MergeRequestSummary merge_requests = 1;
  bytes next_cursor = 2;
}

message ListMergeRequestsByRequesterRequest {
  bytes owner_address = 1;             // 20-byte requester owner address
  uint32 limit = 2;
  bytes cursor = 3;                    // Opaque pagination cursor
}

message ListMergeRequestsByRequesterResponse {
  repeated MergeRequestSummary merge_requests = 1;
  bytes next_cursor = 2;
}
```

#### 9.2 Query Semantics

All merge request listing queries (`ListMergeRequests`, `ListMergeRequestsByRequester`) return only active entries — entries whose forward key exists under prefix `0x1B` and that have not been tombstoned or pruned. A merge request that has been closed by `MERGE_REQUEST_REMOVE` or pruned during quota enforcement has its forward and reverse state entries deleted from canonical storage.

`GetMergeRequest` for a removed, pruned, or non-existent merge request MUST return `NOT_FOUND`.

Closure attribution is not available from canonical state. Clients that need to determine whether a merge request was closed, and by whom, MUST inspect finalized `MERGE_REQUEST_REMOVE` messages for that `(project_id, request_id)` pair from block history (see INV-14). This history lookup is necessarily block-range based on the existing message query surface.

#### 9.3 MergeRequestSummary

```protobuf
message MergeRequestSummary {
  bytes request_id                = 1;
  bytes project_id                = 2;
  bytes requester_owner_address   = 3;
  bytes source_project_id         = 4;
  bytes source_ref                = 5;
  bytes source_commit_hash        = 6;
  bytes target_ref                = 7;
  string title                    = 8;
  uint32 added_at                 = 9;
}
```

#### 9.4 REST gateway endpoints

Add routes:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/projects/{projectId}/merge-requests` | List merge requests for a project |
| GET | `/projects/{projectId}/merge-requests/{requestId}` | Get a specific merge request |
| GET | `/accounts/{ownerAddress}/merge-requests` | List merge requests opened by an account |

#### 9.5 Generic message surfaces

All generic message surfaces keyed by `MessageType` MUST recognize `MERGE_REQUEST_ADD` and `MERGE_REQUEST_REMOVE`, including:

1. `ListMessages`
2. `GetProjectActivity`
3. `GetAccountActivity`
4. `SubscribeMessages`
5. mempool type breakdowns
6. generic message filtering in CLI, gateway, and other transport surfaces

For project-filtered generic surfaces, both merge-request message types are associated with the target `project_id`.

### 10. Message Dispatch

Add to the message-dispatch table:

| Message Type | Resolution | Keys Written |
|---|---|---|
| `MERGE_REQUEST_ADD` | 2P add (content-addressed) | `merge_request(project_id, request_id)`, `merge_request_reverse(owner_address, project_id, request_id)`, `project(project_id)` [merge_request_count++] |
| `MERGE_REQUEST_REMOVE` | 2P remove | deletes `merge_request(project_id, request_id)`, deletes `merge_request_reverse(owner_address, project_id, request_id)`, writes `tombstone(merge_request(...))`, `project(project_id)` [merge_request_count--] |

### 11. Correctness Invariants

#### INV-12: Merge Request Count Consistency

For each project, `project.merge_request_count` MUST equal the count of active merge request entries under `[0x1B | project_id]`. Handlers MUST maintain counter accuracy across add, remove, and prune operations.

#### INV-13: Merge Request Reverse Index Consistency

For every forward entry `[0x1B | project_id:32 | request_id:32]`, the corresponding reverse entry `[0x1C | requester_owner_address:20 | project_id:32 | request_id:32]` MUST exist, and vice versa. Handlers MUST atomically maintain both forward and reverse entries. This invariant also applies during target-project subtree deletion and pruning: deleting a merge-request forward row MUST delete its matching reverse row, and deleting a project's merge-request family MUST also delete the family's tombstones and prune markers.

#### INV-14: Merge Request Closure Attribution by History

Closure actor attribution is derived from finalized message history, not from canonical merge-request state. Closed merge requests have no forward or reverse entry in canonical state — they return `NOT_FOUND` from queries. A client that wants to label a merge request as "withdrawn by requester" or "closed by maintainer" MUST inspect the closing `MERGE_REQUEST_REMOVE` message and compare its `owner_address` with the original requester's `owner_address`.

#### Content-addressed uniqueness

A merge request identity is `request_id = Message.hash`. Re-opening a closed merge request therefore requires a new `MERGE_REQUEST_ADD` and a new `request_id`.

#### Cross-project reference integrity

`MERGE_REQUEST_ADD` validates that the source project is in the target's retained fork lineage under prefix `0x1A` within `MAX_FORK_LINEAGE_DEPTH = 256` hops and that `source_ref` resolves exactly to `source_commit_hash` at execution time. If either project is later removed, or if the source ref later moves, stored references become historical snapshots and clients MUST handle those references gracefully.

### 12. Rationale

This proposal adds a minimal protocol-level primitive for cross-project contribution proposals while following existing tombstone-backed and project-scoped Makechain patterns.

Why a tombstone-backed 2P set:

1. A merge request has an open/closed lifecycle that maps naturally to add/remove semantics.
2. Existing V2 quota and prune-marker machinery already fits this pattern.
3. It avoids inventing a new bespoke state machine.

Why content-addressed identity:

1. Merge requests have no natural stable tuple that should limit a requester to one open request per project.
2. A requester should be able to open multiple concurrent requests against the same project.
3. Content-addressed identity matches Makechain's existing content-addressed object patterns.

Why restrict the source project to the target's fork lineage:

1. The primary use case is contributing changes back from a fork to an upstream project.
2. Requiring fork ancestry prevents arbitrary unrelated projects from being presented as merge candidates.
3. Transitive lineage supports stacked forks without requiring every merge request to come from a direct child fork.
4. Retaining immediate fork-parent pointers under prefix `0x1A` preserves merge-request lineage validation even when removed ancestor project rows are later pruned.

Why require `source_ref` to resolve exactly to `source_commit_hash`:

1. It prevents misleading branch labels from pointing at unrelated commits.
2. It gives clients a simple and consistent interpretation: the merge request proposes the current tip of a named source ref.
3. It keeps `source_commit_hash` authoritative while preserving a human-meaningful branch/ref label.

Why no protocol-level merged or rejected state:

1. Whether a request was merged or rejected is application-layer semantics.
2. That outcome can be inferred by inspecting later `COMMIT_BUNDLE`, `REF_UPDATE`, and `MERGE_REQUEST_REMOVE` history.
3. This preserves Makechain's thin-consensus model.

Why no `closed_by` in canonical state:

1. Finalized message history already gives closure attribution.
2. Adding `closed_by` to canonical state would require either a non-generic tombstone payload or an extra state family just for merge requests.
3. That extra complexity is not justified for the initial primitive.

Why public queries even for private projects:

1. Makechain semantics do not generally gate canonical reads by visibility.
2. Visibility affects mutation authorization, especially `FORK`, rather than public query surfaces.
3. Public discoverability is part of the value of a protocol-level merge-request primitive.

Why requester-funded global quota with a target-project namespace ceiling:

1. Merge requests are initiated by the requester. Charging the requester's active-entry capacity aligns cost with action and eliminates the target-owner-budget griefing vector for public projects.
2. A global per-requester limit prevents spray attacks: opening requests against many projects still consumes the same pool.
3. The reverse index at prefix `0x1C` already groups merge requests by requester, making global per-requester counting efficient without adding new state families.
4. The target-project namespace ceiling (`20 + target_owner_units × 20`) bounds total state growth under any single project. It uses the owner's storage units as a scaling parameter but does not consume the owner's budget — it is a ceiling, not a charge.
5. The target project's `merge_request_count` counter is maintained unchanged, preserving the ability to query how many active merge requests a project has.
6. This removes the target-owner-budget rationale for a protocol-level inbound-merge-request disable flag. Project-level opt-out remains out of scope; clients that wish to ignore merge requests can filter at the application layer, and Layer 2 bounds residual target-local namespace pressure.

### 13. Reset Assumption

This MIP is specified for a clean-slate network reset. Implementations do not need migration logic, hardfork gating, activation backfills, or backward-compatible deserialization for pre-MIP 5 project rows.

### 14. Rejected Alternatives

#### Application-layer merge requests only

Rejected because it removes onchain discoverability and verifiability.

#### Requiring `WRITE` permission on the target project to open a merge request

Rejected because it defeats the purpose of permissionless contribution proposals.

#### Keying merge requests by `(requester_owner_address, project_id)`

Rejected because it would limit each requester to one open merge request per project.

#### Adding `merged`, `rejected`, or `closed_by` to canonical state in the initial version

Rejected because finalized history already provides attribution, while extra canonical state would introduce merge-request-specific complexity that existing Makechain patterns do not need.

#### Allowing merge requests from arbitrary unrelated projects

Rejected because this proposal is intended to represent fork-to-upstream contribution flows, not arbitrary cross-project references.

#### Treating `source_ref` as advisory-only metadata

Rejected because an unbound branch label can misrepresent which source commit is actually being proposed.

### 15. Security Considerations

This proposal introduces a new project-scoped namespace that can be populated by any registered `SIGNING` key against public projects.

Spam resistance:

1. Opening merge requests requires a registered delegated key with `SIGNING` scope.
2. The per-requester global active-entry quota bounds how many merge requests a single account can have open across all projects, preventing one account from flooding any single project or spraying across many projects.
3. The per-target-project namespace ceiling bounds total state growth (active + tombstones) under any single project, preventing unbounded accumulation even when many requesters target the same project.
4. Fork-lineage validation is bounded to `MAX_FORK_LINEAGE_DEPTH = 256` hops, capping per-message ancestry traversal and preventing adversarial deep-fork-chain execution costs.
5. Retained fork-lineage rows preserve ancestry validation across project pruning so merge-request eligibility does not depend on long-term retention of removed project rows.

Authorization security:

1. `MERGE_REQUEST_ADD` intentionally does not require target-project membership for public targets.
2. `MERGE_REQUEST_REMOVE` explicitly allows two closure paths: requester withdrawal and maintainer closure.
3. A malicious maintainer may close another user's merge request, but that is a target-project governance decision and the requester may open a fresh request.

Cross-project reference stability:

1. Merge requests reference `source_project_id` and `source_commit_hash` that are validated at execution time.
2. `source_project_id` is restricted to the target project's fork lineage within `MAX_FORK_LINEAGE_DEPTH = 256` hops, and `source_ref` must resolve exactly to `source_commit_hash` when the merge request is opened.
3. Those references may later become historical if the source project is removed, the source ref later moves, or commits are pruned.
4. Clients must handle historical references gracefully.

Content-addressed identity:

1. `request_id = H(canonical_encode(MessageData))` inherits BLAKE3 collision resistance assumptions.
2. Updated proposals naturally receive new identities when their timestamps differ.

### 16. Acceptance Criteria

This MIP is considered specified when all of the following are true:

1. `MERGE_REQUEST_ADD` and `MERGE_REQUEST_REMOVE` carry canonical wire definitions at enum values `84` and `85` with oneof field numbers `96` and `97`.
2. The proposal uses address-native semantics throughout and does not depend on MID.
3. `MergeRequestAddBody` validates `project_id` (32 bytes), `source_project_id` (32 bytes, not equal to `project_id`), `source_ref` (1-254 bytes, no null bytes), `source_commit_hash` (32 bytes), `target_ref` (1-254 bytes, no null bytes), and `title` (1-200 UTF-8 bytes).
4. `MergeRequestRemoveBody` validates `project_id` (32 bytes) and `request_id` (32 bytes).
5. `MERGE_REQUEST_ADD` requires `SIGNING` scope, with no membership requirement for public targets, `READ+` for private targets, and `READ+` for private source projects unless the requester is the source owner.
6. `MERGE_REQUEST_REMOVE` has dual authorization: requester withdrawal or target-project owner/collaborator with `WRITE+` permission. Requester withdrawal remains valid even if the target project has become `Removed`, provided the active merge-request row still exists. Maintainer closure still requires a target project that is not `Removed`, and `Archived` targets remain closable.
7. Merge request identity is content-addressed as `request_id = Message.hash`.
8. `MERGE_REQUEST_ADD` requires `source_project_id` to be in the target project's retained fork lineage within `MAX_FORK_LINEAGE_DEPTH = 256` hops, and validation fails if traversal terminates early, encounters a cycle, encounters a missing retained intermediate ancestor, or would exceed that bound.
9. Immediate fork ancestry is stored under retained prefix `0x1A`, written by `FORK`, and preserved across project removal and project-subtree pruning.
10. Merge request state is stored at prefix `0x1B` with reverse index at prefix `0x1C` keyed by requester owner address.
11. `ProjectState.merge_request_count` is incremented on add and decremented on remove or active-entry prune, and is serialized as part of canonical `ProjectState` values.
12. `MERGE_REQUEST_ADD` and `MERGE_REQUEST_REMOVE` are classified as Phase 2 project messages grouped by target `project_id`.
13. Storage-limit enforcement uses two independent layers: (a) a requester global active-entry quota with formula `max_merge_requests_per_requester(units) = 20 + requester_units × 20`, enforced by reject-on-exceed with counting via the reverse index at `[0x1C | requester_owner_address]`; and (b) a target-project namespace ceiling with formula `max_merge_requests_per_project(units) = 20 + target_owner_units × 20`, enforced by project-local auto-pruning with active-plus-tombstone counting under `[0x1B | project_id]`, prune-marker semantics, matching reverse-row deletion on active prune, and pending-add reservation. Layer 1 is enforced before Layer 2.
14. Both message types are listed as storage-sensitive.
15. Public operation, exclusion, and compound proofs support merge-request active keys, while retained fork-lineage rows under `0x1A` remain off the public proof surface.
16. gRPC queries have canonical protobuf request/response definitions for `GetMergeRequest`, `ListMergeRequests`, and `ListMergeRequestsByRequester`, including pagination cursors and the optional requester owner-address filter on `ListMergeRequests`.
17. Generic message surfaces, including `ListMessages`, `GetProjectActivity`, `GetAccountActivity`, `SubscribeMessages`, and mempool type breakdowns, recognize `MERGE_REQUEST_ADD` and `MERGE_REQUEST_REMOVE`.
18. gRPC queries and REST gateway endpoints expose public merge-request listing and retrieval, returning only active entries. Removed or pruned merge requests return `NOT_FOUND` from `GetMergeRequest`.
19. `MERGE_REQUEST_REMOVE` does not check source project status — closure proceeds even if the source project has been removed or archived since the merge request was opened.

### 17. Implementation Notes

New files:

| File | Purpose |
|------|---------|
| `crates/makechain-state/src/handlers/merge_requests.rs` | Handler for `MERGE_REQUEST_ADD` and `MERGE_REQUEST_REMOVE` |

Modified files:

| File | Changes |
|------|---------|
| `proto/makechain.proto` | MessageType enum values, body messages, fresh-start oneof field numbers, and canonical merge-request query request/response types |
| `crates/makechain-state/src/keys.rs` | Prefixes `0x1A`, `0x1B`, and `0x1C`, key constructors, explicit queryable/merkleized/proof allowlist updates, and canonical prefix-range bound updates |
| `crates/makechain-state/src/values.rs` | `MergeRequestState` struct, retained fork-lineage value type for `0x1A`, and `ProjectState.merge_request_count` field |
| `crates/makechain-state/src/handlers/project.rs` | `FORK` writes retained `0x1A` fork-parent lineage rows |
| `crates/makechain-state/src/validation.rs` | Structural validation |
| `crates/makechain-state/src/authorization.rs` | Merge-request auth helpers, including requester withdrawal on removed targets and maintainer close on active/archived targets |
| `crates/makechain-state/src/storage_policy.rs` | `max_merge_requests_per_requester()`, `max_merge_requests_per_project()`, requester-global active-entry counting, target-project namespace-ceiling enforcement, merge-request prune-marker cleanup, target-project subtree cleanup of reverse rows, and preservation of retained `0x1A` lineage rows during project pruning |
| `crates/makechain-state/src/transition.rs` | Message dispatch and execution |
| `crates/makechain-state/src/handlers/mod.rs` | `pub mod merge_requests` |
| `crates/makechain-api/src/query.rs` | `get_merge_request()`, `list_merge_requests()`, `list_merge_requests_by_requester()`, and generic activity/list-message integration |
| `crates/makechain-api/src/service.rs` | gRPC handler methods and generic message-stream/filter integration |
| `apps/gateway/src/routes/` | `merge-requests.ts` route file and generic message-surface type recognition |

### 18. Resolved Decisions

This proposal's remaining design choices are resolved as follows:

1. `target_ref` remains required in the initial version.
2. Projects do not gain an inbound-merge-request disable flag in MIP 5. This removes the target-owner-budget rationale for such a flag, while Layer 2 continues to bound residual target-local namespace pressure.
3. Public proof exposure for merge-request active keys and compound proofs is enabled in the initial version.
4. MIP 5 is specified as baseline protocol behavior for a clean-slate reset, with no activation migration or hardfork gating.
5. `MergeRequestAddBody` and `MergeRequestRemoveBody` use fresh-start oneof field numbers `96` and `97`.

### 19. Copyright

Copyright and related rights waived via CC0.
