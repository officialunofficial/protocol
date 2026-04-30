---
mip: 3
title: Address-Native Identity
description: Defines owner_address as the canonical account identifier for the V2 protocol reset.
status: Accepted
type: Standards Track
created: 2026-04-21
---

# MIP-3: Address-Native Identity

## Summary

Makechain V2 uses `owner_address` as the sole canonical account identifier across messages, state, APIs, proofs, and clients. Account ownership is address-native from genesis of the reset network.

## Specification

Every protocol message carries a 20-byte `owner_address`. Account, project, collaborator, verification, link, reaction, signer, storage, and proof surfaces use that address directly.

Project ownership is recorded as `owner_address`. Project-name indexes use `(owner_address, name)`. Account queries, key queries, activity queries, quota proofs, social graph queries, and response summaries all select or expose accounts by `owner_address`.

Signer management is self-authenticating. `SIGNER_ADD` and `SIGNER_REMOVE` require EIP-712 custody authorization from the account owner address. App attribution uses `request_owner_address` when present.

Storage ingress is settlement-backed through `STORAGE_CLAIM`. Claims credit storage units to the message `owner_address` after settlement evidence verifies against the configured host chain.

## Wire Compatibility

Field numbers that are not part of the V2 schema remain reserved. Implementations must not reuse reserved tags for new identity semantics.

## Security Properties

- `owner_address` binds all account-scoped writes to a canonical account key.
- Custody signatures bind signer changes to network, owner address, target key, validity window, and nonce.
- External verification challenges bind claims to network and owner address.
- Replay protection remains scoped to owner address and the relevant protocol object.

## Rationale

The reset network starts from a single identity namespace. This keeps message validation, state keys, APIs, proofs, and client code aligned around one account selector.
