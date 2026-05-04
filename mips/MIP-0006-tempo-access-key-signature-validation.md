---
mip: 6
title: Tempo Access Key Signature Validation
description: Extends Makechain's historical stateful signature validation surfaces to accept active Tempo Access Keys.
author: marthendalnunes <vitor@unofficial.run>
discussions-to: https://github.com/officialunofficial/protocol/discussions
status: Draft
type: Standards Track
created: 2026-05-04
requires: MIP-0003
---

## Abstract

This MIP adds Tempo Access Key signature validation as a new historical stateful signature family for the same Makechain protocol surfaces that already support ERC-1271.

It has four parts:

1. Add `key_type = 4` for Tempo Access Key signatures.
2. Apply the new key type only to existing ERC-1271-capable surfaces: `SIGNER_ADD` custody authorization, `SIGNER_REMOVE` custody authorization, `SIGNER_ADD` app attribution, and `VERIFICATION_ADD(ETH_ADDRESS)`.
3. Reuse the existing `*_block_hash` historical validation fields and `validationBlockHash` typed-data binding.
4. Verify access-key signatures by historical Tempo `eth_call` at the pinned block hash, using AccountKeychain state plus TIP-1020 primitive signature recovery.

This proposal intentionally does not change ordinary Makechain Ed25519 message envelopes, delegated-key lookup, key scopes, state keys, or message types.

## Motivation

Makechain already supports stateful historical signature validation through ERC-1271 for contract-wallet custody signatures, app-attribution signatures, and ETH address verification claims. These checks are pinned to a finalized Tempo block hash so validators and replaying nodes can evaluate the signature against the same historical Tempo state that the signer intended.

Tempo Access Keys provide a native account-level delegation model on Tempo. A root Tempo account can authorize secondary keys with expiry and optional restrictions. These keys can then sign on behalf of the root account in Tempo transactions.

Makechain should let users reuse active Tempo Access Keys for the same stateful signature-validation surfaces that already accept ERC-1271, without expanding the Makechain authorization model or introducing a new block-global Tempo dependency.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### 1. Scope

This MIP is a minimal additive change to Makechain's existing historical stateful signature-validation model.

Tempo Access Key signatures are valid only on the surfaces that already support ERC-1271:

| Surface | Field | Expected root account |
|---------|-------|-----------------------|
| `SIGNER_ADD` custody authorization | `custody_signature` with `custody_key_type = 4` | `MessageData.owner_address` |
| `SIGNER_REMOVE` custody authorization | `custody_signature` with `custody_key_type = 4` | `MessageData.owner_address` |
| `SIGNER_ADD` app attribution | `request_signature` with `request_key_type = 4` | `request_owner_address` |
| `VERIFICATION_ADD(ETH_ADDRESS)` | `claim_signature` with `claim_key_type = 4` | claimed `address` |

This MIP does not allow Tempo Access Keys to sign ordinary Makechain message envelopes. Ordinary authenticated user messages continue to require a valid Ed25519 envelope signature from a Makechain delegated key registered to `owner_address`.

### 2. Key Type

Makechain signature-family fields gain one new value:

| Value | Name | Meaning |
|-------|------|---------|
| `0` | secp256k1 | Direct ECDSA signature |
| `1` | P256 | Direct P256 ECDSA signature |
| `2` | WebAuthn P256 | WebAuthn-wrapped P256 signature |
| `3` | ERC-1271 | Contract-defined historical signature validation |
| `4` | Tempo Access Key | AccountKeychain-authorized access-key signature |

For `VERIFICATION_ADD`, `claim_key_type = 4` is valid only when `verification_type = ETH_ADDRESS`. `SOL_ADDRESS` remains Ed25519-only and MUST NOT use Tempo Access Key validation.

### 3. Wire Format

No new protobuf fields are required.

Existing historical-validation fields are reused:

- `VerificationAddBody.claim_block_hash`
- `SignerAddBody.custody_block_hash`
- `SignerAddBody.request_block_hash`
- `SignerRemoveBody.custody_block_hash`

For `key_type = 4`, the corresponding block-hash field MUST be present, MUST be exactly 32 bytes, and MUST identify a finalized canonical Tempo block on `host_chain_id(MessageData.network)`.

The Tempo Access Key signature format is:

```text
0x03 || root_account:20 || inner_signature
```

Where:

- `0x03` is Tempo's Keychain signature type prefix.
- `root_account` is the 20-byte Tempo account address on whose behalf the access key signs.
- `inner_signature` is a Tempo primitive signature accepted by TIP-1020: secp256k1, P256, or WebAuthn.

The expected `root_account` is defined per surface in Section 1. Validators MUST reject a signature whose embedded `root_account` differs from the expected root account.

### 4. Typed-Data Binding

Tempo Access Key validation reuses the same historical typed-data variants as ERC-1271.

For `SIGNER_ADD`, `SIGNER_REMOVE`, `SignerRequest`, and `VerificationClaim`, when the key type is `4`, the signed EIP-712 typed payload MUST include `bytes32 validationBlockHash` exactly as it does for `key_type = 3`.

The signed `validationBlockHash` value MUST equal the corresponding wire `*_block_hash` field.

This binding prevents validators from selecting a different historical Tempo state after the signature has been produced.

### 5. Historical Verification

Tempo Access Key verification is message-local external evidence. It MUST be evaluated against the finalized Tempo block identified by the corresponding `*_block_hash`.

Given `hash`, `signature`, `expected_root_account`, and `validation_block_hash`, validation is:

```text
verify_tempo_access_key(hash, signature, expected_root_account, validation_block_hash) -> Ok | Err:
  parse signature as 0x03 || root_account || inner_signature
  require root_account = expected_root_account
  require validation_block_hash identifies a finalized canonical Tempo block on host_chain_id(network)

  key_id = historical eth_call at validation_block_hash:
           TIP1020.recover(hash, inner_signature)

  key_info = historical eth_call at validation_block_hash:
             AccountKeychain.getKey(root_account, key_id)

  require key_info.keyId = key_id
  require key_info.isRevoked = false
  require validation_block_timestamp < key_info.expiry
  require key_info.signatureType matches inner_signature
  return Ok
```

All historical calls MUST be evaluated at the same `validation_block_hash`.

TIP-1020 rejects Keychain signatures directly, so validators MUST pass only `inner_signature` to TIP-1020. AccountKeychain state validation and primitive signature recovery are separate steps.

If the referenced Tempo block or required historical call result is unavailable to a replaying node, replay verification follows the existing tri-state external-evidence model and MAY return `NotYetVerifiable`. If evidence is available and contradictory, verification MUST fail closed as `Invalid`.

### 6. Access-Key Restrictions

MIP-6 accepts any active Tempo Access Key for the expected root account.

Validators MUST NOT evaluate AccountKeychain spending limits or call scopes for Makechain signature validation. Those restrictions are Tempo transaction-execution controls and are not part of the Makechain message being signed.

The only AccountKeychain state requirements for MIP-6 are active authorization, non-revocation, non-expiry at the validation block timestamp, and signature-type consistency.

### 7. Security Considerations

Accepting any active Tempo Access Key is intentionally minimal and mirrors the existing ERC-1271 surface area, but it has an important usability risk: a user may authorize an access key for a narrow Tempo application flow and not expect that key to also sign Makechain custody or verification payloads.

Clients SHOULD make this capability clear when creating or using access keys for Makechain. Applications SHOULD prefer short-lived, per-application access keys.

Once Tempo TIP-1049 is live and admin access-key semantics are available, this MIP SHOULD be updated to require Tempo Access Key signatures to come from active admin access keys only. Until then, MIP-6 intentionally accepts any active Tempo access key to mirror the existing ERC-1271 historical-validation model with the smallest possible protocol surface change.

### 8. Rationale

The proposal deliberately mirrors ERC-1271 rather than inventing a new Makechain-specific session-key model.

This keeps the change small:

- no new Makechain messages
- no new Makechain state keys
- no new ordinary message-envelope signature type
- no new block-global Tempo checkpoint
- no interpretation of Tempo spending limits or call scopes

The cost is that Makechain does not yet have a Makechain-specific access-key permission bit. TIP-1049 is the intended future path for tightening this behavior.

### 9. Backward Compatibility

This MIP is additive for the clean-slate protocol line.

Existing signatures with key types `0`, `1`, `2`, and `3` retain their current behavior. Messages using `key_type = 4` are invalid before MIP-6 activation and valid only under the rules defined here after activation.

### 10. Reference Constants

This MIP depends on the following Tempo precompiles:

| Name | Address |
|------|---------|
| `AccountKeychain` | `0xAAAAAAAA00000000000000000000000000000000` |
| `TIP1020 SignatureVerifier` | `0x5165300000000000000000000000000000000000` |

### 11. References

- Tempo Account Keychain precompile: https://docs.tempo.xyz/protocol/transactions/AccountKeychain
- TIP-1020 Signature Verification precompile: https://docs.tempo.xyz/protocol/tips/tip-1020
