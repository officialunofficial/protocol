---
mip: 1
title: MIP Purpose and Process
description: Defines the Makechain Improvement Proposal process, document structure, and lifecycle.
author: Makechain contributors
discussions-to: https://github.com/officialunofficial/protocol/discussions
status: Draft
type: Meta
created: 2026-04-02
requires: null
---

## Abstract

This MIP defines the Makechain Improvement Proposal process.

MIPs are the primary mechanism for proposing protocol changes, documenting design rationale, and creating a durable decision record for Makechain. This MIP specifies the required structure, categories, statuses, numbering, and workflow for future MIPs.

## Motivation

Makechain needs a lightweight, durable process for evolving the protocol without mixing implementation detail, discussion, and specification text.

The process should be:

- simple enough to use early in the project
- structured enough to support long-lived protocol history
- familiar to contributors who have worked with EIPs and similar proposal systems

This MIP intentionally takes lightweight inspiration from the EIP process while remaining much smaller in scope.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### 1. What a MIP is for

A MIP is a design document that describes a proposed or accepted change related to Makechain.

A MIP MUST serve one or more of the following purposes:

- specify a protocol or interface change
- document a process or governance change
- record rationale for a material architectural decision
- provide a stable reference for implementation and review

A MIP is not a substitute for code, tests, or operational runbooks, but it MAY reference all of them.

### 2. MIP Types

Every MIP MUST declare a `type`.

Allowed types are:

- `Standards Track`
- `Meta`
- `Informational`

#### 2.1 Standards Track

Standards Track MIPs define normative changes to the Makechain protocol, network behavior, state model, APIs, wire formats, or other interoperability-critical surfaces.

Examples:

- block header changes
- proof format changes
- RPC additions that light clients depend on
- state-key schema changes

#### 2.2 Meta

Meta MIPs define process, workflow, governance, and repository conventions that affect how Makechain evolves but do not directly change protocol behavior.

Examples:

- the MIP process itself
- proposal lifecycle rules
- editor responsibilities

#### 2.3 Informational

Informational MIPs describe guidance, background material, or design analysis that is useful but not normative.

Informational MIPs do not define mandatory protocol behavior.

### 3. Statuses

Every MIP MUST declare a `status`.

Allowed statuses are:

- `Draft`
- `Review`
- `Last Call`
- `Final`
- `Stagnant`
- `Withdrawn`
- `Living`

#### 3.1 Draft

The MIP is being actively written and has not yet been accepted for broader review.

#### 3.2 Review

The MIP is complete enough for substantive technical review and is being evaluated for acceptance.

#### 3.3 Last Call

The MIP is believed to be stable and is awaiting final feedback before acceptance.

#### 3.4 Final

The MIP has been accepted as the canonical specification for its scope.

Standards Track MIPs SHOULD reach `Final` only when the specification is stable enough to implement or has already been implemented consistently with the document.

#### 3.5 Stagnant

The MIP has seen insufficient activity for a meaningful period and is not currently progressing.

Stagnant MIPs MAY return to `Draft` or `Review` if work resumes.

#### 3.6 Withdrawn

The MIP has been intentionally abandoned by its authors or maintainers.

Withdrawn MIPs remain part of the historical record.

#### 3.7 Living

The MIP is intended to remain continuously updated as the canonical source for an ongoing process.

This status SHOULD be used sparingly. Meta MIPs are the most likely candidates.

### 4. Numbering

MIPs MUST be numbered sequentially.

Rules:

- `MIP-0001` is reserved for this MIP
- lower numbers SHOULD be used for foundational or process-defining MIPs when introduced early
- a MIP number, once assigned, MUST NOT be reused
- withdrawn and superseded MIPs keep their original numbers

File naming convention:

```text
mips/MIP-XXXX-short-kebab-case-title.md
```

where `XXXX` is a zero-padded four-digit number.

### 5. Required Header

Each MIP MUST begin with YAML front matter.

Required fields:

```yaml
---
mip: <number>
title: <short title>
description: <one-sentence description>
author: <author or authors>
discussions-to: <URL>
status: <Draft|Review|Last Call|Final|Stagnant|Withdrawn|Living>
type: <Standards Track|Meta|Informational>
created: <YYYY-MM-DD>
requires: <null or list>
---
```

Field rules:

- `mip` MUST match the file number
- `title` SHOULD be short and specific
- `description` SHOULD be one sentence
- `discussions-to` SHOULD point to the main public discussion thread for the proposal
- `requires` SHOULD list dependent MIPs when relevant, otherwise `null`

Additional fields MAY be added later if the process needs them, but the required fields above define the base format.

### 6. Required Sections

Each MIP MUST contain the following sections, in order:

1. `Abstract`
2. `Motivation`
3. `Specification`
4. `Rationale`
5. `Backwards Compatibility`
6. `Security Considerations`

Recommended sections:

- `Reference Implementation`
- `Test Cases`
- `Copyright`

Meta MIPs MAY omit implementation-oriented material when it is not relevant.

### 7. Discussion and Submission Process

Before a MIP is marked ready for review, the idea SHOULD be discussed publicly.

Accepted discussion venues include:

- the `officialunofficial/protocol` discussions board
- a linked issue or proposal thread in the canonical protocol repository
- another public venue explicitly recognized by maintainers

Submission flow:

1. An author socializes the idea in public discussion.
2. The author drafts a MIP in the required format.
3. The draft is proposed in the canonical repository.
4. Maintainers review the draft for format, scope, and clarity.
5. The MIP is assigned or confirmed a number and tracked through status changes.

### 8. Editorial Responsibilities

Project maintainers act as MIP editors unless and until a separate editor role is established.

Editors are responsible for:

- checking format and naming compliance
- ensuring proposals are scoped clearly
- requesting missing rationale or compatibility analysis
- managing status transitions
- preserving historical records rather than rewriting them after acceptance

Editors are not required to agree with a proposal in order to accept it for review.

### 9. Status Transitions

Recommended transition flow:

```text
Draft -> Review -> Last Call -> Final
```

Alternative transitions:

- `Draft -> Withdrawn`
- `Review -> Withdrawn`
- `Draft -> Stagnant`
- `Review -> Stagnant`
- `Stagnant -> Draft`
- `Final -> Living` only if the document is intentionally converted into a continuously maintained process reference

### 10. Relationship to the Protocol Specification

The canonical protocol specification and the MIP set serve different roles.

- the protocol specification describes the current accepted protocol
- a MIP describes a proposed, pending, or historical change to that protocol

When a Standards Track MIP becomes `Final`, the canonical protocol specification SHOULD be updated to reflect it.

The MIP remains the rationale and proposal history record even after the main specification is updated.

### 11. Lightweight Scope

The MIP process is intentionally lightweight at this stage.

Specifically:

- no separate editor constitution is required yet
- no formal voting mechanism is defined by this MIP
- no mandatory repository automation is required yet

These may be introduced later by future Meta MIPs if the project needs them.

## Rationale

This process borrows the most useful parts of EIP-1 and the EIP template:

- a small standard header
- explicit proposal types
- explicit lifecycle statuses
- a durable numbered record

It intentionally omits heavier machinery that would create overhead before the project needs it.

The goal is to make it easy to write the right document at the right time, not to create a large governance framework up front.

## Backwards Compatibility

This MIP introduces the MIP process and does not change protocol behavior directly.

There are no protocol backwards compatibility concerns.

Repository compatibility impact is minimal:

- future proposal documents SHOULD use the MIP format defined here
- earlier ad hoc design notes MAY remain as historical documents but SHOULD NOT be treated as canonical MIPs

## Security Considerations

A weak proposal process can create ambiguity around what is canonical, reviewed, or accepted.

This MIP reduces that risk by:

- requiring explicit statuses
- separating proposed changes from accepted protocol text
- requiring rationale and compatibility analysis for normative changes
- preserving withdrawn and stagnant proposals as historical records

This MIP does not itself define trust or governance authority beyond normal maintainer control of the canonical repository.

## Reference Implementation

The reference implementation of this MIP is the `mips/` directory structure and document format used in the Makechain repository.

## Copyright

Copyright and related rights waived via CC0.
