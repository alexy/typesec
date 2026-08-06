# Marciana after Cognee Rust and Akka + Fluree

**Status:** dated implementation review and delivery record; active work moved
to the standalone Marciana project

**Reviewed:** 2026-08-05  
**Scope:** TypeSec Marciana, TypeDID, Cognee Rust, and the Akka SDK + Fluree
`semantic-memory` port

This document records the review requested on 2026-08-05 and the corrections
it motivated. It complements `MEMORY.md`, which owns TypeSec's Marciana
security contract and realized v1 record. This file is historical comparative
evidence, not the active roadmap. `MARCIANA-PROJECT.md` is the accepted
TypeSec-side handoff for extracting Marciana's product, cognition, and
composition tier into its initialized first-class sibling project in the
QueryGraph stack.

## Sources reviewed

- [Cognee Rust](https://github.com/topoteretes/cognee-rs), commit
  `d83b52b814228d0ac131d474f01e6ed1be369bab`.
- [Akka SDK + Fluree semantic-memory](https://github.com/TylerJewell/semantic-memory),
  commit `c6b242086fc9b9adead10cf3bd5577968222e139`.
- TypeSec `typesec-memory`, `typesec-integrations`, the Marciana specification
  in `MEMORY.md`, and the QueryGraph handoff described there.

The two external systems are useful for different reasons. Cognee Rust is the
broader cognition and retrieval implementation. The Akka port is a compact
experiment in durable orchestration, unified graph/vector/provenance storage,
and assertion conflict handling. Neither supplies Marciana's capability and
information-flow boundary; neither should be adopted as that boundary.

## Executive judgment

TypeSec's Marciana vault remains the authorization, information-flow, and
rehydration authority. The standalone Marciana project composes native memory
and cognition over TypeSec, Grust, Sail, and LakeCat. TypeDID carries
cryptographic identity, request binding, negotiated obligations, delegation,
and receipts across service boundaries. Cognee, Akka, and Fluree are
comparative design input only, not runtimes, stores, adapters, or compatibility
targets.

The load-bearing rule is:

> Cognition proposes, indexes rank, stores persist, TypeDID identifies, and
> only the capability-gated TypeSec vault reveals or mutates memory.

## Comparative review

### Cognee Rust

Cognee Rust is no longer merely a small edge proof. Its workspace includes
streaming ingestion, deterministic IDs, relational metadata, graph and vector
adapters, temporal extraction, multiple search strategies, session feedback,
memify/truth-subspace work, persistent pipeline-run state, observability, an
HTTP surface, and Rust/Python/TypeScript/Java/C bindings.

Marciana should borrow:

- streaming ingestion and deterministic content/chunk identity;
- explicit component registries and backend factories;
- hybrid lexical/vector/entity/fact/graph retrieval;
- temporal extraction and point-in-time retrieval;
- persistent job/task state, cancellation, retry, and progress;
- feedback-driven cognition and evaluation corpora;
- lifecycle and backend integration tests; and
- one shared wire contract across language bindings.

Marciana should not copy Cognee's authority model. Cognee's relational,
object/file, graph, and vector layers remain separate consistency domains.
Pipeline or deletion failures can require compensating cleanup. Its rich
retrieval surface is valuable, but ranking and extraction must not become an
authorization path.

### Akka SDK + Fluree semantic-memory

The Akka port demonstrates several attractive architectural ideas:

- resumable workflow steps around extraction and persistence;
- graph, vector, full-text, and provenance data in one immutable store;
- cryptographic Fluree commit hashes;
- authored and derived assertion layers;
- corroboration, disagreement, conflict, negation, and resurrection as
  explicit knowledge-lifecycle concepts; and
- a declarative conflict-resolution direction instead of silent
  last-write-wins.

Its current HTTP surface is a prototype, not a safe production boundary:

- the endpoint ACL admits the Internet;
- `/sync`, `/remember`, disagreements, and conflicts are unauthenticated;
- `/forget` invokes an unscoped `forgetAll`; and
- the public `/remember` path invokes extraction and Fluree synchronously,
  while the durable `RememberWorkflow` is a separate path.

The lesson is not to put Fluree directly on the trust boundary. The lesson is
to place a TypeDID-verified Marciana service that requests and validates
TypeSec capabilities in front of a durable workflow and Grust's guarded commit
boundary.

## Findings and implemented corrections

### 1. Every Marciana content path must bind request context

Before this review, ordinary recall received `RequestContext`, while graph
recall, semantic recall, and sensitive reveal used an empty default context.
That allowed a purpose-constrained policy to be checked without the caller's
purpose on alternate paths.

Implemented in commit `dcbf9b0`:

- `recall_neighborhood`, `recall_semantic`, and `reveal` now require
  `&RequestContext`;
- every path passes that context to use-time policy evaluation; and
- regression tests prove a purpose-restricted ODRL rule denies all alternate
  paths when the purpose is absent.

Follow-on rule: future retrieval APIs must reuse a single internal result
validator covering space, validity, quarantine, purpose, and clearance.

### 2. TypeDID negotiation must produce enforceable obligations

The original profile advertised required claims, policy actions, retention,
and audit posture, but compatibility considered only the profile identifier,
cryptography, DID methods, transport, and delivery mode. Wrapping enforced
only the local payload cap.

Implemented in commit `e31d7ee`:

- negotiation returns `NegotiatedTypeDidProfile` rather than a borrowed local
  profile;
- the effective payload cap is the strictest peer cap;
- required claims are the union of both peers' requirements;
- allowed actions are the peer intersection;
- conflicting explicit retention or audit postures are incompatible;
- `DidMessageBody` carries signed policy-visible claims; and
- wrapping rejects missing claims and unnegotiated actions.

Remaining work: replace free-form retention/audit strings with versioned,
typed obligation vocabularies and add deterministic preference ordering plus
downgrade protection when multiple profiles match.

### 3. Replay protection needs a shared durable authority

The old replay cache was owned by one gateway process and consumed an entry
immediately after signature verification, before authenticated decryption had
succeeded.

Implemented in commit `e31d7ee`:

- `ReplayStore` defines an atomic claim seam;
- gateways accept a shared replay authority;
- `InMemoryReplayStore` preserves local compatibility;
- multiple gateway instances sharing one authority reject the same replay;
- authority failure is represented as a fail-closed `DidError`; and
- the claim occurs only after successful authenticated decryption.

Not yet claimed as delivered: cross-restart or cross-replica durability. A
production QueryGraph deployment must implement `ReplayStore` over a shared,
strongly consistent Turso/libSQL or control-plane database. It must atomically
claim `(tenant, audience, signer DID, nonce)`, retain claims through expiry and
clock skew, enforce subject quotas, and distinguish replay protection from
mutation idempotency.

### 4. Semantic index maintenance needs repair, not warnings alone

Marciana correctly treats a semantic index as a ranking cache, but a committed
record followed by a failed index update could remain silently unsearchable by
semantic recall.

Implemented in commit `d039f9f`:

- `IndexMutation` describes id-only upsert/remove repair work;
- `IndexOutbox` is an injectable durable-outbox seam;
- `InMemoryIndexOutbox` supplies deterministic local behavior and coalesces
  operations per memory ID;
- failed post-commit index operations enqueue IDs, never plaintext; and
- authorized `MemoryVault::repair_index` rehydrates content inside the vault,
  retries the index, and acknowledges only successful repairs.

Production requirement: the backing store should commit record mutation and
outbox event atomically. A worker may lease and retry events, but plaintext
must never be serialized into the outbox.

### 5. External cognition must produce inert, versioned proposals

Cognee's extraction and retrieval breadth is desirable; direct write access is
not. Distributed or model-driven jobs must be stale-checkable and must not
bypass label joins or authorization.

Implemented in commit `d039f9f`:

- `CognitionProposal` records schema version, idempotent job ID, input
  snapshot, source digest, algorithm and model version, exact source IDs,
  worker-computed label join, drafts, consolidation plan, audit-safe evidence,
  and creation time; and
- proposals remain inert data with no store handle.

The trusted application service must still reauthorize the initiating
subject, confirm that source IDs and digest match the current snapshot,
recompute the label join, reject stale or revoked work, and apply mutations
through `MemoryVault`.

### 6. Governed rows need a vault-owned source binding

LakeCat-shaped provenance on a draft is not evidence that the exact durable
memory came from an authorized snapshot. TypeSec now owns a separate canonical
`GovernedSourceScope` and the only normal attachment path:

- `remember_governed` checks capability, space, and current policy before
  invoking a trusted verifier over bounded opaque evidence and the exact draft
  digest;
- `governed_source_draft_digest` lets Marciana build an exact authenticated
  staged-row allowlist without reimplementing TypeSec canonicalization;
- local cognition rejects scoped records, governed cognition rejects local,
  mixed, or differently scoped records before reveal and again on authoritative
  reload;
- bindings, fresh authority, proposals, preconditions, prepared commits,
  audits, signed receipts, and derived records retain the exact optional scope;
  and
- schema v1 remains no-scope only, preventing a scoped proposal from being
  downgraded by deleting its scope field.

Opaque provider evidence is never persisted. The trusted-store qualification
is explicit: private Rust fields stop ordinary API forgery, but a backend that
deserializes attacker-authored `StoredRecord` bytes must add record
authentication rather than treating serde visibility as a cryptographic
boundary.

## Target architecture

```text
Agent / framework
    |
    | signed TypeDID request
    v
TypeDID gateway
    - verify sender, recipient, audience, profile, claims, route/body
    - atomically claim replay nonce
    - map verified DID to tenant and policy subject
    |
    | verified attestation + encrypted payload
    v
Marciana application service
    - request/validate scoped TypeSec capability
    - bind purpose and clearance through RequestContext
    - assign idempotent operation id
    |
    +--> durable cognition workflow
    |      - Marciana-native worker reads authorized snapshot
    |      - emits inert CognitionProposal
    |      - no direct memory mutation
    |
    v
MemoryVault
    - reauthorize
    - verify snapshot/digest
    - recompute label joins
    - apply transactional store batch + index-outbox event
    |
    +--> Grust guarded commit and durable backend
    +--> semantic/hybrid index (ranking only)
    +--> audit log and signed TypeDID reply receipt
```

## Historical implementation program

The review originally organized the work as a live P0/P1/P2 checklist. That
checklist is now frozen into three durable conclusions instead of being
maintained as a second roadmap.

First, TypeSec owns and has implemented the security protocol: all
content-returning paths share one visibility gate; request context and current
policy reach alternate reads; TypeDID v2 signs the complete request envelope;
cognition receives a vault-authorized source bundle, produces an inert bound
proposal, and can mutate only through an opaque vault-prepared commit. A lost
commit reply can be recovered by exact job and proposal digest only after a
current capability and policy check, with fixed anti-oracle failures and no
proposal reconstruction or second mutation. Receipt validity starts at the
original trusted TypeSec preparation time, not the later backend commit time,
so recovery cannot mint a fresh lifetime after response loss.

Governed ingestion and cognition additionally carry an exact vault-verified
source scope from staged draft through derived records, authoritative reload,
audit evidence, and signed receipt; local and governed input paths cannot be
silently mixed.

Second, the QueryGraph stack owns reusable substrate rather than Marciana
product semantics. LakeCat issues governed snapshot and authorization evidence;
Grust supplies guarded graph commits and durable backends; Sail supplies generic
distributed compute; QueryGraph applications consume the product. Each owner
canonicalizes its own evidence once, and adapters translate without duplicating
policy, digest, transition, or recovery rules.

Third, the remaining product program moved to the standalone Marciana project:
the native `remember`, `recall`, `improve`, and `forget` service; durable worker
orchestration; memory-specific Grust, Sail, and LakeCat adapters; assertion
provenance and conflict semantics; cross-language wire fixtures; operations;
and compatibility releases. Cognee remains useful design input only. It is not
a runtime, storage layer, adapter dependency, API target, or definition of
completeness.

## Historical acceptance criteria

These criteria remain design input for Marciana's active compatibility and
integration gates; their current status is maintained in the standalone
project.

1. No Marciana content-returning path can omit request purpose or other
   contextual policy inputs.
2. A semantic/graph result can rank an ID but cannot reveal content or widen
   tenant, validity, quarantine, purpose, or clearance scope.
3. Failed index maintenance is durably observable and repairable without
   putting plaintext in an outbox.
4. Cognition worker loss produces no partial memory mutation.
5. A stale proposal, changed source digest, policy revocation, or unauthorized
   space causes proposal application to fail closed.
6. A TypeDID replay is rejected after restart and by another replica; two
   concurrent claims yield exactly one success.
7. Mutation retries cannot duplicate memory even after response loss or a
   crash between commit and reply.
8. Embedding-model identity is stored and mismatched vectors are rejected or
   rebuilt, never silently mixed.
9. Every derived artifact retains complete source lineage and the join of all
   source labels.
10. Destructive operations are tenant- and space-scoped, capability-gated,
    audited, and receipt-producing; no production `forgetAll` surface exists.

## Handoff status on 2026-08-05

TypeSec's governed-source ingestion binding, bound proposals, opaque prepared
commits, complete TypeDID v2 request binding, and policy-gated proposal-free
recovery are implemented. LakeCat owns
and persists the governed scan proof and original authorization evidence.
qg-rust contains the initial verified TypeDID/LakeCat composition slice, but it
remains a consumer and temporary integration edge rather than the owner of the
memory product.

Grust's generic live-Sail execution, durable job, ID-only outbox, guarded
commit, and read-only receipt-recovery substrate is being finalized in its
owning repository. It is not yet a Marciana release. The standalone
`~/src/marciana` checkout is initialized with its ownership and compatibility
rules, but `querygraph-memory` has not yet been transplanted and qg-rust has not
switched to it. A Sail correction for Delta `MERGE` non-null constraints exists
only as a local commit and is not a remotely reachable supported pin.

The active implementation sequence, compatibility matrix, and acceptance
status now belong exclusively to the standalone Marciana repository. This
historical review does not maintain a second execution checklist. Cognee,
Akka, and Fluree remain inspiration only and are absent from the runtime and
storage dependency graph.
