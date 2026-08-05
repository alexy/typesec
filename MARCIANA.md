# Marciana after Cognee Rust and Akka + Fluree

**Status:** implementation review, target architecture, and delivery record  
**Reviewed:** 2026-08-05  
**Scope:** TypeSec Marciana, TypeDID, Cognee Rust, and the Akka SDK + Fluree
`semantic-memory` port

This document records the review requested on 2026-08-05 and turns its useful
findings into a concrete Marciana and TypeDID program. It complements
`MEMORY.md`: `MEMORY.md` remains the canonical product design and QueryGraph
handoff; this file records the comparative review, the resulting corrections,
and the implementation boundary. `MARCIANA-PROJECT.md` records the proposed
extraction of Marciana's product, cognition, and composition tier into a
first-class sibling project in the QueryGraph stack.

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

Marciana should remain the authorization, information-flow, provenance, and
rehydration control plane. Cognee-class systems should plug in as untrusted
cognition and ranking engines. Fluree- or Grust-class systems should plug in as
transactional stores. TypeDID should carry cryptographic identity, request
binding, negotiated obligations, delegation, and receipts across service
boundaries.

The load-bearing rule is:

> Cognition proposes, indexes rank, stores persist, TypeDID identifies, and
> only the capability-gated Marciana vault reveals or mutates memory.

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
to place a TypeDID-verified, capability-minting Marciana gateway in front of a
durable workflow and unified transactional store.

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
    - mint/validate scoped capability
    - bind purpose and clearance through RequestContext
    - assign idempotent operation id
    |
    +--> durable cognition workflow
    |      - Cognee/LLM/extractor reads authorized snapshot
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
    +--> Grust/Fluree-class authoritative store
    +--> semantic/hybrid index (ranking only)
    +--> audit log and signed TypeDID reply receipt
```

## Marciana implementation program

### P0: security closure

- [x] Bind request context on graph recall.
- [x] Bind request context on semantic recall.
- [x] Bind request context on sensitive reveal.
- [x] Test purpose denial on alternate paths.
- [ ] Consolidate all record-returning paths behind one internal validator.
- [ ] Require context on consolidation, forget, reaping, and index repair when
  deployment policy uses contextual write/delete constraints.

### P0: TypeDID request proof

- [x] Make negotiated obligations explicit.
- [x] Enforce strictest payload limit.
- [x] Enforce required claims and action intersection.
- [x] Inject a shared replay authority.
- [x] Claim replay only after authenticated decryption.
- [ ] Define the domain-separated TypeDID HTTP v2 canonical payload covering
  version, sender/key, recipient, environment audience, tenant selection,
  method, canonical path/query, body digest, conversation, nonce/JTI,
  issued/expiry times, and optional idempotency key.
- [ ] Implement a durable QueryGraph `ReplayStore` and cross-restart,
  concurrent-claim, and cross-replica tests.
- [ ] Implement a separate mutation idempotency store and receipt recovery
  path; never advertise a claim-then-mutate sequence as exactly-once.

### P1: durable cognition and indexing

- [x] Define inert, versioned cognition proposals.
- [x] Define an id-only index repair outbox.
- [x] Retry repair through the vault rehydration boundary.
- [ ] Add proposal application that verifies source snapshot/digest and
  recomputes the label join before applying a plan.
- [ ] Add transactional store/outbox implementations in QueryGraph.
- [ ] Add durable job state, leases, cancellation, bounded retry, and
  idempotent application.
- [x] Define native Grust cognition contracts for deduplication and
  reconciliation, with a reference engine and an injectable Sail executor.
- [x] Bind cognition inputs to LakeCat snapshot, projection, subject, purpose,
  plan-token digest, and authorization-receipt digest evidence.
- [ ] Implement the live `grust-sail` cognition executor for extraction,
  temporal enrichment, entity resolution, summaries, communities, and hybrid
  candidate ranking. Cognee remains design inspiration only.

### P1: assertion provenance and conflict

- [ ] Add canonical assertion facets: subject, predicate, object, predicate
  cardinality, assertion layer, confidence, source digest, observed/valid
  times, and derivation lineage.
- [ ] Model corroborating evidence without duplicating the assertion.
- [ ] Preserve cross-layer disagreements and serve the policy winner while
  flagging the loser.
- [ ] Represent genuine no-winner authored conflicts as contested; never
  resolve an authored tie by recency.
- [ ] Keep retraction, deletion, negation, and re-extraction/resurrection as
  distinct operations.
- [ ] Feed every derived summary or assertion back through label join,
  quarantine, capability checks, and audit.

### P2: receipts and interoperability

- [ ] Define TypeDID actions `memory.remember`, `memory.recall`,
  `memory.reveal`, `memory.forget`, and `memory.consolidate`.
- [ ] Bind memory space, tenant, purpose, clearance ceiling, request digest,
  audience, nonce, expiry, and idempotency key into the signed request.
- [ ] Return reply-bound receipts containing operation ID, request/input
  digest, prior and resulting version, affected IDs, policy decision ID,
  backend commit hash, and deletion/consolidation evidence.
- [ ] Support attenuated delegation for one space, purpose, clearance, and
  time window.
- [ ] Publish Rust/Python/JavaScript canonicalization fixtures and malformed
  envelope corpora.

## Acceptance criteria

The program is complete only when all of the following hold:

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

## Delivery boundary

This repository now contains the security fixes and reusable seams listed as
implemented above. The cross-repository implementation uses Grust storage,
LakeCat catalog evidence, TypeSec governance, and QueryGraph composition; it
does not depend on Cognee or reproduce Cognee's store adapters. It does not yet
contain the live Sail cognition executor, hosted QueryGraph control database,
or durable proposal-application service. Durable replay, transactional
record-plus-outbox delivery, and Grust commit-backed receipts therefore remain
cross-repository work. They are requirements here, not falsely reported as
shipped behavior.

## QueryGraph-native implementation update

The first cross-repository implementation landed on 2026-08-05 without a
Cognee dependency:

- TypeSec defines the inert `CognitionProposal`, guarded vault, TypeDID
  obligations, and repairable index boundary.
- Grust `querygraph-memory` binds native cognition to LakeCat/Iceberg snapshot
  evidence and provides reference plus injectable Sail execution contracts.
- LakeCat exports a secret-free `GovernedScanProof` containing the authorized
  principal, purpose, snapshot, narrowed projection, and hashes—not plaintext
  copies—of the Sail plan token and authorization receipt.
- qg-rust converts that LakeCat proof into the Grust cognition source,
  cross-checks its subject and purpose against the verified TypeDID request,
  and receives an inert proposal for later vault application.

### Status at handoff

The governed vertical slice is implemented and verified:

- Grust owns cognition requests, governed LakeCat snapshot inputs, reference
  deduplication/reconciliation, and the `SailCognitionExecutor` boundary.
- LakeCat owns the secret-free governed scan proof.
- TypeSec owns verified identity and obligations, inert proposals, vault
  authorization, label joins, and index-repair seams.
- QueryGraph cross-checks the LakeCat subject and purpose against the verified
  TypeDID request before asking Grust to produce a proposal.
- Cognee is neither linked nor required; Grust remains the authoritative data
  substrate.

This slice has unit and integration coverage in its owning repositories, but
it stops before live distributed execution and durable mutation.

### Next execution goal: production cognition completion

The next goal is complete only when the following sequence works against a
running Sail service and an authoritative Grust store:

1. Implement a `grust-sail` `SailCognitionExecutor` that submits governed
   extraction, temporal enrichment, entity resolution, summarization,
   community, deduplication, reconciliation, and hybrid-ranking work.
2. Carry the LakeCat scan proof and verified TypeDID request through execution
   without exposing raw plan tokens, authorization receipts, or plaintext in
   queues and logs.
3. Persist proposal/job state with leases, bounded retry, cancellation, and
   idempotency; worker loss must not partially mutate memory.
4. Apply proposals only through the TypeSec vault after revalidating the
   source snapshot and digest, authorization, effective projection, and joined
   source labels.
5. Commit the memory mutation and ID-only index outbox atomically in Grust,
   then produce audit evidence and a commit-bound TypeDID receipt.
6. Add running-service tests for stale proposals, revoked authority, changed
   snapshots, cross-tenant or purpose mismatch, retry after response loss,
   worker failure, and outbox recovery.
7. Mark the corresponding program items complete only after the cross-repo
   test suite and strict lint checks pass.
