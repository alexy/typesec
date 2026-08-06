# TypeSec → Marciana project handoff

**Handoff date:** 2026-08-06  
**Source repository:** [querygraph/typesec](https://github.com/querygraph/typesec)  
**Destination repository:** [querygraph/marciana](https://github.com/querygraph/marciana)  
**Destination checkout:** ~/src/marciana (/Users/alexy/src/marciana)  
**Working branch:** firstpair, clean and pushed to origin/firstpair  
**Current head:** e366509 Publish Marciana 2 release post  
**Implementation head:** 5c4b146 Add Ossie semantic adapter and clarify Fluree boundary

This is the complete context handoff for continuing Marciana in its standalone
QueryGraph project. It records durable architectural decisions, implementation,
verified evidence, publication state, and next work. Active design authority
lives in the destination checkout.

## Start here after switching projects

~~~sh
cd ~/src/marciana
git status --short --branch
sed -n '1,260p' AGENTS.md
sed -n '1,260p' DESIGN.md
sed -n '1,220p' COMPATIBILITY.md
sed -n '1,220p' MARCIANA.md
sed -n '1,260p' MARCIANA2.md
sed -n '1,220p' README.md
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
~~~

Do not restart the extraction in TypeSec. TypeSec is the security and
information-flow authority; Marciana is the active memory and cognition
product.

## Decision and invariant

Marciana is a standalone QueryGraph-stack project: a reusable memory and
cognition composition layer above TypeSec, Grust, Sail, and LakeCat. It is not
another storage engine, policy engine, catalog, or compute engine.

The invariant is:

> Cognition proposes, indexes rank, stores persist, TypeDID identifies, and
> only the capability-gated TypeSec vault reveals or mutates protected memory.

Dependency direction:

~~~text
QueryGraph applications and agents
              |
              v
          Marciana
       /      |       \
      v       v        v
  TypeSec   Grust     Sail
              |
              v
           LakeCat
~~~

TypeSec, Grust, Sail, and LakeCat must not depend on Marciana. Shared
foundational capabilities belong upstream and are consumed through released or
exact remotely reachable revisions.

## Ownership

| Concern | Authority | Marciana relationship |
|---|---|---|
| TypeDID identity, signatures, replay, generic receipts | TypeSec | Consume verified identity/context; do not reimplement authority |
| Capabilities, policy, labels, clearance, retention, quarantine | TypeSec | Request and validate; never bypass MemoryVault |
| Protected-content reveal and mutation | TypeSec MemoryVault | Only vault paths may reveal or mutate protected memory |
| Generic graph, traversal, GQL/Cypher, guarded commits | Grust | Project records and use backend commit capabilities |
| Distributed Arrow/Spark execution | Sail / grust-sail | Supply memory-specific schemas and proposal jobs |
| Iceberg catalog and governed scan proofs | LakeCat | Consume proofs through the governed-source adapter |
| Four verbs, memory ledger, cognition jobs, receipts, recovery | Marciana | Own and version product behavior |
| Navigator, QGLake, governed answers, semantic registry | QueryGraph | Consume through thin integration |

Native lifecycle:

| Verb | Meaning | Rule |
|---|---|---|
| remember | Normalize and ingest source material | Durable writes enter a capability-gated vault operation |
| recall | Retrieve lexical, vector, entity, fact, graph, temporal, or completion candidates | Indexes return candidates/IDs; vault applies gates and rehydrates |
| improve | Cognition over an authorized immutable snapshot | Workers emit inert proposals; TypeSec reauthorizes before commit |
| forget | Scoped removal/retraction and retrieval cleanup | Tenant/space scoped, capability-gated, audited, transactional, receipted |

Cognee is inspiration only, not a runtime, store, API compatibility target, or
completeness dependency. Akka and Fluree are comparative input only. Fluree
means the semantic-ledger/query role in the reviewed Akka implementation; it is
not part of Marciana's runtime. Marciana puts TypeDID and TypeSec before any
external semantic projection.

## Security and cognition contract

TypeSec remains authoritative for capability checks, information-flow labels,
clearance, quarantine, retention, protected-content rehydration, proposal
validation, and TypeDID verification.

Required behavior:

- every content path carries request context, including graph, semantic,
  neighborhood, and reveal paths;
- TypeDID binds subject, recipient, route, action, and body;
- negotiated TypeDID obligations are enforceable, not descriptive;
- production replay protection is an atomic claim against shared durable
  authority, not a process-local cache;
- cognition proposals are inert, versioned, digest-bound, stale-checkable data
  without a store handle;
- source labels and governed scope are recomputed at the trusted apply edge;
- queues, outboxes, logs, and receipts contain IDs/digests, not plaintext or
  reusable authorization material; and
- only MemoryVault can rehydrate or mutate protected content.

Improve state machine:

~~~text
TypeDID authenticate + bind intent
  -> persist/recover job + renewable lease
  -> TypeSec preauthorization + governed LakeCat scan
  -> trusted mapped ingestion through TypeSec
  -> fixed Sail proposal-producing execution
  -> LakeCat grant/snapshot revalidation
  -> TypeSec manifest-only reauthorization
  -> exact proposal-digest stage
  -> atomic guarded Grust commit or typed no-change
  -> durable recovery + commit-bound TypeDID receipt
~~~

The physical commit must atomically compare source preconditions, claim
idempotency, apply graph mutations, write ID-only index outbox entries, persist
audit-safe evidence, and retain recoverable backend commit identity. No-change
uses the same authority, audit, and recovery path with zero mutations and zero
outbox rows.

## Current code and intended decomposition

The initial behavior-preserving transplant is executable. Keep its crate and wire
behavior stable before splitting responsibilities. Current product areas include
cognition, memory, catalog, Grust persistence, compatibility, and QueryGraph
integration.

The eventual decomposition may contain:

~~~text
marciana-api/       public four-verb DTOs and compatibility
marciana-cognition/ engines, proposals, reference algorithms
marciana-grust/     MemoryStore, graph projection, Turso/ANN/outbox
marciana-sail/      distributed cognition and Arrow/Spark schemas
marciana-lakecat/   governed-scan proof adapter
marciana-service/   TypeDID router, jobs, workers, receipts
marciana/           optional embedded facade
~~~

Do not split and redesign simultaneously. Each split needs compatibility
fixtures and a separate logical commit.

## Implemented Apache Ossie integration

Files:

~~~text
crates/marciana-cognition/src/ossie.rs
crates/marciana-cognition/tests/ossie.rs
~~~

The adapter validates a bounded Ossie JSON semantic model, rejects duplicate or
overlarge semantics, lowers into Marciana's operator-owned SchemaDefinition,
binds to a source manifest and deterministic digest, and emits a content-free
query plan. The plan still enters RecallIntent and TypeSec authorization.

It does not import an Ossie store, write memory, mint capabilities, or replace
TypeDID. This is a deliberately small supported subset, not a claim to be a
complete Ossie runtime. References: [Apache Ossie](https://github.com/apache/ossie)
and its [incubator proposal](https://cwiki.apache.org/confluence/spaces/INCUBATOR/pages/430408796/OssieProposal).

Semantic Croissant describes record sets and fields; LakeCat supplies catalog,
governed-scan, and lineage evidence; Sail executes authorized lakehouse work;
Ossie supplies a portable semantic edge model; Marciana binds those meanings
to memory records, proposals, recall plans, provenance, and receipts. Memory is
semantic organization, not a collection of independently authoritative stores.

## Compatibility

Current registry: ~/src/marciana/COMPATIBILITY.md.

| Component | Exact/status |
|---|---|
| TypeSec | 14bd5427 |
| Grust | 3bbd715 |
| LakeCat | 415d131 adapter-ready revision |
| QueryGraph | efd6245 consuming standalone Marciana |
| Sail | merged upstream baseline in compat/sail-revision.txt; refresh/live-gate required for next baseline |

Sail PR 2374 has merged upstream. For every new baseline: refresh the selected
canonical QueryGraph Sail source, record the exact reachable commit, build that
source, run the explicit-binary live gate, and update COMPATIBILITY.md. A Sail
binary found on PATH is not integration proof.

Clean-clone compatibility was previously verified for Marciana and qg-rust with
exact reachable revisions. The refreshed Sail live gate remains pending for
the next release baseline.

## Verified evidence

Focused gates passed at the implementation checkpoint:

~~~sh
cd ~/src/marciana
cargo test -p marciana-cognition --lib --quiet
cargo test -p marciana-cognition --test ossie --quiet
cargo clippy -p marciana-cognition --all-targets --all-features -- -D warnings
~~~

Run the full workspace and live Sail gates before claiming a release.

Benchmark (marciana-memory-smoke-v1, 504 records, 1,000 repeats, local,
provider-free, embedding-free):

| Measurement | Linear | Indexed |
|---|---:|---:|
| Case accuracy | 100% | 100% |
| Redaction leaks | 0 | 0 |
| Mean context tokens | 4.8 | 4.8 |
| P50 | 572.52 µs | 7.03 µs |
| P95 | 580.19 µs | 9.64 µs |
| P99 | 580.19 µs | 9.64 µs |

Indexed speedup is 81.44× at P50 and 60.21× at P95/P99. This is a local
engineering diagnostic, not a vendor comparison.

~~~sh
cd ~/src/marciana
python3 -m unittest discover -s benchmarks -p 'test_*.py' -q
python3 benchmarks/run_memory_benchmark.py --json
~~~

## Coffee-market demo

Location: examples/coffee_market_demo/.

It loads a Dataverse-shaped Honduras fixture, optionally writes/queries Sail,
and runs typed Pydantic AI v2 tools over governed memory. Regression sequence:

~~~python
["report", "learn", "learn", "recall", "improve", "recall", "forget"]
~~~

The demo learns an agronomic fact and coffee price, recalls them, improves the
newer San Pedro Sula price, recalls revised context, and forgets only the
obsolete observation. Receipts retain provenance; private signing material
never enters model context.

~~~sh
cd ~/src/marciana
python3 -m unittest discover -s examples/coffee_market_demo/tests -q
python3 -m examples.coffee_market_demo.demo
~~~

The default path is deterministic and key-free; live services and providers
are optional.

## Book and blog assets

The Marciana book is owned by ~/src/marciana/docs/book/ and published through
FirstPair as slug marciana on shelf querygraph.

- [Reader](https://firstpair.org/read/marciana/)
- [Chapter reader](https://firstpair.org/read/marciana/chapters/)

The book was last built from commit 5c4b146 and its Fluree wording clearly
describes the Akka comparison rather than a Marciana dependency.

Marciana 2 release post:

~~~text
docs/blog/marciana-2/post.md
docs/blog/marciana-2/diagrams/diagram-01.{mmd,png}
docs/blog/marciana-2/headboard.png
docs/blog/marciana-2/dist/marciana-2.textpack
docs/blog/marciana-2/dist/VERSION.md
~~~

The textpack was byte-matched to:

~~~text
~/icloud/blogs/marciana-2 (0.12.0-5c4b146).textpack
~~~

It is prepared as a handoff and has not been independently published to a
Ghost/blog production endpoint. The generated headboard depicts St Mark
establishing a library, Greek manuscripts and Petrarch's found volume entering
the collection, newly printed books joining the shelves, and knowledge
spreading across the Mediterranean into a future network.

## Important commits

Newest Marciana commits:

| Commit | Meaning |
|---|---|
| e366509 | Marciana 2 release post, diagram, generated headboard, textpack, changelog |
| 5c4b146 | Ossie adapter/tests and Fluree boundary clarification |
| 1fe0bed | FirstPair identity registration |
| a15716c | QueryGraph blog headboard in book configuration |
| cbfc763 | Book heading numbering normalization |
| 0e99eee | Book evaluation formula normalization |
| 5aba871 | Expanded book appendices |

All are pushed to origin/firstpair. Do not rewrite the branch; use a new
logical commit and changelog entry for the next user-visible change.

## Recommended next work

1. Read and reconcile MARCIANA2.md with implemented Ossie and publication
   status; keep Fluree explicitly comparative.
2. Finish the native vault-backed facade execution path without creating a
   second mutation or authorization route.
3. Centralize canonical digests, wire validation, job transitions,
   retry/recovery, and adapter mappings in small DRY modules.
4. Add cross-stack TypeDID → TypeSec → Marciana → Grust persistence tests,
   including close/reopen, retry, collision, and recovery.
5. Refresh Sail, record its exact revision, build the explicit binary, run live
   schema/cognition tests, and update COMPATIBILITY.md.
6. Add versioned Ossie fixtures for metrics, dimensions, relationships, unknown
   metadata, duplicates, and digest stability.
7. Complete qg-rust route/reopen integration while keeping LakeCat optional for
   local memory and mandatory for governed catalog-backed improve.
8. Split crates only after the behavior-preserving baseline and compatibility
   fixtures are green.

Release candidates require the full workspace suite, strict Clippy, TypeSec
conformance, Grust persistence/recovery, LakeCat proof tests where enabled,
qg-rust route/reopen tests, exact reachable dependency pins, and the explicit
Sail live gate.

## Risks and non-goals

- no Cognee runtime, stores, or compatibility facade;
- no Fluree Marciana dependency;
- no plaintext in proposal queues, metadata outboxes, or logs;
- no process-local replay authority in production;
- no model, index, worker, HTTP handler, or Sail executor may mutate
  authoritative memory directly;
- private Rust fields are not cryptographic protection against hostile storage;
- schema changes require versioned migration and fixtures;
- never discard unrelated user changes while switching projects.

## Continuation brief

Continue Marciana as a small, modular, DRY QueryGraph cognition layer:
TypeDID for identity, TypeSec for protected-memory authority, Grust for durable
graph commits, Sail for proposal-producing execution, LakeCat for governed
catalog proof, Ossie/Croissant for semantic organization, and auditable,
secure, reproducible, correctable agent memory.

