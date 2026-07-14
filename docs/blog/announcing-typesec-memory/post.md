# Announcing TypeSec Memory: remembering is a commodity; authority is not

*July 2026 — Introducing Marciana*

![The lineage of a document from a Cicero-era papyrus and Alexandria through an Alpine scriptorium, Petrarch studying a manuscript in Venice, a later Venetian incunable, and a LaTeX document on a tablet.](assets/typesec-memory-headboard.png)

AI memory is having its startup moment. A growing category promises to extract durable facts from conversations, embed them, rank them, connect them in temporal graphs, consolidate duplicates, and put the right fragments back into an agent's context. That work is useful. It is also converging quickly on a common set of primitives.

TypeSec's bet is deliberately contrarian: basic remember-and-recall will become a platform commodity. Claude, Codex, and their peers already sit where conversation state, context assembly, tools, and model execution meet. We expect them to subsume much of today's standalone memory convenience layer—and to do it well.

That does not make memory less important. It makes the unsolved part more obvious.

The durable enterprise question is not whether an agent *can* remember. It is whether this verified agent may write, recall, transform, share, or forget this memory, for this purpose, at this clearance, under this policy—and whether the organization can prove what happened afterward. Those are authority, privacy, and evidence questions. A vector database plus a `user_id` filter does not answer them.

Today we are announcing **TypeSec Memory**, codename **Marciana**: capability-secured, privacy-first memory for AI agents, built as part of the QueryGraph stack.

Marciana takes its name from Venice's Biblioteca Marciana. A library is not merely a pile of documents: it is an institution for provenance, custody, classification, access, and stewardship. That is the distinction we are building into agent memory.

## Memory with the law inside

Marciana starts from a simple rule: **memory is a resource, and access to it is a capability**.

A memory space such as `memory/team:research/shared` implements the same TypeSec resource model used for tools and governed data. Reading, writing, and deleting require distinct values such as `Capability<CanRead, MemorySpace>`, `Capability<CanWrite, MemorySpace>`, and `Capability<CanDelete, MemorySpace>`. These values have no public constructor. The production path to one runs through policy evaluation and emits audit evidence.

The result is more than an authorization check near a database call. The capability is required by the Rust API itself:

```rust
pub fn recall<L: Clearance>(
    &self,
    space: &MemorySpace,
    capability: &Capability<CanRead, MemorySpace>,
    query: RecallQuery,
    context: &RequestContext,
) -> Result<Recall<L>, MemoryError>;
```

Skip the policy boundary and application code does not receive the value needed to call the vault. Ask for write authority and you do not silently get delete authority. Delegate to a sub-agent and the capability can be narrowed and shortened, never widened. At the JSON and HTTP edges, runtime verification mints the typed authority before execution enters the vault.

This is the distinction TypeSec brings to the memory market: capability gating is not a convention in a prompt or an optional filter in an SDK. It is part of the program's type-level contract.

## Privacy is more than tenant scoping

Memory concentrates everything an agent has seen: personal data, credentials pasted into a chat, commercial context, customer history, medical or financial facts, confidential documents, and instructions that may have arrived through an attack. Treating all of that as undifferentiated text under one tenant key is not responsible AI infrastructure.

Marciana applies TypeSec's information-flow model to every record:

- **Sensitivity labels.** Content carries a runtime `Public`, `Internal`, `Sensitive`, or `Secret` label at rest. The vault is the guarded rehydration point; storage and indexes do not become plaintext authorization bypasses.
- **Clearance-typed recall.** A caller declares the maximum sensitivity of the destination context. Records above that ceiling remain redacted instead of leaking into a prompt.
- **Purpose constraints.** ODRL-aware request context can permit recall for `support` while denying the same record to an `analytics` purpose.
- **Derived-data taint.** Consolidation joins the labels of its sources. A summary of sensitive material is born sensitive; transformation does not launder it.
- **Poisoning resistance.** Untrusted model text can be born quarantined and is excluded from ordinary recall by default rather than silently promoted into durable truth.
- **Auditable forgetting.** Deletion is a capability-gated tombstone operation, and the TypeSec core can issue signed deletion receipts for workflows that require offline-verifiable evidence.

This is Responsible AI as infrastructure, not a model-card aspiration. Privacy is not a storage checkbox added after retrieval. It controls what may enter memory, what may leave it, what derived knowledge inherits, and which agent context may see the result.

## Lineage, time, and DID-bound accountability

Agent memory is not only a bag of facts. It is a history of claims.

Marciana records provenance, the time a fact was observed, the interval during which it was valid, its purposes, sensitivity, entities, and retention deadline. When a fact changes, consolidation invalidates the old assertion instead of overwriting history. “Alice lives in Venice” can remain visible as a past belief beside its successor without being treated as current truth.

The graph returns candidate record identifiers; the TypeSec vault decides whether content may be revealed. That separation matters. Faster retrieval may narrow or reorder a candidate set, but it may never widen authority.

Across the service boundary, qg-python signs requests with an Ed25519 TypeDID credential. qg-rust verifies the `did:key`, recipient, action, exact route, and body digest, then uses the verified DID—not a caller-supplied JSON field—as the TypeSec policy subject. Allowed operations and denials are therefore tied to a cryptographic identity and an auditable policy decision.

V1 provides record provenance and bi-temporal history. Independently addressable assertion lineage, durable cross-replica anti-replay, and the hosted operational controls described below are the next scale layer; we do not blur those future guarantees into the current proof.

## Marciana is a QueryGraph capability

Responsible memory needs more than a standalone SDK. Marciana is deliberately distributed across the QueryGraph stack, with each layer doing the job it is built to do:

| Layer | Responsibility |
|---|---|
| **TypeSec** | Typed authority, sensitivity labels, purpose policy, quarantine, guarded rehydration, audit, and forgetting |
| **`querygraph-memory` on Grust** | Durable graph records, temporal state, entity relationships, transactional consolidation, and the shared conformance contract |
| **qg-rust** | DID-authenticated memory routes and the deny-by-default guard/router/vault boundary |
| **qg-python + Pydantic AI v2** | Ergonomic agent capabilities for credentials and memory without exposing private credential material to the model |
| **The broader QueryGraph stack** | Governed data products, semantics, lineage evidence, and agent workflows around the memory system |

This architecture keeps the boundaries honest. TypeSec owns the law. Grust supplies the durable graph. qg-rust exposes the governed service. qg-python makes it natural for agents to use. QueryGraph connects remembered knowledge to enterprise data, meaning, and evidence.

That last point is the enterprise thesis. A future-forward company will not run one agent with one private notebook. It will operate fleets of agents over catalogs, graphs, policies, customer contexts, and regulated data. Agents will delegate tasks, change roles, share some memories, isolate others, and outlive individual model sessions. Memory must participate in the same identity, policy, lineage, and audit fabric as the rest of the platform.

## A working agent proof, not a slide

The v1 vertical slice is implemented across four repositories and exercised end to end.

The qg-python demonstration gives each Pydantic AI v2 agent two separate native capabilities: `querygraph.typedid-credential` for governed QueryGraph access and `querygraph.marciana-memory` for remember, recall, and forget. Private signing material stays in typed runtime dependencies rather than model instructions or tool arguments.

In the executable story, an authorized specialist obtains a governed answer and commits it to a shared Marciana space. qg-rust is then terminated and restarted. A differently credentialed but authorized supervisor recalls the same durable record from Turso through `querygraph-memory`. A validly signed outsider receives a TypeSec `403` denial, while an unsigned caller receives `401`.

The model context did not grant access. The body did not choose its subject. Restarting the service did not erase the memory. A different agent could read it only because policy granted that DID the required capability.

The test is deterministic and provider-key-free, but the same Pydantic AI capability objects can be attached to production models. The full TypeSec memory suite, Grust adapter conformance tests, qg-rust identity/restart tests, qg-python capability tests, and the live demonstration are green.

## The enterprise moat is governed memory

Extraction quality will improve. Embeddings will get cheaper. Context windows will grow. Model platforms will offer increasingly competent personal and project memory. Those are reasons to avoid rebuilding commodity plumbing as the center of an enterprise architecture.

They are also reasons to invest in the layer the model provider cannot infer on its own: organizational authority.

Which legal entity owns this memory? Which employee, service, or agent DID created it? Was it observed from a governed tool, asserted by an operator, or generated by a model? Which policy allowed the write? May another agent recall it for a different purpose? Does a summary inherit the original classification? What happens after revocation, expiration, supersession, or erasure? Can an auditor reconstruct the decision without trusting the prompt that happened to be in context?

Marciana makes those questions architectural. We believe that makes capability-secured memory a requirement—not an optional feature—for the agentic enterprise.

## What comes next

Marciana v1 is a complete durable local-service proof, and `typesec-memory` is on main for the next TypeSec release. It is not yet a hosted multi-tenant product. The scale program is explicit:

- native, tenant-scoped LanceDB ANN as a rebuildable semantic side index;
- fuller memory-specific GQL pushdown and assertion-level temporal lineage;
- distributed Sail cognition that produces inert consolidation plans for the vault to authorize;
- persistent TypeDID anti-replay and mutation idempotency shared across replicas; and
- hosted multi-tenant operations: quotas, migrations, isolation tiers, backup/restore, deletion propagation, observability, and SLOs.

Those are post-v1 scale and service work, not unfinished v1 requirements. The canonical `MEMORY.md` design specifies their invariants, sequencing, and acceptance gates—including durable identifiers and a complete quarantine-promotion path before multi-process hosting.

The image above traces a document from papyrus, through libraries, scriptoria, manuscript culture, print, and finally a LaTeX workspace. Its point is not nostalgia. Durable memory has always depended on more than copying words. It depends on provenance, custody, classification, interpretation, and institutions that decide who may read and amend the record.

Claude and Codex may remember more for us. TypeSec determines whether they are allowed to. QueryGraph makes that memory part of a governed system.

Welcome to Marciana.

Read next:

- `MEMORY.md` for the canonical cross-stack design and post-v1 roadmap.
- `crates/typesec-memory/src/lib.rs` for the TypeSec memory API and examples.
- `qg-rust/docs/memory-service.md` for the service contract.
- `qg-python/examples/pydantic_ai_v2_memory_agents.py` for the executable Pydantic AI v2 demonstration.
