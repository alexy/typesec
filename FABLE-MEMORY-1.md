# FABLE-MEMORY-1 — Marciana: capability-secured memory for AI agents

*Design date: 2026-07-04 · Author: Claude (Fable) with Alexy · Status: proposed,
implementation next · Codename: **Marciana** (the Biblioteca Marciana — Venice's
great library; the memory subsystem gets a Venetian name of its own, distinct
from the release codename line).*

Typesec learns to remember. This document designs an AI memory subsystem in
the mold of the best OSS memory systems — mem0's extraction/consolidation
loop, Zep's bi-temporal knowledge graph, cognee's ECL pipeline — but with the
property none of them have: **safe, granular, uniform access control**, built
from the primitives typesec already ships (capabilities, SecLib-style labeled
values, ODRL purpose/retention constraints, the interop tool-call plane) and
stored, at scale, on Grust.

---

## 1. Why memory, and why typesec is the right home

Memory is the highest-value asset an agent accumulates. Everything sensitive
an agent ever sees — PII, credentials pasted into a conversation, medical or
financial context, another tenant's data — flows toward its memory, and then
back out into prompts. The OSS state of the art treats access control as a
`user_id` filter on a query: any in-process bug, prompt injection, or
mis-scoped retrieval silently crosses tenants. And memory creates a *new*
attack class the tool-call guard alone can't stop: **memory poisoning** —
a prompt injection that persists itself as a "fact" today and fires in a
different session next week.

| | mem0 | Zep (Graphiti) | cognee | **Marciana** |
|---|---|---|---|---|
| Memory model | facts + ADD/UPDATE/DELETE loop | bi-temporal knowledge graph | ECL pipeline → graph + vectors | records + bi-temporal entity graph |
| Scoping | `user_id` filter | `group_id` filter | dataset filter | **capability per memory space** (unforgeable, minted, expiring) |
| Sensitivity | none | none | none | **type-level labels** (`SecureValue`, join-lattice) |
| Purpose / retention | none | none | none | **ODRL constraints** (purpose-bound recall, retention windows) |
| Deletion | best-effort delete | edge invalidation | delete | **audited tombstones + signed deletion receipts** |
| Poisoning defense | none | none | none | **provenance labels + quarantine + declassify-to-trust** |
| Agent surface | SDK calls | SDK calls | SDK calls | **guarded tool calls** — the same deny-by-default plane as every other tool, across OpenAI/Anthropic/LangChain/Pydantic-AI/MCP |

Every row in the last column is a primitive typesec already has. That is the
argument for building it here: Marciana is not a new security system bolted
onto a memory store; it is the existing security system *applied to* a memory
store. The SecLib fit in particular is exact: consolidation (merge, dedup,
summarize) is `map`/`zip` over labeled values, and the `Join` lattice gives
the only correct answer for free — *a summary of a Sensitive memory is born
Sensitive*; merging Internal with Secret yields Secret. No memory system on
the market gets this right because none of them has an information-flow type
system to get it right *in*.

## 2. Design principles

1. **Memory is a resource; access is a capability.** A memory space has a
   resource id; reading, writing, and forgetting it require
   `Capability<CanRead|CanWrite|CanDelete, MemorySpace>`, minted through a
   `PolicyEngine` like every other capability — audited, expiring, revocable,
   attenuable. There is no unauthenticated path to memory contents.
2. **Contents are labeled, not just scoped.** Every record's content lives in
   a `SecureValue<L, MemoryContent, MemorySpace>`. Scope says *whose* memory;
   the label says *how hot* it is. Both gates apply independently.
3. **Recall declares its clearance.** You don't "search memory"; you recall
   *into a context of a stated sensitivity ceiling*. What exceeds the ceiling
   isn't returned in cleartext — it surfaces as redacted metadata, revealable
   only with the stronger capability.
4. **The model's hands are gloved.** When the *LLM* wants to remember, recall,
   or forget, those are tool calls — routed through the existing
   `ToolCallGuard`, deny-by-default, in all five dialects. Memory gets no
   private side door around the interop plane.
5. **Provenance is security metadata.** Where a memory came from (verified
   TypeDID envelope ≻ human operator ≻ guarded tool output ≻ raw model text)
   determines its birth label and whether it can enter high-trust recall
   without an explicit, audited promotion.
6. **Forgetting is provable.** Deletion writes an audited tombstone and can
   mint a signed deletion receipt (ed25519, offline-verifiable) — the GDPR
   erasure story is a first-class flow, not a `DELETE FROM`.
7. **Storage is a trait; cognition is pluggable.** typesec owns the security
   semantics and the reference stores. Embeddings, LLM extraction, graph
   analytics, and scale live behind traits — with Grust/QueryGraph as the
   flagship backend, not a hard dependency.

## 3. Core model

### 3.1 Spaces and records

```text
memory/<owner>/<space>[/<record-id>]
  memory/user:alice/profile          — durable facts about Alice
  memory/user:alice/episodic         — conversation episodes
  memory/agent:planner/procedural    — learned procedures/skills
  memory/team:support/semantic       — shared knowledge, entity graph
```

A `MemorySpace` implements `Resource` with that id scheme, so **existing
policy engines govern memory with zero new machinery**: RBAC globs
(`memory/user:alice/**`), the graph engine for org-shaped sharing, ODRL for
purpose and time. Capabilities are minted per space; per-record granularity
comes from record ids in the resource path plus per-record labels.

```rust
pub struct MemorySpace { owner: SubjectId, space: String }   // Resource impl

pub struct MemoryRecord {
    pub id: MemoryId,
    pub kind: MemoryKind,          // Episodic | Semantic | Procedural | Profile
    pub content: SecureValue<_, MemoryContent, MemorySpace>,  // label-erased at rest, see 3.3
    pub entities: Vec<EntityRef>,  // hooks into the knowledge graph
    pub provenance: Provenance,    // Conversation | GuardedTool{tool, call_id} | Envelope{id} | Operator | ModelText
    pub observed_at: DateTime<Utc>,   // when we learned it
    pub valid_from:  DateTime<Utc>,   // when it became true   (bi-temporal, Zep-style)
    pub invalid_at:  Option<DateTime<Utc>>, // when it stopped being true
    pub expires_at:  Option<DateTime<Utc>>, // retention deadline
    pub purposes: Vec<String>,     // ODRL purpose tags it may serve
}
```

Bi-temporality is Zep's best idea and we take it wholesale: facts are never
overwritten, they are *invalidated* — "Alice lives in Venice (valid 2023→2026)"
survives next to its successor. Consolidation supersedes; only `forget`
destroys.

### 3.2 The vault: capability-gated operations

```rust
pub struct MemoryVault<S: MemoryStore> { store: S, engine: Arc<dyn PolicyEngine>, /* … */ }

impl<S: MemoryStore> MemoryVault<S> {
    /// Write: requires CanWrite on the space. The draft's provenance fixes
    /// its birth label (see 3.4); the record enters quarantine if untrusted.
    pub fn remember(
        &self, cap: &Capability<CanWrite, MemorySpace>, draft: MemoryDraft,
    ) -> Result<MemoryId, MemoryError>;

    /// Read at a declared clearance ceiling L: returns only records whose
    /// label ⊑ L, as SecureValue<L, …> (join-folded). Hotter hits come back
    /// as RedactedHit { id, kind, label, entities } — visible that they
    /// exist, unreadable without escalation.
    pub fn recall<L: PrivacyLevel>(
        &self, cap: &Capability<CanRead, MemorySpace>, query: RecallQuery, ctx: &RequestContext,
    ) -> Result<Recall<L>, MemoryError>;

    /// Escalate one redacted hit: the sensitive-read capability must cover
    /// the specific record's resource id (mirrors SecureValue::reveal).
    pub fn reveal(
        &self, cap: &Capability<CanReadSensitive, MemorySpace>, id: MemoryId,
    ) -> Result<MemoryContent, MemoryError>;

    /// Consolidate: merge/supersede/summarize a set of records. Labels join;
    /// superseded records get invalid_at, not deletion. Runs atomically
    /// (grust 0.12 transactions on the graph backend).
    pub fn consolidate(
        &self, cap: &Capability<CanWrite, MemorySpace>, plan: ConsolidationPlan,
    ) -> Result<ConsolidationReport, MemoryError>;

    /// Forget: destructive, audited, tombstoned; optionally mints a signed
    /// deletion receipt via typesec-integrations::receipt.
    pub fn forget(
        &self, cap: &Capability<CanDelete, MemorySpace>, selector: ForgetSelector,
    ) -> Result<Tombstone, MemoryError>;
}
```

Key decisions baked into these signatures:

- **`recall<L>` is the SecLib move.** The clearance is a *type parameter*: the
  caller states the sensitivity of the context the memories will flow into
  (a prompt bound for an external model is `Public`/`Internal`; an in-house
  audit tool may recall at `Sensitive`). The result is typed at that ceiling,
  so downstream code cannot accidentally treat hot memories as cool ones —
  the compiler carries the ceiling.
- **`RequestContext` flows through recall**, so ODRL purpose constraints bind
  per-query: a space whose policy says `purpose eq "support"` simply returns
  nothing to an analytics query. Purpose-bound memory is a policy line, not
  application code.
- **Delegation is attenuation.** A planner hands a sub-agent
  `cap.coerce::<CanRead>().attenuated(Duration::from_secs(300))` — read-only,
  five minutes, one space. Cross-process, the same grant travels as a signed
  receipt or inside a TypeDID envelope.
- **New sealed permission, one addition:** `CanForget`? No — `CanDelete`
  already exists and maps exactly. We add **no new permission markers** in M1;
  if quarantine-promotion proves to need its own authority, `CanDeclassify`
  is already there and semantically correct.

### 3.3 Labels at rest

`SecureValue`'s label is compile-time; a store holds mixed-label records. At
rest each record carries a **runtime label tag** (`Public | Internal |
Sensitive | Secret`); the vault is the only component that rehydrates content,
and it re-wraps into the statically-typed `SecureValue<L>` *only* when the
record's runtime label ⊑ the recall ceiling `L`. The unsafe rehydration path
is `pub(crate)` inside typesec-memory — exactly the `new_minted` pattern:
one guarded construction site, compile-fail tests to keep it that way.

### 3.4 Provenance, taint, and memory poisoning

Birth labels by source (defaults, policy-overridable):

| Provenance | Birth label | Quarantined? |
|---|---|---|
| Verified TypeDID envelope (signature + replay checks passed) | as declared by sender profile | no |
| Human operator / explicit API | as declared | no |
| Guarded tool output (`GuardedToolCall::protect_output` taint) | tool resource's level | no |
| **Raw model text / unguarded extraction** | `Internal` | **yes** |

Quarantined records are recallable only at a `Quarantined`-aware query flag
(default **off**) and are excluded from consolidation into durable spaces
until **promoted** — an explicit, audited act requiring `CanDeclassify` on the
space. This is the anti-poisoning valve: an injected "fact" can enter the
episodic log, but it cannot silently become long-term truth that steers
future sessions. The extraction pipeline (3.6) writes *through* this valve,
never around it.

### 3.5 The knowledge graph on Grust

Semantic memory is a typed property graph — Grust's home turf:

```text
(:Entity {name, kind})-[:REL {fact_id, valid_from, invalid_at}]->(:Entity)
(:Episode {id, at})-[:MENTIONS]->(:Entity)
(:Record {id, label, space})-[:ASSERTS]->(:REL edge identity)
```

- **Graph recall**: "what do we know about ACME?" is a GQL/Cypher
  neighborhood query; results map back to record ids, then through the vault's
  label gate — *the graph returns ids, the vault returns content*. Storage
  never becomes an authorization bypass.
- **Bi-temporal edges**: `valid_from`/`invalid_at` as edge properties;
  point-in-time recall ("what did we believe on June 1?") is a property
  predicate.
- **Atomic consolidation**: grust 0.12's transaction surface
  (`begin`/`add_statement`/commit) makes supersede-and-relink a single unit —
  no half-merged memories.
- **Policy synergy**: the *same* Grust instance can hold the org graph the
  `GraphPolicyEngine` evaluates — "share memories up the reporting line" is a
  policy that joins the memory graph and the org graph. No other stack can
  express that in one query engine.

### 3.6 Extraction & consolidation (the mem0 loop, gloved)

An `Extractor` trait turns raw episodes into `MemoryDraft`s and
`ConsolidationPlan`s (ADD / UPDATE(supersede) / NOOP decisions):

```rust
pub trait Extractor {
    fn extract(&self, episode: &Episode, existing: &[MemorySummary]) -> Result<Vec<MemoryDraft>, ExtractError>;
    fn plan(&self, drafts: &[MemoryDraft], existing: &[MemorySummary]) -> Result<ConsolidationPlan, ExtractError>;
}
```

Reference impls: a deterministic `RuleExtractor` (tests, air-gapped use) and
an `OllamaExtractor` in typesec-integrations (the `DidOllamaClient` plumbing
already exists — extraction can run against a *local* model so raw sensitive
episodes never leave the boundary; that's a differentiator worth advertising).
Extractor output is drafts, not writes: everything still enters through
`remember`/`consolidate` with capabilities, labels, and quarantine applied.
The extractor is untrusted by construction.

### 3.7 Storage trait and reference stores

```rust
pub trait MemoryStore: Send + Sync {
    fn put(&self, record: StoredRecord) -> Result<(), StoreError>;
    fn get(&self, id: &MemoryId) -> Result<Option<StoredRecord>, StoreError>;
    fn query(&self, q: &StoreQuery) -> Result<Vec<StoredRecord>, StoreError>;   // filters: space, kind, time, label≤, entities, text
    fn invalidate(&self, id: &MemoryId, at: DateTime<Utc>) -> Result<(), StoreError>;
    fn tombstone(&self, id: &MemoryId) -> Result<(), StoreError>;
    // graph hooks (default: unsupported)
    fn link(&self, ...) -> Result<(), StoreError> { Err(StoreError::Unsupported) }
    fn neighborhood(&self, ...) -> Result<Vec<MemoryId>, StoreError> { Err(StoreError::Unsupported) }
}
```

- `InMemoryStore` — always available; tests, demos, WASM.
- `GrustMemoryStore` — behind a `graph-memory` feature (same pattern as
  typesec-rbac's `graph` feature).
- **Vector search is deliberately *not* in the trait's core.** An optional
  `SemanticIndex` trait (embed + ANN) plugs in beside it; the reference impl
  can use Ollama embeddings, and the scale impl belongs to QueryGraph (§5).
  Marciana's guarantees must hold on `query` alone — semantic search is a
  *ranking* upgrade, never an authorization path.

## 4. Ecosystem integration (the "uniform across typesec" requirement)

- **Interop plane**: ship standard tool bindings — `memory.recall` /
  `memory.remember` / `memory.forget` with `resource_arg: space` — so
  LLM-initiated memory ops are guarded tool calls in all five dialects, are
  hidden by policy-aware tool listing when the subject has no memory rights,
  stream-scrubbed by `typesec proxy`, and gated by `typesec mcp-gate` when
  memory is served over MCP. A `#[typesec_tool]`-annotated reference handler
  makes the binding one declaration.
- **MCP memory server**: `typesec memory-serve` — an MCP server over a vault,
  so *any* MCP-speaking host (Claude, IDEs) gets capability-secured memory by
  pointing at it (optionally fronted by mcp-gate for a second subject's view).
- **Python**: `MemoryGate` in typesec-python mirroring `ToolGate`
  (`remember/recall/forget/consolidate`, clearance as a string, results as
  dicts with `label` + `redacted` flags) + `typesec.adapters` helpers so
  mem0-style call sites port in minutes.
- **WASM**: `WasmMemoryVault` over `InMemoryStore` — session-scoped secure
  memory for JS/edge agents (no Grust on wasm; the trait split makes this
  free).
- **Receipts & TypeDID**: memory grants travel as attenuated capabilities
  serialized to receipts; deletion receipts prove erasure to a counterparty;
  TypeDID envelopes carry cross-agent memory shares end-to-end encrypted.
- **Audit/observability**: every vault op is an `AuditEvent`
  (`memory:read|write|delete|promote` action names) → the OTel sink, decision
  logs, and `typesec replay` work unchanged — *replay a proposed policy change
  against last month's actual memory-access log* before rollout.
- **Conversation typestate**: `Conversation<Consented>` is the natural
  carrier for "this peer consented to being remembered" — `remember` for
  peer-derived facts can require the consent capability. (M5, optional.)

## 5. Placement: typesec vs QueryGraph

**Marciana's security core belongs in typesec; its scale/cognition tier
belongs in QueryGraph.** Concretely:

**typesec (this repo) — crate `typesec-memory` (workspace member #11):**
types, `MemorySpace`, the vault, labels-at-rest, quarantine, `MemoryStore` +
`SemanticIndex` traits, `InMemoryStore`, `GrustMemoryStore` (feature-gated,
same as rbac's grust dep), interop bindings, `memory-serve`, Python/WASM
surfaces, receipts/audit wiring. Rationale: the invariants (one rehydration
site, capability-gated ops, label joins) are compile-time properties that
must live next to the sealed traits and compile-fail tests that enforce them.

**QueryGraph stack — suggested crate `querygraph-memory` (or `grust-memory`):**
everything that is about *scale and intelligence*, implementing typesec's
traits from the outside:

- **`SemanticIndex` at scale** — embedding pipelines and ANN over sail
  (DataFusion / Lance / Spark-sized corpora), hybrid BM25+vector+graph
  ranking à la Zep.
- **Graph analytics** — entity resolution, community detection/summaries
  (Graphiti-style), contradiction detection between records, decay/importance
  scoring — batch jobs over grust-sail, feeding `ConsolidationPlan`s back
  through the vault's front door.
- **Point-in-time & lineage queries as GQL library functions** — this
  pressure-tests grust's new GQL/transaction features with a real workload,
  which is good for Grust itself.
- **Multi-tenant memory service** — a hosted QueryGraph product: one Grust
  cluster, many vaults, typesec policies as the tenancy boundary. This is
  where "memory as a service, with provable isolation" becomes a product
  story neither mem0 nor Zep can tell.

The seam is clean because it's the seam we already operate: typesec-rbac
defines the policy contract, grust supplies the graph. Marciana repeats the
pattern one level up.

### 5.1 QueryGraph handoff spec (`querygraph-memory`)

The contract QueryGraph implements against, versioned with `typesec-memory`:

- **Traits to implement:** `MemoryStore` (required) and `SemanticIndex`
  (optional, for ANN/hybrid ranking). Both are `Send + Sync`, take
  `StoredRecord`/`StoreQuery` by value/ref, and must **never** expose record
  content (the field is crate-private in `typesec-memory`; QueryGraph stores
  persist `StoredRecord` via its `Serialize`/`Deserialize` and hand it back
  whole — the vault does all content access). The Grust reference store
  (`GrustMemoryStore`, M4) is the conformance template.
- **Invariants a backend must preserve** (checked by a shared conformance
  suite QueryGraph runs): `query` honors every `StoreQuery` field with the
  documented semantics (label ceiling, bi-temporal `valid_at`, quarantine,
  purpose overlap); `invalidate` sets `invalid_at` without destroying;
  `tombstone` destroys and returns existence; `neighborhood` returns only ids
  reachable within `hops`. A backend that *widens* any filter fails the
  suite.
- **Fixtures:** `typesec-memory` ships (in `tests/`) a corpus of records +
  expected `query`/`neighborhood` results as JSON; `querygraph-memory` runs
  the same corpus. "Marciana-compatible" is thereby checkable.
- **What QueryGraph adds on top** (not in the trait, layered beside it):
  embedding pipelines feeding `SemanticIndex`, entity resolution and
  community summaries as batch jobs over grust-sail that emit
  `ConsolidationPlan`s back through the vault's front door, point-in-time and
  lineage queries as GQL library functions, and the multi-tenant hosted
  service (typesec policies as the tenancy boundary).
- **Versioning:** `querygraph-memory` tracks `typesec-memory`'s minor version;
  a trait change is a minor bump in both, and the conformance fixtures carry
  a schema version so a backend can assert compatibility at build time.

## 6. Implementation plan (next; each milestone green + changelogged)

- **M1 — vault core** (`typesec-memory`): `MemorySpace`, records, runtime
  labels + single rehydration site, `MemoryVault` ops gated by capabilities,
  `InMemoryStore`, bi-temporal invalidation, tombstones, audit actions,
  quarantine flag; tests incl. compile-fail (`recall` without a capability,
  rehydrate outside the crate). *This alone already beats the field's
  security story.*
- **M2 — policy depth**: ODRL purpose-bound recall + retention reaper +
  deletion receipts; `recall<L>` ceiling semantics + redacted hits + `reveal`
  escalation; attenuated delegation example (planner → sub-agent).
- **M3 — agent surface**: interop tool bindings + `#[typesec_tool]` handlers;
  `typesec memory-serve` (MCP); Python `MemoryGate` + pydantic-ai example;
  WASM vault.
- **M4 — Grust backend**: `GrustMemoryStore` (entity graph, bi-temporal
  edges, GQL recall, transactional consolidation) behind `graph-memory`;
  point-in-time recall test; org-graph × memory-graph shared-instance demo.
- **M5 — cognition hooks**: `Extractor` trait + `RuleExtractor` +
  `OllamaExtractor` (local-model extraction); consolidation loop demo
  (ADD/UPDATE/NOOP); consent-gated remembering via `Conversation<Consented>`;
  QueryGraph handoff spec for `querygraph-memory` (trait versions, fixtures,
  conformance tests).

Non-goals for this cycle: hosted service, embedding model training, UI.

### Implementation status (2026-07-04, branch `fable/memory`)

All five milestones landed as green, tested commits (`typesec-memory`,
workspace member #11):

- **M1 done** — `MemorySpace`/records/runtime `Label` + single rehydration
  site (compile-fail-guarded), `MemoryVault` (remember/recall::<L>/reveal/
  consolidate/forget), `InMemoryStore`, quarantine, provenance birth labels,
  bi-temporal invalidation, audit.
- **M2 done** — `with_policy` per-op ODRL re-check at use time, `reap_expired`
  retention reaper, signed deletion receipts (`receipts` feature),
  attenuated-delegation.
- **M3 done (Rust surface)** — `memory_bindings()` + `MemoryToolRouter`
  (`agent` feature): memory as guarded tool calls across all five dialects;
  `recall_at` runtime-clearance path; `examples/memory_agent.rs`. *Follow-ons
  still open:* Python `MemoryGate`, `typesec memory-serve` (MCP), WASM vault.
- **M4 done** — `GrustMemoryStore` (`graph-memory` feature): record CRUD +
  Grust entity graph, `neighborhood` BFS recall, `recall_neighborhood`
  through the label gate. *Follow-ons:* full GQL query surface, transactional
  consolidation on grust.
- **M5 done** — `Extractor` trait + deterministic `RuleExtractor`,
  `examples/memory_consolidation.rs` (learn → supersede, history preserved),
  and §5.1 the QueryGraph handoff spec. *Follow-on:* `OllamaExtractor`
  (local-model extraction) via `typesec-integrations`' `DidOllamaClient`.

**Follow-on wave (same branch): all agent surfaces + the Ollama extractor
are now done too.**

- **Python `MemoryGate`** — remember/recall/forget from Python, every op
  minting its capability; clearance strings fail closed; denials raise
  `PermissionError`. (typesec-python + unittest coverage.)
- **`typesec memory-serve`** — Marciana as an MCP stdio server: initialize /
  tools/list / tools/call, each call through guard-then-mint; denials are
  `isError` results. Verified e2e over stdio. (Also fixed a real bug it
  surfaced: CLI logs went to stdout, corrupting JSON-RPC streams — now
  stderr.)
- **`WasmMemoryVault`** — session-scoped secure memory for JS/edge agents;
  verified from Node. (Enabler: `typesec_core::time` shims `web-time` on
  wasm32, since `SystemTime::now()` panics on bare wasm.)
- **`OllamaExtractor`** (`ollama` feature) — local-model extraction with a
  strict JSON output contract (malformed output fails closed) and
  episode-provenance drafts (the model cannot upgrade its own trust); raw
  episodes never leave the box. Mock-HTTP tests, no network.

42 crate tests (all features) + 2 runnable examples; 322 workspace tests
green. Remaining deeper work: grust GQL query surface + transactional
consolidation, and the `querygraph-memory` scale tier (§5.1).

## 7. Open questions

1. **Label set extensibility** — are four levels enough for memory (e.g. a
   distinct `Quarantined` *label* vs. the boolean flag chosen here)? Current
   answer: flag + provenance keeps the sealed lattice unchanged; revisit if
   policies want to *address* quarantine directly.
2. **Record-level capabilities** — per-record resource ids work today via
   globs, but minting per-record caps at volume needs a decision cache;
   measure in M2 (the `LatticeEngine`/mint path may want a memoized layer).
3. **Cross-space recall** — "search all of Alice's spaces" needs a
   capability *set* or a parent-space capability (`memory/user:alice/**` as a
   mintable resource). Leaning: allow glob-resource capabilities, since RBAC
   already grants them; needs a compile-fail-safe design pass.
4. **Embedding privacy** — vectors leak content; do embeddings of Sensitive
   records inherit the label (and thus never leave for a remote embedder)?
   Proposed: yes — `SemanticIndex` receives `SecureValue`s and local-only
   indexes are the default for `label ≥ Sensitive`.
5. **Naming** — `typesec-memory` (crate) / `MemoryVault` (type) / *Marciana*
   (subsystem codename) — confirm before M1 lands the crate name on crates.io.

---

*Summary judgment: yes — build it, and build it here. Marciana turns
typesec's thesis ("authorization decisions become compile-time-visible
authority") loose on the one asset every agent framework is racing to
accumulate and none of them knows how to protect. typesec supplies the vault
and the law; Grust supplies the palace; QueryGraph gets the telescope.*
