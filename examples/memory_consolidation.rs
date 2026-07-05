//! The mem0-style extract → consolidate loop, gloved by capabilities.
//!
//! An `Extractor` reads raw episodes and proposes drafts + a consolidation
//! plan — but it is *untrusted*: nothing it produces is written until it
//! passes back through the capability-gated vault, which applies labels,
//! quarantine, and the SecLib join. This demo shows a fact being learned,
//! then updated (superseded, not overwritten — the old fact survives as
//! history).
//!
//! Run: `cargo run -p typesec-cli --example memory_consolidation`.

use typesec_core::policy::{MintOptions, RequestContext, mint_capability_for_id};
use typesec_core::secure_value::Internal;
use typesec_core::{CanWrite, Capability};
use typesec_memory::{
    Episode, Extractor, InMemoryStore, MemorySpace, MemoryVault, RecallQuery, Resource,
    RuleExtractor,
};

const POLICY: &str = r#"
roles:
  - name: keeper
    permissions: [read, write]
    resources: ["memory/**"]
assignments:
  - subject: "agent:keeper"
    roles: [keeper]
"#;

fn main() {
    let engine = typesec_rbac::RbacEngine::from_yaml(POLICY).unwrap();
    let space = MemorySpace::new("user:alice", "semantic");
    let write: Capability<CanWrite, _> = mint_capability_for_id(
        &engine,
        "agent:keeper",
        space.resource_id(),
        &MintOptions::default(),
    )
    .unwrap();
    let read = mint_capability_for_id(
        &engine,
        "agent:keeper",
        space.resource_id(),
        &MintOptions::default(),
    )
    .unwrap();

    let vault = MemoryVault::new(InMemoryStore::new());
    let extractor = RuleExtractor::new();
    let ctx = RequestContext::default();

    // Turn one episode's extracted drafts into writes through the vault.
    let ingest = |vault: &MemoryVault<InMemoryStore>, episode: Episode| {
        for draft in extractor.extract(&episode, &[]).unwrap() {
            vault.remember(&space, &write, draft).unwrap();
        }
    };

    // 1. Learn an initial fact.
    ingest(&vault, Episode::operator("Alice lives in Rome"));
    println!(
        "after episode 1: {} memory(ies)",
        live_count(&vault, &space, &read, &ctx)
    );

    // 2. A new episode updates it. Build the summaries from what we know, let
    //    the extractor plan the supersede, and apply it through the vault.
    let existing = summaries(&vault, &space, &read, &ctx);
    let episode2 = Episode::operator("Alice lives in Venice");
    let drafts = extractor.extract(&episode2, &existing).unwrap();
    let plan = extractor.plan(&drafts, &existing).unwrap();
    if plan.steps.is_empty() {
        // No supersede matched (gists differ) — just add.
        for d in drafts {
            vault.remember(&space, &write, d).unwrap();
        }
    } else {
        let report = vault.consolidate(&space, &write, plan).unwrap();
        println!(
            "consolidated: {} invalidated, {} created",
            report.invalidated.len(),
            report.created.len()
        );
    }

    // 3. Live recall shows the current belief; the superseded fact survives as
    //    bi-temporal history (not returned by default).
    let live = summaries(&vault, &space, &read, &ctx);
    println!(
        "live beliefs now: {:?}",
        live.iter().map(|s| &s.gist).collect::<Vec<_>>()
    );
}

fn live_count(
    vault: &MemoryVault<InMemoryStore>,
    space: &MemorySpace,
    read: &Capability<typesec_core::CanRead, MemorySpace>,
    ctx: &RequestContext,
) -> usize {
    vault
        .recall::<Internal>(space, read, RecallQuery::all(), ctx)
        .unwrap()
        .hits
        .len()
}

fn summaries(
    vault: &MemoryVault<InMemoryStore>,
    space: &MemorySpace,
    read: &Capability<typesec_core::CanRead, MemorySpace>,
    ctx: &RequestContext,
) -> Vec<typesec_memory::MemorySummary> {
    vault
        .recall::<Internal>(space, read, RecallQuery::all(), ctx)
        .unwrap()
        .hits
        .into_iter()
        .map(|h| typesec_memory::MemorySummary {
            id: h.id,
            gist: h.content.text,
        })
        .collect()
}
