//! End-to-end graph-backed recall over the Grust store (`graph-memory`).

#![cfg(feature = "graph-memory")]

use typesec_core::policy::{MintOptions, RequestContext, mint_capability_for_id};
use typesec_core::{CanRead, CanWrite, Capability};
use typesec_memory::store::{GrustMemoryStore, MemoryStore};
use typesec_memory::{
    EntityRef, Label, MemoryContent, MemoryDraft, MemoryKind, MemorySpace, MemoryVault, Provenance,
    Resource,
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

fn cap<P: typesec_core::Permission>(space: &MemorySpace) -> Capability<P, MemorySpace> {
    let engine = typesec_rbac::RbacEngine::from_yaml(POLICY).unwrap();
    mint_capability_for_id(
        &engine,
        "agent:keeper",
        space.resource_id(),
        &MintOptions::default(),
    )
    .unwrap()
}

#[test]
fn graph_recall_returns_neighborhood_records_through_the_label_gate() {
    let space = MemorySpace::new("user:alice", "semantic");
    let vault = MemoryVault::new(GrustMemoryStore::new());
    let write: Capability<CanWrite, _> = cap(&space);
    let read: Capability<CanRead, _> = cap(&space);

    let draft = |text: &str, ents: &[(&str, &str)], label: Label| {
        MemoryDraft::new(
            MemoryKind::Semantic,
            MemoryContent::text(text),
            Provenance::Operator,
        )
        .with_label(label)
        .with_entities(ents.iter().map(|(n, k)| EntityRef::new(*n, *k)))
    };

    vault
        .remember(
            &space,
            &write,
            draft("Alice works at ACME", &[("ACME", "org")], Label::Public),
        )
        .unwrap();
    let venice_id = vault
        .remember(
            &space,
            &write,
            draft(
                "ACME HQ address (confidential)",
                &[("Venice", "place")],
                Label::Sensitive,
            ),
        )
        .unwrap();

    // Relate ACME → Venice so a 1-hop graph recall from ACME reaches the
    // Venice record.
    vault
        .store()
        .link("ACME", "based_in", "Venice", &venice_id)
        .unwrap();

    // Graph recall at Public: the ACME record is a hit, the Sensitive Venice
    // record is redacted (visible existence, sealed content).
    let (hits, redacted) = vault
        .recall_neighborhood(
            &space,
            &read,
            "ACME",
            1,
            Label::Public,
            &RequestContext::default(),
        )
        .unwrap();
    assert!(
        hits.iter()
            .any(|h| h.content.text.contains("Alice works at ACME"))
    );
    assert_eq!(
        redacted.len(),
        1,
        "the Sensitive neighbor is redacted at Public"
    );

    // At Sensitive clearance, the neighbor's content comes through.
    let (hits, redacted) = vault
        .recall_neighborhood(
            &space,
            &read,
            "ACME",
            1,
            Label::Sensitive,
            &RequestContext::default(),
        )
        .unwrap();
    assert!(redacted.is_empty());
    assert!(hits.iter().any(|h| h.content.text.contains("confidential")));
}
