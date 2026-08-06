use chrono::Utc;
use typesec_core::policy::{MintOptions, RequestContext, mint_capability_for_id};
use typesec_core::{CanRead, CanWrite, Capability, Resource};
use typesec_memory::{
    InMemoryStore, Label, MemoryContent, MemoryDraft, MemoryKind, MemorySpace, MemoryVault,
    Provenance,
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

fn capability<P: typesec_core::Permission>(space: &MemorySpace) -> Capability<P, MemorySpace> {
    let policy = typesec_rbac::RbacEngine::from_yaml(POLICY).unwrap();
    mint_capability_for_id(
        &policy,
        "agent:keeper",
        space.resource_id(),
        &MintOptions::default(),
    )
    .unwrap()
}

fn draft(text: &str, label: Label) -> MemoryDraft {
    MemoryDraft::new(
        MemoryKind::Semantic,
        MemoryContent::text(text),
        Provenance::Operator,
    )
    .with_label(label)
}

#[test]
fn candidate_ids_are_deduplicated_and_materialized_through_the_visibility_gate() {
    let vault = MemoryVault::new(InMemoryStore::new());
    let space = MemorySpace::new("user:alice", "profile");
    let other_space = MemorySpace::new("user:bob", "profile");
    let write: Capability<CanWrite, _> = capability(&space);
    let other_write: Capability<CanWrite, _> = capability(&other_space);
    let read: Capability<CanRead, _> = capability(&space);
    let public = vault
        .remember(&space, &write, draft("coffee price", Label::Public))
        .unwrap();
    let sensitive = vault
        .remember(&space, &write, draft("private contract", Label::Sensitive))
        .unwrap();
    let other = vault
        .remember(
            &other_space,
            &other_write,
            draft("other tenant", Label::Public),
        )
        .unwrap();

    let (hits, redacted) = vault
        .recall_ids_at(
            &space,
            &read,
            [public.clone(), sensitive.clone(), public, other],
            Utc::now(),
            Label::Public,
            &RequestContext::default(),
        )
        .unwrap();

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].content.text, "coffee price");
    assert_eq!(redacted.len(), 1);
    assert_eq!(redacted[0].id, sensitive);
}
