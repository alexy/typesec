use chrono::Utc;
use typesec_core::policy::{MintOptions, RequestContext, mint_capability_for_id};
use typesec_core::{CanRead, CanWrite, Capability};
use typesec_memory::store::{InMemoryStore, MemoryStore};
use typesec_memory::{
    CognitionApplyError, CognitionSourcePrecondition, Label, MemoryContent, MemoryDraft,
    MemoryError, MemoryKind, MemorySpace, MemoryVault, Provenance, Resource,
};

const POLICY: &str = r#"
roles:
  - name: cognition
    permissions: [read, write]
    resources: ["memory/**"]
assignments:
  - subject: "agent:planner"
    roles: [cognition]
"#;

fn capability<P: typesec_core::Permission>(space: &MemorySpace) -> Capability<P, MemorySpace> {
    let engine = typesec_rbac::RbacEngine::from_yaml(POLICY).unwrap();
    mint_capability_for_id(
        &engine,
        "agent:planner",
        space.resource_id(),
        &MintOptions::default(),
    )
    .unwrap()
}

fn fixture() -> (
    MemoryVault<InMemoryStore>,
    MemorySpace,
    Capability<CanRead, MemorySpace>,
    typesec_memory::MemoryId,
) {
    let space = MemorySpace::new("tenant:one", "research");
    let vault = MemoryVault::new(InMemoryStore::new());
    let write: Capability<CanWrite, _> = capability(&space);
    let read = capability(&space);
    let id = vault
        .remember(
            &space,
            &write,
            MemoryDraft::new(
                MemoryKind::Semantic,
                MemoryContent::text("private source revision"),
                Provenance::Operator,
            )
            .with_label(Label::Sensitive)
            .for_purposes(["research"]),
        )
        .unwrap();
    (vault, space, read, id)
}

#[test]
fn memories_and_manifest_share_the_exact_loaded_revision() {
    let (vault, space, read, id) = fixture();
    let context = RequestContext::new().with_purpose("research");
    let input = vault
        .cognition_input_at(
            &space,
            &read,
            std::slice::from_ref(&id),
            &context,
            Label::Sensitive,
        )
        .unwrap();

    assert_eq!(input.memories().len(), 1);
    assert_eq!(input.memories()[0].content.text, "private source revision");
    let loaded = vault.store().get(&id).unwrap().unwrap();
    assert_eq!(
        input.manifest().sources[0],
        CognitionSourcePrecondition::for_record(&loaded).unwrap()
    );

    vault.store().invalidate(&id, Utc::now()).unwrap();
    let changed = vault.store().get(&id).unwrap().unwrap();
    assert_ne!(
        input.manifest().sources[0],
        CognitionSourcePrecondition::for_record(&changed).unwrap()
    );
    assert_eq!(input.memories()[0].content.text, "private source revision");
}

#[test]
fn cognition_input_requires_purpose_and_clearance_before_reveal() {
    let (vault, space, read, id) = fixture();
    assert!(matches!(
        vault.cognition_input_at(
            &space,
            &read,
            std::slice::from_ref(&id),
            &RequestContext::new(),
            Label::Sensitive,
        ),
        Err(MemoryError::Cognition(CognitionApplyError::MissingPurpose))
    ));
    assert!(matches!(
        vault.cognition_input_at(
            &space,
            &read,
            &[id],
            &RequestContext::new().with_purpose("research"),
            Label::Public,
        ),
        Err(MemoryError::AboveCeiling { .. })
    ));
}
