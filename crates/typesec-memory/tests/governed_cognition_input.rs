use std::sync::Arc;

use typesec_core::policy::{MintOptions, RequestContext, mint_capability_for_id};
use typesec_core::{CanRead, CanWrite, Capability};
use typesec_memory::{
    CognitionApplyError, GovernedSourceScope, GovernedSourceVerification,
    GovernedSourceVerificationError, GovernedSourceVerifier, InMemoryStore, Label, MemoryContent,
    MemoryDraft, MemoryError, MemoryId, MemoryKind, MemorySpace, MemoryVault, Provenance, Resource,
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

struct AllowGovernedSource;

impl GovernedSourceVerifier for AllowGovernedSource {
    fn verify(
        &self,
        _request: &GovernedSourceVerification<'_>,
    ) -> Result<(), GovernedSourceVerificationError> {
        Ok(())
    }
}

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

fn scope(fill: char) -> GovernedSourceScope {
    GovernedSourceScope::from_digest(format!("sha256:{}", fill.to_string().repeat(64))).unwrap()
}

fn draft(text: &str) -> MemoryDraft {
    MemoryDraft::new(
        MemoryKind::Semantic,
        MemoryContent::text(text),
        Provenance::Operator,
    )
    .for_purposes(["research"])
}

fn assert_scope_mismatch<T>(result: Result<T, MemoryError>) {
    assert!(matches!(
        result,
        Err(MemoryError::Cognition(
            CognitionApplyError::SourceScopeMismatch
        ))
    ));
}

#[test]
fn local_and_governed_cognition_inputs_are_fail_closed_and_distinct() {
    let space = MemorySpace::new("tenant:one", "research");
    let write: Capability<CanWrite, _> = capability(&space);
    let read: Capability<CanRead, _> = capability(&space);
    let vault = MemoryVault::new(InMemoryStore::new())
        .with_governed_source_verifier(Arc::new(AllowGovernedSource));
    let context = RequestContext::new().with_purpose("research");
    let first_scope = scope('a');
    let second_scope = scope('b');

    let local = vault.remember(&space, &write, draft("local")).unwrap();
    let governed = vault
        .remember_governed(
            &space,
            &write,
            draft("governed"),
            &first_scope,
            b"proof-1",
            &context,
        )
        .unwrap();
    let differently_governed = vault
        .remember_governed(
            &space,
            &write,
            draft("other scope"),
            &second_scope,
            b"proof-2",
            &context,
        )
        .unwrap();

    assert_scope_mismatch(vault.cognition_input_at(
        &space,
        &read,
        std::slice::from_ref(&governed),
        &context,
        Label::Sensitive,
    ));
    assert_scope_mismatch(vault.governed_cognition_input_at(
        &space,
        &read,
        std::slice::from_ref(&local),
        &context,
        Label::Sensitive,
        &first_scope,
    ));
    assert_scope_mismatch(vault.governed_cognition_input_at(
        &space,
        &read,
        std::slice::from_ref(&differently_governed),
        &context,
        Label::Sensitive,
        &first_scope,
    ));
    assert_scope_mismatch(vault.governed_cognition_input_at(
        &space,
        &read,
        &[governed.clone(), local],
        &context,
        Label::Sensitive,
        &first_scope,
    ));

    let input = vault
        .governed_cognition_input_at(
            &space,
            &read,
            std::slice::from_ref(&governed),
            &context,
            Label::Sensitive,
            &first_scope,
        )
        .unwrap();
    assert_eq!(input.governed_source_scope(), Some(&first_scope));
    assert_eq!(input.memories()[0].content.text, "governed");
}

#[test]
fn manifest_paths_apply_the_same_exact_scope_rule() {
    let space = MemorySpace::new("tenant:one", "research");
    let write: Capability<CanWrite, _> = capability(&space);
    let read: Capability<CanRead, _> = capability(&space);
    let vault = MemoryVault::new(InMemoryStore::new())
        .with_governed_source_verifier(Arc::new(AllowGovernedSource));
    let context = RequestContext::new().with_purpose("research");
    let expected = scope('c');
    let id = vault
        .remember_governed(
            &space,
            &write,
            draft("governed"),
            &expected,
            b"proof",
            &context,
        )
        .unwrap();

    assert_scope_mismatch(vault.cognition_source_manifest(
        &space,
        &read,
        std::slice::from_ref(&id),
        &context,
    ));
    let manifest = vault
        .governed_cognition_source_manifest(
            &space,
            &read,
            std::slice::from_ref(&id),
            &context,
            &expected,
        )
        .unwrap();
    assert_eq!(
        manifest.sources[0].id,
        MemoryId::from_string(id.to_string())
    );
}
