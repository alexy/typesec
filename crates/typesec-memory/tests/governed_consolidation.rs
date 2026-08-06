use std::sync::Arc;

use typesec_core::policy::{MintOptions, RequestContext, mint_capability_for_id};
use typesec_core::{CanWrite, Capability};
use typesec_memory::store::{InMemoryStore, MemoryStore};
use typesec_memory::{
    ConsolidationPlan, ConsolidationStep, GovernedSourceScope, GovernedSourceVerification,
    GovernedSourceVerificationError, GovernedSourceVerifier, MemoryContent, MemoryDraft,
    MemoryError, MemoryKind, MemorySpace, MemoryVault, Provenance, Resource,
};

const POLICY: &str = r#"
roles: [{name: writer, permissions: [write], resources: ["memory/**"]}]
assignments: [{subject: "agent:writer", roles: [writer]}]
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

fn capability(space: &MemorySpace) -> Capability<CanWrite, MemorySpace> {
    let engine = typesec_rbac::RbacEngine::from_yaml(POLICY).unwrap();
    mint_capability_for_id(
        &engine,
        "agent:writer",
        space.resource_id(),
        &MintOptions::default(),
    )
    .unwrap()
}

fn draft(text: &str) -> MemoryDraft {
    MemoryDraft::new(
        MemoryKind::Semantic,
        MemoryContent::text(text),
        Provenance::Operator,
    )
}

fn scope() -> GovernedSourceScope {
    GovernedSourceScope::from_digest(format!("sha256:{}", "d".repeat(64))).unwrap()
}

#[test]
fn supersede_preserves_a_unanimous_governed_scope() {
    let space = MemorySpace::new("tenant:one", "research");
    let capability = capability(&space);
    let scope = scope();
    let context = RequestContext::new();
    let vault = MemoryVault::new(InMemoryStore::new())
        .with_governed_source_verifier(Arc::new(AllowGovernedSource));
    let source = vault
        .remember_governed(
            &space,
            &capability,
            draft("source"),
            &scope,
            b"proof",
            &context,
        )
        .unwrap();

    let report = vault
        .consolidate(
            &space,
            &capability,
            ConsolidationPlan::new().then(ConsolidationStep::Supersede {
                superseded: vec![source],
                replacement: draft("summary"),
            }),
        )
        .unwrap();
    let replacement = vault.store().get(&report.created[0]).unwrap().unwrap();
    assert_eq!(replacement.governed_source_scope(), Some(&scope));
}

#[test]
fn supersede_rejects_mixed_scopes_without_partial_mutation() {
    let space = MemorySpace::new("tenant:one", "research");
    let capability = capability(&space);
    let scope = scope();
    let vault = MemoryVault::new(InMemoryStore::new())
        .with_governed_source_verifier(Arc::new(AllowGovernedSource));
    let governed = vault
        .remember_governed(
            &space,
            &capability,
            draft("governed"),
            &scope,
            b"proof",
            &RequestContext::new(),
        )
        .unwrap();
    let local = vault.remember(&space, &capability, draft("local")).unwrap();

    let error = vault
        .consolidate(
            &space,
            &capability,
            ConsolidationPlan::new().then(ConsolidationStep::Supersede {
                superseded: vec![governed.clone(), local.clone()],
                replacement: draft("must not exist"),
            }),
        )
        .unwrap_err();
    assert!(matches!(error, MemoryError::GovernedSourceScopeMismatch));
    assert!(
        vault
            .store()
            .get(&governed)
            .unwrap()
            .unwrap()
            .invalid_at
            .is_none()
    );
    assert!(
        vault
            .store()
            .get(&local)
            .unwrap()
            .unwrap()
            .invalid_at
            .is_none()
    );
    assert_eq!(vault.store().len(), 2);
}
