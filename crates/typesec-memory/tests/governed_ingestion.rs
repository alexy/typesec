use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use typesec_core::policy::{
    MintOptions, PolicyEngine, PolicyResult, RequestContext, SubjectId, mint_capability_for_id,
};
use typesec_core::{CanWrite, Capability, ResourceId};
use typesec_memory::store::{InMemoryStore, MemoryStore};
use typesec_memory::{
    GovernedSourceScope, GovernedSourceVerification, GovernedSourceVerificationError,
    GovernedSourceVerifier, MAX_GOVERNED_SOURCE_EVIDENCE_BYTES, MemoryContent, MemoryDraft,
    MemoryError, MemoryKind, MemorySpace, MemoryVault, Provenance, Resource,
    governed_source_draft_digest,
};

const POLICY: &str = r#"
roles:
  - name: writer
    permissions: [write]
    resources: ["memory/**"]
assignments:
  - subject: "agent:ingester"
    roles: [writer]
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
struct SeenVerification {
    scope: String,
    subject: String,
    space_id: String,
    context: RequestContext,
    evidence: Vec<u8>,
    draft_digest: String,
}

#[derive(Default)]
struct RecordingVerifier {
    calls: AtomicUsize,
    fail: AtomicBool,
    seen: Mutex<Vec<SeenVerification>>,
}

impl RecordingVerifier {
    fn failing() -> Self {
        Self {
            fail: AtomicBool::new(true),
            ..Self::default()
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }

    fn seen(&self) -> Vec<SeenVerification> {
        self.seen.lock().expect("verification lock").clone()
    }
}

impl GovernedSourceVerifier for RecordingVerifier {
    fn verify(
        &self,
        request: &GovernedSourceVerification<'_>,
    ) -> Result<(), GovernedSourceVerificationError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.seen
            .lock()
            .expect("verification lock")
            .push(SeenVerification {
                scope: request.scope().to_string(),
                subject: request.subject().to_string(),
                space_id: request.space_id().to_owned(),
                context: request.context().clone(),
                evidence: request.evidence().to_vec(),
                draft_digest: request.draft_digest().to_owned(),
            });
        if self.fail.load(Ordering::Relaxed) {
            Err(GovernedSourceVerificationError::Unavailable)
        } else {
            Ok(())
        }
    }
}

struct DenyPolicy;

impl PolicyEngine for DenyPolicy {
    fn check(&self, _subject: &SubjectId, _action: &str, _resource: &ResourceId) -> PolicyResult {
        PolicyResult::Deny("test denial with private detail".into())
    }
}

struct ExactDraftVerifier {
    allowed_digest: String,
}

impl GovernedSourceVerifier for ExactDraftVerifier {
    fn verify(
        &self,
        request: &GovernedSourceVerification<'_>,
    ) -> Result<(), GovernedSourceVerificationError> {
        if request.draft_digest() == self.allowed_digest {
            Ok(())
        } else {
            Err(GovernedSourceVerificationError::Unavailable)
        }
    }
}

fn fixture() -> (
    MemorySpace,
    Capability<CanWrite, MemorySpace>,
    GovernedSourceScope,
) {
    let space = MemorySpace::new("tenant:one", "governed");
    let engine = typesec_rbac::RbacEngine::from_yaml(POLICY).unwrap();
    let capability = mint_capability_for_id(
        &engine,
        "agent:ingester",
        space.resource_id(),
        &MintOptions::default(),
    )
    .unwrap();
    let scope = GovernedSourceScope::from_digest(format!("sha256:{}", "a".repeat(64))).unwrap();
    (space, capability, scope)
}

fn draft(text: &str) -> MemoryDraft {
    MemoryDraft::new(
        MemoryKind::Semantic,
        MemoryContent::text(text),
        Provenance::Operator,
    )
    .for_purposes(["research"])
}

#[test]
fn governed_ingestion_binds_exact_request_without_persisting_evidence() {
    let (space, capability, scope) = fixture();
    let verifier = Arc::new(RecordingVerifier::default());
    let vault =
        MemoryVault::new(InMemoryStore::new()).with_governed_source_verifier(verifier.clone());
    let context = RequestContext::new()
        .with_purpose("research")
        .with("catalogSnapshot", "snapshot-42");
    let evidence = b"provider-proof-never-persist";

    let id = vault
        .remember_governed(
            &space,
            &capability,
            draft("protected governed fact"),
            &scope,
            evidence,
            &context,
        )
        .unwrap();

    let seen = verifier.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].scope, scope.as_str());
    assert_eq!(seen[0].subject, "agent:ingester");
    assert_eq!(seen[0].space_id, space.resource_id());
    assert_eq!(seen[0].context, context);
    assert_eq!(seen[0].evidence, evidence);
    assert!(seen[0].draft_digest.starts_with("sha256:"));
    assert_eq!(seen[0].draft_digest.len(), 71);
    assert!(!seen[0].draft_digest.contains("protected governed fact"));

    let stored = vault.store().get(&id).unwrap().unwrap();
    assert_eq!(stored.governed_source_scope(), Some(&scope));
    let encoded = serde_json::to_string(&stored).unwrap();
    assert!(encoded.contains(scope.as_str()));
    assert!(!encoded.contains("provider-proof-never-persist"));
}

#[test]
fn authorization_and_evidence_budget_precede_verifier_work() {
    let (space, capability, scope) = fixture();
    let verifier = Arc::new(RecordingVerifier::default());
    let denied = MemoryVault::new(InMemoryStore::new())
        .with_policy(Arc::new(DenyPolicy))
        .with_governed_source_verifier(verifier.clone());
    let context = RequestContext::new().with_purpose("research");

    assert!(matches!(
        denied.remember_governed(
            &space,
            &capability,
            draft("denied"),
            &scope,
            b"evidence",
            &context,
        ),
        Err(MemoryError::PolicyDenied { .. })
    ));
    assert_eq!(verifier.calls(), 0);
    assert!(denied.store().is_empty());

    let bounded =
        MemoryVault::new(InMemoryStore::new()).with_governed_source_verifier(verifier.clone());
    let oversized = vec![0; MAX_GOVERNED_SOURCE_EVIDENCE_BYTES + 1];
    assert!(matches!(
        bounded.remember_governed(
            &space,
            &capability,
            draft("oversized"),
            &scope,
            &oversized,
            &context,
        ),
        Err(MemoryError::GovernedSourceVerification(
            GovernedSourceVerificationError::Unavailable
        ))
    ));
    assert_eq!(verifier.calls(), 0);
    assert!(bounded.store().is_empty());
}

#[test]
fn verifier_failure_is_fixed_and_leaves_no_write() {
    let (space, capability, scope) = fixture();
    let unconfigured = MemoryVault::new(InMemoryStore::new());
    let unavailable = unconfigured
        .remember_governed(
            &space,
            &capability,
            draft("must not persist without a verifier"),
            &scope,
            b"provider-private-diagnostic",
            &RequestContext::new(),
        )
        .unwrap_err();
    assert_eq!(
        unavailable.to_string(),
        "governed source verification is unavailable"
    );
    assert!(unconfigured.store().is_empty());

    let verifier = Arc::new(RecordingVerifier::failing());
    let vault =
        MemoryVault::new(InMemoryStore::new()).with_governed_source_verifier(verifier.clone());

    let error = vault
        .remember_governed(
            &space,
            &capability,
            draft("must not persist"),
            &scope,
            b"provider-private-diagnostic",
            &RequestContext::new(),
        )
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "governed source verification is unavailable"
    );
    assert_eq!(verifier.calls(), 1);
    assert!(vault.store().is_empty());
}

#[test]
fn ordinary_drafts_and_provenance_cannot_claim_a_governed_scope() {
    let (space, capability, scope) = fixture();
    let vault = MemoryVault::new(InMemoryStore::new());
    let original = draft("ordinary local fact");
    let mut forged = serde_json::to_value(&original).unwrap();
    forged
        .as_object_mut()
        .unwrap()
        .insert("governed_source_scope".into(), serde_json::json!(scope));
    assert!(serde_json::from_value::<MemoryDraft>(forged).is_err());

    let id = vault.remember(&space, &capability, original).unwrap();
    assert!(
        vault
            .store()
            .get(&id)
            .unwrap()
            .unwrap()
            .governed_source_scope()
            .is_none()
    );
}

#[test]
fn public_digest_helper_primes_an_exact_draft_allowlist() {
    let (space, capability, scope) = fixture();
    let staged = draft("authenticated staged row");
    let allowed_digest = governed_source_draft_digest(&staged).unwrap();
    let vault = MemoryVault::new(InMemoryStore::new())
        .with_governed_source_verifier(Arc::new(ExactDraftVerifier { allowed_digest }));

    vault
        .remember_governed(
            &space,
            &capability,
            staged,
            &scope,
            b"staging-proof",
            &RequestContext::new(),
        )
        .unwrap();
    assert!(matches!(
        vault.remember_governed(
            &space,
            &capability,
            draft("tampered staged row"),
            &scope,
            b"staging-proof",
            &RequestContext::new(),
        ),
        Err(MemoryError::GovernedSourceVerification(
            GovernedSourceVerificationError::Unavailable
        ))
    ));
    assert_eq!(vault.store().len(), 1);
}
