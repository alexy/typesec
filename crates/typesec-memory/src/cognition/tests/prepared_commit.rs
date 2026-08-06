use chrono::{DateTime, TimeDelta, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use typesec_core::Resource;

use super::*;

#[test]
fn digest_is_canonical_repeatable_and_plaintext_opaque() {
    let commit = prepared_fixture(prepared_at()).commit;

    let digest = commit.canonical_digest().expect("prepared commit digest");
    assert!(is_canonical_sha256(&digest));
    assert_eq!(
        digest,
        "sha256:88f1060a04a33319ba4f4734bad088ea394bfd0713c701975f3ac6e9d840b6b3"
    );
    assert_eq!(digest, commit.canonical_digest().unwrap());
    assert_ne!(digest, commit.proposal_digest());
    assert!(!digest.contains("private source text"));
    assert!(!digest.contains("derived summary"));

    assert_eq!(commit.idempotency_key().job_id(), "job-42");
    assert_eq!(commit.effect(), CognitionEffect::Mutated);
    assert_eq!(commit.proposal_digest(), commit.audit().proposal_digest);
    assert_eq!(commit.source_preconditions().len(), 1);
    assert!(!commit.operations().is_empty());
    let created = commit
        .operations()
        .iter()
        .find_map(|operation| match operation {
            StoreBatchOp::Put(record) => Some(record.as_ref()),
            StoreBatchOp::Invalidate { .. } => None,
        })
        .expect("prepared record write");
    assert_eq!(created.observed_at, prepared_at());
    assert_eq!(created.valid_from, prepared_at());
    assert!(!commit.index_outbox().is_empty());
    assert!(commit.index_outbox().iter().all(|mutation| matches!(
        mutation,
        IndexMutation::Upsert(_) | IndexMutation::Remove(_)
    )));
}

#[test]
fn digest_is_stable_for_identical_preparation_and_binds_prepared_at() {
    let at = prepared_at();
    let first = prepared_fixture(at).commit;
    let identical = prepared_fixture(at).commit;
    let later = prepared_fixture(at + TimeDelta::seconds(1)).commit;

    assert_eq!(
        first.canonical_digest().unwrap(),
        identical.canonical_digest().unwrap()
    );
    assert_ne!(
        first.canonical_digest().unwrap(),
        later.canonical_digest().unwrap()
    );
}

#[test]
fn digest_binds_distinct_grant_snapshot_and_revalidation_evidence() {
    let at = prepared_at();
    let baseline = prepared_fixture(at).commit;
    let changed_grant = prepared_fixture_with_evidence(
        at,
        None,
        "other governed scan",
        "snapshot 42",
        DateTime::<Utc>::UNIX_EPOCH,
    )
    .commit;
    let changed_snapshot = prepared_fixture_with_evidence(
        at,
        None,
        "governed scan",
        "snapshot 43",
        DateTime::<Utc>::UNIX_EPOCH,
    )
    .commit;
    let changed_revalidation = prepared_fixture_with_evidence(
        at,
        None,
        "governed scan",
        "snapshot 42",
        DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1),
    )
    .commit;

    for changed in [changed_grant, changed_snapshot, changed_revalidation] {
        assert_ne!(
            baseline.canonical_digest().unwrap(),
            changed.canonical_digest().unwrap()
        );
    }
    assert_eq!(
        baseline.audit().schema_version,
        CognitionAuditEvidence::SCHEMA_VERSION
    );
    assert_ne!(
        baseline.audit().governed_scan_digest,
        baseline.audit().snapshot_digest
    );
}

#[test]
fn streaming_hashing_matches_the_versioned_canonical_profiles() {
    let fixture = prepared_fixture(prepared_at());

    let mut canonical_binding = fixture.binding.clone();
    canonical_binding.effective_projection.sort();
    assert_eq!(
        fixture.binding.canonical_digest().unwrap(),
        legacy_digest(b"typesec.marciana.binding.v1\0", &canonical_binding)
    );

    let mut canonical_proposal = fixture.proposal.clone();
    canonical_proposal.created_at = DateTime::<Utc>::UNIX_EPOCH;
    canonical_proposal
        .binding
        .as_mut()
        .expect("bound proposal")
        .effective_projection
        .sort();
    assert_eq!(
        fixture.proposal.canonical_digest().unwrap(),
        legacy_digest(b"typesec.marciana.proposal.v2\0", &canonical_proposal)
    );

    assert_eq!(fixture.manifest.sources.len(), fixture.sources.len());
    for (precondition, source) in fixture.manifest.sources.iter().zip(&fixture.sources) {
        assert_eq!(
            precondition.record_digest,
            legacy_digest(b"typesec.marciana.source-record.v1\0", source)
        );
    }
    assert_eq!(
        fixture.manifest.digest,
        legacy_digest(
            b"typesec.marciana.source-manifest.v1\0",
            &fixture.manifest.sources
        )
    );

    let evidence = vec!["model=v1".to_owned(), "temperature=0".to_owned()];
    assert_eq!(
        super::super::digest::evidence_digest(&evidence).unwrap(),
        legacy_digest(b"typesec.marciana.evidence.v1\0", &evidence)
    );
}

#[test]
fn governed_scope_is_bound_into_the_prepared_commit_and_outputs() {
    let at = prepared_at();
    let scope = GovernedSourceScope::from_digest(format!("sha256:{}", "a".repeat(64))).unwrap();
    let local = prepared_fixture(at).commit;
    let governed = prepared_fixture_with_scope(at, Some(scope.clone())).commit;

    assert_ne!(
        local.canonical_digest().unwrap(),
        governed.canonical_digest().unwrap()
    );
    assert_eq!(governed.audit().governed_source_scope, Some(scope.clone()));
    let created = governed
        .operations()
        .iter()
        .find_map(|operation| match operation {
            StoreBatchOp::Put(record) => Some(record.as_ref()),
            StoreBatchOp::Invalidate { .. } => None,
        })
        .expect("prepared record write");
    assert_eq!(created.governed_source_scope(), Some(&scope));
}

struct PreparedFixture {
    commit: PreparedCognitionCommit,
    proposal: CognitionProposal,
    binding: CognitionBinding,
    sources: Vec<StoredRecord>,
    manifest: CognitionSourceManifest,
}

fn prepared_fixture(now: DateTime<Utc>) -> PreparedFixture {
    prepared_fixture_with_scope(now, None)
}

fn prepared_fixture_with_scope(
    now: DateTime<Utc>,
    governed_source_scope: Option<GovernedSourceScope>,
) -> PreparedFixture {
    prepared_fixture_with_evidence(
        now,
        governed_source_scope,
        "governed scan",
        "snapshot 42",
        DateTime::<Utc>::UNIX_EPOCH,
    )
}

fn prepared_fixture_with_evidence(
    now: DateTime<Utc>,
    governed_source_scope: Option<GovernedSourceScope>,
    governed_scan: &str,
    snapshot: &str,
    authority_revalidated_at: DateTime<Utc>,
) -> PreparedFixture {
    let space = MemorySpace::new("tenant:acme", "research");
    let source_id = MemoryId::from_string("mem-source-1");
    let source_time = prepared_at() - TimeDelta::hours(1);
    let sources = vec![StoredRecord::assemble(
        source_id.clone(),
        space.resource_id().to_owned(),
        MemoryKind::Semantic,
        Label::Sensitive,
        false,
        Vec::new(),
        Provenance::Operator,
        governed_source_scope.clone(),
        source_time,
        source_time,
        None,
        vec!["research".into()],
        MemoryContent::text("private source text"),
    )];
    let manifest = super::super::digest::source_manifest(&sources).expect("source manifest");
    let binding = CognitionBinding {
        space_id: space.resource_id().to_owned(),
        subject: "did:key:researcher".into(),
        purpose: "research".into(),
        governed_source_scope,
        governed_scan_digest: super::digest(governed_scan),
        snapshot_digest: super::digest(snapshot),
        plan_task_digest: super::digest("plan token"),
        authorization_receipt_digest: super::digest("authorization receipt"),
        effective_projection: vec!["id".into(), "text".into(), "valid_from".into()],
        source_manifest_digest: manifest.digest.clone(),
        typedid_request_digest: super::digest("TypeDID request"),
    };
    let proposal = CognitionProposal::new(
        "job-42",
        binding.snapshot_digest.clone(),
        binding.source_manifest_digest.clone(),
        "marciana.summarize.sail",
        "1",
        vec![source_id.clone()],
        Label::Sensitive,
    )
    .with_plan(
        ConsolidationPlan::new().then(ConsolidationStep::Supersede {
            superseded: vec![source_id],
            replacement: MemoryDraft::new(
                MemoryKind::Semantic,
                MemoryContent::text("derived summary"),
                Provenance::Operator,
            )
            .with_label(Label::Public),
        }),
    )
    .with_binding(binding.clone());
    super::super::validate::validate_proposal_for_application(&proposal)
        .expect("valid cognition proposal");
    let identity = super::super::identity::CognitionCommitIdentity::from_validated(
        &space, &proposal, &binding,
    )
    .expect("commit identity");
    let mut authority = authority_for(&binding);
    authority.authority_revalidated_at = authority_revalidated_at;
    let commit = super::super::prepare::prepare_commit(
        &space,
        &proposal,
        &binding,
        &authority,
        &sources,
        manifest.clone(),
        &identity,
        now,
    )
    .expect("prepare cognition commit");
    PreparedFixture {
        commit,
        proposal,
        binding,
        sources,
        manifest,
    }
}

fn prepared_at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-05T12:34:56Z")
        .expect("fixed time")
        .with_timezone(&Utc)
}

fn is_canonical_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn legacy_digest(domain: &[u8], value: &impl Serialize) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(serde_json::to_vec(value).expect("legacy canonical serialization"));
    format!("sha256:{:x}", digest.finalize())
}
