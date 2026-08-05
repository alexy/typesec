use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use typesec_core::policy::{
    MintOptions, PolicyEngine, PolicyResult, RequestContext, SubjectId, mint_capability_for_id,
};
use typesec_core::{CanRead, CanWrite, Capability, Resource, ResourceId};

use super::*;
use crate::index::IndexMutation;
use crate::record::{MemoryContent, MemoryDraft, Provenance, StoredRecord};
use crate::space::{MemoryId, MemoryKind, MemorySpace};
use crate::store::{MemoryStore, StoreBatchOp, StoreError, StoreQuery};
use crate::vault::{ConsolidationPlan, ConsolidationStep, MemoryVault};
use crate::{CognitionProposal, Label, MemoryError};

#[derive(Default)]
struct AllowPolicy;

impl PolicyEngine for AllowPolicy {
    fn check(&self, _subject: &SubjectId, _action: &str, _resource: &ResourceId) -> PolicyResult {
        PolicyResult::Allow
    }
}

#[derive(Default)]
struct MutableAuthority {
    current: Mutex<Option<CognitionAuthorityEvidence>>,
}

impl MutableAuthority {
    fn set(&self, evidence: CognitionAuthorityEvidence) {
        *self.current.lock().expect("authority lock") = Some(evidence);
    }
}

impl CognitionAuthorityVerifier for MutableAuthority {
    fn revalidate(
        &self,
        _binding: &CognitionBinding,
        _context: &RequestContext,
    ) -> Result<CognitionAuthorityEvidence, CognitionApplyError> {
        self.current
            .lock()
            .expect("authority lock")
            .clone()
            .ok_or_else(|| CognitionApplyError::Authority("no current evidence".into()))
    }
}

#[derive(Clone, Default)]
struct TransactionalTestStore {
    state: Arc<Mutex<TestState>>,
}

#[derive(Default)]
struct TestState {
    records: HashMap<MemoryId, StoredRecord>,
    applications: BTreeMap<CognitionIdempotencyKey, StoredApplication>,
    outbox: Vec<IndexMutation>,
    audits: Vec<CognitionAuditEvidence>,
    version: u64,
    fail_precondition_once: bool,
}

#[derive(Clone)]
struct StoredApplication {
    proposal_digest: String,
    outcome: CognitionCommitOutcome,
}

impl TransactionalTestStore {
    fn state(&self) -> std::sync::MutexGuard<'_, TestState> {
        self.state.lock().expect("test store lock")
    }

    fn fail_next_precondition(&self) {
        self.state().fail_precondition_once = true;
    }
}

impl MemoryStore for TransactionalTestStore {
    fn put(&self, record: StoredRecord) -> Result<(), StoreError> {
        self.state().records.insert(record.id.clone(), record);
        Ok(())
    }

    fn get(&self, id: &MemoryId) -> Result<Option<StoredRecord>, StoreError> {
        Ok(self.state().records.get(id).cloned())
    }

    fn query(&self, query: &StoreQuery) -> Result<Vec<StoredRecord>, StoreError> {
        let mut records: Vec<_> = self
            .state()
            .records
            .values()
            .filter(|record| query.matches(record))
            .cloned()
            .collect();
        records.sort_by(|left, right| left.id.cmp(&right.id));
        if let Some(limit) = query.limit {
            records.truncate(limit);
        }
        Ok(records)
    }

    fn invalidate(&self, id: &MemoryId, at: DateTime<Utc>) -> Result<(), StoreError> {
        let mut state = self.state();
        let record = state
            .records
            .get_mut(id)
            .ok_or_else(|| StoreError::Backend(format!("no record {id}")))?;
        record.invalid_at = Some(at);
        Ok(())
    }

    fn tombstone(&self, id: &MemoryId) -> Result<bool, StoreError> {
        Ok(self.state().records.remove(id).is_some())
    }
}

impl CognitionCommitStore for TransactionalTestStore {
    fn recover_cognition(
        &self,
        key: &CognitionIdempotencyKey,
        proposal_digest: &str,
    ) -> Result<Option<CognitionCommitOutcome>, CognitionCommitError> {
        let state = self.state();
        let Some(previous) = state.applications.get(key) else {
            return Ok(None);
        };
        if previous.proposal_digest != proposal_digest {
            return Err(CognitionCommitError::IdempotencyConflict);
        }
        let mut recovered = previous.outcome.clone();
        recovered.status = CognitionCommitStatus::AlreadyApplied;
        Ok(Some(recovered))
    }

    fn commit_cognition(
        &self,
        commit: PreparedCognitionCommit,
    ) -> Result<CognitionCommitOutcome, CognitionCommitError> {
        let mut state = self.state();
        if let Some(previous) = state.applications.get(&commit.idempotency_key) {
            if previous.proposal_digest != commit.proposal_digest {
                return Err(CognitionCommitError::IdempotencyConflict);
            }
            let mut recovered = previous.outcome.clone();
            recovered.status = CognitionCommitStatus::AlreadyApplied;
            return Ok(recovered);
        }
        if std::mem::take(&mut state.fail_precondition_once) {
            return Err(CognitionCommitError::StaleSource(
                commit.source_preconditions[0].id.clone(),
            ));
        }
        for expected in &commit.source_preconditions {
            let current = state
                .records
                .get(&expected.id)
                .ok_or_else(|| CognitionCommitError::StaleSource(expected.id.clone()))?;
            if CognitionSourcePrecondition::for_record(current)?.record_digest
                != expected.record_digest
            {
                return Err(CognitionCommitError::StaleSource(expected.id.clone()));
            }
        }

        let mut next_records = state.records.clone();
        for operation in &commit.operations {
            match operation {
                StoreBatchOp::Put(record) => {
                    next_records.insert(record.id.clone(), (**record).clone());
                }
                StoreBatchOp::Invalidate { id, at } => {
                    let record = next_records
                        .get_mut(id)
                        .ok_or_else(|| CognitionCommitError::StaleSource(id.clone()))?;
                    record.invalid_at = Some(*at);
                }
            }
        }

        let prior = state.version;
        let resulting = prior + 1;
        let outcome = CognitionCommitOutcome {
            status: CognitionCommitStatus::Applied,
            backend_commit_hash: format!(
                "test-commit-{resulting}-{}",
                &commit.proposal_digest[7..19]
            ),
            prior_version: prior.to_string(),
            resulting_version: resulting.to_string(),
            affected_ids: commit.audit.affected_ids.clone(),
        };
        state.records = next_records;
        state.version = resulting;
        state.outbox.extend(commit.index_outbox);
        state.audits.push(commit.audit);
        state.applications.insert(
            commit.idempotency_key,
            StoredApplication {
                proposal_digest: commit.proposal_digest,
                outcome: outcome.clone(),
            },
        );
        Ok(outcome)
    }
}

impl From<CognitionApplyError> for CognitionCommitError {
    fn from(error: CognitionApplyError) -> Self {
        Self::Store(StoreError::Backend(error.to_string()))
    }
}

struct Fixture {
    store: TransactionalTestStore,
    vault: MemoryVault<TransactionalTestStore>,
    authority: Arc<MutableAuthority>,
    policy: Arc<AllowPolicy>,
    space: MemorySpace,
    source: MemoryId,
    write: Capability<CanWrite, MemorySpace>,
    context: RequestContext,
    binding: CognitionBinding,
}

impl Fixture {
    fn new() -> Self {
        let store = TransactionalTestStore::default();
        let authority = Arc::new(MutableAuthority::default());
        let policy = Arc::new(AllowPolicy);
        let space = MemorySpace::new("tenant:acme", "research");
        let context = RequestContext::new().with_purpose("research");
        let read = mint::<CanRead>(&policy, &space, &context);
        let write = mint::<CanWrite>(&policy, &space, &context);
        let vault = MemoryVault::new(store.clone())
            .with_policy(policy.clone())
            .with_cognition_authority(authority.clone());
        let source = vault
            .remember(
                &space,
                &write,
                MemoryDraft::new(
                    MemoryKind::Semantic,
                    MemoryContent::text("private source text"),
                    Provenance::Operator,
                )
                .with_label(Label::Sensitive)
                .for_purposes(["research"]),
            )
            .expect("source write");
        let manifest = vault
            .cognition_source_manifest(&space, &read, std::slice::from_ref(&source), &context)
            .expect("source manifest");
        let binding = CognitionBinding {
            space_id: space.resource_id().to_owned(),
            subject: "did:key:researcher".into(),
            purpose: "research".into(),
            governed_scan_digest: digest("governed scan"),
            snapshot_digest: digest("snapshot 42"),
            plan_task_digest: digest("plan token"),
            authorization_receipt_digest: digest("authorization receipt"),
            effective_projection: vec!["id".into(), "text".into(), "valid_from".into()],
            source_manifest_digest: manifest.digest,
            typedid_request_digest: digest("TypeDID request"),
        };
        authority.set(authority_for(&binding));
        Self {
            store,
            vault,
            authority,
            policy,
            space,
            source,
            write,
            context,
            binding,
        }
    }

    fn proposal(&self) -> CognitionProposal {
        CognitionProposal::new(
            "job-42",
            self.binding.governed_scan_digest.clone(),
            self.binding.source_manifest_digest.clone(),
            "marciana.summarize.sail",
            "1",
            vec![self.source.clone()],
            Label::Sensitive,
        )
        .with_plan(
            ConsolidationPlan::new().then(ConsolidationStep::Supersede {
                superseded: vec![self.source.clone()],
                replacement: MemoryDraft::new(
                    MemoryKind::Semantic,
                    MemoryContent::text("derived summary"),
                    Provenance::Operator,
                )
                .with_label(Label::Public),
            }),
        )
        .with_binding(self.binding.clone())
    }
}

fn mint<P: typesec_core::Permission>(
    policy: &Arc<AllowPolicy>,
    space: &MemorySpace,
    context: &RequestContext,
) -> Capability<P, MemorySpace> {
    mint_capability_for_id(
        policy.as_ref(),
        "did:key:researcher",
        space.resource_id(),
        &MintOptions {
            context: context.clone(),
            ..MintOptions::default()
        },
    )
    .expect("capability")
}

fn authority_for(binding: &CognitionBinding) -> CognitionAuthorityEvidence {
    CognitionAuthorityEvidence {
        space_id: binding.space_id.clone(),
        subject: binding.subject.clone(),
        purpose: binding.purpose.clone(),
        governed_scan_digest: binding.governed_scan_digest.clone(),
        snapshot_digest: binding.snapshot_digest.clone(),
        plan_task_digest: binding.plan_task_digest.clone(),
        authorization_receipt_digest: binding.authorization_receipt_digest.clone(),
        effective_projection: binding.effective_projection.clone(),
        typedid_request_digest: binding.typedid_request_digest.clone(),
        policy_decision_id: "policy-decision-7".into(),
    }
}

fn digest(value: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{:x}", Sha256::digest(value.as_bytes()))
}

#[test]
fn valid_application_commits_joined_lineage_and_id_only_evidence() {
    let fixture = Fixture::new();
    let outcome = fixture
        .vault
        .apply_cognition(
            &fixture.space,
            &fixture.write,
            &fixture.proposal(),
            &fixture.context,
        )
        .expect("apply cognition");
    assert_eq!(outcome.status, CognitionCommitStatus::Applied);

    let state = fixture.store.state();
    assert_eq!(state.applications.len(), 1);
    assert_eq!(state.audits.len(), 1);
    assert_eq!(state.outbox.len(), 2);
    let created = outcome
        .affected_ids
        .iter()
        .find(|id| *id != &fixture.source)
        .expect("created id");
    let record = state.records.get(created).expect("derived record");
    assert_eq!(record.label, Label::Sensitive, "worker cannot lower join");
    assert_eq!(record.purposes, ["research"]);
    assert!(matches!(
        &record.provenance,
        Provenance::Cognition { job_id, source_ids, .. }
            if job_id == "job-42" && source_ids == std::slice::from_ref(&fixture.source)
    ));
    assert!(state.records[&fixture.source].invalid_at.is_some());
    assert!(state.outbox.iter().all(|mutation| matches!(
        mutation,
        IndexMutation::Upsert(_) | IndexMutation::Remove(_)
    )));
    let audit_json = serde_json::to_string(&state.audits).expect("audit serialization");
    assert!(!audit_json.contains("private source text"));
    assert!(!audit_json.contains("derived summary"));
}

#[test]
fn retry_recovers_one_commit_and_conflicting_payload_is_rejected() {
    let fixture = Fixture::new();
    let proposal = fixture.proposal();
    let first = fixture
        .vault
        .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context)
        .expect("first apply");
    let retry = fixture
        .vault
        .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context)
        .expect("idempotent retry");
    assert_eq!(retry.status, CognitionCommitStatus::AlreadyApplied);
    assert_eq!(retry.backend_commit_hash, first.backend_commit_hash);
    assert_eq!(retry.affected_ids, first.affected_ids);
    assert_eq!(fixture.store.state().audits.len(), 1);

    let mut conflicting = proposal;
    conflicting.evidence.push("different proposal bytes".into());
    assert!(matches!(
        fixture.vault.apply_cognition(
            &fixture.space,
            &fixture.write,
            &conflicting,
            &fixture.context
        ),
        Err(MemoryError::CognitionCommit(
            CognitionCommitError::IdempotencyConflict
        ))
    ));
    assert_eq!(fixture.store.state().audits.len(), 1);
}

#[test]
fn policy_verifier_binding_and_plan_checks_fail_closed() {
    let fixture = Fixture::new();
    let proposal = fixture.proposal();
    let no_policy =
        MemoryVault::new(fixture.store.clone()).with_cognition_authority(fixture.authority.clone());
    assert!(matches!(
        no_policy.apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context),
        Err(MemoryError::Cognition(
            CognitionApplyError::PolicyUnavailable
        ))
    ));
    let no_verifier = MemoryVault::new(fixture.store.clone()).with_policy(fixture.policy.clone());
    assert!(matches!(
        no_verifier.apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context),
        Err(MemoryError::Cognition(
            CognitionApplyError::AuthorityVerifierUnavailable
        ))
    ));

    let mut changed = authority_for(&fixture.binding);
    changed.snapshot_digest = digest("new snapshot");
    fixture.authority.set(changed);
    assert!(matches!(
        fixture
            .vault
            .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context),
        Err(MemoryError::Cognition(
            CognitionApplyError::BindingMismatch("snapshot digest")
        ))
    ));
    fixture.authority.set(authority_for(&fixture.binding));

    let mut outside = fixture.proposal();
    outside.plan = ConsolidationPlan::new().then(ConsolidationStep::Invalidate {
        ids: vec![MemoryId::from_string("other-source")],
    });
    assert!(matches!(
        fixture
            .vault
            .apply_cognition(&fixture.space, &fixture.write, &outside, &fixture.context),
        Err(MemoryError::Cognition(CognitionApplyError::InvalidPlan(_)))
    ));
    let state = fixture.store.state();
    assert!(state.applications.is_empty());
    assert!(state.outbox.is_empty());
}

#[test]
fn source_change_and_transaction_race_leave_no_partial_cognition_state() {
    let fixture = Fixture::new();
    let proposal = fixture.proposal();
    let mut changed = fixture
        .store
        .get(&fixture.source)
        .expect("store")
        .expect("source");
    changed.label = Label::Secret;
    fixture.store.put(changed).expect("replace source revision");
    assert!(matches!(
        fixture
            .vault
            .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context),
        Err(MemoryError::Cognition(
            CognitionApplyError::SourceManifestMismatch
        ))
    ));
    assert!(fixture.store.state().applications.is_empty());

    let fresh = Fixture::new();
    fresh.store.fail_next_precondition();
    assert!(matches!(
        fresh.vault.apply_cognition(
            &fresh.space,
            &fresh.write,
            &fresh.proposal(),
            &fresh.context
        ),
        Err(MemoryError::CognitionCommit(
            CognitionCommitError::StaleSource(_)
        ))
    ));
    let state = fresh.store.state();
    assert!(state.applications.is_empty());
    assert!(state.outbox.is_empty());
    assert!(state.audits.is_empty());
    assert!(state.records[&fresh.source].invalid_at.is_none());
}

#[test]
fn proposal_and_plan_round_trip_for_durable_job_storage() {
    let fixture = Fixture::new();
    let proposal = fixture.proposal();
    let encoded = serde_json::to_vec(&proposal).expect("serialize proposal");
    let decoded: CognitionProposal =
        serde_json::from_slice(&encoded).expect("deserialize proposal");
    assert_eq!(decoded.job_id, proposal.job_id);
    assert_eq!(decoded.binding, proposal.binding);
    assert_eq!(decoded.plan.steps.len(), 1);
}
