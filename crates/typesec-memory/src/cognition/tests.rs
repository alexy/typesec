use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
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
use crate::{CognitionProposal, GovernedSourceScope, Label, MemoryError};

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
    calls: AtomicUsize,
}

impl MutableAuthority {
    fn set(&self, evidence: CognitionAuthorityEvidence) {
        *self.current.lock().expect("authority lock") = Some(evidence);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl CognitionAuthorityVerifier for MutableAuthority {
    fn revalidate(
        &self,
        _binding: &CognitionBinding,
        _context: &RequestContext,
    ) -> Result<CognitionAuthorityEvidence, CognitionAuthorityError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.current
            .lock()
            .expect("authority lock")
            .clone()
            .ok_or(CognitionAuthorityError::Unavailable)
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
    replace_scope_before_precondition: Option<GovernedSourceScope>,
    preflight_outcome_mutation: Option<fn(&mut CognitionCommitOutcome)>,
    commit_outcome_mutation: Option<fn(&mut CognitionCommitOutcome)>,
    recovery_calls: usize,
    get_calls: usize,
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

    fn replace_scope_before_precondition(&self, scope: GovernedSourceScope) {
        self.state().replace_scope_before_precondition = Some(scope);
    }
}

impl MemoryStore for TransactionalTestStore {
    fn put(&self, record: StoredRecord) -> Result<(), StoreError> {
        self.state().records.insert(record.id.clone(), record);
        Ok(())
    }

    fn get(&self, id: &MemoryId) -> Result<Option<StoredRecord>, StoreError> {
        let mut state = self.state();
        state.get_calls += 1;
        Ok(state.records.get(id).cloned())
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
        let mut state = self.state();
        state.recovery_calls += 1;
        let Some(previous) = state.applications.get(key) else {
            return Ok(None);
        };
        if previous.proposal_digest != proposal_digest {
            return Err(CognitionCommitError::IdempotencyConflict);
        }
        let mut recovered = previous.outcome.clone();
        recovered.status = CognitionCommitStatus::AlreadyApplied;
        if let Some(mutate) = state.preflight_outcome_mutation {
            mutate(&mut recovered);
        }
        Ok(Some(recovered))
    }

    fn commit_cognition(
        &self,
        commit: PreparedCognitionCommit,
    ) -> Result<CognitionCommitOutcome, CognitionCommitError> {
        let mut state = self.state();
        if let Some(previous) = state.applications.get(commit.idempotency_key()) {
            if previous.proposal_digest != commit.proposal_digest() {
                return Err(CognitionCommitError::IdempotencyConflict);
            }
            let mut recovered = previous.outcome.clone();
            recovered.status = CognitionCommitStatus::AlreadyApplied;
            return Ok(recovered);
        }
        if std::mem::take(&mut state.fail_precondition_once) {
            return Err(CognitionCommitError::StaleSource(
                commit.source_preconditions()[0].id.clone(),
            ));
        }
        if let Some(scope) = state.replace_scope_before_precondition.take() {
            let source_id = &commit.source_preconditions()[0].id;
            let record = state.records.get_mut(source_id).expect("source record");
            let mut encoded = serde_json::to_value(&*record).expect("encode source");
            encoded
                .as_object_mut()
                .expect("record object")
                .insert("governed_source_scope".into(), serde_json::json!(scope));
            *record = serde_json::from_value(encoded).expect("replace source scope");
        }
        for expected in commit.source_preconditions() {
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
        for operation in commit.operations() {
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
        let audit = commit.audit().clone();
        let mut outcome = CognitionCommitOutcome {
            status: CognitionCommitStatus::Applied,
            backend_commit_hash: format!(
                "test-commit-{resulting}-{}",
                &commit.proposal_digest()[7..19]
            ),
            prior_version: prior.to_string(),
            resulting_version: resulting.to_string(),
            affected_ids: commit.audit().affected_ids.clone(),
            committed_at: commit.audit().prepared_at,
            audit: audit.clone(),
        };
        state.records = next_records;
        state.version = resulting;
        state.outbox.extend(commit.index_outbox().iter().cloned());
        state.audits.push(audit);
        state.applications.insert(
            commit.idempotency_key().clone(),
            StoredApplication {
                proposal_digest: commit.proposal_digest().to_owned(),
                outcome: outcome.clone(),
            },
        );
        if let Some(mutate) = state.commit_outcome_mutation.take() {
            mutate(&mut outcome);
        }
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
        Self::new_with_scope(None)
    }

    fn new_with_scope(governed_source_scope: Option<GovernedSourceScope>) -> Self {
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
        let source = MemoryId::next();
        let source_record = crate::vault::build_record_with_id_at_and_scope(
            &space,
            MemoryDraft::new(
                MemoryKind::Semantic,
                MemoryContent::text("private source text"),
                Provenance::Operator,
            )
            .with_label(Label::Sensitive)
            .for_purposes(["research"]),
            None,
            source.clone(),
            Utc::now(),
            governed_source_scope.clone(),
        );
        store.put(source_record).expect("source write");
        let manifest = match governed_source_scope.as_ref() {
            Some(scope) => vault.governed_cognition_source_manifest(
                &space,
                &read,
                std::slice::from_ref(&source),
                &context,
                scope,
            ),
            None => vault.cognition_source_manifest(
                &space,
                &read,
                std::slice::from_ref(&source),
                &context,
            ),
        }
        .expect("source manifest");
        let binding = CognitionBinding {
            space_id: space.resource_id().to_owned(),
            subject: "did:key:researcher".into(),
            purpose: "research".into(),
            governed_source_scope,
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
        governed_source_scope: binding.governed_source_scope.clone(),
        job_id: "job-42".into(),
        algorithm: "marciana.summarize.sail".into(),
        algorithm_version: "1".into(),
        governed_scan_digest: binding.governed_scan_digest.clone(),
        snapshot_digest: binding.snapshot_digest.clone(),
        plan_task_digest: binding.plan_task_digest.clone(),
        authorization_receipt_digest: binding.authorization_receipt_digest.clone(),
        effective_projection: binding.effective_projection.clone(),
        typedid_request_digest: binding.typedid_request_digest.clone(),
        policy_decision_id: "policy-decision-7".into(),
    }
}

fn authority_for_proposal(
    binding: &CognitionBinding,
    proposal: &CognitionProposal,
) -> CognitionAuthorityEvidence {
    let mut authority = authority_for(binding);
    authority.job_id.clone_from(&proposal.job_id);
    authority.algorithm.clone_from(&proposal.algorithm);
    authority
        .algorithm_version
        .clone_from(&proposal.algorithm_version);
    authority
}

fn digest(value: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{:x}", Sha256::digest(value.as_bytes()))
}

mod application;
mod authorized_source_limits;
mod governed_scope;
mod hardening;
mod limits_hardening;
mod outcome_hardening;
mod prepared_commit;
mod prepared_expansion_limits;
