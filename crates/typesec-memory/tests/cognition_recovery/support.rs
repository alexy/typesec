use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeDelta, Utc};
use sha2::{Digest, Sha256};
use typesec_core::policy::{MintOptions, RequestContext, mint_capability_for_id};
use typesec_core::{CanRead, CanWrite, Capability, Resource};
use typesec_memory::{
    CognitionAuthorityError, CognitionAuthorityEvidence, CognitionAuthorityVerifier,
    CognitionBinding, CognitionCommitError, CognitionCommitOutcome, CognitionCommitStatus,
    CognitionCommitStore, CognitionEffect, CognitionIdempotencyKey, CognitionProposal,
    CognitionSourcePrecondition, ConsolidationPlan, ConsolidationStep, Label, MemoryError,
    MemoryId, MemoryKind, MemorySpace, MemoryStore, MemoryVault, PreparedCognitionCommit,
    StoreBatchOp, StoreError, StoreQuery, StoredRecord,
};
use typesec_odrl::OdrlEngine;

const SUBJECT: &str = "did:key:researcher";
pub(super) const OTHER_SUBJECT: &str = "did:key:other";
const PURPOSE: &str = "research";
pub(super) const JOB_ID: &str = "job-response-loss";

#[derive(Clone, Default)]
pub(super) struct RecoveryStore {
    state: Arc<Mutex<StoreState>>,
}

#[derive(Default)]
struct StoreState {
    records: HashMap<MemoryId, StoredRecord>,
    applications: BTreeMap<CognitionIdempotencyKey, StoredApplication>,
    commit_calls: usize,
    recovery_calls: usize,
    fail_recovery: bool,
    forced_recovery_status: Option<CognitionCommitStatus>,
}

#[derive(Clone)]
struct StoredApplication {
    proposal_digest: String,
    outcome: CognitionCommitOutcome,
}

impl RecoveryStore {
    fn state(&self) -> std::sync::MutexGuard<'_, StoreState> {
        self.state.lock().expect("recovery store lock")
    }

    pub(super) fn counts(&self) -> (usize, usize) {
        let state = self.state();
        (state.commit_calls, state.recovery_calls)
    }

    pub(super) fn outcome(&self, key: &CognitionIdempotencyKey) -> CognitionCommitOutcome {
        self.state().applications[key].outcome.clone()
    }

    pub(super) fn replace_outcome(
        &self,
        key: &CognitionIdempotencyKey,
        outcome: CognitionCommitOutcome,
    ) {
        self.state()
            .applications
            .get_mut(key)
            .expect("stored outcome")
            .outcome = outcome;
    }

    pub(super) fn fail_recovery(&self, fail: bool) {
        self.state().fail_recovery = fail;
    }

    pub(super) fn force_recovery_status(&self, status: Option<CognitionCommitStatus>) {
        self.state().forced_recovery_status = status;
    }
}

impl MemoryStore for RecoveryStore {
    fn put(&self, record: StoredRecord) -> Result<(), StoreError> {
        self.state().records.insert(record.id.clone(), record);
        Ok(())
    }

    fn get(&self, id: &MemoryId) -> Result<Option<StoredRecord>, StoreError> {
        Ok(self.state().records.get(id).cloned())
    }

    fn query(&self, query: &StoreQuery) -> Result<Vec<StoredRecord>, StoreError> {
        Ok(self
            .state()
            .records
            .values()
            .filter(|record| query.matches(record))
            .cloned()
            .collect())
    }

    fn invalidate(&self, id: &MemoryId, at: DateTime<Utc>) -> Result<(), StoreError> {
        self.state()
            .records
            .get_mut(id)
            .ok_or_else(|| StoreError::Backend("record absent".into()))?
            .invalid_at = Some(at);
        Ok(())
    }

    fn tombstone(&self, id: &MemoryId) -> Result<bool, StoreError> {
        Ok(self.state().records.remove(id).is_some())
    }
}

impl CognitionCommitStore for RecoveryStore {
    fn recover_cognition(
        &self,
        key: &CognitionIdempotencyKey,
        proposal_digest: &str,
    ) -> Result<Option<CognitionCommitOutcome>, CognitionCommitError> {
        let mut state = self.state();
        state.recovery_calls += 1;
        if state.fail_recovery {
            return Err(CognitionCommitError::Store(StoreError::Backend(
                "adapter secret: cluster topology".into(),
            )));
        }
        let Some(application) = state.applications.get(key) else {
            return Ok(None);
        };
        if application.proposal_digest != proposal_digest {
            return Err(CognitionCommitError::IdempotencyConflict);
        }
        let mut outcome = application.outcome.clone();
        outcome.status = state
            .forced_recovery_status
            .unwrap_or(CognitionCommitStatus::AlreadyApplied);
        Ok(Some(outcome))
    }

    fn commit_cognition(
        &self,
        commit: PreparedCognitionCommit,
    ) -> Result<CognitionCommitOutcome, CognitionCommitError> {
        let mut state = self.state();
        state.commit_calls += 1;
        validate_sources(&state, &commit)?;
        apply_operations(&mut state, &commit)?;

        let key = commit.idempotency_key().clone();
        let proposal_digest = commit.proposal_digest().to_owned();
        let audit = commit.audit().clone();
        let ordinal = state.commit_calls;
        let outcome = CognitionCommitOutcome {
            status: CognitionCommitStatus::Applied,
            effect: commit.effect(),
            backend_commit_hash: digest(&format!("backend commit {ordinal}")),
            prior_version: digest(&format!("version {}", ordinal - 1)),
            resulting_version: match commit.effect() {
                CognitionEffect::Mutated => digest(&format!("version {ordinal}")),
                CognitionEffect::NoChange => digest(&format!("version {}", ordinal - 1)),
            },
            affected_ids: audit.affected_ids.clone(),
            committed_at: audit.prepared_at + TimeDelta::milliseconds(1),
            audit,
        };
        state.applications.insert(
            key,
            StoredApplication {
                proposal_digest,
                outcome: outcome.clone(),
            },
        );
        Ok(outcome)
    }
}

fn validate_sources(
    state: &StoreState,
    commit: &PreparedCognitionCommit,
) -> Result<(), CognitionCommitError> {
    for expected in commit.source_preconditions() {
        let current = state
            .records
            .get(&expected.id)
            .ok_or_else(|| CognitionCommitError::StaleSource(expected.id.clone()))?;
        let current =
            CognitionSourcePrecondition::for_record(current).map_err(|_| opaque_store_failure())?;
        if current != *expected {
            return Err(CognitionCommitError::StaleSource(expected.id.clone()));
        }
    }
    Ok(())
}

fn apply_operations(
    state: &mut StoreState,
    commit: &PreparedCognitionCommit,
) -> Result<(), CognitionCommitError> {
    for operation in commit.operations() {
        match operation {
            StoreBatchOp::Put(record) => {
                state.records.insert(record.id.clone(), (**record).clone());
            }
            StoreBatchOp::Invalidate { id, at } => {
                state
                    .records
                    .get_mut(id)
                    .ok_or_else(|| CognitionCommitError::StaleSource(id.clone()))?
                    .invalid_at = Some(*at);
            }
        }
    }
    Ok(())
}

fn opaque_store_failure() -> CognitionCommitError {
    CognitionCommitError::Store(StoreError::Backend("test store integrity failure".into()))
}

#[derive(Default)]
struct CountingAuthority {
    calls: AtomicUsize,
    evidence: Mutex<Option<CognitionAuthorityEvidence>>,
}

impl CountingAuthority {
    fn set(&self, evidence: CognitionAuthorityEvidence) {
        *self.evidence.lock().expect("authority evidence lock") = Some(evidence);
    }
}

impl CognitionAuthorityVerifier for CountingAuthority {
    fn revalidate(
        &self,
        _binding: &CognitionBinding,
        _context: &RequestContext,
    ) -> Result<CognitionAuthorityEvidence, CognitionAuthorityError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.evidence
            .lock()
            .expect("authority evidence lock")
            .clone()
            .ok_or(CognitionAuthorityError::Unavailable)
    }
}

pub(super) struct Fixture {
    pub(super) store: RecoveryStore,
    pub(super) policy: Arc<OdrlEngine>,
    authority: Arc<CountingAuthority>,
    pub(super) space: MemorySpace,
    pub(super) context: RequestContext,
    pub(super) write: Capability<CanWrite, MemorySpace>,
    pub(super) key: CognitionIdempotencyKey,
    pub(super) proposal_digest: String,
}

impl Fixture {
    pub(super) fn new() -> Self {
        Self::new_with_effect(CognitionEffect::Mutated)
    }

    pub(super) fn new_no_change() -> Self {
        Self::new_with_effect(CognitionEffect::NoChange)
    }

    fn new_with_effect(effect: CognitionEffect) -> Self {
        let store = RecoveryStore::default();
        let space = MemorySpace::new("tenant:acme", "research");
        let context = RequestContext::new().with_purpose(PURPOSE);
        let policy = Arc::new(policy_for(&space));
        let read = capability::<CanRead>(&policy, SUBJECT, &space, &context);
        let write = capability::<CanWrite>(&policy, SUBJECT, &space, &context);
        let source = source_record(&space);
        store.put(source.clone()).expect("seed source");

        let manifest_vault = MemoryVault::new(store.clone()).with_policy(policy.clone());
        let manifest = manifest_vault
            .cognition_source_manifest(&space, &read, std::slice::from_ref(&source.id), &context)
            .expect("authorized source manifest");
        let binding = binding(&space, manifest.digest);
        let authority = Arc::new(CountingAuthority::default());
        authority.set(authority_for(&binding));
        let proposal = proposal(source.id, binding, effect);
        let proposal_digest = proposal.canonical_digest().expect("proposal digest");
        let apply_vault = MemoryVault::new(store.clone())
            .with_policy(policy.clone())
            .with_cognition_authority(authority.clone());

        // The response is intentionally discarded: only its canonical
        // proposal identity remains at the recovery caller.
        let lost_response = apply_vault
            .apply_cognition(&space, &write, &proposal, &context)
            .expect("initial cognition commit");
        assert_eq!(lost_response.status, CognitionCommitStatus::Applied);
        drop(lost_response);
        drop(proposal);

        let key =
            CognitionIdempotencyKey::for_authority(space.resource_id(), SUBJECT, PURPOSE, JOB_ID)
                .expect("scoped cognition key");
        Self {
            store,
            policy,
            authority,
            space,
            context,
            write,
            key,
            proposal_digest,
        }
    }

    pub(super) fn vault(&self) -> MemoryVault<RecoveryStore> {
        // Historical recovery deliberately has no mutation-authority adapter.
        MemoryVault::new(self.store.clone()).with_policy(self.policy.clone())
    }

    pub(super) fn recover(&self) -> Result<CognitionCommitOutcome, MemoryError> {
        self.vault().recover_cognition_outcome(
            &self.space,
            &self.write,
            JOB_ID,
            &self.proposal_digest,
            &self.context,
        )
    }

    pub(super) fn authority_calls(&self) -> usize {
        self.authority.calls.load(Ordering::SeqCst)
    }
}

fn binding(space: &MemorySpace, source_manifest_digest: String) -> CognitionBinding {
    CognitionBinding {
        space_id: space.resource_id().to_owned(),
        subject: SUBJECT.into(),
        purpose: PURPOSE.into(),
        governed_source_scope: None,
        governed_scan_digest: digest("governed scan"),
        snapshot_digest: digest("snapshot"),
        plan_task_digest: digest("plan task"),
        authorization_receipt_digest: digest("authorization receipt"),
        effective_projection: vec!["id".into(), "text".into()],
        source_manifest_digest,
        typedid_request_digest: digest("TypeDID request"),
    }
}

fn proposal(
    source: MemoryId,
    binding: CognitionBinding,
    effect: CognitionEffect,
) -> CognitionProposal {
    let proposal = CognitionProposal::new(
        JOB_ID,
        binding.snapshot_digest.clone(),
        binding.source_manifest_digest.clone(),
        "marciana.test",
        "1",
        vec![source.clone()],
        Label::Internal,
    );
    let proposal = match effect {
        CognitionEffect::Mutated => proposal.with_plan(
            ConsolidationPlan::new().then(ConsolidationStep::Invalidate { ids: vec![source] }),
        ),
        CognitionEffect::NoChange => proposal.with_effect(CognitionEffect::NoChange),
    };
    proposal.with_binding(binding)
}

fn policy_for(space: &MemorySpace) -> OdrlEngine {
    OdrlEngine::from_yaml(&format!(
        r#"
policies:
  - uid: "policy:cognition-recovery"
    type: Set
    rules:
      - type: permission
        assignee: "{SUBJECT}"
        action: read
        target: "{}"
        constraints:
          - leftOperand: purpose
            operator: eq
            rightOperand: "{PURPOSE}"
      - type: permission
        assignee: "{SUBJECT}"
        action: write
        target: "{}"
        constraints:
          - leftOperand: purpose
            operator: eq
            rightOperand: "{PURPOSE}"
      - type: permission
        assignee: "{OTHER_SUBJECT}"
        action: write
        target: "{}"
        constraints:
          - leftOperand: purpose
            operator: eq
            rightOperand: "{PURPOSE}"
"#,
        space.resource_id(),
        space.resource_id(),
        space.resource_id(),
    ))
    .expect("ODRL recovery policy")
}

pub(super) fn capability<P: typesec_core::Permission>(
    policy: &Arc<OdrlEngine>,
    subject: &str,
    space: &MemorySpace,
    context: &RequestContext,
) -> Capability<P, MemorySpace> {
    mint_capability_for_id(
        policy.as_ref(),
        subject,
        space.resource_id(),
        &MintOptions {
            context: context.clone(),
            ..MintOptions::default()
        },
    )
    .expect("policy-minted capability")
}

fn source_record(space: &MemorySpace) -> StoredRecord {
    serde_json::from_value(serde_json::json!({
        "id": "mem-source",
        "space_id": space.resource_id(),
        "kind": MemoryKind::Semantic,
        "label": Label::Internal,
        "quarantined": false,
        "entities": [],
        "provenance": { "source": "operator" },
        "observed_at": "2026-01-01T00:00:00Z",
        "valid_from": "2026-01-01T00:00:00Z",
        "invalid_at": null,
        "expires_at": null,
        "purposes": [PURPOSE],
        "content": { "text": "protected source text" }
    }))
    .expect("stored source fixture")
}

fn authority_for(binding: &CognitionBinding) -> CognitionAuthorityEvidence {
    CognitionAuthorityEvidence {
        space_id: binding.space_id.clone(),
        subject: binding.subject.clone(),
        purpose: binding.purpose.clone(),
        governed_source_scope: binding.governed_source_scope.clone(),
        job_id: JOB_ID.into(),
        algorithm: "marciana.test".into(),
        algorithm_version: "1".into(),
        governed_scan_digest: binding.governed_scan_digest.clone(),
        snapshot_digest: binding.snapshot_digest.clone(),
        plan_task_digest: binding.plan_task_digest.clone(),
        authorization_receipt_digest: binding.authorization_receipt_digest.clone(),
        effective_projection: binding.effective_projection.clone(),
        typedid_request_digest: binding.typedid_request_digest.clone(),
        policy_decision_id: digest("current policy decision"),
        authority_revalidated_at: DateTime::<Utc>::UNIX_EPOCH,
    }
}

pub(super) fn digest(value: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(value.as_bytes()))
}
