use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use typesec_core::policy::RequestContext;

use crate::index::IndexMutation;
use crate::label::Label;
use crate::space::MemoryId;
use crate::store::{MemoryStore, StoreBatchOp, StoreError};

/// Immutable authority and input evidence a cognition proposal must echo.
///
/// These are digests and identifiers, never reusable plan tokens, raw
/// authorization receipts, signing material, or memory plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CognitionBinding {
    /// Exact memory space the proposal may mutate.
    pub space_id: String,
    /// Verified TypeDID/policy subject.
    pub subject: String,
    /// Purpose authorized for the scan and mutation.
    pub purpose: String,
    /// Digest of the complete governed LakeCat scan proof.
    pub governed_scan_digest: String,
    /// Digest or immutable identity of the catalog snapshot.
    pub snapshot_digest: String,
    /// Digest of the opaque Sail plan-task token.
    pub plan_task_digest: String,
    /// Digest of the authorization receipt; never the receipt itself.
    pub authorization_receipt_digest: String,
    /// Exact policy-narrowed fields visible to cognition.
    pub effective_projection: Vec<String>,
    /// Digest of the exact TypeSec source-record manifest.
    pub source_manifest_digest: String,
    /// Digest of the verified TypeDID request being answered.
    pub typedid_request_digest: String,
}

impl CognitionBinding {
    pub(crate) fn validate(&self) -> Result<(), CognitionApplyError> {
        for (name, value) in [
            ("spaceId", self.space_id.as_str()),
            ("subject", self.subject.as_str()),
            ("purpose", self.purpose.as_str()),
            ("governedScanDigest", self.governed_scan_digest.as_str()),
            ("snapshotDigest", self.snapshot_digest.as_str()),
            ("planTaskDigest", self.plan_task_digest.as_str()),
            (
                "authorizationReceiptDigest",
                self.authorization_receipt_digest.as_str(),
            ),
            ("sourceManifestDigest", self.source_manifest_digest.as_str()),
            ("typedidRequestDigest", self.typedid_request_digest.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(CognitionApplyError::InvalidBinding(name.to_owned()));
            }
        }
        if self.effective_projection.is_empty()
            || self
                .effective_projection
                .iter()
                .any(|field| field.trim().is_empty())
        {
            return Err(CognitionApplyError::InvalidBinding(
                "effectiveProjection".to_owned(),
            ));
        }
        let mut canonical = self.effective_projection.clone();
        canonical.sort();
        canonical.dedup();
        if canonical.len() != self.effective_projection.len() {
            return Err(CognitionApplyError::InvalidBinding(
                "effectiveProjection contains duplicates".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Fresh, independently resolved authority evidence returned at application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CognitionAuthorityEvidence {
    /// Currently authorized memory space.
    pub space_id: String,
    /// Currently authorized subject.
    pub subject: String,
    /// Currently authorized purpose.
    pub purpose: String,
    /// Current governed-scan proof digest.
    pub governed_scan_digest: String,
    /// Current immutable snapshot digest or identity.
    pub snapshot_digest: String,
    /// Current opaque plan-task digest.
    pub plan_task_digest: String,
    /// Current authorization-receipt digest.
    pub authorization_receipt_digest: String,
    /// Current policy-narrowed projection.
    pub effective_projection: Vec<String>,
    /// Verified TypeDID request digest.
    pub typedid_request_digest: String,
    /// Stable policy decision identifier for audit and receipts.
    pub policy_decision_id: String,
}

/// Trusted application-time adapter for LakeCat and TypeDID evidence.
///
/// Implementations live at the QueryGraph composition boundary. The vault
/// supplies only digest-safe binding material and requires returned evidence
/// to match it exactly.
pub trait CognitionAuthorityVerifier: Send + Sync {
    /// Resolve current authority, snapshot, projection, and request evidence.
    fn revalidate(
        &self,
        binding: &CognitionBinding,
        context: &RequestContext,
    ) -> Result<CognitionAuthorityEvidence, CognitionApplyError>;
}

/// One exact source revision used as an atomic commit precondition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CognitionSourcePrecondition {
    /// Source record identifier.
    pub id: MemoryId,
    /// Domain-separated digest of the complete stored record revision.
    pub record_digest: String,
}

impl CognitionSourcePrecondition {
    /// Compute the canonical precondition for a stored record without exposing
    /// its protected content.
    pub fn for_record(record: &crate::StoredRecord) -> Result<Self, CognitionApplyError> {
        super::digest::source_precondition(record)
    }
}

/// Canonical source manifest returned by the authorized preparation path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CognitionSourceManifest {
    /// Sorted, unique source preconditions.
    pub sources: Vec<CognitionSourcePrecondition>,
    /// Digest of the complete source set.
    pub digest: String,
    /// Join of all source labels.
    pub joined_label: Label,
}

/// Durable mutation idempotency identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CognitionIdempotencyKey {
    /// Exact target memory space.
    pub space_id: String,
    /// Caller/scheduler-assigned durable job id.
    pub job_id: String,
}

/// Plaintext-free durable evidence committed beside a cognition mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CognitionAuditEvidence {
    /// Durable operation/job id.
    pub operation_id: String,
    /// Verified subject.
    pub subject: String,
    /// Target space.
    pub space_id: String,
    /// Authorized purpose.
    pub purpose: String,
    /// Canonical proposal digest.
    pub proposal_digest: String,
    /// Canonical authority-binding digest.
    pub binding_digest: String,
    /// Recomputed source-manifest digest.
    pub source_manifest_digest: String,
    /// Verified TypeDID request digest.
    pub typedid_request_digest: String,
    /// Governed scan proof digest.
    pub governed_scan_digest: String,
    /// Authorization receipt digest.
    pub authorization_receipt_digest: String,
    /// Fresh policy decision id.
    pub policy_decision_id: String,
    /// Digest of worker evidence; worker strings themselves are not persisted.
    pub evidence_digest: String,
    /// IDs affected by the prepared mutation.
    pub affected_ids: Vec<MemoryId>,
    /// Time the vault prepared the transaction.
    pub prepared_at: DateTime<Utc>,
}

/// Complete input to one authoritative cognition transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedCognitionCommit {
    /// Unique application key.
    pub idempotency_key: CognitionIdempotencyKey,
    /// Digest that must match on an idempotent retry.
    pub proposal_digest: String,
    /// Exact source revisions compared inside the transaction.
    pub source_preconditions: Vec<CognitionSourcePrecondition>,
    /// Record writes and invalidations to commit atomically.
    pub operations: Vec<StoreBatchOp>,
    /// ID-only semantic-index work committed in the same transaction.
    pub index_outbox: Vec<IndexMutation>,
    /// Plaintext-free evidence committed in the same transaction.
    pub audit: CognitionAuditEvidence,
}

/// Whether this call performed or recovered a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitionCommitStatus {
    /// This call committed the mutation.
    Applied,
    /// The same idempotency key and proposal digest had already committed.
    AlreadyApplied,
}

/// Commit-bound result retained for retry and receipt recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CognitionCommitOutcome {
    /// Applied versus recovered status.
    pub status: CognitionCommitStatus,
    /// Backend commit hash or immutable commit id.
    pub backend_commit_hash: String,
    /// Authoritative version before the mutation.
    pub prior_version: String,
    /// Authoritative version after the mutation.
    pub resulting_version: String,
    /// Stable affected IDs, identical on retry.
    pub affected_ids: Vec<MemoryId>,
    /// Authoritative backend commit time, identical on retry.
    pub committed_at: DateTime<Utc>,
    /// Exact plaintext-free audit evidence persisted in the same transaction.
    pub audit: CognitionAuditEvidence,
}

/// Atomic cognition transaction failure.
#[derive(Debug, Error)]
pub enum CognitionCommitError {
    /// A source changed between vault validation and the transaction.
    #[error("cognition source '{0}' changed before commit")]
    StaleSource(MemoryId),
    /// The job id was already used for different proposal bytes.
    #[error("cognition idempotency key already belongs to another proposal")]
    IdempotencyConflict,
    /// The authoritative backend failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Authoritative store extension for cognition application.
///
/// There is deliberately no default implementation. A backend must compare
/// every source precondition, claim the idempotency key, apply all operations,
/// insert the ID-only outbox rows, and persist audit evidence in one atomic
/// transaction, or it does not support production cognition.
pub trait CognitionCommitStore: MemoryStore {
    /// Recover a completed application before re-reading sources it may have
    /// intentionally invalidated. A reused key with a different proposal
    /// digest must return [`CognitionCommitError::IdempotencyConflict`].
    fn recover_cognition(
        &self,
        key: &CognitionIdempotencyKey,
        proposal_digest: &str,
    ) -> Result<Option<CognitionCommitOutcome>, CognitionCommitError>;

    /// Commit or recover one idempotent cognition application.
    fn commit_cognition(
        &self,
        commit: PreparedCognitionCommit,
    ) -> Result<CognitionCommitOutcome, CognitionCommitError>;
}

/// Trusted proposal validation failure before the authoritative transaction.
#[derive(Debug, Error)]
pub enum CognitionApplyError {
    /// No policy engine was configured for mandatory use-time reauthorization.
    #[error("cognition application requires a configured policy engine")]
    PolicyUnavailable,
    /// No trusted LakeCat/TypeDID authority verifier was configured.
    #[error("cognition application requires a configured authority verifier")]
    AuthorityVerifierUnavailable,
    /// The proposal schema is not supported.
    #[error("unsupported cognition proposal schema {0}")]
    UnsupportedSchema(u32),
    /// A required binding field was absent or malformed.
    #[error("invalid cognition binding field: {0}")]
    InvalidBinding(String),
    /// The proposal omitted its governed binding.
    #[error("cognition proposal is not bound to governed authority")]
    MissingBinding,
    /// A named binding value did not match current evidence.
    #[error("cognition binding mismatch: {0}")]
    BindingMismatch(&'static str),
    /// The application request omitted a policy purpose.
    #[error("cognition application requires request purpose")]
    MissingPurpose,
    /// Source IDs were empty or duplicated.
    #[error("invalid cognition source set: {0}")]
    InvalidSourceSet(String),
    /// A source is stale or ineligible for cognition.
    #[error("cognition source '{id}' is ineligible: {reason}")]
    InvalidSource {
        /// Source record.
        id: MemoryId,
        /// Fail-closed reason.
        reason: &'static str,
    },
    /// The current source manifest differs from the proposal.
    #[error("cognition source manifest changed")]
    SourceManifestMismatch,
    /// The worker's label join differs from the vault's recomputation.
    #[error("cognition source label join changed")]
    JoinedLabelMismatch,
    /// The proposed mutation is empty or references invalid targets.
    #[error("invalid cognition plan: {0}")]
    InvalidPlan(String),
    /// Canonical serialization failed.
    #[error("cognition canonicalization failed: {0}")]
    Serialization(String),
    /// A trusted authority adapter denied or could not revalidate the binding.
    #[error("cognition authority revalidation failed: {0}")]
    Authority(String),
}
