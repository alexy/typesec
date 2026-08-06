use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use typesec_core::policy::RequestContext;

use crate::governed::GovernedSourceScope;
use crate::label::Label;
use crate::space::MemoryId;
use crate::store::{MemoryStore, StoreError};

use super::PreparedCognitionCommit;
use super::canonical::{is_canonical_sha256, is_canonical_text};
use super::limits::validate_projection_count;

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
    /// Exact vault-verified source scope, or `None` for explicit local input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_source_scope: Option<GovernedSourceScope>,
    /// Digest of the complete governed LakeCat scan proof.
    pub governed_scan_digest: String,
    /// Canonical digest of the immutable catalog snapshot.
    pub snapshot_digest: String,
    /// Digest of the opaque Sail plan-task token.
    pub plan_task_digest: String,
    /// Digest of the original issue-time LakeCat grant receipt; never the
    /// receipt itself or a fresh application-time authorization result.
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
        ] {
            if !is_canonical_text(value) {
                return Err(CognitionApplyError::InvalidBinding(name.to_owned()));
            }
        }
        for (name, value) in [
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
            if !is_canonical_sha256(value) {
                return Err(CognitionApplyError::InvalidBinding(name.to_owned()));
            }
        }
        if self.governed_scan_digest == self.snapshot_digest {
            return Err(CognitionApplyError::InvalidBinding(
                "governedScanDigest and snapshotDigest must be distinct".to_owned(),
            ));
        }
        validate_projection_count(self.effective_projection.len())?;
        if self.effective_projection.is_empty()
            || self
                .effective_projection
                .iter()
                .any(|field| !is_canonical_text(field))
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
    /// Freshly resolved source scope, or `None` for explicit local cognition.
    pub governed_source_scope: Option<GovernedSourceScope>,
    /// Durable job identity resolved from the verified request.
    pub job_id: String,
    /// Cognition algorithm identity resolved from trusted intent.
    pub algorithm: String,
    /// Cognition algorithm version resolved from trusted intent.
    pub algorithm_version: String,
    /// Current governed-scan proof digest.
    pub governed_scan_digest: String,
    /// Current canonical immutable snapshot digest.
    pub snapshot_digest: String,
    /// Current opaque plan-task digest.
    pub plan_task_digest: String,
    /// Original issue-time grant receipt, revalidated without substitution.
    pub authorization_receipt_digest: String,
    /// Current policy-narrowed projection.
    pub effective_projection: Vec<String>,
    /// Verified TypeDID request digest.
    pub typedid_request_digest: String,
    /// Stable application-time decision identifier derived from fresh
    /// authorization and policy evidence.
    pub policy_decision_id: String,
    /// Time the trusted authority adapter completed the current revalidation.
    pub authority_revalidated_at: DateTime<Utc>,
}

/// Trusted application-time adapter for LakeCat and TypeDID evidence.
///
/// Implementations live at the standalone Marciana composition boundary;
/// QueryGraph consumes that integration. The vault supplies only digest-safe
/// binding material and requires returned evidence to match it exactly.
pub trait CognitionAuthorityVerifier: Send + Sync {
    /// Resolve current authority, snapshot, projection, and request evidence.
    fn revalidate(
        &self,
        binding: &CognitionBinding,
        context: &RequestContext,
    ) -> Result<CognitionAuthorityEvidence, CognitionAuthorityError>;
}

/// Opaque failure from a trusted cognition authority adapter.
///
/// Adapter implementations must retain detailed backend causes only in
/// protected diagnostics. This fixed error cannot expose LakeCat or TypeDID
/// response text through the public cognition boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CognitionAuthorityError {
    /// Current authority evidence could not be resolved safely.
    #[error("cognition authority evidence is unavailable")]
    Unavailable,
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
    space_id: String,
    /// Domain-separated digest of the verified subject and purpose.
    authority_scope_digest: String,
    /// Caller/scheduler-assigned durable job id.
    job_id: String,
}

impl CognitionIdempotencyKey {
    /// Construct a canonical key scoped to verified authority without retaining
    /// the raw subject or purpose in scheduler and graph identifiers.
    pub fn for_authority(
        space_id: &str,
        subject: &str,
        purpose: &str,
        job_id: &str,
    ) -> Result<Self, CognitionApplyError> {
        if [space_id, subject, purpose, job_id]
            .into_iter()
            .any(|value| !is_canonical_text(value))
        {
            return Err(CognitionApplyError::InvalidBinding(
                "idempotencyKey".to_owned(),
            ));
        }
        Ok(Self {
            space_id: space_id.to_owned(),
            authority_scope_digest: super::digest::authority_scope_digest(subject, purpose)?,
            job_id: job_id.to_owned(),
        })
    }

    /// Exact target memory space.
    pub fn space_id(&self) -> &str {
        &self.space_id
    }

    /// Opaque verified subject-and-purpose scope.
    pub fn authority_scope_digest(&self) -> &str {
        &self.authority_scope_digest
    }

    /// Caller/scheduler-assigned durable job id.
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    /// Validate a deserialized key before it is used by a trusted backend.
    pub fn validate(&self) -> Result<(), CognitionApplyError> {
        if !is_canonical_text(&self.space_id)
            || !is_canonical_sha256(&self.authority_scope_digest)
            || !is_canonical_text(&self.job_id)
        {
            return Err(CognitionApplyError::InvalidBinding(
                "idempotencyKey".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Plaintext-free durable evidence committed beside a cognition mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CognitionAuditEvidence {
    /// Explicit schema version for durable and cross-process decoding.
    pub schema_version: u32,
    /// Durable operation/job id.
    pub operation_id: String,
    /// Verified subject.
    pub subject: String,
    /// Target space.
    pub space_id: String,
    /// Authorized purpose.
    pub purpose: String,
    /// Exact source scope committed with the mutation, when governed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_source_scope: Option<GovernedSourceScope>,
    /// Canonical proposal digest.
    pub proposal_digest: String,
    /// Canonical authority-binding digest.
    pub binding_digest: String,
    /// Recomputed source-manifest digest.
    pub source_manifest_digest: String,
    /// Verified TypeDID request digest.
    pub typedid_request_digest: String,
    /// Governed scan grant/proof digest.
    pub governed_scan_digest: String,
    /// Immutable catalog snapshot digest consumed by cognition.
    pub snapshot_digest: String,
    /// Original issue-time LakeCat grant receipt digest.
    pub authorization_receipt_digest: String,
    /// Application-time decision id derived from fresh authority evidence.
    pub policy_decision_id: String,
    /// Digest of worker evidence; worker strings themselves are not persisted.
    pub evidence_digest: String,
    /// IDs affected by the prepared mutation.
    pub affected_ids: Vec<MemoryId>,
    /// Time the trusted authority adapter completed application-time
    /// revalidation.
    pub authority_revalidated_at: DateTime<Utc>,
    /// Time the vault prepared the transaction.
    pub prepared_at: DateTime<Utc>,
}

impl CognitionAuditEvidence {
    /// Current durable audit wire schema.
    pub const SCHEMA_VERSION: u32 = 1;
}

/// Whether a call performed a mutation or disclosed an immutable prior commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitionCommitStatus {
    /// This call committed the mutation.
    Applied,
    /// The same idempotency key and proposal digest had already committed;
    /// this status reports historical disclosure, never mutation authority.
    AlreadyApplied,
}

/// Immutable commit-bound result retained for retry and receipt recovery.
///
/// Recovering this value authorizes disclosure of historical commit evidence;
/// it is not mutation authority and cannot be used to reapply the operation.
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
    /// A backend returned an outcome that does not match the prepared request.
    #[error("cognition backend returned an invalid commit outcome")]
    InvalidOutcome,
    /// The authoritative backend failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Authoritative store extension for cognition application.
///
/// There is deliberately no default implementation. A backend must compare
/// every source precondition, claim the idempotency key, apply all operations,
/// insert the ID-only outbox rows, and persist audit evidence in one atomic
/// transaction, or it does not support production cognition. The prepared
/// token has no debug or serialization surface; implementations use its
/// borrow-only accessors inside that trusted transaction boundary.
pub trait CognitionCommitStore: MemoryStore {
    /// Load an immutable completed result before re-reading sources it may
    /// have intentionally invalidated.
    ///
    /// This is a trusted backend seam, not an authorization boundary: it
    /// neither authorizes disclosure nor grants mutation authority. External
    /// result access must use
    /// [`MemoryVault::recover_cognition_outcome`](crate::MemoryVault::recover_cognition_outcome),
    /// which checks current capability and policy first. A reused key with a
    /// different proposal digest must return
    /// [`CognitionCommitError::IdempotencyConflict`].
    fn recover_cognition(
        &self,
        key: &CognitionIdempotencyKey,
        proposal_digest: &str,
    ) -> Result<Option<CognitionCommitOutcome>, CognitionCommitError>;

    /// Commit one vault-prepared application or return its immutable prior
    /// result; the recovery case never reapplies the mutation.
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
    /// Selected records did not all match the binding's exact source scope.
    #[error("cognition sources do not match the required governed scope")]
    SourceScopeMismatch,
    /// The proposed mutation is empty or references invalid targets.
    #[error("invalid cognition plan: {0}")]
    InvalidPlan(String),
    /// A fixed cognition safety budget was exceeded.
    #[error("cognition safety limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// Canonical serialization failed.
    #[error("cognition canonicalization failed: {0}")]
    Serialization(String),
    /// A trusted authority adapter denied or could not revalidate the binding.
    #[error("cognition authority revalidation failed")]
    Authority,
}
