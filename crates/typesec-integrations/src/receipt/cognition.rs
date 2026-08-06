//! Commit-bound receipt claims for governed Marciana cognition.

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use super::ReceiptError;

mod claims;
pub use claims::CognitionCommitReceiptClaims;
pub(super) mod validation;

/// Offline-verifiable evidence for one committed cognition application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CognitionCommitReceipt {
    /// Explicit durable receipt wire schema.
    pub schema_version: u32,
    /// Verified TypeDID subject that authorized application.
    pub subject: String,
    /// TypeSec memory-space resource.
    pub resource: String,
    /// Durable cognition job identifier.
    pub job_id: String,
    /// Exact TypeSec-verified external source scope, when cognition consumed
    /// governed rather than explicitly local records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_source_scope: Option<String>,
    /// Digest of the verified TypeDID request envelope.
    pub typedid_request_digest: String,
    /// Digest of the exact inert proposal.
    pub proposal_digest: String,
    /// Digest of the governed scan grant or proof.
    pub governed_scan_digest: String,
    /// Digest of the immutable catalog snapshot consumed by cognition.
    pub input_snapshot_digest: String,
    /// Digest of the application-time decision identity derived from fresh
    /// authorization and policy evidence.
    pub policy_decision_digest: String,
    /// Digest of LakeCat's original issue-time grant receipt.
    pub authorization_receipt_digest: String,
    /// Opaque backend version observed before application.
    pub prior_version: String,
    /// Opaque backend version produced by application.
    pub resulting_version: String,
    /// IDs invalidated or created by the application.
    pub affected_ids: Vec<String>,
    /// Durable Grust commit identity.
    pub backend_commit_id: String,
    /// Time the trusted authority adapter completed application-time
    /// revalidation.
    pub authority_revalidated_at: DateTime<Utc>,
    /// Trusted TypeSec preparation time after authorization.
    ///
    /// Receipt validity begins here. This is deliberately distinct from the
    /// backend commit time reported by the cognition outcome.
    pub prepared_at: DateTime<Utc>,
    /// Authoritative commit time returned by the transaction backend.
    pub committed_at: DateTime<Utc>,
    /// Receipt expiry.
    pub expires_at: DateTime<Utc>,
}

impl CognitionCommitReceipt {
    /// Current durable cognition receipt wire schema.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Construct claims whose validity begins at trusted vault preparation.
    ///
    /// Returns an error when `ttl` is nonpositive or cannot be added to the
    /// preparation timestamp without overflow, or when any supplied claim is
    /// incomplete or internally inconsistent.
    pub fn new(claims: CognitionCommitReceiptClaims, ttl: TimeDelta) -> Result<Self, ReceiptError> {
        let expires_at = validation::checked_expiry(claims.prepared_at, ttl)?;
        let receipt = Self {
            schema_version: Self::SCHEMA_VERSION,
            subject: claims.subject,
            resource: claims.resource,
            job_id: claims.job_id,
            governed_source_scope: claims.governed_source_scope,
            typedid_request_digest: claims.typedid_request_digest,
            proposal_digest: claims.proposal_digest,
            governed_scan_digest: claims.governed_scan_digest,
            input_snapshot_digest: claims.input_snapshot_digest,
            policy_decision_digest: claims.policy_decision_digest,
            authorization_receipt_digest: claims.authorization_receipt_digest,
            prior_version: claims.prior_version,
            resulting_version: claims.resulting_version,
            affected_ids: claims.affected_ids,
            backend_commit_id: claims.backend_commit_id,
            authority_revalidated_at: claims.authority_revalidated_at,
            prepared_at: claims.prepared_at,
            committed_at: claims.committed_at,
            expires_at,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validate required evidence before signing or accepting claims.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        validation::validate(self)
    }
}
