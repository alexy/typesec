//! Commit-bound receipt claims for governed Marciana cognition.

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use super::ReceiptError;

pub(super) mod validation;

/// Offline-verifiable evidence for one committed cognition application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CognitionCommitReceipt {
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
    /// Digest of the LakeCat-governed input snapshot.
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
    /// Trusted TypeSec preparation and authorization time.
    ///
    /// Receipt validity begins here. This is deliberately distinct from the
    /// backend commit time reported by the cognition outcome.
    pub prepared_at: DateTime<Utc>,
    /// Receipt expiry.
    pub expires_at: DateTime<Utc>,
}

impl CognitionCommitReceipt {
    /// Construct claims whose validity begins at trusted vault preparation.
    ///
    /// Returns an error when `ttl` is nonpositive or cannot be added to the
    /// preparation timestamp without overflow.
    pub fn new(
        subject: impl Into<String>,
        resource: impl Into<String>,
        job_id: impl Into<String>,
        backend_commit_id: impl Into<String>,
        prepared_at: DateTime<Utc>,
        ttl: TimeDelta,
    ) -> Result<Self, ReceiptError> {
        let expires_at = validation::checked_expiry(prepared_at, ttl)?;
        Ok(Self {
            subject: subject.into(),
            resource: resource.into(),
            job_id: job_id.into(),
            governed_source_scope: None,
            typedid_request_digest: String::new(),
            proposal_digest: String::new(),
            input_snapshot_digest: String::new(),
            policy_decision_digest: String::new(),
            authorization_receipt_digest: String::new(),
            prior_version: String::new(),
            resulting_version: String::new(),
            affected_ids: Vec::new(),
            backend_commit_id: backend_commit_id.into(),
            prepared_at,
            expires_at,
        })
    }

    /// Validate required evidence before signing or accepting claims.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        validation::validate(self)
    }
}
