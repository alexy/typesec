//! Commit-bound receipt claims for governed Marciana cognition.

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use super::ReceiptError;

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
    /// Digest of the verified TypeDID request envelope.
    pub typedid_request_digest: String,
    /// Digest of the exact inert proposal.
    pub proposal_digest: String,
    /// Digest of the LakeCat-governed input snapshot.
    pub input_snapshot_digest: String,
    /// Digest of the fresh policy decision used at application time.
    pub policy_decision_digest: String,
    /// Digest of LakeCat's fresh authorization receipt.
    pub authorization_receipt_digest: String,
    /// Backend version observed before application.
    pub prior_version: String,
    /// Backend version produced by application.
    pub resulting_version: String,
    /// IDs invalidated or created by the application.
    pub affected_ids: Vec<String>,
    /// Durable Grust commit identity.
    pub backend_commit_id: String,
    /// Whether this response recovered a previously committed application.
    pub replayed: bool,
    /// Backend commit time; used as the stable receipt issue time.
    pub committed_at: DateTime<Utc>,
    /// Receipt expiry.
    pub expires_at: DateTime<Utc>,
}

impl CognitionCommitReceipt {
    /// Construct claims whose validity begins at the durable commit time.
    pub fn new(
        subject: impl Into<String>,
        resource: impl Into<String>,
        job_id: impl Into<String>,
        backend_commit_id: impl Into<String>,
        committed_at: DateTime<Utc>,
        ttl: TimeDelta,
    ) -> Self {
        Self {
            subject: subject.into(),
            resource: resource.into(),
            job_id: job_id.into(),
            typedid_request_digest: String::new(),
            proposal_digest: String::new(),
            input_snapshot_digest: String::new(),
            policy_decision_digest: String::new(),
            authorization_receipt_digest: String::new(),
            prior_version: String::new(),
            resulting_version: String::new(),
            affected_ids: Vec::new(),
            backend_commit_id: backend_commit_id.into(),
            replayed: false,
            committed_at,
            expires_at: committed_at + ttl,
        }
    }

    /// Validate required evidence before signing or accepting claims.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        for (name, value) in [
            ("subject", self.subject.as_str()),
            ("resource", self.resource.as_str()),
            ("jobId", self.job_id.as_str()),
            ("typedidRequestDigest", self.typedid_request_digest.as_str()),
            ("proposalDigest", self.proposal_digest.as_str()),
            ("inputSnapshotDigest", self.input_snapshot_digest.as_str()),
            ("policyDecisionDigest", self.policy_decision_digest.as_str()),
            (
                "authorizationReceiptDigest",
                self.authorization_receipt_digest.as_str(),
            ),
            ("priorVersion", self.prior_version.as_str()),
            ("resultingVersion", self.resulting_version.as_str()),
            ("backendCommitId", self.backend_commit_id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ReceiptError::InvalidClaims(format!(
                    "{name} must not be empty"
                )));
            }
        }
        if self.expires_at <= self.committed_at {
            return Err(ReceiptError::InvalidClaims(
                "expiresAt must be after committedAt".to_owned(),
            ));
        }
        Ok(())
    }
}
