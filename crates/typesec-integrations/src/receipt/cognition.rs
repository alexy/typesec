//! Commit-bound receipt claims for governed Marciana cognition.

use chrono::{DateTime, TimeDelta, Utc};
use serde::Serialize;
pub use typesec_core::CognitionEffect;

use super::ReceiptError;

mod accessors;
mod claims;
pub use claims::CognitionCommitReceiptClaims;
pub(super) mod validation;
mod wire;

/// Offline-verifiable evidence for one committed cognition application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CognitionCommitReceipt {
    /// Explicit durable receipt wire schema.
    schema_version: u32,
    /// Explicit memory effect of the committed cognition decision.
    effect: CognitionEffect,
    /// Verified TypeDID subject that authorized application.
    subject: String,
    /// TypeSec memory-space resource.
    resource: String,
    /// Durable cognition job identifier.
    job_id: String,
    /// Exact TypeSec-verified external source scope, when cognition consumed
    /// governed rather than explicitly local records.
    #[serde(skip_serializing_if = "Option::is_none")]
    governed_source_scope: Option<String>,
    /// Digest of the verified TypeDID request envelope.
    typedid_request_digest: String,
    /// Digest of the exact inert proposal.
    proposal_digest: String,
    /// Digest of the governed scan grant or proof.
    governed_scan_digest: String,
    /// Digest of the immutable catalog snapshot consumed by cognition.
    input_snapshot_digest: String,
    /// Digest of the application-time decision identity derived from fresh
    /// authorization and policy evidence.
    policy_decision_digest: String,
    /// Digest of LakeCat's original issue-time grant receipt.
    authorization_receipt_digest: String,
    /// Opaque memory version observed before the decision.
    prior_version: String,
    /// Opaque memory version after the decision.
    resulting_version: String,
    /// IDs invalidated or created; empty only for no-change.
    affected_ids: Vec<String>,
    /// Durable Grust commit identity.
    backend_commit_id: String,
    /// Time TypeSec completed application-time authority revalidation.
    authority_revalidated_at: DateTime<Utc>,
    /// Trusted TypeSec preparation time after authorization.
    ///
    /// Receipt expiry is anchored here. This is deliberately distinct from
    /// both the backend commit time and the first-issuance time.
    prepared_at: DateTime<Utc>,
    /// Authoritative commit time returned by the transaction backend.
    committed_at: DateTime<Utc>,
    /// Stable first-issuance time retained for deterministic re-signing.
    issued_at: DateTime<Utc>,
    /// Receipt expiry.
    expires_at: DateTime<Utc>,
}

impl CognitionCommitReceipt {
    /// Current durable cognition receipt wire schema.
    pub const SCHEMA_VERSION: u32 = 3;

    /// Construct claims whose validity begins at stable first issuance and
    /// whose expiry remains anchored at trusted vault preparation.
    ///
    /// Returns an error when `ttl` is nonpositive or cannot be added to the
    /// preparation timestamp without overflow, or when any supplied claim is
    /// incomplete or internally inconsistent.
    pub fn new(claims: CognitionCommitReceiptClaims, ttl: TimeDelta) -> Result<Self, ReceiptError> {
        let expires_at = validation::checked_expiry(claims.prepared_at, ttl)?;
        let receipt = Self {
            schema_version: Self::SCHEMA_VERSION,
            effect: claims.effect,
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
            issued_at: claims.issued_at,
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
