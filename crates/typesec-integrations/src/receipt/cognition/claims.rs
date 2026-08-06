//! Complete inputs for constructing cognition receipt claims.

use chrono::{DateTime, Utc};
use typesec_core::CognitionEffect;

/// Evidence that must be present before a cognition receipt can be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CognitionCommitReceiptClaims {
    /// Explicit memory effect of the committed cognition decision.
    pub effect: CognitionEffect,
    /// Verified TypeDID subject that authorized application.
    pub subject: String,
    /// TypeSec memory-space resource.
    pub resource: String,
    /// Durable cognition job identifier.
    pub job_id: String,
    /// Composite TypeSec-verified external source scope, or `None` for an
    /// explicitly local-only input set.
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
    /// Digest of the original issue-time authorization receipt.
    pub authorization_receipt_digest: String,
    /// Opaque memory version observed before the decision.
    pub prior_version: String,
    /// Opaque memory version after the decision.
    pub resulting_version: String,
    /// IDs invalidated or created; empty only for no-change.
    pub affected_ids: Vec<String>,
    /// Durable backend commit identity.
    pub backend_commit_id: String,
    /// Time the trusted authority adapter completed application-time
    /// revalidation.
    pub authority_revalidated_at: DateTime<Utc>,
    /// Trusted TypeSec preparation time.
    pub prepared_at: DateTime<Utc>,
    /// Authoritative commit time returned by the transaction backend.
    pub committed_at: DateTime<Utc>,
}
