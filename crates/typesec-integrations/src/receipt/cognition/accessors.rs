use chrono::{DateTime, Utc};

use super::{CognitionCommitReceipt, CognitionEffect};

impl CognitionCommitReceipt {
    /// Return the exact durable receipt schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Return the committed cognition effect.
    pub fn effect(&self) -> CognitionEffect {
        self.effect
    }

    /// Borrow the verified TypeDID subject.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Borrow the TypeSec memory-space resource.
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Borrow the durable cognition job identifier.
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    /// Borrow the exact governed source scope, when present.
    pub fn governed_source_scope(&self) -> Option<&str> {
        self.governed_source_scope.as_deref()
    }

    /// Borrow the verified TypeDID request digest.
    pub fn typedid_request_digest(&self) -> &str {
        &self.typedid_request_digest
    }

    /// Borrow the exact cognition proposal digest.
    pub fn proposal_digest(&self) -> &str {
        &self.proposal_digest
    }

    /// Borrow the governed scan proof digest.
    pub fn governed_scan_digest(&self) -> &str {
        &self.governed_scan_digest
    }

    /// Borrow the immutable input snapshot digest.
    pub fn input_snapshot_digest(&self) -> &str {
        &self.input_snapshot_digest
    }

    /// Borrow the application-time policy decision digest.
    pub fn policy_decision_digest(&self) -> &str {
        &self.policy_decision_digest
    }

    /// Borrow the original authorization receipt digest.
    pub fn authorization_receipt_digest(&self) -> &str {
        &self.authorization_receipt_digest
    }

    /// Borrow the memory version observed before the decision.
    pub fn prior_version(&self) -> &str {
        &self.prior_version
    }

    /// Borrow the memory version after the decision.
    pub fn resulting_version(&self) -> &str {
        &self.resulting_version
    }

    /// Borrow the canonical affected IDs.
    pub fn affected_ids(&self) -> &[String] {
        &self.affected_ids
    }

    /// Borrow the durable backend commit identity.
    pub fn backend_commit_id(&self) -> &str {
        &self.backend_commit_id
    }

    /// Return TypeSec's authority-revalidation completion time.
    pub fn authority_revalidated_at(&self) -> DateTime<Utc> {
        self.authority_revalidated_at
    }

    /// Return the trusted TypeSec preparation time.
    pub fn prepared_at(&self) -> DateTime<Utc> {
        self.prepared_at
    }

    /// Return the authoritative backend commit time.
    pub fn committed_at(&self) -> DateTime<Utc> {
        self.committed_at
    }

    /// Return the stable first-issuance time.
    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    /// Return the preparation-anchored expiry time.
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}
