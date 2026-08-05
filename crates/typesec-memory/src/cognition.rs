//! Governed, transactional application of inert cognition proposals.
//!
//! This module owns backend-neutral authority bindings and the no-fallback
//! transaction seam. Cognition engines remain untrusted proposal producers;
//! only [`crate::MemoryVault::apply_cognition`] can turn their output into
//! memory mutations.

mod apply;
mod canonical;
mod digest;
mod input;
mod prepare;
mod prepared;
mod recovery;
mod types;
mod validate;

pub use input::AuthorizedCognitionInput;
pub use prepared::PreparedCognitionCommit;
pub use recovery::CognitionRecoveryError;
pub use types::{
    CognitionApplyError, CognitionAuditEvidence, CognitionAuthorityEvidence,
    CognitionAuthorityVerifier, CognitionBinding, CognitionCommitError, CognitionCommitOutcome,
    CognitionCommitStatus, CognitionCommitStore, CognitionIdempotencyKey, CognitionSourceManifest,
    CognitionSourcePrecondition,
};

impl crate::CognitionProposal {
    /// Domain-separated canonical digest used for durable proposal identity.
    ///
    /// Projection order is normalized and observational `created_at` metadata
    /// is excluded, so a later worker retry of the same governed mutation has
    /// the same identity without reimplementing TypeSec internals.
    pub fn canonical_digest(&self) -> Result<String, CognitionApplyError> {
        digest::proposal_digest(self)
    }
}

impl CognitionBinding {
    /// Domain-separated canonical digest of governed authority evidence.
    pub fn canonical_digest(&self) -> Result<String, CognitionApplyError> {
        self.validate()?;
        digest::binding_digest(self)
    }
}

#[cfg(test)]
mod tests;
