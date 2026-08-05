//! Governed, transactional application of inert cognition proposals.
//!
//! This module owns backend-neutral authority bindings and the no-fallback
//! transaction seam. Cognition engines remain untrusted proposal producers;
//! only [`crate::MemoryVault::apply_cognition`] can turn their output into
//! memory mutations.

mod apply;
mod digest;
mod prepare;
mod types;
mod validate;

pub use types::{
    CognitionApplyError, CognitionAuditEvidence, CognitionAuthorityEvidence,
    CognitionAuthorityVerifier, CognitionBinding, CognitionCommitError, CognitionCommitOutcome,
    CognitionCommitStatus, CognitionCommitStore, CognitionIdempotencyKey, CognitionSourceManifest,
    CognitionSourcePrecondition, PreparedCognitionCommit,
};

impl crate::CognitionProposal {
    /// Domain-separated canonical digest used for durable proposal identity.
    ///
    /// Projection order is normalized before hashing, so every backend uses
    /// the same idempotency digest without reimplementing TypeSec internals.
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
