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

#[cfg(test)]
mod tests;
