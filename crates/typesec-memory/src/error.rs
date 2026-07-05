//! The public error type for vault operations.

use thiserror::Error;
use typesec_core::capability::CapabilityUseError;

use crate::store::StoreError;

/// A memory-vault operation failed.
#[derive(Debug, Error)]
pub enum MemoryError {
    /// The supplied capability was for a different space than the operation
    /// targeted — a capability for `memory/a/x` cannot act on `memory/b/y`.
    #[error("capability covers space '{capability_space}', not '{target_space}'")]
    SpaceMismatch {
        /// Space the capability covers.
        capability_space: String,
        /// Space the operation targeted.
        target_space: String,
    },
    /// The capability was expired or revoked at use time.
    #[error("capability is not usable: {0}")]
    Capability(#[from] CapabilityUseError),
    /// A referenced record does not exist (or is not in the target space).
    #[error("no such record '{0}' in this space")]
    NotFound(String),
    /// A configured policy engine denied the operation under the current
    /// request context (e.g. an ODRL purpose/time constraint failed at use
    /// time), even though a matching capability was presented.
    #[error("policy denied '{action}' at use time: {detail}")]
    PolicyDenied {
        /// The action that was denied.
        action: &'static str,
        /// The engine's rationale.
        detail: String,
    },
    /// A record was requested at a clearance below its label.
    #[error("record '{id}' is labeled {label} — above the recall ceiling {ceiling}")]
    AboveCeiling {
        /// The record id.
        id: String,
        /// The record's label.
        label: &'static str,
        /// The recall/reveal ceiling.
        ceiling: &'static str,
    },
    /// The backing store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}
