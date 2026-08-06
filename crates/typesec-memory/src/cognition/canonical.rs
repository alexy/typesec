//! Shared canonical text and digest validation for cognition identities.

use super::limits::MAX_COGNITION_IDENTITY_BYTES;
pub(super) use crate::canonical::is_canonical_sha256;

pub(super) fn is_canonical_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COGNITION_IDENTITY_BYTES
        && value == value.trim()
        && !value.chars().any(char::is_control)
}
