//! Shared canonical text and digest validation for cognition identities.

const MAX_IDENTITY_BYTES: usize = 4_096;

pub(super) fn is_canonical_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTITY_BYTES
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

pub(super) fn is_canonical_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}
