//! Canonical wire-safety checks for cognition receipt claims.

use chrono::{DateTime, TimeDelta, Utc};

use super::CognitionCommitReceipt;
use crate::receipt::ReceiptError;

pub(in crate::receipt) const MAX_IDENTITY_BYTES: usize = 4 * 1024;
pub(in crate::receipt) const MAX_AFFECTED_ID_COUNT: usize = 4_096;
pub(in crate::receipt) const MAX_AFFECTED_ID_BYTES: usize = 4 * 1024 * 1024;

const INVALID_IDENTITY: &str = "invalid cognition receipt identity";
const INVALID_DIGEST: &str = "invalid cognition receipt digest";
const INVALID_VERSIONS: &str = "invalid cognition receipt versions";
const INVALID_AFFECTED_IDS: &str = "invalid cognition receipt affected IDs";
const INVALID_WINDOW: &str = "invalid cognition receipt validity window";
const INVALID_SCHEMA: &str = "unsupported cognition receipt schema";

pub(super) fn checked_expiry(
    prepared_at: DateTime<Utc>,
    ttl: TimeDelta,
) -> Result<DateTime<Utc>, ReceiptError> {
    let expires_at = prepared_at
        .checked_add_signed(ttl)
        .ok_or_else(|| invalid(INVALID_WINDOW))?;
    if expires_at <= prepared_at {
        return Err(invalid(INVALID_WINDOW));
    }
    Ok(expires_at)
}

pub(super) fn validate(receipt: &CognitionCommitReceipt) -> Result<(), ReceiptError> {
    if receipt.schema_version != CognitionCommitReceipt::SCHEMA_VERSION {
        return Err(invalid(INVALID_SCHEMA));
    }
    validate_identities(receipt)?;
    validate_digests(receipt)?;
    validate_versions(receipt)?;
    validate_affected_ids(&receipt.affected_ids)?;
    if receipt.authority_revalidated_at > receipt.prepared_at
        || receipt.committed_at < receipt.prepared_at
        || receipt.expires_at <= receipt.prepared_at
    {
        return Err(invalid(INVALID_WINDOW));
    }
    Ok(())
}

fn validate_identities(receipt: &CognitionCommitReceipt) -> Result<(), ReceiptError> {
    // Backend versions are store-issued opaque identities, not content
    // digests, so they deliberately share identity canonicalization.
    let identities = [
        receipt.subject.as_str(),
        receipt.resource.as_str(),
        receipt.job_id.as_str(),
        receipt.backend_commit_id.as_str(),
        receipt.prior_version.as_str(),
        receipt.resulting_version.as_str(),
    ];
    if identities.into_iter().all(is_canonical_identity) {
        Ok(())
    } else {
        Err(invalid(INVALID_IDENTITY))
    }
}

fn validate_digests(receipt: &CognitionCommitReceipt) -> Result<(), ReceiptError> {
    let digests = [
        receipt.typedid_request_digest.as_str(),
        receipt.proposal_digest.as_str(),
        receipt.governed_scan_digest.as_str(),
        receipt.input_snapshot_digest.as_str(),
        receipt.policy_decision_digest.as_str(),
        receipt.authorization_receipt_digest.as_str(),
    ];
    if digests.into_iter().all(is_canonical_sha256)
        && receipt.governed_scan_digest != receipt.input_snapshot_digest
        && receipt
            .governed_source_scope
            .as_deref()
            .is_none_or(is_canonical_sha256)
    {
        Ok(())
    } else {
        Err(invalid(INVALID_DIGEST))
    }
}

fn validate_versions(receipt: &CognitionCommitReceipt) -> Result<(), ReceiptError> {
    if receipt.prior_version == receipt.resulting_version {
        Err(invalid(INVALID_VERSIONS))
    } else {
        Ok(())
    }
}

fn validate_affected_ids(ids: &[String]) -> Result<(), ReceiptError> {
    if ids.is_empty() || ids.len() > MAX_AFFECTED_ID_COUNT {
        return Err(invalid(INVALID_AFFECTED_IDS));
    }
    let total_bytes = ids.iter().try_fold(0usize, |total, id| {
        is_canonical_identity(id).then_some(())?;
        total.checked_add(id.len())
    });
    if total_bytes.is_none_or(|total| total > MAX_AFFECTED_ID_BYTES)
        || !ids.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(invalid(INVALID_AFFECTED_IDS));
    }
    Ok(())
}

fn is_canonical_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTITY_BYTES
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn is_canonical_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn invalid(message: &'static str) -> ReceiptError {
    ReceiptError::InvalidClaims(message.to_owned())
}
