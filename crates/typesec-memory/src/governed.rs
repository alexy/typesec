//! Vault-owned binding between persisted memories and verified source scopes.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use typesec_core::SubjectId;
use typesec_core::policy::RequestContext;

use crate::canonical::is_canonical_sha256;
use crate::record::{MemoryDraft, StoredRecord};

const DRAFT_DOMAIN: &[u8] = b"typesec.governed-source-draft.v1\0";

/// Maximum opaque verification evidence accepted before trusted verifier work.
pub const MAX_GOVERNED_SOURCE_EVIDENCE_BYTES: usize = 16 * 1024 * 1024;

/// Opaque, canonical identity of one externally governed source scope.
///
/// Constructing this value is harmless: only
/// [`crate::MemoryVault::remember_governed`] can attach it to a record, and
/// that path first invokes the host-configured [`GovernedSourceVerifier`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct GovernedSourceScope(String);

impl GovernedSourceScope {
    /// Validate and retain one canonical lowercase `sha256:` scope digest.
    pub fn from_digest(value: impl Into<String>) -> Result<Self, GovernedSourceScopeError> {
        let value = value.into();
        if is_canonical_sha256(&value) {
            Ok(Self(value))
        } else {
            Err(GovernedSourceScopeError)
        }
    }

    /// Borrow the canonical scope digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GovernedSourceScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for GovernedSourceScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_digest(value).map_err(serde::de::Error::custom)
    }
}

/// A source scope was not a canonical lowercase SHA-256 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid governed source scope")]
pub struct GovernedSourceScopeError;

/// Borrowed, non-constructible evidence presented to the trusted verifier.
///
/// The verifier must bind the opaque evidence to every exposed field. The
/// draft itself is never released: only its domain-separated digest crosses
/// this boundary.
pub struct GovernedSourceVerification<'a> {
    scope: &'a GovernedSourceScope,
    subject: &'a SubjectId,
    space_id: &'a str,
    context: &'a RequestContext,
    evidence: &'a [u8],
    draft_digest: &'a str,
}

impl<'a> GovernedSourceVerification<'a> {
    pub(crate) fn new(
        scope: &'a GovernedSourceScope,
        subject: &'a SubjectId,
        space_id: &'a str,
        context: &'a RequestContext,
        evidence: &'a [u8],
        draft_digest: &'a str,
    ) -> Self {
        Self {
            scope,
            subject,
            space_id,
            context,
            evidence,
            draft_digest,
        }
    }

    /// Exact canonical scope the vault will attach after verification.
    pub fn scope(&self) -> &GovernedSourceScope {
        self.scope
    }

    /// Capability subject requesting governed ingestion.
    pub fn subject(&self) -> &SubjectId {
        self.subject
    }

    /// Exact target memory-space resource identity.
    pub fn space_id(&self) -> &str {
        self.space_id
    }

    /// Use-time policy context supplied to the vault.
    pub fn context(&self) -> &RequestContext {
        self.context
    }

    /// Bounded opaque evidence supplied by the host integration.
    pub fn evidence(&self) -> &[u8] {
        self.evidence
    }

    /// Domain-separated digest of the exact draft consumed by the vault.
    pub fn draft_digest(&self) -> &str {
        self.draft_digest
    }
}

/// Trusted host adapter that verifies an external source-scope binding.
///
/// TypeSec intentionally knows nothing about LakeCat or another governance
/// provider. Implementations retain detailed failures only in protected host
/// diagnostics and return the fixed public error below.
pub trait GovernedSourceVerifier: Send + Sync {
    /// Verify that the evidence authorizes this exact ingestion request.
    fn verify(
        &self,
        request: &GovernedSourceVerification<'_>,
    ) -> Result<(), GovernedSourceVerificationError>;
}

/// Fixed failure from governed source verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GovernedSourceVerificationError {
    /// Verification failed or its trusted dependency was unavailable.
    #[error("governed source verification is unavailable")]
    Unavailable,
}

pub(crate) fn validate_evidence_budget(
    evidence: &[u8],
) -> Result<(), GovernedSourceVerificationError> {
    if evidence.len() <= MAX_GOVERNED_SOURCE_EVIDENCE_BYTES {
        Ok(())
    } else {
        Err(GovernedSourceVerificationError::Unavailable)
    }
}

/// Compute the exact domain-separated draft digest checked by governed
/// ingestion.
///
/// Trusted adapters use this harmless helper to prime an allowlist from
/// authenticated staged drafts. Possessing a digest grants no authority; the
/// vault still requires a matching verifier decision for the full request.
pub fn governed_source_draft_digest(
    draft: &MemoryDraft,
) -> Result<String, GovernedSourceVerificationError> {
    let mut digest = Sha256::new();
    digest.update(DRAFT_DOMAIN);
    serde_json::to_writer(DigestWriter(&mut digest), draft)
        .map_err(|_| GovernedSourceVerificationError::Unavailable)?;
    Ok(format!("sha256:{:x}", digest.finalize()))
}

pub(crate) fn records_match_source_scope(
    records: &[StoredRecord],
    expected: Option<&GovernedSourceScope>,
) -> bool {
    records
        .iter()
        .all(|record| record.governed_source_scope() == expected)
}

pub(crate) fn unanimous_source_scope(
    records: &[StoredRecord],
) -> Result<Option<GovernedSourceScope>, ()> {
    let expected = records
        .first()
        .and_then(StoredRecord::governed_source_scope)
        .cloned();
    if records_match_source_scope(records, expected.as_ref()) {
        Ok(expected)
    } else {
        Err(())
    }
}

struct DigestWriter<'a>(&'a mut Sha256);

impl std::io::Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
