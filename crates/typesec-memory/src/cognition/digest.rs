use serde::Serialize;
use sha2::{Digest, Sha256};

use super::canonical::canonical_projection;
use super::types::{
    CognitionApplyError, CognitionBinding, CognitionSourceManifest, CognitionSourcePrecondition,
};
use super::{CognitionEffect, PreparedCognitionCommit};
use crate::index::IndexMutation;
use crate::store::StoreBatchOp;
use crate::{
    CognitionAuditEvidence, CognitionIdempotencyKey, CognitionProposal, ConsolidationPlan,
    GovernedSourceScope, Label, MemoryDraft, MemoryId, StoredRecord,
};

const RECORD_DOMAIN: &[u8] = b"typesec.marciana.source-record.v1\0";
const MANIFEST_DOMAIN: &[u8] = b"typesec.marciana.source-manifest.v1\0";
const BINDING_DOMAIN: &[u8] = b"typesec.marciana.binding.v1\0";
const PROPOSAL_DOMAIN: &[u8] = b"typesec.marciana.proposal.v2\0";
const EVIDENCE_DOMAIN: &[u8] = b"typesec.marciana.evidence.v1\0";
const PREPARED_COMMIT_DOMAIN: &[u8] = b"typesec.marciana.prepared-commit.v5\0";
const AUTHORITY_SCOPE_DOMAIN: &[u8] = b"typesec.marciana.authority-scope.v1\0";
// Coalesce serde's field-sized writes before the accelerated SHA backend.
const PROPOSAL_DIGEST_BUFFER_BYTES: usize = 32 * 1024;

fn tagged_serialized_digest<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<String, CognitionApplyError> {
    let mut digest = Sha256::new();
    digest.update(domain);
    serde_json::to_writer(DigestWriter(&mut digest), value)
        .map_err(|error| CognitionApplyError::Serialization(error.to_string()))?;
    Ok(format!("sha256:{:x}", digest.finalize()))
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

pub(super) fn source_precondition(
    record: &StoredRecord,
) -> Result<CognitionSourcePrecondition, CognitionApplyError> {
    Ok(CognitionSourcePrecondition {
        id: record.id.clone(),
        record_digest: tagged_serialized_digest(RECORD_DOMAIN, record)?,
    })
}

pub(super) fn source_manifest(
    records: &[StoredRecord],
) -> Result<CognitionSourceManifest, CognitionApplyError> {
    let mut sources = records
        .iter()
        .map(source_precondition)
        .collect::<Result<Vec<_>, _>>()?;
    sources.sort_by(|left, right| left.id.cmp(&right.id));
    let joined_label = records
        .iter()
        .fold(Label::Public, |joined, record| joined.join(record.label));
    Ok(CognitionSourceManifest {
        digest: tagged_serialized_digest(MANIFEST_DOMAIN, &sources)?,
        sources,
        joined_label,
    })
}

pub(super) fn binding_digest(binding: &CognitionBinding) -> Result<String, CognitionApplyError> {
    binding_digest_with_projection(binding, canonical_projection(&binding.effective_projection))
}

pub(super) fn binding_digest_with_projection(
    binding: &CognitionBinding,
    projection: Vec<&str>,
) -> Result<String, CognitionApplyError> {
    tagged_serialized_digest(BINDING_DOMAIN, &CanonicalBinding::new(binding, projection))
}

pub(super) fn proposal_digest_with_wire_limit(
    proposal: &CognitionProposal,
    max_wire_bytes: usize,
) -> Result<String, CognitionApplyError> {
    // Canonicalization only reorders projection strings (which preserves byte
    // length) and normalizes this timestamp. Adjusting for the two serialized
    // timestamp lengths therefore enforces the exact noncanonical wire limit
    // while hashing the canonical representation in the same bounded pass.
    let canonical_time_bytes = serialized_len(&chrono::DateTime::<chrono::Utc>::UNIX_EPOCH)?;
    let observed_time_bytes = serialized_len(&proposal.created_at)?;
    let canonical_limit = max_wire_bytes
        .checked_sub(observed_time_bytes)
        .and_then(|remaining| remaining.checked_add(canonical_time_bytes))
        .ok_or(CognitionApplyError::LimitExceeded("proposal bytes"))?;

    let mut digest = Sha256::new();
    digest.update(PROPOSAL_DOMAIN);
    let mut writer = BoundedDigestWriter::new(&mut digest, canonical_limit);
    let serialized = {
        let mut buffered =
            std::io::BufWriter::with_capacity(PROPOSAL_DIGEST_BUFFER_BYTES, &mut writer);
        serde_json::to_writer(&mut buffered, &CanonicalProposal::new(proposal))
            .and_then(|()| std::io::Write::flush(&mut buffered).map_err(serde_json::Error::io))
    };
    if writer.exceeded {
        return Err(CognitionApplyError::LimitExceeded("proposal bytes"));
    }
    serialized.map_err(|error| CognitionApplyError::Serialization(error.to_string()))?;
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn serialized_len(value: &impl Serialize) -> Result<usize, CognitionApplyError> {
    let mut writer = LengthWriter::default();
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| CognitionApplyError::Serialization(error.to_string()))?;
    Ok(writer.written)
}

#[derive(Default)]
struct LengthWriter {
    written: usize,
}

impl std::io::Write for LengthWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.written = self
            .written
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("serialized length overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct BoundedDigestWriter<'a> {
    digest: &'a mut Sha256,
    remaining: usize,
    exceeded: bool,
}

impl<'a> BoundedDigestWriter<'a> {
    fn new(digest: &'a mut Sha256, limit: usize) -> Self {
        Self {
            digest,
            remaining: limit,
            exceeded: false,
        }
    }
}

impl std::io::Write for BoundedDigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(std::io::Error::other(
                "cognition proposal exceeds byte limit",
            ));
        }
        self.remaining -= bytes.len();
        self.digest.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalBinding<'a> {
    space_id: &'a str,
    subject: &'a str,
    purpose: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    governed_source_scope: Option<&'a GovernedSourceScope>,
    governed_scan_digest: &'a str,
    snapshot_digest: &'a str,
    plan_task_digest: &'a str,
    authorization_receipt_digest: &'a str,
    effective_projection: Vec<&'a str>,
    source_manifest_digest: &'a str,
    typedid_request_digest: &'a str,
}

impl<'a> CanonicalBinding<'a> {
    fn new(binding: &'a CognitionBinding, effective_projection: Vec<&'a str>) -> Self {
        Self {
            space_id: &binding.space_id,
            subject: &binding.subject,
            purpose: &binding.purpose,
            governed_source_scope: binding.governed_source_scope.as_ref(),
            governed_scan_digest: &binding.governed_scan_digest,
            snapshot_digest: &binding.snapshot_digest,
            plan_task_digest: &binding.plan_task_digest,
            authorization_receipt_digest: &binding.authorization_receipt_digest,
            effective_projection,
            source_manifest_digest: &binding.source_manifest_digest,
            typedid_request_digest: &binding.typedid_request_digest,
        }
    }
}

#[derive(Serialize)]
struct CanonicalProposal<'a> {
    schema_version: u32,
    effect: CognitionEffect,
    job_id: &'a str,
    input_snapshot: &'a str,
    source_digest: &'a str,
    algorithm: &'a str,
    algorithm_version: &'a str,
    source_ids: &'a [MemoryId],
    joined_label: Label,
    drafts: &'a [MemoryDraft],
    plan: &'a ConsolidationPlan,
    evidence: &'a [String],
    created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding: Option<CanonicalBinding<'a>>,
}

impl<'a> CanonicalProposal<'a> {
    fn new(proposal: &'a CognitionProposal) -> Self {
        Self {
            schema_version: proposal.schema_version,
            effect: proposal.effect,
            job_id: &proposal.job_id,
            input_snapshot: &proposal.input_snapshot,
            source_digest: &proposal.source_digest,
            algorithm: &proposal.algorithm,
            algorithm_version: &proposal.algorithm_version,
            source_ids: &proposal.source_ids,
            joined_label: proposal.joined_label,
            drafts: &proposal.drafts,
            plan: &proposal.plan,
            evidence: &proposal.evidence,
            // Creation time is observational scheduler metadata, not mutation
            // identity. A worker retry may regenerate the same inert proposal
            // later while every authority, source, plan, draft, and evidence
            // field remains bound.
            created_at: chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
            binding: proposal.binding.as_ref().map(|binding| {
                CanonicalBinding::new(binding, canonical_projection(&binding.effective_projection))
            }),
        }
    }
}

pub(super) fn evidence_digest(evidence: &[String]) -> Result<String, CognitionApplyError> {
    tagged_serialized_digest(EVIDENCE_DOMAIN, evidence)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalAuthorityScope<'a> {
    subject: &'a str,
    purpose: &'a str,
}

pub(super) fn authority_scope_digest(
    subject: &str,
    purpose: &str,
) -> Result<String, CognitionApplyError> {
    tagged_serialized_digest(
        AUTHORITY_SCOPE_DOMAIN,
        &CanonicalAuthorityScope { subject, purpose },
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalPreparedCommit<'a> {
    idempotency_key: &'a CognitionIdempotencyKey,
    proposal_digest: &'a str,
    source_preconditions: &'a [CognitionSourcePrecondition],
    operations: &'a [StoreBatchOp],
    index_outbox: &'a [IndexMutation],
    audit: &'a CognitionAuditEvidence,
}

pub(super) fn prepared_commit_digest(
    commit: &PreparedCognitionCommit,
) -> Result<String, CognitionApplyError> {
    tagged_serialized_digest(
        PREPARED_COMMIT_DOMAIN,
        &CanonicalPreparedCommit {
            idempotency_key: commit.idempotency_key(),
            proposal_digest: commit.proposal_digest(),
            source_preconditions: commit.source_preconditions(),
            operations: commit.operations(),
            index_outbox: commit.index_outbox(),
            audit: commit.audit(),
        },
    )
}
