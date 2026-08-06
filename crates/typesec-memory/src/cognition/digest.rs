use serde::Serialize;
use sha2::{Digest, Sha256};

use super::PreparedCognitionCommit;
use super::types::{
    CognitionApplyError, CognitionBinding, CognitionSourceManifest, CognitionSourcePrecondition,
};
use crate::index::IndexMutation;
use crate::store::StoreBatchOp;
use crate::{
    CognitionAuditEvidence, CognitionIdempotencyKey, CognitionProposal, Label, StoredRecord,
};

const RECORD_DOMAIN: &[u8] = b"typesec.marciana.source-record.v1\0";
const MANIFEST_DOMAIN: &[u8] = b"typesec.marciana.source-manifest.v1\0";
const BINDING_DOMAIN: &[u8] = b"typesec.marciana.binding.v1\0";
const PROPOSAL_DOMAIN: &[u8] = b"typesec.marciana.proposal.v2\0";
const EVIDENCE_DOMAIN: &[u8] = b"typesec.marciana.evidence.v1\0";
const PREPARED_COMMIT_DOMAIN: &[u8] = b"typesec.marciana.prepared-commit.v5\0";
const AUTHORITY_SCOPE_DOMAIN: &[u8] = b"typesec.marciana.authority-scope.v1\0";

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
    let mut canonical = binding.clone();
    canonical.effective_projection.sort();
    tagged_serialized_digest(BINDING_DOMAIN, &canonical)
}

pub(super) fn proposal_digest(proposal: &CognitionProposal) -> Result<String, CognitionApplyError> {
    let mut canonical = proposal.clone();
    // Creation time is observational scheduler metadata, not mutation
    // identity. A worker retry may regenerate the same inert proposal later;
    // every authority, source, plan, draft, and evidence field remains bound
    // below while the durable idempotency digest stays stable.
    canonical.created_at = chrono::DateTime::<chrono::Utc>::UNIX_EPOCH;
    if let Some(binding) = &mut canonical.binding {
        binding.effective_projection.sort();
    }
    tagged_serialized_digest(PROPOSAL_DOMAIN, &canonical)
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
