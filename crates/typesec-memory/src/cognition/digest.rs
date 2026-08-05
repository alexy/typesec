use sha2::{Digest, Sha256};

use super::types::{
    CognitionApplyError, CognitionBinding, CognitionSourceManifest, CognitionSourcePrecondition,
};
use crate::{CognitionProposal, Label, StoredRecord};

const RECORD_DOMAIN: &[u8] = b"typesec.marciana.source-record.v1\0";
const MANIFEST_DOMAIN: &[u8] = b"typesec.marciana.source-manifest.v1\0";
const BINDING_DOMAIN: &[u8] = b"typesec.marciana.binding.v1\0";
const PROPOSAL_DOMAIN: &[u8] = b"typesec.marciana.proposal.v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"typesec.marciana.evidence.v1\0";

fn tagged_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    format!("sha256:{:x}", digest.finalize())
}

pub(super) fn source_precondition(
    record: &StoredRecord,
) -> Result<CognitionSourcePrecondition, CognitionApplyError> {
    let bytes = serde_json::to_vec(record)
        .map_err(|error| CognitionApplyError::Serialization(error.to_string()))?;
    Ok(CognitionSourcePrecondition {
        id: record.id.clone(),
        record_digest: tagged_digest(RECORD_DOMAIN, &bytes),
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
    let bytes = serde_json::to_vec(&sources)
        .map_err(|error| CognitionApplyError::Serialization(error.to_string()))?;
    Ok(CognitionSourceManifest {
        sources,
        digest: tagged_digest(MANIFEST_DOMAIN, &bytes),
        joined_label,
    })
}

pub(super) fn binding_digest(binding: &CognitionBinding) -> Result<String, CognitionApplyError> {
    let mut canonical = binding.clone();
    canonical.effective_projection.sort();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| CognitionApplyError::Serialization(error.to_string()))?;
    Ok(tagged_digest(BINDING_DOMAIN, &bytes))
}

pub(super) fn proposal_digest(proposal: &CognitionProposal) -> Result<String, CognitionApplyError> {
    let mut canonical = proposal.clone();
    if let Some(binding) = &mut canonical.binding {
        binding.effective_projection.sort();
    }
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| CognitionApplyError::Serialization(error.to_string()))?;
    Ok(tagged_digest(PROPOSAL_DOMAIN, &bytes))
}

pub(super) fn evidence_digest(evidence: &[String]) -> Result<String, CognitionApplyError> {
    let bytes = serde_json::to_vec(evidence)
        .map_err(|error| CognitionApplyError::Serialization(error.to_string()))?;
    Ok(tagged_digest(EVIDENCE_DOMAIN, &bytes))
}
