//! Fixed safety budgets for governed cognition inputs and proposals.

use std::io::{self, Write};

use serde::Serialize;

use crate::{CognitionProposal, ConsolidationStep, MemoryId, StoredRecord};

use super::CognitionApplyError;
use super::identity::COGNITION_OUTPUT_ID_BYTES;

/// Maximum number of source records in one governed cognition operation.
pub const MAX_COGNITION_SOURCE_COUNT: usize = 4_096;

/// Maximum aggregate bytes released or amplified by cognition. This covers
/// the serialized authorized source projection, cloned lineage IDs, and the
/// affected-ID set later bound into a receipt.
pub const MAX_COGNITION_SOURCE_BYTES: usize = 4 * 1024 * 1024;

/// Maximum encoded size of one inert cognition proposal.
pub const MAX_COGNITION_PROPOSAL_BYTES: usize = 16 * 1024 * 1024;

/// Maximum bytes in one canonical cognition identity or projection field.
pub const MAX_COGNITION_IDENTITY_BYTES: usize = 4_096;

/// Maximum fields in one governed cognition projection.
pub const MAX_COGNITION_PROJECTION_FIELDS: usize = 256;

/// Maximum authoritative mutations and affected IDs in one atomic commit.
pub const MAX_COGNITION_MUTATIONS: usize = 4_096;

/// Maximum bytes in a cognition algorithm name or version.
pub const MAX_COGNITION_ALGORITHM_BYTES: usize = 256;

/// Maximum audit-safe worker evidence items in one proposal.
pub const MAX_COGNITION_EVIDENCE_ITEMS: usize = 4_096;

pub(super) fn validate_projection_count(count: usize) -> Result<(), CognitionApplyError> {
    enforce(
        count <= MAX_COGNITION_PROJECTION_FIELDS,
        "effective projection",
    )
}

pub(super) fn validate_proposal_budget(
    proposal: &CognitionProposal,
) -> Result<(), CognitionApplyError> {
    enforce(
        proposal.source_ids.len() <= MAX_COGNITION_SOURCE_COUNT,
        "source count",
    )?;
    enforce(
        proposal.job_id.len() <= MAX_COGNITION_IDENTITY_BYTES,
        "job identity",
    )?;
    enforce(
        proposal.algorithm.len() <= MAX_COGNITION_ALGORITHM_BYTES
            && proposal.algorithm_version.len() <= MAX_COGNITION_ALGORITHM_BYTES,
        "algorithm identity",
    )?;
    enforce(
        proposal.evidence.len() <= MAX_COGNITION_EVIDENCE_ITEMS,
        "evidence count",
    )?;
    enforce(
        proposal.plan.steps.len() <= MAX_COGNITION_MUTATIONS,
        "plan step count",
    )?;

    let outputs = proposal_output_count(proposal)?;
    enforce(outputs <= MAX_COGNITION_MUTATIONS, "mutation count")?;

    let targets = proposal.plan.steps.iter().try_fold(0usize, |total, step| {
        let count = match step {
            ConsolidationStep::Supersede { superseded, .. } => superseded.len(),
            ConsolidationStep::Invalidate { ids } => ids.len(),
        };
        total
            .checked_add(count)
            .ok_or(CognitionApplyError::LimitExceeded("mutation target count"))
    })?;
    enforce(targets <= MAX_COGNITION_MUTATIONS, "mutation target count")?;
    let operations = outputs
        .checked_add(targets)
        .ok_or(CognitionApplyError::LimitExceeded("mutation count"))?;
    enforce(operations <= MAX_COGNITION_MUTATIONS, "mutation count")?;
    validate_prepared_expansion(proposal, outputs)?;

    let mut writer = BoundedWriter::new(MAX_COGNITION_PROPOSAL_BYTES);
    let serialized = serde_json::to_writer(&mut writer, proposal);
    if writer.exceeded {
        return Err(CognitionApplyError::LimitExceeded("proposal bytes"));
    }
    serialized.map_err(|error| CognitionApplyError::Serialization(error.to_string()))
}

pub(super) fn proposal_output_count(
    proposal: &CognitionProposal,
) -> Result<usize, CognitionApplyError> {
    let replacements = proposal
        .plan
        .steps
        .iter()
        .filter(|step| matches!(step, ConsolidationStep::Supersede { .. }))
        .count();
    proposal
        .drafts
        .len()
        .checked_add(replacements)
        .ok_or(CognitionApplyError::LimitExceeded("mutation count"))
}

pub(super) fn validate_prepared_expansion(
    proposal: &CognitionProposal,
    output_count: usize,
) -> Result<(), CognitionApplyError> {
    let source_id_bytes = checked_id_bytes(proposal.source_ids.iter())
        .ok_or(CognitionApplyError::LimitExceeded("lineage bytes"))?;
    validate_lineage_dimensions(proposal.source_ids.len(), source_id_bytes, output_count)?;

    let target_id_bytes =
        checked_id_bytes(proposal.plan.steps.iter().flat_map(|step| match step {
            ConsolidationStep::Supersede { superseded, .. } => superseded.iter(),
            ConsolidationStep::Invalidate { ids } => ids.iter(),
        }))
        .ok_or(CognitionApplyError::LimitExceeded("affected id bytes"))?;
    let output_id_bytes = output_count
        .checked_mul(COGNITION_OUTPUT_ID_BYTES)
        .ok_or(CognitionApplyError::LimitExceeded("affected id bytes"))?;
    let affected_id_bytes = target_id_bytes
        .checked_add(output_id_bytes)
        .ok_or(CognitionApplyError::LimitExceeded("affected id bytes"))?;
    enforce(
        affected_id_bytes <= MAX_COGNITION_SOURCE_BYTES,
        "affected id bytes",
    )
}

fn validate_lineage_dimensions(
    source_count: usize,
    source_id_bytes: usize,
    output_count: usize,
) -> Result<(), CognitionApplyError> {
    let references =
        source_count
            .checked_mul(output_count)
            .ok_or(CognitionApplyError::LimitExceeded(
                "lineage reference count",
            ))?;
    enforce(
        references <= MAX_COGNITION_MUTATIONS,
        "lineage reference count",
    )?;
    let bytes = source_id_bytes
        .checked_mul(output_count)
        .ok_or(CognitionApplyError::LimitExceeded("lineage bytes"))?;
    enforce(bytes <= MAX_COGNITION_SOURCE_BYTES, "lineage bytes")
}

pub(super) fn validate_affected_id_budget(ids: &[MemoryId]) -> Result<(), CognitionApplyError> {
    enforce(affected_ids_within_byte_budget(ids), "affected id bytes")
}

pub(super) fn affected_ids_within_byte_budget(ids: &[MemoryId]) -> bool {
    checked_id_bytes(ids.iter()).is_some_and(|bytes| bytes <= MAX_COGNITION_SOURCE_BYTES)
}

fn checked_id_bytes<'a>(mut ids: impl Iterator<Item = &'a MemoryId>) -> Option<usize> {
    ids.try_fold(0usize, |total, id| total.checked_add(id.as_str().len()))
}

#[cfg(test)]
pub(super) fn validate_lineage_dimensions_for_test(
    source_count: usize,
    source_id_bytes: usize,
    output_count: usize,
) -> Result<(), CognitionApplyError> {
    validate_lineage_dimensions(source_count, source_id_bytes, output_count)
}

/// Incremental guard for source material released to a cognition engine.
///
/// [`Self::try_add`] accounts for an adapter's compact ID-and-text view.
/// TypeSec's authorized input path separately uses the crate-internal full
/// record projection accounting, which includes every field cloned into a
/// [`crate::vault::RecalledMemory`]. Failed additions never advance either
/// budget.
#[derive(Debug, Default)]
pub struct CognitionSourceBudget {
    count: usize,
    bytes: usize,
}

impl CognitionSourceBudget {
    /// Start an empty source budget.
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(super) fn with_usage(count: usize, bytes: usize) -> Self {
        Self { count, bytes }
    }

    /// Account for one compact source ID-and-text view before staging it.
    pub fn try_add(&mut self, id: &str, text: &str) -> Result<(), CognitionApplyError> {
        let count = self
            .count
            .checked_add(1)
            .ok_or(CognitionApplyError::LimitExceeded("source count"))?;
        enforce(count <= MAX_COGNITION_SOURCE_COUNT, "source count")?;
        let bytes = self
            .bytes
            .checked_add(id.len())
            .and_then(|value| value.checked_add(text.len()))
            .ok_or(CognitionApplyError::LimitExceeded("source bytes"))?;
        enforce(bytes <= MAX_COGNITION_SOURCE_BYTES, "source bytes")?;
        self.count = count;
        self.bytes = bytes;
        Ok(())
    }

    /// Account for the complete authorized record projection before retaining
    /// its clone in the vault's cognition input.
    pub(super) fn try_add_record(
        &mut self,
        record: &StoredRecord,
    ) -> Result<(), CognitionApplyError> {
        let count = self
            .count
            .checked_add(1)
            .ok_or(CognitionApplyError::LimitExceeded("source count"))?;
        enforce(count <= MAX_COGNITION_SOURCE_COUNT, "source count")?;
        let remaining = MAX_COGNITION_SOURCE_BYTES
            .checked_sub(self.bytes)
            .ok_or(CognitionApplyError::LimitExceeded("source bytes"))?;
        let projection = authorized_source_projection(record);
        let mut writer = MeasuringWriter::new(remaining);
        let serialized = serde_json::to_writer(&mut writer, &projection);
        if writer.exceeded {
            return Err(CognitionApplyError::LimitExceeded("source bytes"));
        }
        serialized.map_err(|error| CognitionApplyError::Serialization(error.to_string()))?;
        self.count = count;
        self.bytes = self
            .bytes
            .checked_add(writer.written)
            .ok_or(CognitionApplyError::LimitExceeded("source bytes"))?;
        Ok(())
    }
}

fn authorized_source_projection(record: &StoredRecord) -> AuthorizedSourceProjection<'_> {
    AuthorizedSourceProjection {
        id: record.id.as_str(),
        kind: &record.kind,
        label: &record.label,
        content: record.content(),
        entities: &record.entities,
        provenance: &record.provenance,
        valid_from: &record.valid_from,
    }
}

#[cfg(test)]
pub(super) fn authorized_source_projection_bytes(
    record: &StoredRecord,
) -> Result<usize, CognitionApplyError> {
    let mut writer = MeasuringWriter::new(usize::MAX);
    serde_json::to_writer(&mut writer, &authorized_source_projection(record))
        .map_err(|error| CognitionApplyError::Serialization(error.to_string()))?;
    Ok(writer.written)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizedSourceProjection<'a> {
    id: &'a str,
    kind: &'a crate::MemoryKind,
    label: &'a crate::Label,
    content: &'a crate::MemoryContent,
    entities: &'a [crate::EntityRef],
    provenance: &'a crate::Provenance,
    valid_from: &'a chrono::DateTime<chrono::Utc>,
}

fn enforce(allowed: bool, limit: &'static str) -> Result<(), CognitionApplyError> {
    if allowed {
        Ok(())
    } else {
        Err(CognitionApplyError::LimitExceeded(limit))
    }
}

struct BoundedWriter {
    remaining: usize,
    exceeded: bool,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other("cognition proposal exceeds byte limit"));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct MeasuringWriter {
    remaining: usize,
    written: usize,
    exceeded: bool,
}

impl MeasuringWriter {
    fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            written: 0,
            exceeded: false,
        }
    }
}

impl Write for MeasuringWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other("cognition source exceeds byte limit"));
        }
        self.remaining -= bytes.len();
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
