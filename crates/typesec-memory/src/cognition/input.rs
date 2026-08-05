//! One authorized, internally consistent cognition-read snapshot.

use chrono::Utc;
use typesec_core::policy::RequestContext;
use typesec_core::{CanRead, Capability};

use super::digest::source_manifest;
use super::types::CognitionSourceManifest;
use super::validate::{load_sources, required_purpose};
use crate::error::MemoryError;
use crate::label::Label;
use crate::space::{MemoryId, MemorySpace};
use crate::store::MemoryStore;
use crate::vault::{MemoryVault, RecalledMemory};

/// Transient authorized cognition input derived from one set of record values.
///
/// This type is deliberately non-serializable and cannot be constructed
/// outside TypeSec. Its memories and manifest are computed from the same
/// loaded [`crate::StoredRecord`] values, so a worker can never see plaintext
/// from one revision while later binding a manifest from another revision.
pub struct AuthorizedCognitionInput {
    memories: Vec<RecalledMemory>,
    manifest: CognitionSourceManifest,
}

impl AuthorizedCognitionInput {
    /// Exact authorized memories supplied to the untrusted cognition engine.
    pub fn memories(&self) -> &[RecalledMemory] {
        &self.memories
    }

    /// Manifest computed from the same record values as [`Self::memories`].
    pub fn manifest(&self) -> &CognitionSourceManifest {
        &self.manifest
    }

    /// Consume the transient bundle after a trusted composition layer has
    /// bound both parts into one proposal-planning operation.
    pub fn into_parts(self) -> (Vec<RecalledMemory>, CognitionSourceManifest) {
        (self.memories, self.manifest)
    }
}

impl<S: MemoryStore> MemoryVault<S> {
    /// Read exact source revisions for cognition under a runtime clearance.
    ///
    /// Purpose, policy, validity, retention, quarantine, space, and clearance
    /// are checked before any content leaves the vault. Proposal application
    /// later recomputes this manifest and guards every source revision inside
    /// the authoritative transaction.
    pub fn cognition_input_at(
        &self,
        space: &MemorySpace,
        capability: &Capability<CanRead, MemorySpace>,
        source_ids: &[MemoryId],
        context: &RequestContext,
        ceiling: Label,
    ) -> Result<AuthorizedCognitionInput, MemoryError> {
        self.authorize(space, capability, context)?;
        let purpose = required_purpose(context)?;
        let records = load_sources(self, space, source_ids, purpose, Utc::now())?;
        if let Some(record) = records.iter().find(|record| record.label > ceiling) {
            return Err(MemoryError::AboveCeiling {
                id: record.id.to_string(),
                label: record.label.name(),
                ceiling: ceiling.name(),
            });
        }

        let manifest = source_manifest(&records)?;
        let memories = records.iter().map(RecalledMemory::from_record).collect();
        crate::vault::audit(
            "memory:cognition_read",
            capability.subject(),
            space,
            &format!("ceiling={} sources={}", ceiling.name(), records.len()),
        );
        Ok(AuthorizedCognitionInput { memories, manifest })
    }
}
