//! One authorized, internally consistent cognition-read snapshot.

use chrono::Utc;
use typesec_core::policy::RequestContext;
use typesec_core::{CanRead, Capability};

use super::digest::source_manifest;
use super::source_scope::validate_source_scope;
use super::types::CognitionSourceManifest;
use super::validate::{load_sources, required_purpose};
use crate::error::MemoryError;
use crate::governed::GovernedSourceScope;
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
    governed_source_scope: Option<GovernedSourceScope>,
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

    /// Exact verified source scope, or `None` for explicit local cognition.
    pub fn governed_source_scope(&self) -> Option<&GovernedSourceScope> {
        self.governed_source_scope.as_ref()
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
        self.cognition_input_for_scope_at(space, capability, source_ids, context, ceiling, None)
    }

    /// Read exact governed source revisions for cognition.
    ///
    /// Every selected record must carry the exact expected scope. Mixed,
    /// local, or differently scoped sources fail before plaintext leaves the
    /// vault.
    pub fn governed_cognition_input_at(
        &self,
        space: &MemorySpace,
        capability: &Capability<CanRead, MemorySpace>,
        source_ids: &[MemoryId],
        context: &RequestContext,
        ceiling: Label,
        scope: &GovernedSourceScope,
    ) -> Result<AuthorizedCognitionInput, MemoryError> {
        self.cognition_input_for_scope_at(
            space,
            capability,
            source_ids,
            context,
            ceiling,
            Some(scope),
        )
    }

    fn cognition_input_for_scope_at(
        &self,
        space: &MemorySpace,
        capability: &Capability<CanRead, MemorySpace>,
        source_ids: &[MemoryId],
        context: &RequestContext,
        ceiling: Label,
        scope: Option<&GovernedSourceScope>,
    ) -> Result<AuthorizedCognitionInput, MemoryError> {
        self.authorize(space, capability, context)?;
        let purpose = required_purpose(context)?;
        let records = load_sources(self, space, source_ids, purpose, Utc::now())?;
        validate_source_scope(&records, scope)?;
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
            &format!(
                "ceiling={} sources={} governed={}",
                ceiling.name(),
                records.len(),
                scope.is_some()
            ),
        );
        Ok(AuthorizedCognitionInput {
            memories,
            manifest,
            governed_source_scope: scope.cloned(),
        })
    }
}
