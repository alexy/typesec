//! Memory content, provenance, drafts, and the at-rest stored record.
//!
//! The load-bearing invariant lives here: [`StoredRecord`] keeps its
//! `content` **private**. The store round-trips records opaquely, but only
//! the vault (same crate) can read content back out — the single, guarded
//! rehydration site, mirroring core's `Capability::new_minted` pattern. A
//! compile-fail test in `tests/ui/` proves external code cannot touch it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governed::GovernedSourceScope;
use crate::label::Label;
use crate::space::{MemoryId, MemoryKind};

/// The payload of a memory: text plus optional structured attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryContent {
    /// The natural-language statement of the memory.
    pub text: String,
    /// Optional structured facets (subject/predicate/object, tags, …).
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub attributes: serde_json::Map<String, serde_json::Value>,
}

impl MemoryContent {
    /// A text-only memory.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            attributes: serde_json::Map::new(),
        }
    }
}

/// A named entity a record refers to (a hook into the knowledge graph).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityRef {
    /// Canonical entity name.
    pub name: String,
    /// Entity kind (`person`, `org`, `place`, …); free-form.
    pub kind: String,
}

impl EntityRef {
    /// Create an entity reference.
    pub fn new(name: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: kind.into(),
        }
    }
}

/// Where a memory came from — the primary input to its birth label and to
/// whether it is quarantined against memory poisoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum Provenance {
    /// A verified TypeDID envelope (signature + replay checks passed).
    Envelope {
        /// The envelope id.
        envelope_id: String,
    },
    /// A human operator or explicit trusted API call.
    Operator,
    /// The tainted output of a guarded tool call.
    GuardedTool {
        /// Tool the output came through.
        tool: String,
        /// Framework call id, if any.
        call_id: Option<String>,
    },
    /// A conversation turn (structured, but model-adjacent).
    Conversation,
    /// Raw, unverified model text — the poisoning vector; born quarantined.
    ModelText,
    /// A derived artifact applied by the guarded cognition boundary.
    Cognition {
        /// Durable cognition job that produced the artifact.
        job_id: String,
        /// Exact source records that influenced the artifact.
        source_ids: Vec<MemoryId>,
        /// Vault-verified digest of the source manifest.
        source_digest: String,
        /// Cognition algorithm family.
        algorithm: String,
        /// Cognition algorithm or model version.
        algorithm_version: String,
    },
}

impl Provenance {
    /// The default birth label for this source. Trusted sources default to
    /// `Internal`; the model-text vector to `Internal` too but quarantined
    /// (see [`is_untrusted`]). Callers may override via
    /// [`MemoryDraft::with_label`].
    pub fn default_label(&self) -> Label {
        match self {
            Self::Envelope { .. } | Self::Operator => Label::Internal,
            Self::GuardedTool { .. } => Label::Internal,
            Self::Conversation | Self::ModelText | Self::Cognition { .. } => Label::Internal,
        }
    }

    /// Whether a record from this source is born **quarantined** — recallable
    /// only with the quarantine flag and barred from consolidation into
    /// durable memory until explicitly promoted.
    pub fn is_untrusted(&self) -> bool {
        matches!(self, Self::ModelText)
    }
}

/// A request to remember something. Temporal and label fields have safe
/// defaults; provenance is required because it drives security posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDraft {
    pub(crate) kind: MemoryKind,
    pub(crate) content: MemoryContent,
    pub(crate) provenance: Provenance,
    pub(crate) label: Option<Label>,
    pub(crate) entities: Vec<EntityRef>,
    pub(crate) valid_from: Option<DateTime<Utc>>,
    pub(crate) expires_at: Option<DateTime<Utc>>,
    pub(crate) purposes: Vec<String>,
}

impl MemoryDraft {
    /// Start a draft of `kind` carrying `content` from `provenance`.
    pub fn new(kind: MemoryKind, content: MemoryContent, provenance: Provenance) -> Self {
        Self {
            kind,
            content,
            provenance,
            label: None,
            entities: Vec::new(),
            valid_from: None,
            expires_at: None,
            purposes: Vec::new(),
        }
    }

    /// Override the birth label (never used to *lower* below the provenance
    /// default — the vault takes the max of the two, fail-closed).
    #[must_use]
    pub fn with_label(mut self, label: Label) -> Self {
        self.label = Some(label);
        self
    }

    /// Attach referenced entities.
    #[must_use]
    pub fn with_entities(mut self, entities: impl IntoIterator<Item = EntityRef>) -> Self {
        self.entities.extend(entities);
        self
    }

    /// Declare when the fact became true (defaults to now at write time).
    #[must_use]
    pub fn valid_from(mut self, at: DateTime<Utc>) -> Self {
        self.valid_from = Some(at);
        self
    }

    /// Declare a retention deadline.
    #[must_use]
    pub fn expires_at(mut self, at: DateTime<Utc>) -> Self {
        self.expires_at = Some(at);
        self
    }

    /// Tag the purposes this memory may serve (ODRL purpose-bound recall).
    #[must_use]
    pub fn for_purposes(mut self, purposes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.purposes.extend(purposes.into_iter().map(Into::into));
        self
    }

    /// The draft's text (read-only view for extractors and consolidation
    /// planners deciding what supersedes what).
    pub fn content_text(&self) -> &str {
        &self.content.text
    }
}

/// A record as it lives in a store: metadata is public, **content is not**.
///
/// Stores persist and return these opaquely; only the vault reads `content`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRecord {
    /// Record id.
    pub id: MemoryId,
    /// Resource id of the owning space (`memory/<owner>/<space>`).
    pub space_id: String,
    /// Memory kind.
    pub kind: MemoryKind,
    /// Runtime sensitivity label.
    pub label: Label,
    /// Whether the record is quarantined.
    pub quarantined: bool,
    /// Referenced entities.
    pub entities: Vec<EntityRef>,
    /// Provenance.
    pub provenance: Provenance,
    /// Vault-verified external governance scope, when ingestion was governed.
    ///
    /// Private so callers cannot attach or replace it through normal record
    /// APIs. Trusted stores still round-trip it through serde.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    governed_source_scope: Option<GovernedSourceScope>,
    /// When we learned it.
    pub observed_at: DateTime<Utc>,
    /// When the fact became true.
    pub valid_from: DateTime<Utc>,
    /// When it stopped being true (bi-temporal invalidation), if ever.
    pub invalid_at: Option<DateTime<Utc>>,
    /// Retention deadline, if any.
    pub expires_at: Option<DateTime<Utc>>,
    /// Purposes this memory may serve.
    pub purposes: Vec<String>,
    /// The protected payload. Private: only the vault rehydrates it.
    pub(crate) content: MemoryContent,
}

impl StoredRecord {
    /// Whether this record is currently valid at `at` (bi-temporal): it had
    /// become true and has not been invalidated.
    pub fn is_valid_at(&self, at: DateTime<Utc>) -> bool {
        self.valid_from <= at && self.invalid_at.is_none_or(|end| at < end)
    }

    /// Whether the record's retention deadline has passed at `at`.
    pub fn is_expired_at(&self, at: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|deadline| deadline <= at)
    }

    /// Vault-verified external governance scope, if this record has one.
    pub fn governed_source_scope(&self) -> Option<&GovernedSourceScope> {
        self.governed_source_scope.as_ref()
    }

    /// Crate-internal: the protected content, for the vault's single
    /// rehydration site. Not public — reading content is the vault's job.
    pub(crate) fn content(&self) -> &MemoryContent {
        &self.content
    }

    /// Crate-internal: lowercased text for the shared store text filter.
    pub(crate) fn content_text_lower(&self) -> String {
        self.content.text.to_lowercase()
    }

    /// Crate-internal constructor used by the vault when persisting a draft.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn assemble(
        id: MemoryId,
        space_id: String,
        kind: MemoryKind,
        label: Label,
        quarantined: bool,
        entities: Vec<EntityRef>,
        provenance: Provenance,
        governed_source_scope: Option<GovernedSourceScope>,
        observed_at: DateTime<Utc>,
        valid_from: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        purposes: Vec<String>,
        content: MemoryContent,
    ) -> Self {
        Self {
            id,
            space_id,
            kind,
            label,
            quarantined,
            entities,
            provenance,
            governed_source_scope,
            observed_at,
            valid_from,
            invalid_at: None,
            expires_at,
            purposes,
            content,
        }
    }
}

#[cfg(test)]
mod tests;
