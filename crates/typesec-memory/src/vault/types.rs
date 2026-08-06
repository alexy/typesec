//! Query, result, and plan types for the vault.

use std::marker::PhantomData;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::label::{Clearance, Label};
use crate::record::{EntityRef, MemoryContent, MemoryDraft, Provenance, StoredRecord};
use crate::space::{MemoryId, MemoryKind};
use crate::store::StoreQuery;

/// What to recall. Translated to a [`StoreQuery`] scoped to the vault's space;
/// the *ceiling* comes from the `recall::<L>` type parameter, not from here.
#[derive(Debug, Clone, Default)]
pub struct RecallQuery {
    /// Restrict to one memory kind.
    pub kind: Option<MemoryKind>,
    /// Require a referenced entity.
    pub entity: Option<String>,
    /// Case-insensitive substring over record text.
    pub text_contains: Option<String>,
    /// Point-in-time recall: only records valid at this instant.
    pub valid_at: Option<DateTime<Utc>>,
    /// Include quarantined records (default false).
    pub include_quarantined: bool,
    /// Cap the number of returned records.
    pub limit: Option<usize>,
}

impl RecallQuery {
    /// A query matching everything in the space.
    pub fn all() -> Self {
        Self::default()
    }

    /// Free-text recall.
    pub fn text(needle: impl Into<String>) -> Self {
        Self {
            text_contains: Some(needle.into()),
            ..Self::default()
        }
    }

    pub(crate) fn to_store_query(&self, space_id: &str, purposes: Vec<String>) -> StoreQuery {
        StoreQuery {
            space_id: Some(space_id.to_string()),
            kind: self.kind,
            // No label filter here: the vault splits results by ceiling so it
            // can surface redacted hits for records above it.
            max_label: None,
            valid_at: self.valid_at,
            entity: self.entity.clone(),
            text_contains: self.text_contains.clone(),
            any_purpose: purposes,
            include_quarantined: self.include_quarantined,
            include_invalidated: false,
            limit: self.limit,
        }
    }
}

/// A record returned in the clear because its label is at or below the recall
/// ceiling and the caller held the read capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecalledMemory {
    /// Record id.
    pub id: MemoryId,
    /// Memory kind.
    pub kind: MemoryKind,
    /// The record's runtime label (≤ the recall ceiling).
    pub label: Label,
    /// The content.
    pub content: MemoryContent,
    /// Referenced entities.
    pub entities: Vec<EntityRef>,
    /// Provenance.
    pub provenance: Provenance,
    /// When the fact became true.
    pub valid_from: DateTime<Utc>,
}

impl RecalledMemory {
    pub(crate) fn from_record(record: &StoredRecord) -> Self {
        Self {
            id: record.id.clone(),
            kind: record.kind,
            label: record.label,
            content: record.content().clone(),
            entities: record.entities.clone(),
            provenance: record.provenance.clone(),
            valid_from: record.valid_from,
        }
    }
}

/// A record whose label exceeds the recall ceiling: its existence and
/// metadata are visible, but its content is not — escalate with
/// [`MemoryVault::reveal`][crate::MemoryVault::reveal].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedHit {
    /// Record id (usable with `reveal`).
    pub id: MemoryId,
    /// Memory kind.
    pub kind: MemoryKind,
    /// The record's label (above the ceiling).
    pub label: Label,
    /// Referenced entities.
    pub entities: Vec<EntityRef>,
}

impl RedactedHit {
    pub(crate) fn from_record(record: &StoredRecord) -> Self {
        Self {
            id: record.id.clone(),
            kind: record.kind,
            label: record.label,
            entities: record.entities.clone(),
        }
    }
}

/// The result of a `recall::<L>`, carrying its clearance as a type parameter
/// so two recalls at different ceilings are different types and cannot be
/// mixed — the information-flow guarantee at the recall boundary.
#[derive(Debug, Clone)]
pub struct Recall<L: Clearance> {
    /// Records readable at this clearance.
    pub hits: Vec<RecalledMemory>,
    /// Records that exist but exceed this clearance.
    pub redacted: Vec<RedactedHit>,
    _clearance: PhantomData<fn() -> L>,
}

impl<L: Clearance> Recall<L> {
    pub(crate) fn new(hits: Vec<RecalledMemory>, redacted: Vec<RedactedHit>) -> Self {
        Self {
            hits,
            redacted,
            _clearance: PhantomData,
        }
    }

    /// The clearance ceiling this recall was performed at.
    pub fn ceiling(&self) -> Label {
        L::ceiling()
    }

    /// Whether anything was withheld above the ceiling.
    pub fn has_redactions(&self) -> bool {
        !self.redacted.is_empty()
    }
}

/// Which records to forget.
#[derive(Debug, Clone)]
pub enum ForgetSelector {
    /// Forget specific records by id.
    Ids(Vec<MemoryId>),
    /// Forget every record matching a query (scoped to the space).
    Matching(RecallQuery),
}

/// A record of a destructive forget, for the audit trail (and, in M2, a
/// signed deletion receipt).
#[derive(Debug, Clone)]
pub struct Tombstone {
    /// The records that were destroyed.
    pub forgotten: Vec<MemoryId>,
    /// When.
    pub at: DateTime<Utc>,
}

/// A consolidation step: supersede a set of records with a summary, or just
/// invalidate them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::large_enum_variant)] // Preserve the established by-value replacement API.
pub enum ConsolidationStep {
    /// Invalidate `superseded` and write `replacement`. The replacement's
    /// label is raised to the join of all superseded labels (a summary of a
    /// Sensitive memory is Sensitive).
    Supersede {
        /// Records made historical.
        superseded: Vec<MemoryId>,
        /// The consolidating memory.
        replacement: MemoryDraft,
    },
    /// Invalidate records without a replacement (e.g. a retracted fact).
    Invalidate {
        /// Records to invalidate.
        ids: Vec<MemoryId>,
    },
}

/// A batch of consolidation steps applied atomically where the backend
/// supports transactions (M4 Grust store).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationPlan {
    /// The steps to apply, in order.
    pub steps: Vec<ConsolidationStep>,
}

impl ConsolidationPlan {
    /// An empty plan.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a step.
    #[must_use]
    pub fn then(mut self, step: ConsolidationStep) -> Self {
        self.steps.push(step);
        self
    }
}

/// What a consolidation did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsolidationReport {
    /// Records invalidated (made historical).
    pub invalidated: Vec<MemoryId>,
    /// New consolidating records created.
    pub created: Vec<MemoryId>,
}
