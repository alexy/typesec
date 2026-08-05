//! Cognition hooks (`extract` feature): turning raw episodes into memory.
//!
//! An [`Extractor`] is the mem0-style loop — read a raw episode, decide what
//! to remember and what to supersede — but **untrusted by construction**: its
//! output is [`MemoryDraft`]s and a [`ConsolidationPlan`], never writes.
//! Everything still enters through the capability-gated vault, so the
//! extractor cannot bypass labels, quarantine, or policy. A remote LLM
//! extractor sees only what you feed it; a local one (Ollama) keeps sensitive
//! episodes on-box.

#[cfg(feature = "ollama")]
pub mod ollama;
#[cfg(feature = "ollama")]
pub use ollama::OllamaExtractor;

use crate::label::Label;
use crate::record::{MemoryContent, MemoryDraft, Provenance};
use crate::space::{MemoryId, MemoryKind};
use crate::vault::{ConsolidationPlan, ConsolidationStep};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::cognition::CognitionBinding;

/// Versioned, inert output from an external cognition job.
///
/// A proposal carries the input snapshot and sensitivity join needed for a
/// trusted service to detect stale work and reauthorize application. It has no
/// store handle and cannot mutate memory; drafts and plans must still enter
/// through [`crate::MemoryVault::remember`] or
/// [`crate::MemoryVault::consolidate`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitionProposal {
    /// Proposal schema version.
    pub schema_version: u32,
    /// Idempotent scheduler/job identifier.
    pub job_id: String,
    /// Backend-specific snapshot/version read by the job.
    pub input_snapshot: String,
    /// Stable digest of the source records and relevant policy inputs.
    pub source_digest: String,
    /// Cognition algorithm name.
    pub algorithm: String,
    /// Cognition algorithm version or model identity.
    pub algorithm_version: String,
    /// Exact records used as evidence.
    pub source_ids: Vec<MemoryId>,
    /// Join of every source label as computed by the worker. The vault must
    /// recompute this before application rather than trusting it.
    pub joined_label: Label,
    /// New memories proposed for guarded insertion.
    pub drafts: Vec<MemoryDraft>,
    /// Supersede/invalidate operations proposed for guarded consolidation.
    pub plan: ConsolidationPlan,
    /// Audit-safe evidence or explanation; must not contain source plaintext.
    pub evidence: Vec<String>,
    /// Proposal creation time.
    pub created_at: DateTime<Utc>,
    /// Governed authority and source binding required for trusted application.
    ///
    /// Legacy/local proposal producers may leave this absent, but
    /// `MemoryVault::apply_cognition` always rejects an unbound proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<CognitionBinding>,
}

impl CognitionProposal {
    /// Current proposal schema.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Create an inert proposal with no mutations yet.
    pub fn new(
        job_id: impl Into<String>,
        input_snapshot: impl Into<String>,
        source_digest: impl Into<String>,
        algorithm: impl Into<String>,
        algorithm_version: impl Into<String>,
        source_ids: Vec<MemoryId>,
        joined_label: Label,
    ) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            job_id: job_id.into(),
            input_snapshot: input_snapshot.into(),
            source_digest: source_digest.into(),
            algorithm: algorithm.into(),
            algorithm_version: algorithm_version.into(),
            source_ids,
            joined_label,
            drafts: Vec::new(),
            plan: ConsolidationPlan::new(),
            evidence: Vec::new(),
            created_at: Utc::now(),
            binding: None,
        }
    }

    /// Attach proposed drafts.
    #[must_use]
    pub fn with_drafts(mut self, drafts: Vec<MemoryDraft>) -> Self {
        self.drafts = drafts;
        self
    }

    /// Attach a proposed consolidation plan.
    #[must_use]
    pub fn with_plan(mut self, plan: ConsolidationPlan) -> Self {
        self.plan = plan;
        self
    }

    /// Bind the proposal to verified identity, catalog, authorization, and
    /// source-manifest evidence.
    #[must_use]
    pub fn with_binding(mut self, binding: CognitionBinding) -> Self {
        self.binding = Some(binding);
        self
    }
}

/// A raw interaction to extract memories from.
#[derive(Debug, Clone)]
pub struct Episode {
    /// The text of the interaction (a user message, a tool result, …).
    pub text: String,
    /// Where it came from — carried onto every draft so the vault applies the
    /// right birth label and quarantine.
    pub provenance: Provenance,
}

impl Episode {
    /// A raw model-text episode (will be quarantined at write time).
    pub fn model_text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            provenance: Provenance::ModelText,
        }
    }

    /// An operator/trusted episode.
    pub fn operator(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            provenance: Provenance::Operator,
        }
    }
}

/// A compact view of an existing memory, given to the extractor so it can
/// decide ADD vs. supersede without seeing full (possibly sensitive) content.
#[derive(Debug, Clone)]
pub struct MemorySummary {
    /// The record id (for building supersede plans).
    pub id: crate::space::MemoryId,
    /// A short, non-sensitive gist (the caller decides what is safe to show).
    pub gist: String,
}

/// Extraction failed.
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    /// The extractor backend failed (e.g. the model call).
    #[error("extraction failed: {0}")]
    Backend(String),
}

/// Turns raw episodes into memory drafts and consolidation plans. Output is
/// data, never writes — the vault is still the only path to storage.
pub trait Extractor {
    /// Propose memories to add from `episode`, given the current `existing`
    /// summaries.
    fn extract(
        &self,
        episode: &Episode,
        existing: &[MemorySummary],
    ) -> Result<Vec<MemoryDraft>, ExtractError>;

    /// Propose a consolidation plan (supersede/invalidate) over `existing`
    /// given the freshly-extracted `drafts`. The default proposes nothing.
    fn plan(
        &self,
        _drafts: &[MemoryDraft],
        _existing: &[MemorySummary],
    ) -> Result<ConsolidationPlan, ExtractError> {
        Ok(ConsolidationPlan::new())
    }
}

/// A deterministic, dependency-free extractor for tests and air-gapped use.
///
/// It treats each non-empty line of an episode as one semantic memory, and —
/// as a tiny consolidation heuristic — supersedes an existing memory when a
/// new draft looks like an *attribute update*: the same number of words with
/// only the final word (the "value") changed, e.g. "Alice lives in Rome" →
/// "Alice lives in Venice". Real cognition plugs in via [`Extractor`]; this
/// proves the loop end to end without a model.
#[derive(Debug, Default, Clone)]
pub struct RuleExtractor {
    kind: Option<MemoryKind>,
}

impl RuleExtractor {
    /// Create a rule extractor producing `Semantic` memories.
    pub fn new() -> Self {
        Self::default()
    }

    /// Produce memories of a specific kind.
    #[must_use]
    pub fn of_kind(mut self, kind: MemoryKind) -> Self {
        self.kind = Some(kind);
        self
    }
}

impl Extractor for RuleExtractor {
    fn extract(
        &self,
        episode: &Episode,
        _existing: &[MemorySummary],
    ) -> Result<Vec<MemoryDraft>, ExtractError> {
        let kind = self.kind.unwrap_or(MemoryKind::Semantic);
        Ok(episode
            .text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|line| {
                MemoryDraft::new(kind, MemoryContent::text(line), episode.provenance.clone())
            })
            .collect())
    }

    fn plan(
        &self,
        drafts: &[MemoryDraft],
        existing: &[MemorySummary],
    ) -> Result<ConsolidationPlan, ExtractError> {
        let mut plan = ConsolidationPlan::new();
        for draft in drafts {
            let superseded: Vec<_> = existing
                .iter()
                .filter(|m| is_attribute_update(&m.gist, draft.content_text()))
                .map(|m| m.id.clone())
                .collect();
            if !superseded.is_empty() {
                plan = plan.then(ConsolidationStep::Supersede {
                    superseded,
                    replacement: draft.clone(),
                });
            }
        }
        Ok(plan)
    }
}

/// `new` updates the attribute stated by `old`: same word count (≥ 2), all
/// words equal except the last, and the last differs.
fn is_attribute_update(old: &str, new: &str) -> bool {
    let old: Vec<&str> = old.split_whitespace().collect();
    let new: Vec<&str> = new.split_whitespace().collect();
    if old.len() < 2 || old.len() != new.len() {
        return false;
    }
    let eq_prefix = old[..old.len() - 1]
        .iter()
        .zip(&new[..new.len() - 1])
        .all(|(a, b)| a.eq_ignore_ascii_case(b));
    eq_prefix
        && !old
            .last()
            .unwrap()
            .eq_ignore_ascii_case(new.last().unwrap())
}

#[cfg(test)]
mod tests;
