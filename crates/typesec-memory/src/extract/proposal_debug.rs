//! Redacted diagnostics for inert cognition proposals.

use std::fmt;

use super::CognitionProposal;

impl fmt::Debug for CognitionProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CognitionProposal")
            .field("schema_version", &self.schema_version)
            .field("effect", &self.effect)
            .field("source_id_count", &self.source_ids.len())
            .field("joined_label", &self.joined_label)
            .field("draft_count", &self.drafts.len())
            .field("plan_step_count", &self.plan.steps.len())
            .field("evidence_count", &self.evidence.len())
            .field("has_binding", &self.binding.is_some())
            .finish()
    }
}
