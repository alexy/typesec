//! `MemoryVault` — the capability-gated front door to a memory store.
//!
//! Every operation takes a typed `Capability<P, MemorySpace>` as proof: there
//! is no unauthenticated path to memory contents. The vault verifies the
//! capability covers the target space and is still active, performs the store
//! op, re-checks the label ceiling on results, and emits an audit event.

mod types;

pub use types::{
    ConsolidationPlan, ConsolidationReport, ConsolidationStep, ForgetSelector, Recall, RecallQuery,
    RecalledMemory, RedactedHit, Tombstone,
};

use chrono::Utc;
use typesec_core::policy::{RequestContext, SubjectId};
use typesec_core::{CanDelete, CanRead, CanReadSensitive, CanWrite, Capability, Resource};

use crate::error::MemoryError;
use crate::label::{Clearance, Label};
use crate::record::{MemoryContent, MemoryDraft, StoredRecord};
use crate::space::{MemoryId, MemorySpace};
use crate::store::MemoryStore;

/// A capability-secured memory store.
pub struct MemoryVault<S: MemoryStore> {
    store: S,
}

impl<S: MemoryStore> MemoryVault<S> {
    /// Wrap a store.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Borrow the underlying store (read-only; bypasses no gates because the
    /// store cannot read record content — that is the vault's private path).
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Verify a capability covers `space` and is currently usable.
    fn authorize<P>(
        space: &MemorySpace,
        cap: &Capability<P, MemorySpace>,
    ) -> Result<(), MemoryError>
    where
        P: typesec_core::Permission,
    {
        if cap.resource_id().as_str() != space.resource_id() {
            return Err(MemoryError::SpaceMismatch {
                capability_space: cap.resource_id().to_string(),
                target_space: space.resource_id().to_string(),
            });
        }
        cap.ensure_active()?;
        Ok(())
    }

    /// Remember something. Requires `CanWrite`. The provenance fixes the birth
    /// label (a caller override may only *raise* it); untrusted provenance
    /// (raw model text) is quarantined.
    pub fn remember(
        &self,
        space: &MemorySpace,
        cap: &Capability<CanWrite, MemorySpace>,
        draft: MemoryDraft,
    ) -> Result<MemoryId, MemoryError> {
        Self::authorize(space, cap)?;

        let birth = draft.provenance.default_label();
        let quarantined = draft.provenance.is_untrusted();
        // A trusted source's declared label is authoritative (it may set
        // anything, including a lower level for genuinely public facts). An
        // untrusted source may only *raise* above the floor — fail closed, so
        // an injection can never talk its way down to Public.
        let label = if quarantined {
            draft.label.map_or(birth, |l| l.max(birth))
        } else {
            draft.label.unwrap_or(birth)
        };
        let now = Utc::now();
        let id = MemoryId::next();

        let record = StoredRecord::assemble(
            id.clone(),
            space.resource_id().to_string(),
            draft.kind,
            label,
            quarantined,
            draft.entities,
            draft.provenance,
            now,
            draft.valid_from.unwrap_or(now),
            draft.expires_at,
            draft.purposes,
            draft.content,
        );
        self.store.put(record)?;

        audit(
            "memory:write",
            cap.subject(),
            space,
            &format!("id={id} label={} quarantined={quarantined}", label.name()),
        );
        Ok(id)
    }

    /// Recall into a context of clearance `L`. Records at or below `L` are
    /// returned in the clear; records above it come back as [`RedactedHit`]s.
    /// The `RequestContext` purpose binds ODRL-style purpose filtering.
    pub fn recall<L: Clearance>(
        &self,
        space: &MemorySpace,
        cap: &Capability<CanRead, MemorySpace>,
        query: RecallQuery,
        ctx: &RequestContext,
    ) -> Result<Recall<L>, MemoryError> {
        Self::authorize(space, cap)?;

        let purposes = ctx.purpose.iter().cloned().collect();
        let store_query = query.to_store_query(space.resource_id(), purposes);
        let records = self.store.query(&store_query)?;

        let ceiling = L::ceiling();
        let mut hits = Vec::new();
        let mut redacted = Vec::new();
        for record in records {
            if record.label <= ceiling {
                hits.push(RecalledMemory {
                    id: record.id.clone(),
                    kind: record.kind,
                    label: record.label,
                    content: record.content().clone(),
                    entities: record.entities.clone(),
                    provenance: record.provenance.clone(),
                    valid_from: record.valid_from,
                });
            } else {
                redacted.push(RedactedHit {
                    id: record.id.clone(),
                    kind: record.kind,
                    label: record.label,
                    entities: record.entities.clone(),
                });
            }
        }

        audit(
            "memory:read",
            cap.subject(),
            space,
            &format!(
                "ceiling={} hits={} redacted={}",
                ceiling.name(),
                hits.len(),
                redacted.len()
            ),
        );
        Ok(Recall::new(hits, redacted))
    }

    /// Escalate one redacted hit to its content. Requires `CanReadSensitive`,
    /// which clears records up to `Sensitive`; `Secret` records remain sealed
    /// (they need a stronger authority than M1 models).
    pub fn reveal(
        &self,
        space: &MemorySpace,
        cap: &Capability<CanReadSensitive, MemorySpace>,
        id: &MemoryId,
    ) -> Result<MemoryContent, MemoryError> {
        Self::authorize(space, cap)?;
        let record = self.fetch_in_space(space, id)?;
        if record.label > Label::Sensitive {
            return Err(MemoryError::AboveCeiling {
                id: id.to_string(),
                label: record.label.name(),
                ceiling: Label::Sensitive.name(),
            });
        }
        audit("memory:reveal", cap.subject(), space, &format!("id={id}"));
        Ok(record.content().clone())
    }

    /// Consolidate: supersede records with summaries, or invalidate them.
    /// A replacement's label is raised to the join of everything it
    /// supersedes — the SecLib guarantee that a summary is at least as
    /// sensitive as its sources.
    pub fn consolidate(
        &self,
        space: &MemorySpace,
        cap: &Capability<CanWrite, MemorySpace>,
        plan: ConsolidationPlan,
    ) -> Result<ConsolidationReport, MemoryError> {
        Self::authorize(space, cap)?;
        let now = Utc::now();
        let mut report = ConsolidationReport::default();

        for step in plan.steps {
            match step {
                ConsolidationStep::Invalidate { ids } => {
                    for id in ids {
                        self.fetch_in_space(space, &id)?;
                        self.store.invalidate(&id, now)?;
                        report.invalidated.push(id);
                    }
                }
                ConsolidationStep::Supersede {
                    superseded,
                    mut replacement,
                } => {
                    let mut join = Label::Public;
                    for id in &superseded {
                        let record = self.fetch_in_space(space, id)?;
                        join = join.join(record.label);
                    }
                    // Raise the replacement to at least the join.
                    replacement.label = Some(replacement.label.map_or(join, |l| l.max(join)));
                    for id in &superseded {
                        self.store.invalidate(id, now)?;
                        report.invalidated.push(id.clone());
                    }
                    let created = self.remember(space, cap, replacement)?;
                    report.created.push(created);
                }
            }
        }

        audit(
            "memory:consolidate",
            cap.subject(),
            space,
            &format!(
                "invalidated={} created={}",
                report.invalidated.len(),
                report.created.len()
            ),
        );
        Ok(report)
    }

    /// Forget: destroy records irrevocably (tombstoned + audited). Requires
    /// `CanDelete`.
    pub fn forget(
        &self,
        space: &MemorySpace,
        cap: &Capability<CanDelete, MemorySpace>,
        selector: ForgetSelector,
    ) -> Result<Tombstone, MemoryError> {
        Self::authorize(space, cap)?;
        let ids = match selector {
            ForgetSelector::Ids(ids) => ids,
            ForgetSelector::Matching(query) => {
                let mut store_query = query.to_store_query(space.resource_id(), Vec::new());
                // Forgetting reaches everything in scope, incl. invalidated.
                store_query.include_invalidated = true;
                store_query.include_quarantined = true;
                self.store
                    .query(&store_query)?
                    .into_iter()
                    .map(|r| r.id)
                    .collect()
            }
        };

        let mut forgotten = Vec::new();
        for id in ids {
            // Only forget records actually in this space.
            if self.fetch_in_space(space, &id).is_ok() && self.store.tombstone(&id)? {
                forgotten.push(id);
            }
        }
        let at = Utc::now();
        audit(
            "memory:forget",
            cap.subject(),
            space,
            &format!("forgotten={}", forgotten.len()),
        );
        Ok(Tombstone { forgotten, at })
    }

    /// Fetch a record and confirm it belongs to `space`.
    fn fetch_in_space(
        &self,
        space: &MemorySpace,
        id: &MemoryId,
    ) -> Result<StoredRecord, MemoryError> {
        match self.store.get(id)? {
            Some(record) if record.space_id == space.resource_id() => Ok(record),
            _ => Err(MemoryError::NotFound(id.to_string())),
        }
    }
}

/// Emit one structured audit event for a memory operation.
fn audit(action: &str, subject: &SubjectId, space: &MemorySpace, detail: &str) {
    tracing::info!(
        target: "typesec_memory::audit",
        action,
        subject = %subject,
        space = %space.resource_id(),
        detail,
        "memory operation"
    );
}

#[cfg(test)]
mod tests;
