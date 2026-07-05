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

use std::sync::Arc;

use chrono::{DateTime, Utc};
use typesec_core::policy::{PolicyEngine, PolicyResult, RequestContext, SubjectId};
use typesec_core::{
    CanDelete, CanRead, CanReadSensitive, CanWrite, Capability, Permission, Resource,
};

use crate::error::MemoryError;
use crate::label::{Clearance, Label};
use crate::record::{MemoryContent, MemoryDraft, StoredRecord};
use crate::space::{MemoryId, MemorySpace};
use crate::store::MemoryStore;

/// A capability-secured memory store.
///
/// An optional policy engine ([`with_policy`][Self::with_policy]) re-checks
/// each operation against the request context *at use time* — so ODRL
/// purpose/time constraints bind per query, not merely at capability-mint
/// time. The capability is always the primary gate; the engine is defense in
/// depth that can additionally enforce contextual rules.
pub struct MemoryVault<S: MemoryStore> {
    store: S,
    engine: Option<Arc<dyn PolicyEngine>>,
}

impl<S: MemoryStore> MemoryVault<S> {
    /// Wrap a store with capability-only enforcement.
    pub fn new(store: S) -> Self {
        Self {
            store,
            engine: None,
        }
    }

    /// Additionally re-evaluate `engine` on every operation with the request
    /// context — binds contextual ODRL constraints (purpose, time window) at
    /// use time.
    #[must_use]
    pub fn with_policy(mut self, engine: Arc<dyn PolicyEngine>) -> Self {
        self.engine = Some(engine);
        self
    }

    /// Borrow the underlying store (read-only; bypasses no gates because the
    /// store cannot read record content — that is the vault's private path).
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Verify a capability covers `space`, is usable, and — if a policy engine
    /// is configured — that the engine still allows this `action` under `ctx`.
    fn authorize<P>(
        &self,
        space: &MemorySpace,
        cap: &Capability<P, MemorySpace>,
        ctx: &RequestContext,
    ) -> Result<(), MemoryError>
    where
        P: Permission,
    {
        if cap.resource_id().as_str() != space.resource_id() {
            return Err(MemoryError::SpaceMismatch {
                capability_space: cap.resource_id().to_string(),
                target_space: space.resource_id().to_string(),
            });
        }
        cap.ensure_active()?;
        if let Some(engine) = &self.engine {
            let resource = typesec_core::ResourceId::from(space.resource_id());
            match engine.check_with_context(cap.subject(), P::name(), &resource, ctx) {
                PolicyResult::Allow => {}
                other => {
                    return Err(MemoryError::PolicyDenied {
                        action: P::name(),
                        detail: other.to_string(),
                    });
                }
            }
        }
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
        self.authorize(space, cap, &RequestContext::default())?;

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
    /// The `RequestContext` purpose binds ODRL-style purpose filtering. The
    /// clearance rides on [`Recall`] as a type parameter, so recalls of
    /// different sensitivity cannot be mixed.
    pub fn recall<L: Clearance>(
        &self,
        space: &MemorySpace,
        cap: &Capability<CanRead, MemorySpace>,
        query: RecallQuery,
        ctx: &RequestContext,
    ) -> Result<Recall<L>, MemoryError> {
        let (hits, redacted) = self.recall_at(space, cap, query, ctx, L::ceiling())?;
        Ok(Recall::new(hits, redacted))
    }

    /// Recall with a *runtime* clearance ceiling — the untyped path used at
    /// the JSON tool-call boundary (a clearance string can't be a type
    /// parameter). Prefer [`recall`][Self::recall] in Rust code, which keeps
    /// the clearance in the type.
    pub fn recall_at(
        &self,
        space: &MemorySpace,
        cap: &Capability<CanRead, MemorySpace>,
        query: RecallQuery,
        ctx: &RequestContext,
        ceiling: Label,
    ) -> Result<(Vec<RecalledMemory>, Vec<RedactedHit>), MemoryError> {
        self.authorize(space, cap, ctx)?;

        let purposes = ctx.purpose.iter().cloned().collect();
        let store_query = query.to_store_query(space.resource_id(), purposes);
        let records = self.store.query(&store_query)?;

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
        Ok((hits, redacted))
    }

    /// Graph recall: find records in the knowledge-graph neighborhood of
    /// `entity` (within `hops`), then apply the clearance ceiling exactly as
    /// [`recall_at`][Self::recall_at] — the graph returns ids, the vault
    /// returns content, so the store is never an authorization bypass.
    /// Requires a store that supports `neighborhood` (the Grust backend).
    pub fn recall_neighborhood(
        &self,
        space: &MemorySpace,
        cap: &Capability<CanRead, MemorySpace>,
        entity: &str,
        hops: u8,
        ceiling: Label,
    ) -> Result<(Vec<RecalledMemory>, Vec<RedactedHit>), MemoryError> {
        self.authorize(space, cap, &RequestContext::default())?;
        let ids = self.store.neighborhood(entity, hops)?;

        let mut hits = Vec::new();
        let mut redacted = Vec::new();
        for id in ids {
            let Ok(record) = self.fetch_in_space(space, &id) else {
                continue; // id from another space or already gone
            };
            if record.invalid_at.is_some() || record.quarantined {
                continue;
            }
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
            "memory:read_graph",
            cap.subject(),
            space,
            &format!(
                "entity={entity} hops={hops} hits={} redacted={}",
                hits.len(),
                redacted.len()
            ),
        );
        Ok((hits, redacted))
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
        self.authorize(space, cap, &RequestContext::default())?;
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
        self.authorize(space, cap, &RequestContext::default())?;
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
        self.authorize(space, cap, &RequestContext::default())?;
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

    /// Retention reaper: forget every record in `space` whose retention
    /// deadline has passed at `now`. Requires `CanDelete`. Run on a schedule
    /// to enforce ODRL/GDPR retention windows; the removals are tombstoned
    /// and audited exactly like [`forget`][Self::forget].
    pub fn reap_expired(
        &self,
        space: &MemorySpace,
        cap: &Capability<CanDelete, MemorySpace>,
        now: DateTime<Utc>,
    ) -> Result<Tombstone, MemoryError> {
        self.authorize(space, cap, &RequestContext::default())?;
        let mut store_query = crate::store::StoreQuery::in_space(space.resource_id());
        store_query.include_invalidated = true;
        store_query.include_quarantined = true;
        let expired: Vec<MemoryId> = self
            .store
            .query(&store_query)?
            .into_iter()
            .filter(|r| r.is_expired_at(now))
            .map(|r| r.id)
            .collect();

        let mut forgotten = Vec::new();
        for id in expired {
            if self.store.tombstone(&id)? {
                forgotten.push(id);
            }
        }
        audit(
            "memory:reap",
            cap.subject(),
            space,
            &format!("reaped={}", forgotten.len()),
        );
        Ok(Tombstone { forgotten, at: now })
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
