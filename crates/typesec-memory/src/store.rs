//! The storage trait and its query model.
//!
//! A [`MemoryStore`] is a trusted confidentiality and integrity persistence
//! seam. It is deliberately *not* an authorization boundary: production
//! callers authorize through the vault, while the store must faithfully
//! persist and return only vault-originated or otherwise authenticated record
//! bytes. Direct trait calls bypass vault policy and governed-ingestion checks.
//! The database, backend adapter, and any raw backend handle therefore belong
//! to the trusted computing base. A TypeSec-owned authenticated envelope can
//! remove storage from the integrity TCB; removing it from the confidentiality
//! TCB additionally requires encryption and key isolation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::label::Label;
use crate::record::StoredRecord;
use crate::space::{MemoryId, MemoryKind};

pub mod memory;
pub use memory::InMemoryStore;

#[cfg(feature = "graph-memory")]
pub mod grust;
#[cfg(feature = "graph-memory")]
pub use grust::GrustMemoryStore;

/// A store operation failed.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The backend does not support this operation (e.g. graph links on a
    /// flat store).
    #[error("store operation not supported by this backend")]
    Unsupported,
    /// A backend-specific failure.
    #[error("store backend error: {0}")]
    Backend(String),
}

/// A filter over stored records. All set fields must match (AND); an unset
/// field matches everything.
#[derive(Debug, Clone, Default)]
pub struct StoreQuery {
    /// Restrict to one space's resource id.
    pub space_id: Option<String>,
    /// Restrict to one memory kind.
    pub kind: Option<MemoryKind>,
    /// Return only records at or below this label. The vault always sets this
    /// to the recall ceiling — defense in depth beside the vault's own check.
    pub max_label: Option<Label>,
    /// Return only records valid at this instant (bi-temporal point-in-time).
    pub valid_at: Option<DateTime<Utc>>,
    /// Require this entity to be referenced.
    pub entity: Option<String>,
    /// Case-insensitive substring match against record text.
    pub text_contains: Option<String>,
    /// Require one of these purposes (empty = any). ODRL purpose-bound recall.
    pub any_purpose: Vec<String>,
    /// Include quarantined records (default false).
    pub include_quarantined: bool,
    /// Include invalidated records (default false; overridden by `valid_at`).
    pub include_invalidated: bool,
    /// Cap on returned records (None = unlimited).
    pub limit: Option<usize>,
}

impl StoreQuery {
    /// A query scoped to one space.
    pub fn in_space(space_id: impl Into<String>) -> Self {
        Self {
            space_id: Some(space_id.into()),
            ..Self::default()
        }
    }

    /// Whether `record` satisfies this query. Shared by every store so filter
    /// semantics can't drift between backends.
    pub fn matches(&self, record: &StoredRecord) -> bool {
        if let Some(space) = &self.space_id
            && &record.space_id != space
        {
            return false;
        }
        if let Some(kind) = self.kind
            && record.kind != kind
        {
            return false;
        }
        if let Some(max) = self.max_label
            && record.label > max
        {
            return false;
        }
        if record.quarantined && !self.include_quarantined {
            return false;
        }
        match self.valid_at {
            Some(at) => {
                if !record.is_valid_at(at) {
                    return false;
                }
            }
            None => {
                if record.invalid_at.is_some() && !self.include_invalidated {
                    return false;
                }
            }
        }
        if let Some(entity) = &self.entity
            && !record.entities.iter().any(|e| &e.name == entity)
        {
            return false;
        }
        if let Some(needle) = &self.text_contains
            && !record.content_text_lower().contains(&needle.to_lowercase())
        {
            return false;
        }
        if !self.any_purpose.is_empty() {
            // A record with no purpose tags serves any purpose; a tagged
            // record must overlap the requested set.
            let ok = record.purposes.is_empty()
                || record.purposes.iter().any(|p| self.any_purpose.contains(p));
            if !ok {
                return false;
            }
        }
        true
    }
}

/// One write within an atomic [`apply_batch`](MemoryStore::apply_batch).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StoreBatchOp {
    /// Insert or replace a record.
    Put(Box<StoredRecord>),
    /// Invalidate a record at `at` (bi-temporal supersede).
    Invalidate {
        /// Record to invalidate.
        id: MemoryId,
        /// Invalidation instant.
        at: DateTime<Utc>,
    },
}

/// Trusted persistence for memory records.
///
/// This trait is public so backend implementations can integrate with TypeSec,
/// not as an application-level write API. Direct reads and writes bypass vault
/// authorization, and serde field privacy does not authenticate a
/// [`StoredRecord`]. Production application code must use [`crate::MemoryVault`]
/// operations. Graph capabilities are optional and default to
/// [`StoreError::Unsupported`].
pub trait MemoryStore: Send + Sync {
    /// Insert or replace a trusted record by id, bypassing vault gates.
    fn put(&self, record: StoredRecord) -> Result<(), StoreError>;

    /// Fetch a protected record by id, bypassing vault disclosure gates.
    fn get(&self, id: &MemoryId) -> Result<Option<StoredRecord>, StoreError>;

    /// Return records matching `query` (unordered; the vault ranks/limits).
    fn query(&self, query: &StoreQuery) -> Result<Vec<StoredRecord>, StoreError>;

    /// Mark a record invalidated at `at` (bi-temporal supersede).
    fn invalidate(&self, id: &MemoryId, at: DateTime<Utc>) -> Result<(), StoreError>;

    /// Hard-delete a record's content, leaving a tombstone the store may keep
    /// for audit. Returns whether a record existed.
    fn tombstone(&self, id: &MemoryId) -> Result<bool, StoreError>;

    /// Apply a batch of writes.
    ///
    /// The default is **sequential and non-atomic** — a later failure leaves
    /// earlier ops applied. Backends with transactions should override this to
    /// apply the whole batch in one unit; the vault routes consolidation
    /// (supersede-and-relink) through here so it is atomic where supported.
    fn apply_batch(&self, ops: Vec<StoreBatchOp>) -> Result<(), StoreError> {
        for op in ops {
            match op {
                StoreBatchOp::Put(record) => self.put(*record)?,
                StoreBatchOp::Invalidate { id, at } => self.invalidate(&id, at)?,
            }
        }
        Ok(())
    }

    /// Link two entities in the knowledge graph (graph stores only).
    fn link(
        &self,
        _from: &str,
        _rel: &str,
        _to: &str,
        _record: &MemoryId,
    ) -> Result<(), StoreError> {
        Err(StoreError::Unsupported)
    }

    /// Return record ids in an entity's graph neighborhood (graph stores only).
    fn neighborhood(&self, _entity: &str, _hops: u8) -> Result<Vec<MemoryId>, StoreError> {
        Err(StoreError::Unsupported)
    }
}

#[cfg(test)]
mod tests;
