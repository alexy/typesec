//! `InMemoryStore` — the always-available reference store.
//!
//! A poisoned-lock recovery policy (recover the inner guard rather than
//! propagate the panic) matches core's audit-sink approach: the map is not
//! invariant-bearing, so recovering it keeps one panicking writer from
//! wedging all memory.

use std::collections::HashMap;
use std::sync::{PoisonError, RwLock};

use chrono::{DateTime, Utc};

use super::{MemoryStore, StoreError, StoreQuery};
use crate::record::StoredRecord;
use crate::space::MemoryId;

/// An in-process store backed by a `HashMap`. Good for tests, demos, WASM,
/// and single-node deployments.
#[derive(Default)]
pub struct InMemoryStore {
    records: RwLock<HashMap<MemoryId, StoredRecord>>,
}

impl InMemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of records currently held (including invalidated/quarantined).
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Whether the store holds no records.
    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<MemoryId, StoredRecord>> {
        self.records.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<MemoryId, StoredRecord>> {
        self.records.write().unwrap_or_else(PoisonError::into_inner)
    }
}

impl MemoryStore for InMemoryStore {
    fn put(&self, record: StoredRecord) -> Result<(), StoreError> {
        self.write().insert(record.id.clone(), record);
        Ok(())
    }

    fn get(&self, id: &MemoryId) -> Result<Option<StoredRecord>, StoreError> {
        Ok(self.read().get(id).cloned())
    }

    fn query(&self, query: &StoreQuery) -> Result<Vec<StoredRecord>, StoreError> {
        let guard = self.read();
        let mut matches: Vec<&StoredRecord> = guard
            .values()
            .filter(|record| query.matches(record))
            .collect();
        // Deterministic order for tests/ranking: newest observation first.
        matches.sort_by(|a, b| b.observed_at.cmp(&a.observed_at).then(b.id.cmp(&a.id)));
        if let Some(limit) = query.limit {
            matches.truncate(limit);
        }
        Ok(matches.into_iter().cloned().collect())
    }

    fn invalidate(&self, id: &MemoryId, at: DateTime<Utc>) -> Result<(), StoreError> {
        if let Some(record) = self.write().get_mut(id) {
            record.invalid_at = Some(at);
            Ok(())
        } else {
            Err(StoreError::Backend(format!("no record {id}")))
        }
    }

    fn tombstone(&self, id: &MemoryId) -> Result<bool, StoreError> {
        Ok(self.write().remove(id).is_some())
    }
}
