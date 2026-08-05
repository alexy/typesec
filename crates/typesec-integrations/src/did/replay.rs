//! Replay-claim authority for DID and TypeDID gateways.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// Atomically records authenticated envelope identities until they expire.
///
/// Production replicas should share a durable implementation. The built-in
/// [`InMemoryReplayStore`] preserves the previous single-process behavior for
/// local use and tests.
pub trait ReplayStore: Send + Sync {
    /// Claim `key` until `expires_at`. Returns `true` only for the first active
    /// claim. Implementations must perform the check-and-insert atomically and
    /// fail rather than accept when their authority is unavailable.
    fn claim(&self, key: &str, expires_at: u64, now: u64) -> Result<bool, String>;
}

/// Process-local replay authority used by default.
#[derive(Debug, Default)]
pub struct InMemoryReplayStore {
    seen: Mutex<HashMap<String, u64>>,
}

impl InMemoryReplayStore {
    /// Create an empty replay store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReplayStore for InMemoryReplayStore {
    fn claim(&self, key: &str, expires_at: u64, now: u64) -> Result<bool, String> {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.retain(|_, expiry| *expiry >= now);
        if seen.contains_key(key) {
            return Ok(false);
        }
        seen.insert(key.to_owned(), expires_at);
        Ok(true)
    }
}
