//! Replay-claim authority for DID and TypeDID gateways.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

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
    claims: Mutex<ReplayClaims>,
}

#[derive(Debug, Default)]
struct ReplayClaims {
    seen: HashMap<Arc<str>, u64>,
    expirations: BinaryHeap<Reverse<(u64, Arc<str>)>>,
}

impl ReplayClaims {
    fn remove_expired(&mut self, now: u64) {
        while self
            .expirations
            .peek()
            .is_some_and(|Reverse((expiry, _))| *expiry < now)
        {
            let Reverse((expiry, key)) = self
                .expirations
                .pop()
                .expect("peeked replay expiration must remain present");
            if self.seen.get(key.as_ref()) == Some(&expiry) {
                self.seen.remove(key.as_ref());
            }
        }
    }
}

impl InMemoryReplayStore {
    /// Create an empty replay store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReplayStore for InMemoryReplayStore {
    fn claim(&self, key: &str, expires_at: u64, now: u64) -> Result<bool, String> {
        let mut claims = self.claims.lock().unwrap_or_else(PoisonError::into_inner);
        claims.remove_expired(now);
        if claims.seen.contains_key(key) {
            return Ok(false);
        }
        let key: Arc<str> = Arc::from(key);
        claims.seen.insert(Arc::clone(&key), expires_at);
        claims.expirations.push(Reverse((expires_at, key)));
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_claims_are_rejected_through_the_expiry_second() {
        let store = InMemoryReplayStore::new();
        assert!(store.claim("envelope", 20, 10).unwrap());
        assert!(!store.claim("envelope", 20, 19).unwrap());
        assert!(!store.claim("envelope", 20, 20).unwrap());
    }

    #[test]
    fn expired_claims_can_be_reclaimed() {
        let store = InMemoryReplayStore::new();
        assert!(store.claim("envelope", 20, 10).unwrap());
        assert!(store.claim("envelope", 40, 21).unwrap());
        assert!(!store.claim("envelope", 40, 21).unwrap());
    }

    #[test]
    fn expiration_pruning_preserves_later_active_claims() {
        let store = InMemoryReplayStore::new();
        assert!(store.claim("early", 20, 10).unwrap());
        assert!(store.claim("late", 40, 10).unwrap());
        assert!(store.claim("new", 50, 21).unwrap());
        assert!(!store.claim("late", 40, 21).unwrap());
        assert!(store.claim("early", 50, 21).unwrap());
    }
}
