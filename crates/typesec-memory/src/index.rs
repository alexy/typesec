//! `SemanticIndex` — similarity ranking beside the store, ids in, ids out.
//!
//! Semantic search is a **ranking upgrade, never an authorization path**:
//! an index returns record *ids*, and only the vault turns ids into content,
//! behind the same label gate as every other recall. The vault feeds the
//! index at write time and prunes it on forget.
//!
//! ## The embedding-privacy contract
//!
//! Vectors leak content. `index` therefore receives each record's [`Label`],
//! and implementations **must not send content labeled above
//! [`Label::Internal`] to a remote embedding service** — route `Sensitive`
//! and `Secret` content to a local embedder or decline to index it
//! (returning `Ok` after indexing nothing is acceptable; the record stays
//! recallable by ordinary queries). This is a documented contract on the
//! trait: the conformance suite cannot observe network egress, so backends
//! own this promise.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, RwLock};

use crate::label::Label;
use crate::space::MemoryId;

/// Repair operation recorded after post-commit semantic-index maintenance
/// fails. It contains only an id; plaintext is rehydrated inside the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndexMutation {
    /// Re-read and index the current record.
    Upsert(MemoryId),
    /// Remove an id from the index.
    Remove(MemoryId),
}

/// Durable-outbox seam for semantic index repair.
pub trait IndexOutbox: Send + Sync {
    /// Append a failed mutation. Implementations should coalesce by record id
    /// where practical.
    fn push(&self, mutation: IndexMutation) -> Result<(), IndexError>;

    /// Return pending mutations in delivery order.
    fn pending(&self) -> Result<Vec<IndexMutation>, IndexError>;

    /// Acknowledge a successfully repaired mutation.
    fn ack(&self, mutation: &IndexMutation) -> Result<(), IndexError>;
}

/// Process-local reference outbox. Production services can inject a durable
/// transactional implementation through `MemoryVault::with_index_outbox`.
#[derive(Debug, Default)]
pub struct InMemoryIndexOutbox {
    pending: std::sync::Mutex<Vec<IndexMutation>>,
}

impl InMemoryIndexOutbox {
    /// Create an empty outbox.
    pub fn new() -> Self {
        Self::default()
    }
}

impl IndexOutbox for InMemoryIndexOutbox {
    fn push(&self, mutation: IndexMutation) -> Result<(), IndexError> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.retain(|queued| match (&mutation, queued) {
            (IndexMutation::Upsert(id), IndexMutation::Upsert(other))
            | (IndexMutation::Upsert(id), IndexMutation::Remove(other))
            | (IndexMutation::Remove(id), IndexMutation::Upsert(other))
            | (IndexMutation::Remove(id), IndexMutation::Remove(other)) => id != other,
        });
        pending.push(mutation);
        Ok(())
    }

    fn pending(&self) -> Result<Vec<IndexMutation>, IndexError> {
        Ok(self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone())
    }

    fn ack(&self, mutation: &IndexMutation) -> Result<(), IndexError> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(position) = pending.iter().position(|queued| queued == mutation) {
            pending.remove(position);
        }
        Ok(())
    }
}

/// An index operation failed.
#[derive(Debug, Error)]
pub enum IndexError {
    /// The backend failed (embedder down, ANN store unreachable, …).
    #[error("semantic index error: {0}")]
    Backend(String),
}

/// Similarity ranking over memory records. Ids in, ids out.
pub trait SemanticIndex: Send + Sync {
    /// Add (or re-add) a record's text under its label. See the module docs
    /// for the embedding-privacy contract the label carries.
    fn index(&self, id: &MemoryId, label: Label, text: &str) -> Result<(), IndexError>;

    /// Remove a record from the index (forget / reap). Removing an unknown
    /// id is not an error.
    fn remove(&self, id: &MemoryId) -> Result<(), IndexError>;

    /// Return up to `limit` record ids ranked most-similar-first. May return
    /// ids of records that no longer exist or are out of scope — the vault
    /// filters; the index only ranks.
    fn search(&self, query: &str, limit: usize) -> Result<Vec<MemoryId>, IndexError>;
}

/// A deterministic, dependency-free reference index: lowercase-token overlap
/// scoring. Local-only by construction, so every label may be indexed. Real
/// ANN/hybrid ranking lands in `querygraph-memory`; this proves the vault
/// wiring and gives tests a stable ranking.
#[derive(Default)]
pub struct KeywordIndex {
    entries: RwLock<KeywordEntries>,
}

#[derive(Default)]
struct KeywordEntries {
    documents: Vec<Option<KeywordDocument>>,
    document_keys: HashMap<Arc<MemoryId>, usize>,
    vacant_keys: Vec<usize>,
    postings: HashMap<String, HashSet<usize>>,
}

struct KeywordDocument {
    id: Arc<MemoryId>,
    tokens: BTreeSet<String>,
}

impl KeywordIndex {
    /// Create an empty index.
    pub fn new() -> Self {
        Self::default()
    }

    fn tokens(text: &str) -> BTreeSet<String> {
        text.split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(str::to_lowercase)
            .collect()
    }

    fn remove_posting(entries: &mut KeywordEntries, key: usize, token: &str) {
        let remove_posting = entries.postings.get_mut(token).is_some_and(|keys| {
            keys.remove(&key);
            keys.is_empty()
        });
        if remove_posting {
            entries.postings.remove(token);
        }
    }

    fn remove_postings(entries: &mut KeywordEntries, key: usize, tokens: BTreeSet<String>) {
        for token in tokens {
            Self::remove_posting(entries, key, &token);
        }
    }
}

impl SemanticIndex for KeywordIndex {
    fn index(&self, id: &MemoryId, _label: Label, text: &str) -> Result<(), IndexError> {
        let tokens = Self::tokens(text);
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(&key) = entries.document_keys.get(id) {
            let document = entries.documents[key]
                .as_mut()
                .expect("keyword index document key must be valid");
            if document.tokens == tokens {
                return Ok(());
            }
            let old_tokens = std::mem::take(&mut document.tokens);
            for token in old_tokens.difference(&tokens) {
                Self::remove_posting(&mut entries, key, token);
            }
            for token in tokens.difference(&old_tokens) {
                entries
                    .postings
                    .entry(token.clone())
                    .or_default()
                    .insert(key);
            }
            entries.documents[key]
                .as_mut()
                .expect("keyword index document key must be valid")
                .tokens = tokens;
            return Ok(());
        }

        let key = entries.vacant_keys.pop().unwrap_or(entries.documents.len());
        for token in &tokens {
            entries
                .postings
                .entry(token.clone())
                .or_default()
                .insert(key);
        }
        let id = Arc::new(id.clone());
        let document = KeywordDocument {
            id: Arc::clone(&id),
            tokens,
        };
        entries.document_keys.insert(id, key);
        if key == entries.documents.len() {
            entries.documents.push(Some(document));
        } else {
            entries.documents[key] = Some(document);
        }
        Ok(())
    }

    fn remove(&self, id: &MemoryId) -> Result<(), IndexError> {
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((_, key)) = entries.document_keys.remove_entry(id) else {
            return Ok(());
        };
        let document = entries.documents[key]
            .take()
            .expect("keyword index document key must be valid");
        Self::remove_postings(&mut entries, key, document.tokens);
        entries.vacant_keys.push(key);
        Ok(())
    }

    fn search(&self, query: &str, limit: usize) -> Result<Vec<MemoryId>, IndexError> {
        let needle = Self::tokens(query);
        if needle.is_empty() {
            return Ok(Vec::new());
        }
        let entries = self
            .entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let posting_visits = needle
            .iter()
            .filter_map(|token| entries.postings.get(token))
            .map(HashSet::len)
            .sum::<usize>();
        let mut scored = if posting_visits >= entries.document_keys.len() {
            entries
                .documents
                .iter()
                .flatten()
                .map(|document| {
                    (
                        needle.intersection(&document.tokens).count(),
                        document.id.as_ref(),
                    )
                })
                .filter(|(score, _)| *score > 0)
                .collect::<Vec<_>>()
        } else {
            let mut scores = HashMap::<usize, usize>::new();
            for token in &needle {
                if let Some(keys) = entries.postings.get(token) {
                    for &key in keys {
                        *scores.entry(key).or_default() += 1;
                    }
                }
            }
            scores
                .into_iter()
                .map(|(key, score)| {
                    let document = entries.documents[key]
                        .as_ref()
                        .expect("keyword index posting key must be valid");
                    (score, document.id.as_ref())
                })
                .collect::<Vec<_>>()
        };
        // Best score first; ties broken by id for determinism.
        let score_order =
            |a: &(usize, &MemoryId), b: &(usize, &MemoryId)| b.0.cmp(&a.0).then(a.1.cmp(b.1));
        if limit < scored.len() {
            scored.select_nth_unstable_by(limit, score_order);
            scored.truncate(limit);
        }
        scored.sort_unstable_by(score_order);
        Ok(scored.into_iter().map(|(_, id)| id.clone()).collect())
    }
}

#[cfg(test)]
mod tests;
