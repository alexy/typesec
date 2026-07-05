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

use thiserror::Error;

use crate::label::Label;
use crate::space::MemoryId;

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
    entries:
        std::sync::RwLock<std::collections::HashMap<MemoryId, std::collections::BTreeSet<String>>>,
}

impl KeywordIndex {
    /// Create an empty index.
    pub fn new() -> Self {
        Self::default()
    }

    fn tokens(text: &str) -> std::collections::BTreeSet<String> {
        text.split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(str::to_lowercase)
            .collect()
    }
}

impl SemanticIndex for KeywordIndex {
    fn index(&self, id: &MemoryId, _label: Label, text: &str) -> Result<(), IndexError> {
        self.entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.clone(), Self::tokens(text));
        Ok(())
    }

    fn remove(&self, id: &MemoryId) -> Result<(), IndexError> {
        self.entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id);
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
        let mut scored: Vec<(usize, MemoryId)> = entries
            .iter()
            .map(|(id, tokens)| (needle.intersection(tokens).count(), id.clone()))
            .filter(|(score, _)| *score > 0)
            .collect();
        // Best score first; ties broken by id for determinism.
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        Ok(scored.into_iter().take(limit).map(|(_, id)| id).collect())
    }
}

#[cfg(test)]
mod tests;
