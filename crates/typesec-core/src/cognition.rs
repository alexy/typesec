//! Shared wire semantics for governed cognition decisions.

use serde::{Deserialize, Serialize};

/// Authoritative memory effect of one fully evaluated cognition decision.
///
/// This is distinct from delivery status: a newly committed or recovered
/// decision can describe either a mutation or an explicit no-change result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitionEffect {
    /// The decision changes one or more memory records.
    Mutated,
    /// The decision was durably committed without changing memory records.
    NoChange,
}

#[cfg(test)]
mod tests;
