//! Memory spaces (the unit of access control) and record identifiers.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use typesec_core::{Resource, SubjectId};

/// A named region of memory owned by a subject — the resource that
/// capabilities are minted against.
///
/// The resource id is `memory/<owner>/<space>`, so existing policy engines
/// govern memory with no new machinery: RBAC globs
/// (`memory/user:alice/**`), the graph engine for org-shaped sharing, ODRL
/// for purpose and retention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemorySpace {
    owner: SubjectId,
    space: String,
    resource_id: String,
}

impl MemorySpace {
    /// Create a space for `owner` named `space` (e.g. `"profile"`,
    /// `"episodic"`).
    pub fn new(owner: impl Into<SubjectId>, space: impl Into<String>) -> Self {
        let owner = owner.into();
        let space = space.into();
        let resource_id = format!("memory/{owner}/{space}");
        Self {
            owner,
            space,
            resource_id,
        }
    }

    /// The owning subject.
    pub fn owner(&self) -> &SubjectId {
        &self.owner
    }

    /// The space name within the owner.
    pub fn space(&self) -> &str {
        &self.space
    }

    /// The resource id for one record within this space:
    /// `memory/<owner>/<space>/<record-id>`. Per-record capabilities and
    /// per-record `SecureValue` binding use this.
    pub fn record_resource_id(&self, id: &MemoryId) -> String {
        format!("{}/{}", self.resource_id, id.as_str())
    }
}

impl Resource for MemorySpace {
    fn resource_id(&self) -> &str {
        &self.resource_id
    }

    fn resource_type() -> &'static str {
        "MemorySpace"
    }
}

/// A globally-unique record id (`mem-<n>`), monotonic within a process.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MemoryId(String);

impl MemoryId {
    /// Mint a fresh id.
    pub fn next() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(format!("mem-{}", COUNTER.fetch_add(1, Ordering::Relaxed)))
    }

    /// Wrap an externally-supplied id (e.g. loaded from a store).
    pub fn from_string(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The id string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MemoryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The kind of a memory, mirroring the human memory taxonomy the field uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryKind {
    /// A specific event or conversation turn.
    Episodic,
    /// A durable fact or entity relationship.
    Semantic,
    /// A learned procedure or skill.
    Procedural,
    /// A stable attribute of the space's owner.
    Profile,
}

#[cfg(test)]
mod tests;
