//! # typesec-memory — Marciana
//!
//! Capability-secured, information-flow-typed memory for AI agents. Memory in
//! the mold of mem0 / Zep / cognee, with the property none of them have:
//! **safe, granular access control built from typesec's primitives.**
//!
//! - A [`MemorySpace`] is a [`Resource`](typesec_core::Resource)
//!   (`memory/<owner>/<space>`), so existing policy engines govern memory with
//!   no new machinery.
//! - Access is a minted, expiring, revocable, attenuable
//!   [`Capability`](typesec_core::Capability): [`MemoryVault`] has no
//!   unauthenticated path to contents.
//! - Records carry a runtime [`Label`]; recall is *typed* —
//!   [`MemoryVault::recall`] takes a compile-time clearance and returns only
//!   records at or below it (the rest come back redacted). The clearance rides
//!   on [`Recall`] as a type parameter, so recalls of different sensitivity
//!   cannot be mixed.
//! - Provenance fixes each record's birth label and quarantines untrusted
//!   sources (raw model text) against memory poisoning.
//! - Contents live behind a single rehydration boundary
//!   (`StoredRecord::content` is crate-private); a compile-fail test proves
//!   external code cannot read it.
//!
//! ```
//! use std::sync::Arc;
//! use typesec_core::policy::{mint_capability_for_id, MintOptions, RequestContext};
//! use typesec_core::{CanRead, CanWrite, Capability};
//! use typesec_core::secure_value::Internal;
//! use typesec_memory::{InMemoryStore, MemoryVault, MemorySpace, MemoryDraft,
//!     MemoryContent, MemoryKind, Provenance, RecallQuery, Resource};
//!
//! let engine = typesec_rbac::RbacEngine::from_yaml(r#"
//! roles: [{name: keeper, permissions: [read, write], resources: ["memory/**"]}]
//! assignments: [{subject: "agent:me", roles: [keeper]}]
//! "#).unwrap();
//!
//! let space = MemorySpace::new("user:alice", "profile");
//! let write: Capability<CanWrite, _> =
//!     mint_capability_for_id(&engine, "agent:me", space.resource_id(), &MintOptions::default()).unwrap();
//! let read: Capability<CanRead, _> =
//!     mint_capability_for_id(&engine, "agent:me", space.resource_id(), &MintOptions::default()).unwrap();
//!
//! let vault = MemoryVault::new(InMemoryStore::new());
//! vault.remember(&space, &write,
//!     MemoryDraft::new(MemoryKind::Profile, MemoryContent::text("prefers dark mode"), Provenance::Operator)).unwrap();
//!
//! let recall = vault.recall::<Internal>(&space, &read, RecallQuery::all(), &RequestContext::default()).unwrap();
//! assert_eq!(recall.hits.len(), 1);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

#[cfg(feature = "agent")]
pub mod agent;
#[cfg(feature = "conformance")]
pub mod conformance;
pub mod error;
pub mod extract;
pub mod index;
pub mod label;
#[cfg(feature = "receipts")]
mod receipt;
pub mod record;
pub mod space;
pub mod store;
pub mod vault;

pub use error::MemoryError;
pub use extract::{Episode, ExtractError, Extractor, MemorySummary, RuleExtractor};
pub use index::{IndexError, KeywordIndex, SemanticIndex};
pub use label::{Clearance, Label};
pub use record::{EntityRef, MemoryContent, MemoryDraft, Provenance, StoredRecord};
pub use space::{MemoryId, MemoryKind, MemorySpace};
pub use store::{InMemoryStore, MemoryStore, StoreError, StoreQuery};
pub use vault::{
    ConsolidationPlan, ConsolidationReport, ConsolidationStep, ForgetSelector, MemoryVault, Recall,
    RecallQuery, RecalledMemory, RedactedHit, Tombstone,
};

// Re-export the resource trait so downstream can name space.resource_id().
pub use typesec_core::Resource;
