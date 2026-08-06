//! Conformance harness (`conformance` feature): "Marciana-compatible" as a
//! test, not a claim.
//!
//! A backend crate (e.g. `querygraph-memory`) runs its `MemoryStore` through
//! the embedded, versioned fixture corpus:
//!
//! ```rust,ignore
//! #[test]
//! fn my_backend_conforms() {
//!     typesec_memory::conformance::run_store_conformance(&MyStore::new(), true);
//! }
//! ```
//!
//! The harness checks every `StoreQuery` dimension (space scoping, label
//! ceiling, bi-temporal point-in-time, quarantine, purpose overlap, entity
//! and text filters), invalidate/tombstone behavior, and — for graph-capable
//! stores — neighborhood reachability. Expectations are compared as **sets**:
//! ordering is a store's own affair (the vault ranks). A store that *widens*
//! any filter fails loudly with the fixture case name.
//!
//! Conformance verifies backend behavior, not record authenticity,
//! confidentiality, authorization, or database integrity. The tested store
//! and its raw persistence remain trusted TypeSec infrastructure.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::label::Label;
use crate::record::StoredRecord;
use crate::space::{MemoryId, MemoryKind};
use crate::store::{MemoryStore, StoreQuery};

/// The fixture schema version this crate ships. Backends can assert on it.
pub const SCHEMA_VERSION: u32 = 1;

const CORPUS: &str = include_str!("conformance/corpus.json");

#[derive(Deserialize)]
struct Corpus {
    schema_version: u32,
    records: Vec<StoredRecord>,
    queries: Vec<QueryCase>,
    links: Vec<LinkCase>,
    neighborhoods: Vec<NeighborhoodCase>,
}

#[derive(Deserialize)]
struct QueryCase {
    name: String,
    space_id: Option<String>,
    #[serde(default)]
    kind: Option<MemoryKind>,
    #[serde(default)]
    max_label: Option<Label>,
    #[serde(default)]
    valid_at: Option<DateTime<Utc>>,
    #[serde(default)]
    entity: Option<String>,
    #[serde(default)]
    text_contains: Option<String>,
    #[serde(default)]
    any_purpose: Vec<String>,
    #[serde(default)]
    include_quarantined: bool,
    expect: Vec<String>,
}

#[derive(Deserialize)]
struct LinkCase {
    from: String,
    rel: String,
    to: String,
    record: String,
}

#[derive(Deserialize)]
struct NeighborhoodCase {
    name: String,
    entity: String,
    hops: u8,
    expect: Vec<String>,
}

fn parse_corpus() -> Corpus {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("embedded corpus parses");
    assert_eq!(
        corpus.schema_version, SCHEMA_VERSION,
        "corpus schema version drifted from the constant"
    );
    corpus
}

fn id_set(ids: impl IntoIterator<Item = MemoryId>) -> BTreeSet<String> {
    ids.into_iter().map(|id| id.as_str().to_string()).collect()
}

fn expect_set(expect: &[String]) -> BTreeSet<String> {
    expect.iter().cloned().collect()
}

/// Run `store` through the full conformance corpus.
///
/// Set `graph` when the store implements `link`/`neighborhood`; the graph
/// cases are then mandatory instead of skipped. Panics with the failing
/// fixture case name on any deviation. Passing this harness is not a security
/// attestation for untrusted storage.
pub fn run_store_conformance(store: &dyn MemoryStore, graph: bool) {
    let corpus = parse_corpus();

    for record in &corpus.records {
        store
            .put(record.clone())
            .expect("conformance: put must succeed");
    }
    if graph {
        for link in &corpus.links {
            store
                .link(
                    &link.from,
                    &link.rel,
                    &link.to,
                    &MemoryId::from_string(&link.record),
                )
                .expect("conformance: link must succeed on a graph store");
        }
    }

    // Query semantics, dimension by dimension.
    for case in &corpus.queries {
        let query = StoreQuery {
            space_id: case.space_id.clone(),
            kind: case.kind,
            max_label: case.max_label,
            valid_at: case.valid_at,
            entity: case.entity.clone(),
            text_contains: case.text_contains.clone(),
            any_purpose: case.any_purpose.clone(),
            include_quarantined: case.include_quarantined,
            include_invalidated: false,
            limit: None,
        };
        let got = id_set(
            store
                .query(&query)
                .expect("conformance: query must succeed")
                .into_iter()
                .map(|r| r.id),
        );
        assert_eq!(
            got,
            expect_set(&case.expect),
            "conformance query case '{}' deviated",
            case.name
        );
    }

    // Graph reachability.
    if graph {
        for case in &corpus.neighborhoods {
            let got = id_set(
                store
                    .neighborhood(&case.entity, case.hops)
                    .expect("conformance: neighborhood must succeed on a graph store"),
            );
            assert_eq!(
                got,
                expect_set(&case.expect),
                "conformance neighborhood case '{}' deviated",
                case.name
            );
        }
    }

    // Behavioral checks: invalidate hides without destroying; tombstone
    // destroys and reports existence.
    let venice = MemoryId::from_string("fx-venice");
    store
        .invalidate(&venice, Utc::now())
        .expect("conformance: invalidate must succeed");
    let after = id_set(
        store
            .query(&StoreQuery::in_space("memory/user:alice/profile"))
            .expect("conformance: query after invalidate")
            .into_iter()
            .map(|r| r.id),
    );
    assert!(
        !after.contains("fx-venice"),
        "conformance: invalidated record must be hidden by default"
    );
    assert!(
        store
            .get(&venice)
            .expect("conformance: get after invalidate")
            .is_some(),
        "conformance: invalidate must not destroy the record"
    );

    assert!(
        store.tombstone(&venice).expect("conformance: tombstone"),
        "conformance: tombstone must report the record existed"
    );
    assert!(
        store
            .get(&venice)
            .expect("conformance: get after tombstone")
            .is_none(),
        "conformance: tombstoned record must be gone"
    );
    assert!(
        !store
            .tombstone(&MemoryId::from_string("fx-never-existed"))
            .expect("conformance: tombstone of unknown id"),
        "conformance: tombstoning an unknown id must report false"
    );
}

#[cfg(test)]
mod tests;
