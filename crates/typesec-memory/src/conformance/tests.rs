//! The reference stores must pass their own conformance suite — proving the
//! harness and the stores against each other.

use super::*;
use crate::store::InMemoryStore;

#[test]
fn in_memory_store_conforms() {
    run_store_conformance(&InMemoryStore::new(), false);
}

#[cfg(feature = "graph-memory")]
#[test]
fn grust_store_conforms_including_graph_cases() {
    run_store_conformance(&crate::store::GrustMemoryStore::new(), true);
}

#[test]
fn corpus_is_versioned_and_parses() {
    let corpus = parse_corpus();
    assert_eq!(corpus.schema_version, SCHEMA_VERSION);
    assert!(corpus.records.len() >= 7);
    assert!(!corpus.queries.is_empty());
    assert!(!corpus.neighborhoods.is_empty());
}
