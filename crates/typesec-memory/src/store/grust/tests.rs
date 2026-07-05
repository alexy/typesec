use super::*;
use crate::record::{EntityRef, MemoryContent, Provenance, StoredRecord};
use crate::space::{MemoryId, MemoryKind};
use crate::store::StoreQuery;
use chrono::{TimeZone, Utc};

fn rec(id: &str, text: &str, entities: &[(&str, &str)]) -> StoredRecord {
    StoredRecord::assemble(
        MemoryId::from_string(id),
        "memory/user:alice/semantic".into(),
        MemoryKind::Semantic,
        crate::label::Label::Internal,
        false,
        entities
            .iter()
            .map(|(n, k)| EntityRef::new(*n, *k))
            .collect(),
        Provenance::Operator,
        Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        None,
        vec![],
        MemoryContent::text(text),
    )
}

#[test]
fn crud_and_query_match_the_in_memory_semantics() {
    let store = GrustMemoryStore::new();
    store
        .put(rec(
            "m1",
            "Alice works at ACME",
            &[("Alice", "person"), ("ACME", "org")],
        ))
        .unwrap();
    store.put(rec("m2", "unrelated", &[])).unwrap();

    assert_eq!(store.query(&StoreQuery::default()).unwrap().len(), 2);
    let by_entity = store
        .query(&StoreQuery {
            entity: Some("ACME".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(by_entity.len(), 1);
    assert_eq!(by_entity[0].id.as_str(), "m1");

    assert!(store.get(&MemoryId::from_string("m1")).unwrap().is_some());
    assert!(store.tombstone(&MemoryId::from_string("m1")).unwrap());
    assert!(store.get(&MemoryId::from_string("m1")).unwrap().is_none());
}

#[test]
fn neighborhood_walks_the_entity_graph_to_records() {
    let store = GrustMemoryStore::new();
    // Alice → ACME (one record); ACME → Venice (a relation); a record about Venice.
    store
        .put(rec(
            "m1",
            "Alice works at ACME",
            &[("Alice", "person"), ("ACME", "org")],
        ))
        .unwrap();
    store
        .put(rec(
            "m2",
            "ACME is based in Venice",
            &[("ACME", "org"), ("Venice", "place")],
        ))
        .unwrap();
    store
        .put(rec(
            "m3",
            "Venice hosts the Biennale",
            &[("Venice", "place")],
        ))
        .unwrap();
    store
        .put(rec("m4", "totally unrelated", &[("Zeta", "thing")]))
        .unwrap();
    // Relate the entities so BFS can traverse ACME→Venice.
    store
        .link("ACME", "based_in", "Venice", &MemoryId::from_string("m2"))
        .unwrap();

    // 0 hops from ACME: records mentioning ACME directly.
    let direct = store.neighborhood("ACME", 0).unwrap();
    assert!(direct.iter().any(|id| id.as_str() == "m1"));
    assert!(direct.iter().any(|id| id.as_str() == "m2"));
    assert!(
        !direct.iter().any(|id| id.as_str() == "m3"),
        "Venice not reached at 0 hops"
    );

    // 1 hop from ACME reaches Venice, pulling in its records too.
    let one_hop = store.neighborhood("ACME", 1).unwrap();
    assert!(
        one_hop.iter().any(|id| id.as_str() == "m3"),
        "Venice records reached at 1 hop"
    );
    assert!(
        !one_hop.iter().any(|id| id.as_str() == "m4"),
        "Zeta never reached"
    );
}

#[test]
fn tombstone_prunes_relations() {
    let store = GrustMemoryStore::new();
    store
        .put(rec("m2", "ACME in Venice", &[("ACME", "org")]))
        .unwrap();
    store
        .link("ACME", "based_in", "Venice", &MemoryId::from_string("m2"))
        .unwrap();
    store.tombstone(&MemoryId::from_string("m2")).unwrap();
    // With the record and its relation gone, ACME reaches nothing.
    assert!(store.neighborhood("Venice", 1).unwrap().is_empty());
}
