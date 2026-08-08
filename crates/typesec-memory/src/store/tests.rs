use super::*;
use crate::record::{MemoryContent, Provenance, StoredRecord};
use crate::space::{MemoryId, MemoryKind};
use chrono::{TimeZone, Utc};

fn rec(id: &str, label: Label, text: &str) -> StoredRecord {
    StoredRecord::assemble(
        MemoryId::from_string(id),
        "memory/user:alice/profile".into(),
        MemoryKind::Semantic,
        label,
        false,
        vec![],
        Provenance::Operator,
        None,
        Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        None,
        vec![],
        MemoryContent::text(text),
    )
}

#[test]
fn max_label_filters_out_hotter_records() {
    let q = StoreQuery {
        max_label: Some(Label::Internal),
        ..Default::default()
    };
    assert!(q.matches(&rec("m1", Label::Public, "x")));
    assert!(q.matches(&rec("m1", Label::Internal, "x")));
    assert!(!q.matches(&rec("m1", Label::Sensitive, "x")));
    assert!(!q.matches(&rec("m1", Label::Secret, "x")));
}

#[test]
fn text_and_quarantine_filters() {
    let q = StoreQuery {
        text_contains: Some("VENICE".into()),
        ..Default::default()
    };
    assert!(q.matches(&rec("m1", Label::Public, "Alice lives in Venice")));
    assert!(!q.matches(&rec("m1", Label::Public, "Bob lives in Rome")));

    let mut quarantined = rec("m2", Label::Public, "injected");
    quarantined.quarantined = true;
    assert!(
        !StoreQuery::default().matches(&quarantined),
        "quarantine excluded by default"
    );
    let include = StoreQuery {
        include_quarantined: true,
        ..Default::default()
    };
    assert!(include.matches(&quarantined));
}

#[test]
fn text_filter_preserves_unicode_lowercase_semantics() {
    let unicode = StoreQuery {
        text_contains: Some("CAFÉ".into()),
        ..Default::default()
    };
    assert!(unicode.matches(&rec("m1", Label::Public, "Rendez-vous au café")));

    let empty = StoreQuery {
        text_contains: Some(String::new()),
        ..Default::default()
    };
    assert!(empty.matches(&rec("m2", Label::Public, "anything")));
}

#[test]
fn purpose_filter_allows_untagged_and_overlapping() {
    let q = StoreQuery {
        any_purpose: vec!["support".into()],
        ..Default::default()
    };
    let mut tagged = rec("m1", Label::Public, "x");
    tagged.purposes = vec!["support".into()];
    let mut other = rec("m2", Label::Public, "y");
    other.purposes = vec!["analytics".into()];
    let untagged = rec("m3", Label::Public, "z");

    assert!(q.matches(&tagged), "purpose overlaps");
    assert!(!q.matches(&other), "purpose disjoint");
    assert!(q.matches(&untagged), "untagged serves any purpose");
}

#[test]
fn in_memory_store_roundtrips_and_invalidates() {
    let store = InMemoryStore::new();
    store
        .put(rec("m1", Label::Internal, "Alice in Venice"))
        .unwrap();
    store.put(rec("m2", Label::Sensitive, "SSN 123")).unwrap();
    assert_eq!(store.len(), 2);

    let hits = store
        .query(&StoreQuery {
            max_label: Some(Label::Internal),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        hits.len(),
        1,
        "only the Internal record is at/below ceiling"
    );

    store
        .invalidate(&MemoryId::from_string("m1"), Utc::now())
        .unwrap();
    let live = store.query(&StoreQuery::default()).unwrap();
    assert!(
        live.iter().all(|r| r.id.as_str() != "m1"),
        "invalidated records are excluded by default"
    );

    assert!(store.tombstone(&MemoryId::from_string("m2")).unwrap());
    assert!(!store.tombstone(&MemoryId::from_string("nope")).unwrap());
}

#[test]
fn in_memory_store_limit_preserves_rank_order() {
    let store = InMemoryStore::new();
    for id in ["m1", "m4", "m2", "m3"] {
        store.put(rec(id, Label::Public, id)).unwrap();
    }

    let limited = store
        .query(&StoreQuery {
            limit: Some(2),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        limited
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        ["m4", "m3"]
    );
    assert!(
        store
            .query(&StoreQuery {
                limit: Some(0),
                ..Default::default()
            })
            .unwrap()
            .is_empty()
    );
}
