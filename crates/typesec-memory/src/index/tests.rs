use super::*;

fn id(s: &str) -> MemoryId {
    MemoryId::from_string(s)
}

#[test]
fn keyword_index_ranks_by_overlap_and_breaks_ties_by_id() {
    let index = KeywordIndex::new();
    index
        .index(&id("m1"), Label::Internal, "Alice lives in Venice")
        .unwrap();
    index
        .index(&id("m2"), Label::Internal, "Venice hosts the Biennale")
        .unwrap();
    index
        .index(&id("m3"), Label::Internal, "Bob likes tea")
        .unwrap();

    let hits = index.search("where in Venice does Alice live", 10).unwrap();
    assert_eq!(hits[0], id("m1"), "two overlapping tokens beats one");
    assert_eq!(hits[1], id("m2"));
    assert!(!hits.contains(&id("m3")), "no overlap, no hit");

    assert_eq!(
        index.search("venice", 1).unwrap().len(),
        1,
        "limit respected"
    );
    assert!(
        index.search("", 10).unwrap().is_empty(),
        "empty query, no hits"
    );
}

#[test]
fn remove_prunes_and_reindex_replaces() {
    let index = KeywordIndex::new();
    index
        .index(&id("m1"), Label::Secret, "hunter2 password")
        .unwrap();
    assert_eq!(index.search("hunter2", 10).unwrap().len(), 1);

    index.remove(&id("m1")).unwrap();
    assert!(index.search("hunter2", 10).unwrap().is_empty());
    index.remove(&id("m1")).unwrap(); // unknown id is not an error

    index.index(&id("m2"), Label::Public, "old text").unwrap();
    index
        .index(&id("m2"), Label::Public, "new words entirely")
        .unwrap();
    assert!(
        index.search("old", 10).unwrap().is_empty(),
        "reindex replaces"
    );
    assert_eq!(index.search("entirely", 10).unwrap().len(), 1);
}
