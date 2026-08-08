use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use typesec_memory::{
    InMemoryStore, KeywordIndex, MemoryStore, SemanticIndex, StoreQuery, StoredRecord,
};

const RECORD_COUNT: usize = 10_000;

fn record(index: usize) -> StoredRecord {
    let text = if index.is_multiple_of(10) {
        format!("record {index} contains the target phrase")
    } else {
        format!("ordinary memory record {index}")
    };
    serde_json::from_value(serde_json::json!({
        "id": format!("bench-{index:05}"),
        "space_id": "memory/agent:bench/profile",
        "kind": "semantic",
        "label": "internal",
        "quarantined": false,
        "entities": [],
        "provenance": { "source": "operator" },
        "observed_at": "2026-08-07T00:00:00Z",
        "valid_from": "2026-01-01T00:00:00Z",
        "invalid_at": null,
        "expires_at": null,
        "purposes": [],
        "content": { "text": text }
    }))
    .expect("valid benchmark record")
}

fn populated_store() -> InMemoryStore {
    let store = InMemoryStore::new();
    for index in 0..RECORD_COUNT {
        store.put(record(index)).expect("insert benchmark record");
    }
    store
}

fn populated_keyword_index() -> KeywordIndex {
    let index = KeywordIndex::new();
    for record_index in 0..RECORD_COUNT {
        let text = if record_index.is_multiple_of(10) {
            format!("record {record_index} contains the target phrase")
        } else {
            format!("ordinary memory record {record_index}")
        };
        index
            .index(
                &typesec_memory::MemoryId::from_string(format!("bench-{record_index:05}")),
                typesec_memory::Label::Internal,
                &text,
            )
            .expect("index benchmark record");
    }
    index
}

fn bench_store_queries(c: &mut Criterion) {
    let store = populated_store();
    let latest = StoreQuery {
        space_id: Some("memory/agent:bench/profile".to_owned()),
        limit: Some(10),
        ..StoreQuery::default()
    };
    let text = StoreQuery {
        space_id: Some("memory/agent:bench/profile".to_owned()),
        text_contains: Some("TARGET PHRASE".to_owned()),
        limit: Some(10),
        ..StoreQuery::default()
    };

    let mut group = c.benchmark_group("memory_store_query_10k");
    group.sample_size(30);
    group.throughput(Throughput::Elements(RECORD_COUNT as u64));
    group.bench_function("latest_limit_10", |b| {
        b.iter(|| black_box(store.query(black_box(&latest)).expect("query")))
    });
    group.bench_function("case_insensitive_text_limit_10", |b| {
        b.iter(|| black_box(store.query(black_box(&text)).expect("query")))
    });
    group.finish();
}

fn bench_keyword_search(c: &mut Criterion) {
    let index = populated_keyword_index();
    let mut group = c.benchmark_group("keyword_index_search_10k");
    group.sample_size(30);
    group.throughput(Throughput::Elements(RECORD_COUNT as u64));
    group.bench_function("target_phrase_limit_10", |b| {
        b.iter(|| {
            black_box(
                index
                    .search(black_box("target phrase"), black_box(10))
                    .expect("search"),
            )
        })
    });
    group.finish();
}

criterion_group!(benches, bench_store_queries, bench_keyword_search);
criterion_main!(benches);
