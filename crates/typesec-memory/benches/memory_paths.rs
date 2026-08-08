use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use typesec_memory::{
    InMemoryStore, KeywordIndex, Label, MemoryId, MemoryStore, SemanticIndex, StoreQuery,
    StoredRecord,
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
        let (id, text) = keyword_document(record_index);
        index
            .index(&id, typesec_memory::Label::Internal, &text)
            .expect("index benchmark record");
    }
    index
}

fn keyword_document(index: usize) -> (MemoryId, String) {
    let text = if index.is_multiple_of(10) {
        format!("record {index} contains the target phrase")
    } else {
        format!("ordinary memory record {index}")
    };
    (MemoryId::from_string(format!("bench-{index:05}")), text)
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
    for (name, query) in [
        ("sparse_target_phrase_limit_10", "target phrase"),
        ("common_memory_record_limit_10", "memory record"),
        ("missing_tokens_limit_10", "tokens absent everywhere"),
    ] {
        group.bench_function(name, |b| {
            b.iter(|| {
                black_box(
                    index
                        .search(black_box(query), black_box(10))
                        .expect("search"),
                )
            })
        });
    }
    group.finish();

    let id = MemoryId::from_string("bench-00000");
    let mut group = c.benchmark_group("keyword_index_mutation_10k");
    group.sample_size(30);
    group.throughput(Throughput::Elements(1));
    group.bench_function("reindex_unchanged", |b| {
        b.iter(|| {
            index
                .index(
                    black_box(&id),
                    black_box(Label::Internal),
                    black_box("updated target phrase memory record"),
                )
                .expect("replace indexed record")
        })
    });
    group.bench_function("replace_changed_tokens", |b| {
        let mut use_alpha = false;
        b.iter(|| {
            use_alpha = !use_alpha;
            let text = if use_alpha {
                "alternating alpha memory record"
            } else {
                "alternating beta memory record"
            };
            index
                .index(black_box(&id), black_box(Label::Internal), black_box(text))
                .expect("replace indexed record")
        })
    });
    group.finish();
}

fn bench_keyword_population(c: &mut Criterion) {
    let documents = (0..RECORD_COUNT).map(keyword_document).collect::<Vec<_>>();
    let mut group = c.benchmark_group("keyword_index_population");
    group.sample_size(20);
    group.throughput(Throughput::Elements(RECORD_COUNT as u64));
    group.bench_function("build_10k", |b| {
        b.iter_with_large_drop(|| {
            let index = KeywordIndex::new();
            for (id, text) in &documents {
                index
                    .index(id, Label::Internal, text)
                    .expect("index benchmark record");
            }
            index
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_store_queries,
    bench_keyword_search,
    bench_keyword_population
);
criterion_main!(benches);
