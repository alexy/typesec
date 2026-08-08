use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use typesec_memory::{
    CognitionBinding, CognitionProposal, Label, MemoryContent, MemoryDraft, MemoryId, MemoryKind,
    Provenance, governed_source_draft_digest,
};

const PROPOSAL_CASES: [(usize, usize); 3] = [(1, 256), (64, 1_024), (256, 1_024)];

fn digest(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}

fn binding(projection_count: usize) -> CognitionBinding {
    CognitionBinding {
        space_id: "memory/agent:bench/profile".to_owned(),
        subject: "did:key:benchmark".to_owned(),
        purpose: "benchmark".to_owned(),
        governed_source_scope: None,
        governed_scan_digest: digest('1'),
        snapshot_digest: digest('2'),
        plan_task_digest: digest('3'),
        authorization_receipt_digest: digest('4'),
        effective_projection: (0..projection_count)
            .rev()
            .map(|index| format!("field-{index:04}"))
            .collect(),
        source_manifest_digest: digest('5'),
        typedid_request_digest: digest('6'),
    }
}

fn draft(text_bytes: usize) -> MemoryDraft {
    MemoryDraft::new(
        MemoryKind::Semantic,
        MemoryContent::text("x".repeat(text_bytes)),
        Provenance::Operator,
    )
    .with_label(Label::Internal)
}

fn proposal(draft_count: usize, text_bytes: usize) -> CognitionProposal {
    let binding = binding(16);
    CognitionProposal::new(
        "benchmark-job",
        binding.snapshot_digest.clone(),
        binding.source_manifest_digest.clone(),
        "marciana.benchmark",
        "1",
        vec![MemoryId::from_string("benchmark-source")],
        Label::Internal,
    )
    .with_drafts((0..draft_count).map(|_| draft(text_bytes)).collect())
    .with_binding(binding)
}

fn bench_governed_draft_digest(c: &mut Criterion) {
    let mut group = c.benchmark_group("governed_draft_digest");
    group.sample_size(30);
    for text_bytes in [256, 65_536] {
        let draft = draft(text_bytes);
        let serialized_bytes = serde_json::to_vec(&draft)
            .expect("serialize benchmark draft")
            .len();
        group.throughput(Throughput::Bytes(serialized_bytes as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format_args!("{text_bytes}_text_bytes")),
            &draft,
            |b, draft| {
                b.iter(|| {
                    black_box(governed_source_draft_digest(black_box(draft)).expect("draft digest"))
                })
            },
        );
    }
    group.finish();
}

fn bench_binding_digest(c: &mut Criterion) {
    let mut group = c.benchmark_group("cognition_binding_digest");
    group.sample_size(30);
    for projection_count in [4, 256] {
        let binding = binding(projection_count);
        let serialized_bytes = serde_json::to_vec(&binding)
            .expect("serialize benchmark binding")
            .len();
        group.throughput(Throughput::Bytes(serialized_bytes as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format_args!("{projection_count}_fields")),
            &binding,
            |b, binding| b.iter(|| black_box(binding.canonical_digest().expect("binding digest"))),
        );
    }
    group.finish();
}

fn bench_proposal_digest(c: &mut Criterion) {
    let mut group = c.benchmark_group("cognition_proposal_digest");
    group.sample_size(30);
    for (draft_count, text_bytes) in PROPOSAL_CASES {
        let proposal = proposal(draft_count, text_bytes);
        let serialized_bytes = serde_json::to_vec(&proposal)
            .expect("serialize benchmark proposal")
            .len();
        proposal
            .canonical_digest()
            .expect("valid benchmark proposal");
        group.throughput(Throughput::Bytes(serialized_bytes as u64));
        group.bench_with_input(
            BenchmarkId::new("drafts", draft_count),
            &proposal,
            |b, proposal| {
                b.iter(|| black_box(proposal.canonical_digest().expect("proposal digest")))
            },
        );
    }
    group.finish();
}

fn bench_proposal_wire(c: &mut Criterion) {
    let mut group = c.benchmark_group("cognition_proposal_wire");
    group.sample_size(30);
    for (draft_count, text_bytes) in PROPOSAL_CASES {
        let proposal = proposal(draft_count, text_bytes);
        let serialized_bytes = serde_json::to_vec(&proposal)
            .expect("serialize benchmark proposal")
            .len();
        group.throughput(Throughput::Bytes(serialized_bytes as u64));
        group.bench_with_input(
            BenchmarkId::new("serialize_to_sink", draft_count),
            &proposal,
            |b, proposal| {
                b.iter(|| {
                    serde_json::to_writer(std::io::sink(), black_box(proposal))
                        .expect("serialize proposal")
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_governed_draft_digest,
    bench_binding_digest,
    bench_proposal_digest,
    bench_proposal_wire
);
criterion_main!(benches);
