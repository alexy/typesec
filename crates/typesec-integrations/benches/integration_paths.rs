use std::sync::Arc;

use chrono::{TimeDelta, TimeZone, Utc};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use ed25519_dalek::SigningKey;
use typesec_integrations::{
    CognitionCommitReceipt, CognitionCommitReceiptClaims, CognitionEffect, DecisionReceipt, Did,
    DidEnvelope, DidKeyStore, DidMessageBody, Ed25519DidKey, Ed25519DidKeyStore,
    InMemoryReplayStore, ReceiptIssuer, ReceiptVerifier, ReplayStore, StaticDidResolver,
    TypeDidConversation, TypeDidGateway, TypeDidMode, TypeDidProfile, VerificationMethod,
};

const NOW: u64 = 1_800_000_000;
const EXPIRY: u64 = NOW + 300;
const PAYLOAD_SIZES: [usize; 2] = [256, 65_536];

struct DidFixture {
    alice: Did,
    agent: Did,
    resolver: StaticDidResolver,
    keys: Ed25519DidKeyStore,
    alice_authentication: VerificationMethod,
    alice_agreement_public: [u8; 32],
    agent_agreement_public: [u8; 32],
}

fn did_fixture() -> DidFixture {
    let alice_key = Ed25519DidKey::from_seed(b"benchmark-alice-ed25519");
    let agent_key = Ed25519DidKey::from_seed(b"benchmark-agent-ed25519");
    let alice = Did::key(alice_key.signing_public());
    let agent = Did::key(agent_key.signing_public());
    let alice_document = alice_key.document(alice.clone());
    let agent_document = agent_key.document(agent.clone());
    let alice_authentication = alice_document.verification_method[0].clone();
    let alice_agreement_public = alice_key.agreement_public();
    let agent_agreement_public = agent_key.agreement_public();
    let resolver = StaticDidResolver::new()
        .with_document(alice_document)
        .with_document(agent_document);
    let keys = Ed25519DidKeyStore::new()
        .with_key(alice.clone(), alice_key)
        .with_key(agent.clone(), agent_key);
    DidFixture {
        alice,
        agent,
        resolver,
        keys,
        alice_authentication,
        alice_agreement_public,
        agent_agreement_public,
    }
}

fn typedid_envelope(fixture: &DidFixture, payload: &[u8]) -> DidEnvelope {
    DidEnvelope::typedid(
        "benchmark-envelope",
        fixture.alice.clone(),
        fixture.agent.clone(),
        DidMessageBody::agent_message("memory/benchmark", "secret")
            .with_claim("purpose", "benchmark")
            .with_claim("agent_id", "agent:benchmark"),
        TypeDidConversation::new(
            "benchmark-conversation",
            TypeDidMode::RequestReply,
            TypeDidProfile::ed25519_x25519_chacha20().id,
            "a2a",
        ),
        payload,
        &fixture.resolver,
        &fixture.keys,
    )
    .expect("seal benchmark envelope")
}

#[derive(Debug)]
struct AcceptingReplayStore;

impl ReplayStore for AcceptingReplayStore {
    fn claim(&self, _: &str, _: u64, _: u64) -> Result<bool, String> {
        Ok(true)
    }
}

fn populated_replay_store(entries: usize) -> Arc<InMemoryReplayStore> {
    let store = Arc::new(InMemoryReplayStore::new());
    for index in 0..entries {
        assert!(
            store
                .claim(&format!("active-envelope-{index}"), EXPIRY, NOW)
                .expect("populate replay store")
        );
    }
    store
}

fn bench_replay_store(c: &mut Criterion) {
    let mut group = c.benchmark_group("did_replay_claim");
    group.sample_size(30);
    for entries in [1, 1_000, 10_000] {
        let store = populated_replay_store(entries);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("active_hit", entries), &entries, |b, _| {
            b.iter(|| {
                black_box(
                    store
                        .claim(black_box("active-envelope-0"), EXPIRY, NOW)
                        .expect("check replay claim"),
                )
            })
        });
    }
    group.finish();

    let store = populated_replay_store(10_000);
    let mut concurrent = c.benchmark_group("did_replay_concurrent_burst");
    concurrent.sample_size(20);
    for threads in [1, 8] {
        const CLAIMS_PER_THREAD: usize = 128;
        concurrent.throughput(Throughput::Elements((threads * CLAIMS_PER_THREAD) as u64));
        concurrent.bench_with_input(
            BenchmarkId::from_parameter(threads),
            &threads,
            |b, &threads| {
                b.iter(|| {
                    std::thread::scope(|scope| {
                        for _ in 0..threads {
                            let store = Arc::clone(&store);
                            scope.spawn(move || {
                                for _ in 0..CLAIMS_PER_THREAD {
                                    black_box(
                                        store
                                            .claim("active-envelope-0", EXPIRY, NOW)
                                            .expect("check concurrent replay claim"),
                                    );
                                }
                            });
                        }
                    });
                });
            },
        );
    }
    concurrent.finish();
}

fn bench_did_crypto(c: &mut Criterion) {
    let fixture = did_fixture();
    let nonce = [7_u8; 12];
    let associated_data = b"typesec integration benchmark associated data";

    let mut signing = c.benchmark_group("did_ed25519");
    signing.sample_size(30);
    for payload_bytes in PAYLOAD_SIZES {
        let payload = vec![b'x'; payload_bytes];
        let signature = fixture
            .keys
            .sign(&fixture.alice, &payload)
            .expect("sign benchmark payload");
        signing.throughput(Throughput::Bytes(payload_bytes as u64));
        signing.bench_with_input(
            BenchmarkId::new("sign", payload_bytes),
            &payload,
            |b, payload| {
                b.iter(|| {
                    black_box(
                        fixture
                            .keys
                            .sign(&fixture.alice, black_box(payload))
                            .expect("sign benchmark payload"),
                    )
                })
            },
        );
        signing.bench_with_input(
            BenchmarkId::new("verify", payload_bytes),
            &payload,
            |b, payload| {
                b.iter(|| {
                    fixture
                        .keys
                        .verify(
                            &fixture.alice_authentication,
                            black_box(payload),
                            black_box(&signature),
                        )
                        .expect("verify benchmark payload")
                })
            },
        );
    }
    signing.finish();

    let mut encryption = c.benchmark_group("did_x25519_chacha20poly1305");
    encryption.sample_size(30);
    for payload_bytes in PAYLOAD_SIZES {
        let payload = vec![b'x'; payload_bytes];
        let ciphertext = fixture
            .keys
            .encrypt_for(
                &fixture.alice,
                &fixture.agent_agreement_public,
                &payload,
                &nonce,
                associated_data,
            )
            .expect("encrypt benchmark payload");
        encryption.throughput(Throughput::Bytes(payload_bytes as u64));
        encryption.bench_with_input(
            BenchmarkId::new("encrypt", payload_bytes),
            &payload,
            |b, payload| {
                b.iter(|| {
                    black_box(
                        fixture
                            .keys
                            .encrypt_for(
                                &fixture.alice,
                                &fixture.agent_agreement_public,
                                black_box(payload),
                                &nonce,
                                associated_data,
                            )
                            .expect("encrypt benchmark payload"),
                    )
                })
            },
        );
        encryption.bench_with_input(
            BenchmarkId::new("decrypt", payload_bytes),
            &ciphertext,
            |b, ciphertext| {
                b.iter(|| {
                    black_box(
                        fixture
                            .keys
                            .decrypt_for(
                                &fixture.agent,
                                &fixture.alice_agreement_public,
                                &nonce,
                                black_box(ciphertext),
                                associated_data,
                            )
                            .expect("decrypt benchmark payload"),
                    )
                })
            },
        );
    }
    encryption.finish();
}

fn bench_typedid(c: &mut Criterion) {
    let fixture = did_fixture();
    let mut group = c.benchmark_group("typedid_envelope");
    group.sample_size(30);

    for payload_bytes in PAYLOAD_SIZES {
        let payload = vec![b'x'; payload_bytes];
        let envelope = typedid_envelope(&fixture, &payload);
        let gateway = TypeDidGateway::new(
            Arc::new(fixture.resolver.clone()),
            Arc::new(fixture.keys.clone()),
            fixture.agent.clone(),
        )
        .with_replay_store(Arc::new(AcceptingReplayStore));
        group.throughput(Throughput::Bytes(payload_bytes as u64));
        group.bench_with_input(
            BenchmarkId::new("seal", payload_bytes),
            &payload,
            |b, payload| b.iter(|| black_box(typedid_envelope(&fixture, black_box(payload)))),
        );
        group.bench_with_input(
            BenchmarkId::new("open", payload_bytes),
            &envelope,
            |b, envelope| {
                b.iter(|| {
                    black_box(
                        gateway
                            .open_message(black_box(envelope))
                            .expect("open benchmark envelope"),
                    )
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("reference", payload_bytes),
            &envelope,
            |b, envelope| b.iter(|| black_box(black_box(envelope).reference())),
        );
    }
    group.finish();
}

fn digest(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}

fn cognition_receipt(affected_ids: usize) -> CognitionCommitReceipt {
    let authority = Utc.with_ymd_and_hms(2026, 8, 5, 11, 59, 0).unwrap();
    let prepared = Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 0).unwrap();
    CognitionCommitReceipt::new(
        CognitionCommitReceiptClaims {
            effect: CognitionEffect::Mutated,
            subject: "did:key:benchmark-agent".into(),
            resource: "memory/did:key:benchmark-agent/research".into(),
            job_id: "benchmark-job".into(),
            governed_source_scope: Some(digest('a')),
            typedid_request_digest: digest('1'),
            proposal_digest: digest('2'),
            governed_scan_digest: digest('3'),
            input_snapshot_digest: digest('4'),
            policy_decision_digest: digest('5'),
            authorization_receipt_digest: digest('6'),
            prior_version: "version-before".into(),
            resulting_version: "version-after".into(),
            affected_ids: (0..affected_ids)
                .map(|index| format!("memory-{index:04}"))
                .collect(),
            backend_commit_id: "commit-benchmark".into(),
            authority_revalidated_at: authority,
            prepared_at: prepared,
            committed_at: prepared + TimeDelta::seconds(1),
            issued_at: prepared + TimeDelta::seconds(2),
        },
        TimeDelta::minutes(5),
    )
    .expect("construct benchmark cognition receipt")
}

fn bench_receipts(c: &mut Criterion) {
    let now = Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 3).unwrap();
    let issuer = ReceiptIssuer::new(SigningKey::from_bytes(&[11_u8; 32]));
    let verifier = ReceiptVerifier::new(issuer.verifying_key());
    let decision = DecisionReceipt::new(
        "did:key:benchmark-agent",
        "memory:remember",
        "memory/did:key:benchmark-agent/research",
        now,
        TimeDelta::minutes(5),
    )
    .for_tool_call("remember", Some("call-benchmark"));
    let decision_token = issuer.issue(&decision);

    let mut decisions = c.benchmark_group("decision_receipt");
    decisions.sample_size(30);
    decisions.bench_function("issue", |b| {
        b.iter(|| black_box(issuer.issue(black_box(&decision))))
    });
    decisions.bench_function("verify", |b| {
        b.iter(|| {
            black_box(
                verifier
                    .verify(black_box(&decision_token), now)
                    .expect("verify benchmark decision receipt"),
            )
        })
    });
    decisions.finish();

    let mut cognition = c.benchmark_group("cognition_receipt");
    cognition.sample_size(30);
    for affected_ids in [2, 256] {
        let receipt = cognition_receipt(affected_ids);
        let token = issuer
            .issue_cognition(&receipt, now)
            .expect("issue benchmark cognition receipt");
        cognition.throughput(Throughput::Elements(affected_ids as u64));
        cognition.bench_with_input(
            BenchmarkId::new("issue", affected_ids),
            &receipt,
            |b, receipt| {
                b.iter(|| {
                    black_box(
                        issuer
                            .issue_cognition(black_box(receipt), now)
                            .expect("issue benchmark cognition receipt"),
                    )
                })
            },
        );
        cognition.bench_with_input(
            BenchmarkId::new("verify", affected_ids),
            &token,
            |b, token| {
                b.iter(|| {
                    black_box(
                        verifier
                            .verify_cognition(black_box(token), now)
                            .expect("verify benchmark cognition receipt"),
                    )
                })
            },
        );
    }
    cognition.finish();
}

criterion_group!(
    benches,
    bench_replay_store,
    bench_did_crypto,
    bench_typedid,
    bench_receipts
);
criterion_main!(benches);
