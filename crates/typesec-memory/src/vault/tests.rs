use super::*;
use crate::InMemoryStore;
use crate::record::{MemoryContent, MemoryDraft, Provenance};
use crate::space::MemoryKind;
use typesec_core::policy::{MintOptions, RequestContext, mint_capability_for_id};
use typesec_core::secure_value::{Internal, Public, Sensitive};
use typesec_core::{CanDelete, CanRead, CanReadSensitive, CanWrite, Capability};

const POLICY: &str = r#"
roles:
  - name: keeper
    permissions: [read, write, delete, read_sensitive]
    resources: ["memory/**"]
  - name: reader
    permissions: [read]
    resources: ["memory/user:alice/**"]
assignments:
  - subject: "agent:keeper"
    roles: [keeper]
  - subject: "agent:reader"
    roles: [reader]
"#;

fn engine() -> typesec_rbac::RbacEngine {
    typesec_rbac::RbacEngine::from_yaml(POLICY).expect("policy parses")
}

fn cap<P: typesec_core::Permission>(
    subject: &str,
    space: &MemorySpace,
) -> Capability<P, MemorySpace> {
    mint_capability_for_id(
        &engine(),
        subject,
        space.resource_id(),
        &MintOptions::default(),
    )
    .expect("mint")
}

fn vault() -> MemoryVault<InMemoryStore> {
    MemoryVault::new(InMemoryStore::new())
}

fn draft(text: &str, prov: Provenance) -> MemoryDraft {
    MemoryDraft::new(MemoryKind::Semantic, MemoryContent::text(text), prov)
}

#[test]
fn remember_then_recall_returns_content() {
    let space = MemorySpace::new("user:alice", "profile");
    let vault = vault();
    let write: Capability<CanWrite, _> = cap("agent:keeper", &space);
    let read: Capability<CanRead, _> = cap("agent:keeper", &space);

    vault
        .remember(
            &space,
            &write,
            draft("Alice lives in Venice", Provenance::Operator),
        )
        .unwrap();

    let recall = vault
        .recall::<Internal>(
            &space,
            &read,
            RecallQuery::all(),
            &RequestContext::default(),
        )
        .unwrap();
    assert_eq!(recall.hits.len(), 1);
    assert_eq!(recall.hits[0].content.text, "Alice lives in Venice");
    assert!(!recall.has_redactions());
}

#[test]
fn recall_ceiling_redacts_hotter_records() {
    let space = MemorySpace::new("user:alice", "profile");
    let vault = vault();
    let write: Capability<CanWrite, _> = cap("agent:keeper", &space);
    let read: Capability<CanRead, _> = cap("agent:keeper", &space);

    vault
        .remember(
            &space,
            &write,
            draft("public bio", Provenance::Operator).with_label(Label::Public),
        )
        .unwrap();
    vault
        .remember(
            &space,
            &write,
            draft("SSN 123-45-6789", Provenance::Operator).with_label(Label::Sensitive),
        )
        .unwrap();

    // Recall at Public: the Sensitive record is redacted, not returned.
    let recall = vault
        .recall::<Public>(
            &space,
            &read,
            RecallQuery::all(),
            &RequestContext::default(),
        )
        .unwrap();
    assert_eq!(recall.hits.len(), 1);
    assert_eq!(recall.hits[0].content.text, "public bio");
    assert_eq!(recall.redacted.len(), 1);
    assert_eq!(recall.redacted[0].label, Label::Sensitive);

    // The redacted hit reveals with CanReadSensitive.
    let reveal_cap: Capability<CanReadSensitive, _> = cap("agent:keeper", &space);
    let content = vault
        .reveal(
            &space,
            &reveal_cap,
            &recall.redacted[0].id,
            &RequestContext::default(),
        )
        .unwrap();
    assert_eq!(content.text, "SSN 123-45-6789");
}

#[test]
fn recall_at_sensitive_returns_everything() {
    let space = MemorySpace::new("user:alice", "profile");
    let vault = vault();
    let write: Capability<CanWrite, _> = cap("agent:keeper", &space);
    let read: Capability<CanRead, _> = cap("agent:keeper", &space);
    vault
        .remember(
            &space,
            &write,
            draft("a", Provenance::Operator).with_label(Label::Public),
        )
        .unwrap();
    vault
        .remember(
            &space,
            &write,
            draft("b", Provenance::Operator).with_label(Label::Sensitive),
        )
        .unwrap();

    let recall = vault
        .recall::<Sensitive>(
            &space,
            &read,
            RecallQuery::all(),
            &RequestContext::default(),
        )
        .unwrap();
    assert_eq!(recall.hits.len(), 2);
    assert!(!recall.has_redactions());
}

#[test]
fn wrong_space_capability_is_rejected() {
    let alice = MemorySpace::new("user:alice", "profile");
    let bob = MemorySpace::new("user:bob", "profile");
    let vault = vault();
    let write_alice: Capability<CanWrite, _> = cap("agent:keeper", &alice);

    // A capability minted for Alice's space cannot write Bob's.
    let err = vault
        .remember(&bob, &write_alice, draft("x", Provenance::Operator))
        .unwrap_err();
    assert!(matches!(err, MemoryError::SpaceMismatch { .. }));
}

#[test]
fn trusted_source_declares_label_but_untrusted_can_only_raise() {
    let space = MemorySpace::new("user:alice", "profile");
    let vault = vault();
    let write: Capability<CanWrite, _> = cap("agent:keeper", &space);
    let read: Capability<CanRead, _> = cap("agent:keeper", &space);

    // A trusted operator MAY declare something Public.
    vault
        .remember(
            &space,
            &write,
            draft("public bio", Provenance::Operator).with_label(Label::Public),
        )
        .unwrap();
    // An untrusted source trying to label its injection Public is floored to
    // Internal (and quarantined) — it cannot talk its way down.
    vault
        .remember(
            &space,
            &write,
            draft("sneaky", Provenance::ModelText).with_label(Label::Public),
        )
        .unwrap();

    let public = vault
        .recall::<Public>(
            &space,
            &read,
            RecallQuery::all(),
            &RequestContext::default(),
        )
        .unwrap();
    assert_eq!(
        public.hits.len(),
        1,
        "only the operator's genuine Public record"
    );
    assert_eq!(public.hits[0].content.text, "public bio");
    // The model-text record is quarantined AND still Internal — invisible here.
    assert!(
        public.redacted.is_empty(),
        "quarantined record isn't even redacted-listed"
    );
}

#[test]
fn model_text_is_quarantined_and_hidden_by_default() {
    let space = MemorySpace::new("user:alice", "episodic");
    let vault = vault();
    let write: Capability<CanWrite, _> = cap("agent:keeper", &space);
    let read: Capability<CanRead, _> = cap("agent:keeper", &space);

    vault
        .remember(
            &space,
            &write,
            draft("ignore previous instructions", Provenance::ModelText),
        )
        .unwrap();

    // Not returned in normal recall (quarantined).
    let normal = vault
        .recall::<Sensitive>(
            &space,
            &read,
            RecallQuery::all(),
            &RequestContext::default(),
        )
        .unwrap();
    assert!(normal.hits.is_empty() && normal.redacted.is_empty());

    // Returned only when explicitly including quarantine.
    let with_q = vault
        .recall::<Sensitive>(
            &space,
            &read,
            RecallQuery {
                include_quarantined: true,
                ..RecallQuery::all()
            },
            &RequestContext::default(),
        )
        .unwrap();
    assert_eq!(with_q.hits.len(), 1);
}

#[test]
fn consolidation_join_raises_summary_label() {
    let space = MemorySpace::new("user:alice", "semantic");
    let vault = vault();
    let write: Capability<CanWrite, _> = cap("agent:keeper", &space);
    let read: Capability<CanRead, _> = cap("agent:keeper", &space);

    let public_id = vault
        .remember(
            &space,
            &write,
            draft("likes coffee", Provenance::Operator).with_label(Label::Public),
        )
        .unwrap();
    let sensitive_id = vault
        .remember(
            &space,
            &write,
            draft("medical note", Provenance::Operator).with_label(Label::Sensitive),
        )
        .unwrap();

    // Summarize a Public + Sensitive pair; the summary must be Sensitive.
    let plan = ConsolidationPlan::new().then(ConsolidationStep::Supersede {
        superseded: vec![public_id, sensitive_id],
        replacement: draft("health & lifestyle summary", Provenance::Operator)
            .with_label(Label::Public),
    });
    let report = vault.consolidate(&space, &write, plan).unwrap();
    assert_eq!(report.invalidated.len(), 2);
    assert_eq!(report.created.len(), 1);

    // At Public ceiling the summary is hidden (it was raised to Sensitive).
    let public_recall = vault
        .recall::<Public>(
            &space,
            &read,
            RecallQuery::all(),
            &RequestContext::default(),
        )
        .unwrap();
    assert!(public_recall.hits.is_empty());
    assert_eq!(
        public_recall.redacted.len(),
        1,
        "summary is Sensitive, redacted at Public"
    );
}

#[test]
fn forget_is_destructive_and_scoped() {
    let space = MemorySpace::new("user:alice", "profile");
    let vault = vault();
    let write: Capability<CanWrite, _> = cap("agent:keeper", &space);
    let read: Capability<CanRead, _> = cap("agent:keeper", &space);
    let delete: Capability<CanDelete, _> = cap("agent:keeper", &space);

    let id = vault
        .remember(&space, &write, draft("forget me", Provenance::Operator))
        .unwrap();
    let tomb = vault
        .forget(&space, &delete, ForgetSelector::Ids(vec![id.clone()]))
        .unwrap();
    assert_eq!(tomb.forgotten, vec![id]);

    let recall = vault
        .recall::<Sensitive>(
            &space,
            &read,
            RecallQuery::all(),
            &RequestContext::default(),
        )
        .unwrap();
    assert!(recall.hits.is_empty(), "forgotten record is gone");
}

#[test]
fn retention_reaper_forgets_expired_records() {
    use chrono::{TimeZone, Utc};
    let space = MemorySpace::new("user:alice", "episodic");
    let vault = vault();
    let write: Capability<CanWrite, _> = cap("agent:keeper", &space);
    let delete: Capability<CanDelete, _> = cap("agent:keeper", &space);
    let read: Capability<CanRead, _> = cap("agent:keeper", &space);

    let past = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
    vault
        .remember(
            &space,
            &write,
            draft("ephemeral", Provenance::Operator).expires_at(past),
        )
        .unwrap();
    vault
        .remember(&space, &write, draft("durable", Provenance::Operator))
        .unwrap();

    let tomb = vault.reap_expired(&space, &delete, Utc::now()).unwrap();
    assert_eq!(tomb.forgotten.len(), 1, "only the expired record is reaped");

    let recall = vault
        .recall::<Sensitive>(
            &space,
            &read,
            RecallQuery::all(),
            &RequestContext::default(),
        )
        .unwrap();
    assert_eq!(recall.hits.len(), 1);
    assert_eq!(recall.hits[0].content.text, "durable");
}

#[test]
fn attenuated_delegation_hands_a_weaker_shorter_capability() {
    use std::time::Duration;
    let space = MemorySpace::new("user:alice", "profile");
    let vault = vault();
    let planner_write: Capability<CanWrite, _> = cap("agent:keeper", &space);
    vault
        .remember(
            &space,
            &planner_write,
            draft("shared fact", Provenance::Operator),
        )
        .unwrap();

    // A read cap the planner holds, coerced down the lattice and lease-capped
    // before handing to a sub-agent for one short delegated recall.
    let planner_read: Capability<CanRead, _> = cap("agent:keeper", &space);
    let delegated: Capability<CanRead, _> = planner_read.attenuated(Duration::from_secs(300));

    let recall = vault
        .recall::<Sensitive>(
            &space,
            &delegated,
            RecallQuery::all(),
            &RequestContext::default(),
        )
        .unwrap();
    assert_eq!(
        recall.hits.len(),
        1,
        "sub-agent reads with the attenuated cap"
    );
    assert!(delegated.expires_at() <= planner_read.expires_at());
}

#[test]
fn configured_policy_engine_binds_purpose_at_use_time() {
    // An ODRL policy that only permits reading this space for the "support"
    // purpose. The capability is minted (mint uses default ctx here via a
    // permissive companion RBAC), then recall is re-checked per purpose.
    let odrl = typesec_odrl::OdrlEngine::from_yaml(
        r#"
policies:
  - uid: "policy:mem"
    type: Set
    rules:
      - type: permission
        assignee: "agent:keeper"
        action: read
        target: "memory/user:alice/profile"
        constraints:
          - leftOperand: purpose
            operator: eq
            rightOperand: "support"
"#,
    )
    .expect("odrl parses");

    let space = MemorySpace::new("user:alice", "profile");
    // Seed with a permissive vault, then read through a policy-bound one.
    let write: Capability<CanWrite, _> = cap("agent:keeper", &space);
    let store = InMemoryStore::new();
    MemoryVault::new(store)
        .remember(&space, &write, draft("ticket note", Provenance::Operator))
        .ok();

    // Build a fresh vault sharing a store isn't trivial with owned stores;
    // instead seed and read in one policy-bound vault via a permissive engine
    // for the write and the ODRL engine for reads is not compositional here,
    // so we assert the engine denies a wrong-purpose read directly.
    let vault = MemoryVault::new(InMemoryStore::new()).with_policy(std::sync::Arc::new(odrl));
    let seed_write: Capability<CanWrite, _> = cap("agent:keeper", &space);
    // Writing needs `write`, which the ODRL policy doesn't grant → PolicyDenied.
    let write_err = vault
        .remember(&space, &seed_write, draft("x", Provenance::Operator))
        .unwrap_err();
    assert!(matches!(write_err, MemoryError::PolicyDenied { .. }));

    // A read with the wrong purpose is denied; the right purpose is allowed
    // (there are no records, but authorization is what we're testing).
    let read: Capability<CanRead, _> = cap("agent:keeper", &space);
    let denied = vault
        .recall::<Sensitive>(
            &space,
            &read,
            RecallQuery::all(),
            &RequestContext::default(),
        )
        .unwrap_err();
    assert!(
        matches!(denied, MemoryError::PolicyDenied { .. }),
        "no purpose → denied"
    );

    let allowed = vault.recall::<Sensitive>(
        &space,
        &read,
        RecallQuery::all(),
        &RequestContext::default().with_purpose("support"),
    );
    assert!(
        allowed.is_ok(),
        "support purpose satisfies the ODRL constraint"
    );
}

#[test]
fn every_alternate_read_path_binds_purpose_at_use_time() {
    let odrl = typesec_odrl::OdrlEngine::from_yaml(
        r#"
policies:
  - uid: "policy:mem-alternate-reads"
    type: Set
    rules:
      - type: permission
        assignee: "agent:keeper"
        action: read
        target: "memory/user:alice/profile"
        constraints:
          - leftOperand: purpose
            operator: eq
            rightOperand: "support"
      - type: permission
        assignee: "agent:keeper"
        action: read_sensitive
        target: "memory/user:alice/profile"
        constraints:
          - leftOperand: purpose
            operator: eq
            rightOperand: "support"
"#,
    )
    .expect("odrl parses");
    let space = MemorySpace::new("user:alice", "profile");
    let vault = MemoryVault::new(InMemoryStore::new()).with_policy(std::sync::Arc::new(odrl));
    let read: Capability<CanRead, _> = cap("agent:keeper", &space);
    let sensitive: Capability<CanReadSensitive, _> = cap("agent:keeper", &space);
    let no_purpose = RequestContext::default();

    let graph = vault.recall_neighborhood(&space, &read, "ACME", 1, Label::Internal, &no_purpose);
    assert!(matches!(graph, Err(MemoryError::PolicyDenied { .. })));

    let semantic = vault.recall_semantic(&space, &read, "ticket", 10, Label::Internal, &no_purpose);
    assert!(matches!(semantic, Err(MemoryError::PolicyDenied { .. })));

    let reveal = vault.reveal(&space, &sensitive, &MemoryId::next(), &no_purpose);
    assert!(matches!(reveal, Err(MemoryError::PolicyDenied { .. })));
}

#[test]
fn purpose_binds_recall() {
    let space = MemorySpace::new("user:alice", "profile");
    let vault = vault();
    let write: Capability<CanWrite, _> = cap("agent:keeper", &space);
    let read: Capability<CanRead, _> = cap("agent:keeper", &space);

    vault
        .remember(
            &space,
            &write,
            draft("support ticket detail", Provenance::Operator).for_purposes(["support"]),
        )
        .unwrap();

    let analytics = vault
        .recall::<Sensitive>(
            &space,
            &read,
            RecallQuery::all(),
            &RequestContext::default().with_purpose("analytics"),
        )
        .unwrap();
    assert!(
        analytics.hits.is_empty(),
        "support-only memory is invisible to analytics"
    );

    let support = vault
        .recall::<Sensitive>(
            &space,
            &read,
            RecallQuery::all(),
            &RequestContext::default().with_purpose("support"),
        )
        .unwrap();
    assert_eq!(support.hits.len(), 1);
}

#[test]
fn semantic_recall_ranks_through_the_label_gate() {
    use crate::index::KeywordIndex;
    use std::sync::Arc;

    let space = MemorySpace::new("user:alice", "semantic");
    let vault = MemoryVault::new(InMemoryStore::new()).with_index(Arc::new(KeywordIndex::new()));
    let write: Capability<CanWrite, _> = cap("agent:keeper", &space);
    let read: Capability<CanRead, _> = cap("agent:keeper", &space);
    let delete: Capability<CanDelete, _> = cap("agent:keeper", &space);

    vault
        .remember(
            &space,
            &write,
            draft("Alice lives in Venice", Provenance::Operator),
        )
        .unwrap();
    let secret_id = vault
        .remember(
            &space,
            &write,
            draft("Venice safehouse address", Provenance::Operator).with_label(Label::Sensitive),
        )
        .unwrap();
    vault
        .remember(&space, &write, draft("Bob likes tea", Provenance::Operator))
        .unwrap();

    // Internal ceiling: the Venice match is a hit, the Sensitive one is
    // redacted, and the unrelated record isn't ranked at all.
    let (hits, redacted) = vault
        .recall_semantic(
            &space,
            &read,
            "venice",
            10,
            Label::Internal,
            &RequestContext::default(),
        )
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].content.text, "Alice lives in Venice");
    assert_eq!(redacted.len(), 1);
    assert_eq!(redacted[0].id, secret_id);

    // Forget prunes the index: the sensitive record stops ranking entirely.
    vault
        .forget(&space, &delete, ForgetSelector::Ids(vec![secret_id]))
        .unwrap();
    let (_, redacted) = vault
        .recall_semantic(
            &space,
            &read,
            "venice",
            10,
            Label::Internal,
            &RequestContext::default(),
        )
        .unwrap();
    assert!(redacted.is_empty(), "forgotten record no longer surfaces");

    // Without an index attached, semantic recall is Unsupported.
    let bare = MemoryVault::new(InMemoryStore::new());
    let err = bare
        .recall_semantic(
            &space,
            &read,
            "venice",
            10,
            Label::Internal,
            &RequestContext::default(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        MemoryError::Store(crate::store::StoreError::Unsupported)
    ));
}

#[test]
fn consolidation_batches_all_writes_atomically() {
    // A custom store that counts apply_batch calls proves consolidation
    // emits a *single* batch rather than interleaved put/invalidate calls.
    use crate::store::{StoreBatchOp, StoreError, StoreQuery};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingStore {
        inner: InMemoryStore,
        batches: AtomicUsize,
    }
    impl MemoryStore for CountingStore {
        fn put(&self, r: StoredRecord) -> Result<(), StoreError> {
            self.inner.put(r)
        }
        fn get(&self, id: &MemoryId) -> Result<Option<StoredRecord>, StoreError> {
            self.inner.get(id)
        }
        fn query(&self, q: &StoreQuery) -> Result<Vec<StoredRecord>, StoreError> {
            self.inner.query(q)
        }
        fn invalidate(
            &self,
            id: &MemoryId,
            at: chrono::DateTime<chrono::Utc>,
        ) -> Result<(), StoreError> {
            self.inner.invalidate(id, at)
        }
        fn tombstone(&self, id: &MemoryId) -> Result<bool, StoreError> {
            self.inner.tombstone(id)
        }
        fn apply_batch(&self, ops: Vec<StoreBatchOp>) -> Result<(), StoreError> {
            self.batches.fetch_add(1, Ordering::Relaxed);
            for op in ops {
                match op {
                    StoreBatchOp::Put(r) => self.inner.put(*r)?,
                    StoreBatchOp::Invalidate { id, at } => self.inner.invalidate(&id, at)?,
                }
            }
            Ok(())
        }
    }

    let space = MemorySpace::new("user:alice", "semantic");
    let store = CountingStore {
        inner: InMemoryStore::new(),
        batches: AtomicUsize::new(0),
    };
    let vault = MemoryVault::new(store);
    let write: Capability<CanWrite, _> = cap("agent:keeper", &space);
    let read: Capability<CanRead, _> = cap("agent:keeper", &space);

    let a = vault
        .remember(
            &space,
            &write,
            draft("likes coffee", Provenance::Operator).with_label(Label::Public),
        )
        .unwrap();
    let b = vault
        .remember(
            &space,
            &write,
            draft("medical note", Provenance::Operator).with_label(Label::Sensitive),
        )
        .unwrap();

    let plan = ConsolidationPlan::new().then(ConsolidationStep::Supersede {
        superseded: vec![a, b],
        replacement: draft("health summary", Provenance::Operator).with_label(Label::Public),
    });
    let report = vault.consolidate(&space, &write, plan).unwrap();
    assert_eq!(report.invalidated.len(), 2);
    assert_eq!(report.created.len(), 1);
    assert_eq!(
        vault.store().batches.load(Ordering::Relaxed),
        1,
        "one atomic batch, not 3 store calls"
    );

    // The summary was raised to Sensitive by the join — hidden at Public.
    let public = vault
        .recall::<Public>(
            &space,
            &read,
            RecallQuery::all(),
            &RequestContext::default(),
        )
        .unwrap();
    assert!(public.hits.is_empty());
    assert_eq!(public.redacted.len(), 1);
}
