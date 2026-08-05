use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use chrono::{Duration, Utc};
use typesec_core::policy::{MintOptions, RequestContext, mint_capability_for_id};
use typesec_core::{CanRead, CanReadSensitive, CanWrite, Capability};
use typesec_memory::store::{MemoryStore, StoreError, StoreQuery};
use typesec_memory::{
    EntityRef, InMemoryStore, KeywordIndex, Label, MemoryContent, MemoryDraft, MemoryError,
    MemoryId, MemoryKind, MemorySpace, MemoryVault, Provenance, RecallQuery, Resource,
    StoredRecord,
};

const POLICY: &str = r#"
roles:
  - name: reader
    permissions: [read, read_sensitive, write]
    resources: ["memory/**"]
assignments:
  - subject: "agent:reader"
    roles: [reader]
"#;

fn capability<P: typesec_core::Permission>(space: &MemorySpace) -> Capability<P, MemorySpace> {
    let engine = typesec_rbac::RbacEngine::from_yaml(POLICY).unwrap();
    mint_capability_for_id(
        &engine,
        "agent:reader",
        space.resource_id(),
        &MintOptions::default(),
    )
    .unwrap()
}

struct Seed {
    support: MemoryId,
    expired: MemoryId,
}

fn seed<S: MemoryStore>(vault: &MemoryVault<S>, space: &MemorySpace) -> Seed {
    let write: Capability<CanWrite, _> = capability(space);
    let now = Utc::now();
    let draft = |text, provenance| {
        MemoryDraft::new(MemoryKind::Semantic, MemoryContent::text(text), provenance)
            .with_entities([EntityRef::new("shared", "test")])
    };

    vault
        .remember(space, &write, draft("shared live", Provenance::Operator))
        .unwrap();
    let support = vault
        .remember(
            space,
            &write,
            draft("shared support", Provenance::Operator).for_purposes(["support"]),
        )
        .unwrap();
    vault
        .remember(
            space,
            &write,
            draft("shared future", Provenance::Operator).valid_from(now + Duration::days(1)),
        )
        .unwrap();
    let expired = vault
        .remember(
            space,
            &write,
            draft("shared expired", Provenance::Operator).expires_at(now - Duration::days(1)),
        )
        .unwrap();
    vault
        .remember(
            space,
            &write,
            draft("shared quarantined", Provenance::ModelText),
        )
        .unwrap();
    Seed { support, expired }
}

fn texts(memories: &[typesec_memory::RecalledMemory]) -> Vec<&str> {
    let mut values: Vec<_> = memories
        .iter()
        .map(|memory| memory.content.text.as_str())
        .collect();
    values.sort_unstable();
    values
}

#[test]
fn ordinary_recall_applies_visibility_before_the_result_limit() {
    let space = MemorySpace::new("tenant:one", "ordinary");
    let vault = MemoryVault::new(InMemoryStore::new());
    seed(&vault, &space);
    let read: Capability<CanRead, _> = capability(&space);

    let (hits, _) = vault
        .recall_at(
            &space,
            &read,
            RecallQuery {
                limit: Some(1),
                ..RecallQuery::all()
            },
            &RequestContext::new(),
            Label::Sensitive,
        )
        .unwrap();
    assert_eq!(texts(&hits), ["shared live"]);

    let (hits, _) = vault
        .recall_at(
            &space,
            &read,
            RecallQuery::all(),
            &RequestContext::new().with_purpose("support"),
            Label::Sensitive,
        )
        .unwrap();
    assert_eq!(texts(&hits), ["shared live", "shared support"]);
}

#[derive(Default)]
struct NeighborhoodStore {
    inner: InMemoryStore,
    ids: Mutex<Vec<MemoryId>>,
    fail_reads: AtomicBool,
}

impl MemoryStore for NeighborhoodStore {
    fn put(&self, record: StoredRecord) -> Result<(), StoreError> {
        self.ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(record.id.clone());
        self.inner.put(record)
    }

    fn get(&self, id: &MemoryId) -> Result<Option<StoredRecord>, StoreError> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err(StoreError::Backend("read unavailable".to_owned()));
        }
        self.inner.get(id)
    }

    fn query(&self, query: &StoreQuery) -> Result<Vec<StoredRecord>, StoreError> {
        self.inner.query(query)
    }

    fn invalidate(&self, id: &MemoryId, at: chrono::DateTime<Utc>) -> Result<(), StoreError> {
        self.inner.invalidate(id, at)
    }

    fn tombstone(&self, id: &MemoryId) -> Result<bool, StoreError> {
        self.inner.tombstone(id)
    }

    fn neighborhood(&self, _entity: &str, _hops: u8) -> Result<Vec<MemoryId>, StoreError> {
        Ok(self
            .ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone())
    }
}

#[test]
fn graph_and_semantic_reads_share_the_same_visibility_gate() {
    let graph_space = MemorySpace::new("tenant:one", "graph");
    let graph = MemoryVault::new(NeighborhoodStore::default());
    seed(&graph, &graph_space);
    let graph_read: Capability<CanRead, _> = capability(&graph_space);
    let context = RequestContext::new().with_purpose("support");
    let (hits, _) = graph
        .recall_neighborhood(
            &graph_space,
            &graph_read,
            "shared",
            1,
            Label::Sensitive,
            &context,
        )
        .unwrap();
    assert_eq!(texts(&hits), ["shared live", "shared support"]);

    graph.store().fail_reads.store(true, Ordering::SeqCst);
    assert!(matches!(
        graph.recall_neighborhood(
            &graph_space,
            &graph_read,
            "shared",
            1,
            Label::Sensitive,
            &context,
        ),
        Err(MemoryError::Store(StoreError::Backend(message)))
            if message == "read unavailable"
    ));

    let semantic_space = MemorySpace::new("tenant:one", "semantic");
    let semantic =
        MemoryVault::new(InMemoryStore::new()).with_index(std::sync::Arc::new(KeywordIndex::new()));
    seed(&semantic, &semantic_space);
    let semantic_read: Capability<CanRead, _> = capability(&semantic_space);
    let (hits, _) = semantic
        .recall_semantic(
            &semantic_space,
            &semantic_read,
            "shared",
            10,
            Label::Sensitive,
            &context,
        )
        .unwrap();
    assert_eq!(texts(&hits), ["shared live", "shared support"]);
}

#[test]
fn direct_reveal_rechecks_purpose_and_retention() {
    let space = MemorySpace::new("tenant:one", "reveal");
    let vault = MemoryVault::new(InMemoryStore::new());
    let seed = seed(&vault, &space);
    let reveal: Capability<CanReadSensitive, _> = capability(&space);

    assert!(matches!(
        vault.reveal(&space, &reveal, &seed.support, &RequestContext::new()),
        Err(MemoryError::NotFound(_))
    ));
    assert!(matches!(
        vault.reveal(
            &space,
            &reveal,
            &seed.support,
            &RequestContext::new().with_purpose("  "),
        ),
        Err(MemoryError::NotFound(_))
    ));
    assert_eq!(
        vault
            .reveal(
                &space,
                &reveal,
                &seed.support,
                &RequestContext::new().with_purpose("support"),
            )
            .unwrap()
            .text,
        "shared support"
    );
    assert!(matches!(
        vault.reveal(
            &space,
            &reveal,
            &seed.expired,
            &RequestContext::new().with_purpose("support"),
        ),
        Err(MemoryError::NotFound(_))
    ));
}
