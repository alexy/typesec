//! `GrustMemoryStore` (`graph-memory` feature): records plus a Grust-backed
//! entity knowledge graph.
//!
//! Record CRUD lives in an indexed map (reliable, incremental); the
//! *relationships* — which record mentions which entity, and how entities
//! relate — are projected into a Grust [`Graph`](grust::prelude::Graph) so
//! memory recall can traverse the knowledge graph:
//!
//! ```text
//! (:Record {id, label, valid_from, invalid_at})-[:MENTIONS]->(:Entity {name, kind})
//! (:Entity)-[:REL {fact_id, valid_from, invalid_at}]->(:Entity)
//! ```
//!
//! [`neighborhood`](MemoryStore::neighborhood) answers "which records touch an
//! entity, or its graph neighbors within N hops?" via BFS over that graph,
//! honoring the bi-temporal edge window. The vault then runs every returned id
//! back through its label gate — the graph returns ids, the vault returns
//! content, so the store is never an authorization bypass.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{PoisonError, RwLock};

use chrono::{DateTime, Utc};
use grust::prelude::{Graph, Node, NodeId, Value};

use super::{MemoryStore, StoreError, StoreQuery};
use crate::record::StoredRecord;
use crate::space::MemoryId;

const RECORD_LABEL: &str = "Record";
const ENTITY_LABEL: &str = "Entity";
const MENTIONS: &str = "MENTIONS";
const RELATES: &str = "RELATES";

/// A memory store backed by an in-process record index and a Grust entity
/// graph for neighborhood recall.
#[derive(Default)]
pub struct GrustMemoryStore {
    inner: RwLock<Inner>,
}

#[derive(Default)]
struct Inner {
    records: HashMap<MemoryId, StoredRecord>,
    /// Directed entity→entity relationships: (from, rel, to, fact_id).
    relations: Vec<(String, String, String, MemoryId)>,
}

impl GrustMemoryStore {
    /// Create an empty graph store.
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Project the current records and relations into a Grust graph. Rebuilt
    /// on demand for traversal — records are the source of truth.
    fn build_graph(inner: &Inner) -> Graph {
        let mut nodes: Vec<Node> = Vec::new();
        let mut edges = Vec::new();
        let mut entity_ids: HashSet<String> = HashSet::new();

        for record in inner.records.values() {
            let rid = record_node_id(&record.id);
            let mut props: BTreeMap<String, Value> = BTreeMap::new();
            props.insert("id".into(), Value::String(record.id.as_str().to_string()));
            props.insert(
                "label".into(),
                Value::String(record.label.name().to_string()),
            );
            props.insert(
                "valid_from".into(),
                Value::String(record.valid_from.to_rfc3339()),
            );
            if let Some(end) = record.invalid_at {
                props.insert("invalid_at".into(), Value::String(end.to_rfc3339()));
            }
            nodes.push(Node::new(RECORD_LABEL, rid.clone(), props));

            for entity in &record.entities {
                if entity_ids.insert(entity.name.clone()) {
                    let mut ep: BTreeMap<String, Value> = BTreeMap::new();
                    ep.insert("name".into(), Value::String(entity.name.clone()));
                    ep.insert("kind".into(), Value::String(entity.kind.clone()));
                    nodes.push(Node::new(ENTITY_LABEL, entity_node_id(&entity.name), ep));
                }
                edges.push(grust::prelude::Edge::new(
                    MENTIONS,
                    rid.clone(),
                    entity_node_id(&entity.name),
                    BTreeMap::new(),
                ));
            }
        }

        for (from, rel, to, fact) in &inner.relations {
            for name in [from, to] {
                if entity_ids.insert(name.clone()) {
                    let mut ep: BTreeMap<String, Value> = BTreeMap::new();
                    ep.insert("name".into(), Value::String(name.clone()));
                    nodes.push(Node::new(ENTITY_LABEL, entity_node_id(name), ep));
                }
            }
            let mut rp: BTreeMap<String, Value> = BTreeMap::new();
            rp.insert("rel".into(), Value::String(rel.clone()));
            rp.insert("fact_id".into(), Value::String(fact.as_str().to_string()));
            edges.push(grust::prelude::Edge::new(
                RELATES,
                entity_node_id(from),
                entity_node_id(to),
                rp,
            ));
        }

        Graph::new(nodes, edges)
    }
}

impl MemoryStore for GrustMemoryStore {
    fn put(&self, record: StoredRecord) -> Result<(), StoreError> {
        self.write().records.insert(record.id.clone(), record);
        Ok(())
    }

    fn get(&self, id: &MemoryId) -> Result<Option<StoredRecord>, StoreError> {
        Ok(self.read().records.get(id).cloned())
    }

    fn query(&self, query: &StoreQuery) -> Result<Vec<StoredRecord>, StoreError> {
        let inner = self.read();
        let mut matches: Vec<&StoredRecord> = inner
            .records
            .values()
            .filter(|record| query.matches(record))
            .collect();
        matches.sort_by(|a, b| b.observed_at.cmp(&a.observed_at).then(b.id.cmp(&a.id)));
        if let Some(limit) = query.limit {
            matches.truncate(limit);
        }
        Ok(matches.into_iter().cloned().collect())
    }

    fn invalidate(&self, id: &MemoryId, at: DateTime<Utc>) -> Result<(), StoreError> {
        let mut inner = self.write();
        match inner.records.get_mut(id) {
            Some(record) => {
                record.invalid_at = Some(at);
                Ok(())
            }
            None => Err(StoreError::Backend(format!("no record {id}"))),
        }
    }

    fn tombstone(&self, id: &MemoryId) -> Result<bool, StoreError> {
        let mut inner = self.write();
        let removed = inner.records.remove(id).is_some();
        inner.relations.retain(|(_, _, _, fact)| fact != id);
        Ok(removed)
    }

    fn link(&self, from: &str, rel: &str, to: &str, record: &MemoryId) -> Result<(), StoreError> {
        self.write().relations.push((
            from.to_string(),
            rel.to_string(),
            to.to_string(),
            record.clone(),
        ));
        Ok(())
    }

    fn neighborhood(&self, entity: &str, hops: u8) -> Result<Vec<MemoryId>, StoreError> {
        let inner = self.read();
        let graph = Self::build_graph(&inner);
        let start = entity_node_id(entity);

        // BFS over RELATES edges (both directions) up to `hops` to collect the
        // reachable entity set, then gather every Record that MENTIONS one.
        let mut reachable: HashSet<NodeId> = HashSet::new();
        reachable.insert(start.clone());
        let mut frontier: VecDeque<(NodeId, u8)> = VecDeque::new();
        frontier.push_back((start, 0));
        while let Some((node, depth)) = frontier.pop_front() {
            if depth >= hops {
                continue;
            }
            for edge in &graph.edges {
                if edge.label.as_str() != RELATES {
                    continue;
                }
                let next = if edge.from == node {
                    Some(edge.to.clone())
                } else if edge.to == node {
                    Some(edge.from.clone())
                } else {
                    None
                };
                if let Some(next) = next
                    && reachable.insert(next.clone())
                {
                    frontier.push_back((next, depth + 1));
                }
            }
        }

        let mut records: Vec<MemoryId> = Vec::new();
        let mut seen: HashSet<MemoryId> = HashSet::new();
        for edge in &graph.edges {
            if edge.label.as_str() == MENTIONS
                && reachable.contains(&edge.to)
                && let Some(id) = record_id_from_node(&edge.from)
                && seen.insert(id.clone())
            {
                records.push(id);
            }
        }
        Ok(records)
    }
}

fn record_node_id(id: &MemoryId) -> NodeId {
    NodeId::from(format!("rec:{}", id.as_str()).as_str())
}

fn record_id_from_node(node: &NodeId) -> Option<MemoryId> {
    node.as_str()
        .strip_prefix("rec:")
        .map(MemoryId::from_string)
}

fn entity_node_id(name: &str) -> NodeId {
    NodeId::from(format!("ent:{name}").as_str())
}

#[cfg(test)]
mod tests;
