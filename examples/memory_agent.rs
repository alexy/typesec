//! Memory as guarded tool calls — the Marciana agent surface.
//!
//! An LLM's `memory.remember` / `memory.recall` tool calls flow through the
//! same deny-by-default guard as every other tool. This demo (no LLM needed)
//! shows: a keeper agent remembers and recalls; a reader agent is denied a
//! write and an out-of-scope read by the guard *before* any vault op runs;
//! and clearance ceilings redact hotter memories.
//!
//! Run: `cargo run -p typesec-cli --example memory_agent` (or from the repo,
//! `cargo run --example memory_agent --features …` — see Cargo wiring).

use std::sync::Arc;

use serde_json::json;
use typesec_agent::interop::{ToolCallGuard, ToolCallRequest};
use typesec_core::policy::{RequestContext, SubjectId};
use typesec_memory::agent::{MemoryToolRouter, TOOL_RECALL, TOOL_REMEMBER, memory_bindings};
use typesec_memory::{InMemoryStore, MemoryVault};

const POLICY: &str = r#"
roles:
  - name: keeper
    permissions: [read, write, delete]
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

fn main() {
    let engine: Arc<dyn typesec_core::policy::PolicyEngine> =
        Arc::new(typesec_rbac::RbacEngine::from_yaml(POLICY).unwrap());
    let ctx = RequestContext::default();

    // 1. The guard: memory is just another set of tools.
    let mut guard = ToolCallGuard::new(engine.clone());
    for binding in memory_bindings() {
        guard = guard.bind(binding);
    }

    let reader = SubjectId::from("agent:reader");
    let write_call = ToolCallRequest::new(
        TOOL_REMEMBER,
        json!({"space": "memory/user:alice/profile", "text": "secret"}),
    );
    let verdict = guard.check(&reader, write_call, &ctx);
    println!(
        "reader tries to remember → {}",
        if verdict.verdict.is_allowed() { "ALLOWED" } else { "DENIED (guard)" }
    );

    // 2. The router: execute authorized calls against a vault.
    let router = MemoryToolRouter::new(MemoryVault::new(InMemoryStore::new()), engine);

    let id = router
        .handle(
            "agent:keeper",
            &ToolCallRequest::new(
                TOOL_REMEMBER,
                json!({"space": "memory/user:alice/profile", "text": "Alice prefers espresso", "kind": "profile"}),
            ),
            &ctx,
        )
        .unwrap();
    println!("keeper remembered → {id}");

    let recalled = router
        .handle(
            "agent:keeper",
            &ToolCallRequest::new(
                TOOL_RECALL,
                json!({"space": "memory/user:alice/profile", "clearance": "internal"}),
            ),
            &ctx,
        )
        .unwrap();
    println!("keeper recalls (internal) → {}", recalled["hits"]);

    let public = router
        .handle(
            "agent:keeper",
            &ToolCallRequest::new(
                TOOL_RECALL,
                json!({"space": "memory/user:alice/profile", "clearance": "public"}),
            ),
            &ctx,
        )
        .unwrap();
    println!(
        "keeper recalls (public) → {} hit(s), {} redacted",
        public["hits"].as_array().unwrap().len(),
        public["redacted"].as_array().unwrap().len(),
    );
}
