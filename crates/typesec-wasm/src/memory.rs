//! `WasmMemoryVault`: session-scoped, capability-secured memory for JS/TS
//! agents — the browser/edge twin of Python's `MemoryGate`.
//!
//! Same shape as the other wasm types: `_impl` methods return
//! `Result<_, String>` (host-testable; constructing a `JsError` panics off
//! wasm) and thin `#[wasm_bindgen]` wrappers convert at the edge.

use std::sync::Arc;

use serde_json::{Value, json};
use typesec_agent::interop::ToolCallRequest;
use typesec_core::policy::PolicyEngine;
use typesec_memory::agent::{MemoryToolRouter, TOOL_FORGET, TOOL_RECALL, TOOL_REMEMBER};
use typesec_memory::{InMemoryStore, MemoryVault};
use wasm_bindgen::prelude::*;

use crate::{compile, js_err, request_context};

/// Capability-secured memory over an in-process vault (rbac | odrl policy).
#[wasm_bindgen]
pub struct WasmMemoryVault {
    router: MemoryToolRouter<InMemoryStore>,
}

impl WasmMemoryVault {
    fn new_impl(policy_yaml: &str, format: &str) -> Result<Self, String> {
        let engine: Arc<dyn PolicyEngine> = compile(policy_yaml, format)?;
        Ok(Self {
            router: MemoryToolRouter::new(MemoryVault::new(InMemoryStore::new()), engine),
        })
    }

    fn call_impl(&self, subject: &str, tool: &str, args: Value) -> Result<String, String> {
        self.router
            .handle(
                subject,
                &ToolCallRequest::new(tool, args),
                &request_context(None),
            )
            .map(|result| result.to_string())
            .map_err(|err| err.to_string())
    }
}

#[wasm_bindgen]
impl WasmMemoryVault {
    /// Compile a policy (`format` ∈ `rbac` | `odrl`) over an empty vault.
    #[wasm_bindgen(constructor)]
    pub fn new(policy_yaml: &str, format: &str) -> Result<WasmMemoryVault, JsError> {
        Self::new_impl(policy_yaml, format).map_err(js_err)
    }

    /// Remember `text` in `space` (a `memory/<owner>/<space>` id) as
    /// `subject`. Returns `{"id": ...}` JSON.
    pub fn remember(
        &self,
        subject: &str,
        space: &str,
        text: &str,
        kind: Option<String>,
    ) -> Result<String, JsError> {
        let mut args = json!({"space": space, "text": text});
        if let Some(kind) = kind {
            args["kind"] = json!(kind);
        }
        self.call_impl(subject, TOOL_REMEMBER, args).map_err(js_err)
    }

    /// Recall from `space` at a clearance ceiling (default `internal`;
    /// unknown names fail closed to `secret`). Returns
    /// `{"hits": [...], "redacted": [...]}` JSON.
    pub fn recall(
        &self,
        subject: &str,
        space: &str,
        query: Option<String>,
        clearance: Option<String>,
    ) -> Result<String, JsError> {
        let mut args = json!({"space": space});
        if let Some(query) = query {
            args["query"] = json!(query);
        }
        if let Some(clearance) = clearance {
            args["clearance"] = json!(clearance);
        }
        self.call_impl(subject, TOOL_RECALL, args).map_err(js_err)
    }

    /// Forget records by id. Returns `{"forgotten": [...]}` JSON.
    pub fn forget(&self, subject: &str, space: &str, ids: Vec<String>) -> Result<String, JsError> {
        self.call_impl(subject, TOOL_FORGET, json!({"space": space, "ids": ids}))
            .map_err(js_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
roles:
  - name: keeper
    permissions: [read, write, delete]
    resources: ["memory/**"]
assignments:
  - subject: "agent:js"
    roles: [keeper]
"#;

    #[test]
    fn wasm_memory_vault_roundtrips_and_gates() {
        let vault = WasmMemoryVault::new_impl(POLICY, "rbac").expect("vault builds");

        let stored: Value = serde_json::from_str(
            &vault
                .call_impl(
                    "agent:js",
                    TOOL_REMEMBER,
                    json!({"space": "memory/user:alice/profile", "text": "likes wasm"}),
                )
                .unwrap(),
        )
        .unwrap();
        let id = stored["id"].as_str().unwrap().to_string();

        let recall: Value = serde_json::from_str(
            &vault
                .call_impl(
                    "agent:js",
                    TOOL_RECALL,
                    json!({"space": "memory/user:alice/profile"}),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(recall["hits"][0]["text"], "likes wasm");

        // Public ceiling redacts the Internal record.
        let public: Value = serde_json::from_str(
            &vault
                .call_impl(
                    "agent:js",
                    TOOL_RECALL,
                    json!({"space": "memory/user:alice/profile", "clearance": "public"}),
                )
                .unwrap(),
        )
        .unwrap();
        assert!(public["hits"].as_array().unwrap().is_empty());
        assert_eq!(public["redacted"].as_array().unwrap().len(), 1);

        // A stranger is denied by the mint path.
        let denied = vault.call_impl(
            "agent:stranger",
            TOOL_RECALL,
            json!({"space": "memory/user:alice/profile"}),
        );
        assert!(denied.is_err());

        let forgotten: Value = serde_json::from_str(
            &vault
                .call_impl(
                    "agent:js",
                    TOOL_FORGET,
                    json!({"space": "memory/user:alice/profile", "ids": [id]}),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(forgotten["forgotten"].as_array().unwrap().len(), 1);
    }
}
