//! `typesec memory-serve` — capability-secured memory as an MCP server.
//!
//! Any MCP-speaking host (Claude, IDEs, agent runtimes) gets Marciana memory
//! by pointing at this stdio server. Three tools are exposed —
//! `memory.recall`, `memory.remember`, `memory.forget` — and every call runs
//! the full gauntlet: the deny-by-default [`ToolCallGuard`] first (so
//! `tools/list` filtering and denial shapes match every other typesec
//! surface), then the [`MemoryToolRouter`], which mints the capability the
//! operation needs through the policy engine. Denials come back as
//! `isError` tool results, not protocol errors.
//!
//! ```text
//! MCP host ⇄ typesec memory-serve (guard → mint → vault)   [stdio]
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use typesec_agent::interop::{ToolCallGuard, mcp};
use typesec_core::policy::{RequestContext, SubjectId};
use typesec_memory::agent::{
    MemoryToolRouter, TOOL_FORGET, TOOL_RECALL, TOOL_REMEMBER, memory_bindings,
};
use typesec_memory::{InMemoryStore, MemoryVault};

use super::engine::{detect_format, load_engine, request_context};

/// CLI arguments for `typesec memory-serve`.
#[derive(Args)]
pub struct MemoryServeArgs {
    /// Policy file (RBAC, ODRL, or graph YAML) governing memory spaces.
    #[arg(long)]
    policy: PathBuf,
    /// Policy format override: rbac | odrl | graph.
    #[arg(long)]
    format: Option<String>,
    /// Subject the connected MCP host acts as, e.g. "agent:claude".
    #[arg(long)]
    subject: String,
    /// Purpose attached to every policy check (for ODRL constraints).
    #[arg(long)]
    purpose: Option<String>,
}

/// The pure message core (no IO): one JSON-RPC request in, one response out.
struct Server {
    guard: ToolCallGuard,
    router: MemoryToolRouter<InMemoryStore>,
    subject: SubjectId,
    ctx: RequestContext,
}

impl Server {
    fn new(
        engine: Arc<dyn typesec_core::policy::PolicyEngine>,
        subject: &str,
        ctx: RequestContext,
    ) -> Self {
        let mut guard = ToolCallGuard::new(engine.clone());
        for binding in memory_bindings() {
            guard = guard.bind(binding);
        }
        Self {
            guard,
            router: MemoryToolRouter::new(MemoryVault::new(InMemoryStore::new()), engine),
            subject: SubjectId::from(subject),
            ctx,
        }
    }

    /// Handle one JSON-RPC message; `None` for notifications (no response).
    fn handle(&self, line: &str) -> Option<String> {
        let message: Value = serde_json::from_str(line).ok()?;
        let id = message.get("id").cloned();
        let method = message.get("method").and_then(Value::as_str)?;
        // Notifications (no id) get no response per JSON-RPC.
        let id = match (id, method) {
            (Some(id), _) => id,
            (None, _) => return None,
        };

        let result = match method {
            "initialize" => json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "typesec-memory-serve", "version": env!("CARGO_PKG_VERSION")},
            }),
            "tools/list" => {
                // Policy-aware listing: memory tools take their resource from
                // the call's `space` argument, so all three are listed; the
                // per-call guard remains the enforcement point.
                json!({"tools": [
                    tool_def(TOOL_RECALL, "Recall memories from a space at a clearance ceiling",
                        json!({"type": "object", "properties": {
                            "space": {"type": "string", "description": "memory/<owner>/<space>"},
                            "query": {"type": "string"},
                            "clearance": {"enum": ["public", "internal", "sensitive", "secret"]},
                        }, "required": ["space"]})),
                    tool_def(TOOL_REMEMBER, "Store a memory in a space",
                        json!({"type": "object", "properties": {
                            "space": {"type": "string"},
                            "text": {"type": "string"},
                            "kind": {"enum": ["episodic", "semantic", "procedural", "profile"]},
                        }, "required": ["space", "text"]})),
                    tool_def(TOOL_FORGET, "Destroy memories by id (audited, tombstoned)",
                        json!({"type": "object", "properties": {
                            "space": {"type": "string"},
                            "ids": {"type": "array", "items": {"type": "string"}},
                        }, "required": ["space", "ids"]})),
                ]})
            }
            "tools/call" => return Some(self.handle_tool_call(&message, id)),
            "ping" => json!({}),
            _ => {
                return Some(
                    json!({"jsonrpc": "2.0", "id": id,
                           "error": {"code": -32601, "message": format!("method '{method}' not supported")}})
                    .to_string(),
                );
            }
        };
        Some(json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string())
    }

    fn handle_tool_call(&self, message: &Value, id: Value) -> String {
        let calls = match mcp::parse_tool_calls(message) {
            Ok(calls) if !calls.is_empty() => calls,
            _ => {
                return error_result(id, "malformed tools/call request");
            }
        };
        let call = calls.into_iter().next().expect("checked non-empty");

        // Gauntlet step 1: the deny-by-default guard.
        let guarded = self.guard.check(&self.subject, call, &self.ctx);
        if let Some(denial) = mcp::denial_with_id(&guarded, id.clone()) {
            return denial.to_string();
        }

        // Gauntlet step 2: the router mints the capability and hits the vault.
        match self
            .router
            .handle(self.subject.as_str(), &guarded.request, &self.ctx)
        {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": {
                "content": [{"type": "text", "text": result.to_string()}],
            }})
            .to_string(),
            Err(err) => error_result(id, &err.to_string()),
        }
    }
}

fn tool_def(name: &str, description: &str, schema: Value) -> Value {
    json!({"name": name, "description": description, "inputSchema": schema})
}

fn error_result(id: Value, text: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "result": {
        "content": [{"type": "text", "text": format!("[typesec] {text}")}],
        "isError": true,
    }})
    .to_string()
}

/// Serve until stdin closes.
pub async fn run(args: MemoryServeArgs) -> Result<()> {
    let policy_yaml = std::fs::read_to_string(&args.policy)
        .with_context(|| format!("failed to read policy {}", args.policy.display()))?;
    let format = detect_format(&args.format, &policy_yaml);
    let engine = load_engine(format.as_deref(), &policy_yaml)?;
    let server = Server::new(
        engine,
        &args.subject,
        request_context(args.purpose.as_deref()),
    );

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(response) = server.handle(&line) {
            stdout.write_all(response.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
