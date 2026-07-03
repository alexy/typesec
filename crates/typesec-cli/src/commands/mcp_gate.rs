//! `typesec mcp-gate` — a deny-by-default MCP stdio proxy.
//!
//! Fronts any MCP server: JSON-RPC traffic flows through untouched except
//! `tools/call`, which is checked against a Typesec policy first. Denied
//! calls never reach the server — the gate answers them itself with an
//! `isError` tool result. With `--filter-list`, `tools/list` responses are
//! also filtered to bound tools, so the model never sees what it may not
//! call.
//!
//! ```text
//! MCP client ⇄ typesec mcp-gate (policy + tool bindings) ⇄ MCP server
//! ```

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use typesec_agent::interop::{ToolBinding, ToolCallGuard, mcp};
use typesec_core::policy::{RequestContext, SubjectId};

use super::engine::{detect_format, load_engine, request_context};

/// CLI arguments for `typesec mcp-gate`.
#[derive(Args)]
pub struct McpGateArgs {
    /// Policy file (RBAC, ODRL, or graph YAML).
    #[arg(long)]
    policy: PathBuf,
    /// Policy format override: rbac | odrl | graph.
    #[arg(long)]
    format: Option<String>,
    /// Subject the gated server acts as, e.g. "agent:mcp-files".
    #[arg(long)]
    subject: String,
    /// Tool bindings YAML (`tools:` list mapping tool → action/resource).
    #[arg(long)]
    bindings: PathBuf,
    /// Purpose attached to every policy check (for ODRL constraints).
    #[arg(long)]
    purpose: Option<String>,
    /// Also filter `tools/list` responses down to bound tools.
    #[arg(long)]
    filter_list: bool,
    /// The MCP server command to front (everything after `--`).
    #[arg(last = true, required = true)]
    server: Vec<String>,
}

/// One entry in the bindings YAML.
#[derive(Debug, Deserialize)]
struct BindingSpec {
    tool: String,
    action: String,
    resource: String,
    #[serde(default)]
    resource_arg: Option<String>,
    #[serde(default)]
    required_args: Vec<String>,
    #[serde(default)]
    arg_globs: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct BindingsFile {
    tools: Vec<BindingSpec>,
}

fn build_guard(
    engine: std::sync::Arc<dyn typesec_core::policy::PolicyEngine>,
    file: BindingsFile,
) -> Result<(ToolCallGuard, HashSet<String>)> {
    let mut guard = ToolCallGuard::new(engine);
    let mut names = HashSet::new();
    for spec in file.tools {
        names.insert(spec.tool.clone());
        let mut binding = ToolBinding::new(spec.tool, spec.action, spec.resource);
        if let Some(arg) = spec.resource_arg {
            binding = binding.resource_from_arg(arg);
        }
        binding = binding.require_args(spec.required_args);
        for (arg, pattern) in spec.arg_globs {
            binding = binding.arg_glob(arg, &pattern).map_err(|e| anyhow!(e))?;
        }
        guard = guard.bind(binding);
    }
    Ok((guard, names))
}

/// What to do with one line received from the MCP client.
enum ClientAction {
    /// Forward the line to the server unchanged.
    Forward,
    /// Do not forward; send this response back to the client instead.
    Respond(String),
}

/// The pure message-handling core of the proxy (no IO, unit-tested).
struct Gate {
    guard: ToolCallGuard,
    subject: SubjectId,
    ctx: RequestContext,
    bound_tools: HashSet<String>,
    filter_list: bool,
    /// JSON-RPC ids of in-flight `tools/list` requests (string-normalized).
    pending_list_ids: Mutex<HashSet<String>>,
}

fn id_key(id: &serde_json::Value) -> String {
    match id {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

impl Gate {
    fn on_client_line(&self, line: &str) -> ClientAction {
        let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
            // Not JSON we understand — let the server reject it.
            return ClientAction::Forward;
        };
        if self.filter_list
            && message.get("method").and_then(serde_json::Value::as_str) == Some("tools/list")
            && let Some(id) = message.get("id")
        {
            self.pending_list_ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(id_key(id));
            return ClientAction::Forward;
        }
        if !mcp::is_tools_call(&message) {
            return ClientAction::Forward;
        }
        let id = message
            .get("id")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let calls = match mcp::parse_tool_calls(&message) {
            Ok(calls) => calls,
            Err(err) => {
                // Fail closed: a tools/call we cannot parse never reaches the
                // server.
                return ClientAction::Respond(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{"type": "text",
                                         "text": format!("typesec mcp-gate rejected the call: {err}")}],
                            "isError": true,
                        },
                    })
                    .to_string(),
                );
            }
        };
        for request in calls {
            let call = self.guard.check(&self.subject, request, &self.ctx);
            if let Some(denial) = mcp::denial_with_id(&call, id.clone()) {
                return ClientAction::Respond(denial.to_string());
            }
        }
        ClientAction::Forward
    }

    fn on_server_line(&self, line: &str) -> String {
        if !self.filter_list {
            return line.to_string();
        }
        let Ok(mut message) = serde_json::from_str::<serde_json::Value>(line) else {
            return line.to_string();
        };
        let Some(id) = message.get("id").map(id_key) else {
            return line.to_string();
        };
        {
            let mut pending = self
                .pending_list_ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !pending.remove(&id) {
                return line.to_string();
            }
        }
        if let Some(tools) = message
            .pointer_mut("/result/tools")
            .and_then(serde_json::Value::as_array_mut)
        {
            tools.retain(|tool| {
                tool.get("name")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|name| self.bound_tools.contains(name))
            });
        }
        message.to_string()
    }
}

/// Run the stdio proxy until the client or server hangs up.
pub async fn run(args: McpGateArgs) -> Result<()> {
    let policy_yaml = std::fs::read_to_string(&args.policy)
        .with_context(|| format!("failed to read policy {}", args.policy.display()))?;
    let format = detect_format(&args.format, &policy_yaml);
    let engine = load_engine(format.as_deref(), &policy_yaml)?;
    let bindings_yaml = std::fs::read_to_string(&args.bindings)
        .with_context(|| format!("failed to read bindings {}", args.bindings.display()))?;
    let bindings: BindingsFile =
        serde_yaml::from_str(&bindings_yaml).context("failed to parse bindings YAML")?;
    let (guard, bound_tools) = build_guard(engine, bindings)?;

    let gate = std::sync::Arc::new(Gate {
        guard,
        subject: SubjectId::from(args.subject.as_str()),
        ctx: request_context(args.purpose.as_deref()),
        bound_tools,
        filter_list: args.filter_list,
        pending_list_ids: Mutex::new(HashSet::new()),
    });

    let (server_cmd, server_args) = args
        .server
        .split_first()
        .ok_or_else(|| anyhow!("no MCP server command given after --"))?;
    let mut child = tokio::process::Command::new(server_cmd)
        .args(server_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start MCP server '{server_cmd}'"))?;
    let mut child_stdin = child.stdin.take().expect("child stdin is piped");
    let child_stdout = child.stdout.take().expect("child stdout is piped");

    // One writer owns our stdout so client-bound denials and server output
    // never interleave mid-line.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<String>(64);
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(line) = out_rx.recv().await {
            if stdout.write_all(line.as_bytes()).await.is_err()
                || stdout.write_all(b"\n").await.is_err()
            {
                break;
            }
            let _ = stdout.flush().await;
        }
    });

    let gate_in = gate.clone();
    let tx_in = out_tx.clone();
    let client_task = tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            match gate_in.on_client_line(&line) {
                ClientAction::Forward => {
                    if child_stdin.write_all(line.as_bytes()).await.is_err()
                        || child_stdin.write_all(b"\n").await.is_err()
                    {
                        break;
                    }
                    let _ = child_stdin.flush().await;
                }
                ClientAction::Respond(response) => {
                    if tx_in.send(response).await.is_err() {
                        break;
                    }
                }
            }
        }
        // Client hung up: closing child stdin lets the server exit cleanly.
        drop(child_stdin);
    });

    let server_task = tokio::spawn(async move {
        let mut lines = BufReader::new(child_stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if out_tx.send(gate.on_server_line(&line)).await.is_err() {
                break;
            }
        }
    });

    let status = child.wait().await?;
    let _ = tokio::join!(client_task, server_task, writer);
    if !status.success() {
        bail!("MCP server exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
