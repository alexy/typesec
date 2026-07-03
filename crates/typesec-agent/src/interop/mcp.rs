//! Model Context Protocol dialect: JSON-RPC `tools/call` requests in,
//! `isError` tool results out.
//!
//! MCP is the common tool bus emerging across agent hosts (Claude, IDEs,
//! OpenAI-compatible runtimes). Guarding it guards every server behind it —
//! including tools you don't control. The `typesec mcp-gate` CLI subcommand
//! builds a full stdio proxy on this codec.

use serde_json::{Value, json};

use super::call::{GuardedToolCall, InteropError, ToolCallRequest};
use super::wire;

/// Dialect name used in error messages and the Python bindings.
pub const DIALECT: &str = "mcp";

/// Parse `tools/call` invocations from a single JSON-RPC request object or a
/// bare array of requests. Requests with other methods (initialize,
/// tools/list, notifications) yield no calls — they are not errors.
pub fn parse_tool_calls(payload: &Value) -> Result<Vec<ToolCallRequest>, InteropError> {
    let requests: &[Value] = match payload {
        Value::Array(items) => items,
        Value::Object(_) => std::slice::from_ref(payload),
        _ => {
            return Err(InteropError::malformed(
                DIALECT,
                "expected a JSON-RPC request object or an array of them",
            ));
        }
    };
    requests
        .iter()
        .filter(|request| is_tools_call(request))
        .map(parse_request)
        .collect()
}

/// `true` if this JSON-RPC message is a `tools/call` request.
pub fn is_tools_call(message: &Value) -> bool {
    message.get("method").and_then(Value::as_str) == Some("tools/call")
}

fn parse_request(request: &Value) -> Result<ToolCallRequest, InteropError> {
    let params = request
        .get("params")
        .ok_or_else(|| InteropError::malformed(DIALECT, "tools/call request has no 'params'"))?;
    let name = wire::required_str(params, "name", DIALECT)?;
    let arguments = wire::parse_arguments(params.get("arguments"), DIALECT, name)?;
    let mut call = ToolCallRequest::new(name, arguments);
    if let Some(id) = request.get("id").filter(|id| !id.is_null()) {
        // JSON-RPC ids may be numbers or strings; normalize to the string form
        // (`denial` restores numeric ids, `denial_with_id` echoes exactly).
        call = call.with_call_id(match id {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        });
    }
    Ok(call)
}

/// Render a denied/undecided call as a complete JSON-RPC *response* carrying
/// an MCP tool result with `isError: true`, so the client receives the
/// refusal as tool output. A `call_id` that parses as an integer is restored
/// to a numeric id; use [`denial_with_id`] to echo the original id exactly.
/// Returns `None` for allowed calls.
pub fn denial(call: &GuardedToolCall) -> Option<Value> {
    let id = match &call.request.call_id {
        Some(raw) => raw
            .parse::<i64>()
            .map_or_else(|_| json!(raw), |number| json!(number)),
        None => Value::Null,
    };
    denial_with_id(call, id)
}

/// Like [`denial`], but echoing the JSON-RPC `id` verbatim — the form a proxy
/// that still holds the original request should use.
pub fn denial_with_id(call: &GuardedToolCall, id: Value) -> Option<Value> {
    call.denial_message().map(|text| {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{"type": "text", "text": text}],
                "isError": true,
            },
        })
    })
}
