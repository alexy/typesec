//! Anthropic Messages dialect: `tool_use` content blocks in, `tool_result`
//! blocks with `is_error: true` out.

use serde_json::{Value, json};

use super::call::{GuardedToolCall, InteropError, ToolCallRequest};
use super::wire;

/// Dialect name used in error messages and the Python bindings.
pub const DIALECT: &str = "anthropic";

/// Parse `tool_use` blocks from an Anthropic message (`{"content": [...]}`)
/// or a bare content-block array. Non-`tool_use` blocks (text, thinking) are
/// skipped.
pub fn parse_tool_calls(payload: &Value) -> Result<Vec<ToolCallRequest>, InteropError> {
    wire::call_array(payload, "content", DIALECT)?
        .iter()
        .filter(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
        .map(parse_block)
        .collect()
}

fn parse_block(block: &Value) -> Result<ToolCallRequest, InteropError> {
    let name = wire::required_str(block, "name", DIALECT)?;
    let arguments = wire::parse_arguments(block.get("input"), DIALECT, name)?;
    let mut request = ToolCallRequest::new(name, arguments);
    if let Some(id) = wire::optional_str(block, "id") {
        request = request.with_call_id(id);
    }
    Ok(request)
}

/// Render a denied/undecided call as the `tool_result` content block the
/// follow-up user message expects, flagged `is_error` so the model treats it
/// as a failure. Returns `None` for allowed calls.
pub fn denial(call: &GuardedToolCall) -> Option<Value> {
    call.denial_message().map(|content| {
        json!({
            "type": "tool_result",
            "tool_use_id": call.request.call_id.clone().unwrap_or_default(),
            "content": content,
            "is_error": true,
        })
    })
}
