//! OpenAI Chat Completions dialect: `tool_calls` in, `role: "tool"` denial
//! messages out. Works with the OpenAI SDKs and any OpenAI-compatible server.

use serde_json::{Value, json};

use super::call::{GuardedToolCall, InteropError, ToolCallRequest};
use super::wire;

/// Dialect name used in error messages and the Python bindings.
pub const DIALECT: &str = "openai";

/// Parse tool calls from any of the shapes the OpenAI API surfaces them in:
/// a full chat completion (`choices[*].message.tool_calls`), an assistant
/// message (`{"tool_calls": [...]}`), or the bare `tool_calls` array.
pub fn parse_tool_calls(payload: &Value) -> Result<Vec<ToolCallRequest>, InteropError> {
    if let Some(choices) = payload.get("choices").and_then(Value::as_array) {
        let mut calls = Vec::new();
        for choice in choices {
            if let Some(items) = choice
                .pointer("/message/tool_calls")
                .and_then(Value::as_array)
            {
                for item in items {
                    calls.push(parse_call(item)?);
                }
            }
        }
        return Ok(calls);
    }
    wire::call_array(payload, "tool_calls", DIALECT)?
        .iter()
        .map(parse_call)
        .collect()
}

fn parse_call(item: &Value) -> Result<ToolCallRequest, InteropError> {
    let function = item.get("function").ok_or_else(|| {
        InteropError::malformed(DIALECT, "tool call entry has no 'function' object")
    })?;
    let name = wire::required_str(function, "name", DIALECT)?;
    let arguments = wire::parse_arguments(function.get("arguments"), DIALECT, name)?;
    let mut request = ToolCallRequest::new(name, arguments);
    if let Some(id) = wire::optional_str(item, "id") {
        request = request.with_call_id(id);
    }
    Ok(request)
}

/// Filter a request's `tools` array down to the definitions `keep` accepts.
/// Handles both the Chat Completions shape (`{"type": "function",
/// "function": {"name": ...}}`) and the Responses API shape
/// (`{"type": "function", "name": ...}`). Unidentifiable entries are dropped.
pub fn filter_tools(tools: &Value, keep: &dyn Fn(&str) -> bool) -> Value {
    wire::filter_tool_array(
        tools,
        |item| {
            item.pointer("/function/name")
                .or_else(|| item.get("name"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        },
        keep,
    )
}

/// Render a denied/undecided call as the `role: "tool"` message the chat
/// history expects, so the model receives the refusal as tool output.
/// Returns `None` for allowed calls.
pub fn denial(call: &GuardedToolCall) -> Option<Value> {
    call.denial_message().map(|content| {
        json!({
            "role": "tool",
            "tool_call_id": call.request.call_id.clone().unwrap_or_default(),
            "content": content,
        })
    })
}
