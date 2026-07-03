//! LangChain dialect: `AIMessage.tool_calls` in, error `ToolMessage`s out.
//! The same shapes serve LangGraph nodes, which pass LangChain messages.

use serde_json::{Value, json};

use super::call::{GuardedToolCall, InteropError, ToolCallRequest};
use super::wire;

/// Dialect name used in error messages and the Python bindings.
pub const DIALECT: &str = "langchain";

/// Parse tool calls from an `AIMessage` (`{"tool_calls": [...]}`) or a bare
/// array of LangChain `ToolCall` dicts (`{"name", "args", "id"}`).
pub fn parse_tool_calls(payload: &Value) -> Result<Vec<ToolCallRequest>, InteropError> {
    wire::call_array(payload, "tool_calls", DIALECT)?
        .iter()
        .map(parse_call)
        .collect()
}

fn parse_call(item: &Value) -> Result<ToolCallRequest, InteropError> {
    let name = wire::required_str(item, "name", DIALECT)?;
    let arguments = wire::parse_arguments(item.get("args"), DIALECT, name)?;
    let mut request = ToolCallRequest::new(name, arguments);
    if let Some(id) = wire::optional_str(item, "id") {
        request = request.with_call_id(id);
    }
    Ok(request)
}

/// Filter a list of serialized tool definitions (dicts with a `name`) down
/// to the definitions `keep` accepts.
pub fn filter_tools(tools: &Value, keep: &dyn Fn(&str) -> bool) -> Value {
    wire::filter_tool_array(tools, |item| wire::optional_str(item, "name"), keep)
}

/// Render a denied/undecided call as an error `ToolMessage` dict
/// (`status: "error"`), so graphs/chains feed the refusal back to the model.
/// Returns `None` for allowed calls.
pub fn denial(call: &GuardedToolCall) -> Option<Value> {
    call.denial_message().map(|content| {
        json!({
            "type": "tool",
            "tool_call_id": call.request.call_id.clone().unwrap_or_default(),
            "content": content,
            "status": "error",
        })
    })
}
