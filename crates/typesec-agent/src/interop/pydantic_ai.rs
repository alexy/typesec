//! Pydantic AI dialect: `tool-call` message parts in, `retry-prompt` parts
//! out. Complements the capability metadata in
//! `typesec-integrations::pydantic_ai` — the metadata declares the binding,
//! this codec enforces it on the wire.

use serde_json::{Value, json};

use super::call::{GuardedToolCall, InteropError, ToolBinding, ToolCallRequest};
use super::wire;

/// Dialect name used in error messages and the Python bindings.
pub const DIALECT: &str = "pydantic-ai";

/// Metadata key a Pydantic AI tool uses to declare its required permission.
pub const METADATA_PERMISSION_KEY: &str = "typesec_required_permission";
/// Metadata key a Pydantic AI tool uses to declare its resource id.
pub const METADATA_RESOURCE_KEY: &str = "typesec_resource_id";

/// Parse `tool-call` parts from a Pydantic AI model response
/// (`{"parts": [...]}`) or a bare part array. Other parts (text, thinking)
/// are skipped.
pub fn parse_tool_calls(payload: &Value) -> Result<Vec<ToolCallRequest>, InteropError> {
    wire::call_array(payload, "parts", DIALECT)?
        .iter()
        .filter(|part| part.get("part_kind").and_then(Value::as_str) == Some("tool-call"))
        .map(parse_part)
        .collect()
}

fn parse_part(part: &Value) -> Result<ToolCallRequest, InteropError> {
    let name = wire::required_str(part, "tool_name", DIALECT)?;
    let arguments = wire::parse_arguments(part.get("args"), DIALECT, name)?;
    let mut request = ToolCallRequest::new(name, arguments);
    if let Some(id) = wire::optional_str(part, "tool_call_id") {
        request = request.with_call_id(id);
    }
    Ok(request)
}

/// Filter a list of serialized `ToolDefinition`s (dicts with a `name`) down
/// to the definitions `keep` accepts. The pure-Python
/// `typesec.adapters.pydantic_ai.prepare_tools_filter` is the live-object
/// equivalent for `Agent(prepare_tools=...)`.
pub fn filter_tools(tools: &Value, keep: &dyn Fn(&str) -> bool) -> Value {
    wire::filter_tool_array(tools, |item| wire::optional_str(item, "name"), keep)
}

/// Render a denied/undecided call as the `retry-prompt` part Pydantic AI
/// feeds back to the model. Returns `None` for allowed calls.
pub fn denial(call: &GuardedToolCall) -> Option<Value> {
    call.denial_message().map(|content| {
        json!({
            "part_kind": "retry-prompt",
            "tool_name": call.request.tool_name.clone(),
            "tool_call_id": call.request.call_id.clone().unwrap_or_default(),
            "content": content,
        })
    })
}

/// Build a [`ToolBinding`] from the Typesec metadata a Pydantic AI tool
/// carries (the `typesec_required_permission` / `typesec_resource_id` keys
/// produced by `typesec-integrations::pydantic_ai`). Returns `None` when the
/// metadata does not declare both keys.
pub fn binding_from_metadata(tool_name: &str, metadata: &Value) -> Option<ToolBinding> {
    let action = metadata.get(METADATA_PERMISSION_KEY)?.as_str()?;
    let resource = metadata.get(METADATA_RESOURCE_KEY)?.as_str()?;
    Some(ToolBinding::new(tool_name, action, resource))
}
