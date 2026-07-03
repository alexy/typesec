//! Shared JSON helpers for the dialect codecs — one home for the
//! array/argument/string parsing every framework shape needs.

use serde_json::{Map, Value};

use super::call::InteropError;

/// Accept either a bare JSON array or an object holding the array under
/// `container_key` (e.g. a whole assistant message).
pub(super) fn call_array<'a>(
    payload: &'a Value,
    container_key: &str,
    dialect: &'static str,
) -> Result<&'a [Value], InteropError> {
    if let Some(items) = payload.as_array() {
        return Ok(items);
    }
    if let Some(items) = payload.get(container_key).and_then(Value::as_array) {
        return Ok(items);
    }
    Err(InteropError::malformed(
        dialect,
        format!("expected a JSON array or an object with a '{container_key}' array"),
    ))
}

/// Parse tool arguments that frameworks send either as a JSON object or as a
/// string of encoded JSON (OpenAI's `function.arguments`). Missing/null/empty
/// arguments normalize to `{}`.
pub(super) fn parse_arguments(
    value: Option<&Value>,
    dialect: &'static str,
    tool_name: &str,
) -> Result<Value, InteropError> {
    match value {
        None | Some(Value::Null) => Ok(Value::Object(Map::new())),
        Some(Value::Object(map)) => Ok(Value::Object(map.clone())),
        Some(Value::String(raw)) if raw.trim().is_empty() => Ok(Value::Object(Map::new())),
        Some(Value::String(raw)) => serde_json::from_str(raw).map_err(|err| {
            InteropError::malformed(
                dialect,
                format!("tool '{tool_name}' arguments are not valid JSON: {err}"),
            )
        }),
        Some(other) => Err(InteropError::malformed(
            dialect,
            format!("tool '{tool_name}' arguments must be an object or JSON string, got {other}"),
        )),
    }
}

/// Fetch a required string field from a JSON object.
pub(super) fn required_str<'a>(
    object: &'a Value,
    key: &str,
    dialect: &'static str,
) -> Result<&'a str, InteropError> {
    object.get(key).and_then(Value::as_str).ok_or_else(|| {
        InteropError::malformed(
            dialect,
            format!("tool call entry is missing string '{key}'"),
        )
    })
}

/// Fetch an optional string field from a JSON object.
pub(super) fn optional_str(object: &Value, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Retain the tool definitions whose extracted name passes `keep`.
///
/// Entries whose name cannot be extracted are dropped — an unidentifiable
/// tool definition must not slip past a listing filter (fail closed).
pub(super) fn filter_tool_array(
    tools: &Value,
    name_of: impl Fn(&Value) -> Option<String>,
    keep: &dyn Fn(&str) -> bool,
) -> Value {
    let Some(items) = tools.as_array() else {
        return Value::Array(Vec::new());
    };
    Value::Array(
        items
            .iter()
            .filter(|item| name_of(item).is_some_and(|name| keep(&name)))
            .cloned()
            .collect(),
    )
}
