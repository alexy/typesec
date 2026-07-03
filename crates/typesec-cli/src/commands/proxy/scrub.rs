//! Pure request/response rewriting for the enforcement proxy (unit-tested).

use serde_json::{Value, json};
use typesec_agent::interop::dialects::Dialect;
use typesec_agent::interop::{GuardedToolCall, ToolCallVerdict};

use super::ProxyState;

/// Filter the request's `tools` array policy-aware (when enabled).
pub(super) fn filter_request_tools(state: &ProxyState, codec: &Dialect, request: &mut Value) {
    if !state.filter_tools {
        return;
    }
    if let Some(tools) = request.get("tools") {
        let filtered = (codec.filter)(tools, &|name| {
            state.guard.allows_listing(&state.subject, name, &state.ctx)
        });
        request["tools"] = filtered;
    }
}

/// Check one raw tool-call entry through the guard, fail-closed on parse
/// errors. Returns `Ok(())` when the call may run, `Err(refusal_text)` when
/// it must be scrubbed.
fn verdict_for(state: &ProxyState, codec: &Dialect, wrapped: Value) -> Result<(), String> {
    let mut calls = match (codec.parse)(&wrapped) {
        Ok(calls) => calls,
        Err(err) => return Err(format!("[typesec] blocked unparseable tool call: {err}")),
    };
    let Some(request) = calls.pop() else {
        return Err("[typesec] blocked unrecognized tool call".to_string());
    };
    let call: GuardedToolCall = state.guard.check(&state.subject, request, &state.ctx);
    match call.denial_message() {
        None => Ok(()),
        Some(_) => {
            let reason = match &call.verdict {
                ToolCallVerdict::Allow => unreachable!("allowed calls have no denial"),
                ToolCallVerdict::Deny { reason } | ToolCallVerdict::Delegate { reason } => reason,
            };
            Err(format!(
                "[typesec] blocked tool call '{}': {reason}",
                call.request.tool_name
            ))
        }
    }
}

/// Scrub denied tool calls out of an enforced upstream response, in place.
pub(super) fn scrub_response(state: &ProxyState, codec: &Dialect, response: &mut Value) {
    match codec.name {
        "openai" => scrub_openai(state, codec, response),
        "anthropic" => scrub_anthropic(state, codec, response),
        _ => {}
    }
}

fn scrub_openai(state: &ProxyState, codec: &Dialect, response: &mut Value) {
    let Some(choices) = response.get_mut("choices").and_then(Value::as_array_mut) else {
        return;
    };
    for choice in choices {
        let Some(message) = choice.get_mut("message") else {
            continue;
        };
        let Some(entries) = message.get("tool_calls").and_then(Value::as_array) else {
            continue;
        };
        let mut kept = Vec::new();
        let mut refusals = Vec::new();
        for entry in entries.clone() {
            match verdict_for(state, codec, json!([entry])) {
                Ok(()) => kept.push(entry),
                Err(refusal) => refusals.push(refusal),
            }
        }
        if refusals.is_empty() {
            continue;
        }
        let note = refusals.join("\n");
        let content = match message.get("content").and_then(Value::as_str) {
            Some(existing) if !existing.is_empty() => format!("{existing}\n{note}"),
            _ => note,
        };
        message["content"] = json!(content);
        if kept.is_empty() {
            message.as_object_mut().map(|m| m.remove("tool_calls"));
            choice["finish_reason"] = json!("stop");
        } else {
            message["tool_calls"] = Value::Array(kept);
        }
    }
}

fn scrub_anthropic(state: &ProxyState, codec: &Dialect, response: &mut Value) {
    let Some(blocks) = response.get_mut("content").and_then(Value::as_array_mut) else {
        return;
    };
    let mut scrubbed_any = false;
    for block in blocks.iter_mut() {
        if block.get("type").and_then(Value::as_str) != Some("tool_use") {
            continue;
        }
        if let Err(refusal) = verdict_for(state, codec, json!({"content": [block.clone()]})) {
            *block = json!({"type": "text", "text": refusal});
            scrubbed_any = true;
        }
    }
    let any_tool_use = blocks
        .iter()
        .any(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"));
    if scrubbed_any
        && !any_tool_use
        && response.get("stop_reason").and_then(Value::as_str) == Some("tool_use")
    {
        response["stop_reason"] = json!("end_turn");
    }
}
