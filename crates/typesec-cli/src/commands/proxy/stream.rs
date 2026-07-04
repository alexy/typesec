//! Streaming (SSE) enforcement for the proxy.
//!
//! A tool call can only be judged once its name *and* arguments are known, so
//! the model's streamed `tool_calls` / `tool_use` deltas are buffered and
//! reassembled before the guard decides. Plain text deltas are never held —
//! for OpenAI they stream through live; only the tool-call portion is
//! deferred to end-of-stream. Denied calls are dropped (or replaced with a
//! visible `[typesec]` note) exactly as in the non-streaming path, which is
//! reused for the actual verdict via [`super::scrub`].

use std::collections::BTreeMap;

use serde_json::{Value, json};
use typesec_agent::interop::dialects::Dialect;

use super::ProxyState;
use super::scrub::scrub_response;

/// One parsed SSE event: an optional `event:` name and its `data:` payload.
struct SseEvent {
    name: Option<String>,
    data: String,
}

fn parse_sse(body: &str) -> Vec<SseEvent> {
    let mut events = Vec::new();
    let mut name: Option<String> = None;
    let mut data = String::new();
    let mut have_data = false;
    for line in body.lines() {
        if line.is_empty() {
            if have_data || name.is_some() {
                events.push(SseEvent {
                    name: name.take(),
                    data: std::mem::take(&mut data),
                });
                have_data = false;
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("event:") {
            name = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("data:") {
            if have_data {
                data.push('\n');
            }
            data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
            have_data = true;
        }
        // other SSE fields (id:, retry:, comments) are ignored
    }
    if have_data || name.is_some() {
        events.push(SseEvent { name, data });
    }
    events
}

fn emit(out: &mut String, name: Option<&str>, data: &str) {
    if let Some(name) = name {
        out.push_str("event: ");
        out.push_str(name);
        out.push('\n');
    }
    out.push_str("data: ");
    out.push_str(data);
    out.push_str("\n\n");
}

/// Dispatch to the dialect-specific streaming scrubber.
pub(super) fn scrub_stream(state: &ProxyState, codec: &Dialect, body: &str) -> String {
    match codec.name {
        "openai" => scrub_openai_stream(state, codec, body),
        "anthropic" => scrub_anthropic_stream(state, codec, body),
        _ => body.to_string(),
    }
}

/// One tool call accumulated across streamed deltas.
#[derive(Default)]
struct ToolAccum {
    id: Option<String>,
    name: Option<String>,
    arguments: String,
}

fn scrub_openai_stream(state: &ProxyState, codec: &Dialect, body: &str) -> String {
    let events = parse_sse(body);
    let mut out = String::new();
    let mut content = String::new();
    let mut tools: BTreeMap<i64, ToolAccum> = BTreeMap::new();
    let mut template: Option<Value> = None;

    for ev in &events {
        let data = ev.data.trim();
        if data == "[DONE]" {
            continue;
        }
        let Ok(chunk) = serde_json::from_str::<Value>(data) else {
            emit(&mut out, ev.name.as_deref(), data);
            continue;
        };
        if template.is_none() {
            template = Some(chunk.clone());
        }
        let Some(choice) = chunk.pointer("/choices/0") else {
            emit(&mut out, ev.name.as_deref(), data);
            continue;
        };
        let delta = choice.get("delta");

        if let Some(tcs) = delta
            .and_then(|d| d.get("tool_calls"))
            .and_then(Value::as_array)
        {
            for tc in tcs {
                let index = tc.get("index").and_then(Value::as_i64).unwrap_or(0);
                let entry = tools.entry(index).or_default();
                if let Some(id) = tc.get("id").and_then(Value::as_str) {
                    entry.id = Some(id.to_string());
                }
                if let Some(name) = tc.pointer("/function/name").and_then(Value::as_str) {
                    entry.name = Some(name.to_string());
                }
                if let Some(args) = tc.pointer("/function/arguments").and_then(Value::as_str) {
                    entry.arguments.push_str(args);
                }
            }
        }

        // Text content streams through live; a chunk carrying only content (or
        // just the opening role) is forwarded verbatim.
        let has_tool_calls = delta
            .and_then(|d| d.get("tool_calls"))
            .is_some_and(|tcs| !tcs.as_array().map(Vec::is_empty).unwrap_or(true));
        if let Some(text) = delta.and_then(|d| d.get("content")).and_then(Value::as_str) {
            if !text.is_empty() {
                content.push_str(text);
            }
            emit(&mut out, ev.name.as_deref(), data);
        } else if !has_tool_calls
            && choice
                .get("finish_reason")
                .and_then(Value::as_str)
                .is_none()
        {
            // role-only or empty keepalive chunk with no tool calls: pass through
            emit(&mut out, ev.name.as_deref(), data);
        }
    }

    // No tool calls at all — this wasn't a tool-call turn; stream as-is.
    if tools.is_empty() {
        return body.to_string();
    }

    // Reassemble the buffered tool calls into a non-streaming message and
    // reuse the ordinary scrub for the verdict.
    let tool_calls: Vec<Value> = tools
        .values()
        .filter_map(|t| {
            t.name.as_ref().map(|name| {
                json!({
                    "id": t.id.clone().unwrap_or_default(),
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": if t.arguments.is_empty() { "{}".to_string() }
                                     else { t.arguments.clone() },
                    },
                })
            })
        })
        .collect();
    let mut assembled = json!({
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": if content.is_empty() { Value::Null } else { json!(content) },
                "tool_calls": tool_calls,
            },
            "finish_reason": "tool_calls",
        }]
    });
    scrub_response(state, codec, &mut assembled);
    let choice = &assembled["choices"][0];
    let scrubbed_content = choice["message"]["content"].as_str().unwrap_or("");
    let finish_reason = choice["finish_reason"].as_str().unwrap_or("stop");

    let synth = |value: Value| -> String { synth_chunk(template.as_ref(), value) };

    // The refusal note is whatever scrub appended past the streamed content.
    let appended = scrubbed_content
        .strip_prefix(&content)
        .map(|rest| rest.trim_start_matches('\n'))
        .unwrap_or(scrubbed_content);
    if !appended.is_empty() {
        emit(
            &mut out,
            None,
            &synth(
                json!({"delta": {"content": appended}, "index": 0, "finish_reason": Value::Null}),
            ),
        );
    }

    if let Some(kept) = choice["message"]
        .get("tool_calls")
        .and_then(Value::as_array)
    {
        let reindexed: Vec<Value> = kept
            .iter()
            .enumerate()
            .map(|(i, tc)| {
                let mut tc = tc.clone();
                tc["index"] = json!(i);
                tc
            })
            .collect();
        if !reindexed.is_empty() {
            emit(
                &mut out,
                None,
                &synth(
                    json!({"delta": {"tool_calls": reindexed}, "index": 0, "finish_reason": Value::Null}),
                ),
            );
        }
    }

    emit(
        &mut out,
        None,
        &synth(json!({"delta": {}, "index": 0, "finish_reason": finish_reason})),
    );
    emit(&mut out, None, "[DONE]");
    out
}

/// Build a chat.completion.chunk carrying `choice`, reusing the upstream
/// stream's id/model/created/object when a template chunk was seen.
fn synth_chunk(template: Option<&Value>, choice: Value) -> String {
    let mut chunk = json!({
        "object": "chat.completion.chunk",
        "choices": [choice],
    });
    if let Some(template) = template {
        for key in ["id", "model", "created", "system_fingerprint"] {
            if let Some(value) = template.get(key) {
                chunk[key] = value.clone();
            }
        }
    }
    chunk.to_string()
}

fn scrub_anthropic_stream(state: &ProxyState, codec: &Dialect, body: &str) -> String {
    let events = parse_sse(body);
    let mut message_base = json!({"type": "message", "role": "assistant", "content": []});
    let mut blocks: BTreeMap<i64, Value> = BTreeMap::new();
    let mut json_buffers: BTreeMap<i64, String> = BTreeMap::new();
    let mut stop_reason: Option<String> = None;
    let mut saw_tool_use = false;

    for ev in &events {
        let Ok(data) = serde_json::from_str::<Value>(ev.data.trim()) else {
            continue;
        };
        match ev.name.as_deref() {
            Some("message_start") => {
                if let Some(message) = data.get("message") {
                    message_base = message.clone();
                    message_base["content"] = json!([]);
                }
            }
            Some("content_block_start") => {
                if let (Some(index), Some(block)) = (
                    data.get("index").and_then(Value::as_i64),
                    data.get("content_block"),
                ) {
                    if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                        saw_tool_use = true;
                    }
                    blocks.insert(index, block.clone());
                }
            }
            Some("content_block_delta") => {
                if let Some(index) = data.get("index").and_then(Value::as_i64) {
                    let delta = data.get("delta");
                    if let Some(text) = delta.and_then(|d| d.get("text")).and_then(Value::as_str) {
                        let block = blocks
                            .entry(index)
                            .or_insert_with(|| json!({"type": "text", "text": ""}));
                        let combined = format!(
                            "{}{text}",
                            block.get("text").and_then(Value::as_str).unwrap_or("")
                        );
                        block["text"] = json!(combined);
                    }
                    if let Some(pj) = delta
                        .and_then(|d| d.get("partial_json"))
                        .and_then(Value::as_str)
                    {
                        json_buffers.entry(index).or_default().push_str(pj);
                    }
                }
            }
            Some("message_delta") => {
                if let Some(reason) = data.pointer("/delta/stop_reason").and_then(Value::as_str) {
                    stop_reason = Some(reason.to_string());
                }
            }
            _ => {}
        }
    }

    // Finalize tool_use inputs from their accumulated partial JSON.
    for (index, raw) in &json_buffers {
        if let Some(block) = blocks.get_mut(index) {
            block["input"] = serde_json::from_str(raw).unwrap_or_else(|_| json!({}));
        }
    }

    // Non-tool-use stream: nothing to enforce, pass through untouched.
    if !saw_tool_use {
        return body.to_string();
    }

    let content: Vec<Value> = blocks.into_values().collect();
    let mut assembled = message_base.clone();
    assembled["content"] = json!(content);
    if let Some(reason) = &stop_reason {
        assembled["stop_reason"] = json!(reason);
    }
    scrub_response(state, codec, &mut assembled);

    // Re-emit a valid Anthropic event stream from the scrubbed message.
    let mut out = String::new();
    let mut start_message = assembled.clone();
    start_message["content"] = json!([]);
    emit(
        &mut out,
        Some("message_start"),
        &json!({"type": "message_start", "message": start_message}).to_string(),
    );
    let final_stop = assembled
        .get("stop_reason")
        .and_then(Value::as_str)
        .unwrap_or("end_turn");
    if let Some(content) = assembled.get("content").and_then(Value::as_array) {
        for (index, block) in content.iter().enumerate() {
            emit_anthropic_block(&mut out, index, block);
        }
    }
    emit(
        &mut out,
        Some("message_delta"),
        &json!({"type": "message_delta", "delta": {"stop_reason": final_stop}, "usage": {}})
            .to_string(),
    );
    emit(
        &mut out,
        Some("message_stop"),
        &json!({"type": "message_stop"}).to_string(),
    );
    out
}

fn emit_anthropic_block(out: &mut String, index: usize, block: &Value) {
    let block_type = block.get("type").and_then(Value::as_str).unwrap_or("text");
    let mut start_block = block.clone();
    if block_type == "text" {
        start_block["text"] = json!("");
    } else if block_type == "tool_use" {
        start_block["input"] = json!({});
    }
    emit(
        out,
        Some("content_block_start"),
        &json!({"type": "content_block_start", "index": index, "content_block": start_block})
            .to_string(),
    );
    let delta = if block_type == "tool_use" {
        json!({
            "type": "input_json_delta",
            "partial_json": serde_json::to_string(block.get("input").unwrap_or(&json!({})))
                .unwrap_or_else(|_| "{}".to_string()),
        })
    } else {
        json!({"type": "text_delta", "text": block.get("text").and_then(Value::as_str).unwrap_or("")})
    };
    emit(
        out,
        Some("content_block_delta"),
        &json!({"type": "content_block_delta", "index": index, "delta": delta}).to_string(),
    );
    emit(
        out,
        Some("content_block_stop"),
        &json!({"type": "content_block_stop", "index": index}).to_string(),
    );
}

#[cfg(test)]
mod tests;
