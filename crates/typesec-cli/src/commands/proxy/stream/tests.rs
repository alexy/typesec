use super::*;
use crate::commands::proxy::ProxyState;
use std::sync::Arc as StdArc;
use typesec_agent::interop::dialects::dialect;
use typesec_agent::interop::{ToolBinding, ToolCallGuard};
use typesec_core::policy::{RequestContext, SubjectId};

const POLICY: &str = r#"
roles:
  - name: analyst
    permissions: [read]
    resources: ["reports/*"]
assignments:
  - subject: "agent:analyst"
    roles: [analyst]
"#;

fn state() -> ProxyState {
    let engine: StdArc<dyn typesec_core::policy::PolicyEngine> =
        StdArc::new(typesec_rbac::RbacEngine::from_yaml(POLICY).expect("policy parses"));
    let guard = ToolCallGuard::new(engine)
        .bind(ToolBinding::new("read_report", "read", "reports/q1"))
        .bind(ToolBinding::new("wipe_disk", "execute", "infra/disk"));
    ProxyState::for_test(
        guard,
        SubjectId::from("agent:analyst"),
        RequestContext::default(),
    )
}

fn sse_data_objects(body: &str) -> Vec<Value> {
    parse_sse(body)
        .into_iter()
        .filter(|ev| ev.data.trim() != "[DONE]")
        .filter_map(|ev| serde_json::from_str(ev.data.trim()).ok())
        .collect()
}

#[test]
fn openai_stream_passes_through_non_tool_turns() {
    let body = "\
data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hi\"}}]}\n\n\
data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" there\"}}]}\n\n\
data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n\
data: [DONE]\n\n";
    let out = scrub_openai_stream(&state(), dialect("openai").unwrap(), body);
    assert_eq!(out, body, "no tool calls: byte-identical passthrough");
}

#[test]
fn openai_stream_drops_denied_tool_call_and_keeps_allowed() {
    // Two tool calls arrive interleaved across deltas; text streams first.
    let body = "\
data: {\"id\":\"x\",\"model\":\"gpt\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"working\"}}]}\n\n\
data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"type\":\"function\",\"function\":{\"name\":\"read_report\",\"arguments\":\"\"}}]}}]}\n\n\
data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{}\"}}]}}]}\n\n\
data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"c2\",\"type\":\"function\",\"function\":{\"name\":\"wipe_disk\",\"arguments\":\"{}\"}}]}}]}\n\n\
data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n\
data: [DONE]\n\n";
    let out = scrub_openai_stream(&state(), dialect("openai").unwrap(), body);
    let objs = sse_data_objects(&out);

    // The live text chunk is preserved.
    assert!(objs.iter().any(|c| {
        c.pointer("/choices/0/delta/content")
            .and_then(Value::as_str)
            == Some("working")
    }));
    // Exactly one kept tool call, and it is read_report (reindexed to 0).
    let tool_deltas: Vec<&Value> = objs
        .iter()
        .filter_map(|c| {
            c.pointer("/choices/0/delta/tool_calls")
                .and_then(Value::as_array)
        })
        .flatten()
        .collect();
    assert_eq!(tool_deltas.len(), 1);
    assert_eq!(tool_deltas[0]["function"]["name"], "read_report");
    assert_eq!(tool_deltas[0]["index"], 0);
    // A refusal note about the denied call is streamed as content.
    let refusal = objs.iter().any(|c| {
        c.pointer("/choices/0/delta/content")
            .and_then(Value::as_str)
            .is_some_and(|t| t.contains("wipe_disk"))
    });
    assert!(refusal, "denied call surfaced as a [typesec] note");
    // Terminates with a finish chunk and [DONE].
    assert!(out.trim_end().ends_with("data: [DONE]"));
    let finish = objs.iter().find_map(|c| {
        c.pointer("/choices/0/finish_reason")
            .and_then(Value::as_str)
    });
    assert_eq!(finish, Some("tool_calls"), "an allowed call remains");
}

#[test]
fn openai_stream_finish_becomes_stop_when_all_denied() {
    let body = "\
data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c2\",\"type\":\"function\",\"function\":{\"name\":\"wipe_disk\",\"arguments\":\"{}\"}}]}}]}\n\n\
data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n\
data: [DONE]\n\n";
    let out = scrub_openai_stream(&state(), dialect("openai").unwrap(), body);
    let objs = sse_data_objects(&out);
    let finish = objs.iter().find_map(|c| {
        c.pointer("/choices/0/finish_reason")
            .and_then(Value::as_str)
    });
    assert_eq!(finish, Some("stop"));
    let has_tool = objs
        .iter()
        .any(|c| c.pointer("/choices/0/delta/tool_calls").is_some());
    assert!(!has_tool, "no tool calls survive");
}

#[test]
fn anthropic_stream_replaces_denied_tool_use_block() {
    let body = "\
event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"role\":\"assistant\",\"model\":\"claude\",\"content\":[],\"stop_reason\":null}}\n\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"let me help\"}}\n\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":0}\n\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t1\",\"name\":\"read_report\",\"input\":{}}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}\n\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":1}\n\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t2\",\"name\":\"wipe_disk\",\"input\":{}}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}\n\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":2}\n\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\n\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\n";
    let out = scrub_anthropic_stream(&state(), dialect("anthropic").unwrap(), body);

    // read_report survives as a tool_use; wipe_disk is replaced by a text block.
    let starts: Vec<Value> = parse_sse(&out)
        .into_iter()
        .filter(|ev| ev.name.as_deref() == Some("content_block_start"))
        .filter_map(|ev| serde_json::from_str(ev.data.trim()).ok())
        .collect();
    let tool_names: Vec<&str> = starts
        .iter()
        .filter_map(|s| s.pointer("/content_block/name").and_then(Value::as_str))
        .collect();
    assert_eq!(
        tool_names,
        ["read_report"],
        "only the allowed tool_use remains"
    );
    let has_refusal_text = parse_sse(&out)
        .iter()
        .filter(|ev| ev.name.as_deref() == Some("content_block_delta"))
        .filter_map(|ev| serde_json::from_str::<Value>(ev.data.trim()).ok())
        .filter_map(|d| {
            d.pointer("/delta/text")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .any(|t| t.contains("wipe_disk"));
    assert!(
        has_refusal_text,
        "denied tool_use became a [typesec] text block"
    );
}
