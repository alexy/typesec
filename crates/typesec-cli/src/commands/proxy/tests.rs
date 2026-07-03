use super::scrub::{filter_request_tools, scrub_response};
use super::*;
use serde_json::json;
use std::sync::Arc as StdArc;
use typesec_agent::interop::ToolBinding;

const POLICY: &str = r#"
roles:
  - name: analyst
    permissions: [read]
    resources: ["reports/*"]
assignments:
  - subject: "agent:analyst"
    roles: [analyst]
"#;

fn state(filter_tools: bool) -> ProxyState {
    let engine: StdArc<dyn typesec_core::policy::PolicyEngine> =
        StdArc::new(typesec_rbac::RbacEngine::from_yaml(POLICY).expect("policy parses"));
    let guard = ToolCallGuard::new(engine)
        .bind(
            ToolBinding::new("read_report", "read", "reports/unspecified")
                .resource_from_arg("report"),
        )
        .bind(ToolBinding::new("wipe_disk", "execute", "infra/disk"));
    ProxyState {
        guard,
        subject: SubjectId::from("agent:analyst"),
        ctx: RequestContext::default(),
        filter_tools,
        upstream: "http://unused".into(),
        client: reqwest::Client::new(),
    }
}

#[test]
fn request_tools_are_filtered_when_enabled() {
    let mut request = json!({"model": "gpt", "tools": [
        {"type": "function", "function": {"name": "read_report"}},
        {"type": "function", "function": {"name": "wipe_disk"}},
        {"type": "function", "function": {"name": "ghost"}}
    ]});
    filter_request_tools(&state(true), dialect("openai").unwrap(), &mut request);
    assert_eq!(request["tools"].as_array().unwrap().len(), 1);

    let mut untouched = json!({"tools": [{"type": "function", "function": {"name": "ghost"}}]});
    filter_request_tools(&state(false), dialect("openai").unwrap(), &mut untouched);
    assert_eq!(
        untouched["tools"].as_array().unwrap().len(),
        1,
        "off by default"
    );
}

#[test]
fn openai_response_scrub_removes_denied_calls_and_annotates() {
    let mut response = json!({"choices": [{
        "finish_reason": "tool_calls",
        "message": {"role": "assistant", "content": null, "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "read_report", "arguments": "{\"report\": \"reports/q1\"}"}},
            {"id": "c2", "type": "function",
             "function": {"name": "wipe_disk", "arguments": "{}"}}
        ]}
    }]});
    scrub_response(&state(false), dialect("openai").unwrap(), &mut response);
    let message = &response["choices"][0]["message"];
    let kept = message["tool_calls"].as_array().unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0]["function"]["name"], "read_report");
    assert!(
        message["content"]
            .as_str()
            .unwrap()
            .contains("[typesec] blocked tool call 'wipe_disk'")
    );
}

#[test]
fn openai_scrub_restores_stop_when_no_calls_remain() {
    let mut response = json!({"choices": [{
        "finish_reason": "tool_calls",
        "message": {"role": "assistant", "content": "on it", "tool_calls": [
            {"id": "c2", "type": "function", "function": {"name": "wipe_disk", "arguments": "{}"}}
        ]}
    }]});
    scrub_response(&state(false), dialect("openai").unwrap(), &mut response);
    let choice = &response["choices"][0];
    assert!(choice["message"].get("tool_calls").is_none());
    assert_eq!(choice["finish_reason"], "stop");
    assert!(
        choice["message"]["content"]
            .as_str()
            .unwrap()
            .starts_with("on it\n[typesec]")
    );
}

#[test]
fn anthropic_response_scrub_replaces_denied_blocks() {
    let mut response = json!({
        "stop_reason": "tool_use",
        "content": [
            {"type": "text", "text": "checking"},
            {"type": "tool_use", "id": "t1", "name": "read_report",
             "input": {"report": "reports/q1"}},
            {"type": "tool_use", "id": "t2", "name": "wipe_disk", "input": {}}
        ]
    });
    scrub_response(&state(false), dialect("anthropic").unwrap(), &mut response);
    let blocks = response["content"].as_array().unwrap();
    assert_eq!(blocks[1]["type"], "tool_use", "allowed call survives");
    assert_eq!(blocks[2]["type"], "text");
    assert!(blocks[2]["text"].as_str().unwrap().contains("wipe_disk"));
    assert_eq!(response["stop_reason"], "tool_use", "a tool_use remains");

    let mut all_denied = json!({
        "stop_reason": "tool_use",
        "content": [{"type": "tool_use", "id": "t2", "name": "wipe_disk", "input": {}}]
    });
    scrub_response(
        &state(false),
        dialect("anthropic").unwrap(),
        &mut all_denied,
    );
    assert_eq!(all_denied["stop_reason"], "end_turn");
}
