//! `#[typesec_tool]` generates the wire binding from the tool declaration.

use std::sync::Arc;

use serde_json::json;
use typesec_agent::interop::{ToolCallGuard, ToolCallRequest};
use typesec_core::policy::{RequestContext, SubjectId};
use typesec_macro::typesec_tool;

#[typesec_tool(
    action = "read",
    resource = "reports/unspecified",
    resource_arg = "report",
    required_args = "report"
)]
fn read_report(_args: &serde_json::Value) -> &'static str {
    "the report"
}

#[typesec_tool(name = "infra.deploy", action = "execute", resource = "infra/prod")]
pub fn deploy() {}

const POLICY: &str = r#"
roles:
  - name: analyst
    permissions: [read]
    resources: ["reports/*"]
assignments:
  - subject: "agent:analyst"
    roles: [analyst]
"#;

#[test]
fn generated_bindings_carry_the_declaration() {
    assert_eq!(
        read_report(&json!({})),
        "the report",
        "annotated fn is untouched"
    );
    let binding = read_report_binding();
    assert_eq!(binding.tool_name, "read_report");
    assert_eq!(binding.action, "read");
    assert_eq!(binding.resource_arg.as_deref(), Some("report"));
    assert_eq!(binding.required_args, ["report"]);

    let named = deploy_binding();
    assert_eq!(named.tool_name, "infra.deploy");
    assert_eq!(named.resource, "infra/prod");
}

#[test]
fn generated_binding_guards_calls_end_to_end() {
    let engine = typesec_rbac::RbacEngine::from_yaml(POLICY).expect("policy parses");
    let guard = ToolCallGuard::new(Arc::new(engine)).bind(read_report_binding());
    let ctx = RequestContext::default();

    let allowed = guard.check(
        &SubjectId::from("agent:analyst"),
        ToolCallRequest::new("read_report", json!({"report": "reports/q1"})),
        &ctx,
    );
    assert!(allowed.verdict.is_allowed());

    let missing_required = guard.check(
        &SubjectId::from("agent:analyst"),
        ToolCallRequest::new("read_report", json!({})),
        &ctx,
    );
    assert!(!missing_required.verdict.is_allowed());
}
