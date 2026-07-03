//! The `ToolGate` pyclass: guard framework tool calls from Python.

use std::collections::HashMap;
use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::{Value, json};
use typesec_agent::interop::{
    GuardedToolCall, InteropError, ToolBinding, ToolCallGuard, ToolCallRequest, anthropic,
    langchain, openai, pydantic_ai,
};
use typesec_core::policy::SubjectId;

use crate::decision::Decision;
use crate::engine::{compile_policy, request_context};
use crate::format::PolicyFormat;

type ParseFn = fn(&Value) -> Result<Vec<ToolCallRequest>, InteropError>;
type DenialFn = fn(&GuardedToolCall) -> Option<Value>;

fn dialect_codec(dialect: &str) -> PyResult<(ParseFn, DenialFn)> {
    match dialect {
        "openai" => Ok((openai::parse_tool_calls, openai::denial)),
        "anthropic" => Ok((anthropic::parse_tool_calls, anthropic::denial)),
        "langchain" => Ok((langchain::parse_tool_calls, langchain::denial)),
        "pydantic-ai" | "pydantic_ai" => Ok((pydantic_ai::parse_tool_calls, pydantic_ai::denial)),
        other => Err(PyValueError::new_err(format!(
            "unknown dialect '{other}' (expected openai, anthropic, langchain, or pydantic-ai)"
        ))),
    }
}

fn binding_from_map(spec: &HashMap<String, String>) -> PyResult<ToolBinding> {
    let field = |key: &str| {
        spec.get(key)
            .cloned()
            .ok_or_else(|| PyValueError::new_err(format!("tool binding is missing '{key}'")))
    };
    let mut binding = ToolBinding::new(field("tool")?, field("action")?, field("resource")?);
    if let Some(arg) = spec.get("resource_arg") {
        binding = binding.resource_from_arg(arg.clone());
    }
    Ok(binding)
}

/// Deny-by-default tool-call gate over a compiled Typesec policy.
///
/// `tools` is a list of dicts with keys `tool`, `action`, `resource`, and
/// optionally `resource_arg` (the name of a string tool argument that names
/// the resource per call). Tool calls whose tool is not listed are denied.
#[pyclass]
pub(crate) struct ToolGate {
    guard: ToolCallGuard,
}

#[pymethods]
impl ToolGate {
    #[new]
    #[pyo3(signature = (policy_yaml, tools, format = None))]
    fn new(
        policy_yaml: String,
        tools: Vec<HashMap<String, String>>,
        format: Option<&str>,
    ) -> PyResult<Self> {
        let format = PolicyFormat::detect(format, &policy_yaml)?;
        let engine = compile_policy(&policy_yaml, format)?;
        let mut guard = ToolCallGuard::new(Arc::new(engine));
        for spec in &tools {
            guard = guard.bind(binding_from_map(spec)?);
        }
        Ok(Self { guard })
    }

    /// Load the policy from a file instead of an inline string.
    #[staticmethod]
    #[pyo3(signature = (path, tools, format = None))]
    fn from_file(
        path: &str,
        tools: Vec<HashMap<String, String>>,
        format: Option<&str>,
    ) -> PyResult<Self> {
        let yaml = std::fs::read_to_string(path)
            .map_err(|err| PyValueError::new_err(format!("failed to read policy: {err}")))?;
        Self::new(yaml, tools, format)
    }

    /// Check one tool call by name and (optional) JSON arguments.
    #[pyo3(signature = (subject, tool_name, arguments_json = None, purpose = None))]
    fn check_tool(
        &self,
        subject: &str,
        tool_name: &str,
        arguments_json: Option<&str>,
        purpose: Option<&str>,
    ) -> PyResult<Decision> {
        let arguments = match arguments_json {
            None => json!({}),
            Some(raw) => serde_json::from_str(raw).map_err(|err| {
                PyValueError::new_err(format!("arguments_json is not valid JSON: {err}"))
            })?,
        };
        let call = self.guard.check(
            &SubjectId::from(subject),
            ToolCallRequest::new(tool_name, arguments),
            &request_context(purpose),
        );
        Ok(decision_from_call(subject, &call))
    }

    /// Guard a framework payload (`dialect` ∈ openai / anthropic / langchain /
    /// pydantic-ai) and return a JSON report: one entry per tool call with
    /// `allowed`, `reason`, and a framework-shaped `denial` message for
    /// blocked calls.
    #[pyo3(signature = (subject, payload_json, dialect, purpose = None))]
    fn guard_json(
        &self,
        subject: &str,
        payload_json: &str,
        dialect: &str,
        purpose: Option<&str>,
    ) -> PyResult<String> {
        let (parse, denial) = dialect_codec(dialect)?;
        let payload: Value = serde_json::from_str(payload_json)
            .map_err(|err| PyValueError::new_err(format!("payload is not valid JSON: {err}")))?;
        let requests = parse(&payload).map_err(|err| PyValueError::new_err(err.to_string()))?;
        let ctx = request_context(purpose);
        let subject = SubjectId::from(subject);
        let report: Vec<Value> = requests
            .into_iter()
            .map(|request| {
                let call = self.guard.check(&subject, request, &ctx);
                json!({
                    "tool_name": call.request.tool_name,
                    "call_id": call.request.call_id,
                    "action": call.action,
                    "resource": call.resource,
                    "allowed": call.verdict.is_allowed(),
                    "reason": call.verdict.reason(),
                    "denial": denial(&call),
                })
            })
            .collect();
        serde_json::to_string(&report)
            .map_err(|err| PyValueError::new_err(format!("failed to encode report: {err}")))
    }
}

fn decision_from_call(subject: &str, call: &GuardedToolCall) -> Decision {
    Decision::new(
        subject,
        call.action.as_deref().unwrap_or(&call.request.tool_name),
        call.resource.as_deref().unwrap_or("<unresolved>"),
        call.verdict.is_allowed(),
        call.verdict.reason().map(str::to_owned),
    )
}

// `typesec-python` is a cdylib, so tests stay inline (see CLAUDE.md).
#[cfg(test)]
mod tests {
    use pyo3::types::{PyAnyMethods, PyDict, PyList, PyModule};
    use pyo3::{PyResult, Python};

    const RBAC: &str = include_str!("../../../policies/rbac-example.yaml");

    fn tool_bindings(py: Python<'_>) -> PyResult<pyo3::Bound<'_, PyList>> {
        let read_report = PyDict::new(py);
        read_report.set_item("tool", "read_report")?;
        read_report.set_item("action", "read")?;
        read_report.set_item("resource", "reports/default")?;
        read_report.set_item("resource_arg", "report")?;
        let deploy = PyDict::new(py);
        deploy.set_item("tool", "deploy")?;
        deploy.set_item("action", "execute")?;
        deploy.set_item("resource", "infra/deploy")?;
        PyList::new(py, [read_report, deploy])
    }

    fn with_gate(
        test: impl FnOnce(&pyo3::Bound<'_, pyo3::PyAny>, Python<'_>) -> PyResult<()>,
    ) -> PyResult<()> {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let module = PyModule::new(py, "typesec_native")?;
            crate::typesec_native(&module)?;
            let gate = module
                .getattr("ToolGate")?
                .call1((RBAC, tool_bindings(py)?, "rbac"))?;
            test(&gate, py)
        })
    }

    #[test]
    fn check_tool_allows_bound_call_and_denies_unbound() -> PyResult<()> {
        with_gate(|gate, _| {
            let allowed = gate.call_method1(
                "check_tool",
                (
                    "agent:data-pipeline",
                    "read_report",
                    r#"{"report": "reports/q1"}"#,
                ),
            )?;
            assert!(allowed.getattr("allowed")?.extract::<bool>()?);

            let unbound = gate.call_method1("check_tool", ("agent:superadmin", "rm_rf"))?;
            assert!(!unbound.getattr("allowed")?.extract::<bool>()?);
            let reason: String = unbound
                .getattr("reason")?
                .extract::<Option<String>>()?
                .unwrap();
            assert!(reason.contains("no typesec binding"));
            Ok(())
        })
    }

    #[test]
    fn guard_json_reports_mixed_openai_verdicts() -> PyResult<()> {
        with_gate(|gate, _| {
            let payload = r#"{"tool_calls": [
                {"id": "c1", "type": "function",
                 "function": {"name": "read_report", "arguments": "{\"report\": \"reports/q1\"}"}},
                {"id": "c2", "type": "function",
                 "function": {"name": "deploy", "arguments": "{}"}}
            ]}"#;
            let report: String = gate
                .call_method1("guard_json", ("agent:data-pipeline", payload, "openai"))?
                .extract()?;
            let report: serde_json::Value = serde_json::from_str(&report).unwrap();
            assert_eq!(report[0]["allowed"], true);
            assert_eq!(report[0]["denial"], serde_json::Value::Null);
            assert_eq!(report[1]["allowed"], false);
            assert_eq!(report[1]["denial"]["role"], "tool");
            assert_eq!(report[1]["denial"]["tool_call_id"], "c2");
            Ok(())
        })
    }

    #[test]
    fn guard_json_handles_anthropic_and_rejects_unknown_dialect() -> PyResult<()> {
        with_gate(|gate, py| {
            let payload = r#"{"content": [
                {"type": "tool_use", "id": "t1", "name": "deploy", "input": {}}
            ]}"#;
            let report: String = gate
                .call_method1("guard_json", ("agent:deploy-bot", payload, "anthropic"))?
                .extract()?;
            let report: serde_json::Value = serde_json::from_str(&report).unwrap();
            assert_eq!(report[0]["allowed"], true);

            let err = gate
                .call_method1("guard_json", ("agent:deploy-bot", payload, "cobol"))
                .expect_err("unknown dialect must fail");
            assert!(err.is_instance_of::<pyo3::exceptions::PyValueError>(py));
            Ok(())
        })
    }
}
