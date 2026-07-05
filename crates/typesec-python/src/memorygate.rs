//! The `MemoryGate` pyclass: capability-secured agent memory from Python.
//!
//! A thin veneer over `typesec_memory`'s `MemoryToolRouter`: every operation
//! mints the required capability through the compiled policy engine (audited)
//! and executes against an in-process vault. Clearance is a string here —
//! the JSON boundary can't carry a type parameter — mapped fail-closed by
//! `Label::from_name` (unknown names become `secret`, never wider).

use std::sync::Arc;

use pyo3::exceptions::{PyPermissionError, PyValueError};
use pyo3::prelude::*;
use serde_json::{Value, json};
use typesec_agent::interop::ToolCallRequest;
use typesec_memory::agent::{MemoryToolRouter, TOOL_FORGET, TOOL_RECALL, TOOL_REMEMBER};
use typesec_memory::{InMemoryStore, MemoryError, MemoryVault};

use crate::engine::{compile_policy, request_context};
use crate::format::PolicyFormat;

/// Capability-secured memory: remember / recall / forget, policy-gated.
///
/// Each gate owns one in-process vault. Spaces are resource ids
/// (`memory/<owner>/<space>`); the policy decides which subjects may
/// read/write/delete which spaces. Contents of records above the recall
/// clearance come back as redacted stubs, never cleartext.
#[pyclass]
pub(crate) struct MemoryGate {
    router: MemoryToolRouter<InMemoryStore>,
}

fn memory_err(err: MemoryError) -> PyErr {
    match &err {
        MemoryError::PolicyDenied { .. }
        | MemoryError::SpaceMismatch { .. }
        | MemoryError::Capability(_)
        | MemoryError::AboveCeiling { .. } => PyPermissionError::new_err(err.to_string()),
        _ => PyValueError::new_err(err.to_string()),
    }
}

fn to_json_string(value: &Value) -> PyResult<String> {
    serde_json::to_string(value)
        .map_err(|err| PyValueError::new_err(format!("failed to encode result: {err}")))
}

#[pymethods]
impl MemoryGate {
    /// Compile `policy_yaml` (rbac | odrl | graph, auto-detected) and open an
    /// empty vault behind it.
    #[new]
    #[pyo3(signature = (policy_yaml, format = None))]
    fn new(policy_yaml: String, format: Option<&str>) -> PyResult<Self> {
        let format = PolicyFormat::detect(format, &policy_yaml)?;
        let engine = compile_policy(&policy_yaml, format)?;
        let router = MemoryToolRouter::new(
            MemoryVault::new(InMemoryStore::new()),
            Arc::new(engine) as Arc<dyn typesec_core::policy::PolicyEngine>,
        );
        Ok(Self { router })
    }

    /// Load the policy from a file instead of an inline string.
    #[staticmethod]
    #[pyo3(signature = (path, format = None))]
    fn from_file(path: &str, format: Option<&str>) -> PyResult<Self> {
        let yaml = std::fs::read_to_string(path)
            .map_err(|err| PyValueError::new_err(format!("failed to read policy: {err}")))?;
        Self::new(yaml, format)
    }

    /// Remember `text` in `space` as `subject`. Requires the policy to grant
    /// `write` on the space. Returns the new record id.
    #[pyo3(signature = (subject, space, text, kind = None))]
    fn remember(
        &self,
        subject: &str,
        space: &str,
        text: &str,
        kind: Option<&str>,
    ) -> PyResult<String> {
        let mut args = json!({"space": space, "text": text});
        if let Some(kind) = kind {
            args["kind"] = json!(kind);
        }
        let result = self
            .router
            .handle(
                subject,
                &ToolCallRequest::new(TOOL_REMEMBER, args),
                &request_context(None, None),
            )
            .map_err(memory_err)?;
        Ok(result["id"].as_str().unwrap_or_default().to_string())
    }

    /// Recall from `space` at a clearance ceiling (default `internal`).
    /// Returns a JSON string: `{"hits": [...], "redacted": [...]}`. Purpose
    /// binds ODRL-style purpose filtering per call.
    #[pyo3(signature = (subject, space, query = None, clearance = None, purpose = None))]
    fn recall(
        &self,
        subject: &str,
        space: &str,
        query: Option<&str>,
        clearance: Option<&str>,
        purpose: Option<&str>,
    ) -> PyResult<String> {
        let mut args = json!({"space": space});
        if let Some(query) = query {
            args["query"] = json!(query);
        }
        if let Some(clearance) = clearance {
            args["clearance"] = json!(clearance);
        }
        let result = self
            .router
            .handle(
                subject,
                &ToolCallRequest::new(TOOL_RECALL, args),
                &request_context(purpose, None),
            )
            .map_err(memory_err)?;
        to_json_string(&result)
    }

    /// Forget records by id in `space`. Requires `delete` on the space.
    /// Returns the ids actually destroyed.
    #[pyo3(signature = (subject, space, ids))]
    fn forget(&self, subject: &str, space: &str, ids: Vec<String>) -> PyResult<Vec<String>> {
        let result = self
            .router
            .handle(
                subject,
                &ToolCallRequest::new(TOOL_FORGET, json!({"space": space, "ids": ids})),
                &request_context(None, None),
            )
            .map_err(memory_err)?;
        Ok(result["forgotten"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default())
    }
}

// `typesec-python` is a cdylib, so tests stay inline (see CLAUDE.md).
#[cfg(test)]
mod tests {
    use pyo3::types::{PyAnyMethods, PyModule};
    use pyo3::{PyResult, Python};

    const POLICY: &str = r#"
roles:
  - name: keeper
    permissions: [read, write, delete]
    resources: ["memory/**"]
  - name: reader
    permissions: [read]
    resources: ["memory/user:alice/**"]
assignments:
  - subject: "agent:keeper"
    roles: [keeper]
  - subject: "agent:reader"
    roles: [reader]
"#;

    fn with_gate(
        test: impl FnOnce(&pyo3::Bound<'_, pyo3::PyAny>, Python<'_>) -> PyResult<()>,
    ) -> PyResult<()> {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let module = PyModule::new(py, "typesec_native")?;
            crate::_native(&module)?;
            let gate = module.getattr("MemoryGate")?.call1((POLICY, "rbac"))?;
            test(&gate, py)
        })
    }

    #[test]
    fn remember_recall_forget_roundtrip() -> PyResult<()> {
        with_gate(|gate, _| {
            let id: String = gate
                .call_method1(
                    "remember",
                    (
                        "agent:keeper",
                        "memory/user:alice/profile",
                        "likes espresso",
                    ),
                )?
                .extract()?;
            assert!(id.starts_with("mem-"));

            let recall: String = gate
                .call_method1("recall", ("agent:keeper", "memory/user:alice/profile"))?
                .extract()?;
            let recall: serde_json::Value = serde_json::from_str(&recall).unwrap();
            assert_eq!(recall["hits"].as_array().unwrap().len(), 1);
            assert_eq!(recall["hits"][0]["text"], "likes espresso");

            let forgotten: Vec<String> = gate
                .call_method1(
                    "forget",
                    (
                        "agent:keeper",
                        "memory/user:alice/profile",
                        vec![id.clone()],
                    ),
                )?
                .extract()?;
            assert_eq!(forgotten, vec![id]);
            Ok(())
        })
    }

    #[test]
    fn clearance_ceiling_redacts_and_denials_raise_permission_error() -> PyResult<()> {
        with_gate(|gate, py| {
            gate.call_method1(
                "remember",
                ("agent:keeper", "memory/user:alice/profile", "internal note"),
            )?;

            // Public ceiling: the Internal record is redacted, not returned.
            let kwargs = pyo3::types::PyDict::new(py);
            kwargs.set_item("clearance", "public")?;
            let recall: String = gate
                .call_method(
                    "recall",
                    ("agent:keeper", "memory/user:alice/profile"),
                    Some(&kwargs),
                )?
                .extract()?;
            let recall: serde_json::Value = serde_json::from_str(&recall).unwrap();
            assert!(recall["hits"].as_array().unwrap().is_empty());
            assert_eq!(recall["redacted"].as_array().unwrap().len(), 1);

            // The reader may not write: PermissionError, not ValueError.
            let err = gate
                .call_method1(
                    "remember",
                    ("agent:reader", "memory/user:alice/profile", "x"),
                )
                .expect_err("reader cannot write");
            assert!(err.is_instance_of::<pyo3::exceptions::PyPermissionError>(py));
            Ok(())
        })
    }
}
