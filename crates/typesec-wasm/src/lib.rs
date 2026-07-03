//! # typesec-wasm
//!
//! The Typesec decision core for JS/TS agents (Vercel AI SDK, LangChain.js,
//! browser or edge runtimes): compile a policy once, then gate tool calls
//! with the same deny-by-default guard and dialect codecs the Rust and
//! Python surfaces use — same policy file, same verdicts, four languages.
//!
//! Build an npm package with `wasm-pack build --target web crates/typesec-wasm`
//! (or `--target nodejs`). The graph engine is excluded on wasm; RBAC and
//! ODRL are fully supported.
//!
//! ```js
//! import { WasmToolGate } from "typesec-wasm";
//! const gate = new WasmToolGate(policyYaml, "rbac", JSON.stringify([
//!   { tool: "read_report", action: "read", resource: "reports/unspecified",
//!     resource_arg: "report" },
//! ]));
//! const report = JSON.parse(gate.guard_json(subject, JSON.stringify(completion), "openai"));
//! ```
//!
//! Internals return `Result<_, String>` and the `#[wasm_bindgen]` surface
//! converts to `JsError` at the edge — constructing a `JsError` panics off
//! wasm, and the `_impl` layer keeps the crate host-testable.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

use std::sync::Arc;

use serde_json::{Value, json};
use typesec_agent::interop::{
    ToolBinding, ToolCallGuard, ToolCallRequest,
    dialects::{Dialect, dialect, unknown_dialect_message},
};
use typesec_core::ResourceId;
use typesec_core::policy::{PolicyEngine, PolicyResult, RequestContext, SubjectId};
use wasm_bindgen::prelude::*;

fn compile(policy_yaml: &str, format: &str) -> Result<Arc<dyn PolicyEngine>, String> {
    match format {
        "rbac" => Ok(Arc::new(
            typesec_rbac::RbacEngine::from_yaml(policy_yaml)
                .map_err(|err| format!("RBAC YAML parse error: {err}"))?,
        )),
        "odrl" => Ok(Arc::new(
            typesec_odrl::OdrlEngine::from_yaml(policy_yaml)
                .map_err(|err| format!("ODRL YAML parse error: {err}"))?,
        )),
        other => Err(format!(
            "unknown policy format '{other}' (wasm supports rbac and odrl)"
        )),
    }
}

fn dialect_or_err(name: &str) -> Result<&'static Dialect, String> {
    dialect(name).ok_or_else(|| unknown_dialect_message(name))
}

fn js_err(message: String) -> JsError {
    JsError::new(&message)
}

fn request_context(purpose: Option<String>) -> RequestContext {
    purpose.map_or_else(RequestContext::default, |purpose| {
        RequestContext::default().with_purpose(purpose)
    })
}

fn decision_json(subject: &str, action: &str, resource: &str, result: &PolicyResult) -> String {
    let (allowed, reason) = match result {
        PolicyResult::Allow => (true, None),
        PolicyResult::Deny(reason) => (false, Some(reason.clone())),
        PolicyResult::Delegate(reason) => (false, Some(reason.to_string())),
        _ => (false, Some("unknown policy result".to_string())),
    };
    json!({
        "allowed": allowed,
        "subject": subject,
        "action": action,
        "resource": resource,
        "reason": reason,
    })
    .to_string()
}

fn binding_from_value(spec: &Value) -> Result<ToolBinding, String> {
    let field = |key: &str| {
        spec.get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("tool binding is missing string '{key}'"))
    };
    let mut binding = ToolBinding::new(field("tool")?, field("action")?, field("resource")?);
    if let Some(arg) = spec.get("resource_arg").and_then(Value::as_str) {
        binding = binding.resource_from_arg(arg);
    }
    if let Some(required) = spec.get("required_args").and_then(Value::as_array) {
        binding = binding.require_args(required.iter().filter_map(Value::as_str));
    }
    if let Some(globs) = spec.get("arg_globs").and_then(Value::as_object) {
        for (arg, pattern) in globs {
            let pattern = pattern
                .as_str()
                .ok_or_else(|| "arg_globs values must be strings".to_string())?;
            binding = binding
                .arg_glob(arg, pattern)
                .map_err(|err| err.to_string())?;
        }
    }
    if let Some(schema) = spec.get("args_schema") {
        binding = binding
            .args_schema(schema.clone())
            .map_err(|err| err.to_string())?;
    }
    Ok(binding)
}

/// Subject/action/resource decisions over a compiled policy.
#[wasm_bindgen]
pub struct WasmGate {
    engine: Arc<dyn PolicyEngine>,
}

impl WasmGate {
    fn new_impl(policy_yaml: &str, format: &str) -> Result<Self, String> {
        Ok(Self {
            engine: compile(policy_yaml, format)?,
        })
    }
}

#[wasm_bindgen]
impl WasmGate {
    /// Compile a policy (`format` ∈ `rbac` | `odrl`).
    #[wasm_bindgen(constructor)]
    pub fn new(policy_yaml: &str, format: &str) -> Result<WasmGate, JsError> {
        Self::new_impl(policy_yaml, format).map_err(js_err)
    }

    /// Evaluate one decision; returns a JSON string
    /// `{allowed, subject, action, resource, reason}`.
    pub fn check(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        purpose: Option<String>,
    ) -> String {
        let result = self.engine.check_with_context(
            &SubjectId::from(subject),
            action,
            &ResourceId::from(resource),
            &request_context(purpose),
        );
        decision_json(subject, action, resource, &result)
    }
}

/// Deny-by-default tool-call gate: the JS twin of Python's `ToolGate`.
#[wasm_bindgen]
pub struct WasmToolGate {
    guard: ToolCallGuard,
}

impl WasmToolGate {
    fn new_impl(policy_yaml: &str, format: &str, bindings_json: &str) -> Result<Self, String> {
        let engine = compile(policy_yaml, format)?;
        let specs: Vec<Value> = serde_json::from_str(bindings_json)
            .map_err(|err| format!("bindings are not valid JSON: {err}"))?;
        let mut guard = ToolCallGuard::new(engine);
        for spec in &specs {
            guard = guard.bind(binding_from_value(spec)?);
        }
        Ok(Self { guard })
    }

    fn check_tool_impl(
        &self,
        subject: &str,
        tool_name: &str,
        arguments_json: Option<String>,
        purpose: Option<String>,
    ) -> Result<String, String> {
        let arguments = match arguments_json {
            None => json!({}),
            Some(raw) => serde_json::from_str(&raw)
                .map_err(|err| format!("arguments are not valid JSON: {err}"))?,
        };
        let call = self.guard.check(
            &SubjectId::from(subject),
            ToolCallRequest::new(tool_name, arguments),
            &request_context(purpose),
        );
        Ok(json!({
            "allowed": call.verdict.is_allowed(),
            "tool_name": call.request.tool_name,
            "action": call.action,
            "resource": call.resource,
            "reason": call.verdict.reason(),
        })
        .to_string())
    }

    fn guard_json_impl(
        &self,
        subject: &str,
        payload_json: &str,
        dialect_name: &str,
        purpose: Option<String>,
    ) -> Result<String, String> {
        let codec = dialect_or_err(dialect_name)?;
        let payload: Value = serde_json::from_str(payload_json)
            .map_err(|err| format!("payload is not valid JSON: {err}"))?;
        let requests = (codec.parse)(&payload).map_err(|err| err.to_string())?;
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
                    "denial": (codec.denial)(&call),
                })
            })
            .collect();
        serde_json::to_string(&report).map_err(|err| err.to_string())
    }

    fn filter_tools_impl(
        &self,
        subject: &str,
        tools_json: &str,
        dialect_name: &str,
        purpose: Option<String>,
    ) -> Result<String, String> {
        let codec = dialect_or_err(dialect_name)?;
        let tools: Value = serde_json::from_str(tools_json)
            .map_err(|err| format!("tools are not valid JSON: {err}"))?;
        let ctx = request_context(purpose);
        let subject = SubjectId::from(subject);
        let filtered = (codec.filter)(&tools, &|name| {
            self.guard.allows_listing(&subject, name, &ctx)
        });
        serde_json::to_string(&filtered).map_err(|err| err.to_string())
    }
}

#[wasm_bindgen]
impl WasmToolGate {
    /// Compile a policy and bind the tool manifest.
    ///
    /// `bindings_json` is a JSON array of `{tool, action, resource,
    /// resource_arg?, required_args?, arg_globs?, args_schema?}`.
    #[wasm_bindgen(constructor)]
    pub fn new(
        policy_yaml: &str,
        format: &str,
        bindings_json: &str,
    ) -> Result<WasmToolGate, JsError> {
        Self::new_impl(policy_yaml, format, bindings_json).map_err(js_err)
    }

    /// Check one tool call; returns a JSON decision string.
    pub fn check_tool(
        &self,
        subject: &str,
        tool_name: &str,
        arguments_json: Option<String>,
        purpose: Option<String>,
    ) -> Result<String, JsError> {
        self.check_tool_impl(subject, tool_name, arguments_json, purpose)
            .map_err(js_err)
    }

    /// Guard a whole model turn (`dialect` ∈ openai / anthropic / langchain /
    /// pydantic-ai / mcp); returns the JSON report array.
    pub fn guard_json(
        &self,
        subject: &str,
        payload_json: &str,
        dialect: &str,
        purpose: Option<String>,
    ) -> Result<String, JsError> {
        self.guard_json_impl(subject, payload_json, dialect, purpose)
            .map_err(js_err)
    }

    /// Filter a tool-definition list to what the subject may be shown.
    pub fn filter_tools(
        &self,
        subject: &str,
        tools_json: &str,
        dialect: &str,
        purpose: Option<String>,
    ) -> Result<String, JsError> {
        self.filter_tools_impl(subject, tools_json, dialect, purpose)
            .map_err(js_err)
    }
}

#[cfg(test)]
mod tests;
