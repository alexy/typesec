//! The deny-by-default tool-call guard over any [`PolicyEngine`].

use std::collections::HashMap;
use std::sync::Arc;

use typesec_core::ResourceId;
use typesec_core::policy::{PolicyEngine, PolicyResult, RequestContext, SubjectId};

use super::call::{GuardedToolCall, ToolBinding, ToolCallRequest, ToolCallVerdict};
use crate::tool::ToolRegistry;

/// Evaluates normalized tool calls against a policy engine.
///
/// Tools without a [`ToolBinding`] are **denied by default** — a model cannot
/// reach an action the deployment never declared. The guard is engine-agnostic:
/// RBAC, ODRL, graph, a provider engine (WorkOS/Arcade), or any composition of
/// them via [`FallbackEngine`](typesec_core::policy::FallbackEngine) works.
pub struct ToolCallGuard {
    engine: Arc<dyn PolicyEngine>,
    bindings: HashMap<String, ToolBinding>,
}

impl ToolCallGuard {
    /// Create a guard with no bindings (every call denied) over `engine`.
    pub fn new(engine: Arc<dyn PolicyEngine>) -> Self {
        Self {
            engine,
            bindings: HashMap::new(),
        }
    }

    /// Add one tool binding. Re-binding a tool name replaces the previous
    /// binding.
    #[must_use]
    pub fn bind(mut self, binding: ToolBinding) -> Self {
        self.bindings.insert(binding.tool_name.clone(), binding);
        self
    }

    /// Bind every tool registered in a typed [`ToolRegistry`], reusing each
    /// tool's declared permission and resource id.
    #[must_use]
    pub fn bind_registry(mut self, registry: &ToolRegistry) -> Self {
        for spec in registry.list_specs() {
            let binding = ToolBinding::from_spec(&spec);
            self.bindings.insert(binding.tool_name.clone(), binding);
        }
        self
    }

    /// Look up the binding for a tool name.
    pub fn binding(&self, tool_name: &str) -> Option<&ToolBinding> {
        self.bindings.get(tool_name)
    }

    /// Check one tool call for `subject` under `ctx`.
    pub fn check(
        &self,
        subject: &SubjectId,
        request: ToolCallRequest,
        ctx: &RequestContext,
    ) -> GuardedToolCall {
        let (request, action, resource) = match self.resolve(request) {
            Ok(bound) => bound,
            Err(denied) => return denied,
        };
        let result = self.engine.check_with_context(
            subject,
            &action,
            &ResourceId::from(resource.as_str()),
            ctx,
        );
        self.finish(subject, request, action, resource, result)
    }

    /// Check one tool call asynchronously (for IO-bound engines).
    pub async fn check_async(
        &self,
        subject: &SubjectId,
        request: ToolCallRequest,
        ctx: &RequestContext,
    ) -> GuardedToolCall {
        let (request, action, resource) = match self.resolve(request) {
            Ok(bound) => bound,
            Err(denied) => return denied,
        };
        let result = self
            .engine
            .check_with_context_async(subject, &action, &ResourceId::from(resource.as_str()), ctx)
            .await;
        self.finish(subject, request, action, resource, result)
    }

    /// Check a batch of tool calls (one model turn can request several).
    pub fn check_all(
        &self,
        subject: &SubjectId,
        requests: impl IntoIterator<Item = ToolCallRequest>,
        ctx: &RequestContext,
    ) -> Vec<GuardedToolCall> {
        requests
            .into_iter()
            .map(|request| self.check(subject, request, ctx))
            .collect()
    }

    /// Resolve a request to its `(action, resource)`, or finish it immediately
    /// as a structured deny (unbound tool, missing resource argument).
    #[allow(clippy::result_large_err)]
    fn resolve(
        &self,
        request: ToolCallRequest,
    ) -> Result<(ToolCallRequest, String, String), GuardedToolCall> {
        let Some(binding) = self.bindings.get(&request.tool_name) else {
            let reason = format!(
                "tool '{}' has no typesec binding (deny by default)",
                request.tool_name
            );
            return Err(GuardedToolCall {
                request,
                action: None,
                resource: None,
                verdict: ToolCallVerdict::Deny { reason },
            });
        };
        match binding.resolve_resource(&request.arguments) {
            Ok(resource) => Ok((request, binding.action.clone(), resource)),
            Err(reason) => Err(GuardedToolCall {
                action: Some(binding.action.clone()),
                request,
                resource: None,
                verdict: ToolCallVerdict::Deny { reason },
            }),
        }
    }

    fn finish(
        &self,
        subject: &SubjectId,
        request: ToolCallRequest,
        action: String,
        resource: String,
        result: PolicyResult,
    ) -> GuardedToolCall {
        let verdict = match result {
            PolicyResult::Allow => ToolCallVerdict::Allow,
            PolicyResult::Deny(reason) => ToolCallVerdict::Deny { reason },
            PolicyResult::Delegate(reason) => ToolCallVerdict::Delegate {
                reason: reason.to_string(),
            },
            _ => ToolCallVerdict::Deny {
                reason: "unknown policy result".to_string(),
            },
        };
        tracing::info!(
            subject = %subject,
            tool = %request.tool_name,
            action = %action,
            resource = %resource,
            allowed = verdict.is_allowed(),
            "guarded tool call"
        );
        GuardedToolCall {
            request,
            action: Some(action),
            resource: Some(resource),
            verdict,
        }
    }
}
