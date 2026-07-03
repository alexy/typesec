//! Normalized tool-call types shared by every framework dialect.

use serde_json::Value;
use thiserror::Error;
use typesec_core::GlobPattern;

use crate::tool::ToolSpec;

/// A framework payload could not be interpreted as tool calls.
#[derive(Debug, Error)]
pub enum InteropError {
    /// The payload did not match the dialect's expected wire shape.
    #[error("malformed {dialect} tool-call payload: {detail}")]
    Malformed {
        /// Which dialect codec rejected the payload.
        dialect: &'static str,
        /// What was wrong with it.
        detail: String,
    },
}

impl InteropError {
    pub(crate) fn malformed(dialect: &'static str, detail: impl Into<String>) -> Self {
        Self::Malformed {
            dialect,
            detail: detail.into(),
        }
    }
}

/// One tool invocation requested by a model, normalized across frameworks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCallRequest {
    /// Framework-assigned call id (`tool_call_id`, `tool_use_id`, …), if any.
    pub call_id: Option<String>,
    /// Tool name as the model addressed it.
    pub tool_name: String,
    /// Parsed JSON arguments (an empty object when the model sent none).
    pub arguments: Value,
}

impl ToolCallRequest {
    /// Create a normalized tool call.
    pub fn new(tool_name: impl Into<String>, arguments: Value) -> Self {
        Self {
            call_id: None,
            tool_name: tool_name.into(),
            arguments,
        }
    }

    /// Attach the framework-assigned call id.
    #[must_use]
    pub fn with_call_id(mut self, call_id: impl Into<String>) -> Self {
        self.call_id = Some(call_id.into());
        self
    }
}

/// Declares how one tool maps onto the Typesec `(action, resource)` plane.
#[derive(Debug, Clone)]
pub struct ToolBinding {
    /// Tool name as exposed to the model.
    pub tool_name: String,
    /// Typesec action (permission name) required to run the tool.
    pub action: String,
    /// Resource the action applies to when no argument supplies one.
    pub resource: String,
    /// Name of a string tool argument that carries the resource id.
    ///
    /// When set, the resource is taken from the call's arguments and the call
    /// is **denied** if the argument is missing or not a string — a binding
    /// that promises per-argument resources must not silently widen.
    pub resource_arg: Option<String>,
    /// Arguments that must be present on every call (any JSON type).
    pub required_args: Vec<String>,
    /// Per-argument glob constraints: the named argument must be present, be
    /// a string, and match the pattern — otherwise the call is denied. A
    /// constrained argument is implicitly required (fail closed: what is
    /// absent cannot be verified).
    arg_globs: Vec<(String, GlobPattern)>,
}

impl ToolBinding {
    /// Bind a tool to a fixed action and resource.
    pub fn new(
        tool_name: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            tool_name: tool_name.into(),
            action: action.into(),
            resource: resource.into(),
            resource_arg: None,
            required_args: Vec::new(),
            arg_globs: Vec::new(),
        }
    }

    /// Take the resource id from the named string argument of each call.
    #[must_use]
    pub fn resource_from_arg(mut self, arg: impl Into<String>) -> Self {
        self.resource_arg = Some(arg.into());
        self
    }

    /// Require the named arguments to be present on every call.
    #[must_use]
    pub fn require_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.required_args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Constrain the named string argument to a glob pattern (compiled once,
    /// here). The argument becomes required. Fails on an invalid pattern.
    pub fn arg_glob(mut self, arg: impl Into<String>, pattern: &str) -> Result<Self, InteropError> {
        let arg = arg.into();
        let compiled =
            GlobPattern::compile(pattern, "argument").map_err(|err| InteropError::Malformed {
                dialect: "binding",
                detail: err,
            })?;
        self.arg_globs.push((arg, compiled));
        Ok(self)
    }

    /// Check required-argument presence and per-argument glob constraints,
    /// returning a denial reason on the first violation.
    pub(crate) fn validate_arguments(&self, arguments: &Value) -> Result<(), String> {
        for required in &self.required_args {
            if arguments.get(required).is_none() {
                return Err(format!(
                    "tool '{}' requires argument '{required}'",
                    self.tool_name
                ));
            }
        }
        for (arg, glob) in &self.arg_globs {
            let Some(value) = arguments.get(arg).and_then(Value::as_str) else {
                return Err(format!(
                    "tool '{}' requires string argument '{arg}' matching its declared pattern",
                    self.tool_name
                ));
            };
            if !glob.matches(value) {
                return Err(format!(
                    "tool '{}' argument '{arg}' value '{value}' does not match the allowed pattern",
                    self.tool_name
                ));
            }
        }
        Ok(())
    }

    /// Derive a binding from a typed [`ToolSpec`], reusing its declared
    /// permission and resource id.
    pub fn from_spec(spec: &ToolSpec) -> Self {
        Self::new(&spec.name, spec.required_permission, &spec.resource_id)
    }

    /// Resolve the effective resource for one call, failing closed when a
    /// promised resource argument is absent.
    pub(crate) fn resolve_resource(&self, arguments: &Value) -> Result<String, String> {
        match &self.resource_arg {
            None => Ok(self.resource.clone()),
            Some(arg) => arguments
                .get(arg)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    format!(
                        "tool '{}' requires string argument '{arg}' to name the resource",
                        self.tool_name
                    )
                }),
        }
    }
}

/// The guard's verdict on one tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolCallVerdict {
    /// The policy engine allowed the call.
    Allow,
    /// The call is denied (unbound tool, missing resource argument, or an
    /// explicit policy deny).
    Deny {
        /// Why the call was denied.
        reason: String,
    },
    /// No engine could decide; treat as not-allowed unless a fallback engine
    /// resolves it.
    Delegate {
        /// Why the engine delegated.
        reason: String,
    },
}

impl ToolCallVerdict {
    /// `true` only for an explicit allow — delegation is *not* permission.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// The deny/delegate rationale, if any.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allow => None,
            Self::Deny { reason } | Self::Delegate { reason } => Some(reason),
        }
    }
}

/// A tool call together with its resolved binding and verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedToolCall {
    /// The normalized call that was checked.
    pub request: ToolCallRequest,
    /// The Typesec action the call was checked as (absent for unbound tools).
    pub action: Option<String>,
    /// The resolved resource id (absent for unbound tools or failed
    /// resource-argument resolution).
    pub resource: Option<String>,
    /// The verdict.
    pub verdict: ToolCallVerdict,
}

impl GuardedToolCall {
    /// Human-readable denial text for feeding back to the model, or `None`
    /// when the call is allowed.
    pub fn denial_message(&self) -> Option<String> {
        match &self.verdict {
            ToolCallVerdict::Allow => None,
            ToolCallVerdict::Deny { reason } => Some(format!(
                "Tool call '{}' was denied by security policy: {reason}",
                self.request.tool_name
            )),
            ToolCallVerdict::Delegate { reason } => Some(format!(
                "Tool call '{}' was not authorized (no policy engine decided): {reason}",
                self.request.tool_name
            )),
        }
    }
}
