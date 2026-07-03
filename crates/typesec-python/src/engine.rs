//! Compiled policy engine wrapper over the RBAC/ODRL/graph backends.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use typesec_core::{
    ResourceId, SubjectId,
    policy::{PolicyEngine, PolicyResult, RequestContext},
};

use crate::format::PolicyFormat;

pub(crate) fn compile_policy(yaml: &str, format: PolicyFormat) -> PyResult<CompiledPolicyEngine> {
    match format {
        PolicyFormat::Rbac => {
            let engine = typesec_rbac::RbacEngine::from_yaml(yaml)
                .map_err(|err| PyValueError::new_err(format!("RBAC YAML parse error: {err}")))?;
            Ok(CompiledPolicyEngine::Rbac(engine))
        }
        PolicyFormat::Odrl => {
            let engine = typesec_odrl::OdrlEngine::from_yaml(yaml)
                .map_err(|err| PyValueError::new_err(format!("ODRL YAML parse error: {err}")))?;
            Ok(CompiledPolicyEngine::Odrl(engine))
        }
        PolicyFormat::Graph => {
            let engine = typesec_rbac::GraphPolicyEngine::from_yaml(yaml).map_err(|err| {
                PyValueError::new_err(format!("graph policy YAML parse error: {err}"))
            })?;
            Ok(CompiledPolicyEngine::Graph(engine))
        }
    }
}

pub(crate) enum CompiledPolicyEngine {
    Rbac(typesec_rbac::RbacEngine),
    Odrl(typesec_odrl::OdrlEngine),
    Graph(typesec_rbac::GraphPolicyEngine),
}

impl CompiledPolicyEngine {
    /// String-typed decision entry point used by `TypesecGate.check()`.
    pub(crate) fn decide(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        purpose: Option<&str>,
        context: Option<std::collections::HashMap<String, String>>,
    ) -> PolicyResult {
        let subject = SubjectId::from(subject);
        let resource = ResourceId::from(resource);
        self.check_with_context(
            &subject,
            action,
            &resource,
            &request_context(purpose, context),
        )
    }
}

/// The compiled engine is itself a [`PolicyEngine`], so it can back any
/// engine-generic machinery — in particular the tool-call guard.
impl PolicyEngine for CompiledPolicyEngine {
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        match self {
            Self::Rbac(engine) => engine.check(subject, action, resource),
            Self::Odrl(engine) => PolicyEngine::check(engine, subject, action, resource),
            Self::Graph(engine) => engine.check(subject, action, resource),
        }
    }

    fn check_with_context(
        &self,
        subject: &SubjectId,
        action: &str,
        resource: &ResourceId,
        ctx: &RequestContext,
    ) -> PolicyResult {
        match self {
            Self::Rbac(engine) => engine.check(subject, action, resource),
            Self::Odrl(engine) => {
                PolicyEngine::check_with_context(engine, subject, action, resource, ctx)
            }
            Self::Graph(engine) => engine.check(subject, action, resource),
        }
    }
}

pub(crate) fn request_context(
    purpose: Option<&str>,
    custom: Option<std::collections::HashMap<String, String>>,
) -> RequestContext {
    let mut ctx = RequestContext::default();
    if let Some(purpose) = purpose {
        ctx = ctx.with_purpose(purpose.to_string());
    }
    if let Some(custom) = custom {
        ctx.custom = custom;
    }
    ctx
}
