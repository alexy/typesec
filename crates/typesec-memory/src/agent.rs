//! The agent surface (`agent` feature): memory as guarded tool calls.
//!
//! The LLM never touches the vault directly. It emits tool calls —
//! `memory.recall` / `memory.remember` / `memory.forget` — that flow through
//! the same deny-by-default [`ToolCallGuard`](typesec_agent::interop) as every
//! other tool, in all five dialects. [`memory_bindings`] declares the mapping
//! from those tool names to the Typesec `(action, resource)` plane (the
//! resource is taken from each call's `space` argument), and
//! [`MemoryToolRouter`] executes an *authorized* call against a vault by
//! minting the matching capability through a policy engine.

use std::sync::Arc;

use serde_json::{Value, json};
use typesec_agent::interop::{ToolBinding, ToolCallRequest};
use typesec_core::policy::{MintOptions, PolicyEngine, RequestContext, mint_capability_for_id};
use typesec_core::{CanDelete, CanRead, CanWrite, Capability};

use crate::error::MemoryError;
use crate::label::Label;
use crate::record::{MemoryContent, MemoryDraft, Provenance};
use crate::space::{MemoryKind, MemorySpace};
use crate::store::MemoryStore;
use crate::vault::{ForgetSelector, MemoryVault, RecallQuery};

/// Tool name for recall.
pub const TOOL_RECALL: &str = "memory.recall";
/// Tool name for remember.
pub const TOOL_REMEMBER: &str = "memory.remember";
/// Tool name for forget.
pub const TOOL_FORGET: &str = "memory.forget";

/// The standard memory tool bindings, resource-scoped by the `space` argument.
///
/// Register these on a [`ToolCallGuard`](typesec_agent::interop::ToolCallGuard):
/// then guarding, denial rendering, policy-aware listing, and proxy scrubbing
/// all apply to memory exactly as to any other tool. `remember` requires
/// `space` and `text`; `recall`/`forget` require `space`.
pub fn memory_bindings() -> Vec<ToolBinding> {
    vec![
        ToolBinding::new(TOOL_RECALL, "read", "memory/unspecified").resource_from_arg("space"),
        ToolBinding::new(TOOL_REMEMBER, "write", "memory/unspecified")
            .resource_from_arg("space")
            .require_args(["text"]),
        ToolBinding::new(TOOL_FORGET, "delete", "memory/unspecified").resource_from_arg("space"),
    ]
}

/// Executes authorized memory tool calls against a vault.
///
/// The router mints the capability each op needs (running the policy engine,
/// which emits the standard mint audit event), then calls the vault — so even
/// this path cannot bypass authorization. It is engine-agnostic: RBAC, ODRL,
/// graph, or any composition.
pub struct MemoryToolRouter<S: MemoryStore> {
    vault: MemoryVault<S>,
    engine: Arc<dyn PolicyEngine>,
}

impl<S: MemoryStore> MemoryToolRouter<S> {
    /// Build a router over `vault`, minting capabilities through `engine`.
    pub fn new(vault: MemoryVault<S>, engine: Arc<dyn PolicyEngine>) -> Self {
        Self { vault, engine }
    }

    /// Borrow the underlying vault.
    pub fn vault(&self) -> &MemoryVault<S> {
        &self.vault
    }

    /// Dispatch one normalized memory tool call for `subject`, returning a
    /// JSON result. Unknown tools and missing arguments are errors — the
    /// caller should have guarded the call first, but the router re-validates.
    pub fn handle(
        &self,
        subject: &str,
        call: &ToolCallRequest,
        ctx: &RequestContext,
    ) -> Result<Value, MemoryError> {
        let space = MemorySpace::new(
            owner_of(arg_str(call, "space")?),
            space_name_of(arg_str(call, "space")?),
        );
        match call.tool_name.as_str() {
            TOOL_REMEMBER => self.remember(subject, &space, call),
            TOOL_RECALL => self.recall(subject, &space, call, ctx),
            TOOL_FORGET => self.forget(subject, &space, call),
            other => Err(MemoryError::Store(crate::store::StoreError::Backend(
                format!("unknown memory tool '{other}'"),
            ))),
        }
    }

    fn mint<P: typesec_core::Permission>(
        &self,
        subject: &str,
        space: &MemorySpace,
    ) -> Result<Capability<P, MemorySpace>, MemoryError> {
        mint_capability_for_id(
            self.engine.as_ref(),
            subject,
            resource_id(space),
            &MintOptions::default(),
        )
        .map_err(|err| MemoryError::PolicyDenied {
            action: P::name(),
            detail: err.to_string(),
        })
    }

    fn remember(
        &self,
        subject: &str,
        space: &MemorySpace,
        call: &ToolCallRequest,
    ) -> Result<Value, MemoryError> {
        let cap: Capability<CanWrite, _> = self.mint(subject, space)?;
        let text = arg_str(call, "text")?.to_string();
        let kind = arg_str(call, "kind")
            .ok()
            .map(parse_kind)
            .unwrap_or(MemoryKind::Semantic);
        // Tool-originated writes are model-adjacent: born from Conversation
        // provenance (quarantine only for genuinely raw model text via a
        // dedicated flag). Callers wanting a stronger source use the vault.
        let draft = MemoryDraft::new(kind, MemoryContent::text(text), Provenance::Conversation);
        let id = self.vault.remember(space, &cap, draft)?;
        Ok(json!({ "id": id.as_str() }))
    }

    fn recall(
        &self,
        subject: &str,
        space: &MemorySpace,
        call: &ToolCallRequest,
        ctx: &RequestContext,
    ) -> Result<Value, MemoryError> {
        let cap: Capability<CanRead, _> = self.mint(subject, space)?;
        let ceiling = arg_str(call, "clearance")
            .ok()
            .map(Label::from_name)
            .unwrap_or(Label::Internal);
        let query = match arg_str(call, "query").ok() {
            Some(text) if !text.is_empty() => RecallQuery::text(text),
            _ => RecallQuery::all(),
        };
        let (hits, redacted) = self.vault.recall_at(space, &cap, query, ctx, ceiling)?;
        Ok(json!({
            "hits": hits.iter().map(|h| json!({
                "id": h.id.as_str(),
                "text": h.content.text,
                "label": h.label.name(),
                "kind": format!("{:?}", h.kind).to_lowercase(),
            })).collect::<Vec<_>>(),
            "redacted": redacted.iter().map(|r| json!({
                "id": r.id.as_str(),
                "label": r.label.name(),
            })).collect::<Vec<_>>(),
        }))
    }

    fn forget(
        &self,
        subject: &str,
        space: &MemorySpace,
        call: &ToolCallRequest,
    ) -> Result<Value, MemoryError> {
        let cap: Capability<CanDelete, _> = self.mint(subject, space)?;
        let ids = call
            .arguments
            .get("ids")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(crate::space::MemoryId::from_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let tomb = self.vault.forget(space, &cap, ForgetSelector::Ids(ids))?;
        Ok(json!({
            "forgotten": tomb.forgotten.iter().map(|id| id.as_str()).collect::<Vec<_>>(),
        }))
    }
}

fn arg_str<'a>(call: &'a ToolCallRequest, key: &str) -> Result<&'a str, MemoryError> {
    call.arguments
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            MemoryError::Store(crate::store::StoreError::Backend(format!(
                "memory tool call is missing string argument '{key}'"
            )))
        })
}

fn parse_kind(name: &str) -> MemoryKind {
    match name {
        "episodic" => MemoryKind::Episodic,
        "procedural" => MemoryKind::Procedural,
        "profile" => MemoryKind::Profile,
        _ => MemoryKind::Semantic,
    }
}

// A `space` argument is the full resource id `memory/<owner>/<space>`. Split it
// back into owner/name to rebuild the MemorySpace (whose resource id must then
// equal the argument the call was guarded against).
fn owner_of(space_arg: &str) -> String {
    let rest = space_arg.strip_prefix("memory/").unwrap_or(space_arg);
    rest.rsplit_once('/')
        .map_or_else(|| rest.to_string(), |(owner, _)| owner.to_string())
}

fn space_name_of(space_arg: &str) -> String {
    space_arg
        .rsplit_once('/')
        .map_or_else(|| space_arg.to_string(), |(_, name)| name.to_string())
}

fn resource_id(space: &MemorySpace) -> String {
    use typesec_core::Resource;
    space.resource_id().to_string()
}

#[cfg(test)]
mod tests;
