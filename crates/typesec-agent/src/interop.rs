//! Wire-level interop: guard LLM tool calls from any agent framework.
//!
//! Agent frameworks (Pydantic AI, LangChain, the OpenAI and Anthropic SDKs)
//! all share the same last-mile shape: the model emits a *tool call* — a tool
//! name plus JSON arguments — and the host process decides whether to run it.
//! That decision point is exactly where Typesec belongs, and it is the one
//! place none of the frameworks guard for you.
//!
//! This module provides:
//!
//! - [`ToolCallRequest`] — a framework-neutral, normalized tool call.
//! - [`ToolBinding`] — the declaration of how one tool maps onto the Typesec
//!   `(action, resource)` plane, optionally taking the resource from a tool
//!   argument.
//! - [`ToolCallGuard`] — evaluates normalized calls against any
//!   [`PolicyEngine`](typesec_core::policy::PolicyEngine), **deny-by-default**
//!   for tools without a binding.
//! - Dialect codecs ([`openai`], [`anthropic`], [`langchain`],
//!   [`pydantic_ai`]) that parse each framework's wire shape into
//!   [`ToolCallRequest`]s and render denials back in the shape the framework
//!   expects (an error tool-result / retry part), so a blocked call flows back
//!   to the model as feedback instead of crashing the run.
//!
//! ```text
//! model output ─▶ dialect::parse_tool_calls ─▶ ToolCallGuard::check_all
//!                                                   │ Allow ─▶ run the tool
//!                                                   └ Deny  ─▶ dialect::denial ─▶ model
//! ```
//!
//! The typed [`ProtectedTool`](crate::ProtectedTool) path remains the
//! strongest boundary (a capability is required to *compile* the call); this
//! module is the runtime bridge for tools that live on the other side of a
//! JSON wire, where Rust types cannot reach.

mod call;
mod guard;
mod wire;

pub mod anthropic;
pub mod langchain;
pub mod openai;
pub mod pydantic_ai;

pub use call::{GuardedToolCall, InteropError, ToolBinding, ToolCallRequest, ToolCallVerdict};
pub use guard::ToolCallGuard;

#[cfg(test)]
mod tests;
