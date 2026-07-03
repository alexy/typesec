//! Named dialect registry: one dispatch table shared by every binding layer
//! (Python, WASM, the CLI) so dialect names can't drift between them.

use serde_json::Value;

use super::call::{GuardedToolCall, InteropError, ToolCallRequest};
use super::{anthropic, langchain, mcp, openai, pydantic_ai};

/// Parse a framework payload into normalized tool calls.
pub type ParseFn = fn(&Value) -> Result<Vec<ToolCallRequest>, InteropError>;
/// Render a denied call in the framework's feedback shape.
pub type DenialFn = fn(&GuardedToolCall) -> Option<Value>;
/// Filter a tool-definition list by name predicate.
pub type FilterFn = fn(&Value, &dyn Fn(&str) -> bool) -> Value;

/// The codec functions for one framework dialect.
pub struct Dialect {
    /// Canonical dialect name (`openai`, `anthropic`, `langchain`,
    /// `pydantic-ai`, `mcp`).
    pub name: &'static str,
    /// Parse the framework's tool-call payload into normalized requests.
    pub parse: ParseFn,
    /// Render a denied call in the framework's feedback shape.
    pub denial: DenialFn,
    /// Filter a tool-definition list by name predicate.
    pub filter: FilterFn,
}

/// Every supported dialect.
pub const DIALECTS: &[Dialect] = &[
    Dialect {
        name: openai::DIALECT,
        parse: openai::parse_tool_calls,
        denial: openai::denial,
        filter: openai::filter_tools,
    },
    Dialect {
        name: anthropic::DIALECT,
        parse: anthropic::parse_tool_calls,
        denial: anthropic::denial,
        filter: anthropic::filter_tools,
    },
    Dialect {
        name: langchain::DIALECT,
        parse: langchain::parse_tool_calls,
        denial: langchain::denial,
        filter: langchain::filter_tools,
    },
    Dialect {
        name: pydantic_ai::DIALECT,
        parse: pydantic_ai::parse_tool_calls,
        denial: pydantic_ai::denial,
        filter: pydantic_ai::filter_tools,
    },
    Dialect {
        name: mcp::DIALECT,
        parse: mcp::parse_tool_calls,
        denial: mcp::denial,
        filter: mcp::filter_tools,
    },
];

/// Look up a dialect by name (`pydantic_ai` is accepted for `pydantic-ai`).
pub fn dialect(name: &str) -> Option<&'static Dialect> {
    let canonical = if name == "pydantic_ai" {
        "pydantic-ai"
    } else {
        name
    };
    DIALECTS.iter().find(|dialect| dialect.name == canonical)
}

/// The message used when a dialect name is unknown.
pub fn unknown_dialect_message(name: &str) -> String {
    format!("unknown dialect '{name}' (expected openai, anthropic, langchain, pydantic-ai, or mcp)")
}
