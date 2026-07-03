#![no_main]

use libfuzzer_sys::fuzz_target;
use typesec_agent::interop::{anthropic, langchain, mcp, openai, pydantic_ai};

// The dialect codecs are the interop plane's untrusted-input surface: they
// parse whatever a model or framework put on the wire. Each parser must
// return Ok or Err — never panic — for arbitrary JSON.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let _ = openai::parse_tool_calls(&value);
    let _ = anthropic::parse_tool_calls(&value);
    let _ = langchain::parse_tool_calls(&value);
    let _ = pydantic_ai::parse_tool_calls(&value);
    let _ = mcp::parse_tool_calls(&value);
});
