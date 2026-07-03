"""A real Pydantic AI agent guarded by the native Typesec ToolGate.

Where `pydantic_ai_capabilities.py` routes each check through the CLI, this
example uses the Rust-backed `typesec.ToolGate` directly — the same
deny-by-default guard the OpenAI/Anthropic/LangChain/MCP dialects share —
inside a live Pydantic AI agent run over `TestModel` (no credentials needed):

    uv run maturin develop -m crates/typesec-python/Cargo.toml
    uv run python examples/pydantic_ai_toolgate.py

The tool asks the gate before touching the resource; a denied subject gets a
PermissionError carrying the policy reason, which Pydantic AI surfaces as the
run's failure — the protected payload never reaches the model.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

from pydantic_ai import Agent, RunContext
from pydantic_ai.models.test import TestModel

try:
    from typesec import Decision, ToolGate
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "typesec is not installed in this environment.\n"
        "Build it first:  uv run maturin develop -m crates/typesec-python/Cargo.toml"
    ) from exc


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "policies" / "rbac-example.yaml"

# The deployment's tool manifest: the one place tool names acquire meaning.
TOOL_BINDINGS = [
    {"tool": "summarize_report", "action": "read", "resource": "reports/unspecified",
     "resource_arg": "report"},
]

REPORTS = {
    "reports/q1": "Q1 revenue grew 12% quarter over quarter; churn fell to 2.1%.",
}


def require_tool(gate: ToolGate, subject: str, tool: str, arguments_json: str) -> Decision:
    """Raise PermissionError (with the policy reason) unless the call is allowed."""
    decision = gate.check_tool(subject, tool, arguments_json)
    if not decision.allowed:
        raise PermissionError(decision.reason or "access denied")
    return decision


@dataclass
class GateDeps:
    gate: ToolGate
    subject: str


agent = Agent(
    TestModel(call_tools=["summarize_report"]),
    deps_type=GateDeps,
    output_type=str,
    instructions="Summarize verified reports with the summarize_report tool.",
)


@agent.tool
async def summarize_report(ctx: RunContext[GateDeps], report: str = "reports/q1") -> str:
    require_tool(ctx.deps.gate, ctx.deps.subject, "summarize_report",
                 f'{{"report": "{report}"}}')
    body = REPORTS[report]
    return f"[{report}] {body.split(';')[0]}."


async def main() -> None:
    gate = ToolGate.from_file(str(POLICY_PATH), TOOL_BINDINGS, "rbac")

    # analyst role: may read reports/* → the tool runs.
    allowed = await agent.run(
        "Summarize the Q1 report.", deps=GateDeps(gate, "agent:data-pipeline")
    )
    print(f"allowed: {allowed.output}")

    # engineer role: no read on reports/* → PermissionError, payload never
    # reaches the model.
    try:
        await agent.run("Summarize the Q1 report.", deps=GateDeps(gate, "agent:deploy-bot"))
        raise AssertionError("denied subject unexpectedly ran the tool")
    except PermissionError as exc:
        print(f"blocked as expected: {exc}")


if __name__ == "__main__":
    asyncio.run(main())
