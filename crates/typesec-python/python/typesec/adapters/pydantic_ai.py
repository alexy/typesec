"""Pydantic AI adapter.

Two enforcement points, usable together:

1. **Hide unauthorized tools up front** — pass :func:`prepare_tools_filter`
   to ``Agent(prepare_tools=...)``. Tools whose gate verdict is a deny are
   removed from the definitions the model sees, so it never tries them.
2. **Guard the response parts** — :func:`guard_response` checks the
   ``tool-call`` parts of a model response; blocked calls yield
   ``retry-prompt`` denial parts.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .._native import ToolGate
from ..report import GuardResult, guard

DIALECT = "pydantic-ai"


def guard_response(
    gate: ToolGate,
    subject: str,
    response: Any,
    *,
    purpose: str | None = None,
    context: Mapping[str, str] | None = None,
) -> GuardResult:
    """Guard the ``tool-call`` parts of a Pydantic AI model response."""
    return guard(gate, subject, response, DIALECT, purpose=purpose, context=context)


def prepare_tools_filter(
    gate: ToolGate,
    subject: str,
    *,
    purpose: str | None = None,
    context: Mapping[str, str] | None = None,
):
    """Build an ``Agent(prepare_tools=...)`` hook that hides denied tools.

    The hook keeps a tool definition only when the gate allows a call to it
    with empty arguments. Tools whose binding takes the resource from an
    argument cannot be pre-checked without arguments and are therefore kept —
    the call-time guard still applies. Nothing from Pydantic AI is imported:
    the hook works on any sequence of objects with a ``name`` attribute.
    """

    ctx_dict = dict(context) if context else None

    def allows(name: str) -> bool:
        decision = gate.check_tool(subject, name, None, purpose, ctx_dict)
        if decision.allowed:
            return True
        reason = decision.reason or ""
        # Keep per-argument-resource tools: their check needs the call's
        # arguments; deny-by-default still guards the actual call.
        return "requires string argument" in reason

    async def prepare_tools(_ctx: Any, tool_defs: Sequence[Any]) -> list[Any]:
        return [tool for tool in tool_defs if allows(tool.name)]

    return prepare_tools
