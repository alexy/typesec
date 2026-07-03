"""LangChain / LangGraph adapter.

Typical tool node::

    result = guard_tool_calls(gate, subject, ai_message.tool_calls)
    messages = [run_tool(call) for call in result.allowed]
    messages += result.denials   # error ToolMessage dicts for blocked calls
"""

from __future__ import annotations

from typing import Any, Mapping

from .._native import ToolGate
from ..report import GuardResult, guard

DIALECT = "langchain"


def guard_tool_calls(
    gate: ToolGate,
    subject: str,
    tool_calls: Any,
    *,
    purpose: str | None = None,
    context: Mapping[str, str] | None = None,
) -> GuardResult:
    """Guard an ``AIMessage.tool_calls`` list (or a message dict holding one).

    Blocked calls produce error ``ToolMessage`` dicts (``status: "error"``)
    in ``result.denials``.
    """
    return guard(gate, subject, tool_calls, DIALECT, purpose=purpose, context=context)
