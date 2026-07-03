"""Anthropic Messages adapter.

Typical loop::

    message = client.messages.create(..., tools=tools)
    result = guard_message(gate, subject, message.model_dump())
    for call in result.allowed:
        ...run the tool, collect its tool_result block...
    tool_results.extend(result.denials)   # is_error tool_result blocks
    # send tool_results back as the next user message's content
"""

from __future__ import annotations

from typing import Any, Mapping

from .._native import ToolGate
from ..report import GuardResult, guard

DIALECT = "anthropic"


def guard_message(
    gate: ToolGate,
    subject: str,
    message: Any,
    *,
    purpose: str | None = None,
    context: Mapping[str, str] | None = None,
) -> GuardResult:
    """Guard the ``tool_use`` blocks in an Anthropic message.

    Blocked calls produce ``tool_result`` blocks with ``is_error: true`` in
    ``result.denials``, ready for the follow-up user message.
    """
    return guard(gate, subject, message, DIALECT, purpose=purpose, context=context)
