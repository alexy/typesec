"""OpenAI Chat Completions adapter.

Typical loop::

    completion = client.chat.completions.create(..., tools=tools)
    result = guard_completion(gate, subject, completion.model_dump())
    for call in result.allowed:
        ...run the tool, append its result...
    messages.extend(result.denials)   # role:"tool" refusals for blocked calls
"""

from __future__ import annotations

from typing import Any, Mapping

from .._native import ToolGate
from ..report import GuardResult, guard

DIALECT = "openai"


def guard_completion(
    gate: ToolGate,
    subject: str,
    completion: Any,
    *,
    purpose: str | None = None,
    context: Mapping[str, str] | None = None,
) -> GuardResult:
    """Guard the tool calls in a chat completion (or assistant message).

    Blocked calls produce ``{"role": "tool", ...}`` denial messages in
    ``result.denials``, ready to append to the chat history.
    """
    return guard(gate, subject, completion, DIALECT, purpose=purpose, context=context)
