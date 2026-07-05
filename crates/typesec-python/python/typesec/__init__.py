"""Typesec: type-level security for AI agents.

The Rust core compiles a policy (RBAC / ODRL / graph YAML) once and answers
every decision; this package is the Python face of it:

- :class:`TypesecGate` — subject/action/resource decisions.
- :class:`ToolGate` — deny-by-default guarding of framework tool calls
  (OpenAI, Anthropic, LangChain, Pydantic AI, MCP wire shapes).
- :func:`guard` / :class:`ToolCallReport` — typed reports over a whole model
  turn, with framework-shaped denial payloads ready to send back.
- :mod:`typesec.adapters` — per-SDK helpers.
"""

from ._native import Decision, MemoryGate, ToolGate, TypesecGate, check, validate
from .report import GuardResult, ToolCallReport, guard

__all__ = [
    "Decision",
    "MemoryGate",
    "GuardResult",
    "ToolCallReport",
    "ToolGate",
    "TypesecGate",
    "check",
    "guard",
    "validate",
]
