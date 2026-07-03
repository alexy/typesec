"""MCP (Model Context Protocol) adapter.

For a Python MCP host or middleware::

    result = guard_request(gate, subject, jsonrpc_request)
    if result.all_allowed:
        ...forward to the server...
    else:
        respond(result.denials[0])   # complete JSON-RPC isError response

For a zero-code deployment, prefer the `typesec mcp-gate` CLI proxy.
"""

from __future__ import annotations

from typing import Any, Mapping

from .._native import ToolGate
from ..report import GuardResult, guard

DIALECT = "mcp"


def guard_request(
    gate: ToolGate,
    subject: str,
    request: Any,
    *,
    purpose: str | None = None,
    context: Mapping[str, str] | None = None,
) -> GuardResult:
    """Guard a JSON-RPC ``tools/call`` request (or a batch of requests).

    Blocked calls produce complete JSON-RPC responses carrying an
    ``isError: true`` tool result in ``result.denials``.
    """
    return guard(gate, subject, request, DIALECT, purpose=purpose, context=context)
