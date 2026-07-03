"""Typed reports over `ToolGate.guard_json` for whole model turns."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from ._native import ToolGate


@dataclass(frozen=True)
class ToolCallReport:
    """The verdict on one tool call within a model turn."""

    tool_name: str
    call_id: str | None
    action: str | None
    resource: str | None
    allowed: bool
    reason: str | None
    #: Framework-shaped payload to feed back to the model when blocked
    #: (an error tool-result / retry part); ``None`` when allowed.
    denial: dict[str, Any] | None


@dataclass(frozen=True)
class GuardResult:
    """All verdicts for one model turn, split by outcome."""

    calls: list[ToolCallReport]

    @property
    def allowed(self) -> list[ToolCallReport]:
        return [call for call in self.calls if call.allowed]

    @property
    def blocked(self) -> list[ToolCallReport]:
        return [call for call in self.calls if not call.allowed]

    @property
    def denials(self) -> list[dict[str, Any]]:
        """The framework-shaped denial payloads, ready to append/send."""
        return [call.denial for call in self.blocked if call.denial is not None]

    @property
    def all_allowed(self) -> bool:
        return not self.blocked


def guard(
    gate: ToolGate,
    subject: str,
    payload: Any,
    dialect: str,
    *,
    purpose: str | None = None,
    context: Mapping[str, str] | None = None,
) -> GuardResult:
    """Guard one model turn in any dialect and return typed verdicts.

    ``payload`` may be the framework object already serialized (a ``str``) or
    any JSON-serializable structure (the SDK's ``model_dump()`` output, a
    plain dict, a list of tool calls).
    """
    payload_json = payload if isinstance(payload, str) else json.dumps(payload)
    raw = gate.guard_json(
        subject, payload_json, dialect, purpose, dict(context) if context else None
    )
    calls = [
        ToolCallReport(
            tool_name=entry["tool_name"],
            call_id=entry.get("call_id"),
            action=entry.get("action"),
            resource=entry.get("resource"),
            allowed=entry["allowed"],
            reason=entry.get("reason"),
            denial=entry.get("denial"),
        )
        for entry in json.loads(raw)
    ]
    return GuardResult(calls=calls)
