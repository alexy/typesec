"""Tests for the pure-Python `typesec` package layer over the native module.

Run from the repository root with:

    uv run maturin develop -m crates/typesec-python/Cargo.toml
    uv run python -m unittest discover -s tests/python
"""

from __future__ import annotations

import asyncio
import unittest
from dataclasses import dataclass
from pathlib import Path

try:
    from typesec import ToolGate, guard
    from typesec.adapters import anthropic as anthropic_adapter
    from typesec.adapters import mcp as mcp_adapter
    from typesec.adapters import openai as openai_adapter
    from typesec.adapters import pydantic_ai as pydantic_ai_adapter

    HAVE_NATIVE = True
except ImportError:  # pragma: no cover - environment without maturin develop
    HAVE_NATIVE = False

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "policies" / "rbac-example.yaml"

BINDINGS = [
    {"tool": "read_report", "action": "read", "resource": "reports/unspecified",
     "resource_arg": "report"},
    {"tool": "deploy_service", "action": "execute", "resource": "infra/prod"},
]


@unittest.skipUnless(HAVE_NATIVE, "typesec native module not built (run maturin develop)")
class ToolGatePackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = ToolGate.from_file(str(POLICY_PATH), BINDINGS, "rbac")

    def test_guard_returns_typed_reports(self) -> None:
        completion = {"choices": [{"message": {"tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "read_report",
                          "arguments": '{"report": "reports/q1"}'}},
            {"id": "c2", "type": "function",
             "function": {"name": "deploy_service", "arguments": "{}"}},
        ]}}]}
        result = guard(self.gate, "agent:data-pipeline", completion, "openai")
        self.assertEqual(len(result.calls), 2)
        self.assertEqual([c.tool_name for c in result.allowed], ["read_report"])
        self.assertEqual([c.tool_name for c in result.blocked], ["deploy_service"])
        self.assertFalse(result.all_allowed)
        (denial,) = result.denials
        self.assertEqual(denial["role"], "tool")
        self.assertEqual(denial["tool_call_id"], "c2")

    def test_openai_and_anthropic_adapters_fix_the_dialect(self) -> None:
        openai_result = openai_adapter.guard_completion(
            self.gate, "agent:deploy-bot",
            {"tool_calls": [{"id": "x", "function": {"name": "deploy_service",
                                                     "arguments": "{}"}}]},
        )
        self.assertTrue(openai_result.all_allowed)

        anthropic_result = anthropic_adapter.guard_message(
            self.gate, "agent:data-pipeline",
            {"content": [{"type": "tool_use", "id": "t1",
                          "name": "deploy_service", "input": {}}]},
        )
        (denial,) = anthropic_result.denials
        self.assertEqual(denial["type"], "tool_result")
        self.assertTrue(denial["is_error"])

    def test_mcp_adapter_returns_jsonrpc_denials(self) -> None:
        request = {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                   "params": {"name": "rm_rf", "arguments": {}}}
        result = mcp_adapter.guard_request(self.gate, "agent:superadmin", request)
        (denial,) = result.denials
        self.assertEqual(denial["id"], 5)
        self.assertTrue(denial["result"]["isError"])

    def test_prepare_tools_filter_hides_denied_tools(self) -> None:
        @dataclass
        class FakeToolDef:
            name: str

        hook = pydantic_ai_adapter.prepare_tools_filter(self.gate, "agent:data-pipeline")
        tools = [FakeToolDef("read_report"), FakeToolDef("deploy_service"),
                 FakeToolDef("unbound_tool")]
        kept = asyncio.run(hook(None, tools))
        # read_report is kept (per-argument resource: checked at call time);
        # deploy_service is a policy deny; unbound_tool has no binding.
        self.assertEqual([t.name for t in kept], ["read_report"])



@unittest.skipUnless(HAVE_NATIVE, "typesec native module not built (run maturin develop)")
class MemoryGateTests(unittest.TestCase):
    POLICY = """
roles:
  - name: keeper
    permissions: [read, write, delete]
    resources: ["memory/**"]
assignments:
  - subject: "agent:keeper"
    roles: [keeper]
"""

    def setUp(self) -> None:
        from typesec import MemoryGate

        self.gate = MemoryGate(self.POLICY, "rbac")

    def test_remember_recall_forget(self) -> None:
        import json

        mem_id = self.gate.remember(
            "agent:keeper", "memory/user:alice/profile", "prefers dark mode"
        )
        recall = json.loads(
            self.gate.recall("agent:keeper", "memory/user:alice/profile")
        )
        self.assertEqual([h["text"] for h in recall["hits"]], ["prefers dark mode"])

        # Public clearance redacts the Internal-labeled record.
        public = json.loads(
            self.gate.recall(
                "agent:keeper", "memory/user:alice/profile", clearance="public"
            )
        )
        self.assertEqual(public["hits"], [])
        self.assertEqual(len(public["redacted"]), 1)

        self.assertEqual(
            self.gate.forget("agent:keeper", "memory/user:alice/profile", [mem_id]),
            [mem_id],
        )

    def test_denied_subject_raises_permission_error(self) -> None:
        with self.assertRaises(PermissionError):
            self.gate.remember("agent:stranger", "memory/user:alice/profile", "x")

if __name__ == "__main__":
    unittest.main()
