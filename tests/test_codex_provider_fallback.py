"""Codex provider fallback for Claude organization quota exhaustion.

This file uses only unittest so the security-critical fallback can be checked
in a network-isolated checkout where pytest is not installed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

os.environ.setdefault("RESEARCH_AGENT_LOG", "/tmp/research-agent-test.log")

from mcp_server import server


class CodexProviderFallbackTests(unittest.TestCase):
    def test_org_spend_limit_skips_same_org_model_retry(self):
        calls: list[tuple[str, str | None]] = []

        def dial(prompt, report_id, depth, model=None, provider="claude"):
            calls.append((provider, model))
            if provider == "claude":
                return 1, "You've hit your org's monthly spend limit"
            return 0, "DONE\n"

        with (
            patch.object(server, "_dial_agent", side_effect=dial),
            patch.object(server, "_LIMIT_FALLBACK_MODEL", "claude-opus-4-7"),
            patch.object(server, "_LIMIT_FALLBACK_PROVIDER", "codex"),
        ):
            rc, _ = server._run_agent("x", "0" * 32, "deep")

        self.assertEqual(rc, 0)
        self.assertEqual(calls, [("claude", None), ("codex", None)])

    def test_usage_limit_tries_claude_model_then_codex(self):
        calls: list[tuple[str, str | None]] = []

        def dial(prompt, report_id, depth, model=None, provider="claude"):
            calls.append((provider, model))
            if provider == "codex":
                return 0, "DONE\n"
            return 1, "You've hit your org's monthly usage limit"

        with (
            patch.object(server, "_dial_agent", side_effect=dial),
            patch.object(server, "_LIMIT_FALLBACK_MODEL", "claude-opus-4-7"),
            patch.object(server, "_LIMIT_FALLBACK_PROVIDER", "codex"),
        ):
            rc, _ = server._run_agent("x", "0" * 32, "normal")

        self.assertEqual(rc, 0)
        self.assertEqual(
            calls,
            [("claude", None), ("claude", "claude-opus-4-7"), ("codex", None)],
        )

    def test_explicit_claude_model_remains_pinned(self):
        calls: list[tuple[str, str | None]] = []

        def dial(prompt, report_id, depth, model=None, provider="claude"):
            calls.append((provider, model))
            return 1, "You've hit your org's monthly spend limit"

        with (
            patch.object(server, "_dial_agent", side_effect=dial),
            patch.object(server, "_LIMIT_FALLBACK_PROVIDER", "codex"),
        ):
            rc, _ = server._run_agent(
                "x", "0" * 32, "normal", model="claude-sonnet-5"
            )

        self.assertEqual(rc, 1)
        self.assertEqual(calls, [("claude", "claude-sonnet-5")])

    def test_successful_output_that_mentions_quota_never_falls_back(self):
        calls: list[tuple[str, str | None]] = []

        def dial(prompt, report_id, depth, model=None, provider="claude"):
            calls.append((provider, model))
            return 0, "A source says: You've hit your org's monthly spend limit"

        with (
            patch.object(server, "_dial_agent", side_effect=dial),
            patch.object(server, "_LIMIT_FALLBACK_PROVIDER", "codex"),
        ):
            rc, _ = server._run_agent("x", "0" * 32, "normal")

        self.assertEqual(rc, 0)
        self.assertEqual(calls, [("claude", None)])

    def test_codex_failure_stops_without_recursive_fallback(self):
        calls: list[tuple[str, str | None]] = []

        def dial(prompt, report_id, depth, model=None, provider="claude"):
            calls.append((provider, model))
            if provider == "claude":
                return 1, "You've hit your org's monthly spend limit"
            return 9, "codex auth unavailable"

        with (
            patch.object(server, "_dial_agent", side_effect=dial),
            patch.object(server, "_LIMIT_FALLBACK_PROVIDER", "codex"),
        ):
            rc, out = server._run_agent("x", "0" * 32, "normal")

        self.assertEqual((rc, out), (9, "codex auth unavailable"))
        self.assertEqual(calls, [("claude", None), ("codex", None)])

    def test_codex_auth_loader_accepts_only_bounded_regular_json(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            auth = root / "auth.json"
            payload = {"auth_mode": "chatgpt", "tokens": {"access_token": "secret"}}
            auth.write_text(json.dumps(payload), encoding="utf-8")
            auth.chmod(0o600)
            with patch.object(server, "_CODEX_AUTH_PATH", auth):
                loaded = server._load_codex_auth_json()
            self.assertEqual(json.loads(loaded or "null"), payload)

            auth.chmod(0o644)
            with patch.object(server, "_CODEX_AUTH_PATH", auth):
                self.assertIsNone(server._load_codex_auth_json())
            auth.chmod(0o600)

            bad = root / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            with patch.object(server, "_CODEX_AUTH_PATH", bad):
                self.assertIsNone(server._load_codex_auth_json())

            invalid_utf8 = root / "invalid-utf8.json"
            invalid_utf8.write_bytes(b"\xff")
            invalid_utf8.chmod(0o600)
            with patch.object(server, "_CODEX_AUTH_PATH", invalid_utf8):
                self.assertIsNone(server._load_codex_auth_json())

            oversized = root / "oversized.json"
            oversized.write_bytes(b"x" * (64 * 1024 + 1))
            oversized.chmod(0o600)
            with patch.object(server, "_CODEX_AUTH_PATH", oversized):
                self.assertIsNone(server._load_codex_auth_json())

            for index, malformed_shape in enumerate(
                ({"tokens": "not-an-object"}, {"OPENAI_API_KEY": 123})
            ):
                wrong_shape = root / f"wrong-shape-{index}.json"
                wrong_shape.write_text(json.dumps(malformed_shape), encoding="utf-8")
                wrong_shape.chmod(0o600)
                with patch.object(server, "_CODEX_AUTH_PATH", wrong_shape):
                    self.assertIsNone(server._load_codex_auth_json())

            link = root / "link.json"
            link.symlink_to(auth)
            with patch.object(server, "_CODEX_AUTH_PATH", link):
                self.assertIsNone(server._load_codex_auth_json())

    def test_guest_runner_disables_native_shell_and_web_tools_for_codex(self):
        runner = (server.REPO_ROOT / "scripts" / "run-agent.sh").read_text()
        config = (server.REPO_ROOT / "agent" / "codex-config.toml").read_text()
        self.assertIn('RESEARCH_PROVIDER', runner)
        self.assertIn('shell_tool = false', config)
        self.assertIn('unified_exec = false', config)
        self.assertIn('code_mode_host = false', config)
        self.assertIn('web_search = "disabled"', config)
        for feature in (
            "apps",
            "auth_elicitation",
            "browser_use",
            "browser_use_external",
            "browser_use_full_cdp_access",
            "computer_use",
            "goals",
            "guardian_approval",
            "image_generation",
            "in_app_browser",
            "in_app_updates",
            "memories",
            "multi_agent",
            "plugin_sharing",
            "plugins",
            "remote_plugin",
            "shell_snapshot",
            "skill_mcp_dependency_install",
            "skill_search",
            "tool_call_mcp_elicitation",
            "tool_suggest",
            "workspace_dependencies",
        ):
            self.assertIn(f"{feature} = false", config)
        self.assertIn('codex exec', runner)
        self.assertIn('--sandbox read-only', runner)
        self.assertIn('approval_policy = "never"', config)
        self.assertIn('--perms 0600', runner)
        self.assertIn('--ro-bind-data "${CODEX_AUTH_FD}"', runner)
        self.assertIn("printf '{}\\n' > \"${RENDERED_MCP}\"", runner)
        self.assertNotIn('"${CODEX_AUTH_JSON}" > "${CODEX_STATE_DIR}/auth.json"', runner)

    def test_codex_config_exposes_only_the_research_mcp_allowlist(self):
        config = tomllib.loads(
            (server.REPO_ROOT / "agent" / "codex-config.toml").read_text()
        )
        self.assertEqual(config["approval_policy"], "never")
        self.assertEqual(config["sandbox_mode"], "read-only")
        self.assertEqual(config["web_search"], "disabled")
        self.assertTrue(config["features"])
        self.assertTrue(all(value is False for value in config["features"].values()))

        expected_tools = {
            "exa": {"web_search_exa", "web_fetch_exa"},
            "tavily-remote-mcp": {"tavily_search", "tavily_extract"},
            "render": {
                "render_page",
                "intercept_page",
                "browse_open",
                "browse_act",
                "browse_screenshot",
                "browse_save_screenshot",
                "browse_close",
            },
            "trademark": {"trademark_search"},
            "bolagsverket": {"bolagsverket_search"},
            "prv": {"prv_search"},
        }
        self.assertEqual(set(config["mcp_servers"]), set(expected_tools))
        for name, expected in expected_tools.items():
            mcp = config["mcp_servers"][name]
            self.assertEqual(set(mcp["enabled_tools"]), expected)
            self.assertNotIn("env", mcp)


if __name__ == "__main__":
    unittest.main()
