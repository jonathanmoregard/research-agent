"""_run_agent auto-retries with the Opus fallback model when the default
model hits its org-monthly usage limit."""
from __future__ import annotations

import subprocess

import mcp_server.server as server


class _Result:
    def __init__(self, rc: int, stdout: str = "", stderr: str = ""):
        self.returncode = rc
        self.stdout = stdout
        self.stderr = stderr


def _env(monkeypatch):
    monkeypatch.setenv("RESEARCH_SSH_HOST", "127.0.0.1")
    monkeypatch.setenv("RESEARCH_SSH_PORT", "2223")
    monkeypatch.setenv("RESEARCH_SSH_KEY", "/fake/key")
    monkeypatch.setattr(server, "_secrets", lambda: {"claude-token": "t"})
    monkeypatch.setattr(server, "_SSH_RETRIES", 0)  # keep ssh retry out of the picture
    monkeypatch.setattr(server, "_wait_for_sshd", lambda h, p, t: True)


def _capture_models(monkeypatch):
    """subprocess.run stub that records the RESEARCH_MODEL passed on each dial.

    The server encodes RESEARCH_MODEL into the joined remote_cmd (last
    ssh argv). Parsing that lets a single subprocess mock observe the
    model on each dial in order.
    """
    models: list[str | None] = []

    def _run(cmd, *a, **k):
        remote_cmd = cmd[-1]
        model = None
        for token in remote_cmd.split():
            if token.startswith("RESEARCH_MODEL="):
                model = token.split("=", 1)[1].strip("'\"")
                break
        models.append(model)
        # First dial: hit the limit; second (if any): succeed.
        if len(models) == 1:
            return _Result(1, "You've hit your org's monthly usage limit\n")
        return _Result(0, "")

    monkeypatch.setattr(subprocess, "run", _run)
    return models


def test_usage_limit_falls_back_to_opus(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setattr(server, "_LIMIT_FALLBACK_MODEL", "claude-opus-4-7")
    models = _capture_models(monkeypatch)
    rc, _out = server._run_agent(prompt="x", report_id="0" * 32, depth="normal")
    assert rc == 0
    assert models == [None, "claude-opus-4-7"]  # default then fallback


def test_usage_limit_with_explicit_model_does_not_fall_back(monkeypatch):
    """Caller intent wins: an explicit model=... never gets silently replaced."""
    _env(monkeypatch)
    monkeypatch.setattr(server, "_LIMIT_FALLBACK_MODEL", "claude-opus-4-7")
    calls: list[int] = []

    def _run(*a, **k):
        calls.append(1)
        return _Result(1, "You've hit your org's monthly usage limit\n")

    monkeypatch.setattr(subprocess, "run", _run)
    rc, out = server._run_agent(
        prompt="x", report_id="0" * 32, depth="normal", model="claude-sonnet-5"
    )
    assert rc == 1
    assert "usage limit" in out.lower()
    assert len(calls) == 1  # exactly one dial, no fallback


def test_non_limit_failure_does_not_fall_back(monkeypatch):
    """Only 'usage limit' triggers fallback; other rc!=0 outcomes surface as-is."""
    _env(monkeypatch)
    monkeypatch.setattr(server, "_LIMIT_FALLBACK_MODEL", "claude-opus-4-7")
    calls: list[int] = []

    def _run(*a, **k):
        calls.append(1)
        return _Result(2, "some other agent error\n")

    monkeypatch.setattr(subprocess, "run", _run)
    rc, _out = server._run_agent(prompt="x", report_id="0" * 32, depth="normal")
    assert rc == 2
    assert len(calls) == 1


def test_fallback_disabled_via_empty_env(monkeypatch):
    """Empty model and provider settings disable all quota fallback."""
    _env(monkeypatch)
    monkeypatch.setattr(server, "_LIMIT_FALLBACK_MODEL", "")
    monkeypatch.setattr(server, "_LIMIT_FALLBACK_PROVIDER", "")
    calls: list[int] = []

    def _run(*a, **k):
        calls.append(1)
        return _Result(1, "You've hit your org's monthly usage limit\n")

    monkeypatch.setattr(subprocess, "run", _run)
    rc, _out = server._run_agent(prompt="x", report_id="0" * 32, depth="normal")
    assert rc == 1
    assert len(calls) == 1  # no fallback since env-disabled


def test_hit_usage_limit_matches_case_insensitively():
    assert server._hit_usage_limit("You've hit your org's monthly usage limit") is True
    assert server._hit_usage_limit("YOU'VE HIT YOUR ORG'S MONTHLY SPEND LIMIT") is True
    assert server._hit_usage_limit("usage limit") is False
    assert server._hit_usage_limit("no such marker here") is False
    assert server._hit_usage_limit("") is False


def test_quota_diagnosis_is_closed_and_explains_model_pin():
    output = (
        "You've hit your org's monthly spend limit. "
        "ATTACKER_CONTROLLED_OUTPUT_CANARY"
    )
    assert server._agent_quota_diagnosis(output, model_pinned=True) == {
        "layer": "provider",
        "provider": "claude",
        "condition": "quota_exhausted",
        "fallback": "blocked_by_model_pin",
    }
    assert server._agent_quota_diagnosis(output, model_pinned=False) == {
        "layer": "provider",
        "provider": "claude",
        "condition": "quota_exhausted",
        "fallback": "unavailable",
    }


def test_quota_diagnosis_does_not_label_generic_failure():
    assert server._agent_quota_diagnosis(
        "Traceback: ATTACKER_CONTROLLED_OUTPUT_CANARY", model_pinned=True
    ) is None
