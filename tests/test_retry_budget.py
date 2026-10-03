"""retry_research must not turn a stochastic detector into a best-of-N lottery.

Security review 2026-10-03 (C-1): a reject is re-scanned from the same bytes
on every `retry_research` call, with no memory of earlier verdicts. The
honeypot layer samples at the provider default temperature, so an injection
it catches only some of the time is delivered after enough retries.

Policy under test:
  - a CONTENT-derived reject (a detection) may be re-scanned at most
    RESEARCH_MAX_CONTENT_RETRIES times (default 1, so one false-positive
    resample survives);
  - an INFRA reject (scanner outage) stays retryable without limit, because
    the report was never actually judged;
  - the refusal leaks nothing and leaves the report in quarantine.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from injection_scanner.intercept import Verdict  # noqa: E402
from mcp_server import server as srv  # noqa: E402

BODY = "BUDGET_BODY_CANARY"
RID = "d" * 32


def _verdict(ok: bool, reason: str) -> Verdict:
    return Verdict(ok=ok, reason=reason, layers={}, sanitize_stats={},
                   sanitized_text=BODY)


DETECTION = "honeypot:Honeypot_Triggered:scenario_b"
OUTAGE = "lakera_unavailable:URLError"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(srv, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(srv, "_scanner_health_gate", lambda: (True, "ok"))
    import mcp_server.artifact_gate as ag
    monkeypatch.setattr(ag, "discard_artifacts", lambda rid: None)
    monkeypatch.setattr(ag, "gate_artifacts", lambda *a, **k: ([], []))
    return tmp_path


def _first_reject(monkeypatch, reason: str) -> None:
    """Produce the quarantine state exactly as research() would."""
    monkeypatch.setattr(srv, "_scan_text", lambda t: _verdict(False, reason))
    out = srv._scan_and_deliver(BODY, RID, "prompt", 0, 0.0, 0.0)
    assert out["status"] == "error"


def test_detection_is_not_a_lottery(env, monkeypatch):
    _first_reject(monkeypatch, DETECTION)
    # Every later scan "flips" to pass: the lottery an attacker wants to win.
    monkeypatch.setattr(srv, "_scan_text", lambda t: _verdict(True, "pass"))
    results = []
    monkeypatch.setattr(srv, "_scan_text", lambda t: _verdict(False, DETECTION))
    results.append(srv.retry_research(RID))  # retry 1: still detected
    monkeypatch.setattr(srv, "_scan_text", lambda t: _verdict(True, "pass"))
    results.append(srv.retry_research(RID))  # retry 2: would pass -> must be refused
    assert results[0]["status"] == "error"
    assert results[1]["status"] == "error", "second resample of a detection was delivered"
    assert "retry limit" in results[1]["error"]
    assert BODY not in repr(results[1])
    assert not (env / f"{RID}.md").exists()


def test_one_false_positive_resample_still_delivers(env, monkeypatch):
    _first_reject(monkeypatch, DETECTION)
    monkeypatch.setattr(srv, "_scan_text", lambda t: _verdict(True, "pass"))
    out = srv.retry_research(RID)
    assert out["status"] == "done"


def test_infra_reject_stays_retryable(env, monkeypatch):
    _first_reject(monkeypatch, OUTAGE)
    for _ in range(3):
        out = srv.retry_research(RID)
        assert "retry limit" not in out.get("error", "")
    monkeypatch.setattr(srv, "_scan_text", lambda t: _verdict(True, "pass"))
    assert srv.retry_research(RID)["status"] == "done"


def test_budget_is_configurable(env, monkeypatch):
    monkeypatch.setattr(srv, "_MAX_CONTENT_RETRIES", 0)
    _first_reject(monkeypatch, DETECTION)
    monkeypatch.setattr(srv, "_scan_text", lambda t: _verdict(True, "pass"))
    out = srv.retry_research(RID)
    assert out["status"] == "error" and "retry limit" in out["error"]


# A honeypot "unavailable" whose signal is the judge model's own malformed
# output is shaped by the report, not by an outage: a report can make the
# model emit broken tool calls (or run it past max_tokens) on purpose.
# Those must spend the content budget, not ride the free infra retry.
@pytest.mark.parametrize("signal", [
    "unavailable:malformed-tool-call",
    "unavailable:malformed-tool-args",
    "unavailable:unreadable-tool-call",
    "unavailable:anthropic-parse-error:ValueError",
])
def test_content_shaped_honeypot_skip_spends_the_budget(env, monkeypatch, signal):
    reason = f"honeypot_unavailable:scenario_a:{signal}+skipped=1/6"
    _first_reject(monkeypatch, reason)
    monkeypatch.setattr(srv, "_scan_text", lambda t: _verdict(False, reason))
    srv.retry_research(RID)  # the one allowed resample
    monkeypatch.setattr(srv, "_scan_text", lambda t: _verdict(True, "pass"))
    out = srv.retry_research(RID)
    assert out["status"] == "error" and "retry limit" in out["error"]


def test_provider_outage_skip_stays_free(env, monkeypatch):
    reason = "honeypot_unavailable:scenario_a:unavailable:anthropic-api-error:APIConnectionError+skipped=6/6"
    _first_reject(monkeypatch, reason)
    for _ in range(3):
        assert "retry limit" not in srv.retry_research(RID).get("error", "")
