"""Successful quota fallback must stay visible to the calling model."""
from __future__ import annotations

import json

import pytest

import mcp_server.server as srv
from injection_scanner.intercept import Verdict


ADVISORY = {
    "layer": "lakera",
    "condition": "throttled",
    "fallback": "strict_honeypot_unanimous_judges",
    "action": "warn_user",
}


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(srv, "REPORTS_DIR", tmp_path)
    srv._SCANNER_HEALTH.update(ok=True, reason="", last_check=0.0)
    return tmp_path


def _research_success(monkeypatch, lakera_reason: str, **extra_layers: str) -> dict:
    layers = {
        "lakera": lakera_reason,
        "honeypot": "pass",
        "judge": "benign-unanimous",
        **extra_layers,
    }
    monkeypatch.setattr(srv, "_direct_exa", lambda _prompt: (True, "clean report"))
    monkeypatch.setattr(
        srv,
        "_scan_text",
        lambda _text: Verdict(
            ok=True,
            reason="pass",
            layers=layers,
            sanitize_stats={},
            sanitized_text="clean report",
        ),
    )
    return srv.research(prompt="ping", depth="fast")


@pytest.mark.parametrize(
    "lakera_reason",
    ["lakera_unavailable:HTTPError:429", "lakera_unavailable:throttled"],
)
def test_quota_fallback_success_tells_calling_model_to_warn_user(
    reports_dir, monkeypatch, lakera_reason
):
    result = _research_success(monkeypatch, lakera_reason)

    assert result["status"] == "done"
    assert result["scanner_advisory"] == ADVISORY


def test_normal_success_has_no_scanner_advisory(reports_dir, monkeypatch):
    result = _research_success(monkeypatch, "pass")

    assert result["status"] == "done"
    assert "scanner_advisory" not in result


def test_artifact_quota_fallback_also_tells_calling_model_to_warn_user(
    reports_dir, monkeypatch
):
    from mcp_server import artifact_gate

    verdicts = iter(
        [
            Verdict(
                ok=True,
                reason="pass",
                layers={"lakera": "pass", "honeypot": "pass"},
                sanitize_stats={},
                sanitized_text="clean report",
            ),
            Verdict(
                ok=True,
                reason="pass",
                layers={
                    "lakera": "lakera_unavailable:throttled",
                    "honeypot": "pass",
                    "judge": "benign-unanimous",
                },
                sanitize_stats={},
                sanitized_text="clean artifact OCR",
            ),
        ]
    )
    monkeypatch.setattr(srv, "_direct_exa", lambda _prompt: (True, "clean report"))
    monkeypatch.setattr(srv, "_scan_text", lambda _text: next(verdicts))

    def gate_one_artifact(_report_id, _reports_dir, scan_fn, **_kwargs):
        assert scan_fn("clean artifact OCR").ok
        return ["shot.png"], []

    monkeypatch.setattr(artifact_gate, "gate_artifacts", gate_one_artifact)

    result = srv.research(prompt="ping", depth="fast")

    assert result["status"] == "done"
    assert result["scanner_advisory"] == ADVISORY


def test_rejected_artifact_does_not_claim_successful_quota_fallback(
    reports_dir, monkeypatch
):
    from mcp_server import artifact_gate

    verdicts = iter(
        [
            Verdict(
                ok=True,
                reason="pass",
                layers={"lakera": "pass", "honeypot": "pass"},
                sanitize_stats={},
                sanitized_text="clean report",
            ),
            Verdict(
                ok=False,
                reason="lakera_arbitration:attack_vote",
                layers={
                    "lakera": "lakera_unavailable:throttled",
                    "honeypot": "pass",
                    "judge": "attack-vote",
                },
                sanitize_stats={},
                sanitized_text="rejected artifact OCR",
            ),
        ]
    )
    monkeypatch.setattr(srv, "_direct_exa", lambda _prompt: (True, "clean report"))
    monkeypatch.setattr(srv, "_scan_text", lambda _text: next(verdicts))

    def gate_one_artifact(_report_id, _reports_dir, scan_fn, **_kwargs):
        assert not scan_fn("rejected artifact OCR").ok
        return [], ["shot.png"]

    monkeypatch.setattr(artifact_gate, "gate_artifacts", gate_one_artifact)

    result = srv.research(prompt="ping", depth="fast")

    assert result["status"] == "done"
    assert "scanner_advisory" not in result


def test_advisory_never_copies_untrusted_layer_values(reports_dir, monkeypatch):
    poison = "SUCCESS_ADVISORY_LEAK_CANARY"
    result = _research_success(
        monkeypatch,
        "lakera_unavailable:HTTPError:429",
        attacker_controlled=poison,
    )

    assert result["scanner_advisory"] == ADVISORY
    assert poison not in json.dumps(result["scanner_advisory"])


@pytest.mark.parametrize(
    "lakera_reason",
    [
        "lakera_unavailable:HTTPError:429-extra",
        "lakera_unavailable:service-unavailable",
        "lakera_unavailable:limiter-error",
    ],
)
def test_non_quota_states_never_claim_quota_fallback(
    reports_dir, monkeypatch, lakera_reason
):
    result = _research_success(monkeypatch, lakera_reason)

    assert "scanner_advisory" not in result
