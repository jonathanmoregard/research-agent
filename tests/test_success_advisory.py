"""Successful quota fallback must stay visible to the calling model."""
from __future__ import annotations

import json

import pytest

import mcp_server.server as srv
from injection_scanner.intercept import Verdict
from injection_scanner.l2 import Outcome

LAKERA_429 = "lakera_unavailable:HTTPError:429"
LAKERA_THROTTLED = "lakera_unavailable:throttled"
MA_429 = "model_armor_unavailable:HTTPError:429"
MA_THROTTLED = "model_armor_unavailable:throttled"


def _advisory(*vendors: str) -> dict:
    return {
        "layer": "l2",
        "condition": "throttled",
        "vendors": list(vendors),
        "fallback": "strict_honeypot_unanimous_judges",
        "action": "warn_user",
    }


def _summary(outcome: Outcome, verdicts: int) -> str:
    return f"{outcome.value} verdicts={verdicts}/2 floor=2"


def _layers(lakera: str, model_armor: str, outcome: Outcome, **extra: str) -> dict:
    verdicts = sum(r in ("pass",) or r.endswith(":prompt_attack") for r in (lakera, model_armor))
    return {
        "lakera": lakera,
        "model_armor": model_armor,
        "l2": _summary(outcome, verdicts),
        "honeypot": "pass",
        "judge": "benign-unanimous",
        **extra,
    }


def _ok(layers: dict, text: str = "clean report") -> Verdict:
    return Verdict(ok=True, reason="pass", layers=layers, sanitize_stats={}, sanitized_text=text)


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(srv, "REPORTS_DIR", tmp_path)
    srv._SCANNER_HEALTH.update(ok=True, reason="", last_check=0.0)
    return tmp_path


def _research_success(monkeypatch, layers: dict) -> dict:
    monkeypatch.setattr(srv, "_direct_exa", lambda _prompt: (True, "clean report"))
    monkeypatch.setattr(srv, "_scan_text", lambda _text: _ok(layers))
    return srv.research(prompt="ping", depth="fast")


@pytest.mark.parametrize(
    "lakera, model_armor, vendors",
    [
        (LAKERA_429, "pass", ["lakera"]),
        (LAKERA_THROTTLED, "pass", ["lakera"]),
        ("pass", MA_429, ["model_armor"]),
        ("pass", MA_THROTTLED, ["model_armor"]),
        (LAKERA_THROTTLED, MA_429, ["lakera", "model_armor"]),
    ],
)
def test_quota_fallback_success_names_the_throttled_vendors(
    reports_dir, monkeypatch, lakera, model_armor, vendors
):
    result = _research_success(
        monkeypatch, _layers(lakera, model_armor, Outcome.DEGRADED_QUOTA)
    )

    assert result["status"] == "done"
    assert result["scanner_advisory"] == _advisory(*vendors)


@pytest.mark.parametrize("outcome", [Outcome.PASS, Outcome.FLAGGED])
def test_full_panel_success_has_no_scanner_advisory(reports_dir, monkeypatch, outcome):
    # FLAGGED + benign arbitration also delivers; both vendors answered, so
    # no coverage was lost to quota.
    lakera = "lakera:prompt_attack" if outcome is Outcome.FLAGGED else "pass"
    result = _research_success(monkeypatch, _layers(lakera, "pass", outcome))

    assert result["status"] == "done"
    assert "scanner_advisory" not in result


@pytest.mark.parametrize(
    "l2_summary", [None, "disabled (test-only)", "degraded-quota-ish verdicts=1/2", ""]
)
def test_unrecognised_panel_summary_never_claims_quota_fallback(
    reports_dir, monkeypatch, l2_summary
):
    layers = _layers(LAKERA_THROTTLED, "pass", Outcome.DEGRADED_QUOTA)
    if l2_summary is None:
        del layers["l2"]
    else:
        layers["l2"] = l2_summary
    result = _research_success(monkeypatch, layers)

    assert "scanner_advisory" not in result


def test_vendor_list_uses_exact_quota_literals(reports_dir, monkeypatch):
    """Only the exact quota-class reasons name a vendor."""
    layers = _layers(LAKERA_429 + "-extra", MA_THROTTLED, Outcome.DEGRADED_QUOTA)
    result = _research_success(monkeypatch, layers)

    assert result["scanner_advisory"] == _advisory("model_armor")


def test_advisory_never_copies_untrusted_layer_values(reports_dir, monkeypatch):
    poison = "SUCCESS_ADVISORY_LEAK_CANARY"
    layers = _layers(
        LAKERA_429, "pass", Outcome.DEGRADED_QUOTA, attacker_controlled=poison
    )
    result = _research_success(monkeypatch, layers)

    assert result["scanner_advisory"] == _advisory("lakera")
    assert poison not in json.dumps(result["scanner_advisory"])


def _research_with_artifact(monkeypatch, artifact: Verdict, report_layers: dict) -> dict:
    from mcp_server import artifact_gate

    verdicts = iter([_ok(report_layers), artifact])
    monkeypatch.setattr(srv, "_direct_exa", lambda _prompt: (True, "clean report"))
    monkeypatch.setattr(srv, "_scan_text", lambda _text: next(verdicts))

    def gate_one_artifact(_report_id, _reports_dir, scan_fn, **_kwargs):
        v = scan_fn("artifact OCR")
        return (["shot.png"], []) if v.ok else ([], ["shot.png"])

    monkeypatch.setattr(artifact_gate, "gate_artifacts", gate_one_artifact)
    return srv.research(prompt="ping", depth="fast")


def test_artifact_quota_fallback_also_tells_calling_model_to_warn_user(
    reports_dir, monkeypatch
):
    result = _research_with_artifact(
        monkeypatch,
        _ok(_layers("pass", MA_THROTTLED, Outcome.DEGRADED_QUOTA), "clean artifact OCR"),
        report_layers=_layers("pass", "pass", Outcome.PASS),
    )

    assert result["status"] == "done"
    assert result["scanner_advisory"] == _advisory("model_armor")


def test_vendors_are_merged_across_report_and_artifacts(reports_dir, monkeypatch):
    result = _research_with_artifact(
        monkeypatch,
        _ok(_layers("pass", MA_429, Outcome.DEGRADED_QUOTA), "clean artifact OCR"),
        report_layers=_layers(LAKERA_THROTTLED, "pass", Outcome.DEGRADED_QUOTA),
    )

    assert result["scanner_advisory"] == _advisory("lakera", "model_armor")


def test_rejected_artifact_does_not_claim_successful_quota_fallback(
    reports_dir, monkeypatch
):
    rejected = Verdict(
        ok=False,
        reason="l2_arbitration:attack:gpt-4o-mini",
        layers=_layers(LAKERA_THROTTLED, "pass", Outcome.DEGRADED_QUOTA, judge="attack:gpt-4o-mini"),
        sanitize_stats={},
        sanitized_text="rejected artifact OCR",
    )
    result = _research_with_artifact(
        monkeypatch, rejected, report_layers=_layers("pass", "pass", Outcome.PASS)
    )

    assert result["status"] == "done"
    assert result["artifacts"]["quarantined"] == ["shot.png"]
    assert "scanner_advisory" not in result


def test_degraded_panel_warns_even_when_no_vendor_reason_matches(reports_dir, monkeypatch):
    """The summary decides that the fallback ran; an unmatched vendor reason
    may shorten the list but never silences the warning."""
    layers = _layers(LAKERA_429 + "-extra", "pass", Outcome.DEGRADED_QUOTA)
    result = _research_success(monkeypatch, layers)

    assert result["scanner_advisory"] == _advisory()
