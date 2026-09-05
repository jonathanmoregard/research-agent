"""Setup/infra failures are agent-readable; detections stay opaque.

The scanner rejects for two very different kinds of reason and they must
not share a disposition:

  * CONTENT-DERIVED (a detection) — `secret_shape:*`, `encoded_secret:*`,
    `unicode_anomaly:*`, `lakera:prompt_attack`, honeypot triggers. The
    reason is derived from attacker-controlled report bytes, so it stays
    opaque and quarantine-only. Unchanged by this module's feature.

  * SETUP / INFRA (an outage) — `*_unavailable:*` plus the bare
    `no-key` / `key-config-error` / `bad-response` codes. These are our
    own literals plus Python/SDK exception *type names*; injection-scanner
    deliberately keeps matched values out of `reason` (see the comments
    around injection_scanner/intercept.py:100/137/170). Those get
    surfaced to the caller and logged at ERROR so an operator's agent can
    diagnose a Lakera/honeypot outage without a quarantine dive.

Fail-closed is unchanged in BOTH cases: the report is never delivered and
is always quarantined. Only the *diagnosis* becomes visible.
"""
from __future__ import annotations

import json
import logging

import pytest

import mcp_server.server as srv
from injection_scanner.intercept import Verdict

# Canaries for every field that must never ride out on the visible path.
CANARY_BODY = "INFRA_VIS_BODY_CANARY_body000"
CANARY_API_ERROR_DETAIL = "INFRA_VIS_API_ERROR_DETAIL_CANARY_aed111"
CANARY_HONEYPOT_API_ERRORS = "INFRA_VIS_HONEYPOT_API_ERRORS_CANARY_hae222"
CANARY_RAW_EXCERPT = "INFRA_VIS_RAW_EXCERPT_CANARY_rex333"
CANARY_LAYER = "INFRA_VIS_LAYER_CANARY_lay444"
CANARY_STATS = "INFRA_VIS_STATS_CANARY_sta555"

ALL_CANARIES = (
    CANARY_BODY,
    CANARY_API_ERROR_DETAIL,
    CANARY_HONEYPOT_API_ERRORS,
    CANARY_RAW_EXCERPT,
    CANARY_LAYER,
    CANARY_STATS,
)

# The opaque reject payload as it exists today. A content-derived reject
# must stay byte-identical to this (modulo report_id / timings values).
OPAQUE_KEYS = {"status", "error", "report_id", "timings_ms"}
OPAQUE_ERROR = "scanner rejected report (quarantined)"

# The one key the infra path is allowed to add.
INFRA_KEY = "scanner_infra_reason"


def _verdict(reason: str) -> Verdict:
    """A failing Verdict stuffed with every forbidden field we know of.

    Anything the implementation copies wholesale (rather than naming an
    explicit allowlist of safe fields) drags a canary into the response.
    """
    return Verdict(
        ok=False,
        reason=reason,
        layers={
            "lakera": f"{reason} api_error_detail={CANARY_API_ERROR_DETAIL}",
            "honeypot": CANARY_LAYER,
            "honeypot_api_errors": CANARY_HONEYPOT_API_ERRORS,
            "raw_excerpt": CANARY_RAW_EXCERPT,
        },
        sanitize_stats={"stripped": 0, "text": CANARY_STATS},
        sanitized_text=CANARY_BODY,
    )


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(srv, "REPORTS_DIR", tmp_path)
    # Other modules' tests can leave the health gate degraded.
    srv._SCANNER_HEALTH.update(ok=True, reason="", last_check=0.0)
    return tmp_path


def _reject(monkeypatch, reason: str) -> dict:
    """Drive research() down the reject path with a stubbed scanner."""
    monkeypatch.setattr(srv, "_direct_exa", lambda p: (True, CANARY_BODY))
    monkeypatch.setattr(srv, "_scan_text", lambda text: _verdict(reason))
    return srv.research(prompt="ping", depth="fast")


# --------------------------------------------------------------------------
# The predicate itself
# --------------------------------------------------------------------------

INFRA_REASONS = [
    "lakera_unavailable:no-key",
    "lakera_unavailable:key-config-error",
    "lakera_unavailable:bad-response",
    "lakera_unavailable:HTTPError:429",
    "lakera_unavailable:TimeoutError",
    "unicode_sanitize_unavailable:unhandled:ValueError",
    "secret_shapes_unavailable:unhandled:RecursionError",
    "honeypot_unavailable:unhandled:ImportError",
    # intercept re-wraps the honeypot's own reason, so a real outage
    # reaches the server double-prefixed.
    "honeypot:honeypot_unavailable:tool_bait:unavailable:no-openai-api-key+skipped=6/6",
    "judge_unavailable:unhandled:RuntimeError",
    # Bare setup codes, in case a future call site emits one on its own.
    "no-key",
    "key-config-error",
    "bad-response",
]

CONTENT_REASONS = [
    "secret_shape:aws_access_key",
    "encoded_secret:base64:openai_key",
    "unicode_anomaly:stripped=91/1200",
    "lakera:prompt_attack",
    "lakera:flagged",
    "honeypot:honeypot:tool_bait:canary_in_arg:read_file",
    "wrap_escape:close_untrusted",
    # Arbitration only runs after Lakera flagged the text, so even a judge
    # outage here leaks "this report was flagged" — stays opaque.
    "lakera_arbitration:judge_unavailable:unhandled:RuntimeError",
    # Content length is content-derived.
    "oversized:1048576>524288",
    # The scanner blowing up is not on the named infra allowlist.
    "scanner_error:RuntimeError",
    # Novel / unrecognised codes default to opaque.
    "some_future_layer:whatever",
    "totally_novel_reason",
    "secret_shape:thing_unavailable",
    "",
    ":lakera_unavailable",
]


@pytest.mark.parametrize("reason", INFRA_REASONS)
def test_predicate_classifies_infra(reason):
    assert srv._is_infra_reason(reason) is True, reason


@pytest.mark.parametrize("reason", CONTENT_REASONS)
def test_predicate_defaults_to_opaque(reason):
    assert srv._is_infra_reason(reason) is False, reason


def test_predicate_rejects_non_strings():
    for bogus in (None, 42, ["lakera_unavailable:no-key"]):
        assert srv._is_infra_reason(bogus) is False


# --------------------------------------------------------------------------
# End-to-end through research()
# --------------------------------------------------------------------------

def test_infra_reason_is_surfaced_to_caller(reports_dir, monkeypatch):
    reason = "lakera_unavailable:HTTPError:429"
    result = _reject(monkeypatch, reason)
    assert result["status"] == "error"
    assert result[INFRA_KEY] == reason


def test_infra_reason_is_logged_at_error(reports_dir, monkeypatch, caplog):
    reason = "lakera_unavailable:HTTPError:429"
    with caplog.at_level(logging.ERROR, logger="research-agent"):
        _reject(monkeypatch, reason)
    hits = [
        r for r in caplog.records
        if r.levelno >= logging.ERROR and reason in r.getMessage()
    ]
    assert hits, f"infra reason not logged at ERROR: {[r.getMessage() for r in caplog.records]}"


def test_detection_reason_response_is_byte_identical_to_opaque(reports_dir, monkeypatch):
    result = _reject(monkeypatch, "lakera:prompt_attack")
    assert set(result) == OPAQUE_KEYS
    assert result["error"] == OPAQUE_ERROR
    assert INFRA_KEY not in result
    assert set(result["timings_ms"]) == {"agent", "scan", "total"}


@pytest.mark.parametrize(
    "reason",
    ["some_future_layer:whatever", "totally_novel_reason", "scanner_error:RuntimeError"],
)
def test_unrecognised_reason_defaults_to_opaque(reports_dir, monkeypatch, reason):
    result = _reject(monkeypatch, reason)
    assert set(result) == OPAQUE_KEYS
    assert INFRA_KEY not in result
    assert reason not in json.dumps(result)


def test_infra_response_carries_only_allowlisted_keys(reports_dir, monkeypatch):
    result = _reject(monkeypatch, "honeypot_unavailable:unhandled:ImportError")
    assert set(result) == OPAQUE_KEYS | {INFRA_KEY}
    assert result["error"] == OPAQUE_ERROR


def test_no_forbidden_field_reaches_the_caller(reports_dir, monkeypatch):
    """Positive assertion: none of the audit-only fields ride the infra path.

    `api_error_detail`, `honeypot_api_errors`, `raw_excerpt`,
    `sanitized_text` and the report bytes carry provider error bodies that
    can echo request fragments (injection-scanner 4cada8d added them as
    audit-only for exactly that reason).
    """
    result = _reject(monkeypatch, "lakera_unavailable:bad-response")
    blob = json.dumps(result)
    leaked = [c for c in ALL_CANARIES if c in blob]
    assert not leaked, f"forbidden content leaked via the infra path: {leaked}"
    for field in (
        "api_error_detail",
        "honeypot_api_errors",
        "raw_excerpt",
        "sanitized_text",
        "layers",
        "sanitize_stats",
    ):
        assert field not in blob, f"forbidden field name {field!r} present: {blob}"


def test_infra_reject_timing_is_still_bucketed(reports_dir, monkeypatch):
    result = _reject(monkeypatch, "lakera_unavailable:no-key")
    scan_ms = result["timings_ms"]["scan"]
    assert scan_ms % srv._SCAN_TIMING_BUCKET_MS == 0


@pytest.mark.parametrize(
    "reason", ["lakera_unavailable:no-key", "secret_shape:aws_access_key"]
)
def test_report_is_never_delivered_and_always_quarantined(
    reports_dir, monkeypatch, reason
):
    result = _reject(monkeypatch, reason)
    assert result["status"] == "error"
    assert "report" not in result
    assert "report_path" not in result
    # Nothing landed in the deliverable reports dir...
    assert list(reports_dir.glob("*.md")) == []
    # ...and the isolation zone got both the bytes and the audit row.
    zone = reports_dir / "_quarantine"
    assert [p.name for p in zone.glob("*.md")] == [f"{result['report_id']}.md"]
    audit = (zone / "audit.jsonl").read_text(encoding="utf-8")
    assert reason in audit
    assert CANARY_BODY in audit


def test_reject_response_default_is_unchanged():
    """_reject_response with no infra reason must keep its old shape."""
    out = srv._reject_response("rid", 10, 0.0, 0.0)
    assert set(out) == OPAQUE_KEYS
    assert out["error"] == OPAQUE_ERROR
    assert out["report_id"] == "rid"
