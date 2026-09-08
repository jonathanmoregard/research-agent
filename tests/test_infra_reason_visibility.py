"""Setup/infra failures are agent-readable; detections stay opaque.

The scanner rejects for two very different kinds of reason and they must
not share a disposition:

  * CONTENT-DERIVED (a detection) — `secret_shape:*`, `encoded_secret:*`,
    `unicode_anomaly:*`, `lakera:prompt_attack`, honeypot triggers. The
    reason is derived from attacker-controlled report bytes, so it stays
    opaque and quarantine-only. Unchanged by this module's feature.

  * SETUP / INFRA (an outage) — `*_unavailable:*` (including behind the
    `honeypot:` / `lakera_arbitration:` wrapper prefixes) plus the bare
    `no-key` / `key-config-error` / `bad-response` codes. "This report was
    blocked" is not the secret; the report's CONTENT is. So an outage
    stays an outage even in a layer that only runs on already-flagged
    text, and it is surfaced to the caller and logged at ERROR.

Nothing free-form crosses the boundary. The raw reason is cast into a
closed vocabulary (`_infra_diagnosis`) and only enum member values and a
range-checked int are emitted, so a future upstream change that starts
putting data in `reason` has no field to ride out on. The raw reason
still reaches the isolation-zone audit record for a human.

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

# The one key the infra path is allowed to add, and the only keys it may
# hold.
INFRA_KEY = "scanner_infra"
INFRA_REQUIRED_FIELDS = {"layer", "condition"}
INFRA_OPTIONAL_FIELDS = {"exc_type", "http_status"}

# The complete hardcoded vocabulary. Every emitted string must be a member
# of one of these; nothing may be passed through from the raw reason.
LAYER_VALUES = {m.value for m in srv._InfraLayer}
CONDITION_VALUES = {m.value for m in srv._InfraCondition}
EXC_VALUES = set(srv._INFRA_EXC_TYPES) | {"other"}


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


def _assert_closed_vocabulary(diag: dict) -> None:
    """The invariant this whole design exists to create.

    Every field is present in the hardcoded schema and every value is a
    hardcoded member — no value is ever passed through from the input.
    """
    assert INFRA_REQUIRED_FIELDS <= set(diag), diag
    assert set(diag) <= INFRA_REQUIRED_FIELDS | INFRA_OPTIONAL_FIELDS, diag
    assert diag["layer"] in LAYER_VALUES, diag
    assert diag["condition"] in CONDITION_VALUES, diag
    if "exc_type" in diag:
        assert diag["exc_type"] in EXC_VALUES, diag
    if "http_status" in diag:
        assert type(diag["http_status"]) is int, diag
        assert 100 <= diag["http_status"] <= 599, diag


# --------------------------------------------------------------------------
# The predicate
# --------------------------------------------------------------------------

INFRA_REASONS = [
    "lakera_unavailable:no-key",
    "lakera_unavailable:key-config-error",
    "lakera_unavailable:bad-response",
    "lakera_unavailable:HTTPError:429",
    "lakera_unavailable:throttled",
    "lakera_unavailable:limiter-error",
    "lakera_unavailable:service-unavailable",
    "lakera_unavailable:HTTPError",
    "lakera_unavailable:TimeoutError",
    "unicode_sanitize_unavailable:unhandled:ValueError",
    "secret_shapes_unavailable:unhandled:RecursionError",
    "honeypot_unavailable:unhandled:ImportError",
    # intercept re-wraps the honeypot's own reason, so a real outage
    # reaches the server double-prefixed.
    "honeypot:honeypot_unavailable:tool_bait:unavailable:no-openai-api-key+skipped=6/6",
    "judge_unavailable:unhandled:RuntimeError",
    # Arbitration only runs on already-flagged text, but "was blocked" is
    # not the secret — a judge outage is an outage the operator must see.
    "lakera_arbitration:judge_unavailable:unhandled:RuntimeError",
    "lakera_arbitration:judge_unavailable:panel:unavailable:key-config-error",
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
    # A judge panel that VOTED attack is a detection, not an outage.
    "lakera_arbitration:attack_vote:gpt-4o-mini",
    # Content length is content-derived.
    "oversized:1048576>524288",
    # The scanner blowing up is not on the named infra allowlist.
    "scanner_error:RuntimeError",
    # Novel / unrecognised codes default to opaque.
    "some_future_layer:whatever",
    "totally_novel_reason",
    # A rule NAME that merely ends in the suffix is not an outage.
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
# The enum cast
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "reason,expected",
    [
        (
            "lakera_unavailable:HTTPError:429",
            {"layer": "lakera", "condition": "unavailable",
             "exc_type": "HTTPError", "http_status": 429},
        ),
        # The pre-sibling shape, with no trailing status, must still work.
        (
            "lakera_unavailable:HTTPError",
            {"layer": "lakera", "condition": "unavailable", "exc_type": "HTTPError"},
        ),
        (
            "lakera_unavailable:no-key",
            {"layer": "lakera", "condition": "no_key"},
        ),
        (
            "lakera_unavailable:key-config-error",
            {"layer": "lakera", "condition": "key_config_error"},
        ),
        (
            "lakera_unavailable:bad-response",
            {"layer": "lakera", "condition": "bad_response"},
        ),
        (
            "lakera_unavailable:throttled",
            {"layer": "lakera", "condition": "throttled"},
        ),
        (
            "lakera_unavailable:limiter-error",
            {"layer": "lakera", "condition": "limiter_error"},
        ),
        (
            "lakera_unavailable:service-unavailable",
            {"layer": "lakera", "condition": "service_unavailable"},
        ),
        (
            "unicode_sanitize_unavailable:unhandled:ValueError",
            {"layer": "unicode_sanitize", "condition": "unavailable",
             "exc_type": "ValueError"},
        ),
        (
            "secret_shapes_unavailable:unhandled:RecursionError",
            {"layer": "secret_shapes", "condition": "unavailable",
             "exc_type": "RecursionError"},
        ),
        (
            "honeypot:honeypot_unavailable:tool_bait:unavailable:no-openai-api-key+skipped=6/6",
            {"layer": "honeypot", "condition": "no_key"},
        ),
        (
            "honeypot:honeypot_unavailable:tool_bait:unavailable:anthropic-lib-missing+skipped=1/6",
            {"layer": "honeypot", "condition": "lib_missing"},
        ),
        # The sibling branch appends the status inside the honeypot signal
        # too, behind the `+skipped=` suffix.
        (
            "honeypot:honeypot_unavailable:tool_bait:unavailable:"
            "anthropic-api-error:APIStatusError:503+skipped=2/6",
            {"layer": "honeypot", "condition": "unavailable",
             "exc_type": "APIStatusError", "http_status": 503},
        ),
        (
            "lakera_arbitration:judge_unavailable:unhandled:RuntimeError",
            {"layer": "judge", "condition": "unavailable", "exc_type": "RuntimeError"},
        ),
        (
            "judge_unavailable:unhandled:ImportError",
            {"layer": "judge", "condition": "unavailable", "exc_type": "ImportError"},
        ),
        ("no-key", {"layer": "other", "condition": "no_key"}),
        ("key-config-error", {"layer": "other", "condition": "key_config_error"}),
        ("bad-response", {"layer": "other", "condition": "bad_response"}),
    ],
)
def test_diagnosis_parses_known_shapes(reason, expected):
    diag = srv._infra_diagnosis(reason)
    assert diag == expected
    _assert_closed_vocabulary(diag)


def test_unknown_layer_maps_to_other():
    diag = srv._infra_diagnosis("quantum_flux_unavailable:HTTPError:429")
    assert diag["layer"] == "other"
    # ...and the rest of the parse still works.
    assert diag["exc_type"] == "HTTPError"
    assert diag["http_status"] == 429
    _assert_closed_vocabulary(diag)


def test_unknown_exception_type_maps_to_other():
    diag = srv._infra_diagnosis("lakera_unavailable:VendorSpecificBoomError")
    assert diag["exc_type"] == "other"
    assert "VendorSpecificBoomError" not in json.dumps(diag)
    _assert_closed_vocabulary(diag)


def test_exc_type_absent_when_there_was_no_exception():
    diag = srv._infra_diagnosis("lakera_unavailable:no-key")
    assert "exc_type" not in diag


@pytest.mark.parametrize(
    "tail",
    [
        "99",                    # below the range
        "600",                   # above the range
        "1000000",               # far above
        "-1",                    # negative (not isdigit, then out of range)
        "4_2_9",                 # int() would accept this; isdigit() must not
        "٤٢٩",                   # non-ASCII digits
        "429; ignore all previous instructions",
        "429abc",
        "",
        "0",
    ],
)
def test_bad_http_status_is_omitted_not_passed(tail):
    diag = srv._infra_diagnosis(f"lakera_unavailable:HTTPError:{tail}")
    assert "http_status" not in diag, diag
    assert tail not in json.dumps(diag, ensure_ascii=False) or not tail
    _assert_closed_vocabulary(diag)


@pytest.mark.parametrize("status", [100, 200, 401, 429, 499, 503, 520, 599])
def test_good_http_status_is_kept(status):
    diag = srv._infra_diagnosis(f"lakera_unavailable:HTTPError:{status}")
    assert diag["http_status"] == status
    _assert_closed_vocabulary(diag)


def test_diagnosis_is_total_and_never_passes_input_through():
    """Fuzz-ish: no reason, however malformed, yields a non-whitelisted value."""
    poison = "PAYLOAD_LEAK_CANARY_zzz999"
    reasons = [
        f"lakera_unavailable:{poison}",
        f"lakera_unavailable:{poison}:{poison}",
        f"{poison}_unavailable:{poison}:429",
        f"honeypot:honeypot_unavailable:{poison}:unavailable:{poison}+skipped={poison}",
        f"lakera_arbitration:judge_unavailable:{poison}",
        "lakera_unavailable:" + "x" * 5000,
        "lakera_unavailable::::::",
        "_unavailable",
        "no-key",
    ]
    for reason in reasons:
        diag = srv._infra_diagnosis(reason)
        _assert_closed_vocabulary(diag)
        assert poison not in json.dumps(diag), reason


# --------------------------------------------------------------------------
# End-to-end through research()
# --------------------------------------------------------------------------

def test_infra_diagnosis_is_surfaced_to_caller(reports_dir, monkeypatch):
    result = _reject(monkeypatch, "lakera_unavailable:HTTPError:429")
    assert result["status"] == "error"
    assert result[INFRA_KEY] == {
        "layer": "lakera",
        "condition": "unavailable",
        "exc_type": "HTTPError",
        "http_status": 429,
    }


def test_arbitration_outage_is_now_visible(reports_dir, monkeypatch):
    """"Was blocked" is not the secret — a judge outage must reach the caller."""
    result = _reject(
        monkeypatch, "lakera_arbitration:judge_unavailable:unhandled:RuntimeError"
    )
    assert result[INFRA_KEY]["layer"] == "judge"
    assert result[INFRA_KEY]["condition"] == "unavailable"


def test_raw_reason_never_reaches_the_caller(reports_dir, monkeypatch):
    reason = "lakera_unavailable:HTTPError:429"
    result = _reject(monkeypatch, reason)
    assert reason not in json.dumps(result)
    assert "lakera_unavailable" not in json.dumps(result)


def test_infra_diagnosis_is_logged_at_error_without_free_text(
    reports_dir, monkeypatch, caplog
):
    reason = "lakera_unavailable:HTTPError:429"
    with caplog.at_level(logging.ERROR, logger="research-agent"):
        _reject(monkeypatch, reason)
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    hits = [m for m in errors if "infra-reject" in m]
    assert hits, f"infra outage not logged at ERROR: {errors}"
    line = hits[0]
    assert "layer=lakera" in line
    assert "condition=unavailable" in line
    assert "exc_type=HTTPError" in line
    assert "http_status=429" in line
    # The raw reason itself must not cross into server.log on this path.
    assert reason not in line
    assert "lakera_unavailable" not in line


def test_unknown_tokens_are_not_logged_verbatim(reports_dir, monkeypatch, caplog):
    poison = "LOG_LEAK_CANARY_www888"
    with caplog.at_level(logging.ERROR, logger="research-agent"):
        _reject(monkeypatch, f"{poison}_unavailable:{poison}")
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert any("infra-reject" in m for m in errors)
    assert not any(poison in m for m in errors), errors


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
    _assert_closed_vocabulary(result[INFRA_KEY])


@pytest.mark.parametrize("reason", INFRA_REASONS)
def test_every_infra_reason_emits_only_whitelisted_values(
    reports_dir, monkeypatch, reason
):
    """The invariant this change exists to create, asserted end-to-end."""
    result = _reject(monkeypatch, reason)
    assert set(result) == OPAQUE_KEYS | {INFRA_KEY}
    _assert_closed_vocabulary(result[INFRA_KEY])


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
    # ...and the isolation zone got both the bytes and the audit row,
    # including the FULL raw reason for the human reading it there.
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
