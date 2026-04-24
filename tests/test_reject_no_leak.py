"""
Regression tests for every known leak surface on the reject path of
`research()`. Each case plants a canary the caller must never see, then
asserts the MCP return payload does not contain it.

Covered:
  1. Scanner reject          — verdict.reason / verdict.sanitized_text must
                                not leak to caller.
  2. Agent failure (exit!=0) — _output tail must not leak; full output
                                lands in reports/_quarantine/agent_failures.jsonl.
  3. Agent invocation raise  — exception message must not leak.
  4. Fast-mode Exa HTTP err  — response body bytes must not leak.
  5. Fast-mode Exa generic   — exception stringification must not leak.
  6. Scanner exception       — fail-closed: quarantine the content, generic
                                reject response, no traceback in return.
  7. Reject timing bucket    — timings_ms.scan must be bucketized so callers
                                can't fingerprint which layer rejected.

Run:
    uv run python3 tests/test_reject_no_leak.py
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import urllib.error
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from mcp_server import server as srv  # noqa: E402
from scanner.intercept import Verdict  # noqa: E402


CANARY_REASON = "REJECT_REASON_CANARY_abc123"
CANARY_BODY = "REJECT_BODY_CANARY_xyz789"
CANARY_SNIPPET = "REJECT_SNIPPET_CANARY_qqq000"
CANARY_AGENT_OUTPUT = "AGENT_OUTPUT_CANARY_leaks_via_minus500"
CANARY_AGENT_EXC = "AGENT_EXCEPTION_CANARY_wraps_as_error"
CANARY_EXA_BODY = "EXA_HTTP_BODY_CANARY_echoed_in_400"
CANARY_EXA_EXC = "EXA_EXC_CANARY_stringified"
CANARY_SCAN_EXC = "SCAN_EXC_CANARY_in_traceback"


def _fail_verdict() -> Verdict:
    return Verdict(
        ok=False,
        reason=f"regex:role_swap: '{CANARY_REASON}'; secret_shape:aws: '{CANARY_SNIPPET}'",
        layers={
            "regex": f"fail:{CANARY_REASON}",
            "secret_shapes": f"fail:{CANARY_SNIPPET}",
        },
        sanitize_stats={
            "stripped": 0, "bidi_hits": 0, "tag_hits": 0, "zw_hits": 0,
            "nfkc_changed": False, "text": CANARY_BODY,
        },
        sanitized_text=CANARY_BODY,
    )


def _with(obj, attr, replacement):
    orig = getattr(obj, attr)
    setattr(obj, attr, replacement)
    return orig


def _assert_no_canaries(blob: str, canaries: tuple[str, ...]) -> list[str]:
    return [c for c in canaries if c in blob]


def case_scanner_reject_no_leak(tmp: Path) -> list[str]:
    """Scanner fails; no reason/body/snippet in caller return."""
    srv.REPORTS_DIR = tmp
    o1 = _with(srv, "_direct_exa", lambda p: (True, CANARY_BODY))
    o2 = _with(srv, "_scan_text", lambda text: _fail_verdict())
    try:
        result = srv.research(prompt="ping", depth="fast")
    finally:
        srv._direct_exa = o1
        srv._scan_text = o2

    failures: list[str] = []
    blob = json.dumps(result)
    leaks = _assert_no_canaries(
        blob, (CANARY_REASON, CANARY_BODY, CANARY_SNIPPET)
    )
    if leaks:
        failures.append(f"scanner reject leaked canaries {leaks}: {blob}")
    if result.get("status") != "error":
        failures.append(f"expected status=error, got {result}")
    if "report_id" not in result:
        failures.append("report_id missing from reject return")
    audit_path = tmp / "_quarantine" / "audit.jsonl"
    if not audit_path.exists():
        failures.append("audit.jsonl not written")
    else:
        audit = audit_path.read_text(encoding="utf-8")
        if CANARY_REASON not in audit:
            failures.append("audit.jsonl missing reject reason")
        # Operator needs the full suspected-injection bytes in the audit
        # record for diagnosis. It lives in quarantine zone, deny-listed
        # from CC tools. This is intentional — see _write_quarantine_audit.
        if CANARY_BODY not in audit:
            failures.append("audit.jsonl missing raw report bytes — operator can't diagnose")
    return failures


def case_agent_failure_no_leak(tmp: Path) -> list[str]:
    """Non-zero agent exit: output tail must not reach caller."""
    srv.REPORTS_DIR = tmp

    def fake_run_agent(prompt, report_id, depth):
        return 1, f"Traceback ... {CANARY_AGENT_OUTPUT} ... done"

    o1 = _with(srv, "_run_agent", fake_run_agent)
    try:
        result = srv.research(prompt="x", depth="normal")
    finally:
        srv._run_agent = o1

    failures: list[str] = []
    blob = json.dumps(result)
    if CANARY_AGENT_OUTPUT in blob:
        failures.append(f"agent-failure leaked output canary: {blob}")
    if result.get("status") != "error":
        failures.append(f"expected status=error, got {result}")
    if result.get("error") != "agent failed":
        failures.append(f"expected generic 'agent failed', got {result.get('error')!r}")
    if "report_id" not in result:
        failures.append("report_id missing")
    log_path = tmp / "_quarantine" / "agent_failures.jsonl"
    if not log_path.exists():
        failures.append("agent_failures.jsonl not written to quarantine")
    else:
        log = log_path.read_text(encoding="utf-8")
        if CANARY_AGENT_OUTPUT not in log:
            failures.append("agent_failures.jsonl missing the output — operator can't diagnose")
    return failures


def case_agent_exception_no_leak(tmp: Path) -> list[str]:
    """_run_agent raises: exception str must not reach caller."""
    srv.REPORTS_DIR = tmp

    def fake_run_agent(prompt, report_id, depth):
        raise RuntimeError(CANARY_AGENT_EXC)

    o1 = _with(srv, "_run_agent", fake_run_agent)
    try:
        result = srv.research(prompt="x", depth="normal")
    finally:
        srv._run_agent = o1

    failures: list[str] = []
    blob = json.dumps(result)
    if CANARY_AGENT_EXC in blob:
        failures.append(f"agent-exception leaked canary: {blob}")
    if result.get("error") != "agent invocation failed":
        failures.append(f"expected generic 'agent invocation failed', got {result.get('error')!r}")
    return failures


def case_exa_http_error_no_leak(tmp: Path) -> list[str]:
    """_direct_exa HTTPError body must not reach caller."""
    srv.REPORTS_DIR = tmp

    def fake_urlopen(req, timeout=30):
        raise urllib.error.HTTPError(
            url="https://api.exa.ai/search",
            code=400,
            msg="Bad Request",
            hdrs=None,
            fp=io.BytesIO(f'{{"echo": "{CANARY_EXA_BODY}"}}'.encode()),
        )

    import urllib.request
    o1 = _with(urllib.request, "urlopen", fake_urlopen)
    o2 = _with(srv, "_secrets", lambda: {"exa-api-key": "fake"})
    try:
        result = srv.research(prompt="x", depth="fast")
    finally:
        urllib.request.urlopen = o1
        srv._secrets = o2

    failures: list[str] = []
    blob = json.dumps(result)
    if CANARY_EXA_BODY in blob:
        failures.append(f"exa http body leaked: {blob}")
    if "400" not in blob:
        failures.append(f"expected status code 400 in error, got {blob}")
    return failures


def case_exa_generic_exception_no_leak(tmp: Path) -> list[str]:
    """_direct_exa generic exception str must not reach caller."""
    srv.REPORTS_DIR = tmp

    def fake_urlopen(req, timeout=30):
        raise ConnectionError(f"connection refused to {CANARY_EXA_EXC}")

    import urllib.request
    o1 = _with(urllib.request, "urlopen", fake_urlopen)
    o2 = _with(srv, "_secrets", lambda: {"exa-api-key": "fake"})
    try:
        result = srv.research(prompt="x", depth="fast")
    finally:
        urllib.request.urlopen = o1
        srv._secrets = o2

    failures: list[str] = []
    blob = json.dumps(result)
    if CANARY_EXA_EXC in blob:
        failures.append(f"exa generic exception leaked: {blob}")
    return failures


def case_scanner_exception_failclosed(tmp: Path) -> list[str]:
    """Scanner itself raises: must be treated as reject + quarantined."""
    srv.REPORTS_DIR = tmp

    def raising_scan(text):
        raise RuntimeError(CANARY_SCAN_EXC)

    o1 = _with(srv, "_direct_exa", lambda p: (True, CANARY_BODY))
    o2 = _with(srv, "_scan_text", raising_scan)
    try:
        result = srv.research(prompt="x", depth="fast")
    finally:
        srv._direct_exa = o1
        srv._scan_text = o2

    failures: list[str] = []
    blob = json.dumps(result)
    if CANARY_SCAN_EXC in blob:
        failures.append(f"scanner-exception leaked canary: {blob}")
    if CANARY_BODY in blob:
        failures.append(f"scanner-exception leaked body: {blob}")
    if result.get("status") != "error":
        failures.append(f"expected status=error, got {result}")
    if result.get("error") != "scanner rejected report (quarantined)":
        failures.append(f"expected generic reject, got {result.get('error')!r}")
    q_path = tmp / "_quarantine"
    if not (q_path / "audit.jsonl").exists():
        failures.append("scanner exception path did not write audit.jsonl")
    # Content should be quarantined so the operator can diagnose.
    quarantined = list((q_path).glob("*.md"))
    if not quarantined:
        failures.append("scanner exception path did not write quarantine file")
    return failures


def case_reject_timing_bucketed(tmp: Path) -> list[str]:
    """Reject response's timings_ms.scan is bucketized, not raw."""
    srv.REPORTS_DIR = tmp
    o1 = _with(srv, "_direct_exa", lambda p: (True, CANARY_BODY))
    o2 = _with(srv, "_scan_text", lambda text: _fail_verdict())
    try:
        result = srv.research(prompt="x", depth="fast")
    finally:
        srv._direct_exa = o1
        srv._scan_text = o2

    failures: list[str] = []
    scan_ms = (result.get("timings_ms") or {}).get("scan")
    if scan_ms is None:
        failures.append(f"timings_ms.scan missing: {result}")
    elif scan_ms % srv._SCAN_TIMING_BUCKET_MS != 0:
        failures.append(
            f"timings_ms.scan={scan_ms} not a multiple of bucket {srv._SCAN_TIMING_BUCKET_MS}"
        )
    return failures


def main() -> int:
    cases = [
        ("scanner_reject_no_leak", case_scanner_reject_no_leak),
        ("agent_failure_no_leak", case_agent_failure_no_leak),
        ("agent_exception_no_leak", case_agent_exception_no_leak),
        ("exa_http_error_no_leak", case_exa_http_error_no_leak),
        ("exa_generic_exception_no_leak", case_exa_generic_exception_no_leak),
        ("scanner_exception_failclosed", case_scanner_exception_failclosed),
        ("reject_timing_bucketed", case_reject_timing_bucketed),
    ]
    failed = 0
    for name, fn in cases:
        with tempfile.TemporaryDirectory() as td:
            failures = fn(Path(td))
        if failures:
            failed += 1
            print(f"[{name}] FAIL")
            for f in failures:
                print(f"  - {f}")
        else:
            print(f"[{name}] OK")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
