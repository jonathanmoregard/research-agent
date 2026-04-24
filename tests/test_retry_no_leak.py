"""
Regression test for `retry_research()`:

  1. If the second scan still fails, caller gets ZERO bytes of the
     quarantined content / matched snippet — only a generic error + the
     same report_id. File stays in quarantine. A fresh audit.jsonl entry
     is appended.
  2. If the second scan passes, the report is delivered (wrapped) to
     reports/<id>.md and the quarantine copy is gone.
  3. Path-traversal / malformed `report_id` values are rejected before
     any filesystem access.
  4. A valid-shape but non-existent `report_id` returns a not-found error
     without creating a spurious report file.

Run:
    uv run python3 tests/test_retry_no_leak.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from mcp_server import server as srv  # noqa: E402
from scanner.intercept import Verdict  # noqa: E402


CANARY_REASON = "RETRY_REASON_CANARY_abc123"
CANARY_BODY = "RETRY_BODY_CANARY_xyz789"
CANARY_SNIPPET = "RETRY_SNIPPET_CANARY_qqq000"


def _fail_verdict() -> Verdict:
    return Verdict(
        ok=False,
        reason=f"regex:role_swap: '{CANARY_REASON}'; secret_shape:aws: '{CANARY_SNIPPET}'",
        layers={"regex": f"fail:{CANARY_REASON}", "secret_shapes": f"fail:{CANARY_SNIPPET}"},
        sanitize_stats={"stripped": 0, "bidi_hits": 0, "tag_hits": 0, "zw_hits": 0, "nfkc_changed": False, "text": CANARY_BODY},
        sanitized_text=CANARY_BODY,
    )


def _pass_verdict() -> Verdict:
    return Verdict(
        ok=True,
        reason="pass",
        layers={"unicode_sanitize": "clean", "regex": "pass", "secret_shapes": "pass", "honeypot": "left_alone"},  # pragma: allowlist secret
        sanitize_stats={"stripped": 0, "bidi_hits": 0, "tag_hits": 0, "zw_hits": 0, "nfkc_changed": False, "text": CANARY_BODY},
        sanitized_text=CANARY_BODY,
    )


def _seed_quarantine(tmp: Path, report_id: str, body: str) -> Path:
    q = tmp / "_quarantine"
    q.mkdir(parents=True, exist_ok=True)
    p = q / f"{report_id}.md"
    p.write_text(body, encoding="utf-8")
    return p


def _with_stub_scan(verdict_factory):
    """Monkeypatch srv._scan_text to return the given verdict. Returns the
    original so the caller can restore it.
    """
    orig = srv._scan_text
    srv._scan_text = lambda text: verdict_factory()
    return orig


def _failures(results: list[str]) -> int:
    for r in results:
        print(f"FAIL: {r}")
    return 1 if results else 0


def case_retry_reject_no_leak(tmp: Path) -> list[str]:
    """Scenario 1: scan fails again; must not leak canaries."""
    report_id = "a" * 32
    srv.REPORTS_DIR = tmp
    quarantined = _seed_quarantine(tmp, report_id, CANARY_BODY)
    orig_scan = _with_stub_scan(_fail_verdict)
    try:
        result = srv.retry_research(report_id)
    finally:
        srv._scan_text = orig_scan

    failures: list[str] = []
    blob = json.dumps(result)
    for canary in (CANARY_REASON, CANARY_BODY, CANARY_SNIPPET):
        if canary in blob:
            failures.append(f"retry reject leaked canary {canary!r}: {blob}")

    if result.get("status") != "error":
        failures.append(f"expected status=error, got {result}")
    if result.get("report_id") != report_id:
        failures.append(f"expected report_id={report_id}, got {result.get('report_id')}")
    if not quarantined.exists():
        failures.append("rejected file left quarantine (should stay)")
    if (tmp / f"{report_id}.md").exists():
        failures.append("rejected file landed in reports/ (should not)")

    audit_path = tmp / "_quarantine" / "audit.jsonl"
    if not audit_path.exists():
        failures.append("audit.jsonl not written on retry")
    else:
        audit_blob = audit_path.read_text(encoding="utf-8")
        if CANARY_REASON not in audit_blob:
            failures.append("audit.jsonl missing retry reason")
        # Body must be in the audit record — operator diagnostic. Quarantine
        # zone is deny-listed, so no CC tool can read it back.
        if CANARY_BODY not in audit_blob:
            failures.append("audit.jsonl missing raw report bytes on retry")
    return failures


def case_retry_pass_delivers(tmp: Path) -> list[str]:
    """Scenario 2: scan passes; report moves to reports/ wrapped."""
    report_id = "b" * 32
    srv.REPORTS_DIR = tmp
    src = _seed_quarantine(tmp, report_id, CANARY_BODY)
    orig_scan = _with_stub_scan(_pass_verdict)
    try:
        result = srv.retry_research(report_id)
    finally:
        srv._scan_text = orig_scan

    failures: list[str] = []
    if result.get("status") != "done":
        failures.append(f"expected status=done, got {result}")
    expected_path = tmp / f"{report_id}.md"
    if str(expected_path) != result.get("report_path"):
        failures.append(f"expected report_path={expected_path}, got {result.get('report_path')}")
    if src.exists():
        failures.append("quarantined file not moved out on pass")
    if not expected_path.exists():
        failures.append("delivered file missing in reports/")
    else:
        delivered = expected_path.read_text(encoding="utf-8")
        if "<untrusted_external_content" not in delivered:
            failures.append("delivered file missing untrusted wrap")
        if CANARY_BODY not in delivered:
            failures.append("delivered file missing the sanitized body")
    # Feature: pass returns the wrapped report in the `report` field so
    # the caller can inline it without a separate Read.
    report = result.get("report")
    if not isinstance(report, str):
        failures.append(f"pass response missing `report` field: {result}")
    else:
        if "<untrusted_external_content" not in report:
            failures.append("`report` field missing untrusted wrap")
        if CANARY_BODY not in report:
            failures.append("`report` field missing sanitized body")
    return failures


def case_retry_path_traversal(tmp: Path) -> list[str]:
    """Scenario 3: malformed report_ids never touch the filesystem."""
    srv.REPORTS_DIR = tmp
    (tmp / "_quarantine").mkdir(exist_ok=True)
    # Plant a honey file *outside* the quarantine to prove path traversal
    # can't reach it.
    outside = tmp.parent / f"{tmp.name}-outside.md"
    outside.write_text("OUTSIDE_TARGET", encoding="utf-8")

    bad_ids = [
        "../../etc/passwd",
        "../outside",
        "/etc/passwd",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # uppercase — regex fails
        "short",
        "a" * 31,  # too short
        "a" * 33,  # too long
        "z" * 32,  # non-hex chars
        "../" + "a" * 29,
    ]
    orig_scan = _with_stub_scan(_fail_verdict)
    failures: list[str] = []
    try:
        for bad in bad_ids:
            result = srv.retry_research(bad)
            if result.get("status") != "error":
                failures.append(f"path-traversal id {bad!r} not rejected: {result}")
            if result.get("error") not in (
                "invalid report_id",
                "report_id not found in quarantine",
            ):
                failures.append(f"unexpected error for {bad!r}: {result}")
    finally:
        srv._scan_text = orig_scan
        outside.unlink(missing_ok=True)
    return failures


def case_retry_symlink_blocked(tmp: Path) -> list[str]:
    """A symlink planted at the quarantine source must be refused by the
    O_NOFOLLOW read — the scanner must never see /etc/passwd (or any other
    attacker-chosen file) as if it were the quarantined report.
    """
    report_id = "d" * 32
    srv.REPORTS_DIR = tmp
    q = tmp / "_quarantine"
    q.mkdir(parents=True, exist_ok=True)
    # Plant a file elsewhere the attacker wants to exfiltrate, then make
    # the quarantine entry a symlink to it.
    decoy = tmp / "decoy.txt"
    decoy.write_text("DECOY_SECRET_CONTENT", encoding="utf-8")
    sym = q / f"{report_id}.md"
    sym.symlink_to(decoy)
    orig_scan = _with_stub_scan(_pass_verdict)
    try:
        result = srv.retry_research(report_id)
    finally:
        srv._scan_text = orig_scan
        if sym.is_symlink() or sym.exists():
            sym.unlink(missing_ok=True)

    failures: list[str] = []
    blob = json.dumps(result)
    if "DECOY_SECRET_CONTENT" in blob:
        failures.append(f"symlink read delivered decoy content: {blob}")
    if result.get("status") != "error":
        failures.append(f"expected error on symlink, got {result}")
    if result.get("error") != "report_id not found in quarantine":
        failures.append(f"expected not-found, got {result.get('error')!r}")
    delivered = tmp / f"{report_id}.md"
    if delivered.exists():
        failures.append("symlink path led to a delivered report — bypass successful")
    return failures


def case_retry_missing(tmp: Path) -> list[str]:
    """Scenario 4: valid-shape id that doesn't exist in quarantine."""
    srv.REPORTS_DIR = tmp
    (tmp / "_quarantine").mkdir(exist_ok=True)
    orig_scan = _with_stub_scan(_fail_verdict)
    try:
        result = srv.retry_research("c" * 32)
    finally:
        srv._scan_text = orig_scan

    failures: list[str] = []
    if result.get("status") != "error":
        failures.append(f"missing id not rejected: {result}")
    if result.get("error") != "report_id not found in quarantine":
        failures.append(f"unexpected error: {result}")
    if (tmp / f"{'c' * 32}.md").exists():
        failures.append("missing id created a stray file in reports/")
    return failures


def main() -> int:
    cases = [
        ("retry_reject_no_leak", case_retry_reject_no_leak),
        ("retry_pass_delivers", case_retry_pass_delivers),
        ("retry_path_traversal", case_retry_path_traversal),
        ("retry_symlink_blocked", case_retry_symlink_blocked),
        ("retry_missing", case_retry_missing),
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
