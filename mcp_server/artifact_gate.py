"""Post-run screenshot artifact gate.

Pulls the run's screenshots from the scraper microvm, OCRs each with
tesseract, feeds the extracted text through the same ensemble injection
scanner the report went through, and saves passers to
reports/<report_id>/artifacts/ (quarantining failures). Fail-closed:
any OCR or scan error quarantines the image.

The OCR gate is best-effort by design (spec: adversarial rendering that
tesseract can't read will pass) — it raises the bar, it is not a proof.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

SCRAPER_HOST_API = os.environ.get("SCRAPER_HOST_API", "http://127.0.0.1:8123")
SCRAPER_HOST_TOKEN_FILE = os.environ.get(
    "SCRAPER_HOST_TOKEN_FILE", "/var/lib/scraper-bearer/token"
)
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_ARTIFACTS = 10
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\.(png|jpg)$")
_FETCH_CAP = 40 * 1024 * 1024  # 10 x 2 MiB payload, b64-inflated + JSON slack


def _token() -> str:
    with open(SCRAPER_HOST_TOKEN_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()


def fetch_artifacts(run_id: str) -> list[dict]:
    """GET (take-and-clear) the run's artifacts. [] on any failure —
    a broken pull must never block report delivery."""
    req = urllib.request.Request(
        f"{SCRAPER_HOST_API}/artifacts/{run_id}",
        headers={"Authorization": f"Bearer {_token()}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read(_FETCH_CAP)
        out = json.loads(body)
        items = out.get("artifacts") or []
        return items if isinstance(items, list) else []
    except Exception as e:
        print(f"research-agent: artifact fetch failed for {run_id}: "
              f"{type(e).__name__}", file=sys.stderr)
        return []


def discard_artifacts(run_id: str) -> None:
    """Best-effort clear (report-quarantined path)."""
    req = urllib.request.Request(
        f"{SCRAPER_HOST_API}/artifacts/{run_id}",
        headers={"Authorization": f"Bearer {_token()}"},
        method="DELETE",
    )
    try:
        urllib.request.urlopen(req, timeout=15).read(1024)
    except Exception:
        pass


def ocr_image(path: Path) -> str:
    """tesseract <path> stdout. Raises on any failure (caller fails closed)."""
    out = subprocess.run(
        ["tesseract", str(path), "stdout"],
        capture_output=True, text=True, timeout=60,
    )
    if out.returncode != 0:
        raise RuntimeError(f"tesseract rc={out.returncode}: {out.stderr[:200]}")
    return out.stdout


def gate_artifacts(
    report_id: str,
    reports_dir: Path,
    scan_fn,                      # _scan_text — returns Verdict(ok, reason, ...)
    audit_fn=None,                # (report_id, name, reason, ocr_text) -> None
    fetcher=fetch_artifacts,
    ocr_fn=ocr_image,
) -> tuple[list[str], list[str]]:
    """Returns (saved_names, quarantined_names). Never raises."""
    saved: list[str] = []
    quarantined: list[str] = []
    items = fetcher(report_id)
    if not items:
        return saved, quarantined
    art_dir = reports_dir / report_id / "artifacts"
    q_dir = reports_dir / "_quarantine" / report_id / "artifacts"

    for item in items[:MAX_ARTIFACTS]:
        name = item.get("name") or ""
        if not _NAME_RE.match(name):
            name = "unsafe-" + hashlib.sha256(name.encode()).hexdigest()[:12] + ".png"
            reason = "unsafe_name"
            data = b""
            try:
                data = base64.b64decode(item.get("data_b64") or "", validate=True)
            except Exception:
                pass
            _quarantine(q_dir, name, data, reason, "", report_id, audit_fn)
            quarantined.append(name)
            continue
        try:
            data = base64.b64decode(item.get("data_b64") or "", validate=True)
        except Exception:
            _quarantine(q_dir, name, b"", "bad_base64", "", report_id, audit_fn)
            quarantined.append(name)
            continue
        if not data or len(data) > MAX_ARTIFACT_BYTES:
            _quarantine(q_dir, name, data[:MAX_ARTIFACT_BYTES], "bad_size", "",
                        report_id, audit_fn)
            quarantined.append(name)
            continue
        # OCR -> scan. Any exception on either => fail closed.
        try:
            with tempfile.NamedTemporaryFile(
                suffix=Path(name).suffix, delete=False
            ) as tf:
                tf.write(data)
                tmp = Path(tf.name)
            try:
                text = ocr_fn(tmp)
            finally:
                tmp.unlink(missing_ok=True)
            verdict = scan_fn(text)
            ok, reason = bool(verdict.ok), getattr(verdict, "reason", "")
        except Exception as e:
            ok, reason, text = False, f"ocr_error:{type(e).__name__}", ""
        if ok:
            art_dir.mkdir(parents=True, exist_ok=True)
            _write_new(art_dir / name, data)
            saved.append(name)
        else:
            _quarantine(q_dir, name, data, reason, text, report_id, audit_fn)
            quarantined.append(name)
    return saved, quarantined


def _write_new(path: Path, data: bytes) -> None:
    """O_EXCL|O_NOFOLLOW like the report writes — no symlink redirect."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _quarantine(q_dir, name, data, reason, ocr_text, report_id, audit_fn) -> None:
    try:
        q_dir.mkdir(parents=True, exist_ok=True)
        _write_new(q_dir / name, data)
    except OSError as e:
        print(f"research-agent: artifact quarantine write failed "
              f"{report_id}/{name}: {e}", file=sys.stderr)
    if audit_fn is not None:
        audit_fn(report_id, name, reason, ocr_text[:2000])


_ARTIFACT_LINK = re.compile(r"\]\(artifacts/([a-zA-Z0-9._-]+)\)")


def rewrite_artifact_links(
    text: str, report_id: str, saved: list[str], quarantined: list[str]
) -> str:
    """Agent writes ](artifacts/<name>). Saved -> ](<report_id>/artifacts/<name>)
    (resolves relative to reports/); quarantined/unknown -> inert note."""
    def _sub(m):
        name = m.group(1)
        if name in saved:
            return f"]({report_id}/artifacts/{name})"
        return f"] (artifact quarantined: {name})"
    return _ARTIFACT_LINK.sub(_sub, text)
