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
# 10 x 2 MiB b64-inflated (~27 MiB) + JSON slack
_FETCH_CAP = 40 * 1024 * 1024


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
    """Best-effort clear (report-isolated path)."""
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


# ---------------------------------------------------------------------------
# Dir-fd walk helpers — defeat symlink-planted-at-component attacks.
# Never import from server.py (circular). Keep all fds in finally blocks.
# ---------------------------------------------------------------------------

def _open_dir_nofollow(parent_fd: int, name: str) -> int:
    """Open directory `name` relative to `parent_fd`, refusing to follow
    symlinks (raises OSError / ELOOP / ENOTDIR if `name` is a symlink).
    """
    return os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent_fd,
    )


def _ensure_dir_nofollow(parent_fd: int, name: str) -> int:
    """mkdir `name` under `parent_fd` (ignoring EEXIST), then open it with
    O_NOFOLLOW.  Returns the new dir fd.  Raises if `name` is a symlink.
    """
    try:
        os.mkdir(name, 0o755, dir_fd=parent_fd)
    except FileExistsError:
        pass
    return _open_dir_nofollow(parent_fd, name)


def _write_nofollow_excl(leaf_fd: int, fname: str, data: bytes) -> None:
    """Write `data` to `fname` relative to `leaf_fd`, O_EXCL | O_NOFOLLOW."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(fname, flags, 0o644, dir_fd=leaf_fd)
    try:
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(data)
    finally:
        if fd >= 0:
            os.close(fd)


def _make_art_dir_fd(reports_dir: Path, report_id: str) -> int:
    """Open/create reports/<report_id>/artifacts/ via dir-fd walk.

    Each component is opened with O_NOFOLLOW so a pre-planted symlink at
    any intermediate path cannot redirect writes.  Returns leaf dir fd.
    """
    root_fd = os.open(str(reports_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        rid_fd = _ensure_dir_nofollow(root_fd, report_id)
    finally:
        os.close(root_fd)
    try:
        art_fd = _ensure_dir_nofollow(rid_fd, "artifacts")
    finally:
        os.close(rid_fd)
    return art_fd


def _make_q_art_dir_fd(reports_dir: Path, report_id: str) -> int:
    """Open/create reports/_quarantine/<report_id>/artifacts/ via dir-fd walk."""
    root_fd = os.open(str(reports_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        q_fd = _ensure_dir_nofollow(root_fd, "_quarantine")
    finally:
        os.close(root_fd)
    try:
        rid_fd = _ensure_dir_nofollow(q_fd, report_id)
    finally:
        os.close(q_fd)
    try:
        art_fd = _ensure_dir_nofollow(rid_fd, "artifacts")
    finally:
        os.close(rid_fd)
    return art_fd


# ---------------------------------------------------------------------------
# Public gate
# ---------------------------------------------------------------------------

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
    try:
        items = fetcher(report_id)
        if not items:
            return saved, quarantined

        for item in items[:MAX_ARTIFACTS]:
            try:
                _process_item(
                    item, report_id, reports_dir,
                    scan_fn, audit_fn, ocr_fn,
                    saved, quarantined,
                )
            except Exception as exc:
                # Per-item fallback: best-effort audit and continue.
                try:
                    name = (item.get("name") or "unknown") if isinstance(item, dict) else "unknown"
                    print(f"research-agent: item processing error {report_id}/{name}: "
                          f"{type(exc).__name__}: {exc}", file=sys.stderr)
                    if audit_fn is not None:
                        try:
                            audit_fn(report_id, name, f"item_error:{type(exc).__name__}", "")
                        except Exception:
                            pass
                    if name not in quarantined and name not in saved:
                        quarantined.append(name)
                except Exception:
                    pass

    except Exception as exc:
        # Final fallback — gate must never propagate.
        print(f"research-agent: gate_artifacts fatal error {report_id}: "
              f"{type(exc).__name__}: {exc}", file=sys.stderr)

    return saved, quarantined


def _process_item(
    item,
    report_id: str,
    reports_dir: Path,
    scan_fn,
    audit_fn,
    ocr_fn,
    saved: list[str],
    quarantined: list[str],
) -> None:
    """Process one fetched artifact item. May raise — caller handles."""
    # Non-dict item: skip with audit.
    if not isinstance(item, dict):
        reason = "non_dict_item"
        name = f"unsafe-{hashlib.sha256(repr(item).encode('utf-8', 'replace')).hexdigest()[:12]}.png"
        _do_audit(audit_fn, report_id, name, reason, "")
        quarantined.append(name)
        return

    name = item.get("name") or ""
    # Validate name with fullmatch to reject trailing newlines and partial matches.
    if not _NAME_RE.fullmatch(name):
        safe_name = "unsafe-" + hashlib.sha256(
            name.encode("utf-8", "replace")
        ).hexdigest()[:12] + ".png"
        data = b""
        try:
            data = base64.b64decode(item.get("data_b64") or "", validate=True)
        except Exception:
            pass
        _do_quarantine_fd(reports_dir, report_id, safe_name, data, "unsafe_name", "", audit_fn)
        quarantined.append(safe_name)
        return

    try:
        data = base64.b64decode(item.get("data_b64") or "", validate=True)
    except Exception:
        _do_quarantine_fd(reports_dir, report_id, name, b"", "bad_base64", "", audit_fn)
        quarantined.append(name)
        return

    if not data or len(data) > MAX_ARTIFACT_BYTES:
        _do_quarantine_fd(reports_dir, report_id, name, data[:MAX_ARTIFACT_BYTES],
                          "bad_size", "", audit_fn)
        quarantined.append(name)
        return

    # OCR -> scan. Any exception => fail closed.
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
        # Write via dir-fd walk — defeats symlink planted at reports/<id>.
        try:
            art_fd = _make_art_dir_fd(reports_dir, report_id)
            try:
                _write_nofollow_excl(art_fd, name, data)
            finally:
                os.close(art_fd)
            saved.append(name)
        except FileExistsError:
            # Duplicate name / benign retry — treat as write error, fall through.
            _do_quarantine_fd(reports_dir, report_id, name, data,
                              "write_error:FileExistsError", "", audit_fn)
            quarantined.append(name)
        except OSError as exc:
            # Symlink planted or other write failure — isolate, don't save.
            _do_quarantine_fd(reports_dir, report_id, name, data,
                              f"write_error:{type(exc).__name__}", "", audit_fn)
            quarantined.append(name)
    else:
        _do_quarantine_fd(reports_dir, report_id, name, data, reason,
                          text if isinstance(text, str) else "", audit_fn)
        quarantined.append(name)


def _do_quarantine_fd(
    reports_dir: Path,
    report_id: str,
    name: str,
    data: bytes,
    reason: str,
    ocr_text: str,
    audit_fn,
) -> None:
    """Write to _quarantine via dir-fd walk, then fire audit. Never raises."""
    try:
        q_fd = _make_q_art_dir_fd(reports_dir, report_id)
        try:
            try:
                _write_nofollow_excl(q_fd, name, data)
            except FileExistsError:
                pass  # already written (retry) — audit still fires
        finally:
            os.close(q_fd)
    except Exception as exc:
        print(f"research-agent: artifact isolation write failed "
              f"{report_id}/{name}: {type(exc).__name__}: {exc}", file=sys.stderr)
    _do_audit(audit_fn, report_id, name, reason, ocr_text)


def _do_audit(audit_fn, report_id: str, name: str, reason: str, ocr_text: str) -> None:
    """Fire audit_fn, swallowing any exception."""
    if audit_fn is not None:
        try:
            audit_fn(report_id, name, reason, ocr_text[:2000])
        except Exception as exc:
            print(f"research-agent: audit_fn failed {report_id}/{name}: "
                  f"{type(exc).__name__}: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Link rewriting
# ---------------------------------------------------------------------------

_ARTIFACT_LINK = re.compile(r"\]\(artifacts/([a-zA-Z0-9._-]+)\)")
# Matches any remaining artifacts/ reference after first rewrite pass —
# catches traversal attempts like ](artifacts/../x.png).
_RESIDUAL_ARTIFACT_LINK = re.compile(r"\]\(artifacts/[^)]*\)")


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

    result = _ARTIFACT_LINK.sub(_sub, text)
    # Neutralize any residual artifacts/ links (traversal attempts, unknown names).
    result = _RESIDUAL_ARTIFACT_LINK.sub("] (unresolved artifact link)", result)
    return result
