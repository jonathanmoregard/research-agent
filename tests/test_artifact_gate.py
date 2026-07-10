"""Tests for mcp_server/artifact_gate.py — OCR+scan artifact gate.

Injected fetcher/ocr_fn/scan_fn (types.SimpleNamespace verdict stubs).
Never touches the real reports/ directory (uses tempfile).

Use:
    uv run --group dev python3 tests/test_artifact_gate.py
"""
from __future__ import annotations

import base64
import shutil
import sys
import tempfile
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from mcp_server.artifact_gate import gate_artifacts, rewrite_artifact_links  # noqa: E402


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _verdict(ok: bool, reason: str = "", text: str = "") -> types.SimpleNamespace:
    return types.SimpleNamespace(ok=ok, reason=reason, sanitized_text=text)


def _ok_scan(t: str) -> types.SimpleNamespace:
    return _verdict(True, "pass", t)


def _fail_scan(t: str) -> types.SimpleNamespace:
    return _verdict(False, "injection_detected", t)


_PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20  # fake but non-empty


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _artifact(name: str, data: bytes = _PNG_BYTES) -> dict:
    return {"name": name, "mime": "image/png", "data_b64": _b64(data)}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_no_artifacts_noop():
    audit_calls: list = []
    with tempfile.TemporaryDirectory() as td:
        reports = Path(td)
        saved, quarantined = gate_artifacts(
            "a" * 32,
            reports,
            _ok_scan,
            audit_fn=lambda *a: audit_calls.append(a),
            fetcher=lambda rid: [],
            ocr_fn=lambda p: "",
        )
    _assert(saved == [], "expected no saved")
    _assert(quarantined == [], "expected no quarantined")
    _assert(audit_calls == [], "unexpected audit call")


def test_pass_saves_file():
    report_id = "b" * 32
    with tempfile.TemporaryDirectory() as td:
        reports = Path(td)
        saved, quarantined = gate_artifacts(
            report_id,
            reports,
            _ok_scan,
            fetcher=lambda rid: [_artifact("shot.png")],
            ocr_fn=lambda p: "clean text",
        )
        art_path = reports / report_id / "artifacts" / "shot.png"
        _assert(saved == ["shot.png"], f"expected saved=['shot.png'], got {saved}")
        _assert(quarantined == [], f"expected no quarantined, got {quarantined}")
        _assert(art_path.exists(), f"artifact file not written to {art_path}")
        _assert(art_path.read_bytes() == _PNG_BYTES, "artifact bytes mismatch")


def test_fail_quarantines():
    report_id = "c" * 32
    audit_calls: list = []
    with tempfile.TemporaryDirectory() as td:
        reports = Path(td)
        saved, quarantined = gate_artifacts(
            report_id,
            reports,
            _fail_scan,
            audit_fn=lambda *a: audit_calls.append(a),
            fetcher=lambda rid: [_artifact("shot.png")],
            ocr_fn=lambda p: "INJECTION MARKER",
        )
        art_path = reports / report_id / "artifacts" / "shot.png"
        q_path = reports / "_quarantine" / report_id / "artifacts" / "shot.png"
        _assert(saved == [], f"expected no saved, got {saved}")
        _assert(quarantined == ["shot.png"], f"expected quarantined=['shot.png'], got {quarantined}")
        _assert(not art_path.exists(), "artifact written to report dir despite scan failure")
        _assert(q_path.exists(), f"artifact not written to quarantine: {q_path}")
        _assert(len(audit_calls) == 1, f"expected 1 audit call, got {len(audit_calls)}")
        _assert(audit_calls[0][0] == report_id, "audit report_id mismatch")
        _assert(audit_calls[0][2] == "injection_detected", f"audit reason mismatch: {audit_calls[0][2]}")


def test_ocr_missing_fails_closed():
    """ocr_fn raises FileNotFoundError -> quarantined with reason containing 'ocr_error'."""
    report_id = "d" * 32
    audit_calls: list = []

    def broken_ocr(path):
        raise FileNotFoundError("tesseract not found")

    with tempfile.TemporaryDirectory() as td:
        reports = Path(td)
        saved, quarantined = gate_artifacts(
            report_id,
            reports,
            _ok_scan,
            audit_fn=lambda *a: audit_calls.append(a),
            fetcher=lambda rid: [_artifact("shot.png")],
            ocr_fn=broken_ocr,
        )
        _assert(saved == [], f"expected no saved, got {saved}")
        _assert(quarantined == ["shot.png"], f"expected quarantined=['shot.png'], got {quarantined}")
        _assert(len(audit_calls) == 1, "expected 1 audit call")
        reason = audit_calls[0][2]
        _assert("ocr_error" in reason, f"expected 'ocr_error' in reason, got {reason!r}")


def test_bad_name_rejected():
    """Artifact with name '../../x.png' is quarantined with a sha-derived name."""
    report_id = "e" * 32
    audit_calls: list = []
    with tempfile.TemporaryDirectory() as td:
        reports = Path(td)
        saved, quarantined = gate_artifacts(
            report_id,
            reports,
            _ok_scan,
            audit_fn=lambda *a: audit_calls.append(a),
            fetcher=lambda rid: [_artifact("../../x.png")],
            ocr_fn=lambda p: "text",
        )
        _assert(saved == [], f"expected no saved, got {saved}")
        _assert(len(quarantined) == 1, f"expected 1 quarantined, got {quarantined}")
        _assert(quarantined[0].startswith("unsafe-"), f"expected sha-derived name, got {quarantined[0]}")
        _assert(len(audit_calls) == 1, "expected 1 audit call")
        reason = audit_calls[0][2]
        _assert("unsafe_name" in reason, f"expected 'unsafe_name' in reason, got {reason!r}")


def test_oversize_rejected():
    """Artifact > 2 MiB is quarantined, not saved."""
    report_id = "f" * 32
    big_data = b"\x89PNG" + b"\x00" * (2 * 1024 * 1024 + 1)
    audit_calls: list = []
    with tempfile.TemporaryDirectory() as td:
        reports = Path(td)
        saved, quarantined = gate_artifacts(
            report_id,
            reports,
            _ok_scan,
            audit_fn=lambda *a: audit_calls.append(a),
            fetcher=lambda rid: [_artifact("big.png", big_data)],
            ocr_fn=lambda p: "text",
        )
        _assert(saved == [], f"expected no saved, got {saved}")
        _assert(quarantined == ["big.png"], f"expected quarantined=['big.png'], got {quarantined}")
        _assert(len(audit_calls) == 1, "expected 1 audit call")
        reason = audit_calls[0][2]
        _assert("bad_size" in reason, f"expected 'bad_size' in reason, got {reason!r}")


def test_link_rewrite():
    """rewrite_artifact_links rewrites passing links and stubs quarantined ones."""
    report_id = "a1b2c3d4" * 4  # 32 hex chars
    saved = ["shot.png"]
    quarantined = ["bad.png"]

    text = "Here is a screenshot: ![caption](artifacts/shot.png) and a bad one: ![b](artifacts/bad.png)"
    result = rewrite_artifact_links(text, report_id, saved, quarantined)

    _assert(f"]({report_id}/artifacts/shot.png)" in result, f"saved link not rewritten: {result!r}")
    _assert("](artifacts/shot.png)" not in result, f"original saved link still present: {result!r}")
    _assert("(artifact quarantined: bad.png)" in result, f"quarantined link not stubbed: {result!r}")
    _assert("](artifacts/bad.png)" not in result, f"original quarantined link still present: {result!r}")


def test_ocr_real():
    """Render 'INJECTION MARKER 42' with PIL, run real tesseract, check output."""
    if shutil.which("tesseract") is None:
        print("ok: test_ocr_real [SKIP — tesseract not in PATH]")
        return

    try:
        from PIL import Image, ImageDraw
    except ImportError:
        print("ok: test_ocr_real [SKIP — PIL not available]")
        return

    from mcp_server.artifact_gate import ocr_image

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        tmp = Path(f.name)

    try:
        img = Image.new("RGB", (600, 100), "white")
        ImageDraw.Draw(img).text((10, 30), "INJECTION MARKER 42", fill="black")
        img.save(tmp)
        text = ocr_image(tmp)
        _assert("MARKER" in text, f"OCR output missing 'MARKER': {text!r}")
    finally:
        tmp.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            if name != "test_ocr_real":
                print(f"ok: {name}")
    print("ALL PASS")
