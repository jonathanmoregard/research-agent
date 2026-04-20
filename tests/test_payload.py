"""
Pipe a candidate payload file straight through the intercept shim.

Use:
    uv run python3 tests/test_payload.py <file.md> [file2.md ...]
    uv run python3 tests/test_payload.py --stdin   # read from stdin

For each payload prints the full Verdict — overall ok/reason plus the
per-layer breakdown (unicode_sanitize / regex / secret_shapes / honeypot
per scenario). Useful for red-teaming the shim with hand-crafted
prompt-injection attempts without paying the full research round trip.
"""
from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scanner.intercept import scan  # noqa: E402


def run_one(label: str, text: str) -> dict:
    with tempfile.NamedTemporaryFile(
        "w", suffix=".md", delete=False, encoding="utf-8"
    ) as f:
        f.write(text)
        path = Path(f.name)
    try:
        v = scan(path)
    finally:
        path.unlink(missing_ok=True)

    out = {
        "payload": label,
        "ok": v.ok,
        "reason": v.reason,
        "layers": v.layers,
        "sanitize_stats": v.sanitize_stats,
    }
    return out


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    if args == ["--stdin"]:
        text = sys.stdin.read()
        print(json.dumps(run_one("<stdin>", text), indent=2))
        return 0

    results = []
    for fname in args:
        p = Path(fname)
        if not p.exists():
            print(f"skip: {fname} (not found)", file=sys.stderr)
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        r = run_one(str(p), text)
        results.append(r)
        print(f"== {p} ==")
        print(f"  ok:     {r['ok']}")
        print(f"  reason: {r['reason']}")
        print("  layers:")
        for k, v in r["layers"].items():
            print(f"    {k}: {v}")
        s = r["sanitize_stats"]
        print(
            f"  sanitize: stripped={s['stripped']} "
            f"bidi={s['bidi_hits']} tag={s['tag_hits']} zw={s['zw_hits']} "
            f"nfkc_changed={s['nfkc_changed']}"
        )
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
