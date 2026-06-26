"""Tests for trademark_shim pure helpers — RSQL filter construction
(incl. injection-escaping) and the defensive response normalizer.

Use:
    uv run python3 tests/test_trademark_shim.py

Exit 0 on pass, non-zero on first failure (smoke-style, not pytest, to
match the rest of this repo's test style).
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agent.shims.trademark_shim import (  # noqa: E402
    _extract_records,
    _format_hits,
    _rsql_quote,
    build_filter,
    normalize_hit,
)


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        sys.exit(1)


def test_filter_basic_wildcard():
    f = build_filter("kablong")
    _assert(
        f == 'wordMarkSpecification.verbalElement=="*kablong*"',
        f"basic wildcard filter wrong: {f!r}",
    )


def test_filter_exact_no_wildcards():
    f = build_filter("kablong", exact=True)
    _assert("*" not in f, f"exact filter should have no wildcards: {f!r}")


def test_filter_with_classes():
    f = build_filter("kablong", nice_classes=[9, 42])
    _assert("niceClasses=in=(9,42)" in f, f"class clause missing: {f!r}")
    _assert(f.count(";") == 1, f"expected one AND join: {f!r}")


def test_filter_with_status():
    f = build_filter("kablong", status="registered")  # case-normalized
    _assert("status==REGISTERED" in f, f"status clause missing/uppercased: {f!r}")


def test_filter_bad_status_raises():
    try:
        build_filter("kablong", status="totally-made-up")
    except ValueError:
        return
    _assert(False, "bad status did not raise")


def test_filter_empty_name_raises():
    for bad in ("", "   "):
        try:
            build_filter(bad)
        except ValueError:
            continue
        _assert(False, f"empty name {bad!r} did not raise")


def test_filter_class_out_of_range_raises():
    try:
        build_filter("kablong", nice_classes=[0])
    except ValueError:
        pass
    else:
        _assert(False, "nice class 0 did not raise")
    try:
        build_filter("kablong", nice_classes=[46])
    except ValueError:
        return
    _assert(False, "nice class 46 did not raise")


# RSQL injection: a quote in the name must be escaped so it can't break
# out of the quoted term and append attacker-controlled RSQL.
def test_rsql_quote_escapes():
    out = _rsql_quote('foo" or niceClasses=in=(1) or x=="bar')
    _assert('\\"' in out, f"quote not escaped: {out!r}")
    # No bare (unescaped) double-quote remains.
    _assert(out.replace('\\"', "") .count('"') == 0, f"bare quote left: {out!r}")


def test_filter_injection_contained():
    f = build_filter('evil" or status==REGISTERED or "')
    # The injected operators must sit *inside* the quoted term (escaped),
    # not as live RSQL — so there is still exactly one top-level clause.
    _assert(f.count(";") == 0, f"injection added a clause: {f!r}")
    _assert('\\"' in f, f"injected quotes not escaped: {f!r}")


def test_normalize_flat_record():
    rec = {
        "markName": "KABLONG",
        "applicationNumber": "019999999",
        "applicantName": "Acme Oy",
        "niceClasses": [9, 42],
        "status": "REGISTERED",
        "filingDate": "2026-06-17",
    }
    h = normalize_hit(rec)
    _assert(h["mark"] == "KABLONG", f"mark: {h}")
    _assert(h["owner"] == "Acme Oy", f"owner: {h}")
    _assert(h["niceClasses"] == "9, 42", f"classes joined: {h}")
    _assert(h["status"] == "REGISTERED", f"status: {h}")


def test_normalize_st96_nested():
    rec = {
        "wordMarkSpecification": {"verbalElement": "KABLONG"},
        "applicationDate": "2026-01-01",
    }
    h = normalize_hit(rec)
    _assert(h["mark"] == "KABLONG", f"nested verbalElement not read: {h}")
    _assert(h["filingDate"] == "2026-01-01", f"applicationDate fallback: {h}")


def test_normalize_non_dict():
    _assert(normalize_hit("nope") == {}, "non-dict should yield {}")


def test_extract_records_variants():
    _assert(_extract_records({"trademarks": [1, 2]}) == [1, 2], "trademarks key")
    _assert(_extract_records({"content": [3]}) == [3], "content key (Spring page)")
    _assert(_extract_records([7, 8]) == [7, 8], "bare list")
    _assert(_extract_records({"weird": 1}) == [], "unknown shape -> []")


def test_format_hits_empty_dumps_raw():
    out = _format_hits({"unexpected": {"shape": True}})
    _assert("raw" in out.lower(), f"empty result should dump raw shape: {out!r}")


def test_format_hits_lists_records():
    body = {"trademarks": [{"markName": "KABLONG", "status": "REGISTERED"}]}
    out = _format_hits(body)
    _assert("KABLONG" in out, f"mark not in formatted output: {out!r}")
    _assert("1 result" in out, f"count header missing: {out!r}")


def main() -> int:
    tests = [
        test_filter_basic_wildcard,
        test_filter_exact_no_wildcards,
        test_filter_with_classes,
        test_filter_with_status,
        test_filter_bad_status_raises,
        test_filter_empty_name_raises,
        test_filter_class_out_of_range_raises,
        test_rsql_quote_escapes,
        test_filter_injection_contained,
        test_normalize_flat_record,
        test_normalize_st96_nested,
        test_normalize_non_dict,
        test_extract_records_variants,
        test_format_hits_empty_dumps_raw,
        test_format_hits_lists_records,
    ]
    for t in tests:
        t()
        print(f"ok  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
