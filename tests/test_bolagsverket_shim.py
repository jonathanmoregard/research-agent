"""Tests for bolagsverket_shim pure helpers + a fake-data round trip
that exercises the indexer + FTS5 search end-to-end without network.

Use:
    uv run python3 tests/test_bolagsverket_shim.py

Exit 0 on pass, non-zero on first failure (smoke-style, not pytest, to
match the rest of this repo's test style).
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Point the shim's cache dir at a fresh tmpdir BEFORE the module is imported
# so it doesn't try to download anything when its module-level path globals
# get evaluated.
_TMP = tempfile.mkdtemp(prefix="bolagsverket-test-")
os.environ["BOLAGSVERKET_CACHE_DIR"] = _TMP

from agent.shims import bolagsverket_shim as bv  # noqa: E402


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        sys.exit(1)


# ----- pure-helper tests --------------------------------------------------

def test_parse_organisationsidentitet_typical():
    out = bv.parse_organisationsidentitet("5560000001$Organisationsnummer")
    _assert(out == ("5560000001", "Organisationsnummer"), f"got {out}")


def test_parse_organisationsidentitet_missing_type():
    _assert(bv.parse_organisationsidentitet("5560000001") == ("5560000001", ""),
            "missing type should yield empty string")
    _assert(bv.parse_organisationsidentitet("") == ("", ""),
            "empty input yields ('', '')")


def test_parse_organisationsnamn_single():
    out = bv.parse_organisationsnamn("Kablong AB$primärt$2026-06-01$IT-konsult")
    _assert(out == [{
        "name": "Kablong AB", "type": "primärt",
        "date": "2026-06-01", "activity": "IT-konsult",
    }], f"got {out}")


def test_parse_organisationsnamn_multiple():
    raw = ("Kablong AB$primärt$2026-06-01$"
           "|Kablong Sweden$särskilt företagsnamn$2026-07-01$Schemaläggning")
    out = bv.parse_organisationsnamn(raw)
    _assert(len(out) == 2, f"expected 2 names, got {len(out)}")
    _assert(out[0]["name"] == "Kablong AB", f"primary wrong: {out}")
    _assert(out[1]["name"] == "Kablong Sweden", f"secondary wrong: {out}")
    _assert(out[1]["activity"] == "Schemaläggning", f"activity lost: {out}")


def test_parse_organisationsnamn_empty():
    _assert(bv.parse_organisationsnamn("") == [], "empty input → []")


def test_parse_organisationsnamn_handles_dollar_in_activity():
    # The split is bounded to 4 parts so embedded $ in activity survives.
    out = bv.parse_organisationsnamn("Foo$primärt$2026-01-01$a$b$c")
    _assert(out[0]["activity"] == "a$b$c", f"got {out}")


def test_normalize():
    _assert(bv.normalize("  Kablong   AB  ") == "kablong ab", "whitespace collapse")
    _assert(bv.normalize("") == "", "empty → empty")
    _assert(bv.normalize(None) == "", "None → empty")  # type: ignore[arg-type]


def test_is_active():
    _assert(bv.is_active("") is True, "empty deregistration date == active")
    _assert(bv.is_active("   ") is True, "whitespace-only deregistration == active")
    _assert(bv.is_active("2024-01-01") is False, "set date == deregistered")


def test_row_to_record_typical():
    header = [
        "organisationsidentitet", "namnskyddslopnummer", "registreringsland",
        "organisationsnamn", "organisationsform", "avregistreringsdatum",
        "avregistreringsorsak", "pagandeAvvecklingsEllerOmstruktureringsforfarande",
        "registreringsdatum", "verksamhetsbeskrivning", "postadress",
    ]
    cols = {h: i for i, h in enumerate(header)}
    row = [
        "5560000001$Organisationsnummer", "", "SE",
        "Kablong AB$primärt$2026-06-01$Schemaläggning",
        "AB", "", "", "", "2026-05-01", "Group-scheduling SaaS", "",
    ]
    rec = bv._row_to_record(row, cols)
    _assert(rec is not None, "valid row produced None")
    _assert(rec[0] == "5560000001", f"org_id wrong: {rec[0]}")
    _assert(rec[2] == "Kablong AB", f"primary_name wrong: {rec[2]}")
    _assert(rec[4] == 1, f"should be active: {rec[4]}")
    _assert(rec[5] == "2026-05-01", f"reg date wrong: {rec[5]}")
    _assert(rec[8] == "AB", f"form wrong: {rec[8]}")


def test_row_to_record_missing_org_id():
    header = ["organisationsidentitet", "organisationsnamn"]
    cols = {h: i for i, h in enumerate(header)}
    _assert(bv._row_to_record(["", "Foo$..."], cols) is None,
            "empty org_id should yield None")


def test_format_results_no_matches():
    out = bv.format_results("kablong", [])
    _assert("no matches" in out, f"missing 'no matches': {out!r}")


def test_format_results_with_matches():
    results = [{
        "org_id": "5560000001",
        "org_id_type": "Organisationsnummer",
        "primary_name": "Kablong AB",
        "all_names": [{"name": "Kablong AB", "type": "primärt",
                       "date": "2026-06-01", "activity": ""}],
        "is_active": True,
        "registreringsdatum": "2026-05-01",
        "avregistreringsdatum": "",
        "organisationsform": "AB",
        "verksamhetsbeskrivning": "Group-scheduling SaaS",
    }]
    out = bv.format_results("kablong", results)
    _assert("Kablong AB" in out, f"name missing: {out}")
    _assert("ACTIVE" in out, f"status missing: {out}")
    _assert("5560000001" in out, f"org_id missing: {out}")
    _assert("Group-scheduling SaaS" in out, f"activity missing: {out}")


# ----- round trip: build SQLite from a fake CSV ---------------------------

def _make_fake_zip(rows: list[list[str]], path: Path) -> Path:
    """Pack a header + rows into a ;-delimited CSV inside a zip."""
    header = [
        "organisationsidentitet", "namnskyddslopnummer", "registreringsland",
        "organisationsnamn", "organisationsform", "avregistreringsdatum",
        "avregistreringsorsak", "pagandeAvvecklingsEllerOmstruktureringsforfarande",
        "registreringsdatum", "verksamhetsbeskrivning", "postadress",
    ]
    buf = io.StringIO()
    import csv as _csv
    w = _csv.writer(buf, delimiter=";", quotechar='"', escapechar="\\")
    w.writerow(header)
    for r in rows:
        w.writerow(r)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("bolagsverket_bulkfil.txt", buf.getvalue())
    return path


def test_build_and_search_round_trip():
    rows = [
        ["5560000001$Organisationsnummer", "", "SE",
         "Kablong AB$primärt$2026-06-01$Schemaläggning",
         "AB", "", "", "", "2026-05-01", "SaaS scheduling", ""],
        ["5560000002$Organisationsnummer", "", "SE",
         "Kabang Sverige AB$primärt$2016-06-16$",
         "AB", "", "", "", "2016-06-16", "IT-konsult", ""],
        ["5560000003$Organisationsnummer", "", "SE",
         "Annan Foretag AB$primärt$2010-01-01$",
         "AB", "", "", "", "2010-01-01", "Lantbruk", ""],
        ["5560000004$Organisationsnummer", "", "SE",
         "Avregistrerad AB$primärt$2000-01-01$",
         "AB", "2024-01-01", "Likvidation", "", "2000-01-01", "Inactive", ""],
    ]
    zip_path = Path(_TMP) / "fake.zip"
    _make_fake_zip(rows, zip_path)
    bv.DB_PATH = Path(_TMP) / "round_trip.db"
    if bv.DB_PATH.exists():
        bv.DB_PATH.unlink()
    n = bv._build_index_from_zip(zip_path)
    _assert(n == 4, f"expected 4 rows ingested, got {n}")

    hits = bv._search("kablong", 10)
    _assert(len(hits) == 1, f"kablong search should hit once, got {len(hits)}")
    _assert(hits[0]["primary_name"] == "Kablong AB", f"got {hits[0]}")
    _assert(hits[0]["is_active"] is True, "Kablong should be active")

    hits = bv._search("kabang", 10)
    _assert(len(hits) == 1, f"kabang should hit Kabang Sverige AB, got {hits}")
    _assert(hits[0]["primary_name"] == "Kabang Sverige AB", f"got {hits[0]}")

    hits = bv._search("avregistrerad", 10)
    _assert(len(hits) == 1, f"deregistered org should still be searchable")
    _assert(hits[0]["is_active"] is False, "must be flagged DEREGISTERED")

    hits = bv._search("zzz-no-match", 10)
    _assert(hits == [], f"unmatched query should yield []: {hits}")


def test_format_results_truncates_long_output():
    # Build 200 fake records and check the cap fires.
    results = []
    for i in range(200):
        results.append({
            "org_id": f"5560{i:06d}",
            "org_id_type": "Organisationsnummer",
            "primary_name": f"FakeCo {i}",
            "all_names": [{"name": f"FakeCo {i}", "type": "primärt", "date": "2026-01-01", "activity": ""}],
            "is_active": True,
            "registreringsdatum": "2026-01-01",
            "avregistreringsdatum": "",
            "organisationsform": "AB",
            "verksamhetsbeskrivning": "x" * 300,
        })
    out = bv.format_results("fake", results)
    _assert(len(out) <= bv.MAX_OUTPUT_CHARS + 50, f"expected cap, got {len(out)} chars")
    _assert("[output truncated]" in out, "missing truncation marker")


def main() -> int:
    tests = [
        test_parse_organisationsidentitet_typical,
        test_parse_organisationsidentitet_missing_type,
        test_parse_organisationsnamn_single,
        test_parse_organisationsnamn_multiple,
        test_parse_organisationsnamn_empty,
        test_parse_organisationsnamn_handles_dollar_in_activity,
        test_normalize,
        test_is_active,
        test_row_to_record_typical,
        test_row_to_record_missing_org_id,
        test_format_results_no_matches,
        test_format_results_with_matches,
        test_build_and_search_round_trip,
        test_format_results_truncates_long_output,
    ]
    for t in tests:
        t()
        print(f"ok  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
