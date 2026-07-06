"""Tests for prv_shim pure helpers — ST.66 XML parsing (against the
schema observed live on the PRV FTP 2026-07-06), row mapping, and
formatting. No network.

Use: uv run python3 tests/test_prv_shim.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
os.environ.setdefault("PRV_CACHE_DIR", tempfile.mkdtemp(prefix="prv-test-"))

from agent.shims import prv_shim as pv  # noqa: E402


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        sys.exit(1)


# Trimmed real-world structure (observed on the FTP, 2026-07-06).
_XML = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ns2:Transaction xmlns:ns2="http://www.oami.europa.eu/TM-Search">
  <TradeMarkTransactionBody><TransactionContentDetails><TransactionData>
    <TradeMarkDetails><TradeMark operationCode="Insert">
      <RegistrationOfficeCode>SE</RegistrationOfficeCode>
      <ApplicationNumber>1900-62281</ApplicationNumber>
      <ApplicationDate>1946-04-04</ApplicationDate>
      <RegistrationNumber>62281</RegistrationNumber>
      <RegistrationDate>1946-12-20</RegistrationDate>
      <MarkCurrentStatusCode>Registered</MarkCurrentStatusCode>
      <ExpiryDate>2026-12-20</ExpiryDate>
      <MarkFeature>Word</MarkFeature>
      <WordMarkSpecification>
        <MarkVerbalElementText>L'HEURE BLEUE</MarkVerbalElementText>
      </WordMarkSpecification>
      <GoodsServicesDetails><GoodsServices><ClassDescriptionDetails>
        <ClassDescription><ClassNumber>3</ClassNumber></ClassDescription>
        <ClassDescription><ClassNumber>5</ClassNumber></ClassDescription>
      </ClassDescriptionDetails></GoodsServices></GoodsServicesDetails>
      <ApplicantDetails><Applicant>
        <ApplicantName><FullName>Guerlain SA</FullName></ApplicantName>
      </Applicant></ApplicantDetails>
    </TradeMark></TradeMarkDetails>
  </TransactionData></TransactionContentDetails></TradeMarkTransactionBody>
</ns2:Transaction>"""


def test_parse_full_record():
    rec = pv.parse_mark_xml(_XML)
    _assert(rec is not None, "real-structure XML failed to parse")
    _assert(rec["name"] == "L'HEURE BLEUE", f"name: {rec}")
    _assert(rec["appnum"] == "1900-62281", f"appnum: {rec}")
    _assert(rec["regnum"] == "62281", f"regnum: {rec}")
    _assert(rec["status"] == "Registered", f"status: {rec}")
    _assert(rec["feature"] == "Word", f"feature: {rec}")
    _assert(rec["expiry"] == "2026-12-20", f"expiry: {rec}")
    _assert(rec["classes"] == ["3", "5"], f"classes: {rec}")
    _assert(rec["applicants"] == ["Guerlain SA"], f"applicants: {rec}")


def test_parse_garbage_returns_none():
    _assert(pv.parse_mark_xml(b"not xml at all") is None, "garbage parsed")
    _assert(pv.parse_mark_xml(b"<empty/>") is None, "empty accepted")


def test_row_mapping_and_format():
    rec = pv.parse_mark_xml(_XML)
    row = pv.record_to_row(rec)
    _assert(row[0] == "1900-62281" and row[7] == "3, 5", f"row: {row}")
    out = pv.format_results("heure", [row])
    _assert("L'HEURE BLEUE" in out and "Guerlain SA" in out, f"format: {out}")
    _assert("Registered" in out and "3, 5" in out, f"format: {out}")


def test_format_zero_hits():
    out = pv.format_results("klaffar", [])
    _assert("0 hits" in out, f"zero-hit message: {out}")


def main() -> int:
    for t in (test_parse_full_record, test_parse_garbage_returns_none,
              test_row_mapping_and_format, test_format_zero_hits):
        t()
        print(f"ok  {t.__name__}")
    print("\n4 tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
