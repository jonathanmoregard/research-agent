from pathlib import Path
from evals.structural import check_report

FIXTURES = Path(__file__).parent / "fixtures"


def test_good_report_passes():
    result = check_report((FIXTURES / "report_good.md").read_text())
    assert result.ok, result.failures


def test_missing_sources_section_fails():
    result = check_report((FIXTURES / "report_no_sources.md").read_text())
    assert not result.ok
    assert any("Sources" in f for f in result.failures)


def test_uncited_findings_flagged():
    result = check_report((FIXTURES / "report_no_sources.md").read_text())
    assert any("uncited" in f.lower() for f in result.failures)


def test_cited_urls_must_appear_in_sources():
    text = (FIXTURES / "report_good.md").read_text().replace(
        "1. [Example Source](https://example.com/a) — one-line note", ""
    )
    result = check_report(text)
    assert not result.ok


def test_url_with_parentheses():
    text = (FIXTURES / "report_good.md").read_text().replace(
        "https://example.com/a", "https://en.wikipedia.org/wiki/Foo_(bar)"
    )
    result = check_report(text)
    assert result.ok, result.failures


def test_wrapped_bullet_citation_counts():
    text = (FIXTURES / "report_good.md").read_text().replace(
        "- First claim with citation ([Example Source](https://example.com/a))",
        "- First claim with citation that wraps\n  onto a second line ([Example Source](https://example.com/a))",
    )
    result = check_report(text)
    assert result.ok, result.failures
