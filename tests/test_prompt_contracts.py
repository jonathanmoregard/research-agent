from pathlib import Path

REPO = Path(__file__).parent.parent
AGENT_MD = (REPO / "agent" / "CLAUDE.md").read_text()


def _depth_guidance():
    import sys
    sys.path.insert(0, str(REPO))
    from mcp_server.server import DEPTH_GUIDANCE
    return DEPTH_GUIDANCE


def test_query_decomposition_guidance():
    assert "single-search-answerable" in AGENT_MD
    dg = _depth_guidance()
    assert "sub-question" in dg["normal"] and "sub-question" in dg["deep"]


def test_termination_criteria():
    assert "Stop researching when" in AGENT_MD


def test_confidence_tiers():
    for marker in ("3+ independent sources", "unverified"):
        assert marker in AGENT_MD


def test_self_check_pass():
    assert "Self-check before writing" in AGENT_MD
    assert "could not verify" in AGENT_MD.lower()


def test_conflicting_evidence_section():
    assert "## Conflicting evidence" in AGENT_MD


def test_source_quality_ranking():
    assert "primary" in AGENT_MD and "SEO" in AGENT_MD


def test_full_fetch_before_load_bearing_claims():
    assert "load-bearing" in AGENT_MD and "fetched" in AGENT_MD


def test_gaps_section():
    assert "## Gaps" in AGENT_MD


def test_date_anchor_in_prompt_template():
    import sys
    sys.path.insert(0, str(REPO))
    from mcp_server.server import PROMPT_TEMPLATE
    assert "{today}" in PROMPT_TEMPLATE


def test_completion_rubric_protocol():
    assert "## Completion rubric" in AGENT_MD
    assert "3-7 binary" in AGENT_MD


def test_retrac_state_buffer():
    for marker in ("STATE block", "DEAD-ENDS:", "CONFIRMED:", "PLAN:"):
        assert marker in AGENT_MD
