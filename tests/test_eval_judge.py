import json
from pathlib import Path

import pytest

from evals.judge import parse_judge_output, JudgeError
from evals.rubric import build_judge_prompt, JUDGE_MODEL

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_valid_output():
    scores = parse_judge_output((FIXTURES / "judge_output_valid.json").read_text())
    assert scores["overall"] == 0.85
    assert scores["expectation_met"] is True


def test_parse_extracts_json_from_prose():
    raw = "Here is my assessment:\n" + (FIXTURES / "judge_output_valid.json").read_text() + "\nDone."
    assert parse_judge_output(raw)["overall"] == 0.85


def test_parse_malformed_raises():
    with pytest.raises(JudgeError):
        parse_judge_output((FIXTURES / "judge_output_malformed.txt").read_text())


def test_judge_model_is_pinned():
    assert JUDGE_MODEL == "claude-sonnet-4-6"


def test_prompt_contains_report_and_expectation():
    p = build_judge_prompt(question="Q?", expectation="must refuse", report="REPORT BODY")
    assert "REPORT BODY" in p and "must refuse" in p and "Q?" in p


def test_out_of_range_score_raises():
    valid = json.loads((FIXTURES / "judge_output_valid.json").read_text())
    valid["overall"] = 7.3
    with pytest.raises(JudgeError):
        parse_judge_output(json.dumps(valid))


def test_string_bool_raises():
    valid = json.loads((FIXTURES / "judge_output_valid.json").read_text())
    valid["expectation_met"] = "true"
    with pytest.raises(JudgeError):
        parse_judge_output(json.dumps(valid))
