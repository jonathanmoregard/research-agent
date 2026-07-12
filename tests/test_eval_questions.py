import json
from pathlib import Path

QUESTIONS = Path(__file__).parent.parent / "evals" / "questions.json"
VALID_CATEGORIES = {"factual", "trap", "conflicting", "recency", "decomposition"}


def test_suite_shape():
    suite = json.loads(QUESTIONS.read_text())
    assert len(suite) >= 20
    ids = [q["id"] for q in suite]
    assert len(ids) == len(set(ids)), "duplicate ids"
    for q in suite:
        assert q["category"] in VALID_CATEGORIES
        assert len(q["prompt"]) > 20
        assert len(q["expectation"]) > 20
        assert isinstance(q["smoke"], bool)


def test_smoke_subset_covers_categories():
    suite = json.loads(QUESTIONS.read_text())
    smoke_cats = {q["category"] for q in suite if q["smoke"]}
    assert {"factual", "trap", "conflicting", "decomposition"} <= smoke_cats
    assert sum(q["smoke"] for q in suite) <= 5
