from evals.run_eval import compare_to_baseline, summarize

RESULTS = [
    {"id": "fact-01", "category": "factual", "status": "done",
     "structural_ok": True, "scores": {"overall": 0.9, "expectation_met": True}},
    {"id": "trap-01", "category": "trap", "status": "done",
     "structural_ok": True, "scores": {"overall": 0.8, "expectation_met": True}},
    {"id": "conf-01", "category": "conflicting", "status": "done",
     "structural_ok": False, "scores": {"overall": 0.5, "expectation_met": False}},
]


def test_summarize():
    s = summarize(RESULTS)
    assert s["n"] == 3
    assert abs(s["mean_overall"] - (0.9 + 0.8 + 0.5) / 3) < 1e-9
    assert s["expectation_pass_rate"] == 2 / 3
    assert s["structural_pass_rate"] == 2 / 3
    assert s["by_category"]["trap"]["mean_overall"] == 0.8


def test_regression_flags_drop():
    base = {"mean_overall": 0.80, "expectation_pass_rate": 1.0,
            "by_category": {"trap": {"mean_overall": 0.9}}}
    cur = {"mean_overall": 0.70, "expectation_pass_rate": 1.0,
           "by_category": {"trap": {"mean_overall": 0.85}}}
    verdict = compare_to_baseline(cur, base)
    assert not verdict.ok
    assert any("mean_overall" in r for r in verdict.regressions)


def test_regression_flags_incomplete_run():
    base = {"n": 4, "n_done": 4, "mean_overall": 0.80, "expectation_pass_rate": 1.0,
            "by_category": {}}
    cur = {"n": 4, "n_done": 1, "mean_overall": 0.85, "expectation_pass_rate": 1.0,
           "by_category": {}}
    verdict = compare_to_baseline(cur, base)
    assert not verdict.ok
    assert any("incomplete" in r for r in verdict.regressions)


def test_regression_ok_within_tolerance():
    base = {"mean_overall": 0.80, "expectation_pass_rate": 0.9,
            "by_category": {"trap": {"mean_overall": 0.9}}}
    cur = {"mean_overall": 0.78, "expectation_pass_rate": 0.9,
           "by_category": {"trap": {"mean_overall": 0.85}}}
    assert compare_to_baseline(cur, base).ok
