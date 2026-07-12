"""LLM judge via headless `claude -p` (subscription-billed, no API key plumbing)."""
from __future__ import annotations

import json
import re
import subprocess

from evals.rubric import JUDGE_MODEL, build_judge_prompt

_REQUIRED_KEYS = {
    "factual_accuracy", "citation_accuracy", "completeness",
    "source_quality", "instruction_following", "expectation_met",
    "overall", "notes",
}

_SCORE_KEYS = {"factual_accuracy", "citation_accuracy", "completeness",
               "source_quality", "instruction_following", "overall"}


class JudgeError(Exception):
    pass


def parse_judge_output(raw: str) -> dict:
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        raise JudgeError(f"no JSON object in judge output: {raw[:200]}")
    try:
        scores = json.loads(match.group(0))
    except json.JSONDecodeError as e:
        raise JudgeError(f"unparseable judge JSON: {e}") from e
    missing = _REQUIRED_KEYS - scores.keys()
    if missing:
        raise JudgeError(f"judge output missing keys: {sorted(missing)}")
    # Validate score ranges: must be numeric (but NOT bool) in [0.0, 1.0]
    for key in _SCORE_KEYS:
        val = scores[key]
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            raise JudgeError(f"{key} must be a number, got {type(val).__name__}: {val!r}")
        if not (0.0 <= val <= 1.0):
            raise JudgeError(f"{key} out of range [0, 1]: {val}")
    # Validate expectation_met: must be a real bool (not int/str)
    em = scores["expectation_met"]
    if not isinstance(em, bool):
        raise JudgeError(f"expectation_met must be bool, got {type(em).__name__}: {em!r}")
    return scores


def judge_report(question: str, expectation: str, report: str, timeout: int = 300) -> dict:
    prompt = build_judge_prompt(question, expectation, report)
    result = subprocess.run(
        ["claude", "-p", "--model", JUDGE_MODEL],
        input=prompt,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise JudgeError(f"claude -p failed rc={result.returncode}: {result.stderr[:300]}")
    scores = parse_judge_output(result.stdout)
    scores["judge_model"] = JUDGE_MODEL
    return scores
