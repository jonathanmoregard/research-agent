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
