"""Sequential live eval runner + regression comparison.

Usage:
    uv run python3 evals/run_eval.py --subset smoke --out evals/results/<name>.json
    uv run python3 evals/run_eval.py --subset smoke --out ... --baseline evals/baselines/<file>.json

SEQUENTIAL BY DESIGN: the research microvm handles one call at a time;
parallel calls fail instantly. Do not add concurrency here.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

MEAN_DROP_TOLERANCE = 0.05
CATEGORY_DROP_TOLERANCE = 0.10
PASS_RATE_DROP_TOLERANCE = 0.0


@dataclass
class RegressionVerdict:
    ok: bool
    regressions: list[str] = field(default_factory=list)


def summarize(results: list[dict]) -> dict:
    done = [r for r in results if r["status"] == "done"]
    def mean(xs):
        return sum(xs) / len(xs) if xs else 0.0
    by_cat: dict[str, dict] = {}
    for cat in {r["category"] for r in done}:
        cat_rs = [r for r in done if r["category"] == cat]
        by_cat[cat] = {"n": len(cat_rs),
                       "mean_overall": mean([r["scores"]["overall"] for r in cat_rs])}
    return {
        "n": len(results),
        "n_done": len(done),
        "mean_overall": mean([r["scores"]["overall"] for r in done]),
        "expectation_pass_rate": mean([1.0 if r["scores"]["expectation_met"] else 0.0 for r in done]),
        "structural_pass_rate": mean([1.0 if r["structural_ok"] else 0.0 for r in done]),
        "by_category": by_cat,
    }


def compare_to_baseline(current: dict, baseline: dict) -> RegressionVerdict:
    regressions = []
    if current["mean_overall"] < baseline["mean_overall"] - MEAN_DROP_TOLERANCE:
        regressions.append(
            f"mean_overall dropped {baseline['mean_overall']:.2f} -> {current['mean_overall']:.2f}")
    if current["expectation_pass_rate"] < baseline["expectation_pass_rate"] - PASS_RATE_DROP_TOLERANCE:
        regressions.append(
            f"expectation_pass_rate dropped {baseline['expectation_pass_rate']:.2f} -> {current['expectation_pass_rate']:.2f}")
    for cat, base_stats in baseline.get("by_category", {}).items():
        cur_stats = current.get("by_category", {}).get(cat)
        if cur_stats and cur_stats["mean_overall"] < base_stats["mean_overall"] - CATEGORY_DROP_TOLERANCE:
            regressions.append(
                f"category {cat} dropped {base_stats['mean_overall']:.2f} -> {cur_stats['mean_overall']:.2f}")
    return RegressionVerdict(ok=not regressions, regressions=regressions)


async def _research_once(prompt: str, depth: str) -> dict:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command="uv",
        args=["run", "--project", str(REPO_ROOT),
              "python3", str(REPO_ROOT / "mcp_server" / "server.py")],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("research", {"prompt": prompt, "depth": depth})
            for item in result.content:
                if hasattr(item, "text"):
                    try:
                        return json.loads(item.text)
                    except Exception:
                        return {"status": "error", "error": item.text[:300]}
    return {"status": "error", "error": "no content"}


def run_suite(subset: str, depth: str) -> list[dict]:
    from evals.judge import JudgeError, judge_report
    from evals.structural import check_report

    suite = json.loads((REPO_ROOT / "evals" / "questions.json").read_text())
    if subset == "smoke":
        suite = [q for q in suite if q["smoke"]]

    results = []
    for q in suite:
        t0 = time.monotonic()
        print(f"[{q['id']}] researching...", flush=True)
        res = asyncio.run(_research_once(q["prompt"], depth))
        entry: dict = {"id": q["id"], "category": q["category"],
                       "status": res.get("status"), "wall_s": round(time.monotonic() - t0, 1)}
        if res.get("status") != "done":
            entry["error"] = res.get("error")
            results.append(entry)
            print(f"[{q['id']}] ERROR: {entry['error']}", flush=True)
            continue
        report = res["report"]
        structural = check_report(report)
        entry["structural_ok"] = structural.ok
        entry["structural_failures"] = structural.failures
        entry["report_path"] = res.get("report_path")
        try:
            entry["scores"] = judge_report(q["prompt"], q["expectation"], report)
        except JudgeError as e:
            entry["status"] = "judge_error"
            entry["error"] = str(e)
        results.append(entry)
        print(f"[{q['id']}] done in {entry['wall_s']}s", flush=True)
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--subset", choices=["smoke", "full"], default="smoke")
    ap.add_argument("--depth", default="normal")
    ap.add_argument("--out", required=True)
    ap.add_argument("--baseline", default=None)
    args = ap.parse_args()

    results = run_suite(args.subset, args.depth)
    summary = summarize(results)
    out = {"subset": args.subset, "depth": args.depth,
           "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "summary": summary, "results": results}
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2))
    print(json.dumps(summary, indent=2))

    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text())["summary"]
        verdict = compare_to_baseline(summary, baseline)
        if not verdict.ok:
            print("REGRESSION:\n" + "\n".join(f"  - {r}" for r in verdict.regressions))
            return 1
        print("No regression vs baseline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
