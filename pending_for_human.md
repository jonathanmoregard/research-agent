# Pending for human

## 2026-07-31: create a tuned Lakera project policy (cuts scanner false positives)

**Why blocked**: needs an action in the Lakera/Check Point dashboard under your account. The scanner side is already built; no code change substitutes for it.

**Background** — researched 2026-07-31, full report at `reports/70ed58e914644f6193b3ea3709134706.md`:

- Lakera's **default confidence threshold is L4 "Paranoid — higher false positives but very few false negatives"**, and their API reference says outright: *"ensure you have set up a project with a suitable chosen or configured policy rather than using our default policy. The Check Point default policy is intentionally strict and will likely flag more content than appropriate for production use."*
- Their troubleshooting names the **#1 false-positive cause** as *"passing system instructions within user message roles"* — precisely the shape of a research report that quotes or describes agent tooling.
- Independent measurement (BELLS, CeSIA + EPFL, arXiv 2507.06282) puts Lakera at **10.1% ± 4.9% FPR** on the shipped default; the vendor's 0.01–0.5% figures describe a *tuned* project at a lower level.
- Threshold tuning is the **strongest quantified lever** in the mitigation literature (AWS Bedrock harness: 24.0% → 6.0% → 0.0% FP across two threshold steps).

**Steps for human**:
1. Log in at https://platform.lakera.ai/ (Check Point AI Guard).
2. Create a project for research-agent; set its policy confidence threshold to **L3 (Stricter)** — keeps "very low false negatives" while shedding the paranoid tier's over-flagging. L2 (Balanced) if L3 still over-flags.
3. Copy the project id and expose it as `LAKERA_PROJECT_ID`. The scanner already reads this env var (`injection_scanner/lakera.py` → `payload["project_id"]`), so nothing needs writing — it is inert until the value exists. Add it to the env of the three call sites: `research-agent-mcp`, `futuresearch-gate-mcp`, `claude-cl-sync-wrap`.
4. Re-run a benign research call; confirm no `lakera:prompt_attack` quarantine.

**Everything else done**: the architectural half is already in place and matches the state of the art. injection-scanner `001eb1d` defers a `lakera:prompt_attack` classification into L4 judge arbitration instead of rejecting unilaterally — a report is delivered only if the behavioural honeypot is fully clean AND a cross-family judge panel unanimously rules "describes, not directs". Per the research, a single LLM judge is the best-measured design in this space (PromptArmor: <1% FPR *and* FNR on AgentDojo), while ensembles show "only modest gains" and multi-agent arbitration trades FP reduction for detection loss. research-agent's `uv.lock` pins that revision, and `~/Repos/injection-scanner` has been pulled up to it (it was 5 commits behind, which is why the arbitration code wasn't visible locally).

**Explicitly NOT done, and why**: no threshold was loosened in code. The only in-code lever would be treating a Lakera flag as advisory, which weakens a security boundary. The tuned policy above is the correct fix.

## 2026-07-30: RESOLVED — scanner quarantined agent-tooling reports

Root cause identified 2026-07-31: Lakera Guard's **default L4 "Paranoid"** policy, whose documented #1 FP trigger is instruction-shaped prose — exactly what a report *about* agent tooling looks like. Not a research-agent defect.

Mitigation already shipped in scanner `001eb1d` (L4 judge arbitration, see the 2026-07-31 entry above); remaining lever is the dashboard policy, tracked above. The suggested triage step (reading `reports/_quarantine/audit.jsonl` from a bare terminal) is still the way to attribute any *future* individual reject — the zone stays deny-listed to agents by design.

## 2026-07-28: RESOLVED — research pipeline down + watchdog killing runs

Kept for context; all three observations are now closed:

1. **"Deep runs overload the microvm; watchdog restarts the VM mid-run; the watchdog cannot distinguish busy from dead."** Partly right, mostly wrong — and the real cause was measured 2026-07-31. The probe used a bare `ssh-keyscan`, which scans rsa + ecdsa + ed25519; the guest serves **only** ed25519, so two of the three scans hung until `-T` and failed the whole probe ~40% of the time **regardless of load**. On 2026-07-29 fourteen restarts landed between 01:00 and 06:00 with zero research calls that day. Load was a red herring; the busy-gate heartbeat (a real improvement) treated a symptom. Fixed by deriving `-t` from the guest's own `hostKeys` — nixos-config PR #151.
2. **"Serialize calls until fixed."** Superseded. The exclusive lock is now a 3-slot semaphore: two concurrent deep calls peaked at 1.57 GB of a 6 GB guest, 0 OOM kills, CPU peak 0.68 of 2 vCPU.
3. **Scan-timing 5000 ms bucket is not a timeout clue.** Confirmed — it is `_SCAN_TIMING_BUCKET_MS` rounding, and an earlier session's "scanner timeout" theory built on it was wrong.
