# Browser sessions + screenshots for the research agent

Date: 2026-07-10
Status: approved (in-conversation, 2026-07-10)

## Goal

Let the inner research agent navigate websites interactively — look at a
screenshot, decide, act (including hold-and-drag), look again — and let
selected screenshots survive as report artifacts the host/user can view,
gated by OCR + injection scan.

## Non-goals

- No browser inside the research-agent microvm (egress allowlist stays
  anthropic/exa/tavily only).
- No raw CDP exposure to the agent (would bypass the scraper's HTTP-layer
  SSRF/URL gate).
- No Puppeteer; the scraper already uses Playwright and stays on it.

## Architecture

```
inner agent (bwrap jail)
  └─ render shim (MCP) ──HTTP+bearer──▶ scraper microvm (Playwright sessions)
host mcp_server ──after run──▶ pulls artifacts from scraper ──OCR+scan──▶ reports/<id>/artifacts/
```

Trust model unchanged: browser runs only in the scraper VM; everything the
agent sees from the web is untrusted; nothing web-derived reaches the host
unscanned. Screenshots delivered to the inner agent are raw images
(accepted risk — the sandbox contains it, and agent/CLAUDE.md already
mandates treating web content as untrusted data).

## 1. Scraper session API (`scraper/server.py`)

In-memory session registry. Sessions die on scraper restart (acceptable;
agent re-opens). Sync-Playwright objects have thread affinity, so the
session manager owns a dedicated worker thread per session (or a single
browser thread with a command queue — implementer's choice, tested either
way).

Endpoints (all bearer-auth, same token as `/render`):

| Endpoint | Body | Returns |
|---|---|---|
| `POST /session/open` | `{url, viewport?}` | `{session_id, screenshot_b64, snapshot, final_url, title}` |
| `POST /session/{id}/act` | `{actions: [...]}` | same observation shape, captured after actions settle |
| `POST /session/{id}/screenshot` | `{full_page?}` | `{screenshot_b64}` |
| `POST /session/{id}/save_artifact` | `{name}` | `{stored: true, name}` — persists current-viewport PNG under `/artifacts/<run_id>/<name>.png` scraper-side |
| `POST /session/{id}/close` | — | `{closed: true}` |
| `GET /artifacts/{run_id}` | — | artifact list + bytes (host-side use only) |

Actions: `goto`, `click`, `fill`, `press`, `hover`, `scroll`,
`wait_for_selector`, `wait_ms`, `drag {from, to, steps?, hold_ms?}`
implemented via `mouse.down → move → up` (sliders, drag-and-drop, map
panning). Targets accept `ref` (from the ARIA snapshot) or CSS selector.

Snapshot: Playwright ARIA snapshot with element refs where the installed
Playwright supports it, so the agent acts on `ref=e42` instead of
guessing selectors from pixels. Fallback: selector-based actions only.

Guards (parity with `/render`):
- SSRF/URL blocklist enforced on `open` and every `goto` at the HTTP
  layer, before navigation.
- Max 2 concurrent sessions; idle TTL 5 min; max 20 actions per `act`
  call; run_id required for `save_artifact`.
- Viewport default 1280×720; screenshot response ≤ ~1 MiB (downscale or
  JPEG re-encode if over); artifact PNGs ≤ 2 MiB; ≤ 10 artifacts per run.

## 2. Agent-side MCP tools (`agent/shims/render_shim.py`)

New tools alongside `render_page` / `intercept_page`:

- `browse_open(url)` → MCP image content (screenshot) + snapshot text
- `browse_act(session_id, actions)` → image + snapshot
- `browse_screenshot(session_id, full_page=False)` → image
- `browse_save_screenshot(session_id, name)` → confirmation
- `browse_close(session_id)` → confirmation

Text parts (snapshot, titles, URLs) wrapped in
`<untrusted_external_content>` in-shim. Note: the PostToolUse wrap hook
regex in `agent/.claude/settings.json` does not currently cover the
render shim — make wrapping consistent in-shim for all render tools while
in here.

`run_id` reaches the shim via env var (`RESEARCH_RUN_ID`) exported by
`scripts/run-agent.sh` into the bwrap jail.

Tool availability: `normal` and `deep` depths (added to the
allowed-tools lists in `run-agent.sh`); `fast` never invokes the agent.

## 3. Host artifact gate (`mcp_server/server.py`)

After the agent exits and the report text passes the existing scan:

1. Host pulls `GET /artifacts/{run_id}` from the scraper.
2. Per image: tesseract OCR → text → same ensemble `_scan_text()`.
3. Pass → write to `reports/<id>/artifacts/<name>.png`; report links
   (`artifacts/<name>.png`) resolve as written.
4. Fail → move to quarantine dir + audit record (same pattern as report
   quarantine); annotate the report link.
5. Scraper-side artifact dir for the run is deleted after pull.

Artifacts persist scraper-side (not via the jail's writable mount), so
the jail keeps its single-writable-file invariant and the agent cannot
tamper with pixels — the PNG is exactly what the browser rendered.

Residual risk (accepted): OCR is best-effort; adversarial text rendering
tesseract can't read will pass the gate. Host viewers still see images
as images.

New host dependency: tesseract (nix-packaged into the mcp_server
environment). Scraper VM needs no new system deps.

## Open implementation question (resolve during planning)

How `scraper/server.py` changes reach the running scraper microvm
(nixos-config module packaging vs. shared path) — the implementation plan
must identify the existing deployment mechanism and reuse it; no new
deployment machinery.

## 4. Testing

- Scraper: pytest against a local fixture site — session lifecycle, drag
  on a slider fixture, TTL expiry, concurrency cap, SSRF blocklist on
  `goto`, artifact size/count caps. Follow `test_scraper_intercept.py`
  patterns.
- Shim: mocked-HTTP tests following `test_render_shim.py`.
- Host gate: fixture PNGs — one clean, one with an injection string
  rendered into the image (PIL) → must quarantine; OCR-failure path
  fails closed.
- E2E smoke: one real `research()` call on a JS-heavy page; verify the
  screenshot artifact lands in `reports/<id>/artifacts/`.

## 5. Error handling

- Unknown/expired session → clear error instructing the agent to
  `browse_open` again.
- Concurrency cap hit → error advising `browse_close` of an idle session.
- Scraper unreachable → same normalized RuntimeError shape as existing
  render tools.
- OCR/scan errors on artifacts → fail closed (quarantine).
