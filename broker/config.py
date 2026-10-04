"""Broker operator inputs: the single source for budgets, caps and timeouts.

Budgets are deliberately generous starting points. Every run's usage is
logged at deregistration; after a week of logs they get replaced by the
observed p99 plus margin (docs/egress-broker.md §2.3, §8.4). They are
inputs, not fitted constants the design depends on.

Upstream hosts, paths and methods are NOT here: they are code constants in
the route modules, never config or env.
"""
from __future__ import annotations

# --- listeners (systemd socket activation; these are the dev fallbacks) ----
VM_HOST = "127.0.0.1"
VM_PORT = 8124  # research VM reaches it as 10.0.2.2:8124 through SLIRP
ADMIN_SOCKET = "/run/research-broker/admin.sock"
# systemd FileDescriptorName= of each socket unit
FD_NAME_VM = "vm"
FD_NAME_ADMIN = "admin"

# --- the scraper (host loopback hostfwd into the scraper VM) ---------------
SCRAPER_BASE = "http://127.0.0.1:8123"
SCRAPER_TOKEN_FILE = "/var/lib/scraper-bearer/token"

# --- credentials: LoadCredential= names, read from $CREDENTIALS_DIRECTORY ---
CREDENTIAL_NAMES = (
    "exa-api-key",
    "tavily-api-key",
    "euipo-client-id",
    "euipo-client-secret",
    "ebay-client-id",
    "ebay-client-secret",
    "tradera-app-id",
    "tradera-app-key",
)

# --- request bodies ---------------------------------------------------------
MAX_BODY_BYTES = 64 * 1024
MAX_BROWSER_BODY_BYTES = 256 * 1024  # act / intercept
MAX_ADMIN_BODY_BYTES = 256 * 1024    # prompt_urls

DEPTHS = ("normal", "deep")

# --- per-run call budgets (normal, deep) ------------------------------------
ROUTE_BUDGETS: dict[str, dict[str, int]] = {
    "exa": {"normal": 40, "deep": 120},
    "tavily": {"normal": 20, "deep": 60},
    # agent/CLAUDE.md: "25 requests per marketplace per run" (drift-tested)
    "ebay": {"normal": 25, "deep": 25},
    "tradera": {"normal": 25, "deep": 25},
    "euipo": {"normal": 20, "deep": 40},
    # renders + intercepts share one budget
    "render": {"normal": 60, "deep": 150},
    # session/open + act calls share one budget
    "browse": {"normal": 60, "deep": 150},
}
# Browser actions per run: each act/intercept action, each open, each
# screenshot and each saved artifact counts one (§3.6).
BROWSER_ACTIONS = {"normal": 150, "deep": 300}
# Characters typed into pages per run (fill text + printable press keys).
TYPED_CHARS = {"normal": 300, "deep": 600}
# Raw-coordinate channel caps: refs are preferred; these bound the rest.
MAX_DRAGS_PER_RUN = 10
MAX_XY_TARGETS_PER_RUN = 30

# --- ledger ------------------------------------------------------------------
# Worst legitimate feed: 2000 links x 150 renders/acts (deep) = 300 000 plus
# search results. ~100 B/URL -> ~40 MB per run; MemoryMax=1G covers two VM
# slots. No per-host cap: a single-host shopping run legitimately exceeds
# 20 000 URLs (advisor pass, 2026-10-04).
LEDGER_MAX_URLS = 400_000
# How many ledger URLs travel to the scraper with each intercept/open/act.
NAV_POLICY_MAX_URLS = 20_000

# --- marketplace etiquette (moved from the shopping shim) --------------------
MARKETPLACE_MIN_INTERVAL_S = 2.0
UPSTREAM_CONCURRENCY = 4  # per route

# --- timeouts (strict ordering: shim > broker > scraper HTTP wait > worker) --
# Keyed APIs: one upstream call is bounded by KEYED_UPSTREAM_TIMEOUT_S; a
# route that first mints an OAuth token (eBay, EUIPO cold cache) is bounded
# as a whole by KEYED_ROUTE_DEADLINE_S, so the shim (SHIM_KEYED_TIMEOUT_S)
# always sees the upstream error, never "broker unavailable".
KEYED_UPSTREAM_TIMEOUT_S = 30.0
OAUTH_MINT_TIMEOUT_S = 10.0
KEYED_ROUTE_DEADLINE_S = 35.0
SHIM_KEYED_TIMEOUT_S = 45.0
# Scraper routes: broker -> scraper HTTP timeout per endpoint.
SCRAPER_TIMEOUT_S = {
    "render": 100.0,
    "intercept": 100.0,
    "open": 135.0,
    "act": 165.0,
    "screenshot": 135.0,
    "save_artifact": 135.0,
    "close": 135.0,
}
# What the shims wait for the broker (mirrored in agent/shims; tested).
SHIM_SCRAPER_TIMEOUT_S = {
    "render": 115.0,
    "intercept": 115.0,
    "open": 150.0,
    "act": 180.0,
    "screenshot": 150.0,
    "save_artifact": 150.0,
    "close": 150.0,
}

# --- run lifetime -------------------------------------------------------------
MAX_RUN_TTL_S = 6 * 3600
SWEEP_INTERVAL_S = 30.0
