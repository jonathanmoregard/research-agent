"""Suite-wide test isolation.

`mcp_server.server` reads `RESEARCH_AGENT_LOG` at import and installs its
file handler then, so the redirect has to happen here: pytest loads this
file before any test module imports the server. Without it every test run
appended boot and stage lines (fake `id=dddd…` reports included) to the real
`~/.cache/research-agent/server.log`, the log operators triage production
failures from. Set unconditionally, not `setdefault`, so an exported value
pointing at the real log cannot leak through; subprocesses the tests spawn
inherit it.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

_LOG_DIR = Path(tempfile.mkdtemp(prefix="research-agent-test-log-"))
os.environ["RESEARCH_AGENT_LOG"] = str(_LOG_DIR / "server.log")


import pytest  # noqa: E402

_NO_EGRESS_STATE = _LOG_DIR / "no-egress-state"


@pytest.fixture(autouse=True)
def _host_egress_state_isolated(monkeypatch):
    """Never let a test see this host's deploy state (§12.4).

    `_dial_agent` reads /etc/research-agent/egress-era and the broker admin
    socket. On a host past nixos-A (live broker, `.guest-protocol` in the
    checkout) an unpatched dial test would register a run with the REAL
    broker; past nixos-B it would fail closed. Point both at paths that do
    not exist, i.e. today's pre-broker host. Tests that exercise the dual
    mode override these with their own files.
    """
    from mcp_server import server

    monkeypatch.setattr(server, "_EGRESS_ERA_PATH", _NO_EGRESS_STATE / "egress-era")
    monkeypatch.setenv("RESEARCH_BROKER_ADMIN", str(_NO_EGRESS_STATE / "admin.sock"))
