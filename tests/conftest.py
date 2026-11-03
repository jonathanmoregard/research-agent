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

from tests._network_guard import GUARD  # noqa: E402  (installs on import)

_NO_EGRESS_STATE = _LOG_DIR / "no-egress-state"


@pytest.fixture(autouse=True)
def _host_egress_state_isolated(monkeypatch):
    """Never let a test see this host's deploy state (§12.4) or its scraper.

    `_dial_agent` reads /etc/research-agent/egress-era and the broker admin
    socket. On a host past nixos-A (live broker, `.guest-protocol` in the
    checkout) an unpatched dial test would register a run with the REAL
    broker; past nixos-B it would fail closed. Point both at paths that do
    not exist, i.e. today's pre-broker host. Tests that exercise the dual
    mode override these with their own files.
    """
    from mcp_server import server

    monkeypatch.setattr(server, "_EGRESS_ERA_PATH", _NO_EGRESS_STATE / "egress-era")
    monkeypatch.setattr(server, "_ROLL_MARKER_PATH", _NO_EGRESS_STATE / "rolling")
    monkeypatch.setenv("RESEARCH_BROKER_ADMIN", str(_NO_EGRESS_STATE / "admin.sock"))
    # Nor this host's scraper: research() pulls and discards its artifacts at
    # 127.0.0.1:8123 with the host bearer, which is world-readable. No bearer
    # file → the pull fails before it connects.
    from mcp_server import artifact_gate

    monkeypatch.setattr(artifact_gate, "SCRAPER_HOST_TOKEN_FILE",
                        str(_NO_EGRESS_STATE / "scraper-bearer"))
    # Nor write G3 protocol markers into the real /run/user/<uid>.
    from mcp_server import mcp_marker

    monkeypatch.setattr(mcp_marker, "default_dir", lambda: _NO_EGRESS_STATE / "mcp-markers")


@pytest.fixture(autouse=True)
def _no_external_network():
    """Fail any test that tried to leave the host (§8.1), even if the code
    under test caught the refusal and carried on."""
    mark = len(GUARD.violations)
    yield
    tried = GUARD.violations[mark:]
    if tried:
        del GUARD.violations[mark:]
        pytest.fail("test tried to reach the network (tests are hermetic; use a "
                    "loopback stub): " + ", ".join(f"{v.via} -> {v.target!r}" for v in tried),
                    pytrace=False)


@pytest.fixture
def network_guard():
    return GUARD
