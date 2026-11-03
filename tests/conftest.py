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
