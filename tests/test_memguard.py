"""Per-call memory guard rail (scripts/lib/memguard.sh).

Exercises the bash helper the same way tests/test_run_agent_ssh.py
exercises the ssh transport: without a live VM. `memguard.sh` is written
to be sourceable precisely so the classification logic is reachable from
here — the impure parts (`systemd-run`, the real cgroup) are either
probed at runtime or passed in as an argument, so every branch below runs
against a fixture directory instead of a kernel.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
MEMGUARD = REPO / "scripts" / "lib" / "memguard.sh"
RUN_AGENT = REPO / "scripts" / "run-agent.sh"


def _env(**overrides: str) -> dict[str, str]:
    """Ambient env minus RESEARCH_MEM_MAX, plus explicit overrides.

    PATH is inherited on purpose: the helpers shell out to awk/cat, and on
    NixOS those do not live in /bin or /usr/bin.
    """
    env = {k: v for k, v in os.environ.items() if k != "RESEARCH_MEM_MAX"}
    env.update(overrides)
    return env


def _sh(snippet: str, **overrides: str) -> subprocess.CompletedProcess:
    """Source memguard.sh in a fresh bash and run `snippet` against it.

    `set -euo pipefail` matches run-agent.sh, so a helper that misbehaves
    under the caller's shell options fails here rather than in the VM.
    """
    return subprocess.run(
        ["bash", "-c", f'set -euo pipefail\n. "{MEMGUARD}"\n{snippet}'],
        capture_output=True,
        text=True,
        env=_env(**overrides),
    )


def _cgroup_fixture(tmp_path: Path, oom_kill: int) -> Path:
    """Fixture cgroup dir holding a realistic memory.events."""
    d = tmp_path / "cgroup"
    d.mkdir(exist_ok=True)
    (d / "memory.events").write_text(
        f"low 0\nhigh 0\nmax 37\noom 1\noom_kill {oom_kill}\noom_group_kill 0\n"
    )
    return d


# --------------------------------------------------------------------
# memguard_cap — env parsing / validation
# --------------------------------------------------------------------

def test_default_cap_matches_sizing_invariant():
    """The shipped default, and the arithmetic behind it.

    memguard.sh sizes the cap so `slots * cap + guest_base <= guest_mem`:
    3 slots (_VM_SLOTS_DEFAULT), ~1100 MiB measured guest base, 6144 MiB
    guest => cap <= ~1680 MiB. If someone retunes either knob without the
    other, this fails and points at the comment that explains why.
    """
    r = _sh("memguard_cap")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "1536M"

    from mcp_server.server import _VM_SLOTS_DEFAULT

    guest_mem_mib, guest_base_mib = 6144, 1100
    assert _VM_SLOTS_DEFAULT * 1536 + guest_base_mib <= guest_mem_mib, (
        f"{_VM_SLOTS_DEFAULT} slots x 1536 MiB no longer fits in the guest — "
        "re-derive MEMGUARD_DEFAULT_CAP against the invariant in memguard.sh"
    )
    # And still far above a real call's measured 262 MiB cgroup peak.
    assert 1536 >= 4 * 262


def test_empty_env_falls_through_to_default():
    """`export RESEARCH_MEM_MAX=` must NOT silently disable the cap.
    Mirrors test_ssh_settings_empty_env_falls_through_to_default: an empty
    env var is a deployment accident, never an intent to run uncapped."""
    r = _sh("memguard_cap", RESEARCH_MEM_MAX="")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "1536M"


@pytest.mark.parametrize("value", ["1G", "3G", "2048M", "512K", "1T", "3221225472"])
def test_valid_caps_accepted(value):
    r = _sh("memguard_cap", RESEARCH_MEM_MAX=value)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == value


@pytest.mark.parametrize("value", ["off", "OFF", "none", "0"])
def test_cap_can_be_disabled(value):
    r = _sh("memguard_cap", RESEARCH_MEM_MAX=value)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "off"


@pytest.mark.parametrize(
    "value",
    [
        "2GB",                      # systemd wants "2G"; "2GB" is a real typo
        "2 G",
        "-1G",
        "abc",
        "2G; touch /tmp/pwned",
        "$(id)",
        "--property=MemoryMax=1",   # must never be parseable as a flag
        "0x10",
        "2.5G",
    ],
)
def test_invalid_caps_rejected(value):
    r = _sh("memguard_cap", RESEARCH_MEM_MAX=value)
    assert r.returncode != 0, f"{value!r} should be rejected, got {r.stdout!r}"


# --------------------------------------------------------------------
# memguard_scope_argv — the systemd-run prefix
# --------------------------------------------------------------------

def test_scope_argv_shape():
    r = _sh("memguard_scope_argv 2G research-abc.scope /workspace/scripts/lib/memguard.sh")
    assert r.returncode == 0, r.stderr
    argv = r.stdout.splitlines()
    assert argv[0] == "systemd-run"
    assert "--unit=research-abc.scope" in argv
    assert "--property=MemoryMax=2G" in argv
    # The command handed to the scope is the shim, invoked explicitly.
    assert argv[-4:] == ["bash", "/workspace/scripts/lib/memguard.sh", "--shim", "2G"]


def test_scope_argv_is_user_scope_not_system_scope():
    """`systemd-run --scope` against the system manager is denied for the
    `agent` user in the guest — measured: "Failed to start transient scope
    unit: Access denied". Dropping --user would break every call."""
    argv = _sh("memguard_scope_argv 2G u.scope /s.sh").stdout.splitlines()
    assert "--user" in argv
    assert "--scope" in argv


def test_scope_argv_sets_oom_policy_continue():
    """Load-bearing. Under the default OOMPolicy systemd tears the whole
    scope down on the first cgroup OOM and SIGTERMs the shim before it can
    read memory.events — the cap would then be indistinguishable from an
    operator kill (measured: bare rc=143)."""
    argv = _sh("memguard_scope_argv 2G u.scope /s.sh").stdout.splitlines()
    assert "--property=OOMPolicy=continue" in argv


def test_scope_argv_disables_swap():
    argv = _sh("memguard_scope_argv 2G u.scope /s.sh").stdout.splitlines()
    assert "--property=MemorySwapMax=0" in argv


# --------------------------------------------------------------------
# memguard_oom_count — reading the kernel counter
# --------------------------------------------------------------------

def test_oom_count_reads_counter(tmp_path):
    d = _cgroup_fixture(tmp_path, 3)
    assert _sh(f'memguard_oom_count "{d}"').stdout.strip() == "3"


def test_oom_count_missing_dir_is_zero(tmp_path):
    assert _sh(f'memguard_oom_count "{tmp_path}/nope"').stdout.strip() == "0"


def test_oom_count_empty_arg_is_zero():
    assert _sh('memguard_oom_count ""').stdout.strip() == "0"


def test_oom_count_garbage_is_zero(tmp_path):
    """A malformed memory.events must degrade to 0, not to a string that
    blows up the `-gt` comparison in memguard_shim_run."""
    d = tmp_path / "cgroup"
    d.mkdir()
    (d / "memory.events").write_text("oom_kill notanumber\n")
    assert _sh(f'memguard_oom_count "{d}"').stdout.strip() == "0"


# --------------------------------------------------------------------
# memguard_shim_run — outcome classification
# --------------------------------------------------------------------

def test_shim_passes_through_success(tmp_path):
    d = _cgroup_fixture(tmp_path, 0)
    r = _sh(f'memguard_shim_run "{d}" 2G true')
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("rc", [1, 2, 5, 42])
def test_shim_passes_through_failure_rc(tmp_path, rc):
    """An ordinary agent failure keeps its own exit code — the guard rail
    must not swallow or relabel it."""
    d = _cgroup_fixture(tmp_path, 0)
    r = _sh(f'memguard_shim_run "{d}" 2G bash -c "exit {rc}"')
    assert r.returncode == rc, r.stderr


def test_shim_reports_memcap_when_oom_counter_rises(tmp_path):
    """The cap-fired path: the counter rises while the command runs (here
    the command bumps the fixture itself, standing in for the kernel), so
    the shim must return the dedicated exit code and say so."""
    d = _cgroup_fixture(tmp_path, 0)
    bump = f'printf "oom_kill 1\\n" > "{d}/memory.events"; exit 137'
    r = _sh(f"memguard_shim_run \"{d}\" 2G bash -c '{bump}'")
    assert r.returncode == 75, (r.returncode, r.stderr)
    assert "MEMORY CAP EXCEEDED" in r.stderr
    assert "2G" in r.stderr


def test_shim_memcap_wins_over_zero_exit(tmp_path):
    """An OOM kill inside the jail fails the call even when the jail
    exited 0: some process vanished mid-run, so a report that still got
    written may be silently truncated. A clean retryable failure beats a
    silently incomplete research report."""
    d = _cgroup_fixture(tmp_path, 0)
    bump = f'printf "oom_kill 4\\n" > "{d}/memory.events"; exit 0'
    r = _sh(f"memguard_shim_run \"{d}\" 2G bash -c '{bump}'")
    assert r.returncode == 75
    assert "MEMORY CAP EXCEEDED" in r.stderr


def test_shim_no_cgroup_degrades_to_passthrough():
    """No unified hierarchy (dev checkout, odd container): run the command
    and pass its status through rather than failing the call."""
    r = _sh('memguard_shim_run "" 2G bash -c "exit 7"')
    assert r.returncode == 7, r.stderr


def test_shim_requires_marker_argument(tmp_path):
    """Executing the file without --shim must refuse, so a stray
    `bash memguard.sh <anything>` can never silently exec its args."""
    canary = tmp_path / "memguard-should-not-exist"
    r = subprocess.run(
        ["bash", str(MEMGUARD), "touch", str(canary)],
        capture_output=True,
        text=True,
        env=_env(),
    )
    assert r.returncode == 64, (r.returncode, r.stdout, r.stderr)
    assert not canary.exists()


# --------------------------------------------------------------------
# Distinguishability — the whole point of the exercise
# --------------------------------------------------------------------

def test_memcap_message_is_not_a_usage_limit():
    """A memory-capped call must NOT trip the server's Opus roll-over.
    Checked against the real `_hit_usage_limit`, so a future reword of
    either the marker or _LIMIT_MARKERS that made them collide fails here
    — that bug would turn "one call ate too much RAM" into "two calls ate
    too much RAM, the second on a different quota bucket"."""
    from mcp_server.server import _hit_usage_limit

    msg = _sh("memguard_report 2G 137 1 2147483648").stdout
    assert "MEMORY CAP EXCEEDED" in msg
    assert not _hit_usage_limit(msg), f"memcap message reads as a usage limit: {msg!r}"


def test_memcap_exit_code_is_unambiguous():
    """75 (EX_TEMPFAIL) must not collide with anything else run-agent.sh
    or the ssh transport can return: 0 ok, 2..6 config validation,
    137/143 bare signal deaths, 255 ssh transport failure."""
    code = int(_sh('printf %s "$MEMGUARD_EXIT_MEMCAP"').stdout.strip())
    assert code == 75
    assert code not in {0, 1, 2, 3, 4, 5, 6, 124, 137, 143, 255}


# --------------------------------------------------------------------
# Wiring — run-agent.sh actually uses the guard rail
# --------------------------------------------------------------------

def test_run_agent_wires_memguard_around_bwrap():
    """Structural check that the prefix array is expanded immediately
    before bwrap. Cheap insurance against a future edit that keeps the
    helper but detaches it from the jail."""
    src = RUN_AGENT.read_text()
    assert "lib/memguard.sh" in src
    assert '"${MEMGUARD_ARGV[@]}" \\\nbwrap \\' in src


def _dial_argv(monkeypatch, mem_max: str | None) -> str:
    """Run one mocked ssh dial and return the joined remote argv.

    Mirrors tests/test_run_agent_ssh.py: subprocess.run is stubbed so the
    exact remote command is observable without a live VM.
    """
    import subprocess as sp
    from unittest.mock import MagicMock, patch

    from mcp_server import server

    for k, v in {
        "RESEARCH_SSH_HOST": "127.0.0.1",
        "RESEARCH_SSH_PORT": "2223",
        "RESEARCH_SSH_KEY": "/fake/key",
        "RESEARCH_SSH_USER": "agent",
        "EXA_API_KEY": "x",
        "TAVILY_API_KEY": "x",
        "CLAUDE_CODE_OAUTH_TOKEN": "x",
    }.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(
        server, "_CLAUDE_CREDENTIALS_PATH", server.Path("/dev/null/nope")
    )
    server.SECRETS_CACHE.clear()

    if mem_max is None:
        monkeypatch.delenv("RESEARCH_MEM_MAX", raising=False)
    else:
        monkeypatch.setenv("RESEARCH_MEM_MAX", mem_max)

    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return MagicMock(returncode=0, stdout="DONE\n", stderr="")

    with patch.object(sp, "run", side_effect=fake_run):
        server._dial_agent(prompt="p", report_id="ab" * 16, depth="normal")
    return " ".join(captured["argv"])


def test_server_forwards_mem_max_when_operator_sets_it(monkeypatch):
    assert "RESEARCH_MEM_MAX=3G" in _dial_argv(monkeypatch, "3G")


def test_server_omits_mem_max_when_unset(monkeypatch):
    """Unset means "use the guest default" — the server must not invent a
    value, or memguard.sh's default would become dead code."""
    assert "RESEARCH_MEM_MAX" not in _dial_argv(monkeypatch, None)


@pytest.mark.parametrize("bad", ["2GB", "lots", "3G; rm -rf /"])
def test_server_drops_invalid_mem_max(monkeypatch, bad):
    """A typo degrades to the guest default rather than failing every
    call at the guest-side gate."""
    assert "RESEARCH_MEM_MAX" not in _dial_argv(monkeypatch, bad)


def test_mem_max_is_not_a_tool_param():
    """The cap is operator config, not caller input: a prompt-injected or
    merely greedy caller must not be able to raise its own ceiling."""
    import inspect

    from mcp_server import server

    assert "mem" not in inspect.signature(server.research).parameters


def test_run_agent_rejects_invalid_cap_before_running():
    """A typo'd RESEARCH_MEM_MAX fails the call immediately (exit 6) with
    a message naming the variable — not 20 minutes later with an opaque
    systemd error, and before any report file is touched."""
    r = subprocess.run(
        ["bash", str(RUN_AGENT), "a" * 32, "/dev/null"],
        capture_output=True,
        text=True,
        env=_env(RESEARCH_DEPTH="normal", RESEARCH_MEM_MAX="2GB"),
    )
    assert r.returncode == 6, (r.returncode, r.stdout, r.stderr)
    assert "RESEARCH_MEM_MAX" in r.stderr
