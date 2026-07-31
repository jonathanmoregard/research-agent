#!/usr/bin/env bash
# Per-call memory guard rail for the research jail.
#
# WHY
# ---
# One research call == one `bwrap` jail (see ../run-agent.sh). Nothing
# used to bound a single call's RSS. A pathological run — classically a
# browse session accumulating base64 screenshots in the agent's context —
# could grow until the whole 6 GiB microvm went into heavy reclaim. That
# is not a self-contained failure: reclaim pressure stalls sshd, the host
# watchdog's ssh-keyscan probe times out, and the watchdog RESTARTS the VM
# out from under every OTHER in-flight call (exactly the 2026-07-30 13:11
# incident that took the guest from 3 GiB to 6 GiB). So the cap exists to
# make a runaway call die ALONE, not to make honest calls fit.
#
# Sizing data (measured 2026-07-31, 6 GiB guest, 2 vCPU). Two figures,
# and they measure DIFFERENT things — do not conflate them when retuning:
#   Guest-wide RSS: two concurrent `normal` calls peaked at 1.55 GB and
#     two concurrent `deep` at 1.57 GB, 0 OOM kills, CPU peak 0.68 of 2
#     vCPU. That is ~0.8 GB "per call", but it includes the guest kernel,
#     sshd, systemd and the page cache holding /nix/store.
#   Cgroup-charged peak of ONE call, which is what MemoryMax actually
#     bounds: a real `deep` call (claude-opus-5, live web work, 10 KB
#     report, 362 s) peaked at 274718720 bytes == 262 MiB. Read off
#     memory.peak by the telemetry line in memguard_shim_run.
# The second number is the one the cap must clear, because a cgroup only
# gets charged for pages it faults in first — most of the /nix/store
# footprint is already charged to whoever booted the guest.
#
# MECHANISM
# ---------
# `systemd-run --user --scope` puts the jail in its own transient cgroup
# with MemoryMax set. Verified empirically inside this guest 2026-07-31 —
# do not "simplify" any of these away:
#   - `systemd-run --scope` (system manager) fails for the `agent` user
#     with "Failed to start transient scope unit: Access denied". Making
#     it work needs a polkit rule granting org.freedesktop.systemd1
#     manage-units to a non-root user, i.e. a nixos-config change that
#     widens the guest's privilege surface. Not worth it.
#   - `systemd-run --user --scope` works with NO polkit rule and NO
#     `loginctl enable-linger`. pam_systemd starts user@1000.service for
#     the ssh session that run-agent.sh already runs inside, and the
#     memory controller is delegated all the way down:
#       user-1000.slice          cgroup.subtree_control = cpu io memory pids
#       user@1000.service        cgroup.subtree_control = cpu memory pids
#     Lingering is irrelevant precisely because we only ever run inside a
#     live session — the scope is a descendant of the process tree that
#     the session owns, so the manager cannot outlive-and-reap us.
#
# Rejected alternatives:
#   - `ulimit -v` caps VIRTUAL address space, not RSS. V8 reserves large
#     virtual regions it never faults in, so any -v generous enough to let
#     a normal call start is far above a useful RSS bound, and any -v
#     tight enough to bound RSS makes node abort during heap setup. It is
#     the wrong instrument for this, not merely a blunt one.
#   - `ulimit -m` (RLIMIT_RSS) is a no-op on Linux; the kernel has ignored
#     it since 2.4.
#   - Hand-rolling a cgroup directly under the delegated subtree works,
#     but reimplements scope naming, lifecycle and cleanup that systemd
#     already gets right, and leaks cgroup dirs whenever a call is killed.
#
# DUAL ROLE
# ---------
# This file is both:
#   1. SOURCED by run-agent.sh (and by tests/test_memguard.py) for the
#      pure helpers below, and
#   2. EXECUTED as the first process inside the transient scope, via
#      `bash memguard.sh --shim <cap> <cmd...>`, where it runs the jail
#      and then reads the scope cgroup's own `memory.events` to decide
#      whether the cap fired.
# The bookkeeping MUST happen inside the scope: the transient cgroup is
# destroyed the instant the scope empties, so there is no window in which
# run-agent.sh could read the counter from outside.

# Default cap. The sizing invariant, which is the thing to re-derive if
# ANY of the three inputs move:
#
#     slots * cap  +  guest_base  <=  guest_mem
#
#   guest_mem  = 6144 MiB   (microvm.mem, nixos-config
#                            modules/nixos/research-agent-microvm.nix)
#   guest_base ~ 1100 MiB   (measured idle: 636 MiB used + 474 MiB
#                            buff/cache — kernel, systemd, sshd, and the
#                            page cache the virtiofs shares live in)
#   slots      = 3          (_VM_SLOTS_DEFAULT in mcp_server/server.py)
#
#   => cap <= (6144 - 1100) / 3 ~= 1680 MiB.  1536 MiB (1.5 GiB) sits just
#      under that with room to spare.
#
# Why that invariant and not just "bound one hog": with three admission
# slots, three simultaneous runaway calls are reachable. If slots * cap
# exceeds what the guest actually has, the cgroups are individually
# bounded but collectively still able to drive the VM into global reclaim
# — which stalls sshd, trips the host watchdog, and restarts the VM. That
# is precisely the incident this guard rail exists to prevent, so the cap
# has to be sized against the WORST case, not the typical one.
#
# And it is still generous for honest work: 1.5 GiB is ~5.9x the 262 MiB
# cgroup peak measured on a real deep call. A cap that occasionally kills
# legitimate calls would be worse than no cap at all — it would convert a
# rare VM-wide incident into a frequent per-call one — so the margin
# matters more than tightness.
#
# NOTE: this default was 2G until concurrency moved from 1 slot to 3
# (server: "admit N concurrent research calls instead of strictly one").
# 3 x 2 GiB = 6 GiB is the entire guest, leaving nothing for the kernel.
# If RESEARCH_SLOTS is raised again, re-run the arithmetic above — the two
# knobs are coupled and neither is safe to tune alone.
#
# Do NOT tighten this toward the measured peak either. At 256M a real deep
# call still completed (measured) — but only because the cgroup thrashed
# page cache to stay under, turning the cap into a silent latency tax
# instead of a guard rail. It should bind only on pathology.
#
# Override with RESEARCH_MEM_MAX (systemd syntax: bare bytes, or a
# K/M/G/T suffix); "off"/"none"/"0" disables the cap entirely.
MEMGUARD_DEFAULT_CAP="1536M"

# Exit code the wrapper returns when the cap fired.
# Deliberately NOT 137/143: a bare SIGKILL/SIGTERM exit is
# indistinguishable from an operator kill or a watchdog VM restart.
# Deliberately outside the 2..6 block run-agent.sh uses for argument
# validation. 75 is sysexits.h EX_TEMPFAIL, "temporary failure, the user
# is invited to retry", which is the correct semantics: the call is
# retryable and the input is not necessarily wrong.
MEMGUARD_EXIT_MEMCAP=75

# Marker printed on the cap-fired path.
# MUST NOT contain the substring "usage limit": mcp_server/server.py's
# `_hit_usage_limit` does a case-insensitive contains-match for exactly
# that phrase and would otherwise re-dial the entire call on the Opus
# fallback quota — turning "one call ate too much RAM" into "two calls
# ate too much RAM" and burning a second quota bucket to do it.
# tests/test_memguard.py asserts this against the real `_hit_usage_limit`.
MEMGUARD_MARKER="MEMORY CAP EXCEEDED"


memguard_cap() {
    # Resolve the effective cap from RESEARCH_MEM_MAX.
    # Prints the normalised value, or "off" when disabled. Returns 1 on a
    # value systemd would not accept.
    #
    # `${VAR-}` not `${VAR:-}`: an exported-but-empty RESEARCH_MEM_MAX
    # falls through to the default rather than disabling the guard rail.
    # Same semantics the ssh settings already use (see
    # test_ssh_settings_empty_env_falls_through_to_default) — an empty
    # env var is a deployment accident, never an intent to run uncapped.
    local raw="${RESEARCH_MEM_MAX-}"
    [ -n "${raw}" ] || raw="${MEMGUARD_DEFAULT_CAP}"

    case "${raw}" in
        off | OFF | none | 0) printf 'off\n'; return 0 ;;
    esac

    # Validate here rather than letting systemd-run reject it downstream:
    # a typo'd cap would otherwise fail EVERY call with an opaque systemd
    # error long after the operator who set it has stopped looking.
    # Note "2GB" is intentionally invalid — systemd wants "2G".
    if [[ "${raw}" =~ ^[1-9][0-9]*[KMGT]?$ ]]; then
        printf '%s\n' "${raw}"
        return 0
    fi
    return 1
}


memguard_scope_argv() {
    # Print the systemd-run prefix argv, one element per line, for
    # `mapfile -t` on the caller side. None of these elements can contain
    # a newline (cap is regex-gated, unit is derived from the hex uuid,
    # shim path is a literal), so line-delimited output is lossless.
    local cap="${1:?cap required}"
    local unit="${2:?unit name required}"
    local shim="${3:?shim path required}"

    printf '%s\n' \
        systemd-run \
        --user \
        --scope \
        --quiet \
        --collect \
        "--unit=${unit}" \
        "--property=MemoryMax=${cap}" \
        "--property=MemorySwapMax=0" \
        "--property=OOMPolicy=continue" \
        -- \
        bash \
        "${shim}" \
        --shim \
        "${cap}"

    # --user           : see MECHANISM above; the system manager denies us.
    # --quiet          : suppress "Running scope as unit ..."; run-agent.sh
    #                    prints its own, denser line.
    # --collect        : reap the transient unit even if it ends up failed,
    #                    so a long-lived user manager does not accumulate
    #                    dead research-<uuid>.scope units.
    # MemorySwapMax=0  : the guest has no swap today (`free -m` -> Swap 0),
    #                    but if swap is ever added, a capped-but-swappable
    #                    jail would thrash the VM's IO for hours instead of
    #                    dying. Cheap insurance against a future config.
    # OOMPolicy=continue: LOAD-BEARING. With the default policy systemd
    #                    tears the whole scope down on the first cgroup OOM
    #                    — measured in this guest: the shim shell is
    #                    SIGTERMed and run-agent.sh sees a bare rc=143,
    #                    which is exactly the "indistinguishable from an
    #                    operator kill" outcome this file exists to avoid.
    #                    `continue` leaves the scope up so the shim
    #                    survives to read memory.events and report.
}


memguard_self_cgroup() {
    # Absolute path of the calling process's cgroup v2 directory.
    # Returns 1 (and prints nothing) if there is no unified hierarchy —
    # the caller degrades to running uncapped rather than failing.
    local rel
    rel="$(awk -F: '$1 == "0" { print $3; exit }' /proc/self/cgroup 2>/dev/null)"
    [ -n "${rel}" ] || return 1
    printf '%s\n' "/sys/fs/cgroup${rel}"
}


memguard_oom_count() {
    # Print the cgroup's cumulative oom_kill counter, or 0 if unreadable.
    #
    # oom_kill is the ONLY honest signal here. The sibling counters in
    # memory.events are traps:
    #   `max`  increments every time the cgroup merely touched the ceiling;
    #          reclaim usually resolves that and the call finishes fine, so
    #          keying on it would fail healthy calls.
    #   `oom`  counts OOM-handler invocations, which can happen without a
    #          process actually dying.
    # Only oom_kill means "the cap took something out".
    local dir="${1-}"
    local n=""
    if [ -n "${dir}" ] && [ -r "${dir}/memory.events" ]; then
        n="$(awk '$1 == "oom_kill" { print $2; exit }' "${dir}/memory.events" 2>/dev/null)"
    fi
    [[ "${n}" =~ ^[0-9]+$ ]] || n=0
    printf '%s\n' "${n}"
}


memguard_report() {
    # The operator-facing line for the cap-fired path. Kept in one place
    # so tests can assert both what it says and — more importantly — what
    # it does not say (see MEMGUARD_MARKER).
    local cap="${1}" rc="${2}" killed="${3}" peak="${4-}"
    printf 'run-agent: %s — per-call memory cap %s fired: the kernel SIGKILLed %s process(es) inside the jail (jail rc=%s, cgroup peak=%s bytes). This is a resource guard rail, NOT a model quota rejection and NOT an ordinary agent error. Retry the call; if it recurs, raise RESEARCH_MEM_MAX or split the prompt.\n' \
        "${MEMGUARD_MARKER}" "${cap}" "${killed}" "${rc}" "${peak:-unknown}"
}


memguard_shim_run() {
    # Run <cmd...> and classify the outcome against <cgdir>'s oom counter.
    # `cgdir` is passed in rather than resolved internally so this whole
    # function is unit-testable against a fixture directory containing a
    # fake memory.events — see tests/test_memguard.py.
    local cgdir="${1-}"; shift
    local cap="${1:?cap required}"; shift

    local before after rc=0 peak=""
    before="$(memguard_oom_count "${cgdir}")"

    # Raise the jail's oom_score_adj so the kernel's in-cgroup OOM killer
    # prefers it over this bookkeeping shell. Unprivileged processes may
    # RAISE oom_score_adj (only lowering needs CAP_SYS_RESOURCE), and the
    # value is inherited across fork/exec, so every process in the jail
    # inherits 500 while this shell stays at 0. Verified in the guest: the
    # hog is killed, this shell survives to read the counter. Without it
    # the kernel could pick the shim and we would lose the classification
    # for no reason. Non-fatal if the write fails (e.g. a hardened /proc):
    # the counter check below still works, we just lose the bias.
    # NB: the write happens in the SUBSHELL, not here — raising this
    # shell's own oom_score_adj would make the bookkeeping process just as
    # attractive a victim as the jail and defeat the whole point.
    ( { echo 500 > /proc/self/oom_score_adj; } 2>/dev/null; exec "$@" ) || rc=$?

    after="$(memguard_oom_count "${cgdir}")"
    peak="$(cat "${cgdir}/memory.peak" 2>/dev/null || true)"

    if [ "${after}" -gt "${before}" ]; then
        # Fail the call even when rc==0. An OOM kill inside the jail means
        # some process (the agent, or one of its MCP shims) vanished
        # mid-run, so a report that still got written may be silently
        # truncated or missing sources. A silently incomplete research
        # report is worse than a clean, retryable failure.
        memguard_report "${cap}" "${rc}" "$((after - before))" "${peak}" >&2
        return "${MEMGUARD_EXIT_MEMCAP}"
    fi

    # Headroom telemetry on the normal path. One line, same `run-agent:`
    # prefix as every other message from this layer. Without it the cap is
    # an unfalsifiable number: an operator asking "is 2G right for my
    # workload?" has no way to answer, because the transient cgroup — and
    # with it memory.peak — is destroyed the moment this shell exits.
    printf 'run-agent: memory cap %s ok (cgroup peak=%s bytes)\n' \
        "${cap}" "${peak:-unknown}" >&2
    return "${rc}"
}


memguard_available() {
    # Probe, do not infer. `systemd-run --user` needs both a running user
    # manager and a reachable user bus. Both exist for an ssh login
    # session in the guest, and neither exists in a bare container or on a
    # developer checkout — and the difference is not something we can read
    # off any single file. `--scope true` is a ~10 ms no-op.
    command -v systemd-run > /dev/null 2>&1 || return 1
    systemd-run --user --scope --quiet --collect -- true > /dev/null 2>&1
}


# Executed rather than sourced => act as the in-scope shim.
# `--shim` is mandatory so a stray `bash memguard.sh ...` can never
# silently execute its arguments.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    set -uo pipefail
    if [ "${1-}" != "--shim" ]; then
        echo "memguard.sh: not a standalone command." >&2
        echo "memguard.sh: source it for helpers, or run: memguard.sh --shim <cap> <cmd...>" >&2
        exit 64
    fi
    shift
    memguard_shim_run "$(memguard_self_cgroup || true)" "$@"
    exit $?
fi
