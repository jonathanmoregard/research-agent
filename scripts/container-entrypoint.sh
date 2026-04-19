#!/usr/bin/env bash
# Container entrypoint: runs the outbound firewall, drops to vscode, then
# execs the container's main command (tail -f /dev/null for long-running
# worker mode).
#
# Runs as root (Docker default) so iptables/ipset work; the actual research
# jail is launched by the non-root vscode user via bwrap in run-agent.sh.

set -euo pipefail

# Apply network allowlist. Needs --cap-add=NET_ADMIN on the container.
if ! bash /workspace/scripts/init-firewall.sh; then
  echo "[entrypoint] firewall init failed — aborting for safety" >&2
  exit 1
fi

# Hand off. If nothing was passed, keep the container alive as a worker.
if [[ $# -eq 0 ]]; then
  exec tail -f /dev/null
fi
exec "$@"
