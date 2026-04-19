# research-agent container.
#
# Pattern borrowed from trailofbits/claude-code-devcontainer:
#   https://github.com/trailofbits/claude-code-devcontainer
# Same Ubuntu 24.04 base, same bubblewrap-based per-call sandbox. We keep
# the image minimal — only what the research agent needs.
FROM mcr.microsoft.com/devcontainers/base:ubuntu24.04

ARG DEBIAN_FRONTEND=noninteractive

# Base tools + bubblewrap (bwrap) — used to spin a fresh, ephemeral jail for
# every research call so no state, cache, or scratch leaks between runs.
RUN apt-get update && apt-get install -y --no-install-recommends \
      bubblewrap \
      ca-certificates \
      curl \
      jq \
      tini \
      python3 \
      python3-pip \
      python3-venv \
    && rm -rf /var/lib/apt/lists/*

USER vscode
WORKDIR /workspace
ENV PATH="/home/vscode/.local/bin:$PATH"

# Claude Code (native installer).
RUN curl -fsSL https://claude.ai/install.sh | bash

# Host mounts this repo at /workspace. Reports land in /out (bind mount
# from host reports/). Each research call uses a fresh tmpfs scratch dir
# via bubblewrap — see scripts/run-agent.sh.
