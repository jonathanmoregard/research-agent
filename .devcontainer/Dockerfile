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
      iptables \
      ipset \
      jq \
      tini \
      python3 \
      python3-pip \
      python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Python SDKs for Exa and Tavily. Shims in agent/shims/*_shim.py use these
# directly — same REST path the provider playgrounds use — bypassing both
# the hosted mcp.exa.ai/mcp.tavily.com endpoints and the Smithery-wrapped
# stdio MCPs (which break when spawned by Claude Code's MCP client via a
# currently-unexplained interaction with its spawn path in bwrap).
# --break-system-packages because container image is throwaway.
RUN pip3 install --no-cache-dir --break-system-packages \
      exa-py \
      tavily-python \
      curl_cffi

USER vscode
WORKDIR /workspace
ENV PATH="/home/vscode/.local/bin:$PATH"

# Claude Code (native installer).
RUN curl -fsSL https://claude.ai/install.sh | bash

# Switch back to root so the entrypoint can configure iptables.
# run-agent.sh drops privileges for the actual agent invocation via bwrap.
USER root
# bwrap inside --unshare-user maps uid 0 -> nobody, so the nsroot must be
# able to stat /home/vscode (default 750) to set up the ro-bind of .local.
RUN chmod 755 /home/vscode
ENTRYPOINT ["/workspace/scripts/container-entrypoint.sh"]

# Host mounts this repo at /workspace. Reports land in /out (bind mount
# from host reports/). Each research call uses a fresh tmpfs scratch dir
# via bubblewrap — see scripts/run-agent.sh.
