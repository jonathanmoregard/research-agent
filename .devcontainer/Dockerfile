# Base: Trail of Bits dev container.
#
# TODO: pin the exact Trail of Bits image tag. Replace the FROM line below
# with the canonical reference once confirmed. Candidates:
#   - ghcr.io/trailofbits/devcontainers/base
#   - ghcr.io/trailofbits/algo-vm (security-hardened)
# For now we fall back to the Microsoft Python devcontainer image, which is
# the same upstream base many ToB containers extend.
FROM mcr.microsoft.com/devcontainers/python:3.12

# Claude Code CLI
# Official install script; version pinned via CLAUDE_CODE_VERSION env if needed.
RUN curl -fsSL https://claude.ai/install.sh | bash -s -- --yes \
    && claude --version

# Non-root user 'vscode' already exists in the base image.
USER vscode
WORKDIR /workspace

# Minimal Python deps; the rest come from postCreateCommand so the image
# rebuild isn't required when server deps change.
RUN pip install --user --no-cache-dir mcp>=1.0.0

# Scratch dir is tmpfs (see devcontainer.json runArgs). /out is the bind
# mount from the host reports/ directory.
