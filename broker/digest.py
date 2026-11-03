"""The broker's code digest — the single implementation (§12.2 step 4).

The broker reports it at GET /admin/health as `code` (the digest of the code
it LOADED). The nixos code-watch oneshot runs `python3 -m broker.digest` from
the checkout root and reloads the broker when the two differ. Never
reimplement this elsewhere: the two repos version independently, and a quiet
disagreement means the broker reloads on every pull or never again.

Algorithm (this docstring is the source of truth): sha256 over, for each of
the sorted `broker/*.py` names followed by `scraper/urlpolicy.py`, the bytes
`<path relative to the checkout root>\\0<file content>\\0`, or
`<relative path>\\0missing\\0` when the file cannot be read. Relative paths,
so the digest does not depend on where the tree is mounted (the broker sees
it at /run/rb, the oneshot at /home/jonathan/Repos/research-agent).

Stdlib only, and imports nothing from the repo.
"""
from __future__ import annotations

import hashlib
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def code_digest(root: str = _ROOT) -> str:
    h = hashlib.sha256()
    rels = sorted(f"broker/{f}" for f in os.listdir(os.path.join(root, "broker"))
                  if f.endswith(".py"))
    rels.append("scraper/urlpolicy.py")
    for rel in rels:
        try:
            with open(os.path.join(root, rel), "rb") as f:
                h.update(rel.encode() + b"\0" + f.read() + b"\0")
        except OSError:
            h.update(rel.encode() + b"\0missing\0")
    return h.hexdigest()


if __name__ == "__main__":
    print(code_digest(sys.argv[1] if len(sys.argv) > 1 else _ROOT))
