"""Code digest: the single implementation for the broker and the scraper.

Each service reports the digest of the code it LOADED and, on its own,
compares it with the code on disk (docs/egress-broker.md §12.2 step 4,
§12.3 step 1). Root-run units never hash anything; they act on the answer.

It lives in scraper/ because that is the one directory both services see:
the broker runs with broker/ and scraper/ bound at /run/rb, and the scraper
VM's share holds only scraper/ (mounted at /workspace/scraper). broker/digest.py
picks the broker's file set and calls tree_digest(); never hash elsewhere.

Algorithm (this docstring is the source of truth): sha256 over, for each
relative path in the given order, the bytes `<path>\\0<file content>\\0`, or
`<path>\\0missing\\0` when the file cannot be read. Paths are relative to the
checkout root (the directory holding broker/ and scraper/), so the digest
does not depend on where the tree is mounted.

Stdlib only and imports nothing from the repo: the scraper imports this as
`digest` (its directory is on sys.path), the broker as `scraper.digest`.
"""
from __future__ import annotations

import hashlib
import os


def py_files(root: str, subdir: str) -> list[str]:
    """Sorted `<subdir>/<name>.py` for the top level of root/subdir; [] if it is gone."""
    try:
        names = os.listdir(os.path.join(root, subdir))
    except OSError:
        return []
    return sorted(f"{subdir}/{n}" for n in names if n.endswith(".py"))


def tree_digest(root: str, rels: list[str]) -> str:
    h = hashlib.sha256()
    for rel in rels:
        try:
            with open(os.path.join(root, rel), "rb") as f:
                h.update(rel.encode() + b"\0" + f.read() + b"\0")
        except OSError:
            h.update(rel.encode() + b"\0missing\0")
    return h.hexdigest()


def scraper_digest(root: str) -> str:
    """The scraper's code: every scraper/*.py (scraper-http imports them all)."""
    return tree_digest(root, py_files(root, "scraper"))
