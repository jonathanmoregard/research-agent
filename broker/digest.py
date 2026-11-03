"""The broker's code digest (docs/egress-broker.md §12.2 step 4).

The broker reports the digest of the code it LOADED at GET /admin/health as
`code`. On SIGHUP it recomputes this over the tree it runs from and drains
only when the two differ; the root-run code-watch oneshot reloads
unconditionally and never hashes anything itself.

This module only picks the broker's file set: the sorted `broker/*.py`, then
the scraper/ files the broker imports (SCRAPER_DEPS). The hashing is
scraper/digest.py's tree_digest(), shared with the scraper's own /health;
never reimplement it.

`python3 -m broker.digest [root]` from the checkout root prints the digest,
for an operator comparing a checkout with /admin/health.
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:  # `python3 -I` puts neither cwd nor the script dir on it
    sys.path.insert(0, _ROOT)

from scraper.digest import py_files, tree_digest  # noqa: E402


# Every scraper/ module the broker imports; a change to any of them is a
# change to the broker's code.
SCRAPER_DEPS = ["scraper/digest.py", "scraper/urlpolicy.py"]


def code_digest(root: str = _ROOT) -> str:
    return tree_digest(root, py_files(root, "broker") + SCRAPER_DEPS)


if __name__ == "__main__":
    print(code_digest(sys.argv[1] if len(sys.argv) > 1 else _ROOT))
