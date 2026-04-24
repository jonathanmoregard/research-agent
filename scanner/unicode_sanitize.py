"""
Layer 0: Unicode normalization + covert-channel stripping.

Based on the convergent recommendation from Boucher et al. ("Bad Characters",
IEEE S&P 2022), Unicode Technical Standard #39 (confusables), Trojan Source
(Boucher & Anderson 2021), and Rehberger's ASCII-smuggler catalogue.

Goals:
  - Remove invisible channels that can carry hidden instructions or exfil
    payloads: tag block (U+E0000..U+E007F), zero-width marks, bidi overrides.
  - NFKC-normalize so homoglyph lookalikes collapse before other scanners run.
  - Flag anomalies (density of suspicious code points) — caller can escalate
    to quarantine if density is above a threshold, even though the text has
    been stripped.

This is NOT a verdict layer on its own; it cleans input and emits a stats
dict the orchestrator can use.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass

# Unicode ranges / points to strip entirely. Anything in these groups is
# overwhelmingly abusive (near-zero benign prevalence in research reports).
TAG_BLOCK = (0xE0000, 0xE007F)            # Rehberger ASCII smuggler
BIDI_OVERRIDES = (
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
)                                         # Trojan Source
ZERO_WIDTH = (0x200B, 0x200C, 0x200D, 0xFEFF)   # Bad Characters

# Whitespace-in-weird-places: NBSP + line/paragraph separators often used
# to desynchronize tokenizers but not always malicious. We strip only the
# zero-width variants; NBSP is left alone.

# Confusable slashes that NFKC does NOT fold to ASCII `/`. Without
# explicit translation, a tag like `<∕system-reminder>` (U+2215 DIVISION
# SLASH) passes every regex that expects ASCII `/` — defeating the
# wrap_escape defense. NFKC normalizes U+FF0F FULLWIDTH SOLIDUS already,
# so this table only covers the cases NFKC misses.
CONFUSABLE_SLASH_MAP = str.maketrans({
    "⁄": "/",  # FRACTION SLASH
    "∕": "/",  # DIVISION SLASH
})


@dataclass
class SanitizeResult:
    text: str           # cleaned text
    stripped: int       # count of code points removed
    bidi_hits: int
    tag_hits: int
    zw_hits: int
    nfkc_changed: bool  # NFKC normalization changed text


def _in_tag_block(cp: int) -> bool:
    return TAG_BLOCK[0] <= cp <= TAG_BLOCK[1]


def sanitize(text: str) -> SanitizeResult:
    bidi = 0
    tag = 0
    zw = 0
    buf: list[str] = []
    for ch in text:
        cp = ord(ch)
        if _in_tag_block(cp):
            tag += 1
            continue
        if cp in BIDI_OVERRIDES:
            bidi += 1
            continue
        if cp in ZERO_WIDTH:
            zw += 1
            continue
        buf.append(ch)
    raw_clean = "".join(buf)
    nfkc = unicodedata.normalize("NFKC", raw_clean)
    # Fold confusable slashes that NFKC missed so downstream regex layers
    # don't have to carry parallel Unicode alternates.
    folded = nfkc.translate(CONFUSABLE_SLASH_MAP)
    return SanitizeResult(
        text=folded,
        stripped=bidi + tag + zw,
        bidi_hits=bidi,
        tag_hits=tag,
        zw_hits=zw,
        nfkc_changed=(folded != raw_clean),
    )


# Density threshold: if more than this fraction of characters had to be
# stripped, the document is almost certainly hostile even post-sanitize
# (strip still happened, but pattern implies an adversary).
ANOMALY_DENSITY = 0.001  # 0.1%


def is_anomalous(r: SanitizeResult, original_length: int) -> bool:
    if original_length == 0:
        return False
    return (r.stripped / original_length) > ANOMALY_DENSITY
