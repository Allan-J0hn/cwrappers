"""Normalization helpers for fuzzy matching."""

from __future__ import annotations

import re
from typing import List


def normalize(s: str) -> str:
    if not s:
        return ""
    s = s.strip()
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", s)
    s = re.sub(r"[^A-Za-z0-9]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s


def strip_affixes(name: str) -> str:
    """Remove common project-specific prefixes/suffixes so matching isn't biased."""
    if not name:
        return ""
    s = name
    for pref in ("ngx_", "redis_", "__"):
        if s.startswith(pref):
            s = s[len(pref):]
    for suff in ("_impl", "_locked"):
        if s.endswith(suff):
            s = s[: -len(suff)]
    return s


def tokenize(s: str) -> List[str]:
    ns = normalize(s)
    return ns.split() if ns else []
