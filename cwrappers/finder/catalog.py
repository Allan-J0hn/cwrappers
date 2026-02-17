"""API catalog loading and helper configuration."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Set

import yaml


@dataclass
class HelperConfig:
    benign: Set[str]
    benign_regex: List[re.Pattern]
    helpers: Set[str]
    helpers_regex: List[re.Pattern]

    def any_match(self, name: str, which: str = "helpers") -> bool:
        """
        which: "benign" | "helpers"
        """
        if which == "benign":
            if name in self.benign:
                return True
            return any(r.search(name) for r in self.benign_regex)
        if name in self.helpers:
            return True
        return any(r.search(name) for r in self.helpers_regex)


@dataclass
class ApiCatalog:
    """API catalog loaded from YAML."""
    libc: Set[str]
    syscalls: Set[str]
    target_names: Set[str]
    helpers: HelperConfig
    thin_aliases: Set[str] = field(default_factory=set)
    categories: Dict[str, Set[str]] = field(default_factory=dict)
    name_to_category: Dict[str, str] = field(default_factory=dict)

    def category_of(self, name: str) -> str:
        # Prefer explicit category mapping when available
        cat = self.name_to_category.get(name)
        if cat:
            return cat
        # Fallback to legacy buckets
        if name in self.libc:
            return "libc"
        if name in self.syscalls:
            return "system_calls"
        return "unknown"


def load_api_catalog(yaml_path: Path) -> ApiCatalog:
    with open(yaml_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    # Helpers
    helpers_cfg = cfg.get("helpers", {}) or {}

    def _compile_regex_list(xs: Iterable[str]) -> List[re.Pattern]:
        out = []
        for s in xs or []:
            try:
                out.append(re.compile(s))
            except Exception:
                pass
        return out

    benign = set(helpers_cfg.get("benign", []) or [])
    benign_re = _compile_regex_list(helpers_cfg.get("benign_regex", []) or [])
    gen_helpers = set(helpers_cfg.get("helpers", []) or [])
    gen_helpers_re = _compile_regex_list(helpers_cfg.get("helpers_regex", []) or [])
    helpers = HelperConfig(
        benign=benign, benign_regex=benign_re,
        helpers=gen_helpers, helpers_regex=gen_helpers_re
    )
    # Targets
    libc = set(cfg.get("libc", []) or [])
    syscalls = set(cfg.get("syscalls", []) or [])

    # Parse categories map if present
    categories_cfg: Dict[str, Iterable[str]] = {}
    raw_cats = cfg.get("categories")
    if isinstance(raw_cats, dict):
        for k, v in raw_cats.items():
            try:
                if isinstance(v, dict):
                    vv = v.get("apis", [])
                else:
                    vv = v
                categories_cfg[str(k)] = list(vv or [])
            except Exception:
                continue

    # Build categories and name->category index
    categories: Dict[str, Set[str]] = {}
    name_to_category: Dict[str, str] = {}
    for cat, items in (categories_cfg or {}).items():
        s = set(items or [])
        categories[cat] = s
        for nm in s:
            name_to_category.setdefault(nm, cat)

    # Optional categories (backward-compatible). Support both 'thin_alias' and 'thin-alias'.
    thin_aliases: Set[str] = set()
    try:
        cats_meta = cfg.get("categories", {}) or {}
        if isinstance(cats_meta, dict):
            thin_list = cats_meta.get("thin_alias") or cats_meta.get("thin-alias") or []
            thin_aliases = set(thin_list or [])
    except Exception:
        thin_aliases = set()

    if not libc and "families" in cfg:
        fams_cfg = cfg.get("families", {}) or {}
        for _fam, body in fams_cfg.items():
            for nm in (body.get("apis", []) or []):
                libc.add(nm)
            for nm in (body.get("aliases", []) or []):
                libc.add(nm)

    # If categories were provided, use their union as targets by default
    if categories:
        target_names = set().union(*categories.values()) if categories else set()
        # Back-compat for legacy flags: derive libc/syscalls if not present
        if not libc:
            libc_union = set()
            for cat, vals in categories.items():
                if cat != "system_calls":
                    libc_union |= vals
            libc = libc_union
        if not syscalls:
            syscalls = set(categories.get("system_calls", set()))
    else:
        target_names = set().union(libc, syscalls)

    return ApiCatalog(
        libc=libc,
        syscalls=syscalls,
        target_names=target_names,
        helpers=helpers,
        thin_aliases=thin_aliases,
        categories=categories,
        name_to_category=name_to_category,
    )
