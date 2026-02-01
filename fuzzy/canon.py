"""API catalog loading for fuzzy scoring."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Set

import yaml

from cwrappers.fuzzy.normalize import normalize


@dataclass
class CanonSet:
    key: str
    candidates: List[str]


def _candidate_yaml_paths(yaml_path: str | None) -> List[str]:
    candidates: List[str] = []
    if yaml_path:
        candidates.append(yaml_path)

    # Current working directory
    candidates.append(os.path.join(os.getcwd(), "categorized_methods.yaml"))
    candidates.append(os.path.join(os.getcwd(), "methods.yaml"))
    candidates.append(os.path.join(os.getcwd(), "Data", "methods.yaml"))
    candidates.append(os.path.join(os.getcwd(), "Data", "resources_methods.yaml"))

    # Repo root (two levels up from this file: cwrappers/fuzzy/ -> repo)
    try:
        repo_root = Path(__file__).resolve().parents[2]
        candidates.append(str(repo_root / "categorized_methods.yaml"))
        candidates.append(str(repo_root / "methods.yaml"))
        candidates.append(str(repo_root / "Data" / "methods.yaml"))
        candidates.append(str(repo_root / "Data" / "resources_methods.yaml"))
    except Exception:
        pass

    # Script dir
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidates.append(os.path.join(script_dir, "categorized_methods.yaml"))
    except Exception:
        pass

    # De-duplicate while preserving order
    seen = set()
    out = []
    for p in candidates:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def build_canon_sets(yaml_path: str | None = None) -> List[CanonSet]:
    """Load function names from YAML and build candidate sets."""
    cfg = {}
    tried = []
    for p in _candidate_yaml_paths(yaml_path):
        tried.append(p)
        try:
            with open(p, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
                yaml_path = p
                break
        except Exception:
            continue
    if not cfg:
        raise ValueError(f"failed to read yaml at any of: {tried}")

    names: Set[str] = set()
    for section in ("libc", "syscalls"):
        for nm in cfg.get(section, []) or []:
            try:
                if isinstance(nm, str):
                    names.add(nm)
            except Exception:
                pass

    fams = cfg.get("families", {}) or {}
    if isinstance(fams, dict):
        for _fam, body in fams.items():
            if not isinstance(body, dict):
                continue
            for nm in (body.get("apis", []) or []):
                if isinstance(nm, str):
                    names.add(nm)
            for nm in (body.get("aliases", []) or []):
                if isinstance(nm, str):
                    names.add(nm)

    cats = cfg.get("categories", {}) or {}
    if isinstance(cats, dict):
        for _cat_name, cat_body in cats.items():
            if isinstance(cat_body, list):
                for nm in cat_body:
                    if isinstance(nm, str):
                        names.add(nm)
            elif isinstance(cat_body, dict):
                for _k, v in cat_body.items():
                    if isinstance(v, list):
                        for nm in v:
                            if isinstance(nm, str):
                                names.add(nm)

    sets: List[CanonSet] = []
    for key in sorted(names):
        n = normalize(key)
        if not n:
            continue
        sets.append(CanonSet(key=key, candidates=[n]))
    return sets
