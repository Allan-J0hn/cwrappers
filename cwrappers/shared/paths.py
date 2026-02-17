"""Path helpers for packaged resources."""

from __future__ import annotations

from pathlib import Path

DEFAULT_CATALOG_NAME = "categorized_methods.yaml"


def package_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_catalog_path() -> Path:
    return package_root() / "data" / DEFAULT_CATALOG_NAME
