"""Minimal logging helpers."""

from __future__ import annotations

import sys
from typing import Any


def eprint(*args: Any, **kwargs: Any) -> None:
    """Print to stderr."""
    print(*args, file=sys.stderr, **kwargs)
