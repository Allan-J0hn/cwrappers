"""Data models for wrapper detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Row:
    file: str
    function: str
    api_called: str
    category: str
    total_target_calls: int
    hit_locs: List[str]
    per_path_single: bool
    derived_from_params: bool
    derivation_trace: List[str]
    reason: str
    function_loc: Optional[str] = None
    pair_used: bool = False
    via_helper_hop: bool = False
    ignored_helpers: List[str] = field(default_factory=list)
    family: str = "-"
    fan_in: int = 0
    fan_out: int = 0
    function_key: Optional[str] = None
    is_thin_alias: bool = False
    callees: List[str] = field(default_factory=list)
    arg_pass: str = "-"
    ret_pass: str = "-"
