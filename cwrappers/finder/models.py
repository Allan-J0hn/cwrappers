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


@dataclass(frozen=True)
class EdgeEvidenceRow:
    direction: str
    match_kind: str
    query_function: str
    query_function_key: str
    query_function_file: str
    query_function_line: int
    caller: str
    caller_key: str
    callee: str
    callee_key: str
    callsite_file: str
    callsite_line: int
    callsite_column: int
    translation_unit: str


@dataclass(frozen=True)
class TranslationUnitReport:
    translation_unit: str
    parse_succeeded: bool
    retry_used: bool
    diagnostic_ignored_count: int
    diagnostic_note_count: int
    diagnostic_warning_count: int
    diagnostic_error_count: int
    diagnostic_fatal_count: int
    total_diagnostic_count: int
    had_errors: bool
    parse_failure: str = ""
