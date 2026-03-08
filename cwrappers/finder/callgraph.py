"""Callgraph extraction and CSV output."""

from __future__ import annotations

import csv
from collections import defaultdict, namedtuple
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Set, Tuple

from cwrappers.finder.ast_utils import (
    _callee_definition,
    _callee_name,
    _callsite_loc,
    _function_body_cursor,
    _function_key,
    _caller_name,
    _is_callable_definition,
)
from cwrappers.finder.clang_bootstrap import cindex, K
from cwrappers.finder.models import EdgeEvidenceRow, TranslationUnitReport


Edge = namedtuple("Edge", ["caller", "callee", "loc"])
DetailedEdge = namedtuple("DetailedEdge", ["caller_key", "callee_key", "caller", "callee", "loc", "translation_unit"])


@dataclass(frozen=True)
class FunctionDef:
    function_key: str
    function: str
    file: str
    line: int


def build_function_index(
    function_defs: Iterable[FunctionDef],
) -> tuple[Dict[str, FunctionDef], Dict[str, Set[str]]]:
    defs_by_key: Dict[str, FunctionDef] = {}
    keys_by_name: Dict[str, Set[str]] = defaultdict(set)
    for fn_def in function_defs:
        defs_by_key.setdefault(fn_def.function_key, fn_def)
        keys_by_name[fn_def.function].add(fn_def.function_key)
    return defs_by_key, keys_by_name


def resolve_project_function_key(
    function_key: str | None,
    function_name: str | None,
    function_defs_by_key: Mapping[str, FunctionDef],
    keys_by_name: Mapping[str, Set[str]],
) -> tuple[Optional[str], str]:
    key = str(function_key or "")
    name = str(function_name or "")
    if key and key in function_defs_by_key:
        return key, "resolved_key"
    if name and (not key or key.endswith("@<unknown>")):
        candidates = keys_by_name.get(name, set())
        if len(candidates) == 1:
            return next(iter(candidates)), "name_fallback"
    return None, ""


def _simple_edge_identity(caller: str, callee: str, loc: str) -> tuple[str, str, str]:
    return (str(loc or ""), str(caller or ""), str(callee or ""))


def _detailed_edge_identity(caller_key: str, callee_key: str, loc: str) -> tuple[str, str, str]:
    return (str(loc or ""), str(caller_key or ""), str(callee_key or ""))


def collect_function_defs_for_tu(tu: cindex.TranslationUnit) -> List[FunctionDef]:
    defs: List[FunctionDef] = []
    seen_keys: Set[str] = set()

    for cur in tu.cursor.walk_preorder():
        if not _is_callable_definition(cur):
            continue

        function_key = _function_key(cur)
        if function_key in seen_keys:
            continue
        seen_keys.add(function_key)

        loc = getattr(cur, "location", None)
        file_name = ""
        line = 0
        if loc and getattr(loc, "file", None):
            file_name = str(Path(loc.file.name).resolve())
            line = int(getattr(loc, "line", 0) or 0)

        defs.append(
            FunctionDef(
                function_key=function_key,
                function=_caller_name(cur),
                file=file_name,
                line=line,
            )
        )

    return defs


def split_callsite_loc(loc: str) -> Tuple[str, int, int]:
    try:
        path, line, col = str(loc).rsplit(":", 2)
        return path, int(line), int(col)
    except Exception:
        return str(loc or ""), 0, 0


def resolve_edge_query(function_name: str, function_defs: Iterable[FunctionDef]) -> FunctionDef:
    matches = [fd for fd in function_defs if fd.function == function_name]
    matches.sort(key=lambda fd: (fd.file, fd.line, fd.function_key))

    if not matches:
        raise ValueError(f"edge-evidence query function not found: {function_name}")

    unique_matches = list(build_function_index(matches)[0].values())

    if len(unique_matches) != 1:
        locations = ", ".join(
            f"{fd.file or '<unknown>'}:{fd.line or 0}"
            for fd in unique_matches
        )
        raise ValueError(
            "edge-evidence query is ambiguous for function "
            f"{function_name}: {locations}"
        )

    return unique_matches[0]


def build_edge_evidence_rows(query: FunctionDef, edges: Iterable[DetailedEdge]) -> List[EdgeEvidenceRow]:
    rows: List[EdgeEvidenceRow] = []

    def _match_kinds(edge: DetailedEdge, direction: str) -> List[str]:
        if direction == "incoming":
            edge_key = str(getattr(edge, "callee_key", "") or "")
            edge_name = str(getattr(edge, "callee", "") or "")
        else:
            edge_key = str(getattr(edge, "caller_key", "") or "")
            edge_name = str(getattr(edge, "caller", "") or "")

        out: List[str] = []
        if edge_key == query.function_key:
            out.append("resolved_key")
        if edge_key.endswith("@<unknown>") and edge_name == query.function:
            out.append("name_fallback")
        return out

    for edge in edges:
        callsite_file, callsite_line, callsite_column = split_callsite_loc(getattr(edge, "loc", ""))
        translation_unit = str(getattr(edge, "translation_unit", "") or "")

        for direction in ("incoming", "outgoing"):
            for match_kind in _match_kinds(edge, direction):
                rows.append(
                    EdgeEvidenceRow(
                        direction=direction,
                        match_kind=match_kind,
                        query_function=query.function,
                        query_function_key=query.function_key,
                        query_function_file=query.file,
                        query_function_line=query.line,
                        caller=str(getattr(edge, "caller", "") or ""),
                        caller_key=str(getattr(edge, "caller_key", "") or ""),
                        callee=str(getattr(edge, "callee", "") or ""),
                        callee_key=str(getattr(edge, "callee_key", "") or ""),
                        callsite_file=callsite_file,
                        callsite_line=callsite_line,
                        callsite_column=callsite_column,
                        translation_unit=translation_unit,
                    )
                )

    direction_order = {"incoming": 0, "outgoing": 1}
    match_order = {"resolved_key": 0, "name_fallback": 1}
    rows.sort(
        key=lambda row: (
            direction_order.get(row.direction, 99),
            row.translation_unit,
            row.callsite_file,
            row.callsite_line,
            row.callsite_column,
            match_order.get(row.match_kind, 99),
            row.caller_key,
            row.callee_key,
            row.caller,
            row.callee,
        )
    )
    return rows


def collect_callgraph_for_tu(
    tu: cindex.TranslationUnit,
) -> tuple[list[Edge], set[tuple[str, str, str]]]:
    """
    Collect call edges for a single translational unit.
    Returns (edges, seen_callsite_ids) where:
        - edges: list of Edge(caller, callee, loc)
        - seen_callsite_ids: set of per-translation-unit edge identity tuples used for dedup later
    """
    edges: list[Edge] = []
    seen: set[tuple[str, str, str]] = set()

    for cur in tu.cursor.walk_preorder():
        if _is_callable_definition(cur):
            caller = _caller_name(cur)
            body = _function_body_cursor(cur)
            if not body:
                continue

            stack = [body]
            while stack:
                n = stack.pop()
                try:
                    for ch in n.get_children():
                        if ch.kind == K.CALL_EXPR:
                            callee = _callee_name(ch) or "<indirect>"
                            loc = _callsite_loc(ch)
                            edge_key = _simple_edge_identity(caller, callee, loc)
                            if edge_key not in seen:
                                seen.add(edge_key)
                                edges.append(Edge(caller=caller, callee=callee, loc=loc))
                        stack.append(ch)
                except Exception:
                    pass

    return edges, seen


def collect_callgraph_for_tu_detailed(
    tu: cindex.TranslationUnit,
    translation_unit: str | None = None,
) -> tuple[list[DetailedEdge], set[tuple[str, str, str]]]:
    """
    Collect call edges for a single translational unit, returning DetailedEdge with caller_key/callee_key
    suitable for per-function-per-file aggregation.
    """
    edges: list[DetailedEdge] = []
    seen: set[tuple[str, str, str]] = set()
    tu_name = str(translation_unit or getattr(tu, "spelling", "") or "")

    for cur in tu.cursor.walk_preorder():
        if _is_callable_definition(cur):
            caller_key = _function_key(cur)
            caller_name = _caller_name(cur)
            body = _function_body_cursor(cur)
            if not body:
                continue

            stack = [body]
            while stack:
                n = stack.pop()
                try:
                    for ch in n.get_children():
                        if ch.kind == K.CALL_EXPR:
                            callee_name = _callee_name(ch) or "<indirect>"
                            callee_def = _callee_definition(ch)
                            if callee_def:
                                callee_key = _function_key(callee_def)
                            else:
                                # Try to use the USR from the referenced declaration when definition isn't visible
                                callee_ref = getattr(ch, "referenced", None)
                                callee_key = None
                                if callee_ref is not None:
                                    try:
                                        if hasattr(callee_ref, "get_usr"):
                                            usr = callee_ref.get_usr()
                                            if usr:
                                                callee_key = usr
                                    except Exception:
                                        callee_key = None
                                if not callee_key:
                                    callee_key = f"{callee_name}@<unknown>"
                            loc = _callsite_loc(ch)
                            edge_key = _detailed_edge_identity(caller_key, callee_key, loc)
                            if edge_key not in seen:
                                seen.add(edge_key)
                                edges.append(DetailedEdge(caller_key=caller_key, callee_key=callee_key,
                                                          caller=caller_name, callee=callee_name, loc=loc,
                                                          translation_unit=tu_name))
                        stack.append(ch)
                except Exception:
                    pass

    return edges, seen


def _infer_project_function_defs_from_edges(edges: Iterable[DetailedEdge]) -> List[FunctionDef]:
    inferred: List[FunctionDef] = []
    seen_keys: Set[str] = set()
    for edge in edges:
        caller_key = str(getattr(edge, "caller_key", "") or "")
        if not caller_key or caller_key.endswith("@<unknown>") or caller_key in seen_keys:
            continue
        seen_keys.add(caller_key)
        inferred.append(
            FunctionDef(
                function_key=caller_key,
                function=str(getattr(edge, "caller", "") or ""),
                file="",
                line=0,
            )
        )
    return inferred


def write_callgraph(
    outputs_dir: Path,
    edges: list,
    unique_callers: bool = False,
    project_function_defs: Iterable[FunctionDef] | None = None,
    tu_reports: Iterable[TranslationUnitReport] | None = None,
) -> None:
    """
    Write callgraph CSVs:
        - callgraph_edges.csv: raw exported edge rows with project-resolution columns
        - call_counts.csv: project-only per-callee aggregates for project-defined callees
        - function_fan_summary.csv: project-only symmetric fan-in/fan-out summary for project-defined functions
        - translation_units.csv: per-TU parse diagnostics summary
    """
    outputs_dir.mkdir(parents=True, exist_ok=True)

    project_defs_list = list(project_function_defs or [])
    if not project_defs_list and edges:
        project_defs_list = _infer_project_function_defs_from_edges(edges)
    project_defs_by_key, project_keys_by_name = build_function_index(project_defs_list)

    # Dedup only truly identical exported rows. When translation-unit identity is present,
    # preserve repeated header observations across different TUs.
    dedup_edges: list = []
    seen_edge_keys: set[tuple[str, str, str, str]] = set()
    sample = edges[0] if edges else None
    use_detailed = bool(sample and hasattr(sample, "caller_key"))
    for e in edges:
        loc = getattr(e, "loc", None) or "<unknown>"
        caller_k = getattr(e, "caller_key", None) or getattr(e, "caller", "")
        callee_k = getattr(e, "callee_key", None) or getattr(e, "callee", "")
        tu = getattr(e, "translation_unit", None) or ""
        key = (str(tu), str(loc), str(caller_k), str(callee_k))
        if key in seen_edge_keys:
            continue
        seen_edge_keys.add(key)
        dedup_edges.append(e)

    if use_detailed:
        dedup_edges.sort(
            key=lambda e: (
                str(getattr(e, "translation_unit", "") or ""),
                str(getattr(e, "loc", "") or ""),
                str(getattr(e, "caller_key", "") or ""),
                str(getattr(e, "callee_key", "") or ""),
                str(getattr(e, "caller", "") or ""),
                str(getattr(e, "callee", "") or ""),
            )
        )
    else:
        dedup_edges.sort(key=lambda e: (str(getattr(e, "loc", "") or ""), str(getattr(e, "caller", "") or ""), str(getattr(e, "callee", "") or "")))

    enriched_edges = []
    exported_edge_count_by_tu: Dict[str, int] = defaultdict(int)
    for e in dedup_edges:
        caller_key = str(getattr(e, "caller_key", "") or "")
        callee_key = str(getattr(e, "callee_key", "") or "")
        caller_name = str(getattr(e, "caller", "") or "")
        callee_name = str(getattr(e, "callee", "") or "")
        caller_project_key, _caller_match = resolve_project_function_key(
            caller_key,
            caller_name,
            project_defs_by_key,
            project_keys_by_name,
        )
        callee_project_key, _callee_match = resolve_project_function_key(
            callee_key,
            callee_name,
            project_defs_by_key,
            project_keys_by_name,
        )
        tu = str(getattr(e, "translation_unit", "") or "")
        if tu:
            exported_edge_count_by_tu[tu] += 1
        enriched_edges.append(
            {
                "edge": e,
                "caller_key": caller_key,
                "caller_name": caller_name,
                "caller_project_key": caller_project_key or "",
                "callee_key": callee_key,
                "callee_name": callee_name,
                "callee_project_key": callee_project_key or "",
                "translation_unit": tu,
                "loc": str(getattr(e, "loc", "") or ""),
            }
        )

    # 1) Edges: include optional function keys when available
    with open(outputs_dir / "callgraph_edges.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        if use_detailed:
            w.writerow([
                "caller",
                "caller_key",
                "caller_project_key",
                "caller_in_project",
                "callee",
                "callee_key",
                "callee_project_key",
                "callee_in_project",
                "callsite",
                "callsite_file",
                "callsite_line",
                "callsite_column",
                "translation_unit",
            ])
            for row in enriched_edges:
                callsite_file, callsite_line, callsite_column = split_callsite_loc(row["loc"])
                w.writerow([
                    row["caller_name"],
                    row["caller_key"],
                    row["caller_project_key"],
                    "TRUE" if row["caller_project_key"] else "FALSE",
                    row["callee_name"],
                    row["callee_key"],
                    row["callee_project_key"],
                    "TRUE" if row["callee_project_key"] else "FALSE",
                    row["loc"],
                    callsite_file,
                    callsite_line,
                    callsite_column,
                    row["translation_unit"],
                ])
        else:
            w.writerow(["caller", "callee", "callsite", "callsite_file", "callsite_line", "callsite_column"])
            for e in dedup_edges:
                callsite_file, callsite_line, callsite_column = split_callsite_loc(getattr(e, "loc", "") or "")
                w.writerow([e.caller, e.callee, e.loc, callsite_file, callsite_line, callsite_column])

    incoming_subject_edges = [row for row in enriched_edges if row["callee_project_key"]]
    outgoing_subject_edges = [row for row in enriched_edges if row["caller_project_key"]]

    # 2) Aggregate project-only incoming counts by callee.
    counts: Dict[str, int] = defaultdict(int)
    callers_by_callee: Dict[str, Set[str]] = defaultdict(set)
    caller_names_by_callee: Dict[str, Set[str]] = defaultdict(set)
    callsites_by_callee: Dict[str, Set[str]] = defaultdict(set)
    tus_by_callee: Dict[str, Set[str]] = defaultdict(set)
    for row in incoming_subject_edges:
        callee_k = row["callee_project_key"]
        caller_k = row["caller_project_key"] or row["caller_key"] or row["caller_name"]
        caller_def = project_defs_by_key.get(row["caller_project_key"])
        caller_name = caller_def.function if caller_def is not None else row["caller_name"]
        loc = row["loc"]
        tu = row["translation_unit"]
        counts[callee_k] += 1
        if caller_k:
            callers_by_callee[callee_k].add(caller_k)
        if caller_name:
            caller_names_by_callee[callee_k].add(caller_name)
        if loc:
            callsites_by_callee[callee_k].add(str(loc))
        if tu:
            tus_by_callee[callee_k].add(str(tu))

    with open(outputs_dir / "call_counts.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        w.writerow([
            "callee_name",
            "callee_key",
            "callee_file",
            "callee_line",
            "total_calls",
            "unique_callsite_count",
            "unique_translation_unit_count",
            "unique_caller_count",
            "unique_caller_name_count",
            "callers",
            "caller_names",
            "translation_units",
        ])
        if unique_callers:
            items = sorted(
                counts.items(),
                key=lambda x: (
                    -len(callers_by_callee.get(x[0], set())),
                    -x[1],
                    x[0],
                ),
            )
        else:
            items = sorted(
                counts.items(),
                key=lambda x: (
                    -x[1],
                    -len(callers_by_callee.get(x[0], set())),
                    x[0],
                ),
            )
        for callee_k, n in items:
            caller_keys = sorted(callers_by_callee.get(callee_k, set()))
            caller_names = sorted(caller_names_by_callee.get(callee_k, set()))
            translation_units = sorted(tus_by_callee.get(callee_k, set()))
            callee_def = project_defs_by_key.get(callee_k)
            w.writerow([
                callee_def.function if callee_def is not None else "",
                callee_k,
                callee_def.file if callee_def is not None else "",
                callee_def.line if callee_def is not None else 0,
                n,
                len(callsites_by_callee.get(callee_k, set())),
                len(translation_units),
                len(caller_keys),
                len(caller_names),
                ";".join(caller_keys),
                ";".join(caller_names),
                ";".join(translation_units),
            ])

    # 3) Build a project-only symmetric per-function summary.
    incoming_callers: Dict[str, Set[str]] = defaultdict(set)
    incoming_caller_names: Dict[str, Set[str]] = defaultdict(set)
    incoming_callsites: Dict[str, Set[str]] = defaultdict(set)
    incoming_tus: Dict[str, Set[str]] = defaultdict(set)
    incoming_edge_counts: Dict[str, int] = defaultdict(int)

    outgoing_callees: Dict[str, Set[str]] = defaultdict(set)
    outgoing_callee_names: Dict[str, Set[str]] = defaultdict(set)
    outgoing_callsites: Dict[str, Set[str]] = defaultdict(set)
    outgoing_tus: Dict[str, Set[str]] = defaultdict(set)
    outgoing_edge_counts: Dict[str, int] = defaultdict(int)

    for row in incoming_subject_edges:
        callee_k = row["callee_project_key"]
        caller_k = row["caller_project_key"] or row["caller_key"] or row["caller_name"]
        caller_def = project_defs_by_key.get(row["caller_project_key"])
        caller_name = caller_def.function if caller_def is not None else row["caller_name"]
        loc = row["loc"]
        tu = row["translation_unit"]

        incoming_edge_counts[callee_k] += 1
        if caller_k:
            incoming_callers[callee_k].add(caller_k)
        if caller_name:
            incoming_caller_names[callee_k].add(caller_name)
        if loc:
            incoming_callsites[callee_k].add(loc)
        if tu:
            incoming_tus[callee_k].add(tu)

    for row in outgoing_subject_edges:
        caller_k = row["caller_project_key"]
        callee_k = row["callee_project_key"] or row["callee_key"] or row["callee_name"]
        loc = row["loc"]
        tu = row["translation_unit"]
        callee_def = project_defs_by_key.get(row["callee_project_key"])
        callee_name = callee_def.function if callee_def is not None else row["callee_name"]

        outgoing_edge_counts[caller_k] += 1

        if callee_k:
            outgoing_callees[caller_k].add(callee_k)

        if callee_name:
            outgoing_callee_names[caller_k].add(callee_name)
        if loc:
            outgoing_callsites[caller_k].add(loc)
        if tu:
            outgoing_tus[caller_k].add(tu)

    summary_defs = sorted(
        project_defs_by_key.values(),
        key=lambda fd: (
            -len(incoming_callers.get(fd.function_key, set())),
            -len(outgoing_callees.get(fd.function_key, set())),
            fd.function,
            fd.file,
            fd.line,
            fd.function_key,
        ),
    )

    with open(outputs_dir / "function_fan_summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        w.writerow([
            "function",
            "function_key",
            "file",
            "line",
            "fan_in",
            "fan_out",
            "incoming_edge_count",
            "outgoing_edge_count",
            "unique_incoming_callsite_count",
            "unique_outgoing_callsite_count",
            "unique_incoming_translation_unit_count",
            "unique_outgoing_translation_unit_count",
            "caller_keys",
            "caller_names",
            "callee_keys",
            "callee_names",
            "incoming_translation_units",
            "outgoing_translation_units",
        ])
        for fn_def in summary_defs:
            key = fn_def.function_key
            caller_keys = sorted(incoming_callers.get(key, set()))
            caller_names = sorted(incoming_caller_names.get(key, set()))
            callee_keys = sorted(outgoing_callees.get(key, set()))
            callee_names = sorted(outgoing_callee_names.get(key, set()))
            incoming_translation_units = sorted(incoming_tus.get(key, set()))
            outgoing_translation_units = sorted(outgoing_tus.get(key, set()))
            w.writerow([
                fn_def.function,
                key,
                fn_def.file,
                fn_def.line,
                len(caller_keys),
                len(callee_keys),
                incoming_edge_counts.get(key, 0),
                outgoing_edge_counts.get(key, 0),
                len(incoming_callsites.get(key, set())),
                len(outgoing_callsites.get(key, set())),
                len(incoming_translation_units),
                len(outgoing_translation_units),
                ";".join(caller_keys),
                ";".join(caller_names),
                ";".join(callee_keys),
                ";".join(callee_names),
                ";".join(incoming_translation_units),
                ";".join(outgoing_translation_units),
            ])

    if tu_reports is None:
        return

    # 4) Per-TU diagnostics summary.
    report_by_tu = {
        str(report.translation_unit): report
        for report in tu_reports
    }
    tu_keys = sorted(set(report_by_tu.keys()) | set(exported_edge_count_by_tu.keys()))
    with open(outputs_dir / "translation_units.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        w.writerow([
            "translation_unit",
            "parse_succeeded",
            "retry_used",
            "diagnostic_ignored_count",
            "diagnostic_note_count",
            "diagnostic_warning_count",
            "diagnostic_error_count",
            "diagnostic_fatal_count",
            "total_diagnostic_count",
            "had_errors",
            "exported_edge_count",
            "parse_failure",
        ])
        for tu in tu_keys:
            report = report_by_tu.get(tu)
            if report is None:
                w.writerow([tu, "FALSE", "FALSE", 0, 0, 0, 0, 0, 0, "FALSE", exported_edge_count_by_tu.get(tu, 0), ""])
                continue
            w.writerow([
                report.translation_unit,
                "TRUE" if report.parse_succeeded else "FALSE",
                "TRUE" if report.retry_used else "FALSE",
                report.diagnostic_ignored_count,
                report.diagnostic_note_count,
                report.diagnostic_warning_count,
                report.diagnostic_error_count,
                report.diagnostic_fatal_count,
                report.total_diagnostic_count,
                "TRUE" if report.had_errors else "FALSE",
                exported_edge_count_by_tu.get(tu, 0),
                report.parse_failure,
            ])
