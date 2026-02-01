"""Callgraph extraction and CSV output."""

from __future__ import annotations

import csv
from collections import defaultdict, namedtuple
from pathlib import Path
from typing import Dict, Set

from cwrappers.finder.ast_utils import (
    _callee_definition,
    _callee_name,
    _callsite_loc,
    _function_body_cursor,
    _function_key,
    _caller_name,
)
from cwrappers.finder.clang_bootstrap import cindex, K


Edge = namedtuple("Edge", ["caller", "callee", "loc"])
DetailedEdge = namedtuple("DetailedEdge", ["caller_key", "callee_key", "caller", "callee", "loc"])


def collect_callgraph_for_tu(tu: cindex.TranslationUnit) -> tuple[list[Edge], set[str]]:
    """
    Collect call edges for a single translational unit.
    Returns (edges, seen_callsite_ids) where:
        - edges: list of Edge(caller, callee, loc)
        - seen_callsite_ids: set of per-translational unit loc strings used for dedup later
    """
    edges: list[Edge] = []
    seen: set[str] = set()

    for cur in tu.cursor.walk_preorder():
        if cur.kind == K.FUNCTION_DECL and cur.is_definition():
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
                            if loc is not None and loc not in seen:
                                seen.add(loc)
                                edges.append(Edge(caller=caller, callee=callee, loc=loc))
                        stack.append(ch)
                except Exception:
                    pass

    return edges, seen


def collect_callgraph_for_tu_detailed(tu: cindex.TranslationUnit) -> tuple[list[DetailedEdge], set[str]]:
    """
    Collect call edges for a single translational unit, returning DetailedEdge with caller_key/callee_key
    suitable for per-function-per-file aggregation.
    """
    edges: list[DetailedEdge] = []
    seen: set[str] = set()

    for cur in tu.cursor.walk_preorder():
        if cur.kind == K.FUNCTION_DECL and cur.is_definition():
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
                            if loc is not None and loc not in seen:
                                seen.add(loc)
                                edges.append(DetailedEdge(caller_key=caller_key, callee_key=callee_key,
                                                          caller=caller_name, callee=callee_name, loc=loc))
                        stack.append(ch)
                except Exception:
                    pass

    return edges, seen


def write_callgraph(outputs_dir: Path, edges: list, unique_callers: bool = False) -> None:
    """
    Write two CSVs:
        - callgraph_edges.csv: caller, callee, callsite (absolute file:line:col)
        - call_counts.csv: callee, total_calls (unique call-sites across TUs)
    """
    outputs_dir.mkdir(parents=True, exist_ok=True)

    # Global dedup across all TUs by (callsite loc, caller_key, callee_key) to avoid duplicate header callsites
    dedup_edges: list = []
    seen_edge_keys: set[tuple[str, str, str]] = set()
    sample = edges[0] if edges else None
    use_detailed = bool(sample and hasattr(sample, "caller_key"))
    for e in edges:
        loc = getattr(e, "loc", None) or "<unknown>"
        caller_k = getattr(e, "caller_key", None) or getattr(e, "caller", "")
        callee_k = getattr(e, "callee_key", None) or getattr(e, "callee", "")
        key = (str(loc), str(caller_k), str(callee_k))
        if key in seen_edge_keys:
            continue
        seen_edge_keys.add(key)
        dedup_edges.append(e)

    # 1) Edges: include optional function keys when available
    with open(outputs_dir / "callgraph_edges.csv", "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        if use_detailed:
            w.writerow(["caller", "caller_key", "callee", "callee_key", "callsite"])
            for e in dedup_edges:
                w.writerow([getattr(e, "caller", ""), getattr(e, "caller_key", ""),
                            getattr(e, "callee", ""), getattr(e, "callee_key", ""),
                            e.loc])
        else:
            w.writerow(["caller", "callee", "callsite"])
            for e in dedup_edges:
                w.writerow([e.caller, e.callee, e.loc])

    # 2) Aggregate counts by callee.
    counts: Dict[str, int] = defaultdict(int)
    callers_by_callee: Dict[str, Set[str]] = defaultdict(set)
    for e in dedup_edges:
        callee_k = getattr(e, "callee_key", None) or getattr(e, "callee", "")
        caller_k = getattr(e, "caller_key", None) or getattr(e, "caller", "")
        if not callee_k:
            continue
        counts[callee_k] += 1
        if caller_k:
            callers_by_callee[callee_k].add(caller_k)

    callee_name_by_key: Dict[str, str] = {}
    for e in dedup_edges:
        key = getattr(e, "callee_key", None) or getattr(e, "callee", None)
        name = getattr(e, "callee", None) or ""
        if key and name and key not in callee_name_by_key:
            callee_name_by_key[key] = name

    with open(outputs_dir / "call_counts.csv", "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        w.writerow(["callee_name", "callee_key", "total_calls", "unique_caller_count", "callers"])
        items = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
        for callee_k, n in items:
            uniq = len(callers_by_callee.get(callee_k, set()))
            callers_list = sorted(callers_by_callee.get(callee_k, set()))
            callers_s = ";".join(callers_list)
            w.writerow([callee_name_by_key.get(callee_k, ""), callee_k, n, uniq, callers_s])
