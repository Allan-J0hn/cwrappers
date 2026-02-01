"""Wrapper detection logic (accurate/relaxed)."""

from __future__ import annotations

from typing import List, Optional, Set, Tuple

from cwrappers.finder.analysis import (
    _call_hits_target_via_n_hops,
    _call_hits_target_via_one_hop,
    _inner_target_from_one_hop,
    _resolve_target_name_for_call,
    analyze_stmt,
    collect_target_calls,
    has_early_guard_return,
    is_atomic_pair,
    is_helper_call,
    resolve_syscall_indirection,
)
from cwrappers.finder.ast_utils import _callee_name, _function_body_cursor
from cwrappers.finder.catalog import ApiCatalog
from cwrappers.finder.clang_bootstrap import cindex, K
from cwrappers.finder.provenance import check_arguments_provenance


def analyze_wrapper_strict_plus(func_cursor: cindex.Cursor,
                                catalog: ApiCatalog,
                                thin_policy: str = "default") -> Tuple[
                                    bool,
                                    bool,
                                    int,
                                    str,
                                    List[str],
                                    Optional[str],
                                    bool,
                                    List[str],
                                    bool,
                                    bool,
                                    List[str],
                                ]:
    targets = catalog.target_names
    helpers = catalog.helpers

    body = _function_body_cursor(func_cursor)
    if body is None:
        return (False, False, 0, "no-body", [], None, False, [], False, False, [])

    pr = analyze_stmt(body, targets, helpers, max_helper_hops=2)
    if pr.unknown:
        return (False, False, 0, "unknown-control-flow", [], None, False, [], False, False, [])

    counts = pr.counts or set()
    max_pos = max(counts) if counts else 0
    guard_ok = (0 in counts) and has_early_guard_return(func_cursor, catalog.helpers)
    if (0 in counts) and not guard_ok:
        return (False, False, 0, f"path-counts={sorted(counts)}", [], None, False, [], False, False, [])

    via_helper_hop = False
    via_hop_depth_ge2 = False
    ignored_helpers: Set[str] = set()
    hit_locs: List[str] = []
    apis: List[str] = []
    pair_used = False

    def walk_calls(n: cindex.Cursor) -> None:
        nonlocal via_helper_hop
        for ch in n.get_children():
            if ch.kind == K.CALL_EXPR:
                if is_helper_call(ch, helpers):
                    nm = _callee_name(ch) or "<anon>"
                    ignored_helpers.add(nm)
                else:
                    nm = _callee_name(ch)
                    if nm in targets:
                        apis.append(nm)
                        loc = ch.location
                        if loc and loc.file:
                            hit_locs.append(f"{loc.line}:{loc.column}")
                    else:
                        mapped = resolve_syscall_indirection(ch)
                        if mapped and mapped in targets:
                            apis.append(mapped)
                            loc = ch.location
                            if loc and loc.file:
                                hit_locs.append(f"{loc.line}:{loc.column}")
                        else:
                            if _call_hits_target_via_one_hop(ch, targets):
                                via_helper_hop = True
                                inner = _inner_target_from_one_hop(ch, targets)
                                if inner and inner in targets:
                                    apis.append(inner)
                                loc = ch.location
                                if loc and loc.file:
                                    hit_locs.append(f"{loc.line}:{loc.column}")
                            elif _call_hits_target_via_n_hops(ch, targets, 2):
                                via_helper_hop = True
                                via_hop_depth_ge2 = True
                                inner = _inner_target_from_one_hop(ch, targets)
                                if inner and inner in targets:
                                    apis.append(inner)
                                loc = ch.location
                                if loc and loc.file:
                                    hit_locs.append(f"{loc.line}:{loc.column}")
            walk_calls(ch)

    walk_calls(body)

    total_hits = len(hit_locs)
    if total_hits == 0:
        return (False, False, 0, "no-calls", [], None, False, [], False, via_helper_hop, sorted(ignored_helpers))

    if apis:
        first_api = apis[0]
        if first_api and first_api in (catalog.thin_aliases or set()):
            pol = thin_policy or "default"
            if pol in ("default", "direct-only"):
                if via_helper_hop:
                    return (False, False, total_hits, "reject: thin-alias-via-helper", hit_locs, first_api,
                            False, [], False, via_helper_hop, sorted(ignored_helpers))
            elif pol == "allow-1-hop":
                if via_hop_depth_ge2:
                    return (False, False, total_hits, "reject: thin-alias-hop-depth>=2", hit_locs, first_api,
                            False, [], False, via_helper_hop, sorted(ignored_helpers))

    if max_pos >= 2 and not (total_hits == 2 and is_atomic_pair(apis, "")):
        return (False, False, total_hits, "reject: multi-call-per-path", hit_locs, (apis[0] if apis else None),
                False, [], False, via_helper_hop, sorted(ignored_helpers))
    elif max_pos >= 2:
        pair_used = True

    counted_sites = [c for (c, _loc) in collect_target_calls(func_cursor, targets)]
    derived_ok, derivation_trace = check_arguments_provenance(func_cursor, counted_sites, helpers)

    reason = "ok"
    if guard_ok:
        reason += "+ok-guard"
    if via_helper_hop:
        reason += "+via-hop"
    if pair_used:
        reason += "+atomic-pair"
    per_path_single = True
    api_called = apis[0] if apis else None
    return (True, per_path_single, total_hits, reason, hit_locs, api_called, derived_ok, derivation_trace,
        pair_used, via_helper_hop, sorted(ignored_helpers))


# ==========================
# Relaxed analyzer (higher recall)
# ==========================

def analyze_wrapper_relaxed(func_cursor: cindex.Cursor,
                            catalog: ApiCatalog) -> Tuple[
                                bool, bool, int, str, List[str], Optional[str],
                                bool, List[str], bool, bool, List[str]]:
    """Relaxed: allow early-guard 0 paths, helper hops up to 2, no taint requirement."""
    targets = catalog.target_names
    helpers = catalog.helpers
    body = _function_body_cursor(func_cursor)
    if body is None:
        return (False, False, 0, "no-body", [], None, False, [], False, False, [])

    pr = analyze_stmt(body, targets, helpers, max_helper_hops=2)
    keep = any(c > 0 for c in (pr.counts or set()))
    if not keep:
        return (False, False, 0, f"path-counts={(sorted(pr.counts) if pr.counts else [])}", [], None, False, [], False, False, [])

    hits = collect_target_calls(func_cursor, targets)
    apis: List[str] = []
    hit_locs: List[str] = []
    for call, loc in hits:
        nm = _resolve_target_name_for_call(call, catalog)
        if nm:
            apis.append(nm)
            hit_locs.append(loc)
    total_hits = len(apis)
    if total_hits == 0:
        return (False, False, 0, "no-calls", [], None, False, [], False, False, [])
    api_name = apis[0] if apis else None
    per_path_single = set(pr.counts or {}) <= {0, 1}
    reason = "ok"
    return (True, per_path_single, total_hits, reason, hit_locs, api_name, True, [], False, False, [])
