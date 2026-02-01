"""Path analysis and target call detection."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from cwrappers.finder.ast_utils import (
    _callee_definition,
    _callee_name,
    _function_body_cursor,
)
from cwrappers.finder.catalog import ApiCatalog, HelperConfig
from cwrappers.finder.clang_bootstrap import cindex, K


def is_helper_call(call: cindex.Cursor, helpers: HelperConfig, kind: str = "helpers") -> bool:
    nm = _callee_name(call) or ""
    return helpers.any_match(nm, "benign" if kind == "benign" else "helpers")


def _call_hits_target_via_one_hop(call: cindex.Cursor, target_names: Set[str]) -> bool:
    """Conservative one-hop check: call resolves to helper with body that directly calls a target."""
    callee = _callee_definition(call)
    if not callee:
        return False
    body = _function_body_cursor(callee)
    if not body:
        return False
    for ch in body.get_children():
        if ch.kind == K.CALL_EXPR:
            nm = _callee_name(ch)
            if nm in target_names:
                return True
    return False


def _is_small_function(fn: cindex.Cursor, max_stmts: int = 6) -> bool:
    body = _function_body_cursor(fn)
    if not body:
        return False
    try:
        stmts = [c for c in body.get_children() if c.kind != K.DECL_STMT]
        return len(stmts) <= max_stmts
    except Exception:
        return False


def _call_hits_target_via_n_hops(call: cindex.Cursor, target_names: Set[str], max_hops: int = 2, seen: Optional[Set[int]] = None) -> bool:
    """Bounded DFS over tiny helper bodies to find a target within <= max_hops."""
    if max_hops < 1:
        return False
    callee = _callee_definition(call)
    if not callee or not _is_small_function(callee):
        return False
    if seen is None:
        seen = set()
    try:
        hid = callee.hash
    except Exception:
        hid = id(callee)
    if hid in seen:
        return False
    seen.add(hid)
    body = _function_body_cursor(callee)
    if not body:
        return False
    for ch in body.get_children():
        if ch.kind == K.CALL_EXPR:
            nm = _callee_name(ch) or ""
            if nm in target_names:
                return True
            if _call_hits_target_via_n_hops(ch, target_names, max_hops - 1, seen):
                return True
    return False


# Whitelist of atomic pairs (by name). Kept under the "" family
_ATOMIC_PAIRS: Dict[str, set] = {
    "": {
        ("open", "close"),
        ("fopen", "fclose"),
        ("socket", "close"),
        ("malloc", "free"),
        ("calloc", "free"),
        frozenset(("pthread_mutex_lock", "pthread_mutex_unlock")),
        frozenset(("pthread_rwlock_rdlock", "pthread_rwlock_unlock")),
    }
}


def is_atomic_pair(api_names: List[str], family: str) -> bool:
    if len(api_names) != 2:
        return False
    pairs = _ATOMIC_PAIRS.get(family or "", set())
    a, b = api_names[0], api_names[1]
    return (a, b) in pairs or (b, a) in pairs or (frozenset((a, b)) in pairs)


def has_early_guard_return(func_cursor: cindex.Cursor, helpers: HelperConfig) -> bool:
    """Return True if the function starts with a guard that immediately returns."""
    body = _function_body_cursor(func_cursor)
    if not body:
        return False

    stmts = [c for c in body.get_children() if c.kind != K.DECL_STMT]
    if not stmts:
        return False

    i = 0
    while i < len(stmts) and stmts[i].kind == K.CALL_EXPR:
        if is_helper_call(stmts[i], helpers, kind="helpers"):
            i += 1
            continue
        break

    if i >= len(stmts):
        return False

    s = stmts[i]
    if s.kind != K.IF_STMT:
        return False

    kids = list(s.get_children())
    then_node = kids[1] if len(kids) >= 2 else None
    else_node = kids[2] if len(kids) >= 3 else None

    def branch_has_immediate_return(node: cindex.Cursor) -> bool:
        if node is None:
            return False
        for ch in node.get_children():
            if ch.kind == K.RETURN_STMT:
                return True
            if ch.kind == K.COMPOUND_STMT:
                inner = [cc for cc in ch.get_children() if cc.kind != K.DECL_STMT]
                if inner and inner[0].kind == K.RETURN_STMT:
                    return True
        return False

    return branch_has_immediate_return(then_node) or branch_has_immediate_return(else_node)


SYSNR_TO_NAME: Dict[str, str] = {}


def resolve_syscall_indirection(call: cindex.Cursor) -> Optional[str]:
    """If `call` is syscall(SYS_* or __NR_*), return the implied base name."""
    nm = _callee_name(call)
    if nm != "syscall":
        return None
    kids = list(call.get_children())
    if len(kids) < 2:
        return None
    selector = kids[1]
    try:
        txt = "".join(tok.spelling for tok in selector.get_tokens())
    except Exception:
        txt = ""
    m = re.search(r"(?:SYS|__NR)_(\w+)", txt)
    if m:
        return m.group(1)
    try:
        ev = selector.evaluate()
        if ev is not None and hasattr(ev, "value"):
            num = str(getattr(ev, "value", None))
            if num and num in SYSNR_TO_NAME:
                return SYSNR_TO_NAME[num]
    except Exception:
        pass
    return None


def _inner_target_from_one_hop(call_cursor: cindex.Cursor, target_names: Set[str]) -> Optional[str]:
    """Best-effort: inspect callee body; return first direct target name, if any."""
    defn = _callee_definition(call_cursor)
    if not defn:
        return None
    body = _function_body_cursor(defn)
    if not body:
        return None
    for ch in body.get_children():
        if ch.kind == K.CALL_EXPR:
            nm = _callee_name(ch)
            if nm in target_names:
                return nm
    return None


def _resolve_target_name_for_call(call: cindex.Cursor, catalog: ApiCatalog) -> Optional[str]:
    """Return a YAML target name for this call if resolvable, else None."""
    try:
        targets = catalog.target_names
        nm = _callee_name(call) or ""
        if nm in targets:
            return nm
        mapped = resolve_syscall_indirection(call)
        if mapped and mapped in targets:
            return mapped
        if _call_hits_target_via_one_hop(call, targets) or _call_hits_target_via_n_hops(call, targets, 2):
            inner = _inner_target_from_one_hop(call, targets)
            if inner and inner in targets:
                return inner
    except Exception:
        pass
    return None


# ==================================================
# Per-expression counting (used by per-path summary)
# ==================================================

def count_calls_in_expr(node: Optional[cindex.Cursor],
                        target_names: Set[str],
                        helpers: HelperConfig,
                        max_helper_hops: int = 1) -> int:
    """Count *target* calls inside an expression subtree."""
    if node is None:
        return 0
    cnt = 0
    try:
        children = node.get_children()
    except Exception:
        return 0

    for ch in children:
        if ch.kind == K.CALL_EXPR:
            if is_helper_call(ch, helpers, kind="benign"):
                pass
            else:
                name = _callee_name(ch)
                if name in target_names:
                    cnt += 1
                else:
                    mapped = resolve_syscall_indirection(ch)
                    if mapped and mapped in target_names:
                        cnt += 1
                    else:
                        if _call_hits_target_via_one_hop(ch, target_names) or (max_helper_hops > 1 and _call_hits_target_via_n_hops(ch, target_names, max_helper_hops)):
                            cnt += 1
        cnt += count_calls_in_expr(ch, target_names, helpers, max_helper_hops)
    return cnt


# ==========================
# Lightweight path summary
# ==========================

@dataclass
class PathResult:
    counts: Set[int] = field(default_factory=set)
    unknown: bool = False


def _merge_pr(a: PathResult, b: PathResult) -> PathResult:
    return PathResult(counts=(a.counts | b.counts), unknown=(a.unknown or b.unknown))


def analyze_stmt(stmt: cindex.Cursor,
                target_names: Set[str],
                helpers: HelperConfig,
                max_helper_hops: int = 1) -> PathResult:
    """
    Compute a conservative set of per-path call-counts for `stmt`.
    """
    kind = stmt.kind
    pr = PathResult()

    def cap_union(sumset: Set[int], val: int) -> Set[int]:
        out = set()
        for s in sumset or {0}:
            k = s + val
            if k <= 2:
                out.add(k)
            else:
                out.add(2)
        return out

    if kind == K.RETURN_STMT:
        cnt = 0
        for ch in stmt.get_children():
            cnt += count_calls_in_expr(ch, target_names, helpers, max_helper_hops)
        pr.counts = {cnt if cnt <= 2 else 2}
        return pr

    if kind == K.CALL_EXPR:
        if is_helper_call(stmt, helpers, kind="benign"):
            pr.counts = {0}
            return pr
        nm = _callee_name(stmt)
        val = 0
        if nm in target_names:
            val = 1
        else:
            mapped = resolve_syscall_indirection(stmt)
            if mapped and mapped in target_names:
                val = 1
            elif _call_hits_target_via_one_hop(stmt, target_names) or (max_helper_hops > 1 and _call_hits_target_via_n_hops(stmt, target_names, max_helper_hops)):
                val = 1
        pr.counts = {val}
        return pr

    if kind == K.IF_STMT:
        kids = list(stmt.get_children())
        then_branch = kids[1] if len(kids) > 1 else None
        else_branch = kids[2] if len(kids) > 2 else None
        pr_then = analyze_stmt(then_branch, target_names, helpers, max_helper_hops) if then_branch else PathResult({0}, False)
        pr_else = analyze_stmt(else_branch, target_names, helpers, max_helper_hops) if else_branch else PathResult({0}, False)
        pr.counts = pr_then.counts | pr_else.counts
        pr.unknown = pr_then.unknown or pr_else.unknown
        return pr

    if kind == K.SWITCH_STMT:
        acc_pr = PathResult(counts=set(), unknown=False)
        for ch in stmt.get_children():
            if ch.kind in (K.CASE_STMT, K.DEFAULT_STMT):
                kids = list(ch.get_children())
                body = kids[1] if len(kids) >= 2 else None
                prb = analyze_stmt(body, target_names, helpers, max_helper_hops) if body else PathResult({0}, False)
                acc_pr = _merge_pr(acc_pr, prb)
        if not acc_pr.counts:
            acc_pr.counts = {0}
        return acc_pr

    if kind == K.CONDITIONAL_OPERATOR:
        kids = list(stmt.get_children())
        then_node = kids[1] if len(kids) >= 2 else None
        else_node = kids[2] if len(kids) >= 3 else None
        pr_then = analyze_stmt(then_node, target_names, helpers, max_helper_hops) if then_node else PathResult({0}, False)
        pr_else = analyze_stmt(else_node, target_names, helpers, max_helper_hops) if else_node else PathResult({0}, False)
        return _merge_pr(pr_then, pr_else)

    if kind in (K.FOR_STMT, K.WHILE_STMT, K.DO_STMT):
        body = None
        for ch in stmt.get_children():
            if ch.kind == K.COMPOUND_STMT or ch.kind == K.BREAK_STMT or ch.kind == K.CONTINUE_STMT:
                body = ch if ch.kind == K.COMPOUND_STMT else body
        if body is None:
            return PathResult(counts={2}, unknown=True)
        pr_body = analyze_stmt(body, target_names, helpers)
        if any(x >= 2 for x in pr_body.counts):
            return PathResult(counts={2}, unknown=True)
        pr.counts = pr_body.counts | {0, 1}
        pr.unknown = pr_body.unknown
        return pr

    if kind == K.COMPOUND_STMT:
        acc: Set[int] = {0}
        unknown = False
        for ch in stmt.get_children():
            child = analyze_stmt(ch, target_names, helpers, max_helper_hops)
            new_acc: Set[int] = set()
            for v in child.counts:
                new_acc |= cap_union(acc, v)
            acc = new_acc
            unknown = unknown or child.unknown
        pr.counts = acc
        pr.unknown = unknown
        return pr

    acc_pr = PathResult(counts={0}, unknown=False)
    for ch in stmt.get_children():
        acc_pr = _merge_pr(acc_pr, analyze_stmt(ch, target_names, helpers, max_helper_hops))
    return acc_pr


# ===========================
# Target call site collection
# ===========================

def collect_target_calls(fn: cindex.Cursor, target_names: Set[str]) -> List[Tuple[cindex.Cursor, str]]:
    """Find target calls inside `fn`, including helper hops and syscall mapping."""
    hits: List[Tuple[cindex.Cursor, str]] = []

    def visit(n: cindex.Cursor):
        if n.kind == K.CALL_EXPR:
            name = _callee_name(n)
            if name in target_names:
                loc = n.location
                hits.append((n, f"{loc.line}:{loc.column}" if loc else "?"))
            else:
                mapped = resolve_syscall_indirection(n)
                if mapped and mapped in target_names:
                    loc = n.location
                    hits.append((n, f"{loc.line}:{loc.column}" if loc else "?"))
                elif _call_hits_target_via_one_hop(n, target_names) or _call_hits_target_via_n_hops(n, target_names, 2):
                    loc = n.location
                    hits.append((n, f"{loc.line}:{loc.column}" if loc else "?"))
        for ch in n.get_children():
            visit(ch)

    visit(fn)
    return hits


__all__ = [
    "analyze_stmt",
    "collect_target_calls",
    "count_calls_in_expr",
    "has_early_guard_return",
    "is_atomic_pair",
    "is_helper_call",
    "resolve_syscall_indirection",
    "_call_hits_target_via_n_hops",
    "_call_hits_target_via_one_hop",
    "_resolve_target_name_for_call",
]
