"""Argument/return provenance and taint analysis."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from cwrappers.finder.ast_utils import _cursor_loc_key, _function_body_cursor, _is_param, _var_key
from cwrappers.finder.analysis import is_helper_call
from cwrappers.finder.catalog import HelperConfig
from cwrappers.finder.clang_bootstrap import cindex, K


@dataclass
class TaintState:
    taint: Dict[str, List[str]] = field(default_factory=dict)
    ret_tainted: bool = False
    ret_trace: List[str] = field(default_factory=list)

    def mark(self, key: str, why: str) -> None:
        self.taint[key] = self.taint.get(key, []) + [why]

    def is_tainted(self, key: str) -> bool:
        return key in self.taint

    def trace(self, key: str) -> List[str]:
        return self.taint.get(key, [])


def taint_stmt(stmt: cindex.Cursor,
                state: TaintState,
                helpers: Optional[HelperConfig]) -> None:
    """Very simple intra-procedural taint: track assignments from params through locals."""
    kind = stmt.kind
    if kind == K.DECL_STMT:
        for child in stmt.get_children():
            taint_stmt(child, state, helpers)
    elif kind == K.VAR_DECL:
        lhs = _var_key(stmt)
        for child in stmt.get_children():
            t, trace = taint_expr(child, state, helpers or HelperConfig(set(), [], set(), []))
            if t:
                for reason in trace:
                    state.mark(lhs, reason)
    elif kind == K.BINARY_OPERATOR:
        kids = list(stmt.get_children())
        if len(kids) == 2:
            lhs, rhs = kids
            if lhs.kind == K.DECL_REF_EXPR:
                key = _var_key(lhs)
                t, trace = taint_expr(rhs, state, helpers or HelperConfig(set(), [], set(), []))
                if t:
                    for reason in trace:
                        state.mark(key, reason)
    elif kind == K.RETURN_STMT:
        for ch in stmt.get_children():
            t, trace = taint_expr(ch, state, helpers or HelperConfig(set(), [], set(), []))
            if t:
                state.ret_tainted = True
                state.ret_trace += trace
    else:
        for ch in stmt.get_children():
            taint_stmt(ch, state, helpers)


def taint_expr(expr: cindex.Cursor,
               state: TaintState,
               helpers: Optional[HelperConfig]) -> Tuple[bool, List[str]]:
    """Check if an expression is tainted (data-derived from params)."""
    if expr is None:
        return False, []
    kind = expr.kind
    if kind == K.DECL_REF_EXPR:
        key = _var_key(expr)
        if state.is_tainted(key):
            return True, state.trace(key)
    elif kind in (K.UNARY_OPERATOR, K.CSTYLE_CAST_EXPR,
                  K.MEMBER_REF_EXPR, K.ARRAY_SUBSCRIPT_EXPR):
        for ch in expr.get_children():
            t, tr = taint_expr(ch, state, helpers)
            if t:
                return True, tr
    elif kind == K.BINARY_OPERATOR:
        kids = list(expr.get_children())
        for ch in kids:
            t, tr = taint_expr(ch, state, helpers)
            if t:
                return True, tr
    elif kind == K.CALL_EXPR:
        if is_helper_call(expr, helpers or HelperConfig(set(), [], set(), []), kind="benign"):
            return False, []
        return False, []
    else:
        for ch in expr.get_children():
            t, tr = taint_expr(ch, state, helpers)
            if t:
                return True, tr
    return False, []


def extract_call_args(call: cindex.Cursor) -> List[cindex.Cursor]:
    """Return the argument expression cursors for this CALL_EXPR."""
    kids = list(call.get_children())
    if not kids:
        return []
    return kids[1:]


def check_arguments_provenance(func: cindex.Cursor,
                               calls: List[cindex.Cursor],
                               helpers: Optional[HelperConfig] = None) -> Tuple[bool, List[str]]:
    """Run taint analysis on `func`; check that each call's args are derived from params."""
    state = TaintState()
    for ch in func.get_children():
        if _is_param(ch):
            state.mark(_var_key(ch), f"{ch.spelling} is param")

    body = _function_body_cursor(func)
    if not body:
        return False, ["no-body"]

    taint_stmt(body, state, helpers or HelperConfig(set(), [], set(), []))
    trace_out: List[str] = []
    ok = True

    for call in calls:
        for i, arg in enumerate(extract_call_args(call)):
            t, tr = taint_expr(arg, state, helpers)
            ok &= t
            trace_out.append(f"arg{i}:{'tainted' if t else 'clean'}" + (f" [{' ; '.join(tr)}]" if tr else ""))
    return ok, trace_out


# ======================================================
# Argument/return pass-through heuristics (new feature)
# ======================================================

def _gather_params(fn: cindex.Cursor) -> List[cindex.Cursor]:
    params = []
    try:
        for ch in fn.get_children():
            if _is_param(ch):
                params.append(ch)
    except Exception:
        pass
    return params


def _expr_uses_param(expr: cindex.Cursor, param_keys: Set[str]) -> Set[str]:
    """Return set of param variable keys referenced within expr."""
    used: Set[str] = set()
    if expr is None:
        return used
    stack = [expr]
    while stack:
        n = stack.pop()
        try:
            if n.kind == K.DECL_REF_EXPR:
                ref = getattr(n, 'referenced', None)
                if ref is not None:
                    key = _var_key(ref)
                    if key in param_keys:
                        used.add(key)
        except Exception:
            pass
        try:
            for ch in n.get_children():
                stack.append(ch)
        except Exception:
            pass
    return used


def _return_expr_derives_from(expr: cindex.Cursor,
                              call_loc_key: Optional[Tuple[str, int, int]],
                              result_var_keys: Set[str]) -> bool:
    """Heuristic: return expr directly calls target API or returns a variable assigned from it."""
    if not call_loc_key:
        return False
    if expr is None:
        return False
    stack = [expr]
    while stack:
        n = stack.pop()
        try:
            if n.kind == K.CALL_EXPR:
                if _cursor_loc_key(n) == call_loc_key:
                    return True
            elif n.kind == K.DECL_REF_EXPR:
                ref = getattr(n, 'referenced', None)
                if ref is not None:
                    key = _var_key(ref)
                    if key in result_var_keys:
                        return True
        except Exception:
            pass
        try:
            for ch in n.get_children():
                stack.append(ch)
        except Exception:
            pass
    return False


def _expr_param_sources(expr: Optional[cindex.Cursor], var_sources: Dict[str, Set[str]]) -> Set[str]:
    """Return set of parameter-keys that flow into expr via var_sources mapping."""
    if expr is None:
        return set()
    out: Set[str] = set()
    stack = [expr]
    while stack:
        n = stack.pop()
        try:
            if n.kind == K.DECL_REF_EXPR:
                ref = getattr(n, 'referenced', None)
                if ref is not None:
                    key = _var_key(ref)
                    out |= var_sources.get(key, set())
            for ch in n.get_children():
                stack.append(ch)
        except Exception:
            pass
    return out


def _build_var_param_sources(fn: cindex.Cursor) -> Tuple[Dict[str, Set[str]], Set[str]]:
    """Build a map from variable key -> set(param_keys) it derives from."""
    body = _function_body_cursor(fn)
    var_sources: Dict[str, Set[str]] = defaultdict(set)
    params = _gather_params(fn)
    param_keys = {_var_key(p) for p in params}
    for p in params:
        var_sources[_var_key(p)] = {_var_key(p)}
    if not body:
        return var_sources, param_keys

    for _ in range(3):
        changed = False
        stack = [body]
        while stack:
            n = stack.pop()
            try:
                if n.kind == K.VAR_DECL:
                    lhs_key = _var_key(n)
                    for ch in n.get_children():
                        srcs = _expr_param_sources(ch, var_sources)
                        if srcs and not srcs.issubset(var_sources.get(lhs_key, set())):
                            var_sources[lhs_key] = var_sources.get(lhs_key, set()) | srcs
                            changed = True
                elif n.kind == K.BINARY_OPERATOR:
                    kids = list(n.get_children())
                    if len(kids) == 2 and kids[0].kind == K.DECL_REF_EXPR:
                        lhs = kids[0]
                        rhs = kids[1]
                        lhs_ref = getattr(lhs, 'referenced', None)
                        if lhs_ref is not None:
                            lhs_key = _var_key(lhs_ref)
                        else:
                            lhs_key = _var_key(lhs)
                        srcs = _expr_param_sources(rhs, var_sources)
                        if srcs and not srcs.issubset(var_sources.get(lhs_key, set())):
                            var_sources[lhs_key] = var_sources.get(lhs_key, set()) | srcs
                            changed = True
                for ch in n.get_children():
                    stack.append(ch)
            except Exception:
                pass
        if not changed:
            break
    return var_sources, param_keys


def _build_call_result_varset(fn: cindex.Cursor, call_loc_keys: Set[Tuple[str, int, int]]) -> Set[str]:
    """Return set of variable keys that derive (directly or via simple assignments) from the given call sites."""
    body = _function_body_cursor(fn)
    result_vars: Set[str] = set()
    if not body:
        return result_vars
    for _ in range(3):
        changed = False
        stack = [body]
        while stack:
            n = stack.pop()
            try:
                if n.kind == K.VAR_DECL:
                    lhs_key = _var_key(n)
                    for ch in n.get_children():
                        is_from_call = (ch.kind == K.CALL_EXPR and _cursor_loc_key(ch) in call_loc_keys)
                        if is_from_call:
                            if lhs_key not in result_vars:
                                result_vars.add(lhs_key)
                                changed = True
                        else:
                            uses_result = False
                            for ec in ch.get_children():
                                if ec.kind == K.DECL_REF_EXPR:
                                    ref = getattr(ec, 'referenced', None)
                                    if ref is not None and _var_key(ref) in result_vars:
                                        uses_result = True
                                        break
                            if uses_result and lhs_key not in result_vars:
                                result_vars.add(lhs_key)
                                changed = True
                elif n.kind == K.BINARY_OPERATOR:
                    kids = list(n.get_children())
                    if len(kids) == 2 and kids[0].kind == K.DECL_REF_EXPR:
                        lhs = kids[0]
                        rhs = kids[1]
                        lhs_ref = getattr(lhs, 'referenced', None)
                        lhs_key = _var_key(lhs_ref) if lhs_ref is not None else _var_key(lhs)
                        if rhs.kind == K.CALL_EXPR and _cursor_loc_key(rhs) in call_loc_keys:
                            if lhs_key not in result_vars:
                                result_vars.add(lhs_key)
                                changed = True
                        else:
                            uses_result = False
                            stack_rhs = [rhs]
                            while stack_rhs:
                                m = stack_rhs.pop()
                                if m.kind == K.DECL_REF_EXPR:
                                    ref = getattr(m, 'referenced', None)
                                    if ref is not None and _var_key(ref) in result_vars:
                                        uses_result = True
                                        break
                                try:
                                    for ch2 in m.get_children():
                                        stack_rhs.append(ch2)
                                except Exception:
                                    pass
                            if uses_result and lhs_key not in result_vars:
                                result_vars.add(lhs_key)
                                changed = True
                for ch in n.get_children():
                    stack.append(ch)
            except Exception:
                pass
        if not changed:
            break
    return result_vars


def compute_arg_ret_pass_multi(fn: cindex.Cursor, matching_calls: List[cindex.Cursor]) -> Tuple[str, str]:
    """Compute arg_pass and ret_pass with strict AST rules (direct passthrough only)."""
    if not matching_calls:
        return "no", "no"

    def _strip_noop(expr: Optional[cindex.Cursor]) -> Optional[cindex.Cursor]:
        n = expr
        while n is not None and n.kind in (K.PAREN_EXPR, K.CSTYLE_CAST_EXPR, K.UNEXPOSED_EXPR):
            kids = list(n.get_children())
            if not kids:
                break
            n = kids[-1]
        return n

    def _is_direct_param_ref(expr: Optional[cindex.Cursor]) -> Optional[str]:
        e = _strip_noop(expr)
        if e is None:
            return None
        if e.kind == K.DECL_REF_EXPR:
            ref = getattr(e, 'referenced', None)
            if ref is not None and ref.kind == K.PARM_DECL:
                return _var_key(ref)
        if e.kind == K.UNARY_OPERATOR:
            kids = list(e.get_children())
            if len(kids) == 1:
                inner = _strip_noop(kids[0])
                if inner is not None and inner.kind == K.MEMBER_REF_EXPR:
                    bad = False
                    base_param_key = None
                    stack_chain = [inner]
                    while stack_chain and not bad:
                        n = stack_chain.pop()
                        try:
                            for ch in n.get_children():
                                if ch.kind == K.DECL_REF_EXPR:
                                    ref = getattr(ch, 'referenced', None)
                                    if ref is not None and ref.kind == K.PARM_DECL:
                                        base_param_key = _var_key(ref)
                                if ch.kind in (K.ARRAY_SUBSCRIPT_EXPR, K.BINARY_OPERATOR, K.CALL_EXPR, K.CONDITIONAL_OPERATOR):
                                    bad = True
                                    break
                                if ch.kind == K.UNARY_OPERATOR:
                                    bad = True
                                    break
                                stack_chain.append(ch)
                        except Exception:
                            pass
                    if not bad and base_param_key is not None:
                        return base_param_key
        return None

    params = _gather_params(fn)
    param_keys: Set[str] = {_var_key(p) for p in params}
    param_count = len(param_keys)

    used_direct_params_union: Set[str] = set()
    arg_all_direct = False
    for call in matching_calls:
        args = extract_call_args(call)
        if param_count == 0:
            continue
        if len(args) > param_count:
            pass
        direct_map: List[Optional[str]] = []
        ok_all_direct = True
        for a in args:
            pk = _is_direct_param_ref(a)
            if pk is None or pk not in param_keys:
                ok_all_direct = False
            else:
                direct_map.append(pk)
                used_direct_params_union.add(pk)
        if ok_all_direct:
            if len(set(direct_map)) == len(direct_map) and len(set(direct_map)) == param_count:
                arg_all_direct = True
                break

    if arg_all_direct:
        arg_pass = "yes - all"
    elif used_direct_params_union:
        arg_pass = f"yes - {len(used_direct_params_union)}"
    else:
        arg_pass = "no"

    call_loc_keys: Set[Tuple[str, int, int]] = set()
    for c in matching_calls:
        k = _cursor_loc_key(c)
        if k:
            call_loc_keys.add(k)

    def _return_directly_call(ret_node: cindex.Cursor) -> bool:
        expr_children = list(ret_node.get_children())
        for ec in expr_children:
            e = _strip_noop(ec)
            if e is None:
                continue
            if e.kind in (K.BINARY_OPERATOR, K.UNARY_OPERATOR, K.CONDITIONAL_OPERATOR):
                return False
            if e.kind == K.CALL_EXPR and _cursor_loc_key(e) in call_loc_keys:
                return True
        return False

    body = _function_body_cursor(fn)
    total_returns = 0
    direct_returns = 0
    if body is not None:
        stack = [body]
        while stack:
            n = stack.pop()
            if n.kind == K.RETURN_STMT:
                total_returns += 1
                if _return_directly_call(n):
                    direct_returns += 1
            try:
                for ch in n.get_children():
                    stack.append(ch)
            except Exception:
                pass

    try:
        if str(fn.result_type.spelling or "").strip() == "void" or total_returns == 0:
            ret_pass = "no"
        else:
            if direct_returns == total_returns:
                ret_pass = "yes - all"
            elif direct_returns > 0:
                ret_pass = f"yes - {direct_returns}"
            else:
                ret_pass = "no"
    except Exception:
        ret_pass = "no"

    return arg_pass, ret_pass
