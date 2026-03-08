"""AST cursor helpers for libclang."""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

from cwrappers.finder.clang_bootstrap import cindex, K


def _cursor_kinds(*names: str):
    kinds = []
    for name in names:
        kind = getattr(K, name, None)
        if kind is not None:
            kinds.append(kind)
    return tuple(kinds)


_CALLABLE_DECL_KINDS = _cursor_kinds(
    "FUNCTION_DECL",
    "FUNCTION_TEMPLATE",
    "CXX_METHOD",
    "CONSTRUCTOR",
    "DESTRUCTOR",
    "CONVERSION_FUNCTION",
)


def _is_callable_decl(c: Optional[cindex.Cursor]) -> bool:
    return bool(c is not None and getattr(c, "kind", None) in _CALLABLE_DECL_KINDS)


def _is_callable_definition(c: Optional[cindex.Cursor]) -> bool:
    if not _is_callable_decl(c):
        return False
    try:
        return bool(c.is_definition())
    except Exception:
        return False


def _callee_name(call: cindex.Cursor) -> Optional[str]:
    try:
        ref = call.get_definition() or call.referenced
        if ref is None:
            return call.spelling or call.displayname
        return ref.spelling or ref.displayname
    except Exception:
        return call.spelling or call.displayname


def _callee_definition(call: cindex.Cursor) -> Optional[cindex.Cursor]:
    try:
        ref = call.get_definition() or call.referenced
        if _is_callable_decl(ref):
            return ref
    except Exception:
        pass
    return None


def _function_body_cursor(fn: cindex.Cursor) -> Optional[cindex.Cursor]:
    try:
        for ch in fn.get_children():
            if ch.kind == K.COMPOUND_STMT:
                return ch
    except Exception:
        return None
    return None


def _is_param(c: cindex.Cursor) -> bool:
    return c.kind == cindex.CursorKind.PARM_DECL


def _var_key(c: cindex.Cursor) -> str:
    # Stable key for both declarations (PARM_DECL/VAR_DECL) and references (DECL_REF_EXPR).
    base = c
    try:
        if c.kind == K.DECL_REF_EXPR and getattr(c, "referenced", None):
            base = c.referenced
        else:
            canon = getattr(c, "canonical", None)
            if canon is not None:
                base = canon
    except Exception:
        base = c
    return f"{base.spelling}@{base.hash}"


def _caller_name(fn_cursor: cindex.Cursor) -> str:
    """Return a readable caller name for a function definition cursor."""
    try:
        return fn_cursor.spelling or fn_cursor.displayname or "<anon>"
    except Exception:
        return "<anon>"


def _function_key(fn_cursor: cindex.Cursor) -> str:
    """Return a stable key for a function definition: prefer Clang USR if available,
    otherwise fall back to 'name@abs_path:line'."""
    try:
        usr = None
        if hasattr(fn_cursor, "get_usr"):
            try:
                usr = fn_cursor.get_usr()
            except Exception:
                usr = None
        if usr:
            return usr
        name = _caller_name(fn_cursor)
        loc = getattr(fn_cursor, "location", None)
        if loc and getattr(loc, "file", None):
            return f"{name}@{Path(loc.file.name).resolve()}:{loc.line}"
        return f"{name}@<unknown>"
    except Exception:
        return "<unknown>"


def _callsite_loc(call: cindex.Cursor) -> str:
    """Return file:line:column for a call site, using <unknown> when libclang omits the file."""
    try:
        loc = call.location
        if not loc:
            return "<unknown>:0:0"
        if not loc.file:
            return f"<unknown>:{int(getattr(loc, 'line', 0) or 0)}:{int(getattr(loc, 'column', 0) or 0)}"
        return f"{Path(loc.file.name).resolve()}:{loc.line}:{loc.column}"
    except Exception:
        return "<unknown>:0:0"


def _cursor_loc_key(c: Optional[cindex.Cursor]) -> Optional[Tuple[str, int, int]]:
    if c is None:
        return None
    try:
        loc = c.location
        if not loc or not loc.file:
            return None
        return (str(loc.file.name), loc.line, loc.column)
    except Exception:
        return None


__all__ = [
    "_callee_definition",
    "_callee_name",
    "_callsite_loc",
    "_caller_name",
    "_cursor_loc_key",
    "_function_body_cursor",
    "_function_key",
    "_is_callable_decl",
    "_is_callable_definition",
    "_is_param",
    "_var_key",
]
