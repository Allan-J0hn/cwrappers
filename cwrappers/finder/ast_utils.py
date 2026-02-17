"""AST cursor helpers for libclang."""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

from cwrappers.finder.clang_bootstrap import cindex, K


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
        if ref and ref.kind in (K.FUNCTION_DECL, K.FUNCTION_TEMPLATE):
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


def _callsite_loc(call: cindex.Cursor) -> Optional[str]:
    """Return absolute file:line:column for a call site, or None if unavailable."""
    try:
        loc = call.location
        if not loc or not loc.file:
            return None
        return f"{Path(loc.file.name).resolve()}:{loc.line}:{loc.column}"
    except Exception:
        return None


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
