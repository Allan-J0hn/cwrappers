"""Libclang initialization and helpers."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from cwrappers.shared.log import eprint

# Verbose bootstrap logs are opt-in to keep CLI help/output clean.
def _debug(msg: str) -> None:
    if os.environ.get("CWRAPPERS_DEBUG") == "1":
        eprint(msg)


try:
    from clang import cindex
except Exception as e:
    print("ERROR: failed to import clang.cindex. Try `pip install clang`.", file=sys.stderr)
    raise

# Helper used by the clang-args sanitizer to detect existing -I entries.
def _include_already_present(args: list[str], include_path: str) -> bool:
    """Return True if include_path already appears in args (handles -I x and -I/x forms)."""
    if not include_path:
        return False
    for i, a in enumerate(args):
        if a == "-I":
            if i + 1 < len(args) and args[i + 1] == include_path:
                return True
        else:
            if a.startswith("-I") and a[2:] == include_path:
                return True
    return False


# Robust libclang loader: prefer LIBCLANG_PATH, then common distro locations.
def _init_libclang() -> None:
    tried: list[str] = []

    def _try_set(libpath: str) -> bool:
        try:
            if not libpath:
                return False
            libfile = libpath
            if Path(libfile).is_dir():
                candidates = [
                    str(Path(libfile) / "libclang.so"),
                    str(Path(libfile) / "libclang.so.1"),
                    str(Path(libfile) / "libclang-20.so"),
                ]
            else:
                candidates = [libfile]
            for cand in candidates:
                tried.append(cand)
                try:
                    cindex.Config.set_library_file(cand)
                    _debug(f"[debug] set libclang from: {cand}")
                    return True
                except Exception:
                    continue
        except Exception:
            pass
        return False

    # 1) respect explicit environment variable
    env_path = os.environ.get("LIBCLANG_PATH")
    if env_path and _try_set(env_path):
        return

    # 2) try python-clang provided Config.library_file if present
    libfile = getattr(cindex.Config, "library_file", None)
    if libfile:
        try:
            cindex.Config.set_library_file(libfile)
            _debug(f"[debug] using cindex.Config.library_file: {libfile}")
            return
        except Exception:
            tried.append(libfile)

    # 3) common system locations for libclang
    common_dirs = [
        "/usr/lib/llvm-20/lib",
        "/usr/lib/llvm-19/lib",
        "/usr/lib/llvm-18/lib",
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/lib",
    ]
    for d in common_dirs:
        if _try_set(d):
            return

    # 4) attempt to find libclang via ldconfig
    try:
        out = subprocess.check_output(["/sbin/ldconfig", "-p"], stderr=subprocess.DEVNULL, text=True)
        for line in out.splitlines():
            if "libclang.so" in line:
                parts = line.strip().split(" => ")
                if len(parts) == 2:
                    candidate = parts[1]
                    if _try_set(candidate):
                        return
    except Exception:
        pass

    # Common fallback (explicit)
    fallback = "/usr/lib/llvm-20/lib/libclang.so"
    if _try_set(fallback):
        return

    eprint("[warn] libclang not set. Tried:", tried)


def _locate_clang_binary() -> Optional[str]:
    """Return a clang binary path (CLANG_BIN env override, then common names) or None."""
    try:
        return os.environ.get("CLANG_BIN") or shutil.which("clang") or shutil.which("clang-20") or shutil.which("clang-19")
    except Exception:
        return os.environ.get("CLANG_BIN")


_init_libclang()

K = cindex.CursorKind

__all__ = ["cindex", "K", "_include_already_present", "_locate_clang_binary"]
