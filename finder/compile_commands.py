"""Compile commands loading and arg normalization for libclang."""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import List, Optional, Tuple, Dict

from cwrappers.finder.clang_bootstrap import _include_already_present
from cwrappers.shared.log import eprint

# Optional list of (old_prefix, new_prefix) mappings applied to compile_commands
PATH_MAPS: List[Tuple[str, str]] = []


def load_compile_commands(cc_path: Path) -> List[dict]:
    try:
        text = cc_path.read_text(encoding="utf-8")
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError("compile_commands.json root must be a list")
        return data
    except Exception as e:
        eprint(f"ERROR: Failed to read {cc_path}: {e}")
        raise SystemExit(1)


def _tokenize_command_or_args(entry: dict) -> List[str]:
    """Return a token list from either 'arguments' (preferred) or 'command'."""
    args = entry.get("arguments")
    if isinstance(args, list):
        return list(args)
    cmd = entry.get("command")
    if isinstance(cmd, str):
        return shlex.split(cmd)
    return []


def _looks_like_compiler(tok: str) -> bool:
    base = os.path.basename(tok)
    return base in {"cc", "gcc", "clang", "clang-16", "clang-17", "clang-18", "clang-19", "clang-20", "c99", "c11"}


def _is_output_flag(tok: str) -> bool:
    return tok in {"-c", "-E", "-S", "-o", "-MF", "-MT", "-MQ", "-MJ"} or tok.startswith("-o")


def _is_linker_flag(tok: str) -> bool:
    return tok.startswith("-Wl,") or tok.startswith("@")


def _is_object(tok: str) -> bool:
    return tok.endswith(".o") or tok.endswith(".obj")


def _is_unsupported_warning(tok: str) -> bool:
    if not tok.startswith("-W"):
        return False
    if tok.startswith("-Wno-"):
        return True
    bad_exact = {
        "-Wno-missing-attributes",
        "-Wno-unknown-warning-option",
    }
    return tok in bad_exact


def _abs_if_needed(p: str, base: Path) -> str:
    try:
        pp = Path(p)
        return str(pp if pp.is_absolute() else (base / pp).resolve())
    except Exception:
        return p


def _sanitize_clang_args_for_libclang(raw_args, src_path, entry_dir):
    """
    Minimal, strict sanitizer for libclang parse args.
    """
    ADD_DEFAULTS = os.environ.get("WRAPFINDER_ADD_DEFAULTS") == "1"

    def _split_response_file(tok: str):
        if not tok.startswith("@"):
            return [tok]
        p = Path(tok[1:])
        try:
            if p.is_file() and p.stat().st_size <= 2 * 1024 * 1024:
                return shlex.split(p.read_text(errors="ignore"))
        except Exception:
            pass
        return []

    def _abspath(candidate: Optional[str], base_dir: str) -> str:
        try:
            if candidate is None:
                return ""
            p = Path(candidate)
            if not p.is_absolute():
                p = (Path(base_dir) / p).resolve()
            return str(p)
        except Exception:
            return candidate or ""

    def _is_obj_or_lib(tok: str) -> bool:
        lo = tok.lower()
        return lo.endswith((".o", ".obj", ".lo", ".a", ".lib", ".so", ".dylib", ".bc", ".ll"))

    def _is_source_file(tok: str) -> bool:
        lo = tok.lower()
        return lo.endswith((".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm"))

    def _is_warning(tok: str) -> bool:
        if tok.startswith("-Wl,"):
            return False
        return tok.startswith("-W")

    DROP_EXACT = {
        "-c", "-E", "-S",
        "-pipe",
        "-static", "-shared", "-rdynamic",
        "-s",
        "-g", "-ggdb", "-gsplit-dwarf",
        "-save-temps",
    }
    DROP_PREFIXES = (
        "-Wl,", "-Xlinker",
        "-l", "-L",
        "-fuse-ld", "-T", "-u",
        "-flto", "-fwhole-program-vtables",
        "-fprofile", "-fcoverage", "--coverage", "-fprofile-",
        "-fsanitize", "-fno-sanitize",
        "-fmodules", "-fmodule-file=", "-fmodule-map-file=", "-fmodules-cache-path",
        "-m",
    )

    PRESERVE_EXACT = {"-pthread", "-ansi", "-fsigned-char", "-pedantic"}

    PAIR_FLAGS = {
        "-I", "-isystem", "-iquote", "-idirafter",
        "-include", "-imacros",
        "-o", "-MF", "-MT", "-MQ", "-MJ",
        "-x", "-isysroot", "--sysroot",
        "-resource-dir", "-target",
    }

    tokens = []
    for t in (raw_args or []):
        tokens.extend(_split_response_file(t))

    filtered: List[str] = []
    saw_lang = False
    saw_std = False
    saw_resource_dir = False

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        if i == 0 and (not tok.startswith("-")) and (os.path.basename(tok) in {"clang", "clang-20", "clang-19", "clang-18", "clang-17", "clang-16", "gcc", "cc", "c99", "c11"}):
            i += 1
            continue

        if tok in DROP_EXACT:
            i += 1
            continue
        if _is_obj_or_lib(tok) or _is_source_file(tok):
            i += 1
            continue
        if any(tok.startswith(pref) for pref in DROP_PREFIXES):
            i += 1
            continue
        if _is_warning(tok):
            i += 1
            continue

        if tok in PAIR_FLAGS:
            has_value = (i + 1 < n) and (not tokens[i + 1].startswith("-"))
            val = tokens[i + 1] if has_value else None

            if tok in {"-o", "-MF", "-MT", "-MQ", "-MJ"}:
                i += 1 + (1 if has_value else 0)
                continue

            if not has_value:
                eprint(f"[warn] dropping dangling flag (no value): {tok}")
                i += 1
                continue

            abs_val = val
            if tok in {"-I", "-isystem", "-iquote", "-idirafter", "-include", "-imacros", "-isysroot", "--sysroot"}:
                abs_val = _abspath(val, entry_dir)

            if tok == "-x":
                saw_lang = True
            elif tok == "-resource-dir":
                saw_resource_dir = True
            elif tok.startswith("-std"):
                saw_std = True

            filtered.append(tok)
            filtered.append(abs_val)
            i += 2
            continue

        if tok.startswith("-std="):
            saw_std = True
            filtered.append(tok)
            i += 1
            continue

        if tok.startswith("-I") and tok != "-I":
            val = tok[2:]
            if val:
                filtered.append("-I")
                filtered.append(_abspath(val, entry_dir))
            i += 1
            continue

        if tok.startswith("-isystem") and tok != "-isystem":
            val = tok[len("-isystem"):]
            if val:
                filtered.append("-isystem")
                filtered.append(_abspath(val, entry_dir))
            i += 1
            continue

        if tok.startswith("-iquote") and tok != "-iquote":
            val = tok[len("-iquote"):]
            if val:
                filtered.append("-iquote")
                filtered.append(_abspath(val, entry_dir))
            i += 1
            continue

        if tok.startswith("-idirafter") and tok != "-idirafter":
            val = tok[len("-idirafter"):]
            if val:
                filtered.append("-idirafter")
                filtered.append(_abspath(val, entry_dir))
            i += 1
            continue

        if tok.startswith("-isysroot="):
            filtered.append("-isysroot=" + _abspath(tok.split("=", 1)[1], entry_dir))
            i += 1
            continue

        if tok.startswith("--sysroot="):
            filtered.append("--sysroot=" + _abspath(tok.split("=", 1)[1], entry_dir))
            i += 1
            continue

        if tok.startswith("-resource-dir="):
            saw_resource_dir = True
            filtered.append("-resource-dir=" + _abspath(tok.split("=", 1)[1], entry_dir))
            i += 1
            continue

        if tok.startswith("-D"):
            filtered.append(tok)
            i += 1
            continue

        if tok in PRESERVE_EXACT:
            filtered.append(tok)
            i += 1
            continue

        if tok.startswith("-O"):
            filtered.append(tok)
            i += 1
            continue

        i += 1

    if not any(a == "-working-directory" or str(a).startswith("-working-directory=") for a in filtered):
        filtered.append(f"-working-directory={str(Path(entry_dir))}")

    src_dir = str(Path(src_path).parent.resolve())
    ent_dir = str(Path(entry_dir).resolve())
    if src_dir != ent_dir and not _include_already_present(filtered, src_dir):
        filtered.extend(["-I", src_dir])

    def _has_sys_include(argv: list[str], path: str) -> bool:
        try:
            abs_path = str(Path(path).resolve())
        except Exception:
            abs_path = path
        for k, t in enumerate(argv):
            if t in ("-I", "-isystem", "-iquote", "-idirafter"):
                if k + 1 < len(argv) and str(Path(argv[k + 1]).resolve()) == abs_path:
                    return True
            if isinstance(t, str) and t.startswith("-I") and t != "-I":
                v = t[2:]
                try:
                    if str(Path(v).resolve()) == abs_path:
                        return True
                except Exception:
                    pass
        return False

    if not _has_sys_include(filtered, "/usr/include"):
        filtered.extend(["-I", "/usr/include"])

    multiarch = "/usr/include/x86_64-linux-gnu"
    if os.path.isdir(multiarch) and not _has_sys_include(filtered, multiarch):
        filtered.extend(["-I", multiarch])

    if not saw_resource_dir:
        import glob
        candidates = []
        candidates += sorted(glob.glob("/usr/lib/llvm-*/lib/clang/*"), reverse=True)
        candidates += sorted(glob.glob("/usr/lib/clang/*"), reverse=True)
        picked = None

        env_rd = os.environ.get("CLANG_RESOURCE_DIR")
        if env_rd and os.path.exists(os.path.join(env_rd, "include", "stddef.h")):
            picked = env_rd
        else:
            for rd in candidates:
                if os.path.exists(os.path.join(rd, "include", "stddef.h")):
                    picked = rd
                    break
        if picked:
            filtered.append(f"-resource-dir={picked}")

    def _has_any_project_includes(argv: list[str]) -> bool:
        sys_paths = {"/usr/include", "/usr/include/x86_64-linux-gnu"}
        for j, t in enumerate(argv):
            if t in ("-I", "-isystem", "-iquote", "-idirafter"):
                if j + 1 < len(argv) and not str(argv[j + 1]).startswith("-"):
                    try:
                        abs_p = str(Path(argv[j + 1]).resolve())
                        if abs_p not in sys_paths:
                            return True
                    except Exception:
                        pass
            if isinstance(t, str) and t.startswith("-I") and t != "-I":
                v = t[2:]
                try:
                    abs_p = str(Path(v).resolve())
                    if abs_p not in sys_paths:
                        return True
                except Exception:
                    pass
        return False

    if ADD_DEFAULTS and not _has_any_project_includes(filtered):
        src_dir = str(Path(src_path).parent.resolve())
        ent_dir = str(Path(entry_dir).resolve())
        for pth in (ent_dir, src_dir):
            if pth and not _include_already_present(filtered, pth):
                filtered.extend(["-I", pth])

    for k, t in enumerate(filtered[:-1]):
        if t == "-I" and str(filtered[k + 1]).startswith("-"):
            eprint(f"[warn] dropping malformed '-I' followed by flag: {filtered[k+1]}")

    if not saw_lang:
        sp = str(src_path).lower()
        if sp.endswith((".c",)):
            filtered[0:0] = ["-x", "c"]
        elif sp.endswith((".cc", ".cpp", ".cxx", ".c++")):
            filtered[0:0] = ["-x", "c++"]
        elif sp.endswith((".m",)):
            filtered[0:0] = ["-x", "objective-c"]
        elif sp.endswith((".mm",)):
            filtered[0:0] = ["-x", "objective-c++"]
        else:
            filtered[0:0] = ["-x", "c"]

    return filtered


def normalize_args_from_entry(entry: dict) -> Tuple[Path, List[str]]:
    """Convert one compile_commands entry into (absolute_src_path, sanitized_args)."""
    directory = Path(entry.get("directory") or ".").resolve()
    file_field = entry.get("file")
    if not file_field:
        raise ValueError("compile_commands entry missing 'file'")
    src_path = (directory / file_field).resolve()

    if not src_path.exists():
        for old_prefix, new_prefix in PATH_MAPS:
            try:
                s = str(src_path)
                if s.startswith(old_prefix):
                    candidate = Path(s.replace(old_prefix, new_prefix, 1))
                    if candidate.exists():
                        eprint(f"[warn] remapped source path via path-map: {src_path} -> {candidate}")
                        src_path = candidate.resolve()
                        directory = src_path.parent
                        break
            except Exception:
                pass

    if not src_path.exists():
        raise ValueError(f"source path does not exist: {src_path}")

    raw = _tokenize_command_or_args(entry)
    if not raw:
        raise ValueError("compile_commands entry missing 'arguments'/'command'")

    args = _sanitize_clang_args_for_libclang(raw, src_path, directory)
    return (src_path, args)


def build_file_to_args_map(entries: List[dict]) -> Dict[Path, List[str]]:
    out: Dict[Path, List[str]] = {}
    for ent in entries:
        try:
            src, args = normalize_args_from_entry(ent)
            out[src] = args
        except Exception as e:
            eprint(f"[warn] skipping entry due to parse error: {e}")
    return out
