"""Runner for wrapper detection."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import yaml

from cwrappers.finder import compile_commands
from cwrappers.finder.analysis import collect_target_calls, _resolve_target_name_for_call
from cwrappers.finder.callgraph import (
    DetailedEdge,
    FunctionDef,
    build_function_index,
    build_edge_evidence_rows,
    collect_callgraph_for_tu_detailed,
    collect_function_defs_for_tu,
    resolve_project_function_key,
    resolve_edge_query,
    write_callgraph,
)
from cwrappers.finder.catalog import ApiCatalog, load_api_catalog
from cwrappers.finder.clang_bootstrap import cindex, K, _locate_clang_binary
from cwrappers.finder.models import Row, TranslationUnitReport
from cwrappers.finder.output import (
    is_stdout,
    prepare_output_location,
    write_edge_evidence_csv,
    write_edge_evidence_json,
    write_edge_evidence_jsonl,
    write_rows_csv,
    write_rows_json,
    write_rows_jsonl,
)
from cwrappers.finder.provenance import compute_arg_ret_pass_multi
from cwrappers.finder.wrapper_detection import analyze_wrapper_relaxed, analyze_wrapper_strict_plus
from cwrappers.finder.ast_utils import _caller_name, _function_key, _is_callable_definition
from cwrappers.shared.log import eprint
from cwrappers.shared.paths import default_catalog_path


def _safe_output_stem(name: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(name or "").strip())
    return stem.strip("._") or "edge_evidence"


def _default_output_name(fmt: str, edge_evidence: Optional[str] = None) -> str:
    if edge_evidence:
        stem = f"{_safe_output_stem(edge_evidence)}_edge_evidence"
        if fmt == "json":
            return f"{stem}.json"
        if fmt == "jsonl":
            return f"{stem}.jsonl"
        return f"{stem}.csv"
    if fmt == "json":
        return "wrappers.json"
    if fmt == "jsonl":
        return "wrappers.jsonl"
    return "wrappers.csv"


def _apply_out_dir(args) -> None:
    out_dir = getattr(args, "out_dir", None)
    if not out_dir:
        return
    out_dir = str(out_dir)
    if not out_dir:
        return
    default_name = _default_output_name(
        getattr(args, "output", "csv"),
        edge_evidence=getattr(args, "edge_evidence", None),
    )
    args.out = str(Path(out_dir) / default_name)


def _parse_args_provided() -> Set[str]:
    provided: Set[str] = set()
    for tok in sys.argv[1:]:
        if tok.startswith("--"):
            key = tok[2:].split("=")[0].replace("-", "_")
            provided.add(key)
    return provided


def _unique_in_order(names: Iterable[str]) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for n in names:
        v = (n or "").strip()
        if not v or v.lower() == "other":
            continue
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def _join_api_names(names: Iterable[str]) -> str:
    return " - ".join(_unique_in_order(names))


def _split_api_names(field: str) -> List[str]:
    out: List[str] = []
    for part in (field or "").split(" - "):
        p = (part or "").strip()
        if not p:
            continue
        if p.lower() == "other":
            continue
        out.append(p)
    return _unique_in_order(out)


def _parse_callsite_loc(loc: str) -> Tuple[int, int]:
    try:
        _path, line, col = str(loc).rsplit(":", 2)
        return (int(line), int(col))
    except Exception:
        return (10**9, 10**9)


def _trace_reachable_target_apis(
    all_edges: List[DetailedEdge],
    direct_targets_by_function: Dict[str, List[str]],
    function_name_by_key: Dict[str, str],
) -> Dict[str, List[str]]:
    """Compute transitive reachable tracked APIs for each defined function key."""
    adjacency: Dict[str, List[Tuple[str, Tuple[int, int]]]] = defaultdict(list)
    adjacency_seen: Dict[str, Set[str]] = defaultdict(set)
    keys_by_name: Dict[str, Set[str]] = defaultdict(set)
    for k, nm in function_name_by_key.items():
        keys_by_name[nm].add(k)

    for e in all_edges:
        caller_k = str(getattr(e, "caller_key", None) or getattr(e, "caller", "") or "")
        callee_k = str(getattr(e, "callee_key", None) or getattr(e, "callee", "") or "")
        callee_nm = str(getattr(e, "callee", "") or "")
        if not caller_k:
            continue

        resolved_callee_key: Optional[str] = None
        if callee_k in function_name_by_key:
            resolved_callee_key = callee_k
        elif callee_nm and (not callee_k or callee_k.endswith("@<unknown>")):
            candidates = keys_by_name.get(callee_nm, set())
            if len(candidates) == 1:
                resolved_callee_key = next(iter(candidates))

        if resolved_callee_key:
            if resolved_callee_key not in adjacency_seen[caller_k]:
                adjacency_seen[caller_k].add(resolved_callee_key)
                adjacency[caller_k].append((resolved_callee_key, _parse_callsite_loc(getattr(e, "loc", ""))))

    for caller_k in list(adjacency.keys()):
        adjacency[caller_k].sort(key=lambda pair: pair[1])

    memo: Dict[str, List[str]] = {}

    def dfs(func_key: str, stack: Set[str]) -> List[str]:
        if func_key in memo:
            return memo[func_key]

        base: List[str] = list(direct_targets_by_function.get(func_key, []))
        if func_key in stack:
            memo[func_key] = _unique_in_order(base)
            return memo[func_key]

        next_stack = set(stack)
        next_stack.add(func_key)
        for callee_key, _loc_key in adjacency.get(func_key, []):
            base.extend(dfs(callee_key, next_stack))

        memo[func_key] = _unique_in_order(base)
        return memo[func_key]

    for fk in function_name_by_key.keys():
        dfs(fk, set())

    return memo


def _trace_reachable_callee_names(
    all_edges: List[DetailedEdge],
    function_defs_by_key: Dict[str, FunctionDef],
) -> Dict[str, List[str]]:
    """Compute transitive reachable callee names for project-defined callers."""
    _defs_by_key, keys_by_name = build_function_index(function_defs_by_key.values())
    direct_names_by_caller: Dict[str, List[str]] = defaultdict(list)
    project_callees_by_caller: Dict[str, Set[str]] = defaultdict(set)

    for e in all_edges:
        caller_k, _caller_match = resolve_project_function_key(
            getattr(e, "caller_key", None),
            getattr(e, "caller", ""),
            function_defs_by_key,
            keys_by_name,
        )
        if not caller_k:
            continue

        callee_nm = str(getattr(e, "callee", "") or "")
        if callee_nm:
            direct_names_by_caller[caller_k].append(callee_nm)

        callee_k, _callee_match = resolve_project_function_key(
            getattr(e, "callee_key", None),
            getattr(e, "callee", ""),
            function_defs_by_key,
            keys_by_name,
        )
        if callee_k:
            project_callees_by_caller[caller_k].add(callee_k)

    memo: Dict[str, List[str]] = {}

    def dfs(func_key: str, stack: Set[str]) -> List[str]:
        if func_key in memo:
            return memo[func_key]

        names: List[str] = list(direct_names_by_caller.get(func_key, []))
        if func_key in stack:
            memo[func_key] = _unique_in_order(names)
            return memo[func_key]

        next_stack = set(stack)
        next_stack.add(func_key)
        for callee_key in sorted(project_callees_by_caller.get(func_key, set())):
            names.extend(dfs(callee_key, next_stack))

        memo[func_key] = _unique_in_order(names)
        return memo[func_key]

    for fk in function_defs_by_key.keys():
        dfs(fk, set())

    return memo


def _build_translation_unit_report(
    src: Path,
    tu: Optional[cindex.TranslationUnit],
    retry_used: bool,
    parse_failure: str = "",
) -> TranslationUnitReport:
    ignored = 0
    note = 0
    warning = 0
    error = 0
    fatal = 0

    for diag in getattr(tu, "diagnostics", []) or []:
        try:
            sev = int(getattr(diag, "severity", 0) or 0)
        except Exception:
            sev = 0
        if sev <= 0:
            ignored += 1
        elif sev == 1:
            note += 1
        elif sev == 2:
            warning += 1
        elif sev == 3:
            error += 1
        else:
            fatal += 1

    total = ignored + note + warning + error + fatal
    return TranslationUnitReport(
        translation_unit=str(src),
        parse_succeeded=tu is not None,
        retry_used=retry_used,
        diagnostic_ignored_count=ignored,
        diagnostic_note_count=note,
        diagnostic_warning_count=warning,
        diagnostic_error_count=error,
        diagnostic_fatal_count=fatal,
        total_diagnostic_count=total,
        had_errors=bool(parse_failure or error or fatal),
        parse_failure=parse_failure,
    )


def _row_identity(row: Row) -> str:
    key = (row.function_key or "").strip()
    if key and key != "<unknown>":
        return key
    return f"{row.function}@{row.function_loc or '-'}"


def _merge_rows(existing: Row, incoming: Row) -> None:
    existing.api_called = _join_api_names([
        *_split_api_names(existing.api_called),
        *_split_api_names(incoming.api_called),
    ])
    existing.total_target_calls = max(existing.total_target_calls, incoming.total_target_calls)

    existing_hits = set(existing.hit_locs or [])
    existing_hits.update(incoming.hit_locs or [])
    existing.hit_locs = sorted(existing_hits)

    existing.derived_from_params = bool(existing.derived_from_params or incoming.derived_from_params)

    dt = set(existing.derivation_trace or [])
    dt.update(incoming.derivation_trace or [])
    existing.derivation_trace = sorted(dt)

    existing.per_path_single = bool(existing.per_path_single and incoming.per_path_single)
    existing.pair_used = bool(existing.pair_used or incoming.pair_used)
    existing.via_helper_hop = bool(existing.via_helper_hop or incoming.via_helper_hop)

    ih = set(existing.ignored_helpers or [])
    ih.update(incoming.ignored_helpers or [])
    existing.ignored_helpers = sorted(ih)

    if (not existing.family or existing.family == "-") and incoming.family and incoming.family != "-":
        existing.family = incoming.family
    existing.is_thin_alias = bool(existing.is_thin_alias or incoming.is_thin_alias)

    if existing.reason in ("-", "n/a", "N/A", "") and incoming.reason not in ("", "-", "n/a", "N/A"):
        existing.reason = incoming.reason

    if existing.arg_pass in ("", "-", "N/A") and incoming.arg_pass not in ("", "-"):
        existing.arg_pass = incoming.arg_pass
    if existing.ret_pass in ("", "-", "N/A") and incoming.ret_pass not in ("", "-"):
        existing.ret_pass = incoming.ret_pass

    if existing.category in ("unknown", "N/A", "") and incoming.category not in ("", "unknown"):
        existing.category = incoming.category

    if (existing.file in ("", "-") and incoming.file) or (existing.function_loc in ("", "-") and incoming.function_loc):
        if incoming.file:
            existing.file = incoming.file
        if incoming.function_loc:
            existing.function_loc = incoming.function_loc


def _select_category_from_api_called(api_called: str, catalog: ApiCatalog, default_category: str = "unknown") -> str:
    apis = _split_api_names(api_called)
    if not apis:
        return default_category

    counts: Dict[str, int] = defaultdict(int)
    first_idx: Dict[str, int] = {}
    for i, api in enumerate(apis):
        cat = catalog.category_of(api)
        counts[cat] += 1
        if cat not in first_idx:
            first_idx[cat] = i

    if not counts:
        return default_category

    best_n = max(counts.values())
    winners = [cat for cat, n in counts.items() if n == best_n]
    if len(winners) == 1:
        return winners[0]

    winners.sort(key=lambda cat: first_idx.get(cat, 10**9))
    return winners[0] if winners else default_category


def _parse_translation_unit(
    src: Path,
    clang_args: List[str],
    verbose: bool = False,
    debug_preprocess: bool = False,
) -> tuple[Optional[cindex.TranslationUnit], TranslationUnitReport]:
    index = cindex.Index.create()
    try:
        t0 = time.time()
        tu = index.parse(
            str(src),
            args=clang_args,
            options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
        )
        t1 = time.time()
        if verbose:
            eprint(f"[parsed] {src} in {t1 - t0:.2f}s")
            for d in getattr(tu, "diagnostics", []) or []:
                try:
                    eprint(f"[diag] sev={d.severity} loc={d.location} msg={d.spelling}")
                except Exception:
                    pass
        return tu, _build_translation_unit_report(src, tu, retry_used=False)
    except cindex.TranslationUnitLoadError as e:
        if verbose:
            eprint(f"[warn] initial parse failed for {src}: {e}")
            eprint("[warn] retrying with cleaned flags...")

        cleaned = compile_commands.make_retry_clang_args(clang_args)

        try:
            tu = index.parse(
                str(src),
                args=cleaned,
                options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
            )
            if verbose:
                eprint(f"[parsed:retry] {src}")
            return tu, _build_translation_unit_report(src, tu, retry_used=True)
        except cindex.TranslationUnitLoadError as e2:
            eprint(f"[error] libclang failed to parse {src}")
            eprint(f"  original args={clang_args}")
            eprint(f"  cleaned  args={cleaned}")
            eprint(f"  {e2}")
            if debug_preprocess:
                try:
                    clang_bin = _locate_clang_binary()
                    if not clang_bin:
                        eprint("[debug-preprocess] clang binary not found (none of CLANG_BIN/clang/clang-20). Install clang or set CLANG_BIN to the clang path.")
                    else:
                        cmd = [clang_bin, "-E", "-x", "c"]
                        for tok in cleaned:
                            if isinstance(tok, str) and (tok == "-working-directory" or tok.startswith("-working-directory")):
                                continue
                            cmd.append(tok)

                        cmd.append(str(src))

                        cwd = str(Path(src).parent)
                        eprint(f"[debug-preprocess] running: {' '.join(shlex.quote(x) for x in cmd)}  (cwd={cwd})")
                        try:
                            if not Path(cwd).exists():
                                raise FileNotFoundError(cwd)
                            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
                        except FileNotFoundError:
                            eprint(f"[debug-preprocess] warning: TU working-directory does not exist: {cwd}. Falling back to no-cwd run.")
                            proc = subprocess.run(cmd, capture_output=True, text=True)
                        if proc.stdout:
                            eprint("[debug-preprocess] stdout:\n" + proc.stdout)
                        if proc.stderr:
                            eprint("[debug-preprocess] stderr:\n" + proc.stderr)
                except Exception as _e:
                    eprint(f"[debug-preprocess] failed to run clang -E: {_e}")
            return None, _build_translation_unit_report(src, None, retry_used=True, parse_failure=str(e2))


def run_finder(args) -> Optional[Path]:
    provided_args = _parse_args_provided()

    compile_commands.PATH_MAPS = []
    if getattr(args, "path_map", None):
        for pm in args.path_map:
            if "=" in pm:
                old, new = pm.split("=", 1)
                compile_commands.PATH_MAPS.append((old, new))
            else:
                eprint(f"[warn] --path-map ignored (invalid): {pm}")

    if not hasattr(args, "mode"):
        args.mode = "all"
    if not hasattr(args, "output"):
        args.output = "csv"
    if not hasattr(args, "out"):
        args.out = "-"
    if not hasattr(args, "yaml"):
        args.yaml = None
    if not hasattr(args, "only_libc"):
        args.only_libc = False
    if not hasattr(args, "only_syscalls"):
        args.only_syscalls = False

    _apply_out_dir(args)

    if getattr(args, "callgraph_only", False) and getattr(args, "edge_evidence", None):
        print("error: --callgraph-only and --edge-evidence cannot be combined.", file=sys.stderr)
        raise SystemExit(1)

    if getattr(args, "callgraph_only", False):
        bad = []
        if "yaml" in provided_args:
            bad.append("--yaml")
        if "only_libc" in provided_args:
            bad.append("--only-libc")
        if "only_syscalls" in provided_args:
            bad.append("--only-syscalls")
        if bad:
            print(f"error: --callgraph-only cannot be combined with: {', '.join(bad)}", file=sys.stderr)
            raise SystemExit(1)

        conflicting = [f for f in ("yaml", "mode", "output", "out", "only_libc", "only_syscalls") if f in provided_args]
        if conflicting:
            bad = ", ".join(f"--{f.replace('_','-')}" for f in conflicting)
            print(f"error: --callgraph-only cannot be combined with: {bad}", file=sys.stderr)
            raise SystemExit(1)
    else:
        if not is_stdout(args.out):
            prepare_output_location(args.out, prefer_dir=False)

    entries = compile_commands.load_compile_commands(Path(args.compile_commands))
    file_to_args = compile_commands.build_file_to_args_map(entries)

    project_roots: List[Path] = []
    filter_active: bool = False
    if hasattr(args, "project_root") and args.project_root:
        try:
            project_roots = [Path(p).resolve() for p in args.project_root]
        except Exception:
            project_roots = [Path(p) for p in args.project_root]
        filter_active = True
    elif os.environ.get("REPO_ROOT"):
        try:
            rr_env = os.environ.get("REPO_ROOT") or ""
            rr = Path(rr_env).resolve()
            if rr.exists():
                project_roots = [rr]
                filter_active = True
                if getattr(args, "verbose", False):
                    eprint(f"[project-only] using REPO_ROOT={rr}")
        except Exception:
            pass
    elif getattr(args, "project_only", False):
        filter_active = True
        try:
            if file_to_args:
                src_dirs = [str(Path(p).resolve().parent) for p in file_to_args.keys()]
                common = os.path.commonpath(src_dirs)
                if common and common not in ("/", "/home", "/Users"):
                    project_roots = [Path(common)]
                    if getattr(args, "verbose", False):
                        eprint(f"[project-only] inferred project root: {project_roots[0]}")
        except Exception:
            pass
    else:
        try:
            if file_to_args:
                src_dirs = [str(Path(p).resolve().parent) for p in file_to_args.keys()]
                common = os.path.commonpath(src_dirs)
                if common and common not in ("/", "/home", "/Users"):
                    project_roots = [Path(common)]
                    filter_active = True
                    if getattr(args, "verbose", False):
                        eprint(f"[project-scope] inferred project root: {project_roots[0]}")
        except Exception:
            pass

    if not filter_active:
        filter_active = True

    def _is_in_project(path_str: str) -> bool:
        try:
            rp = Path(path_str).resolve()
        except Exception:
            rp = Path(path_str)

        if project_roots:
            for root in project_roots:
                try:
                    rp.relative_to(root)
                    return True
                except Exception:
                    continue
            return False
        else:
            s = str(rp)
            sys_prefixes = (
                "/usr/include",
                "/usr/local/include",
                "/usr/lib/clang",
                "/usr/lib/gcc",
                "/lib/clang",
                "/opt/homebrew/include",
                "/opt/local/include",
            )
            for pref in sys_prefixes:
                if s == pref or s.startswith(pref + "/"):
                    return False
            if "/lib/clang/" in s or s.startswith("/usr/lib/llvm") or s.startswith("/usr/lib/llvm-"):
                return False
            repo_root_env = os.environ.get("REPO_ROOT")
            if repo_root_env:
                try:
                    rr = Path(repo_root_env).resolve()
                    try:
                        rp.relative_to(rr)
                        return True
                    except Exception:
                        return False
                except Exception:
                    pass
            return True

    # ============================
    # CALLGRAPH-ONLY EARLY RETURN
    # ============================
    if getattr(args, "callgraph_only", False) or getattr(args, "edge_evidence", None):
        callgraph_edges: list[DetailedEdge] = []
        function_defs_by_key: Dict[str, FunctionDef] = {}
        tu_reports: List[TranslationUnitReport] = []

        for src, clang_args in file_to_args.items():
            if getattr(args, "verbose", False):
                eprint(f"[callgraph] parsing {src}")

            tu, tu_report = _parse_translation_unit(
                src,
                clang_args,
                verbose=getattr(args, "verbose", False),
                debug_preprocess=getattr(args, "debug_preprocess", False),
            )
            tu_reports.append(tu_report)
            if tu is None:
                continue

            for fn_def in collect_function_defs_for_tu(tu):
                if filter_active and not _is_in_project(fn_def.file or str(src)):
                    continue
                function_defs_by_key.setdefault(fn_def.function_key, fn_def)

            edges_tu, _seen_tu = collect_callgraph_for_tu_detailed(tu, translation_unit=str(src))
            callgraph_edges.extend(edges_tu)

        if getattr(args, "callgraph_only", False):
            out_dir = Path(args.callgraph_out)
            write_callgraph(
                out_dir,
                callgraph_edges,
                unique_callers=getattr(args, "unique_callers", False),
                project_function_defs=function_defs_by_key.values(),
                tu_reports=tu_reports,
            )
            eprint(f"[summary] files={len(file_to_args)} edges={len(callgraph_edges)}")
            return None

        try:
            query_def = resolve_edge_query(str(args.edge_evidence), function_defs_by_key.values())
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)

        evidence_rows = build_edge_evidence_rows(query_def, callgraph_edges)
        out_path = Path(args.out)
        if args.output in {"csv", "json", "jsonl"} and out_path.exists() and out_path.is_dir():
            eprint(f"ERROR: --out points to a directory; provide a file path for {args.output}.")
            raise SystemExit(1)

        if args.output == "csv":
            write_edge_evidence_csv(evidence_rows, out_path)
        elif args.output == "json":
            write_edge_evidence_json(evidence_rows, out_path)
        elif args.output == "jsonl":
            write_edge_evidence_jsonl(evidence_rows, out_path)

        return out_path if not is_stdout(str(out_path)) else None

    # ============================
    # WRAPPER DETECTION PATH
    # ============================

    if not args.yaml:
        bundled_yaml = default_catalog_path()
        if bundled_yaml.is_file():
            args.yaml = str(bundled_yaml)
            if getattr(args, "verbose", False):
                eprint(f"[catalog] using bundled YAML: {args.yaml}")
        else:
            eprint("Error: --yaml is required unless --callgraph-only is specified.")
            raise SystemExit(1)

    catalog = load_api_catalog(Path(args.yaml))
    if not catalog.target_names:
        eprint(f"ERROR: No APIs loaded from {args.yaml}. Expected 'categories' (preferred) or legacy 'libc'/'syscalls'.")
        try:
            with open(args.yaml, "r", encoding="utf-8") as _f:
                dbg = yaml.safe_load(_f) or {}
            present = ", ".join(sorted(dbg.keys())) if isinstance(dbg, dict) else "(non-dict root)"
            eprint(f"Keys present: {present or '(none)'}")
        except Exception as _e:
            eprint(f"(Also failed to inspect YAML keys: {_e})")
        raise SystemExit(1)

    if args.only_libc and args.only_syscalls:
        eprint("ERROR: --only-libc and --only-syscalls cannot be used together.")
        raise SystemExit(1)
    if args.only_libc:
        if getattr(catalog, "categories", None):
            keep_targets: Set[str] = set()
            for cat, vals in catalog.categories.items():
                if cat != "system_calls":
                    keep_targets |= set(vals)
            catalog.target_names = keep_targets
        else:
            catalog.target_names = set(catalog.libc)
    elif args.only_syscalls:
        if getattr(catalog, "categories", None) and "system_calls" in catalog.categories:
            catalog.target_names = set(catalog.categories.get("system_calls", set()))
        else:
            catalog.target_names = set(catalog.syscalls)
    else:
        if getattr(catalog, "categories", None):
            all_union: Set[str] = set()
            for vals in catalog.categories.values():
                all_union |= set(vals)
            catalog.target_names = all_union
        else:
            catalog.target_names = set().union(catalog.libc, catalog.syscalls)

    rows: List[Row] = []
    rows_by_identity: Dict[str, Row] = {}
    all_edges: list[DetailedEdge] = []
    function_name_by_key: Dict[str, str] = {}
    project_function_defs_by_key: Dict[str, FunctionDef] = {}
    direct_targets_by_function: Dict[str, List[str]] = defaultdict(list)
    tu_reports: List[TranslationUnitReport] = []

    for src, clang_args in file_to_args.items():
        if getattr(args, "verbose", False):
            eprint(f"[processing] {src}")
            eprint(f"[debug] Clang args for {src}:")
            for a in clang_args:
                eprint(f"  {a}")

        tu, tu_report = _parse_translation_unit(
            src,
            clang_args,
            verbose=getattr(args, "verbose", False),
            debug_preprocess=getattr(args, "debug_preprocess", False),
        )
        tu_reports.append(tu_report)
        if tu is None:
            continue

        for cursor in tu.cursor.walk_preorder():
            if not _is_callable_definition(cursor):
                continue

            func_name = _caller_name(cursor)
            loc = cursor.location
            func_file = loc.file.name if (loc and loc.file) else str(src)
            func_loc = f"{func_file}:{loc.line}" if (loc and loc.file) else "-"

            if filter_active:
                try:
                    exp = cursor.extent.start.file
                    exp_path = exp.name if exp is not None else func_file
                except Exception:
                    exp_path = func_file
                if not _is_in_project(exp_path):
                    if getattr(args, "verbose", False):
                        eprint(f"[skip:out-of-project] {func_name} @ {exp_path}")
                    continue

            func_key = _function_key(cursor)
            function_name_by_key[func_key] = func_name
            project_function_defs_by_key.setdefault(
                func_key,
                FunctionDef(
                    function_key=func_key,
                    function=func_name,
                    file=str(Path(func_file).resolve()) if func_file not in ("", "-") else "",
                    line=int(getattr(loc, "line", 0) or 0),
                ),
            )

            try:
                for call_cur, _loc in collect_target_calls(cursor, catalog.target_names):
                    resolved_name = _resolve_target_name_for_call(call_cur, catalog)
                    if resolved_name and resolved_name in catalog.target_names:
                        direct_targets_by_function[func_key].append(resolved_name)
            except Exception:
                pass

            keep = False
            per_path_single = False
            total_hits = 0
            reason = "n/a"
            hit_locs: List[str] = []
            api_name: Optional[str] = None
            derived_ok = True
            deriv_trace: List[str] = []
            pair_used = False
            via_helper_hop = False
            ignored_helpers: List[str] = []

            legacy_map = {
                "perpath_relaxed": "relaxed",
                "single": "accurate",
                "perpath": "accurate",
                "perpath_strict_plus": "accurate",
            }
            mode_eff = legacy_map.get(args.mode, args.mode)

            if mode_eff == "relaxed":
                (keep,
                 per_path_single,
                 total_hits,
                 reason,
                 hit_locs,
                 api_name,
                 derived_ok,
                 deriv_trace,
                 pair_used,
                 via_helper_hop,
                 ignored_helpers) = analyze_wrapper_relaxed(cursor, catalog)

            elif mode_eff == "accurate":
                (keep,
                 per_path_single,
                 total_hits,
                 reason,
                 hit_locs,
                 api_name,
                 derived_ok,
                 deriv_trace,
                 pair_used,
                 via_helper_hop,
                 ignored_helpers) = analyze_wrapper_strict_plus(cursor, catalog, getattr(args, "treat_thin_alias", "default"))

            else:  # mode_eff == "all"
                hits = collect_target_calls(cursor, catalog.target_names)
                apis: List[str] = []
                hit_locs = []
                for call, loc in hits:
                    nm = _resolve_target_name_for_call(call, catalog)
                    if nm:
                        apis.append(nm)
                        hit_locs.append(loc)
                total_hits = len(apis)
                if total_hits > 0:
                    (keep,
                     per_path_single,
                     _th,
                     reason,
                     _hl,
                     api_name,
                     derived_ok,
                     deriv_trace,
                     pair_used,
                     via_helper_hop,
                     ignored_helpers) = analyze_wrapper_strict_plus(cursor, catalog, getattr(args, "treat_thin_alias", "default"))
                    if not api_name and apis:
                        api_name = apis[0]
                else:
                    keep = True
                    per_path_single = True
                    reason = "N/A"
                    api_name = None
                    derived_ok = False
                    deriv_trace = []
                    pair_used = False
                    via_helper_hop = False
                    ignored_helpers = []

            if mode_eff in ("relaxed", "accurate"):
                if (not keep) or (total_hits == 0) or (not api_name) or (api_name not in catalog.target_names):
                    continue

            r = Row(
                file=func_file,
                function=func_name,
                function_key=func_key,
                api_called=(api_name or "other") if mode_eff == "all" and not api_name else (api_name or ""),
                category=(catalog.category_of(api_name or "") if (api_name and api_name in catalog.target_names) else ("N/A" if (mode_eff == "all" and not api_name) else catalog.category_of(api_name or ""))),
                total_target_calls=total_hits,
                hit_locs=hit_locs,
                per_path_single=per_path_single,
                derived_from_params=derived_ok,
                derivation_trace=deriv_trace,
                reason=("N/A" if (mode_eff == "all" and not api_name) else (reason if reason != "n/a" else ("ok" if keep else "-"))),
                function_loc=func_loc,
                pair_used=pair_used,
                via_helper_hop=via_helper_hop,
                ignored_helpers=ignored_helpers or [],
                family=("thin_alias" if (api_name and api_name in (catalog.thin_aliases or set())) else "-"),
                is_thin_alias=bool(api_name and api_name in (catalog.thin_aliases or set())),
            )
            rid = _row_identity(r)
            if rid in rows_by_identity:
                _merge_rows(rows_by_identity[rid], r)
            else:
                rows_by_identity[rid] = r
                rows.append(r)
            try:
                if mode_eff == "all" and not api_name:
                    rows_by_identity[rid].arg_pass = "N/A"
                    rows_by_identity[rid].ret_pass = "N/A"
                else:
                    matching_calls: List[cindex.Cursor] = []
                    for call_cur, _loc in collect_target_calls(cursor, catalog.target_names):
                        resolved = _resolve_target_name_for_call(call_cur, catalog)
                        if resolved == api_name:
                            matching_calls.append(call_cur)
                    arg_pass, ret_pass = compute_arg_ret_pass_multi(cursor, matching_calls)
                    rows_by_identity[rid].arg_pass = arg_pass
                    rows_by_identity[rid].ret_pass = ret_pass
            except Exception:
                pass

        try:
            edges_tu, _seen_tu = collect_callgraph_for_tu_detailed(tu, translation_unit=str(src))
            all_edges.extend(edges_tu)
        except Exception:
            pass

    project_defs_by_key, project_keys_by_name = build_function_index(project_function_defs_by_key.values())
    callers_by_callee: Dict[str, Set[str]] = defaultdict(set)
    callees_by_caller: Dict[str, Set[str]] = defaultdict(set)

    for e in all_edges:
        raw_caller_key = str(getattr(e, "caller_key", None) or getattr(e, "caller", "") or "")
        raw_caller_name = str(getattr(e, "caller", "") or "")
        raw_callee_key = str(getattr(e, "callee_key", None) or getattr(e, "callee", "") or "")
        raw_callee_name = str(getattr(e, "callee", "") or "")

        caller_k, _caller_match = resolve_project_function_key(
            getattr(e, "caller_key", None),
            getattr(e, "caller", ""),
            project_defs_by_key,
            project_keys_by_name,
        )
        callee_k, _callee_match = resolve_project_function_key(
            getattr(e, "callee_key", None),
            getattr(e, "callee", ""),
            project_defs_by_key,
            project_keys_by_name,
        )
        caller_identity = caller_k or raw_caller_key or raw_caller_name
        callee_identity = callee_k or raw_callee_key or raw_callee_name

        if callee_k and caller_identity:
            callers_by_callee[callee_k].add(caller_identity)
        if caller_k and callee_identity:
            callees_by_caller[caller_k].add(callee_identity)

    traced_targets_by_function = _trace_reachable_target_apis(
        all_edges=all_edges,
        direct_targets_by_function=direct_targets_by_function,
        function_name_by_key=function_name_by_key,
    )
    reachable_callee_names_by_function = _trace_reachable_callee_names(all_edges, project_defs_by_key)

    for r in rows:
        row_key = r.function_key or ""
        traced = list(traced_targets_by_function.get(row_key, []))
        combined = [*_split_api_names(r.api_called), *traced]
        if combined:
            r.api_called = _join_api_names(combined)
            if r.total_target_calls <= 0:
                r.total_target_calls = len(_unique_in_order(combined))
            r.category = _select_category_from_api_called(r.api_called, catalog, r.category)

    for r in rows:
        key = r.function_key or r.function
        fin = len(callers_by_callee.get(key, set()))
        fout = len(callees_by_caller.get(key, set()))
        r.fan_in = fin
        r.fan_out = fout
        names = list(reachable_callee_names_by_function.get(key, []))
        r.callees = names

    if getattr(args, "callgraph_out", None):
        try:
            out_dir = Path(args.callgraph_out)
            write_callgraph(
                out_dir,
                all_edges,
                unique_callers=getattr(args, "unique_callers", False),
                project_function_defs=project_defs_by_key.values(),
                tu_reports=tu_reports,
            )
            if getattr(args, "verbose", False):
                eprint(f"[callgraph] wrote callgraph to {out_dir} (edges={len(all_edges)})")
        except Exception as _e:
            eprint(f"[callgraph][error] failed to write callgraph: {_e}")

    out_path = Path(args.out)
    if args.output in {"csv", "json", "jsonl"}:
        if out_path.exists() and out_path.is_dir():
            eprint(f"ERROR: --out points to a directory; provide a file path for {args.output}.")
            raise SystemExit(1)

    if args.output == "csv":
        write_rows_csv(rows, out_path, all_columns=getattr(args, "all_columns", False))
    elif args.output == "json":
        write_rows_json(rows, out_path)
    elif args.output == "jsonl":
        write_rows_jsonl(rows, out_path)

    try:
        files_processed = len(file_to_args)
        total_rows = len(rows)
        total_edges = len(all_edges)

        agg_counts: Dict[str, int] = defaultdict(int)
        agg_callers: Dict[str, Set[str]] = defaultdict(set)
        for e in all_edges:
            ck = getattr(e, "callee_key", None) or getattr(e, "callee", None) or "<unknown>"
            ak = getattr(e, "caller_key", None) or getattr(e, "caller", None) or "<unknown>"
            agg_counts[ck] += 1
            agg_callers[ck].add(ak)

        def top_n(d: Dict[str, int], n: int = 10):
            return sorted(d.items(), key=lambda x: (-x[1], x[0]))[:n]

        print("\n[summary] run metrics:")
        print(f"  files processed: {files_processed}")
        print(f"  wrapper rows:    {total_rows}")
        print(f"  callgraph edges: {total_edges}")

        print("  top callees by total_calls:")
        for k, v in top_n(agg_counts, 10):
            uniq = len(agg_callers.get(k, set()))
            print(f"    {k}: total_calls={v}, unique_callers={uniq}")

        if rows:
            by_fan_in = sorted(rows, key=lambda r: (-r.fan_in, r.function_key or r.function))[:10]
            by_fan_out = sorted(rows, key=lambda r: (-r.fan_out, r.function_key or r.function))[:10]
            print("  top wrapper candidates by fan_in:")
            for r in by_fan_in:
                print(f"    {r.function_key or r.function}: fan_in={r.fan_in}, fan_out={r.fan_out}, file={r.file}")
            print("  top wrapper candidates by fan_out:")
            for r in by_fan_out:
                print(f"    {r.function_key or r.function}: fan_out={r.fan_out}, fan_in={r.fan_in}, file={r.file}")
    except Exception:
        pass

    return out_path if not is_stdout(str(out_path)) else None
