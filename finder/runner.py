"""Runner for wrapper detection."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

from cwrappers.finder import compile_commands
from cwrappers.finder.analysis import collect_target_calls, _resolve_target_name_for_call
from cwrappers.finder.callgraph import collect_callgraph_for_tu_detailed, write_callgraph, DetailedEdge
from cwrappers.finder.catalog import ApiCatalog, load_api_catalog
from cwrappers.finder.clang_bootstrap import cindex, K, _locate_clang_binary
from cwrappers.finder.models import Row
from cwrappers.finder.output import is_stdout, prepare_output_location, write_rows_csv, write_rows_json, write_rows_jsonl
from cwrappers.finder.provenance import compute_arg_ret_pass_multi
from cwrappers.finder.wrapper_detection import analyze_wrapper_relaxed, analyze_wrapper_strict_plus
from cwrappers.finder.ast_utils import _function_key
from cwrappers.shared.log import eprint


def _default_output_name(fmt: str) -> str:
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
    default_name = _default_output_name(getattr(args, "output", "csv"))
    args.out = str(Path(out_dir) / default_name)


def _parse_args_provided() -> Set[str]:
    provided: Set[str] = set()
    for tok in sys.argv[1:]:
        if tok.startswith("--"):
            key = tok[2:].split("=")[0].replace("-", "_")
            provided.add(key)
    return provided


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
    if getattr(args, "callgraph_only", False):
        callgraph_edges: list[DetailedEdge] = []
        seen_global: set[str] = set()

        for src, clang_args in file_to_args.items():
            if getattr(args, "verbose", False):
                eprint(f"[callgraph] parsing {src}")

            index = cindex.Index.create()
            try:
                tu = index.parse(
                    str(src),
                    args=clang_args,
                    options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
                )
            except cindex.TranslationUnitLoadError as e:
                eprint(f"[callgraph][error] libclang failed to parse {src}: {e}")
                continue

            edges_tu, _seen_tu = collect_callgraph_for_tu_detailed(tu)

            for e in edges_tu:
                if e.loc not in seen_global:
                    seen_global.add(e.loc)
                    callgraph_edges.append(e)
        out_dir = Path(args.callgraph_out)
        write_callgraph(out_dir, callgraph_edges, unique_callers=getattr(args, "unique_callers", False))
        eprint(f"[summary] files={len(file_to_args)} edges={len(callgraph_edges)}")
        return None

    # ============================
    # WRAPPER DETECTION PATH
    # ============================

    if not args.yaml:
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
    all_edges: list[DetailedEdge] = []
    seen_keys: Set[Tuple[str, str, str]] = set()

    for src, clang_args in file_to_args.items():
        if getattr(args, "verbose", False):
            eprint(f"[processing] {src}")
            eprint(f"[debug] Clang args for {src}:")
            for a in clang_args:
                eprint(f"  {a}")

        index = cindex.Index.create()
        try:
            t0 = time.time()
            tu = index.parse(
                str(src),
                args=clang_args,
                options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
            )
            t1 = time.time()
            if getattr(args, "verbose", False):
                eprint(f"[parsed] {src} in {t1 - t0:.2f}s")
            if getattr(args, "verbose", False):
                for d in getattr(tu, "diagnostics", []) or []:
                    try:
                        eprint(f"[diag] sev={d.severity} loc={d.location} msg={d.spelling}")
                    except Exception:
                        pass

        except cindex.TranslationUnitLoadError as e:
            if getattr(args, "verbose", False):
                eprint(f"[warn] initial parse failed for {src}: {e}")
                eprint("[warn] retrying with cleaned flags...")

            cleaned: List[str] = []
            i = 0
            while i < len(clang_args):
                tok = clang_args[i]
                if tok in ("-o", "-MF", "-MT", "-MQ", "-MJ") and i + 1 < len(clang_args) and not clang_args[i+1].startswith("-"):
                    i += 2
                    continue
                cleaned.append(tok)
                i += 1

            try:
                tu = index.parse(
                    str(src),
                    args=cleaned,
                    options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
                )
                if getattr(args, "verbose", False):
                    eprint(f"[parsed:retry] {src}")
            except cindex.TranslationUnitLoadError as e2:
                eprint(f"[error] libclang failed to parse {src}")
                eprint(f"  original args={clang_args}")
                eprint(f"  cleaned  args={cleaned}")
                eprint(f"  {e2}")
                if getattr(args, "debug_preprocess", False):
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
                continue

        for cursor in tu.cursor.walk_preorder():
            if cursor.kind != K.FUNCTION_DECL or not cursor.is_definition():
                continue

            func_name = cursor.spelling
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

            dedup_key = (func_name, func_loc, api_name or "other")
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            func_key = _function_key(cursor)

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
            rows.append(r)
            try:
                if mode_eff == "all" and not api_name:
                    rows[-1].arg_pass = "N/A"
                    rows[-1].ret_pass = "N/A"
                else:
                    matching_calls: List[cindex.Cursor] = []
                    for call_cur, _loc in collect_target_calls(cursor, catalog.target_names):
                        resolved = _resolve_target_name_for_call(call_cur, catalog)
                        if resolved == api_name:
                            matching_calls.append(call_cur)
                    arg_pass, ret_pass = compute_arg_ret_pass_multi(cursor, matching_calls)
                    rows[-1].arg_pass = arg_pass
                    rows[-1].ret_pass = ret_pass
            except Exception:
                pass

        try:
            edges_tu, _seen_tu = collect_callgraph_for_tu_detailed(tu)
            all_edges.extend(edges_tu)
        except Exception:
            pass

    callers_by_callee: Dict[str, Set[str]] = defaultdict(set)
    callees_by_caller: Dict[str, Set[str]] = defaultdict(set)
    callee_names_by_caller_key: Dict[str, Set[str]] = defaultdict(set)
    unres_callers_by_callee_name: Dict[str, Set[str]] = defaultdict(set)
    unres_callees_by_caller_name: Dict[str, Set[str]] = defaultdict(set)

    for e in all_edges:
        caller_k = getattr(e, "caller_key", None) or getattr(e, "caller", "")
        callee_k = getattr(e, "callee_key", None) or getattr(e, "callee", "")
        callers_by_callee[str(callee_k)].add(str(caller_k))
        callees_by_caller[str(caller_k)].add(str(callee_k))
        callee_nm = getattr(e, "callee", "") or ""
        if callee_nm:
            callee_names_by_caller_key[str(caller_k)].add(callee_nm)

        if isinstance(callee_k, str) and callee_k.endswith("@<unknown>"):
            callee_nm = getattr(e, "callee", "") or ""
            caller_nm = getattr(e, "caller", "") or ""
            if callee_nm and caller_nm:
                unres_callers_by_callee_name[callee_nm].add(caller_nm)
        if isinstance(caller_k, str) and caller_k.endswith("@<unknown>"):
            caller_nm = getattr(e, "caller", "") or ""
            callee_nm = getattr(e, "callee", "") or ""
            if caller_nm and callee_nm:
                unres_callees_by_caller_name[caller_nm].add(callee_nm)

    name_frequency: Dict[str, int] = defaultdict(int)
    for r in rows:
        name_frequency[r.function] += 1

    for r in rows:
        key = r.function_key or r.function
        fin = len(callers_by_callee.get(key, set()))
        fout = len(callees_by_caller.get(key, set()))
        if fin == 0 and name_frequency.get(r.function, 0) == 1:
            fin = len(unres_callers_by_callee_name.get(r.function, set()))
        if fout == 0 and name_frequency.get(r.function, 0) == 1:
            fout = len(unres_callees_by_caller_name.get(r.function, set()))
        r.fan_in = fin
        r.fan_out = fout
        names = sorted(callee_names_by_caller_key.get(key, set()))
        if not names and name_frequency.get(r.function, 0) == 1:
            names = sorted(unres_callees_by_caller_name.get(r.function, set()))
        r.callees = names

    if getattr(args, "callgraph_out", None):
        try:
            out_dir = Path(args.callgraph_out)
            write_callgraph(out_dir, all_edges, unique_callers=getattr(args, "unique_callers", False))
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
