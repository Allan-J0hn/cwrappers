"""Unified CLI with finder, fuzzy, pipeline, and run commands."""

from __future__ import annotations

import sys
import tempfile
from typing import List, Optional

from cwrappers.finder import cli as finder_cli
from cwrappers.finder.runner import run_finder
from cwrappers.fuzzy import cli as fuzzy_cli
from cwrappers.fuzzy.io import process_csv

USAGE = """usage: cwrappers <finder|fuzzy|pipeline|run> [args...]

subcommands:
  finder    run wrapper detection
  fuzzy     run fuzzy post-processing on a finder CSV
  pipeline  run finder, then optional fuzzy scoring
    run       run finder, then fuzzy scoring (single command)

examples:
  cwrappers finder --compile-commands compile_commands.json --out wrappers.csv
  cwrappers fuzzy wrappers.csv
  cwrappers pipeline --compile-commands compile_commands.json --fuzzy
    cwrappers run --compile-commands compile_commands.json --out wrappers.csv
"""


def _find_flag_value(argv: List[str], flag: str) -> Optional[str]:
    for i, tok in enumerate(argv):
        if tok == flag and i + 1 < len(argv):
            return argv[i + 1]
        if tok.startswith(flag + "="):
            return tok.split("=", 1)[1]
    return None


def _has_flag(argv: List[str], flag: str) -> bool:
    return _find_flag_value(argv, flag) is not None


def _extract_pipeline_flags(argv: List[str]):
    fuzzy = False
    fuzzy_out: Optional[str] = None
    fuzzy_out_dir: Optional[str] = None
    fuzzy_top_k: Optional[int] = None

    remaining: List[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--fuzzy":
            fuzzy = True
            i += 1
            continue
        if tok.startswith("--fuzzy-out="):
            fuzzy_out = tok.split("=", 1)[1]
            i += 1
            continue
        if tok == "--fuzzy-out" and i + 1 < len(argv):
            fuzzy_out = argv[i + 1]
            i += 2
            continue
        if tok.startswith("--fuzzy-out-dir="):
            fuzzy_out_dir = tok.split("=", 1)[1]
            i += 1
            continue
        if tok == "--fuzzy-out-dir" and i + 1 < len(argv):
            fuzzy_out_dir = argv[i + 1]
            i += 2
            continue
        if tok.startswith("--fuzzy-top-k="):
            try:
                fuzzy_top_k = int(tok.split("=", 1)[1])
            except Exception:
                fuzzy_top_k = None
            i += 1
            continue
        if tok == "--fuzzy-top-k" and i + 1 < len(argv):
            try:
                fuzzy_top_k = int(argv[i + 1])
            except Exception:
                fuzzy_top_k = None
            i += 2
            continue
        remaining.append(tok)
        i += 1

    return fuzzy, fuzzy_out, fuzzy_out_dir, fuzzy_top_k, remaining


def _pipeline(argv: List[str]) -> int:
    fuzzy, fuzzy_out, fuzzy_out_dir, fuzzy_top_k, finder_argv = _extract_pipeline_flags(argv)

    if fuzzy:
        has_out = _has_flag(finder_argv, "--out") or _has_flag(finder_argv, "--out-dir")
        if not has_out:
            tmp = tempfile.NamedTemporaryFile(prefix="cwrappers_finder_", suffix=".csv", delete=False)
            tmp.close()
            finder_argv = finder_argv + ["--out", tmp.name]
        else:
            out_val = _find_flag_value(finder_argv, "--out")
            if out_val == "-":
                print("error: --fuzzy requires finder output to be a file (not stdout). Use --out or omit it.")
                return 2

    finder_args = finder_cli.parse_args(finder_argv)
    if fuzzy and getattr(finder_args, "edge_evidence", None):
        print("error: --fuzzy cannot be combined with --edge-evidence.")
        return 2
    if fuzzy and getattr(finder_args, "output", "csv") != "csv":
        print("error: --fuzzy requires finder --output csv.")
        return 2
    out_path = run_finder(finder_args)

    if not fuzzy:
        return 0

    if out_path is None:
        print("error: pipeline could not determine finder output path for fuzzy stage.")
        return 2

    yaml_path = getattr(finder_args, "yaml", None)
    try:
        process_csv(
            str(out_path),
            top_k=fuzzy_top_k or 3,
            yaml_path=yaml_path,
            out_path=fuzzy_out,
            out_dir=fuzzy_out_dir,
        )
    except Exception as e:
        print(f"error: {e}")
        return 1

    return 0


def _run(argv: List[str]) -> int:
    """Single-command wrapper run with optional fuzzy stage.

    Behavior:
    - default: finder + fuzzy
    - --fuzzy: force fuzzy on
    - --no-fuzzy: force fuzzy off
    """
    has_fuzzy = any(tok == "--fuzzy" for tok in argv)
    has_no_fuzzy = any(tok == "--no-fuzzy" for tok in argv)

    if has_fuzzy and has_no_fuzzy:
        print("error: --fuzzy and --no-fuzzy cannot be used together.")
        return 2

    # Default for run is fuzzy on unless explicitly disabled.
    if has_no_fuzzy:
        filtered = [tok for tok in argv if tok != "--no-fuzzy"]
        return _pipeline(filtered)

    if has_fuzzy:
        return _pipeline(list(argv))

    return _pipeline(["--fuzzy", *argv])


def main(argv: List[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    if argv and argv[0] in {"-h", "--help", "help"}:
        print(USAGE)
        return 0
    if not argv:
        print(USAGE)
        return 2

    cmd = argv[0]
    rest = argv[1:]

    if cmd == "finder":
        return finder_cli.main(rest)
    if cmd == "fuzzy":
        return fuzzy_cli.main(rest)
    if cmd == "pipeline":
        return _pipeline(rest)
    if cmd == "run":
        return _run(rest)

    print(f"unknown command: {cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
