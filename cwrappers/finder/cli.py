"""CLI for wrapper finder."""

from __future__ import annotations

import argparse
from typing import List

from cwrappers.finder.runner import run_finder


def parse_args(argv: List[str] | None = None):
    parser = argparse.ArgumentParser(description="Find libc/syscall wrapper candidates")
    parser.add_argument(
        "--compile-commands",
        type=str,
        required=True,
        help="Path to compile_commands.json (or equivalent).",
    )
    parser.add_argument(
        "--yaml",
        type=str,
        default=None,
        required=False,
        help=(
            "Path to API catalog YAML. If omitted, uses bundled catalog "
            "(cwrappers/data/categorized_methods.yaml)."
        ),
    )
    parser.add_argument(
        "--only-libc",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Restrict target set to libc functions only.",
    )
    parser.add_argument(
        "--only-syscalls",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Restrict target set to system calls only.",
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=[
            "relaxed",
            "accurate",
            "all",
            "single",
            "perpath",
            "perpath_relaxed",
            "perpath_strict_plus",
        ],
        default="all",
        help=(
            "Mode: 'relaxed' (broader, higher recall), 'accurate' (low-FP), or 'all' (include every function; "
            "mark functions that don't call YAML APIs with 'other' and set dependent columns to 'N/A'). "
            "Legacy aliases accepted but deprecated."
        ),
    )
    parser.add_argument(
        "--output",
        type=str,
        choices=["csv", "json", "jsonl"],
        default="csv",
        help="Output format.",
    )
    parser.add_argument(
        "--out",
        type=str,
        required=False,
        default="-",
        help="Output file path (for csv/json) or directory if your code expects one.",
    )
    parser.add_argument(
        "--out-dir",
        type=str,
        required=False,
        default=None,
        help="Directory to place output file (overrides --out if provided).",
    )
    parser.add_argument(
        "-j",
        type=int,
        default=1,
        help="Number of processes (1 = no multiprocessing).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    parser.add_argument(
        "--callgraph-out",
        type=str,
        required=False,
        default=None,
        help=("Directory to write call graph files (callgraph_edges.csv, call_counts.csv). "
              "Required when using --callgraph-only."),
    )
    parser.add_argument(
        "--callgraph-only",
        action="store_true",
        help="Only build and write call graph CSVs; ignores wrapper-detection flags.",
    )
    parser.add_argument(
        "--unique-callers",
        action="store_true",
        help=("When writing call_counts.csv, also compute unique-caller counts (number of distinct caller functions per callee). "
              "If not set, call_counts.csv contains callsite-counts (unique call-sites)."),
    )
    parser.add_argument(
        "--debug-preprocess",
        action="store_true",
        help="On parse failure, run 'clang -E' with the sanitized args and print preprocessor diagnostics to stderr.",
    )
    parser.add_argument(
        "--path-map",
        action="append",
        help=("Optional mapping to rewrite compile_commands paths when entries were generated in a different checkout. "
              "Format: OLD_PREFIX=NEW_PREFIX. Can be repeated."),
    )
    parser.add_argument(
        "--all-columns",
        action="store_true",
        default=False,
        help=(
            "Output all available CSV columns. By default, a minimal set is written: "
            "file,function,api_called,hit_locs,fan_in,fan_out,reason."
        ),
    )
    parser.add_argument(
        "--project-root",
        action="append",
        default=argparse.SUPPRESS,
        help=(
            "Project root directory. Can be repeated to allow multiple roots. "
            "When provided, functions defined outside these roots are excluded from wrapper results."
        ),
    )
    parser.add_argument(
        "--project-only",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Exclude functions defined outside the project roots. If --project-root is not provided, "
            "a conservative system-include filter is applied (e.g., /usr/include)."
        ),
    )
    parser.add_argument(
        "--treat-thin-alias",
        type=str,
        choices=["default", "direct-only", "allow-1-hop"],
        default="default",
        help=(
            "Accurate-mode policy for categories.thin_alias APIs: "
            "default/direct-only requires a direct call (reject if only via helper); "
            "allow-1-hop permits exactly one helper hop but rejects deeper chains."
        ),
    )

    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv)
    run_finder(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
