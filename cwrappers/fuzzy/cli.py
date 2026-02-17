"""CLI for fuzzy scoring."""

from __future__ import annotations

import argparse
import os
from typing import List

from cwrappers.fuzzy.io import process_csv


def parse_args(argv: List[str] | None = None):
    parser = argparse.ArgumentParser(description="Fuzzy-only scoring of wrapper function names against YAML-sourced API names.")
    parser.add_argument("input_csv", type=str, help="Path to CSV produced by wrapper finder.")
    parser.add_argument(
        "--yaml",
        type=str,
        default=None,
        help=(
            "YAML catalog path (optional). If omitted, uses bundled catalog "
            "(cwrappers/data/categorized_methods.yaml)."
        ),
    )
    parser.add_argument("--out", type=str, default=None, help="Output CSV path.")
    parser.add_argument("--out-dir", type=str, default=None, help="Output directory for CSV.")
    parser.add_argument("--top-k", type=int, default=3, help="Top-k fuzzy matches to consider.")
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv)
    inp = args.input_csv
    if not os.path.isfile(inp):
        print(f"error: not a file: {inp}")
        return 2
    try:
        process_csv(inp, top_k=args.top_k, yaml_path=args.yaml, out_path=args.out, out_dir=args.out_dir)
        return 0
    except Exception as e:
        print(f"error: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
