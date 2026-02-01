"""Output helpers for finder results."""

from __future__ import annotations

import csv
import json
import re
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Iterable, List, Optional

from cwrappers.finder.models import Row
from cwrappers.shared.log import eprint


def is_stdout(path_str: Optional[str]) -> bool:
    return (path_str is None) or (path_str == "-")


def prepare_output_location(path_str: str, prefer_dir: bool = False) -> Path:
    """Ensure the correct directory exists for the given output path."""
    p = Path(path_str)
    if p.exists():
        if p.is_dir():
            return p
        return p

    looks_like_file = p.suffix not in ("", None)
    if looks_like_file and not prefer_dir:
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    p.mkdir(parents=True, exist_ok=True)
    return p


def serialize_hit_locs(hit_locs: Optional[List[str]]) -> str:
    """Encode hit_locs into a delimiter-safe string for CSV consumers."""
    if not hit_locs:
        return ""
    out = []
    for s in hit_locs:
        try:
            ss = str(s).strip()
            ss = re.sub(r"[\s,;]+", "_", ss)
            out.append(ss)
        except Exception:
            out.append(str(s))
    return "|".join(out)


def write_rows_csv(rows: Iterable[Row], out_path: Path, all_columns: bool = False) -> None:
    if str(out_path) == "-":
        w = csv.writer(sys.stdout, quoting=csv.QUOTE_MINIMAL)
        _write_csv_rows(w, rows, all_columns)
        return

    with open(out_path, "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        _write_csv_rows(w, rows, all_columns)


def _write_csv_rows(w: csv.writer, rows: Iterable[Row], all_columns: bool) -> None:
    if all_columns:
        w.writerow([
            "file","function","function_key","api_called","category","total_target_calls",
            "hit_locs","per_path_single","derived_from_params",
            "derivation_trace","arg_pass","ret_pass","reason","function_loc",
            "pair_used","via_helper_hop","ignored_helpers","fan_in","fan_out",
            "family","is_thin_alias","callee"
        ])
        for r in rows:
            w.writerow([
                r.file, r.function, r.function_key or "", r.api_called, r.category, r.total_target_calls,
                serialize_hit_locs(r.hit_locs),
                "TRUE" if r.per_path_single else "FALSE",
                "TRUE" if r.derived_from_params else "FALSE",
                ";".join(r.derivation_trace or []),
                r.arg_pass,
                r.ret_pass,
                r.reason or "-",
                r.function_loc or "-",
                "TRUE" if getattr(r, "pair_used", False) else "FALSE",
                "TRUE" if getattr(r, "via_helper_hop", False) else "FALSE",
                ";".join(getattr(r, "ignored_helpers", []) or []),
                r.fan_in,
                r.fan_out,
                r.family,
                "TRUE" if getattr(r, "is_thin_alias", False) else "FALSE",
                " - ".join(r.callees or []),
            ])
    else:
        w.writerow(["file","function","api_called","category","fan_in","fan_out","callee","hit_locs","arg_pass","ret_pass","reason"])
        for r in rows:
            w.writerow([
                r.file,
                r.function,
                r.api_called,
                r.category,
                r.fan_in,
                r.fan_out,
                " - ".join(r.callees or []),
                serialize_hit_locs(r.hit_locs),
                r.arg_pass,
                r.ret_pass,
                r.reason or "-",
            ])


def write_rows_json(rows: Iterable[Row], out_path: Path) -> None:
    if str(out_path) == "-":
        import sys
        json.dump([asdict(r) for r in rows], sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in rows], f, ensure_ascii=False, indent=2)


def write_rows_jsonl(rows: Iterable[Row], out_path: Path) -> None:
    if str(out_path) == "-":
        import sys
        for r in rows:
            json.dump(asdict(r), sys.stdout, ensure_ascii=False)
            sys.stdout.write("\n")
        return

    with open(out_path, "w", encoding="utf-8") as f:
        for r in rows:
            json.dump(asdict(r), f, ensure_ascii=False)
            f.write("\n")
