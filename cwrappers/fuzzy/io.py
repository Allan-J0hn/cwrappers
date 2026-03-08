"""CSV I/O for fuzzy scoring."""

from __future__ import annotations

import csv
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from cwrappers.fuzzy.canon import build_canon_sets
from cwrappers.fuzzy.scoring import (
    MatchScore,
    best_strong_api_called_match,
    has_traced_catalog_api,
    is_strong_fuzzy_without_api,
    top_k_scores,
    wrapper_score,
)
from cwrappers.finder.catalog import load_api_catalog


def detect_cols(header: List[str]) -> Dict[str, Optional[int]]:
    """Detect indices for columns we use."""
    def norm_header(h: str) -> str:
        if h is None:
            return ""
        h = h.lstrip("\ufeff").strip().lower()
        h = h.replace("-", "_").replace(" ", "_")
        h = re.sub(r"_+", "_", h)
        return h

    names = [h.strip() if isinstance(h, str) else "" for h in header]
    lower = [norm_header(h) for h in names]

    def find_one(options: List[str]) -> Optional[int]:
        for i, h in enumerate(lower):
            if h in options:
                return i
        return None

    def first_not_none(*vals: Optional[int]) -> Optional[int]:
        for v in vals:
            if v is not None:
                return v
        return None

    func_idx = find_one(["function", "func", "symbol"])
    function_loc_idx = find_one(["function_loc", "functionloc", "function_location"])
    file_idx = first_not_none(
        find_one(["file", "filepath", "path", "filename", "source", "source_file", "location"]),
        function_loc_idx,
    )
    fan_in_idx = first_not_none(
        find_one(["fan_in", "fanin"]),
        find_one(["fan-in"]),
    )
    fan_out_idx = first_not_none(
        find_one(["fan_out", "fanout"]),
        find_one(["fan-out"]),
    )
    callee_idx = find_one(["callee"])
    api_called_idx = find_one(["api_called", "api", "target", "called_api"])
    category_idx = find_one(["category", "cat", "group"])
    reason_idx = find_one(["reason"])
    arg_pass_idx = find_one(["arg_pass", "argpass", "arg_passed", "args_pass"])
    ret_pass_idx = find_one(["ret_pass", "retpass", "return_pass", "ret_passed"])

    return {
        "function": func_idx,
        "file": file_idx,
        "function_loc": function_loc_idx,
        "fan_in": fan_in_idx,
        "fan_out": fan_out_idx,
        "callee": callee_idx,
        "api_called": api_called_idx,
        "category": category_idx,
        "reason": reason_idx,
        "arg_pass": arg_pass_idx,
        "ret_pass": ret_pass_idx,
    }


def _reason_score(reason: str) -> float:
    return 0.0


def output_path(inp: str, out_path: Optional[str] = None, out_dir: Optional[str] = None) -> str:
    if out_path:
        return out_path
    in_filename = os.path.splitext(os.path.basename(inp))[0]
    out_filename = f"{in_filename}._fuzzy_scored.csv"
    if out_dir:
        return os.path.join(out_dir, out_filename)
    return os.path.join(os.path.dirname(os.path.abspath(inp)), out_filename)


def _is_na_category(value: str) -> bool:
    v = (value or "").strip().lower()
    return v in {"", "n/a", "na", "none", "-"}


def _load_catalog_with_fallback(yaml_path: Optional[str]):
    candidates: List[str] = []
    if yaml_path:
        candidates.append(yaml_path)
    try:
        from cwrappers.shared.paths import default_catalog_path
        candidates.append(str(default_catalog_path()))
    except Exception:
        pass

    candidates.extend([
        os.path.join(os.getcwd(), "categorized_methods.yaml"),
        os.path.join(os.getcwd(), "methods.yaml"),
        os.path.join(os.getcwd(), "Data", "methods.yaml"),
        os.path.join(os.getcwd(), "Data", "resources_methods.yaml"),
    ])

    seen = set()
    for p in candidates:
        if not p or p in seen:
            continue
        seen.add(p)
        try:
            from pathlib import Path
            pp = Path(p)
            if not pp.is_file():
                continue
            return load_api_catalog(pp)
        except Exception:
            continue
    return None


def _fan_in_high_threshold(raw_rows: List[Dict[str, Any]]) -> int:
    fan_vals = sorted(max(0, int(r.get("fan_in", 0))) for r in raw_rows)
    if not fan_vals:
        return 0
    q_idx = int(0.7 * (len(fan_vals) - 1))
    return max(1, fan_vals[q_idx])


def process_csv(inp_path: str,
                top_k: int = 3,
                yaml_path: Optional[str] = None,
                out_path: Optional[str] = None,
                out_dir: Optional[str] = None) -> str:
    canon_sets = build_canon_sets(yaml_path)
    catalog = _load_catalog_with_fallback(yaml_path)
    out_path = output_path(inp_path, out_path=out_path, out_dir=out_dir)

    with open(inp_path, "r", newline="", encoding="utf-8") as f_in, \
         open(out_path, "w", newline="", encoding="utf-8") as f_out:
        rdr = csv.reader(f_in)
        w = csv.writer(f_out)

        header = next(rdr, None)
        if not header:
            raise ValueError("empty CSV (no header)")

        idx = detect_cols(header)
        func_idx = idx["function"]
        file_idx = idx["file"]
        function_loc_idx = idx["function_loc"]
        fan_in_idx = idx["fan_in"]
        fan_out_idx = idx["fan_out"]
        callee_idx = idx["callee"]
        api_called_idx = idx["api_called"]
        category_idx = idx["category"]
        reason_idx = idx["reason"]
        arg_pass_idx = idx["arg_pass"]
        ret_pass_idx = idx["ret_pass"]

        if func_idx is None:
            raise ValueError("could not detect 'function' column")

        raw: List[Dict[str, Any]] = []
        for row in rdr:
            fn = row[func_idx] if (func_idx is not None and func_idx < len(row)) else ""
            loc_str = ""
            has_file = file_idx is not None and file_idx < len(row) and bool(row[file_idx])
            if has_file:
                loc_str = str(row[file_idx]).strip()
            else:
                has_func_loc = function_loc_idx is not None and function_loc_idx < len(row) and bool(row[function_loc_idx])
                if has_func_loc:
                    loc_str = str(row[function_loc_idx]).strip()
            if not loc_str or loc_str.lower() in {"none", "null", "n/a", "na", "-"}:
                loc_str = "<unknown>"
            callee = row[callee_idx] if (callee_idx is not None and callee_idx < len(row)) else ""
            category = row[category_idx] if (category_idx is not None and category_idx < len(row)) else ""
            api_called = row[api_called_idx] if (api_called_idx is not None and api_called_idx < len(row)) else ""
            reason = row[reason_idx] if (reason_idx is not None and reason_idx < len(row)) else ""
            arg_pass = row[arg_pass_idx] if (arg_pass_idx is not None and arg_pass_idx < len(row)) else ""
            ret_pass = row[ret_pass_idx] if (ret_pass_idx is not None and ret_pass_idx < len(row)) else ""
            fan_in = 0
            fan_out = 0
            if fan_in_idx is not None and fan_in_idx < len(row):
                try:
                    fan_in = int(str(row[fan_in_idx]).strip())
                except Exception:
                    fan_in = 0
            if fan_out_idx is not None and fan_out_idx < len(row):
                try:
                    fan_out = int(str(row[fan_out_idx]).strip())
                except Exception:
                    fan_out = 0

            raw.append({
                "location": loc_str,
                "function": fn,
                "category": category,
                "fan_in": fan_in,
                "fan_out": fan_out,
                "callee": callee,
                "api_called": api_called,
                "reason": reason,
                "arg_pass": arg_pass,
                "ret_pass": ret_pass,
            })

        fan_in_high = _fan_in_high_threshold(raw)
        out_rows: List[Tuple[Tuple[int, int, float, str], List[object]]] = []
        for r in raw:
            scores = top_k_scores(r["function"], canon_sets, k=top_k)
            if not scores:
                scores = [MatchScore(key="", best_match="", exact=False, token_equal=False, lcs_len=0, combined=0.0, rf_score=0.0)]
            best = scores[0]

            category_out = r["category"]
            if catalog is not None:
                matched_api = best_strong_api_called_match(r["function"], r.get("api_called", ""))
                if matched_api:
                    mapped = catalog.category_of(matched_api)
                    if mapped and mapped != "unknown":
                        category_out = mapped
                elif _is_na_category(category_out) and best.key:
                    mapped = catalog.category_of(best.key)
                    if mapped and mapped != "unknown":
                        category_out = mapped

            wscore = wrapper_score(
                function=r["function"],
                api_called=r["api_called"],
                callee_field=r["callee"],
                fan_out=r["fan_out"],
                fuzzy_key=best.key,
                fuzzy_combined=best.combined,
                fuzzy_rf_score=best.rf_score,
                category=category_out,
                reason=r.get("reason", ""),
                arg_pass=r.get("arg_pass", ""),
                ret_pass=r.get("ret_pass", ""),
            )

            fuzzy_match_out = best.key
            if (not has_traced_catalog_api(r["api_called"], category_out)) and (
                not is_strong_fuzzy_without_api(r["function"], best.key, best.combined, best.rf_score)
            ):
                fuzzy_match_out = "NO_MATCH"

            out_row = [
                f"{int(round(wscore * 100))}%",
                r["function"],
                r["api_called"],
                fuzzy_match_out,
                category_out,
                r["fan_in"],
                r["callee"],
                r.get("arg_pass", ""),
                r.get("ret_pass", ""),
                r["location"],
            ]
            fan_in_val = r["fan_in"]
            good_score = wscore >= 0.50
            high_fan = fan_in_val >= fan_in_high

            # Tiering rule (best to worst):
            #   0: >=50% score and high fan-in
            #   1: >=50% score
            #   2: high fan-in
            #   3: everyone else
            if good_score and high_fan:
                tier = 0
            elif good_score:
                tier = 1
            elif high_fan:
                tier = 2
            else:
                tier = 3

            sort_key = (tier, -fan_in_val, -wscore, str(r["function"]))
            out_rows.append((sort_key, out_row))

        out_rows.sort(key=lambda t: t[0])

        out_header = [
            "likelihood_score", "function", "api_called", "fuzzy_match", "category", "fan_in", "callee", "arg_pass", "ret_pass", "location",
        ]
        w.writerow(out_header)
        for _, values in out_rows:
            w.writerow(values)

    print(f"[ok] processed: {inp_path}")
    print(f"[ok] wrote:      {out_path}")
    return out_path
