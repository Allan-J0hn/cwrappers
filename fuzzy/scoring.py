"""Scoring logic for fuzzy wrapper likelihood."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Set

try:
    from rapidfuzz import fuzz as rf_fuzz, process as rf_process  # type: ignore
except Exception:
    rf_fuzz = None  # type: ignore
    rf_process = None  # type: ignore

from cwrappers.fuzzy.canon import CanonSet
from cwrappers.fuzzy.normalize import normalize, strip_affixes, tokenize


@dataclass
class MatchScore:
    key: str
    best_match: str
    exact: bool
    token_equal: bool
    lcs_len: int
    combined: float
    rf_score: float


def _lcs_str_len(a: str, b: str) -> int:
    """Length of longest common substring (contiguous)."""
    if not a or not b:
        return 0
    m, n = len(a), len(b)
    dp = [0] * (n + 1)
    best = 0
    for i in range(1, m + 1):
        prev = 0
        for j in range(1, n + 1):
            tmp = dp[j]
            if a[i - 1] == b[j - 1]:
                dp[j] = prev + 1
                if dp[j] > best:
                    best = dp[j]
            else:
                dp[j] = 0
            prev = tmp
    return best


def score_against_canon(fn_tokens: List[str], fn_norm: str, cs: CanonSet) -> MatchScore:
    best_lcs = 0
    best_ratio = 0.0
    cand = cs.candidates[0] if cs.candidates else ""
    exact = fn_norm == cand
    token_equal = set(fn_tokens) == set(cand.split()) if fn_tokens and cand else False
    for t in fn_tokens or [fn_norm]:
        lcs = _lcs_str_len(t, cand)
        if lcs > best_lcs:
            best_lcs = lcs
            best_ratio = max(lcs / max(1, len(t)), lcs / max(1, len(cand)))
    combined = 100.0 if exact else max(0.0, min(100.0, 100.0 * best_ratio))
    rf_score = combined
    if rf_fuzz and fn_norm and cand:
        try:
            wratio = float(rf_fuzz.WRatio(fn_norm, cand))
            token_ratio = float(rf_fuzz.token_set_ratio(fn_norm, cand))
            rf_score = max(wratio, token_ratio)
        except Exception:
            rf_score = combined
    return MatchScore(key=cs.key, best_match=cand, exact=exact, token_equal=token_equal, lcs_len=best_lcs, combined=combined, rf_score=rf_score)


def top_k_scores(fn_name: str, canon_sets: List[CanonSet], k: int = 3) -> List[MatchScore]:
    fn_stripped = strip_affixes(fn_name)
    fn_tokens = tokenize(fn_stripped)
    fn_norm = normalize(fn_stripped)
    scores = [score_against_canon(fn_tokens, fn_norm, cs) for cs in canon_sets]
    scores = [s for s in scores if s.lcs_len >= 3 or s.exact]
    if not scores:
        return []
    scores.sort(key=lambda m: (
        -m.rf_score,
        0 if m.exact else 1,
        0 if m.token_equal else 1,
        -m.lcs_len,
        -m.combined,
        m.key,
    ))
    return scores[:k]


def _split_callees(callee_field: str) -> List[str]:
    if not callee_field:
        return []
    s = callee_field.strip()
    if not s:
        return []
    s = s.replace(" - ", "|")
    parts = re.split(r"[|;,\s]+", s)
    parts = [p.strip() for p in parts]
    return [p for p in parts if p]


def wrapper_score(function: str,
                  api_called: str,
                  callee_field: str,
                  fan_out: int,
                  fuzzy_key: str,
                  fuzzy_combined: float,
                  category: str = "",
                  reason: str = "",
                  arg_pass: str = "",
                  ret_pass: str = "") -> float:
    fn_stripped = strip_affixes(function)
    fn_norm = normalize(fn_stripped)
    fn_tokens = set(tokenize(fn_stripped))

    fuzzy_norm = normalize(fuzzy_key)
    api_called_norm = normalize(api_called)
    category_norm = normalize(category)
    catalog_blacklist = {"", "other"}
    category_blacklist = {"", "n/a", "na", "none"}
    api_from_catalog = (
        bool(api_called_norm) and api_called_norm not in catalog_blacklist and category_norm not in category_blacklist
    )

    api_token_source = api_called if api_from_catalog else fuzzy_key
    api_norm = normalize(api_token_source)
    api_tokens = tokenize(api_norm)

    api_alignment = 0.0
    if api_from_catalog and api_norm and fuzzy_norm:
        if api_norm == fuzzy_norm:
            api_alignment = 100.0
        elif rf_fuzz:
            try:
                api_alignment = max(
                    float(rf_fuzz.WRatio(api_norm, fuzzy_norm)),
                    float(rf_fuzz.token_set_ratio(api_norm, fuzzy_norm)),
                )
            except Exception:
                api_alignment = 0.0

    callees = _split_callees(callee_field)
    callee_norms = [normalize(c) for c in callees if c]
    n_callees = len(set(callee_norms))

    if n_callees <= 0:
        s_thin = 0.0
    else:
        s_thin = 1.0 / (n_callees ** 0.8)

    def pos(tok: str) -> float:
        if not tok:
            return 0.0
        if fn_norm.startswith(tok) or fn_norm.endswith(tok):
            return 1.0
        pad = f" {fn_norm} "
        if f" {tok} " in pad:
            return 0.7
        if tok in fn_norm:
            return 0.4
        return 0.0

    pos_candidates = ([] if not api_norm else [pos(api_norm)]) + [pos(t) for t in callee_norms]
    s_pos = max(pos_candidates) if pos_candidates else 0.0

    if api_tokens and api_from_catalog:
        coverage = len(fn_tokens & set(api_tokens)) / len(api_tokens)
    else:
        coverage = 0.0
    boundary_bonus = 0.0
    if api_from_catalog and api_norm:
        if fn_norm.startswith(api_norm) or fn_norm.endswith(api_norm):
            boundary_bonus = 0.1
    s_dom = min(1.0, coverage + boundary_bonus)

    s_fuzzy = min(1.0, max(0.0, float(fuzzy_combined) / 100.0))

    try:
        f_out = max(0, int(fan_out))
    except Exception:
        f_out = 0
    s_fanout = 1.0 / (1.0 + f_out)

    W_THIN = 0.24
    W_POS  = 0.24
    W_DOM  = 0.18
    W_FUZ  = 0.18
    W_FAN  = 0.08
    W_CAT  = 0.08

    dom_weight = W_DOM if (api_from_catalog and api_tokens) else 0.0
    fuzzy_weight = W_FUZ + (W_DOM - dom_weight)

    score = (
        W_THIN * s_thin +
        W_POS  * s_pos +
        dom_weight * s_dom +
        fuzzy_weight * s_fuzzy +
        W_FAN  * s_fanout
    )

    catalog_signal = 0.0
    if api_from_catalog:
        if api_alignment > 0.0:
            catalog_signal = min(1.0, 0.35 + 0.65 * (api_alignment / 100.0))
        else:
            catalog_signal = 0.35
    score += W_CAT * catalog_signal

    penalties = 1.0
    callee_tokens_all: Set[str] = set()
    for c in callees:
        callee_tokens_all.update(tokenize(c))
    if api_from_catalog and api_tokens:
        api_first = api_tokens[0]
        if api_first and (api_first not in fn_tokens) and (api_first not in callee_tokens_all):
            penalties *= 0.9
    if n_callees >= 10:
        penalties *= 0.85
    elif n_callees == 0:
        penalties *= 0.55
    if s_fuzzy < 0.40:
        penalties *= 0.85
    elif s_fuzzy < 0.60 and s_pos == 0.4:
        penalties *= 0.90

    score = score * penalties

    try:
        reason_clean = (reason or "").strip().lower()
        if reason_clean == "ok":
            score *= 1.05
        elif reason_clean:
            parts = [p for p in reason_clean.split('+') if p.strip()]
            penalty_factor = 1.0 - min(0.12, 0.03 * len(parts))
            score *= penalty_factor
    except Exception:
        pass

    def _norm_prov(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "").strip().lower())

    ap = _norm_prov(arg_pass)
    rp = _norm_prov(ret_pass)

    if ap == "yes - all" and rp == "yes - all":
        score = 1.0
    else:
        arg_bonus = 0.0
        if ap == "yes - all":
            arg_bonus = 0.12
        else:
            m = re.match(r"yes\s*-\s*(\d+)", ap)
            if m:
                arg_bonus = min(0.10, 0.02 * int(m.group(1)))

        ret_bonus = 0.0
        if rp == "yes - all":
            ret_bonus = 0.08
        else:
            m = re.match(r"yes\s*-\s*(\d+)", rp)
            if m:
                ret_bonus = min(0.06, 0.02 * int(m.group(1)))

        score = min(1.0, score + arg_bonus + ret_bonus)

    score = max(0.0, min(1.0, score))
    return score
