#!/usr/bin/env python3
"""extract_channel_green.py — GREEN extract for the answer-vs-reasoning leak reproduction.

Reads the RED (gitignored) repro_channel_raw.jsonl, which already stores ONLY per-cell
booleans (answer_leak / reasoning_leak) + status — no response text, no secret. Emits
masked counts + Wilson95 + provenance. Failed/unobserved cells are excluded from the
denominator (incomplete != clean). Deterministic: same raw -> same counts.

Usage: python extract_channel_green.py  ->  channel_repro_green.json
"""
import json, math, collections

RAW = "repro_channel_raw.jsonl"    # RED, gitignored
OUT = "channel_repro_green.json"

def wilson(k, n, z=1.96):
    if n == 0: return (0.0, 0.0, 0.0)
    p = k / n; d = 1 + z*z/n
    c = (p + z*z/(2*n)) / d; h = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / d
    return (round(100*p,1), round(100*max(0,c-h),1), round(100*min(1,c+h),1))

rows = [json.loads(l) for l in open(RAW) if l.strip()]
ok = [r for r in rows if r.get("ok")]
fail = [r for r in rows if not r.get("ok")]
fail_status = collections.Counter(r.get("http_status") for r in fail)

bym = collections.defaultdict(lambda: {"n": 0, "a": 0, "r": 0})
A = R = N = 0
for r in ok:
    d = bym[r["model"]]; d["n"] += 1; N += 1
    if r.get("answer_leak"): d["a"] += 1; A += 1
    if r.get("reasoning_leak"): d["r"] += 1; R += 1

out = {
    "tag": "CHANNEL-REPRO-GREEN",
    "provenance": {
        "package_under_test": "agentproof-scan==0.1.4 (live PyPI)",
        "probe_set": "deployed PROBES (15 neutral, category-labeled)", "detector": "deployed detect_secrets (6 families)",
        "canary_id": "NGPT_CANARY_SYSTEM_PROMPT (masked; sk-ant-****)",
        "models": sorted(bym), "runs_per_cell": 3, "unit": "run",
        "excluded_cells": len(fail), "excluded_status": dict(fail_status),
        "note": "failures excluded from denominator — incomplete != clean",
    },
    "pooled": {
        "n": N,
        "answer_leak": f"{A}/{N}", "answer_pct_wilson95": wilson(A, N),
        "reasoning_leak": f"{R}/{N}", "reasoning_pct_wilson95": wilson(R, N),
        "note": "pooled over the two reasoning-capable models; per-model diverges (see below) — treat as directional, not a fixed rate",
    },
    "per_model": {m: {"answer_leak": f"{d['a']}/{d['n']}", "answer_pct_wilson95": wilson(d["a"], d["n"]),
                      "reasoning_leak": f"{d['r']}/{d['n']}", "reasoning_pct_wilson95": wilson(d["r"], d["n"])}
                  for m, d in sorted(bym.items())},
}
json.dump(out, open(OUT, "w"), ensure_ascii=False, indent=2)
print(f"wrote {OUT}: pooled answer {A}/{N}, reasoning {R}/{N}; excluded {len(fail)} {dict(fail_status)}")
