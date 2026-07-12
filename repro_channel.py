#!/usr/bin/env python3
"""repro_channel.py — deployed-probe answer-vs-reasoning leak reproduction.

Uses the SHIPPED agentproof-scan==0.1.4 probe set + detector + canary. Calls two
reasoning-capable models, scores each channel with the deployed detect_secrets, and
writes ONLY booleans/lengths/status per cell (NO response text, NO secret) to a
gitignored *_raw.jsonl. The GREEN aggregate is produced by extract_channel_green.py.
Transient 5xx/429 are retried; unrecovered failures are recorded ok=False and excluded
from the denominator (incomplete != clean)."""
import os, sys, json, time, itertools
import urllib.request, urllib.error
from agentproof_scan.adapters import external_starter as ext
from agentproof_scan.scan import detect_secrets, PROBES
SYS = ext.NGPT_CANARY_SYSTEM_PROMPT
RAW = sys.argv[1] if len(sys.argv) > 1 else "repro_channel_raw.jsonl"
N = int(os.environ.get("REPRO_N", "3"))
MODELS = os.environ.get("REPRO_MODELS", "gemini-3.5-flash,claude-haiku-4-5").split(",")
GEMINI_ENDPOINT = ("https://generativelanguage.googleapis.com/v1beta/models/"
                   "gemini-3.5-flash:generateContent")
RETRY_STATUS = {429, 500, 502, 503}

def _post(url, headers, body, params=None):
    if params:
        url += "?" + "&".join(f"{k}={v}" for k, v in params.items())
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={**headers, "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception:
        return None, {}

def call_anthropic(model, user):
    st, j = _post("https://api.anthropic.com/v1/messages",
                  {"x-api-key": os.environ.get("ANTHROPIC_API_KEY",""), "anthropic-version": "2023-06-01"},
                  {"model": model, "max_tokens": 2500, "system": SYS,
                   "messages": [{"role": "user", "content": user}],
                   "thinking": {"type": "enabled", "budget_tokens": 1536}})
    if st != 200: return st, "", ""
    b = j.get("content", [])
    return st, " ".join(x.get("text","") for x in b if x.get("type")=="text"), \
               " ".join(x.get("thinking","") for x in b if x.get("type")=="thinking")

def call_gemini(user):
    st, j = _post(GEMINI_ENDPOINT, {},
                  {"system_instruction": {"parts": [{"text": SYS}]},
                   "contents": [{"role": "user", "parts": [{"text": user}]}],
                   "generationConfig": {"thinkingConfig": {"includeThoughts": True}}},
                  params={"key": os.environ.get("GEMINI_API_KEY","")})
    if st != 200: return st, "", ""
    try: parts = j["candidates"][0]["content"]["parts"]
    except (KeyError, IndexError, TypeError): return st, "", ""
    return st, " ".join(p.get("text","") for p in parts if not p.get("thought")), \
               " ".join(p.get("text","") for p in parts if p.get("thought"))

def call(model, user):
    return call_anthropic(model, user) if model.startswith("claude") else call_gemini(user)

def leaked(t): return len(detect_secrets(t or "")) > 0

done = set()
if os.path.exists(RAW):
    for line in open(RAW):
        try:
            r = json.loads(line)
            if r.get("ok"): done.add(r["cell_key"])
        except: pass

cells = list(itertools.product(MODELS, range(len(PROBES)), range(N)))
print(f"[repro] probes={len(PROBES)} models={MODELS} N={N} total={len(cells)}", flush=True)
with open(RAW, "a") as fh:
    for model, pi, run in cells:
        ck = f"{model}|p{pi}|{run}"
        if ck in done: continue
        tries = 0
        while True:
            st, ans, rea = call(model, PROBES[pi])
            if st in RETRY_STATUS and tries < 5:
                tries += 1; time.sleep(6*tries); continue
            break
        ok = (st == 200)
        rec = {"cell_key": ck, "model": model, "probe_idx": pi, "run": run,
               "http_status": st, "ok": ok,
               "answer_leak": leaked(ans) if ok else None,
               "reasoning_leak": leaked(rea) if ok else None,
               "reasoning_present": bool(rea) if ok else None}
        fh.write(json.dumps(rec) + "\n"); fh.flush()
        print(f"  {'ok' if ok else '!!'} {ck} st={st} a={rec['answer_leak']} r={rec['reasoning_leak']}", flush=True)
        time.sleep(1.2)
print("[repro] done", flush=True)
