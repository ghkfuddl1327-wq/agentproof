# Detect coverage gaps

Detection-side findings: secret shapes the scanner's `PROVIDER_PATTERNS` does **not** catch.
These are a separate concern from remediation (the fix-prompts in this repo). A secret that is
never detected never reaches a fix-prompt, so these are excluded from remediation measurement and
recorded here as candidates for future detection-side work.

> Honesty note: this is about what the deterministic scanner *finds*, not about whether a model
> *fixes* it. Remediation results (defense_v1 / storage_v2) only cover detected types.

---

## 2026-06-28 -- RESOLVED: modern OpenAI typed keys now detected

OpenAI `sk-proj-` / `sk-svcacct-` / `sk-admin-` are **now DETECTED** (was the priority gap from
2026-06-27). The openai entry in `PROVIDER_PATTERNS` is a merged pattern:
`sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{80,}|sk-[A-Za-z0-9]{20,}` (typed alternative + byte-identical
legacy alternative). FP=0 on negatives, attribution-safe (R2: `sk-ant-` still anthropic-only),
legacy unchanged. A non-overlapping `findall` makes a typed key with an internal `sk-` run count
exactly once as the full key (no double-count). Locked by regression tests (TC1-TC5).

## 2026-06-27 -- detect coverage gaps (vs PROVIDER_PATTERNS)

Tested with synthetic, invalid, high-entropy samples on the `.env` surface.

| Secret shape | Detected? | Note |
|---|---|---|
| OpenAI `sk-proj-` / `sk-svcacct-` / `sk-admin-` | **YES (2026-06-28)** | merged typed+legacy pattern; see resolved note above. |
| DB connection URLs (`postgres://user:pass@host/db`) | **NO** | structured credential; no URL/structural pattern exists. |
| generic high-entropy secrets (no prefix) | **NO** | no provider prefix and no generic-entropy detection rule. |
| legacy openai `sk-[A-Za-z0-9]{20,}` length-FP | **latent FP** | ~15/800 false hits on long (~20k-char) base64url blobs (base64url contains `-`, so `sk-`+20 alnum occurs by chance). Anchorless-`findall`, **same class as the AWS R3 base32 length-FP**; pre-existing/latent, NOT introduced by the typed pattern (legacy alternative is byte-identical). Candidate: post-match gating like AWS. **NOT YET ADDRESSED.** |

**Currently detected (for reference):** AWS `AKIA`, OpenAI (`sk-` legacy + `sk-proj-`/`sk-svcacct-`/
`sk-admin-` typed), GitHub `gh[pousr]_`, Google `AIza`, Anthropic `sk-ant-`, xAI `xai-`.

> Note on the DB-URL gap: even if detection were added, the correct `.env` remediation is an open
> rubric question (whole-URL placeholder vs password-only redaction) -- a structured value differs
> from the opaque-token case storage_v2 handles. Decide that before measuring DB-URL remediation.
