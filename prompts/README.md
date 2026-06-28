# Fix prompts

Paste-in prompts that tell an AI how to fix a secret-leak finding from a pre-deploy scan.

The tool **finds** a leaked credential deterministically; the **fix** is delegated to your own
model (BYOK). These prompts are shaped by what actually breaks when different models try to fix a
leak -- measured, not guessed. Every claim below is tied to a dated measurement; raw transcripts
stay private, aggregates are public.

> Honesty note: these prompts do **not** "secure your app." They handle one specific step --
> getting a model to remove a leaked secret correctly -- and we publish exactly where that works
> and where it doesn't.

---

## Which prompt for which situation

**Recommended: `storage_v2` (surface-aware) -- measured 2026-06-27 on all 4 surfaces.**

| Your finding (surface) | Prompt | Secret removed? | Correct fix for the surface? |
|---|---|---|---|
| Secret in a **.py** file | `storage_v2` | yes -- measured 100% | yes [OK] -- 20/20 |
| Secret in a **.env** file | `storage_v2` | yes -- measured 100% | yes [OK] -- 19/20 (light-model floor ~18/20) |
| Secret in **.yaml / config** | `storage_v2` | yes -- measured 100% | yes [OK] -- 20/20 |
| Secret in **.md / docs** | `storage_v2` | yes -- measured 100% | yes [OK] -- 20/20 |

**Baseline: `defense_v1` (.py-only).** Strips the literal on every surface (100%) but its
remediation rule is `.py`-shaped, so off `.py` it misfires:

| Your finding (surface) | Prompt | Secret removed? | Correct fix for the surface? |
|---|---|---|---|
| Secret in a **.py** file | `defense_v1` | yes -- measured 100% | yes -- measured 19/20 |
| Secret in a **.env** file | `defense_v1` | yes -- measured 100% | NO -- misfires (0/20) -- use `storage_v2` |
| Secret in **.yaml / config** | `defense_v1` | yes -- measured 100% | [!] uneven -- use `storage_v2` |
| Secret in **.md / docs** | `defense_v1` | yes -- measured 100% | [!] split -- use `storage_v2` |

`storage_v2` keeps defense_v1's safety floor (literal removed everywhere) and adds the correct
remediation per file type, closing the `.env` / `.yaml` / `.md` gap -- with 2 documented residuals
(`.env` light-model floor ~18-19/20; grok-4 hidden-reasoning echo ~1-2/20). See
[`storage_v2/RESULTS.md`](storage_v2/RESULTS.md).

---

## The two things we measure

1. **Safety floor -- is the secret actually gone?**
   Did the literal disappear from the model's output? (deterministic check)

2. **Remediation correctness -- is the fix right for *that* file type?**
   `.py` -> read from `os.environ`. `.env` -> placeholder + `.gitignore` + `.env.example` + rotate
   the real key (NOT rewrite the file as code). `.yaml` -> `${VAR}` interpolation. `.md` -> redact.

A prompt can hit (1) perfectly and still miss (2). Our data shows `defense_v1` does exactly that
off the `.py` surface.

---

## defense_v1 scorecard

See `defense_v1/prompt.txt` for the verbatim prompt and `defense_v1/RESULTS.md` for the dated runs.

**Safety floor (secret removed):**
- 2026-06-25, 4 models, N=5 (20 cells): 20/20 removed, 0 echo, 0 reasoning-echo.
- 2026-06-26, independent re-run, same setup (20 cells): reproduced -- 40 cells total, identical.
- 2026-06-26, across 4 surfaces (.py/.env/.yaml/.md), 4 models, N=5 (80 cells): **80/80 removed,
  0 output-echo.** Holds on every surface tested.

**Remediation correctness (per surface, 4 models x N=5):**
- `.py` -- 19/20 appropriate (native -- the rule matches the surface).
- `.env` -- **0/20** appropriate. The rule "read from `os.environ`" is circular inside a `.env`
  (the file *is* the env source); models rewrote the `.env` as a Python file. The literal was
  removed (safe) but the fix is wrong for the surface.
- `.yaml` -- ~14/20. Models that self-corrected to `${VAR}` from their own knowledge passed; one
  reasoning model with no such prior did not. The rule didn't help -- model priors did.
- `.md` -- split. Some models redacted (correct); others injected `os.environ` into documentation.

**Known model-level blind spot:**
- One reasoning model reproduced the secret in its *hidden reasoning trace* in a few cells, even
  when the visible output was clean (3 cells on `.md`, 2026-06-26). An output-only check would
  pass these. The prompt's "don't reproduce it in your reasoning" rule reduces this but does not
  fully guarantee it on every surface -- it's a model-level limit, surfaced here honestly.

---

## Scope -- what is NOT proven

- One synthetic, **invalid** AWS-style test key on one finding shape. Not other secret types
  (database URLs, tokens, private keys) or other code contexts.
- Four models, specific versions. No claim about other models or future versions.
- N=5 per cell is a stability read, **not** a statistical guarantee.
- Measured on a synthetic tracer, not real production findings.

We name what we ran and the scope it covers. Anything outside that scope is untested, and we say so.

---

## How results are recorded

- Each prompt folder has a `RESULTS.md` with **dated** entries: date, conditions (models, surface,
  N), measured outcome, and scope.
- `CHANGELOG.md` tracks prompt evolution by date.
- Raw per-cell transcripts (full model outputs, reasoning traces) are kept **private** -- only
  aggregate results and the prompts themselves are published here.

---

## How to use

1. Run the scanner; it reports a finding (file + surface type).
2. Use `storage_v2` (surface-aware): set `SURFACE: <tag>` from the file type
   (.py->python, .env->dotenv, .yaml->yaml, .md->markdown) and paste your finding.
3. Paste the prompt + your finding into your model.
4. **Verify the fix yourself** -- especially on `.env`, where lightweight models sometimes skip
   authoring the `.gitignore` / `.env.example` files (~18-19/20 floor, see `storage_v2/RESULTS.md`).

This is build-in-public measurement. If you can break a prompt on a surface we marked working,
that's a finding -- open an issue.
