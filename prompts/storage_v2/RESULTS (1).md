# storage_v2 -- RESULTS

Dated aggregate results for the surface-aware `storage_v2` fix-prompt. Aggregates only -- raw
per-cell transcripts and reasoning traces are kept private (not in this repo).

## Measurement setup

- **Models tested:** gemini-2.5-flash, gpt-4o-mini (light) / grok-4 (mid, reasoning) /
  claude-sonnet-4-6 (mid-high).
- **N=5** per cell. Stability read, NOT a statistical guarantee.
- **Tracer:** one synthetic, invalid AWS-style canary on one finding shape.
- **SURFACE tag** derived from file extension: .py->python, .env->dotenv, .yaml->yaml, .md->markdown.

## Dated entries

```
2026-06-26  v1 -> surface-aware tested: safety floor generalizes, remediation .py-only (40/80 correct)
2026-06-27  storage_v2 (surface-aware) 4 surfaces x 4 models x N=5:
  literal removal 80/80 + 20/20 (held)
  surface_correct: .py 20/20  .yaml 20/20  .md 20/20  .env 19/20
2026-06-27  TEST-C type generalization (.env, 4 prefix types x 4 models x N=8 = 128):
  - surface_correct generalizes (NOT AWS-overfit): placeholder 32/32 + not-as-code 32/32 ALL types;
    non-AWS >= AWS control (within-run comparison).
  - safety floor (literal removal): 128/128 all types; output-echo 0; rewritten-as-code 0.
  - grok reasoning-echo TYPE-AGNOSTIC: 5/32 across all 4 providers (model-level, not AWS artifact).
  - residual: gemini/grok auxiliary-file omission (model-tier floor, type-independent, run-variance).
```

NOTE on the .env surface_correct number: it shows run-to-run variance driven by the light-model
floor (~66-90% across runs). The generalization read is the WITHIN-RUN relative comparison
(all types, same N/conditions, cluster together; non-AWS >= AWS control), not an absolute figure.

Validated types: AWS, OpenAI (classic `sk-`), GitHub (`ghp_`), Google (`AIza`).
Detection-side coverage gaps are tracked separately in [`../COVERAGE_GAPS.md`](../COVERAGE_GAPS.md).

## .env dotenv-rule fix progression

The `.env` surface drove the storage_v2 design. The remediation rule was iterated and re-measured
(.env surface, 4 models x N=5 = 20 each), scored on one identical strict rubric (placeholder AND
not-rewritten-as-code AND .gitignore output AND .env.example output AND rotate noted in a file):

```
v1   (defense_v1, "read from os.environ")        0/20   catastrophe: rewritten-as-code 14/20
v2   (surface-aware, narration as instruction)  11/20   light models dropped narration (RULE-4 tension)
v2.1 (narration absorbed into output files)     18-19/20 .gitignore + .env.example authored as files
```

storage_v2 ships the **v2.1 (narration-as-files)** dotenv form: the rotation/.gitignore guidance
lives INSIDE the authored files, which the "return only the corrected file(s)" safety rule permits,
so lightweight models no longer drop it as prose.

## Known residuals (honest)

- **.env ceiling ~18-19/20:** lightweight / free-tier models sometimes truncate to "just fix the
  file" and skip authoring the extra files (.gitignore / .env.example). This is a model-tier floor,
  NOT a wording defect -- further prompt phrasing chases 1-cell swings at N=5.
- **grok-4 hidden-reasoning echo ~1-2/20:** a model-level blind spot, NOT closable by prompt.
  Reduced but never zero across 5 independent runs; the visible output is always clean (0 output
  echo). Caught only by a reasoning-trace check, not by output inspection.

## Scope -- what is proven / not proven

- Validated secret types (`.env` surface): **AWS, OpenAI (classic `sk-`), GitHub (`ghp_`),
  Google (`AIza`)** -- synthetic invalid samples, type generalization confirmed within-run.
- NOT proven: database-connection URLs, generic high-entropy secrets, OpenAI `sk-proj-` /
  `sk-svcacct-` keys (these are detection-side coverage gaps -- see
  [`../COVERAGE_GAPS.md`](../COVERAGE_GAPS.md) -- so they were never in the remediation matrix).
- Four models, specific versions. No claim about other models or future versions.
- N=5 (surface sweep) / N=8 (type sweep) per cell are stability reads, not statistical guarantees.
