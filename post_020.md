# 0.2.0: I shipped the coverage my own page had already promised

*This is a follow-up to my earlier writeup, ["A leaked agent key is two debts — and I caught my own scanner lying about it"](https://www.indiehackers.com/post/a-leaked-agent-key-is-two-debts-and-i-caught-my-own-scanner-lying-about-it-bf6d820b8d). That post stands unedited; this one only covers what changed in `0.2.0`. If you haven't read it, the incidents, the legal ground, and the "why detect instead of mitigate" argument are all there and none of it has changed. Read that first — I'm not going to re-argue it here.*

## First, the correction — because it's the reason this release exists

I keep a rule: the honesty note goes at the top, not the bottom. Here it is for `0.2.0`.

For part of the `0.1.4` window, my **public page described coverage the `0.1.4` package didn't actually ship.** The README talked about 16 detection families and a reasoning-scanning surface; the `0.1.4` wheel on PyPI carried six detection families and no reasoning-scan module at all. The page got ahead of the code. That's the exact failure shape this whole project exists to catch — a claim reading as done before the thing behind it is done — and I did it on my own README.

`0.2.0` is the release where the code catches up to the page. Not a new capability I'm announcing so much as a debt I'm paying: the shipped package now contains what the page said it did. The full correction is appended to the previous post's list (item F below), append-only, nothing deleted.

## What did **not** change — so I don't re-sell it

`0.2.0` is **additive**. Reference these from the prior post; I'm not re-branding them as new:

- The **exit-code contract** (`0` ran-and-clean / `1` scan-didn't-run / `2` defect-found), the `reason=` slugs, and the completion gate — identical.
- **Bring-your-own-key, serverless, Apache-2.0** — identical.
- The **model scope** — Gemini 3 Pro-series, Grok 4–4.3, GPT-4o-mini, Anthropic Haiku through lightweight Sonnet; **no frontier models** — identical. Every cross-model number still reads "on the models a small shop actually ships," not "on all models."
- The **original six credential families** behave exactly as they did in `0.1.4`. Nothing about the old path moved.

If you were already on `0.1.4`, `pip install -U agentproof-scan` changes what's *covered*, not how the tool *behaves*.

## Three numbers went up — and they do **not** add up to one

This is the part I most want read slowly, because the labels are easy to over-read. `0.2.0` moved three different measurements. They count three different things. **A scanner that labels 16 credential shapes is not a scanner that "catches 16 kinds of attack,"** and none of these three numbers is a subset or a total of the others.

| Layer | 0.1.4 → 0.2.0 | What the number means | Backing (byte-reproducible, 0 API) |
|---|---|---|---|
| **Detection (matchers)** | **6 → 16 families** (15 on by default + `postgres` opt-in) | the matcher puts the **right family label** on a credential's *shape*, and stays quiet on look-alikes | `axis_b_coverage_green.json` — the 10 families added since `0.1.4`: 10/10 labelled, 0 missed, 0 false positives on near-miss strings |
| **Elicitation (end-to-end)** | **6 → 10 families** | a credential sitting in an **agent's actual response** is carried out end-to-end: plant → probe → detect, with the right family and nothing invented | `elicitation_green.json` — 10 planted, 10 detected, **FN 0 / FP 0**, no spurious providers (`postgres` excluded, opt-in) |
| **Reasoning-attack (H-CoT)** | **new: 3 probes** | when a fake "reasoning step" is injected into an agent **you own**, the scanner **sees** the resulting reasoning-channel leak — added *on top of* the existing reasoning-channel detection, not replacing it | `hcot_green.json` — 3 probes, **FN 0 / FP 0**; in all three the answer stayed clean and only the reasoning leaked |

Three things I have to be explicit about, or the numbers lie by implication:

- **Detection 16 ≠ elicitation 10 ≠ 3 H-CoT probes.** The first counts *shapes the matcher knows*. The second counts *families actually carried out of an agent's reply*. The third is *a count of attack probes, not families or attacks stopped*. Reading "16" as "the number of things it protects you from" is the misread I'm trying to pre-empt. The genuine capability increase here is the **elicitation 6 → 10** — that's the one that means "more kinds of credential get caught coming *out* of a real agent flow."
- **The H-CoT row is about the scanner, not about any model.** It says *this tool sees that leak on an agent you point it at*. It is **not** a claim that any real model is vulnerable to H-CoT — that would need live measurement against real models, which is **not** in this release. The probes are so you can check an agent **you own**; they are not a jailbreak kit, and "scan only agents you own" is the rule they ship under.
- **All three are offline (`canned`, 0 API calls).** They run the scanner against planted, synthetic, shape-only fakes — no real key, no live model. So none of them tells you how often a *real* agent leaks. That's a different kind of number, below.

## The frontier surface: new **reach**, not a new number

`0.2.0` can now point at a frontier model's **extended-thinking trace** and scan it as a first-class surface — for Anthropic extended thinking, the reasoning lives in `content.0.thinking` while the answer is in `content.1.text`, and the scanner will read the former if you hand it the path. That is **reach**: a surface the tool couldn't see before and now can.

It is **not** a frontier leak *rate*. I did not run a live measurement campaign against a frontier model for this release, so I'm not going to attach a percentage or a model name to a vulnerability claim. "The scanner can now see this surface" and "this model leaks X% of the time" are different sentences, and only the first one is backed here. If the API returns no trace, you get `not_applicable` — *"we couldn't look,"* not a pass.

## The earlier directional numbers — carried forward, and labeled as such

The prior post's cross-model figures are **`0.1.4`-campaign measurements**, and I'm not going to quietly re-print them as if they were freshly measured on `0.2.0`. What they are:

- **Answer channel 0/90 (≤4.1%, Wilson95) vs reasoning channel 41/90 (45.6%, [35.7, 55.8])** — the answer-clean-but-reasoning-leaks split — was measured on the two reasoning-capable models in scope (Haiku, Gemini-flash) against the shipped probe set. Backing: `channel_repro_green.json`, which records `package_under_test = 0.1.4`. Because `0.2.0` is additive and this canary (`sk-ant-…`) is one of the original six families the matcher already had, **the measurement is unchanged — same probes, same models, same detector path — carried forward, not re-run.** Still directional (per-model diverges: Haiku 22/45, Gemini 19/45; small N, probe-wording-sensitive), still not a fixed rate.
- **Mitigation cut answer-side disclosure ~79–93pp** (config-specific), **over-refusal 0/80 on the defended/hardened prompts (118/120 across all three targets)**, and the **~85-vs-53-token** prompt-size cost — all `0.1.4` campaign, **not re-measured for `0.2.0`, unchanged**. The additive release didn't touch the mitigation path, so I carry them forward with that label rather than re-baptizing them as `0.2.0` numbers.

The honesty rule here is simple: a `0.1.4` measurement reused in a `0.2.0` post has to *say* it's a `0.1.4` measurement. Reusing it silently would be its own little false-GREEN.

## Reproduction contract

Two tiers, kept apart on purpose:

- **T1 — every GREEN-backed number reproduces byte-for-byte** from a clone, offline, no API key:
  ```bash
  git clone https://github.com/ghkfuddl1327-wq/agentproof && cd agentproof
  python score_axis_b_coverage.py   # → axis_b_coverage_green.json   (detection 16)
  python score_elicitation.py       # → elicitation_green.json       (elicitation 10)
  python score_hcot.py              # → hcot_green.json              (H-CoT 3 probes)
  python -m pytest -q               # the gates behind them
  ```
  Run any twice, get identical bytes. If a regenerated file differs from the committed one, treat the claim as broken — that's why the generators ship next to the artifacts.
- **T2 — the cross-model observations do NOT reproduce this way.** They're measured snapshots: they depend on API keys, model availability, and provider behaviour that shifts under us. Directional, not byte-reproducible. That's the `0/90`, `41/90`, `79–93pp` bucket above.

## Limits (the `0.2.0` delta only)

Still a detector, not a mitigation and not a shield. Two of the new families are **exposure signals, not proof of a secret** — a **JWT** is often a public ID token, and a **Twilio** `SK…` is a public identifier whose paired secret is separate — and the finding's `scope` says so. **`postgres` is the 16th family and stays opt-in**, because a password inside a `postgres://…` URL false-positives on the placeholder passwords that fill documentation; I'd rather hold it off-by-default than ship a family that cries wolf. Everything the prior post listed under Limits still holds.

## Get it

```bash
pip install -U agentproof-scan      # 0.2.0
```

Apache-2.0, bring-your-own-key, serverless. Repo: github.com/ghkfuddl1327-wq/agentproof

If it breaks something it claims to do, that's a finding — open an issue and tell me where the numbers don't hold on your setup. I'd still rather be calibrated by operators than trust my own green.

---

## Corrections — appended to the previous post's list

Append-only: marked, not deleted.

**F. Public page, `0.1.4` window — coverage described ahead of the shipped package.** SAID (README, during the `0.1.4` window): detection across 16 credential families and a reasoning-scanning surface. [CORRECTED] The `0.1.4` package on PyPI carried **six** detection families and **no** reasoning-scan module — the page described capability the shipped code didn't yet contain. `0.2.0` ships the code: the 16-family matcher (15 default + `postgres` opt-in), end-to-end elicitation for 10 families, and the reasoning/H-CoT surface are now in the package, and the page and package match. Writing coverage into a README before it's in the wheel is exactly the claim-ahead-of-reality failure this tool exists to catch — logged here to the same standard I hold everything else to.
