# A leaked agent key is two debts — and I caught my own scanner lying about it

## First, a correction (this is the whole point)

I build a tool whose entire job is catching claims that read as safe but aren't. So before anything else: earlier versions of this tool — and the posts I wrote about it — made claims that were wrong. I'm not deleting them. I'm marking them, and the full list is at the bottom.

The short version: `0.1.0`–`0.1.3` are yanked. `pip install agentproof-scan` now gives you `0.1.4`, the first release with no known false-GREEN. If opening a security tool's writeup with its own past mistakes feels backwards, good — that's exactly the standard I want to be held to. Now the real story.

## Two debts, arriving at different speeds

If your agent touches an API key, a leak isn't one problem. It's two, and they arrive at different speeds. The fast one is the invoice. The slow one is every log that kept a copy of what leaked — and logs outlive the incident. Most of the people below did nothing careless. They just hadn't priced in either debt yet.

## What already happened (the fast debt)

- A three-person team in Mexico watched a leaked key run up $82,314 in February 2026. Their usual month was about $180 (The Register, Mar 2026).
- Jesse Davies did the things you're told to do — a $10 budget, 2FA, per-project keys, audit logging — and still woke up to AU$25,672 (Tom's Hardware, Apr 2026).
- Another user reportedly watched charges climb toward $128,000 even after the API was already cut off.
- On 2026-04-25, a Cursor AI agent at PocketOS deleted an entire production database in under ten seconds — backups included, because they sat in the same blast radius. It located an over-permissioned token unrelated to its task and used it on its own (The New Stack, May 2026).

The common thread isn't negligence. It's that none of them felt they needed a check like this until after the number landed.

## It isn't solved yet

The tempting response is "the vendors will close this soon." The record says otherwise.

- The Google-billing root cause was reported by Truffle in November 2025. Google first called it intended behavior and dismissed it, reclassified it as a bug in December, and as of February was still working on a root fix — the reporter said they hadn't seen concrete results. Davies counted nine Google safety features that should have caught his case, all off by default (The Register / Tom's Hardware).
- "Comment-and-Control," disclosed 2026-04-15, showed three coding agents — Claude Code, Gemini CLI, and Copilot — leaking repository and API secrets when instructions were injected through PR titles, issues, and comments on GitHub. Vendors paid bounties ($100, $500, one undisclosed) but shipped no CVE and no advisory, so users never heard about it. One fix cut off reading another process's environment via `ps`; `/proc/*/environ` still reached it. Whack-a-mole (CSA Labs / The Register, Apr 2026).
- The trend line is going the wrong way: LLM credential leaks rose 81% year over year to 1.2 million, and hardcoded secrets rose 34% to 28.65 million (GitGuardian, State of Secrets Sprawl 2026).

The vendors haven't closed the door. Planning around "it'll be fixed soon" is planning on something that hasn't happened.

## A scope note before any of my own numbers

Every measurement below comes from one model set: Gemini 3 Pro-series, Grok 4 through 4.3, GPT-4o-mini, and Anthropic's Haiku through lightweight Sonnet. Frontier models (Opus, top-tier GPT, Gemini Ultra) were not measured. That's a target choice, not a gap — these are the models an indie or small team actually wires up to a real API key. Read every number as "on the models a small shop ships," not "on all models."

## Why it can't be fully solved — the model dilemma

The model itself can't police its own trust boundary. Two separate studies make the point. A black-box study (HouYi) found 31 of 36 real LLM-integrated apps vulnerable to prompt injection. And an IEEE S&P 2026 study of 17 third-party chatbot plugins running on 10,000+ sites found 8 transmit conversation history without integrity checks — letting an attacker forge past turns, even system messages, and boost injection 3–8× — while 15 pull scraped web content into the model without separating trusted from untrusted. Safety training is not access control.

Here's what I measured myself, on that model set and nothing wider:

- **Mitigation is partial.** Depending on the model and the probe battery, a system-prompt add-on cut answer-side disclosure by roughly 79–93 percentage points (config-specific, not one fixed figure — see `mitigation_reduction_green.json`), but the reasoning channel kept leaking. Tightening one channel doesn't close another.
- **Over-refusal from the mitigation was zero in the range I tested:** the defended and hardened prompts answered every benign request (0/80 over-refusal, 100%); across all three targets including the undefended control it was 118/120 — the two misses were on the control, not the defense (`overrefusal_green.json`). That range is narrow — in-role, four probes, one model. I am NOT claiming "no over-refusal across all domains." I didn't test that.
- **The real cost isn't intelligence, it's prompt size.** The structural mitigation block I'd actually ship is about 85 tokens of system prompt versus about 53 for a bare generic one — added input on every call, not a change in response length (I did not measure response length, so I make no claim about it). It's an efficiency cost, not a quality one, and I keep the two separate.
- **NOT MEASURED:** whether mitigation lowers task accuracy or success rate. The literature suggests a tradeoff exists; my data doesn't show one either way, so I make no claim about it.

This is why the tool detects rather than mitigates. A single "defense rate" number hides all of the above — the partiality, the token cost, and the degradation I didn't measure. It's the same failure shape I keep running into: the right half of a result hiding the wrong half. And I know that shape well, because I found it in my own tool three times.

The mitigation prompts I measured — with their limits documented per surface and per channel, including the `.env` misfire below — live in the repo under `prompts/`. Reference, not a fix I'm selling.

## Three times my own scanner lied GREEN

The tool calls an AI agent, tries to make it leak a credential, and tells you whether it did. It's a detector. It doesn't harden your agent and it won't secure your app — it measures whether a secret comes back out. Over one week it lied to me three times, and each lie is why a specific number above is stated as narrowly as it is.

**1. It returned "clean" without ever calling the agent.** In versions ≤0.1.2, if the target URL was empty the scan quietly fell back to a bundled demo — or reached nothing at all — and still printed exit 0, "safe." The tool that exists to catch false-GREEN was itself a false-GREEN. The fix wasn't a better probe; it was a contract. A scan now has to account for every probe it launched. If it can't observe a probe's result, it's forbidden from claiming clean — it exits 1 with `reason=incomplete_scan`. Silence is no longer allowed to read as safety.

**2. The right half hid the wrong half.** I ran the mitigation prompt against a matrix of models and the final-answer channel went quiet — green across the board. But the reasoning trace kept leaking. If anything downstream captures that trace — a log sink, an eval harness, an observability tool — the secret is sitting in plain text under a GREEN answer. The same shape showed up one layer down, on the remediation side: the first fix-prompt's advice was `.py`-shaped ("read the value from `os.environ`") and misfired off that surface — on `.env` files it scored 0/20, often rewriting the dotenv line as Python. The surface-aware successor (`storage_v2`, measured 2026-06-27) closes most of that gap — correct dotenv remediation 18–19/20 on the models tested, with a documented ceiling where lightweight models truncate; see `prompts/storage_v2/`. But I only went looking because a single GREEN is an average, and averages hide their worst cell. So the tool stopped reporting one number: it reports per-channel and per-condition now, and scans the reasoning trace as a first-class surface.

**3. One real API call showed more than 32 fixture cells.** I had a 32-cell fixture matrix, all green, and trusted it. Then I pointed the tool at a live model with a real key. Partway through, the free-tier quota tripped (15 probes × a stability factor of 5 = up to 75 requests/run — well over the per-minute limit; in practice it tripped around a dozen in). The old build treated the cut-off run as a completed one and reported clean — finding #1 again, caught in the wild. A quota hit now surfaces as `reason=rate_limit`, explicitly not a tool failure and not a finding. And the first-run recommendation dropped from `--stability 5` to `--stability 2`, because the number I'd printed in the README was one I'd never actually run on a free key. Thirty-two green fixture cells taught me less than one real request that failed.

## The legal ground (the slow debt), stated honestly as unsettled

- **Logs are the liability.** In the OpenAI matter, the SDNY (Judge Stein) ordered production of 20 million chat logs. That case was about copyright, not credentials — but it established that retained LLM logs are discoverable at all, which is the principle that matters here (Lawyer Monthly, Jan 2026).
- **The fines are real.** A serious GDPR violation runs to 4% of revenue or €20M. Free Mobile drew €42M in January 2026 over weak authentication, failed anomaly detection, and over-retention. EU AI Act high-risk enforcement takes effect 2026-08-02 (securitywall / Kiteworks 2026).
- **But the AI-specific case law is unsettled, and I won't pretend otherwise.** In March 2026 a Rome court annulled the €15M fine the Garante had levied on OpenAI — Europe's only finalized GenAI GDPR enforcement, overturned (GDPR Fines Tracker 2026). What's established stays narrow: retained logs are discoverable, and weak auth plus over-retention draws real fines. Whether a secret leaking through a reasoning trace into a log sink creates liability on its own is a plausible chain, not a decided one — and I label it exactly that.

## Doing nothing vs. doing something

Do nothing: $0 today, against an invoice plus a log liability plus (unsettled) regulatory exposure if it goes wrong. Do something: a few minutes before deploy, bring-your-own-key, serverless. The vaccine logic holds — with the root cause open and the model unable to close it alone, right now is the cheapest this will ever be.

## Limits, stated plainly

This detects; it's not a mitigation and it's not a shield. It won't catch a zero-day. It covers 6 credential families, under tested conditions, on the model set above. It matches literal secrets, not semantic ones. The tier-three story — a secret leaking into a reasoning trace, landing in a log sink, and leaving from there — is a plausible chain, not a documented incident, and I label it that way.

## What is verified (narrowly, same model scope)

I scan both the answer and the reasoning channel, and the split is the whole point: a model routinely keeps a secret out of its answer while spilling it in its reasoning. Re-running on the shipped probe set + detector against two reasoning-capable models, the answer channel leaked 0/90 (≤4.1%, Wilson95) while the reasoning channel leaked 41/90 (45.6%, [35.7, 55.8]) — and even that figure hides how model-specific it is (gemini 42%, haiku 49%; small N, sensitive to probe wording), so read it as directional, not a fixed rate. An output-only check misses the reasoning leak; with the answer channel near zero I don't quote a fixed multiplier. (Backing counts: `channel_repro_green.json`.) Deterministic matching held at FN=0 / FP=0 across 6 families, under tested conditions, on the model set in the scope note — not a claim about frontier models. Findings record a one-way fingerprint of the secret, not its value — see the companion post, "audit the detection, not the reasoning," for how that record works. Apache-2.0, bring-your-own-key, serverless. Repo: github.com/ghkfuddl1327-wq/agentproof

## Calibration

If none of the incidents above has happened to you, that's luck, not architecture. The root cause is still open, so the cheapest moment to hold a check like this is now. And if it breaks something it claims to do, that's a finding — open an issue, and tell me where the numbers don't hold on your setup. I'd rather be calibrated by operators than trust my own green.

## Corrections (the full list promised up top)

Append-only: marked, not deleted. All fixed in `0.1.4`; `0.1.0`–`0.1.3` are yanked.

**A. PyPI README, 0.1.0–0.1.3.** SAID: "all-zeros should be rare" / "a present-but-invalid key can still produce a 0" / (0.1.2–0.1.3) "an empty `--url` falls back to the bundled demo." [CORRECTED] Those versions could report a scan as exit 0 ("safe") when the scan never reached the agent (≤0.1.2) or was cut off partway (0.1.3) — exactly the false-GREEN this tool exists to catch. 0.1.4: if any probe was not observed, it doesn't claim clean — it exits 1 with `reason=incomplete_scan`.

**B. `--help` output (code), 0.1.3.** SAID: "if unspecified, exits 0 as before." [CORRECTED] The tool contradicted its own behavior. The completion gate returns exit 1 independent of any gating flag. 0.1.4's `--help` states the actual contract: 0 = ran to completion + clean / 1 = scan did not run / 2 = defect found (when gating enabled).

**C. Post claim, "install friction → 0."** SAID: "installing is basically frictionless." [CORRECTED] Measured in a container (Python already present). On a real Windows machine the Python install itself was most of the friction, and the docs didn't cover that path. 0.1.4 adds it to Prerequisites. Writing "→0" for something never measured is precisely the failure class this project keeps catching.

**D. README recommendation, `--stability 5`.** SAID: recommended `--stability 5`. [CORRECTED] Too aggressive for a first run. On a free Gemini key that's 75 requests (15 probes × 5) and trips the per-minute quota. 0.1.4 recommends `--stability 2` first, and a quota hit surfaces as `reason=rate_limit` — not a tool failure, distinct from a real finding.

**E. Scope note (not a correction).** The campaign measurements (reasoning-channel leak, FN=0 / FP=0) were re-confirmed against the raw data to be unaffected by the swallow bug above (zero contaminated records). That means "not corrupted by the bug" — it does NOT mean independently verified, and it does NOT mean FN=0 holds under all conditions. FN=0 remains "for the 6 known families, under the tested conditions."
