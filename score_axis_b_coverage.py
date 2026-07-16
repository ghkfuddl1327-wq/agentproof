#!/usr/bin/env python3
"""score_axis_b_coverage.py — AXIS B: secret-type coverage boundary (0 API, offline).

Measures where the CURRENT matcher (scan.PROVIDER_PATTERNS, 6 families:
anthropic/openai/xai/google/github/aws) stops. For each credential type OUTSIDE
those 6 families we plant a synthetic, format-correct, high-entropy fake key (real
key 0 — format only) and pass it through the UNCHANGED detect_secrets(). No new
matching logic — pure capability measurement.

Since the matcher only knows 6 providers, a genuinely-new type can be:
  · MISSED         — detect_secrets returns [] (no coverage at all), OR
  · ACCIDENTAL     — coincidentally trips one of the 6 patterns (wrong-label match).
Neither is "correct typing" (the type isn't in the registry), so the output is a
coverage boundary map: caught-by-coincidence vs. missed-entirely.

Discipline: detector FN/FP measurement (outside the rate-claim gate). Per-type COUNTS
only — no "coverage %" generalization claim. Secrets masked in all output. GREEN JSON.
"""
import json
import random

from agentproof_scan.scan import detect_secrets, mask_secret

R = random.Random(1327)
LOWER = "abcdefghijklmnopqrstuvwxyz"
ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
HEXL = "0123456789abcdef"


def rnd(n, cs=ALNUM):
    return "".join(R.choice(cs) for _ in range(n))


def _pem(nlines=8):
    body = "\n".join(rnd(64, B64URL) for _ in range(nlines))
    return "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----"


# NEW candidate credential types — OUTSIDE the 6 covered families.
# FAKE = synthetic, format-correct, high-entropy (must not be filtered as placeholder).
# All values are format-only fakes; no real credential is used.
FAKE = {
    "stripe_secret":        "sk_live_" + rnd(24),                       # underscore, NOT openai sk-
    "slack_bot":            "xoxb-" + rnd(12, "0123456789") + "-" + rnd(12, "0123456789") + "-" + rnd(24),
    "github_finegrained":   "github_pat_" + rnd(22) + "_" + rnd(59),    # new PAT, NOT ghp_
    "jwt":                  "eyJ" + rnd(20, B64URL) + "." + rnd(40, B64URL) + "." + rnd(43, B64URL),
    "pem_private_key":      _pem(),
    "postgres_uri":         "postgres://appuser:" + rnd(24) + "@db.internal.example.com:5432/prod",
    "sendgrid":             "SG." + rnd(22, B64URL) + "." + rnd(43, B64URL),
    "gcp_oauth_secret":     "GOCSPX-" + rnd(28),
    "npm_token":            "npm_" + rnd(36),
    "twilio_api_key":       "SK" + rnd(32, HEXL),
}

# Benign near-misses — placeholder / low-entropy / wrong-length. Must stay silent (FP check).
NEARMISS = {
    "stripe_secret":        "sk_live_your_key_here_placeholder",
    "slack_bot":            "xoxb-000000000000-EXAMPLE-token",
    "github_finegrained":   "github_pat_EXAMPLE_replace_me",
    "jwt":                  "eyJ.PLACEHOLDER.signature",
    "pem_private_key":      "-----BEGIN RSA PRIVATE KEY-----\nYOUR_KEY_HERE\n-----END RSA PRIVATE KEY-----",
    "postgres_uri":         "postgres://user:password@localhost:5432/dbname",
    "sendgrid":             "SG.your_sendgrid_api_key.placeholder",
    "gcp_oauth_secret":     "GOCSPX-your-client-secret-here",
    "npm_token":            "npm_0000000000000000000000000000example",
    "twilio_api_key":       "SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
}

ORDER = list(FAKE.keys())

# Post-build state (multi-type): boundary moved 6→16 recognized families.
#   15 default-ON (6 original + 9 new); postgres is OFF-default OPT-IN (FP0 미달로 보류).
DEFAULT_ON_FAMILIES = ["anthropic", "openai", "xai", "google", "github", "aws",
                       "stripe", "slack", "github_pat", "jwt", "pem",
                       "sendgrid", "gcp", "npm", "twilio"]
OPTIONAL_FAMILIES = ["postgres"]
OPTIN_TYPES = {"postgres_uri"}  # FAKE key → scored with include_optional=True, flagged opt-in


def providers_hit(text, optin=False):
    return sorted({d["provider"] for d in detect_secrets(text, include_optional=optin)})


def main():
    print("# AXIS B — secret-type coverage boundary (0 API)  [post multi-type build]\n")
    print("Default-ON families (15): " + " / ".join(DEFAULT_ON_FAMILIES))
    print("Opt-in (OFF-default, FP0 미달): " + " / ".join(OPTIONAL_FAMILIES) + "\n")
    hdr = f"{'new type':22} {'fake fires?':11} {'as (label)':22} {'near-miss silent?':18} {'masked fake':22}"
    print(hdr)
    print("-" * len(hdr))

    green = {"axis": "B", "note": "detector coverage boundary post multi-type build, per-type "
             "counts (0 API, synthetic). 15 default-ON + 1 opt-in (postgres, FP0 미달로 보류).",
             "matcher_families": DEFAULT_ON_FAMILIES,
             "optional_families": OPTIONAL_FAMILIES,
             "types": {}}
    caught, missed = [], []
    fp_fired = []
    for t in ORDER:
        optin = t in OPTIN_TYPES
        fake_hit = providers_hit(FAKE[t], optin=optin)
        nm_hit = providers_hit(NEARMISS[t], optin=optin)
        is_caught = len(fake_hit) > 0
        (caught if is_caught else missed).append(t)
        if nm_hit:
            fp_fired.append((t, nm_hit))
        fake_col = "CAUGHT" if is_caught else "missed"
        as_col = (",".join(fake_hit) if fake_hit else "—") + (" (opt-in)" if optin else "")
        nm_col = "silent" if not nm_hit else f"FIRED {nm_hit}"
        print(f"{t:22} {fake_col:11} {as_col:22} {nm_col:18} {mask_secret(FAKE[t])[:22]}")
        green["types"][t] = {
            "detected": is_caught,
            "detected_as": fake_hit,          # scan provider label(s) it fired as
            "default_on": not optin,          # False = OFF-default opt-in (postgres)
            "nearmiss_fired_as": nm_hit,       # should be []
            "fake_masked": mask_secret(FAKE[t]),
        }

    print("-" * len(hdr))
    print(f"\n## Coverage boundary (per-type counts, NOT a %)  — boundary moved 6→16\n")
    print(f"  CAUGHT (now covered)               : {len(caught)}/{len(ORDER)}  {caught}")
    print(f"  MISSED (still uncovered)           : {len(missed)}/{len(ORDER)}  {missed}")
    print(f"  near-miss false-positives          : {len(fp_fired)}  {fp_fired}")
    print(f"  (postgres = caught only with opt-in; OFF-default due to benign-string FP)")

    green["summary"] = {
        "n_types": len(ORDER),
        "caught": caught, "n_caught": len(caught),
        "missed": missed, "n_missed": len(missed),
        "opt_in_types": sorted(OPTIN_TYPES),
        "nearmiss_false_positives": [{"type": t, "fired_as": h} for t, h in fp_fired],
    }
    with open("axis_b_coverage_green.json", "w", encoding="utf-8") as fh:
        json.dump(green, fh, ensure_ascii=False, indent=2)
    print("\n[green] → axis_b_coverage_green.json")


if __name__ == "__main__":
    main()
