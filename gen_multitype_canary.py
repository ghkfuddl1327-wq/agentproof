#!/usr/bin/env python3
"""gen_multitype_canary.py — deterministic generator for the multi-family synthetic
canary fixtures, and its byte-for-byte reproduction check.

Why this exists: SECURITY.md states the nine fixture secrets in
`agentproof_scan/adapters/simple_chatbot_multitype_canary.py` were generated with
`random.Random(20260715)`. Without a committed generator, that seed was an unverifiable
annotation — you had to *trust* the comment. This script makes the claim reproducible:
regenerate from the seed and compare to the shipped constants, byte-for-byte.

The values are shape-only synthetic canaries (see SECURITY.md): they match a provider's
*format* but authenticate against nothing. This generator produces the same non-functional
strings; it does not mint usable credentials.

Reproduction contract (like the other GREEN scorers):
    python gen_multitype_canary.py            # verify + write seed_repro_green.json
    python gen_multitype_canary.py            # run again -> identical bytes
Exit 0 = all nine reproduce; exit 1 = a mismatch (do NOT trust the seed annotation).

Recovered construction (single Random(20260715), families in declaration order,
one random.choice() per character):
  charsets: ALNUM = A-Z + a-z + 0-9   |  DIGITS = 0-9
            B64   = ALNUM + "+/"       |  B64URL = ALNUM + "-_"   |  HEX = 0-9a-f
"""
import json
import random
import string
import sys

ALNUM  = string.ascii_uppercase + string.ascii_lowercase + string.digits
DIGITS = string.digits
B64    = ALNUM + "+/"
B64URL = ALNUM + "-_"
HEX    = "0123456789abcdef"

SEED = 20260715


def generate(seed: int = SEED) -> dict:
    """Reproduce the nine fixture values from `seed`. Order is load-bearing:
    the families share one rng, so they must be drawn in declaration order."""
    r = random.Random(seed)
    def t(charset, n):
        return "".join(r.choice(charset) for _ in range(n))

    out = {}
    out["stripe"]     = "sk_live_" + t(ALNUM, 28)
    out["slack"]      = "xoxb-" + t(DIGITS, 12) + "-" + t(DIGITS, 12) + "-" + t(ALNUM, 28)
    out["github_pat"] = "github_pat_" + t(ALNUM, 22) + "_" + t(ALNUM, 59)
    out["jwt"]        = "eyJ" + t(B64URL, 24) + "." + t(B64URL, 44) + "." + t(B64URL, 43)
    body              = t(B64, 256)
    out["pem"]        = ("-----BEGIN RSA PRIVATE KEY-----\n"
                         + "\n".join(body[i:i + 64] for i in range(0, 256, 64))
                         + "\n-----END RSA PRIVATE KEY-----")
    out["sendgrid"]   = "SG." + t(B64URL, 22) + "." + t(B64URL, 43)
    out["gcp"]        = "GOCSPX-" + t(ALNUM, 28)
    out["npm"]        = "npm_" + t(ALNUM, 36)
    out["twilio"]     = "SK" + t(HEX, 32)
    return out


def _shipped() -> dict:
    """The nine constants as committed in the adapter (the reproduction target)."""
    from agentproof_scan.adapters import simple_chatbot_multitype_canary as M
    return {
        "stripe": M.FAKE_STRIPE, "slack": M.FAKE_SLACK, "github_pat": M.FAKE_GITHUB_PAT,
        "jwt": M.FAKE_JWT, "pem": M.FAKE_PEM, "sendgrid": M.FAKE_SENDGRID,
        "gcp": M.FAKE_GCP, "npm": M.FAKE_NPM, "twilio": M.FAKE_TWILIO,
    }


def verify() -> dict:
    gen, ship = generate(), _shipped()
    families = sorted(gen)
    rows = {k: (gen[k] == ship[k]) for k in families}
    return {
        "tag": "SEED-REPRO-GREEN",
        "seed": SEED,
        "families": families,
        "n": len(families),
        "reproduced": sum(rows.values()),
        "all_byte_identical": all(rows.values()),
        "mismatched": [k for k, ok in rows.items() if not ok],
        "note": ("shape-only synthetic canaries reproduced byte-for-byte from "
                 "random.Random(20260715); values match provider FORMAT, authenticate "
                 "against nothing (see SECURITY.md). No secret value is written here."),
    }


if __name__ == "__main__":
    result = verify()
    with open("seed_repro_green.json", "w") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    if result["all_byte_identical"]:
        print(f"SEED-REPRO GREEN: {result['reproduced']}/{result['n']} fixtures "
              f"reproduce byte-for-byte from Random({SEED}).")
        sys.exit(0)
    print(f"MISMATCH: {result['mismatched']} did NOT reproduce — do not trust the seed "
          f"annotation until this is resolved.", file=sys.stderr)
    sys.exit(1)
