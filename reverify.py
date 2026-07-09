"""reverify.py — closed-loop fix verification (thin layer over the EXISTING detector).

This module adds NO new detection logic. It calls scan.detect_secrets (the real ladder
leak detector) twice — once on a "before" target, once on an "after" target — and uses a
local deterministic case-insensitive substring gate (_canary_match) to decide whether a
specific planted synthetic canary still leaks. The deterministic verdict:

    CLOSED      before leaks the canary AND after does NOT      (fix proven)
    NOT_CLOSED  after still leaks the canary                    (fix failed)
    INVALID     before does NOT leak the canary                 (nothing to prove)

The INVALID guard is mandatory and evaluated first: we never report CLOSED unless the
'before' target genuinely leaked the canary in the first place.

Inputs are TWO separate target files (before / after) — not in-place patching.
Secret/canary values are never printed; only verdicts and boolean leak flags are surfaced.

Not wired into any CLI surface — implementation + test only (shipping is a separate
decision, like the post-match validator).
"""

from collections import namedtuple

# Established no-cycle shim: scan never imports reverify (one-directional dependency).
from agentproof_scan.scan import detect_secrets            # existing detector — not reimplemented here

# verdict is the headline; before_leaked/after_leaked are the raw evidence.
Result = namedtuple("Result", ["verdict", "before_leaked", "after_leaked"])


def _canary_match(text, canary):
    # deterministic case-insensitive substring canary gate
    return canary.lower() in (text or "").lower()


def _read(path):
    """Read a target file's text. Inputs are file paths (before / after), not in-place."""
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _scan_leaks_canary(text, canary):
    """True iff the EXISTING detector surfaces a secret that IS our canary.

    Calls scan.detect_secrets (the real detect path) and uses a local case-insensitive
    substring gate to confirm the planted canary is among what leaked — no detection logic
    is reimplemented here.
    """
    return any(_canary_match(hit["match"], canary) for hit in detect_secrets(text or ""))


def reverify(target_before, target_after, canary):
    """Closed-loop verify: does the after-target prove the before-leak was closed?

    Returns a Result(verdict, before_leaked, after_leaked). verdict is one of
    "CLOSED" / "NOT_CLOSED" / "INVALID". The canary value is never echoed.
    """
    before_leaked = _scan_leaks_canary(_read(target_before), canary)
    after_leaked = _scan_leaks_canary(_read(target_after), canary)

    if not before_leaked:
        verdict = "INVALID"        # mandatory guard FIRST — before never leaked
    elif after_leaked:
        verdict = "NOT_CLOSED"     # after still leaks → fix failed
    else:
        verdict = "CLOSED"         # before leaked, after clean → fix proven

    return Result(verdict, before_leaked, after_leaked)
