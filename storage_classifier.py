"""storage_classifier.py — thin, additive validator: is a detected secret value sitting in
plaintext AT REST on a storage surface, or is it a safe env-reference / placeholder?

Independent of reverify (which stays single-purpose). Does NOT modify scan / detect_secrets /
PROVIDER_PATTERNS / regex / is_placeholder (681f1a7 lock). It REUSES:
  - scan.is_placeholder   (the existing entropy/keyword dummy gate — first-pass, unchanged)
and adds local helpers (_read_target, _ext, _local_placeholder, _is_example_file) so this
module depends only on scan(public) + stdlib — no cross-import into other modules.

v2: FIX 1 annotated-assignment FN, FIX 2 classifier-local placeholder FP, FIX 3 explicit example-file
rule. Honest degrade: no file context -> UNKNOWN_CONTEXT, never asserts PLAINTEXT. Values never echoed.
"""
import os
import re

from scan import is_placeholder          # reuse existing placeholder gate (first pass, unchanged)


def _read_target(path):
    """Read a target file's text (stdlib open().read()). Local helper so this module
    depends only on scan(public) + stdlib — no cross-import into other modules."""
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()

# storage surfaces where a literal secret is plaintext-at-rest by virtue of the file type
STORAGE_EXTS = {".env", ".yaml", ".yml", ".json", ".md", ".toml", ".ini", ".cfg"}

# a .py assignment to a credential-ish name (KEY/TOKEN/SECRET/PASSWORD), case-insensitive,
# tolerating an optional PEP-526 annotation between the name and '=' (FIX 1):
#   SECRET_KEY = "..."          and   SECRET_KEY: str = "..."   and   X: Dict[str, str] = "..."
_SENSITIVE_NAME = re.compile(
    r"(?i)\w*(?:KEY|TOKEN|SECRET|PASSWORD)\w*\s*(?::\s*[\w\[\],. ]+)?\s*="
)

# classifier-local placeholder set (FIX 2) — conventional fill-me-in values that
# scan.is_placeholder misses (e.g. CHANGE_ME). Compared after normalization (lower, strip _-<>{} ).
LOCAL_PLACEHOLDERS = {
    "changeme", "replaceme", "yourkeyhere", "placeholder",
    "example", "dummy", "xxx", "todo",
}


def _ext(path):
    """Lowercased file extension, handling dotfiles (`.env` -> `.env`, not '')."""
    base = os.path.basename(path or "").lower()
    root, ext = os.path.splitext(base)
    if not ext and base.startswith("."):
        return base          # dotfile like ".env"
    return ext


def _local_placeholder(value):
    """FIX 2 — conventional placeholder values missed by the core gate, caught classifier-side
    (core scan.is_placeholder is NOT edited). Returns True for CHANGE_ME / REPLACE_ME /
    YOUR_KEY_HERE / <...> / {...} and similar."""
    v = (value or "").strip()
    # a value wrapped in <...> or {...} is a fill-me-in template token
    if (v.startswith("<") and v.endswith(">")) or (v.startswith("{") and v.endswith("}")):
        return True
    norm = re.sub(r"[_\-<>{} ]", "", v.lower())
    return norm in LOCAL_PLACEHOLDERS


def _is_example_file(path):
    """FIX 3 — example/sample/template files hold fake values by convention -> PLACEHOLDER.
    Explicit rule (not the accidental _ext('.env.example') == '.example' miss)."""
    base = os.path.basename(path or "").lower()
    return any(tok in base for tok in (".example", ".sample", ".template"))


def classify_storage_exposure(match_value, file_path):
    """Classify how a detected secret VALUE is exposed, given the file it came from.

    Returns one of:
      "PLAINTEXT_AT_REST" | "ENV_REFERENCE" | "PLACEHOLDER" | "UNKNOWN_CONTEXT"

    Precedence (mirrors reverify's guard-first discipline):
      1. no file context                    -> UNKNOWN_CONTEXT  (never assert PLAINTEXT)
      2. core is_placeholder dummy value     -> PLACEHOLDER  (unchanged first pass)
      2b. classifier-local placeholder (FIX2) -> PLACEHOLDER
      2c. example/sample/template file (FIX3) -> PLACEHOLDER
      3. literal absent + env read present   -> ENV_REFERENCE (safe, not flagged)
      4. literal present on a storage ext    -> PLAINTEXT_AT_REST
      5. literal present in .py assigned to a *_KEY/_TOKEN/_SECRET/_PASSWORD name
         (annotation-tolerant, FIX1)         -> PLAINTEXT_AT_REST
      6. else (present but unrecognized)     -> UNKNOWN_CONTEXT (stay honest)
    """
    # 1) guard FIRST — pure model-output text, no storage signal to reason about
    if not file_path:
        return "UNKNOWN_CONTEXT"

    # 2) dummy/placeholder values are not a real exposure (core gate first pass, unchanged)
    if is_placeholder(match_value):
        return "PLACEHOLDER"
    # 2b) classifier-local placeholder guard (FIX 2 — does not touch core)
    if _local_placeholder(match_value):
        return "PLACEHOLDER"
    # 2c) example/sample/template files hold fake values by convention (FIX 3)
    if _is_example_file(file_path):
        return "PLACEHOLDER"

    try:
        text = _read_target(file_path)
    except OSError:
        return "UNKNOWN_CONTEXT"   # unreadable -> no storage signal, degrade honestly

    present = match_value in (text or "")

    # 3) literal absent but the file reads from the environment -> safe reference
    if not present and ("os.environ" in text or "os.getenv" in text):
        return "ENV_REFERENCE"

    ext = _ext(file_path)

    # 4) literal present on a storage surface (config/markup/env file) -> plaintext at rest
    if present and ext in STORAGE_EXTS:
        return "PLAINTEXT_AT_REST"

    # 5) literal present in a .py, assigned to a credential-ish name -> plaintext at rest
    if present and ext == ".py":
        for line in text.splitlines():
            if match_value in line and _SENSITIVE_NAME.search(line):
                return "PLAINTEXT_AT_REST"

    # 6) present but not a recognized storage surface — do NOT over-assert
    return "UNKNOWN_CONTEXT"
