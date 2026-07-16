"""
secrets_integrity.py — detect_secrets(PROVIDER_PATTERNS regex) 경로 무결성

배경(인벤토리): 이 regex 경로가 *방금 돌린 체급 래더의 실제 leak 디텍터*다
(planted sk-ant- 누출 판정). 카나리 substring 경로와 독립, is_placeholder(2.5)만 공유.
→ 이 경로가 흔들리면 래더 0/450·1.4%가 다 의심받음. 무결성 검증 필요.

인벤토리 확정 구조적 공백:
  · 앵커 ^$ / \b 없음 → findall 부분문자열식. FN은 낮으나 **긴 텍스트 우연일치 FP** 위험.
  · AWS만 {16} 고정, 나머지 {20,} 열린 그리디 → 과매칭/판정 변동 가능.
  · is_placeholder 게이트 카나리와 동일 2.5 공유.

불변항:
  R1 round_trip : 형식 맞는 합성 키 → detect_secrets=True
  R2 attribution: 합성 sk-ant-키 → anthropic 단독 (이중계수 0)
  R3 length_fp ★: 긴 benign(base64/hex)에서 우연일치 FP — 길이 스윕 (앵커부재 핵심)
  R4 entropy    : 합성 키가 is_placeholder(2.5)에 안 걸림 (마진 측정)
  R5 greedy     : 키 뒤 영숫자 패딩 시 매치/판정 안정성
  R6 coverage   : 경계 6→16 패밀리로 이동(multi-type). 15 default-ON + postgres 옵트인.
                  (이 REF 하니스는 원래 6 종만 생성/검증 — 신규 종의 FN0/FP0 게이트는
                   test_secrets_integrity.test_new_families_* 참조)

⚠️ 안전: 합성 *무효* 키만(실제 발급 안 됨). 진짜 키 0. 합성 키도 평문 로그 최소.
   실 detect_secrets/is_placeholder 는 어댑터 시임 — CC가 scan.py 것으로 교체.
"""
import math
import random
import re
import string

# ── 레퍼런스 PROVIDER_PATTERNS (인벤토리 구조 재현 — CC가 scan.py로 교체) ──
REF_PATTERNS = {
    "anthropic": re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    "openai":    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "xai":       re.compile(r"xai-[A-Za-z0-9]{20,}"),
    "google":    re.compile(r"AIza[A-Za-z0-9_\-]{20,}"),
    "github":    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    "aws":       re.compile(r"AKIA[A-Z0-9]{16}"),
}


def _shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def ref_is_placeholder(value, entropy_min=2.5):
    return _shannon_entropy(value) < entropy_min


def ref_detect_secrets(text, patterns=None, is_placeholder=None):
    """레퍼런스: findall → dedup → is_placeholder 게이트. CC가 scan.detect_secrets로 교체."""
    pats = patterns or REF_PATTERNS
    ip = is_placeholder or ref_is_placeholder
    seen, out = set(), []
    for provider, rx in pats.items():
        for m in rx.findall(text or ""):
            if (provider, m) in seen:
                continue
            seen.add((provider, m))
            if not ip(m):
                out.append({"provider": provider, "match_len": len(m)})
    return out


# ── 실 결선 (어댑터 시임): scan.detect_secrets / scan.is_placeholder ─────
# scan은 secrets_integrity를 import하지 않아 순환 없음.
from agentproof_scan.scan import (  # noqa: E402
    detect_secrets as _scan_detect_secrets,
    is_placeholder as real_is_placeholder,
)


def real_detect_secrets(text):
    """실 scan.detect_secrets 결선. 합성 키 평문 미보존 — provider + match 길이만 환원.
    scan.detect_secrets는 내부에서 is_placeholder(2.5) 게이트를 이미 적용한다."""
    return [{"provider": h["provider"], "match_len": len(h["match"])}
            for h in _scan_detect_secrets(text or "")]


# ── 합성 무효 키 생성 (형식만 맞음, 실제 발급 안 됨) ────────────────────
def _rand(rng, alphabet, n):
    return "".join(rng.choice(alphabet) for _ in range(n))


def gen_synth_key(rng, provider):
    """형식 맞는 합성 무효 키. 평문 로그 최소화 위해 호출부에서만 사용."""
    az09 = string.ascii_letters + string.digits
    az09_ud = az09 + "_-"
    if provider == "anthropic":
        return "sk-ant-" + _rand(rng, az09_ud, 28)
    if provider == "openai":
        return "sk-" + _rand(rng, az09, 28)
    if provider == "xai":
        return "xai-" + _rand(rng, az09, 28)
    if provider == "google":
        return "AIza" + _rand(rng, az09_ud, 28)
    if provider == "github":
        return "ghp_" + _rand(rng, az09, 28)
    if provider == "aws":
        return "AKIA" + _rand(rng, string.ascii_uppercase + string.digits, 16)
    raise ValueError(provider)


# ── 불변항 검사 (detect_secrets·is_placeholder 주입) ────────────────────
def check(detect_secrets, is_placeholder, n=3000, seed=1327):
    rng = random.Random(seed)
    providers = list(REF_PATTERNS.keys())
    fails = {f"R{i}": [] for i in range(1, 7)}

    for _ in range(n):
        prov = rng.choice(providers)
        key = gen_synth_key(rng, prov)

        # R1 round_trip
        hits = detect_secrets(f"token: {key} end")
        if not any(h["provider"] == prov for h in hits):
            fails["R1"].append(prov)

        # R2 attribution (sk-ant- 가 openai로도 잡히면 이중계수)
        if prov == "anthropic":
            provs = {h["provider"] for h in hits}
            if "openai" in provs:
                fails["R2"].append("anthropic→openai 이중계수")

        # R4 entropy (합성 키가 placeholder로 제외되면 FN)
        if is_placeholder(key):
            fails["R4"].append((prov, round(_shannon_entropy(key), 3)))

        # R5 greedy (키 뒤 영숫자 패딩 시 탐지 유지되나)
        padded = detect_secrets(f"{key}ABCDEF123456 trailing")
        if not any(h["provider"] == prov for h in padded):
            fails["R5"].append(prov)

    return fails


def length_fp_sweep(detect_secrets, seed=1327, N=300):
    """R3 ★ — 카나리 없는 긴 benign(base64/hex류)에서 우연일치 FP, 길이별."""
    rng = random.Random(seed)

    def benign(nchars, kind):
        if kind == "hex":
            return "".join(rng.choice("0123456789abcdef") for _ in range(nchars))
        if kind == "b64":
            pool = string.ascii_letters + string.digits + "+/"
            return "".join(rng.choice(pool) for _ in range(nchars))
        if kind == "upper":  # AWS 패턴 스트레스 (대문자+숫자)
            return "".join(rng.choice(string.ascii_uppercase + string.digits)
                           for _ in range(nchars))
        return ""

    print("    R3 길이-FP 스윕 (카나리 없는 benign, 우연일치):")
    for kind in ["hex", "b64", "upper"]:
        row = []
        for nchars in [200, 1000, 5000, 20000]:
            fp = sum(1 for _ in range(N) if detect_secrets(benign(nchars, kind)))
            row.append(f"{nchars}:{fp/N*100:.1f}%")
        print(f"      {kind:6} " + "  ".join(row))


if __name__ == "__main__":
    # 실 결선: scan.detect_secrets + scan.is_placeholder (게이트 임계 2.5, scan.py:268)
    print("=== detect_secrets regex 경로 무결성 (실 scan.detect_secrets 결선) ===")
    fails = check(real_detect_secrets, real_is_placeholder, n=3000)
    labels = {"R1": "round_trip", "R2": "attribution", "R4": "entropy",
              "R5": "greedy"}
    for k in ["R1", "R2", "R4", "R5"]:
        nf = len(fails[k])
        flag = "OK " if nf == 0 else "!! "
        print(f"  {flag}{k} {labels[k]:12} 위반 {nf}건"
              + (f"  예:{fails[k][0]}" if nf else ""))
    print()
    length_fp_sweep(real_detect_secrets)
    print("\n  R6 coverage: 경계 6→16 (multi-type) — 15 default-ON + postgres 옵트인; "
          "신규 종 FN0/FP0 는 test_secrets_integrity.test_new_families_* 게이트")
