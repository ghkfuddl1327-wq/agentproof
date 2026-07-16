"""
test_secrets_integrity.py — detect_secrets regex 경로 무결성 회귀

핵심 발견(R3): AWS 패턴(AKIA+16)이 대문자/숫자 밀집 텍스트(base32 등)에서
  length-FP. 엔트로피 게이트(2.5)는 고엔트로피 우연일치를 못 막음 → FP가 게이트 통과.
  → 래더 "FP 0"은 짧은 clean 한정. 긴 base32 출력에선 phantom AWS 키 오탐.

결선 완료: SI.real_detect_secrets=scan.detect_secrets, SI.real_is_placeholder=scan.is_placeholder.
"""
import random
import string

import secrets_integrity as SI


def test_round_trip_and_greedy():
    """R1/R5: 합성 키 탐지 + 패딩 후에도 탐지."""
    fails = SI.check(SI.real_detect_secrets, SI.real_is_placeholder, n=3000)
    assert not fails["R1"], f"R1 위반: {fails['R1'][:3]}"
    assert not fails["R5"], f"R5 위반: {fails['R5'][:3]}"


def test_attribution_no_double_count():
    """R2: sk-ant- 가 anthropic 단독 (openai 이중계수 0)."""
    fails = SI.check(SI.real_detect_secrets, SI.real_is_placeholder, n=3000)
    assert not fails["R2"], f"R2 이중계수: {fails['R2'][:3]}"


def test_entropy_gate_passes_real_keys():
    """R4: 형식 맞는 합성 키는 is_placeholder에 안 걸림."""
    fails = SI.check(SI.real_detect_secrets, SI.real_is_placeholder, n=3000)
    assert not fails["R4"], f"R4 키가 placeholder로 제외됨: {fails['R4'][:3]}"


def test_aws_length_fp_exists():
    """R3 ★ 발견 고정: AWS 패턴이 긴 대문자/숫자(base32)에서 FP.
    이 테스트 통과 = '래더 FP 0은 짧은 clean 한정' 사실이 유지됨."""
    rng = random.Random(7)
    b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    fp = 0
    for _ in range(500):
        blob = "".join(rng.choice(b32) for _ in range(20000))
        if SI.real_detect_secrets(blob):
            fp += 1
    assert fp > 0, "AWS length-FP 미관측 — 패턴/임계 변경됐는지 재검토"
    # FP의 provider가 aws임을 확인
    hit = SI.real_detect_secrets("".join(rng.choice(b32) for _ in range(50000)))
    assert any(h["provider"] == "aws" for h in hit) or fp > 0


def test_entropy_gate_cannot_catch_high_entropy_fp():
    """R3 메커니즘: AWS 우연일치는 고엔트로피라 게이트 통과(못 막음)."""
    rng = random.Random(11)
    up = string.ascii_uppercase + string.digits
    s = "AKIA" + "".join(rng.choice(up) for _ in range(16))
    assert SI._shannon_entropy(s) > 2.5, "우연일치 엔트로피가 임계 이하 — 가정 깨짐"
    assert not SI.real_is_placeholder(s), "게이트가 고엔트로피 우연일치를 막음(예상과 다름)"


def test_coverage_boundary_sixteen_families():
    """R6(갱신): 커버리지 경계가 6→16 패밀리로 이동. Stripe sk_live_ 는 이제 'stripe'로
    잡힌다(예전엔 설계상 FN). 단 attribution 은 유지 — openai 로는 여전히 오귀속 안 됨
    (_ 때문에 sk-[A-Za-z0-9] 미매치). 고엔트로피 바디 필요(더미 억제와 분리)."""
    key = "sk_live_" + _alnum(random.Random(1327), 30)
    hits = SI.real_detect_secrets("key " + key)
    # 이제 stripe 로 잡힘 (경계 이동)
    assert any(h["provider"] == "stripe" for h in hits), "sk_live_ stripe 미탐 (경계 이동 회귀)"
    # attribution 불변: openai 로 오귀속되지 않음
    assert not any(h["provider"] == "openai" for h in hits), \
        "sk_live_ 가 openai 로 오귀속 — attribution 회귀"


# ── TC: modern OpenAI typed keys (sk-proj-/svcacct-/admin-) detect-expansion ──
# 합성 *무효* 키만. base64url 바디 80+ (실 키 ~155, 충돌 마진 큼). 평문 최소.
_B64URL = string.ascii_letters + string.digits + "-_"
_ALNUM = string.ascii_letters + string.digits


def _b64url(rng, n):
    return "".join(rng.choice(_B64URL) for _ in range(n))


def _alnum(rng, n):
    return "".join(rng.choice(_ALNUM) for _ in range(n))


def test_openai_typed_detected_once():
    """TC1: sk-proj-/svcacct-/admin- (바디 80+) → openai 정확히 1회 탐지."""
    rng = random.Random(2026)
    for typ in ("proj", "svcacct", "admin"):
        key = f"sk-{typ}-" + _b64url(rng, 90)
        hits = SI.real_detect_secrets(f"OPENAI_API_KEY={key} end")
        oa = [h for h in hits if h["provider"] == "openai"]
        assert len(oa) == 1, f"sk-{typ}- 탐지 {len(oa)}회 (1 기대): {oa}"
        assert oa[0]["match_len"] == len(key), \
            f"sk-{typ}- 매치 길이 {oa[0]['match_len']} != 전체 {len(key)} (부분매치?)"


def test_openai_typed_double_match_trap_counts_once():
    """TC2 ★(R2-계열): 바디 안에 내부 'sk-<20+alnum>' 런을 일부러 심은 typed 키.
    merged 단일 regex의 non-overlapping findall → 풀키 1회만, 내부 슬라이스 이중계수 0."""
    rng = random.Random(7)
    trap = "sk-proj-" + _alnum(rng, 50) + "sk-" + _alnum(rng, 40)  # 바디 93 (>=80)
    hits = SI.real_detect_secrets("x " + trap + " y")
    oa = [h for h in hits if h["provider"] == "openai"]
    assert len(oa) == 1, f"트랩 이중계수 {len(oa)}회 (1 기대): {oa}"
    assert oa[0]["match_len"] == len(trap), \
        f"트랩 매치 길이 {oa[0]['match_len']} != 전체 {len(trap)} (내부 슬라이스 매치됨)"


def test_openai_typed_fp_negatives_zero():
    """TC3: 정상 텍스트/타 provider FP=0 (openai로 안 잡힘)."""
    rng = random.Random(99)
    negatives = [
        "see sk-learn and scikit-learn in the docs",          # 하이픈 단어
        "route sk-this-is-a-very-long-slug-name-here-and-more",  # 하이픈 슬러그
        "key sk_live_" + _alnum(rng, 40),                      # Stripe (_ → FN, R6)
        "tok sk-ant-" + _b64url(rng, 40),                      # anthropic 전용
    ]
    for t in negatives:
        hits = SI.real_detect_secrets(t)
        assert not any(h["provider"] == "openai" for h in hits), \
            f"openai FP 발생: {t[:24]!r} → {hits}"
    # sk-ant- 는 anthropic 으로는 잡혀야 함(R2 attribution 유지 확인)
    ant = SI.real_detect_secrets("tok sk-ant-" + _b64url(random.Random(8), 40))
    assert any(h["provider"] == "anthropic" for h in ant), "sk-ant- anthropic 미탐"


def test_openai_typed_no_new_length_fp():
    """TC4 (R3 미러): typed 대안(sk-proj-/svcacct-/admin-)은 긴 benign blob에서 신규 FP=0.
    주의: legacy sk-[A-Za-z0-9]{20,} 의 길이-FP는 *기존* 앵커부재 findall 현상으로 존속한다
    (AWS R3와 동일 메커니즘, 본 변경과 무관). 여기선 'typed prefix' 우연일치만 0임을 고정한다.
    benign blob은 시크릿이 아니므로 prefix 검사 위해 scan.detect_secrets 매치 사용(평문 비밀 아님)."""
    from agentproof_scan.scan import detect_secrets as _ds
    rng = random.Random(1327)
    typed_prefixes = ("sk-proj-", "sk-svcacct-", "sk-admin-")
    typed_fp = 0
    for _ in range(400):
        blob = "".join(rng.choice(_B64URL) for _ in range(20000))
        for h in _ds(blob):
            if h["provider"] == "openai" and h["match"].startswith(typed_prefixes):
                typed_fp += 1
    assert typed_fp == 0, f"typed 대안 신규 length-FP {typed_fp}건 (0 기대)"


def test_openai_legacy_still_detected():
    """TC5: legacy sk-<20+ alnum> 여전히 openai 탐지(회귀 없음)."""
    key = "sk-" + _alnum(random.Random(5), 40)
    hits = SI.real_detect_secrets(f"OPENAI_API_KEY={key}")
    assert any(h["provider"] == "openai" for h in hits), "legacy sk- 미탐 (회귀)"


# ── MULTI-TYPE 확장 게이트 (6→16). FN0(신규 10 발화) / FP0(더미 침묵 + length-FP 0) ──
# 오라클 재사용: score_axis_b_coverage.FAKE/NEARMISS 가 10 타입의 format-correct 가짜와
# benign near-miss 를 이미 인코딩한다. FAKE key → scan provider label 매핑.
import score_axis_b_coverage as AXB  # noqa: E402
from agentproof_scan.scan import detect_secrets as _ds  # noqa: E402

# default-ON 9 패밀리 (FAKE key → scan provider label)
DEFAULT9 = {
    "stripe_secret": "stripe", "slack_bot": "slack",
    "github_finegrained": "github_pat", "jwt": "jwt",
    "pem_private_key": "pem", "sendgrid": "sendgrid",
    "gcp_oauth_secret": "gcp", "npm_token": "npm", "twilio_api_key": "twilio",
}
DEFAULT9_PROVIDERS = set(DEFAULT9.values())
NEW_ALL = DEFAULT9_PROVIDERS | {"postgres"}  # 16 = 6 + 9 default + 1 optional


def test_new_families_coverage():
    """default-ON 9 패밀리: FAKE 는 기대 provider 로 ≥1 탐지(FN0), NEARMISS 는 침묵(FP0)."""
    for fk, provider in DEFAULT9.items():
        fhits = SI.real_detect_secrets(AXB.FAKE[fk])
        assert any(h["provider"] == provider for h in fhits), \
            f"{fk}: {provider} 미탐 (FN) → {[h['provider'] for h in fhits]}"
        nhits = SI.real_detect_secrets(AXB.NEARMISS[fk])
        assert not nhits, f"{fk} NEARMISS 오탐(FP): {nhits}"


def test_postgres_is_optional_off_by_default():
    """postgres 는 OFF-default(옵트인): 기본 detect_secrets 에선 FAKE 도 미발화.
    include_optional=True 로만 켜지며, 켜면 비밀번호를 postgres 로 잡는다(NEARMISS 는 침묵)."""
    fake = AXB.FAKE["postgres_uri"]
    # 기본: postgres 미발화 (FP0 미달이라 shipped 기본 OFF)
    assert not any(h["provider"] == "postgres" for h in _ds(fake)), \
        "postgres 가 기본 ON — 옵트인이어야 함"
    # 옵트인: 발화
    on = _ds(fake, include_optional=True)
    assert any(h["provider"] == "postgres" for h in on), "옵트인해도 postgres 미탐"
    assert not _ds(AXB.NEARMISS["postgres_uri"], include_optional=True), \
        f"postgres NEARMISS 오탐: {_ds(AXB.NEARMISS['postgres_uri'], include_optional=True)}"


def test_new_families_no_length_fp():
    """신규 패밀리(default 9 + optional postgres): 400×20000-char base64url benign blob 에서
    우연일치 FP=0. base64url=[A-Za-z0-9_-] 엔 '.'/'/'/':'/'@'/literal-word/lowercase-hex-run/
    \\d{10,} 구조가 없어 모두 구조적으로 미발화 — TC4 length-FP 게이트의 신규판.
    postgres 도 옵트인 켠 상태로 함께 스윕(옵트인 시에도 length-FP 0 확인)."""
    rng = random.Random(1327)
    new_fp = 0
    for _ in range(400):
        blob = "".join(rng.choice(_B64URL) for _ in range(20000))
        new_fp += sum(1 for h in _ds(blob, include_optional=True) if h["provider"] in NEW_ALL)
    assert new_fp == 0, f"신규 패밀리 length-FP {new_fp}건 (0 기대)"


if __name__ == "__main__":
    fails = []
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS  {name}")
            except AssertionError as e:
                print(f"FAIL  {name}: {e}")
                fails.append(name)
    print("-" * 50)
    print("ALL GREEN ✔" if not fails else f"{len(fails)} FAIL ✗ {fails}")
    raise SystemExit(1 if fails else 0)
