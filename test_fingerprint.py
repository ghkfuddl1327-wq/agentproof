"""test_fingerprint.py — 감사 레코드 확장(type+scope+truncated hash) 결정론 회귀.

수락 기준을 게이트로 인코딩(오프라인·인메모리·라이브호출 0):
  (1) additive     : detect_secrets 핵심 매처 불변 + enrich 층에서 scope/fingerprint 만 추가.
  (2) raw value 0  : 심은 canary 실값이 레코드/리포트 어디에도 grep 되지 않음(마스킹+지문 어디에도).
  (3) 해시 결정론  : 동일 값 → 동일 fingerprint(correlate). 다른 값 → 다른 fingerprint.
  (4) GREEN-safe   : fingerprint 는 시크릿 아님(원문 substring 없음, one-way 해시 형식) → 감사 공유 가능.
  (+) type→scope   : PROVIDER_PATTERNS 패밀리 전수 scope 매핑 존재(미상 fallback 아님).

canary 는 형식 맞는 *합성 무효* 키(실제 발급 안 됨). 고엔트로피 → is_placeholder 통과.
"""
import json
import os
import tempfile

# salt 파일을 격리된 임시 경로로 고정(실 ~/.config 미오염). fingerprint 첫 호출 전에 설정.
os.environ["AGP_FINGERPRINT_SALT_FILE"] = os.path.join(
    tempfile.gettempdir(), "agp_fp_salt_test"
)
os.environ.pop("AGP_FINGERPRINT_SALT", None)
os.environ.pop("AGP_FINGERPRINT_SALT_DISABLE", None)

import agentproof_scan.scan as scan
import agentproof_scan.fingerprint as FP

# 형식 맞는 합성 무효 canary (고엔트로피 → is_placeholder 통과, 실제 키 아님).
CANARY = "sk-ant-Ab3xK9pQ2mZ7wR4tY6nL8vC1"
CANARY2 = "sk-ant-Zz9yX8wV7uT6sR5qP4oN3mL2kJ1h"


def _enriched_leaked(text):
    """detect_secrets → enrich_leaked 로 감사 레코드 leaked 리스트를 만든다(scan_once 조립층 축약)."""
    return [FP.enrich_leaked(it, scan.mask_secret) for it in scan.detect_secrets(text)]


# ── (1) additive: 핵심 매처 불변 + enrich 층에서만 확장 ─────────────────────────────
def test_detect_secrets_core_unchanged():
    """detect_secrets(핵심 매처)는 provider/match 만 반환 — scope/fingerprint 는 조립층에서만 추가."""
    hits = scan.detect_secrets(f"tok {CANARY}")
    assert hits == [{"provider": "anthropic", "match": CANARY}]


def test_additive_keys_only_extended():
    leaked = _enriched_leaked(f"key = {CANARY} 노출")
    assert len(leaked) == 1
    entry = leaked[0]
    assert entry["provider"] == "anthropic"            # provider(=type) 유지
    assert entry["match"] == scan.mask_secret(CANARY)   # 마스킹 값 유지
    assert entry["scope"] == FP.scope_for("anthropic")  # additive
    assert "fingerprint" in entry
    assert set(entry.keys()) == {"provider", "match", "scope", "fingerprint"}


# ── (2) raw value 0 ──────────────────────────────────────────────────────────────
def test_raw_value_never_present():
    leaked = _enriched_leaked(f"내부키 {CANARY} 는 숨김")
    blob = json.dumps(leaked, ensure_ascii=False)
    assert CANARY not in blob, "canary 원문이 레코드에 잔존(raw leak)"
    assert leaked[0]["fingerprint"].startswith("sha256-t")
    assert leaked[0]["match"] == "sk-ant-****"


def test_fingerprint_does_not_embed_raw():
    fp = FP.secret_fingerprint(CANARY)
    assert CANARY not in fp
    body = fp.split(":", 1)[1]
    for i in range(len(CANARY) - 5):
        assert CANARY[i:i + 6] not in body, "원문 substring 이 지문에 노출"


# ── (3) 결정론 ───────────────────────────────────────────────────────────────────
def test_fingerprint_deterministic_same_value():
    assert FP.secret_fingerprint(CANARY) == FP.secret_fingerprint(CANARY)


def test_fingerprint_distinct_for_distinct_values():
    assert FP.secret_fingerprint(CANARY) != FP.secret_fingerprint(CANARY2)


def test_fingerprint_correlates_same_secret():
    """같은 시크릿이 서로 다른 위치/레코드에 나오면 fingerprint 로 correlate(같은 값→같은 지문)."""
    a = _enriched_leaked(f"x {CANARY} x")[0]["fingerprint"]
    b = _enriched_leaked(f"y {CANARY} y")[0]["fingerprint"]
    assert a == b


# ── (4) GREEN-safe: one-way 해시 형식, 절단 자기서술 + salt ─────────────────────────
def test_fingerprint_is_truncated_oneway_form():
    fp = FP.secret_fingerprint(CANARY)
    assert fp.startswith("sha256-t48:"), f"예상 형식 아님: {fp}"
    body = fp.split(":", 1)[1]
    assert len(body) == FP.DEFAULT_HEX_LEN and all(c in "0123456789abcdef" for c in body)


def test_truncation_length_configurable():
    short = FP.secret_fingerprint(CANARY, hex_len=6)
    assert short.startswith("sha256-t24:") and len(short.split(":", 1)[1]) == 6


def test_salt_changes_fingerprint():
    unsalted = FP.secret_fingerprint(CANARY, salt="")
    a = FP.secret_fingerprint(CANARY, salt="deploy-A")
    b = FP.secret_fingerprint(CANARY, salt="deploy-B")
    assert unsalted != a != b and unsalted != b
    assert a == FP.secret_fingerprint(CANARY, salt="deploy-A")


def test_salt_on_by_default():
    """per-deployment salt 기본 ON — 명시적 무염과 다름, 그러나 배포내 결정론."""
    default = FP.secret_fingerprint(CANARY)
    assert default != FP.secret_fingerprint(CANARY, salt=""), "기본이 무염과 동일 — salt 미적용"
    assert default == FP.secret_fingerprint(CANARY)


def test_salt_disable_env_reverts_to_unsalted():
    os.environ["AGP_FINGERPRINT_SALT_DISABLE"] = "1"
    try:
        assert FP.secret_fingerprint(CANARY) == FP.secret_fingerprint(CANARY, salt="")
    finally:
        os.environ.pop("AGP_FINGERPRINT_SALT_DISABLE", None)


def test_deployment_salt_persists_and_is_private():
    s1 = FP._load_or_create_deployment_salt()
    s2 = FP._load_or_create_deployment_salt()
    assert s1 == s2 and s1
    path = FP._salt_file_path()
    assert os.path.exists(path)
    assert (os.stat(path).st_mode & 0o077) == 0, "salt 파일 권한이 0600 아님"


# ── (+) type→scope: PROVIDER_PATTERNS 패밀리 전수 매핑 존재 ─────────────────────────
def test_every_family_has_scope():
    for fam, _ in scan.PROVIDER_PATTERNS:
        assert fam in FP.TYPE_SCOPE, f"{fam} scope 매핑 누락"
        assert FP.scope_for(fam) != FP.UNKNOWN_SCOPE, f"{fam} scope 가 미상 fallback"


def test_unknown_type_falls_back_not_raises():
    assert FP.scope_for("nonexistent_family") == FP.UNKNOWN_SCOPE


if __name__ == "__main__":
    fails = []
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS  {name}")
            except Exception as e:  # noqa: BLE001
                print(f"FAIL  {name}: {e!r}")
                fails.append(name)
    print("-" * 50)
    print("ALL GREEN ✔" if not fails else f"{len(fails)} FAIL ✗ {fails}")
    raise SystemExit(1 if fails else 0)
