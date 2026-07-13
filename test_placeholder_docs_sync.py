"""test_placeholder_docs_sync.py — 문서가 시키는 플레이스홀더는 코드가 반드시 거부한다.

PLACEHOLDER_ENV_VALUES 는 하드코딩된 목록이라 문서 드리프트로 다시 열린다:
README 나 .env.example 에 새 플레이스홀더를 쓰면, 유저는 그걸 붙여넣고, 스캐너는
그 값으로 API 를 호출하고, 실패하고, 결함 0건을 보고하고, 유저는 "안전"으로 읽는다.

그래서 **문서에서 파생시킨다**:

    README.md + .env.example 의 `KEY=<리터럴>` 우변 집합  ⊆  PLACEHOLDER_ENV_VALUES

문서에 새 플레이스홀더가 생기면 이 테스트가 먼저 깨진다. 플레이스홀더 집합과
README UNTESTED 표(→ untested_env)가 같은 논리다: 단일 원천에서 파생, 어긋나면 실패.

이 열거가 완전할 필요는 없다. 불완전성은 AgentCallError 가 받는다(잘못된 키 → 4xx →
ensure_ok → exit 1). 이건 그 위의 빠른 경로이고, 이 테스트는 그 경로를 문서와 묶는다.
"""
import pathlib
import re

from agentproof_scan.scan import PLACEHOLDER_ENV_VALUES, is_placeholder_env_value

ROOT = pathlib.Path(__file__).parent

# `GEMINI_API_KEY=PASTE_YOUR_KEY_HERE` / `echo 'MY_AGENT_KEY=sk-your-real-key'` 등에서
# 우변 리터럴만 뽑는다. 따옴표·공백·줄끝은 벗긴다.
_ASSIGN = re.compile(r"\b([A-Z][A-Z0-9_]{2,})=([^\s'\"`)>]+)")

# 문서에 등장하지만 플레이스홀더가 **아닌** 우변 — 실제 예시 값이거나 다른 문법.
_NOT_PLACEHOLDERS = {
    "1",  # AGP_ENABLE_OPTIONAL=1 같은 플래그
    "0",
    "true",
    "false",
    "us-east-1",
}


def _doc_literals():
    """README.md + .env.example 에서 `KEY=값` 우변 리터럴 집합을 뽑는다."""
    found = set()
    for name in ("README.md", ".env.example"):
        p = ROOT / name
        if not p.exists():
            continue
        for _key, value in _ASSIGN.findall(p.read_text(encoding="utf-8")):
            v = value.strip().strip("'\"").lower()
            # `{MY_AGENT_KEY}` 같은 env-ref 토큰과 실제 키 모양은 제외.
            if not v or v.startswith("{") or v in _NOT_PLACEHOLDERS:
                continue
            found.add(v)
    return found


def test_docs_actually_contain_placeholders():
    """추출기가 0개를 뽑고 조용히 통과하는 걸 막는다 (테스트를 테스트한다)."""
    lits = _doc_literals()
    assert lits, "문서에서 KEY=값 리터럴을 하나도 못 뽑았다 — 정규식이 죽었다"


def test_every_doc_placeholder_is_rejected_by_the_code():
    """문서가 붙여넣으라고 시킨 값은 전부 코드가 '키 없음'으로 취급해야 한다."""
    missed = sorted(v for v in _doc_literals() if not is_placeholder_env_value(v))
    assert not missed, (
        f"문서에 있으나 PLACEHOLDER_ENV_VALUES 가 모르는 값: {missed}. "
        "유저가 이 값을 붙여넣으면 스캔이 실패하고 0건을 '안전'으로 보고한다."
    )


def test_no_orphan_in_set_not_in_docs():
    """역방향: 집합의 모든 원소가 문서에 실재해야 한다 (고아 없음).

    docs⊆집합(위)만 검사하면 문서에서 사라진 리터럴이 집합에 남아 고아가 된다 —
    코드가 유저가 절대 안 볼 값을 거부한다. 발견 7: 'your_key_here' 가 그 고아였다.
    양방향으로 잠근다.
    """
    doc_lits = _doc_literals()
    orphans = sorted(v for v in PLACEHOLDER_ENV_VALUES if v.lower() not in doc_lits)
    assert not orphans, (
        f"집합에 있으나 문서에 없는 고아: {orphans}. 문서에서 사라진 리터럴은 "
        "집합에서도 빼라 — 아니면 코드가 아무도 안 붙여넣는 값을 거부한다."
    )


def test_matching_is_case_insensitive_and_strips_whitespace():
    for v in PLACEHOLDER_ENV_VALUES:
        assert is_placeholder_env_value(v.upper())
        assert is_placeholder_env_value(f"  {v}  ")


def test_a_real_looking_key_is_not_treated_as_placeholder():
    """실패 비용이 반대다 — 진짜 키를 플레이스홀더로 오판하면 스캔을 거부해 버린다."""
    assert not is_placeholder_env_value("AIzaSyD3fK9mQ7xR4tL8vN1wZ6yB3cD5hJ0pS7u")
    assert not is_placeholder_env_value("sk-ant-api03-9fK2mQ7xR4tL8vN1wZ6yB3cD5hJ0pS7u")


if __name__ == "__main__":
    fails = []
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS  {name}")
            except Exception as e:  # noqa: BLE001
                print(f"FAIL  {name}: {e}")
                fails.append(name)
    print("-" * 60)
    print("ALL GREEN ✔" if not fails else f"{len(fails)} FAIL ✗ → {fails}")
    raise SystemExit(1 if fails else 0)
