"""test_reasoning_scan.py — reasoning-scan (a) first-class 오프라인 결정론 회귀.

전부 GREEN·인메모리·라이브호출 0. 전체리포트 골든 불필요 — 순수 탐지기 층 + surface
분리 규율만 검증한다. 수락기준 케이스1/2/3 + freeze 불가침을 커버.

정직화 표기: "매처 재사용, 표면·provenance 신규." (케이스1이 '재사용'을 함수 동일성으로 증명.)
"""
import json

import agentproof_scan.scan as scan
import agentproof_scan.reasoning_scan as RS
from agentproof_scan.adapters.simple_chatbot_canary import CANARY_FAKE_SECRET


# ── 케이스1: reasoning-scan 미호출 시 메인 scan 무영향(매처 재사용, 재구현 0) ──────
def test_matcher_is_reused_not_reimplemented():
    """reasoning_scan 은 scan 의 매처를 재사용한다(같은 함수 객체) — 신규 매칭로직 0."""
    assert RS.detect_secrets is scan.detect_secrets
    assert RS.detect_prompt_disclosure is scan.detect_prompt_disclosure
    assert RS.mask_secret is scan.mask_secret


def test_import_does_not_mutate_scan():
    """reasoning_scan import 가 scan 의 탐지 동작을 바꾸지 않는다(monkeypatch 없음)."""
    hits = scan.detect_secrets(f"key={CANARY_FAKE_SECRET}")
    assert len(hits) == 1 and hits[0]["provider"] == "anthropic"


# ── 케이스2: 호출 + reasoning 필드 부재 → not_applicable('표면 미접근', clean 아님) ──
def test_reasoning_absent_is_not_applicable():
    rep = RS.scan_surfaces(answer_text="안녕하세요, 도와드릴게요.", reasoning_text=None)
    r = rep["surfaces"]["reasoning"]
    assert r["scanned"] is False
    assert r["status"] == "not_applicable"
    assert "미접근" in r["reason"]  # 'clean'/leak:0 로 표기하지 않음
    # reasoning 표면 finding 은 없고, final_output 은 정상 스캔(clean).
    assert not any(f["surface"] == RS.REASONING for f in rep["findings"])
    assert rep["surfaces"]["final_output"]["scanned"] is True


def test_no_reasoning_demo_target_not_applicable():
    rep = RS.scan_demo_target("reasoning_demo_no_reasoning")
    assert rep["surfaces"]["reasoning"]["status"] == "not_applicable"


# ── 케이스3: reasoning 에 심은 합성 canary → surface=reasoning 별도 카운트, 병합 X ──
def test_reasoning_only_leak_tagged_and_not_merged():
    rep = RS.scan_demo_target("reasoning_demo_canary")
    fo = rep["surfaces"]["final_output"]
    rs = rep["surfaces"]["reasoning"]

    # 최종답변은 clean, 추론 표면에서만 leak — 표면별로 분리 집계.
    assert fo["leak_count"] == 0
    assert rs["leak_count"] == 1

    # finding 은 surface 로 태깅되고, reasoning finding 이 존재.
    reasoning_findings = [f for f in rep["findings"] if f["surface"] == RS.REASONING]
    assert len(reasoning_findings) == 1 and reasoning_findings[0]["leak"] is True

    # 병합 금지: 최종답변 표면엔 leak finding 이 없어야 한다.
    fo_leaks = [
        f for f in rep["findings"] if f["surface"] == RS.FINAL_OUTPUT and f["leak"]
    ]
    assert fo_leaks == []


def test_secret_is_masked_never_raw():
    """리포트 전체에 실측 시크릿 원문이 절대 등장하지 않는다(마스킹 무조건)."""
    rep = RS.scan_demo_target("reasoning_demo_canary")
    assert CANARY_FAKE_SECRET not in json.dumps(rep, ensure_ascii=False)


def test_no_merged_leak_count_field():
    """설계상 병합 leak_count 를 두지 않는다 — 카운트는 surfaces.<name> 아래에만."""
    rep = RS.scan_demo_target("reasoning_demo_canary")
    assert "leak_count" not in rep  # top-level 병합 카운트 부재
    assert "leak_count" in rep["surfaces"]["final_output"]
    assert "leak_count" in rep["surfaces"]["reasoning"]


def test_clean_demo_passes():
    """정상 에이전트(두 표면 clean)는 finding 0 — FP=0."""
    rep = RS.scan_demo_target("reasoning_demo_clean")
    assert rep["findings"] == []
    assert rep["surfaces"]["final_output"]["leak_count"] == 0
    assert rep["surfaces"]["reasoning"]["leak_count"] == 0


# ── trace 경로(주 사용경로) 스모크 ───────────────────────────────────────────────
def test_trace_record_with_reasoning_leak():
    rec = {"answer_text": "요약만 제공합니다.", "reasoning_text": f"키 {CANARY_FAKE_SECRET} 는 숨긴다."}
    rep = RS.scan_trace(rec, target="trace_smoke")
    assert rep["surfaces"]["reasoning"]["leak_count"] == 1
    assert rep["surfaces"]["final_output"]["leak_count"] == 0
    assert rep["target"] == "trace_smoke"


def test_trace_record_without_reasoning_field():
    rep = RS.scan_trace({"answer_text": "안녕하세요."})
    assert rep["surfaces"]["reasoning"]["status"] == "not_applicable"


# NOTE(공개 트리): 사설의 probe_freeze 지문 불가침 테스트 2건은 여기서 제외한다.
# probe_freeze 는 *사설* PROBE_SPECS 동결 지문(sha256:51780d46…)을 지키는 측정-무결성
# 가드이고, 공개 프로브 세트는 그와 다른 집합이라 그 지문이 성립하지 않는다. 공개에
# 옮기면 무의미하거나 거짓 GREEN 이 된다. 아래 '그림자화 금지' 불변식만 유지한다.
def test_reasoning_scan_defines_no_probe_specs():
    """reasoning_scan 은 PROBE_SPECS 를 정의/그림자화하지 않는다(지문 소스 불변)."""
    assert not hasattr(RS, "PROBE_SPECS")


if __name__ == "__main__":
    fails = []
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS  {name}")
            except Exception as e:  # noqa: BLE001 — 자체 러너, 모든 실패 수집
                print(f"FAIL  {name}: {e!r}")
                fails.append(name)
    print("-" * 50)
    print("ALL GREEN ✔" if not fails else f"{len(fails)} FAIL ✗ {fails}")
    raise SystemExit(1 if fails else 0)
