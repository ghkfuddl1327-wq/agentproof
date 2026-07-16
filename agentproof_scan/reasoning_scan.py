"""reasoning_scan.py — reasoning-scan: 추론 채널까지 스캔하는 first-class 표면.

무엇: 자가호스팅 에이전트가 남긴 **reasoning trace**(추론 채널 + 최종답변)를 받아,
      두 표면 각각에서 시크릿 유출/시스템프롬프트 노출을 탐지한다. finding 은 표면
      (reasoning | final_output)별로 **분리**되며 절대 병합하지 않는다.

왜: 시크릿이 최종답변엔 안 보여도 추론(thinking) 채널엔 남는 실패모드가 있다. 최종
    답변만 스캔하는 도구는 이를 놓친다. reasoning-scan 은 그 표면을 별도로 계량한다.

스코프(중요): **자가호스팅 에이전트 + reasoning trace 를 제공할 수 있을 때에만** 유효.
              범용 스캐너가 아니며, 추론 채널을 노출하지 않는 타깃은 스캔할 수 없다.

정직화 표기: "매처 재사용, 표면·provenance 신규."
  - 재사용: scan.detect_secrets / scan.detect_prompt_disclosure (채널무관 순수함수),
            scan.mask_secret (마스킹). 신규 매칭로직 0.
  - 신규(=자체 FP/FN 회계 대상): reasoning_text 추출·정규화 배관 + surface/provenance 라벨.

무손상: 이 파일은 shipped scan.py 를 import 만 하고 편집하지 않는다(diff 0). probe_freeze
        지문(PROBE_SPECS)도 건드리지 않는다. OFF-default — scan.py 기본 경로에서 안 돎.

[커스터디] GREEN + 합성 fixture 만. 실제 키/raw/probe 원문 미접촉. 라이브 LLM 호출 0.
"""

import argparse
import json
from datetime import datetime, timezone

# ── 매처 재사용 (scan.py 를 import 만; 편집 없음) ───────────────────────────────
from .scan import detect_secrets, detect_prompt_disclosure, mask_secret
from .fingerprint import enrich_leaked  # type+scope+truncated-hash 감사 레코드(순수, additive)

from .reasoning_adapters import REASONING_DEMO_ADAPTERS, DEMO_TRIGGER

RULE = "secret-leak-v0"
SCAN_NAME = "reasoning-scan"
SCOPE_NOTE = (
    "자가호스팅 에이전트 + reasoning trace 제공 시에만 유효. 범용 스캐너 아님 — "
    "추론 채널을 노출하지 않는 타깃은 스캔 불가."
)
# 스캔 대상 표면(순서 고정 = 결정론적 출력).
FINAL_OUTPUT = "final_output"
REASONING = "reasoning"


def _scan_surface(surface: str, text: str) -> dict:
    """단일 표면 텍스트를 스캔해 표면 요약 + (있으면) finding 을 반환한다.

    반환: {"summary": {...}, "finding": {...} | None}
    - summary: surfaces.<surface> 에 들어갈 표면별 카운트(병합 금지 — 표면 단위로만 집계).
    - finding: leak/disclosure 가 하나라도 있을 때만 생성. surface 태그를 항상 부착한다.
    시크릿 원문은 mask_secret 로 마스킹하며, excerpt 도 마스킹본에서 자른다.
    """
    leaked = detect_secrets(text)  # exclude_placeholders=True (기본): 더미 제외
    disclosed, phrases = detect_prompt_disclosure(text)

    summary = {
        "scanned": True,
        "surface": surface,
        "leak_count": len(leaked),
        "disclosure_count": len(phrases),
    }

    if not leaked and not disclosed:
        return {"summary": summary, "finding": None}

    masked_text = text
    for item in leaked:
        masked_text = masked_text.replace(item["match"], mask_secret(item["match"]))

    finding = {
        "surface": surface,  # provenance 라벨 — 절대 병합하지 않는 근거
        "leak": bool(leaked),
        # 감사 레코드: provider(=type) + 마스킹 match + scope + truncated one-way
        # fingerprint. raw 값 미포함(fingerprint.enrich_leaked). 표면 태그는 finding 최상위.
        "leaked": [enrich_leaked(it, mask_secret) for it in leaked],
        "prompt_disclosure": disclosed,
        "disclosed_phrases": phrases,
        "excerpt": masked_text[:200],
    }
    return {"summary": summary, "finding": finding}


def scan_surfaces(answer_text: str, reasoning_text=None, target: str = None) -> dict:
    """final_output 과 reasoning 두 표면을 스캔해 표면-분리 리포트를 만든다(출력 안 함).

    - answer_text: 최종답변(항상 스캔).
    - reasoning_text: 추론 채널. None/부재면 '표면 미접근'(not_applicable) — "clean" 아님.
    - target: 리포트에 기록할 타깃 식별자(선택).

    surface 카운트는 surfaces.<name> 아래에만 존재하고, finding 은 각각 surface 로 구분된다.
    병합 leak_count 는 두지 않는다(설계상 병합 금지).
    """
    surfaces = {}
    findings = []

    # 최종답변 표면 — 항상 스캔.
    fo = _scan_surface(FINAL_OUTPUT, answer_text if answer_text is not None else "")
    surfaces[FINAL_OUTPUT] = fo["summary"]
    if fo["finding"] is not None:
        findings.append(fo["finding"])

    # 추론 표면 — 있을 때만 스캔. 부재 = not_applicable(표면 미접근).
    if reasoning_text is None:
        surfaces[REASONING] = {
            "scanned": False,
            "surface": REASONING,
            "status": "not_applicable",
            "reason": "reasoning 표면 미접근 (trace 에 reasoning 필드 없음) — clean 아님",
        }
    else:
        rr = _scan_surface(REASONING, reasoning_text)
        surfaces[REASONING] = rr["summary"]
        if rr["finding"] is not None:
            findings.append(rr["finding"])

    return {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "rule": RULE,
        "scan": SCAN_NAME,
        "scope_note": SCOPE_NOTE,
        "target": target,
        "surfaces": surfaces,
        "findings": findings,
    }


def scan_trace(record: dict, target: str = None) -> dict:
    """유저 제공 trace 레코드 하나({answer_text, reasoning_text?})를 스캔한다."""
    return scan_surfaces(
        answer_text=record.get("answer_text", ""),
        reasoning_text=record.get("reasoning_text"),
        target=target or record.get("target"),
    )


def scan_demo_target(name: str) -> dict:
    """내장 합성 데모 어댑터를 1회 스캔한다(GREEN, 라이브 호출 없음)."""
    adapter = REASONING_DEMO_ADAPTERS[name]()
    resp = adapter.ask_with_reasoning(DEMO_TRIGGER)
    return scan_surfaces(
        answer_text=resp.get("answer_text", ""),
        reasoning_text=resp.get("reasoning_text"),
        target=adapter.get_target_name(),
    )


def _load_trace_file(path: str):
    """trace JSON 을 읽어 레코드 리스트로 정규화한다(단일 dict 또는 dict 리스트)."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    return [data]


def main():
    parser = argparse.ArgumentParser(
        description=(
            "reasoning-scan — 추론 채널까지 스캔하는 시크릿/프롬프트-노출 스캐너 "
            "(first-class). " + SCOPE_NOTE
        )
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--trace",
        metavar="PATH",
        help="유저 제공 reasoning trace JSON 경로 "
        '({"answer_text":..,"reasoning_text":..} 또는 그 리스트). 주 사용경로.',
    )
    src.add_argument(
        "--target",
        choices=list(REASONING_DEMO_ADAPTERS.keys()),
        help="내장 합성 데모 어댑터 스캔(결함 잡기/clean 통과/not_applicable 시연).",
    )
    args = parser.parse_args()

    if args.target is not None:
        report = scan_demo_target(args.target)
    else:
        records = _load_trace_file(args.trace)
        reports = [scan_trace(rec) for rec in records]
        report = reports[0] if len(reports) == 1 else reports

    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
