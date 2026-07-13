"""test_exitcode_docs_sync.py — 문서·help 가 언급하는 종료코드 계약이 코드와 일치하는가.

이 릴리스의 테제: 문서가 코드보다 많이도 적게도 주장하면 안 된다. 원인은 같다 —
문서와 코드가 따로 갱신된다. 산문 전체는 못 막지만, **계약을 언급하는 부분**은 막는다.

두 가지를 강제한다:
  (1) README + --help 에 등장하는 reason= 슬러그가 코드의 슬러그 집합의 부분집합인가.
      (문서가 존재하지 않는 슬러그를 약속하면 실패 — exit 2=leaks 를 계약이라 믿은 그 부류)
  (2) 안정 토큰 문자열이 문서·코드에서 한 글자도 다르지 않은가.
      (토큰은 공개 계약이다. 산문은 번역돼도 토큰은 불변이어야 CI 의 grep 이 산다)

플레이스홀더 집합 grep 동기(test_placeholder_docs_sync)·untested_env 동기와 같은 논리.
"""
import pathlib
import re

from agentproof_scan.adapters.base import AgentCallError, AgentConfigError
from agentproof_scan.scan import DID_NOT_RUN_TOKEN

ROOT = pathlib.Path(__file__).parent

# 코드의 슬러그 진실 원천: 두 예외의 SLUGS 합집합.
CODE_SLUGS = set(AgentCallError.SLUGS) | set(AgentConfigError.SLUGS)

_SLUG_IN_DOC = re.compile(r"reason=([a-z_]+)")


def _doc_slugs(text):
    """문서/코드 문자열에서 reason=<slug> 인용을 뽑는다. <slug> 자리표시자는 제외."""
    return {s for s in _SLUG_IN_DOC.findall(text) if s != "slug" and "<" not in s}


def test_readme_slugs_are_real():
    """README 가 언급하는 모든 reason= 슬러그는 코드에 실재해야 한다."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    cited = _doc_slugs(text)
    assert cited, "README 에서 reason= 슬러그를 하나도 못 뽑았다 (정규식/문서 확인)"
    orphan = sorted(cited - CODE_SLUGS)
    assert not orphan, (
        f"README 가 코드에 없는 슬러그를 약속한다: {orphan}. "
        "존재하지 않는 계약을 문서에 쓰지 마라(exit 2=leaks 부류)."
    )


def test_help_text_slugs_are_real():
    """--help(argparse) 텍스트가 언급하는 슬러그도 실재해야 한다."""
    scan_src = (ROOT / "agentproof_scan" / "scan.py").read_text(encoding="utf-8")
    # argparse help= 문자열만 대상 — 주석/코드가 아니라 유저가 보는 텍스트.
    helps = re.findall(r'help=\(([^)]*)\)|help="([^"]*)"', scan_src)
    help_text = " ".join(a or b for a, b in helps)
    orphan = sorted(_doc_slugs(help_text) - CODE_SLUGS)
    assert not orphan, f"--help 가 코드에 없는 슬러그를 언급한다: {orphan}"


def test_help_does_not_claim_always_exit_0():
    """도구가 자기 불변식을 부정하는 문장을 출력하면 안 된다.

    P0-1: 스캔이 안 돌면 게이팅 플래그와 무관하게 exit 1. 그런데 0.1.2~0.1.3 의 --help 는
    '미지정 시 항상 exit 0' 이라고 말했다. 그 문장이 되살아나면 이 테스트가 잡는다.
    """
    scan_src = (ROOT / "agentproof_scan" / "scan.py").read_text(encoding="utf-8")
    helps = re.findall(r'help=\(([^)]*)\)|help="([^"]*)"', scan_src)
    help_text = " ".join(a or b for a, b in helps)
    for banned in ("항상 exit 0", "always exit 0", "기존대로 항상"):
        assert banned not in help_text, (
            f"--help 에 '{banned}' 가 있다 — 완주 게이트(exit 1)를 부정하는 거짓 계약이다."
        )


def test_stable_token_is_byte_identical_everywhere():
    """안정 토큰은 문서·코드에서 한 글자도 달라선 안 된다 (공개 계약)."""
    assert DID_NOT_RUN_TOKEN == "AGENTPROOF_SCAN_DID_NOT_RUN"
    for name in ("README.md", "agentproof_scan/scan.py"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert DID_NOT_RUN_TOKEN in text, f"{name} 에 안정 토큰이 없다"


def test_exit_code_table_lists_1_as_did_not_run():
    """README exit-code 표가 1 을 '스캔 미실행'으로 서술하는가 (2=leaks 아님)."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "The scan did not run" in text, "exit 1 이 '스캔 미실행'으로 서술돼야 한다"


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
