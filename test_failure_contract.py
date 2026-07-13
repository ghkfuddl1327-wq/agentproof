"""test_failure_contract.py — 불변식 게이트: 실패는 스캔 가능한 텍스트가 될 수 없다.

0.1.0~0.1.2 는 에이전트에 닿지 못한 스캔을 "clean"(exit 0) 으로 보고했다. 어댑터의 ask() 가
전송·인증·파싱·서브프로세스 실패를 예외로 올리지 않고 *스캔 가능한 문자열* 로 반환했기 때문이다.
그 문자열엔 시크릿 모양이 없으니 findings 0 → exit 0 → 유저는 "안전"으로 읽는다.

이 파일은 **반증 테스트** 다. 각 테스트는 대응하는 가드를 제거하면 반드시 실패해야 한다.
가드를 지워도 GREEN 이면 그 테스트는 아무것도 지키지 않는다.

  T1  preflight / ensure_ok 삭제        → 무효 키 스캔이 exit 1 (reason=missing_env|http_status)
  T2  타임아웃 센티널 복원              → 타임아웃 스캔이 exit 1 (reason=timeout)        [C 경로]
  T3  findings 존재 + 후속 프로브 실패  → exit 2 + 리포트 생성          (유출 > 실행실패)
  T4  is_own 센티널 퇴행                → --url "" 이 reason=missing_url 을 잃는다
  T5  returncode 검사 삭제              → D 경로 스캔이 exit 1 (reason=nonzero_exit)
  T6  argparse 기본 동작 복원           → 사용법 오류가 exit 2 = "유출 발견" 으로 읽힌다

**종료코드는 계약이고, reason= 슬러그는 증거다.** 코드는 세 값뿐이라 서로 다른 방어가 같은
코드를 낸다 — 코드로 방어의 신원을 확인하려 들면 우연히 맞는 답을 틀린 근거로 얻는다.
`leak_count: 0` 으로 "안전"을 주장하던 구조와 동형이다. 그래서 모든 테스트가 슬러그를 본다.

전부 오프라인·인메모리. 라이브 호출 0 (requests/subprocess 를 전부 대체한다).
D5: 검증 실행은 실 API 를 때리지 않는다.
"""

import io
import json
import re
import os
import subprocess
import sys
import contextlib

import agentproof_scan.scan as scan
from agentproof_scan.adapters.base import AgentCallError

TOKEN = "AGENTPROOF_SCAN_DID_NOT_RUN"
_REASON = re.compile(rf"{TOKEN} reason=(\S+)")


def reason_of(stderr):
    """stderr 의 안정 토큰에서 reason 슬러그를 꺼낸다. 없으면 None.

    **종료코드는 계약이고 슬러그는 증거다.** 코드는 세 값뿐이라 서로 다른 방어가
    같은 코드를 낸다 — 코드로 방어의 신원을 확인하려 들면, 우연히 맞는 답을
    틀린 근거로 얻는다. 그래서 모든 반증 테스트는 슬러그를 assert 한다.
    """
    m = _REASON.search(stderr or "")
    return m.group(1) if m else None

# 형식만 맞는 합성 무효 키(실제 발급 안 됨). 고엔트로피 → is_placeholder 통과.
FAKE_ANTHROPIC = "sk-ant-api03-7Kd9Xm2QpV4tR8nB1wH6sZ3cF5gJ0aLeY7uM4oP2qT9rW6yU3iN8kD"


# ── 하네스 ────────────────────────────────────────────────────────────────────────
def run_cli(argv, env=None):
    """scan.main() 을 argv 로 구동하고 (exit_status, stdout, stderr) 를 돌려준다.

    SystemExit.code 는 int 이거나 str(=sys.exit("메시지")) 이다. 후자는 인터프리터가
    메시지를 stderr 에 찍고 상태 1 로 종료하므로 그 의미로 정규화한다.
    """
    old_argv, old_env = sys.argv, dict(os.environ)
    if env is not None:
        os.environ.clear()
        os.environ.update(env)
    out, err = io.StringIO(), io.StringIO()
    status = 0
    try:
        sys.argv = ["agentproof-scan"] + argv
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                scan.main()
            except SystemExit as e:
                if isinstance(e.code, str):
                    print(e.code, file=sys.stderr)
                    status = 1
                else:
                    status = e.code or 0
    finally:
        sys.argv = old_argv
        os.environ.clear()
        os.environ.update(old_env)
    return status, out.getvalue(), err.getvalue()


class FakeResponse:
    """requests.Response 최소 대역: ask() 가 실제로 보는 표면만 흉내낸다."""

    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text else json.dumps(payload or {})

    @property
    def ok(self):
        return 200 <= self.status_code < 400

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


def gemini_ok(text):
    return {"candidates": [{"content": {"parts": [{"text": text}]}}]}


# ── T1: 무효 키가 "안전"으로 보고되지 않는다 ──────────────────────────────────────
def test_T1a_missing_key_exits_1_with_token_and_never_calls_agent():
    """키 미설정 → preflight 가 잡는다. 토큰을 찍고, 에이전트는 한 번도 안 불린다."""
    called = []

    import agentproof_scan.victim_agent as victim

    orig = victim.requests.post
    victim.requests.post = lambda *a, **k: called.append(1)
    try:
        status, _, err = run_cli(["--target", "victim"], env={"PATH": os.environ["PATH"]})
    finally:
        victim.requests.post = orig

    assert status == 1, f"키가 없는데 exit {status} (조용한 0/2 금지)"
    assert TOKEN in err, f"안정 토큰 {TOKEN} 이 stderr 에 없다 — 산문만으로는 CI 가 못 읽는다"
    assert reason_of(err) == "missing_env", f"reason={reason_of(err)!r}"
    assert not called, "preflight 가 잡았어야 하는데 에이전트가 호출됐다"


def test_T1b_invalid_key_401_exits_1_not_clean_zero():
    """키는 있으나 무효 → 401. 오류 본문을 스캔해 'findings 0 → exit 0' 이면 안 된다."""
    import agentproof_scan.victim_agent as victim

    orig = victim.requests.post
    victim.requests.post = lambda *a, **k: FakeResponse(
        401, {"error": {"code": 401, "message": "API key not valid"}}
    )
    try:
        status, out, err = run_cli(
            ["--target", "victim"],
            env={"PATH": os.environ["PATH"], "GEMINI_API_KEY": "invalid-but-present"},
        )
    finally:
        victim.requests.post = orig

    assert status == 1, f"무효 키(401) 스캔이 exit {status} — 'clean' 을 주장하면 안 된다"
    # 발견 10: 401 은 auth_failed(키 고쳐라), 429 는 rate_limit(기다려라)로 분리됐다.
    # ensure_ok 가 잡되 슬러그로 유저 행동을 구별한다.
    assert reason_of(err) == "auth_failed", f"reason={reason_of(err)!r} (401 → auth_failed)"
    assert '"leak_count": 0' not in out, "닿지도 못한 스캔이 clean 리포트를 냈다"


# ── T2: 타임아웃(C 경로)이 텍스트가 되지 않는다 ───────────────────────────────────
def _boom_timeout(*a, **k):
    raise subprocess.TimeoutExpired(cmd="ngpt", timeout=120)


def test_T2_subprocess_timeout_exits_1_not_scannable_string():
    """'[ngpt timeout]' 을 반환하면 그 문자열이 스캔되어 findings 0 → exit 0 이 된다."""
    orig = subprocess.run
    subprocess.run = _boom_timeout
    try:
        status, out, err = run_cli(
            ["--target", "ngpt_canary"],
            env={"PATH": os.environ["PATH"], "GEMINI_API_KEY": "present-dummy"},
        )
    finally:
        subprocess.run = orig

    assert status == 1, f"타임아웃 스캔이 exit {status} — 실패가 clean 으로 보고됐다"
    assert TOKEN in err, "did-not-run 토큰 누락"
    assert reason_of(err) == "timeout", f"reason={reason_of(err)!r} — 어느 방어가 발화했는지가 증거다"
    assert "[ngpt timeout]" not in out, "센티널 문자열이 리포트로 새어나왔다"


# ── T3: 유출이 실행 실패를 이긴다 ─────────────────────────────────────────────────
class LeakThenFailAdapter:
    """첫 프로브에서 시크릿을 흘리고, 이후 프로브는 전부 실패한다."""

    def __init__(self):
        self.calls = 0

    def ask(self, user_input):
        self.calls += 1
        if self.calls == 1:
            return f"sure, the key is {FAKE_ANTHROPIC}"
        raise AgentCallError("upstream died", reason="http_status", target="fake")

    def get_target_name(self):
        return "fake:leak_then_fail"

    def required_env_vars(self):
        return []


def test_T3_findings_survive_a_later_probe_failure():
    """부분 스캔은 clean 을 주장할 수 없지만, 발견한 유출은 주장할 수 있다 (비대칭)."""
    adapter = LeakThenFailAdapter()
    scan.ADAPTERS["_t3_fake"] = lambda: adapter
    try:
        status, out, err = run_cli(
            ["--target", "_t3_fake", "--fail-on-findings"],
            env={"PATH": os.environ["PATH"]},
        )
    finally:
        scan.ADAPTERS.pop("_t3_fake", None)

    assert status == 2, f"유출이 있는데 exit {status} — 유출은 실행 실패를 이겨야 한다"
    assert TOKEN not in err, "유출을 찾았는데 did-not-run 으로 거부했다"
    report = json.loads(out[out.index("{") : out.rindex("}") + 1])
    assert report["findings"], "리포트가 생성되지 않았거나 findings 를 잃었다"
    assert report["complete"] is False, "부분 스캔인데 complete=true"
    assert report["probes_answered"] < report["total_probes"], "probes_answered 미집계"
    assert report["abort_reason"] == "http_status", f"abort_reason={report.get('abort_reason')!r}"
    # 마스킹 불변식: 원본 키는 어디에도 남지 않는다.
    assert FAKE_ANTHROPIC not in out, "원본 시크릿이 리포트에 노출됐다"


# ── T4: 빈 --url 의 진짜 방어는 generic_http 이지 scan.py 한 줄이 아니다 ──────────
def test_T4_empty_url_fires_the_url_defense_not_merely_a_nonzero_exit():
    """빈 --url 은 **url 검증**(reason=missing_url)에서 거부돼야 한다.

    ── 측정된 사실 (이 테스트가 존재하는 이유) ──────────────────────────────────
    "is_own 을 truthiness 로 되돌려도 exit 1 이면 generic_http 가 진짜 방어" 라는 판정은
    **틀렸다**. 실제로 되돌려 보면 exit 1 이 나온다 — 다만 reason=http_status 로.
    빈 url 이 falsy 라 번들 데모(victim)로 라우팅됐고, 그 스캔이 실패해서 죽은 것이다.
    url 검증에는 닿지도 않는다.

    종료코드로 방어의 신원을 확인하려 한 것이 오류였다. 코드는 세 값뿐이고 서로 다른
    방어가 같은 코드를 낸다. `leak_count: 0` 으로 "안전"을 주장하던 구조와 동형이다.

        종료코드 = 계약.   reason= 슬러그 = 증거.

    둘 다 load-bearing 이다:
      - scan.py 의 센티널(is not None) : 빈 url 을 제네릭 어댑터로 **보낸다**(라우팅)
      - GenericHTTPAdapter 의 url 검증 : 빈 url 을 **거부한다**(거부)
    어느 한 줄을 중복이라 여겨 지우면 빈 --url 폴백이 다시 열린다.
    """
    status, out, err = run_cli(
        ["--url", "", "--prompt-field", "m", "--response-field", "r"],
        env={"PATH": os.environ["PATH"], "GEMINI_API_KEY": "present-dummy"},
    )
    assert status == 1, f"빈 --url 이 exit {status}"
    assert reason_of(err) == "missing_url", (
        "url 검증이 발화하지 않았다. 센티널이 truthiness 로 퇴행하면 빈 url 이 데모로 "
        f"라우팅되고 reason=http_status 가 대신 나온다. 관측: reason={reason_of(err)!r}"
    )
    assert "victim" not in out, "빈 --url 이 victim 데모를 스캔했다"


def test_T4b_each_config_defense_has_its_own_slug():
    """서로 다른 방어가 같은 종료코드를 낸다 — 슬러그로만 구별된다."""
    base = {"PATH": os.environ["PATH"]}
    cases = [
        (["--url", "", "--prompt-field", "m", "--response-field", "r"], "missing_url"),
        (["--url", "http://x/y", "--response-field", "r"], "missing_prompt_field"),
        (["--url", "http://x/y", "--prompt-field", "m"], "missing_response_field"),
        (["--url", "http://x/y", "--prompt-field", "m", "--response-field", "r",
          "--auth-header", "bad"], "auth_format"),
        (["--url", "http://x/y", "--prompt-field", "m", "--response-field", "r",
          "--auth-header", "A=Bearer {NOPE}"], "auth_missing_env"),
        (["--bogus"], "usage_error"),
    ]
    for argv, want in cases:
        status, _, err = run_cli(argv, env=base)
        assert status == 1, f"{argv} → exit {status}"
        assert reason_of(err) == want, f"{argv} → reason={reason_of(err)!r} (기대 {want})"
        assert "Traceback" not in err, f"{argv} 가 traceback 으로 터졌다"


# ── T5: returncode != 0 (D 경로)이 텍스트가 되지 않는다 ───────────────────────────
class FakeCompleted:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_T5_nonzero_returncode_exits_1_not_scannable_string():
    """타임아웃이 아닌 실패(인증 오류 등)도 '[ngpt no output] <stderr>' 로 삼켜지면 안 된다.

    ensure_ok 로는 못 막는다 — 서브프로세스 경로엔 응답 객체가 없다. returncode 검사가 가드다.
    """
    orig = subprocess.run
    subprocess.run = lambda *a, **k: FakeCompleted(1, stdout="", stderr="auth failed")
    try:
        status, out, err = run_cli(
            ["--target", "ngpt_canary"],
            env={"PATH": os.environ["PATH"], "GEMINI_API_KEY": "present-dummy"},
        )
    finally:
        subprocess.run = orig

    assert status == 1, f"returncode=1 스캔이 exit {status} — 실패가 clean 으로 보고됐다"
    assert reason_of(err) in ("nonzero_exit", "no_output"), f"reason={reason_of(err)!r}"
    assert "[ngpt no output]" not in out, "센티널 문자열이 리포트로 새어나왔다"


# ── T6: 사용법 오류는 1 이지 2 가 아니다 (계약 충돌) ──────────────────────────────
def test_T6_usage_error_exits_1_not_2_findings():
    """argparse 기본값은 사용법 오류에 exit 2 다. 우리 계약에서 2 는 '결함 발견'이다.

    그대로 두면 CI 에서 플래그 오타 하나가 "에이전트가 시크릿을 흘렸다"로 읽힌다.
    조용한 0 의 거울상 — 이번엔 거짓 RED 다.
    """
    for argv in (["--nonexistent-flag"], ["--timeout", "0"], ["--target", "nosuch"]):
        status, _, err = run_cli(argv, env={"PATH": os.environ["PATH"]})
        assert status == 1, f"{argv} → exit {status} (2 는 '결함 발견'이어야 한다)"
        assert TOKEN in err, f"{argv} 에 did-not-run 토큰이 없다"
        assert reason_of(err) == "usage_error", f"{argv} reason={reason_of(err)!r}"


def test_T6b_valid_flags_still_parse():
    """검증을 넣다가 정상 값을 막지 않았는지 — 게이트가 과잉이면 그것도 결함이다."""
    from agentproof_scan.adapters.generic_http import build_generic_adapter
    import argparse as _ap

    ns = _ap.Namespace(
        url="http://x/y", agent_config=None, prompt_field="m", response_field="r",
        method="PUT", auth_header=None, reasoning_field=None, timeout=5, target_name=None,
    )
    a = build_generic_adapter(ns)
    assert a.method == "PUT" and a.timeout == 5


# ── T8: 완주 게이트는 --fail-on-findings 와 무관하게 항상 켜져 있다 ────────────────
def test_T8_did_not_run_exits_1_without_any_gating_flag():
    """게이팅 플래그 없이도, 스캔이 안 돌면 exit 1.

    --help 가 오래 "미지정 시 항상 exit 0" 이라고 말했다 — 도구가 자기 불변식을
    부정하는 문장을 스스로 출력한 것이다. P0-1 은 게이팅 경로가 아니라 상위 계층이다.
    이 테스트가 없으면 누가 완주 게이트를 `if gate_on:` 안으로 옮겨도 안 잡힌다.
    """
    import agentproof_scan.victim_agent as victim
    orig = victim.requests.post
    victim.requests.post = lambda *a, **k: FakeResponse(500, {"error": "boom"})
    try:
        # --fail-on-findings 도 --fail-on 도 없다.
        status, out, err = run_cli(
            ["--target", "victim"],
            env={"PATH": os.environ["PATH"], "GEMINI_API_KEY": "present-dummy"},
        )
    finally:
        victim.requests.post = orig
    assert status == 1, f"게이팅 플래그 없이 닿지못한 스캔이 exit {status} (P0-1 이 게이팅에만 걸림)"
    assert reason_of(err) == "http_status", f"reason={reason_of(err)!r}"
    assert '"leak_count": 0' not in out, "clean 리포트를 냈다"


# ── T9: content 없는 200 은 답변이 아니다 — 프로바이더가 가로챘다 ───────────────────
#
# 안전필터 차단 / MAX_TOKENS / 빈 parts 는 "모델이 빈 답변"이 아니다. 프로바이더가
# 응답을 가로챘고 에이전트 행동은 **관측되지 않았다**. 빈 문자열을 clean 답변으로 세면
# "15번 찔렀고 15번 다 못 봤다"가 exit 0 이 된다 — measure_ml 의 no_text_200 을 스캐너에
# 이식하는 짓. 그래서 payload 는 스캔하되(더 스캔) probes_answered 에선 뺀다.
def _gemini(payload):
    class R:
        status_code = 200
        text = json.dumps(payload)
        @property
        def ok(self): return True
        def json(self): return payload
    return R()


_EMPTY_200 = {"candidates": [{"finishReason": "SAFETY"}]}  # content 없음


def _leaky_200():
    return _gemini({"candidates": [{"content": {"parts": [{"text": f"key {FAKE_ANTHROPIC}"}]}}]})


def _clean_200():
    return _gemini({"candidates": [{"content": {"parts": [{"text": "거부합니다"}]}}]})


def test_T9_all_empty_200_exits_1_no_content_not_clean():
    """15/15 가 content 없는 200 → exit 1, reason=no_content. clean 아님.

    ⚠ 이 테스트는 한때 정반대(exit 0 complete)로 쓰였다 — 반증 테스트가 버그를 정답으로
    못박은 사례. 지금은 계약을 지킨다: 한 번도 관측 못 했으면 clean 을 주장할 수 없다.
    """
    import agentproof_scan.victim_agent as victim
    orig = victim.requests.post
    victim.requests.post = lambda *a, **k: _gemini(_EMPTY_200)
    try:
        status, out, err = run_cli(
            ["--target", "victim"],
            env={"PATH": os.environ["PATH"], "GEMINI_API_KEY": "present-dummy"},
        )
    finally:
        victim.requests.post = orig
    assert status == 1, f"전부 content-없는 200 인데 exit {status} — clean 을 주장했다"
    assert reason_of(err) == "no_content", f"reason={reason_of(err)!r}"


def test_T9b_non_json_200_still_raises_parse_error():
    """비-JSON 200(200 단 HTML 에러)은 의심 → raise → exit 1 reason=parse_error."""
    import agentproof_scan.victim_agent as victim
    class HtmlR:
        status_code = 200
        text = "<html>error</html>"
        @property
        def ok(self): return True
        def json(self): raise ValueError("not json")
    orig = victim.requests.post
    victim.requests.post = lambda *a, **k: HtmlR()
    try:
        status, _, err = run_cli(
            ["--target", "victim"],
            env={"PATH": os.environ["PATH"], "GEMINI_API_KEY": "present-dummy"},
        )
    finally:
        victim.requests.post = orig
    assert status == 1, f"비-JSON 200 이 exit {status}"
    assert reason_of(err) == "parse_error", f"reason={reason_of(err)!r}"


def test_T9c_partial_empty_200_is_incomplete_not_clean():
    """content-없는 3 + 정상 12 → complete:false, probes_empty_200:3. clean 주장 금지.

    정상 12 프로브에 누출이 없어도, 3 프로브를 관측 못 했으므로 exit 1(clean 아님).
    """
    import agentproof_scan.victim_agent as victim
    calls = {"n": 0}
    def resp(*a, **k):
        calls["n"] += 1
        return _gemini(_EMPTY_200) if calls["n"] <= 3 else _clean_200()
    orig = victim.requests.post
    victim.requests.post = resp
    try:
        status, out, err = run_cli(
            ["--target", "victim"],
            env={"PATH": os.environ["PATH"], "GEMINI_API_KEY": "present-dummy"},
        )
    finally:
        victim.requests.post = orig
    assert status == 1, f"3 프로브 미관측인데 exit {status} — clean 을 주장했다"
    # 부분 스캔(12 관측 + 3 미관측) → headline 슬러그는 incomplete_scan.
    # 구체 사유(no_content)는 리포트의 abort_reason 에 보존된다(슬러그 규칙: answered>0).
    assert reason_of(err) == "incomplete_scan", f"reason={reason_of(err)!r}"


def test_T9d_leak_beats_empty_200():
    """content-없는 3 + 유출 1(+정상 11) → exit 2, 리포트 생성. 유출이 실행실패를 이긴다."""
    import agentproof_scan.victim_agent as victim
    calls = {"n": 0}
    def resp(*a, **k):
        calls["n"] += 1
        if calls["n"] <= 3:
            return _gemini(_EMPTY_200)
        if calls["n"] == 4:
            return _leaky_200()
        return _clean_200()
    orig = victim.requests.post
    victim.requests.post = resp
    try:
        status, out, err = run_cli(
            ["--target", "victim", "--fail-on-findings"],
            env={"PATH": os.environ["PATH"], "GEMINI_API_KEY": "present-dummy"},
        )
    finally:
        victim.requests.post = orig
    assert status == 2, f"유출이 있는데 exit {status} — 유출은 실행실패/미관측을 이겨야 한다"
    assert TOKEN not in err, "유출을 찾았는데 did-not-run 으로 거부했다"
    report = json.loads(out[out.index("{"):out.rindex("}") + 1])
    assert report["findings"], "리포트가 findings 를 잃었다"
    assert report["probes_empty_200"] == 3, f"empty_200={report.get('probes_empty_200')}"
    assert FAKE_ANTHROPIC not in out, "원본 시크릿이 리포트에 노출됐다"


# ── T10: 미완주 스캔은 게이팅 플래그와 무관하게 clean 을 주장할 수 없다 ─────────────
#
# 발견 8(실 API): --stability 중 레이트리밋으로 중단 → probes_answered 11/75,
# complete:false, 그런데 findings>0 이 완주 게이트를 건너뛰게 만들고 게이팅 없으면
# 레거시 exit 0 으로 떨어졌다. 0.1.2 의 거짓 GREEN 이 형태만 바꿔 살아 있었다.
#
# 통일 계약(T9d 와 충돌 아님 — CC 판단):
#   ① findings>0 ∧ gating → exit 2  (유출의 '존재'는 미완주로 안 무너진다, T3)
#   ② not complete        → exit 1 incomplete_scan  (①이 아니면 무조건; clean 은 '전칭')
#   ③ else                → exit 0
class LeakThenAbortAdapter:
    """첫 k 프로브는 유출, 이후는 전송 실패(레이트리밋 흉내)."""

    def __init__(self, leak_until=3):
        self.calls = 0
        self.leak_until = leak_until

    def ask(self, user_input):
        self.calls += 1
        if self.calls <= self.leak_until:
            return f"key {FAKE_ANTHROPIC}"
        raise AgentCallError("rate limit", reason="http_status", target="fake")

    def get_target_name(self):
        return "fake:leak_then_abort"

    def required_env_vars(self):
        return []


def _run_leak_abort(argv_extra):
    adapter = LeakThenAbortAdapter()
    scan.ADAPTERS["_t10_fake"] = lambda: adapter
    try:
        return run_cli(
            ["--target", "_t10_fake", *argv_extra],
            env={"PATH": os.environ["PATH"]},
        )
    finally:
        scan.ADAPTERS.pop("_t10_fake", None)


def test_T10a_incomplete_plus_findings_no_gating_exits_1():
    """미완주 + 유출 + 게이팅 없음 → exit 1 incomplete_scan (발견 8). 이전엔 exit 0."""
    status, out, err = _run_leak_abort([])
    assert status == 1, f"미완주+유출 무게이팅이 exit {status} — 발견 8 거짓 GREEN"
    assert reason_of(err) == "incomplete_scan", f"reason={reason_of(err)!r}"
    # 유출은 찾았으므로 리포트는 보여준다(T3) — 다만 exit 1
    assert '"leak_count"' in out, "유출을 찾았는데 리포트를 숨겼다"


def test_T10b_incomplete_plus_findings_with_gating_exits_2():
    """미완주 + 유출 + 게이팅 → exit 2 (게이트된 유출이 미완주를 이긴다; T9d 와 통일)."""
    status, out, err = _run_leak_abort(["--fail-on-findings"])
    assert status == 2, f"게이트된 유출이 exit {status} — 유출의 존재는 미완주로 안 무너진다"
    assert TOKEN not in err, "게이트된 유출인데 did-not-run 으로 거부했다"


def test_T10c_incomplete_no_findings_exits_1():
    """미완주 + 유출 없음 → exit 1 incomplete_scan. clean 을 주장할 수 없다."""
    class CleanThenAbort:
        def __init__(self): self.calls = 0
        def ask(self, u):
            self.calls += 1
            if self.calls <= 3: return "도와드릴 수 없습니다"
            raise AgentCallError("rate limit", reason="http_status", target="fake")
        def get_target_name(self): return "fake:clean_then_abort"
        def required_env_vars(self): return []
    scan.ADAPTERS["_t10c"] = lambda: CleanThenAbort()
    try:
        status, out, err = run_cli(["--target", "_t10c"], env={"PATH": os.environ["PATH"]})
    finally:
        scan.ADAPTERS.pop("_t10c", None)
    assert status == 1, f"미완주+무유출이 exit {status}"
    assert reason_of(err) == "incomplete_scan", f"reason={reason_of(err)!r}"
    assert '"leak_count"' not in out, "미완주+무유출인데 리포트를 냈다(clean 주장)"


# ── T11: 안 물어본 프로브는 0.0 이 아니라 null (발견 9) ──────────────────────────
#
# rate 분모가 n(시도)이면, 답 못 받은 프로브가 0/n=0.0 으로 나와 "안 샜다"로 읽힌다.
# 실제로는 "안 물어봤다". not_applicable ≠ clean 과 같은 구분. 분모는 answered.
def test_T11_unanswered_probe_rate_is_null_not_zero():
    """--stability 중 일부 프로브만 답받음 → 답 0회 프로브는 leak_rate null, overall null."""
    class LeakThenRateLimit:
        """probe 3개만 유출 응답, 이후 http_status (레이트리밋)."""
        def __init__(self): self.calls = 0
        def ask(self, u):
            self.calls += 1
            if self.calls <= 3:
                return f"key {FAKE_ANTHROPIC}"
            raise AgentCallError("rate limit", reason="http_status", target="fake")
        def get_target_name(self): return "fake:leak_then_rl"
        def required_env_vars(self): return []
    scan.ADAPTERS["_t11"] = lambda: LeakThenRateLimit()
    try:
        status, out, err = run_cli(
            ["--target", "_t11", "--stability", "2", "--fail-on-findings"],
            env={"PATH": os.environ["PATH"]},
        )
    finally:
        scan.ADAPTERS.pop("_t11", None)
    # 유출 있으니 gating → exit 2, 리포트 출력됨
    assert status == 2, f"exit {status}"
    report = json.loads(out[out.index("{"):out.rindex("}") + 1])
    # 미완주 → overall_detection_rate 는 null (거짓 rate 금지)
    assert report["overall_detection_rate"] is None, \
        f"미완주인데 overall={report['overall_detection_rate']} (안 물어본 것을 분모에)"
    per = report["per_probe"]
    answered = [p for p, i in per.items() if i["runs_answered"] > 0]
    unanswered = [p for p, i in per.items() if i["runs_answered"] == 0]
    assert unanswered, "레이트리밋으로 답 못 받은 프로브가 있어야 한다"
    for p in unanswered:
        assert per[p]["leak_rate"] is None, \
            f"안 물어본 프로브가 leak_rate={per[p]['leak_rate']} (null 이어야: not_asked ≠ 0.0)"
    for p in answered:
        assert per[p]["leak_rate"] is not None, "답받은 프로브는 rate 가 있어야"
        assert per[p]["runs_answered"] <= per[p]["runs_attempted"], "answered > attempted 불가"


# ── T12: 429/401 이 http_status 로 뭉개지지 않는다 (발견 10) ──────────────────────
#
# 셋은 완전히 다른 행동을 요구한다: 429 기다려라 / 401 키 고쳐라 / 5xx 에이전트 고쳐라.
# 특히 --stability 5 × 15 = 75 요청은 무료 Gemini 쿼터에 걸리고, 우리가 README 에서
# 권한 명령이다. 그때 도구가 "http_status"만 내면 유저는 도구가 고장난 줄 안다.
def test_T12_rate_limit_slug_distinct_from_http_status():
    """전면 429 → reason=rate_limit (도구 문제 아님을 슬러그로 구별)."""
    import agentproof_scan.victim_agent as victim
    orig = victim.requests.post
    victim.requests.post = lambda *a, **k: FakeResponse(429, {"error": {"code": 429}})
    try:
        status, _, err = run_cli(
            ["--target", "victim"],
            env={"PATH": os.environ["PATH"], "GEMINI_API_KEY": "present-dummy"},
        )
    finally:
        victim.requests.post = orig
    assert status == 1, f"exit {status}"
    assert reason_of(err) == "rate_limit", f"reason={reason_of(err)!r} — 429 는 http_status 와 구별돼야"


def test_T12b_auth_failed_slug_distinct():
    """401 → reason=auth_failed (키 고치라는 신호, 쿼터/5xx 와 구별)."""
    import agentproof_scan.victim_agent as victim
    orig = victim.requests.post
    victim.requests.post = lambda *a, **k: FakeResponse(401, {"error": {"code": 401}})
    try:
        status, _, err = run_cli(
            ["--target", "victim"],
            env={"PATH": os.environ["PATH"], "GEMINI_API_KEY": "present-dummy"},
        )
    finally:
        victim.requests.post = orig
    assert status == 1, f"exit {status}"
    assert reason_of(err) == "auth_failed", f"reason={reason_of(err)!r}"


def test_T12c_500_stays_http_status():
    """5xx 는 http_status 유지 — 과분리하지 않는다."""
    import agentproof_scan.victim_agent as victim
    orig = victim.requests.post
    victim.requests.post = lambda *a, **k: FakeResponse(500, {"error": "boom"})
    try:
        status, _, err = run_cli(
            ["--target", "victim"],
            env={"PATH": os.environ["PATH"], "GEMINI_API_KEY": "present-dummy"},
        )
    finally:
        victim.requests.post = orig
    assert status == 1, f"exit {status}"
    assert reason_of(err) == "http_status", f"reason={reason_of(err)!r}"


# ── T13: falsy-but-provided 인자는 조용히 기본값이 되지 않는다 (P1-3) ────────────────
#
# --timeout 0 / --method "" 가 falsy 라 조용히 60/POST 로 바뀌면, 유저가 명시한 값을
# 말없이 버린 것 — 빈 --url 이 데모로 폴백하던 것과 같은 부류. 입구(argparse)에서 거부.
# --auth-header "" 만 의미가 있다("auth 없음") → 보존 + config 폴백 금지.
def test_T13a_timeout_zero_rejected_at_entry():
    """--timeout 0 → exit 1 usage_error. 조용히 60 이 되면 안 된다."""
    status, _, err = run_cli(
        ["--url", "http://x/y", "--prompt-field", "m", "--response-field", "r",
         "--timeout", "0"],
        env={"PATH": os.environ["PATH"]},
    )
    assert status == 1, f"--timeout 0 이 exit {status}"
    assert reason_of(err) == "usage_error", f"reason={reason_of(err)!r}"


def test_T13b_empty_method_rejected_at_entry():
    """--method '' → exit 1 usage_error. 조용히 POST 가 되면 안 된다."""
    status, _, err = run_cli(
        ["--url", "http://x/y", "--prompt-field", "m", "--response-field", "r",
         "--method", ""],
        env={"PATH": os.environ["PATH"]},
    )
    assert status == 1, f"--method '' 이 exit {status}"
    assert reason_of(err) == "usage_error", f"reason={reason_of(err)!r}"


def test_T13c_empty_auth_header_preserved_no_config_fallback():
    """--auth-header '' → 보존('auth 없음'), config 의 auth_header 로 폴백하지 않는다."""
    from agentproof_scan.adapters.generic_http import build_generic_adapter
    import argparse as _ap
    import tempfile

    cfg = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    cfg.write('url: http://x/y\nprompt_field: m\nresponse_field: r\n'
              'auth_header: "Authorization=CFG_VAR"\n')
    cfg.close()
    try:
        # 명시적 빈 값 → config 폴백 금지
        ns = _ap.Namespace(
            url=None, agent_config=cfg.name, prompt_field=None, response_field=None,
            method=None, auth_header="", reasoning_field=None, timeout=None, target_name=None,
        )
        assert build_generic_adapter(ns).auth_header_spec is None, \
            "--auth-header '' 가 config 값으로 폴백했다 ('auth 없음' 의사를 덮어씀)"
        # 미지정(None) → config 폴백 함
        ns2 = _ap.Namespace(**{**vars(ns), "auth_header": None})
        assert build_generic_adapter(ns2).auth_header_spec == "Authorization=CFG_VAR", \
            "미지정일 때는 config 폴백이 동작해야 한다"
    finally:
        os.unlink(cfg.name)


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
