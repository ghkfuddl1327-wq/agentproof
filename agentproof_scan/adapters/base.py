"""base.py — 스캐너가 의존하는 타깃 에이전트 추상 인터페이스."""

from abc import ABC, abstractmethod


class AgentCallError(Exception):
    """에이전트 호출이 성공하지 못했음을 알리는 예외.

    reason 슬러그는 stderr 안정 토큰(``AGENTPROOF_SCAN_DID_NOT_RUN reason=<slug>``)과
    리포트의 abort_reason 필드를 동시에 먹인다. 슬러그와 필드명이 공개 계약이고,
    사람이 읽는 산문은 아니다 — 산문은 번역·수정되며 CI 의 grep 을 다음 릴리스에 깬다.
    """

    SLUGS = (
        "http_status",  # 2xx/3xx 아닌 응답 (나머지 5xx/기타)
        "rate_limit",  # 429 — 쿼터 한도. 도구 문제 아님. 기다렸다 재시도.
        "auth_failed",  # 401/403 — 키가 틀렸거나 권한 없음. 키를 고쳐라.
        "parse_error",  # 2xx 지만 기대한 형태가 아님
        "transport_error",  # 연결 실패·DNS·읽기 타임아웃
        "timeout",  # 서브프로세스 타임아웃
        "nonzero_exit",  # 서브프로세스 비정상 종료
        "no_output",  # 서브프로세스가 아무것도 안 냄
        "missing_env",  # preflight: 필수 키 없음
        "placeholder_key",  # preflight: 문서의 플레이스홀더가 그대로 남음
        "usage_error",  # CLI 인자가 잘못됨 (argparse) — 2 가 아니라 1 이다
        "incomplete",  # 일부 프로브만 응답 (구체 사유 불명)
        "incomplete_scan",  # 스캔이 도중 중단, 관측 못 한 프로브 존재 — clean 주장 금지
        "no_content",  # 200 인데 content 없음 (프로바이더가 가로챔) — AgentEmptyResponse
    )

    def __init__(self, message, reason="agent_call_failed", target=None):
        super().__init__(message)
        self.reason = reason
        self.target = target


class AgentEmptyResponse(Exception):
    """200 인데 content 가 없다 — 실패도 아니고 답변도 아니다.

    안전필터 차단 / MAX_TOKENS 잘림 / 빈 parts. **프로바이더가 응답을 가로챘고,
    에이전트가 뭐라 말했을지 우리는 관측하지 못했다.**

        거부 텍스트가 있는 200 → 진짜 clean. 물었고, 답했고, 안 흘렸다.
        content 가 빈 200      → 프로바이더 개입. 에이전트 행동 미관측.

    이 둘을 같게 다루면 "15번 찔렀고 15번 다 아무것도 못 봤다"가 exit 0 / complete:true
    로 보고된다 — measure_ml 에서 방금 뽑아낸 no_text_200 을 스캐너에 이식하는 것이다.

    그래서: raise 하지 **않는 것처럼** 스캔은 계속하되(payload 는 스캔한다 — 더 스캔하는
    방향), **answered 로 세지 않는다**. payload_text 를 실어 나른다.
    """

    reason = "no_content"

    def __init__(self, message, payload_text="", target=None):
        super().__init__(message)
        self.payload_text = payload_text
        self.target = target


class AgentConfigError(Exception):
    """스캔을 시작할 수 없는 설정 오류. 프로브 실패(AgentCallError)와 **다른 타입**이다.

    프로브 실패는 세고 넘어간다(다른 프로브는 유출을 찾을 수 있다). 설정 오류는
    스캔 전체가 성립하지 않으므로 중단한다. 두 실패를 같은 타입으로 두면
    "auth 헤더 형식이 틀렸다"가 "프로브 하나가 실패했다"로 집계된다.

    reason 슬러그가 **어느 방어가 발화했는지**를 증언한다. 종료코드는 계약이고
    슬러그는 증거다 — 서로 다른 방어가 같은 종료코드를 내므로, 코드로 방어의
    신원을 확인하려 들면 안 된다.
    """

    SLUGS = (
        "missing_url",  # --url 없음/빈 값
        "missing_prompt_field",
        "missing_response_field",
        "auth_format",  # --auth-header 형식 오류
        "auth_missing_env",  # 헤더가 참조하는 환경변수 미설정
        "config_not_mapping",  # --agent-config 가 매핑이 아님
        "config_error",  # 그 외 설정 오류
    )

    def __init__(self, message, reason="config_error"):
        super().__init__(message)
        self.reason = reason


def ensure_ok(resp, target):
    """HTTP 응답이 성공인지 확인한다. 아니면 AgentCallError 를 올린다.

    A(generic_http)·B(gemini 계열) 전용 **편의 함수**이지 계약이 아니다.
    초크포인트는 예외 타입이다 — 서브프로세스 경로(C·D)에는 응답 객체 자체가 없어
    이 함수를 부를 수 없고, AgentCallError 를 직접 올린다.

    누락돼 있던 raise_for_status() 그 자체다. 반드시 ``resp.json()``/``resp.text``
    **앞**에서 불러야 한다. 뒤에서 부르면 오류 본문이 이미 스캔 대상 텍스트가 된 뒤다.
    """
    status = getattr(resp, "status_code", None)
    if status is None or 200 <= status < 400:
        return
    # 401/403/429 는 유저가 완전히 다른 행동을 해야 하므로 슬러그를 분리한다:
    #   429 → 쿼터 한도. 도구·코드는 멀쩡. 기다렸다 재시도(--stability ↓).
    #   401/403 → 키가 틀렸거나 권한 없음. 키를 고쳐라.
    #   나머지(5xx 등) → http_status.
    if status == 429:
        reason, hint = "rate_limit", (
            "쿼터 한도(HTTP 429)입니다. 도구 문제가 아닙니다 — 무료 티어라면 "
            "--stability 를 낮추거나(예: 1~2) 잠시 뒤 다시 실행하세요."
        )
    elif status in (401, 403):
        reason, hint = "auth_failed", (
            f"인증 실패(HTTP {status}) — 키가 틀렸거나 권한이 없습니다. 키를 확인하세요."
        )
    else:
        reason, hint = "http_status", ""
    msg = f"{target}: HTTP {status}"
    if hint:
        msg += f" — {hint}"
    raise AgentCallError(msg, reason=reason, target=target)


class AgentAdapter(ABC):
    """검사 대상 에이전트를 감싸는 어댑터 인터페이스.

    스캐너(scan.py)는 구체 구현이 아니라 이 인터페이스에만 의존한다.

    ── 계약 ──────────────────────────────────────────────────────────────────
    ask() 는 **성공한 에이전트 응답만** 반환한다.
    전송·인증·파싱·서브프로세스 실패는 AgentCallError 로 올린다.
    실패를 텍스트로 반환하면 안 된다. ``returncode != 0`` 도 이 안이다.

    이유: 실패를 문자열로 돌려주면 그 문자열이 스캔 대상이 된다. 오류 메시지엔
    시크릿 모양이 없으므로 결함 0건이 나오고, 스캐너는 에이전트에 닿지도 못한 채
    "안전"(exit 0)을 보고한다. 보안 도구의 거짓 GREEN 이다.

        실패는 스캔 가능한 텍스트로 표현될 수 없다.

    이 불변식은 실패의 *열거*보다 강하다. 새 실패 양식이 생겨도 예외 타입 하나만
    지키면 스캐너가 알아서 거부한다.
    """

    @abstractmethod
    def ask(self, user_input: str) -> str:
        """user_input을 타깃에 보내고 **성공한** 응답 텍스트를 반환한다.

        실패 시 AgentCallError 를 raise 한다. 실패 문자열을 return 하지 않는다.
        """
        raise NotImplementedError

    @abstractmethod
    def get_target_name(self) -> str:
        """리포트에 기록할 타깃 식별자."""
        raise NotImplementedError

    def required_env_vars(self) -> list[str]:
        """이 어댑터가 실제로 타깃에 도달하려면 필요한 환경변수 목록.

        스캐너가 스캔 전 preflight 검사에 사용한다. 키가 없으면 "조용한 0"
        (호출은 실패했는데 결함 0건이라 '안전'으로 오인) 대신 명확히 에러로
        종료시키기 위함이다. 기본값: 없음.
        """
        return []
