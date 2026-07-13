"""generic_http.py — 설정 기반 제네릭 HTTP 어댑터 (코드 없이 own-agent 스캔).

무엇: 기존 AgentAdapter 인터페이스를 '코드'가 아니라 '설정'(CLI 플래그 또는 config
      파일)으로 구현한다. 자가호스팅 HTTP JSON 에이전트를 --url/--agent-config 로
      겨냥해, 스캔 파이프라인(scan_once/stability/handoff)을 **그대로 재사용**한다.
      신규 스캔로직 0 — 신규는 전송로(transport)뿐.

왜: 지금까지 자기 에이전트를 스캔하려면 AgentAdapter 를 코딩해야 했다(전문가 벽).
    이 어댑터는 그 벽을 없애 "흥미 → 사용" 전환을 연다.

[커스터디] 유저 키는 .env(gitignored)의 **환경변수에서만** 읽는다. config/flag 엔 env
  var '이름'만 담기고 값은 담기지 않는다(config 가 커밋돼도 키가 새지 않는다). 어댑터는
  유저 키를 attribute 로 보관하지 않고, 요청 헤더를 조립하는 순간에만 지역적으로 쓴다.
  요청 본문/헤더는 로그하지 않는다. 응답에 시크릿이 나타나면 기존 마스킹(scan.mask_secret)이
  처리한다. **소유·통제하는 에이전트만 스캔할 것** — 제3자 엔드포인트 프로빙은 유저 책임.

무손상: probe 소스(PROBE_SPECS)·detect_secrets·마스킹 전부 무변경. 이 파일은 전송로만
        추가한다(additive).
"""
import copy
import json
import os
import re

import requests

from .base import AgentAdapter, AgentCallError, AgentConfigError, ensure_ok

# `{ENV_VAR}` 토큰 — auth 헤더 템플릿에서 환경변수 값으로 치환.
_ENV_TOKEN = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

# dot_get 의 "경로 없음" 센티넬 (None 은 정당한 응답 값일 수 있어 구분한다).
_MISSING = object()


def _dot_split(path):
    return [seg for seg in str(path).split(".") if seg != ""]


def dot_get(obj, path, default=_MISSING):
    """중첩 JSON 에서 dot-path 로 값을 꺼낸다 (결정론적).

    예: dot_get(data, "choices.0.message.content"). 리스트는 정수 인덱스로,
    dict 는 키로 내려간다. 경로가 끊기면 default(기본 _MISSING) 반환.
    """
    cur = obj
    for seg in _dot_split(path):
        if isinstance(cur, list):
            try:
                idx = int(seg)
            except ValueError:
                return default
            if not (-len(cur) <= idx < len(cur)):
                return default
            cur = cur[idx]
        elif isinstance(cur, dict):
            if seg not in cur:
                return default
            cur = cur[seg]
        else:
            return default
    return cur


def dot_set(body, path, value):
    """dot-path 위치에 값을 써넣는다 (프롬프트를 요청 본문에 주입).

    중간 dict 키가 없으면 생성한다. 리스트 인덱스는 템플릿에 이미 존재해야 한다
    (본문 템플릿이 구조를 정의하고, 여기선 leaf 만 채운다). 빈 경로는 오류.
    """
    segs = _dot_split(path)
    if not segs:
        raise ValueError("prompt-field 경로가 비어 있습니다")
    cur = body
    for seg in segs[:-1]:
        if isinstance(cur, list):
            cur = cur[int(seg)]
        else:
            if not isinstance(cur.get(seg), (dict, list)):
                cur[seg] = {}
            cur = cur[seg]
    last = segs[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value
    return body


def resolve_auth_header(spec):
    """auth 헤더 스펙을 (name, value) 로 해석한다. 값은 오직 환경변수에서만 온다.

    스펙 형식 두 가지 (둘 다 config/flag 엔 env var '이름'만 담긴다):
      1) 'Header-Name=ENV_VAR'                 → 헤더값 = os.environ[ENV_VAR]
      2) 'Header-Name=Bearer {ENV_VAR} ...'    → `{ENV_VAR}` 토큰만 환경값으로 치환
    dict 형식({"name": ..., "value": ...})도 허용(value 는 위 템플릿 규칙 동일).
    env var 미설정이면 조용한 0 대신 명확한 에러로 멈춘다(커스터디·오탐 방지).
    """
    if isinstance(spec, dict):
        name = str(spec.get("name", "")).strip()
        template = str(spec.get("value", spec.get("template", ""))).strip()
        if not name:
            raise AgentConfigError(
                "[auth] config 의 auth_header 에 name 이 없습니다", reason="auth_format"
            )
    else:
        name, sep, template = str(spec).partition("=")
        name = name.strip()
        template = template.strip()
        if not sep or not name:
            raise AgentConfigError(
                "[auth] --auth-header 형식은 'Header-Name=ENV_VAR' 여야 합니다",
                reason="auth_format",
            )

    missing = []
    if "{" in template and "}" in template:
        # 템플릿 모드: `{ENV_VAR}` 토큰만 치환(Bearer 등 스킴 지원).
        def _sub(m):
            var = m.group(1)
            val = os.environ.get(var)
            if val is None:
                missing.append(var)
                return ""
            return val

        value = _ENV_TOKEN.sub(_sub, template)
    else:
        # 단순 모드: RHS 전체가 env var '이름'. 값을 환경에서 주입.
        val = os.environ.get(template)
        if val is None:
            missing.append(template)
            value = ""
        else:
            value = val

    if missing:
        raise AgentConfigError(
            f"[auth] 환경변수 {', '.join(missing)} 미설정 — .env 에 값을 넣으세요. "
            "(config/flag 엔 이름만 적습니다; 값은 .env 에서만 읽습니다.)",
            reason="auth_missing_env",
        )
    return name, value


def _stringify(v):
    """스캔은 문자열을 받는다. 응답 필드가 str 이 아니면 JSON 직렬화해 넘긴다
    (누출을 문자열 밖에 숨기지 않도록)."""
    if v is None:
        return None
    if isinstance(v, str):
        return v
    return json.dumps(v, ensure_ascii=False)


class GenericHTTPAdapter(AgentAdapter):
    """설정으로 구성하는 HTTP JSON 에이전트 어댑터.

    ask() 는 프롬프트를 body 의 prompt_field(dot-path)에 주입해 POST/GET 하고,
    응답에서 response_field(dot-path)로 답을 꺼낸다. reasoning_field 가 있으면
    추론 트레이스도 함께 꺼내 누적한다(사후 reasoning-scan 용, 추가 호출 없음).
    """

    def __init__(
        self,
        url,
        prompt_field,
        response_field,
        method="POST",
        auth_header=None,
        headers=None,
        body=None,
        reasoning_field=None,
        timeout=60,
        name=None,
    ):
        if not url:
            # ⚠ scan.py 의 `is_own = args.url is not None ...` 센티널과 **둘 다**
            #   load-bearing 이다. 센티널이 빈 url 을 여기로 보내고(라우팅), 이
            #   검증이 거부한다(거부). 둘 중 하나를 중복이라 판단해 지우면 빈
            #   --url 이 번들 데모로 폴백하는 버그가 다시 열린다.
            #   불변식은 어느 한 줄이 아니라 둘의 합의다.
            raise AgentConfigError(
                "[config] --url (또는 config 의 url)이 필요합니다", reason="missing_url"
            )
        if not prompt_field:
            raise AgentConfigError(
                "[config] --prompt-field (프롬프트를 넣을 JSON 필드)가 필요합니다",
                reason="missing_prompt_field",
            )
        if not response_field:
            raise AgentConfigError(
                "[config] --response-field (응답에서 답을 꺼낼 경로)가 필요합니다",
                reason="missing_response_field",
            )
        self.url = url
        self.method = (method or "POST").upper()
        self.prompt_field = prompt_field
        self.response_field = response_field
        self.reasoning_field = reasoning_field
        self.body_template = body if isinstance(body, (dict, list)) else {}
        self.static_headers = dict(headers or {})
        # 스펙만 보관 — 실제 키 값은 attribute 로 저장하지 않는다(커스터디).
        self.auth_header_spec = auth_header
        self.timeout = timeout
        self.name = name or self._derive_name(url)
        # 추론 트레이스 누적 (추가 API 호출 없이 사후 reasoning-scan 용).
        self.last_reasoning = None
        self.reasoning_log = []  # list[(probe, reasoning_text|None)]

    @staticmethod
    def _derive_name(url):
        stripped = re.sub(r"^https?://", "", url).split("?")[0]
        return "own:" + stripped[:60]

    def _build_headers(self):
        headers = {"Content-Type": "application/json"}
        headers.update(self.static_headers)
        if self.auth_header_spec:
            name, value = resolve_auth_header(self.auth_header_spec)
            headers[name] = value  # 지역 변수 — self 에 저장하지 않는다
        return headers

    def _record_reasoning(self, probe, reasoning_text):
        self.last_reasoning = reasoning_text
        self.reasoning_log.append((probe, reasoning_text))

    def ask(self, user_input):
        body = copy.deepcopy(self.body_template)
        dot_set(body, self.prompt_field, user_input)
        try:
            resp = requests.request(
                self.method,
                self.url,
                json=body,
                headers=self._build_headers(),
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            # 연결 실패·DNS·읽기 타임아웃. 예전엔 raw traceback 이었다.
            raise AgentCallError(
                f"{self.name}: {type(e).__name__}",
                reason="transport_error",
                target=self.name,
            ) from e

        # 상태 검사는 json()/text 접근보다 **먼저**. 뒤에 두면 4xx/5xx 오류 본문이
        # 이미 스캔 대상 텍스트가 된 뒤이고, 오류 본문엔 시크릿 모양이 없으니
        # "결함 0건 → 안전"이라는 거짓 GREEN 이 된다.
        ensure_ok(resp, self.name)

        try:
            data = resp.json()
        except ValueError:
            # 2xx 인데 비-JSON: 원문 텍스트를 그대로 스캔(누출 은닉 방지).
            # 오류 페이지가 아니라 성공 응답이므로 스캔 대상이 맞다.
            self._record_reasoning(user_input, None)
            return resp.text

        answer = dot_get(data, self.response_field)
        if answer is _MISSING:
            # 경로가 응답과 안 맞으면 전체 payload 를 스캔(조용한 miss 방지).
            answer = json.dumps(data, ensure_ascii=False)

        reasoning = None
        if self.reasoning_field:
            r = dot_get(data, self.reasoning_field)
            reasoning = None if r is _MISSING else r
        self._record_reasoning(user_input, _stringify(reasoning))
        return _stringify(answer)

    def get_target_name(self):
        return self.name


def load_agent_config(path):
    """config 파일(YAML 또는 JSON)을 dict 로 로드한다. yaml 은 여기서만 lazy import
    (flat 플래그만 쓰는 유저는 `pip install requests` 로 충분)."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    import yaml  # lazy: --agent-config 를 쓸 때만 필요

    data = yaml.safe_load(text)  # YAML 로더는 JSON 도 파싱
    if not isinstance(data, dict):
        raise AgentConfigError(
            f"[config] {path} 는 매핑(YAML/JSON 객체)이어야 합니다",
            reason="config_not_mapping",
        )
    return data


def build_generic_adapter(args):
    """CLI args + (선택) config 파일을 병합해 GenericHTTPAdapter 를 만든다.

    우선순위: flat 플래그 > config 파일. flat 로 안 되는 중첩 body/커스텀 헤더는
    config 파일(body/headers)로만 준다.
    """
    cfg = {}
    if getattr(args, "agent_config", None):
        cfg = load_agent_config(args.agent_config)

    def pick(flag_attr, cfg_key):
        # 센티널: 제공된 falsy 값(빈 문자열, 0)을 버리지 않는다. 버리면 유저가 명시한
        # 값이 조용히 기본값으로 바뀐다. 빈 url 이 데모로 폴백하던 버그와 같은 부류다.
        v = getattr(args, flag_attr, None)
        return v if v is not None else cfg.get(cfg_key)

    # 세 인자의 답이 서로 다르다 — is not None 일괄 치환은 오답이다.
    #   --method ""   : 보존하면 잘못된 HTTP 요청 → 입구에서 거부(argparse 검증).
    #   --timeout 0   : 보존하면 즉시 타임아웃      → 입구에서 거부(argparse 검증).
    #   --auth-header "": 유일하게 의미가 있다 = "auth 없음". 보존하고 config 폴백을 막는다.
    method = pick("method", "method")
    timeout = pick("timeout", "timeout")

    # `or cfg.get(...)` 였다: --auth-header "" 가 falsy 라 config 값으로 되살아났다.
    # "auth 를 끄겠다"는 명시적 의사를 config 가 덮어쓰면 안 된다.
    auth_header = getattr(args, "auth_header", None)
    if auth_header is None:
        auth_header = cfg.get("auth_header")
    if auth_header == "":
        auth_header = None  # 명시적 "auth 없음"

    return GenericHTTPAdapter(
        url=pick("url", "url"),
        prompt_field=pick("prompt_field", "prompt_field"),
        response_field=pick("response_field", "response_field"),
        method=method if method is not None else "POST",
        auth_header=auth_header,
        headers=cfg.get("headers"),
        body=cfg.get("body"),
        reasoning_field=pick("reasoning_field", "reasoning_field"),
        timeout=timeout if timeout is not None else 60,
        name=pick("target_name", "name"),
    )
