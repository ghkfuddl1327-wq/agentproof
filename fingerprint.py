"""fingerprint.py — 감사용 탐지 레코드 확장: type + scope + truncated one-way hash.

목적(감사 준비): 탐지 레코드가 *실값 없이* "어떤 크리덴셜(type) · 접근 범위(scope) ·
어느 인스턴스(fingerprint)"를 답하게 한다. raw value 는 어디에도 넣지 않는다.

이 모듈은 **순수**하다(scan/reasoning_scan 을 import 하지 않음 → 순환 없음). 마스킹은
호출부가 제공하는 mask_fn(예: scan.mask_secret)에 위임한다.

━━ 해시 규율 (중요) ━━
  · non-reversible one-way (SHA-256).
  · **truncated** (기본 48bit=12 hex). 목적은 "동일 시크릿 correlate/dedupe"(어느 인스턴스)
    이지 값 확인이 아니다.
  · 절단(truncate)의 이유: full-hash 는 저엔트로피 시크릿(약한 DB 비번 등, 후보공간이 작음)을
    공격자가 추측값 해싱으로 confirm 할 수 있다. 절단은 identity 를 주되, 저엔트로피 후보공간
    안에서 여러 후보가 같은 prefix 로 충돌하게 만들어 단일 값 confirm 을 모호하게 한다.
    (고엔트로피 API 키는 후보공간이 천문학적이라 어차피 confirm 불가 — 절단은 저엔트로피 커버용.)
  · per-deployment **salt = 기본 ON**(owner relay 07/08). salt 없이는 해시를 계산조차 할 수 없어
    오프라인 confirm 자체가 차단된다 → 저엔트로피 시크릿까지 confirm 불가(절단만으로 못 막던 구멍을
    salt 가 닫는다). 절단은 그 위의 보조 방어(값이 유출돼도 절단으로 identity만).
  · salt 해소 순서(salt=None 기본):
      1) AGP_FINGERPRINT_SALT_DISABLE=1 → 무염(opt-out; 배포 간 correlate 필요 시).
      2) AGP_FINGERPRINT_SALT=<값>       → 그 값(운영자가 명시 관리).
      3) (기본) per-deployment 랜덤 salt 파일 자동 생성·재사용
         (AGP_FINGERPRINT_SALT_FILE 또는 $XDG_CONFIG_HOME/agentproof/fingerprint_salt, 0600,
          repo 밖 → 커밋 위험 0). 배포 내 결정론(같은 값→같은 지문=dedupe) 유지 + 배포 간 상관 차단.
    호출 인자 salt= 는 항상 우선(salt="" 는 명시적 무염).

정직화: 자동 salt 파일은 per-deployment 준-비밀이다. 절대 커밋/출력 금지(repo 밖·0600). 감사에
공유하는 것은 *지문*(credential-free)이지 salt 가 아니다. 지문끼리 같음/다름 비교는 salt 몰라도 가능.

fingerprint 레코드는 credential-free → GREEN-safe(해시는 시크릿 아님) → 감사에 공유 가능.
raw 트레이스 대신 이 레코드만 보관 = 보관해도 시크릿 노출 0 → 변조면(tamper surface) 축소.
"""
import hashlib
import os

# ── type(패밀리) → scope(그 type 이 함의하는 접근 범위) 매핑 테이블 ──────────────────
# scan.PROVIDER_PATTERNS + OPTIONAL_PROVIDER_PATTERNS 의 16 패밀리를 모두 커버한다.
# scope 는 "이 크리덴셜이 유출되면 무엇에 접근 가능한가(blast radius)"를 사람이 읽는 한 줄로.
TYPE_SCOPE = {
    "anthropic":  "Anthropic API (Claude 모델 호출·조직 과금)",
    "openai":     "OpenAI API (모델 호출·조직 과금)",
    "xai":        "xAI API (Grok 모델 호출)",
    "google":     "Google API 키 (AIza — Maps/Cloud 등, 프로젝트 스코프)",
    "github":     "GitHub 액세스 (classic OAuth/PAT — 토큰 스코프 범위의 repo/org)",
    "github_pat": "GitHub fine-grained PAT (스코프 지정된 repo/org 접근)",
    "aws":        "AWS IAM 액세스 키 (IAM 정책 범위의 계정 리소스)",
    "stripe":     "Stripe API (live — 결제·고객 데이터)",
    "slack":      "Slack 워크스페이스 (bot/user 토큰 스코프)",
    "jwt":        "Bearer/ID 토큰 (클레임 범위의 세션/서비스) — exposure 신호(비밀 아닐 수 있음)",
    "pem":        "개인키 (TLS/SSH/서명 — 용도에 따라 blast radius 상이)",
    "sendgrid":   "SendGrid API (이메일 발송)",
    "gcp":        "Google OAuth 클라이언트 시크릿 (GCP 프로젝트)",
    "npm":        "npm 레지스트리 (패키지 publish 권한)",
    "twilio":     "Twilio API Key SID (메시지/음성) — exposure 신호(짝 시크릿 별도)",
    "postgres":   "PostgreSQL DB (자격증명 연결 — 옵트인 패밀리)",
}

# scope 미상 패밀리 fallback(신규 type 추가 시 매핑 누락을 조용히 삼키지 않도록 명시값).
UNKNOWN_SCOPE = "미상 (type→scope 매핑 없음 — TYPE_SCOPE 갱신 필요)"

DEFAULT_HEX_LEN = 12  # 48 bit. dedup identity vs 저엔트로피 confirm 저항의 절충 기본값.


def scope_for(secret_type: str) -> str:
    """type(패밀리) → scope 문자열. 미상이면 UNKNOWN_SCOPE(조용한 누락 방지)."""
    return TYPE_SCOPE.get(secret_type, UNKNOWN_SCOPE)


_DEPLOYMENT_SALT_CACHE = None  # 프로세스 캐시 (파일 salt 반복 IO 방지, 배포내 결정론 보장).


def _salt_file_path():
    """자동 per-deployment salt 파일 경로. repo 밖(커밋 위험 0). 테스트/배포 override 가능."""
    override = os.environ.get("AGP_FINGERPRINT_SALT_FILE")
    if override:
        return override
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return os.path.join(base, "agentproof", "fingerprint_salt")


def _load_or_create_deployment_salt():
    """per-deployment 랜덤 salt 를 파일에서 읽고, 없으면 생성·영속화(0600). 프로세스 캐시."""
    global _DEPLOYMENT_SALT_CACHE
    if _DEPLOYMENT_SALT_CACHE is not None:
        return _DEPLOYMENT_SALT_CACHE
    path = _salt_file_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            existing = f.read().strip()
        if existing:
            _DEPLOYMENT_SALT_CACHE = existing.encode("utf-8")
            return _DEPLOYMENT_SALT_CACHE
    except OSError:
        pass
    # 없음 → 128bit 랜덤 생성, 0600·O_EXCL 로 원자적 생성(동시 생성 경합은 재읽기로 수렴).
    new_salt = os.urandom(16).hex()
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, new_salt.encode("utf-8"))
        finally:
            os.close(fd)
        _DEPLOYMENT_SALT_CACHE = new_salt.encode("utf-8")
    except FileExistsError:
        # 경합: 다른 프로세스가 먼저 생성 → 그 값을 읽어 일관성 유지.
        with open(path, "r", encoding="utf-8") as f:
            _DEPLOYMENT_SALT_CACHE = f.read().strip().encode("utf-8")
    except OSError:
        # 파일시스템 불가(읽기전용 등) → 프로세스-로컬 salt 로 폴백(배포내 결정론만, 영속 X).
        _DEPLOYMENT_SALT_CACHE = new_salt.encode("utf-8")
    return _DEPLOYMENT_SALT_CACHE


def _resolve_salt(salt):
    """salt 정규화. 호출 인자 우선; None 이면 per-deployment salt 기본 ON(위 해소 순서)."""
    # 1) 명시 인자 우선 (salt="" → 명시적 무염).
    if salt is not None:
        return salt.encode("utf-8") if isinstance(salt, str) else salt
    # 2) opt-out: 무염(배포 간 correlate 필요 시).
    if os.environ.get("AGP_FINGERPRINT_SALT_DISABLE") == "1":
        return b""
    # 3) 운영자 명시 salt.
    env = os.environ.get("AGP_FINGERPRINT_SALT")
    if env:
        return env.encode("utf-8")
    # 4) 기본: per-deployment 랜덤 salt 파일(자동 생성·재사용).
    return _load_or_create_deployment_salt()


def secret_fingerprint(value: str, hex_len: int = DEFAULT_HEX_LEN, salt=None) -> str:
    """시크릿 raw 값 → truncated one-way SHA-256 지문 (raw 미포함, 결정론적).

    형식: "sha256-t<bits>:<hex>"  예) "sha256-t48:1a2b3c4d5e6f"
      · -t<bits> 접미사가 "절단됨"과 절단 비트수를 자기서술 → 감사 독자가 값 확인 불가임을 인지.
    같은 (value, salt, hex_len) → 같은 지문(correlate/dedupe 가능). 다른 값 → (충돌 확률 2^-bits
    로) 다른 지문. raw 는 해시 입력으로만 쓰이고 출력엔 원문 substring 이 남지 않는다.
    """
    salt_bytes = _resolve_salt(salt)
    h = hashlib.sha256()
    if salt_bytes:
        h.update(salt_bytes)
        h.update(b":")  # 도메인 구분자 — salt 와 value 경계 고정.
    h.update(value.encode("utf-8"))
    return "sha256-t{}:{}".format(hex_len * 4, h.hexdigest()[:hex_len])


def enrich_leaked(item: dict, mask_fn, hex_len: int = DEFAULT_HEX_LEN, salt=None) -> dict:
    """raw {provider, match} → 감사 레코드 {provider, match(마스킹), scope, fingerprint}.

    additive 규율: 기존 키(provider, match) 불변 + scope/fingerprint 만 추가. type 은
    기존 provider(패밀리) 필드가 곧 type 이므로 새 키를 만들지 않는다(진짜 additive).
      · match     : mask_fn(raw) — 마스킹된 값(원문 아님).
      · fingerprint: secret_fingerprint(raw) — raw 로부터 계산하되 원문 미포함.
      · scope     : provider 가 함의하는 접근 범위.
    raw(item["match"])는 fingerprint 해시 입력·mask_fn 입력으로만 소비되고 반환 dict 엔 없다.
    """
    provider = item["provider"]
    raw = item["match"]
    return {
        "provider": provider,  # == type(패밀리). 기존 계약 불변.
        "match": mask_fn(raw),  # 마스킹된 값 — 원문 아님.
        "scope": scope_for(provider),
        "fingerprint": secret_fingerprint(raw, hex_len=hex_len, salt=salt),
    }
