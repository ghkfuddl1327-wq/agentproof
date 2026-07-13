"""adapters — 스캐너가 다양한 타깃 에이전트를 동일 인터페이스로 검사하기 위한 어댑터 패키지.

import 시 .env(KEY=VALUE)를 os.environ에 로드한다. 두 위치를 본다:
  (1) 소스 트리 루트(개발 시 clone 루트) — 기존 동작 유지,
  (2) 현재 작업 디렉터리 ./.env — pip 설치 후 사용자가 CLI 를 실행하는 곳.
Claude Code의 Bash 셸은 사용자의 대화형 터미널 export를 상속하지 않으므로,
키는 .env에 적어두면 어댑터가 환경변수로 읽어 쓴다(.env는 .gitignore 대상).
설치판에서는 (1)이 site-packages 내부라 무의미 → (2)가 실제 동작 경로다.
"""

import os


def _decode_dotenv(raw):
    """.env 바이트를 텍스트로. 셸마다 디스크에 남기는 바이트가 다르다.

    - bash/zsh      : UTF-8, LF
    - pwsh 7        : UTF-8(BOM 없음), CRLF
    - PowerShell 5.1: `>` 가 Out-File 이고 기본 인코딩이 Unicode = **UTF-16LE + BOM**
    - cmd.exe       : UTF-8, CRLF

    utf-8-sig 는 UTF-8 BOM 을 벗기고, 실패하면(0xff 0xfe 로 시작하는 UTF-16LE 등)
    utf-16 으로 재시도한다(BOM 으로 바이트 순서 판별).

    주장할 수 있는 것은 "이 바이트를 읽는다"이지 "PowerShell 5.1 을 통과한다"가 아니다.
    실 Windows 의 PATH/pip/console-script 해석은 여전히 미검증이다.
    """
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("utf-16")


def _unwrap_whole_assignment(line):
    """`'KEY=VALUE'` 처럼 **할당 전체**를 감싼 따옴표 짝만 벗긴다.

    cmd.exe 는 `echo 'K=V' > .env` 의 작은따옴표를 특수문자가 아니라 리터럴로
    파일에 남긴다. 그러면 키가 `'GEMINI_API_KEY`, 값이 `V'` 가 되어 둘 다 오염된다.

    **값 안의 따옴표는 건드리지 않는다.** `KEY='v'` 는 값이 `'v'` 로 남는다.
    """
    if len(line) >= 2 and line[0] == line[-1] and line[0] in "\"'" and "=" in line:
        return line[1:-1]
    return line


def _parse_dotenv(path):
    if not os.path.isfile(path):
        return
    with open(path, "rb") as f:
        text = _decode_dotenv(f.read())
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        line = _unwrap_whole_assignment(line)
        key, _, value = line.partition("=")
        # 키: 감싸는 따옴표를 벗긴다. 환경변수 이름에 따옴표가 들어갈 일은 없고,
        #     오염되면 키가 영영 안 잡힌다(cmd.exe 경로).
        key = key.strip().strip('"').strip("'").strip()
        # 값: **절대 벗기지 않는다.** 값은 자격증명 리터럴이고 우리 탐지는 리터럴
        #     매칭이다. 로더가 값을 변형하면 파일의 문자열과 메모리의 문자열이
        #     달라지고, FP/FN 이 우리가 통제하지 못하는 지점에서 태어난다.
        #     로더의 관용은 키 이름까지다 — 탐지 표면에는 닿지 않는다.
        value = value.strip()
        if not key:
            continue
        # 이미 환경에 있으면 덮어쓰지 않는다(실제 환경변수 우선).
        os.environ.setdefault(key, value)


def _load_dotenv():
    # (1) 소스 트리 루트(= 이 파일에서 두 단계 위), (2) 현재 작업 디렉터리.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    seen = set()
    for path in (os.path.join(root, ".env"), os.path.join(os.getcwd(), ".env")):
        rp = os.path.realpath(path)
        if rp in seen:
            continue
        seen.add(rp)
        _parse_dotenv(path)


_load_dotenv()
