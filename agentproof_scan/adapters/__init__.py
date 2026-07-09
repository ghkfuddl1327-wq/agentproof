"""adapters — 스캐너가 다양한 타깃 에이전트를 동일 인터페이스로 검사하기 위한 어댑터 패키지.

import 시 .env(KEY=VALUE)를 os.environ에 로드한다. 두 위치를 본다:
  (1) 소스 트리 루트(개발 시 clone 루트) — 기존 동작 유지,
  (2) 현재 작업 디렉터리 ./.env — pip 설치 후 사용자가 CLI 를 실행하는 곳.
Claude Code의 Bash 셸은 사용자의 대화형 터미널 export를 상속하지 않으므로,
키는 .env에 적어두면 어댑터가 환경변수로 읽어 쓴다(.env는 .gitignore 대상).
설치판에서는 (1)이 site-packages 내부라 무의미 → (2)가 실제 동작 경로다.
"""

import os


def _parse_dotenv(path):
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
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
