"""adapters — 스캐너가 다양한 타깃 에이전트를 동일 인터페이스로 검사하기 위한 어댑터 패키지.

import 시 repo 루트의 .env(KEY=VALUE)를 os.environ에 로드한다.
Claude Code의 Bash 셸은 사용자의 대화형 터미널 export를 상속하지 않으므로,
키는 .env에 적어두면 어댑터가 환경변수로 읽어 쓴다(.env는 .gitignore 대상).
"""

import os


def _load_dotenv():
    # adapters/ 의 부모 = repo 루트.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, ".env")
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


_load_dotenv()
