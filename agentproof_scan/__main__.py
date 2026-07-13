"""`python -m agentproof_scan` 진입점.

콘솔 스크립트(`agentproof-scan`)가 PATH 에 안 잡히는 환경 — Windows 의 Scripts/ 디렉터리가
PATH 에 없거나, pipx/venv 를 activate 하지 않은 경우 — 을 위한 탈출구다. 같은 main() 을 부른다.
"""

from .scan import main

if __name__ == "__main__":
    main()
