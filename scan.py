"""scan.py — clone 사용자용 편의 런처(`python scan.py ...`).

실제 코드는 패키지 agentproof_scan 로 옮겨졌다. 이 파일은 기존에 문서화된
`python scan.py --url ...` UX 를 그대로 유지하기 위한 얇은 위임 진입점이며,
휠(wheel)에는 포함되지 않는다([tool.setuptools] packages 에 없음).
pip 설치 사용자는 콘솔 스크립트 `agentproof-scan` 을 쓴다.
"""

from agentproof_scan.scan import main

if __name__ == "__main__":
    main()
