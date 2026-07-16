"""
conftest.py — 테스트 격리 불변식 (test-only, shipped 코드 미접촉)

대상: fingerprint 의 per-deployment salt 상태. 두 조각이 프로세스 전역이다.
  · fingerprint._DEPLOYMENT_SALT_CACHE  (모듈 전역 캐시)
  · AGP_FINGERPRINT_SALT* 환경변수       (경로/무염 스위치)

무엇이 났었나(실측):
  test_failure_contract.run_cli() 은 CLI 환경을 재현하려고 os.environ.clear() 한다.
  그 창에서 스캐너가 지문을 만들면 salt 경로 override 가 사라져 **실 ~/.config** 로
  폴백해 파일을 만들고, 그 값이 _DEPLOYMENT_SALT_CACHE 에 눌러앉는다. 이후
  test_fingerprint 의 salt 테스트는 캐시 히트라 격리 경로에 파일을 만들지 않은 채
  os.path.exists(격리경로) 를 물어 죽는다. 게다가 /tmp 에 남은 이전 실행 잔존물이
  있으면 통과해버려서 — 결함이 "가끔 나는 flaky" 로 위장됐다. 0.1.4 에도 있던 결함이다.

왜 conftest 인가(열거 대신 불변식):
  run_cli 한 곳만 고치면 다음 전역에서 같은 사고가 또 난다. 이 아크에서 이미 세 번째
  (probe_freeze.FROZEN_FINGERPRINT → classify 모듈명 → salt 캐시). 그래서 "어떤 테스트도
  salt 전역을 오염시킨 채 끝낼 수 없다"를 불변식으로 박고, 어기면 **그 테스트가 자기
  이름으로** 실패하게 한다(무고한 후행 테스트가 대신 터지지 않는다).

FROZEN_FINGERPRINT 가드와의 관계: 대상이 다르고 겹치지 않는다. 그 가드는 사설 트리의
probe_freeze 모듈 전용이며, 공개 트리엔 probe_freeze 자체가 없다(공개 프로브 세트는
사설 동결 지문과 다른 집합). 여기선 salt 만 다룬다.
"""
import os
import pathlib

import pytest

import agentproof_scan.fingerprint as FP

_SALT_ENV = ("AGP_FINGERPRINT_SALT_FILE", "AGP_FINGERPRINT_SALT",
             "AGP_FINGERPRINT_SALT_DISABLE")


def _real_salt_dir() -> pathlib.Path:
    """사용자의 진짜 salt 디렉터리 — 테스트가 절대 건드리면 안 되는 곳."""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return pathlib.Path(base) / "agentproof"


@pytest.fixture(autouse=True)
def _salt_isolation(tmp_path, monkeypatch):
    """salt 전역(캐시+env)을 테스트마다 격리·복원하고, 오염시킨 테스트를 잡는다."""
    real_dir = _real_salt_dir()
    before_real = {p.name: p.stat().st_mtime_ns
                   for p in real_dir.glob("*")} if real_dir.exists() else {}
    saved_env = {k: os.environ.get(k) for k in _SALT_ENV}
    saved_cache = FP._DEPLOYMENT_SALT_CACHE

    # 테스트마다 새 경로 → 이전 실행 잔존물(/tmp/…)에 의존하지 않는다.
    iso_override = tmp_path / "salt_override"
    iso_fallback = tmp_path / "salt_fallback"
    monkeypatch.setenv("AGP_FINGERPRINT_SALT_FILE", str(iso_override))
    monkeypatch.delenv("AGP_FINGERPRINT_SALT", raising=False)
    monkeypatch.delenv("AGP_FINGERPRINT_SALT_DISABLE", raising=False)

    # ⚠ env 격리만으론 부족하다: run_cli 은 테스트 *도중* os.environ.clear() 하므로
    #   그 창에서는 override 가 사라져 실 ~/.config 로 폴백한다(HOME 도 지워지면
    #   expanduser 가 passwd 를 읽어 진짜 홈을 찾아낸다 — env 로는 못 막는다).
    #   그래서 경로 계산 자체를 격리한다: env override 분기는 그대로 살리고(문서화된
    #   동작), 폴백만 tmp 로 돌린다. 실 홈은 어떤 경로로도 닿지 않는다.
    def _isolated_salt_file_path():
        return os.environ.get("AGP_FINGERPRINT_SALT_FILE") or str(iso_fallback)

    monkeypatch.setattr(FP, "_salt_file_path", _isolated_salt_file_path)
    FP._DEPLOYMENT_SALT_CACHE = None          # 앞선 테스트가 데워둔 캐시 무효화

    yield

    FP._DEPLOYMENT_SALT_CACHE = saved_cache   # 후행 보호 — 먼저 복원
    for k, v in saved_env.items():            # monkeypatch 가 되돌리지만 명시 복원
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v

    after_real = {p.name: p.stat().st_mtime_ns
                  for p in real_dir.glob("*")} if real_dir.exists() else {}
    if after_real != before_real:
        pytest.fail(
            f"테스트 격리 위반: 실 salt 디렉터리 {real_dir} 를 건드렸다 "
            f"({sorted(set(after_real) - set(before_real)) or '내용 변경'}). "
            "salt 는 tmp 로 격리돼야 한다 — 사용자 홈은 테스트 대상이 아니다."
        )
