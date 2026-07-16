#!/usr/bin/env python3
"""verify_release_identity.py — 게시물 삼자 정합 검사 (repo ↔ wheel ↔ PyPI).

왜 필요한가: "GitHub 에서 읽은 코드"와 "pip 로 설치되는 코드"가 다르면, 이 repo 의
공개 약속(= 코드를 읽고 GREEN 숫자를 재현할 수 있다)이 조용히 깨진다. 버전 문자열만
같고 내용이 다른 게 가장 흔한 사고라서, **파일 바이트**로 대조한다.

무엇을 검사하나:
  1) repo 의 agentproof_scan/** == wheel 안의 같은 경로 (sha256 바이트 동일)
  2) wheel 에 allow-list 밖 파일(스코어러/테스트/런처/GREEN) 미포함 — PyPI 는 되돌릴 수 없다
  3) __init__.__version__ == pyproject version == wheel 파일명 버전
  4) (--pypi) 라이브 PyPI 휠을 받아 로컬 휠과 대조 — 업로드 후 확인용

사용:
  python verify_release_identity.py                       # repo ↔ 로컬 dist/ 휠
  python verify_release_identity.py --pypi                # + 라이브 PyPI 대조(네트워크)

종료코드: 0=정합, 1=불일치(게시 금지), 2=사용 오류.
"""
import argparse
import hashlib
import pathlib
import re
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).parent
PKG = "agentproof_scan"

# 휠에 절대 들어가면 안 되는 것 — pyproject 의 explicit allow-list 규율과 같은 의도.
FORBIDDEN = ("score_", "test_", "secrets_integrity", "hcot_probes", "reverify",
             "storage_classifier", "repro_channel", "green.json", "extract_")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def find_wheel() -> pathlib.Path:
    whls = sorted((ROOT / "dist").glob("*.whl"))
    if not whls:
        sys.exit("dist/ 에 휠이 없다 — `python -m build` 먼저.")
    return whls[-1]


def declared_version() -> tuple[str, str]:
    init = (ROOT / PKG / "__init__.py").read_text(encoding="utf-8")
    v_init = re.search(r'__version__\s*=\s*"([^"]+)"', init).group(1)
    toml = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    v_toml = re.search(r'^version\s*=\s*"([^"]+)"', toml, re.M).group(1)
    return v_init, v_toml


def check_wheel(whl: pathlib.Path) -> int:
    bad = 0
    z = zipfile.ZipFile(whl)
    names = z.namelist()

    # (3) 버전 삼자 일치
    v_init, v_toml = declared_version()
    v_whl = whl.name.split("-")[1]
    ok = v_init == v_toml == v_whl
    print(f"[version] __init__={v_init} pyproject={v_toml} wheel={v_whl}  {'OK' if ok else 'MISMATCH'}")
    bad += not ok

    # (2) allow-list — 휠에 개발 헬퍼/아티팩트가 섞이지 않았나
    leaked = [n for n in names if any(k in n for k in FORBIDDEN)]
    print(f"[custody] 금지 파일 {len(leaked)}건  {'OK' if not leaked else 'LEAKED: ' + str(leaked)}")
    bad += bool(leaked)

    # (1) repo ↔ wheel 바이트 동일
    mismatch, checked = [], 0
    for n in names:
        if not n.startswith(f"{PKG}/") or not n.endswith(".py"):
            continue
        local = ROOT / n
        if not local.exists():
            mismatch.append(f"{n} (repo 에 없음 — 휠에만 존재)")
            continue
        checked += 1
        if sha(z.read(n)) != sha(local.read_bytes()):
            mismatch.append(f"{n} (바이트 상이)")
    # 역방향: repo 에 있는데 휠에 빠진 모듈
    for p in (ROOT / PKG).rglob("*.py"):
        rel = p.relative_to(ROOT).as_posix()
        if "__pycache__" in rel:
            continue
        if rel not in names:
            mismatch.append(f"{rel} (휠에 누락 — repo 에만 존재)")
    print(f"[identity] {checked} 모듈 대조, 불일치 {len(mismatch)}  {'OK' if not mismatch else ''}")
    for m in mismatch:
        print(f"    ✗ {m}")
    bad += bool(mismatch)
    return bad


def check_pypi(whl: pathlib.Path) -> int:
    v = whl.name.split("-")[1]
    with tempfile.TemporaryDirectory() as td:
        r = subprocess.run(
            [sys.executable, "-m", "pip", "download", "--no-deps", "--only-binary=:all:",
             f"agentproof-scan=={v}", "-d", td],
            capture_output=True, text=True)
        if r.returncode != 0:
            print(f"[pypi] {v} 를 받지 못함 — 아직 업로드 전이거나 네트워크 문제.")
            print("       (업로드 전이면 정상. 업로드 후 다시 실행할 것.)")
            return 0
        got = sorted(pathlib.Path(td).glob("*.whl"))[-1]
        same = sha(got.read_bytes()) == sha(whl.read_bytes())
        print(f"[pypi] live {got.name} == local {whl.name}: {'OK' if same else 'MISMATCH'}")
        if not same:
            print("       → PyPI 에 올라간 바이트가 이 repo 의 빌드와 다르다. 재빌드/재업로드 판단 필요.")
        return 0 if same else 1


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pypi", action="store_true", help="라이브 PyPI 휠과도 대조(네트워크)")
    a = ap.parse_args()
    whl = find_wheel()
    print(f"대상 휠: {whl.name}\n")
    bad = check_wheel(whl)
    if a.pypi:
        bad += check_pypi(whl)
    print("\n" + ("정합 ✔ — 게시 가능" if not bad else f"불일치 {bad}건 ✗ — 게시 금지"))
    sys.exit(0 if not bad else 1)


if __name__ == "__main__":
    main()
