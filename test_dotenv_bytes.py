"""test_dotenv_bytes.py — 셸이 남기는 .env 바이트를 로더가 실제로 읽는가.

각 셸에서 README Quick Start 의 한 줄

    echo 'GEMINI_API_KEY=...' > .env

을 실행하면 디스크에 남는 바이트가 다르다. 실패는 셸이 아니라 로더에 있으므로,
바이트를 그대로 주입하면 충실한 재현이 된다.

  bash/zsh      UTF-8, LF                      — 정상 경로
  pwsh 7        UTF-8(BOM 없음), CRLF
  cmd.exe       UTF-8, CRLF, 작은따옴표가 리터럴로 남음 → 키가 `'GEMINI_API_KEY`
  PowerShell 5.1 `>` = Out-File, 기본 Unicode  → **UTF-16LE + BOM**

⚠ 이 파일이 주장할 수 있는 것은 **"이 바이트를 읽는다"** 뿐이다.
   "PowerShell 5.1 을 통과한다"가 아니다 — 실 Windows 의 PATH/pip/console-script
   해석, 셸의 리다이렉트 동작, 파일시스템 줄바꿈 정규화는 여전히 UNTESTED 다.
   문서에서 그 둘을 섞지 마라.
"""
import os
import tempfile

from agentproof_scan.adapters import _parse_dotenv

KEY = "GEMINI_API_KEY"
VALUE = "PASTE_YOUR_KEY_HERE"

VARIANTS = {
    "bash": f"{KEY}={VALUE}\n".encode("utf-8"),
    "pwsh7": f"{KEY}={VALUE}\r\n".encode("utf-8"),
    "cmd": f"'{KEY}={VALUE}' \r\n".encode("utf-8"),
    "ps51": b"\xff\xfe" + f"{KEY}={VALUE}\r\n".encode("utf-16-le"),
}


def _load(raw):
    """raw 바이트를 .env 로 써서 로더에 먹이고, 잡힌 값을 돌려준다."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, ".env")
        with open(path, "wb") as f:
            f.write(raw)
        os.environ.pop(KEY, None)
        try:
            _parse_dotenv(path)
            return os.environ.get(KEY)
        finally:
            os.environ.pop(KEY, None)


def test_bash_bytes_are_read():
    assert _load(VARIANTS["bash"]) == VALUE


def test_pwsh7_crlf_bytes_are_read():
    assert _load(VARIANTS["pwsh7"]) == VALUE, "CRLF 가 값에 섞였다"


def test_cmd_literal_quotes_do_not_poison_the_key():
    """cmd 는 작은따옴표를 리터럴로 남긴다. 인코딩 문제가 아니라 키 이름 문제다."""
    assert _load(VARIANTS["cmd"]) == VALUE, (
        "키에서 따옴표를 안 벗기면 환경변수 이름이 \"'GEMINI_API_KEY\" 가 되어 "
        "영영 안 잡힌다 — utf-8-sig/utf-16 폴백으로는 절대 안 고쳐지는 경로"
    )


def test_ps51_utf16le_bom_bytes_are_read():
    """예전 로더는 여기서 UnicodeDecodeError 로 죽었다(크래시, 조용한 0 아님)."""
    assert _load(VARIANTS["ps51"]) == VALUE


def test_real_env_wins_over_dotenv():
    """os.environ.setdefault 불변: 실제 환경변수가 .env 를 이긴다."""
    os.environ[KEY] = "real-wins"
    try:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, ".env")
            with open(path, "wb") as f:
                f.write(VARIANTS["bash"])
            _parse_dotenv(path)
            assert os.environ[KEY] == "real-wins"
    finally:
        os.environ.pop(KEY, None)


def test_comments_and_blank_lines_ignored():
    raw = b"# comment\n\n" + VARIANTS["bash"]
    assert _load(raw) == VALUE


# ── T7: 로더 관용의 경계 — 값은 절대 변형하지 않는다 ──────────────────────────────
#
# 로더에 관용을 넣는 방향은 스캐너의 엄격함과 반대다. 경계를 코드가 아니라
# 테스트로 못박는다:
#
#     키 이름 → 감싸는 따옴표를 벗긴다.   OK
#     값       → 절대 벗기지 않는다.
#
# 값은 자격증명 리터럴이고 우리 탐지는 리터럴 매칭이다. 로더가 값을 변형하면
# 파일의 문자열과 메모리의 문자열이 달라지고, FP/FN 이 통제 밖에서 태어난다.
def _load_key(raw, key):
    import tempfile as _t

    with _t.TemporaryDirectory() as d:
        p = os.path.join(d, ".env")
        with open(p, "wb") as f:
            f.write(raw)
        os.environ.pop(key, None)
        try:
            _parse_dotenv(p)
            return os.environ.get(key)
        finally:
            os.environ.pop(key, None)


def test_T7_value_quotes_are_preserved_not_stripped():
    """`MY_AGENT_KEY='sk-abc'` → 값은 따옴표를 포함한 `'sk-abc'` 그대로."""
    got = _load_key(b"MY_AGENT_KEY='sk-abc'\n", "MY_AGENT_KEY")
    assert got == "'sk-abc'", (
        f"로더가 값의 따옴표를 벗겼다: {got!r}. 값은 자격증명 리터럴이다 — "
        "로더가 변형하면 탐지가 매칭하는 문자열이 파일의 문자열과 달라진다."
    )


def test_T7b_double_quoted_value_also_preserved():
    assert _load_key(b'MY_AGENT_KEY="sk-abc"\n', "MY_AGENT_KEY") == '"sk-abc"'


def test_T7c_quote_inside_value_untouched():
    assert _load_key(b"MY_AGENT_KEY=sk-a'bc\n", "MY_AGENT_KEY") == "sk-a'bc"


def test_T7d_only_a_pair_wrapping_the_whole_assignment_is_stripped():
    """cmd.exe 의 `'K=V'` 는 할당 전체를 감싼다 — 그 짝만 벗긴다."""
    assert _load_key(b"'MY_AGENT_KEY=sk-abc' \r\n", "MY_AGENT_KEY") == "sk-abc"


def test_T7e_loader_leniency_never_touches_the_detection_surface():
    """탐지기는 로더를 거치지 않는다. 값이 어떻게 저장되든 매처는 원문을 본다."""
    from agentproof_scan.scan import detect_secrets

    raw_line = "MY_AGENT_KEY='AKIA1B2C3D4E5F6G7H8I'\n".encode("utf-8")
    loaded = _load_key(raw_line, "MY_AGENT_KEY")
    assert loaded == "'AKIA1B2C3D4E5F6G7H8I'", loaded
    # 로더가 무엇을 하든, 응답 텍스트에서 키를 찾는 건 detect_secrets 다.
    hits = detect_secrets("the key is AKIA1B2C3D4E5F6G7H8I")
    assert [h["match"] for h in hits] == ["AKIA1B2C3D4E5F6G7H8I"]


if __name__ == "__main__":
    fails = []
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS  {name}")
            except Exception as e:  # noqa: BLE001
                print(f"FAIL  {name}: {e}")
                fails.append(name)
    print("-" * 60)
    print("ALL GREEN ✔" if not fails else f"{len(fails)} FAIL ✗ → {fails}")
    raise SystemExit(1 if fails else 0)
