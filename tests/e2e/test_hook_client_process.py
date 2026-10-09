"""The hook client as Claude Code runs it: a real ``python -I -S hook_client.py <sub>`` process.

No daemon is involved here (tests/e2e/test_daemon_roundtrip.py covers that); these tests pin down
what only a real process can show: byte I/O, ASCII-only stdout, exit codes, environment
independence, the time budget, and that every real event captured in M0a gets a valid answer.
"""

from __future__ import annotations

import asyncio
import json
import locale
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from boundkeep import ownhook, protocol
from boundkeep.ipc import endpoint as ipc_endpoint
from tests.conftest import FIXTURES_DIR, REPO_ROOT, scrubbed_env
from tests.helpers.pipes import new_pipe_endpoint, threaded_pipe_server

pytestmark = pytest.mark.e2e

HOOK = REPO_ROOT / "src" / "boundkeep" / "hook_client.py"
SRC = REPO_ROOT / "src"
ALL_FIXTURES = sorted(p.stem for p in FIXTURES_DIR.glob("*.json") if p.stem != "index")


def run_hook(
    sub: str | None,
    stdin: bytes,
    env: dict[str, str],
    *,
    timeout: float = 30,
) -> subprocess.CompletedProcess[bytes]:
    argv = [sys.executable, "-I", "-S", str(HOOK)]
    if sub is not None:
        argv.append(sub)
    return subprocess.run(
        argv, input=stdin, capture_output=True, env=env, timeout=timeout, check=False
    )


def decision_of(proc: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.endswith(b"\n")
    assert b"\r" not in proc.stdout  # raw bytes: no text-mode newline translation
    proc.stdout.decode("ascii")
    parsed = json.loads(proc.stdout)
    assert list(parsed) == ["hookSpecificOutput"]
    specific = parsed["hookSpecificOutput"]
    assert specific["hookEventName"] == "PreToolUse"
    return specific  # type: ignore[no-any-return]


def assert_valid_hook_result(proc: subprocess.CompletedProcess[bytes]) -> None:
    assert proc.returncode in (0, 2), (proc.returncode, proc.stderr[:300])
    if proc.stdout:
        proc.stdout.decode("ascii")
        json.loads(proc.stdout)
    if proc.returncode == 2:
        assert proc.stderr


def _sub_for(event_name: str) -> str | None:
    return ownhook.SUBCOMMANDS.get(event_name)


def test_without_an_endpoint_a_pre_event_asks_and_mentions_init(
    fixture_bytes: Any, hook_env: dict[str, str]
) -> None:
    proc = run_hook("pre", fixture_bytes("PreToolUse__PowerShell"), hook_env)
    decision = decision_of(proc)
    assert decision["permissionDecision"] == "ask"
    assert "boundkeep init" in decision["permissionDecisionReason"]


def test_with_an_endpoint_but_no_daemon_a_pre_event_asks_and_says_so(
    fixture_bytes: Any, hook_env: dict[str, str], boundkeep_home: Path
) -> None:
    endpoint = ipc_endpoint.new_endpoint(str(boundkeep_home))
    ipc_endpoint.write_endpoint(str(boundkeep_home / "endpoint.json"), endpoint)
    started = time.monotonic()
    proc = run_hook("pre", fixture_bytes("PreToolUse__PowerShell"), hook_env)
    assert "not running" in decision_of(proc)["permissionDecisionReason"]
    assert time.monotonic() - started < 5


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_every_real_event_from_m0a_gets_a_valid_answer(
    name: str, fixture_bytes: Any, hook_env: dict[str, str]
) -> None:
    """Chinese text, check marks, backslash paths, both hosts, every event type."""
    raw = fixture_bytes(name)
    event_name = json.loads(raw)["hook_event_name"]
    proc = run_hook(_sub_for(event_name), raw, hook_env)
    assert_valid_hook_result(proc)
    if event_name == "PreToolUse":
        assert decision_of(proc)["permissionDecision"] == "ask"  # daemon is down: fail closed
    else:
        assert proc.stdout == b""


def test_the_environment_of_the_developer_shell_cannot_change_the_result(
    fixture_bytes: Any, hook_env: dict[str, str], tmp_path: Path
) -> None:
    """-I ignores PYTHON*: a hostile PYTHONPATH/PYTHONIOENCODING must not matter (M0a E18)."""
    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "json.py").write_text("import os\nos._exit(1)\n", encoding="utf-8")
    env = dict(hook_env)
    env.update(
        {
            "PYTHONPATH": str(evil),
            "PYTHONIOENCODING": "ascii",
            "PYTHONUTF8": "0",
            "PYTHONLEGACYWINDOWSSTDIO": "1",
            "PYTHONSTARTUP": str(evil / "json.py"),
        }
    )
    proc = run_hook(
        "pre",
        fixture_bytes("UserPromptSubmit__chinese").replace(b"UserPromptSubmit", b"PreToolUse"),
        env,
    )
    assert decision_of(proc)["permissionDecision"] == "ask"


@pytest.mark.skipif(
    locale.getpreferredencoding(False).lower() not in ("cp936", "gbk"),
    reason="needs a Chinese ANSI code page (zh-CN Windows) to show the bug being guarded",
)
def test_control_a_naive_text_mode_hook_misreads_chinese_input_under_cp936(
    hook_env: dict[str, str],
) -> None:
    """Why byte I/O exists.

    M0a believed the obvious implementation crashes with exit code 1; it does not (the text layer
    of stdin uses the surrogateescape handler). It silently reads DIFFERENT text, so rules that
    match paths or commands containing such characters stop matching. Corrected 2026-10-07;
    see experiments/probe_stdin_encoding.py and docs/hook-behavior.md E18.
    """
    original = {"command": "echo 你好 ✓ done"}
    data = json.dumps(original, ensure_ascii=False).encode("utf-8")
    proc = subprocess.run(
        [sys.executable, "-I", "-S", "-c", "import json, sys; print(ascii(json.load(sys.stdin)))"],
        input=data,
        capture_output=True,
        env=hook_env,
        check=False,
    )
    assert proc.returncode == 0  # no crash ...
    assert proc.stdout.decode("ascii").strip() != ascii(original)  # ... but not the same text


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"{", id="truncated"),
        pytest.param(b"[]", id="array"),
        pytest.param(b"\xff\xfe\x00{}", id="utf16-bom"),
        pytest.param('{"hook_event_name":"PreToolUse","x":"你好"}'.encode("gbk"), id="gbk-bytes"),
        pytest.param(b"\x00" * 1000, id="nul-bytes"),
        pytest.param(b"\x1a" + b" " * 10, id="ctrl-z"),
        pytest.param(b"[" * 20000, id="deep-nesting"),
    ],
)
def test_garbage_on_stdin_asks_for_pre_and_is_quiet_for_other_events(
    data: bytes, hook_env: dict[str, str]
) -> None:
    pre = run_hook("pre", data, hook_env)
    assert decision_of(pre)["permissionDecision"] == "ask"
    for sub in ("post", "prompt"):
        quiet = run_hook(sub, data, hook_env)
        assert (quiet.returncode, quiet.stdout) == (0, b"")
    blocked = run_hook("config", data, hook_env)
    assert blocked.returncode == 2
    assert blocked.stdout == b""
    assert b"blocked" in blocked.stderr


@pytest.mark.parametrize("sub", [None, "post", "bogus", ""])
def test_a_missing_or_wrong_argument_asks_for_a_pre_event(
    sub: str | None, fixture_bytes: Any, hook_env: dict[str, str]
) -> None:
    proc = run_hook(sub, fixture_bytes("PreToolUse__PowerShell"), hook_env)
    assert "mismatch" in decision_of(proc)["permissionDecisionReason"]


def test_pretty_printed_crlf_json_is_read_as_bytes(
    fixture_bytes: Any, hook_env: dict[str, str], boundkeep_home: Path
) -> None:
    """No text-mode newline translation on stdin: CRLF between tokens parses like anything else."""
    event = json.loads(fixture_bytes("PreToolUse__PowerShell"))
    raw = json.dumps(event, indent=2, ensure_ascii=False).replace("\n", "\r\n").encode("utf-8")
    endpoint = ipc_endpoint.new_endpoint(str(boundkeep_home))
    ipc_endpoint.write_endpoint(str(boundkeep_home / "endpoint.json"), endpoint)
    proc = run_hook("pre", raw, hook_env)
    # it got as far as talking to the (absent) daemon, i.e. the event itself parsed
    assert "not running" in decision_of(proc)["permissionDecisionReason"]


def test_version_flag_works_without_stdin(hook_env: dict[str, str]) -> None:
    proc = subprocess.run(
        [sys.executable, "-I", "-S", str(HOOK), "--version"],
        input=b"",
        capture_output=True,
        env=hook_env,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout.startswith(b"boundkeep-hook ")


def test_a_stalled_stdin_is_cut_off_by_the_budget(hook_env: dict[str, str]) -> None:
    env = dict(hook_env, BOUNDKEEP_HOOK_BUDGET_S="1.5")
    argv = [sys.executable, "-I", "-S", str(HOOK), "pre"]
    proc = subprocess.Popen(
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    started = time.monotonic()
    proc.stdin.write(b'{"hook_event_name": "PreToolUse", ')  # ... and never finishes or closes
    proc.stdin.flush()
    try:
        # not communicate(): that would close stdin and turn the stall into a plain EOF
        proc.wait(timeout=10)
        elapsed = time.monotonic() - started
        out = proc.stdout.read()
    finally:
        proc.kill()
        proc.stdin.close()
        proc.stdout.close()
        assert proc.stderr is not None
        proc.stderr.close()
    assert elapsed < 4, elapsed
    assert proc.returncode == 0
    parsed = json.loads(out)["hookSpecificOutput"]
    assert parsed["permissionDecision"] == "ask"
    assert "timed out" in parsed["permissionDecisionReason"]


def test_when_stdout_is_closed_the_answer_is_block_not_silence(
    fixture_bytes: Any, hook_env: dict[str, str]
) -> None:
    argv = [sys.executable, "-I", "-S", str(HOOK), "pre"]
    proc = subprocess.Popen(
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=hook_env
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    assert proc.stderr is not None
    proc.stdout.close()  # the hook is still waiting for stdin, so it cannot have written yet
    try:
        proc.stdin.write(fixture_bytes("PreToolUse__PowerShell"))
        proc.stdin.close()
        proc.wait(timeout=20)
        err = proc.stderr.read()
    finally:
        proc.kill()
        proc.stderr.close()
    assert proc.returncode == 2
    assert b"could not deliver" in err


def test_the_import_closure_stays_light(hook_env: dict[str, str]) -> None:
    """Every import is paid on every tool call (measured: dataclasses +11 ms, typing +2.6 ms)."""
    code = (
        "import sys, json; sys.path.insert(0, sys.argv[1]); base = set(sys.modules); "
        "import boundkeep.hook_client; print(json.dumps(sorted(set(sys.modules) - base)))"
    )
    proc = subprocess.run(
        [sys.executable, "-I", "-S", "-c", code, str(SRC)],
        capture_output=True,
        env=hook_env,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    loaded = set(json.loads(proc.stdout))
    forbidden = {
        "pydantic",
        "yaml",
        "typing",
        "dataclasses",
        "inspect",
        "socket",
        "asyncio",
        "logging",
        "subprocess",
        "argparse",
        "pathlib",
        "shutil",
        "tempfile",
        "boundkeep.install",
        "boundkeep.settings_io",
        "boundkeep.policy",
        "boundkeep.daemon",
        "boundkeep.cli",
    }
    assert not loaded & forbidden, sorted(loaded & forbidden)
    assert {m for m in loaded if m.startswith("boundkeep")} == {
        "boundkeep",
        "boundkeep.hook_client",
        "boundkeep.hook_main",
        "boundkeep.ownhook",
        "boundkeep.paths",
        "boundkeep.protocol",
        "boundkeep.ipc",
        "boundkeep.ipc.client",
        "boundkeep.ipc.endpoint",
    }


def test_scrubbed_env_really_removes_python_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHONIOENCODING", "utf-8")
    monkeypatch.setenv("BOUNDKEEP_HOME", "x")
    env = scrubbed_env()
    assert not [
        k for k in env if k.upper().startswith(("PYTHON", "BOUNDKEEP", "CLAUDE", "ANTHROPIC"))
    ]


@pytest.mark.windows
def test_a_daemon_that_accepts_but_never_answers_is_cut_off_by_the_budget(
    fixture_bytes: Any, hook_env: dict[str, str], boundkeep_home: Path
) -> None:
    """The hard case: the client is blocked inside a pipe read that has no timeout of its own."""
    endpoint = new_pipe_endpoint()
    ipc_endpoint.write_endpoint(str(boundkeep_home / "endpoint.json"), endpoint)

    async def hang(line: bytes) -> bytes:
        await asyncio.sleep(60)
        return b"{}\n"

    env = dict(hook_env, BOUNDKEEP_HOOK_BUDGET_S="1.5")
    with threaded_pipe_server(endpoint, hang, handler_timeout_s=60):
        started = time.monotonic()
        proc = run_hook("pre", fixture_bytes("PreToolUse__PowerShell"), env)
        elapsed = time.monotonic() - started
    decision = decision_of(proc)
    assert decision["permissionDecision"] == "ask"
    assert "timed out" in decision["permissionDecisionReason"]
    assert elapsed < 5, elapsed


@pytest.mark.windows
def test_when_every_pipe_instance_is_busy_the_client_gives_up_inside_its_budget(
    fixture_bytes: Any, hook_env: dict[str, str], boundkeep_home: Path
) -> None:
    endpoint = new_pipe_endpoint()
    ipc_endpoint.write_endpoint(str(boundkeep_home / "endpoint.json"), endpoint)

    async def echo(line: bytes) -> bytes:
        return protocol.encode_response(protocol.decode_request(line).request_id)

    env = dict(hook_env, BOUNDKEEP_HOOK_BUDGET_S="1.5")
    with threaded_pipe_server(endpoint, echo, instances=1, read_timeout_s=30):
        holder = open(endpoint.address, "r+b", buffering=0)  # noqa: SIM115 - takes the only instance
        try:
            started = time.monotonic()
            proc = run_hook("pre", fixture_bytes("PreToolUse__PowerShell"), env)
            elapsed = time.monotonic() - started
        finally:
            holder.close()
    decision = decision_of(proc)
    assert decision["permissionDecision"] == "ask"
    assert "busy" in decision["permissionDecisionReason"]
    assert elapsed < 5, elapsed


# --- a package that cannot even be imported must not let the call through ---------------------


def _broken_copy(tmp_path: Path, victim: str, source: str) -> Path:
    import shutil

    root = tmp_path / "src"
    shutil.copytree(
        SRC / "boundkeep", root / "boundkeep", ignore=shutil.ignore_patterns("__pycache__")
    )
    (root / "boundkeep" / victim).write_text(source, encoding="utf-8")
    return root / "boundkeep" / "hook_client.py"


@pytest.mark.parametrize(
    ("victim", "source"),
    [
        ("ownhook.py", "def (:\n"),  # SyntaxError
        ("protocol.py", "raise RuntimeError('boom')\n"),
        ("paths.py", "import no_such_module_anywhere\n"),
        ("hook_main.py", "x = 1 +\n"),
    ],
)
def test_a_package_that_fails_to_import_still_gives_a_safe_answer(
    tmp_path: Path, hook_env: dict[str, str], victim: str, source: str
) -> None:
    script = _broken_copy(tmp_path, victim, source)
    base = [sys.executable, "-I", "-S", str(script)]
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash"}).encode()
    pre = subprocess.run(
        [*base, "pre"], input=event, capture_output=True, env=hook_env, check=False
    )
    assert pre.returncode == 0
    assert json.loads(pre.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
    config = subprocess.run(
        [*base, "config"], input=b"{}", capture_output=True, env=hook_env, check=False
    )
    assert config.returncode == 2
    assert config.stderr
    for sub in ("post", "prompt"):
        quiet = subprocess.run(
            [*base, sub], input=b"{}", capture_output=True, env=hook_env, check=False
        )
        assert (quiet.returncode, quiet.stdout) == (0, b"")


def test_the_import_failure_answer_is_the_same_as_the_internal_error_answer() -> None:
    from boundkeep import hook_client, hook_main

    assert hook_client._ASK == hook_main._FALLBACK_ASK
