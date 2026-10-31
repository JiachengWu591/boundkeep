"""Regression tests for the medium findings of the independent X1 review of M3a (F1 to F6).

The review report was cut off after its summary (docs/reports/M3a-review-fixes.md says what is
left of it), so every case here was reproduced independently from the one-line descriptions:

* F3, F4: a gray call whose code or arguments the request to the LLM cannot carry (a
  here-document or here-string fed to a program, a ``NAME=value`` prefix, a string piped into an
  interpreter or an assignment in PowerShell, the arguments of an MCP call) is not sent; it asks,
  like a call the normalizer did not see whole (``pipeline.unshown_input``).
* F5: a resolver that hangs no longer holds an attempt of the OpenAI-compatible adapter past its
  budget, so it no longer leaves stuck decision workers behind that turn a rule's deny into the
  daemon's "busy" ask.
* F1, F6 and the MCP resource tools (looked at for F2) need a decision on the spec (X5): they are
  kept as strict ``xfail`` reproductions until then.

Inert payloads only: ``.invalid`` hosts, the ``BKCANARY`` marker, made-up machine paths; the LLM is
``FakeBackend`` (a model that always allows) or the loopback fake server with a blocked resolver.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from collections.abc import Iterator
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.audit.auditor import Auditor
from boundkeep.audit.backends import openai_compatible
from boundkeep.audit.backends.base import BackendError, verdict_json
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.normalize.event import normalize_event
from boundkeep.policy import Policy
from boundkeep.session.store import SessionStore
from tests.contract.conftest import request
from tests.helpers.llm_server import FakeLLMServer, Reply, tool_call_answer
from tests.unit.test_m3a_daemon import KEY, Harness, policy_text
from tests.unit.test_m3a_daemon import bash as daemon_bash
from tests.unit.test_m3a_pipeline import PROJECT, SID, bash, event, policy, post
from tests.unit.test_m3a_pipeline import decide as decide_with

CANARY = "BKCANARY"
WIN_HOME = "C:\\Users\\testuser"
WIN_PROJECT = "C:\\Users\\testuser\\proj"


def manipulated(pol: Policy) -> tuple[Auditor, FakeBackend]:
    """A model that was steered completely: allow, risk 0, no deviation, every time."""
    backend = FakeBackend.answering()
    return Auditor(pol.llm_audit, backend), backend


def audited(payload: dict[str, Any], *, on_failure: str = "ask") -> tuple[Any, FakeBackend]:
    pol = policy(llm=True, on_failure=on_failure)
    auditor, backend = manipulated(pol)
    return decide_with(payload, pol, auditor=auditor), backend


def assert_not_sent(decision: Any, backend: FakeBackend) -> None:
    assert backend.requests == []
    assert decision.decision == protocol.DECISION_ASK  # the user's question, whatever on_failure
    assert decision.decided_by == "gray-unanalysed"
    assert "not sent to the LLM audit" in decision.reason
    assert decision.llm is not None
    assert decision.llm["outcome"] == "not-sent"


# ------------------------------------------------------------------ F3: code the model cannot see

HIDDEN_CODE = [
    f"python3 - <<'EOF'\nprint('{CANARY}')\nEOF",
    f"python3 <<'EOF'\nprint('{CANARY}')\nEOF",
    f"python3 <<< 'print(\"{CANARY}\")'",
    f"node <<'EOF'\nconsole.log('{CANARY}')\nEOF",
    f"perl <<'EOF'\nprint '{CANARY}';\nEOF",
    f"psql <<'EOF'\nDROP TABLE {CANARY};\nEOF",
    f"sqlite3 db.sqlite <<< 'DROP TABLE {CANARY}'",
    f"bash ./tools/run.sh <<'EOF'\n{CANARY}\nEOF",  # the here-document is the script's input
    f"NODE_OPTIONS='--require ./{CANARY}.js' node app.js",
    f"PYTHONSTARTUP={CANARY}.py python3 app.py",
]


@pytest.mark.parametrize("command", HIDDEN_CODE)
@pytest.mark.parametrize("on_failure", ["ask", "deny"])
def test_code_the_request_cannot_carry_is_not_sent(command: str, on_failure: str) -> None:
    decision, backend = audited(bash(command), on_failure=on_failure)
    assert decision.verdict == "gray"
    assert_not_sent(decision, backend)


@pytest.mark.parametrize(
    "command",
    [
        f"bash <<'EOF'\necho {CANARY}\nEOF",  # a shell's here-document is parsed into commands
        f"sh <<< 'echo {CANARY}'",
        f"echo 'print({CANARY})' | python3",  # the code is the echo's argument
        "make test",
        f"python3 tool.py --name {CANARY}",
    ],
)
def test_a_gray_call_whose_code_is_all_in_the_request_is_still_sent(command: str) -> None:
    decision, backend = audited(bash(command))
    assert len(backend.requests) == 1
    assert decision.decided_by == "llm"


def test_a_shell_here_document_shows_its_commands_to_the_model() -> None:
    _decision, backend = audited(bash(f"bash <<'EOF'\necho {CANARY}\nEOF"))
    assert CANARY in backend.requests[0].content


@cache
def _ps_ready() -> bool:
    if sys.platform != "win32":
        return False
    from boundkeep.normalize import psparse

    psparse.warm_up(wait_s=15)
    return bool(psparse.status().get("state") == "ready")


def _ps(command: str) -> dict[str, Any]:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": SID,
        "cwd": WIN_PROJECT,
        "project_dir": WIN_PROJECT,
        "tool_name": "PowerShell",
        "tool_input": {"command": command},
    }


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        f"@'\nprint('{CANARY}')\n'@ | python -",
        "'print(1)' | python",
        f"$env:NODE_OPTIONS='--require ./{CANARY}.js'; node app.js",
        f"$env:DATABASE_URL='{CANARY}'; make migrate",
    ],
)
def test_powershell_code_or_values_the_request_cannot_carry_are_not_sent(command: str) -> None:
    if not _ps_ready():
        pytest.skip("needs the PowerShell parser helper")
    pol = policy(llm=True)
    auditor, backend = manipulated(pol)
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        _ps(command),
        mode="enforce",
        policy=pol,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": WIN_HOME},
        home=WIN_HOME,
        scan_disk=False,
        auditor=auditor,
    )
    assert decision.verdict == "gray"
    assert_not_sent(decision, backend)


# ------------------------------------------------------------ F4: arguments the model cannot see


@pytest.mark.parametrize(
    "command",
    [
        f"DATABASE_URL=postgres://{CANARY}.invalid/db make migrate",
        f"FOO={CANARY} python3 app.py",
        f"env DEPLOY_TARGET={CANARY} make deploy",
        f"TARGET={CANARY}; make deploy",
    ],
)
def test_a_variable_assignment_the_request_cannot_carry_is_not_sent(command: str) -> None:
    decision, backend = audited(bash(command))
    assert_not_sent(decision, backend)


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("mcp__db__execute", {"sql": "DELETE FROM BKCANARY"}),
        ("mcp__tracker__create_issue", {"title": "t", "body": f"{CANARY} body"}),
        ("mcp__docs__search", {"query": "release notes"}),
    ],
)
@pytest.mark.parametrize("on_failure", ["ask", "deny"])
def test_an_mcp_call_whose_arguments_are_not_shown_is_not_sent(
    tool: str, tool_input: dict[str, Any], on_failure: str
) -> None:
    decision, backend = audited(event(tool, tool_input), on_failure=on_failure)
    assert_not_sent(decision, backend)


def test_the_normalizer_names_what_an_action_does_not_carry() -> None:
    def unshown(command: str) -> list[tuple[str, ...]]:
        actions = normalize_event(
            bash(command), platform="posix", env={"HOME": "/home/testuser"}, home="/home/testuser"
        )
        return [a.unshown for a in actions if a.program or a.unshown]

    assert unshown("FOO=1 BAR=2 make") == [("env:FOO", "env:BAR")]
    assert unshown("env FOO=1 make") == [("env:FOO",)]
    assert unshown("python3 <<'EOF'\nx\nEOF") == [("heredoc",)]
    assert unshown("sqlite3 db <<< 'x'") == [("herestring",)]
    assert unshown("cat 3<<'EOF'\nx\nEOF") == [("heredoc:3",)]
    assert unshown("bash <<'EOF'\nls\nEOF") == [(), ()]  # bash, then the ls it reads
    assert unshown("make test") == [()]


# --------------------------------------------------- F5: a hanging resolver and the hard deadline


@pytest.fixture
def blocked_resolver(monkeypatch: pytest.MonkeyPatch) -> Iterator[threading.Event]:
    """``localhost`` does not resolve until the event is set (at the end of the test at most)."""
    release = threading.Event()
    real = socket.getaddrinfo

    def hanging(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host in ("localhost", b"localhost"):
            release.wait(20)
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", hanging)
    yield release
    release.set()


def _localhost(server: FakeLLMServer) -> str:
    return f"http://localhost:{server.port}/v1"


@pytest.mark.parametrize("transport", ["tool_call", "json_object"])
def test_a_hanging_resolver_does_not_stretch_the_adapter_budget(
    blocked_resolver: threading.Event, transport: str
) -> None:
    config = openai_compatible.OpenAICompatible.model_validate(
        {"base_url": "http://localhost:9/v1", "model": "m", "transport": transport}
    )
    backend = openai_compatible.OpenAICompatibleBackend(
        config, env={"BOUNDKEEP_LLM_API_KEY": "dummy-key-for-the-test"}
    )
    started = time.monotonic()
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=time.monotonic() + 0.5)
    elapsed = time.monotonic() - started
    assert caught.value.kind == "timeout"
    assert elapsed < 1.5, elapsed


def test_hanging_lookups_are_bounded() -> None:
    deadline = time.monotonic() + 10
    while openai_compatible._LOOKUPS.running and time.monotonic() < deadline:
        time.sleep(0.02)  # lookups an earlier test released may still be ending
    release = threading.Event()
    pool = openai_compatible._DetachedExecutor()
    futures = [pool.submit(release.wait, 20) for _ in range(openai_compatible.MAX_HANGING_LOOKUPS)]
    try:
        with pytest.raises(OSError, match="name lookups"):
            pool.submit(release.wait, 20)
    finally:
        release.set()
    for future in futures:
        assert future.result(timeout=5) is True
    pool.submit(lambda: None).result(timeout=5)  # the slots are free again


def test_a_hanging_resolver_does_not_turn_a_rule_deny_into_an_ask(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, blocked_resolver: threading.Event
) -> None:
    monkeypatch.setenv("BOUNDKEEP_LLM_API_KEY", KEY)
    project = tmp_path / "proj"
    project.mkdir()
    with FakeLLMServer(Reply(body=tool_call_answer(verdict_json()))) as server:
        h = Harness(
            tmp_path / "home",
            policy_text(base_url=_localhost(server), timeout_ms=300),
            decision_timeout_s=0.5,
            pool_size=1,
        )
        h.send("ping", {})
        started = time.monotonic()
        gray = h.send("pre", daemon_bash(project, "make release"))
        elapsed = time.monotonic() - started
        assert gray.decision == "ask"
        assert h.records()[-1]["decided_by"] == "llm-failure:timeout"  # not abandoned
        assert elapsed < 1.2, elapsed
        denied = h.send("pre", daemon_bash(project, "cat .env"))
        assert server.requests == []
    assert denied.decision == "deny"
    assert h.records()[-1]["decided_by"].startswith("rule:")
    h.daemon._close_session_and_auditors()


# ---------------------------------------- waiting for a decision on the spec (X5, see the report)


@pytest.mark.xfail(strict=True, reason="F1: X5 proposal P-F1 waits for the user's decision")
def test_f1_a_new_session_does_not_run_a_dev_tool_unasked_after_another_read_the_web(
    tmp_path: Path,
) -> None:
    store = SessionStore(str(tmp_path / "s.sqlite"))
    pol = policy(trusted=True)
    post("WebFetch", store, pol)
    write = event("Write", {"file_path": f"{PROJECT}/tests/test_x.py", "content": "x"})
    assert decide_with(write, pol, store=store).decision == protocol.DECISION_NONE
    other = dict(bash("pytest -q"), session_id="00000000-0000-4000-8000-0000000000dd")
    try:
        assert decide_with(other, pol, store=store).decision == protocol.DECISION_ASK
    finally:
        store.close()


@pytest.mark.xfail(strict=True, reason="F6: X5 proposal P-F6 waits for the user's decision")
def test_f6_padding_calls_do_not_use_up_the_taint_window(tmp_path: Path) -> None:
    store = SessionStore(str(tmp_path / "s.sqlite"))
    pol = policy(llm=True)
    auditor, _backend = manipulated(pol)
    fetch = event("WebFetch", {"url": "https://example.invalid", "prompt": "p"})
    decide_with(fetch, pol, store=store)
    for i in range(pol.taint.window):
        decide_with(event("Read", {"file_path": f"{PROJECT}/f{i}.py"}), pol, store=store)
    try:
        run = decide_with(bash("make release"), pol, store=store, auditor=auditor)
        assert run.decision == protocol.DECISION_ASK
    finally:
        store.close()


@pytest.mark.xfail(strict=True, reason="MCP resource tools: X5 proposal P-F2 waits for a decision")
def test_f2_reading_an_mcp_resource_marks_the_session(tmp_path: Path) -> None:
    store = SessionStore(str(tmp_path / "s.sqlite"))
    pol = policy(trusted=True)
    read = event("ReadMcpResourceTool", {"server": "docs", "uri": "docs://x"})
    decide_with(read, pol, store=store)
    try:
        assert decide_with(bash("pytest -q"), pol, store=store).decision == protocol.DECISION_ASK
    finally:
        store.close()
