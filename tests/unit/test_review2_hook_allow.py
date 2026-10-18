"""Review H-2: the hook client must not turn a daemon's ``allow`` into an explicit allow unless the
hook command is pinned with ``--emit-allow``.

Any process of the same user can create another instance of the pipe (or squat the name before
the daemon starts) and answer ``allow``; the client used to print ``permissionDecision: allow`` and
exit 0, silently turning every deny/ask into allow.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

import pytest

from boundkeep import hook_main as hc
from boundkeep import protocol
from boundkeep.ipc import client as ipc_client
from boundkeep.ipc import endpoint as ipc_endpoint

PRE_EVENT = {
    "session_id": "s",
    "cwd": "E:\\proj",
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "echo hi"},
}


@pytest.fixture
def fake_daemon(monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    monkeypatch.setattr(
        ipc_endpoint,
        "read_endpoint",
        lambda path: ipc_endpoint.Endpoint(
            ipc_endpoint.TRANSPORT_NAMED_PIPE, "\\\\.\\pipe\\boundkeep-test"
        ),
    )

    def respond(decision: str = "none", reason: str = "", *, raw: bytes | None = None) -> None:
        def transact(endpoint: object, line: bytes, deadline: float) -> bytes:
            if raw is not None:
                return raw
            request_id = json.loads(line)["id"]
            return protocol.encode_response(request_id, decision=decision, reason=reason).rstrip(
                b"\n"
            )

        monkeypatch.setattr(ipc_client, "transact", transact)

    return respond


def _event(name: str) -> bytes:
    return json.dumps(dict(PRE_EVENT, hook_event_name=name)).encode("utf-8")


def _deadline() -> float:
    return time.monotonic() + 5


def _decision(outcome: hc.Outcome) -> str:
    parsed: dict[str, Any] = json.loads(outcome.stdout)
    return str(parsed["hookSpecificOutput"]["permissionDecision"])


def test_an_allow_without_the_pin_is_no_decision(fake_daemon: Callable[..., None]) -> None:
    fake_daemon("allow", "impostor says fine")
    out = hc.process("pre", _event("PreToolUse"), _deadline())
    assert (out.stdout, out.stderr, out.exit_code) == (b"", b"", 0)


def test_an_allow_with_the_pin_is_an_explicit_allow(fake_daemon: Callable[..., None]) -> None:
    fake_daemon("allow", "rule x")
    out = hc.process("pre", _event("PreToolUse"), _deadline(), emit_allow=True)
    assert out.exit_code == 0
    assert _decision(out) == "allow"


@pytest.mark.parametrize("emit_allow", [False, True])
@pytest.mark.parametrize("decision", ["deny", "ask"])
def test_ask_and_deny_are_honoured_with_or_without_the_pin(
    fake_daemon: Callable[..., None], decision: str, emit_allow: bool
) -> None:
    fake_daemon(decision, "because")
    out = hc.process("pre", _event("PreToolUse"), _deadline(), emit_allow=emit_allow)
    assert _decision(out) == decision


@pytest.mark.parametrize("emit_allow", [False, True])
def test_none_is_no_decision_with_or_without_the_pin(
    fake_daemon: Callable[..., None], emit_allow: bool
) -> None:
    fake_daemon("none")
    out = hc.process("pre", _event("PreToolUse"), _deadline(), emit_allow=emit_allow)
    assert out.stdout == b""


@pytest.mark.parametrize("emit_allow", [False, True])
@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(b"garbage", id="garbage"),
        pytest.param(b"", id="empty"),
        pytest.param(b'{"v":1,"id":"wrong","ok":true,"decision":"allow","reason":""}', id="bad-id"),
        pytest.param(b'{"v":1,"id":"X","ok":true,"decision":"defer","reason":""}', id="defer"),
    ],
)
def test_garbage_from_the_daemon_still_asks(
    fake_daemon: Callable[..., None], raw: bytes, emit_allow: bool
) -> None:
    fake_daemon(raw=raw)
    out = hc.process("pre", _event("PreToolUse"), _deadline(), emit_allow=emit_allow)
    assert _decision(out) == "ask"


@pytest.mark.parametrize(
    ("sub", "event_name"),
    [("post", "PostToolUse"), ("prompt", "UserPromptSubmit")],
)
def test_post_and_prompt_stay_quiet_for_every_decision(
    fake_daemon: Callable[..., None], sub: str, event_name: str
) -> None:
    for decision in ("allow", "deny", "ask", "none"):
        for emit_allow in (False, True):
            fake_daemon(decision)
            out = hc.process(sub, _event(event_name), _deadline(), emit_allow=emit_allow)
            assert (out.stdout, out.stderr, out.exit_code) == (b"", b"", 0)


# --- argument parsing --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["pre"], ("pre", None, False)),
        (["--home", "H", "pre"], ("pre", "H", False)),
        (["--emit-allow", "pre"], ("pre", None, True)),
        (["--home", "H", "--emit-allow", "pre"], ("pre", "H", True)),
        (["--emit-allow", "--home", "H", "pre"], ("pre", "H", True)),
        (["pre", "--emit-allow"], ("pre", None, True)),
        (["--emit-allow", "--emit-allow", "post"], ("post", None, True)),
        ([], (None, None, False)),
        (["--emit-allow"], (None, None, True)),
        # fail closed: nothing that is not understood may switch the pin on
        (["--bogus", "--emit-allow", "pre"], (None, None, False)),
        (["--emit-allow", "--home", "H", "--bogus", "pre"], (None, "H", False)),
        (["--emit-allow", "pre", "extra"], (None, None, False)),
        (["--emit-allow", "pre", "--home"], (None, None, False)),
        (["--emit-allow=1", "pre"], (None, None, False)),
        (["--EMIT-ALLOW", "pre"], (None, None, False)),
        (["--home"], (None, None, False)),
    ],
)
def test_parse_args(args: list[str], expected: tuple[str | None, str | None, bool]) -> None:
    assert hc.parse_args(args) == expected


def test_main_honours_the_flag_in_any_position(
    fake_daemon: Callable[..., None], monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    from boundkeep import paths

    pinned: list[str] = []
    monkeypatch.setattr(paths, "pin_home", pinned.append)
    seen: list[bool] = []
    real_process = hc.process

    def spy(sub: str | None, data: bytes, deadline: float, emit_allow: bool = False) -> hc.Outcome:
        seen.append(emit_allow)
        return real_process(sub, data, deadline, emit_allow)

    monkeypatch.setattr(hc, "process", spy)
    fake_daemon("allow")
    monkeypatch.setattr(hc, "_read_stdin", lambda: _event("PreToolUse"))
    home = str(tmp_path)
    for argv in (
        ["--home", home, "--emit-allow", "pre"],
        ["--emit-allow", "--home", home, "pre"],
        ["--home", home, "pre"],
        ["--home", home, "--nope", "--emit-allow", "pre"],
    ):
        seen.clear()
        assert hc.main(argv) == 0
        assert seen == ["--emit-allow" in argv and "--nope" not in argv], argv
    assert pinned
    assert all(p == home for p in pinned)


def test_an_unknown_flag_still_blocks_config_and_asks_for_pre(
    fake_daemon: Callable[..., None], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hc, "_read_stdin", lambda: _event("ConfigChange"))
    assert hc.main(["--bogus", "config"]) == 2
    monkeypatch.setattr(hc, "_read_stdin", lambda: _event("PreToolUse"))
    assert hc.main(["--bogus", "--emit-allow", "pre"]) == 0  # an ask, never an allow
