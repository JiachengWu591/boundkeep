"""In-process tests of the hook client: every degradation path and the ConfigChange rules.

The transport is replaced by fakes; real processes are exercised in tests/e2e.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from boundkeep import hook_main as hc
from boundkeep import protocol
from boundkeep.ipc import client as ipc_client
from boundkeep.ipc import endpoint as ipc_endpoint

PRE_EVENT = {
    "session_id": "s",
    "cwd": "E:\\proj",
    "hook_event_name": "PreToolUse",
    "tool_name": "PowerShell",
    "tool_input": {"command": 'Write-Output "你好 ✓"'},
}


def _bytes(event: dict[str, Any]) -> bytes:
    return json.dumps(event, ensure_ascii=False).encode("utf-8")


def _deadline() -> float:
    return time.monotonic() + 5


def _decision_json(outcome: hc.Outcome) -> dict[str, Any]:
    assert outcome.stdout.endswith(b"\n")
    outcome.stdout.decode("ascii")
    parsed = json.loads(outcome.stdout)
    assert isinstance(parsed, dict)
    return parsed["hookSpecificOutput"]  # type: ignore[no-any-return]


@pytest.fixture
def fake_daemon(monkeypatch: pytest.MonkeyPatch) -> Callable[..., list[bytes]]:
    """Install an endpoint and a transport; returns a function that sets the daemon's behaviour.

    ``respond(decision, reason)`` makes the daemon answer; ``respond(raw=b'...')`` answers with raw
    bytes; ``respond(raises=Exception(...))`` makes the transport fail. The returned list collects
    the request lines the client sent.
    """
    sent: list[bytes] = []
    monkeypatch.setattr(
        ipc_endpoint,
        "read_endpoint",
        lambda path: ipc_endpoint.Endpoint(
            ipc_endpoint.TRANSPORT_NAMED_PIPE, "\\\\.\\pipe\\boundkeep-test"
        ),
    )

    def respond(
        decision: str = "none",
        reason: str = "",
        *,
        raw: bytes | None = None,
        raises: BaseException | None = None,
    ) -> list[bytes]:
        def transact(endpoint: object, line: bytes, deadline: float) -> bytes:
            sent.append(line)
            if raises is not None:
                raise raises
            if raw is not None:
                return raw
            request_id = json.loads(line)["id"]
            return protocol.encode_response(request_id, decision=decision, reason=reason).rstrip(
                b"\n"
            )

        monkeypatch.setattr(ipc_client, "transact", transact)
        return sent

    return respond


# ---------------------------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------------------------


def test_deny_and_ask_are_rendered_as_ascii_json(fake_daemon: Callable[..., list[bytes]]) -> None:
    fake_daemon("deny", "canary 不 ✓")
    out = hc.process("pre", _bytes(PRE_EVENT), _deadline())
    assert out.exit_code == 0
    decision = _decision_json(out)
    assert decision["hookEventName"] == "PreToolUse"
    assert decision["permissionDecision"] == "deny"
    assert decision["permissionDecisionReason"] == "canary 不 ✓"

    fake_daemon("ask", "please confirm")
    assert (
        _decision_json(hc.process("pre", _bytes(PRE_EVENT), _deadline()))["permissionDecision"]
        == "ask"
    )


def test_no_decision_prints_nothing(fake_daemon: Callable[..., list[bytes]]) -> None:
    fake_daemon("none")
    out = hc.process("pre", _bytes(PRE_EVENT), _deadline())
    assert (out.stdout, out.stderr, out.exit_code) == (b"", b"", 0)


@pytest.mark.parametrize(
    ("sub", "event_name"),
    [("post", "PostToolUse"), ("prompt", "UserPromptSubmit")],
)
def test_post_and_prompt_events_are_forwarded_and_never_print(
    fake_daemon: Callable[..., list[bytes]], sub: str, event_name: str
) -> None:
    sent = fake_daemon("deny", "must be ignored for these events")
    event = {"hook_event_name": event_name, "prompt": "你好 ✓", "tool_name": "WebFetch"}
    out = hc.process(sub, _bytes(event), _deadline())
    assert (out.stdout, out.stderr, out.exit_code) == (b"", b"", 0)
    request = json.loads(sent[0])
    assert request["event"] == sub
    assert request["payload"]["prompt"] == "你好 ✓"


def test_the_request_is_one_ascii_line_with_the_original_text(
    fake_daemon: Callable[..., list[bytes]],
) -> None:
    sent = fake_daemon("none")
    hc.process("pre", _bytes(PRE_EVENT), _deadline())
    assert len(sent) == 1
    sent[0].decode("ascii")
    assert sent[0].count(b"\n") == 1
    assert json.loads(sent[0])["payload"]["tool_input"]["command"] == 'Write-Output "你好 ✓"'


# ---------------------------------------------------------------------------------------------
# Degradation: PreToolUse fails closed, other events fail quiet
# ---------------------------------------------------------------------------------------------

_FAILURES: list[tuple[str, dict[str, Any], str]] = [
    ("daemon-down", {"raises": ipc_client.DaemonUnavailable("x")}, "not running"),
    ("busy", {"raises": ipc_client.DaemonBusy("x")}, "busy"),
    ("timeout", {"raises": ipc_client.DaemonTimeout("x")}, "did not answer"),
    ("protocol", {"raises": protocol.ProtocolError("x")}, "invalid exchange"),
    ("internal", {"raises": ValueError("secret detail")}, "internal error (ValueError)"),
    ("garbage-response", {"raw": b"not json"}, "invalid exchange"),
    ("wrong-id", {"raw": b'{"v":1,"id":"zzz","ok":true,"decision":"none","reason":""}'}, "invalid"),
    (
        "allow-is-not-a-decision",
        {"raw": b'{"v":1,"id":"x","ok":true,"decision":"allow"}'},
        "invalid",
    ),
]


@pytest.mark.parametrize(("name", "behaviour", "needle"), _FAILURES, ids=[f[0] for f in _FAILURES])
def test_pre_events_fail_closed_with_a_reason(
    fake_daemon: Callable[..., list[bytes]], name: str, behaviour: dict[str, Any], needle: str
) -> None:
    fake_daemon(**behaviour)
    out = hc.process("pre", _bytes(PRE_EVENT), _deadline())
    assert out.exit_code == 0
    decision = _decision_json(out)
    assert decision["permissionDecision"] == "ask"
    assert needle in decision["permissionDecisionReason"]
    assert "secret detail" not in out.stdout.decode()  # exception messages are never echoed


@pytest.mark.parametrize(("name", "behaviour", "needle"), _FAILURES, ids=[f[0] for f in _FAILURES])
def test_post_and_prompt_events_fail_quiet(
    fake_daemon: Callable[..., list[bytes]], name: str, behaviour: dict[str, Any], needle: str
) -> None:
    fake_daemon(**behaviour)
    for sub, event_name in (("post", "PostToolUse"), ("prompt", "UserPromptSubmit")):
        out = hc.process(sub, _bytes({"hook_event_name": event_name}), _deadline())
        assert (out.stdout, out.stderr, out.exit_code) == (b"", b"", 0)


def test_an_error_response_from_the_daemon_degrades(
    fake_daemon: Callable[..., list[bytes]],
) -> None:
    def transact(endpoint: object, line: bytes, deadline: float) -> bytes:
        request_id = json.loads(line)["id"]
        return protocol.encode_error(request_id, protocol.ERR_TOO_LARGE, "x").rstrip(b"\n")

    fake_daemon("none")
    ipc_client.transact = transact  # type: ignore[assignment]  # restored by the fixture's monkeypatch
    out = hc.process("pre", _bytes(PRE_EVENT), _deadline())
    assert "too_large" in _decision_json(out)["permissionDecisionReason"]


def test_a_missing_endpoint_degrades_and_mentions_init(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(path: str) -> ipc_endpoint.Endpoint:
        raise ipc_endpoint.EndpointError("endpoint file not found (run 'boundkeep init')")

    monkeypatch.setattr(ipc_endpoint, "read_endpoint", missing)
    out = hc.process("pre", _bytes(PRE_EVENT), _deadline())
    assert "boundkeep init" in _decision_json(out)["permissionDecisionReason"]


# ---------------------------------------------------------------------------------------------
# Bad input
# ---------------------------------------------------------------------------------------------

_BAD_STDIN = [
    pytest.param(b"", id="empty"),
    pytest.param(b"   \n", id="blank"),
    pytest.param(b"{", id="truncated"),
    pytest.param(b"[1, 2]", id="array"),
    pytest.param(b'"text"', id="string"),
    pytest.param(b"\xff\xfe{}", id="invalid-utf8"),
    pytest.param('{"a":"你好"}'.encode("gbk"), id="gbk-bytes"),
    pytest.param(b"[" * 5000, id="deep-nesting"),
]


@pytest.mark.parametrize("data", _BAD_STDIN)
def test_unparsable_stdin_asks_for_pre_and_stays_quiet_for_post(data: bytes) -> None:
    out = hc.process("pre", data, _deadline())
    assert out.exit_code == 0
    assert _decision_json(out)["permissionDecision"] == "ask"
    for sub in ("post", "prompt"):
        quiet = hc.process(sub, data, _deadline())
        assert (quiet.stdout, quiet.stderr, quiet.exit_code) == (b"", b"", 0)
    # without any argument the PreToolUse shape is the safe default
    assert _decision_json(hc.process(None, data, _deadline()))["permissionDecision"] == "ask"


def test_unparsable_stdin_for_config_blocks() -> None:
    out = hc.process("config", b"{", _deadline())
    assert out.exit_code == 2
    assert out.stdout == b""
    assert b"blocked" in out.stderr


def test_event_without_a_name_degrades() -> None:
    out = hc.process("pre", _bytes({"tool_name": "Bash"}), _deadline())
    assert "hook_event_name" in _decision_json(out)["permissionDecisionReason"]


def test_an_unknown_event_is_ignored_when_we_were_not_registered_for_it() -> None:
    out = hc.process(None, _bytes({"hook_event_name": "SessionStart"}), _deadline())
    assert (out.stdout, out.stderr, out.exit_code) == (b"", b"", 0)


@pytest.mark.parametrize(
    "name", ["preToolUse", "PreToolUse ", "PreToolUseX", "PermissionRequest", "SessionStart"]
)
def test_an_unknown_event_name_under_our_registration_does_not_silently_allow(name: str) -> None:
    out = hc.process("pre", _bytes({"hook_event_name": name}), _deadline())
    assert _decision_json(out)["permissionDecision"] == "ask"
    blocked = hc.process("config", _bytes({"hook_event_name": name}), _deadline())
    assert blocked.exit_code == 2


@pytest.mark.parametrize("sub", [None, "post", "prompt", "config", "bogus", ""])
def test_a_missing_or_mismatching_argument_degrades_a_pre_event(
    fake_daemon: Callable[..., list[bytes]], sub: str | None
) -> None:
    sent = fake_daemon("none")
    out = hc.process(sub, _bytes(PRE_EVENT), _deadline())
    decision = _decision_json(out)
    assert decision["permissionDecision"] == "ask"
    assert "mismatch" in decision["permissionDecisionReason"]
    assert sent == []  # nothing was forwarded


def test_a_mismatch_for_a_post_event_is_quiet(fake_daemon: Callable[..., list[bytes]]) -> None:
    fake_daemon("none")
    out = hc.process("pre", _bytes({"hook_event_name": "PostToolUse"}), _deadline())
    assert (out.stdout, out.stderr, out.exit_code) == (b"", b"", 0)


def test_the_event_name_in_stdin_wins_over_text_inside_values(
    fake_daemon: Callable[..., list[bytes]],
) -> None:
    """Attacker-controlled text that looks like an event name must not change the event type."""
    sent = fake_daemon("deny", "blocked")
    event = dict(PRE_EVENT)
    event["tool_input"] = {"command": '"hook_event_name": "PostToolUse"'}
    out = hc.process("pre", _bytes(event), _deadline())
    assert _decision_json(out)["permissionDecision"] == "deny"
    assert json.loads(sent[0])["event"] == "pre"


def test_a_bom_in_stdin_is_tolerated(fake_daemon: Callable[..., list[bytes]]) -> None:
    fake_daemon("deny", "x")
    out = hc.process("pre", b"\xef\xbb\xbf" + _bytes(PRE_EVENT), _deadline())
    assert _decision_json(out)["permissionDecision"] == "deny"


# ---------------------------------------------------------------------------------------------
# Large events
# ---------------------------------------------------------------------------------------------


def test_large_content_and_tool_output_are_elided_but_commands_are_not(
    fake_daemon: Callable[..., list[bytes]],
) -> None:
    sent = fake_daemon("none")
    big = "x" * hc.SMALL_EVENT_BYTES  # the whole event is then above the "small event" threshold
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "a.txt", "content": big, "command": big},
        "tool_response": {"text": big},
    }
    hc.process("pre", _bytes(event), _deadline())
    payload = json.loads(sent[0])["payload"]
    assert payload["tool_input"]["content"] == f"<elided {len(big)} chars>"
    assert payload["tool_input"]["command"] == big  # never truncated: padding could hide the tail
    assert payload["tool_response"] == {"_elided_chars": len(json.dumps({"text": big}))}
    assert payload["tool_input"]["file_path"] == "a.txt"


def test_small_events_are_forwarded_untouched(fake_daemon: Callable[..., list[bytes]]) -> None:
    sent = fake_daemon("none")
    event = dict(PRE_EVENT, tool_response={"a": "b" * 1000})
    hc.process("pre", _bytes(event), _deadline())
    assert json.loads(sent[0])["payload"] == event


def test_an_event_too_large_to_forward_asks(fake_daemon: Callable[..., list[bytes]]) -> None:
    sent = fake_daemon("none")
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "x" * (protocol.MAX_REQUEST_BYTES + 100)},
    }
    out = hc.process("pre", _bytes(event), _deadline())
    assert "too large" in _decision_json(out)["permissionDecisionReason"]
    assert sent == []


# ---------------------------------------------------------------------------------------------
# Property: whatever happens, the outcome is a valid hook result
# ---------------------------------------------------------------------------------------------

_EVENT_NAMES = ["PreToolUse", "PostToolUse", "UserPromptSubmit", "ConfigChange", "Stop", 7, None]
_events = st.fixed_dictionaries(
    {"hook_event_name": st.sampled_from(_EVENT_NAMES)},
    optional={
        "tool_name": st.text(max_size=20),
        "tool_input": st.dictionaries(st.text(max_size=8), st.text(max_size=60), max_size=4),
        "prompt": st.text(max_size=80),
        "source": st.sampled_from(["policy_settings", "user_settings", 3]),
        "file_path": st.just("Z:\\no\\such\\settings.json") | st.text(max_size=10),
    },
)


def _assert_valid_outcome(outcome: hc.Outcome) -> None:
    assert outcome.exit_code in (0, 2)
    if outcome.exit_code == 2:
        assert outcome.stderr  # a block always carries a reason
    if outcome.stdout:
        assert outcome.stdout.isascii()
        assert outcome.stdout.endswith(b"\n")
        body = json.loads(outcome.stdout)
        specific = body["hookSpecificOutput"]
        assert specific["hookEventName"] == "PreToolUse"
        assert specific["permissionDecision"] in ("ask", "deny")
        assert isinstance(specific["permissionDecisionReason"], str)


@settings(
    max_examples=300,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    data=st.one_of(st.binary(max_size=600), _events.map(lambda e: json.dumps(e).encode())),
    sub=st.sampled_from([None, "pre", "post", "prompt", "config", "x"]),
    reply=st.one_of(
        st.none(),
        st.binary(max_size=300),
        st.sampled_from(
            [
                b'{"v":1,"id":"PLACEHOLDER","ok":true,"decision":"deny","reason":"r"}',
                b'{"v":1,"id":"PLACEHOLDER","ok":true,"decision":"ask","reason":"\\u4f60"}',
                b'{"v":1,"id":"PLACEHOLDER","ok":true,"decision":"none","reason":""}',
                b'{"v":1,"id":"PLACEHOLDER","ok":false,"error":"x","detail":"y"}',
            ]
        ),
    ),
    failure=st.sampled_from(
        [
            None,
            ipc_client.DaemonUnavailable("x"),
            ipc_client.DaemonBusy("x"),
            OSError("x"),
            KeyError("k"),
        ]
    ),
)
def test_every_outcome_is_a_valid_hook_result(
    tmp_path: Path, data: bytes, sub: str | None, reply: bytes | None, failure: Exception | None
) -> None:
    def transact(endpoint: object, line: bytes, deadline: float) -> bytes:
        if failure is not None:
            raise failure
        if reply is None:
            return b""
        return reply.replace(b"PLACEHOLDER", json.loads(line)["id"].encode())

    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("BOUNDKEEP_HOME", str(tmp_path / "home"))
        mp.setattr(
            ipc_endpoint,
            "read_endpoint",
            lambda path: ipc_endpoint.Endpoint(
                ipc_endpoint.TRANSPORT_NAMED_PIPE, "\\\\.\\pipe\\boundkeep-t"
            ),
        )
        mp.setattr(ipc_client, "transact", transact)
        _assert_valid_outcome(hc.process(sub, data, time.monotonic() + 5))


# ---------------------------------------------------------------------------------------------
# ConfigChange
# ---------------------------------------------------------------------------------------------

PY = "C:\\uv\\python\\python.exe"
SCRIPT = "E:\\proj\\boundkeep\\src\\boundkeep\\hook_client.py"
POST_MATCHER = "^(?:WebFetch|WebSearch|mcp__.*)$"


def _entry(sub: str, **overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": "command",
        "command": PY,
        "args": ["-I", "-S", SCRIPT, sub],
        "timeout": {"pre": 15, "prompt": 10, "post": 10, "config": 10}[sub],
    }
    entry.update(overrides)
    return entry


def _intact_settings() -> dict[str, Any]:
    return {
        "permissions": {"allow": ["Read"]},
        "hooks": {
            "UserPromptSubmit": [{"hooks": [_entry("prompt")]}],
            "PreToolUse": [{"matcher": "*", "hooks": [_entry("pre")]}],
            "PostToolUse": [{"matcher": POST_MATCHER, "hooks": [_entry("post")]}],
            "ConfigChange": [{"hooks": [_entry("config")]}],
        },
    }


@pytest.fixture
def settings_file(tmp_path: Path, boundkeep_home: Path) -> Callable[..., Path]:
    """Write a settings file (and optionally the install manifest) and return the file's path."""

    def make(
        content: object,
        *,
        manifest: bool = True,
        raw: bytes | None = None,
        name: str = "settings.json",
    ) -> Path:
        project = tmp_path / "proj" / ".claude"
        project.mkdir(parents=True, exist_ok=True)
        path = project / name
        path.write_bytes(raw if raw is not None else json.dumps(content, indent=2).encode())
        boundkeep_home.mkdir(parents=True, exist_ok=True)
        if manifest:
            record = {
                "settings_path": str(path),
                "scope": "project",
                "created_file": False,
                "hook_command": PY,
                "hook_args": ["-I", "-S", SCRIPT],
                "post_matcher": POST_MATCHER,
                "installed_at": "2026-10-07T00:00:00Z",
            }
            (boundkeep_home / "installs.json").write_text(
                json.dumps({"version": 1, "installs": [record]}), encoding="utf-8"
            )
        return path

    return make


def _config(path: Path, source: str = "project_settings") -> hc.Outcome:
    event = {"hook_event_name": "ConfigChange", "source": source, "file_path": str(path)}
    return hc.process("config", _bytes(event), _deadline())


def _blocked(outcome: hc.Outcome, needle: str) -> None:
    assert outcome.exit_code == 2, outcome.stderr
    assert outcome.stdout == b""
    assert needle in outcome.stderr.decode("ascii")


@pytest.fixture(autouse=True)
def _no_daemon_for_config(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    """ConfigChange tests must not depend on a daemon: the notification is best effort."""
    if "fake_daemon" in request.fixturenames:
        return

    def down(endpoint: object, line: bytes, deadline: float) -> bytes:
        raise ipc_client.DaemonUnavailable("test")

    monkeypatch.setattr(ipc_client, "transact", down)


def test_an_intact_settings_file_is_accepted(settings_file: Callable[..., Path]) -> None:
    out = _config(settings_file(_intact_settings()))
    assert (out.stdout, out.stderr, out.exit_code) == (b"", b"", 0)


def test_unrelated_changes_and_extra_foreign_hooks_are_accepted(
    settings_file: Callable[..., Path],
) -> None:
    data = _intact_settings()
    data["env"] = {"A": "B"}
    data["hooks"]["PreToolUse"].insert(
        0, {"matcher": "Bash", "hooks": [{"type": "command", "command": "x"}]}
    )
    assert _config(settings_file(data)).exit_code == 0


@pytest.mark.parametrize("value", [True, "false", "true", 1, 0, {}, []])
def test_disable_all_hooks_is_blocked_even_without_a_manifest(
    settings_file: Callable[..., Path], value: object
) -> None:
    path = settings_file({"disableAllHooks": value}, manifest=False)
    _blocked(_config(path), "disableAllHooks")


@pytest.mark.parametrize("value", [False, None])
def test_disable_all_hooks_false_is_fine(settings_file: Callable[..., Path], value: object) -> None:
    assert _config(settings_file({"disableAllHooks": value}, manifest=False)).exit_code == 0


def test_a_policy_settings_change_is_not_ours_to_block(settings_file: Callable[..., Path]) -> None:
    path = settings_file({"disableAllHooks": True}, manifest=False)
    assert _config(path, source="policy_settings").exit_code == 0


@pytest.mark.parametrize(
    "raw",
    [b"{", b"[]", b"", b"\xff\xfe", b'{"a": 1,}', b'{"a": 1} // comment'],
)
def test_an_unevaluable_settings_file_is_blocked(
    settings_file: Callable[..., Path], raw: bytes
) -> None:
    path = settings_file(None, manifest=False, raw=raw)
    _blocked(_config(path), "cannot be evaluated")


def test_a_deleted_settings_file_is_blocked_only_when_init_wrote_hooks_into_it(
    settings_file: Callable[..., Path],
) -> None:
    path = settings_file(_intact_settings())
    path.unlink()
    _blocked(_config(path), "removed")
    unrelated = settings_file({}, manifest=False, name="settings.local.json")
    unrelated.unlink()
    assert _config(unrelated).exit_code == 0


def _mutations() -> list[tuple[str, Callable[[dict[str, Any]], None]]]:
    def drop_event(event: str) -> Callable[[dict[str, Any]], None]:
        return lambda d: d["hooks"].pop(event)

    def edit(event: str, **changes: Any) -> Callable[[dict[str, Any]], None]:
        def apply(d: dict[str, Any]) -> None:
            d["hooks"][event][0]["hooks"][0].update(changes)

        return apply

    def matcher(event: str, value: object) -> Callable[[dict[str, Any]], None]:
        return lambda d: d["hooks"][event][0].__setitem__("matcher", value)

    return [
        ("drop-pre", drop_event("PreToolUse")),
        ("drop-config", drop_event("ConfigChange")),
        ("drop-post", drop_event("PostToolUse")),
        ("drop-prompt", drop_event("UserPromptSubmit")),
        ("drop-all-hooks", lambda d: d.pop("hooks")),
        ("empty-pre-list", lambda d: d["hooks"].__setitem__("PreToolUse", [])),
        ("other-command", edit("PreToolUse", command="C:\\evil\\python.exe")),
        (
            "other-script",
            edit("PreToolUse", args=["-I", "-S", "C:\\evil\\boundkeep\\hook_client.py", "pre"]),
        ),
        ("extra-arg", edit("PreToolUse", args=["-I", "-S", SCRIPT, "-c", "pass", "pre"])),
        ("if-field", edit("PreToolUse", **{"if": "Bash(never)"})),
        ("async-field", edit("PreToolUse", **{"async": True})),
        ("tiny-timeout", edit("PreToolUse", timeout=0.001)),
        ("short-timeout", edit("PreToolUse", timeout=5)),
        ("bool-timeout", edit("PreToolUse", timeout=True)),
        ("string-timeout", edit("PreToolUse", timeout="15")),
        ("narrow-pre-matcher", matcher("PreToolUse", "Nothing")),
        ("narrow-post-matcher", matcher("PostToolUse", "WebFetch")),
        # ConfigChange matches on the settings source: a matcher could mean "never for settings"
        ("config-matcher-skills", matcher("ConfigChange", "skills")),
        ("config-matcher-policy", matcher("ConfigChange", "policy_settings")),
        ("prompt-matcher", matcher("UserPromptSubmit", "Nothing")),
        ("null-matcher", matcher("PreToolUse", None)),
        ("int-matcher", matcher("PreToolUse", 5)),
        ("list-matcher", matcher("PreToolUse", ["x"])),
        ("huge-timeout", edit("PreToolUse", timeout=10**12)),
        ("infinite-timeout", edit("PreToolUse", timeout=1e999)),
        ("wrong-subcommand", edit("PreToolUse", args=["-I", "-S", SCRIPT, "prompt"])),
        ("http-type", edit("PreToolUse", type="http")),
        ("hooks-not-a-dict", lambda d: d.__setitem__("hooks", [])),
        ("event-not-a-list", lambda d: d["hooks"].__setitem__("PreToolUse", {})),
    ]


@pytest.mark.parametrize(("name", "mutate"), _mutations(), ids=[m[0] for m in _mutations()])
def test_neutering_our_hooks_is_blocked(
    settings_file: Callable[..., Path], name: str, mutate: Callable[[dict[str, Any]], None]
) -> None:
    data = _intact_settings()
    mutate(data)
    _blocked(_config(settings_file(data)), "boundkeep")


def test_a_longer_timeout_or_an_empty_matcher_is_fine(settings_file: Callable[..., Path]) -> None:
    data = _intact_settings()
    data["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = 600
    data["hooks"]["PreToolUse"][0]["matcher"] = ""
    assert _config(settings_file(data)).exit_code == 0


def test_a_malformed_manifest_blocks(
    settings_file: Callable[..., Path], boundkeep_home: Path
) -> None:
    path = settings_file(_intact_settings())
    (boundkeep_home / "installs.json").write_text("{not json", encoding="utf-8")
    _blocked(_config(path), "manifest")
    (boundkeep_home / "installs.json").write_text('{"version": 1, "installs": 5}', encoding="utf-8")
    _blocked(_config(path), "manifest")


def test_a_manifest_record_for_another_file_does_not_apply(
    settings_file: Callable[..., Path], tmp_path: Path
) -> None:
    other = settings_file(_intact_settings())
    stripped = tmp_path / "elsewhere.json"
    stripped.write_text("{}", encoding="utf-8")
    assert other.exists()
    assert _config(stripped).exit_code == 0


@pytest.mark.windows
def test_manifest_paths_match_case_insensitively_on_windows(
    settings_file: Callable[..., Path],
) -> None:
    data = _intact_settings()
    del data["hooks"]["PreToolUse"]
    path = settings_file(data)
    swapped = str(path).swapcase()
    event = {"hook_event_name": "ConfigChange", "source": "project_settings", "file_path": swapped}
    out = hc.process("config", _bytes(event), _deadline())
    assert out.exit_code == 2  # same file despite the different spelling: the removal is caught


def test_the_attempt_is_reported_to_the_daemon_best_effort(
    settings_file: Callable[..., Path], fake_daemon: Callable[..., list[bytes]]
) -> None:
    sent = fake_daemon("none")
    path = settings_file({"disableAllHooks": True}, manifest=False)
    out = _config(path)
    assert out.exit_code == 2
    payload = json.loads(sent[0])["payload"]
    assert json.loads(sent[0])["event"] == "config"
    assert payload["local_decision"] == "deny"
    assert "disableAllHooks" in payload["local_reason"]


def test_a_failing_notification_never_changes_the_decision(
    settings_file: Callable[..., Path], fake_daemon: Callable[..., list[bytes]]
) -> None:
    fake_daemon(raises=OSError("boom"))
    assert _config(settings_file(_intact_settings())).exit_code == 0
    path = settings_file({"disableAllHooks": True}, manifest=False)
    assert _config(path).exit_code == 2


@pytest.mark.parametrize("file_path", [None, "", 5])
def test_a_settings_change_that_names_no_file_cannot_be_evaluated_and_is_blocked(
    file_path: object,
) -> None:
    event: dict[str, Any] = {"hook_event_name": "ConfigChange", "source": "user_settings"}
    if file_path is not None:
        event["file_path"] = file_path
    _blocked(hc.process("config", _bytes(event), _deadline()), "no file_path")


def test_a_skills_change_is_not_a_settings_document(tmp_path: Path) -> None:
    skill = tmp_path / "SKILL.md"
    skill.write_text("# not json", encoding="utf-8")
    assert _config(skill, source="skills").exit_code == 0


@pytest.mark.parametrize(
    "env",
    [
        {"BOUNDKEEP_HOME": "C:\\evil"},
        {"boundkeep_home": "C:\\evil"},
        {"BOUNDKEEP_ANYTHING": "1"},
        {"USERPROFILE": "C:\\evil"},
        {"home": "/evil"},
        {"APPDATA": "C:\\evil"},
        {"CLAUDE_CODE_SIMPLE": "1"},
        {"CLAUDE_CODE_SAFE_MODE": "1"},
        {"CLAUDE_CONFIG_DIR": "C:\\evil"},
        "text",
        ["BOUNDKEEP_HOME"],
        5,
    ],
)
def test_an_env_block_that_can_redirect_or_bypass_the_client_is_blocked(
    settings_file: Callable[..., Path], env: object
) -> None:
    data = _intact_settings()
    data["env"] = env
    _blocked(_config(settings_file(data)), "env")


def test_harmless_env_entries_are_fine(settings_file: Callable[..., Path]) -> None:
    data = _intact_settings()
    data["env"] = {"ANTHROPIC_MODEL": "x", "EDITOR": "vim"}
    assert _config(settings_file(data)).exit_code == 0


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_constants_javascript_refuses_make_the_file_unevaluable(
    settings_file: Callable[..., Path], constant: str
) -> None:
    path = settings_file(None, raw=b'{"x": ' + constant.encode() + b"}")
    _blocked(_config(path), "cannot be evaluated")


@pytest.mark.windows
def test_a_junction_to_the_settings_directory_is_the_same_file(
    settings_file: Callable[..., Path], tmp_path: Path
) -> None:
    import _winapi

    data = _intact_settings()
    del data["hooks"]["PreToolUse"]
    path = settings_file(data)
    link = tmp_path / "link"
    _winapi.CreateJunction(str(path.parent), str(link))
    try:
        assert _config(link / path.name).exit_code == 2  # same file: the removal is caught
        assert _config(Path("\\\\?\\" + str(path))).exit_code == 2
    finally:
        link.rmdir()


def test_a_notification_to_a_daemon_that_never_answers_does_not_delay_a_harmless_change(
    settings_file: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    release = threading.Event()

    def hang(endpoint: object, line: bytes, deadline: float) -> bytes:
        release.wait(30)
        raise ipc_client.DaemonTimeout("test")

    monkeypatch.setattr(ipc_client, "transact", hang)
    monkeypatch.setattr(
        ipc_endpoint, "read_endpoint", lambda path: ipc_endpoint.new_endpoint(str(path))
    )
    path = settings_file(_intact_settings())
    started = time.monotonic()
    out = _config(path)
    release.set()
    assert out.exit_code == 0
    assert time.monotonic() - started < hc.CONFIG_NOTIFY_BUDGET_S + 1.5


# ---------------------------------------------------------------------------------------------
# Delivery and entry point
# ---------------------------------------------------------------------------------------------


def test_deliver_never_returns_one_and_keeps_stdout_ascii(monkeypatch: pytest.MonkeyPatch) -> None:
    writes: list[tuple[int, bytes]] = []
    monkeypatch.setattr(hc, "_write_all", lambda fd, data: writes.append((fd, bytes(data))))
    assert hc._deliver(hc.Outcome(stdout="ünï".encode(), exit_code=0)) == 0
    assert writes == [(1, hc._FALLBACK_ASK)]  # non-ASCII stdout is replaced by the safe answer
    writes.clear()
    assert hc._deliver(hc.Outcome(stderr=b"why", exit_code=2)) == 2
    assert hc._deliver(hc.Outcome(exit_code=1)) == 0  # exit code 1 is never passed through
    assert hc._deliver(hc.Outcome(exit_code=137)) == 0


def test_deliver_blocks_when_the_decision_cannot_be_written(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(fd: int, data: bytes) -> None:
        raise OSError("stdout closed")

    monkeypatch.setattr(hc, "_write_all", broken)
    assert hc._deliver(hc.Outcome(stdout=hc._FALLBACK_ASK)) == 2
    # nothing to say, nothing to fail: no output means no exit code 2
    assert hc._deliver(hc.Outcome()) == 0


def test_main_degrades_when_the_worker_hangs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BOUNDKEEP_HOOK_BUDGET_S", "0.6")

    def hang(sub: str | None, deadline: float) -> hc.Outcome:
        time.sleep(30)
        return hc.Outcome()

    delivered: list[hc.Outcome] = []
    monkeypatch.setattr(hc, "run_hook", hang)
    monkeypatch.setattr(hc, "_deliver", lambda outcome: delivered.append(outcome) or 0)
    started = time.monotonic()
    hc.main(["pre"])
    assert time.monotonic() - started < 3
    assert b'"permissionDecision":"ask"' in delivered[0].stdout
    assert b"timed out" in delivered[0].stdout


def test_main_survives_a_crashing_worker_and_a_crashing_degrade_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(sub: str | None, deadline: float) -> hc.Outcome:
        raise MemoryError

    delivered: list[hc.Outcome] = []
    monkeypatch.setattr(hc, "run_hook", boom)
    monkeypatch.setattr(hc, "_deliver", lambda outcome: delivered.append(outcome) or 0)
    hc.main(["pre"])
    assert delivered[0].stdout == hc._FALLBACK_ASK
    hc.main(["config"])
    assert delivered[1].exit_code == 2
    hc.main(["post"])
    assert delivered[2].stdout == b""
    assert delivered[2].exit_code == 0


def test_the_budget_can_only_be_shortened(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BOUNDKEEP_HOOK_BUDGET_S", raising=False)
    assert hc._budget_for("pre") == hc.BUDGET_S["pre"]
    monkeypatch.setenv("BOUNDKEEP_HOOK_BUDGET_S", "1000")
    assert hc._budget_for("pre") == hc.BUDGET_S["pre"]  # cannot outlive Claude Code's timeout
    monkeypatch.setenv("BOUNDKEEP_HOOK_BUDGET_S", "2")
    assert hc._budget_for("pre") == 2.0
    monkeypatch.setenv("BOUNDKEEP_HOOK_BUDGET_S", "nonsense")
    assert hc._budget_for("pre") == hc.BUDGET_S["pre"]
    assert hc._budget_for(None) == hc.DEFAULT_BUDGET_S


def test_budgets_stay_below_the_timeouts_that_init_writes() -> None:
    # install.HookTimeouts defaults: prompt 10, pre 15, post 10, config 10 (seconds)
    written = {"prompt": 10.0, "pre": 15.0, "post": 10.0, "config": 10.0}
    for sub, timeout in written.items():
        assert hc.BUDGET_S[sub] + hc.EXIT_RESERVE_S < timeout
        assert hc.MIN_ENTRY_TIMEOUT_S[sub] > hc.BUDGET_S[sub]
        assert hc.MIN_ENTRY_TIMEOUT_S[sub] <= timeout


def test_the_env_override_name_is_not_inherited_from_the_developer_shell() -> None:
    assert "BOUNDKEEP_HOOK_BUDGET_S" not in os.environ
