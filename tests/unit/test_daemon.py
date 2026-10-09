"""The daemon's request handling, without any transport."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from boundkeep import paths, protocol
from boundkeep.daemon import pipeline
from boundkeep.daemon.server import Daemon, build_record
from boundkeep.ipc.endpoint import TRANSPORT_NAMED_PIPE, Endpoint
from boundkeep.logstore import AuditLog
from boundkeep.policy import set_mode, write_default_policy

ENDPOINT = Endpoint(TRANSPORT_NAMED_PIPE, "\\\\.\\pipe\\boundkeep-unit-test")


class Harness:
    def __init__(self, home: Path) -> None:
        self.home = home
        home.mkdir(parents=True, exist_ok=True)
        self.policy = paths.policy_file(str(home))
        write_default_policy(self.policy)
        self.messages: list[str] = []
        self.log = AuditLog(paths.audit_log_file(str(home)))
        self.daemon = Daemon(ENDPOINT, home=str(home), log=self.log, report=self.messages.append)

    def send(
        self, event: str, payload: dict[str, Any], request_id: str = "r1"
    ) -> protocol.Response:
        line = protocol.encode_request(event, payload, request_id).rstrip(b"\n")
        raw = asyncio.run(self.daemon.handle(line))
        return protocol.decode_response(raw.rstrip(b"\n"), request_id)

    def records(self) -> list[dict[str, Any]]:
        return [r for r in self.log.tail(1000) if r.get("event") != "daemon"]


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path / "home")


def shell(command: str, tool: str = "PowerShell") -> dict[str, Any]:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "sess-1",
        "agent_id": "agent-9",
        "permission_mode": "default",
        "cwd": "E:\\proj",
        "tool_name": tool,
        "tool_use_id": "toolu_1",
        "tool_input": {"command": command, "description": "d"},
    }


def test_the_canary_is_denied_and_logged(harness: Harness) -> None:
    response = harness.send("pre", shell("echo BOUNDKEEP_CANARY"))
    assert response.ok
    assert response.decision == "deny"
    assert "BOUNDKEEP_CANARY" in response.reason
    (record,) = harness.records()
    assert record["decision"] == "deny"
    assert record["decided_by"] == "canary"
    assert record["mode"] == "enforce"
    assert record["command"] == "echo BOUNDKEEP_CANARY"
    assert record["session_id"] == "sess-1"
    assert record["agent_id"] == "agent-9"
    assert record["permission_mode"] == "default"
    assert record["tool_name"] == "PowerShell"
    assert isinstance(record["latency_ms"], float)


def test_a_normal_command_gets_no_decision_and_is_logged(harness: Harness) -> None:
    response = harness.send("pre", shell("Get-ChildItem"))
    assert (response.ok, response.decision, response.reason) == (True, "none", "")
    (record,) = harness.records()
    assert record["decision"] == "none"
    assert "reason" not in record


def test_chinese_text_and_symbols_reach_the_log_exactly(harness: Harness) -> None:
    command = 'Write-Output "你好，世界 ✓" ; cd "D:\\新建文件夹\\项目"'  # noqa: RUF001 - on purpose
    harness.send("pre", shell(command))
    (record,) = harness.records()
    assert record["command"] == command  # byte for byte what the event said, not mojibake


def test_secrets_are_redacted_before_they_reach_the_log(harness: Harness) -> None:
    secret = "sk-proj-" + "a1B2c3D4" * 4
    harness.send("pre", shell(f'$env:MY_API_KEY = "{secret}"; Write-Output ok'))
    (record,) = harness.records()
    assert secret not in json.dumps(record)
    assert "[REDACTED]" in str(record["command"])
    assert "Write-Output ok" in str(record["command"])


def test_prompts_are_logged_by_length_only(harness: Harness) -> None:
    prompt = "请帮我删除这个文件 sk-should-never-be-logged-0123456789"
    response = harness.send(
        "prompt", {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "session_id": "s"}
    )
    assert response.decision == "none"
    (record,) = harness.records()
    assert record["prompt_chars"] == len(prompt)
    assert prompt not in json.dumps(record, ensure_ascii=False)
    assert "删除" not in json.dumps(record, ensure_ascii=False)


def test_post_events_are_logged_without_tool_output(harness: Harness) -> None:
    response = harness.send(
        "post",
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "WebFetch",
            "tool_use_id": "toolu_2",
            "tool_response": {"text": "<html>page content</html>"},
        },
    )
    assert response.decision == "none"
    (record,) = harness.records()
    assert record["tool_name"] == "WebFetch"
    assert "page content" not in json.dumps(record)


def test_config_attempts_are_logged_with_the_local_verdict(harness: Harness) -> None:
    harness.send(
        "config",
        {
            "hook_event_name": "ConfigChange",
            "source": "local_settings",
            "file_path": "E:\\proj\\.claude\\settings.local.json",
            "local_decision": "deny",
            "local_reason": "the change sets disableAllHooks",
        },
    )
    (record,) = harness.records()
    assert record["event"] == "config"
    assert record["local_decision"] == "deny"
    assert record["local_reason"] == "the change sets disableAllHooks"
    assert record["file_path"].endswith("settings.local.json")


def test_switching_to_audit_only_takes_effect_without_a_restart(harness: Harness) -> None:
    assert harness.send("pre", shell("BOUNDKEEP_CANARY")).decision == "deny"
    set_mode(harness.policy, "audit-only")
    response = harness.send("pre", shell("BOUNDKEEP_CANARY"))
    assert response.decision == "none"
    last = harness.records()[-1]
    assert last["mode"] == "audit-only"
    assert last["would_be"] == "deny"
    set_mode(harness.policy, "enforce")
    assert harness.send("pre", shell("BOUNDKEEP_CANARY")).decision == "deny"


def test_a_broken_policy_asks_until_it_is_fixed(harness: Harness) -> None:
    with open(harness.policy, "a", encoding="utf-8", newline="\n") as f:
        f.write("modee: audit-only\n")  # a typo must not be silently ignored
    response = harness.send("pre", shell("Get-ChildItem"))
    assert response.decision == "ask"
    assert "policy" in response.reason
    assert harness.records()[-1]["decided_by"] == "policy-invalid"
    assert any("policy problem" in m for m in harness.messages)
    write_default_policy(harness.policy, overwrite=True)
    assert harness.send("pre", shell("Get-ChildItem")).decision == "none"


def test_a_missing_policy_file_asks(harness: Harness) -> None:
    os.unlink(harness.policy)
    response = harness.send("pre", shell("Get-ChildItem"))
    assert response.decision == "ask"
    assert "not found" in response.reason


@pytest.mark.parametrize(
    "line",
    [b"", b"garbage", b"[]", b'{"v":1,"id":"a","event":"zzz","payload":{}}', b"\xff"],
)
def test_malformed_requests_get_an_error_response_never_an_exception(
    harness: Harness, line: bytes
) -> None:
    raw = asyncio.run(harness.daemon.handle(line))
    answer = json.loads(raw)
    assert answer["ok"] is False
    assert answer["error"] == protocol.ERR_BAD_REQUEST
    assert harness.records() == []  # nothing is logged for a request that is not one


def test_a_failing_audit_log_never_changes_the_answer(tmp_path: Path) -> None:
    home = tmp_path / "home"
    harness = Harness(home)
    blocker = home / "logs"
    blocker.mkdir()
    broken = AuditLog(str(blocker))  # the "file" is a directory: every append fails
    harness.daemon = Daemon(ENDPOINT, home=str(home), log=broken, report=harness.messages.append)
    assert harness.send("pre", shell("BOUNDKEEP_CANARY")).decision == "deny"
    assert harness.send("pre", shell("ls")).decision == "none"
    assert any("audit log write failed" in m for m in harness.messages)


def test_an_internal_failure_is_an_error_response(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: object, **kwargs: object) -> pipeline.Decision:
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(pipeline, "decide", boom)
    raw = asyncio.run(
        harness.daemon.handle(protocol.encode_request("pre", shell("ls"), "abc").rstrip(b"\n"))
    )
    answer = json.loads(raw)
    assert answer["ok"] is False
    assert answer["error"] == protocol.ERR_INTERNAL
    assert answer["id"] == "abc"
    assert "secret internal detail" not in json.dumps(answer)
    assert not any("secret internal detail" in m for m in harness.messages)


def test_concurrent_requests_are_all_answered_and_logged(harness: Harness) -> None:
    async def scenario() -> list[protocol.Response]:
        async def one(i: int) -> protocol.Response:
            line = protocol.encode_request("pre", shell(f"echo {i}"), f"r{i}").rstrip(b"\n")
            return protocol.decode_response(
                (await harness.daemon.handle(line)).rstrip(b"\n"), f"r{i}"
            )

        return list(await asyncio.gather(*(one(i) for i in range(200))))

    responses = asyncio.run(scenario())
    assert all(r.ok and r.decision == "none" for r in responses)
    assert len(harness.records()) == 200
    assert harness.daemon.requests_served == 200


def test_build_record_keeps_only_known_string_fields() -> None:
    request = protocol.Request(
        "r1",
        "pre",
        {"session_id": 7, "agent_id": "a", "unknown_field": "x", "cwd": ["not", "a", "string"]},
    )
    record = build_record(
        request, pipeline.Decision("none", "", "no-rule"), mode="enforce", latency_ms=1.234
    )
    assert record["agent_id"] == "a"
    assert "session_id" not in record
    assert "unknown_field" not in record
    assert "cwd" not in record
    assert record["latency_ms"] == 1.23


def test_serve_logs_start_and_stop_and_refuses_a_taken_address(tmp_path: Path) -> None:
    pytest.importorskip("ctypes")
    if os.name != "nt":
        pytest.skip("uses a named pipe address")
    from boundkeep.ipc.base import AddressInUse
    from boundkeep.ipc.endpoint import new_endpoint

    harness = Harness(tmp_path / "home")
    endpoint = new_endpoint(str(tmp_path), transport=TRANSPORT_NAMED_PIPE)
    harness.daemon = Daemon(
        endpoint, home=str(harness.home), log=harness.log, report=harness.messages.append
    )
    other = Daemon(endpoint, home=str(harness.home), log=harness.log, report=lambda m: None)

    async def scenario() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(harness.daemon.serve(stop))
        await asyncio.sleep(0.5)
        with pytest.raises(AddressInUse):
            await other.serve(asyncio.Event())
        stop.set()
        await asyncio.wait_for(task, timeout=10)

    asyncio.run(scenario())
    lifecycle = [r["action"] for r in harness.log.tail(100) if r.get("event") == "daemon"]
    assert lifecycle == ["start", "stop"]
    assert any(m.startswith("listening on") for m in harness.messages)


_ = Callable, Awaitable  # imported for the type comments above


@pytest.mark.parametrize("event", ["pre", "post", "prompt"])
@pytest.mark.parametrize("name", [["Bash"], {"a": 1}, 5, None])
def test_a_tool_name_that_is_not_a_string_is_handled_and_logged(
    harness: Harness, event: str, name: object
) -> None:
    payload = shell("echo hi")
    payload["tool_name"] = name
    response = harness.send(event, payload)
    assert response.ok
    assert response.decision == "none"
    assert len(harness.records()) == 1


def test_a_request_that_fails_inside_still_leaves_an_audit_record(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(pipeline, "decide", boom)
    response = harness.send("pre", shell("echo hi"), request_id="r9")
    assert not response.ok
    (record,) = harness.records()
    assert (record["id"], record["decided_by"], record["decision"]) == (
        "r9",
        "internal-error",
        "error",
    )


def test_an_unreadable_policy_is_read_again_without_the_file_changing(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    from boundkeep.daemon import server
    from boundkeep.policy import PolicyError

    real_load = server.load_policy
    failures = [PolicyError("cannot read policy file (locked)")]

    def flaky(path: str) -> object:
        if failures:
            raise failures.pop()
        return real_load(path)

    monkeypatch.setattr(server, "load_policy", flaky)
    monkeypatch.setattr(server, "POLICY_RETRY_S", 0.0)
    assert harness.send("pre", shell("echo BOUNDKEEP_CANARY")).decision == "ask"  # locked
    # the file never changed, but the next request reads it again and the gate is back
    assert harness.send("pre", shell("echo BOUNDKEEP_CANARY")).decision == "deny"
