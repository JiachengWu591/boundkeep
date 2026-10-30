"""The daemon's request handling, without any transport."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import threading
import time
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
    def __init__(self, home: Path, **daemon_kwargs: Any) -> None:
        self.home = home
        home.mkdir(parents=True, exist_ok=True)
        self.policy = paths.policy_file(str(home))
        write_default_policy(self.policy)
        self.messages: list[str] = []
        self.log = AuditLog(paths.audit_log_file(str(home)))
        self.daemon = Daemon(
            ENDPOINT, home=str(home), log=self.log, report=self.messages.append, **daemon_kwargs
        )

    async def asend(
        self, event: str, payload: dict[str, Any], request_id: str
    ) -> tuple[protocol.Response, float]:
        """One request on the running loop; also how long it took to be answered."""
        started = time.perf_counter()
        line = protocol.encode_request(event, payload, request_id).rstrip(b"\n")
        raw = await self.daemon.handle(line)
        return protocol.decode_response(
            raw.rstrip(b"\n"), request_id
        ), time.perf_counter() - started

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


def harmless(i: int = 0) -> dict[str, Any]:
    """A call the default policy allows (a read inside the project): the answer is "no decision"."""
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "sess-1",
        "cwd": "E:\\proj",
        "project_dir": "E:\\proj",
        "tool_name": "Read",
        "tool_use_id": f"toolu_{i}",
        "tool_input": {"file_path": f"E:\\proj\\src\\f{i}.py"},
    }


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
    assert record["decided_by"] == "rule:m0-canary"
    assert record["rules"] == ["m0-canary"]
    assert record["verdict"] == "deny"
    assert record["mode"] == "enforce"
    assert record["command"] == "echo BOUNDKEEP_CANARY"
    assert record["session_id"] == "sess-1"
    assert record["agent_id"] == "agent-9"
    assert record["permission_mode"] == "default"
    assert record["tool_name"] == "PowerShell"
    assert isinstance(record["latency_ms"], float)


def test_an_allowed_call_gets_no_decision_and_is_logged(harness: Harness) -> None:
    response = harness.send("pre", harmless())
    assert (response.ok, response.decision, response.reason) == (True, "none", "")
    (record,) = harness.records()
    assert record["decision"] == "none"
    assert record["verdict"] == "allow"
    assert record["rules"] == ["read-inside-project"]
    assert "reason" not in record


def test_a_command_no_rule_settles_asks_and_the_log_says_which_programs(harness: Harness) -> None:
    response = harness.send("pre", shell("pytest -q && ls", tool="Bash"))
    assert response.decision == "ask"
    (record,) = harness.records()
    assert (record["verdict"], record["decided_by"]) == ("gray", "gray")
    assert record["programs"] == ["pytest", "ls"]


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
    response = harness.send("pre", harmless())
    assert response.decision == "ask"
    assert "policy" in response.reason
    assert harness.records()[-1]["decided_by"] == "policy-invalid"
    assert any("policy problem" in m for m in harness.messages)
    write_default_policy(harness.policy, overwrite=True)
    assert harness.send("pre", harmless()).decision == "none"


def test_a_missing_policy_file_asks(harness: Harness) -> None:
    os.unlink(harness.policy)
    response = harness.send("pre", harmless())
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
    assert harness.send("pre", harmless()).decision == "none"
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
            line = protocol.encode_request("pre", harmless(i), f"r{i}").rstrip(b"\n")
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
    # a PreToolUse call with no usable tool name is gray (asks); the other events never decide
    assert response.decision == ("ask" if event == "pre" else "none")
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

    def flaky(path: str, **kwargs: Any) -> object:
        if failures:
            raise failures.pop()
        return real_load(path, **kwargs)

    monkeypatch.setattr(server, "load_policy", flaky)
    monkeypatch.setattr(server, "POLICY_RETRY_S", 0.0)
    assert harness.send("pre", shell("echo BOUNDKEEP_CANARY")).decision == "ask"  # locked
    # the file never changed, but the next request reads it again and the gate is back
    assert harness.send("pre", shell("echo BOUNDKEEP_CANARY")).decision == "deny"


# --------------------------------------------------------------------------------------------
# The decision runs off the event loop, under a deadline
# --------------------------------------------------------------------------------------------

SLOW_REASON = "boundkeep: review took too long"


class SlowDecide:
    """A stand-in for ``pipeline.decide`` that blocks on commands containing SLOW until released."""

    def __init__(self, real: Callable[..., pipeline.Decision]) -> None:
        self.real = real
        self.release = threading.Event()
        self.started = 0
        self.lock = threading.Lock()

    def __call__(self, event: str, payload: Any, **kwargs: Any) -> pipeline.Decision:
        command = pipeline.shell_command(payload) or ""
        if "SLOW" in command:
            with self.lock:
                self.started += 1
            self.release.wait(30)
        return self.real(event, payload, **kwargs)


@pytest.fixture
def slow(monkeypatch: pytest.MonkeyPatch) -> Any:
    stand_in = SlowDecide(pipeline.decide)
    monkeypatch.setattr(pipeline, "decide", stand_in)
    yield stand_in
    stand_in.release.set()  # let the abandoned workers finish, whatever the test did


def test_a_review_that_takes_too_long_is_answered_ask_at_the_deadline(
    tmp_path: Path, slow: SlowDecide
) -> None:
    harness = Harness(tmp_path / "home", decision_timeout_s=0.3)
    response, took = asyncio.run(harness.asend("pre", shell("echo SLOW " + "x" * 500), "t1"))
    assert response.ok
    assert (response.decision, response.reason) == ("ask", SLOW_REASON)
    assert 0.25 <= took < 2.0
    (record,) = harness.records()
    assert (record["decision"], record["decided_by"]) == ("ask", "timeout")
    assert record["id"] == "t1"
    assert record["command_chars"] == len("echo SLOW ") + 500
    assert "command" not in record  # the length, never the text
    assert "SLOW" not in json.dumps(record)


def test_fast_requests_are_answered_quickly_while_a_review_is_stuck(
    tmp_path: Path, slow: SlowDecide
) -> None:
    harness = Harness(tmp_path / "home", decision_timeout_s=1.5)

    async def scenario() -> list[tuple[protocol.Response, float]]:
        stuck = asyncio.create_task(harness.asend("pre", shell("echo SLOW"), "slow"))
        while slow.started == 0:
            await asyncio.sleep(0.01)
        fast = [harness.asend("pre", harmless(i), f"f{i}") for i in range(20)]
        ping = harness.asend("ping", {}, "ping")
        post = harness.asend("post", {"hook_event_name": "PostToolUse", "tool_name": "Read"}, "p")
        answered = list(await asyncio.gather(*fast, ping, post))
        assert not stuck.done()  # the stuck one is still waiting for its deadline
        answered.append(await stuck)
        return answered

    answered = asyncio.run(scenario())
    *quick, last = answered
    assert all(r.ok for r, _ in quick)
    assert all(took < 1.0 for _, took in quick), [took for _, took in quick]
    assert [r.decision for r, _ in quick[:20]] == ["none"] * 20
    assert last[0].decision == "ask"
    assert last[0].reason == SLOW_REASON


def test_ping_and_other_events_do_not_wait_for_stuck_reviews(
    tmp_path: Path, slow: SlowDecide
) -> None:
    harness = Harness(tmp_path / "home", decision_timeout_s=0.3, pool_size=2)

    async def scenario() -> tuple[protocol.Response, float, protocol.Response, float]:
        stuck = [
            asyncio.create_task(harness.asend("pre", shell(f"SLOW {i}"), f"s{i}")) for i in range(2)
        ]
        await asyncio.gather(*stuck)  # both timed out; both workers are still blocked
        ping, ping_took = await harness.asend("ping", {}, "ping")
        post, post_took = await harness.asend(
            "post", {"hook_event_name": "PostToolUse", "tool_name": "Read"}, "post"
        )
        return ping, ping_took, post, post_took

    ping, ping_took, post, post_took = asyncio.run(scenario())
    assert ping.ok
    assert "stuck=2" in ping.reason
    assert post.ok
    assert post.decision == "none"
    assert max(ping_took, post_took) < 0.5


def test_when_every_worker_is_stuck_new_reviews_are_answered_ask_without_starting_work(
    tmp_path: Path, slow: SlowDecide
) -> None:
    harness = Harness(tmp_path / "home", decision_timeout_s=0.2, pool_size=2)

    async def scenario() -> tuple[protocol.Response, float]:
        await asyncio.gather(
            harness.asend("pre", shell("SLOW a"), "s0"), harness.asend("pre", shell("SLOW b"), "s1")
        )
        # Both timed out. The first review loads the policy (about 0.25 s for the default one,
        # longer than this test's 0.2 s deadline), so a worker may still be on its way into the
        # stuck review: wait until both are in it before counting.
        for _ in range(500):
            if slow.started == 2:
                break
            await asyncio.sleep(0.01)
        before = slow.started
        assert before == 2
        busy = await harness.asend("pre", shell("SLOW c"), "busy")
        assert slow.started == before  # no work was started for it
        return busy

    response, took = asyncio.run(scenario())
    assert response.ok
    assert response.decision == "ask"
    assert "busy" in response.reason
    assert took < 0.15  # immediately, no deadline to wait for
    assert [r["decided_by"] for r in harness.records()] == ["timeout", "timeout", "busy"]
    # the stuck workers finish: the daemon takes work again
    slow.release.set()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        again = harness.send("pre", harmless(), request_id="after")
        if again.decision == "none":
            break
        time.sleep(0.05)
    assert again.decision == "none"


def test_a_worker_that_finishes_late_does_not_change_the_answer_or_the_count(
    tmp_path: Path, slow: SlowDecide
) -> None:
    harness = Harness(tmp_path / "home", decision_timeout_s=0.2, pool_size=2)
    first = harness.send("pre", shell("SLOW"), request_id="late")
    assert (first.decision, first.reason) == ("ask", SLOW_REASON)
    slow.release.set()
    time.sleep(0.3)
    assert "stuck=0" in harness.send("ping", {}, request_id="p").reason
    assert [r["decided_by"] for r in harness.records()] == ["timeout"]  # logged once


def test_pool_threads_are_daemons_so_a_stuck_worker_cannot_keep_the_process_alive(
    tmp_path: Path, slow: SlowDecide
) -> None:
    harness = Harness(tmp_path / "home", decision_timeout_s=0.2, pool_size=2)
    harness.send("pre", shell("SLOW"), request_id="x")
    workers = [t for t in threading.enumerate() if t.name.startswith("boundkeep-decide")]
    assert workers
    assert all(t.daemon for t in workers)


def test_serve_stops_promptly_while_a_review_is_stuck(tmp_path: Path, slow: SlowDecide) -> None:
    if os.name != "nt":
        pytest.skip("uses a named pipe address")
    from boundkeep.ipc import client as ipc_client
    from boundkeep.ipc.endpoint import new_endpoint

    home = Harness(tmp_path / "home")
    endpoint = new_endpoint(str(tmp_path), transport=TRANSPORT_NAMED_PIPE)
    daemon = Daemon(
        endpoint, home=str(home.home), log=home.log, report=lambda m: None, decision_timeout_s=5.0
    )

    async def scenario() -> float:
        stop = asyncio.Event()
        task = asyncio.create_task(daemon.serve(stop))
        await asyncio.sleep(0.5)
        line = protocol.encode_request("pre", shell("SLOW"), "hang")
        client = asyncio.get_running_loop().run_in_executor(
            None, lambda: _call_quietly(ipc_client, endpoint, line)
        )
        while slow.started == 0:
            await asyncio.sleep(0.02)
        began = time.perf_counter()
        stop.set()
        await asyncio.wait_for(task, timeout=10)
        stopped = time.perf_counter() - began
        await asyncio.wait_for(client, timeout=10)
        return stopped

    assert asyncio.run(scenario()) < 5.0


def _call_quietly(ipc_client: Any, endpoint: Endpoint, line: bytes) -> None:
    with contextlib.suppress(Exception):  # the server going away while we wait is the point
        ipc_client.call(endpoint, line, timeout_s=3.0)


def test_the_audit_record_tells_the_decision_time_and_the_previous_write_time(
    harness: Harness,
) -> None:
    harness.send("pre", harmless(1), request_id="a")
    harness.send("pre", harmless(2), request_id="b")
    first, second = harness.records()
    assert "prev_audit_ms" not in first
    assert isinstance(second["prev_audit_ms"], float)
    assert second["prev_audit_ms"] >= 0


def test_the_ping_reply_names_the_claude_config_dir_the_daemon_sees(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    assert "config_dir=-" in harness.send("ping", {}, request_id="p1").reason
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", "E:\\somewhere\\else")
    assert "config_dir=E:\\somewhere\\else" in harness.send("ping", {}, request_id="p2").reason


# --------------------------------------------------------------------------------------------
# The policy: a failed (re)load never leaves an old policy silently active
# --------------------------------------------------------------------------------------------


def _touch_policy(harness: Harness) -> None:
    with open(harness.policy, "a", encoding="utf-8", newline="\n") as f:
        f.write("# edited\n")


def test_a_load_that_blows_up_with_a_non_policy_error_does_not_keep_the_old_policy_active(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    from boundkeep.daemon import server

    assert harness.send("pre", shell("echo BOUNDKEEP_CANARY")).decision == "deny"

    def explode(path: str, **kwargs: Any) -> object:
        raise RuntimeError("yaml library exploded")

    monkeypatch.setattr(server, "load_policy", explode)
    _touch_policy(harness)
    for i in range(3):  # not only the first request after the edit
        response = harness.send("pre", harmless(), request_id=f"r{i}")
        assert (response.ok, response.decision) == (True, "ask"), i
    assert harness.records()[-1]["decided_by"] == "policy-invalid"
    assert "policy error" in harness.send("ping", {}, request_id="p").reason


def test_an_unusable_runtime_addition_is_a_policy_error_not_a_silent_pass(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    def checked(policy: Any, env: Any, home: Any) -> tuple[Any, str | None]:
        return policy, "CLAUDE_CONFIG_DIR is set but cannot be protected"

    monkeypatch.setattr(pipeline, "runtime_policy_checked", checked, raising=False)
    response = harness.send("pre", harmless())
    assert response.decision == "ask"
    assert "cannot be protected" in response.reason
    assert "policy error: CLAUDE_CONFIG_DIR" in harness.send("ping", {}, request_id="p").reason


def test_a_runtime_problem_clears_when_the_policy_is_fine_again(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    problems: list[str | None] = ["boom"]

    def checked(policy: Any, env: Any, home: Any) -> tuple[Any, str | None]:
        return policy, problems[0]

    monkeypatch.setattr(pipeline, "runtime_policy_checked", checked, raising=False)
    from boundkeep.daemon import server

    monkeypatch.setattr(server, "POLICY_RETRY_S", 0.0)
    assert harness.send("pre", harmless()).decision == "ask"
    problems[0] = None  # the file did not change: the daemon looks again by itself
    assert harness.send("pre", harmless(), request_id="r2").decision == "none"
