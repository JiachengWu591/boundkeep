"""The PowerShell helper process and its manager (normalize/psparse.py, normalize/pshelper.ps1).

Two layers. Everything about process management (not ready, timeout, crash, garbage, oversize,
breaker, recycling, shutdown, queueing) runs against a FAKE child injected through ``spawn`` and
needs no PowerShell. Tests marked ``windows`` start the real helper (Windows PowerShell 5.1 or
pwsh) and check what it really answers; they skip elsewhere.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import re
import subprocess
import sys
import threading
import time
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from boundkeep.normalize import psparse
from boundkeep.normalize.model import BashResult, SimpleCmd, Word

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "ps_ast"
HELPER_SCRIPT = REPO / "src" / "boundkeep" / "normalize" / "pshelper.ps1"

READY = b'{"ready":true,"mode":"FullLanguage","version":"5.1.99999.1"}\n'
READY_CLM = b'{"ready":true,"mode":"ConstrainedLanguage","version":"5.1.99999.1"}\n'


# --------------------------------------------------------------------------------------------
# A fake child process
# --------------------------------------------------------------------------------------------


class _FakeOut:
    """stdout of a fake child: a byte buffer with the ``readline(limit)`` semantics of a pipe."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._eof = False
        self._cv = threading.Condition()

    def feed(self, data: bytes) -> None:
        with self._cv:
            self._buf += data
            self._cv.notify_all()

    def eof(self) -> None:
        with self._cv:
            self._eof = True
            self._cv.notify_all()

    def readline(self, limit: int = -1) -> bytes:
        with self._cv:
            while True:
                index = self._buf.find(b"\n")
                if index >= 0 and (limit < 0 or index < limit):
                    end = index + 1
                    break
                if limit >= 0 and len(self._buf) >= limit:
                    end = limit
                    break
                if self._eof:
                    end = len(self._buf)
                    break
                self._cv.wait(timeout=0.05)
            line = bytes(self._buf[:end])
            del self._buf[:end]
            return line

    def close(self) -> None:
        pass


class _FakeIn:
    def __init__(self, proc: FakeProc) -> None:
        self._proc = proc
        self.closed = False

    def write(self, data: bytes) -> int:
        if self._proc.returncode is not None:
            raise BrokenPipeError("child is gone")
        request = json.loads(data.decode("ascii"))
        request["text"] = base64.b64decode(request["b64"]).decode("utf-8")
        self._proc.requests.append(request)
        self._proc.script.on_request(self._proc, request)
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


def ok_reply(request: dict[str, Any], **changes: Any) -> dict[str, Any]:
    text = request["text"]
    reply: dict[str, Any] = {
        "id": request["id"],
        "ok": True,
        "parse_errors": [],
        "commands": [
            {
                "pos": [0, len(text)],
                "invoke": "",
                "name": {"kind": "bare", "v": text.split(" ")[0]},
                "elements": [],
                "redirects": [],
                "stage": {"index": 0, "of": 1},
                "nested": False,
            }
        ],
        "compound": [],
        "dynamic": [],
        "mode": "FullLanguage",
    }
    reply.update(changes)
    return reply


def send(proc: FakeProc, reply: object) -> None:
    proc.out.feed(json.dumps(reply).encode("ascii") + b"\n")


def respond_ok(proc: FakeProc, request: dict[str, Any]) -> None:
    send(proc, ok_reply(request))


def hang(proc: FakeProc, request: dict[str, Any]) -> None:
    """Accept the request and never answer."""


def crash(proc: FakeProc, request: dict[str, Any]) -> None:
    proc.kill()


def garbage(proc: FakeProc, request: dict[str, Any]) -> None:
    proc.out.feed(b"this is not json\n")


def wrong_id(proc: FakeProc, request: dict[str, Any]) -> None:
    send(proc, ok_reply(request, id="0000"))


def not_an_object(proc: FakeProc, request: dict[str, Any]) -> None:
    proc.out.feed(b"[1, 2, 3]\n")


def answer(**changes: Any) -> Callable[[FakeProc, dict[str, Any]], None]:
    def handler(proc: FakeProc, request: dict[str, Any]) -> None:
        send(proc, ok_reply(request, **changes))

    return handler


def error_reply(error: object) -> Callable[[FakeProc, dict[str, Any]], None]:
    def handler(proc: FakeProc, request: dict[str, Any]) -> None:
        send(proc, {"id": request["id"], "ok": False, "error": error})

    return handler


def oversize(proc: FakeProc, request: dict[str, Any]) -> None:
    proc.out.feed(b"x" * 500)  # no newline: longer than any allowed reply line


def block_write(proc: FakeProc, request: dict[str, Any]) -> None:
    """A wedged pipe: the write does not return until the child is killed."""
    proc.killed.wait(10)
    raise BrokenPipeError("killed while writing")


class Script:
    def __init__(
        self,
        ready: bytes | None = READY,
        on_request: Callable[[FakeProc, dict[str, Any]], None] = respond_ok,
    ) -> None:
        self.ready = ready
        self.on_request = on_request


class FakeProc:
    _next_pid = 5000

    def __init__(self, script: Script) -> None:
        FakeProc._next_pid += 1
        self.pid = FakeProc._next_pid
        self.script = script
        self.returncode: int | None = None
        self.killed = threading.Event()
        self.out = _FakeOut()
        self.stdout = self.out
        self.stdin = _FakeIn(self)
        self.requests: list[dict[str, Any]] = []
        if script.ready is not None:
            self.out.feed(script.ready)

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9
        self.killed.set()
        self.out.eof()

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode or 0


class Spawner:
    """A ``spawn`` factory: hands out fake children following ``scripts`` (the last one repeats).

    An exception instance in ``scripts`` is raised instead of producing a child.
    """

    def __init__(self, *scripts: Script | BaseException) -> None:
        self.scripts: list[Script | BaseException] = list(scripts) or [Script()]
        self.procs: list[FakeProc] = []
        self.calls = 0

    def set(self, *scripts: Script | BaseException) -> None:
        self.scripts = list(scripts)
        self.calls = 0

    def __call__(self) -> FakeProc:
        script = self.scripts[min(self.calls, len(self.scripts) - 1)]
        self.calls += 1
        if isinstance(script, BaseException):
            raise script
        proc = FakeProc(script)
        self.procs.append(proc)
        return proc


class OffsetClock:
    """``time.monotonic()`` plus an offset the test can advance (backoff, recycling by age)."""

    def __init__(self) -> None:
        self.offset = 0.0

    def __call__(self) -> float:
        return time.monotonic() + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += seconds


@pytest.fixture
def clock() -> OffsetClock:
    return OffsetClock()


@pytest.fixture
def made() -> Any:
    """Build helpers; every one is shut down at the end of the test."""
    created: list[psparse.PsHelper] = []

    def make(spawner: Spawner, **kwargs: Any) -> psparse.PsHelper:
        kwargs.setdefault("startup_timeout_s", 2.0)
        helper = psparse.PsHelper(spawner, **kwargs)
        created.append(helper)
        return helper

    yield make
    for helper in created:
        helper.shutdown()


def wait_until(condition: Callable[[], object], seconds: float = 3.0) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return bool(condition())


def ready_helper(made: Any, spawner: Spawner | None = None, **kwargs: Any) -> psparse.PsHelper:
    helper = made(spawner or Spawner(), **kwargs)
    assert helper.warm_up(wait_s=3)
    return helper


# --------------------------------------------------------------------------------------------
# Start-up and the happy path (fake child)
# --------------------------------------------------------------------------------------------


def test_status_before_start_is_warming_and_does_not_start(made: Any) -> None:
    spawner = Spawner()
    helper = made(spawner)
    state = helper.status()
    assert state["state"] == "warming"
    assert state["failures"] == 0
    assert state["warmup_ms"] is None
    assert spawner.calls == 0


def test_warm_up_reaches_ready_and_reports_version(made: Any) -> None:
    helper = ready_helper(made)
    state = helper.status()
    assert state["state"] == "ready"
    assert state["mode"] == "FullLanguage"
    assert state["version"] == "5.1.99999.1"
    assert state["warmup_ms"] is not None
    assert state["pid"] is not None


def test_request_returns_the_reply(made: Any) -> None:
    helper = ready_helper(made)
    reply, gray = helper.request("Get-ChildItem -Recurse", budget_s=2)
    assert gray == ()
    assert reply is not None
    assert reply["ok"] is True
    assert reply["commands"][0]["name"]["v"] == "Get-ChildItem"
    assert helper.status()["requests"] == 1


def test_request_line_is_protocol_conform(made: Any) -> None:
    spawner = Spawner()
    helper = ready_helper(made, spawner)
    helper.request("echo 你好 ✓", budget_s=2)
    request = spawner.procs[0].requests[0]
    assert set(request) == {"id", "b64", "text"}
    assert re.fullmatch(r"[0-9a-f]{16}", request["id"])
    assert request["text"] == "echo 你好 ✓"


def test_not_ready_before_the_helper_has_started(made: Any) -> None:
    """A call before the ready line returns gray at once; it never waits for the start."""
    spawner = Spawner(Script(ready=None))  # starts, but never says ready
    helper = made(spawner, startup_timeout_s=30)
    began = time.perf_counter()
    reply, gray = helper.request("ls", budget_s=1)
    assert (reply, gray) == (None, (psparse.REASON_NOT_READY,))
    assert time.perf_counter() - began < 0.5
    assert helper.status()["state"] == "warming"


def test_a_late_ready_line_makes_it_ready(made: Any) -> None:
    spawner = Spawner(Script(ready=None))
    helper = made(spawner, startup_timeout_s=30)
    helper.request("ls", budget_s=0.1)  # triggers the start
    assert wait_until(lambda: spawner.procs)
    spawner.procs[0].out.feed(READY)
    assert helper.warm_up(wait_s=3)


def test_warm_up_is_idempotent(made: Any) -> None:
    spawner = Spawner()
    helper = ready_helper(made, spawner)
    helper.warm_up()
    helper.warm_up()
    assert spawner.calls == 1


def test_positions_become_python_offsets_for_astral_characters(made: Any) -> None:
    text = "echo '😀' x"  # one code point, two UTF-16 units

    def handler(proc: FakeProc, request: dict[str, Any]) -> None:
        # What PowerShell reports: the command spans 3..?? in UTF-16 units
        units = len(text.encode("utf-16-le")) // 2
        reply = ok_reply(request)
        reply["commands"] = [
            {"pos": [0, units], "invoke": "", "name": {"kind": "bare", "v": "echo"}},
            {"pos": [10, 11], "name": {"kind": "bare", "v": "x"}},
            {"pos": "weird", "name": {"kind": "bare", "v": "y"}},
            {"pos": [0, 999], "name": {"kind": "bare", "v": "z"}},
        ]
        send(proc, reply)

    helper = ready_helper(made, Spawner(Script(on_request=handler)))
    reply, gray = helper.request(text, budget_s=2)
    assert gray == ()
    assert reply is not None
    assert reply["commands"][0]["pos"] == [0, len(text)]
    assert reply["commands"][1]["pos"] == [9, 10]
    assert reply["commands"][2]["pos"] == "weird"
    assert reply["commands"][3]["pos"] == [0, 999]  # out of range: left alone, not an exception


def test_positions_are_untouched_for_bmp_text(made: Any) -> None:
    helper = ready_helper(made)
    reply, _ = helper.request("echo 你好", budget_s=2)
    assert reply is not None
    assert reply["commands"][0]["pos"] == [0, 7]


# --------------------------------------------------------------------------------------------
# Unavailable: no PowerShell, constrained language
# --------------------------------------------------------------------------------------------


def test_missing_powershell_is_unavailable_and_sticky(made: Any) -> None:
    spawner = Spawner(FileNotFoundError("no powershell"))
    helper = made(spawner)
    helper.warm_up(wait_s=3)
    state = helper.status()
    assert state["state"] == "unavailable"
    assert "not found" in state["reason"]
    for _ in range(3):
        assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_UNAVAILABLE,))
    assert spawner.calls == 1  # no retry loop


def test_reset_redetects_powershell(made: Any) -> None:
    spawner = Spawner(FileNotFoundError("no powershell"))
    helper = made(spawner)
    helper.warm_up(wait_s=3)
    assert helper.status()["state"] == "unavailable"
    spawner.set(Script())
    helper.reset()
    assert helper.warm_up(wait_s=3)
    assert helper.request("ls", budget_s=1)[1] == ()


def test_constrained_language_mode_is_unavailable(made: Any) -> None:
    spawner = Spawner(Script(ready=READY_CLM))
    helper = made(spawner)
    helper.warm_up(wait_s=3)
    state = helper.status()
    assert state["state"] == "unavailable"
    assert state["mode"] == "ConstrainedLanguage"
    assert "ConstrainedLanguage" in state["reason"]
    assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_UNAVAILABLE,))
    assert spawner.procs[0].killed.is_set()


def test_a_reply_in_another_language_mode_makes_it_unavailable(made: Any) -> None:
    helper = ready_helper(made, Spawner(Script(on_request=answer(mode="ConstrainedLanguage"))))
    assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_UNAVAILABLE,))
    assert helper.status()["state"] == "unavailable"


def test_helper_that_cannot_parse_reports_unusable(made: Any) -> None:
    ready = b'{"ready":true,"mode":"Unusable","version":"7.4.0"}\n'
    helper = made(Spawner(Script(ready=ready)))
    helper.warm_up(wait_s=3)
    assert helper.status()["state"] == "unavailable"


# --------------------------------------------------------------------------------------------
# Failure paths
# --------------------------------------------------------------------------------------------


def test_timeout_is_gray_kills_the_child_and_restarts(made: Any, clock: OffsetClock) -> None:
    spawner = Spawner(Script(on_request=hang), Script())
    helper = ready_helper(made, spawner, clock=clock)
    began = time.perf_counter()
    reply, gray = helper.request("ls", budget_s=0.2)
    elapsed = time.perf_counter() - began
    assert (reply, gray) == (None, (psparse.REASON_TIMEOUT,))
    assert 0.15 < elapsed < 0.6
    assert spawner.procs[0].killed.is_set()
    assert helper.status()["failures"] == 0  # a parse timeout is not a breaker failure
    assert helper.status()["timeouts"] == 1
    # The replacement starts at once (no backoff); gray, never delayed, until it is ready.
    assert helper.warm_up(wait_s=3)
    reply, gray = helper.request("ls", budget_s=1)
    assert gray == ()
    assert reply is not None
    assert spawner.calls == 2


def test_a_hanging_write_is_cut_off_by_the_watchdog(made: Any) -> None:
    helper = ready_helper(made, Spawner(Script(on_request=block_write)))
    began = time.perf_counter()
    reply, gray = helper.request("ls", budget_s=0.2)
    assert (reply, gray) == (None, (psparse.REASON_TIMEOUT,))
    assert time.perf_counter() - began < 0.7


def test_a_slow_big_request_is_a_timeout_but_not_a_breaker_failure(made: Any) -> None:
    spawner = Spawner(Script(on_request=hang), Script())
    helper = ready_helper(made, spawner)
    big = "a;" * (psparse.SLOW_INPUT_BYTES // 2 + 10)
    assert helper.request(big, budget_s=0.15) == (None, (psparse.REASON_TIMEOUT,))
    assert helper.status()["failures"] == 0
    assert helper.warm_up(wait_s=3)  # restarts at once: no backoff for a slow input
    assert spawner.calls == 2


def test_crash_is_gray_and_counted(made: Any) -> None:
    spawner = Spawner(Script(on_request=crash), Script())
    helper = ready_helper(made, spawner)
    assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_CRASHED,))
    assert helper.status()["failures"] == 1


def test_child_that_dies_while_idle_counts_as_a_crash(made: Any, clock: OffsetClock) -> None:
    spawner = Spawner()
    helper = ready_helper(made, spawner, clock=clock)
    spawner.procs[0].kill()
    assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_NOT_READY,))
    assert helper.status()["failures"] == 1
    clock.advance(1.0)
    assert helper.warm_up(wait_s=3)
    assert helper.request("ls", budget_s=1)[1] == ()


@pytest.mark.parametrize(
    "handler",
    [garbage, wrong_id, not_an_object, oversize],
    ids=["garbage", "wrong-id", "not-an-object", "oversize"],
)
def test_protocol_violations_are_crashes(made: Any, handler: Any) -> None:
    helper = ready_helper(made, Spawner(Script(on_request=handler)), max_reply_bytes=200)
    assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_CRASHED,))
    assert helper.status()["failures"] == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"ok": "yes"},
        {"commands": "nope"},
        {"commands": [1, 2]},
        {"parse_errors": None},
        {"compound": [1]},
        {"dynamic": "x"},
        {"mode": 5},
    ],
    ids=["ok", "commands-str", "commands-items", "parse-errors", "compound", "dynamic", "mode"],
)
def test_badly_shaped_replies_are_crashes(made: Any, changes: dict[str, Any]) -> None:
    helper = ready_helper(made, Spawner(Script(on_request=answer(**changes))))
    assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_CRASHED,))


def test_error_reply_without_error_text_is_a_crash(made: Any) -> None:
    helper = ready_helper(made, Spawner(Script(on_request=error_reply(None))))
    assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_CRASHED,))


def test_helper_errors_are_gray_but_do_not_hurt_the_child(made: Any) -> None:
    spawner = Spawner(Script(on_request=error_reply("internal")))
    helper = ready_helper(made, spawner)
    for _ in range(8):  # more than the breaker allows: it must not count
        assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_HELPER_ERROR,))
    assert helper.status()["state"] == "ready"
    assert helper.status()["failures"] == 0
    assert spawner.calls == 1


def test_helper_too_large_error_maps_to_input_too_large(made: Any) -> None:
    helper = ready_helper(made, Spawner(Script(on_request=error_reply("too-large"))))
    assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_TOO_LARGE,))


def test_ready_line_that_is_not_ready_is_a_start_failure(made: Any) -> None:
    for bad in (
        b"hello\n",
        b'{"ready":false,"mode":"FullLanguage"}\n',
        b'{"ready":true}\n',
        b"[]\n",
    ):
        helper = made(Spawner(Script(ready=bad)))
        helper.warm_up()
        assert wait_until(lambda helper=helper: helper.status()["failures"] == 1), bad
        assert helper.status()["state"] == "warming"


def test_child_that_exits_during_start_is_a_start_failure(made: Any) -> None:
    spawner = Spawner(Script(ready=None))
    helper = made(spawner)
    helper.warm_up()
    assert wait_until(lambda: spawner.procs)
    spawner.procs[0].kill()  # EOF before any ready line
    assert wait_until(lambda: helper.status()["failures"] == 1)


def test_start_timeout_is_a_start_failure(made: Any) -> None:
    spawner = Spawner(Script(ready=None))
    helper = made(spawner, startup_timeout_s=0.2)
    helper.warm_up()
    assert wait_until(lambda: helper.status()["failures"] == 1)
    assert spawner.procs[0].killed.is_set()


def test_spawn_errors_are_start_failures(made: Any) -> None:
    for error in (OSError("boom"), RuntimeError("weird")):
        helper = made(Spawner(error))
        helper.warm_up()
        assert wait_until(lambda helper=helper: helper.status()["failures"] == 1)


def test_backoff_doubles_up_to_the_cap(made: Any) -> None:
    helper = made(Spawner(), backoff_initial_s=0.5, backoff_max_s=3.0, max_failures=100)
    seen = []
    for failures in range(1, 8):
        helper._failures = failures
        seen.append(helper._backoff())
    assert seen == [0.5, 1.0, 2.0, 3.0, 3.0, 3.0, 3.0]


def test_circuit_breaker_opens_after_five_failures_and_reset_closes_it(
    made: Any, clock: OffsetClock
) -> None:
    spawner = Spawner(Script(on_request=crash))
    helper = ready_helper(made, spawner, clock=clock, breaker_cooldown_s=1e9)
    for expected in range(1, 5):
        assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_CRASHED,))
        assert helper.status()["failures"] == expected
        clock.advance(60)
        assert helper.warm_up(wait_s=3)
    assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_CRASHED,))
    state = helper.status()
    assert state["state"] == "disabled"
    assert state["failures"] == 5
    for _ in range(3):
        assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_DISABLED,))
    calls = spawner.calls
    clock.advance(600)
    assert helper.warm_up(wait_s=0.2) is False
    assert spawner.calls == calls  # nothing is started while the breaker is open
    spawner.set(Script())
    helper.reset()
    assert helper.status()["failures"] == 0
    assert helper.warm_up(wait_s=3)
    assert helper.request("ls", budget_s=1)[1] == ()


def test_start_failures_also_open_the_breaker(made: Any, clock: OffsetClock) -> None:
    spawner = Spawner(OSError("cannot start"))
    helper = made(spawner, clock=clock, breaker_cooldown_s=1e9)
    for failures in range(1, 6):
        helper.warm_up()
        assert wait_until(lambda failures=failures: helper.status()["failures"] >= failures)
        clock.advance(60)
    assert helper.status()["state"] == "disabled"
    assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_DISABLED,))


# --------------------------------------------------------------------------------------------
# Limits, queueing, recycling, shutdown
# --------------------------------------------------------------------------------------------


def test_oversize_request_is_gray_without_touching_the_child(made: Any) -> None:
    spawner = Spawner()
    helper = made(spawner)
    text = "a" * (psparse.MAX_REQUEST_BYTES + 1)
    assert helper.request(text, budget_s=1) == (None, (psparse.REASON_TOO_LARGE,))
    assert spawner.calls == 0
    # the limit counts UTF-8 bytes, not characters
    wide = "你" * (psparse.MAX_REQUEST_BYTES // 3 + 1)
    assert helper.request(wide, budget_s=1) == (None, (psparse.REASON_TOO_LARGE,))


def test_request_of_exactly_the_limit_is_sent(made: Any) -> None:
    helper = ready_helper(made, max_request_bytes=100)
    assert helper.request("a" * 100, budget_s=2)[1] == ()
    assert helper.request("a" * 101, budget_s=2) == (None, (psparse.REASON_TOO_LARGE,))


@pytest.mark.parametrize("text", ["a\ud800b", "\udc00", "ok \udfff"])
def test_lone_surrogates_are_gray_not_an_exception(made: Any, text: str) -> None:
    helper = ready_helper(made)
    assert helper.request(text, budget_s=1) == (None, (psparse.REASON_BAD_TEXT,))
    assert helper.status()["failures"] == 0


def test_second_caller_gets_busy_after_its_budget(made: Any) -> None:
    gate = threading.Event()
    entered = threading.Event()

    def slow(proc: FakeProc, request: dict[str, Any]) -> None:
        entered.set()
        gate.wait(5)
        send(proc, ok_reply(request))

    helper = ready_helper(made, Spawner(Script(on_request=slow)))
    first: list[Any] = []
    thread = threading.Thread(target=lambda: first.append(helper.request("slow", budget_s=5)))
    thread.start()
    assert entered.wait(2)
    began = time.perf_counter()
    assert helper.request("second", budget_s=0.15) == (None, (psparse.REASON_BUSY,))
    assert 0.1 < time.perf_counter() - began < 0.6
    gate.set()
    thread.join(5)
    assert first[0][1] == ()


def test_requests_are_serialized(made: Any) -> None:
    active = 0
    peak = 0
    lock = threading.Lock()

    def tracking(proc: FakeProc, request: dict[str, Any]) -> None:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.01)
        send(proc, ok_reply(request))
        with lock:
            active -= 1

    helper = ready_helper(made, Spawner(Script(on_request=tracking)))
    results: list[Any] = []
    threads = [
        threading.Thread(target=lambda i=i: results.append(helper.request(f"c{i}", budget_s=5)))
        for i in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert peak == 1
    assert all(gray == () for _, gray in results)
    assert len(results) == 8


def test_zero_budget_returns_at_once(made: Any) -> None:
    helper = ready_helper(made, Spawner(Script(on_request=hang)))
    began = time.perf_counter()
    reply, gray = helper.request("ls", budget_s=0)
    assert reply is None
    assert gray in {(psparse.REASON_TIMEOUT,), (psparse.REASON_BUSY,)}
    assert time.perf_counter() - began < 0.5


def test_recycling_after_n_requests_swaps_without_a_gray_gap(made: Any) -> None:
    spawner = Spawner()
    helper = ready_helper(made, spawner, recycle_after_requests=3)
    for _ in range(3):
        assert helper.request("ls", budget_s=1)[1] == ()
    deadline = time.time() + 3
    while helper.status()["restarts"] == 0 and time.time() < deadline:
        # the old child keeps serving while its replacement starts: never gray
        assert helper.request("ls", budget_s=1)[1] == ()
        time.sleep(0.01)
    assert helper.status()["restarts"] == 1
    assert spawner.calls == 2
    assert spawner.procs[0].killed.is_set()
    assert not spawner.procs[1].killed.is_set()
    assert helper.status()["pid"] == spawner.procs[1].pid


def test_recycling_after_age(made: Any, clock: OffsetClock) -> None:
    spawner = Spawner()
    helper = ready_helper(made, spawner, clock=clock, recycle_after_s=1800)
    assert helper.request("ls", budget_s=1)[1] == ()
    clock.advance(1801)
    assert helper.request("ls", budget_s=1)[1] == ()  # served by the old child, triggers the swap
    assert wait_until(lambda: helper.status()["restarts"] == 1)
    assert spawner.procs[0].killed.is_set()


def test_failed_replacement_keeps_the_old_child_serving(made: Any, clock: OffsetClock) -> None:
    spawner = Spawner(Script(), OSError("no more processes"))
    helper = ready_helper(made, spawner, clock=clock, recycle_after_requests=1)
    assert helper.request("ls", budget_s=1)[1] == ()
    assert wait_until(lambda: helper.status()["failures"] == 1)
    assert helper.request("ls", budget_s=1)[1] == ()
    assert not spawner.procs[0].killed.is_set()


def test_shutdown_kills_the_child_and_refuses_work(made: Any) -> None:
    spawner = Spawner()
    helper = ready_helper(made, spawner)
    helper.shutdown()
    helper.shutdown()  # idempotent
    assert spawner.procs[0].killed.is_set()
    assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_NOT_READY,))
    assert spawner.calls == 1
    helper.reset()
    assert helper.warm_up(wait_s=3)


def test_shutdown_kills_a_child_that_is_still_starting(made: Any) -> None:
    spawner = Spawner(Script(ready=None))
    helper = made(spawner, startup_timeout_s=30)
    helper.warm_up()
    assert wait_until(lambda: spawner.procs)
    time.sleep(0.05)
    helper.shutdown()
    assert spawner.procs[0].killed.is_set()
    assert helper.status()["failures"] == 0  # a stale start result is dropped, not counted


def test_start_that_finishes_after_shutdown_is_discarded(made: Any) -> None:
    spawner = Spawner(Script(ready=None))
    helper = made(spawner, startup_timeout_s=30)
    helper.warm_up()
    assert wait_until(lambda: spawner.procs)
    helper.shutdown()
    spawner.procs[0].out.feed(READY)  # too late: killed already
    time.sleep(0.2)
    assert helper.status()["state"] == "warming"
    assert helper.status()["pid"] is None


def test_request_never_raises_even_if_the_manager_breaks(
    made: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = made(Spawner())

    def explode(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(helper, "_gate", explode)
    assert helper.request("ls") == (None, (psparse.REASON_INTERNAL,))


def test_spawn_that_cannot_start_a_thread_is_a_start_failure(
    made: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = made(Spawner())

    class Broken(threading.Thread):
        def start(self) -> None:
            raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading, "Thread", Broken)
    helper.warm_up()
    assert helper.status()["failures"] == 1


# --------------------------------------------------------------------------------------------
# The module-level API and parse_powershell
# --------------------------------------------------------------------------------------------


@pytest.fixture
def shared() -> Any:
    """Point the module-level API at a fake child; restore a pristine helper afterwards."""
    spawner = Spawner()
    psparse.configure(spawner, startup_timeout_s=2.0)
    yield spawner
    psparse.configure()
    psparse.shutdown()


def test_module_level_api(shared: Spawner) -> None:
    assert psparse.status()["state"] == "warming"
    assert psparse.warm_up(wait_s=3) is True
    assert psparse.status()["state"] == "ready"
    reply, gray = psparse.helper_parse("Get-ChildItem", budget_s=2)
    assert gray == ()
    assert reply is not None
    psparse.shutdown()
    assert psparse.helper_parse("Get-ChildItem") == (None, (psparse.REASON_NOT_READY,))
    psparse.reset()
    assert psparse.warm_up(wait_s=3) is True


def test_shutdown_without_a_helper_is_a_noop() -> None:
    saved = psparse._default
    psparse._default = None
    try:
        psparse.shutdown()
    finally:
        psparse._default = saved


def test_helper_parse_never_raises(shared: Spawner, monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(psparse, "_helper", explode)
    assert psparse.helper_parse("ls") == (None, (psparse.REASON_INTERNAL,))
    assert psparse.parse_powershell("ls").gray == (psparse.REASON_INTERNAL,)


def test_parse_powershell_failure_is_a_gray_bashresult(shared: Spawner) -> None:
    psparse.configure(Spawner(Script(ready=None)), startup_timeout_s=5.0)
    result = psparse.parse_powershell("Get-ChildItem", budget_s=0.1)  # helper not ready yet
    assert isinstance(result, BashResult)
    assert result.commands == ()
    assert result.gray == (psparse.REASON_NOT_READY,)
    assert result.exec_reasons == ()


class _FakePscmd:
    def __init__(self, build: Callable[..., Any]) -> None:
        self.build = build


def test_parse_powershell_hands_the_reply_to_pscmd(
    shared: Spawner, monkeypatch: pytest.MonkeyPatch
) -> None:
    psparse.warm_up(wait_s=3)
    seen: dict[str, Any] = {}

    def build(reply: dict[str, Any], *, source: str) -> BashResult:
        seen["reply"], seen["source"] = reply, source
        return BashResult(commands=(SimpleCmd(argv=(Word("Get-ChildItem"),)),))

    monkeypatch.setitem(sys.modules, "boundkeep.normalize.pscmd", _FakePscmd(build))
    result = psparse.parse_powershell("Get-ChildItem x", budget_s=2)
    assert result.gray == ()
    assert result.commands[0].argv[0].text == "Get-ChildItem"
    assert seen["source"] == "Get-ChildItem x"
    assert seen["reply"]["ok"] is True


def test_parse_powershell_without_pscmd_is_gray(
    shared: Spawner, monkeypatch: pytest.MonkeyPatch
) -> None:
    psparse.warm_up(wait_s=3)
    monkeypatch.setitem(sys.modules, "boundkeep.normalize.pscmd", None)  # import fails
    result = psparse.parse_powershell("ls", budget_s=2)
    assert result == BashResult(commands=(), gray=(psparse.REASON_PSCMD_MISSING,))


def test_parse_powershell_with_a_broken_dependency_is_an_internal_error(
    shared: Spawner, monkeypatch: pytest.MonkeyPatch
) -> None:
    psparse.warm_up(wait_s=3)

    def import_module(name: str) -> Any:
        raise ModuleNotFoundError("No module named 'somethingelse'", name="somethingelse")

    fake_importlib = types.SimpleNamespace(import_module=import_module)
    monkeypatch.setattr(psparse, "importlib", fake_importlib)
    assert psparse.parse_powershell("ls", budget_s=2).gray == (psparse.REASON_INTERNAL,)

    def import_module_other(name: str) -> Any:
        raise SyntaxError("pscmd is broken")

    monkeypatch.setattr(
        psparse, "importlib", types.SimpleNamespace(import_module=import_module_other)
    )
    assert psparse.parse_powershell("ls", budget_s=2).gray == (psparse.REASON_INTERNAL,)


def _build_raises(reply: dict[str, Any], *, source: str) -> BashResult:
    raise ValueError("boom")


def _build_wrong_type(reply: dict[str, Any], *, source: str) -> Any:
    return {"not": "a BashResult"}


@pytest.mark.parametrize("build", [_build_raises, _build_wrong_type], ids=["raises", "wrong-type"])
def test_parse_powershell_survives_a_bad_pscmd(
    shared: Spawner, monkeypatch: pytest.MonkeyPatch, build: Callable[..., Any]
) -> None:
    psparse.warm_up(wait_s=3)
    monkeypatch.setitem(sys.modules, "boundkeep.normalize.pscmd", _FakePscmd(build))
    assert psparse.parse_powershell("ls", budget_s=2).gray == (psparse.REASON_INTERNAL,)


# --------------------------------------------------------------------------------------------
# Environment, executable and script lookup
# --------------------------------------------------------------------------------------------


def test_minimal_env_is_an_allow_list() -> None:
    source = {
        "SystemRoot": r"C:\Windows",
        "SYSTEMDRIVE": "C:",
        "windir": r"C:\Windows",
        "Path": r"C:\Windows\System32",
        "TEMP": r"C:\t",
        "TMP": r"C:\t",
        "USERPROFILE": r"C:\Users\x",
        "FAKE_SECRET_TOKEN": "s3cr3t",
        "ANTHROPIC_API_KEY": "k",
        "CLAUDE_CODE_X": "1",
        "PSModulePath": "somewhere",
        "HOME": "/home/x",
        "LANG": "C",
    }
    env = psparse.minimal_env(source)
    if sys.platform == "win32":
        assert set(env) == {
            "SystemRoot",
            "SystemDrive",
            "windir",
            "PATH",
            "TEMP",
            "TMP",
            "USERPROFILE",
        }
        assert env["PATH"] == r"C:\Windows\System32"  # found despite the case of the key
    else:
        assert set(env) <= {"PATH", "HOME", "TMPDIR", "LANG"}
    assert not any(
        word in key.upper()
        for key in env
        for word in ("TOKEN", "KEY", "SECRET", "CLAUDE", "ANTHROPIC")
    )
    assert psparse.minimal_env(source, {"EXTRA": "1"})["EXTRA"] == "1"
    assert psparse.minimal_env({}) == {}


def _exe_name() -> str:
    return "pwsh.exe" if sys.platform == "win32" else "pwsh"


@pytest.mark.skipif(sys.platform == "win32", reason="PATH is searched only off Windows")
def test_find_powershell_off_windows_uses_an_absolute_path_entry(tmp_path: Path) -> None:
    fake = tmp_path / "pwsh"
    fake.write_bytes(b"")
    env = {"PATH": os.pathsep.join(["relative", "", str(tmp_path)])}
    assert psparse.find_powershell(env) == str(fake)


def test_find_powershell_ignores_relative_path_entries(tmp_path: Path, monkeypatch: Any) -> None:
    (tmp_path / _exe_name()).write_bytes(b"")
    monkeypatch.chdir(tmp_path)  # a planted pwsh in the current directory must never win
    env = {"PATH": os.pathsep.join([".", "bin"]), "SystemRoot": str(tmp_path / "nowhere")}
    with pytest.raises(FileNotFoundError):
        psparse.find_powershell(env)


def test_find_powershell_falls_back_to_system32_windows_powershell(tmp_path: Path) -> None:
    exe = tmp_path / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"")
    env = {"PATH": "", "SYSTEMROOT": str(tmp_path)}
    if sys.platform == "win32":
        assert psparse.find_powershell(env) == str(exe)
    else:
        with pytest.raises(FileNotFoundError):
            psparse.find_powershell(env)


def test_find_powershell_without_any_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        psparse.find_powershell({"PATH": str(tmp_path), "SystemRoot": str(tmp_path)})


def test_script_path_points_at_the_packaged_helper() -> None:
    assert Path(psparse.script_path()).samefile(HELPER_SCRIPT)


def test_script_path_falls_back_to_the_source_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(package: str) -> Any:
        raise ModuleNotFoundError(package)

    monkeypatch.setattr(psparse.importlib.resources, "files", broken)
    assert Path(psparse.script_path()).samefile(HELPER_SCRIPT)


def test_script_path_raises_when_the_script_is_gone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(psparse, "__file__", str(tmp_path / "psparse.py"))
    monkeypatch.setattr(
        psparse.importlib.resources, "files", lambda package: tmp_path / "nothing-here"
    )
    with pytest.raises(FileNotFoundError):
        psparse.script_path()


def test_default_spawn_arguments(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The command line, environment and flags of the real spawn (Popen is replaced)."""
    captured: dict[str, Any] = {}

    class FakePopen:
        pid = 4242

        def __init__(self, args: list[str], **kwargs: Any) -> None:
            captured["args"], captured["kwargs"] = args, kwargs

    monkeypatch.setattr(psparse.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(psparse, "find_powershell", lambda: str(tmp_path / "pwsh.exe"))
    monkeypatch.setattr(psparse, "_assign_to_job", lambda pid: True)
    monkeypatch.setenv("FAKE_SECRET_TOKEN", "s3cr3t")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "key")
    proc = psparse.default_spawn({"X_TEST": "1"})
    assert proc.pid == 4242
    args = captured["args"]
    assert args[0] == str(tmp_path / "pwsh.exe")
    assert {"-NoProfile", "-NonInteractive", "-File"} <= set(args)
    assert args[args.index("-ExecutionPolicy") + 1] == "Bypass"
    assert Path(args[args.index("-File") + 1]).name == "pshelper.ps1"
    kwargs = captured["kwargs"]
    assert "FAKE_SECRET_TOKEN" not in kwargs["env"]
    assert "ANTHROPIC_API_KEY" not in kwargs["env"]
    assert kwargs["env"]["X_TEST"] == "1"
    assert kwargs["stdin"] == subprocess.PIPE
    assert kwargs["stdout"] == subprocess.PIPE
    assert kwargs["stderr"] == subprocess.DEVNULL
    assert kwargs.get("shell", False) is False
    if sys.platform == "win32":
        assert kwargs["creationflags"] == 0x08000000  # CREATE_NO_WINDOW
    assert os.path.isdir(kwargs["cwd"])


# --------------------------------------------------------------------------------------------
# The script itself: static hygiene (any platform)
# --------------------------------------------------------------------------------------------


def _script_code() -> str:
    lines = HELPER_SCRIPT.read_text(encoding="utf-8").splitlines()
    return "\n".join(line for line in lines if not line.lstrip().startswith("#"))


def test_helper_script_is_plain_ascii_without_bom() -> None:
    raw = HELPER_SCRIPT.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert all(byte < 128 for byte in raw)


@pytest.mark.parametrize(
    "pattern",
    [
        r"Invoke-Expression",
        r"\biex\b",
        r"Add-Type",
        r"New-Object",
        r"Invoke-Command",
        r"Start-Process",
        r"\bicm\b",
        r"(?:^|[;{(|=])\s*&\s*[$({\"']",  # the call operator
        r"^\s*\.\s+[$.\"'\w]",  # dot-sourcing
        r"\bImport-Module\b",
        r"\bGetType\b",
        r"System\.Reflection",
        r"\[(?:System\.)?Activator\]",
        r"\.Invoke\(",
        r"\bInvokeScript\b",
        r"\bCreateScriptBlock\b",
        r"\bAddScript\b",
        r"ExecutionContext\.InvokeCommand",
        r"\bSet-Alias\b",
        r"\bWrite-Host\b",
        r"\bWrite-Output\b",
        r"\bOut-Host\b",
    ],
)
def test_helper_script_has_no_dangerous_constructs(pattern: str) -> None:
    assert not re.search(pattern, _script_code(), flags=re.IGNORECASE | re.MULTILINE), pattern


def test_helper_script_never_evaluates_request_text() -> None:
    """The only way the command text is consumed is ParseInput."""
    code = _script_code()
    assert code.count("ParseInput(") == 2  # one self-test of a constant, one for the request
    assert "[Parser]::ParseInput($text," in code


# --------------------------------------------------------------------------------------------
# The fixtures other modules consume (any platform)
# --------------------------------------------------------------------------------------------

REQUIRED_FIXTURE_COMMANDS = [
    "Get-ChildItem",
    "ls -r",
    "rm -rf x",
    r"Remove-Item -Recurse -Force C:\x",
    "& ('i'+'ex') 'whoami'",
    "iex 'whoami'",
    "ls && pwd",
    r"Remove-Item -Recurse -Force C:\ ".strip(),
    r"Get-Content ~\.ssh\id_rsa",
    "curl https://github.com/x".replace("github.com/x", "github.com.evil.com/x"),
    r"Set-Content $env:USERPROFILE\.bashrc x",
    'Write-Output "你好 ✓"',
]


def test_fixture_index_is_complete_and_consistent() -> None:
    index = json.loads((FIXTURES / "index.json").read_text(encoding="utf-8"))
    assert len(index) >= 64
    for command in REQUIRED_FIXTURE_COMMANDS:
        assert command in index, command
    for command, name in index.items():
        reply = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        assert reply["ok"] is True
        assert "id" not in reply
        assert isinstance(reply["commands"], list)
        assert isinstance(reply["parse_errors"], list)
        assert set(reply) == {"ok", "parse_errors", "commands", "compound", "dynamic", "mode"}
        for item in reply["commands"]:
            assert set(item) == {
                "pos",
                "invoke",
                "name",
                "elements",
                "redirects",
                "stage",
                "nested",
            }, command
            start, end = item["pos"]
            assert 0 <= start <= end <= len(command), command
    assert len(set(index.values())) == len(index)


# --------------------------------------------------------------------------------------------
# The real helper (Windows PowerShell 5.1 or pwsh)
# --------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def real() -> Any:
    helper = psparse.PsHelper(startup_timeout_s=60)
    if not helper.warm_up(wait_s=60):
        helper.shutdown()
        pytest.skip(f"no usable PowerShell helper: {helper.status()}")
    yield helper
    helper.shutdown()


def _parse(helper: psparse.PsHelper, text: str) -> dict[str, Any]:
    reply, gray = helper.request(text, budget_s=10)
    assert gray == (), (text, gray)
    assert reply is not None
    return reply


def _cmds(reply: dict[str, Any]) -> list[dict[str, Any]]:
    return list(reply["commands"])


@pytest.mark.windows
class TestRealHelper:
    def test_ready_state(self, real: psparse.PsHelper) -> None:
        state = real.status()
        assert state["state"] == "ready"
        assert state["mode"] == "FullLanguage"
        assert re.fullmatch(r"\d+\.\d+.*", state["version"])
        assert state["warmup_ms"] > 0

    def test_simple_command(self, real: psparse.PsHelper) -> None:
        reply = _parse(real, r"Remove-Item -Recurse -Force C:\x")
        (cmd,) = _cmds(reply)
        assert cmd["name"] == {"kind": "bare", "v": "Remove-Item"}
        assert cmd["elements"] == [
            {"t": "param", "name": "Recurse", "arg": None},
            {"t": "param", "name": "Force", "arg": None},
            {"t": "str", "kind": "bare", "v": "C:\\x"},
        ]
        assert cmd["pos"] == [0, 32]
        assert cmd["stage"] == {"index": 0, "of": 1}
        assert cmd["nested"] is False
        assert cmd["invoke"] == ""
        assert reply["parse_errors"] == []
        assert reply["compound"] == []
        assert reply["dynamic"] == []
        assert reply["mode"] == "FullLanguage"

    def test_bashism_is_just_a_parameter(self, real: psparse.PsHelper) -> None:
        (cmd,) = _cmds(_parse(real, "rm -rf x"))
        assert cmd["name"]["v"] == "rm"
        assert cmd["elements"][0] == {"t": "param", "name": "rf", "arg": None}

    def test_chinese_and_check_mark_round_trip(self, real: psparse.PsHelper) -> None:
        text = 'Write-Output "你好 ✓ $env:USERPROFILE"'
        (cmd,) = _cmds(_parse(real, text))
        assert cmd["elements"] == [
            {
                "t": "expstr",
                "v": "你好 ✓ $env:USERPROFILE",
                "vars": ["env:USERPROFILE"],
                "subexpr": False,
            }
        ]
        (path,) = _cmds(_parse(real, r"Get-Content C:\用户\说明✓.txt"))
        assert path["elements"][0]["v"] == "C:\\用户\\说明✓.txt"

    def test_astral_characters_and_offsets(self, real: psparse.PsHelper) -> None:
        text = "echo '😀'; rm 😀.txt"
        reply = _parse(real, text)
        first, second = _cmds(reply)
        assert first["elements"][0]["v"] == "😀"
        assert text[second["pos"][0] : second["pos"][1]] == "rm 😀.txt"

    def test_obfuscated_invocation_is_dynamic(self, real: psparse.PsHelper) -> None:
        reply = _parse(real, "& ('i'+'ex') 'whoami'")
        (cmd,) = _cmds(reply)
        assert cmd["invoke"] == "&"
        assert cmd["name"]["kind"] == "expr"
        assert "BinaryExpressionAst" in reply["dynamic"]

    def test_backtick_escapes_and_continuation(self, real: psparse.PsHelper) -> None:
        (cmd,) = _cmds(_parse(real, 'Write-Output `"hi`" a` b `\n -Force'))
        assert cmd["elements"][0] == {"t": "str", "kind": "bare", "v": '"hi"'}
        assert cmd["elements"][1] == {"t": "str", "kind": "bare", "v": "a b"}
        assert cmd["elements"][2]["name"] == "Force"

    def test_here_strings(self, real: psparse.PsHelper) -> None:
        reply = _parse(real, "Set-Content a.txt @'\nraw $x\n'@; Set-Content b.txt @\"\nv $x\n\"@")
        first, second = _cmds(reply)
        assert first["elements"][1] == {"t": "str", "kind": "singlehere", "v": "raw $x"}
        assert second["elements"][1]["t"] == "expstr"
        assert second["elements"][1]["vars"] == ["x"]

    def test_subexpression_nested_commands_come_out_in_source_order(
        self, real: psparse.PsHelper
    ) -> None:
        reply = _parse(real, "Remove-Item $(Join-Path $env:TEMP 'x'); ls")
        outer, inner, last = _cmds(reply)
        assert [outer["nested"], inner["nested"], last["nested"]] == [False, True, False]
        assert inner["name"]["v"] == "Join-Path"
        assert outer["elements"][0]["t"] == "other"
        assert outer["elements"][0]["ast"] == "SubExpressionAst"
        assert "SubExpressionAst" in reply["dynamic"]
        starts = [c["pos"][0] for c in _cmds(reply)]
        assert starts == sorted(starts)

    def test_expandable_string_with_subexpression(self, real: psparse.PsHelper) -> None:
        reply = _parse(real, 'Write-Output "now: $(Get-Date)"')
        first, inner = _cmds(reply)
        assert first["elements"][0]["subexpr"] is True
        assert inner["nested"] is True

    def test_nested_script_blocks(self, real: psparse.PsHelper) -> None:
        reply = _parse(
            real, "ls | ForEach-Object { if ($_) { Remove-Item $_ } else { echo { rm x } } }"
        )
        names = [c["name"]["v"] for c in _cmds(reply)]
        assert names == ["ls", "ForEach-Object", "Remove-Item", "echo", "rm"]
        assert [c["nested"] for c in _cmds(reply)] == [False, False, True, True, True]
        assert "IfStatementAst" in reply["compound"]
        assert "ScriptBlockExpressionAst" in reply["dynamic"]
        assert _cmds(reply)[0]["stage"] == {"index": 0, "of": 2}
        assert _cmds(reply)[1]["stage"] == {"index": 1, "of": 2}

    def test_pipeline_stages_and_redirects(self, real: psparse.PsHelper) -> None:
        reply = _parse(real, "git status 2>&1 | Out-File x.txt; ls > a.txt 2>> b.txt *> $null")
        git, out, ls = _cmds(reply)
        assert git["redirects"] == [{"op": ">&", "target": None, "merge": "2>&1"}]
        assert [git["stage"]["index"], out["stage"]["index"], out["stage"]["of"]] == [0, 1, 2]
        # PowerShell hands the redirections over ordered by stream, not by position in the text.
        by_op = {r["op"]: r for r in ls["redirects"]}
        assert set(by_op) == {">", "2>>", "*>"}
        assert by_op[">"]["target"] == {"t": "str", "kind": "bare", "v": "a.txt"}
        assert by_op["2>>"]["target"] == {"t": "str", "kind": "bare", "v": "b.txt"}
        assert by_op["*>"]["target"] == {"t": "var", "name": "null", "splat": False}

    def test_parameter_arguments_variables_arrays_numbers(self, real: psparse.PsHelper) -> None:
        (cmd,) = _cmds(_parse(real, "foo -Path:$env:TEMP -Count 5 a,b @args ${env:HOME}"))
        assert cmd["elements"] == [
            {"t": "param", "name": "Path", "arg": {"t": "var", "name": "env:TEMP", "splat": False}},
            {"t": "param", "name": "Count", "arg": None},
            {"t": "num", "v": "5"},
            {
                "t": "array",
                "items": [
                    {"t": "str", "kind": "bare", "v": "a"},
                    {"t": "str", "kind": "bare", "v": "b"},
                ],
            },
            {"t": "var", "name": "args", "splat": True},
            {"t": "var", "name": "env:HOME", "splat": False},
        ]

    def test_invocation_operators(self, real: psparse.PsHelper) -> None:
        amp, dot = _cmds(_parse(real, "& 'C:\\a b\\x.exe' 1; . .\\setup.ps1"))
        assert amp["invoke"] == "&"
        assert amp["name"] == {"kind": "single", "v": "C:\\a b\\x.exe"}
        assert dot["invoke"] == "."
        assert dot["name"]["v"] == ".\\setup.ps1"

    def test_compound_statements_keep_their_inner_commands(self, real: psparse.PsHelper) -> None:
        reply = _parse(real, "$x = Get-Content a; try { rm $x } catch { } ; function f { ls }")
        assert {"AssignmentStatementAst", "TryStatementAst", "FunctionDefinitionAst"} <= set(
            reply["compound"]
        )
        assert [c["name"]["v"] for c in _cmds(reply)] == ["Get-Content", "rm", "ls"]
        assert all(c["nested"] for c in _cmds(reply))

    def test_and_and_is_a_parse_error_on_windows_powershell(self, real: psparse.PsHelper) -> None:
        if real.status()["version"].split(".")[0] != "5":
            pytest.skip("only Windows PowerShell 5.1 rejects &&")
        reply = _parse(real, "ls && pwd")
        assert reply["parse_errors"], reply
        assert {"msg", "line", "col"} == set(reply["parse_errors"][0])
        assert [c["name"]["v"] for c in _cmds(reply)] == ["ls", "pwd"]

    def test_unterminated_input_reports_errors_not_exceptions(self, real: psparse.PsHelper) -> None:
        for text in ["echo 'x", 'echo "x', "Get-Content (", "}", "@'\nx", "ls |"]:
            assert _parse(real, text)["parse_errors"], text

    def test_empty_and_comment_only(self, real: psparse.PsHelper) -> None:
        for text in ["", "   ", "# nothing", "<# block #>"]:
            reply = _parse(real, text)
            assert reply["commands"] == []
            assert reply["parse_errors"] == []

    def test_nul_and_odd_characters(self, real: psparse.PsHelper) -> None:
        reply = _parse(real, "echo a\x00b \u2018x\u2019 \ufeff \u2028")
        assert reply["ok"] is True

    def test_provider_paths_are_plain_strings(self, real: psparse.PsHelper) -> None:
        (cmd,) = _cmds(_parse(real, r"Get-ItemProperty HKLM:\Software\x"))
        assert cmd["elements"][0] == {"t": "str", "kind": "bare", "v": "HKLM:\\Software\\x"}

    def test_deep_nesting_is_an_error_reply_and_the_helper_lives_on(
        self, real: psparse.PsHelper
    ) -> None:
        for text in ["(" * 20000, "{" * 5000, "$(" * 3000 + ")" * 3000]:
            reply, gray = real.request(text, budget_s=10)
            assert reply is not None or gray in {
                (psparse.REASON_HELPER_ERROR,),
                (psparse.REASON_TOO_LARGE,),
            }
        assert real.status()["state"] == "ready"
        assert real.status()["failures"] == 0
        assert _parse(real, "ls")["commands"]

    def test_too_many_commands_is_too_large_not_a_hang(self, real: psparse.PsHelper) -> None:
        reply, gray = real.request("a;" * 6000, budget_s=20)
        assert reply is None
        assert gray == (psparse.REASON_TOO_LARGE,)
        assert real.status()["state"] == "ready"

    def test_one_mebibyte_of_text(self, real: psparse.PsHelper) -> None:
        text = "echo '" + "x" * (psparse.MAX_REQUEST_BYTES - 7) + "'"
        assert len(text.encode()) == psparse.MAX_REQUEST_BYTES
        began = time.perf_counter()
        reply = _parse(real, text)
        assert time.perf_counter() - began < 10
        (cmd,) = _cmds(reply)
        assert cmd["elements"][0]["ast"] == "TooLongString"  # strings over 32 KiB are not copied
        assert len(json.dumps(reply)) < 4 << 20
        over = text + "x"
        assert real.request(over, budget_s=10) == (None, (psparse.REASON_TOO_LARGE,))

    def test_long_ordinary_input_in_one_request(self, real: psparse.PsHelper) -> None:
        text = "; ".join(f"Get-Item 'file{i}.txt'" for i in range(300))
        reply = _parse(real, text)
        assert len(_cmds(reply)) == 300

    def test_reply_is_ascii_json_even_for_astral_text(self, real: psparse.PsHelper) -> None:
        reply = _parse(real, "echo 😀 你好")
        assert json.dumps(reply)  # serializable; the stdout line itself was pure ASCII

    def test_timing_of_typical_commands(self, real: psparse.PsHelper) -> None:
        commands = [
            "Get-ChildItem",
            "ls -r",
            "rm -rf x",
            r"Remove-Item -Recurse -Force C:\x",
            r"Get-Content ~\.ssh\id_rsa",
            "curl https://example.com/x -o y",
            "git status",
            "ls | Select-Object -First 3",
            "$x = 1",
            'Write-Output "你好 ✓"',
        ]
        samples = []
        for _ in range(5):
            for command in commands:
                began = time.perf_counter()
                _parse(real, command)
                samples.append(time.perf_counter() - began)
        samples.sort()
        assert samples[len(samples) // 2] < 0.1  # generous: ~3 ms on the development machine

    def test_fixtures_match_the_live_helper(self, real: psparse.PsHelper) -> None:
        index = json.loads((FIXTURES / "index.json").read_text(encoding="utf-8"))
        assert index
        for command, name in index.items():
            stored = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
            live = _parse(real, command)
            for key in ("commands", "compound", "dynamic"):
                assert live[key] == stored[key], (command, key)
            assert [(e["line"], e["col"]) for e in live["parse_errors"]] == [
                (e["line"], e["col"]) for e in stored["parse_errors"]
            ], command

    @settings(
        max_examples=60,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    @given(
        st.one_of(
            st.text(max_size=300),
            st.lists(
                st.sampled_from(
                    [
                        "(",
                        ")",
                        "{",
                        "}",
                        "[",
                        "]",
                        "$",
                        "'",
                        '"',
                        "`",
                        "|",
                        ";",
                        "@",
                        "<#",
                        "#>",
                        "&&",
                        "&",
                        ">",
                        "2>&1",
                        "-x",
                        " ",
                        "a",
                        "\n",
                        "$(",
                        "@'",
                        "'@",
                        "@(",
                        ":",
                        "::",
                        "--%",
                        ".",
                        ",",
                        "$_",
                        "\\",
                        "C:\\",
                        "\u4e2d",
                        "\U0001f600",
                    ]
                ),
                max_size=60,
            ).map("".join),
        )
    )
    def test_arbitrary_text_never_breaks_the_helper(
        self, real: psparse.PsHelper, text: str
    ) -> None:
        reply, gray = real.request(text, budget_s=10)
        if reply is None:
            assert gray in {
                (psparse.REASON_HELPER_ERROR,),
                (psparse.REASON_TOO_LARGE,),
                (psparse.REASON_BAD_TEXT,),
            }, gray
        else:
            assert reply["ok"] is True
            assert len(json.dumps(reply)) < 4 << 20
            for command in reply["commands"]:
                start, end = command["pos"]
                assert 0 <= start <= end <= len(text)
        assert real.status()["state"] == "ready"
        assert real.status()["failures"] == 0

    def test_hard_timeout_recovers(self) -> None:
        helper = psparse.PsHelper(startup_timeout_s=60)
        try:
            assert helper.warm_up(wait_s=60)
            began = time.perf_counter()
            reply, gray = helper.request("a;" * 524_288, budget_s=0.3)  # needs ~10 s
            elapsed = time.perf_counter() - began
            assert reply is None
            assert gray == (psparse.REASON_TIMEOUT,)
            assert elapsed < 0.3 + 0.5
            assert helper.status()["failures"] == 0  # big input: not the helper's fault
            assert helper.warm_up(wait_s=60)
            assert _parse(helper, "ls")["commands"]
        finally:
            helper.shutdown()


def _pid_alive(pid: int) -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return False
    try:
        code = ctypes.c_uint32()
        kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        return code.value == 259  # STILL_ACTIVE
    finally:
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle(handle)


def _wait_dead(pid: int, seconds: float = 10.0) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.05)
    return False


@pytest.mark.windows
class TestRealProcessManagement:
    def test_shutdown_kills_the_child(self) -> None:
        helper = psparse.PsHelper(startup_timeout_s=60)
        assert helper.warm_up(wait_s=60)
        pid = helper.status()["pid"]
        assert _pid_alive(pid)
        helper.shutdown()
        assert _wait_dead(pid)

    def test_child_dies_with_a_daemon_that_is_killed_hard(self, tmp_path: Path) -> None:
        """Job Object with KILL_ON_JOB_CLOSE: no atexit, no shutdown, the child still goes."""
        code = (
            "import os\n"
            "from boundkeep.normalize import psparse\n"
            "h = psparse.PsHelper(startup_timeout_s=60)\n"
            "assert h.warm_up(wait_s=60), h.status()\n"
            "print(h.status()['pid'], h.status()['job_object'], flush=True)\n"
            "os._exit(0)\n"
        )
        env = dict(os.environ, PYTHONPATH=str(REPO / "src"))
        done = subprocess.run(
            [sys.executable, "-c", code],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert done.returncode == 0, done.stderr
        pid_text, job_text = done.stdout.split()
        assert job_text == "True"
        assert _wait_dead(int(pid_text))

    def test_the_child_environment_has_no_secrets(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FAKE_SECRET_TOKEN", "s3cr3t")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "key")
        monkeypatch.setenv("CLAUDE_CODE_SOMETHING", "1")
        exe = psparse.find_powershell()
        done = subprocess.run(
            [
                exe,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-ChildItem Env: | ForEach-Object { $_.Name }",
            ],
            env=psparse.minimal_env(os.environ),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        names = {line.strip().upper() for line in done.stdout.splitlines()}
        assert "SYSTEMROOT" in names
        assert "PATH" in names
        assert not {"FAKE_SECRET_TOKEN", "ANTHROPIC_API_KEY", "CLAUDE_CODE_SOMETHING"} & names

    def test_constrained_language_mode_makes_the_helper_unavailable(self) -> None:
        """A real constrained-language session runs the helper script: it must say so and stop."""

        def spawn_constrained() -> subprocess.Popen[bytes]:
            command = (
                "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; & '"
                + psparse.script_path()
                + "'"
            )
            return subprocess.Popen(
                [
                    psparse.find_powershell(),
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    command,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=psparse.minimal_env(os.environ),
                creationflags=0x08000000,
            )

        helper = psparse.PsHelper(spawn_constrained, startup_timeout_s=60)
        try:
            helper.warm_up(wait_s=60)
            state = helper.status()
            assert state["state"] == "unavailable", state
            assert state["mode"] == "ConstrainedLanguage"
            assert state["failures"] == 0
            assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_UNAVAILABLE,))
        finally:
            helper.shutdown()

    def test_parse_powershell_end_to_end_with_a_stub_pscmd(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        helper = psparse.PsHelper(startup_timeout_s=60)
        monkeypatch.setattr(psparse, "_default", helper)
        try:
            assert helper.warm_up(wait_s=60)

            def build(reply: dict[str, Any], *, source: str) -> BashResult:
                names = tuple(Word(c["name"]["v"]) for c in reply["commands"])
                return BashResult(commands=(SimpleCmd(argv=names),))

            monkeypatch.setitem(sys.modules, "boundkeep.normalize.pscmd", _FakePscmd(build))
            result = psparse.parse_powershell("ls | sort", budget_s=5)
            assert result.gray == ()
            assert [w.text for w in result.commands[0].argv] == ["ls", "sort"]
        finally:
            helper.shutdown()
