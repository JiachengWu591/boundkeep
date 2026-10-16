"""Regressions for the M1b review findings about the PowerShell helper manager.

Fake children only (no PowerShell needed) except the tests marked ``windows``.
"""

from __future__ import annotations

import hashlib
import sys
import threading
import time
import types
from pathlib import Path
from typing import Any

import pytest

from boundkeep import doctor
from boundkeep.daemon import server
from boundkeep.normalize import psparse
from tests.unit.test_norm_psparse import (
    FakeProc,
    OffsetClock,
    Script,
    Spawner,
    crash,
    hang,
    ok_reply,
    ready_helper,
    send,
    wait_until,
)

BIG = psparse.SLOW_INPUT_BYTES + 100


def _big(tag: str, size: int = BIG) -> str:
    return (tag + ";") * (size // (len(tag) + 1) + 1)


@pytest.fixture
def clock() -> OffsetClock:
    return OffsetClock()


@pytest.fixture
def made() -> Any:
    created: list[psparse.PsHelper] = []

    def make(spawner: Spawner, **kwargs: Any) -> psparse.PsHelper:
        kwargs.setdefault("startup_timeout_s", 2.0)
        helper = psparse.PsHelper(spawner, **kwargs)
        created.append(helper)
        return helper

    yield make
    for helper in created:
        helper.shutdown()


# --- 1. parse timeouts never open the breaker; half-open cool-down; unavailable retry ---


def test_small_timeouts_never_open_the_breaker(made: Any) -> None:
    helper = ready_helper(made, Spawner(Script(on_request=hang)))
    for _ in range(psparse.MAX_FAILURES + 3):
        assert helper.request("ls", budget_s=0.12) == (None, (psparse.REASON_TIMEOUT,))
        assert helper.warm_up(wait_s=3)
    state = helper.status()
    assert state["state"] == "ready"
    assert state["failures"] == 0
    assert state["timeouts"] == psparse.MAX_FAILURES + 3


def test_open_breaker_half_opens_after_the_cooldown_and_a_good_reply_closes_it(
    made: Any,
    clock: OffsetClock,
) -> None:
    spawner = Spawner(Script(on_request=crash))
    helper = ready_helper(made, spawner, clock=clock, breaker_cooldown_s=60)
    for _ in range(psparse.MAX_FAILURES):
        helper.request("ls", budget_s=1)
        clock.advance(31)
        helper.warm_up(wait_s=3)
    state = helper.status()
    assert state["state"] == "disabled"
    assert 0 < state["retry_in_s"] <= 60
    assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_DISABLED,))
    calls = spawner.calls
    clock.advance(5)  # still inside the cool-down
    assert helper.warm_up(wait_s=0.1) is False
    assert spawner.calls == calls
    clock.advance(40)
    spawner.set(Script())
    assert helper.warm_up(wait_s=3)  # the probe start
    assert helper.request("ls", budget_s=1)[1] == ()
    state = helper.status()
    assert state["state"] == "ready"
    assert state["failures"] == 0
    assert state["retry_in_s"] is None


def test_a_failed_probe_opens_the_breaker_again_for_a_new_cooldown(
    made: Any,
    clock: OffsetClock,
) -> None:
    spawner = Spawner(Script(on_request=crash))
    helper = ready_helper(made, spawner, clock=clock, breaker_cooldown_s=60)
    for _ in range(psparse.MAX_FAILURES):
        helper.request("ls", budget_s=1)
        clock.advance(31)
        helper.warm_up(wait_s=3)
    assert helper.status()["state"] == "disabled"
    clock.advance(61)
    assert helper.warm_up(wait_s=3)  # half-open probe starts (and says ready)
    assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_CRASHED,))
    state = helper.status()
    assert state["state"] == "disabled"
    assert state["retry_in_s"] > 30


def test_reset_clears_cooldown_state(made: Any, clock: OffsetClock) -> None:
    spawner = Spawner(Script(on_request=crash))
    helper = ready_helper(made, spawner, clock=clock, breaker_cooldown_s=1e9)
    for _ in range(psparse.MAX_FAILURES):
        helper.request("ls", budget_s=1)
        clock.advance(31)
        helper.warm_up(wait_s=3)
    assert helper.status()["state"] == "disabled"
    spawner.set(Script())
    helper.reset()
    assert helper.warm_up(wait_s=3)


def test_sticky_unavailable_is_retried_after_a_backoff(
    made: Any,
    clock: OffsetClock,
) -> None:
    spawner = Spawner(FileNotFoundError("no powershell"), Script())
    helper = made(spawner, clock=clock, unavailable_retry_s=30)
    helper.warm_up(wait_s=3)
    state = helper.status()
    assert state["state"] == "unavailable"
    assert 0 < state["retry_in_s"] <= 30
    assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_UNAVAILABLE,))
    assert spawner.calls == 1
    clock.advance(31)
    assert helper.warm_up(wait_s=3)  # PowerShell has appeared meanwhile
    assert helper.request("ls", budget_s=1)[1] == ()


def test_unavailable_retry_backs_off_exponentially(
    made: Any,
    clock: OffsetClock,
) -> None:
    spawner = Spawner(FileNotFoundError("x"))
    helper = made(spawner, clock=clock, unavailable_retry_s=10, unavailable_retry_max_s=25)
    seen = []
    for _ in range(4):
        helper.warm_up(wait_s=3)
        seen.append(round(helper.status()["retry_in_s"]))
        clock.advance(100)
    assert seen == [10, 20, 25, 25]


# --- 2. slow inputs cannot black the helper out ---


def _requests_seen(spawner: Spawner) -> int:
    return sum(len(proc.requests) for proc in spawner.procs)


def test_an_input_that_timed_out_is_answered_gray_without_touching_the_helper(
    made: Any,
) -> None:
    spawner = Spawner(Script(on_request=hang), Script())
    helper = ready_helper(made, spawner)
    text = _big("@")
    assert helper.request(text, budget_s=0.15) == (None, (psparse.REASON_TIMEOUT,))
    assert helper.warm_up(wait_s=3)
    seen, calls = _requests_seen(spawner), spawner.calls
    began = time.perf_counter()
    for _ in range(5):
        assert helper.request(text, budget_s=0.15) == (None, (psparse.REASON_TIMEOUT,))
    assert time.perf_counter() - began < 0.1
    assert _requests_seen(spawner) == seen  # never sent
    assert spawner.calls == calls  # no restart storm
    assert not spawner.procs[1].killed.is_set()


def test_throttle_blocks_other_big_inputs_but_not_small_ones(
    made: Any,
    clock: OffsetClock,
) -> None:
    spawner = Spawner(Script(on_request=hang), Script())
    helper = ready_helper(made, spawner, clock=clock)
    assert helper.request(_big("a"), budget_s=0.15) == (None, (psparse.REASON_TIMEOUT,))
    assert helper.warm_up(wait_s=3)
    other = _big("b")
    assert helper.request(other, budget_s=0.5) == (None, (psparse.REASON_THROTTLED,))
    assert helper.status()["throttled_s"] > 0
    assert _requests_seen(spawner) == 1  # only the first one ever reached a helper
    assert helper.request("ls", budget_s=1)[1] == ()  # small commands keep working
    clock.advance(psparse.THROTTLE_S + 1)
    assert helper.request(other, budget_s=1)[1] == ()  # window over


def test_repeated_kills_tighten_the_throttle_to_medium_inputs(
    made: Any,
    clock: OffsetClock,
) -> None:
    spawner = Spawner(Script(on_request=hang))
    helper = ready_helper(made, spawner, clock=clock)
    for index in range(psparse.THROTTLE_KILLS):
        assert helper.request(f"x{index}", budget_s=0.12) == (None, (psparse.REASON_TIMEOUT,))
        assert helper.warm_up(wait_s=3)
    medium = "m" * (psparse.THROTTLE_STRICT_BYTES + 5)
    assert helper.request(medium, budget_s=0.5) == (None, (psparse.REASON_THROTTLED,))
    assert helper.request("ls", budget_s=0.12) == (None, (psparse.REASON_TIMEOUT,))  # still sent


def test_timeout_cache_is_bounded_and_expires(
    made: Any,
    clock: OffsetClock,
) -> None:
    spawner = Spawner(Script(on_request=hang))
    helper = ready_helper(
        made, spawner, clock=clock, timeout_cache_size=2, timeout_cache_ttl_s=100, throttle_s=0
    )
    texts = [_big(tag) for tag in "abc"]
    for text in texts:
        assert helper.request(text, budget_s=0.12) == (None, (psparse.REASON_TIMEOUT,))
        assert helper.warm_up(wait_s=3)
    assert len(helper._slow_inputs) == 2
    assert hashlib.sha256(texts[0].encode()).digest() not in helper._slow_inputs  # LRU evicted
    sent = _requests_seen(spawner)
    assert helper.request(texts[2], budget_s=0.12) == (None, (psparse.REASON_TIMEOUT,))
    assert _requests_seen(spawner) == sent  # served from the cache
    clock.advance(101)
    assert helper.request(texts[2], budget_s=0.12) == (None, (psparse.REASON_TIMEOUT,))
    assert _requests_seen(spawner) == sent + 1  # expired: it went to the helper again


def test_tiny_inputs_are_never_cached(made: Any) -> None:
    spawner = Spawner(Script(on_request=hang))
    helper = ready_helper(made, spawner)
    helper.request("ls", budget_s=0.12)
    assert helper.warm_up(wait_s=3)
    assert len(helper._slow_inputs) == 0


# --- 3. a helper that dies while idle is restarted on its own ---


def test_idle_death_is_noticed_and_restarted_without_any_request(made: Any) -> None:
    spawner = Spawner()
    helper = ready_helper(made, spawner, backoff_initial_s=0.05)
    spawner.procs[0].kill()  # a crash while nobody is asking
    assert wait_until(lambda: spawner.calls == 2 and helper.status()["state"] == "ready", 5)
    assert helper.status()["failures"] == 1
    assert helper.request("ls", budget_s=1)[1] == ()


def test_deliberate_kills_are_not_idle_deaths(made: Any) -> None:
    spawner = Spawner(Script(on_request=hang), Script())
    helper = ready_helper(made, spawner, backoff_initial_s=0.05)
    helper.request("ls", budget_s=0.12)  # we killed it: timeout, not a crash
    assert helper.warm_up(wait_s=3)
    time.sleep(0.3)
    assert helper.status()["failures"] == 0
    assert spawner.calls == 2  # exactly one replacement


def test_a_crash_during_a_request_is_counted_once(made: Any) -> None:
    spawner = Spawner(Script(on_request=crash), Script())
    helper = ready_helper(made, spawner, backoff_initial_s=60)
    assert helper.request("ls", budget_s=1) == (None, (psparse.REASON_CRASHED,))
    time.sleep(0.2)
    assert helper.status()["failures"] == 1


# --- 4. queue wait does not kill a healthy helper ---


def test_queue_wait_that_eats_the_budget_is_busy_and_does_not_kill(made: Any) -> None:
    gate = threading.Event()
    entered = threading.Event()

    def slow(proc: FakeProc, request: dict[str, Any]) -> None:
        entered.set()
        gate.wait(5)
        send(proc, ok_reply(request))

    spawner = Spawner(Script(on_request=slow))
    helper = ready_helper(made, spawner)
    first: list[Any] = []
    thread = threading.Thread(target=lambda: first.append(helper.request("slow", budget_s=5)))
    thread.start()
    assert entered.wait(2)
    threading.Timer(0.27, gate.set).start()
    # The lock frees up after ~0.27 s, which leaves less than MIN_FLIGHT_S of the 0.35 s budget.
    result = helper.request("second", budget_s=0.35)
    thread.join(5)
    assert result == (None, (psparse.REASON_BUSY,))
    assert first[0][1] == ()
    assert spawner.calls == 1
    assert not spawner.procs[0].killed.is_set()
    assert len(spawner.procs[0].requests) == 1  # the second one was never sent
    assert helper.status()["failures"] == 0
    assert helper.request("ls", budget_s=1)[1] == ()  # and the helper still works


def test_a_request_really_in_flight_past_its_budget_still_kills(made: Any) -> None:
    spawner = Spawner(Script(on_request=hang), Script())
    helper = ready_helper(made, spawner)
    assert helper.request("ls", budget_s=0.2) == (None, (psparse.REASON_TIMEOUT,))
    assert spawner.procs[0].killed.is_set()


# --- 6. kill never waits in the request path ---


class _SlowToDie(FakeProc):
    def wait(self, timeout: float | None = None) -> int:
        time.sleep(0.6)
        return super().wait(timeout)


def test_timeout_does_not_wait_for_the_dying_child(made: Any) -> None:
    class SlowSpawner(Spawner):
        def __call__(self) -> FakeProc:
            script = self.scripts[min(self.calls, len(self.scripts) - 1)]
            self.calls += 1
            assert isinstance(script, Script)
            proc = _SlowToDie(script)
            self.procs.append(proc)
            return proc

    helper = ready_helper(made, SlowSpawner(Script(on_request=hang)))
    began = time.perf_counter()
    assert helper.request("ls", budget_s=0.2) == (None, (psparse.REASON_TIMEOUT,))
    assert time.perf_counter() - began < 0.2 + 0.25


# --- 7. the job object state is per child ---


def _job_spawner(assigned: object) -> Spawner:
    class JobSpawner(Spawner):
        def __call__(self) -> FakeProc:
            proc = super().__call__()
            if assigned is not None:
                proc.job_assigned = assigned  # type: ignore[attr-defined]
            return proc

    return JobSpawner()


def test_status_reports_whether_this_child_is_in_the_job(made: Any) -> None:
    good = ready_helper(made, _job_spawner(True))
    assert good.status()["job_object"] is True
    assert good.status()["job_degraded"] is False
    bad = ready_helper(made, _job_spawner(False))
    assert bad.status()["job_object"] is False
    assert bad.status()["job_degraded"] is (sys.platform == "win32")
    assert bad.request("ls", budget_s=1)[1] == ()  # degraded but allowed


def test_default_spawn_records_a_failed_job_assignment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FakePopen:
        pid = 1

        def __init__(self, args: list[str], **kwargs: Any) -> None:
            pass

    monkeypatch.setattr(psparse.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(psparse, "find_powershell", lambda: str(tmp_path / "pwsh.exe"))
    monkeypatch.setattr(psparse, "_assign_to_job", lambda pid: False)
    assert psparse.default_spawn().job_assigned is False  # type: ignore[attr-defined]

    def boom(pid: int) -> bool:
        raise OSError("no job")

    monkeypatch.setattr(psparse, "_assign_to_job", boom)
    assert psparse.default_spawn().job_assigned is False  # type: ignore[attr-defined]
    monkeypatch.setattr(psparse, "_assign_to_job", lambda pid: True)
    assert psparse.default_spawn().job_assigned is True  # type: ignore[attr-defined]


# --- 5. which PowerShell, which script ---


def _touch(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")
    return str(path)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows lookup rules")
class TestFindPowershellWindows:
    def test_a_pwsh_planted_on_path_is_never_used(self, tmp_path: Path) -> None:
        planted = _touch(tmp_path / "path_dir" / "pwsh.exe")
        system = _touch(
            tmp_path / "win" / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        )
        env = {
            "PATH": str(Path(planted).parent),
            "SystemRoot": str(tmp_path / "win"),
            "ProgramFiles": str(tmp_path / "pf"),
        }
        assert psparse.find_powershell(env) == system

    def test_pwsh_from_program_files_wins_over_windows_powershell(self, tmp_path: Path) -> None:
        _touch(tmp_path / "win" / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
        _touch(tmp_path / "pf" / "PowerShell" / "6" / "pwsh.exe")
        newest = _touch(tmp_path / "pf" / "PowerShell" / "7" / "pwsh.exe")
        _touch(tmp_path / "pf" / "PowerShell" / "8-preview" / "pwsh.exe")
        env = {"SystemRoot": str(tmp_path / "win"), "ProgramFiles": str(tmp_path / "pf")}
        assert psparse.find_powershell(env) == newest

    def test_only_a_planted_pwsh_means_not_found(self, tmp_path: Path) -> None:
        planted = _touch(tmp_path / "bin" / "pwsh.exe")
        env = {"PATH": str(Path(planted).parent), "SystemRoot": str(tmp_path / "nowhere")}
        with pytest.raises(FileNotFoundError):
            psparse.find_powershell(env)

    def test_relative_program_files_is_ignored(self, tmp_path: Path, monkeypatch: Any) -> None:
        _touch(tmp_path / "pf" / "PowerShell" / "7" / "pwsh.exe")
        monkeypatch.chdir(tmp_path)
        with pytest.raises(FileNotFoundError):
            psparse.find_powershell({"ProgramFiles": "pf", "SystemRoot": "win"})


def test_version_key_orders_releases_before_previews() -> None:
    names = ["7", "7-preview", "6", "10", "x"]
    assert sorted(names, key=psparse._version_key, reverse=True) == [
        "10",
        "7",
        "6",
        "x",
        "7-preview",
    ]


def test_script_is_pinned_on_first_use_and_a_changed_file_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    script = tmp_path / "pshelper.ps1"
    script.write_bytes(b"# original\n")
    monkeypatch.setattr(psparse, "_script_pin", None)
    monkeypatch.setattr(psparse, "script_path", lambda: str(script))
    assert psparse.pinned_script() == str(script)
    assert psparse.pinned_script() == str(script)  # unchanged: fine
    script.write_bytes(b"# replaced\n")
    with pytest.raises(OSError, match="changed on disk"):
        psparse.pinned_script()
    script.write_bytes(b"# original\n")  # restored: trusted again
    assert psparse.pinned_script() == str(script)


def test_default_spawn_refuses_a_replaced_script(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    script = tmp_path / "pshelper.ps1"
    script.write_bytes(b"# original\n")
    monkeypatch.setattr(psparse, "_script_pin", None)
    monkeypatch.setattr(psparse, "script_path", lambda: str(script))
    monkeypatch.setattr(psparse, "find_powershell", lambda: str(tmp_path / "pwsh.exe"))
    started: list[Any] = []

    class FakePopen:
        pid = 1

        def __init__(self, args: list[str], **kwargs: Any) -> None:
            started.append(args)

    monkeypatch.setattr(psparse.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(psparse, "_assign_to_job", lambda pid: True)
    psparse.default_spawn()
    script.write_bytes(b"# evil\n")
    with pytest.raises(OSError, match="changed on disk"):
        psparse.default_spawn()
    assert len(started) == 1


def test_a_replaced_script_is_a_start_failure_and_stays_gray(made: Any) -> None:
    helper = made(Spawner(OSError("pshelper.ps1 changed on disk since it was first used")))
    helper.warm_up()
    assert wait_until(lambda: helper.status()["failures"] == 1)
    assert helper.request("ls", budget_s=0.2) == (None, (psparse.REASON_NOT_READY,))


# --- 8. doctor and the daemon status text ---


def test_doctor_shows_cooldown_and_degraded_job() -> None:
    (check,) = doctor.check_powershell_parser(
        "mode=x; powershell=disabled; powershell_retry_s=42; a=b"
    )
    assert check.status == doctor.WARN
    assert "circuit breaker" in check.detail
    assert "42 s" in check.detail
    (check,) = doctor.check_powershell_parser("powershell=unavailable; powershell_retry_s=7")
    assert check.status == doctor.WARN
    assert "7 s" in check.detail
    (check,) = doctor.check_powershell_parser("powershell=warming")
    assert check.status == doctor.INFO
    assert "2 s" in check.detail
    assert "1.5" not in check.detail
    checks = doctor.check_powershell_parser("powershell=ready; powershell_job=no; config_dir=-")
    assert [c.name for c in checks] == ["powershell-parser", "powershell-job"]
    assert checks[0].status == doctor.OK
    assert checks[1].status == doctor.WARN
    assert [c.name for c in doctor.check_powershell_parser("powershell=ready")] == [
        "powershell-parser"
    ]


def test_daemon_status_text_carries_the_helper_state(monkeypatch: pytest.MonkeyPatch) -> None:
    daemon = server.Daemon.__new__(server.Daemon)
    daemon._state = server._PolicyState()
    daemon._requests = 1
    daemon._timeouts = 0
    daemon._pool = types.SimpleNamespace(stuck=0)  # type: ignore[assignment]
    fake = {"state": "disabled", "retry_in_s": 41.6, "job_degraded": True, "throttled_s": 3.2}
    monkeypatch.setattr(psparse, "status", lambda: fake)
    text = daemon._status_text()
    assert "powershell=disabled" in text
    assert "powershell_retry_s=41" in text
    assert "powershell_job=no" in text
    assert "powershell_throttled_s=3" in text
    found = doctor.check_powershell_parser(text)
    assert found[0].status == doctor.WARN
    assert any(c.name == "powershell-job" for c in found)
    monkeypatch.setattr(psparse, "status", lambda: {"state": "ready"})
    assert "powershell=ready; config_dir" in daemon._status_text()


# --- real helper (Windows) ---


@pytest.mark.windows
def test_real_slow_input_does_not_restart_storm_the_helper() -> None:
    if sys.platform != "win32":
        pytest.skip("Windows only")
    helper = psparse.PsHelper(startup_timeout_s=60)
    try:
        if not helper.warm_up(wait_s=60):
            pytest.skip(f"no usable PowerShell helper: {helper.status()}")
        slow = "ls;" * 5000
        assert helper.request(slow, budget_s=0.3)[1] == (psparse.REASON_TIMEOUT,)
        assert helper.warm_up(wait_s=60)
        restarts_pid = helper.status()["pid"]
        began = time.perf_counter()
        for _ in range(20):
            assert helper.request(slow, budget_s=0.3)[1] == (psparse.REASON_TIMEOUT,)
        assert time.perf_counter() - began < 0.5
        assert helper.status()["pid"] == restarts_pid  # no further kill
        assert helper.request("git status", budget_s=2)[1] == ()
        assert helper.status()["job_object"] is True
    finally:
        helper.shutdown()
