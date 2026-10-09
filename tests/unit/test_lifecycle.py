from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from boundkeep.daemon.lifecycle import (
    AlreadyRunning,
    SingleInstance,
    install_stop_handlers,
    process_alive,
    read_pid,
)


def test_the_second_instance_is_refused_and_the_lock_is_reusable_after_release(
    tmp_path: Path,
) -> None:
    lock, pid = str(tmp_path / "serve.lock"), str(tmp_path / "serve.pid")
    first = SingleInstance(lock, pid)
    first.acquire()
    try:
        assert read_pid(pid) == os.getpid()
        with pytest.raises(AlreadyRunning) as info:
            SingleInstance(lock, pid).acquire()
        assert info.value.pid == os.getpid()
        assert str(os.getpid()) in str(info.value)
    finally:
        first.release()
    assert not os.path.exists(pid)  # the pid file goes away with a clean shutdown
    with SingleInstance(lock, pid):
        assert read_pid(pid) == os.getpid()
    first.release()  # releasing twice is fine


def test_the_lock_is_held_across_processes_and_dies_with_the_holder(tmp_path: Path) -> None:
    lock, pid = str(tmp_path / "serve.lock"), str(tmp_path / "serve.pid")
    code = (
        "import sys, time; sys.path.insert(0, sys.argv[3]); "
        "from boundkeep.daemon.lifecycle import SingleInstance; "
        "import os; s = SingleInstance(sys.argv[1], sys.argv[2]); s.acquire(); "
        "print('held', os.getpid(), flush=True); "
        "time.sleep(60)"
    )
    src = str(Path(__file__).resolve().parents[2] / "src")
    holder = subprocess.Popen(
        [sys.executable, "-I", "-c", code, lock, pid, src], stdout=subprocess.PIPE
    )
    try:
        assert holder.stdout is not None
        tag, real_pid = holder.stdout.readline().split()
        assert tag == b"held"
        holder_pid = int(real_pid)  # the venv launcher is a separate process: use the real one
        with pytest.raises(AlreadyRunning) as info:
            SingleInstance(lock, pid).acquire()
        assert info.value.pid == holder_pid
        assert process_alive(holder_pid)
    finally:
        with contextlib.suppress(OSError):
            os.kill(holder_pid, signal.SIGTERM)  # the real interpreter holds the lock
        holder.kill()
        holder.wait(10)
        assert holder.stdout is not None
        holder.stdout.close()
    deadline = time.monotonic() + 5
    while True:  # the OS drops the lock when the holder is gone; no stale lock is left behind
        try:
            with SingleInstance(lock, pid):
                break
        except AlreadyRunning:
            assert time.monotonic() < deadline
            time.sleep(0.05)
    assert not process_alive(holder_pid)


def test_read_pid_tolerates_garbage(tmp_path: Path) -> None:
    path = tmp_path / "serve.pid"
    assert read_pid(str(path)) is None
    for content in (b"", b"abc\n", b"-5\n", b"\xff\xfe"):
        path.write_bytes(content)
        assert read_pid(str(path)) is None
    path.write_bytes(b"1234\n")
    assert read_pid(str(path)) == 1234


def test_process_alive_basics() -> None:
    assert process_alive(os.getpid())
    assert not process_alive(0)
    assert not process_alive(-1)


@pytest.mark.parametrize("name", ["SIGINT", "SIGBREAK", "SIGTERM"])
def test_stop_signals_set_the_event_and_the_handlers_are_restored(name: str) -> None:
    number = getattr(signal, name, None)
    if number is None:
        pytest.skip(f"{name} does not exist here")
    before = signal.getsignal(number)

    async def scenario() -> bool:
        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        restore = install_stop_handlers(loop, stop)
        try:
            loop.call_later(0.1, signal.raise_signal, number)
            await asyncio.wait_for(stop.wait(), timeout=5)
            return stop.is_set()
        finally:
            restore()

    assert asyncio.run(scenario())
    assert signal.getsignal(number) == before


def test_a_lock_path_that_is_a_directory_is_an_oserror_not_a_crash_inside_serve(
    tmp_path: Path,
) -> None:
    lock = tmp_path / "serve.lock"
    lock.mkdir()
    with pytest.raises(
        (PermissionError, IsADirectoryError)
    ):  # the CLI reports this as one line (cli.cmd_serve)
        SingleInstance(str(lock), str(tmp_path / "serve.pid")).acquire()


def test_a_pid_file_that_cannot_be_written_releases_the_lock(tmp_path: Path) -> None:
    pid = tmp_path / "serve.pid"
    pid.mkdir()
    lock = str(tmp_path / "serve.lock")
    with pytest.raises((PermissionError, IsADirectoryError)):
        SingleInstance(lock, str(pid)).acquire()
    SingleInstance(lock, str(tmp_path / "other.pid")).acquire()  # the lock is not stuck
