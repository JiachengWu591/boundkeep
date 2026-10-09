"""Single-instance lock, pid file and stop signals for ``boundkeep serve``."""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import os
import signal
import sys
from collections.abc import Callable
from types import FrameType


class AlreadyRunning(Exception):
    """Another daemon holds the lock."""

    def __init__(self, pid: int | None) -> None:
        super().__init__(
            f"another boundkeep daemon is already running (pid {pid})"
            if pid
            else "another boundkeep daemon is already running"
        )
        self.pid = pid


def read_pid(pid_path: str) -> int | None:
    try:
        with open(pid_path, encoding="ascii") as f:
            text = f.read(32).strip()
    except (OSError, UnicodeDecodeError):
        return None
    return int(text) if text.isdigit() else None


def process_alive(pid: int) -> bool:
    """Whether a process with this pid exists (a hint for ``doctor``; the pipe is the truth)."""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        kernel32.GetExitCodeProcess.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        process_query_limited_information = 0x1000
        still_active = 259
        handle = kernel32.OpenProcess(process_query_limited_information, 0, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_uint32(0)
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return True  # cannot tell: assume it is there
            return code.value == still_active
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class SingleInstance:
    """An exclusive, advisory lock on a file held for the life of the daemon.

    The pid file is informational only (``doctor`` shows it); the lock is what decides. The lock
    disappears with the process, so a crash never leaves a stale lock behind.
    """

    def __init__(self, lock_path: str, pid_path: str) -> None:
        self._lock_path = lock_path
        self._pid_path = pid_path
        self._fd: int | None = None

    def acquire(self) -> None:
        os.makedirs(os.path.dirname(self._lock_path) or ".", exist_ok=True)
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise AlreadyRunning(read_pid(self._pid_path)) from exc
        self._fd = fd
        try:
            self._write_pid()
        except OSError:
            self.release()  # no half-started daemon: the lock goes, the caller reports the error
            raise

    def _write_pid(self) -> None:
        tmp = f"{self._pid_path}.tmp"
        with open(tmp, "w", encoding="ascii", newline="\n") as f:
            f.write(f"{os.getpid()}\n")
        os.replace(tmp, self._pid_path)

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        with contextlib.suppress(OSError):
            os.unlink(self._pid_path)
        try:
            if sys.platform == "win32":
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass  # closing the descriptor releases the lock anyway
        finally:
            os.close(fd)

    def __enter__(self) -> SingleInstance:
        self.acquire()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()


def install_stop_handlers(
    loop: asyncio.AbstractEventLoop, stop: asyncio.Event
) -> Callable[[], None]:
    """Make Ctrl+C, Ctrl+Break (Windows) and SIGTERM set ``stop``; returns the undo function.

    ``loop.add_signal_handler`` does not exist on Windows, so this uses ``signal.signal`` and
    hops into the loop with ``call_soon_threadsafe``. A no-op when not on the main thread.
    """

    def request_stop(signum: int, frame: FrameType | None) -> None:
        loop.call_soon_threadsafe(stop.set)

    previous: dict[int, object] = {}
    names = ["SIGINT", "SIGTERM"] + (["SIGBREAK"] if sys.platform == "win32" else [])
    for name in names:
        number = getattr(signal, name, None)
        if number is None:
            continue
        try:
            previous[number] = signal.signal(number, request_stop)
        except (ValueError, OSError):
            continue

    def restore() -> None:
        for number, handler in previous.items():
            with contextlib.suppress(ValueError, OSError, TypeError):
                signal.signal(number, handler)  # type: ignore[arg-type]

    return restore
