"""PowerShell command parsing through a long-lived helper process (M1b, see docs/m1b-design.md).

``parse_powershell`` is the entry point: it asks ``pshelper.ps1`` (a resident ``pwsh`` /
``powershell.exe`` child) to parse the command text with ``Parser::ParseInput`` and turns the JSON
reply into a ``BashResult`` through ``pscmd.build``. The command text is attacker-influenced; the
helper only parses it, never executes it. This module's own contract:

* **Never raises, never allows.** Every failure (no PowerShell, constrained language mode, helper
  not ready, timeout, crash, protocol violation, oversize request or reply, circuit breaker open)
  ends as ``BashResult(commands=(), gray=(reason,))``. Gray reasons: ``ps-helper-not-ready``,
  ``ps-helper-timeout``, ``ps-helper-crashed``, ``ps-helper-disabled``, ``ps-helper-busy``,
  ``ps-helper-unavailable``, ``ps-helper-error`` (the helper answered ``ok: false``),
  ``ps-input-throttled`` (a big input right after a timeout, see below), ``ps-input-too-large``
  and ``ps-input-invalid`` (text that is not valid Unicode).
* **Bounded time.** A call returns within ``budget_s`` plus a few milliseconds (queue wait, write,
  read and the JSON decode all count; killing a child never waits). A request that really was in
  flight past its budget kills the child (a watchdog timer also unblocks a write into a wedged
  pipe) and a fresh child is started in the background; calls in the meantime are gray
  (``ps-helper-not-ready``), not delayed. Time spent queueing behind another caller never kills
  the healthy helper: when the wait left less than ``MIN_FLIGHT_S`` the call answers
  ``ps-helper-busy`` without sending anything.
* **One request in flight.** Further callers queue on a lock for what is left of their budget, then
  answer ``ps-helper-busy``.
* **Slow inputs cannot black the parser out.** A timeout kills the shared helper and the restart
  takes about 2 s, so a hostile slow input would be a denial of service. Defence in depth: (a) the
  hash of an input (over ``TIMEOUT_CACHE_MIN_BYTES``) that timed out is remembered in a bounded
  LRU with a TTL and answered ``ps-helper-timeout`` at once without touching the helper; (b) for
  ``THROTTLE_S`` after a timeout-kill, inputs over ``SLOW_INPUT_BYTES`` (over
  ``THROTTLE_STRICT_BYTES`` after repeated kills) answer ``ps-input-throttled`` without reaching
  the helper. Small ordinary commands keep working throughout. Residual: a stream of DIFFERENT
  inputs of up to ``SLOW_INPUT_BYTES`` that each need more than the budget can still cost one
  restart each; the breaker does not see it.
* **Restart with backoff, circuit breaker with cool-down.** After a spawn / start-up / crash /
  protocol failure the next start is allowed 0.5 s, 1 s, 2 s, ... (cap 30 s) later; 5 consecutive
  failures open the breaker (``ps-helper-disabled``). Parse timeouts are NOT failures: they say
  something about the input or the load, not about the helper. After ``BREAKER_COOLDOWN_S`` the
  breaker is half-open: one probe start is allowed, a good reply closes it, another failure opens
  it again for a new cool-down. The sticky ``unavailable`` state (no PowerShell, constrained
  language) is retried after a back-off of 30 s doubling to 10 minutes. ``reset()`` clears both at
  once. A good reply resets the failure count.
* **Idle death is noticed.** The reader thread of the serving child reports EOF; that counts as a
  crash and schedules a restart (honouring the back-off). The daemon also calls ``warm_up()``
  periodically, which is idempotent and starts anything that is due.
* **Recycling.** A child older than 30 minutes or that served 2000 requests is replaced by a hot
  swap: the replacement starts in the background and takes over once it is ready.
* **No leaked children.** On Windows every child is put into a Job Object with
  ``KILL_ON_JOB_CLOSE``, so it dies with the daemon even if the daemon is killed. If assigning a
  child to the job fails the child is still used (degraded, not blocked): ``status()`` reports
  ``job_object: False`` / ``job_degraded: True`` and ``doctor`` warns. ``shutdown`` (also
  registered with ``atexit``) kills the children explicitly as well.
* **Which PowerShell, which script.** On Windows ``powershell.exe`` comes from
  ``%SystemRoot%\\System32\\WindowsPowerShell\\v1.0`` and ``pwsh.exe`` only from
  ``%ProgramFiles%\\PowerShell\\<version>`` (both admin-writable locations); PATH is never searched
  there, so a ``pwsh.exe`` planted in a user-writable PATH directory cannot become the parser. The
  helper script is read once (first spawn) and its sha256 is pinned in memory; every later spawn
  re-hashes the file and refuses to start on a mismatch (counted as a start failure, gray). The
  milliseconds between that check and PowerShell opening the file are not closed.
* **Start-up takes about 2 s** (1.8 - 2.3 s measured on Windows PowerShell 5.1); until the ready
  line arrives every call is gray ``ps-helper-not-ready``.
* **Minimal environment**, no console window, working directory = the temp directory.

The reply dict is the helper's JSON with one normalization: ``commands[*].pos`` is converted from
UTF-16 code unit offsets (what PowerShell reports) to Python string offsets.
"""

from __future__ import annotations

import atexit
import base64
import contextlib
import hashlib
import importlib
import importlib.resources
import json
import os
import queue
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol

from boundkeep.normalize.model import BashResult

__all__ = [
    "MAX_REPLY_BYTES",
    "MAX_REQUEST_BYTES",
    "PsHelper",
    "configure",
    "find_powershell",
    "helper_parse",
    "minimal_env",
    "parse_powershell",
    "reset",
    "script_path",
    "shutdown",
    "status",
    "warm_up",
]

MAX_REQUEST_BYTES = 1 << 20  # UTF-8 bytes of the command text
MAX_REPLY_BYTES = 4 << 20
DEFAULT_BUDGET_S = 0.3
STARTUP_TIMEOUT_S = 20.0
RECYCLE_AFTER_S = 30 * 60.0
RECYCLE_AFTER_REQUESTS = 2000
MAX_FAILURES = 5
BACKOFF_INITIAL_S = 0.5
BACKOFF_MAX_S = 30.0
# Circuit breaker: after this long the open breaker lets one probe start through (half-open).
BREAKER_COOLDOWN_S = 60.0
# The sticky "unavailable" state (no PowerShell / constrained language) is retried after this
# back-off, doubling up to the maximum.
UNAVAILABLE_RETRY_S = 30.0
UNAVAILABLE_RETRY_MAX_S = 600.0
# A request needs at least this much time left after queueing (or its whole budget when that is
# smaller) to be sent at all; otherwise the caller is told "busy" and the helper is left alone.
MIN_FLIGHT_S = 0.1
# Slow-input defence. A timeout-kill restarts the shared helper (about 2 s of blackout), so after
# one, inputs longer than SLOW_INPUT_BYTES are answered gray for THROTTLE_S without reaching the
# helper; after THROTTLE_KILLS kills within THROTTLE_WINDOW_S the threshold drops to
# THROTTLE_STRICT_BYTES. Inputs over TIMEOUT_CACHE_MIN_BYTES that timed out are remembered by hash
# (at most TIMEOUT_CACHE_SIZE of them, for TIMEOUT_CACHE_TTL_S) and answered gray at once.
SLOW_INPUT_BYTES = 2048
THROTTLE_S = 30.0
THROTTLE_STRICT_BYTES = 512
THROTTLE_KILLS = 3
THROTTLE_WINDOW_S = 60.0
TIMEOUT_CACHE_MIN_BYTES = 512
TIMEOUT_CACHE_SIZE = 256
TIMEOUT_CACHE_TTL_S = 600.0

REASON_THROTTLED = "ps-input-throttled"
REASON_NOT_READY = "ps-helper-not-ready"
REASON_TIMEOUT = "ps-helper-timeout"
REASON_CRASHED = "ps-helper-crashed"
REASON_DISABLED = "ps-helper-disabled"
REASON_BUSY = "ps-helper-busy"
REASON_UNAVAILABLE = "ps-helper-unavailable"
REASON_HELPER_ERROR = "ps-helper-error"
REASON_TOO_LARGE = "ps-input-too-large"
REASON_BAD_TEXT = "ps-input-invalid"
REASON_PSCMD_MISSING = "ps-pscmd-missing"
REASON_INTERNAL = "ps-internal-error"

_FULL_LANGUAGE = "FullLanguage"
_CREATE_NO_WINDOW = 0x08000000
_SCRIPT_NAME = "pshelper.ps1"
_ENV_KEYS_WINDOWS = ("SystemRoot", "SystemDrive", "windir", "PATH", "TEMP", "TMP", "USERPROFILE")
_ENV_KEYS_POSIX = ("PATH", "HOME", "TMPDIR", "LANG")


class ProcLike(Protocol):
    """What is needed from a child process (``subprocess.Popen`` fits; tests inject fakes)."""

    stdin: Any
    stdout: Any
    pid: int

    def poll(self) -> int | None: ...
    def kill(self) -> None: ...
    def wait(self, timeout: float | None = None) -> int: ...


SpawnFn = Callable[[], ProcLike]


# --------------------------------------------------------------------------------------------
# Locating PowerShell, the script, and the environment
# --------------------------------------------------------------------------------------------


def minimal_env(
    source: Mapping[str, str], extra: Mapping[str, str] | None = None
) -> dict[str, str]:
    """The only environment the helper gets: a fixed allow-list copied from ``source``.

    Nothing else is passed on (no tokens, keys, ``ANTHROPIC*``, ``CLAUDE*``, ``PSModulePath``...).
    Windows names are matched case-insensitively. ``extra`` is for tests.
    """
    wanted = _ENV_KEYS_WINDOWS if sys.platform == "win32" else _ENV_KEYS_POSIX
    upper = {key.upper(): value for key, value in source.items()}
    env = {name: upper[name.upper()] for name in wanted if name.upper() in upper}
    if extra:
        env.update(extra)
    return env


def _version_key(name: str) -> tuple[int, int, str]:
    """Sort key of a ``%ProgramFiles%\\PowerShell\\<name>`` directory: releases before previews,
    higher numbers first (the caller sorts in reverse)."""
    digits = ""
    for char in name:
        if not char.isdigit():
            break
        digits += char
    return (0 if "preview" in name.lower() or "-" in name else 1, int(digits or 0), name)


def find_powershell(env: Mapping[str, str] | None = None) -> str:
    """Absolute path of the PowerShell to run. Raises ``FileNotFoundError`` when there is none.

    On Windows only two admin-writable places are trusted: ``pwsh.exe`` under
    ``%ProgramFiles%\\PowerShell\\<version>`` (newest release first), else Windows PowerShell 5.1
    at ``%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe``. PATH is never searched:
    a ``pwsh.exe`` planted in a user-writable PATH directory must not become the parser whose
    answers the verdicts rest on. Elsewhere (a design target, not a supported platform) the first
    ``pwsh`` in an absolute PATH entry is used, because there is no better trust root; the current
    directory is never searched.
    """
    source = os.environ if env is None else env
    upper = {key.upper(): value for key, value in source.items()}
    if sys.platform != "win32":
        for directory in upper.get("PATH", "").split(os.pathsep):
            if directory and os.path.isabs(directory):
                candidate = os.path.join(directory.strip('"'), "pwsh")
                if os.path.isfile(candidate):
                    return candidate
        raise FileNotFoundError("pwsh was not found")
    seen: set[str] = set()
    for key in ("PROGRAMFILES", "PROGRAMW6432"):
        base = upper.get(key)
        if not base or not os.path.isabs(base) or base.lower() in seen:
            continue
        seen.add(base.lower())
        root = os.path.join(base, "PowerShell")
        try:
            names = sorted(os.listdir(root), key=_version_key, reverse=True)
        except OSError:
            continue
        for name in names:
            candidate = os.path.join(root, name, "pwsh.exe")
            if os.path.isfile(candidate):
                return candidate
    system_root = upper.get("SYSTEMROOT")
    if system_root and os.path.isabs(system_root):
        candidate = os.path.join(
            system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
        )
        if os.path.isfile(candidate):
            return candidate
    raise FileNotFoundError("neither pwsh nor Windows PowerShell was found")


_pin_lock = threading.Lock()
_script_pin: tuple[str, str] | None = None  # (path, sha256 of the contents) from the first spawn


def pinned_script() -> str:
    """Path of ``pshelper.ps1`` after checking it still has the contents seen at the first spawn.

    The first call reads the file and pins its sha256 in memory; later calls re-hash it. A changed
    file raises ``OSError`` (the start fails, every PowerShell command stays gray) so replacing the
    script on disk after the daemon started has no effect on what is trusted.
    """
    global _script_pin
    with _pin_lock:
        if _script_pin is None:
            path = script_path()
            _script_pin = (path, hashlib.sha256(Path(path).read_bytes()).hexdigest())
            return path
        path, digest = _script_pin
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
            raise OSError(f"{_SCRIPT_NAME} changed on disk since it was first used")
        return path


def script_path() -> str:
    """Where ``pshelper.ps1`` lives: package data, else beside this file."""
    with contextlib.suppress(Exception):  # fall back to the source tree
        resource = importlib.resources.files("boundkeep.normalize").joinpath(_SCRIPT_NAME)
        candidate = str(resource)
        if os.path.isfile(candidate):
            return candidate
    beside = Path(__file__).with_name(_SCRIPT_NAME)
    if beside.is_file():
        return str(beside)
    raise FileNotFoundError(_SCRIPT_NAME)


# --------------------------------------------------------------------------------------------
# Windows Job Object: children die with the daemon
# --------------------------------------------------------------------------------------------

_job_lock = threading.Lock()
_job_handle: Any = None
_job_failed = False


def _create_job() -> Any:
    import ctypes
    from ctypes import wintypes

    class _BasicLimits(ctypes.Structure):
        _fields_ = (
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        )

    class _IoCounters(ctypes.Structure):
        _fields_ = tuple((n, ctypes.c_uint64) for n in ("r", "w", "o", "rb", "wb", "ob"))

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = (
            ("BasicLimitInformation", _BasicLimits),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = ctypes.c_void_p
    kernel32.SetInformationJobObject.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        raise OSError("CreateJobObjectW failed")
    info = _ExtendedLimits()
    info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    ok = kernel32.SetInformationJobObject(
        handle,
        9,  # JobObjectExtendedLimitInformation
        ctypes.byref(info),
        ctypes.sizeof(info),
    )
    if not ok:
        kernel32.CloseHandle(handle)
        raise OSError("SetInformationJobObject failed")
    return handle


def _assign_to_job(pid: int) -> bool:
    """Put process ``pid`` into the shared kill-on-close job. False when that is not possible."""
    global _job_handle, _job_failed
    if sys.platform != "win32":
        return False
    import ctypes
    from ctypes import wintypes

    with _job_lock:
        if _job_failed:
            return False
        if _job_handle is None:
            try:
                _job_handle = _create_job()
            except OSError:
                _job_failed = True
                return False
        job = _job_handle
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    process = kernel32.OpenProcess(0x0100 | 0x0001, False, pid)  # SET_QUOTA | TERMINATE
    if not process:
        return False
    try:
        return bool(kernel32.AssignProcessToJobObject(job, process))
    finally:
        kernel32.CloseHandle(process)


def job_object_active() -> bool:
    """True when a kill-on-close Job Object exists (Windows only; for ``status``)."""
    return _job_handle is not None


def default_spawn(extra_env: Mapping[str, str] | None = None) -> ProcLike:
    """Start the real helper: no profile, no window, minimal environment, in the kill-on-close job.

    ``extra_env`` adds variables to the minimal environment (tests only). Raises
    ``FileNotFoundError`` when there is no PowerShell or no script, ``OSError`` otherwise.
    """
    exe = find_powershell()
    script = pinned_script()
    args = [
        exe,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script,
    ]
    creationflags = _CREATE_NO_WINDOW if sys.platform == "win32" else 0
    proc = subprocess.Popen(  # noqa: S603 - fixed argument vector, no shell, absolute executable
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=minimal_env(os.environ, extra_env),
        cwd=tempfile.gettempdir(),
        creationflags=creationflags,
        close_fds=True,
    )
    assigned = False
    with contextlib.suppress(Exception):  # no job is degraded, not fatal
        assigned = _assign_to_job(proc.pid)
    # Remembered on the process object so the manager can report THIS child's state.
    setattr(proc, "job_assigned", assigned)  # noqa: B010 - Popen has no such attribute
    return proc


# --------------------------------------------------------------------------------------------
# One child process
# --------------------------------------------------------------------------------------------

_EOF = object()
_OVERSIZE = object()


class _ProtocolError(Exception):
    """The helper said something that is not the protocol."""


class _Child:
    """A helper process plus the thread that reads its stdout lines into a queue."""

    def __init__(
        self,
        proc: ProcLike,
        max_reply: int,
        clock: Callable[[], float],
        on_exit: Callable[[_Child], None] | None = None,
    ) -> None:
        self.proc = proc
        self.replies: queue.Queue[object] = queue.Queue()
        self.started = clock()
        self.requests = 0
        self.timed_out = False
        self.killed = False  # we ended it (timeout, recycle, shutdown): not a crash
        self.job_assigned = getattr(proc, "job_assigned", None) is True
        self._limit = max_reply + 2
        self._on_exit = on_exit
        self._thread = threading.Thread(target=self._read, name="boundkeep-ps-reader", daemon=True)
        self._thread.start()

    def _read(self) -> None:
        stdout = self.proc.stdout
        try:
            while True:
                line = stdout.readline(self._limit)
                if not line:
                    self.replies.put(_EOF)
                    return
                if len(line) >= self._limit and not line.endswith(b"\n"):
                    self.replies.put(_OVERSIZE)
                    self.kill()
                    return
                self.replies.put(line)
        except Exception:  # noqa: BLE001 - a broken pipe or closed file is just "the child is gone"
            self.replies.put(_EOF)
        finally:
            with contextlib.suppress(Exception):
                stdout.close()
            with contextlib.suppress(Exception):
                self.proc.stdin.close()
            # Reap the process here (it is on its way out: EOF on stdout) so that killing never has
            # to wait in a request path, then tell the manager when nobody killed it on purpose.
            with contextlib.suppress(Exception):
                self.proc.wait(timeout=5.0)
            callback = self._on_exit
            if callback is not None and not self.killed:
                with contextlib.suppress(Exception):
                    callback(self)

    def kill(self, *, wait: bool = False) -> None:
        """Kill the process. Safe from any thread and repeatable; never raises. It does not wait
        unless asked to (``shutdown`` does): the reader thread reaps the process."""
        self.killed = True
        with contextlib.suppress(Exception):
            self.proc.kill()
        if wait:
            with contextlib.suppress(Exception):
                self.proc.wait(timeout=0.2)

    def alive(self) -> bool:
        try:
            return self.proc.poll() is None
        except Exception:  # noqa: BLE001 - an unreadable state counts as dead
            return False

    def drain(self) -> bool:
        """Discard anything the child said unprompted. False when that includes EOF or garbage."""
        healthy = True
        while True:
            try:
                item = self.replies.get_nowait()
            except queue.Empty:
                return healthy
            if item is _EOF or item is _OVERSIZE:
                healthy = False

    def wait_line(self, timeout_s: float) -> bytes:
        try:
            item = self.replies.get(timeout=max(timeout_s, 0.0))
        except queue.Empty:
            raise TimeoutError from None
        if isinstance(item, bytes):
            return item
        raise EOFError


def _decode_json_line(line: bytes) -> dict[str, Any]:
    try:
        value = json.loads(line.decode("utf-8").lstrip("﻿"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _ProtocolError("not JSON") from exc
    if not isinstance(value, dict):
        raise _ProtocolError("not an object")
    return value


def _check_reply(reply: dict[str, Any], rid: str) -> None:
    """Shallow shape check of a helper reply; raises ``_ProtocolError``. Deep checks are pscmd's."""
    if reply.get("id") != rid or not isinstance(reply.get("ok"), bool):
        raise _ProtocolError("wrong id or no ok flag")
    if not reply["ok"]:
        if not isinstance(reply.get("error"), str):
            raise _ProtocolError("error reply without error")
        return
    for key in ("commands", "parse_errors"):
        items = reply.get(key)
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            raise _ProtocolError(f"bad {key}")
    for key in ("compound", "dynamic"):
        items = reply.get(key)
        if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            raise _ProtocolError(f"bad {key}")
    if not isinstance(reply.get("mode"), str):
        raise _ProtocolError("bad mode")


def _check_ready(line: bytes) -> dict[str, Any]:
    info = _decode_json_line(line)
    if info.get("ready") is not True or not isinstance(info.get("mode"), str):
        raise _ProtocolError("bad ready line")
    return info


def _utf16_to_str_offsets(text: str, reply: dict[str, Any]) -> None:
    """PowerShell offsets count UTF-16 code units; make ``commands[*].pos`` Python offsets."""
    if all(ord(ch) <= 0xFFFF for ch in text):
        return
    mapping: list[int] = []
    for index, ch in enumerate(text):
        mapping.append(index)
        if ord(ch) > 0xFFFF:
            mapping.append(index)  # the low surrogate half
    mapping.append(len(text))
    for command in reply["commands"]:
        pos = command.get("pos")
        if (
            isinstance(pos, list)
            and len(pos) == 2
            and all(isinstance(p, int) and 0 <= p < len(mapping) for p in pos)
        ):
            command["pos"] = [mapping[pos[0]], mapping[pos[1]]]


# --------------------------------------------------------------------------------------------
# The manager
# --------------------------------------------------------------------------------------------


class PsHelper:
    """Owns at most one serving helper child (plus one replacement being started).

    All public methods are thread-safe and never raise. Lock order: ``_req_lock`` before ``_lock``;
    ``_lock`` is never held while waiting for anything.
    """

    def __init__(
        self,
        spawn: SpawnFn | None = None,
        *,
        startup_timeout_s: float = STARTUP_TIMEOUT_S,
        recycle_after_s: float = RECYCLE_AFTER_S,
        recycle_after_requests: int = RECYCLE_AFTER_REQUESTS,
        max_failures: int = MAX_FAILURES,
        backoff_initial_s: float = BACKOFF_INITIAL_S,
        backoff_max_s: float = BACKOFF_MAX_S,
        max_request_bytes: int = MAX_REQUEST_BYTES,
        max_reply_bytes: int = MAX_REPLY_BYTES,
        clock: Callable[[], float] = time.monotonic,
        breaker_cooldown_s: float = BREAKER_COOLDOWN_S,
        unavailable_retry_s: float = UNAVAILABLE_RETRY_S,
        unavailable_retry_max_s: float = UNAVAILABLE_RETRY_MAX_S,
        throttle_s: float = THROTTLE_S,
        timeout_cache_size: int = TIMEOUT_CACHE_SIZE,
        timeout_cache_ttl_s: float = TIMEOUT_CACHE_TTL_S,
    ) -> None:
        self._breaker_cooldown = breaker_cooldown_s
        self._unavail_retry = unavailable_retry_s
        self._unavail_retry_max = unavailable_retry_max_s
        self._throttle_s = throttle_s
        self._cache_size = max(timeout_cache_size, 0)
        self._cache_ttl = timeout_cache_ttl_s
        self._spawn: SpawnFn = spawn or default_spawn
        self._startup_timeout = startup_timeout_s
        self._recycle_after_s = recycle_after_s
        self._recycle_after_requests = recycle_after_requests
        self._max_failures = max_failures
        self._backoff_initial = backoff_initial_s
        self._backoff_max = backoff_max_s
        self._max_request = max_request_bytes
        self._max_reply = max_reply_bytes
        self._clock = clock
        self._lock = threading.Lock()
        self._cv = threading.Condition(self._lock)
        self._req_lock = threading.Lock()
        self._child: _Child | None = None
        self._pending: _Child | None = None
        self._starting = False
        self._failures = 0
        self._restarts = 0
        self._requests = 0
        self._next_start = 0.0
        self._disabled = False
        self._disabled_until = 0.0
        self._unavailable: str | None = None
        self._unavail_until = 0.0
        self._unavail_count = 0
        self._timeouts = 0
        self._timeout_kills: deque[float] = deque(maxlen=16)
        self._throttle_until = 0.0
        self._slow_inputs: OrderedDict[bytes, float] = OrderedDict()
        self._wake: threading.Timer | None = None
        self._closed = False
        self._gen = 0
        self._mode: str | None = None
        self._version: str | None = None
        self._warmup_ms: float | None = None
        self._started_at: float | None = None

    # -- public --------------------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """State: ``state`` (warming | ready | disabled | unavailable), ``failures``, ``mode``,
        ``version``, ``warmup_ms`` (the first start; None until then), plus ``requests``,
        ``restarts``, ``pid``, ``reason`` (why disabled / unavailable), ``retry_in_s`` (seconds
        until the half-open probe / the unavailable retry; None otherwise), ``throttled_s``
        (seconds left of the big-input throttle), ``timeouts``, ``job_object`` (THIS child is in
        the kill-on-close job) and ``job_degraded`` (a child runs on Windows without that).
        For ``ping`` and ``doctor``."""
        with self._lock:
            now = self._clock()
            self._refresh_locked(now)
            child = self._child
            state = "warming"
            reason: str | None = None
            retry_in: float | None = None
            if self._disabled:
                retry_in = max(self._disabled_until - now, 0.0)
                state, reason = "disabled", "circuit breaker open"
            elif self._unavailable is not None:
                retry_in = max(self._unavail_until - now, 0.0)
                state, reason = "unavailable", self._unavailable
            elif child is not None and child.alive():
                state = "ready"
            serving = child is not None and child.alive()
            job = serving and child is not None and child.job_assigned
            return {
                "retry_in_s": None if retry_in is None else round(retry_in, 1),
                "throttled_s": round(max(self._throttle_until - now, 0.0), 1),
                "timeouts": self._timeouts,
                "job_degraded": bool(serving and sys.platform == "win32" and not job),
                "state": state,
                "failures": self._failures,
                "mode": self._mode,
                "version": self._version,
                "warmup_ms": self._warmup_ms,
                "requests": self._requests,
                "restarts": self._restarts,
                "pid": child.proc.pid if child is not None else None,
                "reason": reason,
                "job_object": bool(job),
            }

    def warm_up(self, *, wait_s: float = 0.0) -> bool:
        """Start the helper in the background (idempotent). With ``wait_s`` wait that long for it.

        Returns True when the helper is ready. Never raises, never blocks longer than ``wait_s``.
        """
        self._maybe_start()
        if wait_s > 0:
            with self._cv:
                self._cv.wait_for(self._settled_locked, timeout=wait_s)
        with self._lock:
            return self._ready_locked()

    def shutdown(self) -> None:
        """Kill every child and refuse further work until ``reset``. Idempotent, never raises."""
        with self._cv:
            self._closed = True
            self._gen += 1
            children = [self._child, self._pending]
            self._child = None
            self._pending = None
            self._starting = False
            wake, self._wake = self._wake, None
            self._cv.notify_all()
        if wake is not None:
            wake.cancel()
        for child in children:
            if child is not None:
                child.kill(wait=True)

    def reset(self) -> None:
        """Forget failures, close the breaker, re-detect PowerShell; the next call restarts it."""
        self.shutdown()
        with self._cv:
            self._closed = False
            self._disabled = False
            self._disabled_until = 0.0
            self._unavailable = None
            self._unavail_until = 0.0
            self._unavail_count = 0
            self._failures = 0
            self._next_start = 0.0
            self._throttle_until = 0.0
            self._timeout_kills.clear()
            self._slow_inputs.clear()
            self._cv.notify_all()

    def request(
        self, text: str, *, budget_s: float = DEFAULT_BUDGET_S
    ) -> tuple[dict[str, Any] | None, tuple[str, ...]]:
        """Parse ``text``: ``(reply, ())`` or ``(None, (gray_reason,))``."""
        try:
            return self._request(text, budget_s)
        except Exception:  # noqa: BLE001 - the contract is "never raises"; this is the last net
            return None, (REASON_INTERNAL,)

    # -- internals -----------------------------------------------------------------------------

    def _ready_locked(self) -> bool:
        return (
            not self._disabled
            and self._unavailable is None
            and self._child is not None
            and self._child.alive()
        )

    def _settled_locked(self) -> bool:
        return (
            self._closed or self._disabled or self._unavailable is not None or self._ready_locked()
        )

    def _refresh_locked(self, now: float) -> None:
        """Half-open the breaker and retry the sticky unavailable state once their time is up."""
        if self._disabled and now >= self._disabled_until:
            # One probe: a single further failure opens the breaker again, a good reply closes it.
            self._disabled = False
            self._failures = max(self._max_failures - 1, 0)
            self._next_start = now
        if self._unavailable is not None and now >= self._unavail_until:
            self._unavailable = None
            self._next_start = now

    def _schedule_start(self) -> None:
        """Make sure ``_maybe_start`` runs when the next start becomes allowed (now or later)."""
        with self._lock:
            if self._closed:
                return
            if self._disabled:
                at = self._disabled_until
            elif self._unavailable is not None:
                at = self._unavail_until
            else:
                at = self._next_start
            delay = max(at - self._clock(), 0.0)
            timer: threading.Timer | None = None
            if delay > 0:
                timer = threading.Timer(delay + 0.01, self._maybe_start)
                timer.daemon = True
            old, self._wake = self._wake, timer
        if old is not None:
            old.cancel()
        if timer is None:
            self._maybe_start()
        else:
            timer.start()

    def _on_child_exit(self, child: _Child) -> None:
        """Reader-thread callback: the serving child's stdout ended and nobody killed it on purpose.

        That is a crash while idle (or an in-flight one the request also sees; ``_child_failed``
        counts only once). Count it and schedule the restart instead of waiting for a caller.
        """
        with self._lock:
            if self._closed or self._child is not child:
                return
        self._child_failed(child)
        self._schedule_start()

    def _backoff(self) -> float:
        exponent = min(max(self._failures - 1, 0), 16)
        return min(self._backoff_initial * (2.0**exponent), self._backoff_max)

    def _needs_recycle(self, child: _Child) -> bool:
        return (
            child.requests >= self._recycle_after_requests
            or self._clock() - child.started >= self._recycle_after_s
        )

    def _maybe_start(self) -> None:
        """Start a (replacement) child in the background when one is wanted and allowed now."""
        with self._lock:
            self._refresh_locked(self._clock())
            if self._closed or self._disabled or self._unavailable is not None:
                return
            child = self._child
            if child is not None and not child.alive():
                # It died while idle: that is a crash, counted like one.
                self._child = child = None
                self._fail_locked()
            if self._starting or self._disabled:
                return
            if child is not None and not self._needs_recycle(child):
                return
            if self._clock() < self._next_start:
                return
            self._starting = True
            gen = self._gen
        try:
            threading.Thread(
                target=self._start_worker, args=(gen,), name="boundkeep-ps-start", daemon=True
            ).start()
        except Exception:  # noqa: BLE001 - cannot start a thread: count it like a failed start
            self._start_failed(gen, None)

    def _start_worker(self, gen: int) -> None:
        began = time.perf_counter()
        child: _Child | None = None
        try:
            proc = self._spawn()
            child = _Child(proc, self._max_reply, self._clock, self._on_child_exit)
            with self._lock:
                if gen != self._gen:
                    stale = True
                else:
                    stale = False
                    self._pending = child
            if stale:
                child.kill()
                return
            info = _check_ready(child.wait_line(self._startup_timeout))
        except FileNotFoundError:
            self._mark_unavailable(gen, child, "PowerShell or the helper script was not found")
            return
        except (TimeoutError, EOFError, _ProtocolError, OSError, ValueError):
            self._start_failed(gen, child)
            return
        except Exception:  # noqa: BLE001 - whatever the spawn factory did
            self._start_failed(gen, child)
            return
        warm_ms = (time.perf_counter() - began) * 1000
        mode = str(info["mode"])
        version = info.get("version")
        if mode != _FULL_LANGUAGE:
            self._mark_unavailable(
                gen, child, f"language mode {mode}: the parser cannot be used", mode
            )
            return
        self._install(gen, child, mode, version if isinstance(version, str) else None, warm_ms)

    def _install(
        self, gen: int, child: _Child, mode: str, version: str | None, warm_ms: float
    ) -> None:
        # Wait for the request in flight (bounded by its budget) so a swap never cuts one off.
        if not self._req_lock.acquire(timeout=5.0):
            self._start_failed(gen, child)
            return
        old: _Child | None = None
        keep = False
        try:
            with self._cv:
                if not (gen != self._gen or self._closed):
                    old = self._child
                    self._child = child
                    self._pending = None
                    self._starting = False
                    self._mode = mode
                    self._version = version
                    self._unavail_count = 0
                    if self._warmup_ms is None:
                        self._warmup_ms = round(warm_ms, 1)
                    if old is not None:
                        self._restarts += 1
                    keep = True
                    self._cv.notify_all()
        finally:
            self._req_lock.release()
        if not keep:
            child.kill()
        if old is not None:
            old.kill()

    def _fail_locked(self) -> None:
        self._failures += 1
        now = self._clock()
        if self._failures >= self._max_failures:
            self._disabled = True
            self._disabled_until = now + self._breaker_cooldown
        self._next_start = now + self._backoff()
        self._cv.notify_all()

    def _set_unavailable_locked(self, reason: str, mode: str | None) -> None:
        """Enter the sticky unavailable state; it is retried after a doubling back-off."""
        delay = min(
            self._unavail_retry * (2.0 ** min(self._unavail_count, 16)), self._unavail_retry_max
        )
        self._unavail_count += 1
        self._unavailable = reason
        self._unavail_until = self._clock() + delay
        self._mode = mode

    def _start_failed(self, gen: int, child: _Child | None) -> None:
        if child is not None:
            child.kill()
        doomed: _Child | None = None
        with self._cv:
            if gen != self._gen:
                return
            self._pending = None
            self._starting = False
            self._fail_locked()
            if self._disabled:
                doomed, self._child = self._child, None
        if doomed is not None:
            doomed.kill()

    def _mark_unavailable(
        self, gen: int, child: _Child | None, reason: str, mode: str | None = None
    ) -> None:
        if child is not None:
            child.kill()
        with self._cv:
            if gen != self._gen:
                return
            self._pending = None
            self._starting = False
            self._set_unavailable_locked(reason, mode)
            self._cv.notify_all()

    def _child_failed(self, child: _Child, *, count: bool = True) -> None:
        """The serving child timed out, crashed or lied: kill it, count it unless told not to."""
        child.kill()
        doomed: _Child | None = None
        with self._cv:
            if self._child is child:
                self._child = None
                if count:
                    self._fail_locked()
                else:
                    self._next_start = self._clock()
                    self._cv.notify_all()
                if self._disabled:
                    doomed, self._pending = self._pending, None
                    self._starting = False
        if doomed is not None:
            doomed.kill()

    def _gate(self) -> tuple[str, ...] | None:
        """Gray reasons that apply before any work is done, or None to go ahead."""
        with self._lock:
            self._refresh_locked(self._clock())
            if self._disabled:
                return (REASON_DISABLED,)
            if self._unavailable is not None:
                return (REASON_UNAVAILABLE,)
            if self._closed:
                return (REASON_NOT_READY,)
        return None

    def _known_slow(self, data: bytes) -> bytes | None:
        """The cache key of ``data`` when it is a remembered timeout (not expired), else None."""
        if not self._slow_inputs or len(data) <= TIMEOUT_CACHE_MIN_BYTES:
            return None
        key = hashlib.sha256(data).digest()
        with self._lock:
            when = self._slow_inputs.get(key)
            if when is None:
                return None
            if self._clock() - when > self._cache_ttl:
                del self._slow_inputs[key]
                return None
            self._slow_inputs.move_to_end(key)
        return key

    def _throttled(self, size: int) -> bool:
        """True when an input of ``size`` bytes must not reach the helper right now."""
        with self._lock:
            now = self._clock()
            if now >= self._throttle_until:
                return False
            recent = sum(1 for t in self._timeout_kills if now - t < THROTTLE_WINDOW_S)
            limit = THROTTLE_STRICT_BYTES if recent >= THROTTLE_KILLS else SLOW_INPUT_BYTES
            return size > limit

    def _timed_out(self, child: _Child, data: bytes) -> tuple[None, tuple[str, ...]]:
        """A request really was in flight past its budget: kill the child, remember the input.

        Not a breaker failure (it says something about the input or the machine load, not about
        the helper); the replacement starts at once, and big inputs are throttled for a while.
        """
        self._child_failed(child, count=False)
        with self._lock:
            now = self._clock()
            self._timeouts += 1
            self._timeout_kills.append(now)
            self._throttle_until = now + self._throttle_s
            if len(data) > TIMEOUT_CACHE_MIN_BYTES and self._cache_size > 0:
                key = hashlib.sha256(data).digest()
                self._slow_inputs[key] = now
                self._slow_inputs.move_to_end(key)
                while len(self._slow_inputs) > self._cache_size:
                    self._slow_inputs.popitem(last=False)
        self._maybe_start()
        return None, (REASON_TIMEOUT,)

    def _request(self, text: str, budget_s: float) -> tuple[dict[str, Any] | None, tuple[str, ...]]:
        budget = max(budget_s, 0.0)
        deadline = self._clock() + budget
        try:
            data = text.encode("utf-8")
        except UnicodeEncodeError:
            return None, (REASON_BAD_TEXT,)
        if len(data) > self._max_request:
            return None, (REASON_TOO_LARGE,)
        if self._known_slow(data) is not None:
            return None, (REASON_TIMEOUT,)
        gate = self._gate()
        if gate is not None:
            return None, gate
        if self._throttled(len(data)):
            return None, (REASON_THROTTLED,)
        self._maybe_start()
        with self._lock:
            ready = self._ready_locked()
        if not ready:
            return None, (REASON_NOT_READY,)
        if not self._req_lock.acquire(timeout=max(deadline - self._clock(), 0.0)):
            return None, (REASON_BUSY,)
        try:
            # The parse budget runs from the moment the request is sent. When queueing used most
            # of it the caller is told "busy"; the healthy helper is not killed for that wait.
            remaining = deadline - self._clock()
            if remaining <= 0 or remaining < min(budget, MIN_FLIGHT_S):
                return None, (REASON_BUSY,)
            with self._lock:
                child = self._child if self._ready_locked() else None
            if child is None:
                return None, (REASON_NOT_READY,)
            outcome = self._exchange(child, data, deadline)
        finally:
            self._req_lock.release()
        reply, gray = outcome
        if reply is not None:
            _utf16_to_str_offsets(text, reply)
        with self._lock:
            recycle = child.requests >= self._recycle_after_requests or (
                self._clock() - child.started >= self._recycle_after_s
            )
        if recycle:
            self._maybe_start()
        return reply, gray

    def _exchange(
        self, child: _Child, data: bytes, deadline: float
    ) -> tuple[dict[str, Any] | None, tuple[str, ...]]:
        """One request/reply on ``child`` (the caller holds the request lock)."""
        if not child.drain():
            self._child_failed(child)
            return None, (REASON_CRASHED,)
        rid = secrets.token_hex(8)
        line = b'{"id":"' + rid.encode("ascii") + b'","b64":"' + base64.b64encode(data) + b'"}\n'

        def expire() -> None:
            child.timed_out = True
            child.kill()

        remaining = max(deadline - self._clock(), 0.0)
        timer = threading.Timer(remaining, expire)
        timer.daemon = True
        timer.start()
        try:
            try:
                child.proc.stdin.write(line)
                child.proc.stdin.flush()
            except (OSError, ValueError):
                if child.timed_out:
                    return self._timed_out(child, data)
                self._child_failed(child)
                return None, (REASON_CRASHED,)
            try:
                item = child.replies.get(timeout=max(deadline - self._clock(), 0.0))
            except queue.Empty:
                return self._timed_out(child, data)
        finally:
            timer.cancel()
        if child.timed_out:
            return self._timed_out(child, data)
        if not isinstance(item, bytes):
            self._child_failed(child)
            return None, (REASON_CRASHED,)
        try:
            reply = _decode_json_line(item)
            _check_reply(reply, rid)
        except _ProtocolError:
            self._child_failed(child)
            return None, (REASON_CRASHED,)
        child.requests += 1
        with self._lock:
            self._requests += 1
        if not reply["ok"]:
            error = reply.get("error")
            return None, (REASON_TOO_LARGE if error == "too-large" else REASON_HELPER_ERROR,)
        if reply["mode"] != _FULL_LANGUAGE:
            with self._cv:
                self._set_unavailable_locked(
                    f"language mode {reply['mode']}: the parser cannot be used", str(reply["mode"])
                )
            self._child_failed(child)
            return None, (REASON_UNAVAILABLE,)
        with self._lock:
            self._failures = 0
        return reply, ()


# --------------------------------------------------------------------------------------------
# Module-level API (one shared helper per process)
# --------------------------------------------------------------------------------------------

_default_lock = threading.Lock()
_default: PsHelper | None = None


def _helper() -> PsHelper:
    global _default
    with _default_lock:
        if _default is None:
            _default = PsHelper()
        return _default


def configure(spawn: SpawnFn | None = None, **options: Any) -> PsHelper:
    """Replace the shared helper (shutting the old one down). ``options`` are ``PsHelper`` keywords.

    For tests and for a daemon that wants different limits; the default needs no configuration.
    """
    global _default
    with _default_lock:
        old, _default = _default, PsHelper(spawn, **options)
        new = _default
    if old is not None:
        old.shutdown()
    return new


def helper_parse(
    text: str, *, budget_s: float = DEFAULT_BUDGET_S
) -> tuple[dict[str, Any] | None, tuple[str, ...]]:
    """The raw helper reply for ``text`` and no gray reasons, or ``None`` and the gray reasons.

    The reply is the dict described in docs/m1b-design.md section 2 (``ok`` is True). Never raises
    and returns within about ``budget_s`` seconds. This is the function ``pscmd.build`` consumes.
    """
    try:
        return _helper().request(text, budget_s=budget_s)
    except Exception:  # noqa: BLE001 - never raises
        return None, (REASON_INTERNAL,)


def parse_powershell(command: str, *, budget_s: float = DEFAULT_BUDGET_S) -> BashResult:
    """Normalize a PowerShell command line into a ``BashResult`` (the type the Bash parser returns).

    Any failure is gray: ``BashResult(commands=(), gray=(reason,))``. Never raises.
    """
    reply, gray = helper_parse(command, budget_s=budget_s)
    if reply is None:
        return BashResult(commands=(), gray=gray or (REASON_INTERNAL,))
    try:
        module = importlib.import_module("boundkeep.normalize.pscmd")
    except ModuleNotFoundError as exc:
        missing = exc.name or ""
        reason = (
            REASON_PSCMD_MISSING
            if missing.startswith("boundkeep.normalize.ps")
            else REASON_INTERNAL
        )
        return BashResult(commands=(), gray=(reason,))
    except Exception:  # noqa: BLE001 - a broken pscmd must not become an exception here
        return BashResult(commands=(), gray=(REASON_INTERNAL,))
    try:
        result = module.build(reply, source=command)
    except Exception:  # noqa: BLE001 - same
        return BashResult(commands=(), gray=(REASON_INTERNAL,))
    if not isinstance(result, BashResult):
        return BashResult(commands=(), gray=(REASON_INTERNAL,))
    return result


def status() -> dict[str, Any]:
    """State of the shared helper, see :meth:`PsHelper.status`. Never raises, never starts it."""
    return _helper().status()


def warm_up(*, wait_s: float = 0.0) -> bool:
    """Start the shared helper in the background (the daemon calls this at start-up)."""
    return _helper().warm_up(wait_s=wait_s)


def shutdown() -> None:
    """Kill the shared helper's children (the daemon calls this when it stops)."""
    with _default_lock:
        helper = _default
    if helper is not None:
        helper.shutdown()


def reset() -> None:
    """Close the circuit breaker and re-detect PowerShell; the next call restarts the helper."""
    _helper().reset()


atexit.register(shutdown)
