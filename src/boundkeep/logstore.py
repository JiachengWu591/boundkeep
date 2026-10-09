"""Append-only JSONL audit log with redaction, rotation and a cheap ``tail``.

Rules this module enforces (spec section 11, CLAUDE.md):

* Nothing reaches the file before it went through the redactor, and only then is it shortened,
  so a secret cut in half by the length limit can not survive as a fragment.
* A record is bounded twice: before redaction (depth, node count and total characters, so a
  hostile structure cannot make the redactor work for minutes) and after it (every string is
  clipped and the whole line is capped, so the log cannot be flooded and rotation keeps working).
* ``append`` never raises for I/O problems and never loses an event because rotation failed.
  On Windows a rename fails with ``PermissionError`` while a reader or an antivirus scan holds
  the file; we then keep appending to the current file and retry the rotation on a later append.
* Each record is written with a single ``os.write`` on a descriptor that appends atomically and
  is closed right afterwards: lines of concurrent writers (threads, and other processes too) do
  not interleave or overwrite each other, and no handle of ours ever blocks a rename. On POSIX
  that is ``O_APPEND``. On Windows the C runtime emulates ``O_APPEND`` with a seek followed by a
  write, which two processes can interleave (we measured lost lines), so there the file is opened
  with ``CreateFileW`` and ``FILE_APPEND_DATA`` only, which makes the kernel append atomically.
* A torn last line (crash, ``ENOSPC`` after a short write) never swallows the next record: the
  new record starts on a fresh line.
* ``tail`` reads backwards in blocks and skips corrupt or half-written lines.

Standard library plus :mod:`boundkeep.redact`.
"""

from __future__ import annotations

import itertools
import json
import math
import os
import stat
import sys
import threading
import time
from collections.abc import Callable, Mapping

from boundkeep.redact import TRUNCATED, redact_obj

__all__ = ["AuditLog"]

_BLOCK_SIZE = 64 * 1024
_ROTATION_RETRY_SECONDS = 5.0
# Bounds for the structure handed to the redactor (a custom redactor may not bound anything, and
# the default one is only linear): depth, number of values and total characters.
_MAX_DEPTH = 64
_MAX_NODES = 20_000
_MAX_INT_BITS = 1024  # json.dumps refuses ints with more than ~4300 decimal digits
_NODE_COST = 4  # bytes charged per value against the line budget (quotes, separators)
_MIN_LINE_BYTES = 256 * 1024
# A string longer than this is cut before redaction (the log keeps max_string_chars of it anyway).
# The redactor is linear but not free (0.1 to 0.3 microseconds per character on hostile text), so
# the cap and the per-record allowance (a few times the cap) bound what one append can cost.
_MIN_PRE_CLIP_CHARS = 256 * 1024
_RAW_BUDGET_FACTOR = 4
# Appended to a pre-cut string so that a token cut in half ("sk-ab") still looks like one to the
# redactor and is removed instead of surviving as a fragment; stripped again when it is still there.
_CLIP_PAD = "X" * 40
_MAX_TRAILER_DIGITS = 12


# --------------------------------------------------------------------------------------------
# Opening the file for atomic appends
# --------------------------------------------------------------------------------------------

if sys.platform == "win32":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _FILE_READ_DATA = 0x0001
    _FILE_APPEND_DATA = 0x0004  # without FILE_WRITE_DATA: every write goes to the end, atomically
    _FILE_READ_ATTRIBUTES = 0x0080
    _SYNCHRONIZE = 0x00100000
    _FILE_SHARE_ALL = 0x1 | 0x2 | 0x4  # read, write, delete: our short-lived handle blocks nobody
    _OPEN_ALWAYS = 4
    _FILE_ATTRIBUTE_NORMAL = 0x80
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    def _open_append(path: str) -> int:
        """File descriptor whose writes append atomically (see the module docstring)."""
        if "\x00" in path:
            # ctypes would silently cut the path at the NUL and open a different file.
            raise ValueError("embedded null character in path")
        handle = _kernel32.CreateFileW(
            path,
            _FILE_APPEND_DATA | _FILE_READ_DATA | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            _FILE_SHARE_ALL,
            None,
            _OPEN_ALWAYS,
            _FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if handle is None or handle == _INVALID_HANDLE_VALUE:
            # WinError maps the code to the matching OSError subclass (FileNotFoundError,
            # PermissionError, ...), which the callers rely on.
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            fd = msvcrt.open_osfhandle(handle, 0)
        except OSError:
            _kernel32.CloseHandle(handle)
            raise
        msvcrt.setmode(fd, os.O_BINARY)  # no "\n" -> "\r\n" translation
        return fd

else:

    def _open_append(path: str) -> int:
        """File descriptor whose writes append atomically (O_APPEND), mode 0600 when created."""
        return os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)


def _line_separator(fd: int) -> bytes:
    """``b"\\n"`` when the file is not empty and does not end with a newline, else ``b""``.

    After a crash or a short write the last line has no terminator; the next record would be
    glued onto it and both would be lost to ``tail``. When we cannot tell, a separator is added:
    an extra blank line is harmless (readers skip it), a glued record is not.
    """
    try:
        size = os.fstat(fd).st_size
        if size == 0:
            return b""
        os.lseek(fd, size - 1, os.SEEK_SET)
        last = os.read(fd, 1)
    except OSError:
        return b"\n"
    return b"" if last == b"\n" else b"\n"


class _Budget:
    """What is left of the node and character allowance while a structure is bounded."""

    __slots__ = ("chars", "nodes")

    def __init__(self, nodes: int, chars: int) -> None:
        self.nodes = nodes
        self.chars = chars

    @property
    def spent(self) -> bool:
        return self.nodes <= 0 or self.chars < 0


class AuditLog:
    """A rotating JSONL log. One instance per file; safe to share between threads."""

    def __init__(
        self,
        path: str,
        *,
        max_bytes: int = 5 * 1024 * 1024,
        backups: int = 5,
        redactor: Callable[[object], object] = redact_obj,
        max_string_chars: int = 4096,
        clock: Callable[[], float] = time.monotonic,
        rotation_retry_seconds: float = _ROTATION_RETRY_SECONDS,
        max_line_bytes: int | None = None,
    ) -> None:
        """``max_line_bytes`` caps one serialized record (default: 256 KiB, or more when
        ``max_string_chars`` is raised so that one long string still fits)."""
        if max_bytes < 1:
            raise ValueError("max_bytes must be at least 1")
        if backups < 0:
            raise ValueError("backups must not be negative")
        if max_string_chars < 1:
            raise ValueError("max_string_chars must be at least 1")
        if max_line_bytes is None:
            max_line_bytes = max(_MIN_LINE_BYTES, 2 * max_string_chars + 64 * 1024)
        if max_line_bytes < 256:
            raise ValueError("max_line_bytes must be at least 256")
        self._path = os.path.abspath(os.fspath(path))
        self._max_bytes = max_bytes
        self._backups = backups
        self._redactor = redactor
        self._max_string_chars = max_string_chars
        self._max_line_bytes = max_line_bytes
        self._pre_clip = max(_MIN_PRE_CLIP_CHARS, 2 * max_string_chars)
        self._raw_budget = _RAW_BUDGET_FACTOR * self._pre_clip
        self._clock = clock
        self._retry_seconds = rotation_retry_seconds
        self._lock = threading.Lock()
        self._last_error: str | None = None
        # Earliest clock() value at which a failed rotation may be retried; None = no failure.
        self._next_rotation: float | None = None

    @property
    def path(self) -> str:
        return self._path

    @property
    def last_error(self) -> str | None:
        """Message of the most recent failure (it stays set after a later success), or None."""
        return self._last_error

    def _fail(self, what: str, exc: BaseException) -> None:
        self._last_error = f"{what}: {type(exc).__name__}: {exc}"

    # ----------------------------------------------------------------------------------------
    # Writing
    # ----------------------------------------------------------------------------------------

    def append(self, record: Mapping[str, object]) -> bool:
        """Write one record. True when the line is on disk, False otherwise (see last_error)."""
        try:
            data = self._serialize(record)
        except Exception as exc:  # noqa: BLE001 - the audit path must never raise into the hook
            self._fail("could not prepare record", exc)
            return False
        with self._lock:
            try:
                self._rotate_if_needed()
                self._write(data)
            except (OSError, ValueError) as exc:
                # ValueError: os.stat / os.open reject a path with an embedded NUL character.
                self._fail("could not write audit log", exc)
                return False
        return True

    def _serialize(self, record: Mapping[str, object]) -> bytes:
        # Order matters: bound, redact, then truncate (see module docstring).
        bounded = self._bound(dict(record), 0, _Budget(_MAX_NODES, self._raw_budget), set())
        redacted = self._redactor(bounded)
        size = 0
        # A line over the cap is shaped again with a smaller budget (control characters cost six
        # bytes each in JSON, so counting characters can undershoot); the last resort is a stub.
        for divisor in (1, 4, 16):
            budget = _Budget(_MAX_NODES, self._max_line_bytes // divisor)
            shaped = self._shape(redacted, 0, budget, set())
            if not isinstance(shaped, dict):
                shaped = {"record": shaped}
            line = json.dumps(shaped, ensure_ascii=False, separators=(",", ":"))
            # Lone surrogates survive json.dumps(ensure_ascii=False) but not UTF-8 encoding.
            data = (line + "\n").encode("utf-8", errors="replace")
            if len(data) <= self._max_line_bytes:
                return data
            size = len(data)
        stub = {"truncated": True, "reason": "record exceeds max_line_bytes", "bytes": size}
        return (json.dumps(stub, separators=(",", ":")) + "\n").encode("utf-8")

    def _bound(self, value: object, depth: int, budget: _Budget, active: set[int]) -> object:
        """A copy of ``value`` with bounded depth, node count and total string length.

        Runs before the redactor, so strings are kept whole (a secret must be seen whole to be
        recognised) up to ``_pre_clip`` characters; a longer one keeps its head, a pad and a
        trailer with the number of characters dropped (see :meth:`_clip`). What does not fit the
        allowance is replaced by ``[TRUNCATED]``.
        """
        if depth > _MAX_DEPTH:
            return TRUNCATED
        budget.nodes -= 1
        if budget.nodes < 0:
            return TRUNCATED
        if isinstance(value, str):
            if len(value) > self._pre_clip:
                dropped = len(value) - self._pre_clip
                value = f"{value[: self._pre_clip]}{_CLIP_PAD}\x00{dropped}\x00"
            budget.chars -= len(value)
            return value if budget.chars >= 0 else TRUNCATED
        if not isinstance(value, Mapping | list | tuple):
            return value
        ident = id(value)
        if ident in active:
            return TRUNCATED
        active.add(ident)
        try:
            if isinstance(value, Mapping):
                pairs = list(itertools.islice(value.items(), max(budget.nodes, 0) + 1))
                out: dict[object, object] = {}
                for key, item in pairs:
                    if budget.spent:
                        out[TRUNCATED] = TRUNCATED
                        break
                    if isinstance(key, str):
                        budget.chars -= len(key)
                    out[key] = self._bound(item, depth + 1, budget, active)
                return out
            items: list[object] = []
            for item in itertools.islice(value, max(budget.nodes, 0) + 1):
                if budget.spent:
                    items.append(TRUNCATED)
                    break
                items.append(self._bound(item, depth + 1, budget, active))
            return tuple(items) if isinstance(value, tuple) else items
        finally:
            active.discard(ident)

    def _clip(self, text: str) -> str:
        """First ``max_string_chars`` characters, then ``...[truncated N chars]``.

        N counts what was cut here plus what :meth:`_bound` cut before redaction (its trailer).
        """
        text, dropped = _split_trailer(text)
        limit = self._max_string_chars
        if len(text) <= limit:
            return text if dropped == 0 else f"{text}...[truncated {dropped} chars]"
        return f"{text[:limit]}...[truncated {len(text) - limit + dropped} chars]"

    @staticmethod
    def _cost(text: str) -> int:
        """Bytes ``text`` takes in the line (escape overhead is caught by the final size check)."""
        return len(text) if text.isascii() else len(text.encode("utf-8", errors="replace"))

    def _shape(self, value: object, depth: int, budget: _Budget, active: set[int]) -> object:
        """Make ``value`` JSON-safe and bounded: clip strings, repr() everything non-JSON.

        ``budget.chars`` is what the finished line may still spend; once it is gone the rest of a
        container is dropped and a ``[TRUNCATED]`` marker stands in for it.
        """
        if depth > _MAX_DEPTH:
            return TRUNCATED
        budget.nodes -= 1
        if budget.nodes < 0:
            return TRUNCATED
        budget.chars -= _NODE_COST
        if isinstance(value, str):
            clipped = self._clip(str.__str__(value))
            budget.chars -= self._cost(clipped)
            return clipped
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, int):
            if value.bit_length() > _MAX_INT_BITS:
                return f"<int of {value.bit_length()} bits>"
            return int(value)
        if isinstance(value, float):
            return float(value) if math.isfinite(value) else repr(float(value))
        if isinstance(value, Mapping | list | tuple):
            ident = id(value)
            if ident in active:
                return TRUNCATED
            active.add(ident)
            try:
                if isinstance(value, Mapping):
                    return self._shape_mapping(value, depth, budget, active)
                items: list[object] = []
                for item in list(value):
                    if budget.spent:
                        items.append(TRUNCATED)
                        break
                    items.append(self._shape(item, depth + 1, budget, active))
                return items
            finally:
                active.discard(ident)
        clipped = self._clip(self._redact_repr(value))
        budget.chars -= self._cost(clipped)
        return clipped

    def _shape_mapping(
        self, value: Mapping[object, object], depth: int, budget: _Budget, active: set[int]
    ) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, item in list(itertools.islice(value.items(), _MAX_NODES + 1)):
            if budget.spent:
                out.setdefault(TRUNCATED, TRUNCATED)
                break
            name = self._json_key(key)
            budget.chars -= self._cost(name)
            # Two keys can end up equal (clipping, int 1 and "1", secrets redacted to the same
            # text); JSON would keep only one of them, so the later one gets a suffix.
            if name in out:
                index = 2
                while f"{name}#{index}" in out:
                    index += 1
                name = f"{name}#{index}"
            out[name] = self._shape(item, depth + 1, budget, active)
        return out

    def _json_key(self, key: object) -> str:
        """The string json.dumps would use for ``key``, clipped; the redactor already ran."""
        if isinstance(key, str):
            return self._clip(str.__str__(key))
        if key is None:
            return "null"
        if isinstance(key, bool):
            return "true" if key else "false"
        if isinstance(key, int):
            if key.bit_length() > _MAX_INT_BITS:
                return f"<int of {key.bit_length()} bits>"
            return str(int(key))
        if isinstance(key, float):
            return repr(float(key))
        return self._clip(self._redact_repr(key))

    def _redact_repr(self, value: object) -> str:
        """repr() of a non-JSON value, passed through the redactor like any other text."""
        try:
            text = repr(value)
        except Exception:  # noqa: BLE001 - a hostile __repr__ must not break logging
            text = f"<unrepresentable {type(value).__name__}>"
        redacted = self._redactor(text)
        return redacted if isinstance(redacted, str) else repr(redacted)

    def _write(self, data: bytes) -> None:
        try:
            fd = _open_append(self._path)
        except FileNotFoundError:
            # Directory permissions are the caller's business; we only make sure it exists.
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            fd = _open_append(self._path)
        try:
            # One buffer, one os.write: the separator (if any) must not become a second write,
            # or another process could slip its line in between.
            view = memoryview(_line_separator(fd) + data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("os.write wrote no bytes")
                view = view[written:]
        finally:
            os.close(fd)

    # ----------------------------------------------------------------------------------------
    # Rotation
    # ----------------------------------------------------------------------------------------

    def _rotate_if_needed(self) -> None:
        """Rotate when the file is full; a failure is remembered and never propagates."""
        try:
            info = os.stat(self._path)
        except FileNotFoundError:
            return
        except OSError as exc:
            self._fail("could not stat audit log", exc)
            return
        # A directory (or anything else odd) at the log path is left alone: writing to it will
        # fail and be reported; renaming it would only make things worse.
        if not stat.S_ISREG(info.st_mode) or info.st_size < self._max_bytes:
            return
        now = self._clock()
        if self._next_rotation is not None and now < self._next_rotation:
            return
        try:
            self._rotate()
        except OSError as exc:
            self._fail("could not rotate audit log (will retry later)", exc)
            self._next_rotation = now + self._retry_seconds
        else:
            self._next_rotation = None

    def _rotate(self) -> None:
        """audit.jsonl -> .1 -> ... -> .<backups>; the oldest file is overwritten (dropped).

        Safe to run again after a failure part way. The shift only moves the files below the
        lowest free slot: after a failed run that slot is exactly the gap the run left behind, so
        a retry continues where it stopped instead of shifting everything a second time (which
        would drop one more generation per retry). Without a gap the oldest file is dropped, once.
        """
        if self._backups <= 0:
            self._remove_if_present(self._path)
            return
        top = self._backups
        for index in range(1, self._backups + 1):
            if not os.path.lexists(f"{self._path}.{index}"):
                top = index
                break
        # Highest first, so a failure half way never overwrites a newer file with an older one.
        for index in range(top - 1, 0, -1):
            try:
                os.replace(f"{self._path}.{index}", f"{self._path}.{index + 1}")
            except FileNotFoundError:
                continue
        try:
            os.replace(self._path, f"{self._path}.1")
        except FileNotFoundError:
            return

    @staticmethod
    def _remove_if_present(path: str) -> None:
        try:
            os.remove(path)
        except FileNotFoundError:
            return

    # ----------------------------------------------------------------------------------------
    # Reading
    # ----------------------------------------------------------------------------------------

    def tail(self, n: int = 20) -> list[dict[str, object]]:
        """The last ``n`` valid records, oldest first.

        Reads backwards in blocks, so the cost depends on ``n`` and not on the file size. Lines
        that are not valid UTF-8 JSON objects (corruption, a half-written last line) are skipped.
        The files are read without a lock: a concurrent append or rotation can at worst make
        the result a moment stale, or repeat a record that moved to ``.1`` while we read.
        """
        if n <= 0:
            return []
        newest_first: list[dict[str, object]] = []
        candidates = [self._path] + [f"{self._path}.{i}" for i in range(1, self._backups + 1)]
        for candidate in candidates:
            if len(newest_first) >= n:
                break
            self._read_backwards(candidate, n - len(newest_first), newest_first)
        newest_first.reverse()
        return newest_first

    def _read_backwards(self, path: str, want: int, out: list[dict[str, object]]) -> None:
        """Append up to ``want`` records of ``path`` to ``out``, newest first."""
        found = 0
        try:
            with open(path, "rb") as handle:
                pos = os.fstat(handle.fileno()).st_size
                carry = b""
                while pos > 0 and found < want:
                    step = min(_BLOCK_SIZE, pos)
                    pos -= step
                    handle.seek(pos)
                    block = handle.read(step)
                    lines = (block + carry).split(b"\n")
                    # lines[0] may be the tail of a line that started in an earlier block.
                    carry = lines[0]
                    for line in reversed(lines[1:]):
                        record = _parse_line(line)
                        if record is not None:
                            out.append(record)
                            found += 1
                            if found >= want:
                                return
                if pos == 0 and found < want:
                    record = _parse_line(carry)
                    if record is not None:
                        out.append(record)
        except FileNotFoundError:
            return  # rotated away, or never created
        except (OSError, ValueError) as exc:
            self._fail("could not read audit log", exc)

    # ----------------------------------------------------------------------------------------
    # Purge
    # ----------------------------------------------------------------------------------------

    def purge(self) -> int:
        """Delete the log and every rotated file (also ones left by a larger ``backups``)."""
        directory, base = os.path.split(self._path)
        # NTFS and the default macOS volume ignore case: "AUDIT.jsonl" is the same file as
        # "audit.jsonl", so compare the normalised names (identity on POSIX).
        base_key = os.path.normcase(base)
        removed = 0
        with self._lock:
            try:
                names = os.listdir(directory)
            except FileNotFoundError:
                return 0
            except (OSError, ValueError) as exc:
                self._fail("could not list log directory", exc)
                return 0
            for name in names:
                key = os.path.normcase(name)
                suffix = key[len(base_key) + 1 :]
                if key != base_key and not (
                    key.startswith(base_key + ".") and suffix.isascii() and suffix.isdigit()
                ):
                    continue
                try:
                    os.remove(os.path.join(directory, name))
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    self._fail(f"could not remove {name}", exc)
                    continue
                removed += 1
            self._next_rotation = None
        return removed


def _split_trailer(text: str) -> tuple[str, int]:
    """``(text without the pre-clip pad and trailer, characters dropped before redaction)``."""
    if not text.endswith("\x00"):
        return text, 0
    start = text.rfind("\x00", 0, len(text) - 1)
    digits = text[start + 1 : -1]
    if start < 0 or not (0 < len(digits) <= _MAX_TRAILER_DIGITS and digits.isascii()):
        return text, 0
    if not digits.isdigit():
        return text, 0
    body = text[:start]
    if body.endswith(_CLIP_PAD):
        body = body[: -len(_CLIP_PAD)]
    return body, int(digits)


def _parse_line(line: bytes) -> dict[str, object] | None:
    """One log line as a dict, or None for blank, corrupt, partial or non-object lines."""
    line = line.strip()
    if not line:
        return None
    try:
        parsed = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    return parsed if isinstance(parsed, dict) else None
