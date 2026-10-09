"""Reading and writing Claude Code settings files without damaging them.

Standard library only. ``boundkeep init`` edits a file the user owns and probably hand-edited:
the edit must be lossless (values and key order never change), must keep the file's own style
(indent, line endings, trailing newline) so a diff shows only our change, and must never leave a
half-written file behind. A broken settings file is not a harmless failure here: Claude Code only
shows a non-blocking notice (VS Code shows nothing at all), so the gate would be silently open
(docs/hook-behavior.md E6). Hence the rule: whatever cannot be read with certainty is refused with
a ``SettingsError`` instead of being guessed at and rewritten.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

MAX_SETTINGS_BYTES: Final = 4 * 1024 * 1024
# Real settings are about 5 levels deep. The editing code (copy.deepcopy in install.py) needs
# several Python frames per level, so a document that Python can still parse at ~990 levels would
# pass loading and then crash the edit with a RecursionError. Refusing it here, with a clear
# message, keeps every later step safe.
MAX_NESTING_DEPTH: Final = 100
_BOM: Final = b"\xef\xbb\xbf"
_UTF16_BOMS: Final = (b"\xff\xfe", b"\xfe\xff")
_DEFAULT_INDENT: Final = 2
# Module level so tests can exercise the POSIX branches on Windows (and the reverse).
_IS_WINDOWS: Final[bool] = sys.platform == "win32"
# Back-off between attempts to os.replace over a target that another program briefly holds open
# (editor, indexer, antivirus, a second boundkeep run); about 1.4 s in total. Windows only: on
# POSIX a rename over an open file just works, so a PermissionError there is permanent.
_REPLACE_RETRY_DELAYS_S: Final = (0.01, 0.02, 0.05, 0.05, 0.1, 0.1, 0.1, 0.2, 0.2, 0.2, 0.2, 0.2)


class SettingsError(Exception):
    """A settings file (or a settings-shaped value) cannot be read or edited safely."""


@dataclass(frozen=True)
class SettingsDoc:
    """A parsed settings file plus everything needed to write it back in the same style.

    ``compact_separators`` only matters when ``indent`` is None: it tells a minified file
    (``{"a":1}``) from ``json.dumps`` default single-line output (``{"a": 1}``). It is an addition
    to the minimal field set because without it a minified file could not be written back
    unchanged.
    """

    path: str
    exists: bool
    data: dict[str, Any]
    raw: bytes
    had_bom: bool
    newline: str
    indent: int | str | None
    trailing_newline: bool
    compact_separators: bool = False


class _DuplicateKeyError(ValueError):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


class _BadConstantError(ValueError):
    pass


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # Python silently keeps the last of two equal keys; Claude Code's reader may keep the first or
    # the last. We cannot know which entries it would have honoured, so we refuse the document.
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    # NaN / Infinity are not JSON; JavaScript's JSON.parse (Claude Code) rejects them, and
    # writing them back would produce a file Claude Code cannot read.
    raise _BadConstantError(name)


def _check_values(data: object, path: str) -> None:
    """Refuse values that parse in Python but could not be written back as valid UTF-8 JSON, and
    documents nested deeper than ``MAX_NESTING_DEPTH`` (checked iteratively: no recursion here).
    """
    stack: list[tuple[object, int]] = [(data, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, (dict, list)) and depth > MAX_NESTING_DEPTH:
            raise SettingsError(
                f"{path}: nested more than {MAX_NESTING_DEPTH} levels deep; real settings are "
                "far shallower, refusing to edit it"
            )
        if isinstance(item, dict):
            for key, value in item.items():
                _check_text(key, path)
                stack.append((value, depth + 1))
        elif isinstance(item, list):
            stack.extend((value, depth + 1) for value in item)
        elif isinstance(item, str):
            _check_text(item, path)
        elif isinstance(item, float) and not math.isfinite(item):
            # "1e999" parses to infinity in Python; it cannot be written back as JSON.
            raise SettingsError(f"{path}: contains a number too large for a double")


def _check_text(text: str, path: str) -> None:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise SettingsError(
            f"{path}: contains an unpaired surrogate escape (\\ud800-\\udfff) that cannot be "
            "stored as UTF-8"
        ) from None


def _uses_compact_separators(text: str) -> bool:
    """True when the first key/value ``:`` outside a string is not followed by a space."""
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == ":":
            return text[index + 1 : index + 2] != " "
    return False


def _detect_indent(text: str, data: Mapping[str, Any]) -> tuple[int | str | None, bool]:
    """(indent, compact_separators) of an already parsed document."""
    stripped = text.strip()
    if not data:
        # ``{}`` has no style to preserve; a freshly filled file should be readable.
        return _DEFAULT_INDENT, False
    if "\n" not in stripped and "\r" not in stripped:
        return None, _uses_compact_separators(stripped)
    for line in stripped.splitlines()[1:]:
        if not line.strip(" \t"):
            continue
        lead = line[: len(line) - len(line.lstrip(" \t"))]
        if not lead:
            return 0, False
        if set(lead) == {"\t"}:
            return lead, False
        if set(lead) == {" "}:
            return len(lead), False
        return _DEFAULT_INDENT, False  # mixed tabs and spaces: normalize
    return _DEFAULT_INDENT, False


def load_settings(path: str) -> SettingsDoc:
    """Read and strictly validate a settings file. Never writes.

    A missing file is not an error (``exists=False``, empty data). Everything else that is not a
    well-formed UTF-8 JSON object without duplicate keys, or is larger than 4 MiB, raises
    ``SettingsError`` naming the file and the problem.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_SETTINGS_BYTES + 1)
    except FileNotFoundError:
        return SettingsDoc(
            path=path,
            exists=False,
            data={},
            raw=b"",
            had_bom=False,
            newline="\n",
            indent=_DEFAULT_INDENT,
            trailing_newline=True,
        )
    except OSError as exc:
        raise SettingsError(
            f"{path}: cannot be read ({exc.strerror or type(exc).__name__})"
        ) from exc
    if len(raw) > MAX_SETTINGS_BYTES:
        raise SettingsError(
            f"{path}: larger than {MAX_SETTINGS_BYTES // (1024 * 1024)} MiB, refusing to edit it"
        )
    had_bom = raw.startswith(_BOM)
    body = raw[len(_BOM) :] if had_bom else raw
    if body.startswith(_UTF16_BOMS):
        raise SettingsError(f"{path}: looks like UTF-16; Claude Code settings must be UTF-8")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SettingsError(f"{path}: is not valid UTF-8 (bad byte at offset {exc.start})") from exc
    if not text.strip():
        raise SettingsError(f"{path}: is empty (not a JSON object); remove it or write {{}}")
    try:
        parsed = json.loads(
            text, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant
        )
    except _DuplicateKeyError as exc:
        raise SettingsError(
            f"{path}: duplicate key {exc.key!r}; which value Claude Code honours is undefined, "
            "fix the file first"
        ) from exc
    except _BadConstantError as exc:
        raise SettingsError(f"{path}: invalid JSON (the constant {exc} is not allowed)") from exc
    except json.JSONDecodeError as exc:
        raise SettingsError(
            f"{path}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    except RecursionError as exc:
        raise SettingsError(
            f"{path}: nested too deeply (more than {MAX_NESTING_DEPTH} levels)"
        ) from exc
    except ValueError as exc:
        raise SettingsError(f"{path}: invalid JSON value ({exc})") from exc
    if not isinstance(parsed, dict):
        kind = "null" if parsed is None else type(parsed).__name__
        raise SettingsError(f"{path}: top level must be a JSON object, found {kind}")
    _check_values(parsed, path)
    crlf = text.count("\r\n")
    lf_only = text.count("\n") - crlf
    indent, compact = _detect_indent(text, parsed)
    return SettingsDoc(
        path=path,
        exists=True,
        data=parsed,
        raw=raw,
        had_bom=had_bom,
        newline="\r\n" if crlf > lf_only else "\n",
        indent=indent,
        trailing_newline=text.endswith("\n"),
        compact_separators=compact,
    )


def render_settings(doc: SettingsDoc, new_data: Mapping[str, Any]) -> bytes:
    """Serialize ``new_data`` in the style of ``doc``: its indent, line endings, trailing newline.

    Never writes a BOM, even when the original had one: Windows PowerShell 5.1 adds BOMs and some
    readers choke on them (spec 5.1); the caller reports ``doc.had_bom``. Non-ASCII text stays
    UTF-8 and key order is whatever ``new_data`` has.
    """
    separators = (",", ":") if doc.indent is None and doc.compact_separators else None
    try:
        text = json.dumps(
            dict(new_data),
            indent=doc.indent,
            ensure_ascii=False,
            allow_nan=False,
            separators=separators,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise SettingsError(f"{doc.path}: new settings cannot be serialized ({exc})") from exc
    if doc.newline != "\n":
        # Newlines inside JSON strings are always escaped, so every raw one is layout.
        text = text.replace("\n", doc.newline)
    if doc.trailing_newline:
        text += doc.newline
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SettingsError(
            f"{doc.path}: new settings contain text that is not valid UTF-8"
        ) from exc


def _preserved_mode(target: str) -> int | None:
    """Permission bits to carry over to the replacement file, or None to keep mkstemp's 0600.

    Only an EXISTING file on POSIX has bits worth keeping. A new file stays 0600 instead of being
    forced to 0644 regardless of the umask: a fresh user settings.json may later hold tokens in
    its ``env`` block. Windows has no meaningful mode bits.
    """
    if _IS_WINDOWS:
        return None
    try:
        return stat.S_IMODE(os.stat(target).st_mode)
    except OSError:
        return None


def _current_bytes(target: str) -> bytes:
    """Content of ``target`` as ``load_settings`` would have seen it (b"" for a missing file)."""
    try:
        with open(target, "rb") as handle:
            return handle.read(MAX_SETTINGS_BYTES + 1)
    except FileNotFoundError:
        return b""
    except OSError as exc:
        raise SettingsError(
            f"{target}: cannot be re-read before writing ({exc.strerror or type(exc).__name__})"
        ) from exc


def _replace_with_retry(tmp_path: str, target: str) -> None:
    """``os.replace`` that waits out a brief sharing violation on Windows.

    Other errors propagate untouched. A PermissionError that outlasts the back-off becomes a
    ``SettingsError`` that names the file and says what to do, instead of a bare WinError 5.
    """
    delays = iter(_REPLACE_RETRY_DELAYS_S if _IS_WINDOWS else ())
    while True:
        try:
            os.replace(tmp_path, target)
            return
        except PermissionError as exc:
            delay = next(delays, None)
            if delay is None:
                raise SettingsError(
                    f"{target}: cannot be replaced (permission denied): it is locked by another "
                    "program (an editor, antivirus, an indexer or a second boundkeep run) or is "
                    "read-only. Nothing was changed; close the other program and try again"
                ) from exc
            time.sleep(delay)


def write_atomic(path: str, content: bytes, *, expect_raw: bytes | None = None) -> None:
    """Replace ``path`` with ``content`` so that readers see the old or the new file, never half.

    The temp file lives in the same directory (``os.replace`` is only atomic within one volume),
    is flushed and fsynced before the swap, and is removed on any failure; the original is then
    untouched. A symlinked target is resolved first so the link itself survives, and the original
    file's permission bits are kept (``mkstemp`` would otherwise leave 0600 behind; a NEW file
    keeps 0600). On Windows a brief sharing violation is retried for about a second and a lasting
    one is reported as a ``SettingsError``.

    ``expect_raw`` closes the read-modify-write window: pass ``SettingsDoc.raw`` and the write is
    refused (``SettingsError``, file untouched) when the file no longer holds exactly those bytes,
    for example because the user, Claude Code or a second ``init`` edited it meanwhile. That is a
    narrowed window, not a lock: a change between this check and the swap can still be lost.
    """
    target = os.path.realpath(path) if os.path.islink(path) else path
    directory = os.path.dirname(os.path.abspath(target))
    os.makedirs(directory, exist_ok=True)
    mode = _preserved_mode(target)
    fd, tmp_path = tempfile.mkstemp(
        dir=directory, prefix=f".{os.path.basename(target)[:40]}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            os.chmod(tmp_path, mode)
        if expect_raw is not None and _current_bytes(target) != expect_raw:
            raise SettingsError(
                f"{target}: changed since it was read (another program or a second boundkeep "
                "run edited it); not overwriting it, run the command again"
            )
        _replace_with_retry(tmp_path, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp_path)
        raise
    if not _IS_WINDOWS:
        # Persist the rename itself; best effort, the data is already safe.
        with contextlib.suppress(OSError):
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)


def _backup_stem(path: str) -> str:
    base = re.sub(r"[^\w.-]", "_", os.path.basename(path), flags=re.UNICODE)[:40] or "file"
    full = os.path.normcase(os.path.abspath(path))
    digest = hashlib.sha256(full.encode("utf-8", errors="surrogatepass")).hexdigest()[:8]
    return f"{base}-{digest}"


def backup_file(path: str, backup_dir: str, *, now: float | None = None) -> str | None:
    """Copy ``path`` into ``backup_dir`` and return the copy's path (None if ``path`` is missing).

    Name: ``<sanitized base name>-<8 hex of the full path hash>-<UTC yyyymmddThhmmssZ>[-n].bak``.
    The hash keeps ``project-a/settings.json`` and ``project-b/settings.json`` apart. The copy is
    created exclusively, so an earlier backup is never overwritten, even by a concurrent run.
    """
    if not os.path.exists(path):
        return None
    if not os.path.isfile(path):
        raise SettingsError(f"{path}: not a regular file, cannot back it up")
    os.makedirs(backup_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(time.time() if now is None else now))
    stem = f"{_backup_stem(path)}-{stamp}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    attempt = 0
    while True:
        suffix = "" if attempt == 0 else f"-{attempt}"
        dest = os.path.join(backup_dir, f"{stem}{suffix}.bak")
        try:
            # 0600: a settings file can hold tokens in its env block.
            fd = os.open(dest, flags, 0o600)
        except FileExistsError:
            attempt += 1
            continue
        break
    try:
        with os.fdopen(fd, "wb") as out, open(path, "rb") as source:
            shutil.copyfileobj(source, out)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(dest)
        raise
    return dest
