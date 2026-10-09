"""Building blocks of ``boundkeep init`` / ``uninstall`` / ``doctor``: hook entries, merging them
into a settings document, the install manifest, and the launch self check.

Standard library only (plus ``ownhook``, ``paths`` and ``settings_io``); no CLI, doctor or daemon
code lives here. Every function that edits a settings document is PURE (returns a new dict and
never mutates its input) so the caller decides what is written, and a refused edit leaves the
user's file exactly as it was.

Invariants the callers rely on:

- Only entries recognized by ``ownhook.is_own_hook`` are ever replaced or removed. Other people's
  hooks are never reordered, modified or removed, and unknown keys survive untouched.
- Merging twice gives the same document (``MergeReport.unchanged``).
- A wrongly typed ``hooks`` value is a ``SettingsError``, never silently overwritten.
"""

from __future__ import annotations

import contextlib
import copy
import json
import ntpath
import os
import posixpath
import re
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import IO, Any, Final, Literal

from boundkeep import paths
from boundkeep.ownhook import SUBCOMMANDS, is_own_hook
from boundkeep.settings_io import SettingsError, load_settings, write_atomic

# ---------------------------------------------------------------------------------------------
# Hook entries
# ---------------------------------------------------------------------------------------------

_WINDOWS_ABS: Final = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\[^\\/])")


def _is_absolute(path: str) -> bool:
    """Absolute in either path flavor, whatever the current platform."""
    return bool(_WINDOWS_ABS.match(path)) or path.startswith("/")


@dataclass(frozen=True)
class HookCommand:
    """How Claude Code launches the hook client (exec form: no shell, no quoting).

    ``command`` is the ABSOLUTE path of the executable (python.exe, or the boundkeep-hook launcher
    exe); ``base_args`` is for example ``("-I", "-S", "C:\\...\\hook_client.py")`` for the python
    style and ``()`` for the launcher. The subcommand is always the last argument.
    """

    command: str
    base_args: tuple[str, ...] = ()

    def args_for(self, subcommand: str) -> list[str]:
        return [*self.base_args, subcommand]

    def argv_for(self, subcommand: str) -> list[str]:
        return [self.command, *self.args_for(subcommand)]


@dataclass(frozen=True)
class HookTimeouts:
    """Per-event hook timeouts in seconds; the hook client's own budget is smaller."""

    prompt: int = 10
    pre: int = 15
    post: int = 10
    config: int = 10


_DEFAULT_TIMEOUTS: Final = HookTimeouts()  # one shared frozen default (ruff B008)

# The smallest ``timeout`` (seconds) per event that the hook client accepts for our entries: below
# it the client's own deadline (hook_main.BUDGET_S) would pass after Claude Code killed it, and
# the ConfigChange check (hook_main.entry_intact) calls the entry "altered" and blocks the next
# settings change. Must equal hook_main.MIN_ENTRY_TIMEOUT_S; a unit test compares them (the
# hook client stays import-light, so this module does not import it).
MIN_TIMEOUTS_S: Final = {
    "UserPromptSubmit": 6,
    "PreToolUse": 11,
    "PostToolUse": 6,
    "ConfigChange": 6,
}

_BATCH_SUFFIXES: Final = (".cmd", ".bat")
_BATCH_PROBLEM: Final = (
    "a .cmd/.bat file cannot be a hook command: Claude Code starts hooks without a shell and "
    "fails with spawn EINVAL on batch files, showing only a non-blocking notice "
    "(docs/hook-behavior.md E6/E22), so the gate would be silently open; use the real python.exe "
    "or the boundkeep-hook.exe launcher instead of a shim"
)


def _is_batch_file(command: str) -> bool:
    """True for a ``.cmd`` / ``.bat`` command, however it is spelled.

    Windows ignores trailing dots and spaces in a file name, so ``python.cmd.`` is the same file.
    Checked on every platform: a settings file written on one machine may be used on another.
    """
    return command.rstrip(" .").lower().endswith(_BATCH_SUFFIXES)


def _check_post_matcher(matcher: str) -> None:
    """Refuse a PostToolUse matcher that could silently not select the tools it should.

    Claude Code matches by tool name. Whitespace anywhere (tool names have none), an empty
    alternative (``WebFetch|``, which a regex reads as "match everything") and anything that is
    not a valid regular expression would be written into settings.json without a word, and the
    taint hook might then never fire. ``*`` is Claude Code's own wildcard spelling and is allowed
    as is. A matcher valid in JavaScript but not in Python's ``re`` is refused too: fail closed.
    """
    if not matcher or not matcher.strip():
        raise ValueError("post_matcher must not be empty (an empty matcher means all tools)")
    if matcher == "*":
        return
    if any(ch.isspace() or not ch.isprintable() for ch in matcher):
        raise ValueError(
            f"post_matcher {matcher!r} must not contain whitespace or control characters "
            "(tool names have none; padding makes the matcher select nothing)"
        )
    try:
        compiled = re.compile(matcher)
    except re.error as exc:
        raise ValueError(
            f"post_matcher {matcher!r} is not a valid regular expression ({exc})"
        ) from exc
    if compiled.fullmatch("") is not None:
        raise ValueError(
            f"post_matcher {matcher!r} has an empty alternative or matches the empty string, "
            "which would select every tool; write '*' if that is what you want"
        )


def build_hook_groups(
    cmd: HookCommand, *, post_matcher: str, timeouts: HookTimeouts = _DEFAULT_TIMEOUTS
) -> dict[str, dict[str, Any]]:
    """Event name -> the ONE matcher group boundkeep installs for it.

    UserPromptSubmit and ConfigChange take no matcher (the shapes verified in real Claude Code
    2.1.291, experiments/lab_setup.py); PreToolUse uses ``*`` so unknown tool names still reach the
    daemon, which treats them as gray; PostToolUse uses ``post_matcher`` (from the policy's
    ``taint.sources``). An empty matcher means "all tools" to Claude Code, so it is refused rather
    than passed through.

    Raises ``ValueError`` for a relative command, a ``.cmd`` / ``.bat`` command, an empty or
    malformed ``post_matcher``, or a timeout that is not an integer of at least the hook client's
    minimum: each would silently leave the gate open or wider than intended.
    """
    if not _is_absolute(cmd.command):
        raise ValueError(f"hook command must be an absolute path, got {cmd.command!r}")
    if _is_batch_file(cmd.command):
        raise ValueError(f"{_BATCH_PROBLEM} (got {cmd.command!r})")
    _check_post_matcher(post_matcher)
    seconds = {
        "UserPromptSubmit": timeouts.prompt,
        "PreToolUse": timeouts.pre,
        "PostToolUse": timeouts.post,
        "ConfigChange": timeouts.config,
    }
    groups: dict[str, dict[str, Any]] = {}
    for event, sub in SUBCOMMANDS.items():
        timeout = seconds[event]
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
            raise ValueError(f"timeout for {event} must be a positive integer, got {timeout!r}")
        if timeout < MIN_TIMEOUTS_S[event]:
            raise ValueError(
                f"timeout for {event} is {timeout} s but the hook client needs at least "
                f"{MIN_TIMEOUTS_S[event]} s: with less, boundkeep's own ConfigChange check would "
                "call the entry altered and block the next settings change"
            )
        entry: dict[str, Any] = {
            "type": "command",
            "command": cmd.command,
            "args": cmd.args_for(sub),
            "timeout": timeout,
        }
        if not is_own_hook(entry):
            # Uninstall could not find it again: refuse to write what we could not remove.
            raise ValueError(
                "the hook command would not be recognized as boundkeep's own entry "
                f"(command={cmd.command!r}, args={cmd.args_for(sub)!r}); the launcher must be "
                "named boundkeep-hook[.exe], or the script hook_client.py inside a "
                "'boundkeep' directory"
            )
        group: dict[str, Any] = {}
        if event == "PreToolUse":
            group["matcher"] = "*"
        elif event == "PostToolUse":
            group["matcher"] = post_matcher
        group["hooks"] = [entry]
        groups[event] = group
    return groups


# ---------------------------------------------------------------------------------------------
# Merging into and removing from a settings document
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class MergeReport:
    added: tuple[str, ...]
    replaced: tuple[str, ...]
    unchanged: bool


def _same(a: object, b: object) -> bool:
    # Equality that also notices key order (and 1 versus true), unlike ``==``.
    return json.dumps(a, ensure_ascii=True) == json.dumps(b, ensure_ascii=True)


def _own_group_indices(groups: list[Any]) -> list[int]:
    return [
        index
        for index, group in enumerate(groups)
        if isinstance(group, dict)
        and isinstance(group.get("hooks"), list)
        and any(is_own_hook(h) for h in group["hooks"])
    ]


def _first_own_position(groups: list[Any], own_indices: list[int]) -> tuple[int, int]:
    gi = own_indices[0]
    for j, hook in enumerate(groups[gi]["hooks"]):
        if is_own_hook(hook):
            return gi, j
    raise AssertionError(
        "unreachable: group was selected because it holds an own hook"
    )  # pragma: no cover


def _same_matcher(old: Mapping[str, Any], new: Mapping[str, Any]) -> bool:
    return ("matcher" in old) == ("matcher" in new) and old.get("matcher") == new.get("matcher")


def _with_matcher_and_hooks(
    old: Mapping[str, Any], new: Mapping[str, Any], hooks: list[Any]
) -> dict[str, Any]:
    """``old`` with our matcher and ``hooks``, keeping every other key of ``old`` in place."""
    result: dict[str, Any] = {}
    if "matcher" in new and "matcher" not in old:
        result["matcher"] = new["matcher"]
    for key, value in old.items():
        if key == "matcher":
            if "matcher" in new:
                result["matcher"] = new["matcher"]
        elif key == "hooks":
            result["hooks"] = hooks
        else:
            result[key] = value
    return result


def _merge_event(groups: list[Any], ours: Mapping[str, Any]) -> list[Any]:
    """Replace our entries inside one event's group list (see ``merge_hooks``)."""
    own_indices = _own_group_indices(groups)
    if not own_indices:
        return [*groups, copy.deepcopy(dict(ours))]
    first_gi, first_j = _first_own_position(groups, own_indices)
    new_entries = ours["hooks"]
    result: list[Any] = []
    for gi, group in enumerate(groups):
        if gi not in own_indices:
            result.append(group)
            continue
        foreign = [h for h in group["hooks"] if not is_own_hook(h)]
        if gi != first_gi:
            # A duplicate of ours: drop our entry, keep the group only if foreign hooks remain.
            if foreign:
                result.append(_with_matcher_and_hooks(group, group, foreign))
            continue
        if not foreign:
            # A group that is only ours: it may take the new matcher (policy sources changed).
            result.append(_with_matcher_and_hooks(group, ours, copy.deepcopy(list(new_entries))))
        elif _same_matcher(group, ours):
            inner: list[Any] = []
            for j, hook in enumerate(group["hooks"]):
                if j == first_j:
                    inner.extend(copy.deepcopy(list(new_entries)))
                elif not is_own_hook(hook):
                    inner.append(hook)
            result.append(_with_matcher_and_hooks(group, group, inner))
        else:
            # Our entry shares a group with foreign hooks under a matcher that is not ours (for
            # example Bash only): leaving it there would silently narrow the gate. Move it into
            # its own group directly after, and leave the foreign hooks exactly where they were.
            result.append(_with_matcher_and_hooks(group, group, foreign))
            result.append(copy.deepcopy(dict(ours)))
    return result


_TOO_DEEP: Final = (
    "the settings are nested too deeply to edit safely (load_settings refuses such files); "
    "fix the file first"
)


def merge_hooks(
    settings: Mapping[str, Any], groups: Mapping[str, Mapping[str, Any]]
) -> tuple[dict[str, Any], MergeReport]:
    """Return ``settings`` with boundkeep's hook groups installed, plus a report. Pure.

    For each event: our existing entries (``is_own_hook``) are replaced in place (first position
    kept, further copies of ours dropped; a group that also holds foreign entries keeps them and
    only our entry changes); if there are none a new group is appended at the end of the event's
    list. ``hooks`` and the event list are created only when needed. A wrongly typed ``hooks`` or
    event value, or a document nested too deeply to copy, raises ``SettingsError``.
    """
    try:
        return _merge_hooks(settings, groups)
    except RecursionError:
        # A document that did not come through load_settings (which caps the depth) could still
        # blow the stack in deepcopy; a refusal is the contract, not a traceback.
        raise SettingsError(_TOO_DEEP) from None


def _merge_hooks(
    settings: Mapping[str, Any], groups: Mapping[str, Mapping[str, Any]]
) -> tuple[dict[str, Any], MergeReport]:
    result: dict[str, Any] = copy.deepcopy(dict(settings))
    has_hooks = "hooks" in result
    hooks_value: Any = result["hooks"] if has_hooks else {}
    if not isinstance(hooks_value, dict):
        raise SettingsError(
            f'"hooks" must be an object, found {type(hooks_value).__name__}; '
            "not touching it, fix the file first"
        )
    added: list[str] = []
    replaced: list[str] = []
    for event, group in groups.items():
        if event not in hooks_value:
            hooks_value[event] = [copy.deepcopy(dict(group))]
            added.append(event)
            continue
        current = hooks_value[event]
        if not isinstance(current, list):
            raise SettingsError(
                f"hooks.{event} must be a list, found {type(current).__name__}; "
                "not touching it, fix the file first"
            )
        if not _own_group_indices(current):
            hooks_value[event] = [*current, copy.deepcopy(dict(group))]
            added.append(event)
            continue
        merged = _merge_event(current, group)
        if not _same(merged, current):
            replaced.append(event)
        hooks_value[event] = merged
    if not has_hooks and hooks_value:
        result["hooks"] = hooks_value
    report = MergeReport(
        added=tuple(added), replaced=tuple(replaced), unchanged=not added and not replaced
    )
    return result, report


def remove_hooks(settings: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    """Remove every boundkeep entry; return the new settings and how many entries went. Pure.

    Groups, event keys and finally ``hooks`` that this removal leaves empty are dropped; containers
    that were already empty (and not ours) stay. Wrongly typed values are skipped, not raised on:
    uninstall must work on a half edited file. Whether a file left as ``{}`` is deleted is the
    caller's call (the manifest records ``created_file``). A container that was already empty
    before our entries went in cannot be told apart from one they emptied, so merge then remove
    drops it (``{"hooks": {}}`` comes back as ``{}``): documented, not a bug. A document nested too
    deeply to copy raises ``SettingsError``.
    """
    try:
        return _remove_hooks(settings)
    except RecursionError:
        raise SettingsError(_TOO_DEEP) from None


def _remove_hooks(settings: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = copy.deepcopy(dict(settings))
    hooks = result.get("hooks")
    if not isinstance(hooks, dict):
        return result, 0
    removed = 0
    for event in list(hooks):
        groups = hooks[event]
        if not isinstance(groups, list):
            continue
        event_removed = 0
        kept_groups: list[Any] = []
        for group in groups:
            inner = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(inner, list):
                kept_groups.append(group)
                continue
            kept = [h for h in inner if not is_own_hook(h)]
            dropped = len(inner) - len(kept)
            event_removed += dropped
            if dropped == 0:
                kept_groups.append(group)
            elif kept:
                group["hooks"] = kept
                kept_groups.append(group)
        if event_removed:
            removed += event_removed
            if kept_groups:
                hooks[event] = kept_groups
            else:
                del hooks[event]
    if removed and not hooks:
        del result["hooks"]
    return result, removed


# ---------------------------------------------------------------------------------------------
# Where the settings files are
# ---------------------------------------------------------------------------------------------


def _flavor(path: str) -> Any:
    """``ntpath`` for Windows-style paths, ``posixpath`` otherwise, whatever the current OS.

    Keeps ``resolve_settings_path`` a pure function of its arguments that tests can run anywhere.
    A path that starts with ``/`` is POSIX even if it contains a backslash (legal in a Linux file
    name); a backslash, a drive letter or a UNC prefix otherwise marks a Windows path.
    """
    if path.startswith("/"):
        return posixpath
    if "\\" in path or re.match(r"^[A-Za-z]:", path):
        return ntpath
    return posixpath


def resolve_settings_path(
    scope: Literal["project", "user"], *, cwd: str, env: Mapping[str, str]
) -> str:
    """The settings.json ``init`` writes for ``scope``.

    project -> ``<cwd>/.claude/settings.json``; user -> ``<CLAUDE_CONFIG_DIR or ~/.claude>/
    settings.json``. ``.claude/settings.local.json`` also exists but init never writes it. A
    relative ``cwd`` or ``CLAUDE_CONFIG_DIR`` is refused: Claude Code would resolve it against a
    directory we cannot know.
    """
    if scope == "project":
        if not _is_absolute(cwd):
            raise SettingsError(f"project directory must be absolute, got {cwd!r}")
        return str(_flavor(cwd).join(cwd, ".claude", "settings.json"))
    if scope != "user":
        raise ValueError(f"unknown scope {scope!r}")
    config_dir = env.get("CLAUDE_CONFIG_DIR", "")
    if config_dir:
        if not _is_absolute(config_dir):
            raise SettingsError(f"CLAUDE_CONFIG_DIR must be an absolute path, got {config_dir!r}")
        return str(_flavor(config_dir).join(config_dir, "settings.json"))
    names = ("USERPROFILE", "HOME") if os.name == "nt" else ("HOME", "USERPROFILE")
    home = next((env[name] for name in names if env.get(name)), None)
    if home is None:
        home = os.path.expanduser("~")
    if not _is_absolute(home):
        raise SettingsError(f"cannot determine an absolute home directory (got {home!r})")
    return str(_flavor(home).join(home, ".claude", "settings.json"))


# ---------------------------------------------------------------------------------------------
# Manifest: what init changed, so uninstall, doctor and the ConfigChange hook know our entries
# ---------------------------------------------------------------------------------------------

_MANIFEST_VERSION: Final = 1


@dataclass(frozen=True)
class InstallRecord:
    settings_path: str
    scope: str
    created_file: bool
    hook_command: str
    hook_args: tuple[str, ...]
    post_matcher: str
    installed_at: str  # ISO-8601 UTC


def _strip_extended_prefix(path: str) -> str:
    """``\\\\?\\C:\\x`` -> ``C:\\x`` and ``\\\\?\\UNC\\srv\\share`` -> ``\\\\srv\\share``."""
    if path.startswith("\\\\?\\"):
        rest = path[4:]
        if rest[:4].upper() == "UNC\\":
            return "\\\\" + rest[4:]
        return rest
    return path


def _canonical_windows(path: str) -> str:
    """One spelling for the aliases of a Windows path that Windows itself treats as equal.

    Removes the ``\\\\?\\`` prefix, collapses ``.``, ``..`` and repeated separators, drops the
    trailing dots and spaces Windows ignores in every component, and, on Windows, lets the file
    system expand 8.3 short names (``PROGRA~1``) and fix the case of a path that exists. Network
    paths are not resolved: that could block on an unreachable share.
    """
    text = ntpath.normpath(_strip_extended_prefix(path))
    drive, tail = ntpath.splitdrive(text)
    text = drive + "\\".join(part.rstrip(" .") or part for part in tail.split("\\"))
    if os.name == "nt" and not text.startswith("\\\\"):
        # On failure keep the lexical form: the key only has to be stable, not perfect.
        with contextlib.suppress(OSError, ValueError):
            text = _strip_extended_prefix(os.path.realpath(text))
    return text


def _path_key(path: str) -> str:
    """Normalized settings path; case-insensitive for Windows-style paths (drive letters vary)."""
    if _flavor(path) is ntpath:
        return ntpath.normcase(_canonical_windows(path))
    return posixpath.normpath(path)


def _record_from_json(item: object, path: str) -> InstallRecord:
    def bad(why: str) -> SettingsError:
        return SettingsError(f"{path}: invalid install record ({why})")

    if not isinstance(item, dict):
        raise bad("not an object")
    strings = {}
    for name in ("settings_path", "scope", "hook_command", "post_matcher", "installed_at"):
        value = item.get(name)
        if not isinstance(value, str):
            raise bad(f"{name} must be a string")
        strings[name] = value
    created = item.get("created_file")
    if not isinstance(created, bool):
        raise bad("created_file must be true or false")
    args = item.get("hook_args")
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise bad("hook_args must be a list of strings")
    if not strings["settings_path"]:
        raise bad("settings_path is empty")
    return InstallRecord(
        settings_path=strings["settings_path"],
        scope=strings["scope"],
        created_file=created,
        hook_command=strings["hook_command"],
        hook_args=tuple(args),
        post_matcher=strings["post_matcher"],
        installed_at=strings["installed_at"],
    )


def load_manifest(path: str) -> list[InstallRecord]:
    """Read the install manifest; a missing file is ``[]``, a corrupt one a ``SettingsError``."""
    doc = load_settings(path)  # strict: BOM tolerated, duplicate keys and bad JSON refused
    if not doc.exists:
        return []
    if doc.data.get("version") != _MANIFEST_VERSION:
        raise SettingsError(f"{path}: unsupported manifest version {doc.data.get('version')!r}")
    installs = doc.data.get("installs")
    if not isinstance(installs, list):
        raise SettingsError(f'{path}: "installs" must be a list')
    return [_record_from_json(item, path) for item in installs]


def save_manifest(path: str, records: Sequence[InstallRecord]) -> None:
    """Write the manifest atomically (JSON, indent 2, LF)."""
    payload = {
        "version": _MANIFEST_VERSION,
        "installs": [
            {
                "settings_path": r.settings_path,
                "scope": r.scope,
                "created_file": r.created_file,
                "hook_command": r.hook_command,
                "hook_args": list(r.hook_args),
                "post_matcher": r.post_matcher,
                "installed_at": r.installed_at,
            }
            for r in records
        ],
    }
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    write_atomic(path, text.encode("utf-8"))


def _same_settings(a: str, b: str) -> bool:
    if _path_key(a) == _path_key(b):
        return True
    if os.name == "nt" and _flavor(a) is posixpath:
        return False  # a POSIX-style path on a Windows host is only ever compared by spelling
    return paths.same_file(a, b)


def find_record(records: Sequence[InstallRecord], settings_path: str) -> InstallRecord | None:
    """The record for ``settings_path`` however the path is spelled, or None."""
    return next((r for r in records if _same_settings(r.settings_path, settings_path)), None)


def upsert_record(records: Sequence[InstallRecord], record: InstallRecord) -> list[InstallRecord]:
    """Replace the record for the same settings file (in place) or append a new one.

    Re-running ``init`` must not forget that the first run created the file: when a record for
    the path exists and says ``created_file``, that fact is kept.
    """
    result: list[InstallRecord] = []
    placed = False
    for existing in records:
        if not _same_settings(existing.settings_path, record.settings_path):
            result.append(existing)
        elif not placed:
            keep_created = existing.created_file or record.created_file
            result.append(
                InstallRecord(
                    settings_path=record.settings_path,
                    scope=record.scope,
                    created_file=keep_created,
                    hook_command=record.hook_command,
                    hook_args=record.hook_args,
                    post_matcher=record.post_matcher,
                    installed_at=record.installed_at,
                )
            )
            placed = True
    if not placed:
        result.append(record)
    return result


def drop_record(records: Sequence[InstallRecord], settings_path: str) -> list[InstallRecord]:
    return [r for r in records if not _same_settings(r.settings_path, settings_path)]


# ---------------------------------------------------------------------------------------------
# Self check: launch the hook command exactly like Claude Code does
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SelfCheckResult:
    subcommand: str
    env_variant: str  # "inherited" or "no-python-env"
    ok: bool
    exit_code: int | None
    detail: str
    elapsed_s: float


def _sample(event: dict[str, Any]) -> bytes:
    common: dict[str, Any] = {
        "session_id": "00000000-0000-4000-8000-0000000000aa",
        "transcript_path": "C:\\boundkeep-selfcheck\\transcript.jsonl",
        "cwd": "C:\\boundkeep-selfcheck",
    }
    # Claude Code writes UTF-8 with the text unescaped; non-ASCII on purpose, because the Windows
    # code page (936, gbk) is what broke a naive reader in M0a (docs/hook-behavior.md E18).
    return json.dumps({**common, **event}, ensure_ascii=False).encode("utf-8")


_SAMPLE_EVENTS: Final[dict[str, bytes]] = {
    "pre": _sample(
        {
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "PowerShell",
            "tool_input": {"command": 'Write-Output "\u4f60\u597d \u2713"'},
            "tool_use_id": "toolu_selfcheck",
        }
    ),
    "prompt": _sample(
        {
            "permission_mode": "default",
            "hook_event_name": "UserPromptSubmit",
            "prompt": "\u8bf7\u5217\u51fa\u5f53\u524d\u76ee\u5f55\u4e0b\u7684\u6587\u4ef6 \u2713",
        }
    ),
    "post": _sample(
        {
            "permission_mode": "default",
            "hook_event_name": "PostToolUse",
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://example.com", "prompt": "title"},
            "tool_response": {"code": 200, "result": "\u793a\u4f8b\u57df\u540d \u2713"},
            "tool_use_id": "toolu_selfcheck",
        }
    ),
    "config": _sample(
        {
            "hook_event_name": "ConfigChange",
            "source": "local_settings",
            "file_path": "C:\\boundkeep-selfcheck\\.claude\\settings.local.json",
        }
    ),
}
_PRE_DECISIONS: Final = frozenset({"allow", "deny", "ask", "defer"})
_EXCERPT_CHARS: Final = 300
# Values shorter than this are not scrubbed: a 1 to 3 character value ("1", "en", "C:") is not a
# secret, and replacing it would turn every excerpt into noise. Everything longer is.
_MIN_SCRUB_CHARS: Final = 4
_CAPTURE_LIMIT: Final = 1024 * 1024  # bytes kept per stream; the excerpt needs 300 characters
_PIPE_GRACE_S: Final = 2.0  # how long a pipe may stay open after the hook process has exited
_REAP_S: Final = 3.0  # how long to wait for a killed hook and its readers before giving up


def _scrub(text: str, env: Mapping[str, str]) -> str:
    """``text`` with every occurrence of an environment value replaced by ``<env>``.

    Done on the WHOLE text, before any truncation: a value that straddles a cut would otherwise
    leave its first characters behind. Occurrences are located for every value (overlapping ones
    too) and merged before replacing, so a value that is a prefix of another, or two values that
    overlap in the text, never leave a readable remainder.
    """
    spans: list[tuple[int, int]] = []
    for value in {v for v in env.values() if len(v) >= _MIN_SCRUB_CHARS}:
        start = text.find(value)
        while start != -1:
            spans.append((start, start + len(value)))
            start = text.find(value, start + 1)
    if not spans:
        return text
    spans.sort()
    parts: list[str] = []
    position = 0
    begin, end = spans[0]
    for next_begin, next_end in spans[1:]:
        if next_begin <= end:
            end = max(end, next_end)
            continue
        parts += [text[position:begin], "<env>"]
        position, (begin, end) = end, (next_begin, next_end)
    parts += [text[position:begin], "<env>", text[end:]]
    return "".join(parts)


def _excerpt(data: bytes, env: Mapping[str, str]) -> str:
    """Short, ASCII-only quote of a hook's output that never holds an environment value."""
    text = _scrub(data.decode("utf-8", errors="replace").strip(), env)
    return text.encode("ascii", errors="backslashreplace").decode("ascii")[:_EXCERPT_CHARS]


def _evaluate(
    sub: str, code: int, out: bytes, err: bytes, env: Mapping[str, str]
) -> tuple[bool, str]:
    if code not in (0, 2):
        tail = f"; stderr: {_excerpt(err, env)}" if err.strip() else ""
        return False, (
            f"exit code {code}: Claude Code treats every exit code except 0 and 2 as non-blocking, "
            f"so the gate would be silently open{tail}"
        )
    if code == 2 and not err.strip():
        return False, "exit code 2 without a reason on stderr"
    if not out.strip():
        return True, f"exit code {code}, no output"
    if not out.isascii():
        return False, "stdout contains non-ASCII bytes (must be ASCII-only JSON)"
    try:
        decision = json.loads(out.decode("ascii"))
    except ValueError:
        return False, f"stdout is not valid JSON: {_excerpt(out, env)}"
    if not isinstance(decision, dict):
        return False, "stdout JSON is not an object"
    if sub == "pre":
        specific = decision.get("hookSpecificOutput")
        if (
            not isinstance(specific, dict)
            or specific.get("hookEventName") != "PreToolUse"
            or specific.get("permissionDecision") not in _PRE_DECISIONS
        ):
            return False, (
                "stdout is JSON but not a PreToolUse decision "
                '({"hookSpecificOutput": {"hookEventName": "PreToolUse", '
                '"permissionDecision": ...}})'
            )
        return True, f"exit code {code}, decision {specific['permissionDecision']}"
    return True, f"exit code {code}, valid JSON object"


class _Pump(threading.Thread):
    """Drains one pipe of the hook into memory on a daemon thread.

    The main thread never reads, writes or closes the pipes itself: on Windows a read blocked in
    another thread holds the stream's lock, so ``close()`` from the main thread would wait for a
    grandchild that still has the pipe open, possibly forever. A pump that is still blocked when
    we give up is simply left behind (it ends by itself when the pipe closes).
    """

    def __init__(self, stream: IO[bytes]) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self.data = bytearray()
        self.truncated = False

    def run(self) -> None:
        # A broken pipe is the end of the stream as far as we are concerned.
        with contextlib.suppress(OSError, ValueError):
            while chunk := self._stream.read(65536):
                room = _CAPTURE_LIMIT - len(self.data)
                self.data += chunk[: max(room, 0)]
                self.truncated = self.truncated or len(chunk) > room
        with contextlib.suppress(OSError, ValueError):
            self._stream.close()


def _feed(stream: IO[bytes], data: bytes) -> None:
    """Write the event to the hook's stdin and close it; a hook that never reads is fine."""
    # The hook may exit or close stdin before reading everything: not our problem.
    with contextlib.suppress(OSError, ValueError):
        while data:
            written = stream.write(data)
            data = data[written or len(data) :]
    with contextlib.suppress(OSError, ValueError):
        stream.close()


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    """Kill the hook and the processes it started, best effort, without touching its pipes."""
    if os.name == "nt":
        taskkill = os.path.join(
            os.environ.get("SYSTEMROOT", "C:\\Windows"), "System32", "taskkill.exe"
        )
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            subprocess.run(  # noqa: S603  # fixed system tool, no shell, our own pid
                [taskkill, "/T", "/F", "/PID", str(proc.pid)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
                shell=False,
            )
    else:  # pragma: no cover  # POSIX is a design goal, not yet exercised (spec 5.1)
        killpg = getattr(os, "killpg", None)
        if killpg is not None:
            with contextlib.suppress(OSError):
                killpg(proc.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
    with contextlib.suppress(OSError):
        proc.kill()


def _captured(pump: _Pump, env: Mapping[str, str]) -> bytes:
    """What the pump collected. When the capture limit cut the stream, drop the last bytes too:
    an environment value cut in half by the limit could not be recognized by ``_scrub``."""
    data = bytes(pump.data)
    if pump.truncated:
        longest = max((len(v.encode("utf-8", errors="replace")) for v in env.values()), default=0)
        data = data[: max(len(data) - longest, 0)]
    return data


def _launch(
    argv: list[str], stdin: bytes, env: dict[str, str], timeout_s: float
) -> tuple[int | None, bytes, bytes, str | None]:
    """Run once. Returns (exit code or None, stdout, stderr, problem or None). Never raises.

    Never blocks longer than about ``timeout_s`` plus a few seconds, whatever the hook and its
    children do with the pipes (see ``_Pump``).
    """
    # POSIX: a session of its own so that killpg reaches the hook's children on a timeout.
    session: dict[str, Any] = {} if os.name == "nt" else {"start_new_session": True}
    try:
        proc = subprocess.Popen(  # noqa: S603  # argv is our own hook command, shell=False
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            shell=False,
            bufsize=0,
            **session,
        )
    except (OSError, ValueError) as exc:
        reason = getattr(exc, "strerror", None) or str(exc)
        problem = f"cannot launch ({type(exc).__name__}: {_excerpt(str(reason).encode(), env)})"
        return None, b"", b"", problem
    if proc.stdin is None or proc.stdout is None or proc.stderr is None:  # pragma: no cover
        _kill_tree(proc)
        return None, b"", b"", "cannot launch (no pipes)"
    pumps = (_Pump(proc.stdout), _Pump(proc.stderr))
    for pump in pumps:
        pump.start()
    threading.Thread(target=_feed, args=(proc.stdin, stdin), daemon=True).start()
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=_REAP_S)
        deadline = time.monotonic() + _REAP_S
        for pump in pumps:
            pump.join(max(deadline - time.monotonic(), 0.0))
        return (
            None,
            b"",
            b"",
            (
                f"timed out after {timeout_s:g} s: Claude Code treats a timeout as non-blocking, "
                "so the gate would be silently open"
            ),
        )
    deadline = time.monotonic() + _PIPE_GRACE_S
    for pump in pumps:
        pump.join(max(deadline - time.monotonic(), 0.0))
    if any(pump.is_alive() for pump in pumps):
        # The hook is gone but something it started still holds stdout or stderr. Claude Code may
        # wait for the pipes to close, not just for the exit, so this can look like a hang to it.
        # Not killed here: the hook's pid is already free for reuse, and taskkill /T by a stale
        # pid could hit an unrelated process.
        return (
            proc.returncode,
            b"",
            b"",
            (
                f"the hook exited (code {proc.returncode}) but a process it started still holds "
                "its stdout or stderr open; Claude Code may wait for it until the timeout, "
                "which is then a non-blocking failure and the gate would be silently open. Start "
                "background processes (the daemon) with their stdio detached"
            ),
        )
    return proc.returncode, _captured(pumps[0], env), _captured(pumps[1], env), None


def run_self_check(
    cmd: HookCommand, *, env: Mapping[str, str] | None = None, timeout_s: float = 15.0
) -> list[SelfCheckResult]:
    """Launch the hook command for every subcommand and env variant and judge what comes back.

    Exactly as Claude Code does: ``argv`` list, ``shell=False``, a UTF-8 sample event on stdin,
    stdout and stderr captured as bytes, with a timeout. Variants: ``inherited`` (``env`` or the
    process environment) and ``no-python-env`` (the same minus every ``PYTHON*`` variable, which
    the hook client must not depend on). Never raises; a launch failure is a not-ok result. The
    daemon is not needed: with it down ``pre`` answers ``ask``, which is a valid decision. Result
    details never contain environment values.
    """
    batch = _is_batch_file(cmd.command)
    base = dict(os.environ if env is None else env)
    variants = {
        "inherited": base,
        "no-python-env": {k: v for k, v in base.items() if not k.upper().startswith("PYTHON")},
    }
    results: list[SelfCheckResult] = []
    for sub in SUBCOMMANDS.values():
        event = _SAMPLE_EVENTS[sub]
        for variant, variant_env in variants.items():
            started = time.monotonic()
            try:
                if batch:
                    # Popen would start a .cmd through cmd.exe without a murmur; Claude Code
                    # cannot, so report what Claude Code would see instead of launching it.
                    code, ok, detail = None, False, f"cannot launch ({_BATCH_PROBLEM})"
                else:
                    code, out, err, problem = _launch(
                        cmd.argv_for(sub), event, variant_env, timeout_s
                    )
                    if problem is not None or code is None:
                        ok, detail = False, problem or "no exit code"
                    else:
                        ok, detail = _evaluate(sub, code, out, err, variant_env)
            except Exception as exc:  # noqa: BLE001  # contract: the self check never raises
                code, ok = None, False
                detail = f"unexpected error in the self check ({type(exc).__name__})"
            results.append(
                SelfCheckResult(
                    subcommand=sub,
                    env_variant=variant,
                    ok=ok,
                    exit_code=code,
                    detail=detail,
                    elapsed_s=time.monotonic() - started,
                )
            )
    return results
