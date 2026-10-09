"""Recognizing boundkeep's own hook entries inside a Claude Code settings document.

Standard library only and import-light: both the hook client (the ``config`` subcommand checks
that a settings change did not remove our entries or switch hooks off) and the installer
(``init`` / ``uninstall`` only ever touch entries recognized here) import it.

A settings document looks like (spec section 5)::

    {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": ...,
                                                          "args": [..., "pre"], "timeout": 15}]}]}}

An entry is ours when it is an exec-form command hook whose last argument is one of our
subcommands and which runs either the ``boundkeep-hook`` launcher or ``hook_client.py`` from a
``boundkeep`` package directory. Nothing is added to the entries themselves (unknown fields inside
a hook object are not known to be safe), so recognition is purely by shape.
"""

from __future__ import annotations

TYPE_CHECKING = False
if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import Any

# Claude Code hook event -> hook client subcommand (also the last argument of the exec form).
SUBCOMMANDS = {
    "UserPromptSubmit": "prompt",
    "PreToolUse": "pre",
    "PostToolUse": "post",
    "ConfigChange": "config",
}
HOOK_SCRIPT_NAME = "hook_client.py"
INVALID_MATCHER = "<not a string>"  # reported for a "matcher" that is not a string
LAUNCHER_NAMES = frozenset({"boundkeep-hook", "boundkeep-hook.exe"})
_SUBCOMMAND_VALUES = frozenset(SUBCOMMANDS.values())


def _parts(path: str) -> list[str]:
    """Lower-cased path components, accepting both separators whatever the current platform."""
    return path.replace("\\", "/").lower().split("/")


def is_own_hook(hook: object) -> bool:
    """True when ``hook`` (one element of a group's ``hooks`` list) is a boundkeep entry."""
    if not isinstance(hook, dict) or hook.get("type") != "command":
        return False
    command = hook.get("command")
    args = hook.get("args")
    if not isinstance(command, str) or not isinstance(args, list):
        return False
    if not args or not all(isinstance(a, str) for a in args) or args[-1] not in _SUBCOMMAND_VALUES:
        return False
    if _parts(command)[-1] in LAUNCHER_NAMES:
        return True
    for arg in args[:-1]:
        parts = _parts(arg)
        if parts[-1] == HOOK_SCRIPT_NAME and "boundkeep" in parts[:-1]:
            return True
    return False


def own_hooks_in(settings: object) -> Iterator[tuple[str, str | None, dict[str, Any]]]:
    """Yield ``(event, matcher, hook)`` for every boundkeep entry found in ``settings``.

    Tolerates any malformed shape (wrong types are skipped, never raised on): the document is
    user-controlled and may be half edited.
    """
    hooks = settings.get("hooks") if isinstance(settings, dict) else None
    if not isinstance(hooks, dict):
        return
    for event, groups in hooks.items():
        if not isinstance(event, str) or not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            matcher = group.get("matcher")
            if "matcher" in group and not isinstance(matcher, str):
                matcher = INVALID_MATCHER  # null, a number, a list: never the same as "no matcher"
            inner = group.get("hooks")
            if not isinstance(inner, list):
                continue
            for hook in inner:
                if is_own_hook(hook):
                    yield event, matcher, hook


def disables_hooks(settings: object) -> bool:
    """True when ``disableAllHooks`` is set in a way that may switch hooks off.

    Fail closed: any value other than absent, ``null`` or ``false`` counts (a string "false" is
    not a boolean and Claude Code's reading of it is unknown), so such an edit is treated as a
    possible gate shutdown.
    """
    if not isinstance(settings, dict):
        return False
    value = settings.get("disableAllHooks")
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    return True
