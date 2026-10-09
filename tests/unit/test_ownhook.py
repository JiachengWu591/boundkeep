from __future__ import annotations

from typing import Any

import pytest

from boundkeep.ownhook import SUBCOMMANDS, disables_hooks, is_own_hook, own_hooks_in

PY = r"C:\Users\u\AppData\Roaming\uv\python\cpython-3.12.11-windows-x86_64-none\python.exe"
SCRIPT = r"E:\proj\boundkeep\src\boundkeep\hook_client.py"


def _python_style(sub: str = "pre") -> dict[str, Any]:
    return {"type": "command", "command": PY, "args": ["-I", "-S", SCRIPT, sub], "timeout": 15}


def _launcher_style(sub: str = "pre") -> dict[str, Any]:
    return {
        "type": "command",
        "command": r"C:\venv\Scripts\boundkeep-hook.exe",
        "args": [sub],
        "timeout": 15,
    }


@pytest.mark.parametrize("sub", sorted(SUBCOMMANDS.values()))
def test_both_exec_styles_are_recognized(sub: str) -> None:
    assert is_own_hook(_python_style(sub))
    assert is_own_hook(_launcher_style(sub))


def test_posix_paths_and_case_are_recognized() -> None:
    hook = {
        "type": "command",
        "command": "/usr/bin/python3",
        "args": ["-I", "-S", "/home/u/BoundKeep/src/boundkeep/hook_client.py", "post"],
    }
    assert is_own_hook(hook)
    upper = {"type": "command", "command": r"C:\X\BOUNDKEEP-HOOK.EXE", "args": ["prompt"]}
    assert is_own_hook(upper)


@pytest.mark.parametrize(
    "hook",
    [
        None,
        "boundkeep-hook",
        [],
        {},
        {"type": "http", "command": "boundkeep-hook.exe", "args": ["pre"]},
        {"type": "command", "command": "boundkeep-hook.exe"},  # shell form: not ours
        {"type": "command", "command": "boundkeep-hook.exe", "args": []},
        {"type": "command", "command": "boundkeep-hook.exe", "args": ["pre", "extra"]},
        {"type": "command", "command": "boundkeep-hook.exe", "args": [1, "pre"]},
        {"type": "command", "command": 7, "args": ["pre"]},
        # a hook_client.py that does not live in a boundkeep directory is somebody else's
        {"type": "command", "command": "python", "args": ["/x/other/hook_client.py", "pre"]},
        {"type": "command", "command": "python", "args": ["/x/boundkeep/other.py", "pre"]},
        # the script name must be the last path component, not just a directory called that
        {"type": "command", "command": "python", "args": ["/x/boundkeep/hook_client.py/y", "pre"]},
    ],
)
def test_foreign_or_malformed_entries_are_not_ours(hook: object) -> None:
    assert not is_own_hook(hook)


def test_own_hooks_in_walks_the_document_and_reports_event_and_matcher() -> None:
    settings = {
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "other", "args": []}]},
                {"matcher": "*", "hooks": [_python_style("pre")]},
            ],
            "UserPromptSubmit": [{"hooks": [_launcher_style("prompt")]}],
        }
    }
    found = [(event, matcher, hook["args"][-1]) for event, matcher, hook in own_hooks_in(settings)]
    assert found == [("PreToolUse", "*", "pre"), ("UserPromptSubmit", None, "prompt")]


@pytest.mark.parametrize(
    "settings",
    [
        None,
        [],
        {},
        {"hooks": None},
        {"hooks": []},
        {"hooks": {"PreToolUse": None}},
        {"hooks": {"PreToolUse": ["x", 1, None]}},
        {"hooks": {"PreToolUse": [{"hooks": None}]}},
        {"hooks": {7: [{"hooks": [_python_style()]}]}},
    ],
)
def test_own_hooks_in_tolerates_malformed_documents(settings: object) -> None:
    assert list(own_hooks_in(settings)) == []


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        ({}, False),
        ({"disableAllHooks": False}, False),
        ({"disableAllHooks": None}, False),
        ({"disableAllHooks": True}, True),
        # not a boolean: Claude Code's reading is unknown, so fail closed
        ({"disableAllHooks": "false"}, True),
        ({"disableAllHooks": 0}, True),
        ({"disableAllHooks": {}}, True),
        (None, False),
        ([], False),
    ],
)
def test_disables_hooks_fails_closed_on_non_boolean_values(
    settings: object, expected: bool
) -> None:
    assert disables_hooks(settings) is expected
