"""Spec revision 37: the review of revision 36 (docs/reviews/M3a-rev36-review.md).

R36-1: PowerShell's ``Set-Location $env:X`` sets a working directory from an expanded variable; a
relative path resolved against it (and a file a glob matches under an expanded variable) carried
the value into the request's ``paths``. Such a path is now marked as expanded and shown as written;
a glob's matches there are left out.

R36-2: a secret value with whitespace at either end is also looked for without it.

R36-4: a value only in the command text is found; the PowerShell ``python -c`` fixture of revision
36 now has the words the rules really make.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.audit import send_gate
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.normalize.event import normalize_event
from boundkeep.normalize.model import Action, PathRef
from tests.unit.test_m3a_pipeline import HOME, PROJECT, policy
from tests.unit.test_m3a_rev35_review_fixes import REFUSED, _ps
from tests.unit.test_m3a_review_fixes import command, gate
from tests.unit.test_m3a_x1_fixes import WIN_HOME, WIN_PROJECT, manipulated

EXPANDED = "variable-expanded"


def _call(
    text: str,
    env: dict[str, str],
    *,
    tool: str = "PowerShell",
    platform: str = "windows",
    scan_disk: bool = False,
) -> tuple[Any, FakeBackend]:
    """A real call sent to a fake model that allows everything."""
    pol = policy(llm=True)
    auditor, backend = manipulated(pol)
    home = WIN_HOME if platform == "windows" else HOME
    project = WIN_PROJECT if platform == "windows" else PROJECT
    base = {"USERPROFILE": home} if platform == "windows" else {"HOME": home}
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        {
            "hook_event_name": "PreToolUse",
            "session_id": "00000000-0000-4000-8000-0000000000f1",
            "cwd": project,
            "project_dir": project,
            "tool_name": tool,
            "tool_input": {"command": text},
        },
        mode="enforce",
        policy=pol,
        policy_error=None,
        platform=platform,  # type: ignore[arg-type]
        env={**base, **env},
        home=home,
        scan_disk=scan_disk,
        auditor=auditor,
    )
    return decision, backend


def _content(backend: FakeBackend) -> str:
    assert backend.requests, "nothing was sent"
    return backend.requests[0].content


def _paths(content: str) -> list[list[str]]:
    return [[p["path"] for p in a.get("paths", [])] for a in json.loads(content)["actions"]]


# ------------------------------------------------------------------ R36-1


SET_DB = "Set-Location $env:DB_PASSWORD; python gen.py"


@pytest.mark.parametrize(
    ("text", "name", "value", "parts"),
    [
        # the value changed its form in the key: the secret check did not find it
        (SET_DB, "DB_PASSWORD", "pa\\ss1234wd", ["ss1234wd"]),
        (SET_DB, "DB_PASSWORD", "pa/../ss1234wd", ["ss1234wd"]),
        (SET_DB, "DB_PASSWORD", "pass1234wd.", ["pass1234wd"]),
        (
            "Push-Location ${env:API_TOKEN}; python gen.py",
            "API_TOKEN",
            "tk\\9f8e7d6c5b",
            ["9f8e7d"],
        ),
        ("cd $env:SECRETS_DIR; python gen.py", "SECRETS_DIR", "D:\\vault\\prod01", ["vault"]),
        # the value kept its form: it was refused, and is now sent without it
        (SET_DB, "DB_PASSWORD", "pass1234wd", ["pass1234wd"]),
        # a name that does not look secret: its value was sent as it is
        ("Set-Location $env:WORK_DIR; python gen.py", "WORK_DIR", "D:\\vault\\prod01", ["vault"]),
    ],
)
def test_a_path_resolved_against_an_expanded_working_directory_is_shown_as_written(
    text: str, name: str, value: str, parts: list[str]
) -> None:
    decision, backend = _call(text, {name: value})
    content = _content(backend)
    assert decision.decided_by == "llm"
    assert not any(part.casefold() in content.casefold() for part in parts)
    assert "gen.py" in _paths(content)[1]


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ("Set-Location $env:SECRETS_DIR; .\\run.ps1", ".\\run.ps1"),  # the program's own path
        ("Set-Location $env:SECRETS_DIR; Get-Content a.txt > out.txt", "out.txt"),
    ],
)
def test_a_program_path_and_a_redirection_after_it_are_shown_as_written(
    text: str, shown: str
) -> None:
    _, backend = _call(text, {"SECRETS_DIR": "D:\\vault\\prod01"})
    content = _content(backend)
    assert "vault" not in content.casefold()
    assert shown in _paths(content)[1]


def test_a_relative_step_from_an_expanded_working_directory_is_marked_too() -> None:
    text = "Set-Location $env:SECRETS_DIR; Set-Location sub; python gen.py"
    _, backend = _call(text, {"SECRETS_DIR": "D:\\vault\\prod01"})
    assert "vault" not in _content(backend).casefold()


def test_an_absolute_working_directory_after_it_is_not_marked() -> None:
    text = "Set-Location $env:SECRETS_DIR; Set-Location D:\\work; python gen.py"
    _, backend = _call(text, {"SECRETS_DIR": "D:\\vault\\prod01"})
    content = _content(backend)
    assert "vault" not in content.casefold()
    assert "d:/work/gen.py" in _paths(content)[2]


def test_the_rules_still_see_the_key_and_the_mark_is_only_a_note() -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "00000000-0000-4000-8000-0000000000f2",
        "cwd": WIN_PROJECT,
        "project_dir": WIN_PROJECT,
        "tool_name": "PowerShell",
        "tool_input": {"command": "Set-Location $env:SECRETS_DIR; python gen.py"},
    }
    actions = normalize_event(
        payload,
        platform="windows",
        env={"USERPROFILE": WIN_HOME, "SECRETS_DIR": "D:\\vault\\prod01"},
        home=WIN_HOME,
    )
    (ref,) = [r for a in actions for r in a.paths if r.key == "d:/vault/prod01/gen.py"]
    assert EXPANDED in ref.reasons
    assert not ref.uncertain
    (start,) = [r for a in actions for r in a.paths if r.key.endswith("/proj/gen.py")]
    assert EXPANDED not in start.reasons


def test_an_absolute_path_is_not_marked_when_the_working_directory_was_unknown() -> None:
    # no cwd: the expanded directory comes first among the possible ones
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "00000000-0000-4000-8000-0000000000f5",
        "tool_name": "PowerShell",
        "tool_input": {"command": "Set-Location $env:SECRETS_DIR; Get-Content D:\\data\\x.txt"},
    }
    actions = normalize_event(
        payload,
        platform="windows",
        env={"USERPROFILE": WIN_HOME, "SECRETS_DIR": "D:\\vault\\prod01"},
        home=WIN_HOME,
    )
    (ref,) = [r for a in actions for r in a.paths if r.key == "d:/data/x.txt"]
    assert EXPANDED not in ref.reasons


def _bash_refs(text: str) -> list[PathRef]:
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "00000000-0000-4000-8000-0000000000f4",
        "cwd": PROJECT,
        "project_dir": PROJECT,
        "tool_name": "Bash",
        "tool_input": {"command": text},
    }
    actions = normalize_event(payload, platform="posix", env={"HOME": HOME}, home=HOME)
    return [r for a in actions for r in a.paths]


@pytest.mark.parametrize(
    "text",
    [
        "cd $HOME/sub && cat a.txt",
        "cd $HOME/sub && find . -name x -exec cat {} \\;",  # the "{}" too
    ],
)
def test_bash_marks_what_the_path_layer_expands_itself(text: str) -> None:
    # $HOME and $PWD are resolved in Bash too: the home is shown as "~" anyway, so this only
    # costs the model the place (spec revision 37)
    below = [r for r in _bash_refs(text) if r.key.startswith(f"{HOME}/sub")]
    assert len(below) >= 2
    assert all(EXPANDED in r.reasons for r in below)


def test_bash_still_takes_the_working_directory_as_unknown() -> None:
    _, backend = _call(
        'cd "$SECRETS_DIR" && python3 gen.py',
        {"SECRETS_DIR": "/srv/vault/prod01"},
        tool="Bash",
        platform="posix",
    )
    content = _content(backend)
    assert "vault" not in content
    assert "gen.py" in _paths(content)[1]


@pytest.mark.skipif(sys.platform != "win32", reason="a Windows folder on disk")
@pytest.mark.parametrize(
    "text",
    [
        "Get-Content $env:SECRETS_DIR\\*.txt",
        "Set-Location $env:SECRETS_DIR; Get-Content *.txt",
    ],
)
def test_the_files_a_glob_matches_under_an_expanded_variable_are_left_out(
    text: str, tmp_path: Path
) -> None:
    folder = tmp_path / "vault7c2d"
    folder.mkdir()
    (folder / "a.txt").write_text("x", encoding="utf-8")
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "00000000-0000-4000-8000-0000000000f3",
        "cwd": WIN_PROJECT,
        "project_dir": WIN_PROJECT,
        "tool_name": "PowerShell",
        "tool_input": {"command": text},
    }
    env = {"USERPROFILE": WIN_HOME, "SECRETS_DIR": str(folder)}
    actions = normalize_event(payload, platform="windows", env=env, home=WIN_HOME, budget_s=5)
    matches = [r for a in actions for r in a.paths if "glob-match" in r.reasons]
    assert matches
    assert all(EXPANDED in r.reasons for r in matches)
    shown = [send_gate._action(a, send_gate._Places(WIN_HOME, WIN_PROJECT)) for a in actions]
    assert "vault7c2d" not in json.dumps(shown).casefold()


def _glob_match(raw: str) -> PathRef:
    return PathRef(
        raw=raw,
        key=raw.lower().replace("\\", "/"),
        flavor="windows",
        access="read",
        reasons=("glob-match", EXPANDED),
    )


def test_a_left_out_glob_match_is_still_checked() -> None:
    pattern = PathRef(
        raw="$env:X\\*.txt", key="d:/vault/*.txt", flavor="windows", reasons=(EXPANDED, "glob")
    )
    shown = Action(
        tool="Read",
        platform="windows",
        paths=(pattern, _glob_match("D:\\vault\\a.txt")),
    )
    result = gate((shown,), tool="Read", home=WIN_HOME)
    assert result.payload is not None
    assert result.payload["actions"][0]["paths"] == [
        {"path": "$env:X\\*.txt", "access": "unknown", "inside_project": None}
    ]
    odd = Action(
        tool="Read", platform="windows", paths=(pattern, _glob_match("D:\\vault\\a\x07.txt"))
    )
    assert gate((odd,), tool="Read", home=WIN_HOME).refused == (
        "a path holds a control or format character"
    )


def test_a_glob_match_without_the_mark_is_still_shown() -> None:
    match = PathRef(
        raw="D:\\data\\a.txt", key="d:/data/a.txt", flavor="windows", reasons=("glob-match",)
    )
    result = gate((Action(tool="Read", platform="windows", paths=(match,)),), tool="Read")
    assert result.payload is not None
    assert result.payload["actions"][0]["paths"][0]["path"] == "d:/data/a.txt"


# ------------------------------------------------------------------ R36-2


@pytest.mark.parametrize(
    "secret",
    [
        "tok3n9f8e7d6c5b\n",  # Get-Content -Raw keeps the last line feed
        "tok3n9f8e7d6c5b\r\n",
        "  tok3n9f8e7d6c5b",
        "abcd1234\n",  # MIN_SECRET_CHARS exactly once stripped
    ],
)
def test_a_secret_value_with_whitespace_at_an_end_is_found_without_it(secret: str) -> None:
    result = gate((command("python3", "tool.py", secret.strip()),), secrets=(secret,))
    assert result.refused == REFUSED


@pytest.mark.parametrize(
    ("secret", "word", "found"),
    [
        ("  short12  ", "short12", False),  # 7 characters once stripped: not looked for
        ("  short12  ", "x  short12  y", True),  # as written, still looked for
        ("tok3n 9f8e7d6c5b", "tok3n9f8e7d6c5b", False),  # only the ends are stripped
    ],
)
def test_the_stripped_value_controls(secret: str, word: str, found: bool) -> None:
    result = gate((command("echo", word),), secrets=(secret,))
    assert (result.refused == REFUSED) is found


# ------------------------------------------------------------------ R36-4


def test_a_secret_value_only_in_the_command_text_is_found() -> None:
    # a comment: no word holds the value, the command text does, escaped
    result = gate(
        (_ps('Get-Date # pa"ss1234wd'),), tool="PowerShell", home=WIN_HOME, secrets=('pa"ss1234wd',)
    )
    assert result.refused == REFUSED
