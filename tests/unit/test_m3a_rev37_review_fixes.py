"""Spec revision 38: the review of revision 37 (docs/reviews/M3a-rev37-review.md).

R37-1: a file a glob matches gets a second ref, its form on disk, when a link is on the way; that
one had no "glob-match", so it was sent "as written", and its text is the match, which holds the
variable's value. Both now carry it and are left out.

R37-2: the event's cwd is kept as its text and a cd target as its key, so one directory can be two
working directories; once one of them is expanded, every relative path came twice (and nine of
them went over ``MAX_PATHS``). The same path, marked and not, is now one ref, marked.

R37-3: ``D:x`` and ``\\x`` take the first working directory's path or drive; with no cwd in the
event that can be the expanded one, and they were not marked.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.normalize.event import normalize_event
from tests.unit.test_m3a_pipeline import policy
from tests.unit.test_m3a_rev36_review_fixes import EXPANDED, _call, _content, _paths
from tests.unit.test_m3a_x1_fixes import WIN_HOME, WIN_PROJECT, manipulated

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows folders and junctions")


# ------------------------------------------------------------------ R37-1


@pytest.fixture
def linked(tmp_path: Path) -> Iterator[Path]:
    """``real\\a.txt``; ``vaultj7c2d`` a junction to ``real``; ``vaultp7c2d\\lnk`` one too."""
    real = tmp_path / "realq5k3"
    real.mkdir()
    (real / "a.txt").write_text("x", encoding="utf-8")
    plain = tmp_path / "vaultp7c2d"
    plain.mkdir()
    links = [tmp_path / "vaultj7c2d", plain / "lnk"]
    for link in links:
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(real)], check=True, capture_output=True
        )
    yield tmp_path
    for link in links:
        os.rmdir(link)  # the junction only, never what it points to


def _call_disk(text: str, env: dict[str, str]) -> tuple[Any, FakeBackend]:
    pol = policy(llm=True)
    auditor, backend = manipulated(pol)
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        {
            "hook_event_name": "PreToolUse",
            "session_id": "00000000-0000-4000-8000-0000000000a1",
            "cwd": WIN_PROJECT,
            "project_dir": WIN_PROJECT,
            "tool_name": "PowerShell",
            "tool_input": {"command": text},
        },
        mode="enforce",
        policy=pol,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": WIN_HOME, **env},
        home=WIN_HOME,
        scan_disk=True,
        auditor=auditor,
    )
    return decision, backend


@windows_only
@pytest.mark.parametrize(
    ("text", "folder", "mark"),
    [
        ("Get-Content $env:WORK_DIR\\*.txt", "vaultj7c2d", "vaultj7c2d"),  # the value is a link
        ("Set-Location $env:WORK_DIR; Get-Content *.txt", "vaultj7c2d", "vaultj7c2d"),
        ("Get-Content $env:WORK_DIR\\l*\\a.txt", "vaultp7c2d", "vaultp7c2d"),  # a link below it
    ],
)
def test_a_glob_match_through_a_link_is_left_out_with_its_disk_form(
    linked: Path, text: str, folder: str, mark: str
) -> None:
    decision, backend = _call_disk(text, {"WORK_DIR": str(linked / folder)})
    content = _content(backend)
    assert decision.decided_by == "llm"
    assert mark not in content.casefold()
    assert "realq5k3" not in content.casefold()
    assert "*" in _paths(content)[-1][-1]  # the glob as written


@windows_only
@pytest.mark.parametrize("changed", [False, True])
def test_a_secret_value_that_is_a_link_is_sent_without_it(linked: Path, changed: bool) -> None:
    # as written, revision 37 refused it (the disk form's text held the value); changed in form,
    # revision 37 sent it with the value
    value = str(linked / "vaultj7c2d")
    if changed:
        value = str(linked / "realq5k3" / ".." / "vaultj7c2d")
    decision, backend = _call_disk("Get-Content $env:VAULT_TOKEN\\*.txt", {"VAULT_TOKEN": value})
    content = _content(backend)
    assert decision.decided_by == "llm"
    assert "vaultj7c2d" not in content.casefold()
    assert _paths(content) == [["$env:VAULT_TOKEN\\*.txt"]]


@windows_only
def test_the_disk_form_of_a_glob_match_is_a_glob_match_too(linked: Path) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "00000000-0000-4000-8000-0000000000a2",
        "cwd": WIN_PROJECT,
        "project_dir": WIN_PROJECT,
        "tool_name": "PowerShell",
        "tool_input": {"command": "Get-Content $env:WORK_DIR\\*.txt"},
    }
    env = {"USERPROFILE": WIN_HOME, "WORK_DIR": str(linked / "vaultj7c2d")}
    actions = normalize_event(payload, platform="windows", env=env, home=WIN_HOME, budget_s=5)
    resolved = [r for a in actions for r in a.paths if "resolved-on-disk" in r.reasons]
    assert any("realq5k3" in r.key for r in resolved)
    assert all("glob-match" in r.reasons and EXPANDED in r.reasons for r in resolved)


@windows_only
def test_a_glob_match_through_a_link_without_a_variable_is_still_shown(linked: Path) -> None:
    folder = str(linked / "vaultj7c2d")
    _, backend = _call_disk(f"Get-Content '{folder}\\*.txt'", {})
    shown = _paths(_content(backend))[0]
    assert any(p.endswith("realq5k3/a.txt") for p in shown)


# ------------------------------------------------------------------ R37-2


@pytest.mark.parametrize(
    "text",
    [
        "Set-Location $env:PROJ_DIR; python gen.py",
        "Set-Location $PWD; python gen.py",
    ],
)
def test_the_event_cwd_reached_through_a_variable_gives_one_path(text: str) -> None:
    decision, backend = _call(text, {"PROJ_DIR": WIN_PROJECT})
    assert decision.decided_by == "llm"
    assert _paths(_content(backend))[1] == ["gen.py"]


def test_nine_paths_from_it_stay_under_the_limit() -> None:
    files = " ".join(f"t{i}.py" for i in range(1, 10))
    decision, backend = _call(
        f"Set-Location $env:PROJ_DIR; pytest {files}", {"PROJ_DIR": WIN_PROJECT}
    )
    assert decision.decided_by == "llm"
    assert _paths(_content(backend))[1] == [f"t{i}.py" for i in range(1, 10)]


@pytest.mark.parametrize(
    ("platform", "shown"),
    [
        ("windows", ["gen.py"]),  # Git Bash: the cwd's text is not its key
        ("posix", ["gen.py"]),  # the text is the key: one directory all along (a control)
    ],
)
def test_bash_cd_to_its_own_working_directory_gives_one_path(
    platform: str, shown: list[str]
) -> None:
    _, backend = _call('cd "$PWD" && python3 gen.py', {}, tool="Bash", platform=platform)
    assert _paths(_content(backend))[1] == shown


def test_another_directory_still_gives_two_paths() -> None:
    # the event's cwd and the expanded one are different directories: two places, two paths
    _, backend = _call("Set-Location $env:WORK_DIR; python gen.py", {"WORK_DIR": "D:\\w0rk"})
    assert _paths(_content(backend))[1] == ["<project>/gen.py", "gen.py"]


def test_the_marked_one_is_kept_when_a_written_directory_comes_after_it() -> None:
    # "..\gen.py" from the expanded "proj\a" and from the written "proj\b" after it is one path;
    # the marked one is kept, not the last one
    text = f"Set-Location $env:A_DIR; Set-Location {WIN_PROJECT}\\b; python ..\\gen.py"
    _, backend = _call(text, {"A_DIR": f"{WIN_PROJECT}\\a"})
    shown = _paths(_content(backend))[-1]
    assert "..\\gen.py" in shown
    assert "<project>/gen.py" not in shown


@windows_only
def test_refs_that_differ_in_more_than_the_mark_stay_two(linked: Path) -> None:
    # the event's cwd is the folder a link points to, and the link is reached through a variable:
    # "a.txt" read from the cwd and the link's form on disk have one key, not the same reasons
    real = str(linked / "realq5k3")
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "00000000-0000-4000-8000-0000000000a4",
        "cwd": real,
        "project_dir": real,
        "tool_name": "PowerShell",
        "tool_input": {"command": "Set-Location $env:WORK_DIR; Get-Content a.txt"},
    }
    env = {"USERPROFILE": WIN_HOME, "WORK_DIR": str(linked / "vaultj7c2d")}
    actions = normalize_event(payload, platform="windows", env=env, home=WIN_HOME, budget_s=5)
    same = [r for r in actions[-1].paths if r.key.casefold().endswith("realq5k3/a.txt")]
    found = sorted(("resolved-on-disk" in r.reasons, EXPANDED in r.reasons) for r in same)
    assert found == [(False, False), (True, True)]


# ------------------------------------------------------------------ R37-3


def _call_no_cwd(text: str, env: dict[str, str]) -> tuple[Any, FakeBackend]:
    pol = policy(llm=True)
    auditor, backend = manipulated(pol)
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        {
            "hook_event_name": "PreToolUse",
            "session_id": "00000000-0000-4000-8000-0000000000a3",
            "tool_name": "PowerShell",
            "tool_input": {"command": text},
        },
        mode="enforce",
        policy=pol,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": WIN_HOME, **env},
        home=WIN_HOME,
        scan_disk=False,
        auditor=auditor,
    )
    return decision, backend


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ("Set-Location $env:SECRETS_DIR; python D:gen.py", "D:gen.py"),
        ("Set-Location $env:SECRETS_DIR; Get-Content D:gen.py", "D:gen.py"),
        ("Set-Location $env:SECRETS_DIR; Get-Content \\gen.py", "\\gen.py"),  # only the drive
    ],
)
def test_a_drive_relative_path_from_an_expanded_first_directory_is_shown_as_written(
    text: str, shown: str
) -> None:
    decision, backend = _call_no_cwd(text, {"SECRETS_DIR": "D:\\vault\\prod01"})
    content = _content(backend)
    assert decision.decided_by == "llm"
    assert "vault" not in content.casefold()
    assert _paths(content)[1] == [shown]


def test_a_drive_relative_path_is_not_marked_without_an_expanded_directory() -> None:
    _, backend = _call_no_cwd("python D:gen.py", {})
    assert _paths(_content(backend)) == [["d:/gen.py"]]


def test_with_the_event_cwd_first_a_drive_relative_path_is_not_marked() -> None:
    # the event's cwd comes first and was not expanded: the path is read against it, as before
    _, backend = _call("Set-Location $env:WORK_DIR; python D:gen.py", {"WORK_DIR": "D:\\w0rk"})
    assert _paths(_content(backend))[1] == ["d:/gen.py"]
