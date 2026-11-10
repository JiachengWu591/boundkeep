"""Spec revision 19 (review R18-4, docs/reviews/M3a-rev18-review.md): a program run by a path whose
last segment is an 8.3 short name that the disk layer cannot expand is gray
``program-short-name-unresolved`` and is not sent to the model, like a bare short name.

Measured: after ``cd`` into a short-named directory the guard does not know the working directory,
yet Git Bash runs ``./LONGPR~1`` and ``./LONGPR~1.EXE`` there, and PowerShell 5.1 runs
``.\\LONGPR~1.EXE`` after ``Set-Location``. Before, these were gray ``cwd-unknown`` and sent to
the model, while the same command in the long-named directory was denied.

The tests use made-up files under ``tmp_path``; nothing is run.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from boundkeep.daemon import pipeline
from boundkeep.normalize import event
from boundkeep.normalize.model import Word

from .test_m3a_rev17_review_fixes import CLEAN, _msys, _result, _short_path

UNRESOLVED = "program-short-name-unresolved"


def _grays(result: pipeline.Review) -> list[str]:
    return [r for a in result.actions for r in a.gray_reasons]


@pytest.fixture
def tools(tmp_path: Path) -> tuple[Path, str]:
    """(the long directory, its 8.3 short path) of a made-up ``boundkeep.exe``."""
    if sys.platform != "win32":
        pytest.skip("8.3 short names are a Windows thing")
    directory = tmp_path / "longtoolsdirectory"
    directory.mkdir()
    (directory / "boundkeep.exe").write_bytes(b"MZ")
    short = _short_path(directory / "boundkeep.exe")
    if not re.search(r"~\d+\\BOUNDK~\d+\.EXE$", short, re.IGNORECASE):
        pytest.skip("this volume makes no 8.3 short names")
    return directory, short.rsplit("\\", 1)[0]


def _check_unresolved(result: pipeline.Review, command: str) -> None:
    assert str(result.verdict.decision) != "allow", command
    assert UNRESOLVED in _grays(result), (command, _grays(result))
    assert pipeline.unshown_input(result.actions) is not None, command


# --- R18-4: after cd into a short-named directory ------------------------------------------------


@pytest.mark.windows
@pytest.mark.parametrize("program", ["./BOUNDK~1", "./BOUNDK~1.EXE"])
def test_git_bash_in_a_short_named_directory_is_not_sent_to_the_model(
    tmp_path: Path, tools: tuple[Path, str], program: str
) -> None:
    _long, short_dir = tools
    command = f"cd '{_msys(short_dir)}' && {program} mode audit-only"
    _check_unresolved(_result(tmp_path / "w", CLEAN, command, tool="Bash"), command)


@pytest.mark.windows
def test_powershell_in_a_short_named_directory_is_not_sent_to_the_model(
    tmp_path: Path, tools: tuple[Path, str]
) -> None:
    _long, short_dir = tools
    command = f"Set-Location '{short_dir}'; .\\BOUNDK~1.EXE mode audit-only"
    _check_unresolved(_result(tmp_path / "w", CLEAN, command, tool="PowerShell"), command)


@pytest.mark.windows
@pytest.mark.parametrize(
    ("tool", "template"),
    [
        ("Bash", "cd '{msys}' && ./BOUNDK~1 mode audit-only"),
        ("PowerShell", "Set-Location '{win}'; .\\BOUNDK~1.EXE mode audit-only"),
    ],
)
def test_in_the_long_named_directory_it_is_still_denied(
    tmp_path: Path, tools: tuple[Path, str], tool: str, template: str
) -> None:
    long_dir, _short = tools
    command = template.format(msys=_msys(str(long_dir)), win=str(long_dir))
    result = _result(tmp_path / "w", CLEAN, command, tool=tool)
    assert str(result.verdict.decision) == "deny", (command, _grays(result))
    assert "deny-boundkeep-state-commands" in result.verdict.rule_ids
    assert UNRESOLVED not in _grays(result)


# --- the other ways a short name by a path cannot be expanded ------------------------------------


@pytest.mark.windows
@pytest.mark.parametrize(
    ("tool", "command"),
    [
        # the directory is a variable the path layer does not resolve
        ("Bash", '"$TOOLS/BOUNDK~1" mode audit-only'),
        ("PowerShell", '& "$tools\\BOUNDK~1.EXE" mode audit-only'),
        # a glob in the directory
        ("Bash", "/c/long*/BOUNDK~1 mode audit-only"),
        # no such file
        ("Bash", "'{missing}/NOSUCH~1' mode audit-only"),
        ("PowerShell", "& '{missing_win}\\NOSUCH~1.EXE' mode audit-only"),
    ],
)
def test_a_short_name_the_disk_layer_cannot_expand_is_not_sent(
    tmp_path: Path, tools: tuple[Path, str], tool: str, command: str
) -> None:
    long_dir, _short = tools
    command = command.format(missing=_msys(str(long_dir)), missing_win=str(long_dir))
    _check_unresolved(_result(tmp_path / "w", CLEAN, command, tool=tool), command)


@pytest.mark.windows
@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
def test_a_short_name_that_expands_keeps_its_long_name(
    tmp_path: Path, tools: tuple[Path, str], tool: str
) -> None:
    _long, short_dir = tools
    path = _msys(short_dir) if tool == "Bash" else short_dir
    sep = "/" if tool == "Bash" else "\\"
    command = f"& '{path}{sep}BOUNDK~1.EXE' mode audit-only"
    if tool == "Bash":
        command = command[2:]
    result = _result(tmp_path / "w", CLEAN, command, tool=tool)
    assert str(result.verdict.decision) == "deny", (command, _grays(result))
    assert "program-short-name" in _grays(result)
    assert UNRESOLVED not in _grays(result)


# --- what is not a short name as written -----------------------------------------------------


def _ctx(platform: str) -> SimpleNamespace:
    return SimpleNamespace(platform=platform)


@pytest.mark.parametrize(
    "text",
    [
        "./BOUNDK~1",
        "./BOUNDK~1.EXE",
        "C:\\tools\\boundk~1.exe",
        "$DIR/BOUNDK~1",
        "/c/t*/BOUNDK~1",
        "./BOUNDK~1.EXE. ",  # trailing dot and space, which Windows drops (revision 16)
    ],
)
def test_a_literal_short_last_segment_counts(text: str) -> None:
    assert event._short_named_path(_ctx("windows"), Word(text))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "text",
    [
        "BOUNDK~1",  # bare: revision 18 handles it, in Git Bash only
        "./boundkeep.exe",
        "./script.sh",
        "./a~b",
        "./LONGPR~1.toolong",  # an extension longer than three is no short name
        "./$NAME~1",  # a variable in the last segment
        "./BOUND*~1",  # a glob in the last segment
        "./BOUNDK~?",
    ],
)
def test_other_names_do_not_count(text: str) -> None:
    assert not event._short_named_path(_ctx("windows"), Word(text))  # type: ignore[arg-type]


def test_powershell_dynamic_command_names_are_unwrapped() -> None:
    # pscmd wraps a command name it cannot read as ``$(<text>)``; the text inside was written
    wrapped = Word("$($tools\\BOUNDK~1.EXE)", expands=True)
    assert event._short_named_path(_ctx("windows"), wrapped, "powershell")  # type: ignore[arg-type]
    assert not event._short_named_path(_ctx("windows"), Word("$($p)"), "powershell")  # type: ignore[arg-type]
    # only PowerShell's words are wrapped so: in bash the ``)`` is part of the last segment
    assert not event._short_named_path(_ctx("windows"), wrapped, "bash")  # type: ignore[arg-type]


def test_only_on_windows() -> None:
    assert not event._short_named_path(_ctx("linux"), Word("./BOUNDK~1"))  # type: ignore[arg-type]
    assert not event._short_named_path(_ctx("macos"), Word("./BOUNDK~1"))  # type: ignore[arg-type]


@pytest.mark.windows
def test_ordinary_commands_are_not_affected(tmp_path: Path) -> None:
    for tool, command in (
        ("Bash", "git status"),
        ("Bash", "./scripts/build.sh"),
        ("PowerShell", ".\\scripts\\build.ps1"),
        ("Bash", "ls ~1"),
    ):
        grays = _grays(_result(tmp_path / "w", CLEAN, command, tool=tool))
        assert UNRESOLVED not in grays, command
