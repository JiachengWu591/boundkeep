"""Spec revision 35: the home directory written as ``~`` after a colon, and where an option is
cut off (review of revision 34, docs/reviews/M3a-rev34-review.md).

R34-1. Revision 34 refused any ":" before a backslashed UNC form, so after "/OUT:", "/LIBPATH:",
"-Path:" or "FileSystem::" the home stayed with the user name in "command", "args" and "flags".
Now only a drive's colon ("C:\\\\server\\...", a folder on C:) means another path, and a glued
option may end with ":".

R34-3. A path text that begins inside an option glued to a written home ("-t" in the rules' reading
of "cp -isystem<home>/inc") was cut there and kept the name. Now the cut may not fall inside it.

R34-2 changed the spec text only (pinned below).

Nothing is run: the helper only parses, the model is a fake one.
"""

from __future__ import annotations

import pytest

from .test_m3a_pipeline import HOME
from .test_m3a_rev29_review_fixes import _bash
from .test_m3a_rev31_review_fixes import GIT_BASH_HOME, NAME
from .test_m3a_rev32_review_fixes import UNC_HOME, _no_name, _shown, _unc_call, _with_paths
from .test_m3a_x1_fixes import WIN_HOME

UNC_ESCAPED = f"\\\\\\\\server\\\\share\\\\{NAME}"


# --- R34-1: a UNC home after a colon ----------------------------------------------------------


@pytest.mark.parametrize(
    ("written", "shown"),
    [
        (f"/OUT:{UNC_HOME}\\a.exe", "/OUT:~\\a.exe"),
        (f"/LIBPATH:{UNC_HOME}\\lib", "/LIBPATH:~\\lib"),
        (f"/Fe:{UNC_HOME}\\a.exe", "/Fe:~\\a.exe"),
        (f"/F:{UNC_HOME}\\list.txt", "/F:~\\list.txt"),  # findstr: one letter
        (f"/LOG+:{UNC_HOME}\\log.txt", "/LOG+:~\\log.txt"),
        (f"-Path:{UNC_HOME}\\x", "-Path:~\\x"),
        (f"FileSystem::{UNC_HOME}\\x", "FileSystem::~\\x"),
        (f"path:{UNC_HOME}\\x", "path:~\\x"),  # a word and a colon: no drive
        (
            f"Microsoft.PowerShell.Core\\FileSystem::{UNC_HOME}",
            "Microsoft.PowerShell.Core\\FileSystem::~",
        ),
        (f"/OUT:{UNC_ESCAPED}\\\\a.exe", "/OUT:~\\\\a.exe"),
    ],
)
def test_a_unc_home_after_a_colon_that_is_no_drive_is_the_home(written: str, shown: str) -> None:
    assert _shown(written, home=UNC_HOME) == (shown, shown)
    assert _with_paths(args=(written,), raws=(written,), home=UNC_HOME)["args"] == [shown]


@pytest.mark.parametrize(
    "written",
    [
        f"C:{UNC_HOME}\\x",  # a folder on C:
        f"c:{UNC_HOME}\\x",
        f'"C:{UNC_HOME}\\x"',
        f"=C:{UNC_HOME}\\x",
        f"(D:{UNC_HOME}\\x",
        f"C:{UNC_ESCAPED}\\\\x",
    ],
)
def test_a_unc_form_after_a_drive_colon_is_still_another_path(written: str) -> None:
    assert _shown(written, home=UNC_HOME) == (written, written)
    if not written.startswith(('"', "=", "(")):
        assert _with_paths(args=(written,), raws=(written,), home=UNC_HOME)["args"] == [written]


@pytest.mark.parametrize(
    ("written", "shown"),
    [(f"-C:{UNC_HOME}\\x", "-C:~\\x"), (f"/C:{UNC_HOME}\\x", "/C:~\\x")],
)
def test_one_letter_and_a_colon_that_look_like_an_option_are_an_option(
    written: str, shown: str
) -> None:
    """The cost (spec revision 35): read as a path, it is "C:" and then "\\server\\...", not the
    home; shown as the home, like "/F:"."""
    assert _shown(written, home=UNC_HOME) == (shown, shown)


@pytest.mark.parametrize(
    ("written", "shown"),
    [
        (f"/OUT:{WIN_HOME}\\a.exe", "/OUT:~\\a.exe"),
        (f"FileSystem::{WIN_HOME}\\x", "FileSystem::~\\x"),
        (f"-Path:{WIN_HOME}\\x", "-Path:~\\x"),
    ],
)
def test_a_drive_home_after_a_colon_is_unchanged(written: str, shown: str) -> None:
    assert _shown(written, home=WIN_HOME) == (shown, shown)


@pytest.mark.parametrize(
    ("command", "shown"),
    [
        (f"link /OUT:{UNC_HOME}\\a.exe a.obj", "/OUT:~\\a.exe"),
        (f"link /LIBPATH:{UNC_HOME}\\lib a.obj", "/LIBPATH:~\\lib"),
        (f"cl /Fe:{UNC_HOME}\\a.exe a.c", "/Fe:~\\a.exe"),
    ],
)
def test_a_unc_home_after_a_colon_option_in_a_real_powershell_call(
    command: str, shown: str
) -> None:
    """Sent: the rules read "/OUT:..." as a path on the current drive, not as a UNC path."""
    payload = _unc_call(command)
    (action,) = payload["actions"]
    assert shown in action["args"]
    assert payload["command"] == command.replace(UNC_HOME, "~")
    # "paths" is the rules' reading ("c:/out/server/share/<name>/a.exe"): it keeps the name
    assert _no_name({k: v for k, v in action.items() if k != "paths"})


def test_a_glued_colon_option_in_flags_in_a_real_powershell_call() -> None:
    payload = _unc_call(f"gcc '-o:{UNC_HOME}\\a.exe' a.c")
    (action,) = payload["actions"]
    assert "-o:~\\a.exe" in action["flags"]
    assert "-o:~\\a.exe" in action["args"]


def test_a_unc_home_after_a_colon_option_in_a_real_git_bash_call() -> None:
    payload = _unc_call(f"link.exe '/OUT:{UNC_HOME}\\a.exe' a.obj", tool="Bash")
    (action,) = payload["actions"]
    assert "/OUT:~\\a.exe" in action["args"]
    assert payload["command"] == "link.exe '/OUT:~\\a.exe' a.obj"


@pytest.mark.parametrize(
    "command",
    [
        f"make release # then link /OUT:{UNC_HOME}\\a.exe",
        f"python -c \"print(r'FileSystem::{UNC_HOME}\\x')\"",
    ],
)
def test_a_unc_home_after_a_colon_in_a_comment_or_a_string_sends_no_user_name(command: str) -> None:
    payload = _unc_call(command)
    assert _no_name(payload["command"])
    assert _no_name(payload["actions"])


# --- R34-3: the cut does not fall inside an option glued to a written home ---------------------


@pytest.mark.parametrize(
    ("word", "raw", "home", "shown"),
    [
        # the rules read "-t" of "cp -isystem<home>/inc" as "em<home>/inc"
        (f"-isystem{HOME}/inc", f"em{HOME}/inc", HOME, "-isystem~/inc"),
        (f"-IxC:{WIN_HOME[2:]}\\y", f"xC:{WIN_HOME[2:]}\\y", WIN_HOME, "-Ix~\\y"),
        (f"/FoxC:{WIN_HOME[2:]}\\y", f"xC:{WIN_HOME[2:]}\\y", WIN_HOME, "/Fox~\\y"),
        (f"-Ix{UNC_HOME}\\y", f"x{UNC_HOME}\\y", UNC_HOME, "-Ix~\\y"),
    ],
)
def test_the_cut_does_not_fall_inside_an_option_glued_to_a_written_home(
    word: str, raw: str, home: str, shown: str
) -> None:
    action = _with_paths(args=(word,), flags=(word,), raws=(raw,), home=home)
    assert action["args"] == [shown]
    assert action["flags"] == [shown]


@pytest.mark.parametrize(
    ("word", "raw", "home", "shown"),
    [
        (f"-isystem{HOME}/inc", f"{HOME}/inc", HOME, "-isystem~/inc"),
        (f"-isystem{HOME} Smith/inc", f"{HOME} Smith/inc", HOME, None),  # a sibling
        (f"-cf{HOME}/x.tar", f"{HOME}/x.tar", HOME, "-cf~/x.tar"),
        (f"/Fo{WIN_HOME}\\build\\", f"{WIN_HOME}\\build\\", WIN_HOME, "/Fo~\\build\\"),
        (f"-I{UNC_HOME}\\inc", f"{UNC_HOME}\\inc", UNC_HOME, "-I~\\inc"),
        (f"/OUT:{UNC_HOME}\\a.exe", f"{UNC_HOME}\\a.exe", UNC_HOME, "/OUT:~\\a.exe"),
        (f"/OUT:{UNC_HOME} Smith\\a.exe", f"{UNC_HOME} Smith\\a.exe", UNC_HOME, None),
    ],
)
def test_a_cut_at_the_end_of_the_glued_option_is_still_made(
    word: str, raw: str, home: str, shown: str | None
) -> None:
    assert _with_paths(args=(word,), raws=(raw,), home=home)["args"] == [shown or word]


def test_a_relative_path_the_rules_read_after_part_of_a_glued_option_is_shown_as_the_home() -> None:
    """The cost (spec revision 35): ``--o`` and the relative ``x/c/Users/<name>/y`` to the rules,
    ``--ox`` glued to the home in the command text. The longest path text would cut inside
    ``--ox``, so the next one is taken, and the word is shown like the command text."""
    word = f"--ox{GIT_BASH_HOME}/y"
    raws = (f"{GIT_BASH_HOME}/y", f"x{GIT_BASH_HOME}/y")
    assert _with_paths(args=(word,), raws=raws)["args"] == ["--ox~/y"]


def test_a_glued_option_the_rules_split_in_a_real_bash_call() -> None:
    payload = _bash(f"cp -isystem{HOME}/inc a.c")
    assert payload["command"] == "cp -isystem~/inc a.c"
    (action,) = payload["actions"]
    assert action["args"][0] == "-isystem~/inc"
    assert "-isystem~/inc" in action["flags"]
    # "paths" is the rules' reading ("<project>/em/home/<name>/inc"): it keeps the name
    assert _no_name({k: v for k, v in action.items() if k != "paths"})


# --- R34-2: the spec text only (the behaviour is pinned) --------------------------------------


def test_path_boundaries_find_more_only_where_the_result_is_the_same() -> None:
    """The option part "/cyg" is part of the first part of "/cygdrive/c/...": only a path ends at
    "\\" after a slash form. Cut there or not, nothing is replaced ("\\" escapes in Git Bash)."""
    word = f"/cygdrive{GIT_BASH_HOME}\\x"
    assert _with_paths(args=(word,), raws=(f"drive{GIT_BASH_HOME}\\x",))["args"] == [word]


def test_an_extended_unc_form_glued_to_an_option_is_sent_as_written() -> None:
    """The rules read it as a local path, so it is sent; "\\\\?\\UNC\\..." is not replaced."""
    payload = _unc_call(f"link /OUT:\\\\?\\UNC\\server\\share\\{NAME}\\x.exe a.obj")
    assert not _no_name(payload["command"])


def test_a_class_path_list_in_a_real_posix_bash_call() -> None:
    """ "args" has "~:/x"; "paths" is the rules' reading (a sibling "<name>:"), with the name."""
    payload = _bash(f"java -cp {HOME}:/x Main")
    (action,) = payload["actions"]
    assert "~:/x" in action["args"]
    assert not _no_name(action["paths"])
