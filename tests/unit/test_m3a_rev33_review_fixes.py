"""Spec revision 34: the home directory written as ``~`` in lists, after an option and after a UNC
form's neighbour (review of revision 33, docs/reviews/M3a-rev33-review.md).

R33-1. The rules record a list after an option as one path ("-Wl,-rpath,<home>,-z,now",
"-DCMAKE_PREFIX_PATH=<home>;..."), and revision 33 gave it the boundaries of a path, so the home
before "," ";" or ":" stayed with the user name in "args" and "flags". Now "," and ";" end a name in
a path, and so does ":" after a slash form.

R33-2. Revision 33 cut off any part that looked like an option, so "/c" in "/c/Users/<name>/x",
"-C:" in "-C:\\Users\\<name>\\x" or "/root" for the home /root cut a written home in two. Now no
written home may begin in the part cut off, and a "/" option takes no path beginning with "/".

R33-3. The backslashed UNC forms took the left boundary of a drive form, so "C:\\\\server\\..." (a
folder on C:) and ".\\\\server\\..." became "~". Now ":", ".", "\\", "/" and "~" before them mean
another path.

R33-4 changed the spec text only (pinned below).

Nothing is run: the helper only parses, the model is a fake one.
"""

from __future__ import annotations

import json

import pytest

from .test_m3a_pipeline import HOME
from .test_m3a_rev29_review_fixes import _ps
from .test_m3a_rev31_review_fixes import GIT_BASH_HOME, NAME, _as_path, _git_bash
from .test_m3a_rev32_review_fixes import (
    UNC_FORWARD,
    UNC_HOME,
    _no_name,
    _shown,
    _unc_call,
    _with_paths,
)
from .test_m3a_x1_fixes import WIN_HOME

UNC_ESCAPED = f"\\\\\\\\server\\\\share\\\\{NAME}"


# --- R33-1: a list of paths -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("written", "home", "shown"),
    [
        (f"{WIN_HOME},old\\notes.txt", WIN_HOME, "~,old\\notes.txt"),
        (f"{WIN_HOME};x\\notes.txt", WIN_HOME, "~;x\\notes.txt"),
        (f"{WIN_HOME}.;D:\\x", WIN_HOME, "~.;D:\\x"),  # Win32 drops the dot of the first one
        (f"{GIT_BASH_HOME}:old/notes.txt", WIN_HOME, "~:old/notes.txt"),
        (f"{GIT_BASH_HOME}:/opt/x.jar", WIN_HOME, "~:/opt/x.jar"),
        (f"{GIT_BASH_HOME},x", WIN_HOME, "~,x"),
        (f"{HOME}:old/y", HOME, "~:old/y"),
        (f"{HOME};x", HOME, "~;x"),
        (f"{HOME},x", HOME, "~,x"),
        (f"{UNC_HOME};x", UNC_HOME, "~;x"),
        (f"{UNC_FORWARD}:x", UNC_HOME, "~:x"),
    ],
)
def test_a_list_separator_ends_the_home_in_a_path(written: str, home: str, shown: str) -> None:
    assert _as_path(written, home=home)[0] == shown


@pytest.mark.parametrize(
    "written",
    [
        f"{WIN_HOME} Smith\\notes.txt",
        f"{WIN_HOME}(2)\\notes.txt",
        f"{WIN_HOME}'2\\notes.txt",
        f"{GIT_BASH_HOME} Smith/notes.txt",
        f"{HOME} x/y",
    ],
)
def test_a_space_a_quote_or_a_bracket_is_still_part_of_the_name(written: str) -> None:
    home = HOME if written.startswith(HOME) else WIN_HOME
    assert _as_path(written, home=home)[0] == written


def test_an_expanded_path_ends_at_a_list_separator_too() -> None:
    assert _as_path(f"{WIN_HOME};$TOKEN", expanded=True)[1] == "~;$TOKEN"
    assert _as_path(f"{WIN_HOME} Smith;$TOKEN", expanded=True)[1] == f"{WIN_HOME} Smith;$TOKEN"


@pytest.mark.parametrize(
    ("word", "raw", "home", "shown"),
    [
        (
            f"-Wl,-rpath,{GIT_BASH_HOME},-z,now",
            f",-rpath,{GIT_BASH_HOME},-z,now",
            WIN_HOME,
            "-Wl,-rpath,~,-z,now",
        ),
        (
            f"-Wl,-rpath,{WIN_HOME},-z,now",
            f",-rpath,{WIN_HOME},-z,now",
            WIN_HOME,
            "-Wl,-rpath,~,-z,now",
        ),
        (
            f"-DCMAKE_PREFIX_PATH={GIT_BASH_HOME};/opt/b",
            f"_PREFIX_PATH={GIT_BASH_HOME};/opt/b",
            WIN_HOME,
            "-DCMAKE_PREFIX_PATH=~;/opt/b",
        ),
        (f"-I{GIT_BASH_HOME}:/opt/inc", f"{GIT_BASH_HOME}:/opt/inc", WIN_HOME, "-I~:/opt/inc"),
        (
            f"-Wl,-rpath,{UNC_HOME},-z,now",
            f",-rpath,{UNC_HOME},-z,now",
            UNC_HOME,
            "-Wl,-rpath,~,-z,now",
        ),
        # a sibling whose name holds a comma: shown as "~,x", the cost (spec revision 34)
        (f"--directory={GIT_BASH_HOME},x", f"{GIT_BASH_HOME},x", WIN_HOME, "--directory=~,x"),
        # a space is still part of the name
        (f"--directory={GIT_BASH_HOME} Smith/src", f"{GIT_BASH_HOME} Smith/src", WIN_HOME, None),
    ],
)
def test_a_list_after_an_option(word: str, raw: str, home: str, shown: str | None) -> None:
    action = _with_paths(args=(word,), flags=(word,), raws=(raw,), home=home)
    assert action["args"] == [shown or word]
    assert action["flags"] == [shown or word]


def test_a_list_after_an_option_in_a_real_git_bash_call() -> None:
    payload = _git_bash(f"gcc -Wl,-rpath,{GIT_BASH_HOME},-z,now a.c")
    assert payload["command"] == "gcc -Wl,-rpath,~,-z,now a.c"
    (action,) = payload["actions"]
    assert "-Wl,-rpath,~,-z,now" in action["args"]
    assert "-Wl,-rpath,~,-z,now" in action["flags"]
    # "paths" is the rules' reading (one relative path under the project): it keeps the name
    assert not _no_name(action["paths"])
    assert _no_name({k: v for k, v in action.items() if k != "paths"})


def test_a_cmake_list_in_a_real_powershell_call() -> None:
    payload = _ps(f"cmake '-DCMAKE_PREFIX_PATH={WIN_HOME};C:\\x' .")
    (action,) = payload["actions"]
    assert "-DCMAKE_PREFIX_PATH=~;C:\\x" in action["args"]
    assert payload["command"] == "cmake '-DCMAKE_PREFIX_PATH=~;C:\\x' ."


def test_a_unc_home_in_a_linker_list_in_a_real_powershell_call() -> None:
    """Sent: the rules read the list as a relative path, not as a UNC path."""
    payload = _unc_call(f"gcc '-Wl,-rpath,{UNC_HOME},-z,now' a.c")
    (action,) = payload["actions"]
    assert "-Wl,-rpath,~,-z,now" in action["args"]
    assert payload["command"] == "gcc '-Wl,-rpath,~,-z,now' a.c"


def test_a_sibling_with_a_comma_is_shown_as_the_home_in_a_real_git_bash_call() -> None:
    """The cost of R33-1: the word says "~,old", the path is another directory."""
    payload = _git_bash(f"cat '{GIT_BASH_HOME},old/notes.txt'")
    (action,) = [a for a in payload["actions"] if a.get("program") == "cat"]
    assert action["args"] == ["~,old/notes.txt"]
    assert all(not p["path"].startswith("~") for p in action["paths"])


# --- R33-2: where an option is cut off --------------------------------------------------------


@pytest.mark.parametrize(
    ("word", "raw", "home", "shown"),
    [
        (f"{GIT_BASH_HOME}/x", f"/Users/{NAME}/x", WIN_HOME, "~/x"),  # "/c" is not an option
        (f"/cygdrive{GIT_BASH_HOME}/x", f"{GIT_BASH_HOME}/x", WIN_HOME, "~/x"),
        (f"/mnt{GIT_BASH_HOME}/x", f"{GIT_BASH_HOME}/x", WIN_HOME, "~/x"),
        (f"-{WIN_HOME}\\x", f"\\Users\\{NAME}\\x", WIN_HOME, "-~\\x"),  # "-C:" is not either
        ("/root/tmp/x", "/tmp/x", "/root", "~/tmp/x"),  # "/root" is the home
    ],
)
def test_an_option_is_not_cut_off_inside_a_written_home(
    word: str, raw: str, home: str, shown: str
) -> None:
    assert _with_paths(args=(word,), flags=(word,), raws=(raw,), home=home)["args"] == [shown]


@pytest.mark.parametrize(
    ("word", "raw", "home", "shown"),
    [
        (f"/srv{HOME}/x", f"{HOME}/x", HOME, None),  # another path, as revision 32
        (f"/I{GIT_BASH_HOME}/inc", f"{GIT_BASH_HOME}/inc", WIN_HOME, None),  # the cost
        (f"/Fo{WIN_HOME}\\build\\", f"{WIN_HOME}\\build\\", WIN_HOME, "/Fo~\\build\\"),
        (f"/I{UNC_HOME}\\inc", f"{UNC_HOME}\\inc", UNC_HOME, "/I~\\inc"),
        (f"-isystem{GIT_BASH_HOME}/inc", f"{GIT_BASH_HOME}/inc", WIN_HOME, "-isystem~/inc"),
    ],
)
def test_a_slash_option_takes_no_path_that_begins_with_a_slash(
    word: str, raw: str, home: str, shown: str | None
) -> None:
    assert _with_paths(args=(word,), raws=(raw,), home=home)["args"] == [shown or word]


def test_a_word_not_cut_off_is_shown_like_the_command_text() -> None:
    """The option "-C:" is not cut off (the home begins in it), so the whole word has the boundaries
    of the command text, where a space ends the name: shown too often, as a word that is no path."""
    word = f"-{WIN_HOME} Smith\\x"
    raw = f"\\Users\\{NAME} Smith\\x"
    assert _with_paths(args=(word,), raws=(raw,))["args"] == ["-~ Smith\\x"]


def test_the_option_part_is_kept_as_written() -> None:
    """Nothing is replaced in the part cut off: "/root" is the home /root, but "/rootx" is another
    name, and "x" is the path."""
    assert _with_paths(args=("/rootx",), raws=("x",), home="/root")["args"] == ["/rootx"]


@pytest.mark.parametrize(
    "command",
    [
        f"echo {GIT_BASH_HOME}/x > /Users/{NAME}/x",
        f"echo /cygdrive{GIT_BASH_HOME}/x > {GIT_BASH_HOME}/x",
        f"echo /mnt{GIT_BASH_HOME}/x > {GIT_BASH_HOME}/x",
    ],
)
def test_a_written_home_is_not_cut_in_a_real_git_bash_call(command: str) -> None:
    payload = _git_bash(command)
    (action,) = [a for a in payload["actions"] if a.get("program") == "echo"]
    assert action["args"] == ["~/x"]


# --- R33-3: the left boundary of a backslashed UNC form ---------------------------------------


@pytest.mark.parametrize(
    "written",
    [
        f"C:{UNC_HOME}\\x",  # a folder on C:
        f".{UNC_HOME}\\x",  # a relative path
        f"\\{UNC_HOME}\\x",
        f"~{UNC_HOME}\\x",
        f"x\\{UNC_HOME}\\x",
        f"/{UNC_HOME}\\x",
    ],
)
def test_a_unc_form_after_another_character_is_another_path(written: str) -> None:
    assert _shown(written, home=UNC_HOME) == (written, written)
    assert _with_paths(args=(written,), raws=(written,), home=UNC_HOME)["args"] == [written]


@pytest.mark.parametrize(
    ("written", "shown"),
    [
        (f"={UNC_HOME}\\x", "=~\\x"),
        (f"({UNC_HOME})", "(~)"),
        (f'"{UNC_HOME}\\x"', '"~\\x"'),
        (f"a,{UNC_HOME}\\x", "a,~\\x"),
        (f"/I{UNC_HOME}\\inc", "/I~\\inc"),
        (f"-L{UNC_HOME}\\lib", "-L~\\lib"),
        (f"{UNC_ESCAPED}\\\\x", "~\\\\x"),
    ],
)
def test_a_unc_form_after_a_boundary_or_an_option_is_still_the_home(
    written: str, shown: str
) -> None:
    assert _shown(written, home=UNC_HOME) == (shown, shown)


def test_a_unc_form_after_a_drive_in_a_real_powershell_call() -> None:
    payload = _unc_call(f"make release # C:{UNC_HOME}\\x and {UNC_HOME}\\x")
    assert payload["command"] == f"make release # C:{UNC_HOME}\\x and ~\\x"


def test_an_escaped_unc_form_in_a_path_word_is_replaced_too_often() -> None:
    """Written as it is in a path, the escaped form is "\\\\\\server\\..." to Win32; it is still
    shown as the home (spec revision 34)."""
    written = f"{UNC_ESCAPED}\\\\x"
    assert _with_paths(args=(written,), raws=(written,), home=UNC_HOME)["args"] == ["~\\\\x"]


def test_a_url_to_the_same_server_is_replaced_too_often() -> None:
    assert _shown("http://server/share/testuser/x", home=UNC_HOME) == ("http:~/x", "http:~/x")


# --- R33-4: the spec text only (the behaviour is pinned) --------------------------------------


@pytest.mark.parametrize(
    "written",
    [
        f"\\\\?\\UNC\\server\\share\\{NAME}\\x",
        f"//?/UNC/server/share/{NAME}/x",
        f"\\\\.\\UNC\\server\\share\\{NAME}\\x",
        f"\\\\server\\share/{NAME}/x",
        f"//server/share\\{NAME}\\x",
        f"{UNC_FORWARD}\\x",  # the home in PowerShell; "\" escapes in Git Bash
    ],
)
def test_unc_forms_the_spec_lists_as_not_replaced(written: str) -> None:
    assert _shown(written, home=UNC_HOME) == (written, written)
    assert NAME in json.dumps(_shown(written, home=UNC_HOME))
