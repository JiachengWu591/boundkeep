"""Spec revision 32: where the home directory written as ``~`` begins and ends (review of revision
31, docs/reviews/M3a-rev31-review.md).

R31-1. Revision 31 took only one option letter just before the home directory as a beginning and
any ``.`` after it as part of a longer name, so ``-isystem/home/me``, ``/FoC:\\Users\\me\\build\\``
and ``C:\\Users\\me.\\notes.txt`` (the home itself to Win32) went out with the user's name, where
they were replaced before revision 31. Now an option of letters after ``-``, ``--`` (or ``/``
before a drive) that begins a word, and a single dot before a separator or the end.

R31-2. Some characters revision 31 took as an end go on with the name: Bash's brace expansion, the
wildcards ``[ ]`` and, after a slash form, Bash's ``\\`` escape; and in a word the rules read as one
path, a space, a quote, a parenthesis or a comma is part of the name. Now a command text, or a word
that is not one path, ends without those; a word that is one path ends only at a separator or its
end (and, after a drive, at a colon or a single trailing dot).

R31-3 and R31-4 changed the spec text only (pinned below).

Nothing is run: the helper only parses, the model is a fake one.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.audit import send_gate
from boundkeep.daemon import pipeline
from boundkeep.normalize.model import Action, PathRef
from boundkeep.session.facts import FRESH

from .test_m3a_pipeline import HOME, policy
from .test_m3a_rev29_review_fixes import _ps, _sent
from .test_m3a_x1_fixes import WIN_HOME, WIN_PROJECT, manipulated

NAME = "testuser"  # the user name in WIN_HOME and HOME
assert f"C:\\Users\\{NAME}" == WIN_HOME
assert f"/home/{NAME}" == HOME
GIT_BASH_HOME = f"/c/Users/{NAME}"


def _payload(action: Action, *, home: str) -> dict[str, Any]:
    gated = send_gate.gate(
        [action], tool="Bash", facts=FRESH, send_task_intent=False, intent_prompts=1, home=home
    )
    assert gated.request is not None, gated.refused
    assert gated.payload is not None
    return gated.payload


def _shown(written: str, *, home: str = WIN_HOME) -> tuple[str, str]:
    """``written`` as the request shows it in a comment of the command text and as a word that the
    rules did not read as a path."""
    action = Action(
        tool="Bash",
        platform="windows",
        program="make",
        command_text=f"make release # {written}",
        args=(written,),
    )
    payload = _payload(action, home=home)
    (word,) = payload["actions"][0]["args"]
    return payload["command"][len("make release # ") :], word


def _as_path(written: str, *, home: str = WIN_HOME, expanded: bool = False) -> tuple[str, str]:
    """``written`` as one word the rules read as one path: (the word in args, the path shown)."""
    flavor = "posix" if home.startswith("/") else "windows"
    ref = PathRef(
        raw=written,
        key="c:/elsewhere/x" if flavor == "windows" else "/elsewhere/x",
        flavor=flavor,
        access="read",
        reasons=("variable-expanded",) if expanded else (),
    )
    action = Action(
        tool="Bash",
        platform="windows",
        program="cat",
        command_text="cat x",
        args=(written,),
        paths=(ref,),
    )
    actions = _payload(action, home=home)["actions"]
    (word,) = actions[0]["args"]
    ((path,),) = [[p["path"] for p in a["paths"]] for a in actions]
    return word, path


def _git_bash(command: str) -> dict[str, Any]:
    """A real Bash call on Windows (Git Bash), sent to a fake model."""
    pol = policy(llm=True)
    auditor, backend = manipulated(pol)
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        {
            "hook_event_name": "PreToolUse",
            "session_id": "00000000-0000-4000-8000-0000000000dd",
            "cwd": WIN_PROJECT,
            "project_dir": WIN_PROJECT,
            "tool_name": "Bash",
            "tool_input": {"command": command},
        },
        mode="enforce",
        policy=pol,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": WIN_HOME},
        home=WIN_HOME,
        scan_disk=False,
        auditor=auditor,
    )
    return _sent(decision, backend)


def _no_name(payload: dict[str, Any]) -> bool:
    return NAME not in json.dumps(payload).lower()


# --- R31-1: an option glued to it -------------------------------------------------------------


@pytest.mark.parametrize(
    ("written", "shown"),
    [
        (f"-isystem{GIT_BASH_HOME}/include", "-isystem~/include"),
        (f"-iquote{GIT_BASH_HOME}/include", "-iquote~/include"),
        (f"-idirafter/mnt/c/Users/{NAME}/inc", "-idirafter~/inc"),
        (f"--include{WIN_HOME}\\inc", "--include~\\inc"),
        (f"/Fo{WIN_HOME}\\build\\", "/Fo~\\build\\"),
        (f"/Fe{WIN_HOME}\\a.exe", "/Fe~\\a.exe"),
        (f"/FI{WIN_HOME}\\pre.h", "/FI~\\pre.h"),
        (f"-L{WIN_HOME}\\lib", "-L~\\lib"),  # one letter, as in revision 31
        (f"/I{WIN_HOME}\\include", "/I~\\include"),
        (f"-I{GIT_BASH_HOME}/include", "-I~/include"),
        (f"'-isystem{GIT_BASH_HOME}/include'", "'-isystem~/include'"),
        (f"CFLAGS=-isystem{GIT_BASH_HOME}/x", "CFLAGS=-isystem~/x"),
    ],
)
def test_an_option_glued_to_the_home_directory_is_kept_and_the_home_is_a_tilde(
    written: str, shown: str
) -> None:
    assert _shown(written) == (shown, shown)


def test_an_option_glued_to_the_posix_home_directory() -> None:
    for written, shown in (
        (f"-isystem{HOME}/include", "-isystem~/include"),
        (f"-cf{HOME}/x.tar", "-cf~/x.tar"),
        (f"--prefix{HOME}", "--prefix~"),
    ):
        assert _shown(written, home=HOME) == (shown, shown)


@pytest.mark.parametrize(
    "written",
    [
        f"foo-I{GIT_BASH_HOME}/x",  # a relative path; revision 31 replaced it
        f"./-I{GIT_BASH_HOME}/x",
        f"a/-isystem{GIT_BASH_HOME}/x",
        f"x--include{GIT_BASH_HOME}/x",
        f"a/Fo{WIN_HOME}\\x",
        f"/Fo{GIT_BASH_HOME}/x",  # "/" + letters before a slash form is a path: /Fo/c/Users/...
        f"-I2{GIT_BASH_HOME}/x",  # letters only
    ],
)
def test_an_option_that_does_not_begin_a_word_is_part_of_another_path(written: str) -> None:
    assert _shown(written) == (written, written)


def test_the_posix_home_after_a_slash_and_letters_is_another_path() -> None:
    written = f"/Fo{HOME}/x"
    assert _shown(written, home=HOME) == (written, written)


def test_an_msvc_output_option_in_a_real_powershell_call() -> None:
    payload = _ps(f"cl /Fo{WIN_HOME}\\build\\ a.c")
    assert payload["command"] == "cl /Fo~\\build\\ a.c"
    (action,) = payload["actions"]
    assert action["args"] == ["/Fo~\\build\\", "a.c"]
    # A residual: the rules read "/FoC:\..." as the path C:\FoC:\..., whose key carries the name.
    assert [p["path"] for p in action["paths"]] == [f"c:/foc/users/{NAME}/build"]


def test_a_long_gcc_option_sends_no_user_name_in_a_real_git_bash_call() -> None:
    payload = _git_bash(f"gcc -isystem{GIT_BASH_HOME}/include a.c")
    assert payload["command"] == "gcc -isystem~/include a.c"
    assert payload["actions"][0]["flags"][0] == "-isystem~/include"
    assert _no_name(payload)


# --- R31-5 (found while fixing): the flags field ------------------------------------------------


@pytest.mark.parametrize(
    ("command", "flag"),
    [
        (f"gcc -I{GIT_BASH_HOME}/inc a.c", "-I~/inc"),  # replaced in args since revision 31
        (f"tar -cf{GIT_BASH_HOME}/x.tar .", "-cf~/x.tar"),
    ],
)
def test_a_flag_with_a_glued_home_directory_sends_no_user_name(command: str, flag: str) -> None:
    payload = _git_bash(command)
    assert flag in payload["actions"][0]["flags"]
    assert _no_name(payload)


def test_flags_are_shown_like_words() -> None:
    action = Action(
        tool="Bash",
        platform="windows",
        program="gcc",
        command_text="gcc x",
        flags=(f"-I{GIT_BASH_HOME}/inc", f"--out={WIN_HOME}\\o", "-I", f"-I{WIN_HOME}2\\x"),
    )
    assert _payload(action, home=WIN_HOME)["actions"][0]["flags"] == [
        "-I~/inc",
        "--out=~\\o",
        "-I",
        f"-I{WIN_HOME}2\\x",
    ]


# --- R31-1: a single trailing dot -------------------------------------------------------------


@pytest.mark.parametrize(
    ("written", "shown"),
    [
        (f"{WIN_HOME}.\\notes.txt", "~.\\notes.txt"),
        (f"{WIN_HOME}./notes.txt", "~./notes.txt"),
        (f"{WIN_HOME}.", "~."),
        (f"C:/Users/{NAME}./x", "~./x"),
        (f"C:\\\\Users\\\\{NAME}.\\\\x", "~.\\\\x"),
    ],
)
def test_a_single_trailing_dot_before_a_separator_is_the_home_directory(
    written: str, shown: str
) -> None:
    assert _shown(written) == (shown, shown)
    assert _as_path(written)[0] == shown


def test_a_trailing_dot_before_a_space_ends_it_in_a_command_text() -> None:
    assert _shown(f"{WIN_HOME}. x")[0] == "~. x"
    assert _as_path(f"{WIN_HOME}. \\x")[0] == f"{WIN_HOME}. \\x"  # in a path: another name


@pytest.mark.parametrize(
    ("written", "shown"),
    [(f"'{WIN_HOME}.'", "'~.'"), (f"{WIN_HOME}.;x", "~.;x"), (f"({WIN_HOME}.)", "(~.)")],
)
def test_a_trailing_dot_before_any_other_end_of_a_command_text(written: str, shown: str) -> None:
    assert _shown(written) == (shown, shown)


def test_a_trailing_dot_before_a_stream_in_a_path() -> None:
    assert _as_path(f"{WIN_HOME}.:s")[0] == "~.:s"
    assert _as_path(f"{WIN_HOME}.'")[0] == f"{WIN_HOME}.'"


@pytest.mark.parametrize(
    "written",
    [
        f"{WIN_HOME}..\\notes.txt",
        f"{WIN_HOME}.CORP\\notes.txt",
        f"{WIN_HOME}.x",
        f"{GIT_BASH_HOME}./notes.txt",  # Git Bash keeps the dot: another name
        f"/mnt/c/Users/{NAME}./notes.txt",
    ],
)
def test_other_dots_are_another_name(written: str) -> None:
    assert _shown(written) == (written, written)
    assert _as_path(written)[0] == written


def test_a_trailing_dot_after_the_posix_home_is_another_name() -> None:
    written = f"{HOME}./notes.txt"
    assert _shown(written, home=HOME) == (written, written)
    assert _as_path(written, home=HOME)[0] == written


def test_a_trailing_dot_sends_no_user_name_in_a_real_powershell_call() -> None:
    payload = _ps(f"Get-Content {WIN_HOME}.\\notes.txt")
    assert payload["command"] == "Get-Content ~.\\notes.txt"
    (action,) = payload["actions"]
    assert action["args"] == ["~.\\notes.txt"]
    assert [p["path"] for p in action["paths"]] == ["~/notes.txt"]
    assert _no_name(payload)


# --- R31-2: a command text, or a word that is not one path ------------------------------------


@pytest.mark.parametrize("after", ["{2,3}\\x", "[23]\\x", "]", "[", "{", "{a}"])
def test_braces_and_wildcards_go_on_with_the_name(after: str) -> None:
    written = WIN_HOME + after
    assert _shown(written) == (written, written)


@pytest.mark.parametrize(
    "written",
    [
        f"{GIT_BASH_HOME}\\2/notes.txt",  # Bash: /c/Users/<name>2/notes.txt
        f"{GIT_BASH_HOME}{{2,3}}/notes.txt",
        f"{GIT_BASH_HOME}[23]/notes.txt",
        f"/cygdrive/c/Users/{NAME}\\x",
    ],
)
def test_a_backslash_after_a_slash_form_is_bash_s_escape(written: str) -> None:
    assert _shown(written) == (written, written)


def test_a_backslash_after_the_posix_home_goes_on_with_the_name() -> None:
    for written in (f"{HOME}\\2/notes.txt", f"{HOME}{{2,3}}/x", f"{HOME}[23]/x"):
        assert _shown(written, home=HOME) == (written, written)


def test_a_backslash_after_a_drive_form_is_still_a_separator() -> None:
    assert _shown(f"{WIN_HOME}\\x") == ("~\\x", "~\\x")


@pytest.mark.parametrize(
    ("written", "shown"),
    [
        (f"{{/tmp,{GIT_BASH_HOME}}}", "{/tmp,~}"),  # Bash: /tmp and the home
        (f"& {{Get-Content {WIN_HOME}}}", "& {Get-Content ~}"),  # PowerShell ends a word at "}"
        (f"{WIN_HOME}}}", "~}"),
    ],
)
def test_a_closing_brace_still_ends_it(written: str, shown: str) -> None:
    assert _shown(written) == (shown, shown)


def test_brace_expansion_is_shown_as_written_in_a_real_git_bash_call() -> None:
    payload = _git_bash(f"make release # cat {GIT_BASH_HOME}{{2,3}}/notes.txt {GIT_BASH_HOME}/x")
    assert payload["command"] == f"make release # cat {GIT_BASH_HOME}{{2,3}}/notes.txt ~/x"


@pytest.mark.parametrize(
    ("written", "shown"),
    [
        (f"cd {GIT_BASH_HOME} && ls", "cd ~ && ls"),
        (f"print(open('C:/Users/{NAME}').read())", "print(open('~').read())"),
        (f"{WIN_HOME};D:\\tools", "~;D:\\tools"),
        (f"{GIT_BASH_HOME}:/usr/bin", "~:/usr/bin"),
        (f"a,{WIN_HOME},b", "a,~,b"),
    ],
)
def test_code_and_lists_in_a_word_end_it_as_in_a_command_text(written: str, shown: str) -> None:
    assert _shown(written) == (shown, shown)


def test_code_in_a_real_git_bash_call_sends_no_user_name() -> None:
    payload = _git_bash(f"python -c \"print(open('{GIT_BASH_HOME}').read())\"")
    assert "print(open('~').read())" in payload["command"]
    assert _no_name(payload)


@pytest.mark.parametrize(
    ("written", "shown"),
    [
        # still replaced in a command text: the spec lists them as replaced too often
        (f"'{WIN_HOME} Smith\\x'", "'~ Smith\\x'"),
        (f"{GIT_BASH_HOME}'2'/x", "~'2'/x"),
        (f"{GIT_BASH_HOME}`echo 2`/x", "~`echo 2`/x"),
        (f"'{WIN_HOME}(2)\\x'", "'~(2)\\x'"),
        (f"'{GIT_BASH_HOME}:old/x'", "'~:old/x'"),
    ],
)
def test_what_a_command_text_still_replaces_too_often(written: str, shown: str) -> None:
    assert _shown(written)[0] == shown


# --- R31-2: a word that is one path -----------------------------------------------------------


@pytest.mark.parametrize(
    "written",
    [
        f"{WIN_HOME} Smith\\notes.txt",
        f"{WIN_HOME} - Copy\\notes.txt",
        f"{WIN_HOME}(2)\\notes.txt",
        f"{WIN_HOME}'2\\notes.txt",
        f"{WIN_HOME}[23]\\notes.txt",
        f"{WIN_HOME}{{2,3}}\\notes.txt",
        f"{WIN_HOME}}}\\notes.txt",
        f"{WIN_HOME}`2\\notes.txt",
        f"{GIT_BASH_HOME} Smith/notes.txt",
        # "," ";" and ":" after a slash form end it since spec revision 34 (a list of paths):
        # test_m3a_rev33_review_fixes.py
    ],
)
def test_in_a_word_that_is_one_path_the_rest_is_part_of_the_name(written: str) -> None:
    assert _as_path(written)[0] == written


@pytest.mark.parametrize(
    ("written", "shown"),
    [
        (WIN_HOME, "~"),
        (f"{WIN_HOME}\\notes.txt", "~\\notes.txt"),
        (f"{WIN_HOME}/notes.txt", "~/notes.txt"),
        (f"{WIN_HOME}:stream", "~:stream"),  # a stream of the home itself
        (f"{GIT_BASH_HOME}/notes.txt", "~/notes.txt"),
        (f"{GIT_BASH_HOME}\\notes.txt", "~\\notes.txt"),  # Git Bash reads "\" in a word as "/"
        (f"/mnt/c/Users/{NAME}\\x", "~\\x"),
        (f"C:\\\\Users\\\\{NAME}\\\\x", "~\\\\x"),
    ],
)
def test_in_a_word_that_is_one_path_a_separator_ends_it(written: str, shown: str) -> None:
    assert _as_path(written)[0] == shown


def test_a_word_that_is_one_posix_path_ends_only_at_a_slash() -> None:
    assert _as_path(f"{HOME}/x", home=HOME)[0] == "~/x"
    assert _as_path(HOME, home=HOME)[0] == "~"
    for written in (f"{HOME}\\x", f"{HOME} x/y", f"{HOME}'2/y"):
        assert _as_path(written, home=HOME)[0] == written
    # and at a list separator since spec revision 34: test_m3a_rev33_review_fixes.py


def test_an_expanded_path_is_shown_with_the_path_boundaries() -> None:
    assert _as_path(f"{WIN_HOME} Smith\\$TOKEN", expanded=True)[1] == f"{WIN_HOME} Smith\\$TOKEN"
    assert _as_path(f"{WIN_HOME}\\$TOKEN", expanded=True)[1] == "~\\$TOKEN"
    assert _as_path(f"{WIN_HOME}.\\$TOKEN", expanded=True)[1] == "~.\\$TOKEN"


def test_an_option_glued_to_a_path_word_still_counts() -> None:
    """A word the rules read as one path that starts with an option is unusual; it is shown the
    same way as in a text."""
    assert _as_path(f"-isystem{GIT_BASH_HOME}/x")[0] == "-isystem~/x"


def test_a_sibling_profile_in_a_real_powershell_call() -> None:
    payload = _ps(f"Copy-Item README.md '{WIN_HOME} Smith\\a.txt'")
    (action,) = payload["actions"]
    assert f"{WIN_HOME} Smith\\a.txt" in action["args"]  # the word: another profile, as it is
    assert payload["command"] == "Copy-Item README.md '~ Smith\\a.txt'"  # the text: too often
    assert all(not p["path"].startswith("~") for p in action["paths"])


@pytest.mark.parametrize(
    ("written", "home_path"),
    [
        (f"{GIT_BASH_HOME}/notes.txt", True),
        (f"{GIT_BASH_HOME}\\notes.txt", True),
        (f"{GIT_BASH_HOME} Smith/notes.txt", False),
        (f"{GIT_BASH_HOME}(2)/notes.txt", False),
        # "<home>,old" is shown as "~,old" since spec revision 34: test_m3a_rev33_review_fixes.py
        (f"{WIN_HOME}\\notes.txt", True),
        (f"{WIN_HOME}.\\notes.txt", True),
        (f"{WIN_HOME} Smith\\notes.txt", False),
        (f"{WIN_HOME}2\\notes.txt", False),
        (f"/mnt/c/Users/{NAME}\\x", True),
    ],
)
def test_a_path_word_agrees_with_the_paths_field_in_a_real_git_bash_call(
    written: str, home_path: bool
) -> None:
    """The word in args shows the home directory where the rules read the path under it."""
    payload = _git_bash(f"cat '{written}'")
    cats = [a for a in payload["actions"] if a.get("program") == "cat"]
    (action,) = cats
    (word,) = action["args"]
    paths = [p["path"] for p in action["paths"]]
    assert word.startswith("~") == home_path
    assert any(p.startswith("~") for p in paths) == home_path
    assert (NAME not in json.dumps(action).lower()) == home_path


def test_a_quoted_backslash_after_a_slash_form_stays_in_a_git_bash_command_text() -> None:
    """The cost of R31-2's escape: the text cannot tell a quoted "\\" (a separator in Git Bash)
    from an unquoted one (an escape), so neither is replaced; the word and the path are."""
    payload = _git_bash(f"cat '{GIT_BASH_HOME}\\notes.txt'")
    assert payload["command"] == f"cat '{GIT_BASH_HOME}\\notes.txt'"
    (action,) = [a for a in payload["actions"] if a.get("program") == "cat"]
    assert action["args"] == ["~\\notes.txt"]
    assert [p["path"] for p in action["paths"]] == ["~/notes.txt"]


# --- R31-3, R31-4: the spec text only (the behaviour is pinned) -------------------------------


@pytest.mark.parametrize(
    ("written", "shown"),
    [
        (f"${{D}}{GIT_BASH_HOME}/x", "${D}~/x"),
        (f"$(pwd){GIT_BASH_HOME}/x", "$(pwd)~/x"),
        (f"x+{GIT_BASH_HOME}/x", "x+~/x"),
    ],
)
def test_only_the_character_before_a_slash_form_counts(written: str, shown: str) -> None:
    assert _shown(written) == (shown, shown)


@pytest.mark.parametrize(
    "written",
    [
        f"C:\\Users/{NAME}\\x",
        f"C:\\Documents and Settings\\{NAME}\\x",
        f"/c/Users\\{NAME}/x",
    ],
)
def test_other_ways_to_write_the_home_directory_are_not_replaced(written: str) -> None:
    assert _shown(written) == (written, written)


def test_bash_s_tilde_user_is_not_replaced() -> None:
    assert _shown(f"~{NAME}/x", home=HOME) == (f"~{NAME}/x", f"~{NAME}/x")


# --- unchanged ---------------------------------------------------------------------------------


def test_the_home_forms_and_the_request_format_are_unchanged() -> None:
    assert [t for t, _ in send_gate._home_forms(WIN_HOME)] == [
        f"/cygdrive/c/Users/{NAME}",
        f"/mnt/c/Users/{NAME}",
        f"C:\\\\Users\\\\{NAME}",
        f"C:\\Users\\{NAME}",
        f"C:/Users/{NAME}",
        f"/c/Users/{NAME}",
    ]
    assert send_gate.SCHEMA_TAG == "boundkeep.audit-request/2"


def test_no_home_directory_changes_nothing() -> None:
    places = send_gate._Places(None, None)
    assert places.word(f"{WIN_HOME}\\x") == f"{WIN_HOME}\\x"
    assert places.word(f"{WIN_HOME}\\x", path=True) == f"{WIN_HOME}\\x"
