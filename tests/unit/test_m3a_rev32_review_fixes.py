"""Spec revision 33: the home directory written as ``~`` for a UNC home, and after an option
(review of revision 32, docs/reviews/M3a-rev32-review.md).

R32-1. Revision 32 took only ``X:\\...`` homes as Windows homes, so a UNC home
``\\\\server\\share\\me`` fell on the POSIX side: ``\\`` after it no longer ended the name, and
``\\\\server\\share\\me\\notes.txt`` went out with the user name in the command text and in words
that are paths. Now a UNC home is a Windows home, with escaped and forward-slash forms.

R32-2. Only a word equal to one of the action's path texts got the boundaries of a path, so a path
after ``--directory=`` or glued to ``-isystem`` showed a sibling as ``~ Smith`` in "args" and
"flags". Now an option and then such a path is treated as that path.

R32-3 and R32-4 changed the spec text only (pinned below).

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
from .test_m3a_rev29_review_fixes import _sent
from .test_m3a_rev31_review_fixes import GIT_BASH_HOME, NAME, _git_bash
from .test_m3a_x1_fixes import WIN_HOME, WIN_PROJECT, manipulated

UNC_HOME = f"\\\\server\\share\\{NAME}"
UNC_FORWARD = f"//server/share/{NAME}"


def _payload(action: Action, *, home: str) -> dict[str, Any]:
    gated = send_gate.gate(
        [action], tool="Bash", facts=FRESH, send_task_intent=False, intent_prompts=1, home=home
    )
    assert gated.request is not None, gated.refused
    assert gated.payload is not None
    return gated.payload


def _shown(written: str, *, home: str = UNC_HOME) -> tuple[str, str]:
    """``written`` in a comment of the command text, and as a word that is not a path."""
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


def _with_paths(
    *,
    args: tuple[str, ...] = (),
    flags: tuple[str, ...] = (),
    raws: tuple[str, ...] = (),
    home: str = WIN_HOME,
) -> dict[str, Any]:
    """The action as sent, with ``raws`` as the texts of its paths (keys elsewhere)."""
    refs = tuple(
        PathRef(raw=raw, key=f"c:/elsewhere/{i}", flavor="windows", access="read")
        for i, raw in enumerate(raws)
    )
    action = Action(
        tool="Bash",
        platform="windows",
        program="make",
        command_text="make x",
        args=args,
        flags=flags,
        paths=refs,
    )
    (shown,) = _payload(action, home=home)["actions"]
    return shown


def _unc_call(command: str, tool: str = "PowerShell") -> dict[str, Any]:
    """A real call with a UNC home, sent to a fake model."""
    pol = policy(llm=True)
    auditor, backend = manipulated(pol)
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        {
            "hook_event_name": "PreToolUse",
            "session_id": "00000000-0000-4000-8000-0000000000ef",
            "cwd": WIN_PROJECT,
            "project_dir": WIN_PROJECT,
            "tool_name": tool,
            "tool_input": {"command": command},
        },
        mode="enforce",
        policy=pol,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": UNC_HOME},
        home=UNC_HOME,
        scan_disk=False,
        auditor=auditor,
    )
    return _sent(decision, backend)


def _no_name(value: object) -> bool:
    return NAME not in json.dumps(value).lower()


# --- R32-1: a UNC home ------------------------------------------------------------------------


def test_a_unc_home_has_backslashed_escaped_and_forward_forms() -> None:
    assert send_gate._home_forms(UNC_HOME + "\\") == [
        (f"\\\\\\\\server\\\\share\\\\{NAME}", True),
        (UNC_HOME, True),
        (UNC_FORWARD, False),
    ]


@pytest.mark.parametrize(
    ("written", "shown"),
    [
        (f"{UNC_HOME}\\notes.txt", "~\\notes.txt"),  # revision 32 left it as it was
        (UNC_HOME, "~"),
        (f"{UNC_HOME}/notes.txt", "~/notes.txt"),
        (f"{UNC_HOME}.\\notes.txt", "~.\\notes.txt"),  # GetFullPathNameW drops the dot
        (f"'{UNC_HOME}'", "'~'"),
        (f"\\\\\\\\server\\\\share\\\\{NAME}\\\\x", "~\\\\x"),
        (f"{UNC_FORWARD}/notes.txt", "~/notes.txt"),
        (f"\\\\SERVER\\Share\\{NAME.upper()}\\x", "~\\x"),
        (f"/I{UNC_HOME}\\inc", "/I~\\inc"),
        (f"-L{UNC_HOME}\\lib", "-L~\\lib"),
    ],
)
def test_a_unc_home_is_a_tilde(written: str, shown: str) -> None:
    assert _shown(written) == (shown, shown)
    assert _no_name(_shown(written))


@pytest.mark.parametrize(
    "written",
    [
        f"{UNC_HOME}2\\x",
        f"{UNC_HOME}.CORP\\x",
        f"{UNC_HOME}..\\x",
        f"{UNC_HOME}{{2,3}}\\x",
        f"x{UNC_HOME}\\y",  # a relative path
        f"{UNC_FORWARD}\\2/x",  # Bash: the escape goes on with the name
        f"{UNC_FORWARD}./x",
        f"\\\\other\\share\\{NAME}\\x",
    ],
)
def test_other_names_are_left_as_written(written: str) -> None:
    assert _shown(written) == (written, written)


@pytest.mark.parametrize(
    ("written", "shown"),
    [
        (f"{UNC_HOME}\\notes.txt", "~\\notes.txt"),
        (f"{UNC_HOME}:s", "~:s"),
        (f"{UNC_HOME}.\\x", "~.\\x"),
        (f"{UNC_FORWARD}\\notes.txt", "~\\notes.txt"),  # a Windows home: "\" is a separator
        (f"{UNC_FORWARD}/notes.txt", "~/notes.txt"),
        (f"{UNC_HOME} Smith\\notes.txt", f"{UNC_HOME} Smith\\notes.txt"),
        (f"{UNC_HOME}(2)\\x", f"{UNC_HOME}(2)\\x"),
        (f"{UNC_FORWARD}:old/x", "~:old/x"),  # ":" ends a slash form in a path (revision 34)
    ],
)
def test_a_word_that_is_a_path_under_a_unc_home(written: str, shown: str) -> None:
    assert _with_paths(args=(written,), raws=(written,), home=UNC_HOME)["args"] == [shown]


def test_a_unc_home_in_a_real_powershell_call() -> None:
    payload = _unc_call(f"make release # see {UNC_HOME}\\notes.txt and {UNC_HOME}2\\x")
    assert payload["command"] == f"make release # see ~\\notes.txt and {UNC_HOME}2\\x"


def test_a_path_under_a_unc_home_is_network_access_and_not_sent() -> None:
    """Only a text that names the UNC home (a comment, a string) reaches the model: a path under
    it is network access, which the rules ask about before any audit."""
    with pytest.raises(AssertionError, match="network access"):
        _unc_call(f"Copy-Item README.md {UNC_HOME}\\Desktop\\a.txt")


def test_drive_and_posix_homes_are_unchanged() -> None:
    assert [t for t, _ in send_gate._home_forms(WIN_HOME)][-1] == GIT_BASH_HOME
    assert send_gate._home_forms(HOME) == [(HOME, False)]
    assert send_gate._home_forms("//server/share/me") == [("//server/share/me", False)]


# --- R32-2: a path after an option ------------------------------------------------------------


@pytest.mark.parametrize(
    ("word", "raw", "shown"),
    [
        # a sibling: the rest is part of the name
        (f"--directory={GIT_BASH_HOME} Smith/src", f"{GIT_BASH_HOME} Smith/src", None),
        (f"-isystem{GIT_BASH_HOME} Smith/inc", f"{GIT_BASH_HOME} Smith/inc", None),
        (f"-Path:{WIN_HOME} Smith\\x", f"{WIN_HOME} Smith\\x", None),
        (f"/Fo{WIN_HOME}(2)\\x", f"{WIN_HOME}(2)\\x", None),
        (f"-Wl,-rpath,{GIT_BASH_HOME} Smith/lib", f",-rpath,{GIT_BASH_HOME} Smith/lib", None),
        # the home: replaced, the option kept
        (f"--directory={GIT_BASH_HOME}/src", f"{GIT_BASH_HOME}/src", "--directory=~/src"),
        (f"-isystem{GIT_BASH_HOME}/inc", f"{GIT_BASH_HOME}/inc", "-isystem~/inc"),
        (f"--out={WIN_HOME}", WIN_HOME, "--out=~"),
        (f"-Path:{WIN_HOME}.\\x", f"{WIN_HOME}.\\x", "-Path:~.\\x"),
        (f"-Wl,-rpath,{GIT_BASH_HOME}/lib", f",-rpath,{GIT_BASH_HOME}/lib", "-Wl,-rpath,~/lib"),
    ],
)
def test_a_path_after_an_option_has_the_boundaries_of_a_path(
    word: str, raw: str, shown: str | None
) -> None:
    action = _with_paths(args=(word,), flags=(word,), raws=(raw,))
    assert action["args"] == [shown or word]
    assert action["flags"] == [shown or word]


@pytest.mark.parametrize(
    ("word", "raw"),
    [
        (f"pycache_prefix={WIN_HOME} Smith\\c", f"{WIN_HOME} Smith\\c"),  # not an option
        (f"cd {GIT_BASH_HOME} Smith", f"{GIT_BASH_HOME} Smith"),  # code
        (f"a,{WIN_HOME} Smith", f"{WIN_HOME} Smith"),  # a list
        (f"-I {GIT_BASH_HOME} Smith", f"{GIT_BASH_HOME} Smith"),  # a space is not an option
        (f"--x={GIT_BASH_HOME} Smith", f"{GIT_BASH_HOME} Smit"),  # the word does not end with it
    ],
)
def test_anything_else_before_a_path_is_shown_like_the_command_text(word: str, raw: str) -> None:
    assert _with_paths(args=(word,), raws=(raw,))["args"] == [
        send_gate._Places(WIN_HOME, None).word(word)
    ]


def test_the_longest_path_text_that_fits_is_taken() -> None:
    """``--o`` and the relative ``x1/c/Users/<name>/y``, not ``--ox1`` and the home: the path the
    rules read with more of the word wins. (``--ox`` before the home is an option glued to it in
    the command text, and the cut may not fall inside it since spec revision 35:
    test_m3a_rev34_review_fixes.py.)"""
    word = f"--ox1{GIT_BASH_HOME}/y"
    raws = (f"{GIT_BASH_HOME}/y", f"x1{GIT_BASH_HOME}/y")
    assert _with_paths(args=(word,), raws=raws)["args"] == [word]


def test_a_word_equal_to_a_path_still_counts() -> None:
    written = f"{WIN_HOME} Smith\\x"
    assert _with_paths(args=(written,), raws=(written,))["args"] == [written]


@pytest.mark.parametrize(
    ("command", "field", "shown"),
    [
        (
            f"make --directory='{GIT_BASH_HOME} Smith/src' all",
            "args",
            f"--directory={GIT_BASH_HOME} Smith/src",
        ),
        (
            f"gcc '-isystem{GIT_BASH_HOME} Smith/inc' a.c",
            "flags",
            f"-isystem{GIT_BASH_HOME} Smith/inc",
        ),
        (
            f"gcc '-isystem{GIT_BASH_HOME} Smith/inc' a.c",
            "args",
            f"-isystem{GIT_BASH_HOME} Smith/inc",
        ),
        (f"make --directory={GIT_BASH_HOME}/src all", "args", "--directory=~/src"),
    ],
)
def test_a_path_after_an_option_in_a_real_git_bash_call(
    command: str, field: str, shown: str
) -> None:
    payload = _git_bash(command)
    (action,) = payload["actions"]
    assert shown in action[field]


def test_the_home_after_an_option_sends_no_user_name_in_a_real_git_bash_call() -> None:
    payload = _git_bash(f"make --directory={GIT_BASH_HOME}/src all")
    assert payload["command"] == "make --directory=~/src all"
    assert _no_name(payload)


# --- R32-3, R32-4: the spec text only (the behaviour is pinned) -------------------------------


@pytest.mark.parametrize(
    "written",
    [
        f"python {GIT_BASH_HOME}./x.py",  # a native program reads the home; not replaced
        f"Get-ChildItem {WIN_HOME}{{x}}",  # PowerShell ends a word at "{"; not replaced
        f"cat /c/Users/{NAME}\\ Smith/x",
    ],
)
def test_forms_the_spec_lists_as_not_replaced(written: str) -> None:
    assert _shown(written, home=WIN_HOME) == (written, written)


def test_escaped_spaces_in_a_user_name_are_not_replaced() -> None:
    home = f"C:\\Users\\{NAME} Smith"
    for written in (f"cat /c/Users/{NAME}\\ Smith/x", f"Get-Content C:\\Users\\{NAME}` Smith\\x"):
        assert _shown(written, home=home) == (written, written)
    assert _shown(f"cat '/c/Users/{NAME} Smith/x'", home=home)[0] == "cat '~/x'"


def test_a_lone_dash_before_a_slash_form_is_replaced_too_often() -> None:
    assert _shown(f"cat -{HOME}/x", home=HOME) == ("cat -~/x", "cat -~/x")
