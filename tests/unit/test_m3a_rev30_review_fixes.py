"""Spec revision 31: the home directory written as ``~`` in the request to the LLM audit (review of
revision 30, docs/reviews/M3a-rev30-review.md).

R30-1. The home directory was replaced wherever its text occurred, so ``<home>x\\a.txt`` showed as
``~x\\a.txt`` (in Bash the home of a user ``x``). Now only where a name ends after it, and, before
it, where no other path goes on into it ("./c/Users/...", "/x/home/me"); an option letter is a
beginning ("-I/home/me/include").

R30-2. Only ``C:\\Users\\me`` and ``C:/Users/me`` were known; Git Bash's ``/c/Users/me`` and the
escaped ``C:\\\\Users\\\\me`` went out with the user's name. Now also those, WSL's ``/mnt/c`` and
Cygwin's ``/cygdrive/c``.

R30-4 (found while fixing). The match was made on a lowercased copy and applied to the text; the
lowercase of U+0130 is two characters, so after it the positions were off: the home directory
stayed in the request and as many characters after it were cut, which hid them from the model.

R30-3 changed the docs only: the characters that refuse a text are those ``str.isprintable()``
rejects (pinned below).

Nothing is run: the helper only parses, the model is a fake one.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from boundkeep.audit import send_gate
from boundkeep.normalize.model import Action
from boundkeep.session.facts import FRESH

from .test_m3a_pipeline import HOME, bash
from .test_m3a_rev29_review_fixes import _ps, _sent
from .test_m3a_x1_fixes import CANARY, WIN_HOME, audited

NAME = "testuser"  # the user name in WIN_HOME and HOME
assert f"C:\\Users\\{NAME}" == WIN_HOME
assert f"/home/{NAME}" == HOME


def _gate(text: str, *args: str, home: str = WIN_HOME) -> dict[str, Any]:
    action = Action(
        tool="Bash", platform="windows", program="make", command_text=text, args=tuple(args)
    )
    gated = send_gate.gate(
        [action], tool="Bash", facts=FRESH, send_task_intent=False, intent_prompts=1, home=home
    )
    assert gated.request is not None, gated.refused
    assert gated.payload is not None
    return gated.payload


def _shown(written: str, *, home: str = WIN_HOME) -> tuple[str, str]:
    """``written`` as the request shows it in a comment of the command text and as a word."""
    payload = _gate(f"make release # {written}", written, home=home)
    command = payload["command"]
    assert command.startswith("make release # ")
    (word,) = payload["actions"][0]["args"]
    return command[len("make release # ") :], word


def _bash(command: str) -> dict[str, Any]:
    return _sent(*audited(bash(command)))


# --- R30-1: where the home directory ends ------------------------------------------------------


@pytest.mark.parametrize(
    "after", ["x\\a.txt", "2\\a.txt", ".CORP\\a.txt", "_old\\a.txt", "-x\\a.txt", "$suffix", "*"]
)
def test_a_longer_name_is_not_the_home_directory(after: str) -> None:
    written = WIN_HOME + after
    assert _shown(written) == (written, written)


@pytest.mark.parametrize(
    ("after", "shown"),
    [
        ("", "~"),
        ("\\x", "~\\x"),
        ("/x", "~/x"),
        ("'", "~'"),
        ('"', '~"'),
        (" x", "~ x"),
        (";x", "~;x"),
        ("|x", "~|x"),
        ("&x", "~&x"),
        (")", "~)"),
        ("}", "~}"),
        # "]" was here: it goes on with a wildcard since spec revision 32 (R31-2), see
        # test_m3a_rev31_review_fixes.py
        (">x", "~>x"),
        (",x", "~,x"),
        (":x", "~:x"),
        ("`", "~`"),
    ],
)
def test_the_home_directory_ends_where_a_name_ends(after: str, shown: str) -> None:
    command, word = _shown(WIN_HOME + after)
    assert command == shown
    assert word == shown


@pytest.mark.parametrize("end", ["\tx", "\nx", "\r\nx"])
def test_a_line_or_a_tab_ends_it_too(end: str) -> None:
    payload = _gate(f"make release # {WIN_HOME}{end}")
    assert payload["command"] == f"make release # ~{end}"


def test_a_longer_name_stays_in_a_real_powershell_call() -> None:
    command = f"make release # see {WIN_HOME}x\\notes.txt and {WIN_HOME}\\notes.txt"
    assert _ps(command)["command"] == f"make release # see {WIN_HOME}x\\notes.txt and ~\\notes.txt"


def test_a_longer_name_stays_in_a_real_bash_call() -> None:
    command = f"make release # see {HOME}2/notes.txt and {HOME}/notes.txt"
    assert _bash(command)["command"] == f"make release # see {HOME}2/notes.txt and ~/notes.txt"


@pytest.mark.parametrize(
    "written",
    [
        f"./c/Users/{NAME}/x",
        f"foo/c/Users/{NAME}/x",
        f"~/c/Users/{NAME}/x",
        f"XC:\\Users\\{NAME}\\x",
        f"_C:\\Users\\{NAME}\\x",
        f"/d/Users/{NAME}/x",
        f"/mnt/d/Users/{NAME}/x",
    ],
)
def test_another_path_that_ends_alike_is_left_as_it_is(written: str) -> None:
    assert _shown(written) == (written, written)


def test_another_posix_path_that_ends_alike_is_left_as_it_is() -> None:
    for written in (f"/x{HOME}/y", f"/var{HOME}", f".{HOME}/y"):
        assert _shown(written, home=HOME) == (written, written)
    assert _shown(f"{HOME}/y", home=HOME) == ("~/y", "~/y")


@pytest.mark.parametrize(
    ("written", "shown"),
    [
        (f"-I/c/Users/{NAME}/include", "-I~/include"),
        (f"-LC:\\Users\\{NAME}\\lib", "-L~\\lib"),
        (f"/IC:\\Users\\{NAME}\\include", "/I~\\include"),
        (f"--prefix=/c/Users/{NAME}/opt", "--prefix=~/opt"),
        (f"@/c/Users/{NAME}/d.json", "@~/d.json"),
        (f"PATH=/c/Users/{NAME}/bin:/c/Users/{NAME}/x", "PATH=~/bin:~/x"),
    ],
)
def test_an_option_or_an_assignment_just_before_it_is_a_beginning(written: str, shown: str) -> None:
    assert _shown(written) == (shown, shown)


def test_an_option_letter_before_the_posix_home_is_a_beginning() -> None:
    assert _shown(f"-I{HOME}/include", home=HOME) == ("-I~/include", "-I~/include")


# --- R30-2: the other ways to write it ----------------------------------------------------------


@pytest.mark.parametrize(
    ("written", "shown"),
    [
        (f"C:\\Users\\{NAME}\\x", "~\\x"),
        (f"C:/Users/{NAME}/x", "~/x"),
        (f"c:\\users\\{NAME.upper()}\\x", "~\\x"),
        (f"C:\\\\Users\\\\{NAME}\\\\x", "~\\\\x"),
        (f"/c/Users/{NAME}/x", "~/x"),
        (f"/C/USERS/{NAME.upper()}/x", "~/x"),
        (f"/mnt/c/Users/{NAME}/x", "~/x"),
        (f"/cygdrive/c/Users/{NAME}/x", "~/x"),
        (f"file:///C:/Users/{NAME}/x", "file:///~/x"),
        (f"'/c/Users/{NAME}'", "'~'"),
    ],
)
def test_every_known_way_to_write_the_home_directory_is_a_tilde(written: str, shown: str) -> None:
    assert _shown(written) == (shown, shown)
    payload = _gate(f"make release # {written}", written)
    assert NAME not in json.dumps(payload).lower()


def test_git_bash_and_escaped_homes_in_a_real_powershell_call() -> None:
    command = (
        f"make release # /c/Users/{NAME}/notes.txt and "
        f"python -c \"open('C:\\\\Users\\\\{NAME}\\\\x')\""
    )
    payload = _ps(command)
    assert payload["command"] == "make release # ~/notes.txt and python -c \"open('~\\\\x')\""
    assert NAME not in json.dumps(payload).lower()


def test_the_home_forms_are_derived_from_the_home_directory() -> None:
    forms = [text for text, _drive in send_gate._home_forms("D:\\Home\\Me\\")]
    assert forms == [
        "/cygdrive/d/Home/Me",
        "/mnt/d/Home/Me",
        "D:\\\\Home\\\\Me",
        "D:\\Home\\Me",
        "D:/Home/Me",
        "/d/Home/Me",
    ]
    assert send_gate._home_forms("C:\\") == []
    assert send_gate._home_forms("/") == []
    assert send_gate._home_forms("/home/me/") == [("/home/me", False)]


@pytest.mark.parametrize(
    ("home", "written"),
    [
        ("C:\\Users\\J\u00fcrgen", "C:\\USERS\\J\u00dcRGEN\\x"),
        ("C:\\Users\\\u5f20\u4e09", "C:\\Users\\\u5f20\u4e09\\x"),
        ("C:\\Users\\\u0130lker", "c:/users/\u0130lker/x"),
    ],
)
def test_a_user_name_beyond_ascii(home: str, written: str) -> None:
    assert _shown(written, home=home) == ("~" + written[-2:], "~" + written[-2:])


@pytest.mark.parametrize(
    ("home", "written"),
    [
        ("C:\\Users\\kate", "C:\\Users\\\u212aate\\x"),  # the Kelvin sign
        ("C:\\Users\\sam", "C:\\U\u017fers\\sam\\x"),  # the long s
    ],
)
def test_a_name_that_only_unicode_folding_makes_equal_is_another_name(
    home: str, written: str
) -> None:
    assert _shown(written, home=home) == (written, written)


# --- R30-4: a longer lowercase before it cuts nothing -------------------------------------------


@pytest.mark.parametrize("count", [1, 5, len(WIN_HOME), 2 * len(WIN_HOME), 100])
def test_a_dotted_capital_i_before_the_home_directory_cuts_nothing(count: int) -> None:
    dotted = "\u0130" * count
    payload = _gate(
        f"make release # {dotted} {WIN_HOME}\\{CANARY} and the rest",
        f"{dotted}\\{WIN_HOME}\\{CANARY}",
    )
    assert payload["command"] == f"make release # {dotted} ~\\{CANARY} and the rest"
    assert payload["actions"][0]["args"] == [f"{dotted}\\~\\{CANARY}"]


@pytest.mark.parametrize("char", ["\u0130", "\u00df", "\ufb01", "\u0149"])
def test_no_character_before_the_home_directory_shifts_the_match(char: str) -> None:
    text = f"make release # {char * 30} {WIN_HOME}\\{CANARY}{'x' * 40}"
    assert _gate(text)["command"] == f"make release # {char * 30} ~\\{CANARY}{'x' * 40}"


def test_the_text_after_a_home_directory_reaches_the_model() -> None:
    """The review's probe: the comment after the home directory was cut out of the request."""
    dotted = "\u0130" * len(WIN_HOME)
    for command in (
        f"make release # {dotted} {WIN_HOME}{CANARY}{'x' * len(WIN_HOME)}",
        f"make release # {dotted} {WIN_HOME}\\{CANARY}{'x' * len(WIN_HOME)}",
    ):
        assert CANARY in _ps(command)["command"]


# --- R30-3: which characters refuse a text (docs only; the behaviour is pinned) -----------------


@pytest.mark.parametrize(
    "char",
    [
        "\x00",
        "\x1b",
        "\x7f",
        "\u200d",
        "\u202e",
        "\ufeff",
        "\u00a0",
        "\u3000",
        "\u2028",
        "\u2029",
        "\ue000",
        "\u0378",
    ],
)
def test_a_character_that_is_not_printable_refuses_the_text(char: str) -> None:
    action = Action(
        tool="Bash", platform="windows", program="make", command_text=f"make release # a{char}b"
    )
    gated = send_gate.gate(
        [action], tool="Bash", facts=FRESH, send_task_intent=False, intent_prompts=1, home=WIN_HOME
    )
    assert gated.request is None


@pytest.mark.parametrize("char", ["\t", "\u00e9", "\u4e2d", "\uff0c", "\u3002", "\U0001f9ea"])
def test_printable_characters_and_a_tab_are_sent(char: str) -> None:
    assert _gate(f"make release # a{char}b")["command"] == f"make release # a{char}b"


# --- unchanged ---------------------------------------------------------------------------------


def test_the_paths_field_still_uses_the_key() -> None:
    payload = _ps(f"Copy-Item README.md {WIN_HOME}\\Desktop\\a.txt # done")
    assert payload["command"] == "Copy-Item README.md ~\\Desktop\\a.txt # done"
    assert any(p["path"].startswith("~/") for a in payload["actions"] for p in a.get("paths", []))


def test_the_request_format_and_prompt_are_unchanged() -> None:
    assert send_gate.SCHEMA_TAG == "boundkeep.audit-request/2"
    assert _bash("make release")["command"] == "make release"
