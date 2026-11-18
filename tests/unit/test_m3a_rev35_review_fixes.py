"""Spec revision 36: the review of revision 35 (docs/reviews/M3a-rev35-review.md).

R35-1: the value of a secret-looking environment variable is looked for in the serialized request
as written and as the serialization writes it. ``json.dumps`` escapes ``"``, ``\\`` and control
characters, so a value holding one of them was not found and was sent (since M3a).

R35-2 and R35-3 change the spec text only; the behaviours they describe are pinned here.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from boundkeep.audit import send_gate
from boundkeep.normalize.model import Action, PathRef
from boundkeep.session.facts import FRESH
from tests.unit.test_m3a_review_fixes import HOME, command, gate
from tests.unit.test_m3a_x1_fixes import WIN_HOME

REFUSED = "the request would carry the value of a secret environment variable"


def _ps(text: str, *args: str) -> Action:
    return Action(
        tool="PowerShell", platform="windows", program=text.split()[0], args=args, command_text=text
    )


# ------------------------------------------------------------------ R35-1


@pytest.mark.parametrize(
    "secret",
    [
        'pa"ss1234wd',  # a double quote
        "pa\\ss1234wd",  # a backslash
        "pa\tss1234wd",  # a tab
        "pa\nss1234wd",  # a line feed
        'pä"ss1234wd',  # escaped and not ASCII: the request keeps "ä" as it is
        '"\\"\\"\\"\\"',  # escapes only
        'ab"cd123',  # MIN_SECRET_CHARS exactly
    ],
)
def test_a_secret_value_that_the_serialization_escapes_is_found(secret: str) -> None:
    result = gate((command("echo", secret),), secrets=(secret,))
    assert result.request is None
    assert result.refused == REFUSED


def test_a_secret_value_that_the_serialization_escapes_is_found_in_any_case() -> None:
    result = gate((command("echo", "pa\\ss1234wd"),), secrets=("PA\\SS1234WD",))
    assert result.refused == REFUSED


def test_a_secret_value_with_a_quote_is_still_found_as_written_across_two_fields() -> None:
    # Two arguments serialize as ["aaaa", "bbbb"]: the value is there as written, not escaped
    secret = 'aaaa", "bbbb'
    result = gate((command("echo", "aaaa", "bbbb"),), secrets=(secret,))
    assert result.refused == REFUSED


def test_a_secret_value_with_a_quote_in_the_task_intent_is_found() -> None:
    facts = dataclasses.replace(FRESH, intents=('the value is ab"cd1234ef, deploy it',))
    result = gate(
        (command("make", "deploy"),), facts=facts, send_task_intent=True, secrets=('ab"cd1234ef',)
    )
    assert result.refused == REFUSED


def test_a_secret_value_that_is_a_windows_path_is_found_in_the_command() -> None:
    value = "D:\\keys\\gcp.json"
    result = gate(
        (_ps(f"Get-Content {value}", value),), tool="PowerShell", home=WIN_HOME, secrets=(value,)
    )
    assert result.refused == REFUSED


def test_a_secret_value_under_the_home_directory_is_not_in_the_request() -> None:
    # The home is written as "~" first, so the value is not in the request as written or escaped
    value = f"{WIN_HOME}\\keys\\gcp.json"
    result = gate(
        (_ps(f"Get-Content {value}", value),), tool="PowerShell", home=WIN_HOME, secrets=(value,)
    )
    assert result.request is not None
    payload = json.loads(result.request.content)
    assert payload["command"] == "Get-Content ~\\keys\\gcp.json"
    assert "testuser" not in result.request.content


def test_a_secret_value_the_rules_wrote_with_other_separators_is_not_found() -> None:
    # Spec revision 36: a form the rules changed (a path key with "/" for "\\") is not looked for
    value = "D:\\keys\\gcp.json"
    ref = PathRef(
        raw=value,
        key="d:/keys/gcp.json",
        flavor="windows",
        access="read",
        inside_project=False,
        reasons=(),
    )
    action = Action(tool="Read", platform="windows", paths=(ref,))
    result = gate((action,), tool="Read", home=WIN_HOME, secrets=(value,))
    assert result.request is not None
    assert result.payload is not None
    assert result.payload["actions"][0]["paths"][0]["path"] == "d:/keys/gcp.json"


def test_a_secret_value_written_with_escapes_in_the_command_is_not_found() -> None:
    # Spec revision 36: the command text holds 'pa\"ss1234wd', which is not the value
    code = "print('pa\\\"ss1234wd')"
    action = _ps(f'python -c "{code}"', "-c", code)
    result = gate((action,), tool="PowerShell", home=WIN_HOME, secrets=('pa"ss1234wd',))
    assert result.request is not None


@pytest.mark.parametrize(
    ("secret", "word"),
    [
        ('pa"ss1234wd', "other1234wd"),  # not in the request
        ('a"b\\c', 'a"b\\c'),  # shorter than MIN_SECRET_CHARS
        ("pass1234wd", "pass1234wd!"),  # control: as written, no escape needed, still found
    ],
)
def test_the_secret_check_controls(secret: str, word: str) -> None:
    result = gate((command("echo", word),), secrets=(secret,))
    if secret in word and len(secret) >= send_gate.MIN_SECRET_CHARS:
        assert result.refused == REFUSED
    else:
        assert result.request is not None


# ------------------------------------------------------------------ R35-2, R35-3 (spec text only)


def test_an_option_glued_to_a_drive_colon_is_taken_as_an_option_with_a_colon() -> None:
    places = send_gate._Places("\\\\server\\share\\testuser", None)
    assert places.word("-IC:\\\\server\\share\\testuser\\inc") == "-IC:~\\inc"
    assert places.word("/FoC:\\\\server\\share\\testuser\\build\\") == "/FoC:~\\build\\"
    assert places.word("-C:\\\\server\\share\\testuser\\x") == "-C:~\\x"
    assert places.word("C:\\\\server\\share\\testuser\\x") == "C:\\\\server\\share\\testuser\\x"


def test_a_sibling_after_a_cut_inside_the_glued_option_is_shown_like_the_command_text() -> None:
    places = send_gate._Places(HOME, None)
    word = "-isystem/home/testuser Smith/inc"
    assert send_gate._word(word, ["em/home/testuser Smith/inc"], places) == "-isystem~ Smith/inc"
    # cut at the end of the option: the path keeps the boundaries of a path
    assert send_gate._word(word, ["/home/testuser Smith/inc"], places) == word


def test_a_slash_form_before_a_backslash_is_kept_whichever_boundaries_are_used() -> None:
    places = send_gate._Places(WIN_HOME, None)
    for word, cut in (("-isystem/c/Users/testuser\\x", 6), ("/cygdrive/c/Users/testuser\\x", 4)):
        assert not places.home_begins_before(word, cut)
        assert send_gate._word(word, [word[cut:]], places) == word
        assert places.word(word) == word


def test_a_secret_value_inside_the_home_is_no_longer_in_a_comment() -> None:
    # Revision 35 writes the UNC home after "FileSystem::" as "~": the value is gone, so it is sent
    unc = "\\\\server\\share\\testuser"
    text = f"Write-Output 'see FileSystem::{unc}\\x'"
    result = gate(
        (_ps(text, f"see FileSystem::{unc}\\x"),),
        tool="PowerShell",
        home=unc,
        secrets=("testuser",),
    )
    assert result.request is not None
    assert json.loads(result.request.content)["command"] == "Write-Output 'see FileSystem::~\\x'"
