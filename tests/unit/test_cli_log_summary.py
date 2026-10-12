"""The quick view of an audit record in ``boundkeep log`` (text mode)."""

from __future__ import annotations

from boundkeep import cli


def test_a_deny_shows_the_rule_ids_in_brackets_before_the_command() -> None:
    record = {"command": "cat ~/.ssh/id_rsa", "rules": ["no-secret-read", "other"]}
    assert cli._summary(record) == "[no-secret-read,other] cat ~/.ssh/id_rsa"


def test_a_gray_call_without_a_command_shows_why() -> None:
    record = {"gray_reasons": ["powershell-not-parsed-in-m1"], "verdict": "gray"}
    assert cli._summary(record) == "gray: powershell-not-parsed-in-m1"


def test_an_allowed_read_shows_the_rule_and_the_verdict() -> None:
    record = {"rules": ["read-inside-project"], "verdict": "allow"}
    assert cli._summary(record) == "[read-inside-project] (allow)"


def test_control_characters_never_reach_the_terminal() -> None:
    record = {"rules": ["a\x1b[2J"], "gray_reasons": ["x\x07y"]}
    text = cli._summary(record)
    assert "\x1b" not in text
    assert "\x07" not in text


def test_old_records_still_render() -> None:
    assert cli._summary({"command": "echo hi"}) == "echo hi"
    assert cli._summary({"prompt_chars": 12}) == "prompt of 12 characters"
    assert cli._summary({}) == ""
