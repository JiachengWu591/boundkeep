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


def test_a_helper_gray_ask_is_not_shown_like_an_ordinary_no_rule_ask() -> None:
    record = {
        "command": "Get-Date",
        "decided_by": "gray",
        "verdict": "gray",
        "gray_reasons": ["ps-helper-not-ready"],
    }
    assert cli._summary(record) == "gray: ps-helper-not-ready | Get-Date"
    plain = {"command": "Get-Date", "decided_by": "gray", "verdict": "gray", "gray_reasons": []}
    assert cli._summary(plain) == "Get-Date"


def test_normalizer_gray_reasons_are_shown_next_to_the_command() -> None:
    record = {
        "command": "x",
        "decided_by": "gray",
        "gray_reasons": ["normalize-budget-exceeded", "budget:time", "other"],
    }
    assert cli._summary(record).startswith("gray: normalize-budget-exceeded | x")


def test_only_gray_records_get_the_helper_prefix() -> None:
    record = {"command": "x", "decided_by": "rule:a", "gray_reasons": ["ps-helper-timeout"]}
    assert cli._summary(record) == "x"


def test_helper_gray_text_is_sanitized() -> None:
    record = {"decided_by": "gray", "gray_reasons": ["ps-helper-x\x1b[2J"], "command": "a\x07b"}
    text = cli._summary(record)
    assert "\x1b" not in text
    assert "\x07" not in text


def test_pool_timeout_and_busy_records_without_a_command_say_why() -> None:
    assert cli._summary({"decided_by": "timeout", "command_chars": 5}) == "(timeout)"
    assert cli._summary({"decided_by": "busy"}) == "(busy)"
    assert cli._summary({"decided_by": "busy", "reason": "daemon busy"}) == "daemon busy"


def test_init_epilogue_no_longer_says_powershell_is_unparsed() -> None:
    text = " ".join(cli._epilogue("does-not-exist.yaml"))
    assert "not parsed until M1b" not in text
    assert "ps-helper-not-ready" in text


def test_old_records_still_render() -> None:
    assert cli._summary({"command": "echo hi"}) == "echo hi"
    assert cli._summary({"prompt_chars": 12}) == "prompt of 12 characters"
    assert cli._summary({}) == ""
