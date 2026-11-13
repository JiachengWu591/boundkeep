"""Spec revision 24: two findings of the review of revisions 21 and 22
(docs/reviews/M3a-rev21-22-review.md).

R21-1. The builder records at most 64 gray reasons for a line and dropped the rest. Whether a line
is sent to the LLM audit hangs on single reasons (``ps-switch-value``, ``ps-runner-value``,
``ps-pipe-to-interpreter``), and those are added while the commands are built: behind 64 other
reasons, one for each parameter a cmdlet does not have, they were lost and the line was sent
without the text they stand for. Now a reason that does not fit makes the line ``ps-too-large``,
which is never sent.

R22-1. The default value of a parameter is bound to the parameter's variable, exactly like the
collection of a ``foreach``: ``param($x = $env:TOKEN) Get-Date; $x`` prints it (measured,
PowerShell 5.1), and the request held ``Write-Output $x`` and nothing of where ``$x`` comes from.
Now the helper reports the default value as an expression whose value goes somewhere.

Nothing is run: the helper only parses, the model is a fake one.
"""

from __future__ import annotations

from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.daemon import pipeline
from boundkeep.normalize import pscmd

from .test_m3a_ps_expression_output import _actions, _decide, _outputs, _reply, out
from .test_m3a_x1_fixes import CANARY, assert_not_sent
from .test_norm_pscmd import O, P, S, V, build, cmd, rep

TOKEN = "$env:" + CANARY


def _unknown_parameters(letter: str, count: int = 30) -> str:
    """One Get-Date with ``count`` parameters it does not have: one gray reason each, 31 words."""
    return "Get-Date " + " ".join(f"-{letter}{i:02d}" for i in range(count))


PADDING = "; ".join(_unknown_parameters(c) for c in "abc")  # 90 reasons in three commands

# --- R21-1: a reason that does not fit ------------------------------------------------------------

NOT_SHOWN = [
    f"Get-ChildItem -Force:([IO.File]::ReadAllText('C:\\x\\{CANARY}'))",
    f"Get-ChildItem -Recurse:{TOKEN}",
    f"uv run --with {TOKEN} pytest",
    f"'Get-Content {CANARY}' | powershell -Command -",
]


@pytest.mark.windows
@pytest.mark.parametrize("command", NOT_SHOWN)
def test_alone_the_line_is_not_sent_for_its_own_reason(command: str) -> None:
    decision, backend = _decide(command, llm=True)
    assert_not_sent(decision, backend)
    assert "ps-too-large" not in {r for a in _actions(command) for r in a.gray_reasons}


@pytest.mark.windows
@pytest.mark.parametrize("command", NOT_SHOWN)
def test_behind_64_other_reasons_the_line_is_still_not_sent(command: str) -> None:
    line = f"{PADDING}; {command}"
    assert "ps-too-large" in {r for a in _actions(line) for r in a.gray_reasons}
    decision, backend = _decide(line, llm=True)
    assert_not_sent(decision, backend)
    assert decision.verdict == "gray"
    assert decision.decision == protocol.DECISION_ASK


@pytest.mark.windows
def test_the_reason_given_is_that_the_line_was_not_seen_whole() -> None:
    actions = _actions(f"{PADDING}; Get-ChildItem -Recurse:{TOKEN}")
    assert pipeline.incomplete_analysis(actions) == "ps-too-large"


@pytest.mark.windows
def test_a_line_with_fewer_reasons_is_sent_as_before() -> None:
    line = "; ".join(_unknown_parameters(c) for c in "ab")  # 60 reasons
    assert "ps-too-large" not in {r for a in _actions(line) for r in a.gray_reasons}
    decision, backend = _decide(line, llm=True)
    assert len(backend.requests) == 1, decision.reason


@pytest.mark.windows
def test_too_many_reasons_alone_are_not_sent_either() -> None:
    decision, backend = _decide(PADDING, llm=True)
    assert_not_sent(decision, backend)


def _unresolved(count: int) -> Any:
    return cmd("Get-Date", *[P(f"a{i:02d}") for i in range(count)])


def test_the_builder_keeps_64_reasons_without_a_mark() -> None:
    res = build(rep(_unresolved(pscmd.MAX_REASONS)))
    assert len(res.gray) == pscmd.MAX_REASONS
    assert "ps-too-large" not in res.gray


def test_one_more_reason_marks_the_line_and_the_mark_comes_first() -> None:
    res = build(rep(_unresolved(pscmd.MAX_REASONS + 1)))
    assert res.gray[0] == "ps-too-large"
    assert len(res.gray) == pscmd.MAX_REASONS + 1


def test_a_reason_that_is_recorded_already_is_no_new_reason() -> None:
    again = cmd("Get-Date", P("a00"), P("a63"))
    res = build(rep(_unresolved(pscmd.MAX_REASONS), again))
    assert "ps-too-large" not in res.gray


def test_the_builder_marks_a_line_whose_switch_value_did_not_fit() -> None:
    hidden = cmd("Get-ChildItem", P("Force", O("ParenExpressionAst", "([IO.File]::Delete('x'))")))
    res = build(rep(_unresolved(pscmd.MAX_REASONS), hidden))
    assert pscmd.SWITCH_VALUE_GRAY not in res.gray  # it did not fit, which is why the mark is there
    assert res.gray[0] == "ps-too-large"


def test_the_mark_is_not_doubled() -> None:
    """More commands than the builder takes is ``ps-too-large`` by itself, recorded first."""
    many = [_unresolved(pscmd.MAX_REASONS + 5), *[cmd("Get-Date")] * pscmd.MAX_COMMANDS]
    res = build(rep(*many))
    assert res.gray.count("ps-too-large") == 1
    assert len(res.gray) == pscmd.MAX_REASONS


def test_reasons_from_the_helper_s_lists_count_too() -> None:
    kinds = tuple(f"Kind{i:02d}Ast" for i in range(pscmd.MAX_REASONS))
    res = build(rep(cmd("Get-Date"), compound=kinds, loose=("InvokeMemberExpressionAst",)))
    assert res.gray[0] == "ps-too-large"
    assert pscmd.OUTSIDE_COMMAND_GRAY + ":InvokeMemberExpressionAst" not in res.gray


# --- R22-1: the default value of a parameter ------------------------------------------------------

DEFAULTS = [
    ("param($x = $env:A) Get-Date", ["$env:A"]),
    ('param($x = $env:A, $y = "k $b") Get-Date', ["$env:A", "expstr:k $b"]),
    ("param($x = $a, $y = $b) $c", ["$a", "$b", "$c"]),
    ("param($x) Get-Date", []),
    ("param($x, $y = $b) Get-Date", ["$b"]),
    ("function f($x = $env:A) { }", ["$env:A"]),
    ("function f { param($x = $env:A) }", ["$env:A"]),
    ("function f($x = $a) { $x }; f", ["$a", "$x"]),
    ("filter g($x = $a) { }", ["$a"]),
    ("param([string]$x = $env:A) Get-Date", ["$env:A"]),
    ("param($x = ($env:A)) Get-Date", ["ParenExpressionAst"]),
    ("param($x = @{ k = $a }) Get-Date", ["HashtableAst"]),
    ("param($x = $a -eq 1) Get-Date", ["BinaryExpressionAst"]),
    # a value that is known is reported like any other; the builder makes no command of it
    ("param($n = 5, $s = 'a', $f = $false) Get-Date", ["num:5", "str:a", "$false"]),
    # in a command's arguments: the text is in that command's words
    ("Get-Date | ForEach-Object { param($x = $env:A) $x }", []),
    ("& { param($x = $env:A) $x }", []),
    ("Invoke-Command -ScriptBlock { param($x = $env:A) }", []),
    # carried by other commands of the reply
    ("param($x = (Get-Content README.md)) Get-Date", []),
    ("param($x = ${C:\\x\\y}) Get-Date", []),
]


@pytest.mark.windows
@pytest.mark.parametrize(("command", "want"), DEFAULTS)
def test_the_helper_reports_the_default_value_of_a_parameter(command: str, want: list[str]) -> None:
    assert _outputs(command) == want


@pytest.mark.windows
def test_the_entry_of_a_default_value() -> None:
    reply = _reply("param($x = $env:A) Get-Date")
    first, second = reply["commands"]
    assert first["name"] == {"kind": "output", "v": ""}
    assert first["elements"] == [{"t": "var", "name": "env:A", "splat": False}]
    assert (first["pos"], first["invoke"], first["redirects"]) == ([11, 17], "", [])
    assert (first["stage"], first["nested"]) == ({"index": 0, "of": 1}, True)
    assert second["name"]["v"] == "Get-Date"
    assert reply["loose"] == []


@pytest.mark.windows
def test_the_commands_in_a_default_value_are_reported_as_before() -> None:
    reply = _reply("param($x = (Get-Content .env)) Get-Date")
    assert [c["name"]["v"] for c in reply["commands"]] == ["Get-Content", "Get-Date"]
    decision, _ = _decide("param($x = (Get-Content .env)) Get-Date", llm=False)
    assert decision.verdict == "deny"


@pytest.mark.windows
def test_a_typed_parameter_is_still_named_in_loose() -> None:
    assert _reply("param([string]$x = $env:A) Get-Date")["loose"] == ["ParameterAst"]


BOUND = [
    f"param($x = {TOKEN}) Get-Date; $x",
    f'param($x = "key {TOKEN}") Get-Date; $x',
    f"param($a, $x = {TOKEN}) Get-Date; $x",
    f"function f($x = {TOKEN}) {{ $x }}; f",
    f"function f {{ param($x = {TOKEN}) $x }}; f",
]


@pytest.mark.windows
@pytest.mark.parametrize("command", BOUND)
def test_the_request_has_the_default_value(command: str) -> None:
    decision, backend = _decide(command, llm=True)
    assert len(backend.requests) == 1, decision.reason
    assert CANARY in backend.requests[0].content


@pytest.mark.windows
@pytest.mark.parametrize("command", BOUND[:3])
def test_it_is_judged_as_write_output_of_the_default_value(command: str) -> None:
    actions = _actions(command)
    assert [a.program for a in actions] == ["write-output", "get-date", "write-output"]
    assert "ps-dynamic-arg" in actions[0].gray_reasons


@pytest.mark.windows
def test_a_variable_default_beside_an_allowed_command_is_no_longer_allowed() -> None:
    """The cost: nothing is printed here, but the guard does not follow what $x is used for."""
    decision, _ = _decide(f"param($x = {TOKEN}) Get-Date", llm=False)
    assert decision.verdict == "gray"
    assert decision.decision == protocol.DECISION_ASK


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        "param($n = 5) Get-Date",
        "param($s = 'text', $f = $false, $z = $null) Get-Date",
        "param($x) Get-Date",
        "param($code = $LASTEXITCODE) Get-Date",
    ],
)
def test_a_known_default_changes_nothing(command: str) -> None:
    assert [a.program for a in _actions(command)] == ["get-date"]
    decision, backend = _decide(command, llm=True)
    assert decision.verdict == "allow"
    assert backend.requests == []


@pytest.mark.windows
def test_a_default_that_acts_is_still_not_sent() -> None:
    command = f"param($x = [IO.File]::ReadAllText('C:\\x\\{CANARY}')) Get-Date; $x"
    decision, backend = _decide(command, llm=True)
    assert_not_sent(decision, backend)
    assert decision.llm["detail"].startswith(pscmd.OUTSIDE_COMMAND_GRAY + ":")


@pytest.mark.windows
def test_a_script_block_s_parameter_is_in_the_words_of_its_command() -> None:
    command = f"Get-Date | ForEach-Object {{ param($x = {TOKEN}) $x }}"
    decision, backend = _decide(command, llm=True)
    assert len(backend.requests) == 1, decision.reason
    assert CANARY in backend.requests[0].content


def test_the_builder_needs_nothing_new_for_it() -> None:
    entry = out(V("env:TOKEN"), nested=True)
    res = build(rep(entry, cmd("Get-Date"), out(S("x", "single"), nested=True)))
    assert [[w.text for w in c.argv] for c in res.commands] == [
        ["Write-Output", "$env:TOKEN"],
        ["Get-Date"],
    ]
    assert res.commands[0].origin != "top"
