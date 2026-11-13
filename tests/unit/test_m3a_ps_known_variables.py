"""Spec revision 23: ``$LASTEXITCODE`` and ``$?`` are known values where a value is printed.

Revision 22 judges an expression whose value goes somewhere as ``Write-Output <expression>``, and a
value that is known makes no command. The exit code of the last program and whether the last
statement succeeded are now known too, so ``git status; $LASTEXITCODE`` is allowed by its rule
again. A double-quoted string that expands nothing else counts (``"exit=$LASTEXITCODE"``).

Only the unqualified names count, and only in that place: as an argument of a command the variable
is the expanding word it was.

A parameter or a ``foreach`` variable of that name holds whatever the line binds to it (measured on
PowerShell 5.1: ``param($LASTEXITCODE = $env:X) $LASTEXITCODE`` prints the environment variable).
The helper reports such a line in ``loose`` as ``AutomaticVariable``: gray, and not sent.

Nothing is run: the helper only parses, the model is a fake one.
"""

from __future__ import annotations

from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.normalize import pscmd

from .test_m3a_ps_expression_output import _actions, _decide, _outputs, _reply, out
from .test_m3a_x1_fixes import CANARY, assert_not_sent
from .test_norm_pscmd import A, N, O, P, S, V, X, build, cmd, rep

TOKEN = "$env:" + CANARY

KNOWN = [
    "$LASTEXITCODE",
    "$?",
    "${LASTEXITCODE}",
    "${?}",
    "$lastexitcode",
    "$LastExitCode",
    '"exit=$LASTEXITCODE"',
    '"exit=${LASTEXITCODE}"',
    '"ok=$? code=$LASTEXITCODE"',
    '"$LASTEXITCODE"',
    '"done: $true $LASTEXITCODE"',
    '"exit=$LASTEXITCODE`n"',
    '"cost `$5, exit $LASTEXITCODE"',
    '@"\nexit=$LASTEXITCODE\n"@',
    "$LASTEXITCODE, $?",
    "'exit', $LASTEXITCODE",
    '1, "code $LASTEXITCODE", $null',
]


# --- the closing line of a command is allowed again -----------------------------------------------


@pytest.mark.windows
@pytest.mark.parametrize("expr", KNOWN)
def test_beside_an_allowed_command_it_changes_nothing(expr: str) -> None:
    command = f"Get-Date; {expr}"
    actions = _actions(command)
    assert [a.program for a in actions] == ["get-date"]
    assert {r for a in actions for r in a.gray_reasons} == set()
    decision, backend = _decide(command, llm=True)
    assert decision.verdict == "allow"
    assert backend.requests == []


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        "git status; $LASTEXITCODE",
        "git status; $?",
        'git status; "exit=$LASTEXITCODE"',
        "git status\n$LASTEXITCODE",
    ],
)
def test_the_line_gets_what_the_line_without_it_gets(command: str) -> None:
    first = command.replace("\n", ";").split(";")[0]
    with_it, _ = _decide(command, llm=False)
    without, _ = _decide(first, llm=False)
    assert (with_it.verdict, with_it.decision) == (without.verdict, without.decision)
    assert with_it.verdict == "allow"


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        "Get-Date; if ($true) { $LASTEXITCODE }",
        "Get-Date; return $LASTEXITCODE",
        "Get-Date; throw $LASTEXITCODE",
        "foreach ($code in $LASTEXITCODE) { Get-Date }",
        "switch ($LASTEXITCODE) { 0 { Get-Date } }",
        "function f { $LASTEXITCODE }; f",
    ],
)
def test_in_every_place_it_gets_what_a_constant_gets(command: str) -> None:
    constant = command.replace("$LASTEXITCODE", "7")
    mine, theirs = _actions(command), _actions(constant)
    assert [a.program for a in mine] == [a.program for a in theirs]
    assert "write-output" not in [a.program for a in mine]
    with_it, _ = _decide(command, llm=False)
    with_7, _ = _decide(constant, llm=False)
    assert (with_it.verdict, with_it.decision, with_it.rule_ids) == (
        with_7.verdict,
        with_7.decision,
        with_7.rule_ids,
    )


@pytest.mark.windows
def test_at_the_start_of_a_pipeline_the_next_command_still_carries_it() -> None:
    actions = _actions("$LASTEXITCODE | Out-Host")
    assert "write-output" not in [a.program for a in actions]
    assert "ps-pipeline-head-dynamic" in {r for a in actions for r in a.gray_reasons}


@pytest.mark.windows
def test_alone_it_is_still_nothing_understood() -> None:
    decision, backend = _decide("$LASTEXITCODE", llm=True)
    assert_not_sent(decision, backend)


@pytest.mark.windows
def test_the_helper_reports_it_like_any_other_variable() -> None:
    """The helper does not decide what is known: the entry is there and the builder drops it."""
    assert _outputs('Get-Date; $LASTEXITCODE; "exit=$LASTEXITCODE"') == [
        "$LASTEXITCODE",
        "expstr:exit=$LASTEXITCODE",
    ]


# --- what is not known ----------------------------------------------------------------------------

NOT_KNOWN = [
    "$global:LASTEXITCODE",
    "$script:LASTEXITCODE",
    "$env:LASTEXITCODE",
    "$LASTEXITCODEx",
    "$LASTEXITCODES",
    f'"exit=$LASTEXITCODE {TOKEN}"',
    f"$LASTEXITCODE, {TOKEN}",
    '"exit=$($LASTEXITCODE)"',
    '"exit=$global:LASTEXITCODE"',
    "($LASTEXITCODE)",
    "@{ code = $LASTEXITCODE }",
    "$Error",
    "$PSItem",
    "$_",
]


@pytest.mark.windows
@pytest.mark.parametrize("expr", NOT_KNOWN)
def test_anything_else_is_judged_as_write_output(expr: str) -> None:
    command = f"Get-Date; {expr}"
    assert [a.program for a in _actions(command)][:2] == ["get-date", "write-output"]
    decision, _ = _decide(command, llm=False)
    assert decision.verdict == "gray"
    assert decision.decision == protocol.DECISION_ASK


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        "Get-Date; Write-Output $LASTEXITCODE",
        "Get-Date; Write-Output $?",
        'Get-Date; Write-Output "exit=$LASTEXITCODE"',
        "Get-Date; ConvertTo-Json $LASTEXITCODE",
        "Get-Date -Format $LASTEXITCODE",
        "Get-ChildItem -Recurse:$LASTEXITCODE",
    ],
)
def test_as_an_argument_of_a_command_it_is_what_it_was(command: str) -> None:
    decision, _ = _decide(command, llm=False)
    assert decision.verdict == "gray"
    reasons = {r for a in _actions(command) for r in a.gray_reasons}
    assert reasons & {"ps-dynamic-arg", pscmd.SWITCH_VALUE_GRAY}


@pytest.mark.windows
@pytest.mark.parametrize("expr", ["$LASTEXITCODE.ToString()", "$LASTEXITCODE + 1", "-not $?"])
def test_computing_with_it_is_what_it_was(expr: str) -> None:
    assert "write-output" in [a.program for a in _actions(f"Get-Date; {expr}")]


# --- a line that binds the name itself ------------------------------------------------------------

BOUND = [
    f"param($LASTEXITCODE = {TOKEN}) Get-Date; $LASTEXITCODE",
    f"param(${{LASTEXITCODE}} = {TOKEN}) Get-Date; $LASTEXITCODE",
    f"param($lastexitcode = {TOKEN}) Get-Date; $LASTEXITCODE",
    f"param($script:LASTEXITCODE = {TOKEN}) Get-Date; $LASTEXITCODE",
    f"param($a, $LASTEXITCODE = {TOKEN}) Get-Date; $LASTEXITCODE",
    f"param(${{?}} = {TOKEN}) Get-Date; $?",
    f"foreach ($LASTEXITCODE in {TOKEN}) {{ }}; Get-Date; $LASTEXITCODE",
    f"foreach ($LASTEXITCODE in {TOKEN}) {{ $LASTEXITCODE }}",
    f"foreach ($global:LASTEXITCODE in {TOKEN}) {{ }}; Get-Date; $LASTEXITCODE",
    "foreach ($LASTEXITCODE in (Get-Content README.md)) { $LASTEXITCODE }",
    f"Get-Date | ForEach-Object {{ param($LASTEXITCODE = {TOKEN}) $LASTEXITCODE }}",
    f"& {{ param($LASTEXITCODE = {TOKEN}) $LASTEXITCODE }}",
    f". {{ param($LASTEXITCODE = {TOKEN}) }}; $LASTEXITCODE",
    f"function f($LASTEXITCODE = {TOKEN}) {{ $LASTEXITCODE }}; f",
    f"function f {{ param($LASTEXITCODE = {TOKEN}) $LASTEXITCODE }}; f",
    "param($LASTEXITCODE) Get-Date; $LASTEXITCODE",
]


@pytest.mark.windows
@pytest.mark.parametrize("command", BOUND)
def test_the_helper_names_a_line_that_binds_the_name(command: str) -> None:
    assert "AutomaticVariable" in _reply(command)["loose"]


@pytest.mark.windows
@pytest.mark.parametrize("command", BOUND)
def test_such_a_line_is_asked_and_not_sent(command: str) -> None:
    plain, _ = _decide(command, llm=False)
    assert plain.verdict == "gray"
    assert plain.decision == protocol.DECISION_ASK
    reasons = {r for a in _actions(command) for r in a.gray_reasons}
    assert pscmd.OUTSIDE_COMMAND_GRAY + ":AutomaticVariable" in reasons
    decision, backend = _decide(command, llm=True)
    assert_not_sent(decision, backend)


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        f"Get-Date; $LASTEXITCODE = {TOKEN}; $LASTEXITCODE",
        f"Get-Date; $global:LASTEXITCODE = {TOKEN}; $LASTEXITCODE",
        f"Get-Date | ForEach-Object {{ $LASTEXITCODE = {TOKEN} }}; $LASTEXITCODE",
        f"for ($LASTEXITCODE = {TOKEN}; $false) {{ }}; Get-Date; $LASTEXITCODE",
        f"if (($LASTEXITCODE = {TOKEN})) {{ }}; Get-Date; $LASTEXITCODE",
    ],
)
def test_an_assignment_to_it_is_still_asked_and_not_sent(command: str) -> None:
    plain, _ = _decide(command, llm=False)
    assert plain.verdict == "gray"
    decision, backend = _decide(command, llm=True)
    assert_not_sent(decision, backend)


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        "param($x = 1) Get-Date",
        "foreach ($x in 1, 2) { Get-Date }",
        "param($LASTEXITCODES = 1) Get-Date",
        "foreach ($code in $LASTEXITCODE) { Get-Date }",
        "function f($x) { Get-Date }",
        "Get-Date | ForEach-Object { param($x) Get-Date }",
    ],
)
def test_other_parameters_and_loops_are_not_named(command: str) -> None:
    assert "AutomaticVariable" not in _reply(command)["loose"]


@pytest.mark.windows
def test_a_typed_parameter_is_named_as_before_and_once() -> None:
    reply = _reply("param([int]$LASTEXITCODE = 1, [int]$x = 2) Get-Date")
    assert sorted(reply["loose"]) == ["AutomaticVariable", "ParameterAst"]
    assert _reply("param([int]$x = 2) Get-Date")["loose"] == ["ParameterAst"]
    assert _reply("param($LASTEXITCODE = 1) Get-Date")["loose"] == ["AutomaticVariable"]
    assert _reply("foreach ($LASTEXITCODE in 1) { }")["loose"] == ["AutomaticVariable"]


# --- a command that is given the name, or anything that is not constant ---------------------------

NAMED = [
    f"Set-Variable LASTEXITCODE {TOKEN}; $LASTEXITCODE",
    f"Set-Variable -Name LASTEXITCODE -Value {TOKEN}; $LASTEXITCODE",
    f"Set-Variable -Name:lastexitcode -Value {TOKEN}; $LASTEXITCODE",
    f"New-Variable LASTEXITCODE {TOKEN} -Force; $LASTEXITCODE",
    "Get-Date -OutVariable LASTEXITCODE; $LASTEXITCODE",
    "Get-Date -OutVariable:LASTEXITCODE; $LASTEXITCODE",
    "Get-Date -ov +lastexitcode; $LASTEXITCODE",
    'Get-Date -ov "LASTEXITCODE"; "exit=$LASTEXITCODE"',
    f"{TOKEN} | Tee-Object -Variable LASTEXITCODE; $LASTEXITCODE",
    f"Get-Item Env:{CANARY} | Set-Item Variable:\\LAST*; $LASTEXITCODE",
    f"Get-Item Env:{CANARY} | Set-Item variable:lastexitcode; $LASTEXITCODE",
    f"Get-Item Env:{CANARY} | Set-Variable LASTEXIT*; $LASTEXITCODE",
    f"Get-Item Env:{CANARY} | Set-Variable L[a]STEXITCOD?; $LASTEXITCODE",
    f"Get-Item Env:{CANARY} | Set-Variable *; $LASTEXITCODE",
    "Set-Variable ('LAST' + 'EXITCODE') 1; $LASTEXITCODE",
    "Set-Variable $name 1; $LASTEXITCODE",
    'Set-Variable "LAST$x" 1; $LASTEXITCODE',
    "Get-Date | ForEach-Object { $_ }; $LASTEXITCODE",
    "& $cmd; $LASTEXITCODE",
    "& { Get-Date }; $LASTEXITCODE",
    f"Get-Date -Format {TOKEN}; $?",
    "Get-Date @args; $LASTEXITCODE",
]


@pytest.mark.windows
@pytest.mark.parametrize("command", NAMED)
def test_beside_such_a_command_it_is_judged_as_write_output(command: str) -> None:
    assert "write-output" in [a.program for a in _actions(command)]
    decision, _ = _decide(command, llm=False)
    assert decision.verdict == "gray"
    assert decision.decision == protocol.DECISION_ASK


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        f"Set-Variable LASTEXITCODE {TOKEN}; $LASTEXITCODE",
        "Get-Date -OutVariable LASTEXITCODE; $LASTEXITCODE",
        f"Get-Item Env:{CANARY} | Set-Variable LASTEXIT*; $LASTEXITCODE",
    ],
)
def test_with_a_backend_the_request_has_the_print(command: str) -> None:
    decision, backend = _decide(command, llm=True)
    assert len(backend.requests) == 1, decision.reason
    content = backend.requests[0].content
    assert "write-output" in content.lower()
    assert "$LASTEXITCODE" in content


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        "npm test; $LASTEXITCODE",
        'npm test; "exit=$LASTEXITCODE"',
        "make; $?",
        ".\\build.ps1; $LASTEXITCODE",
        "python -m pytest -q tests/unit; $LASTEXITCODE",
        "cmd /c 'exit 3'; $LASTEXITCODE",
        "Get-ChildItem *.py; $LASTEXITCODE",
        "Get-Content README.md | Select-Object -First 3; $?",
        "git log --oneline -n 5 -- src/*.py; $LASTEXITCODE",
    ],
)
def test_beside_commands_with_constant_arguments_it_is_no_command(command: str) -> None:
    assert "write-output" not in [a.program for a in _actions(command)]


# --- the builder ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "element",
    [
        V("LASTEXITCODE"),
        V("lastexitcode"),
        V("?"),
        X("exit=$LASTEXITCODE", "LASTEXITCODE"),
        X("ok=$? code=$LASTEXITCODE", "?", "LASTEXITCODE"),
        X("$true $LASTEXITCODE", "true", "LASTEXITCODE"),
        A(V("LASTEXITCODE"), V("?")),
        A(S("exit", "single"), X("code $LASTEXITCODE", "LASTEXITCODE"), N("1")),
    ],
)
def test_the_builder_makes_no_command_of_it(element: Any) -> None:
    res = build(rep(cmd("Get-Date"), out(element)))
    assert [c.argv[0].text for c in res.commands] == ["Get-Date"]
    assert res.gray == ()


def _expstr(**changes: Any) -> dict[str, Any]:
    return {**X("exit=$LASTEXITCODE", "LASTEXITCODE"), **changes}


@pytest.mark.parametrize(
    "element",
    [
        V("global:LASTEXITCODE"),
        V("env:LASTEXITCODE"),
        V("LASTEXITCODEx"),
        V("LASTEXITCODE", splat=True),
        V("??"),
        X("exit=$LASTEXITCODE $a", "LASTEXITCODE", "a"),
        X("exit=$($LASTEXITCODE)", subexpr=True),
        _expstr(subexpr=True),
        _expstr(subexpr=None),
        _expstr(vars=[]),
        _expstr(vars=None),
        _expstr(vars="LASTEXITCODE"),
        _expstr(vars=["LASTEXITCODE", 5]),
        _expstr(v=None),
        A(V("LASTEXITCODE"), V("a")),
    ],
)
def test_the_builder_keeps_everything_else(element: Any) -> None:
    res = build(rep(cmd("Get-Date"), out(element)))
    assert [c.argv[0].text for c in res.commands] == ["Get-Date", "Write-Output"]


@pytest.mark.parametrize(
    "other",
    [
        cmd("Set-Variable", S("LASTEXITCODE"), N("1")),
        cmd("Set-Variable", S("lastExitCode", "single"), N("1")),
        cmd("Get-Date", P("OutVariable"), S("+LASTEXITCODE")),
        cmd("Get-Date", P("OutVariable", S("LASTEXITCODE", "double"))),
        cmd("Set-Item", S("Variable:\\LAST*")),
        cmd("Set-Item", S("variable:/l?stexitcode")),
        cmd("Set-Item", S("variable:LAST*")),
        cmd("Set-Item", S("C:\\x\\LAST*")),
        cmd("Set-Variable", S("*")),
        cmd("Get-ChildItem", S("src\\*")),  # the cost of not knowing what the argument is for
        cmd("Set-Variable", S("[a-z]*code")),
        cmd("Set-Variable", A(S("a"), S("LASTEXITCODE"))),
        cmd("Set-Variable", A(S("a"), A(S("LASTEXIT*")))),
        cmd("Get-Date", V("x")),
        cmd("Get-Date", X("$x", "x")),
        cmd("Get-Date", O("ParenExpressionAst", "('a')")),
        cmd("Get-Date", P("Format", V("x"))),
        cmd("Get-Date", A(S("a"), V("x"))),
        cmd("x", kind="variable"),
        cmd("x", kind="expandable"),
        cmd("x", kind="expr"),
        {**cmd("Get-Date"), "elements": None},
        {**cmd("Get-Date"), "elements": [5]},
        {**cmd("Get-Date"), "elements": [{"t": "str", "kind": "bare", "v": 5}]},
        {**cmd("Get-Date"), "name": None},
        5,
    ],
)
def test_beside_anything_that_could_name_it_the_builder_keeps_it(other: Any) -> None:
    res = build(rep(other, out(V("LASTEXITCODE")), out(X("exit=$?", "?"))))
    assert [c.argv[0].text for c in res.commands][-2:] == ["Write-Output", "Write-Output"]


@pytest.mark.parametrize(
    "other",
    [
        cmd("git", S("status")),
        cmd("Get-ChildItem", S("*.py"), P("Recurse")),
        cmd("Get-ChildItem", S("src\\*.py"), P("Filter", S("*.code"))),
        cmd("npm", S("test"), S("--"), S("--last"), N("1")),
        cmd("Get-Content", A(S("a.txt"), S("b.txt")), P("TotalCount", N("3"))),
        cmd("Get-Date", kind="single"),
        cmd("", V("env:TOKEN"), kind="output"),
        cmd("C:\\proj\\README.md", kind="file-read", stage=None, nested=True),
    ],
)
def test_beside_anything_else_the_builder_drops_it(other: Any) -> None:
    res = build(rep(other, out(V("LASTEXITCODE"))))
    assert "$LASTEXITCODE" not in [w.text for c in res.commands for w in c.argv]


def test_true_false_and_null_do_not_depend_on_the_other_commands() -> None:
    res = build(rep(cmd("Set-Variable", S("true"), V("x")), out(V("true")), out(V("null"))))
    assert [c.argv[0].text for c in res.commands] == ["Set-Variable"]


def test_a_line_the_helper_named_is_gray_whatever_its_commands_are() -> None:
    res = build(rep(cmd("Get-Date"), out(V("LASTEXITCODE")), loose=("AutomaticVariable",)))
    assert [c.argv[0].text for c in res.commands] == ["Get-Date"]
    assert res.gray == (pscmd.OUTSIDE_COMMAND_GRAY + ":AutomaticVariable",)
