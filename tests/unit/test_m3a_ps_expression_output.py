"""Spec revision 22: a PowerShell expression whose value goes somewhere (O-3 of the revision 21
record).

An expression can stand where a command can. ``$env:TOKEN`` as a statement prints the value exactly
like ``Write-Output $env:TOKEN`` (measured, PowerShell 5.1), yet it is no command, so nothing
looked at it: ``Get-Date; $env:SECRET_TOKEN`` was allowed by a rule with no backend at all, while
``Write-Output $env:SECRET_TOKEN`` has been gray since the H-4 fix of M1c-2. Now the helper reports
such an expression as a command of the name kind ``output`` and it is judged as ``Write-Output
<expression>``. The places: a statement of its own, what ``return`` or ``throw`` is given, the
start of a pipeline, the collection of a ``foreach`` and the condition of a ``switch``.

A value that is known (a constant, ``$true``, ``$false``, ``$null``) is not judged, so
``Get-Date; 'done'`` is what it was.

Nothing is run: the helper only parses, the model is a fake one.
"""

from __future__ import annotations

from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.daemon import pipeline
from boundkeep.normalize import pscmd
from boundkeep.normalize.event import normalize_event

from .test_m3a_pipeline import policy
from .test_m3a_x1_fixes import (
    CANARY,
    WIN_HOME,
    _ps,
    _ps_ready,
    assert_not_sent,
    manipulated,
)
from .test_norm_pscmd import A, N, O, S, V, X, build, cmd, rep

TOKEN = "$env:" + CANARY
BRACED = "${env:" + CANARY + "}"


def _decide(command: str, *, llm: bool) -> tuple[Any, Any]:
    if not _ps_ready():
        pytest.skip("needs the PowerShell parser helper")
    pol = policy(llm=llm)
    auditor, backend = manipulated(pol) if llm else (None, None)
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        _ps(command),
        mode="enforce",
        policy=pol,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": WIN_HOME},
        home=WIN_HOME,
        scan_disk=False,
        auditor=auditor,
    )
    return decision, backend


def _actions(command: str) -> list[Any]:
    if not _ps_ready():
        pytest.skip("needs the PowerShell parser helper")
    return list(
        normalize_event(
            _ps(command), platform="windows", env={"USERPROFILE": WIN_HOME}, home=WIN_HOME
        )
    )


def _reply(command: str) -> dict[str, Any]:
    if not _ps_ready():
        pytest.skip("needs the PowerShell parser helper")
    from boundkeep.normalize import psparse

    reply, gray = psparse.helper_parse(command)
    assert reply is not None, (command, gray)
    return reply


def _shape(e: dict[str, Any]) -> str:
    kind = e["t"]
    if kind == "var":
        return "$" + e["name"]
    if kind == "other":
        return e["ast"]
    if kind == "array":
        return "[" + " ".join(_shape(i) for i in e["items"]) + "]"
    return f"{kind}:{e['v']}"


def _outputs(command: str) -> list[str]:
    """What the helper reports as an expression whose value goes somewhere, in order."""
    return [
        _shape(c["elements"][0])
        for c in _reply(command)["commands"]
        if c["name"]["kind"] == "output"
    ]


# --- a variable that is printed without a command is judged like Write-Output --------------------

PRINTED = [
    f"Get-Date; {TOKEN}",
    f"{TOKEN}; Get-Date",
    f"Get-Date\n{TOKEN}",
    f"Get-Date; {BRACED}",
    f'Get-Date; "key {TOKEN}"',
    f'Get-Date; @"\nkey {TOKEN}\n"@',
    f"Get-Date; {TOKEN}, 1",
    f"Get-Date; ({TOKEN})",
    f"Get-Date; @{{ a = {TOKEN} }}",
    f"Get-Date; $global:{CANARY}",
    f"Get-Date; ${CANARY}",
    f"git status; {TOKEN}",
]


@pytest.mark.windows
@pytest.mark.parametrize("command", PRINTED)
def test_a_printed_variable_is_no_longer_allowed_by_a_rule(command: str) -> None:
    decision, _ = _decide(command, llm=False)
    assert decision.verdict == "gray"
    assert decision.decision == protocol.DECISION_ASK
    reasons = {r for a in _actions(command) for r in a.gray_reasons}
    assert "ps-dynamic-arg" in reasons


@pytest.mark.windows
@pytest.mark.parametrize("command", PRINTED)
def test_with_a_backend_it_is_sent_and_the_request_has_its_text(command: str) -> None:
    decision, backend = _decide(command, llm=True)
    assert len(backend.requests) == 1, decision.reason
    assert decision.decided_by == "llm"
    assert CANARY in backend.requests[0].content


# The line was gray before, for a compound statement or a container, and was sent with none of the
# expression's text; the lone ones were asked because nothing of the call was understood.
SHOWN = [
    TOKEN,
    f'"key {TOKEN}"',
    f"Get-Date; $({TOKEN})",
    f"Get-Date; @({TOKEN})",
    f"Get-Date; {TOKEN} -eq 'x'",
    f"Get-Date; -not {TOKEN}",
    f"Get-Date; if ($true) {{ {TOKEN} }}",
    f"if ($true) {{ {TOKEN} }}",
    f"function f {{ {TOKEN} }}; f",
    f"try {{ {TOKEN} }} catch {{ Get-Date }}",
    f"while ($true) {{ {TOKEN}; break }}",
    f"Get-Date; return {TOKEN}",
    f"Get-Date; throw {TOKEN}",
    f"{TOKEN} | Out-Host",
    f"{TOKEN} | Set-Content x.txt",
    f"({TOKEN}) | Out-Host",
    f"foreach ($x in {TOKEN}) {{ $x }}",
    f"switch ({TOKEN}) {{ default {{ $_ }} }}",
]


@pytest.mark.windows
@pytest.mark.parametrize("command", SHOWN)
def test_where_the_value_goes_somewhere_the_request_has_the_text(command: str) -> None:
    decision, backend = _decide(command, llm=True)
    assert len(backend.requests) == 1, decision.reason
    assert CANARY in backend.requests[0].content


@pytest.mark.windows
@pytest.mark.parametrize(
    "expr",
    [
        TOKEN,
        BRACED,
        f'"key {TOKEN}"',
        f"{TOKEN}, 1",
        f"({TOKEN})",
        f"$({TOKEN})",
        f"@({TOKEN})",
        f"@{{ a = {TOKEN} }}",
        f"({TOKEN} -eq 'x')",
        "$x",
        "$PSVersionTable",
        "$global:LASTEXITCODE",
        '"exit=$LASTEXITCODE $x"',
    ],
)
def test_it_gets_what_write_output_gets(expr: str) -> None:
    bare, _ = _decide(f"Get-Date; {expr}", llm=False)
    named, _ = _decide(f"Get-Date; Write-Output {expr}", llm=False)
    assert (bare.verdict, bare.decision, bare.rule_ids) == (
        named.verdict,
        named.decision,
        named.rule_ids,
    )
    mine, theirs = _actions(f"Get-Date; {expr}"), _actions(f"Get-Date; Write-Output {expr}")
    assert [a.program for a in mine] == [a.program for a in theirs]
    assert {r for a in mine for r in a.gray_reasons} == {r for a in theirs for r in a.gray_reasons}


@pytest.mark.windows
def test_the_expression_stands_where_it_is_written_among_the_commands() -> None:
    actions = _actions(f"Get-Date; {TOKEN}; Get-Location")
    assert [a.program for a in actions] == ["get-date", "write-output", "get-location"]
    assert [p for a in actions for p in a.paths] == []


@pytest.mark.windows
def test_a_string_that_names_a_file_is_printed_not_read() -> None:
    actions = _actions('Get-Date; "$env:USERPROFILE\\.ssh\\id_rsa"')
    assert [a.program for a in actions] == ["get-date", "write-output"]
    assert [p for a in actions for p in a.paths] == []


# --- a value that is known is not judged ----------------------------------------------------------


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        "Get-Date; 'text'",
        'Get-Date; "text"',
        "Get-Date; 42",
        "Get-Date; 'a', 'b'",
        "Get-Date; @'\ntext\n'@",
        "Get-Date; $true",
        "Get-Date; $false",
        "Get-Date; $null",
        "Get-Date; $TRUE",
        "Get-Date; 1, $true, 'x'",
        "'text' | Out-Null; Get-Date",
    ],
)
def test_a_known_value_beside_an_allowed_command_changes_nothing(command: str) -> None:
    actions = _actions(command)
    assert "write-output" not in [a.program for a in actions]
    assert {r for a in actions for r in a.gray_reasons} == set()


@pytest.mark.windows
@pytest.mark.parametrize("command", ["Get-Date; 'text'", "Get-Date; 42", "Get-Date; $true"])
def test_such_a_line_is_still_allowed_by_its_rule(command: str) -> None:
    decision, backend = _decide(command, llm=True)
    assert decision.verdict == "allow"
    assert backend.requests == []


@pytest.mark.windows
def test_a_known_value_alone_is_still_nothing_understood() -> None:
    decision, backend = _decide("'text'", llm=True)
    assert_not_sent(decision, backend)


# --- an expression that acts is still not sent (revision 21) --------------------------------------


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        f"Get-Date; [IO.File]::Delete('C:\\x\\{CANARY}')",
        f"Get-Date; {TOKEN}.Length",
        f"Get-Date; [string]{TOKEN}",
        f"Get-Date; {TOKEN} + 'x'",
        f"[IO.File]::ReadAllText('C:\\x\\{CANARY}') | Out-Host",
    ],
)
def test_an_acting_expression_is_listed_and_still_not_sent(command: str) -> None:
    assert "write-output" in [a.program for a in _actions(command)]
    decision, backend = _decide(command, llm=True)
    assert_not_sent(decision, backend)
    assert decision.llm["detail"].startswith(pscmd.OUTSIDE_COMMAND_GRAY + ":")


@pytest.mark.windows
def test_an_assignment_is_still_not_sent() -> None:
    decision, backend = _decide(f"Get-Date; $x = {TOKEN}; $x", llm=True)
    assert_not_sent(decision, backend)


# --- what the helper reports ----------------------------------------------------------------------

REPORTED = [
    # a statement of its own
    ("$a", ["$a"]),
    ("Get-Date; $a; Get-Location", ["$a"]),
    ("$env:A; ${env:B}; $global:c", ["$env:A", "$env:B", "$global:c"]),
    ("\"x $a\"; 'text'; 42; 1, $b", ["expstr:x $a", "str:text", "num:42", "[num:1 $b]"]),
    ("if ($c) { $a } elseif ($d) { $b } else { 'x' }", ["$a", "$b", "str:x"]),
    ("while ($c) { $a }; do { $b } while ($c); do { $d } until ($c)", ["$a", "$b", "$d"]),
    ("for ($i = 0; $i -lt 3; $i++) { $a }", ["$a"]),
    ("try { $a } catch { $_ } finally { $b }", ["$a", "$_", "$b"]),
    ("trap { $_ }; Get-Date", ["$_"]),
    ("function f { $a }; f", ["$a"]),
    ("function f { begin { $a } process { $b } end { $c } }", ["$a", "$b", "$c"]),
    # after return and throw, not after exit
    ("return $a", ["$a"]),
    ("throw $a", ["$a"]),
    ("exit $a", []),
    # the start of a pipeline, wherever the pipeline stands
    ("$a | Out-Null", ["$a"]),
    ("'x' | Out-Null", ["str:x"]),
    ("if ($a | Out-Null) { }", ["$a"]),
    ("$b = $a | Out-String", ["$a"]),
    # what a loop or a switch binds to a variable
    ("foreach ($x in $list) { $x }", ["$list", "$x"]),
    ("switch ($v) { 1 { $a } default { $b } }", ["$v", "$a", "$b"]),
    # a container is one expression; what is inside is in its text
    ("($a)", ["ParenExpressionAst"]),
    ("$($a; $b)", ["SubExpressionAst"]),
    ("@($a)", ["ArrayExpressionAst"]),
    ("@{ k = $a }", ["HashtableAst"]),
    ("$a -eq 1", ["BinaryExpressionAst"]),
    ("[IO.File]::Delete('x')", ["InvokeMemberExpressionAst"]),
    # a value that is only tested, or assigned
    ("if ($c) { }", []),
    ("while ($c) { }", []),
    ("do { } until ($c)", []),
    ("for (; $c;) { }", []),
    ("$b = $a", []),
    ("$b = ($a)", []),
    # in a command's arguments
    ("Write-Output $a", []),
    ("& { $a }", []),
    ("Get-Date | ForEach-Object { $_ }", []),
    ("Invoke-Command -ScriptBlock { if ($c) { $a } }", []),
    ("Write-Output $($a)", []),
    # a drive-qualified variable is a command of its own; in a string it is part of the string
    ("${C:\\x\\y}", []),
    ("${C:\\x\\y} | Out-Null", []),
    ('"${C:\\x\\y}"', ["expstr:${C:\\x\\y}"]),
    ("$env:A", ["$env:A"]),
    # parentheses around commands only: the commands are reported on their own
    ("(Get-Location)", []),
    ("(Get-Content f | Select-Object -First 1)", []),
    ("(Get-Content f) | Select-Object", []),
    ("('f' | Get-Content)", ["ParenExpressionAst", "str:f"]),
    ("((Get-Location))", ["ParenExpressionAst"]),
    ("($b = Get-Location)", ["ParenExpressionAst"]),
]


@pytest.mark.windows
@pytest.mark.parametrize(
    "command", ["Get-Date; (Get-Location)", "(Get-Location)", "git status; (Get-Date)"]
)
def test_a_command_in_parentheses_gets_what_the_command_gets(command: str) -> None:
    bare = command.replace("(", "").replace(")", "")
    wrapped, _ = _decide(command, llm=False)
    plain, _ = _decide(bare, llm=False)
    assert (wrapped.verdict, wrapped.rule_ids) == (plain.verdict, plain.rule_ids)
    assert wrapped.verdict == "allow"


@pytest.mark.windows
@pytest.mark.parametrize(("command", "want"), REPORTED)
def test_the_helper_reports_an_expression_whose_value_goes_somewhere(
    command: str, want: list[str]
) -> None:
    assert _outputs(command) == want


@pytest.mark.windows
def test_the_entry_has_the_shape_of_a_command() -> None:
    reply = _reply("Get-Date; $a | Out-Null; if ($c) { $b }")
    kinds = [c["name"]["kind"] for c in reply["commands"]]
    assert kinds == ["bare", "output", "bare", "output"]
    head, _, inner = reply["commands"][1:]
    # the head of a pipeline binds its value to the next stage (spec revision 28)
    shape = {"pos", "invoke", "name", "elements", "redirects", "stage", "nested", "bind"}
    assert set(head) == shape
    assert head["bind"] == "head"
    assert "bind" not in inner
    assert head["name"] == {"kind": "output", "v": ""}
    assert (head["pos"], head["invoke"], head["redirects"]) == ([10, 12], "", [])
    assert (head["stage"], head["nested"]) == ({"index": 0, "of": 2}, False)
    assert (inner["stage"], inner["nested"]) == ({"index": 0, "of": 1}, True)


@pytest.mark.windows
def test_an_expression_with_a_redirection_is_reported_as_before() -> None:
    reply = _reply("$a > out.txt")
    assert [c["name"]["kind"] for c in reply["commands"]] == ["expr"]
    assert reply["commands"][0]["elements"] == []


@pytest.mark.windows
def test_the_helper_s_other_lists_are_what_they_were() -> None:
    reply = _reply("Get-Date; $a; if ($c) { $b.d }")
    assert reply["compound"] == ["IfStatementAst"]
    assert reply["dynamic"] == ["MemberExpressionAst"]
    assert reply["loose"] == ["MemberExpressionAst"]


# --- the builder ----------------------------------------------------------------------------------


def out(element: Any, *, stage: tuple[int, int] | None = (0, 1), nested: bool = False) -> Any:
    return cmd("", element, kind="output", stage=stage, nested=nested)


def test_the_builder_reads_it_as_write_output_of_the_expression() -> None:
    res = build(rep(cmd("Get-Date"), out(V("env:TOKEN")), cmd("Get-Location")))
    assert [[w.text for w in c.argv] for c in res.commands] == [
        ["Get-Date"],
        ["Write-Output", "$env:TOKEN"],
        ["Get-Location"],
    ]
    word = res.commands[1].argv[1]
    assert (word.expands, word.glob) == (True, False)
    assert res.gray == ()
    assert res.exec_reasons == ()


@pytest.mark.parametrize(
    ("element", "words", "gray"),
    [
        (X("key $env:TOKEN", "env:TOKEN"), ["key $env:TOKEN"], set()),
        (A(V("a"), N("1")), ["$a", ",", "1"], set()),
        (O("ParenExpressionAst", "($a)"), ["$(($a))"], {"ps-dynamic-value:ParenExpressionAst"}),
        (X("a $($b)", subexpr=True), ["a $($b)"], {"ps-subexpression"}),
        (V("truex"), ["$truex"], set()),
        (V("global:true"), ["$global:true"], set()),
        (A(N("1"), V("x")), ["1", ",", "$x"], set()),
    ],
)
def test_the_words_of_the_expression(element: Any, words: list[str], gray: set[str]) -> None:
    res = build(rep(out(element)))
    assert [w.text for w in res.commands[0].argv] == ["Write-Output", *words]
    assert set(res.gray) == gray


@pytest.mark.parametrize(
    "element",
    [
        S("text", "single"),
        S("text", "double"),
        S("a`b", "single"),
        S("", "single"),
        N("42"),
        A(S("a", "single"), N("1")),
        V("true"),
        V("FALSE"),
        V("Null"),
        A(N("1"), V("true"), S("x", "single")),
    ],
)
def test_a_known_value_is_no_command(element: Any) -> None:
    res = build(rep(cmd("Get-Date"), out(element)))
    assert [c.argv[0].text for c in res.commands] == ["Get-Date"]
    assert res.gray == ()


def test_an_array_with_nothing_in_it_is_not_a_known_value() -> None:
    res = build(rep(out(A())))
    assert [[w.text for w in c.argv] for c in res.commands] == [["Write-Output"]]


def test_a_splat_is_not_a_known_value() -> None:
    res = build(rep(out(V("true", splat=True))))
    assert [c.argv[0].text for c in res.commands] == ["Write-Output"]
    assert "ps-dynamic-value:Splat" in res.gray


@pytest.mark.parametrize("elements", [[], [V("a"), V("b")], None, "x", {"t": "var"}])
def test_an_entry_without_exactly_one_expression_is_not_trusted(elements: Any) -> None:
    broken = out(V("a"))
    broken["elements"] = elements
    res = build(rep(cmd("Get-Date"), broken))
    assert "ps-internal-error" in res.gray
    assert [c.argv[0].text for c in res.commands] == ["Get-Date"]


@pytest.mark.parametrize("value", ["Get-Date", None, 5])
def test_an_entry_with_a_name_is_not_trusted(value: Any) -> None:
    broken = out(V("a"))
    broken["name"]["v"] = value
    res = build(rep(cmd("Get-Date"), broken))
    assert "ps-internal-error" in res.gray
    assert [c.argv[0].text for c in res.commands] == ["Get-Date"]


@pytest.mark.parametrize(
    "damage",
    [{"invoke": "x"}, {"redirects": 5}, {"redirects": [5]}],
)
def test_a_known_value_in_a_malformed_entry_is_still_gray(damage: dict[str, Any]) -> None:
    broken = {**out(S("text", "single")), **damage}
    res = build(rep(cmd("Get-Date"), broken))
    assert "ps-internal-error" in res.gray
    assert [c.argv[0].text for c in res.commands] == ["Get-Date"]


def test_a_value_that_starts_with_a_dash_is_no_parameter() -> None:
    res = build(rep(out(X("-Force $a", "a"))))
    word = res.commands[0].argv[1]
    assert (word.text, word.quoted) == ("-Force $a", True)


def test_at_the_start_of_a_pipeline_it_is_a_stage() -> None:
    later = cmd("Out-Host", stage=(1, 2))
    later["stage"]["head"] = V("a")
    res = build(rep(out(V("a"), stage=(0, 2)), later))
    assert [c.argv[0].text for c in res.commands] == ["Write-Output", "Out-Host"]
    assert [c.in_pipeline for c in res.commands] == [True, True]
    assert "ps-pipeline-head-dynamic" in res.gray


def test_nested_it_is_not_a_top_level_command() -> None:
    res = build(rep(out(V("a"), nested=True), compound=("IfStatementAst",)))
    assert res.commands[0].origin != "top"


def test_the_name_is_not_looked_up_as_an_alias() -> None:
    """The line may redefine any alias; the expression is printed all the same."""
    res = build(rep(cmd("Set-Alias", S("Write-Output"), S("x")), out(V("a"))))
    assert [w.text for w in res.commands[1].argv] == ["Write-Output", "$a"]
    assert "ps-alias-shadowed" not in res.exec_reasons
