"""Spec revision 21: PowerShell text that is in no command (review of revisions 19 and 20, O-1).

The request to the LLM audit lists commands with their words, paths and hosts. PowerShell also
runs text that is no command:

* an expression statement, a condition, what ``return`` or ``throw`` is given, a parameter's
  default, a pipeline's head, a redirection's target. ``git status; [IO.File]::ReadAllText('.env')``
  was sent with none of the expression's text. Now everything of that kind that is not known to do
  nothing is gray ``ps-outside-command:<type>`` and the call is not sent;
* a drive-qualified variable. ``${C:\\x\\.env}`` is the content of that file, an assignment to it
  writes the file and a wildcard in the name is expanded (measured, PowerShell 5.1).
  ``Get-Date; ${E:\\proj\\.env}`` was allowed by a rule, with no backend at all. Now each one is
  judged as ``Get-Content -Path`` / ``Set-Content -Path`` of that path.

Three kinds of text that are in a command and were in no action's words either: the computed value
of a switch, of an option of ``uv run`` and the other runners, and a program name longer than the
request shows.

Nothing is run: the helper only parses, the model is a fake one.
"""

from __future__ import annotations

from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.audit import send_gate
from boundkeep.daemon import pipeline
from boundkeep.normalize import pscmd
from boundkeep.normalize.event import normalize_event
from boundkeep.session.facts import FRESH

from .test_m3a_pipeline import policy
from .test_m3a_x1_fixes import (
    CANARY,
    WIN_HOME,
    WIN_PROJECT,
    _ps,
    _ps_ready,
    assert_not_sent,
    manipulated,
)
from .test_norm_pscmd import O, P, S, V, build, cmd, rep

CALL = f"[IO.File]::Delete('C:\\x\\{CANARY}')"
ENV = WIN_PROJECT + "\\.env"
PREFIX = pscmd.OUTSIDE_COMMAND_GRAY + ":"


def _audited(command: str, *, on_failure: str = "ask") -> tuple[Any, Any]:
    if not _ps_ready():
        pytest.skip("needs the PowerShell parser helper")
    pol = policy(llm=True, on_failure=on_failure)
    auditor, backend = manipulated(pol)
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


def _loose(command: str) -> set[str]:
    return set(_reply(command)["loose"])


def _files(command: str) -> list[tuple[str, str]]:
    """(name kind, path) of the drive-qualified variables, in the order of the reply."""
    return [
        (c["name"]["kind"], c["name"]["v"])
        for c in _reply(command)["commands"]
        if c["name"]["kind"].startswith("file-")
    ]


# --- O-1: an expression that is in no command is not sent -----------------------------------------

OUTSIDE = [
    f"git status; {CALL}",
    f"Get-Date; (New-Object Net.WebClient).DownloadString('https://{CANARY}.invalid/a')",
    f"Get-Date; [IO.StreamWriter]'C:\\x\\{CANARY}'",
    f"Get-Date; 'C:\\x\\{CANARY}' -as [IO.StreamWriter]",
    "Get-Date; [Environment]::UserName",
    f'Get-Date; "a $({CALL})"',
    f"Get-Date; if ([IO.File]::Exists('C:\\x\\{CANARY}')) {{ Get-Date }}",
    f"Get-Date; if ($true) {{ {CALL} }}",
    f"Get-Date; while ([IO.File]::Exists('C:\\x\\{CANARY}')) {{ Get-Date }}",
    f"foreach ($f in [IO.Directory]::GetFiles('C:\\x\\{CANARY}')) {{ Get-Date }}",
    f"switch ([IO.File]::ReadAllText('{CANARY}')) {{ 'a' {{ Get-Date }} }}",
    f"Get-Date; return {CALL}",
    f"Get-Date; throw {CALL}",
    f"Get-Date; exit [IO.File]::ReadAllBytes('{CANARY}').Length",
    f"Get-Date; function f {{ {CALL} }}; f",
    f"function f($a = {CALL}) {{ Get-Date }}; f",
    f"function f([IO.StreamWriter]$w) {{ Get-Date }}; f C:\\x\\{CANARY}",
    f"try {{ {CALL} }} catch {{ Get-Date }}",
    f"Get-Date; @{{ a = {CALL} }}",
    f"Get-Date; @({CALL})",
    f"Get-Date; ({CALL})",
    f"using module .\\sub\\{CANARY}.psm1; Get-Date",
    f"using assembly .\\sub\\{CANARY}.dll; Get-Date",
    f"switch -File {CANARY}.txt {{ default {{ Get-Date }} }}",
    f"({CALL}) | Out-Null",
    f"Get-Date > ({CALL})",
    f"{CALL} > out.txt",
    "Get-Date; $a.Count",
    "Get-Date; $a[0]",
    "Get-Date; [int]$a",
    "Get-Date; 1..3",
    "Get-Date; '{0}' -f $a",
    "Get-Date; $a -replace 'x', 'y'",
    "Get-Date; $a + 1",
    "Get-Date; $a++",
]


@pytest.mark.windows
@pytest.mark.parametrize("command", OUTSIDE)
@pytest.mark.parametrize("on_failure", ["ask", "deny"])
def test_text_that_is_in_no_command_is_not_sent(command: str, on_failure: str) -> None:
    decision, backend = _audited(command, on_failure=on_failure)
    assert decision.verdict == "gray"
    assert_not_sent(decision, backend)
    assert decision.llm["detail"].startswith(PREFIX)


@pytest.mark.windows
def test_the_review_s_command_names_what_was_outside() -> None:
    actions = _actions(f"git status; {CALL}")
    # revision 22 lists the statement as Write-Output of the expression; it is still not sent
    assert [a.program for a in actions if a.program] == ["git", "write-output"]
    reasons = {r for a in actions for r in a.gray_reasons}
    assert PREFIX + "InvokeMemberExpressionAst" in reasons
    assert pipeline.incomplete_analysis(actions) is None
    assert pipeline.unshown_input(actions) == PREFIX + "InvokeMemberExpressionAst"


@pytest.mark.windows
def test_alone_it_is_still_not_sent() -> None:
    decision, backend = _audited(CALL)
    assert_not_sent(decision, backend)


# --- what does nothing, and what is in a command, is sent as before -------------------------------


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        "make test; if ($LASTEXITCODE -ne 0) { exit 1 }",
        "make test; if (-not $?) { exit 1 }",
        "make test; if ($a -eq 1 -and $b -like 'x*' -or !$c) { Get-Date }",
        "make test; while ($i -lt 3) { Get-Date }",
        "make test; $LASTEXITCODE -ne 0",
        "using namespace System.IO; make test",
        "make test; foreach ($f in $files) { Get-Date }",
        "make test; switch ($a) { 1 { Get-Date } }",
        "make test; function f($n) { Get-Date }; f 1",
        "make test; try { Get-Date } catch { Get-Date } finally { Get-Date }",
        "make test > $out",
        'make test; "done $a"',
    ],
)
def test_structure_comparison_and_logic_are_still_sent(command: str) -> None:
    decision, backend = _audited(command)
    assert len(backend.requests) == 1, decision.reason
    assert decision.decided_by == "llm"


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        f"Write-Output ({CALL})",
        f"Get-Date | ForEach-Object {{ {CALL} }}",
        f"& {{ {CALL} }}",
        f'Write-Output "a $({CALL})"',
        f"Get-Date | ForEach-Object {{ Write-Output ({CALL}) }}",
        f"Select-Object @{{ n = 'a'; e = {{ {CALL} }} }}",
        f"Invoke-Command -ScriptBlock {{ param([string]$p) {CALL} }}",
    ],
)
def test_an_expression_in_a_command_s_arguments_is_sent_with_its_text(command: str) -> None:
    decision, backend = _audited(command)
    assert len(backend.requests) == 1, decision.reason
    assert CANARY in backend.requests[0].content


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    ["Get-Date; 'text'", "Get-Date; 1, 2", "Get-Date; $true", "Get-Date; $null"],
)
def test_a_constant_beside_an_allowed_command_changes_nothing(command: str) -> None:
    """A variable there is printed: revision 22, ``test_m3a_ps_expression_output.py``."""
    decision, backend = _audited(command)
    assert decision.verdict == "allow"
    assert backend.requests == []


# --- what the helper reports ----------------------------------------------------------------------

LOOSE = [
    ("[IO.File]::Delete('x')", {"InvokeMemberExpressionAst", "TypeExpressionAst"}),
    ("$a -eq 1", set()),
    ("$a -ceq 'x' -or $b -inotmatch 'y' -xor $c -in 1, 2", set()),
    ("-not $a; !$b", set()),
    ("$a -as [int]", {"BinaryExpressionAst", "TypeExpressionAst"}),
    ("$a -is [int]", {"BinaryExpressionAst", "TypeExpressionAst"}),
    ("1..3", {"BinaryExpressionAst"}),
    ("'{0}' -f $a", {"BinaryExpressionAst"}),
    ("$a -join ','", {"BinaryExpressionAst"}),
    ("-join $a", {"UnaryExpressionAst"}),
    ("$a++", {"UnaryExpressionAst"}),
    ("$a.b", {"MemberExpressionAst"}),
    ("$a[0]", {"IndexExpressionAst"}),
    ("[int]$a", {"ConvertExpressionAst"}),
    ("[int]", {"TypeExpressionAst"}),
    ("$a; 'b'; 1; \"c $d\"; 1, 2; @(1); (2); $(3); { 4 }; @{ a = 1 }", set()),
    ("@{ a = $b.c }", {"MemberExpressionAst"}),
    ('"x $($a.b)"', {"MemberExpressionAst"}),
    ("if ($a.b) { }", {"MemberExpressionAst"}),
    ("if ($a) { } elseif ($b -gt 1) { } else { }", set()),
    ("for (; $i -lt 3;) { }; do { } while ($a); do { } until ($a)", set()),
    ("using module x", {"UsingStatementAst"}),
    ("using assembly x.dll", {"UsingStatementAst"}),
    ("using namespace System.IO", set()),
    ("switch -File x { default { } }", {"SwitchStatementAst"}),
    ("switch -Regex ($a) { 'x' { } }", set()),
    ("function f([int]$n) { }", {"ParameterAst"}),
    ("function f { param([ValidateSet('a')]$x) }", {"ParameterAst"}),
    ("function f($n) { }", set()),
    ("Get-Date > ($a.b)", {"MemberExpressionAst"}),
    ("Get-Date > $a", set()),
    ('Get-Date 2> "$a.log"', set()),
    ("($a.b) | Out-Null", {"MemberExpressionAst"}),
    ("$a.b > out.txt", {"MemberExpressionAst"}),
    ("Write-Output ($a.b)", set()),
    ("Get-Date | ForEach-Object { $_.Name; [IO.File]::Delete($_) }", set()),
    ("Invoke-Command { param([string]$x) switch -File $x { default { } } }", set()),
    ("& ([IO.Path]::Combine('a', 'b'))", set()),
    ("Get-ChildItem -Path ($a.b) -Filter:([IO.Path]::GetTempPath())", set()),
]


@pytest.mark.windows
@pytest.mark.parametrize(("command", "want"), LOOSE)
def test_the_helper_names_what_is_outside_a_command(command: str, want: set[str]) -> None:
    assert _loose(command) == want


@pytest.mark.windows
def test_the_helper_s_other_lists_are_what_they_were() -> None:
    reply = _reply("if ($a) { [IO.File]::Delete('x') }; Write-Output ($b.c)")
    assert reply["compound"] == ["IfStatementAst"]
    assert set(reply["dynamic"]) >= {"InvokeMemberExpressionAst", "MemberExpressionAst"}
    assert [c["name"]["v"] for c in reply["commands"]] == ["", "Write-Output"]
    assert reply["commands"][0]["name"]["kind"] == "output"  # the statement in the if (revision 22)


def test_the_builder_turns_the_list_into_gray_reasons() -> None:
    res = build(rep(cmd("git", S("status")), loose=("InvokeMemberExpressionAst", "ParameterAst")))
    assert PREFIX + "InvokeMemberExpressionAst" in res.gray
    assert PREFIX + "ParameterAst" in res.gray
    assert res.exec_reasons == ()  # the helper's "dynamic" list says what runs code
    assert [c.argv[0].text for c in res.commands] == ["git"]


def test_a_reply_without_the_list_is_not_trusted() -> None:
    reply = {k: v for k, v in rep(cmd("git", S("status"))).items() if k != "loose"}
    assert "ps-internal-error" in build(reply).gray


@pytest.mark.parametrize(
    "reason",
    [PREFIX + "InvokeMemberExpressionAst", pscmd.SWITCH_VALUE_GRAY, pscmd.RUNNER_VALUE_GRAY],
)
def test_the_pipeline_counts_the_reasons_as_input_the_request_cannot_show(reason: str) -> None:
    actions = normalize_event(
        {
            "hook_event_name": "PreToolUse",
            "session_id": "s",
            "cwd": "/home/u/proj",
            "project_dir": "/home/u/proj",
            "tool_name": "Bash",
            "tool_input": {"command": "make test"},
        },
        platform="posix",
        env={"HOME": "/home/u"},
        home="/home/u",
    )
    assert pipeline.unshown_input(actions) is None
    first = actions[0]
    marked = [first.model_copy(update={"gray_reasons": (*first.gray_reasons, reason)})]
    assert pipeline.unshown_input(marked) == reason


# --- a drive-qualified variable is a file ---------------------------------------------------------


@pytest.mark.windows
@pytest.mark.parametrize(
    ("command", "want"),
    [
        ("${C:\\x\\.env}", [("file-read", "C:\\x\\.env")]),
        ("Get-Date; ${C:\\x\\.env}", [("file-read", "C:\\x\\.env")]),
        ('"a ${C:\\x\\y} b"', [("file-read", "C:\\x\\y")]),
        ('Write-Host "a ${C:\\x\\y} b"', [("file-read", "C:\\x\\y")]),
        ("Write-Output ${C:\\x\\y}", [("file-read", "C:\\x\\y")]),
        ("if (${C:\\x\\y}) { Get-Date }", [("file-read", "C:\\x\\y")]),
        ("${C:\\x\\y} | Out-Null", [("file-read", "C:\\x\\y")]),
        ("$b = ${C:\\x\\y}", [("file-read", "C:\\x\\y")]),
        ("${C:rel.txt}", [("file-read", "C:rel.txt")]),
        ("${C:\\x\\*.env}", [("file-read", "C:\\x\\*.env")]),
        ("$HKLM:x", [("file-read", "HKLM:x")]),
        ("${C:\\x\\y} = 1", [("file-write", "C:\\x\\y")]),
        ("[string]${C:\\x\\y} = 'a'", [("file-write", "C:\\x\\y")]),
        ("${C:\\a}, ${C:\\b} = 1, 2", [("file-write", "C:\\a"), ("file-write", "C:\\b")]),
        ("${C:\\x\\y} += 1", [("file-read", "C:\\x\\y"), ("file-write", "C:\\x\\y")]),
        ("${C:\\x\\y}++", [("file-read", "C:\\x\\y"), ("file-write", "C:\\x\\y")]),
        ("--${C:\\x\\y}", [("file-read", "C:\\x\\y"), ("file-write", "C:\\x\\y")]),
        ("${C:\\x\\y}[0] = 1", [("file-read", "C:\\x\\y"), ("file-write", "C:\\x\\y")]),
        ("${C:\\a} = ${C:\\b}", [("file-write", "C:\\a"), ("file-read", "C:\\b")]),
        ("$env:A; $function:f; $alias:a; $variable:v; $global:g; $script:s; $x; ${a b}", []),
        ("$env:A = 1; $function:f = { }; ${env:ProgramFiles(x86)}", []),
        ("$ENV:A; $Function:f; $ALIAS:a; ${Env:A}", []),
    ],
)
def test_the_helper_reports_a_drive_qualified_variable(
    command: str, want: list[tuple[str, str]]
) -> None:
    assert _files(command) == want
    # a ``[type]`` on the left, ``++`` and an index are expressions of their own
    assert _loose(command) <= {"ConvertExpressionAst", "UnaryExpressionAst", "IndexExpressionAst"}


@pytest.mark.windows
def test_the_variable_stands_where_it_is_written_among_the_commands() -> None:
    reply = _reply("Set-Location D:\\work; ${C:rel.txt}; Get-Date")
    assert [c["name"]["v"] for c in reply["commands"]] == ["Set-Location", "C:rel.txt", "Get-Date"]
    variable = reply["commands"][1]
    assert variable["pos"] == [22, 34]
    assert set(variable) == {"pos", "invoke", "name", "elements", "redirects", "stage", "nested"}


def _file(kind: str, path: str) -> dict[str, Any]:
    return {**cmd(path, kind=kind, stage=None, nested=True)}


@pytest.mark.parametrize(
    ("kind", "cmdlet"), [("file-read", "Get-Content"), ("file-write", "Set-Content")]
)
def test_the_builder_reads_it_as_a_content_cmdlet_of_that_path(kind: str, cmdlet: str) -> None:
    res = build(rep(cmd("Get-Date"), _file(kind, "C:\\x\\.env"), cmd("Get-Location")))
    assert [c.argv[0].text for c in res.commands] == ["Get-Date", cmdlet, "Get-Location"]
    words = res.commands[1].argv
    assert [w.text for w in words] == [cmdlet, "-Path", "C:\\x\\.env"]
    assert (words[2].expands, words[2].glob, words[2].quoted) == (False, False, True)
    assert res.gray == ()


def test_a_wildcard_in_the_name_is_one() -> None:
    res = build(rep(_file("file-read", "C:\\x\\*.env")))
    assert res.commands[0].argv[2].glob


def test_the_name_is_taken_as_written() -> None:
    """Between the braces nothing is expanded: ``${C:\\a$b}`` is the file ``a$b``."""
    res = build(rep(_file("file-read", "C:\\a$b\\-x")))
    word = res.commands[0].argv[2]
    assert (word.text, word.expands) == ("C:\\a$b\\-x", False)


@pytest.mark.parametrize("bad", ["", None, 5])
def test_a_variable_without_a_path_is_not_trusted(bad: Any) -> None:
    broken = _file("file-read", "x")
    broken["name"]["v"] = bad
    res = build(rep(cmd("Get-Date"), broken))
    assert "ps-internal-error" in res.gray
    assert [c.argv[0].text for c in res.commands] == ["Get-Date"]


def _var(path: str) -> str:
    return "${" + path + "}"


ENV_VAR = _var(ENV)


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        f"Get-Date; {ENV_VAR}",
        ENV_VAR,
        f'Get-Date; "{ENV_VAR}"',
        f'Write-Host "{ENV_VAR}"',
        f"Write-Output {ENV_VAR}",
        f"if ({ENV_VAR}) {{ Get-Date }}",
        f"{ENV_VAR} | Out-File C:\\x\\copy.txt",
        f"$a = {ENV_VAR}",
        "Get-Date; ${C:.env}",
        "Get-Date; " + _var(WIN_HOME + "\\.ssh\\id_rsa"),
    ],
)
def test_reading_a_protected_file_through_a_variable_is_denied(command: str) -> None:
    decision, backend = _audited(command)
    assert decision.verdict == "deny"
    assert "no-secret-read" in decision.rule_ids
    assert backend.requests == []


@pytest.mark.windows
def test_it_gets_what_the_cmdlet_gets() -> None:
    for path in (ENV, WIN_PROJECT + "\\README.md", "C:\\Windows\\win.ini", "C:\\x\\y.txt"):
        variable, _ = _audited(f"Get-Date; {_var(path)}")
        cmdlet, _ = _audited(f"Get-Date; Get-Content -Path '{path}'")
        assert (variable.verdict, variable.rule_ids) == (cmdlet.verdict, cmdlet.rule_ids), path


@pytest.mark.windows
def test_a_project_file_read_this_way_is_still_allowed() -> None:
    decision, _ = _audited("Get-Date; " + _var(WIN_PROJECT + "\\README.md"))
    assert decision.verdict == "allow"


@pytest.mark.windows
def test_an_assignment_writes_the_file() -> None:
    actions = _actions(f"{ENV_VAR} = 'A=1'")
    accesses = {(a.program, p.access) for a in actions for p in a.paths}
    assert accesses == {("set-content", "write")}
    decision, backend = _audited(f"{ENV_VAR} = 'A=1'")
    assert decision.verdict == "ask"
    assert "ask-secret-file-write" in decision.rule_ids
    assert backend.requests == []


@pytest.mark.windows
def test_a_compound_assignment_reads_and_writes_it() -> None:
    actions = _actions(_var(WIN_PROJECT + "\\notes.txt") + " += 'x'")
    assert {(a.program, p.access) for a in actions for p in a.paths} == {
        ("get-content", "read"),
        ("set-content", "write"),
    }


@pytest.mark.windows
@pytest.mark.parametrize(
    "command", ["Get-Date; $env:SECRET_TOKEN", "Get-Date; $function:prompt", "Get-Date; $alias:ls"]
)
def test_a_drive_that_is_not_a_file_system_lists_no_path(command: str) -> None:
    actions = _actions(command)
    assert [p for a in actions for p in a.paths] == []
    assert [a.program for a in actions] == ["get-date", "write-output"]  # printed (revision 22)


# --- text that is in a command and in no action's words -------------------------------------------


@pytest.mark.windows
@pytest.mark.parametrize(
    ("command", "reason"),
    [
        (f"Get-ChildItem -Force:({CALL})", pscmd.SWITCH_VALUE_GRAY),
        (f"Get-Date -Verbose:({CALL})", pscmd.SWITCH_VALUE_GRAY),
        (f"Set-Location -PassThru:({CALL}) sub; make test", pscmd.SWITCH_VALUE_GRAY),
        (f"uv run --with ({CALL}) pytest", pscmd.RUNNER_VALUE_GRAY),
        (f"uv run --python ({CALL}) pytest", pscmd.RUNNER_VALUE_GRAY),
        (f"uvx --from ({CALL}) ruff check", pscmd.RUNNER_VALUE_GRAY),
        (f"pipx run --spec ({CALL}) ruff check", pscmd.RUNNER_VALUE_GRAY),
        ("uv run --with $pkg make test", pscmd.RUNNER_VALUE_GRAY),
    ],
)
def test_a_computed_value_the_normalizer_drops_is_not_sent(command: str, reason: str) -> None:
    decision, backend = _audited(command)
    assert decision.verdict == "gray"
    assert_not_sent(decision, backend)
    assert decision.llm["detail"] == reason


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        "uv run make test",
        "uv run --frozen make test",
        "uv run make $target",
        "uvx make test",
        f"uv run make ({CALL})",
    ],
)
def test_a_runner_without_an_option_that_has_a_value_is_sent(command: str) -> None:
    """Spec revision 25: one with such an option is not, whatever the value is
    (tests/unit/test_m3a_runner_options.py)."""
    decision, backend = _audited(command)
    assert len(backend.requests) == 1, decision.reason


def test_the_builder_marks_a_runner_option_that_is_computed() -> None:
    call = O("ParenExpressionAst", "(f)")
    res = build(rep(cmd("uv", S("run"), S("--with"), call, S("pytest"))))
    assert pscmd.RUNNER_VALUE_GRAY in res.gray
    res = build(rep(cmd("uv", S("run"), S("--with"), V("pkg"), S("pytest"))))
    assert pscmd.RUNNER_VALUE_GRAY in res.gray
    res = build(rep(cmd("uv", S("run"), S("--frozen"), S("pytest"), call)))
    assert pscmd.RUNNER_VALUE_GRAY not in res.gray  # the tool's own argument stays in its words
    res = build(rep(cmd("uv", S("run"), S("--with"), S("rich"), S("pytest"))))
    assert pscmd.RUNNER_VALUE_GRAY in res.gray  # spec revision 25: a constant value as well
    res = build(rep(cmd("Get-ChildItem", P("Force", call))))
    assert pscmd.SWITCH_VALUE_GRAY in res.gray


def _gate(command: str) -> send_gate.GateResult:
    return send_gate.gate(
        _actions(command),
        tool="PowerShell",
        facts=FRESH,
        send_task_intent=False,
        intent_prompts=1,
        home=WIN_HOME,
    )


@pytest.mark.windows
def test_a_program_name_too_long_to_show_whole_is_refused() -> None:
    """``& $(...; 'Get-Date')``: the name is an expression, and the request cut it at 128."""
    pad = "1, " * 50
    result = _gate(f"& $({pad}{CALL}; 'Get-Date')")
    assert result.request is None
    assert result.refused == f"a program name is longer than {send_gate.MAX_NAME_CHARS} characters"
    short = _gate(f"& $({CALL}; 'Get-Date')")
    assert short.request is not None
    assert CANARY in short.request.content


def test_the_limit_is_on_the_name_s_length() -> None:
    action = normalize_event(
        {
            "hook_event_name": "PreToolUse",
            "session_id": "s",
            "cwd": "/home/u/proj",
            "project_dir": "/home/u/proj",
            "tool_name": "Bash",
            "tool_input": {"command": "make test"},
        },
        platform="posix",
        env={"HOME": "/home/u"},
        home="/home/u",
    )[0]

    def gate(name: str) -> send_gate.GateResult:
        return send_gate.gate(
            [action.model_copy(update={"program": name})],
            tool="Bash",
            facts=FRESH,
            send_task_intent=False,
            intent_prompts=1,
            home="/home/u",
        )

    assert gate("a" * send_gate.MAX_NAME_CHARS).request is not None
    assert gate("a" * (send_gate.MAX_NAME_CHARS + 1)).request is None
