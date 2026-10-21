"""M1c-2 task 2: the expression that STARTS a pipeline.

``$env:SECRET_TOKEN | Select-Object``, ``$x | Get-ChildItem``, ``(Get-Content f) | Select-Object``
used to be judged as if the head did not exist (no command stands for an expression, so its value
flowed into the next stage with no gray marker). The helper digest now carries the head of the
pipeline in the ``stage`` object of every later stage (``"head": <element>``, only when the first
stage is an expression); ``pscmd`` turns it into

* the gray reason ``ps-pipeline-head-dynamic`` when it is not a plain constant string / number;
* an explicit read-path operand (``-Path <value>``) for the cmdlets that read files
  (``'~\\.ssh\\id_rsa' | Get-Content``), which closes the old gap "a literal piped into a reader
  stays gray and is never denied".

Replies are built by hand, read from the real-helper fixtures (any platform) and sent through the
real helper (Windows). Nothing parsed here is executed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from boundkeep.normalize import pscmd, psprograms
from boundkeep.normalize.model import Action, BashResult, Word

from .test_norm_event import WORLDS, run
from .test_norm_pscmd import A, N, O, P, S, V, X, build, cmd, rep

needs_ps = pytest.mark.skipif(sys.platform != "win32", reason="needs the PowerShell parser helper")
WIN = WORLDS["windows"]
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "ps_ast"
HEAD = "ps-pipeline-head-dynamic"


def piped(name: str, *elements: Any, head: Any, index: int = 1, of: int = 2, **kw: Any) -> Any:
    """A later stage of a pipeline whose first stage is the expression ``head``."""
    c = cmd(name, *elements, **kw)
    c["stage"] = {"index": index, "of": of, "head": head}
    return c


def argv(res: BashResult, i: int = 0) -> list[str]:
    return [w.text for w in res.commands[i].argv]


def ps_info(res: BashResult, i: int = 0) -> Any:
    c = res.commands[i]
    return psprograms.classify_ps(c.argv[0].text, c.argv[1:], redirects=c.redirects, env=c.env)


# --------------------------------------------------------------------------------------------
# 1. a constant head piped into a reader is its READ path operand
# --------------------------------------------------------------------------------------------

READERS = [
    ("Get-Content", "-Path"),
    ("Get-ChildItem", "-Path"),
    ("Get-Item", "-Path"),
    ("Get-ItemProperty", "-Path"),
    ("Get-ItemPropertyValue", "-Path"),
    ("Test-Path", "-Path"),
    ("Get-FileHash", "-Path"),
    ("Import-Csv", "-Path"),
    ("Import-Clixml", "-Path"),
    ("Get-Acl", "-Path"),
    ("Resolve-Path", "-Path"),
    ("Convert-Path", "-Path"),
    ("Select-String", "-Path"),
    ("Get-AuthenticodeSignature", "-FilePath"),
    ("Format-Hex", "-Path"),
    ("Set-Location", "-Path"),
    ("Push-Location", "-Path"),
    ("Expand-Archive", "-Path"),
    ("Compress-Archive", "-Path"),
    ("Copy-Item", "-Path"),
]


@pytest.mark.parametrize(("cmdlet", "param"), READERS)
def test_constant_head_becomes_the_read_path_of_a_reader(cmdlet: str, param: str) -> None:
    res = build(rep(piped(cmdlet, head=S("~\\.ssh\\id_rsa", "single"))))
    assert argv(res) == [cmdlet, param, "~\\.ssh\\id_rsa"]
    assert res.gray == ()
    assert res.commands[0].in_pipeline is True
    i = ps_info(res)
    assert ("~\\.ssh\\id_rsa", "read") in {(w.text, a) for w, a in i.paths}
    assert "secret_access" in i.tags


@pytest.mark.parametrize(
    ("alias", "cmdlet", "param"),
    [
        ("gc", "Get-Content", "-Path"),
        ("cat", "Get-Content", "-Path"),
        ("type", "Get-Content", "-Path"),
        ("ls", "Get-ChildItem", "-Path"),
        ("dir", "Get-ChildItem", "-Path"),
        ("gci", "Get-ChildItem", "-Path"),
        ("gi", "Get-Item", "-Path"),
        ("sls", "Select-String", "-Path"),
        ("cp", "Copy-Item", "-Path"),
        ("copy", "Copy-Item", "-Path"),
        ("cpi", "Copy-Item", "-Path"),
        ("cd", "Set-Location", "-Path"),
        ("sl", "Set-Location", "-Path"),
        ("pushd", "Push-Location", "-Path"),
        ("rvpa", "Resolve-Path", "-Path"),
        ("GC", "Get-Content", "-Path"),
    ],
)
def test_the_aliases_of_the_readers_work_too(alias: str, cmdlet: str, param: str) -> None:
    res = build(rep(piped(alias, head=S(".env"))))
    assert argv(res) == [cmdlet, param, ".env"]


@pytest.mark.parametrize("kind", ["bare", "single", "double", "singlehere", "doublehere"])
def test_every_kind_of_constant_string_is_plain(kind: str) -> None:
    res = build(rep(piped("Get-Content", head=S(".env", kind))))
    assert argv(res) == ["Get-Content", "-Path", ".env"]
    assert HEAD not in res.gray


def test_a_number_is_a_constant_too() -> None:
    res = build(rep(piped("Get-Item", head=N("5"))))
    assert argv(res) == ["Get-Item", "-Path", "5"]
    assert res.gray == ()


def test_an_array_of_constants_is_a_plain_constant() -> None:
    res = build(rep(piped("Get-Content", head=A(S("a"), S("b"), N("3")))))
    assert argv(res) == ["Get-Content", "-Path", "a", ",", "b", ",", "3"]
    assert res.gray == ()
    paths = {w.text for w, _ in ps_info(res).paths}
    assert paths == {"a", "b", "3"}


def test_wildcards_in_the_head_are_wildcards_of_the_path() -> None:
    res = build(rep(piped("Get-Content", head=S(".e*"))))
    path = res.commands[0].argv[2]
    assert path.glob is True
    assert path.expands is False
    assert (path, "read") in ps_info(res).paths


def test_a_head_that_starts_with_a_dash_is_a_value_not_a_parameter() -> None:
    res = build(rep(piped("Get-Content", head=S("-Force"))))
    assert res.commands[0].argv[2].quoted is True
    assert ("-Force", "read") in {(w.text, a) for w, a in ps_info(res).paths}


def test_an_existing_path_argument_does_not_hide_the_head() -> None:
    res = build(rep(piped("Get-Content", S("a.txt"), head=S(".env"))))
    paths = {w.text for w, _ in ps_info(res).paths}
    assert {".env"} <= paths


def test_select_string_pattern_stays_the_pattern() -> None:
    res = build(rep(piped("Select-String", S("KEY"), head=S(".env"))))
    info = ps_info(res)
    assert {(w.text, a) for w, a in info.paths} == {(".env", "read")}


def test_copy_item_with_a_constant_source_loses_arguments_from_pipeline() -> None:
    res = build(rep(piped("Copy-Item", P("Destination"), S("out"), head=S(".env"))))
    info = ps_info(res)
    assert (Word(".env"), "read") in info.paths
    assert (Word("out"), "write") in info.paths
    assert "arguments-from-pipeline" not in info.gray


def test_copy_item_with_a_dynamic_head_stays_gray() -> None:
    res = build(rep(piped("Copy-Item", P("Destination"), S("out"), head=V("x"))))
    assert argv(res) == ["Copy-Item", "-Destination", "out"]  # nothing is added: stays as before
    assert "arguments-from-pipeline" in ps_info(res).gray
    assert HEAD in res.gray


@pytest.mark.parametrize(
    "later",
    [
        "Select-Object",
        "Out-String",
        "Out-Null",
        "Format-Table",
        "Sort-Object",
        "Where-Object",
        "ForEach-Object",
        "Measure-Object",
        "ConvertTo-Json",
        "Group-Object",
        "Write-Output",
        "Out-File",
        "Set-Content",
        "Add-Content",
        "Tee-Object",
        "Export-Csv",
        "Invoke-Expression",
        "Remove-Item",
        "Move-Item",
        "Rename-Item",
        "Start-Process",
        "Invoke-WebRequest",
    ],
)
def test_a_constant_head_into_a_cmdlet_that_takes_no_path_from_it_adds_nothing(later: str) -> None:
    res = build(rep(piped(later, head=S("~\\.ssh\\id_rsa"))))
    assert argv(res) == [later]
    assert HEAD not in res.gray


@pytest.mark.parametrize("later", ["Remove-Item", "Move-Item", "Rename-Item", "Set-Content"])
def test_writers_that_take_paths_from_the_pipeline_stay_gray(later: str) -> None:
    res = build(rep(piped(later, head=S("x"))))
    assert "arguments-from-pipeline" in ps_info(res).gray


@pytest.mark.parametrize("external", ["git", "curl.exe", "node", "mytool"])
def test_a_constant_head_into_an_external_program_adds_nothing(external: str) -> None:
    res = build(rep(piped(external, S("status"), head=S("x"))))
    assert argv(res)[1:] == ["status"]
    assert res.gray == ()


def test_the_head_reaches_later_stages_too() -> None:
    reply = rep(
        piped("Select-Object", head=S(".env"), index=1, of=3),
        piped("Get-Content", head=S(".env"), index=2, of=3),
    )
    res = build(reply)
    assert argv(res, 0) == ["Select-Object"]
    assert argv(res, 1) == ["Get-Content", "-Path", ".env"]


# --------------------------------------------------------------------------------------------
# 2. a head that is not a plain constant makes the line gray
# --------------------------------------------------------------------------------------------

DYNAMIC_HEADS = [
    pytest.param(V("env:SECRET_TOKEN"), id="env-variable"),
    pytest.param(V("x"), id="variable"),
    pytest.param(V("true"), id="true"),
    pytest.param(V("null"), id="null"),
    pytest.param(V("args", splat=True), id="splat"),
    pytest.param(X("$env:HOME\\x", "env:HOME"), id="expandable-string"),
    pytest.param(X("a $(1)", subexpr=True), id="expandable-with-subexpression"),
    pytest.param(O("ParenExpressionAst", "(Get-Content f)"), id="paren"),
    pytest.param(O("SubExpressionAst", "$(Get-Content f)"), id="subexpression"),
    pytest.param(O("ArrayExpressionAst", "@(1,2)"), id="array-expression"),
    pytest.param(O("MemberExpressionAst", "$x.Name"), id="member"),
    pytest.param(O("InvokeMemberExpressionAst", "$x.ToString()"), id="method-call"),
    pytest.param(O("InvokeMemberExpressionAst", "[IO.Path]::GetTempPath()"), id="static-call"),
    pytest.param(O("ConvertExpressionAst", "[string]'x'"), id="cast"),
    pytest.param(O("IndexExpressionAst", "$x[0]"), id="index"),
    pytest.param(O("BinaryExpressionAst", "'a' + 'b'"), id="binary"),
    pytest.param(O("UnaryExpressionAst", "-not $x"), id="unary"),
    pytest.param(O("HashtableAst", "@{a=1}"), id="hashtable"),
    pytest.param(O("ScriptBlockExpressionAst", "{ 1 }"), id="script-block"),
    pytest.param(O("TooLongString", "'aaaa"), id="too-long-string"),
    pytest.param(A(S("a"), V("x")), id="array-with-a-variable"),
    pytest.param(A(S("a"), A(S("b"))), id="nested-array"),
    pytest.param(A(), id="empty-array"),
    pytest.param(None, id="none"),
    pytest.param(5, id="int"),
    pytest.param("x", id="bare-python-string"),
    pytest.param([], id="list"),
    pytest.param({}, id="empty-mapping"),
    pytest.param({"t": "zzz"}, id="unknown-kind"),
    pytest.param({"t": "str"}, id="str-without-value"),
]


@pytest.mark.parametrize("head", DYNAMIC_HEADS)
@pytest.mark.parametrize("later", ["Select-Object", "Get-ChildItem", "Out-String", "git"])
def test_a_dynamic_head_is_gray_whatever_follows(head: Any, later: str) -> None:
    res = build(rep(piped(later, head=head)))
    assert HEAD in res.gray
    assert len(res.commands) == 1


@pytest.mark.parametrize("head", DYNAMIC_HEADS)
def test_a_dynamic_head_into_a_reader_adds_its_words_not_a_gray_free_path(head: Any) -> None:
    res = build(rep(piped("Get-Content", head=head)))
    assert HEAD in res.gray
    # a head we cannot read is still listed as the path word it would have been (or nothing)
    assert argv(res)[:1] == ["Get-Content"]


def test_dynamic_heads_keep_their_own_gray_reasons_too() -> None:
    res = build(rep(piped("Select-Object", head=O("ScriptBlockExpressionAst", "{ 1 }"))))
    assert {HEAD, "ps-dynamic-value:ScriptBlockExpressionAst"} <= set(res.gray)
    res = build(rep(piped("Select-Object", head=X("a $(1)", subexpr=True))))
    assert {HEAD, "ps-subexpression"} <= set(res.gray)
    res = build(rep(piped("Select-Object", head=V("args", splat=True))))
    assert {HEAD, "ps-dynamic-value:Splat"} <= set(res.gray)


def test_a_variable_head_into_a_reader_is_listed_as_a_dynamic_path() -> None:
    res = build(rep(piped("Get-Content", head=V("env:USERPROFILE"))))
    assert argv(res) == ["Get-Content", "-Path", "$env:USERPROFILE"]
    word = res.commands[0].argv[2]
    assert word.expands is True


def test_set_location_with_a_dynamic_head_gets_a_dynamic_word_so_the_cwd_is_unknown() -> None:
    res = build(rep(piped("Set-Location", head=V("dir"))))
    assert argv(res) == ["Set-Location", "-Path", "$dir"]
    assert res.commands[0].argv[2].expands is True


def test_a_backtick_in_a_constant_head_is_gray_like_anywhere_else() -> None:
    res = build(rep(piped("Get-Content", head=S("a`b"))))
    assert "ps-backtick" in res.gray
    assert HEAD not in res.gray  # (it is a constant, the backtick is the extra reason)


def test_a_nested_pipeline_head_is_judged_too() -> None:
    reply = rep(piped("Select-Object", head=V("x"), nested=True))
    assert HEAD in build(reply).gray


def test_dynamic_next_stage_name_does_not_hide_the_gray_head() -> None:
    reply = rep(piped("$tool", head=V("x"), kind="variable"))
    res = build(reply)
    assert HEAD in res.gray
    assert "ps-dynamic-command-name" in res.gray


# --------------------------------------------------------------------------------------------
# 3. where the head is NOT looked at
# --------------------------------------------------------------------------------------------


def test_no_head_key_means_the_first_stage_was_a_command() -> None:
    c = cmd("Select-Object", stage=(1, 2))
    res = build(rep(c))
    assert res.gray == ()


@pytest.mark.parametrize(("index", "of"), [(0, 2), (0, 1), (1, 1), (-1, 2), (0, 0)])
def test_a_head_on_the_first_stage_or_outside_a_pipeline_is_ignored(index: int, of: int) -> None:
    res = build(rep(piped("Get-Content", head=V("x"), index=index, of=of)))
    assert HEAD not in res.gray
    assert argv(res) == ["Get-Content"]


@pytest.mark.parametrize(
    "stage", [{"index": "1", "of": 2, "head": V("x")}, {"of": 2, "head": V("x")}]
)
def test_a_malformed_stage_never_adds_a_head(stage: Any) -> None:
    c = cmd("Get-Content")
    c["stage"] = stage
    res = build(rep(c))
    assert HEAD not in res.gray


def test_a_real_command_first_stage_is_untouched() -> None:
    reply = rep(cmd("Get-Content", S("a"), stage=(0, 2)), cmd("Select-Object", stage=(1, 2)))
    res = build(reply)
    assert res.gray == ()
    assert argv(res, 1) == ["Select-Object"]


# --------------------------------------------------------------------------------------------
# 4. the real helper's digests (fixtures: checked in, regenerated by scripts/gen_ps_fixtures.py)
# --------------------------------------------------------------------------------------------


def _fixture(text: str) -> dict[str, Any]:
    index = json.loads((FIXTURES / "index.json").read_text(encoding="utf-8"))
    data: dict[str, Any] = json.loads((FIXTURES / index[text]).read_text(encoding="utf-8"))
    return data


REAL = [
    # (command text, argv of the LAST command, gray must contain, gray must NOT contain)
    ("'~\\.ssh\\id_rsa' | Get-Content", ["Get-Content", "-Path", "~\\.ssh\\id_rsa"], [], [HEAD]),
    ('"~\\.ssh\\id_rsa" | Get-Content', ["Get-Content", "-Path", "~\\.ssh\\id_rsa"], [], [HEAD]),
    ("'.env' | Get-Content", ["Get-Content", "-Path", ".env"], [], [HEAD]),
    ("'.env' | Select-String KEY", ["Select-String", "KEY", "-Path", ".env"], [], [HEAD]),
    ("'x' | Get-ChildItem", ["Get-ChildItem", "-Path", "x"], [], [HEAD]),
    ("'a','b' | Get-Content", ["Get-Content", "-Path", "a", ",", "b"], [], [HEAD]),
    ("1 | Get-Item", ["Get-Item", "-Path", "1"], [], [HEAD]),
    ("@'\n.env\n'@ | Get-Content", ["Get-Content", "-Path", ".env"], [], [HEAD]),
    ("'x' | Select-Object", ["Select-Object"], [], [HEAD]),
    ("'x' | Out-File y.txt", ["Out-File", "y.txt"], [], [HEAD]),
    (
        "'x' | Copy-Item -Destination y",
        ["Copy-Item", "-Destination", "y", "-Path", "x"],
        [],
        [HEAD],
    ),
    ("'x' | Remove-Item -Recurse", ["Remove-Item", "-Recurse"], [], [HEAD]),
    ("'x' | Select-Object | Get-Content", ["Get-Content", "-Path", "x"], [], [HEAD]),
    ("'echo hi' | iex", ["Invoke-Expression"], ["ps-pipe-to-interpreter"], [HEAD]),
    ("$env:SECRET_TOKEN | Select-Object", ["Select-Object"], [HEAD], []),
    ("$x | Get-ChildItem", ["Get-ChildItem", "-Path", "$x"], [HEAD], []),
    ("$null | Out-String", ["Out-String"], [HEAD], []),
    ("(Get-Content f) | Select-Object", ["Select-Object"], [HEAD], []),
    (
        "$(Get-Content f) | Select-Object",
        ["Select-Object"],
        [HEAD, "ps-dynamic:SubExpressionAst"],
        [],
    ),
    ("@(1,2) | Select-Object", ["Select-Object"], [HEAD, "ps-dynamic:ArrayExpressionAst"], []),
    (
        "$x.Name | Get-Content",
        ["Get-Content", "-Path", "$($x.Name)"],
        [HEAD, "ps-dynamic:MemberExpressionAst"],
        [],
    ),
    (
        "$x.ToString() | Get-Content",
        ["Get-Content", "-Path", "$($x.ToString())"],
        [HEAD, "ps-dynamic:InvokeMemberExpressionAst"],
        [],
    ),
    (
        "[IO.Path]::GetTempPath() | Get-ChildItem",
        ["Get-ChildItem", "-Path", "$([IO.Path]::GetTempPath())"],
        [HEAD, "ps-dynamic:InvokeMemberExpressionAst"],
        [],
    ),
    (
        '"$env:USERPROFILE\\.ssh\\id_rsa" | Get-Content',
        ["Get-Content", "-Path", "$env:USERPROFILE\\.ssh\\id_rsa"],
        [HEAD],
        [],
    ),
    ("$x | Copy-Item -Destination y", ["Copy-Item", "-Destination", "y"], [HEAD], []),
    ("Get-Content a | Select-Object", ["Select-Object"], [], [HEAD]),
]


@pytest.mark.parametrize(("text", "last", "has", "lacks"), REAL)
def test_real_digest(text: str, last: list[str], has: list[str], lacks: list[str]) -> None:
    res = pscmd.build(_fixture(text), source=text)
    assert [w.text for w in res.commands[-1].argv] == last
    assert set(has) <= set(res.gray), res.gray
    assert not set(lacks) & set(res.gray), res.gray


def test_real_digest_carries_the_head_in_every_later_stage_only() -> None:
    reply = _fixture("'x' | Select-Object | Get-Content")
    stages = [c["stage"] for c in reply["commands"]]
    assert [s["index"] for s in stages] == [1, 2]
    assert all(
        s["of"] == 3 and s["head"] == {"t": "str", "kind": "single", "v": "x"} for s in stages
    )
    reply = _fixture("Get-Content a | Select-Object")
    assert all("head" not in c["stage"] for c in reply["commands"])


# --------------------------------------------------------------------------------------------
# 5. end to end through the real helper (Windows): Actions and verdict inputs
# --------------------------------------------------------------------------------------------


def acts(command: str) -> list[Action]:
    return run(WIN, command, tool="PowerShell")


def action(command: str, program: str) -> Action:
    found = [a for a in acts(command) if a.program == program]
    assert len(found) == 1, [(a.program, a.gray_reasons) for a in acts(command)]
    return found[0]


def all_reasons(command: str) -> set[str]:
    return {r for a in acts(command) for r in a.gray_reasons}


@needs_ps
@pytest.mark.parametrize(
    ("command", "program", "raw", "secret"),
    [
        ("'~\\.ssh\\id_rsa' | Get-Content", "get-content", "~\\.ssh\\id_rsa", True),
        ('"~\\.ssh\\id_rsa" | Get-Content', "get-content", "~\\.ssh\\id_rsa", True),
        ("'.env' | Get-Content", "get-content", ".env", True),
        ("'.env' | gc", "get-content", ".env", True),
        ("'.env' | cat", "get-content", ".env", True),
        ("'.env' | type", "get-content", ".env", True),
        ("'.env' | Select-String KEY", "select-string", ".env", True),
        ("'.env' | sls KEY", "select-string", ".env", True),
        ("'.env' | Get-Item", "get-item", ".env", True),
        ("'.env' | gi", "get-item", ".env", True),
        ("'.env' | Test-Path", "test-path", ".env", True),
        ("'.env' | Resolve-Path", "resolve-path", ".env", True),
        ("'.env' | Get-FileHash", "get-filehash", ".env", True),
        ("'.env' | Copy-Item -Destination out.txt", "copy-item", ".env", True),
        ("'.env' | cp -Destination out.txt", "copy-item", ".env", True),
        ("'~\\.aws\\credentials' | Get-ChildItem", "get-childitem", "~\\.aws\\credentials", True),
        ("'.env' | Select-Object | Get-Content", "get-content", ".env", True),
        ("'.env' | Sort-Object | Get-Content", "get-content", ".env", True),
        ("@'\n.env\n'@ | Get-Content", "get-content", ".env", True),
        ("'x' | Get-ChildItem", "get-childitem", "x", False),
        ("'README.md' | Get-Content", "get-content", "README.md", False),
        ("1 | Get-Item", "get-item", "1", False),
    ],
)
def test_constant_head_is_a_read_path_end_to_end(
    command: str, program: str, raw: str, secret: bool
) -> None:
    a = action(command, program)
    refs = [p for p in a.paths if p.raw == raw]
    assert len(refs) == 1, [p.raw for p in a.paths]
    assert refs[0].access == "read"
    assert ("secret_access" in a.risk_tags) is secret
    assert HEAD not in all_reasons(command)


@needs_ps
def test_array_head_lists_every_element() -> None:
    a = action("'a','.env' | Get-Content", "get-content")
    assert sorted(p.raw for p in a.paths if p.access == "read") == [".env", "a"]


@needs_ps
@pytest.mark.parametrize(
    "command",
    [
        "$env:SECRET_TOKEN | Select-Object",
        "$env:SECRET_TOKEN | Out-String",
        "$x | Get-ChildItem",
        "$x | Select-Object",
        "$x | Out-File y.txt",
        "$null | Out-Null",
        "$true | Select-Object",
        "(Get-Content f) | Select-Object",
        "(Get-Content f) | Get-Content",
        "(Get-Item .) | Select-Object -ExpandProperty FullName",
        "$(Get-Content f) | Select-Object",
        "@(1,2) | Select-Object",
        "@() | Select-Object",
        "$x.Name | Get-Content",
        "$x.ToString() | Get-Content",
        "[IO.Path]::GetTempPath() | Get-ChildItem",
        "[string]'x' | Get-Content",
        "$x[0] | Get-Content",
        "('a' + 'b') | Get-Content",
        "'a' + 'b' | Get-Content",
        "-not $x | Select-Object",
        "@{a=1} | ConvertTo-Json",
        "{ 1 } | Select-Object",
        '"$env:SECRET_TOKEN" | Select-Object',
        '"$(Get-Date)" | Select-Object',
        '"a $x b" | Select-Object',
        "$x | Select-Object | Sort-Object | Out-String",
        "$env:USERPROFILE | Get-ChildItem",
        "$HOME | Get-ChildItem",
        "$PWD | Get-ChildItem",
        "$PROFILE | Get-Content",
        "$x | Copy-Item -Destination y",
        "$x | Remove-Item -Recurse",
        "$x | Set-Location",
    ],
)
def test_dynamic_head_is_gray_end_to_end(command: str) -> None:
    got = acts(command)
    reasons = {r for a in got for r in a.gray_reasons}
    assert HEAD in reasons, (command, reasons)
    assert any(a.gray for a in got)


@needs_ps
@pytest.mark.parametrize(
    "command",
    [
        "$x = 'a' | Get-Content",
        "if ($x) { $y | Select-Object }",
        "Write-Output $( $y | Select-Object )",
        "Get-Process | ForEach-Object { $_ | Select-Object }",
        "function f { $x | Select-Object }; f",
        "Get-Content a; $x | Select-Object",
        "ls | % { $env:T | Out-String }",
    ],
)
def test_nested_and_later_heads_are_judged_too(command: str) -> None:
    got = acts(command)
    reasons = {r for a in got for r in a.gray_reasons}
    if "$x = 'a'" in command:
        assert HEAD not in reasons  # a constant head
    else:
        assert HEAD in reasons, (command, reasons)


@needs_ps
@pytest.mark.parametrize(
    "command",
    [
        "'x' | Select-Object",
        "'x' | Out-String",
        "'x' | Out-File notes.txt",
        "'x' | Set-Content notes.txt",
        "'x' | Write-Output",
        "'1' | ConvertFrom-Json",
        "1 | Measure-Object",
        "'echo hi' | Out-String",
        "Get-Process | Select-Object -First 3",
        "Get-Content a | Select-Object -First 3",
        "Get-Content a | ForEach-Object { $_ } | Select-Object",
    ],
)
def test_constant_heads_and_command_heads_are_not_gray_by_themselves(command: str) -> None:
    assert HEAD not in all_reasons(command)


@needs_ps
@pytest.mark.parametrize(
    "command",
    [
        "'x' | Remove-Item -Recurse",
        "'x' | Move-Item -Destination y",
        "'x' | Rename-Item -NewName y",
    ],
)
def test_path_writers_fed_by_a_constant_stay_gray_as_before(command: str) -> None:
    assert "arguments-from-pipeline" in all_reasons(command)


@needs_ps
def test_constant_string_piped_to_an_interpreter_is_still_exec_gray() -> None:
    reasons = all_reasons("'whoami' | iex")
    assert "ps-pipe-to-interpreter" in reasons
    reasons = all_reasons("'whoami' | powershell -")
    assert "ps-pipe-to-interpreter" in reasons


@needs_ps
def test_here_string_and_quoted_forms_of_the_head() -> None:
    for command in ('@"\n.env\n"@ | Get-Content', "@'\n.env\n'@ | gc", "(  '.env' ) | gc"):
        got = acts(command)
        reasons = {r for a in got for r in a.gray_reasons}
        if command.startswith("("):
            assert HEAD in reasons
        else:
            assert HEAD not in reasons
            a = next(x for x in got if x.program == "get-content")
            assert [p.raw for p in a.paths] == [".env"]


# --------------------------------------------------------------------------------------------
# 6. arbitrary heads never raise and anything unreadable is gray
# --------------------------------------------------------------------------------------------

_JSON = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.text(max_size=12)
    | st.sampled_from(["str", "num", "array", "var", "expstr", "other", "param"]),
    lambda inner: (
        st.lists(inner, max_size=4)
        | st.dictionaries(
            st.sampled_from(
                ["t", "v", "kind", "items", "name", "splat", "subexpr", "ast", "text", "arg"]
            ),
            inner,
            max_size=5,
        )
    ),
    max_leaves=12,
)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(head=_JSON, later=st.sampled_from(["Get-Content", "Select-Object", "git", "Copy-Item"]))
def test_arbitrary_heads_never_raise(head: Any, later: str) -> None:
    res = build(rep(piped(later, head=head)))
    assert isinstance(res, BashResult)
    assert len(res.commands) == 1
    plain = (
        isinstance(head, dict)
        and head.get("t") in ("str", "num")
        and isinstance(head.get("v"), str)
    )
    if not plain and not (isinstance(head, dict) and head.get("t") == "array"):
        assert HEAD in res.gray
