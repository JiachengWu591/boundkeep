"""M1c-2 task 3: the data-shaping cmdlets are known, clean and path-free.

``Select-Object Out-String Out-Null Format-Table Format-List Sort-Object Group-Object
Measure-Object ConvertTo-Json ConvertFrom-Json Where-Object`` (comparison form) take their words as
property names / values, never as files: known, no paths, no ``exec`` tag, no gray reason. A script
block (``Where-Object { ... }``, calculated properties ``@{e={...}}``) keeps the call gray
(``ps-dynamic-value:ScriptBlockExpressionAst``). ``ForEach-Object``, ``Out-File``, ``Set-Content``,
``Tee-Object``, ``Export-*`` and ``Invoke-*`` are NOT data shaping and stay as they were.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from boundkeep.normalize import psprograms
from boundkeep.normalize.model import Action, Word

from .test_norm_event import WORLDS, run
from .test_norm_pscmd import build, cmd, rep

needs_ps = pytest.mark.skipif(sys.platform != "win32", reason="needs the PowerShell parser helper")
WIN = WORLDS["windows"]

SHAPING: dict[str, list[list[str]]] = {
    "Select-Object": [
        ["-ExpandProperty", "Name"],
        ["Name", ",", "Id"],
        ["-First", "3"],
        ["-Last", "2"],
        ["-Skip", "1"],
        ["-Unique"],
        ["-Property", "*"],
        ["-ExcludeProperty", "x"],
        ["-Index", "0", ",", "1"],
        [".\\a.txt"],
        ["~\\.ssh\\id_rsa"],
    ],
    "Out-String": [[], ["-Stream"], ["-Width", "200"], ["a.txt"]],
    "Out-Null": [[], ["-InputObject", "x"]],
    "Format-Table": [
        [],
        ["Name"],
        ["-AutoSize"],
        ["-Wrap"],
        ["-Property", "Id", ",", "Name"],
        ["-GroupBy", "Name"],
        ["-HideTableHeaders"],
    ],
    "Format-List": [[], ["*"], ["-Property", "*"], ["-Force"]],
    "Sort-Object": [
        ["CPU"],
        ["-Descending"],
        ["-Unique"],
        ["-Property", "CPU"],
        ["-CaseSensitive"],
        ["Name", ",", "Id"],
    ],
    "Group-Object": [
        ["Name"],
        ["-NoElement"],
        ["-Property", "Name"],
        ["-AsHashTable"],
        ["-AsString"],
        ["-CaseSensitive"],
    ],
    "Measure-Object": [
        [],
        ["-Sum"],
        ["-Property", "CPU", "-Sum", "-Average"],
        ["-Line"],
        ["-Word"],
        ["-Character"],
        ["-Maximum", "-Minimum"],
    ],
    "ConvertTo-Json": [[], ["-Depth", "3"], ["-Compress"]],
    "ConvertFrom-Json": [[], ["-InputObject", "{}"]],
    "Where-Object": [
        ["Name", "-EQ", "x"],
        ["CPU", "-GT", "5"],
        ["Name", "-Like", "a*"],
        ["-Property", "Name", "-EQ", "-Value", "x"],
        ["Name", "-Match", "x"],
        ["Name", "-NE", "x"],
        ["Name", "-NotMatch", "x"],
        ["Name", "-In", "a", ",", "b"],
        ["Name", "-Contains", "x"],
        ["Name", "-EQ", "~\\.ssh\\id_rsa"],
    ],
}
CASES = [
    pytest.param(name, args, id=f"{name}:{' '.join(args)}")
    for name, rows in SHAPING.items()
    for args in rows
]


def words(args: list[str]) -> list[Word]:
    """The words the way pscmd shapes them: ``-Param`` unquoted, ``,`` the array separator."""
    return [Word(a) for a in args]


@pytest.mark.parametrize(("name", "args"), CASES)
def test_shaping_cmdlet_is_known_clean_and_path_free(name: str, args: list[str]) -> None:
    i = psprograms.classify_ps(name, words(args))
    assert i.known is True
    assert i.paths == ()
    assert i.urls == ()
    assert i.network is False
    assert i.tags == ()
    assert i.gray == ()
    assert i.subcommand is None


@pytest.mark.parametrize("name", sorted(SHAPING))
def test_lower_case_names_as_event_passes_them_work_too(name: str) -> None:
    for spelling in (name.lower(), name.upper(), name):
        i = psprograms.classify_ps(spelling, words(["x"]))
        assert i.known is True
        assert i.paths == ()
        assert i.tags == ()
        assert i.gray == ()


@pytest.mark.parametrize(("name", "args"), CASES)
def test_parameters_are_flags_and_values_are_not(name: str, args: list[str]) -> None:
    i = psprograms.classify_ps(name, words(args))
    flags = {a for a in args if a.startswith("-") and len(a) > 1 and a[1].isalpha()}
    assert flags <= set(i.flags)
    assert not {a for a in args if not a.startswith("-")} & set(i.flags)


def test_the_question_mark_fallback_alias_is_where_object() -> None:
    i = psprograms.classify_ps("?", words(["Name", "-EQ", "x"]))
    assert i.known is True
    assert i.paths == ()
    assert i.gray == ()
    assert i.tags == ()


# --------------------------------------------------------------------------------------------
# pscmd: alias and abbreviation resolution (hand-built replies, any platform)
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("alias", "canonical"),
    [
        ("select", "Select-Object"),
        ("SELECT", "Select-Object"),
        ("sort", "Sort-Object"),
        ("ft", "Format-Table"),
        ("fl", "Format-List"),
        ("group", "Group-Object"),
        ("measure", "Measure-Object"),
        ("where", "Where-Object"),
        ("?", "Where-Object"),
        ("%", "ForEach-Object"),
        ("foreach", "ForEach-Object"),
        ("select-object", "Select-Object"),
        ("OUT-NULL", "Out-Null"),
        ("convertto-json", "ConvertTo-Json"),
    ],
)
def test_aliases_resolve_to_the_canonical_cmdlet(alias: str, canonical: str) -> None:
    res = build(rep(cmd(alias, stage=(1, 2))))
    assert [w.text for w in res.commands[0].argv] == [canonical]
    assert res.gray == ()


# --------------------------------------------------------------------------------------------
# end to end through the real helper (Windows)
# --------------------------------------------------------------------------------------------


def acts(command: str) -> list[Action]:
    return run(WIN, command, tool="PowerShell")


def stage_two(command: str) -> Action:
    got = acts(command)
    assert len(got) == 2, [(a.program, a.gray_reasons) for a in got]
    assert got[0].program == "get-process"
    return got[1]


CLEAN = [
    ("Get-Process | Select-Object -ExpandProperty Name", "select-object", ["-ExpandProperty"]),
    ("Get-Process | Select-Object Name, Id", "select-object", []),
    ("Get-Process | Select-Object -Exp Name", "select-object", ["-ExpandProperty"]),
    ("Get-Process | select -First 3", "select-object", ["-First"]),
    ("Get-Process | SELECT-OBJECT -First 1", "select-object", ["-First"]),
    ("Get-Process | select-object -first 1", "select-object", ["-First"]),
    (
        "Get-Process | Select-Object -Property * -ExcludeProperty x -Unique",
        "select-object",
        ["-Property", "-ExcludeProperty", "-Unique"],
    ),
    ("Get-Process | Out-String", "out-string", []),
    ("Get-Process | Out-String -Width 200 -Stream", "out-string", ["-Width", "-Stream"]),
    ("Get-Process | Out-String -Wi 3", "out-string", ["-Width"]),
    ("Get-Process | Out-Null", "out-null", []),
    ("Get-Process | Format-Table", "format-table", []),
    (
        "Get-Process | Format-Table -AutoSize -Wrap -Property Id,Name",
        "format-table",
        ["-AutoSize", "-Wrap", "-Property"],
    ),
    ("Get-Process | Format-Table -Auto", "format-table", ["-AutoSize"]),
    ("Get-Process | ft Name", "format-table", []),
    ("Get-Process | Format-List", "format-list", []),
    ("Get-Process | Format-List -Property * -Force", "format-list", ["-Property", "-Force"]),
    ("Get-Process | fl", "format-list", []),
    ("Get-Process | fl *", "format-list", []),
    ("Get-Process | Sort-Object CPU", "sort-object", []),
    ("Get-Process | sort CPU -Descending", "sort-object", ["-Descending"]),
    ("Get-Process | Sort-Object -Desc", "sort-object", ["-Descending"]),
    ("Get-Process | Sort-Object -Property CPU -Unique", "sort-object", ["-Property", "-Unique"]),
    ("Get-Process | Group-Object Name", "group-object", []),
    ("Get-Process | group Name", "group-object", []),
    (
        "Get-Process | Group-Object -NoElement -Property Name",
        "group-object",
        ["-NoElement", "-Property"],
    ),
    ("Get-Process | Measure-Object", "measure-object", []),
    ("Get-Process | measure -Property CPU -Sum", "measure-object", ["-Property", "-Sum"]),
    (
        "Get-Process | Measure-Object -Average -Maximum -Minimum",
        "measure-object",
        ["-Average", "-Maximum", "-Minimum"],
    ),
    ("Get-Process | ConvertTo-Json", "convertto-json", []),
    ("Get-Process | ConvertTo-Json -Depth 3 -Compress", "convertto-json", ["-Depth", "-Compress"]),
    ("Get-Process | Where-Object Name -eq x", "where-object", ["-EQ"]),
    ("Get-Process | where Name -like 'a*'", "where-object", ["-Like"]),
    ("Get-Process | ? Name -eq x", "where-object", ["-EQ"]),
    (
        "Get-Process | Where-Object -Property Name -EQ -Value x",
        "where-object",
        ["-Property", "-EQ", "-Value"],
    ),
    ("Get-Process | Where-Object CPU -GT 5", "where-object", ["-GT"]),
    ("Get-Process | Where-Object Name -Match x", "where-object", ["-Match"]),
    ("Get-Process | Where-Object Name -NE x", "where-object", ["-NE"]),
    ("Get-Process | Where-Object Name -In a,b", "where-object", ["-In"]),
    ("Get-Process | WHERE-OBJECT Name -EQ x", "where-object", ["-EQ"]),
    ("Get-Process | Where-Object Name -eq ~\\.ssh\\id_rsa", "where-object", ["-EQ"]),
    ("Get-Process | Select-Object .\\.env", "select-object", []),
    ("Get-Process | Select-Object `\n  -First 1", "select-object", ["-First"]),
    ("Get-Process | Sort-Object `\n  CPU `\n  -Descending", "sort-object", ["-Descending"]),
    ("Get-Process | Sel`ect-Object -First 1", "select-object", ["-First"]),
    ("Get-Process | & Select-Object -First 1", "select-object", ["-First"]),
    ("Get-Process | & 'Select-Object' -First 1", "select-object", ["-First"]),
    (
        "Get-Process | Microsoft.PowerShell.Utility\\Select-Object -First 1",
        "select-object",
        ["-First"],
    ),
]


@needs_ps
@pytest.mark.parametrize(("command", "program", "flags"), CLEAN)
def test_clean_end_to_end(command: str, program: str, flags: list[str]) -> None:
    a = stage_two(command)
    assert a.program == program
    assert a.paths == ()
    assert a.risk_tags == ()
    assert a.gray is False
    assert a.gray_reasons == ()
    assert a.subcommand is None
    assert a.wrappers == ()
    assert set(flags) <= set(a.flags)
    assert all(not x.gray for x in acts(command))


@needs_ps
def test_chained_shaping_stages_are_all_clean() -> None:
    got = acts(
        "Get-Process | Where-Object CPU -GT 1 | Sort-Object CPU -Descending "
        "| Select-Object -First 3 | Format-Table Name, CPU | Out-String"
    )
    assert [a.program for a in got] == [
        "get-process",
        "where-object",
        "sort-object",
        "select-object",
        "format-table",
        "out-string",
    ]
    assert all(not a.gray and a.risk_tags == () and a.paths == () for a in got)


@needs_ps
@pytest.mark.parametrize(
    "command",
    [
        "Get-Process | Where-Object { $_.CPU -gt 1 }",
        "Get-Process | ? { $_ }",
        "Get-Process | where { $_.Name -eq 'x' }",
        "Get-Process | Where-Object -FilterScript { $true }",
        "Get-Process | Select-Object @{n='x';e={$_.Name}}",
        "Get-Process | Select-Object -Property @{Name='n';Expression={$_.Name}}",
        "Get-Process | Sort-Object { $_.CPU }",
        "Get-Process | Group-Object { $_.Name }",
        "Get-Process | ForEach-Object { $_.Name }",
        "Get-Process | % { $_ }",
        "Get-Process | Format-Table @{l='a';e={$_.Id}}",
        "Get-Process | Measure-Object -Property { $_.CPU }",
    ],
)
def test_script_blocks_keep_the_call_gray(command: str) -> None:
    got = acts(command)
    reasons = {r for a in got for r in a.gray_reasons}
    assert any(r.startswith("ps-dynamic-value:") for r in reasons), (command, reasons)
    assert "ps-dynamic:ScriptBlockExpressionAst" in reasons
    assert any(a.gray for a in got)


@needs_ps
@pytest.mark.parametrize(
    ("command", "program", "expect"),
    [
        ("Get-Process | ForEach-Object Name", "foreach-object", {"paths": (), "gray": ()}),
        ("Get-Process | % Name", "foreach-object", {"paths": (), "gray": ()}),
        ("Get-Process | Out-File x.txt", "out-file", {"paths": ("x.txt",), "gray": ()}),
        ("Get-Process | Set-Content x.txt", "set-content", {"paths": ("x.txt",), "gray": ()}),
        ("Get-Process | Tee-Object x.txt", "tee-object", {"paths": ("x.txt",), "gray": ()}),
        ("Get-Process | Export-Csv x.csv", "export-csv", {"paths": ("x.csv",), "gray": ()}),
        ("Get-Process | Export-Clixml x.xml", "export-clixml", {"paths": ("x.xml",), "gray": ()}),
        (
            "Get-Process | Invoke-Expression",
            "invoke-expression",
            {"gray": ("ps-exec:Invoke-Expression",)},
        ),
        ("Get-Process | iex", "invoke-expression", {"gray": ("ps-exec:Invoke-Expression",)}),
        ("Get-Process | Invoke-WebRequest http://x.example", "invoke-webrequest", {"net": True}),
        (
            "Get-Process | Invoke-Command -ComputerName x",
            "invoke-command",
            {"gray": ("ps-exec:Invoke-Command",)},
        ),
    ],
)
def test_the_other_pipeline_cmdlets_are_not_data_shaping(
    command: str, program: str, expect: dict[str, Any]
) -> None:
    got = acts(command)
    a = next(x for x in got if x.program == program)
    if "paths" in expect:
        assert tuple(p.raw for p in a.paths) == expect["paths"]
        assert all(p.access == "write" for p in a.paths)
    if "gray" in expect:
        assert set(expect["gray"]) <= set(a.gray_reasons)
    if expect.get("net"):
        assert a.network is True
    if program in ("out-file", "set-content", "tee-object", "export-csv", "export-clixml"):
        assert "file_write" in a.risk_tags


@needs_ps
def test_a_backtick_inside_a_parameter_name_is_not_resolved() -> None:
    got = acts("Get-Process | Select-Object -Fir`st 1")
    reasons = {r for a in got for r in a.gray_reasons}
    assert any(r.startswith("ps-param-unresolved:Select-Object:") for r in reasons)


@needs_ps
def test_shaping_cmdlet_with_a_head_expression_is_gray_by_the_head_not_by_itself() -> None:
    got = acts("$env:SECRET_TOKEN | Select-Object")
    select = next(a for a in got if a.program == "select-object")
    assert select.gray is False
    assert select.paths == ()
    assert any("ps-pipeline-head-dynamic" in a.gray_reasons for a in got)
