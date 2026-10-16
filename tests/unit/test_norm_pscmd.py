"""normalize.pscmd: the helper's JSON digest -> SimpleCmd / Word / Redirect (BashResult).

Replies are built by hand in the shape of docs/m1b-design.md section 2 (see ``cmd`` / ``rep``),
or read from the real helper fixtures (tests/fixtures/ps_ast, tests/fixtures/ps_ast_manual). No
PowerShell is needed (pure data), so everything runs on Windows and Linux; one test that
cross-checks the manual fixtures against the live helper is marked ``windows``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from boundkeep.normalize import pscmd, psprograms
from boundkeep.normalize.model import BashResult, Word
from boundkeep.normalize.programs import classify

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "powershell_parse.yaml"

# --------------------------------------------------------------------------------------------
# Builders for hand-written replies
# --------------------------------------------------------------------------------------------


def S(v: str, kind: str = "bare") -> dict[str, Any]:
    return {"t": "str", "kind": kind, "v": v}


def X(v: str, *names: str, subexpr: bool = False) -> dict[str, Any]:
    return {"t": "expstr", "v": v, "vars": list(names), "subexpr": subexpr}


def V(name: str, splat: bool = False) -> dict[str, Any]:
    return {"t": "var", "name": name, "splat": splat}


def N(v: str) -> dict[str, Any]:
    return {"t": "num", "v": v}


def A(*items: Any) -> dict[str, Any]:
    return {"t": "array", "items": list(items)}


def O(ast: str, text: str) -> dict[str, Any]:  # noqa: E743 - short on purpose
    return {"t": "other", "ast": ast, "text": text}


def P(name: str, arg: Any = None) -> dict[str, Any]:
    return {"t": "param", "name": name, "arg": arg}


def RD(op: str, target: Any = None, merge: str | None = None) -> dict[str, Any]:
    return {"op": op, "target": target, "merge": merge}


def cmd(
    name: str,
    *elements: Any,
    kind: str = "bare",
    invoke: str = "",
    redirects: list[Any] | None = None,
    stage: tuple[int, int] | None = (0, 1),
    nested: bool = False,
) -> dict[str, Any]:
    return {
        "pos": [0, 10],
        "invoke": invoke,
        "name": {"kind": kind, "v": name},
        "elements": list(elements),
        "redirects": redirects or [],
        "stage": None if stage is None else {"index": stage[0], "of": stage[1]},
        "nested": nested,
    }


def rep(
    *cmds: Any,
    compound: tuple[str, ...] = (),
    dynamic: tuple[str, ...] = (),
    errors: int = 0,
    **extra: Any,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "ok": True,
        "parse_errors": [{"msg": "m", "line": 1, "col": 1}] * errors,
        "commands": list(cmds),
        "compound": list(compound),
        "dynamic": list(dynamic),
        "mode": "FullLanguage",
    }
    out.update(extra)
    return out


def ps_classify(c: Any) -> Any:
    """The CmdInfo of one SimpleCmd, the way programs.classify is called for PowerShell."""
    return classify(  # noqa: S604 - "powershell" names a dialect, not a subprocess flag
        c.argv[0].text, c.argv[1:], shell="powershell", redirects=c.redirects
    )


def texts(res: BashResult, i: int = 0) -> list[str]:
    return [w.text for w in res.commands[i].argv]


def build(reply: Any, source: str = "") -> BashResult:
    res = pscmd.build(reply, source=source)
    assert isinstance(res, BashResult)
    return res


def check(res: BashResult, expect: dict[str, Any]) -> None:
    if "argv" in expect:
        assert [[w.text for w in c.argv] for c in res.commands] == expect["argv"]
    if "n" in expect:
        assert len(res.commands) == expect["n"]
    if "gray" in expect:
        assert set(res.gray) == set(expect["gray"]), res.gray
    if "gray_has" in expect:
        assert set(expect["gray_has"]) <= set(res.gray), res.gray
    if "gray_not" in expect:
        assert not set(expect["gray_not"]) & set(res.gray), res.gray
    if "exec" in expect:
        assert set(res.exec_reasons) == set(expect["exec"]), res.exec_reasons
    if "exec_has" in expect:
        assert set(expect["exec_has"]) <= set(res.exec_reasons), res.exec_reasons
    if "exec_not" in expect:
        assert not set(expect["exec_not"]) & set(res.exec_reasons), res.exec_reasons
    if "redirects" in expect:
        got = [(r.op, r.target.text if r.target else None) for r in res.commands[0].redirects]
        assert got == expect["redirects"]
    if "pipe" in expect:
        assert [c.in_pipeline for c in res.commands] == expect["pipe"]
    if "origin" in expect:
        assert [c.origin for c in res.commands] == expect["origin"]
    if "word" in expect:  # {text: (expands, glob, quoted)} over every word of command 0
        by_text = {w.text: (w.expands, w.glob, w.quoted) for w in res.commands[0].argv}
        for text, flags in expect["word"].items():
            assert by_text[text] == flags, (text, by_text)


def case(case_id: str, reply: Any, **expect: Any) -> Any:
    return pytest.param(reply, expect, id=case_id)


R = "Remove-Item"

# --------------------------------------------------------------------------------------------
# Names, aliases, abbreviations, parameters
# --------------------------------------------------------------------------------------------

NAME_CASES = [
    case("alias-rm", rep(cmd("rm", S("x"))), argv=[[R, "x"]], gray=[], exec=[]),
    case("alias-ri", rep(cmd("ri", S("x"))), argv=[[R, "x"]]),
    case("alias-del", rep(cmd("del", S("x"))), argv=[[R, "x"]]),
    case("alias-erase", rep(cmd("erase", S("x"))), argv=[[R, "x"]]),
    case("alias-rd", rep(cmd("rd", S("x"))), argv=[[R, "x"]]),
    case("alias-rmdir", rep(cmd("rmdir", S("x"))), argv=[[R, "x"]]),
    case("alias-upper", rep(cmd("RM", S("x"))), argv=[[R, "x"]]),
    case("alias-mixed-canonical", rep(cmd("rEmOvE-iTeM", S("x"))), argv=[[R, "x"]]),
    case("alias-ls", rep(cmd("ls")), argv=[["Get-ChildItem"]]),
    case("alias-dir", rep(cmd("dir")), argv=[["Get-ChildItem"]]),
    case("alias-gci", rep(cmd("gci")), argv=[["Get-ChildItem"]]),
    case("alias-cat", rep(cmd("cat", S("a"))), argv=[["Get-Content", "a"]]),
    case("alias-gc", rep(cmd("gc", S("a"))), argv=[["Get-Content", "a"]]),
    case("alias-type", rep(cmd("type", S("a"))), argv=[["Get-Content", "a"]]),
    case("alias-cp", rep(cmd("cp", S("a"), S("b"))), argv=[["Copy-Item", "a", "b"]]),
    case("alias-copy", rep(cmd("copy", S("a"), S("b"))), argv=[["Copy-Item", "a", "b"]]),
    case("alias-mv", rep(cmd("mv", S("a"), S("b"))), argv=[["Move-Item", "a", "b"]]),
    case("alias-ren", rep(cmd("ren", S("a"), S("b"))), argv=[["Rename-Item", "a", "b"]]),
    case(
        "alias-curl-is-iwr",
        rep(cmd("curl", S("http://x"))),
        argv=[["Invoke-WebRequest", "http://x"]],
    ),
    case(
        "alias-wget-is-iwr",
        rep(cmd("wget", S("http://x"))),
        argv=[["Invoke-WebRequest", "http://x"]],
    ),
    case("alias-irm", rep(cmd("irm", S("http://x"))), argv=[["Invoke-RestMethod", "http://x"]]),
    case("alias-cd", rep(cmd("cd", S(".."))), argv=[["Set-Location", ".."]]),
    case("alias-sl", rep(cmd("sl", S(".."))), argv=[["Set-Location", ".."]]),
    case("alias-echo", rep(cmd("echo", S("hi"))), argv=[["Write-Output", "hi"]]),
    case(
        "alias-percent",
        rep(cmd("%", O("ScriptBlockExpressionAst", "{ 1 }"))),
        argv=[["ForEach-Object", "$({ 1 })"]],
    ),
    case(
        "alias-question",
        rep(cmd("?", O("ScriptBlockExpressionAst", "{ 1 }"))),
        argv=[["Where-Object", "$({ 1 })"]],
    ),
    case(
        "alias-sc-is-set-content", rep(cmd("sc", S("a"), S("b"))), argv=[["Set-Content", "a", "b"]]
    ),
    case("alias-ac", rep(cmd("ac", S("a"), S("b"))), argv=[["Add-Content", "a", "b"]]),
    case(
        "quoted-name-via-call-operator",
        rep(cmd("Remove-Item", S("x"), kind="single", invoke="&")),
        argv=[[R, "x"]],
        gray=[],
    ),
    case(
        "double-quoted-alias-via-call-operator",
        rep(cmd("rm", S("x"), kind="double", invoke="&")),
        argv=[[R, "x"]],
    ),
    case(
        "builtin-module-qualified",
        rep(cmd("Microsoft.PowerShell.Management\\Remove-Item", S("x"))),
        argv=[[R, "x"]],
        gray=[],
    ),
    case(
        "user-module-qualified-is-a-path-not-the-cmdlet",
        rep(cmd("evil\\Remove-Item", S("x"))),
        argv=[["evil\\Remove-Item", "x"]],
        gray_has=["ps-script-exec"],
        exec_has=["ps-script-exec"],
    ),
    case(
        "external-exe-suffix-removed",
        rep(cmd("git.exe", S("status"))),
        argv=[["git", "status"]],
        gray=[],
    ),
    case("external-exe-suffix-upper", rep(cmd("GIT.EXE", S("status"))), argv=[["GIT", "status"]]),
    case(
        "external-sc-exe-is-not-set-content", rep(cmd("sc.exe", S("query"))), argv=[["sc", "query"]]
    ),
    case(
        "external-curl-exe-is-not-iwr",
        rep(cmd("curl.exe", S("http://x"))),
        argv=[["curl", "http://x"]],
    ),
    case("external-plain-name", rep(cmd("git", S("log"))), argv=[["git", "log"]], gray=[]),
    case("external-unknown-name", rep(cmd("mytool", S("x"))), argv=[["mytool", "x"]], gray=[]),
    case(
        "implicit-get-verb-noun-only",
        rep(cmd("Content", S("x"))),
        argv=[["Get-Content", "x"]],
        gray=["ps-implicit-get-verb"],
    ),
    case(
        "implicit-get-verb-any-case",
        rep(cmd("cHiLdItEm", P("Rec"), S("x"))),
        argv=[["Get-ChildItem", "-Recurse", "x"]],
        gray_has=["ps-implicit-get-verb"],
    ),
    case(
        "implicit-get-verb-quoted-through-call-operator",
        rep(cmd("Location", kind="single", invoke="&")),
        argv=[["Get-Location"]],
        gray_has=["ps-implicit-get-verb"],
    ),
    case("implicit-get-verb-not-for-unknown-nouns", rep(cmd("git", S("x"))), gray=[]),
    case("implicit-get-verb-not-for-names-with-digits", rep(cmd("content2", S("x"))), gray=[]),
    case(
        "external-absolute-exe-path",
        rep(cmd("C:\\tools\\a.exe", S("x"))),
        argv=[["C:\\tools\\a.exe", "x"]],
        gray=[],
    ),
    case("external-relative-exe-path", rep(cmd(".\\a.exe")), argv=[[".\\a.exe"]], gray=[]),
    case("external-path-with-parens", rep(cmd("C:\\Program Files (x86)\\a\\b.exe")), n=1, gray=[]),
    case(
        "unknown-cmdlet-no-params-not-gray",
        rep(cmd("Get-Foo", S("x"))),
        argv=[["Get-Foo", "x"]],
        gray=[],
    ),
    case(
        "unknown-cmdlet-param-is-gray",
        rep(cmd("Get-Foo", P("Bar"), S("x"))),
        argv=[["Get-Foo", "-Bar", "x"]],
        gray=["ps-param-unresolved:Get-Foo:-Bar"],
    ),
    case(
        "script-file-by-extension",
        rep(cmd(".\\x.ps1")),
        gray_has=["ps-script-exec"],
        exec_has=["ps-script-exec"],
    ),
    case("batch-file-bare-name", rep(cmd("build.bat")), exec_has=["ps-script-exec"]),
    case(
        "path-without-extension-is-a-script",
        rep(cmd("C:\\tools\\tool")),
        exec_has=["ps-script-exec"],
    ),
    case("vbs-script", rep(cmd("a.vbs")), exec_has=["ps-script-exec"]),
    case(
        "dynamic-name-variable",
        rep(cmd("x", kind="variable", invoke="&")),
        argv=[["$x"]],
        gray_has=["ps-dynamic-command-name"],
        exec_has=["ps-dynamic-command-name"],
        word={"$x": (True, False, False)},
    ),
    case(
        "dynamic-name-expression",
        rep(cmd("('i'+'ex')", kind="expr", invoke="&")),
        argv=[["$(('i'+'ex'))"]],
        gray_has=["ps-dynamic-command-name"],
        exec_has=["ps-dynamic-command-name"],
    ),
    case(
        "dynamic-name-expandable",
        rep(cmd("$x\\a", kind="expandable")),
        gray_has=["ps-dynamic-command-name"],
    ),
    case(
        "dynamic-name-wildcard",
        rep(cmd("Remove-It*", S("x"))),
        gray_has=["ps-dynamic-command-name"],
    ),
    case(
        "dynamic-name-wildcard-path",
        rep(cmd("C:\\Wind*\\System32\\cmd.exe")),
        gray_has=["ps-dynamic-command-name"],
    ),
    case(
        "dynamic-name-dollar-in-quotes",
        rep(cmd("a$b", kind="single")),
        gray_has=["ps-dynamic-command-name"],
    ),
    case("name-with-backtick", rep(cmd("rm`x")), gray_has=["ps-backtick"]),
    case(
        "dot-source-script",
        rep(cmd(".\\setup.ps1", invoke=".")),
        exec_has=["ps-dot-source", "ps-script-exec"],
        gray_has=["ps-dot-source"],
    ),
    case(
        "dot-source-cmdlet-is-still-seen",
        rep(cmd("iex", S("$x"), invoke=".")),
        argv=[["Invoke-Expression", "$x"]],
        exec_has=["ps-dot-source", "ps-exec:Invoke-Expression"],
    ),
    case(
        "call-operator-literal-script",
        rep(cmd(".\\run.cmd", invoke="&")),
        exec_has=["ps-script-exec"],
    ),
    case(
        "iex-alias",
        rep(cmd("iex", S("x"))),
        argv=[["Invoke-Expression", "x"]],
        exec=["ps-exec:Invoke-Expression"],
        gray_has=["ps-exec:Invoke-Expression"],
    ),
    case("icm-alias", rep(cmd("icm", S("x"))), exec_has=["ps-exec:Invoke-Command"]),
    case(
        "saps-alias",
        rep(cmd("saps", S("calc"))),
        argv=[["Start-Process", "calc"]],
        exec_has=["ps-exec:Start-Process"],
    ),
    case(
        "start-alias",
        rep(cmd("start", S("calc"))),
        argv=[["Start-Process", "calc"]],
        exec_has=["ps-exec:Start-Process"],
    ),
    case(
        "ii-alias",
        rep(cmd("ii", S("x.exe"))),
        argv=[["Invoke-Item", "x.exe"]],
        exec_has=["ps-exec:Invoke-Item"],
    ),
    case(
        "add-type", rep(cmd("Add-Type", P("TypeDefinition"), S("x"))), exec_has=["ps-exec:Add-Type"]
    ),
    case(
        "new-object-comobject",
        rep(cmd("New-Object", P("ComObject"), S("WScript.Shell"))),
        exec_has=["ps-exec:New-Object"],
    ),
    case("new-object-plain-is-not-exec", rep(cmd("New-Object", S("Net.WebClient"))), exec=[]),
    case(
        "import-module-path",
        rep(cmd("Import-Module", S(".\\x.psm1"))),
        exec_has=["ps-exec:Import-Module"],
    ),
    case("import-module-name", rep(cmd("Import-Module", S("posh-git"))), exec=[]),
    case(
        "invoke-wmi-method",
        rep(cmd("Invoke-WmiMethod", P("Class"), S("Win32_Process"))),
        exec_has=["ps-exec:Invoke-WmiMethod"],
    ),
    case("start-job", rep(cmd("Start-Job", S("x"))), exec_has=["ps-exec:Start-Job"]),
]

PARAM_CASES = [
    case(
        "param-abbrev-rec",
        rep(cmd("Remove-Item", P("Rec"), S("x"))),
        argv=[[R, "-Recurse", "x"]],
        gray=[],
    ),
    case("param-abbrev-fo", rep(cmd("Remove-Item", P("Fo"), S("x"))), argv=[[R, "-Force", "x"]]),
    case(
        "param-abbrev-r-single-letter",
        rep(cmd("Remove-Item", P("r"), S("x"))),
        argv=[[R, "-Recurse", "x"]],
    ),
    case(
        "param-abbrev-via-alias",
        rep(cmd("rm", P("Rec"), P("Fo"), S("x"))),
        argv=[[R, "-Recurse", "-Force", "x"]],
    ),
    case(
        "param-case-insensitive",
        rep(cmd("Remove-Item", P("RECURSE"), S("x"))),
        argv=[[R, "-Recurse", "x"]],
    ),
    case(
        "param-full-name",
        rep(cmd("Remove-Item", P("Recurse"), S("x"))),
        argv=[[R, "-Recurse", "x"]],
    ),
    case(
        "param-abbrev-pa-is-path",
        rep(cmd("Get-ChildItem", P("Pa"), S("src"))),
        argv=[["Get-ChildItem", "-Path", "src"]],
    ),
    case(
        "param-pspath-is-literalpath",
        rep(cmd("Remove-Item", P("pspath"), S("x"))),
        argv=[[R, "-LiteralPath", "x"]],
    ),
    case(
        "param-colon-value-split",
        rep(cmd("Remove-Item", P("Path", S("C:\\x")))),
        argv=[[R, "-Path", "C:\\x"]],
        gray=[],
    ),
    case(
        "param-colon-value-and-abbrev",
        rep(cmd("Remove-Item", P("Path", S("C:\\x")), P("Rec"))),
        argv=[[R, "-Path", "C:\\x", "-Recurse"]],
    ),
    case(
        "param-colon-switch-false-dropped",
        rep(cmd("Remove-Item", P("Recurse", V("false")), S("x"))),
        argv=[[R, "-Recurse", "x"]],
    ),
    case(
        "param-colon-switch-true-dropped",
        rep(cmd("Remove-Item", P("Force", V("true")), S("x"))),
        argv=[[R, "-Force", "x"]],
    ),
    case(
        "param-colon-switch-dynamic-argument-still-gray",
        rep(cmd("Remove-Item", P("Force", O("ParenExpressionAst", "($x)")), S("y"))),
        argv=[[R, "-Force", "y"]],
        gray_has=["ps-dynamic-value:ParenExpressionAst"],
    ),
    case(
        "param-colon-array-value",
        rep(cmd("Remove-Item", P("Path", A(S("a"), S("b"))))),
        argv=[[R, "-Path", "a", ",", "b"]],
    ),
    case(
        "param-ambiguous",
        rep(cmd("Remove-Item", P("f"), S("x"))),
        argv=[[R, "-f", "x"]],
        gray=["ps-param-unresolved:Remove-Item:-f"],
    ),
    case(
        "param-unknown",
        rep(cmd("Remove-Item", P("Bogus"), S("x"))),
        argv=[[R, "-Bogus", "x"]],
        gray=["ps-param-unresolved:Remove-Item:-Bogus"],
    ),
    case(
        "param-unix-style-rf-is-unresolved",
        rep(cmd("rm", P("rf"), S("x"))),
        argv=[[R, "-rf", "x"]],
        gray=["ps-param-unresolved:Remove-Item:-rf"],
    ),
    case(
        "param-empty-name",
        rep(cmd("Remove-Item", P(""), S("x"))),
        gray_has=["ps-param-unresolved:Remove-Item:-?"],
    ),
    case(
        "param-after-double-dash-token",
        rep(cmd("Remove-Item", P("-"), S("-x"))),
        argv=[[R, "--", "-x"]],
        gray=[],
        word={"-x": (False, False, True)},
    ),
    case(
        "param-dash-value-is-quoted",
        rep(cmd("Remove-Item", S("-x", "single"))),
        word={"-x": (False, False, True)},
    ),
    case(
        "param-dash-number-is-quoted",
        rep(cmd("Get-Foo", N("-5"))),
        word={"-5": (False, False, True)},
    ),
    case(
        "param-common-erroraction",
        rep(cmd("Remove-Item", P("ea"), S("Stop"), S("x"))),
        argv=[[R, "-ErrorAction", "Stop", "x"]],
        gray=[],
    ),
    case(
        "param-whatif-abbrev", rep(cmd("Remove-Item", P("wi"), S("x"))), argv=[[R, "-WhatIf", "x"]]
    ),
    case(
        "param-literalpath-glob-off",
        rep(cmd("Remove-Item", P("LiteralPath"), S("C:\\x\\*"))),
        word={"C:\\x\\*": (False, False, False)},
    ),
    case(
        "param-literalpath-colon-glob-off",
        rep(cmd("Remove-Item", P("LiteralPath", S("C:\\x\\*")))),
        word={"C:\\x\\*": (False, False, False)},
    ),
    case(
        "param-path-glob-on",
        rep(cmd("Remove-Item", P("Path"), S("C:\\x\\*"))),
        word={"C:\\x\\*": (False, True, False)},
    ),
    case(
        "param-literalpath-glob-only-first-value",
        rep(cmd("Remove-Item", P("LiteralPath"), S("a*"), S("b*"))),
        word={"a*": (False, False, False), "b*": (False, True, False)},
    ),
    case(
        "param-literalpath-without-value-resets",
        rep(cmd("Remove-Item", P("LiteralPath"), P("Force"), S("b*"))),
        word={"b*": (False, True, False)},
    ),
    case(
        "external-param-verbatim-case",
        rep(cmd("git", P("C"), S("x"), S("status"))),
        argv=[["git", "-C", "x", "status"]],
        gray=[],
    ),
    case(
        "external-param-colon-joined",
        rep(cmd("curl.exe", P("o", S("f.txt")), S("http://x"))),
        argv=[["curl", "-o:f.txt", "http://x"]],
        gray=[],
    ),
    case(
        "external-param-colon-variable",
        rep(cmd("foo", P("Path", V("env:TEMP")))),
        word={"-Path:$env:TEMP": (True, False, False)},
    ),
    case(
        "external-param-unknown-is-not-gray",
        rep(cmd("npm", P("g"), S("install"))),
        argv=[["npm", "-g", "install"]],
        gray=[],
    ),
    case(
        "external-double-dash",
        rep(cmd("git", S("checkout"), P("-"), S("f"))),
        argv=[["git", "checkout", "--", "f"]],
    ),
    case(
        "powershell-encodedcommand-full",
        rep(cmd("powershell", P("EncodedCommand"), S("abc"))),
        exec_has=["ps-encoded-command", "ps-nested-shell"],
    ),
    case(
        "powershell-enc-abbrev",
        rep(cmd("powershell", P("enc"), S("abc"))),
        exec_has=["ps-encoded-command"],
    ),
    case(
        "powershell-ec-abbrev", rep(cmd("pwsh", P("ec"), S("abc"))), exec_has=["ps-encoded-command"]
    ),
    case(
        "powershell-e-abbrev",
        rep(cmd("powershell.exe", P("e"), S("abc"))),
        exec_has=["ps-encoded-command"],
    ),
    case(
        "powershell-file-is-only-nested-shell",
        rep(cmd("powershell", P("File"), S("a.ps1"))),
        exec=["ps-nested-shell"],
    ),
    case(
        "pwsh-command-nested-shell",
        rep(cmd("pwsh", P("Command"), S("ls"))),
        exec=["ps-nested-shell"],
        gray_has=["ps-nested-shell"],
    ),
    case("cmd-nested-shell", rep(cmd("cmd", S("/c"), S("dir"))), exec=["ps-nested-shell"]),
    case("cmd-exe-nested-shell", rep(cmd("cmd.exe", S("/c"), S("dir"))), exec=["ps-nested-shell"]),
    case("wsl-nested-shell", rep(cmd("wsl", S("rm"), S("-rf"), S("~"))), exec=["ps-nested-shell"]),
    case("bash-nested-shell", rep(cmd("bash", S("-c"), S("x"))), exec=["ps-nested-shell"]),
    case("wscript-script-host", rep(cmd("wscript", S("a.vbs"))), exec_has=["ps-nested-shell"]),
    case("mshta-script-host", rep(cmd("mshta", S("http://x/a.hta"))), exec_has=["ps-nested-shell"]),
]

# --------------------------------------------------------------------------------------------
# Values (Word flags)
# --------------------------------------------------------------------------------------------

VALUE_CASES = [
    case(
        "value-single-quoted",
        rep(cmd("Get-Content", S("a b", "single"))),
        word={"a b": (False, False, True)},
        gray=[],
    ),
    case(
        "value-double-quoted-literal",
        rep(cmd("Get-Content", S("a", "double"))),
        word={"a": (False, False, True)},
    ),
    case("value-bare", rep(cmd("Get-Content", S("a"))), word={"a": (False, False, False)}),
    case(
        "value-single-here-string",
        rep(cmd("Set-Content", S("a"), S("x\ny", "singlehere"))),
        word={"x\ny": (False, False, True)},
        gray=[],
    ),
    case(
        "value-double-here-string-literal",
        rep(cmd("Set-Content", S("a"), S("x\ny", "doublehere"))),
        word={"x\ny": (False, False, True)},
    ),
    case(
        "value-expandable-variable",
        rep(cmd("Get-Content", X("$HOME\\x", "HOME"))),
        word={"$HOME\\x": (True, False, False)},
        gray=[],
    ),
    case(
        "value-expandable-env",
        rep(cmd("Get-Content", X("$env:USERPROFILE\\.ssh\\id_rsa", "env:USERPROFILE"))),
        word={"$env:USERPROFILE\\.ssh\\id_rsa": (True, False, False)},
    ),
    case(
        "value-expandable-subexpression",
        rep(cmd("Get-Content", X("a$(gc b)", subexpr=True))),
        gray_has=["ps-subexpression"],
    ),
    case(
        "value-expandable-subexpression-by-text",
        rep(cmd("Get-Content", X("a$(gc b)"))),
        gray_has=["ps-subexpression"],
    ),
    case(
        "value-expandable-quotes-kept-by-helper",
        rep(cmd("Get-Content", X('"$HOME\\x"', "HOME"))),
        argv=[["Get-Content", "$HOME\\x"]],
    ),
    case(
        "value-expandable-here-string-quotes-kept",
        rep(cmd("Get-Content", X('@"\n$HOME\\x\n"@', "HOME"))),
        argv=[["Get-Content", "$HOME\\x"]],
    ),
    case(
        "value-expandable-glob",
        rep(cmd("Get-Content", X("$HOME\\*.txt", "HOME"))),
        word={"$HOME\\*.txt": (True, True, False)},
    ),
    case("value-variable", rep(cmd("Get-Content", V("x"))), word={"$x": (True, False, False)}),
    case(
        "value-variable-env",
        rep(cmd("Get-Content", V("env:USERPROFILE"))),
        argv=[["Get-Content", "$env:USERPROFILE"]],
    ),
    case(
        "value-variable-braced-name",
        rep(cmd("Get-Content", V("a b"))),
        argv=[["Get-Content", "${a b}"]],
    ),
    case(
        "value-variable-splat",
        rep(cmd("Get-ChildItem", V("params", splat=True))),
        argv=[["Get-ChildItem", "$(@params)"]],  # dynamic word: the path layer cannot place it
        word={"$(@params)": (True, False, False)},
        gray_has=["ps-dynamic-value:Splat"],
    ),
    case(
        "value-number",
        rep(cmd("Get-Content", P("Tail"), N("5"))),
        argv=[["Get-Content", "-Tail", "5"]],
        gray=[],
    ),
    case(
        "value-array-has-separator-for-cmdlets",
        rep(cmd("Get-Content", A(S("a"), S("b"), S("c")))),
        argv=[["Get-Content", "a", ",", "b", ",", "c"]],
    ),
    case(
        "value-array-flat-for-externals",
        rep(cmd("git", S("add"), A(S("a"), S("b")))),
        argv=[["git", "add", "a", "b"]],
    ),
    case(
        "value-nested-array",
        rep(cmd("Get-Content", A(A(S("a")), S("b")))),
        argv=[["Get-Content", "a", ",", "b"]],
    ),
    case(
        "value-other-is-dynamic",
        rep(cmd("Get-Content", O("ParenExpressionAst", "(gi x)"))),
        argv=[["Get-Content", "$((gi x))"]],
        gray_has=["ps-dynamic-value:ParenExpressionAst"],
        word={"$((gi x))": (True, False, False)},
    ),
    case(
        "value-other-scriptblock",
        rep(cmd("Where-Object", O("ScriptBlockExpressionAst", "{ $_ }"))),
        gray_has=["ps-dynamic-value:ScriptBlockExpressionAst"],
    ),
    case(
        "value-other-member-access",
        rep(cmd("Get-Content", O("MemberExpressionAst", "$_.FullName"))),
        argv=[["Get-Content", "$($_.FullName)"]],
    ),
    case(
        "value-unknown-element-type",
        rep(cmd("Get-Content", {"t": "weird"})),
        gray_has=["ps-dynamic-value:Unknown"],
    ),
    case(
        "value-glob-bare", rep(cmd("Get-Content", S("*.txt"))), word={"*.txt": (False, True, False)}
    ),
    case(
        "value-glob-single-quoted",
        rep(cmd("Get-Content", S("*.txt", "single"))),
        word={"*.txt": (False, True, True)},
    ),
    case(
        "value-glob-question-mark",
        rep(cmd("Get-Content", S("a?.txt"))),
        word={"a?.txt": (False, True, False)},
    ),
    case(
        "value-glob-bracket",
        rep(cmd("Get-Content", S("a[0].txt"))),
        word={"a[0].txt": (False, True, False)},
    ),
    case("value-backtick-in-value", rep(cmd("Get-Content", S("a`b"))), gray_has=["ps-backtick"]),
    case(
        "value-backtick-in-expandable", rep(cmd("Get-Content", X("a`$b"))), gray_has=["ps-backtick"]
    ),
    case("value-no-backtick-no-gray", rep(cmd("Get-Content", S("a b"))), gray=[]),
    case(
        "value-stop-parsing-token",
        rep(cmd("foo", S("--%"), S("%PATH%"))),
        gray_has=["ps-stop-parsing"],
    ),
    case("value-stop-parsing-quoted-is-fine", rep(cmd("foo", S("--%", "single"))), gray=[]),
    case(
        "value-chinese-and-check-mark",
        rep(cmd("Set-Content", P("Path"), S("报告.txt"), P("Value"), S("done ✓", "single"))),
        argv=[["Set-Content", "-Path", "报告.txt", "-Value", "done ✓"]],
        gray=[],
    ),
]

# --------------------------------------------------------------------------------------------
# Redirects and pipelines
# --------------------------------------------------------------------------------------------

REDIRECT_CASES = [
    case(
        "redirect-truncate",
        rep(cmd("ls", redirects=[RD(">", S("o.txt"))])),
        redirects=[(">", "o.txt")],
    ),
    case(
        "redirect-append",
        rep(cmd("ls", redirects=[RD(">>", S("o.txt"))])),
        redirects=[(">>", "o.txt")],
    ),
    case(
        "redirect-stderr",
        rep(cmd("ls", redirects=[RD("2>", S("e.txt"))])),
        redirects=[("2>", "e.txt")],
    ),
    case(
        "redirect-all-streams",
        rep(cmd("ls", redirects=[RD("*>", S("a.txt"))])),
        redirects=[("*>", "a.txt")],
    ),
    case(
        "redirect-merge-has-no-target",
        rep(cmd("ls", redirects=[RD("2>", None, "2>&1")])),
        redirects=[("2>&1", None)],
    ),
    case(
        "redirect-two",
        rep(cmd("ls", redirects=[RD(">", S("o")), RD("2>", S("e"))])),
        redirects=[(">", "o"), ("2>", "e")],
    ),
    case(
        "redirect-target-variable",
        rep(cmd("ls", redirects=[RD(">", X("$env:TEMP\\o", "env:TEMP"))])),
        redirects=[(">", "$env:TEMP\\o")],
    ),
    case(
        "redirect-target-dynamic",
        rep(cmd("ls", redirects=[RD(">", O("ParenExpressionAst", "($x)"))])),
        redirects=[(">", "$(($x))")],
        gray_has=["ps-dynamic-value:ParenExpressionAst"],
    ),
    case(
        "redirect-bad-operator-is-gray-but-kept",
        rep(cmd("ls", redirects=[RD("evil", S("o"))])),
        redirects=[(">", "o")],
        gray_has=["ps-internal-error"],
    ),
    case(
        "redirect-missing-target-is-gray",
        rep(cmd("ls", redirects=[RD(">", None)])),
        gray_has=["ps-internal-error"],
    ),
    case(
        "redirect-entry-not-a-mapping",
        rep(cmd("ls", redirects=["x"])),
        gray_has=["ps-internal-error"],
    ),
    case(
        "redirects-not-a-list", rep({**cmd("ls"), "redirects": "x"}), gray_has=["ps-internal-error"]
    ),
]

PIPELINE_CASES = [
    case(
        "pipeline-three-stages",
        rep(cmd("a1", stage=(0, 3)), cmd("a2", stage=(1, 3)), cmd("a3", stage=(2, 3))),
        pipe=[True, True, True],
    ),
    case("pipeline-single-stage", rep(cmd("ls", stage=(0, 1))), pipe=[False]),
    case("pipeline-no-stage", rep(cmd("ls", stage=None)), pipe=[False]),
    case(
        "pipeline-garbage-stage",
        rep({**cmd("ls"), "stage": {"of": "x", "index": None}}),
        pipe=[False],
    ),
    case(
        "pipeline-bool-stage-is-not-an-int",
        rep({**cmd("ls"), "stage": {"of": True, "index": 0}}),
        pipe=[False],
    ),
    case(
        "pipe-to-iex",
        rep(cmd("irm", S("http://x"), stage=(0, 2)), cmd("iex", stage=(1, 2))),
        exec_has=["ps-pipe-to-interpreter", "ps-exec:Invoke-Expression"],
    ),
    case(
        "pipe-to-invoke-expression-full-name",
        rep(cmd("gc", S("a"), stage=(0, 2)), cmd("Invoke-Expression", stage=(1, 2))),
        exec_has=["ps-pipe-to-interpreter"],
    ),
    case(
        "pipe-to-powershell-stdin",
        rep(cmd("gc", S("a"), stage=(0, 2)), cmd("powershell", stage=(1, 2))),
        exec_has=["ps-pipe-to-interpreter", "ps-nested-shell"],
    ),
    case(
        "pipe-to-powershell-dash",
        rep(cmd("gc", S("a"), stage=(0, 2)), cmd("powershell", S("-", "single"), stage=(1, 2))),
        exec_has=["ps-pipe-to-interpreter"],
    ),
    case(
        "pipe-to-powershell-noprofile-only",
        rep(cmd("gc", S("a"), stage=(0, 2)), cmd("pwsh", P("NoProfile"), stage=(1, 2))),
        exec_has=["ps-pipe-to-interpreter"],
    ),
    case(
        "pipe-to-powershell-file-is-not-stdin-code",
        rep(
            cmd("gc", S("a"), stage=(0, 2)), cmd("powershell", P("File"), S("x.ps1"), stage=(1, 2))
        ),
        exec_not=["ps-pipe-to-interpreter"],
    ),
    case(
        "pipe-to-bash",
        rep(cmd("curl.exe", S("http://x"), stage=(0, 2)), cmd("bash", stage=(1, 2))),
        exec_has=["ps-pipe-to-interpreter"],
    ),
    case(
        "pipe-to-python-script-is-not-stdin-code",
        rep(cmd("gc", S("a"), stage=(0, 2)), cmd("python", S("x.py"), stage=(1, 2))),
        exec_not=["ps-pipe-to-interpreter"],
    ),
    case(
        "pipe-to-python-dash",
        rep(cmd("gc", S("a"), stage=(0, 2)), cmd("python", S("-", "single"), stage=(1, 2))),
        exec_has=["ps-pipe-to-interpreter"],
    ),
    case(
        "iex-first-stage-is-not-a-pipe-target",
        rep(cmd("iex", S("x"), stage=(0, 2)), cmd("Out-Null", stage=(1, 2))),
        exec_not=["ps-pipe-to-interpreter"],
        exec_has=["ps-exec:Invoke-Expression"],
    ),
    case(
        "iex-alone-is-not-a-pipe-target",
        rep(cmd("iex", S("x"))),
        exec_not=["ps-pipe-to-interpreter"],
    ),
    case(
        "pipe-to-ordinary-cmdlet",
        rep(cmd("gc", S("a"), stage=(0, 2)), cmd("Out-String", stage=(1, 2))),
        exec=[],
        gray=[],
    ),
    case(
        "nested-command-origin-subexpr",
        rep(cmd("Join-Path", S("a"), nested=True), dynamic=("SubExpressionAst",)),
        origin=["subexpr"],
    ),
    case(
        "nested-command-origin-scriptblock",
        rep(cmd("rm", S("x"), nested=True), dynamic=("ScriptBlockExpressionAst",)),
        origin=["scriptblock"],
    ),
    case("top-level-origin", rep(cmd("rm", S("x"))), origin=["top"]),
]

# --------------------------------------------------------------------------------------------
# Whole-reply level
# --------------------------------------------------------------------------------------------

REPLY_CASES = [
    case("reply-empty-script", rep(), n=0, gray=[], exec=[]),
    case("reply-parse-errors", rep(cmd("ls"), errors=2), gray=["ps-parse-error"], n=1),
    case(
        "reply-compound-types",
        rep(cmd("rm", S("x")), compound=("IfStatementAst", "TrapStatementAst")),
        gray=["ps-compound:IfStatementAst", "ps-compound:TrapStatementAst"],
        n=1,
    ),
    case(
        "reply-compound-keeps-commands-for-deny-rules",
        rep(cmd("rm", P("Recurse"), S("C:\\x"), nested=True), compound=("IfStatementAst",)),
        argv=[[R, "-Recurse", "C:\\x"]],
    ),
    case(
        "reply-dynamic-types-are-exec",
        rep(cmd("ls"), dynamic=("MemberExpressionAst",)),
        gray_has=["ps-dynamic:MemberExpressionAst"],
        exec=["ps-dynamic:MemberExpressionAst"],
    ),
    case(
        "reply-dynamic-type-name-sanitised",
        rep(dynamic=("A b\n\x00c" * 30,)),
        gray_not=["ps-dynamic:A b"],
    ),
    case("reply-not-ok-too-large", {"ok": False, "error": "too-large"}, gray=["ps-too-large"], n=0),
    case(
        "reply-not-ok-internal", {"ok": False, "error": "internal"}, gray=["ps-internal-error"], n=0
    ),
    case("reply-not-ok-no-error", {"ok": False}, gray=["ps-internal-error"]),
    case("reply-ok-not-a-bool", {**rep(), "ok": "yes"}, gray=["ps-internal-error"]),
    case(
        "reply-constrained-language-mode",
        rep(cmd("ls"), mode="ConstrainedLanguage"),
        gray_has=["ps-helper-unavailable"],
    ),
    case("reply-mode-absent-is-fine", {k: v for k, v in rep().items() if k != "mode"}, gray=[]),
    case(
        "reply-missing-commands",
        {k: v for k, v in rep().items() if k != "commands"},
        gray=["ps-internal-error"],
    ),
    case("reply-commands-wrong-type", {**rep(), "commands": {"a": 1}}, gray=["ps-internal-error"]),
    case(
        "reply-missing-compound",
        {k: v for k, v in rep(cmd("ls")).items() if k != "compound"},
        gray_has=["ps-internal-error"],
        n=1,
    ),
    case(
        "reply-missing-dynamic",
        {k: v for k, v in rep(cmd("ls")).items() if k != "dynamic"},
        gray_has=["ps-internal-error"],
    ),
    case(
        "reply-missing-parse-errors",
        {k: v for k, v in rep(cmd("ls")).items() if k != "parse_errors"},
        gray_has=["ps-internal-error"],
    ),
    case(
        "reply-parse-errors-wrong-type",
        {**rep(cmd("ls")), "parse_errors": "boom"},
        gray_has=["ps-internal-error"],
    ),
    case(
        "reply-compound-wrong-type",
        {**rep(cmd("ls")), "compound": 5},
        gray_has=["ps-internal-error"],
    ),
    case("reply-none", None, gray=["ps-internal-error"], n=0),
    case("reply-list", [rep()], gray=["ps-internal-error"]),
    case("reply-string", "{}", gray=["ps-internal-error"]),
    case("reply-int", 7, gray=["ps-internal-error"]),
    case("reply-empty-mapping", {}, gray_has=["ps-internal-error"]),
]

# --------------------------------------------------------------------------------------------
# Adversarial shapes
# --------------------------------------------------------------------------------------------

ADV_CASES = [
    case(
        "adv-command-not-a-mapping", rep("ls", 5, None, ["x"]), gray_has=["ps-internal-error"], n=0
    ),
    case(
        "adv-name-missing",
        rep({**cmd("ls"), "name": None}),
        gray_has=["ps-internal-error", "ps-dynamic-command-name"],
        n=1,
    ),
    case(
        "adv-name-not-a-mapping",
        rep({**cmd("ls"), "name": "ls"}),
        gray_has=["ps-dynamic-command-name"],
    ),
    case(
        "adv-name-value-not-a-string",
        rep({**cmd("ls"), "name": {"kind": "bare", "v": 5}}),
        gray_has=["ps-internal-error"],
    ),
    case(
        "adv-name-kind-missing-is-dynamic",
        rep({**cmd("ls"), "name": {"v": "ls"}}),
        gray_has=["ps-dynamic-command-name"],
    ),
    case(
        "adv-name-kind-unknown-is-dynamic",
        rep({**cmd("ls"), "name": {"kind": "magic", "v": "ls"}}),
        gray_has=["ps-dynamic-command-name"],
    ),
    case("adv-name-empty-string", rep(cmd("")), gray_has=["ps-dynamic-command-name"]),
    case("adv-name-whitespace", rep(cmd("   ")), gray_has=["ps-dynamic-command-name"]),
    case("adv-name-semicolon", rep(cmd("ls;rm")), gray_has=["ps-dynamic-command-name"]),
    case("adv-name-pipe", rep(cmd("a|b")), gray_has=["ps-dynamic-command-name"]),
    case("adv-name-subexpression-text", rep(cmd("$(rm)")), gray_has=["ps-dynamic-command-name"]),
    case(
        "adv-name-unicode-lookalike-is-not-the-cmdlet",
        rep(cmd("rm\u200b", S("x"))),
        argv=[["rm\u200b", "x"]],
    ),
    case(
        "adv-name-fullwidth-is-not-an-alias",
        rep(cmd("\uff52\uff4d", S("x"))),
        argv=[["\uff52\uff4d", "x"]],
    ),
    case(
        "adv-elements-not-a-list",
        rep({**cmd("ls"), "elements": "x"}),
        gray_has=["ps-internal-error"],
        argv=[["Get-ChildItem"]],
    ),
    case(
        "adv-element-not-a-mapping",
        rep(cmd("ls", None, 5, "x")),
        gray_has=["ps-dynamic-value:Unreadable"],
    ),
    case(
        "adv-element-t-missing", rep(cmd("ls", {"v": "x"})), gray_has=["ps-dynamic-value:Unknown"]
    ),
    case(
        "adv-element-str-value-not-a-string",
        rep(cmd("ls", {"t": "str", "v": ["x"]})),
        gray_has=["ps-internal-error"],
    ),
    case(
        "adv-element-str-value-missing",
        rep(cmd("ls", {"t": "str"})),
        gray_has=["ps-internal-error"],
    ),
    case(
        "adv-element-num-value-nan",
        rep(cmd("ls", {"t": "num", "v": float("nan")})),
        gray_has=["ps-internal-error"],
    ),
    case(
        "adv-element-num-value-bool",
        rep(cmd("ls", {"t": "num", "v": True})),
        gray_has=["ps-internal-error"],
    ),
    case(
        "adv-element-var-name-not-a-string",
        rep(cmd("ls", {"t": "var", "name": None})),
        gray_has=["ps-internal-error"],
    ),
    case(
        "adv-element-array-items-not-a-list",
        rep(cmd("ls", {"t": "array", "items": "abc"})),
        gray_has=["ps-internal-error"],
    ),
    case(
        "adv-element-other-without-text",
        rep(cmd("ls", {"t": "other", "ast": "X"})),
        gray_has=["ps-internal-error", "ps-dynamic-value:X"],
    ),
    case(
        "adv-element-other-ast-not-a-string",
        rep(cmd("ls", {"t": "other", "ast": {"a": 1}, "text": "x"})),
        gray_has=["ps-dynamic-value:?"],
    ),
    case(
        "adv-param-name-not-a-string",
        rep(cmd("rm", {"t": "param", "name": None, "arg": None})),
        gray_has=["ps-internal-error"],
    ),
    case(
        "adv-param-name-long",
        rep(cmd("rm", P("x" * 500), S("y"))),
        gray_has=["ps-param-unresolved:Remove-Item:-" + "x" * 63],
    ),
    case(
        "adv-param-arg-garbage",
        rep(cmd("rm", P("Path", 5))),
        gray_has=["ps-dynamic-value:Unreadable"],
    ),
    case(
        "adv-param-arg-is-a-param",
        rep(cmd("rm", P("Path", P("Force")))),
        gray_has=["ps-dynamic-value:Unknown"],
    ),
    case(
        "adv-invoke-operator-unknown",
        rep(cmd("rm", S("x"), invoke="call")),
        gray_has=["ps-internal-error"],
        argv=[[R, "x"]],
    ),
    case("adv-pos-garbage", rep({**cmd("ls"), "pos": "0-5"}), n=1, gray=[]),
    case("adv-pos-negative", rep({**cmd("ls"), "pos": [-5, 3]}), n=1),
    case("adv-nested-flag-not-a-bool", rep({**cmd("ls"), "nested": "yes"}), origin=["top"]),
    case(
        "adv-lone-surrogate-in-value",
        rep(cmd("Get-Content", S("a\ud800b"))),
        gray_has=["ps-invalid-text"],
        argv=[["Get-Content", "a\ufffdb"]],
    ),
    case("adv-lone-surrogate-in-name", rep(cmd("rm\udfff", S("x"))), gray_has=["ps-invalid-text"]),
    case(
        "adv-nul-in-value",
        rep(cmd("Get-Content", S("a\x00b"))),
        gray_has=["ps-invalid-text"],
        argv=[["Get-Content", "a\ufffdb"]],
    ),
    case("adv-nul-in-name", rep(cmd("a\x00b")), gray_has=["ps-invalid-text"], argv=[["a\ufffdb"]]),
    case(
        "adv-valid-astral-characters-are-kept",
        rep(cmd("Get-Content", S("\U0001f600"))),
        argv=[["Get-Content", "\U0001f600"]],
        gray=[],
    ),
    case(
        "adv-compound-list-with-non-strings",
        {**rep(), "compound": [None, 5, ["x"]]},
        gray_has=["ps-compound:?"],
    ),
    case("adv-dynamic-list-huge", rep(dynamic=tuple(f"T{i}" for i in range(5000))), n=0),
    case("adv-compound-list-huge", rep(compound=tuple(f"T{i}" for i in range(5000))), n=0),
]


def _deep(depth: int) -> dict[str, Any]:
    node: dict[str, Any] = S("x")
    for _ in range(depth):
        node = A(node)
    return node


ADV_CASES += [
    case(
        "adv-array-nesting-100-levels",
        rep(cmd("Get-Content", _deep(100))),
        gray_has=["ps-dynamic-value:Unreadable"],
        n=1,
    ),
    case(
        "adv-array-nesting-5-levels-is-fine",
        rep(cmd("Get-Content", _deep(5))),
        argv=[["Get-Content", "x"]],
        gray=[],
    ),
    case(
        "adv-array-nesting-100000-levels",
        rep(cmd("Get-Content", _deep(100_000))),
        gray_has=["ps-dynamic-value:Unreadable"],
    ),
    case(
        "adv-string-just_over_the_limit",
        rep(cmd("Get-Content", S("a" * (pscmd.MAX_STRING + 1)))),
        gray_has=["ps-too-large"],
        n=0,
    ),
    case(
        "adv-string_at_the_limit", rep(cmd("Get-Content", S("a" * pscmd.MAX_STRING))), n=1, gray=[]
    ),
    case(
        "adv-commands-over-the-limit",
        rep(*[cmd("ls") for _ in range(pscmd.MAX_COMMANDS + 1)]),
        gray_has=["ps-too-large"],
        n=pscmd.MAX_COMMANDS,
    ),
    case(
        "adv-commands-at-the-limit",
        rep(*[cmd("ls") for _ in range(pscmd.MAX_COMMANDS)]),
        n=pscmd.MAX_COMMANDS,
        gray=[],
    ),
    case(
        "adv-elements-over-the-limit",
        rep(cmd("Get-Content", *[S("a") for _ in range(pscmd.MAX_ELEMENTS)])),
        gray_has=["ps-too-large"],
        n=0,
    ),
    case(
        "adv-100k-elements-in-one-command",
        rep(cmd("Get-Content", *[S("a") for _ in range(100_000)])),
        gray_has=["ps-too-large"],
    ),
    case(
        "adv-100k-empty-commands",
        rep(*[cmd("ls") for _ in range(100_000)]),
        gray_has=["ps-too-large"],
        n=pscmd.MAX_COMMANDS,
    ),
    case(
        "adv-too-large-keeps-earlier-commands",
        rep(
            cmd("rm", P("Recurse"), S("C:\\x")),
            cmd("Get-Content", *[S("a") for _ in range(pscmd.MAX_ELEMENTS)]),
        ),
        gray_has=["ps-too-large"],
        n=1,
    ),
    case(
        "adv-deny-command-hidden-behind-noise",
        rep(*([cmd("ls")] * 3999), cmd("rm", P("Recurse"), S("C:\\x"))),
        n=pscmd.MAX_COMMANDS,
        gray=[],
    ),
    case(
        "adv-redirect-op-too-long",
        rep(cmd("ls", redirects=[RD(">" * 20, S("o"))])),
        gray_has=["ps-internal-error"],
    ),
    case(
        "adv-redirect-merge-not-a-string",
        rep(cmd("ls", redirects=[RD(">", S("o"), 5)])),
        redirects=[(">", "o")],
    ),
    case(
        "adv-redirect-merge-long-is-cut",
        rep(cmd("ls", redirects=[RD(">", None, "2>&1" + "x" * 99)])),
        n=1,
    ),
    case("adv-stage-not-a-mapping", rep({**cmd("ls"), "stage": [0, 3]}), pipe=[False]),
    case("adv-reply-extra-keys-are-ignored", rep(cmd("ls"), extra=object()), n=1, gray=[]),
]


@pytest.mark.parametrize(
    ("reply", "expect"),
    [
        *NAME_CASES,
        *PARAM_CASES,
        *VALUE_CASES,
        *REDIRECT_CASES,
        *PIPELINE_CASES,
        *REPLY_CASES,
        *ADV_CASES,
    ],
)
def test_build_table(reply: Any, expect: dict[str, Any]) -> None:
    expect = {k: v for k, v in expect.items() if v is not None}
    check(build(reply), expect)


def _alias_def(command: str, *elements: Any, **kw: Any) -> dict[str, Any]:
    return cmd(command, *elements, **kw)


ALIAS_CASES = [
    pytest.param(
        rep(_alias_def("Set-Alias", S("gc"), S("Remove-Item")), cmd("gc", S("x"))),
        [["Set-Alias", "gc", "Remove-Item"], ["$(gc)", "x"]],
        id="set-alias-then-use-positional",
    ),
    pytest.param(
        rep(_alias_def("sal", P("Name"), S("gc"), P("Value"), S("Remove-Item")), cmd("GC", S("x"))),
        [["Set-Alias", "-Name", "gc", "-Value", "Remove-Item"], ["$(GC)", "x"]],
        id="named-parameters-and-case-insensitive-use",
    ),
    pytest.param(
        rep(_alias_def("New-Alias", S("rm"), S("Get-Content")), cmd("rm", S("x"))),
        [["New-Alias", "rm", "Get-Content"], ["$(rm)", "x"]],
        id="new-alias-redefines-rm",
    ),
    pytest.param(
        rep(_alias_def("Set-Alias", S("ll"), S("Get-ChildItem")), cmd("ls", S("x"))),
        [["Set-Alias", "ll", "Get-ChildItem"], ["Get-ChildItem", "x"]],
        id="other-names-keep-their-meaning",
    ),
    pytest.param(
        rep(_alias_def("Set-Alias", V("n"), S("Get-Content")), cmd("ls", S("x")), cmd("git")),
        [["Set-Alias", "$n", "Get-Content"], ["$(ls)", "x"], ["git"]],
        id="unknowable-name-makes-every-alias-suspect",
    ),
    pytest.param(
        rep(_alias_def("Set-Alias", S("gc"), S("Remove-Item")), cmd("Get-Content", S("x"))),
        [["Set-Alias", "gc", "Remove-Item"], ["Get-Content", "x"]],
        id="canonical-names-are-not-aliases",
    ),
    pytest.param(
        rep(_alias_def("Set-Alias", S("content"), S("Remove-Item")), cmd("content", S("x"))),
        [["Set-Alias", "content", "Remove-Item"], ["$(content)", "x"]],
        id="shadowing-the-implicit-get-verb-name",
    ),
    pytest.param(
        rep(_alias_def("Set-Alias", V("n"), S("Remove-Item")), cmd("content", S("x"))),
        [["Set-Alias", "$n", "Remove-Item"], ["$(content)", "x"]],
        id="unknowable-name-also-shadows-the-implicit-get-verb",
    ),
    pytest.param(
        rep(_alias_def("Import-Alias", S("a.csv")), cmd("ls")),
        [["Import-Alias", "a.csv"], ["Get-ChildItem"]],
        id="import-alias-is-not-a-definition-we-can-read",
    ),
]


@pytest.mark.parametrize(("reply", "argv"), ALIAS_CASES)
def test_alias_redefinition_shadows_later_names(reply: Any, argv: list[list[str]]) -> None:
    res = build(reply)
    assert [[w.text for w in c.argv] for c in res.commands] == argv
    assert "ps-alias-redefined" in res.gray or argv[0][0] == "Import-Alias"
    if any(a[0].startswith("$(") for a in argv):
        assert "ps-alias-shadowed" in res.exec_reasons


def test_case_table_sizes() -> None:
    """The tables above are the bulk of the coverage: keep them from silently shrinking."""
    total = sum(
        map(
            len,
            (
                NAME_CASES,
                PARAM_CASES,
                VALUE_CASES,
                REDIRECT_CASES,
                PIPELINE_CASES,
                REPLY_CASES,
                ADV_CASES,
            ),
        )
    )
    assert total >= 200
    assert len([c for c in [*ADV_CASES] if str(c.id).startswith("adv-")]) >= 50


def test_source_text_is_only_informational() -> None:
    res = build(rep({**cmd("ls"), "pos": [2, 7]}), source="xxabcdefgh")
    assert res.commands[0].raw == "abcde"
    assert build(rep(cmd("ls")), source=None).commands[0].raw == ""  # type: ignore[arg-type]


def test_raw_text_is_bounded() -> None:
    res = build(rep({**cmd("ls"), "pos": [0, 10**6]}), source="x" * 10**6)
    assert len(res.commands[0].raw) == 512


def test_build_result_is_hashable_data() -> None:
    res = build(rep(cmd("rm", P("Rec"), S("x"))))
    assert isinstance(res.commands, tuple)
    assert isinstance(res.gray, tuple)
    assert isinstance(res.exec_reasons, tuple)
    assert res.commands[0].argv[1] == Word("-Recurse")


def test_psaliases_exceptions_degrade_to_gray(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: Any) -> None:
        raise RuntimeError("table broken")

    monkeypatch.setattr(pscmd.psaliases, "canonical_command", boom)
    res = build(rep(cmd("rm", P("Rec"), S("x"))))
    assert (
        res.commands[0].argv[0].text == "rm"
    )  # unknown name: an external program, not Remove-Item
    monkeypatch.undo()
    monkeypatch.setattr(pscmd.psaliases, "canonical_param", boom)
    res = build(rep(cmd("rm", P("Rec"), S("x"))))
    assert "ps-param-unresolved:Remove-Item:-Rec" in res.gray


def test_internal_error_is_gray_not_an_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: Any, **_kw: Any) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(pscmd, "_command", boom)
    res = build(rep(cmd("rm", S("x"))))
    assert res.gray == ("ps-internal-error",)
    assert res.commands == ()


# --------------------------------------------------------------------------------------------
# Real helper fixtures
# --------------------------------------------------------------------------------------------


def _load_index(folder: str) -> dict[str, str]:
    path = FIXTURES / folder / "index.json"
    if not path.exists():
        return {}
    data: dict[str, str] = json.loads(path.read_text(encoding="utf-8"))
    return data


REAL = {**_load_index("ps_ast"), **_load_index("ps_ast_manual")}


def _read_fixture(relative: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / relative).read_text(encoding="utf-8"))
    return data


def _fixture_pairs() -> list[Any]:
    out = []
    for folder in ("ps_ast", "ps_ast_manual"):
        for text, name in sorted(_load_index(folder).items()):
            out.append(pytest.param(text, f"{folder}/{name}", id=f"{folder}-{name[:-5]}"))
    return out


@pytest.mark.parametrize(("text", "fixture"), _fixture_pairs())
def test_every_real_fixture_builds_and_classifies(text: str, fixture: str) -> None:
    res = build(_read_fixture(fixture), text)
    assert "ps-internal-error" not in res.gray
    assert "ps-too-large" not in res.gray
    for c in res.commands:
        assert c.argv, "every command has a program"
        assert all(isinstance(w, Word) for w in c.argv)
        info = ps_classify(c)
        assert "ps-internal-error" not in info.gray
        assert "classify-internal-error" not in info.gray
        assert psprograms.classify_ps(c.argv[0].text, c.argv[1:], redirects=c.redirects) == info


def test_there_are_enough_real_fixtures() -> None:
    assert len(REAL) >= 150


@pytest.mark.windows
@pytest.mark.skipif(sys.platform != "win32", reason="needs the real PowerShell helper")
def test_manual_fixtures_are_what_the_real_helper_says() -> None:
    """ps_ast_manual/ is generated with the real helper from index.json's texts: re-check it."""
    from boundkeep.normalize import psparse

    manual = _load_index("ps_ast_manual")
    helper = psparse.PsHelper(startup_timeout_s=60)
    if not helper.warm_up(wait_s=60):
        pytest.skip("no working PowerShell helper")
    try:
        stale = []
        for text, name in manual.items():
            reply, _gray = helper.request(text, budget_s=30)
            assert reply is not None, text
            body = {k: v for k, v in reply.items() if k != "id"}
            if body != _read_fixture(f"ps_ast_manual/{name}"):
                stale.append(text)
        assert not stale, stale[:5]
    finally:
        helper.shutdown()


# --------------------------------------------------------------------------------------------
# The corpus (tests/corpus/powershell_parse.yaml, entries `cmd-*`)
# --------------------------------------------------------------------------------------------


def _corpus() -> list[dict[str, Any]]:
    data = yaml.safe_load(CORPUS.read_text(encoding="utf-8"))
    return [e for e in data if str(e.get("id", "")).startswith("cmd-")]


def _corpus_params() -> list[Any]:
    return [pytest.param(e, id=e["id"]) for e in _corpus()]


def _check_command(cmd_: Any, want: dict[str, Any]) -> None:
    info = ps_classify(cmd_)
    assert cmd_.argv[0].text == want["program"]
    if "args" in want:
        assert [w.text for w in cmd_.argv[1:]] == want["args"]
    if "flags" in want:
        assert set(want["flags"]) <= set(info.flags), info.flags
    got_paths = {(w.text, a) for w, a in info.paths}
    if "paths" in want:
        assert got_paths == {tuple(p) for p in want["paths"]}, got_paths
    if "paths_has" in want:
        assert {tuple(p) for p in want["paths_has"]} <= got_paths, got_paths
    if "urls" in want:
        assert sorted(info.urls) == sorted(want["urls"]), info.urls
    if "net" in want:
        assert info.network is want["net"]
    if "tags" in want:
        assert set(info.tags) == set(want["tags"]), info.tags
    if "tags_has" in want:
        assert set(want["tags_has"]) <= set(info.tags), info.tags
    if "known" in want:
        assert info.known is want["known"]
    if "sub" in want:
        assert info.subcommand == want["sub"]
    if "gray" in want:
        assert set(info.gray) == set(want["gray"]), info.gray
    if "gray_has" in want:
        assert set(want["gray_has"]) <= set(info.gray), info.gray
    if "pipe" in want:
        assert cmd_.in_pipeline is want["pipe"]


@pytest.mark.parametrize("entry", _corpus_params())
def test_corpus_entry(entry: dict[str, Any]) -> None:
    res = build(_read_fixture(entry["fixture"]), entry["text"])
    expect = entry["expect"]
    check(
        res,
        {k: expect[k] for k in ("gray", "gray_has", "exec", "exec_has") if k in expect},
    )
    wants = expect.get("commands")
    if wants is not None:
        assert len(res.commands) == len(wants), [texts(res, i) for i in range(len(res.commands))]
        for got, want in zip(res.commands, wants, strict=True):
            _check_command(got, want)


def test_corpus_is_big_enough_and_fixtures_exist() -> None:
    entries = _corpus()
    assert len(entries) >= 60
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids))
    texts_ = [e["text"] for e in entries]
    assert len(texts_) == len(set(texts_))
    for e in entries:
        assert (FIXTURES / e["fixture"]).is_file(), e["fixture"]
        assert REAL.get(e["text"]) == Path(e["fixture"]).name, e["id"]


# --------------------------------------------------------------------------------------------
# Property tests: arbitrary JSON-like structures never raise; non-conforming ones are gray
# --------------------------------------------------------------------------------------------

_LEAF = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-5, 5),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=12),
    st.sampled_from(
        ["str", "expstr", "var", "num", "array", "other", "param", "&", ".", "bare", "-"]
    ),
)
JSONISH = st.recursive(
    _LEAF,
    lambda inner: st.one_of(
        st.lists(inner, max_size=4),
        st.dictionaries(
            st.sampled_from(
                [
                    "t",
                    "v",
                    "kind",
                    "name",
                    "arg",
                    "items",
                    "ast",
                    "text",
                    "vars",
                    "subexpr",
                    "splat",
                    "elements",
                    "redirects",
                    "op",
                    "target",
                    "merge",
                    "stage",
                    "index",
                    "of",
                    "nested",
                    "invoke",
                    "pos",
                    "commands",
                    "compound",
                    "dynamic",
                    "parse_errors",
                    "ok",
                    "mode",
                    "error",
                ]
            ),
            inner,
            max_size=6,
        ),
    ),
    max_leaves=40,
)

_FIXTURE_REPLIES = [
    _read_fixture(f"ps_ast/{name}") for name in list(_load_index("ps_ast").values())[:60]
]


def _conforms(reply: Any) -> bool:
    """A strict validator: does ``reply`` have the documented shape (so that gray is optional)?"""

    def element(e: Any, top: bool = True) -> bool:
        if not isinstance(e, dict):
            return False
        t = e.get("t")
        if t == "param":
            arg = e.get("arg")
            return top and isinstance(e.get("name"), str) and (arg is None or element(arg, False))
        if t == "str":
            return isinstance(e.get("v"), str)
        if t == "expstr":
            return isinstance(e.get("v"), str)
        if t == "var":
            return isinstance(e.get("name"), str)
        if t == "num":
            return isinstance(e.get("v"), str)
        if t == "array":
            items = e.get("items")
            return isinstance(items, list) and all(element(i, False) for i in items)
        if t == "other":
            return isinstance(e.get("ast"), str) and isinstance(e.get("text"), str)
        return False

    def command(c: Any) -> bool:
        if not isinstance(c, dict) or not isinstance(c.get("name"), dict):
            return False
        name = c["name"]
        if not isinstance(name.get("v"), str) or name.get("kind") not in (
            "bare",
            "single",
            "double",
            "expandable",
            "variable",
            "expr",
        ):
            return False
        if c.get("invoke", "") not in ("", "&", "."):
            return False
        if not isinstance(c.get("elements", []), list) or not all(
            element(e) for e in c.get("elements", [])
        ):
            return False
        reds = c.get("redirects", [])
        if not isinstance(reds, list):
            return False
        for r in reds:
            if not isinstance(r, dict):
                return False
            merge = r.get("merge")
            if isinstance(merge, str) and merge:
                continue
            if not isinstance(r.get("op"), str) or not element(r.get("target"), False):
                return False
        return True

    return (
        isinstance(reply, dict)
        and reply.get("ok", True) is True
        and isinstance(reply.get("commands"), list)
        and isinstance(reply.get("compound"), list)
        and isinstance(reply.get("dynamic"), list)
        and isinstance(reply.get("parse_errors"), list)
        and all(command(c) for c in reply["commands"])
    )


def _mutations() -> st.SearchStrategy[Any]:
    base = st.sampled_from(_FIXTURE_REPLIES)

    def mutate(reply: dict[str, Any], seed: int, replacement: Any) -> Any:
        import copy

        out = copy.deepcopy(reply)
        paths: list[tuple[Any, Any]] = []

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for k in node:
                    paths.append((node, k))
                    walk(node[k])
            elif isinstance(node, list):
                for i in range(len(node)):
                    paths.append((node, i))
                    walk(node[i])

        walk(out)
        if not paths:
            return replacement
        container, key = paths[seed % len(paths)]
        if seed % 3 == 0 and isinstance(container, dict):
            del container[key]
        else:
            container[key] = replacement
        return out

    return st.builds(mutate, base, st.integers(0, 10_000), JSONISH)


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(JSONISH)
def test_arbitrary_json_never_raises_and_nonconforming_is_gray(reply: Any) -> None:
    res = pscmd.build(reply, source="x")
    assert isinstance(res, BashResult)
    if not _conforms(reply):
        assert res.gray, reply
    for c in res.commands:
        assert c.argv
        for r in c.redirects:
            assert r.target is None or isinstance(r.target, Word)
        info = ps_classify(c)
        assert "ps-internal-error" not in info.gray


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(_mutations())
def test_mutated_real_replies_never_raise_and_nonconforming_is_gray(reply: Any) -> None:
    res = pscmd.build(reply, source="")
    assert isinstance(res, BashResult)
    if not _conforms(reply):
        assert res.gray, reply
    for c in res.commands:
        info = ps_classify(c)
        assert "ps-internal-error" not in info.gray


@settings(max_examples=200, deadline=None)
@given(
    st.text(max_size=40),
    st.text(max_size=20),
    st.sampled_from(["bare", "single", "double", "variable", "expr", "expandable"]),
)
def test_arbitrary_names_and_parameters_never_raise(name: str, param: str, kind: str) -> None:
    res = pscmd.build(rep(cmd(name, P(param, S(name)), S(param), kind=kind)), source=name)
    assert isinstance(res, BashResult)
    for c in res.commands:
        ps_classify(c)


@settings(max_examples=100, deadline=None)
@given(st.lists(st.text(max_size=6), max_size=30))
def test_arbitrary_compound_and_dynamic_names_are_bounded(names: list[str]) -> None:
    res = pscmd.build(rep(cmd("ls"), compound=tuple(names), dynamic=tuple(names)), source="")
    assert len(res.gray) <= pscmd.MAX_REASONS
    assert len(res.exec_reasons) <= pscmd.MAX_REASONS


# --------------------------------------------------------------------------------------------
# M1b review fixes: cd.. / cd\ functions, splats, --% stop-parsing, external flag case
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "arg"),
    [("cd..", ".."), ("CD..", ".."), ("cd\\", "\\"), ("Cd\\", "\\")],
)
def test_cd_functions_are_set_location_with_a_fixed_argument(name: str, arg: str) -> None:
    res = build(rep(cmd(name)))
    assert texts(res) == ["Set-Location", arg]
    assert not res.gray
    info = ps_classify(res.commands[0])
    assert info.known
    assert (arg, "read") in {(w.text, a) for w, a in info.paths}


def test_cd_function_with_extra_words_keeps_them_so_the_cwd_is_unknown() -> None:
    res = build(rep(cmd("cd..", S("elsewhere"))))
    assert texts(res) == ["Set-Location", "..", "elsewhere"]  # event._after_cd: two words -> ?


def test_cd_function_redefined_by_the_line_is_dynamic() -> None:
    res = build(
        rep(cmd("Set-Alias", S("cd.."), S("Remove-Item")), cmd("cd..", S("x"))),
        source="Set-Alias cd.. Remove-Item; cd.. x",
    )
    assert "ps-alias-shadowed" in res.gray
    assert texts(res, 1)[0] != "Set-Location"


def test_a_path_qualified_cd_function_is_not_the_builtin() -> None:
    res = build(rep(cmd(".\\cd..")))
    assert texts(res)[0] != "Set-Location"
    assert "ps-script-exec" in res.gray


def test_splat_argument_is_a_dynamic_word_that_no_layer_can_place() -> None:
    res = build(rep(cmd("Remove-Item", P("Recurse"), V("paths", splat=True))))
    assert texts(res) == ["Remove-Item", "-Recurse", "$(@paths)"]
    assert "ps-dynamic-value:Splat" in res.gray
    assert res.commands[0].argv[2].expands
    info = ps_classify(res.commands[0])
    assert any(w.expands and a == "write" for w, a in info.paths), info.paths


def test_splat_on_an_external_program_is_dynamic_too() -> None:
    res = build(rep(cmd("git", V("gitargs", splat=True))))
    assert res.commands[0].argv[1].expands
    assert "ps-dynamic-value:Splat" in res.gray


def test_stop_parsing_rest_of_line_is_split_into_words() -> None:
    res = build(rep(cmd("git", S("reset"), S("--%"), S("--hard HEAD~1"))))
    assert texts(res) == ["git", "reset", "--%", "--hard", "HEAD~1"]
    assert "ps-stop-parsing" in res.gray
    info = ps_classify(res.commands[0])
    assert "--hard" in info.flags


def test_stop_parsing_percent_variables_stay_dynamic() -> None:
    res = build(rep(cmd("cmd", S("--%"), S("/c type %USERPROFILE%\\.ssh\\id_rsa"))))
    words = {w.text: w for w in res.commands[0].argv}
    assert words["%USERPROFILE%\\.ssh\\id_rsa"].expands
    assert "ps-stop-parsing" in res.gray


def test_stop_parsing_only_covers_the_next_string_element() -> None:
    res = build(rep(cmd("git", S("--%"), P("x"), S("a b"))))
    assert "a b" in texts(res)  # not split: it follows a parameter, not the --% token


def test_external_flag_case_is_kept_for_the_rule_matcher() -> None:
    low = build(rep(cmd("git", S("branch"), P("d"), S("x"))))
    up = build(rep(cmd("git", S("branch"), P("D"), S("x"))))
    assert "-d" in ps_classify(low.commands[0]).flags
    assert "-D" in ps_classify(up.commands[0]).flags
    assert "-D" not in ps_classify(low.commands[0]).flags
