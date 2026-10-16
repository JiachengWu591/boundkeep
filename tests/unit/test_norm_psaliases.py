"""Tests for ``boundkeep.normalize.psaliases`` (static PowerShell alias / cmdlet parameter tables).

Three layers:

* table-driven cases for ``canonical_command`` / ``canonical_param`` / ``takes_value`` and the data;
* structural invariants checked by brute force over the whole table, and "never raises" properties;
* ``windows`` consistency tests that compare the tables with the REAL Windows PowerShell 5.1 of the
  machine (aliases, parameters, switch-ness, positions, and every abbreviation against
  ``CommandInfo.ResolveParameter``). They run ONE fixed PowerShell script; the only inputs are
  names that come from the tables themselves (validated against a strict pattern), never untrusted
  text. They skip on other platforms and when ``powershell.exe`` is missing.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from boundkeep.normalize import psaliases as pa
from boundkeep.normalize.psaliases import (
    ALIASES,
    AMBIGUOUS,
    CMDLETS,
    UNMODELED,
    canonical_command,
    canonical_param,
    cmdlet_spec,
    takes_value,
)
from tests.conftest import REPO_ROOT, scrubbed_env

# ---------------------------------------------------------------------------------------------
# Table-driven cases
# ---------------------------------------------------------------------------------------------

ALIAS_CASES = [
    ("ls", "Get-ChildItem"),
    ("dir", "Get-ChildItem"),
    ("gci", "Get-ChildItem"),
    ("cat", "Get-Content"),
    ("gc", "Get-Content"),
    ("type", "Get-Content"),
    ("rm", "Remove-Item"),
    ("del", "Remove-Item"),
    ("erase", "Remove-Item"),
    ("rd", "Remove-Item"),
    ("rmdir", "Remove-Item"),
    ("ri", "Remove-Item"),
    ("cp", "Copy-Item"),
    ("copy", "Copy-Item"),
    ("cpi", "Copy-Item"),
    ("mv", "Move-Item"),
    ("move", "Move-Item"),
    ("mi", "Move-Item"),
    ("ren", "Rename-Item"),
    ("rni", "Rename-Item"),
    ("curl", "Invoke-WebRequest"),
    ("wget", "Invoke-WebRequest"),
    ("iwr", "Invoke-WebRequest"),
    ("irm", "Invoke-RestMethod"),
    ("iex", "Invoke-Expression"),
    ("icm", "Invoke-Command"),
    ("saps", "Start-Process"),
    ("start", "Start-Process"),
    ("sc", "Set-Content"),
    ("ac", "Add-Content"),
    ("clc", "Clear-Content"),
    ("sl", "Set-Location"),
    ("cd", "Set-Location"),
    ("chdir", "Set-Location"),
    ("pushd", "Push-Location"),
    ("popd", "Pop-Location"),
    ("pwd", "Get-Location"),
    ("echo", "Write-Output"),
    ("write", "Write-Output"),
    ("gp", "Get-ItemProperty"),
    ("sp", "Set-ItemProperty"),
    ("rp", "Remove-ItemProperty"),
    ("mp", "Move-ItemProperty"),
    ("cpp", "Copy-ItemProperty"),
    ("clp", "Clear-ItemProperty"),
    ("rnp", "Rename-ItemProperty"),
    ("gi", "Get-Item"),
    ("ni", "New-Item"),
    ("si", "Set-Item"),
    ("cli", "Clear-Item"),
    ("select", "Select-Object"),
    ("sls", "Select-String"),
    ("%", "ForEach-Object"),
    ("foreach", "ForEach-Object"),
    ("?", "Where-Object"),
    ("where", "Where-Object"),
    ("sort", "Sort-Object"),
    ("group", "Group-Object"),
    ("measure", "Measure-Object"),
    ("man", "help"),
    ("cls", "Clear-Host"),
    ("clear", "Clear-Host"),
    ("kill", "Stop-Process"),
    ("spps", "Stop-Process"),
    ("ps", "Get-Process"),
    ("gps", "Get-Process"),
    ("gm", "Get-Member"),
    ("diff", "Compare-Object"),
    ("compare", "Compare-Object"),
    ("sleep", "Start-Sleep"),
    ("tee", "Tee-Object"),
    ("rvpa", "Resolve-Path"),
    ("cvpa", "Convert-Path"),
    ("ii", "Invoke-Item"),
    ("sasv", "Start-Service"),
    ("spsv", "Stop-Service"),
    ("gsv", "Get-Service"),
    ("sv", "Set-Variable"),
    ("set", "Set-Variable"),
    ("nv", "New-Variable"),
    ("gv", "Get-Variable"),
    ("rv", "Remove-Variable"),
    ("clv", "Clear-Variable"),
    ("gwmi", "Get-WmiObject"),
    ("iwmi", "Invoke-WmiMethod"),
    ("rwmi", "Remove-WmiObject"),
    ("swmi", "Set-WmiInstance"),
    ("epcsv", "Export-Csv"),
    ("ipcsv", "Import-Csv"),
    ("ipmo", "Import-Module"),
    ("sal", "Set-Alias"),
    ("nal", "New-Alias"),
    ("gal", "Get-Alias"),
    ("nsn", "New-PSSession"),
    ("etsn", "Enter-PSSession"),
    ("md", "mkdir"),
    ("h", "Get-History"),
    ("history", "Get-History"),
    ("r", "Invoke-History"),
    ("oh", "Out-Host"),
    ("ft", "Format-Table"),
    ("fl", "Format-List"),
    ("ise", "powershell_ise.exe"),
    # aliases that only exist after a built-in module auto-loads
    ("gcb", "Get-Clipboard"),
    ("scb", "Set-Clipboard"),
    ("tnc", "Test-NetConnection"),
    ("inmo", "Install-Module"),
    ("icim", "Invoke-CimMethod"),
    ("gcim", "Get-CimInstance"),
    ("rcim", "Remove-CimInstance"),
]


@pytest.mark.parametrize(("alias", "target"), ALIAS_CASES, ids=[a for a, _ in ALIAS_CASES])
def test_alias_table(alias: str, target: str) -> None:
    assert ALIASES[alias] == target
    assert canonical_command(alias) == target
    assert canonical_command(alias.upper()) == target


COMMAND_CASES: list[tuple[str, str | None]] = [
    ("Remove-Item", "Remove-Item"),
    ("remove-item", "Remove-Item"),
    ("REMOVE-ITEM", "Remove-Item"),
    ("rM", "Remove-Item"),
    ("Invoke-WMIMethod", "Invoke-WmiMethod"),
    ("microsoft.powershell.management\\Remove-Item", "Remove-Item"),
    ("Microsoft.PowerShell.Utility\\Invoke-WebRequest", "Invoke-WebRequest"),
    ("CimCmdlets\\get-ciminstance", "Get-CimInstance"),
    # a non-built-in module prefix could shadow the cmdlet: returned like a path, not resolved
    ("EvilModule\\Remove-Item", "EvilModule\\Remove-Item"),
    # module-qualified ALIASES are not valid PowerShell: not resolved
    ("Microsoft.PowerShell.Management\\rm", "Microsoft.PowerShell.Management\\rm"),
    ("Microsoft.PowerShell.Management\\Nope-Cmd", "Microsoft.PowerShell.Management\\Nope-Cmd"),
    ("a\\b\\Remove-Item", "a\\b\\Remove-Item"),
    ("git.exe", "git.exe"),
    ("GIT.EXE", "GIT.EXE"),
    ("curl.exe", "curl.exe"),
    ("rm.exe", "rm.exe"),
    ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\cmd.exe"),
    ("C:/tools/a.exe", "C:/tools/a.exe"),
    (".\\build.ps1", ".\\build.ps1"),
    ("./run.sh", "./run.sh"),
    ("~/bin/tool", "~/bin/tool"),
    ("\\\\server\\share\\x", "\\\\server\\share\\x"),
    ("C:\\Users\\张三\\x.exe", "C:\\Users\\张三\\x.exe"),
    ("程序.exe", "程序.exe"),
    ("git", None),
    ("npm", None),
    ("python3", None),
    ("Get-Nothing", None),
    ("", None),
    (" ", None),
    (".exe", None),
    ("rm ", None),
    (" rm", None),
    ("r\u0000m", None),
    ("rm\n", None),
    ("\u212aill", None),  # Kelvin sign: not an ASCII 'K', never case-folded into the alias
    ("\u0131f", None),
    ("rm\u200b", None),
    ("Remove-Item\u00ad", None),
    ("Remove-Service", "Remove-Service"),
    ("remove-service", "Remove-Service"),
    ("help", "help"),
    ("MKDIR", "mkdir"),
    ("clear-host", "Clear-Host"),
    ("Get-SmbShare", "Get-SmbShare"),
    ("a" * 40_000, None),
    ("a/" * 20_000, None),
]


@pytest.mark.parametrize(
    ("name", "expected"),
    COMMAND_CASES,
    ids=[repr(n if len(n) < 30 else n[:12] + "...") for n, _ in COMMAND_CASES],
)
def test_canonical_command(name: str, expected: str | None) -> None:
    assert canonical_command(name) == expected


PARAM_CASES: list[tuple[str, str, object]] = [
    # exact names (any case, with or without the dash)
    ("Remove-Item", "-Recurse", "-Recurse"),
    ("Remove-Item", "-recurse", "-Recurse"),
    ("Remove-Item", "RECURSE", "-Recurse"),
    ("Remove-Item", "-Force", "-Force"),
    ("Remove-Item", "-LiteralPath", "-LiteralPath"),
    # unique abbreviations
    ("Remove-Item", "-Rec", "-Recurse"),
    ("Remove-Item", "-R", "-Recurse"),
    ("Remove-Item", "-Fo", "-Force"),
    ("Remove-Item", "-Pa", "-Path"),
    ("Remove-Item", "-Inc", "-Include"),
    ("Remove-Item", "-Ex", "-Exclude"),
    ("Remove-Item", "-Lit", "-LiteralPath"),
    # aliases of parameters
    ("Remove-Item", "-PSPath", "-LiteralPath"),
    ("Remove-Item", "-psp", "-LiteralPath"),
    ("Remove-Item", "-cf", "-Confirm"),
    ("Remove-Item", "-wi", "-WhatIf"),
    ("Remove-Item", "-ea", "-ErrorAction"),
    ("Remove-Item", "-EA", "-ErrorAction"),
    ("Remove-Item", "-vb", "-Verbose"),
    ("Remove-Item", "-db", "-Debug"),
    ("Remove-Item", "-wa", "-WarningAction"),
    ("Remove-Item", "-infa", "-InformationAction"),
    ("Remove-Item", "-ia", None),  # 5.1 has no such alias (it is infa)
    ("Remove-Item", "-ev", "-ErrorVariable"),
    ("Remove-Item", "-wv", "-WarningVariable"),
    ("Remove-Item", "-iv", "-InformationVariable"),
    ("Remove-Item", "-ov", "-OutVariable"),
    ("Remove-Item", "-ob", "-OutBuffer"),
    ("Remove-Item", "-pv", "-PipelineVariable"),
    # the command may be an alias or any-case name
    ("rm", "-rec", "-Recurse"),
    ("RM", "-Rec", "-Recurse"),
    ("del", "-force", "-Force"),
    ("ri", "-r", "-Recurse"),
    ("Microsoft.PowerShell.Management\\Remove-Item", "-Rec", "-Recurse"),
    # ambiguity: several declared parameters
    ("Remove-Item", "-F", AMBIGUOUS),  # Filter / Force
    ("Get-ChildItem", "-Fi", AMBIGUOUS),  # Filter / File
    ("Get-ChildItem", "-Fo", AMBIGUOUS),  # Force / FollowSymlink
    ("gci", "-r", AMBIGUOUS),  # Recurse / ReadOnly (a provider parameter)
    ("Get-ChildItem", "-Fil", AMBIGUOUS),
    # ambiguity: only common parameters (WhatIf is not "declared" either)
    ("Remove-Item", "-w", AMBIGUOUS),
    ("Remove-Item", "-Err", AMBIGUOUS),
    ("Remove-Item", "-Out", AMBIGUOUS),
    ("Remove-Item", "-Inf", AMBIGUOUS),  # InformationAction / InformationVariable
    # PowerShell prefers the command's own parameter over a common one
    ("Remove-Item", "-In", "-Include"),
    ("Remove-Item", "-c", "-Credential"),
    ("Remove-Item", "-Con", "-Confirm"),
    ("Remove-Item", "-u", "-UseTransaction"),
    # an exact alias wins over a prefix of another name (wa is WarningAction, not Wait)
    ("Get-Content", "-wa", "-WarningAction"),
    # a prefix that fits a name AND an alias of the SAME parameter is not ambiguous
    ("Get-ChildItem", "-s", "-Recurse"),
    ("Get-ChildItem", "-rec", "-Recurse"),
    ("Get-ChildItem", "-ad", "-Directory"),
    ("Get-ChildItem", "-Dir", "-Directory"),
    ("Get-ChildItem", "-ah", "-Hidden"),
    ("Get-ChildItem", "-Filt", "-Filter"),
    # unknown things
    ("Remove-Item", "-Nope", None),
    ("Remove-Item", "-Recursex", None),
    ("Remove-Item", "-lp", None),
    ("Remove-Item", "", None),
    ("Remove-Item", "-", None),
    ("Remove-Item", "--Recurse", None),
    ("Remove-Item", "-Recurse:$true", None),
    ("Remove-Item", "-Recurse:", None),
    ("Remove-Item", ":", None),
    ("Remove-Item", "-Rec urse", None),
    (
        "Remove-Item",
        "-Rec\u00adurse",
        None,
    ),  # soft hyphen: PowerShell ignores it, we do not model it
    ("Remove-Item", "-\u0420ecurse", None),  # Cyrillic R
    ("Remove-Item", "-Recurse\u0000", None),
    ("Remove-Item", "-" + "R" * 100, None),
    ("Remove-Item", "-*", None),
    ("Remove-Item", "-?", None),
    ("not-a-cmdlet", "-Recurse", None),
    ("git", "-r", None),
    ("git.exe", "-r", None),
    ("Remove-Service", "-Name", None),  # known command without a parameter table
    ("Get-SmbShare", "-Name", None),
    ("", "-r", None),
    # typographic dashes are parameter dashes for PowerShell
    ("Remove-Item", "\u2013Recurse", "-Recurse"),
    ("Remove-Item", "\u2014Rec", "-Recurse"),
    ("Remove-Item", "\u2015Rec", "-Recurse"),
    # other cmdlets
    ("Copy-Item", "-Dest", "-Destination"),
    ("Copy-Item", "-D", "-Destination"),
    ("Move-Item", "-Dest", "-Destination"),
    ("Set-Content", "-V", "-Value"),
    ("Set-Content", "-Va", "-Value"),
    ("sc", "-Path", "-Path"),
    ("Invoke-WebRequest", "-OutF", "-OutFile"),
    ("iwr", "-Out", "-OutFile"),  # the declared OutFile beats the common Out*
    ("curl", "-Uri", "-Uri"),
    ("curl", "-X", None),  # a curl.exe option, not an Invoke-WebRequest parameter
    ("curl", "-Method", "-Method"),
    ("curl", "-Me", "-Method"),
    ("iwr", "-UseB", "-UseBasicParsing"),
    ("Invoke-WebRequest", "-Proxy", "-Proxy"),
    ("Start-Process", "-Wait", "-Wait"),
    ("Start-Process", "-Wa", "-WarningAction"),  # exact alias beats the prefix of Wait
    ("Start-Process", "-W", AMBIGUOUS),
    ("saps", "-Verb", "-Verb"),
    ("Stop-Process", "-Name", "-Name"),
    ("kill", "-Id", "-Id"),
    ("Set-ExecutionPolicy", "-Scope", "-Scope"),
    ("Set-ExecutionPolicy", "-Sc", "-Scope"),
    ("Set-ExecutionPolicy", "-Fo", "-Force"),
    ("Out-File", "-Path", None),  # in 5.1 FilePath has no alias Path (PowerShell 7 does)
    ("Out-File", "-Fi", "-FilePath"),
    ("Out-File", "-Append", "-Append"),
    ("Select-String", "-Patt", "-Pattern"),
    ("Select-String", "-Pat", AMBIGUOUS),  # Path / Pattern
    ("sls", "-Path", "-Path"),
    ("Select-Object", "-First", "-First"),
    ("Select-Object", "-ExpandProperty", "-ExpandProperty"),
    ("ForEach-Object", "-Process", "-Process"),
    ("Where-Object", "-Property", "-Property"),
    ("Test-Path", "-PathType", "-PathType"),
    ("Test-Path", "-Pa", AMBIGUOUS),  # Path / PathType
]


def _id(cmdlet: str, token: str) -> str:
    return f"{cmdlet}:{token}"[:50].encode("ascii", "backslashreplace").decode("ascii")


@pytest.mark.parametrize(
    ("cmdlet", "token", "expected"),
    PARAM_CASES,
    ids=[_id(c, t) for c, t, _ in PARAM_CASES],
)
def test_canonical_param(cmdlet: str, token: str, expected: object) -> None:
    got = canonical_param(cmdlet, token)
    if expected is AMBIGUOUS:
        assert got is AMBIGUOUS
    else:
        assert got == expected


TAKES_VALUE_CASES: list[tuple[str, str, bool | None]] = [
    ("Remove-Item", "-Recurse", False),
    ("Remove-Item", "Recurse", False),
    ("Remove-Item", "-Force", False),
    ("Remove-Item", "-Path", True),
    ("Remove-Item", "-LiteralPath", True),
    ("Remove-Item", "-PSPath", True),  # aliases are accepted too
    ("Remove-Item", "-Confirm", False),
    ("Remove-Item", "-WhatIf", False),
    ("Remove-Item", "-Verbose", False),
    ("Remove-Item", "-ErrorAction", True),
    ("Remove-Item", "-OutVariable", True),
    ("rm", "-Recurse", False),
    ("Get-ChildItem", "-Directory", False),
    ("Get-ChildItem", "-Name", False),
    ("Get-ChildItem", "-Depth", True),
    ("Invoke-WebRequest", "-UseBasicParsing", False),
    ("Invoke-WebRequest", "-Uri", True),
    ("Set-Content", "-NoNewline", False),
    ("Out-File", "-Append", False),
    ("Out-File", "-FilePath", True),
    ("Start-Process", "-Wait", False),
    ("Start-Process", "-NoNewWindow", False),
    ("Start-Process", "-ArgumentList", True),
    ("Remove-Item", "-Rec", None),  # abbreviations are canonical_param's job
    ("Remove-Item", "-Nope", None),
    ("Remove-Item", "", None),
    ("Remove-Item", "-", None),
    ("Remove-Item", "x" * 500, None),
    ("not-a-cmdlet", "-Path", None),
    ("git", "-Path", None),
    ("Remove-Service", "-Name", None),
]


@pytest.mark.parametrize(
    ("cmdlet", "param", "expected"),
    TAKES_VALUE_CASES,
    ids=[_id(c, p) for c, p, _ in TAKES_VALUE_CASES],
)
def test_takes_value(cmdlet: str, param: str, expected: bool | None) -> None:
    assert takes_value(cmdlet, param) is expected


# (cmdlet, parameter, switch, position, wildcards, path role)
SPEC_CASES: list[tuple[str, str, bool, int | None, bool, str | None]] = [
    ("Get-ChildItem", "Path", False, 0, True, "read"),
    ("Get-ChildItem", "LiteralPath", False, None, False, "read"),
    ("Get-ChildItem", "Filter", False, 1, True, None),
    ("Get-ChildItem", "Recurse", True, None, False, None),
    ("Get-Content", "Path", False, 0, True, "read"),
    ("Get-Content", "TotalCount", False, None, False, None),
    ("Set-Content", "Path", False, 0, True, "write"),
    ("Set-Content", "Value", False, 1, False, None),
    ("Add-Content", "Path", False, 0, True, "write"),
    ("Out-File", "FilePath", False, 0, True, "write"),
    ("Out-File", "Append", True, None, False, None),
    ("Remove-Item", "Path", False, 0, True, "write"),
    ("Remove-Item", "LiteralPath", False, None, False, "write"),
    ("Remove-Item", "Recurse", True, None, False, None),
    ("Copy-Item", "Path", False, 0, True, "read"),
    ("Copy-Item", "Destination", False, 1, True, "write"),
    ("Move-Item", "Path", False, 0, True, "write"),
    ("Move-Item", "Destination", False, 1, True, "write"),
    ("Rename-Item", "NewName", False, 1, False, "write"),
    ("New-Item", "ItemType", False, None, False, None),
    ("New-Item", "Path", False, 0, True, "write"),
    ("Test-Path", "Path", False, 0, True, "read"),
    ("Select-String", "Path", False, 1, True, "read"),
    ("Select-String", "Pattern", False, 0, False, None),
    ("Export-Csv", "Path", False, 0, True, "write"),
    ("Import-Csv", "Path", False, 0, True, "read"),
    ("Expand-Archive", "DestinationPath", False, 1, False, "write"),
    ("Compress-Archive", "DestinationPath", False, 1, False, "write"),
    ("Invoke-WebRequest", "Uri", False, 0, False, None),
    ("Invoke-WebRequest", "OutFile", False, None, False, "write"),
    ("Invoke-WebRequest", "InFile", False, None, False, "read"),
    ("Invoke-RestMethod", "OutFile", False, None, False, "write"),
    ("Start-Process", "FilePath", False, 0, False, "read"),
    ("Start-Process", "RedirectStandardOutput", False, None, False, "write"),
    ("Start-Process", "Wait", True, None, False, None),
    ("Stop-Process", "Name", False, None, True, None),
    ("Stop-Service", "Name", False, 0, True, None),
    ("Set-ExecutionPolicy", "ExecutionPolicy", False, 0, False, None),
    ("Set-Location", "Path", False, 0, True, "read"),
    ("Unblock-File", "Path", False, 0, True, "write"),
    ("Set-MpPreference", "ExclusionPath", False, None, True, "unknown"),
    ("New-NetFirewallRule", "Program", False, None, True, "unknown"),
    ("Add-Type", "OutputAssembly", False, None, False, "write"),
    ("Invoke-Expression", "Command", False, 0, False, None),
    ("Set-Alias", "Value", False, 1, False, None),
]


@pytest.mark.parametrize(
    ("cmdlet", "param", "switch", "position", "wildcards", "role"),
    SPEC_CASES,
    ids=[_id(c, p) for c, p, *_ in SPEC_CASES],
)
def test_param_metadata(
    cmdlet: str, param: str, switch: bool, position: int | None, wildcards: bool, role: str | None
) -> None:
    spec = CMDLETS[cmdlet.lower()]
    p = spec.param(param)
    assert p is not None
    assert (p.switch, p.position, p.wildcards, p.path) == (switch, position, wildcards, role)


def _words(text: str) -> list[str]:
    return text.split()


REQUIRED_CMDLETS = _words("""
Get-ChildItem Get-Content Set-Content Add-Content Clear-Content Out-File Tee-Object Get-Item
Get-ItemProperty Set-ItemProperty New-ItemProperty Remove-ItemProperty Clear-ItemProperty New-Item
Remove-Item Copy-Item Move-Item Rename-Item Test-Path Resolve-Path Select-String Import-Csv
Export-Csv Import-Clixml Export-Clixml Get-FileHash Get-Acl Set-Acl Expand-Archive Compress-Archive
Invoke-WebRequest Invoke-RestMethod Start-BitsTransfer Send-MailMessage Test-NetConnection
Resolve-DnsName Start-Process Invoke-Expression Invoke-Command Enter-PSSession New-PSSession
Add-Type New-Object Import-Module Set-ExecutionPolicy Register-ScheduledTask
Unregister-ScheduledTask New-ScheduledTaskAction Set-Service New-Service Stop-Service Stop-Process
Set-MpPreference Add-MpPreference New-NetFirewallRule Set-NetFirewallProfile Enable-PSRemoting
Set-Alias New-Alias Set-Variable Set-Location Push-Location Write-Output Write-Host ForEach-Object
Where-Object Select-Object Sort-Object Measure-Object Invoke-CimMethod Invoke-WmiMethod
Get-CimInstance Get-WmiObject Unblock-File Set-Clipboard Out-Null Out-String
""")


@pytest.mark.parametrize("name", REQUIRED_CMDLETS)
def test_required_cmdlets_are_modelled(name: str) -> None:
    spec = cmdlet_spec(name)
    assert spec is not None
    assert spec.name == name
    assert canonical_command(name.lower()) == name
    assert any(p.group == "common" for p in spec.params)  # -Verbose & co. apply


def test_remove_service_is_known_by_name_only() -> None:
    # not in Windows PowerShell 5.1 (cannot be checked on this machine): recognised, no table
    assert canonical_command("remove-service") == "Remove-Service"
    assert "remove-service" not in CMDLETS
    assert cmdlet_spec("Remove-Service") is None
    assert canonical_param("Remove-Service", "-Name") is None


def test_ps7_divergent_names_are_aliases_here() -> None:
    assert set(pa.NAMES_DIFFERENT_IN_PS7) == {"curl", "wget", "sc"}
    assert all(n in ALIASES for n in pa.NAMES_DIFFERENT_IN_PS7)


def test_nocommon_function_rejects_common_parameters() -> None:
    assert CMDLETS["clear-host"].kind == "function"
    assert canonical_param("cls", "-Verbose") is None
    assert canonical_param("Get-ChildItem", "-Verbose") == "-Verbose"


def test_positional_and_conflict_helpers() -> None:
    cp = CMDLETS["copy-item"]
    assert [p.name for p in cp.positional()][:2] == ["Path", "Destination"]
    assert not cp.position_conflict
    reg = CMDLETS["register-scheduledtask"]
    assert reg.position_conflict  # -User / -Password have a different position per parameter set
    p = reg.param("User")
    assert p is not None
    assert p.position_conflict
    assert p.position == min(p.positions)


def test_remaining_arguments_flag() -> None:
    obj = CMDLETS["write-host"].param("Object")
    assert obj is not None
    assert obj.rest
    assert not CMDLETS["remove-item"].param("Path").rest  # type: ignore[union-attr]


def test_dynamic_provider_parameters_are_listed() -> None:
    d = CMDLETS["get-childitem"].param("File")
    assert d is not None
    assert d.dynamic
    t = CMDLETS["set-itemproperty"].param("Type")  # Registry provider
    assert t is not None
    assert t.dynamic


def test_dynamic_winner_is_not_trusted() -> None:
    """``-Wa`` on Get-Content would bind the Wait provider parameter in a FileSystem path but a
    common parameter elsewhere: with several candidates a dynamic winner is AMBIGUOUS."""
    assert canonical_param("Get-Content", "-Wai") == "-Wait"  # unique prefix: only Wait
    assert canonical_param("Get-ChildItem", "-Hid") == "-Hidden"
    # Get-Content -W: Wait (dynamic) vs the common Warning* and WhatIf-less names -> not trusted
    assert canonical_param("Get-Content", "-W") is AMBIGUOUS


def test_param_lookup_is_exact_only() -> None:
    spec = CMDLETS["remove-item"]
    assert spec.param("-recurse") is spec.param("Recurse")
    assert spec.param("rec") is None
    assert spec.param("") is None
    assert spec.param("cf") is spec.param("Confirm")


def test_sentinel_and_blank_rows() -> None:
    assert repr(AMBIGUOUS) == "AMBIGUOUS"
    assert AMBIGUOUS is canonical_param("Remove-Item", "-F")
    assert pa._parse_alias_rows("\n\nrm Remove-Item\n  \n") == {"rm": "Remove-Item"}
    assert pa._parse_common("\n") == ()


def test_is_cmdlet_shaped() -> None:
    assert pa.is_cmdlet_shaped("Get-SmbShare")
    assert pa.is_cmdlet_shaped("Remove-AppPackage")
    assert not pa.is_cmdlet_shaped("git")
    assert not pa.is_cmdlet_shaped("a-b-c")
    assert not pa.is_cmdlet_shaped("")
    assert not pa.is_cmdlet_shaped("Get-" + "x" * 200)


# ---------------------------------------------------------------------------------------------
# Never raises
# ---------------------------------------------------------------------------------------------

_ANY_TEXT = st.text(alphabet=st.characters(min_codepoint=0, blacklist_categories=()), max_size=60)


@settings(max_examples=400, deadline=None)
@given(_ANY_TEXT, _ANY_TEXT)
def test_never_raises_on_arbitrary_text(a: str, b: str) -> None:
    r = canonical_command(a)
    assert r is None or isinstance(r, str)
    c = canonical_param(a, b)
    assert c is None or c is AMBIGUOUS or isinstance(c, str)
    assert takes_value(a, b) in (True, False, None)
    cmdlet_spec(a)
    pa.is_cmdlet_shaped(a)
    canonical_param("Remove-Item", b)
    canonical_param("rm", a)
    takes_value("rm", b)


@settings(max_examples=200, deadline=None)
@given(st.sampled_from(sorted(CMDLETS)), _ANY_TEXT)
def test_never_raises_with_known_cmdlet(name: str, token: str) -> None:
    c = canonical_param(name, token)
    assert c is None or c is AMBIGUOUS or isinstance(c, str)
    takes_value(name, token)


def test_edge_inputs_are_total() -> None:
    big = "x" * 1_000_000
    for s in [
        "",
        "\x00",
        "\ud800",
        "\udfff",
        "a\ud800b",
        "-\ud800",
        big,
        "-" + big,
        "\x00" * 100_000,
    ]:
        assert canonical_command(s) in (None, s)
        assert canonical_param("Remove-Item", s) is None
        assert canonical_param(s, "-Recurse") is None
        assert takes_value(s, s) is None
        assert takes_value("Remove-Item", s) is None
    assert canonical_command("rm\ud800") is None
    assert canonical_command("C:\\a\ud800\\b.exe") == "C:\\a\ud800\\b.exe"
    # non-str input (a caller bug) is also answered, not raised
    assert canonical_command(None) is None  # type: ignore[arg-type]
    assert canonical_param(None, "-r") is None  # type: ignore[arg-type]
    assert canonical_param("rm", 3) is None  # type: ignore[arg-type]
    assert takes_value("rm", None) is None  # type: ignore[arg-type]
    assert takes_value(None, "-r") is None  # type: ignore[arg-type]
    assert not pa.is_cmdlet_shaped(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------------------------
# Structural invariants
# ---------------------------------------------------------------------------------------------


def test_alias_keys_are_lowercase_ascii_and_unique_to_one_target() -> None:
    for key, target in ALIASES.items():
        assert key == key.lower()
        assert key.isascii()
        assert key
        assert " " not in key
        assert " " not in target
    assert set(pa.CORE_ALIASES) | set(pa.AUTOLOAD_ALIASES) == set(ALIASES)


def test_every_alias_target_is_known() -> None:
    for alias, target in ALIASES.items():
        known = (
            target.lower() in CMDLETS
            or target.lower() in UNMODELED
            or target in pa.EXTERNAL_TARGETS
        )
        assert known, f"{alias} -> {target} is neither modelled, unmodelled nor external"
        assert canonical_command(alias) == target
        assert canonical_command(target) == target


def test_every_alias_target_has_canonical_spelling() -> None:
    for target in set(ALIASES.values()):
        if target in pa.EXTERNAL_TARGETS:
            continue
        spec = CMDLETS.get(target.lower())
        if spec is not None:
            assert spec.name == target
        else:
            assert UNMODELED[target.lower()] == target


def test_unmodeled_and_cmdlets_are_disjoint() -> None:
    assert not set(UNMODELED) & set(CMDLETS)
    for key, name in UNMODELED.items():
        assert key == key.lower()
        assert name.lower() == key
    for key, spec in CMDLETS.items():
        assert key == spec.name.lower()


def test_important_aliases_are_not_missing() -> None:
    # an alias that hides a destructive / network / execution cmdlet must be in the table
    for name in [
        "rm",
        "del",
        "erase",
        "rd",
        "rmdir",
        "ri",
        "kill",
        "iex",
        "icm",
        "iwr",
        "irm",
        "curl",
        "wget",
        "saps",
        "start",
        "sc",
        "spps",
        "spsv",
        "swmi",
        "iwmi",
        "rwmi",
    ]:
        assert name in ALIASES


def test_no_duplicate_parameter_names_or_colliding_aliases() -> None:
    for spec in CMDLETS.values():
        names = [p.name.lower() for p in spec.params]
        assert len(names) == len(set(names)), f"duplicate parameter in {spec.name}"
        aliases: dict[str, str] = {}
        for p in spec.params:
            for a in p.aliases:
                low = a.lower()
                owner = aliases.setdefault(low, p.name)
                assert owner == p.name, f"{spec.name}: alias {a} of {owner} and {p.name}"
                if low in names:
                    assert low == p.name.lower(), f"{spec.name}: alias {a} is also a parameter"


def test_parameter_rows_are_consistent() -> None:
    for spec in CMDLETS.values():
        for p in spec.params:
            assert p.name
            assert p.name.isascii()
            assert re.fullmatch(r"[A-Za-z0-9_]+", p.name), (spec.name, p.name)
            for a in p.aliases:
                assert re.fullmatch(r"[A-Za-z0-9_]+", a), (spec.name, a)
            assert (p.position is None) == (not p.positions)
            if p.positions:
                assert p.position == min(p.positions)
                assert all(i >= 0 for i in p.positions)
            if p.switch:
                assert p.path is None
                assert not p.wildcards
            assert p.group in ("declared", "common", "sp", "tx", "pg")
            assert p.path in (None, "read", "write", "unknown")


def test_common_parameters_on_every_advanced_command() -> None:
    common = {p.name for p in pa.COMMON_PARAMETERS if p.group == "common"}
    assert common == {
        "Verbose",
        "Debug",
        "ErrorAction",
        "WarningAction",
        "InformationAction",
        "ErrorVariable",
        "WarningVariable",
        "InformationVariable",
        "OutVariable",
        "OutBuffer",
        "PipelineVariable",
    }
    for spec in CMDLETS.values():
        have = {p.name for p in spec.params}
        if spec.name == "Clear-Host":
            assert not common & have
            continue
        assert common <= have, spec.name
        for alias in ("ea", "vb", "db", "wa", "infa", "ev", "wv", "iv", "ov", "ob", "pv"):
            assert isinstance(canonical_param(spec.name, "-" + alias), str)
        has_sp = {"WhatIf", "Confirm"} <= have
        assert ("WhatIf" in have) == ("Confirm" in have)
        if has_sp:
            assert canonical_param(spec.name, "-wi") == "-WhatIf"
            assert canonical_param(spec.name, "-cf") == "-Confirm"


def test_destructive_cmdlets_support_whatif() -> None:
    for name in ["Remove-Item", "Move-Item", "Set-Content", "Stop-Process", "Stop-Service"]:
        assert CMDLETS[name.lower()].param("WhatIf") is not None


def _naive_resolve(spec: pa.CmdletSpec, token: str) -> object:
    """An independent, brute-force statement of the resolution rule."""
    t = token.lower()
    cands = {
        p.name: p
        for p in spec.params
        if p.name.lower().startswith(t) or any(a.lower().startswith(t) for a in p.aliases)
    }
    exact = next((p for p in spec.params if p.name.lower() == t), None)
    if exact is None:
        exact = next((p for p in spec.params if t in (a.lower() for a in p.aliases)), None)
    if exact is not None:
        return AMBIGUOUS if exact.dynamic and len(cands) > 1 else exact.name
    if not cands:
        return None
    if len(cands) == 1:
        return next(iter(cands))
    declared = [p for p in cands.values() if p.group == "declared"]
    if len(declared) == 1 and not declared[0].dynamic:
        return declared[0].name
    return AMBIGUOUS


def _all_prefixes(spec: pa.CmdletSpec) -> set[str]:
    out: set[str] = set()
    for p in spec.params:
        for key in (p.name, *p.aliases):
            out.update(key[:i] for i in range(1, len(key) + 1))
            out.add(key + "x")
    return out


def test_prefix_resolution_matches_brute_force_over_the_whole_table() -> None:
    checked = 0
    for spec in CMDLETS.values():
        for token in sorted(_all_prefixes(spec)):
            want = _naive_resolve(spec, token)
            for variant in (token, token.upper(), "-" + token):
                got = canonical_param(spec.name, variant)
                if want is AMBIGUOUS:
                    assert got is AMBIGUOUS, (spec.name, variant)
                elif want is None:
                    assert got is None, (spec.name, variant)
                else:
                    assert got == "-" + str(want), (spec.name, variant)
                checked += 1
    assert checked > 20_000


def test_unique_prefix_claims_hold() -> None:
    """Whenever a prefix resolves to a parameter, no OTHER parameter has an exact name or alias of
    that prefix, and every other candidate is a non-declared (common) one."""
    for spec in CMDLETS.values():
        for token in _all_prefixes(spec):
            got = canonical_param(spec.name, token)
            if not isinstance(got, str):
                continue
            winner = spec.param(got)
            assert winner is not None
            exact = spec.param(token)
            if exact is not None:
                assert exact is winner
                continue
            others = [
                p
                for p in spec.params
                if p is not winner
                and (
                    p.name.lower().startswith(token.lower())
                    or any(a.lower().startswith(token.lower()) for a in p.aliases)
                )
            ]
            assert all(p.group != "declared" for p in others), (spec.name, token)
            assert winner.name.lower().startswith(token.lower()) or any(
                a.lower().startswith(token.lower()) for a in winner.aliases
            )


def test_the_resolver_never_prefers_an_ambiguous_dynamic_parameter() -> None:
    for spec in CMDLETS.values():
        for token in _all_prefixes(spec):
            got = canonical_param(spec.name, token)
            if not isinstance(got, str):
                continue
            winner = spec.param(got)
            assert winner is not None
            if winner.dynamic:
                cands = [
                    p
                    for p in spec.params
                    if p.name.lower().startswith(token.lower())
                    or any(a.lower().startswith(token.lower()) for a in p.aliases)
                ]
                assert cands == [winner]


# ---------------------------------------------------------------------------------------------
# Data parsing is strict
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    ["Rm remove-item", "rm", "rm a b", "rm Remove-Item extra", "a  b"],
    ids=["uppercase-alias", "one-field", "three-fields", "four-fields", "double-space"],
)
def test_alias_rows_reject_malformed_lines(bad: str) -> None:
    with pytest.raises(ValueError, match="bad alias row"):
        pa._parse_alias_rows(bad)


def test_alias_rows_reject_duplicates() -> None:
    with pytest.raises(ValueError, match="bad alias row"):
        pa._parse_alias_rows("rm Remove-Item\nrm Remove-Item")


def test_cmdlet_rows_reject_bad_tokens_and_duplicates() -> None:
    with pytest.raises(ValueError, match="invalid literal"):
        pa._parse_cmdlets("Foo-Bar\n  Path pos=x")
    with pytest.raises(ValueError, match="bad parameter token"):
        pa._parse_cmdlets("Foo-Bar\n  Path bogus")
    with pytest.raises(ValueError, match="bad cmdlet header"):
        pa._parse_cmdlets("Foo-Bar flag\n  Path")
    with pytest.raises(ValueError, match="bad cmdlet header"):
        pa._parse_cmdlets("Foo-Bar\n  Path\nfoo-bar\n  Path")


def test_cmdlet_rows_parse_every_token_kind() -> None:
    specs = pa._parse_cmdlets(
        "Foo-Bar sp tx\n  Path a=p,pp pos=0,2 wild rest read dyn\n    \n"
        "  Dest write\n  Anything unknown\n  Sw switch\n    wild\nBaz nocommon function\n  X\n"
    )
    foo = specs["foo-bar"]
    path = foo.param("Path")
    assert path is not None
    assert (path.aliases, path.positions, path.wildcards, path.rest, path.path, path.dynamic) == (
        ("p", "pp"),
        (0, 2),
        True,
        True,
        "read",
        True,
    )
    dest = foo.param("Dest")
    assert dest is not None
    assert dest.path == "write"
    anything = foo.param("Anything")
    assert anything is not None
    assert anything.path == "unknown"
    sw = foo.param("Sw")
    assert sw is not None
    assert sw.switch
    assert sw.wildcards  # the continuation line was joined to the row
    assert foo.param("WhatIf") is not None
    assert foo.param("UseTransaction") is not None
    baz = specs["baz"]
    assert baz.kind == "function"
    assert [p.name for p in baz.params] == ["X"]


# ---------------------------------------------------------------------------------------------
# Consistency with the real Windows PowerShell 5.1 of this machine
# ---------------------------------------------------------------------------------------------

# FIXED script: it only calls Get-Alias / Get-Command and reads .Parameters (and asks
# CommandInfo.ResolveParameter, a pure metadata lookup). Its inputs are two files written by the
# test from the tables themselves; nothing else reaches PowerShell.
_PS_SCRIPT = r"""
param([string]$NamesFile, [string]$AliasFile, [string]$OutFile)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ctxs = @(
  $null, ($env:SystemDrive + '\'), 'HKCU:\Software', 'Cert:\CurrentUser\My',
  'Env:\', 'Function:\', 'Variable:\', 'Alias:\'
)
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("V`t" + $PSVersionTable.PSVersion.ToString() + "`t" + $PSVersionTable.PSEdition)
foreach ($a in (Get-Alias)) { $lines.Add("A`t" + $a.Name + "`t" + $a.Definition) }
foreach ($n in (Get-Content -LiteralPath $AliasFile -Encoding UTF8)) {
  $esc = [System.Management.Automation.WildcardPattern]::Escape($n)
  $a = Get-Command $esc -CommandType Alias -ErrorAction SilentlyContinue | Select-Object -First 1
  $d = ''
  if ($a) { $d = $a.Definition }
  $lines.Add("D`t" + $n + "`t" + $d)
}
foreach ($n in (Get-Content -LiteralPath $NamesFile -Encoding UTF8)) {
  $first = Get-Command $n -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $first) { $lines.Add("E`t" + $n + "`t"); continue }
  $lines.Add("E`t" + $n + "`t" + $first.Name)
  $seen = @{}
  $vi = 0
  foreach ($c in $ctxs) {
    try {
      if ($null -eq $c) { $cmd = Get-Command $n -ErrorAction Stop | Select-Object -First 1 }
      else { $cmd = Get-Command $n -ArgumentList $c -ErrorAction Stop | Select-Object -First 1 }
    } catch { continue }
    $sig = ($cmd.Parameters.Keys | Sort-Object) -join ','
    if ($seen.ContainsKey($sig)) { continue }
    $seen[$sig] = 1
    $vi++
    $cmp = [System.StringComparer]::OrdinalIgnoreCase
    $toks = New-Object 'System.Collections.Generic.HashSet[string]' $cmp
    foreach ($p in $cmd.Parameters.Values) {
      $pos = @()
      foreach ($kv in $p.ParameterSets.GetEnumerator()) {
        if ($kv.Value.Position -ne [int]::MinValue) { $pos += [int]$kv.Value.Position }
      }
      $pos = (@($pos | Sort-Object -Unique) -join ',')
      $al = (@($p.Aliases) -join ',')
      $sw = [int][bool]$p.SwitchParameter
      $dy = [int][bool]$p.IsDynamic
      $lines.Add("P`t$n`t$vi`t" + $p.Name + "`t" + $al + "`t" + $sw + "`t" + $dy + "`t" + $pos)
      foreach ($key in (@($p.Name) + @($p.Aliases))) {
        for ($i = 1; $i -le $key.Length; $i++) { [void]$toks.Add($key.Substring(0, $i)) }
        [void]$toks.Add($key + 'x')
      }
    }
    foreach ($t in $toks) {
      try { $r = $cmd.ResolveParameter($t).Name }
      catch {
        $m = $_.Exception.Message
        if ($m -like '*ambiguous*') { $r = '#AMBIGUOUS' }
        elseif ($m -like '*cannot be found*') { $r = '#NOTFOUND' }
        else { $r = '#ERR ' + $m }
      }
      $lines.Add("R`t$n`t$vi`t$t`t$r")
    }
  }
}
[System.IO.File]::WriteAllLines($OutFile, $lines, (New-Object System.Text.UTF8Encoding($false)))
"""

_SAFE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9.\-_?%]{0,80}|[%?]")


class Real:
    """The parsed output of the fixed script."""

    def __init__(self, text: str) -> None:
        self.version = ""
        self.edition = ""
        self.aliases: dict[str, str] = {}
        self.alias_defs: dict[str, str] = {}
        self.names: dict[str, str] = {}
        self.params: dict[str, dict[int, dict[str, tuple[set[str], bool, bool, set[int]]]]] = {}
        self.resolve: dict[str, dict[int, dict[str, str]]] = {}
        for line in text.splitlines():
            f = line.split("\t")
            kind = f[0]
            if kind == "V":
                self.version, self.edition = f[1], f[2]
            elif kind == "A":
                self.aliases[f[1].lower()] = f[2]
            elif kind == "D":
                self.alias_defs[f[1]] = f[2]
            elif kind == "E":
                self.names[f[1]] = f[2]
            elif kind == "P":
                _, n, v, name, aliases, sw, dyn, pos = f
                self.params.setdefault(n, {}).setdefault(int(v), {})[name] = (
                    {a.lower() for a in aliases.split(",") if a},
                    sw == "1",
                    dyn == "1",
                    {int(i) for i in pos.split(",") if i},
                )
            elif kind == "R":
                _, n, v, tok, res = f
                self.resolve.setdefault(n, {}).setdefault(int(v), {})[tok] = res


@pytest.fixture(scope="module")
def real(tmp_path_factory: pytest.TempPathFactory) -> Real:
    exe = shutil.which("powershell.exe")
    if sys.platform != "win32" or exe is None:
        pytest.skip("needs Windows PowerShell (powershell.exe)")
    tmp = tmp_path_factory.mktemp("psreal")
    names = sorted({spec.name for spec in CMDLETS.values()})
    names += sorted(n for n in UNMODELED.values() if n != "Remove-Service")
    alias_names = sorted(ALIASES)
    for n in [*names, *alias_names]:
        assert _SAFE_NAME.fullmatch(n), n  # only table-derived names reach PowerShell
    names_file = tmp / "names.txt"
    alias_file = tmp / "aliases.txt"
    out_file = tmp / "out.tsv"
    script = tmp / "check.ps1"
    names_file.write_text("\n".join(names), encoding="utf-8")
    alias_file.write_text("\n".join(alias_names), encoding="utf-8")
    script.write_text(_PS_SCRIPT, encoding="utf-8-sig")
    proc = subprocess.run(
        [
            exe,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-NamesFile",
            str(names_file),
            "-AliasFile",
            str(alias_file),
            "-OutFile",
            str(out_file),
        ],
        capture_output=True,
        timeout=900,
        check=False,
        cwd=str(tmp),
        env=scrubbed_env(),
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")[:2000]
    return Real(out_file.read_text(encoding="utf-8"))


@pytest.mark.windows
def test_real_powershell_is_windows_powershell_5_1(real: Real) -> None:
    assert real.edition == "Desktop"
    assert real.version.startswith("5.1."), real.version


@pytest.mark.windows
def test_every_real_builtin_alias_is_in_the_table(real: Real) -> None:
    missing = sorted(a for a in real.aliases if a not in ALIASES)
    assert not missing, f"aliases of this machine missing from psaliases.ALIASES: {missing}"


@pytest.mark.windows
def test_every_core_alias_has_the_real_definition(real: Real) -> None:
    wrong = {
        a: (target, real.aliases.get(a))
        for a, target in pa.CORE_ALIASES.items()
        if (real.aliases.get(a) or "").lower() != target.lower()
    }
    assert not wrong, wrong


@pytest.mark.windows
def test_every_autoload_alias_exists_with_the_real_definition(real: Real) -> None:
    wrong = {
        a: (target, real.alias_defs.get(a))
        for a, target in ALIASES.items()
        if (real.alias_defs.get(a) or "").lower() != target.lower()
    }
    assert not wrong, wrong


@pytest.mark.windows
def test_command_names_have_the_real_canonical_spelling(real: Real) -> None:
    for n, real_name in real.names.items():
        assert real_name, f"{n} is not a command of this machine"
        assert real_name == n, f"canonical spelling of {n} is {real_name}"
    targets = {t for t in ALIASES.values() if t not in pa.EXTERNAL_TARGETS}
    for t in targets:
        assert real.names.get(t) == t, t


@pytest.mark.windows
def test_every_parameter_matches_the_real_metadata(real: Real) -> None:
    problems: list[str] = []
    for spec in CMDLETS.values():
        variants = real.params.get(spec.name)
        if not variants:  # a plain function without parameters (Clear-Host)
            if spec.params:
                problems.append(f"{spec.name}: table has parameters, the real command none")
            continue
        merged: dict[str, tuple[set[str], bool, set[int]]] = {}
        for params in variants.values():
            for name, (aliases, sw, _dyn, pos) in params.items():
                cur = merged.setdefault(name, (aliases, sw, set()))
                cur[2].update(pos)
                if cur[0] != aliases or cur[1] != sw:
                    problems.append(f"{spec.name}: -{name} differs between provider contexts")
        table = {p.name: p for p in spec.params}
        for name in merged.keys() - table.keys():
            problems.append(f"{spec.name}: real parameter -{name} missing from the table")
        for name, p in table.items():
            if name not in merged:
                problems.append(f"{spec.name}: table parameter -{name} does not exist")
                continue
            aliases, sw, pos = merged[name]
            if {a.lower() for a in p.aliases} != aliases:
                problems.append(f"{spec.name}: -{name} aliases {p.aliases} vs real {aliases}")
            if p.switch != sw:
                problems.append(f"{spec.name}: -{name} switch {p.switch} vs real {sw}")
            if set(p.positions) != pos:
                problems.append(f"{spec.name}: -{name} positions {p.positions} vs real {pos}")
        real_dyn = {n for v in variants.values() for n, (_, _, d, _) in v.items() if d}
        for name, p in table.items():
            if p.dynamic != (name in real_dyn):
                problems.append(f"{spec.name}: -{name} dynamic flag {p.dynamic} vs real")
    assert not problems, "\n".join(problems[:40])


@pytest.mark.windows
def test_every_abbreviation_resolves_like_the_real_binder(real: Real) -> None:
    """Brute force: every prefix of every real parameter name and alias, plus a non-matching
    extension of each, resolved by ``CommandInfo.ResolveParameter`` in every provider context.

    Safety contract: a concrete answer of the table is what PowerShell binds (or PowerShell fails
    the command); None means PowerShell finds nothing; AMBIGUOUS is exact for commands without
    provider parameters and merely conservative for the others."""
    problems: list[str] = []
    checked = 0
    for name, variants in real.resolve.items():
        if name.lower() not in CMDLETS:
            continue  # known but unmodelled commands have no table to compare
        has_dyn = any(d for v in real.params[name].values() for (_, _, d, _) in v.values())
        tokens = {t for res in variants.values() for t in res}
        for token in sorted(tokens):
            results = {v: res[token] for v, res in variants.items() if token in res}
            for r in results.values():
                if r.startswith("#ERR"):
                    problems.append(f"{name} -{token}: unexpected PowerShell error {r}")
            got = canonical_param(name, "-" + token)
            checked += 1
            if got is AMBIGUOUS:
                if not has_dyn and set(results.values()) != {"#AMBIGUOUS"}:
                    problems.append(f"{name} -{token}: AMBIGUOUS but real {results}")
            elif got is None:
                if set(results.values()) != {"#NOTFOUND"}:
                    problems.append(f"{name} -{token}: None but real {results}")
            else:
                assert isinstance(got, str)
                bad = {r for r in results.values() if r not in (got[1:], "#AMBIGUOUS", "#NOTFOUND")}
                if bad or got[1:] not in results.values():
                    problems.append(f"{name} -{token}: table {got} vs real {results}")
    assert checked > 20_000, checked
    assert not problems, f"{len(problems)} problems:\n" + "\n".join(problems[:40])


@pytest.mark.windows
def test_data_blocks_match_the_generator_output() -> None:
    """The checked-in tables equal what scripts/gen_ps_aliases.py produces on this machine."""
    exe = shutil.which("powershell.exe")
    if sys.platform != "win32" or exe is None:
        pytest.skip("needs Windows PowerShell (powershell.exe)")
    script = Path(REPO_ROOT) / "scripts" / "gen_ps_aliases.py"
    proc = subprocess.run(
        [sys.executable, "-I", str(script)],
        capture_output=True,
        timeout=900,
        check=False,
        env=scrubbed_env(),
    )
    out = proc.stdout.decode("utf-8", "replace")
    assert proc.returncode == 0, out[-3000:] + proc.stderr.decode("utf-8", "replace")[-1000:]
    assert "tables match the machine" in out
