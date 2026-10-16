"""Regenerate the PowerShell alias / cmdlet tables of ``boundkeep.normalize.psaliases``.

Run on Windows with Windows PowerShell 5.1 (``powershell.exe``)::

    python scripts/gen_ps_aliases.py                 # dump the real data, print a diff against the
                                                     # checked-in tables (exit 1 when they differ)
    python scripts/gen_ps_aliases.py --write         # rewrite the generated blocks in psaliases.py
    python scripts/gen_ps_aliases.py --dump out.json # also save the raw dump (for review)

The checked-in module stays STATIC data: importing ``psaliases`` never starts PowerShell. This script
is the only place that does, and only with a FIXED script plus a list of cmdlet names that come from
the constants below (validated against a strict pattern); no untrusted text is ever passed.

What comes from the machine: the alias table (``Get-Alias`` in a clean ``-NoProfile`` session, plus
the aliases that the listed built-in modules export and auto-load), each cmdlet's parameters (name,
aliases, switch-ness, positions, wildcard support, dynamic provider parameters seen in the
FileSystem / Registry / Certificate / Environment / Function / Alias / Variable providers).
What is hand-written (``PATH_ROLES``): which parameter names a path and how it is accessed. The
hand-written part is the policy-relevant judgement; everything else is reproducible.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

MODULE_FILE = ROOT / "src" / "boundkeep" / "normalize" / "psaliases.py"
BLOCKS = (
    "_CORE_ALIAS_DATA",
    "_AUTOLOAD_ALIAS_DATA",
    "_UNMODELED_DATA",
    "_COMMON_DATA",
    "_CMDLET_DATA",
)

# ---------------------------------------------------------------------------------------------
# What to model
# ---------------------------------------------------------------------------------------------


def _words(text: str) -> list[str]:
    return text.split()


#: The cmdlets the task asked for (docs/m1b-design.md section 4 plus the M1b brief).
REQUIRED = _words(
    """
Get-ChildItem Get-Content Set-Content Add-Content Clear-Content Out-File Tee-Object Get-Item
Get-ItemProperty Set-ItemProperty New-ItemProperty Remove-ItemProperty Clear-ItemProperty New-Item
Remove-Item Copy-Item Move-Item Rename-Item Test-Path Resolve-Path Select-String Import-Csv
Export-Csv Import-Clixml Export-Clixml Get-FileHash Get-Acl Set-Acl Expand-Archive
Compress-Archive Invoke-WebRequest Invoke-RestMethod Start-BitsTransfer Send-MailMessage
Test-NetConnection Resolve-DnsName Start-Process Invoke-Expression Invoke-Command Enter-PSSession
New-PSSession Add-Type New-Object Import-Module Set-ExecutionPolicy Register-ScheduledTask
Unregister-ScheduledTask New-ScheduledTaskAction Set-Service New-Service Stop-Service Stop-Process Set-MpPreference Add-MpPreference New-NetFirewallRule
Set-NetFirewallProfile Enable-PSRemoting Set-Alias New-Alias Set-Variable Set-Location
Push-Location Write-Output Write-Host ForEach-Object Where-Object Select-Object Sort-Object
Measure-Object Invoke-CimMethod Invoke-WmiMethod Get-CimInstance Get-WmiObject Unblock-File
Set-Clipboard Out-Null Out-String
"""
)

#: Judged security-relevant (or so common in pipelines that "unknown cmdlet" would be noise):
#: more of the file system / process / service / task / firewall / Defender / remoting / WMI areas.
EXTRA = _words(
    """
Set-Item Clear-Item Invoke-Item Convert-Path Copy-ItemProperty Move-ItemProperty
Rename-ItemProperty New-PSDrive Remove-PSDrive Start-Job Export-Alias Import-Alias Start-Service
Restart-Service Get-Service Get-Process Start-Sleep Get-Location Pop-Location Get-Command
Get-Help Get-Member Get-Variable Get-Alias Get-Date Get-History Group-Object Compare-Object
Format-Table Format-List Format-Wide Format-Custom Out-Host ConvertTo-Json ConvertFrom-Json
Join-Path Split-Path Remove-CimInstance Set-CimInstance New-CimInstance Remove-WmiObject
Set-WmiInstance Get-Clipboard Install-Module Set-ScheduledTask Start-ScheduledTask
New-ScheduledTaskTrigger New-ScheduledTaskPrincipal Remove-NetFirewallRule Set-NetFirewallRule
Disable-NetFirewallRule Remove-MpPreference New-LocalUser Remove-LocalUser Add-LocalGroupMember
Restart-Computer Stop-Computer Disable-PSRemoting Start-Transcript Clear-EventLog Remove-EventLog
Format-Volume Clear-Disk Remove-Partition Write-Error Write-Warning Write-Verbose Write-Debug
Write-Information Invoke-History Get-Unique New-Variable Remove-Variable Clear-Variable
Import-PSSession Export-PSSession Remove-PSSession Disable-WindowsOptionalFeature
"""
)

#: Functions that are alias targets (``md`` -> ``mkdir``, ``man`` -> ``help``, ``clear`` ->
#: ``Clear-Host``): modelled like cmdlets, flagged ``function``.
FUNCTIONS = ["mkdir", "help", "Clear-Host"]

#: Providers whose dynamic parameters are merged into the table (a parameter that exists in ANY of
#: them is listed, flagged ``dyn``): the union can only be MORE ambiguous than a real invocation.
CONTEXTS = [
    "{SystemDrive}\\",
    "HKCU:\\Software",
    "Cert:\\CurrentUser\\My",
    "Env:\\",
    "Function:\\",
    "Variable:\\",
    "Alias:\\",
]

#: Modules whose exported aliases are auto-loaded on first use: they are real aliases of the machine
#: even though a fresh ``Get-Alias`` does not list them. Microsoft.PowerShell.Utility is already in
#: the core list; the others are the ones with cmdlets that touch the system or the network.
ALIAS_MODULES = [
    "Microsoft.PowerShell.Management",
    "CimCmdlets",
    "NetTCPIP",
    "PowerShellGet",
    "Microsoft.PowerShell.LocalAccounts",
    "SmbShare",
]

# ---------------------------------------------------------------------------------------------
# Hand-written knowledge: which parameter names a path, and how it is accessed
# ---------------------------------------------------------------------------------------------
# "read": the cmdlet reads / enumerates / executes it; "write": creates, changes or deletes it;
# "unknown": may be either, or a path-or-URL / path-or-name value. Values that are only a LEAF NAME
# relative to another path (New-Item -Name, Rename-Item -NewName) are marked "write": the consumer
# must join them to the directory. Anything not listed is not a path.

_RW = {"Path": "read", "LiteralPath": "read"}
_WW = {"Path": "write", "LiteralPath": "write"}
_MP = {
    "ExclusionPath": "unknown",
    "ExclusionProcess": "unknown",
    "ControlledFolderAccessAllowedApplications": "unknown",
    "ControlledFolderAccessProtectedFolders": "unknown",
    "SharedSignaturesPath": "unknown",
    "SignatureBlobFileSharesSources": "unknown",
    "SignatureDefinitionUpdateFileSharesSources": "unknown",
}

PATH_ROLES: dict[str, dict[str, str]] = {
    "Get-ChildItem": _RW,
    "Get-Content": _RW,
    "Set-Content": _WW,
    "Add-Content": _WW,
    "Clear-Content": _WW,
    "Out-File": {"FilePath": "write", "LiteralPath": "write"},
    "Tee-Object": {"FilePath": "write", "LiteralPath": "write"},
    "Get-Item": _RW,
    "Get-ItemProperty": _RW,
    "Set-ItemProperty": _WW,
    "New-ItemProperty": _WW,
    "Remove-ItemProperty": _WW,
    "Clear-ItemProperty": _WW,
    "Copy-ItemProperty": {**_WW, "Destination": "write"},
    "Move-ItemProperty": {**_WW, "Destination": "write"},
    "Rename-ItemProperty": _WW,
    "New-Item": {"Path": "write", "Name": "write"},
    "Remove-Item": _WW,
    "Copy-Item": {"Path": "read", "LiteralPath": "read", "Destination": "write"},
    "Move-Item": {"Path": "write", "LiteralPath": "write", "Destination": "write"},
    "Rename-Item": {"Path": "write", "LiteralPath": "write", "NewName": "write"},
    "Set-Item": _WW,
    "Clear-Item": _WW,
    "Invoke-Item": _RW,
    "Test-Path": _RW,
    "Resolve-Path": _RW,
    "Convert-Path": _RW,
    "Join-Path": {"Path": "read", "ChildPath": "read"},
    "Split-Path": _RW,
    "Select-String": {"Path": "read", "LiteralPath": "read"},
    "Import-Csv": _RW,
    "Export-Csv": _WW,
    "Import-Clixml": _RW,
    "Export-Clixml": _WW,
    "Get-FileHash": _RW,
    "Get-Acl": _RW,
    "Set-Acl": _WW,
    "Expand-Archive": {"Path": "read", "LiteralPath": "read", "DestinationPath": "write"},
    "Compress-Archive": {"Path": "read", "LiteralPath": "read", "DestinationPath": "write"},
    "Invoke-WebRequest": {"OutFile": "write", "InFile": "read"},
    "Invoke-RestMethod": {"OutFile": "write", "InFile": "read"},
    "Start-BitsTransfer": {"Source": "unknown", "Destination": "unknown"},
    "Send-MailMessage": {"Attachments": "read"},
    "Start-Process": {
        "FilePath": "read",
        "WorkingDirectory": "read",
        "RedirectStandardOutput": "write",
        "RedirectStandardError": "write",
        "RedirectStandardInput": "read",
    },
    "Start-Job": {"FilePath": "read", "DefinitionPath": "read", "LiteralPath": "read"},
    "Invoke-Command": {"FilePath": "read"},
    "Add-Type": {
        "Path": "read",
        "LiteralPath": "read",
        "OutputAssembly": "write",
        "ReferencedAssemblies": "read",
    },
    "Import-Module": {"Name": "read", "Assembly": "unknown"},
    "Import-PSSession": {"Module": "unknown"},
    "Export-PSSession": {"OutputModule": "write"},
    "New-ScheduledTaskAction": {"Execute": "read", "WorkingDirectory": "read"},
    "New-Service": {"BinaryPathName": "unknown"},
    "Set-Service": {},
    "Set-MpPreference": _MP,
    "Add-MpPreference": _MP,
    "Remove-MpPreference": _MP,
    "New-NetFirewallRule": {"Program": "unknown"},
    "Set-NetFirewallRule": {"Program": "unknown"},
    "Set-NetFirewallProfile": {"LogFileName": "write"},
    "Format-Volume": {"Path": "write"},
    "Clear-Disk": {"Path": "write"},
    "Disable-WindowsOptionalFeature": {
        "LogPath": "write",
        "Path": "unknown",
        "ScratchDirectory": "write",
        "WindowsDirectory": "unknown",
    },
    "Unblock-File": _WW,
    "Set-Clipboard": {"Path": "read", "LiteralPath": "read"},
    "Set-Location": _RW,
    "Push-Location": _RW,
    "Export-Alias": {"Path": "write", "LiteralPath": "write"},
    "Import-Alias": {"Path": "read", "LiteralPath": "read"},
    "New-PSDrive": {"Root": "unknown"},
    "Start-Transcript": {"Path": "write", "LiteralPath": "write", "OutputDirectory": "write"},
    "mkdir": {"Path": "write", "Name": "write"},
}

# Parameters whose names look like a path but are not one (reviewed): silences the generator's
# "unannotated path-like parameter" report.
NOT_PATHS: set[tuple[str, str]] = {
    ("Get-ChildItem", "Filter"),
    ("Get-ChildItem", "Include"),
    ("Get-ChildItem", "Exclude"),
    ("Get-ChildItem", "Name"),
    ("Select-String", "Pattern"),
    ("Test-NetConnection", "ConstrainSourceAddress"),
    ("Add-Type", "AssemblyName"),
    ("Import-Module", "CimResourceUri"),
    ("Register-ScheduledTask", "TaskPath"),
    ("Unregister-ScheduledTask", "TaskPath"),
    ("Set-ScheduledTask", "TaskPath"),
    ("Start-ScheduledTask", "TaskPath"),
    ("Invoke-WmiMethod", "Path"),
    ("Remove-WmiObject", "Path"),
    ("Set-WmiInstance", "Path"),
    ("Invoke-CimMethod", "ResourceUri"),
    ("Get-CimInstance", "ResourceUri"),
    ("Remove-CimInstance", "ResourceUri"),
    ("Set-CimInstance", "ResourceUri"),
    ("New-CimInstance", "ResourceUri"),
    ("Get-Command", "Module"),
    ("Get-Help", "Path"),
    ("help", "Path"),
    ("Remove-NetFirewallRule", "PolicyStoreSource"),
    ("Disable-NetFirewallRule", "PolicyStoreSource"),
    ("Remove-EventLog", "Source"),
    ("Format-Volume", "FileSystem"),
    ("Format-Volume", "FileSystemLabel"),
    ("Format-Volume", "NewFileSystemLabel"),
    ("Export-PSSession", "Module"),
}

_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{1,80}$")
_PATHLIKE_RE = re.compile(
    r"(Path|File|Dir|Folder|Destination|Root|Source|Script|Assembly|Program|Execute|Module|Attachment)",
    re.IGNORECASE,
)
COMMON = _words(
    "Verbose Debug ErrorAction WarningAction InformationAction ErrorVariable WarningVariable "
    "InformationVariable OutVariable OutBuffer PipelineVariable"
)

# ---------------------------------------------------------------------------------------------
# The fixed PowerShell script
# ---------------------------------------------------------------------------------------------

PS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$names = @(__NAMES__)
$modules = @(__MODULES__)
$ctxs = @(__CONTEXTS__)

function Get-Pos($p) {
  $r = @()
  foreach ($kv in $p.ParameterSets.GetEnumerator()) {
    $pos = $kv.Value.Position
    if ($pos -ne [int]::MinValue) { $r += [int]$pos }
  }
  ,@($r | Sort-Object -Unique)
}

function Get-Rest($p) {
  foreach ($kv in $p.ParameterSets.GetEnumerator()) {
    if ($kv.Value.ValueFromRemainingArguments) { return $true }
  }
  return $false
}

$out = [ordered]@{}
$out.os = [Environment]::OSVersion.VersionString
$out.ps = $PSVersionTable.PSVersion.ToString()
$out.build = $PSVersionTable.BuildVersion.ToString()
$out.edition = [string]$PSVersionTable.PSEdition

$al = @()
foreach ($a in (Get-Alias)) {
  $t = $a.Definition
  $c = Get-Command $t -ErrorAction SilentlyContinue | Select-Object -First 1
  $ct = if ($c) { $c.Name } else { $t }
  $al += [ordered]@{ name = $a.Name; def = $t; target = $ct; kind = if ($c) { [string]$c.CommandType } else { 'Missing' } }
}
$out.aliases = @($al)

$mal = @()
foreach ($m in $modules) {
  # the NAMES come from the manifests (AliasesToExport), the definitions from the real resolution
  # (Get-Command autoloads the module); the loaded module's own export list is added too
  $aliasNames = @{}
  foreach ($mod in @(Get-Module -ListAvailable $m)) {
    foreach ($k in $mod.ExportedAliases.Keys) { $aliasNames[$k] = 1 }
  }
  Import-Module $m -ErrorAction Stop
  foreach ($k in (Get-Module $m).ExportedAliases.Keys) { $aliasNames[$k] = 1 }
  foreach ($n in ($aliasNames.Keys | Sort-Object)) {
    $esc = [System.Management.Automation.WildcardPattern]::Escape($n)
    $a = Get-Command $esc -CommandType Alias -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $a) { continue }
    $t = $a.Definition
    $c = Get-Command $t -ErrorAction SilentlyContinue | Select-Object -First 1
    $ct = if ($c) { $c.Name } else { $t }
    $mal += [ordered]@{ name = $a.Name; def = $t; target = $ct; module = $m }
  }
}
$out.module_aliases = @($mal)

$cm = @()
foreach ($n in $names) {
  $first = Get-Command $n -ErrorAction Stop | Select-Object -First 1
  $params = [ordered]@{}
  $variants = @($null) + @($ctxs)
  foreach ($c in $variants) {
    try {
      if ($null -eq $c) { $cmd = Get-Command $n -ErrorAction Stop | Select-Object -First 1 }
      else { $cmd = Get-Command $n -ArgumentList $c -ErrorAction Stop | Select-Object -First 1 }
    } catch { continue }
    foreach ($p in $cmd.Parameters.Values) {
      if (-not $params.Contains($p.Name)) {
        $wild = $false
        foreach ($at in $p.Attributes) { if ($at -is [System.Management.Automation.SupportsWildcardsAttribute]) { $wild = $true } }
        if (-not $wild -and $cmd.ImplementingType) {
          # compiled cmdlets: ParameterMetadata hides the attribute, the property / field has it
          $flags = [System.Reflection.BindingFlags]'Public,Instance,FlattenHierarchy'
          foreach ($m in $cmd.ImplementingType.GetMember($p.Name, $flags)) {
            foreach ($at in $m.GetCustomAttributes($true)) { if ($at -is [System.Management.Automation.SupportsWildcardsAttribute]) { $wild = $true } }
          }
        }
        $params[$p.Name] = [ordered]@{
          name = $p.Name
          aliases = @($p.Aliases)
          switch = [bool]$p.SwitchParameter
          dyn = [bool]$p.IsDynamic
          type = $p.ParameterType.Name
          wild = $wild
          pos = (Get-Pos $p)
          rest = [bool](Get-Rest $p)
        }
      }
    }
  }
  $cm += [ordered]@{ name = $first.Name; type = [string]$first.CommandType; params = @($params.Values) }
}
$out.cmdlets = @($cm)
$out | ConvertTo-Json -Depth 8 -Compress
"""


def _ps_list(items: list[str]) -> str:
    for item in items:
        if not (_NAME_RE.match(item) or re.fullmatch(r"[A-Za-z][A-Za-z0-9.]{1,80}", item)):
            raise ValueError(f"refusing to embed {item!r} in the PowerShell script")
    return ",".join("'" + i + "'" for i in items)


def _ps_ctx_list() -> str:
    return ",".join(
        "('" + c.replace("{SystemDrive}", "' + $env:SystemDrive + '") + "')" for c in CONTEXTS
    )


def build_script(names: list[str]) -> str:
    return (
        PS_SCRIPT.replace("__NAMES__", _ps_list(names))
        .replace("__MODULES__", _ps_list(ALIAS_MODULES))
        .replace("__CONTEXTS__", _ps_ctx_list())
    )


def run_dump(names: list[str] | None = None, *, timeout: float = 600) -> dict[str, object]:
    """Run the fixed script in a clean ``powershell.exe`` and return the parsed JSON."""
    names = names if names is not None else all_names()
    script = build_script(names)
    with tempfile.TemporaryDirectory() as tmp:
        ps1 = Path(tmp) / "dump.ps1"
        ps1.write_text(script, encoding="utf-8-sig")
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(ps1),
            ],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace")[:2000])
    result: dict[str, object] = json.loads(proc.stdout.decode("utf-8-sig"))
    return result


def all_names() -> list[str]:
    seen: dict[str, None] = {}
    for n in [*REQUIRED, *EXTRA, *FUNCTIONS]:
        seen.setdefault(n, None)
    return list(seen)


# ---------------------------------------------------------------------------------------------
# Dump -> table text
# ---------------------------------------------------------------------------------------------


def alias_lines(dump: dict[str, object]) -> tuple[list[str], list[str]]:
    core = sorted(
        (a["name"].lower(), a["target"])
        for a in dump["aliases"]  # type: ignore[index, attr-defined]
    )
    core_names = {n for n, _ in core}
    auto = sorted(
        {
            (a["name"].lower(), a["target"])  # type: ignore[index, attr-defined]
            for a in dump["module_aliases"]  # type: ignore[attr-defined]
            if a["name"].lower() not in core_names  # type: ignore[index, attr-defined]
        }
    )
    return [f"{n} {t}" for n, t in core], [f"{n} {t}" for n, t in auto]


# Windows PowerShell 5.1 does not expose wildcard support in its metadata for compiled cmdlets
# (``SupportsWildcards`` is absent from ParameterMetadata AND from the implementing property), so
# the flag is a hand-written, deliberately CONSERVATIVE rule: a value MAY be a wildcard pattern.
#   * every parameter with a path role is ``wild`` except the literal-only names below;
#   * ``-Include`` / ``-Exclude`` / ``-Filter`` and the process / service / item-property ``-Name``
#     parameters of ``WILD_NAMES`` are ``wild``;
#   * whatever the machine does report (functions) is kept.
LITERAL_PARAMS = {
    "LiteralPath",
    "OutFile",
    "InFile",
    "DestinationPath",
    "OutputAssembly",
    "RedirectStandardOutput",
    "RedirectStandardError",
    "RedirectStandardInput",
    "WorkingDirectory",
    "Execute",
    "BinaryPathName",
    "Root",
    "NewName",  # a leaf name, not a pattern
    "Name",  # New-Item / mkdir -Name (process and service names are in WILD_NAMES)
}
LITERAL_PAIRS = {
    ("Start-Process", "FilePath"),
    ("Start-Job", "FilePath"),
    ("Invoke-Command", "FilePath"),
}
WILD_ANY = {"Include", "Exclude", "Filter"}
WILD_NAMES = {
    "Stop-Process": {"Name"},
    "Get-Process": {"Name"},
    "Stop-Service": {"Name", "DisplayName"},
    "Start-Service": {"Name", "DisplayName"},
    "Restart-Service": {"Name", "DisplayName"},
    "Get-Service": {"Name", "DisplayName"},
    "Get-ItemProperty": {"Name"},
    "Remove-ItemProperty": {"Name"},
    "Clear-ItemProperty": {"Name"},
    "Import-Module": {"Name"},
    "Get-Alias": {"Name"},
    "Get-Variable": {"Name"},
    "Remove-Variable": {"Name"},
    "Clear-Variable": {"Name"},
    "Get-Command": {"Name"},
    "Get-Help": {"Name"},
    "Select-Object": {"Property", "ExcludeProperty", "ExpandProperty"},
    "Format-Table": {"Property"},
    "Format-List": {"Property"},
    "Format-Wide": {"Property"},
    "Format-Custom": {"Property"},
}


def _wildcards(cmdlet: str, p: dict[str, object], role: str | None) -> bool:
    name = str(p["name"])
    if p["switch"]:
        return False
    if p["wild"] or name in WILD_NAMES.get(cmdlet, ()) or name in WILD_ANY:
        return True
    if role is None:
        return False
    return name not in LITERAL_PARAMS and (cmdlet, name) not in LITERAL_PAIRS


def cmdlet_text(dump: dict[str, object], notes: list[str]) -> str:
    out: list[str] = []
    for c in dump["cmdlets"]:  # type: ignore[attr-defined]
        name: str = c["name"]
        roles = PATH_ROLES.get(name, {})
        params = {p["name"]: p for p in c["params"]}
        header = [name]
        if c["type"] == "Function":
            header.append("function")
        if "WhatIf" in params and "Confirm" in params:
            header.append("sp")
        if "UseTransaction" in params:
            header.append("tx")
        out.append(" ".join(header))
        skip = set(COMMON) | {"UseTransaction"}
        if "sp" in header:
            skip |= {"WhatIf", "Confirm"}
        missing = [p for p in COMMON if p not in params]
        if len(missing) == len(COMMON):
            header.append("nocommon")  # a plain function: no common parameters at all
            out[-1] = " ".join(header)
            skip = set()
        elif missing:
            notes.append(f"{name}: missing some common parameters {missing}")
        declared = [p for n, p in params.items() if n not in skip]
        # SupportsPaging adds these three; PowerShell ranks them below the command's own parameters
        paging = {"IncludeTotalCount", "Skip", "First"} <= params.keys()
        for role_name in roles:
            if role_name not in params and roles is not _MP:  # _MP is shared, not every one exists
                notes.append(f"{name}: PATH_ROLES names unknown parameter {role_name}")
        declared.sort(key=lambda p: (min(p["pos"]) if p["pos"] else 99, p["name"].lower()))
        for p in declared:
            toks = [p["name"]]
            if p["aliases"]:
                toks.append("a=" + ",".join(p["aliases"]))
            if p["switch"]:
                toks.append("switch")
            if p["pos"]:
                toks.append("pos=" + ",".join(str(i) for i in p["pos"]))
                if len(p["pos"]) > 1:
                    notes.append(f"{name}: -{p['name']} has positions {p['pos']} in different sets")
            role = None if p["switch"] else roles.get(p["name"])
            if _wildcards(name, p, role):
                toks.append("wild")
            if p["rest"]:
                toks.append("rest")
            if role:
                toks.append(role)
            elif (
                _PATHLIKE_RE.search(p["name"].replace("Description", ""))
                and p["type"] in ("String", "String[]", "FileInfo", "Uri", "Uri[]", "Object")
                and (name, p["name"]) not in NOT_PATHS
            ):
                notes.append(f"REVIEW {name} -{p['name']} ({p['type']}) looks like a path: no role")
            if p["dyn"]:
                toks.append("dyn")
            if paging and p["name"] in ("IncludeTotalCount", "Skip", "First"):
                toks.append("pg")
            out.extend(wrap_tokens(toks, "  ", "    "))
    return "\n".join(out)


def wrap_tokens(toks: list[str], first: str, rest: str, width: int = 96) -> list[str]:
    """Greedy wrap of ``toks`` into lines of at most ``width`` columns (continuations indented)."""
    lines: list[str] = []
    cur = first
    for tok in toks:
        sep = "" if cur in (first, rest) else " "
        if len(cur) + len(sep) + len(tok) > width and cur not in (first, rest):
            lines.append(cur)
            cur = rest
            sep = ""
        cur += sep + tok
    lines.append(cur)
    return lines


_GROUPS = {
    **dict.fromkeys(COMMON, "common"),
    "WhatIf": "sp",
    "Confirm": "sp",
    "UseTransaction": "tx",
}


def common_text(dump: dict[str, object], notes: list[str]) -> str:
    """The parameters every (advanced) command gets; verified to be identical everywhere."""
    cmdlets = {c["name"]: c for c in dump["cmdlets"]}  # type: ignore[attr-defined]
    base = {p["name"]: p for p in cmdlets["Remove-Item"]["params"]}
    out = []
    for name, group in _GROUPS.items():
        p = base[name]
        toks = [name]
        if p["aliases"]:
            toks.append("a=" + ",".join(p["aliases"]))
        if p["switch"]:
            toks.append("switch")
        toks.append(group)
        out.append(" ".join(toks))
    for cname, c in cmdlets.items():
        for p in c["params"]:
            ref = base.get(p["name"])
            if (
                p["name"] in _GROUPS
                and ref is not None
                and (p["aliases"], p["switch"]) != (ref["aliases"], ref["switch"])
            ):
                notes.append(f"{cname}: -{p['name']} differs from the shared definition")
    return "\n".join(out)


def render_blocks(dump: dict[str, object]) -> tuple[dict[str, str], list[str]]:
    notes: list[str] = []
    core, auto = alias_lines(dump)
    modeled = {c["name"].lower() for c in dump["cmdlets"]}  # type: ignore[attr-defined]
    targets = {line.split()[1] for line in [*core, *auto]}
    unmodeled = sorted(t for t in targets if t.lower() not in modeled)
    blocks = {
        "_CORE_ALIAS_DATA": "\n".join(core),
        "_AUTOLOAD_ALIAS_DATA": "\n".join(auto),
        "_UNMODELED_DATA": "\n".join(wrap_tokens(unmodeled, "", "")),
        "_COMMON_DATA": common_text(dump, notes),
        "_CMDLET_DATA": cmdlet_text(dump, notes),
    }
    return blocks, notes


def block_regex(name: str) -> re.Pattern[str]:
    return re.compile(rf'(^{name} = """\\?\n)(.*?)(\n"""$)', re.S | re.M)


def current_blocks(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for name in BLOCKS:
        m = block_regex(name).search(text)
        found[name] = m.group(2) if m else ""
    return found


def apply_blocks(text: str, blocks: dict[str, str]) -> str:
    for name, body in blocks.items():
        pat = block_regex(name)
        if not pat.search(text):
            raise SystemExit(f"{MODULE_FILE.name} has no {name} block")
        text = pat.sub(lambda m, body=body: m.group(1) + body + m.group(3), text, count=1)
    return text


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument(
        "--write", action="store_true", help="rewrite the generated blocks in psaliases.py"
    )
    ap.add_argument("--dump", metavar="FILE", help="save the raw JSON dump")
    args = ap.parse_args(argv)
    if sys.platform != "win32":
        print("needs Windows PowerShell 5.1 (powershell.exe)")
        return 2
    dump = run_dump()
    if args.dump:
        Path(args.dump).write_text(json.dumps(dump, indent=1), encoding="utf-8", newline="\n")
    print(f"# {dump['os']} / PowerShell {dump['ps']} ({dump['edition']}) build {dump['build']}")
    blocks, notes = render_blocks(dump)
    for n in notes:
        print("NOTE:", n)
    text = MODULE_FILE.read_text(encoding="utf-8")
    old = current_blocks(text)
    changed = False
    for name, new in blocks.items():
        if old.get(name, "") != new:
            changed = True
            diff = difflib.unified_diff(
                old.get(name, "").splitlines(),
                new.splitlines(),
                f"checked-in {name}",
                f"machine {name}",
                lineterm="",
            )
            print("\n".join(diff))
    if not changed:
        print("tables match the machine")
        return 0
    if args.write:
        with MODULE_FILE.open("w", encoding="utf-8", newline="\n") as fh:
            fh.write(apply_blocks(text, blocks))
        print(f"rewrote {MODULE_FILE}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
