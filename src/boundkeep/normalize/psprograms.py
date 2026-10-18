"""PowerShell knowledge: turn one parsed cmdlet / program call into facts rules match on.

``classify_ps(program, args, redirects=..., env=...)`` is what ``programs.classify`` calls for
``shell="powershell"``. ``program`` is the canonical cmdlet name (``pscmd`` already resolved aliases
and abbreviated parameters: ``rm -r -fo x`` arrives as ``Remove-Item -Recurse -Force x``) or the
name of an external program. ``args`` are the words after it in the shape ``pscmd`` produces:

* a PARAMETER is an unquoted word that starts with ``-`` (``-Recurse``); the value of a parameter
  that takes one is the NEXT word (``-Path:x`` was already split into ``-Path`` and ``x``);
* a VALUE that starts with ``-`` (a quoted string, a number, anything after ``--``) is marked
  ``quoted=True`` so it cannot be mistaken for a parameter;
* an element the parser could not read as a literal arrives as ``$(<its text>)`` with
  ``expands=True``: it is dynamic for every layer below;
* an array argument (``a,b``) arrives flattened into separate words (known approximation: the
  array's elements may bind to the wrong positional slot, which only ever over-lists paths).

Design rules (docs/m1b-design.md section 4, docs/m1-design.md bottom lines):

* Knowledge is DATA: one row per cmdlet in ``_row(...)`` calls (positional parameter order, the role
  of each path / URL parameter, switches, flags that change the verdict). The handlers only
  interpret the rows.
* Never raises (``classify_ps`` turns an internal error into ``known=False`` plus every risk tag).
* Never infers safety. Words are over-listed rather than dropped: a positional that no slot claims,
  or the value of a parameter we do not know, becomes an ``unknown`` path. A gray reason is added
  only where the meaning of the command itself is unknowable (code execution, link creation,
  alias redefinition, a provider path that is not a file, ...).
* Programs that are not cmdlets are delegated to the Bash-side tables (``programs.classify``).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace

from boundkeep.normalize import programs, psaliases
from boundkeep.normalize.model import Access, Redirect, RiskTag, Word
from boundkeep.normalize.programs import (
    _ALL_TAGS,
    CmdInfo,
    _Acc,
    _copy_into,
    _generic_arg,
    _is_dirlike,
    _join_child,
    _pathlike,
    derive_risk_tags,
)

__all__ = [
    "EXEC_CMDLETS",
    "NESTED_SHELLS",
    "STDIN_INTERPRETERS",
    "classify_ps",
    "dynamic_name",
    "exec_reasons_of",
    "is_cmdlet_name",
    "param_takes_value",
    "reads_stdin_as_code",
    "strip_module",
]

_MAX_WORDS = 20000  # classify_ps looks at no more arguments than this; the rest is gray

# ---------------------------------------------------------------------------------------------
# Cmdlet rows
# ---------------------------------------------------------------------------------------------
# Roles of a parameter's value:
#   r / w / u   a file path read / written / either      x    a value that is not a path
#   url         a host or URL (network)                  ru   a URL if it has "://", else read
# Kinds: roles (generic), transfer (Copy-Item / Move-Item), rename, newitem, alias, variable,
# importmodule, newobject, system.


@dataclass(frozen=True, slots=True)
class Cmdlet:
    """One row of the cmdlet table."""

    name: str  # canonical spelling
    positional: tuple[str, ...] = ()  # parameters bound by position, in order ("-Path", ...)
    roles: Mapping[str, str] = field(default_factory=dict)  # lower-case "-param" -> role
    switches: frozenset[str] = frozenset()  # lower-case "-param" that take no value
    scan: frozenset[str] = frozenset()  # parameters whose value is scanned for paths and URLs
    kind: str = "roles"
    network: bool = False  # always talks to the network
    pipe: bool = False  # the path may arrive from the pipeline: write to "whatever it carries"
    gray: tuple[str, ...] = ()  # gray reasons every call of this cmdlet gets
    runs_code: bool = False  # executes code or a program (EXEC_CMDLETS)
    config: bool = False  # changes the system, persistence or security settings


_CMDLETS: dict[str, Cmdlet] = {}


def _fs(text: str) -> frozenset[str]:
    """A frozenset of the whitespace-separated words of ``text`` (compact table rows)."""
    return frozenset(text.split())


def _params(text: str) -> list[str]:
    return ["-" + t for t in text.split()]


def _row(
    names: str,
    *,
    pos: str = "",
    r: str = "",
    w: str = "",
    u: str = "",
    x: str = "",
    url: str = "",
    ru: str = "",
    sw: str = "",
    scan: str = "",
    kind: str = "roles",
    net: bool = False,
    pipe: bool = False,
    gray: str = "",
    code: bool = False,
    config: bool = False,
) -> None:
    """Register the cmdlets of ``names`` (space separated) with one shared description."""
    roles: dict[str, str] = {}
    for role, text in (("r", r), ("w", w), ("u", u), ("x", x), ("url", url), ("ru", ru)):
        for p in _params(text):
            roles[p.lower()] = role
    for name in names.split():
        _CMDLETS[name.lower()] = Cmdlet(
            name=name,
            positional=tuple(_params(pos)),
            roles=roles,
            switches=frozenset(p.lower() for p in _params(sw)),
            scan=frozenset(p.lower() for p in _params(scan)),
            kind=kind,
            network=net,
            pipe=pipe,
            gray=tuple(gray.split()),
            runs_code=code,
            config=config,
        )


_PATH_R = "Path LiteralPath PSPath"
_FILTERS = "Filter Include Exclude"
_WRITE_X = _FILTERS + " Value Encoding Stream Credential Type PropertyType"

# --- read ---
_row(
    "Get-Content",
    pos="Path",
    r=_PATH_R,
    x=_FILTERS + " TotalCount Tail First Last Head Encoding Delimiter ReadCount Stream",
    sw="Force UseTransaction Wait Raw",
)
_row(
    "Get-ChildItem",
    pos="Path Filter",
    r=_PATH_R,
    x=_FILTERS + " Depth Attributes",
    sw="Recurse Force Name UseTransaction FollowSymlink Directory File Hidden ReadOnly System",
)
_row("Get-Item", pos="Path", r=_PATH_R, x=_FILTERS + " Stream", sw="Force UseTransaction")
_row(
    "Get-ItemProperty Get-ItemPropertyValue",
    pos="Path Name",
    r=_PATH_R,
    x=_FILTERS + " Name",
    sw="UseTransaction",
)
_row(
    "Test-Path",
    pos="Path",
    r=_PATH_R,
    x=_FILTERS + " PathType OlderThan NewerThan",
    sw="IsValid UseTransaction",
)
_row("Get-FileHash", pos="Path", r="Path LiteralPath", x="Algorithm InputStream")
_row(
    "Import-Csv",
    pos="Path Delimiter",
    r="Path LiteralPath",
    x="Delimiter Header Encoding",
    sw="UseCulture",
)
_row("Import-Clixml", pos="Path", r="Path LiteralPath", x="First Skip", sw="IncludeTotalCount")
_row(
    "Get-Acl",
    pos="Path",
    r=_PATH_R,
    x=_FILTERS,
    sw="Audit AllCentralAccessPolicies UseTransaction",
)
_row("Resolve-Path Convert-Path", pos="Path", r=_PATH_R, sw="Relative UseTransaction")
_row(
    "Select-String",
    pos="Pattern Path",
    r="Path LiteralPath",
    x="Pattern Include Exclude Encoding Context InputObject",
    sw="SimpleMatch CaseSensitive Quiet List NotMatch AllMatches",
)
_row("Get-AuthenticodeSignature", pos="FilePath", r="FilePath LiteralPath")
_row("Format-Hex", pos="Path", r="Path LiteralPath", x="Count Offset Encoding")
_row(
    "Set-Location Push-Location",
    pos="Path",
    r="Path LiteralPath",
    x="StackName",
    sw="PassThru UseTransaction",
)

# --- write ---
_row(
    "Set-Content Add-Content",
    pos="Path Value",
    w=_PATH_R,
    x=_WRITE_X + " AsByteStream",
    sw="PassThru Force UseTransaction NoNewline",
    pipe=True,
)
_row(
    "Clear-Content",
    pos="Path",
    w=_PATH_R,
    x=_FILTERS + " Stream",
    sw="Force UseTransaction",
    pipe=True,
)
_row(
    "Out-File",
    pos="FilePath Encoding",
    w="FilePath LiteralPath Path",
    x="Encoding Width InputObject",
    sw="Append Force NoClobber NoNewline",
)
_row(
    "Export-Csv",
    pos="Path Delimiter",
    w="Path LiteralPath",
    x="Delimiter Encoding InputObject",
    sw="Force NoClobber Append UseCulture NoTypeInformation",
)
_row(
    "Export-Clixml",
    pos="Path",
    w="Path LiteralPath",
    x="Depth Encoding InputObject",
    sw="Force NoClobber",
)
_row(
    "Export-Alias",
    pos="Path Name",
    w="Path LiteralPath",
    x="Name Scope As Value",
    sw="PassThru Append Force NoClobber",
)
_row("Export-Console", pos="Path", w="Path", sw="Force NoClobber")
_row("Tee-Object", pos="FilePath", w="FilePath LiteralPath", x="Variable InputObject", sw="Append")
_row(
    "Start-Transcript",
    pos="Path",
    w="Path LiteralPath OutputDirectory",
    sw="Append Force NoClobber IncludeInvocationHeader",
)
_row(
    "Remove-Item",
    pos="Path",
    w=_PATH_R,
    x=_FILTERS + " Stream Credential",
    sw="Recurse Force UseTransaction",
    pipe=True,
)
_row(
    "Clear-Item",
    pos="Path",
    w=_PATH_R,
    x=_FILTERS + " Value",
    sw="Force UseTransaction",
    pipe=True,
)
_row(
    "Set-Item",
    pos="Path Value",
    w=_PATH_R,
    x=_WRITE_X,
    sw="Force PassThru UseTransaction",
    pipe=True,
)
_row(
    "Set-ItemProperty New-ItemProperty Remove-ItemProperty",
    pos="Path Name Value",
    w=_PATH_R,
    x=_WRITE_X + " Name InputObject",
    sw="PassThru Force UseTransaction",
    pipe=True,
)
_row(
    "Rename-ItemProperty Copy-ItemProperty Move-ItemProperty Clear-ItemProperty",
    pos="Path Name NewName",
    w=_PATH_R + " Destination",
    x="Name NewName Credential",
    sw="PassThru Force UseTransaction",
    pipe=True,
    config=True,  # registry value moves / copies / renames: persistence and settings tampering
)
_row(
    "Set-Acl",
    pos="Path AclObject",
    w="Path LiteralPath",
    x="AclObject InputObject CentralAccessPolicy",
    sw="ClearCentralAccessPolicy Passthru UseTransaction",
    pipe=True,
)
_row("Unblock-File", pos="Path", w="Path LiteralPath", pipe=True)
_row(
    "Compress-Archive",
    pos="Path DestinationPath",
    r="Path LiteralPath",
    w="DestinationPath",
    x="CompressionLevel",
    sw="Update Force",
)
_row(
    "Expand-Archive",
    pos="Path DestinationPath",
    r="Path LiteralPath",
    w="DestinationPath",
    sw="Force",
    gray="archive-members-unknown",
)
_row(
    "Save-Help",
    pos="DestinationPath",
    w="DestinationPath",
    r="LiteralPath",
    x="Module UICulture",
    sw="UseDefaultCredentials Force",
    net=True,
)
_row(
    "Update-Help",
    pos="Module",
    r="SourcePath LiteralPath",
    x="Module UICulture",
    sw="Recurse UseDefaultCredentials Force",
    net=True,
)
_row("Save-Module Save-Script", pos="Name", w="Path LiteralPath", x="Name", sw="Force", net=True)

# --- transfer / rename / create ---
_row(
    "Copy-Item",
    pos="Path Destination",
    r=_PATH_R,
    w="Destination",
    x=_FILTERS + " Credential FromSession ToSession",
    sw="Container Force Recurse PassThru UseTransaction",
    kind="transfer",
    pipe=True,
)
_row(
    "Move-Item",
    pos="Path Destination",
    w=_PATH_R + " Destination",
    x=_FILTERS + " Credential",
    sw="Force PassThru UseTransaction",
    kind="transfer",
    pipe=True,
)
_row(
    "Rename-Item",
    pos="Path NewName",
    w=_PATH_R,
    x="NewName Credential",
    sw="Force PassThru UseTransaction",
    kind="rename",
    pipe=True,
)
_row(
    "New-Item",
    pos="Path",
    w="Path",
    x="Name ItemType Value Target Credential",
    sw="Force UseTransaction",
    kind="newitem",
)

# --- network ---
_WEB_X = (
    "Method Body Headers ContentType UserAgent Credential Certificate CertificateThumbprint "
    "TimeoutSec MaximumRedirection MaximumRetryCount RetryIntervalSec SessionVariable WebSession "
    "TransferEncoding Authentication Token SslProtocol ResponseHeadersVariable "
    "StatusCodeVariable Form CustomMethod ProxyCredential"
)
_WEB_SW = (
    "UseBasicParsing UseDefaultCredentials DisableKeepAlive ProxyUseDefaultCredentials PassThru "
    "SkipCertificateCheck SkipHttpErrorCheck AllowUnencryptedAuthentication NoProxy Resume "
    "SkipHeaderValidation PreserveAuthorizationOnRedirect AllowInsecureRedirect"
)
_row(
    "Invoke-WebRequest Invoke-RestMethod",
    pos="Uri",
    url="Uri Proxy",
    w="OutFile",
    r="InFile",
    x=_WEB_X,
    sw=_WEB_SW,
    net=True,
)
_row(
    "Start-BitsTransfer",
    pos="Source Destination",
    ru="Source",
    w="Destination",
    x="DisplayName Description Priority RetryInterval RetryTimeout Credential TransferType",
    sw="Asynchronous Dynamic CustomHeadersWriteOnly Suspended",
    net=True,
)
_row(
    "Send-MailMessage",
    pos="To Subject Body SmtpServer",
    url="SmtpServer",
    r="Attachments",
    x="To From Cc Bcc Subject Body Credential Port Priority Encoding",
    sw="BodyAsHtml UseSsl",
    net=True,
)
_row(
    "Test-NetConnection Test-Connection",
    pos="ComputerName CommonTCPPort",
    url="ComputerName TargetName Destination",
    x="Port CommonTCPPort InformationLevel Count Source",
    sw="TraceRoute DiagnoseRouting Quiet",
    net=True,
)
_row(
    "Resolve-DnsName",
    pos="Name Type",
    url="Name Server",
    x="Type",
    sw="DnsOnly CacheOnly NoHostsFile NoIdn NoRecursion QuickTimeout TcpOnly CheckCache "
    "DnssecOk DnssecCd LlmnrNetbiosOnly LlmnrFallback LlmnrOnly NetbiosFallback",
    net=True,
)
_row(
    "New-PSSession Enter-PSSession",
    pos="ComputerName",
    url="ComputerName ConnectionUri HostName",
    x="Credential Name Port UserName KeyFilePath Session ConfigurationName SessionOption",
    sw="EnableNetworkAccess RunAsAdministrator UseSSL AllowRedirection",
    net=True,
)
_row(
    "Install-Module Install-Script Install-Package Update-Module Find-Module Find-Script "
    "Find-Package Publish-Module Install-PackageProvider",
    pos="Name",
    x="Name Repository Scope Source Version RequiredVersion MinimumVersion MaximumVersion "
    "Credential Proxy ProxyCredential NuGetApiKey Path",
    sw="AllowClobber SkipPublisherCheck Force AllVersions IncludeDependencies "
    "AllowPrerelease ForceBootstrap",
    net=True,
)

# --- code execution ---
_row("Invoke-Expression", pos="Command", scan="Command", code=True)
_row(
    "Invoke-Command",
    pos="ScriptBlock",
    url="ComputerName ConnectionUri HostName",
    r="FilePath",
    x="ScriptBlock ArgumentList Credential Session ThrottleLimit Port ConfigurationName UserName",
    sw="UseSSL AsJob InDisconnectedSession HideComputerName NoNewScope AllowRedirection "
    "EnableNetworkAccess RunAsAdministrator",
    scan="ArgumentList",
    code=True,
)
_row(
    "Start-Process",
    pos="FilePath ArgumentList",
    r="FilePath WorkingDirectory RedirectStandardInput",
    w="RedirectStandardOutput RedirectStandardError",
    x="ArgumentList Verb Credential WindowStyle",
    sw="LoadUserProfile NoNewWindow PassThru Wait UseNewEnvironment",
    scan="ArgumentList",
    code=True,
)
_row("Invoke-Item", pos="Path", r="Path LiteralPath", x=_FILTERS, sw="UseTransaction", code=True)
_row(
    "Add-Type",
    pos="TypeDefinition",
    r="Path LiteralPath",
    w="OutputAssembly",
    x="TypeDefinition Name MemberDefinition Namespace Language ReferencedAssemblies AssemblyName",
    sw="PassThru IgnoreWarnings",
    code=True,
)
_row(
    "Invoke-WmiMethod",
    pos="Class Name ArgumentList",
    url="ComputerName",
    x="Class Name ArgumentList Namespace",
    sw="AsJob EnableAllPrivileges",
    code=True,
)
_row(
    "Invoke-CimMethod",
    pos="ClassName Arguments MethodName",
    url="ComputerName",
    x="ClassName Arguments MethodName Namespace Query",
    code=True,
)
_row(
    "Start-Job Start-ThreadJob",
    pos="ScriptBlock",
    r="FilePath WorkingDirectory",
    x="ScriptBlock ArgumentList Name Credential",
    code=True,
)
_row(
    "Register-ScheduledJob Register-ObjectEvent Register-EngineEvent Register-WmiEvent "
    "Register-CimIndicationEvent",
    pos="Name",
    x="Name Action Trigger",
    code=True,
    config=True,
)
_row(
    "Import-Module",
    pos="Name",
    r="Assembly",
    x="Name FullyQualifiedName Prefix Function Cmdlet Variable Alias Version",
    sw="Global Force PassThru AsCustomObject DisableNameChecking NoClobber",
    kind="importmodule",
)
_row(
    "New-Object",
    pos="TypeName ArgumentList",
    x="TypeName ArgumentList Property",
    sw="Strict",
    kind="newobject",
)

# --- state that changes what later words mean ---
_row(
    "Set-Alias New-Alias",
    pos="Name Value",
    x="Name Value Description Option Scope",
    sw="PassThru Force",
    kind="alias",
)
_row(
    "Import-Alias",
    pos="Path",
    r="Path LiteralPath",
    x="Scope",
    sw="PassThru Force",
    kind="alias",
)
_row(
    "Set-Variable New-Variable",
    pos="Name Value",
    x="Name Value Description Option Scope Visibility",
    sw="Force PassThru",
    kind="variable",
)

# --- system, persistence, security settings: tagged config_tamper and gray ---
_row(
    "Set-ExecutionPolicy Register-ScheduledTask Set-ScheduledTask Unregister-ScheduledTask "
    "Disable-ScheduledTask New-ScheduledTask New-ScheduledTaskAction New-ScheduledTaskTrigger "
    "New-ScheduledTaskPrincipal New-ScheduledTaskSettingsSet Set-Service New-Service "
    "Remove-Service Set-MpPreference Add-MpPreference Remove-MpPreference New-NetFirewallRule "
    "Set-NetFirewallRule Set-NetFirewallProfile Set-NetFirewallSetting Enable-NetFirewallRule "
    "Disable-NetFirewallRule Remove-NetFirewallRule Enable-PSRemoting Disable-PSRemoting "
    "Enable-WindowsOptionalFeature Disable-WindowsOptionalFeature Set-LocalUser New-LocalUser "
    "Add-LocalGroupMember Enable-LocalUser Add-Computer Restart-Computer Stop-Computer "
    "Clear-EventLog Limit-EventLog Remove-EventLog Format-Volume Clear-Disk Initialize-Disk "
    "Remove-Partition Set-DnsClientServerAddress Enable-WSManCredSSP "
    "Set-WmiInstance New-CimInstance Set-CimInstance Remove-CimInstance Remove-WmiObject "
    "Set-WSManInstance Remove-LocalUser Disable-LocalUser Remove-LocalGroupMember "
    "Enable-ScheduledTask Unregister-ScheduledJob Set-ScheduledJob Register-PSSessionConfiguration "
    "Set-PSSessionConfiguration Enable-PSSessionConfiguration Disable-PSSessionConfiguration "
    "Unregister-PSSessionConfiguration Add-WindowsCapability Remove-WindowsCapability "
    "Install-WindowsFeature Uninstall-WindowsFeature Remove-Computer Rename-Computer "
    "Disable-NetAdapter Set-NetIPAddress New-NetRoute Remove-NetRoute Remove-VM Stop-VM "
    "New-SmbShare Remove-SmbShare Grant-SmbShareAccess Clear-RecycleBin Set-Date Set-TimeZone "
    "Uninstall-Module Set-PSRepository Register-PSRepository Unregister-PSRepository "
    "Set-NetFirewallAddressFilter Set-NetFirewallPortFilter Set-NetFirewallApplicationFilter",
    kind="system",
    config=True,
)

# Build runners: they run the project's own build scripts (arbitrary code), like make / msbuild.
_row(
    "Invoke-Build Invoke-psake Invoke-Pester Invoke-MSBuild",
    pos="Task",
    x="Task File Script Configuration Parameters",
    code=True,
)

# Cmdlets that read or compute and touch no file: their words are values, not paths.
_NOPATH = _fs(
    "write-output write-host write-verbose write-warning write-error write-debug "
    "write-information out-null out-string out-host select-object where-object "
    "foreach-object sort-object group-object measure-object format-list format-table "
    "format-wide get-date get-location get-process get-service get-command get-help "
    "get-alias get-member get-host get-history get-variable get-random get-culture "
    "convertto-json convertfrom-json convertto-csv convertfrom-csv convertto-html "
    "start-sleep join-path split-path stop-process stop-service start-service clear-host "
    "new-guid compare-object pop-location read-host get-computerinfo get-module "
    "get-psdrive get-unique out-printer"
)

EXEC_CMDLETS: Mapping[str, str] = {k: c.name for k, c in _CMDLETS.items() if c.runs_code}
"""Lower-case name -> canonical name of the cmdlets that run code, a program or a file."""

NESTED_SHELLS = frozenset(
    {
        "powershell", "pwsh", "cmd", "wsl", "bash", "sh", "zsh", "dash", "ksh", "fish",
        "wscript", "cscript", "mshta", "rundll32", "regsvr32", "conhost",
    }
)  # fmt: skip
"""External programs that run another shell, a script host or arbitrary code."""

_SYSTEM_EXTERNALS = frozenset(
    {
        "reg", "regedit", "regedit32", "schtasks", "sc", "netsh", "wmic", "bcdedit", "diskpart",
        "vssadmin", "wevtutil", "net", "net1", "takeown", "icacls", "cacls", "cipher", "setx",
        "format", "fsutil", "mountvol", "shutdown", "dism", "chkdsk", "secedit", "auditpol",
    }
)  # fmt: skip
# Windows command-line tools that take ``/switch`` words (``/add``, ``/MIR``, ``/w:C:\x``): the
# switches are FLAGS (lower-cased: they are case-insensitive), never paths. ``subcommand`` is the
# first plain word for the tools that have verbs (``net user``, ``vssadmin delete``).
_SUBCOMMAND_TOOLS = frozenset({"net", "net1", "vssadmin", "wevtutil", "reg", "sc", "netsh", "wmic"})
_COPY_TOOLS = frozenset({"robocopy", "xcopy"})
_SWITCH_RE = re.compile(r"/[A-Za-z0-9?][A-Za-z0-9_?+\-]*(?::.*)?\Z", re.DOTALL)
# switches that delete files in the destination (/mir /purge) or in the source (/move /mov)
_ROBOCOPY_PURGES = frozenset({"/mir", "/purge", "/move", "/mov"})
_ROBOCOPY_NAME_LISTS = frozenset({"/xf", "/xd", "/if"})  # followed by names, not paths to act on
_ROBOCOPY_LOGS = frozenset({"/log", "/log+", "/unilog", "/unilog+"})
# Build tools run the project's own build scripts and plugins: arbitrary code by design.
_BUILD_TOOLS = frozenset(
    {
        "msbuild", "nmake", "make", "gmake", "mingw32-make", "gradle", "mvn", "ant", "cmake",
        "ninja", "bazel", "devenv", "dotnet",
    }
)  # fmt: skip
_DOTNET_INFO_FLAGS = frozenset(
    {"--version", "--info", "--help", "-h", "-?", "/?", "--list-sdks", "--list-runtimes"}
)
_SCRIPT_EXTS = (
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
    ".py", ".pyw", ".pl", ".rb", ".sh", ".msi", ".msc", ".lnk", ".cpl", ".scr", ".com", ".jar",
    ".reg",
)  # fmt: skip
STDIN_INTERPRETERS = frozenset(
    {
        "powershell", "pwsh", "cmd", "sh", "bash", "zsh", "dash", "ksh", "python", "python3",
        "node", "perl", "ruby", "php", "wsl",
    }
)  # fmt: skip
_VERBS = _fs(
    "get set new remove add clear copy move rename invoke start stop test out write read import "
    "export select where sort measure format convert convertto convertfrom enable disable "
    "register unregister install uninstall update find save publish send receive enter exit push "
    "pop resolve join split compare group show hide lock unlock grant revoke block unblock wait "
    "watch debug trace limit restart resume suspend disconnect connect mount dismount expand "
    "compress checkpoint restore backup edit open close submit undo redo reset repair optimize "
    "initialize merge step sync use confirm complete assert protect unprotect switch request "
    "approve deny ping build deploy foreach tee resize search skip unpublish"
)
_COMMON_SWITCHES = frozenset({"-verbose", "-debug", "-whatif", "-confirm", "-usetransaction"})
_COMMON_VALUES = frozenset(
    {
        "-erroraction", "-warningaction", "-informationaction", "-errorvariable",
        "-warningvariable", "-informationvariable", "-outvariable", "-outbuffer",
        "-pipelinevariable", "-progressaction",
    }
)  # fmt: skip
_PATH_PARAM_WORDS = ("path", "file", "dir", "folder")
_PATH_PARAM_NAMES = frozenset(
    {"-destination", "-source", "-target", "-output", "-outfile", "-infile", "-in", "-out"}
)
_KNOWN_PROVIDERS = frozenset(
    {"hklm", "hkcu", "hkcr", "hku", "hkcc", "env", "cert", "wsman", "alias", "function", "variable"}
)
_PROVIDER_WORDS = frozenset(
    {"registry", "certificate", "environment", "alias", "function", "variable", "wsman"}
)
_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
_DYNAMIC_NAME_CHARS = frozenset("$`*?[]{}\x00\n\r;|&<>")
_PATHISH = frozenset({"-path", "-literalpath", "-pspath", "-filepath"})
_LINK_FREE = frozenset({"file", "directory", "item"})


# ---------------------------------------------------------------------------------------------
# Small helpers (names, parameters, paths)
# ---------------------------------------------------------------------------------------------


def strip_module(program: str) -> str:
    """``Microsoft.PowerShell.Management\\Remove-Item`` -> ``Remove-Item``.

    Only the built-in modules ``psaliases`` knows are resolved (a user module could shadow the
    cmdlet): any other qualified name stays a path. Aliases are NOT resolved here.
    """
    if "\\" not in program or "/" in program:
        return program
    try:
        canon = psaliases.canonical_command(program)
    except Exception:  # noqa: BLE001 - a lookup that raises must degrade to "not resolved"
        return program
    if isinstance(canon, str) and canon and "\\" not in canon and "/" not in canon:
        return canon
    return program


def _base(program: str) -> str:
    """Lower-case file name of a program, directory and ``.exe`` removed."""
    cut = max(program.rfind("/"), program.rfind("\\"))
    name = (program[cut + 1 :] if cut >= 0 else program).strip().lower()
    if name.endswith(".exe") and len(name) > 4:
        name = name[:-4]
    return name


def _has_sep(text: str) -> bool:
    return "/" in text or "\\" in text


def dynamic_name(program: str) -> bool:
    """Is a command name unknowable from its text (empty, ``$x``, wildcards, shell syntax)?

    A path-qualified name may contain parentheses (``C:\\Program Files (x86)\\a.exe``); a bare
    name may not.
    """
    if not program or not program.strip():
        return True
    if any(c in _DYNAMIC_NAME_CHARS for c in program):
        return True
    return not _has_sep(program) and ("(" in program or ")" in program)


def is_cmdlet_name(name: str) -> bool:
    """Is ``name`` a cmdlet: one of the tables, or ``Verb-Noun`` with an approved-style verb?"""
    if not name or _has_sep(name) or "." in name:
        return False
    if name.lower() in _CMDLETS or name.lower() in _NOPATH:
        return True
    verb, dash, noun = name.partition("-")
    return bool(dash) and bool(noun) and verb.lower() in _VERBS and noun[0].isalpha()


def _is_param(w: Word) -> bool:
    """An unquoted ``-Name`` word. A quoted word, ``-5`` and a lone ``-`` are values."""
    t = w.text
    return not w.quoted and len(t) > 1 and t[0] == "-" and (t[1].isalpha() or t[1] in "_-?")


def param_takes_value(cmdlet: str, param: str) -> bool | None:
    """Does the canonical parameter ``param`` of ``cmdlet`` take a value? None = not known.

    The cmdlet rows are authoritative for the cmdlets they cover; ``psaliases.takes_value`` answers
    for the rest. Never raises.
    """
    spec = _CMDLETS.get(cmdlet.lower())
    key = param.lower()
    if spec is not None and key in spec.roles:
        return True
    if key in _COMMON_SWITCHES or (spec is not None and key in spec.switches):
        return False
    if key in _COMMON_VALUES:
        return True
    try:
        answer = psaliases.takes_value(cmdlet, param)
    except Exception:  # noqa: BLE001 - a lookup table that raises must not break classification
        return None
    return answer if isinstance(answer, bool) else None


def _provider_of(text: str) -> tuple[str, str, bool] | None:
    """(label, rest, also_a_file) when ``text`` is qualified with a PowerShell provider.

    ``FileSystem::C:\\x`` (with or without the ``Microsoft.PowerShell.Core\\`` module prefix) is a
    plain file path once the prefix is removed: label ``filesystem``. ``HKLM:\\x``, ``Env:Path``,
    ``Registry::HKEY_...`` belong to another provider: the label is the lower-case drive or
    provider name. A multi-letter drive that is not a well-known provider (``id_rsa:stream`` is an
    alternate data stream, ``X:`` may be any PSDrive) is reported with ``also_a_file`` True: the
    caller marks the line gray AND lists the text as a file path. Single letters are file-system
    drives (None).
    """
    stripped = text.lstrip()
    cut = stripped.find("::")
    if cut > 0:
        head = stripped[:cut]
        module, _, word = head.rpartition("\\")
        word_low = word.lower()
        if (
            (word_low in _PROVIDER_WORDS or word_low == "filesystem")
            and all(c.isalnum() or c in "._" for c in module)
            and "/" not in head
        ):
            return word_low, stripped[cut + 2 :], word_low == "filesystem"
    colon = stripped.find(":")
    if colon >= 2:
        name = stripped[:colon]
        if name[0].isalpha() and all(c in _NAME_CHARS or c in "*?[]" for c in name):
            known = name.lower() in _KNOWN_PROVIDERS or any(c in name for c in "*?[]")
            return name.lower(), stripped[colon + 1 :], not known
    return None


class _Ctx:
    """The accumulator of one classification (wraps programs._Acc plus what it lacks)."""

    __slots__ = ("a", "config", "name")

    def __init__(self, name: str) -> None:
        self.a = _Acc(name)
        self.config = False
        self.name = name

    def put(self, w: Word, access: Access) -> None:
        """List a path word; provider paths (registry, env, ...) are not files: gray instead.

        A URL where a path was expected (``Start-Process https://x``) is a network target.
        """
        if w.text[:5].lower() == "file:":
            if access == "read":
                self.a.target(w)  # the path inside the file: URL, read
            else:
                self.a.path(w, access)
                self.a.gray.append("ps-file-url")
            return
        if "://" in w.text:
            self.a.target(w)
            return
        info = _provider_of(w.text)
        if info is None:
            self.a.path(w, access)
            return
        label, rest, as_file = info
        if label == "filesystem":
            self.a.path(replace(w, text=rest), access)
            return
        self.a.gray.append(f"ps-provider-path:{label}")
        self.config = True
        if access != "read":
            self.a.write_hint = True
        if as_file:
            self.a.path(w, "unknown" if access == "read" else access)

    def value(self, role: str, w: Word) -> None:
        """Apply one parameter value according to its role."""
        if role == "r":
            self.put(w, "read")
        elif role == "w":
            self.put(w, "write")
        elif role == "u":
            self.put(w, "unknown")
        elif role == "url":
            self.a.target(w)
        elif role == "ru":
            self.put(w, "read")  # put() sends a URL to the network targets
        # role "x": the value is not a path


# ---------------------------------------------------------------------------------------------
# Binding: parameters, values and positionals
# ---------------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Bound:
    named: list[tuple[str, Word]] = field(default_factory=list)  # (lower-case -param, value)
    groups: list[list[Word]] = field(default_factory=list)  # positional arguments (arrays grouped)
    positional: list[Word] = field(default_factory=list)  # the same words, flat
    flags: list[str] = field(default_factory=list)
    loose: list[Word] = field(default_factory=list)  # values of parameters we cannot place


def _is_sep(w: Word) -> bool:
    """The array separator ``pscmd`` puts between the elements of ``a,b`` for cmdlets."""
    return w.text == "," and not (w.quoted or w.expands or w.glob)


def _take_group(args: Sequence[Word], i: int) -> tuple[list[Word], int]:
    """The words of one argument starting at ``i`` (an array ``a , b , c`` is ONE argument)."""
    group = [args[i]]
    i += 1
    while i + 1 < len(args) and _is_sep(args[i]) and not _is_param(args[i + 1]):
        group.append(args[i + 1])
        i += 2
    return group, i


def _bind(name: str, args: Sequence[Word]) -> _Bound:
    """Split ``args`` into flags, parameter values and positionals (PowerShell binding order).

    An array argument (``a,b``) is ONE argument: all of its words bind to the same slot. A word
    after a parameter whose arity is unknown is BOTH a possible value (``loose``) and a possible
    positional: it is listed either way.
    """
    out = _Bound()
    i = 0
    n = len(args)
    after = False
    while i < n:
        w = args[i]
        if _is_sep(w):
            i += 1  # a stray separator carries no information
            continue
        if after or not _is_param(w):
            group, i = _take_group(args, i)
            out.groups.append(group)
            out.positional.extend(group)
            continue
        i += 1
        tok = w.text
        if tok == "--":
            after = True
            continue
        out.flags.append(tok)
        takes = param_takes_value(name, tok)
        if takes is False or i >= n or _is_param(args[i]) or _is_sep(args[i]):
            continue
        group, i = _take_group(args, i)
        if takes is True:
            out.named.extend((tok.lower(), g) for g in group)
        else:
            out.loose.extend(group)
            out.groups.append(group)
            out.positional.extend(group)
    return out


def _assign_positionals(spec: Cmdlet, bound: _Bound) -> list[Word]:
    """Bind the positional arguments to the free positional slots; return the words left over."""
    taken = {key for key, _ in bound.named}
    slots = [p for p in spec.positional if p.lower() not in taken]
    if taken & _PATHISH:
        slots = [p for p in slots if p.lower() not in _PATHISH]
    extra: list[Word] = []
    for i, group in enumerate(bound.groups):
        if i < len(slots):
            bound.named.extend((slots[i].lower(), w) for w in group)
        else:
            extra.extend(group)
    return extra


def _has_path_param(bound: _Bound) -> bool:
    return any(key in _PATHISH for key, _ in bound.named)


def _named(bound: _Bound, *keys: str) -> list[Word]:
    return [w for key, w in bound.named if key in keys]


def _pipeline_word() -> Word:
    """Stands for the paths a previous pipeline stage hands over: dynamic for every layer."""
    return Word("$(pipeline input)", expands=True)


# ---------------------------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------------------------


def _h_roles(ctx: _Ctx, spec: Cmdlet, bound: _Bound, extra: list[Word]) -> None:
    for key, w in bound.named:
        role = spec.roles.get(key)
        if role is not None:
            ctx.value(role, w)
        if key in spec.scan:
            _generic_arg(ctx.a, w)
    has_path_role = any(r in ("r", "w", "u") for r in spec.roles.values())
    for w in extra:
        if has_path_role:
            ctx.put(w, "unknown")
        else:
            _generic_arg(ctx.a, w)
    if spec.pipe and not _has_path_param(bound):
        ctx.put(_pipeline_word(), "write")
        ctx.a.gray.append("arguments-from-pipeline")


def _h_transfer(ctx: _Ctx, spec: Cmdlet, bound: _Bound, extra: list[Word]) -> None:
    """Copy-Item / Move-Item: sources, destination; a directory destination gets child names.

    Positional arguments bind as in PowerShell (Path, then Destination); words no slot claims are
    sources too (over-listed, never dropped). Without any source the paths come from the pipeline.
    """
    a = ctx.a
    move = spec.name == "Move-Item"
    dests = _named(bound, "-destination")
    sources = _named(bound, "-path", "-literalpath", "-pspath") + extra
    if not sources:
        sources_now = [_pipeline_word()]
        a.gray.append("arguments-from-pipeline")
    else:
        sources_now = sources
    for w in sources_now:
        ctx.put(w, "read")  # a source is always read; a moved one is removed: read AND written
        if move:
            ctx.put(w, "write")
    for d in dests:
        ctx.put(d, "write")
    flags = {f.lower() for f in bound.flags}
    if "-recurse" in flags and not move:
        a.gray.append("directory-write")  # a copied directory brings members we cannot see
    if "-tosession" in flags or "-fromsession" in flags:
        a.gray.append("ps-remote-copy")
        a.network = True
    for d in dests:
        if _provider_of(d.text) is None:
            _copy_into(a, d, sources, dirlike=_is_dirlike(d), parents=False)


def _sibling(path: Word, name: Word) -> Word:
    """``DIR\\NAME`` for ``Rename-Item DIR\\old NAME``: the new name lives next to the old one."""
    text = path.text.rstrip("/\\")
    cut = max(text.rfind("/"), text.rfind("\\"))
    new = name.text if cut < 0 else text[: cut + 1] + name.text
    return Word(new, path.expands or name.expands, path.glob or name.glob, True)


def _h_rename(ctx: _Ctx, spec: Cmdlet, bound: _Bound, extra: list[Word]) -> None:
    _h_roles(ctx, spec, bound, extra)
    paths = _named(bound, "-path", "-literalpath", "-pspath")
    for p in paths or ([] if not spec.pipe else [_pipeline_word()]):
        ctx.put(p, "read")  # the old item is read (moved to its new name), as well as written
    for new in _named(bound, "-newname"):
        if not paths:
            ctx.put(new, "write")
        for p in paths:
            if _provider_of(p.text) is None:
                ctx.put(_sibling(p, new), "write")


def _h_newitem(ctx: _Ctx, spec: Cmdlet, bound: _Bound, extra: list[Word]) -> None:
    """New-Item: the path, ``-Name`` children, and the target of a link (read, and gray)."""
    _h_roles(ctx, spec, bound, extra)
    parents = _named(bound, "-path")
    for name in _named(bound, "-name"):
        if not parents:
            ctx.put(name, "write")  # created in the current directory
        for p in parents:
            child = _join_child(p, name.text) if _provider_of(p.text) is None else None
            if child is not None:
                dynamic = child.expands or name.expands
                wild = child.glob or name.glob
                ctx.a.path(replace(child, expands=dynamic, glob=wild), "write")
    types = _named(bound, "-itemtype")
    if any(t.expands or t.glob or t.text.lower() not in _LINK_FREE for t in types):
        ctx.a.gray.append("ps-link-creation")
        for target in _named(bound, "-value", "-target"):
            ctx.put(target, "read")


def _module_path_like(w: Word) -> bool:
    t = w.text
    return (
        _pathlike(t)
        or w.expands
        or w.glob
        or t.lower().endswith((".ps1", ".psm1", ".psd1", ".dll"))
    )


def _h_importmodule(ctx: _Ctx, spec: Cmdlet, bound: _Bound, extra: list[Word]) -> None:
    _h_roles(ctx, spec, bound, extra)
    for w in _named(bound, "-name", "-fullyqualifiedname") + extra:
        if _module_path_like(w):
            ctx.put(w, "read")


def _h_alias(ctx: _Ctx, spec: Cmdlet, bound: _Bound, extra: list[Word]) -> None:
    _h_roles(ctx, spec, bound, extra)
    ctx.a.gray.append("ps-alias-redefined")


def _h_variable(ctx: _Ctx, spec: Cmdlet, bound: _Bound, extra: list[Word]) -> None:
    _h_roles(ctx, spec, bound, extra)
    ctx.a.gray.append("ps-variable-assign")


def _h_system(ctx: _Ctx, spec: Cmdlet, bound: _Bound, extra: list[Word]) -> None:
    ctx.a.gray.append(f"ps-system-change:{spec.name}")
    ctx.config = True
    for w in bound.positional:
        _generic_arg(ctx.a, w)
    for key, w in bound.named:
        if key not in ("-name",):
            _generic_arg(ctx.a, w)


_HANDLERS = {
    "roles": _h_roles,
    "transfer": _h_transfer,
    "rename": _h_rename,
    "newitem": _h_newitem,
    "importmodule": _h_importmodule,
    "newobject": _h_roles,
    "alias": _h_alias,
    "variable": _h_variable,
    "system": _h_system,
}


def _filelike(text: str) -> bool:
    """``name.ext``: a bare file name (no separator) with a short alphanumeric extension."""
    stem, dot, ext = text.rpartition(".")
    return bool(dot) and bool(stem) and 1 <= len(ext) <= 5 and ext.isalnum() and " " not in text


def _unknown_cmdlet(ctx: _Ctx, args: Sequence[Word]) -> None:
    """A cmdlet without a row: parameters are flags; path-looking words are unknown paths."""
    a = ctx.a
    a.known = False
    after_pathy = False
    after = False
    for w in args:
        if _is_sep(w):
            continue
        if not after and _is_param(w):
            if w.text == "--":
                after = True
                continue
            a.flags.append(w.text)
            low = w.text.lower()
            after_pathy = low in _PATH_PARAM_NAMES or any(p in low for p in _PATH_PARAM_WORDS)
            continue
        if after_pathy or _filelike(w.text):
            ctx.put(w, "unknown")
        else:
            _generic_arg(a, w)
        after_pathy = False


# ---------------------------------------------------------------------------------------------
# Execution reasons (shared with pscmd)
# ---------------------------------------------------------------------------------------------


def _is_encoded_param(text: str) -> bool:
    low = text.lower()
    rest = low[1:]
    return len(low) > 1 and low[0] in "-/" and (rest == "ec" or "encodedcommand".startswith(rest))


def alias_definitions(program: str, args: Sequence[Word]) -> tuple[frozenset[str], bool]:
    """(lower-case names a ``Set-Alias`` / ``New-Alias`` call defines, some name is unknowable).

    ``((), False)`` for any other program. A name that is missing or dynamic (``$x``, a glob) sets
    the flag: after it, ANY alias on the line may mean something else. Never raises.
    """
    try:
        spec = _CMDLETS.get(_base(strip_module(program)))
        if spec is None or spec.kind != "alias" or spec.name == "Import-Alias":
            return frozenset(), False
        bound = _bind(spec.name, list(args)[:_MAX_WORDS])
        _assign_positionals(spec, bound)
        named = _named(bound, "-name")
        names = frozenset(w.text.lower() for w in named if w.text and not (w.expands or w.glob))
        return names, not named or len(names) != len(named)
    except Exception:  # noqa: BLE001 - never raise: an unreadable definition is "unknowable"
        return frozenset(), True


def exec_reasons_of(program: str, args: Sequence[Word]) -> tuple[str, ...]:
    """Why a call executes code the parser cannot see inside (empty when it does not).

    ``ps-exec:<Cmdlet>`` for Invoke-Expression, Invoke-Command, Start-Process, Add-Type, ...;
    ``ps-nested-shell`` for powershell / pwsh / cmd / wsl / script hosts, plus
    ``ps-encoded-command`` for ``-EncodedCommand``; ``ps-script-exec`` for a script file (by
    extension) or any path-qualified name that is not a ``.exe``; ``ps-exec:Import-Module`` for a
    module loaded from a path, ``ps-exec:New-Object`` for ``-ComObject``. Never raises.
    """
    out: dict[str, None] = {}
    try:
        name = strip_module(program)
        low = _base(name)
        spec = _CMDLETS.get(low) if not _has_sep(name) else None
        if spec is not None and spec.runs_code:
            out[f"ps-exec:{spec.name}"] = None
        if low in NESTED_SHELLS:
            out["ps-nested-shell"] = None
            if low in ("powershell", "pwsh") and any(
                not w.quoted and _is_encoded_param(w.text) for w in args
            ):
                out["ps-encoded-command"] = None
        text = name.strip().lower()
        if text.endswith(_SCRIPT_EXTS) or (_has_sep(text) and not text.endswith(".exe")):
            out["ps-script-exec"] = None
        if spec is not None and spec.kind == "importmodule":
            bound = _bind(spec.name, list(args)[:_MAX_WORDS])
            extra = _assign_positionals(spec, bound)
            if any(
                _module_path_like(w) for w in _named(bound, "-name", "-fullyqualifiedname") + extra
            ):
                out["ps-exec:Import-Module"] = None
        if (
            spec is not None
            and spec.kind == "newobject"
            and any(_is_param(w) and w.text.lower() == "-comobject" for w in args)
        ):
            out["ps-exec:New-Object"] = None
    except Exception:  # noqa: BLE001 - never raise; the caller already grays what it cannot read
        out["ps-internal-error"] = None
    return tuple(out)


def reads_stdin_as_code(program: str, args: Sequence[Word]) -> bool:
    """Does this call, as a pipeline target, run what the pipeline hands it as code?

    ``| Invoke-Expression`` always; ``| powershell`` / ``| pwsh`` / ``| sh`` / ``| python`` ...
    when no script or file argument is given (only parameters and ``-``). Never raises.
    """
    try:
        low = _base(strip_module(program))
        if low == "invoke-expression":
            return True
        return low in STDIN_INTERPRETERS and not any(
            not _is_param(w) and w.text != "-" for w in args
        )
    except Exception:  # noqa: BLE001 - never raise
        return True


# ---------------------------------------------------------------------------------------------
# Redirects, environment, assembly
# ---------------------------------------------------------------------------------------------


def _apply_redirects(ctx: _Ctx, redirects: Sequence[Redirect]) -> None:
    for r in redirects:
        tgt = r.target
        if tgt is None:
            continue
        if tgt.text.lower() in ("$null", "${null}") and not tgt.glob:
            continue
        ctx.put(tgt, "read" if "<" in r.op else "write")


def _tag_union(*groups: Sequence[RiskTag]) -> tuple[RiskTag, ...]:
    have = {t for g in groups for t in g}
    return tuple(t for t in _ALL_TAGS if t in have)


def _finish(
    ctx: _Ctx,
    program: str,
    redirects: Sequence[Redirect],
    env: Sequence[tuple[str, Word]],
    extra_tags: Sequence[RiskTag] = (),
) -> CmdInfo:
    a = ctx.a
    _apply_redirects(ctx, redirects)
    for var, _value in env:
        if programs.is_code_env(var):
            a.exec_hint = True
            a.gray.append(f"env-code-injection:{var}")
    paths = list(dict.fromkeys(a.paths))
    network = a.network or bool(a.urls)
    flags = tuple(dict.fromkeys(a.flags))
    tags = derive_risk_tags(
        program=program,
        subcommand=a.sub,
        flags=flags,
        paths=paths,
        network=network,
        exec_hint=a.exec_hint,
        write_hint=a.write_hint,
        secret_hint=a.secret_hint,
        config_hint=ctx.config,
    )
    return CmdInfo(
        known=a.known,
        subcommand=a.sub,
        flags=flags,
        paths=tuple(paths),
        urls=tuple(dict.fromkeys(a.urls)),
        network=network,
        tags=_tag_union(tags, extra_tags),
        gray=tuple(dict.fromkeys(a.gray)),
        recursive=a.recursive,
    )


def _external(
    program: str,
    args: Sequence[Word],
    redirects: Sequence[Redirect],
    env: Sequence[tuple[str, Word]],
) -> CmdInfo:
    """A program that is not a cmdlet: the Bash-side tables know it (git, curl, npm, ...)."""
    name = program if _has_sep(program) else _base(program)
    base = _base(program)
    extra: list[RiskTag] = []
    if base in _SYSTEM_EXTERNALS or base in _COPY_TOOLS:
        ctx = _Ctx(name)
        a = ctx.a
        if _has_sep(program):
            a.path(Word(program, expands=program[:1] == "~"), "unknown")  # as the Bash side does
        if base in _COPY_TOOLS:
            _h_copytool(ctx, base, args)
        else:
            _h_wintool(ctx, base, args)
    else:
        info = programs.classify(name, list(args), shell="bash")  # noqa: S604 - a dialect
        ctx = _Ctx(name)
        a = ctx.a
        a.known = info.known
        a.sub = info.subcommand
        a.flags.extend(info.flags)
        a.paths.extend(info.paths)
        a.urls.extend(info.urls)
        a.network = info.network
        a.gray.extend(info.gray)
        a.recursive = info.recursive
        extra.extend(info.tags)
        if base in _BUILD_TOOLS and _runs_build_code(ctx, base, args):
            a.known = True
            a.gray.append(f"ps-build-tool:{base}")
            extra.append("exec")
    reasons = exec_reasons_of(program, args)
    if reasons:
        a.gray.extend(reasons)
        extra.append("exec")
    if base in _SYSTEM_EXTERNALS:
        a.gray.append(f"ps-system-change:{base}")
        ctx.config = True
    return _finish(ctx, base, redirects, env, extra)


def _runs_build_code(ctx: _Ctx, base: str, args: Sequence[Word]) -> bool:
    """Does this build tool call run project code? (always, except ``dotnet --info`` and alike)."""
    if base != "dotnet":
        return True
    plain = [w for w in args if not (w.text.startswith("-") or w.text.startswith("/"))]
    if plain:
        ctx.a.sub = plain[0].text.lower()
        return ctx.a.sub != "help" or any(w.expands or w.glob for w in plain)
    return not all(w.text.lower() in _DOTNET_INFO_FLAGS for w in args)


def _provider_free(w: Word) -> bool:
    """Is ``w`` an ordinary file path (no PowerShell provider such as ``HKLM:``)?"""
    return _provider_of(w.text) is None


def _switch_flag(w: Word) -> tuple[str, str] | None:
    """(lower-case ``/name``, value after ``:``) when ``w`` is a Windows ``/switch`` word."""
    if w.expands or w.glob or not _SWITCH_RE.fullmatch(w.text):
        return None
    name, _, value = w.text.partition(":")
    return name.lower(), value


def _h_wintool(ctx: _Ctx, base: str, args: Sequence[Word]) -> None:
    """net / vssadmin / reg / takeown / cipher / format ...: ``/x`` words are flags, not paths."""
    a = ctx.a
    a.known = True
    for w in args:
        sw = _switch_flag(w)
        if sw is not None:
            a.flags.append(sw[0])
            if sw[1]:
                _generic_arg(a, replace(w, text=sw[1]))
        elif _is_param(w) and w.text != "--":
            a.flags.append(w.text.lower())
        elif (
            base in _SUBCOMMAND_TOOLS
            and a.sub is None
            and w.text.isalpha()
            and not (w.expands or w.glob)
        ):
            a.sub = w.text.lower()
        else:
            _generic_arg(a, w)


def _h_copytool(ctx: _Ctx, base: str, args: Sequence[Word]) -> None:
    """robocopy / xcopy: ``SOURCE DEST [files...] [/switches]``; /MIR /PURGE /MOVE delete."""
    a = ctx.a
    a.known = True
    plain: list[Word] = []
    skipping = False
    for w in args:
        sw = _switch_flag(w)
        if sw is None:
            if not skipping:
                plain.append(w)  # (the names after /XF /XD /IF are filters, not operands)
            continue
        skipping = sw[0] in _ROBOCOPY_NAME_LISTS
        a.flags.append(sw[0])
        if sw[0] in _ROBOCOPY_PURGES:
            a.gray.append(f"ps-destructive-copy:{sw[0]}")
        if sw[1] and sw[0] in _ROBOCOPY_LOGS:
            ctx.put(replace(w, text=sw[1]), "write")
        elif sw[1]:
            _generic_arg(a, replace(w, text=sw[1]))
    moves = bool(set(a.flags) & {"/move", "/mov"})
    list_only = bool(set(a.flags) & {"/l"})  # /L only lists the names it would copy
    if (base == "robocopy" or set(a.flags) & {"/s", "/e"}) and not list_only:
        a.recursive = True  # the source directory is copied with (robocopy: all of) its contents
    if not plain:
        return
    sources, dests, names = plain[:1], plain[1:2], plain[2:]
    for s in sources:
        ctx.put(s, "read")
        if moves:
            ctx.put(s, "write")
    for d in dests:
        ctx.put(d, "write")
        if _provider_free(d):
            if base == "xcopy":  # a file source lands in DEST under its own name
                _copy_into(a, d, sources, dirlike=_is_dirlike(d), parents=False)
            elif names:  # robocopy copies the named files (patterns: unknowable names -> gray)
                _copy_into(a, d, names, dirlike=True, parents=False)
            else:  # robocopy copies the members of the source directory
                a.gray.append("directory-write")


# cmdlet (lower case) -> the switch that makes it walk the subtree (None: always)
# (only cmdlets that READ content: ``Get-ChildItem -Recurse`` merely lists names and is not here;
# what it pipes into ``Get-Content`` / ``Select-String`` is a different command, and the pipeline
# stage that takes arguments from the pipeline is gray by itself.)
_RECURSIVE_CMDLETS: dict[str, frozenset[str] | None] = {
    "copy-item": frozenset({"-recurse"}),
    "compress-archive": None,
}
_LISTING_RECURSE = frozenset({"-recurse", "-depth"})  # Get-ChildItem; -Depth implies -Recurse


def _cmdlet(
    spec: Cmdlet,
    args: Sequence[Word],
    redirects: Sequence[Redirect],
    env: Sequence[tuple[str, Word]],
) -> CmdInfo:
    ctx = _Ctx(spec.name)
    bound = _bind(spec.name, args)
    extra = _assign_positionals(spec, bound)
    ctx.a.flags.extend(bound.flags)
    ctx.config = spec.config
    ctx.a.gray.extend(spec.gray)
    ctx.a.network = spec.network
    _HANDLERS[spec.kind](ctx, spec, bound, extra)
    for w in bound.loose:
        if _pathlike(w.text) or w.expands or w.glob:
            ctx.put(w, "unknown")
    key = spec.name.lower()
    switches = _RECURSIVE_CMDLETS.get(key, frozenset())
    if key in _RECURSIVE_CMDLETS and (
        switches is None or switches & {f.lower() for f in bound.flags}
    ):
        ctx.a.recursive = True  # reads the whole subtree of its directory operands
    if (
        key == "get-childitem"
        and not ctx.a.paths
        and _LISTING_RECURSE & {f.lower() for f in bound.flags}
    ):
        ctx.a.path(Word("."), "read")  # no path: the current directory (listing: not scanned)
    reasons = exec_reasons_of(spec.name, args)
    if reasons:
        ctx.a.exec_hint = True
        ctx.a.gray.extend(reasons)
    return _finish(ctx, spec.name, redirects, env)


def _nopath(
    name: str,
    args: Sequence[Word],
    redirects: Sequence[Redirect],
    env: Sequence[tuple[str, Word]],
) -> CmdInfo:
    ctx = _Ctx(name)
    for w in args:
        if _is_param(w) and w.text != "--":
            ctx.a.flags.append(w.text)
    return _finish(ctx, name, redirects, env)


_FALLBACK_ALIASES = {"?": "where-object", "%": "foreach-object"}


def _classify_ps(
    program: str,
    args: Sequence[Word],
    redirects: Sequence[Redirect],
    env: Sequence[tuple[str, Word]],
) -> CmdInfo:
    if not isinstance(program, str):
        program = ""
    words = [w for w in args if isinstance(w, Word)]
    problems: list[str] = []
    if len(words) != len(args):
        problems.append("ps-internal-error")
    if len(words) > _MAX_WORDS:
        words = words[:_MAX_WORDS]
        problems.append("ps-too-large")
    program = _FALLBACK_ALIASES.get(program, program)
    if dynamic_name(program):
        ctx = _Ctx(program)
        ctx.a.gray.append("dynamic-program")
        _unknown_cmdlet(ctx, words)
        info = _finish(ctx, program, redirects, env)
    else:
        name = strip_module(program)
        low = _base(name)
        if not _has_sep(name) and low in _CMDLETS:
            info = _cmdlet(_CMDLETS[low], words, redirects, env)
        elif not _has_sep(name) and low in _NOPATH:
            info = _nopath(low, words, redirects, env)
        elif not _has_sep(name) and is_cmdlet_name(name):
            ctx = _Ctx(name)
            _unknown_cmdlet(ctx, words)
            info = _finish(ctx, name, redirects, env)
        else:
            info = _external(name, words, redirects, env)
    if problems:
        info = replace(info, gray=tuple(dict.fromkeys((*info.gray, *problems))))
    return info


def classify_ps(
    program: str,
    args: Sequence[Word],
    *,
    redirects: Sequence[Redirect] = (),
    env: Sequence[tuple[str, Word]] = (),
) -> CmdInfo:
    """Classify ONE PowerShell command (canonical cmdlet name or external program, plus words).

    ``args`` follow the convention in the module docstring. Cmdlets with a row get exact facts
    (``known=True``); a cmdlet-shaped name without one is ``known=False`` with path-looking words
    listed as unknown paths; anything else is an external program, classified by the Bash tables.
    Provider paths (``HKLM:``, ``Env:``) are not files: ``config_tamper`` plus gray
    ``ps-provider-path:<drive>``. Redirect targets are written paths (``$null`` is dropped).

    Never raises: an internal error yields ``known=False``, every risk tag and gray
    ``ps-internal-error``.
    """
    try:
        return _classify_ps(program, args, redirects, env)
    except Exception:  # noqa: BLE001 - a classifier that raises would fail the gate open
        return CmdInfo(
            known=False,
            subcommand=None,
            flags=(),
            paths=(),
            urls=(),
            network=False,
            tags=_ALL_TAGS,
            gray=("ps-internal-error",),
        )
