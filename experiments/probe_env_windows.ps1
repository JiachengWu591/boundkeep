# M0a E20 / E21 的本地探针（只读，不改系统）。用法：powershell -NoProfile -ExecutionPolicy Bypass -File experiments\probe_env_windows.ps1
# 输出只含 ASCII 以外的字符时按系统代码页显示；结论摘抄进 docs/hook-behavior.md。
$ErrorActionPreference = 'Continue'
"== PowerShell: $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion); language mode: $($ExecutionContext.SessionState.LanguageMode)"

"== E20: Parser::ParseInput under ConstrainedLanguage (one-way switch inside this process)"
$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'
"language mode now: $($ExecutionContext.SessionState.LanguageMode)"
try {
    $t = $null; $e = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput('Remove-Item -Recurse x', [ref]$t, [ref]$e)
    "parse OK in CLM; command count = " + @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)).Count
} catch {
    "parse BLOCKED in CLM: " + $_.Exception.GetType().Name + ": " + $_.Exception.Message
}
"-- fallback inside CLM: Get-Alias / Get-Command still work?"
try { "Get-Alias rm -> " + (Get-Alias rm).Definition } catch { "Get-Alias blocked: " + $_.Exception.Message }
