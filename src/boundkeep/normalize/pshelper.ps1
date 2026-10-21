# boundkeep PowerShell parse helper (M1b, docs/m1b-design.md section 2).
#
# A long-lived child process owned by boundkeep.normalize.psparse. It reads ONE request per line
# from stdin and answers with ONE JSON line on stdout. The command text it is asked about is
# attacker-influenced, so this script only PARSES it: the text goes to
# [System.Management.Automation.Language.Parser]::ParseInput as data and the resulting syntax tree
# is only read. Nothing in this file evaluates, invokes or loads anything derived from that text
# (no Invoke-Expression, no dot-sourcing, no Add-Type, no New-Object, no call operator on a
# variable, no reflection). tests/unit/test_norm_psparse.py greps for those tokens.
#
# Protocol (UTF-8 without BOM, LF-terminated lines, stdout carries nothing but JSON lines and is
# pure ASCII: every non-ASCII character is written as a \uXXXX escape):
#   ready   {"ready":true,"mode":"FullLanguage","version":"5.1.26100.9444"}
#   request {"id":"<hex>","b64":"<base64 of the UTF-8 command text>"}
#   reply   {"id":"..","ok":true,"parse_errors":[..],"commands":[..],"compound":[..],
#            "dynamic":[..],"mode":".."}   or   {"id":"..","ok":false,"error":"too-large|internal"}
#
# Speed note: a PowerShell function call costs ~20 microseconds and a StringBuilder call ~1, so the
# serializer builds whole JSON fragments per call instead of one call per token.

using namespace System.Management.Automation.Language

$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# ---- constrained language mode: say so and stop (before anything needs a full-language type) --
# Under constrained language mode ([Parser]::ParseInput and most .NET types are blocked) the helper
# cannot work; the Python side must see that as "unavailable", not as a crash.
$script:Mode = $ExecutionContext.SessionState.LanguageMode.ToString()
if ($script:Mode -ne 'FullLanguage') {
    # A bare string statement is written to stdout (no .NET method call: not allowed here).
    '{"ready":true,"mode":"' + $script:Mode + '","version":"' + $PSVersionTable.PSVersion.ToString() + '"}'
    exit 0
}

# ---- limits ----------------------------------------------------------------------------------
$script:MaxTextBytes = 1048576      # the request text; the Python side checks first
$script:MaxB64Chars = 1398200       # base64 of 1 MiB is 1398104 characters
$script:MaxOutChars = 4000000       # < 4 MiB: the reply is ASCII, so characters are bytes
$script:MaxNodes = 200000
$script:MaxCommands = 5000
$script:MaxString = 32768
$script:MaxHeadString = 4096        # a pipeline head string is repeated per later stage
$script:MaxOtherText = 2000
$script:MaxDepth = 12
$script:MaxErrors = 50

# ---- explicit UTF-8, no BOM, independent of the console code page ----------------------------
$script:Utf8 = [System.Text.UTF8Encoding]::new($false)
$script:StrictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
try {
    [Console]::InputEncoding = $script:Utf8
    [Console]::OutputEncoding = $script:Utf8
} catch {
    # A process without a console cannot set the code page; the raw streams below do not need it.
    $null = $_
}
$script:In = [System.IO.StreamReader]::new([Console]::OpenStandardInput(), $script:Utf8, $false, 65536)
$script:Out = [System.IO.StreamWriter]::new([Console]::OpenStandardOutput(), $script:Utf8, 65536)
$script:Out.NewLine = "`n"
$script:Out.AutoFlush = $true

# ---- tables ----------------------------------------------------------------------------------
$script:StrKind = @{
    'BareWord' = 'bare'; 'SingleQuoted' = 'single'; 'DoubleQuoted' = 'double'
    'SingleQuotedHereString' = 'singlehere'; 'DoubleQuotedHereString' = 'doublehere'
}
$script:FileStream = @{
    'Output' = ''; 'Error' = '2'; 'Warning' = '3'; 'Verbose' = '4'
    'Debug' = '5'; 'Information' = '6'; 'All' = '*'
}
$script:MergeStream = @{
    'Output' = '1'; 'Error' = '2'; 'Warning' = '3'; 'Verbose' = '4'
    'Debug' = '5'; 'Information' = '6'; 'All' = '*'
}
# Expression node types that construct or compute a value: the command line is not static.
$script:DynamicTypes = @{}
foreach ($n in @(
        'SubExpressionAst', 'ScriptBlockExpressionAst', 'InvokeMemberExpressionAst',
        'MemberExpressionAst', 'TypeExpressionAst', 'ConvertExpressionAst', 'IndexExpressionAst',
        'BinaryExpressionAst', 'UnaryExpressionAst', 'ArrayExpressionAst', 'TernaryExpressionAst',
        'AttributedExpressionAst', 'UsingExpressionAst', 'ErrorExpressionAst',
        'BaseCtorInvokeMemberExpressionAst')) {
    $script:DynamicTypes[$n] = $true
}

# ---- JSON writing (no ConvertTo-Json: exact control over shape, escaping and size) -----------
$script:Sb = [System.Text.StringBuilder]::new(4096)
$script:NeedEsc = [System.Text.RegularExpressions.Regex]::new('[^\x20-\x7e]')
$script:Esc = [System.Text.RegularExpressions.MatchEvaluator]{
    param($m)
    '\u{0:x4}' -f [int]$m.Value[0]
}

# A JSON string literal (with quotes) for any text; ASCII-only result.
function J([string]$s) {
    if ($s.Length -eq 0) { return '""' }
    $t = $s.Replace('\', '\\').Replace('"', '\"')
    return '"' + $script:NeedEsc.Replace($t, $script:Esc) + '"'
}

function JClip([string]$s, [int]$max) {
    if ($s.Length -gt $max) { $s = $s.Substring(0, $max) }
    return (J $s)
}

function TypeShort($node) {
    $full = $node.PSObject.TypeNames[0]
    return $full.Substring($full.LastIndexOf('.') + 1)
}

function Add-Other($e) {
    [void]$script:Sb.Append('{"t":"other","ast":' + (J (TypeShort $e)) + ',"text":' + (JClip $e.Extent.Text $script:MaxOtherText) + '}')
}

function Add-TooLong($e) {
    [void]$script:Sb.Append('{"t":"other","ast":"TooLongString","text":' + (JClip $e.Extent.Text 200) + '}')
}

# One command element (or a redirection target / parameter argument). Unknown nodes become
# "other" with their source text; the consumer must treat them as dynamic.
function Add-Elem($e, [int]$depth) {
    $sb = $script:Sb
    if ($null -eq $e) { [void]$sb.Append('null'); return }
    if ($depth -gt $script:MaxDepth) { Add-Other $e; return }
    if ($e -is [StringConstantExpressionAst]) {
        if ($e.Value.Length -gt $script:MaxString) { Add-TooLong $e; return }
        [void]$sb.Append('{"t":"str","kind":"' + $script:StrKind[$e.StringConstantType.ToString()] + '","v":' + (J $e.Value) + '}')
    } elseif ($e -is [CommandParameterAst]) {
        [void]$sb.Append('{"t":"param","name":' + (J $e.ParameterName) + ',"arg":')
        Add-Elem $e.Argument ($depth + 1)
        [void]$sb.Append('}')
    } elseif ($e -is [VariableExpressionAst]) {
        $splat = if ($e.Splatted) { 'true' } else { 'false' }
        [void]$sb.Append('{"t":"var","name":' + (J $e.VariablePath.UserPath) + ',"splat":' + $splat + '}')
    } elseif ($e -is [ExpandableStringExpressionAst]) {
        if ($e.Value.Length -gt $script:MaxString) { Add-TooLong $e; return }
        $vars = [System.Collections.Generic.List[string]]::new()
        $subexpr = 'false'
        foreach ($n in $e.NestedExpressions) {
            if ($n -is [VariableExpressionAst]) {
                $vars.Add((J $n.VariablePath.UserPath))
            } else {
                $subexpr = 'true'
            }
        }
        [void]$sb.Append('{"t":"expstr","v":' + (J $e.Value) + ',"vars":[' + ($vars -join ',') + '],"subexpr":' + $subexpr + '}')
    } elseif ($e -is [ConstantExpressionAst]) {
        [void]$sb.Append('{"t":"num","v":' + (JClip $e.Extent.Text 200) + '}')
    } elseif ($e -is [ArrayLiteralAst]) {
        [void]$sb.Append('{"t":"array","items":[')
        $first = $true
        foreach ($item in $e.Elements) {
            if (-not $first) { [void]$sb.Append(',') }
            $first = $false
            Add-Elem $item ($depth + 1)
        }
        [void]$sb.Append(']}')
    } else {
        Add-Other $e
    }
}

# The head of a pipeline is repeated in every later stage: a long string is cut short (it becomes
# an "other" element, which the consumer treats as dynamic).
function Add-Head($e) {
    if (($e -is [StringConstantExpressionAst]) -and ($e.Value.Length -gt $script:MaxHeadString)) { Add-TooLong $e; return }
    Add-Elem $e 1
}

function Add-Name($e) {
    $sb = $script:Sb
    if ($e -is [StringConstantExpressionAst]) {
        [void]$sb.Append('{"kind":"' + $script:StrKind[$e.StringConstantType.ToString()] + '","v":' + (JClip $e.Value $script:MaxString) + '}')
    } elseif ($e -is [ExpandableStringExpressionAst]) {
        [void]$sb.Append('{"kind":"expandable","v":' + (JClip $e.Value $script:MaxString) + '}')
    } elseif ($e -is [VariableExpressionAst]) {
        [void]$sb.Append('{"kind":"variable","v":' + (J $e.VariablePath.UserPath) + '}')
    } else {
        [void]$sb.Append('{"kind":"expr","v":' + (JClip $e.Extent.Text $script:MaxOtherText) + '}')
    }
}

function Add-Redirect($r) {
    $sb = $script:Sb
    if ($r -is [FileRedirectionAst]) {
        $op = $script:FileStream[$r.FromStream.ToString()]
        if ($r.Append) { $op += '>>' } else { $op += '>' }
        [void]$sb.Append('{"op":' + (J $op) + ',"target":')
        Add-Elem $r.Location 1
        [void]$sb.Append(',"merge":null}')
    } elseif ($r -is [MergingRedirectionAst]) {
        $m = $script:MergeStream[$r.FromStream.ToString()] + '>&' + $script:MergeStream[$r.ToStream.ToString()]
        [void]$sb.Append('{"op":">&","target":null,"merge":' + (J $m) + '}')
    } else {
        [void]$sb.Append('{"op":"?","target":null,"merge":null}')
    }
}

function Add-Command($c, $root) {
    $sb = $script:Sb
    if ($sb.Length -gt $script:MaxOutChars) { throw 'too-large' }
    $isCmd = $c -is [CommandAst]
    $invoke = ''
    if ($isCmd) {
        $inv = $c.InvocationOperator.ToString()
        $invoke = if ($inv -eq 'Ampersand') { '&' } elseif ($inv -eq 'Dot') { '.' } else { '' }
    }
    [void]$sb.Append('{"pos":[' + $c.Extent.StartOffset + ',' + $c.Extent.EndOffset + '],"invoke":"' + $invoke + '","name":')
    if ($isCmd) {
        $elems = $c.CommandElements
        if ($elems.Count -gt 0) { Add-Name $elems[0] } else { [void]$sb.Append('{"kind":"expr","v":""}') }
    } else {
        $elems = @()
        [void]$sb.Append('{"kind":"expr","v":' + (JClip $c.Extent.Text $script:MaxOtherText) + '}')
    }
    [void]$sb.Append(',"elements":[')
    for ($i = 1; $i -lt $elems.Count; $i++) {
        if ($i -gt 1) { [void]$sb.Append(',') }
        Add-Elem $elems[$i] 0
    }
    [void]$sb.Append('],"redirects":[')
    $first = $true
    foreach ($r in $c.Redirections) {
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        Add-Redirect $r
    }
    [void]$sb.Append('],"stage":')
    $p = $c.Parent
    $nested = 'true'
    if ($p -is [PipelineAst]) {
        $idx = $p.PipelineElements.IndexOf($c)
        [void]$sb.Append('{"index":' + $idx + ',"of":' + $p.PipelineElements.Count)
        # An expression that STARTS the pipeline ('x' | Get-Content, $env:A | Select-Object,
        # (Get-Content f) | ...) is no CommandAst, but its value flows into every later stage: it
        # goes into the stage object of the later stages as "head" (an ordinary element).
        if ($idx -gt 0) {
            $headNode = $p.PipelineElements[0]
            if ($headNode -is [CommandExpressionAst]) {
                [void]$sb.Append(',"head":')
                Add-Head $headNode.Expression
            }
        }
        [void]$sb.Append('}')
        # Top level = the pipeline sits directly in the end block of the root script block
        # (PowerShell 7 may wrap it in a pipeline chain first).
        $cont = $p.Parent
        while (($null -ne $cont) -and ($cont -isnot [NamedBlockAst]) -and $cont.PSObject.TypeNames[0].EndsWith('.PipelineChainAst')) {
            $cont = $cont.Parent
        }
        if (($cont -is [NamedBlockAst]) -and [object]::ReferenceEquals($cont.Parent, $root)) { $nested = 'false' }
    } else {
        [void]$sb.Append('null')
    }
    [void]$sb.Append(',"nested":' + $nested + '}')
}

function Add-StrList($list) {
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $list) { $parts.Add((J $s)) }
    [void]$script:Sb.Append('[' + ($parts -join ',') + ']')
}

# Parses one request; leaves the reply (after the id) in $script:Sb. Throws 'too-large' or any
# other error; the caller turns both into an error reply.
function New-Reply([string]$b64) {
    if ($b64.Length -gt $script:MaxB64Chars) { throw 'too-large' }
    $bytes = [System.Convert]::FromBase64String($b64)
    if ($bytes.Length -gt $script:MaxTextBytes) { throw 'too-large' }
    $text = $script:StrictUtf8.GetString($bytes)

    $tokens = $null
    $errors = $null
    $root = [Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
    # Keep only the nodes that matter: commands, statements that are not plain pipelines, and
    # expressions other than literals and variables. (Cheaper than classifying every node.)
    $pred = [System.Func[Ast, bool]] {
        param($a)
        # An expression statement with a redirection ('x' > file, $a >> f) writes a file although it
        # is no CommandAst: report it as a command whose name is an expression.
        if ($a -is [CommandExpressionAst]) { return ($a.Redirections.Count -gt 0) }
        if ($a -is [CommandBaseAst]) { return ($a -is [CommandAst]) }
        if ($a -is [PipelineAst]) { return $false }
        if ($a -is [StatementAst]) { return $true }
        if ($a -is [ExpressionAst]) {
            return -not (($a -is [ConstantExpressionAst]) -or ($a -is [VariableExpressionAst]) -or
                ($a -is [ExpandableStringExpressionAst]) -or ($a -is [ArrayLiteralAst]))
        }
        return $false
    }
    $nodes = $root.FindAll($pred, $true)
    if ($nodes.Count -gt $script:MaxNodes) { throw 'too-large' }

    $cmds = [System.Collections.Generic.List[object]]::new()
    $compound = [System.Collections.Generic.List[string]]::new()
    $dynamic = [System.Collections.Generic.List[string]]::new()
    foreach ($n in $nodes) {
        if (($n -is [CommandAst]) -or ($n -is [CommandExpressionAst])) {
            $cmds.Add($n)
        } else {
            $short = TypeShort $n
            if ($n -is [ExpressionAst]) {
                if ($script:DynamicTypes.ContainsKey($short) -and -not $dynamic.Contains($short)) { $dynamic.Add($short) }
            } elseif (-not $compound.Contains($short)) {
                $compound.Add($short)
            }
        }
    }
    if ($cmds.Count -gt $script:MaxCommands) { throw 'too-large' }

    $sb = $script:Sb
    [void]$sb.Append('"ok":true,"parse_errors":[')
    $first = $true
    $count = 0
    foreach ($e in $errors) {
        if ($count -ge $script:MaxErrors) { break }
        $count++
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        [void]$sb.Append('{"msg":' + (JClip $e.Message 300) + ',"line":' + $e.Extent.StartLineNumber + ',"col":' + $e.Extent.StartColumnNumber + '}')
    }
    [void]$sb.Append('],"commands":[')
    $first = $true
    foreach ($c in $cmds) {
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        Add-Command $c $root
    }
    [void]$sb.Append('],"compound":')
    Add-StrList $compound
    [void]$sb.Append(',"dynamic":')
    Add-StrList $dynamic
    [void]$sb.Append(',"mode":' + (J $script:Mode) + '}')
}

function Get-LineReply([string]$line) {
    $m = [System.Text.RegularExpressions.Regex]::Match($line, '^\{"id":"([0-9a-f]{1,64})","b64":"([A-Za-z0-9+/=]*)"\}$')
    if (-not $m.Success) { return '{"id":"","ok":false,"error":"internal"}' }
    $id = $m.Groups[1].Value
    [void]$script:Sb.Clear()
    $err = $null
    try {
        [void]$script:Sb.Append('{"id":"' + $id + '",')
        New-Reply $m.Groups[2].Value
    } catch {
        $err = if ($_.Exception.Message -eq 'too-large') { 'too-large' } else { 'internal' }
    }
    if ($null -ne $err) {
        return ('{"id":"' + $id + '","ok":false,"error":"' + $err + '"}')
    }
    return $script:Sb.ToString()
}

# ---- start-up --------------------------------------------------------------------------------
$script:Mode = $ExecutionContext.SessionState.LanguageMode.ToString()
if ($script:Mode -eq 'FullLanguage') {
    try {
        $t0 = $null
        $e0 = $null
        $null = [Parser]::ParseInput('Get-Date', [ref]$t0, [ref]$e0)
    } catch {
        # Parsing works only in full language mode; whatever stops it makes the helper useless.
        $script:Mode = 'Unusable'
    }
}
# Run the whole pipeline once on fixed samples (JIT and type loading cost ~0.3 s on the first
# request otherwise). The samples are constants of this file, never user input.
foreach ($sample in @(
        'Get-ChildItem -Path "$env:TEMP\x$(1)" -Recurse:$true 1,2 @a 5 ''q'' | ForEach-Object { $_.Name; [IO.Path]::GetTempPath() } > out.txt 2>&1; $x = if ($a) { "b" }',
        'a && b ; rm -rf x < y')) {
    try {
        $null = Get-LineReply ('{"id":"00","b64":"' + [System.Convert]::ToBase64String($script:Utf8.GetBytes($sample)) + '"}')
    } catch {
        $null = $_
    }
}
[void]$script:Sb.Clear()
$ready = '{"ready":true,"mode":"' + $script:Mode + '","version":"' + $PSVersionTable.PSVersion.ToString() + '"}'
$script:Out.WriteLine($ready)

# ---- main loop -------------------------------------------------------------------------------
while ($true) {
    $line = $script:In.ReadLine()
    if ($null -eq $line) { break }
    $line = $line.TrimStart([char]0xFEFF).Trim()
    if ($line.Length -eq 0) { continue }
    $reply = '{"id":"","ok":false,"error":"internal"}'
    try {
        # @(...) swallows anything a callee might leak into the output stream; the reply is last.
        $got = @(Get-LineReply $line)
        $reply = [string]$got[$got.Count - 1]
    } catch {
        $null = $_
    }
    $script:Out.WriteLine($reply)
}
