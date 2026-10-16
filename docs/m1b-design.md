# M1b 设计契约（PowerShell 方言归一化；实现者先读这份）

读之前先读 `docs/m1-design.md`（M1 的底线与数据模型，全部继续适用）、`PROJECT_SPEC.md` §5.1"命令方言"。M1b 的目标：`PowerShell` 工具的命令归一化成和 Bash 一样的 `Action` 列表。**解析不了、含动态构造、拿不准一律灰色**。

```
event.py (PowerShell 工具)
  └─ psparse.parse_powershell(text) -> BashResult        # 与 Bash 同一个结果类型
       ├─ pshelper.ps1 (长驻 powershell.exe, 只调用 Parser::ParseInput, 只返回 JSON)
       └─ pscmd.build(result_json) -> BashResult          # JSON -> SimpleCmd/Word/Redirect
  └─ programs.classify(program, args, shell="powershell", ...)  -> psprograms.classify_ps(...)
       ├─ psaliases (别名与规范参数名，静态数据)
       └─ 复用 paths / domains / programs 里的外部程序表
```

## 1. 与 M1 的接缝（尽量不改 M1 代码）

- `psparse.parse_powershell(command, *, budget_s=0.3) -> BashResult`：`event._shell_actions` 对 `shell == "powershell"` 改用它，其余循环（cd 跟踪、路径、域名、`Action` 构造）与 Bash **完全同一段代码**。`BashResult.gray` 非空时整行灰色；解析器未就绪、超时、熔断、PowerShell 缺失都返回 `BashResult(commands=(), gray=("ps-helper-...",))`，绝不抛异常、不阻塞超过 `budget_s`。
- `SimpleCmd.argv[0].text` 是**规范 cmdlet 名**（别名已还原，保持规范大小写如 `Remove-Item`）或外部程序名（`git`、`curl.exe`）。参数按源码顺序放进 `argv[1:]`：参数名统一成 `-RealName`（完整规范名，冒号写法 `-Path:x` 拆成 `-Path` 和 `x` 两个词，开关参数只有 `-Name`），其值是紧随其后的 `Word`（`expands` / `glob` 按 PowerShell 语义设置）。位置参数不带参数名，按出现顺序保留。无法确定归属的参数（缩写不唯一、未知 cmdlet 的参数）原样保留并让该行灰色。
- 重定向进 `SimpleCmd.redirects`（`>`、`>>`、`2>`、`*>`、`2>&1`…），目标是 `Word`。管道段 `in_pipeline=True`；`&`（调用）、`.`（点源）见第 5 节。
- `programs.classify(..., shell="powershell")`：把 M1 里返回 `powershell-not-classified` 的分支改成调用 `psprograms.classify_ps(program, args, redirects=..., env=...)`，返回同一个 `CmdInfo`（paths / urls / network / tags / gray / flags / subcommand）。`flags` 放规范参数名（含开关，如 `-Recurse`、`-Force`），规则的 `flags_any` 对 PowerShell 不区分大小写（M1 matcher 已按 shell 处理）。
- 路径方言：`paths.normalize_path(..., dialect="powershell")` 已存在；变量规则见第 4 节。

## 2. 辅助进程（`pshelper.ps1` + `psparse.py`，实现者 A）

**进程**：`powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File pshelper.ps1`（优先 `pwsh.exe` 7+ 若存在，否则 5.1；与 Claude Code 的自动检测一致：先找 `pwsh` 再回退 `powershell`）。环境变量**最小化**：只传 `SystemRoot`、`SystemDrive`、`windir`、`PATH`、`TEMP`、`TMP`、`USERPROFILE`（解析器不需要，但 PowerShell 启动要）；绝不继承 `*TOKEN*`、`*KEY*`、`*SECRET*`、`ANTHROPIC*`、`CLAUDE*` 等。无窗口（`CREATE_NO_WINDOW`）。辅助进程不得出现 `Invoke-Expression`、点源、`Add-Type`、`& $x`、`New-Object`、反射：用户文本只作为数据传给 `[System.Management.Automation.Language.Parser]::ParseInput`。

**协议**（stdin/stdout 各一行 JSON，UTF-8 无 BOM，`[Console]::InputEncoding/OutputEncoding` 显式设 UTF-8）：
请求 `{"id":"<hex>","b64":"<base64 of utf-8 text>"}`；应答 `{"id":"<hex>","ok":true,"parse_errors":[{"msg":"...","line":1,"col":5}],"commands":[...],"compound":["IfStatementAst",...],"dynamic":["SubExpressionAst",...],"mode":"FullLanguage"}` 或 `{"id":..,"ok":false,"error":"too-large|internal"}`。请求文本 ≤ 1 MiB（Python 侧先检查，超限直接灰色）；应答 ≤ 4 MiB，超限视为失败。启动后辅助进程先写一行 `{"ready":true,"mode":"FullLanguage","version":"5.1.x"}`；`mode` 不是 `FullLanguage`（约束语言模式）→ Python 侧置"不可用"，整体灰色，`doctor` 报告。

**JSON 形状**（序列化函数是辅助进程里**唯一**复杂的代码，保持小而纯，只读 AST）：
- `commands`：脚本里**每一个** `CommandAst`（用 `FindAll({$args[0] -is [CommandAst]}, $true)` 取，嵌套在子表达式、脚本块、控制语句里的也要在内；顺序为源码位置顺序）。每项：
  `{"pos":[start,end],"invoke":"" | "&" | ".", "name":{"kind":"bare|single|double|expandable|variable|expr","v":"Remove-Item"},"elements":[E...],"redirects":[{"op":">|>>|2>|...","target":E|null,"merge":"2>&1"|null}],"stage":{"index":0,"of":3}|null,"nested":bool}`
  其中 `nested` 表示这个命令在子表达式 / 脚本块 / 语句体内（不是顶层管道的元素）。
- `E`（命令元素）：`{"t":"param","name":"Recurse","arg":E|null}`、`{"t":"str","kind":"bare|single|double|singlehere|doublehere","v":"text"}`、`{"t":"expstr","v":"raw text","vars":["env:USERPROFILE","x"],"subexpr":bool}`、`{"t":"var","name":"env:USERPROFILE","splat":false}`、`{"t":"num","v":"5"}`、`{"t":"array","items":[E...]}`、`{"t":"other","ast":"ScriptBlockExpressionAst","text":"..."}`（任何不认识的节点：文本保留，**按动态处理**）。
- `compound`：脚本里出现的所有**非简单管道**语句类型名（`IfStatementAst`、`ForEachStatementAst`、`WhileStatementAst`、`TryStatementAst`、`SwitchStatementAst`、`FunctionDefinitionAst`、`AssignmentStatementAst`、`TrapStatementAst`、`UsingStatementAst`、`DataStatementAst`…）。出现任一 → 整行灰色（但 `commands` 里仍然要有它们里面的命令，让 deny 规则能命中）。
- `dynamic`：出现的动态构造节点类型名（`SubExpressionAst`、`ScriptBlockExpressionAst`、`InvokeMemberExpressionAst`、`MemberExpressionAst`、`TypeExpressionAst`、`ConvertExpressionAst`、`IndexExpressionAst`、`ExpandableStringExpressionAst` 里含 `$(`…）→ 灰色并按第 5 节加 `exec` 标签。
- 5.1 不认识的 `&&`、`||`、三元 `?:`、`??`：`parse_errors` 非空 → 整行灰色（`ps-parse-error`）。

**进程管理**（Python 侧，`psparse.py`）：守护进程启动时后台预热（线程），`ready` 前的调用立即返回 `("ps-helper-not-ready",)`；单次调用硬超时（默认 0.3 s，由 `budget_s` 控制；超时 → 灰色 `ps-helper-timeout`，并把这个进程判死、杀掉、重启）；崩溃/EOF/应答非法 → 灰色 `ps-helper-crashed`，指数退避重启（0.5 s 起，上限 30 s）；连续 5 次失败 → 熔断 `ps-helper-disabled`（此后一直灰色，直到 `reset()`）；存活上限 30 分钟或处理 2000 次请求后回收重建（防泄漏）；同一时刻最多一个在途请求（锁），排队超过预算 → 灰色 `ps-helper-busy`；`shutdown()` 保证杀掉子进程（守护进程退出时调用，且子进程随父进程消失：Windows Job Object 或 `atexit` 加 `terminate`，两者择一做可靠）；所有异常内部消化。对外：`parse_powershell()`、`status() -> dict`（`state`: warming|ready|disabled|unavailable、`failures`、`mode`、`version`、`warmup_ms`，给 `ping` 与 `doctor` 用）、`warm_up()`、`shutdown()`、`reset()`。可注入的 `spawn` 工厂（测试用假进程，不要求真 PowerShell）。

## 3. JSON → SimpleCmd（`pscmd.py`，实现者 B）

`build(reply: dict, *, source: str) -> BashResult`：对 `reply["commands"]` 每项产出 `SimpleCmd`（`origin` 为 `top` / `subexpr` / `scriptblock`）。规则：
- **命令名**：`psaliases.canonical_command(name)` 还原（别名、大小写、带 `.exe` 的外部程序名：`git.exe` → `git`；路径限定的外部程序同 M1）；还原不唯一或名字是动态的（`kind` 为 `variable` / `expr` / `expandable` 含变量）→ `gray` `ps-dynamic-command-name`；`invoke == "&"` 且名字是字面量字符串 → 当作普通调用（`& "C:\x\a.exe"`）；`invoke == "."` → 点源 → `exec_reasons` `ps-dot-source` 加灰色。
- **参数**：`psaliases.canonical_param(cmd, token)` 返回规范名 / `None`（未知）/ `AMBIGUOUS`；`None` 或 `AMBIGUOUS` → 灰色 `ps-param-unresolved:<cmd>:<token>`。`-Name:value` 与 `-Name value` 等价；开关参数后面不吃值（用 `psaliases` 的开关集合判断；不确定的后随词仍然保留为位置参数并**让该命令的路径参数保持可能**）。`-EncodedCommand` / `-enc`（给 `powershell.exe`/`pwsh` 的）→ `exec_reasons` `ps-encoded-command`；`powershell`/`pwsh`/`cmd` 作为被调用的程序 → `exec` + 灰色（外壳嵌套，同 Bash 的 foreign shell）。
- **值（Word）**：`str` 单引号 / 其它字面量 → 不展开；`double`/`expstr`：含 `$var` → `expands=True`（已知变量 `env:*`、`HOME`、`PWD` 交给路径层，其余变量 → 路径层标不确定）；含 `$(`…）→ 灰色 `ps-subexpression`；`var` → `expands=True`；`array` 元素各自展开成独立 Word；`other` → 动态，灰色 `ps-dynamic-value:<ast>`；`glob`：PowerShell 通配符 `*` `?` `[...]` 出现在**未加引号**的裸字或带引号的路径值里都可能被 cmdlet 当通配符（`-Path` 通配，`-LiteralPath` 不通配），按参数是否 `-LiteralPath` 设置 `glob`。反引号（`` ` ``）转义/续行：`str kind=bare` 里的反引号已由 AST 处理成值，**不要**自己再解析；但命令文本里出现反引号续行造成的拼接，只要 AST 给出的值是字面量就当字面量，值里含反引号字符本身则灰色 `ps-backtick`。
- **其他灰色**（`gray`，并给 `exec_reasons` 的以 `E` 标）：`compound`（`ps-compound:<type>`）、`dynamic`（`ps-dynamic:<type>`，`E`）、`parse_errors`（`ps-parse-error`）、`Invoke-Expression`/`iex`（`E`）、`Invoke-Command`/`icm`（`E`）、`Start-Process`/`saps`/`start`（`E`）、`Add-Type`、`New-Object -ComObject`、`Invoke-WmiMethod`/`Invoke-CimMethod`、`[scriptblock]::Create`（`InvokeMemberExpressionAst` 已覆盖）、`Import-Module` 指向路径、`.\x.ps1` / `& .\x.ps1` / `& $x` / 调用任何 `.ps1`/`.bat`/`.cmd`/`.vbs`/`.js` 文件（脚本间接执行，`E`）、`cmd /c`、`wsl`（同 Bash 的 wsl 规则，其后命令按 Bash 重新解析不在 M1b 范围：灰色）。
- 管道：段间 `in_pipeline=True`；`stage` 信息用于 `in_pipeline`。把管道末段是 `Invoke-Expression`/`iex` 或 `powershell`/`pwsh` 读 stdin（`| iex`、`| powershell -`）→ `exec_reasons` `ps-pipe-to-interpreter`。
- 任何内部错误 → `BashResult(commands=已得到的, gray=("ps-internal-error",))`。

## 4. cmdlet 知识表（`psprograms.py`，实现者 B）

`classify_ps(program, args, *, redirects, env) -> CmdInfo`（`args` 是第 1 节形状的 Word 序列）。数据表，不是零散代码（沿用 programs.py 的风格）：

- **读**：`Get-Content`（`-Path`/`-LiteralPath`）、`Get-ChildItem`（`-Path`）、`Get-Item`、`Get-ItemProperty`（含注册表提供程序）、`Select-String -Path`、`Test-Path`、`Get-FileHash`、`Import-Csv`、`Import-Clixml`、`Get-Acl`、`Resolve-Path`、`Measure-Object`（无路径）。位置参数 0 是 `-Path`。
- **写**：`Set-Content`、`Add-Content`、`Out-File`（`-FilePath`）、`Export-Csv`/`Export-Clixml`、`New-Item`（`-Path`/`-Name`，`-ItemType`）、`Remove-Item`（`-Recurse`、`-Force` 进 flags）、`Move-Item`、`Copy-Item`（源读、`-Destination` 写，目录目的地按 M1 的"目录加子名"约定列合成子路径）、`Rename-Item`、`Set-ItemProperty`、`New-ItemProperty`、`Remove-ItemProperty`、`Clear-Content`、`Set-Acl`、`Expand-Archive`（`-DestinationPath`）、`Compress-Archive`（`-DestinationPath` 写）、重定向目标。
- **联网**：`Invoke-WebRequest`/`iwr`/（5.1 里 `curl`/`wget` 别名指向它）、`Invoke-RestMethod`/`irm`、`Start-BitsTransfer`、`Send-MailMessage`、`Test-NetConnection`、`Resolve-DnsName`、`New-PSSession`/`Enter-PSSession`（`-ComputerName` 主机）；`-Uri` 值给 `urls`；`-OutFile` 是写路径；`-InFile` 读路径；代理参数（`-Proxy`）的主机也列进 `urls`。
- **提供程序路径**：`HKLM:`、`HKCU:`、`HKCR:`、`HKU:`、`Env:`、`Cert:`、`WSMan:`、`Alias:`、`Function:`、`Variable:`（这些路径不是文件）→ 不列入文件 `paths`，打 `config_tamper` 标签 + 灰色 `ps-provider-path:<drive>`；`Env:`/`Set-Item Env:X` 同理。`FileSystem::C:\x` 形式（`Microsoft.PowerShell.Core\FileSystem::`）还原为文件路径。
- **系统与持久化**（打标签并灰色，具体 deny/ask 由策略层决定）：`Set-ExecutionPolicy`、`Register-ScheduledTask`、`New-ScheduledTask*`、`Set-Service`/`New-Service`/`Remove-Service`、`Set-MpPreference`/`Add-MpPreference`（`-ExclusionPath`）、`New-NetFirewallRule`、`Set-NetFirewall*`、`Enable-PSRemoting`、`Disable-WindowsOptionalFeature`、`reg`/`reg.exe`、`schtasks`、`sc.exe`、`netsh`、`wmic`（同 M1 的 windows-persistence-commands 外部程序）、`Stop-Process`/`Stop-Service` 无标签。
- **外部程序**：不是 cmdlet 的名字当外部程序，调用 `programs.classify(name, args_as_bash_style, shell="bash")` 的同一张表（`git`、`curl.exe`、`npm`、`pip`、`docker`…）；PowerShell 的 `-` 开头长参数与 bash 风格不同的程序（`git`）无需特殊处理。
- **flags**：规范参数名（含开关）；`subcommand`：外部程序沿用 M1 规则；cmdlet 无 subcommand（动词-名词本身就是 program）。
- **风险标签**：沿用 `programs.derive_risk_tags` 这个唯一入口（M1b 只扩展它的输入，不另起一套）。
- 未知 cmdlet / 未知外部程序：`known=False`，所有看起来像路径的位置参数按 `unknown` 访问列出，像 URL 的进 `urls`，不灰色（和 Bash 的未知程序一致，由规则取舍）。

## 5. 别名与参数（`psaliases.py`，实现者 C）

数据 + 查询函数，零运行时依赖 PowerShell：
- `ALIASES: dict[str, str]`（小写别名 → 规范 cmdlet 名；覆盖 5.1 内置别名：`ls dir gci`→`Get-ChildItem`，`cat gc type`→`Get-Content`，`rm del erase rd rmdir ri`→`Remove-Item`，`cp copy cpi`→`Copy-Item`，`mv move mi`→`Move-Item`，`ren rni`→`Rename-Item`，`curl wget iwr`→`Invoke-WebRequest`，`irm`→`Invoke-RestMethod`，`iex`→`Invoke-Expression`，`icm`→`Invoke-Command`，`saps start`→`Start-Process`，`sc`→`Set-Content`，`ac`→`Add-Content`，`sl cd chdir`→`Set-Location`，`echo write`→`Write-Output`，`gp sp`→`Get/Set-ItemProperty`，`select`→`Select-Object`，`sls`→`Select-String`，`%`→`ForEach-Object`，`?`→`Where-Object`，`iwr` 等，以真实 `Get-Alias` 输出为准）。**不依赖 `ResolvedCommandName`**。
- `CMDLETS: dict[str, CmdletSpec]`（规范名小写 → 规范名、参数集：每个参数的规范名、是否开关、位置序号、是否接受路径通配）。至少覆盖第 4 节列出的所有 cmdlet 与它们的公共参数（`-ErrorAction`、`-Verbose`、`-WhatIf`、`-Confirm`…）。
- `canonical_command(name) -> str | None`：别名→规范名；已是规范名（不区分大小写）→规范形；是外部程序（有扩展名 `.exe` 或带路径）→ 原样（交给外部程序表）；否则 `None`。
- `canonical_param(cmdlet, token) -> str | None | AMBIGUOUS`：不区分大小写；完整名、或**唯一前缀**缩写（`-Rec` → `-Recurse`）；不唯一 → `AMBIGUOUS`；cmdlet 未知或前缀无匹配 → `None`。`-Name:value` 的冒号由调用方先拆开。`takes_value(cmdlet, canonical_param) -> bool | None`（None=不确定）。
- **Windows 一致性测试**（标 `windows`）：对表里每个别名与 cmdlet，用真实 `Get-Alias` / `Get-Command X` 的 `Definition` 与 `Parameters` 比对（别名目标相同、每个声明的参数确实存在、开关标记一致、每个"唯一前缀"确实唯一）；差异即失败。测试用 `subprocess` 起 `powershell.exe -NoProfile`，没有 PowerShell 就跳过，绝不执行用户文本。

## 6. 灰色原因与 `exec` 标签总表

`ps-helper-not-ready` `ps-helper-timeout` `ps-helper-crashed` `ps-helper-disabled` `ps-helper-busy` `ps-helper-unavailable`（找不到 PowerShell / 约束语言模式）· `ps-parse-error` `ps-compound:<T>` `ps-dynamic:<T>` `ps-dynamic-command-name` `ps-dynamic-value:<T>` `ps-subexpression` `ps-backtick` `ps-param-unresolved:<cmd>:<tok>` `ps-provider-path:<drive>` `ps-dot-source`(E) `ps-encoded-command`(E) `ps-pipe-to-interpreter`(E) `ps-script-exec`(E) `ps-nested-shell`(E) `ps-internal-error` · 以及 M1 的 `cwd-unknown`、`unparseable-url` 等沿用。`E` = 同时进 `exec_reasons`。

## 7. 测试要求（各模块）

- 每个模块 ≥90% 行覆盖；`mypy --strict`；`ruff`；显式 utf-8；Windows 与 Linux 都要过（依赖真 PowerShell 的测试标 `windows`，用 `skip` 而不是失败）。
- **A（psparse）**：假 `spawn` 注入下覆盖全部失败路径（未就绪、超时、崩溃、非法应答、超大应答、超大请求、熔断与 `reset`、回收、`shutdown` 杀进程、并发排队）；真 PowerShell（标 `windows`）下覆盖：中文与 ✓、`& ('i'+'ex')`、反引号、here-string、`$(...)`、嵌套脚本块、5.1 不认识的 `&&`、约束语言模式（用 `$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'` 在辅助进程里模拟不可行时，用假进程返回 `mode`）；辅助进程的环境变量不含密钥（真起一个带 `FAKE_SECRET_TOKEN` 的环境验证）；序列化对任意输入不抛、输出体积有界。
- **B（pscmd/psprograms）**：表驱动 ≥150 条（别名 / 缩写 / 冒号写法 / 位置参数 / 通配 / 变量 / 提供程序 / 重定向 / 管道 / 外部程序 / exec 触发），≥50 条对抗；hypothesis 对任意 JSON 形状（含缺字段、错类型）不抛、非法即灰色。B 用手写的 JSON 夹具（`tests/fixtures/ps_ast/*.json`，由真 PowerShell 生成一次并检入，生成脚本也检入 `scripts/gen_ps_fixtures.py`）。
- **C（psaliases）**：别名表、缩写唯一性、一致性（Windows）、对任意字符串不抛。
- 语料：`tests/corpus/powershell_parse.yaml`（A+B 共用，≥100 条，≥40 对抗，含中文与 ✓）与 `tests/corpus/pipeline_ps_*.yaml`（端到端，默认策略下的判决，两个平台各跑一遍：Linux 上用夹具而不是真 PowerShell，所以端到端语料的 AST 来自检入的 JSON 夹具或假辅助进程——细节见 B 的任务）。

## 8. 我（组装者）负责

`event._shell_actions` 的 PowerShell 分支接线、`programs.classify` 的分发、`daemon/server.py` 里预热与 `shutdown` 与 `ping`/`doctor` 的状态字段、策略规则与 tests、`powershell-dialect.md`、对抗审查与修复、冒烟与报告。
