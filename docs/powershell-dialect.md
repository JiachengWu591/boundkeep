# PowerShell 方言：怎么处理、哪些支持、哪些看不清

> 适用范围：`PowerShell` 工具（Claude Code 在 Windows 上的 shell 工具）的命令，由 M1b 归一化后交给和 Bash 同一套规则。实测只在 **Windows 11 + Windows PowerShell 5.1** 上做过；pwsh 7 与 Linux / macOS 上的 pwsh 是设计目标，没有实测（见"已知缺口"）。boundkeep 不是沙箱：下面所有"拦住"的意思是"规则在命令执行之前给出 deny / ask"，不是隔离。
> 设计契约见 `docs/m1b-design.md`；规则怎么写见 `docs/policy-reference.md` 的"PowerShell 命令的规则写法"（本文不重复）。

## 1. 总体做法：只解析，从不执行

PowerShell 的语法比 Bash 难得多（别名、参数缩写、反引号、here-string、`$(...)`、`& ('i'+'ex')`……），用正则或自写词法器猜很容易被绕过。所以 boundkeep 让 **PowerShell 自己的解析器** 把命令切成语法树，再把语法树翻译成和 Bash 一样的 `Action` 列表：

```
Claude Code 的 PowerShell 工具调用
  → 守护进程 → psparse（辅助进程管理）→ pshelper.ps1（只调用 Parser::ParseInput，只返回 JSON）
  → pscmd（JSON → 命令与参数）→ psprograms / psaliases（cmdlet 知识表、别名与参数缩写）
  → 与 Bash 同一段路径 / 域名 / 规则代码 → allow / ask / deny
```

要点：

- **绝不执行用户文本。** 命令文本只作为数据交给 `[System.Management.Automation.Language.Parser]::ParseInput`，辅助脚本里没有 `Invoke-Expression`、点源、`Add-Type`、`New-Object`、反射（测试会检查这些词不出现在脚本里）。请求经 stdin 以 JSON 行传入（base64 编码的 UTF-8），不拼进命令行。
- **辅助进程是一个长驻的子进程**，由守护进程在启动时后台预热。它的启动参数是 `-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File pshelper.ps1`，没有窗口（`CREATE_NO_WINDOW`），工作目录是临时目录。
- **用哪个 PowerShell**：不搜索 `PATH`（否则放在用户可写 PATH 目录里的假 `pwsh.exe` 就成了裁判）。只认两个管理员才能写的位置：`%ProgramFiles%\PowerShell\<版本>\pwsh.exe`（存在就优先，新的正式版在前），否则固定的 `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`（Windows PowerShell 5.1）。开发机上没有装 pwsh 7，所以实测的是 5.1。
- **环境变量最小化**：只传 `SystemRoot`、`SystemDrive`、`windir`、`PATH`、`TEMP`、`TMP`、`USERPROFILE`；不继承任何令牌、密钥、`ANTHROPIC*`、`CLAUDE*`。
- **脚本被钉住**：第一次启动时读 `pshelper.ps1` 并把 sha256 记在守护进程内存里；之后每次重启都重新计算，不一致就拒绝启动（所有 PowerShell 命令保持灰色）。所以守护进程运行期间有人改磁盘上的脚本不会生效。（残余：校验与 PowerShell 打开文件之间有毫秒级的间隙，没有封死。）
- **Job Object**：Windows 上辅助进程放进一个 `KILL_ON_JOB_CLOSE` 的 Job Object，守护进程即使被强杀，辅助进程也随之消失。万一放不进去（`doctor` 会警告 `powershell-job`），辅助进程仍然可用，但守护进程被硬杀后要自己清理残留的 `powershell.exe`。
- **约束语言模式**：辅助进程如果发现自己不在 `FullLanguage` 模式（比如机器策略强制约束语言模式），解析器不可用，状态变成 `unavailable`，所有 PowerShell 命令灰色，`doctor` 报告。

## 2. 启动、预算与降级

| 事项 | 行为 |
|---|---|
| 预热 | 守护进程启动时后台起辅助进程，约 2 秒（开发机上 1.8 到 2.3 秒）后就绪。**就绪之前，每条 PowerShell 命令都是灰色，原因 `ps-helper-not-ready`，即 ask。** 重启辅助进程期间同理。其他工具（Read、Bash 等）不受影响 |
| 单次预算 | 每条命令的解析预算 0.3 秒（从请求发出算起）。超时 → 灰色 `ps-helper-timeout`，**并杀掉这个辅助进程、后台重启**（约 2 秒内灰色）。排队等别的请求用掉了预算则回答 `ps-helper-busy`，不杀健康的辅助进程 |
| 超时记忆 | 超时的输入（超过 512 字节的）按哈希记住（最多 256 条、10 分钟），再来同样的输入直接灰色，不再去碰辅助进程 |
| 节流 | 一次超时杀进程之后的 30 秒内，超过 2048 字节的输入直接灰色 `ps-input-throttled`；60 秒内被杀 3 次后门槛降到 512 字节。普通的短命令不受影响 |
| 崩溃 | 崩溃、EOF、应答不合协议 → 灰色 `ps-helper-crashed`，按 0.5 秒、1 秒、2 秒……（上限 30 秒）退避重启。辅助进程闲置时自己死掉也会被发现（读线程收到 EOF，守护进程每 2 秒也会检查一次） |
| 熔断 | 连续 5 次启动 / 崩溃 / 协议失败后熔断，状态 `disabled`，灰色 `ps-helper-disabled`。**解析超时不计入失败**（那说明输入慢，不说明辅助进程坏了）。熔断后 60 秒进入半开状态：放行一次探测启动，成功就恢复，失败再等 60 秒 |
| 不可用 | 找不到 PowerShell、或约束语言模式：状态 `unavailable`，灰色 `ps-helper-unavailable`；之后按 30 秒起、翻倍、上限 10 分钟的间隔重新检测 |
| 回收 | 辅助进程存活超过 30 分钟或处理了 2000 个请求后热切换：新的在后台起好再接手，不产生灰色 |
| 大小 | 请求文本 ≤ 1 MiB（超了 → `ps-input-too-large`）；应答 ≤ 4 MiB（超了 → 失败）；文本不是合法 Unicode → `ps-input-invalid` |
| 失败即灰色 | 以上所有失败都是灰色（没有 LLM 后端时即 ask），绝不放行，绝不抛异常 |

没有规则能定案的普通 PowerShell 命令也是 ask。默认策略（M1c 起）为日常的只读与项目内写入命令加了 allow 规则（`Get-ChildItem`、`Get-Content`、`Select-String`、`git status` 等，见 `docs/policy-reference.md` 的"日常 allow 规则"）；M1c-2 又加了数据整理 cmdlet（`allow-ps-data-shaping`）和受信任项目里的开发工具（`allow-devtools-trusted-project`，默认没有受信任的项目）。其余仍然是 ask；**strict 没有这些 allow 规则**。

## 3. 支持的构造

下表里的"路径"都走 M1 的路径规范化，结果和 Bash 的路径一样参与 `no-secret-read`、`rm-outside-project` 等规则。

| 构造 | 怎么处理 | 例子 |
|---|---|---|
| cmdlet 与别名 | 别名在静态表（`psaliases`，与真实 `Get-Alias` 的一致性测试只在 Windows 上跑）里还原成规范名，不区分大小写；规则里写规范名 | `rm` `del` `ri` → `Remove-Item`；`cat` `gc` `type` → `Get-Content`；`ls` `dir` `gci` → `Get-ChildItem`；`curl` `wget` `iwr` → `Invoke-WebRequest` |
| 参数缩写与冒号写法 | 唯一前缀还原成规范参数名（依据 `Get-Command` 的参数集，静态表固化）；`-Path:x` 等价于 `-Path x`；开关参数不吃后面的值 | `rm -r -fo x` = `Remove-Item -Recurse -Force x`；缩写不唯一或不认识 → 灰色 `ps-param-unresolved:<cmdlet>:<参数>` |
| 位置参数 | 按 cmdlet 的位置序号绑定到路径 / 值参数；认不出归属的后随词按"可能是路径"列出（多列不漏列） | `Get-Content .env`、`Copy-Item a b` |
| 变量 | 认识 `$env:NAME`、`$HOME`、`$PWD`、`$PROFILE`（任意大小写，含 `${...}` 写法）和开头的 `~`；`$env:NAME` 取自守护进程的环境（hook 客户端只转发 `CLAUDE_PROJECT_DIR`）。`$PWD` 按"该命令执行时的工作目录"解析（`cd` 之后用的是新目录）。其他变量 → 路径不确定，不会被当成项目内 | `gc $env:USERPROFILE\.ssh\id_rsa`、`gc $HOME\.ssh\id_rsa` |
| `$PROFILE` | 展开成两个候选：`~\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` 与 `~\Documents\PowerShell\...`（不知道是 5.1 还是 7），被 `protect-windows-persistence` 覆盖 | `Add-Content $PROFILE 'x'` → ask |
| 重定向 | `>`、`>>`、`2>`、`*>` 的目标是写路径；`2>&1` 之类的合并没有路径；`$null` 不算 | `echo x > ~\.bashrc` |
| 管道 | 每段单独归一化，段间 `in_pipeline`；任一段灰色则整行灰色。没有路径参数的写类 cmdlet（`Remove-Item`、`Set-Content`、`Copy-Item` 无源……）按"写入管道带来的路径"处理 → 灰色 `arguments-from-pipeline` | `Get-ChildItem \| Remove-Item` → 灰色 |
| 管道的开头（M1c-2） | **以表达式开头的管道**（`'x' \| Get-Content`、`$env:A \| Select-Object`、`(Get-Content f) \| ...`）的开头不是 `CommandAst`，辅助进程的摘要在**后面每一段**的 `stage` 对象里带一个 `head` 字段（`stage.head`，普通元素；超过 4096 字符的字符串被截断成"其他"元素，按动态处理）。归一化层处理：开头是**纯常量**（字符串、数字）且这一段是读文件的 cmdlet（`Get-Content`、`Select-String`、`Get-Item`、`Resolve-Path`、`Test-Path` 等）→ 开头就是该 cmdlet 的**读路径**（`'~\.ssh\id_rsa' \| Get-Content` 现在是 deny）；开头不是纯常量（变量、子表达式、括号表达式、方法调用……）→ 整行灰色 `ps-pipeline-head-dynamic` | `$env:SECRET_TOKEN \| Select-Object` → 灰色；`'..\x' \| Get-Content` → 读项目外的路径 |
| 开发工具（M1c-2） | `pytest`、`ruff`、`mypy`、`black`、`isort`、`flake8`、`pylint`（`psprograms.DEV_TOOLS`）：裸名、`.exe`、路径限定的 `.exe`（`& '.\.venv\Scripts\ruff.exe' check .`，`&` 后接字面量路径），或 `python` / `python3` / `python3.N` / `py`（带或不带 `.exe`）以 `python [-I -u -B -E -s -S -q -O -OO \| -X 项 \| -W 项] -m <工具>` 的形式调用。结果：程序名就是工具、已知、`exec` 标签、**没有灰色原因、没有包装器标记**；操作数是 `unknown` 访问的路径；路径限定的程序把可执行文件的路径作为读路径列出（伪环境变量 `boundkeep-exe-path`，任何命令行都拼不出来）；加载或运行点名文件 / 代码的选项（`-p`、`-c`、`--config`、`--rcfile`、`--init-hook` ……）保留为标志；同一行里先写后运行的可执行文件灰色 `exec-of-written-file`。`python script.py`、`python -c`、`python -m pip` 等仍按解释器处理。哪些放行见 `docs/policy-reference.md` 的"Dev-tools preset" | `pytest -q` → 工具 `pytest`；`python -m mypy src` → 工具 `mypy`，操作数 `src` |
| 目录跟踪 | `cd` / `Set-Location` / `Push-Location`（及 `chdir`、`sl`、`pushd`）跟踪工作目录，包括内置函数 `cd..`、`cd\`；`Pop-Location`、`cd -`、多个参数、动态值 → 工作目录未知（相对路径灰色 `cwd-unknown`） | `cd ..; Get-Content .env` |
| 通配符 | PowerShell 的通配符（`*` `?` `[...]`）**会匹配以点开头的文件**（和 Bash 不同）：`Get-Content *` 在含 `.env` 的项目里会被 `no-secret-read` deny。`-LiteralPath` 的值不当通配符；`-Path` 的才是 | `gc *`、`gc .e*` → deny（项目里有 `.env`）；`gc -LiteralPath 'a[1].txt'` 是字面名 |
| 读 | `Get-Content`、`Get-ChildItem`、`Get-Item`、`Get-ItemProperty`、`Select-String`、`Test-Path`、`Get-FileHash`、`Import-Csv` / `Import-Clixml`、`Get-Acl`、`Resolve-Path`、`Format-Hex` 等 | |
| 写 | `Set-Content`、`Add-Content`、`Clear-Content`、`Out-File`、`Export-Csv` / `Export-Clixml`、`Tee-Object`、`Start-Transcript`、`New-Item`、`Remove-Item`、`Set-Item`、`Set-ItemProperty` 系列、`Set-Acl`、`Compress-Archive` / `Expand-Archive` 的目标等 | |
| 复制、移动、改名 | `Copy-Item`：源读、目的写（目的是目录就列出合成的子路径）；`Move-Item` / `Rename-Item`：**源按读加写计**（移走等于读出并删除）。`-Recurse` 复制目录带来看不见的成员 → 灰色 `directory-write` | `Move-Item .env x.txt` → 读 `.env`，deny |
| 联网 | `Invoke-WebRequest` / `Invoke-RestMethod`（含 `-Uri`、`-Proxy` 的主机）、`Start-BitsTransfer`、`Send-MailMessage`、`Test-NetConnection`、`Resolve-DnsName`、`New-PSSession` / `Enter-PSSession`、`Install-Module` 等；`-OutFile` 是写路径，`-InFile` 是读路径；域名走 `net-allowlist` | |
| 外部程序 | 不是 cmdlet 的名字当外部程序，用和 Bash 同一张程序表（`git`、`curl.exe`、`npm`、`pip`、`docker`……）；`.exe` 去掉。**flags 的大小写**：cmdlet 参数与 `/switch` 不区分大小写，外部程序的短标志区分（`git branch -d` 与 `-D` 是两回事） | |
| robocopy / xcopy | `/switch` 是标志不是路径；第一个位置参数读、第二个写；`/mir` `/purge` `/move` `/mov` 会删除 → 灰色 `ps-destructive-copy:<开关>`（`/move` 同时把源算作写） | |
| net / reg / sc / netsh / wmic / vssadmin / wevtutil 等 | Windows 工具：`/switch` 成为标志，第一个纯字母词成为子命令（`net user bob /add` 的 `user`），供 `ask-net-account-changes` 等规则用 | |
| 系统与持久化 cmdlet | 计划任务、服务、Defender 排除项、防火墙、`Set-ExecutionPolicy`、本地用户与组、WMI / CIM 实例、注册表属性写入、`Restart-Computer`、`Format-Volume`、`Clear-EventLog` 等：打 `config_tamper` 标签并灰色 `ps-system-change:<名字>`；外部程序 `reg` `schtasks` `sc` `netsh` `wmic` `bcdedit` `diskpart` `net` `setx` `takeown` `icacls` `cipher` `shutdown` `dism` `format` 等同理。具体 ask 由 `windows-persistence-commands`、`ask-net-account-changes` 决定 | |
| git | `git restore <路径>` 与 `git checkout -- <路径>` 一样受 `ask-git-discard-paths` 管；`git branch -D` 与 `-d` 分开（标志区分大小写） | |

## 4. 仍然灰色的构造与原因

灰色就是 ask（没有 LLM 后端时）。灰色的行里 deny / ask 规则仍按"已经看清的那部分"匹配（比如 `if ($x) { Get-Content .env }` 里的 `Get-Content .env` 仍会被 deny）。**灰色的 Action 永远不会命中 allow 规则。** 下面的原因出现在审计日志的 `gray_reasons` 里，`boundkeep log` 的文本视图里 `ps-helper-*` 会直接显示。

带 **(E)** 的同时打 `exec` 标签（"运行了我们看不到里面的代码"）。

| 灰色原因 | 触发 | 说明 |
|---|---|---|
| `ps-helper-not-ready` | 辅助进程预热中或重启中 | 守护进程启动后头约 2 秒；超时 / 崩溃后重启的约 2 秒 |
| `ps-helper-timeout` / `ps-helper-crashed` / `ps-helper-busy` / `ps-helper-disabled` / `ps-helper-unavailable` / `ps-helper-error` | 辅助进程的各种失败 | 见第 2 节；`ps-helper-error` 是辅助进程自己回答"失败" |
| `ps-input-throttled` / `ps-input-too-large` / `ps-input-invalid` | 大输入在超时之后被节流 / 超过 1 MiB / 不是合法 Unicode | |
| `ps-parse-error` | 解析器报语法错误 | 包括 5.1 不认识的 `&&`、`\|\|`、三元 `?:`、`??`（这些是 pwsh 7 语法） |
| `ps-compound:<类型>` | `if` / `foreach` / `while` / `try` / `switch` / 函数定义 / 赋值 / `trap` / `using` 等复合语句 | 里面的命令仍被解析并参与匹配 |
| `ps-dynamic:<类型>` (E) | 子表达式 `$(...)`、脚本块 `{ }`、方法调用 `[x]::M()`、成员访问、类型转换、索引、二元 / 一元 / 三元表达式、`@(...)` 等 | 值在运行时才知道 |
| `ps-dynamic-value:<类型>` | 命令参数是括号表达式、脚本块、展开 `@splat` 等看不清的节点 | 文本保留，当动态值处理 |
| `ps-subexpression` | 双引号字符串里含 `$(...)` | |
| `ps-backtick` | 值里含反引号字符本身 | 反引号转义和续行由 AST 处理，不自己再解析 |
| `ps-stop-parsing` | `--%`（停止解析符号） | 其后的词被拆开列出，但整行灰色 |
| `ps-dynamic-command-name` (E) | 命令名是变量或表达式：`& $x`、`& ('i'+'ex')` | |
| `ps-alias-shadowed` (E) / `ps-alias-redefined` | 同一行里用 `Set-Alias` / `New-Alias` 重定义了别名（或名字不可知），之后的同名命令含义不再可信 | |
| `ps-implicit-get-verb` | 裸名 `Content x`（PowerShell 会当成 `Get-Content x`） | 按 `Get-Content` 归一化并灰色 |
| `ps-param-unresolved:<cmdlet>:<参数>` | 参数缩写不唯一、cmdlet 或参数不认识 | 例如 `Get-ChildItem -r`：提供程序动态参数使 `-r` 有歧义 |
| `ps-provider-path:<盘>` | `HKLM:`、`HKCU:`、`Env:`、`Cert:`、`WSMan:`、`Alias:`、`Function:`、`Variable:`、`Registry::` 路径 | 不是文件路径，打 `config_tamper`，见下节缺口 |
| `ps-dot-source` (E) | `. .\x.ps1` 点源 | |
| `ps-encoded-command` (E) | `powershell -EncodedCommand` / `-enc` | |
| `ps-pipe-to-interpreter` (E) | `... \| iex`、`... \| powershell -` 等把管道当代码 | |
| `ps-pipeline-head-dynamic` | 以变量、子表达式、括号表达式等**不是纯常量**的表达式开头的管道（`$env:SECRET_TOKEN \| Select-Object`、`$x \| Out-String`、`(Get-Content f) \| ...`） | 值流进后面的每一段，却没有命令代表它（M1c-2 起；之前整行不带任何标记） |
| `ps-script-exec` (E) | 调用脚本文件（`.ps1` `.bat` `.cmd` `.vbs` `.js` `.py` `.msi` `.lnk` 等）或路径限定的非 `.exe` | |
| `ps-nested-shell` (E) | `powershell` `pwsh` `cmd` `wsl` `bash` `sh` `wscript` `cscript` `mshta` `rundll32` `regsvr32` 等 | |
| `ps-exec:<名字>` (E) | `Invoke-Expression`（`iex`）、`Invoke-Command`（`icm`）、`Start-Process`（`saps`、`start`）、`Invoke-Item`、`Add-Type`、`Invoke-WmiMethod` / `Invoke-CimMethod`、`Start-Job`、`Register-ScheduledJob` / `Register-ObjectEvent`、构建运行器、`Import-Module <路径>`、`New-Object -ComObject` | |
| `ps-build-tool:<程序>` | `msbuild` `make` `gradle` `mvn` `cmake` `dotnet`（`--info` 除外）等 | 它们会运行项目自己的构建脚本 |
| `ps-system-change:<名字>` | 系统与持久化类 cmdlet / 外部程序 | 见第 3 节 |
| `ps-destructive-copy:<开关>` | `robocopy /mir` `/purge` `/move` | 见缺口：没有对应的 ask 规则 |
| `ps-remote-copy` / `ps-link-creation` / `ps-variable-assign` / `ps-file-url` | `Copy-Item -ToSession`；`New-Item -ItemType SymbolicLink / Junction / HardLink`；`Set-Variable` / `New-Variable`；写入 `file:` URL | |
| `ps-too-large` / `ps-internal-error` / `ps-invalid-text` | 回复或参数超过上限、内部错误、非法文本 | 一律灰色 |
| 非 `ps-` 前缀 | `arguments-from-pipeline`、`directory-write`、`archive-members-unknown`（`Expand-Archive`）、`dynamic-program`、`env-code-injection:<变量>`、`cwd-unknown`、`unparseable-url`、`exec-of-written-file`、`normalize-budget-exceeded` | 与 Bash 共用 |

## 5. 已知无法处理的写法 / 已知缺口

每条都不会变成 allow；下面是"仍然看不清"或"没有规则可用"的清单。除非特别说明，结果都是灰色（ask）或"没有规则命中"（也是 ask）。

**策略语言的缺口（需要改策略 schema 才能补）**

1. **提供程序与注册表路径只能灰色，不能被 `path_glob` 匹配。** `HKLM:`、`HKCU:`、`Registry::`、`Env:` 等不是文件路径，不进 `paths`。后果：注册表删除、`New-Item` / `Set-Item` / `Remove-Item` 作用于注册表没有任何规则（只有 `Set-ItemProperty` / `New-ItemProperty` / `Remove-ItemProperty` 等按程序名在 `windows-persistence-commands` 里）；读环境变量（`Get-ChildItem Env:`、`echo $env:API_KEY`）没有规则。它们都会因为灰色而 ask，但 deny 做不到。
2. **`/switch` 词无法用 `flags_any` 匹配。** 策略 schema 要求 `flags_any` 的条目以 `-` 开头，所以 `net user bob /add`、`robocopy a b /mir` 的 `/add`、`/mir` 写不进规则。`net` 靠子命令（`ask-net-account-changes`）；`robocopy /mir` `/purge` `/move` 只有灰色 `ps-destructive-copy:*`，没有 ask 规则。
3. **`format` 不在 `ask-disk-tools` 里**（只有 `Format-Volume`、`diskpart` 等）。`format` 作为外部程序仍会得到灰色 `ps-system-change:format`，所以是 ask，但不是由规则命中的。

**解析与归一化的缺口**

4. **（M1c-2 已关闭）管道开头的字面量**：`"~\.ssh\id_rsa" | Get-Content` 以前灰色且没有 deny；现在辅助进程的摘要在后续各段带 `stage.head`，纯常量开头成为读文件 cmdlet 的读路径（命中 `no-credential-store-read` / `no-secret-read` 就是 deny），非常量开头整行灰色 `ps-pipeline-head-dynamic`。仍然看不清的：开头是 `(Get-Content f)` 这类括号表达式时，括号里的命令按子表达式灰色，不做路径推断。
4a. **（X1 审查 H-4 已收紧）非路径参数里的展开**：`ConvertTo-Json $env:SECRET_TOKEN`（第一个位置参数就是 `-InputObject`）会把值原样打印，`Select-Object -Property $env:X` 把值当列标题，`Get-Date $env:X`、`Get-Content a.txt -TotalCount $env:X` 在报错里回显。现在 allow 名单上的 cmdlet（数据整形与无路径的那些，以及读类的 `Get-Content`、`Select-String`、`Test-Path`、`Get-Item`、`Resolve-Path`、`Get-ChildItem`、`Set-Location`）的参数里只要有展开（`$true` / `$false` / `$null` 除外），且那不是一个交给路径层判断的路径，就是灰色 `ps-dynamic-arg`。名单之外的 cmdlet 没有变化（它们本来就没有 allow 规则，是灰色或 ask）。
4b. **（X1 审查 H-1 到 H-3）开发工具**：参数里任何以 `@` 开头的词（带引号的 `'@args.txt'` 在 PowerShell 里是普通字符串，会原样交给 ruff / pytest / mypy 当参数文件）是灰色 `devtool-argument-file`；pylint 的 `--output-format` / `-f` 的值不是内置报告器名是灰色 `devtool-output-format`。PowerShell 没有行内环境变量前缀，`devtool-env-prefix` 只在 Bash 方言出现。
5. **计算出来的路径**：`$(Join-Path ...)`、`(Join-Path ...)`、成员访问如 `$PROFILE.CurrentUserAllHosts`、`('a' + 'b')` 都是动态值，灰色。
6. **`$PROFILE` 假定默认的 Documents 位置。** Documents 被 OneDrive 重定向时，`$PROFILE` 指向的真实路径不会被跟随；直接写出真实路径时被 `**/documents/...` 规则覆盖。
7. **UNC / 网络路径不算联网**：`\\host\share` 被当作普通（项目外）路径，不进 `domains`，`net-allowlist` 看不到。
8. **祖先目录的递归读取**：`Get-ChildItem ~ -Recurse -Filter id_rsa | Get-Content` 灰色（规则按具体路径匹配，不认"递归读祖先"；与 M1 报告的同一设计缺口）。
9. **.NET、COM、`Add-Type`**：`[IO.File]::ReadAllText(...)`、`[System.Net.WebClient]`、`New-Object -ComObject`、`Add-Type` 都灰色并打 `exec`；不分析其内部。
10. **`Get-ChildItem -r` 这类有歧义的缩写**灰色（提供程序动态参数使唯一前缀不唯一）；写全名 `-Recurse` 就清楚。
11. **已知的小缺口**：数组实参（`a,b`）展平后元素可能绑到错误的位置槽，只会多列路径；`dotnet` 等构建工具一律当作会运行代码。

**辅助进程的缺口**

12. **不同的小输入反复超时仍可能各花一次重启。** 2048 字节以内、每次都不一样、每次都超过 0.3 秒预算的输入，哈希缓存和节流都挡不住：每条可能让辅助进程被杀并重启一次（约 2 秒灰色）。缓解：哈希缓存 + 节流；熔断不会被它触发。
13. **超时会杀掉唯一共享的辅助进程**（重启约 2 秒），没有热备。重启期间所有 PowerShell 命令灰色（ask），不会放行。
14. **脚本钉住有毫秒级间隙**：校验 `pshelper.ps1` 的哈希与 PowerShell 打开它之间没有封死。
15. **只验证了 Windows PowerShell 5.1。** 若装了 pwsh 7（`%ProgramFiles%\PowerShell\<版本>`），会优先使用它；那条路径与 Linux / macOS 的 pwsh 都没有实测。pwsh 7 的语法（`&&` `||` `?:` `??`）在 5.1 里是解析错误 → 灰色。
16. **机器策略与辅助进程**：如果机器策略把执行策略设成 `AllSigned` 且无法被 `-ExecutionPolicy Bypass` 覆盖，辅助脚本（未签名）无法启动，状态变成 `disabled` / `unavailable`，PowerShell 命令全部灰色。这一点没有在真实的受管机器上验证。

**使用上的后果**

17. **没有命中任何规则的普通 PowerShell 命令仍会 ask**（默认策略的 allow 规则只覆盖日常的只读、数据整理与项目内写入，strict 没有）。
18. **`Get-Content *`、`Get-ChildItem *` 在含 `.env` 的项目里现在会 deny**：PowerShell 的通配符确实匹配点开头的文件（与 Bash 不同），boundkeep 按真实语义展开。想读别的文件请写具体文件名。

## 6. 如何排查

- `boundkeep doctor`：daemon 一行里有守护进程的状态文本，其中 `powershell=<状态>`（`ready` | `warming` | `disabled` | `unavailable`），异常时还有 `powershell_retry_s=<秒>`（距离下次探测）、`powershell_throttled_s=<秒>`（节流剩余）、`powershell_job=no`（没放进 Job Object）。另有 `powershell-parser` 一项：`ready` 是 OK，`warming` 是 INFO（启动约 2 秒），`disabled` / `unavailable` 是 WARN 并给出原因与修法；`powershell-job` 警告对应 `powershell_job=no`。（没有单独的 `boundkeep ping` 子命令；daemon 的 ping 文本就显示在 `doctor` 里。）
- `boundkeep log --tail 20`：被辅助进程问题灰色的命令显示成 `gray: ps-helper-not-ready | <命令>`（`ps-helper-*` 与 `normalize-*` 原因直接显示）；其他灰色原因用 `--json` 看 `gray_reasons`。
- `boundkeep explain <event.json>`：用本机环境解释一个事件的路径、命中的规则与最终判决（PowerShell 事件：`{"tool_name":"PowerShell","tool_input":{"command":"..."},"cwd":"..."}`）。
- `boundkeep test [--platform windows|posix|all]`：策略内置测试（假机器上跑真的管线）。运行前会等辅助进程就绪（最多 10 秒）；**主机上没有可用的 PowerShell 解析器（状态 `unavailable`）时，PowerShell 的用例被明确标成 `[SKIP]` 并计入"skipped"**，不算通过也不算失败；辅助进程只是慢或被熔断时用例照跑、照实失败。
- 辅助进程反复重启或一直 `not-ready`：先看 `doctor` 的 `powershell-parser`；确认 `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` 存在、能在 `FullLanguage` 下运行（`$ExecutionContext.SessionState.LanguageMode`）、没有被安全软件拦截；然后重启 `boundkeep serve`。
