# 规格修订 23 到 26 的复审

日期：2026-11-12。代码：`ced7a87`（`main`，与 `origin/main` 相同；代码提交是 `8d268d3`）。

审查对象（`git show 8d268d3 -- src`）：
- 修订 23：`pscmd` 的 `_quiet`、`_names_exit_code`、`_settled`、`_known_value`；`pshelper.ps1` 的 `AutomaticVariable`。记录 `docs/reports/M3a-ps-known-variables.md`。
- 修订 24：`pscmd._State.add_gray` 的 `overflow` 和 `build` 里的 `ps-too-large`；`pshelper.ps1` 的 `Add-Default`、`Test-Carried`。记录 `docs/reports/M3a-rev21-22-review-fixes.md`。
- 修订 25：`programs.peel_runner_options` 的 `valued`、`_peel_python_m`；`bash._emit` 的 `runner-option-value`、`pscmd._peel_runners` 的 `ps-runner-value`；`pipeline._UNSHOWN_REASONS`。记录 `docs/reports/M3a-runner-options.md`。
- 修订 26：`bash._strip` 的 `taken`，`bash._emit` 的 `wrapper-option-value` 和 `kept_whole`。记录 `docs/reports/M3a-wrapper-options.md`。
- 规格：开头修订 23 到 26 的段落，§5.1、§7 里对应的几条。

**这不是独立复审。** 四次修订都是这个会话写的，使用者说"复审修订 23 到 26"，在这里审。下面的结论都重新量过，没有照搬记录里的说法。作者的盲点，这次复审可能同样看不到。

**本次没有做的事**：
- 只新增了这份报告，改了状态说明里指向它的几行，并更正了"没有推送"。没有改代码、规格正文、策略和测试。
- 没有读 `.env`，没有用 LLM 密钥，没有访问真实 LLM 服务。
- 没有读 `eval/authoring/h1-*`、`h2-*` 和留出批次，没有改系统设置。
- 没有跑测试，没有做变异测试，没有重跑作者的扫描。
- 没有运行 `sudo`。这台机器 PATH 上的 `sudo` 是 Windows 自带的，会请求提权。
- 没有在任何盘的根目录下建文件或目录。

**判决怎么取的**：
- 在 TEMP 下建假项目（`src/a.py`、`README.md`、`.env`、`sub/b.txt`、`tests/test_a.py`，内容是编的），用完已删。受信任项目的探针另用一份把这个假项目写进 `trusted_projects` 的默认策略。
- 用 `pipeline.review` 取规则层的判决，默认策略，没有后端，平台 `windows`。PowerShell 命令经真实的 PowerShell 5.1 解析辅助进程。
- "送审"按 `pipeline._finish` 的条件算：判决是灰色，`incomplete_analysis`、`unshown_input`、`device_path` 都不拦，并且 `send_gate.gate` 给出了请求。请求没有发出去。
- "请求里有没有"：看请求的 JSON 里有没有探针里的标记 `BKCANARY`。
- 实测：新的 `powershell.exe -NoProfile`；Git Bash 里的 GNU 工具。只用编出来的字符串和 TEMP 下的临时脚本，用完已删。
- 版本：PowerShell 5.1.26100.9818；GNU bash 5.2.37（msys）；coreutils 8.32。
- 探测脚本在 scratchpad（`rvr26_probe.py`、`rvr26_probes*.txt`、`rvr26_out*.jsonl`），不进仓库。共约 150 条探针。

下文的说法：
- "规则放行"：由 allow 规则给出。默认配置下，之后还有 Claude Code 自己的权限流程。
- "灰色"：没有规则作出决定。没有后端时问，有后端时送审，除非写明"不送审"。

## 1. 结论

**四次修订的目标都达到了，没有发现回退，没有发现不需要后端的放行。**
- 修订 23：能给 `$LASTEXITCODE` 放值的写法里，按名字放值的 cmdlet 本来就是灰色。`-OutVariable` 一类只认字面上的名字，写成 `ſ`、`ı`、`İ` 的变体，实测 PowerShell 5.1 不会把它们当成同一个变量。没有找到能让安静的一行打印出秘密的写法。
- 修订 24：R21-1 的四种写法（开关值、运行器选项、管道进解释器、参数默认值，前面都凑满 90 条原因）都带 `ps-too-large`，不送审。参数默认值在 9 个位置（`&`、`.`、`ForEach-Object`、`Invoke-Command`、函数、`filter`、`$(…)`、脚本的 `param`、命令参数里的函数）都送审，请求里都有标记。
- 修订 25：两种 shell 里 20 多种写法，带值选项的都不送审。认不出的写法（贴在短选项后面的值、`-p:值`、`--%`、splat、写在 `run` 之前的全局选项）运行器不被剥掉，整条的词都在请求里，或者由规则问。
- 修订 26：约 40 种写法，包括贴着写的值、嵌套、20 层包装器、`find -exec`、`bash -c`、`env -S` 的各种组合，吃掉了值的都不送审。只有一处漏了，见 RV26-1。

**范围之内：高危 0，中危 0，低危 1，信息 3。**

| 编号 | 级别 | 一句话 | 要后端吗 | 来源 |
|---|---|---|---|---|
| RV26-1 | 低 | 包装器的长开关写成 `--名字=值` 时，值被丢掉，也不标 `wrapper-option-value`：`sudo --preserve-env=BKCANARY pytest -q` 送审，请求里没有标记 | 要 | 修订 26 的 `_strip` |
| RV23-1 | 信息 | `ſ`、`ı`、`İ` 写的名字不是 `$LASTEXITCODE`（实测），按名字放值的 cmdlet 本来就是灰色，名字检查没有缺口 | — | 修订 23 |
| RV24-1 | 信息 | `pscmd._type_names` 把 `compound`、`dynamic`、`loose` 三张表各截在 64 条，截掉时不置 `overflow`。实际碰不到：辅助进程会去重，PowerShell 5.1 一共只有 64 种具体的 AST 类型 | — | M1b 就有；和 R21-1 同一类 |
| RV25-1 | 信息 | `_peel_python_m` 只在 `-W`、`-X` 的值另写一个词时记"带值"，`-Xdev` 这种贴着写的不记。`python -m boundkeep …` 一律由规则问或拒绝，从不送审，所以没有影响 | — | 修订 25 |
| O-4 | 范围外 | PowerShell 里超过 32768 个字符的字符串常量只剩前 200 个字符，整条调用照常送审。`Invoke-Expression '<填充>…<代码>'`、`Add-Type -TypeDefinition '<填充>…'` 实测执行或编译了请求里看不到的尾部 | 要 | 截断是 M1b 的辅助进程（`9149823`）；M3a 的发送闸门上线后就会送审 |

## 2. 发现

### RV26-1（低）：长开关带 `=值`，值被丢掉

`bash._strip` 遇到 `long_flags` 里的名字时，不看后面有没有 `=`，整个词当开关吃掉（`if nm in spec.long_flags: … i += 1; continue`）。所以 `--名字=值` 的值不进 `optargs`，也不置 `taken`，修订 26 的标记不加。运行器那边 `peel_runner_options` 写的是 `name in flags and not eq`，带 `=` 的开关算认不出，不剥。

| 写法（Bash） | 判决 | 送审 | 请求里有标记 |
|---|---|---|---|
| `sudo --preserve-env=BKCANARY pytest -q` | 灰色 | 送审 | 没有 |
| `env --ignore-environment=BKCANARY pytest -q` | 灰色 | 送审 | 没有 |
| `ls \| xargs --replace=BKCANARY wc -l`（`--eof=`、`--max-lines=` 相同） | 问（`ask-shell-read-outside-project`，`arguments-from-stdin`） | — | — |
| `sudo -EuBKCANARY pytest -q`、`env -uBKCANARY pytest -q`、`nice --adjustment=BKCANARY pytest -q` | 灰色，不送审（`wrapper-option-value`） | — | — |

真实程序怎么读：
- GNU `env`、`timeout` 拒绝带值的开关：`env --ignore-environment=X true`、`timeout --foreground=x 1 true`、`env --null=x true` 都报 "option doesn't take an argument"，退出码 125，命令不运行（实测）。
- GNU `xargs` 的 `--replace`、`--eof`、`--max-lines` 接受可选的值（实测 `--replace=@`、`--eof=b`、`--max-lines=1` 都起作用）。但带 `xargs` 的行由规则问，不送审。
- sudo 的 `--preserve-env=列表` 按 sudo 手册接受，只把列出的变量带进去。没有运行。

所以真正送审、又丢了值的只有 `sudo --preserve-env=列表`。它只带列出的变量；`sudo -E`（只带开关）带全部变量，按设计照常送审。请求里少了的不比 `sudo -E` 多，所以评低。

**建议**：`long_flags` 里的名字带 `=` 时置 `taken`（或者和运行器一样当认不出的选项，不剥），两种都只多问几条本来就不会运行的写法。

### RV23-1（信息）：用别的字母写的名字

修订 23 的名字检查用 `lower()` 和 `fnmatch`。实测 PowerShell 5.1（`cmd /c exit 7` 之后）：

| 写法 | 之后 `$LASTEXITCODE` |
|---|---|
| `Get-Date -OutVariable "LAſTEXITCODE" \| Out-Null`（U+017F） | 7，没有被改 |
| `… -OutVariable "LASTEXıTCODE"`（U+0131） | 7 |
| `… -OutVariable "LASTEXİTCODE"`（U+0130） | 7 |
| `… -OutVariable "lastexitcode"` | 被改成日期（检查认得出，不安静） |
| `& { param($LAſTEXITCODE = "bound") $LASTEXITCODE }` | 7 |

规则层：前三种由规则放行，打印的是 7，没有放值。按名字放值、又能用通配符或反引号写名字的 cmdlet 都是灰色：`Set-Variable`、`New-Variable` 是 `ps-variable-assign`，`Set-Item Variable:\…` 和重定向到 `Variable:\…` 是 `ps-provider-path:variable`。`-OutVariable`、`-ErrorVariable`、`Tee-Object -Variable` 只认字面上的名字。所以 `[!E]` 在 `fnmatch` 和 PowerShell 通配符里的读法不同、反引号转义这两处差别，都只出现在本来就是灰色的命令上。不需要改。

### RV24-1（信息）：三张类型表的截断

`pscmd._type_names` 返回 `raw[:MAX_REASONS]`，截掉的时候不置 `overflow`。这和 R21-1 是同一类："不送审"靠某一条原因在不在，`ps-compound:AssignmentStatementAst` 被截掉就会送审。

现在碰不到：
- 辅助进程逐类型去重（`if (-not $compound.Contains($short))`，`loose`、`dynamic` 同样）；
- PowerShell 5.1 的 `System.Management.Automation.Language` 里，具体的 `Ast` 子类一共 64 种（实测），每张表只装其中一部分，`CommandAst`、`ScriptBlockAst` 这类不会进 `loose`。

PowerShell 7 的类型更多，没有量。**建议**：截断时也置 `overflow`，一行改动。

### RV25-1（信息）：`python -Xdev -m boundkeep`

`_peel_python_m` 只在 `t in _PY_VALUE_FLAGS`（`-W`、`-X`、`-Q`，值另写一个词）时记 `valued`；`-Xdev`、`-Wignore` 走"别的短开关"那一支，不记。探针：`python -X BKCANARY -m boundkeep log --tail 3` 带 `runner-option-value`，`python -XBKCANARY -m boundkeep …` 不带。两条都由 `ask-boundkeep-cli` 问，`python -m boundkeep` 的任何写法都由规则问或拒绝，不会送审。`-Q` 是 Python 2 的开关。不需要改。

### O-4（范围外）：超长字符串只剩前 200 个字符

辅助进程遇到超过 `$script:MaxString`（32768）个字符的字符串常量或可展开字符串时（管道开头的字符串是 4096），报成 `{"t":"other","ast":"TooLongString","text":<前 200 个字符>}`（`Add-TooLong`）。`pscmd` 把它记成灰色 `ps-dynamic-value:TooLongString` 和一个 200 个字符的词。这个原因既不在 `_UNANALYSED_PREFIXES` 里，也不在 `_UNSHOWN_REASONS` 里；200 个字符又低于发送闸门 400 个字符的上限。所以整条调用照常送审，请求里只有开头。

| 写法（PowerShell 工具，`<填充>` 是 33000 个 `#`） | 送审 | 请求里有尾部的标记 |
|---|---|---|
| `Invoke-Expression '<填充>`n BKCANARY'`、`iex …` | 送审（`ps-exec:Invoke-Expression`） | 没有 |
| `Add-Type -TypeDefinition '//<填充>`npublic static class BKCANARY {}'` | 送审（`ps-exec:Add-Type`） | 没有 |
| `python -c '<填充> BKCANARY'`、`node -e …`、`powershell -Command …`、`cmd /c …`、`Write-Output …` | 送审 | 没有 |
| 对照：`python -c '<1000 个 #> BKCANARY'` | 不送审（发送闸门：词超过 400 个字符） | — |
| 对照：Bash 工具的 `python -c '<填充> BKCANARY'` | 不送审（同上，Bash 不截） | — |

实测（PowerShell 5.1）：
- 外部程序收不到这么长的参数：`cmd.exe /c "rem <33000 个 #>"` 报"文件名或扩展名太长"，没有运行。所以 `python -c`、`node -e`、`powershell -Command`、`cmd /c` 这几行实际上跑不起来。
- 在 PowerShell 进程里执行的不受这个限制：`Invoke-Expression ('<33000 个 #>' + "`n'iex ran the tail'")` 打印了 `iex ran the tail`；`Add-Type -TypeDefinition` 编译出了写在填充之后的类。
- Claude Code 的 PowerShell 工具（这个会话所在的版本）把整段脚本放进环境变量 `CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT`，再经 `cmd.exe` 启动 `powershell.exe -Command "… Invoke-Expression -Command $__claudeCodeScript"`（看的是这个会话自己的进程的命令行）。照同样的链路，33072 和 70072 个字符的脚本都完整运行，`Invoke-Expression` 执行了尾部。没有通过真实的 Claude Code 工具调用去跑这么长的命令。
- `295badc` 的代码上结果相同。

**级别**：按 F3、F4 的标准是中危：模型被要求放行它没看到的代码，`Invoke-Expression`、`Add-Type` 会执行这段代码。需要后端。早于修订 23 到 26。

**建议**：`TooLongString` 按"没看全"处理。在 `pscmd` 里遇到这个类型时加 `ps-too-large`，或者把 `ps-dynamic-value:TooLongString` 放进 `_UNANALYSED_PREFIXES`。没有后端时判决不变（本来就是灰色，问）。其他截断已经核对过，都不会送审：
- 其余 `other` 元素截在 2000 个字符，超过发送闸门 400 个字符的上限，会被拒绝；
- 表达式形式的命令名截在 2000 个字符，超过程序名 128 个字符的上限，同样被拒绝；
- Bash 的词不截。

## 3. 核对过、没有问题的

| 检查 | 结果 |
|---|---|
| 修订 23：`Set-Variable -Name 'LAST`EXITCODE'`、`Set-Item 'Variable:\LAST[!E]XITCODE'`、`Get-Date > Variable:\LASTEXITCODE` 之后打印 `$LASTEXITCODE` | 灰色（`ps-variable-assign`、`ps-provider-path:variable`），没有一条由规则放行 |
| 修订 23：`Get-Content Env:X`、`Get-Item Env:X`、`Get-ChildItem Env:`、`Get-Content Variable:\PWD` | 灰色，没有一条由规则放行；带 `-OutVariable` 再打印 `$LASTEXITCODE` 时也是灰色 |
| 修订 24：R21-1 的四种写法在最终代码上 | 都带 `ps-too-large`，不送审。只凑 61 条时 `ps-switch-value` 照常记下，不送审 |
| 修订 24：参数默认值在 `& { }`、`. { }`、`1 \| ForEach-Object { }`、`Invoke-Command`、`function f($x = …)`、`filter`、`$(function …)`、脚本的 `param`、命令参数里的函数 | 9 种都送审，请求里都有标记 |
| 修订 25：`--env-file=值`、`--directory`、`uvx --from`、`uv tool run --from`、`pipx run --spec`（Bash）；`--with=值`、`& uv …`、引号写的词（PowerShell） | 都不送审 |
| 修订 25：`uv run -p值`、`uv run -p:值`、`uv run --% …`、splat、`uv --directory 值 run …`、`poetry -C 值 run …` | 运行器不被剥掉。前五种由规则问（`net-unknown-destination`）；`poetry -C` 送审，请求里有标记 |
| 修订 25：`uv run uv run --env-file …`、13 层 `uv run`、`sudo uv run --env-file …`、`find src -exec uv run --env-file … {} \;` | 都不送审 |
| 修订 26：贴着写的值（`-uX`、`-EuX`、`-iX`、`sshpass -eX`）、`nice --adjustment=`、`numactl --membind=`、`stdbuf -o`、`ionice -c`、`tini -p`、`ssh-agent -a`、`exec -a`、`time -o`、`wsl --cd`、`sudo -s -u`、`sudo -S -u` | 不送审，或由规则问 |
| 修订 26：`timeout 5 env -C …`、`bash -c "env -C …"`、`sh -c 'sudo -u …'`、`ls \| xargs sudo -u …`、`uv run sudo -u …`、`find src -exec sudo -u / env -C / timeout …`、20 层 `nohup` 或 `timeout 1` | 不送审，或由规则问 |
| 修订 26：`env -S` 的组合（`-C 值 -S '…' tests`、`-S` 贴着写、`--split-string=`、`-u 值 -S`、`-S '…' NAME=1`） | 送审，请求里都有标记（env 整条记下） |
| 修订 26：`env -C 值` 单独一条、`busybox env -C 值 pytest` | 送审，请求里有标记（env 没有被剥掉） |
| 同一类在别处：受信任项目里 `python -X pycache_prefix=值 -m pytest`、`python -W 值 -m pytest`、`.venv\Scripts\python.exe -X … -m pytest`（两种 shell） | 不认成开发工具，不由规则放行；送审，请求里有标记 |
| 同一类在别处：`cmd /c uv run --env-file …`、`Start-Process uv -ArgumentList …` | 送审，请求里有标记 |

## 4. 建议的顺序

（后记，2026-11-12：使用者说"按建议顺序修三条"，O-4、RV26-1、RV24-1 已按这里的建议修，规格修订 27，记录 `docs/reports/M3a-rev23-26-review-fixes.md`。修的时候查到这次复审漏掉的一条，记为 O-5：绑到变量上的常量不在请求里（`param($p = '~\.ssh\id_rsa') Get-Content $p` 送审，请求里只有 `Get-Content $p`），按 F3、F4 的标准是中危，要后端，早于修订 23。这次复审没有扫常量的参数默认值；是修这三条时的扫描里出现了"送审、请求里没有标记"的几行才发现的。使用者说"O-5 也按你的建议修"，规格修订 28，同一份记录第 7 节。）

1. O-4：改动最小（一处原因），堵的是 `Invoke-Expression`、`Add-Type` 送审时只给模型看开头。
2. RV26-1：`long_flags` 带 `=` 时置 `taken`，和运行器的读法一致。
3. RV24-1：截断时置 `overflow`，防的是以后类型变多。

RV23-1、RV25-1 不需要改。真实宿主里这四次修订都没有专门跑过（修订 23、24 的代表写法在 2026-11-12 的真实冒烟里，见 `docs/hook-behavior.md`）。
