# 规格修订 19 和 20 的复审

日期：2026-11-10。代码：`6a3565d`（`main`，与 `origin/main` 相同，工作区干净）。

审查对象：
- 修订 19：`git show 30813d0 -- src`。具体是 `event._short_named_path`、`_command_action` 里加灰色原因的那一段，以及 `pipeline._UNSHOWN_REASONS` 的注释。记录 `docs/reports/M3a-short-name-unresolved.md`。
- 修订 20：`git show 92a5e56 -- src`。具体是 `programs._Acc` 的 `posix_devices`、`_Acc.path`、`classify` 和 `_classify` 的参数，以及 `psprograms` 里两处传 `False`。记录 `docs/reports/M3a-ps-dev-paths.md`。
- 规格：开头修订 19、20 的段落，§5.1，§7"请求装不下的输入"。

**这不是独立复审。** 两次修订都是这个会话写的，使用者选择在这里审。下面的结论都重新量过，没有照搬记录里的说法。不过作者的盲点，这次复审可能同样看不到。

**本次没有做的事**：
- 只新增了这份报告，并在状态说明里加了指向它的几行。没有改代码、规格正文、策略和测试。使用者看过结论之后说提交，报告和这几行在 `b15e064`，已推送到 `origin/main`。没有打标签。
- 没有读 `.env`，没有用 LLM 密钥，没有访问真实 LLM 服务。
- 没有读 `eval/authoring/h1-*`、`h2-*` 和留出批次，没有改系统设置。
- 没有跑测试，没有做变异测试，没有重跑作者的扫描。代码自修订 20 的全量之后没有改。
- 没有在任何盘的根目录下建文件或目录。R20-1 里"那个位置有内容时会怎样"因此没有实测（第 2 节写明了）。

**判决怎么取的**：
- 在 TEMP（C: 卷，会生成 8.3 短名）下建假项目和一个长名的工具目录，里面是假的 `boundkeep.exe`（两个字节）。用完已删。
- 用 `pipeline.review` 取规则层的判决，没有后端，平台 `windows`。PowerShell 命令经真实的 PowerShell 5.1 解析辅助进程。
- "送审"按 `pipeline._finish` 的条件算：判决是灰色，并且 `incomplete_analysis`、`unshown_input`、`device_path` 都不拦。
- "请求里带了什么"取自 `send_gate.gate` 的结果，没有发出去。
- "修改前"指 `e208c74`（修订 19 之前）的 `src`；"M3a 收尾时"指标签 `m3a-done` 的 `src`。两个都导出在 scratchpad，经 `RR_SRC` 加载。
- 实测用改了名字的 `whoami.exe` 副本（TEMP 的长名目录里）和一个临时 git 仓库，用完已删。
- 版本：PowerShell 5.1.26100.9818，Git Bash 的 bash 5.2.37（msys），git 2.48.1.windows.1。
- 探测脚本在 scratchpad（`rvr_*.py`、`rvr_real*.ps1`），不进仓库。

下文的说法：
- "规则放行"：由 allow 规则给出。默认配置下，之后还有 Claude Code 自己的权限流程。
- "灰色"：没有规则作出决定。没有后端时问，有后端时送审，除非写明"不送审"。

## 1. 结论

**两次修订的目标都达到了，没有发现回退。**
- 修订 19：`cd` 进短名目录之后运行的短名程序，在 Bash 的 28 种写法、PowerShell 的 24 种写法里查过。凡是长名写法是 deny 的，短名写法都是灰色、不送审，只有一种写法例外（R19-1，Git Bash 实测不运行它）。
- 修订 20：PowerShell 里 108 种命令形状，`/dev/null`、`/dev/zero`、`/dev/stdout` 各自和一个编出来的邻居（`/dev/nullx` 等）对照，324 对的判决、规则和路径数全部相同。嵌套的 PowerShell（`powershell -Command`、`Invoke-Expression`、脚本块）也一样。

**范围之内：高危 0，中危 0，低危 3，信息 1。** 四条都早于这两次修订。其中 R19-2、R19-3 和修订 19 修的 R18-4 是同一个原因：`cd` 进路径里带短名的目录之后，工作目录算未知。修订 19 只处理了命令名这一个位置。

**范围之外查到一条（O-1），按 X1 审查 F3、F4 的标准应算中危。** 它从 `m3a-done` 起就有，和这两次修订无关，只在配置了 LLM 后端时起作用。

| 编号 | 级别 | 一句话 | 要后端吗 | 来源 |
|---|---|---|---|---|
| R19-1 | 信息 | Bash 里短名后面带 `.EXE` 再加尾随的点或空格（`./BOUNDK~1.EXE.`），展开不了时得到的是 `program-short-name`，照常送审。Git Bash 实测不运行这种写法 | 送审要 | 修订 18 的"补 `.exe` 再找"。修订 19 没有改到它 |
| R19-2 | 低 | 短名程序不在命令名的位置、而是交给启动器时（`Start-Process .\BOUNDK~1.EXE`、`cmd /c .\BOUNDK~1.EXE`），工作目录未知时照常送审，模型只看得到短名。PowerShell 实测这两种都运行 | 送审要 | 修订 19 只看命令名，这是它声明的范围 |
| R19-3 | 低 | `cd` 进短名目录之后按短名读受保护的文件（`cat ./ENV~1.PRO`，它是 `.env.production`）是灰色、照常送审；目录写长名时是 deny。两种 shell 实测都读出内容 | 不要（没有后端时是问，不是 deny） | 修订 19 只看命令名，没有碰路径参数 |
| R20-1 | 低 | Windows 上的 bash 方言里，Git Bash 启动的原生程序拿到的不是设备：`/dev/tty` 原样传过去，`/dev/zero` 变成 `/Device/Null`，`/dev/stdout` 变成 `/proc/self/fd/1`，都被读成当前盘上的路径（实测）。守卫不记这些路径，所以受信任项目里 `pytest /dev/tty` 是规则放行，`pytest /dev/ttx` 是问 | **不要** | 早于修订 20。修订 20 只改了 PowerShell 方言 |
| O-1 | 范围外 | PowerShell 里单独成句的表达式（`[IO.File]::ReadAllText('.env')`）和别的命令写在同一行时，整行照常送审，请求里没有这个表达式的任何文字 | 要 | `m3a-done` 上相同 |

## 2. 发现

### R19-1（信息）：`.EXE` 后面再带点或空格的短名，Bash 里得到一个编出来的长名

`<短名目录>` 是 `…/LONGTO~1`，里面有假的 `boundkeep.exe`。

| 写法 | shell | 判决 | 灰色原因 | 送审 |
|---|---|---|---|---|
| `cd '<短名目录>' && ./BOUNDK~1.EXE mode audit-only`（对照） | Bash | 灰色 | `program-short-name-unresolved` | 否 |
| `cd '<短名目录>' && ./BOUNDK~1.EXE. mode audit-only` | Bash | 灰色 | `program-short-name`、`program-name-trailing-dots` | **是** |
| `cd '<短名目录>' && "./BOUNDK~1.EXE " mode audit-only` | Bash | 灰色 | 同上 | **是** |
| `<短名目录>/NOSUCH~1.EXE. mode audit-only`（文件不存在） | Bash | 灰色 | 同上 | **是** |
| `<短名目录>/BOUNDK~1.EXE. mode audit-only`（展开得出） | Bash | deny | — | — |
| `Set-Location '<短名目录>'; & '.\BOUNDK~1.EXE.' mode audit-only` | PowerShell | 灰色 | `program-short-name-unresolved` | 否 |

送审的那三行，请求里的程序名是 `boundk~1.exe.`。

**原因**：`_short_name_program` 在 bash 方言里按原样找不到时，给文字补上 `.exe` 再找一次。条件是文字不以 `.exe` 结尾，而 `./BOUNDK~1.EXE.` 以 `.exe.` 结尾，于是找的是 `./BOUNDK~1.EXE..exe`。这个名字不再像短名，路径层给它的词法形式就不带 `short-name-unresolved`，被当成"展开出来的长名"。函数最后返回 `boundk~1.exe.`，调用方以为展开成功了。

**实测**（Git Bash，`cd` 进短名目录之后）：

| 写法 | 结果 |
|---|---|
| `./LONGPR~1.EXE`、`./LONGPR~1`（对照） | 运行 |
| `./LONGPR~1.EXE.` | 退出码 127，没有运行 |
| `"./LONGPR~1.EXE "` | 退出码 127，没有运行 |
| `./LONGPR~1.`、`./longprogramname.exe.` | 退出码 127，没有运行 |

所以这是原因标错、多送审了一种跑不起来的写法，不是可以利用的缺口。`e208c74` 上判决相同：修订 19 没有引入它，只是"凡是展开不了都标"在这种写法上没有做到。规格 §5.1 写的是"去掉结尾的点和空格之后符合短名"，代码和它不一致。

### R19-2（低）：交给启动器的短名程序，模型只看得到短名

| 写法 | shell | 长名目录 | 短名目录（工作目录未知） |
|---|---|---|---|
| `Set-Location '<目录>'; Start-Process .\<程序> -ArgumentList 'mode','audit-only'` | PowerShell | 灰色，送审 | 灰色，**送审** |
| `Set-Location '<目录>'; cmd /c .\<程序> mode audit-only` | PowerShell | 灰色，送审 | 灰色，**送审** |
| `Invoke-Item`、`powershell -Command "& '…'"`、`Invoke-Expression "& '…'"` | PowerShell | 灰色，送审 | 灰色，**送审** |
| `cd '<目录>' && start ./<程序> mode audit-only`、`winpty ./<程序> …` | Bash | 灰色，送审 | 灰色，**送审** |
| `cd '<目录>' && cmd //c ./<程序> mode audit-only` | Bash | ask | ask |

- 这些写法用长名时本来就不是 deny，是灰色、送审（`Start-Process boundkeep …` 是已知的灰色）。差别在模型看到的名字：长名目录里它看到 `boundkeep.exe`，短名目录里只看到 `.\BOUNDK~1.EXE`。修订 19 的理由正是"模型看到的是一个说明不了自己是什么程序的名字"。
- 短名目录写成能展开的绝对路径时（`Start-Process '<短名目录>\BOUNDK~1.EXE'`），请求的 `paths` 里有展开后的 `…/longtoolsdirectory/boundkeep.exe`，模型看得到。缺口只在展开不了的时候。
- 实测（PowerShell 5.1，`Set-Location` 进短名目录之后）：`Start-Process .\LONGPR~1.EXE -NoNewWindow -Wait` 和 `cmd /c .\LONGPR~1.EXE` 都运行。`cmd /c LONGPR~1.EXE`（不带 `.\`）不运行。`Invoke-Item`、Bash 的 `start` 和 `winpty` 没有量。
- 在 Bash 里包一层的写法没有这个问题：`env`、`command`、`exec`、`nohup`、`timeout`、`nice`、`time`、`sudo`、`bash -c`、`sh -c`、`eval`、子 shell、管道、`if`，短名目录里都是灰色、不送审。PowerShell 的 `& { … }`、`Start-Job { … }`、`Invoke-Command { … }`、`if`、`try` 也一样。

### R19-3（低）：短名目录里按短名读受保护的文件

`<短名目录>` 里有 `.env.production`，短名是 `ENV~1.PRO`。假项目里没有同名的文件。

| 写法 | shell | 判决 |
|---|---|---|
| `cd '<长名目录>' && cat ./.env.production` | Bash | deny（`no-secret-read`） |
| `cd '<长名目录>' && cat ./ENV~1.PRO` | Bash | deny（磁盘层展开得出长名） |
| `cat <短名目录>/ENV~1.PRO`（不 `cd`） | Bash | deny |
| `cd '<短名目录>' && cat ./.env.production` | Bash | deny（按名字） |
| `cd '<短名目录>' && cat ./ENV~1.PRO` | Bash | **灰色，送审** |
| `cd '<短名目录>' && cp ./ENV~1.PRO /tmp/x` | Bash | **灰色，送审** |
| `Set-Location '<短名目录>'; Get-Content .\ENV~1.PRO` | PowerShell | **灰色，送审** |
| `Set-Location '<长名目录>'; Get-Content .\ENV~1.PRO`、`Get-Content '<短名目录>\ENV~1.PRO'` | PowerShell | deny |

- 短名目录在项目里面时也一样（`cd '<项目>/LONGSE~1' && cat ./ENV~1.PRO` 是灰色、送审）。
- **实测**：`cd` 进短名目录之后，Git Bash 的 `cat ./ENV~1.PRO` 和 PowerShell 5.1 的 `Get-Content .\ENV~1.PRO` 都打印出假文件的内容。
- **原因**：`cd` 的目标带短名时，工作目录算未知，候选只剩"未知"和 hook 给的工作目录。相对路径于是没法展开，按名字写的 deny 规则也认不出 `ENV~1.PRO`。目录本身其实展开得出来（请求的 `paths` 里有 `…/longtoolsdirectory`）。
- 没有后端时是问，问的是 `cat ./ENV~1.PRO`，使用者也看不出它是哪个文件。有后端时模型看到的同样只有短名。
- 短名本身就命中规则的不受影响：`ID_RSA~1`（`id_rsa_backup_copy`）仍是 deny，`ENV~1`（`.env`）要看 hook 给的工作目录里有没有 `.env`。
- 修订 19 没有改路径参数的处理，所以它早于修订 19。R18-4 的复审只写了程序名，没有写到这里。

### R20-1（低）：Git Bash 启动的原生程序拿到的不是设备

修订 20 的依据是"这六个名字是 Bash 的设备"。在 Windows 上这只对 MSYS 自己的程序（`cat`、`rm`、`head`）成立。原生程序（python、git、pytest、ruff、node、curl）由 MSYS 先转换参数再启动。

**实测**（Git Bash，把参数交给 `.venv` 里的 `python.exe` 打印出来）：

| 写的 | 原生程序拿到的 | python 解析成 |
|---|---|---|
| `/dev/null` | `nul` | `\\.\nul`（设备） |
| `/dev/tty` | `/dev/tty` | `C:\dev\tty` |
| `/dev/zero` | `/Device/Null` | `C:\Device\Null` |
| `/dev/stdout` | `/proc/self/fd/1` | `C:\proc\self\fd\1` |
| `/dev/stdin`、`/dev/stderr` | `/proc/self/fd/0`、`/proc/self/fd/2` | 同样在当前盘上 |
| `/dev/nullx`（对照） | `<Git 安装目录>/dev/nullx` | — |

git 也一样：`git status /dev/zero` 报 `Invalid path '/Device'`，`git -C /dev/tty status` 报 `cannot change to '/dev/tty'`，`git --git-dir=/dev/stdout log` 报 `not a git repository: '/proc/self/fd/1'`。只有 `/dev/null` 是设备（`git status /dev/null` 正常运行）。

**判决**（Bash，设备名 / 编出来的邻居）：

| 写法 | 策略 | `/dev/tty` 等五个名字 | 邻居（`/dev/ttx`） |
|---|---|---|---|
| `git status <名字>`、`git ls-files`、`git blame`、`git log -p -- <名字>`、`git show HEAD:<名字>` | 默认 | **规则放行** | ask |
| `git -C <名字> status`、`git diff --no-index <名字> README.md` | 默认 | 灰色 | ask |
| `pytest <名字>`、`python -m pytest <名字>`、`ruff check`、`ruff format`、`mypy`、`black`、`isort`、`flake8`、`pylint` | 项目在 `trusted_projects` 里 | **规则放行** | ask |
| `pytest -c <名字>`、`ruff check src --config <名字>`、`mypy src --config-file <名字>` | 同上 | 灰色 | ask |

PowerShell 里同样的 22 种开发工具写法，设备名和邻居的判决全部相同（修订 20 的效果）。

**能造成什么**：
- 这台机器上 `C:\dev`、`E:\dev` 都不存在。git 的那几条都报错退出；`python -m pytest /dev/tty` 是"no tests ran"，退出码 4。
- 当前盘上真有 `\dev\tty`（或 `\Device\Null`、`\proc\self\fd\1`）时，受信任项目里的 `pytest /dev/tty` 会由规则放行，去跑项目之外那个目录里的测试；`ruff format /dev/tty` 会改写那里的文件。**这一点没有实测**：要在盘的根目录下建目录，这次没有做。
- agent 自己建不出那个位置而不被问：`mkdir -p /c/dev/tty` 是灰色，往 `C:\dev\tty\conftest.py` 写文件是 ask（`ask-project-autorun-files`）。所以前提是那里本来就有内容，或者使用者（有后端时是模型）批准过一次。项目放在 `X:\dev\` 下面是常见的布局，`X:\dev\tty` 这个名字不常见。
- `/dev/null` 没有这个问题。重定向也没有：`2>/dev/tty` 是 bash 自己打开的，确实是设备。

`m3a-done` 上 `git status /dev/tty` 同样是规则放行。规格 §5.1 和修订 20 的记录写"bash 方言：无害设备"，没有区分 MSYS 程序和原生程序。

### O-1（范围外）：单独成句的 PowerShell 表达式，请求里什么都没带

查 R19-2 时碰到的，和短名、`/dev/` 都无关。

| 写法 | 判决 | 送审 |
|---|---|---|
| `[IO.File]::Delete('C:\x\y')`（单独一条） | 灰色 | 否（"什么都没看懂"） |
| `Get-Date; [IO.File]::Delete('C:\x\y')` | 灰色 | **是** |
| `git status; [IO.File]::ReadAllText('.env')` | 灰色 | **是** |
| `Get-Date; if ($true) { [IO.File]::Delete('C:\x\y') }` | 灰色 | **是** |
| `Get-Date; function f { [IO.File]::Delete('C:\x\y') }; f` | 灰色 | **是** |
| `Get-Date; (New-Object Net.WebClient).DownloadString('https://example.com/a')` | 灰色 | **是** |
| `Get-Date; $a = [IO.File]::ReadAllText('.env')`（赋值，对照） | 灰色 | 否 |
| `Write-Output ([IO.File]::ReadAllText('.env'))`（对照） | 灰色 | 是，表达式的文字在 `args` 里 |

`git status; [IO.File]::ReadAllText('.env')` 的请求里，`actions` 只有两项：

- `{"program": "git", "subcommand": "status", "args": ["status"], "network": false, "risk_tags": []}`
- `{"network": false, "risk_tags": ["exec"], "unclear": ["ps-dynamic:InvokeMemberExpressionAst", "ps-dynamic:TypeExpressionAst"]}`

模型知道有一段带 `exec` 的内容没看清，但看不到类型名、方法名、路径。`DownloadString` 那一条，请求里是 `new-object Net.WebClient`，没有网址，`network` 是 `false`，`domains` 是空的。

- 规格 §7 的原则是"请求装不下的代码与参数不送审"（修订 7，P-F34）。那里列的是 here-document、赋值、管道进解释器的字符串、MCP 参数，没有列单独成句的表达式。单独一条时它靠"整个调用什么都没看懂"被拦下，前面多一条 `Get-Date` 就拦不住了。
- 模型回答 allow 之后，§9.5 的二次裁决没有一行管这种情况：`deviates_from_task` 为假、`risk` 不超过 1、会话没有被污染时，最终就是 allow。
- 没有后端时这些都是问，默认配置不受影响。还没有接过真实的 LLM 服务。
- Bash 里没有查到同样的情况：`ls; $x`、`ls; eval "$x"`、`ls; while read l; do $l; done < cmds.txt` 的请求里都有那条命令的程序名或参数。
- `m3a-done` 上判决相同。

X1 审查把同一类的 F3、F4 评为中危，所以这一条也应算中危。

## 3. 核对过、没有问题的

- **修订 19 的拆包装**：`& "$tools\BOUNDK~1.EXE"`、`$p = '…'; & $p` 都是灰色、不送审。
- **修订 19 的代价属实**：文件不存在的短名路径（`<短名目录>/NOSUCH~1.EXE`）在两种 shell 里都是灰色、不送审。PowerShell 里不带 `.EXE` 的短名路径也是。
- **修订 20，PowerShell 里包一层的外部程序**：`env rm -rf`、`xargs`、`sudo`、`timeout`、`busybox`、`nohup`、`uv run`、`npx` 后面的 `/dev/null`，都和 `/dev/nullx` 判决相同。
- **修订 20，从 Bash 里启动 PowerShell**：`powershell -Command "Remove-Item -Recurse -Force /dev/null"`、`pwsh -c "…"`、`cmd //c "del /dev/null"` 和邻居判决相同。
- **修订 20 记录第 6 节第 6 条**写"从 PowerShell 启动的 MSYS 程序，没有量"。这次量了：从 PowerShell 5.1 运行 Git 的 `usr\bin\cat.exe /dev/null`，退出码 0、输出为空；`ls.exe -l /dev/null`、`ls.exe -l /dev/zero` 显示字符设备。它们确实读成设备，守卫按路径记，只会更严，和记录的说法一致。
- **`_Acc` 只在三处创建**（`_classify`、pip 的子累加器、`psprograms._Ctx`），都给了 `posix_devices`。`programs.classify` 的调用方只有 `event._command_action`（默认值 `True`）和 `psprograms._external`（`False`）。
- **文档**：规格 §5.1、`docs/powershell-dialect.md` 的两行和代码一致。`docs/policy-reference.md`、`docs/threat-model.md` 里没有和修订 20 冲突的说法。

## 4. 记录里要更正或补充的文字

1. 修订 19 的记录第 4 节和规格 §5.1："去掉结尾的点和空格之后符合短名"在 bash 方言里对 `.EXE.`、`.EXE ` 不成立（R19-1）。
2. 修订 19 的记录第 6 节：没有写到交给启动器的短名（R19-2）和短名目录里的路径参数（R19-3）。
3. 修订 20 的记录第 6 节第 6 条："没有量"可以改成量过的结果（第 3 节）。
4. 修订 20 的记录和规格 §5.1："bash 方言里是无害设备"要加上"对 MSYS 自己的程序"（R20-1）。

这四处都没有改，等使用者决定怎么处理。

## 5. 建议

1. **O-1 在 M3b 之前定下来。** 它只在有后端时起作用，而 M3b 正是第一次接真实后端。修法要改规格 §7"请求装不下的输入"。一种做法：请求里有一项动作既没有程序名，也没有参数、路径、主机时，整个调用不送审。代价是 PowerShell 里带方法调用的多条命令都改成直接问。
   - 2026-11-11 补记：规格修订 21 修了这一条（`docs/reports/M3a-ps-outside-command.md`），没有用上面这个做法。它行不通：PowerShell 里几乎每条灰色的命令都带一项没有程序名的动作（整行的灰色原因就记在那里），照它做等于整个 PowerShell 都不送审。实际的做法是让辅助进程报出不在任何命令参数里的表达式和语句。
2. **R19-1 可以随下一次改动顺手修。** 补 `.exe` 之前先去掉结尾的点和空格，或者只把磁盘上确实存在的文件算作"展开出来的名字"。它不影响安全，只是原因标错。
3. **R19-2、R19-3 和 R18-4 可以从同一个原因上修，要先定设计。** `cd` 的目标只因为带短名才不确定、而磁盘层展开得出一个存在的目录时，把展开后的目录当作工作目录。这样三条都按长名判，`./BOUNDK~1`、`cat ./ENV~1.PRO` 会是 deny，修订 19 的灰色原因只留给真的展开不了的情况。要先量的是：`cd` 失败时留在原目录的那个候选要不要保留。不改这一层的话，另一种做法是只补症状：启动器参数里、路径参数里有展开不了的短名时也不送审；那样没有后端时仍然是问，不是 deny。
4. **R20-1 要先定设计。** 守卫不知道哪个程序是 MSYS 的。一种做法：Windows 上的 bash 方言里，重定向的目标照旧算设备，命令参数里只有 `/dev/null` 算设备，其余五个名字记成路径。代价是 `head -c 16 /dev/zero` 这类写法要问。
5. **真实宿主里还没有跑。** 修订 17 到 20 都没有跑过真实冒烟。
