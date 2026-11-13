# `$LASTEXITCODE` 和 `$?` 算已知值（规格修订 23）

日期：2026-11-11。基线：`295badc`（代码 `646cb05`）。依据：`docs/reports/M3a-ps-expression-output.md` 第 6 节第 2 条。

使用者说"当做已知值"。修订 22 把值有去处的表达式记成 `Write-Output <表达式>`，代价是 `git status; $LASTEXITCODE` 这样的收尾写法在默认配置下由 allow 变成问。这次把这两个变量算作已知值。

使用者说"代码一次、文档一次"：代码（修订 23 到 26 一起）在 `8d268d3`，这份记录和规格在其后一个提交（`ced7a87`）。**已推送**（2026-11-12，使用者说"推送"），没有打标签。复审见 `docs/reviews/M3a-rev23-26-review.md`。（2026-11-12 更正：这里原来写的是提交时的状态"没有推送"。）

没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务（模型是 `FakeBackend`），没有打开留出批次和攻击样本。实测用的是一个只在那次运行里存在的假环境变量，值也是假的。

## 1. 结论

- `git status; $LASTEXITCODE`、`Get-Date; $?`、`Get-Date; "exit=$LASTEXITCODE"` 回到由规则放行。
- 做的比"加两个名字"多，因为实测发现这个名字能被同一行绑上任意值。直接加名字会开出一个不需要后端的放行口子：`param($LASTEXITCODE = $env:SECRET_TOKEN) Get-Date; $LASTEXITCODE` 打印环境变量。所以加了两道限制（第 3 节）。
- 规则条目与策略文件没变，Bash 没变。手头语料 1146 条 PowerShell 命令的级别没有一条变化。

## 2. 实测（PowerShell 5.1.26100.9818）

假环境变量 `BK_RV23_FAKE`，值里带标记。每条在新的 `powershell.exe -NoProfile -Command` 里跑，看输出里有没有标记。

| 写法 | 打印出标记 |
|---|---|
| `cmd /c exit 7; $LASTEXITCODE; $?` | 否（打印 `7`、`True`） |
| `param($LASTEXITCODE = $env:BK_RV23_FAKE) Get-Date \| Out-Null; $LASTEXITCODE` | **是** |
| `param(${LASTEXITCODE} = …)`、`param($script:LASTEXITCODE = …)` | **是** |
| `foreach ($LASTEXITCODE in $env:BK_RV23_FAKE) { $LASTEXITCODE }` | **是** |
| `foreach ($LASTEXITCODE in $env:BK_RV23_FAKE) { }; $LASTEXITCODE`（循环之后） | **是** |
| `1 \| ForEach-Object { param($LASTEXITCODE = …) $LASTEXITCODE }` | **是** |
| `& { param($LASTEXITCODE = …) $LASTEXITCODE }` | **是** |
| `function f($LASTEXITCODE = …) { $LASTEXITCODE }; f` | **是** |
| `Set-Variable LASTEXITCODE $env:BK_RV23_FAKE; $LASTEXITCODE` | **是** |
| `New-Variable LASTEXITCODE $env:BK_RV23_FAKE -Force; $LASTEXITCODE` | **是** |
| `… \| Write-Output -OutVariable LASTEXITCODE \| Out-Null; $LASTEXITCODE` | **是** |
| `… \| Tee-Object -Variable LASTEXITCODE \| Out-Null; $LASTEXITCODE` | **是** |
| `… \| Set-Variable LASTEXIT*; $LASTEXITCODE`（变量已存在时，通配符） | **是** |
| `Set-Item Variable:\LASTEXIT* $env:BK_RV23_FAKE; $LASTEXITCODE` | **是** |
| `param(${?} = …) ${?}`、`foreach (${?} in …) { ${?} }` | 否 |
| `Set-Variable ? …; $?`、`-OutVariable ?` | 否（报错：只读或常量） |
| `$LASTEXITCODE++`（之前是 7） | 否（打印 `8`） |

`$?` 绑不上别的值。`$LASTEXITCODE` 是普通的全局变量，参数、`foreach`、按名字放值的命令都能改它。

## 3. 修法

**`pscmd`（已知值）**：值有去处的表达式（名字种类 `output`）里，下面几种不建命令：
- `$LASTEXITCODE`、`$?`，不带作用域，不分大小写，`${LASTEXITCODE}` 也算；
- 双引号字符串（含 here-string），里面只展开这两个变量和 `$true`、`$false`、`$null`，没有 `$(…)`；
- 它们和常量的数组。

**限制一：只在"安静的一行"里算**（`pscmd._quiet`）。整行每条命令都满足：
- 名字是常量（不是变量、表达式）；
- 参数都是常量：字符串、数字、它们的数组、不带值或带常量值的参数。变量、带变量的字符串、括号、`$(…)`、脚本块、splat 都不算；
- 没有一个字符串参数可能指到这个名字：含 `lastexitcode`（不分大小写），或者最后一个 `:`、`\`、`/` 之后的部分是能匹配它的通配符（`LAST*`、`L[a]STEXITCOD?`、`*`）。

不安静时照修订 22 记成 `Write-Output $LASTEXITCODE`，带变量是灰色，有后端时请求里有它。值有去处的表达式和带盘符的变量本身不是"拿名字的命令"，不影响这个判断。`$true`、`$false`、`$null` 不受这条限制，和原来一样。

**限制二：参数和 `foreach` 变量**（`pshelper.ps1`）。名字是 `LASTEXITCODE` 或 `?` 的参数（脚本、函数、脚本块的 `param`）和 `foreach` 变量，辅助进程报进 `loose`，名字 `AutomaticVariable`，整行是灰色 `ps-outside-command:AutomaticVariable`，不送审、直接问。带作用域的名字一样算；写在命令参数里的脚本块里也报（修订 21 的 `loose` 只报命令参数之外的，这一项例外）。

赋值语句（`$LASTEXITCODE = …`、`for` 的初始化、括号里的赋值）本来就是灰色 `ps-compound:AssignmentStatementAst`，不送审，没有改。

**这样之后还能给它放值的**：安静的一行里运行的代码（`.\build.ps1; $LASTEXITCODE` 的脚本、模块里的函数）。那些代码自己就能打印任何东西，这次打印没有带来新的能力。

**没有改的**：
- H-4 那张表（命令参数里哪些展开的词算无害：`psprograms._BENIGN_EXPANSIONS`、`event._BOOLEAN_LITERALS`、`pscmd._BOOLEAN_LITERALS`）。修订 22 的记录写过"要放宽应该改那张表，两种写法一起放"，这次没有照办：那张表管所有命令、两种 shell（Bash 里 `$LASTEXITCODE` 是普通变量），改了会让带这个变量的任何命令都能被 allow 规则放行；而 `Write-Output` 没有 allow 规则，改了表 `Write-Output $LASTEXITCODE` 也还是问。所以 `Write-Output $LASTEXITCODE`、`ConvertTo-Json $LASTEXITCODE`、`Get-Date -Format $LASTEXITCODE` 不变。
- 管道开头：`$LASTEXITCODE | Out-Host` 里后面的命令照旧带 `ps-pipeline-head-dynamic`。

## 4. 判决变化

专门扫描（scratchpad 的 `rv23_scan_full.py`）：24 种文字 × 45 个位置，1080 行，对 `295badc` 的代码。位置里有 18 种"同一行另外给这个名字放值"的写法。

| | 行数 |
|---|---|
| 级别相同 | 736 |
| 变松：灰色送审 → allow | **50** |
| 变紧：allow → 问 | 10 |
| 变紧：灰色送审 → 问 | 284 |

- 变松的 50 行全是已知值（10 种写法）写在放行的命令旁边，5 个位置：`Get-Date` 之后、之前、下一行，`git status` 之后，以及 `param($x = $env:…) Get-Date` 之后（绑的是别的名字，那个值没有被打印）。不是已知值的写法没有一行变松。
- 给这个名字放值的 18 种写法里，没有一行由规则放行。两行例外是对照：`Get-Date -OutVariable LASTEXITCODE; 'text'` 和 `…; $true`，打印的是常量，修改前也放行。
- `Set-Variable LASTEXITCODE $env:…; <已知值>` 和 `Get-Date -OutVariable LASTEXITCODE; <已知值>` 各 10 行仍然送审，请求里有 `Write-Output` 那一条。
- 变紧 allow → 问的 10 行：`param($LASTEXITCODE = …) Get-Date; 'text'` 这类，行里有那个参数或 `foreach` 变量，原来因为打印的是常量而放行。
- 变紧送审 → 问的 284 行里，254 行是带那个参数或 `foreach` 变量的（现在不送审），30 行是整行只剩已知值、没有命令的（`$LASTEXITCODE` 单独一条、`foreach ($i in 1, 2) { $LASTEXITCODE }`）：和 `'text'` 单独一条一样，是"什么都没看懂"，直接问。
- 没有一行少记路径。

手头语料（`tests/corpus` 和评测集的 PowerShell 命令，不含留出集）1146 条：级别变了的 0 条。

（后记：修订 24、25 做完之后在最终的代码上再跑这个扫描，变松的是 40 行、4 个位置。`param($x = $env:…) Get-Date` 之后那个位置不再放行，因为修订 24 把参数的默认值记成了一条命令；对照里 `param($x = $env:…) Get-Date; 'text'` 两行也由 allow 变成灰色送审。其余的数字相同。）

## 5. 测试

| 测试和检查 | 结果 |
|---|---|
| 新测试文件 `tests/unit/test_m3a_ps_known_variables.py` | 190 passed |
| 新测试文件在 `295badc` 的代码上 | 88 条失败，102 条通过（通过的是对照：不算已知值的写法、命令参数里的、赋值、别的名字的参数） |
| 修订 22 的专门扫描（928 行）在新代码上 | 12 行变松（`$LASTEXITCODE`、`$?`、`"exit=$LASTEXITCODE"` 写在 `Get-Date` 之后、之前、下一行和 `git status` 之后），12 行由送审变成问（这三种单独一条、或在只有它的循环体里，整行没有命令），其余级别相同。带标记送审的仍是 336 行，没有一行少记路径 |
| `scripts/gen_ps_fixtures.py --check` | 235 个夹具，0 个不同（夹具没有变） |
| 变异：35 个（辅助进程 10 个，`pscmd` 25 个），在副本上跑新测试文件、`test_m3a_ps_expression_output.py`、`test_norm_pscmd.py` | 35 个全部抓到 |
| `boundkeep test` default / strict | 1142 / 0 失败，334 / 0 失败 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过 |
| 原有差分（修订 16 到 20 的扫描、修订 17 和 IR-1 的真实目录树、带冒号的普通命令、系统目录、逐程序、真实磁盘 23544 条、假机器 179508 条、孪生项目 30720 条、含 git 或 `~` 的语料 1164 次判决），在修订 23 的代码上跑一遍、修订 23 到 26 全部做完后又跑一遍 | 两次都是级别全部相同，没有一行少记路径。`boundkeep test` 1142 / 0、334 / 0。评测指标相同，`results/*.json` 除日期和延迟外只有 `atk-exfil-032` 的灰色原因多了几个（修订 22 起就是这样），`eval/report.md` 没有重新生成 |
| 全量（和修订 24、25、26 一起跑，分六段，不是一个进程） | 29659 passed、169 skipped、0 失败，六段都一次跑完，合计与收集到的 29828 条相同，各段用时合计 2:21:22。开始和结束时电源都是最佳性能。跑完核对过代码与四个新测试文件的指纹，没有变 |

修订 22 的测试 `test_it_gets_what_write_output_gets` 里原来有 `$LASTEXITCODE`、`$?`、`"exit=$LASTEXITCODE"` 三条，现在它们不再和 `Write-Output` 的写法判得一样，换成了 `$global:LASTEXITCODE` 和 `"exit=$LASTEXITCODE $x"`。

冒烟脚本 `scripts/smoke_claude_m3a.py` 的 `readings` 一段加了修订 17 到 23 的 9 条探针。`--only readings --dry`（不调用 Claude，直接把调用发给实验目录里的 hook）22 项 0 失败；修订 24 又加了一条，23 项 0 失败。真实宿主（2026-11-12，Claude Code 2.1.318，使用者在自己的终端里运行）：23 项 0 失败，约 0.215 美元，记在 `docs/hook-behavior.md`。

## 6. 代价和残余

1. **有后端时，安静的一行送审的请求里没有这次打印**。`npm test; $LASTEXITCODE` 的请求里只有 `npm test`。行里运行的代码能给 `$LASTEXITCODE` 放任意值再让它被打印，但那些代码自己就能打印。
2. **整行只有已知值时由送审变成问**（扫描里的 30 行）：`$LASTEXITCODE` 单独一条。默认配置下它本来就是问。
3. **常量参数里带通配符 `*` 结尾的一行不算安静**：`Get-ChildItem src\*; $LASTEXITCODE` 里它仍是 `Write-Output`，是问。原因是守卫不知道哪个参数会被当成变量名，只能按文字判断。`*.py` 这样的不受影响。
4. **带变量参数的一行不算安静**：`pytest $args; $LASTEXITCODE`、`git commit -m "$msg"; $LASTEXITCODE`。这样的行因为带变量本来就不由规则放行。
5. **`-OutVariable` 之外的公共参数没有单独处理**，靠"参数里出现这个名字"一并挡住。名字必须写全或写成通配符，所以没有别的写法。
6. **只在 PowerShell 5.1 上量过**。

## 7. 没有做的

- `$global:LASTEXITCODE`、`$script:LASTEXITCODE` 不算已知值。
- 别的自动变量（`$PSVersionTable`、`$PWD`、`$Error`）不算。
- 命令参数里的 `$LASTEXITCODE` 不变（第 3 节）。
- 修订 22 留下的：`if ($env:A)`、`exit $env:A` 的文字仍不在请求里；`foreach ($u in '常量')` 和参数默认值绑的常量也不在。
- PowerShell 7 上没有量。
