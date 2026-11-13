# PowerShell 里值有去处的表达式（规格修订 22，O-3）

日期：2026-11-11。基线：`a91dfe6`（代码 `e52c596`）。依据：`docs/reports/M3a-ps-outside-command.md` 第 7 节的 O-3。

使用者说"按照你建议执行；先提交修订21再去修改O-3"。O-3 当时列了两种修法，没有写推荐。这次开发 agent 推荐并采用第一种（当作 `Write-Output <表达式>`），做法上有一处不同，所以当时写的代价没有发生，见第 4 节。

全量跑完后使用者说"提交，不推送"。代码在 `646cb05`，这份记录和规格在其后一个提交。**已推送**（2026-11-11，使用者说"先推送"，`origin/main` = `295badc`），没有打标签。复审见 `docs/reviews/M3a-rev21-22-review.md`。（2026-11-12 更正：这里原来写的是提交时的状态"没有推送"和"这次修复没有复审"。）

没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务（模型是 `FakeBackend`），没有打开留出批次和攻击样本。实测用的是一个只在那次运行里存在的假环境变量，值也是假的。

## 1. 结论

**修了 O-3**：PowerShell 里表达式可以站在命令的位置上。`$env:TOKEN` 单独成句就把值打印出来，和 `Write-Output $env:TOKEN` 一样，但它不是命令，原来守卫不看它。

- 原来 `Get-Date; $env:SECRET_TOKEN`、`Get-Date; "key $env:SECRET_TOKEN"`、`Get-Date; ($env:SECRET_TOKEN)` 由规则放行（`allow-ps-no-path-commands`），不需要 LLM 后端。`Write-Output $env:SECRET_TOKEN` 从 M1c-2 的 H-4 起就是灰色。
- 现在值有去处的表达式按 `Write-Output <表达式>` 记成一条命令：单独成句、`return` / `throw` 后面、管道开头、`foreach` 的集合、`switch` 的条件。带变量的是灰色 `ps-dynamic-arg`，默认配置下问，有后端时送审，请求里有它的文字。
- 值已经知道的不记：常量和 `$true`、`$false`、`$null`。`Get-Date; 'done'` 照旧由规则放行。

**规则条目和策略文件没有改，Bash 没有改。** 会动手的表达式（修订 21 的 `ps-outside-command`）照旧不送审。

**有一类变松**（只在有后端时）：整行没有任何命令、只有表达式的调用，原来靠"什么都没看懂"直接问，现在和 `Write-Output` 的写法一样送审（第 6 节第 1 条）。

## 2. 修改前后

没有后端时看规则判决；"送审"一栏是有后端时会不会把这次调用交给模型。

| 写法（PowerShell） | 修改前 | 修改后 |
|---|---|---|
| `Get-Date; $env:SECRET_TOKEN`、`${env:SECRET_TOKEN}`、`$x`、`$global:x` | **allow**（`allow-ps-no-path-commands`） | 灰色 `ps-dynamic-arg`，送审，文字在请求里 |
| `Get-Date; "key $env:SECRET_TOKEN"`、here-string、`$env:A, 1`、`($env:A)`、`@{ a = $env:A }` | **allow** | 灰色，送审，文字在请求里 |
| `git status; $LASTEXITCODE`、`git status; $?`、`git status; "exit=$LASTEXITCODE"` | allow | 灰色，送审（代价，第 6 节第 2 条） |
| `Get-Date; $($env:A)`、`@($env:A)`、`$env:A -eq 'x'`、`-not $env:A` | 灰色，送审，请求里没有它的文字 | 灰色，送审，文字在请求里 |
| `Get-Date; if ($true) { $env:A }`、函数体、`try` / `catch`、`return $env:A`、`throw $env:A` | 灰色，送审，请求里没有它的文字 | 灰色，送审，文字在请求里 |
| `$env:A \| Out-Host`、`$env:A \| Set-Content x.txt` | 灰色，送审，请求里只有后面那条命令 | 灰色，送审，多一条 `Write-Output $env:A` |
| `foreach ($x in $env:A) { $x }`、`switch ($env:A) { default { $_ } }`、`$env:A`（单独一条） | 灰色，不送审（什么都没看懂） | 灰色，送审，文字在请求里（第 6 节第 1 条） |
| `Get-Date; 'done'`、`42`、`'a', 'b'`、`$true`、`$null` | allow | allow |
| `Get-Date; (Get-Location)` | allow | allow |
| `Get-Date; [IO.File]::Delete('x')`、`$env:A.Length`、`[string]$env:A` | 灰色，不送审（修订 21） | 灰色，不送审，多一条 `Write-Output` |
| `Get-Date; if ($env:A) { … }`、`exit $env:A`、`$v = $env:A` | 灰色（赋值不送审） | 不变 |
| `Write-Output $env:A`、`ForEach-Object { $env:A }`、`& { $env:A }` | 灰色，送审 | 不变 |
| `Get-Date; ${E:\proj\README.md}` | allow | allow |
| `Get-Date; "${E:\proj\README.md}"` | allow | 灰色，送审（第 6 节第 3 条） |
| `$env:A > x.txt` | 灰色，送审 | 不变 |
| Bash 的全部写法 | 不变 | 不变 |

## 3. 实测

PowerShell 5.1.26100.9818。每种写法在一个子进程里跑，环境变量 `BK_O3_FAKE` 的值是假的，只在那次运行里存在。

| 写法 | 输出里有没有那个值 |
|---|---|
| `Get-Date \| Out-Null; $env:BK_O3_FAKE` | 有 |
| `Get-Date \| Out-Null; ${env:BK_O3_FAKE}` | 有 |
| `Get-Date \| Out-Null; ($env:BK_O3_FAKE)` | 有 |
| `Get-Date \| Out-Null; $env:BK_O3_FAKE, 1` | 有 |
| `Get-Date \| Out-Null; @{a = $env:BK_O3_FAKE}` | 有 |
| `if ($true) { $env:BK_O3_FAKE }` | 有 |
| `function f { $env:BK_O3_FAKE }; f` | 有 |
| `try { $env:BK_O3_FAKE } catch { }` | 有 |
| `foreach ($x in $env:BK_O3_FAKE) { $x }` | 有 |
| `switch ($env:BK_O3_FAKE) { default { $_ } }` | 有 |
| `return $env:BK_O3_FAKE` | 有 |
| `throw $env:BK_O3_FAKE` | 有，在错误信息里 |
| `$env:BK_O3_FAKE \| Out-Host` | 有 |
| `exit $env:BK_O3_FAKE` | 没有 |
| `if ($env:BK_O3_FAKE) { }` | 没有 |
| `$x = $env:BK_O3_FAKE` | 没有 |
| `Get-Date \| Out-Null; $true; $null; $false` | 打印 `True`、`False`，`$null` 什么都不打印 |

带变量的字符串（`"key $env:BK_O3_FAKE"`）这一行没有量成：引号在传给子进程时被剥掉了。它打印展开后的字符串是 PowerShell 的基本行为，这里没有重量。

## 4. 修法

O-3 当时写的第一种修法有一条代价：单独一条的会动手的表达式（`[IO.File]::Delete('x')`）会从"不送审"变成"带着文字送审"。这次没有发生，因为两件事分开了：表达式记成 `Write-Output` 是为了让规则层和请求看得到它；会动手的表达式另有修订 21 的灰色原因 `ps-outside-command`，那个原因照旧让整个调用不送审。

O-3 当时把"`git status; "exit=$LASTEXITCODE"` 在默认配置下由 allow 变成问"只写在第二种修法下面。**这条代价第一种修法也有**：`Write-Output` 带变量在规则层是灰色，没有后端时灰色就是问。当时写漏了，这次的做法有这条代价（第 6 节第 2 条）。

**辅助进程 `pshelper.ps1`**（只解析，不执行，这一点没有变）：

- 所有不带重定向的表达式语句（`CommandExpressionAst`）都检查一遍，值有去处的报成一条命令：名字的种类是 `output`，表达式是它唯一的参数。位置（`Test-Output`）：
  - 管道里不止它一个元素：它在管道开头，值流进后面的命令；
  - 它是脚本、函数、脚本块的语句，或是 `if`、循环、`switch`、`try` / `catch` / `finally`、`trap` 的语句块里的语句；
  - 它在 `return`、`throw` 后面；
  - 它是 `foreach` 的集合或 `switch` 的条件。
- 不报的：
  - 在某条命令的参数里的（沿用修订 21 的 `Test-Loose`）；
  - `$(…)`、`@(…)` 里面的语句，括号和哈希表里面的：外面那一层已经整段报了；
  - `if`、`while`、`do`、`for` 的条件，`exit` 后面，赋值的右边；
  - 带盘符的变量本身：它已经是一条 `file-read`；
  - 只包着命令的括号（`(Get-Location)`）：里面的命令各自照常报。
- 带重定向的表达式照旧报成名字是表达式的命令。

**`pscmd.py`**：

- 名字种类是 `output` 的一条变成 `Write-Output <表达式>`，表达式照普通参数转成词：变量和带变量的字符串是会展开的词，括号、`$(…)`、哈希表等是 `$(<原文>)` 加灰色 `ps-dynamic-value:<类型>`。
- 值已经知道的不建命令：字符串常量、数字、`$true` / `$false` / `$null`（不分大小写），以及全由它们组成的数组。
- `elements` 不是正好一项的，是 `ps-internal-error`，不建命令。
- 名字不经过别名查找：这一行重新定义了什么别名都不影响它。

**规则层没有改**：`Write-Output` 带会展开的词，`psprograms` 原来就给 `ps-dynamic-arg`（H-4 的修复）。

**文档**：规格修订 22（修订说明、§5.1、§7 的一句）；`docs/powershell-dialect.md`；`docs/m1b-design.md` 的回复格式。

**测试**：

- 新文件 `tests/unit/test_m3a_ps_expression_output.py`，167 条。
- `tests/unit/test_m3a_ps_outside_command.py`：四条断言跟着改（多了一条 `write-output`；"变量不改变判决"那一条只留常量）。
- `tests/corpus/powershell_parse.yaml`：11 条期望里加上 `Write-Output` 这一条（两条单独成句的方法调用，九条以表达式开头的管道）。
- `tests/unit/test_m1c2_ps_pipehead.py`：一条断言跟着改（管道开头多了一条 `output`）。
- `tests/unit/test_norm_pscmd.py`：形状校验器认识 `output` 这个名字种类（名字为空、正好一个表达式）。
- 夹具用真的辅助进程重新生成：`tests/fixtures/ps_ast/` 235 个里 35 个有变化，`tests/fixtures/ps_ast_manual/` 58 个里 1 个。变化都是多出来的 `output` 命令，原有的内容没有变。

做的过程里测试抓到两处错：

- 值已经知道的条目一开始直接跳过，没有检查条目别的部分（`redirects` 等）；随机变形测试要求不合格的回复一定是灰色。改成先走完整条检查，最后才不建命令。
- 一度删掉了"父节点不是管道就不算"的检查，以为它多余。赋值右边的表达式正好不在管道里，`$b = $a` 被报成了输出；新测试当场失败，检查已恢复。

## 5. 度量

"级别"分五档，从松到严：allow、灰色送审、灰色不送审（问）、ask、deny。旧代码是 `e52c596` 的 `src`，导出到 scratchpad，经 `RR_SRC` 加载。

**专门扫描**：真实目录树（假文件），32 种文字 × 29 个位置，共 928 行，新旧代码各跑一次。

- 32 种文字：19 种带变量的（环境变量、普通变量、`$LASTEXITCODE`、`$?`、带变量的字符串和 here-string、数组、括号、`$(…)`、`@(…)`、哈希表、比较、`-not`、括号包着的命令）；7 种值已经知道的；3 种会动手的；3 种带盘符的变量。
- 29 个位置：单独一条；跟在 `Get-Date` 后面、前面、下一行；跟在 `git status`、`make test` 后面；`if`、`else`、函数、`try`、`catch`、`while`、`foreach`、`switch` 的语句体；`return`、`throw`、`exit`；管道开头（后面是 `Out-Host`、`Set-Content`、`curl.exe`）；`foreach` 的集合、`switch` 的条件；`if`、`while` 的条件；赋值右边；命令参数；脚本块参数；`& { }`；带重定向。

| 类别 | 行数 | 级别相同 | 更严 | 变松 |
|---|---|---|---|---|
| 带变量的 | 551 | 391 | 52 | 108 |
| 值已经知道的 | 203 | 189 | 0 | 14 |
| 会动手的 | 87 | 87 | 0 | 0 |
| 带盘符的变量 | 87 | 82 | 5 | 0 |

- 更严的 52 行都是 allow 变成灰色送审：13 种带变量的文字，各在 4 个位置（跟在 `Get-Date` 后面、前面、下一行，跟在 `git status` 后面）。这就是 O-3。
- 带变量的行里，修改前 57 行是 allow，修改后剩 5 行，都是 `(Get-Location)`（括号包着的命令，不是变量）。
- 送审而且请求里有那个变量名的：修改前 56 行，修改后 336 行。修改后送审而请求里没有它的，只剩 `if` / `while` 的条件和 `exit` 后面（第 7 节）。
- 变松的 122 行都是同一种情况：修改前整行没有任何命令，靠"什么都没看懂"不送审；修改后有了 `Write-Output` 这一条，照常送审（第 6 节第 1 条）。位置是单独一条，`while`、`foreach`、`switch` 的语句体，`foreach` 的集合和 `switch` 的条件。
- 带盘符的变量更严的 5 行是写在字符串里的那一种（第 6 节第 3 条）。
- 会动手的 87 行级别都没变，照旧不送审或由别的原因决定。
- 没有一行少记了路径。

**修订 21 的扫描**（694 行）在新代码上重跑：12 行由 allow 变成灰色送审（跟在 `Get-Date` / `git status` 后面的变量、带变量的字符串、哈希表、`$function:prompt`、`$alias:ls`），10 行由灰色不送审变成灰色送审（单独一条的同类写法），其余 672 行级别相同。会动手的表达式 272 行级别全部相同。

**手头语料上的代价**：测试语料和评测集（不含留出批次）里全部 1146 条 PowerShell 命令，在假的 Windows 机器上按 `boundkeep test` 的方式判，再过发送闸门：**级别变了的 0 条**。语料里没有"规则放行的命令后面跟一个裸变量"这种写法。

**原有差分**（基线是修订 21 代码的输出）：

| 差分 | 结果 |
|---|---|
| 修订 20 的扫描（2482 行） | 全部相同 |
| 修订 19 的扫描（160 行） | 全部相同 |
| 修订 18 的扫描（5100 条） | 全部相同 |
| 修订 17 的真实目录树扫描（10092 条） | 全部相同。和别的差分连着跑的那一次有 1 行 Bash 命令撞到时间预算（deny 变成灰色 `budget:time`，电源模式是最佳能效），单独重跑后 10092 行逐行相同 |
| 修订 16 的扫描（12768 条） | 全部相同 |
| IR-1 的扫描（10320 条） | 级别全部相同；Bash 和 PowerShell 的 5160 对判决仍然全部相同。有 1 行的灰色原因不同：基线里那一行撞过时间预算，这次没有 |
| 带冒号的普通命令（492 条）、系统目录、逐程序 | 全部相同 |
| 真实磁盘（23544 条）、假机器（179508 条）、孪生项目（30720 条） | 级别全部相同 |
| 含 git 或 `~` 的语料（655 条，1164 次判决） | 0 条不同 |
| `boundkeep test` default / strict | 1142 / 0 失败，334 / 0 失败 |
| 评测（`--config rules+taint --test-contaminated`，输出到 scratchpad） | 指标全部相同。`results/*.json` 除日期和延迟外，只有 test 切分那条漏判样本（`atk-exfil-032`）的灰色原因又多了几个，判决没变。仓库里的 `eval/report.md` 没有重新生成 |

| 测试和检查 | 结果 |
|---|---|
| 新测试文件 | 167 passed |
| 新测试文件在 `e52c596` 的代码上 | 127 条失败，40 条通过（通过的是对照：值已经知道的、会动手的、赋值、手写回复里和这次无关的） |
| 最相关的 5 个测试文件（新文件、`test_m3a_ps_outside_command.py`、`test_norm_pscmd.py`、`test_norm_psparse.py`、`test_m1c2_ps_pipehead.py`） | 1660 passed，1 skipped |
| `scripts/gen_ps_fixtures.py --check` | 235 个夹具，0 个不同 |
| 变异：45 个，在副本上跑新测试文件、`test_m3a_ps_outside_command.py`、`test_norm_pscmd.py`、`test_norm_psparse.py` | 44 个抓到，1 个存活，是等价的：给"值有去处的位置"加上赋值语句。赋值右边的表达式不在管道里（实测 `$b = $a`、`$b = ($a)`），前一个检查已经把它挡掉，加不加这一项结果一样 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过 |
| 全量（分六段跑，不是一个进程；收集到 29280 条） | **29110 passed，169 skipped，1 failed**，合计 29280，与收集到的相同。六段都一次跑完，各段用时合计 2:42:49（开始时电源模式是最佳能效）。跑完后核对过工作区没有变（`git diff HEAD` 在代码、测试和测试会读的文档上的哈希，以及新测试文件的哈希，都和开始时相同） |
| 失败的那一条 | `test_m1c2_devtools_bash.py::test_d_everything_else_is_classified_as_before[python -x -m pytest-expected7-bashposix]`，在第 1 段里。是 Bash 命令，结果里多了一条 `normalize-budget-exceeded` / `budget:time`，也就是归一化撞到了时间预算。全量结束后单独重跑：这次的代码 5 次都通过，整个文件 463 passed；`e52c596` 的代码 5 次都通过，整个文件 463 passed。这次没有改 Bash 的路径。在全量里没有重现过第二次，原因只能说是机器慢时撞预算，没有进一步查 |

## 6. 代价和残余

1. **整行没有命令、只有表达式的调用，有后端时由问变成送审**（扫描里的 122 行）。`$env:SECRET_TOKEN` 单独一条、`foreach ($x in $env:A) { $x }` 原来因为"什么都没看懂"直接问；现在它们是 `Write-Output $env:SECRET_TOKEN`，和这样写的命令判得一样，请求里有文字。默认配置（没有后端）下它们照旧是问。
2. **常见的收尾写法在默认配置下由 allow 变成问**：`git status; $LASTEXITCODE`、`npm test; "exit=$LASTEXITCODE"`、`make; $?`。`Write-Output $LASTEXITCODE` 原来就是这样（H-4 只把 `$true`、`$false`、`$null` 当常量）。手头语料里没有这种写法，真实使用里有多少不知道。要放宽的话应该改 H-4 那张表，两种写法一起放，这次没有动。（后记，修订 23：使用者说"当做已知值"，这两个变量在值有去处的位置上不再记成 `Write-Output`。没有照这里说的去改 H-4 那张表，原因和加的两道限制见 `docs/reports/M3a-ps-known-variables.md`。）
3. **带盘符的变量写在字符串里**（`"${E:\proj\README.md}"`）：项目里的文件原来和 `Get-Content` 一样是 allow，现在多一条 `Write-Output "<带变量的字符串>"`，是灰色。单独成句的 `${E:\proj\README.md}` 不变。
4. **哈希表、括号里的常量也算**：`Get-Date; @{ a = 1 }`、`Get-Date; ('x')` 由 allow 变成灰色送审。只有裸的常量和它们的数组不算。
5. **请求里的动作数会多**：发送闸门一次最多 8 条命令，多出来的 `Write-Output` 也占数。带很多裸变量语句的长脚本更容易超过，超过就不送审、直接问。手头语料里没有因此变化的。
6. **`Write-Output` 这个名字是守卫起的**，命令行里没有它。请求里它和真写出来的 `Write-Output` 分不开。`foreach` 的集合和 `switch` 的条件也记成它：值不是被打印，是绑到 `$x` / `$_` 上，语义上等于 `foreach ($x in Write-Output …)`。
7. **只在 PowerShell 5.1 上量过**。PowerShell 7 的管道链（`&&`、`||`）外面多一层，辅助进程照 `Add-Command` 原有的写法跳过它，这一段在 5.1 上跑不到，没有测试。

## 7. 没有做的

- **只被判断的位置不记**：`if ($env:A) { … }`、`while ($env:A) { … }`、`exit $env:A`。条件只漏一位，`exit` 把值变成退出码。有后端时这样的调用照常送审，请求里没有这段文字（修订 21 把变量算作无害，这次没有改）。
- **绑定是常量时请求里也没有它**：`foreach ($u in 'https://example.com/x') { curl.exe $u }` 的请求里是 `curl $u`，没有那个网址（常量不记）。函数参数的默认值（`function f($u = 'https://example.com/x') { curl.exe $u }; f`）也一样。赋值语句因为同样的原因不送审，这两种没有照办。这是原来就有的，这次没有变。
- `$LASTEXITCODE`、`$?` 没有放进常量表（第 6 节第 2 条）。（修订 23 已处理。）
- 真实宿主里没有跑。PowerShell 7 上没有量。
- 复审的 R19-1、R19-2、R19-3、R20-1 没有动。
