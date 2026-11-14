# 修订 23 到 26 复审的三条修复和绑到变量上的值（规格修订 27、28）

日期：2026-11-12。基线：`ced7a87`。依据：`docs/reviews/M3a-rev23-26-review.md` 的 O-4、RV26-1、RV24-1。

使用者看过复审结论之后说"按建议顺序修三条"（规格修订 27）。修的时候查到 O-5（第 7 节），使用者说"O-5 也按你的建议修"（规格修订 28）。

使用者说"代码一次、文档一次"：代码（修订 27、28 一起）在 `86a7e2f`，这份记录、复审报告和规格在其后一个提交（`4b76463`）。**已推送**（2026-11-13，使用者说"推送"），没有打标签。复审见 `docs/reviews/M3a-rev27-28-review.md`。（2026-11-13 更正：这里原来写的是提交时的状态"没有推送"。）

没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务（模型是 `FakeBackend`），没有打开留出批次和攻击样本。实测只用编出来的字符串和 TEMP 下的临时脚本，用完已删；没有运行 `sudo`。

## 1. 结论

- O-4 已修：PowerShell 辅助进程截短的字符串（超过 32768 个字符，管道开头的超过 4096 个，只报前 200 个字符）让这一行加上 `ps-too-large`，不送审、直接问。复审的 `Invoke-Expression`、`Add-Type`、`python -c`、`node -e`、`powershell -Command`、`cmd /c`、`Write-Output` 几种写法现在都不送审。
- RV26-1 已修：Bash 方言里包装器的长开关写成 `--名字=值` 时，值算包装器吃掉的词，灰色 `wrapper-option-value`，不送审。`sudo --preserve-env=X pytest -q` 现在不送审。
- RV24-1 已修：辅助进程报的 `compound`、`dynamic`、`loose` 三张类型表各最多读 64 条，超过时这一行加上 `ps-too-large`。
- O-5 已修（修订 28）：一行里绑到变量上、请求里看不到的常量（PowerShell 的参数默认值、`foreach` 的集合、`switch` 的条件、管道开头、函数体里的输出；Bash 的 `for` / `select` 词表）记进动作的 `unshown`，灰色时不送审。规则不看 `unshown`，由规则放行的照旧放行。
- 规则条目与策略文件没变。没有后端时这些调用本来就是灰色（问），判决级别不变。

## 2. O-4：被截短的字符串

**原来**：辅助进程（`pshelper.ps1` 的 `Add-TooLong`，M1b 就有）把超过 `$script:MaxString`（32768）个字符的字符串常量或可展开字符串、超过 `$script:MaxHeadString`（4096）个字符的管道开头字符串，报成 `{"t":"other","ast":"TooLongString","text":<前 200 个字符>}`。`pscmd` 记成灰色 `ps-dynamic-value:TooLongString` 和一个 200 个字符的词。这个原因不拦送审；200 个字符又低于发送闸门每个词 400 个字符的上限，所以整条调用照常送审，请求里只有开头。

复审实测（PowerShell 5.1）：`Invoke-Expression` 执行了尾部，`Add-Type -TypeDefinition` 编译了尾部；外部程序收不到这么长的参数（"文件名或扩展名太长"）。Claude Code 的 PowerShell 工具把脚本放在环境变量里交给 `Invoke-Expression`，照同样的链路 33072 和 70072 个字符的脚本都能运行。

**现在**（`pscmd._convert`）：遇到 `ast` 是 `TooLongString` 的元素，这一行加上 `ps-too-large`（`ps-dynamic-value:TooLongString` 照旧也记）。`ps-too-large` 本来就在 `pipeline._UNANALYSED_PREFIXES` 里，`pipeline` 没有改。

辅助进程报的每个元素都经过 `_convert`：命令的参数（含被丢掉的开关值）、参数的值、数组的元素、重定向的目标、管道开头、值有去处的表达式和参数默认值，所以只改这一处。辅助进程没有改，夹具不变。

别的截断核对过，不用改：
- 其余认不出的表达式的文字截在 2000 个字符，命令名截在 2000 或 32768 个字符，都超过发送闸门的上限（词 400、程序名 128），本来就不送审；
- 数字常量的文字截在 200 个字符，只少了数字；
- Bash 的词不截。

（2026-11-13 复审补充：这里只核对了单个的值。Bash 解析器在整行中途停下（嵌套超过 32 层、词数、记号数、1 MiB）时，停下之后的命令照样不在请求里，整条照常送审，见 `docs/reviews/M3a-rev27-28-review.md` 的 O-6。）

## 3. RV26-1：长开关带 `=值`

**原来**：`bash._strip` 遇到 `long_flags` 里的名字时，整个词当开关吃掉，`=` 后面的值被丢掉，`taken` 不置位，修订 26 的标记不加。运行器那边（`peel_runner_options`）带 `=` 的开关算认不出，不剥。

**现在**：`long_flags` 里的名字带 `=` 时置 `taken`，整次调用灰色 `wrapper-option-value`，不送审。包装器照旧被剥掉，里面的命令照旧由规则判。

受影响的写法：GNU `env`、`timeout` 拒绝给开关带值（实测，退出码 125，命令不运行），这些写法多问几次没有代价；接受可选值的是 `sudo --preserve-env=LIST`（sudo 手册）和 `xargs --replace=R`、`--eof=E`、`--max-lines=N`（实测），带 `xargs` 的行本来就由规则问。

## 4. RV24-1：三张类型表

**原来**：`pscmd._type_names` 读 `compound`、`dynamic`、`loose` 时各截在 64 条（`raw[:MAX_REASONS]`），截掉不留痕迹。`ps-compound:AssignmentStatementAst` 被截掉，这一行就会送审。

**现在**：超过 64 条时置 `_State.overflow`，`build` 照修订 24 在第一条加上 `ps-too-large`。

现在碰不到：辅助进程逐类型去重，PowerShell 5.1 一共只有 64 种具体的 AST 类型（复审实测），每张表只装其中一部分。防的是以后的版本类型变多（PowerShell 7 没有量）。

## 5. 判决变化

专门扫描（scratchpad 的 `rv27_scan.py`，对 `ced7a87` 的代码），627 行：
- PowerShell 字符串：9 种长度（200、400、1000、4096、4097、5000、32768、32769、40000）× 13 个位置（`Invoke-Expression`、`Add-Type`、`python -c`、`Write-Output`、可展开字符串、`-Value` 的值、数组元素、参数默认值、管道开头进 `Out-File`、管道开头进 `Invoke-Expression`、重定向目标、here-string、和 `Get-Content .env` 同一行）；
- Bash 对照 6 行（长词不截）；
- Bash 包装器的 42 个长开关 × 不带值、带 `=值` 两种写法 × 6 种命令（`pytest -q`、`git status`、`cat README.md`、`cat .env`、`rm -rf build`、`boundkeep mode audit-only`）。

| | 行数 |
|---|---|
| 被截短的字符串，送审 → 不送审（`ps-too-large`） | 27 |
| 被截短的字符串，原来就不送审（管道进解释器），现在多一个 `ps-too-large` | 5 |
| 被截短的字符串，deny 不变（和 `Get-Content .env` 同一行），多一个 `ps-too-large` | 2 |
| 长开关带 `=值`，送审 → 不送审（`wrapper-option-value`） | 136 |
| 长开关带 `=值`，级别不变（deny 88、规则问 10），多一个 `wrapper-option-value` | 98 |
| 长开关带 `=值`，原来就不送审，不变 | 18 |
| 其余（没截短的字符串、不带值的长开关、Bash 对照） | 341，判决、规则、灰色原因、程序名一项都没变 |

- 没有一行变松，没有一行少记路径。
- 送审改为不送审的 27 行都是确实被截短的：长度过了 32768，或者模板多加了字符（`"$x <串>"`、`'<串>.txt'`）之后过了；管道开头的过了 4096。
- 两份代码上都"送审、请求里没有标记"的 11 行：参数默认值是常量（7 行，第 7 节的 O-5）、管道开头的常量进 `Out-File`（4 行，写进文件的内容；也是 O-5 那一类）。没有截短的都没变。

手头语料：PowerShell 1146 条、Bash 1880 条 × posix 和 windows 两个平台（`tests/corpus` 和评测集，不含留出集）：级别变了的 0 条。

**修订 28 的专门扫描**（scratchpad 的 `rv28_scan.py`，对 `ced7a87` 的代码），316 行：
- PowerShell：9 种值（常量字符串、`~\.ssh\…` 路径、`'README.md'`、数字、`$true`、常量数组；对照：环境变量、带变量的字符串、只包着命令的括号）× 7 个位置（参数默认值、函数参数默认值、`foreach` 的集合、`switch` 的条件、管道开头、函数体的输出；对照：单独成句的打印）× 4 种用法（`Get-Content`、`Invoke-Expression`、`Write-Output`、不用）；
- Bash：6 种词表（路径、字符串、文件名、通配符、命令替换、`"$@"`）× 4 种循环体 × `for` / `select`；对照：不带 `in` 的 `for`、算术 `for`、`while`、直接写路径。

| | 行数 |
|---|---|
| PowerShell 绑定位置上的已知值，送审 → 不送审（`ps-bound-value:<位置>`） | 135 |
| PowerShell 绑定位置上的已知值，由规则放行，不变（多记一项 `unshown`） | 5 |
| PowerShell 绑定位置上的已知值，原来就不送审，不变（多记一项） | 4 |
| Bash `for` / `select` 带词表，送审 → 不送审（`for-words`） | 36 |
| Bash `for` / `select` 带词表，规则问，不变（多记一项） | 12 |
| 其余（值不是已知的、打印的位置、Bash 对照） | 124，判决、送审、请求一项都没变 |

- 没有一行变松，没有一行少记路径。
- 新代码上"送审、请求里没有标记"的只剩 6 行，都是单独成句打印的常量（`'<常量>'; Invoke-Expression README.md`）：值进的是输出，不进变量，按设计不算。

手头语料（修订 28）：PowerShell 1146 条里 9 条由送审改为不送审，都在 `tests/corpus`（管道开头的常量 8 条，如 `'~\.ssh\id_rsa' | Move-Item -Destination x`、`'x' | Out-File out.txt`、`'..\x' | Get-Content`；`foreach ($i in 1) { cd x }` 1 条），评测集 0 条，没有变松；Bash 1880 条 × 两个平台 0 条变化。

## 6. 测试

| 测试和检查 | 结果 |
|---|---|
| 新测试文件 `tests/unit/test_m3a_rev23_26_review_fixes.py` | 90 passed |
| 新测试文件在 `ced7a87` 的代码上 | 42 条失败，48 条通过（通过的是对照：辅助进程的回复形状、短字符串照常送审、不带值的开关不标、带 `xargs` 的行由规则问、没有后端时级别不变） |
| 新测试文件 `tests/unit/test_m3a_bound_values.py`（修订 28） | 116 passed |
| 它在 `ced7a87` 的代码上 | 77 条失败，39 条通过。失败里有一部分是对照，读的是新字段 `unshown`，旧代码没有这个字段 |
| 夹具 | `tests/fixtures/ps_ast` 235 个里 25 个、`ps_ast_manual` 58 个里 1 个用真的辅助进程重新生成；逐个核对过，唯一的差别是多了 `bind`（`ps_ast` 里管道开头 24 个、`switch` 1 个）。之后 `scripts/gen_ps_fixtures.py --check` 0 个不同 |
| 相邻 17 个测试文件（修订 27 时） | 1 条失败、7862 passed、1 skipped。失败的是 `test_norm_bash.py` 里和真实 bash 对比的一个样本，只在从 Git Bash 启动 pytest 时才跑，`ced7a87` 的代码上同样失败（修订 20 的记录写过） |
| 变异：修订 27，10 个（`pscmd` 8 个，`bash` 2 个），在副本上跑新测试文件、修订 24 和 26 的测试 | 10 个全部抓到 |
| 变异：修订 28，20 个（辅助进程 12 个，`pscmd` 3 个，`event` 3 个，`bash` 2 个），在副本上跑新测试文件和修订 24 的测试 | 19 个抓到，1 个存活，是等价的：去掉"类的方法"（`FunctionMemberAst`）这一支。PowerShell 5.1 里类的方法体外面还有一层 `FunctionDefinitionAst`（实测节点链），前一支已经认出。留着这一支，防别的版本结构不同 |
| 相邻 21 个测试文件（修订 28 之后） | 6 条失败、8212 passed、1 skipped。两条形状测试（`test_the_entry_has_the_shape_of_a_command`、`test_fixture_index_is_complete_and_consistent`）断言了条目的键集合，现在绑定位置上多一个 `bind`，已改；两条 `switch -File` 用例的不送审理由变了，改成不把 `-File` 的路径算作绑定（第 7 节），测试没有改；`test_idle_death_is_noticed_and_restarted_without_any_request` 有 5 秒的等待，当时原有差分在同时跑，单独重跑 5 次都过，`ced7a87` 上也过；和真实 bash 对比的那一条同上。改完后受影响的 5 个文件 1292 passed |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过 |
| 原有差分（修订 16 到 20 的扫描、修订 17 和 IR-1 的真实目录树、带冒号的普通命令、系统目录、逐程序、真实磁盘 23544 条、假机器 179508 条、孪生项目 30720 条、含 git 或 `~` 的语料 1164 次判决），修订 27、28 都做完后 | 级别全部相同，没有一行少记路径。`boundkeep test` 1142 / 0、334 / 0。评测指标相同，`results/*.json` 除日期和延迟外只有 `atk-exfil-032` 的灰色原因多了几个（修订 22 起就是这样），`eval/report.md` 没有重新生成 |
| 全量（修订 27、28 一起跑） | 分六段跑，不是一个进程：29866 passed、169 skipped、0 failed，合计与收集到的 30035 条相同，各段用时合计 2:24:42（开始、续跑和结束时电源都是最佳性能）。中途按使用者的话停过一次：前五段跑完（25112 passed、166 skipped），第 6 段在约 95% 时停下（已跑的 4571 条没有失败）；续跑前核对 `git diff HEAD -- src tests policies eval scripts docs/policy-reference.md docs/powershell-dialect.md` 的哈希和两个新测试文件的哈希都没有变，第 6 段从头单独跑：4754 passed、3 skipped |

## 7. O-5：绑到变量上的值（修订 28）

PowerShell 里绑到变量上的常量不在请求里。修订 22 让值已经知道的表达式（常量，`$true`、`$false`、`$null`）不建 `Write-Output`，理由是打印它不多给什么；修订 24 把参数默认值也报成这样的表达式，沿用了这条豁免。但参数默认值、`foreach` 的集合、`switch` 的条件、喂给别的命令的管道开头不是打印，而是把值**绑到变量上**，之后变量可能被执行、被当路径用。

探针（默认策略，没有后端，假项目在 TEMP 下）：

| 写法（PowerShell） | 判决 | 送审 | 请求里有那个值 |
|---|---|---|---|
| `param($p = '~\.ssh\id_rsa') Get-Content $p` | 灰色 | 送审 | 没有 |
| `foreach ($p in '~\.ssh\id_rsa') { Get-Content $p }` | 灰色 | 送审 | 没有 |
| 对照：`Get-Content ~\.ssh\id_rsa` | deny（`no-secret-read`） | — | — |
| `param($x = '<代码>') Invoke-Expression $x`、函数参数默认值同样写法 | 灰色 | 送审 | 没有 |
| `foreach ($c in '<代码>') { Invoke-Expression $c }`、`switch ('<代码>') { default { Invoke-Expression $_ } }` | 灰色 | 送审 | 没有 |
| `'<代码>' \| ForEach-Object { Invoke-Expression $_ }` | 灰色 | 送审 | 没有 |
| `param($p = '<程序>.exe') & $p` | 灰色 | 送审 | 没有 |
| 对照：`$x = '<代码>'; Invoke-Expression $x` | 灰色 | 不送审（`ps-compound:AssignmentStatementAst`） | — |
| 对照：`'<代码>' \| Invoke-Expression` | 灰色 | 不送审（`ps-pipe-to-interpreter`） | — |
| `param($p = '~\<名字>') Remove-Item -Recurse -Force $p`、`foreach` 同样写法 | deny（`rm-outside-project`，删除目标定不下来） | — | — |

按 X1 审查 F3、F4 的标准是中危：模型被要求放行它没看到的值。要后端。早于修订 23（`foreach` 的集合、`switch` 的条件、管道开头从 M3a 的发送闸门起就这样；参数默认值从修订 24 起照修订 22 的规则豁免）。修订 24 只看了带变量的默认值，修订 23 到 26 的复审也没有查到；修这三条时的扫描（`rv27_scan.py`）里出现了"送审、请求里没有标记"的几行，才看出它们和打印不是一回事。

当时要先定设计，先没有改，提出的做法是：绑定位置上的已知值不建命令、不加灰色原因，只记进 `Action.unshown`（规则不看它，只决定不送审）。使用者说"O-5 也按你的建议修"。

修的时候又查到同一类的三处，一起修了：
- `data v { '<代码>' }; Invoke-Expression $v`：数据段把里面的输出绑到 `$v` 上；
- `function f { '<代码>' }; Invoke-Expression (f)`、`function f { return '~\.ssh\id_rsa' }; Get-Content (f)`：函数体里的常量输出交给调用者（函数定义本身不在请求里）；
- Bash 的 `for p in ~/.ssh/id_rsa; do cat "$p"; done`、`for c in '<代码>'; do eval "$c"; done`、`select …`：词表不是命令，请求里只有循环体里的 `cat $p`、`eval $c`。`set -- <词>` 的词在 `set` 的参数里，请求里有，不算。

**现在**：
- 辅助进程给值有去处的表达式里**绑定位置**上的那些多报一个键 `"bind"`：`default`（参数默认值）、`foreach`（集合）、`switch`（条件）、`head`（管道开头）、`body`（函数、`filter`、类的方法、脚本块表达式、`data` 段里的语句）。打印的位置（函数和脚本块之外单独成句、`return`、`throw` 后面）不报。`switch -File <路径>` 的路径也不报：它绑的是文件的各行，修订 21 已经让它不送审（第一版报了，相邻测试里两条 `switch -File` 的用例不送审的理由由 `ps-outside-command:SwitchStatementAst` 变成了 `ps-bound-value:switch`，于是排除）。
- `pscmd` 遇到带 `bind` 的条目、值又已经知道时，照旧不建命令，另记一项 `ps-bound-value:<位置>`，放进 `BashResult.unshown`；值不是已知的照旧记成 `Write-Output`，请求里有它。
- Bash 解析器在 `for NAME in 词…`、`select NAME in 词…` 读到至少一个词时记 `for-words`。词里的命令替换照旧解析成命令。
- `event` 把这一行的 `unshown` 加到这一行每个动作的 `unshown` 上（和 `NAME=value` 赋值、here-document 同一个字段），`pipeline.unshown_input` 照旧据此不送审。`pipeline` 没有改。

（测试与测量见第 5、6 节。）

## 8. 代价和残余

1. **有后端时，带超长字符串的 PowerShell 命令直接问**，不再送审。32768 个字符以内、又超过 400 个字符的，本来就被发送闸门拒绝。
2. **`sudo --preserve-env=LIST …`、`xargs --replace=R …` 直接问**（后者本来就由规则问）。
3. 外部程序收不到超长参数，`python -c`、`cmd /c` 那几种写法实际上跑不起来；修了也只是多问，没有坏处。
4. PowerShell 7 上没有量。这次修复没有复审，真实宿主里没有跑。
