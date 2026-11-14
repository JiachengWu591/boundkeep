# 修订 27 和 28 复审的四条修复（规格修订 29）

日期：2026-11-13。基线：`4b76463`（代码同 `86a7e2f`）。依据：`docs/reviews/M3a-rev27-28-review.md` 的 O-6、R28-1、R28-2、R28-3。

使用者看过复审结论之后说"按建议顺序修"：先修 O-6，再一次修 R28-1 到 R28-3。

使用者说"分两次提交"：代码在 `fed8930`，这份记录、复审报告和规格在其后一个提交。没有推送，没有打标签。

没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务（模型是 `FakeBackend`），没有打开留出批次和攻击样本。实测只用编出来的字符串和 TEMP 下的临时文件，用完已删；没有运行 `sudo`。

## 1. 结论

- O-6 已修：Bash 解析器中途停下（结构嵌套超过 32 层、词数或记号数超过上限、只读了前 1 MiB、`bash -c` / `eval` 递归超过 8 层）的一行算没看全，不送审、直接问。复审的 `pytest -q; { { …（40 层）cat .env; }; … }` 现在不送审。
- R28-1 已修：类的属性初值按绑定处理（`ps-bound-value:property`）。`enum` 的成员值是整数，不算。
- R28-2 已修：函数之外 `throw` 后面的值按绑定处理（`ps-bound-value:throw`）。复审建议只在一行里有 `catch` / `trap` 时才算，修的时候实测不够（第 4 节）：`finally` 里、`ErrorActionPreference` 设成 `SilentlyContinue` 之后的代码都能从 `$Error` 拿到它。所以改成一律算。
- R28-3 已修：命令参数之外的 `-match`、`-notmatch`（含 `i`、`c` 变体）的左边按绑定处理（`ps-bound-value:match`）。
- 三种绑定都和修订 28 一样：值已经知道的只记 `unshown`，不是已知的记成 `Write-Output <值>`，请求里有它。
- 规则条目与策略文件没变。没有后端时判决级别不变。

## 2. O-6：Bash 解析器中途停下

**原来**：`bash.parse_bash` 碰到上限时抛出 `_Abort`，剩下的文字不再解析，已经找到的命令照常返回，这一行另加一条灰色原因（`nesting-too-deep`、`too-many-words`、`too-many-tokens`、`too-long`；`bash -c` 递归超过 8 层是 `depth-exceeded`，不抛出，但里面的不再解析）。这几个原因都不在 `pipeline._UNANALYSED_PREFIXES` 里，整条照常送审，请求里只有停下之前的命令。停下之后的命令规则也看不到。

**现在**（`pipeline._UNANALYSED_PREFIXES`）：加上这五个原因。`incomplete_analysis` 遇到它们就返回，这一行不送审、直接问（`decided_by: gray-unanalysed`）。解析器没有改。

这五个原因的字面别处没有用到（查过 `src/`：`glob-too-many-matches`、`brace-expansion-too-large`、`path-too-deep`、`ps-input-too-large` 都不以它们开头），所以不会误伤别的灰色调用。

停下之后要不要像预算用完时那样做词法兜底、继续找看得出的 deny，没有做：没有后端时这一行仍然是灰色，问，和原来一样。

## 3. R28-1：类的属性初值

**原来**：辅助进程只给值有去处的表达式和参数默认值报条目。类的属性初值（`PropertyMemberAst.InitialValue`）两样都不是，整个类定义只进 `compound`（`ps-compound:TypeDefinitionAst`），这个原因不拦送审。`class C { static [string]$p = '<代码>' }; Invoke-Expression ([C]::p)` 送审，请求里只有 `Invoke-Expression $(([C]::p))`。

**现在**（`pshelper.ps1`）：
- 选节点的谓词多认 `PropertyMemberAst`：有初值、并且不在 `enum` 里。
- 这样的属性和参数默认值一样，报成一条名字种类 `output` 的条目，`"bind":"property"`（新函数 `Add-Bound`，原来的 `Add-Default` 并进了它）。初值只包着命令（`(Get-Location)`）的不报，命令本身已经报了；写在命令参数里的脚本块里的不报，文字在请求里。
- `pscmd` 没有改：它本来就按 `bind` 处理，值已经知道的记 `ps-bound-value:property`，不是已知的记成 `Write-Output <初值>`。
- 属性本身不进 `compound`、`dynamic`、`loose`，所以原有的灰色原因不变。

## 4. R28-2：`throw` 后面的值

**原来**：修订 22 把 `throw` 后面算作值有去处，修订 28 又把函数之外的 `throw` 算作打印的位置，已知值不记。但 `throw` 的值进 `$Error`，被 `catch` 或 `trap` 接住时还在 `$_` 里。

**第一版**照复审的建议：一行里有带 `catch` 子句的 `try` 或任何 `trap` 时，`throw` 后面才算绑定，理由是没有它们时 `throw` 结束整个脚本、后面的代码拿不到这个值。变异测试里"只有 `finally` 的 `try` 也算"这一个存活了，于是实测（PowerShell 5.1，和工具一样把脚本交给 `Invoke-Expression`，只用字符串）：

| 写法 | 结果 |
|---|---|
| `try { throw 'v' } finally { 'in finally: ' + $Error[0].Exception.Message }` | 打印 `in finally: v` |
| `Set-Variable ErrorActionPreference SilentlyContinue; throw 'v'; 'after: ' + $Error[0].Exception.Message` | `throw` 不结束脚本，打印 `after: v` |
| `$ErrorActionPreference = 'SilentlyContinue'; throw 'v'; …` | 同上（赋值本来就不送审） |
| `throw 'v'; …`、`if ($true) { throw 'v' }; …`、`1 \| ForEach-Object { throw 'v' }; …`、`foreach ($i in 1) { throw 'v' }; …` | 脚本结束，后面不运行 |

所以"没有 `catch` / `trap` 就拿不到"不成立：`finally` 和 `ErrorActionPreference` 都能让后面的代码从 `$Error` 读出它，而 `Set-Variable` 的写法是送审的。按名字去认 `ErrorActionPreference`（含通配符、`Set-Item Variable:\…`）又是修订 23 那种容易漏的检查。

**现在**（`pshelper.ps1`）：`Get-Binding` 遇到 `throw` 后面的值、又不在函数体里时，一律返回 `throw`。值已经知道的记 `ps-bound-value:throw`，不是已知的照旧记成 `Write-Output`。`return` 照旧算打印：它之后这一行什么都不运行，也没有变量存着它的值。

代价：有后端时 `pytest; if (-not $?) { throw 'failed' }`、`npm test; if ($LASTEXITCODE) { throw "tests failed" }` 这类常见写法直接问，不再送审。没有后端时这些行本来就是灰色（`ps-compound:ThrowStatementAst`），不变。

## 5. R28-3：条件里的 `-match`

**原来**：`if`、`while` 等的条件不在请求里（修订 22 记为"没有做"）；比较运算又在修订 21 的无害清单上，不进 `loose`。`-match` 把匹配到的部分放进 `$Matches`，`if ('<代码>' -match '.*') { Invoke-Expression $Matches[0] }` 送审，请求里只有 `Invoke-Expression $($Matches[0])`。

**现在**（`pshelper.ps1`）：
- 新表 `$script:MatchOperator`：`Imatch`、`Cmatch`、`Inotmatch`、`Cnotmatch`（`-match` 的记号就是 `Imatch`）。
- 扫描到这四种运算、又不在任何命令参数里（`Test-Loose`）、左边不是只包着命令的括号时，把左边报成一条 `"bind":"match"` 的条目。
- 左边是已知值时记 `ps-bound-value:match`；不是已知值时记成 `Write-Output <左边>`，请求里多了它（`if ($env:X -match '.*') { … }` 现在请求里有 `$env:X`）。
- 写在命令参数里的（`Where-Object { $_ -match 'x' }`、`ForEach-Object { if ($_ -match 'x') { … } }`）不报：整个脚本块的文字在请求里。
- 单独成句的 `'<代码>' -match '.*'` 原来是 `Write-Output`，请求里有它；现在左边已知，多记一项 `ps-bound-value:match`，不送审，偏严。

## 6. 判决变化

专门扫描（scratchpad 的 `rv29_scan.py`，对 `4b76463` 的代码），512 行：
- Bash：4 种前缀（`pytest -q; `、`git status; `、`cat README.md; `、什么都没有）× 13 种停下的方式 × 3 种藏在后面的命令（`cat .env`、`cat <标记>`、`rm -rf build`）。13 种是：`{ }`、`( )` 嵌套 30、31、32、33、40 层，20001 个 `case` 模式，40 万个换行，1 MiB 空格，9 层和 7 层 `bash -c`。
- PowerShell：8 种值（常量字符串、`~\.ssh\…` 路径、`'README.md'`、数字、`$true`、环境变量、带变量的字符串、只包着命令的括号）× 4 种用法（`Get-Content`、`Invoke-Expression`、`Write-Output`、不用）× 10 个位置（静态属性、实例属性、`catch`、`trap`、没被接住的 `throw`、`if` 里的 `-match`、`while` 里的 `-match`、单独成句的 `-match`；对照：命令参数里的 `-match`、`if` 里的 `-like`），另加 12 行对照（`enum`、没有初值的属性、类的方法）。

| | 行数 |
|---|---|
| Bash 解析器中途停下，送审 → 不送审：嵌套 33、40 层 36 行（`nesting-too-deep`），词数 9 行，记号数 12 行，1 MiB 12 行 | 69 |
| Bash 原来就不送审，现在理由换成停下的原因（9 层 `bash -c` 原来被发送闸门拒绝；停下之前什么都没有的原来是"什么都没看懂"） | 27 |
| PowerShell 已知值，送审 → 不送审（`ps-bound-value`）：静态属性、实例属性、`catch`、`trap`、没被接住的 `throw`、`if` 和 `while` 里的 `-match`、单独成句的 `-match`，各 20 行 | 160 |
| PowerShell 值不是已知的（环境变量、带变量的字符串），照常送审，请求里现在有它（`Write-Output`）：属性和 `-match` 的位置 | 32 |
| 单独成句的 `$env:X -match …`：多了一条 `Write-Output $env:X`，别的不变 | 8 |
| 其余 | 216，判决、送审、请求一项都没变 |

- 没有一行变松，没有一行少记路径。嵌套 30 到 32 层的照常解析完，`cat .env` 照旧是 deny。
- 新代码上"送审、请求里没有标记"的从 116 行降到 16 行，剩下的都是 `if` 里的 `-like`：它不填 `$Matches`，条件的文字本来就不在请求里（修订 22 列为没有做），按设计不算。

手头语料：PowerShell 1146 条、Bash 1880 条 × posix 和 windows 两个平台（`tests/corpus` 和评测集，不含留出集）：级别变了的 0 条。

## 7. 测试

| 测试和检查 | 结果 |
|---|---|
| 新测试文件 `tests/unit/test_m3a_rev27_28_review_fixes.py` | 126 passed |
| 它在 `4b76463` 的代码上（第一版，122 条） | 66 条失败，56 条通过（通过的是对照：命令参数里的 `-match`、`enum`、`-like`、规则先判、构造器对已知位置的处理、嵌套 30 层照常 deny 等） |
| 夹具 | `tests/fixtures/ps_ast` 235 个里 1 个（`throw 'x'`）用真的辅助进程重新生成，唯一的差别是多了 `"bind": "throw"`；`ps_ast_manual` 58 个不变。之后 `scripts/gen_ps_fixtures.py --check` 0 个不同 |
| 相邻 16 个测试文件 | 1 条失败、3295 passed、39 skipped。失败的是比对夹具和辅助进程的测试，就是上面那个夹具；重新生成之后 `test_norm_psparse.py`、`test_norm_pscmd.py` 938 passed |
| 变异，第一轮 21 个（`pipeline` 5 个，辅助进程 16 个），在副本上跑新测试文件和修订 28 的测试 | 19 个抓到，2 个存活。一个是"只有 `finally` 的 `try` 也算接住"，追下去发现 `throw` 的条件本身不对（第 4 节），改成一律算；另一个是"左边只包着命令时也报"，补了测试 |
| 变异，第二轮 18 个（`pipeline` 5 个，辅助进程 13 个） | 18 个全部抓到 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过 |
| 原有差分（修订 16 到 20 的扫描、修订 17 和 IR-1 的真实目录树、带冒号的普通命令、系统目录、逐程序、真实磁盘 23544 条、假机器 179508 条、孪生项目 30720 条、含 git 或 `~` 的语料 1164 次判决），对修订 27、28 的输出 | 全部相同，没有一行少记路径。中途按使用者的话停过一次：前 12 组跑完后停下，继续时补跑了含 git 的语料、`boundkeep test` 和评测。`boundkeep test` 1142 / 0、334 / 0。评测指标相同，`results/*.json` 除日期和延迟外只有 `atk-exfil-032` 的灰色原因不同（修订 22 起就是这样），`eval/report.md` 没有重新生成 |
| 全量 | 分六段跑，不是一个进程：29990 passed、169 skipped、**2 failed**，六段都一次跑完，合计与收集到的 30161 条相同，各段用时合计 3:45:55。开始时电源是最佳能效，09:56 左右（第 3 段中）使用者换成最佳性能。跑完后 `git diff HEAD -- src tests policies eval scripts docs/policy-reference.md docs/powershell-dialect.md` 的哈希和新测试文件的哈希与开始时相同。失败的两条都在第 1 段，都是这次没改的模块里的计时测试：`test_daemon.py::test_concurrent_requests_are_all_answered_and_logged`（200 个并发请求没有全部答成 `none`）和 `test_install.py::test_hang_times_out_without_raising_and_in_bounded_time`（超时 1 秒的钩子，用时不在 1 到 10 秒之间）；那一段结束时可用内存只剩 558 MB、可用提交 1161 MB。全量结束后单独重跑，这次的代码和 `4b76463` 的代码各 5 次都通过。后三段在最佳性能下仍比修订 27、28 那次慢约一半（含语料的第 5 段 1:54:02，那次 1:16:01）；同一时刻在两份代码上交替各跑两次语料里同样的 404 条，这次的代码 208、194 秒，`4b76463` 211、199 秒，慢的不是这次的改动 |

## 8. 代价和残余

1. **有后端时，这些灰色调用直接问，不再送审**：嵌套超过 32 层的 Bash 命令；带常量属性初值的类；`throw` 一个常量，包括 `pytest; if (-not $?) { throw 'failed' }` 这类常见写法；命令参数之外拿常量做 `-match`，包括单独成句的 `'x' -match 'y'`（原来请求里有它，现在偏严）。
2. 值不是已知的属性初值和 `-match` 左边，现在多一条 `Write-Output`，占发送闸门 8 条命令的上限。
3. Bash 解析器停下之后的命令规则仍然看不到，没有后端时是问，不是 deny（和原来一样）。
4. 条件的文字仍然不在请求里：`if ($env:A -like '*')` 这类不绑定变量的条件没有改。
5. 这次只补了复审列出的三种绑定位置，加上修的时候查到的 `finally` 和 `ErrorActionPreference`。PowerShell 里给变量放值的地方是否还有别的，没有系统地再列一遍。
6. PowerShell 7 上没有量。这次修复没有复审，真实宿主里没有跑。
