# 修订 21、22 复审的两条修复（规格修订 24）

日期：2026-11-12。基线：`295badc`，工作区里还有没提交的修订 23。依据：`docs/reviews/M3a-rev21-22-review.md` 的 R21-1、R22-1。

使用者看过复审结论之后说"先修这两条"。O-2（运行器自己的选项不在请求里）要先定设计，这次没有动。

使用者说"代码一次、文档一次"：代码（修订 23 到 26 一起）在 `8d268d3`，这份记录和规格在其后一个提交（`ced7a87`）。**已推送**（2026-11-12，使用者说"推送"），没有打标签。复审见 `docs/reviews/M3a-rev23-26-review.md`。（2026-11-12 更正：这里原来写的是提交时的状态"没有推送"。）

没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务（模型是 `FakeBackend`），没有打开留出批次和攻击样本。

## 1. 结论

- R21-1 已修：灰色原因记满 64 条之后又来新的，这一行加上 `ps-too-large`，不送审、直接问。复审的 4 种写法（前面垫 90 个原因）现在都不送审。
- R22-1 已修：参数的默认值按 `Write-Output <默认值>` 记成一条命令。`param($x = $env:SECRET_TOKEN) Get-Date; $x` 送审的请求里现在有 `$env:SECRET_TOKEN`。
- 规则条目与策略文件没变，Bash 没变。手头语料 1146 条 PowerShell 命令的级别没有一条变化（对 `295badc`，含修订 23）。

## 2. R21-1：记不下的原因

**原来**：`pscmd._State.add_gray` 记满 `MAX_REASONS`（64）条之后，新的原因直接丢掉。`ps-switch-value`、`ps-runner-value`、`ps-pipe-to-interpreter` 是逐条处理命令时才加的，前面先凑够 64 条（每个 cmdlet 不认识的参数一条 `ps-param-unresolved:…`），它们就没有了，`pipeline.unshown_input` 找不到，整行照常送审。

**现在**：
- 记满之后又来了一条**没记过的**原因，`_State.overflow` 置位。已经记过的原因再来一次不算。
- `build` 返回时，置位而且原因里还没有 `ps-too-large` 的，把 `ps-too-large` 放在第一条。
- `ps-too-large` 本来就在 `pipeline._UNANALYSED_PREFIXES` 里：这一行算没看全，不送审。`pipeline` 没有改。
- 上限本身没有改，还是 64 条；加上标记最多 65 条。

| 写法（`<垫>` 是三条 `Get-Date -a00 … -a29`，共 90 个原因） | 修改前 | 修改后 |
|---|---|---|
| `<垫>; Get-ChildItem -Force:([IO.File]::ReadAllText('C:\x\BKCANARY'))` | 送审，请求里没有标记 | 不送审 |
| `<垫>; Get-ChildItem -Recurse:$env:BKCANARY` | 送审，没有标记 | 不送审 |
| `<垫>; uv run --with $env:BKCANARY pytest` | 送审，没有标记 | 不送审 |
| `<垫>; 'Get-Content BKCANARY' \| powershell -Command -` | 送审，没有标记 | 不送审 |
| `<垫>` 单独一行 | 送审 | 不送审 |
| 两条 `Get-Date -a00 … -a29`（60 个原因） | 送审 | 送审，不变 |

没有后端时这些行本来就是问，不变。

## 3. R22-1：参数的默认值

**原来**：参数的默认值不在任何命令里。是会动手的表达式时有 `ps-outside-command`（修订 21），是变量、字符串时什么都不记。`param($x = $env:SECRET_TOKEN) Get-Date; $x` 实测打印出值；送审的请求里是 `Get-Date` 和 `Write-Output $x`。

**现在**（`pshelper.ps1`）：
- 带默认值的 `ParameterAst` 也被访问。默认值不在命令参数里（`Test-Loose`）、也没有被别的命令带着（`Test-Carried`）时，报成一条名字种类是 `output` 的命令，默认值是它唯一的参数，`stage` 是 `{"index":0,"of":1}`，`nested` 是 `true`。`pscmd` 不用改，照修订 22 读成 `Write-Output <默认值>`。
- `Test-Carried` 是从 `Test-Output` 里拆出来的两条：带盘符的变量本身（已经是一条 `Get-Content`），只包着命令的括号（里面的命令各自照常记）。行为没有变。
- 值已经知道的（`param($n = 5)`、`param($f = $false)`、安静的一行里的 `param($code = $LASTEXITCODE)`）照修订 22、23 不建命令。
- 写在命令参数里的脚本块的参数（`ForEach-Object { param($x = $env:A) $x }`）不另外记，文字已经在那条命令的参数里。
- 带类型的参数照旧另有 `ps-outside-command:ParameterAst`，不送审。

专门扫描（scratchpad 的 `rv24_scan.py`）：20 种默认值 × 12 种写法，240 行，对 `295badc` 的代码。

| | 行数 |
|---|---|
| 级别相同 | 222 |
| 变紧：allow → 灰色送审 | 18 |
| 变松 | 0 |

- 变紧的 18 行：默认值是变量、带变量的字符串、括号或哈希表里的变量（6 种；`$(…)`、`@(…)`、比较运算这 3 种原来就是灰色），参数写在脚本开头，旁边是放行的命令（`param($x = $env:…) Get-Date`、`… git status`、`param($a, $x = …) Get-Date`）。
- 带变量的默认值：修改前送审的 72 行里 45 行的请求没有标记，18 行由规则放行；修改后送审 90 行，请求里都有标记。另外 18 行是带类型的参数，前后都不送审。
- 对照（没有参数的 `Get-Date; <值>`、赋值）一行没有变。没有一行少记路径。

## 4. 测试

| 测试和检查 | 结果 |
|---|---|
| 新测试文件 `tests/unit/test_m3a_rev21_22_review_fixes.py` | 55 passed |
| 新测试文件在 `295badc` 的代码上 | 32 条失败，23 条通过（通过的是对照） |
| 相邻 7 个测试文件（新文件、修订 23 和 22 的测试、`test_m3a_ps_outside_command.py`、`test_norm_pscmd.py`、`test_norm_psparse.py`、`test_m1c2_ps_pipehead.py`） | 1904 passed，1 skipped（加最后一条测试之前跑的） |
| `scripts/gen_ps_fixtures.py --check` | 235 个夹具，0 个不同（夹具里没有命令参数之外的参数默认值） |
| 复审的探针（`rvr23_p3.json`、`rvr23_p6.json`）在新代码上 | R21-1 的 4 种写法都不送审；R22-1 的两种写法送审，请求里有标记 |
| 手头语料 1146 条 | 级别变了的 0 条 |
| 变异：18 个（辅助进程 11 个，`pscmd` 7 个），在副本上跑新测试文件和修订 22、23 的测试、`test_norm_pscmd.py` | 18 个全部抓到 |
| 冒烟脚本的 `readings` 加了一条参数默认值的探针，`--only readings --dry`（不调用 Claude） | 23 项 0 失败 |
| 真实冒烟（2026-11-12，Claude Code 2.1.318，使用者在自己的终端里运行，`docs/hook-behavior.md`） | 23 项 0 失败，约 0.215 美元。R22-1 的那条探针送审了；R21-1 没有放进冒烟（命令太长） |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过 |
| 原有差分（修订 16 到 20 的扫描、修订 17 和 IR-1 的真实目录树、带冒号的普通命令、系统目录、逐程序、真实磁盘 23544 条、假机器 179508 条、孪生项目 30720 条、含 git 或 `~` 的语料 1164 次判决），修订 23 到 26 全部做完后 | 级别全部相同，没有一行少记路径。`boundkeep test` 1142 / 0、334 / 0。评测指标相同，`results/*.json` 除日期和延迟外只有 `atk-exfil-032` 的灰色原因多了几个（修订 22 起就是这样），`eval/report.md` 没有重新生成 |
| 全量（修订 23 到 26 一起跑，分六段，不是一个进程） | 29659 passed、169 skipped、0 失败，六段都一次跑完，合计与收集到的 29828 条相同，各段用时合计 2:21:22。开始和结束时电源都是最佳性能。跑完核对过代码与四个新测试文件的指纹，没有变 |

## 5. 代价和残余

1. **`param($x = $env:USERNAME) Get-Date` 由 allow 变成灰色**（问，或送审）。这一行什么都不打印，但守卫不跟踪 `$x` 后来用在哪里，只能在绑定的地方记。脚本开头带 `param` 的命令行在手头语料里没有。
2. **带 64 个以上不同灰色原因的一行不再送审**。正常命令到不了这个数。
3. **发送闸门一次最多 8 条命令**，每个带默认值的参数多占一条。
4. **O-2 没有修**：`uv run --env-file .env pytest`、`uv run --index-url https://… pytest` 的请求里仍然只有 `pytest -q`。要先定设计。
5. 修订 22 留下的不变：`if ($env:A)`、`exit $env:A`、`for` 的初始化和迭代位置的文字不在请求里（实测这些位置不打印）；`foreach ($u in '常量')` 绑的常量不在。
6. 只在 PowerShell 5.1 上量过。这次修复没有复审。
