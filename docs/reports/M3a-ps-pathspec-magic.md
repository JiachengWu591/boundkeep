# PowerShell 里的 git pathspec 魔法（独立复审 IR-1）

日期：2026-11-06。基线：`d44ae65`（`src` 与 `c69684c` 相同）。代码提交：`2778e56`（未推送，未打标签）。依据：独立复审 `docs/reviews/M3a-rev13-16-independent-review.md` 的 IR-1。使用者说"提交并修 IR-1"。

没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次和攻击样本。扫描用的目录树放在 scratchpad 里，文件内容是编的；命令只解析、不运行。

## 1. 结论

**IR-1 已修。** 场景是 PowerShell 里，会话工作目录在项目的子目录。这时 `git add :/`、`git add ':!x'`、`git add ':(top)'` 这些作用于整个仓库的写法，又会扫描项目根目录：项目里有没被忽略的受保护名字时就问（`git-add-may-stage-protected`），和 Bash 相同。

规格没有改。§5.1 本来就要求这样（修订 16 那段写了"`git add` 另有整个仓库的检查"），是 PowerShell 一侧的实现没跟上。规则条目和策略文件也没有改。

## 2. 原因

修订 13 改了 `programs._pathspec`，把魔法换成它代表的路径。所以 `event._stages_whole_repository` 不能再靠"以 `:` 开头"认出整个仓库的写法，改成看 `CmdInfo.pathspec_magic`。

PowerShell 里不是 cmdlet 的外部程序走 `psprograms._external`。它先用 Bash 的表算出 `CmdInfo`，再把字段一个个抄进自己的累加器，最后由 `_finish` 重新构造 `CmdInfo`。抄的时候漏了 `pathspec_magic`，所以在 PowerShell 里这个字段永远是 False，项目根不再被扫描。

回归测试（X1 复审的 R5-1）只测了 Bash，所以没抓到。

## 3. 修法

- **`src/boundkeep/normalize/psprograms.py`**：`_external` 抄 `pathspec_magic`，`_finish` 把它传出去。
- **`tests/unit/test_git_local_vcs_allow.py`**：两条测试改成 Bash 和 PowerShell 都测，PowerShell 只在 Windows 上跑：
  - R5-1 那条，17 种写法；
  - "子目录里的 `git add .` 只看那个目录"那条。
- **`tests/unit/test_m3a_ps_cmdinfo.py`**（新，26 条）：
  - 21 条外部命令，把 PowerShell 和 Bash 算出的 `CmdInfo` 逐字段比较。比较时遍历 `dataclasses.fields`，所以以后新加的字段也会比到。灰色原因和风险标签，PowerShell 可以比 Bash 多，不能少。
  - 另外几条直接检查 `classify_ps` 给出的 `pathspec_magic`。
- **没有采用复审建议的另一种写法**（改用 `dataclasses.replace`）：`_external` 还要合并 PowerShell 自己的灰色原因、风险标签和重定向。以后再漏抄字段，逐字段的测试就能抓到。

## 4. 度量

**真实目录树扫描**（新做的）。只看规则判决，没有后端。旧代码是 `c69684c`。共 10320 条，组合方式：

- 4 种目录树：项目根有 `.env`、`src` 里有 `.env`、项目根有 `secrets/id_rsa`、没有受保护的名字；
- 14 种子命令 × 18 种写法，另加 6 条不带 pathspec 的对照；
- Bash、PowerShell 两种 shell；
- 工作目录在项目根、`src`、`sub`，另有两种在项目根用同一行 `cd` / `Set-Location` 进子目录的写法。

| 结果 | 条数 |
|---|---|
| 相同 | 10062 |
| 收紧：PowerShell 由规则放行变成灰色（`git-add-may-stage-protected`） | 243 |
| 同级：PowerShell 本来就是灰色（`git-pathspec-magic`），多了 `git-add-may-stage-protected` | 15 |
| **变松** | **0** |

收紧的 243 条分布：

- **子命令**：全是 `git add`，其中 162 条带 `--`。
- **目录树**：都在有受保护名字的树里：项目根 `.env` 99 条、`secrets/id_rsa` 99 条、`src/.env` 45 条。没有受保护名字的树一条都没变。
- **工作目录**：项目根 54 条、`src` 81 条、`sub` 108 条；其中在项目根用同一行 `Set-Location` 进子目录的 36 条。
- **写法**：`:(top)src`、`:/src`、`:(literal)src` 各 36 条；`:/`、`:!x`、`:^x`、`:(top)`、`:(exclude)x`、`:(exclude,top)x`、`:!/x`、`::`、`:/:` 各 15 条。

**修好之后 Bash 和 PowerShell 的比较**：5160 对，判决全部相同。修之前，这 243 条两边不一样。

**没有重跑的差分**：系统目录、逐程序、真实磁盘、假机器、孪生项目、带冒号的普通命令。理由是 `pathspec_magic` 在整个代码里只有一处读取：`event._stages_whole_repository`，也就是 `git add` 的整个仓库检查，而它只在真实磁盘上起作用。上面的目录树扫描已经覆盖了它。

**其他：**

| 项目 | 结果 |
|---|---|
| 新测试和改过的测试 | 62 passed（新文件 26 条，`test_git_local_vcs_allow.py` 里改过的两条测试共 36 条） |
| 变异：5 个（不抄、抄成 False、抄成 True、`_finish` 不传、`_finish` 传 True），在副本上跑 | **全部抓到**。两个测试文件分开跑，也各自抓到全部 5 个：新文件靠逐字段比较，`test_git_local_vcs_allow.py` 靠真实目录树上的判决 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过；77 个源文件没有问题 |
| `boundkeep test` default / strict | 1142 / 0 失败，334 / 0 失败 |
| 评测（`--config rules+taint --test-contaminated`，输出到 scratchpad，没有打开留出批次） | `results/*.json` 去掉时间戳之后相同；`report.md` 只有日期一行和 4 行延迟不同 |
| 全量（分六段跑，不是一个进程） | **28446 通过、169 跳过、1 失败**。07:21:36 到 09:44:22，共 2:22:46；六段都一次跑完，合计与收集到的 28616 条相同，测试文件清单 121 个，与 `tests/` 相同；开始之后 `src`、`tests`、`policies`、`eval`、`scripts` 和测试要读的两份文档都没有改过。失败的是 `test_redact.py::test_linear_time_on_hostile_input[assignment-doubled-quotes]`：2 MB 的构造输入用了 2.21 秒，预算是 2 秒。它和这次修改无关（`redact` 没有改），单跑 5 次都过（1.00 到 1.24 秒）。第 6 段结束时可用的提交内存只剩 644 MB，这一段用了 22 分钟，平时约 11 分钟。这个测试没有改 |

**顺带修的**：`ruff format --check .` 在 `d44ae65` 上不通过，原因是独立复审报告里有一段 Python 示例代码不合格式。已用 `ruff format` 格式化，只改排版。

## 5. 代价和残余

1. **只暂存一个目录的魔法写法也要问**：PowerShell 里 `git add ':/src'`、`git add ':(top)src'`，项目里任何地方有没被忽略的受保护名字时要问。这和 Bash 一样：任何以 `:` 开头的 pathspec 都按整个仓库看（X1 复审 R5-1、R6-1 的做法），偏保守。
2. **复审的 IR-2 到 IR-8 没有处理。** 有几处文字在 PowerShell 的子目录里曾经不成立，修好之后又成立了，原文没有改：
   - 修订 13 记录第 4a 节"判决回到原样"；
   - 修订 16 记录第 6 节第 1 条；
   - 规格 §5.1 修订 16 那段"`git add` 另有整个仓库的检查"。
3. **真实宿主里没有跑子目录里的这类调用**：冒烟的工作目录在项目根。

## 6. 没有做的

- 这次修复没有复审。
- 没有推送：`2a460da`、`d44ae65`、`2778e56` 和它之后的文档提交都只在本地。
