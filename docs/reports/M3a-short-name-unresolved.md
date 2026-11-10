# 带路径而展开不了的短名不送审（规格修订 19，复审 R18-4）

日期：2026-11-10。基线：`e208c74`。依据：复审 `docs/reviews/M3a-rev18-review.md` 的 R18-4。

使用者说"修 R18-4"。在覆盖范围的问题上，选了"凡是展开不了都标"。

代码在 `30813d0`，文档在其后一个提交（`f34eb5c`），两个都已推送到 `origin/main`。没有打标签。

没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次和攻击样本。实测用的"程序"是改了名字的 `whoami.exe` 副本，放在 TEMP 的长名目录里，用完已删。

## 1. 结论

**改了什么**：在 Windows 上，程序带路径、最后一段是字面上的 8.3 短名，而磁盘层展开不出唯一的长名时，现在是灰色 `program-short-name-unresolved`，不送审，总是问。这和修订 18 对裸短名的处理一样。原来这样的写法得到的是 `program-path-qualified` 或 `cwd-unknown` 一类的灰色，有后端时送审。模型看到的是一个说明不了自己是什么程序的名字。

**为什么改**：复审 R18-4 实测到下面两种写法都会运行，守卫却照常送审：
- Git Bash：`cd` 进路径里带短名的目录之后，运行 `./BOUNDK~1`；
- PowerShell：`Set-Location` 进这样的目录之后，运行 `.\BOUNDK~1.EXE`。

同样的命令放在长名目录里，原来就是 deny。

**规则条目和策略文件没有改，判决的级别一条都没有变**（第 5 节）。

## 2. 修改前后

真实目录树（假文件），没有后端，看的是规则判决和送不送审。`<短名目录>` 是 `…\LONGTO~1` 这样的路径，那里有一个假的 `boundkeep.exe`。

| 写法 | 修改前 | 修改后 |
|---|---|---|
| Bash：`cd '<短名目录>' && ./BOUNDK~1 mode audit-only` | 灰色（`cwd-unknown`），送审 | 灰色，**不送审** |
| PowerShell：`Set-Location '<短名目录>'; .\BOUNDK~1.EXE mode audit-only` | 灰色（`cwd-unknown`），送审 | 灰色，**不送审** |
| Bash：`"$TOOLS/BOUNDK~1" mode audit-only`；PowerShell：`& "$tools\BOUNDK~1.EXE" mode audit-only` | 灰色，送审 | 灰色，**不送审** |
| 文件不存在：`'…/NOSUCH~1.EXE' mode audit-only`（两种 shell） | 灰色，送审 | 灰色，**不送审**（代价） |
| PowerShell：`& '<短名目录>\BOUNDK~1' mode audit-only`（不带 `.EXE`，PowerShell 不运行它） | 灰色，送审 | 灰色，**不送审**（代价） |
| 长名目录里的 `./BOUNDK~1`（Bash）、`.\BOUNDK~1.EXE`（PowerShell） | deny | deny |
| 展开得出长名的 `'…/LONGTO~1/BOUNDK~1.EXE' mode audit-only` | deny（`program-short-name`） | deny |
| `./build.sh`、`./a~b`、`git status`、裸的 `boundkeep` | 不变 | 不变 |

## 3. 实测

实测都在 R18-4 的复审里，这里摘一下：

| shell | 写法 | 结果 |
|---|---|---|
| Git Bash | `cd` 进 `…/RV18R_~2/LONGTO~1` 后运行 `./LONGPR~1` | 运行，退出码 0 |
| Git Bash | 同上，运行 `./LONGPR~1.EXE` | 运行，退出码 0 |
| PowerShell 5.1 | `Set-Location` 进短名目录后运行 `.\LONGPR~1.EXE` | 运行 |
| PowerShell 5.1 | 经 PATH 运行 `LONGPR~1.EXE`、`longpr~1.exe`、`LONGPR~1` | `CommandNotFoundException` |

PowerShell 不运行不带 `.EXE` 的短名路径，这一条是修订 17 复审时量的。

## 4. 修法

- `event._short_named_path`：判断"程序带路径、最后一段是字面上的 8.3 短名"。成立的条件：
  - 平台是 Windows；
  - 程序名里有 `/` 或 `\`；
  - 最后一段不含 `$`、`` ` ``、`*`、`?`、`[`；
  - 去掉结尾的点和空格之后，最后一段符合 `paths.is_short_name`。

  PowerShell 读不出的命令名，`pscmd._dynamic_word` 会包成 `$(<原文>)`，这里先拆掉这层包装再判断。只在 PowerShell 里拆。
- `event._command_action`：`_short_name_program` 展开不出长名、而 `_short_named_path` 成立时，加上 `program-short-name-unresolved`。这个原因已经在 `pipeline._UNSHOWN_REASONS` 里（修订 18），所以带它的调用不送审。
- 文档：
  - 规格：修订 19 的段落，§5.1 程序名的 8.3 短名一条，§7"请求装不下的输入"；
  - `docs/policy-reference.md`：`program-short-name-unresolved` 一句；
  - `docs/threat-model.md`：第 4 节短名那一句。
- 测试：新文件 `tests/unit/test_m3a_short_name_unresolved.py`，29 条。它们是：
  - R18-4 的两种 shell；
  - 长名目录对照；
  - 目录写成变量或通配符、文件不存在；
  - 能展开的短名对照；
  - 不算短名的写法；
  - PowerShell 拆包装、只在 Windows 上。

## 5. 度量

| 差分 | 结果 |
|---|---|
| 专门扫描：20 种程序写法 × 4 种工作目录（不 `cd`、长名目录、短名目录、项目里的短名子目录）× 2 种 shell，共 160 行，新旧代码各跑一次 | **级别全部相同**。49 行多了 `program-short-name-unresolved`，并且改为不送审，都是最后一段像短名、展开不出长名的写法；其余 111 行完全相同 |
| 修订 18 的扫描（5100 条） | 全部相同 |
| 修订 17 的真实目录树扫描（10092 条） | 全部相同。`--` 前后对照的计数（404 条更松，542 条更严）和修订 18 时一样 |
| 修订 16 的扫描（12768 条） | 全部相同 |
| IR-1 的扫描（10320 条） | 全部相同；Bash 和 PowerShell 的 5160 对判决仍然全部相同 |
| 带冒号的普通命令（492 条）、系统目录、逐程序 | 全部相同 |
| 真实磁盘（23544 条）、假机器（179508 条）、孪生项目（30720 条） | 级别全部相同 |
| 含 git 或 `~` 的语料（655 条，1164 次判决） | 0 条不同 |
| `boundkeep test` default / strict | 1142 / 0 失败，334 / 0 失败 |
| 评测（`--config rules+taint --test-contaminated`，输出到 scratchpad） | `results/*.json` 去掉时间戳之后相同；`report.md` 只有日期一行和 4 行延迟不同（跑评测时变异测试和别的测试在同时跑） |

上面"修订 N 的扫描"那几行，基线是修订 18 代码的输出。专门扫描的旧代码是 `e208c74` 的 `src`，导出到 scratchpad，经 `RR_SRC` 加载。

| 测试和检查 | 结果 |
|---|---|
| 新测试文件 | 29 passed |
| 新测试文件在 `e208c74` 的代码上 | 8 条行为测试失败；16 条直接测新函数的测试失败，因为函数还不存在；5 条对照通过 |
| 受影响的 18 个测试文件 | 6085 passed，7 skipped（改最后一条测试输入之前跑的） |
| 读 `docs/policy-reference.md` 的 6 个测试文件，加上新文件 | 7596 passed，62 skipped |
| 变异：9 个，在副本上跑新测试文件、修订 18 的测试文件和 `test_m3a_git_operands_and_short_names.py` | **全部抓到**。第一轮"不去掉结尾的点和空格"那一个存活：测试用的 `./BOUNDK~1. ` 不去掉也像短名。改成 `./BOUNDK~1.EXE. ` 之后抓到 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过 |
| 全量（分六段跑，不是一个进程；测试文件清单 124 个，与 `tests/` 相同） | 28654 passed，169 skipped，**1 failed**，合计与收集到的 28824 条相同。用时 4:39:20，其中第 5 段 3:06:43；05:40 左右电源从"最佳能效"换成了"最佳性能"，各段用时和上次不能直接比。跑的期间 `src`、`tests`、`policies`、`eval`、`scripts` 和两份被测试读的文档都没有改。失败的是 `test_norm_psprograms.py::test_a_dynamic_word_in_path_position_is_never_dropped`：hypothesis 这次随机生成到 `Remove-Item /dev/zero`，路径被丢掉了。单跑仍然失败，在 `e208c74` 的代码上同样失败，和这次修改无关，没有修（第 7 节） |

## 6. 代价和残余

1. **路径写错、文件不存在的短名程序也直接问，不再送审**。PowerShell 里不带 `.EXE` 的短名路径也一样，虽然 PowerShell 不运行它。这是使用者选的范围。
2. **只看最后一段**：
   - 最后一段带变量或通配符时（`./$NAME~1`）不算，照旧是动态程序名的灰色，送审；
   - 目录里的短名（`C:\PROGRA~1\…\git.exe`）不展开，和修订 17 一样。
3. **拆 `$(…)` 依赖 `pscmd._dynamic_word` 的写法**：那里改了，这里要跟着改。`test_powershell_dynamic_command_names_are_unwrapped` 和变异 `rv19:no-unwrap` 会发现。
4. **裸短名仍只在 Git Bash 里处理**：PowerShell 5.1 不运行裸短名，带不带 `.EXE` 都不运行（实测）。别的 shell 没有量。

## 7. 没有做的

- 这次修复没有复审，真实宿主里没有跑。
- R18-1 到 R18-3 按使用者的决定记为 IR-7 的同类，不修（`docs/threat-model.md` 第 4 节）。
- 全量里那条失败查到的问题，早于这次修改，没有修：
  - `programs.py` 把 `/dev/null`、`/dev/stdin`、`/dev/stdout`、`/dev/stderr`、`/dev/tty`、`/dev/zero` 当作无害设备，不记路径。这是 Bash 的读法，PowerShell 一侧也照用了。
  - PowerShell 5.1 把它们解析成当前盘根下的普通路径：`/dev/zero` 是 `E:\dev\zero`（实测路径解析，没有动文件）。
  - 结果（PowerShell，没有后端）：`Remove-Item -Recurse /dev/null` 是灰色、送审，而 `/dev/nullx` 是 deny（`rm-outside-project`）；`Remove-Item /dev/zero` 是灰色，而 `/dev/zerox` 是 ask（`ask-delete-outside-project`）。
  - 只牵涉这六个名字。规格里没有写到这一点，要修就先改规格，等使用者决定。（规格修订 20 已修，记录 `docs/reports/M3a-ps-dev-paths.md`。）
  - 失败的用例已经存进 `.hypothesis/`（不进 git），修好之前，这条测试在本机每次都会失败。
