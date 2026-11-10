# 修订 17 复审的修复，以及修时查到的两处（规格修订 18）

日期：2026-11-09。基线：`7b65ad8`。依据：复审 `docs/reviews/M3a-rev17-review.md`（不是独立的）的 R17-1 到 R17-6。

使用者说"开始执行修复"，并做了三个选择：
- R17-1 选"按树的读法收紧"；
- R17-2 选"补 .exe，裸短名不送审"；
- 修复时查到的子目录问题选"一起修"。

代码在 `2534c31`，文档在其后一个提交（`e72192b`），两个都已推送到 `origin/main`。没有打标签。

没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次和攻击样本。实测用的 git 仓库、"密钥"、程序都是假的，放在 scratchpad 和 TEMP 里，用完已删。真正运行过的只有 git、`tar`，以及一份改了名字的 `cmd.exe` 副本（用来证明短名会被运行）。

## 1. 结论

复审的四个低危缺口都修了，两条信息项的文字也改了。修的时候又查到两处更早就有的放行，复审没有发现，这次一起修了：

1. **`git show HEAD HEAD:src` 由规则放行**：实测打印 HEAD 的全部改动。
2. **工作目录在项目子目录时，`git log -p`、`git show HEAD`、`git stash show -p` 由规则放行**：实测 git 打印整个仓库，包括顶层的 `.env`。

**规则条目和策略文件没有改。** 专门扫描 5100 条，和修订 17 相比 644 条收紧、0 条变松（第 5 节）。

全量是 28619 通过、169 跳过、7 失败（第 5 节）：
- 5 条是一个测试替身少抄了新字段，已改；
- 2 条是计时测试和锁文件测试，旧代码上也会失败。

| 条目 | 修法 |
|---|---|
| R17-1 | `git diff` 里 `--` 之前不以 `:` 开头的 `REV:PATH`，单独出现或和别的修订号放在一起时，按递归读整个仓库。下面几种不变：正好两个 `REV:PATH`（只读这两个路径）、`--` 之后有 pathspec（读这些 pathspec 和 `REV:PATH` 的路径）、只列名字的选项 |
| `git show` 带提交（新） | `REV:PATH` 只在 `--` 之前每个操作数都是 `REV:PATH` 时才免于扫描 |
| R17-3 | `archive` 的 tree-ish 是 `:/text` 时，不再当作 `REV:PATH` 缩小范围 |
| R17-4 | `archive` 的选项表加上 `--mtime`、`--add-virtual-file`；遇到表里没有的长选项时，后面的操作数不再用来缩小范围 |
| 子目录（新） | `show`、`log -p`、`stash show -p`，以及 R17-1 的 `diff`，没有 pathspec 时另外递归读项目根。带 `top`（`/`）的 pathspec 另按项目根读；只有排除时也另读项目根，但 `grep`、`archive` 除外。只在工作目录位于项目根之下时加 |
| R17-2 | 只在 bash 方言里：带路径的短名按原样找不到时，补 `.exe` 再找；像短名的裸程序名标灰色 `program-short-name-unresolved`，不送审 |
| R17-5 | 规格 §5.1、`_colon_kind` 的文档字符串、修订 17 记录第 6 节第 2 条：`--` 之前的 `::x` 在 NTFS 上 git 从不接受 |
| R17-6 | 修订 17 记录第 6 节第 8 条：两种 shell 判决不同的范围补全 |

## 2. 修改前后

真实目录树（假文件），没有后端，看的是规则判决。"有"指项目里有 `.env`、`secrets/id_rsa`；"子目录"指 hook 收到的工作目录是项目里的 `sub`，那里没有受保护的名字。两种 shell 结果相同，除非另外注明。

| 写法 | 修改前 | 修改后 |
|---|---|---|
| `git diff HEAD:src`、`HEAD:secrets`、`HEAD HEAD:src`、`--cached HEAD:src`（有） | 规则放行 | **deny** |
| `git diff HEAD~1`、`git diff`、`git diff HEAD:src HEAD~1:src`、`git diff HEAD:a.py HEAD~1:a.py`、`git diff --stat HEAD:src`、`git diff HEAD:src -- a.py` | 规则放行 | 规则放行（不变） |
| `git diff HEAD:src`（无） | 规则放行 | 规则放行（不变） |
| `git show HEAD HEAD:src`、`git show HEAD:src HEAD`、`git show HEAD :src/a.py`（有） | 规则放行 | **deny** |
| `git show HEAD:src`、`git show HEAD:src/a.py HEAD:README.md` | 规则放行 | 规则放行（不变） |
| `git archive ':/seed'`、`-- ':/seed'`（有） | 灰色 | **deny** |
| `git archive --mtime 2020-01-01 HEAD`、`--add-virtual-file a.txt:b HEAD`（有） | 灰色 | **deny** |
| `git archive HEAD:src`、`git archive HEAD src` | 灰色 | 灰色（不变） |
| 子目录：`git log -p`、`git show HEAD`（有） | **规则放行** | **deny** |
| 子目录：`git stash show -p`（有） | 灰色 | **deny** |
| 子目录：`git log -p ':/secrets'`、`':(top)'`、`':!b.txt'`、`git diff HEAD:src`（有） | 规则放行 | **deny** |
| 子目录：`git log -p -- b.txt`、`git log -p ':(top)src'`、`git log --oneline`、`git status`、`git diff` | 规则放行 | 规则放行（不变） |
| 子目录：`git grep -e x`、`git archive HEAD` | 灰色 | 灰色（不变） |
| Bash：`'…/BOUNDK~1' mode audit-only`（不带 `.EXE`） | 灰色 | **deny**，灰色 `program-short-name` |
| Bash：`BOUNDK~1 mode audit-only`（经 PATH） | 灰色，配了后端时送审 | 灰色 `program-short-name-unresolved`，**不送审** |
| PowerShell：`BOUNDK~1 mode audit-only`、`& '…\BOUNDK~1'` | 灰色 | 灰色（不变；PowerShell 5.1 不运行它们） |

## 3. 实测

**git**（2.48.1.windows.1），假仓库，一个提交 `seed`：

| 命令 | 结果 |
|---|---|
| `git diff HEAD:src`、`HEAD:secrets`、`HEAD HEAD:src`、`--cached HEAD:src` | 退出码 0，把假 `.env`、假私钥当作新增或删除打印全文 |
| `git diff HEAD:src/a.py` | 退出码 129（blob 不能和工作区比较） |
| `git show HEAD HEAD:src`、`git show HEAD:src HEAD`、`git show HEAD :src/a.py` | 退出码 0，打印 HEAD 的全部改动，含假 `.env` 和假私钥 |
| `git show HEAD:src` | 只列名字 |
| `git archive ':/seed'`、`-- ':/seed'` | 退出码 0，归档里有 `.env`、`secrets/id_rsa` |
| `git archive --mtime 2020-01-01 HEAD`、`--add-virtual-file a.txt:b HEAD` | 退出码 0，整个树都在归档里 |
| 从 `sub` 运行 `git log -p`、`git show HEAD`、`git stash show -p` | 都打印出顶层的假 `.env` |
| 从 `sub` 运行 `git log -p ':/secrets'`、`':(top)'`、`':!b.txt'`、`git diff HEAD:src` | 都打印出假内容 |
| 从 `sub` 运行 `git log -p .` | 只有 `sub` 的改动 |
| 从 `sub` 运行 `git grep -e FAKE`、`git grep -e FAKE HEAD`、`git grep -e FAKE ':!b.txt'` | 退出码 1，没有找到（只在 `sub` 里找） |
| 从 `sub` 运行 `git grep -e FAKE ':(top)'`、`':/secrets'` | 找到假内容（`top` 到了仓库顶层） |
| 从 `sub` 运行 `git archive HEAD` | 归档里只有 `b.txt` |
| 从 `sub` 运行 `git archive HEAD ':(top)'`、`':/secrets'` | 退出码 128；`':!b.txt'` 退出码 0，归档是空的 |

**Git Bash 和 PowerShell 5.1**（`cmd.exe` 的副本改名为 `longprogramname.exe`，短名 `LONGPR~1.EXE`，C: 卷）：

| shell | 写法 | 结果 |
|---|---|---|
| Git Bash | `'/c/…/LONGPR~1'`（不带 `.EXE`） | 运行 |
| Git Bash | `LONGPR~1`，目录在 PATH 里 | 运行 |
| PowerShell 5.1 | `& 'C:\…\LONGPR~1'`（不带 `.EXE`） | `CommandNotFoundException` |
| PowerShell 5.1 | `LONGPR~1`、`LONGPR~1.EXE`，目录在 PATH 里 | `CommandNotFoundException` |

## 4. 修法

- `programs._git_diff_trees`：`diff` 的 `REV:PATH` 读法（R17-1）。
- `programs._git_operands`：
  - `show` 只在每个操作数都是 `REV:PATH` 时才不扫描；
  - `archive` 的 tree-ish 是 `search` 类时不计入 `rev_paths`；
  - 有不认识的长选项时，`archive` 不缩小范围（`_unknown_long_option`）。
- 选项表：`archive` 加上 `mtime=x add-virtual-file=x` 和三个开关。
- 新字段 `CmdInfo.top_paths`：git 从仓库顶层读的路径。
  - 来源有两处：`_git_operands` 读整个仓库时；`_pathspec` 遇到 `top`，或者只有排除（`grep`、`archive` 除外）时。
  - `-C`、`--git-dir`、`--work-tree` 时不记。
  - `event._top_words` 把它们放到项目根下，只在每个工作目录都在项目里、并且至少一个在根之下时才加（`_cwds_below_project`）。
  - `psprograms` 照抄这个字段，`test_m3a_ps_cmdinfo.py` 逐字段比较两种 shell 时会比到它。
- `event._short_name_program`：bash 方言里补 `.exe` 再找。`event._bare_short_name`：给出灰色原因 `program-short-name-unresolved`。`pipeline._UNSHOWN_REASONS` 加上这个原因，所以不送审。

## 5. 度量

"修改前"指 `7b65ad8` 的 `src`（导出到 scratchpad）。

**专门扫描**（5100 条，真实目录树）：
- 3 种目录树：有全部受保护名字、只有顶层 `.env`、没有受保护名字；
- 17 种子命令，25 种写法；
- 工作目录在根或在 `sub`；
- 两种 shell。

结果是 4456 条相同、644 条收紧、**0 条变松**。收紧的都在第 2 节列出的几类里：

| 类 | 收紧的写法 |
|---|---|
| `diff` 的 `REV:PATH` | `git diff HEAD:src` 一类 |
| `show` 带提交 | `git show HEAD HEAD:src` 一类 |
| `archive` | tree-ish 是 `:` 开头的词，或者有 `--mtime`、`--add-virtual-file` |
| 子目录里的整仓库读 | `log -p`、`show`、`stash show -p`，以及带 `top` 的 pathspec |

第一版里只有排除的 pathspec 对 `grep`、`archive` 也另读项目根。实测这两个子命令这时只作用于当前目录，于是收窄了：子目录里的 `git grep -e x ':!b.txt'`、`git archive HEAD ':!b.txt'` 回到修订 17 的灰色，规格也改了。

| 原有的差分 | 结果 |
|---|---|
| 修订 17 的真实目录树扫描（10092 条） | 只有收紧，没有变松：`git` 部分 344 条，带 `--` 的部分 176 条，都在上面几类里；短名和长名的判决全部相同。`--` 之前比之后松的行由 384 条减到 312 条，没有新增；剩下的操作数都是 `:x`、`:N:x`、`REV:PATH`（git 先当修订号）或属于 `cat-file` |
| 修订 16 的扫描（12768 条） | 全部相同 |
| IR-1 的真实目录树扫描（10320 条） | 204 条收紧（子目录里带 `top` 或排除的写法），没有变松；Bash 和 PowerShell 的 5160 对判决仍然全部相同 |
| 带冒号的普通命令（492 条） | 全部相同 |
| 系统目录（4972 种情况 × 5 种环境 × 2 套策略）、逐程序（6334 种情况 × 2 套策略） | 全部相同 |
| 真实磁盘（23544 条）、假机器（179508 条）、孪生项目（30720 条） | 级别全部相同 |
| 含 git 或 `~` 的语料（655 条，1164 次判决） | 0 条不同 |
| `boundkeep test` default / strict | 1142 / 0 失败，334 / 0 失败 |
| 评测（`--config rules+taint --test-contaminated`，输出到 scratchpad，没有打开留出批次） | `results/*.json` 去掉时间戳之后相同；`report.md` 只有日期一行和 4 行延迟不同（跑评测时测试文件在同时跑） |

| 测试和检查 | 结果 |
|---|---|
| 新测试文件 `tests/unit/test_m3a_rev17_review_fixes.py` | 101 passed |
| 受影响的 11 个测试文件（新文件，修订 17 的文件，`test_m3a_readings`、`test_git_local_vcs_allow`、`test_m3a_ps_cmdinfo`、`test_m1c3_cd_allow`、`test_m1c_allow_rules`、`test_m3a_pathspec_and_dotted_names`、`test_review3_core_search`、`test_pipeline_corpus`、`test_evalkit_import`） | 8250 passed，2 skipped（加最后一条测试之前跑的）。漏挑了 `test_review2_core_search.py`，全量才查到（见下文） |
| 变异：21 个，在副本上跑新测试文件、修订 17 的测试文件和 `test_m3a_ps_cmdinfo.py` | **全部抓到**。第一轮 20 个；"工作目录在项目之外也加项目根"那一个存活，加了 `test_a_working_directory_outside_the_project_is_another_repository` 之后抓到 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过 |
| 全量（分六段跑，不是一个进程） | 28619 通过、169 跳过、**7 失败**，合计与收集到的 28795 条相同。09:22:29 到 13:09:48，共 3:47:19，六段都一次跑完。测试文件清单 123 个，与 `tests/` 相同。开始之后，`src`、`tests`、`policies`、`eval`、`scripts` 和测试要读的两份文档都没有改过。失败分两类，见下文 |

**全量里的 7 条失败**：

- **5 条在 `test_review2_core_search.py`**，原因是测试替身，判决本身没有问题。
  - 这个文件把 `programs.classify` 换成替身，替身把 `CmdInfo` 的字段逐个抄进 `SimpleNamespace`，没有抄到新加的 `top_paths`。`event.py` 读这个字段时抛 `AttributeError`，守卫按内部错误给了灰色。
  - 替身改成 `dataclasses.replace(info, recursive=True)`，保留全部字段。同一个文件里另有两条断言"不是 deny"的测试，之前是靠内部错误给的灰色通过的；现在它们也断言没有内部错误。改后这个文件 49 passed。
  - 受影响文件的清单是按改动的函数挑的。这个文件只替换了 `classify`，所以没有挑进去，变异测试也没有跑它。
- **2 条在第 1 段，和修订 18 无关**：
  - `test_daemon.py::test_concurrent_requests_are_all_answered_and_logged`：200 个并发请求里，有的没有得到"不决定"。
  - `test_lifecycle.py::test_the_lock_is_held_across_processes_and_dies_with_the_holder`：用 `os.replace` 写 pid 文件时 `PermissionError`。

  两条单跑各 5 次都通过。但把 `test_daemon.py` 整个一起跑时，这条和另外两条计时测试会一起失败；另外两条是 `test_fast_requests_are_answered_quickly_while_a_review_is_stuck` 和 `test_ping_and_other_events_do_not_wait_for_stuck_reviews`。`7b65ad8` 的代码也一样：新旧代码交替各跑 2 次，4 次都是这 3 条失败、44 条通过。

  当时的电源计划是 `Silent`，电源模式是"最佳能效"（注册表里的叠加方案是 `961cc777…`），接着电源。`M3a.md` 第 5.1 节已经记过 Silent 下这几条计时测试会失败。`daemon/lifecycle.py`、`test_daemon.py`、`test_lifecycle.py` 相对 `7b65ad8` 都没有改；`daemon/pipeline.py` 只多了一个不送审的原因。这几条测试没有改。
- 全量没有因此重跑。

## 6. 代价和残余

1. **子目录里不带 `--` 的 `git log -p b.txt` 现在是 deny**（项目里任何地方有受保护的名字时）。`--` 之前的普通词可能是修订号，所以照常读整个仓库，和在项目根运行一致；写成 `git log -p -- b.txt` 仍然放行。
2. **用项目根代替仓库顶层**，和 `git add` 的整个仓库检查相同：
   - 仓库顶层在项目之上时（monorepo 的子项目），读不到项目之外的部分（X1 复审 R3-5 的老问题，没有改）；
   - 项目里另有一个嵌套仓库、工作目录在它里面时，读得比 git 多。
3. **只在工作目录位于项目根之下时才另读项目根。** 工作目录不在项目里时不加，判决由原来的规则决定。
4. **git 报错的命令也收紧了**：`git diff HEAD:a.py`（退出码 129）、`git archive ':(top)src'` 这样无效的 tree-ish、`git diff --add-virtual-file …` 这样不存在的选项，现在都是 deny。不影响能运行的命令。
5. **IR-7（空树）没有改**，仍等使用者决定。
6. **裸短名只在 bash 方言里处理**：PowerShell 5.1 不运行它（实测）。别的 shell 没有量。
7. **`top_paths` 由 `Word` 的值对应**：同一条命令里同时有 `./src` 和 `:(top)src` 时，`./src` 也另按项目根读。只会多读，不会少读。

## 7. 没有做的

- 真实宿主里没有跑。
- 复审在 `docs/reviews/M3a-rev18-review.md`（2026-11-10，不是独立的，同一个会话做的）。它没有发现回退，查到四个低危缺口，都没有修：
  - R18-1 是这次修法留下的：两棵子树的比较按当前目录扫描，子目录里的 `git diff HEAD~1:secrets HEAD:secrets` 仍由规则放行；
  - R18-2 到 R18-4 更早就有。
- 子目录场景的前提是 hook 收到的 `cwd` 在子目录里。Claude Code 的工具是否把上一条命令 `cd` 进去的目录带到下一条的 `cwd`，没有在真实宿主里量过。复审补充（I-1）：同一条命令里先 `cd sub` 再 `git log -p`，修订 18 之前就是 deny，所以这个前提决定了子目录修复在真实宿主里有没有作用。
