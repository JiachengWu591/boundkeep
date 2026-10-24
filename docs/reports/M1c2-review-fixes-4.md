# M1c / M1c-2 X1 复审：R-1 到 R-12 的修复

日期：2026-10-23。依据：`docs/reviews/M1c2-fixes-rereview.md`（独立复审，3 条高危、5 条中危、7 条低危）。接 `M1c2-review-fixes.md`、`-2.md`、`-3.md`。**没有提交**，没有碰 `~/.boundkeep` 与 `~/.claude`。按三批做，每批补测试与语料。

## 1. 结论

三条高危都关了，中危与低危除了明确接受的缺口也都处理了。核心思路是把三次复发的根因——"按 cmdlet、按选项、按目录逐个列黑名单"——换成一个统一机制：动作的 `dynamic_args` 标记。

| 批 | 编号 | 修法 |
|---|---|---|
| 一 | R-2 | `pscmd` 不再把开关的冒号值整个丢掉：值会展开且不是 `$true` / `$false` / `$null` 就加灰色 `ps-switch-value` |
| 一 | R-3 | 子树扫描对要被读的普通文件取 `st_nlink`，发现硬链接给灰色 `recursive-scan-hardlink`；时间预算 0.2 → 0.35 秒 |
| 二 | R-1、R-4 | 归一化层给每个动作一个标记 `dynamic_args`：命令里有一个**不是路径的**词会展开（对开发工具还有通配符）。**任何 allow 规则都不匹配**这样的动作（`policy/matcher.py`，与"灰色""带包装器"同一位置）。deny / ask 不受影响 |
| 三 | R-5 | 已安装代码的写保护扩到 `venv`、`env`、`.tox`、`.nox`、`.conda`、`.pixi`、`.direnv`、`__pypackages__`、`dist-packages`（两份策略）；路径限定的开发工具不在这些目录里就带包装器标记 `unvetted-exe`，没有 allow 规则匹配它 |
| 三 | R-6 | "钥匙、设置、应用数据目录不能信任"从策略加载器移到 `trust add`（拒绝）与 `doctor`（对存量条目警告并提示 `trust remove`）；加载器不再因此让整份策略失败 |
| 三 | R-8 | `pytest --debug[=FILE]` 声明为写路径选项（两种方言），裸文件名也当路径 |
| 三 | R-7 | 策略不可用时第一次见到的会话也记下快照（空） |
| 三 | R-9 | `protected_read_globs` 用精确的 `LINK_RULE_IDS` 集合代替 `deny-link-` 前缀 |
| 三 | R-10 | `trust add` 的嵌套仓库搜索不穿过 Windows 联接点 |
| 三 | R-11 | pytest 自己的 `-W` / `--pythonwarnings` 带点的类别灰色 `devtool-warning-filter` |
| 三 | R-12 | 白名单环境变量连值一起检查：值是路径（`/x`、`../x`、`C:\x`）、含空格、引号、`$` 的不行 |
| 三 | R-14 | 主目录守护目录清单加 `.azure`、`.password-store`、`.terraform.d`、`.vscode`、`.cache`、`.local`、`Library` |
| 三 | R-15 | 文档与规格同步 |

## 2. 设计要点

- **`dynamic_args`**（`normalize/event.py::_has_dynamic_args`、`model.Action.dynamic_args`）：对命令的每个词，`expands`（或开发工具的 `glob`）且不是 `$true` / `$false` / `$null`、也没有被路径层当作路径（`_consumed_as_path`：整词相等、`--opt=VALUE`、`-opt:VALUE`、`-oVALUE`）就标记。`cat $FILE`、`Get-Content $HOME\a.txt`、`ls "$PWD/src"` 是路径，路径层判断；`pytest -k "$u@args.txt"`、`ConvertTo-Json $env:TOKEN`、`ruff --select $env:X`、`git log -n $env:X` 被标记。这一个机制同时盖住了复审的 R-1（展开之后才是 `@`）、R-4（外部程序的选项值）和 R-2 的另一半，并取代 `ps-dynamic-arg` 的逐个 cmdlet 名单（后者保留，因为它给出可读的灰色原因）。通配符只对开发工具算：`grep -rn x --include=*.py .` 不受影响。
- **R-3 的代价**：本仓库 6141 个条目的树，扫描 33 → 65 毫秒（约 5 微秒一个文件，Windows 上多一次 `os.stat`）。30000 条目的项目约 +150 毫秒，所以预算提到 0.35 秒以保持同样的条目容量。pnpm 的 `node_modules`、`uv` 装进 `.venv` 的包这类本来就有多个名字的树，对整个项目目录做 `Grep` 会变灰（问一次）。`Glob` 只列名字，不受影响。
- **R-5 用包装器标记而不是"不识别"**：先试过让 `devtool_form` 对非环境目录的可执行文件返回 None，结果项目外的全局解释器（`/usr/bin/python3 -m pytest`）从 ask 变成了灰色，是变松。改成仍识别为开发工具（项目外的可执行文件仍被 `ask-devtools-path-outside-project` 问），只加 `unvetted-exe` 标记（`Action.wrappers`），allow 规则本来就不匹配带包装器的动作。

## 3. 测试与语料

- 新 `tests/unit/test_m1c2_rereview_fixes.py`（587 个用例，Windows 主机上 30 个因 PowerShell 只跑 Windows 假机器而跳过）：
  - R-2：35 个（cmdlet, 开关）× 5 种展开形式在有无信任下都不是 allow，布尔字面量 × 4 仍 allow；
  - R-3：`subtree.scan` 的单元测试（硬链接、深层、目录与单名字文件、`select` 排除、`skip_names`）与真实磁盘的整条管道（`Grep`、`rg`、`grep -r` 等 7 种目录读在有硬链接时不是 allow、无链接时仍 allow、删掉链接后又 allow、Grep 的 `glob` 够不到时不受影响）；
  - R-1、R-4：21 条复审给出的命令 × 两个平台标记为 `dynamic_args` 且在 default / strict、有无信任下都不是 allow，16 条常量与路径词不标记；
  - R-5：11 个环境目录 × 两个策略 × 两个平台的写入、4 个只是长得像的名字照旧 allow、7 个环境里的可执行文件仍 allow、9 个别处的可执行文件不是 allow 且带标记；
  - R-8、R-11、R-12、R-9、R-14 各自的表。
- `tests/unit/test_m1c2_trust_cli.py`：`trust add` 拒绝守护目录（5 种）、旧策略里有这种条目时策略仍可加载 / `trust list` 正常 / `doctor` 警告并给出 `trust remove` / 删除后警告消失、联接点不被穿过。`test_m1c2_review_fixes_trust_links.py`：策略不可用时的会话快照。
- 语料：新文件 `tests/corpus/pipeline_x1_rereview.yaml`（85 条：70 条 R-2 的 `adv`、11 条 R-5 的写入、4 条"只是长得像"的 allow）；`pipeline_m1c2_trusted.yaml` 加 56 条（R-1/R-4 21、R-5 9、R-8 7、R-11 4、R-12 4、仍 allow 的 11）。default 加 7 条、strict 加 2 条 `tests:`。规则数不变（72 / 56）。

**改过的旧期望**：`test_m1c2_review_fixes_3.py` 里已安装代码规则的 glob 清单与 M-3 的四个测试（加载器不再拒绝，`trust.guard_tree_reason` 才拒绝）；`test_m1c2_devtools_bash.py` 里路径限定的可执行文件在环境目录外时 `wrappers == ("unvetted-exe",)`；语料里 `m2r-l1-006`、`m2r-l1-013`（`pytest --debug=C:x`，gray → ask，因为 `--debug` 现在是写路径）。没有放宽任何期望。

## 4. 验证

- `ruff check .`、`ruff format --check .`（183 个文件）、`mypy`（48 个源文件，strict）：干净。
- `boundkeep test`：default 806 次运行、strict 304 次运行，0 失败。
- `scripts/measure_ask_rate.py`：Windows 54.2、POSIX 53.3，与之前一致，与设计目标有差异的条目 0 个。
- 完整套件：见第 6 节。

## 5. 没做的与需要你知道的

- **接受的缺口**（复审里的原话保留）：会话快照在内存里，守护进程重启与 512 个会话之后的驱逐仍会让一个会话拿到当前列表（R-7 只修了"策略不可用"这一种）；`cmd /c mklink`、`fsutil` 的相对写法仍只是 ask（R-8 的另一半，靠 `--debug` 修好后不再能经硬链接写策略文件）；**选项白名单没做**。
- **可用性代价**：`pytest -k "$NAME"`、`Select-String -Pattern $pattern`、`Get-Content a.txt -Tail $n` 这类带变量的值会多问；开发工具里**未加引号**的通配符词（`pytest -k test_*`）变灰；整个项目目录的 `Grep` 在含硬链接的树里变灰；一个叫 `env` 的源码目录的写入会问；`./pytest` 这类项目内可执行文件不再被放行。
- **R-13（可用性回归）**没有单独处理：既有的灰色（`--cov-report`、`-p no:cacheprovider`、`PYTHONPATH=src pytest`）仍是最常见的询问，是 `flags_none` 与环境变量名单的设计代价，选项白名单才能解决。
- **没有在真实 Claude Code 里验证**，Linux 容器没有跑。
- **推送**：上一轮已推送（`main` 与标签）；这一轮不推送、不提交。

## 6. 完整套件

**最终的完整运行（`uv run pytest -q`，Windows 主机，约 49 分钟）：24433 通过、167 跳过、0 失败。** Linux 容器没有跑。

过程：第一次完整运行 24428 通过、5 失败，都是新行为让旧期望过时，没有一个是新行为出错：

- `test_m1c2_ps_devtools.py` 的 4 个用例（PowerShell 的路径限定开发工具在环境目录外时 `wrappers` 现在是 `("unvetted-exe",)`），改了期望（和 Bash 一侧的同类用例一致）。
- `test_m1c2_review_fixes.py::test_the_trusted_corpus_has_the_adversarial_entries_of_the_review`：它要求所有 `m2r-` 前缀的语料条目都是 `adv` 且期望非 allow，我把"仍然 allow 的邻居"也起名 `m2r-keep-*`，改名为 `m2k-keep-*`。

这一轮改过的旧期望：以上，再加第 3 节列的那几项；**没有放宽任何期望**。
