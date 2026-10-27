# M2 之后的规则改动一：git add / commit / stash 的定向 X1 审查（终稿）

日期：2026-10-26。审查对象：`f7fe657`（代码）、`be43c66`（文档）以及工作区里尚未提交的全部修复。依据：`docs/reports/M2-rules-1.md`（作者的声明，当作待核实的说法）。只读，未改任何源码、策略或已提交文档；本文件未加入 git。

版本史：R3-1（commit 的 `--pathspec-from-file`）→ R3-2（`stash --output`，我第一次写错后更正）→ R4-1（`--` 绕过白名单）→ R5-1（cwd 在子目录时 `git add -A` 漏扫）→ R6-1（`--no-ignore-removal` 与只有排除的 pathspec）→ 本版：R6-1 的最后复核。

## 0. 结论先行

- **没有高危，也没有中危。** R6-1 已关闭。
- **三条规则都可以冻结**（`allow-git-add`、`allow-git-commit-message`、`allow-git-stash`，以及 `ask-git-read-outside-project` 的子命令扩充）。冻结之后 `policies/default.yaml` 一变，M2 基线要对应重取。
- 第 3 节是终局的"已声明的残余"清单，供写总结用。

| 编号 | 结论 |
|---|---|
| R3-1 commit 的 `--pathspec-from-file` | 已关闭 |
| R3-2 / R4-1 `stash list|show` 写文件（含 `--` 绕过） | 已关闭（白名单；`--` 标记） |
| R3-3 / R5-1 / R6-1 `git add` 暂存未跟踪的敏感文件 | 已关闭（降级为灰色，整仓库形式扫描项目根） |
| R3-4、R3-6、R3-10 | 已关闭 |
| R3-5 仓库根在项目之上 | 已关闭（爬升上限 128；联接点项目是已声明残余） |
| R3-7、R3-8 `-p`/`-i` 及缩写 | 已关闭 |
| R3-9 `GIT_TRACE*` | 旧残余，不是这次引入（第 3 节） |

## 1. 方法

与前几轮一致：假机器上用 `policycli._run_one` / `pipeline.review` 判决；需要真实磁盘的在 `%TEMP%\bk_rr_disk` 的一次性目录里做（项目根有 `.git` 目录和一个 `.env`，子目录 `src`，cwd 取项目根或 `src`）；git 的真实语义在 `%TEMP%\bk_rr_git*` 的一次性仓库里用 `--dry-run` 等无害命令确认。没有碰真实的 `~/.boundkeep`、`~/.claude`。

## 2. R6-1 修复的最后复核

`_stages_whole_repository`：`-A`、`--a…`（`--all` 的前缀）、`--no-i…`（`--no-ignore-removal` 的前缀）或任一以 `:` 开头的操作数时，额外扫描项目根；只有全是普通路径且没有这些选项时才只扫 cwd/操作数。

同样的子目录设置（cwd=`proj\src`，项目根有 `.env`）：

- **灰色（`git-add-may-stage-protected`）**：`--no-ignore-removal`、`--no-ignore-rem`、`--no-i`、`--no-ig`、`--no-ignore-removal -v`、`--no-ignore-removal src`；`':!x'`、`':^x'`、`':(exclude)x'`、`':!/x'`、`':(exclude,top)x'`、`':(icase,top)x'`、`':(literal)x'`、`':(attr:x)'`；`-- ':/'`、`-- ':!x'`、`:/`；`-A`、`-Av`、`-vA`、`--all`、`--a`、`--al`；混合 `src :!x`、`notes.md ':!x'`。`':(glob,top)*'` 是 ask（另一条规则，本来就挡）。PowerShell：`--no-ignore-removal`、`--no-i`、`':!x'`、`':(exclude)x'`、`-- ':/'`、`-Av`、`-vA` 全灰。
- **不受影响（allow）**：普通文件操作数（`notes.md`、`./notes.md`、`pkg/m.py`、`-- notes.md`）、普通目录操作数（`pkg`、`./pkg`、`../src`）、`.`、`notes.md pkg`、`-u`；带选项的普通操作数（`-v notes.md`、`-n pkg`、`--chmod=+x notes.md`、`-N notes.md`、`--renormalize pkg`）；不暂存整仓库的选项（`--no-all`、`--ignore-removal`、`--no-intent-to-add`、`--no-interactive`、`--no-edit`）。PowerShell 的 `notes.md`、`pkg`、`.`、`./notes.md`、`-u` 同样 allow。
- **以 `:` 开头的文件名**：`./:colon.txt`、`-- ./:colon.txt`、`pkg/:colon.txt` 是普通路径，allow；裸的 `:colon.txt`、`':colon.txt'` 灰色。这与 git 一致（裸的 `:name` 在 git 里就是 pathspec 魔法，要写成 `./:name` 才是文件名），所以灰色是安全方向的多问，不是漏。
- **项目根干净时的对照**：`--no-ignore-removal`、`':!x'`、`:/`、`-A`、`notes.md`、`pkg` 全部 allow（没有无谓的询问）。
- **组合**：`git add --no-ignore-removal && git commit -m x`、`git add -A; git stash -u` 整行灰色；`git add notes.md && git commit -m x`、`git add notes.md; git stash` allow；仓库根在项目之上（项目=`src`）时 `--no-ignore-removal`、`':!x'`、`notes.md` 都是 `git-root-above-project` 灰色；cwd 在项目根时同样的写法都灰色。
- 回归：`tests/unit/test_git_local_vcs_allow.py` 287 个通过；`boundkeep test` default 905、strict 310，0 失败；`scripts/measure_ask_rate.py` Windows 52.3、POSIX 51.3，与设计目标差异 0。重跑 R3-1、R3-2、R4-1、R3-7 的片段无变化。

**R6-1：已关闭。**

## 3. 终局清单：已声明的残余（open items）

**需要决定 / 没有残余需要在冻结前处理：无。**

**已声明、可接受的残余**

1. **仓库自带的 hook / 过滤器 / fsmonitor**：`git commit` 运行 `.git/hooks`；`git add` 运行 `filter.*.clean`；`add|commit|stash` 刷新索引时可能运行 `core.fsmonitor`——来自随仓库带来的配置，agent 自己写不了（`ask-git-internals-write`）。这也是 `defaults.emit_allow` 必须保持关闭的原因（与 `allow-git-read-only` 同一类）。
2. **暂存未被忽略的敏感文件**：`git add` 在扫描到受保护名字时变灰（询问），不是拒绝；扫描不看 `.gitignore`，所以有被忽略的 `.env` 的项目里每次 `git add .`/`-A` 会询问。扫描跳过 `.venv`、`venv`、`node_modules`、`__pycache__`、`.tox`、`.nox`、`.mypy_cache`、`.pytest_cache`、`.ruff_cache`、`.hypothesis` 和版本控制目录（没有找到利用这个跳过名单的办法）。
3. **性能**：扫描共用 0.35 秒 / 30000 条目的预算；文件数超过几千到一万多的项目里 `git add .`/`-A`/`add <大目录>` 变灰（`recursive-scan-budget`，安全方向），每次 `git add .` 判决多约 0.3 秒；`git add -u`、`git status` 不受影响。
4. **项目是联接点**：从联接点路径打开项目时，`git-root-above-project` 从字面 cwd 向上找，找不到仓库根（低危；作者已声明）。
5. **历史里的秘密**：已删除的文件或旧 stash 里的敏感内容，工作区扫描看不到——`git log -p`、`git show` 同样如此（旧缺口）。新规则下 `stash list|show` 只放行 `--oneline`/`--stat` 系列，不会打印补丁。
6. **用户自己的配置**：`stash.showPatch` 等会让无选项的 `git stash show` 打印补丁；用户配置，agent 写不了。
7. **`GIT_TRACE*` 环境前缀**：把追踪输出写到环境变量指名路径；`git` 程序没有环境前缀白名单。这是旧残余，也影响已冻结的 `allow-git-read-only`，不是这三条规则引入的。
8. **`git diff` 不做工作区扫描**（已冻结的 `allow-git-read-only` 的旧缺口）：已跟踪的敏感文件的改动经 `git diff` 可见；R3-3 的降级方案只堵了"先 `git add` 再 `git diff --cached`"这条新链。
9. **选项白名单（L-1）整体未做**：只有 `stash list|show` 用了白名单；`add`/`commit`/`stash push` 靠黑名单加缩写列举，已用真实 git 逐个核对唯一前缀，但"列全"只能靠测试。
10. **评测**：test 切分已被污染（`M2-rules-1.md` 第 6 节）；`m2-baseline` 标签对应改动之前的规则，要对改后的规则做无偏比较需要新的留出集，规则一改也要重取基线。
11. **没有验证的环境**：pwsh 7、真 bash、Linux/macOS、Docker；符号链接（无权限，用联接点/硬链接代替）；没有重跑完整 `pytest`、`ruff`、`mypy`。

## 4. 作者声明核对

| 声明 | 判定 |
|---|---|
| 整仓库形式（`-A`、`--all*`、`--no-ignore-removal*`、任何以 `:` 开头的操作数）扫描项目根，其余只扫 cwd/操作数 | 属实（含缩写 `--no-i`、`--a`、`--al`；普通路径与以 `:` 开头但写成 `./:name` 的文件名不受影响） |
| 其余各项（`--` 标记、`--inter…`、爬升上限 128、降级方案、跳过名单） | 属实，见前几版与本轮重跑 |
| 没有放宽任何期望 | 属实 |

## 5. 结论

- **高危是否清零：是。中危：无。**
- **能否冻结：三条规则都可以冻结。** 冻结前不再有必须做的事；残余见第 3 节，需要使用者知情的是第 1、2、3、10 条。
- 冻结之后若再改 `policies/default.yaml` 或归一化器，请再做一次同样的定向复核，并重取 M2 基线。
