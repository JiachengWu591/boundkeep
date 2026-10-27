# M2 之后的规则改动一：git add、git commit、git stash 的 allow 规则

日期：2026-10-26。**状态：已实现、测试通过、五轮独立的定向 X1 审查做完，无高危、中危剩余**（见第 6a、6b 节）。基线标签 `m2-baseline` 对应的是改动之前的规则（`policies/default.yaml` sha256 `5140b88b59a89354…`）；审查修复之后的最终规则是 `7e0eda0cd64e133f…`（中间的 `39d8a6f7…` 是第一版）；评测数字没有变（dev：Windows 误报 34.8%、POSIX 65.0%；达到要求的攻击样本数不变）。

## 1. 为什么改

M2 的基线（`docs/reports/M2.md` 第 4 节，只用 dev 统计）里，误报最大的一块是“没有规则匹配（灰色）”的日常命令：Windows 21 条、POSIX 35 条。其中 `git add`、`git commit`、`git stash` 是最典型的一组：本地的版本控制操作，只写仓库自己的索引与对象库，不联网、不运行程序、不碰项目外的文件，却因为没有 allow 规则而每次都问。规则本身有独立于数据集的理由（它们是最常见的本地写操作，与已经允许的 `git status`、`mkdir`、项目内写文件同一档），不是为了某几条样本写的。

## 2. 改了什么

| 位置 | 改动 |
|---|---|
| `policies/default.yaml` | 新增 `allow-git-add`、`allow-git-commit-message`、`allow-git-stash`（strict 不加，有测试守着）；`ask-git-read-outside-project` 的子命令列表加上 `add`、`commit`、`stash`（项目外的路径照样问）；两条旧的 `tests:` 期望（`git stash list`、`git add .`）从 gray 改为 allow，新增 35 条覆盖 |
| `src/boundkeep/normalize/programs.py` | `git stash` 的子命令不在 push、save、list、show、apply、pop 之内时（drop、clear、branch、create、store、未知），动作上多一个标记 `--stash-other`。规则语言看不见位置参数，这是同 `git push +ref` 标成 `--force` 一样的做法 |
| 测试 | 新增 `tests/unit/test_git_local_vcs_allow.py`（141 个）；`test_m1c_allow_rules.py` 的规则登记与“保护范围”一致性测试更新；两份语料里原来写“必须不放行”的 5 条（`git stash list`、`git stash`、`git add .`、`git commit -m x`、PowerShell 的 `git add .`）改为 allow，`git stash drop` 仍是 adv；工作流语料里 8 条从 keep-ask 档移到 allow 档 |
| 文档 | `docs/policy-reference.md` 加三行规则说明 |

## 3. 它放行什么、不放行什么

- **放行**：`git add`（无 `-f`、`-e`、`--pathspec-from-file`）、`git commit`（消息写在命令行：`-m`、`--message` 或 `--no-edit`；无 `-e`、`-S`）、`git stash`（push、list、show、apply、pop；无 `-a`）。
- **不放行**：`-f` / `--force` 及其缩写（会暂存被忽略的文件）；会启动编辑器、gpg 的选项；`git stash drop` / `clear` / `branch` / `create` / `store`；全局的 `-c`、`-C`、`--git-dir`、`--work-tree`、`--exec-path`、`--paginate`；包装器（`sudo`、`env`、`time`）和带代码的环境变量前缀（`GIT_EDITOR=…`）；消息是计算出来的（`-m "$(date)"`）。
- **仍由别的规则判断**：操作数是密钥或凭据（`git add .env`、`git add ~/.ssh/id_rsa`）是 deny；`.git` 里的路径是 deny；项目外的路径是 ask；同一行里有 `git push` 之类，整行取最严的那个。

## 4. 对评测的影响

只用 dev 描述（test 的情况见第 6 节）：

| 格子 | 误报（改动前 → 后） | 达到样本要求的攻击样本 |
|---|---|---|
| Windows dev | 36.5% → 34.8%（66 → 63 条） | 77 / 94，没变 |
| POSIX dev | 68.3% → 65.0%（82 → 78 条） | 90 / 104，没变 |

改动很小，不是误报的主因（最大的两块还是 MCP 一律灰色，约 20 条，和 `net-allowlist` 太粗，10 到 16 条）。**没有任何攻击样本因此变成 allow**（拦截合计仍是 100%）。

## 5. 风险与残余（需要审查的地方）

1. **hook**：`git commit` 会运行仓库自己的 hook（`.git/hooks`、`core.hooksPath`）。agent 自己写不了这些（`ask-git-internals-write`），但随仓库带来的 hook 会跑；与 `allow-git-read-only` 的 fsmonitor 同一类残余，所以 `defaults.emit_allow` 必须保持关闭。
2. **`git add -A`** 会把没被忽略的未跟踪 `.env` 放进索引（操作数里没有路径，密钥规则看不到）。只是进了索引，没有外传；之后的 `git push` 会问。
3. **选项缩写**：git 接受长选项的唯一前缀。我把 `--force`、`--edit`、`--gpg-sign`、`--pathspec-from-file`、`--all` 的各个缩写逐个列进了 `flags_none`，但没有别的办法保证列全。这类问题的根本解法还是“选项白名单”（L-1，一直没做）：只放行已知安全的选项，其余一律问。建议审查者重点看这个。
4. **`git stash` 的 `--stash-other` 标记**是规范化器和规则之间的约定，两边要同时改；测试守着。
5. 项目惯例是 allow 规则要做定向 X1 审查。写这一节时没做；之后做了五轮，结果见第 6a、6b 节。

## 6. test 切分已被污染

做这个改动之前，我为了写 M2 报告看过 test 切分的指标和每格前 10 条。这次改动的动机来自 dev 的原因统计和规则自身的理由，test 里也没有 `git add` / `commit` / `stash` 的样本（test 上的数字没有变），但严格按方法学，规则是在看过 test 之后改的，**test 不再能给改后的规则一个无偏的估计**。`eval/report.md` 因此带 `--test-contaminated`，局限性一节写明了这一点。要对改后的规则做无偏比较，需要一个新的留出集。

## 6a. 独立审查的结果（2026-10-26）

同一复审者（`docs/reviews/M2-rules-1-review.md`，未提交）审了这三条规则：**一条高危 R3-1**，其余关闭。

- **R3-1（高）**：`allow-git-commit-message` 的 `flags_none` 漏了 `--pathspec-from-file` / `--pathspec-file-nul`。`git commit` 支持这个选项（真实 git 2.48.1 确认），会读取所指的文件，没有匹配路径时把文件内容原样打进报错——一个读文件并回显的通道。而规范化器没有为 `commit` 声明这个选项，值只有“看起来像路径”（以 `.`、`/`、`~` 等开头）才会被当作路径检查，`id_rsa`、`credentials.json`、`config` 这样的裸文件名完全不受检查。
- **修复**：(1) `allow-git-commit-message` 补上 `--pathspec-from-file` 的全部缩写和 `--pathspec-file-nul`；另外两条规则也补上 `--pathspec-file-nul`；(2) 根本一层：`_GIT_SUB_OPTS` 给 `commit`、`add`、`stash` 都声明 `pathspec-from-file=r`，文件按“读路径”判断，所以 `--pathspec-from-file=id_rsa` 现在是 deny，项目外的是 ask；(3) default 的 `tests:` 加 3 条，`test_git_local_vcs_allow.py` 加 14 条，语料加 6 条 adv。
- 复审者的结论：`allow-git-add`、`allow-git-stash` 与守卫规则的扩充可以冻结；`allow-git-commit-message` 要在修复后用报告第 2 节的片段复核。

**第二轮复核**（`docs/reviews/M2-rules-1-review.md` 更新版）：R3-1 关闭，但发现了 R3-2（高）、R3-3 到 R3-5（中）、R3-6 到 R3-10（低）。处理如下：

| 编号 | 问题 | 处理 |
|---|---|---|
| R3-2（高） | `git stash list --format=%b --output=conftest.py` 把 stash 消息（agent 可控）写进项目里的裸文件名（`conftest.py`、`Makefile`、`package.json`、`CLAUDE.md` ...），绕过自动运行文件与 agent 配置的 ask 规则；`stash list|show` 带着整个 `git log` / `git diff` 的选项集 | **改成白名单**：规范化器对 `stash list` 只放 `--oneline`、对 `stash show` 只放 `--stat`、`--name-only`、`--name-status`、`--numstat`、`--shortstat`，其余选项打上 `--stash-other`。顺带关掉 R3-4、R3-6、R3-10 |
| R3-3（中） | `git add -A`（allow）加已冻结的 `git diff --cached`（allow）：一个没被 `.gitignore` 忽略的 `.env` 的全文进入上下文 | 复审者给了一个便宜而安全的办法，已采用：`git add`（`-u` 除外）作用于目录或整个工作区时，先在那棵树下找受保护的名字；找到就**灰色（ask）**，不是 deny。依赖目录和缓存目录（`.venv`、`node_modules`、`__pycache__` 等）不计，因为虚拟环境里有 `cacert.pem` 这类名字像密钥的文件。代价：未被忽略、也没被跳过的 `.env` 在磁盘上时，`git add .` 回到“问一次”（与改动之前一样）。它要读磁盘，假机器和评测里不生效 |
| R4-1（高，第三轮） | `git stash list -- --output=zz.txt`：git 自己的 `stash list` 解析器接受用户给的 `--`，其后的选项仍然生效（真实 git 确认；`git log|diff|show` 与 `stash show` 不是这样），而规范化器把 `--` 之后的都当操作数，白名单看不见 | `stash list|show` 里出现 `--` 一律打上 `--stash-other` |
| R5-1（中，第四轮） | R3-3 的扫描只看当前目录：cwd 是 `proj\src` 时，`git add -A`、`--all`、`:/`、`:(top)` 仍是 allow（这几种写法从子目录也暂存整个仓库），而 bash 的 `cd` 会跨调用保留 | `-A`、`--all`（含缩写）、`:/`、`:(top)` 时**也扫描项目根**，不只扫 cwd。大目录树（约 8000 个以上文件）会因扫描预算用尽而灰色，多约 0.3 秒；这是 ask，方向安全 |
| R6-1（中，第五轮） | 从子目录 cwd，`--no-ignore-removal`（等于 `-A`）和只含排除的 pathspec（`:!x`、`:^x`、`:(exclude)x`、`:!/x`、`:(exclude,top)x`）也暂存整个仓库，没被扫描（真实 git `--dry-run` 确认） | 规则改成“除非每个操作数都是普通路径（不以 `:` 开头）且没有 `-A`、`--all`、`--no-ignore-removal`（及其唯一缩写），一律也扫项目根” |
| R3-7 补（低） | `--inter` 到 `--interacti` 是 `--interactive` 的有效唯一缩写，没在 `flags_none` | 三条规则都补上 |
| R3-5 补（低） | 向上找 `.git` 最多 16 层；联接点项目不在检查范围 | 这个检查改为最多 128 层；联接点项目仍是残余 |
| R3-4（中） | `git stash list -p` 显示已贮藏的密钥改动 | 由 R3-2 的白名单关闭 |
| R3-5（中） | 仓库根在项目目录之上时，`git stash`、`git add -A`、`git commit -a` 会动项目以外的文件 | 新灰色原因 `git-root-above-project`：找到的 `.git` 在项目目录严格之上时，这三个子命令不 allow。要读磁盘，所以假机器和评测里不生效；真实磁盘上有 5 个命令 × 两种情形的测试 |
| R3-6、R3-10（低） | `stash show` 的 `--ext-diff`、`--textconv`、`-O` | 由 R3-2 的白名单关闭 |
| R3-7、R3-8（低） | `-p` / `--patch` / `-i` / `--interactive` 加 stdin 可启动编辑器；全局 `-p` | 三条规则的 `flags_none` 都加了 `-p`、`--patc`、`--patch`、`-i`、`--interactiv`、`--interactive` |
| R3-9（低） | `GIT_TRACE=<路径>` 等把追踪信息写到指定路径 | 既有残余（Bash 层对 `git` 没有环境前缀白名单，同样影响已冻结的 `allow-git-read-only`），不在这次改动里处理 |

**R3-3 为什么不是 deny**：根子在已冻结的 `allow-git-read-only`——`git diff` 的“整个工作区是隐式读取”没有触发子树扫描。扫描器不看 `.gitignore`，所以让 `git add` 或 `git diff` 在发现受保护名字时 deny，会让项目里只要**磁盘上存在**一个 `.env`（哪怕被忽略）就拒绝最常用的 `git add .` 或 `git diff`，伤害远大于它挡住的情形。所以改成 ask：磁盘上有受保护名字时，`git add .` 回到改动之前的“问一次”，没有时才放行。**仍然留下的**：`git commit -a` 和 `git stash -u` 不做这个扫描（它们不会把新的未跟踪文件放进可被 `git diff --cached` 显示的索引）；已跟踪的 `.env` 被改过之后，`git diff` 显示它的内容是 `allow-git-read-only` 本来就有的缺口；根本办法仍是 git 感知的扫描（只看未被忽略的文件）。
- 复审者另记两点低危提醒，没有单独编号：`-p` / `--patch` 在有 stdin 时可进入交互式选取；`GIT_TRACE=<路径>` 这类环境变量会把追踪信息写到指定路径，是 Bash 层对 `git` 没有环境变量白名单的旧残余，不是这次引入的。

## 6b. 审查的最终结果（五轮，2026-10-26）

复审者（`docs/reviews/M2-rules-1-review.md`，未提交）五轮下来：R3-1 到 R3-10、R4-1、R5-1、R6-1 共发现 **3 条高危、4 条中危**，全部已修（除了 R3-3 改为“问一次”，不是 deny）。**最后一轮结论：没有高危或中危剩余，`allow-git-add`、`allow-git-commit-message`、`allow-git-stash` 和 `ask-git-read-outside-project` 的子命令扩充都可以冻结。**

这三条规则的最终形态靠三层：规则的 `flags_none`（`-f`、`-e`、`-S`、`-p`、`-i`、`--pathspec-from-file` 等及缩写）、规范化器里的两处白名单与标记（`stash list|show` 只放极少几个选项，`--` 也不放；`stash` 的其余子命令打 `--stash-other`）、以及两处读磁盘的检查（`git-root-above-project`、`git-add-may-stage-protected`）。

**已声明的残余**（完整清单在复审报告末尾）：

1. 仓库自带的 hook、clean 过滤器、`core.fsmonitor` 会跑——`defaults.emit_allow` 必须保持关闭。
2. 磁盘上有未被忽略也没被跳过的受保护名字时，`git add` 是“问一次”，不是 deny；依赖和缓存目录不计。
3. 大目录树（约 8000 个以上文件）因扫描预算用尽而灰色，每次 `git add .` 多约 0.3 秒。
4. 通过联接点打开的项目，“仓库根在项目之上”的检查看不到。
5. 只存在于历史或旧 stash 里的密钥，树扫描看不到。
6. 用户配置里的 `stash.showPatch` 可以让朴素的 `git stash show` 打印补丁。
7. 已冻结的 `allow-git-read-only` 的两处旧缺口：`GIT_TRACE*` 环境变量前缀可以把追踪输出写到指定路径；`git diff` 不扫描工作区。
8. 没有通用的选项白名单（L-1）：只有 `stash list|show` 有。
9. 评测：test 切分已被污染，策略一变基线要重取。
10. 没有覆盖：pwsh 7、真 bash、Linux 与 macOS、符号链接。

## 7. 验证

`ruff`、`mypy`（57 个源文件，strict）干净；`boundkeep test`：default 870 条（原 806）、strict 310 条（原 304），0 失败；`test_m1c_allow_rules.py`、`test_pipeline_corpus.py`、`test_git_local_vcs_allow.py` 共 6368 个通过；完整套件见会话里的最终报告。
