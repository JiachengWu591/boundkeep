# M2 之后的规则改动一：git add、git commit、git stash 的 allow 规则

日期：2026-10-26。**状态：已实现、测试通过；没有做独立的安全审查**（项目惯例是每次加 allow 规则都要做定向 X1 审查，见第 5 节）。基线标签 `m2-baseline` 对应的是改动之前的规则（`policies/default.yaml` sha256 `5140b88b59a89354…`）；改动之后的规则是 `39d8a6f7f32d492b…`。

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
5. 项目惯例是 allow 规则要做定向 X1 审查。**这次没做**，所以这三条规则在审查通过之前，不应当作已冻结的规则。

## 6. test 切分已被污染

做这个改动之前，我为了写 M2 报告看过 test 切分的指标和每格前 10 条。这次改动的动机来自 dev 的原因统计和规则自身的理由，test 里也没有 `git add` / `commit` / `stash` 的样本（test 上的数字没有变），但严格按方法学，规则是在看过 test 之后改的，**test 不再能给改后的规则一个无偏的估计**。`eval/report.md` 因此带 `--test-contaminated`，局限性一节写明了这一点。要对改后的规则做无偏比较，需要一个新的留出集。

## 7. 验证

`ruff`、`mypy`（57 个源文件，strict）干净；`boundkeep test`：default 870 条（原 806）、strict 310 条（原 304），0 失败；`test_m1c_allow_rules.py`、`test_pipeline_corpus.py`、`test_git_local_vcs_allow.py` 共 6368 个通过；完整套件见会话里的最终报告。
