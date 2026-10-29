# 留出集 h2 的封存记录

日期：2026-10-29。**状态：正常样本那一半已封存（261 条）；攻击样本那一半等使用者按 `eval/authoring/HOLDOUT.md` 写。** h2 写完之后、下一次改规则之前用 `run_eval.py --open-holdout h2` 打开一次。

h1 在 2026-10-28 打开之后改过规则，已被污染（`docs/reports/M2-rules-3.md` 第 9 节），所以之后的规则需要一批新的留出样本。

## 1. 冻结的规则

| 项 | 值 |
|---|---|
| 提交 | `53159b4`（之后到 h2 打开之前不改规则） |
| `policies/default.yaml` sha256 | `168b4bee184933cc010bd997618a020b3e97f719bc62822f3c3204c333cf588f` |

## 2. 先做的框架改动：留出集分批

原来的代码把所有留出样本当成一个整体：加进 h2 会改变 h1 的指纹、和 h1 一起打开、一起被判为已污染。改成每一批独立（口径 `docs/eval-methodology.md` 第 4b 节）：

| 位置 | 改动 |
|---|---|
| `evalkit/dataset.py` | `batches`、`batch_hash`（一批的指纹；只有一批时等于原来整个留出集的指纹）；`sealed(samples, opened)` 只放出要打开的那一批；留出样本不得与 dev、test **或别的批次**重复动作 |
| `evalkit/holdout.py` | 台账每行记批次，污染按批次判断；没有批次字段的旧行算 h1（当时只有 h1） |
| `eval/run_eval.py` | `--open-holdout 批次`（只有一批时可以不写名字，有多批时必须写）；`--check` 打印每一批的指纹；结果里 `holdout_batches` 列出每一批的状态 |
| `evalkit/report.py` | 每一批一行状态（封存 / 以前打开过 / 已污染 / 这次打开） |
| `evalcli.py`、`importer.py` | `import-session --holdout h2` 丢弃 dev、test 与别的批次里已有的动作（计为 `already-in-dev-test-or-another-batch`）；`promote` 放进 `holdout/<批次>/real.jsonl` |
| `eval/add_samples.py` | `--holdout h2` 输出到 `holdout/h2/<类别>.jsonl`，id `hold-h2-…` |
| 数据 | h1 的 8 个文件移进 `eval/datasets/holdout/h1/`（内容不变，指纹仍是 `ec0ea392daf0c15a…`，与台账一致） |

## 3. 正常样本（真实会话，261 条）

| 项 | 值 |
|---|---|
| 来源 | 使用者选定：四个与规则开发无关的项目在 2026-10-25 之后的会话（不含 boundkeep 本项目）。E:\2026…（代理模型研究）、FYP（proposal 与 problem formulation）、uszipcode3-0（公开数据源调研）、zh-ipi-bench。这些会话没有任何样本进过 dev、test、h1 |
| 导入 | 1828 次工具调用 → 271 条候选（丢掉：路径在项目 / 主目录 / 系统目录之外 793、像密钥 70、同类调用超过 3 条 312、不导入的工具 344、过长 30、被权限拒绝 2、重复 6） |
| 预筛（使用者同意） | 删 9 条：把 API key 文件读进变量 1、按进程名全部结束 2、重复的轮询 1、提到导师不愿公开的数据源 1、含 Gist id 2、调查一封来信的发件方 2。去掉任务意图 107 条：uszipcode3-0 整个会话（意图里有使用者粘贴的导师回复，涉及不公开的信息）与 4 条以 Claude Code 自动续接摘要为意图的调用。`runs_repo_code` 改正 8 条（`pdflatex`、项目里的构建脚本为 True，临时目录里 agent 写的脚本为 False） |
| 去重 | 去掉意图之后有 1 对变成同一个事件（两次参数为空的 `get_page_text`），删掉后一条 |
| 确认 | 使用者在对话里确认了其余全部样本；由我用 `dataset.confirm_file` 写入，`boundkeep eval promote` 入库到 `eval/datasets/holdout/h2/real.jsonl` |
| 构成 | 全部 Windows；PowerShell 94、Write 50、Read 41、Edit 30、Grep 27、Glob 6、MCP（浏览器面板等）13；`runs_repo_code` 8 条；没有任务意图的 114 条（107 条是预筛去掉的，8 条导入时就没有） |
| 指纹（正常样本这一半） | `8f1992e64193a9633f3b5dbc9054aae819da3e8cb0a75c9a212652542721c082` |

**没有在这些样本上跑过规则**：预筛只按隐私和与 h1 一致的口径（批量结束进程、重复轮询）删，不看裁决；重新生成的评测报告没有打开 h2。

## 4. 偏差与局限（打开时要带着读）

1. **只有 Windows**：使用者的会话都在 Windows 上，h2 目前没有 POSIX 的正常样本，POSIX 的误报率在 h2 上没有数字。
2. **集中在一个会话**：uszipcode3-0 占 102 条（39%），而且这些样本没有任务意图（对 `rules-only` 没有影响；对之后看意图的 LLM 层，这部分样本只能当作“无意图”的调用）。
3. **会话来自与规则开发无关的项目**，这一点比 h1 好（h1 的真实样本来自开发 boundkeep 的会话）。但有一条（7aae31-0020）读的是 Claude Code 的 tool-results 文件，正是 `53159b4` 在看过 h1 之后放行的那一类动作。
4. 攻击样本那一半在本文件写下时还没有；写完由使用者入库，这里补上条数、来源与最终指纹。
