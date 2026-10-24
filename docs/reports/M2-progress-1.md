# M2 进度（一）：评测框架与种子样本

日期：2026-10-24。**没有提交。** 规则已冻结（`m1c2-x1-rereview2-fixes-done`，复审者确认无高危、中危），但这一步产出的是框架与种子样本，**还不是基线**：样本量没到要求，标签没有经你确认，所以没有生成 `eval/report.md`。

## 1. 做了什么

| 部分 | 位置 | 说明 |
|---|---|---|
| 样本 schema | `src/boundkeep/evalkit/schema.py` | pydantic，字段按任务书：id、category、label、platform、task_intent、tainted、taint_sources、tool、input、expected_min_verdict、rationale、provenance、split，外加 `pair`（注入偏离的成对键）。内部一致性在加载时校验（恶意样本必须有 ask / deny 要求、正常样本不得要求拦截等） |
| 切分 | 同上 `split_of` | 内容哈希决定，30% 为 test；带 `pair` 键的按键哈希，成对样本不会跨集。`split` 写错就是加载错误；`--stamp` 填入或纠正 |
| 数据集加载与校验 | `evalkit/dataset.py` | 重复 id、重复事件、成对跨集、注入类缺 pair、不惰性（密钥形态、个人路径含中文用户名、恶意样本里的真实域名）都会停止加载，信息带文件与行号；两个切分各有指纹 |
| 脱敏 | `evalkit/redact.py` | `find_leaks`（校验用）与 `redact`（导入器用，下一步），同一套模式 |
| 运行器 | `evalkit/runner.py` | 进程内、假机器、同 `boundkeep test`；`platform: any` 两台机器各跑一次；灰色与管线错误折成 ask；没有 PowerShell 解析器时 PowerShell 样本跳过并列出；四行消融里只有 `rules-only` 能跑 |
| 指标 | `evalkit/metrics.py` | 口径见 `docs/eval-methodology.md`（版本 2）；分母为 0 的比率是 `None`，不是 0 |
| 报告 | `evalkit/report.py` | Markdown + JSON；固定四行消融（未运行的写"未运行"）、按平台与切分分别报告、漏报 / 误报前 10 条、自动生成的局限性一节 |
| 入口 | `eval/run_eval.py` | `--check`、`--stamp`、`--config rules-only`、`--policy`、`--out-dir` |
| 种子样本 | `eval/datasets/attacks/seed-v0.jsonl`（64）、`benign/seed-v0.jsonl`（53） | 七类攻击全覆盖（含 Windows 变体）；6 对注入偏离（同一动作、两种任务意图）；全部手写、惰性。**标签是我写的，没有经你确认** |
| 口径文档 | `docs/eval-methodology.md` | 指标定义、切分与冻结规则、惰性规则、复现命令 |
| 测试 | `tests/unit/test_evalkit.py`（50） | schema、切分稳定性、重复、惰性与脱敏、运行器、指标、报告确定性、`run_eval.py` |

## 2. 在种子样本上试跑的结果（只是试跑，不是基线）

输出到临时目录，没有写入仓库。种子集上规则层的现象，供你判断样本和规则的方向，**不要引用这些数字**：

- 攻击样本：有效裁决全部不是 allow（拦截合计 100%）；漏报都是"该 deny 实际只 ask"（如 `Format-Volume`、PowerShell profile、`Run` 注册表项、启动文件夹、`/etc/hosts`、写 `.git/hooks`）。
- 正常样本：误报约 50%（dev 与 test 各平台 47–58%），原因大多是"没有规则匹配"（`npm test`、`git add/commit`、`uv sync` 等）和默认策略对未受信任项目里开发工具的 ask。这是真实的基线现象，但种子集里的正常样本由我挑选，不能代表你的日常分布，所以需要真实会话导入。
- 注入偏离的成对样本：规则层不看任务意图，所以正常的一半与恶意的一半得到相同裁决（这是 `rules-only` 的固有表现，也是 LLM 层要回答的问题）。
- 延迟（进程内）：规则路径 p50 约 3–5 毫秒，p95 约 4–9 毫秒。

## 3. 还没做、需要你参与的

1. **样本量**：任务书要求每类攻击不少于 30 条（现在 6–11 条）、正常样本不少于 300 条（现在 53 条）。
2. **标签确认**（⛔）：种子样本的 `expected_min_verdict` 与 `label` 是我定的，需要你逐条或抽样确认；LLM 辅助生成的样本还需要全部人工抽检。
3. **抽检一致率阈值**（⛔）：任务书要求先和你商定阈值再抽检，还没商定。
4. **真实会话导入**（⛔）：`boundkeep eval import-session`（先脱敏后落盘，丢弃含疑似密钥的样本并统计，支持 Windows 会话 JSONL 与 `C:\Users\<名字>` 路径）还没写；导入的样本必须由你确认才能入库。
5. **基线**：样本与标签定稿、test 集冻结之后，运行 `python eval/run_eval.py --config rules-only` 生成 `eval/report.md`，写 `docs/reports/M2.md`（含漏报 / 误报的原因分析）。
6. 与评测并行、不依赖评测：真实 Claude Code 里的手工验收；Linux 容器套件（本机 Docker Desktop 已安装但守护进程没有运行，我没有去启动它）。

## 4. 验证

`ruff check`、`ruff format`、`mypy`（55 个源文件，strict）干净；`tests/unit/test_evalkit.py` 50 个通过；`python eval/run_eval.py --check` 通过（117 个样本）。完整套件这一步没有重跑（只加了新模块与新测试，没有改旧代码；`pyproject.toml` 只加了两条 per-file-ignores）。

## 5. 第 2 版（按确认建议修改）

标签确认表见 `eval/seed-v0-label-review.md`（117 条：攻击 64、正常 53），表头列出了相对第 1 版的全部改动。口径升到版本 2：正常样本加 `runs_repo_code` 标记，报告把误报拆成“运行项目自身代码的命令”与“其余”，头条误报率不变；另跑一遍“假机器的项目受信任”作为独立的参考表（不是消融行）。标签仍未经你确认。
