# M3a 的 X1 审查：规格决定之后的实现（规格修订 7）

> 日期：2026-10-30（全量测试 10-30 22:17–23:29；评测报告记的运行日期是 10-31）。前一份处理记录 `docs/reports/M3a-review-fixes.md`（F3、F4、F5 已修，提交 `1959969`、`4d723c0`）。使用者 2026-10-30 回复"按你的建议执行"：采纳那份报告第 7 节各提案的方案 A，并按第 8 节的建议做（P-F2 先做 hook 实测）。**使用者 2026-10-31 确认后分三次提交：`687f35a` 规格、`55d1af4` 代码，文档与评测生成物在其后一个提交；已推送，包含在标签 `m3a-done` 里。**（2026-11-06 更正：这里原来写的是提交时的状态"未推送，未打标签"。）

## 1. 结论

| 提案 | 结果 | 一句话 |
|---|---|---|
| P-F1（F1） | **已实现** | 读过不可信内容的会话写过的项目带标记；开发工具在**所有**会话里再问（`ask-devtools-after-untrusted-project-write`），直到用户在终端运行 `boundkeep taint clear` |
| P-F6（F6） | **已实现** | 污染窗口只被污染一步改成了 ask 的调用消耗，无害的调用用不掉它；默认 `window` 由 8 改为 3；会话库 schema 1 → 2 自动迁移 |
| P-F2 | **已实测、已实现** | Claude Code 2.1.304 的 hook 里读 MCP 资源的工具叫 `ListMcpResourcesTool`、`ReadMcpResourceTool`、`ReadMcpResourceDirTool`（第三个是实验中发现的）；三个都进了默认与 strict 的 `taint.sources` |
| P-F34 | **规格文字已写** | §7"请求装不下的输入"、§9.2、§10；代码上一轮已实现 |
| F5 | 规格文字澄清 | §9.1：硬期限包括名字解析 |

- 规格先改（`PROJECT_SPEC.md` 修订 7），再改代码。
- 上一轮留下的三个 strict xfail 复现（F1、F6、P-F2）现在都通过，已去掉标记。
- 评测重新生成（规则改了）：所有指标、`rules+taint` 增量与敏感度表**与上一版逐项相同**，只有策略哈希变了。
- 全量测试结果见第 5.1 节。

## 2. 交付物

| 文件 | 内容 |
|---|---|
| `PROJECT_SPEC.md` | 修订 7：§7（项目上的标记、窗口的计数、请求装不下的输入）、§8（默认来源、`window: 3`、新匹配字段）、§9.1、§9.2、§10、§12、§13，开头的修订说明与当前进度 |
| `src/boundkeep/session/marks.py`（新） | `written_locations`（从动作算出写到的位置）、`marked`（项目是否带标记）、`location_key` / `within`（键的比较，与 `project_trusted` 同一种读法） |
| `src/boundkeep/session/store.py` | schema 2：列 `calls_since_taint` 改名 `taint_asks`，新表 `project_marks`；schema 1 原地迁移；`taint_asked`、`mark_written`（上限 1000 个位置，超出记一个 `*`）、`marks`、`clear_marks`；`tool_call` / `facts` 带上标记；普通调用不再计数 |
| `src/boundkeep/session/facts.py`、`__init__.py` | `SessionFacts.taint_asks`、`marks`、`marks_known`；`UNKNOWN` 的标记未知 |
| `src/boundkeep/daemon/pipeline.py` | 读过不可信内容的会话里，判决之前打项目标记；判决之后，污染一步改成了 ask（管线自己的，或 §9.5 的 `tainted-sensitive`）且是 enforce 时用掉一次窗口（`used_taint_window`）；审计记录的 `taint` 改为 `taint_asks`，另记 `marked_places` / `marks: unknown` |
| `src/boundkeep/policy/schema.py`、`matcher.py` | 匹配字段 `project_written_after_untrusted`（只能用于 deny / ask，加载时检查）；默认来源与 `window`；策略测试的 `project_marked` |
| `src/boundkeep/policycli.py` | `boundkeep test` 认 `project_marked: true`；`explain` 用的假存储补上新方法 |
| `src/boundkeep/taintcmd.py`（新）、`cli.py` | `boundkeep taint list`、`boundkeep taint clear [--project-dir DIR \| --all]`；`clear` 拒绝在 Claude Code 启动的进程里或没有真实控制台时运行（复用 `trust` 的两道检查） |
| `src/boundkeep/doctor.py` | 检查项 `project-marks`：列出标记，提示怎样解除 |
| `policies/default.yaml`、`policies/strict.yaml` | 新 ask 规则 `ask-devtools-after-untrusted-project-write`；`deny-boundkeep-state-commands` 加 `taint`；来源与 `window`；`tests:` 新增 10 条（default）与 4 条（strict） |
| `experiments/mcp_resource_server.py`（新） | P-F2 实验用的最小 MCP 服务（带一个资源，仅标准库） |
| `tests/unit/test_m3a_x1_decisions.py`（新） | 42 个用例：标记的打法与匹配、跨会话、跨项目、清理与重启之后仍在、上限、读不出时命中、CLI 的两道检查与清除、doctor、窗口只被询问消耗、`audit-only` 不计数、来源让窗口重新开始、schema 1 迁移 |
| `tests/unit/test_m3a_x1_fixes.py` | 去掉三个 strict xfail 标记 |
| `tests/unit/test_m3a_session_store.py`、`test_m3a_pipeline.py`、`test_m3a_daemon.py`、`test_m3a_schema_cli.py`、`test_policy.py`、`test_m1c2_trusted_projects.py`、`test_m1c2_trusted_policy.py` | 按新的计数方式、默认值与新字段改写（见第 4 节第 7 条） |
| `docs/hook-behavior.md` | 新节"MCP 资源工具"：实验做法与结果 |
| `docs/threat-model.md`、`privacy.md`、`policy-reference.md`、`architecture.md`、`eval-methodology.md` | 同步；`privacy.md` 写明会话库里多了项目路径 |
| `eval/report.md`、`eval/results/*.json` | 重新生成（第 5.2 节） |
| `CLAUDE.md` | 当前状态与下一步 |

## 3. 验收标准逐条对照

| 标准 | 结果 | 证据 |
|---|---|---|
| 先改规格，再实现 | 做到 | 修订 7 在代码之前写好；代码与它逐条对应（第 2 节） |
| 每条有测试，原来的复现转正 | 做到 | 三个 strict xfail 改成普通测试后通过；新文件 42 个用例全部通过 |
| P-F2 先做 hook 实测 | 做到 | 两次 `claude -p`（haiku），共约 0.08 美元；结果在 `docs/hook-behavior.md` |
| `uv run ruff check .` | 通过 | All checks passed! |
| `uv run ruff format --check .` | **1 个文件不合格式，不是本轮的** | 仍是未跟踪的 `docs/reviews/M3a-security-review.md`；其余 271 个文件已格式化 |
| `uv run mypy` | 通过 | Success: no issues found in 75 source files |
| `boundkeep test` default / strict | 通过 | **1138 / 0**，**334 / 0**（上一轮 1120、326，多出的是新的 `tests:` 条目） |
| 规则改了，重新生成评测 | 做到 | 第 5.2 节 |
| 全量 `uv run pytest -q` | 见第 5.1 节 | |

## 4. 与提案的偏差

1. **`trust remove` 不清标记**（P-F1 原文说"`trust remove` 同时清掉"）：清标记是放宽，而 `trust remove` 不要求真实控制台；只让 `taint clear`（两道检查）做这件事。
2. **写到项目之外的路径也打标记**（原文只说"对项目内路径的写"）：确定在项目之外的写记路径本身，所以写进**别的项目**的测试文件，在那个项目里同样生效。代价很小（这样的写在默认策略里本来就要问）。
3. **访问方式 `unknown` 的路径也算写**（原文说"带写路径的 shell 命令"）：表里没有的程序认不出读写，按可能写处理，安全方向。
4. **`taint list` 对 agent 也拒绝**：规则语言只看子命令，和 `trust list` 一样；用户在终端或 `doctor` 里看。
5. **窗口只在 enforce 下计数**：`audit-only` 不问任何人，计数会让窗口在没人被问的情况下过去。规格修订 7 已写明。
6. **schema 1 迁移把计数清零**：旧的计数是"调用次数"，说明不了问过几次；清零之后，读过不可信内容的旧会话重新进入窗口（安全方向）。
7. **改写的旧测试**：`test_m3a_session_store.py` 里断言"第 9 次调用之后不再污染"的用例改成"问过 3 次之后不再污染"，并发测试改为并行计 `taint_asked`；`test_m3a_pipeline.py` 的 `test_padding_calls_do_not_wait_out_the_sticky_bit` 原来断言 25 次读文件之后 `tainted` 为假，现在为真（这正是 F6 的修复）；`test_m1c2_trusted_projects.py` 的匹配字段表补上新字段；`test_policy.py` 的默认来源改为六个；`test_m1c2_trusted_policy.py` 断言的被拒子命令集合补上 `taint`（全量运行才发现）。都不是为了让测试通过而放宽：新行为更严或只是新增。
8. **策略测试多了 `project_marked`**：CLAUDE.md 要求新判决路径有 `tests:` 回归用例，而原有的 `tainted` 表达不了"别的会话写过这个项目"。
9. **多了一个来源 `ReadMcpResourceDirTool`**：提案只列了两个，实验里的工具清单有第三个，hook 里也触发。
10. **已有安装的升级**：`~/.boundkeep/policy.yaml` 是 `init` 当时写的，仍是旧的来源与 `window: 8`（计数方式按修订 7，所以是"问 8 次"）；要新默认值就编辑它或 `boundkeep init --reset-policy`。PostToolUse 的 matcher 要重新 `init` 才包含新来源；PreToolUse 的 matcher 是 `*`，新来源在那里立即打标记。`docs/policy-reference.md` 已写。

## 5. 度量

### 5.1 测试

- 新测试 `tests/unit/test_m3a_x1_decisions.py`：**42 passed**。
- 受影响面的分组运行（全部 `tests/unit/test_m3a_*.py`、`test_policy.py`、`test_install.py`、`test_doctor_rules.py`、`test_m1c2_trusted_projects.py`、`tests/contract`），改完旧测试之后全部通过；改之前的 6 个失败都是第 4 节第 7 条说的旧断言。
- 全量 `uv run pytest -q`（所有改动之后，22:17–23:29）：第一遍 26699 通过、169 跳过、2 失败，用时 1:11:45。两个失败是 `test_m1c2_trusted_policy.py::test_trust_is_a_denied_boundkeep_subcommand[default|strict]`：它把 `deny-boundkeep-state-commands` 的子命令集合写死成不含 `taint`，而这次是有意加上 `taint`（第 4 节第 7 条）。把断言改成含 `taint` 之后，单独重跑这个文件 1894 通过、0 失败；没有为此重跑全量。跳过的都是需要 POSIX、bash、符号链接权限或 `--live` 的用例，和上一轮相同。

### 5.2 评测

规则改了（新 ask 规则、`deny-boundkeep-state-commands` 加 `taint`、来源与窗口），所以按 `docs/reports/M3a.md` 第 5.3 节重新生成：`uv run python eval/run_eval.py --config rules+taint --test-contaminated`（不打开任何留出批次）。

- 数据集指纹不变：dev `34a1cd18e50712e5`，test `5f2bab54704e0132`（留出批次 h1、h2 只算指纹，未打开）。
- 新策略 sha256 `9251f93327bce504…`（原 `0e924b87c5432d66…`）。
- `rules-only.json` 与 `rules+taint.json` 去掉延迟与日期字段之后，与上一版**只差 `policy_sha256`**：所有单元格、`taint_delta`、`taint_sensitivity` 相同。原因：新 ask 规则只在项目带标记时命中，评测不模拟项目标记（单个样本表达不了，规格 §12 已写）；新来源没有出现在样本里；窗口的计数方式对单次调用的样本没有影响。
- 所以 `docs/reports/M3a.md` 第 5.3 节的表仍然成立。报告里的运行日期是 2026-10-31（过了午夜）。

### 5.3 代价

- **P-F1**：只对用了 `trusted_projects` 或配置了 LLM 后端的用户有影响（默认两者都没有时，开发工具本来就是灰色、要问）。一个读过网页或 MCP 内容的会话只要往项目里写过东西，之后在这个项目里运行 `pytest`、`ruff`、`mypy` 等都要问，换会话也一样，直到用户在终端 `boundkeep taint clear`。ask 的理由在 Claude Code 的确认框里不显示（M0 的实测），所以用户要从 `doctor` 或 `boundkeep taint list` 知道为什么。
- **P-F6**：只在配置了 LLM 后端时有实际影响。读过不可信内容之后，模型放行的前 3 个敏感动作会问（原来是来源之后的 8 次调用之内，无论那是什么调用）；`audit-only` 不变。
- **P-F2**：会话读过 MCP 资源之后也算读过不可信内容（粘性规则与窗口都生效）。

## 6. 已知问题与局限

- **项目标记只认得出写路径的写**：`python gen.py`、`make` 之类运行代码的命令，以及没有路径参数就写文件的 MCP 工具，写下的东西不打标记。这些调用在被污染的会话里本身是灰色。
- **没审查就回答的调用不打项目标记**：守护进程繁忙或超时时的回答、策略文件坏掉时的 ask。来源调用在那时仍打污染标记（M3a 的行为不变）。
- **标记按路径的键比较**：写进别的项目时记的是写入时的路径（不解析链接）；从另一个链接进入同一个目录的会话可能对不上。项目目录本身记两种形式（键入的与解析链接之后的）。
- **`doctor` 打开 schema 1 的库会迁移它**：如果此时还有旧版守护进程开着这个库，它之后的读写会失败，按"状态未知"处理（失败即关闭），重启守护进程即可。
- **VS Code 扩展里没有测资源工具的名字**：同一个内置二进制，预计相同，没有实测记录。
- 每个 PreToolUse 读一次全部标记（最多 1001 行）；没有测大量标记下的延迟。

## 7. 规格变更提案

无新的提案。

## 8. 需要你决定的事项

1. **提交**（已按下列三组完成，见开头）：建议三次，逐个列文件，不推送、不打标签。
   - 规格：`PROJECT_SPEC.md`。
   - 代码：`src/boundkeep/session/marks.py`、`src/boundkeep/session/store.py`、`src/boundkeep/session/facts.py`、`src/boundkeep/session/__init__.py`、`src/boundkeep/daemon/pipeline.py`、`src/boundkeep/policy/schema.py`、`src/boundkeep/policy/matcher.py`、`src/boundkeep/policycli.py`、`src/boundkeep/taintcmd.py`、`src/boundkeep/cli.py`、`src/boundkeep/doctor.py`、`policies/default.yaml`、`policies/strict.yaml`、`experiments/mcp_resource_server.py`、`tests/unit/test_m3a_x1_decisions.py`、`tests/unit/test_m3a_x1_fixes.py`、`tests/unit/test_m3a_session_store.py`、`tests/unit/test_m3a_pipeline.py`、`tests/unit/test_m3a_daemon.py`、`tests/unit/test_m3a_schema_cli.py`、`tests/unit/test_policy.py`、`tests/unit/test_m1c2_trusted_projects.py`、`tests/unit/test_m1c2_trusted_policy.py`。
   - 文档与生成物：`docs/reports/M3a-review-fixes-2.md`、`docs/hook-behavior.md`、`docs/threat-model.md`、`docs/privacy.md`、`docs/policy-reference.md`、`docs/architecture.md`、`docs/eval-methodology.md`、`CLAUDE.md`、`eval/report.md`、`eval/results/rules-only.json`、`eval/results/rules+taint.json`。
2. **定向 X1 复审**：F1、F6 的实现（标记的打法与匹配、`taint clear` 的两道检查、窗口的计数与迁移）以及上一轮的 F3–F5，建议由独立的会话做，同时补上 F7–F13 拿不到的部分。复审之后再决定是否打 `m3a-done`。
3. **`trusted_projects` 是否推荐**：建议等复审之后再议。
4. **`docs/reviews/M3a-security-review.md`**：仍未跟踪、未动，由你决定。
5. 如果你自己的机器上装着 boundkeep：`~/.boundkeep/policy.yaml` 要编辑或 `init --reset-policy` 才有新的来源与 `window`（第 4 节第 10 条）。

## 9. 进入下一步的前置条件

- 提交（已完成，2026-10-31）；
- 定向复审之后高危、中危清零，再由你决定是否打 `m3a-done`；
- M3b 要在复审之后、由你自备密钥。
