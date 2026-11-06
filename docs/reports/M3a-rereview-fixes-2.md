# 规格修订 8 的实现：P-R2、P-R3、P-R5、P-R6、P-R7、P-R9 验收报告

> 日期：2026-10-31。依据：M3a 修复的定向复审（`docs/reviews/M3a-rereview.md`）与上一轮的提案（`docs/reports/M3a-rereview-fixes.md` 第 7 节）。使用者先回复"好，按这个方案"（先做 hook 实测，再写规格修订 8），看过草案之后回复"Yes, as drafted"。使用者确认之后已提交到 `main`（2026-10-31，"Yes, commit now"）：`dc9b268` 规格、`4a6c07d` 代码与测试，本报告与其他文档在其后一个提交。**已推送，包含在标签 `m3a-done` 里**（2026-11-06 更正：这里原来写的是提交时的状态"未推送、未打标签"）。

## 1. 结论

**有条件通过**：六条提案都已按修订 8 实现，偶发失败的测试也一并修了。第一批的新测试在旧代码上跑过，先失败、后通过；第二批没有在旧代码上跑过（见第 4 节第 6 条）。规则、策略与评测数字都没变。复审的中危 R-2、R-3、R-5 都已处理，低危 R-6、R-7、R-9 也处理了。R-8 仍未处理。下一步是在独立会话里做一次定向复审，之后再决定 `trusted_projects` 与 `m3a-done`。

| 提案（复审发现） | 处理 | 改了什么 |
|---|---|---|
| P-R5（R-5，中）经 shell 读进来的外部内容不是来源 | **已实现** | `session/sources.py`：带网络的 shell 调用是来源（`shell-network:<程序>`），只搬代码的子命令除外；不是 deny 时，在判决之后记 |
| P-R6（R-6，低）看不到写路径的写不打标记 | **已实现** | 以下几类即使看不到写路径，也记项目目录：会运行代码且规则没放行的动作、写文件的 MCP 工具、会改工作区的 git 子命令。来源调用自己的写也记 |
| P-R7（R-7，低）写到项目外只记文件 | **已实现（备选）** | 开发工具的配置文件写到项目之外时，记它所在的目录 |
| P-R2（R-2，中）配置 LLM 时标记不进 LLM 路径 | **已实现** | 带标记项目里的 `exec` 灰色调用不送审，`decided_by: gray-marked-project` |
| P-R3（R-3，中）被拒或没人看见的询问也消耗窗口 | **已实现（A）** | 窗口按 `tool_use_id` 对上 PostToolUse 才计数；会话库 schema 3（`pending_asks`）；配置了 LLM 时 PostToolUse 的 matcher 为 `*` |
| P-R9（R-9，低）fork 丢粘性位与窗口 | **已实现** | `init` 注册 SessionStart（第五个 hook）。`source` 不是 `startup` / `clear` 的会话，如果库里没有它，就按读过不可信内容开始；新会话记一行干净的状态 |
| 偶发失败的测试（上一轮第 6 节） | **已修** | `normalize_event` 在调用时才读 `TIME_BUDGET_S`；测试同时放宽它 |
| R-8（低）标记上限可被打满 | 未处理 | 上一轮已建议暂不处理 |

## 2. 交付物

| 文件 | 说明 |
|---|---|
| `PROJECT_SPEC.md` | 修订 8：§5、§7、§8、§10、§12；含实现时补的三处（第 4 节第 1、2、4 条） |
| `src/boundkeep/session/sources.py`（新） | `network_source`：shell 调用里第一个读远端文字的网络动作。`moves_code` 的例外名单包括 git 的 `clone|fetch|pull|push`，以及各包管理器的安装、同步、构建、运行类子命令 |
| `src/boundkeep/normalize/mcpnames.py`（新） | MCP 工具名的读写动词表与 `mcp_access`，从 `event.py` 搬过来；`session.marks` 要用它，又不能导入 `event.py`（会和策略包循环导入） |
| `src/boundkeep/session/marks.py` | `hidden_write`；`written_locations` 收每个动作自己的判决；开发工具配置文件名 `TOOL_CONFIG_NAMES`，写到项目外时记所在目录 |
| `src/boundkeep/session/store.py` | 改动如下： |
| | • schema 3，新增 `pending_asks` 表，从 1、2 迁移 |
| | • `taint_asked(sid, tool_use_id)` 只记下询问；`tool_result(..., tool_use_id=)` 对上之后计数 |
| | • 新增 `source_seen`、`session_start` |
| | • 来源调用会清掉待确认的询问；清理时一并删掉 |
| `src/boundkeep/daemon/pipeline.py` | 改动如下： |
| | • P-R5 与 P-R6 的打标记：来源调用按之后的状态打标记 |
| | • 判决之后调 `source_seen` |
| | • `runs_in_marked_project`，实现 P-R2 |
| | • 处理 PostToolUse 的 `tool_use_id`，以及 SessionStart 事件 |
| `src/boundkeep/daemon/server.py` | 没有审查就回答的 shell 调用记作来源 `shell-unreviewed`（第 4 节第 4 条） |
| `src/boundkeep/protocol.py`、`ownhook.py`、`hook_main.py`、`hook_client.py` | 新事件 `session`；`ownhook.BASE_EVENTS` 与 `required_events`；ConfigChange 的检查只对写明装过 SessionStart 的安装记录要求它；SessionStart 失败时静默 |
| `src/boundkeep/install.py`、`cli.py`、`policy/loader.py`、`policy/__init__.py` | 改动如下： |
| | • SessionStart 的条目：没有 matcher，超时 10 秒（最少 6 秒） |
| | • 安装记录多一个 `events` 字段 |
| | • 自检多了 `session` 的样例 |
| | • 新函数 `post_matcher_for`：有 LLM 后端时返回 `*` |
| `src/boundkeep/doctor.py` | 缺 SessionStart 时 WARN（缺其余四个仍是 FAIL）；配置了 LLM 而 PostToolUse 的 matcher 不是 `*` 时 WARN |
| `src/boundkeep/normalize/event.py` | 用 `mcpnames.mcp_access`；`budget_s` 默认 None，在调用时读 `TIME_BUDGET_S` |
| `src/boundkeep/policycli.py` | `explain` 的固定会话补上新的接口方法 |
| `tests/unit/test_m3a_rev8_sources_marks.py`（新） | 82 个用例，覆盖 P-R5（含 9 个 PowerShell 写法，只在 Windows 上运行）、P-R6、P-R7 |
| `tests/unit/test_m3a_rev8_window_fork.py`（新） | 38 个用例：P-R2、P-R3、P-R9，以及 install、doctor、hook 客户端 |
| `tests/unit/test_m3a_session_store.py`、`test_m3a_x1_decisions.py` | 窗口测试改成"询问 → 对应的 PostToolUse"；新增 `tool_use_id` 不可用时不记 |
| `tests/unit/test_install.py`、`test_hook_client.py`、`test_review2_install_cli.py`、`tests/e2e/test_cli_flow.py`、`test_cli_hardening.py`、`tests/golden/settings/*.after.json` | hook 由四个变成五个；golden 文件用代码重新生成，diff 只多出 SessionStart 那一组 |
| `tests/unit/test_review3_core_lexical.py` | 偶发失败的修法 |
| `docs/hook-behavior.md`、`experiments/`（`lab_setup.py --profile rr`、`run_cli_probe.py --permission-prompts`、新 `mcp_permission_server.py`、`README.md`） | 两个 hook 实测及其复现方法 |
| `docs/threat-model.md`、`docs/policy-reference.md`、`docs/privacy.md`、`docs/architecture.md`、`CLAUDE.md` | 按修订 8 更新 |
| `docs/reports/M3a-rereview-fixes-2.md`（新） | 本报告 |

## 3. 验收标准逐条对照

| 标准 | 结果 | 证据 |
|---|---|---|
| 先有失败的复现（第一批） | 通过 | 用一个总说"不是来源"的桩 `network_source` 跑新文件：**37 失败、36 通过**；通过的都是"不该变"的对照：只搬代码、读与查看、干净会话不打标记 |
| P-R5 | 通过 | 下面两组都有逐条测试，各 10 条与 22 条： |
| | | • 算来源的：`gh issue view`、`gh pr view --comments`、`gh api`、`curl`、`wget -qO-`、`npm view`、`ssh 主机 命令`、`git ls-remote`、`cargo search`、`http GET` |
| | | • 不算来源的：`git pull|fetch|clone|push`、`pip|pip3|python -m pip install`、`uv sync`、`uv pip install`、`npm install|ci`、`yarn`、`pnpm add`、`npx`、`cargo build|test`、`go test`、`go mod download`、`poetry install`、`brew|apt-get|conda install` |
| | | • 受信任项目里批准过 `gh issue view` 之后，`pytest -q` 被 `ask-devtools-after-untrusted-content` 问；`git pull` 之后不问 |
| | | • 被规则 deny、被 LLM deny 的调用不算来源；`audit-only` 下算 |
| | | • 来源调用自己按之前的状态判（记录里 `read_untrusted: false`） |
| | | • `curl -o tests/test_x.py` 给项目打标记 |
| P-R6 | 通过 | 被污染的会话里，下面 15 种写法都把项目目录记成标记，另一个会话的 `pytest` 因此被问： |
| | | • git：`stash pop`、`stash apply`、`checkout`、`switch`、`apply`、`am`、`merge`、`pull`、`reset --hard`、`cherry-pick`、`rebase` |
| | | • 运行代码：`python gen.py`、`python -c "open(...)"`、`make generate` |
| | | • 相对路径的 MCP 写 |
| | | 对照不打标记：`git status`、`git stash list`、`git log`、`ls`、`cat`、`Read`、MCP 读；干净会话也不打 |
| | | 会话里第一个来源调用（带项目内路径的 MCP 写）也给项目打标记 |
| P-R7 | 通过 | `~/pytest.ini`、`~/.pylintrc`、`~/conftest.py`、`~/pyproject.toml` 都记主目录，另一个会话的 `pytest` 被问；兄弟项目的 `conftest.py` 只记那个项目，`pytest` 不问；`~/notes.txt`、`~/.config/mypy/config` 仍只记文件，`pytest` 不问 |
| P-R2 | 通过 | 用永远 allow 的假后端： |
| | | • 带标记的项目里，`npm test`、`make test`、`python -m unittest`、`tox` 都不送审（后端零次请求），`decided_by: gray-marked-project`，理由提到 `taint clear` |
| | | • 不带标记的项目，模型照常判 |
| | | • 标记读不出（状态库不可用）时同样不送审 |
| | | • 没有 LLM 时没有变化（`decided_by: gray`） |
| | | • P-R6 与 P-R2 合起来的效果见第 6 节第 1 条 |
| P-R3 | 通过 | • 询问之后计数是 0，对应的 PostToolUse 到了才变成 1；同一个 id 的第二次 PostToolUse 不再加 |
| | | • 拒绝 10 次（没有 PostToolUse）之后计数仍是 0，第 11 次仍然问 |
| | | • 3 次"批准并运行"之后，模型的 allow 成立，计数是 3 |
| | | • 别的调用的 id、别的会话的同一个 id、空 id 都不计数 |
| | | • 新的来源调用清掉待确认的询问 |
| | | • `audit-only` 不记 |
| | | • 待确认的询问每个会话最多 64 个，最旧的被丢掉 |
| | | • 清理时删掉已删会话的待确认询问 |
| | | • schema 2 的库迁移之后保留原计数，并能用新表 |
| | | • `post_matcher_for`：有 LLM 时是 `*`，没有时是来源名单；配置了 LLM 而 matcher 是来源名单时 `doctor` 给 WARN |
| P-R9 | 通过 | • `source` 为 `fork`、`resume`、`compact`、`teleport`、缺失、数字 7、而库里没有这个会话时：读过不可信内容、被污染，来源名 `inherited:…`，`pytest` 被问 |
| | | • `startup`、`clear`：干净，`pytest` 不问 |
| | | • 已知的干净会话之后再 resume、compact：仍然干净 |
| | | • 不可用的会话 id 什么都不写；这个事件没有决定 |
| | | • `init` 写的 SessionStart 没有 matcher；安装记录会带上 `events` |
| | | • ConfigChange 的检查：旧记录（没有 `events`）缺 SessionStart 不算被改；新记录缺了才算；记录不能免掉基础的四个 hook |
| | | • hook 客户端：SessionStart 失败时静默，守护进程回答 deny 也静默 |
| `ruff check` / `ruff format --check` / `mypy` | 通过 | `ruff check .` 通过；`ruff format --check .` 只标出未跟踪、没动的 `docs/reviews/M3a-security-review.md`；`mypy src` 77 个文件没有问题 |
| `boundkeep test` | 通过 | default **1138 / 0**，strict **334 / 0**（策略没改） |
| 评测不变 | 通过 | 重跑到 scratchpad（`run_eval.py --config rules+taint --test-contaminated --out-dir <scratchpad>`，不开留出批次）：两个结果文件去掉日期与延迟之后，与已提交的逐字段相同 |

## 4. 与计划的偏差

1. **P-R9：新会话也要记一行。** 实现时发现，没调用过来源的会话在库里本来没有记录，只有来源调用和任务意图会建行。照草案写，每一次 resume 都会把干净会话当成不认识的会话，长会话里常见的自动压缩也一样。现在 `startup` 和 `clear` 会记一行干净的状态。代价是升级之前开始的会话：第一次 resume 或 compact 时，会按读过不可信内容开始。规格 §7 已补一句。
2. **P-R6："规则没放行的"的读法。** 草案原文是"灰色的、带 `exec` 或 `file_write` 标签的动作"，第一版实现照字面做，结果写到项目之外的 `Write` 也把项目标上了：`Write` 带 `file_write`，判决是 ask。现在的读法是：
   - `exec` 的动作，只要规则没有放行就记，因为会运行代码，写到哪里都可能；
   - `file_write` 的动作，只在没有可写路径时才记。
   
   规格 §7 的文字已按这个改。
3. **P-R5 的例外名单比草案列的长。** 草案写的是"安装与同步类子命令……等"。名单里还有 `cargo build|test|run`、`go build|test|run`、`uv run`、`npx` / `npm exec`，因为 normalize 层给它们设 `network`，只是表示"可能下载依赖"。不放进名单的话，JS 和 Rust 项目里几乎每个会话都会被污染。名单之外的一律算来源。
4. **没有审查就回答的 shell 调用也记作来源（`shell-unreviewed`）。** 草案没提到这一点。守护进程繁忙或超时时，没人看过这条命令会不会读网页，按失败即关闭处理，跟"没审查的来源调用照样打标记"同一个思路。规格 §7 已补一句。
5. **`mcp_access` 搬进了新模块 `normalize/mcpnames.py`。** `session.marks` 要用它，而 `marks` 是被策略匹配器导入的；从 `event.py` 直接导入会和策略包形成循环导入。行为没变。
6. **第二批的测试没有在旧代码上跑过。** P-R2、P-R3、P-R9 的测试是在改代码之前写的，但测试要导入的东西旧代码里还没有：`post_matcher_for`、`EVENT_SESSION`、`MAX_PENDING_ASKS`。所以没有"先红"的记录。第一批有，见第 3 节。
7. **hook 实测花了约 0.23 美元。** 我原先估计"几美分"。每次 `claude -p` 约 5 到 6 美分，因为工具清单很长。PostToolUse 的延迟没有另测，用的是已有数据的估计，见第 5 节。
8. **`doctor` 对缺 SessionStart 给 WARN，不给 FAIL。** 缺了它闸门照样工作，只是 fork 出来的会话会从干净状态开始。缺基础的四个 hook 仍是 FAIL。
9. **改了一个已有的 hook 客户端测试。** SessionStart 现在是认识的事件了，"未注册的事件名"那组用例改用 `SessionEnd`。另加一个用例：`pre`、`config`、`post` 的条目收到 SessionStart 时，什么都不输出。原有规则是"登记不一致时按事件自己的类型降级"，而 SessionStart 没有工具调用可以拦。

## 5. 度量

- 新测试：`test_m3a_rev8_sources_marks.py` 82 个，`test_m3a_rev8_window_fork.py` 38 个，共 120 个，全部通过。9 个 PowerShell 用例是全量开始之后加的，单独跑过，见第 5.1 节。
- 分组运行：
  - 改完第一批之后，M3a 与 MCP 相关的 14 个文件：895 通过。
  - 改完第二批、更新完旧测试之后，M3a 的 8 个文件：349 通过。
  - `test_install.py`：304 通过、1 跳过。
  - hook 客户端加 e2e CLI：177 通过。
  - 更早一次跑的是第二批受影响的单元测试加全部 e2e：3748 通过、3 跳过、3 失败。3 个失败都是旧测试还没跟上第五个 hook（第 4 节第 9 条和 `test_cli_*`），已改，改后单独重跑通过。
- 全量：见第 5.1 节。
- 评测：与已提交的相同（第 3 节）。
- hook 实测（Claude Code 2.1.304，`claude -p`，haiku）：4 次运行，约 0.23 美元，结果写在 `docs/hook-behavior.md`"M3a 复审的实测"。
- PostToolUse 挂 `*` 的代价：每次工具调用多一个 hook 进程，估计多约 45 到 50 ms。依据是 M0a E10（每个 hook 事件约 45 ms）和 M3a 的 `bench_hook`（守护进程在线时 p50 48.6 ms）。只在配置了 LLM 后端时才挂。真实 Claude Code 里没有另测。

### 5.1 全量

- 全量 `pytest -q`（10-31 07:11–08:22，用时 1:11:27）：**26860 通过、169 跳过、1 失败**。
- 失败的是 `tests/unit/test_review2_install_cli.py::test_emit_allow_on_in_the_policy_is_pinned_into_every_hook`：旧测试把 hook 数钉在 4 个（`assert 5 == 4`），和第 4 节第 9 条那几处是同一类。断言已改成 5 个、子命令加上 `session`。改后这个文件 45 个用例单独重跑都通过。
- 9 个 PowerShell 用例是全量开始之后加的，不在这次全量里。它们与 `test_m3a_rev8_sources_marks.py` 一起单独重跑：82 个都通过。
- 上一轮偶发失败的 `test_review3_core_lexical.py::test_a_deny_after_1400_distinct_commands_is_still_a_deny` 这次通过。

## 6. 已知问题与局限

1. **P-R6 与 P-R2 合起来的效果，规格里两条各自写了，这里单独说明。** 配置了 LLM 后端时：
   - 读过不可信内容的会话，第一次运行会运行代码的灰色命令（`make`、`npm test`），项目就被标记；
   - 从那以后，这个项目里所有会运行代码的灰色命令都不送审、直接问，不管哪个会话，直到用户运行 `taint clear`；
   - 窗口对这类命令不再起作用，只对其余敏感动作（写文件、网络外发）还有意义。
   
   这是安全的方向，但用了 LLM 的用户在这类项目里会被问得多。有测试固定这个行为：`test_after_a_run_step_the_project_keeps_its_code_from_the_model`。
2. **从干净会话 fork 出来的会话也被当作读过不可信内容。** 原因是 SessionStart 不带父会话的 id。开发工具在 fork 里再问，fork 里的写会给项目打标记。
3. **SessionStart 失败时放行。** 守护进程在会话开始时不在，或那次写库失败，fork 出来的会话就从干净状态开始。`doctor` 只能检查它是否注册了。
4. **升级之后要重新运行 `boundkeep init`。** 不重新运行时：
   - 没有 SessionStart：fork 从干净状态开始，`doctor` 给 WARN；
   - 配置了 LLM 而 PostToolUse 的 matcher 不是 `*`：窗口不被消耗，会话一直被污染，多问，`doctor` 给 WARN。
   
   升级之前开始的会话，第一次 resume 或 compact 时按读过不可信内容开始。
5. **以下都没在真实 Claude Code 里跑过。** 新的 SessionStart 条目、`*` matcher、待确认询问的完整链路，都只有单元测试和 e2e（假的 Claude Code 事件）。真实 Claude Code 只验证过事件形状：用的是观察用的 hook，不是 boundkeep 自己。桌面应用与 VS Code 扩展里的 fork、`--continue --fork-session`、2.1.304 上 `/compact` 的 `source`、agent 团队的队友，也都未测。
6. **项目标记的局限：**
   - 规则直接放行、又不带写路径的命令写下的东西不打标记；
   - 用户级的配置位置（`~/.config/...`、`%APPDATA%`）只记文件本身；
   - 可编辑安装的兄弟项目只记文件本身。
   
   这些写在会话 A 里本身要问。
7. **P-R5 被接受的残余：** 安装脚本与 git 的输出里也可能有远端写的文字；`git fetch` 之后用 `git log -p origin/...` 读到的内容不算来源。
8. **R-8 仍未处理。** 一次调用写 1001 个项目外路径，会把标记换成"所有位置"。

## 7. 规格变更提案

无新提案。第 4 节第 1、2、4 条是实现时发现的，已直接写进修订 8 的文字，请在看本报告时一并确认。

## 8. 需要你决定的事项

1. **提交**（已完成：`dc9b268`、`4a6c07d`，文档在其后一个提交），分三次，逐个列文件，不推送、不打标签：
   - 规格：`PROJECT_SPEC.md`。
   - 代码：
     - 源码：`src/boundkeep/cli.py`、`daemon/pipeline.py`、`daemon/server.py`、`doctor.py`、`hook_client.py`、`hook_main.py`、`install.py`、`normalize/event.py`、`normalize/mcpnames.py`（新）、`ownhook.py`、`policy/__init__.py`、`policy/loader.py`、`policycli.py`、`protocol.py`、`session/marks.py`、`session/sources.py`（新）、`session/store.py`。
     - 测试：`tests/unit/test_m3a_rev8_sources_marks.py`（新）、`test_m3a_rev8_window_fork.py`（新）、`test_m3a_session_store.py`、`test_m3a_x1_decisions.py`、`test_install.py`、`test_hook_client.py`、`test_review2_install_cli.py`、`test_review3_core_lexical.py`、`tests/e2e/test_cli_flow.py`、`test_cli_hardening.py`、`tests/golden/settings/` 下的 8 个 `*.after.json`。
   - 文档与实验：`docs/reports/M3a-rereview-fixes-2.md`（新）、`docs/hook-behavior.md`、`docs/threat-model.md`、`docs/policy-reference.md`、`docs/privacy.md`、`docs/architecture.md`、`CLAUDE.md`、`experiments/README.md`、`experiments/lab_setup.py`、`experiments/run_cli_probe.py`、`experiments/mcp_permission_server.py`（新）。
   - 复审报告 `docs/reviews/M3a-rereview.md`：建议随文档一起提交，它是这两轮修复的依据。`docs/reviews/M3a-security-review.md` 仍由你决定。
2. **定向复审**：按方案第四步，在独立会话里复审修订 8 的实现，重点看第 4 节第 1 到 4 条与第 6 节第 1 到 4 条。
3. **真实 Claude Code 里的冒烟**（可选）：用 `scripts/smoke_claude.py` 那种真 boundkeep 的方式，各跑一次 fork 与"询问被批准"，每次约 0.1 美元。
4. **R-8**：仍建议暂不处理。

## 9. 进入下一步的前置条件

- 提交：已完成（第 8 节第 1 条）。
- 定向复审没有新的高危与中危之后，再决定 `trusted_projects` 是否改为推荐设置，以及是否打 `m3a-done`。
