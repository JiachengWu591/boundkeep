# M3a X1 定向复审的处理：R-1、R-4、R-10 验收报告

> 日期：2026-10-31。复审报告 `docs/reviews/M3a-rereview.md`（独立会话写，未跟踪）：没有高危，中危 R-1 到 R-5，低危 R-6 到 R-10，信息 3 条；F1、F6 部分修，F2–F5 已修。使用者回复"好，先修这三条"：在这里修不需要改规格的 R-1、R-4、R-10，其余写成规格变更提案（第 7 节），等你决定。**使用者 2026-10-31 确认后分两次提交：`f8b7a71` 代码，文档在其后一个提交；未推送，未打标签。复审报告 `docs/reviews/M3a-rereview.md` 仍未跟踪。**

## 1. 结论

**有条件通过**：R-1、R-4、R-10 已修，各有先失败、后通过的回归测试（`tests/unit/test_m3a_rereview_fixes.py`，44 个用例），规则、策略与评测数字都没变。R-2、R-3、R-5、R-6、R-7、R-9 要改 §7，只写了提案；在它们定下来之前，F1、F6 仍是"部分修"，`trusted_projects` 仍不建议改为推荐设置。

| 复审发现 | 处理 | 改了什么 |
|---|---|---|
| R-1（中）会话工作目录在项目外时，项目内的写不打标记 | **已修** | 动作上新增 `project_root`（与工作目录无关的项目目录），打标记用它 |
| R-4（中）`python -m boundkeep.cli` 绕过 `deny-boundkeep-state-commands` | **已修** | 归一化层把 `python -m boundkeep.<模块>` 认成 `boundkeep`（`boundkeep.hook_client` 认成 `boundkeep-hook`） |
| R-10（低）已安装的策略得不到新来源，`doctor` 不提示 | **已修** | `doctor` 新检查 `taint-sources` |
| R-2、R-3、R-5、R-6、R-7、R-9 | 提案（第 7 节） | 无 |
| R-8（低）标记上限可被一次调用打满 | 未处理 | 复审标为"可选"，第 8 节 |

## 2. 交付物

| 文件 | 说明 |
|---|---|
| `src/boundkeep/normalize/model.py` | `Action.project_root`、`project_root_resolved`：`inside_project` 据以判断的项目目录，工作目录在项目外也照样设置；没有规则读它，也不发给 LLM（发送出口只用 `project`） |
| `src/boundkeep/normalize/event.py` | 有项目根时，把它写进每个动作的 `project_root` |
| `src/boundkeep/session/marks.py` | `written_locations` 记项目目录时，把 `project_root` 也算上 |
| `src/boundkeep/normalize/programs.py` | `_boundkeep_module`：`-m boundkeep`、`-m boundkeep.<任何模块>`（不分大小写）是 boundkeep；`-mboundkeep.cli` 同样；`boundkeep.hook_client` 是 `boundkeep-hook`；`boundkeepx`、`boundkeep_cli` 这类别的包不是 |
| `src/boundkeep/doctor.py` | `check_taint_sources`：活动策略缺少默认来源时 WARN（窗口不是默认值时一并说明）；任一设置层里 boundkeep 的 PostToolUse matcher 与 `taint.sources` 算出的不一致时 WARN |
| `tests/unit/test_m3a_rereview_fixes.py`（新） | 44 个用例，见第 3 节 |
| `docs/threat-model.md` | 项目标记一条补上"工作目录在项目外也记"；第 4 节新增"间接运行 boundkeep 的状态命令"（哪些写法认得出、哪些仍是灰色） |
| `docs/policy-reference.md` | `project_written_after_untrusted` 一行补上同一句 |
| `docs/reports/M3a-rereview-fixes.md`（新） | 本报告 |
| `CLAUDE.md` | 当前状态 |

## 3. 验收标准逐条对照

| 标准 | 结果 | 证据 |
|---|---|---|
| 每条发现先有失败的复现 | 通过 | 修之前跑新文件：**36 失败、5 通过**（通过的 5 个是对照：没有 `cwd` 的写本来就打标记、写到项目外只记路径、读不打标记、`boundkeepx` / `boundkeep_cli` 不是 boundkeep） |
| R-1 | 通过 | 被污染的会话在 `cwd=/home/testuser/notes`（项目旁边的目录）里 `Write` / `Edit` 项目内的测试文件与 `conftest.py`、`echo x > <项目>/tests/...`、`echo x > $TARGET/...`（不确定在哪）、以及没有 `cwd` 的 `Write`：标记都是项目目录，另一个会话的 `pytest -q` 被 `ask-devtools-after-untrusted-project-write` 问；写到项目外仍只记那个路径，读仍不打标记；`normalize_event` 给出 `project=None`（`project_trusted` 不适用，原有行为）、`project_root=<项目>` |
| R-4 | 通过 | 11 种写法 × 有无 LLM（`FakeBackend.answering()`，永远 allow）共 22 个用例都是 deny，规则含 `deny-boundkeep-state-commands`：`python -m boundkeep.cli mode audit-only` / `uninstall` / `init --reset-policy` / `taint clear --all` / `trust add .`、`python -m boundkeep.__main__ …`、`python3 -m …`、`python -mboundkeep.cli …`、`python -I -m boundkeep.cli serve`、`uv run python -m …`、`python -m BOUNDKEEP.CLI …`；归一化的程序名、子命令与 `python-m` 包装都对（包装让 allow 规则不匹配） |
| R-10 | 通过 | 默认策略加默认 matcher：不报；旧来源 `[WebFetch, WebSearch, mcp__*]`：WARN 点名三个 MCP 资源工具，修法含 `taint.sources` 与 `boundkeep init`；旧来源加 `window: 8`：一并说明；matcher 是旧的：WARN 点名设置层，修法 `run 'boundkeep init' again`；策略读不出、没有 PostToolUse 条目：不报（留给别的检查） |
| `ruff check` / `ruff format --check` / `mypy` | 通过 | `ruff check src tests` 通过；`ruff format --check .` 只标出未跟踪、没动的 `docs/reviews/M3a-security-review.md`；`mypy src` 75 个文件没有问题 |
| `boundkeep test` | 通过 | default **1138 / 0**，strict **334 / 0**（策略没改，与上一轮相同） |
| 评测不变 | 通过 | 策略文件没改，所以没有重新生成 `eval/`；另跑一遍到 scratchpad（`run_eval.py --config rules+taint --test-contaminated --out-dir <scratchpad>`，不开留出批次），两个结果文件去掉日期与延迟之后与已提交的逐字段相同 |

## 4. 与计划的偏差

1. **R-1 没有按复审的第一种做法"记路径本身"**，而是给动作加了与工作目录无关的项目目录。记路径本身漏掉路径不确定的写（`echo x > $TARGET/...`：`inside_project` 是"不确定"，又没有项目键，什么都不记）；用项目目录时它和工作目录在项目内的情况一样，记项目目录。`project` 本身不变：工作目录在项目外时 `project_trusted` 仍不适用。
2. **R-4 只改了归一化**，没有给 `mode`、`uninstall` 加 `trust add` 那样的运行时两道检查（复审说的纵深防御）：那会让用户自己在脚本里运行的 `boundkeep mode` 被拒，是用户看得见的行为变化，复审也说要在 §7 / §12 提一句。第 8 节第 3 条。模块名不分大小写比较：Python 在 Windows 上导入时区分大小写，所以 `-m BOUNDKEEP.CLI` 实际跑不起来，但多拒绝一些是安全方向。
3. **R-10 还查了 PostToolUse matcher 与策略来源是否一致**（复审建议里有）；`window` 只在缺少默认来源时一并说明：单看 `window: 8` 分不清是旧默认还是你自己设的。
4. **全量测试开始之后又改了两处**：`doctor` 的提示文字（加上窗口的说明）与新测试文件里 3 个用例。这两处只在定向运行里测过（第 5 节）。

## 5. 度量

- 新测试 `tests/unit/test_m3a_rereview_fixes.py`：44 passed。
- 受影响面的分组运行：
  - `test_m3a_x1_decisions.py`、`test_m3a_x1_fixes.py`、`test_m3a_pipeline.py`、`test_m3a_review_fixes.py`、`test_m3a_send_gate.py`、`test_session_tool_results.py`、`test_review2_policy_guard.py`、`test_project_memory.py`、`test_policy_rules.py`、`test_review2_install_logic.py`、`test_doctor_rules.py`、`test_m1c2_trusted_projects.py`、`test_m1c2_trusted_policy.py`：2999 passed、2 skipped。
  - `test_norm_bash.py`、`test_norm_event.py`、`test_norm_paths.py`、`test_norm_psparse.py`、`test_hookcmd.py`、`test_install.py`：1821 passed、47 skipped。
  - 改完 `doctor` 文字之后：`test_m3a_rereview_fixes.py`、`test_review2_install_logic.py`、`test_doctor_rules.py` 161 passed、1 skipped。
- 全量 `uv run pytest -q`（10-31 01:58–03:09，第 4 节第 4 条那两处之前）：26741 通过、169 跳过、**1 失败**，用时 1:11:01。失败的是 `test_review3_core_lexical.py::test_a_deny_after_1400_distinct_commands_is_still_a_deny`：`cat .env` 仍然是 deny（安全性质成立），但耗尽的是时间预算（`budget:time`），不是测试断言的动作预算（`budget:actions`）。判断是机器负载造成的偶发失败，与本轮改动无关，依据：
  - 单独跑这个用例 5 次都通过（每次约 1.5 秒），整个文件 58 passed；
  - 这个输入的归一化中位数 41 ms、最大 47 ms，而 `TIME_BUDGET_S` 是 250 ms，余量约 6 倍；
  - 新加的 `project_root` 让 1400 个 `Action` 的构造从 2.8 ms 变成 3.3 ms，而这个输入只产生 258 个动作；
  - 这个测试只放宽了 `LEXICAL_TIME_BUDGET_S`，没有放宽 `TIME_BUDGET_S`（`pipeline.review` 用 `normalize_event` 在定义时绑定的默认值，打补丁改模块常量也改不到它），所以长时间运行里一次停顿就会让时间预算先到。第 6 节。
- 没有花钱：没有运行 `claude -p`，没有访问任何 LLM 服务。

## 6. 已知问题与局限

- **F1、F6 仍是部分修**：R-2（配置 LLM 时标记不进 LLM 路径）、R-3（被拒或没人看见的询问也消耗窗口）、R-5（shell 读进来的外部内容不是来源）都要改规格，见第 7 节。不阻塞提交，阻塞 `m3a-done`。
- **间接运行 boundkeep 的写法仍是灰色**：`python -c "from boundkeep.cli import main; …"`、`python -m runpy boundkeep …`、按路径运行 `cli.py`、`cmd /c`、`Start-Process`。没有 LLM 时问用户，配置 LLM 时由模型判断。已写进 `docs/threat-model.md` 第 4 节，有测试确认前两种仍是 `python`。
- **R-1 的前提没有在真实 Claude Code 里测**：复审推断 hook 的 `cwd` 在 `cd` 之后跟着变（官方文档说是"当前工作目录"）。修复不依赖它：工作目录在项目内、外、缺失，三种情况都打标记。
- **偶发失败的测试** `test_a_deny_after_1400_distinct_commands_is_still_a_deny`（第 5 节）：断言的是哪种预算先耗尽，而 250 ms 的时间预算在负载下可能先到。要彻底稳定，得让这个测试绕开时间预算：或者直接调用 `normalize_event(..., budget_s=60)`，或者让 `normalize_event` 在调用时才读 `TIME_BUDGET_S`（改源码）。这轮没做，不在三条发现之内；不阻塞。
- 复审第 6 节"没覆盖到的范围"（真实 Claude Code、macOS / Linux、UNC 与 `subst` 项目、并发写标记的延迟、审计器的发送出口）这一轮也没有覆盖。

## 7. 规格变更提案

以下六条都要改 `PROJECT_SPEC.md` §7（R-5 还有 §8），按 X5 写，等你逐条决定；批准之后先改规格再改代码。

### P-R2 带标记的项目里，会运行代码的灰色调用不送审

- **现状**：§7"项目上的标记"只让开发工具名单（`ask-devtools-after-untrusted-project-write` 的 7 个程序）在带标记的项目里再问。
- **问题**：配置了 LLM 时，`npm test`、`make test`、`python -m unittest`、`tox` 在另一个会话里是灰色、送审；那个会话没读过不可信内容，污染一步不适用，模型的 allow 就是结果（复审 R-2，用永远 allow 的假后端复现）。
- **建议文本**（加在"项目上的标记"下）："动作的项目带标记时，带 `exec` 风险标签的灰色调用不发给 LLM，直接 ask（与'请求装不下的输入'同样处理，不消耗窗口）。"
- **影响面**：`pipeline._finish`（与 `unshown_input` 同一处）、新测试；没有 LLM 时没有变化（灰色本来就问）；评测不模拟标记，数字不变。
- **备选**：把这次调用当作"被污染"交给污染一步：带敏感标签的 LLM allow 改成 ask，但会消耗窗口、逻辑更绕。**建议用正文的做法。**

### P-R3 窗口只被用户批准并执行了的询问消耗

- **现状**：§7"窗口只被污染一步改成了 ask 的调用消耗……计数在判决之后写"。
- **问题**：boundkeep 在判决时就计数，不知道用户批没批。同一个敏感调用被拒 3 次，第 4 次静默放行；`dontAsk` 模式、`claude -p` 与后台子 agent 里的 ask 用户根本看不到，也照样计数（复审 R-3；后两种未实测）。
- **建议文本**："污染一步改成 ask 的调用，记下它的 `tool_use_id`；同一个 `tool_use_id` 的 PostToolUse 到达（用户批准了、工具真的运行了）时才计一次。被拒或没人看见的询问不计数。"
- **影响面**：PostToolUse 的 matcher 要从"来源工具"扩到所有工具（每次工具调用多一次 hook 进程，延迟要实测），`init` 与 `doctor` 跟着改，会话库加一张待确认表；PreToolUse / PostToolUse 是否带 `tool_use_id` 要先做 hook 实测（`docs/hook-behavior.md` 里没有记录，[未验证]）。
- **备选**：B. 不扩 PostToolUse：`permission_mode` 为 `dontAsk`、事件带 `agent_id` 时不计数，并且窗口过去之后，本会话里问过的同一个动作（按缓存键）仍然问。代价小，但"用户拒绝了 3 个不同的动作"仍会耗尽窗口。**建议 A，先做 hook 实测（与 P-F2 那次一样，几美分）。**

### P-R5 被批准的、带网络动作的 shell 调用也算来源

- **现状**：§7 污染升级规则的局限："来源只按工具名识别。通过 Bash 的 `curl` 读取网页……v0 不会打污染标记"。
- **问题**：`gh issue view`、`gh pr view --comments`、`curl`、`npm view` 被批准一次之后，"先写后运行"在受信任项目里和没有 M3a 时一样（复审 R-5）。对编码 agent 来说"读 issue 然后修"是最常见的注入入口。
- **建议文本**："shell 调用里有动作带网络目标（`domains` 非空或 `network` 为真），而判决不是 deny 时，这次调用也算来源：PreToolUse 时置粘性位并让窗口重新开始（与来源工具同样，被拒也算，安全方向）。"
- **影响面**：`pipeline.decide`、`store.tool_call`（来源判断不只看工具名）、§8 `taint.sources` 的含义、文档；评测：`rules+taint` 里带网络的正常样本会被标成被污染，相关数字可能变，要重跑。代价：批准过网络命令的会话，之后的开发工具都会再问。
- **备选**：接受现状，在 `trusted_projects` 的文档里明说这一条，并继续不推荐它。**建议采纳正文。**

### P-R6 看不到写路径的写也记项目目录

- **现状**：§7"打标记"只看动作路径的访问方式；局限一条只提了运行代码的命令与 MCP 工具。
- **问题**：`git stash pop`（规则直接放行）、`git apply`、`git checkout`、`python gen.py`、相对路径的 MCP 写、以及会话里第一个来源调用本身就是带写路径的 MCP 写，都不打标记（复审 R-6）。
- **建议文本**："读过不可信内容的会话里，灰色的、带 `exec` 或 `file_write` 标签的、MCP 的、以及会改工作区的 `git` 子命令（`stash pop|apply`、`checkout`、`restore`、`switch`、`apply`、`am`、`merge`、`pull`、`reset`、`cherry-pick`、`rebase`）的调用，记它的项目目录；来源调用自己带写路径时也记。"
- **影响面**：`marks.written_locations` 或 `pipeline.decide`、测试；只在读过不可信内容的会话里多打标记，安全方向。
- **备选**：只加 `git` 子命令与"来源调用自己的写"，其余保留为局限。**建议采纳正文。**

### P-R7 写到项目之外时记所在目录

- **现状**：§7"路径确定、而且不在项目之内时……记路径本身"。
- **问题**：写 `~/pytest.ini`、`~/.pylintrc`、兄弟项目 `../lib`（可编辑安装）时，标记是那个文件，读它的受信任项目看不到（复审 R-7）。
- **建议文本**：把"记路径本身"改成"记路径所在的目录"。
- **影响面**：`marks.written_locations`、测试、`docs/privacy.md`（存的是目录）。写到主目录的文件会让主目录下所有项目都带标记，开发工具都再问，直到 `taint clear`。
- **备选**：只对已知的工具配置文件名（`pytest.ini`、`.pylintrc`、`setup.cfg`、`tox.ini`、`pyproject.toml`、`conftest.py`、mypy 配置）记目录，其余仍记文件。**建议备选**：正文的做法误伤太大。

### P-R9 resume / compact 遇到不认识的会话时按"读过不可信内容"开始

- **现状**：§7 会话状态库只讨论了 resume 与 compact 不换 `session_id`。
- **问题**：fork（`--fork-session`、桌面应用的 fork）、清理之后的 resume 会带着旧上下文换成库里没有的 id，粘性位与窗口丢了（复审 R-9，未实测）。
- **建议文本**："`init` 注册 `SessionStart`；`source` 为 `resume` 或 `compact` 而 `session_id` 不在库里时，这个会话按'读过不可信内容'开始（失败即关闭）。"
- **影响面**：`init`（新 hook）、`hook_main`、`store`、`doctor`；先做 hook 实测：fork 之后 SessionStart 的 `source` 与 `session_id`。
- **备选**：只写进威胁模型。**建议采纳正文，先做实测。**

## 8. 需要你决定的事项

1. **提交**（已按下列两组完成，见开头）：建议两次，逐个列文件，不推送、不打标签。
   - 代码：`src/boundkeep/normalize/model.py`、`src/boundkeep/normalize/event.py`、`src/boundkeep/normalize/programs.py`、`src/boundkeep/session/marks.py`、`src/boundkeep/doctor.py`、`tests/unit/test_m3a_rereview_fixes.py`。
   - 文档：`docs/reports/M3a-rereview-fixes.md`、`docs/threat-model.md`、`docs/policy-reference.md`、`CLAUDE.md`。
2. **复审报告 `docs/reviews/M3a-rereview.md`**：要不要随文档一起提交（建议提交：它是这轮修复的依据）；`docs/reviews/M3a-security-review.md` 仍由你决定。
3. **`mode` / `uninstall` 的运行时两道检查**（R-4 的纵深防御）：建议暂不加（H-5 已说明它不是边界，而且会挡住你自己在脚本里的用法）。
4. **第 7 节六条提案**：逐条批准、修改或拒绝。建议：P-R2、P-R5、P-R6、P-R9 采纳正文；P-R3 采纳 A（先做 hook 实测）；P-R7 采纳备选。
5. **R-8**（标记上限可被一次调用打满）：建议暂不处理，安全方向。

## 9. 进入下一步的前置条件

- 本轮提交（已完成，2026-10-31）；
- 第 7 节的提案定下来并实现之后，F1、F6 才能算修完；再做一次定向复审（或由你判断是否需要），之后再决定 `trusted_projects` 与 `m3a-done`。
