# M3a 独立 X1 审查：中危 F1–F6 的处理

日期：2026-10-30。依据：`docs/reviews/M3a-security-review.md`（未被 git 跟踪，只剩前 28 行，见第 6.1 节）、`IMPLEMENTATION_PROMPTS.md` 的全局提示词 G、X3、X5，`PROJECT_SPEC.md` 修订 6 的 §7（M3a 一段）、§9、§10，`docs/reports/M3a.md`。基线是 `main` 的 `0ac85a5`。**没有提交、没有推送、没有打标签。** 没有读 `.env`，没有持有或使用任何 LLM 密钥，没有访问任何真实的 LLM 服务（只用 `FakeBackend` 与 127.0.0.1 上的假服务）；没有读 `eval/authoring/h1-*.txt`、`h2-*.txt` 与 `eval/datasets/holdout/` 下的文件，没有加 `--open-holdout`；没有起草攻击样本；没有动 `docs/reviews/M3a-security-review.md`；没有读审查会话的对话记录，也没有试图还原被中止的报告正文。

## 1. 结论

**有条件通过。** 六条中危里：

| 编号 | 状态 | 一句话 |
|---|---|---|
| F1 | **未修，等你决定**（X5 提案 P-F1） | 粘性位只在读过不可信内容的那个会话里有效，换个会话运行开发工具不再问。已复现（strict xfail 测试） |
| F2 | **无法确认** | 审查只说"规则层另一条 M-2 绕过"，没有细节。我查过的方向与找到的一个相关缺口（MCP 资源工具不是污染来源，提案 P-F2）见第 6.2 节；不能断定那就是 F2 |
| F3 | **已修**（规格文字待补，P-F34） | 送审的调用里有模型看不到的代码（here-document / here-string、`NODE_OPTIONS=…` 这类赋值、PowerShell 管道进解释器的字符串与赋值）：现在不送审，直接 ask |
| F4 | **已修**（规格文字待补，P-F34） | 送审的调用里有模型看不到的参数（`NAME=value` 前缀、MCP 调用的参数）：现在不送审，直接 ask |
| F5 | **已修**（规格不用改） | 名字解析卡住时适配器的期限不是硬期限，卡住的审查占满工作线程之后，规则的 deny 被"繁忙"的 ask 取代：现在名字解析在不被等待的后台线程里，期限是硬的 |
| F6 | **未修，等你决定**（X5 提案 P-F6） | agent 可以用几次无害调用把污染窗口用完。已复现（strict xfail 测试） |

另外修了 `docs/reports/M3a.md` 第 5.1 节记下的计时竞争测试（第 6.2 节末）。低危 F7–F13 与两条信息项的细节已经拿不到（第 6.3 节）。

F3、F4、F5、F6 只在配置了 LLM 后端时成立（默认 `backend: none`）；F1 与 P-F2 只在用了 `trusted_projects` 时成立（默认空）。**建议在 F1 决定并实现之前，`trusted_projects` 继续不推荐。**

## 2. 交付物

| 路径 | 说明 |
|---|---|
| `src/boundkeep/audit/backends/openai_compatible.py` | F5：`_DetachedExecutor`（每次尝试的事件循环的默认执行器：每个名字解析一个守护线程，关闭时不等；全局最多 `MAX_HANGING_LOOKUPS` = 8 个，再多就立刻 `OSError`，即 `network` 失败）；`_run` 用它 |
| `src/boundkeep/normalize/model.py` | F3/F4：`SimpleCmd.stdin_text`（这个命令的 here-document / here-string，`heredoc` / `herestring`，别的描述符记成 `heredoc:3`）；`Action.unshown`（这个动作没带上的输入：`env:NAME` 与 `stdin_text`；规则不看它） |
| `src/boundkeep/normalize/bash.py` | 记下 `stdin_text`；shell 自己把 here-document / here-string 当命令读时（`bash <<EOF`），正文被解析成单独的命令，清掉标准输入那一项 |
| `src/boundkeep/normalize/event.py` | `Action.unshown` = 赋值的变量名（PowerShell 开发工具的内部伪变量除外）+ `stdin_text` |
| `src/boundkeep/daemon/pipeline.py` | `unshown_input`：`Action.unshown`、PowerShell 的 `ps-pipe-to-interpreter` 与 `ps-compound:AssignmentStatementAst`、任何 MCP 调用 → 不送审，直接 ask（`decided_by: gray-unanalysed`，理由写"the LLM audit could not be shown all of it (…)"） |
| `tests/unit/test_m3a_x1_fixes.py`（新） | 48 个用例：F3 / F4 / F5 的复现（修之前 39 个失败，见第 3 节）与对照；F1、F6、P-F2 的 strict xfail 复现 |
| `tests/unit/test_m3a_review_fixes.py` | `test_an_ordinary_mcp_call_is_still_sent` 改为 `…_is_not_sent_either`：F4 有意反转了这条自查时的断言（第 4 节） |
| `tests/e2e/test_hook_client_process.py` | 计时竞争：占位连接先发 1 个不带换行的字节 |
| `docs/threat-model.md`、`docs/privacy.md`、`docs/architecture.md` | 新的不送审情形、名字解析的期限、F1 / F6 / MCP 资源工具三个待定缺口 |
| `docs/reports/M3a-review-fixes.md` | 本报告 |
| `CLAUDE.md` | "当前状态"加一条本轮的摘要，"下一步"改为等第 8 节的决定 |

没有改：`policies/*.yaml`、`policy/` 下的代码、`PROJECT_SPEC.md`（规格等你对第 7 节的决定）、`eval/`。

## 3. 验收标准逐条对照

| 标准（任务书） | 结果 | 证据 |
|---|---|---|
| 每条先写会失败的复现测试，再修，再确认通过 | F3、F4、F5 做到；F1、F6 只写了复现（strict xfail），等决定；F2 无法确认 | 修之前 `uv run pytest tests/unit/test_m3a_x1_fixes.py`：**39 failed, 6 passed, 3 xfailed**（6 个通过的是"仍然送审"的对照用例）；修之后：**45 passed, 3 xfailed** |
| F5 的修复前后 | 修前 0.5 秒预算的一次尝试在卡住的解析器上用了 **6.09 秒**（解析器放开才回来）；守护进程（1 个工作线程）里一次灰色审查被放弃之后，`cat .env` 与 `cat ~/.ssh/id_rsa` 都是 `busy` 的 **ask**。修后同一尝试 **0.53 秒** 超时；`make release` 0.31 秒得到 `llm-failure:timeout`，`cat .env` 是 **deny**（`rule:no-secret-read`） | 探测脚本在会话的 scratchpad，没进仓库；对应测试 `test_a_hanging_resolver_does_not_stretch_the_adapter_budget`、`test_a_hanging_resolver_does_not_turn_a_rule_deny_into_an_ask` |
| 计时竞争测试 | 已修 | 单独连跑 5 次通过；把客户端的启动人为推迟 1.6 秒：不发那个字节时失败，发了通过（临时改动已撤回） |
| `uv run ruff check .` | 通过 | All checks passed! |
| `uv run ruff format --check .` | **1 个文件不合格式，不是我的** | `docs/reviews/M3a-security-review.md` 第 19 行的 Python 片段（未跟踪的审查报告，任务书要求不动它）；排除它之后 `267 files already formatted` |
| `uv run mypy` | 通过 | Success: no issues found in 73 source files |
| `boundkeep test` default / strict | 通过，0 失败 | default 1120 / strict 326，见第 5.1 节 |
| 全量 `uv run pytest -q` | 通过，0 失败 | 26655 passed, 169 skipped, 3 xfailed，见第 5.1 节 |
| 规则有改动时重新生成评测 | 规则没有改动（`policies/` 与 `policy/` 无差异；新字段 `Action.unshown` 不参与任何规则；评测不用 LLM） | 第 5.2 节 |

## 4. 与计划的偏差

1. **审查报告没有可用的正文**：只剩结论段与严重度口径，每条中危只有一句话。下面每条都是我按那一句话自己找到并复现的情形；**审查者心里的具体写法可能不止这些，也可能是别的**，我不能确认它们一一对应。
2. **F3、F4 在规格文字批准之前就实现了**。理由：规格 §7 已经写明（P11，使用者已批准）"模型只能看到调用的一部分时，它的 allow 会盖住没人看过的部分，所以不送审、直接 ask"，F3、F4 正是这种情形，修法只让结果更严；但 §7 列举的情形里没有它们，§9.2 也写着 MCP 调用发送"服务名与工具名"，所以文字要改（P-F34）。如果你不接受，回退只要删掉 `pipeline._finish` 里对 `unshown_input` 的调用。另一种修法（把这些代码与参数发给模型）见 P-F34 的备选。
3. **F1、F6 只写了提案与复现，没有实现**：两者都要改 §7 的设计（粘性位的作用范围、窗口的计数方式），各有明显的代价，按任务书停下等你决定。
4. **一条旧断言被有意反转**：M3a 自查留下的 `test_an_ordinary_mcp_call_is_still_sent` 断言普通 MCP 调用会送审；F4 之后不再送审，测试改名为 `test_an_ordinary_mcp_call_is_not_sent_either` 并断言不送审。这不是为了让测试通过而放宽：新行为更严。
5. **`ruff format --check .` 不是 0**：唯一的问题在未跟踪的审查报告里，按约束没有动它。它进不进仓库、要不要格式化由你决定。

## 5. 度量

### 5.1 测试与静态检查

- 新测试 `tests/unit/test_m3a_x1_fixes.py`：48 个用例，本机 45 通过、3 个 strict xfail（F1、F6、P-F2；它们一旦"意外通过"就会让套件失败，提醒同步去掉标记）。PowerShell 的 4 个用例需要真实的解析辅助进程，非 Windows 上跳过。
- M3a 原有测试与一致性测试（`tests/unit/test_m3a_*.py` 9 个文件 + `tests/contract`）：改完代码之后 **1 failed, 791 passed, 1 skipped**（live）；唯一的失败就是第 4 节第 4 条那条被有意反转的断言，改过之后它通过（见下一条）。
- 受影响面的分组运行（`test_m3a_review_fixes.py`、`test_norm_event.py`、`test_norm_bash.py`、`test_pipeline.py`、`test_pipeline_corpus.py`、`test_daemon.py`）：**5863 passed, 39 skipped in 2547.69s**（跳过的是本机没有可用 bash 的差分用例与 POSIX 专用用例）。
- `boundkeep test --policy policies/default.yaml`：**1120 test(s) run, 0 failed**；`--policy policies/strict.yaml`：**326 test(s) run, 0 failed**（与 M3a 相同，策略没有改）。
- 全量 `uv run pytest -q`（所有改动完成之后跑，2026-10-30 11:16–12:24）：**26655 passed, 169 skipped, 3 xfailed in 4099.56s (1:08:19)**，0 failed。3 个 xfail 就是上面的 F1、F6、P-F2；跳过的是 POSIX 专用、本机没有可用 bash、不能建符号链接、live 后端（要 `--live`）与只在 Windows 假机器上跑的 PowerShell 用例。

### 5.2 评测

规则没有改：`git diff 0ac85a5 -- policies src/boundkeep/policy` 为空；`Action.unshown` 只被 `pipeline.unshown_input` 读，而它只在有 LLM 审计器时才被调用；`rules-only` 与 `rules+taint` 都不用 LLM。所以按任务书不需要重新生成评测，`eval/report.md` 与 `eval/results/*.json` 没有动。

作为核对，按 `docs/reports/M3a.md` 第 5.3 节的命令重跑了一次，只是输出到会话的 scratchpad（`uv run python eval/run_eval.py --config rules+taint --test-contaminated --out-dir <scratchpad>`，不打开任何留出批次）：数据集指纹不变（dev `34a1cd18e50712e5`，test `5f2bab54704e0132`；留出批次只算指纹）；`rules-only.json` 与 `rules+taint.json` 去掉延迟与日期字段之后与仓库里的文件**逐项相同**（`cells`、`taint_delta`、`taint_sensitivity`、`policy_sha256` 都在比较之内）。所以 `docs/reports/M3a.md` 第 5.3 节的表（windows / posix 拦截 100.0% / 100.0%，达到要求 85.7% / 97.6%，误报 36.6% / 75.0%，`rules+taint` 增量 0）仍然成立。

### 5.3 F3 / F4 的代价

配置了 LLM 后端时，下面这些灰色调用从"交给模型"变成"直接问"，与没有后端时相同：带 `NAME=value` 前缀或单独赋值的命令（`CI=1 npm test`、`NODE_ENV=test make`）；任何带 here-document / here-string 的命令（包括 `cat <<EOF > 文件` 这类写文件的写法，以及 `git commit -F - <<EOF`）；PowerShell 里先给变量赋值再运行的命令；全部 MCP 调用（声明为只读的由规则放行，不受影响）。没有 LLM 后端时（默认）判决一条都不变。没有在真实会话上量过增加了多少询问（M3b 之前没有真实的 LLM 判决可比）。

## 6. 已知问题与局限

### 6.1 审查报告的情况

`docs/reviews/M3a-security-review.md` 未被 git 跟踪，停在 F1 的"受影响的不变量"一行中间（共 28 行）。按任务书只用了第 9 行的结论段（没有高危；中危 6、低危 7、信息 2；F1、F2 不需要 LLM，是 M-2 的绕过；F3–F6 只在配置了 LLM 时成立，各一句描述）与第 11 行的严重度口径（`emit_allow` 关闭时，"放行"等于"boundkeep 不再问"）。

### 6.2 逐条

**F1（中）跨会话的"先写后运行"**

- 复现：受信任项目，会话 A 调用 `WebFetch`（粘性位置位），A 写 `tests/test_x.py`（项目内写入，allow）；会话 B（新的 `session_id`：新开会话或 `/clear`）运行 `pytest -q`：**无决定（放行）**。`test_f1_a_new_session_does_not_run_a_dev_tool_unasked_after_another_read_the_web`（strict xfail）。
- 原因：`session_read_untrusted` 按 `session_id` 存（规格 §7："一直保留到换新的 `session_id`"），写入留在项目里，标记不跟着走。
- 修法：要改规格，见 P-F1。没有实现。
- 影响面：只在 `trusted_projects` 非空时（默认空）。

**F2（中）规则层另一条 M-2 绕过 —— 无法确认**

审查只说了"规则层就能复现、是 M-2 的绕过"，没有写是什么。我查过的方向：

1. 开发工具的各种写法会不会绕过粘性规则：在受信任项目、`WebFetch` 之后、没有 LLM，试了 60 多种（`pytest`、`python -m pytest`、`python3 -m pytest`、`.venv/bin/pytest`、`pytest.exe`、`py.test`、`python -m _pytest`、`dmypy`、`stubgen`、`pyreverse`、`pyflakes`、`uv run pytest`、`poetry run pytest`、`pipenv run pytest`、`conda run pytest`、`tox`、`nox`、`make test`、`npm test`、`cd tests && pytest`、`pytest --version` 等）。**没有一种是放行**：开发工具名单里的都被 `ask-devtools-after-untrusted-content` 问到，名单外的都是灰色（没有后端时就是 ask）。所以 `docs/reports/M3a.md` 第 6 节第 3 条的包管理器写法只在配置了 LLM 时才是缺口（属于 F6 的范围），不是规则层的。
2. 别的会运行仓库代码的 allow 规则：`git commit -m`（`allow-git-commit-message`）会运行仓库已有的 hook（例如已安装的 pre-commit 读工作区里的配置），被污染之后仍然放行。这一点在规则注释里已经作为残余接受（写 `.git/hooks`、`.pre-commit-config.yaml`、`.git/config` 都是 ask），不是新发现。
3. **来源没有覆盖到的读取途径**：Claude Code 读 MCP 资源的工具 `ReadMcpResourceTool`、`ListMcpResourcesTool` 名字不以 `mcp__` 开头，默认 `taint.sources`（`WebFetch`、`WebSearch`、`mcp__*`）认不出。它们本身是未知工具（灰色，ask）；用户同意读取之后，会话不被标记，随后的"写测试 → `pytest`"在受信任项目里不再问。`test_f2_reading_an_mcp_resource_marks_the_session`（strict xfail）。**[未验证]** 这两个名字在 hook 事件里的写法（我是从 Claude Code 自己的工具清单看到的，没有做 hook 实测）。要不要加进默认来源要改规格 §8 的默认值，见 P-F2。

这三项里哪一项是 F2、或者 F2 是不是别的，我无法确认。

**F3（中）送审的调用里有模型看不到的代码 —— 已修**

- 复现（`FakeBackend` 永远 allow，即模型已被完全操纵）：`python3 - <<'EOF' … EOF`、`python3 <<< '…'`、`node <<'EOF'`、`perl <<'EOF'`、`psql <<'EOF' DROP TABLE …`、`sqlite3 db <<< 'DROP …'`、`bash ./tools/run.sh <<'EOF'`（here-document 是脚本的输入）、`NODE_OPTIONS='--require ./x.js' node app.js`、`PYTHONSTARTUP=x.py python3 app.py`；PowerShell 的 `@'…'@ | python -`、`'print(1)' | python`、`$env:NODE_OPTIONS='…'; node app.js`。请求里只有 `python3 -`、`psql`、`node app.js` 和一条"看不懂"的原因，代码本身不在请求里，模型的 allow 就是最终的放行。
- 修法：归一化层记下每个动作没带上的输入（`Action.unshown`），管线在送审之前检查（`unshown_input`），有就不送审、直接 ask，不按 `on_failure`（与 P11 的"没被完整分析"同一条路）。shell 自己读的 here-document / here-string 已被解析成单独的命令，照常送审（`bash <<'EOF' echo … EOF` 仍发，命令在请求里）；`echo 'code' | python3` 的代码就是 `echo` 的参数，照常送审。
- 测试：`test_code_the_request_cannot_carry_is_not_sent`（10 种 × `on_failure` ask / deny）、`test_powershell_code_or_values_the_request_cannot_carry_are_not_sent`（4 种）、对照 `test_a_gray_call_whose_code_is_all_in_the_request_is_still_sent`（5 种）、`test_a_shell_here_document_shows_its_commands_to_the_model`、`test_the_normalizer_names_what_an_action_does_not_carry`。

**F4（中）送审的调用里有模型看不到的参数 —— 已修**

- 复现：`DATABASE_URL=postgres://… make migrate`、`FOO=… python3 app.py`、`env DEPLOY_TARGET=… make deploy`、`TARGET=…; make deploy`：请求里只有 `make migrate` 等，赋值整个不见，连一条"看不懂"的原因都没有。MCP 调用：`mcp__db__execute {"sql": "DELETE …"}`、`mcp__tracker__create_issue {"body": …}`、`mcp__docs__search {"query": …}`：请求里只有服务名、工具名与从参数里认出的路径和主机（以及 `mcp-sql-not-read-only` 这类原因），参数的值不发（§9.2 的设计），模型放行它没见过的 SQL 与正文。
- 修法：同 F3（`env:NAME` 进 `Action.unshown`；任何 MCP 调用都算"参数没有展示"）。
- 测试：`test_a_variable_assignment_the_request_cannot_carry_is_not_sent`（4 种）、`test_an_mcp_call_whose_arguments_are_not_shown_is_not_sent`（3 种 × ask / deny）。

**F5（中）名字解析卡住时期限不是硬的，规则的 deny 变成 ask —— 已修**

- 复现：把 `socket.getaddrinfo` 换成对 `localhost` 一直等待的版本，`base_url` 指向 `http://localhost:<端口>/v1`。适配器一次 0.5 秒预算的尝试用了 6.09 秒：`asyncio.timeout` 按时取消了等待，但 `asyncio.run` 关闭事件循环时要等默认执行器里的解析线程结束（Python 3.12 最多 300 秒）。守护进程里这次审查超过期限（规则 2 秒 + 预算 + 0.5 秒）被放弃，工作线程卡住；卡住的线程数达到线程池大小之后，守护进程对每个调用都回答 `busy` 的 ask，包括规则会 deny 的 `cat .env`、`cat ~/.ssh/id_rsa`（1 个工作线程时一次就够，默认 4 个时 4 次）。用户在确认框里点"同意"就读到了。
- 修法：每次尝试的事件循环用 `_DetachedExecutor` 作默认执行器：名字解析在自己的守护线程里，关闭循环时不等；尝试在期限到时就结束，解析线程等解析器自己放弃。这种后台线程全局最多 8 个，再多的解析立刻 `OSError`（`network` 失败，按 `on_failure`），不会无限堆积。规格 §9.1 本来就要求"预算是每次尝试的硬期限"，所以不改规格。
- 测试：`test_a_hanging_resolver_does_not_stretch_the_adapter_budget`（两种传输，< 1.5 秒）、`test_hanging_lookups_are_bounded`、`test_a_hanging_resolver_does_not_turn_a_rule_deny_into_an_ask`（守护进程，1 个工作线程：灰色调用 < 1.2 秒得到 `llm-failure:timeout`，随后 `cat .env` 是 deny）。
- 残余：守护进程"卡住的工作线程占满就回答 busy"这条路本身还在（例如别的原因让审查超时）；那时规则的 deny 仍会变成 ask。要彻底避免，需要在繁忙时也先跑规则（规则本身可能慢，所以才放在线程池里），没有在本次处理。

**F6（中）污染窗口可以被 agent 自己用完**

- 复现：配置了 LLM（永远 allow），`WebFetch` 之后连发 8 次 `Read`，随后 `make release`：模型的 allow 不再被污染一步改成 ask，**无决定（放行）**。`test_f6_padding_calls_do_not_use_up_the_taint_window`（strict xfail）。
- 原因：规格 §7 / P1 规定窗口按每次 PreToolUse 计数，无害调用也算。
- 修法：要改规格，见 P-F6。没有实现。

**计时竞争测试 `test_when_every_pipe_instance_is_busy_the_client_gives_up_inside_its_budget` —— 已修**

- 按 `docs/reports/M3a.md` 第 5.1 节的修法：占位连接打开后先写 1 个不带换行的字节，服务端就按 30 秒的读取期限等这一行，不再按 1 秒的首字节期限放开唯一的管道实例。
- 验证：单独连跑 5 次通过；临时让客户端晚 1.6 秒启动（模拟负载高时的延迟），不写那个字节时失败、写了通过；临时改动已撤回，`git diff` 只剩 4 行。

### 6.3 低危 F7–F13 与两条信息项

审查报告没有写到它们，细节已经拿不到。我没有猜测它们是什么，也没有处理。要知道它们，只能重新做一次（定向或完整的）审查。

### 6.4 其他

- `ruff format --check .` 因未跟踪的审查报告而不为 0（第 4 节第 5 条）。
- 没有在真实 Claude Code 里验证任何一条（都是管线与守护进程层面的行为，测试用真实的 `Daemon.handle`）。

## 7. 规格变更提案

### P-F1（§7 粘性位与 M-2）：把"读过不可信内容之后写进项目"记在项目上

- **现状**：§7 M3a 一段："匹配字段 `session_read_untrusted: true` 表示这个会话任何时候调用过 `taint.sources` 里的工具……一直保留到换新的 `session_id`"。
- **问题**：写入留在项目里，标记只留在会话里。F1 的复现：会话 A 读网页并写测试文件，会话 B 运行 `pytest` 不问。
- **建议**（方案 A）：
  - 会话状态库加一张表，按项目目录（规范化的键）记"被读过不可信内容的会话写过"：一个 `session_read_untrusted` 为真的会话里，任何对项目内路径的写（`Write`、`Edit`、`NotebookEdit`，以及带写路径的 shell 命令）在 PreToolUse 时标记它的项目（PreToolUse 标记，随后被拒绝的写也算，安全方向）。
  - 新匹配字段 `project_written_after_untrusted: true`（同样只能用于 deny / ask 规则，状态未知算命中）；`ask-devtools-after-untrusted-content` 的条件改成"`session_read_untrusted` **或** `project_written_after_untrusted`"（拆成两条同 id 前缀的 ask 规则，default 与 strict 相同）。
  - 解除：只能由用户在终端运行 `boundkeep taint clear <项目>`（与 `trust` 一样，agent 对它的调用被 `deny-boundkeep-state-commands` 拒绝；`trust remove` 同时清掉）；`doctor` 列出被标记的项目。不按时间过期（时间可以被等过去）。
  - 规格修改文本：在 §7 "粘性位与 M-2"下加一条："**项目上的标记**：读过不可信内容的会话往项目里写过东西之后，这个项目对**所有**会话都带标记 `project_written_after_untrusted`，开发工具一律再问，直到用户在终端运行 `boundkeep taint clear`。"
- **影响面**：`session/store.py`（新表、迁移到 schema 2）、`pipeline.decide`（写入时标记）、`policy/schema.py` 与 `matcher.py`（新字段）、两份策略与 `tests:`、`cli.py`（新子命令）、`doctor.py`、`docs/policy-reference.md`、`docs/threat-model.md`；评测：`rules+taint` 的模拟要加项目标记（单次调用的样本仍表达不了跨会话链，数字预计不变）。
- **备选与代价**：
  - **B：读过就标项目**（会话在项目里读了不可信内容，不管写没写，都标记项目）。更简单，但每次在受信任项目里查一次文档，之后所有会话的 `pytest` 都要问，直到手动清除；代价大于 A。
  - **C：不改，写进文档**。代价：F1 一直开着，`trusted_projects` 不能推荐。
  - **D：按文件内容跟踪**（记下被污染会话写过的文件的哈希，开发工具运行时检查这些文件是否还在）。最精确，但 pytest 会导入任何文件，要跟踪的范围说不清，实现与开销都大；不建议。
- 我的建议：A。

### P-F6（§7 污染窗口的计数）：窗口只被"被它改成了 ask 的调用"消耗

- **现状**：§7 与 P1："窗口按 PreToolUse 计数：来源调用之后的第 1 到第 `taint.window` 次调用为'被污染'"。
- **问题**：无害调用也计数，agent 读网页之后先发 `window` 次 `Read`，之后 LLM 对敏感动作的 allow 就照常放行（F6）。
- **建议**（方案 A）：窗口从"N 次调用"改为"N 次**本来会被放行的敏感动作**"：只有污染一步真的把一个 allow 改成了 ask 的调用才消耗窗口；其余调用（规则判定的、灰色却不敏感的、被问的）不计数。这样要用完窗口，agent 得让用户被问 N 次。规格修改文本："`tainted` 表示：来源调用之后，污染一步改成 ask 的调用还不到 `taint.window` 次"；P1 的计数一条相应改写。
- **影响面**：`session/store.py`（计数要在判决之后写，PreToolUse 多一次写）、`pipeline` 与 `audit/verdict.py`（污染一步触发时回报）、`taint.window` 的含义与默认值（8 次询问可能偏多，建议改为 3）、`docs/threat-model.md`、`docs/policy-reference.md`；评测口径不变（单次调用的样本不受计数方式影响）。
- **备选与代价**：
  - **B：LLM 路径也用粘性位**（会话读过不可信内容之后，LLM 对敏感动作的 allow 一律 ask）。最简单、最严；代价是用过 `WebFetch` 或任何 MCP 工具的会话里，LLM 层对敏感动作基本不再放行，LLM 的价值大半没了。
  - **C：时间加次数**（窗口至少持续 T 分钟）。agent 可以用 `sleep` 一类调用等过去，效果弱；不建议。
  - **D：不改，写进文档**。代价：F6 开着；M3b 接入真实后端前必须二选一。
- 我的建议：A；如果你更看重简单，B。

### P-F2（§8 默认 `taint.sources`）：把读 MCP 资源的工具加进默认来源

- **现状**：§8 `taint.sources: [WebFetch, WebSearch, "mcp__*"]`。
- **问题**：`ReadMcpResourceTool`、`ListMcpResourcesTool` 读的是 MCP 服务的内容，名字不匹配 `mcp__*`（第 6.2 节 F2 第 3 条）。
- **建议**：先做一个 M0a 式的最小实验，确认这两个工具在 hook 事件里的 `tool_name`（[未验证]）；确认后默认与 strict 的 `sources` 加上它们，§8 的示例同步。
- **影响面**：两份策略（规则改动，要按 `docs/reports/M3a.md` 第 5.3 节重新生成评测）；`init` 生成的 PostToolUse matcher 随之变化，**已安装的用户要重新 `init` 才会在 PostToolUse 打标记**（PreToolUse 的 matcher 是 `*`，那一处立即生效）；`docs/threat-model.md`。
- **备选**：不加，写进已知局限（代价：用户同意过一次 MCP 资源读取之后，粘性位就看不见它）。

### P-F34（§7 不送审的情形、§9.2 发送内容）：补上"请求装不下的代码与参数"（代码已按此实现）

- **现状**：§7 "没被完整分析的灰色调用不送审"列了六种情形；§9.2 的字段里，MCP 调用发"服务名与工具名"。
- **问题**：F3、F4（第 6.2 节）。
- **建议文本**：§7 那一段的列表后加："**请求装不下的输入**：命令里的 here-document 或 here-string（shell 自己当命令读的除外，它们被解析成单独的命令）、`NAME=value` 赋值（命令前缀、`env NAME=v`、单独的赋值）、PowerShell 里管道进解释器的字符串与赋值语句、MCP 调用的参数。模型看不到它们，所以这些调用同样不送审，直接 ask。"§9.2 的"MCP 的服务名与工具名"一项删去，改为"MCP 调用不送审（参数不发，见 §7）"。
- **影响面**：已实现的代码（第 2 节）；`docs/` 已同步；评测不受影响。
- **备选与代价**：**把这些内容也发给模型**（here-document 正文、赋值的值、MCP 参数，经同样的长度、控制字符、脱敏与秘密值检查）。好处是配置了后端时这些调用仍由模型判断，询问更少；代价是发出去的内容变多：here-document 常常就是文件内容（`cat <<EOF > f`），MCP 参数里常有整段文件或正文，与 §9.2、§11 "不发文件内容"冲突，所以不建议。

### （不需要提案）F5

§9.1 已写"预算是每次尝试的硬期限"，修复只是让实现符合它。可以顺手在 §9.1 那句里加上"名字解析"四个字，算文字澄清。

## 8. 需要你决定的事项

1. **P-F1**：选 A（项目标记 + 终端命令解除，建议）/ B / C / D。决定之后我先改规格再实现，并把 strict xfail 测试转正。
2. **P-F6**：选 A（只被改成 ask 的调用消耗窗口，建议，同时把默认 `window` 改为 3）/ B（LLM 路径也用粘性位）/ C / D。M3b 接入真实后端之前需要定。
3. **P-F2**：要不要先做 hook 实测、再把 MCP 资源工具加进默认来源（建议要；它会改规则，要重新生成评测）。
4. **P-F34**：接受已实现的"不送审"（建议），还是改成把这些内容发给模型。
5. **`trusted_projects` 是否推荐**：建议在 F1 落地之前继续不推荐；F1 按 A 实现之后再议。
6. **`docs/reviews/M3a-security-review.md`**：残缺且未跟踪、`ruff format --check` 不过。删掉、原样提交、还是格式化后提交，由你决定。
7. **定向复审**：F3–F5 改了归一化层、管线与适配器，F1 / F6 还没做。建议等 F1、F6 实现之后，一起做一次定向 X1 复审（同时补上 F7–F13 拿不到的部分），再决定是否打 `m3a-done`。
8. **提交**：建议两次。代码：`src/boundkeep/audit/backends/openai_compatible.py`、`src/boundkeep/daemon/pipeline.py`、`src/boundkeep/normalize/bash.py`、`src/boundkeep/normalize/event.py`、`src/boundkeep/normalize/model.py`、`tests/unit/test_m3a_x1_fixes.py`、`tests/unit/test_m3a_review_fixes.py`、`tests/e2e/test_hook_client_process.py`；文档：`docs/reports/M3a-review-fixes.md`、`docs/threat-model.md`、`docs/privacy.md`、`docs/architecture.md`、`CLAUDE.md`。不推送、不打标签。

## 9. 进入下一步的前置条件

- 你对第 8 节第 1 到 4 条做决定；F1、F6（以及选了的话 P-F2）按规格先改、再实现、再测；
- 定向复审之后高危、中危清零，再由你决定是否打 `m3a-done`；
- M4、M5 不依赖这些修复，可以并行；M3b 要在 F6 落地之后、由你自备密钥。
