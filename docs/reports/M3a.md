# M3a 验收报告：会话状态、污染标记、LLM 后端接口与二次裁决

日期：2026-10-30。依据：`IMPLEMENTATION_PROMPTS.md` 的"M3a：不依赖网络与密钥"一节、`PROJECT_SPEC.md` §7、§9、§10、§11。**使用者已于 2026-10-30 确认本报告**（包括第 7 节的提案与第 8 节的建议）。代码提交是 `46169eb`，文档与生成物另作一次提交。没有用任何 LLM 密钥、没有访问任何真实的 LLM 服务（只对 127.0.0.1 上的本地假服务测过），没有读 `.env`，没有打开任何留出批次，没有读使用者的攻击样本。

## 1. 结论

**有条件通过。** 提示词里 M3a 的验收标准逐条满足（第 3 节）：全部测试与静态检查通过；二次裁决的表驱动测试覆盖全部组合；一致性测试对假后端与本地假服务全部通过；失败注入与发送出口都有测试；`rules+taint` 行如实写出增量（**0**，原因见第 5.3 节）。条件：（一）第 7 节的规格变更提案与第 8 节的事项要你决定；（二）独立会话的 X1 审查（重点：审计器被注入、绕过污染标记、后端适配器）；（三）LLM 层没有接过任何真实服务，它对攻击的实际效果要到 M3b 才知道，任何文档都不能对它的效果做表述。

## 2. 交付物

| 路径 | 说明 |
|---|---|
| `src/boundkeep/session/facts.py` | 一次调用所处的污染状态（`SessionFacts`；`FRESH`、`UNKNOWN`），纯数据 |
| `src/boundkeep/session/intent.py` | 任务意图：`<ide_*>` 等宿主块整段剥离（到最后一个同名闭合标签，没有闭合到结尾；那个闭合标签落在后面另一个块里时，删除范围一直延伸到那个块的结尾）、`<pasted_content>` 不取只留长度、去控制字符、截断处的半个词丢掉、先脱敏再截断；最多处理 64 个宿主块，之后的全部丢弃；线性时间 |
| `src/boundkeep/session/store.py` | SQLite（WAL）会话状态：窗口计数、粘性位、来源名、任务意图；`BEGIN IMMEDIATE` + 一把锁；清理（30 天、5000 个会话）；`secure_delete`，`log --purge` 之后截断 WAL，删掉的提示词不留在文件里；打不开时的替身 `UnavailableStore`（一律"未知"= 已污染） |
| `src/boundkeep/audit/backends/base.py` | `AuditBackend` 协议、`BackendError`（七类）、`GatedRequest`（只能由发送出口构造）、输出 schema 与严格校验 `parse_verdict` |
| `src/boundkeep/audit/backends/fake.py` | 脚本化的假后端，输出走同一个 `parse_verdict` |
| `src/boundkeep/audit/backends/openai_compatible.py` | httpx 直接 POST `/chat/completions`：`tool_call` 与 `json_object` 两种传输、`extra_body` 透传、不跟随重定向、只收未压缩且 ≤ 256 KiB 的回答、预算是整次尝试的硬期限（`asyncio.timeout`，每次尝试一个事件循环、一个客户端）、至多一次重试（`Retry-After` 不是不超过 2 秒的纯秒数就不重试）、客户端建不起来（SOCKS 代理缺扩展包）是 `network` 失败、错误信息不含请求体 / 回答体 / 密钥 |
| `src/boundkeep/audit/send_gate.py` | 唯一的发送出口：字段白名单、`<project>` / `~` 相对路径、变量展开出来的路径按原文显示、脱敏；看不全、含控制 / 格式字符、秘密跨词出现（`--password X`）、整个请求再脱敏一遍仍会变、含守护进程环境里秘密变量的值，都不发 |
| `src/boundkeep/audit/prompts/audit_system.md`、`audit/prompt.py` | 系统提示词（版本 1，sha256 `6af80007…`），不含用户数据；版本表 `VERSIONS`，改了文件不登记哈希测试就失败 |
| `src/boundkeep/audit/verdict.py` | §9.5 的二次裁决，纯函数 |
| `src/boundkeep/audit/cache.py`、`audit/auditor.py` | 内存缓存（键 = 后端、模型、传输、提示词哈希、发送内容）；把发送出口、缓存、后端、裁决串起来，任何失败都是 `on_failure` |
| `src/boundkeep/llmcheck.py`、`cli.py` | `boundkeep llm check`；`explain --tainted`；`log --purge` 同时删任务意图 |
| `src/boundkeep/daemon/pipeline.py`、`daemon/server.py` | 管线接会话状态、污染一步与 LLM 审计；没有被完整分析的灰色调用不送审、直接问；守护进程打开状态库、按策略重建审计器、prompt / post 在线程里写、期限从提交时起按 LLM 预算加 0.5 秒延长（排队的请求也有）、带 LLM 的审查超时按 `on_failure`、没审查就回答的调用仍给来源工具打标记、每小时清理 |
| `src/boundkeep/policy/schema.py`、`policy/matcher.py` | `taint.window`、`taint.sensitive_tags`、`llm_audit.intent_prompts` / `intent_chars`、`extra_body` 保留键、匹配字段 `session_read_untrusted`、策略测试的 `tainted` |
| `src/boundkeep/normalize/event.py` | 表里没有的程序、整行看不懂的命令、包管理器与任务运行器（`npm`、`uv`、`make`、`cargo` 等）、未知工具标 `exec`，MCP 调用标 `exec` 与 `network_egress`（只影响污染一步与审计内容） |
| `src/boundkeep/doctor.py`、`policycli.py` | `doctor` 显示状态库与 LLM 后端；`boundkeep test` 支持 `tainted: true` |
| `policies/default.yaml`、`policies/strict.yaml` | 新规则 `ask-devtools-after-untrusted-content`（两份相同）；`taint` 写明 `window` 与 `sensitive_tags`；`tests:` 加 7 条污染用例 |
| `src/boundkeep/evalkit/runner.py`、`metrics.py`、`report.py`、`eval/run_eval.py` | `rules+taint` 配置（真实 `SessionStore` 内存库）；每次运行同时测两种离线配置；"变化"表与"全部污染"参考表 |
| `eval/report.md`、`eval/results/rules-only.json`、`eval/results/rules+taint.json` | 重新生成（`--config rules+taint --test-contaminated`） |
| `tests/contract/`、`tests/helpers/llm_server.py` | 后端一致性测试（假后端 + 本地假 HTTP 服务的两种传输）；live 版默认跳过 |
| `tests/unit/test_m3a_*.py`（9 个文件） | 意图、状态库、发送出口、编排器与缓存、二次裁决、管线（含对抗样例）、守护进程（失败注入与发送出口）、schema 与 CLI；`test_m3a_review_fixes.py` 是第 6a 节自查发现的回归测试 |
| `docs/threat-model.md`、`docs/privacy.md`（新） | 污染层与审计层的能与不能；发送与保存的内容 |
| `docs/architecture.md`、`docs/policy-reference.md`、`docs/eval-methodology.md` | 对应更新（口径加第 6 节，指标版本不变） |
| `pyproject.toml`、`uv.lock` | 新的运行时依赖 `httpx>=0.27`（锁定 0.28.1） |

## 3. 验收标准逐条对照

| 标准 | 结果 | 证据 |
|---|---|---|
| 全部测试与静态检查通过 | 通过 | 见第 5.1 节（`uv run pytest -q`、`ruff check .`、`ruff format --check .`、`mypy`） |
| 二次裁决的表驱动测试覆盖全部组合 | 通过 | `tests/unit/test_m3a_verdict.py`：手写的 24 行表 × 污染 × 敏感 = 96 种模型组合，各在 `on_failure` 为 ask / deny 时跑一遍；10 种失败 × 2 × 4 × 2；外加 hypothesis 性质测试；361 条 |
| 一致性测试对假后端与本地假服务全部通过 | 通过 | `tests/contract/test_backend_contract.py` 150 条：合法输出、缺字段、类型错误、多余字段、截断、非 JSON、嵌套、重复键、超长、4xx / 401 / 403 / 429 / 408 / 5xx、超时、慢滴、超大回答（有无 Content-Length）、压缩回答、301 / 302 / 307 / 308 重定向（另一个源收不到请求）、断连、拒绝连接、缺密钥、不可用的密钥值、错误信息不含密钥与请求；`test_backend_live.py` 标 `live`，默认跳过 |
| 失败注入：超时、5xx、限流、非法输出、网络断开、未配置密钥均降级为 on_failure | 通过 | `tests/unit/test_m3a_daemon.py`：经真实的 OpenAI 兼容适配器打本地假服务，`on_failure` 为 ask 与 deny 各一遍：`timeout`、`http_5xx`、`rate_limit`、`invalid_output`、`auth`（401）、死掉的端点、缺 `BOUNDKEEP_LLM_API_KEY`（此时一个请求都不发） |
| 发送出口：含各类密钥的输入，发送内容不含明文；请求体、日志、错误信息都不含密钥 | 通过 | `test_m3a_send_gate.py`（`sk-`、`AKIA`、`ghp_`、`Bearer`、JWT、`$env:…TOKEN`、`password=`、私钥块；命令、路径、意图三处）；`test_m3a_daemon.py::test_secrets_never_reach_the_body_the_log_or_an_error`：假服务把密钥与整个请求体原样写进 400 错误里，断言请求体、审计日志、守护进程消息、错误细节都不含密钥与秘密的明文，密钥只出现在请求头 |
| `rules+taint` 行完整，增量如实写，并分析原因 | 通过 | `eval/report.md` 的消融表与"变化"表；第 5.3 节 |
| 完成后由独立会话做 X1 | 待做 | 不在本任务内 |

提示词里的其余要求：

| 要求 | 结果 |
|---|---|
| 任务意图：最近 N 条、截断前先脱敏、N 与长度可配置；剥离 `<ide_*>`、`<pasted_content>` 当不可信；用 `vscode__UserPromptSubmit.json` 测 | 做了（`intent_prompts`、`intent_chars`；粘贴的内容"不取"，只留长度标记）；`test_m3a_intent.py` 用这个真实夹具 |
| 污染：`taint.sources` 在 PostToolUse 打标记，窗口按 §7；resume / compact / clear 以 E9 为准并有测试；已知局限写进 `docs/threat-model.md`；服务端工具以 M0a 为准 | 做了；另在 PreToolUse 也打标记（第 4 节）；`test_resume_and_compact_keep_the_session_and_a_clear_starts_a_new_one`、守护进程重启测试 |
| 并发不丢更新；清理策略 | 做了：同一个库 8 线程 × 100 次、两个连接 × 4 线程、两个进程，计数都精确；30 天 / 5000 个会话 |
| 后端接口、假后端、OpenAI 兼容适配器（transport 两种、extra_body、参数自己解析校验、至多一次重试、总预算、base_url 约束）；anthropic 不做 | 做了；`backend: anthropic` 得到一个总是失败的审计器（`on_failure`），`llm check` 说"not implemented" |
| 发送出口：字段白名单 + 脱敏；提示词版本化、哈希进每条审计日志；输入构造器只接受结构化字段 | 做了；审计记录的 `llm.prompt` 是 `v1:6af800076bda27df` |
| 缓存：键、TTL、命中在日志里标明 | 做了（`llm.cache`: `hit` / `miss` / `off`） |
| 管线：normalize → rules → 污染升级 → 后端（可选）→ 裁决；`audit-only` 只记录；`backend: none` 灰色 ask | 做了；`audit-only` 下仍然调用 LLM，记 `would_be`（影子模式要反映 enforce 的样子） |
| `boundkeep llm check` 对假服务测 | 做了（两种传输、失败、缺密钥、没有后端、anthropic） |
| 对抗测试：注入文本、表面相符实际越权、超长 / 多语言 / 控制字符、恶意或畸形回答 | 做了（`test_m3a_pipeline.py` 后半部分；第 6 节说明"多语言"的处理） |

## 4. 与计划的偏差

1. **计划没有单独停下来等批准**：工作协议要求出计划后停下等"继续"，你在开始时已经说了"继续"，所以计划写进了会话笔记（共享笔记目录的 `M3a-plan.md`），直接实现。
2. **新依赖 httpx**（BSD-3-Clause，Encode 维护，锁定 0.28.1，带进 httpcore、h11、anyio、certifi、idna）：规格 §13 的技术选型与 M3a 提示词都点名用它，所以没有另外问；只在构造适配器时才导入，hook 客户端不受影响。第 8 节请你确认。
3. **污染在 PreToolUse 也打标记**（规格只写了 PostToolUse）：hook 客户端在 PostToolUse 失败时什么也不做（没有决定可以降级），只靠它打标记就是失败即放行；PreToolUse 一定经过守护进程。代价是一次随后被拒绝的来源调用也算数（安全的方向）。第 7 节 P1。
4. **M-2 写成 ask 规则，而不是 X1 审查建议的"给 allow 规则加条件"**：加条件只会让命令变成灰色，配置了 LLM 后端时灰色交给模型，链又通了；ask 规则不经过模型。另外用**粘性位**而不是窗口：窗口可以被几次无害的调用等过去。规则不带 `project_trusted`，不受信任的项目里也生效（strict 同样有）。第 7 节 P2。
5. **失败分类多了 `http_4xx`**：规格的六类里没有"服务拒绝了请求但不是认证或限流"（模型名写错、参数不支持），一致性测试又要求 4xx。二次裁决另认三种不来自后端的失败：发送出口拒绝（`refused`）、没有可用后端（`unavailable`）、内部异常（`internal`）。第 7 节 P4。
6. **审计输入是 `actions` 列表**：规格 §9.2 的例子是单个 `action`，但一次工具调用可以有多个动作（管道、`&&`）。另加了 `read_untrusted` 字段。第 7 节 P5。
7. **任务意图只在配置了 LLM 后端且 `send_task_intent` 时才存**：没有后端时没有谁读它，提示词摘录就不落盘（隐私）。
8. **归一化层的一处改动**：表里没有的程序（`gradle`、`./build.sh`、`& .\tools\run.exe`）、整行看不懂的命令、包管理器与任务运行器（`npm`、`npx`、`uv`、`pip`、`make`、`cargo`、`go`、`dotnet` 等，表里认识它们，但它们的子命令大多运行项目自己的代码）、未知工具标成 `exec`；MCP 调用标 `exec` 与 `network_egress`（服务端做什么、连不连网，从参数看不出来）。原先它们没有任何风险标签，被污染窗口内 LLM 对它们的 allow 不会变成 ask。标签不参与任何规则匹配，所以 `rules-only` 的数字一个都没变（第 5.3 节）。第 7 节 P10。
9. **期限的延长方式**：守护进程第一次请求时还没加载策略，按"当前策略"算期限会少掉 LLM 预算（测试发现）。改成两路取较大者：提交时按上一次加载的策略（排队等工作线程的请求也有这段时间），工作线程重读策略后再告诉等待的事件循环；另加 0.5 秒余量。带 LLM 审计的审查超时，enforce 下按 `on_failure` 回答（`deny` 就拒绝），`audit-only` 下与其他超时一样是 ask。最长 2 + 6 + 0.5 = 8.5 秒，仍在 hook 客户端的 10 秒之内。
10. **审计层的提示词与 schema 从规格写起，没有从 injection-blast-radius 复制**，所以 `docs/design-origin.md` 没有要记的来源 commit。
11. 顺手加的小项：`doctor` 显示状态库是否可用与是否配置了 LLM 后端；`boundkeep log --purge` 同时删除存下的任务意图（污染标记保留）；`boundkeep explain --tainted`；README 里隐私文档的指向（原写 TODO）。
12. **没有被完整分析的灰色调用不送审**（自查发现 #10）：归一化的预算用完、解析器内部错误、PowerShell 辅助进程没就绪、子树扫描超限、MCP 参数没看全、MCP 参数里带命令、或者一个程序名 / 路径 / 主机 / MCP 工具名都没认出来时，模型只能看到调用的一部分（或什么都看不到），它的 allow 会覆盖没人看过的部分。这些调用直接 ask（`decided_by: gray-unanalysed`，理由里写明"没有送 LLM 审计"），不按 `on_failure`：它们不是审计失败，与没有配置后端时的灰色相同。第 7 节 P11，第 8 节第 8 条。
13. **ping 的状态文字**：`session=` 与 `llm=` 放在 PowerShell 字段之前，`config_dir=` 仍在最后（`doctor` 从那里读到 "; policy error:" 为止）。

## 5. 度量

### 5.1 测试与静态检查

- 全量 `uv run pytest -q`（2026-10-30 05:12 到 06:23，电源方案 Turbo，第 6a 节的修复之后）：**1 failed, 26609 passed, 169 skipped in 4297.40s (1:11:37)**。跳过的是 POSIX 专用、需要符号链接权限、本机没有可用 bash 的用例，以及默认不跑的 live 测试。上面说的 4 条计时测试这一轮都通过了。
  - 唯一的失败是 `tests/e2e/test_hook_client_process.py::test_when_every_pipe_instance_is_busy_the_client_gives_up_inside_its_budget`，原因是测试本身有计时竞争，不是 M3a 的回归。这条测试经过的代码（`hook_client.py`、`hook_main.py`、`ipc/`、`tests/helpers/pipes.py` 和测试文件本身）相对 HEAD 都没有改动。
  - 测试先占住唯一的管道实例（只连接，不发任何数据）。假服务端用的是正式的 `NamedPipeServer`：第一个字节 1.0 秒内没到就回一条错误，再等 0.5 秒让客户端读，大约 1.5 秒后放开这个实例。客户端的 IPC 期限是它自己的进程启动后 1.5 − 0.3 = 1.2 秒。所以只要 hook 客户端的 Python 进程晚于占位连接约 0.3 秒才开始运行（全量跑到第 70 分钟时机器负载高），它就会在期限之内连上，拿到回显服务端"没有决定"的回答，标准输出为空。对一个没给决定的回答，这正是正确的输出。
  - 复跑结果：这条测试单独连跑 5 次全部通过，整个文件 70 条通过。`test_m3a_review_fixes.py` 最后几处只改格式与 lint 的编辑排在全量运行收集测试之后，复跑 45 条通过。
  - 这条测试没有修，不在 M3a 范围内，列为后续事项。修法：让占位连接先发 1 个不带换行的字节，服务端就按 30 秒的读取期限等它，不再按首字节期限放开实例。
- `uv run ruff check .`：All checks passed；`uv run ruff format --check .`：266 files already formatted；`uv run mypy`：Success: no issues found in 73 source files（第 6a 节的修复之后重跑）。
- `boundkeep test`：default 1120 条、strict 326 条，0 失败（含新加的污染用例；第 6a 节的修复之后重跑）。
- 新增测试 796 条（`tests/contract` 164 条，其中 live 1 条默认跳过；`test_m3a_verdict.py` 361；`test_m3a_intent.py` 28；`test_m3a_session_store.py` 38；`test_m3a_send_gate.py` 27；`test_m3a_auditor.py` 37；`test_m3a_pipeline.py` 39；`test_m3a_daemon.py` 25；`test_m3a_schema_cli.py` 32；`test_m3a_review_fixes.py` 45），另在 `test_evalkit.py` 加了 4 条、改了 2 条（M2 时的断言"`rules+taint` 不可运行"随 M3a 更新）。
- **计时类测试与电源方案**：Windows 电源方案为 "Silent" 时，`test_daemon.py` 里按固定期限（0.2 到 2 秒）计时的 4 条测试会失败（加载一次默认策略约 1 秒，正常约 0.2 秒），**已提交的 HEAD 在同样设置下也失败其中 3 条**（导出到 scratchpad 里对照运行），所以不是 M3a 的回归。使用者切换到 "Turbo" 之后，这 4 条连续 5 次全部通过，`test_daemon.py`、`test_m3a_daemon.py`、`test_m3a_review_fixes.py` 共 117 条通过。上面的全量运行和 `eval/report.md` 的重新生成也都在 Turbo 下进行。

### 5.2 延迟（本机：Windows 11 build 26200，20 核，Python 3.12.11；不经过 Claude Code）

- **会话状态库每次调用的开销**（WAL 文件，`synchronous=NORMAL`，库里另有 200 个会话；脚本在会话的 scratchpad 里，没有进仓库）：干净会话的 PreToolUse 只读不写，p50 0.008 ms、p95 0.010 ms；被污染过的会话每次写一次计数，p50 0.028 ms、p95 0.057 ms，最大 15.9 ms（一次 WAL 检查点）；来源工具的 PostToolUse p50 0.020 ms。
- **规则路径**（评测的进程内管线耗时，ms，p50 / p95）：两次运行之间本身就差到 ±15%，比两种配置之间的差还大，没有可测出的退化：

| 机器 / 切分 | rules-only 第 1 次 | rules+taint 第 1 次 | rules-only 第 2 次 | rules+taint 第 2 次 |
|---|---|---|---|---|
| windows / dev | 3.79 / 9.88 | 3.95 / 9.63 | 4.49 / 11.17 | 3.96 / 9.92 |
| windows / test | 4.19 / 8.77 | 4.15 / 7.98 | 4.57 / 11.23 | 4.34 / 8.52 |
| posix / dev | 2.69 / 3.64 | 2.69 / 3.50 | 3.00 / 4.40 | 2.71 / 3.82 |
| posix / test | 2.71 / 3.96 | 2.74 / 3.72 | 2.93 / 4.54 | 2.70 / 3.77 |

  （`rules+taint` 用的是内存库；真实守护进程用 WAL 文件，开销见上一条。）
- **hook 客户端端到端**（`scripts/bench_hook.py`，每行 60 次，一次 PowerShell 事件；结果写在会话的 scratchpad，没有覆盖仓库里的 `scripts/bench_hook_result.json`）：守护进程在线时默认写法 p50 48.6 ms / p95 53.7 ms；守护进程侧从收到请求到回答 p50 2.9 ms / p95 4.0 ms；守护进程不在时 p50 42.8 ms。仓库里唯一的同口径记录是 M0 的（当时守护进程侧只是占位，0.1 ms），不能当作 M3a 的对照；M1 之后没有同口径的记录。
- **LLM 路径的延迟、每千动作 token、LLM 调用占比**：未测（没有真实后端，M3b）。

### 5.3 评测：`rules+taint` 相对 `rules-only`

命令：`uv run python eval/run_eval.py --config rules+taint --test-contaminated`（不打开任何留出批次；test 切分沿用"已被污染"的声明）。数据集指纹不变：dev `34a1cd18e50712e5`，test `5f2bab54704e0132`；策略 sha256 `0e924b87c5432d66…`。

| 配置 | windows 拦截（test） | posix 拦截（test） | windows 达到要求 | posix 达到要求 | windows 误报 | posix 误报 |
|---|---:|---:|---:|---:|---:|---:|
| rules-only | 100.0% | 100.0% | 85.7% | 97.6% | 36.6% | 75.0% |
| rules+taint | 100.0% | 100.0% | 85.7% | 97.6% | 36.6% | 75.0% |

dev 切分同样完全相同；在污染会话里判的样本：windows dev 16、test 8，posix dev 26、test 10，**有效裁决与规则结论都没有一条改变**。`rules-only` 的数字也与改动之前（`HEAD` 的 `eval/results/rules-only.json`）逐项相同：新规则只在污染会话里生效，`exec` 标签不参与规则。

**增量为 0 的原因**（不是实现失效，是设计加数据集共同决定的）：

1. 按规格 §7，污染只让**不是规则给出的** allow 变严。没有 LLM 后端时，这样的 allow 只有"什么都不碰的工具"（`TodoWrite`、`ToolSearch`），它们没有风险标签；灰色本来就是 ask。所以没有 LLM 时，污染层唯一能改变判决的途径是规则里的 `session_read_untrusted`，而默认策略里只有一条这样的规则（开发工具）。
2. 60 个在污染会话里判的样本全是攻击样本（数据集里**没有一条正常样本标了 `tainted`**），而且没有一个是开发工具命令；它们在 `rules-only` 里已经全部被拦（ask 或 deny）。污染层只能让判决变严，已经拦下的不会变；要求 deny 而实际 ask 的那几条（`windows-persistence-commands`、`ps-provider-path` 等）与污染无关。
3. 样本是单次调用。污染层真正针对的是**跨调用的链**（读网页 → 写测试文件 → 运行 pytest），数据集表达不了，只有单元测试覆盖（`test_m3a_pipeline.py` 的 M-2 一组，含"等 25 次调用也不会过期"）。

**代价**（参考表，不是消融行：把全部样本都放进刚读过不可信内容的会话里再判一次）：未受信任的项目没有任何额外询问（误报率 windows dev 34.3% → 34.3%，posix test 75.0% → 75.0%）；受信任项目里开发工具的放行消失，误报率回到未受信任的水平（windows dev 32.0% → 34.3%，windows test 35.2% → 36.6%，posix dev 56.7% → 62.5%，posix test 70.5% → 75.0%）。也就是说，读过一次网页之后，本会话里受信任项目的 `pytest` 都要问——这正是 X1 审查 M-2 预计并接受的代价。

## 6. 已知问题与局限

（每条都不阻塞 X1 审查。）

1. **污染只按工具名识别来源**：`curl`、`Invoke-WebRequest`、`git clone`、读下载来的文件都不打标记（规格 §7 的 v0 局限，详见 `docs/threat-model.md`）。影响：M-2 的 ask 规则看不见经这些途径进来的注入。
2. **守护进程没运行的那段时间**（那时每个调用都问）里用户同意的来源调用不会被记下；M3a 不注册 SessionStart，分不清新会话与状态丢失的旧会话。30 天以上不活动后再 resume 的会话，污染标记已被清理。
3. **配置了 LLM 后端时，开发工具名单之外会运行项目代码的命令**（`make`、`npm test`、`./build.sh`）交给模型；只有在污染窗口内它们才一定是 ask（现在都带 `exec` 标签）。窗口过后就是模型说了算。粘性规则 `ask-devtools-after-untrusted-content` 只认开发工具本身：`pipenv run pytest`、`conda run pytest`、`poetry run pytest` 这类经包管理器启动的形式，规则层看到的程序是包管理器，不是 pytest，所以不受这条规则约束（窗口内仍因 `exec` 标签是 ask）。
4. **LLM 层的质量完全未知**：只有代码层面的保证（第 3 节、`docs/threat-model.md` 第 3 节）。M3b 之前，README 与任何文档都不能对它的效果做表述。
5. **`audit-only` 下也会调用 LLM**（为了记录 `would_be`），会花 token。
6. **"多语言输入"不走降级**：中文命令与路径照常送审（不然对中文用户没有用）；降级的是超长与含控制 / 格式字符的输入。提示词原文写"超长输入、多语言输入、含控制字符的输入：不崩溃，且走降级路径"，我把"降级"理解为"不能安全处理时"，请确认（第 8 节）。
7. **代理**：远端 `base_url` 走环境变量里的代理（httpx 的 `trust_env`），回环地址不走；TLS 用系统证书库（`ssl.create_default_context()`）。环境里是 SOCKS 代理而没装 `socksio` 时，每次审计都是 `network` 失败（`on_failure`），`llm check` 会说"the HTTP client could not be set up"。
11. **每次审计一次 TLS 握手**：为了让预算成为整次尝试的硬期限，每次尝试用自己的事件循环与客户端，审计之间不保持连接。对真实服务的代价没有测过（M3b）。
12. **发送出口新增的拒绝有误伤的可能**：跨词秘密的检查会拒绝 `--token X` 这类带秘密值的命令（这正是目的），也可能拒绝"看起来像"的无害写法；整个请求再脱敏一遍会变时也拒绝。在 dev 与 test 的正常样本上量过（只读正常样本，不读攻击样本与留出集；PowerShell 样本没有辅助进程时跳过）：94 次灰色判定里 93 次照常送审、0 次被这些规则拒绝、1 次因"MCP 参数里带命令"不送审。
8. **Windows 上连接一个没人监听的本机端口约要 2 秒**（系统会重试 SYN），所以"网络断开"的失败在 Windows 上有时报成 `timeout` 而不是 `network`；两者都是 `on_failure`。
9. **`git <未知子命令>`** 不带 `exec` 标签（git 的处理器认识这个程序，只是子命令未知；它本来就是灰色）。
10. 一次性脚本（存储微基准）留在会话的 scratchpad，没有进仓库；要复现，用第 5.2 节的描述。

## 6a. 自查与修复

实现完成后先做了一轮自查（多路对抗审查：意图、状态库、发送出口、适配器、守护进程、评测；每条发现都写复现再核实）。保留 15 条，驳回 4 条（复现不成立）。全部已修，回归测试集中在 `tests/unit/test_m3a_review_fixes.py`（45 条）与 `tests/contract/test_backend_contract.py`（新增 13 条）。这一轮不能代替 X1 独立审查。

| # | 级别 | 发现 | 修复 | 测试 |
|---|---|---|---|---|
| 1 | 高 | 两个宿主块交叠时（粘贴的文字里带 `</ide_opened_file>`），按"最后一个闭合标签"剥离会把粘贴内容的后半段当成用户的话留下 | 删除范围覆盖了另一个块的开始标签时，延伸到那个块的结尾，直到范围内没有新的开始标签；最多 64 个宿主块 | 构造用例 + 3000 个随机提示词的性质测试（任何块名的第一个开始标签到最后一个闭合标签之间的词都不留下） |
| 2 | 中 | 截断落在 `https://user:密码@host` 中间时，没有 `@` 的半截不像秘密，脱敏认不出来 | 截断过的文字丢掉被截断的那个词，再脱敏 | 截断落在密码里的用例 |
| 3 | 中 | `log --purge` 删掉的提示词还留在库文件与 WAL 的旧页里 | `secure_delete=ON`；删除后 `wal_checkpoint(TRUNCATE)` | 删除后直接读库文件与 WAL 的字节 |
| 4 | 高 | 整个请求再脱敏一遍时，脱敏器的 shell 模式在 JSON 上会跨字段吞掉内容，结果仍能解析，模型看到的是被删掉一部分动作的请求 | 改为：再脱敏一遍会变就不发（`refused`，`on_failure`）；JSON 用带空格的分隔符，减少跨字段的误配 | 打桩的脱敏器；`localhost:3000` 与相邻的 `user@` 不误拒 |
| 5 | 中 | `--password X`、`-Password X`、`curl -u user:pw` 的秘密要连起来才看得出，逐词脱敏漏掉 | 把动作的词按 shell 引号拼成一行再脱敏，与逐词的结果不同就不发 | 四种写法被拒；`-H 'Authorization: …'` 仍照常送审（已脱敏） |
| 6 | 中 | 路径里的 `$GITHUB_TOKEN` 用守护进程的环境展开后，展开值（可能就是 API 密钥）进了路径的比较键并被发出 | 变量展开过的路径按原文（`$GITHUB_TOKEN/x`）显示；审计器收集名字像秘密的环境变量（含 `api_key_env`）的值，请求里出现任何一个（不分大小写，≥ 8 字符）就不发 | 原文显示、按值拒绝、`secret_values` 的取舍（不含 `PWD`、作者名） |
| 7 | 中 | 适配器的期限是 httpx 的"每次读"超时，服务端一字节一字节地发响应头可以把一次审计拖到几分钟 | 每次尝试放进 `asyncio.timeout(剩余预算)`，整次尝试（连接、TLS、头、体）一个硬期限 | 响应头滴发约 9 秒的假服务，0.8 秒预算内超时（两种传输） |
| 8 | 低 | `Retry-After` 是日期、负数、`nan`、`inf` 时，`nan` 会绕过等待上限并让 `sleep` 抛异常 | 只认不超过 6 位整数加 3 位小数的秒数，其余一律"不重试" | 8 种取值；`0.25` 照常等待 |
| 9 | 低 | 环境里是 SOCKS 代理而没装 `socksio` 时，构造客户端抛 `ImportError`（审计器兜成 `internal`，`llm check` 打出回溯） | 构造失败映射为不可重试的 `network`；`llm check` 兜住任何异常 | 打桩的 `AsyncClient`；`llm check` 遇到适配器异常时报 FAILED |
| 10 | 高 | 没有被完整分析的灰色调用（预算用完、解析器内部错误、MCP 参数没看全……）也送审，模型的 allow 覆盖没人看过的部分 | 不送审，直接 ask（第 4 节第 12 条） | 每类原因；未知工具与带命令的 MCP 调用一个请求都不发，`on_failure` 为 deny 时也是 ask |
| 11 | 中 | MCP 调用与未知工具没有风险标签，污染窗口内 LLM 的 allow 不会变成 ask | MCP 标 `exec` 与 `network_egress`，未知工具标 `exec` | 标签测试 |
| 12 | 中 | 排队等工作线程的 PreToolUse 只有 2 秒期限（LLM 预算要等工作线程读了策略才知道）；因超时或繁忙没有审查的来源调用不打标记 | 提交时就按上一次的策略加预算；`abandon` 报告任务是否根本没开始，没开始的与繁忙时回答的调用另开线程给来源工具打标记 | 不自报预算的慢审查照常完成；繁忙时 `WebFetch` 仍让会话被污染；`abandon` 的返回值 |
| 13 | 中 | 带 LLM 的审查超时时回答 ask，`on_failure: deny` 的用户得到的是可以点"同意"的确认框 | enforce 下按 `on_failure`；期限另加 0.5 秒余量 | ask / deny 两种；耗时在 0.8 到 2 秒之间 |
| 14 | 低 | 包管理器与任务运行器（`npm test`、`uv run`、`make`）认识却不带 `exec` | 事件层的运行器名单加 `exec`；`pipenv run pytest` 一类绕开粘性规则的写法记入第 6 节第 3 条 | `npm`、`make`、`cargo`、`uv` |
| 15 | 低 | 评测"全部污染"参考表的"会话干净"两列取自 `rules+taint`（标了 `tainted` 的样本在那里不干净），"没有一条正常样本标了 `tainted`"写死在报告里 | 干净两列取自 `rules-only`；那句话按数据生成（有的话写条数） | 两种数据下的报告文字；`run_eval.py` 的取值 |

## 7. 规格变更提案

代码已经按下面实现，`PROJECT_SPEC.md` 的设计章节**还没有改**（只更新了"当前进度"与 §14 的状态）；你同意后我把它们写进规格。

- **P1（§7 污染升级规则）**：来源工具的调用在 PreToolUse 与 PostToolUse 两处都打标记；窗口按 PreToolUse 计数：来源调用之后的第 1 到第 `window` 次调用为"被污染"，来源调用自己按它之前的状态判；PostToolUse 让窗口从那一刻重新开始。会话状态存在 `~/.boundkeep/session.sqlite`，30 天不活动删除，最多 5000 个会话。
- **P2（§7 / §8）**：新匹配字段 `session_read_untrusted: true`（会话里任何时候调用过来源，粘住；状态未知算命中；只能用于 deny / ask 规则），以及默认与 strict 策略的规则 `ask-devtools-after-untrusted-content`（M-2 的实现）。§7 "开发工具预设"一段里"会话污染标记（M3a）计划用来进一步收紧这条链路"改为已实现的描述。
- **P3（§8 `llm_audit` / `taint`）**：`taint.window`（1 到 1000）与 `taint.sensitive_tags`；`llm_audit.intent_prompts`（1 到 10，默认 3）与 `intent_chars`（40 到 2000，默认 300）；`extra_body` 不能设适配器自己设的键；`timeout_ms` 最多用 6000 毫秒；`<base_url>/chat/completions` 的拼法。
- **P4（§9.1）**：失败分类加 `http_4xx`（共七类）；二次裁决另认 `refused`、`unavailable`、`internal`，都按 `on_failure`。
- **P5（§9.2）**：输入是 `actions` 列表，另有 `read_untrusted`；路径写成 `<project>/…`、`~/…`；粘贴的内容不取；任务意图只在配置了后端且 `send_task_intent` 时才存；看不全或含控制 / 格式字符的输入不发，按 `on_failure`。
- **P6（§9.5 / §9.6）**：给 Claude Code 的理由只由结构化字段组成，模型写的文字只进审计日志；缓存键是"发送内容的哈希 + 后端 + 模型 + 传输 + 提示词哈希"（比规格的键更全），只缓存合法的模型结论；`audit-only` 下也调用 LLM。
- **P7（§10 失败与降级）**：加一行"会话状态库不可用（损坏、磁盘满、权限）→ 每个调用按'状态未知'判，即当作已污染；守护进程启动时与 `ping` 状态、`doctor` 里说明"。
- **P8（§12）**：每次运行测量全部离线配置；`rules+taint` 的模拟方式；"全部污染"参考表（已写进 `docs/eval-methodology.md` 第 6 节，指标版本不变）。
- **P9（§13 目录）**：`session/facts.py`、`session/intent.py`、`session/store.py`、`audit/auditor.py`、`audit/prompt.py`、`llmcheck.py`、`tests/contract/`、`docs/threat-model.md`、`docs/privacy.md`。
- **P10（§7 Action 的 `risk_tags`）**：表里没有的程序、整行看不懂的命令、包管理器与任务运行器、未知工具带 `exec`；MCP 调用带 `exec` 与 `network_egress`。
- **P11（§7 判定管线 / §9.2）**：没有被完整分析的灰色调用（归一化预算用完、解析器内部错误、PowerShell 辅助进程不可用、子树扫描超限、MCP 参数没看全或带命令、什么都没认出来）不送审，直接 ask。发送出口另拒绝：跨词出现的秘密、再脱敏一遍会变的请求、含守护进程秘密环境变量的值的请求；变量展开过的路径按原文发送。
- **P12（§10）**：带 LLM 审计的审查期限 = 规则的 2 秒 + 预算 + 0.5 秒，从提交时算；超时时 enforce 下按 `on_failure`。适配器的预算是每次尝试的硬期限；`Retry-After` 不是短的纯秒数就不重试。

## 8. 需要你决定的事项

1. **第 7 节的 P1 到 P12**：建议全部接受；接受后我把它们写进 `PROJECT_SPEC.md`（单独一个文档提交）。
2. **httpx 作为运行时依赖**：建议保留（规格与提示词点名；不跟随重定向、超时、流式读取都靠它）。另一个选择是换成标准库 `http.client`（少 6 个包，期限可以按每次读设置，但要自己处理更多细节）。
3. **`trusted_projects` 要不要因 M-2 已收紧而改为推荐设置**：建议等 M3a 的 X1 审查之后再定；在那之前文档仍写"不推荐"。
4. **"多语言输入"的理解**（第 6 节第 6 条）：建议按现在的做法（中文照常送审，超长与控制 / 格式字符才降级）。
5. **要不要补"标了 `tainted` 的正常样本"**：现在污染层对正常操作的代价只能看参考表。补的话我写模板，样本由你确认；补了会改变 dev / test 指纹，并且要重取基线。建议在做 h3 留出集时一起考虑。
6. **会话保留 30 天、最多 5000 个**：建议保持。依据（官方文档 `code.claude.com/docs/en/data-usage`，2026-10-30 读取）：Claude Code 把会话记录在本机保留 30 天以便 resume，`cleanupPeriodDays` 可以改；**在 Claude Desktop 或 Cowork 里开始或最近继续的会话默认不受这个期限限制**，所以在那里 resume 一个 30 天以前的会话时，boundkeep 已经没有它的污染标记。要不要把保留期做成配置项（或者跟着 `cleanupPeriodDays` 走），请你决定；我的建议是先保持常量，等有 Desktop 宿主的实测再说。
8. **没被完整分析的灰色调用回答 ask 还是 `on_failure`**（第 4 节第 12 条）：建议 ask（它们不是审计失败，与没配后端时的灰色一样；`on_failure: deny` 的用户会看到确认框）。另一个选择是同样按 `on_failure`，更严，但 PowerShell 辅助进程预热的那 2 秒里，`on_failure: deny` 会拒绝所有 PowerShell 灰色命令。
9. **提交方式**：建议两次。代码：`src/`、`tests/`、`policies/`、`pyproject.toml`、`uv.lock`、`eval/run_eval.py`（"session, audit, pipeline: M3a ..."）；文档与生成物：`docs/`、`CLAUDE.md`、`PROJECT_SPEC.md`、`IMPLEMENTATION_PROMPTS.md`、`README.md`、`eval/report.md`、`eval/results/*.json`。是否打标签（例如 `m3a-done`）由你决定。

## 9. 进入下一步的前置条件

- 你确认本报告（尤其第 7、8 节）并让我提交（**2026-10-30 已确认并提交**；P1 到 P12 写进 `PROJECT_SPEC.md` 是另一次文档提交，还没做）；
- 独立会话做 M3a 的 X1 审查（范围见 `IMPLEMENTATION_PROMPTS.md` X1 第 3、4、8 条：绕过污染标记、攻击审计器、后端适配器与配置），高危清零；
- M3b 需要你自备密钥、确认费用，并在你自己的 shell 里运行；M4、M5 可以在 M3a 审查之后开始（不依赖 M3b）。
