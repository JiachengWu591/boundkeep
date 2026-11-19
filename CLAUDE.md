# CLAUDE.md — boundkeep（守界）

## 项目是什么

编码 agent（首先是 Claude Code）的运行时动作审查层：挂在 hook 出口，对每个工具调用判定 allow / ask / deny。
三层：确定性规则 → 会话状态（任务意图 + 污染标记）→ 可选的 LLM 意图审计（仅灰色地带）。
LLM 后端可插拔（OpenAI 兼容接口，DeepSeek 为参考预设），默认关闭；关闭时灰色地带直接 ask，项目仍然完整可用。

完整设计见 `PROJECT_SPEC.md`，那是唯一事实来源。要改设计，先改规格，再改代码。

## 当前前提（不得违反）

- 开发使用 Claude Code 订阅。没有 Anthropic API 密钥，任何步骤都不得依赖 Anthropic API。
- 运行时 LLM 后端由用户自备密钥，只通过环境变量 `BOUNDKEEP_LLM_API_KEY` 提供。不读取 `ANTHROPIC_API_KEY`（它会改变 Claude Code 自身的计费路径）。
- 不得把订阅登录凭证、Agent SDK、`claude -p`、prompt hook 或 agent hook 用作运行时审计后端。
- 你（开发 agent）不持有任何 LLM 密钥，不读取 `.env`，不把密钥写入任何文件、日志、提示词、缓存或报告。需要真实调用时，写出命令，由用户在自己的 shell 里运行。
- 目标平台含 Windows 原生（开发机：Windows 11、简体中文、代码页 936，宿主是 VS Code 扩展，当前会话的 shell 工具是 `PowerShell`；M0a 要在 VS Code 扩展与 CLI 里分别测 hook，见规格 §5.1）、WSL2、macOS / Linux。"支持"按平台以实测为准，未实测的只写"设计目标"（规格 §5.1）。

## 开发前必读

1. `PROJECT_SPEC.md` 的 §4 设计原则、§5 官方文档核对结论、§5.1 平台支持、§7 判定管线、§9 LLM 审计层、§10 失败与降级。
   每个里程碑的实现提示词在 `IMPLEMENTATION_PROMPTS.md`，按其中的工作协议执行。
2. §16 的待验证清单：涉及 Claude Code 实际行为的部分，先写最小实验确认，再写实现。不要凭印象假设 hook 的字段名、退出码或 matcher 语法。
3. 涉及外部产品的事实（模型名、参数、价格、订阅与 API 政策），一律对照官方文档并记录日期，它们变动很快。

## 不可违反的原则

- 失败即关闭：任何出错、超时、解析失败，降级为 `ask`，绝不静默放行。
- hook 进程自身异常时，退出码只能是 0（并输出合法决定）或 2；非 0 非 2 会被 Claude Code 当成非阻断错误而放行。
- hook 客户端的 I/O 不依赖代码页或 `PYTHON*` 环境变量：按字节读 stdin、显式 UTF-8 解码，按字节写只含 ASCII 的 JSON。Windows 中文系统默认按 gbk 读 stdin：含中文的事件被悄悄读成乱码（`json.load(sys.stdin)` 不抛异常，文本却变了，规则匹配落空；孤立代理项还会在之后编码时崩溃，退出码 1 等于放行）（开发机实测，规格 §5.1；2026-10-07 更正了 M0a 原先"会抛 UnicodeDecodeError"的说法）。所有文本模式的文件读写都显式写 `encoding="utf-8"`。
- Windows 的 hook 通道是命名管道，由我们用 ctypes 自己创建并设置只授予当前用户的 DACL；标准库默认创建的管道对 Everyone 可读，不得使用。
- 不确定即灰色：命令解析失败、规则缺失、工具名未知，永远不会自动 allow。
- 不替用户做决定：判为 ALLOW 时默认返回"无决定"，只有 `defaults.emit_allow` 显式开启才输出 allow。
- 代码二次裁决：LLM 输出不被直接信任，最终判决由代码按 §9.5 计算。
- 发给 LLM 与写进日志的内容必须先过发送出口与脱敏；永远不发送文件内容和工具原始输出。
- LLM 后端地址是出站目标：只允许 https（本机回环地址除外），不跟随跨域重定向，限制响应体积，错误信息不回显请求体与密钥。
- 闸门被悄悄关闭（hook 路径错误、不可执行、disableAllHooks）只会得到非阻断提示，所以 `init` 自检与 `doctor` 检查不是可选项。
- boundkeep 不是沙箱，文档和 README 中不得暗示它提供强隔离。

## 不要做

- 不要在没有评测数据时，在 README 或文档里写拦截率、延迟、成本等数字。数字只来自 `eval/report.md`。
- 不要声明支持任何没有通过后端一致性测试、也没有真实运行过的 LLM 服务（包括本地模型）。LLM 结论按"后端 + 模型 + 版本 + 设置"分别报告，不跨模型外推。
- 不要声明支持未实测的平台（含 macOS / Linux）。平台与 LLM 后端同理：先有实测记录，再写"支持"。
- 不要在 v0 范围外加功能（Web 界面、其他 agent 适配、输入端内容审计）。想加，先改 §6。
- 不要为了通过评测而针对评测集写专用规则；规则应有独立于数据集的理由。
- 不要把 injection-blast-radius 的代码作为依赖引入；需要复用时复制，并在 `docs/design-origin.md` 记录来源 commit。
- 不要在代码或文档里写死模型名与价格；模型名是配置项。

## 常用命令

```
uv sync
uv run pytest -q                    # 默认不访问网络、不使用密钥；live 测试默认跳过（--live 开启）
uv run ruff check . ; uv run ruff format --check .
uv run mypy                         # strict，检查 src/
uv run boundkeep init --project-dir <一次性目录>   # 只在一次性目录里试，别写真实项目与用户级 settings
uv run boundkeep serve              # 常驻进程（手动启动；没启动时每个工具调用都会 ask）
uv run boundkeep doctor             # 检查 hook 配置、常驻进程、策略文件、闸门是否被悄悄关闭
uv run boundkeep mode [enforce|audit-only] ; uv run boundkeep log --tail 20
uv run python scripts/bench_hook.py        # hook 客户端延迟（真实进程，约 1 分钟）
uv run python scripts/smoke_claude.py      # 真实 Claude Code 冒烟（claude -p，haiku，几美分；手工运行）
uv run python scripts/smoke_claude_m3a.py  # M3a 会话层的真实冒烟（fork、项目标记、询问计数，修订 10 到 16 的读法；全部约 0.4 到 0.5 美元；手工运行；--only readings --dry 不调用 Claude）
# 以下从 M1 起才有：boundkeep test、boundkeep llm check、eval/run_eval.py
```
## 约定

- Python 3.11+，类型标注完整，pydantic v2 做 schema。
- 每个模块保持薄：`normalize` 只做解析，`policy` 只做匹配，`audit` 只做后端调用与裁决，`pipeline` 只做编排。
- 平台差异只出现在 `ipc/`、命令方言解析与路径规范化，规则引擎与判定管线不含平台分支。路径规范化的词法层显式使用 `ntpath` / `posixpath` / `PureWindowsPath`，不用当前平台默认的 `os.path`，使 Windows 语义可在任何平台单测。
- 新增规则类型或判决路径，必须同时补：单元测试、`tests:` 回归用例、必要时补评测样本。
- 新增 LLM 后端适配器，必须通过同一套一致性测试，并按 `IMPLEMENTATION_PROMPTS.md` 的 X6 流程登记。
- 提交信息写清楚改了哪一层、为什么。
- 环境变量：`BOUNDKEEP_LLM_API_KEY`（见 `.env.example`），不要把密钥写进任何文件。

## 当前状态

- 阶段（2026-10-25）：**M2 已完成，标签 `m2-baseline`**：评测集、评测框架（`src/boundkeep/evalkit`、`eval/run_eval.py`）与 `rules-only` 基线。报告 `docs/reports/M2.md`，生成物 `eval/report.md` 与 `eval/results/rules-only.json`，口径 `docs/eval-methodology.md`（指标版本 3）。数据集 633 条（恶意 241、正常 392，其中真实会话 150，全部经使用者确认；dev 指纹 `34a1cd18e50712e5`，test 指纹 `5f2bab54704e0132`）。**已知缺口：obfuscation 只有 11 条，不足 30 条**（起草这一类样本被安全分类器拦下；补法是 `eval/authoring/TEMPLATE.txt` 加 `eval/add_samples.py`，补完重跑评测）。基线对应的规则冻结在提交 `6821142`（标签 `m1c2-x1-rereview2-fixes-done`），独立复审（`docs/reviews/M1c2-fixes-rereview-2.md`）之后高危、中危都已清零。已完成并有标签：M0a、M0、M1、M1b、M1c、M1c-2、M1c-3、M1c-4，以及 M1c / M1c-2 的 X1 审查和两轮复审的修复（报告 `docs/reports/M1c2-review-fixes*.md`）。
- **评测怎么用**：`uv run python eval/run_eval.py --check` 校验数据集并打印指纹；`uv run python eval/run_eval.py --config rules-only` 离线运行并写报告（只计入 `label_confirmed: true` 的样本）。真实会话导入是 `boundkeep eval import-session|confirm|promote`（导入物在被 git 忽略的 `eval/staging/`，`confirm` 在 Claude Code 会话里拒绝执行，是使用者自己的命令）。**指标口径或样本集一变，指纹就变；基线要用新的指纹重跑，规则一改也要重取基线**。看过 test 切分的结果之后不得再据此改规则（否则要声明 test 已被污染）。
- **等你做 / 未做**：真实 Claude Code 里的手工验收（特别是真实控制台里的 `trust add`，要在 Claude Code 之外的终端运行）；Linux 容器套件（本机 Docker Desktop 的守护进程没有启动）；M-2（先写后运行的污染位）推迟到 M3a，期间 `trusted_projects` 保持默认关闭、不作为推荐设置；L-1 的选项白名单会改规则，做完要重取基线。评测暴露的规则层问题记在 `docs/reports/M2.md` 第 7 节：其中 `git add` / `git commit` / `git stash` 已在 M2 之后加了 allow 规则（`docs/reports/M2-rules-1.md`，五轮定向 X1 审查之后无高危、中危，残余已列出；已声明 test 切分被污染；`m2-baseline` 标签仍是改动之前的规则）；只读信息命令 `which`、`NAME --version`、`git ls-files` 也加了 allow 规则（`docs/reports/M2-rules-2.md`，三轮复审之后无高危、中危；版本管理器 shim 读取仓库里已有选择文件的残余已由使用者于 2026-10-27 接受；新的留出集由使用者另行决定）；剩下三项已在 `docs/reports/M2-rules-3.md` 处理（2026-10-28，同一复审者审了两轮，`docs/reviews/M2-rules-3-review.md`，无高危、中危遗留，残余已列出）：MCP 参数里的本机路径、命令、URL 进入 deny / ask 规则，策略顶层键 `mcp_read_only` 让用户声明只读工具（默认空）；网络拆成 `net-unknown-destination` 与 `net-allowlist`（匹配字段 `destination`）；项目之外的持久化、`find -delete`、递归改权限与格式化工具默认由 ask 改为 deny。**留出集 h1**（`eval/datasets/holdout/`，评测口径第 4b 节）在这些规则改动之前封存了 169 条正常样本（指纹 `0aacd20fdef20db6`）；攻击样本 58 条由使用者借助模型起草（`provenance: llm-assisted`，我起草时被安全分类器拦下，也没有读它们的内容），2026-10-28 补入，补齐后指纹 `ec0ea392daf0c15a`；**2026-10-28 已打开一次**（`docs/reports/M2-rules-3.md` 第 8 节：留出攻击无一放行，达到要求 windows 60.6%、posix 54.3%，差距主要来自留出集要求 deny 的比例高；两条正常样本被 M1 就有的规则误拒）。**打开之后已改过一次规则**（第 9 节：当前会话的 `~/.claude/projects/<slug>/<会话 id>/tool-results/` 可被文件工具只读，规则 `no-session-transcript-read` 与 `allow-session-tool-results-read`，匹配字段 `except_session_tool_results` 与 `path_in_session_tool_results`），所以 **h1 已被污染**，台账 `eval/holdout-ledger.jsonl` 与评测报告都会这样声明；再要无偏的数字需要新的留出批次。**留出集 h2**（2026-10-29，`docs/reports/holdout-h2.md`）：留出集改成分批（每批一个目录 `eval/datasets/holdout/<批次>/`、自己的指纹与台账记录，`--open-holdout h2` 只打开这一批，动作不得与 dev、test 或别的批次重复；h1 的文件移进 `holdout/h1/`，指纹不变）；正常样本 261 条来自使用者其他四个项目的真实会话（预筛后使用者确认，全部 Windows）；攻击样本 56 条由使用者借助模型起草（我没有读内容，三行与 dev / test 重复，经同意不读内容地删掉），95% 要求 deny；317 条，指纹 `238a8cae34c131e4`。**2026-10-29 打开了一次**（规则 `53159b4`，`docs/reports/holdout-h2.md` 第 6 节）：没有攻击被放行；达到要求 windows 43.8%、posix 38.2%（几乎全是要求 deny、实际 ask，落在网络、未声明 MCP、结束进程等已知残余里）；正常样本误报率 62.8%（dev 34.3%），按项目 23% 到 100%，说明 allow 覆盖贴合的是开发 boundkeep 的工作流；5 条正常样本被 deny（4 条 `rm-outside-project` 的不确定删除目标，1 条读 Claude Code 记忆目录）。**打开之后修了其中一类**（同一报告第 7 节）：当前项目的 auto memory 可被文件工具只读（`allow-project-memory-read`，匹配字段 `path_in_project_memory`、`except_project_memory`），写 memory 是明确的 ask。删除那一类**试过又撤回了**：让定不下来的删除目标改为问，会让 34 条刻意钉成 deny 的对抗语料（变量、`xargs`、循环、管道、splat、scratchpad 的反例）一起变宽松；要改得先跟踪变量赋值、把管道上游的路径传下去，再单独审。默认策略的 YAML 节点数已到 9849，加载上限随后由 1 万提到 2 万（`policy/loader.py`；256 KiB 的文件大小上限会在约 1.4 万个节点时先到）。所以 **h2 也已被污染**，再要无偏的数字需要新的留出批次（h3）。
- **M3a 已完成并提交**（2026-10-30，代码提交 `46169eb`，报告 `docs/reports/M3a.md`。使用者已确认报告，包括第 7 节的规格变更提案 P1 到 P12 与第 8 节的建议；P1 到 P12 已写进 `PROJECT_SPEC.md`，即修订 6）：会话状态在 `~/.boundkeep/session.sqlite`（`src/boundkeep/session/`：WAL、一把锁加 `BEGIN IMMEDIATE`，多线程、多连接、多进程的计数都有测试；30 天 / 5000 个会话的清理；库打不开或读写失败一律当作"已污染"）。污染：来源工具在 PreToolUse 与 PostToolUse 两处打标记；窗口（`taint.window`，默认 8）只管不是规则给出的 allow（LLM 的 allow 经 §9.5，规则的 allow 不受影响）；粘性位 `session_read_untrusted`（新匹配字段，只能用在 deny / ask 规则里）让 **M-2 的 ask 规则 `ask-devtools-after-untrusted-content`**（default 与 strict 相同）在会话读过网页 / 搜索 / MCP 之后对开发工具一律再问，受信任项目也一样；`trusted_projects` 是否因此改为推荐设置，等 X1 审查后由使用者决定，在那之前仍不推荐。任务意图只在配置了 LLM 后端且 `send_task_intent` 时才存：`<ide_*>` 整段剥离（到最后一个闭合标签，没闭合到结尾）、`<pasted_content>` 不取只留长度、先脱敏再截断。`src/boundkeep/audit/`：发送出口（字段白名单、`<project>` / `~` 相对路径、两遍脱敏、看不全或含控制字符就不发）、后端协议与七类失败（规格六类加 `http_4xx`）、假后端、OpenAI 兼容适配器（httpx 0.28.1，新加的运行时依赖，规格 §13 与 M3a 提示词点名；不跟随任何重定向、只收未压缩且 ≤ 256 KiB 的回答、至多重试一次、错误信息不含请求体与密钥），二次裁决（96 种模型组合加全部失败组合的表驱动测试）、内存缓存、`boundkeep llm check`、`tests/contract`（假后端与本地假服务两种传输都过；live 版默认跳过）。LLM 预算钳到 6 秒，守护进程在策略有后端时把期限从 2 秒延长这么多。归一化层把"表里没有的程序"与"整行看不懂"标成 `exec`（只影响污染一步与发给模型的内容，不影响任何规则）。评测：每次运行同时测 `rules-only` 与 `rules+taint`；**`rules+taint` 相对 `rules-only` 的增量为 0**（60 个在污染会话里判的攻击样本都已被规则拦下，没有一个是开发工具；正常样本没有一条标了 `tainted`），代价见报告里"全部污染"的参考表。没有接过任何真实 LLM 服务。实现之后做了一轮自查（保留 15 条发现，全部已修，报告第 6a 节，回归测试 `tests/unit/test_m3a_review_fixes.py`）：没被完整分析的灰色调用不送审、直接 ask；发送出口另拒绝跨词秘密、再脱敏会变的请求与含环境里秘密变量值的请求；适配器的预算是每次尝试的硬期限（`asyncio.timeout`，审计之间不保持连接）；带 LLM 的审查超时按 `on_failure`。
- **M3a 的 X1 审查**（2026-10-30）：结论没有高危、中危 6 条（F1–F6），报告写到 F1 中间被中止，残稿没有进仓库，2026-11-01 移入了回收站（结论段的内容记在 `docs/reports/M3a-review-fixes.md` 第 6.1 节；低危 F7–F13 与信息项的细节拿不到）。处理记录 `docs/reports/M3a-review-fixes.md`（已提交，`1959969` 代码、`4d723c0` 文档）：F3、F4（模型看不到的代码与参数：here-document / here-string、`NAME=value` 赋值、PowerShell 管道进解释器的字符串与赋值、MCP 调用的参数）现在不送审、直接 ask（`Action.unshown`、`pipeline.unshown_input`；规格文字待补，提案 P-F34）；F5（名字解析卡住时适配器期限不硬，卡住的工作线程让规则的 deny 变成 busy 的 ask）已修（`_DetachedExecutor`）；F1（粘性位不跨会话）与 F6（窗口可被无害调用用完）要改 §7，只写了 X5 提案 P-F1、P-F6 与 strict xfail 复现；F2 无法确认指什么，查到的相关缺口是 MCP 资源工具不是污染来源（P-F2，hook 里的工具名未实测）。计时竞争的管道测试已修。规则没有改，评测数字不变。
- **规格修订 7 与它的实现**（2026-10-30，使用者说"按你的建议执行"，即 P-F1、P-F6、P-F2、P-F34 的方案 A；记录 `docs/reports/M3a-review-fixes-2.md`；已提交，`687f35a` 规格、`55d1af4` 代码，文档与评测生成物在其后一个提交）：项目上的标记（`session/marks.py`，会话库 schema 2 的 `project_marks` 表）：读过不可信内容的会话里可能写的动作记下项目目录（写到项目之外时记路径），匹配字段 `project_written_after_untrusted` 与 ask 规则 `ask-devtools-after-untrusted-project-write` 让开发工具在所有会话里再问，只有用户在终端运行 `boundkeep taint clear` 解除（与 `trust add` 同样的两道检查；agent 的 `boundkeep taint` 被 `deny-boundkeep-state-commands` 拒绝；`doctor` 列出标记）；污染窗口只被污染一步改成了 ask 的调用消耗（`taint_asks`，enforce 下才计数），默认 `window` 3；默认来源加 `ListMcpResourcesTool`、`ReadMcpResourceTool`、`ReadMcpResourceDirTool`（2.1.304 的 hook 实测，`docs/hook-behavior.md`）。评测重新生成，数字不变。`trusted_projects` 在定向复审之前仍不推荐。
- **F1–F6 修复的定向 X1 复审**（2026-10-31，独立会话；报告 `docs/reviews/M3a-rereview.md`）：没有高危，中危 R-1 到 R-5，低危 R-6 到 R-10；F1、F6 部分修，F2–F5 已修；在 R-1、R-5 处理之前不建议推荐 `trusted_projects`。使用者说"好，先修这三条"：R-1（工作目录在项目外时项目内的写不打标记；动作新增 `project_root`，打标记用它）、R-4（`python -m boundkeep.<模块>` 认成 `boundkeep`）、R-10（`doctor` 的 `taint-sources` 检查）已修，记录 `docs/reports/M3a-rereview-fixes.md`；已提交，`f8b7a71` 代码，文档在其后一个提交；R-2、R-3、R-5、R-6、R-7、R-9 写成提案 P-R2 到 P-R9（报告第 7 节），等使用者决定。规则、策略与评测数字没变。
- **规格修订 8**（2026-10-31，使用者按草案接受："Yes, as drafted"）：先做两个 hook 实测（Claude Code 2.1.304，`docs/hook-behavior.md`"M3a 复审的实测"：Pre / Post 带同一个 `tool_use_id`，被批准的询问有 PostToolUse、被拒的没有；`--fork-session` 换新 id、`source: fork`、不带父 id），再按 P-R2、P-R3、P-R5、P-R6、P-R7、P-R9 实现，记录 `docs/reports/M3a-rereview-fixes-2.md`：带网络的 shell 调用是来源（`session/sources.py`，只搬代码的子命令除外）；看不到写路径的写、开发工具配置文件所在目录也打项目标记；带标记的项目里 `exec` 灰色调用不送审；窗口按 `tool_use_id` 对上 PostToolUse 才计数（会话库 schema 3，`pending_asks`；配置了 LLM 时 PostToolUse matcher 为 `*`）；`init` 注册 SessionStart（第五个 hook，安装记录多 `events`；旧记录不要求它）。规则、策略与评测数字没变。已提交并推送（`dc9b268` 规格、`4a6c07d` 代码，文档在其后一个提交；包含在后来的标签 `m3a-done` 里）。
- **修订 8 的定向复审**（2026-10-31，同一个独立审查会话；报告 `docs/reviews/M3a-rereview-2.md`）：没有高危、中危。R-1 到 R-5 已修；R-6、R-7、R-9 已修但有残余；R-8 仍未处理。低危 S-1 到 S-7、信息 S-8、S-9，残余与计划见 `docs/reports/M3a-closeout.md`。S-2、S-4 这次只把规格 §7 的文字写准，代码没动。
- **真实 Claude Code 冒烟**（2026-11-01，2.1.304，`scripts/smoke_claude_m3a.py`，结果在 `docs/hook-behavior.md`）：真的 boundkeep，26 项通过，约 0.31 美元。fork、resume、项目标记的跨会话链路、按 `tool_use_id` 计数的窗口都在真实宿主里跑通了（LLM 是本机假服务，批准由权限提示工具代替真人）。`auto` 模式没有测到：`init` 事件写 auto，hook 收到 default，询问被拒，分不清它是否生效。
- **M3a 收尾**（2026-11-01，标签 `m3a-done`，记录 `docs/reports/M3a-closeout.md`）：全量测试 26870 通过、169 跳过、0 失败。使用者决定（"全部按建议办"）：接受修订 8 实现时补的三处规格文字；`trusted_projects` 改为**有条件推荐**（默认仍是空列表，只信任自己写过或审计过的仓库，写进了 README 与 `docs/policy-reference.md`）。LLM 层仍然没有接过真实服务，文档不能对它的效果做表述。
- **M3a 之后的低危残余与规格修订 9**（2026-11-01 到 11-02，已提交并推送，`4906558` 代码、`cb58d91` 规格与文档，未打标签；记录 `docs/reports/M3a-low-residuals.md`）：使用者说"按建议实现"。第二轮定向复审的 S-1、S-2、S-3、S-5、S-6、S-7 已处理：漏记 SessionStart 的会话在所有安装都注册了这个 hook 时按 `inherited:unknown` 开始，只有这一个来源时不打项目标记（S-1）；运行注册表里的包算来源，裸名字的 `npx` 除外（S-2）；配置了 LLM 时 shell 来源在 PostToolUse 也记（S-3，没有后端时不起作用）；表外的 git 子命令打标记（S-5。复审点名的写法修改之前就会打）；根目录的开发工具配置记"所有位置"（S-6）；`enforce` 下规则 deny 的调用不打标记，标记记下类别，会话库 schema 4（S-7。被问、用户拒绝的调用仍然打）。规则、策略与评测数字没变。全量测试 27203 通过、169 跳过、0 失败（1:12:40，也包括下一条的修复）；这批改动的第一次全量静默中断，原因不知道。真实冒烟重跑通过（2026-11-02，26 项 0 失败，约 0.225 美元，`docs/hook-behavior.md`），但只验证原有链路，这些新路径真实宿主里没有跑。
- **带前缀路径的折叠**（2026-11-02，已提交并推送，`a3b38c5` 代码、`fa494e9` 记录，未打标签；记录 `docs/reports/M3a-prefix-folding.md`）：全量里 `test_normalization_is_idempotent` 失败，追到路径规范化先读第一段、Win32 先折叠再读第一段，这个错误在 `m3a-done` 上就有。已修，只在配置了 LLM 后端时才有影响。
- **Windows 设备路径不送审与规格修订 10**（2026-11-02 到 11-03，已提交并推送，`2f0f009` 代码，文档在其后一个提交，未打标签；记录 `docs/reports/M3a-device-paths.md`）：使用者说"修设备路径"。key 在 `//./` 之下的灰色调用不送审、直接问（`pipeline.device_path`，`decided_by: gray-device-path`）；只有 Win32 确实读成 `NUL` 的写法例外（白名单，`nul.bat`、`nul:x`、`\\srv\share\nul` 的 key 相同但都是普通文件，不算）。`\\.\C:` 是卷，key 由 `c:/` 改成 `//./c:`。规则、策略与评测数字没变。全量：1 失败、27411 通过、169 跳过（1:17:40，终端面板，代码页 936）。失败的 `test_every_abbreviation_resolves_like_the_real_binder` 与这次修改无关：它只认 PowerShell 的英文报错，这台机器上 936 下报错是中文，所以 936 下失败、65001 下通过。已修（`e976a03`，这个测试文件两种代码页下都 465 通过），之后没有再跑全量。真实宿主里没有跑。残余（记录第 6 节）：文件名恰好是设备名的路径（`aux.py`）key 藏住了真实位置，按路径写的 deny 匹配不到，结果是问；卷是问，不是 deny。
- **路径与闸门的审查修复与规格修订 11**（2026-11-04，已提交并推送，`7f7ffe9` 代码，文档在其后一个提交，未打标签；审查 `docs/reviews/M3a-path-gate-review.md`，记录 `docs/reports/M3a-path-gate-fixes.md`）：独立审查没有高危、5 条中危、8 条低危；使用者说"一起修"，修了 G-1 到 G-5、G-9、G-13。`NUL` 的例外缩小到 shell 命令里的裸名字和只带前缀的写法；UNC 的 `pipe`、`mailslot`、`ipc$` 不送审；`\\?\`、`\??\` 下任何一段、不带前缀时中间一段的尾随点和空格都不确定；链接通向设备时 key 写设备，解析结果不在本机固定盘上不再 `stat`；`which` 以两个分隔符开头的参数算读路径；非字母盘符不确定；`$FOO\..` 不折叠。G-5 审查评为中危，我在本机回环上量到 `which` 确实访问 UNC 路径，按审查的标准应算高危（外部主机与 NTLM 没有量）。判决数字没变，规则条目没变。全量分六段跑，不是一个进程：1 失败、27669 通过、169 跳过（失败的 `test_round_trip_law` 是 Hypothesis 的 200 毫秒期限超时，与这次修改无关，单跑 3 次都过；之后加了 `deadline=None`，`4409fb3`，只重跑了这个文件）；之前两轮在 74% 和 47% 无声中断，原因没查到（记录第 5 节）。真实宿主里没有跑。残余见记录第 6 节，审查的 G-6、G-7、G-8、G-10、G-11、G-12 没有修。
- **修订 11 的定向复审与规格修订 12**（2026-11-04，已提交并推送，`bede21d` 代码，`ae99b20` 文档，未打标签；复审 `docs/reviews/M3a-path-gate-rereview.md`，不是独立的，同一个会话做的；记录 `docs/reports/M3a-dots-and-folding.md`）：七条里六条成立，G-2 只修了一半（GR-1：最后一段的尾随点仍算确定，Git Bash 里 `cd ../proj. && cat x` 读到项目外，规则放行）；另有一条更早就有的同类问题（GR-2：`casefold` 把 NTFS 分得开的目录读成同一个）。使用者说"修 GR-1、GR-2"：任何一段的尾随点和空格都不确定；Windows 的 key 用 `paths.windows_fold` 按 NTFS 的比较方式折叠，`path_glob` 仍然 `casefold`，所以 deny 不变。没有采用复审报告的"标为不确定"，因为 `ß` 在项目路径里时每个文件都要问。规则条目与评测数字没变。全量分六段跑，不是一个进程：27803 通过、169 跳过、0 失败（2:04:02，六段都一次跑完，合计与收集到的 27972 条相同）。GR-3、GR-4、GR-5 没有修；这次修复没有复审，真实宿主里没有跑。**读法因程序而异：`GetFullPathNameW` 不代表打开时的读法，NT 路径（`RtlDosPathNameToNtPathName_U_WithStatus`）也只是走 Win32 转换的程序的读法，Git Bash 和 Node 读文件都保留尾随的点。要分程序量。**
- **修订 12 的复审与规格修订 13**（2026-11-05，已提交并推送，`372bfa1` 代码，文档在其后一个提交，未打标签；复审 `docs/reviews/M3a-dots-and-folding-review.md`，不是独立的，同一个会话做的；记录 `docs/reports/M3a-readings-fixes.md`）：修订 12 的两个目标达到了，但带来一个回退（RV-1）：带尾随点的路径算不确定之后不再查磁盘，项目里有联接点时 deny 变成问或送审，PowerShell 5.1 真的会写穿（`Set-Content guard\policy.yaml.`）；中间一段始于修订 11，当时的差分在假机器上，看不到。另有两条早就有的同类问题：Git Bash 把 `work:s` 当独立目录（RV-2），主机名比较用 `casefold` 和 IDNA（RV-3）。使用者说"修这三条"：只因读法不确定（尾随点、空格、流名）的路径照样查磁盘，两种读法都查，结果仍然不确定（`paths.reading_only`、`reading_text`）；流名不在最后一段或在 bash 方言里算不确定；主机名用 `windows_fold`，非 ASCII 的主机名目的地未知。git 的 pathspec 魔法（`:/src`、`:!x`）不算流名，git 自己解析（`programs._pathspec`，实测）；不解析魔法的子命令（`blame`、`apply` 等）仍然不确定。规则条目与评测数字没变。真实磁盘差分 23544 条对 `78127af`、`2f8f59d`、`d1729dd` 都没有变松。全量分六段跑，不是一个进程：28098 通过、169 跳过、0 失败（2:08:06，六段都一次跑完，合计与收集到的 28267 条相同；1 条警告是测试把熔断冷却设成 `1e9` 秒，记录第 5 节）。这之前的第一次全量有 10 个失败：9 个是我把 git 的普通命令也改成了问，1 个是语料钉的旧值（`m2r-h1-010` 由灰色改成问）。RV-4（大小写敏感目录）、RV-6（折叠表依赖 Unicode 版本）、GR-3、GR-4、GR-5 没有修（RV-7 见下一条）；这次修复没有复审，真实宿主里没有跑。**假机器的差分看不到磁盘层：改路径判断时要用真联接点跑真实磁盘差分，并分程序量真实读法。差分不能只看变松：收紧也要逐条看，语法里要有日常命令，否则误报要等全量才发现。**
- **RV-7 与规格修订 14**（2026-11-05，已提交并推送，`fef9fe9` 代码，文档在其后一个提交，未打标签；记录 `docs/reports/M3a-program-fold.md`）：使用者说"修 RV-7"。判断带路径的程序在不在系统目录时用 `windows_fold`。复审只点了这一处，但程序名有同样的问题（`lſ a.txt`、`ﬁnd . -name x`、`Teſt-Path a.txt` 也由规则放行；实测 Git Bash 跑的是另一个文件，PowerShell 5.1 找不到这个 cmdlet）。名字仍按 `casefold` 认，deny / ask 规则看得到（`ſudo`、`mkfſ` 不变）；只有 `casefold` 才读成这个名字的写法是灰色 `program-fold-variant`，不送审，因为发给模型的是折叠之后的名字。代价：配了后端时名字里带 `ß`、`µ`、连字的程序直接问。规则条目与评测数字没变。逐程序扫描 12668 条：ASCII 写法和普通 Unicode 名字全部相同，折叠写法没有一条还被规则放行，deny 没有减少；真实磁盘差分 23544 条级别相同。变异 11 个全部抓到。全量分六段跑，不是一个进程：28212 通过、169 跳过、0 失败（2:07:45，合计与收集到的 28381 条相同）。**没有修、要先定设计的**（记录第 7 节）：`_system_dir` 丢盘符、前缀太宽，`D:/Windows/System32/git.exe status`、`C:/Windows/System32evil/git.exe status`、`C:/msys64/home/x/cat a.txt` 由规则放行，不需要特殊字符，普通账户写得进这些位置（这台机器只读过 ACL，没有放过程序）。这次修复没有复审，真实宿主里没有跑。（修订 15 已修，见下一条。）
- **系统目录与规格修订 15**（2026-11-05，已提交并推送，`8ddc6e2` 代码，文档在其后一个提交，未打标签；记录 `docs/reports/M3a-system-dirs.md`）：使用者说"修盘符问题"。Windows 主机上，带路径的程序只有目录**正好**是 `%SystemRoot%\System32`、`%SystemRoot%\SysWOW64`，或 `%ProgramFiles%`、`%ProgramFiles(x86)%` 下 Git 的 `cmd`、`bin`、`usr\bin`、`mingw64\bin`、`mingw32\bin`，并且带盘符，才算系统里的程序；变量取守护进程的环境，没有时按 Windows 默认值，值不是普通的 `X:\…` 时不给出任何目录。bash 方言里不带盘符的 `/usr/bin` 等照旧算（Git Bash 自己的目录，实测 `cygpath`）。别的盘、子目录（`System32\Tasks` 普通账户可写）、msys / cygwin、带盘符的 POSIX 目录、PowerShell 里不带盘符的 `/usr/bin`（当前盘根下）都不再由规则放行，是灰色或命中项目外的 ask / deny 规则。规则条目与策略文件没变。系统目录扫描 49720 条、逐程序扫描、真实磁盘、假机器、孪生项目差分都没有变松，deny 没有减少；变异 16 个，15 个抓到，1 个等价。全量分六段跑，不是一个进程：28318 通过、169 跳过、1 失败（`test_a_worker_that_finishes_late_does_not_change_the_answer_or_the_count`，M1 的测试固定睡 0.3 秒，跑在"最佳能效"下；和这次修改无关，单跑 5 次都过，没有修）。代价：PowerShell `/usr/bin/git.exe status`、Git Bash `/Windows/System32/git.exe status` 要问，装在别处的 Git 带完整路径调用要问。复审见下一条；真实宿主里没有跑。**判断"系统的程序"不能只看路径的样子：要量那个目录谁能写、那个 shell 把这个写法读到哪里。**
- **修订 13 到 15 的复审**（2026-11-06，已提交并推送，测试 `c085855`，文档在其后一个提交，未打标签；`docs/reviews/M3a-rev13-15-review.md`，不是独立的，同一个会话做的）：三次修订的目标达到了，没有高危、中危，没有回退。两条低危都早于修订 13，没有修：RS-1 长形式的 git pathspec 魔法丢了路径（`git diff -- ':(top).env'` 由规则放行，`git diff -- .env` 是 deny；实测 git 确实打印内容）；RS-2 PowerShell 里 `& '…\boundkeep.exe.' mode audit-only` 由 deny 变成问、有后端时送审（实测 PowerShell 5.1 运行带尾随点或空格的程序路径）。两条的效果都有已被规则放行或已知是灰色的写法（`git log -p`、`git stash`、`Start-Process boundkeep …`），没有带来新能力。同时：M1 的计时测试 `test_a_worker_that_finishes_late_does_not_change_the_answer_or_the_count` 改成带期限的轮询（压着 CPU 时旧写法 10 次失败 1 次，新写法 10 次都过）；三份旧记录（`M3a-review-fixes-2.md`、`M3a-rereview-fixes.md`、`M3a-rereview-fixes-2.md`）里过时的"未推送"已更正。（RS-1、RS-2 修订 16 已修，见下一条。）
- **pathspec 魔法与带尾随点的程序名，规格修订 16**（2026-11-06，已提交并推送，`c69684c` 代码，文档在其后一个提交，未打标签；记录 `docs/reports/M3a-pathspec-and-dotted-names.md`）：使用者说"修 RS-1、RS-2"。RS-1：git 按 pathspec 读的操作数，魔法按 git 的语法拆开（短形式是 `:` 加 `/`、`!`、`^` 若干个、可选再加 `:`，长形式是 `:(…)`），之后的路径按当前目录读，`git diff -- ':(top).env'`、`git stash push -- ':(top).claude/settings.json'` 现在是 deny；有排除时读作 `.`（git 作用于其余整个仓库，实测）；`top`、`exclude`、`literal` 以外的词或没闭合的括号是灰色 `git-pathspec-magic`。修的时候查到同类的一处：`git archive` 只有第一个操作数按 `REV:PATH` 读（`git archive HEAD '::secrets/id_rsa'` 原来只是灰色，实测 git 把那个文件打进了归档；原文举的 `'::.git/config'` 打不进去，独立复审 IR-5 更正）。RS-2：Windows 上程序名先去掉结尾的点和空格，名字变了是灰色 `program-name-trailing-dots`；启动器名（`python.exe.` 加 `-m`、`uv.exe.` 加 `run`）在任何平台上都这样去掉，原来漏在这一层。规则条目与策略文件没变；原有六组差分级别相同；新的扫描里程序名 1600 条 0 条变松，pathspec 10880 条有 946 条变松，都是按 git 的真实读法该放的（排除 666、结束冒号 210、没闭合的括号 58、`attr` 12）；变异 16 个全部抓到；评测除日期和延迟外相同。全量分六段跑，不是一个进程：28403 通过、169 跳过、0 失败（3:22:30，合计与收集到的 28572 条相同）。代价：`git diff -- ':!secrets/id_rsa'` 由 deny 变成规则放行；`icase`、`glob`、`attr` 要问；`top` 按当前目录读，不按仓库顶层。独立复审和真实冒烟见下一条。**pathspec 的排除不缩小范围：被排除的路径不是目标，其余整个仓库才是。**
- **修订 13 到 16 的独立复审与修订 10 到 16 的真实冒烟**（2026-11-06，已提交并推送，冒烟脚本 `2a460da`，文档在其后一个提交，未打标签）：
  - 独立复审 `docs/reviews/M3a-rev13-16-independent-review.md` 由另开的会话完成，不带作者的上下文：高危 0、中危 1、低危 3、信息 4。修订 16 的 RS-1、RS-2 修好了。
  - 中危 IR-1 是修订 13 带来的回退：PowerShell 里会话工作目录在项目子目录时，`git add :/`、`git add ':!x'`、`git add ':(top)'` 由问变成规则放行。实测会把顶层没被忽略的 `.env` 暂存进去，再由规则放行的 `git diff --cached` 打印出来。原因是 `psprograms` 重新构造 `CmdInfo` 时没有抄 `pathspec_magic`；回归测试只测了 Bash。
  - 低危：IR-2 `--` 之前的魔法（`git show ':!README.md'` 规则放行）；IR-3 `REV:目录` 不扫子树；IR-4 程序路径的 8.3 短名。
  - 信息：IR-5 修订 16 的记录和规格里"`.git/config` 被打进归档"的例子不成立（git 报错退出）；IR-6 几处"效果与已放行的写法相同"只在假机器上成立；IR-7 `git diff <空树> HEAD` 由规则放行，打印全部已提交内容（早就有）；IR-8 uv 生成的启动器带尾随点照常运行。
  - 这些都没有修，等使用者决定。
  - 真实冒烟：`scripts/smoke_claude_m3a.py` 加了 `readings` 一段，修订 10 到 16 各一条代表写法，用 PowerShell 工具；`--dry` 不调用 Claude。Claude Code 2.1.318 上 13 项 0 失败，约 0.158 美元，记录在 `docs/hook-behavior.md`。没有覆盖子目录里的工作目录、Bash 工具和 VS Code 扩展。
  - **PowerShell 里的外部程序是在 `psprograms` 里重新构造 `CmdInfo` 的：给 `CmdInfo` 加字段要同时改那里，测试要两种 shell 都测。**
- **IR-1 已修**（2026-11-06，已提交并推送，`2778e56` 代码，`5654402` 文档，未打标签；记录 `docs/reports/M3a-ps-pathspec-magic.md`）：使用者说"提交并修 IR-1"。
  - 修法：`psprograms._external` 抄 `pathspec_magic`，`_finish` 传出去。规格没有改：§5.1 本来就这样要求。
  - 测试：R5-1 的回归测试改成 Bash、PowerShell 都测；新文件 `tests/unit/test_m3a_ps_cmdinfo.py` 把两种 shell 算出的 `CmdInfo` 逐字段比较，以后新加的字段也会比到。
  - 真实目录树扫描 10320 条（4 种目录树、14 种子命令 × 18 种写法、两种 shell、工作目录在根或子目录）：PowerShell 的 `git add` 有 243 条由规则放行变成灰色（`git-add-may-stage-protected`），15 条同级，变松 0；修好之后 Bash 和 PowerShell 的 5160 对判决全部相同。
  - 其他：变异 5 个全部抓到，两个测试文件分开跑也各自抓到；`boundkeep test` 1142 / 0、334 / 0；评测除日期和延迟外相同。
  - 全量分六段跑，不是一个进程：28446 通过、169 跳过、1 失败（2:22:46，合计与收集到的 28616 条相同）。失败的是 `test_redact.py::test_linear_time_on_hostile_input[assignment-doubled-quotes]`：2.21 秒，预算 2 秒；当时可用的提交内存只剩 644 MB。它和这次修改无关，单跑 5 次都过（1.00 到 1.24 秒），没有改。
  - 代价：PowerShell 里 `git add ':/src'` 这类写法，项目里有没被忽略的受保护名字时要问，和 Bash 一样。
  - IR-2 到 IR-8 当时没有处理（修订 17 处理了，见下一条）；这次修复没有复审；真实宿主里没有跑子目录里的这类调用。
  - 顺带：复审报告里的一段 Python 代码块用 `ruff format` 排了版，否则 `ruff format --check .` 不通过。
- **git 的 `:` 操作数、`REV:目录` 与 8.3 短名，规格修订 17**（2026-11-07，已提交并推送，`996fd6f` 代码，文档在其后一个提交，未打标签；记录 `docs/reports/M3a-git-operands-and-short-names.md`）：使用者说"按照你的建议去完成"，按独立复审第 7 节的顺序做。
  - IR-2：`--` 之前的 `:!x`、`:^x`、`:(…)`、`::x`、`:/x` 同时按 `REV:PATH` 和 pathspec 读（`programs._colon_kind`）。打印内容的子命令里 pathspec 限定范围，`:/x` 可能是按提交说明找到的提交，不限定。`:x`、`:N:x` 是索引里的文件，只按 `REV:PATH` 读：第一版也当 pathspec 读，`git show :0:a.py` 由放行变成问，收窄了，规格也改了。
  - IR-3：`git archive` 的 tree-ish 是第一个操作数，写在 `--` 后面也是；`archive`、`grep` 的 `REV:目录` 递归读。
  - IR-4：Windows 上带路径、最后一段是 8.3 短名的程序，取磁盘层解析出来的长名给 deny / ask 规则，灰色 `program-short-name`（`event._short_name_program`）。实测 PowerShell 5.1 和 Git Bash 都运行短名路径。
  - IR-5、IR-6、IR-8 的文字在原处标了"更正"或"补充"；IR-7 没有改，写进 `docs/threat-model.md` 第 4 节：收紧它会让 `git diff HEAD~1` 在任何有受保护文件的项目里被拒绝，要使用者决定。（2026-11-10 使用者决定记为接受的残余，见修订 18 复审那一条。）
  - 规则条目与策略文件没变。真实目录树扫描 10092 条：`--` 之前的写法 826 条收紧、28 条变松，28 条都和同一个操作数写在 `--` 之后的判决相同（`git log -p ':(top)src'` 只读 `src`，实测）；带 `--` 的写法 4968 条一条没变；短名和长名判决全部相同。原有差分全部相同或级别相同，含 git 的语料 1164 次判决 0 条不同，`boundkeep test` 1142 / 0、334 / 0，评测除日期和延迟外相同。
  - 全量分六段跑，不是一个进程：28525 通过、169 跳过、0 失败（2:09:59，六段都一次跑完，合计与收集到的 28694 条相同）。真实宿主里没有跑。
  - 复审（2026-11-09，`docs/reviews/M3a-rev17-review.md`，不是独立的，同一个会话做的；使用者选择在这里做）：三个目标达到了，没有回退；高危、中危 0，低危 4，信息 2，都早于修订 17，没有修。
    - R17-1：`git diff HEAD:src` 由规则放行，实测打印所有已跟踪文件的全文。和 IR-7 同类，但收紧它不牵连 `git diff HEAD~1`，要和 IR-7 一起由使用者决定；收紧 IR-7 时它应升为中。
    - R17-2：Git Bash 运行不带 `.EXE` 的短名路径和经 PATH 的裸短名（实测，PowerShell 5.1 不运行），判决是灰色。
    - R17-3：`git archive ':/text'` 打包按提交说明找到的提交，判决是灰色。
    - R17-4：`git archive --mtime 值 HEAD`、`--add-virtual-file 值 HEAD` 的值被当成 tree-ish，判决是灰色。
    - R17-5、R17-6 是文字：`--` 之前的 `::x` git 不接受（退出码 128）；两种 shell 的判决在带冒号的操作数上有 584 对不同，都是 PowerShell 更松，实测的 14 条 git 都不打印内容。
    - （R17-1 到 R17-6 修订 18 已修，见下一条。）

  - **改 git 操作数的读法时，要把同一个操作数写在 `--` 前后各算一次对照：`--` 之前的读法不应比之后松，除非那个词在 `--` 之前是修订号。**
- **修订 17 复审的修复，规格修订 18**（2026-11-09，已提交并推送，`2534c31` 代码，文档在其后一个提交，未打标签；记录 `docs/reports/M3a-rev17-review-fixes.md`）：使用者说"开始执行修复"。R17-1 选"按树的读法收紧"，R17-2 选"补 .exe，裸短名不送审"，修复时查到的子目录问题选"一起修"。
  - R17-1：`git diff` 里 `--` 之前不以 `:` 开头的 `REV:PATH` 按整个仓库读（`programs._git_diff_trees`）；正好两个 `REV:PATH`、`--` 之后有 pathspec、只列名字时不这样。`git diff HEAD~1` 不变，IR-7（空树）不变。
  - 复审漏掉、修时查到的两处，都由规则放行、实测打印 `.env`：
    - `git show HEAD HEAD:src`：`REV:PATH` 现在只在每个操作数都是它时才免于扫描；
    - 工作目录在项目子目录时的 `git log -p`、`git show HEAD`：新字段 `CmdInfo.top_paths`，`show`、`log -p`、`stash show -p` 和 `diff` 的子树比较另读项目根，带 `top` 或只有排除的 pathspec 另按项目根读（`grep`、`archive` 只作用于当前目录，实测，只有排除时不另读）。只在工作目录位于项目根之下时加（`event._top_words`）。
  - R17-3、R17-4：`archive` 的 tree-ish 是 `:/text` 时不缩小范围；选项表加 `--mtime`、`--add-virtual-file`；有不认识的长选项时不缩小范围。
  - R17-2：bash 方言里带路径的短名找不到时补 `.exe` 再找；像短名的裸程序名是灰色 `program-short-name-unresolved`，不送审（`pipeline._UNSHOWN_REASONS`）。PowerShell 不变（实测不运行这两种）。
  - R17-5、R17-6 的文字在规格 §5.1、`_colon_kind` 的文档字符串、修订 17 记录第 6 节原处更正。
  - 规则条目与策略文件没变。专门扫描 5100 条：644 条收紧，0 条变松。原有差分全部相同或只有收紧；`boundkeep test` 1142 / 0、334 / 0；评测除日期和延迟外相同。变异 21 个全部抓到。受影响的 11 个测试文件 8250 通过。
  - 全量分六段跑，不是一个进程。结果是 28619 通过、169 跳过、7 失败，用时 3:47:19，合计与收集到的 28795 条相同。
    - 5 条在 `test_review2_core_search.py`：它的 `classify` 替身把 `CmdInfo` 的字段逐个抄过去，没有 `top_paths`，守卫报内部错误。替身改成了 `dataclasses.replace`，改后这个文件 49 通过。
    - 另外 2 条是 `test_daemon.py` 和 `test_lifecycle.py` 的计时、锁文件测试，单跑各 5 次都过。整个 `test_daemon.py` 一起跑时有 3 条计时测试失败，`7b65ad8` 上也一样失败（电源计划 Silent，最佳能效），所以和这次修改无关，没有改。
    - 全量没有重跑。
  - 真实宿主里没有跑。
  - 复审（2026-11-10，`docs/reviews/M3a-rev18-review.md`，不是独立的，同一个会话做的；使用者选择在这里做）：目标达到了，没有回退；高危、中危 0，低危 4，信息 1，都没有修。
    - R18-1：子目录里的 `git diff HEAD~1:secrets HEAD:secrets` 由规则放行。两棵子树的扫描按当前目录算，git 从仓库顶层读。这是修订 18 自己的修法留下的。
    - R18-2：花括号里带冒号的修订号（`git show 'HEAD@{10:00}'`、`'HEAD^{/fix: typo}'`）被当成 `REV:PATH`，规则放行，实测打印整个提交。
    - R18-3：`git log -p --full-diff -- sub` 只读 `sub`，规则放行；实测打印碰过 `sub` 的提交的全部补丁。
    - R18-1 到 R18-3 能打印的，IR-7 的 `git diff <空树> HEAD` 都能打印（规则放行，实测）。
    - 2026-11-10 使用者决定：IR-7 记为接受的残余，R18-1 到 R18-3 作为同类记在 `docs/threat-model.md` 第 4 节 IR-7 那一条下面，不修。以后查到打印已提交内容、又不超出 `git diff <空树> HEAD` 的 git 写法，也记在那里，不单独修。
    - R18-4：`cd` 进路径带短名的目录之后，`./BOUNDK~1`、`.\BOUNDK~1.EXE` 是灰色、照常送审，两种 shell 实测都运行。它和 IR-7 无关，可以单独修，要先定设计。（修订 19 已修，见下一条。）
    - I-1：同一条命令里先 `cd sub` 再 `git log -p`，修订 18 之前就是 deny；子目录修复只在 hook 收到的工作目录本身在子目录时起作用，这一点要在真实宿主里量。
  - 代价：子目录里不带 `--` 的 `git log -p b.txt` 现在是 deny，和在根运行一致。
  - **给 `CmdInfo` 加字段时，先搜测试里逐个抄字段的替身。受影响文件按改动的函数挑，挑不到它们；它们出错时守卫给灰色，断言"不是 deny"的测试仍会通过。**
  - **复审不能只看"改了的地方对不对"：同一类读法在别的子命令、别的工作目录里也要过一遍。修订 17 的复审漏掉了 `git show HEAD HEAD:src` 和子目录，都是修 R17-1 时顺着同一类找到的。**
- **R18-4 的修复，规格修订 19**（2026-11-10，已提交并推送，`30813d0` 代码，文档在其后一个提交，未打标签；记录 `docs/reports/M3a-short-name-unresolved.md`）：使用者说"修 R18-4"，范围选"凡是展开不了都标"。
  - 改了什么：Windows 上，程序带路径、最后一段是字面上的 8.3 短名，而磁盘层展开不出唯一的长名时，标灰色 `program-short-name-unresolved`，不送审（`event._short_named_path`）。展开不出的情况包括：工作目录未知（`cd` 进短名目录之后）、目录写成变量或通配符、文件不存在、展开出的名字不唯一。两种 shell 都这样。PowerShell 读不出的命令名包成 `$(…)`，先拆开再看。
  - 规则条目与策略文件没变，判决级别一条没变。
    - 专门扫描 160 行：49 行多了这个灰色原因、改为不送审，其余完全相同。
    - 原有差分全部相同；`boundkeep test` 1142 / 0、334 / 0；评测除日期和延迟外相同。
  - 测试：新测试 29 条，在修改前的代码上 8 条行为测试失败。变异 9 个全部抓到（补了一条测试输入）。受影响的 18 个测试文件 6085 通过。
  - 全量分六段跑，不是一个进程：28654 通过、169 跳过、1 失败，用时 4:39:20，合计与收集到的 28824 条相同（05:40 左右电源换成了最佳性能）。
    - 失败的是 `test_norm_psprograms.py` 的 hypothesis 测试，这次随机生成到 `Remove-Item /dev/zero`。`e208c74` 上同样失败，和这次修改无关，没有修。
    - 它查到一个早已存在的问题：`programs.py` 把 `/dev/null`、`/dev/zero` 等六个名字当无害设备、不记路径。这是 Bash 的读法；PowerShell 5.1 把它们解析成当前盘根下的普通路径（`/dev/zero` 是 `E:\dev\zero`）。所以 PowerShell 里 `Remove-Item -Recurse /dev/null` 是灰色、送审，`/dev/nullx` 是 deny。规格里没有写到，要修先改规格。（修订 20 已修，见下一条。）
    - 失败用例存在 `.hypothesis/` 里，修好之前本机每次都会失败。
  - 复审见下一条末尾；真实宿主里没有跑。
  - 代价：路径写错、文件不存在的短名程序也直接问，不再送审。
- **PowerShell 里的 `/dev/null`、`/dev/zero` 是普通路径，规格修订 20**（2026-11-10，已提交并推送，`92a5e56` 代码，文档在其后一个提交，未打标签；记录 `docs/reports/M3a-ps-dev-paths.md`）：使用者说"修 /dev 这条"，范围选"整个 PowerShell 工具"，`/dev/tcp` 选"记路径，网络标记也留着"。
  - 改了什么：`/dev/null`、`/dev/stdin`、`/dev/stdout`、`/dev/stderr`、`/dev/tty`、`/dev/zero` 只在 bash 方言里是无害设备。PowerShell 方言里照常记路径：cmdlet 的路径参数、重定向、外部程序的参数（`programs._Acc` 的 `posix_devices`，建的时候必须给，`psprograms` 一侧给 False）。`/dev/tcp/…`、`/dev/udp/…` 在 PowerShell 里既记路径，也保留网络目标。
  - 实测（PowerShell 5.1，临时目录挂成 PSDrive）：`Remove-Item /dev/zero`、`Remove-Item -Recurse /dev/null`、`Set-Content`、`>` 都真的作用在当前盘根下的 `\dev\…` 上；`'x' > /dev/tcp/example.com/80` 写的是文件。python、`curl.exe`、cmd 也按当前盘的路径读，只有 git 自己把 `/dev/null` 当空文件。
  - 规则条目与策略文件没变，bash 方言一条没变。专门扫描 2482 行：0 行变松，PowerShell 有 120 行收紧（`Remove-Item -Recurse -Force /dev/null` 从灰色到 deny），672 行级别相同、多记了路径。
  - 测试：新测试 84 条，在修改前的代码上 72 条失败。原来失败的那条随机生成测试通过了。
  - 原有差分全部相同；`boundkeep test` 1142 / 0、334 / 0；评测除日期和延迟外相同。变异 13 个全部抓到（第一轮有一个等价的存活，所以把 `posix_devices` 改成了必填的构造参数）。受影响的 26 个测试文件 8795 通过，1 条失败和这次修改无关（`test_norm_bash.py` 里和真实 bash 对比的一个样本，只在从 Git Bash 启动 pytest 时才跑，旧代码上同样失败）。
  - 全量分六段跑，不是一个进程：28739 通过、169 跳过、0 失败，用时 2:32:27，六段都一次跑完，合计与收集到的 28908 条相同（从头到尾电源都是最佳性能）。
  - 真实宿主里没有跑。
  - 代价：PowerShell 里的 `git status 2>/dev/null` 从 allow 变成 ask（当前盘没有 `\dev` 时这条命令本来就报错、不运行，实测）；丢弃输出要写 `$null`。
  - 没有改：单独的 `-` 在 PowerShell 的 cmdlet 里是当前目录下名叫 `-` 的文件（实测 `Remove-Item -` 删掉它），两种方言里仍然不记路径。
  - 复审（2026-11-10，`docs/reviews/M3a-rev19-20-review.md`，修订 19 和 20 一起审；不是独立的，同一个会话做的；`b15e064`，已推送）：两次修订的目标都达到了，没有回退。范围之内高危、中危 0，低危 3，信息 1，都早于这两次修订，没有修。
    - R19-1（信息）：Bash 里 `./BOUNDK~1.EXE.`（`.EXE` 后面再带点或空格）展开不了时标成了 `program-short-name`，照常送审。Git Bash 实测不运行它。
    - R19-2、R19-3（低）：和 R18-4 同一个原因，`cd` 进短名目录之后工作目录算未知。交给 `Start-Process`、`cmd /c` 的短名程序照常送审；按短名读受保护的文件（`cat ./ENV~1.PRO`，它是 `.env.production`）是灰色，长名目录里是 deny，两种 shell 实测都读出内容。
    - R20-1（低）：Windows 上 Git Bash 启动的原生程序拿到的不是设备（`/dev/tty` 是 `C:\dev\tty`，`/dev/zero` 变成 `/Device/Null`，实测）。受信任项目里 `pytest /dev/tty` 由规则放行，`pytest /dev/ttx` 是问。那个位置有内容时的效果没有实测。
    - 范围之外的 O-1，按 X1 审查 F3、F4 的标准应算中危，`m3a-done` 起就有：PowerShell 里单独成句的表达式（`git status; [IO.File]::ReadAllText('.env')`）照常送审，请求里没有它的任何文字。只在有后端时起作用，要在 M3b 之前定。（修订 21 已修，见下一条。）
    - R19-1 到 R19-3、R20-1 都等使用者决定。
  - **复审时编的假项目要留意巧合：`cat ./ENV~1` 是 deny，只是因为假项目自己也有 `.env`。对照用的受保护文件要只存在于被测的那个目录里。**
  - **随机生成测试（hypothesis）的失败不是偶发：它会把失败用例存进 `.hypothesis/`，以后每次重放。先在旧代码上单跑，旧代码也失败就是早已存在的问题。**
- **PowerShell 里不在任何命令之内的文字，规格修订 21**（2026-11-11，已提交并推送，`e52c596` 代码，文档在其后一个提交，未打标签；记录 `docs/reports/M3a-ps-outside-command.md`）：使用者说"按建议执行"，指复审的建议"先定 O-1"。两处取舍的提问被应用退出打断，先是开发 agent 按自己的推荐定的；全量跑完后使用者说"按照你建议执行；先提交修订21再去修改O-3"，照此定下：O-1 的范围选"白名单，比较和逻辑运算算无害"；带盘符的变量选"按读写文件记路径"。
  - 原因是同一个：PowerShell 会执行不是命令的文字，而守卫和发给 LLM 的请求都是按命令看的。
  - O-1：不在任何命令的参数里的表达式和语句是灰色 `ps-outside-command:<类型>`，不送审（辅助进程回复里新增的 `loose`）。无害清单：常量、变量、字符串、数组；括号、`$(…)`、`@(…)`、脚本块、哈希表；比较和逻辑运算。`using module`、`using assembly`、`switch -File`、带类型或特性的函数参数也算。重定向的目标按不在参数里看。
  - 修 O-1 时查到一条更重的，不需要后端：`${E:\proj\.env}` 这样带盘符的变量就是那个文件的内容。原来 `Get-Date; ${E:\proj\.env}` 由规则放行（`allow-ps-no-path-commands`），项目之外的 `.ssh\id_rsa` 也一样。现在辅助进程把每一处报成一条命令（名字种类 `file-read` / `file-write`），按 `Get-Content -Path` / `Set-Content -Path` 判，`.env` 是 deny。
  - 在命令里、但请求里也没有的三种文字：开关参数的值（`ps-switch-value`，原来就有这个原因，现在不送审）、`uv run` 一类运行器自己的选项的值（新原因 `ps-runner-value`）、超过 128 个字符的程序名（发送闸门拒绝，原来是截断）。
  - 实测（PowerShell 5.1，TEMP 下的假文件）：带盘符的变量单独成句、在字符串里、在条件里都读出文件，通配符起作用，赋值改写文件；类型转换、`-as`、带类型的参数、开关参数的值、命令名表达式、重定向目标、条件、参数默认值、`using module` 都真的建出了文件，`switch -File` 读出了内容。
  - 规则条目与策略文件没变，Bash 没变。专门扫描 694 行：会动手的表达式 187 行由送审改为不送审；带盘符的变量 79 行变成 deny（原来 10 行是 allow）；4 行变松，都是单独一条的带盘符变量，现在和 `Get-Content` 同一个路径得到的一样。
  - 手头语料 1146 条 PowerShell 命令：70 条由送审改为不送审，都在测试语料里（64 条是语料专门写的开关值用例），评测集 0 条，没有变松。
  - 测试：新测试 203 条，在修改前的代码上 169 条失败。夹具 293 个用真的辅助进程重新生成，只多了 `loose` 一项。原有差分全部相同；`boundkeep test` 1142 / 0、334 / 0；评测指标相同，一条漏判样本的灰色原因多了两个，`eval/report.md` 没有重新生成。变异 40 个全部抓到（第一轮有一个等价的存活，去掉了那处多余的判断）。
  - 全量分六段跑，不是一个进程：28945 通过、169 跳过、0 失败，六段都一次跑完，合计与收集到的 29114 条相同。中途按使用者的话停过一次：前四段跑完后第 5 段停在约 51%，核对工作区没有变（`git diff HEAD` 和两个未跟踪文件的哈希）之后，第 5、6 两段从头跑。各段用时合计 3:26:12（前四段 40:15，最佳性能；后两段 2:45:57，最佳能效）。
  - 真实宿主里没有跑。PowerShell 7 上没有量。
  - 代价：有后端时，`$x.Count`、`$a[0]`、`[int]$x`、`1..10`、`'{0}' -f $x` 写在命令参数之外也直接问；`uv run --with $pkg pytest`、`-Force:$x` 只要带变量就不送审；带类型的函数参数一律算。
  - **O-3 没有修，等使用者决定**：单独成句的变量和带变量的字符串不在任何命令里。`Get-Date; $env:SECRET_TOKEN` 由规则放行（不需要后端），把环境变量的值打印进上下文；`Write-Output $env:SECRET_TOKEN` 是灰色。和 X1 审查的 H-4 是同一类（当时评为高危），`m3a-done` 起就有。两种修法都有代价：当作 `Write-Output <表达式>`（单独一条的表达式会从不送审变成带着文字送审），或只标灰色（`git status; "exit=$LASTEXITCODE"` 在默认配置下由 allow 变成问）。（修订 22 已修，见下一条。）
  - **修一处"看不到的文字"时，把同一类的位置都扫一遍：这次从一条表达式查出了带盘符的变量、开关值、运行器选项、命令名四处。探针要让发送闸门自己判"送不送"，并检查请求的 JSON 里有没有那段文字。**
- **PowerShell 里值有去处的表达式，规格修订 22**（2026-11-11，已提交并推送，`646cb05` 代码，文档在其后一个提交，未打标签；记录 `docs/reports/M3a-ps-expression-output.md`）：使用者说"按照你建议执行；先提交修订21再去修改O-3"。O-3 的两种修法里开发 agent 推荐并采用"当作 `Write-Output <表达式>`"。
  - PowerShell 里表达式可以站在命令的位置上，`$env:TOKEN` 单独成句就把值打印出来（实测 5.1）。原来 `Get-Date; $env:SECRET_TOKEN`、`Get-Date; "key $env:SECRET_TOKEN"`、`Get-Date; ($env:SECRET_TOKEN)` 由规则放行，不需要后端。
  - 现在辅助进程把值有去处的表达式报成一条命令（名字种类 `output`），`pscmd` 记成 `Write-Output <表达式>`：单独成句、`return` / `throw` 后面、管道开头、`foreach` 的集合、`switch` 的条件。带变量的是灰色 `ps-dynamic-arg`（H-4 给 `Write-Output $env:TOKEN` 定的原因），送审，请求里有它的文字。
  - 不记的：值已经知道的（常量，`$true`、`$false`、`$null`）；`if` / `while` / `for` 的条件、`exit` 后面、赋值右边；命令参数里的；带盘符的变量本身；只包着命令的括号。
  - 会动手的表达式照旧不送审（修订 21 的 `ps-outside-command`），所以 O-3 当时写的那条代价没有发生。规则条目与策略文件没变，Bash 没变。
  - 专门扫描 928 行（32 种文字 × 29 个位置）：52 行由 allow 变成灰色送审（这就是 O-3）；带变量的行里修改前 57 行 allow，修改后剩 5 行，都是 `(Get-Location)`。变松 122 行，都是整行没有命令、原来靠"什么都没看懂"直接问的，现在和 `Write-Output` 的写法一样送审。没有一行少记路径。
  - 手头语料 1146 条 PowerShell 命令：级别变了的 0 条。
  - 测试：新测试 167 条，在修订 21 的代码上 127 条失败。夹具重新生成，36 个多了 `output` 命令。原有差分全部相同（修订 17 的扫描连着跑时有 1 行撞到时间预算，单独重跑后相同）；`boundkeep test` 1142 / 0、334 / 0；评测指标相同，`eval/report.md` 没有重新生成。变异 45 个，44 个抓到，1 个存活的是等价的（赋值右边的表达式不在管道里，前一个检查已经挡掉）。
  - 全量分六段跑，不是一个进程：29110 通过、169 跳过、**1 失败**，六段都一次跑完，合计与收集到的 29280 条相同，各段用时合计 2:42:49（开始时是最佳能效）。失败的是 `test_m1c2_devtools_bash.py` 里 `python -x -m pytest` 那一条（Bash），结果里多了一条 `budget:time`，归一化撞到了时间预算。全量结束后单独重跑，这次的代码和 `e52c596` 的代码各 5 次都通过，整个文件各 463 通过。这次没有改 Bash 的路径。
  - 真实宿主里没有跑。PowerShell 7 上没有量。
  - 代价：`git status; $LASTEXITCODE`、`npm test; "exit=$LASTEXITCODE"` 在默认配置下由 allow 变成问（`Write-Output $LASTEXITCODE` 原来就是）；`"${E:\proj\README.md}"`、`@{ a = 1 }`、`('x')` 单独成句也变灰色；多出来的 `Write-Output` 占发送闸门的 8 条命令上限。
  - 没有做：`if ($env:A)`、`exit $env:A` 的文字仍不在请求里；`foreach ($u in '常量')` 和函数参数默认值绑的常量也不在。`$LASTEXITCODE`、`$?` 没有放进常量表。
  - **给不是命令的东西起一个命令名时，值已经知道的要直接放过：`Write-Output` 没有 allow 规则，照记的话 `Get-Date; 'done'` 也会变成问。先看那个名字在规则层是怎么判的。**
- **`$LASTEXITCODE` 和 `$?` 算已知值，规格修订 23**（2026-11-11，已提交并推送，`8d268d3` 代码（修订 23 到 26 一起），`ced7a87` 文档，未打标签；记录 `docs/reports/M3a-ps-known-variables.md`）：使用者说"当做已知值"。
  - 值有去处的表达式里，不带作用域的 `$LASTEXITCODE`、`$?` 和只含它们的双引号字符串不记成 `Write-Output`。`git status; $LASTEXITCODE` 回到由规则放行。
  - 实测这个名字能被同一行绑上任意值，所以加了两道限制。直接加名字的话 `param($LASTEXITCODE = $env:SECRET_TOKEN) Get-Date; $LASTEXITCODE` 由规则放行，打印环境变量。
    - 名字是它的参数和 `foreach` 变量：辅助进程报 `AutomaticVariable`，整行灰色 `ps-outside-command:AutomaticVariable`，不送审。写在命令参数里的脚本块里也报。
    - 只在安静的一行里算：每条命令的名字和参数都是常量，没有一个参数可能指到这个名字（含 `lastexitcode`，或最后一段是能匹配它的通配符）。`Set-Variable`、`-OutVariable`、`Tee-Object -Variable`、`Set-Item Variable:\LAST*` 都能给它放值（实测）。不安静时照旧是 `Write-Output`。
  - 没有改 H-4 那张表：它管所有命令、两种 shell，而 `Write-Output` 没有 allow 规则。命令参数里的 `$LASTEXITCODE` 不变。
  - 规则条目与策略文件没变，Bash 没变。专门扫描 1080 行（24 种文字 × 45 个位置）：变松 50 行，全是已知值写在放行的命令旁边；给这个名字放值的 18 种写法没有一行放行。手头语料 1146 条：0 条变化。
  - 测试：新测试 190 条（在修订 22 的代码上 88 条失败）；变异 35 个全部抓到；原有差分全部相同。全量（修订 23 到 26 一起跑）分六段跑，不是一个进程：29659 通过、169 跳过、0 失败，六段都一次跑完，合计与收集到的 29828 条相同，各段用时合计 2:21:22（开始和结束时电源都是最佳性能）。
  - 冒烟脚本的 `readings` 加了修订 17 到 24 的 10 条探针（共 19 条调用），`--dry` 23 项 0 失败。真实宿主（2026-11-12，Claude Code 2.1.318，使用者在自己的终端里运行）：23 项 0 失败，约 0.215 美元，记在 `docs/hook-behavior.md`。只验证每次修订的一条代表写法；R21-1 的长命令、Bash 工具、子目录里的工作目录没有覆盖。
  - 代价：有后端时安静的一行送审的请求里没有这次打印（能给它放值的只剩这一行运行的代码，那些代码自己就能打印）；`Get-ChildItem src\*; $LASTEXITCODE`、`pytest $args; $LASTEXITCODE` 里它仍是 `Write-Output`。
  - **把一个变量算作已知之前，先量它能不能被同一行改掉：参数、`foreach`、按名字放值的命令（含通配符）都要试。**
- **修订 21 和 22 的复审**（2026-11-11，已提交并推送，在 `ced7a87` 里；`docs/reviews/M3a-rev21-22-review.md`，不是独立的，同一个会话做的）：两次修订的目标达到了，没有回退，没有不需要后端的放行。范围之内高危 0、中危 1、低危 1、信息 3；范围之外 1 条。R21-1、R22-1 已修（下一条），O-2 已修（再下一条）。
  - R21-1（中，要后端）：`pscmd` 的灰色原因最多记 64 条（M1b 就有）。一行里先用不认识的参数凑够 64 条，`ps-switch-value`、`ps-runner-value`、`ps-pipe-to-interpreter` 就记不进去，整行照常送审，请求里没有被丢掉的文字。建议：上限满了改记 `ps-too-large`，直接问。
  - R22-1（低，要后端）：参数默认值是变量时不在请求里，`param($x = $env:SECRET_TOKEN) Get-Date; $x` 送审的请求里只有 `Write-Output $x`。早于修订 21。
  - O-2（范围外，按 F3、F4 的标准是中危，要后端，两种 shell）：`uv run`、`uvx`、`pipx run` 自己的选项不在请求里，也不进规则：`uv run --env-file .env pytest`、`uv run --index-url https://… pytest` 的请求里只有 `pytest -q`。
  - 信息：`for` 的初始化和迭代位置不记（实测不打印）；`$true`、`$false`、`$null` 绑不上别的值（实测）；带盘符的变量各种写法里会读文件的都按读文件判。
- **复审的两条修复，规格修订 24**（2026-11-12，已提交并推送，`8d268d3` 代码（修订 23 到 26 一起），`ced7a87` 文档，未打标签；记录 `docs/reports/M3a-rev21-22-review-fixes.md`）：使用者说"先修这两条"。
  - R21-1：`pscmd` 的灰色原因记满 64 条之后又来新的，这一行加上 `ps-too-large`（放在第一条），不送审。`pipeline` 没有改，`ps-too-large` 本来就不送审。复审的 4 种写法现在都不送审。
  - R22-1：辅助进程把参数的默认值报成名字种类 `output` 的一条命令，`pscmd` 照修订 22 读成 `Write-Output <默认值>`。值已经知道的、写在脚本块参数里的、带盘符的变量本身、只包着命令的括号不记。
  - 规则条目与策略文件没变，Bash 没变。专门扫描 240 行（20 种默认值 × 12 种写法）：18 行由 allow 变成灰色送审，没有变松；带变量的默认值送审时请求里都有它（原来 72 行里 45 行没有）。手头语料 1146 条：0 条变化。
  - 测试：见记录；原有差分全部相同。全量：见修订 23 那一条（四次修订一起跑，0 失败）。
  - 代价：`param($x = $env:USERNAME) Get-Date` 由 allow 变成灰色；带 64 个以上不同灰色原因的一行不再送审。
  - **"不送审"靠的是某一条原因在不在，所以任何会丢原因的地方（条数上限、截断、去重）都要当成"没看全"处理。**
- **运行器自己的选项，规格修订 25**（2026-11-12，已提交并推送，`8d268d3` 代码（修订 23 到 26 一起），`ced7a87` 文档，未打标签；记录 `docs/reports/M3a-runner-options.md`）：复审的 O-2，使用者在三种做法里选"带值选项就不送审"。
  - `uv run`、`uv tool run`、`uvx`、`pipx run`、`poetry run` 带了有值的选项（`--with`、`--env-file`、`--index-url`、`--python`、`--spec` 等）时不送审、直接问：Bash 方言是灰色 `runner-option-value`，PowerShell 方言是 `ps-runner-value`（修订 21 就有，原来只管值带变量的）。只带开关的照常送审。
  - `programs.peel_runner_options` 多返回一项"有没有带值的选项"；`peel_runner` 不变。`pipeline._UNSHOWN_REASONS` 加了 `runner-option-value`。
  - 规则层没有变（带 `wrappers` 的动作本来就不由 allow 规则放行），规则条目与策略文件没变。专门扫描 620 行（31 种前缀 × 10 种命令 × 两种 shell）：带值选项的行原来 297 行送审，现在 0 行；其余一项没变。手头语料 PowerShell 1146 条、Bash 1880 条 × 两个平台：0 条变化。
  - 测试：见记录；原有差分全部相同。全量：见修订 23 那一条（四次修订一起跑，0 失败）。
  - 代价：有后端时 `uv run --with rich pytest`、`uv run --python 3.12 pytest` 直接问。`uv run --env-file .env pytest` 是问，不是 deny：选项的值仍然不进路径层和域名层。
  - W-1（`sudo -u`、`env -C` 的值不在请求里）修订 26 已修，见下一条。
- **包装器自己吃掉的词，规格修订 26**（2026-11-12，已提交并推送，`8d268d3` 代码（修订 23 到 26 一起），`ced7a87` 文档，未打标签；记录 `docs/reports/M3a-wrapper-options.md`）：使用者说"W-1 也照同样的办法修"。
  - Bash 方言里 `sudo`、`env`、`time`、`nice`、`timeout`、`xargs` 等包装器被剥掉时，吃掉的词里有不是开关的（选项的值、`nice -5`、`timeout 60` 的时长、`gosu user` 的用户），这次调用不送审：灰色 `wrapper-option-value`。只带开关的照常送审。PowerShell 不剥这些名字，没有变。规则层不变。
  - 带 `env -S` 时 env 不被剥掉，整条连同选项记下，值在请求里，不标。第一版把它也标了，扫描查出请求里本来就有那个值，改掉了。后面没有命令时包装器不被剥掉，也不标。
  - 专门扫描 450 行：176 行由送审变成问，没有一行变松，没有一行少记路径。手头语料 Bash 1880 条 × 两个平台：4 条由送审变成问（3 条 `timeout 5 pytest`，1 条 `env -C ~/.claude sh -c "echo x > settings.json"`，后者正是这一类问题）。
  - 测试：新测试 195 条；`tests/corpus/bash_parse.yaml` 的 23 条包装器条目补上新的灰色原因。变异 13 个，第一轮存活 1 个（缺 `env -C x -S '…' tests` 这种写法的测试），补测试后全部抓到。原有差分全部相同。全量：见修订 23 那一条（四次修订一起跑，0 失败）。
  - 代价：有后端时 `timeout 60 pytest`、`nice -n 10 make` 直接问。值仍然不进路径层：`env -C ~/.claude sh -c "echo x > settings.json"` 是问，不是 deny。
  - **看"请求里有没有"要量请求本身：带 `env -S` 的那一条从代码上看像是丢了值，实际 env 命令被整条记下了。**
- **修订 23 到 26 的复审**（2026-11-12，已提交并推送，在 `4b76463` 里；`docs/reviews/M3a-rev23-26-review.md`，不是独立的，同一个会话做的）：四次修订的目标达到了，没有回退，没有不需要后端的放行。范围之内高危、中危 0，低危 1，信息 3；范围之外 1 条。O-4、RV26-1、RV24-1 已修（规格修订 27，下一条）。
  - RV26-1（低，要后端，Bash）：包装器的长开关写成 `--名字=值` 时，值被丢掉、不标：`sudo --preserve-env=X pytest` 送审，请求里没有 X。GNU `env`、`timeout` 拒绝这种写法（实测，命令不运行），带 `xargs` 的行由规则问；效果不超过照常送审的 `sudo -E`。
  - 信息：RV23-1 用 `ſ`、`ı`、`İ` 写的名字不是 `$LASTEXITCODE`（实测）；RV24-1 三张类型表截在 64 条，实际碰不到；RV25-1 `python -Xdev -m boundkeep` 不记带值，规则本来就问。
  - O-4（范围外，按 F3、F4 的标准是中危，要后端，只在 PowerShell）：超过 32768 个字符的字符串常量只剩前 200 个字符，整条照常送审。`Invoke-Expression`、`Add-Type` 实测执行或编译了请求里看不到的尾部；照 Claude Code 启动 PowerShell 的方式（脚本放在环境变量里），7 万个字符的脚本也能运行。M1b 起就有。建议按 `ps-too-large` 处理，不送审。
  - **找"请求里看不到的文字"时也要看截断：辅助进程截到 200 个字符，低于发送闸门 400 个字符的上限，闸门就发现不了。**
- **复审的三条修复，规格修订 27**（2026-11-12，已提交并推送，`86a7e2f` 代码（修订 27、28 一起），`4b76463` 文档，未打标签；记录 `docs/reports/M3a-rev23-26-review-fixes.md`）：使用者说"按建议顺序修三条"。
  - O-4：`pscmd._convert` 遇到辅助进程截短的字符串（`TooLongString`）时，这一行加上 `ps-too-large`，不送审。辅助进程报的每个元素都经过这里，所以只改这一处；辅助进程和夹具没有改。
  - RV26-1：Bash 包装器的长开关写成 `--名字=值` 时置 `taken`，灰色 `wrapper-option-value`，不送审。包装器照旧被剥掉，里面的命令照旧由规则判。
  - RV24-1：`_type_names` 截断 `compound`、`dynamic`、`loose` 时置 `overflow`，这一行加上 `ps-too-large`。
  - 规则条目与策略文件没变，没有后端时判决级别不变。新测试 90 条（在 `ced7a87` 上 42 条失败）；专门扫描 627 行，没有一行变松，没有一行少记路径；语料 0 条变化；变异 10 个全部抓到；原有差分全部相同。全量：见修订 28 那一条（两次修订一起跑）。
  - 代价：有后端时带超长字符串的 PowerShell 命令、`sudo --preserve-env=LIST …` 直接问。
  - 修的时候查到 O-5（绑到变量上的常量不在请求里），修订 28 已修，见下一条。
- **绑到变量上的值，规格修订 28**（2026-11-12，已提交并推送，`86a7e2f` 代码（修订 27、28 一起），`4b76463` 文档，未打标签；记录同上，第 7 节）：使用者说"O-5 也按你的建议修"。
  - 原来：修订 22、24 让 PowerShell 里值已经知道的表达式（常量）不建 `Write-Output`，理由是打印它不多给什么；但参数默认值、`foreach` 的集合、`switch` 的条件、管道开头、函数体的输出是把值绑到变量上或交给调用者。`param($p = '~\.ssh\id_rsa') Get-Content $p` 送审，请求里只有 `Get-Content $p`（直接写路径是 deny）；`param($x = '<代码>') Invoke-Expression $x` 送审，请求里没有代码。Bash 的 `for p in ~/.ssh/id_rsa; do cat "$p"; done` 也一样。修订 24 只看了带变量的默认值，修订 23 到 26 的复审也没有查到；修这三条时的扫描（`rv27_scan.py`）里出现了"送审、请求里没有标记"的几行，才看出它们和打印不是一回事。
  - 现在：辅助进程给绑定位置上的这种条目加 `"bind"`（`default`、`foreach`、`switch`、`head`、`body`）；`pscmd` 遇到其中值已经知道的，照旧不建命令，另记 `ps-bound-value:<位置>`；Bash 解析器给带词表的 `for` / `select` 记 `for-words`。都进 `BashResult.unshown`，再由 `event` 放进这一行每个动作的 `unshown`：规则不看它，判决不变，灰色时不送审。
  - 修的时候查到、一起修的：`data v { '…' }` 数据段、函数体里的常量输出（`function f { '<代码>' }; Invoke-Expression (f)`）、Bash 的 `for` / `select`。
  - 测试与测量：新测试 116 条（在 `ced7a87` 上 77 条失败）；专门扫描 316 行，没有一行变松，没有一行少记路径；语料 PowerShell 1146 条里 9 条由送审改为不送审（都在 `tests/corpus`），Bash 0 条；夹具 26 个只多了 `bind`；变异 20 个，1 个等价存活（PowerShell 5.1 里类的方法体外面还有一层 `FunctionDefinitionAst`）。`switch -File` 的路径不算绑定（修订 21 已经不送审）。原有差分全部相同。全量（修订 27、28 一起跑）分六段跑，不是一个进程：29866 通过、169 跳过、0 失败，合计与收集到的 30035 条相同，各段用时合计 2:24:42（开始、续跑和结束时电源都是最佳性能）。中途按使用者的话停过一次：前五段跑完后第 6 段停在约 95%，核对工作区没有变（限于代码、测试等目录的 `git diff HEAD` 和两个新测试文件的哈希）之后，第 6 段从头单独跑。
  - 真实宿主里没有跑。PowerShell 7 上没有量。
  - 代价：有后端时 `foreach ($f in 'a.py', 'b.py') { ruff check $f }`、`for f in *.py; do ruff check "$f"; done`、`'x' | Out-File out.txt` 这类灰色调用直接问。由规则放行的（`param($n = 5) Get-Date`）不变。
  - **给已知值开豁免时要分清"打印"和"绑定"：值进了变量，之后可能被执行或当路径用，请求里就得有它，否则不送审。**
- **修订 27 和 28 的复审**（2026-11-13，已提交并推送，在 `b480453` 里；`docs/reviews/M3a-rev27-28-review.md`，不是独立的，同一个会话做的）：修订 27 的三个目标达到了；修订 28 部分达到，记录里列的位置都堵上了，同一类还有三处没有覆盖。没有回退，没有不需要后端的放行。范围之内中危 3，范围之外 1 条，都要后端，复审时都没有修（修订 29 已修，见下一条）。
  - R28-1：类的属性初值不在请求里（`class C { static [string]$p = '…' }; Invoke-Expression ([C]::p)` 送审）。
  - R28-2：被 `catch` / `trap` 接住的 `throw` 把值交给 `$_` 和 `$Error`，修订 22、28 却把它算作打印。
  - R28-3：条件里的 `-match` / `-notmatch` 把值交给 `$Matches`。
  - 三处实测（PowerShell 5.1）都读出了编出来的文件，`Invoke-Expression` 也执行了。
  - O-6（范围外，M1 的解析器起就有）：Bash 解析器中途停下（嵌套超过 32 层、词数、记号数、1 MiB）时，停下之后的命令规则看不到，整条照常送审，请求里只有停下之前的命令。嵌套 40 层的 `{ }` 约 100 个字符，Git Bash 实测照样运行里面的命令。没有后端时 deny 变成问。修订 27 的记录写"Bash 的词不截"，没有核对整行的截断。
  - 建议先修 O-6（`_UNANALYSED_PREFIXES` 一处），再一次修 R28-1 到 R28-3（都在辅助进程里）。
  - **截断要看两层：单个值被截短，和整行在中途停下。停下之后的文字也是"请求里看不到的文字"。**
  - **找"绑定"要从"哪些语法会给变量放值"列起（参数、循环、属性、异常、正则的自动变量），不能只在已知的输出位置里挑。**
- **复审的四条修复，规格修订 29**（2026-11-13，已提交并推送，`fed8930` 代码、`b480453` 文档，未打标签；记录 `docs/reports/M3a-rev27-28-review-fixes.md`）：使用者说"按建议顺序修"。
  - O-6：Bash 解析器中途停下的五种原因（`nesting-too-deep`、`too-many-words`、`too-many-tokens`、`too-long`、`depth-exceeded`）进了 `pipeline._UNANALYSED_PREFIXES`，这样的一行不送审、直接问。解析器没改。
  - R28-1、R28-3：辅助进程把类的属性初值（`enum` 除外）和命令参数之外 `-match` / `-notmatch` 的左边，像参数默认值一样报成带 `bind` 的条目（`property`、`match`，新函数 `Add-Bound`）。`pscmd` 不用改。
  - R28-2：函数之外 `throw` 后面的值一律算绑定（`throw`）。复审建议只在有 `catch` / `trap` 时算；第一轮变异里"只有 `finally` 也算"存活，追下去实测 `finally` 里、`Set-Variable ErrorActionPreference SilentlyContinue` 之后都能从 `$Error` 拿到这个值，所以改成一律算，规格同步改了。
  - 规则条目与策略文件没变，没有后端时判决级别不变。新测试 126 条（第一版 122 条在 `4b76463` 上 66 条失败）；专门扫描没有一行变松，没有一行少记路径，"送审、请求里没有标记"由 116 行降到 16 行（都是 `-like` 对照）；语料 0 条变化；夹具 1 个只多了 `bind`；变异第二轮 18 个全部抓到。原有差分全部相同（中途按使用者的话停过一次，继续时补跑了剩下的三步）。全量分六段跑，不是一个进程：29990 通过、169 跳过、**2 失败**，六段都一次跑完，合计与收集到的 30161 条相同，各段用时合计 3:45:55（开始时是最佳能效，09:56 左右第 3 段中使用者换成最佳性能）。失败的两条都在第 1 段，是这次没改的模块里的计时测试（`test_daemon.py` 的 200 个并发请求、`test_install.py` 的钩子超时用时），那一段结束时可用内存只剩 558 MB；全量结束后单独重跑，这次的代码和 `4b76463` 的代码各 5 次都通过。
  - 代价：有后端时，嵌套超过 32 层的 Bash 命令、带常量属性初值的类、`throw` 一个常量（含 `pytest; if (-not $?) { throw 'failed' }`）、命令参数之外拿常量做 `-match` 直接问。
  - **复审的建议也要实测：它的前提（"没有 catch 就拿不到"）在变异测试里露了馅，量过才知道不成立。**
- **修订 29 的复审**（2026-11-14，已提交并推送，在 `a33c163` 里；`docs/reviews/M3a-rev29-review.md`，不是独立的，同一个会话做的）：四个目标都达到了，上次复审的写法和这次加的变体都不送审。没有回退，没有不需要后端的放行。范围之内中危 1，范围之外 1 条，都要后端，复审时都没有修（修订 30 已修，见下一条）。
  - R29-1：条件里的比较运算报错时，报错信息带着条件里的文字进 `$Error` / `$_`：`-like` 的模式不合法（`'BKCANARY['`）、`-lt` 一类转不成类型、`switch -Wildcard` / `-Regex` 的条件不是已知值时标签不合法。都送审，请求里没有那段文字；实测（PowerShell 5.1）读出了编出来的文件，`Invoke-Expression` 也执行了。
  - O-7（范围外，M3a 的发送闸门起就有）：脚本读得到自己的全文。Claude Code 的 PowerShell 工具把整段脚本留在 `$__claudeCodeScript` 里（环境变量清掉了，变量还在）；Bash 有 `$BASH_EXECUTION_STRING`、`/proc/$$/cmdline`、`set`。注释、单独成句的常量、条件里的文字都能变成路径或代码，请求里都没有。在这个会话的真实工具里实测：只写在注释里的路径被读出，注释里的代码被 `Invoke-Expression` 执行。修订 22 起"打印常量不多给什么"的前提因此不成立，修订 28、29 一处一处补的这一类补不完。
  - 建议先请使用者定 O-7 的方向：A（推荐）请求带上整行的全文，设总长上限，R29-1 一起解决；B 把读脚本自身的写法记进 `unshown`，做不全；C 只堵注释。
  - **找"请求里看不到的文字"时，先问脚本能不能读到它自己：能的话，所有不在请求里的文字都是通道，一处一处补补不完。**
  - **报错也是把值放进变量的地方：比较、类型转换、模式解析失败都会把文字带进 `$Error`。**
- **请求带上命令全文，规格修订 30**（2026-11-14，已提交并推送，`bc5137f` 代码、`a33c163` 文档，未打标签；记录 `docs/reports/M3a-rev29-review-fixes.md`）：使用者对 O-7 选"A：请求带全文"。
  - Bash、PowerShell 的请求多了 `command`：命令全文，整段发，主目录写成 `~`；取自动作本来就带着的 `Action.command_text`，流水线和审计器不用改。`schema` 改为 `boundkeep.audit-request/2`，系统提示词改为版本 2（说明以全文为准，读自身全文、用注释或报错信息拼代码算混淆执行）。只改了 `send_gate.py`、`prompt.py`、`audit_system.md`。
  - 不发的情形：全文超过 4000 个字符；带控制字符或格式字符；全文或任何一个词经过脱敏会变（带秘密的 shell 命令整条不发，不发脱敏过的全文：脱敏会整段吞掉文字，比如私钥块）。原来"不送审"的情形一条都不放宽，here-document 的正文仍然不离开本机。
  - 上限按语料定：今天会送审的 2025 次里命令最长 472 个字符，加全文后请求最长 2591 个字符。
  - 规则层不变。复审的 102 条探针重跑：判决、送不送审都没有变，原来送审却看不到标记的 31 条现在都看得到。新测试 61 条（在 `b480453` 上 51 条失败）；变异 14 个全部抓到；改了 4 个旧测试文件（期望变了的：带秘密的 shell 命令由"脱敏后发"改为"不发"，提示词版本 `v2`）。语料 4906 次判决：级别 0 次变化，送审变成不送审 16 次（`Write-Output a<NUL>b` 1 次；名字像秘密的变量写成 `名字=值` 的 15 次，如 `echo token=$X_TOKEN`，都在 `tests/corpus`），评测集 0 次。原有差分全部相同（它们只看判决，用不到发送闸门）。全量分六段跑，不是一个进程：30054 通过、169 跳过、0 失败，合计与收集到的 30223 条相同，各段用时合计 2:24:44（全程最佳性能），跑完后代码的哈希与开始时相同。
  - 代价：请求长了一些（语料里中位数 390 → 426 个字符，最长 2572）；有后端时，超长的、带控制字符的、带像秘密的文字的 shell 命令直接问；模型看了全文之后判得怎样，要到 M3b 才量得到。
  - **请求是给模型看的，"规则层的读法"不能代替原文：读法总会漏掉一部分，而脚本读得到自己的原文。**
- **修订 30 的复审**（2026-11-15，已提交并推送，在 `d4f2393` 里；`docs/reviews/M3a-rev30-review.md`，不是独立的，同一个会话做的）：使用者说"完成修订 30 的任务"。目标达到，没有回退，没有放行。39 条探针在新旧代码上比；参数里带命令的 MCP 调用（`unanalysed:mcp-command`）、here-string、here-document 前后都不送审，只提秘密变量名字的命令照常送审。
  - R30-1（低）：`_Places.word` 换主目录不看边界，`<主目录>x\a.txt` 在 `command` 和 `args` 里显示成 `~x\a.txt`（Bash 里是用户 `x` 的主目录）；`paths` 是对的。
  - R30-2（低，隐私）：Git Bash 的 `/c/Users/<名字>/…` 和字符串里转义过的 `C:\\Users\\<名字>` 不换，用户名随请求发出；规格和隐私文档没说这是尽力而为。
  - R30-3（信息）：发送闸门用 `str.isprintable()`，拒绝的还有 ASCII 空格以外的空白（不换行空格、全角空格）、`U+2028`、私用区、未分配的码位（比 Unicode 15.0 新的 emoji）；文档只写了控制字符和格式字符。修订 30 起注释里的也算，6 条这样的探针由送审改为直接问。建议只改文档。
  - 冒烟：`scripts/smoke_claude_m3a.py` 的 readings 一段加了一条带注释的送审调用，检查假后端收到的 `command` 等于宿主发来的命令、`schema` 是 `/2`、注释不在动作里。`--dry` 试跑 26 项 0 失败；检查本身用旧格式、文字不同、标记在动作里三种请求对照过，都判为失败。真实宿主里由使用者运行（`uv run python scripts/smoke_claude_m3a.py --only readings`）。使用者跑了两次，代码是修订 31 的工作区：第一次 23 项失败，宿主的模型把整串命令当成安全测试拒绝了，一次也没调用（11-12 那次第一次也被拒绝过）；脚本的 readings 提示词改为如实说明测试，整串都没调用时换新会话再问；第二次 26 项 0 失败，约 0.111 美元。
  - 都要后端，复审时都没有修。建议：R30-1、R30-2 一起修（先改规格）；R30-3 只改文档。修订 31 已修，见下一条；修的时候又发现 R30-4。
  - **送出去的内容变了范围，原来只在词上用的近似（主目录换成 `~`、哪些字符算可打印）要在新范围上重新量：它们的毛病会跟着进新字段，而且新字段里的写法更多。**
  - **冒烟的提示词要如实说明在测什么：一串看起来像攻击的命令，宿主的模型会整串拒绝，钩子什么也没收到，失败的检查说明不了 boundkeep。先看模型调用了没有。**
- **主目录写成 `~` 的修复，规格修订 31**（2026-11-15，已提交并推送，`ad36e99` 代码、`d4f2393` 文档，未打标签；记录 `docs/reports/M3a-rev30-review-fixes.md`）：使用者说"按建议修"。
  - 只改了 `send_gate._Places.word`：
    - 主目录多认四种写法：`C:\\Users\\<名字>`、`/c/…`、`/mnt/c/…`、`/cygdrive/c/…`，长的先试（R30-2）；
    - 后面必须是名字结束处，前面不能接着别的路径，选项字母（`-I`、`/I`）后面照样换（R30-1）；
    - 字母只按单个字符的大小写对应匹配，不做 Unicode 折叠；
    - 用正则直接在原文上找。
  - R30-4（中，修的时候发现）：原来在 `lower()` 过的文字上找、在原文上换。`İ` 小写后是两个字符，写在主目录前面，主目录就留在请求里，它后面同样长的文字被删掉，注释里的东西可以这样藏起来。词里从 M3a 起就这样。一起修了，复审报告加了后记。
  - R30-3 只改文档：拒绝的字符按 `str.isprintable()` 照实写。
  - 规则层、判决、送不送审、请求格式、提示词都不变。新测试 90 条（在 `a33c163` 上 32 条失败）；相关旧测试 373 条一条没改都通过；变异 19 个全部抓到；复审的 43 条探针判决和送不送审 0 变化，请求文字变了 9 条（都是预期的）。语料 4906 次判决级别 0 次变化，送审的 2009 次请求长度都没变。原有差分全部相同。全量分六段跑，不是一个进程：30144 通过、169 跳过、0 失败，六段都一次跑完，合计与收集到的 30313 条相同，各段用时合计 2:25:24（开始和结束时电源都是最佳性能），跑完后代码的哈希与开始时相同。真实宿主里只跑了上一条的冒烟（26 项 0 失败），命令里没有主目录。
  - 第一版的左边界不认选项，`-I/home/<名字>/include` 原来换、第一版不换，自己试的时候发现，加了例外。
  - **在变换过的文字上找位置、回到原文上改，是同一类错：只要变换会改变长度（`lower()` 遇到 `İ`），位置就错开。要么在原文上找，要么证明变换不改长度。**
- **修订 31 的复审**（2026-11-15，已提交并推送，在 `68ab7c7` 里；`docs/reviews/M3a-rev31-review.md`，不是独立的，同一个会话做的）：使用者说"先复审修订30"，问清楚后选"复审修订 31"。R30-1、R30-2、R30-4 都修好了，没有放行，判决和送不送审不变。`_Places.word` 直接调用 30 条（新旧代码比）、整条链路 16 条。
  - R31-1（低，隐私，退步）：原来换、现在不换：粘在长选项后面（`-isystem/home/<名字>`、MSVC 的 `/Fo<主目录>\…`），和 `<主目录>.\…`（Win32 实测打开的就是主目录）。用户名随 `command`、`args` 发出，`paths` 是 `~`。规格说过"不能因为加了边界就少换"。
  - R31-2（低）：右边界里的字符在 shell 里会接着名字：`<主目录>{2,3}`、`[23]`、Bash 的 `\2`、`'2'`，引号里的空格和标点。模型看到 `~{2,3}/notes.txt`，实际是兄弟目录；`paths` 是对的。盘符和 POSIX 写法原来就这样，Git Bash 写法是修订 31 带来的。规格和记录把它写成"名字结束的地方"，不准确。
  - R31-3（信息）：`${D}/home/<名字>`、`$(pwd)/…` 前面的词没结束，照样换，送审。R31-4（信息，文档）：混用分隔符、`~<名字>`、`C:\Documents and Settings\<名字>` 不换，规格的列表里没有。
  - 核对过：只有 `U+0130` 的小写会变长（Python 3.12 全部码位）；`src` 里别处没有在变换过的文字上找位置的；"长的先试"对结果完全没有影响（记录说"几乎没有"）；每次不到 1 毫秒。
  - 都要后端，复审时都没有修。建议：R31-1、R31-2 一起改（先改规格）：选项例外放宽到几个字母，单个尾随点算结束；解析过的词只认末尾和分隔符；全文去掉 `{}[]`，斜杠写法去掉 `\`。R31-3、R31-4 只改规格文字。已修，见下一条（修订 32）。
  - **加了一个限制条件，要把原来匹配、现在不匹配的写法列出来逐个看：规格里写了"不能少换"，测试只覆盖了想到的那几种。**
  - **命令全文是没解析过的 shell 文字，词是解析过的值：同一个字符（空格、引号、`\`、`{`）在两边意思不同，边界不能共用一套。**
- **主目录边界的修复，规格修订 32**（2026-11-16，已提交并推送，`80909e2` 代码、`68ab7c7` 文档，未打标签；记录 `docs/reports/M3a-rev31-review-fixes.md`）：使用者说"按建议修"，之后说"分两次提交"、"推送"。先改规格，再改 `send_gate`。
  - R31-1：选项是 `-`、`--`（盘符写法还有 `/`）加几个字母，要在词的开头，换的时候留着；盘符写法后面单个 `.` 再接本来算结束的字符，也换，点留着。
  - R31-2：命令全文的边界去掉 `{`、`[`、`]`，斜杠写法再去掉 `\`；规则层整个读成一个路径的词（和某个路径原文一字不差）只认分隔符和末尾。
  - R31-5（低，修的时候发现，M3a 起就有）：`flags` 不经过主目录替换，`-I/c/Users/<名字>/inc` 带着用户名发出。现在也换。
  - 和建议不同、规格里写了原因的：`}` 留着（PowerShell 里结束一个词，实测）；只有路径词按路径的边界，代码、列表照命令全文（按建议 `bash -c "cd <主目录> && ls"` 会少换）；路径词里盘符写法认 `:`（数据流），Windows 主目录的斜杠写法认 `\`（Git Bash 实测）。代价：Git Bash 里加了引号的 `'/c/Users/<名字>\x'`，命令全文不再换。
  - R31-3、R31-4 只改规格文字；修订 31 记录里两处说法照实更正。
  - 新测试 114 条；旧测试删了一行（`]` 后面算结束）；变异 37 个全部抓到；70 条探针判决、送不送审 0 变化，请求变了 14 条都是预期的；语料 4906 次判决级别 0 变化，送审 2009 次请求哈希都相同；原有差分全部相同（rv17 第一次在负载下辅助进程超时 1132 次，单独重跑相同）。全量分六段跑，不是一个进程：30257 通过、169 跳过、0 失败，合计与收集到的 30426 条相同，各段用时合计 2:27:03（开始和结束时电源都是最佳性能），跑完后代码的哈希与开始时相同。真实宿主里没有跑。
  - **复审的建议是在一种 shell、一类用法上想的。照做之前，在另一种 shell 和别的用法（代码、列表、`flags` 这类别的字段）上也量一遍。**
  - **对照新旧代码时，让脚本自己报出加载的是哪份代码，不对就停：PowerShell 变量不分大小写，循环变量 `$s` 覆盖了 `$S`，"旧代码"那一轮跑的其实是新代码，结果显示"0 条变化"。导出的旧代码树也要带上 `policies`。**
- **修订 32 的复审**（2026-11-16，已提交并推送，在 `9d041b6` 里；`docs/reviews/M3a-rev32-review.md`，不是独立的，同一个会话做的）：使用者说"复审修订32"。R31-1、R31-2、R31-5 都修好了，没有放行，判决和送不送审不变。直接调用 18 条（新旧代码比，脚本自己核对加载的代码）、整条链路 7 条、补充 4 条。
  - R32-1（低，隐私，退步）：主目录是 UNC 路径（`\\server\share\<名字>`）时被当成斜杠写法，后面的 `\` 不再算结束，命令全文和路径词都不换了。守护进程的主目录是 `USERPROFILE`，是 UNC 的很少见。
  - R32-2（低）：`=` 后面、粘在选项后面的路径不算路径词：`--directory=<主目录> Smith/src` 在 `args` 里、`-isystem<主目录> Smith/inc` 在 `flags` 里显示成 `~ Smith`；`paths` 是对的。修订 31 也这样，规格只写了命令全文会多换。
  - R32-3（信息，文档）：Git Bash 里 `<名字>./` 只对 MSYS 的程序是另一个名字，原生程序（`python`）读到主目录（实测）。R32-4（信息，文档）：PowerShell 在 `{` 处也结束一个词；用户名带空格时的转义写法不换；单独一个 `-` 在斜杠写法前照样换。
  - 核对过：记录里的实测都重新量过；路径词的认法；`task_intent` 是用户自己的提示，文档写明不换；其他字段不带用户名；203 条测试通过。
  - 都要后端，复审时都没有修。建议：R32-1、R32-2 一起改（先改规格）：`\\` 开头的主目录算 Windows 的；以路径原文结尾、前面是选项的词，后面那段用路径的边界。R32-3、R32-4 只改规格文字。（修订 33 已修，见下一条。）
  - **按写法（盘符 / 斜杠）定的规定，要回头对每种主目录的形状量一遍：UNC 主目录是 Windows 的，却不以盘符开头，落进了斜杠写法那一边。**
  - **一个值会出现在几种位置（单独成词、`=` 后面、粘在选项后面），修了一个位置，其他位置要逐个量。**
- **UNC 主目录与选项后面的路径，规格修订 33**（2026-11-16，已提交并推送，`72db96a` 代码、`9d041b6` 文档，未打标签；记录 `docs/reports/M3a-rev32-review-fixes.md`）：使用者说"按建议修"，之后说"分两次提交"、"推送"。先改规格，再改 `send_gate`。
  - R32-1：以两个反斜杠开头的主目录是 UNC 的主目录，认 `\\server\share\<名字>`、转义过的 `\\\\server\\share\\<名字>`（这两种和盘符写法一样，`\`、单个尾随点算结束，路径词里还认 `:`）和 `//server/share/<名字>`（命令全文里按斜杠写法，路径词里 `\`、`/` 都是分隔符）。实际影响比复审写的小：UNC 主目录下的路径是网络访问，规则层直接问，不送审；会送审的只有注释、字符串里的。
  - R32-2：`args`、`flags` 里的词以这个动作某个路径原文结尾、前面是选项（`-`、`--` 或 `/`，一个字母，再跟字母、数字、`_`、`-`，可以带 `=` 或 `:`），选项原样，后面那段按路径的边界换；长的原文先试。前面不是选项的（`pycache_prefix=`、代码、列表）照命令全文的规定换。规则层记下的原文实测是：`--directory=`、`-isystem` 后面的值，`-Wl,-rpath,…` 的 `,-rpath,…`。
  - R32-3、R32-4 只改规格文字，测试钉住了不换的写法（Git Bash 交给原生程序的 `<名字>./`、PowerShell 的 `<主目录>{x}`、转义空格）。
  - 规则层、判决、送不送审、请求格式、提示词不变。新测试 57 条（在 `68ab7c7` 上 21 条失败，通过的 36 条是对照）；相关旧测试 486 条一条没改都通过；变异 48 个，47 个抓到（第一轮"短的原文先试"存活，补了测试；"选项那段也换"是等价的）；74 条探针判决和送不送审 0 变化，请求变了 2 条（兄弟目录原样）；语料 4906 次判决级别 0 次变化，送审 2009 次请求哈希都相同；原有差分全部相同。全量分六段跑，不是一个进程：30314 通过、169 跳过、0 失败，合计与收集到的 30483 条相同；各段用时合计 3:44:47，比修订 32 慢约一半（电源一直是最佳性能，其他进程几乎不占 CPU，原因没查出来）；跑完后代码的哈希与开始时相同。真实宿主里没有跑。
  - 原有差分和全量的脚本放在临时目录里，这次跑之前被系统的存储感知删掉了（C 盘空间少，大约 7 天以前的临时文件都没了）。从会话记录里按写入和修改的顺序重建，放回原来的路径；差分输出和修订 32 逐行相同，全量前五段的清单按收集顺序切开，切点都和上次对上。
- **修订 33 的复审**（2026-11-17，已提交并推送，和修订 34 的文档在同一个提交里；`docs/reviews/M3a-rev33-review.md`，不是独立的，同一个会话做的，另请了一个只拿代码和规格的子代理单独找错，它报的每一条都重新量过）：使用者说"复审修订33"。R32-1、R32-2 都修好了，没有放行，判决和送不送审不变。整条链路 22 条（其中 9 条新旧代码比）、规则层的路径原文 34 条、新旧代码同一进程里的直接调用 21 条；相关测试 543 passed；记录里的数字都对得上。
  - R33-1（低，隐私，比修订 32 少换）：选项后面的值是一串路径（`-Wl,-rpath,<主目录>,-z,now`、`-DCMAKE_PREFIX_PATH=<主目录>;…`），规则层整段记成一个路径原文，修订 33 整段按路径的边界，`args`、`flags` 带着用户名。同一请求的 `paths` 本来就带着（规则层的读法），多出来的只是大小写。UNC 主目录写在 `-Wl` 里也送审，记录那句"UNC 主目录下的路径不送审"不准。
  - R33-2（低，隐私，少见）：`_OPTION_PREFIX` 只看形状，`/c`、`/cygdrive`、`/mnt`、`/srv`、`-C:`、只有一段的主目录 `/root` 都合，会把主目录的写法从中间切开（`echo /c/Users/<名字>/x > /Users/<名字>/x` 的 `args` 原样）。"选项那段也换"的变异不是等价的。
  - R33-3（低，多换，修订 33 新增）：UNC 带反斜杠的写法用了盘符写法的左边界，`C:\\server\share\<名字>\x`、`.\\server\…` 也换成 `~`。
  - R33-4（信息，文档）：`\\?\UNC\…`、`\\.\UNC\…`、混用分隔符、PowerShell 里正斜杠写法后面的 `\` 不换，规格没写。
  - 都要后端，复审时都没有修。建议：R33-1、R33-2 一起改（先改规格，修订 34；R33-1 要使用者在"路径的边界加上 `,`、`;`、斜杠写法的 `:`"和"只改规格文字"里定）；R33-3 改左边界；R33-4 只改文字；记录里三句说法照实改。（修订 34 已修，见下一条。）
  - **把一类词从命令全文的边界挪到路径的边界之前，先量规则层记下的路径原文是什么形状：它可能是一串路径，也可能从词的中间切开。**
  - **只看形状判断"前一段是不是选项"，要量它会不会把主目录的某种写法切成两半：`/c`、`/cygdrive`、`/root` 的形状都像选项。**
- **一串路径、选项从哪里切开、UNC 的左边界，规格修订 34**（2026-11-17，已提交并推送，`0834756` 代码，文档在其后一个提交，未打标签；记录 `docs/reports/M3a-rev33-review-fixes.md`）：使用者说"按建议修"。先改规格，再改 `send_gate`。
  - R33-1（按建议 A）：路径的边界（规则层读成路径的整个词、选项后面的路径原文、展开过变量的路径原文）里，`,`、`;` 也算结束，斜杠写法的 `:` 也算。`-Wl,-rpath,<主目录>,-z,now`、`-DCMAKE_PREFIX_PATH=<主目录>;…`、`java -cp /c/Users/<名字>:/x` 在 `args`、`flags` 里换成 `~`。代价：名字带 `,`、`;`、`:` 的兄弟目录多换（`--directory=~,x`）。`paths` 是规则层的读法，没改，仍带着用户名。
  - R33-2：以路径原文结尾、前面合选项形状的词，再看两条才切开：按命令全文的边界找主目录的写法，没有一处从前面那段里开始；前面那段以 `/` 开头时，路径原文不以 `/` 开头。代价：Git Bash 里 `/I/c/Users/<名字>/inc` 在 `args` 里不换（修订 32 也这样）。
  - R33-3：UNC 带反斜杠的写法单独一个左边界，前面不能是字母、数字、下划线、`.`、`\`、`/`、`~`、`:`；粘着 `/I`、`-L` 的照旧。
  - R33-4 只改规格文字（`\\?\UNC\…` 等不换）；修订 33 记录里三句说法加了更正（UNC 不送审、`-Wl` 的原文、变异等价）。
  - 旧测试改了 6 处，都是规格修订 34 改掉的行为（路径里的 `,`、`;`、斜杠写法的 `:` 原来算名字的一部分），搬到新文件按新行为钉住。
  - 规则层、判决、送不送审、请求格式、提示词不变。新测试 65 条（在 `9d041b6` 上 40 条失败，通过的 25 条是对照）；相关测试 604 passed；变异 70 个全部抓到（第一轮"只用命令全文的边界找""只用路径的边界找"两个存活，推下来路径的边界找不出更多，代码改成只用命令全文，补了测试；"找不出更多"字面上不成立，见修订 34 的复审 R34-2）；86 条探针判决和送不送审 0 变化，原有 74 条的请求都没变；语料 4906 次判决级别 0 次变化，送审 2009 次请求哈希都相同；原有差分全部相同；冒烟 `--dry` 26 / 0（实验目录用 `--root` 放在 `E:\boundkeep\_bk_smoke_dry`，用完已删，不在盘根）。全量分六段跑，不是一个进程：30375 通过、169 跳过、0 失败，六段都一次跑完，合计与收集到的 30544 条相同；各段用时合计 3:44:04，和修订 33 差不多（开始和结束时电源都是最佳性能）；跑完后代码的哈希与开始时相同。真实宿主里没有跑。
- **修订 34 的复审**（2026-11-17，已提交并推送，和修订 35 的文档在同一个提交里；`docs/reviews/M3a-rev34-review.md`，不是独立的，同一个会话做的，另请了一个只拿代码和规格的子代理单独找错，它报的每一条都重新量过）：使用者说"复审修订34"。R33-1、R33-2、R33-3 都修好了，没有放行，判决和送不送审不变。整条链路 21 条（新旧代码比）、新旧代码同一进程里的直接调用 17 条、随机 33.6 万个词；子代理的整条链路网格 31008 次；记录里的数字都对得上。相关的 11 个测试文件跑了 4 次，第一次 1 条失败（没记下是哪条），后 3 次 604 passed。
  - R34-1（低，隐私，比修订 33 少换）：UNC 带反斜杠的写法左边界排除 `:`，不分是不是盘符的冒号。`link /OUT:\\server\share\<名字>\a.exe`、`/LIBPATH:`、`cl /Fe:`、`-Path:`、`FileSystem::` 后面的主目录随 `command`、`args`、`flags` 发出；真实的 `link`、`cl` 调用会送审（规则层读成本地路径，`paths` 本来就带着小写的用户名），注释、字符串里的只在 `command`、`args` 里多发出去。盘符的主目录不受影响。
  - R34-2（信息，文档）：`\\?\UNC\…` 粘着选项时也送审，规格说不送审；"按路径的边界找不出更多"有反例（`/cyg` 加 `drive/c/…\x`），结果相同；`java -cp /c/Users/<名字>:/x` 在 Windows 上不送审，规格拿它做例子；记录说"UNC 前面是 `:` 几乎都是盘符"；`docs/privacy.md` 漏了 `:` 和尾随点。
  - R34-3（信息，原来就有）：路径原文从粘着的选项中间开始时也切开，`cp -isystem/home/<名字>/inc`（`-t` 的值是 `em/home/…`）的 `args`、`flags` 带着用户名；没有找到真实的写法。
  - 复审时都没有修。建议：R34-1 左边界只排除盘符的冒号（`(?<!(?<!\w)[A-Za-z]:)`），先改规格（修订 35）；R34-3 可以一起改；R34-2 只改文字。（修订 35 已修，见下一条。）
  - **给左边界排除一个字符之前，先列出这个字符后面真会接这种写法的场合：冒号后面除了盘符多写的反斜杠，还有 `/OUT:`、`-Path:`、`FileSystem::`。**
  - **"按 A 找不出比 B 更多"这类说法，随机比对的词要包括各段的前缀，不只是整段：只试 `/cygdrive`，漏了 `/cyg`。**
- **冒号后面的 UNC 主目录、切开的地方不落在粘着的选项中间，规格修订 35**（2026-11-17，已提交并推送，`962f491` 代码，文档在其后一个提交，未打标签；记录 `docs/reports/M3a-rev34-review-fixes.md`）：使用者说"按建议修"。先改规格，再改 `send_gate`。
  - R34-1：UNC 带反斜杠的写法的左边界，不粘选项时只排除盘符的冒号（`_DRIVE_COLON`：一个字母加 `:`，字母前面不是字母、数字、下划线）；粘着的选项可以带一个 `:`（`/OUT:`、`/F:`、`-Path:`）。`FileSystem::` 后面的也换。代价：`-C:\\server…`、`/C:\\server…` 按选项换成 `-C:~`。
  - R34-3：`home_begins_before` 也看切开的地方是不是落在主目录写法粘着的选项中间（`m.start() < cut` 且选项末尾不是 `cut`）。`cp -isystem/home/<名字>/inc` 照命令全文换。代价：修订 33 的 `test_the_longest_path_text_that_fits_is_taken` 的例子 `--ox/c/Users/<名字>/y` 同一种形状，现在是 `--ox~/y`；这条测试改用 `--ox1/c/…`（`1` 不是字母，不算粘着的选项）仍钉"最长的先试"，`--ox` 搬到新文件按新行为钉住。
  - R34-2 只改文字：规格修订 35 里更正修订 34 的三句；修订 34 记录里四句加了带日期的更正；`home_begins_before` 的注释；`docs/privacy.md` 路径的结束字符补了 `:` 和尾随点。
  - 规则层、判决、送不送审、请求格式、提示词不变。新测试 44 条（在 `0834756` 上 25 条失败，通过的 19 条是对照）；相关测试 648 passed；变异 76 个，第一轮 74 个抓到（"字母加冒号都排除"补了 `path:\\server…` 一条后抓到；"选项可以带几个冒号"24 万个随机词只有 1 个输出不同，是没有意义的 `/C::\\…`，算实际上等价）；92 条探针判决和送不送审 0 变化，请求只变了新的 `cp -isystem` 一条；UNC 主目录的整条链路 21 条判决和送不送审 0 变化，请求变了 8 条，都是冒号后面的主目录换成 `~`；语料 4906 次判决逐行相同；原有差分全部相同；冒烟 `--dry` 26 / 0（实验目录在 `E:\boundkeep\_bk_smoke_dry`，用完已删）；速度不到 0.4 毫秒。全量分六段跑，不是一个进程：30419 通过、169 跳过、0 失败，六段都一次跑完，合计与收集到的 30588 条相同；各段用时合计 3:42:31，和修订 34 差不多（开始和结束时电源都是最佳性能）；跑完后代码的哈希与开始时相同。真实宿主里没有跑。
- **修订 35 的复审**（2026-11-17，已提交并推送，和修订 36 的文档在同一个提交里；`docs/reviews/M3a-rev35-review.md`，不是独立的，同一个会话做的，另请了一个只拿代码和规格的子代理单独找错，它报的每一条都重新量过）：使用者说"复审修订35"。R34-1、R34-3 都修好了，没有发现少换，判决没有变。随机比对：本会话 30 万段文字 × 两种边界加 30 万个选项词，子代理 66 万个词，新代码多带用户名的 0 次；整条链路本会话 27 条、子代理 100 条，判决和送不送审 0 变化；记录里的数字都对得上；相关测试 648 passed。
  - R35-1（低，隐私，M3a 起就有）：秘密环境变量的值在 `json.dumps` 之后的文字里找，`"`、`\`、控制字符被转义，值里有这些字符时找不到，`echo 'pa"ss1234wd'` 照样送审，和 `docs/privacy.md` 写的不一致。
  - R35-2（信息，多换，代价没写全）：`gcc -IC:\\server\share\<名字>\inc` 一类按冒号选项换成 `-IC:~\inc`；R34-3 不切开时整个词照命令全文换，`cp '-isystem/home/<名字> Smith/inc'` 的 `args`、`flags` 成了 `~ Smith`；`-isystem/c/Users/<名字>/a;/c/Users/<名字>\b` 换的是哪一处变了（两版都发出一次用户名）；修复记录第 6 节漏了 `path:`、`Temp:`。
  - R35-3（信息，文档）：规格第 331 行把 `-C:\\server…` 列在不换的例子里（代码按选项换）；"按路径的边界多找到的只有一种"现在多了 `-isystem/c/Users/<名字>\x` 一种，结果相同；"送不送审不变"有例外（秘密值落在主目录写法里时，修订 34 拒绝、修订 35 送审，请求里没有那个值）；`link` 的请求没有 `flags`。
  - 复审时都没有修。建议：R35-1 先改规格（修订 36），秘密值在 JSON 里的写法也查；R35-2、R35-3 只改文字。（修订 36 已修，见下一条。）
  - **随机比对不能只数用户名出现几次：次数少了的也要看换掉的是不是主目录（`~ Smith` 是兄弟目录），次数相同而输出不同的要单独列出来；生成器要有 `;` 一串路径和斜杠写法后面跟 `\` 的组合。**
  - **说"送不送审不变"之前，送审前的每一道检查都要一起量：请求的文字变了，秘密值的检查结果也可能跟着变。**
- **秘密变量的值也按 JSON 里的写法找，规格修订 36**（2026-11-17，已提交并推送，`8ffa34e` 代码，文档在其后一个提交，未打标签；记录 `docs/reports/M3a-rev35-review-fixes.md`）：使用者说"按建议修"。先改规格，再改 `send_gate`。
  - R35-1：新的 `_carries`，秘密值的原样写法和 `json.dumps(值, ensure_ascii=False)[1:-1]` 都在请求的 casefold 里找。值里有 `"`、`\`、控制字符的，原来送审、请求里带着原值，现在不送审，按 `on_failure` 处理。代价：名字像秘密的变量的值是 Windows 路径时（`GOOGLE_APPLICATION_CREDENTIALS=D:\keys\gcp.json`），照写这个路径的命令也不送审（POSIX 上本来就这样）。仍找不到：命令里转义着写的（`"print('pa\"ss…')"`）、路径的 key 里 `\` 写成 `/` 的。
  - R35-2、R35-3 只改文字：规格修订 36 补了修订 35 的代价、更正了四句；`home_begins_before` 的注释；修订 35 的记录里几句加了带日期的更正；`docs/privacy.md`、`docs/threat-model.md` 写明两种写法。
  - 新测试 21 条（在 `962f491` 上 10 条失败，都是秘密值的；通过的 11 条是对照和修订 35 行为的钉子）；相关测试 669 passed；变异 84 个，第一轮 82 个抓到（"只找转义之后的写法"补了一条跨两个参数的原样写法 `aaaa", "bbbb` 后抓到；"选项可以带几个冒号"和修订 35 一样，算实际上等价）；秘密值的整条链路 14 条：8 条由送审改为问（值里有 `"`、`\`、制表符的 6 条，`D:\keys\gcp.json` 2 条），6 条不变（命令里转义着写的仍送审）；92 条探针和原有的 49 条整条链路判决、送不送审、请求都 0 变化；语料 4906 次判决逐行相同；原有差分全部相同；冒烟 `--dry` 26 / 0（实验目录在 `E:\boundkeep\_bk_smoke_dry`，用完已删）；速度：1000 个秘密值时 4.7 毫秒（旧代码 4.1）。全量分六段跑，不是一个进程：30440 通过、169 跳过、0 失败，六段都一次跑完，合计与收集到的 30609 条相同；各段用时合计 3:50:19（第 6 段 1:10:01，修订 35 是 44:10，没有查原因；开始和结束时电源都是最佳性能）；跑完后代码的哈希与开始时相同。真实宿主里没有跑。
- **修订 36 的复审**（2026-11-18，已提交并推送，和修订 37 的文档在同一个提交里；`docs/reviews/M3a-rev36-review.md`，不是独立的，同一个会话做的，另请了一个只拿代码、规格、文档、记录和新测试的子代理单独找错，它报的每一条都用另写的脚本重新量过）：使用者说"复审修订36"。目标达到：`_carries` 没有发现错，送审的只少不多；shell 自己去掉的转义（Bash 的 `\"`、`$'…'`、拼起来的引号，PowerShell 的反引号、双写引号，共 10 种）也找到了，旧代码带着值送审。记录里的数字都对得上；相关测试 669 passed；本机 Bash 和 PowerShell 里名字像秘密的 3 个变量，值经过 JSON 转义都不变（只看了名字和长度）。
  - R36-1（低，隐私，原来就有）：PowerShell 的 `Set-Location`、`Push-Location`、`cd` 的目标是 `$env:名字` 时，规则层展开它当工作目录，后面命令的相对路径没有"展开过变量"的标记，`paths` 里是展开之后的值：`Set-Location $env:DB_PASSWORD; python gen.py`，值 `pa\ss1234wd` 发出 `<project>/pa/ss1234wd/gen.py`；`D:\vault\prod01`、`..`、尾随的点也一样。值不变形时被秘密检查找到；名字不像秘密的变量照发。Bash 的 `cd "$X"` 工作目录算作不知道，不这样。和 `send_gate` 的注释、`docs/privacy.md`、`docs/threat-model.md` 说的"不发展开值"不一致。
  - R36-2（信息，原来就有）：没写进"仍找不到"的改了形的写法：任务意图存的时候控制字符变成空格、连着的空白并成一个，截断在 300 个字符处只剩前一段；命令里把 Windows 路径的值写成 `D:/…`、`/d/…`、`.\`；环境里的值带尾随换行（`Get-Content -Raw`）。
  - R36-3（信息，文档）："命令里转义着写的找不到"说宽了，真正找不到的是交给程序自己解释的转义（`printf '\x22'`、各种语言的字符串）；PowerShell 那个例子找不到，是因为 5.1 把词拆成了两个；记录第 6 节和提交说明说任务意图里的控制字符会拒绝，其实不会。
  - R36-4（信息，测试）：没有一条测试的值只在 `command` 里；PowerShell `python -c` 那条测试给的 `args` 不是规则层真实拆出来的样子。
  - 复审时都没有修。建议：R36-1 先改规格（修订 37），由展开过变量的工作目录解析出来的路径按原文发或者不发，判决不变；R36-2 的尾随空白可以一起改；其余只改文字和测试。（修订 37 已修，见下一条。）
  - **量"找不到的"要按规则层的读法分开：shell 去掉的转义在词里就是原值，交给程序解释的转义才不是；只看命令全文会把找得到的也写成找不到。**
  - **说某个字段里的值会被拒绝之前，先看它存进去、拼进去之前有没有被改写：任务意图存的时候控制字符就成了空格；路径从工作目录来时，展开过的变量藏在工作目录里。**
- **展开过变量的工作目录后面的路径按原文发，规格修订 37**（2026-11-18，已提交并推送，`1499e14` 代码，文档在其后一个提交，未打标签；记录 `docs/reports/M3a-rev36-review-fixes.md`）：使用者说"按建议修"，复审留给使用者的两处选了"按原文发""只补尾随空白"。先改规格，再改 `event.py` 和 `send_gate`。
  - R36-1：`_Line.expanded_cwds` 记下展开变量得来的工作目录（`cd` 的目标展开过变量，或者是从这样的目录走的相对路径）；`_refs` 对按它解析的相对路径、以及字面形式展开过变量的路径在盘上的其他形式，加上 `variable-expanded`（只作说明，判决不变），`send_gate` 按原文发。通配符匹配到的文件原文就是盘上的路径，带标记的不放进请求（`_hidden_match`），文字照旧检查。实测：链接的目标原来就带标记，子代理的推测不对；通配符匹配到的文件原来不带。代价：`$env:TEMP` 一类目录之后、Bash 的 `cd $HOME/…`、`cd $PWD/…` 之后（路径层自己解析这几个变量），模型看到的少了；值没改形、原来被秘密检查拒绝的，现在送审（请求里没有值）。
  - R36-2：`_carries` 也找去掉两头空白的值（至少 8 个字符）。R36-3 只改文字；R36-4：值只在注释里的一条，PowerShell `python -c` 那条的 `args` 改成规则层真实拆出来的两个词。
  - 新测试 28 条（在 `8ffa34e` 上 21 条失败，通过的 7 条是对照）；改了 1 条旧测试的 `args`；相关测试 697 passed；和切换目录、变量展开、通配符有关的现有测试从 PowerShell 跑 11219 passed（从 Bash 工具跑时和真实 bash 比对的一条会失败，旧代码也一样）；变异 106 个，第一轮 101 个抓到（"绝对路径也加标记""`find -exec` 不传"各补一条测试后抓到；`git add` 扫描、程序名展开两处的路径不进请求，"选项可以带几个冒号"同前，实际上等价）；整条链路原有 83 条 0 变化，子代理发现的 23 条里 9 条照预期变了；92 条探针 0 变化；语料 4906 次判决逐行相同；原有差分全部相同，`boundkeep test` 1142 / 0、334 / 0；冒烟 `--dry` 26 / 0（实验目录在 `E:\boundkeep\_bk_smoke_dry`，用完已删）。全量分六段跑，不是一个进程：30468 通过、169 跳过、0 失败，六段都一次跑完，合计与收集到的 30637 条相同；各段用时合计 2:25:47，比修订 36 快约三分之一（含语料的第 5 段 1:15:22、第 6 段 29:12，修订 36 是 1:58:33、1:10:01，没有查原因；开始和结束时电源都是最佳性能）；跑完后代码的哈希与开始时相同。真实宿主里没有跑。（复审见下一条。）
- **修订 37 的复审**（2026-11-18，已提交并推送，和修订 38 的文档在同一个提交里；`docs/reviews/M3a-rev37-review.md`，不是独立的，同一个会话做的，另请了一个只拿代码、规格、文档、记录和新测试的子代理单独找错，它报的每一条都用另写的脚本重新量过）：使用者说"复审修订37"。主要目标达到：同一个调用里 `Set-Location $env:名字` 之后的相对路径按原文发；规则层不读这个标记，判决不变；8.3 短名补量了，原来就带标记；记录里的数字都对得上。
  - R37-1（低，隐私，修订 37 没修全）：`_resolved_forms` 给通配符匹配到的文件在盘上解析出来的那一份不带 `glob-match`，`_hidden_match` 不藏它。经过目录联接时（变量的值是联接，或通配符经过值下面的联接），它按"原文"发出匹配到的路径，里面就是值。名字像秘密、值照原样的，原文里是带 `\` 的原值，反而改为拒绝，规格没写这处送审变化。
  - R37-2（低，多问，修订 37 引入）：`_Line` 一开始的工作目录是事件 `cwd` 的原文，`cd` 的目标是 key，`_merge_cwds` 不合并。展开出来的目录就是事件的工作目录时（`Set-Location $env:PROJ_DIR`、`Set-Location $PWD`），两份路径一份带标记一份不带，去重去不掉：9 个路径变 18 个，超过 `MAX_PATHS`，由送审变成问。
  - R37-3（信息，原来就有）：事件里没有 `cwd` 时，`D:gen.py` 按展开出来的目录解析，不带标记。Claude Code 的事件都带 `cwd`。
  - R37-4（信息，原来就有，真实宿主里没有量）：标记只在一个调用之内。工作目录留到下一次调用时，下一个事件的 `cwd` 就是展开出来的目录，后面的路径带着值。
  - R37-5（信息，文档）："通配符匹配到的文件不发""送不送审只在一处变"说宽了；隐私和威胁模型文档只写了 PowerShell；`strip()` 去掉的是 Unicode 空白，不去掉 BOM。
  - 复审时都没有修。建议：修订 38 改 `_resolved_forms`（或 `_hidden_match`）和去重，补经过目录联接的测试；R37-3 改代码还是写进规格、R37-4 只写进规格还是放进会话状态，由使用者定。（修订 38 已修，见下一条。）
  - **Windows 上走整条链路的脚本要先等 PowerShell 解析器就绪（`psparse.warm_up`）：没就绪时 PowerShell 命令全是灰色、不送审，新旧两版"一样"，其实什么都没量。**
  - **修好一个分支，要看同一个函数给出的其他几份：通配符匹配和链接分别量过，不等于通配符经过链接也对。**
- **通配符经过链接的盘上形式也不发、同一目录的路径只留一份，规格修订 38**（2026-11-19，已提交并推送，`98d4ff5` 代码，文档在其后一个提交，未打标签；记录 `docs/reports/M3a-rev37-review-fixes.md`）：使用者说"按建议修"，复审留给使用者的两处按复审的推荐做（R37-3 改代码，R37-4 只写进规格）。先改规格，再改 `event.py`。
  - R37-1：`_resolved_forms` 给盘上解析出来的那一份也带上 `extra_reasons`（`glob-match`），`send_gate` 的 `_hidden_match` 把展开过变量的两份都藏起来。值照原样、名字像秘密、又是链接的，修订 37 拒绝，现在送审（请求里没有值）。
  - R37-2：`_refs` 去重时不算 `variable-expanded`，只差这个标记的两份留带标记的那一份。事件的 `cwd` 仍是原文，`cd` 的目标仍是 key，没有改（牵涉面大）。代价：`Set-Location $env:PROJ_DIR` 之后的路径发 `gen.py`，修订 36 是 `<project>/gen.py`。
  - R37-3：`_CWD_READINGS`（`drive-relative`、`rooted-current-drive`）的路径，所用的第一个工作目录是展开变量得来的时也加标记。R37-4 写进规格的"仍有的"。R37-5：规格修订 38 更正修订 37 的说法，修订 37 的记录四处加更正，`docs/privacy.md`、`docs/threat-model.md` 补上 Bash、链接、BOM。
  - 新测试 20 条（在 `1499e14` 上 14 条失败，通过的 6 条是对照）；和切换目录、变量展开、通配符有关的现有测试 22706 passed；变异 114 个，第一轮 109 个抓到（"去重总留后来的那一份""去重的键不看原因"各补一条测试后抓到；其余 3 个同修订 37，实际上等价）；复审时写的脚本 27 条里 14 条照预期变了；整条链路原有 106 条、92 条探针 0 变化；语料 4906 次判决逐行相同；原有差分全部相同（修订 19、20 的脚本被系统清理 TEMP 时删了，按对话记录重建后补跑），`boundkeep test` 1142 / 0、334 / 0；冒烟 `--dry` 26 / 0（实验目录在 `E:\boundkeep\_bk_smoke_dry`，用完已删）。全量分六段跑，不是一个进程：30488 通过、169 跳过、0 失败，六段都一次跑完，合计与收集到的 30657 条相同；各段用时合计 2:37:00（含语料的第 5 段 1:26:12，修订 37 是 1:15:22，没有查原因；开始和结束时电源都是最佳性能）；跑完后代码的哈希与开始时相同。真实宿主里没有跑。
- **下一步**：M3b（自备密钥、确认费用）或 M4（不依赖 M3b）；接真实后端之前，收尾记录第 5 节里还剩 `auto` 模式的实测。总览见 `PROJECT_SPEC.md` 开头的"当前进度"与 §14 的状态列。
- 规格是"修订 3"加上 M0a 的 10 条已接受变更与 M1 的澄清（§7：Action 列表、`inside_project` 三值、POSIX 路径大小写、`project_dir`）；`IMPLEMENTATION_PROMPTS.md` 已对齐。hook 的实测事实在 `docs/hook-behavior.md`（带版本），平台记录在 `docs/platforms.md`：**M0 支持范围 = Windows 11 原生的 VS Code 扩展与交互式 CLI（2.1.292，PowerShell 工具）**，M1 的手工验收做完之前不扩大这个声明。
- M1 已实现并通过自动测试：自写的保守 Bash 解析器（不用 bashlex，GPLv3+）、程序知识表、路径两层规范化、域名规范化、策略 schema 与规则引擎（`boundkeep test`、`boundkeep explain`）、判决到 hook 输出的映射（`allow` 只在 `emit_allow` 时输出）、`init` 把 home 固定进 hook 参数并支持 `--reset-policy`。设计契约在 `docs/m1-design.md`，策略字段在 `docs/policy-reference.md`。没有 LLM 后端时灰色就是 ask，所以 enforce 下大部分命令会弹确认，日常先用 `audit-only`。
- 独立审查（四路：解析器、路径与域名、策略语义、性能与集成）共约 60 条发现，已按文件分工修复并有回归测试；真实 Claude Code 冒烟（`scripts/smoke_claude_m1.py`，11 项）全过。Linux 容器里的 M1 测试已跑（真 bash 5.2，差分测试通过）。
- M1 手工验收（VS Code 扩展 2.1.296 与交互式 CLI）通过，记录在 `docs/manual-acceptance-m1.md`：被拒绝的理由可见，ask 的理由在确认框里仍不显示（与 M0 一致）；验收中发现并已修：文本版 `boundkeep log` 不显示命中的规则。
- M1b 已实现：常驻辅助进程（`powershell.exe`/`pwsh`，只做 `ParseInput`，从不执行命令；Job Object 随守护进程退出而终止；预热约 2 秒，期间 PowerShell 命令一律灰色 `ps-helper-not-ready`；熔断带 60 秒半开；慢输入有哈希缓存与限流），AST 摘要经 `pscmd` → `programs.classify(shell="powershell")` → `psprograms`，别名/参数表 `psaliases`（只有 Windows 上的一致性测试）。设计契约 `docs/m1b-design.md`，使用说明与已知缺口 `docs/powershell-dialect.md`，报告 `docs/reports/M1b.md`。审查（四路，约 1500 条命令只解析不执行）无 blocker、无 allow 绕过；两项 HIGH（熔断器永久打开、慢输入造成的全员灰色）与六项 MEDIUM 已修。pwsh 7 与 Linux/macOS 上的 pwsh 没有实测（只有 Windows PowerShell 5.1）。冒烟 `scripts/smoke_claude_m1b.py`（10 项）全过。
- X1 审查（2026-10-18）：三条高危（H-1 目录目标的 Grep/Glob 被 allow、H-2 同用户进程冒充守护进程、H-3 在别处打开会话时没有任何告警）与十余条中危。第一轮修复已做：H-1 有界遍历子树（`normalize/subtree.py`，3 万条目/0.2 秒，超出灰色，不按目录名跳过）；H-2 客户端默认不输出 `allow`（hook 参数 `--emit-allow` 才放行）并收紧管道 DACL；H-3 `init`/`doctor` 提示（SessionStart 心跳留给 M2）；M-1/M-3/M-4/M-5/M-6/M-8/M-9/M-10/M-11/M-12 见修复记录。**没做**：M-2（`evaluate` 预算）、M-7（管道连接数）、M-13（enforce 下可日常使用，必须在 M2 评测前达成）、L-1 到 L-18、H-2 的服务端 PID 校验。第二轮（复审）：R-1 `glob`+`type` 的绕过已修、Grep 无 glob 时跳过 `.git` 等版本控制目录、Glob 不再扫描、项目级 `.claude/settings.json` 可读（写保护不变）、管道 DACL 加 OWNER RIGHTS ACE、ConfigChange 只阻断有证据的削弱（实测 hook 的 ask 优先于 `permissions.allow` 与 `bypassPermissions`）。副作用：目录 Grep 在含受保护文件的项目里会被拒绝（除非 glob 排除）、开发 boundkeep 本身时 `protect-guard-code` 会禁止编辑已安装的包（用 `audit-only`）。
- M1c（2026-10-20，报告 `docs/reports/M1c.md`）：选方案 A（规则层加 allow，不靠 LLM）。`defaults.emit_allow` 仍默认关闭，所以 allow = "无决定"，由 Claude Code 自己的权限流程接手，boundkeep 只做到与 Claude Code **持平**（不再比它多弹确认），不替用户批准任何东西。新增：匹配字段 `flags_none`、`paths_read_only`；加载检查"allow 规则必须限定 `tool` 或 `program`"；先加 L-11 的 `ask-project-autorun-files`（strict 为 deny）与 `ask-secret-file-write`、`ask-credential-file-write`、`ask-git-internals-write`，再加 default 专有的 allow：第 1 档只读检查（`ls`、`tree`、`find`、`rg`、`cat`、`head/tail/wc/grep`、`pwd`、`git status|diff|log|show|blame|rev-parse`、`git branch` 的列表形态、PowerShell 的 `Get-Content/Select-String/Test-Path/Get-Item/Resolve-Path/Get-ChildItem/Get-Location/Get-Date/Measure-Object`），第 2 档项目内写入（`Write/Edit/MultiEdit/NotebookEdit`、`mkdir`、`touch`）；第 3 档（`pytest`、`npm test` 等会运行仓库代码的命令）**刻意不 allow**。`echo`、`Write-Output`、`Select-Object` 因为会把环境变量打印进上下文而不放行；`GIT_DIR`、`RIPGREP_CONFIG_PATH` 等环境前缀已进 `_ENV_CODE`；strict 不加新的 allow（子集一致性测试）。度量语料 `tests/corpus/workflow_benign.yaml`（312 条，合成）：每百动作询问数 Windows 80.6→52.6、POSIX 77.9→50.4，只读与项目内写入两档降到 0，必须拦截的无一放行。残余风险：不可信仓库里 `git status` 等仍可能运行该仓库 `.git/config` 指定的程序（所以 emit_allow 要保持关闭）；以变量开头的管道不被标灰；`head -n $TOKEN f` 这类选项值里的展开看不到。**还没做**：用你的真实会话统计覆盖率（`scripts/session_command_stats.py` 只输出计数，由你自己运行）；第 3 档与 emit_allow 的可选预设；allow 规则的定向 X1 审查。
- M1c-2（2026-10-21，报告 `docs/reports/M1c2.md`）：用户的真实会话统计（PowerShell 占 3354 次调用，只有约 1% 被放行）显示 M1c 的第 1、2 档几乎没覆盖到 PowerShell 开发工作流；最大的挡路者是带路径的 `.venv\Scripts\python.exe/ruff/mypy`（第 3 档）。新增：策略顶层键 `trusted_projects` 与匹配字段 `project_trusted`（默认空列表，strict 永不放行；链接/连接点解析后也必须被信任；拒绝过宽目录）；`boundkeep trust add|remove|list`（用户在终端运行，`add` 在 stdin 不是真实控制台时拒绝，agent 调用被策略 deny）；`pytest`、`ruff`、`mypy`、`black`、`isort`、`flake8`、`pylint`（含 `python -m <工具>` 与带路径形式）的识别与 allow 规则（52 个危险标志用 `flags_none` 排除，YAML 与 Python 表有一致性测试）；PowerShell 管道头修复（新灰色原因 `ps-pipeline-head-dynamic`，常量字符串喂给读取者变成读路径，`'~\.ssh\id_rsa' | Get-Content` 现在 deny）与数据整形 cmdlet 的 allow；同一行"先写后执行"检测扩展到 mypy/pylint/flake8/pytest 的配置与测试文件。**风险**：预设与项目内写入 allow 合起来构成"先写测试文件、再运行 pytest"的链路，跨工具调用的这条链无法识别；只应信任自己写过或审计过的仓库（M3 的污染标记计划收紧）。**没做**：真实控制台里 `trust add` 的成功路径没有自动化测试（手工验收 T2 是第一次）；对 node 工具的预设；每个工具单独的 allow 规则。真实覆盖率用 `scripts/session_command_stats.py --trust <项目>` 量化，你还没运行。
- M1c-3（2026-10-21，报告 `docs/reports/M1c3.md`）：用户统计显示 `Set-Location` 出现在约 2290 次 PowerShell 调用里而没有 allow 规则，一行里只要有一条命令不是 allow 整行就不是 allow。新增 `allow-cd-family`（默认策略独有）：`cd`、`pushd`、`Set-Location`、`Push-Location`（含别名），**必须带 `path_inside_project` 与只读路径**。我最初要求不加路径条件，实现者用探测证明那样 `cd /tmp && git status`、`cd ../other && git log`、`cd $x && git status` 都会变成 allow（这些命令没有路径，目录来自 cd，规则无从判断），所以保留了条件：项目外与动态目标的 cd、`cd -`、裸 `cd`、`popd`、`Pop-Location` 仍是灰色。`cd` 之后的命令仍按新目录判断（`cd .. && cat .env`、`cd ~/.ssh && cat id_rsa` 仍 deny）。整合时补了 `cd-extra-arguments` 灰色原因（zsh 的 `cd old new` 会替换路径子串）。合成语料每百动作询问数 Windows 58.0→55.2，`t1-read` 档 11.0→0。**还没做**：项目外 `cd` 要放行需要规范化器对不确定的 cd 目标打灰色原因；`Write` 到项目外目录（如 Claude Code 的 scratchpad）的分类有待用户的统计确认。
- 所有改动在用户确认前不提交；推送与打标签也要使用者明确说了才做。