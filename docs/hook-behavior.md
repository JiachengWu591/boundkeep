# hook 行为实测记录（M0a）

> 状态：已完成；界面操作也做了（见"界面操作结果"），仍未验证的项见状态表与验收报告 `docs/reports/M0a.md`。本文件的结论优先于规格 §5 的"官方文档核对结论"：二者不一致以实测为准，并记录差异。
> 总体：没有发现推翻规格设计的事实；发现了几处与官方文档措辞不一致或文档没写的行为，都已写进规格 §5.1。
> 证据：`experiments/evidence/`（脱敏）；未脱敏的原始记录在被 git 忽略的 `experiments/raw/`；每项都可用 `experiments/` 里的脚本重跑（见 `experiments/README.md`）。

## 测量环境（除非另注）

- 日期：2026-10-06；Claude Code：2.1.291（VS Code 扩展 `anthropic.claude-code-2.1.291-win32-x64` 自带的 `native-binary\claude.exe`）
- 宿主：CLI 引擎（`claude -p`，`CLAUDE_CODE_ENTRYPOINT=sdk-cli`）与 VS Code 扩展（`claude-vscode`）。Desktop 应用未测。
- 系统：Windows 11 Home China，build 26200，区域 zh-CN，ANSI 代码页 936；Intel Core i7-13700H；Windows PowerShell 5.1.26100.9444；Python 3.12.7
- shell 工具：默认只有 `PowerShell`（Git 装在 `D:\新建文件夹\Git`，没有被自动发现）；设置 `CLAUDE_CODE_GIT_BASH_PATH` 后 `Bash`（Git Bash）与 `PowerShell` 并存
- 方法：`lab_setup.py` 在 `E:\bk-lab*` 建一次性目录、项目级 settings 挂观察用 hook；`run_cli_probe.py` 用 `claude -p`（`claude-haiku-4-5-20251001`，除另注；`--setting-sources project`、`--permission-prompts none`，子进程环境清除全部 `CLAUDE*` 变量）触发工具调用。证据有两份互相印证：记录器日志，和 Claude 自己的 `--include-hook-events` 事件流。
- 费用：60 次 `claude -p` 运行，各次结果里的 `total_cost_usd` 之和约 1.36 美元（haiku 为主；恢复会话的累计成本可能有重复计入）。

## 实验状态

| 实验 | 状态 | 一句话结论 |
|---|---|---|
| E1 拒绝理由回传 | 已验证（CLI 引擎） | exit 2 的 stderr 与 deny JSON 的理由（含 `\u` 转义的中文与 ✓）都原样回传给模型 |
| E2 超时 | 部分验证 | `timeout` 单位为秒；超时的 hook 被终止（outcome `cancelled`），非阻断；上限与默认值未测 |
| E3 stdin 字段 | 部分验证 | 已记录 7 类事件（SessionStart、UserPromptSubmit、PreToolUse、PostToolUse、Stop、PermissionRequest、ConfigChange）与 12 种工具（含 MCP 与 Agent）的字段，39 个夹具在 `tests/fixtures/hook_events/windows/`；本版本 init 事件的工具清单里没有 MultiEdit，NotebookEdit 在清单里但没触发过；**VS Code 扩展会把 IDE 上下文（含选中的文件内容）拼进 `UserPromptSubmit` 的 `prompt`**；WebSearch 的 `tool_response.results` 是字典与纯文本字符串混合的列表 |
| E4 additionalContext | 已验证 | PostToolUse 与 UserPromptSubmit 的 `additionalContext` 都能让模型看到 |
| E5 matcher | 部分验证 | 16 种写法的触发矩阵已测；`Task|Agent` 的实际触发未测 |
| E6 退出码与坏 hook | 已验证（CLI 引擎） | 23 种失败模式；**任何起不来或崩溃的 hook 都不阻断；非法 JSON 被当作"无决定"**。**VS Code 界面里 hook 出错、超时、崩溃时没有任何提示**；被阻断时理由显示在弹窗与工具调用卡片里 |
| E7 同类项目 | 部分验证 | `docs/related-work.md` 已写完；cc-audit 有两个同名项目；来源是调研员的汇总，我只亲自复核了 cc-audit B 的 README，其余单元格未逐格复核 |
| E8 ask | 部分验证 | `-p` 下 ask 被自动拒绝；VS Code 里 ask 会弹出确认，批准后命令执行；**确认框默认视图里不显示 hook 的理由**（只有命令与模型的描述；截图一次；折叠箭头展开后是否有理由未试） |
| E9 并发与会话 | 部分验证 | resume / continue / compact 前后 session_id 不变；项目、local、`--settings` 三处 hook 合并；`/clear` 换新 session_id（SessionStart 的 `source` 为 `clear`）；并行工具调用没能让模型发出 |
| E10 性能 | 已验证（本机微基准） | `python -I -S` 的 hook 进程约 30 ms；`.exe` 启动器 +17 ms；mise shim +64 ms；每次工具调用 hook 增量约 95 ms |
| E11 allow 语义与权限模式 | 部分验证 | **hook 的 allow 会替用户跳过确认**，但压不过 ask / deny 规则；bypassPermissions 未测；auto 模式未生效 |
| E12 配置篡改 | 已验证（CLI 引擎） | `disableAllHooks` 一旦生效 hook 全停；会话中改动立刻生效；`ConfigChange` hook 能拦下这类改动 |
| E13 覆盖面 | 部分验证 | 子 agent、MCP、WebFetch、WebSearch、ToolSearch 都触发；`@` 引用绕过 hook |
| E14 prompt / agent hook | 已验证（实验性） | PreToolUse 上可用；不能替代 command hook |
| E15 hook 是否触发 | CLI 引擎与 VS Code 扩展已验证；Desktop 未测 | 见下 |
| E16 exec 形式 | 部分验证 | 绝对路径 `python.exe` + `args`、`.exe` 启动器、含空格与中文的路径都可用；VS Code 里 `python.exe -I -S` 的 exec 写法没有出现黑色控制台窗口（用户目视一次；`.exe` 启动器未测） |
| E17 Windows 的 stdin 形式 | 部分验证 | 路径全是反斜杠；盘符大小写不稳定；`Bash` 命令里的路径写法未测 |
| E18 环境与编码 | 已验证 | 默认 gbk 解码会让含中文的事件崩溃，崩溃即放行；环境变量原样传入 hook |
| E19 命名管道的真实行为 | 待 M0 | 要在 M0 的真实实现与真实 Claude Code 下补做；原型的并发与 DACL 基准见 E10（`bench_pipe_concurrency.py`） |
| E20 PowerShell 解析 | 部分验证 | 5.1 下 AST 解析器可用；**约束语言模式下不可用** |
| E21 路径规范化的边界 | 部分验证 | 见下 |
| E22 工具链解析 | 已验证 | 命令不存在、`.cmd` 垫片、Store 占位符等都是非阻断的静默失效 |
| E23 配置与托管 | 部分验证 | `-p` 与 VS Code 扩展里的信任行为已观察（扩展里没有弹信任对话框，项目级 hook 照常运行）；托管设置、`CLAUDE_CONFIG_DIR` 未测 |
| E24 其他平台 | 未验证 | 本机 WSL 里只有 `docker-desktop` 发行版；没有 macOS 与通用 Linux |

## E15 hook 是否触发

- **官方文档**：hook 对 `PowerShell` 工具同样触发；只匹配 `Bash` 的 hook 在没有 Git Bash 的 Windows 上永远不触发。
- **CLI 引擎**：SessionStart、UserPromptSubmit、PreToolUse、PostToolUse、Stop 都触发；`PowerShell`、`Read`、`Write` 工具；设置 `CLAUDE_CODE_GIT_BASH_PATH`（路径含中文）后 `Bash` 与 `PowerShell` 并存且都触发。
- **VS Code 扩展（2.1.291）**：同样触发，13 条记录，五类事件都在。用户报告的 #92074（扩展 v2.1.259、Windows 10：hook 完全不触发）没有复现；版本与系统不同，是否已修复未知。
- 置信度：高。证据：`events_summary.txt`、`hook_outcomes.txt`、`run_results.txt`。
- 对设计：Windows 原生在两个宿主里引擎层可行；"支持"仍要等 M0 在具体宿主上通过。

## E1、E2、E6、E8 决定、退出码与超时

| hook 的行为 | Claude 记录的 outcome | 对工具调用的影响 |
|---|---|---|
| 退出 0、无输出 | `success` | 走正常权限流程 |
| 退出 1 | `error` | 非阻断，命令照常执行 |
| 退出 2，stderr 有理由 | `error`（exit_code 2） | 阻断；stderr 的理由回传给模型 |
| 崩溃（Python 抛异常，退出 1） | `error` | 非阻断，命令照常执行 |
| 超过 `timeout`（5 秒，hook 睡 30 秒） | `cancelled`（exit_code 1） | 非阻断，命令照常执行；该次调用 8.58 秒，基线 3.14 秒（多约 5.4 秒） |
| 退出 0，stdout 是 deny JSON | `success` | 阻断；`permissionDecisionReason` 回传给模型 |
| 退出 0，stdout 是 ask JSON，`-p` 且无人批准 | `success` | 自动拒绝：`permission_denied`，"no approval surface in this session; permission request denied automatically" |

**坏 hook 与命令无法启动**（`fail_*` 运行，每种一轮；`stderr` 摘自 Claude 的 `hook_response`）：

| 情形 | Claude 的反应 | 命令执行了吗 |
|---|---|---|
| `command` 路径不存在 | `error`，`ENOENT: no such file or directory` | 是 |
| `command` 是 `.cmd` 垫片（exec 形式） | `error`，`spawn ... EINVAL` | 是 |
| `command` 是非可执行文件 | `error`，`EFTYPE: inappropriate file type or format` | 是 |
| `command` 是 Microsoft Store 的 `python.exe` 占位符 | `error`，退出码 49 | 是 |
| 退出码 127 / 3 | `error` | 是 |
| stderr 有输出、退出 0 | `success`，stderr 被忽略 | 是 |
| stdout 是普通文本、退出 0 | `success`，无决定 | 是 |
| **stdout 是非法 JSON（`{not json`）、退出 0** | `success`，**被当作无决定** | 是 |
| stdout 是非 UTF-8 字节、退出 0 | `success`，字节被替换为 U+FFFD | 是 |
| stdout 2 MB、退出 0 | `success` | 是 |
| 不读 stdin、睡 30 秒（`timeout` 5） | `cancelled` | 是 |
| allow JSON + 退出 2 | `error`（exit 2），以退出码 2 为准 | 否（阻断） |
| **deny JSON + 退出 1** | `error`（exit 1），**deny 仍然生效**，理由以 "PreToolUse:PowerShell hook error: <理由>" 回传 | 否 |
| 旧式 `{"decision":"block","reason":...}`、退出 0 | `success`，仍然阻断，理由回传 | 否 |
| shell 形式，PowerShell 执行，路径带引号但不加 `&` | `error`，PowerShell 解析错误（stderr 是 GBK 乱码） | 是 |
| shell 形式 `& "path" ...`（默认 shell 为 PowerShell） | 正常 | — |
| `shell: "powershell"` | 正常 | — |
| `shell: "bash"` 但没有 Git Bash | `error`，`Failed to run: Hook ...` | 是 |
| exec 形式：mise 的 `python.exe` shim | 正常 | — |
| exec 形式：distlib 生成的 `.exe` 启动器 | 正常 | — |
| exec 形式：含空格与中文的目录里的 `.exe` 或脚本 | 正常 | — |

- 官方文档一致：只有退出码 2，或退出 0 加合法 JSON 决定才会阻断。**与文档措辞不同的两点**：deny JSON 配退出码 1 也被执行；旧式 `decision: block` 仍被接受。方向都是更安全，但不要依赖。
- **对设计的影响**：规格 §10 的降级设计成立。新增三条要求：① 客户端必须保证 stdout 总是 `json.dumps` 生成的合法 JSON（非法 JSON 等于放行）；② 任何异常都输出 ask 并以 0 退出；③ `init` 与 `doctor` 要按 exec 形式原样启动 hook 命令并校验输出，才能发现"命令起不来"这类静默失效。
- 被阻断或拒绝的调用只有 PreToolUse 记录，没有 PostToolUse。
- **VS Code 扩展里同一组命令**（`acceptEdits` 模式，你亲自做的界面测试；证据 `m0a_summary.txt` 的 VS Code 一节）：退出码 1、超时、崩溃的三条命令都执行了，退出码 2 与 JSON 拒绝的两条被阻断，与 CLI 引擎一致；ask 那条分别过了 25.7 秒与 13.6 秒才执行（弹出确认，你点了批准）。**界面上的可见性（你的回答）**：被阻断的两条，hook 给的理由出现在弹窗与工具调用卡片里；hook 退出码 1、超时、崩溃时**界面完全没有任何提示**；ask 的确认框里是否显示 hook 的理由，以及命令执行时是否闪现控制台窗口，你当时记不清；**事后单独重测了一次**：确认框默认视图里只有命令（`Write-Output BK_ASK_MARK`）与模型写的描述，**没有 hook 的理由**；执行时没有黑色窗口。都是一次目视观察。
- 对设计：被阻断的理由用户看得到，所以拒绝理由要写成给人看的话；而 hook 起不来或崩溃时用户也看不出来，`init` 的自检与 `doctor` 是发现闸门失效的唯一办法。
- 未测：非法 JSON 的 PreToolUse 之外的事件、`timeout` 的上限与 UserPromptSubmit 默认的 30 秒、交互式 ask 弹窗里的理由文字。

## E3 stdin 字段（部分验证）

完整字段名见 `experiments/evidence/event_shapes.txt`，真实事件夹具见 `tests/fixtures/hook_events/windows/`（34 个，脱敏）。要点：

- 所有事件都有 `session_id`、`transcript_path`、`cwd`、`hook_event_name`；`permission_mode` 在 SessionStart 上没有。
- `UserPromptSubmit`：用户提示的字段是 `prompt`，另有 `prompt_id`。`SessionStart`：`source`（见到 `startup`、`resume`、`compact`）。`Stop`：`last_assistant_message`、`stop_hook_active`、`background_tasks`、`session_crons`。`ConfigChange`：`source`（`local_settings`）、`file_path`。
- `PreToolUse` 的 `tool_input`：`PowerShell` 与 `Bash` 是 `{command, description}`；`Read` 是 `{file_path}`；`Write` 是 `{content, file_path}`；`Edit` 是 `{file_path, old_string, new_string, replace_all}`；`Glob` 与 `Grep` 是 `{pattern, path}`（**字段叫 `path`，不是 `file_path`**）；`WebFetch` 是 `{url, prompt}`；`ToolSearch` 是 `{query, max_results}`；MCP 工具是工具自己的参数，且顶层多一个 `mcp_server` 字段。
- `PostToolUse` 另有 `duration_ms` 与 `tool_response`：`PowerShell` / `Bash` 是 `{stdout, stderr, interrupted, isImage[, noOutputExpected]}`；`Read` 是 `{file, type}`；`Write` 是 `{content, filePath, originalFile, structuredPatch, type, userModified}`（`filePath` 驼峰）；`Edit` 是 `{filePath, newString, oldString, originalFile, replaceAll, structuredPatch, userModified}`；`Glob` 是 `{filenames, numFiles, totalMatches, truncated, durationMs, countIsComplete}`；`Grep` 是 `{filenames, mode, numFiles, totalFiles}`；`WebFetch` 是 `{result, code, codeText, bytes, durationMs, url}`；MCP 工具是内容块的列表。
- 子 agent 内的调用多 `agent_id`、`agent_type`（见 E13）。
- **宿主差异**：VS Code 扩展的 payload 多 `scratchpad_dir` 与 `effort: {level}`；`permission_mode` 是用户在扩展里的实际模式（`acceptEdits`），CLI 里是 `default`。
- **VS Code 扩展会把 IDE 上下文拼进 `UserPromptSubmit` 的 `prompt`**：`<ide_opened_file>The user opened the file <路径> in the IDE ...</ide_opened_file>`（当前编辑器的文件路径）与 `<ide_selection>The user selected the lines 1 to 7 from <路径>:\n<选中的那段文件内容></ide_selection>`（**选中的文件内容整段在里面**）；用户粘贴的文字被包在 `<pasted_content id="...">` 里。对设计：提取任务意图时必须剥离所有 `<ide_*>` 块，并把 `<pasted_content>` 当作不可信文本，否则会把文件内容发给 LLM 后端（规格 §9.2 与 §11 已补）。
- 对设计：`tool_response` 含工具原始输出，与规格 §11"不发送工具原始输出"一致；normalize 要按工具取路径字段（`file_path`、`path`、`pattern`），不能只认 `file_path`；`Glob` 的 `pattern` 本身可能是绝对路径或含 `..`。

## E4 additionalContext（已验证）

PostToolUse hook 输出 `{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"<nonce>"}}`，UserPromptSubmit 同理；模型在回答里把两个 nonce 都完整抄了出来。对设计：污染告警可以通过 `additionalContext` 让模型看到；它也意味着 hook 能向模型的上下文注入文字，要避免把不可信内容回显进去。

## E5 matcher（部分验证）

PreToolUse 上 16 种写法对 PowerShell、Read、Write、Edit、Glob、Grep、ToolSearch、WebFetch、MCP 的触发矩阵见 `m0a_summary.txt`。结论：

- `*`、空字符串、省略 matcher：匹配所有工具（含 `ToolSearch`）。
- 只含字母、数字、下划线、连字符、空格、逗号、竖线的是**精确名单，区分大小写**：`PowerShell` 匹配，`powershell` 不匹配；`Pow`（前缀）不匹配；`Read,Write` 逗号名单有效；`Bash|PowerShell`、`Read|Write|Edit|MultiEdit`、`Glob|Grep`、`WebFetch|WebSearch` 有效。
- 含其他字符的按正则：`Pow.*`、`^Pow.*$`、`mcp__.*` 有效；`mcp__bkmcp__echo` 精确匹配 MCP 工具名。
- PostToolUse 的 matcher 同理（`mcp__.*` 有效）。未测：`Task|Agent`（本次没有走到匹配）。
- 对设计：规格 §5 的 matcher `*` 与 PostToolUse 的 `WebFetch|WebSearch|mcp__.*` 都成立。

## E9 并发与会话（部分验证）

- 同一事件上挂两个 hook（PreToolUse 的 pre-iso 与 pre-noiso）：同一毫秒并行启动。
- `session_id` 在 `--resume <id>`、`--continue`、`/compact` 前后不变；SessionStart 的 `source` 依次是 `startup`、`resume`、`resume`、`compact`（compact 会再触发一次 SessionStart）。
- 项目级、local 级、`--settings` 三处的 UserPromptSubmit hook **合并**（三个都触发），不是覆盖。用户级未测（不改你的用户设置）。
- 并行工具调用：haiku 与 sonnet 都是每轮只发一个工具调用，没能触发并行；未验证。
- **`/clear` 换新 session_id**（VS Code 扩展里实测）：`/clear` 之后触发一次 SessionStart，`source` 为 `clear`，session_id 是新的；所以按 session_id 存的任务意图与污染状态在 `/clear` 后自然是新的，不需要额外处理。
- 对设计：常驻进程必须能同时处理同一事件的多个 hook 请求（规格 §5.1 的管道实例池）；session_id 可作会话状态的键，compact 之后任务意图与污染状态不需要重建。

## E10 性能（已验证，本机微基准）

数字只代表本机当时的状态（i7-13700H，Windows 11 build 26200，Python 3.12.7，后台有 Claude 与 VS Code 在跑），不是产品评测。`bench_hook_cold_start.py` 各测 60 次，墙钟时间含进程创建与解释器启动：

| 写法 | p50 | p95 |
|---|---|---|
| `python -I -S -c pass` | 17.7 ms | 26.6 ms |
| `python -I -c pass`（导入 site） | 25.9 ms | 28.0 ms |
| `python -I -S probe_hook.py`（记录器，写一行日志） | 29.5 ms | 32.8 ms |
| 同一脚本包成 distlib `.exe` 启动器 | 46.2 ms | 52.9 ms |
| 经 mise 的 `python.exe` shim | 93.3 ms | 118.9 ms |
| hook 形状的命名管道客户端（`python -I -S`，一次往返） | 28.9 ms | 43.0 ms |
| 同上，`.exe` 启动器 | 44.4 ms | 58.5 ms（最大 257 ms） |
| 常驻进程没起（`FileNotFoundError` 立即降级） | 28.1 ms | 39.8 ms |

- 新生成的 `.exe` 第一次运行 271.8 ms，约是稳态的 6 倍：这是杀毒软件首次扫描的代理，不是对 Defender 的直接测量。
- **Claude 视角的每次工具调用耗时**（Glob × 10 × 2 轮，从 assistant 的 tool_use 到 tool_result 到达）：挂 3 个 hook 进程（PreToolUse 并行 2 个 + PostToolUse 1 个）p50 142 ms、p95 204 ms；禁用 hook（`--settings` 里 `disableAllHooks`）p50 47 ms、p95 54 ms。增量约 95 ms，大致是每个 hook 事件各 45 ms。
- **命名管道服务端的并发原型**（`bench_pipe_concurrency.py`，每种配置 3 轮；证据 `experiments/evidence/pipe_concurrency_4x50.json`、`pipe_concurrency_32x20.json`；这是原型基准，不是 M0 的 E19）。客户端按规格 §5.1 的写法：`FileNotFoundError` 立即失败，其他 `OSError` 退避重试（0.5 ms 起，翻倍到 20 ms，总预算 2 秒）；"不重试"是预算为 0 的对照，用来量"管道忙"有多常见。实测里同一事件最多并行触发 2 个 hook（E9）；模型发出并行工具调用时会更多（没能触发，未验证），所以 4 个客户端一组比已见到的真实情况更保守，32 个客户端是压力测试。表里的范围是 3 轮的最小到最大，来自最后一次运行；我跑过不止一次，同一配置在两次运行之间有明显波动（不重试时的成功数最多差近一倍），所以只当量级看，不当固定值。

| 服务端 | 顺序往返 p50 / p95 | 4 客户端 × 50 次：不重试时成功 | 重试后 p99 / 最大 | 32 客户端 × 20 次：不重试时成功 | 重试后 p99 / 最大 |
|---|---|---|---|---|---|
| asyncio `start_serving_pipe`（1 个待连接实例） | 0.070 到 0.075 / 0.144 到 0.165 ms | 42 到 47 / 200 | 2.7 到 2.9 / 5.2 ms | 160 到 177 / 640 | 34.0 到 34.7 / 54.4 到 75.6 ms |
| ctypes，实例池 1 | 0.021 到 0.023 / 0.033 到 0.045 ms | 29 到 33 / 200 | 2.6 到 4.8 / 4.9 到 9.3 ms | 42 到 58 / 640 | 35.0 到 74.8 / 54.7 到 116.3 ms |
| ctypes，实例池 8 | 0.023 到 0.025 / 0.026 到 0.051 ms | 192 到 196 / 200 | 0.2 到 0.9 / 0.6 到 1.0 ms | 283 到 330 / 640 | 6.1 到 10.0 / 18.1 到 18.6 ms |

  - **重试后全部成功**：三种服务端、两组并发、每组 3 轮，共 7560 次调用，0 失败；"管道忙"始终是 `OSError(errno=22, winerror=None)`，没有出现别的错误形态。
  - **不重试时失败很常见**：单实例的服务端（asyncio 与实例池 1）在 4 个并发客户端下有 76% 到 85% 的首次连接遇到"管道忙"，32 个并发下是 72% 到 93%；实例池 8 个把这个比例在 4 并发下降到 2% 到 4%，32 并发下降到 48% 到 55%，32 并发的重试后 p99 从 34 ms 以上降到 6 到 10 ms。
  - 单实例的 ctypes 服务端并不比 asyncio 基线好（32 并发时 p99 与最大延迟相当或更差），好处来自实例池而不是 ctypes 本身。无并发时一次往返约 0.02（ctypes）到 0.07 ms（asyncio），相对 hook 进程启动的约 30 ms 可以忽略。
  - **DACL**（用 `NamedPipeClientStream.GetAccessControl` 读出，SID 与账户名已脱敏）：asyncio 的管道是 `D:(A;;FR;;;WD)(A;;FR;;;AN)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<当前用户>)`，Everyone 与匿名账户有读权限；ctypes 服务端是 `D:P(A;;FA;;;<当前用户>)`，只有当前用户。
- 对设计：命名管道往返本身可以忽略，开销来自进程启动；默认 exec 写法倾向 `python.exe -I -S <脚本>`（比 `.exe` 启动器快约 17 ms，比 mise shim 快约 64 ms，还忽略 `PYTHON*` 环境变量）；boundkeep 只在 PreToolUse 挂一个 hook（外加按 `taint.sources` 生成的 PostToolUse），按这个增量估计每次工具调用多约 45 到 90 ms，M0 实测后再定。

## E11 allow 语义与权限模式（部分验证）

规则：项目 settings 里 `ask: PowerShell(New-Item *BK_ASKRULE*)`、`deny: PowerShell(New-Item *BK_DENYRULE*)`；不预先允许任何工具；命令含 `BK_ALLOW` 时 hook 返回 allow。五条 `New-Item` 命令的结果：

| 命令 | 结果 |
|---|---|
| 无规则、无 hook 决定 | 触发 PermissionRequest，无人批准，被拒 |
| hook 返回 allow | **执行了，没有 PermissionRequest**：allow 替用户跳过了确认 |
| 命中 ask 规则 + hook allow | 仍触发 PermissionRequest，被拒：**allow 压不过 ask 规则** |
| 命中 deny 规则 + hook allow | 被拒，没有 PermissionRequest：**allow 压不过 deny 规则** |
| 命中 ask 规则、无 hook 决定 | 触发 PermissionRequest，被拒 |

- 另：`Write-Output` 这类只读命令本来就不需要批准，用它做"无 hook"基线没有区分度。
- **权限模式**：`manual`（hook 里的 `permission_mode` 是 `default`）、`acceptEdits`、`plan`、`dontAsk` 下，hook 的 deny 与 ask 都生效（命令都没执行），allow 与无决定的命令执行了。`--permission-mode auto` 时 payload 里仍是 `default`，说明 auto 模式没有生效（可能需要账户或版本条件），不算已测。`bypassPermissions` 按协议只在一次性容器里并经你批准才能测，未测。
- 对设计：`emit_allow` 默认关闭是对的——开启后 boundkeep 会替用户跳过确认；Claude Code 自己的 ask / deny 规则仍然是上限。`doctor` 开启时要提示。

## E12 配置篡改（已验证，CLI 引擎）

- **`disableAllHooks` 的效果**：`.claude/settings.local.json` 里有 `{"disableAllHooks": true}`（来源 local）时，hook 一个都不跑：记录器 0 条、Claude 的 `hook_started` 0 条，没有任何提示。
- **Claude Code 自带的保护**：agent 用 `Write` 工具或 PowerShell `Set-Content` 写这个文件，即使工具已被预先允许，也要人工批准，无人批准时被拒。这是 Claude Code 在 `permissions.allow` 之上的保护，boundkeep 的 `protect-guard-config` 是再加一层，且 PreToolUse hook 能看到这两次尝试。
- **会话中途改配置立刻生效**：外部进程在命令执行期间把 `settings.local.json` 改成 `disableAllHooks: true`，之后的 PostToolUse、后续命令的 hook、Stop 都不再触发（没有"启动时快照"）。
- **`ConfigChange` 事件**：文件改动约 1.5 秒内触发，输入 `source: local_settings`、`file_path`。**hook 返回退出码 2 能阻止变更**：被阻止后后续的 hook 都照常触发（官方文档：`policy_settings` 来源的变更不能被阻止）。
- 对设计：① boundkeep 的 `init` 应同时注册一个 `ConfigChange` hook，拦下会引入 `disableAllHooks` 或移除 boundkeep hook 的变更；② 它拦不住"会话开始前文件里就已经有 `disableAllHooks`"，那种情况只能靠 `doctor` 与 SessionStart 时的自检；③ 托管设置与 `CLAUDE_CONFIG_DIR` 未测。

## E13 覆盖面（部分验证）

- **子 agent**：启动子 agent 的工具在 hook 里叫 `Agent`（init 的工具列表里叫 `Task`）；子 agent 里的 PowerShell 调用触发 PreToolUse 与 PostToolUse，并带 `agent_id`、`agent_type`（`general-purpose`）。
- **`@` 引用绕过 hook**：提示词里的 `@probe.txt` 让模型直接答对了文件内容，没有任何 Read 的 PreToolUse。官方文档已说明，实测证实。
- **MCP**：用最小 stdio 服务（`experiments/mcp_echo_server.py`）验证：工具名 `mcp__bkmcp__echo`，hook 输入顶层有 `mcp_server`，PostToolUse 的 `tool_response` 是内容块列表。
- **WebFetch、WebSearch、ToolSearch** 都触发 PreToolUse 与 PostToolUse：用户报告的 #93182（服务端工具不经过 hook）在 `WebSearch` 上没有复现。`WebSearch` 的 `tool_input` 有 `query` 与 `mode`；`tool_response` 是 `{query, results, durationSeconds, searchCount}`，其中 `results` 是列表，里面既有 `{tool_use_id, content:[{title, url}]}` 字典，也有一段纯文本摘要字符串，污染提取不能假设元素类型一致。
- **`Agent` 工具的 PostToolUse**（只观察到一条）：子 agent 以后台方式启动时，PostToolUse 在启动那一刻就触发，`tool_response` 是 `{isAsync: true, status: "async_launched", agentId, outputFile, ...}`，不含子 agent 的结果文本；同步方式的返回形态没有观察到。
- 对设计：`taint.sources` 里的 `WebFetch`、`WebSearch`、`mcp__*` 都能收到 PostToolUse；规则要覆盖 `Agent`、`ToolSearch`；`@` 引用的绕过只能靠 Claude Code 自己的 Read deny 规则补充（规格 §3 已写）。

## E14 prompt hook 与 agent hook（已验证，agent hook 为实验性）

PreToolUse 上挂 `type: "prompt"` 的 hook（提示词要求：命令含 `BK_PROMPT_BLOCK` 就返回 `{"ok": false, "reason": ...}`）：

- 默认（`continueOnBlock` 为 false）：被判 `ok: false` 的调用被拒绝，**整轮对话随之结束**，模型的最终回复为空；理由作为警告出现。
- `continueOnBlock: true`：理由回传给模型，模型继续并汇报了理由。
- `type: "agent"`：同样拦下，理由是 "Agent hook condition was not met: ..."；agent hook 自己的内部工具调用（`StructuredOutput`）也会触发挂在 `*` 上的 hook。
- 这类 hook 经 Claude Code 当前会话的认证调用模型（无需另配 API 密钥），但没有任务意图与污染状态，输出格式由 Claude Code 规定，无法做代码二次裁决。
- 对设计：支撑规格 §5"为什么不用其他处理器"；不进 v0。

## E16 exec 形式（部分验证）

- `command` 为 `python.exe` 绝对路径、`args` 为数组：可用，包括 `-I -S` 与 `-S`；hook 进程直接拿到参数，不经过 shell。
- distlib 生成的 `.exe` 启动器可用（内嵌脚本，`__file__` 在 zip 里，所以记录目录要用环境变量指定）；含空格与中文的目录（`路径 测试`）里的 `.exe` 与脚本都可用。
- 冷启动与首次运行数字见 E10。
- 控制台窗口：VS Code 里 `python.exe -I -S` 的 exec 写法目视没有闪现（一次观察），`.exe` 启动器未测；未测：较早版本的 Claude Code 丢弃 `args` 的行为（本机版本太新，无法复现）。
- 对设计：M0 的 exec 写法默认选 `python.exe -I -S <脚本>`；`.exe` 启动器作为备选（路径更短，但慢约 17 ms，首次运行要过杀毒软件扫描）。

## E17 Windows 的 stdin 形式（部分验证）

- `cwd`：`E:\bk-lab`；`transcript_path`：`C:\Users\<user>\.claude\projects\E--bk-lab\<uuid>.jsonl`（项目目录被编码成 `E--bk-lab`）；`tool_input.file_path`：`E:\bk-lab\probe.txt`。都是反斜杠加盘符。环境变量 `CLAUDE_PROJECT_DIR` 同形。
- **盘符大小写不稳定**（VS Code 扩展）：`CLAUDE_PROJECT_DIR` 与 `file_path` 是小写 `e:\bk-lab`，`cwd` 在同一会话里既有 `e:\bk-lab` 也有 `E:\bk-lab`，甚至同一个 PreToolUse 事件的两个并行 hook 看到的 `cwd` 大小写也不同（Read 那一次）；`transcript_path` 里的项目目录被编码成小写的 `e--bk-lab`。CLI 引擎里 `cwd` 与 `file_path` 一律是大写。原因未明。所以路径比较必须不区分大小写（规格 §5.1 已要求），也不能假设几个字段的盘符写法一致。
- 未测：`Bash` 命令里的路径写法（模型只写了 `pwd`）。

## E18 环境与编码（已验证）

- **环境变量原样传入 hook**：CLI 引擎里外层设置的 `PYTHONIOENCODING` 能在 hook 里看到；清除后看不到。**VS Code 扩展宿主的 hook 环境里没有它**（它只设在开发机的 shell 环境里）。
- hook 进程还会得到 Claude Code 自己设置的 `CLAUDECODE`、`CLAUDE_CODE_ENTRYPOINT`、`CLAUDE_CODE_SESSION_ID`、`CLAUDE_PROJECT_DIR`、`CLAUDE_CODE_MESSAGING_SOCKET`、`CLAUDE_CODE_MESSAGING_TOKEN` 等。**`CLAUDE_CODE_MESSAGING_TOKEN` 是令牌**：hook 与日志绝不能记录环境变量的值。
- **stdin 是 UTF-8 字节**。Python 在没有 `PYTHONIOENCODING`、也没开 UTF-8 模式时按 gbk 解码：含非 ASCII 的事件（带中文的 `UserPromptSubmit`、含 `✓` 或中文的 `PowerShell` 命令及其 `PostToolUse`）按文本模式读 stdin 会抛 `UnicodeDecodeError`，纯 ASCII 的事件没事；`print` 非 ASCII 到 stdout 同样失败；崩溃的 hook 退出码为 1，非阻断，命令照常执行（`BK_NAIVE`）——闸门悄悄放行。
- 对设计：规格 §5.1 的"hook 客户端 I/O"约束（按字节读写、显式 UTF-8、ASCII-only JSON、最外层捕获所有异常）被真实事件证实；用户提示词含中文是常态，所以 `UserPromptSubmit` 最先出问题。

## E20 PowerShell（部分验证）

- Claude Code 的 PowerShell 工具用的是 `powershell.exe`（Windows PowerShell 5.1.26100.9444；本机没装 pwsh）；进程级执行策略为 `Bypass`，CurrentUser 为 `RemoteSigned`，与官方文档一致。
- **约束语言模式下 AST 解析器不可用**：`[System.Management.Automation.Language.Parser]::ParseInput` 报 "Method invocation is supported only on core types in this language mode"；`Get-Alias` 仍可用。所以规格 §5.1 的 AST 辅助进程方案遇到约束语言模式必须降级为灰色，`doctor` 要报告。
- Claude Code 自己的 PowerShell 权限分析很保守：`Write-Output $PSVersionTable.PSEdition` 这类含 `$` 变量或 .NET 属性访问的命令，即使有精确的允许规则，在 `-p` 下也需要批准而被拒；`Get-Host`、`Get-ExecutionPolicy -List` 这类只读 cmdlet 可以。
- 未测：`pwsh.exe`（7+）与 `powershell.exe` 的选择逻辑（本机没有 pwsh）。

## E21 路径规范化的边界（部分验证）

`probe_paths_windows.py` 的结果：

- Documents 没有被 OneDrive 重定向（`~\Documents`），PowerShell profile 在 `~\Documents\WindowsPowerShell\`；本机所有盘都是 NTFS；目录级大小写敏感属性是关闭的；8.3 短名生成状态需要管理员权限，未查到。
- `os.path.realpath`：存在的短名前缀会展开（`C:\PROGRA~1\nonexist` → `C:\Program Files\nonexist`）；**不存在的短名保持原样**（`C:\Users\NONEXI~1`），所以 allow 侧要把它当"无法确定"；`..` 在不存在的路径上按词法折叠。
- Git Bash 的路径映射（`cygpath -w`）：`/` 与 `/usr` 映射到 Git 安装目录（本机含中文），`/tmp` 映射到 `%TEMP%`，`/c/Users` 映射到 `C:\Users`，`$HOME` 映射到用户目录，`/d/x` 映射到 `D:\x`。
- 未测：非 NTFS 卷、WSL 的 `/mnt/<盘>/`、用户报告的绕过（#99193、#94256）的复现（那是用户 hook 的比较方式问题，boundkeep 的规范化层实现后再测）。

## E22 工具链解析（已验证）

见 E6 的坏 hook 表：命令不存在、`.cmd` 垫片、非可执行文件、Microsoft Store 占位符（本机真实存在，退出码 49）都是非阻断的静默失效，命令照常执行；mise 的 `python.exe` shim 能用但慢约 64 ms。另外 `claude doctor` 在本机报告 `C:\Users\<user>\.local\bin\claude.exe missing or broken`（解释了终端里 `claude` 命令的 mise shim 报错），**它不报告任何 hook 状态**，所以 `boundkeep doctor` 要自己查。

## E23 配置与托管（部分验证）

- `claude -p` 不弹工作区信任对话框；项目级 hook 照常运行，但项目 settings 里的 `permissions.allow` 被忽略，并向 stderr 打印一行 "Ignoring N permissions.allow entries from .claude/settings.json: this workspace has not been trusted ..."。
- `claude --help`：`--safe-mode`（设置 `CLAUDE_CODE_SAFE_MODE=1`）会禁用包括 hook 在内的所有自定义；`--bare` 跳过 settings 与插件里的 hook。这两个开关都会让闸门静默失效。
- **VS Code 扩展里打开从未打开过的目录**（`E:\bk-lab-matchers`）：没有弹出任何信任对话框，该目录项目级的 SessionStart hook 随会话启动照常运行。`~/.claude.json` 里 `e:/bk-lab` 的 `hasTrustDialogAccepted` 是 false，hook 却照常运行；VS Code 的工作区信任没有被关闭（用户设置里只有 `untrustedFiles: open`），没弹对话框的原因未明（可能是父目录已被信任）。官方文档"接受信任前不运行 settings 里的 hook"在这个宿主与配置下没有观察到。工具类 hook 在未信任目录里是否运行没能测（你只打开了目录，没发消息，也没有信任对话框可以拒绝）。
- 对设计：项目级 hook 配置在新克隆的目录里随会话启动立即生效（利于"策略进仓库、克隆即生效"），反过来也意味着不可信仓库自带的 hook 也会在没有对话框的情况下运行——那是 Claude Code 与 VS Code 的问题，boundkeep 的 `doctor` 只需如实报告信任状态。
- 未测：托管设置（`allowManagedHooksOnly`，需要管理员权限，不改机器级配置）、`CLAUDE_CONFIG_DIR`（换目录会丢登录态）、CLI 交互会话里的信任行为。

## 与官方文档的差异

没有矛盾。文档没写或措辞不同的：deny JSON 配退出码 1 仍被执行；旧式 `decision: block` 仍被接受；`-p` 下项目 `permissions.allow` 被忽略；Git 装在非标准路径时 Claude Code 不自动发现 Git Bash；盘符大小写在同一会话里不稳定；VS Code 扩展的 payload 多 `scratchpad_dir` 与 `effort`。

## 界面操作结果（2026-10-06，VS Code 扩展，`acceptEdits` 模式）

按 `E:\bk-lab\README_VSCODE_UI.md` 做了：六条标记命令（两次，第二次在 `/clear` 之后）、`/clear`、打开从未打开过的目录。你的回答与日志对得上的部分已写进 E6、E9、E23。当时没能确认、之后重测过的（ask 确认框不显示 hook 的理由；执行时没有控制台窗口）见 E6 一节；仍没能确认的：未信任目录里工具类 hook 是否运行（没有对话框可拒绝，也没发消息）。

## 对设计的影响汇总

1. 规格 §10 的降级设计成立；客户端 I/O、总预算、最外层异常捕获、合法 JSON 输出都是硬要求（E6、E18）。
2. `emit_allow` 默认关闭是对的；Claude Code 自己的 ask / deny 规则是上限（E11）。
3. `ConfigChange` hook 是 `protect-guard-config` 之外的第二道防线，`doctor` 补会话前就存在的 `disableAllHooks`（E12）。
4. exec 写法默认 `python.exe -I -S <脚本>`；`init` 与 `doctor` 要按 exec 形式原样启动并校验输出（E6、E10、E16）。
5. normalize 要按工具取路径字段，盘符比较不区分大小写（E3、E17）。
6. PowerShell AST 方案在约束语言模式下降级为灰色（E20）。
7. hook 出错、超时、崩溃时 VS Code 界面完全没有提示，用户自己也看不出闸门失效；`init` 自检与 `doctor` 是唯一的发现手段（E6）。
8. 任务意图要从 `UserPromptSubmit` 的 `prompt` 里剥离 `<ide_*>` 块（含选中的文件内容）并把 `<pasted_content>` 当不可信文本（E3）。
