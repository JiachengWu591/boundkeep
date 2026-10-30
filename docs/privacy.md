# 隐私：什么离开本机，什么留在本机

> 状态：2026-10-30（M3a）。boundkeep 默认**不配置任何 LLM 后端**（`llm_audit.backend: none`），这时没有任何数据离开本机。M3a 实现了 OpenAI 兼容接口的适配器，但**没有接过任何真实服务**（只对本地假服务做过一致性测试），所以这里不声明支持任何厂商，也不替任何厂商的数据保留与训练条款做承诺：配置一个后端之前，请自己读那家服务的条款。哪些后端实测过、版本与结论，M3b 起记在 `docs/llm-backends.md`。

## 1. 发给 LLM 后端的内容（只在配置了后端时，只对规则判不了的动作）

唯一的发送出口是 `src/boundkeep/audit/send_gate.py`：先按字段白名单取值，再整体脱敏；序列化之后再脱敏一遍，结果有任何不同就不发。一次请求的用户消息是一个 JSON 对象：

| 字段 | 内容 |
|---|---|
| `task_intent` | 用户最近几条提示（`llm_audit.intent_prompts`，默认 3），每条最多 `intent_chars` 字（默认 300）。宿主拼进提示的 `<ide_opened_file>`、`<ide_selection>`（含选中的文件内容）等块整段去掉；用户粘贴的文字（`<pasted_content>`）不取，只留"粘贴了 N 个字符"的标记；先脱敏再截断。`send_task_intent: false` 时这个字段是 `null` |
| `tool` | 工具名（`Bash`、`PowerShell`、`Write`、`mcp__服务__工具` ……） |
| `actions` | 每个简单命令一项：程序名、子命令、选项、命令的词（主目录写成 `~`）、路径（项目内写成 `<project>/…`，主目录下写成 `~/…`，附访问方式与是否在项目内；用守护进程的环境展开过变量的路径按原文，如 `$GITHUB_TOKEN/x`）、主机名、风险标签、包装器、规则判不了的原因 |
| `cwd_inside_project`、`tainted`、`taint_sources`、`read_untrusted` | 工作目录是否在项目内；会话是否刚读过不可信内容，以及来源**工具名**（不含内容） |

**不发**：文件内容（`Write` 的 `content`、`Edit` 的新旧文本）、工具输出（`tool_response`）、原始命令行、工作目录、`session_id`、`transcript_path`、环境变量、hook 事件里白名单之外的任何字段。

**不发的情形**：动作太多、词太多或太长、请求超过 16000 字符、词或路径里有控制字符或格式字符、秘密要几个词连起来才看得出（`--password X`、`curl -u user:pw`）、序列化后再脱敏一遍会变、请求里出现守护进程环境里名字像秘密（KEY、TOKEN、SECRET、PASSW、CREDENTIAL、AUTH、COOKIE）的变量的值（至少 8 个字符，不分大小写，含 API 密钥本身）时，什么都不发，直接按 `on_failure` 处理；调用没有被完整分析时（解析器的预算用完、内部错误等）也不发，直接 ask（`docs/threat-model.md`）。

**系统提示词**固定在 `src/boundkeep/audit/prompts/audit_system.md`，不含任何用户数据；它的版本与哈希写进每条审计记录。

**脱敏是尽力而为**（规格 §11）：`sk-*`、`AKIA*`、`ghp_*`、私钥块、`Bearer *`、名字里有 KEY / TOKEN / SECRET / PASSWORD 的赋值（含 PowerShell 与 cmd 的写法）等形态会被替换为 `[REDACTED]`；脱敏器认得的"选项 + 值"写法（`--password X`、`curl -u user:pw`）整条命令不发；不带任何可识别形态的口令（一个裸的位置参数）认不出来。所以发送内容先走白名单，不只靠脱敏。

**密钥**：只从 `api_key_env` 指定的环境变量（默认 `BOUNDKEEP_LLM_API_KEY`）读，每次调用时读，只放在 `Authorization` 请求头里；不写进策略、日志、缓存、会话状态、错误信息或报告。boundkeep 不读 `ANTHROPIC_API_KEY`。

## 2. 留在本机的内容（`~/.boundkeep/`，只有当前用户能读）

| 文件 | 内容 | 保留 |
|---|---|---|
| `logs/audit.jsonl` | 每个事件一条：判决、命中的规则、shell 命令（脱敏、截断）、工具名、会话 id；提示词只记长度；M3a 起另有污染状态（是否被污染、来源工具名），以及 LLM 审计的摘要（后端、模型、提示词版本、是否命中缓存、结果、token 数、模型写的理由，清洗并截断到 300 / 200 字） | 5 MiB 轮转，保留 5 份；`boundkeep log --purge` 删除 |
| `session.sqlite`（及 `-wal`、`-shm`） | 每个会话：首次与最近出现的时间、距上次污染来源调用的工具调用次数、来源工具名（最多 16 个）；**只在配置了 LLM 后端且 `send_task_intent` 为 true 时**，另存最近几条任务意图（与上面发送的是同一份文字） | 30 天没有活动的会话删除；最多 5000 个会话；`boundkeep log --purge` 同时删除所有任务意图（污染标记保留：删掉它会让已读过不可信内容的会话变回"干净"）；库开着 `secure_delete`，删除之后截断 WAL，删掉的文字不留在文件的旧页里 |
| 内存 | LLM 结论的缓存（键是发送内容的哈希） | `cache_ttl_s`（默认 600 秒），守护进程退出即消失 |

没有后端时，`session.sqlite` 里只有工具名与计数。
