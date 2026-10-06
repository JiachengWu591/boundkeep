# 同类项目对照（M0a E7）

> 调研日：2026-10-06。方法：桌面调研，只读，不写代码。
> 来源：调研员（子 agent）读取各项目公开页面后汇总；**我复核了 cc-audit B（selimllc）的 README**，其余单元格未逐格复核。读不到或文档没写的一律记"未知"，不推测。
> 注意：调研员发现 WebFetch 的摘要不可靠（曾对一个项目声称某文件存在而实际不存在），关键结论是用原始 README、PyPI JSON 与 GitHub API 核对的。
> 这个赛道有不少早期项目，规格 §15 要求 README 不得声称"没有同类"。

## 对照表

| 项目 | 定位 / 版本 / 许可 / 语言 | 运行时阻断（挂载点；失败时） | LLM | 任务意图 | 污染追踪 | 评测数据 | 界面 | Windows | 检查 hook 被关 | 与装前扫描的关系 |
|---|---|---|---|---|---|---|---|---|---|---|
| cc-audit A（ryo-ebata） | 装前静态扫描 skills / hooks / MCP；v3.23.23（2026-10-05），MIT，Rust [1] | 否。`hook` 子命令是 git pre-commit；MCP proxy 有 `--block`，不是 Claude hook [1] | 无（自称 AI-free）[1] | 无 | 无 | 无，只写"100+ 规则" [1] | CLI，HTML / SARIF 报告 [1] | README 未写；release 有 windows-msvc 包 [1] | 未提 disableAllHooks；有 baseline / drift 检测 [1] | 就是装前扫描，与运行时互补 |
| cc-audit B（selimllc） | 本地 PreToolUse 审计 + 敏感文件阻断；v0.2.0（2026-09-06），MIT，Python [2] | PreToolUse，matcher `*`，exit 2 阻断。策略文件损坏时 fail-closed；**自身内部崩溃时 fail-open** [2] | 无（"No network calls"）[2] | 未提 | 未提 | 未提；仅三平台 CI 测试 [2] | CLI report / tail [2] | **明确支持**，CI 跑 windows-latest [2] | `cc-audit status` 检查注册、解释器与自检；保护 settings.json；未提 disableAllHooks [2] | 运行时，与 A 互补 |
| lasso-security/claude-hooks | 间接提示注入检测；无 release，dev 分支最后提交 2026-01-08，MIT，Python + TS [3] | 否：PostToolUse 只警告；代码异常时 exit 0 放行 [3] | 无（正则，"No LLM API usage"）[3] | 无 | 无：无状态、逐次警告，不收紧后续判定 [3] | 无 | 无，只给上下文警告文本 | 未提；安装依赖 bash / uv [3] | 未提 | 运行时内容检测，与装前扫描互补 |
| AgentGuard（PyPI `agentsguard`） | 手机审批风险命令；0.4.1（2026-07-12），专有许可，Python ≥ 3.9 [4] | PreToolUse（示例 matcher 仅 Bash）；LOW 放行，CRITICAL 拒绝，MEDIUM / HIGH 等手机审批，超时默认拒绝 [4] | 未提；分类器实现未知 | 未提 | 未提 | 无 | 手机（Telegram，或云中继 + App）、CLI 日志 [4] | 未知 | 未提；`.claude/` 列为受保护文件，改动必须审批 [4] | 运行时 |
| OpSentry | 三层：bash hook、CI AST 分析、沙箱配置生成；PyPI 1.8.9（2026-10-01），Apache-2.0，Shell + Python [5][6] | PreToolUse bash 脚本，exit 2 阻断；宿主超时按 fail-open 处理（文档承认不可控）；超长命令、脚本数、文件大小超限则 fail-closed [6] | 运行时无；Pro 档 CI 有"LLM 代码审查（BYOK）"；红队循环用 headless claude [6] | 无 | 无 | 168 个 hook 测试（101 功能 + 67 对抗），8 类红队攻击均已修补；无拦截率或误报率 [6]（红队日志写 203，数字不一致） | CLI；仪表盘只列在 Enterprise 档 [6] | 仅 WSL；WSL2 沙箱是未勾选的计划项 [5][6] | `verify.sh` 与 patrol 查 hook 存在、未改、已注册；SHA-256 基线 + chattr / chflags 锁；未提 disableAllHooks [6] | 运行时 + CI 层，CI 层部分重叠 |
| TaskBound A（vaibhavkrishna12004） | 研究原型，按用户任务核对动作；无 release，2026-09-27 创建，MIT，Python [7] | 在模拟邮件助手的工具调用前拦截，**不是 Claude Code hook**；高风险转人工，签名短期令牌；失败行为未知 [7] | 被测 agent 用 Claude Haiku 4.5；guard 是否用 LLM 未知 [7] | **有**："检查动作是否属于用户实际分配的任务"；policy.yaml 有 task profiles [7] | 部分：读客户数据后会话标为 sensitive（敏感数据标记，不是不可信内容标记）[7] | 有，作者自测小样本：无 guard 55 / 80 次泄露，有 guard 29 次尝试 0 泄露；误报率"待测" [7] | 无 | 无 | 未提 | 运行时 |
| TaskBound B（PuffBear） | AgentDojo 基准上的防御研究；分支 `fde-agentdojo-defense`，最近推送 2026-09-08，MIT，Python [8] | 在工具执行边界拒绝并返回净化的拒绝信息；**不是 Claude Code hook** [8] | 防御是否用 LLM 未写；评测 agent 用 LLM [8] | **有**：从原始用户任务推导"授权包络" [8] | 近似：工具返回文本只能提供数据，不能产生授权 [8] | **有**：开发集 ASR 6/12 降到 0/12，良性效用 14/16 持平；封存集两臂 ASR 均 0/12；6 次合法重复删除被误拦 [8] | HTML / PDF 报告，非产品 UI [8] | 未知 | 未提 | 运行时研究 |

## 对 boundkeep 定位的含义

- **cc-audit 有两个同名项目**：A 是装前静态扫描（与 boundkeep 互补）；B 是运行时 PreToolUse 审计，支持 Windows、CI 含 windows-latest，**最接近 boundkeep 的确定性层**。B 的差别在：内部崩溃时放行（boundkeep 的不变量是降级为 ask）、没有任务意图 / 污染追踪 / 评测数据（README 未提）。规格 §15 与 README 要把两者分开写。
- **任务意图 + 污染追踪的组合**：在已读到的资料里，只有 TaskBound 两个研究项目触及"任务意图"，且都不是 Claude Code hook；没有项目同时有任务意图、污染追踪与带拦截率 / 误报率的评测。这只是"已读到的资料里没有"，不是"没有"（README 不得声称没有同类）。
- **hook 被关闭的检测**：全体都没提 `disableAllHooks`；只有 cc-audit B 与 OpSentry 做了 hook 完整性或自检。boundkeep 的 `doctor` 与 `ConfigChange` 拦截（docs/hook-behavior.md E12）在这一点上有差异化。
- **失败行为**：多数项目对自身崩溃 / 宿主超时是放行；boundkeep 的客户端必须保证降级为 ask（实测见 E6、E18）。
- 评测口径：TaskBound B 的评测最严谨，诚实报告了误拦与恢复失败，但只是 AgentDojo 基准内的结果，不能外推到 Claude Code。

## 读不到 / 不确定

- 名称冲突：PyPI 上另有 `agentguard-security`、`agentguard-auth` 等同名系列，只按指定的 `agentsguard` 读；搜索结果里 Auditware 的 "Sentry" 平台名字与 OpSentry 相近，未打开，应是另一个产品。
- AgentGuard：GitHub 仓库页返回 404，只能依据 PyPI README；分类器是否用 LLM、云中继数据流向、hook 自身崩溃时的行为、Windows，均未知。
- OpSentry：缺 `jq` 时是放行还是阻断未写；GitHub 最新 release 落后于 PyPI；"没有其他工具公开对抗测试证据"是厂商说法。
- TaskBound A：README 写有 `guard.py` 与 `policy.yaml`，但 GitHub API 的 git tree 里没有这两个文件，核心代码目前读不到；数字是作者自测的小样本（每组 10 次）。
- TaskBound：两个项目是否就是规格里指的"TaskBound"，无法确认。
- 多数项目的 Windows 文档为"未知"。

## 来源

1. https://github.com/ryo-ebata/cc-audit（README、docs/FEATURES.md、docs/CLI.md、releases/tag/v3.23.23）
2. https://github.com/selimllc/cc-audit ；https://pypi.org/project/cc-audit/
3. https://github.com/lasso-security/claude-hooks/tree/dev（README、INSTALLATION.md、post-tool-defender.py）
4. https://pypi.org/project/agentsguard/ ；https://pypi.org/pypi/agentsguard/json
5. https://pypi.org/project/opsentry/
6. https://github.com/opsight-intelligence/opsentry/tree/develop（README、docs/quickstart.md、docs/red-team-log.md、CHANGELOG.md、opsentry/verify.sh、opsentry/baseline.py）
7. https://github.com/vaibhavkrishna12004/TaskBound
8. https://github.com/PuffBear/taskbound-agentdojo-defense/tree/fde-agentdojo-defense（reports/final_report.md）
