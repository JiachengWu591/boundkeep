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
- hook 客户端的 I/O 不依赖代码页或 `PYTHON*` 环境变量：按字节读 stdin、显式 UTF-8 解码，按字节写只含 ASCII 的 JSON。Windows 中文系统默认按 gbk 解码，含中文的事件会抛 `UnicodeDecodeError`，Python 以退出码 1 退出，等于放行（开发机实测，规格 §5.1）。
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

## 常用命令（骨架完成后补全）

```
uv sync
uv run pytest -q                    # 默认不访问网络、不使用密钥；live 测试默认跳过
uv run ruff check .
uv run mypy src
uv run boundkeep test               # 运行策略内置的 tests
uv run boundkeep doctor             # 检查 hook 配置、常驻进程、策略文件、闸门是否被悄悄关闭
uv run boundkeep llm check          # 验证已配置的 LLM 后端（需要用户本地的密钥）
uv run python eval/run_eval.py --config rules-only
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

- 阶段：M0a（见 `PROJECT_SPEC.md` §14）。
- 规格已修订到"修订 3"：在修订 2（LLM 后端可插拔且默认关闭；依据官方 hooks 文档修正了配置、超时、降级与 allow 语义）的基础上，加入 Windows 原生与 WSL2（§5.1、§16-D、M1b）。
- `IMPLEMENTATION_PROMPTS.md` 已按修订 3 对齐（新增 M1b、E15 到 E24，M0 / M1 / M2 / R / X1 补了 Windows 与平台要求）。
- M0a 的实验与验收报告已完成，等用户确认（2026-10-06，Claude Code 2.1.291，Windows 11）：E1 到 E24 都有明确状态（已验证 / 部分验证 / 未验证 / 待 M0），结果在 `docs/hook-behavior.md`、`docs/platforms.md`、`docs/related-work.md`，脚本在 `experiments/`，验收报告在 `docs/reports/M0a.md`（结论"有条件通过"）。hook 在 CLI 引擎与 VS Code 扩展里都触发（E15）；Desktop 应用未测。界面操作用户已做完：阻断理由显示在弹窗与工具调用卡片里；hook 出错、超时、崩溃时界面没有任何提示；`/clear` 换新 session_id；打开从未打开过的目录没有弹信任对话框。已重测（均一次目视）：ask 确认框默认视图里不显示 hook 的理由；`python.exe -I -S` 的 exec 写法没有控制台窗口闪现。未验证：E11 的 `bypassPermissions`（`auto` 模式没生效）、E19（待 M0）、E23 的托管设置与 `CLAUDE_CONFIG_DIR`、E24 的其他平台。
- M0a 期间我直接改了规格与提示词（违反"M0a 不直接改规格"），用户已审阅并接受报告第 7 节的 10 条变更，同意提交脱敏证据与夹具，并要求复现（我已按 README 重跑 E3、E6、E10、E15 通过）。
- 下一步：进入 M0：先读 M0 提示词、出实施计划，等用户说"继续"再写代码。M0 手工验收时补看：ask 确认框折叠箭头展开后是否有理由、`.exe` 启动器在 VS Code 里是否闪窗、`bypassPermissions`。
