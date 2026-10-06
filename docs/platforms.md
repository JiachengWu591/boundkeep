# 平台与宿主支持记录

> "支持"的定义（规格 §5.1）：该平台与宿主上 M0 的验收项在真实 Claude Code 里跑通，并有本文件的实测记录；没有记录就写"设计目标，未实测"。
> M0 尚未开始，所以下表里**没有任何一行是"支持"**。本表记录的是 M0a 的可行性证据。
> 日期：2026-10-06；Claude Code 2.1.291；证据与方法见 `docs/hook-behavior.md` 与 `experiments/`。

| 平台 | 宿主 | shell 工具 | hook 是否触发（E15） | 状态 |
|---|---|---|---|---|
| Windows 11 原生 | CLI 引擎（`claude -p`，`sdk-cli`） | 只有 PowerShell（Git Bash 未被自动发现） | **已验证**：SessionStart、UserPromptSubmit、PreToolUse、PostToolUse、Stop 都触发；PowerShell、Read、Write 工具 | 可行性已验证；M0 未做，不声明支持 |
| Windows 11 原生 | CLI 引擎 | PowerShell + Bash（手动设置 `CLAUDE_CODE_GIT_BASH_PATH`，路径含中文） | **已验证**：Bash 与 PowerShell 都触发 | 同上 |
| Windows 11 原生 | VS Code 扩展 2.1.291（`claude-vscode`） | 只有 PowerShell | **已验证**：13 条记录，五类事件都触发；PowerShell、Read、Write 工具。用户报告的 #92074（v2.1.259）没有复现 | 可行性已验证；M0 未做，不声明支持 |
| Windows 11 原生 | Desktop 应用 | 未知 | 未测（用户报告 #95833、#77708，未核实） | 未测 |
| WSL 2 | CLI | Bash | 未验证：本机 WSL 里只有 `docker-desktop` 发行版 | 未验证 |
| macOS / Linux | — | — | 未验证：没有环境 | 未验证 |

## 当前判断

- **引擎层，Windows 原生可行**：hook 在 CLI 引擎里对 PowerShell、Bash、Read、Write 全部触发，exec 形式、退出码与超时语义、拒绝理由回传都符合规格 §5 与 §10 的设计；没有发现需要推翻设计的事实。
- **VS Code 扩展宿主（开发机的日常宿主）里 hook 同样触发**，与 CLI 引擎行为一致。剩下的未知是 Desktop 应用。
- **判断**：Windows 原生在两个已测宿主里引擎层都可行，可以进入 M0；"支持"的声明要等 M0 的验收在对应宿主上通过。
- **必须做进 M0 的防御**（已写入规格 §5.1 与 §10）：hook 客户端按字节读写（否则含中文的事件会让它崩溃并放行）；stdout 总是 `json.dumps` 生成的合法 JSON（非法 JSON 会被当作无决定）；任何异常都输出 `ask` 并以 0 退出；总超时预算自己实现；`init` 与 `doctor` 按 exec 形式原样启动 hook 命令并校验输出（命令起不来、Store 占位符、`.cmd` 垫片都是静默放行）；注册 `ConfigChange` hook 拦截 `disableAllHooks`。
- 已测的 hook 语义（E1 到 E14）见 `docs/hook-behavior.md`；多数是在 CLI 引擎里测的，VS Code 扩展里测了"是否触发"、payload 形式，以及用户亲自做的界面测试（阻断理由、ask、`/clear`、新目录）。VS Code 里：被阻断的理由显示在弹窗与工具调用卡片里，**hook 出错、超时、崩溃时界面没有任何提示**（所以 `doctor` 与自检是唯一的发现手段），`/clear` 换新 session_id，打开从未打开过的目录没有弹信任对话框。ask 的确认框默认视图里**不显示** hook 的理由（只有命令与模型的描述）；`python.exe -I -S` 的 exec 写法执行时没有控制台窗口闪现（均为一次目视观察）。
- VS Code 扩展会把 IDE 上下文（含选中的文件内容）拼进 `UserPromptSubmit` 的 `prompt`，任务意图提取必须剥离（规格 §9.2）。
- 其他平台没有环境，保持"设计目标，未实测"。
