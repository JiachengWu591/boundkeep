# 平台与宿主支持记录

> "支持"的定义（规格 §5.1）：该平台与宿主上 M0 的验收项在真实 Claude Code 里跑通，并有本文件的实测记录；没有记录就写"设计目标，未实测"。
> M0 的手工验收已在 Windows 11 原生的 **VS Code 扩展与 CLI（交互式）** 上通过（2026-10-08，Claude Code 2.1.292，shell 工具为 PowerShell；记录见 `docs/manual-acceptance-m0.md`），这两行写"M0 支持"。**M0 只有通路、降级与配置自保护，真正的规则在 M1**：这里的"支持"指"闸门能可靠地到达并在失败时关闭"，不是"能拦住危险命令"。其余行仍是"可行性已验证"或"未测"。
> M0a 的日期：2026-10-06；Claude Code 2.1.291；证据与方法见 `docs/hook-behavior.md` 与 `experiments/`。

| 平台 | 宿主 | shell 工具 | hook 是否触发（E15） | 状态 |
|---|---|---|---|---|
| Windows 11 原生 | CLI 引擎（`claude -p`，`sdk-cli`），M0 冒烟：Claude Code 2.1.292 | 只有 PowerShell（Git Bash 未被自动发现） | **已验证**：SessionStart、UserPromptSubmit、PreToolUse、PostToolUse、Stop 都触发；PowerShell、Read、Write 工具；M0 冒烟 14 项检查 0 失败（`scripts/smoke_claude.py`） | 自动冒烟通过；`-p` 不是用户日常用法，"支持"以下面的交互式 CLI 行为准 |
| Windows 11 原生 | **CLI 交互式**（VS Code 扩展自带的 2.1.292 可执行文件） | 只有 PowerShell | **已验证**：B1 到 B3 通过（canary 被拦且理由可见、普通命令放行、常驻进程停掉后出现确认提示） | **M0 支持**（见上方范围说明；Git Bash 未测） |
| Windows 11 原生 | CLI 引擎 | PowerShell + Bash（手动设置 `CLAUDE_CODE_GIT_BASH_PATH`，路径含中文） | **已验证**：Bash 与 PowerShell 都触发 | 同上 |
| Windows 11 原生 | **VS Code 扩展 2.1.292**（`claude-vscode`；M0a 在 2.1.291 上测过触发） | 只有 PowerShell | **已验证**：M0a 13 条记录五类事件都触发；M0 手工验收 A1 到 A7 通过。用户报告的 #92074（v2.1.259）没有复现 | **M0 支持**（见上方范围说明） |
| Windows 11 原生 | Desktop 应用 | 未知 | 未测（用户报告 #95833、#77708，未核实） | 未测 |
| WSL 2 | CLI | Bash | 未验证：本机 WSL 里只有 `docker-desktop` 发行版 | 未验证 |
| macOS / Linux | — | — | 未验证：没有环境 | 未验证 |

## 当前判断

- **引擎层，Windows 原生可行**：hook 在 CLI 引擎里对 PowerShell、Bash、Read、Write 全部触发，exec 形式、退出码与超时语义、拒绝理由回传都符合规格 §5 与 §10 的设计；没有发现需要推翻设计的事实。
- **VS Code 扩展宿主（开发机的日常宿主）里 hook 同样触发**，与 CLI 引擎行为一致。剩下的未知是 Desktop 应用。
- **判断**：Windows 原生在两个已测宿主里引擎层都可行，可以进入 M0；"支持"的声明要等 M0 的验收在对应宿主上通过。
- **必须做进 M0 的防御**（已写入规格 §5.1 与 §10）：hook 客户端按字节读写（否则含中文的事件会被悄悄读成乱码，规则匹配落空；2026-10-07 更正了 M0a 原先"会崩溃"的说法，见 `hook-behavior.md` E18）；stdout 总是 `json.dumps` 生成的合法 JSON（非法 JSON 会被当作无决定）；任何异常都输出 `ask` 并以 0 退出；总超时预算自己实现；`init` 与 `doctor` 按 exec 形式原样启动 hook 命令并校验输出（命令起不来、Store 占位符、`.cmd` 垫片都是静默放行）；注册 `ConfigChange` hook 拦截 `disableAllHooks`。
- 已测的 hook 语义（E1 到 E14）见 `docs/hook-behavior.md`；多数是在 CLI 引擎里测的，VS Code 扩展里测了"是否触发"、payload 形式，以及用户亲自做的界面测试（阻断理由、ask、`/clear`、新目录）。VS Code 里：被阻断的理由显示在弹窗与工具调用卡片里，**hook 出错、超时、崩溃时界面没有任何提示**（所以 `doctor` 与自检是唯一的发现手段），`/clear` 换新 session_id，打开从未打开过的目录没有弹信任对话框。ask 的确认框默认视图里**不显示** hook 的理由（只有命令与模型的描述）；`python.exe -I -S` 的 exec 写法执行时没有控制台窗口闪现（均为一次目视观察）。
- VS Code 扩展会把 IDE 上下文（含选中的文件内容）拼进 `UserPromptSubmit` 的 `prompt`，任务意图提取必须剥离（规格 §9.2）。
- **M0 手工验收的发现**（单次观察，2.1.292）：① 常驻进程不在时，两个宿主都弹出确认框（失败即关闭成立），但框里**不显示** boundkeep 的理由（CLI 三次、VS Code 一次，hook 实际返回了理由），用户看到的是一个没有解释的确认；解释只能靠 `boundkeep doctor` 与审计日志；② 把 hook 命令改成不存在的路径，Claude Code 没有任何提示，而**当前会话里原来的 hook 仍继续生效**（hook 配置在会话启动时固定），新会话才会失效，`doctor` 立刻报 FAIL；③ VS Code 里命令执行时没有看到控制台窗口闪现；④ `doctor` 在会话开始前报告该目录"未标记信任"，之后两个宿主里 hook 都触发了（会话期间是否点过信任对话框没有记录，所以"未信任目录里 hook 是否运行"仍未确定）。
- **不在"支持"范围内**：Git Bash 作为 shell 工具、Desktop 应用、`bypassPermissions` 与 `auto` 权限模式、提升权限（UAC）令牌下的连接、杀毒软件的影响、POSIX 传输、WSL、macOS、Linux。
- 其他平台没有环境，保持"设计目标，未实测"。
