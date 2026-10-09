# M0 手工验收（由你来做）

> 目的：在真实的 Claude Code 里确认 M0 的验收项，自动测试做不到这一步。只有这里每一项都通过的"平台 + 宿主"才能在 `docs/platforms.md` 里写"支持"。
> 约束：只在一次性目录 `E:\bk-lab-m0` 里做；**不要**在本仓库、也不要写用户级的 `~/.claude/settings.json`。boundkeep 自己的状态在 `%USERPROFILE%\.boundkeep\`（日志、策略、端点），验收完可以整个删掉。
> 预期时间：每个宿主约 10 分钟。已有自动化的预演：`uv run python scripts/smoke_claude.py`（用 `claude -p` 在 CLI 引擎里跑过，几美分），结果见 `docs/reports/M0.md`；它不能替代你在 VS Code 界面里的观察。

## 准备（一次）

在 PowerShell 里：

```powershell
cd E:\boundkeep\boundkeep
New-Item -ItemType Directory -Force E:\bk-lab-m0 | Out-Null
uv run boundkeep init --project-dir E:\bk-lab-m0
uv run boundkeep doctor --project-dir E:\bk-lab-m0      # 此时应只有 daemon 一项 [FAIL]：还没启动
```

另开一个 PowerShell 窗口，保持打开：

```powershell
cd E:\boundkeep\boundkeep
uv run boundkeep serve
```

回到第一个窗口再跑一次 `uv run boundkeep doctor --project-dir E:\bk-lab-m0`，现在应该没有 `[FAIL]`（可能有 `[WARN]`，例如工作区信任、托管设置，把它们记下来）。

## 宿主 A：VS Code 扩展

用 VS Code 打开文件夹 `E:\bk-lab-m0`，开一个新的 Claude Code 会话。

| # | 你对 Claude 说 | 应该看到 | 结果 |
|---|---|---|---|
| A1 | `用 PowerShell 执行这条命令：Write-Output BOUNDKEEP_CANARY` | 命令**没有执行**；界面（弹窗或工具调用卡片）里有理由，包含 `M0 canary rule` | |
| A2 | `用 PowerShell 执行：Get-ChildItem` | 正常走 Claude Code 自己的权限流程（可能弹确认框，是 Claude Code 的，不是 boundkeep 的），执行后有输出 | |
| A3 | `用 PowerShell 执行：Write-Output "你好 ✓"` | 同 A2；然后在另一个窗口运行 `uv run boundkeep log --tail 5`，这条命令的文字**原样**出现（中文与 ✓ 没有变成乱码） | |
| A4 | 在 `serve` 的窗口按 Ctrl+C 停掉常驻进程，再让 Claude 执行 `Get-ChildItem` | 弹出**确认框**（失败即关闭：boundkeep 不在就问你）。点开确认框右上角的折叠箭头：看里面有没有 `boundkeep daemon is not running` 的理由，记下有没有 | |
| A5 | 重新 `uv run boundkeep serve`，再执行 A1 | 又被拦截 | |
| A6 | 把 `E:\bk-lab-m0\.claude\settings.json` 里 PreToolUse 的 `command` 改成一个不存在的路径（保存） | 此时 Claude Code **什么提示也不会有**（M0a 实测）。运行 `uv run boundkeep doctor --project-dir E:\bk-lab-m0` 必须报 `[FAIL]` 并给出修复建议 | |
| A7 | 运行 `uv run boundkeep init --project-dir E:\bk-lab-m0` 修好，再 `doctor` | 恢复；之后重新开一个会话再测 A1 | |
| A8 | （可选）命令执行的瞬间留意有没有黑色控制台窗口闪一下 | 记下有没有（默认的 `python.exe -I -S` 写法 M0a 没看到） | |

## 宿主 B：CLI

你终端里的 `claude` 命令是坏的（mise shim 找不到二进制；`claude doctor` 也这么说）。用 VS Code 扩展自带的可执行文件：

```powershell
$claude = (Get-ChildItem "$env:USERPROFILE\.vscode\extensions\anthropic.claude-code-*\resources\native-binary\claude.exe" | Select-Object -Last 1).FullName
cd E:\bk-lab-m0
& $claude        # 交互式会话；在里面重复 A1、A2、A4 的内容
```

| # | 内容 | 应该看到 | 结果 |
|---|---|---|---|
| B1 | 同 A1 | 被拦截，终端里能看到理由 | |
| B2 | 同 A2 | 正常 | |
| B3 | 同 A4（停掉 `serve` 后） | 终端里出现确认提示（再看有没有 boundkeep 的理由） | |

## 收尾

```powershell
cd E:\boundkeep\boundkeep
uv run boundkeep uninstall --project-dir E:\bk-lab-m0
# 想清掉 boundkeep 的状态：删除 %USERPROFILE%\.boundkeep 与 E:\bk-lab-m0
```

把两张表的"结果"列（通过 / 失败 + 你看到的原话）告诉我；A4、B3 里"确认框里有没有理由"和 A8 是 M0a 留下的未确认项，请如实记下。

## 验收记录（2026-10-08，由你执行，原话整理）

环境：Windows 11、VS Code 扩展 2.1.292、同一个扩展自带的 CLI 2.1.292（交互式，shell 工具是 PowerShell）、目录 `E:\bk-lab-m0`、常驻进程用 `uv run boundkeep serve`。

宿主 A：VS Code 扩展

| # | 结果 |
|---|---|
| A1 | **通过**。命令未执行，提示 `boundkeep: blocked (M0 canary rule: the command contains BOUNDKEEP_CANARY)`；审计日志里有对应的 `deny` |
| A2 | **通过**。`Get-ChildItem` 正常执行并有输出（你没有看到弹窗，所以不知道有没有弹 Claude Code 自己的确认框） |
| A3 | **通过**。`你好 ✓` 正常输出；`boundkeep log` 里命令文字原样，中文与 ✓ 没有乱码 |
| A4 | **通过，但有一个产品问题**。常驻进程停掉后 `Get-ChildItem` 弹出了 "Allow this PowerShell command?" 确认框，失败即关闭成立；框展开后里面**没有** `boundkeep daemon is not running`，也没有任何 boundkeep 字样，只有命令与模型写的说明。hook 本身返回了这句理由（直接调用 hook_client 验证过），是 VS Code 扩展没有在确认框里显示它 |
| A5 | **通过**。重启常驻进程后 A1 又被拦截 |
| A6 | **通过**。PreToolUse 的 `command` 改成不存在的路径后 Claude Code 没有任何提示；`doctor` 报 2 个 `[FAIL]`、退出码 1，并附 `fix: run 'boundkeep init'`。补充：改坏之后，**本会话里 canary 仍被拦**，说明 hook 配置在会话启动时已固定、不热加载 |
| A7 | **通过**。`init` 修复后 `doctor` 恢复，0 problem；新开的会话里 A1 被拦截（有截图，日志里有对应的 `deny`） |
| A8 | **没有看到黑色控制台窗口闪一下**（一次目视观察；默认的 `python.exe -I -S` 写法） |

宿主 B：CLI（交互式）

| # | 结果 |
|---|---|
| B1 | **通过**。命令没有执行，报错 `PreToolUse:PowerShell hook error: boundkeep: blocked (M0 canary rule: …)`，理由在终端里可见；审计日志里有 `deny` |
| B2 | **通过**。`Get-ChildItem` 正常执行；日志记为 `none` |
| B3 | **通过**。停掉常驻进程后出现了确认提示（失败即关闭成立）；确认提示里**没有** boundkeep 的理由（你肉眼核对；hook 实际返回了 `boundkeep daemon is not running; start it with 'boundkeep serve'`，Claude Code 界面没有展示它）。共测三次，结果一致。注：这次是用 `taskkill /T /F` 杀的常驻进程，不等同于 Ctrl+C |

收尾：`uninstall` 报 `E:\bk-lab-m0\.claude\settings.json does not exist; nothing to remove`（条目在之前的步骤里已经没有了）。`doctor` 的两个 `[WARN]`：目录未标记信任（见 `docs/platforms.md`）、PATH 上的 `claude` shim 不能运行（M0a 起的老问题）。

