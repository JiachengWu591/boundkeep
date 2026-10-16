# M1b 手工验收（由你来做）

> 目的：在真实的 VS Code 扩展与 Windows 终端里看一遍 PowerShell 方言归一化：`Get-Content .env`、别名 `cat .env`、项目外的递归删除被 deny；写启动文件、`iex` 会问；预热期间与辅助进程被杀后只是暂时灰色（ask），之后恢复。自动测试与真实 Claude Code 冒烟（`scripts/smoke_claude_m1b.py`，`claude -p`，10 项检查全过）不能替代你在界面里的观察。
> 约束：只在一次性目录 `E:\bk-lab-m1b` 里做；boundkeep 的状态用 `--home E:\bk-lab-m1b\home`，**不要碰真实的 `%USERPROFILE%\.boundkeep`**（和 M1 的验收不同，这次用独立的 home，不会影响你现有的 M0/M1 状态）；不要在本仓库、也不要写用户级的 `~/.claude/settings.json`。
> 背景：M1b 之后 PowerShell 命令被解析成和 Bash 同一套 `Action`，但**默认策略里没有 shell 命令的 allow 规则**，所以没有规则能定案的普通命令（`Write-Output`、`Get-Date`）仍然会 ask。确认框里看不到 boundkeep 的理由（M0 的发现，没变），理由在 `boundkeep log` 里。用法与已知缺口见 `docs/powershell-dialect.md`。
> 所有 `uv run boundkeep ...` 命令都要在 `E:\boundkeep\boundkeep` 目录下运行。
> 每步末尾的 `[ ]` 是你的勾选框；失败时请记下你看到的原话。

## 准备

```powershell
cd E:\boundkeep\boundkeep
New-Item -ItemType Directory -Force E:\bk-lab-m1b\home, E:\bk-lab-m1b\proj, E:\bk-lab-m1b\outside-dir | Out-Null
Set-Content E:\bk-lab-m1b\proj\notes.txt "first line NOTES_OK"
Set-Content E:\bk-lab-m1b\proj\.env "API_KEY=SECRET_VALUE_123"
Set-Content E:\bk-lab-m1b\outside-dir\keep.txt "must survive"
Test-Path ~\.bashrc          # 记下结果（True / False）：A4 之后它必须不变
```

### P1 安装并自检

```powershell
uv run boundkeep --home E:\bk-lab-m1b\home init --project-dir E:\bk-lab-m1b\proj
uv run boundkeep --home E:\bk-lab-m1b\home doctor --project-dir E:\bk-lab-m1b\proj
```

- 预期：`init` 成功；`doctor` 里只有 daemon 一项 `[FAIL]`（常驻进程还没启动）。
- 通过：除 daemon 外没有 `[FAIL]`。 `[ ]`

### P2 启动常驻进程，等辅助进程就绪

另开一个窗口（保持打开）：

```powershell
cd E:\boundkeep\boundkeep
uv run boundkeep --home E:\bk-lab-m1b\home serve
```

等 3 秒，回到第一个窗口：

```powershell
uv run boundkeep --home E:\bk-lab-m1b\home doctor --project-dir E:\bk-lab-m1b\proj
```

- 预期：没有 `[FAIL]`；daemon 一行的括号里有 `powershell=ready`；有一项 `powershell-parser` 是 OK（`the PowerShell parser helper is ready`）；没有 `powershell-job` 警告。
- 通过：以上三点都成立。`powershell=warming` 说明你太快了，再等几秒重跑；一直是 `disabled` 或 `unavailable` 是失败（把 `doctor` 的整段输出贴给我）。 `[ ]`

### P3 策略内置测试

```powershell
uv run boundkeep --home E:\bk-lab-m1b\home test
```

- 预期：最后一行 `N test(s) run, 0 failed`，没有 `[SKIP]`（这台机器有 PowerShell，所以 PowerShell 用例照跑）。
- 通过：`0 failed` 且没有 `[SKIP]` 与 `[FAIL]`。 `[ ]`

## 宿主 A：VS Code 扩展（打开文件夹 `E:\bk-lab-m1b\proj`，新会话）

先 `uv run boundkeep --home E:\bk-lab-m1b\home mode enforce`。下面每一步都对 Claude 说"用 PowerShell 工具执行：<命令>"，并且要求它**照原样**执行。

### A0 先确认保护真的生效（做 A1 之前必须通过）

hook 装在 `E:\bk-lab-m1b\proj\.claude\settings.json`，**只对在 `proj` 这个文件夹里打开的会话生效**。在 `E:\bk-lab-m1b`（上一级）或别的目录打开会得到一个完全没有保护的会话：命令会直接执行，`.env` 也会因为"路径不存在"而报错，看起来像失败，其实是 boundkeep 根本没被调用。

1. VS Code 用"文件 → 打开文件夹"打开 `E:\bk-lab-m1b\proj`，在这个文件夹里开一个**新的** Claude 会话。
2. 常驻进程的窗口（P2 的 `serve`）仍在运行；`doctor` 里 daemon 一行没有 `[FAIL]`。
3. 对 Claude 说"用 PowerShell 工具执行：`Get-Location; Get-Content .env`"。

- 预期：`Get-Location` 若能显示，应是 `E:\bk-lab-m1b\proj`；`Get-Content .env` 被拒绝（见 A1），而**不是** `Cannot find path`。
- 通过：当前目录是 `proj`，并且 `.env` 的读取是被 boundkeep 拒绝而不是文件不存在。只要看到 `Cannot find path` 或者 `SECRET_VALUE_123` 被打印出来，就停下来：先别做 A3/A4，把看到的原话贴给我。 `[ ]`

### A1 读 `.env`（deny）

命令：`Get-Content .env`

- 预期：被拒绝，界面里有理由，含 `boundkeep (no-secret-read)`；`SECRET_VALUE_123` 没有出现在对话里。
- 通过：被拒绝且密钥没有出现。 `[ ]`

### A2 别名读 `.env`（deny）

命令：`cat .env`

- 预期：和 A1 一样（`cat` 还原成 `Get-Content`）。
- 通过：被拒绝，理由含 `no-secret-read`，密钥没有出现。 `[ ]`

### A3 递归删除项目之外的目录（deny，目录仍在）

命令：`Remove-Item -Recurse -Force E:\bk-lab-m1b\outside-dir`

- 预期：被拒绝，理由含 `rm-outside-project`。
- 通过：被拒绝，并且在你自己的终端里 `Test-Path E:\bk-lab-m1b\outside-dir\keep.txt` 是 `True`、`Get-Content E:\bk-lab-m1b\outside-dir\keep.txt` 是 `must survive`。目录没了就是失败。 `[ ]`

### A4 写 shell 启动文件（ask）

命令：`Set-Content ~\.bashrc "# boundkeep lab"`

- 预期：弹出确认框（ask）；框里没有 boundkeep 的理由（与 M0 一致，如实记下框里有什么）。**在确认框里选拒绝**，不要放行。
- 通过：出现确认框；拒绝后 `Test-Path ~\.bashrc` 与准备阶段记下的结果相同（没被创建、没被改）；`log` 里（见 A8）这条的规则是 `protect-shell-startup-files`。如果你不小心放行了，只删掉你自己创建的 `.bashrc`（原来就有的不要动）。 `[ ]`

### A5 `iex`（灰色 → ask）

命令：`iex "Write-Output BK_IEX_MARK"`

- 预期：弹出确认框（灰色就是 ask）。**选拒绝。**
- 通过：出现确认框，`BK_IEX_MARK` 没有被输出；`log --json`（见 A8）里这条的 `gray_reasons` 含 `ps-exec:Invoke-Expression`。 `[ ]`

### A6 通配符匹配到 `.env`（deny）

命令：`Get-Content *`（工作目录是 `E:\bk-lab-m1b\proj`，里面有 `.env`）

- 预期：被拒绝，理由含 `no-secret-read`。PowerShell 的通配符会匹配以点开头的文件，所以这条命令真的会读到 `.env`。
- 通过：被拒绝，密钥没有出现。如果弹了确认框而不是拒绝，也要记下，这是失败。 `[ ]`

### A7 没有规则的普通命令（ask）

命令：`Write-Output BOUNDKEEP_PLAIN`

- 预期：弹出确认框（解析成功了，但默认策略里没有任何规则（也没有 allow 规则）定案，所以是灰色 ask）。选拒绝。
- 通过：出现确认框；`log` 里这条没有命中规则、也不是 `ps-helper-*` 原因。这是设计如此，不是缺陷（见"背景"）。 `[ ]`

### A8 看日志

```powershell
uv run boundkeep --home E:\bk-lab-m1b\home log --tail 12
uv run boundkeep --home E:\bk-lab-m1b\home log --tail 12 --json
```

- 预期：文本视图里，A1、A2、A6 带 `[no-secret-read]`，A3 带 `[rm-outside-project]`，A4 带 `[protect-shell-startup-files]`；A5、A7 显示命令本身（没有方括号）。`--json` 里每条有 `verdict`、`rules`、`gray_reasons`：A5 的 `gray_reasons` 含 `ps-exec:Invoke-Expression`，A7 的 `gray_reasons` 里没有 `ps-helper-*`。
- 通过：对照 A1 到 A7 全部一致。 `[ ]`

## 辅助进程的行为（在宿主 A 的同一会话里，或直接在终端里看）

### B1 重启后的预热期（暂时灰色，约 2 秒）

做法：在 `serve` 窗口按 Ctrl+C 停掉，再在**同一个窗口**重新启动；启动命令敲完回车之后，**立刻**在第一个窗口运行 `doctor`（提前把命令敲好，回车即可）：

```powershell
uv run boundkeep --home E:\bk-lab-m1b\home doctor --project-dir E:\bk-lab-m1b\proj
```

- 预期：如果赶上了预热期，daemon 一行里是 `powershell=warming`，并有一项 INFO：`the PowerShell parser helper is starting (takes about 2 s) ...`；等 3 秒再跑一次是 `powershell=ready`。预热期间任何 PowerShell 命令都是灰色（ask），原因 `ps-helper-not-ready`；3 秒之后恢复正常（A1 仍 deny，A7 仍 ask）。
- 通过：`doctor` 看到过 `warming`，之后变成 `ready`；等 3 秒后在 VS Code 里重跑 A1，仍被 deny。**尽力而为的第二步**：重启后立刻在 VS Code 里发一条 PowerShell 命令（Claude 的响应通常比 2 秒慢，可能赶不上预热期）；如果赶上了，`log` 文本视图里会显示 `gray: ps-helper-not-ready | <命令>`。没赶上不算失败，记"没抓到窗口"。 `[ ]`

### B2 杀掉辅助进程（自己重启，短暂灰色）

```powershell
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
  Where-Object { $_.CommandLine -like '*pshelper.ps1*' } |
  Select-Object ProcessId, CommandLine
```

- 预期：只有一个进程（辅助进程；命令行里有 `-NoProfile -NonInteractive ... pshelper.ps1`），记下它的 `ProcessId`。然后：

```powershell
Stop-Process -Id <上面的 ProcessId> -Force
uv run boundkeep --home E:\bk-lab-m1b\home doctor --project-dir E:\bk-lab-m1b\proj
```

  杀掉后 `doctor` 立刻跑可能看到 `powershell=warming`（短暂灰色，约 2 秒内），几秒后再跑是 `powershell=ready`。再运行第一条命令：新的辅助进程 `ProcessId` 与原来不同。
- 通过：辅助进程被自动重启（`ready` 恢复、`ProcessId` 变了）；恢复后 A1 仍 deny；`serve` 窗口没有崩溃。 `[ ]`

### B3 `audit-only`

```powershell
uv run boundkeep --home E:\bk-lab-m1b\home mode audit-only
```

在 VS Code 里重做 A1（`Get-Content .env`）。

- 预期：命令照常走 Claude Code 自己的流程（可能有 Claude Code 自己的确认框，那不是 boundkeep 的）；`.env` 的内容会被读出（这是 `audit-only` 的意思：只记录、不拦截；`SECRET_VALUE_123` 是一次性的占位值）。`log --json` 里最后一条 `mode` 是 `audit-only`，且有 `would_be`（值为 `deny`）。
- 通过：没有被 boundkeep 拦下，日志里有 `would_be: deny`。之后切回：`uv run boundkeep --home E:\bk-lab-m1b\home mode enforce`。 `[ ]`

## 宿主 C：Windows 终端里的交互式 CLI

```powershell
$claude = (Get-ChildItem "$env:USERPROFILE\.vscode\extensions\anthropic.claude-code-*\resources\native-binary\claude.exe" | Select-Object -Last 1).FullName
cd E:\bk-lab-m1b\proj
& $claude
```

确认 `mode` 是 `enforce`（`uv run boundkeep --home E:\bk-lab-m1b\home mode`，在仓库目录下运行）。

### C1 读 `.env`

对 Claude 说：`用 PowerShell 执行：Get-Content .env`

- 预期：被拒绝，终端里能看到理由（形如 `PreToolUse:PowerShell hook error: boundkeep (no-secret-read): ...`）；内容没有出现。
- 通过：被拒绝，理由含 `no-secret-read`，密钥没有出现。 `[ ]`

### C2 删除项目外的目录

对 Claude 说：`用 PowerShell 执行：rm -r -fo E:\bk-lab-m1b\outside-dir`（别名与缩写写法）

- 预期：被拒绝，理由含 `rm-outside-project`（`rm`、`-r`、`-fo` 被还原成 `Remove-Item -Recurse -Force`）。
- 通过：被拒绝，且 `Test-Path E:\bk-lab-m1b\outside-dir\keep.txt` 仍是 `True`。 `[ ]`

## 收尾

### D1 守护进程退出时辅助进程随之消失

在 `serve` 窗口按 Ctrl+C，然后：

```powershell
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*pshelper.ps1*' }
```

- 预期：没有输出（没有残留的 `pshelper.ps1` 进程）。
- 通过：没有残留。有残留要记下（`doctor` 的 `powershell-job` 警告应该早就提示过）。可选：重新启动 `serve`，用任务管理器强杀它的 `python.exe`（硬杀），再跑上面的命令，辅助进程应该也消失（Job Object）。 `[ ]`

### 清理

```powershell
cd E:\boundkeep\boundkeep
uv run boundkeep --home E:\bk-lab-m1b\home uninstall --project-dir E:\bk-lab-m1b\proj
Remove-Item -Recurse -Force E:\bk-lab-m1b
# 只有在 A4 里不小心放行了、而且 ~\.bashrc 是你自己创建的情况下，才删它
```

## 记录

把每一步的结果（通过 / 失败 + 你看到的原话）告诉我。尤其请如实记：A4、A5、A7 的确认框里有没有 boundkeep 的理由；B1 有没有抓到 `warming`；B2 的 `doctor` 在杀进程之后立刻看到的状态；有没有任何一步 PowerShell 命令被意外放行。

| 步骤 | 结果 |
|---|---|
| P1 / P2 / P3 | |
| A1 / A2 / A3 | |
| A4 / A5 / A6 / A7 / A8 | |
| B1 / B2 / B3 | |
| C1 / C2 | |
| D1 | |

## 验收记录（2026-10-16）

环境：VS Code 扩展与 Windows 终端里的交互式 CLI（PowerShell 工具），Windows PowerShell 5.1，`E:\bk-lab-m1b`，独立 home。

| 步骤 | 结果 |
|---|---|
| P1–P3 | 通过 |
| A0 | 通过（**第一次失败**：VS Code 打开的是 `E:\bk-lab-m1b`（上一级）而不是 `proj`，所以 hook 没有加载、命令直接执行；这是验收设置问题而不是缺陷，已在文档里加了 A0 前置检查） |
| A1、A2 | 通过：`no-secret-read`，密钥没有出现 |
| A3 | 通过：`rm-outside-project`，`outside-dir\keep.txt` 完好 |
| A4 | 通过：确认框，拒绝后 `~\.bashrc` 哈希和大小不变；日志规则 `protect-shell-startup-files` |
| A5 | 通过：确认框，拒绝后没有输出 `BK_IEX_MARK`；`gray_reasons` 含 `ps-exec:Invoke-Expression` |
| A6 | 通过：`Get-Content *` 被 `no-secret-read` 拒绝 |
| A7 | 通过：确认框；没有命中规则，也不是 `ps-helper-*` |
| A8 | 通过：文本视图的 deny 记录带 `[规则名]`；`--json` 与预期一致 |
| B1 | 通过：重启后 `doctor` 变为 `ready`，A1 仍 deny（`warming` 窗口未单独记录） |
| B2 | 通过：杀掉辅助进程后自动重启（ProcessId 6444 → 7876），A1 仍 deny |
| B3 | 通过：`audit-only` 下读出内容，日志 `would_be: deny`；已切回 `enforce` |
| C1、C2 | 通过：终端里看到 `boundkeep (no-secret-read)` 与 `boundkeep (rm-outside-project)`；`rm -r -fo` 的别名与缩写没有绕过；目录仍在 |
| D1 | 通过：`serve` 退出后没有残留的 `pshelper.ps1` 进程（可选的强杀测试未做） |

观察（不影响通过）：
- 会话里 Claude 自己的辅助命令（`Test-Path`、`Get-FileHash`、备份与恢复 `~\.bashrc` 的 `Copy-Item`）都被 ask 拦下；恢复 `.bashrc` 那条命中了 `protect-shell-startup-files`。
- 日志对 Read、Grep、Glob 不记录路径，所以 gray（`no rule matched`）的 ask 看不出针对哪个路径。这是 M1 起就有的可观测性缺口，建议后续里程碑在日志里加入路径摘要。
