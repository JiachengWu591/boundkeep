# experiments/：M0a 的可重复实验

对应提示词 M0a。目的：把 Claude Code 的 hook 行为变成"已验证事实"（结果见 `docs/hook-behavior.md`、`docs/platforms.md`、`docs/related-work.md`）。

| 文件 | 作用 |
|---|---|
| `probe_hook.py` | 观察用 hook（仅标准库）：记录原始事件，默认退出码 0、不输出；带总开关与测试标记（BK_EXIT1 / EXIT2 / DENY / ASK / ALLOW / SLEEP / NAIVE / CTX / UPS_CTX）；日志里不记录环境变量的值 |
| `fail_hook.py` | "坏 hook"：非法 JSON、非 UTF-8 输出、各种退出码、不读 stdin 等 |
| `mcp_echo_server.py` | 最小 MCP stdio 服务（E5 / E13） |
| `lab_setup.py` | 在仓库之外建一次性实验目录并写项目级 hook 配置；`--profile base / matchers / e11 / e12 / fail / e14`；不动用户级 settings |
| `run_cli_probe.py` | 用 `claude -p` 触发工具调用（极短提示词、最便宜的模型、设花费上限；子进程环境清除所有 `CLAUDE*` 变量；记录每条输出的到达时刻） |
| `run_failmodes.py` | 逐个坏 hook 模式跑一轮（E6 / E16 / E22） |
| `e12_midflight.py` | 会话中途改 `settings.local.json`，看 `ConfigChange` 与 hook 是否继续（E12） |
| `make_launcher.py` | 用 pip 自带的 distlib 生成 `.exe` 启动器（E10 / E16） |
| `ipc_pipe_server.py`、`ipc_pipe_client.py` | 命名管道服务端 / hook 形状客户端原型（ctypes、显式 DACL、多实例；M0 的前身） |
| `ipc_pipe_server_asyncio.py` | 基线：asyncio 的 `start_serving_pipe` 服务端（默认 DACL、单个待连接实例） |
| `bench_hook_cold_start.py`、`analyze_latency.py` | E10 的冷启动、管道往返、每次工具调用的耗时 |
| `bench_pipe_concurrency.py` | E10 的命名管道并发原型基准：不重试 / 重试、实例池大小、DACL；输出的 SID 与账户名已脱敏 |
| `probe_env_windows.ps1`、`probe_paths_windows.py` | E20 / E21 的本地只读探针 |
| `analyze_events.py` | 汇总 `raw/events.jsonl`：每次运行、每个宿主收到了哪些事件 |
| `make_evidence.py`、`summarize_m0a.py` | 从 `raw/` 生成脱敏证据到 `evidence/` |
| `make_fixtures.py` | 从 `raw/` 生成脱敏的事件夹具到 `tests/fixtures/hook_events/windows/` |
| `raw/` | 未脱敏的原始记录，**被 git 忽略，绝不提交** |
| `evidence/`、夹具 | 脱敏结果；经确认后才可提交 |

## 前提

已登录的 Claude Code；`run_cli_probe.py` 默认使用 VS Code 扩展自带的可执行文件，找不到时用 PATH 上的 `claude`，也可以用 `--claude` 指定。每次运行约几十秒、花费约 0.01 到 0.06 美元（全部 60 次约 1.4 美元）。想让观察用 hook 立刻停手：在 `experiments/raw/` 里建一个名为 `OFF` 的空文件。

## 复现（PowerShell，仓库根目录）

```powershell
# E15 / E6 / E18：基线、标记命令、去掉 PYTHON* 环境变量、指定 Git Bash
python experiments\lab_setup.py --profile base --lab E:\bk-lab
python experiments\run_cli_probe.py --name a_cli --prompt E:\bk-lab\prompts\prompt_a.txt --lab E:\bk-lab
python experiments\run_cli_probe.py --name b_cli --prompt E:\bk-lab\prompts\prompt_b.txt --lab E:\bk-lab
python experiments\run_cli_probe.py --name c_cli_noenv --prompt E:\bk-lab\prompts\prompt_a.txt --lab E:\bk-lab --drop-python-env
python experiments\run_cli_probe.py --name d_cli_gitbash --prompt E:\bk-lab\prompts\prompt_d.txt --lab E:\bk-lab `
  --extra-env "CLAUDE_CODE_GIT_BASH_PATH=<你的 Git Bash 路径>" --allow "Bash(echo *)" --allow "Bash(pwd)"

# E4、E13（子 agent 与 @ 引用）
python experiments\run_cli_probe.py --name e4_ctx --prompt E:\bk-lab\prompts\prompt_e4.txt --lab E:\bk-lab
python experiments\run_cli_probe.py --name e13_cli --prompt E:\bk-lab\prompts\prompt_e13.txt --lab E:\bk-lab --allow Task

# E5 / E3 / E13（matcher 矩阵、全部工具类型、MCP）
python experiments\lab_setup.py --profile matchers --lab E:\bk-lab-matchers
python experiments\run_cli_probe.py --name m_cli --prompt E:\bk-lab-matchers\prompts\prompt_m.txt --lab E:\bk-lab-matchers `
  --allow Edit --allow Glob --allow Grep --allow WebFetch --allow mcp__bkmcp__echo `
  --arg=--mcp-config --arg=E:\bk-lab-matchers\mcp.json --arg=--strict-mcp-config

# E11（allow 语义、权限模式）
python experiments\lab_setup.py --profile e11 --lab E:\bk-lab-e11
python experiments\run_cli_probe.py --name e11_allow_b --prompt E:\bk-lab-e11\prompts\prompt_e11b.txt --lab E:\bk-lab-e11 --no-default-allow
#   模式：对 manual / acceptEdits / plan / dontAsk / auto 各跑一次 prompt_e11_modes.txt，加 --arg=--permission-mode --arg=<模式>

# E12（disableAllHooks、会话中途改配置、ConfigChange 拦截）
python experiments\lab_setup.py --profile e12 --lab E:\bk-lab-e12 [--cfg-block]
python experiments\e12_midflight.py

# E6 / E16 / E22（23 种坏 hook）
python experiments\run_failmodes.py

# E14（prompt / agent hook）
python experiments\lab_setup.py --profile e14 --lab E:\bk-lab-e14 --hooktype prompt [--cob]   # 或 --hooktype agent

# E10（冷启动与每次工具调用的耗时）
python experiments\bench_hook_cold_start.py 60
python experiments\bench_pipe_concurrency.py --threads 4 --per 50 --out experiments\evidence\pipe_concurrency_4x50.json
python experiments\bench_pipe_concurrency.py --threads 32 --per 20 --out experiments\evidence\pipe_concurrency_32x20.json
#   每次工具调用：prompt_lat.txt 在"有 hook"与"--arg=--settings --arg=<含 disableAllHooks 的文件>"下各跑两轮，再 analyze_latency.py

# E20 / E21（本地只读）
powershell -NoProfile -ExecutionPolicy Bypass -File experiments\probe_env_windows.ps1
python experiments\probe_paths_windows.py

# 汇总与脱敏证据、夹具
python experiments\analyze_events.py --paths
python experiments\make_evidence.py
python experiments\summarize_m0a.py
python experiments\make_fixtures.py
```

## 需要界面操作的部分

见 `E:\bk-lab\README_VSCODE.md`（hook 触发）与 `E:\bk-lab\README_VSCODE_UI.md`（用户能看到什么、`/clear`、未接受信任时 hook 是否运行）。做完后运行 `python experiments\analyze_events.py --paths`，没有 `BK_RUN` 的那一组、`entrypoint=claude-vscode` 的记录就是扩展宿主里的 hook。没有任何记录也是结论。

## 清理

`E:\bk-lab*` 与 `experiments/raw/` 都可以直接删除。
