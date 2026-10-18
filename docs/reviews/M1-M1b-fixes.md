# M1 + M1b 安全审查的修复记录

对应审查：`docs/reviews/M1-M1b-security-review.md`（HEAD `5453af0`，标签 `m1b-done`）。本文记录第一轮修复做了什么、没做什么、付出了什么代价，以及需要你批准的规格变更提议。

## 1. 范围

按审查报告自己的优先级：

- **进 M2 之前必须修**：H-1、H-2、H-3（只做最低限度）、M-3。
- **进 M3 之前必须修**：M-1、M-4、M-5、M-6、M-8、M-9、M-10、M-11、M-12。
- **本轮没做**（报告把它们列在 M2 评测清单里）：M-2、M-7、M-13，以及 L-1 到 L-18（个别顺手修的在下面注明）。

每一条都先用失败测试复现，再修复；复现不了的会说明。五个修复者按文件归属并行，互不修改对方的文件。

## 2. 逐条对照

| 编号 | 状态 | 做了什么 | 没做 / 残留 |
|---|---|---|---|
| **H-1** 目录目标的 Grep/Glob 被 allow | 已修 | 新模块 `normalize/subtree.py`：对目录目标做有界的广度优先遍历（`os.scandir`，不跟随链接/联接点），把命中策略读保护 glob 的文件作为读路径交给规则；Grep 的 `glob`/`type` 与 Glob 的 `pattern` 用来缩小范围；受保护 glob 由 `pipeline.protected_read_globs(policy)` 从已加载的策略里取。预算 3 万个条目 / 0.2 秒，超出则灰色 `recursive-scan-budget`，目录读不了则灰色 `recursive-scan-unreadable`。**不按目录名跳过任何目录**（攻击者可以自己建 `node_modules`）。真实 Claude Code 冒烟：对项目目录 Grep、不带 glob，`.env` 被拒绝，密钥没有返回 | 见第 3 节的可用性代价 |
| **H-2** 同用户进程冒充守护进程 | 已修（两项） | ① 客户端默认不再输出 `allow`：守护进程回答 `allow` 时按"无决定"处理，只有 hook 参数里带 `--emit-allow` 才放行；`init` 在策略 `defaults.emit_allow` 打开时写入该参数，`doctor` 检查两者是否一致。`ask`/`deny` 始终有效，冒充者只能收紧。② 管道实例创建完后收紧 DACL，去掉"创建新实例"的权限，同一用户也不能再建同名实例（实测第二次 `CreateNamedPipeW` 返回错误 5，对照组可以）；`serve` 在收紧失败时拒绝启动 | **③ 客户端校验服务端进程 ID 没做**：标准库没有 `GetNamedPipeServerProcessId`，需要在快速客户端里加 ctypes，且重启时序有误报风险。残留风险：同用户进程在守护进程启动**之前**占住管道名（此时 `serve` 会响亮失败，客户端也会忽略它回答的 `allow`） |
| **H-3** 在别处打开会话时没有任何告警 | 已修（最低限度） | `init` 项目级安装时打印醒目提示"只对在 `<路径>` 里打开的会话生效，其他目录没有任何 hook，Claude Code 也不会警告；要对所有目录生效用 `--scope user`"；`doctor` 不带 `--project-dir` 时明确说明检查的是哪个目录（新增 `scope` 检查，项目级安装为 WARN）；`check_workspace_trust` 现在尊重 `CLAUDE_CONFIG_DIR` | **没有加 SessionStart hook**（报告自己说可放进 M2 第一批）。`check_activity` 仍是 INFO：在错误目录里开的会话不会运行任何 hook，也不会留下日志，别的目录里的事件也证明不了这个项目，所以 WARN 不可靠。`CLAUDE_CONFIG_DIR` 下 `.claude.json` 的位置是凭记忆写的，没有验证 |
| **M-1** 预算耗尽丢掉 deny | 已修 | 预算触发后，触发的命令和之后的命令继续做**纯词法**分类（不展开通配符、不查磁盘、不遍历），`cd` 跟踪保留，仍追加灰色 `budget:*` 标记，所以永远不会是 allow；磁盘查询预算与通配符预算拆开（`MAX_GLOB_DISK_KEYS` 256 与 `MAX_DISK_KEYS` 64） | 一行里**不同**的命令超过约 1300 条时，尾部仍会被丢，结果是灰色，不是 allow |
| **M-3** `_fail_safe` 读错参数位置 | 已修 | 新增 `_find_sub()`，跳过 `--home <值>`、`--emit-allow` 与未知 `--flag` 再找子命令；`sys.path.insert(0, …)` 改成 `append`（`-I -S` 下包根里的 `json.py` 不能再遮蔽标准库）。回归测试覆盖 config/pre/post/prompt 与五种参数布局 | — |
| **M-4** 守闸门自己的代码没有保护 | 已修 | 运行时规则（`pipeline.py`）`protect-guard-code`：已安装的包目录（含 hook 脚本与策略文件）、`sys.executable` 与基础解释器、`boundkeep-hook`、`installs.json` 记录的解释器、boundkeep home；`protect-guard-dirs`：`**/.claude`、`**/.boundkeep`、boundkeep home、`CLAUDE_CONFIG_DIR` 目录本身（写、删、改名、移动）。YAML 里 `protect-guard-config` 补了 `**/.claude`、`~/.claude`、`managed-settings*`，`ask-agent-exec-config`（strict 为 deny）补了 `.claude/rules|output-styles|statusline.*|plugins/**`。完整性：`init` 把 hook 解释器、`hook_client.py`、`hook_main.py` 的 sha256 记入 `installs.json`（`hook_files`），`doctor` 不一致即 FAIL，守护进程启动时校验并记一条 `integrity-warning`（只警告、不拒绝启动） | L-11 中其余的持久化路径（`package.json`、`Makefile`、`pyproject.toml` 等）没做 |
| **M-5** boundkeep 自己的命令行只有 gray | 已修 | `boundkeep` 的 `mode`/`uninstall`/`init`/`serve` 子命令、`--reset-policy`/`--purge`/`--python`/`--hook-style`/`--rotate-endpoint`/`--home` 开关、`boundkeep-hook` 一律 deny；其余 boundkeep 命令 ask；`claude …` 一律 ask（strict 对 `--settings`/`--permission-mode`/`--dangerously-skip-permissions` deny）；杀进程类（`taskkill`/`pkill`/`killall`/`kill`/`Stop-Process`/`Stop-Service`）ask；`pip|pipx|python -m pip uninstall` ask（strict deny）。`programs.py` 现在给 `boundkeep` 报出子命令，`python -m boundkeep …` 归一成 `boundkeep`，`uv run`/`uvx`/`pipx run`/`poetry run` 解包（带包装标记，allow 规则永不匹配） | 规则语言没有"位置参数"匹配，所以 `pip uninstall boundkeep` 与 `taskkill /IM python.exe` 无法只针对目标，只能对整个程序 ask；`claude config` 是子命令不是开关，只能对整个 `claude` ask；不认识的运行器选项（如 `uv run --weird`）保持灰色 |
| **M-6** ConfigChange 与 `init` 对削弱闸门的配置不够严 | 已修 | 新增 `claude_settings.assess_settings`/`blocking_reasons`/`watched_fingerprints`：`bypassPermissions`、`skipDangerousModePermissionPrompt`、笼统的 allow（`Bash(*)`、`PowerShell(*)`、`Write(*)` 等）、高风险环境变量名（`PATH`、`PATHEXT`、`COMSPEC`、`PSModulePath`、`NODE_OPTIONS`、`CLAUDE_CODE_GIT_BASH_PATH`、`CLAUDE_PROJECT_DIR`、`PYTHON*` 等）、拼错的事件名 / 错位的顶层键 → ConfigChange 阻断；会执行命令的键（`statusLine`、`apiKeyHelper` 等）与外来 `PreToolUse` hook 用 `init` 记录的哈希基线判断变化（ConfigChange 事件不带差异，不能一律阻断）；`init` 对 `disableAllHooks`、会重定向 home 的 `env` 拒绝（rc 1，不写文件，`--dry-run` 同样），对其余项大声警告，并检查其他层；`doctor` 对**所有**层做同一组检查（BOM 在含我们 hook 的层里现为 FAIL）。ConfigChange 的接线在 `hook_main.config_violation`，有回归测试 | Claude Code 对这些键的真实行为没有测过，所有文字都写"可能削弱"；阻断 `PATH`/`NODE_OPTIONS` 这类变量会误伤合法用法 |
| **M-8** 消费型程序把凭据当"只写" | 已修 | gzip/bzip2/xz/zstd/lz4、`git mv|add|rm|update-index|checkout-index|commit|stash push`、`rsync --remove-source-files` 的源操作数改成 `unknown`（可能读也可能写）；`git mv .env x`、`gzip -k .env` 等现在 deny，`git mv a.py b.py` 保持灰色 | — |
| **M-9** 递归读取祖先目录与 `rev:path` | 已修 | `CmdInfo.recursive`：`grep -r`、`rg/ag/ack`、`tar` 创建、`zip -r`、`7z a`、`cp -r`、`rsync -a`、`find -exec`、`ls -R`、`git grep|archive|log -p|show|stash show -p`、`Compress-Archive`、`Get-ChildItem -Recurse`、`xcopy /s`、`robocopy` 对目录操作数用 H-1 的同一遍历；`git show HEAD:.env`、`git cat-file -p HEAD:.env`、`git show :.env`、`git archive HEAD .env`、`git diff A:.env B:.env`、`git log -L 1,5:.env` 解析 `rev:path` 后现为 deny | `git diff`、`git format-patch` 没标成递归；`git diff secrets/key.pem`（不带 `--`）分不清是路径还是版本；`mv` 目录不算递归 |
| **M-10** 解析器与真 bash 的分歧 | 已修（未做差分） | `time` 后接复合命令时是保留字；`coproc NAME {…}` 跳过 NAME；`eval --` 去掉第一个 `--`；`max_depth` 3→8，包装层数上限 16→64 | **`time`/`coproc`/`eval --` 的用例按 bash 语法实现，没有逐条与真 bash 对照**（容器里虽有真 bash，但这批新用例没有加进差分测试）；`docs/m1-design.md` 的 `max_depth` 已同步改成 8 |
| **M-11** 项目内的凭据类文件被 allow | 已修 | `no-secret-read` 增加 `**/*.env`、`**/env`、`**/.envs/**`、`credentials.txt`、`secrets.{yml,yaml,json,toml,txt}`、`secret.txt`、`key.txt`、`keys.txt`、`password(s).txt`、`token.txt`、`.htpasswd`、`kubeconfig`、`*.kubeconfig`、`local.settings.json`、`*.kdbx`、`*.kdb`；`no-credential-store-read` 增加 `**/.git/credentials`、`**/.config/git/credentials`，`id_rsa*` 等覆盖备份；`no-agent-state-read` 增加 `**/.claude/settings*.json`、`**/.mcp.json`；`docker-compose.yml`、`README` 保持允许 | 见第 3 节的误报 |
| **M-12** UNC / WebDAV 不算联网 | 已修 | UNC 主机（`\\evil.example\s\x`、`\\host@80\DavWWWRoot\x`、IP 主机）现在是联网动作：`domains=(host,)`、`network_egress` 标签、灰色 `unc-network`，`net-allowlist` 会询问；`localhost`、`127.0.0.1`、`::1`、本机名、`wsl$`、`wsl.localhost`、`\\localhost\c$` 保持本地。覆盖 shell 命令、Read/Write/Edit、Grep/Glob 路径 | — |
| M-2 `evaluate` 没有预算 | **未做** | — | 进 M2 评测清单 |
| M-7 8 个空闲管道连接占满 | **未做** | — | 进 M2 评测清单 |
| M-13 日常只能 audit-only | **未做**（设计层） | — | 见第 6 节 |
| L-1 到 L-18 | **基本未做** | 顺手修的：L-6 里的 `Stop-Service` 现在 ask；L-10（读 boundkeep 自己的状态）现在 ask（`ask-guard-state-read`）；L-2 里 `py` 归一成 `python` | 其余逐条取舍，放进 M2 清单 |

## 3. 可用性代价与我接受的误报（请你确认可以接受）

这些是修复带来的实际副作用，不是理论风险：

1. **目录目标的 Grep / Glob**：项目里只要有受保护文件，对该目录的 `Grep`、`Glob *`、`Glob **/*` 都会被 deny，除非 `glob` 或 `type` 把它排除在外（`Glob` 只列名字，本来可以只 ask，我按"保守"保持 deny）。超过约 3 万个条目的树（大的 `node_modules`、`.git/objects`）变成灰色，会弹确认。没有按目录名跳过，是因为攻击者可以自己建这个名字的目录。
2. `.claude/settings.json`（项目与用户级）现在**读取**也被拒绝：agent 看不到自己的设置了，写入本来就是拒绝的。
3. 名叫 `env` 的目录（比如 virtualenv）被 `ls env` 或 `Grep path=env` 会拒绝；`env/bin/activate`、`python -m venv env`、`rm -rf env` 不受影响。
4. `id_rsa*` 连公钥 `id_rsa.pub` 一起拒绝。
5. `key.txt`、`keys.txt`、`password.txt`、`token.txt`、`secret(s).txt`、`credentials.txt`、`secrets.*`、`*.env` 这些名字即使内容无害也会拒绝。
6. `**/.claude` 写保护会连带拒绝 `mkdir .claude`、`git add .claude`、`git restore .claude`、`Copy-Item x .claude`；目录**里面**的文件（`.claude/commands/x.md`）不受影响。
7. 杀进程、`claude`、卸载包会对无害用途多一次确认（它们原来就是灰色 = ask，交互上没有新增摩擦；它们在接入 LLM 后端、由 LLM 裁决灰色之后才有意义）。strict 里所有 `pip/pipx uninstall` 都是 deny。
8. `ask-guard-state-read` 对任何含 `.boundkeep` 目录的路径询问，包括项目级的。
9. ConfigChange 阻断 `PATH`、`NODE_OPTIONS` 等环境变量与笼统的 allow 规则，会误伤合法使用。
10. **开发者注意**：运行时规则 `protect-guard-code` 保护已安装的包目录。在本仓库的可编辑安装上运行闸门时，agent 不能编辑 `src/boundkeep`；开发 boundkeep 本身时请用 `audit-only` 或不带守卫的运行方式。
11. 往 `.claude` 目录里写（`tar -xf x.tar -C ~/.claude`、`unzip -d ~/.claude`、`rsync -a x ~/.claude/`、`git clone … .claude`、`git -C ~/.claude pull`）原来是灰色或 ask，现在是 deny；对应的 7 条旧语料预期已按设计更新，`read-win-unc` 由灰色改为 ask（M-12），`ps-subexpression-arg` 由灰色改为 deny（未解析的文本里仍出现 `.ssh/id_rsa`）。

## 4. 修复过程中发现的问题

- 冒烟脚本 `scripts/smoke_claude_m1b.py` 的 `ps-delete` 场景有一次失败：模型自己先问了"你确定要删除吗"，没有调用工具，所以日志里没有记录。这是模型的非确定性，不是 boundkeep 的问题；脚本现在在"模型没有调用工具"时带明确的确认语重试一次再判定。
- Linux 容器里核心修复者的 10 个新测试失败：测试写死了 Windows 风格的工作目录，并假设假 Windows 路径存在于本机磁盘。原因在测试写法，不在运行时规则；已改成使用宿主自己的路径风格，Linux 与 Windows 都断言同样的内容。
- `boundkeep test`/`explain` 的假机器现在传 `scan_disk=False`：否则判决会取决于这台机器上的真实目录（`../..` 从假项目出发是真实的用户目录）。

## 5. 验证

见本文末尾的"验证结果"（修复全部落地后的最终运行）。

## 6. 需要你批准的规格变更提议

我没有改 `PROJECT_SPEC.md`（"要改设计，先改规格"，由你批准后再改）。下面是建议的文字；批准后我会连同 `docs/architecture.md`、`CLAUDE.md` 一起改。

| 位置 | 建议改动 |
|---|---|
| §3 范围外 | 明说：**同一用户的进程可以冒充守护进程**（创建同名管道实例或抢先占名）。boundkeep 不防御已在同一用户下运行的恶意进程，只保证它无法借此放行动作（客户端不执行 `allow`）。 |
| §5.1 与 `docs/architecture.md` 第 62 行 | "管道名含随机令牌，防止抢占"的表述改成"只防其他用户"；补充：创建完所有实例后 DACL 去掉创建实例权限；客户端永不输出 `allow`，除非 hook 参数显式带 `--emit-allow`（写进 §3 的客户端不变量）。 |
| §7 判定管线 | 加一句："目录目标的读类动作，只有在确认其子树不含受保护路径时才可 allow；遍历超出预算则灰色。" |
| §7 / M1 不变量 | 加一句："预算耗尽不得使已可见的 deny 变弱：预算触发后的命令仍做词法分类。" |
| §10 最后一行 | 补"hook 配置层与会话目录不匹配"的检测要求（`init` 提示 + `doctor` 说明检查目录；SessionStart 心跳留给 M2）；§10 第 233 行写的 "BOM 只警告" 改为"在含 boundkeep hook 的层里是 FAIL"；`installs.json` 新增 `hook_files`、`watched` 字段（版本仍为 1，向后兼容）。 |
| §6 / 核心承诺 | 补一条：**"在 enforce 下可日常使用"必须在 M2 评测之前达成**（allow 规则或 LLM），否则默认配置下防护等于要么关闭（audit-only 什么都不防）要么每条命令都点确认（M-13）。 |

## 7. 下一步

1. 你确认第 3 节的代价与第 6 节的规格提议。
2. 提交（建议一个修复提交 + 一个文档提交，不打新标签，或打 `m1b-fix1`）。
3. M2 清单：M-2（`evaluate` 的工作量预算）、M-7（管道连接数限制与更短的首字节期限）、M-13（enforce 下可日常使用）、SessionStart 心跳、L-1 到 L-18 逐条取舍；另外日志对 Read/Grep/Glob 不记录路径，建议加入路径摘要；`CLAUDE_CONFIG_DIR` 下 `.claude.json` 的位置需要核对官方文档。
4. 修复后再做一次独立 X1 复审，重点是 H-1 的遍历（预算、绕过、性能）、`--emit-allow` 与 DACL 的收紧、ConfigChange 的新阻断面。

## 验证结果（修复全部落地后的最终运行，2026-10-18）

| 项目 | 结果 |
|---|---|
| Windows 全量 pytest | 8868 通过、73 跳过、0 失败 |
| Linux 容器（python:3.12，uid 1000，`uv sync --frozen`，含真 bash） | 8313 通过、628 跳过、0 失败 |
| ruff check / ruff format --check | 干净（135 个文件） |
| mypy（strict，`src`） | 47 个源文件无问题（Windows 与 Linux） |
| 真实 Claude Code 冒烟 `scripts/smoke_claude_m1.py` | 11/11（约 $0.10） |
| 真实 Claude Code 冒烟 `scripts/smoke_claude_m1b.py` | 12/12（约 $0.10）；新增 `grep-dir` 场景验证 H-1：对项目目录 Grep、不带 glob，`.env` 被拒绝、密钥没有返回 |

说明：
- 第一次 Linux 全量有 11 个失败：10 个是核心修复者的新测试写死了 Windows 风格的工作目录（测试写法问题，运行时规则本身在 POSIX 上正确），1 个是 `echo a | time { …; }`（真 bash 拒绝这种语法，解析器却当成合法，已改为灰色）。修复后重跑全绿。
- 手工验收（VS Code 与终端 CLI）这一轮**没有重做**：这批改动影响 hook 客户端、`init` 的写入与运行时保护，建议你在提交前重做 `docs/manual-acceptance-m1b.md` 的 P1–P3、A0–A3、C1，至少确认守护进程、`doctor`、读 `.env`、删除界外目录仍按预期工作，并留意 `init` 新增的项目级提示。
