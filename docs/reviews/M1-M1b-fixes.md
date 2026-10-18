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
| **H-2** 同用户进程冒充守护进程 | 已修（两项） | ① 客户端默认不再输出 `allow`：守护进程回答 `allow` 时按"无决定"处理，只有 hook 参数里带 `--emit-allow` 才放行；`init` 在策略 `defaults.emit_allow` 打开时写入该参数，`doctor` 检查两者是否一致。`ask`/`deny` 始终有效。**更正（复审）**：这不等于"冒充者只能收紧"——客户端无法区分合法的 `none` 与冒充的 `none`，所以同一用户的冒充者回答 `none` 仍可静默关掉 boundkeep 的全部 deny；这次去掉的只是"用显式 `allow` 跳过 Claude Code 自己的确认框"这一档。真实残余：冒充者能**关掉** boundkeep，但不能放宽到比没装 boundkeep 更宽。② 管道实例创建完后收紧 DACL，去掉"创建新实例"的权限，直接再建同名实例会得到错误 5（对照组可以）。**更正（复审）**：所有者隐含拥有 `WRITE_DAC`，同一用户用三次调用（以 `WRITE_DAC` 打开、改 DACL、再建实例）就能撤销，所以这只是提高门槛；第二轮已加 OWNER RIGHTS ACE 堵这条路径；`serve` 在收紧失败时拒绝启动 | **③ 客户端校验服务端进程 ID 没做**：标准库没有 `GetNamedPipeServerProcessId`，需要在快速客户端里加 ctypes，且重启时序有误报风险。残留风险：同用户进程在守护进程启动**之前**占住管道名（此时 `serve` 会响亮失败，客户端也会忽略它回答的 `allow`） |
| **H-3** 在别处打开会话时没有任何告警 | 已修（最低限度） | `init` 项目级安装时打印醒目提示"只对在 `<路径>` 里打开的会话生效，其他目录没有任何 hook，Claude Code 也不会警告；要对所有目录生效用 `--scope user`"；`doctor` 不带 `--project-dir` 时明确说明检查的是哪个目录（新增 `scope` 检查，项目级安装为 WARN）；`check_workspace_trust` 现在尊重 `CLAUDE_CONFIG_DIR` | **没有加 SessionStart hook**（报告自己说可放进 M2 第一批）。`check_activity` 仍是 INFO：在错误目录里开的会话不会运行任何 hook，也不会留下日志，别的目录里的事件也证明不了这个项目，所以 WARN 不可靠。`CLAUDE_CONFIG_DIR` 下 `.claude.json` 的位置是凭记忆写的，没有验证 |
| **M-1** 预算耗尽丢掉 deny | 已修 | 预算触发后，触发的命令和之后的命令继续做**纯词法**分类（不展开通配符、不查磁盘、不遍历），`cd` 跟踪保留，仍追加灰色 `budget:*` 标记，所以永远不会是 allow；磁盘查询预算与通配符预算拆开（`MAX_GLOB_DISK_KEYS` 256 与 `MAX_DISK_KEYS` 64） | （第二轮已去掉条数上限，见第 8 节） |
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

1. **目录目标的 Grep / Glob**：项目里只要有受保护文件，对该目录的 `Grep`、`Glob *`、`Glob **/*` 都会被 deny，除非 `glob` 或 `type` 把它排除在外（`Glob` 只列名字，本来可以只 ask，我按"保守"保持 deny；**第二轮已改：Glob 不再扫描、Grep 在没有用户 glob 时跳过 `.git` 等版本控制目录，见第 8 节**）。超过约 3 万个条目的树（大的 `node_modules`、`.git/objects`）变成灰色，会弹确认。没有按目录名跳过，是因为攻击者可以自己建这个名字的目录。
2. ~~`.claude/settings.json`（项目与用户级）现在**读取**也被拒绝~~ **第二轮已改**：只保护 `settings.local.json`、用户级 `settings*.json` 与 `.mcp.json` 的读取；项目级 `.claude/settings.json` 可以读（它通常提交进仓库，且 `init` 默认就写它），写入保护不变，见第 8 节。
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

## 8. 第二轮修复（复审，2026-10-18）

对应复审：`docs/reviews/M1-M1b-fixes-rereview.md`（审查对象 `8ca058c` 与 `21eb98f`）。复审结论：第一轮修复大体有效，但 H-1 的修复自己留下了一个新绕过（R-1），并带来三处会让日常用不下去的误拒（U-1 至 U-3）。

**先做了一个实验来决定 ConfigChange 该拦什么**（真实 Claude Code CLI 引擎，`-p` 模式，几分钱，2026-10-18）：hook 对一条灰色命令回答 `ask` 时，项目设置里加 `permissions.allow: ["PowerShell(*)"]`，命令**仍然没有执行**；加 `permissions.defaultMode: "bypassPermissions"`，命令也**没有执行**。所以这两类设置没有可演示的削弱能力。其他模式与宿主未测。

| 编号 | 状态 | 做了什么 | 残留 |
|---|---|---|---|
| **R-1**（高）Grep 的 `glob`＋`type` 绕过扫描器 | 已修 | 选择器按 ripgrep 的规则：只要给了正的 `glob`（哪怕不认识），`type` 一律不参与收窄；`glob` 编译失败或没有可用部分时不收窄（扫描全部）；只有否定 glob 时 `type` 仍然生效；只有 `type` 时行为不变。回归测试用真实临时目录（`.env`、`sub/.env`、`certs/x.pem`、`a.py`），含复审的 `.e?v`+`py`、`[.]env`+`json`、`*.p[e]m`+`py`、`.e\nv`+`py`、`.e?v`+`markdown` | 复审用真实 ripgrep 15.0.0 验证了语义；"Claude Code 把这些参数原样传给 ripgrep"仍来自二进制字符串，没有用真 Claude Code 对这条路径单独跑 |
| **U-1** 任何 git 仓库里无 glob 的 Grep 被拒（`.git/config`） | 已修 | Grep 工具在**没有用户 glob** 时跳过 `.git .svn .hg .bzr .jj .sl`（精确大小写、任意深度，不计预算；扫描根本身不跳）；给了任何非空 glob（包括否定 glob）就照常扫描（复审实测 `-g '*'` 会让 `.git/config` 重新出现）。shell 的递归读只在 `program == git` 时跳过（`git grep/log -p/show/archive` 读对象库，不读 `.git/config`）；`grep -r`、`tar`、`cp -r` 仍会扫 `.git` 并 deny | — |
| **U-2** 默认安装让项目里的 Grep 失效 | 已修 | `no-agent-state-read` 不再包含 `**/.claude/settings*.json`，改为 `**/.claude/settings.local.json`、用户级 `~/.claude/settings.json` 与 `settings.local.json`（含从 WSL 看 Windows home 的 `**/users/*/.claude/…`）、`**/.mcp.json`；**项目级 `.claude/settings.json` 可以读**；所有 settings 的**写入**保护不变（`protect-guard-config`）。两个策略保持超集，`boundkeep test` 0 失败（default 245、strict 178，两平台合计） | `CLAUDE_CONFIG_DIR` 指向的自定义配置目录的 `settings*.json` 读取不受保护（运行时规则只保护 `.credentials.json` 与 `projects/**`），要保护需要改 Python |
| **U-3** 只列名字的命令被当"读内容" | 已修 | `Glob` 工具不再扫描子树（仍检查基础路径与向上爬出项目的模式）；`ls -R`、`dir /s`、`Get-ChildItem -Recurse`/`-Depth`、`find` 不带 `-exec`/`-ok`、`rsync --list-only`、`robocopy`/`xcopy /L`、`tree`、`du` 不再标成递归（仍把目录操作数当读路径）；同时把 `gzip -r`/`zstd -r` 等、`docker cp`（本地源）、`bsdtar`/`gtar`、`pax -w/-rw` 这几类**读内容**的命令补成递归 | **管道喂给读取者**的写法（`ls -R \| xargs cat`、`find . \| xargs cat`、`Get-ChildItem -Recurse \| Get-Content`）原来因为 `ls -R` 被扫描而 deny，现在是灰色（ask）——回到 M1 原有水平，不是比审查时更差；要恢复 deny 需要"管道上游是递归列举、下游是读取者"的信号（`model.py` + `event.py` 一起改）。`git diff`/`git format-patch` 没标成递归（否则任何存在被忽略的 `.env` 的仓库里这些常用命令都会被拒） |
| **M-1 残余**（1400 条不同命令后的 `cat .env` 仍灰色） | 已修 | 去掉词法分类的条数上限；改为：外形相同的命令只保留一份，项目内且没有任何 deny/ask 规则能选中的路径被丢弃（`pipeline.rule_path_globs` 提供规则的 glob、程序与访问方式），可能被规则看到的路径最多 1024 个，墙钟上限 0.8 秒；解析器的词数上限在 `event.py` 里提到 20000。实测：1400 条不同 `echo` 后的 `cat .env` 约 0.07 秒、deny；10 万字节一行（9000 条不同 `echo`）后的 `cat .env` 约 0.3–0.4 秒、deny | 一行里几千条各不相同又都带路径的命令，可能因 0.8 秒上限变灰色（ask），绝不会是 allow；词法模式下递归读（`grep -r x .`）仍不扫描、仍是灰色 |
| **DACL** 同一用户三次调用即可撤销收紧 | 已修 | 在 DACL 里加 OWNER RIGHTS ACE：`D:P(A;;0x12019B;;;<用户SID>)(A;;0x20000;;;OW)`，只授予 `READ_CONTROL`，关掉所有者隐含的 `WRITE_DAC`。测试里先复现了旧 DACL 的三步撤销（以 `WRITE_DAC` 打开、`SetSecurityInfo`、再建实例），再显示新 DACL 下第一步就得到错误 5；直接再建实例仍是错误 5；客户端 `open(addr,'r+b')`、`read_acl_of_pipe`、`AddressInUse`、重启都正常。`doctor` 的管道 ACL 检查只接受 mask 恰好为 `0x20000` 的 OWNER RIGHTS 条目（更宽的 mask 或其他 SID 仍然 FAIL） | 这只是**提高门槛**，提权的管理员（`SeTakeOwnershipPrivilege`）可以接管所有权；同一用户在守护进程**启动之前**占住管道名仍然可能（`serve` 响亮失败，但客户端在这期间会对占位者说话，`doctor` 看不出来）；一个工作线程在连续失败后退出会永久少一个实例（M-7，未做）；没测"默认所有者是 Administrators 组的非提权令牌" |
| **C-1**（中）外来 hook 靠形状伪装绕过 | 已修 | 一个条目只有在命令与参数**精确等于**某条安装记录的 `hook_command` + `[*hook_args, 对应子命令]` 时才算"自己的"，其余长得像的一律按外来处理；`record_problem` 现在会报"发现一个长得像 boundkeep 的额外 hook"；`init` 对无法替换的长得像的条目警告，`doctor` 对它报 FAIL。复审的三种伪装与变体（独立组、放进我们的组、放在前面、更窄的 matcher、其他事件）都有测试 | 没有安装记录时只有形状启发式，只用于 `doctor` 警告，不阻断 |
| **C-2**（中）监视范围太窄 | 已修 | `watched_fingerprints` 现在覆盖**所有事件**里的外来命令 hook，以及 `enabledPlugins`、`extraKnownMarketplaces`、`mcpServers`、`appendPlugins`、`prependPlugins`、`pluginConfigs`、`enabledMcpjsonServers`、`enableAllProjectMcpServers`、`managedMcpServers`；基线加版本标记，旧基线只判断它原来覆盖的部分，新增标签只提示"请重新 init" | **没有基线的文件**（项目级安装时的用户级 settings、`settings.local.json`）仍然不拦（ConfigChange 事件不带差异，无法"首次使用即信任"），只 warn/info，文字里写明"不拦截"；只是停用一个插件也会触发阻断，直到重新 `init`（试过容忍并放弃，过度设计）；没有用真实的 ConfigChange 事件端到端测过 |
| **C-3**（低）误拦与没有证据的阻断 | 已修 | 笼统的 `permissions.allow`、`bypassPermissions`、`skipDangerousModePermissionPrompt` 降为 **WARN**（文字写明"2026-10-18 在 CLI 引擎 `-p` 模式下观察到 hook 的 ask 仍然优先；其他模式与宿主未测"）；阻断的环境变量只剩会重定向 home、项目目录或关闭 hook 的：`USERPROFILE`、`HOME`、`HOMEDRIVE`、`HOMEPATH`、`APPDATA`、`LOCALAPPDATA`、`CLAUDE_CONFIG_DIR`、`CLAUDE_CODE_SIMPLE`、`CLAUDE_CODE_SAFE_MODE`、`CLAUDE_PROJECT_DIR`、`BOUNDKEEP_*`；`PATH`、`PATHEXT`、`COMSPEC`、`PSMODULEPATH`、`NODE_OPTIONS`、`NODE_PATH`、`LD_*`、`DYLD_*` 只警告，`PYTHON*` 只提示（`PYTHONUTF8`、`Path` 不再被拦）；"粘性阻断"的提示文字写明做法：`boundkeep init` 接受新的命令类条目，在此之前对该文件的任何 settings 改动都会被拦（基线不会自动更新） | — |
| **init 顺序** | 已修 | `init` 先写 manifest（含新基线与 `hook_files`）再写 settings；settings 写失败时按字节还原旧 manifest（原来没有则删除）；测试用注入的 `OSError` 覆盖首次 init、已有外来记录、改钉参数的重 init | — |
| **完整性哈希范围** | 已修 | 除解释器、`hook_client.py`、`hook_main.py` 外，还包括 `hook_main` 运行时导入的模块（由 AST 静态计算，含延迟导入与传递依赖：`protocol`、`paths`、`ownhook`、`claude_settings`、各包的 `__init__`、`ipc/client`、`ipc/endpoint`）；一个 `python -I -S` 子进程测试保证 `sys.modules` 里的每个 `boundkeep.*` 模块都在列表里；旧的三文件记录只警告"请重新 init" | 若以后加入动态导入，静态计算会漏掉（目前没有） |

**复审里的措辞更正（已改正文）**：第一轮"冒充者只能收紧"和"同一用户也不能再建同名实例"说得过强，已在第 2 节的表格里就地更正，规格 §3、§5.1 也按复审的表述写成了"冒充者能关掉 boundkeep，但关不到比没装更宽""收紧 DACL 只是提高门槛"。

**第二轮之后仍然没做的**：M-2、M-7、M-13、L-1 到 L-18、H-2 的服务端 PID 校验、SessionStart 心跳；"管道上游是递归列举、下游是读取者"的信号；`CLAUDE_CONFIG_DIR` 自定义目录的 `settings*.json` 读保护；ConfigChange 的端到端测试（真实事件）。

### 第二轮的验证结果（2026-10-18）

| 项目 | 结果 |
|---|---|
| Windows 全量 pytest | 9479 通过、73 跳过、0 失败（约 30 分钟） |
| Linux 容器（python:3.12，uid 1000，含真 bash） | 8882 通过、670 跳过、0 失败 |
| ruff check / ruff format --check | 干净（144 个文件） |
| mypy（strict，`src`） | 47 个源文件无问题（Windows 与 Linux） |
| 真实 Claude Code 冒烟 `scripts/smoke_claude_m1.py` | 11/11 |
| 真实 Claude Code 冒烟 `scripts/smoke_claude_m1b.py` | 16/16；新增 `grep-glob-type`（R-1）场景，并改成比较前后的 Grep deny 条数，不会被前一个场景留下的记录蒙混 |
| 实验：hook 的 `ask` 与 `permissions.allow` / `bypassPermissions` 谁优先 | 两种设置下命令都没有执行（hook 的 ask 优先）；CLI 引擎 `-p` 模式，其他模式与宿主未测 |

第二轮过程中的两点：
- 第二轮的单元与语料测试变多（含带真实磁盘的遍历测试），Windows 全量从约 13 分钟变成约 30 分钟，主要是 `tests/unit/test_pipeline_corpus.py`；后续可以考虑给带磁盘的测试加标记、日常只跑子集。
- 第一次 Linux 重跑失败是 Docker Desktop 的守护进程没有运行（不是测试失败），启动后重跑全绿。

**手工验收这一轮没有重做**（上一轮你做了复测并通过；第二轮又改了 `init` 的写入顺序、ConfigChange 的阻断面、管道 DACL）。建议你至少重做：`init` + `doctor`（确认没有 FAIL，尤其 `pipe-acl` 与新的完整性哈希检查）、`serve`、读 `.env`、对项目目录 Grep。
