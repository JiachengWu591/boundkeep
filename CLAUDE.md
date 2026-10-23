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
- hook 客户端的 I/O 不依赖代码页或 `PYTHON*` 环境变量：按字节读 stdin、显式 UTF-8 解码，按字节写只含 ASCII 的 JSON。Windows 中文系统默认按 gbk 读 stdin：含中文的事件被悄悄读成乱码（`json.load(sys.stdin)` 不抛异常，文本却变了，规则匹配落空；孤立代理项还会在之后编码时崩溃，退出码 1 等于放行）（开发机实测，规格 §5.1；2026-10-07 更正了 M0a 原先"会抛 UnicodeDecodeError"的说法）。所有文本模式的文件读写都显式写 `encoding="utf-8"`。
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

## 常用命令

```
uv sync
uv run pytest -q                    # 默认不访问网络、不使用密钥；live 测试默认跳过（--live 开启）
uv run ruff check . ; uv run ruff format --check .
uv run mypy                         # strict，检查 src/
uv run boundkeep init --project-dir <一次性目录>   # 只在一次性目录里试，别写真实项目与用户级 settings
uv run boundkeep serve              # 常驻进程（手动启动；没启动时每个工具调用都会 ask）
uv run boundkeep doctor             # 检查 hook 配置、常驻进程、策略文件、闸门是否被悄悄关闭
uv run boundkeep mode [enforce|audit-only] ; uv run boundkeep log --tail 20
uv run python scripts/bench_hook.py        # hook 客户端延迟（真实进程，约 1 分钟）
uv run python scripts/smoke_claude.py      # 真实 Claude Code 冒烟（claude -p，haiku，几美分；手工运行）
# 以下从 M1 起才有：boundkeep test、boundkeep llm check、eval/run_eval.py
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

- 阶段（2026-10-22）：**M1c-4 已提交并有标签 `m1c4-done`**（放行当前会话自己的 scratchpad，`allow-session-scratchpad`，报告 `docs/reports/M1c4.md`，真实会话手工验收还没做）。**对 M1c / M1c-2 的定向 X1 审查已做**（`docs/reviews/M1c2-security-review.md`：6 条高危、3 条中危、若干低危），**H-1 到 H-6 已修**（报告 `docs/reports/M1c2-review-fixes.md`、`M1c2-review-fixes-2.md`；完整套件 22924 通过 / 0 失败，ruff、mypy 干净），标签 `m1c2-x1-fixes-done`。已完成并有标签：M0a、M0、M1、M1b、M1c（`m1c-done`）、M1c-2（`m1c2-done`）、M1c-3（`m1c3-done`）、M1c-4（`m1c4-done`）；对 M1+M1b 的 X1 审查与复审的两轮修复已提交。**等你做**：对这一轮修复的复审；中危 M-1（`pytest.toml`）、M-3（`trust add` 提示嵌套仓库）与 `.venv` / `site-packages` / `node_modules` 写入改 ask 建议在冻结规则前做，M-2（先写后运行的污染位）与 L-1（选项值里的路径，需要选项白名单）要你决定做不做；真实 Claude Code 里的手工验收（特别是真实控制台里的 `trust add`，现在要在 Claude Code 之外的终端里运行）。**下一步**：M2（评测集与 `rules-only` 基线），基线必须在规则冻结之后取。总览见 `PROJECT_SPEC.md` 开头的"当前进度"与 §14 的状态列。
- 规格是"修订 3"加上 M0a 的 10 条已接受变更与 M1 的澄清（§7：Action 列表、`inside_project` 三值、POSIX 路径大小写、`project_dir`）；`IMPLEMENTATION_PROMPTS.md` 已对齐。hook 的实测事实在 `docs/hook-behavior.md`（带版本），平台记录在 `docs/platforms.md`：**M0 支持范围 = Windows 11 原生的 VS Code 扩展与交互式 CLI（2.1.292，PowerShell 工具）**，M1 的手工验收做完之前不扩大这个声明。
- M1 已实现并通过自动测试：自写的保守 Bash 解析器（不用 bashlex，GPLv3+）、程序知识表、路径两层规范化、域名规范化、策略 schema 与规则引擎（`boundkeep test`、`boundkeep explain`）、判决到 hook 输出的映射（`allow` 只在 `emit_allow` 时输出）、`init` 把 home 固定进 hook 参数并支持 `--reset-policy`。设计契约在 `docs/m1-design.md`，策略字段在 `docs/policy-reference.md`。没有 LLM 后端时灰色就是 ask，所以 enforce 下大部分命令会弹确认，日常先用 `audit-only`。
- 独立审查（四路：解析器、路径与域名、策略语义、性能与集成）共约 60 条发现，已按文件分工修复并有回归测试；真实 Claude Code 冒烟（`scripts/smoke_claude_m1.py`，11 项）全过。Linux 容器里的 M1 测试已跑（真 bash 5.2，差分测试通过）。
- M1 手工验收（VS Code 扩展 2.1.296 与交互式 CLI）通过，记录在 `docs/manual-acceptance-m1.md`：被拒绝的理由可见，ask 的理由在确认框里仍不显示（与 M0 一致）；验收中发现并已修：文本版 `boundkeep log` 不显示命中的规则。
- M1b 已实现：常驻辅助进程（`powershell.exe`/`pwsh`，只做 `ParseInput`，从不执行命令；Job Object 随守护进程退出而终止；预热约 2 秒，期间 PowerShell 命令一律灰色 `ps-helper-not-ready`；熔断带 60 秒半开；慢输入有哈希缓存与限流），AST 摘要经 `pscmd` → `programs.classify(shell="powershell")` → `psprograms`，别名/参数表 `psaliases`（只有 Windows 上的一致性测试）。设计契约 `docs/m1b-design.md`，使用说明与已知缺口 `docs/powershell-dialect.md`，报告 `docs/reports/M1b.md`。审查（四路，约 1500 条命令只解析不执行）无 blocker、无 allow 绕过；两项 HIGH（熔断器永久打开、慢输入造成的全员灰色）与六项 MEDIUM 已修。pwsh 7 与 Linux/macOS 上的 pwsh 没有实测（只有 Windows PowerShell 5.1）。冒烟 `scripts/smoke_claude_m1b.py`（10 项）全过。
- X1 审查（2026-10-18）：三条高危（H-1 目录目标的 Grep/Glob 被 allow、H-2 同用户进程冒充守护进程、H-3 在别处打开会话时没有任何告警）与十余条中危。第一轮修复已做：H-1 有界遍历子树（`normalize/subtree.py`，3 万条目/0.2 秒，超出灰色，不按目录名跳过）；H-2 客户端默认不输出 `allow`（hook 参数 `--emit-allow` 才放行）并收紧管道 DACL；H-3 `init`/`doctor` 提示（SessionStart 心跳留给 M2）；M-1/M-3/M-4/M-5/M-6/M-8/M-9/M-10/M-11/M-12 见修复记录。**没做**：M-2（`evaluate` 预算）、M-7（管道连接数）、M-13（enforce 下可日常使用，必须在 M2 评测前达成）、L-1 到 L-18、H-2 的服务端 PID 校验。第二轮（复审）：R-1 `glob`+`type` 的绕过已修、Grep 无 glob 时跳过 `.git` 等版本控制目录、Glob 不再扫描、项目级 `.claude/settings.json` 可读（写保护不变）、管道 DACL 加 OWNER RIGHTS ACE、ConfigChange 只阻断有证据的削弱（实测 hook 的 ask 优先于 `permissions.allow` 与 `bypassPermissions`）。副作用：目录 Grep 在含受保护文件的项目里会被拒绝（除非 glob 排除）、开发 boundkeep 本身时 `protect-guard-code` 会禁止编辑已安装的包（用 `audit-only`）。
- M1c（2026-10-20，报告 `docs/reports/M1c.md`）：选方案 A（规则层加 allow，不靠 LLM）。`defaults.emit_allow` 仍默认关闭，所以 allow = "无决定"，由 Claude Code 自己的权限流程接手，boundkeep 只做到与 Claude Code **持平**（不再比它多弹确认），不替用户批准任何东西。新增：匹配字段 `flags_none`、`paths_read_only`；加载检查"allow 规则必须限定 `tool` 或 `program`"；先加 L-11 的 `ask-project-autorun-files`（strict 为 deny）与 `ask-secret-file-write`、`ask-credential-file-write`、`ask-git-internals-write`，再加 default 专有的 allow：第 1 档只读检查（`ls`、`tree`、`find`、`rg`、`cat`、`head/tail/wc/grep`、`pwd`、`git status|diff|log|show|blame|rev-parse`、`git branch` 的列表形态、PowerShell 的 `Get-Content/Select-String/Test-Path/Get-Item/Resolve-Path/Get-ChildItem/Get-Location/Get-Date/Measure-Object`），第 2 档项目内写入（`Write/Edit/MultiEdit/NotebookEdit`、`mkdir`、`touch`）；第 3 档（`pytest`、`npm test` 等会运行仓库代码的命令）**刻意不 allow**。`echo`、`Write-Output`、`Select-Object` 因为会把环境变量打印进上下文而不放行；`GIT_DIR`、`RIPGREP_CONFIG_PATH` 等环境前缀已进 `_ENV_CODE`；strict 不加新的 allow（子集一致性测试）。度量语料 `tests/corpus/workflow_benign.yaml`（312 条，合成）：每百动作询问数 Windows 80.6→52.6、POSIX 77.9→50.4，只读与项目内写入两档降到 0，必须拦截的无一放行。残余风险：不可信仓库里 `git status` 等仍可能运行该仓库 `.git/config` 指定的程序（所以 emit_allow 要保持关闭）；以变量开头的管道不被标灰；`head -n $TOKEN f` 这类选项值里的展开看不到。**还没做**：用你的真实会话统计覆盖率（`scripts/session_command_stats.py` 只输出计数，由你自己运行）；第 3 档与 emit_allow 的可选预设；allow 规则的定向 X1 审查。
- M1c-2（2026-10-21，报告 `docs/reports/M1c2.md`）：用户的真实会话统计（PowerShell 占 3354 次调用，只有约 1% 被放行）显示 M1c 的第 1、2 档几乎没覆盖到 PowerShell 开发工作流；最大的挡路者是带路径的 `.venv\Scripts\python.exe/ruff/mypy`（第 3 档）。新增：策略顶层键 `trusted_projects` 与匹配字段 `project_trusted`（默认空列表，strict 永不放行；链接/连接点解析后也必须被信任；拒绝过宽目录）；`boundkeep trust add|remove|list`（用户在终端运行，`add` 在 stdin 不是真实控制台时拒绝，agent 调用被策略 deny）；`pytest`、`ruff`、`mypy`、`black`、`isort`、`flake8`、`pylint`（含 `python -m <工具>` 与带路径形式）的识别与 allow 规则（52 个危险标志用 `flags_none` 排除，YAML 与 Python 表有一致性测试）；PowerShell 管道头修复（新灰色原因 `ps-pipeline-head-dynamic`，常量字符串喂给读取者变成读路径，`'~\.ssh\id_rsa' | Get-Content` 现在 deny）与数据整形 cmdlet 的 allow；同一行"先写后执行"检测扩展到 mypy/pylint/flake8/pytest 的配置与测试文件。**风险**：预设与项目内写入 allow 合起来构成"先写测试文件、再运行 pytest"的链路，跨工具调用的这条链无法识别；只应信任自己写过或审计过的仓库（M3 的污染标记计划收紧）。**没做**：真实控制台里 `trust add` 的成功路径没有自动化测试（手工验收 T2 是第一次）；对 node 工具的预设；每个工具单独的 allow 规则。真实覆盖率用 `scripts/session_command_stats.py --trust <项目>` 量化，你还没运行。
- M1c-3（2026-10-21，报告 `docs/reports/M1c3.md`）：用户统计显示 `Set-Location` 出现在约 2290 次 PowerShell 调用里而没有 allow 规则，一行里只要有一条命令不是 allow 整行就不是 allow。新增 `allow-cd-family`（默认策略独有）：`cd`、`pushd`、`Set-Location`、`Push-Location`（含别名），**必须带 `path_inside_project` 与只读路径**。我最初要求不加路径条件，实现者用探测证明那样 `cd /tmp && git status`、`cd ../other && git log`、`cd $x && git status` 都会变成 allow（这些命令没有路径，目录来自 cd，规则无从判断），所以保留了条件：项目外与动态目标的 cd、`cd -`、裸 `cd`、`popd`、`Pop-Location` 仍是灰色。`cd` 之后的命令仍按新目录判断（`cd .. && cat .env`、`cd ~/.ssh && cat id_rsa` 仍 deny）。整合时补了 `cd-extra-arguments` 灰色原因（zsh 的 `cd old new` 会替换路径子串）。合成语料每百动作询问数 Windows 58.0→55.2，`t1-read` 档 11.0→0。**还没做**：项目外 `cd` 要放行需要规范化器对不确定的 cd 目标打灰色原因；`Write` 到项目外目录（如 Claude Code 的 scratchpad）的分类有待用户的统计确认。
- 所有改动在用户确认前不提交。M1c-4 的改动目前都在工作区里，未提交、未打标签。