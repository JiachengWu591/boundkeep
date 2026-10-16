# M1b 验收报告

## 1. 结论

**通过：自动验收、Linux 容器验证、真实 Claude Code 冒烟、四路独立对抗审查和手工验收（VS Code 扩展与终端 CLI，2026-10-16，记录在 `docs/manual-acceptance-m1b.md`）都完成，审查没有发现 blocker，也没有发现"能让命令绕过规则变成 allow"的缺口；等你对第 8 节做选择并确认提交。** M1b 让 `PowerShell` 工具的命令也被归一化成和 Bash 同一种 `Action` 列表，由同一套规则判定：PowerShell 自己的解析器（只解析，从不执行）把命令切成语法树，别名、参数缩写、`$env:`、重定向、管道、`cd` 跟踪、通配符、外部程序都进同一条规则链；解析不了、含动态构造、辅助进程不可用，一律灰色（ask），不会放行。M1 报告里"PowerShell 一律灰色"这个最大的遗留事实，现在只对一部分构造成立（清单见 `docs/powershell-dialect.md`）。

需要当面说清的三件事：

1. **仍然没有 allow 规则。** 默认策略里 shell 命令没有 allow 规则，所以不命中任何规则的普通 PowerShell 命令（`Get-Date`、`Write-Output`）仍然 ask。M1b 让 deny 与 ask 能精确命中（`Get-Content .env`、`cat .env`、`rm -r -fo <项目外目录>`），不是让日常命令不再弹框。日常使用在策略与 LLM 里程碑之前仍建议 `boundkeep mode audit-only`。
2. **有一批已知缺口**（注册表与环境变量没有规则、`/switch` 词无法匹配、管道里的字符串字面量等），见第 6 节。每条都只会灰色，不会变成放行，但其中几条意味着"能 deny 的事只能 ask"。
3. **本机只验证了 Windows PowerShell 5.1。** pwsh 7、Linux / macOS 的 pwsh、OneDrive 重定向的 Documents、机器策略把执行策略设成 `AllSigned` 都没有实测，见第 6 节的"未验证 / 风险"。

## 2. 交付物

| 路径 | 说明 |
|---|---|
| `src/boundkeep/normalize/psparse.py` | 辅助进程管理器：预热、单次 0.3 秒预算、超时杀进程重启、崩溃退避重启、熔断（60 秒半开）、慢输入的哈希缓存与节流、30 分钟 / 2000 请求回收（热切换）、Windows Job Object（`KILL_ON_JOB_CLOSE`）、最小环境变量、固定路径的 PowerShell（不搜索 `PATH`）、脚本哈希钉住；永不抛异常、永不放行；可注入 `spawn` 用于假进程测试 |
| `normalize/pshelper.ps1` | 辅助脚本：只调用 `Parser::ParseInput`，只读语法树，输出纯 ASCII 的 JSON 行；检测约束语言模式；启动时用固定样本预热 JIT |
| `normalize/pscmd.py` | 语法树摘要（JSON）→ `SimpleCmd` / `Word` / `Redirect`：别名还原、参数缩写、冒号写法、字符串种类、`$(...)`、反引号、`--%`、`cd..` / `cd\`、别名重定义、管道到解释器等；永不抛异常，格式不对一律灰色 |
| `normalize/psprograms.py` | cmdlet 知识表（读 / 写 / 复制移动改名 / 创建 / 联网 / 执行 / 系统与持久化）、提供程序路径、robocopy / xcopy 与 `net` `reg` `sc` 等 Windows 工具的 `/switch`、外部程序委托给 Bash 一侧的程序表；表驱动 |
| `normalize/psaliases.py` | 静态的别名表与参数表（含唯一前缀判定），不依赖运行时 PowerShell；有 Windows 专用的一致性测试（对照真实 `Get-Alias` / `Get-Command`），生成脚本 `scripts/gen_ps_aliases.py` |
| `normalize/event.py`（改） | PowerShell 分支接线：`psparse.parse_powershell` 替换 M1 的"一律灰色"；`$env:` / `$HOME` / `$PWD` / `$PROFILE` 解析、PowerShell 通配符匹配点文件、`-LiteralPath` 的括号当字面、`cd` / `Set-Location` / `Push-Location` 跟踪；辅助进程的耗时不计入 M1 的预算 |
| `normalize/paths.py`、`programs.py`（改） | PowerShell 方言的路径与变量规则、通配符展开含点文件；外部程序表的扩展 |
| `policy/matcher.py`（改） | flag 折叠修复：PowerShell 的 cmdlet 参数与 `/switch` 不区分大小写，外部程序的短标志区分（`git branch -d` 与 `-D`） |
| `redact.py`（改） | PowerShell 的密钥写法脱敏：`ConvertTo-SecureString`、`-Password`、`Env:` 赋值、here-string、`curl -u`、`docker login -p` 等，不再漏进审计日志 |
| `policies/default.yaml`、`strict.yaml`（改） | `windows-persistence-commands` 扩展（11 项 → 53 项程序名，默认与 strict 相同）；新增 `ask-net-account-changes`；`ask-git-discard-paths` 加入 `restore`；PowerShell 的 `tests:`（默认 31 条）；把 M1 里写成 `expect: gray` 的 `Remove-Item -Recurse -Force C:\` 改成 `deny` |
| `cli.py`、`doctor.py`、`daemon/server.py`、`policycli.py`（改） | 守护进程启动时预热、每 2 秒轮询辅助进程、退出时 `shutdown`；ping 文本带 `powershell=<状态>`；`doctor` 的 `powershell-parser` 与 `powershell-job` 检查；`boundkeep log` 文本视图显示 `gray: ps-helper-*`；`boundkeep test` 在没有 PowerShell 解析器的主机上跳过 PowerShell 用例；`init` 的提示文字 |
| `tests/`（新增 9 个单元测试文件、5 个语料文件、254 个 AST 夹具；改 8 个已有的测试相关文件） | 见第 5 节 |
| `tests/corpus/powershell_parse.yaml`、`pipeline_ps*.yaml` | 解析语料 169 条；端到端语料 246 条（其中 214 条标 `adv: true`） |
| `tests/fixtures/ps_ast/`、`ps_ast_manual/`、`scripts/gen_ps_fixtures.py` | 由真 PowerShell 生成并检入的语法树夹具（Linux 上用它们代替真 PowerShell），生成脚本 |
| `scripts/smoke_claude_m1b.py` | 真实 Claude Code 的 M1b 冒烟 |
| `docs/m1b-design.md`、`docs/powershell-dialect.md`、`docs/manual-acceptance-m1b.md`、`docs/reports/M1b.md`、`docs/policy-reference.md`（改） | 设计契约、用户文档（支持的构造、灰色原因、已知缺口、排查）、手工验收步骤、本报告、策略字段参考的 PowerShell 一节 |

未提交的改动：`git status --short` 在写本报告时共 46 个路径（20 个修改、26 个新增，目录算一个路径；其中 45 个是实现与测试阶段的、1 个是 `docs/powershell-dialect.md`；本报告与 `docs/manual-acceptance-m1b.md` 是之后写的，没有算在内）：

- 修改（20）：`docs/policy-reference.md`、`policies/default.yaml`、`policies/strict.yaml`、`src/boundkeep/{cli,doctor,policycli,redact}.py`、`src/boundkeep/daemon/server.py`、`src/boundkeep/normalize/{event,paths,programs}.py`、`src/boundkeep/policy/matcher.py`、`tests/conftest.py`、`tests/corpus/pipeline.yaml`、`tests/e2e/test_cli_m1.py`、`tests/unit/{test_cli_log_summary,test_norm_event,test_norm_programs,test_pipeline_corpus,test_policy_rules}.py`
- 新增（26）：`docs/m1b-design.md`、`docs/powershell-dialect.md`、`scripts/{gen_ps_aliases,gen_ps_fixtures,smoke_claude_m1b}.py`、`src/boundkeep/normalize/{psaliases,pscmd,psparse,psprograms}.py`、`src/boundkeep/normalize/pshelper.ps1`、`tests/corpus/{pipeline_ps,pipeline_ps_review_cmd,pipeline_ps_review_event,pipeline_ps_review_policy,powershell_parse}.yaml`、`tests/fixtures/ps_ast/`、`tests/fixtures/ps_ast_manual/`、`tests/unit/{test_event_review_ps,test_norm_psaliases,test_norm_pscmd,test_norm_psparse,test_norm_psprograms,test_policy_review_ps,test_policycli_ps,test_psparse_review_m1b,test_redact_powershell}.py`

## 3. 验收标准逐条对照

标准原文取自 `IMPLEMENTATION_PROMPTS.md` 的 M1b"验收标准"与"测试要求"。

| 标准 | 结果 | 证据 |
|---|---|---|
| `pytest`、`ruff`、`mypy --strict`（normalize 包）在 Windows 与 Linux 上全绿；依赖真 PowerShell 的测试只在 Windows 上运行 | **通过（带一条说明）** | Windows 完整套件 **7772 通过、73 跳过**（审查修复全部落地后的最终运行；此前一次运行有 1 个 policy-rules 测试失败，已按新的大小写规则更新并重跑）。Linux 容器（`python:3.12`，uid 1000，`uv sync --frozen`）：7310 通过、535 跳过。`ruff check` 与 `ruff format --check` 无告警；`mypy`（strict）46 个源文件无问题 |
| `boundkeep test --platform windows` 通过全部 tests | **通过** | 默认策略 windows：71 条、0 失败；posix：47 条、0 失败；strict windows：51 条、0 失败 |
| 语料库全部通过；对抗样本里任何一条被判为 allow 而应为 gray 或更严，视为失败 | **通过** | 端到端语料 246 条（214 条 `adv: true`）在默认策略下判决；解析语料 169 条（`cmd-*`，没有逐条的 `adv` 标签，所以"≥40 条对抗"这一项靠端到端语料的 214 条对抗条目与四路审查满足，而不是靠解析语料自己）。默认策略里 shell 命令没有 allow 规则，对抗条目的测试额外断言"永不 allow、永不比预期宽松" |
| 辅助进程的失败路径（未就绪、崩溃、超时、熔断）都有测试，且都不静默放行 | **通过** | `tests/unit/test_norm_psparse.py`、`test_psparse_review_m1b.py`：假 `spawn` 注入下覆盖未就绪、超时、崩溃、非法应答、超大应答与请求、熔断与半开恢复、回收、`shutdown` 杀进程、排队；真 PowerShell（标 `windows`）覆盖中文与 ✓、`& ('i'+'ex')`、反引号、here-string、`$(...)`、嵌套脚本块、5.1 不认识的 `&&`、辅助进程环境不含密钥 |
| 别名表与参数缩写的一致性测试（只在 Windows） | **通过** | `tests/unit/test_norm_psaliases.py`（Windows 专用的一致性部分对照真实 `Get-Alias` 与 `Get-Command`） |
| 报告列出"已知无法处理的写法"，每条说明为何进入灰色 | **通过** | 第 6 节与 `docs/powershell-dialect.md` 第 5 节 |
| 解析只"解析"，不执行；辅助进程不继承环境变量中的密钥；有存活时间上限 | **通过** | 辅助脚本里没有执行类构造（测试检查）；环境白名单 7 个变量，带伪造密钥变量的真实启动测试；30 分钟 / 2000 请求回收；Job Object 保证随守护进程消失。四路审查全程只解析、没有执行任何被测命令 |
| 解析器不得崩溃：任意字符串给出结构化结果或 gray | **通过** | `psparse`、`pscmd`、`psprograms` 全部"永不抛"；hypothesis 对任意 JSON 形状（缺字段、错类型）不抛、非法即灰色 |
| 真实 Claude Code 冒烟 | **通过** | 见第 5 节：10 项检查 0 失败 |
| 独立安全审查 | **未做，已计划** | 见第 8 节决定 #1：M1 与 M1b 合并成一次 X1 审查 |

## 4. 与计划的偏差

- **熔断规则改了。** 设计契约写"连续 5 次失败后一直灰色，直到 `reset()`"。审查发现 5 个小的慢输入就能把熔断永久打开（高危）。现在：解析超时不计入失败；熔断后 60 秒半开，放行一次探测；"不可用"（没有 PowerShell、约束语言模式）按 30 秒起翻倍、上限 10 分钟重试。
- **选择 PowerShell 的方式改了。** 设计契约写"与 Claude Code 的自动检测一致：先找 `pwsh` 再回退 `powershell`"。审查发现 `PATH` 里的假 `pwsh.exe` 可以成为裁判。现在只认 `%ProgramFiles%\PowerShell\<版本>\pwsh.exe`（存在就优先）与固定的 `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`，不搜索 `PATH`；辅助脚本的哈希在第一次启动时钉住。
- **预算语义改了。** 契约写"排队超过预算 → busy"。审查发现排队等待会杀掉健康的辅助进程。现在预算从请求发出算起，排队用掉预算则 `ps-helper-busy`，不杀进程。
- **灰色原因比契约的总表多。** 新增 `ps-helper-error`、`ps-input-throttled`、`ps-input-too-large`、`ps-input-invalid`、`ps-alias-shadowed`、`ps-alias-redefined`、`ps-implicit-get-verb`、`ps-stop-parsing`、`ps-build-tool`、`ps-destructive-copy`、`ps-system-change`、`ps-exec:<名字>`（按具体 cmdlet 命名的 exec 原因）等；完整清单在 `docs/powershell-dialect.md`。
- **辅助进程新增的保护**（契约没有）：慢输入的哈希缓存与节流、读线程 EOF 回调与守护进程轮询（发现闲置时死掉的辅助进程）、异步杀进程（避免预算超出）、Job Object 状态报告。
- **默认策略的改动超出提示词的清单**：`windows-persistence-commands` 从 11 项扩到 53 项；新增 `ask-net-account-changes`（`net` / `net1` 的 `user`、`localgroup`、`group`、`share`、`stop`、`start`、`accounts`、`config`）；`ask-git-discard-paths` 加入 `restore`。这是实质的策略内容，请你抽看。
- **`matcher.py` 与 `redact.py` 被改动**：flag 折叠修复（`git branch -d` 与 `-D` 被折成一个）与 PowerShell 密钥写法脱敏（原来会漏进审计日志）。两处都是审查发现的缺陷，不是计划内的工作。
- **语料期望的调整**：一条语料 `ps-splat` 的期望故意从 gray 改成 ask（`@splat` 的路径按动态处理后命中了 ask 规则）；两个测试的期望按设计更改（`Move-Item` / `Rename-Item` 的源改为读加写；splat）。
- **`boundkeep ping`**：任务说明里提到的 `boundkeep ping` 并不是一个 CLI 子命令；守护进程的 ping 文本（含 `powershell=<状态>`）显示在 `boundkeep doctor` 的 daemon 一行里。文档按这个事实写。
- **做法**：设计契约（`docs/m1b-design.md`）把实现分成三块（辅助进程管理、摘要到命令与知识表、别名与参数表），我自己做组装与策略；之后四个独立的只读审查者（辅助进程与进程管理、命令隐藏与别名、策略与接线、性能与并发）各路合计至少约 1500 条命令的解析试验（只解析，没有执行任何一条）；四个修复者按文件分工修复，每项先写能复现的测试。修复期间四个修复者各遇到一次网络中断，被续跑完成，我核对了状态。M1 的四路审查与这一次的四路审查合计八路，之后计划做**一次**合并的 X1 安全审查（你选择的方案 B，见第 8 节）。
- **没做**：pwsh 7 与 Linux / macOS 的 pwsh 实测；OneDrive 重定向的 Documents 实测；受管机器（机器策略强制执行策略）实测；E21 的"profile 路径取自 `$PROFILE` 与已知文件夹"只做到默认 Documents 位置。

## 5. 度量

- **测试**：Windows 完整套件 7770 通过、73 跳过（之后修复了 1 个 policy-rules 测试，见第 3 节）；Linux 容器（`python:3.12`，uid 1000，`uv sync --frozen`）7310 通过、535 跳过（跳过的是 Windows 专用测试，其中包括需要真 PowerShell 的）。`ruff check`、`ruff format --check` 无告警，`mypy` strict 46 个源文件无问题。新增源码：`psparse.py` 约 1100 行、`pscmd.py` 约 470 行、`psprograms.py` 约 1370 行、`psaliases.py` 约 2700 行（大部分是数据表）、`pshelper.ps1` 约 360 行（含注释与空行）；新增测试文件 9 个，语料 415 条（解析 169、端到端 246），AST 夹具 254 个。**覆盖率没有重新测量，本报告不写覆盖率数字。**
- **延迟**（本机：Windows 11 build 26200，i7-13700H，Windows PowerShell 5.1，Defender 开着；辅助进程已预热，典型 PowerShell 命令 40 种）：

| 项目 | p50 | p95 | 备注 |
|---|---|---|---|
| `helper_parse`（辅助进程一次解析） | 1.5 ms | 2.3 ms | |
| `pipeline.review`（PowerShell，含解析、归一化、规则） | 2.4 ms | 5.7 ms | 提示词的预算是 p95 ≤ 20 ms |
| `Daemon.handle`（PowerShell，含审计写入与线程池往返） | | 7.3 ms | |
| 真实 hook 客户端端到端（PowerShell） | 52.5 ms | 63 ms | 同一台机器上 Read 为 51.7 / 59 ms（说明 PowerShell 没有明显多花时间） |
| 32 个并发 hook | | 338 ms | 没有因辅助进程产生的灰色 |
| 辅助进程首次就绪 | 1.8 到 2.3 秒 | | 就绪之前的 PowerShell 命令都是灰色 |

  5000 次顺序请求内存稳定；回收（热切换）期间零灰色。数字是本机的单次测量，不跨机器外推。Claude Code 的版本没有记入本报告（冒烟脚本的输出里有），请补。
- **真实 Claude Code 冒烟**（`scripts/smoke_claude_m1b.py`，haiku，约 0.085 美元）：**10 项检查 0 失败**：`Get-Content .env` 与别名 `cat .env` 被 `no-secret-read` 拒绝且密钥没有回到模型；`Remove-Item -Recurse -Force <项目外目录>` 被 `rm-outside-project` 拒绝，目录与里面的文件完好；`Write-Output` 解析成功但没有规则命中，灰色 ask，`-p` 模式下没有运行；`iex "..."` 灰色 ask，原因 `ps-exec:Invoke-Expression`，没有运行。
- **审查**：四路独立审查（辅助进程与进程管理；命令隐藏与别名；策略与接线；性能与并发）。结果：**0 个 blocker、0 个 allow 绕过**；每个没有解析的构造至少有一个灰色原因。已修复并有"先复现"的回归测试的发现（括号内为严重度，未标的是低或中）：
  - 小的慢输入 5 次就让熔断永久打开（高）→ 超时不计失败、60 秒半开、不可用的退避重试
  - 一个慢输入让所有调用方黑屏约 1.9 秒、反复触发时重启风暴（高）→ 超时输入的哈希缓存、大输入节流
  - 闲置时死掉的辅助进程没有被重启 → 读线程 EOF 回调与守护进程轮询
  - 排队超时杀掉健康的辅助进程 → 预算从发出请求算起，`ps-helper-busy` 不杀进程
  - `PATH` 里的假 `pwsh` → 固定路径；辅助脚本哈希钉住；预算超出（异步杀进程）；Job Object 状态
  - `cd..` 与 `cd\` 没有被跟踪（中）；通配符不匹配点文件（中）；`$PWD` 按 `cd` 之前的目录解析（中）；已知的 PowerShell 变量被当成动态 → 误 deny 与联接点降级（中）
  - PowerShell 的密钥写法漏进审计日志（中：`ConvertTo-SecureString`、`-Password`、`Env:` 赋值、here-string、`curl -u`、`docker login -p` 等）
  - posix 上 pwsh 的 `cd` 跟踪失效；`boundkeep test` 在没有 PowerShell 的主机上失败 → 现在跳过；`-LiteralPath` 带 `[`；陈旧的提示文字；`$PROFILE` 与 ProgramData 的启动路径；splat 路径；`--%`；git `-d` 与 `-D` 的折叠
  - `Move-Item` / `Rename-Item` 的源原来只算写（现在读加写，所以移动 `.env` 会被 deny）；一批系统变更 cmdlet 与外部程序被分类并写进持久化规则；`boundkeep log` 文本视图显示 `gray: ps-helper-*`；`git restore` 规则
- **成本**：冒烟约 0.085 美元；开发全程不使用 Anthropic API。

## 6. 已知问题与局限

每条：描述、影响、是否阻塞下一步。除特别说明外，结果是灰色（ask）或"没有规则命中"，不会变成 allow；**都不阻塞 M2**，但前五条建议在 X1 审查前后评估是否补。

| 编号 | 描述 | 影响 | 阻塞 |
|---|---|---|---|
| 1 | 提供程序与注册表路径（`HKLM:`、`Registry::`、`Env:`）不是文件路径，只能灰色，`path_glob` 匹配不到。注册表删除、`New-Item` / `Set-Item` / `Remove-Item` 作用于注册表没有规则；读环境变量（`Get-ChildItem Env:`、`echo $env:API_KEY`）没有规则 | 只能 ask，不能 deny | 否（需要策略 schema 扩展，建议进 M2 的清单） |
| 2 | `/switch` 词无法用 `flags_any` 匹配（schema 要求以 `-` 开头）。`robocopy /mir` `/purge` `/move` 有灰色 `ps-destructive-copy:*` 但没有 ask 规则；`net ... /add` 只能靠子命令规则 | 同上 | 否 |
| 3 | `format` 不在 `ask-disk-tools`（外部程序 `format` 仍得灰色 `ps-system-change:format`，所以是 ask，但不是规则命中） | 无法在 strict 里升级成 deny | 否 |
| 4 | `"~\.ssh\id_rsa" \| Get-Content`（管道里的字符串字面量）灰色，不会 deny。要修需要改辅助进程的摘要 | 能 ask 不能 deny | 否 |
| 5 | 计算出来的路径（`$(Join-Path ...)`、成员访问 `$PROFILE.CurrentUserAllHosts`）灰色；`$PROFILE` 假定默认 Documents（OneDrive 重定向不跟随）；UNC 路径（`\\host\share`）不被当作联网；祖先目录递归读取（`Get-ChildItem ~ -Recurse -Filter id_rsa \| Get-Content`）灰色 | 同上 | 否 |
| 6 | .NET 调用、`Add-Type`、COM 灰色（打 `exec`）；`Get-ChildItem -r` 这类有歧义的缩写灰色 | 能 ask | 否 |
| 7 | 不同的小输入（≤ 2048 字节、每次都不一样、每次都超过 0.3 秒预算）仍可能各花一次辅助进程重启（约 2 秒灰色）；哈希缓存与节流挡不住 | 可用性（拒绝服务），不是放行 | 否 |
| 8 | 超时会杀掉唯一共享的辅助进程，重启约 2 秒，没有热备 | 重启期间 PowerShell 命令全部灰色 | 否 |
| 9 | 辅助脚本哈希钉住后，校验与 PowerShell 打开文件之间仍有毫秒级间隙 | 需要本机已有写权限的攻击者；残余风险 | 否 |
| 10 | 普通 PowerShell 命令没有命中规则时仍 ask（没有 allow 规则）；`Get-Content *`、`Get-ChildItem *` 在含 `.env` 的项目里现在会 deny（符合 PowerShell 通配符真实语义） | 日常使用很吵；建议 `audit-only` | 否 |
| 11 | 数组实参展平后元素可能绑到错误的位置槽，只会多列路径 | 过度匹配 | 否 |

**未验证 / 风险**（没有证据，不要当成已验证）：

- **pwsh 7**：若机器上装了 `%ProgramFiles%\PowerShell\<版本>\pwsh.exe`，辅助进程会优先使用它；这条路径没有实测（开发机上没有装）。Linux / macOS 的 pwsh 同样只是设计目标，`pwsh` 7 的语法差异（`&&` 等）只在 5.1 上验证过会变成解析错误。
- **OneDrive 重定向的 Documents**：`protect-windows-persistence` 里有 `**/documents/...` 的写法，但在真实的重定向机器上没有验证；`$PROFILE` 变量不跟随重定向。
- **机器策略的执行策略（如 `AllSigned`）**：辅助脚本是未签名的，若机器策略使 `-ExecutionPolicy Bypass` 无效，辅助进程会启动不了 → `disabled` / `unavailable`，所有 PowerShell 命令灰色。没有在受管机器上验证。
- **高负载机器上的行为**：延迟数字来自开发机空闲时；0.3 秒预算在重载机器上会不会频繁超时（超时即杀进程重启）没有实测。32 个并发 hook 的测试只覆盖了一个负载点。
- **Claude Code 的版本与宿主**：自动冒烟用的是 CLI 引擎（`-p`）；VS Code 扩展与交互式 CLI 里的行为已由 2026-10-16 的手工验收确认（全部通过；重启后的预热窗口 `warming` 没有单独记录）。
- **覆盖率**：本报告没有记录。

## 7. 规格变更提案

无新增提案。需要你确认的两处自行做的细节：辅助进程的选择顺序与契约不同（只认固定位置、不搜索 `PATH`，见第 4 节），以及熔断从"永久"改成"60 秒半开"。规格 §5.1"命令方言"里若写了"与 Claude Code 的自动检测一致"，建议同步改成"固定位置的 `pwsh`（`%ProgramFiles%\PowerShell`）优先，其次固定位置的 5.1"。

## 8. 需要你决定的事项

1. **安全审查的方式**：M1 与 M1b 各做一次 X1（`IMPLEMENTATION_PROMPTS.md` 的原计划），还是合并成一次。你已选 **B：合并做一次覆盖 M1 与 M1b 的 X1**（M1 已有四路对抗审查，M1b 又有四路；X1 是独立会话、只读代码）。建议：照 B 做，重点看第 6 节的缺口 1 到 5、辅助进程的进程与文件信任、以及灰色原因是否都真的不会变成 allow。
2. **要不要在 M2 之前补策略 schema 的缺口**（第 6 节的 1、2、3）：A. 先不补，进 M2，把它们写进 M2 的评测清单（**建议**）；B. 现在补：`flags_any` 允许 `/` 开头、给提供程序路径一个独立的匹配字段（注册表 / 环境变量）。
3. **日常使用的模式**：M1b 之后规则能精确命中了，但没有 allow 规则，enforce 仍然每条普通命令都问。A. 继续 `audit-only`，观察一周再调（**建议**）；B. 日常用 enforce，接受频繁的确认框。
4. **默认策略的新增内容**（`windows-persistence-commands` 扩到 53 项、`ask-net-account-changes`、`restore`）：A. 先按现状（**建议**）；B. 你逐条看。
5. **提交**：A. 三个提交——① 设计契约与规格相关文档；② 代码、测试、策略、脚本、夹具；③ 报告、验收步骤、用户文档与 `CLAUDE.md`（**建议**）；B. 一个提交。我不会在你确认前提交，也不会推送。

## 9. 进入下一步的前置条件

- 手工验收已完成并通过（`docs/manual-acceptance-m1b.md` 末尾有记录）。验收里发现的可观测性缺口：日志对 Read、Grep、Glob 不记录路径，建议后续里程碑加入路径摘要。
- 提交前无需再补数字：最终运行（7772 通过 / ruff / mypy / `boundkeep test`）已记录在第 3 节；手工验收见 `docs/manual-acceptance-m1b.md`。
- 你对第 8 节 #1 到 #5 做出选择。
- 之后提交，再另开会话做合并的 X1 安全审查（M1 加 M1b）；高危发现清零后进入 M2。
