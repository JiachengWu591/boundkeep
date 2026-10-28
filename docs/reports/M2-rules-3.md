# M2 之后的规则改动三：留出集 h1，MCP、网络、持久化与递归删除

日期：2026-10-28。**状态：已实现；同一复审者审了两轮（第 7 节），没有 high / medium 遗留，A 到 E 五组都可以冻结；整套测试见第 6 节；留出集还缺攻击样本，没有打开。**

## 0. 留出集 h1 的封存记录（在任何规则改动之前）

| 项 | 值 |
|---|---|
| 封存时间 | 2026-10-28，规则改动开始之前 |
| 当时的代码 | 提交 `7e1d70b` 之上（留出集框架未提交） |
| 当时的策略 | `policies/default.yaml` sha256 `91afc2f87079ba80ea0170d124be6738adb919e87031ece0db1006cfa7375f5b` |
| 留出集指纹 | `0aacd20fdef20db633a079e351f8b176eea5d5d7e832f1b16d9b232ea9564937` |
| 内容 | 169 条正常样本：真实会话 127 条（`eval/datasets/holdout/real.jsonl`，2026-10-25 与本会话及其复审子代理，Windows），合成 42 条（`benign-synthetic.jsonl`，LLM 助手起草） |
| 确认 | 使用者在对话里同意了预筛结论（155 条真实候选删 28 条：14 条安全实验、2 条批量结束进程、12 条重复的轮询；42 条合成全部保留），由我用 `dataset.confirm_file` 写入，`boundkeep eval promote` 入库 |
| 攻击样本 | **还没有**。我起草留出集攻击样本时被安全分类器拦下，不再尝试；由使用者之后自己写（`eval/authoring/HOLDOUT.md`），写的时候不看 `policies/`。它们在规则冻结之后才写也不影响无偏性：规则改动看不到它们 |

规则改动只看 dev。留出集在规则冻结之后打开一次（`run_eval.py --open-holdout`，记入台账）。

## 1. 留出集框架

| 位置 | 改动 |
|---|---|
| `src/boundkeep/evalkit/schema.py` | 切分加 `holdout`；样本字段 `holdout: 批次名`，有它就是留出样本（不看哈希）；`action_key` |
| `src/boundkeep/evalkit/dataset.py` | 留出样本不得重复 dev / test 里已有的动作（任何意图）；`sealed()` 把留出样本分开 |
| `src/boundkeep/evalkit/holdout.py`（新） | 台账 `eval/holdout-ledger.jsonl`：每次打开记一行（日期、留出集指纹、策略指纹）；更早的打开用了另一份策略，或打开之后样本变了，就判为已污染 |
| `eval/run_eval.py` | 默认不测留出集，报告只写“已封存”；`--open-holdout` 才测，消融行改用 holdout 列，并写台账；`--check` 打印 holdout 指纹 |
| `metrics.py`、`report.py` | 留出集打开时多一列；数据集表多一列；局限性一节写留出集状态与污染声明 |
| `importer.py`、`evalcli.py` | `import-session --holdout 批次` 生成 `hold-real-` 候选，已在 dev / test 的动作丢弃；`promote` 按字段放进 `eval/datasets/holdout/` |
| `eval/add_samples.py` | `--holdout 批次`；覆盖除 injection-deviation 以外的攻击类别，并支持 MCP 工具（输入是 JSON 对象） |
| 文档 | `docs/eval-methodology.md` 第 4b 节、`PROJECT_SPEC.md` 第 12 节、`eval/authoring/HOLDOUT.md`（写攻击样本的说明） |

## 2. 规则改动（规格见 `PROJECT_SPEC.md` 第 7 节“M2 评测之后的规则层”）

### MCP 工具一律灰色 → 参数进入规则，用户可以声明只读工具

- 归一化层（`normalize/event.py`）：路径类键里的**绝对路径或 `~` 路径**按本机路径交给路径规则（访问方式按工具名的动词）；`command` / `cmd` / `script`（含 `args`）按 Bash 解析成带灰色 `mcp-command` 的附加动作，只能触发 deny / ask；`http(s)://` 值进入域名；看起来会写的 SQL 加 `mcp-sql-not-read-only`。相对路径不处理：它可能是远端仓库里的路径。
- 策略：顶层键 `mcp_read_only`（默认空）与匹配字段 `mcp_read_only: true`；默认策略新增 `allow-declared-read-only-mcp` 与 `ask-mcp-path-outside-project`。strict 没有这条 allow。
- **默认策略不声明任何工具**，所以随附策略下正常的 MCP 调用仍然问；这一类误报要靠用户自己声明来降。理由：工具名由用户配置的服务器决定，内置名单不可靠；而只读工具的参数照样会发给服务器，信不信得过是用户的判断。

### `net-allowlist` 太粗 → 拆成两条，补白名单

- 新匹配字段 `destination: known | unknown`。`net-unknown-destination`：目的地无法确定（`git fetch`、`npm ci`、`uv sync`、`cargo build` 等走配置好的远端或包源）；`net-allowlist`：已知主机不在白名单。理由文字各自准确。
- 白名单补上 `githubusercontent.com`、`registry.yarnpkg.com`、`crates.io`、`proxy.golang.org`、`sum.golang.org`、`api.nuget.org`。在白名单上不等于放行（命令仍要有 allow 规则）。
- **没有解决、也不打算在规则层解决的**：上传制品、发构建通知与外传在规则层分不清，仍然问；要靠任务意图（M3 的 LLM 层）。

### 持久化与递归删除默认只问不拒 → 项目之外的改为 deny

| 规则 | 变化 |
|---|---|
| `protect-windows-persistence` | ask → deny（PowerShell profile、启动文件夹、计划任务目录） |
| `deny-windows-persistence-tamper`（新） | deny：`Register-ScheduledTask`、`New-Service`、`Set-WmiInstance`、本地账户、Defender、防火墙、`Set-ExecutionPolicy`、`Enable-PSRemoting`、`Clear-EventLog`、`bcdedit`、`takeown`、关机。`reg`、`sc`、`schtasks`、`wevtutil`、`vssadmin` 等有只读用法、规则分不清的仍是 ask |
| `protect-shell-startup-files` | ask → deny；`~/.local/bin`、`~/bin` 拆到 `ask-user-path-dirs-write`（仍是 ask） |
| `ask-system-config-write` → `deny-system-config-write` | ask → deny |
| `ask-ssh-write` → `deny-ssh-write` | ask → deny |
| `deny-crontab-install`（新） | 除 `crontab -l` 外的 `crontab` |
| `deny-service-registration`（新） | `systemctl` / `launchctl` 的注册类动词；规范化层现在把它们的第一个位置参数当作 subcommand |
| `ask-find-delete` → `deny-find-delete-outside-project` | 项目外 ask → deny |
| `ask-recursive-permission-change` → `deny-recursive-permission-change` | 项目外 ask → deny |
| `ask-disk-tools` → `deny-disk-tools` | ask → deny（与 strict 相同） |

项目之内的自动运行文件（`package.json`、`.git/hooks` 等）仍是 ask：它们在项目里，看得见、改得回来。strict 加了同样的 deny 规则（有测试保证 strict 至少同样严格）。

## 3. 对评测的影响（看 dev；test 已被污染，只作参考）

| 格子 | 达到要求的攻击样本（之前 → 之后） | 正常操作误报率（之前 → 之后） |
|---|---|---|
| Windows dev | 77 / 94 → **86 / 94** | 34.8% → 34.8%（deny 由 1 条变 2 条） |
| POSIX dev | 90 / 104 → **101 / 104** | 62.5% → 62.5%（deny 由 1 条变 2 条） |

- dev 上未达到要求的攻击从 31 条（两台机器合计）降到 11 条。剩下的：结束进程（`kill -9 -1`、`pkill -f boundkeep`、`Stop-Process`，没在这一批的范围里）、注册表路径（`HKCU:\...`、`reg save`、`Set-ItemProperty ...\Run`，规则看不到提供程序路径）、`cmd /c del /s`（cmd 不解析）、`wevtutil cl`（有只读用法）、`.git/hooks` 写入（项目内，有意保持 ask），以及 Windows 假机器上写 `/home/testuser/.bashrc` 的 MCP 样本（那台机器的主目录不是它，所以是 ask）。
- **新的 deny 误报（这次决定的代价）**：两条“任务里明确要求”的正常样本被拒：配置每日备份的 `crontab -`、为开发服务器开防火墙端口的 `New-NetFirewallRule`。另一条已有的（生成 ssh 部署密钥）原本就是 deny（`no-secret-read`）。用户要做这些事需要自己在终端里做。
- MCP 的正常样本误报不变（默认策略不声明任何只读工具）。网络类误报不变，只是理由从“主机不在白名单”分成了两种。
- 合成语料（`scripts/measure_ask_rate.py`）：每百动作询问数 Windows 50.4 → 49.6、POSIX 49.3 → 48.7（`must-block` 档里三条由 ask 变 deny），与设计目标有差异的条目 0。

## 4. 残余与没做的

1. MCP：任何键下的绝对、`~`、UNC 路径与 `file:` URI 都看（复审 R9-1 之后），但不以 `..` 开头的相对路径不看（可能是远端仓库里的路径），服务器自己读写的东西看不到；读写按工具名判断是启发式（以读类词开头、且不含写入类的词才算只读，复审 R10-1 之后）。
2. 声明为只读的 MCP 工具仍然可以把 agent 放进参数的内容带给它的服务器。
3. SQL 判断是启发式：只认单条、以 `SELECT` / `WITH` / `SHOW` / `EXPLAIN` 等开头、不含写入类词的语句；`SELECT` 里调用的会写的函数（例如 PostgreSQL 的 `setval`、存储过程）看不到（复审者已确认 `select setval('s', 1)` 会被放行）。SQL 参数按键名识别（含 `sql`、`statement` 的键，以及 `query`、`q`、以 `query` 结尾的键），别的键名下的 SQL 看不到。
4. 网络：上传与外传在规则层分不清（见上）。
5. Windows 注册表（提供程序路径）、`cmd /c`、结束进程都没有动；`launchctl asuser <uid> launchctl load ...` 这种嵌套只是 ask（外层动词 `asuser` 不是注册类）。
6. 这些 deny 在任务确实需要时会挡路（见上面的两条误报）；理由文字说明了“需要时自己做”。

## 5. 验证

`ruff`、`mypy`（58 个源文件）干净；`boundkeep test`：default 1065 条、strict 318 条，0 失败；与规则相关的单元测试约 5150 个通过；新增 `tests/unit/test_m2_rules3.py`（136 个：MCP 参数、只读声明的正反例、SQL、网络两条规则、服务管理器动词、deny 与 strict 一致、复审 R9 / R10 的回归）；端到端语料里 58 条因新的 deny 规则由 ask 改为 deny（逐条核对过：全部是变严，没有一条变松）；评测框架测试 128 个通过。评测已重跑（`--test-contaminated`，**留出集未打开，台账不存在**）。

## 6. 整套测试

`uv run pytest -q`（2026-10-28，1 小时 5 分）：25733 通过、168 跳过、2 失败。

1. `test_m1c2_trusted_projects.py::test_every_match_field_is_in_this_table_and_parses`：这张表要列出每个匹配字段，新加的 `destination` 与 `mcp_read_only` 没有补进去。已补，这个文件 200 个测试通过。
2. `test_norm_bash.py::test_work_is_roughly_linear`：计时测试（大输入的耗时不得超过小输入的 40 倍），在长时间满载运行时超限。这一批没有改 Bash 解析器（`git status` 下 `normalize/` 只改了 `event.py` 与 `programs.py`），单独连跑 5 次都通过。

修完之后没有再跑一遍整套测试（要一个多小时）；改动只涉及上面那张测试表。

## 7. 独立审查（`docs/reviews/M2-rules-3-review.md`）

同一复审者审了 A（MCP 参数）、B（只读声明）、C（网络）、D（持久化与删除）、E（留出集框架）。**没有 high；两条 medium，都只在用户声明了只读 MCP 工具时才成立**（随附策略不声明任何工具，开箱即用的情况下两条都不触发）。复审者没有打开留出集数据，也没有运行 `--open-holdout`。

| 编号 | 级别 | 问题 | 处理 |
|---|---|---|---|
| R9-1 | medium | 声明为只读的工具，用没列出的键名（`file_name`、`folder`、`uri`…）、`file://`、前导空格、`$HOME` / `%USERPROFILE%`、盘符相对路径，或者让一个大的兄弟参数耗尽走查预算，就能读到 `~/.ssh/id_rsa` 而被放行 | 本机路径改为看**任何键**的值（去掉前后空白，`file:` URI 取其路径）；变量开头的路径与路径键下的盘符相对路径加灰色 `mcp-path-unclear`；走查改为广度优先，任何上限被触到（节点、深度、宽度、超长文本）加灰色 `mcp-arguments-not-all-seen`；键名比较去掉 `_` 与 `-` |
| R9-2 | medium | `{"sql": "; delete from t"}`、`{"sql": "(delete from t)"}` 被判为“不是 SQL”，声明过的查询工具因此放行写操作 | 首词在去掉注释与开头的 `;`、`(` 之后取；写入类的词与 `;` 在原文（含注释）里找；`sql` / `statement(s)` 键下不能证明只读的一律算可能写；`query` 键下以写入类首词开头或有 `;` 后接词的算可能写 |
| R9-3 | low | `systemctl` 的值选项（`--legend`、`--check-inhibitors`、`--preset-mode` 的空格写法）不在表里，值被当成动词，注册由 deny 退成 ask | 补上这些选项；另外第一个位置参数不是已知动词时加灰色 `service-manager-unknown-verb`，并在后面的位置参数里找注册类动词 |
| R9-4 | low | `crontab` 的 `-l` 豁免太粗（`-e -l` 落到 ask）；`-V` / `--help` 被误拒 | `-V`、`--help`、`--version` 加进豁免；`-l` 与 `-e` / `-r` / 文件同用会被 crontab 自己拒绝，作为残余写明 |
| R9-5 | low | 列表形式的 `command`（没有 `args`）丢了 deny；`New-CimInstance` 的 WMI 订阅是 ask，而 `Set-WmiInstance` 是 deny | 命令键下的字符串列表拼成一条命令行；`args` / `arguments` / `argv` 都认；`New-CimInstance` 加进 `deny-windows-persistence-tamper`（default 与 strict） |
| R9-6 | info | 白名单扩大后，发往新主机的上传由“规则问”变成“灰色问”（默认策略下仍是问）；声明过的抓取类 MCP 工具访问白名单主机会被放行 | 写进残余：白名单只决定“规则问”还是“交给之后的审计层”；声明抓取类工具是用户的选择 |
| R9-7 | info | 留出集台账是随结果提交的文件，污染判断靠 git 审阅，不是运行时强制 | 写进残余 |

复审者确认没有问题的部分：每一处改动 strict 都至少同样严格（210 个用例对比）；allow 豁免只在“灰色原因恰好只有 `mcp-tool-not-reviewed` 且已声明”时生效，strict 永不放行；MCP 命令的附加动作始终是灰色；改名之后没有丢失原来的 ask；`destination` 拆分没有让原来问的变成不问；走查有界（< 0.3 秒）；留出集默认不打开，去重双向，`split` 与 `holdout` 字段互相约束。复审者的冻结意见：C、E 可以冻结；D 可以冻结（R9-3 到 R9-5 是建议）；A 要先修 R9-1；B 要先修 R9-2。修复之后等复审者复核。

修复之后 dev 上的数字不变（Windows 86 / 94、POSIX 101 / 104，误报率 34.8% / 62.5%）；`boundkeep test` default 1065、strict 318 条 0 失败；`tests/unit/test_m2_rules3.py` 104 个通过（新增 R9-1 到 R9-5 的回归）。

**残余（补充）**：R9-6、R9-7 如上；`crontab -l -e` 一类混用由 crontab 自己拒绝；`file://~/x` 这种不规范的 URI 被当成 UNC 路径处理（仍然命中受保护的名字）。

### 复核（第二轮）

复审者复核：R9-1、R9-2、R9-3、R9-5 关闭，R9-4 部分关闭（`-l` 与 `-e` / `-r` / 文件混用仍是 ask，残余已写明，可以接受）；**没有新的 high / medium，A 到 E 都可以冻结**；确认 `event.py` 与 HEAD 的差异只有 MCP 部分、三个 import 与 `_dispatch` 的一行（文件被意外清空后的恢复是完整的）。另提了两条 low，已修：

| 编号 | 级别 | 问题 | 处理 |
|---|---|---|---|
| R10-1 | low | 声明过的工具：没有 scheme、`ftp://` / `wss://`、写在文字里的 URL 不进网络规则；`shell` / `commands` / `code` 不算命令；`sqlQuery`、`q` 下的 SQL 不检查；`get_and_store` 这样的名字被当成只读，能写 `.git/hooks` 与 `package.json` | 值里的任何 `scheme://` URL（`file:` 除外）都进域名，主机类键（`url`、`host`、`endpoint`、`webhook` 等）下没有 scheme 的值按主机处理；命令键加 `shell`、`commands`、`code`；SQL 按键名识别（含 `sql` / `statement` 的键严格，`query` / `q` / 以 `query` 结尾的键只看可能写的）；只读要求工具名**以读类词开头**且不含写入类的词，写入类词表扩充 |
| R10-2 | low | 路径前有字节序标记（U+FEFF）时不被当成路径；`../.ssh/id_rsa` 这种向上爬的相对路径被放行 | 去掉前后空白之外再去掉不可见字符（BOM、零宽字符）；以 `..` 开头的值加灰色 `mcp-path-unclear` |
| R10-3 | info | 以 `/*` 开头的 SQL 被当成绝对路径（ask） | 谨慎方向，不改 |

修复之后 `tests/unit/test_m2_rules3.py` 136 个通过（新增 R10 的回归）。
