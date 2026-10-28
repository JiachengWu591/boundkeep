# M2-rules-3 独立 X1 审查：留出集 h1、MCP、网络、持久化与递归删除

- 审查对象：工作树（未提交），基线 HEAD `7e1d70b`。范围 A–E 见协调者的请求与 `docs/reports/M2-rules-3.md` 第 2/3/6 节。
- 方法：在两台假机器（posix / windows）上用 `policycli._run_one` / `boundkeep test` 裁决，输入保持惰性（`testuser` 路径、`.invalid` 主机、`CANARY`）；对每条规则把改动前（`git archive HEAD` 的 `old2`）与改动后、default 与 strict 做差分。不执行被审命令，不做 shim 实验。**没有打开留出集**：没有运行 `--open-holdout`，没有读 `eval/datasets/holdout/` 下的数据文件，`eval/holdout-ledger.jsonl` 至今不存在（已确认）。仓库只读，唯一产出是本文件。
- 结论先行：**没有 high；有两条 medium（R9-1、R9-2），都只在"用户把某个 MCP 工具声明为只读"时才成立——随附的默认策略 `mcp_read_only` 为空，所有 MCP 调用都是 gray→ask，不受影响。** 其余为 low/info，均为 deny→ask 的降级或文档问题，没有发现应被拒/询问的动作在默认策略下变成 allow。

## 一、发现

### R9-1（medium）声明为只读的 MCP 工具：路径类后备规则（no-secret-read / ask-mcp-path-outside-project）可被多种写法绕过

`allow-declared-read-only-mcp` 的注释声称"受保护的名字（密钥、凭据、agent 状态、启动文件）照样由它们自己的、无 `tool:` 过滤的规则拒绝"。这个保证只在"该路径被规范化器识别成本机路径"时成立。对一个已声明只读的工具，下面每一种都让 `~/.ssh/id_rsa`（本应 deny）或项目外路径（本应 ask）变成 **allow**（未声明的工具则仍是 gray→ask，无回归）：

1. **未覆盖的路径键名。** `_MCP_PATH_KEYS` 漏了很常见的几个：`file_name`（注意：`filename` 和 `fileName` 都在表里会 deny，但带下划线的 `file_name` 不在 → allow）、`folder`、`location`、`target_file`、`pathname`、`abs_path`、`repo_path`、`notebook_path`、`input`、`uri`、`url`。示例（声明只读，posix）：`{"file_name": "~/.ssh/id_rsa"}` → **allow**；`{"folder": …}`、`{"target_file": …}` 同样。服务器用哪个键名不在用户控制内，所以"声明只读"不该意味着能读密钥。
2. **`file://` 值。** `{"path": "file:///home/testuser/.ssh/id_rsa"}` → **allow**（`_local_path_text` 不认 `file:` 前缀，`_URL_VALUE` 只认 `https?://`）。
3. **前导空格 / 环境变量 / 盘符相对。** `{"path": " /home/testuser/.ssh/id_rsa"}`（前导空格，`_local_path_text` 对未 strip 的文本 `startswith("/")` 为假）→ allow；`{"path": "$HOME/.ssh/id_rsa"}`、windows 下 `{"path": "%USERPROFILE%\\.ssh\\id_rsa"}`、`{"path": "C:Users\\testuser\\.ssh\\id_rsa"}`（盘符相对，`text[1:3]` 不是 `:/`/`:\\`）→ allow。这些取决于服务器是否会把它们解析成真实路径，但规则在不确定时应偏保守。
4. **遍历预算 + LIFO 顺序能把被覆盖的键也挤掉。** `_mcp_walk` 用栈（后进先出）且 `len(out) < 500` 时才继续。`{"path": "/home/testuser/.ssh/id_rsa", "zz": [[…100 项…] ×6]}` → **allow**：`zz` 的 600 个叶子先被弹出，填满 500 的预算，循环在轮到 `path` 之前停止，密钥路径从未被登记。深度（`{"x":{"x":…{"path":secret}}}` 8 层）和宽度（dict 只取前 100 个键，`path` 在第 101 个 → allow）同理。也就是说即使键名正确，攻击者只要在参数里塞一个大的兄弟字段就能把真实路径挤出预算。

严重度定为 medium 而非 high：随附默认策略 `mcp_read_only: []`，开箱即用时每个 MCP 调用都是 gray→ask，上述都不触发；要成立必须 (a) 用户把某工具声明为只读、(b) 命中上述某种写法。但它确实违反了规则注释给出的"声明只读仍挡密钥"的保证，而最常见的键名（`path`/`file_path`/`filename`/`source`/`paths`/`dir` 等）与常见写法是被正确覆盖、能 deny 的。

建议：让 `allow-declared-read-only-mcp` 在"遍历被预算/深度/宽度截断"或"出现了像本机路径、却落在未识别键名下的值"时不再豁免（即给动作补一个非 `MCP_GRAY` 的灰色原因，使其退回 gray→ask）；并补齐 `file_name`、`folder`、`location`、`target_file`、`pathname`、`abs_path`、`repo_path`、`notebook_path` 等键名、`file://` 值、对值先 strip。验收：上面每一行都应从 allow 变 deny 或 ask。

### R9-2（medium）声明为只读的 SQL/query 工具：前导 `;` 或 `(` 让写语句绕过 mcp-sql-not-read-only → allow

`sql_is_read_only` 取第一个词判断是否像 SQL：`first = stripped.split(None,1)[0].casefold().rstrip("(;")`。它只 **rstrip** `(;`，不处理前导字符，所以：

| 输入（声明只读的 `mcp__db__query`） | first 词 | 裁决 |
|---|---|---|
| `delete from t` | `delete` ∈ `_SQL_FIRST` → 判为可能写 → 加 note | **gray**（正确） |
| `; delete from t` | `;` → `rstrip("(;")` → `""` ∉ `_SQL_FIRST` → 返回 None（"不像 SQL"）→ 不加 note | **allow** |
| `(delete from t)` | `(delete` → rstrip 不动前导 `(` → ∉ `_SQL_FIRST` → None → 不加 note | **allow** |

也就是在 `delete`/`drop`/`update` 前放一个 `;` 或 `(` 就能让"看起来会写"的判断失灵，mcp-sql-not-read-only 不再附加，动作 gray 原因恰好只剩 `MCP_GRAY` → 命中 allow 豁免。对一个被声明只读、本意只跑 SELECT 的 query 工具，这等于把写权限交回去，服务器会照原样执行。`SELECT … INTO t2 …`、`select 1; delete …`、`/* c */ delete …` 都仍正确判为 gray（写词在正文里被 `_SQL_WRITE_WORD` 命中），只有前导 `;`/`(` 这类"首词不像语句"的情形漏了。

严重度 medium（同样只在声明了 query 工具时成立，且 SQL 判断本就声明为启发式——报告残余 3）；但报告自己的回归用例断言 `delete from t` → gray，而 `; ` 前缀可轻易击穿，所以作为具体可复现的绕过列出。建议：首词取 `lstrip("(;").split()[0]`（去掉前导 `(`/`;`/空白再取词），并且当语句含多条（`;` 分隔出不止一段）时一律判为可能写。

### R9-3（low）systemctl：个别"带值长选项"不在选项表里，其值被当成动词，使注册命令从 deny 降为 ask

`_h_service_manager` 把第一个位置参数当 subcommand，选项值靠 `_SYSTEMCTL_OPTS` 消费。表里漏了几个真实的带值选项，于是其值被错当成动词：

- `systemctl --legend no enable foo` → 动词被读成 `no` → **gray**（strict ask），而不是 deny；
- `systemctl --check-inhibitors no enable foo` → gray；
- `systemctl --preset-mode full preset foo` → 动词读成 `full` → gray。

（`--legend=no enable foo` 这种 `=` 形式反而正确 deny，因为 `=` 把值并进同一个 token，`enable` 仍是第一个位置参数。）这些选项以空格分值的形式是否被真实 systemctl 接受，取决于 getopt，但结果方向是把一个注册命令从 deny 降级到 ask——不是 allow。另外 `launchctl asuser 501 launchctl load x.plist` 的外层动词是 `asuser` → ask，内层 `launchctl load` 作为参数未被单独解析，也绕过了 deny-service-registration（仍 ask）。

正面确认（都 deny）：`systemctl enable/--user enable/-q enable/-t service enable/--type=service enable/-H host enable/--root /tmp/r enable/'enable'/e''nable/-- enable/sudo systemctl enable//usr/bin/systemctl enable`；`launchctl load/-w load/load -w/bootstrap/submit/enable`。动词大小写变体（`ENABLE`/`Enable`）、动态动词（`$V`）→ gray（`service-manager-dynamic-verb` 或未知动词），正确。

建议：把 `--legend`、`--check-inhibitors`、`--preset-mode` 等带值选项补进 `_SYSTEMCTL_OPTS`。影响小（只降到 ask），可在冻结时列为低优先。

### R9-4（low）deny-crontab-install 的 `flags_none: ["-l"]` 过粗：`-l` 与安装/编辑/删除同时出现时落到 ask

只要命令里出现 `-l`，deny-crontab-install 就不匹配，落到 ask-scheduled-jobs：`crontab -e -l`、`crontab -r -l`、`crontab -l jobs.txt`、`crontab -le`、`crontab -rl`、`crontab -l -r` 全是 **ask** 而不是 deny。真实 crontab 多数实现对"同时给 -l 和 -e/-r"会报"only one option permitted"而拒绝执行，所以实际危害低；但豁免的意图是"仅列出"，范围应收窄。反方向的小瑕疵：`crontab -V`、`crontab --help` 现在是 deny（无 -l），属于无害命令被误拒。建议：豁免条件改成"有 `-l` 且无 `-e`/`-r`/`-i` 且无文件操作数"，并把 `-V`/`--help`/`-n`/`-T`（校验类）排除出 deny。都只影响 deny↔ask，不涉及 allow。

### R9-5（low）两处"现代等价写法"未进 deny，降到 ask

1. 列表形式的 `command` 且没有 `args`：`{"command": ["rm","-rf","~"]}` → 每个 token 被当成**独立**的 bash 命令解析（`rm` 单独 → gray，`-rf`、`~` 各自 → gray），危险的 `rm -rf ~` 没有作为一条命令被 deny，整体落到 gray→ask。`{"command":"rm","args":["-rf","~"]}`（有 args）才会正确拼接并 deny。建议：当 `command` 是字符串列表且无 `args` 时，按 argv 拼接成一条命令（和 args 分支一致）。
2. `New-CimInstance -Namespace root\subscription …`（WMI 事件订阅持久化的现代写法）→ ask，而旧的 `Set-WmiInstance` → deny。两者达成同样的持久化。建议：若要 deny WMI 订阅，`New-CimInstance` 也应进 `deny-windows-persistence-tamper`（现在仍 ask，非 allow）。

### R9-6（info）网络白名单扩充：对新主机的上传/外传由 ask 变 gray；声明只读的抓取类 MCP 工具对白名单主机直接 allow

- 新增 `githubusercontent.com`、`crates.io`、`registry.yarnpkg.com`、`proxy.golang.org`、`sum.golang.org`、`api.nuget.org` 后，对这些主机的**上传/外传**（`curl -T notes.txt https://uploads.githubusercontent.com/x`、`curl -d @notes.txt https://gist.githubusercontent.com/x`、`curl -F f=@notes.txt https://crates.io/…`）从 ask 变为 **gray**。在随附配置（无 LLM、`emit_allow` 关）下 gray 仍然 == ask，所以最终闸门没有放松；但语义从"问"变成了"无决定"（将来接 LLM 或开 allow 预设时，gray 是可被自动放行的那个带）。报告第 2 节已说明"白名单上不等于放行，命令仍需 allow 规则"，而网络命令没有 allow 规则，所以 shell 侧不会真正 allow——这一条属于口径提醒，不是回归。
- 但声明只读的抓取类 MCP 工具 + 白名单主机会真正 **allow**：`mcp__web__fetch {"url":"https://raw.githubusercontent.com/attacker/repo/main/x"}`（声明只读）→ allow（无路径、无命令、主机在白名单、`net-allowlist` 不触发）。`github.com` 本就在白名单，加入 `githubusercontent.com` 扩大了这类工具可无询问拉取的内容主机范围（把攻击者可控的内容带进来）。这在"声明只读的抓取工具"的设计残余之内，但建议在残余里写明。
- 正面确认：`destination: known/unknown` 拆分无回退。目的地不明（`git fetch`、`uv sync`、`npm ci`、`curl $URL`）走 `net-unknown-destination` → ask；白名单外主机（`a.example.invalid`、`ssh host.example.invalid`、`evilgithubusercontent.com`、`githubusercontent.com.example.invalid`）→ `net-allowlist` → ask；真子域判断正确。多个域名里只要有一个不在白名单仍 ask。

### R9-7（info）留出集台账是"随结果提交的普通文件"，污染判定靠 git 评审而非强制

- 污染逻辑本身正确：任一更早的打开若 `policy_sha256`（整份策略文本的 sha256）不同或 `holdout_hash` 不同，就自动声明污染；同策略同样本重复打开不算污染。策略指纹用整份文本，连注释改动也会触发污染——偏保守，安全方向。
- 但 `eval/holdout-ledger.jsonl` 是一个普通的被提交文件，agent 对 `eval/` 的写是普通项目写（allow），所以"自动声明污染"依赖没人删改台账、靠 git 评审兜底，不是 boundkeep 运行时能强制的。这与项目定位一致（评测诚信靠流程），作为 info 列出。
- 其余 E 项检查均正常：`schema._consistent` 双向强制 `split == split_of(self)`，带 `holdout` 字段必为 `holdout` 切分、`holdout` 切分必带该字段，手写样本无法靠哈希把留出样本塞进 dev，也无法把非留出样本冒充 holdout；`dataset.validate` 双向查重（留出样本的 `action_key`——平台+工具+输入，忽略任务意图——若已在 dev/test 则报错；新加的 dev/test 样本若与留出样本同 action 也报错）；`importer` 对已在 dev/test 的动作丢弃（`already-in-dev-or-test`）；默认运行用 `dataset.sealed` 的非留出部分，`--open-holdout` 才测留出集且打开前先写台账；`--check` 与普通运行只打印留出集指纹（id/键/标签的哈希），不把留出样本输入喂进运行。`run_eval.py --check` 实测：`802 samples … holdout 169, 指纹 0aacd20fdef20db6`，与封存记录一致。

## 二、其他核对

- **严格至少同样严格。** 逐条差分（d1 矩阵，约 210 条）确认：default 变 deny 的每一条，strict 同样 deny 或更严（例如 `find -exec rm`、`shred`、`Get-ChildItem … | Remove-Item` 在 strict 是 deny，在 default 是 ask）；没有出现 default=deny 而 strict<deny 的情形。新增的五条 deny 规则（crontab-install、service-registration、recursive-permission-change、find-delete-outside-project、windows-persistence-tamper）在 default 和 strict 里逐字相同；原有的 ssh-write / system-config / shell-startup / windows-persistence 在 strict 本就是 deny（strict 未改这几条，仍更严）。
- **`boundkeep test`**：default 1065 条、strict 318 条，0 失败。
- **单元测试**：`tests/unit/test_m2_rules3.py` + `tests/unit/test_evalkit_holdout.py` 共 72 passed。
- **遍历有界、无 DoS**：200k 字符的 command/path、100 条命令、400 条路径、100 个 URL 的 MCP 输入都在 0.3s 内返回，方向安全（超长文本 `_text` 返回 None → 不解析 → gray；超长路径仍 deny）。
- **改名未丢保护**：旧 `ask-system-config-write`/`ask-ssh-write`/`ask-find-delete`/`ask-recursive-permission-change`/`ask-disk-tools` 在 default 已全部被对应的 deny 规则取代或升级，没有发现某条路径因改名而两条规则都不命中的情形（d1 矩阵里对应行都从 ask 变 deny，无变 gray/allow 的）。`~/.local/bin`、`~/bin` 按设计从 deny 拆到 `ask-user-path-dirs-write`（ask），是有意的放宽，已在报告说明。
- **MCP 命令附加动作不会被放行**：`{"command":"git status"}`（无害）→ gray（附加动作带 `mcp-command:<tool>`，所以主动作 gray 原因不止 `MCP_GRAY`，即使声明只读也不豁免）；`{"command":"rm -rf ~"}` / `{"cmd":"rm","args":["-rf","~"]}` → deny。附加的 shell 动作始终 `gray=True`，只能触发 deny/ask。
- **声明匹配边界**：`mcp__*`（通配服务器）、`mcp__gh*`、`MCP__gh__x`（大小写）、`mcp__gh__`（空工具）、`mcp__gh__x y`（空格）、`mcp__gh__**` 都被 schema 拒绝；`mcp__gh__get_*` 这类"整服务器 + 工具前缀"接受。工具名匹配区分大小写（与 `mcp_server` 一致），`mcp__FS__read_file` 不匹配 `mcp__fs__read_file`——正确，但属于易踩的配置坑（键名 casefold，工具名不 casefold），值得在文档里提一句。`mcp__a__*` 会把服务器 `a` 的所有工具（含名字里带 write 的）声明只读——是用户自己用通配的结果。

## 三、试过但没有成立（没有发现的绕过）

- 默认策略下让任何 MCP 调用变 allow：不可能（`mcp_read_only` 为空，所有 MCP 调用 gray→ask）。
- 让 `net-allowlist`/`net-unknown-destination` 对白名单外主机不 ask：没找到；真子域、多域名、UNC 主机（`\\host.example.invalid\share`）都正确进 ask。
- 让新的 deny 规则对项目内路径误伤：`find . -delete`、`chmod -R 755 .`、`chmod -R u+x scripts`（项目内）仍 gray（default）/ask（strict），没有变 deny。
- 用包装器/路径限定绕过注册 deny：`sudo systemctl enable`、`env systemctl enable`、`/usr/bin/systemctl enable`、`/bin/launchctl load`、`& 'Set-MpPreference'`、`Defender\Set-MpPreference`、`Microsoft.PowerShell.Management\Stop-Computer`、`TAKEOWN.EXE`、`bcdedit.exe` 都仍 deny。
- 用列表/嵌套把 `{"command":…}` 的危险命令变 allow：声明只读也不行（有 `mcp-command` 灰色原因，豁免不生效）。
- 让留出集在普通运行里被测、或让带 `holdout` 字段的样本落进 dev/test：schema 与 validate 双向拦住。

## 四、结论

- **是否有 high / medium**：没有 high；两条 medium（R9-1、R9-2），均仅在用户声明了只读 MCP 工具时成立，默认策略不受影响。
- **各组能否冻结**：
  - **A（MCP 参数）**：建议先处理 R9-1（至少：遍历被截断或出现未识别键名下的路径值时，不给 allow 豁免；并补齐常见路径键名与 `file://`）。在此之前，随附默认策略安全（不声明任何工具），但规则注释里"声明只读仍挡密钥"的保证不准确。修好后可冻结。
  - **B（只读声明）**：matcher 的豁免逻辑严谨正确（只在灰色原因恰好等于 `(MCP_GRAY,)` 且声明过时放行，strict 永不放行——已确认 strict+声明仍 gray/ask）。但 R9-2（SQL 前导 `;`/`(`）是声明 query 工具时的真实写绕过，**修好前 B 不宜冻结**（或在文档里明确"不要声明 SQL/query 类工具为只读"）。
  - **C（网络）**：可冻结。无闸门回归；R9-6 作为口径提醒/残余。
  - **D（持久化与递归删除）**：可冻结。R9-3/R9-4/R9-5 都是 deny→ask 的降级（非 allow），建议修但不阻塞；strict≥default 已确认。
  - **E（留出集框架）**：可冻结。R9-7 为 info（台账是流程性诚信，非运行时强制）。

## 五、建议声明的残余

1. MCP 参数只看能识别为本机路径的绝对/`~`/盘符路径；相对路径、二进制参数、服务器自读写的内容看不到；读写判断是按工具名启发式（报告残余 1，准确）。**补充**：声明只读的工具，若服务器使用未覆盖的键名、`file://` 值，或参数被超大兄弟字段挤出遍历预算，其路径不被路径规则审查（R9-1，建议修）。
2. 声明只读的 MCP 工具仍会把参数原样发给服务器（报告残余 2，准确）；对抓取类工具，参数里的 URL 指向白名单主机时会被 allow，`githubusercontent.com` 等的加入扩大了这一范围（R9-6）。
3. SQL 判断是启发式：前导 `;`/`(` 的写语句会被判为"不像 SQL"而漏过（R9-2，建议修）；存储过程等服务器侧的写看不到（报告残余 3）。
4. 网络层分不清上传/外传与正常推送，一律 ask；白名单主机上的上传在随附配置下仍是 ask（gray），但语义是"无决定"（R9-6）。
5. 新增 deny 的降级面：个别 systemctl 带值长选项的空格形式、`crontab` 与 `-l` 混用、列表形式 `command`、`New-CimInstance` WMI 订阅会落到 ask 而非 deny（R9-3/4/5），都不会变 allow。
6. 留出集台账是随结果提交的普通文件，污染判定靠 git 评审兜底，不是运行时强制（R9-7）。
7. 本审查未覆盖：真实 MCP 服务器对各种路径/URL 写法的实际解析行为；留出集攻击样本（尚未写）；`--open-holdout` 的实跑（按要求未打开）。

## 六、操作透明度

本轮没有执行任何被审命令，没有做 shim 实验，没有打开留出集（未运行 `--open-holdout`，未读 `eval/datasets/holdout/` 数据文件，`eval/holdout-ledger.jsonl` 不存在）。只用 scratchpad 里的 `h.py`/`t.py`/`m1.py`/`c*.py`/`d1.txt`（都不在仓库内）对规则做裁决，用 `git archive HEAD` 取基线做差分，并重跑了 `boundkeep test`、`test_m2_rules3.py`、`test_evalkit_holdout.py` 和 `run_eval.py --check`。除本文件外未修改任何文件。


---

# 复核（第二轮）：R9-1 到 R9-5 的修复

- 范围：只复核 R9-1..R9-5 的修复（`docs/reports/M2-rules-3.md` 第 7 节）。方法同上一轮：两台假机器上裁决，输入惰性，没有打开留出集（`eval/holdout-ledger.jsonl` 仍不存在），没有 shim 实验。
- **event.py 的差异范围已确认**：`git diff HEAD -- src/boundkeep/normalize/event.py` 只有三处：import（新增 `shlex`、`collections.deque`，`typing` 加 `Final`）、MCP 段（`_mcp_action` 换成 `MCP_GRAY` 常量、键表、`_mcp_walk`、`_mcp_access`、`_local_path_text`、`sql_is_read_only`、`_mcp_actions`）、`_dispatch` 里的一行（`return _mcp_actions(ctx, tool, tool_input)`）。删除的 4 行恰好是旧的 `from typing import Any`、`def _mcp_action`、它的 `return _gray(...)`、`_dispatch` 的旧调用。没有发现意外清空后恢复时遗留的其他差异。
- 结论先行：**R9-1、R9-2、R9-3、R9-5 关闭；R9-4 部分关闭（剩下的一半已列为残余，可接受）。没有新的 high / medium。** 另有几条 low（R10-1..R10-3），其中 R10-1 是我上一轮观察到却没写进报告的，这里补上并说明。

## 一、逐条

| 编号 | 结论 | 证据（声明只读 / 未声明 / strict+声明） |
|---|---|---|
| R9-1 | **关闭** | 上一轮全部用例重跑：键名 `file_name`/`folder`/`location`/`target_file`/`pathname`/`abs_path`/`repo_path`/`notebook_path`/`input`/`uri`/`url` 下的 `~/.ssh/id_rsa` 全部 deny/deny/deny；`file:///…`、`file:/…`、前导空格、尾随空格、`//…`、`~testuser/…`、`proj/../.ssh/…` 全部 deny；`$HOME/…`、windows 的 `%USERPROFILE%\…`、路径键下的 `C:Users\…` → gray（`mcp-path-unclear`），不再 allow；深度 8、宽度 101 → gray（`mcp-arguments-not-all-seen`）；"大兄弟字段挤预算"那条（`{"path": 密钥, "zz": [600 项]}`）→ deny（广度优先先看到顶层 `path`）。新绕法尝试：不间断空格 / em 空格前缀 → deny；`FILE://`、`File://`、四斜杠、`file://localhost/…`、百分号编码 → deny；`\\?\` 加正斜杠、`\\.\` 设备前缀、混合斜杠、`file:///C|/…` → deny；路径拆进列表、旁边夹非字符串值 → deny；超过 4 MiB 的兄弟值 → deny 且带 `mcp-arguments-not-all-seen`。 |
| R9-2 | **关闭** | `; delete from t`、`(delete from t)` → gray（`mcp-sql-not-read-only`）；`select 1; delete …`、`SELECT … INTO …`、`select 1 -- ; delete` → gray。新绕法尝试：换行分隔的第二条语句、全角分号 `；`、`call p()`、`exec p` → gray；`with x as (select 1) select …`、大小写混写的 `SeLeCt` → allow（正确，只读）。`query` 键下 `update readme` → gray（保守的误报）、`how to delete a branch` → allow（搜索文本，正确）、`x; y` → gray。 |
| R9-3 | **关闭** | `--legend no`、`--check-inhibitors no`、`--preset-mode full`、`--image-policy x`、`--what x` 后接注册动词 → deny；未知首个位置参数（`systemctl foo enable`、`--foo bar enable`、`--unit foo enable`）→ deny 且带 `service-manager-unknown-verb`；`launchctl foo load` → deny。已知非注册动词后面出现 `enable` 字样（`systemctl status enable`、`list-units enable`、`start enable.service`）→ gray，正确（那是单元名，不是动词）。剩下的一点：`launchctl asuser 501 launchctl load x.plist` 仍是 ask（外层动词 `asuser` 是已知动词，内层不单独解析），只到 ask，不变 allow，列为残余。 |
| R9-4 | **部分关闭** | `crontab -V`、`--help`、`--version` → ask（不再误拒）。`-l` 与 `-e`/`-r`/文件同用（`crontab -l -e`、`-le`、`-rl`、`-l jobs.txt`）仍是 ask 而非 deny；作者已把它写进残余（crontab 自己会拒绝混用）。可接受。 |
| R9-5 | **关闭** | `{"command": ["rm","-rf","~"]}` → deny；`{"cmd":"rm","args":[…]}` → deny；嵌套的 `command`+`args` → ask（不再是 gray）；`New-CimInstance -Namespace root\subscription …` → deny（default 与 strict）。`New-CimInstance -ClassName Win32_Process` 也随之 deny（创建进程，合理）；`Get-CimInstance` 仍 gray。 |

strict 仍然至少同样严格：本轮 114 条 D 组用例里没有 strict 比 default 松的。`boundkeep test` default 1065 / strict 318、`test_m2_rules3.py` 104 个按作者报告，本轮没有重跑全量。

## 二、新发现

### R10-1（low）声明只读工具：几类"上一轮已观察到、但我没写进报告"的缺口（我的遗漏）

以下四类在上一轮的探测里已经出现，但没有写进 R9 编号的发现，属于我的遗漏，在这里补上。它们都只在用户声明了只读工具时成立（未声明时都是 gray→ask）：

1. **URL 只认 `http(s)://` 开头。** 声明只读的 `mcp__web__fetch`：`{"url": "a.example.invalid/x"}`（无协议）、`ftp://…`、`wss://…`、`"see https://…"`（嵌在文本里）→ **allow**。这与 `allow-declared-read-only-mcp` 注释里"白名单外的主机仍会问"的说法不一致（`HTTPS://` 大写、前导空格、`//host` 已经正确 ask）。多数抓取服务器只接受 http(s)，所以实际可利用性较低。建议：任意 `scheme://` 都提取主机进入域名，非 http(s) 的协议加 `unparseable-url`；`url`/`uri`/`endpoint`/`host` 键下无协议的值也当作主机处理，或至少加一个灰色原因。
2. **命令类键名不全。** 声明只读工具带 `{"shell": …}`、`{"commands": [...]}`、`{"code": …}` → **allow**（只有 `command`/`cmd`/`script` 等会被识别）。声明一个接受 shell 或代码参数的工具为只读本身就是误声明，但规则注释说"没有命令参数"才豁免。建议：把 `shell`、`commands`、`code`、`scripts`、`exec` 等加进命令键，或对不认识但像命令的键加灰色原因。
3. **SQL 只在 `sql`/`query`/`statement(s)` 键下检查。** `{"sqlQuery": "delete from t"}`、`{"q": "delete from t"}` → **allow**。建议：键名比较已去掉 `_`/`-`，可以再加 `sqlquery`、`q`、`querytext` 等，或者对任何键的值，只要首词是写入类 SQL 动词就加 `mcp-sql-not-read-only`。
4. **按工具名猜读写，与前缀声明叠加。** 声明 `mcp__fs__get_*` 时，`mcp__fs__get_and_store` 这类名字含读词、写词却不在写词表里的工具被当作只读访问，写项目内的 `.git/hooks/pre-commit`、`package.json`、`.github/workflows/ci.yml`、`.claude/settings.json` → **allow**（`.env` 仍 deny）。这需要服务器真的有这样命名的写工具、且用户用前缀声明覆盖了它。建议在文档里提醒"前缀声明会覆盖服务器以后新增的工具"，并把 `store`、`modify`、`overwrite`、`writeback` 等加进写词表。

### R10-2（low）R9-1 修复之后仍看不到的两种路径

- **字节序标记前缀。** `{"path": "\ufeff/home/testuser/.ssh/id_rsa"}` → **allow**（Python 的 `strip()` 不去掉 U+FEFF）。服务器多半把它当作文件名的一部分（打开失败），可利用性低。建议 `_local_path_text` 先去掉 `\ufeff` 与零宽字符。
- **以 `..` 开头的相对路径。** `{"path": "../.ssh/id_rsa"}`、`{"path": "../../etc/passwd"}` → **allow**。这属于作者残余 1（相对路径不处理，因为可能是远端仓库里的路径），但以 `..` 开头的值既不是远端仓库内的路径，又正好越出项目。建议：路径键下以 `..` 开头的相对值加 `mcp-path-unclear`，让声明只读工具也退回询问；同时 windows 下非路径键里的盘符相对值（`{"note": "C:Users\\…"}`）→ allow，与"只在路径键下判断盘符相对"的设计一致，可以接受。

### R10-3（info）以 `/` 开头的 SQL 被当成路径

`{"sql": "/*x*/select 1"}` → ask（`ask-mcp-path-outside-project`）：值以 `/` 开头，被任何键的本机路径判断当成绝对路径。方向保守（多问一次），只影响以注释开头的只读查询。如在意误报，可以在 SQL 键下先剥掉注释再做路径判断。

## 三、残余清单是否完整

作者第 7 节的"残余（补充）"加上第 4 节，覆盖了 R9-6、R9-7、crontab 混用、`file://~/x` 当 UNC。建议补充或改写：

1. 第 4 节残余 1 的措辞已过时："只看绝对路径"应改为"看任何键的值里能识别为本机的绝对、`~`、UNC、盘符与 `file:` 路径；相对路径（包括以 `..` 开头、越出项目的）不处理；字节序标记前缀的值看不到"（R10-2）。
2. 声明只读工具时：URL 只认 `http(s)://`（R10-1 第 1 点）、命令与 SQL 只在列出的键名下识别（R10-1 第 2、3 点）、按工具名猜读写会被前缀声明放大（R10-1 第 4 点）。修或写进残余均可。
3. `launchctl asuser … launchctl load` 的内层不解析，落到 ask（R9-3 剩下的一点）。
4. 第 4 节残余 3（SQL 里会写的函数看不到）已用 `select setval('s', 1)` → allow 确认，描述准确。

## 四、结论

- R9-1、R9-2、R9-3、R9-5：**关闭**。R9-4：**部分关闭**，剩余部分已列为残余，可接受。
- 是否有新的 high / medium：**没有**。新增的 R10-1、R10-2 为 low，R10-3 为 info，都只在用户声明了只读 MCP 工具时成立，或只会多问一次。
- 能否冻结：
  - **A（MCP 参数）**：可以冻结。R9-1 已关闭；R10-1/R10-2 建议修，不修就按第三节写进残余。
  - **B（只读声明）**：可以冻结。R9-2 已关闭；matcher 的豁免逻辑本轮未改动。
  - **C（网络）**：可以冻结（本轮无改动）。
  - **D（持久化与递归删除）**：可以冻结。R9-3、R9-5 关闭；R9-4 剩余部分与 `launchctl asuser` 作为残余。
  - **E（留出集框架）**：可以冻结（本轮无改动；R9-7 已写进残余）。
- 残余清单：按第三节补充后完整。

## 五、操作透明度

本轮没有执行任何被审命令，没有 shim 实验，没有打开留出集（未运行 `--open-holdout`，未读 `eval/datasets/holdout/`，台账不存在）。只用 scratchpad 里的 `m1.py`、`c1/c2/c5/c6.py`、`t.py`、`d2.txt` 做裁决。除在本文件末尾追加本节外，未修改任何文件。