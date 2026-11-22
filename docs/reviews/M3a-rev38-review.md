# 规格修订 38 的复审

日期：2026-11-19。代码：`fbe7fcb`（`main`，与 `origin/main` 相同；代码提交是 `98d4ff5`）。

审查对象（`git show 98d4ff5 -- src`）：
- `normalize/event.py`：`_resolved_forms` 给盘上解析出来的那一份也带上 `extra_reasons`；新的 `_CWD_READINGS`；`_refs` 的标记条件和去重；
- `audit/send_gate.py`：只改了 `_hidden_match` 的注释；
- 规格开头修订 38 的段落、§9.2 两条，`docs/privacy.md`、`docs/threat-model.md` 对应的几句，修订 37 记录里的四处更正；
- 记录 `docs/reports/M3a-rev37-review-fixes.md`、两个提交说明、新测试 `tests/unit/test_m3a_rev37_review_fixes.py`。

**这不是独立复审。** 修订 38 是这个会话写的，使用者说"复审修订38"。下面的结论都重新量过，没有照搬记录里的说法。另请了一个子代理单独找错，只给了它代码、规格、隐私和威胁模型文档、记录、修订 37 的复审和新测试，没给我自己的判断。它报的每一条都在这个会话里用另写的脚本、另搭的目录重新量过才写进来（表里的"谁发现"一列）。

**本次改了什么**：
- 新增这份报告。
- 状态说明里加了指向这份报告的几行。
- 没有改 `src`、规格正文、策略、测试和脚本。

**本次没有做的事**：
- 没有读 `.env`，没有用 LLM 密钥，没有访问真实 LLM 服务。探针里的 `.env` 都是 scratchpad 里编出来的文件（内容 `MADE_UP=1`）。
- 没有读 `eval/authoring/h1-*`、`h2-*` 和留出批次，没有改系统设置。子代理也按这几条做，没有改仓库。
- 没有跑 `claude`，没有跑全量和语料：只读代码，跑相关的脚本。
- 没有在任何盘的根目录下建文件或目录。scratchpad 里搭的目录（目录联接、名字以点结尾的目录、8.3 短名）用完都删了，先删联接。

**怎么量的**：
- 两份代码：工作区（`fbe7fcb`，代码同 `98d4ff5`）和 `1499e14` 的 `src`（修订 38 时导出的 `tree-1499e14`）。每个脚本都核对加载的是哪份文件，不对就停；走 PowerShell 的都先等解析器就绪（`psparse.warm_up`）。
- 整条链路：用测试里的假后端（`FakeBackend`，什么都放行）走完整条 `pipeline.decide`，默认策略；要看"没有后端"时去掉后端。Windows，事件的 `cwd` 和项目相同。
- 脚本（scratchpad）：
  - `rv38r_mine.py`，14 条：从展开出来的目录 `Set-Location D:sub`、`D:..\x`、`\sub`、`Push-Location D:sub`；事件工作目录的另几种写法（结尾的 `\`、大写、`/`）；经过目录联接、8.3 短名到达事件的工作目录；
  - `rv38r_tdot.py`，11 条：名字以点结尾的目录旁边有同名的目录联接或普通目录，通配符只匹配到带点的那个（重新量子代理的发现 1、2）；`rv38r_tdot_refs.py` 打出规则层给的路径和原因；
  - `rv38r_real.ps1`：同样的目录里 PowerShell 5.1 实际拷走了什么；
  - `rv38r_globcwd.py`，4 条：切换到事件自己的工作目录之后的通配符（重新量子代理的发现 3）；
  - `rv38r_r2left.py`，4 条：仍算两份的情形；
  - `rv38r_numbers.py`：从原始输出重新数记录里的数字。
- 子代理：脚本在 scratchpad 的 `rv38r_agent\` 下，每个脚本都核对加载的是哪份代码、解析器是否就绪。它重跑了新测试在两份代码上的结果，没有重跑语料、探针和原有差分。

## 1. 结论

**修订 38 的三处修复本身都成立：量过的每一种写法，变量的值都不再进请求。但 R37-1 的修法带出一处判决变松（R38-1，中危）：通配符匹配到的目录在盘上解析出来的那一份多了 `glob-match`，递归读不再往下找，名字以点结尾的目录旁边有目录联接时，读到 `.env` 的命令由拒绝变成灰色。规格、记录说的"规则层的判决不变"不对。**（2026-11-21 更正："读到 `.env` 的命令"指 PowerShell 5.1 这类去掉尾随点的程序；那种布局里 Git Bash 的 `tar`、`grep -r`、`cp -r` 读的是空的 `kq.`，读不到 `.env`。见修订 39 的复审 R39-5。）

- 原因：`_native_dir`（`event.py` 第 1292 到 1301 行）对"不确定"的路径，只有 `paths.reading_only(ref.reasons)` 为真时才往下找；`reading_only` 要求每个原因都在 `_READING_REASONS` 或 `_INFO_REASONS` 里（`paths.py` 第 307 到 317 行）。`glob-match` 不在里面。修订 37 的复审核对过 `variable-expanded` 在 `_INFO_REASONS` 里、`_native_dir` 结果不变；修订 38 给另一份路径加 `glob-match` 时没有再核对。
- 验证没有拦住它：语料、探针、原有差分里都没有"名字以点结尾的目录加上目录联接"的布局；新测试和变异只看发送那一边，没有钉住拒绝。
- 记录里的数字都对得上原始输出（第 3 节）。

**高危 0，中危 1，低危 1，信息 3。**

| 编号 | 级别 | 一句话 | 要后端吗 | 谁发现 | 来源 |
|---|---|---|---|---|---|
| R38-1 | 中（判决变松，修订 38 引入） | 通配符只匹配到名字以点结尾的目录、而同名不带点的是指向要保护文件的目录联接时，`rg x ???`、`tar -czf o.tgz ???`、`Copy-Item -Recurse ??? b` 原来拒绝（`no-secret-read`），现在灰色：没有后端时问，有后端时送审，被操纵的模型能放行 | 不要（没有后端时由拒绝变问） | 子代理 | 修订 38 |
| R38-2 | 低（判决偏松，原来就有） | 同样的布局，同名不带点的是普通目录时，两版都是灰色；直接写 `kq.` 两版都拒绝。通配符匹配到的那一份本来就带 `glob-match`，一直不往下找 | 不要 | 子代理 | M3a 起 |
| R38-3 | 信息（代价没写全，修订 38 引入） | `Set-Location $env:PROJ_DIR`（值就是事件的工作目录）或 `Set-Location $PWD` 之后，`Get-Content *.txt` 只发 `*.txt`，项目里匹配到的文件一个都不发；规格只写了 `gen.py` 代替 `<project>/gen.py` | 要 | 子代理 | 修订 38 |
| R38-4 | 信息（多问，原来就有） | 经过目录联接、8.3 短名、带尾随点的值到达事件的工作目录时，同一个目录仍算两份，9 个路径仍问；规格"同一个目录的两份工作目录，路径只留一份"说宽了 | 要 | 我（联接、8.3），子代理（尾随点） | 修订 37 |
| R38-5 | 信息（文档） | 因为 R38-1，规格修订 38 的"不变：规则层和它的判决"、状态行，记录第 1 节"判决都不变"、第 3 节"在规则层补原因"、`_resolved_forms` 的注释，都没说到递归读 | 不涉及 | 两边都发现 | 修订 38 的文字 |

R38-1 是要紧的一条。

## 2. 发现

### R38-1（中，判决变松，修订 38 引入）：通配符匹配到的目录经过链接时，递归读不再往下找

布局（`rv38r_tdot.py` 的 J）：事件的 `cwd` 和项目都是 `projj`，里面有：
- `kq.`：名字以点结尾的普通目录，用 `\\?\` 前缀建的（普通的 Win32 调用会把尾随点去掉）；
- `kq`：指向 `projj\secretsz` 的目录联接，`secretsz` 里有 `.env`；
- 通配符 `???` 只匹配到 `kq.`。

规则层：`_glob_refs` 给 `kq.` 两份路径。第一份 key 去掉尾随点（`…/projj/kq`）；第二份是它在盘上解析出来的 `…/projj/secretsz`。两份都只差读法（`trailing-dots-spaces-ambiguous`）。修订 37 里第二份的原因是读法加上 `resolved-on-disk`，`reading_only` 为真，`_native_dir` 往下找，找到 `secretsz\.env`，`no-secret-read` 拒绝。修订 38 给第二份加上 `glob-match`（`event.py` 第 987 行），`reading_only` 为假，不往下找。

规则层给 Bash `rg made ???` 的路径（`rv38r_tdot_refs.py`）：

| key | 新代码的原因 | `1499e14` 的原因 |
|---|---|---|
| `…/projj/???` | `glob` | 同左 |
| `…/projj/kq` | `trailing-dots-spaces`、`trailing-dots-spaces-ambiguous`、`glob-match` | 同左 |
| `…/projj/secretsz` | 同上，加 `resolved-on-disk` | `trailing-dots-spaces`、`trailing-dots-spaces-ambiguous`、`resolved-on-disk` |
| `…/projj/secretsz/.env` | 没有 | `recursive-scan`（递归读找到的） |

整条链路（`rv38r_tdot.py`）：

| 工具 | 命令 | 新代码 | `1499e14` |
|---|---|---|---|
| Bash | `rg made ???` | 灰色：没有后端问，有后端送审、被放行 | 拒绝（`no-secret-read`） |
| Bash | `tar -czf out.tgz ???` | 同上 | 拒绝 |
| Bash | `grep -r made ???` | 问（`ask-shell-read-outside-project`） | 拒绝 |
| PowerShell | `Copy-Item -Recurse ??? backup` | 灰色，同上 | 拒绝 |
| PowerShell | `rg made ???` | 灰色，同上 | 拒绝 |
| Bash、PowerShell | `rg made kq.`、`Copy-Item -Recurse kq. backup`（对照，不用通配符） | 拒绝 | 拒绝 |
| Bash | `rg made l??`（对照：`lnk` 是不带点的联接） | 拒绝 | 拒绝 |

实际会读到：同样的目录里，PowerShell 5.1 的 `Get-ChildItem ???` 只匹配到 `kq.`，`Copy-Item -Recurse ??? backup` 拷出来的是 `.env`；Python 的 `os.listdir('kq.')` 列出 `.env`（`rv38r_real.ps1`）。Win32 打开 `kq.` 时去掉尾随点，进的是联接。子代理在 Git Bash 里量到同样的展开（`???` 是 `kq.`）。

- 不要后端也有影响：原来拒绝，现在问。有后端时送给模型，模型（被命令文字操纵时）能放行。
- 前提：项目里要有名字以点结尾的目录，旁边是同名不带点、指向要保护文件的链接，命令要用通配符而不是直接写名字。名字以点结尾的目录普通的 Win32 调用建不出来，要 `\\?\` 前缀或别的工具；被注入的 agent 可以先建好再用。
- 违反规格修订 38 的"不变：规则层和它的判决"，也违反修订 13 的"只差读法的路径照样查盘"（`reading_only` 的注释写的就是不能把拒绝那一边挡在外面）。
- **建议**：`_native_dir`（以及别处对 PathRef 调用 `reading_only` 的地方）把 `glob-match` 当作只作说明的原因：
  - 或者放进 `paths._INFO_REASONS`；
  - 或者在 `_native_dir` 里先去掉它再判断。
  
  这样同时修好 R38-2。先改规格（修订 39），再改代码，补 J、P 两种布局的测试（Bash、PowerShell 各几条，钉住拒绝）。要跑原有差分：往下找的目录变多，判决只会变紧，要逐条核对。

### R38-2（低，判决偏松，原来就有）：同样的原因，没有链接时两版都不往下找

布局（`rv38r_tdot.py` 的 P）：`projp` 里有 `kq.`（`\\?\` 建的）和普通目录 `kq`，`kq\.env`。Win32 打开 `kq.` 进的是 `kq`。

| 命令 | 新代码 | `1499e14` |
|---|---|---|
| Bash `rg made ???`、PowerShell `Copy-Item -Recurse ??? backup` | 灰色 | 灰色 |
| Bash `rg made kq.`（对照） | 拒绝 | 拒绝 |

- 通配符匹配到的那一份本来就带 `glob-match`，只差读法，`_native_dir` 一直不往下找。直接写名字时没有 `glob-match`，往下找，拒绝。
- **建议**：和 R38-1 一起修。

### R38-3（信息，代价没写全，修订 38 引入）：切换到自己的工作目录之后，项目里的通配符匹配一个都不发

`rv38r_globcwd.py`，事件的 `cwd` 和项目是 `projg`（里面有 `a.txt`、`b.txt`），`PROJ_DIR` 的值就是它：

| 命令 | 新代码 | `1499e14` |
|---|---|---|
| `Get-Content *.txt`（对照） | `<project>/*.txt`、`<project>/a.txt`、`<project>/b.txt` | 同左 |
| `Set-Location $env:PROJ_DIR; Get-Content *.txt` | `*.txt` | `<project>/*.txt`、`<project>/a.txt`、`<project>/b.txt`、`*.txt` |
| `Set-Location $PWD; Get-Content *.txt` | `*.txt` | 同上 |

- R37-2 的去重把两份合成带标记的一份，`_hidden_match` 再把带标记的匹配藏起来。没有值发出去，模型看到的少了：项目里的文件名一个都看不到，只看到通配符。
- 规格修订 38 和记录第 6 节只写了相对路径由 `<project>/gen.py` 改为 `gen.py`。
- **建议**：写进规格的代价。要不要对"key 能从没展开过的工作目录得到"的匹配照样发，是设计上的取舍，由使用者定；复审的推荐是只写进规格。

### R38-4（信息，多问，原来就有）：同一个目录仍算两份的几种写法

`rv38r_mine.py`、`rv38r_r2left.py`，`PROJ_DIR` 指向事件的工作目录，但写法不同：

| 写法 | 新代码 | `1499e14` |
|---|---|---|
| 结尾多一个 `\`、全大写、`/` 分隔（对照：修订 38 修好的） | 9 个路径，送审 | 拒绝、问（超过 16 个） |
| 指向工作目录的目录联接 | `python gen.py` 发 3 份；9 个路径拒绝、问 | 同左 |
| 工作目录的 8.3 短名 | 2 份；9 个路径拒绝、问 | 同左 |
| 值带尾随点（`…\proj.`） | 2 份；9 个路径拒绝、问 | 同左 |

- key 或其余原因不同（盘上解析出来的样子、短名、`trailing-dots-spaces`），不在"只差这个标记"之内，不合并。不会多发出东西，只会多问。
- 子代理报的另一条（`Set-Location $env:PROJ_DIR\sub; Set-Location ..`）不算：`cd` 可能失败，旧的工作目录留着，那里真的是三个可能的工作目录。
- **建议**：规格修订 38 那条的标题改窄（"只差标记的两份路径只留一份"），把这几种写进"仍有的"。

### R38-5（信息，文档）

1. **因为 R38-1**，下面几处不对：
   - 规格修订 38 段落第 399 行"不变：规则层和它的判决"；
   - 状态行"规则层和它的判决、请求格式、提示词不变"；
   - 记录第 1 节"规则层的判决、请求格式、提示词都不变"；
   - 记录第 3 节把 R37-1 的修法说成只是在规则层补原因；
   - `_resolved_forms` 的注释只说了发送那一边。
   
   代码提交说明里"whole chains (106 calls) and 92 probes: no verdict … changed"说的是量过的那些，本身没错，但读起来像是判决都不变。（子代理）
2. **因为 R38-3**，规格修订 38 第 390 行和记录第 6 节第 1 条只写了 `gen.py`。（子代理）
3. **因为 R38-4**，规格修订 38 第 387 行的标题说宽了。（我）

- **建议**：随下一次修订改文字。修订 38 的记录加带日期的更正；提交说明不能改，在下一份记录里说明。

## 3. 核对过、没有问题的

| 检查 | 结果 |
|---|---|
| R37-1 修好了 | 值本身是目录联接、切换到联接再用通配符、通配符经过值下面的联接、两种 Bash 写法、没有 `cwd` 时的 `C:*.txt`：新代码请求里只有通配符的原文，旧代码有 `…\vaultj7c2d\a.txt` 一类；名字像秘密、值照原样的，旧代码拒绝，新代码送审、没有值（子代理 6 条；我的 `rv37r_verify.py` 11 条） |
| 通配符的盘上形式只有一处 | 匹配到的文件只经过 `_glob_refs` → `_resolved_forms`；保留尾随点的读法（`_kept_forms`）、`..` 先跟链接（`_dotdot_forms`）不用于通配符的匹配；`_mark_hard_linked` 保留原因（我） |
| R37-2 修好了 | 子代理 12 种写法（事件 `cwd` 带 `\`、`/`，值换大小写、带 `\.`、`..\proj`、`$HOME\proj`，Bash 的 `$HOME/proj`、`$PWD/.`，`cd` 两次）：9 个路径新代码送审、旧代码问；我量的结尾 `\`、大写、`/` 同样。另一个目录照旧两份 |
| R37-3 修好了，`_CWD_READINGS` 齐全 | 路径层里不算相对、key 却取工作目录的，只有 `_shape_drive` 的 `drive-relative` 和 `_shape_rooted_windows` 的 `rooted-current-drive`（`paths.py` 第 1247 到 1278 行）；`$PWD` 走 `_uses_pwd`，算相对。没有 `cwd` 时 `D:gen.py`、`\gen.py`、`/gen.py`、`D:..\gen.py` 都按原文（子代理） |
| 从展开出来的目录 `cd D:sub` 一类 | 有 `cwd` 时，`Set-Location D:sub`、`D:..\x`、`\sub`、`Push-Location D:sub` 之后，请求里两版都没有值（`rv38r_mine.py`）；没有 `cwd` 时工作目录算作不知道（子代理） |
| 其他途径 | UNC 的值出现在 `domains` 里，但 `net-allowlist` 问，不送审；`git -C`、重定向、`.\tool.exe`、`Copy-Item` 的目标、`Push-Location` 加 `Pop-Location`、嵌套的 `powershell -Command`：没有值（子代理） |
| 递归读找到的要保护的文件 | 默认策略的 23 个要保护的名字，直接读都是拒绝或问，`_scan_refs` 造的、key 里有值的路径不送审（子代理） |
| 记录里的数字 | 都和 scratchpad 里的原始输出对得上（`rv38r_numbers.py`）：复审脚本 11 条变 9、16 条变 5；变异第一轮 109 / 114，存活的 5 个和记录一样，重跑 2 / 2；整条链路 106 条 0 变化；语料 4906 行、送审 2009、不同 0 行；全量 30488 / 169，合计 30657，用时 2:37:00；评测延迟 3.65 / 8.78（修订 37 是 3.71 / 8.50）；冒烟 26 / 0；修订 19、20 补跑 2482、160 条相同 |
| 新测试在 `1499e14` 上 | 子代理重跑：14 failed、6 passed，和记录一样；新代码 20 passed |
| 文档 | `docs/privacy.md`、`docs/threat-model.md`、修订 37 记录的四处更正和规格说法一致（R38-5 的几处除外） |

没有量的：
- ripgrep 没装，"实际读到什么"用的是 PowerShell 5.1 的 `Copy-Item` 和 Python 的 `os.listdir`；
- 只在 POSIX 上跑的 `_dotdot_forms`；
- PowerShell 7、Linux、macOS；
- 真实宿主，包括 R37-4（标记留到下一次调用）。

## 4. 建议的顺序

1. R38-1、R38-2 先改规格（修订 39）：通配符匹配到的、只差读法的目录，连同它在盘上解析出来的样子，照样往下找。再改 `_native_dir`（或 `_INFO_REASONS`），补 J、P 两种布局的测试，跑变异、探针、语料、原有差分和全量。
2. R38-3、R38-4 写进规格（代价和仍有的）；要不要改代码由使用者定，复审的推荐是只写进规格。
3. R38-5 随修订 39 改文字；修订 38 的记录加带日期的更正。

这份复审没有改代码。
