# 规格修订 37 的复审

日期：2026-11-18。代码：`1a2c787`（`main`，与 `origin/main` 相同；代码提交是 `1499e14`）。

审查对象（`git show 1499e14 -- src`）：
- `normalize/event.py`：`_Line.expanded_cwds`、`_expanded`、`_refs` 的 `expanded_cwds` 参数、`_cd_target` 和 `_after_cd` 的改动、五处调用；
- `audit/send_gate.py`：`_hidden_match`，`_carries` 去掉两头空白之后也找；
- 规格开头修订 37 的段落、§9.2 两条，`docs/privacy.md`、`docs/threat-model.md` 对应的几句；
- 记录 `docs/reports/M3a-rev36-review-fixes.md`、两个提交说明、新测试 `tests/unit/test_m3a_rev36_review_fixes.py`。

**这不是独立复审。** 修订 37 是这个会话写的，使用者说"复审修订37"。下面的结论都重新量过，没有照搬记录里的说法。另请了一个子代理单独找错，只给了它代码、规格、隐私和威胁模型文档、记录和新测试，没给我自己的判断。它报的每一条都在这个会话里用另写的脚本重新量过才写进来（表里的"谁发现"一列）。

**本次改了什么**：
- 新增这份报告。
- 状态说明里加了指向这份报告的几行。
- 没有改 `src`、规格正文、策略、测试和脚本。

**本次没有做的事**：
- 没有读 `.env`，没有用 LLM 密钥，没有访问真实 LLM 服务。
- 没有读 `eval/authoring/h1-*`、`h2-*` 和留出批次，没有改系统设置。子代理也按这几条做，没有改仓库。
- 没有跑 `claude`，没有跑全量：只读代码，跑相关的脚本，探针都在 scratchpad 里。
- 没有在任何盘的根目录下建文件或目录。scratchpad 里为量盘上的形式建的目录（目录联接、8.3 短名、要保护的文件）用完都删了。

**怎么量的**：
- 两份代码：工作区（`1a2c787`，代码同 `1499e14`）和 `8ffa34e` 的 `src`（修订 37 时导出的 `tree-8ffa34e`）。每个脚本都核对加载的是哪份文件，不对就停。
- 整条链路：用测试里的假后端（`FakeBackend`）走完整条 `pipeline.decide`，默认策略加上后端，看判决、送不送审和请求。Windows，PowerShell 工具，事件的 `cwd` 和项目是 `C:\Users\testuser\proj`（另注明的除外）。
- **先等 PowerShell 解析器就绪**：这次自己的几个脚本第一遍没有等，PowerShell 命令全是灰色 `ps-helper-not-ready`，判决是问、不送审，新旧两版"一样"，其实什么都没量。补上 `psparse.warm_up` 之后全部重跑，下文都是重跑的结果。修订 37 的验证没有这个问题：整条链路的脚本 12 次运行都记下了"PS helper ready: True"，探针和整条链路的输出里没有一条 `ps-helper-not-ready`（核对过）。
- 脚本（scratchpad）：
  - `rv37r_probes.py`，11 条：盘符相对、根相对、`..`、`Pop-Location`、`git -C`、`$PWD`；
  - `rv37r_nocwd.py`，9 条，事件里有和没有 `cwd` 各跑一次；
  - `rv37r_scan.py`，7 条：一个带 `.env`、`.pem` 的目录，递归读；
  - `rv37r_short.py`、`rv37r_short_py.py`、`rv37r_short_bash.py`：8.3 短名，各 3 条；
  - `rv37r_nextcall.py`，3 条：工作目录留到下一次调用；
  - `rv37r_verify.py`，11 条：重新量子代理的两条发现（目录联接和通配符 6 条，项目目录 5 条）。
- 子代理：脚本在 scratchpad 的 `rv37r_agent\` 下，自己导出了一份 `077dbfc` 的旧代码，每个脚本都核对加载的是哪份代码。它重跑了新测试在两份代码上的结果，没有重跑语料、探针和原有差分。

## 1. 结论

**修订 37 的主要目标达到了：同一个调用里，PowerShell 用 `Set-Location $env:名字` 切换工作目录之后，后面的相对路径在请求里是原文，判决不变。找到的问题：通配符经过目录联接匹配到的文件仍带着值发出（R37-1，修订 37 说已经不发）；展开出来的目录正好是事件的工作目录时，每个相对路径算两次，路径多的调用由送审变成问（R37-2，修订 37 引入）；两种原来就有、修订 37 没覆盖的情形（R37-3、R37-4）；文档几处说宽了（R37-5）。**

- 规则层不读这个标记：`src` 和 `policies` 里读 `PathRef.reasons` 的只有 `send_gate` 和 `event` 自己；`variable-expanded` 是只作说明的原因，`paths.reading_only` 加上它结果不变。判决不变的说法成立，量过的每一对新旧调用判决都相同。
- 记录里的数字都对得上原始输出（第 3 节）。
- 8.3 短名：规格说"原来就带，测过"，修订 37 当时只量了目录联接。这次补量：变量本身展开过的路径，8.3 短名在盘上的长名字两版都带标记；从展开出来的工作目录走的 `AVERYL~1.TXT`，旧代码发出长名字所在的完整路径，新代码按原文发。说法是对的。

**高危 0，中危 0，低危 2，信息 3。**

| 编号 | 级别 | 一句话 | 要后端吗 | 谁发现 | 来源 |
|---|---|---|---|---|---|
| R37-1 | 低（隐私，修订 37 没修全） | 通配符匹配到的文件，经过目录联接时，它在盘上解析出来的那一份没有 `glob-match`，不会被藏起来，按"原文"发出，原文就是匹配到的路径，里面就是变量的值；秘密值照原样时反而改为拒绝，规格没写这处送审变化 | 要 | 子代理 | 修订 37（`_resolved_forms` 是原来就有的） |
| R37-2 | 低（多问，修订 37 引入） | 展开出来的目录就是事件的工作目录时（`Set-Location $env:PROJ_DIR`、`Set-Location $PWD`），后面每个相对路径在请求里出现两次；9 个路径变成 18 个，超过 `MAX_PATHS`，原来送审，现在拒绝、问 | 要 | 子代理 | 修订 37 |
| R37-3 | 信息（隐私，原来就有） | 事件里没有 `cwd` 时，盘符相对路径（`D:gen.py`）按展开出来的目录解析，不带标记，请求里带着值 | 要 | 我 | M3a 起 |
| R37-4 | 信息（隐私，原来就有，真实宿主里没有量） | 标记只在一个调用之内：宿主若把工作目录留到下一次调用，下一个事件的 `cwd` 就是展开出来的目录，后面的路径带着值 | 要 | 我 | M3a 起 |
| R37-5 | 信息（文档） | 因为 R37-1、R37-2，"通配符匹配到的文件不发""送不送审只在一处变"说宽了；隐私和威胁模型文档只写了 PowerShell；`strip()` 去掉的是 Unicode 空白，不去掉 BOM | 不涉及 | 两边都发现 | 修订 37 的文字 |

五条都只在有后端时才有影响。R37-1 是要紧的一条：修订 37 说通配符匹配到的文件不发，经过目录联接时仍然发出。

## 2. 发现

### R37-1（低，隐私，修订 37 没修全）：通配符经过目录联接匹配到的文件仍带着值发出

`_glob_refs` 对每个匹配到的文件调用 `_resolved_forms`（`event.py` 第 954 到 987 行）。它给出两份：
- 匹配到的路径本身，原因里有 `glob-match`；
- 路径在盘上解析出来的样子与 key 不同时，再给一份，原因是 `_with(resolved.reasons, "resolved-on-disk")`，没有 `glob-match`。

`_refs` 给两份都加上 `variable-expanded`。`_hidden_match` 只藏两个原因都有的，第二份留在请求里。`_path` 对带标记的显示原文，而这一份的原文（`raw`）就是匹配到的路径，里面就是变量的值。目录里没有链接时两份 key 相同，没有第二份，所以修订 37 的测试（`tmp_path` 下的普通目录）看不出来。记录里"盘上的形式"量了目录联接，没有和通配符一起量。

整条链路（`rv37r_verify.py`）。`vaultj7c2d` 是指向 `realq5k3` 的目录联接，`realq5k3` 里有 `a.txt`；`vaultp7c2d` 是普通目录，里面的 `lnk` 是指向 `realq5k3` 的目录联接：

| 命令 | 环境变量 | 新代码 | `8ffa34e` |
|---|---|---|---|
| `Get-Content $env:WORK_DIR\*.txt` | `WORK_DIR=…\vaultj7c2d` | 送审，`paths` 有 `…\vaultj7c2d\a.txt` | 送审，`…/vaultj7c2d/a.txt` 和 `…/realq5k3/a.txt` |
| `Set-Location $env:WORK_DIR; Get-Content *.txt` | 同上 | 送审，`paths` 有 `…\vaultj7c2d\a.txt` | 送审，同上加 `…/vaultj7c2d/*.txt` |
| `Get-Content $env:WORK_DIR\l*\a.txt` | `WORK_DIR=…\vaultp7c2d` | 送审，`paths` 有 `…\vaultp7c2d\lnk\a.txt` | 送审，两个盘上的路径 |
| `Get-Content $env:WORK_DIR\*.txt`（对照） | `WORK_DIR=…\realq5k3`（普通目录） | 送审，`paths` 只有 `$env:WORK_DIR\*.txt` | 送审，`…/realq5k3/a.txt` |
| `Get-Content $env:VAULT_TOKEN\*.txt` | `VAULT_TOKEN=…\vaultj7c2d`（名字像秘密，值照原样） | 拒绝、问：原文里是带 `\` 的原值，秘密检查找到 | 送审，key 里是 `/` 的写法，找不到 |
| 同上 | `VAULT_TOKEN=…\realq5k3\..\vaultj7c2d`（值改了形） | 送审，`paths` 有 `…\vaultj7c2d\a.txt`，找不到 | 送审 |

- 修订 37 比原来少发了 `realq5k3` 那一份，但变量的值仍在请求里。
- 送不送审多了一处变化：值照原样、名字像秘密的，原来送审，现在拒绝。方向是少发，但规格修订 37 说送不送审只在一处变。
- 要后端，要变量的值本身是目录联接（或符号链接），或者通配符要经过值下面的链接。8.3 短名的值不受影响：那里通配符不展开（`glob-not-expanded`）。
- **建议**：`_resolved_forms` 给盘上解析出来的那一份也带上 `extra_reasons`（`glob-match`），`_hidden_match` 就会一起藏起来；或者 `_hidden_match` 改为藏起原文不是命令里写的那个词的、带标记的路径。补一条经过目录联接的测试（Windows 上 `mklink /J`，POSIX 上符号链接），连同上表的两条秘密值。

### R37-2（低，多问，修订 37 引入）：展开出来的目录就是事件的工作目录时，每个相对路径算两次

`_Line` 一开始的工作目录是事件里 `cwd` 的原文（`event.py` 第 1934 行：`cwds=(ctx.cwd,)`），`cd` 的目标是 key。同一个目录写法不同，`_merge_cwds` 不会合并。修订 37 之前，两份工作目录给出的路径完全相同，被 `_refs` 去重（去重的键里有 `reasons`）；现在其中一份带标记，两份都留下来。

整条链路（`rv37r_verify.py`），事件的 `cwd` 和项目都是 scratchpad 里的 `proj`，`PROJ_DIR` 的值就是它：

| 命令 | 新代码 | `8ffa34e` |
|---|---|---|
| `Set-Location $env:PROJ_DIR; python gen.py` | 送审，`paths` 是 `<project>/gen.py`、`gen.py` | 送审，`<project>/gen.py` |
| `Set-Location $env:PROJ_DIR; pytest t1.py … t7.py` | 送审，14 个路径 | 送审，7 个 |
| `Set-Location $env:PROJ_DIR; pytest t1.py … t9.py` | 拒绝、问："a command touches more than 16 paths" | 送审，9 个 |
| `Set-Location $PWD; pytest t1.py … t9.py` | 同上，拒绝、问 | 送审，9 个 |
| `pytest t1.py … t9.py`（对照） | 送审，9 个 | 送审，9 个 |

- 不会多发出东西，只会多问。子代理在 Bash 里量到同样的情形（`cd "$PWD" && pytest t1.py … t9.py`：18 个路径对 9 个）。
- 这也是规格修订 37 没写的送审变化。
- **建议**：`_refs` 去重时，原文、key、访问方式、确定与否都相同的两份，只留带标记的那一份；或者一开始就把事件的 `cwd` 换成 key，让 `_merge_cwds` 合并（后一种牵涉面大，要跑原有差分）。补一条测试。

### R37-3（信息，隐私，原来就有）：事件里没有 `cwd` 时的盘符相对路径

`_relative_text` 不把 `D:gen.py` 当相对路径，`_refs` 只按第一个可能的工作目录解析它。路径层对盘符相同的工作目录接着拼（`paths.py` 第 1253 到 1259 行），key 里就有那个目录。事件里有 `cwd` 时，第一个总是它，不会出事。事件里没有 `cwd` 时，`Set-Location $env:X` 之后展开出来的目录排第一，而它没有标记（`relative` 为假）。

整条链路（`rv37r_nocwd.py`），`SECRETS_DIR` / `WORK_DIR` 的值是 `D:\vault\prod01`：

| 命令 | 没有 `cwd` | 有 `cwd` |
|---|---|---|
| `Set-Location $env:SECRETS_DIR; python D:gen.py` | 送审，`paths` 是 `d:/vault/prod01/gen.py` | 送审，`d:/gen.py` |
| `Set-Location $env:WORK_DIR; Get-Content D:gen.py` | 送审，`d:/vault/prod01/gen.py` | 送审，`d:/gen.py` |
| `Set-Location $env:WORK_DIR; Get-Content \gen.py` | 送审，`d:/gen.py`（只有盘符） | 送审，`c:/gen.py` |
| `Set-Location $env:WORK_DIR; Get-Content gen.py`（对照） | 送审，`gen.py`（修订 37 修好的） | 送审，`<project>/gen.py`、`gen.py` |

- 新旧代码一样。Claude Code 发来的事件都带 `cwd`，实际碰不到；规则层支持没有 `cwd` 的事件，测试里也有这种情形（`test_an_absolute_path_is_not_marked_when_the_working_directory_was_unknown`）。
- **建议**：盘符相对、根相对（原因里有 `drive-relative`、`rooted-current-drive`）的路径，所用的工作目录是展开出来的时也加标记；或者写进规格的"仍有的"。

### R37-4（信息，隐私，原来就有，真实宿主里没有量）：工作目录留到下一次调用

`expanded_cwds` 只在一个调用（一个 `_Line`）里。宿主若把工作目录留到下一次调用，下一个事件的 `cwd` 就是展开出来的目录，规则层不知道它是怎么来的，后面的路径按 key 发。

模拟（`rv37r_nextcall.py`），把下一个事件的 `cwd` 设成 `C:\Users\testuser\proj\pa\ss1234wd`，`DB_PASSWORD=pa\ss1234wd`：
- 同一个调用里 `Set-Location $env:DB_PASSWORD; python gen.py`：新代码送审，`<project>/gen.py`、`gen.py`，没有值（修订 37 修好的）；
- 下一个调用 `python gen.py`：两版都送审，`paths` 是 `<project>/pa/ss1234wd/gen.py`，值改了形，秘密检查找不到。

- 只模拟了事件；Claude Code 的 PowerShell 工具会不会把 `Set-Location` 留到下一次调用、hook 事件的 `cwd` 是不是跟着变，没有在真实宿主里量。目录在项目之外时 Claude Code 可能会把工作目录改回去，也没有量。
- **建议**：先写进规格的"仍有的"（标记只在一个调用之内）。要跨调用记住，得放进会话状态（SQLite），是设计上的取舍，由使用者定。

### R37-5（信息，文档）

1. **因为 R37-1**，下面几处说宽了："通配符匹配到的文件不放进请求、只发通配符的原文"——规格修订 37 段落第 369 行、§9.2 第 1125 行、`docs/privacy.md` 第 14 行、`docs/threat-model.md` 第 37 行、记录第 1、3、4 节、代码提交说明。经过链接时并不是这样。（子代理）
2. **因为 R37-1、R37-2**，规格修订 37 第 380 行"送不送审只在上面那一处变"不对：还有 R37-1 的秘密值照原样时改为拒绝、R37-2 的路径翻倍后超过上限。两处都是少发。（子代理）
3. `docs/privacy.md`、`docs/threat-model.md` 只写了 PowerShell 的 `Set-Location $env:名字`；Bash 的 `cd $HOME/…`、`cd $PWD/…` 之后也按原文发，规格写在代价里。（子代理）
4. `_carries` 用 Python 的 `str.strip()`，去掉的是所有 Unicode 空白（不换行空格、全角空格、U+2028、U+001F 都去掉），不去掉 BOM（U+FEFF）和零宽空格（`isspace()` 都是假）。规格只说"空白"。Bash 的 `$(cat 文件)` 读 UTF-8 带 BOM 的文件时值里留着 BOM，命令里照写不带 BOM 的值，仍然找不到。这不算错，只是没写。（子代理，我核对过各字符的 `isspace()`）
5. 规格说"链接、8.3 短名的目标原来就带，测过"，修订 37 只量了目录联接。这次补量了 8.3 短名，说法是对的（第 1 节）。（我）

- **建议**：随下一次修订改文字。修订 37 的记录加带日期的更正；提交说明不能改，在下一份记录里说明。

## 3. 核对过、没有问题的

| 检查 | 结果 |
|---|---|
| 规则层不读标记 | `src`、`policies` 里读 `PathRef.reasons` 的只有 `send_gate` 和 `event`；`variable-expanded` 在 `paths._INFO_REASONS` 里，`reading_only`、`_native_dir` 结果不变；`dataclasses` 换成了 `model_copy`，`PathRef` 是冻结的 pydantic 模型 |
| 同一个调用里的各种 `cd` | 子代理（`cases_misc.py`、`cases_nested.py`、`cases_overmark.py`）：`Set-Location -Path` / `-LiteralPath` / `-Path:$env:X`、`sl`、`chdir`、`pushd`、`Push-Location` 加 `Pop-Location`、带引号的 `"$env:X\sub"`、`${env:X}\..\other`、`..`、`$PWD\gen.py`、`if` 和脚本块里的 `cd`、重定向、`Copy-Item`、管道、`python -m pytest`、嵌套的 `bash -c` / `cmd /c` / `powershell -Command`、Bash 的子 shell、`cd -`、`find -exec {}`、`xargs`：`paths`、`args`、`domains`、`command` 里都没有值。我量的 `..`、`Pop-Location`、`$PWD\gen.py` 同样（`rv37r_probes.py`） |
| 事件里有 `cwd` 时的盘符相对、根相对路径 | 按事件的工作目录解析，只有盘符，没有值（`rv37r_probes.py`、`rv37r_nocwd.py`） |
| 递归读找到的要保护的文件 | `_scan_refs` 造的路径不带标记，key 里有值；但它们都命中 deny / ask 的读规则（`rg x .` 拒绝，`Get-ChildItem -Recurse` 问），不送审（`rv37r_scan.py`，两版一样）。没有搭"规则对某个目录有例外、例外里又有要保护的名字"的情形 |
| 8.3 短名 | Bash 的 `cat $HOME/AVERYL~1.TXT`、PowerShell 的 `Get-Content $env:WORK_DIR\AVERYL~1.TXT`：长名字那一份两版都带标记、按原文发；`Set-Location $env:WORK_DIR; Get-Content AVERYL~1.TXT`（目录是长名字）：旧代码发出完整的长路径，新代码按原文发（`rv37r_short*.py`） |
| "第一份是字面形式" | `_refs_one` 总是先放字面形式，`_mark_hard_linked` 不改顺序，通配符的匹配接在后面（子代理） |
| 藏起来的匹配 | 照旧算进 `MAX_PATHS`，照旧过 `_checked_text`（新测试和子代理） |
| `_carries` 和 `MIN_SECRET_CHARS` | 原样的值至少 8 个字符就找，去掉空白之后不到 8 个的那一份不找；没有发现超出这条规则的误报（子代理） |
| 记录里的数字 | 都和 scratchpad 里的原始输出对得上：整条链路 12 + 10 + 27 + 14 + 20 = 83 条 0 变化，`rv36r_agentcheck` 23 条里判决变 3、送不送审变 3、请求变 9；探针 92 条 0 变化；语料 4906 行、不同 0 行；变异第一轮 101 / 106，重跑 5 个抓到 3 个，合计 103；原有差分都是 `same`，`boundkeep test` 1142 / 0、334 / 0；全量六段 30468 / 169 / 0，合计 30637（`rv37_chain_log.txt`、`rv37_mutants*.txt`、`diffs37.txt`、`full37\chunks\status.txt`） |
| 新测试在 `8ffa34e` 上 | 子代理重跑：21 failed、7 passed，和记录一样；新代码 28 passed |
| R36-4 的说法 | 子代理核对：PowerShell 5.1 把 `print('pa\"ss1234wd')` 拆成 `print('pa\` 和 `ss1234wd)"` 两个词 |

## 4. 建议的顺序

1. R37-1 先改规格（修订 38）：通配符匹配到的文件，连同它在盘上解析出来的样子，都不放进请求；写明秘密值照原样时的送审变化。再改 `_resolved_forms`（或 `_hidden_match`），补经过目录联接的测试，跑变异、探针、语料、原有差分和全量。
2. R37-2 跟着一起改：去重时只留带标记的那一份（或者把事件的 `cwd` 换成 key），补测试。
3. R37-3 改代码还是写进规格，R37-4 只写进规格还是放进会话状态，由使用者定。复审的推荐：R37-3 改代码（小改动），R37-4 先写进规格。
4. R37-5 随修订 38 改文字；修订 37 的记录加带日期的更正。

这份复审没有改代码。
