# 规格修订 42 的复审

日期：2026-11-24。代码：`0a37a14`（`main`，与 `origin/main` 相同；代码提交是 `3a7d94c`）。

审查对象（`git show 3a7d94c -- src`）：
- `normalize/subtree.py`：`_sibling_state` 在列表里找不到名字时调用 `_alias_state`；
- `normalize/event.py`：`_existing_realpath`、`_first_on_disk`、`_short_and_reading`、`_cd_short_target`（新），`_refs_one`、`_resolved_kept_forms`、`_match_kept_forms`、`_scan_refs`、`_after_cd` 的改动；
- `normalize/paths.py`：`short_reading_only`（新），`_expand_glob` 不再因为 `short-name-unresolved` 不展开；
- 规格开头修订 42 的段落；
- 记录 `docs/reports/M3a-rev41-review-fixes.md`、两个提交说明、新测试 `tests/unit/test_m3a_rev41_review_fixes.py`。

**这不是独立复审。** 修订 42 是这个会话写的，使用者说"复审修订42"。下面的结论都重新量过，没有照搬记录里的说法。另请了一个子代理单独找错，只给了它代码、规格、记录、修订 41 的复审和新测试，没给我自己的判断。它报的每一条，都在这个会话里用另写的脚本、另搭的目录（别的名字、别的布局）重新量过才写进来（表里"谁发现"一列）。

**本次改了什么**：
- 新增这份报告。
- 规格和 `CLAUDE.md` 的状态说明里加了指向这份报告的几行。
- 没有改 `src`、规格正文、策略、测试和脚本。

**本次没有做的事**：
- 没有读 `.env`，没有用 LLM 密钥，没有访问真实 LLM 服务。探针里的 `.env` 和凭据文件都是 scratchpad 里编出来的文件（内容 `MADE_UP=1`），看真实程序读到什么时只列文件名或字节数。
- 没有读 `eval/authoring/h1-*`、`h2-*` 和留出批次，没有改系统设置。子代理也按这几条做，没有改仓库。
- 没有跑 `claude`，没有跑全量、语料、变异和原有差分：只读代码，跑相关的脚本，并从修订 42 验证时的原始输出里重新数记录里的数字。
- 没有在任何盘的根目录下建文件或目录。scratchpad 里搭的目录（名字以点结尾的目录、目录联接、四组各两万七千个空目录、三万个文件的目录）用完都删了，先删联接（只删联接本身）。

**怎么量的**：
- 四份代码：工作区（`0a37a14`，代码同 `3a7d94c`）、`8d43a51`（修订 41）、`e56ebd2`（修订 40）、`2b87375`（修订 39）的 `src`（scratchpad 里的 `tree-8d43a51`、`tree-e56ebd2`、`tree-2b87375`）。每个脚本都核对加载的是哪份代码，并核对 `event.py`、`paths.py`、`subtree.py` 的哈希和 `git rev-parse <提交>:<文件>` 相同，不对就停；子代理另把四份的 `src` 和策略逐个和提交比过（各 82 个文件相同）。走 PowerShell 的都先等解析器就绪（`psparse.warm_up`）。
- 整条链路：用测试里的假后端（什么都放行）走完整条 `pipeline.decide`，默认策略；要看"没有后端"时去掉后端。Windows，事件的 `cwd` 和项目相同。下面的两个字母：前一个没有后端、后一个有后端；拒绝 D，问 A，送审后由假后端放行 S（"问、送审"）。
- 8.3 短名用 `GetShortPathNameW` 从系统读；联接用 `_winapi.CreateJunction` 建；名字以点结尾的目录用 `\\?\` 建。
- 真实程序：Git Bash（这台机器上在 `D:\新建文件夹\Git`）的 `grep -rl`、`cat`、`wc -c`，cmd 的 `dir /s /b`、`findstr /s`，Python 的 `os.listdir`，.NET 的 `[IO.Directory]::GetFiles`，PowerShell 5.1 的 `Get-ChildItem`、`Get-Content`、`Resolve-Path`。ripgrep 没装。
- 脚本（scratchpad）：
  - `rv42r_h.py`：加载、核对代码，走整条链路；
  - `rv42r_big.py`：R40-1 的布局和三种变体（R42-1），四份代码，三轮，B1 另跑五轮；
  - `rv42r_agentbig.py`：成对的带点目录和同名文件、三万个文件的目录（R42-1、R42-3）；
  - `rv42r_variants.py`、`rv42r_variants_cmp.py`：短名带点的同名目录（R42-4）、`cd` 的十几种写法、`cd` 之后放行那边、前缀写成短名的通配符，修订 42 和 41；
  - `rv42r_agentcheck.py`、`rv42r_agentcheck2.py`、`rv42r_agentcheck_cmp.py`：重新量子代理的其余几条，四份代码；
  - `rv42r_real.py`：R42-4 的布局里真实程序读到什么，PowerShell 的通配符认不认 8.3 短名；
  - `rv42r_counts.py`：从原始输出重新数记录里的数字。
- 子代理：脚本在 scratchpad 的 `rv42r_agent\` 下。它做了 191 条新旧对比（四份代码），另量了 R40-1 那一类布局的门槛（`x5_summary.txt`），用内核重新算了大小写表；重跑了新测试在两份代码上的结果；没有重跑语料、探针、变异和原有差分。

## 1. 结论

**修订 42 的三处修复本身成立：R41-1 的几种布局（短名、大小写表）都拒绝，R41-3、R41-4 列的写法和另外几十种写法由灰色变成拒绝；没有一条由规则放行的（子代理 191 条、我这边几十条，放行那边都没有变松）；记录里的数字都对得上。但"只比修订 41 变严"说错了，有三处变松，都是由拒绝变成问或送审：**
- **R42-1（低危，修订 42 引入）。** 列表里没有的兄弟出栈时问一次盘，这些时间在下一次读时钟时算进第一遍的 0.35 秒。R40-1 的布局后面只要再有 64 个条目，修订 42 就问，修订 41 拒绝：R40-1 回来了。列表只记目录和链接，同名的文件兄弟也要问盘，还多一次失败的列目录，门槛比修订 39 还早。
- **R42-2（低危，修订 42 让它更容易到；底下的毛病修订 39 就有）。** 可能的工作目录超过上限（8 个）时，留下的是最早的 7 个，丢掉的是最新的那个。`cd a && cd b && cd c && cd <外面>/.kube && cat config` 四版都是灰色、送审；修订 42 的 `cd` 进短名多记一个目录，`cd SRCFOL~1 && cd x && cd y && cd <外面>/.kube && cat config` 由拒绝变成送审。不要特别的目录布局。
- **R42-3（低危，修订 42 引入，不是新能力）。** 新加的解析和遍历花的是每个请求共用的三份预算（修订 39 的 64 次查盘、第一遍的 30000 个条目、修订 40 的 64 次查询）。前面的短名写法用完，后面的操作数做不了，拒绝变成问（不送审）。长名写法四版本来就这样。

另有三条原来就有的、修复没覆盖到的写法（都是有后端时送审），和两条信息：
- **R42-4（低危）**：旁边有一个真叫 `VAULTS~1.` 的干净目录时，`rg made VAULTS~1.` 仍是灰色、送审；Win32 程序读到的是 `vaultstorage.` 里的 `.env`。
- **R42-5（低危）**：不带点的、像短名的真实长名（`data~1`），和 `cd` 进它（带点、带空格也一样），四版都是灰色、送审。
- **R42-6（低危）**：经 8.3 短名进到名字以点结尾的目录之后，里面的 Win32 兄弟不往下找，`Grep path=…\ARCHIV~1` 四版都是灰色、送审。
- R42-7（信息）：`cd` 进短名之后用短名写的程序，由"问、不送审"变成送审（和长名一样）。R42-8（信息）：规格、记录、提交说明里几处说法。

**高危 0，中危 0，低危 6，信息 2。**

| 编号 | 级别 | 一句话 | 要后端吗 | 谁发现 | 来源 |
|---|---|---|---|---|---|
| R42-1 | 低（判决变松：拒绝变成问） | 27000 个没有兄弟的带点空目录，后面再有 64 到 100 个条目，再后面 `zz9/.env`：修订 42 问 12/12，修订 41 拒绝 12/12；9000 对"带点空目录 + 同名文件"：修订 42 问 6/6，修订 41 拒绝 | 不要（不送审） | 两边都发现（文件兄弟是子代理） | 修订 42 |
| R42-2 | 低（判决变松：拒绝变成送审） | `cd SRCFOL~1 && cd x && cd y && cd <外面>/.kube && cat config`：修订 42 送审，修订 39 到 41 拒绝；四个普通 `cd` 四版都送审 | 有后端时送审 | 子代理 | 修订 39 就有，修订 42 少一个 `cd` 就到 |
| R42-3 | 低（判决变松：拒绝变成问） | `rg made BIGFOL~1/* <外面>/secretsz`、`cd LONGNA~1; cat b00…b35; cat <P>/jj/config`、`rg made LONGER~1/m* ???`：修订 42 问，修订 41 拒绝 | 不要（不送审） | 子代理 | 修订 42（长名写法原来就这样） |
| R42-4 | 低（判决偏松，原来就有） | `vaultstorage./.env` 旁边一个干净的 `VAULTS~1.`：`rg made VAULTS~1.`、`Grep`、`tar`、`Copy-Item` 四版都送审；Python、cmd 读到 `.env` | 有后端时送审 | 两边都发现 | 修订 39 就有（R41-3 的修复没覆盖） |
| R42-5 | 低（判决偏松，原来就有） | `data~1/.env`：`rg made data~1`、`Grep`、`tar`、`Copy-Item`、`cd data~1 && rg made sub`（`data~1.`、`'data~1 '` 也一样）四版都送审；Git Bash 读到 | 有后端时送审 | 子代理 | 修订 39 就有 |
| R42-6 | 低（判决偏松，原来就有） | `archivefolder./cfg.`（空）旁边联接 `cfg` 指向放着 `.env` 的目录：`Grep path=…\ARCHIV~1` 四版都送审；cmd 的 `findstr /s` 读到 | 有后端时送审 | 子代理 | 修订 39 就有 |
| R42-7 | 信息（送审变了） | `cd LONGTO~1 && ./MYPROG~1.EXE --version`：修订 39 到 41 问、不送审，修订 42 送审（长名写法四版都送审） | 不涉及 | 子代理 | 修订 42 |
| R42-8 | 信息（文档） | "只比修订 41 变严"、"R40-1 仍是修好的"、"有兄弟的照旧……不问盘"、"不读时钟，所以仍走完"、"变量……不查"、PowerShell 通配符那条"没有量" | 不涉及 | 两边都发现 | 修订 42 的文字 |

R42-1 和 R40-1 是同一个问题换了个地方：省下的盘调用又加回来，时间仍算在第一遍里。R42-2、R42-3 是同一个教训：修复让短名写法"和长名一样"时，长名在共用预算、工作目录上限上的毛病也一起带了过来，要拿长名的已知代价逐条对照。R42-4 到 R42-6 和 R41-3 是同一类：一个名字有几种读法时，每种读法都要查。

## 2. 发现

### R42-1（低，判决变松，修订 42 引入）：兄弟问盘的时间算进第一遍，R40-1 回来了

我的布局（`rv42r_big.py`），没有后端，四条命令（`Grep path=<project>`、`rg made .`、`tar -czf ../o.tgz .`、`Copy-Item -Recurse . ..\b`）各三轮：

| 布局 | 修订 42 | 修订 41 | 修订 40 | 修订 39 |
|---|---|---|---|---|
| B1：27000 个没有兄弟的空目录 `k00000.`…`k26999.`，`zz9/.env`（R40-1 本身） | 拒绝 31/32（问的那一次是进程里第一次判决；另跑五轮 20/20 拒绝） | 拒绝 32/32 | 问 12/12 | 拒绝 12/12 |
| B2：同上，另有 `src/` 里 100 个文件 | 问 12/12 | 拒绝 12/12 | 问 12/12 | 问 12/12 |
| B3：`src/` 里 64 个文件 | 问 12/12 | 拒绝 12/12 | 问 12/12 | 问 12/12 |
| B4：没有 `src/`，`zz9/` 里 `.env` 前面列出 100 个文件 | 问 12/12 | 拒绝 12/12 | 问 12/12 | 问 12/12 |

- 问的都是 `recursive-scan-budget`，不送审。每次判决修订 42 用 0.78 到 1.14 秒，修订 41 0.51 到 0.58 秒。
- 文件兄弟（子代理找到，我用 `rv42r_agentbig.py` 重新量过）：9000 对"空目录 `pNNNN.` + 文件 `pNNNN`"，后面 `zz0/` 里 64 个文件、`zz9/.env`：`rg made .`、`Grep path=<project>` 修订 42 问 6/6，修订 41 拒绝 6/6，修订 39 `rg` 问 1/3、`Grep` 拒绝；同样数目、没有兄弟的空目录三版都拒绝。
- 门槛（子代理，`x5_summary.txt`，每个三轮）：没有兄弟的空目录后面跟 64 个文件时，修订 42 在 21000 个时开始问（`rg` 2/3），24000 起都问；修订 41 到 27000 都拒绝；修订 40 从 24000、修订 39 从 21000 起问。成对的布局（n 个条目，一半是文件），修订 42 从 15000（7500 对）起都问，修订 41 都拒绝，修订 40 从 15000 起偶尔问，修订 39 从 21000 起问；这时修订 42 做了 7500 次 `lstat` 和 7502 次列目录，修订 39 做了 7503 次列目录，修订 41 只有 3 次。
- 原因：
  - `_sibling_state`（`subtree.py:502`）在列表里找不到名字时调用 `_alias_state`（`subtree.py:504`）；列表只记目录和链接（`subtree.py:718`），所以同名的文件兄弟也"找不到"，`lstat` 成功就是 `_ENTER`（`subtree.py:442`），再去列一个文件，失败（`subtree.py:685`）。
  - 这次调用不在列目录的循环里，但 `_out_of_time`（`subtree.py:581`）算的是从这次遍历开始到现在的时间；第一遍每 64 个条目读一次时钟（`subtree.py:704`）。出栈时花的时间在下一次读时钟时算进去。
  - R40-1 的布局里 `.env` 是第 27002 个条目，不是 64 的倍数，第一遍（`defer`）在完整匹配前也不读时钟，出栈之后再也没读过时钟，所以 0.41 到 0.45 秒（超过 0.35 秒）也"走完"了。后面只要再有 64 个条目，就用完预算。
- 规格修订 42 写了"它花的时间会在下一次读时钟时算进第一遍的 0.35 秒……门槛回到修订 39、40 的样子，比修订 41 早一点"，但又说"R40-1 仍是修好的"、"仍走完、仍拒绝"、"有兄弟的照旧从列表里取，不问盘"（文件兄弟要问盘）。记录第 6 节第 2 条"不读时钟，所以仍走完、仍拒绝"也不对。
- 前提：和 R40-1 一样，要两万多个没有兄弟的带点目录（或七千多对带点目录和同名文件），后面再有几十个条目。只能拼出问，不能拼出放行。
- **建议**：
  - 列表也记文件（只记名字），名字和文件对上时按列表定，不问盘（修订 41 的文档本来就说"文件不用打开"）；
  - 兄弟那次 `lstat` 的时间不算进第一遍的时钟：量出来还回去（`_scan_one` 把遍历时间还给请求，`event.py:1836`，是同一种做法），或者算在修订 40 自己的那份时间里。次数受条目数限制（每个带点目录最多一次）。只对含 `~` 或非 ASCII 的名字问盘，挡不住把目录起名叫 `k~0001.` 的布局；
  - 补 B2、B4 和成对布局的测试。这是代码改动，先改规格（修订 43），要不要做由使用者定。

### R42-2（低，判决变松，修订 42 让它更容易到；底下的毛病修订 39 就有）：工作目录超过上限时丢掉最新的

子代理找到（`plainlongfolder/a/b`、`.kube/config`）；我用别的名字重新量过（`rv42r_agentcheck2.py`）。布局：项目里 `srcfolderlong/x/y`（短名 `SRCFOL~1`）、`q/r/s`；项目外 `O/.kube/config`（编出来的；`config` 这个名字本身不受保护，只有它所在的目录让它受保护）。

| 命令（Bash） | 修订 42 | 41 | 40 | 39 |
|---|---|---|---|---|
| `cd <O>/.kube && cat config` | DD | DD | DD | DD |
| `cd SRCFOL~1 && cd x && cd y && cd <O>/.kube && cat config` | AS | DD | DD | DD |
| 同上，用 `;` 连；PowerShell 四个 `Set-Location` 再 `Get-Content config` | AS | DD | DD | DD |
| `cd SRCFOL~1 && cd x && cd <O>/.kube && cat config` | DD | DD | DD | DD |
| `cd srcfolderlong && cd x && cd y && cd <O>/.kube && cat config` | AS | AS | AS | AS |
| `cd q && cd r && cd s && cd <O>/.kube && cat config` | AS | AS | AS | AS |
| `cd q && cd r && cd <O>/.kube && cat config` | DD | DD | DD | DD |

- 送审时灰色原因是 `cwd-unknown`。Git Bash 跑完了整条（`… && wc -c < config` 打印 11）。
- 原因：每个 `cd` 都留着原来的目录（`cd` 可能失败），再加上新的；三个 `cd` 之后就有 8 个可能的目录。`_merge_cwds`（`event.py:1949`）超过 `MAX_CWDS`（8，`event.py:98`）时留下前 7 个已知的，也就是最早的，再加"不知道"；第四个 `cd` 的目标（几个 `cd` 都成功时唯一真实的那个）被丢掉，`cat config` 只在旧目录和"不知道"里找，成了灰色。修订 42 的 `cd` 进短名把解析到的目录加在"不知道"旁边（`event.py:1994`），多一个目录，少一个 `cd` 就到上限。
- 只对名字本身不受保护的文件有用：我第一次用 `.aws/credentials`、`.ssh/id_rsa` 量，四版都拒绝（名字就对上了规则）。
- 定成低危：不放行，没有后端时问；但不要任何特别的目录布局，四个普通的 `cd` 就到，凭据目录里的文件送给模型去判。
- **建议**：超过上限时留下最新的目标，丢掉最早的（丢掉的照旧换成"不知道"，放行那边看到的不变）；补测试。要不要做由使用者定；复审建议和 R42-1 一起做。

### R42-3（低，判决变松，修订 42 引入，不是新能力）：新的解析和遍历花的是共用的预算

子代理找到，三处我都用别的名字重新量过（`rv42r_agentcheck.py`、`rv42r_agentcheck2.py`、`rv42r_agentbig.py`）。都是由拒绝变成问（不送审）；长名写法四版本来就这样。

| 哪份预算 | 布局 | 命令 | 修订 42 | 41 | 40 | 39 |
|---|---|---|---|---|---|---|
| 修订 39 的 64 次查盘（`MAX_DISK_KEYS`） | `longnamedfolder`（`LONGNA~1`），联接 `jj` 指向项目外的 `.ssh`（里面 `config`） | `cd LONGNA~1; cat b00 … b35; cat <P>/jj/config` | AA | DD | DD | DD |
| 同上 | 同上 | 只写 `b00 … b29` | DD | DD | DD | DD |
| 同上 | 同上 | `cd longnamedfolder; cat b00 … b35; cat <P>/jj/config` | AA | AA | AA | AA |
| 第一遍的 30000 个条目 | `bigfoldername/big/` 里 30001 个干净文件（`BIGFOL~1`），项目外 `O/secretsz/.env` | `rg made BIGFOL~1/* <O>/secretsz`、`cd BIGFOL~1 && rg made big <O>/secretsz` | AA | DD | — | DD |
| 同上 | 同上 | `rg made bigfoldername/* <O>/secretsz` | AA | AA | — | AA |
| 修订 40 的 64 次查询（`MAX_READING_DISK_KEYS`） | `longerfolder/m00.`…`m63.`（空，`LONGER~1`），联接 `zq.` 指向项目外放着 `.env` 的目录 | `rg made LONGER~1/m* ???`、`grep -r made LONGER~1/m* ???` | AA | DD | DD | AS / AA |
| 同上 | 同上 | `rg made longerfolder/m* ???` | AA | AA | AA | AS |

- 操作数倒过来写时都拒绝。PowerShell 的写法和 Bash 一样。Git Bash 经过 `jj` 读到了 11 个字节。
- 原因：
  - 查盘：相对路径在每个已知的工作目录里各解析一次，每次一次查盘（`event.py:1353`）；`cd` 进短名多一个已知目录，次数翻倍，过了 64 次整行进入词法模式，联接不再解析。
  - 第一遍：通配符现在展开（`paths.py:1650` 起），`cd` 的目标现在往下找，大目录先走完共用的第一遍，后面的操作数停在 `event.py:1745`。
  - 查询：通配符匹配到的带点名字每个都用修订 40 的查询（`event.py:1203` 起）。
- 规格修订 42 只说了"修订 42 的几处新解析也在这一份里"（第三处），前两处没写；"只比修订 41 变严"不成立。
- **建议**：写进规格的代价（和 R39-3、R40-2、R41-2 同一类）。复审推荐只写进规格。

### R42-4（低，判决偏松，原来就有）：同名的假目录让 Win32 那种读法不查

两边都发现。我的布局（`rv42r_variants.py`）：`P/vaultstorage./.env`（短名 `VAULTS~1`），旁边一个真叫 `VAULTS~1.` 的干净目录（里面 `a.txt`）。经 `\\?\` 列 `VAULTS~1` 得到 `.env`，列 `VAULTS~1.` 得到 `a.txt`。

| 命令 | 修订 42 | 修订 41 |
|---|---|---|
| `rg made VAULTS~1.`、`tar -czf o.tgz VAULTS~1.`、`Grep path=…\VAULTS~1.`、`Copy-Item -Recurse VAULTS~1. b` | AS | AS |
| 对照：没有那个假目录 | DD | AS |

- 子代理用 `P\VAULTS~1.\`（空）量到四版都是 AS。
- 实际会读到（`rv42r_real.py`）：Python 的 `os.listdir('…\VAULTS~1.')`（Win32 路径）列出 `.env`；cmd 的 `dir /s /b VAULTS~1.` 列出 `VAULTS~1\.env`；`findstr /s /m MADE VAULTS~1.\*` 读到 `VAULTS~1.\.env`；Git Bash 保留点，只读到那个干净的目录；PowerShell 5.1 的 `Get-ChildItem`、`Set-Location` 和 .NET 的 `GetFiles` 出错。子代理另量到 `os.walk` 列出 `.env`。
- 原因：`_first_on_disk`（`event.py:1017`）取第一个在盘上存在的；`_resolved_kept_forms` 先给保留点的原文、再给 key（`event.py:1418`）。原文 `VAULTS~1.` 存在（假目录），key（Win32 读的那个）就不查了；盘上解析出来的那份的 key 去掉了点（`vaultstorage`），自己往下找什么也没有。规格写的"保留点的原文……解析不到（不存在）时，再用 key 解析一次"和代码一致，问题在"解析不到时"。
- **建议**：随下一次修订，先改规格：两种读法都查，各自记下（每条路径最多两次，规格已经这样算）；`cd` 的目标也一样，两个都加进可能的工作目录。补这个布局的测试。要不要做由使用者定。

### R42-5（低，判决偏松，原来就有）：不带点的、像短名的真实长名

子代理找到（`notes~1`）；我用 `data~1` 重新量过（`rv42r_agentcheck.py`）。布局：`P/data~1/.env`、`P/data~1/sub/.env`（`data~1` 是长名，盘上没有另外的短名）。

- 四版都是 AS：`rg made data~1`、`tar -czf o.tgz data~1`、`rg made data~1/sub`、`Grep path=…\data~1`、`Copy-Item -Recurse data~1 b`、`cd data~1 && rg made sub`、`cd data~1. && rg made sub`、`cd 'data~1 ' && rg made sub`、`Set-Location data~1; rg made sub`。对照 `cat data~1/.env` 四版都拒绝。
- 实际会读到：Git Bash 的 `grep -rl MADE data~1` 列出 `data~1/.env`、`data~1/sub/.env`；`cd data~1 && grep -rl MADE sub` 列出 `sub/.env`。子代理另量到 cmd 的 `dir /s`、PowerShell 的 `Set-Location notes~1` 也列出 `.env`。
- 原因：带 `~数字` 的名字都标上 `short-name-unresolved`；盘上解析出来还是同一个 key，仍不确定。R41-3 修的 `notes~1.` 靠的是"只差读法"（`_short_and_reading`，`event.py:1033`），不带点就没有读法，只剩那份不确定的路径，不往下找（`_native_dir`，`event.py:1683`）。`cd` 的目标解析到的也"像短名"，`_cd_short_target` 返回 None（`event.py:1942` 之后）。
- **建议**：随下一次修订，先改规格：盘上解析出来正好是写的那个长名时，它就不是没展开的短名，按确定的处理（操作数和 `cd` 都是）。补测试。要不要做由使用者定。

### R42-6（低，判决偏松，原来就有）：经短名进到带点目录之后，里面的 Win32 兄弟不往下找

子代理找到（`vaultstorage./inner.`）；我用别的名字重新量过（`rv42r_agentcheck.py`）。布局：`P/archivefolder.`（短名 `ARCHIV~1`）里一个空目录 `cfg.`，旁边联接 `cfg` 指向项目外放着 `.env` 的目录；对照 `P/plainarchive/`（短名 `PLAINA~1`）里同样的东西。

| 命令 | 修订 42 | 41 | 40 | 39 |
|---|---|---|---|---|
| `Grep path=…\ARCHIV~1.`、`Grep path=…\ARCHIV~1`、`Grep path=…\archivefolder.` | AS | AS | AS | AS |
| `rg made ARCHIV~1.` | AA（`recursive-scan-link`） | AS | AS | AS |
| `rg made ARCHIV~1`、`tar -czf o.tgz ARCHIV~1`、`Copy-Item -Recurse ARCHIV~1 b` | AA | AA | AS | AS |
| 对照：`Grep path=…\PLAINA~1`、`rg made PLAINA~1`、`rg made plainarchive` | DD | DD | DD | DD |

- 实际会读到：cmd 的 `findstr /s /m MADE ARCHIV~1\*` 读到 `ARCHIV~1\cfg\.env` 和 `ARCHIV~1\cfg.\.env`（经过 `cfg.` 打开的是联接 `cfg`），经 `ARCHIV~1.\*` 一样；经 `archivefolder.\*` 什么也没有（Win32 去掉点，没有 `archivefolder`）。`rg` 那几条问（不送审），是因为别的路上碰到了联接。
- 原因：短名解析出来的目录名字以点结尾，按"保留点的读法"走（`kept=True`，`event.py:1737`、`event.py:1766` → `subtree.py:571` 的 `_KEPT`），这种遍历不找 Win32 兄弟（`subtree.py:682`、`subtree.py:724`）。可 Win32 程序是经短名进去的，在里面照旧按 Win32 的方式打开名字。
- **建议**：随下一次修订，先改规格：经 8.3 短名到达的带点目录，Win32 程序进得去，按两种读法走（`_BOTH`），里面的 Win32 兄弟也找。补测试。要不要做由使用者定。

### R42-7（信息）：`cd` 进短名之后用短名写的程序，由"不送审"变成送审

子代理找到；我用别的名字重新量过。布局：`P/longtoolsfolder/myprogram.exe`（空文件，没有运行；短名 `LONGTO~1`、`MYPROG~1.EXE`）。

- `cd LONGTO~1 && ./MYPROG~1.EXE --version`、`./MYPROG~1`、PowerShell 的 `Set-Location LONGTO~1; .\MYPROG~1.EXE --version`：修订 42 送审（`program-short-name`），修订 39 到 41 问、不送审（`program-short-name-unresolved`）。长名写法 `cd longtoolsfolder && ./myprogram.exe --version` 四版都送审。
- `cd LONGTO~1 && cd .. && ./MYPROG~1.EXE --version` 修订 42 也送审：`cd ..` 可能失败，原来的目录照旧算一个可能的工作目录（设计如此）。
- 判决不变（问），变的是送不送审，和长名一样。记录第 1 节只写了变严的、请求多了路径的和原有差分里由灰色变成拒绝的 3 行，没写这一类。**建议**：随下一次修订写进记录。

### R42-8（信息，文档）：几处说法

1. "只比修订 41 变严"（规格修订 42 的开头、记录第 1 节的小标题）：有 R42-1、R42-2、R42-3，不成立。代码提交说明写的是"in everything measured"，没说错。
2. 规格 R41-1 那条"R40-1 仍是修好的"、"仍走完、仍拒绝"、"比修订 41 早一点"、"有兄弟的照旧从列表里取，不问盘"，记录第 6 节第 2 条"不读时钟，所以仍走完、仍拒绝"：见 R42-1（门槛 21000 对 27000 以上；文件兄弟要问盘，门槛比修订 39 还早）。
3. 记录第 3 节和代码提交说明"目标里还有别的不确定（变量、非法字符）时不查"：环境里有的变量会展开，展开后照样查（`Set-Location $env:BKDIR\PLAINL~1; rg made sub` 修订 42 拒绝、修订 41 送审）；环境里没有的才不查（`$env:BKNOTSET` 四版都送审）。应写"展不开的变量"。
4. 规格"仍有的"那条"PowerShell 的通配符会不会按 8.3 短名匹配（`Get-ChildItem PLAINL~?`），没有量"：这次量了。PowerShell 5.1 的 `Get-ChildItem -Path PLAINL~?` 什么也不列，`Get-Content PLAINL~?\.env` 出错；Git Bash 的 `cat PLAINL~?/.env` 读不到；只有 cmd 的 `dir /b PLAINL~?` 列出 `plainlongfolder`。`Get-Content PLAINL~?\.env`、`cat PLAINL~?/.env` 修订 42 和 41 都拒绝（最后一段是 `.env`）。
- **建议**：随下一次修订改文字。

## 3. 核对过、没有问题的

| 检查 | 结果 |
|---|---|
| R41-1 修好了 | 子代理在 6 种布局里量了 18 条（`AAAALO~2`、`LONGFO~1.NAM`、下一层、U+1FA0/1FA8、U+1FB3/1FBC、`.svn` 的 `SVN~1`）：修订 42 都拒绝，修订 41 放行或问，修订 39、40 拒绝；`findstr`、`os.walk` 经过带点目录读到了 `.env`。我没有另量这几种写法 |
| R41-3 修好了 | 我量的 `cd` 写法（`rv42r_variants.py`）：`pushd`、`cd ./X/`、小写短名、绝对路径、`cd X && grep -r`、`sl`、`Push-Location` 7 条由送审（`grep -r` 那条是规则的问）变成拒绝，`cd X/sub`、`cd X && cd sub`、`cd X && cat sub/.env`、`Set-Location -Path X\sub` 两版都拒绝；没有假目录的 `VAULTS~1.` 由送审变成拒绝。子代理另量了 13 种写法、18 种 `cd`、`Set-Location`、`pushd` 的写法，都由送审变成拒绝 |
| R41-4 修好了 | `cat PLAINL~1/.e*`、`Get-Content PLAINL~1\.e*` 由送审变成拒绝；`cat PLAINL~1/*`（目录里有 `.env` 和 `a.txt`）仍是灰色、送审，请求多了匹配到的路径。子代理另量了 12 种写法，都拒绝 |
| 放行那边 | 我量的 `cd CLEANL~1 && cat a.txt`、`ls`、`git status`、`pwd`、`rg made .`、`cat sub/a.txt`，PowerShell 的 `Get-Content`、`Get-ChildItem`，`cat`、`rm`、`cp`、`ls`、`Get-Content`、`Remove-Item` 加前缀写成短名的通配符：判决两版相同，9 条请求多了路径。子代理 191 条里 0 条新放行 |
| 记录里的数字（`rv42r_counts.py`，子代理另数了一遍） | 都和 scratchpad 的原始输出对得上：探针 59 条，27 条变严（J1 4、G1 1、U1 4、J2 2、A1 3、L1 3、D1 4、E1 4、E2 2，都变成 `no-secret-read`），0 条变松，请求变了 23 条（16 条原来送审、现在拒绝，7 条两版都送审）；修订 41 的探针 49 条、修订 40 的 61 条都没变；速度测量里 27000 个没有兄弟的空目录第一遍 0.409 到 0.446 秒，交错的布局两版都问；变异 228 个，第一轮 222 个抓到，存活的 6 个就是记录列的那几个；全量 30696 + 169 = 30865，用时 1:27:23 |
| 新测试在两份代码上 | 子代理重跑：新代码 32 passed；`8d43a51` 上 25 failed、7 passed，和记录一样 |
| 大小写表 | 子代理用内核重新算过：NTFS 认作同一个、`windows_fold` 分开的 27 对；反过来 0 对，基本平面以外也是 0 |
| 出错 | 所有脚本都没有异常；搭的目录都删了 |

没有量的：
- ripgrep（没装）、PowerShell 7、Linux、macOS、网络位置；
- 符号链接（错误 1314）：新的 `_existing_realpath`（`event.py:1011`）对 `realpath` 的结果再做一次 `lexists`，结果是共享路径时会再碰一次服务器；`realpath` 本身已经会打开符号链接的目标，`resolve_on_disk` 从修订 39 起就这样（`paths.py:1746`），`paths.py:1755` 对 `stat` 特意避开了共享路径；
- 不生成短名的卷、别的卷的大小写表；
- 真实的守护进程（2 秒）、真实宿主；
- 变异、语料、探针、原有差分、全量：这次没有重跑。

## 4. 建议的顺序

1. R42-1：列表也记文件；兄弟那次 `lstat` 的时间不算进第一遍的时钟（或算在修订 40 自己的那份时间里）；补 B2、B4、成对布局的测试。代码改动，先改规格（修订 43），要不要做由使用者定。
2. R42-2：工作目录超过上限时留下最新的目标；补测试。它原来就有，不要特别的布局，凭据目录里的文件会送给模型；复审建议和 R42-1 一起做，由使用者定。
3. R42-4、R42-5、R42-6：随下一次修订，先改规格，补测试；要不要做由使用者定。
4. R42-3：写进规格的代价。复审的推荐是只写进规格。
5. R42-7、R42-8 随下一次修订改文字。

这份复审没有改代码。
