# 读法不确定只关 allow 侧（规格修订 13）

日期：2026-11-05。基线：`d1729dd`。依据：复审 `docs/reviews/M3a-dots-and-folding-review.md` 的 RV-1、RV-2、RV-3。使用者说"修这三条"。没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次和攻击样本；判决都用假后端（总是放行），真实文件都在 scratchpad 或 `tmp_path` 里，内容是假的，用完已删。

## 1. 结论

**三条都修了。** 代码提交 `372bfa1`，文档在其后一个提交。RV-1 的回退没有了：23544 条真实联接点、真实磁盘的差分，对比修订 10 之后的 `78127af`、修订 11 的 `2f8f59d`、修订 12 的 `d1729dd`，都没有一条变松。规则条目和策略文件没有改，评测除日期和延迟外与记录相同。全量 28098 通过、169 跳过、0 失败（第 5 节）。第一次全量查出我修过头了，把 git 的普通命令也改成了问，已修（第 4a 节）。

**这次的原则**：路径的"不确定"分两种。一种是说不清目标（变量、通配符），一种是目标就那么几个，只是说不清程序走哪种读法（尾随点、空格、流名）。后一种只关 allow 侧，磁盘照样查。这本来就是规格 §5.1 的方向规则，修订 11、12 没有守住。

## 2. 修改前后

真实联接点：项目里 `guard`→`~/.boundkeep`、`keys`→`~/.ssh`、`cc`→`~/.claude`。"有后端"的假后端总是放行。

| 发现 | 写法 | 修改前，无后端 / 有后端 | 修改后，无后端 / 有后端 |
|---|---|---|---|
| RV-1 | PowerShell `Set-Content guard\policy.yaml. x`（真的会写到那里） | 问 / 送审，无决定 | **deny / deny** |
| RV-1 | PowerShell `Set-Content guard.\policy.yaml x` | 问 / 送审，无决定 | **deny / deny** |
| RV-1 | PowerShell `Get-Content keys\config.`，`Set-Content keys\config. x` | 问 / 送审，无决定 | **deny / deny** |
| RV-1 | `Read keys\config.`，`Write cc\settings.json.` | 问 / 送审，无决定 | **deny / deny** |
| RV-1 | Grep、Glob `path=<项目>\keys.`，Bash `ls keys.` | 问 / 送审，无决定 | **deny / deny** |
| RV-1 | `cd keys. && ls`，`Set-Location keys.; Get-Content config` | 问 / 送审，无决定 | **deny / deny** |
| RV-1 | `cat k*/config.`，`Get-Content k*\config.` | 问 / 送审，无决定 | **deny / deny** |
| RV-1 | `Read out\notes.txt.`（`out` 通向没有规则点名的目录） | 问 / 送审 | **不变** |
| RV-1 | `Read a.txt.`、`Grep path=clean.`、`cd clean. && cat c.txt` | 问 / 送审 | **不变**，allow 侧仍然关着 |
| RV-2 | Git Bash `mkdir ../work:s`，`cat ../work:s/left.txt`，`cd ../work:s && cat left.txt`，`ls`，`touch` | 无决定，规则放行，真的读写到项目外 | **问**（命令照样能跑，变的是 boundkeep 不再替它说"在项目里"） |
| RV-2 | `work\uf03as` 是通向 `~/.ssh` 的联接点：`cat ../work:s/config` | 无决定 | **deny** |
| RV-2 | `Read C:\proj\sub:s\a.txt` | 无决定 | 问 |
| RV-2 | `Read C:\proj\a.txt:s`，`a.txt::$DATA`（文件工具、最后一段） | 无决定 | **不变**：真的是这个文件的流 |
| RV-2 | `git diff -- ':!x'`，`git status --short -- ':!eval'`，`git log -- ':/src'`，`git add ':!x'`（两种 shell） | 无决定 | **不变**：这是 git 自己的魔法，不是路径（第 4a 节） |
| RV-3 | `Read \\localhoſt\c$\proj\a.txt`，`Write` 同上，`cat` 同上 | 无决定，有无后端都一样 | **问**（`net-unknown-destination`） |
| RV-3 | `\\deſk-pc\c$\…`（`COMPUTERNAME=DESK-PC`） | 无决定 | **问** |
| RV-3 | `\\localhoſt\share\x.txt`，`\\wſl$\Ubuntu\x.txt` | 无后端问，有后端送审 | **问，不送审** |
| RV-3 | `\\localhost\c$\proj\a.txt`，`\\DESK-PC\c$\proj\a.txt`（真的是本机） | 无决定 | **不变** |

## 3. 修法

- **`src/boundkeep/normalize/paths.py`**：
  - RV-1：新函数 `reading_only`（路径只因读法不确定）。`_resolve_on_disk`、`_expand_glob` 不再把这些原因（`trailing-dots-spaces-ambiguous`、`stream-name-ambiguous`、`extended-path-dots`、`cwd-uncertain`）当阻塞，结果仍然不确定。
  - RV-1：新函数 `reading_text`：保留点的读法，`c:/proj/keys./x`，Git Bash 里 `:` 映射成 `U+F03A`。
  - RV-2：`_norm` 里，`ads-stripped` 在 bash 方言或流名不在最后一段（`_stream_before_last`）时，加 `stream-name-ambiguous`，算不确定。
  - RV-3：`_unc_shape` 用 `windows_fold` 比较主机名和 `COMPUTERNAME`。
- **`src/boundkeep/normalize/event.py`**：
  - RV-1：`_refs_one` 对只因读法不确定的路径也查磁盘，并加上 `_kept_forms`（保留点的读法，`\\?\` 加原文解析）。
  - RV-1：`_native_dir` 让这样的路径也做目录扫描；`_cd_target` 返回保留点的文本，所以 `cd keys.` 之后的相对路径看得到磁盘，也仍然不确定；Glob 的 `pattern` 带路径时，`path` 带点也能作锚点。
  - RV-3：`_unc_server` 用 `windows_fold`；`_unc_refs` 里非 ASCII 的主机名算目的地未知。
  - RV-2 的修正：`_stages_whole_repository` 把 `pathspec_magic` 也算作暂存整个仓库（第 4a 节）。
- **`src/boundkeep/normalize/programs.py`**：RV-2 的修正：`_pathspec` 和 `CmdInfo.pathspec_magic`（第 4a 节）。
- **规格**：修订 13，§5.1。`policies/` 没有改。

## 4. 和复审建议不同的地方

- **主机名还多一层。** 复审只点了 `casefold`。换掉之后，`canonical_host` 的 IDNA 仍然把 `localhoſt` 读成 `localhost`，`_unc_refs` 又把它算成本机。所以非 ASCII 的 UNC 主机名一律算目的地未知。这样也挡住了全角数字（`\\１２７.0.0.1\…`）和把 `ſ` 写进允许域名的写法。
- **"Win32 打不开中间的冒号"不全对。** 复审和我最初写进规格的话都这样说。实测 `dir::$INDEX_ALLOCATION\a.txt`、`dir:$I30:$INDEX_ALLOCATION\a.txt` 在 Python、Node、PowerShell 5.1、cmd 里都打得开，读的就是 `dir\a.txt`。仍然标不确定（正常写路径用不到），磁盘照查，所以经过联接点的这种写法也是 deny。规格已改对。
- **`cd` 复审没有点到。** 只改 `_resolve_on_disk` 不够：`_cd_target` 对不确定的路径返回未知，`cd deep. && cat inner/config` 就看不到 `inner` 是链接。

## 4a. 第一次全量查出来的错

修完之后我报告"都没有变松"，这是真的，但第一次全量有 10 个失败（28192 条里 10 失败、28013 通过、169 跳过，耗时 2:09:27），说明我把判决改严了，又没有发现：

- **9 个是我修过头了。** Git Bash 里所有带冒号的词都算不确定，`git add :/`、`git diff -- ':!x'`、`git status --short -- ':!eval'` 这些普通命令因此从规则放行变成问；PowerShell 里 `git log -- ':/src'`、`git diff --stat -- ':!eval/results'`、`git blame -- ':/a.py'` 也一样（`:` 在最后一段之前）。这是误报，我之前列的代价里没有它。差分没有发现，因为我的差分只管"有没有变松"，变严全部归为预期；而且语法里只有 `cat`、`rm`、`Get-Content` 这些程序，没有 git。
- **实测**（真 git，临时仓库，Git Bash 和 PowerShell 5.1 结果相同）：Git Bash 把 `:/src`、`:!x`、`:^x`、`:(top)src`、`:!/x`、`:!a/b` 原样传给原生程序；`add`、`rm`、`clean`、`restore`、`commit`、`stash push`、`diff`、`log`、`status`、`ls-files`、`grep`、`archive` 都按魔法解析；`mkdir ':lit'` 写出来的 `U+F03Alit`，`git status -- ':lit'` 不认，读的是 `lit`；`:/../outside/z`、`:(top)../outside/z`、`:!../outside/z` 都没有碰工作树外的文件。`blame`、`annotate`、`mv`、`hash-object`、`update-index`、`checkout-index`、`apply` 不解析魔法，把这个词当普通名字。
- **修法**（规格 §5.1 先改）：`programs._pathspec`：git 按 pathspec 读的操作数，开头的魔法到第一个分隔符为止读作 `.`（`:/src` 是 `./src`，`:!x` 是 `.`），和修订 13 之前的 key 相同，判决回到原样。`CmdInfo.pathspec_magic` 留给 `git add` 的"暂存整个仓库"检查。不解析魔法的子命令和 `-C`、`--git-dir`、`--work-tree`、`--pathspec-from-file` 的值仍然不确定。
- **`git blame -- ':/a.py'` 变严了，保留。** 它原来放行，现在问。git 把这个词当文件名，命令本身失败，放不放行都没有实际意义，所以不为它开例外。
- **1 个是测试钉的旧值，改了语料。** `pytest '@C:\Users\testuser\x.txt'` 由灰色变成问（`ask-devtools-path-outside-project`）。它要读的文件确实在项目外，POSIX 上同样的写法 `m2r-h1-017`、`m2r-h1-018` 本来就是问，所以这是修正。`tests/corpus/pipeline_m1c2_trusted.yaml` 的 `m2r-h1-010` 由 `gray` 改成 `ask`。没有后端时两者都是问；有后端时不再送审。

## 5. 度量

| 项目 | 结果 |
|---|---|
| 新测试 `tests/unit/test_m3a_readings.py`（真联接点，文件工具、Bash、PowerShell，有无后端） | 295 passed（220 条加 git 魔法的 75 条） |
| **真实磁盘差分**（新做的，审查时缺的就是它）：真联接点、真磁盘查询，23544 条（9 个目录 × 6 种后缀 × 6 个文件 × 5 种后缀 × 7 种写法，加目录级的 8 种写法，乘有无后端）。级别：deny > 问 > 送审 > 规则放行 | 对 `78127af`：收紧 6371，**变松 0**。对 `2f8f59d`：收紧 6926，**变松 0**。对 `d1729dd`：收紧 7271，**变松 0** |
| 假机器差分（`d1729dd` 对当前，179508 条） | 收紧 1371，**变松 0**。比修 git 之前多 1 条：`Write 1:\..\ſettings.json` 有后端时由送审变成 `gray-unanalysed` 的问。它和 git 无关，单跑 5 次两边都是送审，差分当时在和变异测试抢 CPU，可能是时间预算用完了，没有确认；方向是收紧 |
| 带冒号的普通命令（新加的，164 条 × 3 种策略，492 条；有 git 魔法，这是上面的差分缺的） | 相同 475，收紧 17，**变松 0**。收紧的只有 `git blame -- ':/a.py'`（两种 shell，命令本身就失败）、Git Bash 的 `cat a.txt:s`、`ls sub:s`、`ls sub:s/x`，和有后端时的 `cp a:b c`、`ls /c/x:y`（`llm-failure:refused`） |
| 孪生字母项目的差分（`d1729dd` 对当前，5 台假机器，30720 条） | 级别全部相同，**变松 0** |
| 写法扫描（13104 条，项目的同级目录加 36 种后缀） | 规则放行只剩两类：文件工具最后一段的流（读的是项目目录自己的流）；`/.`、`/x/..` 这些折回项目的写法。Bash 里的冒号、所有尾随点和空格都是 0 |
| 真实 Git Bash 链路 | 第 2 节的 RV-2 行都量过；命令照样能跑，判决是问或 deny |
| 真实 PowerShell 5.1 | `Get-Content`（带不带 `-LiteralPath`）、`cmd type`、Python `open` 都读到 `keys\config.` 的目标，`Set-Content` 写穿了假策略文件。这正是判决回到 deny 的理由 |
| key 稳定性：108 万次 | 不稳定 0 |
| `Weiß` 下的代价：120 个判决对比普通用户名 | 0 处不同 |
| 变异：30 个（`disk:*`、`scan:*`、`glob:*`、`cd:*`、`kept:*`、`anchor:*`、`only:*`、`text:*`、`stream:*`、`server:*`、`unc:*`），副本上跑 5 个测试文件 | **29 个抓到，1 个存活**。第一轮 8 个存活，说明测试没盯住 `cd` 这一层（`cd keys.` 本身就被 deny，掩盖了后面的判断）和"结果仍然不确定"，补了测试之后分两轮重跑（只重跑存活的）。存活的 `cd:any-uncertain` 去掉 `_cd_target` 里的 `reading_only` 检查：只影响 8.3 短名这类本来就不确定的路径，工作目录仍然不确定，判决不变。这 30 个是修 git 之前跑的，修完没有重跑 |
| 变异：git 魔法的 13 个（`spec:*`、`stage:ignored`），副本上跑 2 个测试文件 | **全部抓到**。第一轮 2 个存活（`spec:slash-only`、`spec:not-dynamic`），补了测试之后重跑这两个，都抓到 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过；77 个源文件没有问题 |
| `boundkeep test` default / strict | 1142 / 0 失败，334 / 0 失败 |
| 评测（`--config rules+taint --test-contaminated`，输出到 scratchpad，没有打开留出批次） | `results/*.json` 去掉日期、延迟、sha 之后相同；`report.md` 只有日期一行和 4 行延迟不同（后台任务在抢 CPU）。策略 sha256 没变，所以仓库里的评测文件没有重新生成 |
| 全量（分六段跑，不是一个进程，当前代码） | **28098 通过、169 跳过、0 失败**，2:08:06。六段都一次跑完，合计 28267 条，与收集到的相同，测试文件清单与 `tests/` 相同；运行期间 `src/`、`tests/`、`policies/`、`eval/` 没有文件变化。有 1 条警告，见下 |

全量的那条警告：`test_oversize_request_is_gray_without_touching_the_child` 名下的 `PytestUnhandledThreadExceptionWarning`（`OverflowError: timeout value is too large`），警告只是记在这个测试名下。`test_norm_psparse.py` 有两个测试把 `breaker_cooldown_s` 设成 `1e9`，熔断时 `_schedule_start` 用它起一个定时器，超过了 Windows 的等待上限（`threading.TIMEOUT_MAX`，约 49.7 天），定时器线程抛错；如果线程进入等待之前定时器已被取消，就没有警告，所以上一轮全量没有出现（这一点是推断，没有复现这个竞争）。单独起这么长的定时器能复现这个错误，60 秒的不会。默认冷却是 60 秒，也没有配置入口，所以这只是测试的参数造成的。这次没有改这两个文件，也没有处理这条警告。

已修改的旧测试：`test_norm_paths.py` 两行（`ads-index-allocation`、`ads-only-stream-component` 现在不确定）；`tests/corpus/pipeline_m1c2_trusted.yaml` 的 `m2r-h1-010`（第 4a 节）。这些是有意的行为变化。

## 6. 代价和残余

1. **Git Bash 里 `cat a.txt:s` 要问**，`rm -f a.txt:s` 按项目外算。这样的写法很少。
2. **配了后端时，Git Bash 里带冒号的路径不送审，直接问。** 保留的读法里有 `U+F03A`，发送出口拒绝看不全的字符（`llm-failure:refused`，实测原因是"a path holds a control or format character"）。这是失败即关闭，方向对；假机器差分里这类共 1204 条（1160 条原来送审，44 条原来规则放行）。
3. **非 ASCII 的 UNC 主机名**：`\\bücher.example\x` 即使域名在白名单里，也按未知目的地问。Windows 怎么读这种名字只量过 `localhoſt`，所以不替它做 IDNA。
4. **`reading_text` 只管普通盘符路径**：`\\localhost\c$\keys.\x` 没有保留点的读法，只有去掉的读法。
5. **`cd` 带冒号**：Git Bash 里 `cd keys:s` 的工作目录按 `keys\uf03as` 算（这是它真正进的地方）。别的程序里这条命令打不开目录。
6. **每个这样的路径多一次 `realpath`**，走原有的磁盘预算。这种路径本来就少。
7. **目录扫描只走去掉点的读法和解析出来的目标**：字面上的 `sub.` 是普通目录（不是链接）时，里面的 `.env` 扫不到，结果是问，不是 deny。这和修改前一样。
8. **`git blame -- ':/a.py'` 要问**（第 4a 节），命令本身就失败。
9. **`pytest '@C:\Users\testuser\x.txt'` 配了后端时不再送审**，直接问（`m2r-h1-010`）。
10. **git 魔法的例外靠子命令表**：`_GIT_PATHSPEC_ALL` 和 `after` 这条路径认哪些子命令，就替哪些读魔法。只量了第 4a 节列出的子命令和写法；表外的子命令里这种词仍然不确定，方向是多问。
11. **没有修的**：
   - 复审的 RV-4（大小写敏感目录）；
   - RV-6 里折叠表依赖 Python 的 Unicode 版本；
   - RV-7（系统目录的判断仍用 `casefold`，修复时才查到，范围是使用者定的）。之后已修，规格修订 14，记录 `docs/reports/M3a-program-fold.md`；
   - 上一轮的 GR-3、GR-4、GR-5。RV-5 只在记录开头加了更正，正文没有逐条改。

## 7. 没有做的

- 这次修复没有复审，包括 git 魔法的例外（它是放宽，又是第一次全量之后才加的）。复审 RV 本身也不是独立的。
- 没有重跑的：写法扫描、key 稳定性、`Weiß` 的代价、最早的 30 个变异。这些数字都在修 git 之前，修 git 只动了 git 的操作数。
- 真实 Claude Code 的 hook 链路里没有跑。宿主工具的读法只用复审时本会话的工具试过：Read、Write 保留点，Grep、Glob 去掉点。
- 只量了 C: 卷；FAT、exFAT、ReFS、SMB 没有量。
- 真实模型没有接过。
