# 规格修订 18 的复审

日期：2026-11-10。代码：`11dcecf`（`main`，与 `origin/main` 相同，工作区干净）。

审查对象：
- 代码改动：`git diff 7b65ad8 2534c31 -- src`。具体是 `programs._git_diff_trees`，`_git_operands` 里 `show` 的免扫描条件和 `archive` 的选项，`_pathspec` 的 top 与排除，`CmdInfo.top_paths`，`event._top_words` 与 `_cwds_below_project`，短名补 `.exe` 和裸短名（`_short_name_program`、`_bare_short_name`），以及 `pipeline._UNSHOWN_REASONS`。
- 规格：开头修订 18 的段落，§5.1。
- 修复记录：`docs/reports/M3a-rev17-review-fixes.md`。

**这不是独立复审。** 修订 18 是这个会话写的。本来提议另开一个不带上下文的会话来审，使用者选择在这里做。下面的结论都重新量过，没有直接照搬记录里的说法。不过作者的盲点，这次复审可能同样看不到。修订 17 的复审也是这样做的，结果漏了两处（见那份报告开头的说明）。

**本次没有做的事**：
- 只新增了这份报告，没有改代码、规格、策略和测试，也没有提交。
- 没有读 `.env`，没有用 LLM 密钥，没有访问真实 LLM 服务。
- 没有读 `eval/authoring/h1-*`、`h2-*` 和留出批次，没有改系统设置。
- 没有跑测试。代码自全量之后没有改，那次全量的结果在修复记录第 5 节。
- 没有做变异测试，没有重跑作者的扫描。

**判决怎么取的**：
- 在 TEMP（C: 卷，会生成 8.3 短名）下建假项目，含 `src/a.py`、`README.md`、`.env`、`secrets/id_rsa`、`sub/b.txt`（修订 18 测试文件的 `FULL`）。
- 用 `pipeline.review` 取规则层的判决，没有后端，平台 `windows`。PowerShell 命令经真实的 PowerShell 5.1 解析辅助进程。
- "子目录"指 hook 收到的工作目录是 `sub`。
- "修改前"指 `7b65ad8` 的 `src`，导出在 scratchpad，`PYTHONPATH` 指过去跑同一批命令。
- 实测用的 git 仓库也在 TEMP，有两个提交：
  - `init: add files`：`.env` 的内容是 `FAKE-SECRET-ENV`，`secrets/id_rsa` 的内容是 `FAKE-KEY-1`；
  - `fix: typo`：`secrets/id_rsa` 改成 `FAKE-KEY-2`，`sub/b.txt` 也改了。

  用完已删。
- 短名的实测用改了名字的 `whoami.exe` 副本，放在 TEMP 的长名目录里。
- 版本：git 2.48.1.windows.1，PowerShell 5.1，Git Bash 是 `D:\新建文件夹\Git\bin\bash.exe`。

下文的说法：
- "规则放行"：由 allow 规则给出。默认配置下，之后还有 Claude Code 自己的权限流程。
- "灰色"：没有规则作出决定。没有后端时问，有后端时送审。

## 1. 结论

**修订 18 的目标达到了，没有发现回退。**
- R17-1 到 R17-4 的写法，现在都是 deny 或者按设计处理。
- 复审漏掉的两处，现在都是 deny：`git show HEAD HEAD:src`，以及工作目录在子目录时的 `git log -p`。
- Git Bash 的短名，包在七种程序后面也都抓到了。
- 两种 shell 在 15 条对照命令上的判决，都不比 `7b65ad8` 松。

**但同一类读法里还有四个缺口。** 高危 0，中危 0，低危 4，信息 1。
- R18-1 是修订 18 自己的修法留下的；其余三个在 `7b65ad8` 上判决相同，比修订 18 早。
- **R18-1 到 R18-3 打印的内容，IR-7 的 `git diff <空树> HEAD` 都能打印。** 那条写法规则照样放行，实测打印出假 `.env` 和假私钥（第 3 节）。所以在使用者决定 IR-7 之前，修这三个不会减少 agent 实际能读到的内容。
- R18-4 和 IR-7 无关：它关系到守卫自己的状态命令。

| 编号 | 级别 | 一句话 | 要后端吗 | 来源 |
|---|---|---|---|---|
| R18-1 | 低 | 子目录里的 `git diff HEAD~1:secrets HEAD:secrets` **规则放行**，实测打印两个版本的假私钥；在根目录运行是 deny | **不要** | 修订 18 的修法本身。两棵子树的比较现在会扫描，但扫的是相对当前目录的路径；git 从仓库顶层读 `REV:PATH` |
| R18-2 | 低 | 花括号里带冒号的修订号被当成 `REV:PATH`。`git show 'HEAD@{10:00}'`、`git show 'HEAD^{/fix: typo}'` 在两种 shell 里都**规则放行**，`git show 'HEAD@{2026-11-09 10:00:00}'` 在 PowerShell 里**规则放行**；实测都打印整个提交的补丁，含假 `.env` | **不要** | 修订 18 之前就有（`_rev_path` 在第一个冒号处切开） |
| R18-3 | 低 | `git log -p --full-diff -- sub`、`git show --full-diff HEAD~1 -- sub` **规则放行**，只读了 `sub`；实测打印碰过 `sub` 的提交的全部补丁，含假 `.env` 和假私钥 | **不要** | 修订 18 之前就有。pathspec 缩小读取范围是修订 16 到 18 的前提，`--full-diff` 让它不成立 |
| R18-4 | 低 | `cd` 进路径里带短名的目录之后，`./BOUNDK~1 mode audit-only`（Git Bash）和 `.\BOUNDK~1.EXE mode audit-only`（PowerShell）是灰色、照常送审；目录写长名时是 deny。两种 shell 实测都运行 | 送审要 | 修订 18 之前就有。修订 18 只让裸短名不送审 |
| I-1 | 信息 | 同一条命令里先 `cd sub`（PowerShell 是 `Set-Location sub`）再 `git log -p`，在 `7b65ad8` 上两种 shell 都已经是 deny。修订 18 的子目录修复只改变 hook 收到的工作目录本身就在子目录里的情况，所以记录第 7 节的前提决定了这项修复在真实宿主里有没有用 | — | 补充说明 |

## 2. 发现

### R18-1（低）：子目录里比较两棵子树，扫描的位置不对

| 写法 | 工作目录 | 修订 18（两种 shell） | 修改前（两种 shell） |
|---|---|---|---|
| `git diff HEAD~1:secrets HEAD:secrets` | 根 | deny（`no-credential-store-read`） | 规则放行 |
| `git diff HEAD~1:secrets HEAD:secrets` | `sub` | **规则放行** | 规则放行 |
| `git diff HEAD~1:./secrets HEAD:./secrets` | `sub` | 规则放行 | — |
| `git diff HEAD:secrets`（一棵子树） | `sub` | deny | 规则放行 |
| `git show HEAD:secrets/id_rsa` | `sub` | deny（名字规则是 `**/` 形式，位置不影响） | — |

实测（工作目录 `sub`）：

| 命令 | 结果 |
|---|---|
| `git diff HEAD~1:secrets HEAD:secrets` | 打印 `-FAKE-KEY-1`、`+FAKE-KEY-2` |
| `git diff HEAD~1:./secrets HEAD:./secrets` | 退出码 128（`sub/secrets` 不存在） |
| `git diff HEAD:secrets -- .` | 不打印任何假密钥（pathspec 把范围限在 `sub/`） |
| `git archive HEAD:secrets \| tar -t` | 空归档 |
| `git grep -e FAKE HEAD:secrets` | 没有输出 |

**原因**：
- git 读 `REV:PATH` 时，PATH 从仓库顶层算，除非以 `./` 或 `../` 开头（上表第一、二行的对照）。
- `_git_operands` 列出 `REV:PATH` 时用的是 `a.path(_sub(w, rp))`，路径相对当前目录。
- 正好两个 `REV:PATH` 时，`_git_diff_trees` 设了递归之后直接返回，于是扫描的是 `sub/secrets`。那个目录不存在，什么也扫不到。
- `archive`、`grep` 在子目录里只看那棵树里与当前目录对应的部分（上表最后两行），所以它们从子目录读到的是灰色，这是对的。
- 读单个文件（`REV:文件`）时靠名字规则，也不受影响。

**修法**：对不以 `./`、`../` 开头的 `REV:PATH`，另外调用 `a.top_path(rp)`，和 `:(top)x` 用同一套机制。

**IR-7 的上限**：在根目录运行 `git diff HEAD~1 HEAD` 也是规则放行，打印的内容相同，而且更多。

### R18-2（低）：花括号里带冒号的修订号

git 找 `REV:PATH` 里的冒号时，跳过花括号里的冒号。下面的实测里，这几条都被 git 当作一个提交，打印整个补丁。

| 写法（根目录） | Bash | PowerShell | 修改前 |
|---|---|---|---|
| `git show HEAD`（对照） | deny | deny | deny |
| `git show 'HEAD@{10:00}'` | **规则放行** | **规则放行** | 相同 |
| `git show 'HEAD^{/fix: typo}'` | **规则放行** | **规则放行** | 相同 |
| `git show 'HEAD@{2026-11-09 10:00:00}'` | ask（`ask-git-read-outside-project`） | **规则放行** | 相同 |
| `git show 'HEAD^{/:?}'` | ask（`glob-not-expanded`） | ask | — |
| `git show 'HEAD^{/fix}'`（没有冒号） | deny | deny | — |
| `git archive 'HEAD@{2026-11-09 10:00:00}'` | 灰色 | 灰色 | — |

实测：

| 命令 | 结果 |
|---|---|
| `git show 'HEAD^{/init: add}'` | 第一个提交的全部补丁，含 `+FAKE-SECRET-ENV`、`+FAKE-KEY-1` |
| `git show 'HEAD@{10:00}'` | HEAD 的补丁，含 `-FAKE-KEY-1`、`+FAKE-KEY-2` |
| `git show 'HEAD@{2099-01-01 00:00:00}'` | 同上 |
| `git show 'HEAD^{/:?}'` | 同上 |

**原因**：`_rev_path` 在第一个冒号处切开，`HEAD@{10:00}` 被读成修订号 `HEAD@{10` 加路径 `00}`。`show` 的每个操作数都是 `REV:PATH` 时不扫描，于是规则放行。

两种 shell 在日期加时间的写法上判决不同，是 R17-6 那一类：PowerShell 更松。

**修法**：`_rev_path` 像 git 一样跳过花括号里的冒号。

**IR-7 的上限**：一个提交的补丁，`git diff <它的父提交> <它>` 也能打印，规则照样放行。

### R18-3（低）：`--full-diff` 让 pathspec 不再限制打印的内容

| 写法 | 工作目录 | 两种 shell | 修改前 |
|---|---|---|---|
| `git log -p -- sub`（对照） | 根 | 规则放行，只读 `sub` | 相同 |
| `git log -p --full-diff -- sub` | 根 | **规则放行**，只读 `sub` | 相同 |
| `git log -p --full-diff -- .` | `sub` | **规则放行** | — |
| `git show --full-diff HEAD~1 -- sub` | 根 | **规则放行** | 相同 |

实测：

| 命令 | 结果 |
|---|---|
| `git log -p -- sub` | 只有 `sub/b.txt` 的两段差异 |
| `git log -p --full-diff -- sub` | 两个提交的全部补丁，含 `+FAKE-SECRET-ENV`、`FAKE-KEY-1`、`FAKE-KEY-2` |
| `git show --full-diff HEAD~1 -- sub` | 第一个提交的全部补丁，含 `+FAKE-SECRET-ENV` |
| `git show HEAD~1 -- sub` | 只有 `sub/b.txt` |
| 在 `sub` 里运行 `git log -p --full-diff -- .` | 同第二行 |

**原因**：`_git_operands` 里，`--` 之后有 pathspec 就算"缩小了范围"（`restricted = bool(after) …`）。`--full-diff` 只用 pathspec 选提交，打印的是这些提交的全部改动。
`allow-git-read-only` 的 `flags_none` 里也没有它。

**修法**：二选一。
- 在 `_git_operands` 里，有 `--full-diff` 时不算缩小范围；
- 或者把它加进 `flags_none`。这要改策略，按 CLAUDE.md 要先改规格。

**IR-7 的上限**：同 R18-2。

### R18-4（低）：`cd` 进路径带短名的目录之后，短名程序照常送审

| 写法 | 修订 18 | 修改前 | 送审吗 |
|---|---|---|---|
| Bash：`cd '<…>/outsidetoolsdir' && ./BOUNDK~1 mode audit-only` | deny（`program-short-name`） | 灰色（R17-2，修订 18 修了） | — |
| Bash：`cd '<…>/OUTSID~1' && ./BOUNDK~1 mode audit-only` | **灰色**（`cwd-unknown`） | 灰色 | **送审** |
| PowerShell：`Set-Location '<…>\outsidetoolsdir'; .\BOUNDK~1.EXE mode audit-only` | deny | deny | — |
| PowerShell：`Set-Location '<…>\OUTSID~1'; .\BOUNDK~1.EXE mode audit-only` | **灰色**（`cwd-unknown`） | 灰色 | **送审** |
| Bash：`cd LONGSU~1 && git log -p`（项目里的子目录） | deny（另有 `cwd-unknown`） | deny | — |

实测：
- Git Bash `cd` 进短名目录（`…/RV18R_~2/LONGTO~1`）之后，`./LONGPR~1` 和 `./LONGPR~1.EXE` 都运行，退出码 0；
- PowerShell 5.1 `Set-Location` 进短名目录之后，`.\LONGPR~1.EXE` 运行。

**原因**：
- `cd` 的目标里有短名段时，守卫把工作目录记为未知。
- 之后带路径的短名程序没有办法展开，`_short_name_program` 返回 None。
- 修订 18 只给裸短名加了 `program-short-name-unresolved`（不送审），带路径但展开不了的短名没有加。

有后端时，模型看到的是一个说明不了自己是什么程序的名字。

**修法**：带路径、最后一段是短名、又展开不了时，也标 `program-short-name-unresolved`。要先定设计：
- 文件不存在时也这样标吗？修订 18 的测试 `test_a_short_name_with_no_file_even_with_exe_stays_gray` 要求那种情况仍是普通灰色。
- 要不要只在工作目录未知时标？

## 3. 核实了的说法

| 记录或规格里的说法 | 核实结果 |
|---|---|
| R17-1：`git diff HEAD:src` 现在是 deny | 成立，两种 shell 都是；修改前规则放行 |
| `git show HEAD HEAD:src` 现在是 deny | 成立，两种 shell 都是；修改前规则放行 |
| 子目录里的 `git log -p` 现在是 deny | 成立，两种 shell 都是；修改前规则放行 |
| 代价第 1 条：子目录里不带 `--` 的 `git log -p b.txt` 是 deny，`git log -p -- b.txt` 放行 | 成立；修改前两条都放行 |
| `grep`、`archive` 在子目录里只作用于当前目录 | 成立，带 `REV:目录` 时也是这样（R18-1 的实测表） |
| 工作目录在项目之外时不另读项目根 | 成立（代码与测试）。另外量了联接（junction）：项目目录是联接、工作目录走真实路径时，是 deny（`root_resolved` 起作用）；反过来，项目目录是真实路径、工作目录走联接时，是 ask（`ask-git-read-outside-project`）。都不放行 |
| Git Bash 运行不带 `.EXE` 的短名和经 PATH 的裸短名 | 成立。另外量了：包在 `env`、`command`、`timeout 5`、`nice`、`nohup`、`xargs`、`exec` 后面的裸短名也都运行，裸的 `LONGPR~1.EXE` 也运行 |
| 守卫对这些写法：裸短名是灰色、不送审；带路径的是 deny | 成立，上面七种包装后面也一样：裸短名都是 `program-short-name-unresolved`、不送审，带路径不带 `.EXE` 的是 deny |
| 代价第 6 条：PowerShell 5.1 不运行裸短名 | 成立，范围更宽：经 PATH 的 `LONGPR~1.EXE`、`longpr~1.exe`、`LONGPR~1` 都是 `CommandNotFoundException`，`Get-Command LONGPR~1.EXE` 也找不到 |
| 两种 shell 判决相同 | 这次的对照命令里只有一条不同：`git show 'HEAD@{2026-11-09 10:00:00}'`（R18-2），属于 R17-6 那一类 |
| IR-7 没有改 | 成立：`git diff 4b825dc642cb6eb9a060e54bf8d69288fbee4904 HEAD`、`git diff HEAD~1 HEAD`、`git diff HEAD~1` 在新旧代码、两种 shell 里都是规则放行。实测第一条打印 `+FAKE-SECRET-ENV`、`+FAKE-KEY-2` |
| 没有变松 | 这次的 15 条对照命令在两种 shell 里都不比 `7b65ad8` 松；根目录里两棵子树的比较由规则放行变成了 deny |

## 4. 范围

- 用到的探针都在这个会话的 scratchpad：`rv18r_probe1.py` 到 `rv18r_probe8.py` 取判决，`rv18r_real1.ps1`、`rv18r_real2.ps1` 实测短名。git 的实测直接在 Git Bash 里跑。
- 没有看的：
  - 仓库顶层在项目之上（monorepo）或项目里有嵌套仓库时的读法。记录第 6 节第 2 条已经写了这两种情况会少读、会多读。
  - `git -C`、`--git-dir`、`--work-tree`：`allow-git-read-only` 本来就不放行它们，是灰色。
  - `git log -p --follow`：改名之前的内容会被打印，没有实测。
- 真实宿主里没有跑。记录第 7 节的前提（Claude Code 是否把 `cd` 之后的目录带进下一次调用的 `cwd`）仍没有量过，见 I-1。

## 5. 建议的顺序

1. **先由使用者决定 IR-7。**
   - 如果 IR-7 记为接受的残余：把 R18-1 到 R18-3 写进威胁模型 IR-7 那一条，作为同类，不修。修了也不减少 agent 能读到的内容。
   - 如果要收紧 IR-7：R18-1 到 R18-3 要一起处理，否则仍是绕过的路。三处的改动都不大，见各条的修法。
2. **R18-4 和 IR-7 无关**，可以单独修。要先定设计（展开不了的带路径短名标什么，文件不存在时怎样），补测试，按惯例跑差分和全量。
3. **真实宿主**：记录第 7 节的前提，和 M3b 的真实冒烟一起量。量出来之前，修订 18 的子目录修复在真实宿主里有没有作用还不知道（I-1）。
