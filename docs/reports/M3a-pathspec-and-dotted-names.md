# git 的 pathspec 魔法与带尾随点的程序名（规格修订 16）

日期：2026-11-06。基线：`77f1bdb`。代码提交：`c69684c`（已推送，未打标签）。依据：复审 `docs/reviews/M3a-rev13-15-review.md` 的 RS-1、RS-2。使用者说"修 RS-1、RS-2"。没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次和攻击样本；判决都用假后端（总是放行）。实测用的 git 仓库、"密钥"、标记文件都是假的，放在 scratchpad 里，用完已删；真正运行过的程序只有 `cmd.exe`（写标记文件）、`hostname.exe` 和 scratchpad 里的 git 仓库。

## 1. 结论

**两条都修了，另外修了同一类的一处：`git archive` 的操作数。**

- **RS-1**：git 按 pathspec 读的操作数，魔法按 git 的语法拆开。`git diff -- ':(top).env'`、`git stash push -- ':(top).claude/settings.json'` 现在和不带魔法的写法一样是 deny。
- **同类的一处**：`git archive TREE-ISH PATH...` 里，tree-ish 之后的操作数原来先被当成 `REV:PATH`（`:x` 是索引里的路径），`git archive HEAD '::.git/config'` 只是灰色。实测 git 把那个文件打进了归档。现在只有第一个操作数按 `REV:PATH` 读，其余的按 pathspec 读。
- **RS-2**：Windows 上取程序名之前先去掉结尾的点和空格。`& 'C:\tools\boundkeep.exe.' mode audit-only` 现在是 deny。启动器（`python -m`、`uv run` 等）的名字也一样处理：`& 'C:\Python312\python.exe.' -m boundkeep mode audit-only` 原来漏在这一层，修的时候才发现。

规则条目和策略文件没有改，评测除日期和延迟外与记录相同。原有的六组差分级别全部相同。新做的专门扫描里，程序名部分 0 条变松；pathspec 部分有变松的，都是按 git 的真实读法该放的，逐类列在第 5 节。全量分六段跑：28403 通过、169 跳过、0 失败。

## 2. 修改前后

假机器，项目 `C:\proj`。"规则放行"是无决定、由 allow 规则给出。有后端时假后端总是放行，所以"送审"的结果都是无决定。

| 写法 | 修改前，无后端 / 有后端 | 修改后，无后端 / 有后端 |
|---|---|---|
| `git stash push -- ':(top).claude/settings.json'`，`cd sub && …`，`':(top,icase).CLAUDE/SETTINGS.JSON'` | 规则放行 / 规则放行 | **deny / deny**（`protect-guard-config`） |
| `git diff -- ':(top).env'`，`git log -p -- …`，`git show HEAD -- …`，`git add ':(top).env'` | 规则放行 / 规则放行 | **deny / deny**（`no-secret-read`） |
| `git restore -- ':(top).claude/settings.json'`，`git checkout -- …` | 问 / 问 | **deny / deny** |
| `git grep --no-index -e TOKEN -- ':(top).env.local'` | 问 / 送审 | **deny / deny** |
| `git archive HEAD '::.git/config'`，`':(top).git/config'`，`':/:.ssh/config'` | 问 / 送审 | **deny / deny** |
| `git diff -- '::.env'`，`git add '::.claude/settings.json'`（带结束冒号的短形式） | 规则放行 / 规则放行 | **deny / deny** |
| PowerShell `& 'C:\tools\boundkeep.exe.' mode audit-only`，`.exe `、`.exe..`、`taint clear` | 问 / 送审 | **deny / deny**（`deny-boundkeep-state-commands`） |
| PowerShell `& 'C:\Python312\python.exe.' -m boundkeep mode audit-only`，`& 'C:\tools\uv.exe.' run boundkeep …` | 问 / 送审 | **deny / deny** |
| PowerShell `& 'C:\Windows\System32\diskpart.exe.'` | 问 / 送审 | **deny / deny**（`deny-disk-tools`） |
| PowerShell `& 'C:\Windows\System32\git.exe.' status` | 问 / 送审 | **不变**：灰色，不被规则放行，照常送审（模型看到的 `git` 就是 PowerShell 运行的） |
| `git diff -- ':!secrets/id_rsa'`，`git add ':!/.env'`，`git commit -m x -- ':!x'` | deny / deny | **规则放行 / 规则放行**：排除，git 作用于除它以外的整个仓库（第 6 节第 1 条） |
| `git log -- ':(icase)src'`，`git diff -- ':(glob)**/a.py'`，`':(attr:x)y'` | 有些规则放行 | **问 / 送审**（`git-pathspec-magic`，第 6 节第 2 条） |
| `git diff -- ':(topsecrets/id_rsa'`（括号没有闭合） | deny / deny | **问 / 送审**：git 报错退出，什么都不读（实测） |
| `git log --oneline -- ':(top)src'`，`git diff -- ':!x'`，`git add :/`，`git stash push -- ':!x'` | 规则放行 / 规则放行 | **不变** |
| Bash `ls.`，`cat. a.txt`，`'cat ' a.txt` | 问 / 送审 | **不变**：灰色（`program-name-trailing-dots`）；Git Bash 不运行这些名字（实测） |
| Bash `. ./env.sh`，`./run.sh` | 不变 | **不变**：`.` 和 `..` 不算带尾随点的名字 |

## 3. 实测

**git**（2.48.1.windows.1，scratchpad 里的假仓库，从子目录 `sub` 运行）：

| 命令 | 结果 |
|---|---|
| `git stash push -- ':(top).claude/settings.json'`，`':/.claude/settings.json'`，`':(top,icase).CLAUDE/SETTINGS.JSON'` | 顶层的 `.claude/settings.json` 被还原 |
| `git restore -- ':(top).claude/settings.json'` | 同上 |
| `git stash push -- ':!src/a.txt'`，`':(exclude)src/a.txt'`，`':(top)'` | 整个仓库都被还原（只有排除时 git 作用于整个仓库） |
| `git diff`、`git log -p`、`git show HEAD`、`git grep -e TOKEN` 加 `-- ':(top).env'` | 打印出已跟踪的假密钥 |
| `git grep --no-index` 和 `git grep --untracked --no-exclude-standard` 加 `-- ':(top).env.local'` | 打印出**未跟踪、被忽略**的假密钥 |
| `git diff -- '::secrets/id_rsa'`，`':/:secrets/id_rsa'` | 打印出假密钥（结束冒号是魔法的一部分） |
| `git archive HEAD '::secrets/id_rsa'`，`':(top)secrets/id_rsa'` | 归档里有那个文件 |
| `git diff -- ':(topsecrets/id_rsa'`，`':(top'` | 退出码 128："Invalid pathspec magic" / "Missing ')'" |

**程序名**（Windows PowerShell 5.1，`cmd.exe` 写标记文件证明它运行了；cmd 一行的结果作废，因为重定向由外层 cmd 做了）：

| 写法 | 运行了吗 |
|---|---|
| `& 'C:\Windows\System32\cmd.exe.'`，`cmd.exe..`，`'…\cmd.exe '`，`'…\System32.\cmd.exe'`，`Start-Process -FilePath '…\cmd.exe.'` | 运行了 |
| `& 'C:\Windows\System32\cmd.'`，`cmd.exe::$DATA`，裸名字 `cmd.exe.`、`hostname.`、`hostname.exe.` | 找不到 |
| Git Bash：`cmd.exe.`，`/c/Windows/System32/cmd.exe.`，`C:/…/cmd.exe.`，`/c/…/cmd.`，`/c/Windows/System32./cmd.exe` | 找不到（对照 `/c/Windows/System32/cmd.exe` 运行了） |

## 4. 修法

- **`src/boundkeep/normalize/programs.py`**：
  - `_pathspec` 按 git 的语法拆魔法：短形式是 `:` 后跟 `/`、`!`、`^` 中的若干个，可选再跟一个 `:`；长形式是 `:(…)`，括号里是逗号分开的词。之后的部分按当前目录读，有排除时读作 `.`。长形式里有 `top`、`exclude`、`literal` 以外的词，或括号没有闭合，加灰色原因 `git-pathspec-magic`，路径照样给规则看。
  - `_git_operands`：`git archive` 只有第一个操作数按 `REV:PATH` 读。
  - `peel_runner`：启动器的名字先去掉结尾的点和空格。不分平台：多认出一个启动器只会让里面的命令被判，带启动器的调用本来就不放行。
- **`src/boundkeep/normalize/event.py`**：`_canonical_program` 在 Windows 上先去掉名字结尾的点和空格，再去掉 `.exe`；名字因此变了，加灰色原因 `program-name-trailing-dots`。`.` 和 `..` 不动。
- **`tests/unit/test_m3a_pathspec_and_dotted_names.py`**（新，84 条）。
- **`tests/unit/test_m3a_readings.py`**：修订 13 钉住的两个读法改了：`':(top)src'` 原来读成 `c:/proj`，现在是 `c:/proj/src`；`':!a/b'` 原来读成 `c:/proj/b`，现在是 `c:/proj`。`git add ':^x/.env'` 从"被保护的名字照样看得见"那组移走了，它是排除，挪到新文件里在真实目录上测：项目里有受保护的名字时，它由 `git-add-may-stage-protected` 问。
- **规格**：修订 16，§5.1。`docs/policy-reference.md` 加了两个灰色原因，`docs/threat-model.md` 第 4 节加了带尾随点的写法。`policies/` 没有改。

## 5. 度量

代码最后一次改动在 01:12:09（`event.py`），下面的差分、变异和全量都在这之后跑。

**专门扫描**（新做的）。pathspec 部分：16 种子命令 × 17 种魔法 × 10 个目标 × 当前目录在根或子目录 × 有无后端，共 10880 条，另有不带魔法的对照 288 条。程序名部分：10 个名字 × 8 种后缀 × 5 种目录 × 两种 shell × 有无后端，共 1600 条。旧代码是 `77f1bdb`。

| 部分 | 结果 |
|---|---|
| 程序名，1600 条 | 1020 相同，550 收紧，30 同级，**变松 0**。带尾随点的写法被规则放行的 0 条；不带点是 deny、带点不是 deny 的 0 条 |
| 不带魔法的对照，288 条 | 全部相同 |
| pathspec，10880 条 | 6748 相同，2884 收紧，302 同级，**946 变松**，分类如下 |

变松的 946 条：

| 类 | 条数 | 例子 | 为什么该放 |
|---|---|---|---|
| 排除 | 666 | `git diff -- ':!secrets/id_rsa'` 由 deny 变成规则放行；`git archive HEAD ':!.env'` 由 deny 变成问 | git 作用于除它以外的整个仓库（实测），和 `git diff -- .`、`git archive HEAD` 判得一样。原来把被排除的路径当成了目标 |
| 带结束冒号的短形式 | 210 | `git diff -- ':/:src'` 由问变成规则放行 | 原来读成带冒号的怪路径，算项目外；现在和 `git diff -- ./src` 一样 |
| 括号没有闭合 | 58 | `git diff -- ':(topsecrets/id_rsa'` 由 deny 变成问 | git 报错退出（实测），什么都不读 |
| `attr` 魔法，有后端时 | 12 | `git archive HEAD ':(attr:a)'` 由发送出口拒发变成送审 | 级别从问变成送审，没有变成规则放行 |

修改之后，"带魔法时不是 deny、不带魔法时是 deny"的写法只剩括号没有闭合的那一类（252 条）。

**其他差分**（对修订 15 的输出，这几组的语法里没有这两类写法，看的是有没有牵连）：

| 项目 | 结果 |
|---|---|
| 系统目录扫描（49720 条） | 全部相同 |
| 逐程序扫描（12668 条） | 全部相同 |
| 真实磁盘差分（真联接点，23544 条） | 级别全部相同 |
| 假机器差分（179508 条） | 级别全部相同 |
| 孪生字母项目（30720 条） | 级别全部相同 |
| 带冒号的普通命令（492 条） | 全部相同 |

**其他：**

| 项目 | 结果 |
|---|---|
| 新测试和改过的测试 | 新文件 84 条；和 `test_m3a_readings.py`、`test_git_local_vcs_allow.py`、`test_norm_programs.py`、`test_info_commands_allow.py` 一起 1601 passed；另外 14 个相关文件 9579 passed（`git archive` 那处修改之前跑的） |
| 变异：16 个（去掉点、只去点不去空格、不加灰色原因、`.` 也算、所有主机都去、启动器不去、旧正则、长形式排除不认、短形式排除不认、不认结束冒号、不认的词不灰、`literal` 也灰、括号没闭合不灰、排除时保留路径、`archive` 全部按 `REV:PATH`、魔法的词不分大小写），副本上跑 2 个测试文件 | **全部抓到**，第一轮就抓到 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过；77 个源文件没有问题 |
| `boundkeep test` default / strict | 1142 / 0 失败，334 / 0 失败 |
| 评测（`--config rules+taint --test-contaminated`，输出到 scratchpad，没有打开留出批次） | `results/*.json` 去掉日期、延迟、sha 之后相同；`report.md` 只有日期一行和 4 行延迟不同。策略 sha256 没变，仓库里的评测文件没有重新生成 |
| 全量（分六段跑，不是一个进程，当前代码） | **28403 通过、169 跳过、0 失败**（01:29:06 到 04:51:36，3:22:30；六段都一次跑完，合计与收集到的 28572 条相同，测试文件清单 120 个与 `tests/` 相同；开始之后 `src`、`tests`、`policies`、`eval`、`scripts` 和测试要读的两份文档都没有改过）。比前几次慢：机器没有睡眠，测试进程一直满载，第 5 段用了 2:02:19 |

## 6. 代价和残余

1. **排除读作 `.`**：`git diff -- ':!secrets/id_rsa'`、`git add ':!/.env'`、`git stash push -- ':!x/.env'` 由 deny 变成规则放行。这是 git 的真实读法：被排除的路径恰好不碰，其余的都碰，和不带路径的 `git diff`、`git add -A`、`git stash` 一样。`git add` 在真实磁盘上另有 `git-add-may-stage-protected`：项目里有受保护的名字时问。
2. **`icase`、`glob`、`attr` 魔法要问**：原来有一些被规则放行（`git diff -- ':(icase)'`）。没有后端时要问一次。
3. **`top` 和 `/` 按当前目录读，不按仓库顶层**：在子目录里运行时 key 是子目录下的同名路径。名字规则（`.env`、`.claude/settings.json`）照样命中，按位置写的规则可能看不到。git 顶层在项目之上时另有 `git-root-above-project` 的检查，这次没有重新量。
4. **只有排除时 git 作用于整个仓库，这里读作当前目录**：在子目录里会窄一些。效果和不带路径的同一条命令相同，而那些本来就放行。
5. **括号没有闭合由 deny 变成问**：git 报错退出，没有实际影响，但判决级别降了。
6. **程序名去掉点之后多出来的 deny**：Bash 里的 `diskpart.`、`boundkeep. mode` 现在是 deny。Git Bash 不运行这些名字，PowerShell 只有带路径时才运行，所以碰不到能正常运行的命令。
7. **uv 生成的启动器（`boundkeep.exe`、`python.exe` 的跳板）带尾随点时是否照常运行，没有量**，只量了 `cmd.exe`。启动器靠自己的文件名找脚本时，可能不运行；那样多出来的 deny 也不伤人。
8. **没有修的**：复审的 RV-4、RV-6，RV-5 的正文更正；上一轮的 GR-3、GR-4、GR-5。

## 7. 没有做的

- 这次修复没有复审。
- 真实 Claude Code 的 hook 链路里没有跑。修订 10 到 16 都没有。
- pwsh 7、别的 git 版本没有量；只量了 NTFS。
- 真实模型没有接过。
