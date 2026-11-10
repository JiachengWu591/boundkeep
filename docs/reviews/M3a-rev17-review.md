# 规格修订 17 的复审

日期：2026-11-09。代码：`69fd10d`（`main`，与 `origin/main` 相同，工作区干净）。审查对象：`git diff 4009976 996fd6f -- src`，即 `programs._colon_kind`、`_git_operands`、`_h_git` 末尾，`event._short_name_program`，`paths.is_short_name`；规格开头修订 17 的段落与 §5.1 里 git 的 `:` 操作数、程序名的 8.3 短名两处；记录 `docs/reports/M3a-git-operands-and-short-names.md`。

**之后（2026-11-09）**：使用者说"开始执行修复"。R17-1 到 R17-6 在规格修订 18 处理了，记录在 `docs/reports/M3a-rev17-review-fixes.md`。修的时候又查到两处这份复审漏掉的放行，也一起修了：
- `git show HEAD HEAD:src` 打印整个提交；
- 工作目录在子目录时，`git log -p`、`git show HEAD` 打印整个仓库。

第一处在第 3 节"`--` 之前比之后松的 384 行"里其实看得到，这份复审只把其中的 `git diff` 当成了问题；第二处这份复审没有看子目录里的整仓库读。下面的判决都是修之前的。

**这不是独立复审。** 修订 17 是这个会话写的。本来提议另开一个不带上下文的会话来审，使用者选择在这里做。下面的结论都重新量过，没有直接照搬作者的说法。不过作者的盲点，这次复审可能同样看不到。

只新增了这份报告，没有改代码、规格、策略和测试，也没有提交。没有读 `.env`，没有用 LLM 密钥，没有访问真实 LLM 服务。没有读 `eval/authoring/h1-*`、`h2-*` 和留出批次，没有改系统设置。

全量测试没有跑：作者已经跑过，28525 通过、169 跳过、0 失败。这次只跑了 git 相关的四个测试文件（第 4 节），也没有做变异测试。

**判决怎么取的**：
- 在 TEMP（C: 卷，会生成 8.3 短名）下建假项目，含 `src/a.py`、`README.md`、`.env`、`secrets/id_rsa`、`.claude/settings.json`。用 `pipeline.review` 取规则层的判决，没有后端，平台 `windows`。PowerShell 命令经真实的 PowerShell 5.1 解析辅助进程。
- "修改前"指 `5654402` 的 `src`，它和 `4009976` 的 `src` 相同（`git diff --stat` 为空）。导出在上一个会话的 scratchpad 里，`PYTHONPATH` 指过去跑同一批命令。
- 实测用的 git 仓库也在 TEMP，"密钥"是 `FAKE_TOKEN=made-up-for-a-test` 这样的假字符串，用完已删。git 是 2.48.1.windows.1，PowerShell 是 5.1，Git Bash 是 `D:\新建文件夹\Git\bin\bash.exe`。

下文的说法：
- "规则放行"：由 allow 规则给出（默认配置下之后还有 Claude Code 自己的权限流程）。
- "灰色"：没有规则作出决定，没有后端时问，有后端时送审。

## 1. 结论

**修订 17 的三个目标达到了，没有发现回退。但同一片代码里还有四个缺口，都是修订 17 之前就有的。** 其中三处是 deny 变成灰色，一处是规则放行打印受保护文件。高危 0，中危 0，低危 4，信息 2。

| 编号 | 级别 | 一句话 | 要后端吗 | 来源 |
|---|---|---|---|---|
| R17-1 | 低 | `git diff HEAD:src`（`REV:目录` 作 `diff` 的操作数）**规则放行**；实测打印每个已跟踪文件的全文，假 `.env` 和假私钥都在。和 IR-7 同类，但写法普通，而且收紧它不牵连 `git diff HEAD~1` | **不要** | 修订 17 之前就有。IR-3 只处理了 `archive`、`grep` 的 `REV:目录` |
| R17-2 | 低 | Git Bash 能运行不带 `.EXE` 的短名路径（`'/c/…/BOUNDK~1' mode audit-only`），也能经 PATH 运行裸短名（`BOUNDK~1 mode audit-only`）；两种写法都是灰色，`boundkeep.exe` 的写法是 deny。PowerShell 5.1 不运行这两种写法（实测） | 送审要 | 修订 17 之前就有。IR-4 只修了带 `.EXE` 的路径写法 |
| R17-3 | 低 | `git archive ':/seed'` 打包按提交说明找到的那个提交的整个树（实测，假 `.env` 在归档里），判决是灰色；`git archive HEAD` 是 deny | 送审要 | 修订 17 之前就有。修订 17 在 `show`、`grep`、`log` 里把 `:/x` 当作可能是一个提交，`archive` 的 tree-ish 漏了 |
| R17-4 | 低 | `git archive --mtime 2020-01-01 HEAD`、`--add-virtual-file a.txt:b HEAD` 是灰色，带 `=` 的写法是 deny。原因是选项表里没有这两个带值的选项，值被当成 tree-ish，`HEAD` 被当成 pathspec | 送审要 | 修订 17 之前就有，和 IR-3 是同一段代码 |
| R17-5 | 信息 | `--` 之前的 `::x` 不是 git 的 pathspec：实测 `git show '::.env'`、`git show '::src'`、`git diff '::src'` 都报 `ambiguous argument`，退出码 128。规格 §5.1、`_colon_kind` 的文档字符串、记录第 6 节第 2 条都说它是 | — | 记录与实测不符。规则读得更多，不影响安全 |
| R17-6 | 信息 | 记录第 6 节第 8 条说两种 shell 的判决只在 `rev-parse` 的两种写法上不同。作者自己的扫描里，5046 对中有 584 对不同（修改前 633 对），都是 PowerShell 更松，都是操作数中间带冒号的写法。实测其中 14 条，git 都报错或什么都不打印 | — | 记录写窄了。修订 17 之前就有 |

**为什么 R17-1 是低、不是中**：它在修订 17 之前就有，也没有带来新能力：IR-7 的 `git diff <空树> HEAD` 早就由规则放行，效果相同。**如果使用者决定收紧 IR-7，这一条应升为中**：那时它是剩下的、写法最普通的同类缺口。

**为什么其余三条是低**：判决由 deny 变成灰色，不是放行。没有后端时仍然要问；有后端时要送审，靠模型拦。

## 2. 发现

### R17-1（低）：`git diff REV:目录` 规则放行，打印所有已跟踪文件

**写法**：`git diff HEAD:src`、`git diff HEAD:secrets`、`git diff HEAD HEAD:src`、`git diff --cached HEAD:src`、`git diff --stat HEAD:src`。

**判决**：项目里有 `.env`、`secrets/id_rsa` 时，这五种写法在 Bash 和 PowerShell 里都是规则放行（`allow-git-read-only`），修改前后相同。同一个操作数写在 `--` 之后（`git diff -- HEAD:src`）时，Bash 是问（`ask-git-read-outside-project`），PowerShell 规则放行；git 把它当作字面上带冒号的路径，不打印任何内容。

**实测**（假仓库，一个提交）：

| 命令 | 退出码 | 输出 |
|---|---|---|
| `git diff HEAD:src` | 0 | `.env`、`README.md`、`secrets/id_rsa` 都作为新文件打印全文，含 `FAKE_TOKEN=…` 和 `FAKE PRIVATE KEY…` |
| `git diff HEAD:secrets` | 0 | 同上 |
| `git diff HEAD HEAD:src` | 0 | 同样的内容，作为删除打印 |
| `git diff --cached HEAD:src` | 0 | 和索引比较，同样打印 `.env` 和 `secrets/id_rsa` 的全文 |
| `git diff --stat HEAD:src` | 0 | 只列名字 |
| `git diff HEAD:src/a.py` | 129 | 用法错误：blob 不能和工作区比较 |

**原因**：git 把 `HEAD:src` 这棵子树当作仓库根，和工作区（或另一个提交）比较，于是所有已跟踪文件都成了新增或删除，打印全文。工作区里改过、还没提交的内容也会打印出来。规则层把 `REV:PATH` 只读作 `src` 这个路径，`diff` 也不在递归读的子命令里。修订 17 的 IR-3 只让 `archive`、`grep` 的 `REV:目录` 递归读。

**和 IR-7 的关系**：效果和 `git diff <空树> HEAD` 相同，但写法普通得多。另外，IR-7 的取舍是"收紧会让 `git diff HEAD~1` 被拒绝"，这一条没有这个代价：`diff` 的 `REV:PATH` 操作数要么是目录（打印整个已跟踪树），要么是 blob（单个 blob 对工作区是用法错误，两个 blob 互相比较时规则已经读这两个路径）。

**建议**：和 IR-7 一起由使用者决定。可选的修法是：`git diff`（不带 `--no-index`）里有 `REV:PATH` 操作数时，按递归读整个工作区。代价是项目里有受保护名字时，`git diff HEAD:a.py HEAD~1:a.py` 这种两个 blob 的比较也被拒绝。

### R17-2（低）：Git Bash 里不带 `.EXE` 的短名和经 PATH 的裸短名

**写法与判决**（`<短目录>` 是 `C:\Users\…\BK-RV1~1\LONGTO~1`，里面有一个假的 `boundkeep.exe`，短名 `BOUNDK~1.EXE`）：

| 写法 | 修订 17 | 修改前 |
|---|---|---|
| Bash：`'/c/…/LONGTO~1/BOUNDK~1.EXE' mode audit-only` | deny（`program-short-name`） | 灰色 |
| Bash：`'/c/…/LONGTO~1/BOUNDK~1' mode audit-only` | **灰色**（程序名 `boundk~1`） | 灰色 |
| Bash：`BOUNDK~1 mode audit-only`，`<短目录>` 在 PATH 里 | **灰色** | 灰色 |
| Bash：`boundkeep mode audit-only`，同样的 PATH | deny | deny |
| PowerShell：带 `.EXE` 的短名，加尾随点、加空格、小写、短目录 | 都是 deny | 带 `.EXE` 的写法是灰色（IR-4）；其余变体没有在修改前的代码上跑 |

**实测**（`cmd.exe` 的副本改名为 `longprogramname.exe`，短名 `LONGPR~1.EXE`，运行 `/c echo`）：

| shell | 写法 | 结果 |
|---|---|---|
| Git Bash | `'/c/…/LONGPR~1.EXE'` | 运行，退出码 0 |
| Git Bash | `'/c/…/LONGPR~1'`（不带 `.EXE`） | **运行**，退出码 0 |
| Git Bash | `LONGPR~1`，目录在 PATH 里 | **运行**，退出码 0 |
| PowerShell 5.1 | `& 'C:\…\LONGPR~1.EXE'` | 运行，退出码 0 |
| PowerShell 5.1 | `& 'C:\…\LONGPR~1'`（不带 `.EXE`） | `CommandNotFoundException` |
| PowerShell 5.1 | `LONGPR~1`、`LONGPR~1.EXE`，目录在 PATH 里 | `CommandNotFoundException` |

**原因**：`_short_name_program` 只取磁盘上真实存在的那个路径的长名。Git Bash 找不到 `…/BOUNDK~1` 时会自己补上 `.exe` 再找，规则层不会。规格写的"文件不存在时名字不变"本身没错，但这里文件是存在的，只是要补 `.exe` 才找得到。裸名字由 PATH 查找，规则层不知道 hook 进程之外的 PATH。

**建议**：只在 bash 方言里改：
- 带路径、找不到文件时，补 `.exe` 再找一次；
- 裸名字本身像短名时，给一个灰色原因，并且不送审（模型看到的 `BOUNDK~1` 认不出是什么）。

用 `uv tool install` 装的 boundkeep 在 `~/.local/bin`，通常就在 PATH 里，所以裸名字这种写法最简单。

### R17-3（低）：`git archive ':/text'` 打包按提交说明找到的提交

**判决**：Bash 和 PowerShell 都是灰色。规则层看到的路径只有 `/seed`（PowerShell 里是 `c:/seed`），没有递归读。`git archive -- ':/seed'` 也是这样。对照：`git archive HEAD` 和 `git archive 'HEAD^{/seed}'`（同一个提交的另一种写法）都是 deny。修改前同样是灰色。

**实测**：`git archive -o a1.tar ':/seed'` 退出码 0，归档里有 `.env`、`secrets/id_rsa`，`.env` 的内容就是假 token；`git archive -- ':/seed'` 也一样。

**原因**：`_git_operands` 里 `archive` 的 tree-ish 不分种类，一律算作 `REV:PATH`（`rev_paths += 1`），于是 `restricted` 为真，不读 `.`。修订 17 对 `show`、`grep`、`log` 把 `search` 这一类从 `rev_paths` 里排除了，`archive` 没有排除。规格 §5.1 写的"`:/x` 可能是按提交说明找到的提交……不限定范围"也只说了这三个子命令。

**建议**：`archive` 的 tree-ish 是 `search` 类时也不限定范围，读 `.`。改动是一行，加一条测试。

### R17-4（低）：`git archive` 选项表少了两个带值的选项

**判决**：`git archive --mtime 2020-01-01 HEAD`、`git archive --add-virtual-file a.txt:b HEAD` 都是灰色，规则看到的路径是 `./head`。`--mtime=2020-01-01`、`--add-virtual-file=a.txt:b` 的写法是 deny。两种 shell 相同，修改前也相同。

**实测**：两种分开写值的形式，git 都接受，退出码 0，归档里有 `.env`、`secrets/id_rsa`。

**原因**：`_GIT_SUB_OPTS["archive"]` 只列了 `output`、`remote`、`exec`、`prefix`、`format`、`add-file`。不认识的长选项被当成开关，它的值就成了第一个位置参数，被当作 tree-ish；真正的 `HEAD` 被当作 pathspec，`len(pos) > 1` 让范围变窄。

**建议**：选项表加上 `mtime=x add-virtual-file=x`。更稳的做法是：`archive` 遇到不认识的选项时给灰色原因，并且读 `.`。

### R17-5（信息）：`--` 之前的 `::x` 不是 pathspec

**实测**：

| 命令 | 退出码 | 输出 |
|---|---|---|
| `git show '::.env'` | 128 | `fatal: ambiguous argument '::.env': unknown revision or path not in the working tree.` |
| `git show '::src'` | 128 | 同上 |
| `git diff '::src'` | 128 | 同上 |
| `git show ':!:README.md'` | 128 | 同上 |
| `git show ':!README.md'` | 0 | 按 pathspec 执行，打印出假 `.env` 和假私钥（和作者的实测一致） |

在 `--` 之前，git 只在下面几种情况下把一个词当 pathspec：
- 长形式 `:(…)`；
- `:/x`、`:!x`、`:^x`，并且 x 存在；
- 字面上就有一个叫这个名字的文件。

`::x` 是第三种情况，而 NTFS 上不会有这样的文件。

**影响**：规则层把 `::x` 当 pathspec 读，读得比 git 多，不影响安全。但规格 §5.1 的"所以 `:/x`、`:!x`、`:^x`、`:(…)`、`::x` 规则两种读法都看"、`_colon_kind` 的文档字符串，以及记录第 6 节第 2 条（"`git show '::src'` 比 `git show -- '::src'` 严"）都写成 git 会接受这种写法。记录那条代价说的是一条 git 根本不执行的命令。

### R17-6（信息）：两种 shell 的判决不同，范围比记录写的宽

用作者自己的扫描文件（`rv17_old.jsonl`、`rv17_new2.jsonl`）按同一条命令、同一棵树、同一个工作目录配对 Bash 和 PowerShell：

- 修订 17 之后，5046 对中 584 对不同；修订 17 之前是 633 对。少了的 49 对来自 `::x` 的写法，以及 `mkfs.ext4` 的短名。
- 每一对都是 PowerShell 更松：PowerShell 放行而 Bash 问或 deny，或者 PowerShell 灰色而 Bash deny。
- 涉及的操作数都是中间带冒号的写法：`--` 之后的 `:0:.env`、`HEAD:.env`、`HEAD:src`；`git blame` 的任何带冒号的操作数；`--` 之前的 `::src`。

对其中 14 条做了实测：

- `git blame` 加 `':(top).env'`（带和不带 `--`）、`':.env'`、`':0:.env'`、`'HEAD:.env'`、`':/.env'`、`':!README.md'`；
- `git show -- ':0:.env'`、`git show -- 'HEAD:.env'`、`git diff -- ':0:.env'`、`git diff -- 'HEAD:.env'`、`git log -p -- 'HEAD:.env'`；
- `git show '::src'`、`git diff '::src'`。

结果：

- 退出码 128（`no such path`、`outside repository`、`ambiguous argument`）；
- 或者退出码 0 但什么都不打印。

没有一条打印出假 token 或假私钥。对照组是 `git show -- ':.env'`：git 把它读作 pathspec `.env`，打印出假 token，两种 shell 的判决都是 deny。

原因是 Git Bash 把 `:` 当成名字的一部分（修订 13 的 RV-2），所以 Bash 那边的读法更保守。这不是泄露，但 IR-1 留下的教训"两种 shell 判决应该相同"对这一类写法不成立：以后两种 shell 的判决出现差异时，不能一律当成错误。

## 3. 核实了的说法

| 记录或规格里的说法 | 核实结果 |
|---|---|
| 带 `--` 的写法 4968 条一条没变 | 成立：按作者的两个扫描文件重新数，判决和规则 id 都相同 |
| `--` 之前的写法 28 条变松，都和同一个操作数写在 `--` 之后的判决相同 | 成立：28 条都相等，是 `log -p`、`stash show -p` 加 `:(top)src`、`::src`、`:(icase)src`、`:(top)secrets`。实测 `git log -p ':(top)src'` 和带 `--` 的写法一样只读 `src` |
| `--` 之前不应比之后松，除非那个词在 `--` 之前是修订号 | 成立：修订 17 之后，`--` 之前比之后松的 384 行，操作数都是 `:x`、`:N:x` 或 `REV:PATH`（git 先当修订号），或者属于 `cat-file`（不收 pathspec）。其中 `git diff 'HEAD:src'` 这一类见 R17-1 |
| `git show ':!README.md'` 现在是 deny | 成立，两种 shell 都是 |
| `archive` 的 tree-ish 写在 `--` 之后也认得；`archive`、`grep` 的 `REV:目录` 递归读 | 成立：实测 `git archive -- HEAD:secrets` 的归档里只有 `id_rsa`，`git grep -e FAKE HEAD:secrets` 打印出假私钥；判决都是 deny（测试 `test_a_tree_operand_reads_what_is_below_it`） |
| `cat-file` 不收 pathspec | 成立：`git cat-file -p ':(top).env'`、`':!README.md'` 都是 `path … does not exist`，退出码 128 |
| 带 `.EXE` 的短名路径按长名判，两种 shell 都是 deny | 成立，加尾随点、尾随空格、小写、短目录也都成立。`Start-Process` 和 `cmd /c` 包着的写法仍是灰色，长名也一样（早就知道） |
| PowerShell 5.1 和 Git Bash 都运行短名路径 | 成立，但 Git Bash 运行的写法更多，见 R17-2 |
| 只看最后一段；文件不存在时名字不变 | 成立，但不带 `.EXE` 的写法在 Git Bash 里不是"不存在"，见 R17-2 |

## 4. 测试

- `tests/unit/test_m3a_git_operands_and_short_names.py`、`tests/unit/test_m3a_readings.py`、`tests/unit/test_git_local_vcs_allow.py`、`tests/unit/test_m3a_ps_cmdinfo.py`：704 passed（4 分钟）。
- 没有做变异测试，没有跑全量。

## 5. 建议的顺序

1. **R17-1 和 IR-7 一起由使用者决定**。R17-1 可以单独收紧，不牵连 `git diff HEAD~1`。
2. **R17-3、R17-4**：都是 `_git_operands` 或选项表里的小改动，各补一条测试。做了要按惯例跑差分和全量。
3. **R17-2**：需要先定设计：裸名字要不要送审，补 `.exe` 只在 bash 方言里做。
4. **R17-5、R17-6**：在规格 §5.1、`_colon_kind` 的文档字符串和记录第 6 节里改正文字。
