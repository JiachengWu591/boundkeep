# git 的 `:` 操作数、`REV:目录` 与 8.3 短名（规格修订 17）

日期：2026-11-07。基线：`4009976`。依据：独立复审 `docs/reviews/M3a-rev13-16-independent-review.md` 的 IR-2、IR-3、IR-4。使用者说"按照你的建议去完成"。按复审第 7 节建议的顺序做：

- **IR-1**：已在上一轮修好（`docs/reports/M3a-ps-pathspec-magic.md`）。
- **IR-5、IR-6、IR-8**：改正规格和记录里的文字。
- **IR-2、IR-3、IR-4**：低危，这次一起修。
- **IR-7**：要使用者决定，这次只写进 `docs/threat-model.md`。

代码提交 `996fd6f`，这份记录与规格在其后一个提交；没有推送，没有打标签。

没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次和攻击样本。实测用的 git 仓库、"密钥"、程序都是假的，放在 scratchpad 和 TEMP 里，用完已删。真正运行过的只有 git 和一份改了名字的 `cmd.exe` 副本（用来证明短名路径会被运行）。

## 1. 结论

**IR-2、IR-3、IR-4 都修了，规格修订 17。**

- **IR-2**：`--` 之前以 `:` 开头的 git 操作数，规则同时按 `REV:PATH` 和 pathspec 两种读法看。
  - `git show ':!README.md'`、`git show ':(top)secrets'` 在项目里有受保护名字时，现在和 `git show` 一样是 deny。
  - `git checkout ':(top).claude/settings.json'` 现在被 `protect-guard-config` 拒绝。
- **IR-3**：`git archive` 的 tree-ish 是第一个操作数，写在 `--` 后面也是；`archive`、`grep` 里的 `REV:目录` 递归读。`git archive HEAD:secrets`、`git archive -- HEAD:secrets`、`git grep -e x HEAD:secrets` 现在是 deny。
- **IR-4**：Windows 上带路径的程序最后一段是 8.3 短名时，deny / ask 规则看磁盘上的长名。`& '…\BOUNDK~1.EXE' mode audit-only` 现在是 deny，灰色原因 `program-short-name`。

**文字更正**：IR-5 的例子、IR-6 的论证、IR-8 的补充，都已在原处标明"更正"或"补充"：

- `PROJECT_SPEC.md` 修订 16 那段、`CLAUDE.md`；
- `docs/reports/M3a-pathspec-and-dotted-names.md` 第 1、3、6 节；
- `docs/reviews/M3a-rev13-15-review.md` 开头和第 1 节。

**IR-7 没有改**，写进了 `docs/threat-model.md` 第 4 节。

**规则条目和策略文件没有改。** 修改前后的扫描（第 5 节）里，`--` 之前的写法共 4968 条：

- 28 条变松，每一条都和同一个操作数写在 `--` 之后的判决相同；
- 带 `--` 的写法（4968 条）一条都没变；
- 短名和长名的判决在 7 种程序名、3 种目录树、两种 shell 上全部相同。

## 2. 修改前后

真实目录树（假文件），没有后端，看的是规则判决。"有"指项目里有 `.env`、`secrets/id_rsa`、`.claude/settings.json`，"无"指一个受保护的名字都没有。两种 shell 结果相同。

| 写法 | 修改前（有 / 无） | 修改后（有 / 无） |
|---|---|---|
| `git show ':!README.md'`、`':(top)'` | 规则放行 / 规则放行 | **deny** / 规则放行 |
| `git show ':(top)secrets'` | 规则放行 / 规则放行 | **deny** / 规则放行 |
| `git show ':(top)src'`（`src` 里没有受保护的名字） | 规则放行 | 规则放行（不变） |
| `git show ':/fix'`（按提交说明找提交） | 问 / 问 | **deny** / 问 |
| `git grep FAKE ':(top)'`、`':!README.md'`、`git grep 'key:value'` | 灰色 / 灰色 | **deny** / 灰色 |
| `git checkout ':(top).claude/settings.json'`、`':/.claude/settings.json'` | 灰色 / 灰色 | **deny / deny**（`protect-guard-config`） |
| `git checkout ':/src'` 这类不带受保护名字的 | 灰色 | 问（`ask-git-discard-paths`，和 `git checkout -- src` 相同） |
| `git archive HEAD:secrets`、`-- HEAD:secrets`、`-o x.tar -- HEAD:secrets` | 灰色 | **deny**（`no-credential-store-read`） |
| `git archive -- HEAD` | 灰色 | **deny** / 灰色（整个工作区） |
| `git grep -e x HEAD:secrets` | 灰色 | **deny** / 灰色 |
| `git log -p ':(top).env'` | deny / **规则放行** | deny / **deny** |
| `git log -p ':(top)src'`（受保护的名字在 `src` 之外） | deny | **规则放行**：和 `git log -p -- ':(top)src'` 相同，git 只读 `src`（实测） |
| `git show :.env`、`git show HEAD:src/a.py`、`git show HEAD:secrets`、`git diff ':!x'`、`git log --oneline :/fix` | | 不变 |
| PowerShell `& '…\BOUNDK~1.EXE' mode audit-only`，Bash `'…/BOUNDK~1.EXE' mode audit-only` | 灰色（`program-path-qualified`，名字 `boundk~1`） | **deny**（`deny-boundkeep-state-commands`），灰色 `program-short-name` |
| 同一个目录里不存在的 `NOSUCH~1.EXE` | 灰色 | 灰色（不变） |

## 3. 实测

**git**（2.48.1.windows.1）。scratchpad 里的假仓库有两个提交：`seed` 加入所有文件，`fix src` 只改 `src/a.py`。工作区里改过 `.claude/settings.json`。

| 命令 | 结果 |
|---|---|
| `git show ':!README.md'`、`':(top)src'` | 打印 HEAD 提交在这个 pathspec 范围内的改动，git 把它当 pathspec，没有报错 |
| `git show ':/fix'` | 打印提交说明匹配 "fix" 的那个提交 |
| `git show ':/seed'` | 打印 `seed` 提交的全部改动，**包括假 `.env` 和假私钥** |
| `git show HEAD:secrets` | 只有 `tree HEAD:secrets` 和名字 `id_rsa`，没有内容 |
| `git log -p ':(top)src'` | 只有 `src` 的改动，没有 `.env`、私钥 |
| `git log -p ':(top).env'` | 打印假 `.env` |
| `git grep -e marker ':(top)'` | 打印假 `.env` 的那一行 |
| `git grep 'TOKEN=dummy'`（只有模式） | 打印假 `.env` 的那一行 |
| `git grep -e MARKER HEAD:secrets` | `HEAD:secrets:id_rsa:DUMMY-KEY-MARKER` |
| `git archive --format=tar HEAD:secrets`、`-- HEAD:secrets` | 归档里有 `id_rsa` 和假私钥 |
| `git archive --format=tar -- HEAD` | 整个树，假 `.env` 和假私钥都在 |
| `git archive HEAD '::.git/config'` | 退出码 128，"pathspec '::.git/config' did not match any files"（IR-5） |
| `git checkout ':(top).claude/settings.json'`；从 `sub` 运行 `git checkout ':/.claude/settings.json'` | "Updated 1 path from the index"，文件被还原 |

**8.3 短名**：把 `cmd.exe` 复制成 scratchpad 里的 `fakeboundkeepprogram.exe`，短名是 `FAKEBO~1.EXE`。

- PowerShell 5.1 里 `& '<短名路径>' /c "echo ran>标记文件"` 写出了标记文件。
- Git Bash 里按短名路径运行，输出了 `bash-ran-short`；对照的长名路径输出 `bash-ran-long`。

所以两种 shell 都会运行短名路径，这次的修法两种都处理。

## 4. 修法

- **`src/boundkeep/normalize/programs.py`**：
  - **`_colon_kind`（新）**：把 `:` 开头的词分成三类：
    - `index`：`:x`、`:N:x`，索引里的文件，是修订号；
    - `search`：`:/text`，按提交说明找到的提交，或者从顶层算的 pathspec；
    - `pathspec`：`:!x`、`:^x`、`:(…)`、`::x`。
  - **`_git_operands`**：
    - `archive` 的 `REV:PATH` 看 `pos[0]`，不看 `before[:1]`。
    - 只有 `index` 类和不以 `:` 开头的 `REV:PATH` 算"指定了一个对象"。
    - `show` 有这样的操作数时照旧不递归。`archive`、`grep` 也递归，`archive` 以 tree-ish 的目录为范围。
    - 非 `archive` 的命令里，`pathspec` 类的操作数限定范围，`search` 类和 `index` 类不限定；`grep` 的 `REV:PATH` 也不限定，因为它的第一个操作数可能是模式。
  - **`_h_git` 的末尾**：
    - `--` 之前的 `pathspec` 类和 `search` 类的词，除 `cat-file`、`archive` 外，都按 `_pathspec` 读一次，和 `--` 之后的词一样：按当前目录读，有 `-C` 时也按那个目录读。
    - `index` 类（`:x`、`:N:x`）不这样读。git 只在有一个字面上叫 `:x` 的文件时才把它当 pathspec，NTFS 不允许这样的名字。第一版也读了它们，差分里 `git show :0:a.py` 由放行变成问（`0:a.py` 被当成带冒号的路径），于是收窄了，规格也一起改了。
    - `archive` 的 tree-ish 不再在末尾被当成 pathspec 读。
- **`src/boundkeep/normalize/event.py`**：`_short_name_program`（新），在 `_command_action` 里紧接 `_canonical_program` 之后调用。
  - 只在 Windows 上、程序带路径、最后一段像 8.3 短名时，用磁盘层的读法（`_refs`，和路径的磁盘查找共用预算）取解析出来的长名。
  - 路径层会同时列出原样的形式（带 `short-name-unresolved`）和解析出来的形式，只取后者。几个可能的工作目录给出的名字必须相同。
  - 名字变了的，加灰色 `program-short-name`。
- **`src/boundkeep/normalize/paths.py`**：公开 `is_short_name`。
- **`tests/unit/test_m3a_git_operands_and_short_names.py`**（新，76 条）：
  - `:` 词的分类；
  - 五组 IR-2：打印内容的命令扫描整个工作区、没有受保护名字时仍放行、`--` 之前的 pathspec 和 `--` 之后一样限定范围、受保护名字被拒绝、假机器上的 `checkout`；
  - 没有变的写法；
  - 两组 IR-3；
  - 两组 IR-4：在 TEMP 所在的 C: 卷上用 `GetShortPathNameW` 取真实短名，卷不生成短名时跳过。
  - 都是 Bash 和 PowerShell 两种 shell。
- **`tests/unit/test_m3a_readings.py`**：修订 13 钉住的 `git -C sub checkout ':/x'` 多了一个按当前目录读的 key `c:/proj/x`，和带 `--` 的写法（新加的一行）相同。
- **规格**：修订 17，§5.1 的 pathspec 一段和程序名一段。`docs/policy-reference.md` 加了 `program-short-name` 和 `--` 之前的魔法；`docs/threat-model.md` 第 4 节加了短名和 IR-7。`policies/` 没有改。

## 5. 度量

**真实目录树扫描**（新做的）。只看规则判决，没有后端。旧代码是 `5654402`（`src` 与 `4009976` 相同）。共 10092 条，组合方式：

- 3 种目录树：受保护的名字都有、只有项目根的 `.env`、一个都没有；
- 两种 shell，工作目录在项目根或 `sub`；
- 18 种子命令 × 23 种写法，写法包括 `:` 开头的各类和 `HEAD:secrets` 这样的 `REV:PATH`。每条另算一遍同一个操作数写在 `--` 之后的版本作对照；
- 6 条 `archive` 的 `--` 写法；
- 7 种程序名的短名和长名路径。

| 部分 | 结果 |
|---|---|
| `--` 之前的写法，4968 条 | 3990 相同，124 同级，826 收紧，**28 变松** |
| 同一个操作数写在 `--` 之后，4968 条 | **全部相同** |
| `archive` 的 `--` 写法，72 条 | 64 相同，8 收紧（`-- HEAD:secrets`、`-- HEAD`） |
| 程序名，84 条 | 60 相同，15 同级（多了 `program-short-name`），9 收紧（`boundkeep`、`mkfs.ext4` 的短名）。`diskpart`、`git`、`cat` 这些不超过 8.3 的名字没有另外的短名，是对照。修改后短名和长名的判决**全部相同** |

**变松的 28 条**：都是 `git log -p` 或 `git stash show -p` 加 `':(top)src'`、`'::src'`、`':(top)secrets'`、`':(icase)src'`，而受保护的名字在这个 pathspec 之外。修改前它们扫描整个工作区（deny），修改后只扫描 pathspec 指的目录，变成规则放行或灰色。**28 条都和同一个操作数写在 `--` 之后的判决相同**（`git log -p -- ':(top)src'` 修订 16 起就这样）；实测 git 也只读那个目录。

**收紧的 826 条**：

| 从 → 到 | 条数 | 主要是 |
|---|---|---|
| 规则放行 → deny | 218 | `--` 之前的 `.env` 现在看得见（`git log ':(top).env'`、`git rev-parse '::.env'`，和带 `--` 的写法相同）；`git show` 加排除或空 pathspec 扫描整个工作区 |
| 规则放行 → 灰色 | 200 | `--` 之前的 `:(icase)src`、没闭合的 `:(top`，和 `--` 之后一样是 `git-pathspec-magic` |
| 问 → deny | 28 | `git show ':/'`、`':/src'`、`':/fix'`（可能是按提交说明找到的提交，整个工作区）、`'::src'`（见第 6 节第 2 条） |
| 灰色 → 问 | 192 | `git checkout` 加 `:` 开头的词，现在看得到路径，由 `ask-git-discard-paths` 问 |
| 灰色 → deny | 188 | `git grep`、`git ls-files`、`git stash show -p` 加 `:` 开头的词或 `REV:PATH`，扫描整个工作区或看到受保护名字 |

**修改后，同一个操作数在 `--` 之前和之后的比较**：4070 相同；414 条 `--` 之前更严；484 条 `--` 之前更松。

- **更严**：`:/x`（可能是提交）、`:x` 和 `:N:x`（`show` 等还按索引路径读）、`::x`（第 6 节第 2 条），这是设计如此。
- **更松**，设计如此：
  - `HEAD:secrets` 这样的 `REV:PATH` 写在 `--` 之后，被读成带冒号的路径，这本身不是有效写法；
  - `:.env`、`:0:.env`、`:src` 这样的索引写法：写在 `--` 之前是修订号，`log`、`rev-parse` 读不到它的内容；写在 `--` 之后才是 pathspec；
  - 6 条 `git cat-file -p '::.env'`（PowerShell）：`cat-file` 不收 pathspec，修改前后都是灰色。

**其他：**

| 项目 | 结果 |
|---|---|
| 含 git 或 `~` 的语料条目（655 条，两个平台共 1164 次判决，按 `test_pipeline_corpus.py` 的方式跑） | 0 条与钉住的结果不同 |
| 新测试 | 77 passed（收窄后在"没有变的写法"里加了 `git show :0:src/a.py`、`git rev-parse :0:src/a.py`；变异之后加了一条分类器层的测试，见下一行） |
| 相关的 18 个测试文件（收窄之前） | 8013 passed，12 skipped；收窄之后，四个 git 相关的文件 761 passed |
| 修订 16 的专门扫描（12768 条）、IR-1 的目录树扫描（10320 条） | 全部相同；IR-1 扫描里 Bash 和 PowerShell 的 5160 对仍然全部相同 |
| 带冒号的普通命令（492 条） | 收窄前 3 条收紧（Bash 的 `git show :0:a.py` 由放行变成问），收窄后全部相同 |
| 系统目录（49720 条）、逐程序（12668 条） | 全部相同（收窄之前跑的；收窄只少读了 `--` 之前的 `:x`，这两组没有这种写法） |
| 真实磁盘（23544 条）、假机器（179508 条）、孪生项目（30720 条） | 级别全部相同（同上，收窄之前跑的） |
| 变异：19 个，在副本上跑新测试文件和 `test_m3a_readings.py`。包括：不读 `--` 之前的 pathspec、索引写法也读、`:/x` 不读、所有 `:` 词都算修订号、`:/x` 算修订号、`:/x` 限定范围、pathspec 不限定范围、`grep` / `archive` 的 `REV:目录` 不递归、`archive` 的 tree-ish 只看 `--` 之前、`archive` 的旧范围、`--` 之后的 tree-ish 也当 pathspec 读、`cat-file` 也读、两个分类错误，以及短名的四种 | **全部抓到**。第一轮 17 个；`cat-file` 也读、`--` 之后的 tree-ish 也当 pathspec 读这两个只是多列一个路径、不改判决，第一轮存活，加了一条分类器层的测试（`test_operands_that_are_no_pathspecs_are_not_read_as_paths`）之后抓到 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过；77 个源文件没有问题 |
| `boundkeep test` default / strict | 1142 / 0 失败，334 / 0 失败 |
| 评测（`--config rules+taint --test-contaminated`，输出到 scratchpad，没有打开留出批次） | `results/*.json` 去掉时间戳之后相同；`report.md` 只有日期一行和 4 行延迟不同 |
| 全量（分六段跑，不是一个进程） | 28525 通过、169 跳过、0 失败（2:09:59，六段都一次跑完，合计与收集到的 28694 条相同；测试文件清单 122 个，与 `tests/` 相同；跑的期间 `src`、`tests`、`policies`、`eval`、`scripts` 和两份测试会读的文档都没有改动） |

## 6. 代价和残余

1. **`git show ':/fix'` 这类写法在有受保护名字的项目里由问变成 deny**：`:/text` 可能是按提交说明找到的提交，git 会打印那个提交的全部改动（实测 `:/seed` 打出了假 `.env` 和私钥），所以按整个工作区看。
2. **`git show '::src'` 比 `git show -- '::src'` 严**：它还按索引路径 `:src` 读，在 Windows 上这个词读成项目目录的流名，于是整个项目被扫描。这种写法不常见，方向是收紧。
3. **`git rev-parse '::.env'`、`':(top).env'` 现在是 deny**：`rev-parse` 只打印对象名，不打印内容，但带 `--` 的写法本来就是 deny，这次只是一致了。索引写法 `git rev-parse ':.env'` 仍然放行（它是修订号）。
4. **`--` 之前的 `:(icase)`、`:(glob)`、`:(attr:…)`、没闭合的括号现在要问**，和 `--` 之后相同（修订 16）。
5. **`git grep -e x HEAD:src` 在项目里任何地方有受保护名字时是 deny**：`grep` 的 `REV:PATH` 不限定扫描范围，因为它的第一个操作数可能是模式。`git grep` 没有 allow 规则，原来就是问，现在是 deny。
6. **变松的 28 条**（第 5 节）和带 `--` 的写法一致。`top` 仍按当前目录读（修订 16 第 6 节第 3 条）。
7. **短名只看最后一段**：目录里的短名不展开（`C:\PROGRA~1\Git\cmd\git.exe status` 仍是灰色 `program-path-qualified`，不被当成系统目录里的程序）。文件不存在时名字不变。只在 C: 卷上量过，E: 卷不生成短名。
8. **扫描里看到、但不是这次引入的**：PowerShell 和 Bash 对 `git rev-parse -- ':0:.env'`、`git rev-parse -- 'HEAD:.env'` 的判决不同（PowerShell 放行，Bash deny），修改前就这样。`rev-parse` 不打印内容。
9. **没有处理的**：IR-7（要使用者决定）；复审"没有查的"那一节里顺带看到的 `*` 跨目录匹配（`git show HEAD -- '*id_rsa'` 是问）和 PowerShell 里经 `env.exe` 运行 `boundkeep`。

## 7. 没有做的

- 这次修复没有复审。
- 真实 Claude Code 的 hook 链路里没有跑。冒烟的 `readings` 一段没有加这次的写法。
- pwsh 7、别的 git 版本没有量；只量了 NTFS 的 C: 卷。
