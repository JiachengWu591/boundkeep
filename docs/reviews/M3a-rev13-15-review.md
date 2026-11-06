# 规格修订 13 到 15 的复审

日期：2026-11-06。代码：`1a6078b`（与 `origin/main` 相同）。审查对象：`git diff d1729dd 8ddc6e2 -- src`（修订 13 的 `372bfa1`、修订 14 的 `fef9fe9`、修订 15 的 `8ddc6e2`），记录 `docs/reports/M3a-readings-fixes.md`、`M3a-program-fold.md`、`M3a-system-dirs.md`。

**这不是独立复审。** 三次修复都是这个会话写的，复审也是。我尽量靠实测下结论，但可能和写修复时有同样的盲点。要独立的眼光，得另开一个不带这段对话的会话。

这次复审只新增了这份报告，没有改代码、规格和策略。没有读 `.env`，没有 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次和攻击样本。判决都用假后端（总是放行）。实测用的 git 仓库、"密钥"和标记文件都是假的，放在 scratchpad 里，用完已删。全量没有跑。

## 1. 结论

**三次修订的目标都达到了，没有找到高危、中危，也没有找到它们带来的回退。** 找到两条低危，都在这三次修订改过的代码旁边，在修订 13 之前就有（`d1729dd` 上判决相同），三次修订都没有发现。

| 编号 | 级别 | 一句话 | 要后端吗 | 来源 |
|---|---|---|---|---|
| RS-1 | 低 | git 的长形式 pathspec 魔法丢了路径：`git diff -- ':(top).env'` 由规则放行，`git diff -- .env` 是 deny；`git stash push -- ':(top).claude/settings.json'` 由规则放行，不带魔法的写法是 deny | **不要** | 早就有。修订 13 改过这段（`programs._pathspec`），只处理了短形式 |
| RS-2 | 低 | PowerShell 里 `& 'C:\tools\boundkeep.exe.' mode audit-only` 由 deny 变成问，配了后端时送审；PowerShell 5.1 真的运行这个程序 | 问不要，送审要 | 早就有。和修订 14 同一类（程序名的读法），修订 14 没有覆盖 |

**为什么都是低。** RS-1 的这几条命令能做到的，不带路径的写法本来就由规则放行：`git log -p`、`git diff`、`git show HEAD` 显示所有已跟踪文件的内容，`git stash` 还原所有已跟踪文件的改动。已跟踪的 `.env` 被 `git diff` 显示，是 `docs/reports/M2-rules-1.md` 记下的 `allow-git-read-only` 原有缺口。RS-2 的效果和 `docs/threat-model.md` 第 4 节已经记下的间接写法相同（`Start-Process boundkeep -ArgumentList …`、`cmd /c` 都是灰色）。两条都没有带来新能力，问题在于规则自以为看得见这个目标，实际看不见。

## 2. 发现

### RS-1（低）：长形式的 pathspec 魔法丢了路径

`programs._pathspec` 用 `re.sub(r"^:[^/\\]*", ".", text)` 把魔法换成 `.`：

| 写法 | 换成 | git 实际作用于（实测） |
|---|---|---|
| `:/src`（短形式） | `./src` | `<顶层>/src` |
| `:(top).claude/settings.json` | **`./settings.json`**，丢了 `.claude` | `<顶层>/.claude/settings.json` |
| `:(top).env` | `.` | `<顶层>/.env` |
| `:!src/a.txt`（只有排除） | `./a.txt` | 整个仓库，除了 `src/a.txt` |

右列在 scratchpad 的假仓库里量过（git 2.x，Git for Windows）。从子目录 `sub` 运行：

- `git stash push -- ':(top).claude/settings.json'`、`git restore -- ':(top).claude/settings.json'` 都把顶层的 `.claude/settings.json` 还原成了已提交的内容；
- `git stash push -- ':!src/a.txt'` 还原了整个仓库；
- `git diff`、`git log -p`、`git show HEAD`、`git grep` 加 `-- ':(top).env'` 都打印出已跟踪的假密钥；
- `git grep --no-index` 和 `git grep --untracked --no-exclude-standard` 加 `-- ':(top).env.local'` 打印出**未跟踪、被忽略**的假密钥。

假机器，项目 `C:\proj`，无后端（有后端时相同，只有 `git grep` 那几行有后端时送审）：

| 写法 | 判决 | 同一目标不带魔法 |
|---|---|---|
| `git stash push -- ':(top).claude/settings.json'`，`':(top,icase).CLAUDE/SETTINGS.JSON'`，`cd sub && …` | 规则放行（`allow-git-stash`） | deny（`protect-guard-config`） |
| `git diff -- ':(top).env'`，`git log -p -- …`，`git show HEAD -- …` | 规则放行（`allow-git-read-only`） | deny（`no-secret-read`） |
| `git add ':(top).env'` | 规则放行（`allow-git-add`） | deny |
| `git restore -- ':(top).claude/settings.json'`，`git checkout -- …` | 问（`ask-git-discard-paths`） | deny |
| `git grep --no-index -e TOKEN -- ':(top).env.local'` | 问，有后端时送审 | deny |
| `git stash push -- ':/.claude/settings.json'`（短形式），`cd sub && …` | deny | deny |

**对照**（同样无后端）：`git log -p`、`git diff`、`git show HEAD`、`git stash`、`git stash push`、`git add -A` 都由规则放行；`git grep -e TOKEN`、`git grep --no-index -e TOKEN` 是问。所以除了 `restore` / `checkout` 那两行由 deny 变成问，上表的每一种效果都有一个不带路径、也被放行的写法。git 顶层在项目之上时另有 `git-root-above-project` 的检查（M2-rules-1），这次没有重新量。

**修订 13 留下的说法**：`_pathspec` 的文档写"魔法到第一个分隔符为止读作 `.`（`:/src` 是 `./src`，`:!x` 是 `.`）"，例子对，但长形式 `:(top)x` 的路径紧跟在 `)` 后面，没有分隔符。规格 §5.1 那一句（"不算流名，git 自己解析"）本身没错。

**建议**（没有试过）：按 git 的语法解析魔法。短形式是 `:` 加 `/`、`!`、`^` 中的若干个，可选再加一个 `:`；长形式是 `:(…)`。之后的部分作为路径，同时按当前目录和项目根各算一次，标为不确定（allow 侧用不上，deny 侧两处都能命中）；只有排除时整个仓库都算。`glob`、`icase`、`attr` 也标不确定。要补测试：长形式、组合魔法、只有排除、从子目录运行。

### RS-2（低）：PowerShell 里带尾随点或空格的程序路径

实测（Windows PowerShell 5.1，`cmd.exe` 写标记文件证明它运行了）：

| 写法 | 运行了吗 |
|---|---|
| `& 'C:\Windows\System32\cmd.exe.'`，`cmd.exe..`，`'…\cmd.exe '`，`'…\System32.\cmd.exe'` | **运行了** |
| `Start-Process -FilePath 'C:\Windows\System32\cmd.exe.'` | **运行了** |
| `& 'C:\Windows\System32\cmd.'`，`cmd.exe::$DATA`，裸名字 `cmd.exe.` | 找不到 |
| Git Bash：`cmd.exe.`，`/c/Windows/System32/cmd.exe.`，`C:/…/cmd.exe.`，`/c/Windows/System32./cmd.exe` | 找不到（对照 `/c/Windows/System32/cmd.exe` 运行了） |

boundkeep 取程序名时只去掉结尾的 `.exe`，`boundkeep.exe.` 就是一个不认识的程序。假机器：

| PowerShell 写法 | 无后端 / 有后端 | 不带点 |
|---|---|---|
| `& 'C:\tools\boundkeep.exe.' mode audit-only`，`'…\boundkeep.exe ' …`，`'…\boundkeep.exe..' uninstall`，`'…\boundkeep.exe.' taint clear` | 问 / 送审 | deny（`deny-boundkeep-state-commands`） |
| `& 'C:\Windows\System32\diskpart.exe.'`，`.exe `，`.exe..` | 问 / 送审 | deny（`deny-disk-tools`） |
| `& 'C:\Windows\System32.\diskpart.exe'`（点在目录上） | deny / deny | deny |
| `& 'C:\Python312\python.exe.' -m boundkeep mode audit-only` | 问 / 送审 | deny |

`boundkeep mode` 和 `uninstall` 没有运行时的检查（`trust add`、`taint clear` 有两道），只靠这条规则。`docs/threat-model.md` 第 4 节说路径限定的 `boundkeep.exe` 认得出，带尾随点或空格时不成立。uv 生成的 `boundkeep.exe` 启动器在这种写法下是否照常运行，没有量，只量了 `cmd.exe`。Bash 工具里这些写法都是问，Git Bash 也不运行它们。

**建议**（没有试过）：Windows 上取程序名之前先去掉结尾的点和空格（PowerShell 5.1 和 Win32 的读法），deny / ask 规则看去掉之后的名字；名字因此变了的，加一个灰色原因，allow 规则用不上。这和修订 14 的方向相同。

## 3. 查过、没有问题的

| 查了什么 | 结果 |
|---|---|
| 修订 15：`ctx.env` 是什么 | 守护进程的 `os.environ`（`daemon/server.py:570`、`:596`）。agent 在自己的 shell 里改变量传不到这里 |
| 修订 15：`_system_dir` 的写法变体 | `C:/Windows//System32`、`\\?\C:\Windows\System32`、`\\localhost\c$\Windows\System32`、`System32.`、短名字：都不在集合里，都是灰色，方向是收紧 |
| 修订 15：变量的值 | `C:\`、`%SystemDrive%\Windows`、带 `..`、带尾随点：都不给出目录 |
| 修订 15：Git Bash 自己的 `/usr/local/bin`、`/opt/homebrew/bin` | 照样算系统目录。正常安装时它们在 `Program Files` 之下，普通账户写不进；Git 装在可写目录时，和 `/usr/bin` 本身一样（`M3a-system-dirs.md` 第 6 节第 4 条） |
| 修订 13：`reading_only` 里的 `cwd-uncertain` | 加 `cwd-uncertain` 时同时加上工作目录自己的原因（`paths.py:1305-1308`），工作目录因为别的原因不确定时，`reading_only` 是 False |
| 修订 13：`cd ../work:s && cat x`（Git Bash） | 新的工作目录是 `work\uf03as`，之后的路径是确定的项目外路径，问；它是联接点时磁盘层照样跟过去 |
| 三次修订的其余代码 | 读完了 `git diff d1729dd 8ddc6e2 -- src` 的全部增量（310 行增、57 行删），没有别的发现 |
| 那条计时测试 | 原来固定睡 0.3 秒；20 个忙进程压着 CPU 时，旧写法 10 次失败 1 次，改成轮询（5 秒期限）之后 10 次都过。改动在 `c085855` |

## 4. 没有查

- 真实 Claude Code 的 hook 链路。修订 10 到 15 都没有在真实宿主里跑过。
- uv 启动器带尾随点时是否运行（RS-2）；pwsh 7。
- git 顶层在项目之上时，长形式魔法和 `git-root-above-project` 的配合（RS-1）。
- 这里的修法建议都没有试过。

## 5. 建议

1. RS-1 和 RS-2 都是低危，也都没有带来新能力，可以和别的低危一起排期。如果要修，RS-2 改动小（一处取名字），RS-1 要按 git 的语法写一个小解析器，并改规格 §5.1 的那一句。
2. 接真实后端之前，先在真实宿主里跑一次覆盖修订 10 到 15 的冒烟。现有的 `scripts/smoke_claude_m3a.py` 只覆盖原有链路。
3. 要独立的结论，另开一个会话复审。
