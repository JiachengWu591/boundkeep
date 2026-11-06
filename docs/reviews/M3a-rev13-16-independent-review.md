# 规格修订 13 到 16 的独立复审

日期：2026-11-06。代码：`7faa165`（`main`，与 `origin/main` 相同，工作区干净）。审查对象：`git diff d1729dd c69684c -- src`，即修订 13 `372bfa1`、修订 14 `fef9fe9`、修订 15 `8ddc6e2`、修订 16 `c69684c`；记录 `docs/reports/M3a-readings-fixes.md`、`M3a-program-fold.md`、`M3a-system-dirs.md`、`M3a-pathspec-and-dotted-names.md`；规格开头修订 13 到 16 的段落与 §5.1。重点是没有复审过的修订 16：`programs._pathspec`、`_git_operands`、`peel_runner`，`event._canonical_program`。

**这是独立复审。** 这个会话没有参与修订 13 到 16 的编写，也是在自己的结论定下之后才读的 `docs/reviews/M3a-rev13-15-review.md`（第 6 节对照）。作者的说法都当作待核实。

只新增了这份报告，没有改代码、规格、策略和测试，没有提交。没有读 `.env`，没有 LLM 密钥，没有访问真实 LLM 服务，没有读 `eval/authoring/h1-*`、`h2-*` 和留出批次。没有碰 `scripts/`，没有切分支，没有改系统设置。全量测试没有跑，只跑了相关的五个测试文件（第 4 节）。

**判决怎么取的**：真实磁盘上的假项目（scratchpad 里的 git 仓库，"密钥"是写着 `dummy-not-a-secret` 的假字符串，`home` 也是假的），`pipeline.decide` 加总是放行的假后端（`FakeBackend`），平台 `windows`，PowerShell 命令经真实的 PowerShell 5.1 解析辅助进程；关键几条另用 `uv run boundkeep explain --policy policies\default.yaml <事件>` 复核过。"修改前"是把 `d1729dd`（修订 13 之前）的 `src` 与 `policies` 用 `git archive` 导出到 scratchpad，`PYTHONPATH` 指过去跑同一批命令；`372bfa1`、`fef9fe9`、`8ddc6e2`、`c69684c` 也各跑了一遍。git 是 2.48.1.windows.1，PowerShell 是 5.1.26100.9711，Git Bash 是 `D:\新建文件夹\Git\bin\bash.exe`。

下文"规则放行"是无决定、由 allow 规则给出（默认配置下之后还有 Claude Code 自己的权限流程）；"问 / 送审"指无后端时问、有后端时送审（假后端总是放行，结果是无决定）。

## 1. 结论

**修订 16 点名的两类写法修好了，修订 13 到 15 的目标也都达到了；但修订 13 带来一个 PowerShell 专有的回退，四次修订和它们的复审都没有发现。** 高危 0，中危 1，低危 3，信息 4。

| 编号 | 级别 | 一句话 | 要后端吗 | 来源 |
|---|---|---|---|---|
| IR-1 | **中** | PowerShell 里，会话工作目录在项目的子目录时，`git add :/`、`git add ':!x'`、`git add ':(top)'` 由"问 / 送审"变成**规则放行**；实测它们把顶层未被忽略的 `.env` 暂存，随后规则放行的 `git diff --cached` 打印全文 | **不要** | **修订 13 引入的回退**，修订 14 到 16 都还在。Bash 不受影响 |
| IR-2 | 低 | 不带 `--` 的 pathspec 魔法：`git show ':!README.md'`、`git show ':(top)secrets'` 规则放行（`git show` 是 deny）；`git grep T ':(top)'`、`git checkout ':(top).claude/settings.json'` 问 / 送审（不带魔法是 deny）。实测 git 都按 pathspec 执行 | 放行的不要 | 修订 13 之前就有。修订 16 说"git 按 pathspec 读的操作数"按魔法拆，没有覆盖 `--` 之前的操作数 |
| IR-3 | 低 | `REV:目录` 不扫子树：`git archive HEAD:secrets`、`git grep -e x HEAD:secrets` 问 / 送审，`git archive HEAD secrets` 是 deny；实测归档里、grep 输出里有假私钥 | 送审要 | 修订 13 之前就有。修订 16 改了这段代码（archive 只认第一个操作数），没有碰到它 |
| IR-4 | 低 | 程序名的另一种 Win32 读法：8.3 短名。`& 'C:\…\BOUNDK~1.EXE' mode audit-only` 问 / 送审（`boundkeep.exe` 是 deny）；实测 PowerShell 5.1 按路径运行短名 | 送审要 | 修订 13 之前就有。和 RS-2 同一类，修订 16 只处理了点和空格 |
| IR-5 | 信息 | 规格修订 16、记录第 1 节、非独立复审开头都说 `git archive HEAD '::.git/config'` "实测 git 把那个文件打进了归档"。实测不成立：git 报 `pathspec '::.git/config' did not match any files`，退出码 128 | — | 记录与实测不符 |
| IR-6 | 信息 | 三处"效果和原本就放行的写法相同"的论证只在假机器上成立：真实磁盘上项目里有受保护名字时，`git log -p`、`git show HEAD` 是 deny，`git add -A` 是问；修订 13 记录"判决回到原样"在 PowerShell 子目录不成立（IR-1） | — | 记录与实测不符 |
| IR-7 | 信息 | 已知缺口比记录写的宽：`git diff <空树> HEAD`、`git diff <空树>` 规则放行，打印每个已跟踪文件的全文（假 `.env`、假私钥都在）；`docs/reports/M2-rules-1.md` 只写了"已跟踪的 `.env` 被改过之后" | 不要 | 修订 13 之前就有，不在本次范围；它是 IR-2、IR-3、RS-1 都只评低的原因 |
| IR-8 | 信息 | PowerShell 5.1 运行 `X.exe.` 走 ShellExecute：另开窗口、异步、输出不回到调用方、`$LASTEXITCODE` 不更新。uv 生成的 `boundkeep.exe.`、`python.exe.` 都照常运行（补上修订 16 记录第 6 节第 7 条"没有量"） | — | 实测补充 |

**为什么 IR-1 是中、不是高**：原来的判决是问，不是 deny；要两步（先暂存，再 `git diff --cached`），还要有一个没被 `.gitignore` 忽略的受保护文件在当前目录之外。**为什么不是低**：它是回退，把 X1 复审 R3-3 / R5-1 修过的口子在开发机的主 shell 上重新打开；不需要后端，不需要特殊字符，`git add :/` 是常见写法。前提是 hook 收到的 `cwd` 在子目录里（例如在子目录里启动会话）；同一行里 `Set-Location sub; git add ':/'` 是送审，不受影响；PowerShell 工具是否把上一条命令 `cd` 进去的目录带到下一条的 `cwd`，没有量。

## 2. 发现

### IR-1（中，修订 13 引入的回退）：PowerShell 子目录里带魔法的 `git add` 由规则放行

**写法**：PowerShell 工具，`cwd` 是项目的子目录（例 `<项目>\sub`）：`git add :/`、`git add -- ':/'`、`git add ':(top)'`、`git add ':!x'`、`git add ':(exclude)x'`。

**修改前后**（项目根下有 `.env`，子目录里没有）：

| 写法 | `d1729dd` | `372bfa1`、`fef9fe9`、`8ddc6e2`、`c69684c` |
|---|---|---|
| PowerShell，`cwd=sub`：上面五种 | 问 / 送审（`git-add-may-stage-protected`） | **规则放行**（`allow-git-add`） |
| Bash，`cwd=sub`：同样五种 | 问 / 送审 | 问 / 送审（不变） |
| PowerShell，`cwd=sub`：`git add -A` | 问 / 送审 | 问 / 送审（不变） |
| PowerShell，`cwd=sub`：`git diff --cached` | 规则放行 | 规则放行（不变） |

**实测**（scratchpad 里的假仓库：`README.md`、`sub/b.txt` 已提交，顶层 `.env` 未跟踪、未被忽略）：在 `sub` 里运行 `git add -- ':/'` 和 `git add -- ':!README.md'`，`git diff --cached --name-only` 都列出 `.env`，`git diff --cached` 打印出假密钥的那一行。

**原因**：修订 13 让 `_pathspec` 把魔法换成路径，旧的 `_stages_whole_repository` 靠 `target.startswith(":")` 认整个仓库的写法，于是改成看 `CmdInfo.pathspec_magic`。PowerShell 里的外部程序走 `psprograms._external`：它调 `programs.classify(..., shell="bash")` 拿到 `info`，只把 `known`、`sub`、`flags`、`paths`、`urls`、`network`、`gray`、`recursive` 抄进自己的累加器，`_finish` 重新构造 `CmdInfo` 时没有 `pathspec_magic`，于是 PowerShell 里它永远是 False，项目根不再被扫描。`CmdInfo` 的其余字段我逐个对过，只漏了这一个。

**测试为什么没抓到**：R5-1 的回归测试 `tests/unit/test_git_local_vcs_allow.py::test_the_whole_repository_forms_are_looked_at_from_a_sub_directory` 用的 `_tree_review` 固定 `tool_name: "Bash"`。修订 13 记录里的真实磁盘差分（23544 条）语法里没有 git，"带冒号的普通命令"（492 条）在项目根运行。

**复现**（不依赖我的 scratchpad，在仓库根目录运行；和 `_tree_review` 相同，只多了 `tool`）：

```python
# uv run python repro_ir1.py  -> 当前代码 PowerShell 除 git add -A 外四行 allow；把 d1729dd 的 src、policies 导出后 PYTHONPATH 指过去，全部 gray
import os, tempfile
from pathlib import Path
from boundkeep.daemon import pipeline
from boundkeep.normalize import psparse
from boundkeep.policy import default_policy_text, parse_policy_text

psparse.warm_up(wait_s=15)
with tempfile.TemporaryDirectory() as d:
    project = Path(d) / "proj"
    (project / ".git").mkdir(parents=True)
    (project / "src").mkdir()
    (project / "src" / "a.py").write_text("x\n", encoding="utf-8")
    (project / ".env").write_text("x\n", encoding="utf-8")
    home = str(Path(d) / "home"); os.makedirs(home)
    env = {k: v for k, v in os.environ.items() if k.upper() in ("SYSTEMROOT", "PATH", "TEMP")}
    env["USERPROFILE"] = env["HOME"] = home
    runtime, _ = pipeline.runtime_policy_checked(parse_policy_text(default_policy_text(), home=home), env, home)
    for tool in ("Bash", "PowerShell"):
        for cmd in ("git add -A", "git add :/", "git add ':(top)'", "git add ':!x'", "git add -- ':/'"):
            payload = {"tool_name": tool, "tool_input": {"command": cmd}, "cwd": str(project / "src"),
                       "project_dir": str(project), "session_id": "s"}
            r = pipeline.review(payload, runtime, platform=pipeline.local_platform(), env=env, home=home)
            print(tool, cmd, r.verdict.decision, [g for a in r.verdict.actions for g in a.gray_reasons])
```

当前代码的输出：Bash 五行都是 `gray ['git-add-may-stage-protected']`；PowerShell 除 `git add -A` 外四行是 `allow []`。也可以用 `boundkeep explain`：事件 `{"hook_event_name":"PreToolUse","tool_name":"PowerShell","tool_input":{"command":"git add -- ':/'"},"cwd":"<项目>\\sub","project_dir":"<项目>","session_id":"s"}`，项目根下放一个 `.env`，输出 `verdict: allow   rules: allow-git-add`；同一事件换成 `Bash` 是 `verdict: gray`。

**记录里与此不符的说法**：修订 13 记录第 4a 节"和修订 13 之前的 key 相同，判决回到原样"；修订 16 记录第 6 节第 1 条"`git add` 在真实磁盘上另有 `git-add-may-stage-protected`"；规格 §5.1 修订 16 那一段"（`git add` 另有整个仓库的检查）"。三处在 PowerShell 的子目录里都不成立。

**建议**：`_external` 把 `info.pathspec_magic` 抄过来，`_finish` 传出去；更稳的是让 `_external` 在 Bash 侧的 `CmdInfo` 上用 `dataclasses.replace` 改它要改的字段，以后加字段不会再漏。测试：R5-1 那条参数化加上 `PowerShell`；再加一条"PowerShell 外部程序的 `CmdInfo` 与 Bash 侧逐字段相同（除了 PowerShell 自己加的灰色原因和标签）"。改完要重跑真实磁盘差分，并把 git 和非根目录的 `cwd` 加进语法。

### IR-2（低，修订 13 之前就有）：`--` 之前的 pathspec 魔法

**写法与判决**（当前代码与 `d1729dd` 相同）：

| 写法 | 判决 | 不带魔法的对照 |
|---|---|---|
| `git show ':!README.md'`、`':^README.md'`、`':(exclude)README.md'`、`':(top)'`、`':(top)secrets'`、`git show HEAD ':!README.md'` | **规则放行**（`allow-git-read-only`），有无后端相同 | `git show`、`git show HEAD -- secrets`：deny（`no-secret-read`、`no-credential-store-read`） |
| `git grep FAKE ':(top)'`、`git grep FAKE ':!README.md'` | 问 / 送审 | `git grep FAKE`：deny |
| `git checkout ':(top).claude/settings.json'`、`git checkout ':/.claude/settings.json'` | 问 / 送审（没有路径） | `git checkout .claude/settings.json`：deny（`protect-guard-config`） |

**实测**：`git show ':!README.md'`、`':^README.md'`、`':(exclude)README.md'`、`':(top)'` 都打印 HEAD 里 `.env` 和 `secrets/id_rsa` 的假内容，`':(top)secrets'` 打印 `secrets/id_rsa`；`git grep FAKE ':(top)'`、`':!README.md'` 打印 `.env` 的那一行；两种 `git checkout` 都输出 `Updated 1 path from the index`，`.claude/settings.json` 被还原成已提交的内容；退出码都是 0。也就是说，没有 `--` 时，git 把长形式 `:(…)` 当 pathspec（后面没有路径的 `':(top)'` 也照样执行，说明不靠"文件存在"判断），`:/x`、`:!x`、`:^x` 也当 pathspec（实测的几条里 `x` 都存在；`x` 不存在时 git 怎么消歧没有量）。

**原因**：`show`、`diff`、`grep`、`cat-file` 在 `--` 之前的操作数，除了以 `.`、`/`、`~` 或盘符开头的词，只走 `_rev_path`：`:!README.md` 被读成索引路径 `!README.md`，算一个 `REV:PATH`，`_git_operands` 于是在设 `recursive` 之前返回，整个工作区不再扫描。`checkout` 在 `--` 之前的操作数只在 `_outside_like`（以 `.`、`/`、`~` 或盘符开头）时才算路径，`:(top)…` 和 `:/…` 都不算。修订 16 的规格写的是"git 按 pathspec 读的操作数，魔法按 git 的语法拆开"，实现只覆盖了 `--` 之后的操作数和 `_GIT_PATHSPEC_ALL`、`stash push`、`archive` 的操作数。

**为什么是低**：效果都有一直规则放行的写法：`git diff <空树> HEAD` 打印所有已提交的内容（IR-7），`git stash` 把 `.claude/settings.json` 的改动还原掉（规则放行，`allow-git-stash`）。如果以后收紧 IR-7，这一条应升为中。

**建议**：`--` 之前、以 `:` 开头的操作数，两种读法都给规则看：`_rev_path` 的索引路径和 `_pathspec` 的路径；排除形式和空路径（`:(top)`、`:/`）不算 `REV:PATH`，照样递归扫描 `.`；`checkout` 的这种操作数也走 `_pathspec`。git 的 `--` 前消歧还会把带通配符的词当 pathspec，也一并考虑。规格 §5.1 修订 16 那一句写清范围。

### IR-3（低，修订 13 之前就有）：`REV:目录` 不扫子树

**写法与判决**（当前代码与 `d1729dd` 相同）：`git archive HEAD:secrets`、`git archive -- HEAD:secrets`、`git archive -o x.tar -- HEAD:secrets`、`git grep -e dummy HEAD:secrets` 都是问 / 送审；对照 `git archive HEAD secrets`、`git archive HEAD -- secrets`、`git grep -e dummy HEAD -- secrets` 是 deny（`no-credential-store-read`）。

**实测**：`git archive --format=tar HEAD:secrets` 和 `git archive -- HEAD:secrets` 的归档里都是 `id_rsa`，解开就是假私钥；`git grep -e dummy HEAD:secrets` 打印 `HEAD:secrets:id_rsa:DUMMY KEY …`。

**原因**：`_rev_path` 得到的 `secrets` 只按普通读加入，`rev_paths` 不为零时 `_git_operands` 直接返回，目录不扫描。`git archive -- HEAD:secrets` 里 `--` 被 git 的选项解析吃掉，tree-ish 仍是第一个参数；boundkeep 把它当 `--` 之后的 pathspec，key 成了 `<项目>/head`。修订 16 改了这里的循环（`before[:1] if sub == "archive"`），这两种情况没有碰到。

**为什么是低**：同 IR-2，`git diff <空树> HEAD` 规则放行同样的内容。

**建议**：`archive`、`grep` 的 `REV:PATH` 按递归读（是目录就扫子树）；`archive` 的第一个非选项参数就是 tree-ish，不论它在 `--` 前后。

### IR-4（低，修订 13 之前就有）：程序名的 8.3 短名

**写法与判决**：PowerShell `& 'C:\Users\x\BOUNDK~1.EXE' mode audit-only` 问 / 送审（灰色 `program-path-qualified`，程序名是 `boundk~1`）；`& 'C:\Users\x\boundkeep.exe' mode audit-only` 是 deny（`deny-boundkeep-state-commands`）。`d1729dd` 到 `c69684c` 都一样；修订 16 只把 `boundkeep.exe.` 那一行改成了 deny。

**实测**：C: 卷会生成短名：scratchpad 里复制的 `fakeboundkeepprogram.exe`（`whoami.exe` 的副本）`dir /x` 显示 `FAKEBO~1.EXE`，PowerShell 5.1 `& '…\FAKEBO~1.EXE'` 运行了它；裸名字 `FAKEBO~1` 经 PATH 找不到。这台机器上 E: 的 `.venv\Scripts\boundkeep.exe`、`System32` 里的程序、`D:\新建文件夹\Git` 下的程序都没有短名，所以这台机器现在的安装碰不到。

**为什么是低**：和 RS-2 同一类、同一级：只在 `boundkeep.exe` 所在的卷生成 8.3 短名时成立（例如项目或 `uv tool` 装在 C: 上）。

**建议**：带路径的程序在磁盘上解析到的长名字（已有的 `program-path-qualified` 路径解析结果的最后一段，或 `GetLongPathNameW`）也给 deny / ask 规则看；名字含 `~` 且长名不同的，灰色。规格 §5.1 修订 16 那一段可以写成"程序名的 Win32 读法"，把短名列进去。

### IR-5（信息）：`.git/config` 打不进归档

规格修订 16（开头的修订段落）、修订 16 记录第 1 节、`docs/reviews/M3a-rev13-15-review.md` 开头的补记都说：原来 `git archive HEAD '::.git/config'` 只是灰色，"实测 git 把那个文件打进了归档"。实测：`git archive --format=tar HEAD '::.git/config'` 输出 `fatal: pathspec '::.git/config' did not match any files`，退出码 128；`':.git/config'` 也一样。树里不可能有 `.git` 这一段，所以 archive 永远拿不到它。记录第 3 节表格里量的是 `'::secrets/id_rsa'`、`':(top)secrets/id_rsa'`，那是对的（我量 `'::.env'` 也打进了归档），修法本身成立，只是例子写错了。**建议**：三处的例子换成 `'::secrets/id_rsa'`。

### IR-6（信息）：几处"效果相同"的论证只在假机器上成立

- 修订 16 记录第 6 节第 1、4 条和非独立复审第 1 节，都用"不带路径的写法本来就放行"（`git log -p`、`git show HEAD`、`git add -A`、`git stash`）论证排除读作 `.`、长形式魔法都没有带来新能力。在真实磁盘上、项目里有 `.env` 或私钥时，`git log -p`、`git show`、`git show HEAD` 是 deny（子树扫描），`git add -A` 是问；只有 `git diff`、`git stash` 一直放行。结论碰巧仍然对，是因为 IR-7 的 `git diff <空树>`。
- 修订 13 记录第 4a 节"判决回到原样"、修订 16 记录第 6 节第 1 条：见 IR-1。

**建议**：以后评"没有新能力"时，在真实磁盘上、项目里放受保护名字再量一次对照写法。

### IR-7（信息，不在本次范围）：`git diff <修订>` 打印已提交的全部内容

`git diff 4b825dc642cb6eb9a060e54bf8d69288fbee4904 HEAD`（空树对 HEAD）和 `git diff 4b825dc642cb6eb9a060e54bf8d69288fbee4904`（空树对工作区）都是规则放行（`allow-git-read-only`），`d1729dd` 上 `git diff <空树>` 也是；实测前者打印出 `.env` 和 `secrets/id_rsa` 的假内容。同一内容，`git show HEAD:.env`、`git show HEAD`、`git log -p` 都是 deny。原因是 `_git_operands` 只给 `grep`、`archive`、`log -p`、`show`、`stash show -p` 设 `recursive`，`diff` 带修订时不设。`docs/reports/M2-rules-1.md` 第 72、89 行记下了"`git diff` 不扫描工作区"，但写的是"已跟踪的 `.env` 被改过之后"，没有写带修订的 `diff` 可以打印每个已跟踪文件的全文、包括历史里的。`allow-git-read-only` 的测试样例里本来就有 `git diff HEAD~1`。**建议**：另开一项决定，带修订操作数的 `diff`（以及 `--cached` 加修订）是否按 `show` 一样递归扫描；至少把这个更宽的形式写进 `docs/threat-model.md`。

### IR-8（信息）：带尾随点的程序在 PowerShell 5.1 里怎么运行

- `Get-Command 'C:\Windows\System32\cmd.exe.'` 是 `Application`，`Extension` 为空。`& '…\cmd.exe.' /c "echo …> 文件"`、`'…\cmd.exe '`、`'…\cmd.exe. .'`、`Start-Process -FilePath '…\cmd.exe.'` 都写出了标记文件，确实运行了；但 `&` 的写法控制台上没有任何输出，`$LASTEXITCODE` 不更新，要等一会儿文件才出现：PowerShell 按"文档"交给 ShellExecute，另开窗口、异步运行。读文件类的命令这样跑，输出不会回到 agent；改状态的命令（`boundkeep mode audit-only`）照样生效。
- uv 生成的启动器：`Start-Process -FilePath 'E:\boundkeep\boundkeep\.venv\Scripts\boundkeep.exe.' -ArgumentList '--version' -RedirectStandardOutput …` 输出 `boundkeep 0.0.0.dev0`，退出码 0；`explain <事件>` 也正常；`& '…\.venv\Scripts\python.exe.' -c "open(…,'w').write('ran')"` 写出了文件。修订 16 记录第 6 节第 7 条"没有量"，现在量过了：会运行，所以那条 deny 是有用的。
- 裸名字 `cmd.exe.`、`& '…\cmd.'`、`& '…\cmd.exe::$DATA'`、`Start-Process '…\cmd.exe::$DATA'` 都运行不了；Git Bash 里 `/c/Windows/System32/cmd.exe.`、`cmd.`、`whoami.exe::$DATA` 都是 `No such file or directory`。和修订 16 记录第 3 节一致。

**建议**：修订 16 记录第 3 节加一句"按 ShellExecute 运行，输出不回到调用方"，第 6 节第 7 条改成已量。

## 3. 查过、没有问题的

| 查了什么 | 结果 |
|---|---|
| 修订 16 RS-1 点名的写法（真实磁盘，根目录和 `sub`） | `git diff -- ':(top).env'`、`git stash push -- ':(top).claude/settings.json'`、`':/.claude/settings.json'`、`git restore ':(top).claude/settings.json'`、`git commit -m x -- ':(top).env'`、`git stash -- ':(top).claude/settings.json'`、`git diff -- ':(top)secrets/id_rsa'`、`git diff -- ':(icase).ENV'`、`':(glob)**/.env'`、`git archive HEAD '::.env'`、`'::.git/config'` 都是 deny；`d1729dd` 到 `8ddc6e2` 上 `git diff -- ':(top).env'` 是规则放行 |
| `_pathspec` 与 git 的语法逐条比 | 短形式只认 `/!^`、可选一个结束冒号，与 git 相同；git 遇到别的魔法字符（`#`、`-`、`@` 等）报错退出，这里多看一个路径，方向对。长形式：`text.find(")")` 与 git 的结束位置在 git 不报错的输入上相同（被 `\` 转义的 `)` 只可能出现在 `attr:` 值或别的词里，git 都会报错退出）；空词、大小写不同、带空格的词这里都是灰色，git 是报错或忽略，方向都对；`prefix:N` 灰色；括号没闭合实测退出码 128（`Missing ')'`） |
| 排除读作 `.` | 实测 git 作用于除它以外的整个仓库；`git diff -- ':!secrets/id_rsa'` 放行与 `git diff` 相同；`git archive HEAD ':!README.md'` 仍是 deny（`.` 照样递归扫描）；`git stash push -- ':!README.md'` 放行与 `git stash` 相同 |
| git 自己的通配（引号里的 `.en?`、`*.env`、`.e[n]v`、`':(top).en?'`） | 磁盘上展开，deny |
| 修订 16 RS-2：`_canonical_program` | PowerShell `& '…\boundkeep.exe.'`、`'…\boundkeep.exe .'` → deny；`diskpart.exe.` → deny；`cmd.exe.` `/c type …\.ssh\id_rsa` → deny；`reg.exe.` 写 `Run` 键 → 问（与不带点相同）；`git.exe. status` → 灰色送审，不被规则放行；Bash `boundkeep.exe.`、`/c/…/boundkeep.exe.` → deny（多出来的，Git Bash 本来就跑不了）；`.`、`..` 不算（读代码，没有单独量） |
| 修订 16：`peel_runner` 不分平台去点 | 剥出来的命令带 `wrappers` 标记，`matcher.py:296` 让 allow 规则一律不匹配，所以 POSIX 上 `./uv. run …` 只会更严；PowerShell `& 'C:\x\uv.exe.' run boundkeep mode audit-only`、`& 'C:\x\python.exe.' -m boundkeep …` → deny |
| 修订 16：`git archive` 只认第一个操作数为 `REV:PATH` | `git archive HEAD '::.env'`、`HEAD -- .env`、`-o x.tar HEAD -- .env` → deny；第二个操作数写成 `HEAD:.env` 时 git 报 pathspec 不匹配，不读 |
| 修订 13 RV-1（真联接点 `keys`→假 `~\.ssh`、`guard`→假 `~\.boundkeep`） | 19 种写法（PowerShell `keys.\id_rsa`、`keys\id_rsa.`、`'keys. \id_rsa'`、`::$DATA`、`Set-Content guard\policy.yaml. x`、`guard.\policy.yaml`、`Copy-Item`、`Get-ChildItem keys. -Recurse`、`Select-String x keys.\*`；Bash `cat keys./id_rsa`、`grep -r x keys.`；Read 工具带点、流名、短名）在修订 13 之后全部 deny；`d1729dd` 上有 6 种是问或送审。实测 PowerShell 5.1 `Get-Content keys.\id_rsa`、`keys\id_rsa.` 读到了假私钥，`Set-Location keys.` 失败 |
| 修订 13 RV-2、RV-3 | Bash `cat ../proj:s/a.txt` 由规则放行变成问（`llm-failure:refused`）；`cat .env:x`、`'secrets/id_rsa:x'`、Read `.env:x` → deny；`\\localhoſt\c$\…\a.txt` 由规则放行变成问（`net-unknown-destination`）；`\\localhost\c$\…\.env`、`\\127.0.0.1\c$\…\id_rsa` → deny |
| 修订 14：PowerShell 别名的折叠写法 | `lſ a.txt`、`ſls x a.txt`、`ſl ..` → 问，不送审（`program-fold-variant`）；实测 PowerShell 5.1 找不到 `lſ` |
| 修订 15：deny / ask 有没有变松 | 13 条（`C:/`、`D:/Windows/System32/diskpart.exe`，`/usr/bin/rm -rf ~`，`C:/msys64/usr/bin/rm`，`E:/usr/bin/cat ~/.ssh/id_rsa`，`reg.exe` 写 `Run` 键两种 shell，`curl.exe`，`powershell.exe -Command Get-Content ~\.ssh\id_rsa`，`OpenSSH/ssh.exe`，`System32`、`SysWOW64` 的 `cmd.exe /c type`）五个版本判决相同；`/usr/bin/cat a.txt`、`'C:\Program Files\Git\cmd\git.exe' status` 仍规则放行 |
| PowerShell 与 Bash 的 `CmdInfo` | 逐字段对了 `psprograms._finish` 与 `programs._classify`：只少 `pathspec_magic`（IR-1） |
| 相关测试文件 | 见第 4 节 |

## 4. 跑过的测试

`uv run pytest -q tests/unit/test_m3a_pathspec_and_dotted_names.py tests/unit/test_m3a_readings.py tests/unit/test_git_local_vcs_allow.py tests/unit/test_m3a_program_fold.py tests/unit/test_m3a_system_dirs.py`（当前代码）：**887 passed**，3 分 47 秒。

它们没有抓到 IR-1：R5-1 那条只测 Bash。全量没有跑。

## 5. 没有查的

- 真实 Claude Code 的 hook 链路。修订 10 到 16 都没有在真实宿主里跑过，这次也没有。
- pwsh 7；WSL2 里经 interop 运行 `/mnt/c/…/cmd.exe.`（这台机器没有可用的发行版）；别的 git 版本（只量了 2.48.1.windows.1）；NTFS 以外的文件系统。
- git 顶层在项目之上（monorepo）时 `:(top)` 的读法与 `git-root-above-project` 的配合；`git restore`、`git clean` 带排除从子目录运行的真实范围。
- 发给模型的请求内容（`program-name-trailing-dots`、`git-pathspec-magic` 送审时模型看到什么）没有逐字检查。
- 变异测试、作者的大差分（49720、23544、179508 条）没有重跑。
- 顺带看到、没有深究的线索（都早于修订 13，不在本次范围）：git 默认 pathspec 里 `*` 跨目录匹配，`git show HEAD -- '*id_rsa'` 是问（`secrets/id_rsa` 写全是 deny），`git archive HEAD '*id_rsa'`、`git grep -e x -- '*id_rsa'` 是问 / 送审，实测 git 打印了 `secrets/id_rsa`；PowerShell 里 `& '…\Git\usr\bin\env.exe' boundkeep mode audit-only` 是问 / 送审（`env` 在 PowerShell 里不按包装器剥开），`env.exe` 在这种调用下能否找到 `boundkeep` 没有量。

## 6. 与非独立复审（`docs/reviews/M3a-rev13-15-review.md`）的对照

**一致的**：RS-1、RS-2 我都复现了（`d1729dd` 到 `8ddc6e2` 上 `git diff -- ':(top).env'` 规则放行，`& '…\boundkeep.exe.' mode audit-only` 问 / 送审），修订 16 也都修好了。PowerShell 5.1 和 Git Bash 对尾随点、`::$DATA` 的读法与它的表格相同。修订 15 的 `ctx.env`、系统目录变体、修订 13 的联接点结论我没有发现不同。

**它没有的**：

- **IR-1**：它的结论是"没有找到它们带来的回退"。修订 13 在 PowerShell 子目录的 `git add` 上就是一个回退，而且修订 16 记录与规格都把这个检查当作还在起作用。
- IR-2（`--` 之前的魔法：`show` 规则放行，`grep`、`checkout` 送审）；它的 RS-1 建议也只列了长形式、组合魔法、排除、子目录。
- IR-3（`REV:目录` 不扫子树）、IR-4（8.3 短名）。
- IR-5：它开头补记里"git 却把 `.git/config` 打进了归档"不成立。
- IR-6：它第 1 节"不带路径的写法本来就由规则放行：`git log -p`、`git diff`、`git show HEAD` …、`git add -A`"是假机器上的结果，真实磁盘上项目里有受保护名字时前两个和 `git add -A` 都不放行。
- IR-7：它引用了 M2-rules-1 的"`git diff` 显示已跟踪的 `.env`"，没有发现带修订的 `diff` 能打印全部已提交内容，而这才是它"没有新能力"结论真正的依据。
- IR-8：uv 启动器带尾随点会运行（它列为没有量）；ShellExecute 的运行方式。

## 7. 建议的顺序

1. 修 IR-1（一处抄字段，加 PowerShell 的测试），它是回退，又不需要后端。
2. 改正 IR-5、IR-6、IR-8 涉及的规格与记录文字。
3. IR-2、IR-3、IR-4 是低危，可以和别的低危一起排；如果决定收紧 IR-7（带修订的 `git diff`），IR-2、IR-3 应一起修，否则收紧没有意义。
4. 这次和前几次一样，真实宿主里没有跑。接真实后端之前跑一次覆盖修订 10 到 16 的冒烟。
