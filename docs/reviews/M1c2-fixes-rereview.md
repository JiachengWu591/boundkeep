# M1c / M1c-2 X1 修复的定向复审

日期：2026-10-23。审查对象：`git diff 5089c1d..HEAD`（`4b1d61d`、`977b040`、`e282477`、`75e1863`，标签 `m1c4-done` 到 `m1c2-x1-medium-fixes-done`）。对照上一轮审查 `docs/reviews/M1c2-security-review.md` 的 H-1 到 H-6、M-1、M-3、L-1 便宜部分，以及三份修复报告（`M1c2-review-fixes.md`、`-2.md`、`-3.md`）。本轮编号 R-1 起。

## 0. 结论先行

**高危没有清零：3 条高危（R-1、R-2、R-3），5 条中危，7 条低危。不建议现在冻结规则、取 M2 基线。**

| 上一轮 | 是否真的关闭 | 依据 |
|---|---|---|
| H-1 参数文件 `@` | **没有关闭**（R-1） | 词以 `@` 开头才灰色；选项值里**以展开或通配符开头**的词（Bash `"${u}@a.txt"`、`?args.txt`、`[@]a.txt`，PowerShell `"$u@a.txt"`）运行时才变成 `@a.txt`，归一化层看不见。用已装的真 pytest 与 ruff 确认会读参数文件。受信任项目里整行 `allow`。 |
| H-2 pylint `--output-format` | 关闭（pylint 没装，未在真实工具上验证） | 唯一缩写、`-f` 各种附着、重复、大小写、空值、逗号、`${f:-…}` 全部灰色；其余六个工具的"格式:路径"写法没有发现同类问题 |
| H-3 环境变量前缀 | 关闭（有一个低危的值问题，R-12） | `export`/`declare`/`set -a`/`read`/子 shell/`env`/`time`/`command`/`&&` 后的前缀、大小写变体、`Path`/`path`、PowerShell 的 `$env:` 赋值都是灰色 |
| H-4 `ps-dynamic-arg` | **没有关闭**（R-2） | **冒号附着的开关值**（`-Stream:$env:X`、`-Verbose:$env:X`、`-Wait:$env:X`、`-Unique:$env:X` …）被 `pscmd` 丢掉，allow 规则覆盖的每个 cmdlet 都有这个洞；另有 R-4（外部程序的选项值）。 |
| H-5a `trust add` 与环境变量 | 关闭（按它自己声明的"不是边界"） | `cmd_add` 第一件事检查，`remove`/`list` 不受限且无害 |
| H-5b 会话快照 | 基本关闭，有三个"失败即放行"的边（R-7，低） | 并发与 LRU 的实现正确；重启、被驱逐、会话开始时策略不可用三种情形会拿到**当前**列表 |
| H-6a `st_nlink` | **没有关闭**（R-3） | 只在 `resolve_on_disk` 里查；**目录读（`Grep`/`Glob`/`rg`/`grep -r`）的子树扫描没有查 nlink**：项目里普通名字的硬链接指向 `~/.ssh/id_rsa`，对目录做 `Grep` 仍是 `allow`（真实磁盘确认，内容行会进入上下文）。 |
| H-6b 链接规则 | 大体关闭，有相对路径的缝（R-8，中） | ~60 种 `ln`/`cp -l`/`New-Item`/`mklink`/`fsutil` 写法对已知秘密与守护文件都是 deny；但 `Set-Location <守护目录>; cmd /c mklink /H n policy.yaml` 与 `fsutil hardlink create` 的**相对**写法只是 ask |

**H-1 到 H-6 没有全部真的关闭，高危不是零，不能冻结。** 冻结前必须做的事见第 8 节。

读法说明与上一轮相同：`emit_allow: false` 下的 `allow` 是"无决定"，boundkeep 不再是闸门，后续由用户的 Claude Code 权限设置决定。

## 1. 方法与惰性

- 判决观察：真实管道（`policycli._run_one` / `pipeline.review`），假机器（Windows `C:\Users\testuser`、POSIX `/home/testuser`），策略 = 随附 default（或 strict）加 `trusted_projects: [假项目]`。PowerShell 命令由真实辅助进程解析（只解析，不执行）。**没有执行任何被审查的命令。**
- 旧版对照：`git archive m1c4-done` 导出到临时目录，用 `sys.path` 指向它（旧代码 + 旧策略），不碰工作区。
- 真实磁盘：`%TEMP%\bk_rr_disk` 下一次性目录（假 home、项目、硬链接、联接点），`BOUNDKEEP_HOME` 指向 `%TEMP%` 下的目录。没碰真实的 `~/.boundkeep`、`~/.claude`；没有运行 `boundkeep trust add`（`trust list`、`trust remove`、`doctor`、`explain` 在一次性 `BOUNDKEEP_HOME` 上运行过）。
- 对**已装的**真实工具做的无害运行（一次性目录 `%TEMP%\bk_rr_h1`，载荷惰性，只写那个目录里的文件）：用 `-k "$u@a.txt"` 形式的参数确认 pytest 9.1.1 展开 `@a.txt`（`a.txt` 里是 `--debug=dbg_out.log`，该文件被写出）；确认 ruff 展开 `--select "$u@r.txt"`（`r.txt` 里是 `--output-file=ruff_out.txt`，该文件被写出）；`ruff check --select <无效名>` 与 `mypy --python-version <无效值>` 的错误信息会原样回显那个值。没有运行 black / isort / flake8 / pylint（没装，没下载）。
- 脚本都在会话临时目录，不在仓库里。

## 2. 发现：高

### R-1 H-1 的修复可以绕过：展开或通配符产生的 `@` 词

- **对应**：H-1。**机制**：`devtool_gray_reasons`（`programs.py`）只看 `args` 里**字面文本**以 `@` 开头的词。
- **事实**：argparse 的 `fromfile_prefix_chars` 与 ruff 的 argfile 在**展开之后**才看参数。选项值（`-k` 的值、`--select` 的值……）里以展开或通配符开头的词，归一化层看到的文本是 `${u}@a.txt` / `?args.txt`，不是 `@`；位置参数里这种词已被"整词是展开则灰色"（`dynamic-argument-may-be-option`）盖住，**选项值没有**。
- **惰性复现**（受信任项目；下列全部 `allow`，规则 `allow-devtools-trusted-project`）：

```yaml
trusted_projects: ["C:\\Users\\testuser\\proj", "/home/testuser/proj"]
tests:
  - { tool: Bash,       platform: [posix],   input: { command: 'pytest -k "${u}@args.txt"' },            expect: gray }
  - { tool: Bash,       platform: [posix],   input: { command: 'pytest -k "${X:-@args.txt}"' },         expect: gray }
  - { tool: Bash,       platform: [posix],   input: { command: 'ruff check --select "${u}@args.txt" .' }, expect: gray }
  - { tool: Bash,       platform: [posix],   input: { command: 'pytest -k ?args.txt' },                 expect: gray }  # 需要项目里有 @args.txt 与 args.txt 两个文件
  - { tool: Bash,       platform: [posix],   input: { command: 'ruff check --select [@]r.txt .' },      expect: gray }
  - { tool: PowerShell, platform: [windows], input: { command: 'pytest -k "$u@args.txt"' },             expect: gray }
  - { tool: PowerShell, platform: [windows], input: { command: 'ruff check --select "$u@r.txt" .' },    expect: gray }
```

  （`$u`、`${u}` 是未设置的变量，展开为空；`${X:-@args.txt}` 是 Bash 的默认值展开，同一行内自给自足，不需要任何前置状态。）同类的 `pylint --disable "${u}@x"`、`mypy --python-version "$u@x"` 等同理。
- **实际观察**：Bash `pytest -k $u@a.txt`、`-k "$u@a.txt"`、`-k "$0@a.txt"`、PowerShell `-k $u@a.txt`、`-k "${env:NOSUCH}@a.txt"` 全是 allow。对照：位置参数 `pytest "${u}@a.txt"` 是 ask（`dynamic-argument-may-be-option`）；`pytest -k "$(true)@a.txt"`（命令替换）是灰色；字面 `@` 的各种写法（引号、转义、`$'…'`、`--` 之后、`--%`）都是灰色。真实工具：见第 1 节，pytest 9.1.1 与 ruff 都读了那个文件，`--debug=<路径>` / `--output-file=<路径>` 被执行。
- **攻击**：和 H-1 完全一样：`Write args.txt`（`allow-project-file-writes`，不弹框），内容 `--debug=C:\Users\me\.boundkeep\policy.yaml`（pytest 的 `--debug` 以 `w` 打开并截断）或 `--output-file=…`、`-p evil_plugin`、`--python-executable`，再跑上面任一行。`~/.claude/settings.json`（去掉 hook）、`policy.yaml`（守护进程把策略视为不可用）、shell 启动文件都能被截断。
- **严重度**：高（修复可被绕过而回到上一轮 H-1 的状态；不需要用户确认）。
- **建议修复**：`devtool_gray_reasons` 对**所有**参数词（含选项值）：词本身 `expands`/`glob` 且文本以展开或通配符字符开头（`$`、`` ` ``、`*`、`?`、`[`、`{`、`~`，PowerShell 的变量/子表达式）时，除非它是路径操作数，加灰色 `devtool-dynamic-arg`；或更简单：开发工具命令里**任何**非路径角色的、含展开/通配符的词都灰色（`pytest -k "$NAME"` 会多问，见 R-13）。最终还是选项白名单。
- **需要改规格**：§7 的"任何参数以 `@` 开头"改成"任何参数（展开之后）可能以 `@` 开头"。

### R-2 H-4 的修复可以绕过：冒号附着的开关值

- **对应**：H-4。**机制**：`pscmd._elements` 里 `if takes is not False:  # a switch's :$false is not a value`：开关参数的冒号值**整个丢掉**，只在它是复杂表达式时才留下灰色标记（`_convert` 的副作用），简单变量（`$env:X`、`"$env:X"`、`${env:X}`、`$x`）一点痕迹都不留。`_nopath` 与 `_cmdlet` 的 `ps-dynamic-arg` 检查都看不到它。
- **惰性复现**（Windows，PowerShell；下列全部 `allow`，不需要信任）：

```yaml
tests:
  - { tool: PowerShell, platform: [windows], input: { command: 'Out-String -Stream:$env:SECRET_TOKEN' },                expect: gray }
  - { tool: PowerShell, platform: [windows], input: { command: 'ConvertTo-Json -Compress:$env:SECRET_TOKEN' },         expect: gray }
  - { tool: PowerShell, platform: [windows], input: { command: 'Get-Content a.txt -Wait:$env:SECRET_TOKEN' },         expect: gray }
  - { tool: PowerShell, platform: [windows], input: { command: 'Get-Content a.txt -Verbose:$env:SECRET_TOKEN' },      expect: gray }
  - { tool: PowerShell, platform: [windows], input: { command: 'Select-String x a.txt -Quiet:$env:SECRET_TOKEN' },     expect: gray }
  - { tool: PowerShell, platform: [windows], input: { command: 'Sort-Object -Descending:"$env:SECRET_TOKEN"' },        expect: gray }
  - { tool: PowerShell, platform: [windows], input: { command: 'Get-ChildItem -Recurse:${env:SECRET_TOKEN}' },         expect: gray }
  - { tool: PowerShell, platform: [windows], input: { command: 'Set-Location . -PassThru:$env:SECRET_TOKEN' },         expect: gray }
  - { tool: PowerShell, platform: [windows], input: { command: 'Measure-Object -Line:$env:SECRET_TOKEN' },            expect: gray }
```

- **实际观察**：上面每条都是 `allow`（`allow-ps-data-shaping`、`allow-ps-no-path-commands`、`allow-ps-inspect-inside-project`、`allow-ps-list-here`、`allow-cd-family`）。作用于 `Out-String`、`ConvertTo-Json`、`Select-Object -Unique:`、`Sort-Object -Descending:`、`Format-Table -AutoSize:`、`Group-Object -NoElement:`、`Get-Location -Stack:`、`Get-Content` 的 `-Raw -Wait -Force -Verbose -Debug`、`Select-String` 的各开关、`Test-Path -IsValid:`、`Get-Item -Force:`、`Resolve-Path -Relative:`、`Get-ChildItem` 的 `-Recurse -Force -Name -File -Directory -Hidden`、`Set-Location/Push-Location -PassThru:`。对照：空格分隔的 `Out-String -Stream $env:X`、非开关的 `-Depth:$env:X`、`-First:$n` 都是灰色。
- **后果**：PowerShell 把非布尔值绑定到开关参数时会报 `Cannot convert value "<值>" to type "System.Management.Automation.SwitchParameter"` 并回显值（**这一条是我对 PowerShell 行为的已知事实，没有执行验证**——按任务约束不执行被审查的命令）。这是 H-4 的原始危害：环境变量里的密钥进入模型上下文。
- **严重度**：高（修复可以被绕过而回到 H-4；不需要信任、不需要确认）。
- **建议修复**：`pscmd._elements` 在丢弃开关的冒号值时，若值不是 `$true`/`$false`/`$null`/字面 `0`、`1`，加灰色 `ps-switch-value`（或者把它作为 `named` 值保留，让 `_non_constant` 看到）。补语料：每个允许名单上的 cmdlet × `-<开关>:$env:X`。
- **需要改规格**：不需要（实现缺口）；文档 `powershell-dialect.md` 的 4a 条"参数里只要有展开……就是灰色"要在修好后才成立。

### R-3 H-6a 的修复不完整：目录读的子树扫描不查硬链接数

- **对应**：H-6（也是上一轮"一个项目里普通名字的硬链接被 `Grep` 目录读到"的预想风险）。**机制**：`_hard_linked` 只在 `paths._resolve_on_disk`（单个路径）里调用；`normalize/subtree.py` 的 `scan` 只比对**名字**是否命中受保护 glob，没有 `st_nlink`（`grep nlink src/` 只有 `paths.py`）。
- **真实磁盘复现**（`%TEMP%\bk_rr_disk`，假 home；项目 `proj`；`os.link(home\.ssh\id_rsa, proj\notes.txt)`；`os.link(home\.boundkeep\policy.yaml, proj\cfg.yaml)`；`proj\sub\readme.md` 也是指向 `id_rsa` 的硬链接；联接点 `proj\lnk` → `home\.ssh` 作对照）：

| 动作 | 判决 |
|---|---|
| `Read proj\notes.txt` | gray（nlink 检查生效） |
| `Write/Edit proj\cfg.yaml` | gray |
| `Get-Content notes.txt`、`cat notes.txt`、`head/tail/wc/grep … notes.txt` | gray / ask |
| **`Grep pattern=BEGIN path=proj`（含 `output_mode=content`、`glob=*.txt`、不带 path）** | **allow**（`read-inside-project`） |
| **`Grep path=proj\sub`**、**`Glob **/* path=proj`** | **allow** |
| **Bash `grep -rn BEGIN .`、`grep -r BEGIN`、`rg BEGIN`、`rg -n INERT sub`** | **allow**（`allow-read-filters`、`allow-rg-inside-project`） |
| `find . -type f` | allow（只列名字，无泄露） |
| `tar cf x.tar .`、`cp -r . ../x`、`zip -r`、`Copy-Item . -Recurse`、`git grep` | gray（本来就没有 allow 规则） |
| `Read proj\lnk\id_rsa`、`Grep path=proj\lnk` | deny（联接点路径层有效） |

  （联接点存在时 Bash 的 `grep -r` 因 `recursive-scan-link` 变灰；删掉联接点后上表成立。）
- **后果**：硬链接指向 `~/.ssh/id_rsa`（或 `.env`、凭据文件）、名字普通（`notes.txt`）时，`Grep` 目录的 `output_mode=content` 把秘密的匹配行直接返回给模型。创建硬链接在 boundkeep 的白名单写法里 deny（见 R-8 之外的 ~60 种写法），但任何灰色写法（`python -c "os.link(…)"`、`tar x`、`unzip`、`cmd /c mklink` 的相对写法）只是 ask，用户批准一次之后读取就不再有任何提示；`git clone --local`、pnpm、`uv` 的 `.venv`、`cp -al` 备份产生的**存量**硬链接同理。这与上一轮 H-6 的"批准一次 ask，之后读 `id_rsa`"是同一个链，只是读取从 `Read` 换成了 `Grep`。
- **作者声明的核对**：第二份报告写"已经存在的硬链接……经 `Write` 等是 ask，不是 deny"——对单个路径属实，**没有说**目录读，这条是未声明的缺口。
- **严重度**：高（本应被拦的读变成 allow；前提是存在一个硬链接，创建它需要至多一次 ask）。
- **建议修复**：`subtree._walk` 对每个**普通文件**条目取 `st_nlink`（POSIX 上 `DirEntry.stat()` 免费；Windows 上 `DirEntry.stat()` 的 `st_nlink` 恒为 0，要多一次 `os.stat`，注意 30000 条目/0.2 秒的预算——超预算已是灰色，可以接受），`>1` 的文件当作"命中"（让 `Grep`/`rg`/`grep -r` 灰色并说明原因 `hard-linked-in-tree`）。更便宜的收紧：目录读遇到任何 `nlink>1` 的文件都灰色，不判断它是否指向秘密。
- **需要改规格**：§7 的硬链接一段加"目录读同样"。

## 3. 发现：中

### R-4 H-4 的范围：外部程序的选项值里的展开仍把环境变量打印进上下文

- **对应**：H-4。**事实**：用已装的真工具确认回显的是 ruff 与 mypy：`ruff check --select <无效名>` → `Unknown rule selector `<名>``；`mypy --python-version <无效值>` → `Invalid python version '<值>'`。pytest `-k`/`-m`（表达式语法错误时）与 git `-n <非数字>` 等的回显来自我对这些工具的了解，**没有验证**。
- **惰性复现**（受信任项目的开发工具；git 无需信任）：

```yaml
tests:
  - { tool: PowerShell, platform: [windows], input: { command: 'ruff check --select $env:SECRET_TOKEN .' },        expect: gray }
  - { tool: PowerShell, platform: [windows], input: { command: 'mypy --python-version $env:SECRET_TOKEN src' },     expect: gray }
  - { tool: PowerShell, platform: [windows], input: { command: 'git log -n $env:SECRET_TOKEN' },                   expect: gray }
  - { tool: Bash,       platform: [posix],   input: { command: 'ruff check --select "$SECRET_TOKEN" .' },          expect: gray }
  - { tool: Bash,       platform: [posix],   input: { command: 'head -n "$SECRET_TOKEN" f' },                      expect: gray }
```

  全部 `allow`。`git log $env:X`（位置参数）是 ask，选项值不是。
- **评估**：Bash 一侧的"选项值里的展开看不到"是 M1c 已声明的缺口；H-4 的修法只覆盖 PowerShell 的 allow 名单 cmdlet，**没有覆盖 M1c-2 新加的开发工具预设与 `git` 的 PowerShell allow 规则**，而这些在 PowerShell 里同样会把值回显。第一份报告（"H-4 只覆盖 allow 名单上的 cmdlet"）没有掩盖这一点，但标题"H-4 关闭"过强。
- **严重度**：中（同样的危害，但前提是受信任项目，或属于已声明的 M1c 缺口）。
- **建议修复**：与 R-1 合并：开发工具与 `git` 的 allow 规则下，选项值里含展开的词一律灰色。

### R-5 M-1 与"已安装代码"只覆盖 `.venv`、`site-packages`、`node_modules`

- **对应**：M-1（已安装代码）。**惰性复现**（`Write` 与路径限定的调用，两个平台）：

| 路径 | `Write` | 路径限定调用（受信任） |
|---|---|---|
| `.venv/bin/pytest`、`.venv/Scripts/pytest.exe`、`.venv/pyvenv.cfg` | ask（新规则） | — |
| **`venv/bin/pytest`**、`env/bin/pytest`、`.tox/py312/bin/pytest`、`.nox/…/python`、`.conda/bin/pytest`、`.pixi/envs/default/bin/pytest`、`.direnv/…/bin/pytest`、`__pypackages__/…/x.py`、`venv/pyvenv.cfg`、`bin/pytest`、`tools/ruff` | **allow** | **allow**：`venv/bin/pytest -q`、`.\venv\Scripts\pytest.exe -q`、`./venv/bin/python -m pytest`、`bin/pytest -q`、`./pytest -q`、`tools/ruff check .` |

  只有路径里含 `site-packages` 的（`venv/Lib/site-packages/x.py`）会 ask。
- **后果**：上一轮 M-2 写道"`.venv` 的写入 ask 是这条链上唯一便宜的一环"。它确实堵了 `.venv`，但 `Write venv/bin/pytest`（脚本文本）加 `venv/bin/pytest -q` 在受信任项目里仍然没有任何提示——而且任意项目内的 `./pytest` 或 `bin/pytest` 也一样。M-2（写测试文件再 `pytest`）本来就开着，所以**边际风险不大**，但"唯一便宜的一环已做"这个说法不准确。
- **严重度**：中（与 M-2 同类；`trusted_projects` 默认关闭）。
- **建议修复**：glob 加 `**/venv/**`、`**/env/**`（或更精确：`**/{venv,env,.tox,.nox,.pixi,.conda,.direnv,__pypackages__}/**`）；更根本：路径限定的开发工具可执行文件如果在**本会话写过**才灰色（M3a 的污染位）。`ask-installed-package-dirs-write` 的注释里混进了一个制表符（"No \tool: filter"），不影响解析。

### R-6 M-3 的加载器在升级路径上让整份策略失效

- **对应**：M-3（a）。**事实**：`_GUARD_HOME_TREES` 在 `_canonical_trusted_project` 里抛 `ValueError`，整份策略 `PolicyError`。在一次性 `BOUNDKEEP_HOME` 里放一份 `trusted_projects: ['C:\Users\86188\AppData\Local\Foo\proj', 'C:\Users\86188\dev\ok']` 的策略（第二条完全合法）：
  - `boundkeep trust list` → 退出码 1，`invalid policy: trusted_projects[0]: … is too broad: it is a directory of keys, settings or application data`；
  - `boundkeep doctor` → `[FAIL] policy: …`，修复提示是 **"fix … or delete it and run 'boundkeep init'"**（删除策略 = 丢掉所有自定义规则；没有提到 `trust remove`）；
  - `boundkeep explain` → 同样失败；
  - `boundkeep trust remove --project-dir <那一条>` → **成功**（有出路，但没有任何地方告诉用户）；
  - `boundkeep test` 用内置策略，不受影响。
  守护进程：策略无法加载时对所有 PreToolUse 返回 ask（失败即关闭；按 CLAUDE.md 与 `Daemon._refresh_policy` 的设计推断，我没有启动守护进程端到端验证）。
- **评估**：失败是关闭的（不是放行），且 `trusted_projects` 默认空、M1c-2 刚发布，受影响的用户很少；但升级后的第一次守护进程重启就把用户带进"全员 ask"，且提示把人引向删除策略。报告三写了"位于 AppData 下的项目不能再被信任"，没有写这条后果。
- **严重度**：中（可用性，失败即关闭）。
- **建议修复**：加载器对**旧条目**降级：丢弃该条目并记一条警告（`doctor` 红字），其余策略照常加载；`doctor` 的修复提示加 `boundkeep trust remove --project-dir <条目>`；`explain`/`trust list` 对策略错误同样给出这条提示。

### R-7 H-5b：快照在三种情形下"失败即放行"

- **对应**：H-5b。**实现正确的部分**（读代码确认）：`_TrustSnapshots.effective` 在锁内完成"弹出—比较—重新放入"，并发安全；删除立即生效；没有可用 id（非字符串、空、超过 200 字符）一个受信任项目都没有；审计记录的 `session_id` 经过 `AuditLog._bound` 的长度与形状限制；`boundkeep log` 对没有 `tool_name`/`verdict` 的 `trust-changed` 记录不会崩（全部是 `.get`）；`_session_policy` 在非 PreToolUse 事件上也记下会话；`state.policy.trusted_projects` 只有 `_session_policy` 一处读取用于判决（`doctor`、`explain` 读磁盘上的当前策略，只做展示）。
- **会拿到"当前"列表的情形**（都是快照丢失后把会话当成新会话）：(1) 守护进程重启（作者已声明）；(2) 同一会话被 LRU 驱逐（512 个其他会话之后；一个长期运行的会话在多窗口/CI 场景下可能遇到）；(3) 会话的第一个事件到达时策略不可用（`_session_policy` 在 `policy is None` 时直接返回，**不记录会话**；之后策略恢复，快照在那时才取，包含期间新增的条目——与 R-6 的场景相接）。
- **评估**：把这三种情形组合成攻击需要至少两次用户批准（写 `policy.yaml` 的灰色命令，加上杀掉/重启守护进程的 `Stop-Process`/`kill`，两者都是 ask），所以是低到中。作者的"known limit"只写了(1)。
- **严重度**：低。
- **建议修复**：快照落盘（与 `endpoint.json` 同目录、DACL 同），或记录"每个条目第一次被守护进程看到的时间"，条目的出现时间晚于会话第一个事件时才算新增；`policy is None` 时也记录会话（只记 id 与"无条目"）。

### R-8 H-6b：相对路径的 `mklink`/`fsutil` 只是 ask，加上 `--debug=<裸文件名>` 的存量缺口

- **对应**：H-6b。**事实**：`deny-link-*` 规则（`program: [ln, New-Item]`、`[cp]`）加上守护文件的写规则，对**绝对路径**的所有写法都是 deny。相对路径靠 cwd 跟踪：Bash `cd ~/.boundkeep && ln policy.yaml x` deny；PowerShell `Set-Location C:\Users\testuser\.boundkeep; New-Item -ItemType HardLink -Path n -Value policy.yaml` deny。**但**内层命令是文本的写法不走 cwd：

```yaml
tests:
  - { tool: PowerShell, platform: [windows], input: { command: 'Set-Location C:\Users\testuser\.boundkeep; cmd /c mklink /H n policy.yaml' },                       expect: deny }  # 实际 ask
  - { tool: PowerShell, platform: [windows], input: { command: 'cd C:\Users\testuser\.boundkeep; fsutil hardlink create C:\Users\testuser\proj\n policy.yaml' }, expect: deny }  # 实际 ask
  - { tool: Bash,       platform: [posix],   input: { command: 'rsync -a --link-dest=/home/testuser/.boundkeep /home/testuser/.boundkeep/ n/' },                       expect: deny }  # 实际 ask
```

  实际都只是 ask（`ask-guard-state-read`）。`install`、`git clone --local`、`pax -rw`、`robocopy` 对守护目录也是 ask（这些不会创建指向 `policy.yaml` 的硬链接，除了 `rsync --link-dest`）。
- **后果**：用户批准那一次 ask 之后，`n` 是 `policy.yaml` 的硬链接。之后 `Write n`/`Edit n` 因 nlink 检查是 gray（ask），**但**作者已声明的残余——选项值里的裸文件名不被当作路径——让受信任项目里的 `pytest --debug=n` 直接 allow（我在真实磁盘上确认：`pytest --debug=notes.txt`，`notes.txt` 是硬链接，allow；带分隔符的 `--debug=./notes.txt` 是 ask），pytest 以 `w` 打开并截断 `policy.yaml`。
- **严重度**：中（需要一次 ask，且在受信任项目里）。
- **建议修复**：`cmd /c` 与 `fsutil` 的内层文本按跟踪的 cwd 解析相对路径；或在 `deny-link-*` 的 `program` 里加 `link`、`mklink`、`fsutil`、`rsync`（带 `--link-dest`）；`--debug=`、`--junit-xml=` 这类**写路径**角色的选项值不论有无分隔符都当路径（这是选项白名单的一部分）。

## 4. 发现：低

- **R-9 `deny-link-` 前缀会让用户自己的规则悄悄失去子树保护**（H-6b）。`protected_read_globs` 用 `rule.id.startswith("deny-link-")` 排除规则。真实磁盘实验：用户规则 `deny-vault-read`（`path_glob: ["**/vault/**"]`、`access: read`、deny）对 `Grep path=proj` deny；同一条规则改名 `deny-link-vault-read`，`Grep path=proj` 变成 **allow**（直接 `Read vault/k.txt` 仍 deny）。建议：用显式的规则属性标记，或加载器拒绝用户规则使用这个前缀。`.boundkeep/**` 仍在 `ask-guard-state-read` 里，没有被排除（确认）。
- **R-10 `nested_repositories` 会跟随 Windows 联接点**（M-3b）。报告三与代码注释写"never through a link"。实测（Python 3.12，`DirEntry.is_dir(follow_symlinks=False)` 对联接点返回 `True`，`is_junction()` 为 `True`）：`root\a\jct` → `outside`，`nested_repositories(root)` 返回了 `a\jct\repo`（联接点另一头的仓库）。只是提示用的辅助函数，但声明不准确，且会在联接点指向大目录时多耗时（仍受 5000 条目上限）。建议：`is_dir(follow_symlinks=False) and not entry.is_junction()`。5000 条目上限没有挂钟时间上限；慢盘/映射盘上最坏情形是 5000 次 `scandir` 的往返（交互式命令，可接受）。
- **R-11 pytest 自己的 `-W error::pkg.Cls` 仍是 allow**（L-1）。`python -W` 的点类别已不再是开发工具调用，但 pytest 的 `-W` 同样会导入 `pkg`（上一轮 M-2 已记录这条）；`pytest -W error::evil.Cls` 仍 allow。与 M-2 同类（写测试文件同样能执行代码），所以只是不一致。
- **R-12 白名单里的变量，值不受限**（H-3）。`LC_ALL=/home/x`、`LANG=../../x`、`TZ=:/home/testuser/.ssh/id_rsa` 都是 allow。glibc 对 `LC_*` 里的绝对路径会从该目录加载二进制 locale 数据（我没有验证这条，也不确定能否被利用）；`TZ=:路径` 只读该文件。建议：白名单变量的值要求匹配 `[A-Za-z0-9_.@-]*`。
- **R-13 可用性**（H-4、L-1）：新增的灰色会让下列**合法**命令多问：`Select-String -Pattern $pattern src\app.py`、`Get-Content a.txt -Tail $n`、`pytest -k "a:b"`/`-m "a:b"`（单字母加冒号当盘符相对路径，已声明）。量化见第 7 节：204 条日常命令里变化 5 条（2 条是上述合法命令，3 条是 `.venv`/`node_modules` 写入变 ask）。同时既有的灰色在这条语料里仍最常见：`pytest --cov-report=term-missing`（`--cov-report` 在 `flags_none`）、`pytest -p no:cacheprovider`、`PYTHONPATH=src pytest`、`pytest --junitxml=report.xml`、`pytest --pdb`。
- **R-14 `_GUARD_HOME_TREES` 的清单**（M-3a）没有 `.azure`、`.password-store`、`.local`、`.cache`、`.mozilla`、`.vscode`、`.terraform.d`、`.cargo`、`.npm`、`Library`（macOS）。POSIX 上 `.SSH`（大小写）会被一并拒绝（案例折叠，对大小写敏感的文件系统是误拒，无害）。
- **R-15 文档与规格需要同步**：PROJECT_SPEC.md §7 与 `docs/powershell-dialect.md` 的 4a 条现在写的是"任何参数以 `@` 开头""参数里只要有展开就是灰色"，R-1、R-2 修好之前这两句不成立；`nested_repositories` 的"不跟随链接"见 R-10。

## 5. 三份修复报告的声明核对

属实 = 我独立复现；不准确 = 部分成立或表述过强；无法验证 = 未重跑或没有条件。

**报告一（H-1 到 H-4）**

| 声明 | 判定 |
|---|---|
| 附录 A 的 17 条现在都是 gray（15 条 + 第三份报告补的 2 条） | 属实（逐条重跑，全部 gray） |
| H-1：七个工具、两种方言，任何词以 `@` 开头就灰色（含 `--` 之后、选项值、引号内外） | 属实**对字面 `@`**；对展开/通配符产生的 `@` 不准确（R-1） |
| H-2：只认内置报告器名；唯一缩写、`-f`、重复、空值、大小写、逗号分隔 | 属实（~35 种写法验证）；pylint 本身未验证 |
| H-3：白名单；`FOO=1 pytest` 灰色 | 属实（~60 种来源与变体验证）；R-12 是白名单值的问题 |
| H-4：allow 名单上的 cmdlet 的非路径展开一律 `ps-dynamic-arg` | **不准确**：冒号附着的开关值漏过（R-2）；外部程序的选项值不在范围内（R-4） |
| `_nopath` 与 `_cmdlet` 里 `Select-String`、`Get-Content` 等读类 cmdlet 的"路径位置展开交给路径层" | 属实；没有被滥用（`-Stream`、`-ReadCount`、`-Delimiter`、`-Tail`、`-Filter`、`-Include` 的展开都灰色；`Get-ChildItem . $env:X` 灰色） |
| `measure_ask_rate` Windows 54.2、POSIX 53.3 与修复前一致 | 属实（重跑：54.2 / 53.3；`--trusted` 48.0 / 47.4；与设计目标有差异的条目 0） |
| default 775 / strict 280 次运行 0 失败（后来 795 / 300） | 属实（重跑：default 795、strict 300，0 失败；规则数 72） |
| 708 个新用例、111 条语料、完整套件数字 | 无法验证（按任务约束没有重跑） |
| 改过的旧期望只有 4 个单元测试 | 属实且合理（见第 6 节）；它们的更严期望正确 |

**报告二（H-5、H-6）**

| 声明 | 判定 |
|---|---|
| `trust add` 在 `CLAUDECODE`/`CLAUDE_CODE_ENTRYPOINT` 存在时拒绝，`remove`/`list` 不受影响 | 属实（读代码；`cmd_add` 第一条检查，早于 tty 检查与任何写入）。本会话的 agent shell 里两个变量确实存在（`CLAUDECODE=1`，入口 `claude-desktop`）。用户自己在 Claude 桌面应用的"终端面板"或 VS Code 扩展里开的终端是否带这两个变量**无法验证**（只能推理：它们是启动 `claude` 子进程时设置的，不一定被用户的终端继承） |
| 终端检查与环境变量检查不是边界 | 属实（文档措辞已改） |
| 快照：会话首个事件时的条目、新增对本会话不生效、删除立即生效、无 id 则无受信任项目、新增记审计 | 属实（读代码）；"快照在内存里"只是三种丢失情形中的一种（R-7） |
| H-6a：`st_nlink>1` 的路径对 allow 不确定，`Write`/`Edit`/`Read` 经硬链接由 allow 变 gray | 属实对**单个路径**（真实磁盘确认，含大写、正斜杠、`\\?\`、尾点、`::$DATA`、`..`、MSYS 路径、相对路径、联接点下的硬链接）；**对目录读不成立**（R-3） |
| 已存在的硬链接"经 `Write` 等是 ask" | 不准确（漏了 `Grep`/`Glob`/`rg`/`grep -r`，R-3） |
| H-6b：31 条链接到守护文件的写法 × 两平台 × 两策略全部 deny；`ln`/`New-Item` 的目标是读路径，源/目的角色没有搞反 | 属实对绝对路径（我另验证了 ~60 种，含 `-t`/`-T`/`-s`/`-f`/`-sf`/别名 `ni`/`-Type`/`-it`/冒号形式/`Hard Link`/`link`/`mklink`/`fsutil`/`cmd /c`/`powershell -c`/`Start-Process cmd`）；相对路径的 `cmd /c mklink`、`fsutil`、`rsync --link-dest` 是 ask（R-8） |
| 规则 id 以 `deny-link-` 开头的 deny 读规则不进 `protected_read_globs` | 属实，但副作用见 R-9；`.boundkeep/**` 仍在 `ask-guard-state-read` 里 |
| 运行时孪生规则（`CLAUDE_CONFIG_DIR`、已安装代码）存在、幂等 | 属实（设 `CLAUDE_CONFIG_DIR` 后规则数 72 → 80，二次调用结果相等，`New-Item -ItemType HardLink … cfg\settings.json` deny） |
| 去掉两条链接规则的 `tool:` 过滤（读类 deny/ask 规则不按 `tool:` 过滤的不变量） | 属实（`program` 限定） |
| 改过的旧期望：`+2` → `+4` | 属实且合理 |
| 完整重跑 22924 通过 | 无法验证 |

**报告三（M-1、M-3、L-1）**

| 声明 | 判定 |
|---|---|
| `pytest.toml`、`.pytest.toml`、`.pdbrc` 加进写保护；同一行检测也认这两个名字 | 属实（`Write .pdbrc` 等 ask；`boundkeep test` 的新用例通过） |
| 新规则 `ask-installed-package-dirs-write`：`.venv`、`site-packages`、`node_modules` 要问 | 属实，但覆盖不全（R-5）；"这条链上唯一便宜的一环"过强 |
| M-3a：主目录里的 `.ssh` 等及其下一切不能作为条目 | 属实；**未提**对已有策略的后果（R-6） |
| M-3b：`trust add` 在目录下面（三层、最多 5000 个条目、不进 `.git`/`node_modules`/`.venv`、**不跟随链接**）发现别的仓库要 `yes` | 部分不准确：联接点被跟随（R-10）；`_confirm` 只认 `yes`、无 tty 时先拒绝；提示文本里的名字经 `printable_entry` 清洗 |
| L-1：`-X` 只认列表里的值；`-W` 带点类别不再是开发工具调用；`-X`/`-W` 重复与连写 | 属实（对 `python -X/-W`；见 R-11 对 pytest 自己的 `-W`）。`-X importtime`/`faulthandler`/`perf` 等在列表里无写文件的副作用（`-X perf` 在 `/tmp` 写一个以 pid 命名的 map 文件，路径不受控）；`importtime=2` 被拒，无害 |
| 盘符相对路径灰色：`--debug=C:x`、`-oD:x`、`C:file.py` | 属实；`--cov-report=xml:cov.xml`、`--tb=short`、`--rootdir=C:\x` 不误报；`-k "a:b"`、`-m "a:b"` 误报（已声明） |
| 改过的旧期望：7 条语料 + 8 条（两个文件）从 gray 变 ask；`test_session_command_stats` 改用假 home；配置名清单加三项 | 属实；全部变严或前提调整，**没有放宽**（逐条读了 diff） |
| M-2 推迟；`trusted_projects` 保持默认关闭 | 属实（默认策略里没有 `trusted_projects`）。R-1、R-3 修好之前这个"默认关闭"仍是唯一的真正闸门 |
| 完整套件 23492 通过 | 无法验证 |

## 6. 回归与副作用

- **语料与度量**：`scripts/measure_ask_rate.py` 与报告一致（54.2 / 53.3；受信任 48.0 / 47.4）。`boundkeep test --platform all`：default 795、strict 300，0 失败。
- **自己构造的日常命令**：204 条（PowerShell 约 100，Bash 约 104；覆盖 `Select-Object`/`Sort-Object`/`Where-Object`/`Group-Object`/`Format-Table`/`ConvertTo-Json`/`Get-Content -Tail|-TotalCount|-Raw|-Wait`/`Get-ChildItem -Filter|-Recurse|-Name`/`Select-String`/`Test-Path`/`Set-Location`/`git`/`pytest -k|-m|-x|--co|--lf|-n|--cov`/`pylint --output-format=json|colorized`/`-f json`/`CI=1 pytest`/`FORCE_COLOR`/`NO_COLOR`/`LC_ALL`/`python -X dev|utf8|importtime -m pytest`/`python -W error`/`ruff check --fix .`/`ruff format`/`mypy --strict`/`black`/`isort`/`flake8`/`pylint`/`.venv` 与 `venv` 的路径限定调用/管道）。修复前（`m1c4-done` 的代码与策略，导出到临时目录）与修复后，受信任与不受信任两种下，**变化相同的 5 条**：
  - allow → gray：`Select-String -Pattern $pattern src\app.py`、`Get-Content a.txt -Tail $n`（合法命令被新增灰色，预期之内）；
  - allow → ask：Bash `touch .venv/x`；
  - gray → ask：`rm -rf node_modules`、`python -m venv .venv`（仍然会被询问，只是原因变成规则）。
  `allow` 总数：受信任 177 → 174，不受信任 72 → 69。`uv sync`、`pip install -e .`、`npm install`、`git status`、`ruff check .`、`pytest -k …`、`CI=1 pytest`、`python -X dev -m pytest`、`pylint --output-format=json` 判决不变。
- **上一轮附录 A 的 17 条**：全部 gray（逐条重跑，包括 `python -X pycache_prefix=…`、`pytest --debug=C:x`）。
- **硬链接的误报面**：本仓库自己的 `.venv`（3796 个文件）`st_nlink>1` 的数量是 0（缓存与 `.venv` 在不同盘，`uv` 用复制）；缓存与 `.venv` 在同一个卷时 `uv`/pnpm 的链接文件会让读写多问一次，这在第二份报告里已声明，我没有造这个环境去量化。

## 7. 尝试过但没有成功的攻击

- **H-1 的字面 `@`**：引号（`"@a"`、`'@'a`、`''@a`）、反斜杠、`$'@a'`、`$'\x40a'`、`$'\100a'`、`$'\u0040a'`、`--` 之后、`--%`、PowerShell 反引号转义 `` `@a ``、here-string；连写短选项 `-k@a`、`-p@a`（argparse 不展开，非绕过）；`pytest -k @a.txt` 在 PowerShell 是解析错误；PowerShell 冒号附着的值 `-k:'@a.txt'`、`--select='@a.txt'`（是一个参数 `-k:@a.txt`，不是参数文件）；`$(…)`、反引号命令替换、花括号展开、数组 splat、`(…)`、`@(…)`（都灰色）。
- **H-2**：见第 0 节；`--output-format:json:x`（PowerShell 冒号形式）是 allow，但 pylint 会把它当成未知选项报错，不构成绕过。
- **H-3**：`export X=…;`、`declare -x`、`typeset -x`、`set -a`、`read X <<<`、`(export …)`、`{ …; }`、`env X=… tool`、`env -S`、`command`/`time`/`builtin` 前缀、`cd dir && X=1 tool`、`X=1 python -m pytest`、`X=1 ./.venv/bin/ruff`、`\X=1 …`、`"X"=1 …`；PowerShell `$env:X='…'; tool`、`& { $env:X=…; tool }`、`Set-Item Env:`、`[Environment]::SetEnvironmentVariable`、`cmd /c "set X=… && tool"`——全部灰色。`Path=`、`path=`、`pYtHoNpAtH=`、`ruff_output_file=` 大小写变体灰色。
- **H-6 单个路径的写法**：见第 5 节；`Get-Content (Resolve-Path notes.txt)` 等动态写法是 ask/gray。
- **链接创建**：~60 种 `ln`/`cp -l`/`New-Item`/`mklink`/`fsutil`/`robocopy`/`link`/`wsl ln` 对 `~/.ssh/id_rsa`、`~/.boundkeep/policy.yaml`、`~/.claude/settings.json` 的绝对路径写法全部 deny；`python -c "os.link(…)"`、`perl -e link`、`tar x`、`unzip`、`Add-Type CreateHardLink`、`[IO.File]::Copy` 是灰色（会被询问）。
- **`deny-link-` 运行时孪生规则**：重复调用幂等，没有被去重逻辑丢掉。
- **`trust add`**：没有运行；`remove` 只能删除条目，不能把别人的条目改写成别的东西（读代码）。

## 8. 没有覆盖的范围

- **pylint、black、isort、flake8 没装**：H-2 与第 3 节里这四个工具的选项表只来自文档与记忆；`DEVTOOL_RISKY_FLAGS` 对它们的完整性没有对照真实 `--help`。pytest、ruff、mypy 我对照了已装版本的 `--help`（`--junit-xml` 在 pytest 9.1.1 里是另一个拼写，已在 `flags_none` 里）。mypy 的 `--linecoverage-report`、`--memory-xml-report`、`--imprecision-report` 不在 `flags_none` 也不在选项表里（值是路径时由路径层处理，裸目录名不会）。
- **R-2 的 PowerShell 报错行为**是已知事实，没有执行验证；**R-6 的守护进程端到端**（策略无法加载 → 全员 ask）是读代码推断，没有启动守护进程。
- **8.3 短名字**：本机该卷对文件名没有生成短名字（`GetShortPathName` 返回长名），所以 H-6 的短名字路径没有测到。
- **符号链接**（本账号无权限）：联接点与硬链接代替；**pwsh 7**、**真 bash**、**Linux/macOS**、**Docker**：没有。
- **真实 Claude Code 的行为**：Bash/PowerShell 工具里的环境变量是否跨调用保留、`session_id` 在 `--resume`/`claude -p`/子 agent 下是否变化、`CLAUDECODE` 是否会进入用户自己打开的终端——只能推理，未验证。
- **GetFileInformationByHandle 以外的硬链接来源**（ADS、压缩、OneDrive 占位符、WinSxS）：没有实测。
- 没有重跑完整套件（按任务说明）；没有跑 `ruff`、`mypy`。

## 9. 结论

- **H-1 到 H-6 是否真的关闭：没有。** H-1（R-1）、H-4（R-2）、H-6（R-3）可以被绕过，回到上一轮的高危状态；H-2、H-3 关闭；H-5a 按其声明关闭；H-5b 基本关闭（R-7）。
- **高危是否清零：否，3 条。**
- **能否冻结规则进入 M2：不能。** 三条高危的修法都在归一化层或子树扫描里，冻结前改动；它们不改规则文件（R-5 需要改 glob）。建议的顺序：
  1. **R-1**：开发工具命令里"含展开/通配符的词"的统一处理（和 R-4 一起做），补语料（每个工具 × `${u}@x`/`$u@x`/`?x`/`[@]x` × 两种方言 × 选项值与位置）；
  2. **R-2**：`pscmd` 保留开关冒号值，非常量时灰色，补语料（允许名单上每个 cmdlet × 每个开关 × `-X:$env:V`）；
  3. **R-3**：`subtree._walk` 查 `st_nlink`（预算内），补真实磁盘测试（`os.link`，`tmp_path`）；
  4. R-5 的 glob 与 R-6 的加载器降级（升级路径）；R-8 的相对路径；
  5. 选项白名单（L-1 的长期方案）仍会改规则，要么在 M2 基线之前做，要么做完重取基线——R-1、R-4、R-8 的根本解法都是它；
  6. 修完之后再做一轮只针对这三条的定向复审（我可以直接复用本轮的 `tests:` 片段），再冻结。
- 在这些修好之前，`trusted_projects` 保持默认关闭是唯一可靠的闸门；R-2 与 R-3 **不需要**这个设置就能触发（R-2 只需要 PowerShell，R-3 只需要一个已存在的硬链接）。
