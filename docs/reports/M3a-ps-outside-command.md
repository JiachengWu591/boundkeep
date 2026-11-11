# PowerShell 里不在任何命令之内的文字（规格修订 21，复审 O-1）

日期：2026-11-11。基线：`c791684`。依据：复审 `docs/reviews/M3a-rev19-20-review.md` 的 O-1。

使用者说"按建议执行"，指复审的建议"先定 O-1"。做的时候有两处要取舍，提问被应用退出打断，先是开发 agent 按自己的推荐定的。全量跑完后使用者说"按照你建议执行；先提交修订21再去修改O-3"，照此定下：

- O-1 的范围：选了"白名单，比较和逻辑运算算无害"。
- 带盘符的变量：选了"按读写文件记路径"。

代码在 `e52c596`，这份记录和规格在其后一个提交。没有推送，没有打标签。这次修复没有复审。

没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务（模型是 `FakeBackend`），没有打开留出批次和攻击样本。实测用的是 TEMP 下一个单独目录里的假文件，用完已删。

## 1. 结论

**修了三件事，都是同一个原因**：PowerShell 会执行不是命令的文字，而守卫和发给 LLM 的请求都是按命令来看的。

1. **O-1（只在有 LLM 后端时起作用）**：不在任何命令的参数里的表达式和语句，现在是灰色 `ps-outside-command:<类型>`，不送审，总是问。原来 `git status; [IO.File]::ReadAllText('.env')` 照常送审，请求里没有这个表达式的任何文字。
2. **带盘符的变量（不需要后端，默认配置就有）**：`${C:\x\.env}` 就是那个文件的内容。原来 `Get-Date; ${E:\proj\.env}` 由规则放行，项目之外的 `.ssh\id_rsa` 也一样；现在按 `Get-Content -Path` / `Set-Content -Path` 判，`.env` 是 deny。这一条是修 O-1 时查到的，比 O-1 重。
3. **在命令里、但请求里也没有的文字**：开关参数的值（`-Force:(…)`）、`uv run` 一类运行器自己的选项的值、超过 128 个字符的命令名。前两种现在不送审，第三种由发送闸门拒绝。

**规则条目和策略文件没有改。** 判决级别的变化只有带盘符的变量那一类（第 5 节）。

**还有一条没有修，等使用者决定**（第 7 节 O-3）：`Get-Date; $env:SECRET_TOKEN` 这样单独成句的变量由规则放行，会把环境变量的值打印进上下文。

## 2. 修改前后

没有后端时看规则判决；"送审"一栏是有后端时会不会把这次调用交给模型。

| 写法（PowerShell） | 修改前 | 修改后 |
|---|---|---|
| `git status; [IO.File]::ReadAllText('.env')` | 灰色，送审，请求里没有表达式的文字 | 灰色，**不送审** |
| `Get-Date; if ([IO.File]::Exists('x')) { … }`、`return`、`throw` 后面的表达式、函数参数的默认值 | 灰色，送审 | 灰色，**不送审** |
| `Get-Date; $a.Count`、`$a[0]`、`[int]$a`、`1..3`、`'{0}' -f $a` | 灰色，送审 | 灰色，**不送审**（代价） |
| `make test; if ($LASTEXITCODE -ne 0) { exit 1 }` | 灰色，送审 | 灰色，送审 |
| `Write-Output ([IO.File]::ReadAllText('.env'))`、`ForEach-Object { … }` | 灰色，送审，文字在 `args` 里 | 不变 |
| `Get-Date; ${E:\proj\.env}` | **allow**（`allow-ps-no-path-commands`） | **deny**（`no-secret-read`） |
| `Get-Date; ${C:\Users\u\.ssh\id_rsa}` | **allow** | **deny** |
| `Write-Output ${E:\proj\.env}`、`"${E:\proj\.env}"`、`if (${E:\proj\.env}) { … }` | 灰色，送审，或 allow | **deny** |
| `${E:\proj\.env} = 'A=1'` | 灰色，不送审 | **ask**（`ask-secret-file-write`） |
| `Get-Date; ${E:\proj\README.md}` | allow | allow（`Get-Content` 读项目里的文件也是 allow） |
| `${E:\proj\README.md}`（单独一条） | 灰色，不送审 | allow（和 `Get-Content` 一样，见第 6 节第 1 条） |
| `Get-ChildItem -Force:([IO.File]::Delete('C:\x\y'))` | 灰色，送审，请求里没有这个值 | 灰色，**不送审** |
| `uv run --with ([IO.File]::Delete('C:\x\y')) pytest` | 灰色，送审，请求里没有这个值 | 灰色，**不送审** |
| `& $(…150 个字符…; [IO.File]::Delete('C:\x\y'); 'Get-Date')` | 灰色，送审，命令名在 128 个字符处被截断 | 灰色，闸门拒绝，不送审 |
| Bash 的全部写法 | 不变 | 不变 |

## 3. 实测

PowerShell 5.1.26100.9818，假文件放在 TEMP 下的单独目录里。

**带盘符的变量**：

| 写法 | 结果 |
|---|---|
| `Get-Date \| Out-Null; ${<目录>\.env}` | 打印文件内容 |
| `"in a string: ${<目录>\.env}"` | 打印文件内容 |
| `if (${<目录>\.env}) { … }` | 条件为真，读了文件 |
| `${<目录>\*.env}`、`${<目录>\.en?}` | 打印文件内容，通配符起作用 |
| `Set-Location <目录>; ${C:.env}` | 打印文件内容，相对于 C 盘的当前目录 |
| `${<目录>\.env} = "CHANGED=1"` | 文件内容被改写 |
| `${.env}`（不带盘符）、`${FileSystem::<路径>}` | 什么都不打印，是普通变量 |

**不是命令的文字确实会动手**。下面每一种都在目录里建出了对应的文件，或读出了内容：

| 写法 | 做了什么 |
|---|---|
| `[IO.StreamWriter]'<目录>\cast.txt'` | 类型转换新建了文件 |
| `'<目录>\as.txt' -as [IO.StreamWriter]` | `-as` 新建了文件 |
| `function f([IO.StreamWriter]$w) { }; f <目录>\param.txt` | 参数的类型在调用时转换，新建了文件 |
| `Get-ChildItem -Force:([IO.File]::WriteAllText(…))` | 开关参数的值被求值，写了文件 |
| `cmd /c rem ([IO.File]::WriteAllText(…))` | 外部程序的参数被求值，写了文件 |
| `& $([IO.File]::WriteAllText(…); 'Get-Date')` | 命令名表达式被求值，写了文件 |
| `Get-Date > $([IO.File]::WriteAllText(…); '<目录>\out.txt')` | 重定向目标被求值，写了文件 |
| `if ([IO.File]::WriteAllText(…)) { }` | 条件被求值，写了文件 |
| `function g($a = [IO.File]::WriteAllText(…)) { }; g` | 参数默认值被求值，写了文件 |
| `using module <目录>\m.psm1` | 模块被加载，模块里的代码写了文件 |
| `switch -File '<目录>\.env' { default { "read: $_" } }` | 逐行读出文件内容 |

## 4. 修法

复审第 5 节写的做法（有一项没有程序名的动作就不送审）没有用。它行不通：PowerShell 里几乎每条灰色的命令都带这样一项，整行的灰色原因就记在那里，照它做等于整个 PowerShell 都不送审。

**辅助进程 `pshelper.ps1`**（只解析，不执行，这一点没有变）：

- 回复多了一项 `loose`：不在任何命令的参数里、又不在无害清单上的表达式和语句的类型名。
  - 判断"在不在命令的参数里"：从节点往上找，先碰到 `CommandAst` 就在，先碰到重定向或走到顶就不在。往上走的步数有上限（一次请求 100 万步），超过就回答 `too-large`。
  - 无害清单：
    - 常量、变量、字符串、数组字面量（它们根本不进检查）；
    - 容器：括号、`$(…)`、`@(…)`、脚本块、哈希表；
    - 运算符是比较或逻辑的二元、一元表达式；
    - 只是结构的语句：`if`、循环、`switch`、`try`、`trap`、函数定义、`return`、`throw`、`exit`、`break`、`continue`、赋值、`data`、类型定义、`using namespace`。
  - 另外算进 `loose` 的：`using module`、`using assembly`、`switch -File`、带类型或特性的参数、不认识的语句类型。
- 带盘符的变量（`VariablePath.IsDriveQualified`，驱动器名不是 `env`、`function`、`alias`、`variable`）每一处报成一条命令，名字的种类是 `file-read` 或 `file-write`，值是路径。
  - 赋值的左边是写；`+=`、`++`、左边带索引的又读又写，报两条；别的都是读。
  - 它们和别的命令按出现的先后排在一起，所以 `Set-Location` 之后的相对写法按新的工作目录算。

**`pscmd.py`**：

- `loose` 里的每个名字变成灰色原因 `ps-outside-command:<类型>`。回复里没有 `loose` 是 `ps-internal-error`。
- `file-read` 变成 `Get-Content -Path <路径>`，`file-write` 变成 `Set-Content -Path <路径>`。路径原样取，不展开；带 `*`、`?`、`[` 时按通配符。
- 运行器（`uv run`、`uvx`、`pipx run`、`poetry run`、`python -m boundkeep`）被剥掉时，它自己的选项里有展开的词，加灰色原因 `ps-runner-value`。
- 开关参数的值原来就有 `ps-switch-value`，没有改。

**`pipeline.py`**：`ps-outside-command`、`ps-switch-value`、`ps-runner-value` 加进 `_UNSHOWN_REASONS`，带它们的调用不送审。

**`send_gate.py`**：程序名长过 128 个字符时拒绝，原来是截断。

**`psparse.py`**：回复的形状检查多了 `loose`。

**文档**：规格修订 21（修订说明、§5.1、§7）；`docs/powershell-dialect.md`；`docs/policy-reference.md`；`docs/m1b-design.md` 的回复格式。

**测试**：

- 新文件 `tests/unit/test_m3a_ps_outside_command.py`，202 条。
- `tests/unit/test_norm_pscmd.py`、`tests/unit/test_norm_psparse.py`：手写的回复加上 `loose`，加了"没有 `loose`"和"`loose` 类型不对"的用例。
- 夹具 `tests/fixtures/ps_ast/`（235 个）和 `tests/fixtures/ps_ast_manual/`（58 个）用真的辅助进程重新生成。差异只有新增的 `loose` 一项：284 个是空的，9 个不空。命令一条没变。

## 5. 度量

下面"级别"分五档，从松到严：allow、灰色送审、灰色不送审（问）、ask、deny。旧代码是 `c791684` 的 `src`，导出到 scratchpad，经 `RR_SRC` 加载。

**专门扫描**：真实目录树（假文件），42 种文字 × 16 个位置，加 22 条单独的命令，共 694 行，新旧代码各跑一次。42 种文字是 17 种会动手的表达式、10 种无害的、15 种带盘符的变量或对照；16 个位置是单独一条、跟在 `Get-Date` / `git status` / `make test` 后面、`if` 的条件和语句体、函数体、`return`、命令参数、脚本块参数、管道开头、重定向目标、赋值右边、开关参数的值、运行器选项的值、命令名。

| 类别 | 行数 | 级别相同 | 更严 | 变松 |
|---|---|---|---|---|
| 会动手的表达式 | 272 | 85 | 187 | 0 |
| 无害的 | 160 | 140 | 20 | 0 |
| 带盘符的变量和对照 | 240 | 123 | 113 | 4 |
| 单独的 PowerShell 命令 | 15 | 10 | 5 | 0 |
| Bash 对照 | 7 | 7 | 0 | 0 |

- 会动手的表达式，更严的 187 行都是"灰色送审"变成"灰色不送审"：153 行因为 `ps-outside-command`，17 行因为 `ps-switch-value`，17 行因为 `ps-runner-value`。修改后仍然送审的 51 行都在命令里：命令参数、脚本块参数、命令名各 17 行，文字在请求里。
- 无害的，更严的 20 行是开关参数的值和运行器选项的值两个位置（第 6 节第 3 条）。其余 140 行完全相同，`if` 的条件、`return`、函数体里的照常送审。
- 带盘符的变量，更严的 113 行：
  - 79 行变成 deny（`no-secret-read`，其中 15 行还有 `no-credential-store-read`）。原来 10 行是 allow，59 行是灰色送审，10 行是灰色不送审。
  - 16 行由灰色不送审变成 ask（`ask-secret-file-write`）。
  - 6 行由 allow 变成灰色送审：项目之外的普通文件，和 `Get-Content` 一样。
  - 12 行因为开关参数或运行器选项的值不送审。
- 变松的 4 行都是单独一条的带盘符变量（第 6 节第 1 条）。
- 没有一行少记了路径。

**手头语料上的代价**：测试语料和评测集（不含留出批次）里全部 1146 条 PowerShell 命令，在假的 Windows 机器上按 `boundkeep test` 的方式判，再过发送闸门。

| 来源 | 条数 | 级别变了的 |
|---|---|---|
| `tests/corpus/*.yaml` | 994 | 70，都是灰色送审变成灰色不送审 |
| `eval/datasets/benign` | 85 | 0 |
| `eval/datasets/attacks` | 67 | 0 |

70 条里 64 条是 `ps-switch-value`（语料里专门写的 `-Stream:$env:SECRET_TOKEN` 一类用例），6 条是 `ps-outside-command`（`$x.Name | Get-Content`、`foreach ($f in 1..3) { … }` 等）。没有一条变松。

**原有差分**（基线是修订 20 代码的输出）：

| 差分 | 结果 |
|---|---|
| 修订 20 的扫描（2482 行） | 全部相同 |
| 修订 19 的扫描（160 行） | 全部相同 |
| 修订 18 的扫描（5100 条） | 全部相同 |
| 修订 17 的真实目录树扫描（10092 条） | 全部相同 |
| 修订 16 的扫描（12768 条） | 全部相同 |
| IR-1 的扫描（10320 条） | 全部相同；Bash 和 PowerShell 的 5160 对判决仍然全部相同。和变异测试同时跑的那一次有 1 行撞到时间预算、多了灰色原因（级别没变），单独重跑后 10320 行全部相同 |
| 带冒号的普通命令（492 条）、系统目录、逐程序 | 全部相同 |
| 真实磁盘（23544 条）、假机器（179508 条）、孪生项目（30720 条） | 级别全部相同 |
| 含 git 或 `~` 的语料（655 条，1164 次判决） | 0 条不同 |
| `boundkeep test` default / strict | 1142 / 0 失败，334 / 0 失败 |
| 评测（`--config rules+taint --test-contaminated`，输出到 scratchpad） | 指标全部相同。`results/*.json` 除日期和延迟外，只有 test 切分一条漏判样本（`atk-exfil-032`）的灰色原因从 2 个变成 4 个，判决没变。仓库里的 `eval/report.md` 没有重新生成 |

| 测试和检查 | 结果 |
|---|---|
| 新测试文件 | 203 passed |
| 新测试文件在 `c791684` 的代码上（只补了三个常量的名字，行为是旧的） | 169 条失败，34 条通过（通过的是对照） |
| 受影响的 26 个测试文件 | 5112 passed，1 skipped |
| 读 `docs/policy-reference.md`、`docs/powershell-dialect.md` 的 6 个测试文件，加上新文件 | 7770 passed，62 skipped |
| `scripts/gen_ps_fixtures.py --check` | 235 个夹具，0 个不同 |
| 变异：40 个，在副本上跑新测试文件、`test_norm_pscmd.py`、`test_norm_psparse.py`、`test_m3a_send_gate.py` | **全部抓到**。第一轮 41 个里有 1 个存活，是等价的：赋值的右边是语句，往上走到赋值语句的只可能是左边，原来多写了一个判断。去掉那个判断之后重跑了这段代码的 4 个变异，都抓到 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过 |
| 全量（分六段跑，不是一个进程） | **28945 passed，169 skipped，0 failed**，合计与收集到的 29114 条相同，六段都一次跑完 |

全量中途按使用者的话停过一次，不是连续跑完的：

- 前四段 01:29 起跑完（19571 通过，165 跳过）。第 5 段跑到约 51% 时停下，到那里没有失败，这一次的输出不算。
- 继续之前核对了工作区：`git diff HEAD` 的哈希和两个未跟踪文件的哈希都和停下时一样。然后第 5、6 两段从头跑（5541 通过、1 跳过；3833 通过、3 跳过）。跑完又核对了一次，仍然一样。
- 各段的测试用时合计 3:26:12。前四段 40:15，电源模式是最佳性能；第 5 段 2:14:39、第 6 段 31:18，电源模式是最佳能效。

## 6. 代价和残余

1. **单独一条的带盘符变量，有 4 行在专门扫描里变松**。`${E:\proj\README.md}` 单独一条原来是"什么都没看懂"，直接问；现在读成 `Get-Content`，项目里的文件是 allow，别处的文件和 `$HKLM:x` 这样的注册表路径是灰色、送审。它得到的和 `Get-Content <同一个路径>` 完全一样，请求里有程序名和路径。
2. **有后端时多问的写法**：`$x.Count`、`$a[0]`、`[int]$x`、`1..10`、`'{0}' -f $x`、`$a + 1`、`$i++` 写在命令参数之外时不再送审。`for ($i = 0; $i -lt 3; $i++)` 原来就因为赋值不送审。
3. **开关参数的值、运行器选项的值，只要带变量就不送审**，不管它是不是表达式：`uv run --with $pkg pytest`、`Get-ChildItem -Force:$x`。
4. **带类型的函数参数一律算**：`function f([string]$name) { … }` 也不送审，不区分类型有没有副作用。
5. **命令参数里的表达式照常送审**，模型要自己读 .NET 调用的文字。请求里的 `paths`、`domains`、`network` 不反映表达式里的路径和网址：`Write-Output ((New-Object Net.WebClient).DownloadString('https://…'))` 的 `network` 是 `false`。这一点没有变。
6. **只在 PowerShell 5.1 上量过**。辅助进程用类型名查表，PowerShell 7 新增的类型（三元表达式、管道链）不在无害清单上的都算。
7. **`${C:\x}` 里的路径不展开变量**，这是 PowerShell 的读法（花括号里是字面量）。提供程序限定的写法 `${FileSystem::C:\x}` 在 5.1 里是普通变量（实测什么都不打印），守卫照样交给路径层，只会更严。

## 7. 没有做的

- **O-3（新查到，没有修，等使用者决定）**：单独成句的变量和带变量的字符串不在任何命令里，守卫看不到。
  - `Get-Date; $env:SECRET_TOKEN`、`Get-Date; "key $env:SECRET_TOKEN"` 由规则放行（`allow-ps-no-path-commands`），不需要后端；`Write-Output $env:SECRET_TOKEN` 是灰色（`ps-dynamic-arg`）。
  - 危害和 X1 审查的 H-4 一样：环境变量里的密钥进入模型的上下文。H-4 和它的绕过 R-2 当时都评为高危。
  - `m3a-done` 上相同。修订 21 把它算作无害（变量不动手），没有改变它。
  - 两种修法都有代价，所以没有擅自加进来：
    - 把单独成句的表达式当作 `Write-Output <表达式>`：语义是准的，变量照 `ps-dynamic-arg` 变灰色、送审，文字在请求里。代价是单独一条的表达式（`[IO.File]::Delete('x')`）从"不送审"变成"带着文字送审"，改了 P11 以来的做法。
    - 只标灰色、不送审：`git status; "exit=$LASTEXITCODE"` 这类常见写法在默认配置下由 allow 变成问。
- 真实宿主里没有跑。
- 复审的 R19-1、R19-2、R19-3、R20-1 没有动。
- PowerShell 7 上没有量。
