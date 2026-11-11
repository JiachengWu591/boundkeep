# PowerShell 里的 `/dev/null`、`/dev/zero` 是普通路径（规格修订 20）

日期：2026-11-10。基线：`fb9fd4d`。来源：修订 19 的全量里，`test_norm_psprograms.py::test_a_dynamic_word_in_path_position_is_never_dropped` 这条随机生成测试生成到 `Remove-Item /dev/zero`，发现路径被丢掉了（`docs/reports/M3a-short-name-unresolved.md` 第 7 节）。

使用者说"修 /dev 这条"，并做了两个选择：
- 范围选"整个 PowerShell 工具"；
- `/dev/tcp` 选"记路径，网络标记也留着"。

代码在 `92a5e56`，文档在其后一个提交（`9bb2194`），两个都已推送到 `origin/main`。没有打标签。

没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次和攻击样本。实测用的文件都是假的，放在 TEMP 下的临时目录里，用完已删；当前盘的根下没有建过任何东西。

## 1. 结论

**改了什么**：`/dev/null`、`/dev/stdin`、`/dev/stdout`、`/dev/stderr`、`/dev/tty`、`/dev/zero` 这六个名字，现在只在 bash 方言里是无害设备。PowerShell 方言里它们是普通路径，照常记。`/dev/tcp/主机/端口`、`/dev/udp/主机/端口` 在 PowerShell 里既记路径，也保留网络目标。

**为什么改**：程序知识表把这六个名字当设备、不记路径，这是 Bash 的读法，PowerShell 一侧照搬了。PowerShell 5.1 把 `/dev/zero` 解析成当前盘根下的 `\dev\zero`，`Remove-Item`、`Set-Content` 和重定向都真的作用在那个文件上（第 3 节）。所以 PowerShell 里：
- `Remove-Item -Recurse /dev/null` 是灰色、送审，同样写法的 `/dev/nullx` 是 deny；
- `Get-ChildItem /dev/null`、`git status 2>/dev/null` 由规则放行，换成 `/dev/nullx` 是 ask。

**规则条目和策略文件没有改。bash 方言一条没变，没有一条判决变松**（第 5 节）。

## 2. 修改前后

真实目录树（假文件），PowerShell，没有后端。`/dev/nullx` 是对照：它从来不在那六个名字里。

| 写法 | 修改前 | 修改后 | 对照 `/dev/nullx` |
|---|---|---|---|
| `Remove-Item /dev/zero` | 灰色 | ask（`ask-delete-outside-project`） | ask |
| `Remove-Item -Recurse -Force /dev/null` | 灰色 | deny（`rm-outside-project`） | deny |
| `Get-ChildItem /dev/null` | allow（`allow-ps-list-here`） | ask（`ask-shell-read-outside-project`） | ask |
| `git status 2> /dev/null` | allow（`allow-git-read-only`） | ask（`ask-git-read-outside-project`），代价 | ask |
| `git diff --no-index /dev/null README.md` | 灰色 | ask（`ask-git-read-outside-project`），代价 | ask |
| `Set-Content /dev/null x`、`echo hi > /dev/null` | 灰色，不记路径 | 灰色，记路径 | 灰色 |
| `curl.exe -s -o /dev/null https://example.com/a` | 不记路径 | 记路径，级别不变 | 相同 |
| `Remove-Item -Recurse -Force /dev/tcp/example.com/80` | ask（`net-allowlist`） | deny（`rm-outside-project`） | deny |
| `Get-Content /dev/tcp/example.com/80` | ask（`net-allowlist`），不记路径 | ask（`net-allowlist`），记路径 | 灰色 |
| `git status 2> $null` | allow | allow | |
| Bash：`git status 2>/dev/null`、`rm /dev/zero`、`cat x > /dev/tcp/h/80` | 不变 | 不变 | |

## 3. 实测

PowerShell 5.1.26100。把 TEMP 下的一个临时目录挂成只在这个会话里存在的 PSDrive，再进到它的根，这样 `/dev/…` 就落在临时目录里。

| 写法 | 结果 |
|---|---|
| `Get-Content /dev/tty`、`/dev/stdin` | 读到临时目录里 `dev\tty`、`dev\stdin` 的内容 |
| `Remove-Item /dev/zero` | `dev\zero` 被删掉 |
| `Remove-Item -Recurse /dev/null` | 目录 `dev\null` 和里面的文件被删掉 |
| `Set-Content /dev/stderr '…'` | 写进了 `dev\stderr` |
| `'x' > /dev/stdout`、`'x' > /dev/null` | 建出了文件 `dev\stdout`、`dev\null` |
| `'x' > /dev/tcp/example.com/80`、`Get-Content` 同一个名字 | 读写的是文件 `dev\tcp\example.com\80`，没有连网 |
| 当前盘没有 `\dev` 时的 `git --version 2>/dev/null`、`'x' > /dev/null` | 报错 `Could not find a part of the path 'C:\dev\null'`，git 没有运行 |
| `Get-Content -`、`Remove-Item -` | 读到、删掉了当前目录里名叫 `-` 的文件 |

从 PowerShell 启动的外部程序拿到的是原样的文字（当前盘 C: 的根下没有 `\dev`）：

| 程序 | 结果 |
|---|---|
| python：`os.path.abspath('/dev/null')` | `C:\dev\null`，不存在 |
| `curl.exe -s -o /dev/null file:///C:/Windows/win.ini` | 退出码 23（写不了输出文件） |
| `cmd /c type /dev/zero` | 退出码 1 |
| `git hash-object /dev/zero` | 退出码 128，`could not open '/dev/zero'` |
| `git hash-object /dev/null` | 退出码 0，得到空文件的哈希：git 自己把这个名字当空文件 |

## 4. 修法

- `programs._Acc.posix_devices`：新字段，建 `_Acc` 时必须给，没有默认值。True 是原来的读法。`_Acc.path` 只在它为 True 时跳过那六个名字；`/dev/tcp/…`、`/dev/udp/…` 照旧记网络目标，它为 False 时再把路径记上。
- `programs.classify`：新参数 `posix_devices`，默认 True。`python -m pip` 用的第二个 `_Acc` 跟着第一个走。
- `psprograms._Ctx`：建 `_Acc` 时给 False，cmdlet 和 PowerShell 的重定向因此都按路径记。
- `psprograms._external`：外部程序走 Bash 的程序表，调用时传 `posix_devices=False`。
- 文档：
  - 规格：修订 20 的段落，§5.1 命令方言里"`/dev/` 下的名字因方言而异"一条；
  - `docs/powershell-dialect.md`：第 3 节表里重定向一行，以及新的一行。
- 测试：新文件 `tests/unit/test_m3a_ps_dev_paths.py`，84 条。它们是：
  - cmdlet、带引号的写法、复制的两头；
  - PowerShell 的重定向，`$null` 对照；
  - 外部程序的参数，`python -m pip`；
  - `/dev/tcp`、`/dev/udp`：路径和网络目标都在；
  - bash 方言的对照；
  - 真实目录树上的判决：六个名字逐个和 `/dev/nullx` 比，实测过的几条命令，`git status 2>/dev/null` 的代价。

## 5. 度量

| 差分 | 结果 |
|---|---|
| 专门扫描：45 种 PowerShell 写法、28 种 Bash 写法 × 18 个词（六个设备名、三个 `/dev/tcp` 和 `/dev/udp`、九个对照）× 带不带引号，共 2482 行，新旧代码各跑一次 | **0 行变松**，没有一行少了路径、主机或联网标记。Bash 的 952 行和 PowerShell 对照词的 720 行完全相同。PowerShell 的 810 行里 120 行收紧，672 行级别相同、多记了路径，18 行完全相同（`& /dev/null`，程序名本来就记了路径） |
| 其中收紧的 120 行 | 灰色到 ask 48 行，灰色到 deny 24 行，allow 到 ask 36 行（`git status 2>`、`git status *>`、`Get-ChildItem`），`/dev/tcp` 的 ask 到 deny 12 行 |
| 修订 19 的扫描（160 行）、修订 18 的扫描（5100 条）、修订 16 的扫描（12768 条） | 全部相同 |
| 修订 17 的真实目录树扫描（10092 条） | 全部相同。`--` 前后对照的计数（404 条更松，542 条更严）和修订 19 时一样 |
| IR-1 的扫描（10320 条） | 全部相同；Bash 和 PowerShell 的 5160 对判决仍然全部相同 |
| 带冒号的普通命令（492 条）、系统目录、逐程序 | 全部相同 |
| 真实磁盘（23544 条）、假机器（179508 条）、孪生项目（30720 条） | 级别全部相同 |
| 含 git 或 `~` 的语料（655 条，1164 次判决） | 0 条不同 |
| `boundkeep test` default / strict | 1142 / 0 失败，334 / 0 失败 |
| 评测（`--config rules+taint --test-contaminated`，输出到 scratchpad） | `results/*.json` 去掉时间戳之后相同；`report.md` 只有日期一行和 4 行延迟不同 |

专门扫描的级别按 allow、灰色、ask、deny 从松到严排。旧代码是 `fb9fd4d` 的 `src`。原有差分的基线是修订 19 代码的输出。

原有差分是在"`posix_devices` 改成必填的构造参数"这一步之前跑的，那一步不改行为：改完之后重跑专门扫描，输出和改之前逐字节相同；新测试、变异、受影响的测试文件和全量都在最后的代码上跑。这些差分全部相同，说明的是别处没有被牵连；PowerShell 里带 `/dev/` 名字的写法靠专门扫描来看。

| 测试和检查 | 结果 |
|---|---|
| 新测试文件 | 84 passed |
| 新测试文件在 `fb9fd4d` 的代码上 | 72 failed，12 passed（通过的都是 bash 方言和 `$null` 的对照） |
| 原来失败的 `test_a_dynamic_word_in_path_position_is_never_dropped` | 通过 |
| 受影响的 26 个测试文件（从 Git Bash 里启动） | 8795 passed，31 skipped，1 failed。失败的是 `test_norm_bash.py::test_word_splitting_matches_real_bash` 的一个样本（`a\\b 'a\\b' "a\\b"`），和这次修改无关：在 `fb9fd4d` 的代码上同样失败。这组测试要 PATH 上有 bash 才跑，从 PowerShell 启动时全部跳过（整个文件 499 passed，38 skipped），全量就是这样跑的。失败的原因看上去在测试的做法上：脚本经 `-c` 传给 Git Bash 时反斜杠少了一半（真实 bash 给出 `ab`，解析器给出 `a\b`），没有再查，也没有改 |
| 变异：13 个，在副本上跑新测试文件和 `test_norm_programs.py` | **全部抓到**。第一轮 12 个里有一个存活，是等价的：把 `_Acc` 里 `posix_devices` 的默认值改反，而三处建 `_Acc` 的地方都会覆盖它。所以把它改成了必填的构造参数，`_classify` 的参数也去掉了默认值，变异重写后再跑 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过 |
| 全量（分六段跑，不是一个进程；测试文件清单 125 个，与 `tests/` 相同） | 28739 passed，169 skipped，**0 failed**，合计与收集到的 28908 条相同。六段都一次跑完，退出码都是 0。用时 2:32:27（09:21 到 11:53），其中第 5 段 1:16:41；从头到尾电源都是"最佳性能"，上一次（修订 19）是 4:39:20，中途才换的。跑的期间 `src`、`tests`、`policies`、`eval`、`scripts` 和两份被测试读的文档都没有改 |

## 6. 代价和残余

1. **PowerShell 里的 `git status 2>/dev/null` 从 allow 变成 ask**，`*>`、`Get-ChildItem /dev/null` 也一样。当前盘没有 `\dev` 目录时，这样的命令在 PowerShell 5.1 里本来就报错、不运行（实测）。丢弃输出要写 `$null`。
2. **git 的 `/dev/null`**：git 自己把它当空文件，这里不开例外。PowerShell 里的 `git diff --no-index /dev/null x` 从灰色变成 ask。
3. **`/dev/tcp` 不够忠实**：PowerShell 里读写这样的路径不连网，守卫仍然按联网问一次。这是使用者选的，换来没有一条判决变松。
4. **非 Windows 上的 PowerShell 没有量**：那里 `/dev/null` 是真的设备，守卫现在会多记一个路径，只会更严。支持范围本来就只有 Windows。
5. **单独的 `-` 没有改**：两种方言里都不记路径。PowerShell 的 cmdlet 把它当当前目录里名叫 `-` 的文件，`Remove-Item -` 真的删掉它（实测）。它在这次选的范围之外，文件也只能在当前目录里。
6. **从 PowerShell 启动的 MSYS 程序**（Git 的 `usr\bin` 在 PATH 里时的 `cat.exe` 等）自己认得 `/dev/null`，守卫仍然按路径记，只会更严。没有量。

## 7. 没有做的

- 这次修复没有复审，真实宿主里没有跑。
