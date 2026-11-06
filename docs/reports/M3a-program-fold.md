# 程序名和系统目录的折叠（规格修订 14）

日期：2026-11-05。基线：`1ce6220`。依据：复审 `docs/reviews/M3a-dots-and-folding-review.md` 的 RV-7。使用者说"修 RV-7"。没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次和攻击样本；判决都用假后端（总是放行），真实跑过的程序只有 scratchpad 里的假脚本，没有在 scratchpad 之外建文件。

## 1. 结论

**RV-7 修了，还多修了一处复审没有写的。** 复审只点了系统目录。程序名本身有同样的问题：`lſ a.txt`、`ﬁnd . -name x`、PowerShell 的 `Teſt-Path a.txt` 也由规则放行，而实测它们不是 `ls`、`find`、`Test-Path`。两处都修了；这样写的程序名同时不再送审，因为模型看不到它的写法（第 4 节）。代码提交 `fef9fe9`，文档在其后一个提交。

规则条目和策略文件没有改，评测除日期和延迟外与记录相同。差分对 `d1729dd` 没有变松；对修订 13 有 1 条，是修订 13 那次差分自己多收紧的，这次回到了原判决（第 5 节）。全量 28212 通过、169 跳过、0 失败。

**同时查到一类更容易成立的问题，没有修**（第 7 节）：系统目录的判断丢了盘符、前缀又太宽，`D:/Windows/System32/git.exe status` 不需要任何特殊字符就由规则放行。修它要先定几个设计问题，等使用者决定。（2026-11-05 补记：已在规格修订 15 修复，记录 `docs/reports/M3a-system-dirs.md`。）

## 2. 修改前后

假机器。"规则放行"是无决定、由 allow 规则给出；之后 Claude Code 自己的权限流程还会接手。有后端时假后端总是放行，所以"送审"这一格的结果都是无决定。

| 写法 | 修改前，无后端 / 有后端 | 修改后，无后端 / 有后端 |
|---|---|---|
| Bash `/uſr/bin/cat a.txt` | 规则放行 / 规则放行 | **问 / 送审**（模型看得到 `/uſr/bin/...` 和灰色原因） |
| 两种 shell `C:/Windowſ/System32/git.exe status`，`Syſtem32`，`Syﬆem32` | 规则放行 / 规则放行 | **问 / 问**（`ask-git-read-outside-project`，不送审） |
| 两种 shell `/uſr/bin/rm -rf x` | 问 / 送审 | **deny / deny**（`rm-outside-project`，和别的目录里的 `rm` 一样） |
| Bash `lſ a.txt`，`ﬁnd . -name x` | 规则放行 / 规则放行 | **问 / 问，不送审** |
| Bash `/usr/bin/lſ a.txt`，`C:/Windows/System32/lſ.exe a.txt` | 规则放行 / 规则放行 | **问 / 问，不送审** |
| PowerShell `Teſt-Path a.txt`，`Select-ſtring x a.txt` | 规则放行 / 规则放行 | **问 / 问，不送审** |
| 两种 shell `ruﬀ check .`，`ſed -n 1p a.py`，`maKe`（这个 `K` 是开尔文符号 U+212A） | 问 / 送审 | 问 / **问，不送审** |
| Bash `größe a.txt`，`µtool a.txt`（不是已知程序） | 问 / 送审 | 问 / **问，不送审**（第 6 节第 1 条） |
| `ſudo cat a.txt`，`ſſh host` | 问 / 问 | **不变**：`sudo`、`ssh` 的规则照样命中 |
| `mkfſ x.img`，`diſkpart`，`boundKeep mode audit-only` | deny / deny | **不变** |
| Bash `/usr/bin/cat a.txt`；两种 shell `C:/WINDOWS/SYSTEM32/git.exe status`，`git status`；PowerShell `Test-Path a.txt` | 规则放行 / 规则放行 | **不变** |
| `测试.exe a.txt`，`C:/Users/Weiß/.venv/Scripts/pytest.exe -q` | 问 / 送审 | **不变**：普通名字，路径里的 `ß` 不算 |
| Bash `"C:\Program Files\Git\uſr\bin\cat.exe" a.txt` | 规则放行 / 规则放行 | **不变**：在 Git 的前缀之下（第 6 节第 3 条） |

## 3. 修法

- **`src/boundkeep/normalize/event.py`**：
  - `_system_dir` 用 `paths.windows_fold`，不用 `casefold`。
  - `_canonical_program` 在 Windows 上比较 `name.casefold()` 和 `paths.windows_fold(name)`，不一样就加灰色原因 `program-fold-variant`。`program` 字段仍是 `casefold` 的结果，所以 deny / ask 规则照样命中。
- **`src/boundkeep/daemon/pipeline.py`**：`program-fold-variant` 进 `_UNSHOWN_REASONS`，这样的调用不送审（`gray-unanalysed`）。
- **`tests/unit/test_m3a_program_fold.py`**（新，114 条）：会变成 ASCII 的字符（`TO_ASCII`）是运行时算的，孪生目录由它生成。覆盖孪生目录、程序名、包装器（`env`、`xargs` 等）、`bash -c` 里的命令、deny / ask 规则、普通名字、POSIX 主机和 PowerShell。
- **规格**：修订 14，§5.1 和 §7。`docs/policy-reference.md` 加了灰色原因的说明。`policies/` 没有改。

## 4. 和复审建议不同的地方

复审的建议是"这一处换成 `paths.windows_fold`，一行"（当时没有试过）。那一行只管系统目录。

- **程序名是单独的一处。** 只改那一行之后，`lſ a.txt` 仍然由规则放行：`_canonical_program` 自己把名字 `casefold` 成了 `ls`。
- **程序名不能也直接换成 `windows_fold`。** 那样 `ſudo` 就不再命中 `sudo` 的规则，`mkfſ` 不再命中 deny，方向反了。所以名字仍按 `casefold` 认，只关 allow 侧。这和修订 12、13 是同一个方向规则（§5.1）。
- **不送审是复审没有提的。** 我从假后端收到的请求量过：发给模型的是 `"program": "sed"`，看不出写的是 `ſed`。如果照常送审，模型批准的是另一个程序。带路径的孪生目录不同，请求里有 `/uſr/bin/sed` 原文和灰色原因，所以照常送审（`test_the_model_is_shown_the_twin_directory_as_written`）。

## 5. 度量

代码最后一次改动在 08:07:43，下面的差分、变异和全量都在这之后跑。

**实测的读法**（只在 scratchpad 的假目录和假脚本上）：

- Git Bash：`uſr` 和 `usr` 是两个目录；PATH 上名为 `lſ` 的脚本运行的是它自己，不是 `ls`。
- Windows PowerShell 5.1.26100.9711：`Get-Command 'Teſt-Path'`、`Get-Proceſſ` 都找不到；`env:UſERPROFILE` 没有设置，`env:userprofile` 有。

**逐程序的扫描**（新做的，这次的主要依据）：表里 251 个程序名和 158 个 cmdlet，普通写法和折叠写法，6334 条，乘有无后端共 12668 条。折叠写法用 11 个 `casefold` 后全是 ASCII 的字符，每个字符只换名字或目录里第一次出现的地方。收紧的也逐组读过。

| 组 | 条数 | 结果 |
|---|---|---|
| 全 ASCII 的写法（大写、`.exe`、带路径） | 8644 | **全部相同** |
| 不含这类字符的非 ASCII 名字（中文、日文、俄文、带重音、希腊字母） | 240 | **全部相同** |
| 含这类字符、不是已知程序的名字 | 120 | 65 相同；55 收紧，都是有后端时送审变成问 |
| 已知程序，名字里换一处 | 2512 | 1364 相同；1148 收紧：1076 条由送审变成问，72 条由规则放行变成问 |
| 系统目录，路径里换一处 | 1152 | 480 相同；552 收紧；120 同样是问，只是理由变了（灰色变成 ask 规则） |

扫描里，折叠写法还被规则放行的 **0** 条；修改前 deny、修改后不是 deny 的 **0** 条。扫描不含 `Git\uſr` 这种写法（第 6 节第 3 条），它单独有测试。

**其他差分**（这几组的语法里没有折叠写法，看的是普通写法有没有被牵连）：

| 项目 | 结果 |
|---|---|
| 真实磁盘差分（真联接点，23544 条，对修订 13） | 级别全部相同 |
| 假机器差分（179508 条，对 `d1729dd`） | 级别相同 178138，收紧 1370，**变松 0** |
| 假机器差分（同样的 179508 条，对修订 13 的那次结果） | 级别相同 179507，1 条"变松"：`Write 1:\..\ſettings.json` 有后端时由 `gray-unanalysed` 的问变回送审。修订 13 的记录已经提到它：那次差分和变异测试在抢 CPU，这条比 `d1729dd` 多收紧了 1 条。这次回到了 `d1729dd` 的判决。可能是时间预算用完了，仍然没有确认 |
| 孪生字母项目（5 台假机器，30720 条，对修订 13） | 级别全部相同 |
| 带冒号的普通命令（492 条，对修订 13） | 全部相同 |

**其他：**

| 项目 | 结果 |
|---|---|
| 新测试 | 114 passed |
| 变异：11 个（`sys:casefold`、`sys:no-fold`、`name:no-gray`、`name:deny-side-fold`、`name:no-folding`、`name:all-hosts`、`name:upper-counts`、`name:any-unicode`、`name:only-long-s`、`name:whole-word`、`send:off`），副本上跑 2 个测试文件 | **全部抓到**，第一轮就抓到，没有存活 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过；77 个源文件没有问题 |
| `boundkeep test` default / strict | 1142 / 0 失败，334 / 0 失败 |
| 评测（`--config rules+taint --test-contaminated`，输出到 scratchpad，没有打开留出批次） | `results/*.json` 去掉日期、延迟、sha 之后相同；`report.md` 只有日期一行和 4 行延迟不同。策略 sha256 没变，所以仓库里的评测文件没有重新生成 |
| 全量（分六段跑，不是一个进程，当前代码） | **28212 通过、169 跳过、0 失败**，2:07:45。六段都一次跑完，合计 28381 条，与收集到的相同，测试文件清单与 `tests/` 相同；运行期间 `src/`、`tests/`、`policies/`、`eval/` 没有文件变化 |

修订 13 全量里那条 `1e9` 秒定时器的警告，这次没有出现。这和"它取决于竞争"的推断相符，但这个竞争仍然没有复现，也没有处理。

## 6. 代价和残余

1. **配了后端时，名字里带 `ß`、`µ`、`ς`、连字的程序不再送审，直接问。** 没有后端时没有变化（灰色本来就问）。这是这次唯一可能碰到正常程序的代价：判断不了一个字符是不是有意写的，所以按字符算。路径里的这些字符不算，只看程序名。
2. **`/uſr/bin/rm -rf x` 现在是 deny**（`rm-outside-project`），原来是问。它现在和 `/tmp/evil/rm -rf x` 的判决相同：不是系统目录里的 `rm`。
3. **`"C:\Program Files\Git\uſr\bin\cat.exe" a.txt` 仍然由规则放行。** `C:\Program Files\Git\` 之下的任何名字都算系统的，这是原有的前缀语义，和 `Git\tmp\cat.exe` 同一类（第 7 节）。修订 15 之后要问，有后端时送审。
4. **`windows_fold` 仍依赖 Python 的 Unicode 版本**（RV-6，没有修）。表外字符走 `casefold`，新版 Unicode 新增的大小写对会被合并。这次的灰色判断也用它。
5. **查过、没有改的三处 `casefold`**：
   - `_env_get`：`$env:WORKſPACE\a.txt` 是灰色，`$env:UſERPROFILE\.ssh\id_rsa` 是 deny，都不放行。
   - `programs.devtool_exe_in_env` 的 `seg.casefold()`：`.venv` 的孪生目录没有带来新的洞，写字面的 `.venv` 一样做得到。
   - `paths.py` 的 `same()`：只让遍历早停一步。
6. **没有修的**：复审的 RV-4、RV-6，RV-5 的正文更正；上一轮的 GR-3、GR-4、GR-5。

## 7. 查到的另一类问题，没有修

> 2026-11-05 补记：这一节的问题已在规格修订 15 修复（使用者说"修盘符问题"），设计问题怎么定的、代价和度量见 `docs/reports/M3a-system-dirs.md`。下面保留原文。

修 RV-7 时顺手查的。这些写法不需要特殊字符，修改前后判决相同，都由规则放行（在 `1ce6220` 上也量过）。

| 成因 | 写法 | 放行的 shell |
|---|---|---|
| `_system_dir` 丢掉盘符 | `D:/Windows/System32/git.exe status` | 两种 |
| 同上，加上 Windows 上也接受 POSIX 目录 | `E:/usr/bin/cat a.txt`，`D:/usr/bin/cat a.txt`，`C:/usr/bin/cat a.txt`，`D:/bin/cat a.txt` | Bash |
| `/windows/system32`、`/windows/syswow64` 两个前缀没有结尾的斜杠 | `C:/Windows/System32evil/git.exe status`，`C:/Windows/SysWOW64evil/git.exe status` | 两种 |
| 前缀之下的任何子目录都算系统目录 | `C:/Windows/System32/spool/drivers/color/git.exe status`，`"C:\Program Files\Git\tmp\cat.exe" a.txt` | 前者两种，后者 Bash |
| msys、cygwin 没有安装时前缀也算数 | `C:/msys64/home/x/cat a.txt`，`C:/cygwin/tmp/cat.exe a.txt` | Bash |

**为什么比 RV-7 容易。** 前提和 RV-7 一样：程序要先放在那里，写到项目外本身要问。但这些位置普通账户写得进去，也不需要 `ſ` 这样的字符。这台机器上只读过 ACL，没有真的建目录或放程序：

- `D:\`、`E:\`：Authenticated Users 有修改权限（M）。
- `C:\`：Authenticated Users 可以建文件夹（AD）。
- `C:\Windows\System32\spool\drivers\color`：BUILTIN\Users 有读取、执行和写入（RX,WD）。
- `C:\usr`、`C:\msys64`、`C:\cygwin`、`C:\cygwin64`、`D:\Windows`、`E:\Windows`、`D:\usr`、`E:\usr` 现在都不存在。

**建议先定的设计问题**（要改规格）：

- 哪个盘算系统盘？读 `SystemRoot`，还是写死 `C:`？环境变量本身可能被改。
- System32 之下的子目录要不要整体信任？`spool\drivers\color` 这样的可写子目录怎么排除？还是只信任 System32 本身这一层？
- Windows 上 `/usr/bin` 带盘符时算什么？Git Bash 里不带盘符的 `/usr/bin` 是 Git 自己的目录，`E:/usr/bin` 不是。
- msys、cygwin、Git 的前缀是否只信任具体的 `usr\bin`、`bin`，而且要求真的安装了？

收紧之后，这些路径上的正常程序（比如装在别的盘上的 Git）会多问，这个代价也要量。

## 8. 没有做的

- 这次修复没有复审。
- 真实 Claude Code 的 hook 链路里没有跑。修订 10 到 14 都没有；`scripts/smoke_claude_m3a.py` 只覆盖原有链路。
- 没有在真实的 `C:\Windowſ` 放过程序，只在 scratchpad 的孪生目录上跑过。
- 只量了 NTFS 和 Windows PowerShell 5.1；pwsh 7、FAT、exFAT、ReFS、SMB 没有量。
- 真实模型没有接过。
