# 系统目录只认确切的几个（规格修订 15）

日期：2026-11-05。基线：`c3e4b5a`。依据：修订 14 的记录 `docs/reports/M3a-program-fold.md` 第 7 节。使用者说"修盘符问题"。没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次和攻击样本；判决都用假后端（总是放行）。实测只读了 ACL、只让 `cygpath` 和 `GetFullPath` 算路径，没有在 scratchpad 之外建目录或放程序。

## 1. 结论

**第 7 节的五类写法都不再由规则放行。** Windows 主机上，带路径的程序只有目录正好是下面之一才算系统里的程序：`%SystemRoot%\System32`、`%SystemRoot%\SysWOW64`，`%ProgramFiles%`、`%ProgramFiles(x86)%` 下 Git 的 `cmd`、`bin`、`usr\bin`、`mingw64\bin`、`mingw32\bin`；都要带盘符，不含子目录。bash 方言里不带盘符的 `/usr/bin`、`/bin` 等照旧算（Git Bash 自己的目录）。别的位置的程序仍按名字认，deny / ask 规则照样命中；allow 规则用不上，是灰色 `program-path-qualified`，或者因为程序本身在项目外而命中 ask / deny 规则（第 2 节）。代码提交 `8ddc6e2`，文档在其后一个提交。

规则条目和策略文件没有改，评测除日期和延迟外与记录相同。所有差分都没有变松，修改前 deny 的仍然 deny（第 5 节）。全量 28318 通过、169 跳过、1 失败；失败的是 M1 就有的计时测试，和这次修改无关，单跑 5 次都过（第 5 节）。

**代价**：PowerShell 里的 `/usr/bin/git.exe status`、Git Bash 里的 `/Windows/System32/git.exe status` 现在要问；在别的盘或别的目录装的 Git，带路径调用要问或送审（第 6 节）。

## 2. 修改前后

假机器。"规则放行"是无决定、由 allow 规则给出；之后 Claude Code 自己的权限流程还会接手。有后端时假后端总是放行，所以"送审"的结果都是无决定。下面每一行，守护进程环境里不设这三个变量（按默认值）和设成本机的真实值，结果都一样。

| 写法 | 修改前，无后端 / 有后端 | 修改后，无后端 / 有后端 |
|---|---|---|
| 两种 shell `D:/Windows/System32/git.exe status` | 规则放行 / 规则放行 | **问 / 问**（`ask-git-read-outside-project`） |
| Bash `C:/Windows/System32evil/git.exe status`，`C:/Windows/System32/Tasks/git.exe status`，`C:/Windows/System32/spool/drivers/color/git.exe status` | 规则放行 / 规则放行 | **问 / 问**（同上） |
| Bash `C:/msys64/home/x/cat a.txt`，`C:/msys64/usr/bin/cat a.txt`，`C:/cygwin/tmp/cat.exe a.txt` | 规则放行 / 规则放行 | **问 / 送审** |
| Bash `"C:\Program Files\Git\tmp\cat.exe" a.txt`，`"C:\Program Files\Git\uſr\bin\cat.exe" a.txt` | 规则放行 / 规则放行 | **问 / 送审**（后一条是修订 14 记录第 6 节第 3 条的残余） |
| Bash `E:/usr/bin/cat a.txt`，`C:/usr/bin/cat a.txt` | 规则放行 / 规则放行 | **问 / 送审** |
| Bash `/Windows/System32/git.exe status` | 规则放行 / 规则放行 | **问 / 问**：Git Bash 里这是 Git 自己目录下的 `Windows\System32`（实测） |
| PowerShell `/usr/bin/git.exe status` | 规则放行 / 规则放行 | **问 / 问**：PowerShell 里这是当前盘根下的 `\usr\bin`（实测） |
| Bash `E:/usr/bin/rm -rf x` | 问 / 送审 | **deny / deny**（`rm-outside-project`，和别的目录里的 `rm` 一样） |
| Bash `D:/Windows/System32/diskpart.exe` | deny / deny | **不变** |
| Bash `/usr/bin/git.exe status`，`/usr/bin/cat a.txt`，`/usr/local/bin/git status` | 规则放行 / 规则放行 | **不变** |
| Bash `C:/Windows/System32/git.exe status`；PowerShell `C:/WINDOWS/SYSTEM32/git.exe status` | 规则放行 / 规则放行 | **不变** |
| Bash `"C:\Program Files\Git\usr\bin\cat.exe" a.txt`；PowerShell `& 'C:\Program Files\Git\cmd\git.exe' status` | 规则放行 / 规则放行 | **不变** |
| Bash `/c/Windows/System32/git.exe status`，`/mingw64/bin/git status` | 问 / 问 | **不变**：修改前也不算系统目录（第 6 节第 3 条） |
| Bash `C:/Windows/System32/OpenSSH/ssh.exe -V`，`.../WindowsPowerShell/v1.0/powershell.exe -Command Get-Date` | `ssh` 问 / 问（`net-unknown-destination`），`powershell` 问 / 送审 | **不变**：子目录不算了，但这两个程序本来就没有 allow 规则 |

变量会移动这些目录：`SystemRoot` 是 `D:\Windows` 时，`D:/Windows/System32/git.exe status` 由规则放行，`C:/Windows/System32/git.exe status` 要问（`test_the_system_root_comes_from_the_environment`）。

## 3. 修法

- **`src/boundkeep/normalize/event.py`**：
  - `_WINDOWS_SYSTEM_PREFIXES`（不带盘符的前缀）换成 `_WINDOWS_SYSTEM_ROOTS`：三个变量、各自的 Windows 默认值、各自之下的目录。`_windows_system_dirs` 由它们算出折叠之后的目录集合（`lru_cache`），`_system_dir` 按 `windows_fold` 精确比较。
  - 变量取守护进程自己的环境（`ctx.env`，即 `os.environ`）。`_env_value` 按 Windows 的方式比较 ASCII 变量名的大小写。没有这个变量时用默认值；值不是 `X:\…` 的绝对路径，或者有一段以点或空格结尾（Win32 会读成别的），这个变量不给出任何目录，不退回默认值：不知道系统在哪时，猜 `C:` 是往宽的方向猜。
  - Windows 主机上，不带盘符的 POSIX 系统目录只在 bash 方言里算。`_system_dir` 多了 `shell`、`env` 两个参数，`_canonical_program` 把当前方言传进来。
- **`tests/unit/test_m3a_system_dirs.py`**（新，107 条）：确切的目录集合；坏的变量值；变量移动目录；系统目录里的程序照样放行；第 7 节的写法和它们的变体不再放行；PowerShell 与 Bash 里的 `/usr/bin`；发给模型的请求；变量名的大小写；开尔文符号的目录按 NTFS 比较；本机真实环境；deny / ask 规则照样命中；POSIX 主机不变。
- **`tests/unit/test_m3a_program_fold.py`**：修订 14 的两条测试写的是前缀语义（`msys64`、`cygwin64`、`Git/用户`、`System32/Weiß`、`System32/ſ` 之下算系统目录，`Git\uſr` 照样放行），改成了现在的语义。
- **规格**：修订 15，§5.1。`docs/policy-reference.md` 灰色原因 `program-path-qualified` 那一条加了一句。`policies/` 没有改。

## 4. 第 7 节的设计问题，这次怎么定的

- **哪个盘是系统盘**：读 `SystemRoot`，没有时用 `C:\Windows`。读的是守护进程的环境，是使用者自己启动 `boundkeep serve` 时的环境；agent 在自己 shell 里改变量，传不到守护进程。程序到底从哪里运行由命令里写的绝对路径决定，与变量无关；变量只决定信任哪些目录。
- **System32 的子目录**：一个都不算。实测 `System32\Tasks` 给 Authenticated Users 写入权限 (CI)(W,Rc)，修订 14 量过 `spool\drivers\color` 给 Users 写入权限 (RX,WD)。列出全部可写子目录、再随系统更新维护，做不到，所以只认 System32 和 SysWOW64 这一层。
- **带盘符的 `/usr/bin`**：不算。不带盘符时只在 bash 方言里算：`cygpath -w /usr/bin`、`/bin` 都是 Git 自己的 `usr\bin`，Git Bash 的 PATH 找到 `cat` 也在 `/usr/bin/cat`。PowerShell 里 `[IO.Path]::GetFullPath('/usr/bin')`（当前目录在 E 盘）是 `E:\usr\bin`，不算。
- **msys、cygwin**：不算，装了也不算。`C:\` 给 Authenticated Users 建文件夹（AD），并让新建的子项继承修改权限（(OI)(CI)(IO)(M)）。这台机器上 `C:\` 下由安装程序建的文件夹多数继承了这个修改权限（`Config`、`db`、`QMDownload` 属于 Administrators，`eSupport` 属于 SYSTEM），也有不继承的（`VS`、`VSTOOL`、`VSRAM`）。msys2、cygwin 的安装程序属于哪一种没有量（这台机器没有装）。要在判决时读 ACL 才分得清，没有这样做。
- **Git**：只认 `Program Files` 和 `Program Files (x86)` 下的那五个目录。`Program Files` 属于 TrustedInstaller，Users 只有读取和执行（实测）。Git 默认装在这里，它的目录是否沿用这个 ACL，这台机器量不到（Git 装在 `D:\新建文件夹\Git`，见第 6 节第 4 条）。

## 5. 度量

代码最后一次改动在 17:59:30；测试文件最后一次改动在 18:20:17（第一轮变异之后加了一条）。下面的差分、变异和全量都在这之后跑。

**实测的读法和 ACL**（只读）：

| 位置 | 结果 |
|---|---|
| `C:\Windows\System32`、`SysWOW64`、`System32\WindowsPowerShell\v1.0`、`System32\OpenSSH`、`System32\wbem`、`C:\Program Files` | Users 只有读取和执行 |
| `C:\Windows\System32\Tasks` | Authenticated Users：(CI)(W,Rc) |
| `C:\Windows\Tasks` | Authenticated Users：RX,WD |
| `C:\` | Authenticated Users：(AD)，(OI)(CI)(IO)(M) |
| `D:\`、`E:\` | Authenticated Users：M |
| `D:\新建文件夹\Git`、它的 `usr\bin`（这台机器的 Git） | Authenticated Users：M |
| Git Bash 的 `cygpath -w` | `/usr/bin`、`/bin` → Git 的 `usr\bin`；`/Windows/System32` → Git 目录下的 `Windows\System32`；`/c/Windows/System32` → `C:\Windows\System32`；`C:/usr/bin` → `C:\usr\bin` |
| Git Bash 的 `type` | `cat` 是 `/usr/bin/cat`，`git` 是 `/mingw64/bin/git` |
| PowerShell 5.1 的 `GetFullPath`（当前目录在 E 盘） | `/usr/bin` → `E:\usr\bin`；`/Windows/System32` → `E:\Windows\System32` |

**系统目录的扫描**（新做的，这次的主要依据）：三组目录，每组乘两种 shell、有无后端、五种环境（不设变量、本机真实值、变量名全大写、`SystemRoot` 等指向 D 盘、变量值是坏的），共 49720 条。

| 组 | 条数 | 结果 |
|---|---|---|
| 要保留的 Windows 目录（13 种写法：大小写、正反斜杠、结尾斜杠） | 8360 | 前三种环境里**全部相同**；变化的 1642 条收紧、190 条同级都在"指向 D 盘"和"坏值"两种环境里，是设计如此 |
| 要保留的 POSIX 目录（7 个，不带盘符） | 6160 | Bash **全部相同**；PowerShell 里不再有一条被规则放行（770 收紧、350 同级） |
| 要去掉的目录（第 7 节的写法与变体，34 种） | 35200 | 20704 相同，13071 收紧，1425 同级；还被规则放行的 **0** 条，只有"指向 D 盘"的环境里 `D:/Windows/System32`、`D:\WINDOWS\SysWOW64`、`D:/Program Files/Git/usr/bin` 三个照样放行，这是那个环境的系统目录 |

扫描里变松的 **0** 条，修改前 deny、修改后不是 deny 的 **0** 条。

**其他差分**（对修订 14 的输出）：

| 项目 | 结果 |
|---|---|
| 逐程序的扫描（修订 14 的 12668 条） | 只有 PowerShell 的 `/usr/bin/...` 变了：11 条收紧、15 条同级（例：`/usr/bin/egrep a.txt` 有后端时由送审变成问）。折叠写法还被规则放行的 0 条，deny 没有减少 |
| 真实磁盘差分（真联接点，23544 条） | 级别全部相同 |
| 假机器差分（179508 条） | 级别全部相同 |
| 孪生字母项目（30720 条） | 级别全部相同 |
| 带冒号的普通命令（492 条） | 全部相同 |

**其他：**

| 项目 | 结果 |
|---|---|
| 新测试和改过的测试 | 107 passed；两个文件合计 221 passed |
| 变异：16 个（盘符、前缀、POSIX 目录的方言与盘符、变量的读取、大小写、校验、坏值、空值、Git 与 x86 的目录、SysWOW64、折叠、点段、方言的传递），副本上跑 | 第一轮 14 个抓到。`sys:lower-not-fold`（用 `lower` 代替 `windows_fold`）存活，加了开尔文符号的测试之后抓到。`sys:dots`（去掉 `.`、`..` 段的检查）存活，是等价变异：精确比较之下带这种段的目录本来就不在集合里。检查留着，以后改成规范化之后再比较时它才有用 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过；77 个源文件没有问题 |
| `boundkeep test` default / strict | 1142 / 0 失败，334 / 0 失败 |
| 评测（`--config rules+taint --test-contaminated`，输出到 scratchpad，没有打开留出批次） | `results/*.json` 去掉日期、延迟、sha 之后相同；`report.md` 只有日期一行和 4 行延迟不同。策略 sha256 没变，仓库里的评测文件没有重新生成 |
| 全量（分六段跑，不是一个进程，当前代码） | **28318 通过、169 跳过、1 失败**，18:21:46 到 21:41:14。六段都一次跑完，合计 28488 条，与收集到的相同，测试文件清单（119 个）与 `tests/` 相同；运行期间 `src/`、`tests/`、`policies/`、`eval/` 没有文件变化 |

**那 1 条失败**：`tests/unit/test_daemon.py::test_a_worker_that_finishes_late_does_not_change_the_answer_or_the_count`。测试放开卡住的工作线程后固定睡 0.3 秒，再断言 `stuck=0`，得到的是 `stuck=1`：线程还没退出。它在第 1 段（18:21 到 18:37），当时电源模式是"最佳能效"。它是 M1 的测试（`7319884`），`tests/unit/test_daemon.py` 和 `src/boundkeep/daemon/` 在 `c3e4b5a` 之后都没有改；全量之后单跑 5 次都过，整个文件 47 passed。没有修：要修就是把固定的睡眠改成带期限的轮询，和修订 11 那条 Hypothesis 期限同一类。

六段用时 15:08、14:36、24:02、13:39、1:56:16、15:25。第 4 段中途电源模式改成了"最佳性能"（电源计划仍是 `Silent`），第 5 段反而比修订 14 的 1:15:45 慢，原因没有查。

## 6. 代价和残余

1. **PowerShell 里不带盘符的 `/usr/bin/...` 要问**。那是当前盘根下的 `\usr\bin`，原来的放行本来就不对；只有真有这个目录的人才会碰到。
2. **Git Bash 里不带盘符的 `/Windows/System32/...` 要问**。那是 Git 目录下的 `Windows\System32`，正常不存在。
3. **Git Bash 的盘符写法 `/c/Windows/System32/git.exe` 和 `/mingw64/bin/git` 仍然要问**（修改前也是）。前者就是 `C:\Windows\System32`，后者是 Git Bash 的 PATH 里 `git` 的真实位置。没有加：这两种写法的含义取决于 Git 的挂载表和安装目录，要另量。
4. **装在别处的 Git**（这台机器的 `D:\新建文件夹\Git`）：带完整 Windows 路径调用它的程序要问或送审。但 Git Bash 里不带路径的 `cat` 和 `/usr/bin/cat` 都运行这个目录里的文件，这个目录 Authenticated Users 可以修改（实测），照样放行。所以信任 `/usr/bin/cat` 和信任 PATH 上的 `cat` 是同一件事，不是这次新开的口子；boundkeep 不是沙箱，不防同一台机器上别的账户改写程序。
5. **System32 子目录里的程序带路径调用不再算系统的**（`WindowsPowerShell\v1.0`、`OpenSSH`、`wbem`）。这些目录 Users 只读（实测），可以按名单加回来；这次没有加，因为它们里面的程序本来就没有 allow 规则（第 2 节最后一行）。
6. **`Program Files\Git` 的 ACL 没有在真实安装上量过**（第 4 节）。
7. **变量来自守护进程的环境。** 使用者在改过 `SystemRoot` 的环境里启动守护进程，信任就跟着走；坏的值不给出任何目录。
8. **`windows_fold` 仍依赖 Python 的 Unicode 版本**（RV-6，没有修）。
9. **没有修的**：复审的 RV-4、RV-6，RV-5 的正文更正；上一轮的 GR-3、GR-4、GR-5；那条计时测试（第 5 节）。

## 7. 没有做的

- 这次修复没有复审。
- 真实 Claude Code 的 hook 链路里没有跑。修订 10 到 15 都没有；`scripts/smoke_claude_m3a.py` 只覆盖原有链路。
- 没有在任何真实位置建目录、放程序，只读了 ACL；可写的位置能否真的放进程序、被 shell 运行，没有试。
- 只量了 NTFS 和 Windows PowerShell 5.1；pwsh 7、FAT、exFAT、ReFS、SMB 没有量。
- 真实模型没有接过。
