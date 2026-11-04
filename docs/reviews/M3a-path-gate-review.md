# 带前缀路径的折叠与设备路径闸门的独立审查

日期：2026-11-03。代码：`78127af`（工作区干净）。审查对象：`a3b38c5`（`_fold_prefixed`、`_shape_prefixed`，记录 `docs/reports/M3a-prefix-folding.md`）；`2f0f009`（`device_path`、`_NUL_KEY`、`_NUL_REASONS`、`_finish` 的 `gray-device-path` 分支，`device-name-suffix`，卷的 key `//./c:`；规格 §7、§9.2 修订 10，记录 `docs/reports/M3a-device-paths.md`）；`tests/unit/test_norm_prefix_folding.py`、`tests/unit/test_device_paths_not_sent.py`、`tests/unit/test_norm_paths.py` 的新行。

作者的说法都当作待核实。没有改代码和测试，本报告未提交。没有读 `.env`，没有 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次和攻击样本。全量测试没有跑。

## 1. 结论

**高危：没有。中危：5 条。低危：8 条。测试缺口：5 条。信息：3 条。**

闸门本身写得对：`audit-only`、`on_failure`、污染窗口都符合规格（第 6 节），直接写出来的设备路径在我试过的 Read、Write、Edit、Glob、Grep、NotebookEdit、Bash、PowerShell 写法里都问，不送审。问题在闸门依据的那个 key：它在几种写法下说不准真实位置，而白名单只看 key 和理由。

| 编号 | 级别 | 一句话 | 要后端吗 |
|---|---|---|---|
| G-1 | 中 | `NUL` 豁免放过普通文件：`\\.\C:\Users\bob\.ssh\nul`、`C:\…\nul\.`，请求与真 `NUL` 一字不差，还会命中它的缓存 | 要 |
| G-2 | 中 | 末尾的点在 `\\?\` 下是字面字符：`\\?\C:\proj.\a.txt` 在项目之外，key 却是 `c:/proj/a.txt`，标为确定，规则放行。Node 下不带前缀也一样。用真文件量过 | **不要** |
| G-3 | 中 | 本机管道的 UNC 写法绕过闸门：`\\localhost\pipe\x`、`\\127.0.0.1\pipe\x` 送审，模型放行就是无决定 | 要 |
| G-4 | 中 | 项目里通向设备的链接：`_resolve_on_disk` 退回词法 key，规则放行；通向 UNC 时审查自己会 `stat` 目标 | **不要** |
| G-5 | 中 | `which //srv/share/x` 被 `allow-no-path-commands` 放行，看不到网络规则。**这是最接近高危的一条**，实际连接我没有量 | **不要** |
| G-6 | 低 | 参数里写明的设备路径认不出：`foo /out:'\\.\pipe\x'`、`cmd /c 'type \\.\pipe\x'` | 要 |
| G-7 | 低 | 命名空间的根：`\\.`、`//.`、`\\.\UNC\` 的 key 是 `//`，送审 | 要 |
| G-8 | 低 | `///srv/share/x`：Win32 读成 UNC，key 是 `c:/srv/share/x`，送审 | 要 |
| G-9 | 低 | 不是英文字母的盘符：`1:\x` 的 key 是 `c:/proj/1/x`，确定，规则放行 | **不要** |
| G-10 | 低 | 物理磁盘的另一种写法：`\\?\GLOBALROOT\Device\Harddisk0\DR0` 是问，不是 deny | 不要 |
| G-11 | 低 | POSIX 机器上 `//./etc/shadow` 就是 `/etc/shadow`，却被读成 Windows 设备，deny 变成问 | 不要 |
| G-12 | 低 | 普通 UNC 的 key 丢了服务器：`\\:x\pypi.org\s` 的 key 是 `//pypi.org/s`，确定，白名单不问 | 要 |
| G-13 | 低 | key 不稳定：`$FOO\..` → `.` → `c:/proj`。**属性测试 200 个种子里失败 3 个**，存下例子之后每轮都失败 | 不相关 |

"要后端吗"列的影响范围：LLM 层至今没有接过真实服务，所以"要"的几条目前没有用户受影响；"不要"的几条现在就成立。allow 在默认配置下只是"无决定"，Claude Code 自己的权限流程还会接手，boundkeep 不会替用户批准，只是没有拦。

### 五个问题的答案

| 问题 | 答案 |
|---|---|
| 1. 真正到达设备、卷、管道或网络共享的路径还能送审或被规则放行吗 | **能。** 送审：G-1、G-3、G-6、G-7、G-8。规则放行：G-2（目录名特殊时）、G-4、G-5、G-9（盘符存在时）。直接写出来的 `\\.\`、`\\?\`、`\??\`、`//./`、`//?/`、`/\.\` 形式没有漏（第 6 节） |
| 2. 白名单之外的路径能拿到豁免吗；豁免的能是普通文件吗 | 前一个：**不能**。我试过的全部理由都拿不到豁免，只是测试大多没钉（T-1）。后一个：**能**，G-1。白名单只看理由，而理由说不出路径是不是普通文件 |
| 3. 有错的 key 标为确定吗；有不稳定的 key 吗 | **都有。** 标为确定却错的：G-2、G-9、G-12、G-6 的 `foo of=`。不稳定：G-13。这次新加的 `//./c:`、`//./nul`、`//./pipe/x` 都稳定 |
| 4. 闸门在 `audit-only`、`on_failure`、污染窗口下对吗；路径进理由或审计记录吗 | **对。** 理由与 `llm` 字段不带路径。shell 调用的 `command` 字段带路径，这是原有设计（I-2） |
| 5. 测试钉住了它们声称的东西吗 | **大部分钉住了**：66 个变异里抓到 40 个，但活下来的 26 个集中在白名单与 `on_failure`。两条 Win32 对照测试的设计挡不住 G-1、G-2（T-3、T-4） |

## 2. 怎么量的

- **词法基准，比 `GetFullPathNameW` 更接近实际**：`RtlDosPathNameToNtPathName_U_WithStatus`，也就是 `CreateFileW` 拿到的 NT 路径，加上 `RtlIsDosDeviceName_U`。它不打开任何东西（对 DOS 设备名只看父目录在不在）。这个选择本身是一条发现：`GetFullPathNameW` 不代表打开时的读法，作者的对照因此看不见 G-1、G-2：

  | 写法 | `GetFullPathNameW` | NT 路径 |
  |---|---|---|
  | `\\?\C:\proj\nul.` | `\\?\C:\proj\nul` | `\??\C:\proj\nul.` |
  | `\\?\<root>\proj.\data.txt` | `\\?\<root>\proj\data.txt` | `\??\<root>\proj.\data.txt` |
  | `\??\C:\proj\nul` | `\\.\nul` | `\??\C:\proj\nul` |
  | `\??\C:\` | `C:\??\C:\` | `\??\C:\` |

- **判决**：`pipeline.decide`，默认策略加一个 LLM 块，后端是总是放行的 `FakeBackend`，`scan_disk=False`（与作者的测试相同），假机器（`C:\proj`，`C:\Users\bob`）。守护进程实际开着目录扫描，所以我用 `scan_disk=True` 重跑了 13 条代表行（G-1、G-2、G-3、G-5、G-6、G-9，含 Grep、Glob），结果相同。PowerShell 的行等辅助进程就绪之后才算，它只解析不执行。
- **模糊测试**：固定种子。Win32 基准 300000 条两轮（种子 20261103、20261104），字面命名空间 300000 条（种子 20261105），稳定性 300000 条（种子 3，三种上下文、三种方言）。语法故意偏向 `UNC`、盘符、`nul`、点、空段，所以比例不代表真实分布。
- **变异**：把 `src` 和三个测试文件复制到 scratchpad，改副本，跑这三个文件。未改的副本：798 passed, 5 skipped（8 秒）。
- **碰过的真东西**，都在 scratchpad 里且已删除：用 `\\?\` 创建名为 `nul` 的普通文件和目录，名为 `proj.` 的目录，并用 Python、Node、PowerShell 读取。此外用 Git for Windows 的 `which.exe` 查了 `C:/Windows/notepad.exe`。没有打开设备或卷，没有创建链接，没有执行 `subst`。
- **一处计划外的网络访问，要说清楚**：G-4 的探针把 `realpath` 换成假的、让它返回 `\\srv\share\x`，代码接着对这个路径真的调了 `os.stat`（这本身就是 G-4 的一部分）。所以我的 5 次运行在这台机器上发起了对主机名 `srv` 的解析或连接尝试。发现之后，复现脚本改成拦截 UNC 的 `os.stat`，只记录、不访问网络，之后没有再发生。我没有查这些尝试走到了哪一步。

**重跑**：完整脚本在这组会话的共享笔记目录 `M3a-path-gate-probes/repro.py`（和全部探针、原始输出在一起，目录在仓库之外）：

```
$env:PYTHONDONTWRITEBYTECODE='1'; .venv\Scripts\python.exe <笔记目录>\M3a-path-gate-probes\repro.py <一个空的 scratch 目录>
```

单条复现只需要附录里的两个函数。下面的输出都是实际运行的结果；`none` 是无决定，`sent` 是发给后端的请求数。

## 3. 中危

### G-1 `NUL` 豁免放过普通文件

- **位置**：`pipeline.py:669-686`，`paths.py:1304-1311`（最后一段是设备名就换成 `//./nul`，不管前面是什么）。
- **违反**：规格 §7"只有 Win32 确实读成 `NUL` 的写法才照常送审"。
- **复现**：

  | 写法 | NT 路径 | 判决 |
  |---|---|---|
  | `\\.\C:\Users\bob\.ssh\nul` | `\??\C:\Users\bob\.ssh\nul` | none，`llm`，sent=1 |
  | `\\?\C:\Users\bob\.ssh\nul` | 同上 | none，`llm`，sent=1 |
  | `\??\C:\Users\bob\.ssh\nul` | 同上 | none，`llm`，sent=1 |
  | `//./C:/Users/bob/.ssh/nul`、`//?/C:/…/nul` | 同上 | none，`llm`，sent=1 |
  | `\\?\C:\proj\nul.` | `\??\C:\proj\nul.` | none，`llm`，sent=1 |
  | `C:\Users\bob\.ssh\nul\.`（**没有前缀**） | `\??\C:\Users\bob\.ssh\nul` | none，`llm`，sent=1 |
  | `C:\Users\bob\.ssh\nul\`、`nul\`、`nul.\` | `…\nul\`，普通目录 | none，`llm`，sent=1 |

  前五行的 key 都是 `//./nul`，理由只有前缀和 `device:NUL`（`nul.` 多一个 `trailing-dots-spaces`），全在白名单里。除了 `\??\` 那行，其余几行 `RtlIsDosDeviceName_U` 都是 0（`\??\` 那行它误判，NT 路径才是打开时的读法）。

  用真文件量过：在 scratch 里用 `\\?\` 创建 `nul`，内容 `ordinary file`。用 `\\.\` 读回来是这个内容，目录列表里也有它。Read、Write 判决都是 `llm`，sent=1。目录同理：`<dir>\sub\nul\` 列得出里面的文件，Grep、Glob 这个路径都送审（读代码：路径不确定，`_native_dir` 返回 None，子树扫描不会进去）。

- **模型分不清**：请求里只有 `{"path": "//./nul", "access": "write", "inside_project": null}`，和真 `NUL` 一字不差。所以缓存也会命中：

  ```
  Write 'NUL' -> by=llm cache=miss requests so far=1
  Write '\\.\C:\Users\bob\.ssh\nul' -> by=llm-cache cache=hit requests so far=1
  ```

  同一个进程里只要放行过一次 `Write NUL`，之后写任何目录下名为 `nul` 的文件都不用再问模型。
- **模糊测试**：300000 条里 5242 条拿到豁免，其中 1464 条不是 `NUL`（不重复的 699 条），另有 470 条是打不开的路径（目录不存在，NT 转换报 `0xC0000033`），没有害处。
- **影响与限度**：只影响名字恰好是 `nul` 的文件或目录。这样的文件没有扩展名，启动目录里大概率不会运行（没有量），也没有常见程序读它，所以直接危害小。评为中危，是因为这条豁免的全部理由就是"这确实是 `NUL`"，而写法上可以写到任何目录。污染会话里写操作仍会被问（`tainted-sensitive`），读不会。没有后端时灰色本来就问。strict 策略由 `ask-read-outside-project` 问（实测）。
- **更大的疑问（没有量）**：Node 24.11 的 `path.win32.toNamespacedPath('C:\\proj\\nul')` 返回 `\\?\C:\proj\nul`。如果宿主的文件工具这样打开，那么 Read、Write 上的 `C:\proj\nul` 在实际运行时也是普通文件，"Win32 读成 NUL"这个依据对文件工具就不成立。这里没有打开，因为万一读法相反，打开的就是设备。Git Bash 的 `> nul` 同理没有量。
- **修法方向**：豁免只给 shell（`action.shell` 非空），`2>NUL` 这个写豁免的理由只存在于 shell，没有人 Read `NUL`。路径上只认没有盘符和目录的 `nul`，或没有前缀、末尾不带分隔符和 `\.` 的写法。`paths.py` 里，前缀后面跟盘符时不要按 DOS 设备名读。

### G-2 末尾的点是字面字符：key 说在项目里，文件在项目外

- **位置**：`paths.py:1084`（`extended-path-dots` 只查整段是 `.` 或 `..` 的），`paths.py:903`（中间一段恰好一个点算"确切"），`_PLAIN_REASONS` 含 `trailing-dots-spaces`（`paths.py:325-334`）。
- **违反**：`inside_project` 的约定"True 只在确定在里面时"，以及 `a3b38c5` 记录里"与 Win32 不一致却标为确定 0"。
- **复现**（真文件，项目是 `<root>\proj`，里面是空的）：

  ```
  project holds: [] | its parent holds: ['proj', 'proj.']
  Read '\\?\<root>\proj.\data.txt': nt='\??\<root>\proj.\data.txt' key='<root>/proj/data.txt' uncertain=False -> none by=rule:read-inside-project sent=0
  Read '\??\<root>\proj.\data.txt': nt='\??\<root>\proj.\data.txt' key='<root>/proj/data.txt' uncertain=False -> none by=rule:read-inside-project sent=0
  Write \\?\<root>\proj.\new.py -> none by=rule:allow-project-file-writes sent=0
  python reads through \\?\: outside the project
  ```

  不带前缀的 `<root>\proj.\data.txt`：Win32 读成 `proj\data.txt`（NT 路径 `\??\<root>\proj\data.txt`），PowerShell `Get-Content -LiteralPath` 报 `ItemNotFoundException`。但 **Node 读到的是项目外的文件**（`fs.readFileSync` 实测输出 `outside the project`，`toNamespacedPath` 结尾是 `\proj.\secret.txt`）。如果宿主的文件工具这样打开，就不需要前缀。
- **怎么被漏掉的**：作者的压力比对用 `GetFullPathNameW`，它在 `\\?\` 下把点去掉了（第 2 节的表）；`test_the_key_says_what_win32_says` 也没有 `\\?\` 的行。我第一版的模糊测试也漏了，因为我的基准把点去掉再比，直到回头查基准才发现。不去点重跑：字面命名空间 120709 条确定的 key 里，58297 条的中间一段带点、与 NT 路径不一致（语法故意偏向这种写法）。
- **影响与限度**：真实目标只能是名字末尾带点的目录，这种目录一般不存在。但 `mkdir '\\?\C:\proj.'` 和对其中文件的 Write 都由规则放行，不问，agent 可以自己造出来。只靠这一步能做的只是往这样一个目录写东西，要读写真正有价值的地方得再加一个联接点：`cmd /c 'mklink /J C:\proj. C:\Users\bob\Documents'` 是 `llm`，送审（模型放行就是无决定）；指向 `.aws` 的被 `no-credential-store-read` 拒绝。链接建好之后，`Read \\?\C:\proj.\credentials` 由规则放行（key 是 `c:/proj/credentials`）；我没有真的建这个联接点。同样的问题也影响 scratchpad、tool-results、memory 的判断（`SessionDir` 接受这个理由），那部分没有单独量。
- **修法方向**：字面命名空间（`\\?\`、`\??\`）下任何一段末尾带点或空格都标为不确定；不带前缀时中间一段末尾的点也标为不确定，或把 Node 的读法考虑进来。正常写路径的人不会这样写，所以没有误报的代价。

### G-3 本机管道的 UNC 写法绕过闸门

- **位置**：`event.py:1078`、`event.py:1094`（本机服务器不算远端，所以没有网络规则），`pipeline.py:682`（闸门只认 `//./`）。
- **违反**：规格 §7 把 `//./pipe/x` 列为"key 说不清通向哪里"，但同一个管道的另一种写法照常送审。
- **复现**：

  ```
  Read '\\.\pipe\x':          key='//./pipe/x'          -> ask  by=gray-device-path sent=0
  Read '\\localhost\pipe\x':  key='//localhost/pipe/x'  uncertain=False -> none by=llm sent=1
  Read '//localhost/pipe/x':  同上
  Read '\\127.0.0.1\pipe\x':  key='//127.0.0.1/pipe/x'  uncertain=False -> none by=llm sent=1
  Read '\\?\UNC\localhost\pipe\x'、'\\.\UNC\127.0.0.1\pipe\x'：同样 none，llm，sent=1
  Read '\\MYPC\pipe\x'（COMPUTERNAME=MYPC）、'\\127.1\pipe\x'、'\\0x7f.0.0.1\pipe\x'、'\\2130706433\pipe\x'：同样
  Read '\\localhost\mailslot\x'、'\\localhost\IPC$\x'：同样
  ```

  Write、Edit、Grep、Glob、`foo > '\\localhost\pipe\x'`、`Get-Content '\\localhost\pipe\x'`、`Test-Path '\\localhost\pipe\x'` 都一样。模型看到的是 `"path": "//localhost/pipe/x"`、`"network": false`。strict 由 `ask-read-outside-project` 问（实测）。
- **没有量**：管道命名的公开文档写法是 `\\ServerName\pipe\PipeName`，这些写法确实连到同一个管道这一点我没有打开验证。
- **相邻的情况**：`\\127.0.0.1\share\x`、`\\wsl$\Ubuntu\etc\shadow` 也送审，但 key 说得清位置，那是"本机不算网络"的设计，不算这条。白名单上的主机 `\\pypi.org\pipe\x` 也送审，同一个原因。
- **修法方向**：`device_path` 同时看 UNC key：服务器是本机（复用 `_LOCAL_UNC_SERVERS`、`COMPUTERNAME` 和回环判断），或共享名是 `pipe`、`ipc$`、`mailslot`。

### G-4 项目里通向设备的链接：规则放行，审查自己还碰目标

- **位置**：`paths.py:1521`（解析结果是设备就返回原路径），`paths.py:1528`（`_hard_linked` 对解析结果调 `os.stat`，不看它是不是 UNC）。不是这两次提交引入的（`7319884`，M1），但正好回答问题 1。
- **复现**（`realpath` 是假的；没有创建链接，没有打开目标；`os.stat` 对 UNC 只记录）：

  ```
  E:\proj\link.txt -> '\\.\pipe\x': none by=rule:read-inside-project sent=0; os.stat 调用: []
  E:\proj\link.txt -> '\\?\Volume{12345678-…}\x': none by=rule:read-inside-project sent=0; os.stat 调用: []
  E:\proj\link.txt -> '\\?\GLOBALROOT\Device\Mup\srv\share\x': none by=rule:read-inside-project sent=0; os.stat 调用: []
  E:\proj\link.txt -> '\\srv\share\x': ask by=rule:net-allowlist sent=0; os.stat 调用: ['\\srv\share\x', '\\srv\share\x']
  ```

  对照最能说明问题：通向 UNC 的链接由网络规则问，通向设备的反而不问。`device_path` 也看不到，key 仍是 `e:/proj/link.txt`。
- **第二个问题**：通向 UNC 时，审查过程自己 `stat` 了目标（我的探针就是这样意外碰到网络的，第 2 节）。`is_local_disk` 只检查输入路径，docstring 说"a dead server could block this call"正是要避免这一点。按 `event.py:1102` 的注释，访问 UNC 路径会把用户的 NTLM 凭证发给服务器，所以如果链接真的通向外部主机，这发生在判决之前，用户拒绝也来不及。真实的 `realpath` 还会自己沿着链接打开目标，没有量。
- **影响与限度**：要项目里已经有这样的链接。创建符号链接要权限或开发者模式；联接点不要，但目标要是本地卷。**我没有用真实的 `realpath` 跑过**，因为那会打开设备，所以 Python 对这类目标实际返回什么没有验证；这条的第一部分依赖它返回的是设备形式的路径。第二部分（`stat`）是代码路径，只要解析结果是 UNC 就成立。
- **修法方向**：解析结果是设备时，保留一个 `//./…` 形式的引用，或把路径标为不确定；`_hard_linked` 之前先过 `is_local_disk`。

### G-5 `which` 带网络路径被规则放行

- **位置**：`policies/default.yaml:1549-1564`（`allow-no-path-commands`，`d1228ed`）。
- **复现**（默认策略，**没有后端也一样**）：

  ```
  Bash 'which //srv/share/x' -> none by=rule:allow-no-path-commands sent=0
  no backend, which //srv/share/x -> none by=rule:allow-no-path-commands
  Bash "which '\\.\pipe\x'" -> none by=rule:allow-no-path-commands sent=0
  Bash 'which //./GLOBALROOT/Device/Mup/srv/share/x' -> none by=rule:allow-no-path-commands sent=0
  ```

  `which` 确实会查路径形式的参数（Git for Windows 的 `which.exe`，本机实测）：`which C:/Windows/notepad.exe` 输出这个路径；反斜杠形式 `C:\Windows\notepad.exe` 只按名字搜 PATH，说找不到。所以带正斜杠的 UNC 很可能真的走网络。
- **与已知的差别**：`docs/reviews/M2-rules-2-review.md` 的 R7-3 和策略注释只说"只透露存在性与可执行位"，没有考虑参数是网络路径。`net-allowlist` 看不到它，因为这个词不算路径。
- **没有量**：真的跑 `which //host/...` 会连到网络，我没有做。如果量出来确实发起了 SMB 连接，这条应该升为高危：不需要后端，不需要前提，一条命令把 NTLM 发给任意主机，boundkeep 不问。strict 没有这条 allow，走灰色（实测 `llm`，sent=1）。
- **修法方向**：`which` 的参数以 `//`、`\\` 开头时不放行，或把它当路径交给网络规则。

## 4. 低危

### G-6 参数里写明的设备路径认不出

记录第 6 节第 4 条写的是 `foo $P`、`python -c` 这种认不出的值。下面这些是写明的字面路径，不在那两个例子里，而且 `--out=`、`-o` 已经认得，Windows 上最常见的 `/out:` 反而不认得。

| 写法 | 判决 |
|---|---|
| Bash `foo --out='\\.\pipe\x'`、`foo -o'\\.\pipe\x'` | 问，`gray-device-path`（对照） |
| Bash `foo /out:'\\.\pipe\x'`、`foo /o:…`、`foo --out:…`、`foo of='\\.\C:'`、`foo x=…`、`foo @…`、`foo 'x,\\.\pipe\x'`、`foo 'file://///./pipe/x'` | none，`llm`，sent=1 |
| Bash `cmd /c 'type \\.\pipe\x'`、`cmd.exe /c 'copy a \\.\C:'`、`powershell -c 'gc \\.\pipe\x'` | none，`llm`，sent=1（`sh -c` 会解析，所以是问） |
| PowerShell `foo -out:'\\.\pipe\x'`、`foo /out:\\.\pipe\x`、`foo 'FileSystem::\\.\pipe\x'` | none，`llm`，sent=1 |
| PowerShell `cmd /c 'type \\.\pipe\x'`、`cmd /c "copy a \\.\C:"`、`powershell -c "gc '\\.\pipe\x'"`、`bash -c 'cat //./pipe/x'`、`Invoke-Expression "gc '\\.\pipe\x'"`、`New-Object IO.FileStream('\\.\pipe\x','Open')`、`Get-Content ("\\.\" + 'pipe\x')` | none，`llm`，sent=1 |

模型能在 `args` 里看到原文，所以不算隐藏。但 `foo of='\\.\C:'` 的请求里还有 `{"path": "<project>/of=/c", "inside_project": true}`：**错的 key 标为确定，并告诉模型它在项目里**。修法方向：参数按 `=`、`:`、`,` 切开后，只要有一段带设备前缀就算设备路径。

### G-7 命名空间的根

`\\.`、`//.`（类型 root-local-device，NT 路径 `\??\`）和 `\\.\UNC`、`\\.\UNC\`（NT 路径 `\??\UNC\`）的 key 都是 `//`，理由 `unc-incomplete`，不是设备也不是网络，所以 none，`llm`，sent=1。`\\?`、`\\.\`、`\\?\` 已经是 `//./`，是问。这些目标一般打不开（没有量）。修法方向：`\\.` 与 `\\?` 同样处理；`//` 这个 key 也算在闸门内。

### G-8 三个开头的斜杠

`///srv/share/x`：NT 路径 `\??\UNC\\srv\share\x`（Win32 类型 UNC，服务器段是空的），key `c:/srv/share/x`，不确定，none，`llm`，sent=1；`cat ///srv/share/x` 同样。三个反斜杠 `\\\srv\share\x` 已经走 `net-allowlist`，只有全是正斜杠的漏了。Node 的 `path.win32.resolve` 把两者都读成当前盘的 `\srv\share\x`，所以 key 对 Node 工具是对的；原生程序能不能这样打开没有量。

### G-9 不是英文字母的盘符

`paths.py:1204` 要求 `isascii` 与 `isalpha`，其他盘符按相对路径读，`:` 当成数据流去掉，理由 `ads-stripped` 不算不确定。

```
Read '1:\credentials': nt='\??\1:\credentials' key='c:/proj/1/credentials' uncertain=False -> none by=rule:read-inside-project sent=0
Read 'é:\credentials': 同样放行；Write '1:\settings.json' -> none by=rule:allow-project-file-writes
cat '1:\credentials' -> none by=rule:allow-cat-inside-project；PowerShell Get-Content '1:\credentials' -> none by=rule:allow-ps-inspect-inside-project
```

带前缀的 `\\.\1:\x` 已经是设备，是问。默认没有这样的盘。`subst 1: C:\Users\bob\Documents` 是 `llm`（指向 `.claude` 的被 `protect-guard-config` 拒绝）。**我没有执行 `subst`，它会改这台机器的状态**；公开资料说非字母盘可以这样定义，要确认可以在自己的终端用一个一次性目录试，然后 `subst 1: /d` 删掉。Node 把 `1:\x` 读成当前目录下的路径，所以走 Node 的文件工具到不了那个盘；`cmd /c type 1:\x` 这种原生调用可以。如果盘能定义，而原生的读或写又被规则放行，这条应该升为中危。修法方向：第二个字符是 `:` 而第一个不是字母时标为不确定，而不是当数据流。

### G-10 物理磁盘的另一种写法

`dd if=x of='\\.\PhysicalDrive0'` 是 deny，`\\?\GLOBALROOT\Device\Harddisk0\DR0`、`\\.\GLOBALROOT\Device\Harddisk0\Partition0`、`\\?\GLOBALROOT\GLOBAL??\PhysicalDrive0`、`\\.\GLOBALROOT\DosDevices\PhysicalDrive0`、`\\?\Harddisk0Partition1` 都是问（`gray-device-path`）。记录第 6 节第 2 条说的是卷；这里是物理磁盘本身。这些路径都是问，不送审。这些写法是否都确实通向磁盘是公开资料的说法，我没有打开。修法方向：`no-raw-disk-access` 补上这些 glob，要改规则，评测要重取，由使用者决定。

### G-11 POSIX 机器上 `//./x` 就是 `/x`

```
Read '/etc/shadow' -> deny by=rule:no-secret-read
Read '//./etc/shadow' -> ask by=gray-device-path
dd if=x of=/dev/sda -> deny by=rule:no-raw-disk-access
dd if=x of=//./dev/sda -> ask by=gray-device-path
```

`_ext_prefix_len` 不看平台。`event.py:1110` 给 UNC 写了"POSIX 上 `//host/x` 只是 `/host/x`"，这里没有对应的判断。理由文字还说是 Windows 设备路径。POSIX 目前只是设计目标，所以是低危。这和记录第 6 节第 3 条（`/dev/...` 送审）不是一回事。

### G-12 普通 UNC 的 key 丢了服务器

`_win_part` 把服务器段当路径段处理，`:x` 变成 `.`，然后被 `_unc_shape` 的循环跳过，后一段补成服务器。`a3b38c5` 修的是带前缀的同类错误，这里是不带前缀的：

```
Read '\\:x\pypi.org\s':  nt='\??\UNC\:x\pypi.org\s'  key='//pypi.org/s' uncertain=False -> none by=llm sent=1
Read '\\..\pypi.org\s':  nt='\??\UNC\..\pypi.org\s'  key='//pypi.org/s' uncertain=False -> none by=llm sent=1
Read '\\::1\pypi.org\s': nt='\??\UNC\::1\pypi.org\s' key='//pypi.org/s' uncertain=False -> none by=llm sent=1
```

`pypi.org` 在白名单上，所以网络规则不问，模型看到的也是这个主机。这些服务器名大概率解析不了（没有量），所以是低危。`\\srv\..\evil\share\x` 的 key 是 `//srv/evil/share/x`，主机没错，只是共享名错了，网络规则仍然问。修法方向：服务器段不走 `_win_part`；前两段里出现 `.`、`..`、冒号就标为不确定。

### G-13 key 不稳定，属性测试会随机失败

```
'$FOO\..':    '.' -> 'c:/proj'
'~x\..':      '.' -> 'c:/proj'
'$FOO\..\a':  'a' -> 'c:/proj/a'
```

以变量或 `~` 开头的路径没有锚点，折叠之后变量没了，留下的 `.` 第二遍就按工作目录读。300000 条里 25 条不稳定且不在测试的豁免内（另有 3063 条是测试明确豁免的 UNC 键）。第一遍的 key 带着不确定标记，我在 `src/` 里也没有查到把 key 再规范化一遍的调用，所以没有安全后果。

**实际后果是全量测试**：`test_normalization_is_idempotent` 的 `FRAGMENTS` 里就有 `$FOO`、`\`、`..`。把测试原样跑 200 个种子（每次清空例子库）：**3 个失败**（`raw='%\..'`、`'~C:\..'`、`'$FOO\..'`）。Hypothesis 把失败例子存下来之后每轮都失败，正是 `a3b38c5` 那次的经过。这是一次 75 分钟的全量里随时可能出现的红灯，与当次改动无关。修法方向：折叠掉开头的未知段时保留它（`$FOO/..` 不折叠），或者像 `tilde-user` 那样处理。

## 5. 测试缺口（问题 5）

66 个变异，40 个被抓到，26 个活下来。全表在 `M3a-path-gate-probes/mutants.txt`。

**抓到的**：`device_path` 的全部写法变异（只看第一个动作、只看第一个路径、只看读或只看写、去掉豁免、只按 key 豁免、`//./nul/x` 也豁免、排除卷）；`_finish` 分支（关掉、只在 enforce 生效、丢记录、理由或记录带路径）；污染窗口；`_fold_prefixed` 的 no-op、不弹第一段、保留去点之后的写法；`_shape_prefixed` 的 13 个变异；`device-name-suffix`；白名单里删掉任何一个理由；白名单里加 `ads-stripped`、`unc`、`device-name-suffix`、`prefix-path-folded`。这些测试是有用的。

| 编号 | 级别 | 缺口 | 证据 |
|---|---|---|---|
| T-1 | 低 | **白名单的封闭性基本没钉**。规格写了"带变量或通配符的也不算"，但把这些理由加进白名单，测试全过 | 22 个变异活下来：`glob`、`brace`、`variable-expanded`、`variable-syntax-mismatch`、`home-expanded`、`msys-translated`、`cygdrive-translated`、`wsl-translated`、`drive-relative`、`rooted-current-drive`、`rooted-no-drive`、`trailing-dots-spaces-ambiguous`、`short-name-unresolved`、`odd-leading-separators`、`extended-path-dots`、`no-cwd`、`cwd-uncertain`、`dynamic-word`、`unresolved-expansion`、`nul-byte`、`too-long`、`resolved-on-disk`。**现在的代码是对的**（`$HOME/nul`、`%TEMP%\nul`、`~/nul`、`C:\pro?\nul`、`C:nul`、`\nul`、`/c/proj/nul`、`/cygdrive/…`、`/mnt/…`、`C:\PROGRA~1\nul`、`cat $(x)/nul` 实测都问），只是没有测试 |
| T-2 | 低 | **`on_failure` 没有测试**。闸门跟着 `on_failure: deny` 变成 deny，测试全过 | 变异 `finish:follows-on-failure` 活下来。现在的代码是对的（第 6 节） |
| T-3 | 低 | `test_what_is_exempt_is_nul_to_win32` 名不副实：它只遍历手写的 `REALLY_NUL`，不问代码实际豁免了什么。G-1 因此不会让它失败。它用的 `GetFullPathNameW` 对 `\??\` 也不准（第 2 节） | 读代码；`\\.\C:\proj\nul` 不在列表里 |
| T-4 | 低 | `test_the_key_says_what_win32_says` 比的是 `_key(raw) == _key(buffer.value)`，两边过同一个函数。26 行里 5 行 Win32 原样返回，等于自己比自己。错误只要两边一致就看不出：`\\.\C:\proj\nul` 这样的路径两边都是 `//./nul`，会通过。没有 `\\?\`、`\??\` 的行，加了也不够，因为 `GetFullPathNameW` 在那里不是打开时的读法 | `p7_tests.py` 实测。`LEXICAL` 表另外钉了这些 key，所以不是全盲 |
| T-5 | 信息 | `_fold_prefixed` 里"`...`、`.. ` 按 `..` 算"的谨慎读法没有钉；闸门与 `incomplete_analysis` 的先后没有钉（结果都是问，只有 `decided_by` 不同） | 变异 `fold:dotdot-literal-only`、`fold:dot-literal-only`、`finish:gate-before-unanalysed` 活下来。Win32 把 `\\.\foo\...\UNC\srv\share\x` 当字面，key 读成 UNC，确实是更谨慎的读法 |

## 6. 查过、没有问题的

- **直接写出来的设备路径**：`\\.\`、`\\?\`、`\??\`、`//./`、`//?/`、`/\.\`、`\/.\`，大小写，折叠（`\\.\foo\..\pipe\x`），重复分隔符，末尾的点和空格，流：都问。物理磁盘的这些写法都 deny。
- **shell 的各种位置**：程序位置（`'\\.\pipe\x' arg`、`sudo`、`env`、`nohup`、`exec`、`.`、`source`、`bash`、`python`、`node`、PowerShell 的 `&`、`.`），重定向（`>`、`>>`、`<`、`2>`、`&>`、`<>`、`>|`、`*>`），子 shell、命令替换、管道、`tee`、`xargs`、`cd`、`pushd`、`Set-Location`，`-o'…'`、`--out=…`，引号和转义，`{a,b}`，通配符，`sh -c`。`P=…; cat $P` 是 `gray-unanalysed`，同样不送审。
- **PowerShell 的路径写法**：`FileSystem::`、`Microsoft.PowerShell.Core\FileSystem::`、裸词、双引号、`-LiteralPath`、`'…' | Get-Content`、`Out-File`、`Set-Content`、`Add-Content`、`Copy-Item`、`Move-Item`、`Test-Path`、`Get-Item`、`Resolve-Path`、`Select-String`、`Import-Csv`、`Get-FileHash`、`Start-Process`、`Invoke-Item`、`file:` URL：都问，`Get-ChildItem` 由 `ask-shell-read-outside-project` 问。`[IO.File]::…` 是 `gray-unanalysed`。
- **其他工具**：Glob（`pattern` 与 `path`）、Grep、NotebookEdit、MultiEdit 都问；LS、未知工具、`Task` 是 `gray-unanalysed`；WebFetch 的 `file:` 由网络规则问。
- **不是漏洞的写法**：` \\.\pipe\x`（开头有空格）Win32 读成相对路径，确实不是设备。`bash -c "cat '\\.\pipe\x'"` 在双引号里 `\\` 变成 `\`，确实不是设备，写对转义之后是问。`cat 'file:////./pipe/x'` 被规则放行，但 NT 路径在项目下（`…\file:\pipe\x`），`cat` 不读 URL，到不了管道。`COM0`、`LPT0`、`COM10`、`ＮＵＬ`（全角）、`nul\xa0`：Win32 不认为是设备，key 也不是，一致。`foo > C:\…\nul` 这样的 shell 写法属于 G-1。
- **`NUL` 的真写法**：`nul`、`NUL`、`nul.`、`nul `、`nul...`、`.\nul`、`src/nul`、`..\nul`、`C:\nul`、`\\.\NUL`、`\\?\NUL`、`\??\nul`：豁免，NT 路径都是 `\??\nul`（目录要存在，否则 `0xC0000033`）。真 NUL 却不豁免的（`nul:`、`C:nul`、`\nul`）是谨慎方向，没有害处。
- **`on_failure`**：`on_failure: deny` 的策略下，`\\.\pipe\x`、`\\.\C:`、`aux.py` 都是问，sent=0；`NUL` 照常送审。符合规格"不按 `on_failure`"。
- **`audit-only`**：`decision=none`、`decided_by=audit-only`、`would_be=ask`、`llm={"outcome":"not-sent","detail":"device-path"}`、sent=0。
- **污染窗口**：连续几次设备路径的询问，`taint_asks` 保持 0。对照：G-1 的 `Write` 经 `tainted-sensitive` 变成问，`taint_asks` 从 0 到 1，这个计数是对的（模型放行之后污染一步才接手）。
- **项目标记**：污染会话里的设备路径写（`inside_project` 为 None）按 `written_places` 给项目打标记，所以 `aux.py` 的 key 不会让它漏掉（读代码）；实测一串这样的写之后 `marks` 是 `('c:/proj',)`，没有 `//./…` 的标记。
- **闸门顺序**：带标记的项目先 `gray-marked-project`，分析不全的先 `gray-unanalysed`，都是问。代码顺序与规格 §7 的图一致，标记那一步图上没画（信息）。
- **理由与 `llm` 字段**：Read、Write、Bash、PowerShell、Glob，两种模式，路径都不在里面。
- **折叠后的 key**：Win32 基准下，带前缀且标为确定的 5775 条里，只有中间一段带冒号的不一致（如 `\\.\C:\C:` → `c:/c`；这种路径 NTFS 大概率打不开，没有量）。除这一类和 G-2 之外，`a3b38c5` 的结论成立。
- **稳定性**：带前缀的路径在 300000 条（工具方言）里 0 条不稳定；`//./c:`、`//./nul`、`//./pipe/x` 稳定；第二遍没有丢掉设备标记（0 条）。第二遍会丢掉不确定标记（12807 条，如 `prefix-path-folded`），这是"理由描述原文"的自然结果，我在 `src/` 里没有查到依赖它的代码。

## 7. 信息

- **I-1 规格和记录有一句写错了**：规格 §7 与记录第 3 节说 `\\.\C:\.` "实际是根目录"。实测 NT 路径是 `\??\C:`，也就是卷本身；`\\.\C:\foo\..` 也是。代码按卷算，**代码是对的**。真正"谨慎地按卷算"的是 `\\.\foo\..\C:\`（NT 路径 `\??\C:\`，是根目录）。
- **I-2 审计记录里的路径**：理由和 `llm` 里没有路径，`test_the_reason_and_the_record_do_not_carry_the_path` 也只测这两处。但 shell 调用的记录有 `command` 字段（原有设计，`server.py:137-140`），程序位置的路径的文件名会进 `programs`，所以路径还是进了审计日志；文件工具的 `file_path` 不进。这与这次改动无关，只是"不写路径"要按这个范围读。`AuditLog` 对这些字段的脱敏与截断我没有跑，`build_record` 的 docstring 这样说。
- **I-3 记录第 4 节的表**：`C:\proj\nul` 被写成"`NUL` 在哪个目录都算"。`GetFullPathNameW` 确实这样说，但打开时目录不存在就是 `0xC0000033`（打不开），存在才是 `\??\nul`（`C:\Windows\nul` 实测）。按 `NUL` 豁免没有害处，只是表上的说法比实际宽。

## 8. 没有查的

- **真实宿主**：没有跑 Claude Code，文件工具到底怎么打开路径（G-1、G-2 的 Node 读法）是最值得实测的一点。Node 的结果是独立用 `node` 24.11 量的，不是宿主里的版本。
- **真实模型**：全是假后端。模型看到这些请求会怎么回答不知道。
- **打开设备、卷、管道、网络共享**：按要求没有打开。`\\.\C:` 是卷、`GLOBALROOT\Device\Mup` 通向共享、`\\localhost\pipe\x` 是同一个管道，都是公开资料的说法；只有第 2 节说的那次计划外 `stat` 碰过 `\\srv\share\x`。
- **真实的 `realpath` 与真实链接**（G-4）、`subst`（G-9）、`which //host/…` 的实际连接（G-5）、Git Bash 里 `> nul` 的实际结果（G-1）：都没有做，原因写在各条里。
- **其他平台和版本**：只有 Windows 11 build 26200、Windows PowerShell 5.1、Python 3.12.11。没有 pwsh 7，没有真 POSIX 机器（G-11 是假机器）。
- **策略**：主要是默认策略。strict 只跑了 G-1、G-3、G-5、G-6、G-9 的代表行，其中 `1:\credentials` 在 strict 下也被规则放行。
- **MCP**：MCP 调用本来就不送审，没有单独试路径。
- **全量测试与评测**：按要求没有跑全量，没有跑 `boundkeep test` 和评测。只跑了那三个测试文件的副本。

## 附录：单条复现

从仓库根目录运行，把判决的行换成要查的写法：

```python
import ctypes, re
from ctypes import wintypes
from boundkeep import protocol
from boundkeep.audit.auditor import Auditor
from boundkeep.audit.backends.base import verdict_json
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.policy import default_policy_text, parse_policy_text

HOME, PROJECT = "C:\\Users\\bob", "C:\\proj"
LLM = "  backend: openai_compatible\n  openai_compatible:\n    base_url: https://llm.example.invalid/v1\n    model: m"
POLICY = parse_policy_text(
    re.sub(r"^  backend: none.*$", lambda _m: LLM, default_policy_text(), count=1, flags=re.M),
    home=HOME,
)


class US(ctypes.Structure):
    _fields_ = [("Length", wintypes.USHORT), ("Max", wintypes.USHORT), ("Buffer", ctypes.c_void_p)]


ntdll = ctypes.WinDLL("ntdll")
ntdll.RtlDosPathNameToNtPathName_U_WithStatus.argtypes = [
    ctypes.c_wchar_p,
    ctypes.POINTER(US),
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ntdll.RtlDosPathNameToNtPathName_U_WithStatus.restype = ctypes.c_long
ntdll.RtlFreeUnicodeString.argtypes = [ctypes.POINTER(US)]


def nt(raw):  # the NT path CreateFileW is handed; nothing is opened
    out = US()
    status = ntdll.RtlDosPathNameToNtPathName_U_WithStatus(raw, ctypes.byref(out), None, None)
    if status < 0:
        return f"<status {status & 0xFFFFFFFF:#x}>"
    text = ctypes.wstring_at(out.Buffer, out.Length // 2)
    ntdll.RtlFreeUnicodeString(ctypes.byref(out))
    return text


def verdict(tool, tool_input, cwd=PROJECT):  # a fake backend that allows whatever it is shown
    backend = FakeBackend(lambda _r: verdict_json(verdict="allow"))
    call = {
        "hook_event_name": "PreToolUse",
        "session_id": "s",
        "cwd": cwd,
        "project_dir": cwd,
        "tool_name": tool,
        "tool_input": tool_input,
    }
    d = pipeline.decide(
        protocol.EVENT_PRE,
        call,
        mode="enforce",
        policy=POLICY,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": HOME},
        home=HOME,
        scan_disk=False,
        auditor=Auditor(POLICY.llm_audit, backend),
    )
    return d.decision or "none", d.decided_by, len(backend.requests)


print(
    nt("\\\\.\\C:\\Users\\bob\\.ssh\\nul"),
    verdict("Read", {"file_path": "\\\\.\\C:\\Users\\bob\\.ssh\\nul"}),
)
print(nt("\\\\?\\C:\\proj.\\a.txt"), verdict("Read", {"file_path": "\\\\?\\C:\\proj.\\a.txt"}))
print(nt("\\\\localhost\\pipe\\x"), verdict("Read", {"file_path": "\\\\localhost\\pipe\\x"}))
print(verdict("Bash", {"command": "which //srv/share/x"}))
```

输出：

```
\??\C:\Users\bob\.ssh\nul ('none', 'llm', 1)
\??\C:\proj.\a.txt ('none', 'rule:read-inside-project', 0)
\??\UNC\localhost\pipe\x ('none', 'llm', 1)
('none', 'rule:allow-no-path-commands', 0)
```

注意 `C:\proj`、`C:\Users\bob` 是假路径，别换成这台机器上真实存在的 UNC 或链接：判决时 `realpath` 是真的（G-4）。
