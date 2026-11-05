# 规格修订 12 的定向复审（尾随点与 NTFS 折叠）

日期：2026-11-05。代码：`d1729dd`（工作区干净，与 `origin/main` 相同）。审查对象：`git diff 2f8f59d bede21d`，记录 `docs/reports/M3a-dots-and-folding.md`。

**这不是独立复审。** 卡片写的是独立复审，但使用者选了在这里做，修复也是这个会话写的。我尽量靠实测下结论，可能和写修复时有同样的盲点。真要独立的眼光，还得另开一个不带这段对话的会话。

**之后（2026-11-05）**：使用者说"修这三条"，RV-1、RV-2、RV-3 已修，记录 `docs/reports/M3a-readings-fixes.md`（规格修订 13）。下面的判决是修之前的。修复时又查到一条同类问题，见 RV-7；RV-2 的建议里"Win32 反正打不开"不全对，见第 2 节该条。

这次复审只新增了这份报告，没有改代码、测试、规格和策略。没有读 `.env`，没有 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次和攻击样本。全量没有跑。判决都用假后端（总是放行）。实测的"密钥"和"策略"都是假内容，文件都在 scratchpad 里，用完已删。

## 1. 结论

**修订 12 的两个目标达到了，但它带来了一个回退（RV-1）。** 尾随点和空格不再被规则放行（13104 条写法的扫描里，这两类都是 0 条）；折叠表对真实卷逐字符比对，一个错误都没有。

**回退是：项目里有链接时，deny 变成了问，配了后端时变成送审。** 带尾随点的路径现在算不确定，而不确定的路径不看磁盘，也就看不到链接通向哪里。修订 11 已经把中间一段弄成这样，修订 12 扩大到最后一段。我之前说的"deny 不变""没有一条变松"，只在假机器上成立。**建议在接后端之前修掉。**

| 编号 | 级别 | 一句话 | 要后端吗 | 来源 |
|---|---|---|---|---|
| RV-1 | 中 | 经过链接时，`Set-Content guard\policy.yaml. x` 由 deny 变成问；配了后端时送审，模型看不到真实目标 | 问不要，送审要 | **修订 12 扩大的回退**（中间一段始于修订 11） |
| RV-2 | 中 | Git Bash 里 `work:s` 是另一个目录，key 却说是项目 `work`：`cat ../work:s/left.txt` 读到项目外，规则放行 | **不要** | 早就有，和 GR-1 同类，修订 12 没有覆盖 |
| RV-3 | 中 | `\\localhoſt\c$\proj\a.txt` 的 key 是 `c:/proj/a.txt` 且确定：规则放行，实际却走网络名字解析 | **不要** | 早就有，和 GR-2 同类（主机名比较仍用 `casefold`） |
| RV-4 | 低 | 大小写敏感目录里，项目 `work` 旁边的 `WORK` 是另一个目录，key 相同，规则放行 | 不要 | 早就有，和 GR-2 同类 |
| RV-5 | 低 | 记录里有四处说法不准，含"差分 0 条变松"的适用范围和第 6 节第 6、8 条 | | 这次的记录 |
| RV-6 | 低 | 验证碰不到磁盘层；折叠表依赖 Python 的 Unicode 版本，3.14 没量 | | 这次的验证 |
| RV-7 | 低 | 判断程序在不在系统目录时仍用 `casefold`：`/uſr/bin/cat a.txt`、`C:/Windowſ/System32/git.exe status` 都由规则放行（修复 RV-3 时才查到） | 不要 | 早就有，和 GR-2 同类 |

**影响范围。** RV-1 走的是 PowerShell 工具，这是这台机器的默认 shell，也在支持声明之内（`docs/platforms.md`）。它要求项目里已经有一个名字看不出目标的链接。RV-2 只在 Git Bash 作为 shell 工具时成立，Git Bash 不在支持声明里。boundkeep 不替用户批准，无决定之后 Claude Code 自己的权限流程还会接手，那一步没有量。

## 2. 发现

### RV-1（中）：带尾随点的路径不再看磁盘，经过链接时 deny 降级

**前提**：项目里有联接点 `guard`→`~/.boundkeep`、`keys`→`~/.ssh`、`cc`→`~/.claude`。下面是真实联接点、真实磁盘查询的判决。

| 写法 | `78127af` | `2f8f59d` | 现在，无后端 | 现在，有后端 |
|---|---|---|---|---|
| `Write <项目>\guard\policy.yaml`（对照，没有点） | | deny | deny | deny |
| PowerShell `Set-Content guard\policy.yaml. x` | | deny `protect-guard-config` | **问** | **送审，无决定** |
| PowerShell `Set-Content cc\settings.json. x` | | deny `protect-guard-config` | **问** | **送审，无决定** |
| PowerShell `Get-Content keys\config.` | | deny `no-secret-read` | **问** | **送审，无决定** |
| PowerShell `Set-Content keys\config. x` | | deny `deny-ssh-write` | **问** | **送审，无决定** |
| PowerShell `Get-Content k*\config.` | | deny | **问** | **送审，无决定** |
| PowerShell `Get-ChildItem keys.` | | deny | 问（`ask-shell-read-outside-project`） | 问 |
| Grep、Glob `path=<项目>\keys.`，Bash `ls keys.` | | deny | **问** | **送审，无决定** |
| `Read <项目>\keys.\config`（中间一段） | deny | 问 | 问 | 送审，无决定 |
| PowerShell `Set-Content guard.\policy.yaml x`（中间一段） | deny | 问 | 问 | 送审，无决定 |
| `Read ~\.ssh\id_rsa.`、`Read keys\id_rsa.`（路径或文件名本身命中规则） | | deny | deny | deny |

空格表示没有量。

**真实程序确实打开了目标**（假文件）：

| 程序 | `keys\config.` |
|---|---|
| PowerShell 5.1 `Get-Content`（带不带 `-LiteralPath` 都一样）、cmd `type`、Python `open` | **读到 `.ssh\config`** |
| PowerShell 5.1 `Set-Content 'guard\policy.yaml.' …` | **假策略文件被改写** |
| Node `readFileSync`、Git Bash `cat`、`ls`、`cd` | 找不到（保留那个点） |

本会话的宿主工具（Claude Code 桌面应用，版本没有记）：Read 和 Write 保留点，Write 真的创建了 `written.txt.`。Grep 和 Glob 去掉点：`path=sub.` 列出和读到的是 `sub` 里的文件，显示的路径却写 `sub.\…`。Grep 另有一次存在性检查，字面上没有 `only.txt.` 时报"路径不存在"。所以工具这条路的实际影响比 PowerShell 小，判决的降级仍然一样。

**模型看到的是**（有后端时，`Set-Content guard\policy.yaml. x`）：

```json
{"program": "set-content", "args": ["guard\\policy.yaml.", "x"],
 "paths": [{"path": "<project>/guard/policy.yaml", "access": "write", "inside_project": null}]}
```

没有任何地方提到 `~/.boundkeep`。假后端放行，结果就是无决定。真实模型会怎么答没有量。无后端时用户看到的确认框，理由里也只有项目里的路径。

**链接从哪来**：

| 智能体自己建 | 判决 |
|---|---|
| 联接点或符号链接指向 `~/.ssh`（`New-Item`、`mklink`、`ln -s`） | deny |
| 指向 `~/.boundkeep` | deny（`deny-link-to-guard-files`） |
| 指向主目录本身 | 无后端问，有后端送审 |

指向主目录时路径里还带着 `.ssh`、`.boundkeep`，名字规则挡得住：量过的 12 种读写里，只有 `Get-Content up\.claude\settings.json.` 从 deny 变成问。所以主要场景是链接已经存在：用户自己的 dotfiles、仓库自带的符号链接、之前批准过的一步。这是把它定为中而不是高的原因之一，另一个是无后端时还会问。

**原因**：

- `normalize/event.py:955-958`：只有路径确定（或只差短名）才查磁盘。
- `normalize/paths.py:1557-1559`：`_resolve_on_disk` 把 `trailing-dots-spaces-ambiguous` 当作阻塞原因。
- `normalize/paths.py:1499-1501`：`_expand_glob` 同样，通配符不展开。
- `normalize/event.py:1132`：不确定的路径不做目录扫描。

修订 12 让所有尾随点都算不确定，这些分支就都跳过了。而规格 §5.1 的方向规则是 deny 侧"可能匹配就算匹配"，"不确定"本来只该影响 allow 侧。

**建议**（没有试过）：只因尾随点而不确定的路径，继续走磁盘层，结果仍然标不确定：

1. `_resolve_on_disk` 和 `_refs_one` 不把这个原因当阻塞，加上解析后的 PathRef，保持 `uncertain`。
2. 两种读法都解析：去掉点的（Win32），保留点的（`\\?\` 加原文，Git Bash 和 Node 的读法）。
3. `_expand_glob`、`_scan_refs` 同样处理。
4. 回归测试用真联接点，覆盖最后一段和中间一段，覆盖 PowerShell、Bash 和文件工具，并加对应的变异。

### RV-2（中）：Git Bash 里的冒号是另一个目录

key 把 `work:s` 读成 `work` 的流 `s`，原因 `ads-stripped` 算确定（`normalize/paths.py:929-931`、`:134`）。但 Git Bash（Cygwin 系）把冒号映射成私有区字符 `U+F03A`，`work:s` 是一个普通的独立目录。

真实 Git Bash，项目 `work`，无后端：

| 命令 | boundkeep | 实际 |
|---|---|---|
| `mkdir ../work:s` | 无决定 `allow-mkdir-touch-inside-project` | 父目录多了 `work\uf03as` |
| `cat ../work:s/left.txt` | 无决定 `allow-cat-inside-project` | 读到项目外的文件 |
| `cd ../work:s && cat left.txt` | 无决定 `allow-cd-family`、`allow-cat-inside-project` | 同上 |
| `ls ../work:s`，`grep -r`，`head`，`wc -l` | 无决定 | 同上 |
| `touch ../work:s/new.txt` | 无决定 | 写到项目外 |
| `work\uf03as` 是通向私人目录的联接点：`cat ../work:s/notes.txt` | 无决定 | **读到私人目录**；`touch` 也写进去了 |
| `cat ../work:s/.env` | deny | 规则仍然命中 |

Node 和 Python 打不开这个路径（退出码 1）。本会话的 Read 打开 `<根>\sub:s\b.txt`、Grep 的 `path=<根>\sub:s` 都报不存在，而 `subs` 是存在的。所以只有 Git Bash 这条路。

13104 条写法的扫描里，能拿到规则放行的后缀只有冒号一类：`:s`、`:s.`、`:s `、`::$DATA`、`:s:$DATA`、`::$INDEX_ALLOCATION`、`:$I30:$INDEX_ALLOCATION`、`:s/x/..`。所有尾随点、空格写法都是 0；`/.`、`/x/..` 这些会折回项目的写法被放行，是对照，读的确实是项目。

**建议**（没有试过）：`ads-stripped` 在这两种情况下算不确定：bash 方言；流出现在非最后一段（Win32 反正打不开，代价为零）。同时从 `_PLAIN_REASONS`（`paths.py:366`）里考虑。代价是 Git Bash 里 `cat a.txt:s` 要问。

**更正（修复时实测）**："Win32 反正打不开"不全对。`dir::$INDEX_ALLOCATION\a.txt` 和 `dir:$I30:$INDEX_ALLOCATION\a.txt` 在 Python、Node、PowerShell 5.1、cmd 里都打得开，读的就是 `dir\a.txt`；`dir:s\a.txt`、`dir::$DATA\a.txt`、`dir:s:$INDEX_ALLOCATION\a.txt` 打不开。修复仍然标不确定，正常写路径用不到这种写法。

### RV-3（中）：主机名比较用 `casefold`，`ſ` 能冒充本机

GR-2 修了 key，没有修这两处：`normalize/paths.py:1068-1070`（`server.casefold() in _LOCAL_SERVERS`，以及与 `COMPUTERNAME` 比较）、`normalize/event.py:1092-1094`（`_unc_server`）。

假机器，`COMPUTERNAME=DESK-PC`，什么都没有打开（探针拦下了所有到文件系统的 UNC 字符串）：

| 路径 | key | Read、Write、`cat` |
|---|---|---|
| `\\localhost\c$\proj\a.txt`（对照） | `c:/proj/a.txt`，确定 | 无决定 |
| `\\localhoſt\c$\proj\a.txt` | **`c:/proj/a.txt`，确定** | **无决定，有无后端都一样** |
| `\\deſk-pc\c$\proj\a.txt` | **`c:/proj/a.txt`，确定** | **无决定** |
| `\\evil\share\x.txt`（对照） | | 问 `net-allowlist` |
| `\\localhoſt\share\x.txt`、`\\wſl$\Ubuntu\x.txt` | | 无后端问；有后端送审，**没有 `net-allowlist`** |

Windows 不这样读这个名字：`GetHostAddresses("localhoſt")` 报"不知道这个主机"，`Test-Path \\localhoſt\C$\Windows` 是 False，而 `localhost` 是 `::1, 127.0.0.1` 和 True。所以它走的是名字解析，不是本机。

风险和 G-5 相同：局域网里有人应答这个名字（LLMNR、NBNS）或 DNS 后缀被控制时，读这个路径会把 NTLM 发过去，写会把内容发过去。**这一步没有量**：这台机器上没有人应答，没有连接发生，所以我没有定为高。`2f8f59d` 判决相同。

**建议**（没有试过）：这几处比较都换成 `windows_fold`。

### RV-4（低）：大小写敏感目录

NTFS 可以按目录开启大小写敏感。`fsutil file setCaseSensitiveInfo` 在这台机器上成功了（没有查当前进程是否提权）；公开文档说 WSL 建的目录默认如此，没有量。

父目录开启后，`parent\work`（项目）和 `parent\WORK` 同时存在：

- key 相同，`inside_project` 是 True，`resolve_on_disk` 的 key 也没有变（它拿折叠后的 key 去解析）。
- PowerShell、Python、Node、Git Bash 读 `WORK\a.txt` 都读到了孪生目录。
- 假机器上 `Read`、`Write`、`Edit`、`Grep`、`Glob`、`cat` 写 `WORK\a.txt` 都是规则放行。
- 项目在 `\\wsl.localhost\Ubuntu\home\me\proj` 时，`…\PROJ\a.txt` 也是规则放行（只量了判决，没有打开，也没有确认那个共享大小写敏感）。

**建议**：可以先只记下来。要修的话，磁盘层用原文而不是 key 解析，再和项目的真实路径逐字比较；这也能兜住所有"key 合并了"的情况，包括 RV-6 里没量到的卷。代价是多一次 `realpath`，也没有试过。

### RV-5（低）：记录里不准的说法

`docs/reports/M3a-dots-and-folding.md`：

1. **第 1、2、5 节**："deny 不变""从 deny 降级或从问变成无决定的 0 条"。数字没错（重新核对了 `rr_diff12`），但差分在假机器上跑，没有磁盘，看不到 RV-1。记录写了孪生目录没覆盖，没有写磁盘层没覆盖。
2. **第 6 节第 6 条**："已经存下的 `trusted_projects` 要重新 `trust add`"，这是错的。`trust add` 存的是原路径（`trust.py:476,505`），key 在加载时算（`policy/schema.py:734`）。实测 `C:\Users\Weiß\p` 这个条目继续有效，`pytest` 是 `allow-devtools-trusted-project`。这个代价不存在。
3. **第 6 节第 8 条**："中间一段带冒号……NTFS 大概率打不开（没有量）"。Win32 确实打不开，但 Git Bash 打得开，见 RV-2。
4. **第 6 节第 3 条**只写了一个方向（别的文件系统把 `ſ` 和 `s` 算同一个）。反方向才是危险的：卷的表比 `casefold` 细（比如旧版 Windows 格式化的 NTFS，新增的大小写对不合并），key 就会把两个目录读成一个，是 GR-2 的原样。没有这样的卷可量。

另外 `docs/reviews/M3a-path-gate-rereview.md` 说修订 11"没有让判决变松"，同样只在假机器上成立：中间一段的降级从修订 11 开始（RV-1 的表），那次复审没看出来。

### RV-6（低）：验证的缺口

- **差分、变异和新测试都碰不到这条路径。** 差分 `scan_disk=False`。17 个变异没有一个针对带尾随点路径的磁盘查询。`test_m3a_dots_and_folding.py` 里 `scan_disk=True` 的只有真实同级目录和孪生目录，断言的都是"问"，没有一个经过链接；`test_m3a_path_gate_fixes.py` 也没有。所以全量全绿也发现不了 RV-1。
- **折叠表依赖 Python 的 Unicode 版本。** `windows_fold` 对表外字符调用 `str.casefold`，新版 Unicode 新增的大小写对不在表里，会被合并。实测（真实卷的类，下一节）：3.11（Unicode 14.0）、3.12（15.0）、3.13（15.1）都是 0 错误。3.14 本机没有，没量。`.python-version` 是 3.12，但 `requires-python` 没有上限，而对比测试在别的版本上直接跳过，出问题不会有提示。**建议**：改成"只折叠表里列出的字符"，不依赖 Python 的版本。

### RV-7（低）：系统目录的判断仍用 `casefold`

修复 RV-3 时才查到，所以上面"查过、没有问题的"一节里没有它。`normalize/event.py` 的系统目录判断（`low = text.casefold()`，供 `_canonical_program` 判断带路径的程序名）把 `ſ` 读成 `s`。假机器，无后端：

| 命令 | 判决 |
|---|---|
| `/usr/bin/cat a.txt`（对照） | 无决定 `allow-cat-inside-project` |
| `/uſr/bin/cat a.txt` | **无决定 `allow-cat-inside-project`** |
| `./bin/cat a.txt`（对照） | 问 |
| `C:/Windows/System32/git.exe status`（对照） | 无决定 `allow-git-read-only` |
| `C:/Windowſ/System32/git.exe status` | **无决定 `allow-git-read-only`** |

也就是说，`C:\Windowſ\System32\git.exe` 这个孪生位置上的程序会被当成系统里的 `git`。**前提**：那个文件要先存在，写到项目外本身要问；没有真的放程序跑过。所以定为低。

**建议**（没有试过）：这一处换成 `paths.windows_fold`，一行。

## 3. 布置的四个问题

**1. 还有写法让 key 说"确定在项目里"，文件在项目外，不要后端就放行吗？** 有：RV-2（Git Bash 冒号）、RV-3（主机名）、RV-4（大小写敏感目录）。尾随点和空格本身没有了。

**2. 两种折叠混用有没有放松 deny 或 ask？** 折叠本身没有。`casefold(windows_fold(c)) == casefold(c)` 对基本平面全部成立，所以 `path_glob` 看到的和以前一样。放松 deny 的是另一件事，尾随点改成不确定（RV-1）。逐处检查的结果在下一节。

**3. 修复者的验证有多大漏洞？**

- 假项目没有孪生字母：**影响为零**。补跑 5 台假机器（`work`、`Weiß\ss`、`fix\test`、`Ås`、`ва`），30720 条，2618 条变化，从 deny 降级或从问变成无决定的 0 条。
- 折叠表只按内核量过：**对 C: 影响为零**，见下一节。其他卷没量。
- 差分没有磁盘：**这个漏洞是真的**，它正好藏住了 RV-1。

**4. 记录属实吗？** 差分和 984 条的数字属实，第 6 节第 1、2、5 条属实。不实的见 RV-5。

## 4. 查过、没有问题的

| 查了什么 | 结果 |
|---|---|
| **真实卷的表**（C:，NTFS）：基本平面 63447 个名字全部建一遍，用 `realpath` 取卷保留的名字分类 | 973 个类不止一个名字。一个 key 对两个类：**0**。一个类两个 `casefold`（deny 可能漏）：**0**。ASCII 和别的字符被卷合并：**没有**。一个类两个 key：27 组，都是带下标 iota 的希腊字母，与记录相同 |
| `windows_fold` 的性质（基本平面全部） | 一个字符折成多个：0；不幂等：0。基本平面之外 260 个有大小写的字符，卷都不合并 |
| 尾随点和空格（36 种后缀 × 7 种拼法 × 3 种结尾 × 18 种工具和命令，13104 条） | 规则放行 0 条。包括 `cd … && cd ../work && cat`、`git -C`、`rg`、`find`、`pushd` |
| `Weiß` 下的代价：同样的 120 个判决对比无表内字符的用户 | **0 处不同**，含 memory、tool-results、scratchpad、会话记录。"不增加代价"属实 |
| `session/marks.py:location_key` | 仍然 `casefold`。孪生目录的标记算到项目上，多问不少问；不确定的写打项目标记（`conftest.py.`）；`clear_marks` 两边都走 `location_key`，能清掉 |
| `audit/send_gate.py:_Places` | 项目和主目录的 key 都用 `windows_fold`，`<project>`、`~` 相对形式正常，没有把 `Weiß` 的路径原样发出去 |
| `normalize/subtree.py` | `casefold` 只用在保护规则的匹配和命中的 key 上，都是 deny 侧 |
| `_expand_glob` 换成 `windows_fold` | PowerShell 5.1 和 cmd 的通配符都不把 `ſ` 当 `s`（`.ſſ*` 找不到 `.ssh`，`.s*` 找得到），所以改得对。`[char]::ToUpper('ſ')` 在 zh-CN 下虽然是 `S`，通配符不受影响 |
| `SessionDir`、`memory_for`、`_comparison_key`、`policy/schema.py:625`、`devtool_exe_in_env` | 读过代码，没有放松。`memory_for` 的 `casefold` 只会少算 slug，`devtool_exe_in_env` 的目录本来就在项目里 |
| 重跑 | 新测试 129 通过；key 稳定性 108 万次 0 不稳定。变异 17/17 是读的输出，没有重跑 |

## 5. 没有查

- 真实 Claude Code 的 hook 链路。宿主工具只是用本会话的工具试了读法，hook 没有参与。
- E:、D: 两个卷（约束是文件只放 scratchpad，它在 C: 上）。这个仓库就在 E: 上。FAT、exFAT、ReFS、SMB、旧版 Windows 格式化的卷。
- 名字解析真有人应答时的连接和 NTLM（RV-3）。
- 真实模型对 RV-1 请求的回答。
- Python 3.14。macOS、Linux。
- Cygwin 的其他行为（`.exe` 后缀、`.lnk` 当符号链接）；非 Unicode 程序的 best-fit 转换。
- 这里的修法建议都没有试过。RV-1 的修法会动磁盘层的预算路径，要单独量。

## 6. 建议顺序

1. **修 RV-1**：唯一的回退，在默认 shell 上，接后端之前必须修。
2. **修 RV-3**：改动最小，几处比较。
3. **修 RV-2**：要改规格 §5.1。
4. 修 RV-1 时一起补真联接点的测试，并让差分能跑在真实磁盘上（RV-6），再改表的依赖方式。
5. 改记录里不准的地方（RV-5）。
6. RV-4 先记下，由使用者决定。

上一轮留下的 GR-3、GR-4、GR-5 还在，这次没有动。
