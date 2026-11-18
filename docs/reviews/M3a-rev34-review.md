# 规格修订 34 的复审

日期：2026-11-17。代码：`7da4687`（`main`，与 `origin/main` 相同；代码提交是 `0834756`）。

审查对象（`git show 0834756 -- src`）：
- `audit/send_gate.py`：
  - 路径的边界 `_PATH_AFTER_DRIVE`、`_PATH_AFTER_WINDOWS`、`_PATH_AFTER_POSIX`；
  - UNC 的左边界 `_BEFORE_UNC`，`_home_pattern` 分开的两组，`_option_of`；
  - `_Places.home_begins_before`、`_word`。
- 规格开头修订 34 的段落，`docs/privacy.md`、`docs/threat-model.md` 对应的几句。记录是 `docs/reports/M3a-rev33-review-fixes.md`。

**这不是独立复审。** 修订 34 是这个会话写的，使用者说"复审修订34"。下面的结论都重新量过，没有照搬记录里的说法。为了少一点作者的盲点，另请了一个子代理单独找错。只给了它代码和规格，没给记录、复审报告和提交说明。它报的每一条都在这个会话里重新量过才写进来（表里的"谁发现"一列）。

**本次改了什么**：
- 新增这份报告。
- 状态说明里加了指向这份报告的几行。
- 没有改 `src`、规格正文、策略、测试和脚本。

**本次没有做的事**：
- 没有读 `.env`，没有用 LLM 密钥，没有访问真实 LLM 服务。
- 没有读 `eval/authoring/h1-*`、`h2-*` 和留出批次，没有改系统设置。子代理也按这几条做，没有改仓库。
- 没有跑 `claude`，没有跑全量：只读代码，跑相关测试，探针都在 scratchpad 里。
- 没有在任何盘的根目录下建文件或目录。

**怎么量的**：
- 记录里的数字：对 scratchpad 里的原始输出重新算了一遍（语料逐行比、探针汇总、两轮变异、全量六段）。新测试在 `9d041b6` 的代码上重跑，速度脚本重跑。
- 命令全文和路径词：`rv34r_text.py`，新代码和 `9d041b6` 的代码在同一个进程里各加载一份，脚本报出两份文件的路径并核对，17 条。每个路径再用 `GetFullPathNameW` 读一次（只做字符串变换，不访问网络）。
- 整条链路：用测试里的假后端（`FakeBackend`）走完整条 `pipeline.decide`，看判决、送不送审和请求。
  - `rv34r_chain.py`，12 条；
  - `rv34r_agent.py`，9 条（子代理的发现，有两条是 POSIX 的主目录）；
  - 新代码和 `9d041b6` 各跑一次，脚本核对加载的是哪份代码，不对就停。
- 主目录是测试用的 `C:\Users\testuser`、`/home/testuser`，和编出来的 `\\server\share\testuser`。
- 规格说"按路径的边界找不出更多"：`rv34r_fuzz.py`，随机 33.6 万个词。
- 子代理：脚本在 scratchpad 的 `rv34-agent\` 下，每个脚本都报出加载的是哪份代码。它另做了一张整条链路的网格：12 个程序 × 17 种选项写法 × 各种主目录的写法 × 8 种后缀，两种 shell，共 31008 次调用，新旧代码比。

下文的说法：
- "主目录"：探针里的那几个。
- "多换"：不是主目录的写成了 `~`。"少换"：是主目录的没有换，用户名随请求发出。
- "路径原文"：规则层记下的路径的原样文字（`PathRef.raw`）。
- "盘符的冒号"：紧跟在一个单独的字母后面、这个字母又在词的开头或非字母数字后面的 `:`，如 `C:`。

## 1. 结论

**修订 34 的目标达到了：R33-1、R33-2、R33-3 都修好了，没有发现放行，判决和送不送审都没有变。但 R33-3 的左边界排除 `:` 太宽：UNC 主目录写在冒号选项（`/OUT:`、`/LIBPATH:`、`-Path:`）或 `FileSystem::` 后面时不再换，比修订 33 少换，真实的 `link /OUT:\\server\…` 会送审（R34-1）。另有几句规格和记录的说法不准（R34-2），以及一条原来就有的少换（R34-3）。**

- R33-1：`-Wl,-rpath,<主目录>,-z,now`、`-DCMAKE_PREFIX_PATH=<主目录>;…` 在 `args`、`flags` 里是 `~`。子代理的网格里，这一类只有变好的。代价和规格写的一样：`make --directory=~,x`。
- R33-2：`/c`、`/cygdrive`、`/mnt`、`-C:`、主目录 `/root` 都不再从中间切开；`/srv/home/<名字>/x` 原样。子代理另找到一条变好的：PowerShell 的 `gcc -IC:\Users\<名字>\inc,x`，规则层记下的路径原文是 `:\Users\…`，修订 33 的 `args` 带着用户名，修订 34 是 `-I~\inc,x`。
- R33-3：`C:\\server\…`、`.\\server\…` 原样。
- 记录里的数字都对得上；有几句说法不准（R34-2）。
- 相关的 11 个测试文件跑了 4 次：3 次 604 passed，第一次 1 failed、603 passed（见第 3 节）。

**高危 0，中危 0，低危 1，信息 2。**

| 编号 | 级别 | 一句话 | 要后端吗 | 谁发现 | 来源 |
|---|---|---|---|---|---|
| R34-1 | 低（隐私，比修订 33 少换） | UNC 带反斜杠的写法前面是 `:` 就不换，不分是不是盘符的冒号：`/OUT:`、`/LIBPATH:`、`/Fe:`、`-Path:`、`FileSystem::` 后面的主目录随 `command`、`args`、`flags` 发出 | 要 | 两边都发现 | 修订 34：R33-3 的左边界排除 `:` |
| R34-2 | 信息（文档） | 几句说法不准：`\\?\UNC\…` 粘着选项时也送审；"按路径的边界找不出更多"有反例（结果相同）；`java -cp` 的例子在 Windows 上不送审；记录说"前面是 `:` 几乎都是盘符"；`docs/privacy.md` 漏了 `:` | 不涉及 | 两边都发现（各几句） | 修订 34 的文字 |
| R34-3 | 信息（原来就有） | 路径原文从粘着的选项中间开始时也切开：`cp -isystem/home/<名字>/inc` 的 `args`、`flags` 带着用户名 | 要 | 子代理 | 修订 33 起 |

R34-1、R34-3 只在有后端时才有影响，改的都只是请求里的文字。

## 2. 发现

### R34-1（低，隐私，比修订 33 少换）：UNC 前面的 `:` 不分是不是盘符的冒号

`_BEFORE_UNC` 规定 UNC 带反斜杠的写法前一个字符不能是 `:`。规格修订 34 给的理由只有 `C:\\server\…`（C 盘上的目录）。但 `:` 后面直接接 UNC 路径的写法还有：
- MSVC 和链接器带冒号的选项：`/OUT:`、`/LIBPATH:`、`/PDB:`、`/Fe:`、`/Fo:`；`robocopy` 的 `/LOG:`；
- PowerShell 的 `-Path:<值>`；
- PowerShell 带提供程序的路径：`FileSystem::\\server\share\…`、`Microsoft.PowerShell.Core\FileSystem::\\…`。

粘着的选项那一支是 `(?:--?|/)[A-Za-z]+`，后面不带 `:`，这些都不算；另一支又排除 `:`，所以都不换。修订 33 用的是盘符写法的左边界（只排除字母、数字、下划线），这些都换。

整条链路，新代码和 `9d041b6` 各跑一次，主目录 `\\server\share\<名字>`：

| 写的 | `command`、`args`：修订 34 | 修订 33 | `paths` | 送审吗 |
|---|---|---|---|---|
| PowerShell `link /OUT:\\server\share\<名字>\a.exe a.obj` | 原样，带用户名 | `/OUT:~\a.exe` | `c:/out/server/share/<名字>/a.exe` | 送 |
| PowerShell `link /LIBPATH:\\server\share\<名字>\lib a.obj` | 原样 | `/LIBPATH:~\lib` | `c:/libpath/server/share/<名字>/lib` | 送 |
| PowerShell `cl /Fe:\\server\share\<名字>\a.exe a.c` | 原样 | `/Fe:~\a.exe` | `c:/fe/server/share/<名字>/a.exe` | 送 |
| PowerShell `gcc '-o:\\server\share\<名字>\a.exe' a.c`（写法是编的，看机制） | 原样，`flags` 也原样 | `-o:~\a.exe` | `<project>/server/share/<名字>/a.exe` | 送 |
| Git Bash `link.exe '/OUT:\\server\share\<名字>\a.exe' a.obj` | 原样 | `/OUT:~\a.exe` | `/OUT:/server/share/<名字>/a.exe` | 送 |
| PowerShell `make release # then link /OUT:\\server\share\<名字>\a.exe` | `command` 原样 | `/OUT:~\a.exe` | 无 | 送 |
| PowerShell `python -c "print(r'FileSystem::\\server\share\<名字>\x')"` | 原样 | `FileSystem::~\x` | 无 | 送 |
| PowerShell `Get-Content FileSystem::\\…`、`Get-Content -Path:\\…`、`robocopy … /LOG:\\…` | — | — | — | 不送（网络访问，问） |

- 前五行是真实的调用。规则层把 `/OUT:…` 读成当前盘上的路径（`c:/out/…`），不是网络访问，所以送审。
  - `paths` 本来就带着小写的用户名，修订 34 多发出去的是原来的大小写。
  - 和修订 33 的复审 R33-1 同一类：规则层的读法本来就不准。
- 后两行是注释和字符串，`paths` 里没有用户名，修订 34 只在 `command`、`args` 里把它发了出去。修订 33 不会。
- 子代理的网格：31008 次调用里，新代码带着用户名、旧代码没有的，只有这一类（UNC 主目录写在 `/X:` 后面，360 次）。
- 盘符的主目录不受影响：盘符写法的左边界不排除 `:`，`link /OUT:C:\Users\<名字>\a.exe` 两版都是 `/OUT:~\a.exe`。
- 规格修订 34 说"粘着选项的（`/I`、`-L`）照旧"；规格修订 33 列的选项形状本来就包括 `-Path:` 这种带冒号的。代价里没有写这一条。
- 记录第 3 节说"UNC 写法前面是 `:` 时，几乎都是盘符后面多写了一个反斜杠"，不准。这是修订 33 的复审给建议时没有量冒号选项，记录照着写了。
- 两种 UNC 写法现在相反：正斜杠写法前面是 `:` 照样换，连 URL 里的也换（`http:~/x`）；反斜杠写法前面是 `/OUT:` 却不换。
- **建议**：只排除盘符的冒号。左边界改成 `(?<![\w./\\~])(?<!(?<!\w)[A-Za-z]:)`：前一个字符不是字母、数字、下划线、`.`、`\`、`/`、`~`，也不是"词开头的一个字母加 `:`"。
  - 两边各自试过：`C:\\server`、`c:\\server`、`-C:\\server`、`.\\server` 仍不换；`/OUT:`、`/LIBPATH:`、`/LOG+:`、`-Path:`、`FileSystem::`、`=`、空格后面的换。
  - 先改规格（修订 35），补测试，跑变异。判决和送不送审不变。

### R34-2（信息，文档）：几句说法不准

1. 规格修订 34 的 R33-4 一段说"真去访问这些路径的，规则层按网络访问问，不送审；会送审的只有注释、字符串里的"。粘着选项时不成立（两版一样）：
   - PowerShell `link /OUT:\\?\UNC\server\share\<名字>\x.exe a.obj`、`gcc '-Wl,-rpath,\\?\UNC\server\share\<名字>\lib' a.c` 都送审，`command`、`args`、`flags`、`paths` 都带着用户名；
   - 规则层把它们读成本地的相对路径；
   - 单独的 `Get-Content \\?\UNC\…` 是网络访问，问，不送审，和规格一致。

   和修订 33 的复审更正过的"UNC 主目录下的路径不送审"是同一类。
2. "按路径的边界找不出更多"（规格修订 34 的 R33-2 一段、记录第 2 节和第 5 节、`home_begins_before` 的注释、提交说明、`CLAUDE.md`）字面上不成立。
   - 反例：Windows 的主目录，词 `/cygdrive/c/Users/<名字>\x`，前面那段 `/cyg`，路径原文 `drive/c/Users/<名字>\x`。斜杠写法后面是 `\`，只有路径的边界算结束，所以只有它找到"主目录从前面那段里开始"。
   - 推理漏了一种：`/` 开头的前面那段是第一段的一部分，路径原文就不以 `/` 开头。
   - 结果相同：切开时路径原文里认不出主目录，不切时命令全文也不换（Git Bash 里 `\` 是转义，规格修订 32），两种都原样。子代理随机找到的 100 个反例，`_word` 的结果都一样。
   - 我自己的随机比对选项清单里只有整段的 `/cygdrive`，没有 `/cyg` 这种前缀，所以 33.6 万个词 0 条反例。
   - 应改成："多找到的只有这一种，切不切结果相同"。
3. 规格修订 34 拿 `java -cp /c/Users/<名字>:/x` 做 R33-1 变好的例子。
   - 在 Windows 的 Git Bash 里，这条两版都不送审：路径里有 U+F03A，拒绝。记录第 4 节写了。
   - 只在 POSIX 上换：`java -cp /home/<名字>:/x Main` 的 `args` 修订 34 是 `~:/x`，修订 33 原样。但 `paths` 两版都是 `/home/<名字>:/x`：规则层把它读成一个兄弟目录，用户名照样发出。
4. 记录第 3 节"UNC 写法前面是 `:` 时，几乎都是盘符后面多写了一个反斜杠"（见 R34-1）。
5. `docs/privacy.md` 说规则层读成路径的词和选项后面的路径"只认分隔符、`,`、`;` 和行尾"，漏了：
   - `:`：盘符写法从修订 32 起，斜杠写法从修订 34 起；
   - 盘符写法的单个尾随点。

- **建议**：和 R34-1 一起改文字。

### R34-3（信息，原来就有）：路径原文从粘着的选项中间开始

- POSIX 的 `cp -isystem/home/<名字>/inc a.c`：规则层把 `cp` 的短选项拆开（`-i -s -y -s -t`），`-t` 的值是 `em/home/<名字>/inc`，这就是路径原文。
- `_word`：前面那段 `-isyst` 合选项形状；路径原文不以 `/` 开头；主目录的写法连粘着的 `-isystem` 从 0 开始，但主目录本身从第 8 个字符开始，不在切开的地方（第 6 个）之前。所以切开，路径原文里 `/home/<名字>` 前面是 `m`，不换。
- 结果：`args`、`flags` 带着用户名；`command` 是 `-isystem~/inc`；`paths` 是 `<project>/em/home/<名字>/inc`，本来也带着。`9d041b6` 一样。
- `gcc -isystem/home/<名字>/inc` 没有问题（`-isystem~/inc`）。
- 子代理试了 80 个真实的编译器和工具选项，没有找到会这样的；只有没有意义的短选项串会。
- **建议**（可选）：切开的地方落在主目录写法粘着的选项中间（`m.start() < cut < m.start() + len(option)`）时也不切。`-isystem` 加 `/home/…` 这种正常的不受影响（切开的地方正好是选项的末尾）。可以和 R34-1 一起改，也可以只写进规格。

## 3. 核对过、没有问题的

| 检查 | 结果 |
|---|---|
| 记录里的数字 | 都和 scratchpad 里的原始输出对得上：<br>- 语料 4906 行，和修订 33 的输出逐行逐列相同（级别、送审、请求哈希）；`gray-sent` 2009 次。<br>- 探针汇总：86 条，判决 0、送不送审 0 变化，请求没变 77 条、变了 9 条。<br>- 变异：第二轮 7 个、最终 70 个全部抓到。<br>- 全量六段：30375 passed、169 skipped、0 failed，合计 30544。<br>- 速度重跑：都不到 0.4 毫秒（最慢 0.339 毫秒） |
| 新测试在 `9d041b6` 上 | 重跑：40 failed、25 passed（先确认加载的是旧代码树里的 `send_gate`） |
| R33-3 | `C:\\server\share\<名字>\x` 在字符串里送审，`command`、`args` 原样，和规格一致 |
| 子代理的网格 | 31008 次调用：新代码比旧代码多带用户名的只有 R34-1 一类；输出变了的都伴随用户名位置的变化，没有新的多换 |
| `args` 与 `flags` | 一致：同一个 `_word`，同一组路径原文 |
| `/` 选项后面的 `//server/…` | `cl /I//server/share/<名字>/inc`：整条链路两版相同（规则层记下的原文是整个词），和规格"斜杠写法前面只认 `-`、`--` 开头的选项"一致 |
| 奇怪的主目录 | `C:\`、`/`、`\\server\share`、`\\?\C:\…`、带正则元字符的、带 `İ` 的、`None`：都没有异常（子代理）。`_option_of` 在 POSIX 和只有 UNC 写法的主目录上不出错 |
| 速度（子代理） | 64 个 400 字符的刁钻词 × 16 个路径原文，最多 5 毫秒；6 万次随机里单次 `_word` 最慢 1.75 毫秒 |
| 相关测试 | 11 个文件（新文件、`test_m3a_rev32_review_fixes.py`、`test_m3a_rev31_review_fixes.py`、`test_m3a_rev30_review_fixes.py`、`test_m3a_send_gate.py`、`test_m3a_rev29_review_fixes.py`、`test_m3a_review_fixes.py`、`test_m3a_x1_fixes.py`、`test_m3a_auditor.py`、`test_m3a_daemon.py`、`test_m3a_pipeline.py`），跑了 4 次：<br>- 第一次 1 failed、603 passed，那次没有打开失败摘要，没记下是哪一条；<br>- 后 3 次都是 604 passed。<br><br>全量（`0834756` 的代码）这些文件都通过。像是偶发的，没有查出是哪一条 |
| 文档 | `docs/threat-model.md` 的一句和代码一致；`docs/privacy.md` 见 R34-2 |

**没有查的**：
- 真实的 `link.exe`、`cl.exe` 怎么读 `/OUT:\\server\…`：按 MSVC 选项的写法推，没有跑。
- 真实的模型看到这些文字会怎么理解（M3b）。
- PowerShell 7、Linux、macOS；真的 UNC 配置文件。
- 第一次相关测试里失败的是哪一条。
- 规则层把 `/OUT:…`、`-Wl,` 读成本地相对路径、Git Bash 里 `:` 成了 U+F03A，是规则层的事，这次没有看。

## 4. 建议的顺序

1. R34-1 改代码：UNC 带反斜杠写法的左边界只排除盘符的冒号。先改规格（修订 35），补测试（冒号选项、`FileSystem::`、`C:\\server` 仍不换），跑变异。判决和送不送审不变。
2. R34-3 可以一起改（可选）。
3. R34-2 只改文字：规格修订 34 的几句、修订 34 记录的几句、`home_begins_before` 的注释、`docs/privacy.md`。
