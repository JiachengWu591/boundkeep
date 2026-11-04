# Windows 设备路径不送审（规格修订 10）

日期：2026-11-02 到 11-03。基线：`41bfac6`。依据：`docs/reports/M3a-prefix-folding.md` 第 5 节第 1 条。使用者说"修设备路径"（我的建议是"让这些路径不送审、直接问"）。没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次；所有判决用的都是假后端，路径只是字符串，没有打开任何路径，没有执行任何命令。

## 1. 结论

**后来的更正（2026-11-04）**：独立审查（`docs/reviews/M3a-path-gate-review.md`）发现这里的 `NUL` 豁免仍然放过普通文件（`\\.\C:\Users\bob\.ssh\nul`、`C:\x\nul\.`）。原因是我用 `GetFullPathNameW` 当依据，它不代表打开时的读法：下面第 3、4 节关于"Win32 读成 `NUL`"的说法都要这样读。修订 11 已缩小豁免，见 `docs/reports/M3a-path-gate-fixes.md`。

**已修，已提交并推送（`2f0f009` 代码，文档在其后一个提交；未打标签）。** 配置了 LLM 后端时，碰到 Windows 设备路径的灰色调用不再送审，直接问（`decided_by: gray-device-path`）。`NUL` 例外。没有后端时结果不变（灰色本来就问）。全量结果见第 5 节。

**比原来说的范围大两处，都是实测之后才发现的**（第 4 节）：

- `\\.\C:` 打开的是整个卷，key 却是 `c:/`，标为确定，`dd of='\\.\C:'` 可以被模型放行。现在 key 是 `//./c:`，也不送审。
- 我最初按 key 豁免 `NUL`，这样是错的：`...\Startup\nul.bat` 的 key 也是 `//./nul`，在 Windows 11 上却是普通文件，模型可以放行写入启动目录。现在只豁免 Win32 确实读成 `NUL` 的写法。这个漏洞在我改之前就有，只是原来所有灰色调用都送审，它没有单独显现。

LLM 层至今没有接过真实服务，所以目前没有用户受影响；我只用总是放行的假后端测过，真实模型会怎么回答不知道。

## 2. 修改前后

假后端（总是放行），`enforce`：

| 写法 | 修改前 | 修改后 |
|---|---|---|
| `\\.\GLOBALROOT\Device\Mup\srv\share\x`（Read、Write、Edit，三种前缀） | 无决定，`llm`，送审 1 次 | 问，`gray-device-path`，不送审 |
| `\\?\Volume{1234}\x`、`\\.\HarddiskVolume1\x`、`\\.\pipe\x` | 同上 | 同上 |
| `\\.\COM1`、`COM1`、`CON` | 同上 | 同上 |
| `\\.\C:`、`\\?\C:`、`\??\C:`、`dd if=x of='\\.\C:'` | 同上（key 是 `c:/`，标为确定） | 同上（key 是 `//./c:`，不确定） |
| `...\Startup\nul.bat`、`nul.txt`、`nul:x`、`\\srv\share\nul` | 同上 | 同上 |
| `aux.py`、`src/con.py`、`C:\proj\aux` | 同上 | 同上（代价，第 6 节第 1 条） |
| `foo '\\.\pipe\x'`、`foo --out='\\.\pipe\x'`、`foo > '\\.\pipe\x'`、`foo a.txt && bar '\\.\pipe\x'` | 同上 | 同上 |
| `NUL`、`\\.\NUL`、`C:\proj\NUL`、`foo > NUL`、`foo 2>NUL`、`foo > /dev/null` | 无决定，`llm` | **不变** |
| `ps aux`、`foo con`、`make con`、`foo --name=con` | 无决定，`llm` | **不变**：普通的词不算路径 |
| `\\.\C:\`、`C:\`、`\\.\D:\data\x.txt` | 无决定，`llm` | **不变**：是目录或文件，不是卷 |
| `\\.\PhysicalDrive0` | deny，`no-raw-disk-access` | **不变** |
| `\\.\UNC\srv\share\x` | 问，`net-allowlist` | **不变** |
| `rm -rf '\\.\C:'` | deny，`rm-outside-project` | **不变** |

## 3. 修法

- **`src/boundkeep/daemon/pipeline.py`**：`device_path(actions)`：任何路径的 key 在 `//./` 之下、又不是确实的 `NUL`，这次灰色调用就不送审。理由和审计记录里不写路径，因为它们进审计日志。这不是审计失败，不按 `on_failure`，也不消耗污染窗口（有测试，对照组是污染一步自己造成的询问）。
- **`src/boundkeep/normalize/paths.py`**：
  - `\\.\C:` 这样盘符后面什么都没有的写法，key 是 `//./c:`，不确定，是设备。`\\.\C:\` 仍是 `c:/`。Win32 折叠之后只剩盘符的（`\\.\foo\..\C:`）同样处理。（更正，2026-11-04：这里原来写"`\\.\C:\.` 实际是根目录"，错了，它的 NT 路径是 `\??\C:`，就是卷；真正谨慎地按卷算的是 `\\.\foo\..\C:\`。）
  - 名字不只是设备名的（`aux.py`、`nul .txt`）加理由 `device-name-suffix`。`nul:x` 已经带 `ads-stripped`。
- **`NUL` 的豁免是白名单**：key 恰好是 `//./nul`，并且路径上的理由都在 `device:NUL`、`device-prefix`、`extended-prefix`、`nt-prefix`、`trailing-dots-spaces` 之内。其他任何理由（`unc`、`ads-stripped`、`device-name-suffix`、`prefix-path-folded`、变量、通配符）都不豁免，所以新的理由只会多问，不会多放。
- **规则与策略没有改**，规格修订 10 写在 §7 与 §9.2。

## 4. 测量

`GetFullPathNameW`，Windows 11 build 26200（纯词法，不碰磁盘和网络）：

| 写法 | Win32 的结果 | key | 真的是设备吗 |
|---|---|---|---|
| `nul`、`NUL`、`nul.`、`nul ` | `\\.\nul` | `//./nul` | 是 |
| `C:\proj\nul`、`src/nul`、`..\nul` | `\\.\nul` | `//./nul` | 是：`NUL` 在哪个目录都算（更正，2026-11-04：说宽了，目录不存在时打不开，`0xC0000033`） |
| `nul.txt`、`nul.bat`、`nul .txt`、`nul:x` | 普通路径 | `//./nul` | **不是** |
| `C:\proj\nul.txt`、`...\Startup\nul.bat` | 普通路径 | `//./nul` | **不是** |
| `\\srv\share\nul` | 普通的 UNC 路径 | `//./nul` | **不是** |
| `aux`、`con`、`prn`、`com1`、`lpt1` | `\\.\aux` 等 | `//./aux` 等 | 是 |
| `aux.py`、`src\aux`、`C:\proj\aux`、`C:\proj\con`、`src\com1.txt` | 普通路径 | `//./aux` 等 | **不是** |
| `C:\proj\aux\x` | 普通路径 | `c:/proj/aux/x` | 不是（带 `device-component`，不确定） |
| `\\.\C:` | `\\.\C:` | `//./c:` | 是：卷 |
| `\\.\C:\` | `\\.\C:\` | `c:/` | 不是：根目录 |

这张表只代表这一个版本。旧版 Windows 上 `aux.py` 也是设备，所以 M1 才写成这个 key；新版的读法没有让这个 key 变得更对，只是让第 6 节第 1 条成立。`\\.\C:` 打开的是卷这一点是公开资料的说法，`GetFullPathNameW` 只说明它不是 `\\.\C:\`，我没有真的打开过。

## 5. 度量

| 项目 | 结果 |
|---|---|
| 新测试，修改之前 | 80 failed, 26 passed（106 条，当时的版本） |
| 只按 key 豁免 `NUL` 时，补上"看起来像 `NUL` 的文件"之后 | 33 failed, 156 passed（189 条）。这 33 条就是第 1 节说的漏洞 |
| 新测试修改后 | 189 passed |
| 相关测试（新文件、`test_norm_prefix_folding.py`、`test_norm_paths.py`、`test_m3a_low_residuals.py`、`test_m3a_review_fixes.py`、`test_m3a_x1_fixes.py`、`test_m3a_rev8_window_fork.py`、`test_m3a_rev8_sources_marks.py`） | 1226 passed, 5 skipped |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过；77 个源文件没有问题 |
| `boundkeep test` default / strict | 1138 / 0 失败，334 / 0 失败 |
| 压力测试：20 万条带前缀的路径（固定种子，只看修改后） | 崩溃 0，不稳定 0，与 Win32 不一致却标为确定 0。不一致的 5012 条全部标为不确定（上次 4856 条，多出来的是 `\\.\C:\.`、`\\.//D:\` 这类谨慎读成卷的写法） |
| 全量 `uv run pytest -q` | **1 failed, 27411 passed, 169 skipped**（1:17:40）。失败的那条与这次修改无关，已修（`e976a03`），之后没有再跑全量，所以这份代码还没有一轮全量完全通过。经过见本节末尾 |
| 评测（命令同 `M3a.md`，输出到 scratchpad） | `rules-only.json`、`rules+taint.json` 除日期与延迟外**完全相同**；`report.md` 只有运行日期和 4 行延迟不同。`eval/` 没有改动，不重新生成。这在预料之中：这两种配置都没有后端，闸门不起作用；dev、test 里带前缀的样本盘符后面都有路径，key 不变。没有打开留出批次；查这一点时我的 grep 排除写错了，输出里多了两行计数：h1、h2 的 `path-evasion.jsonl` 各有一行匹配带前缀的写法。没有看到内容，这两批本来也已被污染 |

新测试：`tests/unit/test_device_paths_not_sent.py`（判决，Read、Write、Edit、Bash、PowerShell；豁免的写法与 `GetFullPathNameW` 一致，只在 Windows 上跑；普通的词不受影响；规则仍然在前面；没有后端时不变；`audit-only`；理由不带路径；污染窗口）；`tests/unit/test_norm_paths.py` 加 8 行；`tests/unit/test_norm_prefix_folding.py` 的 Win32 一致性加 4 条。

全量跑了三轮：

1. 第一轮是我自己停的：跑的过程中量出 `NUL` 的豁免是错的（第 1 节），代码要改。
2. 第二轮在会话的后台 shell 里跑（代码页 65001），开始时已是最终代码。跑到 96%、0 失败时中断。应用的通知只说会话结束前它没有跑完；系统日志里没有重启和睡眠，真正的原因没有查实。没有汇总行，不算结果。
3. 第三轮改在终端面板里跑（代码页 936），这样不随会话结束。跑完，就是上表的结果。

失败的是 `tests/unit/test_norm_psaliases.py::test_every_abbreviation_resolves_like_the_real_binder`。这条测试用 `-like '*ambiguous*'` 和 `-like '*cannot be found*'` 给 PowerShell 的报错分类，只认英文。这台机器上 PowerShell 的界面语言随代码页变：936 下是 `zh-CN`，65001 下是 `en-US`。所以中文报错全部分类失败，报了 23899 个问题。同一份代码只跑这一条：65001 下 `1 passed`，936 下 `1 failed`。这是测试的问题：这次修改没有碰这条测试和它测的 `psaliases.py`，`src/` 里也没有按报错文字判断的同类写法；我没有在更早的提交上跑过 936。

使用者说"先修再提交"。`e976a03` 在这条测试的 PowerShell 脚本开头把线程的界面语言设成 `en-US`。修好之后，整个 `test_norm_psaliases.py` 在 936 和 65001 下都是 465 passed。我提议不再跑全量，只跑这个文件。

因此，这份代码的测试结果要合起来看：这一条修好之后只跑过这个文件；最后 4% 的测试只在 936 下跑过；其余的测试两轮都没有失败。

## 6. 残余

1. **文件名恰好是设备名的路径，key 把真实位置藏起来了**（这次发现，修改之前就有，没有修）。`C:\Users\bob\.ssh\aux`、`...\Startup\aux.bat`、`\\srv\share\aux.txt` 的 key 都是 `//./aux`，所以按路径写的规则匹配不到：本该 deny 的变成问，没有 UNC 的网络规则。这次修改之后这些调用都是问，不会被模型或规则悄悄放行。
   - 代价：配置了后端时，`cat src/aux.py` 也要问。这种文件名在 Windows 上少见，但确实存在。
   - 可能的修法：名字带后缀或在目录里的，key 写真实路径、标为不确定（与 `prefix-path-folded` 同样的做法），rules 就能匹配，模型也看得到真实路径。要改 M1 的路径规范化和一批表项，由使用者决定。
2. **卷是问，不是 deny**：`no-raw-disk-access` 只列了 `//./physicaldrive*`，`//./c:`、`//./harddiskvolume*`、`//./volume{...}` 不在里面。写卷和写物理磁盘同样危险。加进去要改规则，评测要重取，由使用者决定。
3. **POSIX 没有动**：`/dev/input/event0`、`/dev/shm/x`、`/sys/kernel/x`、`/dev/stdin` 照常送审（`/dev/sda`、`/dev/mem` 有规则 deny，`/dev/tcp` 有网络规则）。
4. **只看 `Action.paths`**：归一化认不出的路径（`foo $P`、`python -c` 里的字符串）不算。这与其他规则的局限相同，这次没有单独测。
5. **`NUL` 的写法只在 build 26200 上量过**：豁免测试只断言"豁免的写法 Win32 读成 `NUL`"，这个方向在别的版本上我没有验证。

## 7. 没有做的

- 写这份记录时没有独立审查。这是安全相关的改动，只有我自己的测试；路径折叠那次也没有审查。（2026-11-03 两次一起审查了，`docs/reviews/M3a-path-gate-review.md`。）
- 真实宿主里没有跑，路径都是字符串，假后端代替模型。真实冒烟不涉及这些写法，这次没有重跑。
