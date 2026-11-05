# 路径与闸门的审查修复（规格修订 11）

日期：2026-11-04。基线：`78127af`。依据：独立审查 `docs/reviews/M3a-path-gate-review.md`。使用者说"一起修"，范围是我建议的 5 条中危（G-1 到 G-5）加 G-9、G-13。没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次和攻击样本；所有判决用的都是假后端（总是放行），没有打开任何设备、卷或外部主机。

## 1. 结论

**已修并提交**（`7f7ffe9` 代码，文档在其后一个提交，未推送，未打标签）。七条都有测试。全量结果见第 5 节。

**G-5 比审查写的严重。** 审查评为中危，并写明"如果量出来确实发起了连接就升为高危"。我量了：`which.exe`（Git for Windows）对 `//localhost/C$/Windows/System32/notepad.exe` 退出码 0，并打印这个路径；同目录下不存在的文件退出码 1，报找不到。所以 `which` 确实访问 UNC 路径。按审查自己的标准这条应算高危。只量了本机回环，没有测外部主机，也没有确认 NTLM 凭证是否发出。这条只影响 Bash 工具；boundkeep 之前不作决定（无决定），之后由 Claude Code 自己的权限流程处理，那一步我没有量。

**不需要后端就成立的三条（G-2、G-4、G-5）和 G-9 现在都问。** 其余几条只在配置了后端时才有影响。LLM 层至今没有接过真实服务。

**更正（2026-11-04，定向复审 `docs/reviews/M3a-path-gate-rereview.md`）**：G-2 当时只修了一半，最后一段的尾随点仍算确定（GR-1）。修订 12 修了，记录 `M3a-dots-and-folding.md`。下面第 2 节 `C:\proj\a.txt.` 那一行"确定，不变"是当时的结果，修订 12 之后不确定。

**我之前的两个说法是错的**，已在原记录里更正：`M3a-prefix-folding.md` 的"与 Win32 不一致却标为确定 0"（基准 `GetFullPathNameW` 不代表打开时的读法）；`M3a-device-paths.md` 的"`\\.\C:\.` 实际是根目录"（它的 NT 路径是 `\??\C:`，就是卷）。

## 2. 修改前后

假后端，`enforce`。"无决定"是 boundkeep 不拦。

| 发现 | 写法 | 修改前 | 修改后 |
|---|---|---|---|
| G-5 | Bash `which //srv/share/x`、`which -a …`、`which '\\srv\share\x'`（有无后端都一样） | 无决定，`allow-no-path-commands` | 问，`net-allowlist` |
| G-5 | Bash `which '\\.\pipe\x'`、`which //./GLOBALROOT/Device/Mup/srv/share/x` | 无决定，同上 | 问 |
| G-5 | `which python3`、`which -a git`、`which ./x`、`which C:/Windows/notepad.exe` | 无决定 | **不变** |
| G-2 | Read `\\?\C:\proj.\a.txt`、`\??\C:\proj.\a.txt`、`C:\proj.\a.txt` | 无决定，`read-inside-project` | 没有后端：问。有后端：送审，`inside_project` 是 null |
| G-2 | Write `\\?\C:\proj.\new.py` | 无决定，`allow-project-file-writes` | 同上 |
| G-2 | 真文件：`proj.\data.txt` 在项目之外，用 `\\?\` 读 | 无决定，规则放行 | 没有后端：问 |
| G-2 | `C:\proj\a.txt.`（最后一段） | 确定 | **不变** |
| G-4 | `E:\proj\link.txt` 通向 `\\.\pipe\x`（假 `realpath`） | 无决定，`read-inside-project` | 问，`gray-device-path` |
| G-4 | 通向 `\\.\PhysicalDrive0` | 无决定 | deny，`no-raw-disk-access` |
| G-4 | 通向 `\\srv\share\x` | 问，但先 `stat` 了目标 | 问，不再 `stat` |
| G-9 | Read `1:\credentials`、`é:\credentials`；`cat '1:\credentials'` | 无决定，规则放行 | 没有后端：问。有后端：送审 |
| G-1 | Bash `foo > '\\.\C:\Users\bob\.ssh\nul'`、`'C:\x\nul\.'`、`'C:\proj\nul'`、`'src/nul'` | 无决定，`llm`；还会命中真 `NUL` 的缓存 | 问，`gray-device-path` |
| G-1 | Read、Write、Edit `NUL`、`\\.\NUL`、`C:\proj\nul` | 无决定，`llm` | 问，`gray-device-path` |
| G-1 | Bash `foo > NUL`、`foo 2>nul`、`foo > '\\.\NUL'`、`cp a.txt NUL` | 无决定，`llm` | **不变** |
| G-3 | `\\localhost\pipe\x`、`\\127.0.0.1\pipe\x`、`\\MYPC\pipe\x`、`\\localhost\mailslot\x`、`\\localhost\IPC$\x`、`\\pypi.org\pipe\x` | 无决定，`llm` | 问，`gray-device-path` |
| G-3 | `\\127.0.0.1\share\x`、`\\wsl$\Ubuntu\pipe\x` | 无决定，`llm` | **不变** |
| G-13 | `$FOO\..` 的 key | `.`，第二遍 `c:/proj` | `$foo/..`，稳定 |

## 3. 修法

- **`src/boundkeep/daemon/pipeline.py`**（G-1、G-3）：`device_path` 不再用 key 加理由的白名单。`NUL` 的例外只给 `action.shell` 不为空的动作，并且路径的**原文**完全匹配裸名字 `nul`（可带末尾的点或空格）或只带前缀的 `\\.\nul`、`\\?\nul`、`\??\nul`、`//./nul`、`//?/nul`。UNC 的共享名是 `pipe`、`mailslot`、`ipc$` 时也算，不看服务器。
- **`src/boundkeep/normalize/paths.py`**：
  - G-2：`_win_part` 只有最后一段的尾随点和空格才算确定；`\\?\`、`\??\` 下任何一段带尾随点或空格都加 `extended-path-dots`。
  - G-4：`_resolve_on_disk` 的解析结果是设备时，key 写设备，不再退回原路径；`_hard_linked` 之前先过 `is_local_disk`。
  - G-9：Windows 上时，第二个字符是 `:` 而第一个不是英文字母的，加 `non-letter-drive`，不确定。
  - G-13：以 `$`、`%`、`~` 开头又没有锚点的路径，开头这一段不参与折叠。压力测试还找到一类：没有工作目录时 `.//D:x` 的 key 是 `D:x`，第二遍读成盘符；现在 key 保留 `./`。
- **`src/boundkeep/normalize/programs.py`**（G-5）：`which` 有了自己的处理函数，以两个分隔符开头的参数算读路径，其余和原来一样。
- **`policies/default.yaml`**：只改了注释，`tests:` 加 2 条。规则条目没有改。`strict.yaml` 没有改。
- **规格**：修订 11，§5.1、§7。

## 4. 和审查建议不同的地方

- **G-1 的 key 没有改**。审查建议"前缀后面跟盘符时不要按 DOS 设备名读"，我试过：key 变成 `c:/proj/nul`，但这个 key 再规范化一遍就是 `//./nul`，属性测试的稳定性不成立，而且 `Write \\?\C:\proj\nul` 的判决实测仍是 `gray-device-path`。所以保持设备 key，靠缩小豁免解决：结果是问。代价写在第 6 节第 1 条。
- **G-3 只看共享名，不看服务器**。审查建议同时判断服务器是不是本机。只看共享名更简单，也盖住了白名单主机上的 `\\pypi.org\pipe\x`。
- **G-4 用设备 key，不是"标为不确定"**。这样 `no-raw-disk-access` 这样的规则也看得到。
- **T-2 补了测试，T-3 换了依据**（`on_failure` 有测试了；豁免的写法现在按 NT 路径断言）。T-1 不再适用，因为白名单没有了。

## 5. 度量

| 项目 | 结果 |
|---|---|
| 新测试 `tests/unit/test_m3a_path_gate_fixes.py`，修改之前（265 条的版本，跑在 `78127af` 的代码上） | 160 failed, 105 passed |
| 新测试修改后 | 283 passed（后来为 `.//D:x` 加了 18 条） |
| 相关测试（新文件、`test_device_paths_not_sent.py`、`test_norm_paths.py`、`test_norm_prefix_folding.py`、`test_m3a_low_residuals.py`、`test_m3a_review_fixes.py`、`test_m3a_x1_fixes.py`、`test_m3a_rev8_window_fork.py`、`test_m3a_rev8_sources_marks.py`） | 1465 passed, 5 skipped（`.//D:x` 之前的一轮）；之后前四个文件 1055 passed, 5 skipped |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过；77 个源文件没有问题 |
| `boundkeep test` default / strict | 1142 / 0 失败，334 / 0 失败 |
| `test_normalization_is_idempotent`，200 个种子，每个都清空例子库 | 0 失败（审查时 3 个失败） |
| 稳定性压力测试：30 万条（固定种子，属性测试的片段加几个前缀） | 不稳定且不在豁免内：0 |
| 确定的 key 与 NT 路径对照：30 万条（固定种子，故意偏向点、盘符、`UNC`） | 确定的 109683 条：一致 62884；`\\?\` 下重复分隔符 2698（实测一种打不开，一种就是同一个文件）；后面一段带冒号 44101（`a:b`、`C:`，见第 6 节第 3 条）；**其他 0**。G-2 那一类没有了。（更正：这只对 NT 路径成立，Git Bash 和 Node 读文件不走这个转换，见开头的更正） |
| 全量（分六段跑，**不是一个进程**，经过见下） | **1 failed, 27669 passed, 169 skipped**，共 27839。失败的是 `test_settings_io.py::test_round_trip_law`，超时，与这次修改无关（见下）。第 4 段取的是重跑的结果 |
| 评测（命令同 `M3a.md`） | 除策略 sha256、日期与延迟外**完全相同**，判决没有一条变化。`policies/default.yaml` 的注释和 `tests:` 改了，sha256 变了，所以 `eval/report.md` 与 `eval/results/` 重新生成。没有打开留出批次 |

**全量的经过。** 最终代码上先有两轮 `pytest -q` 中途无声中断：终端面板那轮 00:25:58 开始，01:00:18 输出停止，到 74%（20704 条）；WMI 启动那轮 01:58:46 开始，02:15:51 停止，到 47%（13327 条）。两轮到中断时都是 0 失败，没有崩溃记录，也没有睡眠，下一条测试都很普通。**原因没有查到**。02:15 那轮的启动方式会打开一个空白的 Windows Terminal 窗口，关掉它会无声杀掉测试，但没有证实发生过。所以改成按测试文件分六段，每段一个新进程，隐藏窗口，记下退出码和内存（调度脚本第一次引号写错，六段都立刻退出 1，没有跑测试）：

| 段 | 结果 | 用时 | 退出码 | 峰值工作集（每 30 秒采样） |
|---|---|---|---|---|
| 1 | 4751 passed, 26 skipped | 0:12:06 | 0 | 329 MB |
| 2 | 4878 passed, 89 skipped | 0:13:45 | 0 | 147 MB |
| 3 | 4655 passed, 6 skipped | 0:23:26 | 0 | 113 MB |
| 4 第一次 | 1 failed, 5262 passed, 44 skipped | 0:15:45 | 1（调度脚本的问题，见下） | 380 MB |
| 4 重跑 | 5263 passed, 44 skipped | 0:14:43 | 0 | 386 MB |
| 5 | 5540 passed, 1 skipped | 2:04:56 | 0 | 126 MB |
| 6 | 1 failed, 2582 passed, 3 skipped | 0:08:15 | 1 | 188 MB |

- **第 6 段的失败是超时**。`test_round_trip_law` 的一个例子（`data={}`）第一次用了 333 毫秒，超过 Hypothesis 默认的 200 毫秒期限；Hypothesis 马上重试，同一个例子 4.75 毫秒，于是报 `FlakyFailure`。之后单跑这个文件 3 次都是 89 passed, 3 skipped。`settings_io.py` 和这个测试文件相对 `78127af` 都没有改，之前的全量也没有失败在这里。使用者说"先修再提交"：这个文件的两条属性测试加了 `deadline=None`（`4409fb3`），之后单跑这个文件 89 passed, 3 skipped。**全量没有因此重跑**，上表的数字是这个修改之前的。还有四条属性测试用默认期限，这次没有动：`test_m3a_verdict.py` 的 `test_properties_of_the_ruling`，`test_protocol.py` 的三条。
- **第 4 段第一次的失败是我的调度脚本造成的，不是产品问题**。`run_chunk.py` 没写 `__main__` 保护，`test_two_processes_lose_no_update` 用 spawn 起的两个子进程导入它时又把整段测试跑了一遍，测试等 60 秒没等到它们结束就失败了，主进程退出时也在等它们。修了脚本，停掉这两个子进程及其下级，这一段自动重跑，通过。状态文件里第 4 段的"没有 summary 行"是误报：`Get-Content -Tail 1 -Encoding UTF8` 读这个输出返回空，整个文件读是有结果行的。
- **第 5 段比以往整轮全量都慢，原因只查明了一部分**。主要耗在 `test_pipeline_corpus.py`，每条约 1.6 秒。抽样 121 条语料放在新进程里跑，这次的代码和 `78127af` 都是每条约 0.25 秒（解析策略 0.245 / 0.249 秒，判决约 0.005 秒），所以不是这次修改拖慢的。隐藏启动的短测速度相同；关掉垃圾回收不变（只测了一小片语料）；只有主线程在占 CPU。这颗 i7-13700H 有性能核和能效核，把进程绑到性能核后从每秒 0.60 条提到约 1.02 条（各量 45 秒）。**第 5 段后半和第 6 段是绑在性能核上跑的**。绑核之后每条仍约 1 秒，余下的没有查明。

已修改的旧测试：`test_device_paths_not_sent.py` 去掉了文件工具读 `NUL` 仍送审的两组（换到新文件，改按 NT 路径断言）；`test_norm_paths.py` 三行预期（`dots-trailing-dot-on-project`、`dots-mid-single-dot-is-ambiguous`、`unicode-cyrillic-drive-is-not-a-drive`）与 `none-trailing-dot-on-project-dir`；`test_m1c4_scratchpad.py` 的 `scratchpad.` 改成不算 scratchpad；`test_m1c_allow_rules.py` 的名单允许 `which`。这些都是有意的行为变化。

**测量时碰到的外部东西**：G-5 我访问了本机回环的 `C$` 共享，没有碰外部主机。审查时，审查会话的探针有 5 次运行对主机名 `srv` 发起了解析或连接尝试（审查报告第 2 节），它没有查这些尝试走到了哪一步。

## 6. 残余

1. **文件名恰好是设备名的路径，key 仍然藏住真实位置**（`M3a-device-paths.md` 第 6 节第 1 条，这次没有动）。`\\?\C:\Users\bob\.ssh\nul`、`C:\x\nul\.` 也属于这一类：结果是问，不是 deny，按路径写的规则匹配不到。
2. **`realpath` 自己会沿着链接打开目标**。这次只去掉了 `_hard_linked` 的 `stat`。如果项目里真有通向 UNC 的符号链接，访问可能在判决之前就发生了。没有量，因为这台机器的账号不能创建符号链接（测试也因此跳过）；联接点不能指向 UNC。（复审补充，GR-4：目录扫描也跟着链接，`subtree.py` 的 `_link_to_dir` 与 `_hard_linked`，这次没有修。）
3. **后面一段带冒号**：`\\?\UNC\srv\share\C:` 的 key 是 `//srv/share/c`，确定。NT 路径保留冒号。审查第 6 节已列出；这种路径 NTFS 大概率打不开（没有量）。
4. **`C:\proj.` 本身**：最后一段的点仍算确定，所以 Write `C:\proj.` 由 `allow-project-file-writes` 放行（实测）。Win32 读成项目根，打不开；Node 读成项目旁边一个叫 `proj.` 的文件。只能造出这样一个名字没有意义的文件，所以没有处理。（更正：这里说错了。它可以是目录，`cd` 之后的相对路径都落在里面。这就是 GR-1，修订 12 修了。）
5. **配置了后端时，不确定的路径仍然送审**：G-2、G-9 的写法现在不被规则放行，但模型看到的 key 还是 `c:/proj/a.txt`（`inside_project` 是 null），模型放行就是无决定。这与其他不确定的路径相同。
6. **`which` 以外的查找命令**：`type //srv/share/x`、`command -v …`、`test -e …`、PowerShell `Get-Command //srv/share/x` 没有后端时问（`gray`），有后端时送审（实测 `llm`，sent=1）。它们本来就没有 allow 规则，所以不是 G-5 那一类，但模型放行之后同样可能连到那台主机。`net-allowlist` 看不到它们，属于 G-6 一类。
7. **审查的其余发现没有修**：G-6、G-7、G-8、G-10、G-11、G-12，测试缺口 T-4、T-5，信息 I-2。范围是使用者定的。其中 G-10（物理磁盘的其他写法是问，不是 deny）和卷一样，加进 `no-raw-disk-access` 要改规则。
8. **Node 的读法只有审查量过**：Node 24.11，独立运行，不是宿主里的版本。文件工具到底怎么打开路径，是真实宿主里最值得实测的一点。

## 7. 没有做的

- 真实宿主里没有跑，路径都是字符串，假后端代替模型。
- 之后做了定向复审（`docs/reviews/M3a-path-gate-rereview.md`），同一个会话做的，不是独立的。
