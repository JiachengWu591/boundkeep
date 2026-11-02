# 带前缀路径的折叠（`test_normalization_is_idempotent` 的失败）

日期：2026-11-02。基线：`fec0fce`（`m3a-done`），工作区里另有 `M3a-low-residuals.md` 那批未提交的改动，两者碰的文件不重叠。使用者说"修，再跑全量"。没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次；所有判决用的都是假后端，路径只是字符串，没有执行任何命令。

## 1. 结论

**已修，已提交（`a3b38c5` 代码，`fa494e9` 记录），未推送、未打标签。** 全量测试里 `tests/unit/test_norm_paths.py::test_normalization_is_idempotent` 失败，追下去是路径规范化的一个真实错误：**Windows 先折叠路径再读第一段，代码是先读第一段**。这个错误在 `m3a-done` 上就有，不是低危残余那批改动带来的（`paths.py`、它唯一依赖的 `model.py` 和这个测试文件当时都与 `fec0fce` 相同）。之前的全量没碰到，是因为 Hypothesis 每次只随机抽 400 个例子；这次抽到之后，例子存进了本机的 `.hypothesis`，不修就每次都失败。

**影响：只在配置了 LLM 后端时才有。** 没有后端时这些路径是灰色，结果就是问，与修改之前相同。配置了后端时，它们绕过了本该匹配的规则，模型说放行就不再问。LLM 层至今没有接过真实服务，所以目前没有用户受影响；我只用总是放行的假后端测过，真实模型会怎么回答不知道。

## 2. 根因

`\\.\` 这个前缀就是路径唯一的根。Win32 先折叠后面的 `.`、`..`、空段和末尾的点，再看第一段是不是 `UNC` 或盘符。旧代码直接看写出来的第一段，所以读错了。下表用 `GetFullPathNameW` 实测（它是纯词法的，不碰磁盘和网络）：

| 写法 | Win32 的结果 | 旧的 key | 后果 |
|---|---|---|---|
| `\\.\foo\..\UNC\srv\share\x` | `\\.\UNC\srv\share\x` | `//./unc/srv/share/x`（设备） | `net-allowlist` 匹配不到 |
| `\\.\.\UNC\…`、`\\.\\UNC\…`、`\\.\UNC.\…` | 同上 | 同上 | 同上 |
| `\\.\foo\..\C:\Users\bob\.claude\settings.json` | `\\.\C:\Users\bob\.claude\settings.json` | `//./c/users/bob/.claude/settings.json`（设备） | 按完整路径写的规则匹配不到 |
| `\\.\C:\..\D:\x` | `\\.\D:\x` | `c:/d/x`，**标为确定** | key 指向了别的盘 |
| `\\.\UNC\srv\..\evil\share\x` | `\\.\UNC\evil\share\x` | `//srv/evil/share/x`，**标为确定** | key 里的主机是错的 |
| `\\.\C:\..\proj\a.txt` | `\\.\proj\a.txt` | `c:/proj/a.txt`，**标为确定** | 被 `read-inside-project` 放行。目标是一个叫 `proj` 的设备，通常不存在，但 key 确实是错的 |

Hypothesis 找到的 `\\?\\\.\UNC` 是这一类的表现：第一遍得到 `//./unc`，第二遍把它读成 UNC，得到 `//`。

**假后端（总是放行）下的判决，修改前后：**

| 写法（Read、Write） | 修改前 | 修改后 |
|---|---|---|
| `\\srv\share\x`、`\\.\UNC\srv\share\x` | 问，`rule:net-allowlist`，不送审 | 不变 |
| `\\.\foo\..\UNC\srv\share\x` 等 | 无决定，`llm`，送审 1 次 | 问，`rule:net-allowlist`，不送审 |

## 3. 修法

只改了 `src/boundkeep/normalize/paths.py` 的 `_shape_prefixed`，加一个 `_fold_prefixed`：

- 先折叠整段再读第一段。
- 折叠确实改变了什么（或者第一段前面有空段），就加理由 `prefix-path-folded` 并标为不确定。key 写它能到达的地方，这样 deny、ask 规则匹配得上，allow 规则不会放行。
- `UNC.`、`C:.` 按 Win32 读成 `UNC` 与 `C:`。`UNC ` 和 `UNC:x` Win32 不这样读，但这是谨慎的读法，而且设备 key `//./unc/...` 只会被读回 UNC，所以也按 UNC 算，同样标为不确定。

**有意的行为变化**：`\\.\C:\proj\..\x` 这种折叠不影响第一段的写法，key 没变，但现在也标为不确定（`Read` 不再被 `read-inside-project` 放行，变成灰色）。没有人会这样写路径，判断"折叠有没有越过根"反而要多写分支。没有折叠的写法（`\\.\C:\x`、`\\?\C:\x`、`\\.\UNC\srv\s\x`，包括末尾的分隔符和中间重复的分隔符）结果不变，有测试钉住。

规格与设计文档没有写过这一段的语义，不用改规格。规则与策略没有改。

## 4. 度量

| 项目 | 结果 |
|---|---|
| 新测试修改前 | 75 failed（新加的表项与判决测试，加上原来那条属性测试） |
| `test_norm_paths.py` 与 `test_norm_prefix_folding.py` 修改后 | 589 passed, 5 skipped |
| 压力比对：同一批 10 万条带前缀的路径（固定种子，故意组合 `UNC`、盘符、`..`、`.`、空段、末尾的点和空格） | key 不稳定：15682 → **0**。与 Win32 不一致却标为确定：117 → **0**。修改前后都确定的路径 key 变化：**0**。原本不确定、现在变成确定：**0** |
| 另一轮 20 万条（只看修改后） | 崩溃 0，不稳定 0，与 Win32 不一致却标为确定 0；不一致的 4856 条全部标为不确定（`...`、`.. ` 这类写法，代码按谨慎读法算 `..`，Win32 另有读法） |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过；77 个源文件没有问题 |
| `boundkeep test` default / strict | 1138 / 0 失败，334 / 0 失败 |
| 全量 `uv run pytest -q` | **27203 passed, 169 skipped, 0 failed**（1:12:40，退出码 0）。这次跑的是工作区的全部改动，包括 `M3a-low-residuals.md` 那批；上一次全量是 1 failed（就是这条属性测试）、27086 passed、169 skipped。Hypothesis 存下的失败例子这次也重放了 |
| 评测（命令同 `M3a.md`，输出到 scratchpad） | `rules-only.json`、`rules+taint.json` 除日期与延迟外**完全相同**；`report.md` 只有运行日期和 4 行延迟不同。`eval/` 没有改动，不重新生成 |

新测试：`tests/unit/test_norm_paths.py` 的表里加了 20 行（同时走 key 稳定性检查）；新文件 `tests/unit/test_norm_prefix_folding.py` 测判决（Read、Write、Edit、Bash）和与 `GetFullPathNameW` 的一致（只在 Windows 上跑）。

## 5. 残余

1. **真正的设备路径仍然可以被模型放行**（实测，假后端）：`\\.\GLOBALROOT\Device\Mup\srv\share\x`、`\\?\Volume{1234}\x`、`\\.\pipe\x` 是灰色，配置了后端时送审，模型说放行就是无决定。物理磁盘有 `no-raw-disk-access` 拦着。`GLOBALROOT\Device\Mup` 通向网络共享是公开资料里的说法，我没有实测。修法可以是设备路径不送审、直接问，但要改规格 §9 与 `pipeline.py`，这次没有做，由使用者决定。
2. `\\?\` 与 `\??\` 在真正打开文件时不折叠（`CreateFile` 把 `.`、`..` 当字面字符）。key 写的是折叠后的读法，标为不确定，与原来 `extended-path-dots` 的做法一致。
3. `\\?\\\?\C:\x` 这种前缀套前缀，第一段是 `?`，仍然是设备 key（`//./?/c/x`），不确定。这不是 Win32 能打开的路径，没有处理。

## 6. 没有做的

- 没有独立审查。这是安全相关的归一化代码，改动不大，但只有我自己的测试。
- 真实宿主里没有跑这些写法，路径都是字符串，假后端代替模型。2026-11-02 重跑的真实冒烟（26 项，0 失败，`docs/hook-behavior.md`）是在这份代码上跑的，但不涉及带前缀的路径。
