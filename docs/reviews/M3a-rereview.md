# M3a X1 修复的定向复审（F1–F6，规格修订 7）

日期：2026-10-31。审查对象：`main` 的 `742a20b` 及之前（第一轮 `1959969`；第二轮 `687f35a` 规格、`55d1af4` 代码、`742a20b` 文档）。作者的声明（`docs/reports/M3a-review-fixes.md`、`docs/reports/M3a-review-fixes-2.md`、`PROJECT_SPEC.md` 修订 7 的 §7–§10）当作待核实的说法，以代码与实验为准。本轮编号 R-1 起，与上一次审查的 F1–F13 无关。上一次审查的低危 F7–F13 细节已丢失，本轮没有试图还原。

## 0. 结论先行

**没有高危。中危 5 条（R-1 到 R-5），低危 5 条（R-6 到 R-10），信息 3 条。** 中危里有两条不需要 LLM（R-1、R-5），三条只在配置了 LLM 后端时成立（R-2、R-3、R-4）。

最要紧的是 **R-1**：会话的工作目录在项目之外时（Claude Code 的附加工作目录；`cd` 进去之后会话的工作目录就跟着变，本会话里实际看到了），`Action.project` 为空，`written_locations` 记不下任何位置，而项目内的 `Write` / `Edit` 仍由 `allow-project-file-writes` 放行。F1 原来的链路（读网页 → 写测试文件 → 另一个会话 `pytest`）因此又不问了：没有 LLM 时只多一次 `cd` 的询问，配置了 LLM 时一次都不问。修起来很小（第 2 节）。

| 上一轮 | 判定 | 依据 |
|---|---|---|
| F1 粘性位不跨会话 | **部分修** | 项目标记本身可靠：跨会话、重启后仍在；Windows 上 11 种项目目录写法（大小写、8.3 短名、`\\?\`、联接点、正斜杠、尾随分隔符与点、`\\localhost\C$` 管理共享、`\\?\UNC`、`\\.\`）都对得上（会话 A 用任一写法、B 用规范写法或同一写法；A 用规范写法、B 用任一写法）。但 R-1（工作目录在项目外的写不打标记、照常放行）让主场景重新打开；R-6、R-7、R-9 是较弱的漏标；配置 LLM 时标记根本不进 LLM 路径（R-2） |
| F2（原文无法确认） | **P-F2 已修；同类缺口仍在** | 三个 MCP 资源工具名在 `DEFAULT_TAINT_SOURCES`、`policies/default.yaml:56` 与 strict 里都在（hook 实测记录 `docs/hook-behavior.md:280-285`，我没有重做 hook 实测）。经 shell 读取的不可信内容（`gh issue view`、`curl` 等，被批准一次）仍不是来源，规格 §7 已列为 v0 局限，见 R-5；它很可能就是原 F2 想说的那类 |
| F3 模型看不到的代码 | **已修** | 试的变体都不送审或已展示给模型（第 5 节）；文件内容本来就不发，属设计 |
| F4 模型看不到的参数 | **已修** | `NAME=value` 前缀、`env -S`、MCP 调用都不送审；`export` / `declare -x` 的值作为参数展示给模型 |
| F5 名字解析的硬期限 | **已修** | `_DetachedExecutor` 代码核对无误；作者的测试 `tests/unit/test_m3a_x1_fixes.py` 与 `test_m3a_x1_decisions.py` 本机 90 passed。残余（作者已列）：工作线程被别的原因卡满时，"busy" 仍把规则的 deny 变成 ask |
| F6 窗口可被无害调用用完 | **部分修** | 无害调用不再计数（已验证）。但被用户拒绝的询问、没人看见的询问（`dontAsk`、`claude -p`、后台子 agent）同样消耗窗口；同一个动作被拒 3 次之后第 4 次静默放行（R-3） |

**对 `trusted_projects` 是否推荐的影响**：R-1 与 R-5 都是不需要 LLM 的 M-2 绕过，在它们处理之前我不建议改为推荐设置。

## 1. 方法

- 只读代码；唯一写的仓库文件是本报告。实验脚本在会话的 scratchpad，实验目录是 `%TEMP%\bk-rereview`（一次性的项目目录、联接点 `jproj`、每次实验新建的 `session.sqlite`）。没有碰真实的 `~/.boundkeep`、`~/.claude`；没有运行任何 `boundkeep trust` / `taint` 命令；没有执行任何被判定的命令（只调用 `pipeline.review` / `pipeline.decide`）。
- 两种机器：测试里的假 POSIX 机器（`tests/unit/test_m3a_pipeline.py` 的 `policy`、`event`、`bash`、`decide`，home `/home/testuser`、项目 `/home/testuser/proj`），以及本机真实 Windows 磁盘（真实 home，PowerShell 由真实辅助进程只解析不执行）。策略是随附的 default（需要时加 `trusted_projects` 或 LLM 块）。
- LLM 只用 `FakeBackend.answering()`（永远 allow，等于"模型已被完全操纵"，与上一轮 F3–F6 的假设相同）。没有读 `.env`，没有任何密钥，没有访问真实 LLM 服务，没有运行 `claude -p`。
- 一次无害的宿主观察：在本会话（Claude 桌面应用的 Code 标签）里用 PowerShell 工具 `cd` 进本会话的附加工作目录，环境提示的"Primary working directory"随之变成那个目录，随后 `cd` 回仓库。hook 输入的 `cwd` 就是这个会话工作目录，这一点是**推断**（官方文档称 hook 的 `cwd` 是"当前工作目录"），没有用 hook 记录器实测。
- 作者的回归测试：`uv run pytest -q tests/unit/test_m3a_x1_decisions.py tests/unit/test_m3a_x1_fixes.py` → 90 passed in 35.37s。全量套件按要求没有跑。

## 2. 发现：中

### R-1 会话工作目录在项目之外时，项目内的写入照常放行且不打标记（P-F1 的主场景失效）

- **受影响的不变量**：§7"项目上的标记"（"一次调用只要有一个动作的路径可能是写，就记下写到的位置"）；M-2 / F1 的修复目标。
- **机制**：`normalize/event.py:453-488` `_project_keys`：会话的 `cwd` 不确定在项目之内时，`Action.project` 与 `project_resolved` 都是 None（为了让 `project_trusted` 不适用，本身是对的）。`session/marks.py:62-73` `written_locations`：项目内的写走 `out.update(dict.fromkeys(projects))`，`projects` 为空就什么也不记；"记路径本身"那一支要求 `inside_project is not True`，而路径的 `inside_project` 是按项目根算的，为 True。于是**一个位置都不记**。与此同时 `allow-project-file-writes` 只看路径在项目内，照常放行。
- **惰性复现**（假机器，受信任项目，无 LLM）：

```python
from boundkeep.session.store import SessionStore
from tests.unit.test_m3a_pipeline import PROJECT, bash, decide, event, policy

pol = policy(trusted=True)
s = SessionStore(r"<临时目录>\session.sqlite")
decide(event("WebFetch", {"url": "https://example.invalid/", "prompt": "p"}), pol, store=s)
decide(
    event(
        "Write",
        {"file_path": f"{PROJECT}/tests/test_x.py", "content": "x"},
        cwd="/home/testuser/notes",
    ),
    pol,
    store=s,
)
s.marks()  # []
decide(dict(bash("pytest -q"), session_id="00000000-0000-4000-8000-0000000000cc"), pol, store=s)
```

- **实际观察**：`Write` → 无决定（`rule:allow-project-file-writes`），标记 `[]`；另一个会话的 `pytest -q` → 无决定（`rule:allow-devtools-trusted-project`）。`Edit` 同样放行、不记；写 `conftest.py` 被 `ask-project-autorun-files` 问，但同样不记。真实 Windows 磁盘上重做一遍（项目 `%TEMP%\bk-rereview\projectlongname` 受信任，`cwd` 是旁边的目录）：`Write`、`Edit` 无决定、标记为空，`New-Item -ItemType File <项目内>` 灰色、标记为空，会话 B 的 `pytest -q` 与 `.venv\Scripts\python.exe -m pytest -q` 都是无决定。
- **怎么到达这个状态**：会话 A 读网页之后 `cd` 进一个附加工作目录（`--add-dir`、`permissions.additionalDirectories`、桌面应用的附加目录）。项目外的 `cd` / `Set-Location` 是灰色：没有 LLM 时问一次（理由是通用的"没有规则判定"）；配置了 LLM 时模型放行，`cd` 没有敏感标签，污染一步不管它（假机器上实测：被污染的会话里 `cd /home/testuser/notes` → 无决定，`by=llm`），整条链一次都不问。
- **建议修复**：`written_locations` 在动作没有项目键时，项目内的写也记**路径本身**（或项目根的键；根在 `_Ctx.root` 里有）；或者更直接：打标记用项目根，不用 `Action.project`。补回归测试：`cwd` 在项目外、`cwd` 经联接点出项目、`cwd` 缺失三种。
- **改规格**：不用（实现没做到 §7 已写的内容）。

### R-2 项目标记只接到 7 个程序的 ask 规则上，没有接到 LLM 路径（配置了 LLM 时 F1 的跨会话链仍在）

- **受影响的不变量**：§7 P-F1 的目的（"写进项目的东西留在项目里"）；§9.5 污染一步。
- **机制**：标记只被 `ask-devtools-after-untrusted-project-write`（`policies/default.yaml:1425-1435`，程序名单 `pytest ruff mypy black isort flake8 pylint`）读取。会运行项目代码、却不在名单里的命令是灰色，配置了 LLM 时送审；会话 B 没有读过不可信内容，`facts.tainted` 为假，污染一步不适用，模型的 allow 就是最终结果。
- **惰性复现**：`policy(llm=True)`，`FakeBackend.answering()`；会话 A：`WebFetch` → `Write tests/test_x.py`（标记 `/home/testuser/proj`）；会话 B 逐个判下列命令。
- **实际观察**：`python -m unittest`、`npm test`、`make test`、`tox`、`hatch test` → 无决定（`by=llm`）。`pytest -q`、`python -m pytest`、`uv run pytest`、`poetry run pytest`、`.venv/bin/python -m pytest` → ask（规则）。会话 A 里同样的命令（`uv run pytest` 等）被粘性规则问到，没问题。
- **建议修复**：动作的项目带标记时，把这次调用当作"被污染"交给污染一步（带 `exec` / `file_write` 等敏感标签的 LLM allow 改为 ask），或者带标记项目里带 `exec` 标签的灰色调用不送审、直接 ask。后者更简单，也不消耗窗口。
- **改规格**：要（§7 P-F1 现在只说"开发工具在带标记的项目里再问"）。

### R-3 被拒绝或没人看见的询问也消耗污染窗口（F6 只修了一半）

- **受影响的不变量**：§7 修订 7 的计数理由（"要用完窗口，用户得被问 `window` 次"）；§4 失败即关闭。
- **机制**：`daemon/pipeline.py:821-823` 在判决时就 `taint_asked`，不看用户的回答，也不看 `permission_mode`。boundkeep 在 PreToolUse 时不知道用户批没批；而有几种场合 hook 的 ask 根本不会出现在用户面前：
  1. **用户拒绝**：同一个动作被问 3 次、用户 3 次都拒绝，第 4 次静默放行。缓存命中（`llm-cache`）同样计数，所以 agent 只要原样重发。
  2. **`dontAsk` 模式与 `claude -p`**：仓库自己的实测（`docs/hook-behavior.md:171-178`）：这两种情况下 hook 的 ask 直接被拒、没有确认框。计数照加。
  3. **后台子 agent**：Claude Code 文档写明后台子 agent 对没有预先批准的权限请求自动拒绝；子 agent 的调用只是多了 `agent_id`、`agent_type`（`docs/hook-behavior.md:106`、`:191`；`session_id` 与主会话相同是我的推断，文档没有明说）。被污染的主 agent 起一个后台子 agent 发 3 个敏感调用，窗口在用户看不见的情况下用完。**[未实测]**（要真实 Claude Code，会花钱，没有做）。
- **惰性复现**：`policy(llm=True)`，`FakeBackend.answering()`；`WebFetch` 之后连判 4 次同一个命令（我用的是 `python -m boundkeep.cli mode audit-only`，`make release` 同理，作者的 `test_only_the_taint_steps_asks_use_up_the_window` 就是这个形态）。
- **实际观察**：#1 ask（`by=llm`）、#2 ask（`by=llm-cache`）、#3 ask（`by=llm-cache`）、#4 **无决定**（`by=llm`）。
- **建议修复**（任选，可组合）：只在同一个 `tool_use_id` 的 PostToolUse 到达时计数（用户批了、工具真的跑了）；被问过而没有执行的动作（按缓存键）在本会话里不再因窗口结束而放行；`permission_mode` 为 `dontAsk` / `plan` 或调用带 `agent_id` 时不计数。
- **改规格**：要（§7"窗口的计数"）。

### R-4 `python -m boundkeep.cli <状态命令>` 绕过 `deny-boundkeep-state-commands`；配置 LLM 时模型可以放行 `mode audit-only`

- **受影响的不变量**：§3 T3（防护被关闭）；`deny-boundkeep-state-commands` / `deny-boundkeep-state-flags` 的意图（`python -m boundkeep` 已被识别并 deny，说明作者想覆盖模块形式）。
- **机制**：`src/boundkeep/cli.py:776` 有 `if __name__ == "__main__"`，所以 `python -m boundkeep.cli …` 就是完整的 CLI；归一化层只把 `python -m boundkeep` 认成程序 `boundkeep`，`boundkeep.cli` / `boundkeep.__main__` 认不出，命令是程序 `python` 的灰色。`mode`、`uninstall`、`init`、`serve` 没有 `trust` / `taint clear` 那样的运行时检查（`cli.py:522` `cmd_mode` 没有）。
- **惰性复现与观察**（假机器）：

| 命令 | 无 LLM | LLM（永远 allow），新会话 |
|---|---|---|
| `python -m boundkeep.cli mode audit-only` | ask（gray） | **无决定**（by=llm） |
| `python -m boundkeep.cli uninstall` | ask（gray） | **无决定** |
| `python -m boundkeep.cli init --reset-policy` | ask（gray） | **无决定** |
| `python -m boundkeep.cli taint clear --all` / `trust add` | ask（gray） | 无决定（运行时两道检查仍会拒绝，除非另起控制台并清掉 `CLAUDECODE`） |
| `python -m boundkeep.__main__ mode audit-only`、`python3 -m …`、`uv run python -m …` | ask（gray） | 无决定 |

  被污染的会话里，同一条 `mode audit-only` 问 3 次之后第 4 次放行（R-3）。对照：`boundkeep taint clear`、`python -m boundkeep taint clear`、`.venv/Scripts/boundkeep.exe`、`BOUNDKEEP.EXE TAINT`、`uvx` / `pipx run` / `uv tool run` / `py -m`、`boundkeep log --pur`（选项缩写）都是 deny。
- **建议修复**：归一化层把 `python -m boundkeep.<任何子模块>` 认成 `boundkeep`（`boundkeep.hook_client` 认成 `boundkeep-hook`）并照常取子命令；`mode` 与 `uninstall` 加上 `trust add` 同样的两道检查（纵深防御，H-5 已说明它不是边界）。`python -c "from boundkeep.cli import main; …"` 这类写法仍只能是灰色，最终靠 LLM，这一点应写进威胁模型。
- **改规格**：别名不用；运行时检查若要加，§7 / §12 提一句。
- **说明**：这个缺口在 M3a 之前就有，但那时灰色就是 ask；M3a 接入 LLM 之后，它从"deny 变成 ask"升级为"可能被模型静默放行"。

### R-5 经 shell 读取的不可信内容不是来源：被批准一次之后，"先写后运行"在受信任项目里又不问了（规格已列为 v0 局限）

- **受影响的不变量**：M-2 / §7 粘性位的目的；X1 第 3 条。
- **机制**：来源只按工具名识别（§7"污染升级规则"的局限一条）。`gh issue view`、`gh pr view --comments`、`gh api`、`curl`、`npm view`、`git fetch` 之后的 `git log origin/...` 读进来的都是外部可控的文字，但会话不会被标记。
- **惰性复现与观察**（假机器，受信任项目）：`gh issue view 12` → ask（`net-unknown-destination`）；用户批准之后同一个会话的 `pytest -q` → 无决定（`allow-devtools-trusted-project`），会话里写的测试文件也不打标记。`curl`、`npm view`、`git fetch` 同样。
- **为什么仍算中危**：对编码 agent 来说"读 issue 然后修"是最常见的注入入口，用户本来就让 agent 去读，那一次批准几乎必然发生；批准之后整条 M-2 链和没有 M3a 时一样。它可能正是原 F2 说的"规则层另一条 M-2 绕过"。
- **建议修复**：被判为 ask / allow、带网络动作（`domains` 非空或 `network` 标签）的 shell 调用也当作来源（PreToolUse 时置粘性位，与来源工具同样处理"随后被拒"的安全方向）。代价：每次批准过的网络命令都会让本会话的开发工具再问。
- **改规格**：要（§7 局限一条、§8 `taint.sources` 的含义）。如果使用者选择接受，至少应在 `trusted_projects` 的文档里明说这一条，并继续不推荐。

## 3. 发现：低

### R-6 没有可见写路径的写不打标记，其中 `git stash pop` / `apply` 由规则直接放行

- **观察**（假机器，受信任项目，`WebFetch` 之后）：`git stash pop` → 无决定（`allow-git-stash`），标记 `[]`；`git apply /tmp/x.patch`、`git checkout other`、`python gen.py`、`python -c "open('tests/test_x.py','w')…"` → ask，标记 `[]`；MCP 写工具用相对路径（`{"path": "tests/test_x.py"}`）→ ask，标记 `[]`；**会话里第一个来源调用本身就是带写路径的 MCP 写**（`mcp__fs__write_file {"path": "<项目>/tests/test_x.py"}`）→ ask，标记 `[]`（这次调用按它之前的状态判，`read_untrusted` 为假）。随后另一个会话的 `pytest` 都是无决定。对照：`tar -xf`、`unzip`、`cp /tmp/x tests/…` 会打标记。
- **`git stash` 的洗白路径**：被污染的会话 A 写测试文件（打标记）→ `git stash -u`（放行）→ 工作区干净，用户检查 `git status` 之后运行 `taint clear` → A `git stash pop`（放行、不记）→ 会话 B `pytest` 不问。需要用户在中间清标记，所以是低危。
- **建议修复**：读过不可信内容的会话里，任何灰色、带 `exec` / `file_write` 标签、或是 MCP 调用的动作，都记它的项目目录；`git` 的会改工作区的子命令（`stash pop|apply`、`checkout`、`restore`、`switch`、`apply`、`am`、`merge`、`pull`、`reset`、`cherry-pick`、`rebase`）同样；来源调用自己带写路径时也记。
- **改规格**：要（§7"局限"一条现在只提了运行代码的命令与 MCP 工具）。

### R-7 写到项目之外只记文件路径，读取那个文件的项目看不到

- **机制**：`marked()`（`session/marks.py:76-93`）只比较"标记在项目之下"或"项目在标记之下"。写到上级目录或主目录的工具配置时，标记是那个文件本身，与项目没有包含关系。
- **观察**（假机器，受信任项目 `/home/testuser/proj`，`WebFetch` 之后）：`Write ~/pytest.ini`（项目的上级目录，pytest 在项目没有自己的配置时向上找）→ ask（`ask-python-tool-config-write`），标记 `/home/testuser/pytest.ini`；`Write ~/.pylintrc`（`init-hook` 执行任意代码）同样；`Write ~/.config/mypy/config`（`plugins` 加载任意文件）→ ask（gray）。三种情况下会话 B 的 `pytest` / `pylint` 都是无决定。同类：可编辑安装（`pip install -e ../lib`）的兄弟项目被写入，标记在 `../lib`，导入它的受信任项目看不到。
- **为什么是低危**：这些写在会话 A 里本身要问。
- **建议修复**：项目外的写记它所在的**目录**而不是文件（`marked` 对项目在该目录之下的情况命中）；主目录与 `~/.config` 下的工具配置写入记 `*` 或主目录。
- **改规格**：要（P-F1 偏差第 2 条的写法）。

### R-8 标记上限可被一次调用打满，逼用户用 `taint clear --all`

- **观察**：被污染的会话里一条 `touch /tmp/flood/f0 … /tmp/flood/f1000`（1001 个项目外路径）→ ask（灰色；用户拒绝也一样，标记在 PreToolUse 时就写了），标记表里只剩一个 `*`（`store.py:362-363`：`count + len(new) > MAX_MARKS` 时整批换成 `*`）。之后任何项目、任何会话的开发工具都问。
- **风险**：安全方向，但它让用户习惯 `taint clear --all`，而 `--all` 会把真正可疑项目的标记一起清掉。
- **建议修复**：单次调用的写路径很多时只记项目目录与 `*`，不吞掉已有标记的可见性；`taint list` / `doctor` 把 `*` 单列并说明来源；提供只清 `*` 的写法，`--all` 先列出项目标记再要求输入 `yes`。
- **改规格**：可选（§7 上限一条）。

### R-9 新的 `session_id` 带着旧上下文：fork、`--fork-session`、子会话与队友、清理之后的 resume 丢掉粘性位与窗口

- **机制**：粘性位与窗口按 `session_id` 存；规格只讨论了 resume 与 compact（不换 id）。Claude Code 的 `--resume <id> --fork-session` 按官方文档会换新 id 而保留对话；桌面应用的"fork"会话、agent 团队里接收主会话转述内容的队友也是新 id；30 天清理（`RETENTION_S`）之后 resume 的会话在库里也是新的。会话 A 只读了网页、没有写项目（所以没有项目标记）时，fork 出来的会话 B 写测试文件不打标记、`pytest` 不问。
- **[未实测]**：没有在真实 Claude Code 里确认 fork 之后 hook 的 `session_id`（要花钱）。`claude …` 命令本身由 `ask-claude-cli` 问，agent 不能自己静默 fork；桌面应用里 fork 要用户点。
- **建议修复**：`init` 注册 `SessionStart`；`source` 为 `resume` 或 `compact` 而 `session_id` 不在库里的会话，按"读过不可信内容"开始（失败即关闭）。fork 正好是"新 id 的 resume"。
- **改规格**：要（§7 会话状态库一段）。

### R-10 已安装的策略得不到新的来源与 `window`，`doctor` 不提示

- **观察**：`doctor.py` 没有把活动策略的 `taint.sources` 与 `DEFAULT_TAINT_SOURCES` 比较的检查；已经 `init` 过的用户仍是 `[WebFetch, WebSearch, "mcp__*"]` 与 `window: 8`（按修订 7 的计数是"问 8 次"），P-F2 对他们不生效，PostToolUse 的 matcher 也要重新 `init`。作者在报告第 4 节第 10 条与 `docs/policy-reference.md` 写明了。
- **建议修复**：`doctor` 在活动策略缺少默认来源、或 PostToolUse matcher 与策略来源不一致时给 WARN。
- **改规格**：不用。

## 4. 信息

- **I-1 MCP 工具描述与服务说明不经过来源**：`ToolSearch` 被判为 `harmless-tool`（放行），它把延迟加载的 MCP 工具的完整描述（服务作者写的文字）带进上下文；非延迟的 MCP 工具描述与服务的 instructions 在会话开始时就在上下文里，没有任何工具调用。配置了 MCP 服务的会话从第一轮起就可能含不可信文字。hook 看不到前者以外的部分；可以考虑把 `ToolSearch` 选中 `mcp__` 工具也当作来源，其余写进威胁模型。
- **I-2 ask 的理由在确认框里不显示**（M0 实测，作者已列）：用户在会话 B 里看到 `pytest` 被问，却不知道原因是项目标记，容易一律批准，标记的价值打折。
- **I-3 适配器对远端主机 `trust_env=True`**（`openai_compatible.py:279`，文件头已写）：httpx 会读取 `HTTP(S)_PROXY`、`ALL_PROXY`、`NO_PROXY`、`SSL_CERT_FILE`、`SSL_CERT_DIR`。这些是用户启动守护进程时的环境，不是 agent 能改的；只是"`BOUNDKEEP_LLM_API_KEY` 之外读取的变量"应在 `docs/privacy.md` 列全。

## 5. 尝试过但没有成功的攻击

- **直接改会话库**：`rm` / `mv` / `: >` / `cp /dev/null` / `sqlite3 … DELETE` / `Remove-Item` / `Clear-Content` / `Set-Content` / `Rename-Item`，路径写成 `~`、`$HOME`、`$USERPROFILE`、`$env:USERPROFILE`、`/c/Users/…`、大小写变化、8.3 短名 `BOUNDK~1`、`\\?\`、`::$DATA`、尾随点，以及 `-wal` 文件：全部 deny（`protect-guard-config`、`protect-guard-code`）。`python -c "import sqlite3…"` 与 `[IO.File]::Delete(…)` 是灰色（无 LLM 时问）。
- **换名字调用 `boundkeep taint`**：路径限定的 `boundkeep.exe`、`BOUNDKEEP.EXE TAINT`、`uvx` / `pipx run` / `uv tool run` / `py -m` / `python -m boundkeep`、`CLAUDECODE= …` 前缀、`$env:CLAUDECODE=''; …`：全部 deny。选项缩写 `boundkeep log --pur`、`init --reset` 也被标志规则拦下。`Start-Process`、`cmd /c start` 是灰色；运行时两道检查在那样起的子进程里能被绕过（新控制台、可清环境变量），这是 H-5 已知的，靠规则与 LLM 兜底。唯一的漏网是 R-4 的模块写法。
- **库不可读 / 版本更新**：schema 版本高于 2、打不开 → `UnavailableStore` → `UNKNOWN`，`marks_known` 为假，规则当作命中（代码核对）。`taint clear --project-dir C:\` 不会清掉全部（`location_key` 拒绝盘符根）。
- **Windows 路径让 `marked` 判错**：第 0 节表里的 11 种写法，按那里写的组合全部命中（没有跑非规范写法之间的全部两两组合）；8.3 短名的项目目录本身不被当作受信任（灰色），写入记成解析后的长路径。
- **用无害调用耗尽窗口**：`WebFetch` 之后连发 `Read` 不计数（作者测试与我的实验一致）；`audit-only` 下标记照写（`pipeline.py:804` 不看模式）、窗口不计数。
- **缓存投毒跨污染状态**：缓存键覆盖整个请求内容与模型（`audit/cache.py:27-33`），`rule_on` 每次按当前的 `tainted` 重新裁决（`auditor.py:222-228`），所以未污染会话里缓存的 allow 在污染会话里仍会被改成 ask。
- **F3 / F4 的变体**：`env -S "NODE_OPTIONS=… node app.js"`、`make -f /dev/stdin <<'EOF'` → 不送审、ask（`gray-unanalysed`）；`export` / `declare -x NODE_OPTIONS=…`、函数定义 `f() { node app.js; }; f`、`awk 'BEGIN{system(…)}'` → 送审，但值与函数体都在请求里；`python3 - < /tmp/x.py`、`python3 -c "$(cat /tmp/x.py)"`、`xargs -a /tmp/args.txt node` → 送审，模型看到"执行某个文件 / 参数来自文件"（文件内容按设计不发）。`node -e "$(curl …)"`、`git -c core.sshCommand=… fetch` 先被网络规则问到。
- **F5**：`_DetachedExecutor.shutdown` 不等待，`asyncio.run` 关闭循环时不再被卡住的解析线程拖住；全局最多 8 个悬挂解析。没有找到别的、不受 `asyncio.timeout` 约束又会卡住的步骤（TLS 握手与读取都在超时之内）。会话库被别的进程长时间锁住时，每次 `tool_call` 最多等 2 秒（`BUSY_TIMEOUT_S`）而守护进程的期限也是 2 秒，规则的 deny 会变成"太慢"的 ask；但要锁库得先运行一段灰色的 Python，它本身就能直接做坏事，不算提升。

## 6. 没有覆盖到的范围

- 没有在真实 Claude Code 里跑任何东西（不花钱）：后台子 agent 的自动拒绝与它的 `session_id`、fork 之后的 `session_id`、`dontAsk` / `-p` 下的计数、hook `cwd` 在 `cd` 之后的值（R-1 的前提只通过会话工作目录的变化间接确认）。
- macOS / Linux：POSIX 键区分大小写，大小写不敏感的 APFS 上两个会话用不同大小写进入同一个目录会对不上；只是设计目标平台，没测。
- `subst` 盘符、映射的网络盘、WSL 的 `\\wsl.localhost\…` 项目：`location_key` 拒绝 `//` 开头的键，纯 UNC 项目里的写**存不进**标记（读代码；`\\localhost\C$` 之所以可以，是因为它被解析成了 `c:/…`）；这种项目能不能被信任没有测。
- 多进程同时写标记、1001 个标记下的延迟、schema 1 → 2 迁移与旧守护进程并存：只读了代码与作者的测试。
- X1 第 4 条（审计器）只核对了缓存与二次裁决；发送出口的脱敏、任务意图投毒、畸形回答没有重测。第 8 条只核对了 https 限制、不跟随重定向、响应体积上限与 `ANTHROPIC_API_KEY` 的拒绝。
- 上一次审查的 F7–F13 与两条信息项：细节已丢失，无法逐条核对。

## 7. 规格变更提案（需要使用者决定）

| 来源 | 位置 | 要点 |
|---|---|---|
| R-2 | §7 P-F1 | 带标记的项目里，带 `exec` 等敏感标签的灰色调用不送审或经污染一步 |
| R-3 | §7 窗口的计数 | 只计"用户批准且执行了"的询问；被拒的动作不因窗口结束而放行；`dontAsk` / 后台子 agent 不计数 |
| R-5 | §7 局限、§8 | 带网络动作、被批准的 shell 调用也算来源；或明确接受并在 `trusted_projects` 文档里写明 |
| R-6 | §7 局限 | 读过不可信内容的会话里，灰色 / `exec` / MCP / 改工作区的 git 子命令都记项目目录 |
| R-7 | §7 P-F1 | 项目外的写记所在目录 |
| R-9 | §7 会话状态库 | `SessionStart` 的 `resume` / `compact` 遇到未知 `session_id` 时按读过不可信内容开始 |

R-1、R-4、R-10 是实现问题，不用改规格。
