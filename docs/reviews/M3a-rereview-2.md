# M3a 修复的第二轮定向复审（规格修订 8 的实现）

日期：2026-10-31。审查对象：`git diff 58897a7..75a24b1`，重点是 `4a6c07d`（代码与测试）；另核对 `f8b7a71`（R-1、R-4、R-10 的修复）。作者的声明（`docs/reports/M3a-rereview-fixes-2.md`、`PROJECT_SPEC.md` 修订 8、`docs/hook-behavior.md`"M3a 复审的实测"）当作待核实的说法。上一轮报告是 `docs/reviews/M3a-rereview.md`（R-1 到 R-10），本轮编号从 S-1 开始。

## 0. 结论先行

**没有高危，没有中危。低危 7 条（S-1 到 S-7），信息 2 条（S-8、S-9）。** 上一轮的中危 R-1 到 R-5 都已修；低危里 R-6、R-7、R-9 已修但各有残余，R-8 仍未处理（仍建议暂不处理），R-10 已修。

修订 8 没有破坏失败即关闭、退出码只能是 0 或 2、不确定即灰色这三条不变量（第 5 节）。唯一新增的"失败即放行"是 SessionStart 没被记录时 fork / resume 的会话从干净状态开始（S-1）。规格 §10 已经明写，这次实测确认了它的行为。

**`trusted_projects` 能不能改为推荐设置**：从这一轮的结果看，已经没有阻止它的高危或中危。我的建议是"有条件推荐"：文档里写明只信任自己写过或审计过的仓库，写明第 3 节列出的残余；改推荐之前，先在真实 Claude Code 里各跑一次 fork 与"询问被批准"（作者报告第 8 节第 3 条的冒烟）。这两条完整链路至今只有单元测试与假事件，没有在真实宿主里跑过。最终由你决定。

| 上一轮 | 判定 | 依据 |
|---|---|---|
| R-1 工作目录在项目外的写不打标记（中） | **已修** | 实测：`cwd` 在项目外时项目内的 `Write` 仍放行，但标记记成项目根，另一个会话的 `pytest -q` 被 `ask-devtools-after-untrusted-project-write` 问 |
| R-2 标记不进 LLM 路径（中） | **已修** | 实测：带标记的项目里 `make release` 不送审，`decided_by: gray-marked-project`；作者对 `npm test`、`make test`、`python -m unittest`、`tox` 的测试通过 |
| R-3 被拒或没人看见的询问也消耗窗口（中） | **已修** | 存储层实测：只有 `tool_use_id` 对上的 PostToolUse 才计数；从未询问过的 id、被 64 条上限挤掉的 id、新来源之前的 id 都不计数。宿主行为（被拒的询问没有 PostToolUse）依据作者的实测记录，我没有重做 |
| R-4 `python -m boundkeep.cli` 绕过 deny（中） | **已修** | 实测：`python -m boundkeep.cli mode audit-only`、`… taint clear --all` 都是 deny（`deny-boundkeep-state-commands`） |
| R-5 经 shell 读进来的外部内容不是来源（中） | **已修，有残余** | 实测：`gh issue view`、`curl`、`wget -qO-`、`git ls-remote`、`npm view`、`pip index versions`、`pip search`、`cargo search` 都让会话变成读过不可信内容；`pip|npm|pnpm|yarn install`、`npm ci`、`uv sync`、`cargo build`、`git clone|fetch|pull` 不算。残余见 S-2、S-3、S-4 |
| R-6 看不到写路径的写不打标记（低） | **已修，有残余** | 作者测试覆盖 15 种写法；残余见 S-5 |
| R-7 写到项目外只记文件（低） | **已修（备选），有残余** | 残余见 S-6；用户级配置位置在规格里已列为局限 |
| R-8 标记上限可被一次调用打满（低） | **未修，仍建议暂不处理** | 代码没变 |
| R-9 新 `session_id` 丢粘性位与窗口（低） | **已修，有残余** | 实测：`source` 为 `resume`、`compact`、`fork`、`teleport`、空、数字、缺失且库里没有该会话时，`pytest -q` 被问；`startup`、`clear` 干净；已知的干净会话 resume 之后仍然干净。残余见 S-1 |
| R-10 已装的策略得不到新来源 | **已修** | `doctor.check_taint_sources`：缺默认来源时 WARN，PostToolUse 的 matcher 与 `post_matcher_for` 不一致时 WARN |

## 1. 方法

- 只读代码；唯一新写的仓库文件是本报告。实验脚本在会话 scratchpad，实验用的会话库放在 `%TEMP%\bk-rr8` 的一次性目录里。没有碰真实的 `~/.boundkeep`、`~/.claude`，没有运行任何 boundkeep 状态命令，没有执行任何被判定的命令（只调用 `pipeline.decide`、`normalize_event` 与 `SessionStore` 的方法）。
- 机器：测试里的假 POSIX 机器（`tests/unit/test_m3a_pipeline.py` 的 `policy`、`event`、`bash`、`decide`）。LLM 只用 `FakeBackend.answering()`（永远 allow）。没有读 `.env`，没有密钥，没有访问真实 LLM 服务，没有运行 `claude -p`。
- 相关测试：`uv run pytest -q tests/unit/test_m3a_rev8_sources_marks.py tests/unit/test_m3a_rev8_window_fork.py tests/unit/test_m3a_session_store.py tests/unit/test_m3a_x1_decisions.py tests/unit/test_m3a_x1_fixes.py` → **250 passed**（66.74 秒）。全量套件没有跑。
- 本轮有几项我只读了代码、没有写实验，下面逐条标明"读代码"。

## 2. 发现：高、中

无。

## 3. 发现：低

### S-1 SessionStart 没被记录时，fork / resume 出来的会话从干净状态开始（P-R9 的失败即放行）

- **受影响的不变量**：§4 失败即关闭；§7 P-R9。规格 §10 已把它列为"失败即放行的一处"。
- **机制**：只有 `session_start` 会为没调用过来源的会话写行；`tool_call` 遇到库里没有的会话时按干净判（`store.py` 的 `_facts(None, …)`）。守护进程在会话开始时不在、SessionStart 没注册（旧安装）、或那次写库失败，fork 出来的会话就没有行，之后一直是干净的。
- **惰性复现**：新库里不发 SessionStart，直接在受信任项目里判 `bash("pytest -q")`。
- **观察**：无决定（`rule:allow-devtools-trusted-project`）。对照：先发 `source: fork` 的 SessionStart，同一个调用被 `ask-devtools-after-untrusted-content` 问。
- **建议修复**：既然 `startup` / `clear` 现在一定会写一行，"PreToolUse 时库里没有这个会话"就只剩几种情况：漏了 SessionStart、旧安装、升级前开始的会话。安装记录里写明装过 SessionStart 时，把这种会话按 `inherited:unknown` 开始，就能关掉这处放行。代价：守护进程晚于会话启动时，那个会话里的开发工具会再问。
- **改规格**：要（§7 P-R9、§10 那一行）。

### S-2 P-R5 的例外名单比规格文字宽：运行远端包的子命令也被当作"只搬代码"

- **受影响的不变量**：§7 P-R5（"只搬代码、不把远端文字读进上下文的子命令不算"）。
- **机制**：`session/sources.py` 的 `_MOVES_CODE` 除了安装与同步，还收了 `npx`（不带子命令）、`npm exec|x|dlx|create|init`、`bunx`、`pnpx`、`cargo run`、`go run`、`uv run`、`uv tool`、`pipx run`。这些命令会下载并运行一个包，包的输出进上下文，这正是远端写的文字。规格 §7 的例外只写了"安装与同步类子命令……等"；作者报告第 4 节第 3 条说明了加长的理由（不加的话，JS 与 Rust 项目里几乎每个会话都被污染）。
- **观察**：`npx cowsay hi`、`bunx cowsay hi`、`cargo run`、`go run .`、`uv run python app.py` 都不让会话变成读过不可信内容（实测）。这些调用本身都是网络规则的 ask，所以不是静默执行；问题在批准之后会话不带污染。
- **为什么是低危**：运行远端包是比"读远端文字"更大的事件，用户在确认框里看到的就是这件事；一旦批准，包自己的代码就能做任何事，污染位不是主要防线。
- **建议修复**：至少把总是远端的写法（`pnpm dlx`、`yarn dlx`、`pipx run`、`uv tool run`、`npm exec <包>`、`npx` 带明确版本或 scope 的包）从名单里拿掉；`npx <本地 bin>` 这种常见写法可以保留。或者把规格文字改成与代码一致，由你确认这个取舍。
- **改规格**：要（文字与代码对齐，二选一）。

### S-3 shell 来源只在被审查的 PreToolUse 时记录，PostToolUse 不补记

- **受影响的不变量**：§7"来源工具的调用在 PreToolUse 与 PostToolUse 两处都打标记"的理由（只在一处打会在那一处失败时放行）。
- **机制**（读代码）：`decide` 只在 PreToolUse 时调用 `network_source` / `source_seen`；`tool_result` 只按工具名判来源。守护进程繁忙或超时时，`server._mark_unreviewed` 会记 `shell-unreviewed`（这一侧已处理）；但 hook 客户端连不上守护进程时，守护进程根本没看到这次 PreToolUse。配置了 LLM 时 PostToolUse 的 matcher 是 `*`，这次 Bash 调用的 PostToolUse 会到达，但只被拿去对待确认的询问，不会被认成来源。
- **影响**：守护进程不在时每个调用都问，用户批准了一次 `gh issue view`；守护进程回来之后，这个会话按干净判。
- **建议修复**：PostToolUse 的负载里有 `tool_input`，对 Bash / PowerShell 再跑一次归一化与 `network_source`，与来源工具一样在两处记。
- **改规格**：不用（规格的原则已经要求两处记）。

### S-4 shell 来源依赖归一化层认出网络：用代码读网页不算来源

- **受影响的不变量**：§7 P-R5 与"局限"一条。
- **机制**（读代码）：`network_source` 只看动作的 `network` / `domains`，这些来自程序表。解释器一行代码、项目里的脚本、PowerShell 直接调用 .NET 的网络类，归一化层看不出网络；它们是灰色（问用户），批准之后会话不带污染。规格 §7 的"局限"只列了读本地文件，没有列这一类。
- **为什么是低危**：没被注入的 agent 读 issue 用的是 `gh`、`curl`、`WebFetch`，这些都已覆盖；需要换成这些写法的通常已经是被注入之后。
- **建议修复**：在规格 §7 的局限里写明"运行代码自己去取的远端内容不算来源"；可选：带 `exec` 的灰色调用被批准时也按来源记（会让很多会话被污染，需要权衡）。
- **改规格**：要（局限的文字）。本轮没有测 PowerShell 的 .NET 写法，见第 6 节。

### S-5 名单之外、会改工作区的 git 子命令不打标记

- **受影响的不变量**：§7 P-R6。
- **机制**（读代码）：`marks.hidden_write` 对 git 只看 `_GIT_WORKTREE`（`checkout`、`restore`、`switch`、`apply`、`am`、`merge`、`pull`、`reset`、`cherry-pick`、`rebase`）与 `stash pop|apply`。`revert`、`stash branch`、`worktree add`、`sparse-checkout`、`submodule update`、`bisect`、`read-tree -u`、`checkout-index` 也会改工作区；git 不带 `exec` 标签，所以"规则没放行的 exec"那一支也接不住。
- **为什么是低危**：这些子命令都不在 allow 规则里，在被污染的会话里会问。
- **建议修复**：把它们加进 `_GIT_WORKTREE`；或者反过来，git 只把明确只读的子命令当作不写，其余在被污染的会话里都记项目目录。
- **改规格**：不用（规格写的是"会改工作区的 git 子命令"，名单是实现细节）。

### S-6 写在盘符根或文件系统根的开发工具配置只记文件本身

- **受影响的不变量**：§7 P-R7。
- **机制**（读代码）：`marks._parent` 要求父目录本身是可用的标记键；`location_key` 拒绝 `e:` 与 `/` 这样的根。所以 `E:\pytest.ini`、`E:\conftest.py`、`/pytest.ini` 记的是文件本身，不覆盖根下面的任何项目。pytest 在项目没有自己的配置时会向上找到它们。
- **为什么是低危**：这些写在会话 A 里要问（`ask-python-tool-config-write`）；系统盘根普通用户通常不能建文件，但非系统盘（本机的 `E:`）通常可以。
- **建议修复**：父目录是根时记 `*`（与上限同一个"所有位置"标记），或者给每个盘符根一个专门的键。
- **改规格**：要（P-R7 一条补一句）。

### S-7 P-R2 与 P-R6 合起来的效果：一次被问（甚至被拒）的运行代码的调用就会长期改变这个项目

- **受影响的不变量**：无（安全方向）。这是对第 4、6 节已写明设计的评估。
- **观察**：被污染的会话里，被粘性规则问到的 `pytest -q`，无论用户批不批，都会给项目打标记（`hidden_write`：带 `exec`、判决不是 allow）。被规则 deny 的运行代码的动作也会打标记，尽管它不会执行。配置了 LLM 时，之后这个项目里所有带 `exec` 的灰色调用都不送审，直到 `taint clear`；窗口对这类调用不再起作用。
- **可利用的一面**：不是绕过。被注入的 agent 可以用一次会被拒的调用让项目带上标记，把 LLM 层在这个项目里关掉、让询问变多，借询问疲劳推动用户更随意地批准或者习惯性地 `taint clear`。确认框里不显示 ask 的理由（M0 的实测），用户也不知道为什么被问。
- **建议修复**：判决是 deny 的动作不打标记（它不会执行）；`taint list` 除了来源名，再记下打标记的调用属于哪一类（"读过网页之后的写"与"读过网页之后被问的 pytest"）。
- **改规格**：可选。

## 4. 信息

- **S-8 `audit-only` 下被规则 deny 的网络调用照样执行，但不算来源**（读代码）：`network_source` 只在 `result.verdict.decision != "deny"` 时调用，看的是规则的判决，不看模式。`audit-only` 本来就不拦，只影响切回 `enforce` 之后会话的状态。
- **S-9 本身带 `exec` 的来源命令在自己那次调用里就给项目打标记**：`npm view` 等包管理器命令带 `exec`，作为来源按调用之后的状态打标记，于是只读的查询也标记项目。`gh`、`curl`、`wget`、`git ls-remote` 不带 `exec`，不会这样（实测确认。复审中我一度以为"读 issue 就标记项目"，核对之后发现那个标记是我在同一会话里随后探测的 `pytest` 打的，不是 `gh` 打的）。

## 5. 不变量核对（修订 8 新增的代码）

- **失败即关闭**：会话库打不开、迁移失败 → `UnavailableStore` → `UNKNOWN`，当作已污染、标记未知；P-R2 在标记未知时同样不送审（`runs_in_marked_project`）。`tool_use_id` 缺失、不可用、被 64 条上限挤掉 → 不计数，会话保持被污染。PostToolUse 的 matcher 没跟上（旧安装）→ 不计数，`doctor` WARN。schema 1 → 3 先清零再加表，2 → 3 保留计数；迁移在 `BEGIN IMMEDIATE` 里进行，失败回滚。唯一的例外是 S-1，规格已写明。
- **退出码只能是 0 或 2**：`hook_client._fail_safe` 对 `session` 不输出、退出 0；`hook_main._fallback_outcome` 对 `session` 返回空的 `Outcome()`。SessionStart 的标准输出会进模型上下文，客户端不输出任何东西，这一点是对的。作者的测试覆盖"守护进程回答 deny 也静默"。
- **不确定即灰色**：修订 8 没有新增 allow 规则，策略没变；新代码只会让会话更早被污染、让更多调用不送审。
- **ConfigChange 的检查**：`ownhook.required_events` 对没有 `events` 的旧安装记录不要求 SessionStart，对新记录要求；基础的四个 hook 始终要求。安装记录在 `~/.boundkeep/`，受 `protect-guard-config` 保护。

## 6. 试过但没有成功的攻击

- **重复使用同一个 `tool_use_id`**：每次询问都会重新登记这个 id，所以每次"询问 + 对应的 PostToolUse"都计一次，等同于正常批准，不能多算也不能少算。
- **伪造 PostToolUse 来消耗窗口**：从未被询问过的 id 的 PostToolUse 不计数（实测 5 次，计数保持 0）。PostToolUse 只在工具真正运行之后才会到达，agent 改不了 `tool_use_id`。
- **用上限挤掉待确认的询问**：被挤掉的询问之后的 PostToolUse 不计数（实测），结果是会话保持被污染，安全方向。
- **新来源之后用旧的 id**：来源调用清掉待确认的询问，之后旧 id 的 PostToolUse 不计数（实测）。
- **用"运行代码的灰色调用"耗尽窗口**：在被污染的会话里，第一次这样的调用就给项目打标记，之后同类调用都不送审，窗口对它们根本不起作用。
- **P-R9 的各种 `source`**：除了 `startup` 与 `clear`，`resume`、`compact`、`fork`、`teleport`、空字符串、数字、缺失都按读过不可信内容开始（实测）。
- **换名字绕过来源判定**：`pip3.12`、`pnpm`、`yarn` 等按 `_family` 归入原来的包管理器；名单之外的名字一律算来源，误伪装只会让会话多被污染。
- **R-4 的其他模块写法**：`python -m boundkeep.taintcmd`（这个模块没有 `__main__`，什么也不做）、`python -m boundkeep.daemon.server` 都被认成 `boundkeep`，按 `ask-boundkeep-cli` 问。

## 7. 没有覆盖到的范围

- **真实 Claude Code 里的完整链路**：新的 SessionStart 条目、`*` matcher、待确认询问的批准与计数，都只有单元测试与假事件。按约束没有运行 `claude -p`。建议你在 Claude Code 之外的终端里，按作者报告第 8 节第 3 条跑两次冒烟（各约 0.1 美元）：一次 `--resume <id> --fork-session` 之后在受信任项目里运行开发工具，确认被问；一次在配置了 LLM 的会话里读网页之后批准三次敏感操作，确认第四次才不再被污染一步改成 ask。
- **`auto` 权限模式**：`docs/hook-behavior.md` 记录了 `--permission-mode auto` 当时没有生效。如果 auto 模式下 hook 的 ask 会被 Claude Code 的分类器自动批准，PostToolUse 就会在没人看的情况下到达，窗口被消耗。要测，可在一次性目录里用 `experiments/run_cli_probe.py` 的现有做法加 `--permission-mode auto` 跑一次，看被 hook 问到的调用有没有 PostToolUse。
- **SessionStart 与第一次 PreToolUse 的先后**：如果宿主不等 SessionStart 的 hook 结束就发第一次工具调用，fork 出来的会话的第一次调用会按干净判。没有测。
- **PowerShell 的写法**：本轮没有在真实 Windows 上测 P-R5 的 PowerShell 形式（作者的测试里有 9 种）；S-4 里 .NET 网络类的写法没有测。
- **S-5、S-6、S-8 只读了代码**，没有写实验。
- 多进程同时写 `pending_asks`、大量待确认询问下的延迟、schema 1 → 3 迁移与旧守护进程并存：只读了代码与作者的测试。
- 上一次 X1 审查的 F7–F13：细节已丢失，仍无法核对。

## 8. 规格变更提案（需要使用者决定）

| 来源 | 位置 | 要点 |
|---|---|---|
| S-1 | §7 P-R9、§10 | 装过 SessionStart 的安装里，PreToolUse 时库里没有的会话按 `inherited:unknown` 开始 |
| S-2 | §7 P-R5 | 例外名单与文字对齐：拿掉总是远端的"运行包"写法，或在文字里写明并接受 |
| S-4 | §7 局限 | 写明"运行代码自己去取的远端内容不算来源" |
| S-6 | §7 P-R7 | 父目录是根时记"所有位置" |
| S-7 | §7 P-R6 | 判决是 deny 的动作不打标记（可选） |

S-3、S-5 是实现问题，不用改规格。R-8 仍建议暂不处理。
