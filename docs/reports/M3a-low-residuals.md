# M3a 低危残余（S-1、S-2、S-3、S-5、S-6、S-7）验收报告

日期：2026-11-01。依据：`docs/reports/M3a-closeout.md` 第 5 节、`docs/reviews/M3a-rereview-2.md` 第 3、8 节。基线：`fec0fce`（`m3a-done`）。规格：修订 9（使用者 2026-11-01 说"按建议实现"，即第 7 节各提案的建议方案）。没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次，没有起草攻击样本，没有运行 `taint clear`、`trust add`。所有复现都是惰性负载和假机器路径，LLM 只用 `FakeBackend`。

## 1. 结论

**通过，已提交（`4906558` 代码、`cb58d91` 规格与文档），未推送、未打标签。** 六条都已处理，有测试，全量测试 27203 通过、169 跳过、0 失败（第 5 节，这次全量也包括另一个会话做的前缀路径修复）。条件：新路径只有单元测试与假事件，真实宿主里没有跑；真实冒烟重跑通过，但它只验证原有链路（第 8 节第 1 条）；S-3 与 S-7 只解决了一部分（第 6 节）。

有三条和复审的说法不一样，都是复现之后才发现的：

- **S-5**：复审点名的 8 种写法，默认策略下修改之前**已经会打标记**（复审第 7 节写明 S-5 只读了代码）。真正漏掉的是程序表之外的 git 子命令（别名 `git co main`、外部命令 `git foo`）。
- **S-2**：`pipx run`、`uv tool run` 根本到不了 `_MOVES_CODE`，只从名单删掉没有效果（第 3.3 节）。
- **S-1**：配置了 LLM 时 `UserPromptSubmit` 先写一行，"库里没有"不成立，只改 `tool_call` 接不住（第 3.6 节）。

## 2. 交付物

| 文件 | 说明 |
|---|---|
| `PROJECT_SPEC.md` | 修订 9：§7（P-R5 的名单与 PostToolUse、P-R6 的 git 名单、P-R7 的根目录、P-R9 的漏记 SessionStart、deny 不打标记、标记的类别）、§10 |
| `src/boundkeep/daemon/pipeline.py` | S-3：`_note_shell_result`；S-7：deny 不打标记；S-1：`session_start_expected`，只有这一个来源时不打标记 |
| `src/boundkeep/daemon/server.py` | S-1：读安装记录（文件变了才重读），传给管线 |
| `src/boundkeep/install.py` | S-1：`session_start_expected` |
| `src/boundkeep/session/store.py` | schema 4（`project_marks.kinds`）；S-1：`unknown_inherited`、晚到的 `startup` / `clear` |
| `src/boundkeep/session/marks.py` | S-5：名单与表外子命令；S-6：`_config_mark`；S-7：`written_places` 带类别 |
| `src/boundkeep/session/sources.py` | S-2：拿掉 `dlx`、`create`、`pipx run`、`pnpx`；认 `NAMED_PACKAGE_FLAG` 与 `REMOTE_PACKAGE_RUNNERS` |
| `src/boundkeep/session/facts.py` | S-1：`NO_SESSION_START_SOURCE` |
| `src/boundkeep/normalize/programs.py` | S-2：npx 一类调用的标记 `--named-package`；`uv run --with`、`uv run <URL>` 的标记 `uv-run-remote`；认识 `pnx` |
| `src/boundkeep/taintcmd.py` | S-7：`taint list` 显示类别；S-6："所有位置"的说明 |
| `src/boundkeep/policycli.py`、`src/boundkeep/doctor.py` | 新参数；SessionStart 的提示 |
| `tests/unit/test_m3a_low_residuals.py`（新） | 215 条，全部通过（Windows，含 PowerShell 用例） |
| `tests/unit/test_review2_programs_classify.py`、`tests/unit/test_m3a_session_store.py` | 两处既有断言的预期值，见第 4 节第 5、6 条 |
| `docs/threat-model.md`、`docs/policy-reference.md`、`docs/privacy.md`、`docs/architecture.md`、`README.md`、`docs/reports/M3a-closeout.md`、`CLAUDE.md` | 残余与状态 |

## 3. 逐条对照

### 3.1 S-3：shell 来源在 PostToolUse 也记

- **先确认 matcher**：`policy.loader.post_matcher_for` 在 `llm_audit.backend` 不是 `none` 时返回 `*`，否则返回来源名单。没有后端时 Bash、PowerShell 匹配不上，宿主根本不启动这个 hook。测试 `test_what_this_fix_cannot_reach_without_a_backend` 把这一点钉住了。负载里确实有 `tool_input`（夹具 `PostToolUse__Bash_gitbash.json`、`PostToolUse__PowerShell.json`）。
- **复现**：不发 PreToolUse，直接发 `gh issue view 12` 的 PostToolUse，修改前会话不带污染，之后 `pytest -q` 不问。
- **修法**：`decide` 处理 PostToolUse 时，对 shell 工具再跑一次归一化与 `network_source`，命中就 `source_seen`。不看判决（调用已经运行了），不看策略（策略坏了也照记），不扫目录。守护进程把 PostToolUse 放在单独的线程里处理，不进审查的线程池，也不阻塞事件循环。
- **测试**：Bash 与 PowerShell 的来源与非来源、畸形负载、策略损坏、库不可用、窗口重新开始、守护进程的完整路径。
- **修法覆盖不到的情况**（第 6 节第 1、2 条）：没有后端的安装不变；守护进程在工具运行完时还没回来也不变。复审描述的场景只有"工具运行完之前守护进程已经回来"这种情况才被修好。
- **附带效果**：`audit-only` 下被规则 deny、照样运行的网络调用，现在在 PostToolUse 时算来源（信息项 S-8），只在配置了后端时成立。方向是对的：调用确实运行了。

### 3.2 S-5：会改工作区的 git 子命令

**两种做法的比较（实测，默认策略，读过网页的会话）：**

| 写法 | 修改前 | 走的分支 |
|---|---|---|
| `git revert`、`stash branch`、`worktree add`、`sparse-checkout`、`submodule update`、`bisect`、`read-tree -u`、`checkout-index` | **已经打标记** | 规则没放行，带 `file_write`，没有可写路径 |
| `git add .`、`fetch`、`push`、`branch x`、`tag`、`gc`、`init` | 已经打标记 | 同上（`git add .` 是路径分支） |
| `git commit -m x`、`git stash` | 不打 | 规则放行（`allow-git-commit-message`、`allow-git-stash`） |
| `git co main`、`git ci -m x`、`git foo`、`git $SUB` | **不打** | 灰色，没有任何标签：**这才是漏洞** |

- 只加名单：默认策略下这 8 种写法结果不变，别名和外部命令仍然漏。
- 完整的"只读白名单"：能接住表外子命令，但规则放行的 `git commit -m`、`git stash` 也会打标记，而它们不带进新内容；还要按参数判断 `git remote -v`、`git config --get`、`git branch --list`。

**选择：两者各取有用的部分。**

1. 规则没放行、程序表也不认识的子命令（灰色原因 `git-unknown-subcommand:`、`git-dynamic-subcommand`）按可能写算。这是真正补上漏洞的一条。
2. 复审的名单也加上，规则放行时也记。它只对使用者自己写了 allow 规则的策略有作用。

`git worktree list`、`submodule status`、不带 `-u` 的 `read-tree` 不进名单。

- **测试**：`git co` 等 4 条修改前失败；名单的 9 种写法在 `hidden_write(action, "allow")` 下修改前失败；默认策略下名单的 9 种写法修改前修改后都通过（回归钉）；只读写法不打标记；PowerShell 下 `git co main` 相同。

### 3.3 S-2：运行远端包

**先查文档（2026-11-01 读取）：**

| 写法 | 官方文档 | 决定 |
|---|---|---|
| `pnpm dlx`、`pnpx`、`pnx` | 从注册表取包，`pnpx` 与 `pnpm dlx` 是 `pnx` 的别名（pnpm.io/cli/dlx） | 算来源 |
| `yarn dlx` | 在临时环境里安装并运行（yarnpkg.com/cli/dlx） | 算来源 |
| `npm init <名字>`、`npm create` | `npm init foo` 就是 `npm exec create-foo`；不带名字只写 package.json（docs.npmjs.com npm-init） | 带名字算，不带不算 |
| `pipx run` | 在临时环境里运行最新版本，默认从 PyPI 取（pipx.pypa.io 首页；`run` 的详细页面我没有读到） | 算来源 |
| `uvx`、`uv tool run` | 同一个命令，工具装进临时隔离环境（docs.astral.sh/uv/guides/tools） | 算来源 |
| `go run 包@版本` | 忽略当前目录的 go.mod（pkg.go.dev/cmd/go） | 算来源 |
| `pnpm exec` | 把 `node_modules/.bin` 加进 PATH；文档没说它会下载，也没明确排除 | 不算 |
| `npx`、`npm exec` 裸名字 | 与本地已有的任何版本匹配，没有才下载（docs.npmjs.com npx、npm-exec） | **区分不了**，不算 |
| `npx 名字@版本` | 只有名字和版本都与本地依赖相同才算匹配 | 算来源 |
| `bunx 名字@版本` | 带版本直接跳过本地（bun.com/docs/pm/bunx） | 算来源 |
| `npx @scope/名字` | **文档没有说 scope 影响解析**，它和裸名字一样先看本地 | **区分不了**，算来源（使用者接受） |

`yarn exec`、`bun exec` 没有查官方页面，按 `pnpm exec` 同样处理，这一条是推断。

**S-2 的修法比任务写的多一步。** `peel_runner` 把 `pipx run`、`uvx`、`uv tool run` 剥掉，动作的程序是里面的 `cowsay`，`network` 为假，`network_source` 第一步就跳过了。所以要看 `Action.wrappers`（`REMOTE_PACKAGE_RUNNERS`）。`_MOVES_CODE` 里的 `pipx run` 只在没被剥掉的写法里有用（`pipx --verbose run x`）。

**任务点名之外加上的同类写法**：`pnpx`、`pnx`、`create` 一族、`npm init <名字>`、`uv run --with`、`uv run <URL>`、`go run 包@版本`，以及带 URL 或 `--package`、`--yes`、`--call` 的 npx 写法。

**`npx @scope/名字` 算来源的代价**：`npx @biomejs/biome check` 这种本地依赖也算来源，而且它带 `exec`，自己那次就给项目打标记（S-9）。这样的 JS 项目每个会话都可能重新打标记，配置了 LLM 时这个项目里带 `exec` 的灰色调用就一直不送审。反过来，裸名字的残余不变：`npx cowsay` 在项目没有 cowsay 时下载并运行，批准之后会话不带污染。

**测试**：`RUNS_REMOTE_PACKAGE` 45 种写法算来源，`RUNS_THE_PROJECTS_CODE` 25 种不算，PowerShell 10 种，加上会话层的 4 条。

### 3.4 S-7：判决是 deny 的调用不打标记（P-S7 方案 A）

- **复现**：读过网页的会话里 `python gen.py && rm -rf ~/.ssh` 被规则 deny，什么也不会运行，却记下 `/home/testuser/proj` 与 `~/.ssh`；另一个会话的 `make test` 变成 `gray-marked-project`，后端调用 0 次。
- **修法**：`enforce` 下规则判决是 deny 的调用跳过打标记（`audit-only` 下它会运行，照样打）。`project_marks` 加一列 `kinds`（schema 4，旧行显示为未知），`written_places` 给每个位置算类别：`write`（看得到路径的写）、`hidden-write`（看不到路径的写）、`run`（规则没放行的运行代码）；`taint list` 显示为 `(after WebFetch; by a command that runs code)`。
- **没有改的**：LLM 的 deny 仍然打标记。标记在送审之前写，否则审查超时时调用可能被批准运行却没有标记。**被问、用户拒绝的调用也仍然打标记**，这是 S-7 里更常见的一半（第 6 节第 3 条）。
- **测试**：3 种 deny 写法不留标记、别的会话不受影响；deny 不再把项目挡在 LLM 之外；`audit-only` 照样打；ask 与 LLM deny 仍然打；类别的计算与合并；上限时"所有位置"带上这次调用的类别；schema 1、2、3 迁移且保留旧标记；`taint list` 的输出。

### 3.5 S-6：写在根目录的开发工具配置（P-S6 方案 A）

- **复现（假机器）**：`E:\pytest.ini` 记 `e:/pytest.ini`，`/pytest.ini` 记 `/pytest.ini`，`E:\proj`、`/srv/proj` 都不算带标记。
- **修法**：`_config_mark`：配置文件的目录是根时记 `*`。其余写法不变（`E:\notes.txt` 仍记文件，`E:\lab\pytest.ini` 仍记 `e:/lab`）。`taint list` 的说明改成写明这种来历和"只有 `--all` 能解除"。
- **测试**：Windows 与 POSIX 的根目录配置，其余写法不变，`clear_marks(目录)` 清不掉、`--all` 清得掉。

pytest 向上查找根目录配置的行为是复审的说法，我没有另外实测。

### 3.6 S-1：库里没有的会话（P-S1 方案 B）

- **复现**：新库、不发 SessionStart，受信任项目里 `pytest -q` 无决定；发 `source: fork` 之后同一调用被问。配置了 LLM 时先发提示词再调用，也是无决定（`add_prompt` 写了一行）。
- **修法**：
  - `install.session_start_expected`：所有安装记录的 `events` 都有 SessionStart 才为真；没有记录为假；记录读不出为真。守护进程按文件的修改时间与大小缓存。
  - `tool_call` 与 `add_prompt`：库里没有这个会话时写一行，来源 `inherited:unknown`，窗口从 0 开始。
  - `decide`：只有这一个来源时不打项目标记，别的来源一到就照常打。
  - `session_start`：`startup` / `clear` 把只有这个来源的行改回干净，防宿主没等 hook 结束。
- **测试**：会话被问；旧安装不变；各种写法不留标记；真来源之后照常打；窗口照常走；晚到的 `startup` / `clear` 改回干净，别的 `source` 不改，真来源不被抹掉；提示词先到；安装记录的 8 种情况；守护进程的完整路径，包括清单变化后立刻生效。

## 4. 与计划的偏差

1. S-5 没有按"加名单就修好"处理，原因见第 3.2 节。
2. S-2 动了归一化层（`programs.py`），不只是 `sources.py`，原因见第 3.3 节。
3. S-2 的范围比"至少这四种"大，都是同一类写法。
4. **SessionStart 不带 `source` 时的来源名改了**：原来也叫 `inherited:unknown`，现在叫 `inherited:no-source`（字面值 `unknown` 也一样），因为 `inherited:unknown` 现在专指漏记 SessionStart，只有它不打标记。P-R9 的行为不变，测试 `test_a_session_start_that_inherits_still_marks` 钉住了。
5. **改了一条既有测试的预期**：`test_peel_runner` 钉着 `uv run --with` 的标记名 `uv-run`，现在是 `uv-run-remote`。被剥离的内容和判决都没变，同时补了 `uv run -p ... cmd` 仍是 `uv-run` 的用例。
6. **改了一条既有测试的预期**：`test_nothing_but_names_and_counters_is_stored` 钉着 `project_marks` 的列，现在多 `kinds`。它只存三个固定的词，不存工具内容，`docs/privacy.md` 已同步。
7. 一个任务里两次停下：S-1、S-6、S-7 按 X5 先提案，使用者决定之后才实现，全量测试放在最后。

## 5. 度量

| 项目 | 结果 |
|---|---|
| 新测试，S-2、S-3、S-5 修改前 | 79 failed, 71 passed（当时的 150 条；通过的是回归钉和只判"不算"的用例） |
| 新测试，S-1、S-6、S-7 只搭好接口、行为没改时 | 34 failed, 181 passed（215 条）。`written_places`、`session_start_expected` 这两个纯函数是先写好再跑的，它们的 12 条用例没有经历先失败 |
| 新测试修改后 | 215 passed |
| 相关测试（M3a 的 12 个文件） | 修复第 4 节第 6 条之前 666 passed, 1 failed, 1 skipped；那条修好之后所在文件与 e2e 目录合跑 174 passed（4 分 37 秒） |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过；77 个源文件没有问题 |
| `boundkeep test` default / strict | 1138 / 0 失败，334 / 0 失败 |
| 全量 `uv run pytest -q` | **27203 passed, 169 skipped, 0 failed, 1:12:40**（2026-11-02 03:53:23 到 05:06:06）。经过见下面"全量测试的经过" |
| 评测 | 规则与策略没有改。动了归一化层，所以按 `M3a.md` 第 5.3 节的命令重跑到 scratchpad 里比对（全部改动之后又跑了一次）：`rules-only.json`、`rules+taint.json` 除日期与延迟外**完全相同**；`report.md` 只有运行日期和 4 行延迟不同。`eval/` 没有改动，不重新生成 |

**延迟**：比对时规则路径的 p50 由已提交报告的 3.75 变成 5.93 ms，所以我把基线 `fec0fce` 与 S-2、S-3、S-5 改完时的代码在同一台机器上交替各跑了 3 次（电源方案 Silent，`rules-only` 全部样本那一行，p50 ms）：基线 5.74、10.53、6.46，当前 6.89、6.84、5.97。范围相互重叠，**没有测出退化**；全部改动之后的一次是 5.82。与已提交报告的差别来自运行环境，不是这次改动（已提交的那次运行条件我没有记录，这一点是推断）。这只量了 PreToolUse 的路径。配置了 LLM 后端时，每次 shell 调用的 PostToolUse 多跑一次归一化，这部分没有单独测。

**全量测试的经过**（共三次，只有第三次是最终代码）：

| 次 | 谁跑的 | 时间 | 结果 |
|---|---|---|---|
| 1 | 这个会话 | 2026-11-01 09:13:45 开始（Silent） | **静默中断，没有结果，原因不知道**。只有开始记录，没有结束记录。我把输出接到了 `Select-Object -Last 60`，它要等进程结束才写，所以连跑到哪里都看不出来 |
| 2 | 另一个会话 | 到 2026-11-02 01:46，1:17:30 | 1 failed, 27086 passed, 169 skipped。失败的是 `tests/unit/test_norm_paths.py::test_normalization_is_idempotent` |
| 3 | 另一个会话 | 2026-11-02 03:53:23 到 05:06:06，1:12:40（Turbo，接电源，据那个会话的记录） | **27203 passed, 169 skipped** |

- **第 2 次的失败不是这批改动带来的**：这批改动没有碰 `normalize/paths.py`、`normalize/model.py` 和那个测试文件。根因是路径规范化先读第一段、Win32 先折叠再读第一段，这个错误在 `m3a-done` 上就有，Hypothesis 这次才抽到。修复不属于 S-1 到 S-7，记录在 `docs/reports/M3a-prefix-folding.md`，由那个会话负责。
- **第 3 次覆盖的是工作区的全部改动**：这批改动加上前缀路径的修复。我核对过输出的最后一行，也核对过 `src/`、`tests/` 里最新的文件是 03:50:54，早于开跑时间。退出码 0 是那个会话的记录，输出文件里没有。
- 评测在前缀路径修复之后由那个会话又跑了一次，结果与上表相同（`M3a-prefix-folding.md` 第 4 节）。

## 6. 已知问题与局限

| # | 描述 | 影响 | 阻塞 M3b？ |
|---|---|---|---|
| 1 | S-3：没有后端时 matcher 到不了 shell 工具，这个修法完全不起作用（使用者决定不加 hook） | 只影响受信任项目的开发工具（没有后端时灰色本来就问） | 否 |
| 2 | S-3：守护进程到工具运行完还没回来，PostToolUse 被客户端静默丢弃，什么也记不下。这是复审场景的常见情形 | 这段时间被批准的来源，之后不算。S-1 的修法盖住了"会话第一次被守护进程看到"的部分，**会话已经在库里的盖不住** | 否 |
| 3 | S-7：被问、用户拒绝的调用仍然打标记。被注入的 agent 可以用一次会被拒绝的调用让项目带标记，配置了 LLM 时这个项目带 `exec` 的灰色调用不送审 | 询问疲劳，不是绕过。解决办法是推迟到 PostToolUse，代价是新的失败即放行，等 `auto` 模式测过再看 | 否 |
| 4 | S-7：LLM 的 deny 仍然打标记 | 同上，范围更小 | 否 |
| 5 | S-6：`*` 过宽。写 `E:\pytest.ini` 让所有盘上的项目都带标记，只有 `--all` 能解除（它清掉所有标记）；加上第 3 条，被拒绝的一次尝试就有这个效果 | 少见，但一次影响全机 | 否 |
| 6 | S-1：只要有一条旧安装记录，所有安装都按旧行为（从干净开始）。`doctor` 提示重新 `init` | 重新 `init` 就解决 | 否 |
| 7 | S-1：漏记 SessionStart 的 fork 只在自己会话里再问，它的写不打项目标记 | 要同时发生两件少见的事 | 否 |
| 8 | S-1：守护进程晚于会话启动时，那个会话的开发工具一直再问，没有手动解除的办法（`/clear` 换新会话就好） | 多问，不打标记 | 否 |
| 9 | S-2：裸名字分不出本地还是下载 | 第 3.3 节 | 否 |
| 10 | S-2：`python -m pipx run x`、`python -m uv tool run x`、`npm innit vite`（`init` 的别名）认不出；`pnpm.cmd dlx x`、`npx.cmd x@1` 在 PowerShell 下是灰色 `ps-script-exec`，`.cmd` 不进程序表。都是要问的灰色，批准之后不算来源，属于 S-4 那一类 | 低 | 否 |
| 11 | S-3：PowerShell 辅助进程没就绪时（守护进程启动后约 2 秒），PreToolUse 与 PostToolUse 都认不出；PostToolUse 只记会话，不补项目标记（与来源工具现在的行为一致） | 窗口很短；守护进程不在时的写不打标记，威胁模型已写 | 否 |
| 12 | 新路径只有单元测试与假事件，真实宿主里没有跑；冒烟只验证原有链路 | 第 8 节第 1 条 | 否 |
| 13 | 第一次全量静默中断，原因不知道（第 5 节） | 之后两次都跑到了结尾，没有再现；如果是套件本身的问题，还可能再出现 | 否 |

R-8、S-4、S-8（配了后端时已附带解决，第 3.1 节）、S-9 按任务不处理。`auto` 模式的实测不在这个任务里，仍未知。

## 7. 规格变更

修订 9 已写进 `PROJECT_SPEC.md`。X5 提案的要点与决定（使用者 2026-11-01，"按建议实现"）：

| 提案 | 现状 → 改成 | 采纳 | 没选的方案及其代价 |
|---|---|---|---|
| P-S1（§7 P-R9、§10） | 漏记 SessionStart 从干净开始 → 所有安装都注册时按 `inherited:unknown` 开始 | B：只有这一个来源时不打项目标记 | A（也打标记）：守护进程手动启动，晚于会话很常见，一件小事变成所有会话的长期状态，要 `taint clear`。C（不改）：§10 的放行留着。D（客户端落盘补记）：新的持久化路径，不值得 |
| P-S6（§7 P-R7） | 根目录的配置只记文件 → 记"所有位置" | A | B（每个盘符一个键）：约 15 行，只影响同一个盘，POSIX 上仍等于所有位置。C（不改） |
| P-S7（§7） | deny 也打标记 → `enforce` 下规则 deny 不打；标记记类别 | A | A'（不加类别）：不用迁移，但看不出为什么带标记。B（ask 推迟到 PostToolUse）：被拒的询问也不打了，但 PostToolUse 丢了就没有标记，新的失败即放行。C（不改） |
| P-S35（§7 P-R5、P-R6） | S-3、S-5 的文字比代码窄 → 对齐，不改设计 | 接受 | 不改：规格比代码窄 |

另外两项决定：`npx @scope/名字` 算来源；没有后端时不给 shell 工具挂 PostToolUse（每次 shell 调用多一个 hook 进程，按现有估计约 45 到 50 ms，只为第 6 节第 1 条那一小类）。

影响面：会话状态库 schema 3 → 4（升级时自动迁移，旧标记保留；旧版本的守护进程打不开新库，会报 schema 版本并按状态未知判）。已完成步骤的结论不变：规则、策略与评测数字没变。

## 8. 需要你决定的事项

1. **真实冒烟 `scripts/smoke_claude_m3a.py`：已跑**（2026-11-02，使用者说"先跑冒烟"）：26 项检查 0 失败，脚本估算约 0.225 美元，记录在 `docs/hook-behavior.md`。它不覆盖这次新增的路径（漏记 SessionStart、PostToolUse 补记、deny 不打标记），也不覆盖 schema 3 的迁移，只验证原有链路没被破坏；要覆盖新路径得另外加检查。`auto` 仍然没有测到。
2. **提交：已完成**（2026-11-02，使用者说"提交"）：`4906558` 代码，`cb58d91` 规格与文档。前缀路径修复单独提交（`a3b38c5` 代码，`fa494e9` 记录）。`CLAUDE.md` 与 `PROJECT_SPEC.md` 的进度随 `cb58d91` 提交。没有推送，没有打标签。

## 9. 进入下一步的前置条件

- M3b 要你自备密钥、确认费用，在你自己的 shell 里运行。收尾记录第 5 节里计划在 M3b 之前做的低危，到这里只剩 `auto` 模式的实测（"M3b 之前再测一次"）。
- 正在运行的守护进程要重启才用上新代码；已有的安装要重新 `boundkeep init` 才会有 SessionStart 的记录（`doctor` 会提示）。
