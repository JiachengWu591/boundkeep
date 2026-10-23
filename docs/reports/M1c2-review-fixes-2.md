# M1c / M1c-2 X1 审查：H-5 与 H-6 的修复

日期：2026-10-22。依据：`docs/reviews/M1c2-security-review.md`（H-5 agent 可以让项目受信任，H-6 硬链接）。接 `docs/reports/M1c2-review-fixes.md`（H-1 到 H-4）。**没有提交，没有碰 `~/.boundkeep` 与 `~/.claude`**（硬链接实验都在 `%TEMP%` 的一次性目录里）。

## 1. 结论

| 编号 | 修法 | 位置 |
|---|---|---|
| H-5a | `trust add` 在环境里有 `CLAUDECODE` 或 `CLAUDE_CODE_ENTRYPOINT` 时拒绝（`Start-Process` 起的子进程会继承它们）；`remove`、`list` 不受影响 | `src/boundkeep/trust.py` |
| H-5b | 守护进程按 `session_id` 记下会话**第一个事件**时的 `trusted_projects`；之后新增的条目对那个会话不生效，删除立即生效，没有可用会话 id 就没有受信任的项目；新增被记进审计日志（`trust-changed`）并在控制台提示 | `src/boundkeep/daemon/server.py` |
| H-6a | 磁盘解析对已存在的普通文件读 `st_nlink`，大于 1 的路径带原因 `hard-linked`：`inside_project` 不再是 `true`（变为不确定），`in_scratchpad` 为 `false`，名字照旧交给 deny / ask 规则 | `normalize/paths.py`、`normalize/event.py` |
| H-6b | 新规则 `deny-link-to-guard-files`（`ln`、`New-Item`）与 `deny-link-copy-of-guard-files`（`cp -l` / `--link`）：读路径命中守护文件（与 `protect-guard-config` 同一份 glob）就 deny；运行时加的 `CLAUDE_CONFIG_DIR` 与"已安装代码"保护各有同样的孪生规则 | `policies/default.yaml`、`policies/strict.yaml`、`daemon/pipeline.py` |

真实磁盘上重跑审查的 H-6 实验（一次性目录里的联接点 + 指向"策略文件"的硬链接）：`Write` / `Edit` / `Read` 经硬链接 allow → 现在都是 gray（ask）；联接点路径照旧 deny；`Set-Content hard.yaml` 与 `'x' > hard.yaml` 本来就是 gray。

## 2. 设计要点

- **会话快照（H-5b）**：`_TrustSnapshots`（有界，最多 512 个会话，最久未用的先丢）。`effective(session_id, current)` 返回 `current` 里同时出现在该会话首次快照里的条目，和"自会话开始后新增、还没提示过"的条目。快照在内存里。`Daemon._session_policy` 在 PreToolUse（决策用）与其他事件（只记下会话）里调用，对 `Policy` 用 `model_copy(update={"trusted_projects": ...})`，不改规则。用户自己 `trust add` 之后要新开会话才生效（已写进文档）。
- **为什么不只靠终端检查**：审查实测 `Start-Process`、`cmd /c start`、`cmd /c … < CON`、`subprocess(stdin=CONIN$)` 都能让 `_stdin_is_tty()` 为真，而间接写法对规则只是灰色。环境变量检查也只是提高门槛（agent 可以清掉变量，但那是一个灰色命令，仍是 ask）；快照才是不依赖进程检测的那一道。
- **硬链接（H-6a）**：`_resolve_on_disk` 本来就对每个路径 `realpath` 一次，在同一次调用里多一个 `os.stat`，不增加磁盘查询预算，不改 `NormPath.uncertain`。事件层 `_mark_hard_linked` 把词法形式与解析后的形式都标成"不确定"，所以 `read-inside-project`、`allow-project-file-writes`、`allow-session-scratchpad` 与所有 `path_inside_project` 的规则不再匹配；`path_outside_project` 的 ask 规则（"不确定也算在外面"）会命中。
- **链接规则（H-6b）**：`ln` 的源、`New-Item -ItemType HardLink|SymbolicLink|Junction` 的 `-Value`/`-Target` 是**读路径**（`New-Item` 只有创建链接时才列读路径）。规则 id 以 `deny-link-` 开头的 deny 读规则**不进** `protected_read_globs`：它们点名的是被创建链接的目标，不是读内容；否则对含项目级 `.claude/settings.json` 的目录做 `Grep` 会被拒绝，而项目级 settings.json 可读是有意的（`docs/policy-reference.md`）。有测试。

## 3. 测试

- `tests/unit/test_m1c2_review_fixes_trust_links.py`（新，183 个用例，Windows 主机上 27 个因 PowerShell 只跑 Windows 假机器而跳过）：快照（保留、会话中途新增不生效且只提示一次、删除立即生效且加回来又生效、第一个事件是 prompt、没有可用 id、有界）；守护进程层（用真实的 `Daemon.handle`：先 ask → 加信任 → 同一会话仍 ask、新会话 none；第二个项目；别的规则不受影响；审计日志里恰好一条 `trust-changed`）；真实文件的硬链接（`os.link`）：`resolve_on_disk` 带 `hard-linked`，目录与不存在的路径与单名字文件不带；`Write` / `Edit` / `Read` / `NotebookEdit` 对硬链接不是 allow、对照的普通文件是 allow、链接删掉后又是 allow；标记保留名字（`.env` 的硬链接仍是 deny）；链接规则：两份策略的 glob 与 `protect-guard-config` 逐项相等、规则形状；31 条"链接到守护文件"× 两个平台 × default / strict 全部 deny；13 条邻居（普通文件的链接与复制、对守护文件的单纯复制与读）保持原判决；`Grep`/`Glob` 目录仍 allow；`protected_read_globs` 不含 `**/.claude/settings*.json`；`CLAUDE_CONFIG_DIR` 与已安装代码的运行时孪生规则存在且 `ln <config_dir>/settings.json …` 是 deny。
- `tests/unit/test_m1c2_trust_cli.py`：新增 5 个用例（两个标记变量各一个、拒绝时一个字节都不改、变量消失后又能用、`remove`/`list` 不受影响、空值不算）；`env` 夹具现在清掉这两个变量（这套测试扮演一个坐在终端前的人；套件在 Claude Code 里跑时变量是被继承的）。
- 语料：新文件 `tests/corpus/pipeline_x1_h6_links.yaml`，44 条（31 条 `adv: true` 的 `x1h6-link-*`，期望 deny；13 条 `x1h6-keep-*` 说明哪些写法不变）。它被 `test_pipeline_corpus.py` 在两个平台上运行。H-5 没有语料条目（它是守护进程的会话状态，不是单个事件的判决）；硬链接的真实磁盘行为不能进语料（假机器不在磁盘上），在单元测试里用 `tmp_path`。
- 两份策略各加 6 条 `tests:`（`ln` / `cp -l` / `New-Item` 创建链接 deny，单纯 `cp` 仍 ask）。规则数：default 69 → **71**，strict 53 → **55**。

## 4. 验证

- `ruff check .`、`ruff format --check .`（178 个文件）、`mypy`（48 个源文件，strict）：干净。
- `boundkeep test`：default 785 次运行、strict 290 次运行，0 失败。
- 完整套件：见第 6 节。
- 审查给出的 H-6 实验在真实磁盘上重跑（见第 1 节）。

## 5. 没做的与要知道的

- **硬链接的存量**：已经存在的硬链接（不是 boundkeep 允许创建的）经 `Write` 等是 ask，不是 deny——名字普通，boundkeep 不知道它指向哪里。选项值里的**裸文件名**（`pytest --debug=hard.yaml`，没有分隔符）不被当作路径，所以经硬链接的这类写法仍是 allow（旧缺口，H-1 里"选项白名单"的长期方向会一并解决；创建链接已经被拒绝）。
- **代价**：真的有多个名字的文件（pnpm 的 `node_modules`、`uv` 装进 `.venv` 的包、`git clone --local`）的读写会多问一次；`.venv` 里的写入因此更常被问（这与审查 M-2 的建议同向）。
- **快照在内存里**：守护进程重启后重新开始记。用户自己 `trust add` 后要新开会话才生效；这是行为变化，已写进 `docs/policy-reference.md` 与 `PROJECT_SPEC.md` §7。
- **终端与环境变量检查都不是边界**：文档已改成这样写（之前写的是"纵深防御"）。`CLAUDECODE` 可以被清掉；真正的闸门是会话快照加规则覆盖。
- **没有在真实 Claude Code 里验证**：`CLAUDECODE` / `CLAUDE_CODE_ENTRYPOINT` 在 agent 的 PowerShell 工具里确实存在（本机实测，`claude-desktop` 入口），但没有在 CLI、其他入口里确认；`session_id` 在事件里的存在是已知的（审计日志）。冒烟脚本没重跑。
- **H-5/H-6 之外没有改**：M-1 到 M-3 与低危仍然开着。

## 6. 完整套件

第一次完整运行（`uv run pytest -q`，Windows 主机，约 47 分钟）：**22926 通过、132 跳过、14 失败**。我能指认的 13 个失败（另一个我没有在输出里找到，见下）和处理：

- 9 个是新语料 `x1h6-*` 里的 PowerShell 条目被 POSIX 假机器也跑了（条目少写了 `platform: windows`）：已补，重新生成语料。
- `test_read_deny_and_ask_rules_do_not_filter_by_tool`（default、strict 各一）：这是项目的不变量"读类的 deny / ask 规则不按 `tool:` 过滤"，我的两条链接规则写了 `tool: [Bash, PowerShell]`。已删掉（规则靠 `program` 就只会匹配 shell 程序），运行时孪生规则同样。
- `test_runtime_policy_is_idempotent_and_never_loses_a_deny`：断言运行时规则数 `+ 2`，现在 `protect-guard-code` 多了两条链接孪生规则，改成 `+ 4`（唯一改过的旧期望）。
- `test_settings_io.py::test_values_and_key_order_never_change`：hypothesis 的 200 ms 截止时间在完整套件的负载下超过（`DeadlineExceeded`），单独运行通过；与本次改动无关（它第二次又在聚焦运行里超时一次，再单独运行 89 个全过）。
- 日志里我数到 13 行 `FAILED`，汇总说 14：多出的一个我没有找到（可能是同类的计时用例）。

**改完之后的完整重跑（`uv run pytest -q`，Windows 主机，约 49 分钟）：22924 通过、132 跳过、0 失败。** 下面是重跑之前、只跑受影响文件那一轮的记录，留作过程说明：改完之后只重跑了受影响的文件：新测试、`test_pipeline_corpus.py`、`test_policy_rules.py`、`test_review2_core_misc.py`、`test_settings_io.py`——**5094 通过、30 跳过、1 失败**（那个失败就是上面的 hypothesis 计时用例，单独跑通过）。ruff、`ruff format --check`（179 个文件）、mypy 在最后一次改动之后跑，干净；`boundkeep test` default 785、strict 290 次运行 0 失败，规则数 71 / 55；`measure_ask_rate` 仍是 54.2 / 53.3。Linux 容器没有跑。
