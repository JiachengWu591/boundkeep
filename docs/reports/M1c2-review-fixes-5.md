# M1c / M1c-2 X1 第二次复审：R2-1、R2-2 与低危的修复

日期：2026-10-24。依据：`docs/reviews/M1c2-fixes-rereview-2.md`（同一复审者的第二次复审，1 条高危、1 条中危、5 条低危）。接 `M1c2-review-fixes.md` 到 `-4.md`。**没有提交**，没有碰 `~/.boundkeep` 与 `~/.claude`。

## 1. 结论

| 编号 | 严重度 | 修法 |
|---|---|---|
| R2-1 | 高 | `dynamic_args` 里"已被路径层消费"从文本后缀匹配改成精确判断（`event.py::_consumed_as_path`） |
| R2-2 | 中 | `programs.devtool_exe_in_env` 先用 `posixpath.normpath` 折叠 `.` 与 `..`，开头仍是 `..`（环境在项目之外）不算项目的环境 |
| R2-4 | 低 | `trust list` 对守护目录条目多印一行 `should not be trusted (…): boundkeep trust remove` |
| R2-5 | 低 | 白名单环境变量的值：除 `TZ` 外不允许有 `/`；不能以 `-`、`@` 开头；不能含 `..` |
| R2-3 | 低 | 不改：29000 个文件的树 `Grep` 目录变灰（安全方向），预算保持 0.35 秒；写入"可用性代价" |
| R2-6 | 低 | 不改：`env`/`venv` 目录的源码写入在 strict 里是 deny，预期代价 |
| R2-7 | 低 | 不改：变严的命令清单已知，其中带变量的写法是预期代价，项目内可执行文件是设计目标 |

## 2. 设计要点

- **R2-1 的精确判断**：一个词算"被路径层当作路径"，只有三种情形：整词等于路径文本；以 `-` 开头、**第一个** `=` 或 `:` 之后的部分整体等于路径文本，且选项名部分不含 `$`、反引号、`*`、`?`、`[`、`{`；单字母短选项的 `-oVALUE`。其余一律保留 `dynamic_args`。`"$u@a.txt=tests"`、`$SECRET_TOKEN=src`、`?a.txt=tests`、`[@]a.txt=tests` 不以 `-` 开头，所以永远不被豁免；`--$u=src` 的选项名本身会展开，也不豁免。
- **R2-2**：判断前把 `\` 换成 `/` 再折叠。`./venv/../pytest` → `pytest`（无目录段）→ 带 `unvetted-exe`；`./venv/./bin/pytest`、`./venv/bin/../bin/pytest` 折叠后仍在环境里，照旧放行；`../venv/bin/pytest` 在项目之外，不算。`python -m pytest` 的解释器路径用同一个函数，同时修好。

## 3. 测试与语料

- 新 `tests/unit/test_m1c2_rereview2_fixes.py`（259 个用例）：`_consumed_as_path` 的 24 行真值表；12 个开发工具选项位 × 5 种展开前缀 × 6 种后缀 × default/strict × 有无信任都不是 allow；复审给出的 13 条 Bash 和 5 条 PowerShell 复现；10 条字面选项值仍被理解（`dynamic_args` 为假）；`devtool_exe_in_env` 的 26 行真值表；复审列出的 8 条 POSIX 与 4 条 Windows 的 `..` 复现都带 `unvetted-exe` 且不是 allow；环境自己的工具仍 allow；R2-5 的 17 行真值表；R2-4 的两个用例。已确认对旧代码有 148 个失败（新代码 0 个）。
- 语料：`pipeline_m1c2_trusted.yaml` 加 40 条 `m2s-*`（R2-1 23 条、R2-2 12 条，全是 `adv`，受信任与不受信任都是 gray；5 条"字面值仍 allow"）。一条 Windows 绝对路径的 `..` 复现在 Windows 假机器上判决是 ask（路径在假 home 之外），所以绝对路径那条标为 `platform: posix`。
- 没有改任何旧期望。

## 4. 验证

- `ruff check`、`ruff format`、`mypy`（48 个源文件，strict）：干净。
- `boundkeep test`：default 806、strict 304，0 失败（没有新增 `tests:` 条目）。
- `scripts/measure_ask_rate.py`：POSIX 53.3，与之前一致，与设计目标有差异的条目 0 个。
- 受信任语料 + 单元测试里含 `env` 或 `trust` 的用例：5060 通过、47 跳过。
- 完整套件：见第 6 节。

## 5. 没做的与需要你知道的

- 之前接受的缺口不变：M-2（写文件再运行）等 M3a 的污染位；会话快照在内存里；`cmd /c mklink`、`fsutil` 的相对写法仍只是 ask；选项白名单没做；`trusted_projects` 保持默认关闭、不作为推荐设置。
- R2-3：大项目（约 2.9 万个文件）里对整个项目目录的 `Grep` 会多问一次。
- 没有在真实 Claude Code 里验证，Linux 容器没有跑。
- 下一步：请同一复审者（`a74f28c598b0d35a7`）只复核 R2-1 与 R2-2（尤其是 c17/c18 那批片段）；通过后规则冻结，再取 M2 基线。

## 6. 完整套件

**最终的完整运行（`uv run pytest -q`，Windows 主机，约 49 分钟）：24841 通过、167 跳过、0 失败**（上一轮 24433，多出的 408 个是本轮新增的用例与语料）。Linux 容器没有跑。

过程：改完 R2-1/R2-2 后第一次跑受信任语料，只有 1 条失败——我自己写的 `m2s-adv-029`（POSIX 绝对路径）在 Windows 假机器上判决是 ask 而不是 gray（假 home 之外），改为 `platform: posix`，没有放宽任何期望。
