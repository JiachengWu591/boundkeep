# M1c / M1c-2 X1 审查：H-1 到 H-4 的修复

日期：2026-10-22。依据：`docs/reviews/M1c2-security-review.md`（H-1 参数文件、H-2 pylint `--output-format`、H-3 Bash 环境变量前缀、H-4 PowerShell 非常量参数）。**H-5（`trust add` 的终端检查）与 H-6（硬链接）没有改**，M-1 到 M-3 与低危也没有改，见第 5 节。没有提交，没有改策略规则（`policies/*.yaml` 只加了 `tests:` 用例），没有碰 `~/.boundkeep` 与 `~/.claude`。

## 1. 结论

四项都在**归一化层**修，用新的灰色原因，所以策略规则一条没改（`allow` 规则本来就不匹配灰色动作）。审查报告附录 A 的 17 条用例，H-1 到 H-4 的 15 条现在都是 gray；剩下的 2 条是 L-1（`pytest --debug=C:x` 与 `python -X pycache_prefix=…`），按任务范围没改。

| 编号 | 修法 | 新的灰色原因 |
|---|---|---|
| H-1 | 工具的**任何**参数（位置参数、选项的值、`--` 之后）以 `@` 开头就灰色；七个工具、Bash 与 PowerShell 一样 | `devtool-argument-file` |
| H-2 | pylint 的 `--output-format` / `-f` 的值必须是内置报告器名（`text parseable colorized json json2 msvs github`，逗号连接），否则灰色 | `devtool-output-format` |
| H-3 | Bash 工具命令前的环境变量前缀只认一份短白名单（`CI`、`NO_COLOR`、`TERM`、`LANG`、`LC_*`、`PYTHONHASHSEED`、`PYTHONUTF8` ……），其余灰色 | `devtool-env-prefix:<名字>` |
| H-4 | allow 名单上的 PowerShell cmdlet 的参数里有非路径的展开（`$env:X`、`"x$env:X"`、`${env:X}`、`$global:X`；`$true`/`$false`/`$null` 除外）就灰色 | `ps-dynamic-arg` |

## 2. 改了什么

- `src/boundkeep/normalize/programs.py`：`devtool_gray_reasons(tool, args, values)`（H-1、H-2 的共用函数，两种方言都调它）、`devtool_env_is_safe(name)` 与常量 `DEVTOOL_ARGFILE_GRAY`、`DEVTOOL_OUTPUT_FORMAT_GRAY`、`DEVTOOL_ENV_GRAY`；`_h_devtool` 调用它；`_apply_env` 对开发工具检查前缀；原来只给 pytest 与 mypy 的参数文件灰色并入共用函数（其余工具的 `@` 操作数同样列为读路径，所以 `@.env` 仍命中 `no-secret-read`）。
- `src/boundkeep/normalize/psprograms.py`：`_dev_tool` 调 `devtool_gray_reasons` 并检查（实际上总是空的）环境前缀；`_nopath`（`ConvertTo-Json`、`Select-Object`、`Measure-Object`、`Get-Date`、`Get-Location`、`Out-String` ……）与 `_cmdlet`（读类 cmdlet：`Get-Content`、`Select-String`、`Test-Path`、`Get-Item`、`Resolve-Path`、`Get-ChildItem`、`Set-Location`、`Push-Location` 的**非路径角色**的值）加 `ps-dynamic-arg`。展开的路径（`Get-Content $HOME\a.txt`）仍交给路径层，不灰。
- `policies/default.yaml`：只加了 7 条 `tests:`（H-4 的 5 条 `expect: gray`，2 条 `expect: allow` 保证没有变成一刀切的灰色）。规则数不变（69）。
- 文档：`docs/policy-reference.md`（开发工具一节三个新原因、`allow-ps-data-shaping` 一行、"参数里的环境变量"缺口）、`docs/powershell-dialect.md`（缺口 4a、4b）、`PROJECT_SPEC.md` §7 的开发工具段（契约补充，长期方向是选项白名单）。

## 3. 测试

- 新 `tests/unit/test_m1c2_review_fixes.py`：708 个用例（Windows 主机上其中 26 个因为 PowerShell 只跑 Windows 假机器而在 POSIX 参数上跳过）。分类器层：七个工具 × 8 种 `@` 写法 × 两种方言；`@` 的反例（`a@b.py`、单个 `@`、`--`）；pylint 17 种带文件或类的 `--output-format` 写法（含 `-f`、`-ftext:…`、唯一缩写 `--output-form`）与 12 种内置写法；七个工具 × 21 个不在白名单的环境变量名、× 17 个白名单名；13 个 PowerShell cmdlet × 5 种展开 × 3 种位置、× 常量与布尔字面量的反例；读类 cmdlet × 7 个非路径参数。整条管道层：审查给出的 H-1 到 H-3 共 ~50 条命令在 trusted / untrusted / strict 三种策略下都不是 allow；H-4 的 33 条在有无信任时都是 gray 或 ask；30 多条普通写法（`pytest -q`、`pylint --output-format=json src`、`CI=1 pytest -q`、`Get-ChildItem | Select-Object -First 5` ……）仍然是 allow，没有变成一刀切的灰色。再加：策略自带 `tests:` 里有这批命令、语料里有 `m2r-` 条目、文档里有这四个原因。
- `tests/corpus/pipeline_m1c2_trusted.yaml` 加了 **111 条 `adv: true` 的 `m2r-*` 条目**（H-1 43、H-2 11、H-3 24、H-4 33），含"每个开发工具 × `@` 写法 × 两种方言"与"每个开发工具 × 一个不在白名单的环境变量"；`expect` 与 `expect_untrusted` 是观察到后逐条核对过的判决（都不是 allow）。它们同时被 `test_trusted_corpus_entry`（信任策略）与 `test_pipeline_corpus`（随附策略）运行，也被"信任策略下 `adv` 的 shell 条目永不 allow"的硬不变量覆盖。
- 这一轮是先改代码、再写测试；"修之前确实是 allow"由审查当时的复现（附录 A 的 17 条在修之前全部是 allow）证明，我没有把新测试文件放回旧代码上再跑一遍。

## 4. 验证

- `uv run ruff check .`、`ruff format --check .`（176 个文件）、`mypy`（48 个源文件，strict）：干净。
- `boundkeep test`（`BOUNDKEEP_HOME` 指向临时目录）：default 775 次运行（768 + 7 条只在 Windows 上跑的新用例）0 失败，strict 280 次运行 0 失败。
- `scripts/measure_ask_rate.py`：Windows 54.2、POSIX 53.3，与修复前完全一致；与设计目标有差异的条目 0 个（合成语料里没有用到被收紧的写法，所以数字不动；这不说明真实会话里没有影响，见第 5 节）。
- 完整 `uv run pytest`：见第 6 节。
- 对照审查附录 A 的 17 条：H-1 到 H-4 的 15 条现在都是 gray；`pytest --debug=C:x`（Windows）与 `python -X pycache_prefix=…`（两种方言）仍是 allow，那是 L-1。

## 5. 没做的与需要你知道的

- **H-5、H-6 没改**（任务只要求 H-1 到 H-4）。规则冻结前它们仍然开着；在它们修好之前，`trusted_projects` 保持默认关闭。
- **M-1（`pytest.toml`）、M-2（跨调用链的污染位）、M-3（信任范围）与 L-1 到 L-6 没改。**
- **没有换成选项白名单**：本次是对已知的三类漏洞的最小修补。黑名单（`flags_none`）仍然在，审查建议的长期方向（每个工具的安全选项白名单，未列出的选项灰色）需要新的匹配字段，改规格，不在这次范围。
- **会增加询问的地方**（真实使用里可能感觉到）：带 `@` 开头参数的开发工具命令；`pylint --output-format=…` 用了内置名以外的值；Bash 里 `FOO=1 pytest`（名单外的前缀）；PowerShell 里这些 cmdlet 带了变量参数（`Select-Object -First $n`、`Get-Content a.txt -Tail $n`、`Where-Object Name -eq $x`）。`$HOME\…` 之类作为路径的展开不受影响。
- **H-4 只覆盖 allow 名单上的 cmdlet**：名单之外没有 allow 规则（本来就是灰色或 ask），没有改。`Out-String`、`Select-Object` 等在 `_NOPATH` 里的 cmdlet（含 `Write-Output`）现在对任何展开参数都灰色，对 allow 没有影响。
- **pylint 的行为没有在真实 pylint 上验证**（没装）：H-2 的修法只依赖"只认内置报告器名"，不依赖对 pylint 行为的猜测，所以即使 pylint 的实际语法与文档略有出入，也只是更严。
- **没有在真实 Claude Code 里验证**（这一轮只改归一化层，冒烟 `smoke_claude_m1c2.py` 没重跑；它会花几美分，由你决定）。

## 6. 完整套件

`uv run pytest -q`（Windows 主机，约 44 分钟）：**22671 通过、105 跳过、5 失败**。5 个失败：

- `tests/unit/test_m1c2_devtools_bash.py` 的 4 个用例**编码了被有意改掉的旧行为**，我改了它们的期望（这是整个改动里唯一改过的旧期望）：`test_harmless_env_prefix_is_still_a_dev_tool`（旧：`FOO=1 pytest -q` 无灰色原因；现在 `FOO=1` 不在白名单里，改用 `CI=1`，另加一个断言 `FOO=1`/`RUFF_OUTPUT_FILE=…` 仍是开发工具但带 `devtool-env-prefix`）；`test_c_argument_files_are_gray`（旧：ruff 不是参数文件工具；现在所有工具的 `@` 词都灰色）；`test_classify_a_code_env_prefix_is_gray`（旧：只有 `env-code-injection:`；现在先有 `devtool-env-prefix:` 再有它）。
- `tests/unit/test_norm_bash.py::test_work_is_roughly_linear`：计时断言，完整套件的负载下超了阈值；单独运行通过（M1c-2 的审查之前就有这类计时测试，与本次改动无关，我没有改它）。

改完这 4 个期望之后我只重跑了这两个文件和相关文件（`test_m1c2_devtools_bash.py`、`test_m1c2_review_fixes.py`：1145 通过、26 跳过），**没有重跑完整套件**。ruff、`ruff format --check`（177 个文件）、mypy 是在最后一次改动之后跑的，干净。Linux 容器没有跑。
