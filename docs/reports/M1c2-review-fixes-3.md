# M1c / M1c-2 X1 审查：中危 M-1、M-3 与 L-1 的便宜部分

日期：2026-10-23。依据：`docs/reviews/M1c2-security-review.md`。接 `M1c2-review-fixes.md`（H-1 到 H-4）与 `M1c2-review-fixes-2.md`（H-5、H-6）。**没有提交**，没有碰 `~/.boundkeep` 与 `~/.claude`。M-2 与 L-1 的长期方案按建议处理（第 4 节）。

## 1. 做了什么

| 项 | 修法 | 位置 |
|---|---|---|
| M-1 | `pytest.toml`、`.pytest.toml`（pytest 9.1.1 实测会读）与 `.pdbrc`（`pytest --pdb` / `--trace` 启动 pdb 时执行）加进工具配置的写保护；同一行"先写后运行"的检测也认这两个 pytest 配置名 | `policies/{default,strict}.yaml`、`normalize/event.py` |
| 已安装代码 | 新规则 `ask-installed-package-dirs-write`（strict：`deny-installed-package-dirs-write`）：写 `**/.venv/**`、`**/site-packages/**`、`**/node_modules/**` 要问。正常工作流不通过文件写入改它们（包由包管理器安装），而 `allow-project-file-writes` 原来放行这些写入 | 两份策略 |
| M-3 | （a）主目录里的 `.ssh`、`.gnupg`、`.aws`、`.kube`、`.docker`、`.config`、`.claude`、`.boundkeep`、`AppData` 及其下的一切不能作为 `trusted_projects` 条目（加载器报 "too broad"）；（b）`trust add` 在目录下面（三层、最多 5000 个条目、不进 `.git`/`node_modules`/`.venv`、不跟随链接）发现别的仓库时列出来，要用户输入 `yes`，否则一个字节都不写；目录本身没有 `.git` 只提示一行，不拦 | `policy/schema.py`、`trust.py` |
| L-1（便宜部分） | `python -X <值>` 只认一份无副作用的值（`dev`、`utf8`、`faulthandler`、`importtime`、`tracemalloc=N`、`frozen_modules=on|off`、`int_max_str_digits=N`、`no_debug_ranges`、`warn_default_encoding`、`perf`、`cpu_count=N`、`gil=0|1`），`-W` 的类别含 `.`（会被导入的模块）就不行：不满足就不再是开发工具调用（退回普通的 `python` 调用，灰色）；工具参数里的盘符相对路径（`--debug=C:x`、`-oD:x`、`C:file.py`）是灰色 `devtool-drive-relative` | `normalize/programs.py`、`normalize/psprograms.py` |
| M-2 | 文档：`trusted_projects` 在 M3a 的会话污染位存在之前保持默认关闭，不作为推荐设置（不写进面向用户的 README）；已安装代码的写入改 ask 是这条链上唯一便宜且不伤正常工作流的一环 | `docs/policy-reference.md`、`PROJECT_SPEC.md` §7 |

规则数：default 71 → **72**，strict 55 → **56**。

## 2. 测试与语料

- 新 `tests/unit/test_m1c2_review_fixes_3.py`：约 330 个用例。pytest.toml / .pdbrc 两个策略 × 两个平台 × Write / Edit；同一行写后运行的几种形式；八种已安装代码路径 × 两个策略 × 两个平台 × Write / Edit 的 ask / deny、读它们照旧 allow、项目自己的源码（含 `venv_helpers/`、`site_packages.py` 这类名字）照旧 allow；shell 写入已安装代码；规则形状（glob 清单、无 `tool:`）；16 个钥匙/设置/应用数据目录条目被拒绝、7 个普通项目目录照旧被接受、POSIX 版；`nested_repositories` 的找到、不报根自己与依赖目录、深度与条目上限、不存在的目录；`-X` / `-W` 的 27 种值；`python -X pycache_prefix=…` / `-W error::evil.Cls` 在两种方言下不再是开发工具调用、普通选项（`-X dev`、`-W error`、`-W ignore::DeprecationWarning`）照旧 allow；盘符相对路径 × 七个工具 × 两种方言，及其反例（绝对路径、节点 id、URL、`a:`）。
- `tests/unit/test_m1c2_trust_cli.py`：新增 `trust add` 的嵌套仓库用例（拒绝时策略文件字节不变、说 yes 才写、单个仓库与普通目录不提问、`_confirm` 只认 `yes`）。
- 语料：新文件 `tests/corpus/pipeline_x1_m_installed.yaml`（37 条：已安装代码与 pytest 配置的 Write / Edit / shell 写入，`adv: true`，期望 ask；加几条"不变"的邻居）；`pipeline_m1c2_trusted.yaml` 加 16 条 `m2r-l1-*`（L-1 与 M-1 的受信任项目版本）。
- 两份策略各加 5 条 `tests:`。

**改过的旧期望（7 条语料，都是变严）**：`pipeline_m1c2_trusted.yaml` 里 `m2t-n-flag-mypy-python-exec`、`m2t-n-flag-isort-virtual-env`、`m2t-n-written-tool`、`m2t-n-written-python`、`m2t-n-written-python-ruff`、`m2t-n-copied-tool`、`m2t-n-ps-written-tool`，期望从 `gray` 变成 `ask`：它们的命令把 `.venv/...` 当作写入目标，现在命中新规则。另外 `test_m1c2_trusted_policy.py` 的两份配置名清单加了三项。

## 3. 验证

- `ruff check .`、`ruff format --check .`（180 个文件）、`mypy`（48 个源文件，strict）：干净。
- `boundkeep test`：default 795 次运行、strict 300 次运行，0 失败；规则数 72 / 56。
- `scripts/measure_ask_rate.py`：Windows 54.2、POSIX 53.3，与之前一致（合成语料不写 `.venv`，不动）。
- 完整套件：见第 5 节。

## 4. 没做的与需要你知道的

- **M-2（会话污染位）没有做**：按建议推迟到 M3a，期间 `trusted_projects` 保持默认关闭；只加了便宜的那一环（已安装代码写入改 ask）。**这条链仍然开着**：先 `Write tests/test_x.py` 再 `pytest`，在受信任项目里没有任何一步弹框。
- **L-1 的长期方案（每个工具的选项白名单）没有做**：它需要新的匹配字段、改规格，规则变更较大。**它会改规则，所以如果要做，要么在 M2 基线之前做，要么做完重取基线**；我只做了审查点名的几个具体写法。选项值里的裸文件名（`pytest --debug=conftest.py`、`--debug=hard.yaml`）仍然不被当作路径，这是同一个缺口的另一面。
- **代价**：`.venv` / `node_modules` / `site-packages` 里的写入现在会问；`uv` 的硬链接装进 `.venv` 的包读写也会多问一次（H-6）。`python -W` 的值里带点的类别不再被当作开发工具调用，`-X` 只认列出的值，会多问：如果你的工作流里有 `python -X importtime -m pytest` 之类的写法，已在清单里。
- **盘符相对路径检测有误报**：`pytest -k "a:b"` 这样的单字母加冒号参数会被当作盘符相对路径而变灰色；节点 id（`t::x`）、绝对路径、URL 不受影响。
- **推送**：上一轮要求推送，但被权限拒绝（见本轮回复），**没有推送任何东西**。

## 5. 完整套件

**最终的完整运行（`uv run pytest -q`，Windows 主机，约 49 分钟）：23492 通过、137 跳过、0 失败。** Linux 容器没有跑。

过程：第一次完整运行 23479 通过、13 失败，都是新规则让旧期望变严或让一个测试的前提失效，没有一个是新行为出错：

- 12 个语料条目（`pipeline_m1c2_devtools.yaml` 的 `m1c2-dt-written-tool`、`-written-python`、`-written-python-ruff`、`-copied-tool`；`pipeline_m1c2_ps.yaml` 的 `m1c2-ps-dev-venv`、`-exec-written-exe`、`-exec-written-exe-after-cd`、`-exec-written-python-exe`，两个平台共 12 个用例）：命令把 `.venv/...` 当作写入目标（含 `python -m venv .venv`），期望从 `gray` 改成 `ask`（变严，仍不是 allow）。
- `test_session_command_stats.py::test_trust_pretends_a_project_is_trusted_without_writing_anything`：它把 pytest 的 `tmp_path`（Windows 上在 `AppData\Local\Temp` 里）当作受信任项目，现在 `AppData` 下的条目被加载器拒绝；改成用一个假的用户主目录（`USERPROFILE` / `HOME`），项目放在它下面。**这也是一个真实的行为后果**：位于 `AppData` 下的项目不能再被信任（正常项目不在那里）。
- 以上加上前面 `test_m1c2_trusted_policy.py` 里配置名清单的三项，是这一轮改过的全部旧期望。
