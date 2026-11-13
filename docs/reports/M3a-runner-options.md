# 运行器自己的选项（规格修订 25，复审 O-2）

日期：2026-11-12。基线：`295badc`，工作区里还有没提交的修订 23、24。依据：`docs/reviews/M3a-rev21-22-review.md` 的 O-2。

使用者在三种做法里选了"带值选项就不送审"。

使用者说"代码一次、文档一次"：代码（修订 23 到 26 一起）在 `8d268d3`，这份记录和规格在其后一个提交（`ced7a87`）。**已推送**（2026-11-12，使用者说"推送"），没有打标签。复审见 `docs/reviews/M3a-rev23-26-review.md`。（2026-11-12 更正：这里原来写的是提交时的状态"没有推送"。）

没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务（模型是 `FakeBackend`），没有打开留出批次和攻击样本。没有运行 `uv`、`pipx`、`poetry`。

## 1. 结论

- `uv run`、`uv tool run`、`uvx`、`pipx run`、`poetry run` 带了有值的选项时，这次调用不送审、直接问。两种 shell 都这样。
- 只带开关的（`uv run --frozen pytest`）和不带选项的照旧送审。
- 规则层没有变。这些调用没有后端时本来就是问，现在也是；规则条目与策略文件没变。
- 手头语料：PowerShell 1146 条、Bash 1880 条（两个平台各跑一遍），级别变了的 0 条。

## 2. 原来

运行器被剥掉之后，按里面的命令判，运行器的选项和值整个丢掉。请求里只有里面的命令和一个 `wrappers` 标记：

| 写法 | 送审的请求里 |
|---|---|
| `uv run --env-file .env pytest -q` | `pytest -q`，`wrappers: ["uv-run"]`，没有 `.env` |
| `uv run --index-url https://… pytest -q` | 同上，没有网址，`network: false` |
| `uv run --with <包或网址> pytest -q` | `pytest -q`，`wrappers: ["uv-run-remote"]`，没有包名 |
| `uvx --from <包> cowsay hi`、`pipx run --spec <包> cowsay hi` | `cowsay hi`，没有包名 |

修订 21 给 PowerShell 加了 `ps-runner-value`，只管值里带变量或表达式的。Bash 里 `uv run --with $PKG pytest` 照常送审。

## 3. 修法

- `programs.peel_runner_options`：和 `peel_runner` 一样认运行器，多返回一项 `valued`，表示被剥掉的词里有没有带值的选项。带值的选项是各运行器表里的 `values`（`uv` 和 `uvx` 的 `--with`、`--env-file`、`--index-url`、`--python`、`--directory` 等 49 个，`pipx` 的 `--spec`、`--python`、`--pip-args`、`--index-url`，`poetry` 的 `-C`、`--directory`、`-P`、`--project`），`--opt 值` 和 `--opt=值` 两种写法都算。`peel_runner` 保留，返回值不变。
- Bash 方言（`bash.py`）：`valued` 时加灰色 `runner-option-value`。
- PowerShell 方言（`pscmd.py`）：`valued` 时加灰色 `ps-runner-value`。这个原因修订 21 就有，原来只在值里有变量时加。
- `pipeline._UNSHOWN_REASONS` 加上 `runner-option-value`。带这两个原因之一的调用不送审。
- `python -m boundkeep` 这种"解释器只是启动器"的写法：解释器自己的 `-W`、`-X`、`-Q` 带值，也算 `valued`，为的是这一项只有一个意思。判决不受它影响：里面是 boundkeep 自己的命令行，由规则给出问或 deny，本来就不送审。

没有改的：选项的值仍然不进路径层和域名层。

## 4. 判决变化

专门扫描（scratchpad 的 `rv25_scan.py`）：31 种前缀 × 10 种里面的命令 × 两种 shell，620 行，对 `295badc` 的代码。

| | Bash | PowerShell |
|---|---|---|
| 带值选项，送审 → 不送审 | 153 | 144 |
| 带值选项，原来就不送审（值带变量，`ps-runner-value`） | 0 | 9 |
| 带值选项，deny（里面是 `boundkeep mode audit-only`） | 17 | 17 |
| 只带开关或不带选项的运行器，不变 | 100 | 100 |
| 对照（没有运行器、表里没有的选项、`sudo -u`、`env -C`），不变 | 40 | 40 |

- 带值选项的行修改前有 297 行送审，修改后 0 行。
- Bash 里值带变量的 9 行（`uv run --with $X …`）原来送审，现在不送审。
- 其余的行，判决、规则、灰色原因、程序名一项都没有变。没有一行变松，没有一行少记路径。

## 5. 测试

| 测试和检查 | 结果 |
|---|---|
| 新测试文件 `tests/unit/test_m3a_runner_options.py` | 108 passed |
| 新测试文件在 `295badc` 的代码上 | 不能收集（`peel_runner_options` 不存在）。行为上的差别见第 4 节：带值选项的 297 行原来送审 |
| 修订 21 的测试（`test_m3a_ps_outside_command.py`） | 3 条钉着旧行为（"运行器的选项是常量时照常送审"），已改成"不带有值选项的运行器照常送审"和"常量的值也标" |
| 涉及运行器的 11 个测试文件 | 改那 3 条之前：3 failed，3207 passed，38 skipped；改完后这个文件和新文件 303 passed |
| 手头语料 | PowerShell 1146 条、Bash 1880 条 × posix 和 windows 两个平台：级别变了的 0 条 |
| 变异：12 个（`programs` 5 个，`bash` 3 个，`pscmd` 3 个，`pipeline` 1 个），在副本上跑新测试文件、`test_review2_programs_classify.py`、`test_m3a_ps_outside_command.py` | 11 个抓到，1 个存活，是等价的：PowerShell 一侧原来还查"被剥掉的词里有没有会展开的"，现在每个可能展开的被剥掉的词都是带值选项的值，已经算在 `valued` 里。这段多余的检查已删掉，改后的那一行另跑 2 个变异（永远不标、永远标），都抓到 |
| 冒烟脚本的 `readings` 加了一条 `uv run --env-file …` 的探针，`--only readings --dry`（不调用 Claude） | 24 项 0 失败。真实宿主里这一条没有跑 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过 |
| 原有差分（修订 16 到 20 的扫描、修订 17 和 IR-1 的真实目录树、带冒号的普通命令、系统目录、逐程序、真实磁盘 23544 条、假机器 179508 条、孪生项目 30720 条、含 git 或 `~` 的语料 1164 次判决），修订 23 到 26 全部做完后 | 级别全部相同，没有一行少记路径。`boundkeep test` 1142 / 0、334 / 0。评测指标相同，`results/*.json` 除日期和延迟外只有 `atk-exfil-032` 的灰色原因多了几个（修订 22 起就是这样），`eval/report.md` 没有重新生成 |
| 全量（修订 23 到 26 一起跑，分六段，不是一个进程） | 29659 passed、169 skipped、0 失败，六段都一次跑完，合计与收集到的 29828 条相同，各段用时合计 2:21:22。开始和结束时电源都是最佳性能。跑完核对过代码与四个新测试文件的指纹，没有变 |

## 6. 代价和残余

1. **有后端时，带值选项的运行器直接问，不再送审**：`uv run --with rich pytest`、`uv run --python 3.12 pytest`、`uv run --directory sub pytest`。没有后端时不变。
2. **`uv run --env-file .env pytest` 是问，不是 deny**。选项的值不进路径层，`no-secret-read` 看不到它。`--index-url` 的主机也不进网络规则。要改就是当时的第二种做法，这次没有做。
3. **表里没有的选项**（`uv run --weird x pytest`）不变：带 `wrapper-options:uv` / `ps-runner-options`，判决是问，不送审。
4. **`sudo`、`env` 这些包装器自己的选项同样不在请求里（W-1，新查到，没有修）**。扫描的对照行里，Bash 的 `sudo -u BKCANARY pytest -q` 和 `env -C BKCANARY pytest -q` 都送审，请求里没有标记：看不出换成了哪个用户、换到了哪个目录。`env -C` 有灰色 `wrapper-option:env:-C`，但这个原因不拦送审。PowerShell 里 `sudo …` 是问，`env -C BKCANARY …` 送审时请求里有标记（那里 `env` 不当包装器剥）。和 O-2 是同一类，早就有，只在有后端时起作用。（后记：使用者说"W-1 也照同样的办法修"，规格修订 26，记录 `docs/reports/M3a-wrapper-options.md`。）
5. 没有运行真的 `uv`，选项表这次没有重新核对。
6. 这次修复没有复审。真实宿主里没有跑（冒烟是在这次改动之前跑的）。
