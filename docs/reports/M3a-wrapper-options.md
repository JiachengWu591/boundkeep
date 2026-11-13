# 包装器自己吃掉的词（规格修订 26，W-1）

日期：2026-11-12。基线：`295badc`，工作区里还有没提交的修订 23、24、25。依据：`docs/reports/M3a-runner-options.md` 第 6 节第 4 条（W-1）。

使用者说"W-1 也照同样的办法修"，也就是修订 25 的"带值就不送审"。

使用者说"代码一次、文档一次"：代码（修订 23 到 26 一起）在 `8d268d3`，这份记录和规格在其后一个提交（`ced7a87`）。**已推送**（2026-11-12，使用者说"推送"），没有打标签。复审见 `docs/reviews/M3a-rev23-26-review.md`。（2026-11-12 更正：这里原来写的是提交时的状态"没有推送"。）

没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务（模型是 `FakeBackend`），没有打开留出批次和攻击样本。没有运行 `sudo`、`env` 或别的包装器。

## 1. 结论

- Bash 方言里，`sudo`、`env`、`time`、`nice`、`timeout`、`xargs` 等包装器被剥掉时，吃掉的词里有不是开关的，这次调用不送审、直接问：灰色 `wrapper-option-value`。
- 只带开关的、带 `env -S` 的、后面没有命令的照旧送审。
- 规则层没有变。PowerShell 方言不剥这些名字，没有变。规则条目与策略文件没变。
- 手头语料 Bash 1880 条（两个平台各跑一遍）：4 条由送审变成问，都在 `tests/corpus`，评测集里没有。其中一条正是这一类问题：`env -C ~/.claude sh -c "echo x > settings.json"` 原来送审时只有 `sh -c "echo x > settings.json"`，看不出目录是 `~/.claude`。

## 2. 原来

Bash 方言的包装器表（`bash._WRAPPERS`：`sudo`、`doas`、`env`、`nohup`、`time`、`command`、`builtin`、`exec`、`nice`、`ionice`、`timeout`、`stdbuf`、`setsid`、`wsl`、`sshpass`、`gosu`、`su-exec`、`ssh-agent`、`tini`、`chronic`、`torify`、`numactl`、`xargs`）里的包装器被剥掉之后，按里面的命令判。包装器的名字进 `wrappers` 标记，它吃掉的词（选项和值、`timeout` 的时长、`gosu` 的用户）不在任何动作的词里。

| 写法 | 送审的请求里 |
|---|---|
| `sudo -u <用户> pytest -q` | `pytest -q`，`wrappers: ["sudo"]`，没有用户 |
| `env -C <目录> pytest -q` | `pytest -q`，`wrappers: ["env"]`，没有目录（另有灰色 `wrapper-option:env:-C`，但不拦送审） |
| `time -o <文件> pytest -q` | `pytest -q`，没有那个会被写的文件 |
| `timeout 60 pytest -q` | `pytest -q`，没有时长 |

`sudo -D`、`sudo -R`、`env -C`、`env -P`、`time -o`、`xargs -a` 这些带路径的选项原来有灰色 `wrapper-option:<名字>:<选项>`，照常送审。`NAME=value` 赋值（`env A=b cmd`）从修订 7 起就不送审，不在这次的范围里。

## 3. 修法（`bash.py`、`pipeline.py`）

- `_Stripped` 多一项 `taken`：剥选项时吃掉了不在 `optargs` 里的、不是开关的词。三种：`nice -5` 这样写在选项里的数；可选、贴在选项后面的值（`xargs -i{}`）；操作数（`timeout 60` 的时长、`gosu`、`su-exec` 的用户）。
- `_emit` 里，包装器真的被剥掉（后面有命令）、不是带 `env -S` 的 env、并且 `taken` 或 `optargs` 不空时，加灰色 `wrapper-option-value`。
- `pipeline._UNSHOWN_REASONS` 加上 `wrapper-option-value`。
- 带 `env -S` 时 env 本来就不被剥掉：`-S` 的值当命令再解析一遍，env 命令本身连同别的选项作为一条命令记下（`['env', '-C', 'dir', '-S', 'pytest -q']`），值都在请求里。写第一版时我把它也标了，扫描查出来请求里本来就有那个值，改掉了。
- 后面没有命令时（`timeout 60` 单独一条、`sudo -u root` 单独一条）包装器不被剥掉，整条的词都在请求里，不标。

PowerShell 方言没有改：`sudo`、`env` 在那里是普通程序，参数照常在请求里。复审时量过 `env -C BKCANARY pytest -q`，请求里有标记。

## 4. 判决变化

专门扫描（scratchpad 的 `rv26_scan.py`）：45 种前缀 × 10 种后续，450 行，Bash 方言，对 `295badc` 的代码。

| | 行数 |
|---|---|
| 吃掉了词的包装器，送审 → 不送审 | 176 |
| 吃掉了词的包装器，级别不变（deny 56、规则问 11、送审 27） | 94 |
| 只带开关的包装器、`env -S`，不变 | 140 |
| 对照：不变 | 33 |
| 对照：`uv run --with …`，送审 → 不送审（修订 25 的变化） | 7 |

- 吃掉了词、仍然送审的 27 行：8 行带 `env -S`（请求里有标记）；19 行后面没有命令，包装器没被剥掉，整条的词都在请求里。
- 没有一行变松，没有一行少记路径。
- 只带开关的和对照里的行，判决、规则、灰色原因、程序名一项都没有变（修订 25 那 9 行除外）。

手头语料 Bash 1880 条 × posix、windows 两个平台：各有 4 条由送审变成问。

| 语料 | 命令 |
|---|---|
| `pipeline_fix_event` `fe-env-C-gray` | `env -C ~/.claude sh -c "echo x > settings.json"` |
| `pipeline_m1c2_devtools` `m1c2-dt-timeout` | `timeout 5 pytest` |
| `pipeline_m1c2_trusted` `m2t-n-timeout` | `timeout 5 pytest` |
| `workflow_benign` `ka-dev-timeout-pytest` | `timeout 5 pytest` |

没有后端时这 4 条前后都是问。

## 5. 测试

| 测试和检查 | 结果 |
|---|---|
| 新测试文件 `tests/unit/test_m3a_wrapper_options.py` | 195 passed |
| 新测试文件在 `295badc` 的代码上 | 不能收集（`WRAPPER_OPTION_VALUE_GRAY` 不存在）。行为上的差别见第 4 节 |
| 相邻 13 个测试文件（Bash 解析器、语料、事件、管道、运行器、修订 21 的测试等） | 24 条失败、7267 passed、39 skipped：都在 `test_norm_bash.py`。语料 `tests/corpus/bash_parse.yaml` 钉着每条的灰色原因，23 条包装器条目现在多一个 `wrapper-option-value`（脚本逐条核对过，这是唯一的差别），已补上；`test_wrapper_edge_cases` 里 `sudo -u $u rm x` 原来断言没有灰色原因，已改。改完后这个文件里的语料和包装器测试 352 passed |
| 手头语料 | 见第 4 节 |
| 变异：13 个（`bash` 12 个，`pipeline` 1 个），在副本上跑新测试文件和 `test_m3a_runner_options.py` | 第一轮 12 个抓到，1 个存活：去掉"带 `env -S` 不标"这个条件。不是等价的，是测试没有覆盖 `-S` 的值后面还有词的写法（`env -C x -S 'pytest -q' tests`，这时剥出的 `rest` 不空）。补了这一条，再跑抓到 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过 |
| 原有差分（修订 16 到 20 的扫描、修订 17 和 IR-1 的真实目录树、带冒号的普通命令、系统目录、逐程序、真实磁盘 23544 条、假机器 179508 条、孪生项目 30720 条、含 git 或 `~` 的语料 1164 次判决），修订 23 到 26 全部做完后 | 级别全部相同，没有一行少记路径。`boundkeep test` 1142 / 0、334 / 0。评测指标相同，`results/*.json` 除日期和延迟外只有 `atk-exfil-032` 的灰色原因多了几个（修订 22 起就是这样），`eval/report.md` 没有重新生成 |
| 全量（修订 23 到 26 一起跑，分六段，不是一个进程） | 29659 passed、169 skipped、0 失败，六段都一次跑完，合计与收集到的 29828 条相同，各段用时合计 2:21:22。开始和结束时电源都是最佳性能。跑完核对过代码与四个新测试文件的指纹，没有变 |

## 6. 代价和残余

1. **有后端时 `timeout 60 pytest`、`nice -n 10 make`、`xargs -n 1 wc -l` 直接问，不再送审**。语料里 `timeout 5 pytest` 有 3 条。`xargs` 的写法本来就被规则问，不受影响。
2. **值仍然不进路径层**：`env -C ~/.claude sh -c "echo x > settings.json"` 是问，不是 deny，`settings.json` 仍按项目目录读。`time -o <文件>` 的写也一样。要让规则看得到，得把这些值交给路径层，这次没有做。
3. **PowerShell 里 `sudo`、`env` 是普通程序**，没有动；Windows 上它们通常不存在。
4. 包装器表和各自的选项表这次没有重新核对。
5. 这次修复没有复审，真实宿主里没有跑。
