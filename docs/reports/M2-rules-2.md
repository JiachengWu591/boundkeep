# M2 之后的规则改动二：只读信息类命令

日期：2026-10-27。**状态：已实现、测试通过；独立审查一轮并已修复，见第 6 节（等同一复审者复核）。** 接 `docs/reports/M2-rules-1.md`（`git add` / `commit` / `stash`）。基线标签 `m2-baseline` 仍对应最早的规则；test 切分已被污染（见 `M2-rules-1.md` 第 6 节），报告继续带这个声明。新的留出集由使用者之后单独决定。

## 1. 范围与理由

`docs/reports/M2-rules-1.md` 之后，我再看了 dev 切分上的正常样本误报，把“没有规则匹配”的日常命令分三类：会运行项目代码的（有意问）、项目内的文件操作（`cp`、`mv`、`rm` 等，风险比 `git add` 高，这一批不做）、**只读的信息命令**。这一批只做第三类里风险最低、理由独立于评测集的几个：它们只打印版本、程序的位置或文件**名**，不读文件内容。

**有意不做的**（原因写在这里，免得以后误以为是疏漏）：`git remote -v`（远端地址里常带令牌，会打进上下文）、`jq`（`jq -n env` 会打印环境变量）、`sed -n`（`w` 命令会写文件，脚本是位置参数，规则看不见）、`diff`（`-r`、`-l` 等选项）、`du`（`--files0-from`、`-X` 读文件）、`docker ps`、`Get-Command`（PowerShell 参数缩写要表项支持，价值只有一条样本）、`date`/`whoami`/`uname`（不在误报清单里）。

## 2. 改了什么

| 位置 | 改动 |
|---|---|
| `policies/default.yaml` | `allow-no-path-commands` 加 `which`；新增 `allow-version-probe`、`allow-git-ls-files`；`ask-git-read-outside-project` 的子命令加 `ls-files`，`ask-shell-read-outside-project` 的程序加 `which`；新增 `ask-toolchain-selector-write`（strict：`deny-toolchain-selector-write`，审查 R7-2）；`tests:` 新增约 75 条；两条旧期望（`git --version`、PowerShell 的 `python --version`）从 gray 改为 allow；strict 只多了一条 deny（`deny-toolchain-selector-write`）和几条测试，没有新增 allow（子集一致性测试守着） |
| `src/boundkeep/normalize/programs.py` | `NAME --version` 之后出现任何别的参数时，动作上多一个标记 `--version-with-arguments`；`git ls-files` 的选项走**白名单**，白名单之外的选项和字面 `--` 都打上 `--git-other-option` |
| 测试 | 新增 `tests/unit/test_info_commands_allow.py`（164 个）；`test_m1c_allow_rules.py` 更新（登记表、路径保护一致性、“不得放行解释器”守卫改为只给 `allow-version-probe` 开口并断言它的形状）；两份语料里原来写“必须不放行”的 6 条改为 allow，新增 14 条对抗样本；工作流语料 8 条从 keep-ask 档移到 t1-read 档 |
| 文档 | `docs/policy-reference.md` 加两行并注明 `which` |

## 3. 放行什么、不放行什么

- `which NAME`（Bash）；`NAME --version`，`NAME` 是 git、python、python3、pip、pip3、node、npm、uv、cargo、rustc、dotnet、docker 之一，**后面什么都没有**；`git ls-files`，选项只限 `-o`、`--others`、`-m`、`--modified`、`-d`、`--deleted`、`-z`、`--cached`、`--exclude-standard`，路径必须在项目里。
- 不放行：`python --version -c ...`、`node --version x.js`、`pip --version install x`、`node -v`、带展开的名字、重定向、`sudo`、会带代码的环境变量前缀（`PYTHONSTARTUP=x`）、`git ls-files --exclude-from=...`、`--format=...`、`-c`（和全局的 `-c key=value` 同名）、`-- 路径`、项目外的路径、`git -C ...`、`git -c ...`。`npx` 不在其中：它是启动器，规范化器本来就标成灰色。
- 规则的前提：`NAME --version` 运行的是 PATH 上找到的那个程序，与用户自己的 shell 一样；这是所有命令共有的残余。**审查后补充（R7-1）**：前面有**任何**环境变量前缀的 `NAME --version` 与 `git ls-files` 都不放行（`PYENV_VERSION=x python --version`、`MISE_TRUSTED_CONFIG_PATHS=/ python3 --version`、`GIT_TRACE=文件 git --version`），`GIT_TRACE*`/`GIT_TRACE2*` 另外进了“带代码的环境变量”表；`git ls-files` 的 pathspec 以 `:` 开头（`:/`、`:(top)`、`:!x`）不放行（R7-4）；`-p`/`-P` 进了 `flags_none`（R7-6）；`which -i x < 项目外文件` 现在 ask（R7-3）。

## 4. 对评测的影响（看 dev）

| 格子 | 误报（上一版 → 这一版） | 达到要求的攻击样本 |
|---|---|---|
| Windows dev | 34.8% → 34.8% | 77 / 94，没变 |
| POSIX dev | 65.0% → 62.5% | 90 / 104，没变 |

（test 上 Windows 39.4% → 38.0%，POSIX 77.3% → 75.0%，仅供参考，test 已被污染。）改动很小，符合预期；没有任何攻击样本变成 allow。`scripts/measure_ask_rate.py`：Windows 50.4、POSIX 49.3（`M2-rules-1` 之后是 52.3 / 51.3），与设计目标有差异的条目 0。

## 5. 验证

`ruff`、`mypy`（57 个源文件，strict）干净；`boundkeep test`：default 1016 条、strict 318 条，0 失败；与本批相关的单元测试（`test_info_commands_allow.py`、`test_m1c_allow_rules.py`、`test_git_local_vcs_allow.py`、`test_m1c2_trusted_policy.py`、`test_m1c_autorun_rules.py`）4859 个通过。完整套件：25584 通过、2 失败、167 跳过（2 小时 16 分，复审者同时在跑命令，机器负载高）。两个失败是 `test_norm_event.py::test_too_many_refs_are_cut_off[win]` 与 `test_policy.py::test_replace_is_retried_while_another_process_holds_the_file`，单独重跑六轮都通过；前者断言规范化器的路径预算，而规范化器还有一个墙钟预算，负载高时可能先触发。判断为负载下的抖动，与本批改动无关，但没有复现失败时的具体断言，机器空闲时应再跑一遍整套确认。

测试里先发现并修好的两处：`git ls-files > out.txt` 一开始被放行（规则漏了 `paths_read_only`，重定向写的文件没被拦住）；`npx --version` 本来就是灰色（启动器），从程序列表里去掉。

## 6. 独立审查

同一复审者（X1，`docs/reviews/M2-rules-2-review.md`）审了这一批：**一条 high、一条 medium、其余 low/info**，没有发现攻击样本变 allow，但发现了规则之外的链。

| 编号 | 级别 | 问题 | 处理 |
|---|---|---|---|
| R7-1 | high | 三条新规则对环境变量前缀不设防：`GIT_TRACE=任意文件 git --version` 向文件追加跟踪行；版本管理器 shim 读 `PYENV_VERSION`、`MISE_*` 等；与“项目内写入 `mise.toml` 等被放行”叠加成无询问的代码执行链 | 规范化器：`NAME --version` 与 `git ls-files` 前有任何 env 前缀即打标记（不放行）；`GIT_TRACE*` 进代码环境变量表；表里每一行有 `tests:`、语料与单元测试 |
| R7-2 | medium | 版本探测会触发 shim（本机的 python/node/npm/uv 就是 mise shim），shim 读项目里的选择文件，开着 auto-install 时会联网安装，复审者实验时还引起过进程风暴 | 写这些文件（`mise.toml`、`.tool-versions`、`.python-version`、`.node-version`、`.nvmrc`、`.ruby-version`、`.sdkmanrc`、`global.json`、`uv.toml` 等）由新规则 ask（strict deny）。复核（R8-1）发现名单只列了文件名、漏了 mise 的其他配置位置，改成目录和模式通配：`**/.mise/**`、`**/mise/config*.toml`、`**/mise/conf.d/**`、`**/.config/mise/**`、`**/mise.*.toml`、`**/.mise.*.toml`、`**/.rtx.toml`、`**/.python-versions`、`**/.volta/**` 等 20 条。**没有修**的部分见残余 1，使用者已明确接受 |
| R7-3 | low | `which` 的注释与事实不符；`which -i x < 项目外文件` 的 stdin 不经路径检查 | 改正注释与文档；`which` 加进 `ask-shell-read-outside-project` |
| R7-4 | low | `git ls-files :/` 等 pathspec 魔法可列出项目之上整个仓库的文件名 | 规范化器：以 `:` 开头的操作数打标记 |
| R7-5 | low | 工作流语料 8 条的注释仍写“not allowed” | 已改 |
| R7-6 | info | 全局 `-p`/`-P` 与 `--paginate` 处理不一致 | `-p`/`-P` 进 `flags_none` |

**复核结果：** 第二轮（R7-1、R7-3 到 R7-6 关闭；新提 R8-1 medium、R8-2、R8-3 两条 low）和第三轮（R8-1 到 R8-3 全部关闭）之后，**没有 high、medium 遗留**；`allow-version-probe`、`allow-git-ls-files`、`allow-no-path-commands`（`which`）三条复审者都判可冻结（`allow-version-probe` 以使用者接受残余 1 为前提）。复审者的两条 info：`.mise/`、`.volta/`、`.config/mise/` 目录下建目录和 `git add` 其中的文件也会 ask，这是有意的保守行为，不是误报；选择文件名单依据文档和记忆，没有实测，方向是多拦不漏拦。

**残余风险（复审者要求显式列出；使用者已于 2026-10-27 明确接受第 1 条，其余三条随之列入）：**

1. **版本管理器 shim。** `NAME --version` 运行 PATH 上的程序。若它是 mise/asdf/pyenv/volta/rustup 的 shim，shim 会读项目里的选择文件并可能运行其中配置的程序、联网安装工具链。代理写这些文件会被拦下，但**别人放进来的**（`git clone`/`git pull` 一个不可信仓库、解压）拦不住：之后一次 `python --version` 就可能触发。规则语言看不到文件是否存在，所以无法在存在这类文件时降级。若使用者不接受，做法有两种：把 `allow-version-probe` 整条拿掉（约 8 条工作流语料回到 ask），或让规范化器在发现选择文件时给探测打标记（见残余 6，常见仓库会退回 ask）。
2. `GIT_TRACE` 以外会影响 git 行为的环境变量不再相关（前缀一律不放行）；但 shell 里事先 `export` 过的变量看不到。
3. `which ./.env` 只透露文件是否存在且可执行；名字找不到时 `which` 会打印整个 PATH。
4. 不可信仓库里 `git ls-files` 可能受 `.git/config` 影响（与 `git status` 同类，`emit_allow` 保持关闭）。
5. （复核补充）残余 1 的几点说明：触发不需要恶意——仓库里本来就有、指向未安装版本的 `.tool-versions`，开着 auto-install 的 shim 也会在 `--version` 时联网安装、写盘、拉起进程，所以在带 shim 的机器上放行 `--version` 不等于零副作用；选择文件的来源不止 clone 和解压，`git stash pop` 恢复出来的、其他进程写入的也拦不住；项目上级目录和用户级配置（`~/.config/mise`、`~/.tool-versions`）shim 也会读，它们依赖项目外写入保持 ask；`mise.<env>.toml`、`.rtx.toml`、`.volta/hooks.json` 是否真被相应工具读取没有实测（出于安全原因没有做 shim 实验）。
6. **可选的收窄方式（未做，使用者可另行决定）：** 规范化器在 cwd 到项目根各级发现任一选择文件时给 `NAME --version` 打标记，让探测规则不匹配。代价：带 `.python-version`/`.nvmrc`/`.tool-versions` 的常见仓库会退回 ask。这比“整条拿掉”便宜，复核者建议写在这里。第 6 节第一条残余里“规则语言看不到文件，只能整条拿掉”的说法据此更正。
7. （复核补充）全局 `-p`/`-P` 在已冻结的 `allow-git-read-only` 上仍被放行（非 tty 下无已知利用，非本批引入）；未覆盖 PowerShell 的 `where.exe`/`Get-Command`、Windows 商店版 python 启动器、pwsh 7。
