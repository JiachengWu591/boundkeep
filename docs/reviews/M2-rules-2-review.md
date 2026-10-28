# M2-rules-2 定向 X1 复审：只读信息命令规则

- 审查对象：工作树（未提交），基线 HEAD 70bbd98。规则 `allow-no-path-commands`（`[pwd, which]`）、`allow-version-probe`、`allow-git-ls-files`、`ask-git-read-outside-project`（新增 `ls-files`）；`normalize/programs.py` 中 `VERSION_PROBE_PROGRAMS` / `VERSION_EXTRA_FLAG` / `_GIT_LS_FILES_FLAGS` / `GIT_OTHER_OPTION_FLAG` 及 `_h_git` / `_classify` 两处打标。
- 方法：作者的报告（`docs/reports/M2-rules-2.md`）全部当作"作者声称"逐条核对；只做 normalize/裁决，不执行被审命令；真实 git 只在临时仓库里跑；仓库只读，唯一产出为本文件（未跟踪）。
- 结论先行：**仍有 1 个 high、1 个 medium**，均出在 `allow-version-probe`（env 前缀没有任何门控；版本管理器 shim 会读代理可写的项目文件）。`allow-git-ls-files` 与 `which` 只有 low 级问题。`allow-version-probe` 目前**不能冻结**。

## 一、发现

### R7-1（high）`allow-version-probe` / `allow-git-ls-files` / `allow-no-path-commands` 对 env 前缀完全不设防，与"默认策略对 Write 放行版本管理器配置文件"叠加成无询问代码执行链

事实（均用 `h.py` / `t.py` 做过裁决，default 策略，Bash/posix；PowerShell 里 `$env:X=..; cmd` 是复合语句，本来就 gray，不受影响）：

| 命令 | 裁决 |
|---|---|
| `MISE_TRUSTED_CONFIG_PATHS=/ python --version` | **allow**（allow-version-probe） |
| `MISE_AUTO_INSTALL=1 python --version`、`MISE_DATA_DIR=x python --version` | allow |
| `PYENV_VERSION=x python --version`、`VOLTA_HOME=x node --version` | allow |
| `RUSTUP_TOOLCHAIN=x / RUSTUP_HOME=x / CARGO_HOME=x cargo --version` | allow |
| `NPM_CONFIG_PREFIX=x / npm_config_userconfig=x / NPM_CONFIG_SCRIPT_SHELL=x npm --version` | allow |
| `PIP_CONFIG_FILE=x pip --version`、`PIP_INDEX_URL=http://x pip --version`、`UV_CONFIG_FILE=x uv --version` | allow |
| `DOCKER_HOST=tcp://x / DOCKER_CONFIG=x / DOCKER_CONTEXT=x docker --version`、`DOTNET_ROOT=x / DOTNET_CLI_HOME=x dotnet --version` | allow |
| `GIT_TRACE=/home/testuser/.bashrc git --version`；`GIT_TRACE=... git ls-files`；`GIT_TRACE2_EVENT=... git ls-files` | allow |
| 对照：`MISE_TRUSTED_CONFIG_PATHS=/ pytest`、`PYENV_VERSION=x pytest` | gray（`devtool-env-prefix:...`） |

也就是说同一批 env 名，开发工具规则已经用 `devtool_env_is_safe` 判为危险（gray），而版本探测规则没有接这套门控。`_ENV_CODE` 只拦 `PATH`/`BASH_ENV`/`LD_PRELOAD`/`GIT_DIR`/`GIT_PAGER` 等已知名字。

后果：

1. `GIT_TRACE=<任意文件> git --version`（或 `git ls-files`）会向任意路径追加 trace 行：我在临时目录里用真实 git 确认了 `git --version` 在 `GIT_TRACE=<file>` 下会创建/追加该文件。这是"只读规则做了写入、且写到项目外"。注：`GIT_TRACE=... git status/log/add` 在 HEAD（已冻结的 git 规则）上同样 allow，这是已存在的缺口，ls-files 与版本探测只是继承；但新规则把它扩到了 `git --version` 这个本来不涉及仓库的调用。
2. 链：默认策略对 `mise.toml`、`.mise.toml`、`mise.local.toml`、`.python-version`、`.tool-versions`、`.nvmrc`、`.node-version`、`global.json`、`uv.toml`、`pip.conf`、`Cargo.toml`、`.sdkmanrc` 等的 Write **裁决为 allow**（strict 为 gray）；`rust-toolchain(.toml)`、`.npmrc`、`pyproject.toml`、`package.json`、`.envrc`、`.cargo/config.toml` 是 ask。代理可以先无询问写 `mise.toml`（mise 配置里有 `[env]` 的 `_.source`、模板 `exec()` 等会执行命令的入口），再用 `MISE_TRUSTED_CONFIG_PATHS=/ python --version` 一次性自我信任并触发 shim。此前 `python --version` 是 gray，这条链是新规则新开出来的。
   - 诚实说明：这条链的最后一跳（mise 实际执行 `_.source`/`exec()`）我**没有**完整复现，依据是（a）两个前半段已用裁决验证，（b）本机 python/node/npm/uv 确实是 mise shim，shim 会去读项目配置（见 R7-2 的意外观察）。我因安全原因不再做进一步的 shim 实验。因此严重度按"本机有 mise/asdf/pyenv/volta/rustup shim 的用户"给 high；没有任何版本管理器的机器上这条链不成立。
3. `GIT_DISCOVERY_ACROSS_FILESYSTEM=1`、`GIT_CEILING_DIRECTORIES=x` 同样被接受，影响仓库发现范围，和下面 R7-4 叠加。

建议：版本探测、ls-files、`pwd/which` 三条规则都应在命中前要求"无 env 前缀"，或复用 `devtool_env_is_safe`；同时把 `git_trace*`、`git_trace2*` 加入 `_ENV_CODE`（顺带修掉已冻结 git 规则里的同一问题）。验收用例：上表每一行都应变 gray。

### R7-2（medium）版本探测会触发版本管理器 shim，shim 读取代理可写文件，并可能联网安装/拉起大量子进程

- 规则注释把 `NAME --version` 当作"只打印版本"，作者报告也只声明"`NAME --version` runs whatever PATH resolves"。但 shim 型启动器（mise、asdf、pyenv、volta、rustup、nvm 包装）在打印版本之前会先解析项目目录里的 `.python-version` / `.tool-versions` / `mise.toml` / `.nvmrc` / `rust-toolchain`，在开启 auto-install 时还会下载并安装对应工具链。这些文件里有一批 Write 是 allow（见 R7-1 表）。
- 实际观察（需如实报告）：本机 `python`/`uv`/`node`/`npm` 是开启了 auto-install 的 mise shim。我在临时目录里放了 `.python-version=3.99.99`，并把 mise 的 data/cache/state 目录重定向到临时目录后执行 `python --version`，**shim 递归自启，短时间内产生数百个 mise 进程**。我立即 `taskkill /F /IM mise.exe /T` 清理（确认归零），真实 mise 目录未被写入（时间戳未变）。这是我自己审查操作造成的事故，已处理，不会重复实验。它同时说明：一个 `NAME --version` 在代理可控的目录配置下可以产生远超"打印一行版本"的副作用（进程风暴、下载、写盘）。
- 建议：除 R7-1 的 env 门控外，把"此规则只在没有版本管理器 shim 时才等价于只读"写进规则注释与文档；可选地让版本探测规则在项目目录存在上述 shim 配置文件时降级为 ask（目前规则语言看不到文件存在性，可能需要 normalizer 打标）。若接受为剩余风险，请显式写入 residual 清单（见第四节）。

### R7-3（low）`which` 的注释与事实不符；重定向/stdin 操作数未走路径检查

- `default.yaml` 中 `allow-no-path-commands` 的注释称"传给它的路径只会被测试是否可执行；secret 与 credential 规则仍会审判该路径"。**这不成立**：`which` 属于 `_NO_PATH_PROGRAMS`，`_h_nopath` 不登记任何路径，所以这些规则看不到它的操作数：`which ./.env`、`which .env`、`which /etc/passwd`、`which /home/testuser/.ssh/id_rsa`、`which -a ./.env` 全部 allow（`which ~/.ssh/id_rsa` 因波浪号被 gray，也只是巧合）。实际暴露面很小：GNU which 只做存在性/可执行位判断并回显名字，不读内容；缺失时错误信息会打印整个 PATH。建议只改注释，或改成"which 操作数不做路径判断，只泄露存在性与 PATH"。
- `which -i git < ~/.bashrc` 为 allow（项目外 stdin 重定向未判）；`which -i git < .env` 则被 `no-secret-read` deny。`-i/--read-alias/--read-functions` 会从 stdin 读别名定义并只回显被查询名字对应的定义行，因此最多泄露项目外文件中的 `alias git=...` 之类的单行。其他无路径规则（如 `pwd < ~/.bashrc`）同属已存在的重定向行为，不是本次新增。
- 试过但不成立：`which` 的任何选项（`--skip-*`、`--tty-only`、`-v`、`-V`、`--help`）都只打印；`which … > out.txt` 为 gray；`which … | xargs …` 为 gray；`sudo/env/command/time which` 为 gray；`WHICH`、`./which` 为 gray；`which $X` / `which \`x\`` / `$(…)` 为 gray。PowerShell 下 `which`/`where`/`Get-Command` 仍为 gray（符合作者"非目标"）。

### R7-4（low）`git ls-files` 的 pathspec 魔法绕过"项目外"检查；没有 git-root-above-project 检查

- `git ls-files :/`、`':(top)'`、`':(top)src'`、`':!src'`、`':^src'`、`':(exclude)src'`、`':(glob)**/*.py'`、`':/..'`、`':(top)../x'` 全部 allow，因为路径检查把以 `:` 开头的词当成非路径。当 git 根目录在项目之上时，`:/` / `:(top)` 会列出整个仓库而不止项目子树；配合 `-o` 还会列出整个仓库的未跟踪文件名，包括 `.env`、`id_rsa` 一类名字。输出只含文件名，不含内容，因此只给 low。此外 `git ls-files *.py`（未加引号、通配符未展开）因 `glob-not-expanded` 变成 ask，属保守方向。
- 建议：对 ls-files 做和 `git add`/`git commit` 一致的处理——pathspec 里出现 `:` 魔法前缀或 `..` 时视为"项目外"，并复用已有的 git-root-above-project 磁盘检查。
- 试过但不成立：路径明确在项目外（`..`、`../other`、`/etc`、`~`、`C:\Windows`）全部 ask；`.env`、`./.env`、`~/.ssh`、`-X ~/.ssh/id_rsa`、`--exclude-from=.env`、`--with-tree=.env` 全部 deny；`git ls-files >> ../out.txt` 为 ask；`git ls-files > out.txt` 为 gray。

### R7-5（low，文档/测试卫生）`workflow_benign.yaml` 里 8 条改为 allow 的条目注释仍写"not allowed … moved to keep-ask"

- 条目本身（tier、expect_after）已改对，但行尾注释与现状相反，会误导以后读语料的人。建议顺手改注释，不影响裁决。

### R7-6（info，已存在）全局选项 `-p` / `-P` / `-h` / `-v` 被 allow-git-ls-files 放行，而 `--paginate` 在 `flags_none` 里

- `git -p ls-files` allow，`git --paginate ls-files` gray。`git -p status` 在 HEAD 上同样是 allow（allow-git-read-only），所以这是已存在的不一致，不是本次引入。非 tty 下 git 不会真的起分页器，我没找到利用方式。建议下一轮把短选项和长选项对齐。

## 二、核对结果（作者声称 vs 实测）

| 作者声称 | 核对 |
|---|---|
| `NAME --version` 只在"恰好一个字面参数 `--version`"时 allow | 成立：引号/转义/`$'..'`/续行/注释/`;`/`&`/`2>&1`/`>/dev/null` 形式在 Bash 下都归一成同一个字面参数，正确 allow；任何额外参数（`x`、`""`、`''`、`$X`、`` `echo x` ``、`$(..)`、`*`、`~`、`{a,b}`、`<(..)`）、缩写（`--v`..`--versio`）、`--version=x`、`--`、`-V`、大小写变体、`python -m --version`、`node --require x --version`、`cargo +nightly --version`、`docker --context x --version`、`git -c … --version`、`git --version -c …`、`--version --version` 都不是 allow（要么 gray 要么交给别的规则）。PowerShell 下反引号拆分、`'..'`/`".."`、`& python`、`.exe` 后缀、全路径、大小写同样正确；`$a`、`@a`、`$null`、`($x)`、`--%`、`/version`、`-version`、`--version:x` 均不 allow |
| 打标可靠，无已知旁路 | 在上述覆盖范围内成立。例外是 R7-1/R7-2：标记机制没问题，问题在规则之外（env 与 shim） |
| `git --version` 不咨询别名/配置 | 成立（真实 git 验证：不读 alias、fsmonitor、pager） |
| `NAME` 路径限定变体被拦 | 部分成立：`./python`、`../python`、`.venv/bin/python`、`~/bin/python`、`/tmp/python`、`./node` 均 gray（`program-path-qualified`）；但 `/usr/bin/python3`、`C:\Windows\System32\python.exe`、`python.exe`、`git.exe` 是 allow，这是预期的系统路径形式 |
| 管道/复合：`&&`、`;`、`\|`、子 shell 里每一段都单独裁决 | 成立：`python --version; rm -rf .` 整体 gray；`python --version && python -c 'print(1)'` gray；`python --version \| xargs python -c 'x'` gray；`bash -c 'python --version'` gray；`cmd /c`、`powershell -c`、`iex`、`Start-Process` 均 gray |
| ls-files 只放行 `_GIT_LS_FILES_FLAGS` 内的选项，其余全部 gray | 成立：缩写（`--oth`、`--mod`、`--del`、`--cac`、`--exclude-st`）、簇（`-om`、`-oz`）、`-c/-s/-t/-v/-f/-u/-k/-i`、`-x/-X/--exclude*`、`--directory`、`--no-empty-directory`、`--eol`、`--deduplicate`、`--sparse`、`--resolve-undo`、`--recurse-submodules`、`--with-tree`、`--format`、`--error-unmatch`、`--debug`、`--abbrev`、`--full-name`、`--` 一律 gray。`--others=x`、`-z=x`、`--modified=x` 被 allow，但真实 git 会因"选项不带值"报错退出，无副作用 |
| ls-files 的全局选项被拦 | 成立：`-c`、`-C`、`--git-dir`、`--work-tree`、`--exec-path`、`--config-env`、`--paginate`、`--help`、未知全局选项均 gray；`--no-pager`、`--literal-pathspecs`、`--no-optional-locks`、`--bare`、`--namespace`、`--attr-source` 等无害选项 allow |
| ls-files 不运行程序 | 部分不成立：我在临时仓库里设置了 `core.fsmonitor` 指向一个会写标记文件的脚本，`git ls-files`（含所有 allowlist 选项）都会触发它，因为读索引就会 tweak fsmonitor。这与已冻结的 `git status/diff` 同一信任边界：触发前提是 `.git/config` 可写，而 `.git/config`、`.git/hooks/*`、`.git/info/exclude`、`.gitconfig` 的 Write 目前都是 ask。归入已声明残余 |
| 严格策略不动 | 成立：`git diff 70bbd98 -- policies/strict.yaml` 为空；`boundkeep test` strict 310 条 0 失败 |
| 旧测试期望没有被放宽 | 成立，且变更与协调者列出的完全一致：`default.yaml` 内 `git --version`（Bash）与 PowerShell `python --version` 两条 gray→allow；pipeline 语料 6 条 adv-gray→allow；workflow 语料 8 条 keep-ask→t1-read；`test_m1c_allow_rules.py` 的 NOT_ALLOWED 列表删 5 行（`git --version`、Bash 的 `python/node/npm --version`、PS 的 `python --version`）；解释器守卫测试只豁免 `allow-version-probe`，并对它另加了 `flags_any == ["--version"]`、`--version-with-arguments ∈ flags_none`、`paths_read_only` 的断言。另外 `ask-git-read-outside-project` 的子命令列表与 `EXPECTED_ALLOW_IDS` 同步更新。没有发现被删除或弱化的非预期期望 |

测试与度量（重新跑了与本次相关的部分，没有跑全量）：
- `tests/unit/test_info_commands_allow.py` + `tests/unit/test_m1c_allow_rules.py`：1645 passed, 1 skipped（跳过的是需要受信项目的用例，与本次无关）。
- `boundkeep test --policy policies/default.yaml`：960 条，0 失败；strict：310 条，0 失败。
- `scripts/measure_ask_rate.py`：posix 默认策略各 tier 与目标一致，"verdict differs from expect_after: 0"。

## 三、试过但没有成立的路径

- 版本探测：env 前缀以外的所有 Bash/PowerShell 引用、转义、缩写、续行、重定向、`--` 形式（见上表）；`sudo/env/command/builtin/exec/time/nohup/timeout/xargs` 前缀（全部 gray）；`PATH=./bin`、`PYTHONSTARTUP/PYTHONPATH/PYTHONHOME/PYTHONUSERBASE/PYTHONWARNINGS`、`NODE_OPTIONS`、`NODE_PATH`、`GIT_EXEC_PATH`、`GIT_CONFIG_GLOBAL`（均 gray，被 `_ENV_CODE` 或 `devtool_env_is_safe` 拦住）；`py`、`python3.12`、`pythonw`、`npx`、`pnpm`、`yarn`、`go`、`java`、`bash`、`sh`、`curl`、`ssh -V`、`gcc`、`make`、`docker version`、`git version`、`node -v`、`python -V`（不在列表，gray 或 ask）。
- `docker --version` 在 `DOCKER_HOST=tcp://x` 下：docker CLI 打印版本前不连接守护进程，所以不是联网路径，但这仍是 R7-1 的 env 门控问题。
- `git ls-files` 的管道/命令替换：`| xargs cat`、`| xargs -I{} sh -c`、`| while read`、`cat $(git ls-files)`、`rm $(git ls-files -o)`、`| sh`、`| python -c` 均 gray 或 ask；`git ls-files && git push` 由 `net-allowlist` 判 ask；`git ls-files | Remove-Item` 为 ask；PowerShell `ForEach-Object { Get-Content $_ }`、`Get-Content (git ls-files)` 为 gray。
- `git LS-FILES`、`git ls-file`、`git ls-fil`：未知子命令，gray。
- 真实 git（临时仓库）：allowlist 选项集合内除 fsmonitor 以外没有观察到写文件或起程序的行为。

## 四、结论与冻结建议

- 是否仍有 high/medium：**有**。R7-1（high，env 前缀无门控 + Write 放行版本管理器配置的链，GIT_TRACE 任意文件追加）；R7-2（medium，shim 读取代理可写配置、auto-install、进程风暴，本机已观察到失控）。
- 能否冻结：
  - `allow-git-ls-files`：修 R7-1 的 env 门控与 R7-4 的 pathspec 魔法检查后可冻结；仅 R7-4 本身是 low，可在冻结时作为残余声明。
  - `allow-no-path-commands`（`pwd`、`which`）：改正注释（R7-3）即可冻结，无需改裁决逻辑；R7-1 的 env 门控若统一做在三条规则上更好。
  - `allow-version-probe`：**暂不可冻结**。需要先做 R7-1 的 env 门控并重跑 R7-1 表中每一行；R7-2 需要修复或由使用者明确接受为残余。
- 建议的修复顺序：（1）三条规则统一要求无 env 前缀，或接入 `devtool_env_is_safe`；（2）`_ENV_CODE` 增加 `git_trace*`、`git_trace2*`；（3）改 `which` 注释；（4）ls-files 对 `:` 魔法/`..` 复用 git-root-above-project；（5）把 workflow 语料注释改正。

## 五、最终声明的残余（Declared residuals）

若使用者决定按下述方式接受，冻结后应写进规则注释与 `docs/reports`：

1. `NAME --version` 执行的是 PATH 解析到的任何程序（作者已声明）；若是版本管理器 shim，则其副作用（读项目版本文件、auto-install、网络下载、进程风暴）不受规则约束（R7-2，如不修复）。
2. `GIT_TRACE*` 可经 git 规则向任意文件追加 trace 行（已存在于 git 规则，本次扩展到 `git --version` / `git ls-files`；若 R7-1 修复则不再是残余）。
3. `git ls-files`（以及 `git status/diff`）在 `.git/config` 被写入 `core.fsmonitor` 之后会运行该程序；前提是 `.git/config` 已被改写，目前其 Write 为 ask。
4. `git ls-files :/` 一类 pathspec 魔法会列出项目之上的整个 git 仓库的文件名（R7-4，如不修复）；只含文件名。
5. `which` 的操作数不经任何路径规则，仅泄露存在性和可执行位，缺失时错误信息会打印 PATH；`which -i/--read-alias` 配合项目外 stdin 重定向可回显目标文件里与查询名字相同的别名定义行（R7-3）。
6. `-p/-P/-h/-v` 全局选项与 `--paginate` 处理不一致（R7-6，已存在，非 tty 下无实际利用）。
7. 本审查未覆盖：PowerShell 下 `where.exe`/`Get-Command` 的细节；Windows App Execution Alias（Store 版 python 启动器）对 `python --version` 的实际行为；mise `_.source`/`exec()` 在带有 `MISE_TRUSTED_CONFIG_PATHS` 时的最后一跳的实机复现（出于安全考虑未再做）。

## 六、操作透明度

审查期间我仅在 %TEMP% 下的临时目录里运行了真实的 `git`（`--version`、`ls-files` 全部 allowlist 选项、`core.fsmonitor`/`GIT_TRACE` 验证）、`python/node/npm --version` 的无害确认，以及一次导致 mise 进程风暴的实验（见 R7-2，已清理、真实 mise/`~/.claude`/`~/.boundkeep` 未被触碰）。仓库内没有修改任何源文件或已提交文档；临时仓库已删除。


---

# 复核（第二轮）：R7-1..R7-6 修复后

- 复核对象：同一工作树（HEAD 仍是 70bbd98，改动未提交）。方法同前：只做 normalize/裁决，不执行被审命令；真实 git 只在上一轮临时仓库里用过；本轮没有任何 shim 实验。
- 结论先行：**R7-1 到 R7-6 全部关闭；新增 1 条 medium（R8-1，选择文件名单不完整，代理仍可用别的名字写 mise 配置）和 2 条 low；`allow-git-ls-files` 与 `which` 可以冻结；`allow-version-probe` 在 R8-1 修好、残余 1 被接受之后可以冻结。**

## 一、逐条是否关闭

| 编号 | 上轮级别 | 本轮 | 证据 |
|---|---|---|---|
| R7-1 env 前缀 | high | **关闭** | 重跑上轮 v1/v2 全量用例（Bash/posix 与 PowerShell/windows 两台假机器）：上轮 allow 的 98 + 121 条里，减少的恰好是 env 前缀组（24 条，含 `CI=1`、`PYTHONSAFEPATH=1`、`MISE_*`、`PYENV_VERSION`、`VOLTA_HOME`、`RUSTUP_*`、`CARGO_HOME`、`NPM_CONFIG_*`、`PIP_*`、`UV_CONFIG_FILE`、`DOTNET_*`、`DOCKER_*`、`GIT_TRACE`）和 ls-files 的 17 条（env 前缀、`:` 魔法、`-p`/`-P`、`which -i git < ~/.bashrc`）；**没有任何新增 allow**。`GIT_DISCOVERY_ACROSS_FILESYSTEM=1 git ls-files`、`GIT_CEILING_DIRECTORIES=x git ls-files`、`DOCKER_HOST=tcp://x docker --version` 现为 gray。额外试了 `X= git --version`、空值、多个前缀、`(X=1 …)`、`{ X=1 …; }`、`X=1 \python`、`X=1 'python'`、`X=1 python "--version"`、`X=1 /usr/bin/python3`、`X=$(echo a) python`、`X=1 command/env python`、`&&` 与 `;` 之后的前缀、`if … then X=1 …`、`export X=1; python --version`、`declare -x`、`set -a`、独立赋值 `X=1; python --version`：全部 gray。PowerShell 的 `$env:X=…;`、`Set-Item env:`、`[Environment]::SetEnvironmentVariable` 都是复合语句，gray。`is_code_env` 的 `git_trace*` 前缀对大小写不敏感（`git_trace=`、`Git_Trace=`、`GIT_TRACE2`、`GIT_TRACE_PACKET`、`GIT_TRACE_SETUP`、`GIT_TRACE2_PERF` 均 gray）；因为在 `_ENV_CODE` 层，已冻结的 `git status/log/add` 带 `GIT_TRACE=…` 也变成 gray，顺带修好了上轮指出的同类缺口 |
| R7-2 选择文件写入 | medium | **部分关闭**，见 R8-1 | 13 个名字在 default 下 ask、strict 下 deny，覆盖 Write/Edit/MultiEdit/NotebookEdit 与全部 shell 写法（`>`、`>>`、`tee`、`cp`、`mv`、`git mv`、`rsync`、`install`、`dd of=`、`sed -i`、`ln`/`ln -s`、`touch`、`git checkout/restore`、PowerShell 的 `Set-Content`/`Out-File`/`Copy-Item`/`Move-Item`/`Rename-Item`/`New-Item`/`Add-Content`/`>`）、嵌套子目录（`**/`）、大小写变体（`MISE.TOML` 等，两台假机器）、反斜杠路径。残余 1 的描述见第三节 |
| R7-3 which | low | **关闭** | `default.yaml` 与 `policy-reference.md` 的措辞现在与事实一致（路径只被当命令名、只透露存在性与可执行位、缺失时打印 PATH）；`which -i git < ../other`、`< ~/.bashrc`、`< /etc/passwd`、`2>../x`、`< $X`、`--read-alias/--read-functions … < ../other/a` 现为 ask（`ask-shell-read-outside-project`）；项目内 `< src/a.txt`、`< ./a`、`<<< x`、`< /dev/null` 仍 allow，`< .env` 仍 deny |
| R7-4 `:` pathspec | low | **关闭** | `:`、`:/`、`":/"`、`\:/`、`$':/'`、`":"/`、`""':/'`、`:(top)`、`:!src`、`:^.env`、放在选项前后或多个操作数中间、`-- ':/'`、PowerShell 的 `':/'`/`":/"`/`:/`/`` `:/ `` 全部 gray。`./:x`、`src/:x` 不以冒号开头（git 当普通路径），仍 allow，这是正确的 |
| R7-5 语料注释 | low | **关闭** | 8 条注释已改成 "allow-version-probe (…)"；`t1-go-version` 的旧注释仍是 keep-ask 的事实，没问题 |
| R7-6 `-p`/`-P` | info | **关闭**（ls-files 内） | `git -p/-P ls-files`、`--no-pager -p`、`-pP`、`-pc` 均 gray，`--no-pager ls-files` 仍 allow。`git -p status` 在 `allow-git-read-only` 上仍是 allow，是已存在的行为，非本批引入，保留在残余清单 |

测试与度量（重跑了与本批相关的部分，没有跑全量）：
- `boundkeep test`：default 994 条、strict 314 条，0 失败。
- `test_info_commands_allow.py`、`test_m1c_allow_rules.py`、`test_git_local_vcs_allow.py`：1989 passed、1 skipped（需要受信项目的用例，与本批无关）。
- `scripts/measure_ask_rate.py`：Windows 50.4（目标 50.4），POSIX 49.3（目标 49.3），"verdict differs from expect_after: 0"。
- 旧期望没有被放宽：`git diff HEAD -- tests policies` 的删除行仍只有上轮列出的那些（`git --version` 与 PowerShell `python --version` 两条 gray 期望、五行 NOT_ALLOWED、`allow-no-path-commands` 的程序列表、`ask-git-read-outside-project` 的子命令列表、解释器守卫改成只豁免 `allow-version-probe`）。
- **strict 策略本轮有改动**（上轮是零改动）：只新增 `deny-toolchain-selector-write` 一条 deny 和 2 条 `tests:`，没有新增任何 allow，也没有删除或放宽任何已有规则；subset 一致性测试通过。方向是更严，不构成问题，但"strict 不变"的说法现在应改成"strict 只多了一条 deny"。

## 二、新发现

### R8-1（medium）选择文件名单不完整：用别的名字照样写得进 mise 配置，default 下是 allow

在 default 策略下，Write（posix 与 windows 两台假机器结果相同）以下路径仍是 **allow**（strict 为 gray）；其中前几条是 mise 官方文档里列出的配置文件位置，shim 在项目目录里会读它们：

| 路径 | 说明 |
|---|---|
| `.config/mise/config.toml`、`.config/mise/config.local.toml`、`.config/mise/conf.d/*.toml` | mise 的 XDG 风格项目配置，是最常见的位置之一；`.config/mise.toml` 因为被 `**/mise.toml` 匹配所以已 ask，但同目录下的 `mise/config.toml` 没有 |
| `mise/config.toml`、`mise/config.local.toml`、`mise/conf.d/*.toml`、`.mise/config.local.toml`、`.mise/conf.d/*.toml` | 同上；只有 `.mise/config.toml` 在名单里 |
| `mise.dev.toml`、`.mise.dev.toml`、`mise.production.toml`（`mise.<env>.toml`） | 仅在环境里设了 `MISE_ENV` 时才被读，门槛高，但设置 `MISE_ENV` 的 export 在同一会话里可以由用户事先做 |
| `.rtx.toml`、`rtx.toml` | mise 的旧名字；是否仍被读取我这次没有核实 |
| `.python-versions` | pyenv 多版本文件（复数） |
| `.volta/hooks.json` | volta 的项目级钩子（`distro` 钩子可以指向要运行的可执行文件） |

对应的 shell 写入（`echo x > .config/mise/config.toml`、`mv a.txt .config/mise/config.toml`、`git mv …`、PowerShell `Set-Content .config\mise\config.toml`）是 gray 而不是 allow（`.config` 下未知路径不是 allow），所以真正的缺口是 **Write / Edit / MultiEdit 工具直接写这些路径**。

严重度说明：这条绕过本身要成立，还需要 mise 把新写的配置当作可信（mise 对会执行代码的配置要求先 `mise trust`；R7-1 修好之后代理不能再用 `MISE_TRUSTED_CONFIG_PATHS` 自我信任）。我没有也不会再做 shim 实验，所以不能确认利用到哪一步，只能确认"默认 Write 放行 + shim 会读这些路径"这两个前提。因此按 medium，而不是 high。它同时直接削弱了 R7-2 的修复：名单只覆盖了作者想到的名字。

建议：把 glob 改成按目录和模式覆盖，而不是只列文件名。因为每条规则上限 64 个 glob，可以再单立一条或换成目录通配：`**/.config/mise/**`、`**/.mise/**`、`**/mise/config*.toml`、`**/mise/conf.d/**`、`**/mise.*.toml`、`**/.mise.*.toml`、`**/.rtx.toml`、`**/rtx.toml`、`**/.python-versions`、`**/.volta/**`。验收：上表每一行 default 都应变 ask、strict 变 deny。不需要加的（我也检查过，不是探测程序的选择文件）：`Cargo.toml`、`pip.conf`、`nuget.config`、`Directory.Build.props`、`dotnet-tools.json`、`.dockerignore`、`.pnp.cjs`/`.yarnrc.yml`（yarn 不在探测名单里，且 `.yarnrc.yml` 已是 ask）、`.envrc`（direnv 是 shell 钩子不是 shim，且已是 ask）、`rust-toolchain(.toml)`、`.npmrc`、`package.json`（含 volta 的 `volta` 键）、`pyproject.toml`、`.cargo/config(.toml)`（均已是 ask）。

### R8-2（low）`docs/policy-reference.md` 表格行被合并

第 189 行把 `allow-git-ls-files` 行和 `allow-ps-inspect-inside-project` 行连在了一起（前一行缺末尾的 ` |` 与换行）。结果是 `allow-ps-inspect-inside-project` 这条规则在文档里不再有自己的行，渲染出来的表格也多了列。只影响文档，改成两行即可。

### R8-3（low，文档/措辞）残余 1 与 `strict` 的说法需要更新

见第三节对残余 1 的评价；另外作者报告第 2 节写 "strict 不变（有测试守着）"，现在应写成 "strict 只多了一条 deny"。

## 三、对残余 1 的评价

作者的描述方向准确：别人放进来的（`git clone/pull`、解压）选择文件拦不住，规则会放行 `NAME --version`，shim 随后读这些文件。需要补充或更正的几点：

1. **"规则语言看不到文件是否存在，所以无法降级；唯一做法是整条拿掉规则"这句不准确。** 规则语言确实看不到，但规范化器已经有若干真实磁盘检查（git-root-above-project、子树扫描、硬链接检测）。同样的办法可用于这里：在 cwd 到项目根的各级目录里发现任一选择文件（含 R8-1 的名单）时，给 `NAME --version` 打一个类似 `--version-with-arguments` 的标记，让探测规则不匹配（回到 ask）。这样 clone 下来的不可信仓库在带有选择文件时仍会问，没有这类文件时才放行；代价是常见仓库（带 `.python-version`、`.nvmrc`、`.tool-versions` 的）会退回 ask，需要评估误报。这是比"整条拿掉"便宜得多的折中，建议写进残余说明作为可选关闭方式。
2. **触发并不需要恶意。** 仓库里本来就有、用户也信任的 `.tool-versions`/`.python-version`，只要指向一个未安装的版本，开启 auto-install 的 shim 会在 `NAME --version` 时联网下载并安装工具链（我上轮在本机观察到过 mise 递归拉起大量进程）。这是副作用（网络、写盘、进程数），不是代码执行，建议在残余里单列一句，让使用者知道"放行 `--version` 在带 shim 的机器上不等于零副作用"。
3. **文件来源不止 clone/解压**：已存在于仓库里的、其他进程写入的、以及 `git stash pop/apply` 这类 allow 的 git 操作恢复出来的选择文件同样拦不住（写入检查只看工具调用本身）。
4. **范围之外的位置**：项目目录的上级目录和用户级配置（`~/.config/mise`、`~/.tool-versions`）也会被 shim 读取；代理对它们的写入是项目外写，仍走 ask/deny，不在本残余内，但应写明"依赖项目外写入保持 ask"。
5. 用户事先 `export` 的 `MISE_ENV`、`MISE_TRUSTED_CONFIG_PATHS`、`PYENV_VERSION` 之类仍然有效（作者的残余 2 已写到）。

## 四、问题回答

1. 每条是否关闭：R7-1 关闭；R7-2 部分关闭（13 个名字关闭，名单不完整见 R8-1）；R7-3、R7-4、R7-5、R7-6 关闭。
2. 是否还有 high/medium：**没有 high；有 1 条 medium（R8-1）**，另有 2 条 low（R8-2、R8-3）。
3. 能否冻结：
   - `allow-no-path-commands`（`which`）：**可以冻结**（R7-3 关闭，残余 3 如实）。
   - `allow-git-ls-files`：**可以冻结**（R7-1、R7-4、R7-6 关闭；残余仅为 `.git/config` 里的 `core.fsmonitor` 与 `git -p status` 一类已存在项）。
   - `allow-version-probe`：**修好 R8-1 之前不能冻结**；R8-1 修好后，若残余 1 被接受，可以冻结。
4. 若残余 1 被接受，`allow-version-probe` 能否冻结：**能，前提是先修 R8-1**（因为 R8-1 是代理自己能写的路径，不属于"别人放进来"那一类，不能算进残余 1）。建议同时采纳第三节第 1 点的可选标记方案来缩小残余 1，但这不是冻结的必要条件。

## 五、更新后的声明残余清单

1. `NAME --version` 运行 PATH 上的程序；若为版本管理器 shim，shim 会读项目及上级目录里**已经存在**的选择文件，可能触发 auto-install（联网、写盘、进程数）或执行其中配置的程序；代理自己写这些文件被 ask/deny（R8-1 修好之后），别人放进来的拦不住。可选关闭方式：规范化器检测选择文件存在并打标记。
2. 用户事先 `export` 的环境变量看不到。
3. `which` 的参数不经路径规则，只透露存在性和可执行位，缺失时错误信息打印 PATH。
4. `git ls-files`（以及 `git status/diff`）在 `.git/config` 被写入 `core.fsmonitor` 后会运行该程序；前提是 `.git/config` 已被改写（其 Write 为 ask）。
5. `git -p status` 等已冻结规则里的 `-p`/`-P` 仍被放行，非 tty 下无已知利用。
6. `mise.<env>.toml`、`.rtx.toml`、`.volta/hooks.json` 是否真的被相应工具读取，我没有逐一实测（出于安全原因不做 shim 实验），按文档和记忆列入 R8-1 的建议名单；若使用者希望名单有实证依据，需要在隔离环境里单独核实。
7. 本复核未覆盖：PowerShell 下 `where.exe`/`Get-Command`；Windows 商店版 python 启动器；pwsh 7。

## 六、操作透明度

本轮没有执行任何被审命令，没有做 shim 实验，没有创建临时仓库；只用 `h.py`/`t.py`/`w3.py`（均在会话 scratchpad，不在仓库里）对规则做裁决，并重跑了 `boundkeep test`、三份相关单元测试和 `measure_ask_rate.py`。除本文件外未修改任何文件。

---

# 复核（第三轮）：R8-1 / R8-2 / R8-3

- 范围：只复核 R8-1、R8-2、R8-3。方法同前（只做裁决，不执行被审命令，没有 shim 实验）。
- 结论先行：**R8-1、R8-2、R8-3 全部关闭；没有 high、没有 medium。残余 1 已由使用者于 2026-10-27 明确接受，`allow-version-probe` 现在可以冻结。** 只有两条 info 级说明，不阻塞。

## 一、逐条

### R8-1 选择文件名单不完整：关闭

策略现在是 20 条 glob（default 的 `ask-toolchain-selector-write` 与 strict 的 `deny-toolchain-selector-write` 逐条相同，我用 diff 比对过：20 对 20，完全一致）。

1. 上轮表里每一行，Write 工具在 posix 与 windows 两台假机器上都是 **default ask / strict deny**：`.config/mise/config.toml`、`.config/mise/config.local.toml`、`.config/mise/conf.d/x.toml`、`mise/config.toml`、`mise/config.local.toml`、`mise/conf.d/x.toml`、`mise/conf.d/sub/y.toml`、`.mise/config.local.toml`、`.mise/conf.d/x.toml`、`.mise/tasks/build`、`.mise/x.sh`、`mise.dev.toml`、`.mise.dev.toml`、`mise.production.toml`、`mise.a.b.toml`、`sub/mise.dev.toml`、`.rtx.toml`、`rtx.toml`、`.python-versions`、`.volta/hooks.json`、`.volta/config.json`、`.volta/x/y/z`，以及嵌套在子目录里的 `a/b/.config/mise/config.toml`、`a/.mise/config.toml`、`a/mise/config.toml`。上轮已覆盖的 13 个名字（含大小写变体 `MISE.TOML`、`.Python-Version`、`.TOOL-VERSIONS`、`GLOBAL.JSON`、`UV.TOML`、`.NVMRC`）、Edit、MultiEdit、NotebookEdit 仍然全部 ask。
2. shell 写法（上轮是 gray 的那批）现在是 ask：`echo x > .config/mise/config.toml`、`mv`/`git mv`/`cp` 到 `.config/mise/` 与 `mise/conf.d/`、`echo x | tee .rtx.toml`、`sed -i … .python-versions`、`ln -s a .config/mise/config.toml`、`echo x > .volta/hooks.json`、`echo x > mise.dev.toml`、`touch .mise/anything`；PowerShell 的 `Set-Content`、`Copy-Item`、`New-Item` 到同类路径也是 ask，包括大写写法（`MISE.DEV.TOML`、`.\.CONFIG\MISE\config.toml`）。
3. **没有误伤读**（`access: write` 才匹配）：`Read`、`Grep` 对 `.config/mise/config.toml`、`mise.toml`、`.mise/config.toml`、`.volta/hooks.json`、`.python-version`、`mise/conf.d/x.toml`、`global.json` 在 default 与 strict 下都和改前一样（allow）；`cat`、`ls`、`ls -la .mise`、`grep -r x .mise`、`rg x .volta`、`git status .mise`、PowerShell 的 `Get-Content .config\mise\config.toml`、`Get-ChildItem .mise` 都仍然 allow。`Glob` 对这些路径是 gray/ask，但对照 `README.md`、`src/a.py` 的 Glob 也是同样结果，是 Glob 本身的行为，与本批无关。
4. **没有把普通项目内写入意外变 ask**（25 个对照路径，两台假机器，default allow / strict gray，与改前一致）：`mise/foo.py`、`mise/README.md`、`mise/config.py`、`mise/conf.dx/a.toml`、`mise/configuration.md`、`mise/config_notes.txt`、`src/mise/foo.py`、`docs/mise/guide.md`、`mise.md`、`mise.lock`、`premise.toml`、`my-mise.toml`、`mise_helpers.toml`、`src/mise.py`、`.config/other/x.toml`、`.config/foo.toml`、`config/mise-notes.md`、`.mise-notes`、`volta/x.json`、`.voltax/x`、`src/.miser/x`、`mise.toml.bak`、`mise.tomlx`、`x.mise.toml`、`a.mise/config.toml`。此外上轮列出的"不必加"的文件（`Cargo.toml`、`pip.conf`、`nuget.config`、`Directory.Build.props`、`.dockerignore`、`.pnp.cjs`、`Pipfile`、`uv.lock`、`.go-version`、`.java-version`、`.terraform-version`、`.bun-version`、`.asdfrc`、`mise.lock`）仍是 allow，没有被通配带进去；`echo x > mise/foo.py` 仍是 gray，`mkdir mise` 仍是 allow，`git add mise/foo.py` 仍是 allow。
5. 有意的副作用（作者已说明，我确认行为如描述）：`.mise/**`、`.volta/**`、`.config/mise/**` 下一律 ask，包括建目录（`mkdir .mise`、`mkdir .volta`、`mkdir -p .config/mise`、`New-Item -ItemType Directory .mise`），以及 `git add` 一个选择文件（`git add .python-version`、`git add .mise/config.toml`、`git add .config/mise/config.toml`）。这两项属于保守方向，不是问题；`mkdir mise`（目录本身不匹配任何 glob）仍然 allow。

### R8-2 policy-reference.md 表格行合并：关闭

`allow-git-ls-files` 与 `allow-ps-inspect-inside-project` 现在分别在第 189、190 行，行尾都是完整的 ` |`，没有再合并。

### R8-3 "strict 不变"的说法：关闭

`docs/reports/M2-rules-2.md` 第 2 节现在写 "strict 只多了一条 deny（`deny-toolchain-selector-write`）和几条测试，没有新增 allow"。我核对了 `git diff HEAD -- policies/strict.yaml`：新增行里只有一个 `- id:`（`deny-toolchain-selector-write`）和一个 `action: deny`，加上 `tests:` 条目；strict 没有任何 allow 增删，也没有删除或放宽已有规则。与事实一致。

## 二、其余核对

- `boundkeep test`：default 1016 条、strict 318 条，0 失败。
- 旧期望没有被放宽：`git diff HEAD -- tests policies` 的删除行仍然只有第一轮列出的那批（`git --version` 与 PowerShell `python --version` 两条 gray 期望、五行 NOT_ALLOWED、`allow-no-path-commands` 的程序列表与 `ask-git-read-outside-project` 的子命令列表、解释器守卫改为只豁免 `allow-version-probe`）。这一轮没有新增删除行。
- 我没有重新跑定向 pytest 和评测（作者报告已跑，并且本轮规则改动只涉及一条 ask/deny 规则的 glob 列表，上面的裁决表已覆盖它的行为）。如需要我可以补跑。
- 残余声明（报告第 6 节残余 5、6）与我上轮建议一致：auto-install 副作用、`git stash pop` 等来源、项目上级目录与用户级配置依赖项目外写入保持 ask、`mise.<env>.toml`/`.rtx.toml`/`.volta/hooks.json` 未实测、可选的磁盘检测标记方案未做。第 1 条里"只能整条拿掉"的说法已更正为两种做法。准确。

## 三、新增说明（info，不阻塞）

1. `.mise/**`、`.volta/**`、`.config/mise/**` 的通配会让建这些目录和 `git add` 其中的文件也变 ask，如上所述是有意的保守行为，建议在 `policy-reference.md` 的规则说明里提一句，免得日后被当成误报。
2. 名单仍然依赖对 mise、asdf、pyenv、volta、rustup 配置位置的文档与记忆。出于安全原因没有做 shim 实验，所以"这些位置确实被读取"没有实证；方向是保守的（多拦不漏拦），已记入残余 5。

## 四、结论

- R8-1、R8-2、R8-3：**全部关闭**。
- 是否还有 high/medium：**没有**。累计状态：R7-1..R7-6 与 R8-1..R8-3 全部关闭，无遗留 high/medium。
- `allow-version-probe`：**可以冻结**（残余 1 已被使用者接受，且 R8-1 已修好，不再有"代理自己能写"的绕过）。
- `allow-git-ls-files`、`allow-no-path-commands`（`which`）：上一轮已判可冻结，本轮没有变化。

## 五、最终声明的残余（冻结时写入）

1. 版本管理器 shim：`NAME --version` 运行 PATH 上的程序；项目及上级目录里**已经存在**的选择文件，以及其他进程、clone、解压、`git stash pop` 带来的选择文件，会被 shim 读取，可能触发 auto-install（联网、写盘、进程数）或执行其中配置的程序。代理自己写这些文件被 ask（strict deny）。**使用者已于 2026-10-27 明确接受。** 可选的收窄方式（规范化器检测选择文件并打标记）未做。
2. 用户事先 `export` 的环境变量看不到。
3. `which` 的参数不经路径规则，只透露存在性和可执行位；缺失时错误信息打印 PATH。
4. `git ls-files`（以及 `git status/diff`）在 `.git/config` 被写入 `core.fsmonitor` 之后会运行该程序；前提是 `.git/config` 已被改写（其 Write 为 ask）。
5. 已冻结规则 `allow-git-read-only` 里的全局 `-p`/`-P` 仍被放行，非 tty 下无已知利用。
6. 选择文件名单依据文档与记忆，未实测；方向保守。
7. 未覆盖：PowerShell 下 `where.exe`/`Get-Command`；Windows 商店版 python 启动器；pwsh 7。

## 六、操作透明度

本轮没有执行任何被审命令，没有 shim 实验，没有创建临时仓库；只用 scratchpad 里的 `w3.py`/`w4.py`/`t.py` 做裁决，并重跑了 `boundkeep test`（default/strict）和 `git diff HEAD` 的比对。除本文件外未修改任何文件。