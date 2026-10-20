# M1c 验收报告

## 1. 结论

**自动验收、Linux 容器验证和真实 Claude Code 冒烟都通过；手工验收（`docs/manual-acceptance-m1c.md`）、对 allow 规则的定向 X1 审查、以及在你自己真实会话上的覆盖率测量都还没做。等你对第 7 节做选择，并完成第 8 节的前置条件。**

M1c 的目标来自 X1 审查的 M-13（`docs/reviews/M1-M1b-security-review.md`）：`enforce` 下默认策略只有一条 allow 规则（`Read` / `Glob` / `Grep`），几乎每条 shell 命令和每次 `Write` / `Edit` 都会 ask。这比没有 boundkeep 更糟（boundkeep 的 ask 会盖过 Claude Code 自己的自动批准），还会把用户推向 `audit-only`（不防护任何东西）。你选了方案 A（在规则层补 allow 规则），没有选方案 B（LLM）。

需要当面说清的四件事：

1. **这是"与 Claude Code 对齐"，不是"自动批准"。** `defaults.emit_allow` 仍是 `false`：规则判为 `allow` 时 boundkeep 输出"无决定"，由 Claude Code 自己的权限流程决定要不要弹框。M1c 的效果是 boundkeep 不再对"理解得很清楚的安全动作"多问一次，不是替你点了确认。
2. **没有放行任何会运行仓库代码的命令。** 构建与测试命令（`pytest`、`npm test`、`cargo test` 等，下称 Tier 3）有意不放行：它们运行仓库里的代码。
3. **度量用的语料是合成的。** 下面的"问询率"数字说的是设计语料（`tests/corpus/workflow_benign.yaml`，312 条），不是你真实会话里的比例。真实覆盖率要用 `scripts/session_command_stats.py` 在你自己的会话记录上测，你还没有运行它，所以**未验证**。
4. **有残余风险**（第 4 节）。最主要的一条：在不可信的仓库里，`git status` / `diff` / `log` / `show` 仍可能运行该仓库 `.git/config` 里配置的程序（fsmonitor、textconv、外部 diff、分页器）。这正是 `emit_allow` 必须保持关闭的原因。

## 2. 交付物

字段与规则的完整说明在 `docs/policy-reference.md`（实现者已更新，含"日常 allow 规则（M1c，仅 default）"一节），本报告不重复，只列要点。

| 路径 | 说明 |
|---|---|
| `src/boundkeep/policy/schema.py`、`policy/matcher.py`（改） | 新增匹配字段 `flags_none`（动作的标志里一个都没有才匹配，条目规则与 `flags_any` 相同，两者不能列同一条目）与 `paths_read_only`（每条路径的访问方式恰好是 `read`；没有路径时为真）；新增加载期检查"an allow rule must name a tool or a program"（只靠标志或路径收窄的 allow 规则几乎放行一切） |
| `src/boundkeep/normalize/programs.py`（改） | `_ENV_CODE` 增加 `GIT_DIR`、`GIT_WORK_TREE`、`GIT_EXEC_PATH`、`GIT_COMMON_DIR`、`GIT_INDEX_FILE`、`GIT_OBJECT_DIRECTORY`、`GIT_ALTERNATE_OBJECT_DIRECTORIES`、`GIT_NAMESPACE`、`GIT_TEMPLATE_DIR`、`GIT_EDITOR`、`GIT_SEQUENCE_EDITOR`、`GIT_CONFIG`、`XDG_CONFIG_HOME`、`RIPGREP_CONFIG_PATH`、`LESS`、`LESSKEY`、`MANPAGER`（见第 4 节 (b)） |
| `policies/default.yaml`（改，63 条规则） | 见下面的"规则清单" |
| `policies/strict.yaml`（改，52 条规则） | **没有新增 allow 规则**（唯一的 allow 仍是 `read-inside-project`；它的 allow 规则是 default 的子集，有测试保持）；加了 `deny-project-autorun-files`、`ask-secret-file-write`、`ask-credential-file-write`、`ask-git-internals-write`；修了 `ask-read-outside-project`（第 4 节 (c)） |
| `tests/unit/test_m1c_allow_rules.py`、`test_m1c_autorun_rules.py`、`test_m1c_match_fields.py`、`test_m1c_env_code.py`、`test_measure_ask_rate.py`、`test_session_command_stats.py`（新增） | 规则、字段、环境变量前缀与两个脚本的测试 |
| `tests/corpus/pipeline_m1c_allow.yaml`（535 条，其中 425 条 `adv: true`、110 条期望 allow）、`pipeline_m1c_autorun.yaml`（150 条，52 条 `adv: true`）（新增） | 端到端语料；敌对写法放在这里 |
| `tests/corpus/workflow_benign.yaml`（新增，312 条） | 合成的"日常开发流程"度量语料，五层；不是 `pipeline*.yaml`，所以不会被要求精确判决 |
| 已有的 8 个 `tests/corpus/pipeline*.yaml` 与 4 个单元测试文件（改） | 期望值按新规则调整，见第 4 节 |
| `scripts/measure_ask_rate.py`（新增） | 在假机器上跑语料，按平台与层输出"每 100 个动作的问询数"（ask + gray 都算），可对比多份策略；只读、确定性、不联网 |
| `scripts/session_command_stats.py`（新增） | 读你自己的 `~/.claude/projects` 会话记录，输出聚合统计，见第 6 节与手工验收文档 |
| `scripts/smoke_claude_m1c.py`（新增） | 真实 Claude Code 冒烟（`claude -p`），看 boundkeep 的判决与磁盘上的结果 |
| `docs/policy-reference.md`（改）、`docs/reports/M1c.md`、`docs/manual-acceptance-m1c.md`、`IMPLEMENTATION_PROMPTS.md`（改） | 字段参考、本报告、手工验收步骤、里程碑表与 M1c 小节 |

**default 的规则清单（要点）**

- **L-11 的 ask 规则（先于任何项目内写入的 allow 规则）**：`ask-project-autorun-files`（strict：`deny-project-autorun-files`）覆盖构建、CI、IDE、容器与工具配置里"会让代码日后自己跑起来"的文件（`package.json`、`Makefile`、`pyproject.toml`、`conftest.py`、`.github/workflows/**`、`Dockerfile*`、`.vscode/tasks.json` 等，以及用户级的 `~/.cargo/config*`、`~/.aws/config`、`pip.conf` 等；完整清单见 `docs/policy-reference.md`）。这是 X1 审查 L-11 列出的那批路径。规则在 `default.yaml` 里排在 `allow-project-file-writes` 之前（`ask-project-autorun-files` 在文件第 242 行，`allow-project-file-writes` 在第 1371 行；`ask-secret-file-write`、`ask-git-internals-write` 也都在它之前）；判定本身是"最严者胜"，所以顺序是意图的表达，不是正确性的依赖。
- **新增 ask 规则（default 与 strict 同名）**：`ask-secret-file-write`、`ask-credential-file-write`（glob 与 `no-secret-read`、`no-credential-store-read` 逐字相同，有测试保持一致）、`ask-git-internals-write`（`**/.git/**`）。
- **守门规则（仅 default）**：`ask-shell-read-outside-project`、`ask-git-read-outside-project`。几条 allow 规则（读 stdin 的 `head` / `tail` / `wc` / `grep`、不带路径的 `Get-ChildItem`、不带路径的 `git status` / `diff`）没有路径可以要求"在项目内"，从另一侧补上：这些程序带一个不能证明在项目内的路径时 ask。
- **Tier 1（只读，仅 default）**，每条都有 `paths_read_only: true`，读路径的程序再加 `path_inside_project`，并用 `flags_none` 排除危险选项：`allow-list-inside-project`（`ls` / `dir`）、`allow-tree-inside-project`、`allow-find-inside-project`、`allow-rg-inside-project`、`allow-cat-inside-project`、`allow-read-filters`（`head` / `tail` / `wc` / `grep` / `egrep` / `fgrep`）、`allow-no-path-commands`（只有 `pwd`）、`allow-git-read-only`（`git status` / `diff` / `log` / `show` / `blame` / `rev-parse`，Bash 与 PowerShell）、`allow-git-branch-list`（只有 `-a` / `-r` / `--list` / `--show-current` 等列出写法）、`allow-ps-inspect-inside-project`（`Get-Content` / `Select-String` / `Test-Path` / `Get-Item` / `Resolve-Path`）、`allow-ps-list-here`（`Get-ChildItem`）、`allow-ps-no-path-commands`（`Get-Location`、`Get-Date`、`Measure-Object`）。
- **Tier 2（项目内写入，仅 default）**：`allow-mkdir-touch-inside-project`（Bash 的 `mkdir` / `touch`，排除 `touch -r`）、`allow-project-file-writes`（`Write` / `Edit` / `MultiEdit` / `NotebookEdit` 写项目内的文件）。PowerShell 的 `mkdir` / `New-Item` / `cp` / `mv` / `rm` / 重定向 / `tee` / `sed -i` 都不在其中。
- **排除的危险选项**（逐条理由见 `docs/policy-reference.md`）：`find` 的 `-delete`、`-exec*`、`-ok*`、`-fprint*`、`-fls`、`-files0-from`、`-printf`；`rg` 的 `--pre`、`--hostname-bin`、`-r` / `--replace` 与几个会打印命令行字符串的分隔符选项；`git` 的 `-c`、`--config-env`、`-C`、`--git-dir`、`--work-tree`、`--exec-path`、`--paginate`、`--ext-diff`、`--textconv`（含 git 接受的唯一前缀）、`--output`、`--no-index`、`--ignore-revs-file`、`--help`，以及会原样打印命令行字符串的 `--format` / `--pretty` / `--date` 一类；`tree` 的 `-o`、`-R`、`-H`、`-T`、`--timefmt`；`ls --time-style`；`Get-Date -Format` / `-UFormat` / `-Date`；`head` / `tail` / `wc` / `grep` 的 `--files0-from` 与 `--label`；`git branch` 另外排除删除、改名、复制、强制、改上游一类选项。**打印命令行文字的选项被排除，是因为 `$TOKEN` 这样的环境变量展开会被带进输出。**
- **没有放行**：Tier 3 的构建与测试命令；版本探测（`git --version`、`python --version` 等）；`git stash`（含 `stash list`）、光秃秃的 `git branch`、`git remote -v`、`git ls-files` 等；`du`、`date`、`printenv`；PowerShell 的 `New-Item` / `mkdir` / `touch`；`cp` / `mv` / `rm` / `sed -i` / `tee` / 重定向；带通配符的 `Select-String -Path src\*.py`。

未提交的改动（写本报告时 `git status --short`，不含本报告与手工验收文档）：

- 修改（18）：`docs/policy-reference.md`、`policies/{default,strict}.yaml`、`src/boundkeep/normalize/programs.py`、`src/boundkeep/policy/{matcher,schema}.py`、`tests/corpus/{pipeline,pipeline_fix_event,pipeline_fix_policy,pipeline_ps,pipeline_review2_policy,pipeline_review2_programs,pipeline_review3_policy,pipeline_review3_programs}.yaml`、`tests/unit/{test_pipeline,test_policy_rules,test_review2_core_search,test_review3_programs_listing}.py`
- 新增（12）：`scripts/{measure_ask_rate,session_command_stats,smoke_claude_m1c}.py`、`tests/corpus/{pipeline_m1c_allow,pipeline_m1c_autorun,workflow_benign}.yaml`、`tests/unit/{test_m1c_allow_rules,test_m1c_autorun_rules,test_m1c_env_code,test_m1c_match_fields,test_measure_ask_rate,test_session_command_stats}.py`

## 3. 验收标准逐条对照

`IMPLEMENTATION_PROMPTS.md` 在 M1c 之前没有这个里程碑的提示词；标准取自 X1 审查 M-13 的要求（"在 enforce 下可日常使用，allow 规则或 LLM"）与本里程碑的约束（不降低已有保护、不替用户批准）。我在 `IMPLEMENTATION_PROMPTS.md` 里补了 M1c 小节。

| 标准 | 结果 | 证据 |
|---|---|---|
| enforce 下，日常只读检查与项目内写入不再被 boundkeep 多问一次 | **通过（对设计语料）；对真实会话未验证** | 见第 5 节：t1-read 与 t2-write 两层的问询率都从 73.5 / 65.1 与 100 降到 0.0；与设计目标的差异为 0 条。真实会话覆盖率没测 |
| 已有保护不被削弱：保护名字的 deny / ask 仍然最严者胜；任何 `adv: true` 的 shell 条目不是 allow；must-block 层没有 allow | **通过** | `tests/unit/test_pipeline_corpus.py` 对每个 `adv: true` 的 Bash / PowerShell 条目断言"永不 allow"；敌对写法在 `pipeline_m1c_allow.yaml`（535 条里 425 条 `adv: true`）与 `pipeline_m1c_autorun.yaml`；`workflow_benign.yaml` 的 must-block 层 79 条没有一条是 allow |
| L-11 那批"让代码日后运行"的路径在任何项目内写入 allow 之前就 ask | **通过** | `ask-project-autorun-files` 在 default 里排在 `allow-project-file-writes` 之前；`test_m1c_autorun_rules.py` 与 `pipeline_m1c_autorun.yaml`（150 条）；冒烟里 `Write Makefile` 为 ask、文件没有创建 |
| `emit_allow` 保持 `false`；strict 没有新增 allow 规则 | **通过** | default 的 `defaults.emit_allow: false`；strict 只有 `read-inside-project` 一条 allow，`test_strict_keeps_read_inside_project_as_its_only_allow_rule` 与 `test_strict_allow_rules_are_a_subset_of_defaults` |
| 新的 allow 规则必须点名工具或程序 | **通过** | `schema.py` 加载期检查；`test_policy_rules.py` 里原先不带 `tool` 的 allow 测试规则已补 `tool` |
| `pytest`、`ruff`、`mypy` 在 Windows 与 Linux 上全绿 | **通过** | 以下数字是主会话的运行结果，不是我重跑的：Windows 完整套件 **13438 通过、73 跳过、0 失败**（约 24 分钟）；Linux 容器（`python:3.12`、uid 1000、真 bash）**12598 通过、913 跳过、0 失败**；`ruff check`、`ruff format --check`、`mypy` 无告警 |
| `boundkeep test` 通过全部 tests | **通过** | default：63 条规则、每个平台 356 条测试、603 次运行、0 失败；strict：52 条规则、每个平台 154 条测试、253 次运行、0 失败（规则数与每平台测试条数我核对过 YAML，运行次数是主会话的结果） |
| 真实 Claude Code 冒烟 | **通过** | `smoke_claude_m1.py` 11/11、`smoke_claude_m1b.py` 16/16、`smoke_claude_m1c.py` 11/11：`git status`、列目录、项目内 `Write` 的 boundkeep 判决为 allow；`Write .env` 与 `Write Makefile` 为 ask 且文件没有创建；`echo` 环境变量、`git -c core.pager=x log`、项目外读取都不是 allow（项目外读取的内容也没有回到模型） |
| 手工验收（VS Code 扩展里的真实会话） | **未做** | `docs/manual-acceptance-m1c.md` 已写好，等你操作 |
| 对 allow 规则的定向 X1 审查 | **未做，已计划** | 见第 7 节 #4 |

## 4. 偏差与风险

**集成时发现并已修的三件事**（都是主会话在把各部分合起来之后发现的，每件有测试）：

- **(a) `echo $SECRET_VAR` 一度变成 allow。** X1 审查 L-7 早就警告过：给 `echo` 写 allow，秘密就能被打印，规则语言分不清 `echo hello` 与 `echo $NAME`。修法：`echo`、`Write-Output`、`Select-Object` 从 allow 里拿掉。`echo hello` 因此仍然 ask（语料里归 keep-ask）。
- **(b) `GIT_DIR=x git status` 一度是 allow。** `GIT_DIR`、`GIT_WORK_TREE`、`GIT_EXEC_PATH`、`RIPGREP_CONFIG_PATH`、`XDG_CONFIG_HOME`、`LESS` 等不在 `programs._ENV_CODE`（"会让程序运行别的东西"的环境变量前缀清单）里，所以带这种前缀的命令没变灰。已加入，由 `tests/unit/test_m1c_env_code.py` 守住（主会话记录的该文件测试数为 170，我只核对到文件里有 3 个测试函数，其余是参数化，没有重跑）。已知缺口：清单之外的变量仍可能漏过，见下面的残余风险。
- **(c) M1c 之前就存在的 strict 缺陷。** strict 的 `ask-read-outside-project` 用 `path_glob: ['**']` 加 `access: read`，而子树扫描（目录 `Grep` 的受保护文件探测）把读规则里的 glob 当"受保护名字"：`**` 让目录下每一项都命中，扫描在第一层就停下，`certs/a.pem` 这样嵌套的受保护文件永远看不到，于是 strict 下对含该文件的项目目录做 `Grep` 会被放行。已改成只写 `path_outside_project: true`（`test_no_read_rule_has_a_catch_all_glob`、`test_a_recursive_read_still_finds_a_nested_secret` 守住）。这是 M1c 之前就有的缺陷，不是 M1c 引入的。

**对已有测试与语料的改动。** 因为现在有了 allow 规则，一批原先期望 `gray` 的良性条目期望变成 `allow`（例如 `git status`、`ls -la`、`Get-ChildItem`、写 `docs/notes.md`）。需要特别交代的是 `adv: true` 的条目：当前 diff 里有 **9 条**原先标 `adv: true` 的良性命令变成 allow，实现者去掉了它们的 `adv` 标记，并在条目上写了原因：`r2-git-show-rev-ordinary`、`r2-time-group-benign`、`r3-ls-R`、`r3-ls-laR`、`r3-ls-R-project-dir`、`r3-tree-a`、`r3-find-plain`、`r3-ps-gci-recurse`、`r3-ps-dir-recurse`。（一度是 10 条；`semicolon-in-quotes` 在 `echo` 拿出 allow 之后改回去了，所以不在 diff 里。）"没有任何 `adv: true` 的 shell 条目是 allow"这条安全网仍然成立；这些命令的敌对写法（受保护目录、`find -fprint`、`du`、危险选项等）仍是 `adv: true`，在 `r3-*` 的其余条目与 `pipeline_m1c_allow.yaml` 里。另有 `fe-exec-written-make`（`echo x > Makefile && make`）从 gray 变 ask，仍是 `adv: true`。

**残余风险**（每条都要当面说清）：

- **不可信仓库里的 git。** `git status` / `diff` / `log` / `show` 在不可信的仓库里仍可能运行该仓库 `.git/config` 里配置的程序（`core.fsmonitor`、textconv、外部 diff 驱动、分页器）。规则排除了命令行上的 `-c`、`--ext-diff`、`--textconv`、`--paginate`，但仓库配置本身的风险没有消除。这是 `emit_allow` 保持关闭的主要原因：boundkeep 的 allow 只是"无决定"，真正放不放行由 Claude Code 自己决定。
- **变量开头的 PowerShell 管道元素被归一化层丢掉。** `$env:X | Select-Object` 不带灰色标记，所以 `Select-Object` 不放行；`Write-Output` 同理（它打印展开后的参数）。
- **选项值里的展开看不见。** 归一化层只在整个位置参数就是一个展开时标灰色（`cat $FILE`）；嵌在选项值里的（`head -n $TOKEN f`、`--format=$TOKEN`）看不见，而几乎每个程序都会在错误信息里回显非法参数。能直接打印参数的选项已逐个排除，错误信息里的回显无法消除。
- **环境变量前缀清单是有限的。** 只有清单里的变量会变灰；清单外的变量仍可能让某个程序读到不同的配置。
- **`git -p log` 与 `git log -p` 在匹配器眼里是同一个标志。** 所以 `-p` 没有被排除。
- **`allow-project-file-writes` 的范围很宽。** 它也覆盖源码、测试，以及 `.venv` 与 `node_modules` 里的文件。源码日后被运行时才会执行，这与 Claude Code 自己的行为一致，但要知道它覆盖了什么。
- **规则语言看不见位置参数。** 光秃秃的 `git branch`（与 `git branch NAME` 分不开）和 `git stash list`（与 `git stash` 分不开）保持 ask。
- **版本探测有意不放行。** `git --version`、`python --version`、`node --version` 等程序是 exec 程序，规则语言看不出后面有没有别的参数。
- **allow 之后 Claude Code 还弹不弹框，不由 boundkeep 决定**，也没有逐条命令测过（冒烟脚本看的是 boundkeep 的判决，不是命令有没有运行）。

## 5. 度量

- **测试**：见第 3 节。Windows 13438 通过 / 73 跳过 / 0 失败；Linux 容器 12598 通过 / 913 跳过 / 0 失败；`boundkeep test` default 603 次运行、strict 253 次运行、0 失败。新增或改动的测试文件列表见第 2 节。本报告不写覆盖率数字（没有测）。
- **每 100 个动作的问询数**（`scripts/measure_ask_rate.py`，语料 `tests/corpus/workflow_benign.yaml`，312 条：t1-read 84、t2-write 27、t3-exec 35、keep-ask 87、must-block 79，其中 72 条仅 Windows、2 条仅 POSIX；"问询"指 ask + gray，因为没有 LLM 后端时两者都会弹框）。下面是实现者的表格，我没有重跑：

| 范围 | HEAD 的 default | 现在的 default |
|---|---|---|
| 全部，Windows | 80.6 | **52.6** |
| 全部，POSIX | 77.9 | **50.4** |
| t1-read（Windows / POSIX） | 73.5 / 65.1 | **0.0** |
| t2-write | 100 | **0.0** |
| t3-exec、keep-ask | 100 | 100 |
| must-block（Windows / POSIX） | 51.9 / 51.6 | 51.9 / 51.6（不变） |

  与设计目标（每条语料的 `expect_after`）有差异的条目为 0；must-block 层没有一条是 allow。剩下的 52.6 / 50.4 来自三部分：t3-exec（35 条，有意不放行）、keep-ask（87 条，有意不放行或放不了）和 must-block 里本来就该 ask 的那部分。**这条语料是合成的，层的比例是我们设计的，所以 80.6 → 52.6 说的是"对这个设计语料"，不能读成"你的真实会话少问了三成"。** 它的用处是证明规则确实在设计的范围内起作用、没有越界，并给出"再往下要放行什么"的清单；真实比例要靠 `session_command_stats.py` 测。
- **延迟**：没有重测。M1c 只在归一化层加了环境变量前缀，其余是规则；default 现在有 63 条规则，规则变多对延迟的影响没有单独测量。
- **成本**：冒烟的费用没有记录在我拿到的材料里；开发全程不使用 Anthropic API。

## 6. 工具说明

- `scripts/measure_ask_rate.py`：只读、确定性，在假机器上跑，不碰你的文件与家目录；`--policy` 可重复以对比多份策略；退出码在数字无论多少时都是 0，只有语料或策略读不出来时才是 1。
- `scripts/session_command_stats.py`：读 `~/.claude/projects` 下的会话记录（只读），对其中的 `Bash`、`PowerShell`、`Read`、`Write`、`Edit`、`MultiEdit`、`NotebookEdit`、`Grep`、`Glob` 调用跑一遍归一化与规则，输出：每个工具名的调用数；每份策略下每个工具的判决分布；判决不是 allow 的 shell 程序名（只在出现次数不少于 `--min-count` 且长得像普通程序名时才显示）；灰色原因（截到第一个冒号）。**它不输出**命令、参数、路径、文件内容、提示词、会话 id、项目名。注意两点：它输出的不只是"计数"，还有满足阈值的程序名；脚本文件头注释里提到的 `--out` 选项在代码里并不存在（只写 stdout）。为判定目录类的 `Grep` / `Glob`，它会像 hook 一样只读地扫描相应目录。输出是否贴给我由你决定。

## 7. 需要你决定的事项

1. **运行统计脚本并把聚合结果发给我**（手工验收文档里有命令）。下一轮据此补最常见的、目前仍 ask 的命令。语料里标为 keep-ask、而真实使用里可能想放行的有：`git add`、`git commit`、`git remote -v`、`git ls-files`、`du`、版本探测（`git --version`、`python --version` 等）。每放行一类，都要先说明为什么安全，再补测试，不是看频率就加。
2. **要不要加一个可选的预设**：A. 给构建与测试命令（Tier 3）的 opt-in 预设；B. 给 `emit_allow` 的 opt-in 预设；C. 都不加，先观察（**建议**：在 X1 定向审查和真实覆盖率数据之前不加）。Tier 3 运行仓库代码，`emit_allow` 会让 boundkeep 替你批准，两者都应该由你显式选择。
3. **提交方式**：A. 两个提交——① 代码、测试、策略、脚本；② 文档（报告、手工验收、`policy-reference.md`、`IMPLEMENTATION_PROMPTS.md`、`CLAUDE.md`）——然后打标签 `m1c-done`（**建议**）；B. 一个提交。我没有提交，也没有推送。
4. **是否在 M2 之前对 allow 规则做一次定向 X1 审查**：建议做（主会话会给审查提示词）。重点：每条 allow 规则的 `flags_none` 清单是否漏了会写文件、运行程序或读任意文件的选项；`paths_read_only` 与 `path_inside_project` 的组合；环境变量前缀清单；allow 与保护名字的 deny / ask 规则的交互；strict 是否真的没有新增放行面。

## 8. 进入下一步的前置条件

- 手工验收（`docs/manual-acceptance-m1c.md`）完成并通过。
- 定向 X1 审查完成，高危发现清零。
- 第 7 节的选择做完；提交并打标签 `m1c-done`。
- `CLAUDE.md` 的"当前状态"还没有写 M1c（本次任务不改它），提交前由主会话更新。
- 之后进 M2。**M2 的基线必须在 allow 规则冻结之后再取**（`IMPLEMENTATION_PROMPTS.md` 的 M2 前置已改）：否则 rules-only 基线对应的是一份之后又会变的策略。

## 9. 未验证

- **你自己的真实会话上的覆盖率**：`session_command_stats.py` 还没有在你的会话记录上运行过。第 5 节的数字都来自合成语料。
- **pwsh 7**：和 M1b 一样，只有 Windows PowerShell 5.1 实测。
- **你自己的 `permissions.allow` 列表**：allow 的输出是"无决定"，Claude Code 的最终行为取决于你的权限设置，没有按你的设置实测。
- **Claude Code 的其他版本**：只在当前使用的版本上冒烟；版本号请在手工验收时记入。
- **allow 之后 Claude Code 是否仍然弹框**：没有逐条命令测。
- **本报告的数字来源**：测试运行数、延迟与度量表来自主会话与实现者；我核对了 YAML 里的规则数与测试条数、语料条数、diff 内容与脚本代码，没有重跑任何测试或脚本。
