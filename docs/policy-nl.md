# 用一句话加规则：`boundkeep policy`（M4）

> 状态：2026-11-26，规格修订 44（`PROJECT_SPEC.md` §8.1）。在线模式（`policy add`）只对本地假服务和假后端测过，**没有接过任何真实 LLM 服务**；离线模式（`policy prompt` 加 `policy check`）不联网，可以照常使用。

你用一句话说想要什么规则（"不许 agent 运行 curl"、"写 migrations 目录之前问我"），boundkeep 把它变成一份**提议**：新增的规则，加上每条规则的测试用例。提议先由代码检查，再在历史调用上回放影响。全部显示给你之后，要你在自己的终端里输入 `yes`，才写进策略文件。

- 提议只能**新增**规则和测试。改或删已有规则、改设置（`mode`、`defaults.emit_allow`、`trusted_projects`、`mcp_read_only`、`taint`、`llm_audit`），都请自己编辑策略文件，或者用对应的命令。唯一会改动已有内容的情况：某条已有测试的判决被新规则变严了（比如默认策略里原来期望"灰色"的 `curl …`，加了"禁止 curl"之后变成 deny），这时改写它的 `expect`。这些改写都列在输出里，并给出警告 `existing-tests-changed`。
- 规则按最严者胜合并（deny > ask > allow），所以新加的 allow 盖不过已有的 deny 或 ask。比如"允许读 `.env.example`"会被 `no-secret-read` 盖住，检查结果里会说明这一点（`shadowed`）。要放宽已有规则，只能自己编辑。
- 这些命令只由你在自己的终端里运行。默认策略拒绝 agent 运行 `boundkeep policy` 的任何形式，因为回放会把审计日志里其他会话的命令打印出来，在线模式会花钱。命令本身也会检查：每个子命令在 Claude Code 启动的进程里（设置了 `CLAUDECODE` 或 `CLAUDE_CODE_ENTRYPOINT`）都拒绝运行；写入（`check --apply`、`add`、`undo`）还要真实控制台，和 `trust add` 一样。VS Code 里从 Claude Code 之外打开的终端可以正常使用。

## 两种模式

### 离线：不需要任何后端

```
boundkeep policy prompt "写 migrations 目录之前问我"
```

这条命令输出一段提示词：系统提示词（字段说明、JSON Schema、例子），你的那句话，以及当前策略的规则 id。在线模式发给后端的也是这一份。把它粘贴给你自己选的任何 LLM 工具（对话产品、你自己的 Claude Code 会话等），把回答里的 YAML 存成文件（带着 ```yaml 代码块也可以），然后运行：

```
boundkeep policy check proposal.yaml            # 只检查、只显示
boundkeep policy check proposal.yaml --apply    # 检查通过后问你，输入 yes 才写入
```

`--out FILE` 把提示词写进一个新文件，不打印。boundkeep 不会自动调用任何工具来完成离线提议（订阅登录凭证、`claude -p` 都不用），`prompt` 和 `check` 不联网。

### 在线：用已配置的后端

```
boundkeep policy add "never run terraform destroy"
boundkeep policy add "..." --dry-run --out proposal.yaml   # 只检查，并把提议存下来
```

前提是策略的 `llm_audit` 配置了后端（`docs/llm-backends.md`），密钥在 `BOUNDKEEP_LLM_API_KEY`；`backend: none` 时这条命令会提示改用离线模式。

- **发送的内容**：只有你那句话（不超过 2000 字，主目录写成 `~`）和当前策略的规则 id 列表。不发策略的其他内容，不发任何文件内容。那句话里有看起来像秘密的文字时（令牌、密钥），什么都不发，请你去掉之后再试。
- 发送之前，命令会显示发往哪个主机、哪个模型，以及要发的文字。
- 预算默认 60 秒（`--timeout`，5 到 300 秒），至多重试一次，不缓存。失败时只报失败类别，什么也不写。
- 一次请求的费用按你的服务商的价格计算。boundkeep 不在文档里写价格。

## 检查结果怎么读

输出依次是：
1. 提议者自己的说明（`summary`、`impact`），标着"未核实"；
2. 要加进策略文件的规则和测试，原样显示；
3. 测试的运行结果；
4. 金丝雀的判断次数；
5. 回放；
6. 全部结论，分 `REFUSED`、`WARNING`、`note` 三级。

有一条 `REFUSED` 就不能写入；只有警告时照常可以写入，确认时会提醒你有几条警告。

| 级别 | 代码 | 意思 |
|---|---|---|
| 拒绝 | `parse` / `secret` | 格式不对，或者含形似密钥的字符串（测试输入里也算） |
| 拒绝 | `merge` | 规则 id 与已有的重复，或者加入之后策略加载失败 |
| 拒绝 | `allow-shell-any` | allow 规则作用于 Bash / PowerShell，却没写 `program` |
| 拒绝 | `allow-runs-code` | allow 规则放行会运行任意代码的程序：shell、任何写法的解释器（`python`、`py`、`python3.12`、`pythonw`、`node`……）、包装器（`sudo`、`env`、`nice`……）、`Invoke-Expression`、`Start-Process`，以及 boundkeep 的解析器不认识的程序（把程序名交给解析器判断）。构建、测试与包管理工具只给警告 |
| 拒绝 | `allow-outside-project` | allow 规则带 `path_outside_project`；或者带 `path_glob`、或作用于文件工具（`Read`、`Write`、`Edit`、`Grep`、`Glob`……），却没有 `path_inside_project: true`（或会话自己的目录） |
| 拒绝 | `allow-network` | allow 规则联网（`network`、`WebFetch`、`WebSearch`，或解析器判为联网的程序，如 `curl`），却没有 `domain_in` |
| 拒绝 | `canary` | 一个内置的"永远不该被自动放行"的动作（读密钥、写钩子配置、项目外的读写、管道进 shell、外传到未知主机……）被这份提议放行了 |
| 拒绝 | `tests-fail` | 原有测试因提议而失败，但不是"变严"（比如原来期望灰色、现在被新 allow 放行：`expect: gray` 正是防止规则过宽的；或者两台假机器上结果不同）；也包括新规则决定判决的测试与它的 `expect` 不符 |
| 拒绝 | `tests-few` | 某条新规则命中的测试少于 3 条，或者不命中的（相似但不该命中）少于 3 条 |
| 警告 | `shadowed` | 新规则被更严的已有规则盖住，在它的测试上改变不了判决 |
| 警告 | `no-change` | 新规则命中的测试，在原策略下判决已经一样 |
| 警告 | `conflict` | 两条新规则在同一个测试上给出不同的动作 |
| 警告 | `existing-tests-changed` | 有已有测试的判决被新规则变严，要改写它们的 `expect`（给出条数与样例；条数多说明规则可能过宽） |
| 警告 | `allow-repo-code` | allow 规则放行会运行仓库代码的程序（`make`、`npm`、`pytest`、`cargo`……），只应信任自己写过或审计过的仓库 |
| 警告 | `replay-malicious-allowed` | 回放里有标为恶意的评测样本被新放行 |
| 警告 | `replay-broad` | 回放里超过 10% 的正常调用被新拦下 |
| 注明 | `test-expect` | 一条新测试的判决由已有规则决定，提议者猜错了：按实际判决写入 |
| 注明 | `tests-already-failing` | 原策略里有测试在加入提议之前就失败 |

测试在 `boundkeep test` 用的两台假机器上跑（Windows：`C:\Users\testuser`，POSIX：`/home/testuser`）。没有 PowerShell 解析器的主机上，PowerShell 测试和金丝雀会跳过，输出里写明，不算通过；跳过的测试不计入"每条规则 3 条命中、3 条不命中"。

## 回放

新、旧两版策略在同样的条件下判同一批调用，所以显示出来的差异只来自这份提议：

- **评测集的 dev 切分**：只在 boundkeep 的源码仓库里有，装好的包里没有，这时会写明跳过。只读 `eval/datasets/attacks/` 与 `benign/`，只取标签经过确认的 dev 样本；从不读留出集，也不用 test 切分。样例只显示样本 id、标签、类别与判决变化，不显示内容。`--dataset DIR` 指定别的目录。
- **审计日志**：最近 1000 条 PreToolUse 记录里的 shell 调用（`--log-limit N` 改条数，`0` 跳过）。日志不记文件工具的路径，也不记项目目录，所以有两点近似：
  - 文件工具的调用，以及被截短或没有命令的记录，算"无法回放"，并给出条数；
  - 记录里的 `cwd` 当作项目目录，按新会话判，不看磁盘。

## 写入、备份与撤销

- 写入只在策略文件末尾的列表里追加：新规则接在 `rules:` 的最后一项之后，新测试接在 `tests:` 的最后一项之后，各带一行注释（时间、来源）。被新规则变严的已有测试，只把 `expect` 的值原地换掉。原文件的注释和格式不变。写好之后用真实的加载器读一遍，结果必须正好是"原有的（这些 `expect` 换过）加上新的"，不然不写。
- 规则语言只对一部分程序报"子命令"（`git`、`docker`、`npm`、`pip`、`cargo`、`systemctl` 等，PowerShell 里另有 `net`、`reg`、`sc.exe` 等；完整名单在提示词里）。`terraform apply`、`kubectl delete`、`make lint` 这种写法永远命中不了，检查会以 `tests-few`（命中 0 条）拒绝它。这时只能对整个程序写规则。
- 写入之前，原文件复制到 `~/.boundkeep/policy-history/`（只有你能读，保留最近 20 份），然后原子替换。记录写进那里的 `index.jsonl`，审计日志另记一条 `event: policy`。正在运行的守护进程在下一个事件时读到新策略。
- `boundkeep policy undo` 回到最近一次没有撤销过的写入之前，与当时的文件逐字节相同。如果之后你又手改过文件，它会先告诉你这些改动会一起丢掉（改过的文件也会存进历史）。连续 `undo` 一次次往回退。
- `boundkeep policy history` 列出写入与撤销的记录。

## 已知局限

- 在线模式没有接过真实的 LLM 服务，模型写出的提议质量没有测过。`eval/policy-compile-report.md` 里的数字来自手写的假后端回答，只说明检查流程怎么对待这些回答。用真实后端跑一次基准：`uv run python eval/run_policy_bench.py --backend configured --confirm`，用你的密钥，费用由你承担。
- 金丝雀是一份有限的名单，不是证明：一条很窄的 allow（例如只放行 `~/dev/shared/**` 的读）不会碰到它们。放宽方向的安全主要靠三点：只能新增规则、最严者胜、allow 规则的语法限制。
- 回放是近似（见上）。
- 2026-11-26 之前安装的策略文件里，`deny-boundkeep-state-commands` 还没有 `policy` 这个子命令，这时 agent 的 `boundkeep policy …` 调用不会被策略拒绝，只靠命令自己在 Claude Code 的进程里拒绝运行（agent 能清掉那两个环境变量，所以这一道可以绕过）。用 `boundkeep init --reset-policy` 换成新的默认策略，或者自己把 `policy` 加进那条规则的 `subcommand` 列表。
