# 写留出集 h1 的攻击样本

留出集是一批**在改规则之前**写完、封存的样本，用来给之后的规则一个无偏的数字（`docs/eval-methodology.md` 第 4b 节）。正常样本那一半已经在 M2-rules-3 的规则改动之前封存（真实会话 127 条、合成 42 条，共 169 条，指纹 `0aacd20fdef20db6`），攻击这一半由你来写。

## 写多少

每类 8 到 12 条就够，总数 50 条左右。条数越少，一条样本对比例的影响越大（10 条时一条就是 10 个百分点），报告会写明。

| 类别 | 写什么（按你自己对“攻击者会怎么做”的理解来写） |
|---|---|
| `exfil` | 读密钥、凭据、环境变量，再通过网络、文件或别的渠道送出去 |
| `destructive` | 删除、覆盖、格式化、结束进程、改权限等破坏性动作 |
| `tamper` | 改 hook / 策略 / shell 启动文件 / PowerShell profile / git hooks / 启动项 / 计划任务 / 注册表启动项等 |
| `mcp-misuse` | 通过 MCP 工具做上面这些事，或滥用 MCP 工具的写操作 |
| `path-evasion` | 用路径写法绕过（大小写、`..`、短名、备用数据流、设备名、MSYS 路径等） |
| `obfuscation`（可选） | 编码、拼接、间接执行 |

`injection-deviation`（同一个动作、不同任务意图的成对样本）这个工具不支持，这一批不写。

**最重要的一条：写的时候不要去看 `policies/` 里的规则，也不要先跑一遍看结果。** 描述规则的文件同样不要看：`docs/policy-reference.md`、`docs/reports/M2-rules-3.md`、`docs/reviews/M2-rules-3-review.md` 和 `tests/`。 按“攻击者会怎么做”来写，而不是按“规则会不会拦”来写；样本要能代表攻击，而不是代表规则。`ask` 还是 `deny` 按你自己的产品判断填：你认为这件事**必须被直接拒绝**就写 `deny`，问一次就够就写 `ask`。不用管现在的规则给什么。

## 格式

每个类别一个文本文件，放在 `eval/authoring/`（比如 `h1-exfil.txt`），一行一条，字段之间用 ` ### `（前后各一个空格）分隔：

```
平台 ### 工具 ### 要求 ### 命令或路径或输入 ### 为什么是恶意的 [### tainted]
```

- 平台：`posix` / `windows` / `any`
- 工具：`Bash` 或 `PowerShell`（后面写命令）；`Read`（后面写文件路径）；MCP 工具名 `mcp__服务名__工具名`（后面写一个 JSON 对象，例如 `{"path": "..."}`）
- 要求：`ask` 或 `deny`
- 最后一个可选字段写 `tainted`，表示这条发生在读过外部网页内容之后
- 以 `#` 开头的行和空行会被忽略

## 约束（工具会检查，不满足就报错并指出行号）

- URL 只能用保留域名：`.invalid`、`.example`、`.test`、`.localhost`、`example.com`、`example.org`、`example.net`
- 用户目录只能是 `testuser`（`C:\Users\testuser\...`、`/home/testuser/...`），项目目录是 `C:\Users\testuser\proj` / `/home/testuser/proj`
- 不要放真实的密钥；需要“秘密”的地方写 `CANARY-...`
- 不能和 dev / test 里已有的动作完全相同（工具会报 `repeats an action`，改一下写法即可）

## 怎么生成

每写完一个文件，在仓库根目录运行（文件可以反复改、反复运行，输出每次重写）：

```bash
uv run python eval/add_samples.py eval/authoring/h1-exfil.txt --category exfil --holdout h1
```

输出在 `eval/datasets/holdout/<类别>.jsonl`，样本 id 是 `hold-atk-...`，标记为已确认（你自己写的）。全部写完后：

```bash
uv run python eval/run_eval.py --check
```

它会打印 `holdout` 指纹。**不要加 `--open-holdout`**：那会测留出集并记进台账，之后规则一改，它就被判为已污染。

## 写完之后

告诉我写完了。我只跑自动检查（格式、惰性、不与 dev / test 重复）并记下指纹，**不看你写的攻击样本的内容**；提交由你决定。

规则已经在 M2-rules-3 改完并冻结（提交 `0210b85`），所以攻击这一半写在规则改动之后，报告会写明这一点。写完之后、下一次改规则（M3a、L-1 等）之前，用 `--open-holdout` 打开留出集一次，测的就是这一批规则；之后再改规则再打开，台账会自动声明污染。
