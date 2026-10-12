# 架构（M0 通路与降级；M1 判定管线）

> 状态：M0 实现于 2026-10-08，M1 的判定管线随后接入（§6）。通路、降级、IPC 与客户端不变量（§1 到 §5、§7、§8）是 M0 的结论；§6 描述 M1 的常驻进程：normalize、规则、取最严，判定在事件循环之外的线程里、带期限地运行。M1 之后 PowerShell 命令仍不被解析（M1b 才做），每一条都落到 `ask`，文档与 README 不得暗示 PowerShell 已被规则审查。
> 事实来源是 `PROJECT_SPEC.md`；与 Claude Code 行为有关的结论以 `hook-behavior.md`（带版本的实测）为准。

## 1. 通路

```
Claude Code ──(每个 hook 事件起一个新进程，事件 JSON 走 stdin)──> hook_client.py ──> hook_main.py
                                                                          │ 本机 IPC：一行 JSON 去，一行 JSON 回
                                                                          ▼
                              Windows：命名管道（ctypes，显式 DACL）      boundkeep serve（常驻）
                              POSIX：Unix 套接字（0600，目录 0700）          │ pipeline.decide → Decision
                                                                          ▼
                                                              logs/audit.jsonl（脱敏、截断、轮转）
```

一次 PreToolUse 的过程：

1. Claude Code 按 settings 里的 exec 形式启动 `python.exe -I -S …\hook_client.py pre`，把事件 JSON（UTF-8 字节）写进 stdin。
2. `hook_client.py` 只做三件事：记下进程起点、把包根目录放进 `sys.path`（`-I -S` 下既没有脚本目录也没有 site-packages）、调用 `hook_main.entry`。逻辑放在 `hook_main.py` 是因为主脚本每次启动都要从源码编译，被导入的模块走缓存字节码。
3. `hook_main` 按字节读 stdin，解析事件，读 `endpoint.json`，经 `ipc/client.py` 发一行请求，等一行应答，渲染成 Claude Code 的 hook 输出，写 stdout，`os._exit`。
4. 常驻进程解码请求，必要时重读策略文件，`pipeline.decide`（M1：normalize → 规则 → 取最严）在工作线程里给出判定，写一条审计记录，回应答。

## 2. 模块

| 模块 | 职责 |
|---|---|
| `hook_client.py` / `hook_main.py` | hook 客户端：只用标准库；按字节 I/O；总预算；降级；`config` 子命令（ConfigChange 的本地检查） |
| `protocol.py` | 线路格式、常量、严格的编解码（客户端与常驻进程共用，只用标准库） |
| `ownhook.py` | 在 settings 里识别 boundkeep 自己的 hook 条目、`disableAllHooks` 的保守判断（客户端与安装器共用） |
| `paths.py` | boundkeep 自己的文件放哪（`BOUNDKEEP_HOME` 可改，测试一律用临时目录） |
| `ipc/endpoint.py`、`ipc/client.py` | 端点描述（`endpoint.json`）与客户端（连接、退避重试、期限） |
| `ipc/named_pipe.py`、`ipc/winsec.py` | Windows 服务端（ctypes、重叠 I/O）与 ACL/SDDL 辅助 |
| `ipc/unix.py` | POSIX 服务端（只在 Linux 容器里测过，没有宿主验证，见 §9） |
| `ipc/base.py` | 服务端抽象与工厂 |
| `daemon/server.py`、`daemon/pipeline.py`、`daemon/lifecycle.py` | 常驻进程（请求处理、判定线程池与期限、策略热加载、审计记录）、判定管线（M1）、单实例锁与停止信号 |
| `policy/` | M0 的最小策略（`version`、`mode`、`defaults.emit_allow`、`taint.sources`），严格校验 |
| `redact.py`、`logstore.py`、`fsperm.py` | 脱敏、JSONL 审计日志、目录与文件的私有性检查 |
| `settings_io.py`、`install.py`、`claude_settings.py` | 读写 Claude Code 的 settings、合并与移除 hook 条目、自检、清单 |
| `hookcmd.py` | 选择并校验 hook 要启动的解释器 |
| `cli.py`、`doctor.py`、`console.py` | 命令行、检查、UTF-8 安全的控制台输出 |

## 3. 协议

一行请求、一行应答，UTF-8，换行结尾；请求 ≤ 8 MiB，应答 ≤ 64 KiB，理由 ≤ 2000 字符。

```
请求  {"v":1,"id":"<16 位十六进制>","event":"pre|post|prompt|config|ping","payload":{…Claude Code 的事件…}}
应答  {"v":1,"id":"…","ok":true,"decision":"deny|ask|none","reason":"…"}
      {"v":1,"id":"…","ok":false,"error":"bad_request|too_large|timeout|internal|…","detail":"…"}
```

- `decision` 是抽象的：**Claude Code 的输出格式只由客户端生成**（`json.dumps(ensure_ascii=True)`），所以"stdout 总是合法的纯 ASCII JSON 或为空"只需要在一处保证。
- `none` 表示"无决定"：退出 0、什么都不输出，调用交还给 Claude Code 原有的权限流程。M0 从不返回 `allow`（`emit_allow` 默认关闭，M0 也没有实现开启）。
- 协议层的错误（过大、超时、处理器异常）用占位 id `-` 回应；客户端据此按降级处理。
- `ping` 只用于 `boundkeep doctor`：有应答、不写日志、不经过判定线程池（判定卡住时 ping 照样即时应答）。应答的 `reason` 是状态文本：`mode=…; requests=N; timeouts=N; stuck=N; config_dir=<路径或 ->`，策略不可用时再加 `; policy error: …`。`timeouts` 是迄今因超过期限而被放弃的判定数，`stuck` 是此刻仍在运行的被放弃的工作线程数，`config_dir` 是常驻进程自己环境里的 `CLAUDE_CONFIG_DIR`（`doctor` 拿它与自己的环境比对，见 §6）。
- 任何不符合的请求或应答都是 `ProtocolError`；协议改动必须升版本号。

## 4. 本机 IPC

- **端点**：`init` 生成并写入 `<home>/endpoint.json`（原子写）。Windows 的管道名是 `\\.\pipe\boundkeep-<32 位随机令牌>`，令牌防止别的进程抢先创建同名管道。
- **Windows 服务端**（`ipc/named_pipe.py`）：用 ctypes 调 `CreateNamedPipeW`。
  - DACL 只授予当前用户（`SecurityDescriptor.private()`）；`PIPE_REJECT_REMOTE_CLIENTS`；第一个实例带 `FILE_FLAG_FIRST_PIPE_INSTANCE`，名字被占用时启动失败（`AddressInUse`）。
  - 预建 8 个实例，每个实例一个线程，全部重叠 I/O 加期限：连上后 1 秒内一个字节都不写的客户端被放弃（hook 客户端连上就写），已开始的请求总共 5 秒；应答写完后最多再等 0.5 秒让客户端读完，再回收实例。同用户的恶意进程仍可用大量连接拖慢服务（实测：8 个沉默连接把一次真实请求延迟约 1 秒），这是已知局限，不是防线。
  - 请求交给常驻进程的 asyncio 事件循环处理；关闭服务端时不会因为等待事件循环而死锁。
  - 不用 asyncio 自带的管道服务端：它创建管道时传空安全属性，Everyone 与匿名账户可读（M0a E10 实测）。
- **客户端**（`ipc/client.py`）：管道不存在、被拒绝、连接过早关闭都是 `DaemonUnavailable`，立即降级；其余 `OSError`（M0a 实测的"管道忙"，errno 22）在预算内指数退避重试。
- **POSIX**（`ipc/unix.py`）：asyncio 的 Unix 套接字服务；目录 0700 且属于当前用户，套接字 0600；残留的套接字文件（没人监听）会被清理，仍在应答的则拒绝启动。**在 Linux 容器里的自动测试全部通过，但没有在真实宿主里验证过**（见 §9）。

## 5. hook 客户端的不变量与降级

不变量，各自对应一种"静默放行"（证据见 `hook-behavior.md` E6、E18、E22）：

- 按字节读写：stdin 读字节、显式 UTF-8 解码；stdout 写字节，只含 ASCII。文本模式的 stdin 在代码页 936 下不会崩溃，而是把中文**悄悄读成乱码**（E18，2026-10-07 更正），规则会因此匹配落空。
- 退出码只有 0 或 2；最外层捕获 `BaseException`；stdout 写不出去时退出 2（宁可阻断也不静默）。
- 总预算从进程起点算，覆盖读 stdin 与 IPC：`pre` 10 秒，`prompt`、`post`、`config` 各 5 秒，小于 `init` 写进 settings 的 `timeout`（15、10、10、10 秒）。环境变量 `BOUNDKEEP_HOOK_BUDGET_S` 只能把预算调小（测试用）。
- 事件类型以事件里的 `hook_event_name` 为准，命令行参数只作交叉检查；缺参数或不一致就降级。注册过的子命令收到不认识的事件名（改名、拼写、多一个空格）也降级，不静默放行。
- 入口脚本 `hook_client.py` 自己也有兜底：`import boundkeep` 失败（升级到一半、缓存文件损坏）或 `entry()` 抛出任何东西，都按同一张降级表回答（pre 输出 ask，config 退出 2），不会以退出码 1 退出（Claude Code 把 1 当作"没有决定"，工具照常执行）。入口脚本本身有语法错误时仍会退出 1，这一点无法兜住。

降级表（每一行都有测试）：

| 情形 | PreToolUse | PostToolUse、UserPromptSubmit | ConfigChange |
|---|---|---|---|
| 常驻进程没起 / 端点文件缺失 | `ask` 并说明原因 | 无操作 | 本地判断，不需要它 |
| 管道忙到预算用尽、超时、应答非法、应答是错误 | `ask` | 无操作 | — |
| stdin 为空、非法 JSON、非 UTF-8、过大 | `ask` | 无操作 | 阻断（退出 2） |
| 命令行参数缺失或与事件不一致 | `ask` | 无操作 | 阻断 |
| 内部异常、总预算用尽 | `ask` | 无操作 | 阻断 |
| 事件不是我们注册的类型（例如 SessionStart），且命令行参数也不是我们的子命令 | 什么都不输出 | 什么都不输出 | — |
| 请求超过 8 MiB | `ask` | 无操作 | — |
| stdout 写不出去 | 退出 2 | 退出 2 | 退出 2 |

大事件：不裁剪 `command`（填充可以藏住尾部）；超过 256 KiB 的事件里，`Write` / `Edit` 的内容字段与 `tool_response` 只转发长度。

## 6. 常驻进程

- 一个请求一个判定；`handle` 从不抛异常，任何失败都是错误应答，客户端据此 `ask`。
- **M1 判定管线**（`daemon/pipeline.py`）：PreToolUse 的载荷经 `normalize_event` 变成一组 `Action`（shell 命令按简单命令拆开，其他工具各一个），策略规则逐个 Action 求值并取最严（deny > ask > 灰色 > allow）；没有规则能判定的是灰色，M3 之前没有 LLM 后端，灰色就是 `ask`。`allow` 只有 `defaults.emit_allow` 打开时才发给 Claude Code，默认是"无决定"。审计模式（`audit-only`）只记录与 `would_be`，不返回决定。PowerShell 命令在 M1b 之前整条灰色，即每条都 `ask`。非 PreToolUse 事件（post、prompt、config）管线立即回"无决定"。策略不可用（读不了、不合法、运行期规则加不上）时 PreToolUse 一律 `ask`，原因写进应答与审计记录。
- **判定在事件循环之外、带期限地运行**：PreToolUse 的整个判定（策略重读、normalize、规则）交给一个有界的守护线程池（默认 4 个线程，`Daemon(pool_size=…)`），用 `asyncio.wait` 等结果，期限默认 2.0 秒（`Daemon(decision_timeout_s=…)`；hook 客户端自己的 PreToolUse 预算是 10 秒）。原因：一条恶意构造的几 KB 命令（例如 `cd src && cd src && …` 的长链）可以让解析器算上十几秒，同步运行会卡死事件循环，连 ping 和其他请求都得不到应答（审查实测）。超过期限时：应答 `ask`，理由 `boundkeep: review took too long`，审计记录 `decision: ask`、`decided_by: timeout`，只记命令的长度（`command_chars`），不记命令正文，常驻进程继续服务。
- **被放弃的线程**：线程无法被杀死，超时后工作线程继续跑到自己结束。它被记为"卡住"，同时补一个新线程顶替它的位置（容量不减半）。卡住的线程数达到池大小时，新的 PreToolUse 请求不再起任何工作，立即应答 `ask`（`boundkeep: daemon busy`，`decided_by: busy`，同样只记长度），直到有线程返回为止；线程总数因此不超过池大小的两倍。排在队列里、还没开始的判定在超时时被取消，不会白跑。`ping` 与非 PreToolUse 事件不经过线程池，不会排在卡住的判定后面。线程池的线程是守护线程：停止（`serve` 的 stop）与进程退出都不等它们，不会被一个卡住的判定拖住（`ThreadPoolExecutor` 会在退出时 join 线程，所以没有用它）。
- **策略热加载**：每个请求检查策略文件的修改时间与大小，变了就重读（PreToolUse 在持锁的工作线程里重读；ping 与其他事件在事件循环上重读，只有文件真的变了时才有这点开销），所以 `boundkeep mode` 立即生效。策略不可用时 PreToolUse 一律 `ask`，直到修好；文件没变但上次读失败（编辑器或杀毒软件暂时占用）时，每秒最多重读一次，所以占用解除后自己恢复。重读的任何失败（包括 `PolicyError` 之外的异常，以及 `runtime_policy_checked` 报告的运行期规则问题）都记成策略错误，**绝不**让旧策略在"没有错误"的状态下继续生效；文件的 (mtime, size) 键只在新结果（策略或错误）存好之后才前移。
- **`CLAUDE_CONFIG_DIR`**：常驻进程从**自己的**环境读它，用来给那个目录里的 settings 与凭据加保护规则；Claude Code 的环境可能不同，而 hook 客户端只转发 `CLAUDE_PROJECT_DIR`。`doctor` 在自己的环境设了它时给 INFO（常驻进程必须以同样的值启动），并在 ping 状态里的 `config_dir` 与自己的环境不同时给 WARN。
- **失败也留痕**：处理请求时出现内部错误，除了返回错误应答，还会往审计日志写一条 `decision: error`、`decided_by: internal-error` 的记录。
- **输出不阻塞**：常驻进程的报告行经有界队列由单独线程写 stderr，满了就丢；没人读的 stderr 管道不会再把事件循环卡死。`console.out/err` 容忍没有 stdout/stderr（`pythonw.exe`）。
- **审计记录**：时间、事件 id、事件类型、判定与来源、模式、延迟（`latency_ms`：从收到请求行到判定出来，不含这条记录自己的写入；记录无法包含自己的写入时间，所以 `prev_audit_ms` 是**上一条**记录的写入耗时，处理器总耗时约为两者之和）、`session_id`、`agent_id`、`permission_mode`、工具名、`cwd`，shell 工具的命令，`prompt` 事件只记长度，`config` 事件记被改的文件与本地判断。不记提示词原文、文件内容、工具输出。
- **日志写入**：先脱敏，再把每个字符串截到 4096 字符，一次 `os.write`；写失败只记录并返回 `False`，从不改变判定；Windows 上轮转因文件被占用而失败时继续写旧文件，稍后重试，不丢事件。5 MiB 轮转，保留 5 份。**追加用只写句柄**：Windows 上只申请 `FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE`（POSIX 是 `O_WRONLY | O_APPEND`）。早先的实现为了偷看最后一个字节而申请了读权限，在 Windows Defender 实时扫描下每次打开要 20 到 80 毫秒（实测：带读权限 26 毫秒中位数，只写 0.35 毫秒）。"文件是否以换行结尾"改为内存里的状态：进程启动后的第一次追加、轮转之后、清空之后、写失败之后各用一次单独的读打开检查，其余时候信任它（我们写的每条记录都以换行结尾），所以崩溃留下的半行仍然不会吞掉下一条记录。追加本身在事件循环上做（不占判定线程）。
- **单实例**：文件锁（Windows `msvcrt.locking`，POSIX `flock`）加 pid 文件；再加管道的首实例标志。锁随进程消失，崩溃不会留下死锁。
- **停止**：Ctrl+C、Ctrl+Break（Windows）、SIGTERM 都会让它清理退出。

## 7. ConfigChange 的自我保护

`init` 同时注册 ConfigChange hook。它在 hook 客户端本地判断（不依赖常驻进程）并且**失败即关闭**：

- 变更后的 settings 文件读不了或不是合法 JSON → 阻断；
- `disableAllHooks` 取任何不是 `null` / `false` 的值 → 阻断；
- 对 `init` 记录过的文件（记录按"同一个文件"匹配：联接点、`\\?\` 前缀、8.3 短名、大小写都算同一个）：被删除，或 boundkeep 的任一条目被删、被指向别处、被加了 `if` 等额外字段、`timeout` 不在允许范围（PreToolUse 11 到 3600 秒，其余 6 到 3600 秒）、PreToolUse / UserPromptSubmit / ConfigChange 的 matcher 被设成非空（ConfigChange 的 matcher 匹配的是变更来源，设了就可能永远不触发）或不是字符串、PostToolUse 的 matcher 与 `init` 记录的不同 → 阻断；
- settings 的 `env` 块设置了 `BOUNDKEEP_*`、`USERPROFILE`、`HOME`、`HOMEDRIVE`、`HOMEPATH`、`APPDATA`、`LOCALAPPDATA`、`CLAUDE_CONFIG_DIR`、`CLAUDE_CODE_SIMPLE`、`CLAUDE_CODE_SAFE_MODE`（hook 客户端会因此找不到真的端点而去连别的东西，或 Claude Code 跳过 hook），或 `env` 不是对象 → 阻断；
- 文件里含 `NaN`、`Infinity`（JavaScript 的 `JSON.parse` 拒绝它们）→ 按"无法评估"阻断；
- 事件是设置类来源却没有 `file_path` → 阻断（无法评估）；来源是 `skills` → 放行（那不是 settings 文档）；
- 来源是托管策略（`policy_settings`）→ 放行，Claude Code 本来就不让 hook 阻断它。

阻断（退出 2）后变更在当前会话里不生效（M0a E12）。它拦不住"会话开始前文件里就已经有 `disableAllHooks`"，那种情况由 `boundkeep doctor` 发现。

## 8. 磁盘上的文件（`~/.boundkeep/`，`BOUNDKEEP_HOME` 可改）

| 路径 | 内容 |
|---|---|
| `endpoint.json` | IPC 端点（传输方式、地址） |
| `policy.yaml` | 当前策略（M0：四个键） |
| `installs.json` | `init` 改过哪些 settings 文件、写了什么命令，ConfigChange 与 `uninstall` 靠它认出自己的条目 |
| `logs/audit.jsonl`（及 `.1` 到 `.5`） | 审计日志 |
| `serve.lock`、`serve.pid` | 单实例锁与 pid |
| `backups/` | `init`、`uninstall` 改动前的 settings 副本 |

目录与文件都对当前用户私有：POSIX 用 0700 / 0600，Windows 用只含当前用户与 SYSTEM 的受保护 DACL；`doctor` 逐项回读检查。

## 9. 已知局限（M0）

- （M0 的局限，M1 起已被 §6 的判定管线取代）判定管线曾是占位；M1 起有规则，`allow` 默认仍不输出（`emit_allow`）。
- **POSIX 传输只在容器里测过**：2026-10-08 在 Linux 容器里跑过（Docker Desktop，`python:3.12`，Linux 6.6 WSL2 内核，非 root 用户，`uv sync --frozen`）：`mypy` 与 `ruff` 无告警，`pytest` 1643 通过、173 跳过（都是 Windows 专用）、0 失败；容器里的 `init`、`serve`、hook 客户端端到端也通过。这只证明代码与测试在 Linux 上成立，**不是宿主验收**：没有在 Linux 上跑过真实的 Claude Code。 审查者从代码里看到两点尚未处理：Unix 套接字服务端没有并发连接数上限（每条连接的读缓冲最多 8 MiB），`os.umask` 的修改跨越了一个 `await`。在有真实 POSIX 宿主的验收之前不得声明 POSIX 支持。
- 未测：提升权限（UAC）令牌下连管道、杀毒软件的影响（M0a E19 的剩余部分）。
- 常驻进程需要手动 `boundkeep serve`，没有自启动；它不在时每个工具调用都会 `ask`（失败即关闭）。
- **M0 没有保护 `~/.boundkeep` 与 settings 文件不被 agent 自己改写**：这是 M1 的 `protect-guard-config` 规则的活（规格 §8）。M0 里 agent 若能写这些文件（例如改 `endpoint.json` 指向别的管道），闸门就可以被绕开；ConfigChange 的自我保护只覆盖 Claude Code 的 settings 文件。
- `BOUNDKEEP_HOME` 只用于测试与实验目录：hook 与常驻进程必须看到同一个值，真实使用时不要设置它。ConfigChange 会拦下把它写进 settings `env` 块的改动。**M1 起 `init` 把 home 固定进 hook 命令的参数**（`... hook_client.py --home <绝对路径> pre`，子命令仍是最后一个参数），hook 客户端据此忽略环境里的 `BOUNDKEEP_HOME` 与 `USERPROFILE`，所以环境无法再把它引到别的守护进程；`doctor` 对没有固定 home 的 M0 安装给警告，对固定值与当前 home 不一致的报 FAIL。已有的 M0 安装重新运行 `init` 即可升级。
- 审计日志的脱敏是尽力而为：规格 §11 列出的形态都覆盖，另加几种常见的（`xox*-`、`AIza`、`sk_live_`、`npm_`、`glpat-`、JWT、`X-*-Key/Token/Auth` 头、`--pass`），但 `curl -u user:密码`、`mysql -pSECRET`、`sshpass -p`、`docker login -p` 这类位置参数里的口令不会被识别。日志文件只有当前用户能读。
- 审计日志靠体积可以被同用户进程冲掉（约 1000 个最大尺寸的事件就能轮转掉一条旧记录）；M0 没有防篡改机制，同用户本来也能直接删文件。
- `boundkeep log` 的文本输出把不可打印字符（含 ESC、BEL、双向控制符）换成 `?`；`--json` 输出保持原样（JSON 转义过）。
- hook 客户端每次启动约 40 ms（见 `scripts/bench_hook.py` 与其结果文件），其中 `json` 导入约占 9 ms。
- `doctor` 不能判断宿主是否真的在触发 hook；M0a 的实测里两个宿主都触发了，但没有自动检测手段。
