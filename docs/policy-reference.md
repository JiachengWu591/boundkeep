# 策略文件参考（M1）

策略文件是安全配置：拼写错误必须大声失败，不能被悄悄忽略。所以所有层级都是严格模式（未知键报错、不做类型转换），错误信息带行号和字段路径。默认文件在 `policies/default.yaml`，更严的在 `policies/strict.yaml`；`boundkeep init` 把默认策略写到 `~/.boundkeep/policy.yaml`（已有的文件不会被覆盖，`--reset-policy` 才会，并保留备份与当前 mode）。

规格的权威来源是 `PROJECT_SPEC.md` §7、§8；这里是字段参考。

## 顶层

```yaml
version: 1                     # 必须是整数 1
mode: enforce                  # enforce | audit-only
defaults:
  emit_allow: false            # true：规则判为 allow 时向 Claude Code 输出 allow（替用户自动批准）
llm_audit: {...}               # 只校验结构（M3 才有后端）
taint: {sources: [WebFetch, WebSearch, "mcp__*"]}   # 决定 PostToolUse 的 matcher
trusted_projects: []           # 你明确信任的项目目录（默认空），见下面的"受信任的项目"
mcp_read_only: []              # 你声明只读的 MCP 工具（默认空），见下面的"MCP 工具"
rules: [...]
tests: [...]
```

- `mode: audit-only`：不向 Claude Code 返回任何决定，只在审计日志里记录 `would_be`（enforce 下会给出的决定）。先用它观察再切 enforce。
- `emit_allow` 默认关闭：ALLOW 的输出是"无决定"，Claude Code 照常走它自己的权限流程。打开后 boundkeep 会替你跳过本该弹出的确认（E11：压不过你自己的 ask / deny 规则），`doctor` 会对此告警。
- 只含 M0 那四个键（`version`、`mode`、`defaults`、`taint`）的旧文件仍然合法，但没有规则：所有 shell 命令都会 ask，`doctor` 会提示运行 `init --reset-policy`。
- `llm_audit`：`backend` 为 `none | openai_compatible | anthropic`；`on_failure` 只能是 `ask` 或 `deny`（写 `allow` 有专门的报错）；`base_url` 必须是 https（本机回环地址除外）且不带凭据；`api_key_env` 必须是环境变量名，不能是 `ANTHROPIC_API_KEY`。**策略里任何形似密钥的字符串都会被拒绝加载**，错误只给字段路径，不回显值。

## 规则

```yaml
rules:
  - id: no-secret-read               # 唯一，[a-z0-9-]+；m0-canary 保留
    tool: [Bash, PowerShell]         # 可选：已知工具名列表，可写 "mcp__*" 这样的前缀星号；省略 = 全部工具
    platform: [windows]              # 可选：posix | windows；省略 = 全部（内置规则都不写）
    match:                           # 各字段是 AND；列表内是 OR
      path_glob: ["**/.env", "~/.ssh/**"]
      access: read
    action: deny                     # deny | ask | allow
    reason: "禁止读取密钥与凭证文件"      # deny / ask 必填，显示给用户和 Claude
```

标量可以代替只有一个元素的列表（`program: git`）。`allow` 规则至少要有一个 match 字段（空的 match 会放行所列工具的一切），而且必须写规则级 `tool` 或 `match.program` 之一（两者都写也行）；只靠标志、路径、域名收窄的 allow 规则几乎会放行一切，加载时报 "an allow rule must name a tool or a program"。deny / ask 规则不受此限。

**路径规则不要写 `tool:`。** Read、Grep、Glob、Bash、PowerShell 等都会带路径，只列其中几个的读规则等于给其余的留了绕行的路（`Grep` 读 `.env` 曾因此被放行）。内置的所有读类 deny / ask 规则都没有 `tool:`，也没有 `platform:`：Windows 凭据、浏览器、持久化类的 glob 在纯 Linux 上本来就匹配不到任何东西，而 WSL 里看到的 `/mnt/c/Users/x/.ssh/config`（键 `c:/users/x/...`）要靠不依赖主目录的 `**/users/*/...` 写法拦住。

**`tool` 的校验。** 每个名字必须是已知工具（`Bash`、`PowerShell`、`Read`、`Write`、`Edit`、`MultiEdit`、`NotebookEdit`、`Glob`、`Grep`、`WebFetch`、`WebSearch`、`ToolSearch`、`TodoWrite`、`Agent`，以及 `Task`、`BashOutput`、`KillShell`、`ExitPlanMode`、`AskUserQuestion`、`Skill`、`SlashCommand`），或以 `mcp__` 开头，或是这些的前缀星号写法（`mcp__github__*`）。其余一律是加载错误并给出 "did you mean"（`Bsh` → `Bash`；大小写敏感）。只列了不碰路径的工具（`WebSearch`、`Agent` 等）却写了路径条件（`path_glob`、`access`、`path_outside_project`、`path_inside_project`、`path_in_scratchpad`）也是错误：规则永远不会命中。

### match 字段

| 字段 | 含义 |
|---|---|
| `path_glob` | 列表。该动作涉及的**任一**路径匹配**任一**模式即匹配。模式必须以 `/`、`**`、`~/` 或盘符（`c:/`）开头（锚定）；一律正斜杠；不区分大小写。永远匹配不到规范键的模式会被拒绝加载，见下 |
| `access` | `read` 或 `write`，需要和 `path_glob` 一起用。路径的访问方式等于它**或**为 `unknown`（可能读也可能写）时匹配 |
| `program` | 程序名列表。Bash 里区分大小写；PowerShell 不区分。程序名取基本名（`/bin/rm` → `rm`，`curl.exe` → `curl`），所以条目里不能有空格或路径分隔符（`rm`，不是 `/bin/rm` 或 `rm -rf`），否则加载报错 |
| `subcommand` | `git push` 的 `push`、`docker image push` 的 `push` 等；单个词，不能有空白 |
| `flags_any` | 标志列表，出现任一即匹配。合并短标志两种写法都有（`-rf` 同时给出 `-rf`、`-r`、`-f`），长标志去掉 `=值`。每个条目必须以 `-` 开头（PowerShell 参数 `-Recurse` 同样），否则加载报错（`force` 永远匹配不到） |
| `flags_none` | 标志列表（条目规则、校验、大小写折叠与 `flags_any` 完全相同，同样不能为空、每项以 `-` 开头），动作的标志里**一个都没有**才匹配；没有任何标志的动作匹配。与其他字段 AND。给日常只读命令的 allow 规则排除危险开关用（例如 `program: find` 配 `flags_none: ["-delete", "-exec"]`）。不能和 `flags_any` 列同一个条目（永远不会命中，加载报错） |
| `path_outside_project: true` | 任一路径**不能确定**在项目内（`inside_project` 为 false 或 null）即匹配；没有路径时不匹配。与 `path_glob` / `access` 同用时见下面的"同一条路径" |
| `path_inside_project: true` | 至少一个路径，且**每个**路径都**确定**在项目内。这是 allow 侧用的，不确定不算。不能和 `path_outside_project` 同写（永远不会命中，加载报错） |
| `path_in_scratchpad: true` | 至少一个路径，且**每个**路径（每个形式：键入的字面形式与符号链接 / junction / 短名字解析后的形式）都**确定**在**当前会话的 scratchpad** 里或就是它（Claude Code 给 agent 放中间文件的目录 `<临时目录>/claude/<项目 slug>/<会话 id>/scratchpad`，见"Session scratchpad"一节）。由归一化层写在 `PathRef.in_scratchpad`，任何不确定都是 false。这是 allow 侧用的，与 `path_inside_project` 一样：不知道就不匹配。与其他字段 AND；**单独写它不满足** allow 规则必须点名工具或程序的加载检查；只列不碰路径的工具时加载报错。`boundkeep explain` 的明细行是 `path_in_scratchpad: every path is inside the session scratchpad` |
| `paths_read_only: true` | **每个**路径的访问方式都恰好是 `read`。`write` 与 `unknown`（可能写）都不算只读；没有任何路径的动作匹配（`pwd`、`echo hi`，空真）。与其他字段 AND，不要求路径在项目内（要的话再写 `path_inside_project`）。这是 allow 侧用的；写在 deny / ask 规则里时，访问方式为 `unknown` 的路径不会让它命中 |
| `project_trusted: true` | 该动作的**项目目录**等于或位于顶层 `trusted_projects` 的某一项之内才匹配（见"受信任的项目"）。项目目录未知、不确定、过宽（文件系统根、盘符根、主目录或其祖先），或会话的工作目录不在项目内时，不匹配。**单独写它不满足** allow 规则必须点名工具或程序的加载检查。失败方向：allow 规则里任何问题都算不匹配；deny / ask 规则里"无法判断项目是否受信任"算匹配（已知不受信任才不匹配） |
| `network: true` | 该动作联网 |
| `domain_not_in` | 联网，且（目标域名未知，或**任一**域名不在列表里）。域名精确相等或是真正的子域才算"在" |
| `domain_in` | 联网，且域名非空且**每个**都在列表里 |
| `destination` | `known` 或 `unknown`，需要联网：`known` 至少有一个已知域名，`unknown` 一个都没有（配置好的 git 远端或包源、运行时拼出的主机、变量里的 URL）。M2 之后加入，用来把"目的地无法确定"和"主机不在白名单"分成两条规则 |
| `mcp_server` | MCP 工具的 server 名。**区分大小写**（`GitHub` 不是 `github`） |
| `mcp_read_only: true` | 该动作是顶层 `mcp_read_only` 里声明过的 MCP 工具的调用，而且它的灰色原因**只有** `mcp-tool-not-reviewed`（参数里有命令、可能写入的 SQL、读不懂的 URL 等都会多一个原因）。只有带这个字段的 allow 规则能放行这样一个灰色动作；单独写它不满足 allow 规则必须点名工具或程序的检查 |

所有布尔字段只能写 `true`，列表不能为空。**任何 match 字段、`tool`、`platform` 都不能写成 null**（`key:` 后面留空、`null`、`~`）：缺省才表示"不限"，一个悄悄等价于缺省的 null 会让 `path_inside_project:` 这样的笔误把 allow 规则放宽。加载时报 `rules[0].match.path_inside_project: ... is null`，带行号。

### MCP 工具（`mcp_read_only`，M2 之后）

MCP 调用永远带灰色原因 `mcp-tool-not-reviewed`：boundkeep 不知道一个服务器拿参数做什么。归一化层从参数里取出能判断的部分交给 deny / ask 规则（它们大多没有 `tool:`，所以对 MCP 同样生效）：

- **路径**：**任何键**下的值（含嵌套的列表与对象；前后空白不算），只要是绝对路径、`~` 开头的路径、UNC 路径或 `file:` URI，都按本机路径处理（X1 审查 R9-1：只认路径类键名会漏掉 `file_name`、`folder`、`uri` 等）；相对路径可能是远端仓库里的路径，不处理。以变量开头且带分隔符的值（`$HOME/...`、`%USERPROFILE%\\...`）与路径类键下的盘符相对路径（`C:x`）这里解析不了，加灰色 `mcp-path-unclear`。参数走查按层广度优先，有上限（500 个值、6 层、每层 100 项、单个值 4 MiB）；超过任何一项加灰色 `mcp-arguments-not-all-seen`：没看全的调用不会被放行。工具名**以** `read` / `get` / `list` / `search` 等词**开头**、且不含写入类的词时，访问方式是读，否则是"可能读也可能写"（`get_and_store` 可能写）。以 `..` 开头的值加灰色 `mcp-path-unclear`；值前后的不可见字符（字节序标记、零宽字符）不算。所以 `mcp__filesystem__read_file` 读 `~/.aws/credentials` 被拒，写 `~/.bashrc` 被拒。
- **命令**：`command` / `commands` / `cmd` / `script` / `shell` / `code` 键的字符串或字符串列表（同级有 `args` / `arguments` / `argv` 列表时拼在一起）按 Bash 方言解析，得到的动作带灰色 `mcp-command:<工具名>`：只能让 deny / ask 生效（`rm -rf ~` 被拒），永远不会放行。
- **URL**：值里任何 `scheme://` 形式的 URL（`file:` 除外，它是路径；也包括写在一段文字里的），以及主机类键（`url`、`uri`、`host`、`endpoint`、`webhook` 等）下没有 scheme 的值，都进入域名，`net-allowlist` 照常判断；解析不出主机的加灰色 `unparseable-url`。
- **SQL**：键名含 `sql` 或 `statement` 的参数里**不能证明是单条只读语句**的（`SELECT` / `WITH` / `SHOW` / `EXPLAIN` 等开头、不含写入类的词、没有第二条语句；首词在去掉注释与开头的 `;`、`(` 之后取，写入类的词与 `;` 在原文里找，MySQL 的 `/*! ... */` 也算），以及 `query`、`q`、以 `query` 结尾的键里看起来会写的（以写入类首词开头，或有 `;` 后接词），加灰色 `mcp-sql-not-read-only`（X1 审查 R9-2）。

顶层 `mcp_read_only` 是你声明为只读的工具：`mcp__服务名__工具名`，或 `mcp__服务名__前缀*`；服务名必须写全（通配的服务名会把所有服务器的工具都声明成只读，加载报错），最多 64 项，默认空。默认策略的 `allow-declared-read-only-mcp` 放行声明过的工具的调用，条件是：灰色原因只有 `mcp-tool-not-reviewed`、本机路径都是只读；项目外的路径由 `ask-mcp-path-outside-project` 问，白名单外的主机由 `net-allowlist` 问，受保护的文件照常被拒。策略文件 agent 写不了，所以声明只能由你改。**注意**：参数会原样发给服务器，一个只读但连远端服务的工具仍然能把 agent 塞进查询里的内容带出去；只声明你信得过的服务器的工具。strict 策略没有这条 allow。

### 受信任的项目（`trusted_projects`）

```yaml
trusted_projects:
  - ~/work/my-own-project        # 主目录相对：~/ 或 ~\，按加载时的 home 展开，和 path_glob 里的 ~ 一样
  - C:\Users\me\code\other       # 绝对路径：C:\... 或 C:/...（Windows），/...（POSIX）
```

**A trusted project is one whose own code you let tools run without asking: a prompt injection that gets the agent to write a test file and run pytest then executes code unreviewed; do not trust a repository you did not write or audit.**（受信任的项目，就是你允许其自身代码在不询问的情况下被工具运行的项目：提示注入只要让 agent 写一个测试文件再运行 pytest，就会不经审查地执行代码。不要信任你没有写过或审计过的仓库。）

- 默认空列表，缺省等于空。**条目不是 glob**：一个条目表示"这个目录以及它下面的一切"。
- 每项是字符串，加载时校验并规范化一次（存成规范键：`/` 分隔，Windows 风格整条小写；重复项折叠，保留第一次出现的顺序），出错时点名那一项（`trusted_projects[2]: '...' ...`）。最多 64 项，每项最长 1024 字符。
- **拒绝**：空白或首尾带空白；相对路径（含 `C:foo`、`\foo`）；UNC / 网络路径（`\\host\share`、`//host/share`）；含 `*`、`?`、`[`、`$`、`%` 的条目（不是模式，也不是变量）；含 `..` 段；含 NUL 与控制字符；`~user` 形式；NTFS 备用数据流、尾随的点或空格、`/mnt/c/...` 与 `/c/...` 这类被翻译的写法（写成 `C:\...`，首个目录名是单个字母的 POSIX 路径会被读成盘符）；以及**过宽**的目录：主目录本身、主目录的任何祖先、盘符根、`/`、`/home`、`/Users`、`C:\Users`、`~/Documents`、`~/Desktop`、`~/Downloads` 本身、`/tmp`、`/var/tmp`、`/usr`、`/opt` 一类放着许多东西的目录本身，以及 `C:\Windows`、`C:\Program Files*`、`/etc` 等系统目录（含其下）。过宽的判断与归一化层拒绝过宽的项目根是同一份代码（`policy.schema.too_broad`）。
- 另一种平台风格的条目（Windows 守护进程里的 `/home/x/p`，POSIX 里的 `C:\p`）能加载，但永远匹配不到。
- 比较按路径段前缀（`/home/a/proj2` 不在 `/home/a/proj` 内），不是字符串前缀；Windows 风格不区分大小写，POSIX 风格区分。
- "项目目录"就是归一化层用于 `inside_project` 的那个目录（事件的 `project_dir`，没有时取 `cwd` 所在的 git 根），规范键放在 `Action.project`（每个动作都有；`Action.project_resolved` 是符号链接 / junction 解析后的目录，只在与前者不同时设置，两者都要在受信任的项目里才匹配）。项目目录未知、过宽，或会话的 `cwd` 已不在项目内（命令在别处运行，不是在运行这个项目的代码）时 `Action.project` 为 `None`，`project_trusted` 不匹配。
- `boundkeep explain` 里命中规则的明细行写 `project_trusted: project is inside a trusted project`；不受信任的说明行 `project_trusted: project is not trusted` 由 `policy.matcher.project_trust_line(action, trusted_projects)` 生成（没命中的规则本来就不列明细）。
- **`project_trusted` 只说明"项目是否受信任"**，不说明命令读写哪些路径；运行仓库代码的 allow 规则仍应同时用 `path_inside_project` 等字段约束路径。

### 同一条路径（correlation）

`path_glob`（连同 `access`）与 `path_outside_project` 必须由**同一条路径**满足：这条路径匹配某个 glob、访问方式相容、并且不是确定在项目内。例如严格策略里的 `ask-write-outside-project`（`path_glob: ["**"]`、`access: write`、`path_outside_project: true`）对 `cp /tmp/src.txt ./dest.txt` 不再触发：项目外的 `/tmp/src.txt` 只是被读，被写的 `dest.txt` 在项目内。`path_inside_project` 仍然是"所有路径"；和 `path_glob` 同用时，再要求其中一条路径匹配 glob。只写 `path_outside_project` 时仍是"任一路径"。

### allow 规则与包装器

`allow` 规则永远不会匹配带 `wrappers`（`sudo`、`env X=1`、`nohup` 等被剥掉的前缀）的 Action，也不会匹配灰色 Action，**也不会匹配 `dynamic_args` 的 Action**（X1 复审 R-1、R-2、R-4：命令里有一个不是路径的词会展开——变量、命令替换，对开发工具还有通配符，`$u@args.txt` 展开后是参数文件，`ConvertTo-Json $env:TOKEN` 会被打印，`ruff --select $env:TOKEN` 会被回显；展开成路径的词交给路径层，`$true` / `$false` / `$null` 不算；这样一次盖住所有 allow 规则，不再逐个 cmdlet 维护名单；deny / ask 规则不受影响）：`sudo ls` 与 `ls` 不是同一个动作，不能搭 `allow program: ls` 的便车。deny / ask 规则仍按已知部分匹配这两类 Action。

### 判定语义

- 一次工具调用归一化为**一个或多个** Action（一条 shell 命令行里每个简单命令一个）。每个 Action 取命中规则中最严的：`deny` > `ask` > `allow`；一条都没命中就是**灰色**。
- 整体取各 Action 最严的：任一 deny → deny；否则任一 ask → ask；否则任一灰色 → 灰色；**全部**为 allow 才是 allow；没有 Action 也是灰色。
- 灰色在没有 LLM 后端时输出 `ask`（`llm_audit.backend: none`）。
- **带 `gray` 标记的 Action（解析不了、动态内容、未知工具、PowerShell 里解析不了或动态的构造）永远不会命中 allow 规则**；deny / ask 规则仍按已知部分匹配。
- 内部出错对 deny / ask 规则算"命中"，对 allow 规则算"不命中"：失败只会更严。
- 内置规则 `m0-canary`（命令文本里含 `BOUNDKEEP_CANARY` → deny）总是最先评估，不写在 YAML 里。
- 另有一条随机器而定的规则：设置了 `CLAUDE_CONFIG_DIR` 时，守护进程在加载策略时给该目录的 `settings*.json` 加上和 `protect-guard-config` 一样的写保护（`protect-guard-config-dir`）。

### 路径与 glob

- 路径先规范化再匹配（`normalize/paths.py`）：展开 `~` 与已知变量、统一分隔符、折叠 `..`、去掉 `\\?\` 前缀、NTFS 备用数据流、尾随的点与空格，翻译 MSYS / `/cygdrive` / `/mnt/c` 形式；Windows 风格的路径整条小写（casefold）。文件系统存在的路径还会额外按 realpath 再匹配一次，所以指向 `~/.ssh` 的符号链接同样会命中。
- 永远不可能匹配的 glob 加载时就报错：任何空段（`~/a//b`）、`.` 或 `..` 段（`~/.ssh/../.aws/**` 保护不了任何东西，规范键里没有这些）、首尾空白（开头恰好两个 `/` 的 UNC 与 `//./physicaldrive*` 设备命名空间是真实的键形状，允许）。
- 主目录里的反斜杠（Linux 允许 `/home/we\ird`）在 `~` 展开时变成 `?`（匹配除 `/` 外任一字符，多匹配是安全方向），不再让整份策略加载失败。
- glob 语法：`*`、`?` 不跨 `/`；`[...]` 类不匹配 `/`；`**/` 匹配零或多级目录；结尾的 `/**` 匹配目录本身及其下全部；字符串里不能有反斜杠、控制字符，不能以 `/` 结尾；`~/` 在加载时展开为用户主目录（对 glob 元字符转义）。匹配是线性时间（位集合模拟的 NFA，没有回溯）。限制：模式 512 字符、1024 个 token、键 32768 字符。
- 比较大小写：deny / ask 侧不区分大小写（可能匹配即匹配）；`inside_project` 对 Windows 风格路径不区分，对 POSIX 风格路径区分。

## 加载时的其他检查

- 策略文本里出现单独的 `\r`（后面不是 `\n`）会被拒绝：PyYAML 把它当换行，按行工作的工具不当，可以用它藏一行。CRLF 与 LF 都没问题。
- 形似密钥的字符串会被拒绝加载（含 `npm_`、`glpat-`、`sk_live_`、`Authorization: Basic ...`、`private_key` 一类名字下的 64 位十六进制）。例外：`tests[].input` 不扫描（密钥处理的回归用例必须含形似密钥的文本；它只在假机器上跑），其余字段仍然扫描。`credentials: /home/user/.aws/credentials/foo` 这样的理由文字不会被误判：赋值形式只在值像随机串（字母数字混合、不是路径）时才命中。

## 测试

```yaml
tests:
  - { tool: Bash, input: { command: "rm -rf /" }, expect: deny }
  - { tool: Read, platform: [windows], input: { file_path: "~\\.SSH\\id_rsa" }, expect: deny }
  - { tool: Bash, cwd: "/home/dev/proj", project_dir: "/home/dev/proj", input: { command: "rm -rf build" }, expect: gray }
```

`expect` 取 `deny | ask | allow | gray`（`gray` = 规则层不应定案，用来防止规则过宽）。可选字段 `platform`、`cwd`、`project_dir`，以及 `session_id`（事件的会话 id，默认是一个不是 UUID 的固定值，所以默认没有任何路径在"会话 scratchpad"里；测 `path_in_scratchpad` 要写一个 UUID）。`boundkeep test [--policy 文件] [--platform windows|posix|all]` 用**假机器**（Windows：`C:\Users\testuser`，POSIX：`/home/testuser`）跑真实的管线，所以 Windows 路径的用例在任何平台都能通过；默认两个平台都跑。

`boundkeep explain <事件.json|->` 用**本机的真实环境**（你的主目录与环境变量、事件里的 `cwd` 与 `project_dir`）解释一个事件：每个动作的程序、路径（规范键与 `inside_project`）、域名、风险标签、命中的规则、最终判决和 hook 实际会输出什么。

## 内置策略里的规则

每条规则的理由都写在 `policies/default.yaml` 的注释里（独立于任何数据集）。`strict.yaml` 里"ask"的持久化与配置类规则改为 deny（规则名 `ask-` 改 `deny-`），另有若干更严的规则（见文件头）。概览：

| 规则 | 动作 | 内容 |
|---|---|---|
| `protect-guard-config` | deny | 写 `.claude/settings*.json`、`.boundkeep/**`、`.claude` 目录本身与 `~/.claude`（删除、改名、移动、覆盖都算写）、`managed-settings.json`、`managed-settings.d/**` |
| `deny-boundkeep-state-commands` | deny | `boundkeep` / `boundkeep-hook` 的 `mode`、`uninstall`、`init`、`serve`、`trust`（`trust` 的每种写法都拒绝，`trust list` 也一样：规则只看得到子命令；用户在自己的终端里运行它，列表用 `boundkeep doctor` 看；CLI 自己在 stdin 不是终端时、或环境里有 `CLAUDECODE` / `CLAUDE_CODE_ENTRYPOINT` 时也会拒绝；**注意这两道检查都不是边界**：`Start-Process`、`cmd /c start`、`cmd /c … < CON` 起的子进程有真实的控制台，间接写法（`cmd /c`、`powershell -Command`、`python -c`）规则只看到灰色（ask）。真正挡住"agent 给自己加信任"的是守护进程的会话快照，见"Dev-tools preset"一节）（**依赖归一化层报告 boundkeep 的子命令，见下文"程序命令行规则"**） |
| `deny-boundkeep-state-flags` | deny | `boundkeep` / `boundkeep-hook` 带 `--reset-policy`、`--purge`、`--python`、`--hook-style`、`--rotate-endpoint`、`--home`（按标志即可匹配，现在就生效） |
| `deny-boundkeep-hook-run` | deny | 手工运行 `boundkeep-hook` |
| `ask-boundkeep-cli` | ask | `boundkeep` 其余命令（`doctor`、`test`、`explain`、`log --tail`、`llm`）；这些是给用户自己终端用的，ask 让确认框里有带 boundkeep 字样的理由 |
| `ask-claude-cli`（strict 另有 `deny-claude-cli-flags`） | ask（strict：带 `--settings` / `--permission-mode` / `--dangerously-skip-permissions` 为 deny） | 任何 `claude ...`：`config set` 改权限与 hooks、嵌套会话可能不在本闸门之内 |
| `ask-kill-processes` | ask | `taskkill`、`pkill`、`killall`、`kill`、`Stop-Process`、`Stop-Service`（目标是参数，规则语言匹配不了，所以一律问） |
| `ask-package-uninstall`（strict：`deny-package-uninstall`） | ask（strict：deny） | `pip` / `pip3[.x]` / `pipx` / `python[3[.x]] -m pip` 的 `uninstall`、`uninstall-all`（包名是参数，匹配不了，所以任何卸载都问） |
| `ask-guard-state-read` | ask | 读 `.boundkeep/**`（`endpoint.json`、`policy.yaml`、`logs/audit.jsonl`） |
| `deny-link-to-guard-files` | deny | **X1 审查 H-6。** `ln`、`New-Item`（`-ItemType HardLink` / `SymbolicLink` / `Junction`；`New-Item` 只有创建链接时才会把目标列为读路径）的**读路径**命中 `protect-guard-config` 的那份 glob（`.boundkeep/**`、`.claude/settings*.json`、`~/.claude`、managed settings，有测试保证两份清单相等）。硬链接是同一个文件的另一个名字：`ln ~/.boundkeep/policy.yaml here` 之后，对 `here` 的普通 `Write` 就改写了策略，而按名字判断的规则看不见。创建链接是目标被点名的唯一时刻，所以在这里拒绝。`protect-guard-config-dir`（`CLAUDE_CONFIG_DIR`）与 `protect-guard-code`（已安装的代码、解释器、boundkeep 主目录）这两条守护进程在运行时加的规则各有一条同样的孪生规则（`deny-link-protect-guard-config-dir`、`deny-link-protect-guard-code`、`deny-link-copy-…`）。这些规则的 glob **不进入** `protected_read_globs`（规则 id 以 `deny-link-` 开头）：它们点名的是被创建链接的目标，不是读内容，否则对含 `.claude/settings.json` 的目录做 `Grep` 会被拒绝，而项目级 settings.json 可读是有意的 |
| `deny-link-copy-of-guard-files` | deny | 同上，`cp -l` / `cp --link`（用硬链接代替复制）。不带 `-l` 的 `cp` 仍然只是读（`ask-guard-state-read`） |
| `ask-agent-exec-config` | ask | 写 `.mcp.json`、`~/.claude.json`、`.claude/{hooks,commands,agents,skills,rules,output-styles,plugins}/**`、`.claude/statusline.*`、`CLAUDE.md`、`CLAUDE.local.md` |
| `ask-repo-exec-config` | ask | 写 `.git/hooks/**`、`.git/config`、`.envrc`、`.husky/**`、`.vscode/{tasks,settings,launch}.json`、`.github/workflows/**`、`.devcontainer/**` |
| `ask-user-config-write` | ask | 写 `~/.gitconfig`、`~/.npmrc`、`~/.pypirc`、`~/.config/pip/pip.conf`、`~/.netrc`、`~/.docker/config.json` |
| `ask-project-autorun-files`（strict：`deny-project-autorun-files`） | ask（strict：deny） | 写（新建、修改、改名、删除；Write / Edit / MultiEdit 与所有 shell 写入，规则没有 `tool:` 限制，`access: write`）会让代码日后自己跑起来的文件。项目内：`package.json`、`Makefile` / `makefile` / `GNUmakefile`、`pyproject.toml`、`setup.py`、`setup.cfg`、`tox.ini`、`noxfile.py`、`conftest.py`、`sitecustomize.py`、`usercustomize.py`、`*.pth`、`build.rs`、`rust-toolchain[.toml]`、`.cargo/config[.toml]`、`.npmrc`、`.yarnrc*`、`.pnpmfile.cjs`、`.pre-commit-config.yaml`、`.gitattributes`、`.gitmodules`、`.envrc`、`.husky/**`、`.github/workflows/**`、`.github/actions/**`、`.gitlab-ci.yml`、`.circleci/**`、`Jenkinsfile`、`azure-pipelines.yml`、`.travis.yml`、`bitbucket-pipelines.yml`、`Dockerfile*`、`docker-compose*.{yml,yaml}`、`compose.{yml,yaml}`、`compose.*.{yml,yaml}`、`.devcontainer/**`、`.vscode/{tasks,settings,launch,extensions,mcp}.json`、`.idea/runConfigurations/**`。用户级：`~/.cargo/config[.toml]`、`~/.gradle/init.d/**`、`~/.gradle/init.gradle*`、`~/.condarc`、`~/.yarnrc*`、`~/.terraformrc`、`~/.aws/config`（`credential_process`）、`~/.config/pip/pip.conf`、`%APPDATA%\pip\pip.ini`（含 WSL 看到的 `/mnt/c/Users/x/AppData/Roaming/pip/pip.ini`）。**先于项目内写入的 allow 规则存在**：default 里的 `allow-project-file-writes`（见下）已经加上，这些文件靠"最严者胜"仍然是 ask，不会被悄悄放行。名字整体匹配；不含 README、`*.md`、源码、锁文件、`tsconfig.json`、`.gitignore`、`.editorconfig`（这些写入在 default 里是 allow，strict 里仍是灰色）。**已接受的误报**：改 `package.json`、`Makefile`、`pyproject.toml`、`conftest.py`、Dockerfile、CI 文件都会问（有意为之）；`*.pth` 也匹配 PyTorch 权重文件，`Dockerfile*` 也匹配 `Dockerfile.md`；`cp Makefile 任意位置` 也会问（`cp` 分不清目标是文件还是目录，把 `<目标>/Makefile` 也算作写入）；读这些文件不受影响。与 `ask-repo-exec-config` 有重叠（`.envrc`、`.husky`、`.vscode`、workflows、devcontainer），重复是有意的：两条都命中也只是同一个 ask |
| `ask-secret-file-write`、`ask-credential-file-write`（strict 同名，同为 ask） | ask | 写（Write / Edit / MultiEdit / NotebookEdit 与所有 shell 写入，`access: write`，没有 `tool:` 限制）`no-secret-read` 与 `no-credential-store-read` 列的那批文件，glob **逐字相同**（有测试保持两份一致）。读它们被拒绝是因为内容就是秘密；写一个新的 `.env`、密钥或凭据文件会改变项目连到哪个账号，用 Edit 改还会让 agent 看到旧内容。项目内的普通写入在 default 里有 allow 规则（`allow-project-file-writes`），所以这些名字必须先 ask |
| `ask-git-internals-write`（strict 同名，同为 ask） | ask | 写 `**/.git/**`：HEAD、refs、index、对象库、`info/attributes`，以及子模块与 worktree 里的 hooks 和 config（`.git/modules/x/hooks/...`、`.git/modules/x/config`），较窄的 `ask-repo-exec-config`（`.git/hooks`、`.git/config`）够不着这些。git 自己会写这些文件，shell 里的 git 命令不会点名 `.git` 路径 |
| `no-secret-read` | deny | 读 `.env`、`.env.*`、`*.env`、名为 `env` 的文件、`.envs/**`、`**/.ssh/**`、`*.pem`、`*.key`、`*.jks`、`*.keystore`、`*.tfstate*`、`*.tfvars`、`service-account*.json`、`credentials.json` / `credentials.txt`、`secrets.{yml,yaml,json,toml,txt}`、`secret.txt`、`key.txt` / `keys.txt`、`password(s).txt`、`token.txt`、`.htpasswd`、`kubeconfig`、`*.kubeconfig`、`local.settings.json`、`*.kdbx` / `*.kdb`、`/etc/shadow*`、`/etc/sudoers*`、`/etc/ssh/ssh_host_*`、`/proc/*/environ`。名字整体匹配，所以 `env.py`、`kubeconfig.go`、`docker-compose.yml`、`README` 仍可读 |
| `no-credential-store-read` | deny | 读云 CLI 与容器配置（`.aws`、`.azure`、gcloud、gh、op、doctl、rclone、kube、docker）、`.gnupg`、`.git-credentials`、`.git/credentials`、`.config/git/credentials`、`.gitconfig`、`.git/config`、`.netrc` / `_netrc`、`.npmrc`、`.pypirc`、`.pgpass`、`.my.cnf`、`.s3cfg`、`.boto`、`.vault-token`、`.cargo/credentials*`、`.gem/credentials`、`.m2/settings.xml`、Terraform 凭据、GitHub CLI 与 gcloud 的 `%APPDATA%` 目录、私钥文件（`id_rsa*`、`id_ed25519*` 等，含 `.bak` 备份；代价是公钥 `id_rsa.pub` 也读不了） |
| `no-agent-state-read` | deny | 读 `~/.claude/.credentials.json`、`~/.claude.json`、用户级 `~/.claude/settings.json` 与 `~/.claude/settings.local.json`、项目的 `.claude/settings.local.json`（这几个的 `env` 块里常放令牌）、`.mcp.json`（MCP 服务器的 headers 与 env）、`.claude/projects/**`（会话记录）、`history.jsonl`、`shell-snapshots`、`ide` |
| `no-history-read` | deny | 读 `.bash_history`、`.zsh_history`、`.python_history`、`.psql_history`、`.mysql_history`、PSReadLine 的 `ConsoleHost_history.txt` 等 |
| `no-windows-credential-read` / `no-browser-profile-read` | deny | Windows 凭据、DPAPI、保险库、`System32\config`、`windows\repair`；Windows / Linux / macOS 浏览器配置目录与钥匙串。都含 `**/users/*/...` 形式，WSL 看到的 `/mnt/c/Users/x/...` 也被拦 |
| `no-raw-disk-access` | deny | 读写 `/dev/sd*`、`nvme*`、`mmcblk*`、`/dev/mem`、`\\.\PhysicalDrive*` 等裸设备 |
| `protect-windows-persistence` | deny（M2 之后，原为 ask） | PowerShell profile（含 OneDrive 重定向后的 Documents）、启动文件夹、计划任务目录 |
| `deny-windows-persistence-tamper` | deny（M2 之后） | 没有只读用法、编码任务也用不到的那部分：`Register-ScheduledTask`、`Register-ScheduledJob`、`New-Service`、`Set-WmiInstance`、`New-LocalUser`、`Add-LocalGroupMember`、Defender 的三个 `*-MpPreference`、防火墙规则与设置、`Set-ExecutionPolicy`、`Enable-PSRemoting`、`Clear-EventLog`、`bcdedit`、`takeown`、`Stop-Computer`、`Restart-Computer` |
| `windows-persistence-commands` | ask | PowerShell profile（含 OneDrive 重定向后的 Documents）、启动文件夹、`schtasks` / `reg` / `sc`（含 WSL 里的 `reg.exe`）；按程序名：计划任务与计划作业、服务、注册表属性写入（含 `Copy/Move/Rename/Clear-ItemProperty`）、WMI/CIM 实例、本地用户与组、防火墙规则与设置、Defender 排除项、`Clear-EventLog`、`setx`、`vssadmin`、`wevtutil`、`takeown`、`cipher`、`Stop-Computer` / `Restart-Computer` |
| `ask-net-account-changes` | ask | `net` / `net1` 的 `user`、`localgroup`、`group`、`share`、`stop`、`start`、`accounts`、`config`（建账号、提权限、改密码、共享、控制服务） |
| `protect-shell-startup-files`、`deny-system-config-write` | deny（M2 之后，原为 ask） | `.bashrc` / `.zshrc` / autostart / systemd 用户单元 / LaunchAgents；写 `/etc/**` 等系统配置 |
| `ask-user-path-dirs-write` | ask | 写 `~/.local/bin`、`~/bin`（装个脚本是正常请求，所以不拒） |
| `deny-crontab-install`、`deny-service-registration` | deny（M2 之后） | 除 `crontab -l` 以外的 `crontab`；`systemctl` / `launchctl` 的注册类动词（`enable`、`link`、`add-wants`、`preset`、`set-property`、`edit`、`load`、`bootstrap`、`submit` 等）。规范化层把 `systemctl` / `launchctl` 的第一个位置参数作为 subcommand |
| `ask-scheduled-jobs`、`ask-user-services`、`ask-launchctl` | ask | 其余的 `crontab -l` / `at` / `systemd-run`；`systemctl --user`；`launchctl` |
| `deny-ssh-write` | deny（M2 之后，原为 ask） | 写 `.ssh` |
| `ask-privilege-escalation` | ask | `su` / `sudo` / `doas` / `pkexec` 作为程序出现（被剥掉的 `sudo` 看里面的命令） |
| `rm-outside-project` | deny | 递归删除项目之外的路径 |
| `ask-delete-outside-project` | ask | 删除项目之外的单个文件 |
| `git-force-push` | ask | `--force`、`--force-with-lease`、`+refspec`、`--mirror`、`--delete` 的 push |
| `ask-git-reset-hard`、`ask-git-clean-force`、`ask-git-discard-paths`、`ask-git-branch-force-delete`、`ask-git-rewrite-history` | ask | `git reset --hard`、`git clean -f`、`git checkout -- <路径>` 与 `git restore <路径>`（`--staged` 也会问：规则语言不能排除标志）、`git branch -D`、`filter-branch` / `filter-repo` |
| `ask-docker-prune` | ask | `docker system/volume/image prune` |
| `deny-find-delete-outside-project` | deny（M2 之后，原为 ask） | 项目之外的 `find ... -delete`（strict 另外对项目内也问） |
| `deny-disk-tools` | deny（M2 之后，原为 ask） | `mkfs*`、`wipefs`、`fdisk`、`parted`、`diskpart` 等 |
| `deny-recursive-permission-change` | deny（M2 之后，原为 ask） | 项目之外的 `chmod -R` / `chown -R` / `chgrp -R`（strict 另外对项目内也问） |
| `net-allowlist` | ask | 访问已知主机且不在白名单里：pypi.org、files.pythonhosted.org、github.com、githubusercontent.com、registry.npmjs.org、registry.yarnpkg.com、crates.io、proxy.golang.org、sum.golang.org、api.nuget.org（含子域）。在白名单上不等于放行，命令仍要有 allow 规则 |
| `net-unknown-destination` | ask | 联网但目的地无法确定（配置好的 git 远端或包源、运行时拼出的主机）（M2 之后从 `net-allowlist` 拆出） |
| `ask-mcp-path-outside-project` | ask | MCP 调用的本机路径不在项目内（见"MCP 工具"） |
| `allow-declared-read-only-mcp` | allow | **仅 default**：`mcp_read_only` 里声明过的 MCP 工具的调用（默认没有声明，不生效；见"MCP 工具"） |
| `ask-shell-read-outside-project`、`ask-git-read-outside-project`（仅 default；strict 的 `ask-read-outside-project` 已经覆盖） | ask | 下面几条 allow 规则（读 stdin 的 `head` / `tail` / `wc` / `grep` / `egrep` / `fgrep`、不带路径的 `Get-ChildItem`、不带路径的 `git status` / `git diff`）没有路径可以要求"在项目内"，所以从另一侧补上：这些程序带一个不能证明在项目内的路径（项目外，或不确定；读、写都算）时 ask，最严者胜。这两条没有 `path_glob` / `access`，有意如此：读类规则里的 `**` 会进入递归读取的子树扫描的"受保护名字"，让目录下的每个文件都被当成受保护文件。程序清单必须与那几条 allow 规则一致（有测试检查）；git 那条的子命令清单与 git 的 allow 规则一致。`cat` 不在其中：它的 allow 规则要求路径在项目内，项目外的 `cat` 仍是灰色 |
| `read-inside-project` | allow | `Read` / `Glob` / `Grep` 且路径确定在项目内（strict 里唯一的 allow 规则） |
| `allow-list-inside-project` | allow | **仅 default。** Bash `ls` / `dir`：路径都只读且确定在项目内（不带路径时是 `.`）；排除 `--time-style`（`+FORMAT` 会原样打印其中的字符，环境变量的值也在内） |
| `allow-tree-inside-project` | allow | Bash `tree`，路径都只读且在项目内；排除 `-o` / `--output`（写文件）、`-R`（在每个目录里写 `00Tree.html`）、`-H` / `-T` / `--timefmt`（打印命令行上给的字符串） |
| `allow-find-inside-project` | allow | Bash `find`，起点（默认 `.`）都在项目内；排除 `-delete`、`-exec`、`-execdir`、`-ok`、`-okdir`、`-fprint`、`-fprint0`、`-fprintf`、`-fls`、`-files0-from`、`-printf`（打印它拿到的格式串） |
| `allow-rg-inside-project` | allow | Bash `rg`，路径都在项目内；排除 `--pre`（对每个文件先运行一个命令）、`--hostname-bin`，以及打印命令行上给的字符串的 `-r` / `--replace`、`--context-separator`、`--field-context-separator`、`--field-match-separator`、`--path-separator` |
| `allow-cat-inside-project` | allow | Bash `cat`，路径都只读且在项目内。不带路径的 `cat`（读 stdin）没有路径可检查，不匹配（灰色） |
| `allow-read-filters` | allow | Bash `head` / `tail` / `wc` / `grep` / `egrep` / `fgrep`，路径都只读；没有路径时读 stdin（`git log \| head -n 5`）。不要求 `path_inside_project`，项目外的路径由 `ask-shell-read-outside-project` 问；排除 `--files0-from`（要数的文件名放在规则看不见的文件里）与 `--label`（grep 会把它当文件名打印） |
| `allow-no-path-commands` | allow | （`pwd`，M2 之后加了 `which`：打印程序在哪里，不读文件；带展开的名字永远不放行，因为它的报错会重复那个名字；给它一个路径（`which ./.env`）时规则只把它当成命令名，结果只透露该文件是否存在且可执行，名字找不到时 `which` 会打印整个 PATH）Bash `pwd`（重定向会让它有一条写路径，`paths_read_only` 就不匹配）。**`echo` 不在其中**（也没有 `printf`、`printenv`、`env`）：它打印 shell 展开后的参数，`echo $ANTHROPIC_API_KEY` 会把环境变量的值送进 agent 的上下文（X1 复审 L-7），规则语言分不清 `echo hello` 与 `echo $NAME` |
| `allow-git-read-only` | allow | `git status` / `diff` / `log` / `show` / `blame` / `rev-parse`（Bash 与 PowerShell），路径都只读。排除的选项见下节 |
| `allow-git-branch-list` | allow | 只有列出分支的写法：`git branch` 带 `-a`、`-r`、`--list`、`-l`、`--all`、`--remotes` 或 `--show-current`，且不带删除、改名、复制、强制、改上游、编辑说明等选项。**光秃秃的 `git branch` 不允许**（规则语言看不见位置参数，分不清 `git branch` 与 `git branch NAME`），`-v` / `-vv` 也不在其中：`git branch -v NAME` 会创建分支 |
| `allow-git-add` | allow | `git add`：把工作区文件复制进索引，不运行程序、不联网。操作数是访问方式未知的路径，所以密钥、凭据、`.git` 规则照常判断（`git add .env`、`git add .git/config` 是 deny），项目外的路径由 `ask-git-read-outside-project` 问。不在其中：`-f` / `--force`（会暂存被忽略的文件，也就是密钥与构建产物所在）及其所有缩写，`-e` / `--edit`（启动编辑器），`--pathspec-from-file` 及缩写，以及 `-c`、`-C`、`--git-dir` 等全局选项。残余：`git add -A` 会把没被忽略的未跟踪 `.env` 放进索引（只是索引，之后的 `git push` 会问） |
| `allow-git-commit-message` | allow | `git commit`，且消息写在命令行上（`-m`、`--message` 或 `--no-edit`，否则 git 会启动配置里的编辑器）。写一个提交对象、移动当前分支，只在本地，可由 reflog 撤销。会运行的：仓库自己的 hook（`.git/hooks`、`core.hooksPath`）；agent 写不了这些（`ask-git-internals-write`），仓库自带的 hook 是残余（与 `allow-git-read-only` 的 fsmonitor 同一类，所以 `emit_allow` 保持关闭）。不在其中：`-e` / `--edit`、`-S` / `--gpg-sign`（启动配置的 gpg 程序）及缩写，`--pathspec-from-file` / `--pathspec-file-nul` 及缩写（git 会读取那个文件，没有匹配路径时把内容原样打进报错；X1 审查 R3-1），全局选项。`--pathspec-from-file` 的文件在 `add`、`commit`、`stash` 里都按“读路径”判断，密钥与项目外规则照常生效。消息是计算出来的（`-m "$(date)"`）一律 ask |
| `allow-git-stash` | allow | `git stash` 的 push（含不带子命令）、list、show、apply、pop：把未提交的改动存进 stash 再取回，不会丢东西。**不允许**：`drop`、`clear`（销毁 stash）、`branch`、`create`、`store` 与其他任何子命令——规范化器给它们打上不可能是真实 git 选项的标记 `--stash-other`（规则语言看不见位置参数），规则的 `flags_none` 里列了它；`-a` / `--all`（会把被忽略的文件、构建产物、虚拟环境一起收走）；`--pathspec-from-file`；`-p` / `--patch`（交互式）；全局选项。**`stash list` 与 `stash show` 带着 `git log` / `git diff` 的整套选项**（`--output` 会写文件、`--format` 会打印值、`-p` 会显示被贮藏的密钥改动、`--ext-diff` 会启动程序），黑名单列不全，所以这两个由规范化器按**白名单**处理：`list` 只允许 `--oneline`，`show` 只允许 `--stat`、`--name-only`、`--name-status`、`--numstat`、`--shortstat`，其余选项一律打上 `--stash-other`（X1 审查 R3-2、R3-4）。`add`、`commit`、`stash` 在**仓库根在项目目录之上**时（monorepo 子目录、主目录里的 dotfiles 仓库）一律灰色 `git-root-above-project`：它们没有路径操作数，作用范围是整个仓库的工作区（R3-5；要读磁盘，所以假机器和评测里不生效） |
| `allow-version-probe` | allow | `NAME --version` 且后面**什么都没有**，`NAME` 是常见工具链程序（git、python、python3、pip、pip3、node、npm、uv、cargo、rustc、dotnet、docker（`npx` 是启动器，规范化器本来就把它标成灰色，不在其中））：打印版本就退出。规范化器对这些程序在 `--version` 之后出现任何别的参数（`python --version -c ...`、`node --version x.js`）都打上 `--version-with-arguments`，规则的 `flags_none` 里列了它。只认拼全的 `--version`（`node -v` 不放行：`python -v` 是详细模式的交互解释器）。**前面有环境变量前缀就不放行**（`PYENV_VERSION=x python --version`、`GIT_TRACE=文件 git --version` 等：版本管理器的 shim 与 git 会读这些变量；`GIT_TRACE*` 同时进了“会带代码的环境变量”表，git 会把跟踪输出追加到它指向的文件）。残余：运行的是 PATH 上找到的那个程序，与用户自己的 shell 一样；若它是版本管理器的 shim（mise、asdf、pyenv、volta、rustup），shim 会读项目里的选择文件并可能运行其中配置的程序，所以写这些文件（`mise.toml`、`.tool-versions`、`.python-version`、`.node-version`、`.nvmrc`、`.ruby-version`、`.sdkmanrc`、`global.json`、`uv.toml` 等，复核后按目录和模式通配，含 mise 的 `.config/mise/`、`mise/`、`.mise/` 各配置位置与 `.volta/`）由 `ask-toolchain-selector-write`（strict：`deny-toolchain-selector-write`）拦下；别人（git 拉取、解压）放进来的这类文件不在此列 |
| `allow-git-ls-files` | allow | `git ls-files`：列出文件**名**（`-o` 含未跟踪的），不打印内容。选项很多（`--exclude-from` 读文件、`--format`、`--debug` 会打印），所以规范化器按白名单处理：只认 `-o`、`--others`、`-m`、`--modified`、`-d`、`--deleted`、`-z`、`--cached`、`--exclude-standard`，其他选项和字面的 `--` 都打上 `--git-other-option`（`-c` 不在白名单里：它同时是全局的 `-c key=value`）。项目外的路径由 `ask-git-read-outside-project` 问 |
| `allow-ps-inspect-inside-project` | allow | PowerShell `Get-Content` / `Select-String` / `Test-Path` / `Get-Item` / `Resolve-Path`，路径都只读且在项目内。**没有路径的调用不匹配**（`Get-ChildItem \| Get-Content` 的文件名来自管道，会读整个列表里的每个文件，包括 `.env`） |
| `allow-ps-list-here` | allow | PowerShell `Get-ChildItem`（`ls` / `dir` / `gci`）：不带路径时列当前目录，所以不要求 `path_inside_project`，路径不在项目内时由 `ask-shell-read-outside-project` 问；提供程序路径（`Env:`、`HKLM:`）、通配符、未知参数（`-Credential`）归一化层返回灰色，不匹配 |
| `allow-ps-no-path-commands` | allow | PowerShell `Get-Location`、`Get-Date`、`Measure-Object`（都在归一化层的"无路径"清单里；只打印计数或日期）。排除 `Get-Date -Format` / `-UFormat`（原样打印格式串）与 `-Date`（解析失败的值会出现在错误信息里）。**`Write-Output` 与 `Select-Object` 不在其中**：前者打印展开后的参数（`$env:SECRET_TOKEN`），后者打印管道里的值，而归一化层会丢掉以变量开头的管道元素（`$env:SECRET_TOKEN \| Select-Object` 不带任何标记） |
| `allow-mkdir-touch-inside-project` | allow | Bash `mkdir` / `touch`，路径都在项目内；排除 `touch -r` / `--reference`（参考文件的时间戳）。名字敏感的（`Makefile`、`.env`、`.git/...`）由上面的 ask 规则拦住。PowerShell 的 `mkdir`、`New-Item`（可建符号链接与联接点）、`cp`、`mv`、`rm`、重定向、`tee`、`sed -i` 都不在其中 |
| `allow-project-file-writes` | allow | Write / Edit / MultiEdit / NotebookEdit 写项目内的文件（`path_inside_project`；`..` 走出项目、别的盘、解析不了的路径都不算）。上面所有保护名字的规则都比它严：守护进程自己的文件（deny），会让代码日后运行的文件、秘密、凭据、`.git`、agent 配置（ask） |
| `ask-python-tool-config-write`（strict：`deny-python-tool-config-write`） | ask（strict：deny） | 写（`access: write`，没有 `tool:` 限制）会让开发工具加载代码的配置文件：`mypy.ini`、`.mypy.ini`（`plugins =`）、`pylintrc`、`.pylintrc`、`pylintrc.toml`、`.pylintrc.toml`（`init-hook`、`load-plugins`）、`.flake8`（本地插件）、`.coveragerc`（插件）、`pytest.ini`、`.pytest.ini`、`pytest.toml`、`.pytest.toml`（pytest 9 也读；`addopts = -p ...`、rootdir）、`.pdbrc`（`pytest --pdb` / `--trace` 启动 pdb 时执行；X1 审查 M-1）。和 `ask-project-autorun-files` 同一个理由，单独成一条规则是因为一条规则的 `path_glob` 最多 64 项（那一条已满）。信任项目里的 dev-tool allow 规则绝不能在 agent 刚写的配置后面运行 |
| `ask-installed-package-dirs-write`（strict：`deny-installed-package-dirs-write`） | ask（strict：deny） | **X1 审查（M-2 的便宜缓解）。** 写 `**/.venv/**`、`**/venv/**`、`**/env/**`、`**/.tox/**`、`**/.nox/**`、`**/.conda/**`、`**/.pixi/**`、`**/.direnv/**`、`**/__pypackages__/**`、`**/site-packages/**`、`**/dist-packages/**`、`**/node_modules/**`（X1 复审 R-5 把清单从三项扩到这些；`access: write`，没有 `tool:` 限制；一个叫 `env` 的源码目录也会问，这是接受的误报）：已安装的代码不是项目自己的源码，改它们等于在一个没人读的库名下改 `pytest` 或任何被导入的包；包由包管理器（一条命令，不是文件写入）安装或升级，所以正常工作流不需要这个写入。否则 `allow-project-file-writes` 会放行（它们在项目内）。读它们照旧 |
| `allow-ps-data-shaping` | allow | **仅 default。** PowerShell 只整理管道内容、不带路径的 cmdlet：`Select-Object`、`Where-Object`、`Sort-Object`、`Group-Object`、`Format-Table`、`Format-List`、`Out-String`、`Out-Null`、`ConvertTo-Json`、`ConvertFrom-Json`（`paths_read_only`；排除 `-InputObject`：`Select-Object -InputObject $env:SECRET_TOKEN` 会原样打印它拿到的值）。上游命令单独判定，整行全是 allow 才 allow；以变量或表达式开头的管道整行灰色（`ps-pipeline-head-dynamic`），所以 `$env:SECRET_TOKEN \| Select-Object` 不是 allow。脚本块参数本来就灰色。**X1 审查（H-4）**：这些 cmdlet 以及 `Get-Location`、`Get-Date`、`Measure-Object` 与读类 cmdlet（`Get-Content`、`Select-String`、`Test-Path`、`Get-Item`、`Resolve-Path`、`Get-ChildItem`、`Set-Location`）的**参数里只要有展开**（`$env:TOKEN`、`"x$env:TOKEN"`、`${env:TOKEN}`、`$global:X`，`$true` / `$false` / `$null` 除外），且这个展开不是一个由路径层判断的路径，就是灰色 `ps-dynamic-arg`：`ConvertTo-Json $env:SECRET_TOKEN` 的第一个位置参数就是被排除的 `-InputObject`，会把值原样打印；`Select-Object -Property $env:SECRET_TOKEN` 把值当列标题打印；`Get-Date $env:X`、`Get-Content a.txt -TotalCount $env:X` 在报错里回显它。**不在其中**：`ForEach-Object`（脚本块）、`Out-File`、`Set-Content`、`Tee-Object`、`Export-*`（写文件）、`Invoke-*`（运行代码）、`Write-Output` |
| `allow-cd-family` | allow | **仅 default（M1c-3）。** 改工作目录的命令：Bash `cd`、`pushd`，PowerShell `Set-Location`、`Push-Location`（别名 `sl`、`chdir`、`cd`、`pushd` 在归一化层已是这两个规范名；`-Path`、`-LiteralPath`、`-PassThru`、`-StackName` 照常）。`cd` 只改目录：不读、不写、不运行、不联网，之前每一行 `Set-Location 'proj'; <任何命令>` 即使后面全是 allow 也整行灰色（一行要所有命令都是 allow 才 allow）。匹配条件：`paths_read_only` + **`path_inside_project`（目标必须已知在项目内；有意不放宽）**。原因：`git status`、`pwd` 这类**不带路径**的命令的工作目录来自前面的 cd，没有任何路径可供规则判断，若放行出项目的 cd，`cd ../other && git status` 会是 allow，而 `git -C ../other status` 是 ask（`ask-git-read-outside-project`），形成绕过。所以出项目、指向变量或命令替换或通配符（`cd $x`、`cd "$(pwd)"`、`cd *`）、`cd -`、光秃秃的 `cd`（回到主目录）、`popd` / `Pop-Location` / 不带参数的 `pushd`（没有路径可证明）都保持原状（灰色）。**cd 目标由谁判定：** 受保护的位置（`~/.ssh`、`~/.aws`、`.env`、凭据库）由已有的 deny / ask 规则通过 cd 携带的目录路径（read）判定，如 `cd ~/.ssh` 是 deny（`no-secret-read`），allow 规则不会削弱它们（最严者胜）；项目内的 `.git`、`.claude`、`certs` 目录本身没有规则保护（只有里面的文件有），cd 进去是 allow，但**之后的命令按新目录判定**：`cd .git && cat config` 是 deny（`no-credential-store-read`），`cd .. && cat .env` 是 deny（`no-secret-read`），`cd src && cat ../.env` 是 deny。`cd` 可能失败，所以旧目录与新目录同时保持可能：`cd src && cat ../README.md`（从项目根看 `..` 在项目外）灰色。带 `sudo` / `env` / `nohup` / `time` 的 cd、重定向（`cd src > out.txt`）、灰色动作（通配符、`HKLM:`、`-Credential`、未解析的参数）、`if` / `foreach` 等复合语句里的 cd 都不匹配。残余：cd 到项目外或未知目录、后面又是带路径未知的命令，整行仍是灰色或 ask；Bash 的 `cd a b`（两个参数）在 zsh 里是"替换"，归一化层只把第一个词当目标（建议以后在归一化层把多参数的 cd 标灰，见 `docs/reports/M1c3.md`）。strict 没有这条规则 |
| `allow-session-scratchpad` | allow | **仅 default（M1c-4）。** `tool: [Write, Edit, MultiEdit, NotebookEdit, Read, Grep, Glob]` + `path_in_scratchpad: true`：Claude Code 每个会话的 scratchpad（`<临时目录>/claude/<slug>/<会话 id>/scratchpad`）里的读写与搜索不再问，目录本身也算（`Grep` / `Glob` 的 `path`）。只认**当前会话**、**本机守护进程的临时目录**之下、`session_id` 是 UUID 的情形；其他会话、`scratchpad2`、临时目录及其上级、`..` 走出去的、含变量或通配符的、会话 id 缺失或畸形的、符号链接 / junction 指向别处的，一律不匹配。**Shell 工具（Bash、PowerShell）不在工具清单里**：`python <scratchpad>\x.py`、`cat <scratchpad>\x.py` 与以前完全一样（灰色）。所有 deny / ask 规则仍然最严者胜：`Write <scratchpad>\.env` 是 ask（`ask-secret-file-write`），`Read <scratchpad>\.env`、`Read <scratchpad>\id_rsa` 是 deny，`Write <scratchpad>\Makefile` / `package.json` / `conftest.py` 是 ask；`Grep` 目录时仍会扫描子树里的受保护名字。strict 没有这条规则。见"Session scratchpad"一节 |
| `ask-devtools-path-outside-project` | ask | **仅 default。** 下一行 allow 规则的搭档（模式同 `ask-shell-read-outside-project`）：dev 工具命令可以没有任何路径，所以 allow 规则不能要求 `path_inside_project`；这条让任何不能证明在项目内的路径（操作数、`-c` 文件、路径限定的 python 或工具本身的可执行文件）都 ask。程序清单与 allow 规则相同（有测试检查）。带 `project_trusted: true`，所以不信任的项目里它不出声（那里本来就没有 allow，命令是灰色）；无法判断项目时算命中。没有 `path_glob` / `access`，原因同上面的守卫规则 |
| `allow-devtools-trusted-project` | allow | **仅 default，且只在 `trusted_projects` 里的项目生效**（默认列表为空：没有项目被信任，这些命令仍是灰色 ask）。`pytest`、`ruff`、`mypy`、`black`、`isort`、`flake8`、`pylint`（也包括 `python -m 工具`、`.exe`、项目自己虚拟环境里按路径写的形式）。`flags_none` 就是 `programs.DEVTOOL_RISKY_FLAGS`（各工具的清单合并，有测试保证两边相等）。见"Dev-tools preset"一节 |

### 日常 allow 规则（M1c，仅 default）

default 加了上面这批 allow 规则，strict 没有（它的唯一 allow 规则仍是 `read-inside-project`；默认的 `emit_allow: false` 不变）。**`emit_allow` 关闭时 allow 的输出是"无决定"，Claude Code 自己的权限流程照常决定**：这些规则让 boundkeep 对"理解得很清楚的安全动作"不再多问一次，与 Claude Code 对齐，它们不替用户批准任何东西。保护名字的 deny / ask 规则仍然最严者胜；灰色动作与带 `sudo` / `env` / `nohup` 的动作永远不匹配 allow。

每条 Tier 1 规则都有 `paths_read_only: true`（每条路径的访问方式恰好是 `read`；`ls > f` 的重定向、`touch`、`git diff --output=f` 都带写路径，所以不匹配），读路径的程序再加 `path_inside_project`，并用 `flags_none` 排除程序里所有会写文件、运行东西、或读不在命令行上的文件的选项。git 排除的选项和理由：

| 排除的选项 | 理由 |
|---|---|
| `-c`、`--config-env` | 行内配置可以设 `core.pager`、`core.fsmonitor`、textconv、外部 diff：代码执行 |
| `-C`、`--git-dir`、`--work-tree` | 换了目录或仓库，路径不再已知 |
| `--exec-path` | git 子命令从那个目录运行 |
| `--paginate` | 启动配置里的分页器 |
| `--ext-diff`、`--textconv`（连同 git 接受的唯一前缀 `--ext`、`--ext-d`……、`--textc`、`--textco`、`--textcon`） | 运行 diff 驱动配置的程序 |
| `--output` | 把 diff 写进文件（它也会产生一条写路径） |
| `--no-index` | 比较磁盘上任意两个文件 |
| `--open-files-in-pager` | 启动程序（`git grep` 才有，这里不允许 grep，仍然列出） |
| `--ignore-revs-file` | git 读一个文件当作修订名，错误信息会引用其中的内容 |
| `--help` | 启动 man 手册查看器 |
| `--format`、`--pretty`、`--src-prefix`、`--dst-prefix`、`--line-prefix`、`--date`、`--sq-quote`、`--default`（`--form`、`--forma`、`--pret`、`--prett` 等缩写同） | 打印命令行上给的字符串，环境变量的值也在内（`git log --format=$TOKEN`）。代价：`git log --pretty=format:%h` 也要问，`--oneline`、`--stat`、`--name-only` 不受影响 |

`git branch` 另外排除 `-d` `-D` `--delete` `-m` `-M` `--move` `-c` `-C` `--copy` `-f` `--force` `-u` `--set-upstream-to` `--unset-upstream` `--edit-description` `--track` `--no-track`。

**没有放行的命令**：`python` / `node` / `npm` / `cargo` / `go` / `git` 的版本探测（`--version`；这些程序是 exec 程序，规则语言看不出后面没有别的参数）；`git stash`（含 `stash list`：看不见 `list` 位置参数，而 `git stash` 会存起你的改动）；光秃秃的 `git branch`；`git remote -v`（远程 URL 可能带令牌）；`git ls-files` / `grep` / `cat-file` / `describe` 等其余只读子命令（没有语料需要，可以以后加）；`du`、`date`、`printenv`；PowerShell 的 `New-Item`、`mkdir`、`touch`；`cp` / `mv` / `rm` / `sed -i` / `tee` / 重定向；带通配符的 `Select-String -Path src\*.py`（归一化层对通配符路径返回灰色，灰色永远不匹配 allow）。

**已知缺口，不会被这些规则消除**：
- 在**不可信的仓库**里，`git status` / `diff` / `log` / `show` 仍可能运行该仓库 `.git/config` 里配置的程序（`core.fsmonitor`、textconv、外部 diff 驱动、分页器）。这正是 `emit_allow` 必须保持关闭、并排除 `-c` / `--ext-diff` / `--textconv` / `--paginate` 的原因；仓库配置本身的风险没有消除。
- 环境变量前缀只有归一化层的"代码型"清单（`LD_PRELOAD`、`PAGER`、`GIT_PAGER`、`GIT_EXTERNAL_DIFF`、`GIT_CONFIG_*` ……）会变灰；`GIT_DIR=x git status`、`RIPGREP_CONFIG_PATH=x rg ...` 不在清单里（后者的配置文件可以写 `--pre=...`）。
- `git -p log`（全局的 paginate）与 `git log -p` 在匹配器眼里是同一个标志 `-p`，所以 `-p` 没有被排除。
- **参数里的环境变量。** 归一化层只在整个位置参数就是一个展开时才标灰色（`cat $FILE`），`--format=$TOKEN` 这样嵌在选项值里的展开看不见，而几乎每个程序都会在错误信息里回显非法的参数（`head -n $TOKEN f` 报 `invalid number of lines`）。能直接打印参数的选项已逐个排除（`find -printf`、`rg -r`、`git --format` / `--pretty` / `--date`、`ls --time-style`、`Get-Date -Format` ……），错误信息里的回显无法消除。（PowerShell 一侧的 allow 名单 cmdlet 已在 X1 审查后收紧：参数里的展开是灰色 `ps-dynamic-arg`，见 `allow-ps-data-shaping`；这一条缺口现在只剩 Bash 的选项值与 PowerShell 的其他 cmdlet。）另见：归一化层丢掉以变量开头的 PowerShell 管道元素（`$env:X \| Get-ChildItem` 把值当路径，错误信息回显它）。
- 不带路径的 `Get-ChildItem`、`Select-Object` 等也可能从管道接收字符串路径（`Get-Content list.txt \| Get-ChildItem` 会列出 list.txt 里写的目录，只泄露名字）。
- 写规则里的 `**`（`ask-write-outside-project`、`ask-find-delete`、`ask-git-discard-paths`）是 `access: write`，不进入递归读取的子树扫描；**读规则里不能有 `**`**：`pipeline.protected_read_globs`（子树扫描用的"受保护名字"）会把它当作名字，目录下的每一项都命中，扫描在第一层就停下，`certs/a.pem` 这样嵌套的受保护文件永远看不到。strict 的 `ask-read-outside-project` 原先正是 `path_glob: ["**"]` + `access: read`，因此在 strict 里对含 `certs/a.pem` 的项目目录做 `Grep` 会被放行（M1c 之前就有）；现在它只写 `path_outside_project: true`（任何不能证明在项目内的路径都问），有测试（`test_no_read_rule_has_a_catch_all_glob`、`test_a_recursive_read_still_finds_a_nested_secret`）。
- `allow-project-file-writes` 允许写项目内的任何普通文件，包括源码与测试：它们日后被运行时才会执行，这与 Claude Code 自己的行为一致。**例外（X1 审查）**：`.venv`、`site-packages`、`node_modules` 里的写入不再放行：它们是已安装的代码，不是项目自己的源码，改它们等于改 `pytest`、`ruff` 或任何被导入的库本身（`ask-installed-package-dirs-write`，strict 为 `deny-installed-package-dirs-write`）；读它们照旧。

### Dev-tools preset (trusted projects)

**A trusted project is one whose own code you let tools run without asking. Together with the Write/Edit allow rules this forms a write-then-run chain: a prompt injection that gets the agent to write a test file (tests/test_x.py is an ordinary project file) and run pytest executes that code unreviewed. Trust only repositories you wrote or audited; the session taint tracking planned for M3 is meant to tighten this.**

- **默认策略没有任何受信任的项目**（`trusted_projects` 缺省为空），所以默认用户完全不受影响：`pytest`、`ruff` 等仍是灰色（ask）。**strict 永远不放行**（它没有 dev-tool 规则，信任与否都一样）。
- **怎么开启**：在你自己的终端里运行 `boundkeep trust add`（在项目目录里，或 `--project-dir <目录>`）。这个命令在 stdin 不是终端时拒绝；在 Claude Code 启动的进程里（环境里有 `CLAUDECODE` 或 `CLAUDE_CODE_ENTRYPOINT`，子进程会继承）也拒绝，要在 Claude Code 之外的终端里运行；策略里的 `deny-boundkeep-state-commands` 也拒绝 agent 直接运行任何 `boundkeep trust ...`（含 `list`、`remove`）。
- **条目的范围（X1 审查 M-3）**：条目是"这个目录和它下面的一切"，所以往里 `git clone` 的任何仓库、在其中打开的任何会话也被信任。`trust add` 因此在目录**下面**（三层之内，最多 5000 个条目，不进 `.git`、`node_modules`、`.venv`、不跟随链接）发现别的仓库时列出它们并要求输入 `yes`，否则不写（目录本身没有 `.git` 只是提示一行）。主目录里的钥匙、设置与应用数据目录（`.ssh`、`.gnupg`、`.aws`、`.azure`、`.kube`、`.docker`、`.config`、`.claude`、`.boundkeep`、`.password-store`、`.terraform.d`、`.vscode`、`.cache`、`.local`、`AppData`、`Library` 及其下的一切）不能作为条目：**`trust add` 拒绝，`doctor` 对已经在列表里的条目警告并给出 `trust remove` 的提示；策略加载器不拒绝**（X1 复审 R-6：升级前写进策略的条目不能让整份策略加载失败、守护进程对每个事件都 ask；agent 本来就改不了策略文件，加载器这一道没有安全收益）。
- **推荐用法（X1 审查 M-2）**：见下面"已知缺口（响亮版）"：先写测试文件、再运行 pytest 这条链在受信任的项目里没有任何一步弹框，而规则看不到上一次调用写了什么。能收紧它的是 M3a 的会话污染位（读过网页或 MCP 结果之后，受信任项目的开发工具回到 ask），**在它存在之前，`trusted_projects` 保持默认关闭，不要把它当作推荐设置**（也不要写进面向用户的 README）；只对你写的或审计过的仓库开，并且知道这一点。`.venv` / `site-packages` / `node_modules` 的写入已经改成 ask（`ask-installed-package-dirs-write`）：这是这条链上唯一便宜且不伤正常工作流的一环。
- **会话快照（X1 审查 H-5）**：这三道检查都能被一个 agent 绕过（见上，终端检查拦不住它的子进程），所以守护进程另外对每个会话记下它**第一个事件**时的 `trusted_projects`：之后加进策略文件的条目**对那个会话不生效**，只对以后开始的会话生效（守护进程在日志里记一条 `trust-changed`，并在控制台提示）；删掉的条目立刻失效；没有可用 `session_id` 的事件没有任何受信任的项目。所以注入的会话不能给自己加信任；**你自己运行 `trust add` 之后，要新开一个会话才生效**。快照在内存里：守护进程重启后重新开始记（重启前不久加的条目会对重启后遇到的会话生效，这个限制要知道）。
- **怎么看**：`boundkeep trust list`（在你自己的终端里）和 `boundkeep doctor`（会列出受信任的项目，指出过期、被重定向或多余的条目）。
- **允许的形式**：`pytest`、`ruff`、`mypy`、`black`、`isort`、`flake8`、`pylint`，裸名、`.exe`、路径限定（项目自己的 `.venv\Scripts\ruff.exe`），或 `python [无害选项] -m <工具>`（`python` / `python3` / `python3.N` / `py`，无害选项是 `-I -u -B -E -s -S -q -O -OO`、`-X 项`、`-W 项`；**X1 审查 L-1**：`-X` 的值只认 `dev`、`utf8[=0|1]`、`faulthandler`、`importtime`、`tracemalloc[=N]`、`frozen_modules=on|off`、`int_max_str_digits=N`、`no_debug_ranges`、`warn_default_encoding`、`perf`、`cpu_count=N|default`、`gil=0|1`；`-W` 的值是 `动作[:消息[:类别[:模块[:行号]]]]`，类别含 `.`（一个会被导入的模块，`-W error::pkg.Cls`）就不行。`python -X pycache_prefix=<路径> -m pytest` 往任意目录写字节码，`-W` 的带点类别在启动时导入模块，所以它们不再是开发工具调用，退回普通的 `python` 调用）。**另外**，工具参数里出现盘符相对路径（`--debug=C:x`、`-oD:x`、`C:file.py`；是"那个盘当前目录"下的文件，路径层不认）是灰色 `devtool-drive-relative`。PowerShell 里的 `& '.\.venv\Scripts\ruff.exe' check .` 同样。归一化层对它们给出：程序名就是工具、已知、`exec` 标签、**没有灰色原因、没有包装器标记**，操作数是访问方式 `unknown` 的路径（这些工具可能写：`--fix`、`black`、`isort`、缓存），路径限定的工具或解释器的可执行文件作为读路径列出。
- **不放行的**：带包装器（`sudo pytest`、`uv run pytest`、`timeout 5 pytest`、`env X=1 pytest`、`nohup`）；带代码型环境变量前缀（`PYTHONPATH=...`、`PYTEST_ADDOPTS=...`、`PYTEST_PLUGINS`、`PYLINTRC`、`PATH` ……）；`python script.py`、`python -c`、`python -m pip install`、`node`、`npm test`；项目之外的解释器或工具（`C:\Python312\python.exe -m pytest`）；操作数在项目之外（`pytest ../other`）；操作数是秘密文件（`pytest .env`，deny）；同一行里先写文件再运行（`echo x > tests/test_x.py; pytest`：`exec-of-written-file`，灰色）；命令的项目不是受信任的那个（兄弟目录 `/home/a/proj-evil`、父目录、cwd 在项目之外）。
- **X1 复审的补充（R-1、R-5、R-8、R-11、R-12）**：（一）**`@` 展开之后**：`pytest -k "$u@args.txt"`、`-k ?args.txt`、`--select [@]r.txt` 在运行时才变成参数文件，字面文本不以 `@` 开头，所以靠统一机制：动作的 `dynamic_args`（见规则表上方"也不会匹配 `dynamic_args`"）让 allow 规则不匹配；开发工具的**通配符**词也算。（二）**路径限定的开发工具必须在虚拟环境目录里**（`.venv`、`venv`、`env`、`.tox`、`.nox`、`.conda`、`.pixi`、`.direnv`、`__pypackages__`）：`./pytest`、`bin/pytest`、`tools/ruff` 是 agent 可能写过的任意文件，仍按开发工具归一化（项目外的可执行文件仍被 `ask-devtools-path-outside-project` 问），但带包装器标记 `unvetted-exe`，所以没有 allow 规则匹配它。（三）`pytest --debug[=FILE]` 是写路径选项（argparse 的 `nargs='?'`：下一个词也被当文件名），裸文件名也当路径判断。（四）pytest 自己的 `-W` / `--pythonwarnings` 的值和 `python -W` 一样检查：带点的类别会被导入，灰色 `devtool-warning-filter`。（五）白名单里的环境变量名**连值一起检查**：`CI=1`、`LC_ALL=C.UTF-8`、`TZ=America/New_York` 可以；值是路径（`/x`、`../x`、`C:\x`）、含空格或引号或 `$` 的不行（glibc 会从 `LC_ALL=/dir` 的目录加载数据，`TZ=:路径` 读文件）。
- **X1 审查（M1c/M1c-2，H-1 到 H-3）加的三种灰色，不靠 `flags_none`，两种方言都一样**：
  - `devtool-argument-file`：工具的**任何**参数（位置参数、选项的值、`--` 之后）以 `@` 开头（`pytest '@args.txt'`、`ruff check @args.txt`、`mypy "@args.txt"`）。ruff、pytest、mypy 都从 `@文件` 读更多参数，文件里的 `--output-file`、`-p`、`--junitxml`、`--debug=` 不经过 `flags_none` 与路径规则。PowerShell 里不带引号的 `@args.txt` 是解析错误（本来就灰色），**带引号就是普通字符串**。
  - `devtool-output-format`：pylint 的 `--output-format` / `-f` 的值不是内置报告器名（`text parseable colorized json json2 msvs github`，可用逗号连接）。`--output-format=text:<路径>` 把输出写到任意文件，`--output-format=模块.类` 会导入那个类（等价于被禁止的 `--load-plugins`）。
  - `devtool-env-prefix:<名字>`（Bash 方言；PowerShell 没有行内环境变量前缀，`$env:X='…'; pytest` 本来就是复合语句、整行灰色）：工具命令前有 `NAME=value`，而 `NAME` 不在这个短名单里：`CI`、`NO_COLOR`、`FORCE_COLOR`、`CLICOLOR`、`CLICOLOR_FORCE`、`TERM`、`COLORTERM`、`COLUMNS`、`LINES`、`LANG`、`LANGUAGE`、`LC_*`、`TZ`、`PYTHONHASHSEED`、`PYTHONUTF8`、`PYTHONIOENCODING`、`PYTHONUNBUFFERED`、`PYTHONDONTWRITEBYTECODE`、`PYTHON_COLORS`、`PYTEST_DISABLE_PLUGIN_AUTOLOAD`。原来的"代码型环境变量"黑名单漏掉了把输出或缓存送到任意路径的变量（`RUFF_OUTPUT_FILE=~/.bashrc ruff check .`、`COVERAGE_FILE`、`RUFF_CACHE_DIR`、`PYTHONPYCACHEPREFIX`、`XDG_CACHE_HOME` ……）：路径规则看不到变量的值。
- **`flags_none` = `programs.DEVTOOL_RISKY_FLAGS`**（合并，下表按工具列出）：这些选项加载或运行命令行上点名的文件或代码，或把输出写到别处，保留为标志，任何一个出现都不放行（包括各种写法：`--flag=x`、`--flag x`、`-pX`、`-qpX`，以及长选项的唯一缩写，工具表会把缩写还原成全名）。

| 工具 | 排除的选项 |
|---|---|
| pytest | `-p`、`-c`、`--rootdir`、`--confcutdir`、`--basetemp`、`--junitxml`、`--cov-report`、`-o`、`--override-ini`、`--pdbcls`、`--cov-config`、`--log-file`、`--report-log`、`--html`、`--tx`、`--rsyncdir`、`--pastebin` |
| ruff | `--config`、`--output-file`、`--cache-dir` |
| mypy | `--config-file`、`--python-executable`、`--install-types`、`--non-interactive`、`--cache-dir`、`--junit-xml`、`--custom-typeshed-dir`、`--shadow-file`、`--report-dir` 以及各种 `--*-report` |
| black | `--config`、`--stdin-filename` |
| isort | `--settings-path`、`--settings-file`、`--sp`、`--virtual-env`、`--conda-env`、`--src` |
| flake8 | `--config`、`--append-config`、`--output-file` |
| pylint | `--rcfile`、`--load-plugins`、`--init-hook`、`--output`、`--source-roots`、`--extension-pkg-allow-list`、`--extension-pkg-whitelist` |

- 规则是**一条**，各工具的清单合并：副作用：某个工具的危险选项对七个工具一起生效，例如 `mypy -p 包名`（对 mypy 它只是包名）和 `pylint --src` 也会 ask，因为 `-p`、`--src` 在别的工具里是危险的。想精确可以拆成每工具一条规则（`DEVTOOL_RISKY_FLAGS` 本来就按工具分）。
- 仍然要问或拒绝的：操作数是密钥、凭据、`.claude/settings*.json`、`.boundkeep/**`、`.mcp.json`（deny）；操作数是 `Makefile`、`pyproject.toml`、`conftest.py`、CI 文件、`.git/**`、`mypy.ini` 等会运行代码的文件（ask，`ruff check --fix Makefile`、`black pyproject.toml`）；任何不在项目内的路径（`ask-devtools-path-outside-project`）；网络地址。
- **已知缺口（响亮版）**：规则看不到"上一次调用写了什么"。agent 先用 Write 写 `tests/test_x.py`（普通项目文件，`allow-project-file-writes` 放行），下一次调用再运行 `pytest`，这两步各自都是 allow：写后运行的链在跨调用时没有任何规则能拦住。只有同一行里的"写后运行"会被识别（`exec-of-written-file`）。所以只信任你自己写的或审计过的仓库；M3 计划的会话污点追踪才是真正收紧这条链的办法。`conftest.py`、`mypy.ini`、`pytest.ini` 等配置文件本身的写入是 ask。

**硬链接（X1 审查 H-6；M1 起是已知局限，现在有修法）**：硬链接是同一个文件的另一个名字，按名字判断的规则（`protect-guard-config`、凭据与秘密规则、`path_inside_project`）都看不到。两处修补：（一）路径层的磁盘解析（`resolve_on_disk`，每个路径本来就要 `realpath` 一次）现在对已存在的**普通文件**再读一次 `st_nlink`，大于 1 的路径带原因 `hard-linked`：它的 `inside_project` 不再是 `true`（变成"不确定"，`path_outside_project` 的 ask 规则会命中，所有 `path_inside_project` 的 allow 规则不再匹配），`in_scratchpad` 为 `false`；名字本身照旧交给 deny / ask 规则。这是一次多出来的 `stat`，不占用磁盘查询预算。代价：一个正好有多个名字的文件（pnpm 的 `node_modules`、`uv` 装进 `.venv` 的包、`git clone --local` 的对象）的读写会多问一次。（二）创建链接那一刻拒绝：`deny-link-to-guard-files`、`deny-link-copy-of-guard-files`（见规则表）。**（三）目录读（X1 复审 R-3）**：`Grep` / `Glob` / `rg` / `grep -r` 对目录的子树扫描（`normalize/subtree.py`）只比对名字，而硬链接名字普通（`notes.txt` → `~/.ssh/id_rsa`），所以扫描对每个**会被这个命令读的**普通文件也取 `st_nlink`（Windows 上 `DirEntry.stat()` 报告 0，要多一次 `os.stat`，约 5 微秒一个文件，时间预算因此从 0.2 秒提到 0.35 秒，条目上限 30000 不变），发现一个就给灰色 `recursive-scan-hardlink`（不判断它指向哪里）。被 Grep 的 `glob` 排除的文件和 `skip_names`（`.git` 等）不查。`Glob` 只列名字，不读内容，不受影响。代价：pnpm 的 `node_modules`、`uv` 装进 `.venv` 的包这类本来就有多个名字的树，对整个项目目录做 `Grep` 会变灰（问一次）；对子目录或带 `glob` 的 `Grep` 不受影响。没有解决的：链接已经存在、而用户之前已经批准了创建它（现在创建受保护文件的链接是 deny，不是 ask），或者链接是 boundkeep 之外的进程建的，那么对它的读写会因（一）变成 ask，而不是 deny。

**settings 文件的读与写保护不对称（有意如此，X1 复审 U-2）**：写保护覆盖所有 settings 文件（`**/.claude/settings*.json`、`~/.claude/settings*.json`，`protect-guard-config`）；读保护只覆盖真正放凭据的文件：`~/.claude/settings.json`、`~/.claude/settings.local.json`（含 WSL 看到的 `/mnt/c/Users/x/.claude/...`）和项目的 `.claude/settings.local.json`，外加 `.mcp.json`。**项目级 `.claude/settings.json` 可以读**：它通常提交进仓库，`init` 默认就把 hook 条目写在这里；如果把它读保护，每个受保护项目里没有 glob 的 `Grep`、`Glob **/*`、`grep -rn TODO .`、`ls -R` 都会被 deny（目录遍历命中受保护文件名）。代价：项目级 settings.json 里若有人写了令牌（`env` 块），agent 能读到；令牌应放 `settings.local.json` 或用户级文件。
`PowerShell` 工具的命令由辅助进程（Windows PowerShell 5.1 或 pwsh，只调用解析器、不执行任何用户文本）解析，结果和 Bash 一样是 Action 列表，命令类规则与路径规则同样适用。仍然灰色的构造见下一节。

### Session scratchpad（`path_in_scratchpad`，M1c-4，仅 default）

Claude Code 给每个会话一个只属于它的 scratchpad，agent 用它放中间文件：`<临时目录>/claude/<项目 slug>/<会话 id>/scratchpad`（Windows 例：`C:\Users\<用户>\AppData\Local\Temp\claude\e--bk-lab-m1b-proj\19513824-5f23-476c-bd11-f2f49fb38457\scratchpad`；slug 是项目路径把分隔符换成 `-`），hook 事件的 `session_id` 就是那个会话目录的名字。用户 60 天的真实会话里，首个路径在临时目录的 `Write` 544 次、`Read` 127 次、`Edit` 61 次都不是 allow，它们都是这个目录。

**精确地说什么算"在 scratchpad 里"**（归一化层，`PathRef.in_scratchpad`）：

- 事件的 `session_id` 必须存在且是 UUID 形状（`8-4-4-4-12` 个十六进制数字，大小写不限）；缺失、空白、带分隔符、`..`、`*`、过长或任何别的形状一律不标记。
- 根是 `<守护进程的临时目录>/claude/<恰好一段>/<session_id>/scratchpad`。临时目录取自归一化层拿到的环境（不看真实机器、不用 `tempfile`，所以 `boundkeep test` 的假机器是确定的）：Windows 取 `TEMP`，否则 `TMP`，否则 `%LOCALAPPDATA%\Temp`，否则 `<主目录>\AppData\Local\Temp`（变量名不分大小写；同名不同大小写又取值不同算"有疑问"：不标记）；POSIX 取 `TMPDIR`，否则 `/tmp`。临时目录必须是本机盘符路径或 POSIX 绝对路径（UNC、设备路径、相对路径、含变量的都不行）。假机器：Windows `C:\Users\testuser\AppData\Local\Temp`，POSIX `/tmp`。
- `claude`、`scratchpad` 两段在 Windows 风格里不分大小写，POSIX 里区分；会话 id 一段始终不分大小写。
- scratchpad 目录本身也标记（`Grep` / `Glob` 的 `path`）。它的上级（临时目录、`claude`、slug、会话目录）、别的会话、`scratchpad2`、`scratchpad.x`、`..` 折叠后走出去的路径、不确定的路径（变量、通配符、花括号、8.3 短名字、尾随点与空格的歧义写法、设备名）都**不**标记；`\\?\` 前缀与 NTFS 数据流先由已有的路径层规范化。
- **键入的形式与链接解析后的形式必须都在里面。** 一个路径可能产生两个 `PathRef`（字面的和 `resolve_on_disk` 之后的），匹配器要求每个都标记。scratchpad 里指向别处的符号链接或 junction，scratchpad 目录（或它的上级目录）自己是指向别处的链接，都让解析后的形式落到解析后的临时目录之外：不标记。临时目录本身是链接时，按解析后的临时目录比较。相对路径按事件的 `cwd` 走已有的相对路径逻辑。

**规则文本：**

```yaml
  - id: allow-session-scratchpad
    tool: [Write, Edit, MultiEdit, NotebookEdit, Read, Grep, Glob]
    match:
      path_in_scratchpad: true
    action: allow
```

**不覆盖 shell。** Bash 与 PowerShell 不在工具清单里，所以没有任何 shell 程序因为 scratchpad 而得到 allow；`python <scratchpad>\x.py` 仍是灰色的 exec。最严者胜：每条已有的 deny / ask 规则（密钥、凭据、`.git` 内部、自动运行文件、守护进程配置……）对 scratchpad 里的同名文件照样生效。测试 `tests/unit/test_m1c4_scratchpad.py` 用 m1c3-done 的策略做差分：所有反例的判决与该策略逐条相同，只有正例从灰色变成 allow。策略的 `tests:` 条目可以写 `session_id`（一个 UUID），scratchpad 的用例每个平台各写一份（路径含平台的临时目录）。

**残余风险：**

- agent 可以在 scratchpad 里写一个脚本（不再问），而**运行它仍由 exec 规则判定**（灰色，会问）。这一步没有放宽；但写与运行是两次调用，规则看不到它们的关系（与 `allow-project-file-writes` 同类，M3 的污染标记才是收紧办法）。
- 守护进程的临时目录可能与 Claude Code 的不同（例如守护进程以不同环境变量启动）。那样路径不在守护进程的临时目录下，规则**不适用**，一切保持原状，不会更宽松。路径本身用 8.3 短名字拼写的也不被认出（只有守护进程自己的 `TEMP` 写成短名字时，才会解析成长名字再比较）。
- 恶意项目无法用名字伪造：根必须在守护进程的临时目录之下，项目里叫 `claude\x\<id>\scratchpad` 的目录只是普通的项目内路径（有它自己的规则）。同一用户的其他进程能在临时目录下建同名目录，这在"同一用户的进程"信任边界之内。
- 检查与实际使用之间有时间差：解析在判定时做一次，之后有人把目录换成链接，规则看不到（与项目内规则的磁盘解析同一限制）。

## PowerShell 命令的规则写法

设计契约见 `docs/m1b-design.md`；这里只列写规则时要知道的事。

- 规则的 `tool` 写 `[Bash, PowerShell]`（或不写）；Windows 专属的程序放进同一条规则即可，不需要 `platform:`。
- **程序名**不区分大小写，并且是规范名：别名在匹配之前已被还原，所以 `rm`、`del`、`ri` 都是 `Remove-Item`，`ls`、`dir`、`gci` 都是 `Get-ChildItem`，`gc`、`cat`、`type` 都是 `Get-Content`。规则里写规范名（`Remove-Item`），不要写别名。外部程序取基本名（`curl.exe` → `curl`、`vssadmin.exe` → `vssadmin`）。
- **参数**：`flags_any` 写规范参数名（`-Recurse`，不区分大小写）；缩写（`-Rec`）和冒号写法（`-Path:x`）已被还原。git 等外部程序的标志照外部程序的规则。
- **子命令**：`net`、`net1`、`vssadmin`、`wevtutil`、`reg`、`sc`、`netsh`、`wmic` 的第一个纯字母词是 `subcommand`（`net user bob /add` 的 `user`）。`/add`、`/delete` 这类开关词会成为 flag，但 `flags_any` 的条目必须以 `-` 开头，所以不能直接匹配 `/add`：要靠子命令（`ask-net-account-changes`）或程序名。
- **注册表与提供程序路径**（`HKLM:`、`Env:` 等）不是文件路径，`path_glob` 匹配不到；目前只能按程序名（`Set-ItemProperty`、`New-ItemProperty`、`Remove-ItemProperty` 等都在 `windows-persistence-commands` 里）取舍。`Set-Item` / `New-Item` / `Remove-Item` 对注册表的操作没有规则，见 `docs/powershell-dialect.md` 的已知缺口。
- **灰色原因**以 `ps-` 开头，出现在审计日志的 `gray_reasons` 与 `boundkeep log` 里：`ps-helper-not-ready`（守护进程启动后头一两秒，辅助进程还在预热，所有 PowerShell 命令都 ask）、`ps-helper-timeout` / `ps-helper-crashed` / `ps-helper-busy` / `ps-helper-disabled` / `ps-helper-unavailable`、`ps-parse-error`、`ps-compound:<类型>`（`if`、`foreach`、函数、赋值等复合语句）、`ps-dynamic:<类型>` 与 `ps-dynamic-value:<类型>`（子表达式、脚本块、成员调用、类型转换）、`ps-dynamic-command-name`、`ps-param-unresolved:<cmdlet>:<参数>`、`ps-provider-path:<盘>`、`ps-dot-source`、`ps-encoded-command`、`ps-pipe-to-interpreter`、`ps-script-exec`、`ps-nested-shell`（`iex`、`Invoke-Command`、`Start-Process`、`powershell -c`、`cmd /c` 一类）。灰色的 Action 永远不会命中 allow 规则，但 deny / ask 规则仍按已知部分匹配。

已知限制：`Grep` 的 `path` 是目录时，策略只看到这个目录（项目内就放行），看不到目录里的 `.env`；`Glob` 只返回文件名，也不算读内容。这两类需要归一化层把 `glob` 参数当作路径（不属于策略）。

## 理由文字与运行时规则

- deny 的理由是 `boundkeep (<规则id>): <理由>`（多条规则时 id 用逗号连接）。所有理由（deny / ask / 灰色）都在 `pipeline._text` 里净化：控制字符、换行、bidi 控制符换成 `?`，每段截到 100 字符（灰色理由与程序名 80），整体 600；灰色理由里有攻击者可控的文字（`git-unknown-subcommand:<它敲的字>`）。写进审计日志的 `gray_reasons` / `programs` 同样净化。
- `runtime_policy_checked(policy, env, home) -> (Policy, 错误文字 | None)` 在设置了 `CLAUDE_CONFIG_DIR` 时给该目录加两条规则：写 `settings*.json` 的 deny（`protect-guard-config-dir`）和读 `.credentials.json`、`projects/**` 的 deny（`no-claude-config-dir-secret-read`）。目录名里的 `[`、`*`、`?` 会转义。它**从不抛异常**：相对路径、解析不了、超过 512 字符的 glob、任何意外都返回原策略和一条可打印的错误文字，由调用方（守护进程）记录。`runtime_policy` 只返回策略。