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

标量可以代替只有一个元素的列表（`program: git`）。`allow` 规则至少要有一个 match 字段（空的 match 会放行所列工具的一切）。

**路径规则不要写 `tool:`。** Read、Grep、Glob、Bash、PowerShell 等都会带路径，只列其中几个的读规则等于给其余的留了绕行的路（`Grep` 读 `.env` 曾因此被放行）。内置的所有读类 deny / ask 规则都没有 `tool:`，也没有 `platform:`：Windows 凭据、浏览器、持久化类的 glob 在纯 Linux 上本来就匹配不到任何东西，而 WSL 里看到的 `/mnt/c/Users/x/.ssh/config`（键 `c:/users/x/...`）要靠不依赖主目录的 `**/users/*/...` 写法拦住。

**`tool` 的校验。** 每个名字必须是已知工具（`Bash`、`PowerShell`、`Read`、`Write`、`Edit`、`MultiEdit`、`NotebookEdit`、`Glob`、`Grep`、`WebFetch`、`WebSearch`、`ToolSearch`、`TodoWrite`、`Agent`，以及 `Task`、`BashOutput`、`KillShell`、`ExitPlanMode`、`AskUserQuestion`、`Skill`、`SlashCommand`），或以 `mcp__` 开头，或是这些的前缀星号写法（`mcp__github__*`）。其余一律是加载错误并给出 "did you mean"（`Bsh` → `Bash`；大小写敏感）。只列了不碰路径的工具（`WebSearch`、`Agent` 等）却写了路径条件（`path_glob`、`access`、`path_outside_project`、`path_inside_project`）也是错误：规则永远不会命中。

### match 字段

| 字段 | 含义 |
|---|---|
| `path_glob` | 列表。该动作涉及的**任一**路径匹配**任一**模式即匹配。模式必须以 `/`、`**`、`~/` 或盘符（`c:/`）开头（锚定）；一律正斜杠；不区分大小写。永远匹配不到规范键的模式会被拒绝加载，见下 |
| `access` | `read` 或 `write`，需要和 `path_glob` 一起用。路径的访问方式等于它**或**为 `unknown`（可能读也可能写）时匹配 |
| `program` | 程序名列表。Bash 里区分大小写；PowerShell 不区分。程序名取基本名（`/bin/rm` → `rm`，`curl.exe` → `curl`），所以条目里不能有空格或路径分隔符（`rm`，不是 `/bin/rm` 或 `rm -rf`），否则加载报错 |
| `subcommand` | `git push` 的 `push`、`docker image push` 的 `push` 等；单个词，不能有空白 |
| `flags_any` | 标志列表，出现任一即匹配。合并短标志两种写法都有（`-rf` 同时给出 `-rf`、`-r`、`-f`），长标志去掉 `=值`。每个条目必须以 `-` 开头（PowerShell 参数 `-Recurse` 同样），否则加载报错（`force` 永远匹配不到） |
| `path_outside_project: true` | 任一路径**不能确定**在项目内（`inside_project` 为 false 或 null）即匹配；没有路径时不匹配。与 `path_glob` / `access` 同用时见下面的"同一条路径" |
| `path_inside_project: true` | 至少一个路径，且**每个**路径都**确定**在项目内。这是 allow 侧用的，不确定不算。不能和 `path_outside_project` 同写（永远不会命中，加载报错） |
| `network: true` | 该动作联网 |
| `domain_not_in` | 联网，且（目标域名未知，或**任一**域名不在列表里）。域名精确相等或是真正的子域才算"在" |
| `domain_in` | 联网，且域名非空且**每个**都在列表里 |
| `mcp_server` | MCP 工具的 server 名。**区分大小写**（`GitHub` 不是 `github`） |

所有布尔字段只能写 `true`，列表不能为空。**任何 match 字段、`tool`、`platform` 都不能写成 null**（`key:` 后面留空、`null`、`~`）：缺省才表示"不限"，一个悄悄等价于缺省的 null 会让 `path_inside_project:` 这样的笔误把 allow 规则放宽。加载时报 `rules[0].match.path_inside_project: ... is null`，带行号。

### 同一条路径（correlation）

`path_glob`（连同 `access`）与 `path_outside_project` 必须由**同一条路径**满足：这条路径匹配某个 glob、访问方式相容、并且不是确定在项目内。例如严格策略里的 `ask-write-outside-project`（`path_glob: ["**"]`、`access: write`、`path_outside_project: true`）对 `cp /tmp/src.txt ./dest.txt` 不再触发：项目外的 `/tmp/src.txt` 只是被读，被写的 `dest.txt` 在项目内。`path_inside_project` 仍然是"所有路径"；和 `path_glob` 同用时，再要求其中一条路径匹配 glob。只写 `path_outside_project` 时仍是"任一路径"。

### allow 规则与包装器

`allow` 规则永远不会匹配带 `wrappers`（`sudo`、`env X=1`、`nohup` 等被剥掉的前缀）的 Action，也不会匹配灰色 Action：`sudo ls` 与 `ls` 不是同一个动作，不能搭 `allow program: ls` 的便车。deny / ask 规则仍按已知部分匹配这两类 Action。

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

`expect` 取 `deny | ask | allow | gray`（`gray` = 规则层不应定案，用来防止规则过宽）。`boundkeep test [--policy 文件] [--platform windows|posix|all]` 用**假机器**（Windows：`C:\Users\testuser`，POSIX：`/home/testuser`）跑真实的管线，所以 Windows 路径的用例在任何平台都能通过；默认两个平台都跑。

`boundkeep explain <事件.json|->` 用**本机的真实环境**（你的主目录与环境变量、事件里的 `cwd` 与 `project_dir`）解释一个事件：每个动作的程序、路径（规范键与 `inside_project`）、域名、风险标签、命中的规则、最终判决和 hook 实际会输出什么。

## 内置策略里的规则

每条规则的理由都写在 `policies/default.yaml` 的注释里（独立于任何数据集）。`strict.yaml` 里"ask"的持久化与配置类规则改为 deny（规则名 `ask-` 改 `deny-`），另有若干更严的规则（见文件头）。概览：

| 规则 | 动作 | 内容 |
|---|---|---|
| `protect-guard-config` | deny | 写 `.claude/settings*.json`、`.boundkeep/**`、`.claude` 目录本身与 `~/.claude`（删除、改名、移动、覆盖都算写）、`managed-settings.json`、`managed-settings.d/**` |
| `deny-boundkeep-state-commands` | deny | `boundkeep` / `boundkeep-hook` 的 `mode`、`uninstall`、`init`、`serve`（**依赖归一化层报告 boundkeep 的子命令，见下文"程序命令行规则"**） |
| `deny-boundkeep-state-flags` | deny | `boundkeep` / `boundkeep-hook` 带 `--reset-policy`、`--purge`、`--python`、`--hook-style`、`--rotate-endpoint`、`--home`（按标志即可匹配，现在就生效） |
| `deny-boundkeep-hook-run` | deny | 手工运行 `boundkeep-hook` |
| `ask-boundkeep-cli` | ask | `boundkeep` 其余命令（`doctor`、`test`、`explain`、`log --tail`、`llm`）；这些是给用户自己终端用的，ask 让确认框里有带 boundkeep 字样的理由 |
| `ask-claude-cli`（strict 另有 `deny-claude-cli-flags`） | ask（strict：带 `--settings` / `--permission-mode` / `--dangerously-skip-permissions` 为 deny） | 任何 `claude ...`：`config set` 改权限与 hooks、嵌套会话可能不在本闸门之内 |
| `ask-kill-processes` | ask | `taskkill`、`pkill`、`killall`、`kill`、`Stop-Process`、`Stop-Service`（目标是参数，规则语言匹配不了，所以一律问） |
| `ask-package-uninstall`（strict：`deny-package-uninstall`） | ask（strict：deny） | `pip` / `pip3[.x]` / `pipx` / `python[3[.x]] -m pip` 的 `uninstall`、`uninstall-all`（包名是参数，匹配不了，所以任何卸载都问） |
| `ask-guard-state-read` | ask | 读 `.boundkeep/**`（`endpoint.json`、`policy.yaml`、`logs/audit.jsonl`） |
| `ask-agent-exec-config` | ask | 写 `.mcp.json`、`~/.claude.json`、`.claude/{hooks,commands,agents,skills,rules,output-styles,plugins}/**`、`.claude/statusline.*`、`CLAUDE.md`、`CLAUDE.local.md` |
| `ask-repo-exec-config` | ask | 写 `.git/hooks/**`、`.git/config`、`.envrc`、`.husky/**`、`.vscode/{tasks,settings,launch}.json`、`.github/workflows/**`、`.devcontainer/**` |
| `ask-user-config-write` | ask | 写 `~/.gitconfig`、`~/.npmrc`、`~/.pypirc`、`~/.config/pip/pip.conf`、`~/.netrc`、`~/.docker/config.json` |
| `no-secret-read` | deny | 读 `.env`、`.env.*`、`*.env`、名为 `env` 的文件、`.envs/**`、`**/.ssh/**`、`*.pem`、`*.key`、`*.jks`、`*.keystore`、`*.tfstate*`、`*.tfvars`、`service-account*.json`、`credentials.json` / `credentials.txt`、`secrets.{yml,yaml,json,toml,txt}`、`secret.txt`、`key.txt` / `keys.txt`、`password(s).txt`、`token.txt`、`.htpasswd`、`kubeconfig`、`*.kubeconfig`、`local.settings.json`、`*.kdbx` / `*.kdb`、`/etc/shadow*`、`/etc/sudoers*`、`/etc/ssh/ssh_host_*`、`/proc/*/environ`。名字整体匹配，所以 `env.py`、`kubeconfig.go`、`docker-compose.yml`、`README` 仍可读 |
| `no-credential-store-read` | deny | 读云 CLI 与容器配置（`.aws`、`.azure`、gcloud、gh、op、doctl、rclone、kube、docker）、`.gnupg`、`.git-credentials`、`.git/credentials`、`.config/git/credentials`、`.gitconfig`、`.git/config`、`.netrc` / `_netrc`、`.npmrc`、`.pypirc`、`.pgpass`、`.my.cnf`、`.s3cfg`、`.boto`、`.vault-token`、`.cargo/credentials*`、`.gem/credentials`、`.m2/settings.xml`、Terraform 凭据、GitHub CLI 与 gcloud 的 `%APPDATA%` 目录、私钥文件（`id_rsa*`、`id_ed25519*` 等，含 `.bak` 备份；代价是公钥 `id_rsa.pub` 也读不了） |
| `no-agent-state-read` | deny | 读 `~/.claude/.credentials.json`、`~/.claude.json`、`.claude/settings*.json`（项目与用户级；`env` 块里常放令牌）、`.mcp.json`（MCP 服务器的 headers 与 env）、`.claude/projects/**`（会话记录）、`history.jsonl`、`shell-snapshots`、`ide` |
| `no-history-read` | deny | 读 `.bash_history`、`.zsh_history`、`.python_history`、`.psql_history`、`.mysql_history`、PSReadLine 的 `ConsoleHost_history.txt` 等 |
| `no-windows-credential-read` / `no-browser-profile-read` | deny | Windows 凭据、DPAPI、保险库、`System32\config`、`windows\repair`；Windows / Linux / macOS 浏览器配置目录与钥匙串。都含 `**/users/*/...` 形式，WSL 看到的 `/mnt/c/Users/x/...` 也被拦 |
| `no-raw-disk-access` | deny | 读写 `/dev/sd*`、`nvme*`、`mmcblk*`、`/dev/mem`、`\\.\PhysicalDrive*` 等裸设备 |
| `protect-windows-persistence`、`windows-persistence-commands` | ask | PowerShell profile（含 OneDrive 重定向后的 Documents）、启动文件夹、`schtasks` / `reg` / `sc`（含 WSL 里的 `reg.exe`）；按程序名：计划任务与计划作业、服务、注册表属性写入（含 `Copy/Move/Rename/Clear-ItemProperty`）、WMI/CIM 实例、本地用户与组、防火墙规则与设置、Defender 排除项、`Clear-EventLog`、`setx`、`vssadmin`、`wevtutil`、`takeown`、`cipher`、`Stop-Computer` / `Restart-Computer` |
| `ask-net-account-changes` | ask | `net` / `net1` 的 `user`、`localgroup`、`group`、`share`、`stop`、`start`、`accounts`、`config`（建账号、提权限、改密码、共享、控制服务） |
| `protect-shell-startup-files`、`ask-system-config-write`、`ask-scheduled-jobs`、`ask-user-services`、`ask-launchctl` | ask | `.bashrc` / `.zshrc` / autostart / systemd 用户单元 / `~/.local/bin`；写 `/etc/**` 等系统配置；`crontab` / `at` / `systemd-run`；`systemctl --user`；`launchctl` |
| `ask-ssh-write` | ask | 写 `.ssh` |
| `ask-privilege-escalation` | ask | `su` / `sudo` / `doas` / `pkexec` 作为程序出现（被剥掉的 `sudo` 看里面的命令） |
| `rm-outside-project` | deny | 递归删除项目之外的路径 |
| `ask-delete-outside-project` | ask | 删除项目之外的单个文件 |
| `git-force-push` | ask | `--force`、`--force-with-lease`、`+refspec`、`--mirror`、`--delete` 的 push |
| `ask-git-reset-hard`、`ask-git-clean-force`、`ask-git-discard-paths`、`ask-git-branch-force-delete`、`ask-git-rewrite-history` | ask | `git reset --hard`、`git clean -f`、`git checkout -- <路径>` 与 `git restore <路径>`（`--staged` 也会问：规则语言不能排除标志）、`git branch -D`、`filter-branch` / `filter-repo` |
| `ask-docker-prune` | ask | `docker system/volume/image prune` |
| `ask-find-delete` | ask | `find ... -delete`（默认只在项目之外；strict 一律） |
| `ask-disk-tools` | ask | `mkfs*`、`wipefs`、`fdisk`、`parted`、`diskpart` 等（strict：deny） |
| `ask-recursive-permission-change` | ask | `chmod -R` / `chown -R` / `chgrp -R` 项目之外（strict 一律） |
| `net-allowlist` | ask | 访问 pypi.org、files.pythonhosted.org、github.com、registry.npmjs.org 之外的主机（目标未知也算） |
| `read-inside-project` | allow | `Read` / `Glob` / `Grep` 且路径确定在项目内（唯一的 allow 规则） |

`PowerShell` 工具的命令由辅助进程（Windows PowerShell 5.1 或 pwsh，只调用解析器、不执行任何用户文本）解析，结果和 Bash 一样是 Action 列表，命令类规则与路径规则同样适用。仍然灰色的构造见下一节。

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