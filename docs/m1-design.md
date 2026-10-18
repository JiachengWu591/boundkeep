# M1 设计契约（实现者先读这份）

M1 把 M0 的占位判定换成 **normalize → rules → 取最严 → 灰色 ask**。本文档是各模块之间的契约；语义的权威来源是 `PROJECT_SPEC.md` §5.1（路径与方言）、§7（判定管线、Action）、§8（策略格式）与 §7 里"M1 的澄清"。

```
hook 事件 ─> normalize_event ──> [Action, ...] ──> policy.evaluate ──> Verdict ──> hook 输出（M0 的 render）
              │  bash.parse_bash        (语法：只切词，不懂语义)
              │  programs.classify      (语义：程序、子命令、标志、路径参数、联网)
              │  paths.normalize_path   (路径规范化，词法层 + 文件系统层)
              └  domains.canonical_host (域名与 IP)
```

## 底线（所有模块）

- **不能崩**：任意输入（含孤立代理项、NUL、几 MB 长的串、深嵌套）要么给出结构化结果，要么给出灰色；不抛未处理的异常。每个解析入口都有长度、token 数、嵌套深度的上限，超限即灰色。**时间复杂度线性或近线性**：不得有可被构造成指数回溯的正则。
- **宁可灰色，不可误放**：任何无法确定的情形都不推断为安全。解析器与归一化器**永不**产生"放行"的信号，只产生信息；放行只来自策略里显式的 allow 规则。
- **纯函数**：词法层与匹配不碰文件系统、不读环境（环境经参数传入）。文件系统层单独一个函数。
- **不用正则去匹配整条命令串来决定放行。**
- 文本 I/O 显式 `encoding="utf-8"`；Windows 语义用 `ntpath` / `posixpath` 显式选择，不用当前平台默认的 `os.path`；测试在 Windows 与 Linux 都要过（Linux 用 Docker 容器验证）。
- 类型：`mypy --strict` 通过（`normalize` 与 `policy` 包）；`ruff` 通过；每个公开函数有 docstring 说明语义与失败行为。
- 不引入新依赖。不要提交（commit）任何东西；只动你负责的文件。

## 数据模型

`src/boundkeep/normalize/model.py` 已经写好（`Word`、`Redirect`、`SimpleCmd`、`BashResult`、`PathRef`、`Action`）。**不要改它**；需要改动就在报告里提出。

## 模块 A：`normalize/paths.py`（路径规范化）

```python
@dataclass(frozen=True, slots=True)
class NormPath:
    raw: str
    key: str                    # 规范比较键，见下
    flavor: Literal["windows", "posix"]
    absolute: bool
    uncertain: bool             # 无法知道真实目标：未解析变量、通配符、驱动器相对路径、设备名、…
    reasons: tuple[str, ...]    # 为什么不确定或特殊，稳定的短标记，如 "unresolved-variable:FOO"、"glob"、"drive-relative"、"device:NUL"、"ads-stripped"、"msys-translated"、"git-bash-root"、"short-name-unresolved"、"unc"
    is_device: bool = False

def normalize_path(raw: str, *, cwd: str | None, home: str | None,
                   env: Mapping[str, str] | None = None,
                   dialect: Literal["bash", "powershell", "tool"] = "tool") -> NormPath
def inside_project(path: NormPath, project_root: NormPath | None) -> bool | None   # True / False / None
def resolve_on_disk(path: NormPath) -> NormPath    # 文件系统层：本机，realpath，展开链接/联接点/8.3 短名，绝不抛异常，失败原样返回
def key_of_home(home: str) -> str                   # 给策略加载用：把 home 目录转成 key
```

**key 的格式**（策略的 `path_glob` 与 `inside_project` 都按 key 比较）：
- 一律正斜杠，折叠 `.`、`..` 与重复分隔符，无尾随斜杠（根除外）。
- Windows 风格路径（盘符、反斜杠、UNC、`\\?\`、`\\.\` 前缀，或 `dialect` 为 powershell / tool 且明显是 Windows 形式）：盘符小写 + `:/`，整条 `casefold`，例如 `c:/users/bob/.ssh/id_rsa`；UNC 为 `//server/share/...`；设备名为 `//./nul` 一类。
- POSIX 风格路径：保持大小写，例如 `/home/dev/proj/a.py`。
- `inside_project` 的前缀判断必须按路径段边界（`/proj` 不是 `/proj2` 的前缀），Windows 风格不区分大小写（key 已 casefold），POSIX 风格区分。

**必须处理**（规格 §5.1 与 M1 提示词）：展开 `~`、`$HOME`、`${HOME}`、`%USERPROFILE%`、`$env:USERPROFILE`、`%APPDATA%`、`%LOCALAPPDATA%`、`%TEMP%`、`$PWD` 等（取自 `env` 与 `home`/`cwd` 参数；未知变量 → `uncertain`）；统一分隔符；去掉 `\\?\` 与 `\\.\` 前缀（`\\?\UNC\srv\share` → UNC）；NTFS 备用数据流后缀（`:stream`、`::$DATA`）；尾随的点与空格（每一段）；折叠 `..`（不能折叠出根之外：`C:\..\..\x` → `c:/x`）；驱动器相对路径（`C:foo`，`uncertain`）；UNC；设备名（`NUL`、`CON`、`PRN`、`AUX`、`COM1`–`COM9`、`LPT1`–`LPT9`，含带扩展名的 `NUL.txt`，`is_device`，不算项目内）；MSYS（`/c/Users/x`）、`/cygdrive/c/...` 与 WSL 的 `/mnt/c/...` 翻译为 Windows 路径；Git Bash 的 `/`、`/usr`、`/tmp`、`/home` 等无法可靠映射 → `uncertain`（按项目外处理）；8.3 短名（`PROGRA~1`）在词法层无法展开 → 标 `short-name-unresolved` 并 `uncertain`（文件系统层才能展开）；相对路径按 `cwd` 解析（`cwd` 为 None 则 `uncertain`）；全角与组合字符、Unicode 同形字不做"修复"（保持原样，不误判为同一路径）；空串与纯空白 → `uncertain`。
**方向规则**：`inside_project` 只有在**确定**在内时才返回 True；无法确定（`uncertain`、项目根为 None、不同盘符/不同 flavor）返回 None；确定在外返回 False。

## 模块 B：`normalize/bash.py`（保守的 Bash 解析器）

```python
def parse_bash(command: str, *, max_depth: int = 8, max_words: int = 4000,
               max_length: int = 1 << 20) -> BashResult
```
**不用 bashlex**（GPLv3+，与 MIT 冲突）。自写词法加递归下降，只做 `BashResult` 要的事：把命令行切成简单命令，保留每个词的"是否含展开 / 通配符 / 引号"信息。

**必须处理**：单引号、双引号（含其中的 `$`、反引号、`\` 转义）、`$'...'`、`$"..."`、反斜杠转义与续行；`| |& || && ; & 换行`；重定向（`> >> < << <<< <> >| &> &>> n> n>&m`，目标作为 `Word`；here-doc 的分隔符与正文：正文**不是**命令，除非 here-doc 喂给解释器（`bash <<EOF`、`python - <<EOF`、`sh`、`zsh`、`perl`、`ruby`、`node` 等）→ 加 `exec_reasons` 与 `gray`）；子 shell `( ... )`、`{ ...; }`；命令替换 `$( ... )` 与反引号（内部命令**递归解析**并加入 `commands`，`origin="substitution"`，含替换的词 `expands=True`）；前缀赋值 `A=1 B=2 cmd`；`NAME=value` 独占一条命令（只赋值）。
**包装器**（从 `argv` 剥掉并记入 `wrappers`，可嵌套）：`sudo`（含 `-u user`、`-E`、`--` 等常见选项）、`doas`、`env`（含 `-i`、`-u`、`NAME=v`）、`nohup`、`time`、`command`、`builtin`、`exec`、`nice`、`ionice`、`timeout`（带时长参数）、`stdbuf`、`setsid`、`xargs`（`args_from_stdin=True`，剥掉其选项如 `-0 -I{} -n1 -P4`；剥选项时遇到不认识的选项 → 加 `gray`）。选项参数的剥法不确定时宁可灰色。
**递归**：`bash -c "..."`、`sh -c`、`zsh -c`、`dash -c`、`ksh -c`（含 `-lc`、`-ec` 等合并标志、`--` ）的字符串参数按命令行递归解析，`origin="bash-c"`，深度超过 `max_depth` → `gray`。
**灰色（加入 `BashResult.gray`，并尽量仍返回已解析出的命令）**：`if/then/elif/else/fi`、`for/while/until/do/done`、`case/esac`、`select`、`function` 与 `name() {`、`[[ ]]`、`(( ))` 算术、`$(( ))`、数组与关联数组赋值、进程替换 `<( )` `>( )`、花括号展开（含逗号或 `..` 的 `{a,b}`、`{1..3}`）、`coproc`、`!` 取反、`trap`、`alias` 展开风险（别名无法知道，不处理）、未闭合的引号/括号/here-doc、`\x00` NUL、超长或超词数、深度超限。**`exec_reasons`**：`eval`、`source`/`.` 一个文件、`python -c`、`python3 -c`、`node -e`、`perl -e`、`ruby -e`、`php -r`、`bash -s`、`curl ... | sh`（管道末端是解释器：`sh bash zsh dash ksh python* node perl ruby php pwsh powershell cmd`）、`base64 -d | bash`、`xargs sh -c`、`find ... -exec`/`-execdir`/`-ok`（后面接命令，按 `exec` 处理并灰色）。
**不要做**：不展开变量（`$X` 原样留在 `Word.text`，`expands=True`）；不做通配符展开；不"修复"Windows 路径（反斜杠按 Bash 语义是转义）；不判断命令是否危险（那是策略的事）。
解析器**必须对任意输入返回 `BashResult` 而不抛异常**；任何内部错误 → `gray=("internal-error",)`。

## 模块 E：`normalize/programs.py` 与 `normalize/domains.py`

```python
# domains.py
@dataclass(frozen=True, slots=True)
class Host:
    name: str                   # 规范化：小写、去尾随点、IDN→punycode、IP 规范化（十进制/十六进制/八进制 IPv4 写法还原为点分，IPv6 去括号压缩）
    kind: Literal["domain", "ip", "localhost", "unknown"]
    raw: str
def canonical_host(raw: str) -> Host | None           # 单个 host[:port] 或 URL 的 authority；去 userinfo（user:pw@）、端口、尾随点
def extract_hosts(text: str) -> tuple[Host, ...]       # 从一个参数里找出 URL（http/https/ftp/ssh/git/scp 形 user@host:path/ git@host:org/repo）
def host_matches(host: Host, allowed: Sequence[str]) -> bool   # 精确相等或真正的子域；"evilgithub.com"、"github.com.evil.com"、"github.com@evil.com" 都不匹配 "github.com"

# programs.py
@dataclass(frozen=True, slots=True)
class CmdInfo:
    known: bool
    subcommand: str | None
    flags: tuple[str, ...]      # 含合并短标志的两种写法：-rf → "-rf","-r","-f"；长标志去掉 =值（--force=1 → --force）；PowerShell 参数名保持原样大小写，匹配时由策略做不区分大小写比较
    paths: tuple[tuple[Word, Access], ...]     # 哪些参数是文件路径、怎么访问
    urls: tuple[str, ...]       # 原始 URL / host 字符串，交给 domains 处理
    network: bool
    tags: tuple[RiskTag, ...]
    gray: tuple[str, ...]       # 无法理解的原因（含动态词 expands/glob 出现在关键位置）
def classify(program: str, args: Sequence[Word], *, shell: Shell, redirects: Sequence[Redirect] = ()) -> CmdInfo
```
`classify` 的知识表要覆盖（M1 提示词）：**文件读**（cat、less、more、head、tail、grep/rg/ag、wc、sort、cut、awk/sed（无 `-i`）、diff、file、stat、ls、find、tree、xxd、od、strings、source…）、**写**（cp、mv、rm、rmdir、touch、mkdir、tee、dd of=、sed -i、chmod、chown、ln、truncate、install、rsync 目的端、重定向 `>`/`>>` 的目标、`tar` 的 `-C`/`-f` 方向、`unzip -d`）、**联网**（curl、wget、git clone/fetch/pull/push/ls-remote、pip install/download、npm/yarn/pnpm install/publish、npx、docker pull/push/run、ssh、scp、rsync 远端、nc/ncat/telnet、ftp、gh）以及代理参数（`-x`、`--proxy`、`http_proxy=`）、**git** 子命令提取（跳过 `-C dir`、`-c k=v`、`--git-dir=`、`--work-tree=` 这类全局选项，`-C dir` 的目录算作路径参数）、`cd`（本身不是风险；`classify` 对 `cd` 返回 `paths=((目录, "read"),)`，`cd` 之后同一命令行里相对路径的基准由调用方处理）。`risk_tags` 推导（`network_egress`、`file_write`、`exec`、`secret_access`、`config_tamper`）**集中在 `programs.py` 的一个函数里**，便于审计。**未知程序**：`known=False`，所有看起来像路径的参数（含 `/`、`\`、`~`、盘符、以 `.` 开头）作为 `(word, "unknown")` 路径，看起来像 URL 的进 `urls`；`PowerShell` 的 `shell="powershell"` 在 M1 一律不会被调用（整条灰色），但表里留好接口。
关键边界：参数含 `expands=True` 或 `glob=True` 的词出现在路径位置 → 该路径仍列出（由路径层标 uncertain），不要丢弃；`--` 之后全是位置参数；`-f=value`、`--opt value` 与 `--opt=value` 的区别按程序表处理，不确定时把后随词也当成可能的路径（宁可多列）。

## 模块 D：策略（`policy/` 扩展）

沿用 M0 的 `policy/schema.py`、`loader.py`（`mode` 行编辑、`default_policy_text()`、`taint_sources_to_matcher` 等**不得破坏**，M0 的测试必须继续通过；只有 `version`/`mode`/`defaults`/`taint` 的 M0 格式文件仍合法，`rules` 缺省为空）。

扩展 `Policy`：`llm_audit`（只校验结构，不实现后端：`backend: none|openai_compatible|anthropic`、`timeout_ms`、`on_failure: ask|deny`（**不允许 allow**）、`send_task_intent`、`cache_ttl_s`、两个后端子块；**任何字符串值形似密钥时拒绝加载**，如 `sk-…`、`AKIA…`、`ghp_…`、私钥块、长随机串紧跟在 key/token 名后）、`rules: tuple[Rule, ...]`、`tests: tuple[PolicyTest, ...]`。全部 `extra=forbid`、strict、frozen；错误信息要指出**行号与字段路径**（用 PyYAML 的 node marks：自己写一个带位置的 loader，仍然是 `safe_load` 级别的安全，不构造任意对象，拒绝重复键与别名/锚点炸弹）。

`Rule`：`id`（唯一，`[a-z0-9-]+`）、`tool: list[str]`（支持 `mcp__*` 这种前缀星号；不写 = 全部工具）、`platform: list[posix|windows]` 可选、`match`、`action: deny|ask|allow`、`reason`（deny/ask 必填）。`match` 的字段：`path_glob`（列表）、`access: read|write`、`program`、`subcommand`、`flags_any`、`path_outside_project: bool`、`path_inside_project: bool`、`network: bool`、`domain_not_in`、`domain_in`、`mcp_server`。**未知字段报错**。`PolicyTest`：`tool`、`input`（hook 的 `tool_input`）、`platform` 可选（列表）、`cwd`/`project_dir` 可选、`expect: deny|ask|allow|gray`。

**匹配语义**（纯函数 `match_rule(rule, action, *, platform) -> bool`）：
- 字段间 AND、列表内 OR；`tool` 与 `platform` 先过滤。
- `program`：shell 为 bash 时精确比较（区分大小写）；powershell 时不区分大小写。`subcommand`、`flags_any`：flags 精确比较（PowerShell 参数名不区分大小写）。
- `path_glob`：`Action.paths` 中**任一** `PathRef.key` 匹配**任一** glob（deny/ask 侧**不区分大小写**：把 key 与 glob 都 casefold 后比较）；`access` 给定时，`PathRef.access` 必须等于它**或**为 `unknown`（unknown = 可能读也可能写，"可能匹配即匹配"）。glob 语法：`**` 跨目录、`*` 不跨 `/`、`?`、`[...]`；一律正斜杠；`~/` 在**加载时**展开（`loader` 接受 `home` 参数，用 `paths.key_of_home`）；glob 编译时做长度/复杂度限制，匹配是线性的（不得用可指数回溯的构造；可自写迭代匹配）。
- `path_outside_project: true`：**任一** path 的 `inside_project is not True`（即 False 或 None）时匹配；没有 path 时不匹配。`path_inside_project: true`：至少一个 path 且**每个** path 的 `inside_project is True` 才匹配（allow 侧，确定才算）。
- `network: true`：`Action.network`。`domain_not_in`：`network` 且（`domains` 为空——不知道去哪——或**任一** domain 不在列表里）；`domain_in` 相反（`domains` 非空且**每个**都在列表里）。域名比较用 `domains.host_matches` 的同一语义（精确或真子域）。
- **gray 的 Action**（`Action.gray=True`）：deny/ask 规则仍按已知部分匹配；**allow 规则永不匹配 gray 的 Action**。

**合并**（`evaluate(policy, actions, *, platform) -> Verdict`）：对每个 Action 取命中规则中最严者（deny > ask > allow）；未命中 = gray。整体：任一 deny → deny；否则任一 ask → ask；否则任一 gray（含 `Action.gray`）→ gray；只有**全部** allow → allow；`actions` 为空 → gray。`Verdict` 含 `decision`（deny|ask|allow|gray）、`reasons`、`rule_ids`、每个 Action 的明细（供 `explain` 与审计）。同一动作的取最严要写专门的测试。内置规则 `m0-canary`（`BOUNDKEEP_CANARY` 出现在 `command_text` 里 → deny）作为**始终最先评估**的内置规则，由 `evaluate` 实现，不写进 YAML。

交付 `policies/default.yaml`（按规格 §8 的规则集：protect-guard-config、no-secret-read、rm-outside-project、git-force-push、net-allowlist、read-inside-project、protect-windows-persistence，并补充你认为必要的 Windows 凭据与浏览器配置目录规则；**每条规则的注释里写明独立于任何数据集的理由**）与 `policies/strict.yaml`（更严：例如 net-allowlist 去掉 pypi 以外、写项目外一律 ask、网络一律 ask）。`tests:` 部分先按规格写，可能要等我把整条管线接上后再核对，你的测试用手工构造的 `Action` 即可。

## 我（组装者）负责

`normalize/__init__.py::normalize_event`（按工具名分派：Bash/PowerShell/Read/Write/Edit/MultiEdit/NotebookEdit/Glob/Grep/WebFetch/WebSearch/mcp__*/其他→gray；把 bash → programs → paths → domains 串起来、`cd` 之后的相对路径、项目根）、`daemon/pipeline.py`、判决到 hook 输出的映射、审计记录、`boundkeep test` / `explain`、hook 客户端转发 `CLAUDE_PROJECT_DIR`、`init` 写新默认策略、语料库与对抗审查。
