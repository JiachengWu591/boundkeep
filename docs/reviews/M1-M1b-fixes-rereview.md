# X1 复审：第一轮修复（提交 8ca058c）

复审对象：`8ca058c`（X1 修复第一轮）与 `21eb98f`（修复记录）。范围按你的要求只看三处：H-1 的子树遍历（预算、绕过、性能）、`--emit-allow` 与管道 DACL 收紧、ConfigChange 的新阻断面。工作区干净；仍然只读源码，所有实验在一次性目录里做，没有执行任何被审查的命令。

证据等级同上一份报告：**［复现］**＝我在这台机器上跑过并看到输出；**［代码阅读］**＝只读了代码。新增一个对照工具：这台机器上 VS Code 自带 **ripgrep 15.0.0**（`rev 3a612f88b8`），我用它对一次性目录里的 CANARY 文件做了 `--hidden`/`--glob`/`--type` 的真实语义实验（只列文件名，没有碰任何真实文件）。Claude Code 2.1.301 的 Grep 参数构造仍来自上一轮读到的二进制字符串。

## 0. 结论

**第一轮修复大体有效，但 H-1 的修复本身留下了一个新的绕过（R-1，高），并带来三处会让日常用不下去的误拒（U-1 至 U-3，中）。**

- 上一轮四个"进 M2 之前必须修"里，M-3、H-2 的客户端部分、M-1 的词法分类、M-4/M-5/M-8/M-10 我逐条重跑了原复现，**全部已修**（第 5 节）。
- **R-1（高）**：Grep 同时给 `glob` 与 `type` 时，扫描器用"且"，ripgrep 用"glob 命中即纳入、不再看 type"，于是 `Grep path=<项目> glob=".e?v" type="py"` 判 `allow`，而 ripgrep 15 会列出 `.env`。**H-1 在这条路径上没有修好。**
- **H-2 的 DACL 收紧只挡住"直接再建实例"，同一用户三次 API 调用就能撤销**；加一个 OWNER RIGHTS ACE 可以堵上（我在自建的管道上验证了）。修复记录里"同一用户也不能再建同名实例"的说法过强。
- **ConfigChange 的"外来 hook"监视可以被形状伪装绕过**（我复现了三种），监视范围也只含两个事件；若干新增阻断项（`PATH`、`NODE_OPTIONS`、`PYTHON*`、笼统 allow）要么没有可演示的攻击，要么检测太窄，却会误拦合法用法。
- 没有任何 Bash 或 PowerShell 命令得到 `allow`（这一轮我又跑了约 130 个新用例，没有出现）。

## 1. H-1：子树遍历

### R-1（高）Grep 的 `glob`＋`type` 组合绕过扫描器 —— 回归

- **证据**：［复现］（ripgrep 15.0.0 的实测输出＋ boundkeep 判决）。
- **ripgrep 的真实语义**（项目里有 `.env`、`sub\.env`、`certs\x.pem`、`a.py`，参数同 Claude Code：`--hidden --glob '!.git/' -l`）：

  | 参数 | 列出 |
  |---|---|
  | `-g .env --type py` | `.env`、`sub\.env`（**glob 命中即纳入，type 不再过滤**） |
  | `-g '*.pem' --type py` | `certs\x.pem` |
  | `-g .e?v --type py`，`-g .e?v --type md`，`-g '[.]env' --type json`，`-g '\.env' --type py` | `.env`、`sub\.env` |
  | `--type py`（无 glob） | 只有 `a.py`、`b.py` |
  | `-g '!*.md' --type py` | 只有 `a.py`、`b.py`（只有否定 glob 时 type 仍然生效） |

- **boundkeep 的判决**（`SP\M\r1.json`、`r11.json`，HEAD 代码）：

  ```
  deny   Grep path=<项目> glob=".e?v"                          (只有 glob：正确)
  allow  Grep path=<项目> glob=".e?v"  type="py"                ← ripgrep 列出 .env
  allow  Grep path=<项目> glob="[.]env" type="json"             ← ripgrep 列出 .env
  allow  Grep path=<项目> glob="*.p[e]m" type="py"              ← ripgrep 列出 certs\x.pem
  allow  Grep path=<项目> glob=".e\nv"  type="py"               ← ripgrep 列出 .env（`\n` 是转义的 n）
  allow  Grep path=<项目> glob=".e?v"  type="markdown"
  gray   Grep path=<项目> glob="\.e?v" type="py"                （glob-pattern-path，ask，不是放行）
  deny   Grep path=<项目> type="json"                           （只有 type：正确，列出 credentials.json）
  ```
- **原因**：`event.py` 的 `_search_selector` 里 `select()` 先要求 glob 命中，再要求 `type` 命中（"且"）。ripgrep 的 `-g` 是 override，命中后不再看 type。另外 glob 编译失败（`GlobError`）时 `name_globs`/`path_globs` 被清空，但只要有 `type` 就仍然按 type 单独收窄，同样比 ripgrep 窄。
- **利用条件**同 H-1：秘密文件未被 `.gitignore` 覆盖（或项目不是 git 仓库）。参数全由 agent 控制，一次调用即可。
- **建议修复**：只要给了 `glob`（哪怕不认识），`type` 一律不参与收窄；`GlobError`、`_glob_alternatives` 返回 None 时整体不收窄（`select=None`）。`type` 单独使用时现在的行为正确。
- **规格**：不需要改。

### 其余绕过尝试：没有成功

- **junction / 符号链接**：ripgrep 15 默认不跟随（我造了一个指向假 home 的 junction，`rg --hidden` 不列，`--follow` 才列）；Claude Code 的 Grep 没有传 `--follow`（只有它的文件索引用）。扫描器不跟随，行为一致。显式写进链接路径（`Grep path=<项目>\jh`）仍被 deny。
- **OneDrive 一类的"云"重新解析点**：这台机器上的 OneDrive 目录带 `ReparsePoint` 属性（`Get-Item` 实测）。我担心 `_is_link` 会把它们当链接而不下降；实测 `subtree.scan` 访问了全部 20780 个条目，`dir_links` 为假，ripgrep 同样列出全部 19408 个文件。**不成立。**
- **VCS 目录被 `--glob '!.git'` 排除，用户 glob 能否重新纳入**：实测可以：`-g '*'` 会让 `.git\config` 重新出现，`-g .git/config`、`**/.git/config`、`.git/**`、`config` 都不会。所以"没有用户 glob 时可以跳过 `.git`"安全，"有 glob 时必须扫"也正确，现在的实现对后者是对的（见 U-1 的建议）。
- **Windows 的 glob 大小写**：ripgrep 的 `-g` 区分大小写，扫描器不区分（只会多拦，方向安全）。
- **`.gitignore`**：只会让 ripgrep 读得更少。

### 预算与性能（［复现］，本机，Defender 开着，Python 3.12.11，热缓存）

| 场景 | 结果 |
|---|---|
| 2 万个条目的树，`Grep path=<根>`，秘密在 `zzz\deeper\deepest\.env` | deny，约 80–90 ms（宽度优先，深层秘密也在预算内找到） |
| 4 万个条目的树，同样调用 | **gray `recursive-scan-budget`**，约 130–190 ms（30000 条目上限先到） |
| 4 万个条目，带 `glob=*.txt` | 同样 gray（预算按遍历算，glob 不缩小遍历） |
| 同一行 3 个 `grep -r`（2 万条目树） | 第三个 `recursive-scan-budget`，整体仍 deny（秘密在前两次里被找到） |
| 真实 OneDrive 根（20780 条目）只遍历 | 全部访问完，状态 ok |
| 本仓库（6872 条目，含 `.venv`、`.git`） | `Grep path=.` deny 约 76–89 ms；`Glob **/*.py` allow 约 69 ms；`Grep src`（113 条目）约 2–3 ms |

- 预算耗尽的方向是 **gray（ask），从不 allow**：这点成立。耗尽后 deny 变 ask 是可被 agent 操纵的（建 3 万个空文件即可，或本来就有 `node_modules`），与上一轮 M-1 同一类；M3 之后会变成真绕过。
- 扫描耗时不计入请求的 0.25 秒期限（`ctx.budget.deadline += elapsed`），也没有跨请求的缓存：每次 Grep 重扫一遍。并行的多个 Grep 会叠加；`evaluate` 仍无预算（M-2 未做）。
- **词法模式下完全不扫描**：预算耗尽后（如 300 个前置 `true;`）`grep -r x .`、`tar czf x.tgz ~` 得到 gray 而不是 deny（［复现］，`SP\M\r9.json`）。方向仍然是 ask，但"词法分类保住 deny"这条对子树类 deny 不成立。
- **上一轮 M-1 的修复本身**：300 个 `true;`/`ls;`/不同的 `echo cN;` 之后的 `cat .env` 现在 deny；64 个不同路径加秘密 deny；`cd /c/Windows && rm -rf *` deny（`rm-outside-project`）。**残余**：1400 个不同的 `echo cN;`（约 14 KB）之后的 `cat .env` 仍然是 gray（修复记录自己写了"约 1300 条"）。要彻底解决，应当把所有剩余命令都做词法分类（只需要扫文本里的受保护名字），而不是设一个条数上限。

### 可用性回归（中；直接威胁"能在 enforce 下日常使用"）

扫描让下面这些**日常命令被 deny（不是 ask）**。我在最小的假项目里复现，不依赖任何秘密文件：

- **U-1：任何 git 仓库里，不带 `glob`/`type` 的 `Grep`（含不写 `path`）都被 deny**，因为 `.git/config` 在 `no-credential-store-read` 里。项目里只有 `.git/config`、`src/a.py`、`README.md` 时：`Grep path=<根>` deny、`Grep`（无 path）deny、`Glob *` deny；带 `glob=*.py` 或 `type=py` 才 allow。Claude Code 自己的 Grep 会 `--glob '!.git'`（二进制里 `E$o=[".git",".svn",".hg",".bzr",".jj",".sl"]`），所以这里拒绝的是 ripgrep 根本不会读的文件。同一原因：`git log -p`、`git show`、`git grep`、`git stash show -p`、`git archive`、`rg x`、`ls -R` 在该仓库里全部 deny（［复现］，`SP\M\r7.json`）；这些 git 命令读的是对象库，不是 `.git/config`。
- **U-2：boundkeep 自己的默认安装让项目里的 Grep 失效。** `init` 默认写项目级 `.claude/settings.json`，而 M-11 把 `**/.claude/settings*.json` 并入了读保护，于是在这样的项目里 `Grep`（无 glob）、`Glob **/*`、`grep -rn TODO .`、`ls -R` 全部 deny（`no-agent-state-read`，［复现］，`SP\M\r10.json`）。
- **U-3：只列名字的命令也被当成"读内容"。** `ls -R`、`Get-ChildItem -Recurse`、`Glob **/*` 不泄露文件内容，却因为子树里有受保护文件名而 deny。

这三条会把用户推向 `audit-only`（上一份报告的 M-13），那时一切都不防。建议：
1. Claude Code 的 Grep 在**没有用户 glob** 时跳过 `.git`、`.svn`、`.hg`、`.bzr`、`.jj`、`.sl`（实测 ripgrep 在这种情况下确实不会进去；有 glob 时仍要扫，见上）。
2. `git log -p/show/grep/stash show/archive` 不要标成"递归读工作树"。
3. 只列名字的程序/`Glob` 把命中降为 ask 或不算读。
4. `.claude/settings.json`（项目级、通常是提交进仓库的）不要整体读保护，保护 `settings.local.json` 与用户级文件即可。

### 仍然只是 gray 的递归读取（上一轮 M-9 的残余，信息性）

`gzip -r .`、`zstd -r .`、`bsdtar cf x .`、`pax -w .`、`cpio -o`、`docker cp . c:/x`、`curl -F f=@.`、`git diff HEAD`、`find . | xargs cat`、`du -a`、`tree -a`、`gci -r -fo | cat`（缩写不唯一）、`sls x -Path . -Recurse` 均为 gray（ask）；`cat ./*`、`cat -- *` 在 bash 里不匹配点文件，gray 是对的。其余约 60 个递归读取命令（`grep -r/-R`、`rg`、`ag`、`tar`、`zip -r`、`7z`、`cp -r`、`rsync -a`、`git grep/log -p/show/archive/stash show -p`、`ls -R`、`find -exec cat`、`Get-ChildItem -Recurse | Get-Content`、`Compress-Archive`、`Copy-Item -Recurse`、`robocopy /e`、`xcopy /s`、`findstr /s`、`Select-String -Path .\*`、`tar -cf`）在含 `.env` 的项目里都是 deny。

## 2. `--emit-allow`

- **代码阅读**（`hook_main.py` 的 `process`、`parse_args`，`install.py` 的 `with_emit_allow`）：守护进程回 `allow` 而 hook 命令没带 `--emit-allow` 时，客户端返回空输出（"无决定"）；`ask`/`deny` 照常。`parse_args` 对未知 `--flag`、缺值的 `--home`、第二个位置参数一律 fail-closed（`sub=None`、`emit_allow=False`，事件按自己的类型降级）。`ConfigChange` 的 `record_problem` 比较 `[*base_args, sub]`，所以手工加上或去掉 `--emit-allow` 都会被判"被改动"。我没有发现新的放行路径。
- **［复现］M-3**：用修复后的源码复制一份、把 `hook_main.py` 弄坏、按带 `--home` 与 `--emit-allow` 的真实形式启动：`config` 退出码 2；`pre` 输出 ask；`post`/`prompt` 空输出、退出码 0。上一轮的 bug 已修。
- **修复记录的措辞要更正**：「冒充者只能收紧」不准确。客户端对 `none`（"无决定"）本来就不加区分，所以同一用户的冒充者回答 `none` 照样可以静默关掉 boundkeep 的全部 deny（`.env` 的 Read 退回 Claude Code 自己的权限流程，项目内默认免确认）。这次修复去掉的只是"冒充者用显式 `allow` 跳过 Claude Code 自己的确认框"这一档。客户端无法区分合法的 `none`（规则判了 allow、`emit_allow` 关）与冒充的 `none`；令牌也防不了同一用户（它能读 `endpoint.json`）。所以 H-2 的真实残余是"同用户进程能关掉 boundkeep，但关不到比没装 boundkeep 更宽"，应当这样写进规格 §3，而不是"只能收紧"。
- 打开 `emit_allow` 的用户（`--emit-allow` 已钉进 hook 命令）仍然会听从冒充者的 `allow`。这是设计内的，但文档应当写明。
- 顺带：`init` 先 `write_atomic` 写 settings（`cli.py:308`），后 `save_manifest`（`cli.py:315`）。有会话在运行时，ConfigChange 在两步之间会拿新文件对旧记录比较，把 `init` 自己的改动判成"被改动"而阻断（只影响正在运行的会话，文件已写入；重启即可）。低。

## 3. 管道 DACL 收紧

- **代码阅读**：实例用 `WRITE_DAC` 创建，建完后 `SetSecurityInfo` 把 DACL 换成 `D:P(A;;0x0012019B;;;<用户SID>)`（读写与读 DACL，没有 `FILE_CREATE_PIPE_INSTANCE`）；收紧失败则 `serve` 拒绝启动（fail-closed）；工作线程用 Disconnect/Connect 复用实例，不再创建。
- **［复现］（自建的一次性管道 `\\.\pipe\bk-x1-dacl-test-*`，用 boundkeep 自己的 `winsec`，不是真实管道，没有任何服务端回答任何东西）**：

  ```
  create instance 1 (first, WRITE_DAC): True
  create instance 2 BEFORE tightening (same user): True
  tightened
  a) create instance AFTER tightening: refused (win32 error 5)
  b1) open pipe with WRITE_DAC as same user: SUCCEEDED
  b2) SetSecurityInfo(FILE_ALL_ACCESS) by same user: SUCCEEDED
  b3) create instance after re-granting: SUCCEEDED (defence undone by the same user)
  ```
  收紧确实挡住了 D 的原始攻击（直接再建实例得到错误 5），但**所有者隐含拥有 WRITE_DAC**，同一用户用三次调用（以 WRITE_DAC 打开、改 DACL、再建实例）就能撤销。代码注释自己写着"The owner can always change the DACL again"，修复记录没有提。
- **［复现］可行的加固**：在同一个 DACL 里加一个 OWNER RIGHTS ACE，只给 READ_CONTROL：`D:P(A;;0x12019B;;;<SID>)(A;;0x20000;;;OW)`。同样的一次性管道上：直接再建实例仍是错误 5，**以 WRITE_DAC 打开也被拒（错误 5）**，撤销路径被堵。（提权的管理员可以接管所有权，不在范围内。）
- **未变的残余**：守护进程启动**之前**占住管道名（`serve` 响亮失败，但客户端仍对占位者说话；`doctor` 仍然看不出来）。M-7（8 个空闲连接占满固定的 8 个实例，每个 hook 等约 10 秒后 ask）未做，且因为现在不能再建实例，一个工作线程在 `_MAX_CONSECUTIVE_FAILURES` 后退出会永久少一个实例（上一版同样不重建，只是现在连守护进程自己也不能重建）。
- 客户端以 `open(address, "r+b")`（GENERIC_WRITE 含 `FILE_APPEND_DATA`）连接已收紧的管道：［复现］在同一个一次性管道上，收紧之后 `open(name, "r+b", buffering=0)` 成功。

## 4. ConfigChange 的新阻断面

我用纯函数（`claude_settings.blocking_reasons`、`hook_main.record_problem`）对构造出来的 settings 文档做了检查，没有碰任何真实 settings 文件（`SP\M\cc1.py`、`cc2.py`）。

### C-1（中）"外来 hook"监视可以靠形状伪装绕过

`ownhook.is_own_hook` 只看形状：exec 形式、最后一个参数是 `pre/post/prompt/config`，并且命令文件名是 `boundkeep-hook(.exe)`，**或**某个参数的文件名是 `hook_client.py` 且路径里有名为 `boundkeep` 的目录。［复现］以下全部"通过"（`blocking_reasons` 与 `record_problem` 都不报）：

- 再加一个 PreToolUse hook：`C:\evil\boundkeep-hook.exe`，`args:["pre"]`（放在自己的组里、放进我们的组里、放在前面并给更窄的 matcher）；
- `C:\py\python.exe` 跑 `C:\evil\boundkeep\hook_client.py pre`；
- 真启动器加 `--home C:\evil`。

原因：外来 hook 被 `is_own_hook` 过滤掉，不进 `watched_fingerprints`；`record_problem` 只检查"期望的条目存在且完整"，不检查"没有多余的、长得像我们的条目"。影响受限于必须先写得进 settings（PreToolUse 对 settings 的写本来就 deny），而且额外的 hook 不能把 boundkeep 的 deny/ask 变成放行；但它能运行任意程序，并且并行于 boundkeep 运行。建议：自有条目要与 `init` 记录的 `hook_command`+`hook_args` **精确相等**才算"自己的"，其余一律按外来处理；同一事件里出现多个长得像的条目要阻断。

### C-2（中）监视范围太窄

- 只监视 `PreToolUse`、`PermissionRequest`。［复现］新增 `SessionStart`、`PostToolUse`、`UserPromptSubmit` 的外来命令 hook、`enabledPlugins`（插件自带 hooks）、`extraKnownMarketplaces` 都通过。它们同样在 boundkeep 的审查之外运行命令，与 `statusLine` 是同一类；而 `statusLine` 在有基线时被拦。
- **没有基线的文件完全不拦**：`init` 没碰过的文件（项目级安装时的用户级 settings、`settings.local.json`）里，新增 `statusLine`、外来 PreToolUse hook 只是 `info`/`warn`，ConfigChange 放行（［复现］"NO baseline" 两项通过）。
- 笼统 allow 的识别太窄：`Bash(*)`、`Bash`、`Bash(**)`、`Bash(:*)`、`PowerShell(*)`、`Write(*)`、`Edit` 被拦；`Bash(*:*)`、`Bash(* *)`、`Bash(**/*)`、`Bash(python:*)`、`Bash(bash:*)`、`Bash(sh:*)`、`Bash(powershell:*)`、`Bash(env:*)`、`Bash(find:*)`、`PowerShell(pwsh:*)`、`Write(//**)` 通过。后几种在效果上与笼统 allow 相当（`python:*` 是 Claude Code 里很常见的一键允许）。更根本的问题：修复记录自己写明 Claude Code 对这些键的行为没有测过，而在 enforce 下 boundkeep 对未命中的 shell 命令返回 ask，**hook 的 ask 与 `permissions.allow` 谁优先是未验证的**；如果 hook ask 优先，这项阻断保护不了什么，却会拦下"`Bash(*)` 加 boundkeep 当唯一闸门"这种合理的组合。
- `permissions.deny` 被清空/删除、`defaultMode: "acceptEdits"/"dontAsk"` 没有基线也不拦（信息性）。

### C-3（低）误拦，以及没有可演示攻击的阻断项

- ［复现］`env.PYTHONUTF8`（中文 Windows 上很常见）、`env.NODE_OPTIONS`、`env.Path` 被阻断。我另外验证了它们**对 hook 客户端没有影响**：用 `python -I -S hook_client.py --home <隔离> pre` 启动，对 `SystemRoot`、`windir`、`SystemDrive`、`TEMP`、`TMP`、`PATH`、`ComSpec`、`USERPROFILE`、`APPDATA`、`LOCALAPPDATA`、`ProgramData`、`PATHEXT`、`HOMEDRIVE` 各做"删除/置空/指向不存在目录"三种改动，共 39 次，**全部退出码 0 并输出合法 ask**，没有一次崩溃（"通过的假设"：环境变量不能让客户端以非 0 非 2 退出）。所以 `PATH`、`PATHEXT`、`COMSPEC`、`PSMODULEPATH`、`NODE_OPTIONS`、`PYTHON*` 这些块没有已演示的攻击，只有误拦。建议保留只有证据的那部分（会重定向 home 的变量，现在已有 `--home` 钉住）。
- **粘性阻断**（［复现］）：用户在 `init` 之后自己加了一个外来 PreToolUse hook，此后**任何**对该文件的 ConfigChange（包括 `/config` 改主题或模型）都因为基线过期而被阻断，直到重新 `init`。
- **ConfigChange 不是持久状态的执法点**：它阻断的是"把改动应用到当前会话"，磁盘上的文件已经改了；下一次会话启动时不会再触发 ConfigChange，被削弱的配置会直接生效。目前没有 SessionStart 检查（上一轮 H-3 里"SessionStart 心跳"这一项仍未做），只有手动 `doctor`。
- 完整性哈希只覆盖解释器、`hook_client.py`、`hook_main.py`；`hook_main` 导入的 `protocol.py`、`ipc/client.py`、`ipc/endpoint.py`、`paths.py`、`ownhook.py`、`claude_settings.py` 不在其中，守护进程启动时只警告不拒绝（修复记录已说明"只是事后发现"）。运行时的 `protect-guard-code` 对包目录的写 deny 是更主要的保护。

## 5. 第一轮修复的逐条重跑（上一份报告的原复现）

| 编号 | 重跑结果 |
|---|---|
| H-1（无 glob/type 的情形） | `Grep path=<项目>`、无 path、`glob=.e?v`、`glob=*.env` 现在 deny；`Grep src`、`glob=*.py` 仍 allow（但见 R-1） |
| H-2（客户端） | 代码阅读与 M-3 的复现见第 2 节 |
| M-1 | `300×true`/`300×ls`/300 个不同的 `echo` 之后的 `cat .env` deny；64 个不同路径＋秘密 deny；`cd /c/Windows && rm -rf *` deny。残余见第 1 节 |
| M-3 | 见第 2 节，`config` 退出码 2 |
| M-4 | 对 `hook_main.py`、`.venv\Scripts\python.exe`、重定向到 `hook_client.py` 的写 deny（`protect-guard-code`） |
| M-5 | `boundkeep mode audit-only`、`python -m boundkeep mode`、`uninstall`、`init --reset-policy`（Bash 与 PowerShell）deny；`taskkill`、`Stop-Process` ask；`Read` 的 `endpoint.json`、`audit.jsonl` ask |
| M-8 | `git mv .env`、`gzip -k .env`、`zstd -o x.zst .env`、`git add -f .env` deny |
| M-9 | `git show HEAD:.env` deny |
| M-10 | `coproc X { rm -rf <项目外>; }`、`time { rm -rf … }`、`eval -- rm -rf …` 现在 deny（没有对真 bash 做差分，修复记录自己也这么说） |
| 其余 | M-6、M-11、M-12 未逐条重跑；M-11 的副作用见 U-2 |

## 6. 没有覆盖到的范围

- 真实 Claude Code 端到端：R-1 里"ripgrep 会列出文件"来自真实 ripgrep 15.0.0 的输出，"Claude Code 把这些参数原样传给 ripgrep"来自 2.1.301 二进制里的参数构造字符串，**没有用真 Claude Code 跑 Grep 工具**；VS Code 扩展里的行为未测。
- `type` 之外 ripgrep 的其他收窄项（`--glob` 与 `--iglob`、用户 deny 权限转成的 `--iglob`）；`-g` 里空白/逗号拆分与花括号的全部边界。
- 管道：只在自建一次性管道上验证了 DACL 行为；没有对真实守护进程重跑冒充实验；没有测提权（管理员）与另一个 Windows 用户。
- ConfigChange：只对构造出的文档做了纯函数检查，没有触发真实的 ConfigChange 事件，也不知道 Claude Code 对 `permissions.allow` 与 hook ask 的优先级。
- POSIX/WSL、pwsh 7、Git Bash、真 bash 差分：同上一轮，未测。
- `evaluate()` 的预算（M-2）、M-7、M-13 本轮未做，我没有复审。

## 7. 建议的下一步（按优先级）

1. **R-1**：`type` 不参与收窄（只要有 `glob`），解析不了的 `glob` 整体不收窄；补回归用例（至少 `glob=.e?v type=py`、`glob=[.]env type=json`、`glob=.e\nv type=py`）。
2. **U-1、U-2、U-3**：没有用户 glob 时 Grep 跳过 VCS 目录；git 对象类命令不当工作树递归读；`settings.json`（项目级）不整体读保护。否则默认安装在自己的项目里就让 Grep 不可用。
3. **DACL**：加 OWNER RIGHTS ACE（`(A;;0x20000;;;OW)`），并把修复记录与规格里的"同一用户也不能再建"改成"提高门槛"；把"只能收紧"改成"只能关掉 boundkeep，关不到比没装更宽"。
4. **ConfigChange**：自有条目与记录精确相等才算自己的；监视范围扩到所有会运行命令的事件与插件键；先验证 hook ask 与 `permissions.allow` 的优先级再决定要不要保留笼统 allow 的阻断；去掉没有证据的 `PATH`/`NODE_OPTIONS`/`PYTHON*` 阻断；`init` 先写 manifest 再写 settings，或在写之前刷新基线。
5. 词法分类对所有剩余命令都做（不设条数上限），并在词法模式下仍扫描文本里的受保护名字。
