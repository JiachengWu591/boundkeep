# 修订 11 路径与闸门修复的定向复审

日期：2026-11-04。代码：`2f8f59d`（工作区干净，比 `origin/main` 多 3 个提交）。审查对象：`7f7ffe9`（G-1 到 G-5、G-9、G-13），记录 `docs/reports/M3a-path-gate-fixes.md`，测试 `tests/unit/test_m3a_path_gate_fixes.py`。

**这不是独立复审。** 修复是这个会话写的，使用者选了在这里做。我尽量靠实测下结论，但可能和写修复时有同样的盲点。

**之后（同一天）**：使用者说"修 GR-1、GR-2"，已修，记录 `docs/reports/M3a-dots-and-folding.md`（规格修订 12）。下面的判决是修之前的。GR-2 没有照这里的修法方向做，第 3 节有说明。

这次复审没有改代码和测试。没有读 `.env`，没有 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次和攻击样本。全量没有跑。

## 1. 结论

**七条里六条成立，G-2 只修了一半（GR-1）。** 另外查出一条与 G-2 同类、更早就有的问题（GR-2）。这两条都不需要后端，都由规则放行，都用真文件量过。修复本身没有让判决变松：差分的 89076 条里，没有一条从 deny 降级或从问变成无决定（第 5 节）。

| 编号 | 级别 | 一句话 | 要后端吗 | 来源 |
|---|---|---|---|---|
| GR-1 | 中 | 最后一段的尾随点或空格仍算确定：Git Bash 里 `cd ../proj. && cat x` 读到项目外，规则放行 | **不要** | 这次修复留下的。记录第 6 节第 4 条说它没有意义，说错了 |
| GR-2 | 中 | 大小写折叠把两个不同的目录读成一个：项目 `work` 旁边的 `wor\u212a`（开尔文符号），Read、Write、`cat` 都被规则放行 | **不要** | 早就有，`78127af` 上结果相同。审查和修复都没有查 |
| GR-3 | 低 | Git Bash 里 `> nul` 是普通文件，PowerShell 5.1 里报错。规格写的"内容被丢弃"只对 cmd 成立 | 要 | 修订 10 的依据 |
| GR-4 | 低 | 目录扫描仍会跟着链接访问目标。G-4 只修了 `_resolve_on_disk` 一处 | 不要 | 早就有 |
| GR-5 | 信息 | UNC 的共享名写成变量或通配符时，G-3 的闸门看不到 | 要 | 这次修复的边界 |

**影响范围。** GR-1、GR-3 的 shell 路径只在 Git Bash 作为 shell 工具时成立。这台机器默认只有 PowerShell（`docs/hook-behavior.md:12`，设了 `CLAUDE_CODE_GIT_BASH_PATH` 才有 Bash），Git Bash 也不在当前的支持声明里（`docs/platforms.md:27`）。PowerShell 5.1、cmd、Python 的 `cd ..\proj.` 都留在项目里（实测）。GR-2 不依赖 shell。boundkeep 不替用户批准，无决定之后 Claude Code 自己的权限流程还会接手，那一步没有量。

### 七条修复

| 发现 | 结论 | 依据 |
|---|---|---|
| G-1 `NUL` 豁免放过普通文件 | **成立** | 审查的写法都不再送审，也不再命中真 `NUL` 的缓存。17 条 Bash、8 条 PowerShell 的变体符合规格。只有裸名字和只带前缀的写法还送审。依据上的问题见 GR-3 |
| G-2 尾随点：key 说在项目里，文件在项目外 | **只修了一半** | 中间一段和字面命名空间修好了（24 种 Read、Glob、Bash、PowerShell 写法都问）。最后一段没有修，见 GR-1 |
| G-3 管道的 UNC 写法 | **成立** | 22 种 Read 写法、7 条 Bash、6 条 PowerShell 都问：`.`、`..`、重复分隔符、尾随点、流、`\\?\UNC\`、`FileSystem::`。`\\localhost\y\..\pipe\x` 仍送审，这是对的：NT 路径在共享 `y` 之下，key 也这样写。变量和通配符见 GR-5，`file:` 的写法见第 6 节 |
| G-4 通向设备的链接 | **第一部分成立，第二部分修了一处** | 通向设备的假链接问或 deny（测试）。`_resolve_on_disk` 不再 `stat` 非本机目标；目录扫描没有改，见 GR-4。真硬链接、真联接点仍然问，没有回归 |
| G-5 `which` 带网络路径 | **成立** | 51 种形状里 46 种问（`which.exe`、`WHICH`、`/usr/bin/which`、`command`、`env`、`nohup`、`sudo`、`xargs`、`bash -c`、`--`、引号拼接、混合分隔符）。还放行的 5 种都没有连到外部：`which -a=//…`、`which --x=//…` 真跑报"无效选项"，退出码 255，输出里没有查找结果；`which //localhost/C$/proj/x` 是项目里的同一个文件；`which srv/share/x`、`which file://srv/share/x` 不是 UNC。58 个 allow 程序扫了一遍，没有同类（第 6 节） |
| G-9 非字母盘符 | **成立** | 16 种写法里 13 种问。余下的 `1a:\x`、`C1:\x`、`:\x` 第二个字符不是冒号，不是盘符写法；key 还是错的且确定，属于记录第 6 节第 3 条那一类（后面一段带冒号） |
| G-13 key 不稳定 | **成立** | 更宽的语法跑 108 万次：不稳定 0 条；同样的语法在 `78127af` 上 278 条（14 种形状）。变量开头之后的 deny 规则仍然 deny（12 行） |

## 2. 怎么量的

- **判决**：`pipeline.decide`，默认策略，假后端总是放行，假机器（`C:\proj`，`C:\Users\bob`）；真文件那几组用 `scan_disk=True` 和 scratchpad 里的真实项目目录。PowerShell 的行等解析辅助进程就绪之后才算。
- **保护**：探针把 `os.stat`、`lstat`、`scandir`、`listdir`、`open`、`os.path.realpath`、`exists`、`isdir` 等包了一层，给它们 UNC 或设备路径就拒绝并记录。所有判决探针记录到的次数都是 0，也就是判决过程没有碰这类路径。
- **真实程序**：Git Bash（Git for Windows，`D:\新建文件夹\Git`）、Windows PowerShell 5.1、cmd、Python 3.12.11、Node 24.11。文件都在 scratchpad 里，用完已删。
- **碰过的网络**：只有本机回环。`which //localhost/C$/Windows/System32/notepad.exe` 与 `find`、`ls`、`head`、`wc`、`grep` 带 `//localhost/C$/Windows/win.ini` 的写法。没有碰外部主机。
- **差分**：同一份语法跑 `78127af` 和当前代码，比判决（第 5 节）。
- **探针**：都在这个会话的 scratchpad，仓库之外，名字以 `rr_` 开头。单条复现见附录。

## 3. 中危

### GR-1 最后一段的尾随点：G-2 没有修完

- **位置**：`paths.py:907`（`if stripped == "" or not final:`，最后一段算确切），`paths.py:1088`（`s.endswith` 在去掉流之前看，所以 `proj.:s` 查不到）。
- **违反**：`inside_project` 的约定"True 只在确定在里面时"，这正是 G-2 要修的。
- **复现**（真文件，真 Git Bash，判决来自同一条命令，没有后端）：

  ```
  mkdir ../work.                       无决定 rule:allow-mkdir-touch-inside-project       真的创建了 work.
  cd ../work. && pwd && cat left.txt   无决定 rule:allow-cd-family,allow-no-path-commands,allow-cat-inside-project
                                       输出 .../real-chain/work. | was already there
  ls ../work.                          无决定 rule:allow-list-inside-project              输出 left.txt
  cat ../work./left.txt                问 gray（G-2 修到的只有这一条）
  ```

  项目旁边有一个通向私人目录的联接点时也一样：

  ```
  cd ../work. && pwd && cat notes.txt  无决定 同上    输出 PRIVATE NOTES OUTSIDE THE PROJECT
  cd ../work. && ls                    无决定         输出 notes.txt
  ```

  尾随空格相同：`cd '../work ' && cat left.txt` 无决定，读到外面；`mkdir '../work  '` 无决定，真的创建了。`Grep`、`Glob` 的 `path` 写 `<root>\work.` 也由 `read-inside-project` 放行（宿主实际怎么打开没有量）。
- **流也漏了**：`\\?\C:\proj.::$DATA` 的 NT 路径是 `\??\C:\proj.::$DATA`，key 是 `c:/proj`，确定；`C:\proj.:s`、`\\?\C:\proj.:s` 相同（Win32 也不去这个点），`Write` 由 `allow-project-file-writes` 放行。规格 §5.1 说"`\\?\` 与 `\??\` 下任何一段带都标为不确定"，这几种写法不成立。
- **各程序的读法**（`../proj.`，实测，两个目录都有 `a.txt`，内容不同）：

  | 程序 | 读成 |
  |---|---|
  | Git Bash 的 `cd`、`cat`、`ls` | `proj.` |
  | Node `readFileSync`、`readdirSync` | `proj.` |
  | Node `process.chdir` | `proj` |
  | PowerShell 5.1 `Set-Location`（报错后留在 `proj`）、`Get-Content` | `proj` |
  | cmd `cd`、Python `open`、`os.chdir` | `proj` |

- **怎么漏的**：我的对照基准是 NT 路径，`C:\proj.` 的 NT 路径确实是 `\??\C:\proj`。但 Git Bash 和 Node 不是这个读法。记录第 6 节第 4 条只想到"造出一个名字没有意义的文件"，没想到它可以是目录，而 `cd` 之后的相对路径全都落在里面。记录第 5 节的"G-2 那一类没有了"也是只对 NT 路径成立。
- **影响与限度**：`mkdir` 不问，agent 可以自己造出这个目录。但要读到有价值的内容，还要项目旁边已有这样的目录或链接，或者有一次提问被批准：`ln -s ~/Documents ../proj.` 和 `cmd /c mklink /J ..\proj. …` 都问（配了后端则送审，审查量过 `mklink`）。`mklink` 带 `\\?\…\work.` 真跑报"文件已存在"，应该是点被去掉了；我是用 `_winapi.CreateJunction` 造的。写也有限：`cd ../proj. && echo x > new.py` 问，`rm -rf` deny。strict 策略下 Bash 这几行都问，但 `Read C:\proj.`、`Grep C:\proj.` 仍放行。
- **修法方向**：最后一段也标为不确定（去掉 `final` 的例外），并且先去掉流再看点。key 不变，所以 deny 规则照常匹配（`.ssh.\id_rsa`、`.env.` 实测都还是 deny）。代价只是 `a.txt.` 这样的路径从规则放行变成问或送审，正常写路径的人不这样写。`test_other_dots_stay_certain` 里至少两行要改（其他测试文件还没有看全），规格 §5.1 也要改。

### GR-2 大小写折叠：key 说是同一个目录，NTFS 说不是

- **位置**：`paths.py:1337`（`key.casefold()`）。比较时项目根也走同一个折叠。
- **复现**（真目录，scratchpad 所在的 NTFS，没有后端，`scan_disk=True`）：

  ```
  项目 'work'，旁边 'wor\u212a'（KELVIN SIGN）：samefile=False，项目目录是空的
    Read  <旁边>\data.txt  -> 无决定 rule:read-inside-project
    Write <旁边>\new.py    -> 无决定 rule:allow-project-file-writes
    cat   <旁边>/data.txt  -> 无决定 rule:allow-cat-inside-project
  ```

  `sub`/`\u017fub`、`pross`/`pro\u00df`、`fix`/`\ufb01x`、`test`/`te\ufb06` 四组结果相同。`mkdir ../pro\u017fj/deeper` 由 `allow-mkdir-touch-inside-project` 放行。`78127af` 上结果相同，不是这次引入的。
- **范围**：枚举基本多文种平面，用 `RtlUpcaseUnicodeChar`（不碰文件系统）比较内核的大写和 `str.casefold()`。折叠成 ASCII 而内核认为不同的字符有 11 个：`ß`、`ſ`、`ẞ`、`U+212A`（开尔文符号）、`ﬀ`、`ﬁ`、`ﬂ`、`ﬃ`、`ﬄ`、`ﬅ`、`ﬆ`。所以项目路径任何一段含 `k`、`s`、`ss`、`ff`、`fi`、`fl`、`ffi`、`ffl`、`st` 就受影响，`boundkeep` 也是。
- **反方向没有问题**：内核大写成 ASCII 字母、`casefold` 却折叠到别处的字符是 0 个，所以这条路绕不过按名字写的 deny。`.ſſh` 这样的名字 key 是 `.ssh`，只会多拦。
- **影响与限度**：和 G-2 同一类。写不用问，但只能写到这样一个孪生目录里；要读有价值的内容，同样要已有孪生目录或链接，建链接要问一次。strict 下 `Read` 仍放行，`Write` 和 `cat` 问。
- **没有量**：scratchpad、tool-results、memory 的判断（路径里同样有这些字母）；非 ASCII 的项目名里两种折叠是否不一致；通过宿主的 Write 工具实际写入。
- **修法方向**：key 继续折叠（deny 规则受益），但路径里出现"非 ASCII、折叠后是 ASCII"的字符时标为不确定。这样的字符正常路径里几乎没有，代价很小。
- **更正（动手时发现）**：上面最后一句是错的，`ß` 在其中，`C:\Users\Weiß\proj` 下每个文件都会变成要问。范围也说窄了：`в` 和 `U+1C80`、`Å` 和 `U+212B` 在真实 NTFS 上同样是不同的目录。实际的修法是让 key 按 NTFS 的方式折叠。

## 4. 低危与信息

### GR-3 `NUL` 例外的依据只对 cmd 成立

规格 §7 写"写进去的内容被丢弃，读到的是空"，§7 还写"Git Bash 里的读法没有实测"。现在量了（`echo hello > nul`）：

| 程序 | 结果 |
|---|---|
| Git Bash | 当前目录多了一个普通文件 `nul`，6 字节；`cat nul` 能读回来 |
| Windows PowerShell 5.1 | 报错 `FileStream was asked to open a device that was not a file`，什么都没写 |
| cmd | 丢弃，没有文件 |

所以 Git Bash 下模型看到的 `//./nul` 不是真实位置。`pipeline.py` 的注释"最坏也只是当前目录下一个叫 `nul` 的文件"是对的，只是当前目录可以在别处：`cd C:/Users/bob/Documents && foo > nul` 是 `llm`，sent=1（`cd ~/.ssh; …` 是 deny）。名字固定，直接危害小，所以是低危。我不建议改代码，例外仍然值得留；要改的是规格的这句话。`test_what_is_exempt_is_nul_when_opened` 也只说明 Win32 的读法。

### GR-4 目录扫描仍跟着链接访问目标

G-4 的第二部分是"审查自己去 `stat` 目标，在判决之前就碰到了网络"。`7f7ffe9` 改了 `paths.py:_resolve_on_disk`，但 `subtree.py` 有同样的调用：`_link_to_dir` 的 `entry.is_dir(follow_symlinks=True)`（`subtree.py:433`），`_hard_linked` 的 `os.stat(entry.path)`（`subtree.py:319`）。用假目录项代替符号链接（没有创建链接，没有打开任何东西）：

```
calls that follow the link: ['entry.is_dir(follow_symlinks=True)', "os.stat('C:\\proj\\link') (follows links)"]
```

所以 Grep、Glob、`git add .` 这样会扫描子树的调用，碰到通向 UNC 的符号链接时，大概率在判决之前连到那台主机。这台机器的账号不能创建符号链接，真实行为没有量。记录第 6 节第 2 条只提了 `realpath`，要补上这里。修法方向：Windows 上符号链接自身的属性就带目录位，判断是否通向目录不必跟随；`_hard_linked` 遇到链接直接跳过。

### GR-5 共享名是变量或通配符

```
cat //localhost/$S/x     none llm sent=1      对照 cat //./$S/x    ask gray-device-path
cat //localhost/pip?/x   none llm sent=1      对照 cat //./pip?/x  ask gray-device-path
```

环境里 `S=pipe` 时这就是管道。`cat $P` 本来也送审，模型能看到原文，所以算信息。`Read \\localhost\*\x` 同样送审，但打不开。

## 5. 差分：有没有判决变松

同一份语法（29 种开头 × 16 种中间 × 16 种结尾 × Read、Write、`cat`、`foo >`、`which`、`rm -rf`，两种策略：有后端、没有后端），`78127af` 对当前代码，共 89076 条，假机器，`scan_disk=False`。

- **变化 11184 条，从 deny 降级或从问变成无决定的 0 条。**
- 2742 条从"规则放行"变成送审（有后端，1371 条）或问（没有后端，1371 条），如 `sub.\a.txt`。这些都是收紧，符合 G-2。
- 2150 条从送审变成 `gray-device-path`，符合 G-1、G-3。
- `which` 带路径的 4592 条从规则放行变成问或 deny，符合 G-5。其中 `which '\\?\.env'` 变成 `no-secret-read` 的 deny，这个说法不太准（`which` 不读内容），但方向是谨慎的。
- **一个代价**：`rm -rf 'sub.\'` 变成 `rm-outside-project` 的 deny，共 1286 条（746 条原来送审或问，540 条原来由别的 ask 规则问）。路径不确定，这条规则就按项目外算。这样的写法很少，只记下来。
- 余下 414 条仍是同样的 deny，只是命中的规则列表多了。

## 6. 查过、没有问题的

- **第一个怀疑不成立**：`_resolve_on_disk` 重新规范化时会不会洗掉新加的不确定？不会。`extended-path-dots`、`trailing-dots-spaces-ambiguous`、`non-letter-drive` 都不在 `_INFO_REASONS` 里，算 `blocking`，函数直接返回原路径。真文件的 `Read <root>\proj.\a.txt`、`Read \\?\<root>\proj.\a.txt` 用 `scan_disk=True` 都问。
- **带点的路径上 deny 没有变松**：`.ssh.\id_rsa`、`id_rsa.`、`\\?\…\.ssh\id_rsa.`、`.aws.\credentials`、`.env.`、`.git.\config`、`.claude.\settings.json` 的 Read、Write 共 24 行，deny 的还是 deny，其余都问，差分里也没有一条从 deny 降级。
- **G-5 没有同类**：默认策略的 allow 规则点名 58 个程序，每个试 9 种带网络路径或设备路径的形状。留下的都不是路径查找：`grep`、`egrep`、`fgrep`、`rg` 的第一个位置参数是模式；`pwd` 不用参数；`find -f`、`find --x`、`ls -x=`、`head -x=`、`wc -x=`、`grep -x=` 真跑都报未知选项，退出码非 0，输出里没有查找结果。`tree`、`tail`、`dir` 这几个相同形状没有真跑。
- **`file:` 的写法**：`Read file:////localhost/pipe/x` 由 `read-inside-project` 放行，key 是 `c:/proj/file/localhost/pipe/x`，因为文件工具的路径不是 URL（和审查第 6 节里 `cat 'file:////./pipe/x'` 同一种情况，宿主里没有量）。PowerShell 的 `file:////localhost/pipe/x` 问，`file://localhost/pipe/x` 送审。`Get-Content 'file:////localhost/C$/Windows/win.ini'` 真跑抛了错，没有读到。
- **硬链接没有回归**：`is_local_disk(new)` 这道判断只跳过非本机目标。真硬链接、真联接点在两份代码上都问；普通文件都由规则放行。项目在可移动盘上时，`_resolve_on_disk` 第 1536 行本来就直接返回，没有变化。
- **测试数字**：当前代码上 `test_m3a_path_gate_fixes.py` 283 条全过，加上 `test_settings_io.py` 共 372 passed, 3 skipped。同一个新测试文件跑在 `78127af` 的代码上：164 failed, 119 passed，说明它确实测到了修复（记录写的 160/105 是加 18 条之前的版本）。

## 7. 变异：测试钉住了修复吗

把 `src`、`tests`、`docs`、`policies`、`scripts` 复制到 scratchpad，改副本里修复的代码，跑五个测试文件（`test_m3a_path_gate_fixes.py`、`test_device_paths_not_sent.py`、`test_norm_paths.py`、`test_m1c4_scratchpad.py`、`test_m1c_allow_rules.py`）。未改的副本：3867 passed, 628 skipped。

**35 个变异，抓到 32 个，活下来 3 个。** 审查时活下来的 26 个集中在白名单和 `on_failure`：白名单已经没有了，`on_failure` 现在有测试（`test_on_failure_does_not_touch_the_gate_or_nul`，这组变异没有改它）。活下来的三个都是低危的测试缺口，代码现在是对的：

| 变异 | 缺什么 | 为什么现在没事 |
|---|---|---|
| `ipc:any-flavor`：去掉 `ref.flavor == "windows"` | 没有测试钉住 POSIX 上 `//host/pipe/x` 照常送审 | POSIX 目前只是设计目标 |
| `which:as-write`：`which` 的路径按写算 | 没有测试钉住访问方式是读 | 网络路径由 `net-allowlist` 问，读写结果相同 |
| `which:drops-flags`：`_h_which` 丢掉选项 | 这五个文件没有钉住 `which` 的选项 `allow-no-path-commands` 不看选项（`which -i x` 实测放行），丢掉它们现在不改变判决；`which -i x < ../other/aliases` 由重定向的路径问 |

**这组变异测不到 GR-1、GR-2**，因为它们是修复没有覆盖的路径，不是修复写错了。`test_other_dots_stay_certain` 还把 GR-1 的行为钉成了正确（变异 `dots:final-also-ambiguous` 被它抓到）。

## 8. 要更正的文字

这些是事实错误或说得过满。修订 12 已经改了与 GR-1、GR-2 有关的几行；还没有改的是 `PROJECT_SPEC.md:423`、`:425` 两行（GR-3，不在"修 GR-1、GR-2"的范围内）。下表的行号是写这份报告时的：

| 位置 | 现在的说法 | 问题 |
|---|---|---|
| `docs/reports/M3a-path-gate-fixes.md` 第 1 节 | G-2、G-4、G-5、G-9 "现在都问" | G-2 的最后一段不问（GR-1） |
| 同上第 5 节 | "G-2 那一类没有了" | 只对 NT 路径成立 |
| 同上第 6 节第 2 条 | 只提 `realpath` | 目录扫描也跟着链接（GR-4） |
| 同上第 6 节第 4 条 | "只能造出这样一个名字没有意义的文件" | 可以是目录，`cd` 之后都落在里面（GR-1） |
| 同上第 7 节 | "这次修复没有复审" | 现在有这份，但不是独立的 |
| `PROJECT_SPEC.md:282` | "`\\?\` 与 `\??\` 下任何一段带都标为不确定" | 带流的写法不成立（GR-1） |
| `PROJECT_SPEC.md:423` | "写进去的内容被丢弃，读到的是空" | 只对 cmd 成立（GR-3） |
| `PROJECT_SPEC.md:425` | "Git Bash 里的读法没有实测" | 现在量了（GR-3） |
| `PROJECT_SPEC.md:61`、`CLAUDE.md` 修订 11 那条 | "没有复审" | 同上 |
| `CLAUDE.md` 修订 11 那条的粗体 | "查路径的真实读法要用 NT 路径" | 说窄了。NT 路径只是走 Win32 转换的程序的读法，Git Bash 和 Node 的文件读取不是。要分程序量 |

## 9. 没有查的

- **真实宿主**：没有跑 Claude Code。Read、Write、Grep、Glob 到底怎么打开带尾随点的路径，只有独立运行的 Node 的结果。
- **真实模型**：全是假后端。
- **设备、卷、管道、外部主机**：没有打开，没有连接。`which`、`find` 等只碰了本机回环。
- **真实符号链接**：账号没有权限，GR-4 和 G-4 都靠假 `realpath`、假目录项。
- **其他环境**：只有 Windows 11 build 26200、NTFS、Windows PowerShell 5.1、Python 3.12.11、Node 24.11。没有 pwsh 7，没有真 POSIX 机器，没有 FAT、ReFS 或大小写敏感的目录。
- **strict 策略**：只跑了 GR-1、GR-2 的代表行。
- **全量测试与评测**：没有跑。这份报告的结论不依赖它们，代码也没有变。
- **审查留下的其余发现**：G-6、G-7、G-8、G-10、G-11、G-12、T-4、T-5、I-2 没有重新查。

## 附录：单条复现

从仓库根目录运行。GR-2 只用字符串，不碰文件：

```python
from boundkeep.normalize.paths import inside_project, normalize_path

kw = {"cwd": "C:\\work", "home": "C:\\Users\\bob", "env": {}, "dialect": "tool"}
root = normalize_path("C:\\work", **kw)
for raw in ("C:\\wor\u212a\\data.txt", "..\\work.", "C:\\work.::$DATA", "C:\\work.\\a.txt"):
    got = normalize_path(raw, **kw)
    print(ascii(raw), got.key, got.uncertain, inside_project(got, root))
```

输出：

```
'C:\\wor\u212a\\data.txt' c:/work/data.txt False True
'..\\work.' c:/work False True
'C:\\work.::$DATA' c:/work False True
'C:\\work.\\a.txt' c:/work/a.txt True None
```

最后一行是 G-2 修到的，前三行是 GR-2、GR-1。

GR-1 的真实读法，在一个空目录的子目录 `work` 里，用 Git Bash 运行：

```bash
mkdir ../work. && echo outside > ../work./left.txt && cd ../work. && pwd && cat left.txt
```

`pwd` 打印 `.../work.`，`cat` 打印 `outside`。用完要删 `work.`：它的名字 Win32 读不到，`rm -r` 在 Git Bash 里可以。
