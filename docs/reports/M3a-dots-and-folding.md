# 最后一段的尾随点与大小写折叠（规格修订 12）

日期：2026-11-04。基线：`2f8f59d`。依据：定向复审 `docs/reviews/M3a-path-gate-rereview.md` 的 GR-1、GR-2。使用者说"修 GR-1、GR-2"。没有读 `.env`，没有用任何 LLM 密钥，没有访问真实 LLM 服务，没有打开留出批次和攻击样本；判决都用假后端（总是放行），真实文件都在 scratchpad 或 `tmp_path` 里，用完已删。

## 1. 结论

**两条都修了，未提交。** 这两条都不需要后端，都是"key 说在项目里，文件在项目外"，修之前规则直接放行，现在都问。规则条目和策略文件没有改，评测除延迟外与记录相同。全量 27803 通过、169 跳过、0 失败（第 5 节）。

**GR-2 的修法和复审报告写的不同。** 报告建议把这些字符标为不确定，并说"这样的字符正常路径里几乎没有"。这句说错了：`ß` 就在其中，`C:\Users\Weiß\proj` 下每个文件都会变成要问。另外实测发现受影响的不只是 ASCII 字母：`в` 和 `U+1C80`、`Å` 和 `U+212B` 在真实 NTFS 上也是不同的目录。所以改成让 key 按 NTFS 的方式折叠，第 4 节写了原因。

## 2. 修改前后

没有后端，`enforce`。"无决定"是 boundkeep 不拦。真实 Git Bash、真实目录。

| 发现 | 写法 | 修改前 | 修改后 |
|---|---|---|---|
| GR-1 | `cd ../work. && cat left.txt`（读到项目外） | 无决定，`allow-cd-family`、`allow-cat-inside-project` | 问 |
| GR-1 | 同上，`work.` 是通向私人目录的联接点 | 无决定 | 问 |
| GR-1 | `ls ../work.`、`cd ../work. && ls` | 无决定 | 问 |
| GR-1 | `mkdir ../work.`、`mkdir '../work  '` | 无决定，`allow-mkdir-touch-inside-project` | 问 |
| GR-1 | `cd '../work ' && cat left.txt` | 无决定 | 问 |
| GR-1 | Grep、Glob 的 `path` 写 `<root>\work.` | 无决定，`read-inside-project` | 问 |
| GR-1 | Write `C:\proj.:s`、`\\?\C:\proj.:s`；Read `\\?\C:\proj.::$DATA` | 无决定 | 问 |
| GR-1 | Read `a.txt.`、`C:\proj\a.txt ` | 无决定，`read-inside-project` | 问（有后端：送审） |
| GR-1 | Read `.env.`、`.ssh\id_rsa.` | deny | **不变** |
| GR-2 | 项目 `work`，旁边把 `k` 换成 `U+212A`：Read、Write、`cat` | 无决定 | 问 |
| GR-2 | `sub`/`ſub`、`pross`/`proß`、`fix`/`ﬁx`、`test`/`teﬆ` | 无决定 | 问 |
| GR-2 | `Å`/`U+212B`、`в`/`U+1C80`、基本平面之外的大小写对 | 无决定 | 问 |
| GR-2 | `.ſſh\id_rsa`、`.aws\credentialſ` | deny | **不变** |
| GR-2 | 项目 `C:\Users\Weiß\p` 里的文件 | 无决定 | **不变** |
| GR-2 | `c:\WORK\x`（真正的大小写变体） | 无决定 | **不变** |

真实程序的读法没有变（`cd ../work.` 在 Git Bash 里还是进 `work.`），变的是 boundkeep 不再替它说"在项目里"。

## 3. 修法

- **`src/boundkeep/normalize/paths.py`**：
  - GR-1：`_win_part` 只要去掉了尾随的点或空格，就加 `trailing-dots-spaces-ambiguous`，不再分最后一段和中间一段。它在去掉流之后才看，所以 `proj.:s`、`proj.::$DATA` 也算。`final`、`ends_sep` 这两个参数没有用了，一起去掉。`_PLAIN_REASONS` 去掉 `trailing-dots-spaces`（它现在总是和不确定一起出现）。
  - GR-2：新函数 `windows_fold`，key 用它折叠。ASCII 走 `lower`；324 个 `casefold` 会合并而内核分得开的字符，以及基本平面之外的字符，保持原样；其余 `casefold`。
  - `SessionDir._below`（scratchpad、tool-results、memory）、`_expand_glob` 也用它。
- **`src/boundkeep/policy/matcher.py`**：`_comparison_key`（`project_trusted`）用 `windows_fold`。
- **`src/boundkeep/policy/glob.py`**：只改了说明。匹配时两边仍然 `casefold`，这是 `.ſſh` 仍然被 deny 的原因。
- **规格**：修订 12，§5.1。`policies/` 没有改。

**顺带修好的一个问题**：`_resolve_on_disk` 拿 key 当本机路径去 `realpath`。修之前，孪生目录里的文件被解析成了项目里同名的文件。现在 key 保留了那个字符，解析的是真实位置（`test_a_real_twin_directory_is_not_allowed`）。

## 4. 和复审建议不同的地方

- **GR-2 没有标为不确定。** 三种做法比较过：

  | 做法 | `ß` 在项目路径里 | `.ſſh` 的 deny | 复杂度 |
  |---|---|---|---|
  | 出现这些字符就标为不确定（报告的建议） | **每个文件都要问** | 保留 | 小 |
  | key 按 NTFS 折叠，`path_glob` 仍然 `casefold`（采用） | 不受影响 | 保留 | 一张表 |
  | 同时保存两个 key | 不受影响 | 保留 | 动 `NormPath` 和所有比较处 |

  采用的做法正好符合规格的方向规则：allow 侧确定才算，deny 侧可能匹配就算。
- **用表，不用规则。** 我先试了"折叠成 ASCII 或折叠成多个字符的才保留"这样的规则，但 `в`/`U+1C80`、`Å`/`U+212B` 这类一对一的合并漏掉了，俄语、瑞典语路径一样能造孪生目录。只修 ASCII 就又是"修了一半"。表是从内核量出来的，测试会重新量一遍对比。

## 5. 度量

| 项目 | 结果 |
|---|---|
| 新测试 `tests/unit/test_m3a_dots_and_folding.py` | 129 passed |
| 折叠表对内核（`RtlUpcaseUnicodeChar`，基本平面全部） | 与算出来的集合相同；一个 key 对应两个内核类的 0 个；一个内核类对应两个 key 的 27 组（都是带下标 iota 的希腊字母，谨慎方向）；内核合并而 `casefold` 分开的 0 个 |
| 真实 NTFS | `U+212A`、`U+017F`、`U+00DF`、`U+FB01`、`U+FB06`、`U+212B`、`U+1C80`、基本平面之外一对：都是两个不同的目录 |
| 变异：17 个（`dots:*`、`fold:*`、`session:*`、`glob:*`、`trust:*`），副本上跑 4 个测试文件 | **17 个全部抓到**。未改的副本 2351 passed, 626 skipped |
| 差分：`2f8f59d` 对当前代码，179508 条，假机器（项目 `C:\proj`，所以孪生目录这一行差分没有覆盖，靠测试和真实目录） | 变化 3110 条，**从 deny 降级或从问变成无决定的 0 条** |
| key 稳定性：108 万次（固定种子，语法含 `ſ`、`K`、`ß`、非字母盘符） | 不稳定 0 |
| `uv run ruff check .`、`ruff format --check .`、`uv run mypy` | 通过；77 个源文件没有问题 |
| `boundkeep test` default / strict | 1142 / 0 失败，334 / 0 失败 |
| 评测（`--config rules+taint --test-contaminated`，输出到 scratchpad，没有打开留出批次） | `results/*.json` 去掉日期、延迟、sha 之后相同；`report.md` 只有 4 行延迟不同。策略 sha256 没变，所以仓库里的评测文件没有重新生成 |
| 相关测试（新文件、`test_m3a_path_gate_fixes.py`、`test_device_paths_not_sent.py`、`test_norm_paths.py`、`test_norm_prefix_folding.py`、`test_m3a_low_residuals.py`、`test_m3a_review_fixes.py`、`test_m3a_x1_fixes.py`、`test_m3a_rev8_window_fork.py`、`test_m3a_rev8_sources_marks.py`、`test_m1c4_scratchpad.py`、`test_policy_glob.py`） | 3743 passed, 9 skipped |
| 全量（分六段，隐藏窗口，绑 P 核；不是一个进程，第一段到第六段各自 `pytest -q`） | **27803 passed, 169 skipped, 0 failed**。2:04:02（09:47:58 到 11:52:00），六段都是一次跑完、退出码 0，没有重跑。合计 27972 条，与 `pytest --collect-only` 收集到的 27972 条相同；六段的文件列表与 `tests/` 下 116 个测试文件相同；开跑之后 `src/`、`tests/`、`policies/`、`eval/` 没有文件改过 |

已修改的旧测试：`test_norm_paths.py` 三行（`dots-trailing-space`、`dots-last-component-all-stripped`、`none-trailing-dots-on-last-component`），`test_m3a_path_gate_fixes.py` 的最后一段从"确定"移到"不确定"。这些都是有意的行为变化。

## 6. 代价和残余

1. **`rm -rf a.txt.` 变成 deny**（`rm-outside-project`），`rm -rf .env.` 也一样。路径不确定，这条规则就按项目外算。差分里这类共 984 条（528 条原来送审或问，456 条原来由别的 ask 规则问）。这样的写法很少，只记下来。
2. **配置了后端时这些路径仍然送审**：模型看到的 key 还是去掉点之后的（`inside_project` 是 null），模型放行就是无决定。这与其他不确定的路径相同（记录 `M3a-path-gate-fixes.md` 第 6 节第 5 条）。孪生目录不一样：key 保留那个字符，模型看到的是 `c:/wor` 加 `U+212A`，不再写成 `<project>/…`。
3. **只量了 NTFS 和这一台机器的内核表**（Windows 11 build 26200）。FAT、exFAT、ReFS、SMB 共享、其他 Windows 版本格式化的卷，表可能不同；哪个文件系统把 `ſ` 和 `s` 算同一个时，key 反而说成两个，allow 侧是谨慎方向，deny 侧靠 `path_glob` 的 `casefold` 兜住。
4. **表按 Unicode 15.0 量的**（Python 3.12）。项目支持 3.11 以上，其他版本的 `casefold` 可能多合并新增的大小写对，表里没有；对比测试在别的 Unicode 版本上跳过。
5. **`session/marks.py:location_key` 仍然 `casefold`**：写到孪生目录的标记也算到项目上。这是多问，不是少问，没有改。
6. **已经存下的 `trusted_projects`**：路径含这些字符时，旧的 key（`weiss`）不再匹配新的 key（`weiß`），要重新 `trust add`。方向是谨慎的，目前也没有真实用户。
7. **没有修的**：复审的 GR-3（规格说 `> nul` 内容被丢弃，只对 cmd 成立）、GR-4（目录扫描跟着链接访问目标）、GR-5（共享名是变量或通配符）；审查的 G-6、G-7、G-8、G-10、G-11、G-12，T-4、T-5，I-2。范围是使用者定的。
8. **`:\x`、`1a:\x`、`C1:\x`、中间一段带冒号**：key 还是错的且确定，这种路径 NTFS 大概率打不开（没有量）。记录 `M3a-path-gate-fixes.md` 第 6 节第 3 条那一类，没有动。

## 7. 没有做的

- 这次修复没有复审。
- 真实 Claude Code 里没有跑。Git Bash、Node、PowerShell 是独立运行的，宿主的 Read、Write、Grep、Glob 实际怎么打开这些路径没有量。
- 其他文件系统和 Windows 版本（第 6 节第 3 条）。
