# M3a 收尾记录

日期：2026-11-01。依据：`docs/reports/M3a.md` 第 9 节、`docs/reports/M3a-rereview-fixes-2.md` 第 9 节、`docs/reviews/M3a-rereview-2.md`。这一步没有改产品代码（`src/`、`policies/`、`tests/` 都没动），规则、策略与评测数字不变。没有读 `.env`，没有用任何 LLM 密钥（冒烟里 LLM 是 127.0.0.1 上的假服务，密钥是写在脚本里的假值），没有打开留出批次。

## 1. 结论

**通过，已打 `m3a-done`（使用者 2026-11-01 决定）。** 第二轮定向复审没有高危、中危；真实 Claude Code 冒烟 26 项通过；全量测试 26870 通过、169 跳过、0 失败。条件：LLM 层没有接过任何真实服务，它对攻击的实际效果要到 M3b 才知道，任何文档都不能对它的效果做表述；`auto` 模式没有测到；低危残余见第 5 节。

## 2. 审查与修复的经过

| 轮次 | 报告 | 发现 | 处理 |
|---|---|---|---|
| X1 独立审查 | 写到 F1 中间被安全分类器中止，残稿没有进仓库（第 6 节第 3 条） | 高 0、中 6、低 7、信息 2 | `M3a-review-fixes.md`、`M3a-review-fixes-2.md`、规格修订 7。低危 F7–F13 与信息项的细节已经拿不到 |
| 第一轮定向复审 | `docs/reviews/M3a-rereview.md` | 高 0、中 5、低 5、信息 3 | `M3a-rereview-fixes.md`、`M3a-rereview-fixes-2.md`、规格修订 8 |
| 第二轮定向复审 | `docs/reviews/M3a-rereview-2.md` | 高 0、中 0、低 7、信息 2 | 第 5 节 |

三轮的严重度一路下降，第二轮定向复审之后没有高危、中危，所以这里不再开一轮修复：低危按第 5 节的计划处理。

## 3. 验收

- `uv run ruff check .`：通过。`uv run ruff format --check .`：通过（残稿移走之后）。`uv run mypy`：77 个源文件没有问题。
- `boundkeep test`：default 1138 条、strict 334 条，0 失败。
- 全量 `uv run pytest -q`（2026-11-01，被测代码是 `75a24b1`：`src/`、`tests/`、`policies/` 相对它没有改动）：**26870 passed, 169 skipped in 6366.16s (1:46:06)**，退出码 0。跳过的是 POSIX 专用、需要符号链接权限、本机没有可用 bash 的用例，以及默认不跑的 live 测试。这是修订 8 之后第一次没有失败的全量：`M3a-rereview-fixes-2.md` 第 5.1 节那次有 1 条旧测试失败（改后只重跑了那个文件），9 个 PowerShell 用例也是那次开始之后才加的。运行时 Windows 的电源方案是 Silent（用户试过切到 Turbo，`powercfg` 仍显示 Silent），所以比 M3a 那次（Turbo，1:11:37）慢；`M3a.md` 第 5.1 节记的 Silent 下会失败的 4 条计时测试，这次都通过了。
- **真实 Claude Code 冒烟**（2026-11-01，2.1.304，`claude -p`，haiku，`scripts/smoke_claude_m3a.py`）：26 项检查 0 失败，6 次运行共约 0.31 美元。逐条结果在 `docs/hook-behavior.md`"M3a 的真实冒烟"。我另外对照审计日志、原始输出和磁盘上的文件核对过，一致。这是真的 boundkeep 第一次在真实宿主里跑这些链路：SessionStart 的 hook、fork 与 resume、项目标记的跨会话链路、按 `tool_use_id` 计数的窗口。
- 脚本自己的验证（没有调用模型）：用一个假宿主（只在会话的临时目录里，没有进仓库）跑真实的 hook、守护进程与规则，正常情况 26 项通过；把宿主改坏 4 种（不发 SessionStart、SessionStart 来晚、批准后没有 PostToolUse、拒绝后也有 PostToolUse）都报失败；模型没调用工具、漏了步骤时的补跑分支也走过。
- 评测：规则与策略没有改，没有重新生成。

## 4. 这一步的改动

| 文件 | 说明 |
|---|---|
| `scripts/smoke_claude_m3a.py`（新） | 真实冒烟。三部分：fork、window、auto（auto 只记录）。单次运行有花费上限（`--budget`），累计超过 `--max-total` 不再开新的运行 |
| `experiments/mcp_permission_server.py` | 新环境变量 `BK_PERM_ONLY`（正则）：请求的 JSON 匹配不上就拒绝。不设时行为不变。冒烟用它只批准那几条复制命令和那个保留域名的抓取，模型跑偏也不会被批准 |
| `docs/hook-behavior.md` | 新一节"M3a 的真实冒烟" |
| `PROJECT_SPEC.md` | §7：P-R5 的例外名单写成与代码一致，写明运行类子命令的残余（S-2）；来源的局限补上"运行代码自己去取的内容"（S-4）。开头的当前进度与 §14 的状态列 |
| `IMPLEMENTATION_PROMPTS.md`、`CLAUDE.md`、`docs/threat-model.md` | 状态与残余 |
| `docs/policy-reference.md`、`README.md` | `trusted_projects` 有条件推荐；README 另更正了污染来源的说法与 `docs/threat-model.md` 的指向 |
| `docs/reviews/M3a-rereview-2.md` | 第二轮定向复审的报告，随文档提交 |

## 5. 残余与计划

都不是高危、中危，都不挡 `m3a-done`。"M3b 之前"是因为 M3b 第一次接真实后端，有的只在配置了 LLM 时才有影响，其余是顺手一起修。

| 编号 | 残余 | 计划 |
|---|---|---|
| S-1 | 守护进程没记下 SessionStart 时，fork、resume 出来的会话从干净状态开始（规格 §10 已写明的一处失败即放行） | M3b 之前；要改规格（§7 P-R9、§10）：装过 SessionStart 的安装里，库里没有的会话按 `inherited:unknown` 开始 |
| S-2 | 运行类子命令（`npx`、`cargo run`、`pipx run` 等）不算来源 | 规格文字这次已写准。M3b 之前把总是运行远端包的写法从名单里拿掉 |
| S-3 | shell 来源只在 PreToolUse 记；守护进程不在线时，被批准的 `gh issue view` 不记 | M3b 之前；不用改规格 |
| S-4 | 运行代码自己去取的远端内容不算来源 | 规格局限这次已写明。不改代码 |
| S-5 | 名单之外、会改工作区的 git 子命令（`revert`、`stash branch`、`worktree add` 等）不打标记 | M3b 之前；不用改规格 |
| S-6 | 写在盘符根或文件系统根的工具配置（`E:\pytest.ini`）只记文件本身，覆盖不到下面的项目 | M3b 之前；要改规格（§7 P-R7） |
| S-7 | 被问甚至被拒的运行代码的调用也给项目打标记；配置了 LLM 时，这能关掉这个项目的 LLM 层、制造询问疲劳 | M3b 之前；可选的规格变更（§7 P-R6）：判决是 deny 的动作不打标记 |
| R-8 | 一次调用写 1001 个项目外路径，把标记换成"所有位置" | 仍建议暂不处理 |
| S-8、S-9 | 信息项：`audit-only` 下被 deny 的网络调用不算来源；`npm view` 这类带 `exec` 的来源在自己那次调用里就打标记 | 不处理 |
| `auto` 模式 | 冒烟里 `init` 事件写 `auto`，hook 收到 `default`，询问被拒。分不清是 auto 没生效，还是它不批准 hook 的询问 | 仍未知。如果 auto 会自动批准，窗口会在没人看的情况下被消耗（只影响配置了 LLM 的用户）。M3b 之前再测一次 |
| 没覆盖的宿主 | 真人在确认框里批准（冒烟里由权限提示工具代替）；VS Code 扩展与桌面应用里的这些链路；`Bash` 工具 | 手工验收时看 |
| F7–F13 | 第一次 X1 审查的低危，细节已丢失 | 无法核对 |

## 6. 使用者的决定（2026-11-01，"全部按建议办"）

1. **`m3a-done` 与推送**：标签打在这一步的文档提交上，连同之前没推送的提交一起推送。
2. **`trusted_projects` 改为有条件推荐**：默认仍是空列表，写明只信任自己写过或审计过的仓库，并列出第 5 节的残余（`docs/policy-reference.md`、README）。
3. **残缺的审查报告**：`docs/reviews/M3a-security-review.md` 没有进仓库，移入了 Windows 回收站，清空之前可以从那里恢复。它的结论段记在 `M3a-review-fixes.md` 第 6.1 节；留着它 `ruff format --check` 会一直报它。较早的修复报告里提到这个路径的地方是当时的记录，没有改。
4. **修订 8 实现时补的三处规格文字**（`M3a-rereview-fixes-2.md` 第 4 节第 1、2、4 条）：接受。

## 7. 进入下一步的前置条件

- M3b 要你自备密钥、确认费用，在你自己的 shell 里运行。M4、M5 不依赖 M3b，前置（M3a 已验收）已满足。
- 建议先修第 5 节计划在 M3b 之前做的低危，再接真实后端。
