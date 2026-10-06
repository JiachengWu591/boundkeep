"""创建 M0a 的一次性实验目录，并写入项目级 hook 配置（提示词 M0a：实验在仓库之外的一次性目录里做）。

用法：python experiments/lab_setup.py [--profile base] [--lab <目录>] [--python <解释器绝对路径>] [--fail <模式>]
- 只写实验目录；不动用户级 settings.json。目录里放 .bk-lab 标记文件；非空且没有该标记时拒绝写入。
- hook 用 exec 形式（command + args，不经过 shell），除非该实验就是要测 shell 形式。
- 配置（profile）：
    base      E15 / E3 / E4 / E13 / E9 的基础配置：5 类事件的记录器，PreToolUse 上 pre-iso 与 pre-noiso 并行
    matchers  E5 / E13：十几种 matcher 写法各挂一个记录器，外加最小 MCP 服务的配置
    e11       E11：权限规则（ask / deny）+ PermissionRequest / PermissionDenied 记录器，不预先允许任何工具
    e12       E12：base + ConfigChange 记录器
    fail      E6 / E16 / E22：pre-iso 记录器 + 一个坏 hook（--fail 指定模式）
    e14       E14：pre-iso 记录器 + prompt 或 agent hook（--hooktype，--cob 加 continueOnBlock）
"""
import argparse
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "probe_hook.py")
FAIL = os.path.join(HERE, "fail_hook.py")
MCP = os.path.join(HERE, "mcp_echo_server.py")

ALLOW_BASE = ["PowerShell(Write-Output *)", "Read", "Write"]
UNICODE_DIR = "\u8def\u5f84 \u6d4b\u8bd5"  # "路径 测试"：含空格与中文

PROMPTS = {
    "prompt_a.txt": """这是一个 hook 行为实验，请严格按下面三步执行，不要做别的事：
1. 用 PowerShell 工具执行：Write-Output 'BK_A_MARK ✓ 中文'
2. 用 Read 工具读取当前目录下的 probe.txt
3. 用 Write 工具创建 out_a.txt，内容为 hi
完成后只回复 DONE。
""",
    "prompt_b.txt": """这是一个 hook 行为实验。请按顺序逐条执行下面的 PowerShell 命令：每条单独调用一次 PowerShell 工具，不要合并，不要重试；即使被拒绝或报错也继续下一条。全部完成后，用一句话汇报每条的结果（成功的输出、被拒绝时的拒绝理由原文、或报错）。
1. Write-Output BK_EXIT1_MARK
2. Write-Output BK_EXIT2_MARK
3. Write-Output BK_DENY_MARK
4. Write-Output BK_SLEEP_MARK
5. Write-Output BK_NAIVE_MARK
6. Write-Output BK_ASK_MARK
""",
    "prompt_d.txt": """这是一个 hook 行为实验，请严格按下面两步执行，不要做别的事：
1. 用 Bash 工具执行：echo BK_D_MARK ✓ 中文 && pwd
2. 用 PowerShell 工具执行：Write-Output 'BK_D_PS'
完成后只回复 DONE。
""",
    "prompt_m.txt": """这是一个 hook 匹配实验，请按顺序逐步执行，每步单独调用一次对应工具，不要合并、不要重试，失败也继续：
1. PowerShell 工具：Write-Output 'BK_M_PS'
2. Read 工具：读取 probe.txt
3. Write 工具：创建 out_m.txt，内容为 hi
4. Read 工具读取 notes.txt，然后用 Edit 工具把其中的 alpha 改成 beta
5. Glob 工具：模式 *.txt
6. Grep 工具：在当前目录搜索 probe
7. WebFetch 工具：抓取 https://example.com，用一句话说明页面标题
8. MCP 工具 mcp__bkmcp__echo：text 参数为 BK_M_MCP
完成后只回复 DONE。
""",
    "prompt_e4.txt": """BK_UPS_CTX 这是一个 hook 实验。
1. 用 PowerShell 工具执行：Write-Output 'BK_CTX_marker'
2. 然后回答：你的上下文里有没有以 BK_CTX_NONCE 或 BK_UPS_NONCE 开头、后面还带着一串字符的额外信息？有就原样抄出完整内容；没有就只回答 NONE。
""",
    "prompt_e11.txt": """这是一个权限语义实验。请按顺序逐条执行下面的 PowerShell 命令：每条单独调用一次 PowerShell 工具，不要合并，不要重试；即使被拒绝也继续下一条。全部完成后用一句话汇报每条是成功还是被拒绝，以及拒绝理由原文。
1. Write-Output BK_PLAIN
2. Write-Output BK_ALLOW_PLAIN
3. Write-Output BK_ASKRULE_PLAIN
4. Write-Output BK_ASKRULE_BK_ALLOW
5. Write-Output BK_DENYRULE_PLAIN
6. Write-Output BK_DENYRULE_BK_ALLOW
""",
    "prompt_e11b.txt": """这是一个权限语义实验（用会写文件的命令，因为只读命令本来就不需要批准）。请按顺序逐条执行下面的 PowerShell 命令：每条单独调用一次 PowerShell 工具，不要合并，不要重试；即使被拒绝也继续下一条。全部完成后用一句话汇报每条是成功还是被拒绝。
1. New-Item -ItemType File -Path BK_PLAIN_F.txt -Force
2. New-Item -ItemType File -Path BK_ALLOW_F.txt -Force
3. New-Item -ItemType File -Path BK_ASKRULE_BK_ALLOW_F.txt -Force
4. New-Item -ItemType File -Path BK_DENYRULE_BK_ALLOW_F.txt -Force
5. New-Item -ItemType File -Path BK_ASKRULE_F.txt -Force
""",
    "prompt_e11_modes.txt":"""这是一个权限模式实验。请按顺序逐条执行下面的 PowerShell 命令：每条单独调用一次 PowerShell 工具，不要合并，不要重试；即使被拒绝也继续下一条。全部完成后用一句话汇报每条是成功还是被拒绝。
1. Write-Output BK_PLAIN_MODE
2. Write-Output BK_DENY_MODE
3. Write-Output BK_ASK_MODE
4. Write-Output BK_ALLOW_MODE
""",
    "prompt_e12.txt": """这是一个配置篡改实验，请按顺序执行，每步单独调用一次对应工具，不要重试，失败也继续：
1. Write 工具：创建 .claude/settings.local.json，内容为 {"disableAllHooks": true}
2. PowerShell 工具：Set-Content -Path .claude/settings.local.json -Value '{"disableAllHooks": true}'
3. PowerShell 工具：Write-Output 'BK_E12_AFTER'
全部完成后用一句话汇报每步是成功还是被拒绝。
""",
    "prompt_e12b.txt": """这是一个 hook 实验，请按顺序执行 PowerShell 命令，每条单独调用一次，不要合并：
1. Write-Output 'BK_BEFORE'
2. Start-Sleep -Seconds 15
3. Write-Output 'BK_AFTER'
完成后只回复 DONE。
""",
    # 含 $ 变量或 .NET 属性访问的写法（如 Write-Output $PSVersionTable.PSEdition）在 -p 下需要批准而被拒，所以用只读 cmdlet
    "prompt_ws.txt": """这是一个 hook 覆盖面实验：请用 WebSearch 工具搜索 "example domain iana"，然后只回复 DONE。
""",
    "prompt_e20.txt":"""这是一个环境探测实验，请按顺序执行下面两条 PowerShell 命令，每条单独调用一次，然后把两条的输出原样汇报：
1. Get-Host
2. Get-ExecutionPolicy -List
""",
    "prompt_e13.txt": """这是一个 hook 覆盖面实验：
1. 先不使用任何工具，只根据 @probe.txt 回答：这个文件第一行的第一个单词是什么？
2. 然后用 Task 工具启动一个子 agent，让它用 PowerShell 工具执行 Write-Output 'BK_SUB_PS'，并汇报输出。
完成后只回复 DONE。
""",
    "prompt_e14.txt": """这是一个 hook 实验。请按顺序逐条执行下面的 PowerShell 命令：每条单独调用一次 PowerShell 工具，不要合并，不要重试；即使被拒绝也继续下一条。全部完成后用一句话汇报每条的结果和拒绝理由原文。
1. Write-Output BK_PROMPT_OK
2. Write-Output BK_PROMPT_BLOCK
""",
    "prompt_resume.txt": """这是一个会话实验：请用 PowerShell 工具执行 Write-Output 'BK_RESUME'，然后只回复 DONE。
""",
    "prompt_par.txt": """这是一个并行实验：请在同一条消息里同时调用三个工具（并行，不要分开发）：Read 读取 probe.txt、Read 读取 notes.txt、PowerShell 执行 Write-Output 'BK_PAR'。完成后只回复 DONE。
""",
    "prompt_lat.txt": """这是一个延迟测量实验。请按顺序调用 Glob 工具 10 次，一次只调用一个，不要并行，每次的模式依次是：*.txt、*.md、*.json、prompts/*、*.py、*.cmd、*.log、.claude/*、**/*.txt、*。每次调用后不要评论。全部完成后只回复 DONE。
""",
    "prompt_ui.txt": """这是一个 hook 行为实验。请按顺序逐条执行下面的 PowerShell 命令：每条单独调用一次 PowerShell 工具，不要合并，不要重试；即使被拒绝或报错也继续下一条。全部完成后，用一句话汇报每条的结果。
1. Write-Output BK_EXIT1_MARK
2. Write-Output BK_EXIT2_MARK
3. Write-Output BK_DENY_MARK
4. Write-Output BK_SLEEP_MARK
5. Write-Output BK_NAIVE_MARK
6. Write-Output BK_ASK_MARK
""",
}

README_VSCODE = """# VS Code 扩展宿主里的 hook 触发检查（M0a E15）

1. 在 VS Code 里：文件 → 打开文件夹…，选择本目录（会开一个新窗口）。
2. 打开 Claude Code 面板，开始一个新会话。若出现"信任此文件夹"的对话框，选择信任
   （项目里的 hook 要接受信任之后才会运行）。
3. 把 prompts\\prompt_a.txt 的全部内容粘贴到输入框并发送。若被询问权限，选择允许
   （命令只有 Write-Output、读 probe.txt、写 out_a.txt）。
4. 看到回复 DONE 后，回到之前的会话告诉我"VS Code 测完了"。不需要做别的。

说明：如果这次会话里没有任何 hook 记录，也请告诉我——这本身就是要观察的结果。
"""

README_VSCODE_UI = """# VS Code 扩展里"用户能看到什么"的检查（M0a E6 / E8 的界面部分）

前提：同一个 E:\\bk-lab 窗口，开一个新会话。

1. 把 prompts\\prompt_ui.txt 的全部内容粘贴并发送。六条命令会被 hook 用不同方式处理：
   1 退出码 1　2 退出码 2（阻断）　3 JSON 拒绝　4 睡 30 秒（hook 的 timeout 是 5 秒）　5 hook 崩溃　6 JSON 询问
2. 过程中请留意并回答（没看到也请如实说"没看到"）：
   a. 哪几条命令弹出了权限询问框？框里有没有显示 hook 给的理由文字（例如 BK_ASK_REASON_5d1e）？
   b. 被阻断的两条（第 2、3 条），界面上有没有显示拒绝理由？显示在哪里（聊天里的一行警告、工具调用卡片、弹窗）？
   c. 第 1、4、5 条（hook 出错、超时、崩溃），界面上有没有任何错误或警告提示？原文是什么？
   d. 命令执行时，有没有黑色控制台窗口闪一下？
3. 同一个会话里接着做（E9：/clear 之后会话号是否变化）：输入 /clear，然后发一句"用 PowerShell 执行 Write-Output 'BK_AFTER_CLEAR'"。
4. 把以上回答发给我；第 3 步我会从 hook 记录里读会话号，不需要你看。

# 可选：没接受信任时 hook 会不会运行（E23）

5. 用 VS Code 打开另一个从没打开过的目录 E:\\bk-lab-matchers（新窗口）。出现"信任此文件夹"对话框时，**不要选信任**
   （选"不信任"或类似的受限选项，没有就直接关掉对话框）。
6. 在 Claude Code 面板里发："用 PowerShell 执行 Write-Output 'BK_UNTRUSTED'"。若被询问权限，选允许。
7. 告诉我：对话框上的按钮叫什么；你有没有进入"受限模式"之类的状态；命令执行了没有。我会从记录里看有没有 hook 事件。
"""


def default_lab(profile):
    base = "bk-lab" if profile == "base" else "bk-lab-" + profile
    if os.name == "nt":
        return (os.path.splitdrive(HERE)[0] or "C:") + "\\" + base
    return "/tmp/" + base


def hook(py, label, timeout, isolated=True, script=SCRIPT):
    args = (["-I", "-S"] if isolated else ["-S"]) + [script, label]
    return {"type": "command", "command": py, "args": args, "timeout": timeout}


def entry(hooks, matcher="__omit__"):
    e = {"hooks": hooks}
    if matcher != "__omit__":
        e["matcher"] = matcher
    return e


def base_hooks(py, pre_timeout=5):
    return {
        "SessionStart": [entry([hook(py, "session-start", 20)])],
        "UserPromptSubmit": [entry([hook(py, "prompt", 20)])],
        "PreToolUse": [entry([hook(py, "pre-iso", pre_timeout), hook(py, "pre-noiso", pre_timeout, isolated=False)], "*")],
        "PostToolUse": [entry([hook(py, "post-iso", 20)], "*")],
        "Stop": [entry([hook(py, "stop", 20)])],
    }


MATCHERS = [
    ("m-star", "*"), ("m-empty", ""), ("m-omitted", "__omit__"), ("m-bash-ps", "Bash|PowerShell"),
    ("m-ps-exact", "PowerShell"), ("m-ps-lower", "powershell"), ("m-pow-prefix", "Pow"), ("m-pow-regex", "Pow.*"),
    ("m-anch-regex", "^Pow.*$"), ("m-rw-list", "Read|Write|Edit|MultiEdit"), ("m-comma", "Read,Write"),
    ("m-mcp-regex", "mcp__.*"), ("m-mcp-exact", "mcp__bkmcp__echo"), ("m-glob-grep", "Glob|Grep"),
    ("m-web", "WebFetch|WebSearch"), ("m-task", "Task|Agent"),
]


def fail_entry(mode, py, lab, files):
    """返回要并行挂在 PreToolUse 上的坏 hook；files 收集要写进实验目录的文件。"""
    t = 5
    pyfail = {"type": "command", "command": py, "args": ["-I", "-S", FAIL, mode], "timeout": t}
    if mode in ("badjson", "json_and_exit2", "jsondeny_exit1", "nonutf8", "exit127", "exit3", "stderr_only",
                "old_block", "plain_text", "bigout", "hang_noread"):
        return pyfail
    if mode == "nonexist":
        return {"type": "command", "command": "D:\\no_such_dir\\nothing.exe", "args": ["x"], "timeout": t}
    if mode == "cmdshim":
        files["shim.cmd"] = "@echo off\r\nexit /b 0\r\n"
        return {"type": "command", "command": os.path.join(lab, "shim.cmd"), "args": ["x"], "timeout": t}
    if mode == "notexec":
        files["notexec.txt"] = "this is not an executable\n"
        return {"type": "command", "command": os.path.join(lab, "notexec.txt"), "args": ["x"], "timeout": t}
    if mode == "shellform_noamp":
        return {"type": "command", "command": '"%s" -I -S "%s" shellform-noamp' % (py, SCRIPT), "timeout": t}
    if mode == "shellform_amp":
        return {"type": "command", "command": '& "%s" -I -S "%s" shellform-amp' % (py, SCRIPT), "timeout": t}
    if mode == "shellform_ps":
        return {"type": "command", "shell": "powershell", "timeout": t,
                "command": '& "%s" -I -S "%s" shellform-ps' % (py, SCRIPT)}
    if mode == "shellform_bash":
        return {"type": "command", "shell": "bash", "timeout": t,
                "command": '"%s" -I -S "%s" shellform-bash' % (py.replace("\\", "/"), SCRIPT.replace("\\", "/"))}
    if mode == "miseshim":
        shim = os.path.expandvars(r"%LOCALAPPDATA%\mise\shims\python.exe")
        return {"type": "command", "command": shim, "args": ["-I", "-S", SCRIPT, "mise-shim"], "timeout": t}
    if mode == "winapps":
        stub = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe")
        return {"type": "command", "command": stub, "args": ["-I", "-S", SCRIPT, "winapps-alias"], "timeout": t}
    if mode in ("exe_launcher", "unicode_exe"):
        import make_launcher
        d = os.path.join(lab, "bin") if mode == "exe_launcher" else os.path.join(lab, UNICODE_DIR, "bin")
        made = make_launcher.build(d, python=py)
        return {"type": "command", "command": made[0], "args": [mode.replace("_", "-")], "timeout": t}
    if mode == "unicode_script":
        d = os.path.join(lab, UNICODE_DIR)
        os.makedirs(d, exist_ok=True)
        dst = os.path.join(d, "probe_hook.py")
        shutil.copyfile(SCRIPT, dst)
        return {"type": "command", "command": py, "args": ["-I", "-S", dst, "unicode-script"], "timeout": t}
    raise SystemExit("unknown --fail mode: %s" % mode)


def build(profile, py, lab, a):
    files = {}
    settings = {"hooks": base_hooks(py)}
    allow = list(ALLOW_BASE)
    if profile == "base":
        files["README_VSCODE.md"] = README_VSCODE
        files["README_VSCODE_UI.md"] = README_VSCODE_UI
    elif profile == "matchers":
        pre = [entry([hook(py, label, 10)], m) for label, m in MATCHERS]
        settings["hooks"] = {
            "SessionStart": [entry([hook(py, "session-start", 20)])],
            "PreToolUse": pre,
            "PostToolUse": [entry([hook(py, "post-iso", 20)], "*"), entry([hook(py, "m-post-mcp", 20)], "mcp__.*")],
        }
        allow += ["Edit", "Glob", "Grep", "WebFetch", "mcp__bkmcp__echo"]
        files["mcp.json"] = json.dumps({"mcpServers": {"bkmcp": {"command": py, "args": [MCP]}}}, indent=2) + "\n"
    elif profile == "e11":
        settings["hooks"] = {
            "PreToolUse": [entry([hook(py, "pre-iso", 10)], "*")],
            "PostToolUse": [entry([hook(py, "post-iso", 20)], "*")],
            "PermissionRequest": [entry([hook(py, "perm-request", 10)], "*")],
            "PermissionDenied": [entry([hook(py, "perm-denied", 10)], "*")],
        }
        settings["permissions"] = {
            "ask": ["PowerShell(Write-Output BK_ASKRULE*)", "PowerShell(New-Item *BK_ASKRULE*)"],
            "deny": ["PowerShell(Write-Output BK_DENYRULE*)", "PowerShell(New-Item *BK_DENYRULE*)"],
        }
        allow = []
    elif profile == "e12":
        label = "cfg-block" if a.cfg_block else "cfg-change"
        settings["hooks"]["ConfigChange"] = [entry([hook(py, label, 10)])]
        allow += ["PowerShell(Set-Content *)"]
    elif profile == "fail":
        fe = fail_entry(a.fail, py, lab, files)
        settings["hooks"] = {
            "PreToolUse": [entry([hook(py, "pre-iso", 10), fe], "*")],
            "PostToolUse": [entry([hook(py, "post-iso", 20)], "*")],
        }
    elif profile == "e14":
        ptxt = ('You are a security gate. Input JSON: $ARGUMENTS\nIf tool_input.command contains the text BK_PROMPT_BLOCK, '
                'respond with exactly {"ok": false, "reason": "BK_PROMPT_REASON_41aa"}. Otherwise respond with exactly {"ok": true}.')
        ph = {"type": a.hooktype, "prompt": ptxt, "timeout": 60}
        if a.cob and a.hooktype == "prompt":
            ph["continueOnBlock"] = True
        settings["hooks"] = {
            "PreToolUse": [entry([hook(py, "pre-iso", 10), ph], "*")],
            "PostToolUse": [entry([hook(py, "post-iso", 20)], "*")],
        }
    else:
        raise SystemExit("unknown profile: %s" % profile)
    if allow:
        settings.setdefault("permissions", {})["allow"] = allow
    files["probe.txt"] = "probe file for M0a E15\n"
    files["notes.txt"] = "alpha\n"
    for name, text in PROMPTS.items():
        files["prompts/" + name] = text
    files[".claude/settings.json"] = json.dumps(settings, indent=2) + "\n"
    return files


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:  # UTF-8、无 BOM；换行按文本里写的
        f.write(text.encode("utf-8"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="base", choices=["base", "matchers", "e11", "e12", "fail", "e14"])
    ap.add_argument("--lab")
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--fail", default="")
    ap.add_argument("--hooktype", default="prompt", choices=["prompt", "agent"])
    ap.add_argument("--cob", action="store_true", help="prompt hook 加 continueOnBlock")
    ap.add_argument("--cfg-block", action="store_true", help="e12：ConfigChange hook 阻止含 disableAllHooks 的变更")
    a = ap.parse_args()
    lab = os.path.abspath(a.lab or default_lab(a.profile))
    marker = os.path.join(lab, ".bk-lab")
    if os.path.isdir(lab) and os.listdir(lab) and not os.path.exists(marker):
        sys.exit("拒绝写入：%s 非空且不是 bk-lab 目录" % lab)
    if not os.path.isabs(a.python) or not os.path.exists(a.python):
        sys.exit("--python 必须是存在的绝对路径：%s" % a.python)
    sys.path.insert(0, HERE)
    # 清掉上一次实验可能留下的会改变 hook 行为的文件
    for stale in (".claude/settings.local.json", "out_a.txt", "out_m.txt"):
        p = os.path.join(lab, *stale.split("/"))
        if os.path.exists(p):
            os.remove(p)
    files = build(a.profile, a.python, lab, a)
    write(marker, "M0a lab, safe to delete\n")
    for rel, text in files.items():
        write(os.path.join(lab, *rel.split("/")), text)
    os.makedirs(os.path.join(HERE, "raw"), exist_ok=True)
    print("lab ready:", lab, "| profile:", a.profile + (" / " + a.fail if a.fail else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
