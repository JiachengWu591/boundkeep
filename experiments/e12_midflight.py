"""E12：会话进行中，外部进程把 .claude/settings.local.json 改成 {"disableAllHooks": true}，
看 ConfigChange 是否触发、之后的 hook 是否还在跑。

流程：启动 run_cli_probe.py（提示词里第 2 步是 Start-Sleep 15 秒）；一旦记录器看到那条 Start-Sleep 的 PreToolUse，
就写入配置文件并记下时刻；等运行结束后汇总。用法：python experiments/e12_midflight.py
前提：已用 `lab_setup.py --profile e12 --lab E:\\bk-lab-e12` 建好实验目录。
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.environ.get("BK_E12_LAB", r"E:\bk-lab-e12")
NAME = os.environ.get("BK_E12_NAME", "e12_midflight")
EVENTS = os.path.join(HERE, "raw", "events.jsonl")


def events():
    out = []
    if os.path.exists(EVENTS):
        with open(EVENTS, "rb") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if (r.get("env_values") or {}).get("BK_RUN") == NAME:
                    out.append(r)
    return out


def main():
    cmd = [sys.executable, os.path.join(HERE, "run_cli_probe.py"), "--name", NAME,
           "--prompt", os.path.join(LAB, "prompts", "prompt_e12b.txt"), "--lab", LAB,
           "--setting-sources", "project,local", "--allow", "PowerShell(Start-Sleep *)"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    t_write = None
    deadline = time.time() + 150
    while p.poll() is None and time.time() < deadline:
        if t_write is None:
            for r in events():
                c = ((r.get("payload") or {}).get("tool_input") or {}).get("command") or ""
                if r.get("event") == "PreToolUse" and "Start-Sleep" in c:
                    time.sleep(3)  # 让 sleep 真正跑起来
                    with open(os.path.join(LAB, ".claude", "settings.local.json"), "wb") as f:
                        f.write(b'{"disableAllHooks": true}\n')
                    t_write = time.strftime("%H:%M:%S", time.gmtime())
                    t_write_ms = time.time()
                    break
        time.sleep(0.3)
    out = p.communicate()[0].decode("utf-8", "replace")
    print(out.encode("ascii", "backslashreplace").decode("ascii")[-900:])
    print("settings.local.json written (UTC) at:", t_write)
    for r in events():
        if r.get("label") in ("pre-iso", "post-iso", "cfg-change", "session-start", "stop"):
            p_ = r.get("payload") or {}
            c = (p_.get("tool_input") or {}).get("command") or ""
            print("  ", r["ts"][11:23], "%-13s" % r["label"], "%-14s" % r.get("event"), json.dumps(c, ensure_ascii=True)[:60],
                  json.dumps({k: p_[k] for k in ("file_path", "source") if k in p_}))


if __name__ == "__main__":
    main()
