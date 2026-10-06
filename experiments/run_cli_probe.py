"""用 claude -p 在实验目录里触发工具调用，观察 hook（M0a 的 E1 到 E24 里需要真实 Claude Code 的那些）。

不做任何评测：提示词极短、用最便宜的模型、设花费上限。默认不保存会话（--persist 例外）。
子进程环境：清除所有 CLAUDE* 变量（否则会继承外层会话的令牌与会话号，既污染实验也串用凭据）；
--drop-python-env 时再清除 PYTHON*。BK_RUN 与 BK_PROBE_DIR 由本脚本设置。
输出写到 experiments/raw/runs/<name>/（未脱敏，已被 git 忽略）：stdout.jsonl、stderr.txt、meta.json、times.json
（times.json 里是每条输出到达的时刻，用来量工具调用的延迟）。
"""
import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def find_claude():
    pattern = os.path.join(os.path.expanduser("~"), ".vscode", "extensions", "anthropic.claude-code-*",
                           "resources", "native-binary", "claude*")
    found = sorted(glob.glob(pattern))
    return found[-1] if found else shutil.which("claude")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--prompt", required=True, help="提示词文件（UTF-8），经 stdin 传入")
    ap.add_argument("--lab", required=True)
    ap.add_argument("--claude", default=find_claude())
    ap.add_argument("--model", default="claude-haiku-4-5-20251001")
    ap.add_argument("--budget", default="0.50")
    ap.add_argument("--drop-python-env", action="store_true")
    ap.add_argument("--extra-env", action="append", default=[], help="KEY=VALUE，可重复")
    ap.add_argument("--no-default-allow", action="store_true", help="不预先允许 Write-Output / Read / Write")
    ap.add_argument("--allow", action="append", default=[], help="额外的 --allowedTools 项，可重复")
    ap.add_argument("--setting-sources", default="project")
    ap.add_argument("--persist", action="store_true", help="保存会话（resume 实验需要）")
    ap.add_argument("--arg", action="append", default=[], help="原样传给 claude 的参数，写成 --arg=--flag，可重复")
    ap.add_argument("--timeout", type=int, default=300)
    a = ap.parse_args()

    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("CLAUDE")}
    if a.drop_python_env:
        env = {k: v for k, v in env.items() if not k.upper().startswith("PYTHON")}
    for kv in a.extra_env:
        k, _, v = kv.partition("=")
        env[k] = v
    env["BK_RUN"] = a.name
    env["BK_PROBE_DIR"] = os.path.join(HERE, "raw")
    allowed = ([] if a.no_default_allow else ["PowerShell(Write-Output *)", "Read", "Write"]) + a.allow
    cmd = [a.claude, "-p", "--model", a.model,
           "--output-format", "stream-json", "--verbose", "--include-hook-events",
           "--setting-sources", a.setting_sources,
           "--permission-prompts", "none", "--max-budget-usd", a.budget]
    if not a.persist:
        cmd.append("--no-session-persistence")
    cmd += a.arg
    if allowed:
        cmd += ["--allowedTools", *allowed]
    with open(a.prompt, "rb") as f:
        prompt = f.read()
    out_dir = os.path.join(HERE, "raw", "runs", a.name)
    os.makedirs(out_dir, exist_ok=True)

    t0 = time.time()
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=a.lab, env=env)
    lines, times, err_chunks = [], [], []

    def read_out():
        for line in p.stdout:
            lines.append(line)
            times.append(round(time.time() - t0, 3))

    def read_err():
        err_chunks.append(p.stderr.read())

    threads = [threading.Thread(target=read_out), threading.Thread(target=read_err)]
    for t in threads:
        t.start()
    try:
        p.stdin.write(prompt)
        p.stdin.close()
    except OSError:
        pass
    try:
        rc = p.wait(timeout=a.timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        rc = "timeout"
    for t in threads:
        t.join(timeout=10)
    elapsed = round(time.time() - t0, 1)
    out, err = b"".join(lines), b"".join(err_chunks)
    with open(os.path.join(out_dir, "stdout.jsonl"), "wb") as f:
        f.write(out)
    with open(os.path.join(out_dir, "stderr.txt"), "wb") as f:
        f.write(err)
    with open(os.path.join(out_dir, "times.json"), "w", encoding="utf-8") as f:
        json.dump(times, f)
    with open(os.path.join(out_dir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump({"cmd": cmd, "rc": rc, "elapsed_s": elapsed, "cwd": a.lab, "drop_python_env": a.drop_python_env,
                   "dropped_claude_env_names": sorted(k for k in os.environ if k.upper().startswith("CLAUDE"))},
                  f, ensure_ascii=True, indent=1)
    print("run %s: rc=%s elapsed=%ss stdout=%d bytes stderr=%d bytes" % (a.name, rc, elapsed, len(out), len(err)))
    summarize(out)
    if err.strip():
        print("stderr tail:", err.decode("utf-8", "replace")[-400:].encode("ascii", "backslashreplace").decode("ascii"))
    return 0


def summarize(out):
    counts = {}
    for line in out.decode("utf-8", "replace").splitlines():
        try:
            m = json.loads(line)
        except Exception:
            continue
        key = (m.get("type"), m.get("subtype"))
        counts[key] = counts.get(key, 0) + 1
        if m.get("type") == "system" and m.get("subtype") == "init":
            print("init: session_id=%s model=%s tools=%d (%s)" % (m.get("session_id"), m.get("model"),
                  len(m.get("tools") or []), ",".join(t for t in (m.get("tools") or []) if t.startswith(("mcp__", "Bash", "PowerShell", "Task", "Agent")))))
        if m.get("type") == "result":
            res = {k: m.get(k) for k in ("subtype", "is_error", "num_turns", "total_cost_usd", "result")}
            print("result:", json.dumps(res, ensure_ascii=True)[:900])
    print("message types:", {"%s/%s" % k: v for k, v in sorted(counts.items(), key=str)})


if __name__ == "__main__":
    sys.exit(main())
