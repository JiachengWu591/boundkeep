"""E6 / E16 / E22：逐个"坏 hook"模式跑一轮 claude -p，汇总 Claude 对每种失败的反应。

用法：python experiments/run_failmodes.py [模式 ...]    不带参数时跑全部。
每个模式：lab_setup --profile fail --fail <模式> -> run_cli_probe（提示词：执行一条 Write-Output）-> 汇总：
  hook 有没有真的被启动、Claude 记录的 exit_code / outcome / stdout / stderr、工具有没有执行。
结果同时写到 experiments/raw/failmodes.json。
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.environ.get("BK_FAIL_LAB", r"E:\bk-lab-fail")
MODES = [
    "nonexist", "cmdshim", "notexec", "exit127", "exit3", "stderr_only", "plain_text", "badjson",
    "json_and_exit2", "jsondeny_exit1", "old_block", "nonutf8", "bigout", "hang_noread",
    "shellform_noamp", "shellform_amp", "shellform_ps", "shellform_bash",
    "miseshim", "winapps", "exe_launcher", "unicode_exe", "unicode_script",
]
PROBE_LABEL = {
    "shellform_noamp": "shellform-noamp", "shellform_amp": "shellform-amp", "shellform_ps": "shellform-ps",
    "shellform_bash": "shellform-bash", "miseshim": "mise-shim", "winapps": "winapps-alias",
    "exe_launcher": "exe-launcher", "unicode_exe": "unicode-exe", "unicode_script": "unicode-script",
}


def load_events(run):
    out = []
    with open(os.path.join(HERE, "raw", "events.jsonl"), "rb") as f:
        for line in f:
            try:
                r = json.loads(line)
            except Exception:
                continue
            if (r.get("env_values") or {}).get("BK_RUN") == run:
                out.append(r)
    return out


def ascii_head(s, n=70):
    return json.dumps((s or "")[:n], ensure_ascii=True)


def run_mode(mode):
    name = "fail_" + mode
    if mode == "winapps" and not os.path.exists(os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe")):
        return {"mode": mode, "skipped": "no WindowsApps python.exe alias on this machine"}
    r = subprocess.run([sys.executable, os.path.join(HERE, "lab_setup.py"), "--profile", "fail", "--lab", LAB, "--fail", mode],
                       capture_output=True)
    if r.returncode != 0:
        return {"mode": mode, "error": r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace")}
    prompt = os.path.join(LAB, "prompts", "prompt_fail.txt")
    with open(prompt, "wb") as f:
        f.write(("请用 PowerShell 工具执行 Write-Output 'BK_FAIL_%s'，然后只回复 DONE。\n" % mode).encode("utf-8"))
    subprocess.run([sys.executable, os.path.join(HERE, "run_cli_probe.py"), "--name", name, "--prompt", prompt, "--lab", LAB],
                   capture_output=True)
    stream = []
    try:
        with open(os.path.join(HERE, "raw", "runs", name, "stdout.jsonl"), "rb") as f:
            for line in f:
                try:
                    stream.append(json.loads(line))
                except Exception:
                    pass
    except OSError:
        pass
    ev = load_events(name)
    expect = PROBE_LABEL.get(mode, "fail-hook")
    started = any(e.get("label") == expect and (expect != "fail-hook" or e.get("mode") == mode) for e in ev)
    pre = [m for m in stream if m.get("subtype") == "hook_response" and m.get("hook_event") == "PreToolUse"]
    odd = [m for m in pre if m.get("exit_code") != 0 or m.get("outcome") != "success" or m.get("stdout") or m.get("stderr")]
    executed = any(e.get("event") == "PostToolUse" for e in ev)
    result = next((m for m in stream if m.get("type") == "result"), {})
    denied = [m for m in stream if m.get("subtype") == "permission_denied"]
    return {
        "mode": mode,
        "hook_process_started": started,
        "pre_hook_responses": len(pre),
        "odd_responses": [{"exit": m.get("exit_code"), "outcome": m.get("outcome"), "stdout": ascii_head(m.get("stdout")),
                           "stderr": ascii_head(m.get("stderr")), "output": ascii_head(m.get("output"))} for m in odd],
        "tool_executed": executed,
        "permission_denied": len(denied),
        "model_result": ascii_head(result.get("result"), 120),
    }


def main():
    modes = sys.argv[1:] or MODES
    results = []
    for mode in modes:
        res = run_mode(mode)
        results.append(res)
        print(json.dumps(res, ensure_ascii=True))
        sys.stdout.flush()
    path = os.path.join(HERE, "raw", "failmodes.json")
    old = []
    if os.path.exists(path):
        try:
            old = json.load(open(path, encoding="utf-8"))
        except Exception:
            old = []
    seen = {r["mode"] for r in results}
    with open(path, "w", encoding="utf-8") as f:
        json.dump([r for r in old if r.get("mode") not in seen] + results, f, ensure_ascii=True, indent=1)


if __name__ == "__main__":
    main()
