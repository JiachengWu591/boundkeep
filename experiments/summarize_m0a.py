"""把 M0a 各实验的结果从 experiments/raw/ 重新推导出来，生成脱敏的 experiments/evidence/m0a_summary.txt。

只读 raw/（未脱敏，被 git 忽略）；输出经 make_evidence 的脱敏规则处理，只含 ASCII。
用法：python experiments/summarize_m0a.py
"""
import json
import os
import statistics
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import analyze_latency  # noqa: E402
import make_evidence as me  # noqa: E402

RAW = os.path.join(HERE, "raw")


def events():
    out = []
    with open(os.path.join(RAW, "events.jsonl"), "rb") as f:
        for line in f:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


EV = events()


def run_events(run):
    return [e for e in EV if (e.get("env_values") or {}).get("BK_RUN") == run]


def stream(run):
    p = os.path.join(RAW, "runs", run, "stdout.jsonl")
    rows = []
    if os.path.exists(p):
        for line in open(p, "rb"):
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def result_text(run):
    for m in stream(run):
        if m.get("type") == "result":
            return m.get("result") or ""
    return ""


def cmd_of(e):
    ti = (e.get("payload") or {}).get("tool_input") or {}
    return ti.get("command") or ti.get("file_path") or ""


def sec(title):
    return ["", "=" * 8 + " " + title]


def e4():
    t = result_text("e4_ctx")
    return sec("E4 additionalContext") + [
        "PostToolUse nonce visible to model : %s" % ("BK_CTX_NONCE_9a1b" in t),
        "UserPromptSubmit nonce visible     : %s" % ("BK_UPS_NONCE_3c7d" in t)]


def e5():
    rows = [e for e in run_events("m_cli") if e.get("event") in ("PreToolUse", "PostToolUse")]
    tools, labels = [], []
    for r in rows:
        if r["tool"] not in tools:
            tools.append(r["tool"])
        if r["label"] not in labels:
            labels.append(r["label"])
    out = sec("E5 matcher x tool (PreToolUse; count of hook invocations)")
    pre = [r for r in rows if r["event"] == "PreToolUse"]
    out.append("%-14s" % "label" + " ".join("%-11s" % t[:11] for t in tools))
    for l in labels:
        if not any(r["label"] == l for r in pre):
            continue
        out.append("%-14s" % l + " ".join("%-11s" % (("x%d" % n) if (n := sum(1 for r in pre if r["label"] == l and r["tool"] == t)) else ".") for t in tools))
    matchers = {"m-star": "*", "m-empty": '""', "m-omitted": "(omitted)", "m-bash-ps": "Bash|PowerShell", "m-ps-exact": "PowerShell",
                "m-ps-lower": "powershell", "m-pow-prefix": "Pow", "m-pow-regex": "Pow.*", "m-anch-regex": "^Pow.*$",
                "m-rw-list": "Read|Write|Edit|MultiEdit", "m-comma": "Read,Write", "m-mcp-regex": "mcp__.*",
                "m-mcp-exact": "mcp__bkmcp__echo", "m-glob-grep": "Glob|Grep", "m-web": "WebFetch|WebSearch", "m-task": "Task|Agent"}
    fired = {r["label"] for r in pre}
    out.append("matchers that never fired: " + ", ".join("%s (%s)" % (l, m) for l, m in matchers.items() if l not in fired))
    return out


def e6():
    out = sec("E6 / E16 / E22 broken-hook modes (one claude -p run each)")
    p = os.path.join(RAW, "failmodes.json")
    if not os.path.exists(p):
        return out + ["(failmodes.json missing)"]
    for r in json.load(open(p, encoding="utf-8")):
        if "skipped" in r or "error" in r:
            out.append("%-16s %s" % (r["mode"], r.get("skipped") or r.get("error")))
            continue
        odd = "; ".join("exit=%s outcome=%s stderr=%s" % (o["exit"], o["outcome"], o["stderr"][:60]) for o in r["odd_responses"]) or "all hook responses success/no output"
        out.append("%-16s hook_started=%-5s tool_executed=%-5s %s" % (r["mode"], r["hook_process_started"], r["tool_executed"], odd))
    return out


def e9():
    out = sec("E9 sessions and config merge")
    for run in ("e9_s1", "e9_s2", "e9_s3", "e9_s4"):
        ss = [(e["payload"].get("source"), str(e["payload"].get("session_id"))[:8]) for e in run_events(run) if e.get("event") == "SessionStart"]
        out.append("%-7s SessionStart (source, session_id[:8]): %s" % (run, ss))
    out.append("e9_merge UserPromptSubmit hooks fired: %s" % sorted(e["label"] for e in run_events("e9_merge") if e.get("event") == "UserPromptSubmit"))
    pre = [e for e in run_events("e9_par_sonnet") if e.get("label") == "pre-iso"]
    out.append("e9_par_sonnet: PreToolUse starts %s (model issued one tool per turn, so parallel tool calls were NOT exercised)" % [e["ts"][17:23] for e in pre])
    return out


def e10():
    out = sec("E10 per-tool-call latency seen by the host (Glob x10 per run)")
    for label, runs in (("hooks ON ", ["e10_hooks_1", "e10_hooks_2"]), ("hooks OFF", ["e10_nohooks_1", "e10_nohooks_2"])):
        xs = sorted(x for r in runs for x in analyze_latency.latencies(r))
        out.append("%s n=%d p50=%.0f ms p95=%.0f ms min=%.0f max=%.0f" % (label, len(xs), statistics.median(xs), xs[min(len(xs) - 1, int(len(xs) * .95))], xs[0], xs[-1]))
    b = os.path.join(RAW, "bench_hook_cold_start.json")
    if os.path.exists(b):
        d = json.load(open(b))
        out += sec("E10 process cold start / pipe round trip (bench_hook_cold_start.py)")
        out.append("machine: %s" % json.dumps(d.get("machine")))
        for k, v in d.items():
            if k != "machine":
                out.append("%-62s %s" % (k, json.dumps(v)))
    return out


def e11():
    out = sec("E11 hook allow vs permission rules (e11_allow_b; New-Item needs approval unless a hook allows)")
    R = run_events("e11_allow_b")
    name = lambda e: cmd_of(e).split("-Path ")[-1].split(" ")[0]
    out.append("reached PreToolUse : %s" % [name(e) for e in R if e.get("event") == "PreToolUse" and e["label"] == "pre-iso"])
    out.append("executed           : %s" % [name(e) for e in R if e.get("event") == "PostToolUse"])
    out.append("PermissionRequest  : %s" % [name(e) for e in R if e.get("event") == "PermissionRequest"])
    out.append("rules: ask=New-Item *BK_ASKRULE*, deny=New-Item *BK_DENYRULE*; hook allows when the command contains BK_ALLOW")
    out += sec("E11 hook decisions under each permission mode (commands: PLAIN, DENY, ASK, ALLOW)")
    for mode in ("manual", "acceptEdits", "plan", "dontAsk", "auto"):
        R = run_events("e11_mode_" + mode)
        modes = sorted({e["payload"].get("permission_mode") for e in R if e.get("event") == "PreToolUse" and e.get("payload")})
        ran = [cmd_of(e).replace("Write-Output ", "") for e in R if e.get("event") == "PostToolUse"]
        out.append("--permission-mode %-12s payload permission_mode=%s executed=%s" % (mode, modes, ran))
    return out


def e12():
    out = sec("E12 disableAllHooks / config tampering")
    d = run_events("e12_disable")
    out.append("e12_disable: settings.local.json={disableAllHooks:true} present at start -> recorder events=%d, hook_started=%d" % (
        len(d), sum(1 for m in stream("e12_disable") if m.get("subtype") == "hook_started")))
    t = stream("e12_tamper")
    out.append("e12_tamper: permission_denied for %s" % [m.get("tool_name") for m in t if m.get("subtype") == "permission_denied"])
    for run in ("e12_midflight", "e12_midflight_block"):
        R = [e for e in run_events(run) if e.get("label") in ("pre-iso", "post-iso", "cfg-change", "cfg-block", "stop")]
        out.append("%s (settings.local.json rewritten mid-run):" % run)
        for e in R:
            p = e.get("payload") or {}
            out.append("    %s %-10s %-13s %s" % (e["ts"][11:23], e["label"], e.get("event"), json.dumps(cmd_of(e) or p.get("source") or "", ensure_ascii=True)[:50]))
    return out


def e13():
    out = sec("E13 coverage")
    R = [e for e in run_events("e13_cli") if e.get("label") in ("pre-iso", "post-iso")]
    for e in R:
        p = e.get("payload") or {}
        out.append("  %-13s %-10s agent_id=%s agent_type=%s" % (e.get("event"), e.get("tool"), "yes" if p.get("agent_id") else "-", p.get("agent_type") or "-"))
    out.append("@probe.txt reference: model answered the file's first word without any Read hook (see stream); text=%s" % json.dumps(
        next((b["text"][:20] for m in stream("e13_cli") if m.get("type") == "assistant" for b in m["message"]["content"] if b.get("type") == "text"), ""), ensure_ascii=True))
    ws = {(e.get("event"), e.get("tool")) for e in run_events("e13_websearch") if e.get("tool")}
    out.append("WebSearch hooks: %s" % sorted(ws, key=str))
    mcp = [e for e in run_events("m_cli") if e.get("tool", "").startswith("mcp__") and e["label"] == "m-star"]
    out.append("MCP: tool_name=%s top-level extra fields=%s" % (mcp[0]["tool"], sorted(set(mcp[0]["payload"]) - {"cwd", "hook_event_name", "permission_mode", "prompt_id", "session_id", "tool_input", "tool_name", "tool_use_id", "transcript_path"}) if mcp else None))
    return out


def e14():
    out = sec("E14 prompt / agent hooks on PreToolUse (BK_PROMPT_OK then BK_PROMPT_BLOCK)")
    for run in ("e14_prompt", "e14_prompt_cob", "e14_agent"):
        ex = [cmd_of(e) for e in run_events(run) if e.get("event") == "PostToolUse" and e.get("tool") == "PowerShell"]
        cost = next((m.get("total_cost_usd") for m in stream(run) if m.get("type") == "result"), None)
        names = sorted({m.get("hook_name") for m in stream(run) if m.get("subtype") == "hook_response"})
        out.append("%-15s executed=%s hook_names=%s cost=%s final_text=%s" % (run, ex, names, cost, json.dumps(result_text(run)[:90], ensure_ascii=True)))
    return out


def vscode():
    out = sec("VS Code extension (claude-vscode) sessions: hook timeline from the interactive UI tests")
    V = [r for r in EV if (r.get("env_values") or {}).get("CLAUDE_CODE_ENTRYPOINT") == "claude-vscode" and r.get("label") not in ("fail-hook", "pre-noiso")]
    order = []
    for r in V:
        p = r.get("payload") or {}
        key = (str(p.get("session_id")), (p.get("cwd") or "").lower())
        if key not in order:
            order.append(key)
        r["_s"] = order.index(key) + 1
    for i, key in enumerate(order, 1):
        out.append("-- session #%d cwd=%s" % (i, key[1]))
        for r in [x for x in V if x["_s"] == i]:
            p = r.get("payload") or {}
            ti = p.get("tool_input") or {}
            what = ti.get("command") or ti.get("file_path") or p.get("source") or (p.get("prompt") or "")[:30].replace("\n", " ")
            out.append("   %s %-13s %-16s %-10s mode=%-11s %s" % (r["ts"][11:23], r["label"], r.get("event"), r.get("tool") or "-", p.get("permission_mode"), json.dumps(what, ensure_ascii=True)[:60]))
    out.append("(gaps: BK_ASK_MARK PreToolUse -> PostToolUse took 25.7 s and 13.6 s = the user was prompted and approved; BK_EXIT2 / BK_DENY have no PostToolUse = blocked)")
    return out


def local_probes():
    out = sec("E20 / E21 local probes")
    for cmd in ([sys.executable, os.path.join(HERE, "probe_paths_windows.py")],
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", os.path.join(HERE, "probe_env_windows.ps1")]):
        p = subprocess.run(cmd, capture_output=True)
        out += p.stdout.decode("utf-8", "replace").splitlines()[:60]
    return out


def main():
    lines = ["# M0a 汇总（脱敏；由 experiments/summarize_m0a.py 从 raw/ 重新推导）", "# Claude Code 2.1.291, Windows 11 build 26200, 2026-10-06"]
    for f in (e4, e5, e6, e9, e10, e11, e12, e13, e14, vscode, local_probes):
        try:
            lines += f()
        except Exception as ex:  # 某一节缺数据不应拖垮整个汇总
            lines += ["", "(%s failed: %s: %s)" % (f.__name__, type(ex).__name__, ex)]
    me.write("m0a_summary.txt", "\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
