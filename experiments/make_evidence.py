"""从 experiments/raw/（未脱敏，被 git 忽略）生成脱敏后的证据到 experiments/evidence/。

提示词 M0a：脱敏结果经确认后才可提交。脱敏规则：Windows 用户名 -> <user>；UUID -> <uuid>；
toolu_* -> <tool_use_id>；输出只含 ASCII（非 ASCII 用 \\u 转义）。
用法：python experiments/make_evidence.py
"""
import glob
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw")
OUT = os.path.join(HERE, "evidence")
USER = os.path.basename(os.path.expanduser("~"))
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
TOOLU = re.compile(r"toolu_[A-Za-z0-9]+")


def clean(text):
    text = text.replace(USER, "<user>") if USER else text
    text = UUID.sub("<uuid>", text)
    text = TOOLU.sub("<tool_use_id>", text)
    return text


def ascii_only(text):
    return text.encode("ascii", "backslashreplace").decode("ascii")


def write(name, text):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(ascii_only(clean(text)).encode("ascii"))
    print("wrote", os.path.join("experiments", "evidence", name))


def load_events():
    path = os.path.join(RAW, "events.jsonl")
    rows = []
    with open(path, "rb") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def events_summary():
    p = subprocess.run([sys.executable, os.path.join(HERE, "analyze_events.py"), "--paths"], capture_output=True)
    write("events_summary.txt", p.stdout.decode("utf-8", "replace"))


def event_shapes(rows):
    seen = {}
    for r in rows:
        p = r.get("payload")
        if not isinstance(p, dict):
            continue
        key = (r.get("event"), r.get("tool"))
        if key in seen:
            continue
        shape = {"top": sorted(p.keys())}
        for sub in ("tool_input", "tool_response"):
            if isinstance(p.get(sub), dict):
                shape[sub] = sorted(p[sub].keys())
        seen[key] = shape
    lines = ["# 各 hook 事件 stdin JSON 的字段名（只含字段名，不含值）", ""]
    for (ev, tool), shape in sorted(seen.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
        lines.append("%s / %s" % (ev, tool or "-"))
        lines.append("  " + json.dumps(shape, ensure_ascii=True))
    write("event_shapes.txt", "\n".join(lines) + "\n")


def stream_rows(path):
    rows = []
    with open(path, "rb") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def run_reports():
    outcomes = ["# Claude 自己记录的 hook 结果（--include-hook-events 的 hook_response），按运行分组", ""]
    results = ["# 每次 claude -p 运行的概况", ""]
    for d in sorted(glob.glob(os.path.join(RAW, "runs", "*"))):
        name = os.path.basename(d)
        meta = json.load(open(os.path.join(d, "meta.json"), encoding="utf-8"))
        rows = stream_rows(os.path.join(d, "stdout.jsonl"))
        init = next((m for m in rows if m.get("subtype") == "init"), {})
        res = next((m for m in rows if m.get("type") == "result"), {})
        results.append("== %s" % name)
        results.append("  rc=%s elapsed_s=%s drop_python_env=%s" % (meta.get("rc"), meta.get("elapsed_s"), meta.get("drop_python_env")))
        results.append("  model=%s tools=%s" % (init.get("model"), init.get("tools")))
        results.append("  result=%s" % json.dumps({k: res.get(k) for k in ("subtype", "is_error", "num_turns", "total_cost_usd", "result")}, ensure_ascii=True))
        outcomes.append("== %s" % name)
        for m in rows:
            if m.get("subtype") == "hook_response":
                outcomes.append("  %-16s %-24s exit=%s outcome=%s stdout=%s stderr=%s" % (
                    m.get("hook_event"), m.get("hook_name"), m.get("exit_code"), m.get("outcome"),
                    json.dumps((m.get("stdout") or "")[:80], ensure_ascii=True),
                    json.dumps((m.get("stderr") or "")[:100], ensure_ascii=True)))
            if m.get("subtype") == "permission_denied":
                outcomes.append("  PERMISSION_DENIED tool=%s reason_type=%s reason=%s" % (
                    m.get("tool_name"), m.get("decision_reason_type"), m.get("decision_reason")))
    write("run_results.txt", "\n".join(results) + "\n")
    write("hook_outcomes.txt", "\n".join(outcomes) + "\n")


def main():
    rows = load_events()
    events_summary()
    event_shapes(rows)
    run_reports()


if __name__ == "__main__":
    main()
