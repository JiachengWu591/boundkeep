"""汇总 experiments/raw/events.jsonl：每个宿主 / 每次运行收到了哪些 hook 事件（M0a E15 到 E18）。

用法：python experiments/analyze_events.py [--since 2026-10-06T00:00:00] [--paths]
输出只含 ASCII（非 ASCII 用 \\u 转义），可以直接贴进报告。
"""
import argparse
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def load(since):
    path = os.path.join(HERE, "raw", "events.jsonl")
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, "rb") as f:
        for line in f:
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("ts", "") >= since:
                rows.append(r)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", default="")
    ap.add_argument("--paths", action="store_true", help="同时列出 cwd / transcript_path / file_path 的形式")
    a = ap.parse_args()
    rows = load(a.since)
    print("records:", len(rows))
    groups = {}
    for r in rows:
        ev = r.get("env_values", {})
        key = (ev.get("BK_RUN") or "(none)", ev.get("CLAUDE_CODE_ENTRYPOINT") or "(unset)")
        groups.setdefault(key, []).append(r)
    for (run, entry), rs in sorted(groups.items()):
        print("\n== run=%s entrypoint=%s records=%d" % (run, entry, len(rs)))
        for r in rs:
            tool = r.get("tool") or "-"
            flags = []
            if r.get("naive_decode_ok") is False:
                flags.append("naive_decode_FAILS(%s)" % r.get("naive_decode_error"))
            elif r.get("naive_decode_matches_utf8") is False:
                flags.append("naive_decode_MOJIBAKE")
            if r.get("naive_print_ok") is False:
                flags.append("naive_print_FAILS")
            if r.get("stdin_has_bom"):
                flags.append("BOM")
            print("%s %-13s %-17s tool=%-10s stdin_enc=%-8s utf8_mode=%s %s" % (
                r.get("ts", "")[11:23], r.get("label"), r.get("event"), tool,
                r.get("stdin_encoding"), (r.get("py_flags") or {}).get("utf8_mode"), " ".join(flags)))
            if a.paths and r.get("paths"):
                for k, v in r["paths"].items():
                    if v:
                        print("      %s: %s" % (k, json.dumps(v, ensure_ascii=True)))
        names = sorted({n for r in rs for n in r.get("env_names", [])})
        print("  env names seen in hook process:", ", ".join(names))
        vals = {}
        for r in rs:
            vals.update(r.get("env_values", {}))
        print("  whitelisted env values:", json.dumps(vals, ensure_ascii=True))


if __name__ == "__main__":
    main()
