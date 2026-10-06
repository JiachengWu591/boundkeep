"""E10：从 claude -p 的 stream-json 与到达时刻（times.json）算每次工具调用的耗时。

耗时 = assistant 消息（含 tool_use）到达 到 对应 tool_result 的 user 消息到达，
包含 PreToolUse hook、权限处理、工具执行、PostToolUse hook。
用法：python experiments/analyze_latency.py <运行名> [<运行名> ...]   （多个运行名会合并成一组）
"""
import json
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def latencies(run):
    d = os.path.join(HERE, "raw", "runs", run)
    times = json.load(open(os.path.join(d, "times.json")))
    lines = open(os.path.join(d, "stdout.jsonl"), "rb").read().splitlines(keepends=False)
    started, out = {}, []
    for i, line in enumerate(lines):
        if not line.strip() or i >= len(times):
            continue
        try:
            m = json.loads(line)
        except Exception:
            continue
        if m.get("type") == "assistant" and not m.get("parent_tool_use_id"):
            for b in m["message"]["content"]:
                if b.get("type") == "tool_use":
                    started[b["id"]] = times[i]
        elif m.get("type") == "user":
            c = m["message"].get("content")
            if isinstance(c, list):
                for b in c:
                    if b.get("type") == "tool_result" and b.get("tool_use_id") in started:
                        out.append((times[i] - started.pop(b["tool_use_id"])) * 1000)
    return out


def main():
    xs = []
    for run in sys.argv[1:]:
        xs += latencies(run)
    xs.sort()
    if not xs:
        print("no tool calls found")
        return
    print("runs=%s n=%d p50=%.0f ms p95=%.0f ms mean=%.0f ms min=%.0f max=%.0f" % (
        ",".join(sys.argv[1:]), len(xs), statistics.median(xs), xs[min(len(xs) - 1, int(len(xs) * 0.95))],
        statistics.mean(xs), xs[0], xs[-1]))


if __name__ == "__main__":
    main()
