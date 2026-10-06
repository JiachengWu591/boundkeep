"""E6 / E22 用的"坏 hook"：按模式制造各种失败（只在一次性实验目录里用）。仅标准库。

用法：python -I -S fail_hook.py <mode>
模式：badjson（stdout 非法 JSON，退出 0）、json_and_exit2（allow JSON + 退出 2）、jsondeny_exit1（deny JSON + 退出 1）、
nonutf8（stdout 非 UTF-8 字节，退出 0）、exit127、exit3、stderr_only（只写 stderr，退出 0）、
old_block（旧式 {"decision":"block"}，退出 0）、plain_text（stdout 普通文本，退出 0）、
bigout（stdout 2 MB，退出 0）、hang_noread（不读 stdin，睡 30 秒）。
每次运行向 raw/events.jsonl 追加一条 {label: fail-hook, mode} 证明它真的被启动过。
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.environ.get("BK_PROBE_DIR") or os.path.join(HERE, "raw")
MODE = sys.argv[1] if len(sys.argv) > 1 else ""


def note():
    try:
        os.makedirs(RAW_DIR, exist_ok=True)
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "label": "fail-hook",
            "mode": MODE,
            "env_values": {"BK_RUN": os.environ.get("BK_RUN")},
        }
        with open(os.path.join(RAW_DIR, "events.jsonl"), "ab") as f:
            f.write((json.dumps(rec, ensure_ascii=True) + "\n").encode("ascii"))
    except Exception:
        pass


def deny_json(kind, reason):
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": kind,
                                              "permissionDecisionReason": reason}}).encode("ascii")


def main():
    note()
    if MODE == "hang_noread":
        time.sleep(30)
        return 0
    try:
        sys.stdin.buffer.read()
    except Exception:
        pass
    out, err = sys.stdout.buffer, sys.stderr.buffer
    if MODE == "badjson":
        out.write(b"{not json")
        return 0
    if MODE == "json_and_exit2":
        out.write(deny_json("allow", "BK_J2_ALLOW_JSON"))
        err.write(b"BK_J2_STDERR_REASON")
        return 2
    if MODE == "jsondeny_exit1":
        out.write(deny_json("deny", "BK_J1_DENY_REASON"))
        return 1
    if MODE == "nonutf8":
        out.write(b"\xff\xfe\xfd")
        return 0
    if MODE == "exit127":
        return 127
    if MODE == "exit3":
        return 3
    if MODE == "stderr_only":
        err.write(b"BK_STDERR_ONLY_TEXT")
        return 0
    if MODE == "old_block":
        out.write(json.dumps({"decision": "block", "reason": "BK_OLD_BLOCK_REASON"}).encode("ascii"))
        return 0
    if MODE == "plain_text":
        out.write(b"BK_PLAIN_TEXT_STDOUT")
        return 0
    if MODE == "bigout":
        out.write(b"x" * 2_000_000)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
