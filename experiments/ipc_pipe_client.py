"""hook 形状的命名管道客户端原型（M0 的前身；规格 §5.1）。仅标准库。

读 stdin 的事件，连管道（FileNotFoundError 表示常驻进程没起，立刻降级 ask；其他 OSError 视为"管道忙"，
在总预算内退避重试），发一行紧凑 JSON，读一行应答，把应答写到 stdout，退出 0。
用法：python -I -S ipc_pipe_client.py <管道全名> [预算秒数，默认 2]
"""
import json
import os
import sys
import time

ASK = b'{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"daemon unavailable"}}'


def main():
    pipe = sys.argv[1]
    budget = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
    t_end = time.monotonic() + budget
    try:
        data = sys.stdin.buffer.read()
        line = json.dumps(json.loads(data.decode("utf-8")), ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
    except Exception:
        sys.stdout.buffer.write(ASK)
        return 0
    delay = 0.0005
    while True:
        try:
            f = open(pipe, "r+b", buffering=0)
            break
        except FileNotFoundError:
            sys.stdout.buffer.write(ASK)
            return 0
        except OSError:
            if time.monotonic() >= t_end:
                sys.stdout.buffer.write(ASK)
                return 0
            time.sleep(delay)
            delay = min(delay * 2, 0.02)
    try:
        f.write(line)
        buf = b""
        while b"\n" not in buf:
            chunk = f.read(4096)
            if not chunk:
                break
            buf += chunk
        sys.stdout.buffer.write(buf.strip() or ASK)
    finally:
        f.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
