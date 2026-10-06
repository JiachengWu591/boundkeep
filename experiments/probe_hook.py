"""M0a 观察用 hook（规格 §16-D；提示词 M0a 的 E1 到 E24）。

只记录，不改变会话行为：默认退出码 0、不输出任何内容。
- 仅标准库；按字节读 stdin；日志是纯 ASCII 的 JSON 行（非 ASCII 用 \\u 转义）。
- 不记录环境变量的值，只记录名称；白名单里的非敏感项除外。
- 总开关：raw 目录里存在名为 OFF 的文件时，什么都不做。
- 测试标记（只在命令 / 提示词里出现时才触发；只有指定标签的 hook 会动手，其余 hook 只记录）：
    标签 pre-iso，PreToolUse 的 tool_input.command 含：
      BK_EXIT1  退出码 1（应为非阻断）        BK_EXIT2  退出码 2 并写 stderr（应阻断）
      BK_DENY   permissionDecision=deny        BK_ASK    permissionDecision=ask
      BK_ALLOW  permissionDecision=allow       BK_SLEEP  睡 30 秒（配合较短的 timeout）
      BK_NAIVE  用默认编码解码 stdin 并 print 非 ASCII，让异常逃逸
    标签 post-iso，PostToolUse 的 tool_input.command 含 BK_CTX：输出 additionalContext
    标签 prompt，UserPromptSubmit 的 prompt 含 BK_UPS_CTX：输出 additionalContext

标签：argv[1]。同一事件上可以并行挂多个 hook（例如 pre-iso 带 -I，pre-noiso 不带 -I，用来对比
PYTHON* 环境变量是否传进 hook、是否掩盖编码问题）。
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE.lower().endswith(".exe"):  # 被 make_launcher 内嵌进 .exe 时，__file__ 在 zip 里
    HERE = os.path.dirname(HERE)
RAW_DIR = os.environ.get("BK_PROBE_DIR") or os.path.join(HERE, "raw")
ENV_VALUE_WHITELIST = (
    "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_CODE_SESSION_ATTENDED",
    "CLAUDE_AGENT_SDK_VERSION",
    "CLAUDE_PROJECT_DIR",
    "PYTHONIOENCODING",
    "PYTHONUTF8",
    "BK_RUN",
)


def _pathform(value):
    if not isinstance(value, str):
        return None
    return {
        "value": value,
        "has_backslash": "\\" in value,
        "has_forward_slash": "/" in value,
        "drive": value[:2] if len(value) > 1 and value[1] == ":" else None,
    }


def build_record(raw, label):
    now = time.time()
    stdin_enc = getattr(sys.stdin, "encoding", None)
    stdout_enc = getattr(sys.stdout, "encoding", None)
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + ".%03dZ" % (int(now * 1000) % 1000),
        "label": label,
        "argv": sys.argv[1:],
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "stdin_len": len(raw),
        "stdin_head_hex": raw[:16].hex(),
        "stdin_has_bom": raw.startswith(b"\xef\xbb\xbf"),
        "py": sys.version.split()[0],
        "py_exe": sys.executable,
        "py_flags": {
            "isolated": sys.flags.isolated,
            "no_site": sys.flags.no_site,
            "utf8_mode": sys.flags.utf8_mode,
        },
        "stdin_encoding": stdin_enc,
        "stdout_encoding": stdout_enc,
        "cwd": os.getcwd(),
        "env_names": sorted(
            k for k in os.environ if k.upper().startswith(("CLAUDE", "PYTHON", "ANTHROPIC", "BK_"))
        ),
        "env_values": {k: os.environ[k] for k in ENV_VALUE_WHITELIST if k in os.environ},
    }
    ev = None
    try:
        text = raw.decode("utf-8")
        ev = json.loads(text)
        rec["utf8_ok"] = True
    except Exception as e:  # 记录失败原因，不让观察 hook 自己崩溃
        text = None
        rec["utf8_ok"] = False
        rec["parse_error"] = type(e).__name__
    # 天真写法（按默认文本编码读 stdin / print 非 ASCII）会不会出事，逐事件记录，但不真的崩溃
    enc = stdin_enc or "utf-8"
    try:
        decoded = raw.decode(enc)
        rec["naive_decode_ok"] = True
        rec["naive_decode_matches_utf8"] = text is not None and decoded == text
    except Exception as e:
        rec["naive_decode_ok"] = False
        rec["naive_decode_error"] = type(e).__name__
    try:
        "✓中".encode(stdout_enc or "ascii")
        rec["naive_print_ok"] = True
    except Exception as e:
        rec["naive_print_ok"] = False
        rec["naive_print_error"] = type(e).__name__
    if isinstance(ev, dict):
        ti = ev.get("tool_input") if isinstance(ev.get("tool_input"), dict) else {}
        rec["event"] = ev.get("hook_event_name")
        rec["tool"] = ev.get("tool_name")
        rec["paths"] = {
            "cwd": _pathform(ev.get("cwd")),
            "transcript_path": _pathform(ev.get("transcript_path")),
            "file_path": _pathform(ti.get("file_path")),
        }
        rec["payload"] = ev
    return rec, ev


def append(rec):
    os.makedirs(RAW_DIR, exist_ok=True)
    data = (json.dumps(rec, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
    with open(os.path.join(RAW_DIR, "events.jsonl"), "ab") as f:
        f.write(data)


def _emit(obj):
    sys.stdout.buffer.write(json.dumps(obj, ensure_ascii=True).encode("ascii"))
    sys.stdout.buffer.flush()


def emit_decision(kind, reason):
    _emit({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": kind,
            "permissionDecisionReason": reason,
        }
    })


def emit_context(event, text):
    _emit({"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}})


def act(label, ev, raw):
    """只在测试标记出现时才有行为；其余一律返回 0。"""
    if not isinstance(ev, dict):
        return 0
    name = ev.get("hook_event_name")
    ti = ev.get("tool_input") if isinstance(ev.get("tool_input"), dict) else {}
    cmd = ti.get("command") if isinstance(ti.get("command"), str) else ""
    if label == "cfg-block" and name == "ConfigChange":
        # E12：新配置里含 disableAllHooks 就阻止这次变更（退出码 2）
        try:
            with open(ev.get("file_path") or "", "rb") as f:
                if b"disableAllHooks" in f.read():
                    sys.stderr.buffer.write(b"BK_CFG_BLOCKED: disableAllHooks is not allowed\n")
                    return 2
        except OSError:
            pass
        return 0
    if label == "post-iso" and name == "PostToolUse" and "BK_CTX" in cmd:
        emit_context("PostToolUse", "BK_CTX_NONCE_9a1b: 这是 hook 注入的上下文")
        return 0
    if label == "prompt" and name == "UserPromptSubmit" and "BK_UPS_CTX" in str(ev.get("prompt")):
        emit_context("UserPromptSubmit", "BK_UPS_NONCE_3c7d: 提示词阶段注入的上下文")
        return 0
    if label != "pre-iso" or name != "PreToolUse" or not cmd:
        return 0
    if "BK_EXIT1" in cmd:
        return 1
    if "BK_EXIT2" in cmd:
        sys.stderr.buffer.write("BK_EXIT2_REASON_91c2: 中文理由 ✓\n".encode("utf-8"))
        return 2
    if "BK_DENY" in cmd:
        emit_decision("deny", "BK_DENY_REASON_7f3a: 测试拒绝理由 ✓")
        return 0
    if "BK_ASK" in cmd:
        emit_decision("ask", "BK_ASK_REASON_5d1e: 测试询问理由")
        return 0
    if "BK_ALLOW" in cmd:
        emit_decision("allow", "BK_ALLOW_REASON_2e8f: 测试放行理由")
        return 0
    if "BK_SLEEP" in cmd:
        time.sleep(30)
        return 0
    if "BK_NAIVE" in cmd:
        text = raw.decode(sys.stdin.encoding)  # 天真写法：用默认编码解码，失败就让异常逃逸
        json.loads(text)
        print("✓ 中文")  # 天真写法：print 非 ASCII
        return 0
    return 0


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "?"
    try:
        raw = sys.stdin.buffer.read()
    except Exception:
        raw = b""
    if os.path.exists(os.path.join(RAW_DIR, "OFF")):
        return 0
    ev = None
    try:
        rec, ev = build_record(raw, label)
        append(rec)
    except Exception as e:
        try:
            append({"label": label, "record_error": type(e).__name__})
        except Exception:
            pass
    return act(label, ev, raw)


if __name__ == "__main__":
    sys.exit(main())
