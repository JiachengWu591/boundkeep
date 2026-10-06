"""从 experiments/raw/events.jsonl（未脱敏）生成脱敏的 hook 事件夹具到 tests/fixtures/hook_events/windows/。

提示词 M0a：夹具覆盖 §16-A 提到的所有事件与工具类型，不含真实密钥或个人路径；脱敏结果经确认后才可提交。
脱敏：Windows 用户名 -> testuser；UUID -> 固定编号的占位 UUID；toolu_* / prompt_id / agent_id -> 固定编号占位。
保留：中文、✓ 等非 ASCII 字符（测试需要）；盘符大小写（e: 与 E: 的差异本身就是要测的）。
用法：python experiments/make_fixtures.py
"""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "tests", "fixtures", "hook_events", "windows")
USER = os.path.basename(os.path.expanduser("~"))
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
TOOLU = re.compile(r"toolu_[A-Za-z0-9]+")
AGENT = re.compile(r"\ba[0-9a-f]{16}\b")


class Mapper:
    def __init__(self):
        self.maps = {}

    def sub(self, kind, value):
        m = self.maps.setdefault(kind, {})
        if value not in m:
            m[value] = len(m) + 1
        return m[value]

    def clean(self, s):
        if USER:
            s = s.replace(USER, "testuser")
        s = UUID.sub(lambda m: "00000000-0000-4000-8000-%012d" % self.sub("uuid", m.group(0)), s)
        s = TOOLU.sub(lambda m: "toolu_FIXTURE%04d" % self.sub("toolu", m.group(0)), s)
        s = AGENT.sub(lambda m: "afixture%09d" % self.sub("agent", m.group(0)), s)
        return s


def walk(x, f):
    if isinstance(x, str):
        return f(x)
    if isinstance(x, list):
        return [walk(i, f) for i in x]
    if isinstance(x, dict):
        return {walk(k, f): walk(v, f) for k, v in x.items()}
    return x


# (文件名, 条件) —— 在 events.jsonl 里挑第一条满足条件的记录
def picks(rows):
    def first(**kw):
        for r in rows:
            p = r.get("payload")
            if not isinstance(p, dict):
                continue
            if all(((r.get(k) if k in ("label", "event", "tool") else None) == v) or
                   (k == "run" and (r.get("env_values") or {}).get("BK_RUN") == v) or
                   (k == "entry" and (r.get("env_values") or {}).get("CLAUDE_CODE_ENTRYPOINT") == v) or
                   (k == "source" and p.get("source") == v) or
                   (k == "has_agent" and ("agent_id" in p) == v) for k, v in kw.items()):
                return r
        return None

    return [
        ("SessionStart__startup", first(event="SessionStart", run="a_cli", source="startup")),
        ("SessionStart__resume", first(event="SessionStart", run="e9_s2", source="resume")),
        ("SessionStart__compact", first(event="SessionStart", run="e9_s4", source="compact")),
        ("UserPromptSubmit__chinese", first(event="UserPromptSubmit", run="a_cli")),
        ("PreToolUse__PowerShell", first(event="PreToolUse", tool="PowerShell", label="pre-iso", run="a_cli")),
        ("PostToolUse__PowerShell", first(event="PostToolUse", tool="PowerShell", label="post-iso", run="a_cli")),
        ("PreToolUse__Bash_gitbash", first(event="PreToolUse", tool="Bash", label="pre-iso", run="d_cli_gitbash")),
        ("PostToolUse__Bash_gitbash", first(event="PostToolUse", tool="Bash", label="post-iso", run="d_cli_gitbash")),
        ("PreToolUse__Read", first(event="PreToolUse", tool="Read", label="pre-iso", run="a_cli")),
        ("PostToolUse__Read", first(event="PostToolUse", tool="Read", label="post-iso", run="a_cli")),
        ("PreToolUse__Write", first(event="PreToolUse", tool="Write", label="pre-iso", run="a_cli")),
        ("PostToolUse__Write", first(event="PostToolUse", tool="Write", label="post-iso", run="a_cli")),
        ("PreToolUse__Edit", first(event="PreToolUse", tool="Edit", label="m-star", run="m_cli")),
        ("PostToolUse__Edit", first(event="PostToolUse", tool="Edit", label="post-iso", run="m_cli")),
        ("PreToolUse__Glob", first(event="PreToolUse", tool="Glob", label="m-star", run="m_cli")),
        ("PostToolUse__Glob", first(event="PostToolUse", tool="Glob", label="post-iso", run="m_cli")),
        ("PreToolUse__Grep", first(event="PreToolUse", tool="Grep", label="m-star", run="m_cli")),
        ("PostToolUse__Grep", first(event="PostToolUse", tool="Grep", label="post-iso", run="m_cli")),
        ("PreToolUse__WebFetch", first(event="PreToolUse", tool="WebFetch", label="m-star", run="m_cli")),
        ("PostToolUse__WebFetch", first(event="PostToolUse", tool="WebFetch", label="post-iso", run="m_cli")),
        ("PreToolUse__WebSearch", first(event="PreToolUse", tool="WebSearch", label="m-star", run="e13_websearch")),
        ("PostToolUse__WebSearch", first(event="PostToolUse", tool="WebSearch", label="post-iso", run="e13_websearch")),
        ("PreToolUse__mcp_echo", first(event="PreToolUse", tool="mcp__bkmcp__echo", label="m-star", run="m_cli")),
        ("PostToolUse__mcp_echo", first(event="PostToolUse", tool="mcp__bkmcp__echo", label="post-iso", run="m_cli")),
        ("PreToolUse__ToolSearch", first(event="PreToolUse", tool="ToolSearch", label="m-star", run="m_cli")),
        ("PostToolUse__ToolSearch", first(event="PostToolUse", tool="ToolSearch", label="post-iso", run="e13_cli")),
        ("PreToolUse__Agent", first(event="PreToolUse", tool="Agent", label="pre-iso", run="e13_cli")),
        ("PostToolUse__Agent", first(event="PostToolUse", tool="Agent", label="post-iso", run="e13_cli")),
        ("PreToolUse__PowerShell_in_subagent", first(event="PreToolUse", tool="PowerShell", label="pre-iso", run="e13_cli", has_agent=True)),
        ("PostToolUse__PowerShell_in_subagent", first(event="PostToolUse", tool="PowerShell", label="post-iso", run="e13_cli", has_agent=True)),
        ("Stop", first(event="Stop", run="a_cli")),
        ("ConfigChange__local_settings", first(event="ConfigChange", run="e12_midflight")),
        ("PermissionRequest__PowerShell", first(event="PermissionRequest", run="e11_allow_b")),
        ("vscode__SessionStart", first(event="SessionStart", entry="claude-vscode")),
        ("vscode__SessionStart__clear", first(event="SessionStart", entry="claude-vscode", source="clear")),
        ("vscode__UserPromptSubmit", first(event="UserPromptSubmit", entry="claude-vscode")),
        ("vscode__PreToolUse__PowerShell", first(event="PreToolUse", tool="PowerShell", label="pre-iso", entry="claude-vscode")),
        ("vscode__PreToolUse__Read", first(event="PreToolUse", tool="Read", label="pre-iso", entry="claude-vscode")),
        ("vscode__PostToolUse__PowerShell", first(event="PostToolUse", tool="PowerShell", label="post-iso", entry="claude-vscode")),
    ]


def main():
    rows = []
    with open(os.path.join(HERE, "raw", "events.jsonl"), "rb") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    os.makedirs(OUT, exist_ok=True)
    mapper = Mapper()
    index, missing = [], []
    for name, rec in picks(rows):
        if rec is None:
            missing.append(name)
            continue
        payload = walk(rec["payload"], mapper.clean)
        path = os.path.join(OUT, name + ".json")
        with open(path, "wb") as f:
            f.write((json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        env = rec.get("env_values") or {}
        index.append({"file": name + ".json", "event": rec.get("event"), "tool": rec.get("tool"),
                      "host_entrypoint": env.get("CLAUDE_CODE_ENTRYPOINT"), "run": env.get("BK_RUN") or "(vscode)"})
    meta = {
        "claude_code_version": "2.1.291", "platform": "Windows 11 build 26200, zh-CN, ANSI code page 936",
        "captured": "2026-10-06", "source": "experiments/probe_hook.py (M0a)",
        "sanitization": "user name -> testuser; UUIDs / toolu_* / agent ids -> numbered placeholders; Chinese text and drive-letter case kept",
        "notes": [
            "stdin is UTF-8 bytes; paths use backslashes; drive-letter case varies (see vscode__* fixtures: lowercase e:)",
            "PostToolUse.tool_response contains raw tool output (never forward it to an LLM backend)",
        ],
        "files": index, "missing": missing,
    }
    with open(os.path.join(OUT, "index.json"), "wb") as f:
        f.write((json.dumps(meta, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    print("fixtures written:", len(index), "missing:", missing)


if __name__ == "__main__":
    main()
