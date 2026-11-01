"""最小的 MCP stdio 服务，只有一个权限提示工具（P-R3 的实验：hook 回答 ask、而有人批准时，PostToolUse
是否触发、两个事件的 tool_use_id 是否相同）。仅标准库。

`claude -p --permission-prompts host --permission-prompt-tool mcp__bkperm__approve` 把权限提示交给它：
请求里含 DENYME 就拒绝，否则批准（原样返回输入）。设了环境变量 BK_PERM_ONLY（正则）时，请求的 JSON 匹配不上它也拒绝。
每次收到的参数记到 raw/perm_tool.jsonl（纯 ASCII）。不做任何有副作用的事。
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.environ.get("BK_PROBE_DIR") or os.path.join(HERE, "raw")
ONLY = os.environ.get("BK_PERM_ONLY")


def send(obj):
    sys.stdout.buffer.write((json.dumps(obj, ensure_ascii=True) + "\n").encode("ascii"))
    sys.stdout.buffer.flush()


def log(args):
    os.makedirs(RAW_DIR, exist_ok=True)
    rec = {"run": os.environ.get("BK_RUN"), "arguments": args}
    with open(os.path.join(RAW_DIR, "perm_tool.jsonl"), "ab") as f:
        f.write((json.dumps(rec, ensure_ascii=True) + "\n").encode("ascii"))


def decide(args):
    text = json.dumps(args, ensure_ascii=True)
    if "DENYME" in text or (ONLY and not re.search(ONLY, text)):
        return {"behavior": "deny", "message": "BK_PERM_DENIED"}
    return {"behavior": "allow", "updatedInput": args.get("input") or {}}


def handle(msg):
    method = msg.get("method")
    mid = msg.get("id")
    params = msg.get("params") or {}
    if method == "initialize":
        proto = params.get("protocolVersion") or "2024-11-05"
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": proto, "capabilities": {"tools": {}},
            "serverInfo": {"name": "bkperm", "version": "0.0.1"}}})
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [{
            "name": "approve", "description": "Permission prompt handler for a hook experiment.",
            "inputSchema": {"type": "object", "properties": {
                "tool_name": {"type": "string"}, "input": {"type": "object"}, "tool_use_id": {"type": "string"}},
                "required": ["tool_name", "input"]}}]}})
    elif method == "tools/call":
        args = params.get("arguments") or {}
        try:
            log(args)
        except OSError:
            pass
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": json.dumps(decide(args), ensure_ascii=True)}]}})
    elif mid is not None:
        send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}})


def main():
    for line in sys.stdin.buffer:
        line = line.strip()
        if not line:
            continue
        try:
            handle(json.loads(line))
        except Exception:
            pass


if __name__ == "__main__":
    main()
