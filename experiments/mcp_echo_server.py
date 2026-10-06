"""最小的 MCP stdio 服务（只为 M0a 的 E5 / E13 验证 MCP 工具的命名与 hook 输入）。仅标准库。

按换行分隔的 JSON-RPC：initialize、notifications/initialized、ping、tools/list、tools/call。
唯一的工具 echo(text) 返回 "BK_MCP_ECHO:<text>"。不做任何有副作用的事。
"""
import json
import sys


def send(obj):
    sys.stdout.buffer.write((json.dumps(obj, ensure_ascii=True) + "\n").encode("ascii"))
    sys.stdout.buffer.flush()


def handle(msg):
    method = msg.get("method")
    mid = msg.get("id")
    if method == "initialize":
        proto = (msg.get("params") or {}).get("protocolVersion") or "2024-11-05"
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": proto, "capabilities": {"tools": {}},
            "serverInfo": {"name": "bkmcp", "version": "0.0.1"}}})
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [{
            "name": "echo", "description": "Echo the given text (M0a probe tool, no side effects).",
            "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}}]}})
    elif method == "tools/call":
        args = ((msg.get("params") or {}).get("arguments")) or {}
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": "BK_MCP_ECHO:" + str(args.get("text"))}]}})
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
