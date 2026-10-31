"""最小的 MCP stdio 服务，带资源（只为 P-F2 的实验：读 MCP 资源的工具在 hook 事件里叫什么）。仅标准库。

按换行分隔的 JSON-RPC：initialize、ping、tools/list、tools/call、resources/list、
resources/templates/list、resources/read。唯一的资源 bkres://note 的内容是 "BK_MCP_RESOURCE_MARK"；
唯一的工具 echo(text) 返回 "BK_MCP_ECHO:<text>"。不做任何有副作用的事。
"""
import json
import sys

NOTE = {"uri": "bkres://note", "name": "note", "description": "P-F2 probe resource (inert text).",
        "mimeType": "text/plain"}


def send(obj):
    sys.stdout.buffer.write((json.dumps(obj, ensure_ascii=True) + "\n").encode("ascii"))
    sys.stdout.buffer.flush()


def handle(msg):
    method = msg.get("method")
    mid = msg.get("id")
    params = msg.get("params") or {}
    if method == "initialize":
        proto = params.get("protocolVersion") or "2024-11-05"
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": proto, "capabilities": {"tools": {}, "resources": {}},
            "serverInfo": {"name": "bkres", "version": "0.0.1"}}})
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [{
            "name": "echo", "description": "Echo the given text (probe tool, no side effects).",
            "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}}]}})
    elif method == "tools/call":
        args = params.get("arguments") or {}
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": "BK_MCP_ECHO:" + str(args.get("text"))}]}})
    elif method == "resources/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"resources": [NOTE]}})
    elif method == "resources/templates/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"resourceTemplates": []}})
    elif method == "resources/read":
        send({"jsonrpc": "2.0", "id": mid, "result": {"contents": [{
            "uri": params.get("uri"), "mimeType": "text/plain", "text": "BK_MCP_RESOURCE_MARK"}]}})
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
