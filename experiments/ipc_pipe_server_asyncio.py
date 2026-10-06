"""基线：asyncio 的 start_serving_pipe 命名管道服务端（对照 ipc_pipe_server.py 的 ctypes 版）。

只有一个待连接的实例，且 asyncio 没有给安全属性的入口，管道用默认（NULL）DACL。
用法：python -I ipc_pipe_server_asyncio.py <管道全名>
"""
import asyncio
import json
import sys

PIPE = sys.argv[1]


class Proto(asyncio.Protocol):
    def connection_made(self, tr):
        self.tr = tr
        self.buf = b""

    def data_received(self, data):
        self.buf += data
        if b"\n" not in self.buf:
            return
        line = self.buf.split(b"\n", 1)[0]
        if line.startswith(b"HANG"):
            return  # 不应答
        reply = json.dumps({"permissionDecision": "ask", "n": len(line)}).encode("ascii") + b"\n"
        self.tr.write(reply)
        self.tr.close()


async def main():
    loop = asyncio.get_running_loop()
    await loop.start_serving_pipe(Proto, PIPE)
    print("READY", flush=True)
    await asyncio.sleep(600)


asyncio.run(main())
