"""A local fake of an OpenAI-compatible chat endpoint, for the contract and failure tests.

It listens on 127.0.0.1 (a free port; plain http is allowed for a loopback host), records every
request it gets (path, headers, body) and answers each one as scripted: a ``Reply`` or a function
of the request that returns one. Nothing here talks to the network beyond the loopback interface.
"""

from __future__ import annotations

import contextlib
import json
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


@dataclass
class Seen:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


@dataclass
class Reply:
    status: int = 200
    body: bytes | str | dict[str, Any] = b""
    headers: dict[str, str] = field(default_factory=dict)
    delay_s: float = 0.0  # before the status line
    drip: tuple[int, float] | None = None  # (bytes per write, seconds between writes)
    # the status line and the headers dripped like that (each byte comes before any read timeout)
    header_drip: tuple[int, float] | None = None
    hang_up: bool = False  # close the connection without any answer
    content_length: bool = True  # send Content-Length (else close-delimited)


def tool_call_answer(arguments: str, *, usage: dict[str, int] | None = None) -> dict[str, Any]:
    """An OpenAI chat completion that calls report_verdict with ``arguments`` (a JSON string)."""
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "report_verdict", "arguments": arguments},
                        }
                    ],
                },
            }
        ],
        "usage": usage or {"prompt_tokens": 900, "completion_tokens": 60, "total_tokens": 960},
    }


def json_answer(content: str, *, usage: dict[str, int] | None = None) -> dict[str, Any]:
    """An OpenAI chat completion whose message content is ``content`` (json_object transport)."""
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }
        ],
        "usage": usage or {"prompt_tokens": 900, "completion_tokens": 60, "total_tokens": 960},
    }


def _encode(body: bytes | str | dict[str, Any]) -> bytes:
    if isinstance(body, dict):
        return json.dumps(body).encode("utf-8")
    if isinstance(body, str):
        return body.encode("utf-8")
    return body


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False  # a handler still sleeping (a timeout test) must not hold up the close


class FakeLLMServer:
    def __init__(self, reply: Reply | Callable[[Seen], Reply] | None = None) -> None:
        self.reply: Reply | Callable[[Seen], Reply] = reply or Reply(status=500)
        self.requests: list[Seen] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                headers_seen = {k.lower(): v for k, v in self.headers.items()}
                seen = Seen("POST", self.path, headers_seen, body)
                server.requests.append(seen)
                reply = server.reply(seen) if callable(server.reply) else server.reply
                if reply.delay_s:
                    time.sleep(reply.delay_s)
                if reply.hang_up:
                    self.close_connection = True
                    with contextlib.suppress(OSError):
                        self.connection.shutdown(socket.SHUT_RDWR)
                    return
                data = _encode(reply.body)
                if reply.status in (204, 304) or reply.status < 200:
                    data = b""  # these statuses carry no body
                if reply.header_drip is not None:
                    self._drip_head(reply, data)
                    return
                self.send_response(reply.status)
                headers = {"Content-Type": "application/json", **reply.headers}
                for name, value in headers.items():
                    self.send_header(name, value)
                if reply.content_length:
                    self.send_header("Content-Length", str(len(data)))
                else:
                    self.send_header("Connection", "close")
                    self.close_connection = True
                self.end_headers()
                try:
                    if reply.drip is None:
                        self.wfile.write(data)
                    else:
                        size, pause = reply.drip
                        for start in range(0, len(data), size):
                            self.wfile.write(data[start : start + size])
                            self.wfile.flush()
                            time.sleep(pause)
                except OSError:
                    pass  # the client gave up (a timeout test): nothing to do

            def _drip_head(self, reply: Reply, data: bytes) -> None:
                assert reply.header_drip is not None
                size, pause = reply.header_drip
                padding = "".join(f"X-Pad-{i}: {'p' * 8}\r\n" for i in range(40))
                head = (
                    f"HTTP/1.1 {reply.status} OK\r\n{padding}"
                    f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n"
                ).encode("ascii")
                self.close_connection = True
                try:
                    for start in range(0, len(head), size):
                        self.wfile.write(head[start : start + size])
                        self.wfile.flush()
                        time.sleep(pause)
                    self.wfile.write(data)
                except OSError:
                    pass  # the client gave up: that is what the test wants

        self._httpd = _Server(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def __enter__(self) -> FakeLLMServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
