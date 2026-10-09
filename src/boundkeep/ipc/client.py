"""IPC client: one request line out, one response line back. Standard library only.

Error classes tell the caller what to do (the hook client degrades every one of them to ``ask``):

* ``DaemonUnavailable``: nobody is listening (pipe or socket missing, connection refused, access
  denied, connection closed early). Immediate; retrying will not help.
* ``DaemonBusy``: on Windows every pipe instance was busy for the whole budget. M0a measured this
  as ``OSError(errno=22, winerror=None)`` from ``open()``; it is retried with back-off.
* ``DaemonTimeout``: connected but no complete response before the deadline.
* ``ProtocolError`` (from ``boundkeep.protocol``): the response was too large or malformed.
"""

from __future__ import annotations

import sys
import threading
import time

from boundkeep.ipc.endpoint import TRANSPORT_NAMED_PIPE, TRANSPORT_UNIX, Endpoint
from boundkeep.protocol import MAX_RESPONSE_BYTES, ProtocolError


class IpcError(Exception):
    """Base class of the client errors."""


class DaemonUnavailable(IpcError):
    pass


class DaemonBusy(IpcError):
    pass


class DaemonTimeout(IpcError):
    pass


_FIRST_RETRY_DELAY_S = 0.0005
_MAX_RETRY_DELAY_S = 0.02


def transact(endpoint: Endpoint, request_line: bytes, deadline: float) -> bytes:
    """Send ``request_line`` (newline terminated) and return the response line without newline.

    ``deadline`` is a ``time.monotonic()`` value. Blocking: on Windows pipes a hung daemon blocks
    the read forever, so callers that must not block use ``call`` or run this in their own worker
    thread (the hook client does).
    """
    if endpoint.transport == TRANSPORT_NAMED_PIPE:
        return _transact_pipe(endpoint.address, request_line, deadline)
    if endpoint.transport == TRANSPORT_UNIX:
        return _transact_unix(endpoint.address, request_line, deadline)
    raise DaemonUnavailable(f"unknown transport {endpoint.transport!r}")


def call(endpoint: Endpoint, request_line: bytes, *, timeout_s: float) -> bytes:
    """``transact`` with an enforced deadline (worker thread + join); for CLI and tests."""
    deadline = time.monotonic() + timeout_s
    box: dict[str, object] = {}

    def work() -> None:
        try:
            box["result"] = transact(endpoint, request_line, deadline)
        except BaseException as exc:  # noqa: BLE001 - handed to the calling thread below
            box["error"] = exc

    worker = threading.Thread(target=work, name="boundkeep-ipc", daemon=True)
    worker.start()
    worker.join(max(0.0, deadline - time.monotonic()))
    if worker.is_alive():
        raise DaemonTimeout("no response before the deadline")
    error = box.get("error")
    if isinstance(error, BaseException):
        raise error
    result = box.get("result")
    if not isinstance(result, bytes):
        raise DaemonUnavailable("ipc worker finished without a result")
    return result


def _transact_pipe(address: str, request_line: bytes, deadline: float) -> bytes:
    delay = _FIRST_RETRY_DELAY_S
    while True:
        try:
            # Unbuffered binary read/write on the pipe path; M0a verified this works as a client.
            handle = open(address, "r+b", buffering=0)  # noqa: SIM115 - closed in the with below
            break
        except FileNotFoundError as exc:
            raise DaemonUnavailable("pipe does not exist (is 'boundkeep serve' running?)") from exc
        except PermissionError as exc:
            raise DaemonUnavailable("access to the pipe was denied") from exc
        except OSError as exc:
            # "Pipe busy" has no dedicated exception type here (errno 22, winerror None): retry.
            if time.monotonic() >= deadline:
                raise DaemonBusy("all pipe instances were busy until the deadline") from exc
            time.sleep(delay)
            delay = min(delay * 2, _MAX_RETRY_DELAY_S)
    with handle:
        try:
            view = memoryview(request_line)
            while view:
                written = handle.write(view)
                if not written:
                    raise DaemonUnavailable("pipe closed while sending the request")
                view = view[written:]
            buf = bytearray()
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    raise DaemonUnavailable("connection closed before a complete response")
                buf += chunk
                newline = buf.find(b"\n")
                if newline >= 0:
                    return bytes(buf[:newline])
                if len(buf) > MAX_RESPONSE_BYTES + 1:
                    raise ProtocolError("response too large")
        except OSError as exc:
            raise DaemonUnavailable(
                f"pipe i/o failed: {exc.strerror or type(exc).__name__}"
            ) from exc


def _transact_unix(address: str, request_line: bytes, deadline: float) -> bytes:
    if sys.platform == "win32":
        raise DaemonUnavailable("unix sockets are not available on Windows")
    import socket  # imported lazily: only POSIX needs it, and it is not free

    def remaining() -> float:
        left = deadline - time.monotonic()
        if left <= 0:
            raise DaemonTimeout("deadline reached")
        return left

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        try:
            sock.settimeout(remaining())
            sock.connect(address)
            sock.settimeout(remaining())
            sock.sendall(request_line)
            buf = bytearray()
            while True:
                sock.settimeout(remaining())
                chunk = sock.recv(65536)
                if not chunk:
                    raise DaemonUnavailable("connection closed before a complete response")
                buf += chunk
                newline = buf.find(b"\n")
                if newline >= 0:
                    return bytes(buf[:newline])
                if len(buf) > MAX_RESPONSE_BYTES + 1:
                    raise ProtocolError("response too large")
        except (FileNotFoundError, ConnectionRefusedError) as exc:
            raise DaemonUnavailable("socket does not exist or nobody is listening") from exc
        except PermissionError as exc:
            raise DaemonUnavailable("access to the socket was denied") from exc
        except TimeoutError as exc:
            raise DaemonTimeout("no response before the deadline") from exc
        except OSError as exc:
            raise DaemonUnavailable(
                f"socket i/o failed: {exc.strerror or type(exc).__name__}"
            ) from exc
