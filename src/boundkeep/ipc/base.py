"""Server side of the local IPC (the daemon). The hook client uses ``boundkeep.ipc.client``.

One request is one line, one response is one line (see ``boundkeep.protocol``). A transport only
moves bytes and enforces the transport-level limits; it knows nothing about events or decisions.
``Handler`` receives the request line without its newline and returns the full response line
including the trailing newline.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Coroutine
from typing import Any, Protocol

from boundkeep.ipc.endpoint import TRANSPORT_NAMED_PIPE, TRANSPORT_UNIX, Endpoint

Handler = Callable[[bytes], Coroutine[Any, Any, bytes]]
ErrorSink = Callable[[str], None]

DEFAULT_INSTANCES = 8  # measured in M0a: a pool of 8 cuts "pipe busy" under 4 clients to 2 to 4%
DEFAULT_READ_TIMEOUT_S = 5.0
DEFAULT_HANDLER_TIMEOUT_S = 30.0


class ServerStartError(Exception):
    """The server could not start (message is safe to print)."""


class AddressInUse(ServerStartError):
    """Another server already owns the address (pipe name or socket path)."""


class IpcServer(Protocol):
    @property
    def address(self) -> str: ...

    async def start(self) -> None:
        """Create the endpoint. After it returns, clients can connect without a busy window."""

    async def close(self) -> None:
        """Stop accepting, drop idle connections, release the endpoint. Safe to call twice."""


def create_server(
    endpoint: Endpoint,
    handler: Handler,
    *,
    instances: int = DEFAULT_INSTANCES,
    read_timeout_s: float = DEFAULT_READ_TIMEOUT_S,
    handler_timeout_s: float = DEFAULT_HANDLER_TIMEOUT_S,
    on_error: ErrorSink | None = None,
) -> IpcServer:
    """The server for ``endpoint.transport``; the transport modules are imported lazily."""
    if endpoint.transport == TRANSPORT_NAMED_PIPE:
        if sys.platform == "win32":
            from boundkeep.ipc.named_pipe import NamedPipeServer

            return NamedPipeServer(
                endpoint.address,
                handler,
                instances=instances,
                read_timeout_s=read_timeout_s,
                handler_timeout_s=handler_timeout_s,
                on_error=on_error,
            )
        raise ServerStartError("named pipes are only available on Windows")
    if endpoint.transport == TRANSPORT_UNIX:
        if sys.platform != "win32":
            from boundkeep.ipc.unix import UnixSocketServer

            return UnixSocketServer(
                endpoint.address,
                handler,
                read_timeout_s=read_timeout_s,
                handler_timeout_s=handler_timeout_s,
                on_error=on_error,
            )
        raise ServerStartError("unix sockets are not available on Windows")
    raise ServerStartError(f"unknown transport {endpoint.transport!r}")
