"""POSIX Unix-domain-socket server (asyncio).

[UNVERIFIED on this machine: the development host is Windows, where the standard library has no
``AF_UNIX``. The tests in tests/platform/test_unix_socket.py are marked ``posix`` and have not been
run yet; do not claim POSIX support until they have (spec 5.1).]

The socket lives in a private directory (mode 0700, owned by us) and is created with mode 0600, so
only this user can connect. A stale socket file left behind by a crashed daemon is removed; a
socket that still answers means another daemon runs and is refused as ``AddressInUse``.
Semantics match ``named_pipe.py``: one request line, one response line, transport-level problems
answered with a protocol error line (placeholder id ``-``).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import stat
import sys

from boundkeep import protocol
from boundkeep.ipc.base import (
    DEFAULT_HANDLER_TIMEOUT_S,
    DEFAULT_READ_TIMEOUT_S,
    AddressInUse,
    ErrorSink,
    Handler,
    ServerStartError,
)

if sys.platform == "win32":  # pragma: no cover
    raise ImportError("boundkeep.ipc.unix is only available on POSIX")
assert sys.platform != "win32"  # lets mypy skip the rest on Windows

_TRANSPORT_ERROR_ID = "-"
_PROBE_TIMEOUT_S = 1.0


class UnixSocketServer:
    def __init__(
        self,
        address: str,
        handler: Handler,
        *,
        read_timeout_s: float = DEFAULT_READ_TIMEOUT_S,
        handler_timeout_s: float = DEFAULT_HANDLER_TIMEOUT_S,
        on_error: ErrorSink | None = None,
        max_request_bytes: int = protocol.MAX_REQUEST_BYTES,
    ) -> None:
        if not os.path.isabs(address):
            raise ServerStartError(f"not an absolute socket path: {address!r}")
        self._address = address
        self._handler = handler
        self._read_timeout_s = read_timeout_s
        self._handler_timeout_s = handler_timeout_s
        self._on_error = on_error
        self._max_request_bytes = max_request_bytes
        self._server: asyncio.Server | None = None
        self._clients: set[asyncio.Task[None]] = set()
        self._created = False

    @property
    def address(self) -> str:
        return self._address

    def _report(self, message: str) -> None:
        if self._on_error is not None:
            with contextlib.suppress(Exception):
                self._on_error(message)

    # -- lifecycle ---------------------------------------------------------------------------

    async def start(self) -> None:
        if self._server is not None:
            raise ServerStartError("server already started")
        self._prepare_directory()
        self._remove_stale_socket()
        previous = os.umask(0o177)  # the socket is created with mode 0600
        try:
            self._server = await asyncio.start_unix_server(
                self._serve_client, path=self._address, limit=self._max_request_bytes + 2
            )
        except OSError as exc:
            raise ServerStartError(
                f"cannot listen on {self._address}: {exc.strerror or type(exc).__name__}"
            ) from exc
        finally:
            os.umask(previous)
        self._created = True
        os.chmod(self._address, 0o600)  # belt and braces: do not depend on the umask alone

    async def close(self) -> None:
        server, self._server = self._server, None
        if server is None:
            return
        server.close()
        for task in list(self._clients):
            task.cancel()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(server.wait_closed(), timeout=5.0)
        if self._created:
            self._created = False
            with contextlib.suppress(OSError):
                os.unlink(self._address)

    def _prepare_directory(self) -> None:
        directory = os.path.dirname(self._address)
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            info = os.stat(directory)
        except OSError as exc:
            raise ServerStartError(
                f"cannot use the socket directory {directory}: {exc.strerror}"
            ) from exc
        if info.st_uid != os.geteuid():
            raise ServerStartError(f"refusing to use {directory}: it is owned by another user")
        if info.st_mode & 0o077:
            raise ServerStartError(
                f"refusing to use {directory}: other users have access (run 'chmod 700')"
            )

    def _remove_stale_socket(self) -> None:
        try:
            info = os.lstat(self._address)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ServerStartError(f"cannot inspect {self._address}: {exc.strerror}") from exc
        if not stat.S_ISSOCK(info.st_mode):
            raise ServerStartError(f"{self._address} exists and is not a socket")
        if info.st_uid != os.geteuid():
            raise ServerStartError(f"{self._address} belongs to another user")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(_PROBE_TIMEOUT_S)
            try:
                probe.connect(self._address)
            except (ConnectionRefusedError, FileNotFoundError):
                os.unlink(self._address)  # nobody listens: a leftover of a crashed daemon
                return
            except OSError as exc:
                raise ServerStartError(
                    f"cannot tell whether {self._address} is in use: {exc.strerror}"
                ) from exc
        finally:
            probe.close()
        raise AddressInUse(
            f"another server already listens on {self._address} (is 'boundkeep serve' running?)"
        )

    # -- connections -------------------------------------------------------------------------

    async def _serve_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._clients.add(task)
        try:
            response = await self._read_and_answer(reader)
            if response is not None:
                writer.write(response)
                await asyncio.wait_for(writer.drain(), timeout=max(self._read_timeout_s, 1.0))
        except (ConnectionError, TimeoutError, asyncio.CancelledError):
            pass
        except Exception as exc:  # noqa: BLE001 - one bad connection must not stop the server
            self._report(f"connection failed: {type(exc).__name__}")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            if task is not None:
                self._clients.discard(task)

    async def _read_and_answer(self, reader: asyncio.StreamReader) -> bytes | None:
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=self._read_timeout_s)
        except TimeoutError:
            return protocol.encode_error(
                _TRANSPORT_ERROR_ID, protocol.ERR_TIMEOUT, "no complete request line in time"
            )
        except (asyncio.LimitOverrunError, ValueError):
            return protocol.encode_error(
                _TRANSPORT_ERROR_ID, protocol.ERR_TOO_LARGE, "request too large"
            )
        except asyncio.IncompleteReadError:
            return None  # the client left before finishing its request
        line = raw[:-1]
        if len(line) > self._max_request_bytes:
            return protocol.encode_error(
                _TRANSPORT_ERROR_ID, protocol.ERR_TOO_LARGE, "request too large"
            )
        try:
            response = await asyncio.wait_for(self._handler(line), timeout=self._handler_timeout_s)
        except TimeoutError:
            return protocol.encode_error(
                _TRANSPORT_ERROR_ID, protocol.ERR_TIMEOUT, "the daemon did not answer in time"
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a failing handler must not take the server down
            self._report(f"handler failed: {type(exc).__name__}")
            return protocol.encode_error(
                _TRANSPORT_ERROR_ID, protocol.ERR_INTERNAL, "internal error"
            )
        if (
            not isinstance(response, bytes)
            or not response.endswith(b"\n")
            or len(response) > protocol.MAX_RESPONSE_BYTES + 1
        ):
            self._report("handler returned an invalid response")
            return protocol.encode_error(
                _TRANSPORT_ERROR_ID, protocol.ERR_INTERNAL, "internal error"
            )
        return response
