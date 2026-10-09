"""Where the daemon listens (``endpoint.json``). Standard library only.

``boundkeep init`` generates the endpoint once and writes it into the private home directory; the
daemon creates the pipe or socket at that address and the hook client reads the file on every call.
On Windows the pipe name carries a random token so another process cannot pre-create (squat) the
pipe before the daemon starts; the DACL and the first-instance flag protect the rest (spec 5.1).
"""

from __future__ import annotations

import json
import os
import re
import sys

TRANSPORT_NAMED_PIPE = "named_pipe"
TRANSPORT_UNIX = "unix"
TRANSPORTS = frozenset({TRANSPORT_NAMED_PIPE, TRANSPORT_UNIX})

ENDPOINT_FORMAT_VERSION = 1
MAX_ENDPOINT_FILE_BYTES = 4096
PIPE_PREFIX = "\\\\.\\pipe\\"
# Longest sun_path that is portable (macOS 104, Linux 108, minus the terminating NUL).
MAX_UNIX_SOCKET_PATH = 100

_PIPE_NAME_RE = re.compile(r"\\\\\.\\pipe\\boundkeep-[0-9A-Za-z_-]{1,64}")


class EndpointError(Exception):
    """The endpoint file is missing, unreadable or invalid."""


class Endpoint:
    __slots__ = ("address", "transport")

    def __init__(self, transport: str, address: str) -> None:
        self.transport = transport
        self.address = address

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, Endpoint)
            and self.transport == other.transport
            and self.address == other.address
        )

    def __hash__(self) -> int:
        return hash((self.transport, self.address))

    def __repr__(self) -> str:
        return f"Endpoint(transport={self.transport!r}, address={self.address!r})"


def default_transport() -> str:
    return TRANSPORT_NAMED_PIPE if sys.platform == "win32" else TRANSPORT_UNIX


def pipe_address(token: str) -> str:
    return f"{PIPE_PREFIX}boundkeep-{token}"


def new_endpoint(home: str, *, transport: str | None = None) -> Endpoint:
    """A fresh endpoint with a random token. Nothing is created or written here."""
    transport = transport or default_transport()
    token = os.urandom(16).hex()
    if transport == TRANSPORT_NAMED_PIPE:
        return Endpoint(TRANSPORT_NAMED_PIPE, pipe_address(token))
    if transport == TRANSPORT_UNIX:
        preferred = os.path.join(home, "serve.sock")
        if len(preferred.encode("utf-8", "surrogateescape")) <= MAX_UNIX_SOCKET_PATH:
            return Endpoint(TRANSPORT_UNIX, preferred)
        # Home is too deep for a socket path: use a short private directory (the server creates
        # it with mode 0700 and refuses to use one it does not own).
        uid = os.getuid() if hasattr(os, "getuid") else 0
        return Endpoint(TRANSPORT_UNIX, f"/tmp/bk-{uid}-{token[:8]}/serve.sock")  # noqa: S108
    raise EndpointError(f"unknown transport {transport!r}")


def validate_endpoint(endpoint: Endpoint) -> None:
    if endpoint.transport == TRANSPORT_NAMED_PIPE:
        if not _PIPE_NAME_RE.fullmatch(endpoint.address):
            raise EndpointError("named pipe address must look like \\\\.\\pipe\\boundkeep-<token>")
    elif endpoint.transport == TRANSPORT_UNIX:
        if not os.path.isabs(endpoint.address):
            raise EndpointError("unix socket address must be an absolute path")
        if len(endpoint.address.encode("utf-8", "surrogateescape")) > MAX_UNIX_SOCKET_PATH:
            raise EndpointError("unix socket path is too long")
    else:
        raise EndpointError(f"unknown transport {endpoint.transport!r}")


def write_endpoint(path: str, endpoint: Endpoint) -> None:
    """Atomically write ``endpoint.json`` (temporary file in the same directory, then replace)."""
    validate_endpoint(endpoint)
    data = (
        json.dumps(
            {
                "v": ENDPOINT_FORMAT_VERSION,
                "transport": endpoint.transport,
                "address": endpoint.address,
            },
            ensure_ascii=True,
            indent=2,
        ).encode("ascii")
        + b"\n"
    )
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp-{os.getpid()}"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        import contextlib  # lazy: only the writer needs it, the hook client only reads

        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def read_endpoint(path: str) -> Endpoint:
    """Read and validate ``endpoint.json``; raises ``EndpointError`` for anything wrong."""
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_ENDPOINT_FILE_BYTES + 1)
    except FileNotFoundError as exc:
        raise EndpointError("endpoint file not found (run 'boundkeep init')") from exc
    except OSError as exc:
        raise EndpointError(
            f"endpoint file unreadable: {exc.strerror or exc.__class__.__name__}"
        ) from exc
    if len(data) > MAX_ENDPOINT_FILE_BYTES:
        raise EndpointError("endpoint file is too large")
    try:
        obj = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        raise EndpointError("endpoint file is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise EndpointError("endpoint file is not a JSON object")
    version = obj.get("v")
    if isinstance(version, bool) or version != ENDPOINT_FORMAT_VERSION:
        raise EndpointError("endpoint file has an unsupported version")
    transport = obj.get("transport")
    address = obj.get("address")
    if not isinstance(transport, str) or not isinstance(address, str):
        raise EndpointError("endpoint file is missing transport or address")
    endpoint = Endpoint(transport, address)
    validate_endpoint(endpoint)
    return endpoint
