"""The POSIX Unix-socket server.

[UNVERIFIED on the Windows development host: every test here is marked ``posix`` and is skipped
there. They have to be run on Linux or macOS (or in a Linux container) before POSIX support can be
claimed; see docs/platforms.md.]
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import stat
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.ipc import client as ipc_client
from boundkeep.ipc import endpoint as ipc_endpoint
from boundkeep.ipc.base import AddressInUse, ServerStartError

pytestmark = pytest.mark.posix

if os.name == "posix":
    from boundkeep.ipc.unix import UnixSocketServer


def endpoint_of(address: str) -> ipc_endpoint.Endpoint:
    return ipc_endpoint.Endpoint(ipc_endpoint.TRANSPORT_UNIX, address)


def request_line(payload: object = None, request_id: str = "r1") -> bytes:
    return protocol.encode_request(protocol.EVENT_PRE, {"v": payload}, request_id)


async def echo(line: bytes) -> bytes:
    request = protocol.decode_request(line)
    return protocol.encode_response(request.request_id, decision="ask", reason=str(request.payload))


def socket_path(tmp_path: Path) -> str:
    # Unix socket paths are short (about 104 bytes): keep them out of pytest's deep tmp paths.
    directory = Path("/tmp") / f"bk-test-{os.getpid()}-{os.urandom(4).hex()}"
    directory.mkdir(mode=0o700)
    return str(directory / "serve.sock")


@contextlib.asynccontextmanager
async def serving(
    path: str, handler: Callable[[bytes], Awaitable[bytes]] = echo, **options: Any
) -> AsyncIterator[UnixSocketServer]:
    server = UnixSocketServer(path, handler, **options)  # type: ignore[arg-type]
    await server.start()
    try:
        yield server
    finally:
        await server.close()


async def call(address: str, line: bytes, timeout_s: float = 10.0) -> bytes:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, lambda: ipc_client.call(endpoint_of(address), line, timeout_s=timeout_s)
    )


def run(coro: Awaitable[None]) -> None:
    asyncio.run(coro)  # type: ignore[arg-type]


def test_roundtrip_and_private_permissions(tmp_path: Path) -> None:
    path = socket_path(tmp_path)

    async def scenario() -> None:
        async with serving(path) as server:
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
            assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700
            line = await call(server.address, request_line("你好 ✓"))
            assert protocol.decode_response(line, "r1").reason == "{'v': '你好 ✓'}"
        assert not os.path.exists(path)  # the socket file is removed on close

    run(scenario())


def test_32_concurrent_clients_lose_no_request(tmp_path: Path) -> None:
    path = socket_path(tmp_path)
    failures: list[str] = []

    def client(worker: int) -> None:
        for i in range(20):
            rid = f"w{worker}-{i}"
            try:
                line = ipc_client.call(endpoint_of(path), request_line(i, rid), timeout_s=20)
                if not protocol.decode_response(line, rid).ok:
                    failures.append(rid)
            except Exception as exc:
                failures.append(f"{rid}: {exc!r}")

    async def scenario() -> None:
        async with serving(path):
            loop = asyncio.get_running_loop()
            await asyncio.gather(*(loop.run_in_executor(None, client, n) for n in range(32)))

    run(scenario())
    assert failures == []


def test_a_stale_socket_file_is_replaced(tmp_path: Path) -> None:
    path = socket_path(tmp_path)
    leftover = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    leftover.bind(path)
    leftover.close()  # the file stays, nobody listens: what a crashed daemon leaves behind
    assert os.path.exists(path)

    async def scenario() -> None:
        async with serving(path) as server:
            assert protocol.decode_response(await call(server.address, request_line()), "r1").ok

    run(scenario())


def test_a_live_server_is_not_displaced(tmp_path: Path) -> None:
    path = socket_path(tmp_path)

    async def scenario() -> None:
        async with serving(path):
            with pytest.raises(AddressInUse):
                await UnixSocketServer(path, echo).start()
            assert protocol.decode_response(await call(path, request_line()), "r1").ok

    run(scenario())


def test_something_that_is_not_a_socket_is_never_deleted(tmp_path: Path) -> None:
    path = socket_path(tmp_path)
    Path(path).write_text("precious", encoding="utf-8")

    async def scenario() -> None:
        with pytest.raises(ServerStartError, match="not a socket"):
            await UnixSocketServer(path, echo).start()

    run(scenario())
    assert Path(path).read_text(encoding="utf-8") == "precious"


def test_a_directory_open_to_others_is_refused(tmp_path: Path) -> None:
    path = socket_path(tmp_path)
    os.chmod(os.path.dirname(path), 0o755)  # noqa: S103 - deliberately too open

    async def scenario() -> None:
        with pytest.raises(ServerStartError, match="other users"):
            await UnixSocketServer(path, echo).start()

    run(scenario())


def test_silent_oversized_and_failing_clients_do_not_hurt(tmp_path: Path) -> None:
    path = socket_path(tmp_path)
    errors: list[str] = []

    async def broken(line: bytes) -> bytes:
        if b"boom" in line:
            raise RuntimeError("secret detail")
        return await echo(line)

    async def scenario() -> None:
        async with serving(
            path, broken, read_timeout_s=0.5, max_request_bytes=1000, on_error=errors.append
        ):
            silent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            silent.connect(path)
            try:
                huge = json.loads(await call(path, b'{"x":"' + b"a" * 5000 + b'"}\n'))
                assert huge["error"] == protocol.ERR_TOO_LARGE
                failing = json.loads(await call(path, request_line("boom")))
                assert failing["error"] == protocol.ERR_INTERNAL
                assert "secret detail" not in json.dumps(failing)
                assert protocol.decode_response(await call(path, request_line()), "r1").ok
                silent.settimeout(5)
                loop = asyncio.get_running_loop()  # a blocking recv here would stall the server
                answer = await loop.run_in_executor(None, silent.recv, 4096)
                assert json.loads(answer)["error"] == protocol.ERR_TIMEOUT
            finally:
                silent.close()

    run(scenario())
    assert not any("secret detail" in e for e in errors)


def test_a_slow_handler_is_cut_off_and_close_is_prompt(tmp_path: Path) -> None:
    path = socket_path(tmp_path)

    async def slow(line: bytes) -> bytes:
        await asyncio.sleep(30)
        return await echo(line)

    async def scenario() -> None:
        started = time.monotonic()
        async with serving(path, slow, handler_timeout_s=0.5):
            answer = json.loads(await call(path, request_line()))
            assert answer["error"] == protocol.ERR_TIMEOUT
        assert time.monotonic() - started < 6

    run(scenario())
