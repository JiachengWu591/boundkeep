"""The Windows named-pipe server, exercised through the real client code over real pipes."""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import json
import os
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.ipc import client as ipc_client
from boundkeep.ipc import endpoint as ipc_endpoint
from boundkeep.ipc.base import AddressInUse, ServerStartError

pytestmark = pytest.mark.windows

if os.name == "nt":  # the module imports only on Windows
    from boundkeep.ipc import winsec
    from boundkeep.ipc.named_pipe import NamedPipeServer


def new_address() -> str:
    return ipc_endpoint.pipe_address(os.urandom(8).hex())


def endpoint_of(address: str) -> ipc_endpoint.Endpoint:
    return ipc_endpoint.Endpoint(ipc_endpoint.TRANSPORT_NAMED_PIPE, address)


def request_line(payload: object = None, request_id: str = "r1") -> bytes:
    return protocol.encode_request(protocol.EVENT_PRE, {"v": payload}, request_id)


async def echo(line: bytes) -> bytes:
    request = protocol.decode_request(line)
    return protocol.encode_response(request.request_id, decision="ask", reason=str(request.payload))


@contextlib.asynccontextmanager
async def serving(
    handler: Callable[[bytes], Awaitable[bytes]] = echo, **options: Any
) -> AsyncIterator[NamedPipeServer]:
    server = NamedPipeServer(new_address(), handler, **options)
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


def connect_raw(address: str, timeout_s: float = 10.0) -> Any:
    """Open the pipe like a client, retrying "pipe busy" the way the real client does."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return open(address, "r+b", buffering=0)
        except FileNotFoundError:
            raise
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.005)


def process_handle_count() -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.GetProcessHandleCount.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    count = ctypes.c_uint32(0)
    assert kernel32.GetProcessHandleCount(kernel32.GetCurrentProcess(), ctypes.byref(count))
    return int(count.value)


def test_a_request_gets_the_handlers_answer() -> None:
    async def scenario() -> None:
        async with serving() as server:
            line = await call(server.address, request_line("你好 ✓"))
            response = protocol.decode_response(line, "r1")
            assert response.ok
            assert response.decision == "ask"
            assert response.reason == "{'v': '你好 ✓'}"

    run(scenario())


def test_many_sequential_requests_all_succeed() -> None:
    async def scenario() -> None:
        async with serving() as server:
            for i in range(200):
                line = await call(server.address, request_line(i, f"r{i}"))
                assert protocol.decode_response(line, f"r{i}").ok

    run(scenario())


def test_32_concurrent_clients_lose_no_request() -> None:
    """Spec M0 acceptance: >= 32 concurrent hook clients, no request lost (pipe busy is retried)."""
    seen: list[str] = []

    async def counting(line: bytes) -> bytes:
        request = protocol.decode_request(line)
        seen.append(request.request_id)
        return await echo(line)

    failures: list[str] = []

    def client_thread(address: str, worker: int) -> None:
        for i in range(20):
            rid = f"w{worker}-{i}"
            try:
                line = ipc_client.call(endpoint_of(address), request_line(i, rid), timeout_s=20)
                if not protocol.decode_response(line, rid).ok:
                    failures.append(f"{rid}: not ok")
            except Exception as exc:
                failures.append(f"{rid}: {type(exc).__name__}: {exc}")

    async def scenario() -> None:
        async with serving(counting) as server:
            loop = asyncio.get_running_loop()
            futures = [
                loop.run_in_executor(None, client_thread, server.address, n) for n in range(32)
            ]
            await asyncio.gather(*futures)

    run(scenario())
    assert failures == []
    assert len(seen) == 32 * 20
    assert len(set(seen)) == 32 * 20


def test_the_pipe_is_private_to_the_current_user() -> None:
    async def scenario() -> None:
        async with serving() as server:
            acl = winsec.read_acl_of_pipe(server.address)
            assert acl.dacl_present
            assert acl.aces, "a pipe without ACEs would be unusable"
            for ace in acl.aces:
                assert ace.allowed
                assert ace.sid == winsec.current_user_sid()
            everyone = {winsec.WORLD_SID, winsec.ANONYMOUS_SID, winsec.AUTHENTICATED_USERS_SID}
            assert not {ace.sid for ace in acl.aces} & everyone
            # the probe borrowed an instance for a moment; the server must be fine afterwards
            assert protocol.decode_response(await call(server.address, request_line()), "r1").ok

    run(scenario())


def test_a_second_server_on_the_same_name_is_refused_and_the_first_keeps_working() -> None:
    async def scenario() -> None:
        async with serving() as first:
            second = NamedPipeServer(first.address, echo)
            with pytest.raises(AddressInUse):
                await second.start()
            assert protocol.decode_response(await call(first.address, request_line()), "r1").ok

    run(scenario())


def test_a_name_can_be_reused_after_close() -> None:
    async def scenario() -> None:
        address = new_address()
        first = NamedPipeServer(address, echo)
        await first.start()
        await first.close()
        with pytest.raises(ipc_client.DaemonUnavailable):
            ipc_client.call(endpoint_of(address), request_line(), timeout_s=2)
        second = NamedPipeServer(address, echo)
        await second.start()
        try:
            assert protocol.decode_response(await call(address, request_line()), "r1").ok
        finally:
            await second.close()

    run(scenario())


def test_silent_clients_cannot_starve_the_pool() -> None:
    """More idle connections than instances: they time out and real requests still get through."""

    async def scenario() -> None:
        async with serving(instances=4, read_timeout_s=0.6) as server:
            silent = [connect_raw(server.address) for _ in range(4)]
            try:
                started = time.monotonic()
                line = await call(server.address, request_line(), timeout_s=15)
                assert protocol.decode_response(line, "r1").ok
                assert time.monotonic() - started < 10
            finally:
                for handle in silent:
                    handle.close()

    run(scenario())


def test_a_client_that_connects_and_leaves_does_not_hurt() -> None:
    async def scenario() -> None:
        async with serving(instances=2, read_timeout_s=2) as server:
            for _ in range(10):
                connect_raw(server.address).close()
            partial = connect_raw(server.address)
            partial.write(b'{"v":1,"id":"half')  # no newline, then gone
            partial.close()
            for i in range(20):
                assert protocol.decode_response(
                    await call(server.address, request_line(i, f"r{i}")), f"r{i}"
                ).ok

    run(scenario())


def test_an_oversized_request_gets_a_protocol_error_not_a_hang() -> None:
    async def scenario() -> None:
        async with serving(max_request_bytes=1000) as server:
            line = await call(server.address, b'{"x":"' + b"a" * 5000 + b'"}\n')
            answer = json.loads(line)
            assert answer["ok"] is False
            assert answer["error"] == protocol.ERR_TOO_LARGE
            assert protocol.decode_response(await call(server.address, request_line()), "r1").ok

    run(scenario())


def test_a_request_that_never_ends_gets_a_timeout_answer() -> None:
    async def scenario() -> None:
        async with serving(read_timeout_s=0.5) as server:
            loop = asyncio.get_running_loop()

            def stall() -> bytes:
                with connect_raw(server.address) as handle:
                    handle.write(b'{"v":1,"id":"slow"')  # never terminated
                    return handle.read(4096)

            data = await loop.run_in_executor(None, stall)
            assert json.loads(data)["error"] == protocol.ERR_TIMEOUT

    run(scenario())


def test_a_failing_handler_yields_an_internal_error_and_the_server_lives_on() -> None:
    errors: list[str] = []

    async def broken(line: bytes) -> bytes:
        if b"boom" in line:
            raise RuntimeError("secret detail that must not travel")
        return await echo(line)

    async def scenario() -> None:
        async with serving(broken, on_error=errors.append) as server:
            answer = json.loads(await call(server.address, request_line("boom")))
            assert answer["ok"] is False
            assert answer["error"] == protocol.ERR_INTERNAL
            assert "secret detail" not in json.dumps(answer)
            assert protocol.decode_response(await call(server.address, request_line()), "r1").ok

    run(scenario())
    assert any("RuntimeError" in e for e in errors)
    assert not any("secret detail" in e for e in errors)


def test_a_slow_handler_is_cut_off() -> None:
    async def slow(line: bytes) -> bytes:
        await asyncio.sleep(30)
        return await echo(line)

    async def scenario() -> None:
        async with serving(slow, handler_timeout_s=0.5) as server:
            started = time.monotonic()
            answer = json.loads(await call(server.address, request_line()))
            assert answer["error"] == protocol.ERR_TIMEOUT
            assert time.monotonic() - started < 5

    run(scenario())


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(b"no newline at the end", id="no-newline"),
        pytest.param(b"x" * (protocol.MAX_RESPONSE_BYTES + 100) + b"\n", id="too-large"),
        pytest.param("text\n", id="not-bytes"),
        pytest.param(None, id="none"),
    ],
)
def test_an_invalid_handler_response_becomes_an_internal_error(bad: Any) -> None:
    async def wrong(line: bytes) -> bytes:
        return bad  # type: ignore[no-any-return]

    async def scenario() -> None:
        async with serving(wrong) as server:
            answer = json.loads(await call(server.address, request_line()))
            assert answer["error"] == protocol.ERR_INTERNAL

    run(scenario())


def test_close_returns_promptly_with_idle_workers_and_a_silent_client() -> None:
    async def scenario() -> None:
        server = NamedPipeServer(new_address(), echo, instances=4, read_timeout_s=30)
        await server.start()
        silent = connect_raw(server.address)
        try:
            await asyncio.sleep(0.2)
            started = time.monotonic()
            await server.close()
            assert time.monotonic() - started < 4
        finally:
            silent.close()
        await server.close()  # closing twice is fine
        assert not [t for t in threading.enumerate() if t.name.startswith("boundkeep-pipe-")]

    run(scenario())


def test_close_while_a_request_is_in_flight_does_not_deadlock() -> None:
    release = threading.Event()

    async def hanging(line: bytes) -> bytes:
        while not release.is_set():
            await asyncio.sleep(0.05)
        return await echo(line)

    async def scenario() -> None:
        server = NamedPipeServer(new_address(), hanging, instances=2, handler_timeout_s=30)
        await server.start()
        loop = asyncio.get_running_loop()
        pending = loop.run_in_executor(
            None, lambda: _try_call(server.address, request_line(), timeout_s=10)
        )
        await asyncio.sleep(0.3)
        started = time.monotonic()
        await server.close()
        assert time.monotonic() - started < 5
        release.set()
        await pending

    run(scenario())


def _try_call(address: str, line: bytes, timeout_s: float) -> bytes | None:
    try:
        return ipc_client.call(endpoint_of(address), line, timeout_s=timeout_s)
    except ipc_client.IpcError:
        return None


@contextlib.contextmanager
def threaded_server(**options: Any) -> Iterator[str]:
    """The server on its own loop in a background thread; the test thread is a plain client."""
    address = new_address()
    ready = threading.Event()
    stop = threading.Event()
    problems: list[BaseException] = []

    def serve() -> None:
        async def main() -> None:
            server = NamedPipeServer(address, echo, **options)
            try:
                await server.start()
            except BaseException as exc:
                problems.append(exc)
                ready.set()
                return
            ready.set()
            while not stop.is_set():
                await asyncio.sleep(0.02)
            await server.close()

        asyncio.run(main())

    thread = threading.Thread(target=serve, name="test-pipe-server", daemon=True)
    thread.start()
    assert ready.wait(10)
    if problems:
        raise problems[0]
    try:
        yield address
    finally:
        stop.set()
        thread.join(10)


def test_no_handles_leak_over_many_connections() -> None:
    """300 requests and 20 abandoned connections leave the process's handle count where it was."""
    with threaded_server(instances=4) as address:
        endpoint = endpoint_of(address)
        for i in range(30):  # warm up: thread pools, caches
            ipc_client.transact(endpoint, request_line(i, f"w{i}"), time.monotonic() + 5)
        time.sleep(0.3)
        before = process_handle_count()
        for i in range(300):
            line = ipc_client.transact(endpoint, request_line(i, f"r{i}"), time.monotonic() + 5)
            assert protocol.decode_response(line, f"r{i}").ok
        for _ in range(20):
            connect_raw(address).close()
        time.sleep(0.5)  # let the workers recycle the abandoned connections
        after = process_handle_count()
        assert after - before <= 5, (before, after)


@pytest.mark.parametrize("instances", [0, 65, -1])
def test_invalid_pool_sizes_are_refused(instances: int) -> None:
    with pytest.raises(ServerStartError):
        NamedPipeServer(new_address(), echo, instances=instances)


def test_only_boundkeep_pipe_addresses_are_accepted() -> None:
    with pytest.raises(ServerStartError):
        NamedPipeServer("not-a-pipe", echo)


def test_a_server_can_only_be_started_once() -> None:
    async def scenario() -> None:
        async with serving() as server:
            with pytest.raises(ServerStartError):
                await server.start()

    run(scenario())


def test_eight_silent_clients_delay_a_real_request_by_about_a_second() -> None:
    """A client that connects and stays silent must not hold an instance for the 5 s timeout."""

    async def scenario() -> None:
        async with serving(instances=8) as server:  # default read timeout: 5 s
            silent = [connect_raw(server.address) for _ in range(8)]
            try:
                started = time.monotonic()
                line = await call(server.address, request_line(), timeout_s=15)
                assert protocol.decode_response(line, "r1").ok
                assert time.monotonic() - started < 3.0
            finally:
                for handle in silent:
                    handle.close()

    run(scenario())


def test_clients_that_read_their_answer_but_never_hang_up_do_not_hold_the_pool() -> None:
    async def scenario() -> None:
        async with serving(instances=2) as server:
            loop = asyncio.get_running_loop()

            def lingering() -> Any:
                handle = connect_raw(server.address)
                handle.write(request_line())
                assert handle.readline()
                return handle  # kept open

            handles = [await loop.run_in_executor(None, lingering) for _ in range(2)]
            try:
                started = time.monotonic()
                line = await call(server.address, request_line(), timeout_s=15)
                assert protocol.decode_response(line, "r1").ok
                assert time.monotonic() - started < 1.5
            finally:
                for handle in handles:
                    handle.close()

    run(scenario())
