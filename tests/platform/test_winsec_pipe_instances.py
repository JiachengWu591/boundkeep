"""Review H-2, server side: once the daemon's pipe instances exist, nobody may create another one.

The user's ACE used to be FILE_ALL_ACCESS, which includes FILE_CREATE_PIPE_INSTANCE (0x4, the same
bit as FILE_APPEND_DATA): any process of the same user could add an instance of its own to the
pipe and answer hook requests in the daemon's place. The daemon now rewrites the DACL after its
fixed pool has been created. Everything here runs on pipes with a random name made by the test.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.ipc import client as ipc_client
from boundkeep.ipc import endpoint as ipc_endpoint

pytestmark = pytest.mark.windows

if os.name == "nt":  # the modules import only on Windows
    from boundkeep.ipc import winsec
    from boundkeep.ipc.named_pipe import NamedPipeServer

_PIPE_ACCESS_DUPLEX = 0x3
_FILE_FLAG_OVERLAPPED = 0x40000000
_PIPE_REJECT_REMOTE_CLIENTS = 0x8
_ERROR_ACCESS_DENIED = 5
_INVALID = ctypes.c_void_p(-1).value


def _k32() -> Any:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateNamedPipeW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    k32.CreateNamedPipeW.restype = ctypes.c_void_p
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    k32.CloseHandle.restype = ctypes.c_int
    return k32


def _try_to_add_an_instance(address: str, *, private_dacl: bool) -> int:
    """What a same-user impostor does: CreateNamedPipeW on the existing name. Returns the Win32
    error code, 0 when it succeeded (the handle is closed again)."""
    k32 = _k32()
    flags = _PIPE_ACCESS_DUPLEX | _FILE_FLAG_OVERLAPPED
    if private_dacl:
        with winsec.SecurityDescriptor.private() as descriptor:
            attributes = descriptor.attributes
            handle = k32.CreateNamedPipeW(
                address,
                flags,
                _PIPE_REJECT_REMOTE_CLIENTS,
                255,
                4096,
                4096,
                0,
                ctypes.byref(attributes),
            )
    else:
        handle = k32.CreateNamedPipeW(
            address, flags, _PIPE_REJECT_REMOTE_CLIENTS, 255, 4096, 4096, 0, None
        )
    if handle and handle != _INVALID:
        k32.CloseHandle(handle)
        return 0
    return int(ctypes.get_last_error())


def new_address() -> str:
    return ipc_endpoint.pipe_address(os.urandom(8).hex())


async def echo(line: bytes) -> bytes:
    request = protocol.decode_request(line)
    return protocol.encode_response(request.request_id, decision="ask", reason="ok")


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


def run(coro: Awaitable[None]) -> None:
    asyncio.run(coro)  # type: ignore[arg-type]


def test_control_a_pipe_with_the_old_all_access_dacl_accepts_another_instance() -> None:
    """The problem as reported: with FILE_ALL_ACCESS for the user a second instance is allowed."""
    k32 = _k32()
    address = new_address()
    with winsec.SecurityDescriptor.private() as descriptor:
        first = k32.CreateNamedPipeW(
            address,
            _PIPE_ACCESS_DUPLEX | 0x00080000,  # first instance
            _PIPE_REJECT_REMOTE_CLIENTS,
            255,
            4096,
            4096,
            0,
            ctypes.byref(descriptor.attributes),
        )
    assert first
    assert first != _INVALID
    try:
        assert _try_to_add_an_instance(address, private_dacl=True) == 0
        assert _try_to_add_an_instance(address, private_dacl=False) == 0
    finally:
        k32.CloseHandle(first)


@pytest.mark.parametrize("instances", [1, 8])
def test_the_daemons_pipe_refuses_further_instances_even_for_its_own_user(instances: int) -> None:
    async def scenario() -> None:
        async with serving(instances=instances) as server:
            assert (
                _try_to_add_an_instance(server.address, private_dacl=True) == _ERROR_ACCESS_DENIED
            )
            assert (
                _try_to_add_an_instance(server.address, private_dacl=False) == _ERROR_ACCESS_DENIED
            )

    run(scenario())


def test_the_dacl_lets_the_user_connect_read_and_write_but_not_create_instances() -> None:
    async def scenario() -> None:
        async with serving() as server:
            acl = await asyncio.get_running_loop().run_in_executor(
                None, winsec.read_acl_of_pipe, server.address
            )
            assert acl.dacl_present
            assert acl.dacl_protected
            assert [(ace.sid, ace.allowed) for ace in acl.aces] == [
                (winsec.current_user_sid(), True)
            ]
            mask = acl.aces[0].mask
            assert not mask & winsec.FILE_CREATE_PIPE_INSTANCE, hex(mask)
            assert mask & 0x1  # FILE_READ_DATA
            assert mask & 0x2  # FILE_WRITE_DATA
            assert mask & 0x20000  # READ_CONTROL (doctor reads the DACL)
            assert mask & 0x100000  # SYNCHRONIZE
            assert not mask & 0x40000  # WRITE_DAC
            assert not mask & 0x80000  # WRITE_OWNER

    run(scenario())


def test_the_client_still_connects_and_gets_answers_after_the_tightening() -> None:
    async def scenario() -> None:
        async with serving() as server:
            loop = asyncio.get_running_loop()
            endpoint = ipc_endpoint.Endpoint(ipc_endpoint.TRANSPORT_NAMED_PIPE, server.address)
            for i in range(30):  # more than the pool: every instance is recycled and reused
                rid = f"r{i}"
                line = protocol.encode_request(protocol.EVENT_PRE, {"i": i}, rid)
                answer = await loop.run_in_executor(
                    None, lambda line=line: ipc_client.call(endpoint, line, timeout_s=10)
                )
                response = protocol.decode_response(answer, rid)
                assert (response.ok, response.decision) == (True, "ask")

    run(scenario())


def test_a_name_that_is_taken_still_fails_with_address_in_use() -> None:
    from boundkeep.ipc.base import AddressInUse

    async def scenario() -> None:
        async with serving() as server:
            second = NamedPipeServer(server.address, echo)
            with pytest.raises(AddressInUse):
                await second.start()

    run(scenario())


def test_the_name_can_be_served_again_after_a_clean_stop() -> None:
    async def scenario() -> None:
        address = new_address()
        for _ in range(2):
            server = NamedPipeServer(address, echo)
            await server.start()
            await server.close()

    run(scenario())
