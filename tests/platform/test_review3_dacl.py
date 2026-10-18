"""Review round 3 (re-review section 3): the pipe DACL must not be undoable by its own owner.

Round 1 tightened the pipe DACL to ``D:P(A;;0x0012019B;;;<user>)`` after creating the instances.
That blocks a direct ``CreateNamedPipeW`` of one more instance (error 5), but the OWNER of a
kernel object implicitly holds ``WRITE_DAC``, so the same user could undo it with three calls:

1. open the pipe with ``WRITE_DAC``,
2. ``SetSecurityInfo`` it back to ``FILE_ALL_ACCESS``,
3. create another instance.

The fix adds an OWNER RIGHTS ACE that grants only ``READ_CONTROL``: ``(A;;0x20000;;;OW)``. A DACL
that contains an OWNER RIGHTS ACE switches the implicit owner rights off. Everything here uses
throwaway pipes with a random name; the tests never touch a pipe that belongs to a user's daemon.
The tightening raises the bar for the same user; it is not a boundary against an elevated
administrator (who can take ownership), and it says nothing about a same-user process that
squats the pipe NAME before the daemon starts.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import os
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
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
_FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
_PIPE_REJECT_REMOTE_CLIENTS = 0x8
_ERROR_ACCESS_DENIED = 5
_INVALID = ctypes.c_void_p(-1).value
_SE_KERNEL_OBJECT = 6
_DACL_SECURITY_INFORMATION = 0x4
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_READ_CONTROL = 0x00020000
_FILE_SHARE_READ_WRITE = 0x3
_OPEN_EXISTING = 3

# What round 1 shipped: the user may connect/read/write and read the DACL, nothing else. The owner's
# implicit WRITE_DAC is NOT switched off, which is the defect.
_ROUND1_MASK = 0x0012019B


def _round1_sddl() -> str:
    return f"D:P(A;;0x{_ROUND1_MASK:X};;;{winsec.current_user_sid()})"


class _Win32:
    """The few kernel32 / advapi32 calls the attacker (a same-user process) needs."""

    def __init__(self) -> None:
        self.k32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
        self.adv: Any = ctypes.WinDLL("advapi32", use_last_error=True)
        self.create_error = 0  # Win32 error of the last failed create_instance
        vp = ctypes.c_void_p
        u32 = ctypes.c_uint32
        self.k32.CreateNamedPipeW.argtypes = [ctypes.c_wchar_p, u32, u32, u32, u32, u32, u32, vp]
        self.k32.CreateNamedPipeW.restype = vp
        self.k32.CreateFileW.argtypes = [ctypes.c_wchar_p, u32, u32, vp, u32, u32, vp]
        self.k32.CreateFileW.restype = vp
        self.k32.CloseHandle.argtypes = [vp]
        self.k32.CloseHandle.restype = ctypes.c_int
        self.adv.SetSecurityInfo.argtypes = [vp, ctypes.c_int, u32, vp, vp, vp, vp]
        self.adv.SetSecurityInfo.restype = u32
        self.adv.GetSecurityDescriptorDacl.argtypes = [
            vp,
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(vp),
            ctypes.POINTER(ctypes.c_int),
        ]
        self.adv.GetSecurityDescriptorDacl.restype = ctypes.c_int

    def create_instance(self, name: str, *, first: bool, sddl: str | None, write_dac: bool) -> int:
        """CreateNamedPipeW as the daemon (or an impostor) would. Returns the handle or 0."""
        flags = _PIPE_ACCESS_DUPLEX
        if first:
            flags |= _FILE_FLAG_FIRST_PIPE_INSTANCE
        if write_dac:
            flags |= _WRITE_DAC
        if sddl is None:
            handle = self.k32.CreateNamedPipeW(
                name, flags, _PIPE_REJECT_REMOTE_CLIENTS, 255, 4096, 4096, 0, None
            )
            error = int(ctypes.get_last_error())
        else:
            with winsec.SecurityDescriptor.from_sddl(sddl) as descriptor:
                handle = self.k32.CreateNamedPipeW(
                    name,
                    flags,
                    _PIPE_REJECT_REMOTE_CLIENTS,
                    255,
                    4096,
                    4096,
                    0,
                    ctypes.byref(descriptor.attributes),
                )
                error = int(ctypes.get_last_error())
        if not handle or handle == _INVALID:
            self.create_error = error
            return 0
        self.create_error = 0
        return int(handle)

    def open_client(self, name: str, access: int) -> tuple[int, int]:
        """CreateFileW on the pipe with exactly ``access``: (handle or 0, win32 error)."""
        handle = self.k32.CreateFileW(
            name, access, _FILE_SHARE_READ_WRITE, None, _OPEN_EXISTING, 0, None
        )
        if not handle or handle == _INVALID:
            return 0, int(ctypes.get_last_error())
        return int(handle), 0

    def set_dacl(self, handle: int, sddl: str) -> int:
        """SetSecurityInfo(DACL) from SDDL on a handle. Returns the Win32 status (0 = success)."""
        with winsec.SecurityDescriptor.from_sddl(sddl) as descriptor:
            present = ctypes.c_int(0)
            acl = ctypes.c_void_p()
            defaulted = ctypes.c_int(0)
            assert self.adv.GetSecurityDescriptorDacl(
                descriptor.address,
                ctypes.byref(present),
                ctypes.byref(acl),
                ctypes.byref(defaulted),
            )
            return int(
                self.adv.SetSecurityInfo(
                    handle, _SE_KERNEL_OBJECT, _DACL_SECURITY_INFORMATION, None, None, acl, None
                )
            )

    def close(self, handle: int) -> None:
        if handle:
            self.k32.CloseHandle(handle)


class _Outcome:
    """What the three-call undo achieved, step by step."""

    def __init__(self) -> None:
        self.open_write_dac_error = 0  # 0 = the open succeeded
        self.set_dacl_status: int | None = None  # None = step not reached
        self.new_instance_created = False


def _three_call_undo(win: _Win32, name: str) -> _Outcome:
    """The re-review's attack: WRITE_DAC open, DACL back to FILE_ALL_ACCESS, create an instance."""
    outcome = _Outcome()
    handle, error = win.open_client(name, _WRITE_DAC)
    outcome.open_write_dac_error = error
    if not handle:
        return outcome
    try:
        regrant = f"D:(A;;FA;;;{winsec.current_user_sid()})"
        outcome.set_dacl_status = win.set_dacl(handle, regrant)
    finally:
        win.close(handle)
    if outcome.set_dacl_status == 0:
        impostor = win.create_instance(name, first=False, sddl=None, write_dac=False)
        outcome.new_instance_created = bool(impostor)
        win.close(impostor)
    return outcome


def _new_name() -> str:
    return "\\\\.\\pipe\\bk-r3-dacl-" + os.urandom(8).hex()


@contextlib.contextmanager
def _one_off_pipe(win: _Win32, *, instances: int = 2) -> Iterator[tuple[str, list[int]]]:
    """A pipe made by the test with the daemon's creation flags (private DACL, WRITE_DAC)."""
    name = _new_name()
    handles: list[int] = []
    try:
        for index in range(instances):
            handle = win.create_instance(
                name, first=index == 0, sddl=winsec.private_sddl(), write_dac=True
            )
            assert handle, f"cannot create the one-off pipe instance {index}"
            handles.append(handle)
        yield name, handles
    finally:
        for handle in handles:
            win.close(handle)


@pytest.fixture
def win() -> _Win32:
    return _Win32()


# --- 1. the reproduction, then the fix ------------------------------------------------------


def test_reproduction_the_round1_dacl_is_undone_by_its_owner_with_three_calls(win: _Win32) -> None:
    """BEFORE: the round-1 DACL blocks the direct attack but not WRITE_DAC -> re-grant -> create."""
    with _one_off_pipe(win) as (name, handles):
        for handle in handles:
            assert win.set_dacl(handle, _round1_sddl()) == 0
        # the direct attack of review H-2 is refused ...
        assert not win.create_instance(name, first=False, sddl=None, write_dac=False)
        assert win.create_error == _ERROR_ACCESS_DENIED
        # ... but the owner holds WRITE_DAC implicitly, so three calls defeat it
        outcome = _three_call_undo(win, name)
        assert outcome.open_write_dac_error == 0, "the owner could not open with WRITE_DAC"
        assert outcome.set_dacl_status == 0
        assert outcome.new_instance_created, "the defence was not undone"


def test_after_the_fix_the_owner_cannot_open_the_pipe_with_write_dac(win: _Win32) -> None:
    """AFTER: the same one-off pipe, tightened by winsec.forbid_new_pipe_instances."""
    with _one_off_pipe(win) as (name, handles):
        for handle in handles:
            winsec.forbid_new_pipe_instances(handle)
        outcome = _three_call_undo(win, name)
        assert outcome.open_write_dac_error == _ERROR_ACCESS_DENIED
        assert outcome.set_dacl_status is None
        assert not outcome.new_instance_created
        # the direct attack is still refused
        assert not win.create_instance(name, first=False, sddl=None, write_dac=False)
        assert win.create_error == _ERROR_ACCESS_DENIED
        assert not win.create_instance(
            name, first=False, sddl=winsec.private_sddl(), write_dac=False
        )
        assert win.create_error == _ERROR_ACCESS_DENIED


@pytest.mark.parametrize("access", [_WRITE_DAC, _WRITE_OWNER, _WRITE_DAC | _WRITE_OWNER, 0x1F01FF])
def test_after_the_fix_no_right_to_rewrite_the_security_can_be_opened(
    win: _Win32, access: int
) -> None:
    with _one_off_pipe(win) as (name, handles):
        for handle in handles:
            winsec.forbid_new_pipe_instances(handle)
        opened, error = win.open_client(name, access)
        win.close(opened)
        assert (opened, error) == (0, _ERROR_ACCESS_DENIED)


def test_after_the_fix_the_dacl_is_the_client_ace_plus_a_read_only_owner_rights_ace(
    win: _Win32,
) -> None:
    with _one_off_pipe(win) as (name, handles):
        for handle in handles:
            winsec.forbid_new_pipe_instances(handle)
        acl = winsec.read_acl_of_pipe(name)  # READ_CONTROL still works
        assert acl.dacl_present
        assert acl.dacl_protected
        by_sid = {ace.sid: ace for ace in acl.aces}
        assert set(by_sid) == {winsec.current_user_sid(), winsec.OWNER_RIGHTS_SID}
        assert len(acl.aces) == 2
        assert all(ace.allowed and not ace.inherited for ace in acl.aces)
        assert by_sid[winsec.OWNER_RIGHTS_SID].mask == _READ_CONTROL
        user_mask = by_sid[winsec.current_user_sid()].mask
        assert user_mask == winsec.PIPE_CLIENT_ACCESS_MASK
        assert not user_mask & winsec.FILE_CREATE_PIPE_INSTANCE
        assert not user_mask & (_WRITE_DAC | _WRITE_OWNER)


def test_the_sddl_carries_exactly_the_two_expected_entries() -> None:
    sddl = winsec.pipe_clients_only_sddl()
    assert sddl == f"D:P(A;;0x12019B;;;{winsec.current_user_sid()})(A;;0x20000;;;OW)"


def test_a_failed_tightening_leaves_the_old_dacl_and_raises(win: _Win32) -> None:
    """Fail closed: a handle without WRITE_DAC cannot be tightened, and that is an OSError."""
    name = _new_name()
    handle = win.create_instance(name, first=True, sddl=winsec.private_sddl(), write_dac=False)
    assert handle
    try:
        with pytest.raises(PermissionError):  # ERROR_ACCESS_DENIED: no WRITE_DAC on the handle
            winsec.forbid_new_pipe_instances(handle)
        acl = winsec.read_acl_of_pipe(name)
        assert [ace.sid for ace in acl.aces] == [winsec.current_user_sid()]
    finally:
        win.close(handle)


# --- 2. the daemon's own server side keeps working ------------------------------------------


async def _echo(line: bytes) -> bytes:
    request = protocol.decode_request(line)
    return protocol.encode_response(request.request_id, decision="ask", reason="ok")


@contextlib.asynccontextmanager
async def _serving(
    handler: Callable[[bytes], Awaitable[bytes]] = _echo, **options: Any
) -> AsyncIterator[NamedPipeServer]:
    server = NamedPipeServer(_new_name(), handler, **options)
    await server.start()
    try:
        yield server
    finally:
        await server.close()


def _run(coro: Awaitable[None]) -> None:
    asyncio.run(coro)  # type: ignore[arg-type]


def test_the_daemons_pipe_defeats_the_three_call_undo(win: _Win32) -> None:
    async def scenario() -> None:
        async with _serving() as server:
            outcome = await asyncio.get_running_loop().run_in_executor(
                None, _three_call_undo, win, server.address
            )
            assert outcome.open_write_dac_error == _ERROR_ACCESS_DENIED
            assert not outcome.new_instance_created

    _run(scenario())


def test_the_server_keeps_serving_after_a_failed_undo_attempt(win: _Win32) -> None:
    """The refused WRITE_DAC open must not connect to (and so burn) an instance."""

    async def scenario() -> None:
        async with _serving(instances=1) as server:
            loop = asyncio.get_running_loop()
            endpoint = ipc_endpoint.Endpoint(ipc_endpoint.TRANSPORT_NAMED_PIPE, server.address)
            for _ in range(3):
                outcome = await loop.run_in_executor(None, _three_call_undo, win, server.address)
                assert outcome.open_write_dac_error == _ERROR_ACCESS_DENIED
            for i in range(5):
                rid = f"r{i}"
                line = protocol.encode_request(protocol.EVENT_PRE, {"i": i}, rid)
                answer = await loop.run_in_executor(
                    None, lambda line=line: ipc_client.call(endpoint, line, timeout_s=10)
                )
                assert protocol.decode_response(answer, rid).ok

    _run(scenario())


def test_the_daemons_dacl_is_readable_and_the_pool_recycles_after_the_probe() -> None:
    """doctor's probe (READ_CONTROL) works, and the worker recycles the instance it connected."""

    async def scenario() -> None:
        async with _serving(instances=2) as server:
            loop = asyncio.get_running_loop()
            endpoint = ipc_endpoint.Endpoint(ipc_endpoint.TRANSPORT_NAMED_PIPE, server.address)
            for i in range(10):
                acl = await loop.run_in_executor(None, winsec.read_acl_of_pipe, server.address)
                assert {ace.sid for ace in acl.aces} == {
                    winsec.current_user_sid(),
                    winsec.OWNER_RIGHTS_SID,
                }
                rid = f"p{i}"
                line = protocol.encode_request(protocol.EVENT_PRE, {"i": i}, rid)
                answer = await loop.run_in_executor(
                    None, lambda line=line: ipc_client.call(endpoint, line, timeout_s=10)
                )
                assert protocol.decode_response(answer, rid).ok

    _run(scenario())


def test_a_taken_name_is_address_in_use_and_a_stopped_name_can_be_served_again() -> None:
    from boundkeep.ipc.base import AddressInUse

    async def scenario() -> None:
        async with _serving() as server:
            with pytest.raises(AddressInUse):
                await NamedPipeServer(server.address, _echo).start()
        again = NamedPipeServer(server.address, _echo)
        await again.start()
        await again.close()

    _run(scenario())
