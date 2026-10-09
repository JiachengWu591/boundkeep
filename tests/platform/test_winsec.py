"""Windows ACL helpers: build private descriptors, read ACLs back, prove pipes and dirs are private.

Everything here runs on tmp_path directories or on pipes created by the test itself. Every handle
the tests open is closed in a ``finally``.
"""

from __future__ import annotations

import ctypes
import gc
import importlib.util
import os
import re
import struct
import subprocess
import sys
import uuid
import weakref
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from boundkeep import fsperm
from boundkeep.ipc import winsec

pytestmark = pytest.mark.windows

SID_RE = re.compile(r"^S-1-\d+(-\d+)+$")
TRUSTED = {
    winsec.SYSTEM_SID,
    winsec.ADMINISTRATORS_SID,
    winsec.CREATOR_OWNER_SID,
    winsec.OWNER_RIGHTS_SID,
}

PIPE_ACCESS_DUPLEX = 0x3
PIPE_REJECT_REMOTE_CLIENTS = 0x8
FILE_READ_DATA = 0x1


# --- tiny ctypes layer for the pipe tests (explicit signatures: no pointer truncation) ------


def _k32() -> ctypes.WinDLL:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateNamedPipeW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(winsec.SECURITY_ATTRIBUTES),
    ]
    k32.CreateNamedPipeW.restype = ctypes.c_void_p
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    k32.CloseHandle.restype = ctypes.c_int
    k32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.GetCurrentProcess.argtypes = []
    k32.GetCurrentProcess.restype = ctypes.c_void_p
    k32.GetProcessHandleCount.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    k32.GetProcessHandleCount.restype = ctypes.c_int
    return k32


def _handle_count() -> int:
    """Number of kernel handles this process holds right now."""
    k32 = _k32()
    count = ctypes.c_uint32(0)
    assert k32.GetProcessHandleCount(k32.GetCurrentProcess(), ctypes.byref(count))
    return count.value


@contextmanager
def _pipe(
    attributes: winsec.SECURITY_ATTRIBUTES | None,
    *,
    instances: int = 2,
) -> Iterator[str]:
    """A throw-away local named pipe with the given security attributes (None = default).

    ``instances`` server instances are created (and the pipe allows exactly that many).
    """
    k32 = _k32()
    name = "\\\\.\\pipe\\boundkeep-test-" + uuid.uuid4().hex
    handles: list[int] = []
    try:
        for _ in range(instances):
            handle = k32.CreateNamedPipeW(
                name,
                PIPE_ACCESS_DUPLEX,
                PIPE_REJECT_REMOTE_CLIENTS,
                instances,
                4096,
                4096,
                0,
                None if attributes is None else ctypes.byref(attributes),
            )
            if handle is None or handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            handles.append(handle)
        yield name
    finally:
        for handle in handles:
            k32.CloseHandle(handle)


def _icacls(*args: str) -> None:
    exe = os.path.join(os.environ["SYSTEMROOT"], "System32", "icacls.exe")
    result = subprocess.run([exe, *args], capture_output=True, check=False)
    assert result.returncode == 0, result.stdout[-300:] + result.stderr[-300:]


def _sids(acl: winsec.AclInfo) -> set[str]:
    return {a.sid for a in acl.aces}


# --- platform neutrality --------------------------------------------------------------------


def test_constants_are_the_well_known_sids() -> None:
    assert winsec.WORLD_SID == "S-1-1-0"
    assert winsec.ANONYMOUS_SID == "S-1-5-7"
    assert winsec.AUTHENTICATED_USERS_SID == "S-1-5-11"
    assert winsec.BUILTIN_USERS_SID == "S-1-5-32-545"
    assert winsec.SYSTEM_SID == "S-1-5-18"
    assert winsec.ADMINISTRATORS_SID == "S-1-5-32-544"
    assert winsec.CREATOR_OWNER_SID == "S-1-3-0"


def _every_windows_call(
    descriptor: winsec.SecurityDescriptor,
) -> dict[str, Callable[[], object]]:
    """One call per public function that talks to Windows (arguments are valid on purpose)."""
    return {
        "current_user_sid": winsec.current_user_sid,
        "private_sddl": winsec.private_sddl,
        "from_sddl": lambda: winsec.SecurityDescriptor.from_sddl("D:P"),
        "SecurityDescriptor.private": winsec.SecurityDescriptor.private,
        "describe_descriptor": lambda: winsec.describe_descriptor(descriptor),
        "read_acl_of_path": lambda: winsec.read_acl_of_path("x"),
        "read_acl_of_pipe": lambda: winsec.read_acl_of_pipe("\\\\.\\pipe\\x"),
        "set_private_acl": lambda: winsec.set_private_acl("x"),
    }


@pytest.mark.parametrize(
    "name",
    [
        "current_user_sid",
        "private_sddl",
        "from_sddl",
        "SecurityDescriptor.private",
        "describe_descriptor",
        "read_acl_of_path",
        "read_acl_of_pipe",
        "set_private_acl",
    ],
)
def test_every_call_fails_with_oserror_when_not_windows(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A descriptor object that points nowhere. Its address is reset below, so nothing here can
    # hand a bogus pointer to the real LocalFree.
    descriptor = winsec.SecurityDescriptor(1)
    try:
        call = _every_windows_call(descriptor)[name]
        monkeypatch.setattr(sys, "platform", "linux")
        with pytest.raises(OSError, match="Windows only"):
            call()
    finally:
        descriptor._address = None


def test_module_imports_and_stays_inert_when_not_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    # POSIX test runs import this module: loading a fresh copy while sys.platform says "linux" must
    # work, and only the calls into Windows may fail.
    spec = importlib.util.spec_from_file_location("winsec_as_linux", winsec.__file__)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "winsec_as_linux", module)  # dataclasses needs it
    spec.loader.exec_module(module)
    assert module.WORLD_SID == winsec.WORLD_SID
    assert module.AclInfo(None, False, False, (), "").dacl_present is False
    with pytest.raises(OSError, match="Windows only"):
        module.current_user_sid()


# --- SIDs and SDDL --------------------------------------------------------------------------


def test_current_user_sid_format_and_stability() -> None:
    sid = winsec.current_user_sid()
    assert SID_RE.match(sid)
    assert sid not in {winsec.WORLD_SID, winsec.SYSTEM_SID, winsec.ANONYMOUS_SID}
    assert winsec.current_user_sid() == sid


def test_private_sddl_shape() -> None:
    sid = winsec.current_user_sid()
    assert winsec.private_sddl() == f"D:P(A;;GA;;;{sid})"
    assert winsec.private_sddl(include_system=True) == f"D:P(A;;GA;;;{sid})(A;;GA;;;SY)"


# --- SecurityDescriptor lifecycle -----------------------------------------------------------


def test_descriptor_attributes_shape() -> None:
    with winsec.SecurityDescriptor.private() as sd:
        attrs = sd.attributes
        assert isinstance(attrs, winsec.SECURITY_ATTRIBUTES)
        assert attrs.nLength == ctypes.sizeof(winsec.SECURITY_ATTRIBUTES)
        assert attrs.lpSecurityDescriptor == sd.address
        assert attrs.bInheritHandle == 0


def test_descriptor_close_twice_and_use_after_close() -> None:
    sd = winsec.SecurityDescriptor.private()
    sd.close()
    sd.close()
    with pytest.raises(ValueError, match="closed"):
        _ = sd.attributes
    with pytest.raises(ValueError, match="closed"):
        _ = sd.address


def test_descriptor_context_manager_closes() -> None:
    with winsec.SecurityDescriptor.private(include_system=True) as sd:
        assert sd.address
    with pytest.raises(ValueError, match="closed"):
        _ = sd.attributes


def test_descriptor_del_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    sd = winsec.SecurityDescriptor.private()
    sd.close()
    sd.__del__()  # already closed: nothing to do

    live = winsec.SecurityDescriptor.private()

    def failing_close(self: winsec.SecurityDescriptor) -> None:
        raise RuntimeError("close blew up")

    with monkeypatch.context() as patched:
        patched.setattr(winsec.SecurityDescriptor, "close", failing_close)
        live.__del__()  # a destructor must swallow whatever close() raises
    live.close()  # the real close still works, so nothing leaks from this test


def test_descriptor_del_on_a_half_built_object_never_raises() -> None:
    broken = winsec.SecurityDescriptor.__new__(winsec.SecurityDescriptor)  # __init__ never ran
    broken.__del__()


def test_attributes_keep_the_descriptor_alive() -> None:
    sd = winsec.SecurityDescriptor.private()
    watcher = weakref.ref(sd)
    attrs = sd.attributes
    address = attrs.lpSecurityDescriptor
    del sd
    gc.collect()
    assert watcher() is not None, "the attributes must keep their descriptor alive"
    assert attrs.lpSecurityDescriptor == address
    del attrs
    gc.collect()
    assert watcher() is None


def test_attributes_never_become_null_after_close() -> None:
    # A NULL lpSecurityDescriptor means "default security": Everyone and Anonymous may read it.
    sd = winsec.SecurityDescriptor.private()
    first, second = sd.attributes, sd.attributes
    assert first is not second
    live_address = first.lpSecurityDescriptor
    sd.close()
    for attrs in (first, second):
        assert attrs.lpSecurityDescriptor is not None
        assert attrs.lpSecurityDescriptor != 0
        assert attrs.lpSecurityDescriptor != live_address
        assert attrs.nLength == ctypes.sizeof(winsec.SECURITY_ATTRIBUTES)
        assert attrs.bInheritHandle == 0


def test_pipe_from_a_temporary_descriptor_is_still_private() -> None:
    # The classic mistake: the descriptor is dropped (and its destructor runs) right away.
    attrs = winsec.SecurityDescriptor.private().attributes
    gc.collect()
    with _pipe(attrs) as name:
        acl = winsec.read_acl_of_pipe(name)
    assert [(a.sid, a.allowed) for a in acl.aces] == [(winsec.current_user_sid(), True)]
    assert winsec.WORLD_SID not in _sids(acl)
    assert winsec.ANONYMOUS_SID not in _sids(acl)


def test_pipe_from_attributes_of_a_closed_descriptor_fails_instead_of_going_public() -> None:
    sd = winsec.SecurityDescriptor.private()
    attrs = sd.attributes
    sd.close()
    with pytest.raises(OSError) as raised, _pipe(attrs):  # noqa: PT011
        pytest.fail("a pipe was created from the attributes of a closed descriptor")
    assert raised.value.winerror == 1305  # ERROR_REVISION_MISMATCH: the poisoned descriptor


def test_pipe_from_attributes_used_after_the_with_block_fails() -> None:
    with winsec.SecurityDescriptor.private() as sd:
        attrs = sd.attributes
        with _pipe(attrs) as name:  # inside the block it works and is private
            assert winsec.WORLD_SID not in _sids(winsec.read_acl_of_pipe(name))
    with pytest.raises(OSError), _pipe(attrs):  # noqa: PT011
        pytest.fail("a pipe was created from stale attributes")


@pytest.mark.parametrize("bad", ["not sddl", "D:P(A;;GA;;;ZZZZ)", "D:(A;;GA;;;S-1-1-0", "O:"])
def test_from_sddl_rejects_garbage(bad: str) -> None:
    # No `match`: the message is the localized Windows error text.
    with pytest.raises(OSError):  # noqa: PT011
        winsec.SecurityDescriptor.from_sddl(bad)


@pytest.mark.parametrize("empty", ["", "   ", "\n"])
def test_from_sddl_rejects_empty(empty: str) -> None:
    # An empty SDDL would convert to a descriptor without a DACL: everybody has full access.
    with pytest.raises(ValueError, match="empty"):
        winsec.SecurityDescriptor.from_sddl(empty)


def test_from_sddl_rejects_embedded_nul() -> None:
    with pytest.raises(ValueError, match="NUL"):
        winsec.SecurityDescriptor.from_sddl("D:P\0(A;;GA;;;WD)")


def test_private_descriptor_reads_back_as_private() -> None:
    sid = winsec.current_user_sid()
    with winsec.SecurityDescriptor.private(include_system=True) as sd:
        acl = winsec.describe_descriptor(sd)
    assert acl.dacl_present
    assert acl.dacl_protected
    assert _sids(acl) == {sid, winsec.SYSTEM_SID}
    assert all(a.allowed and not a.inherited for a in acl.aces)
    assert "D:P" in acl.sddl


def test_null_dacl_is_detected_not_confused_with_empty_or_private() -> None:
    # "D:NO_ACCESS_CONTROL" is SDDL for a NULL DACL: everybody has full access.
    with winsec.SecurityDescriptor.from_sddl("D:NO_ACCESS_CONTROL") as sd:
        null_acl = winsec.describe_descriptor(sd)
    assert null_acl.dacl_present is False
    assert null_acl.aces == ()

    # "D:P" with no ACEs is an EMPTY DACL: present, nobody has access.
    with winsec.SecurityDescriptor.from_sddl("D:P") as sd:
        empty_acl = winsec.describe_descriptor(sd)
    assert empty_acl.dacl_present is True
    assert empty_acl.aces == ()

    with winsec.SecurityDescriptor.private() as sd:
        assert winsec.describe_descriptor(sd).dacl_present is True


def test_null_dacl_is_an_error_in_check_private() -> None:
    null_acl = winsec.AclInfo(None, False, False, (), "D:NO_ACCESS_CONTROL")
    problems = fsperm._problems_from_acl("x", null_acl, winsec.current_user_sid())
    assert [p.severity for p in problems] == ["error"]
    assert "S-1-1-0" in problems[0].message


def test_unknown_sid_gets_no_name_but_read_still_works() -> None:
    # A well-formed SID that no account has: the lookup fails, the read must not.
    unknown = "S-1-5-21-111111111-222222222-333333333-999999"
    with winsec.SecurityDescriptor.from_sddl(f"D:P(A;;GA;;;{unknown})") as sd:
        acl = winsec.describe_descriptor(sd)
    assert [(a.sid, a.name) for a in acl.aces] == [(unknown, None)]


def test_account_names_resolve_for_well_known_sids() -> None:
    with winsec.SecurityDescriptor.from_sddl("D:P(A;;GR;;;WD)(A;;GR;;;SY)") as sd:
        acl = winsec.describe_descriptor(sd)
    by_sid = {a.sid: a.name for a in acl.aces}
    assert by_sid[winsec.WORLD_SID]
    assert by_sid[winsec.SYSTEM_SID]


def test_deny_and_inherited_flags_are_parsed() -> None:
    with winsec.SecurityDescriptor.from_sddl("D:P(D;;GW;;;BG)(A;ID;GR;;;SY)") as sd:
        acl = winsec.describe_descriptor(sd)
    deny, allow = acl.aces
    assert (deny.sid, deny.allowed, deny.inherited) == ("S-1-5-32-546", False, False)
    assert (allow.sid, allow.allowed, allow.inherited) == (winsec.SYSTEM_SID, True, True)


# --- reading and writing file ACLs ----------------------------------------------------------


def test_fresh_tmp_dir_has_only_trusted_principals(tmp_path: Path) -> None:
    acl = winsec.read_acl_of_path(str(tmp_path))
    assert acl.dacl_present
    allowed = {a.sid for a in acl.aces if a.allowed}
    assert allowed <= {winsec.current_user_sid(), *TRUSTED}, acl.sddl
    assert acl.owner_sid is not None
    assert [p for p in fsperm.check_private(str(tmp_path)) if p.severity == "error"] == []

    # pytest creates tmp_path with mkdir(mode=0o700), which on Python 3.12.4+ gives it a protected
    # ACL. A plain mkdir inside it inherits that ACL: unprotected, inherited, trusted only.
    plain = tmp_path / "plain"
    plain.mkdir()
    inherited = winsec.read_acl_of_path(str(plain))
    assert inherited.aces
    assert not inherited.dacl_protected
    assert all(a.inherited for a in inherited.aces)
    assert {a.sid for a in inherited.aces if a.allowed} <= {winsec.current_user_sid(), *TRUSTED}
    problems = fsperm.check_private(str(plain))
    assert [p.severity for p in problems] == ["warning"]
    assert "inherits" in problems[0].message


def test_set_private_acl_on_directory(tmp_path: Path) -> None:
    sid = winsec.current_user_sid()
    target = tmp_path / "private"
    target.mkdir()
    winsec.set_private_acl(str(target))
    acl = winsec.read_acl_of_path(str(target))
    assert acl.dacl_present
    assert acl.dacl_protected
    assert _sids(acl) == {sid, winsec.SYSTEM_SID}
    assert all(a.allowed and not a.inherited for a in acl.aces)
    # Inheritable (OI + CI) so that files created inside later are private too.
    assert "OICI" in acl.sddl
    assert fsperm.check_private(str(target)) == []

    child = target / "created-later.txt"
    child.write_text("x", encoding="utf-8")
    child_acl = winsec.read_acl_of_path(str(child))
    assert _sids(child_acl) == {sid, winsec.SYSTEM_SID}
    assert all(a.inherited for a in child_acl.aces)
    assert fsperm.check_private(str(child)) == []


def test_set_private_acl_without_system(tmp_path: Path) -> None:
    target = tmp_path / "me-only"
    target.mkdir()
    winsec.set_private_acl(str(target), include_system=False)
    assert _sids(winsec.read_acl_of_path(str(target))) == {winsec.current_user_sid()}


def test_set_private_acl_on_file_is_not_inheritable(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_text("x", encoding="utf-8")
    winsec.set_private_acl(str(f))
    acl = winsec.read_acl_of_path(str(f))
    assert acl.dacl_protected
    assert _sids(acl) == {winsec.current_user_sid(), winsec.SYSTEM_SID}
    assert "OICI" not in acl.sddl


def test_set_private_acl_is_idempotent(tmp_path: Path) -> None:
    target = tmp_path / "d"
    target.mkdir()
    winsec.set_private_acl(str(target))
    first = winsec.read_acl_of_path(str(target))
    winsec.set_private_acl(str(target))
    assert winsec.read_acl_of_path(str(target)) == first


def test_set_private_acl_removes_an_everyone_grant(tmp_path: Path) -> None:
    target = tmp_path / "d"
    target.mkdir()
    _icacls(str(target), "/grant", "*S-1-1-0:(OI)(CI)R")
    assert winsec.WORLD_SID in _sids(winsec.read_acl_of_path(str(target)))
    winsec.set_private_acl(str(target))
    assert winsec.WORLD_SID not in _sids(winsec.read_acl_of_path(str(target)))


def test_everyone_grant_makes_check_private_report_an_error(tmp_path: Path) -> None:
    target = tmp_path / "shared"
    target.mkdir()
    # *S-1-1-0 is the SID form: independent of the Windows display language.
    _icacls(str(target), "/grant", "*S-1-1-0:(OI)(CI)R")
    acl = winsec.read_acl_of_path(str(target))
    everyone = [a for a in acl.aces if a.sid == winsec.WORLD_SID]
    assert everyone
    assert everyone[0].allowed
    assert everyone[0].mask & FILE_READ_DATA
    assert not everyone[0].inherited

    problems = fsperm.check_private(str(target))
    errors = [p for p in problems if p.severity == "error"]
    assert errors
    assert any("S-1-1-0" in p.message and "Everyone" in p.message for p in errors)


def test_read_acl_of_nonexistent_path(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        winsec.read_acl_of_path(str(tmp_path / "nope"))
    with pytest.raises(FileNotFoundError):
        winsec.set_private_acl(str(tmp_path / "nope"))


@pytest.mark.parametrize(
    "name", ["with space", "含中文 目录", "trailing.dot.dir", "uni-\u00e9\u00e8"]
)
def test_paths_with_spaces_and_non_ascii(tmp_path: Path, name: str) -> None:
    target = tmp_path / name
    target.mkdir()
    winsec.set_private_acl(str(target))
    acl = winsec.read_acl_of_path(str(target))
    assert _sids(acl) == {winsec.current_user_sid(), winsec.SYSTEM_SID}
    assert fsperm.check_private(str(target)) == []
    inner = target / "文件 1.txt"
    inner.write_text("x", encoding="utf-8")
    assert fsperm.check_private(str(inner)) == []


# --- named pipes ----------------------------------------------------------------------------


def test_pipe_with_private_descriptor_shows_only_the_current_user() -> None:
    with winsec.SecurityDescriptor.private() as sd, _pipe(sd.attributes) as name:
        acl = winsec.read_acl_of_pipe(name)
    assert acl.dacl_present
    assert [(a.sid, a.allowed) for a in acl.aces] == [(winsec.current_user_sid(), True)]
    assert winsec.WORLD_SID not in _sids(acl)
    assert winsec.ANONYMOUS_SID not in _sids(acl)


def test_pipe_with_null_security_attributes_grants_everyone_read() -> None:
    # The M0a finding (docs/hook-behavior.md E10): the default DACL of a pipe created without
    # explicit security attributes lets Everyone read it. This is why the explicit DACL exists.
    with _pipe(None) as name:
        acl = winsec.read_acl_of_pipe(name)
    everyone = [a for a in acl.aces if a.sid == winsec.WORLD_SID and a.allowed]
    assert everyone, acl.sddl
    assert everyone[0].mask & FILE_READ_DATA


def test_read_acl_of_pipe_rejects_non_pipe_paths_and_missing_pipes() -> None:
    with pytest.raises(ValueError, match="named pipe"):
        winsec.read_acl_of_pipe("C:\\Windows")
    with pytest.raises(ValueError, match="named pipe"):
        winsec.read_acl_of_pipe("\\\\server\\pipe\\x")
    with pytest.raises(FileNotFoundError):
        winsec.read_acl_of_pipe("\\\\.\\pipe\\boundkeep-test-does-not-exist-" + uuid.uuid4().hex)


def test_pipe_attributes_do_not_depend_on_the_descriptor_object_surviving() -> None:
    # Same pattern as a daemon that keeps only the attributes for creating further pipe instances.
    attrs = winsec.SecurityDescriptor.private(include_system=True).attributes
    gc.collect()
    with _pipe(attrs, instances=3) as name:
        acl = winsec.read_acl_of_pipe(name)
    assert _sids(acl) == {winsec.current_user_sid(), winsec.SYSTEM_SID}


def test_read_acl_of_pipe_reports_busy_when_every_instance_is_connected() -> None:
    k32 = _k32()
    with winsec.SecurityDescriptor.private() as sd, _pipe(sd.attributes, instances=1) as name:
        client = k32.CreateFileW(name, 0xC0000000, 0, None, 3, 0, None)  # GENERIC_READ | WRITE
        assert client not in (None, ctypes.c_void_p(-1).value)
        try:
            with pytest.raises(OSError) as raised:  # noqa: PT011
                winsec.read_acl_of_pipe(name)
            assert raised.value.winerror == 231  # ERROR_PIPE_BUSY: callers treat it as "busy"
        finally:
            k32.CloseHandle(client)


# --- hostile paths and pipe names -----------------------------------------------------------


def test_path_functions_reject_a_nul_and_change_nothing(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.mkdir()
    before = winsec.read_acl_of_path(str(victim))
    for hostile in (str(victim) + "\0junk", "\0" + str(victim), str(victim) + "\0"):
        with pytest.raises(ValueError, match="NUL"):
            winsec.read_acl_of_path(hostile)
        with pytest.raises(ValueError, match="NUL"):
            winsec.set_private_acl(hostile)
        with pytest.raises(ValueError, match="NUL"):
            winsec.set_private_acl(hostile, include_system=False)
    # c_wchar_p would have truncated at the NUL and rewritten the real directory's ACL.
    assert winsec.read_acl_of_path(str(victim)) == before
    with pytest.raises(ValueError, match="NUL"):
        winsec.read_acl_of_pipe("\\\\.\\pipe\\boundkeep\0x")


def test_path_functions_reject_bytes(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        winsec.read_acl_of_path(os.fsencode(tmp_path))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        winsec.set_private_acl(os.fsencode(tmp_path))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        winsec.read_acl_of_pipe(b"\\\\.\\pipe\\x")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        winsec.read_acl_of_path(42)  # type: ignore[arg-type]


def test_path_functions_accept_pathlike(tmp_path: Path) -> None:
    target = tmp_path / "pathlike"
    target.mkdir()
    winsec.set_private_acl(target)
    assert winsec.read_acl_of_path(target) == winsec.read_acl_of_path(str(target))
    assert _sids(winsec.read_acl_of_path(target)) == {winsec.current_user_sid(), winsec.SYSTEM_SID}


@pytest.mark.parametrize(
    "bad",
    [
        "\\\\.\\pipe\\",
        "\\\\.\\pipe\\..",
        "\\\\.\\pipe\\.",
        "\\\\.\\pipe\\..\\C:\\Windows\\System32\\notepad.exe",
        "\\\\.\\pipe\\a\\b",
        "\\\\.\\pipe\\a/b",
        "\\\\.\\pipe\\a\\",
        "//./pipe/x",
        "\\\\.\\PIPE",
        "pipe\\x",
        "",
    ],
)
def test_read_acl_of_pipe_accepts_only_a_single_pipe_name_component(bad: str) -> None:
    with pytest.raises(ValueError, match="named pipe"):
        winsec.read_acl_of_pipe(bad)


def test_read_acl_of_pipe_refuses_a_handle_that_is_not_a_pipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Backstop behind the name check: even if a name slips through, only FILE_TYPE_PIPE is read.
    # Win32 normalizes ".." in \\.\ paths, so this name really opens the file.
    plain = tmp_path / "not-a-pipe.txt"
    plain.write_text("x", encoding="utf-8")
    sneaky = "\\\\.\\pipe\\..\\" + str(plain)
    monkeypatch.setattr(winsec, "_pipe_arg", lambda name: str(name))
    before = _handle_count()
    with pytest.raises(OSError, match="not a named pipe"):
        winsec.read_acl_of_pipe(sneaky)
    assert _handle_count() - before <= 1  # the handle that was opened is closed again


# --- ACE parsing (fail-closed branches and the object / callback layouts) -------------------


def _sid_bytes(authority: int, *subauthorities: int) -> bytes:
    head = struct.pack("BB", 1, len(subauthorities)) + authority.to_bytes(6, "big")
    return head + b"".join(struct.pack("<I", s) for s in subauthorities)


EVERYONE = _sid_bytes(1, 0)
GUID = bytes(range(16))


def _ace_bytes(
    ace_type: int,
    sid: bytes = EVERYONE,
    *,
    flags: int = 0,
    mask: int = 0x1F01FF,
    object_flags: int | None = None,
    trailer: bytes = b"",
) -> bytes:
    body = struct.pack("<I", mask)
    if object_flags is not None:
        body += struct.pack("<I", object_flags)
        body += GUID * bin(object_flags).count("1")
    body += sid + trailer
    return struct.pack("<BBH", ace_type, flags, 4 + len(body)) + body


@pytest.mark.parametrize(("ace_type", "allowed"), [(0, True), (1, False), (9, True), (10, False)])
def test_parse_plain_and_callback_aces(ace_type: int, allowed: bool) -> None:
    raw = _ace_bytes(ace_type, flags=0x10, mask=0x120089, trailer=b"\x61\x72\x74\x78")
    layout = winsec._parse_ace(raw, 0)
    assert layout.allowed is allowed
    assert layout.mask == 0x120089
    assert layout.flags == 0x10
    assert layout.sid_offset == 8
    assert raw[layout.sid_offset : layout.sid_offset + len(EVERYONE)] == EVERYONE


@pytest.mark.parametrize(("ace_type", "allowed"), [(5, True), (6, False), (11, True), (12, False)])
@pytest.mark.parametrize(("object_flags", "offset"), [(0, 12), (1, 28), (2, 28), (3, 44)])
def test_parse_object_aces_skips_the_guids(
    ace_type: int, allowed: bool, object_flags: int, offset: int
) -> None:
    sid = _sid_bytes(5, 32, 544)
    raw = _ace_bytes(ace_type, sid, object_flags=object_flags)
    layout = winsec._parse_ace(raw, 3)
    assert layout.allowed is allowed
    assert layout.sid_offset == offset
    assert raw[layout.sid_offset : layout.sid_offset + len(sid)] == sid


@pytest.mark.parametrize("ace_type", [2, 3, 4, 7, 8, 13, 17, 0x40, 0xFF])
def test_parse_refuses_ace_types_it_cannot_interpret(ace_type: int) -> None:
    # Fail closed: audit, alarm, compound, label ... ACEs must not be silently skipped.
    with pytest.raises(OSError, match=f"unsupported ACE type {ace_type} at index 2"):
        winsec._parse_ace(_ace_bytes(ace_type), 2)


def test_parse_refuses_malformed_aces() -> None:
    good = _ace_bytes(0)
    with pytest.raises(OSError, match="malformed"):
        winsec._parse_ace(good[:12], 0)  # too short
    with pytest.raises(OSError, match="malformed"):
        winsec._parse_ace(good + b"\0\0", 0)  # header size differs from the bytes we have
    understated = bytearray(good)
    understated[2] -= 4
    with pytest.raises(OSError, match="malformed"):
        winsec._parse_ace(bytes(understated), 0)  # header size differs the other way
    with pytest.raises(OSError, match="bad SID"):
        winsec._parse_ace(_ace_bytes(0, b"\x02" + EVERYONE[1:]), 0)  # SID revision 2
    with pytest.raises(OSError, match="sub-authorities"):
        winsec._parse_ace(_ace_bytes(0, _sid_bytes(5, *range(16))), 0)  # more than 15
    overrun = bytearray(_ace_bytes(0, _sid_bytes(5, 1, 2)))
    overrun[9] = 4  # the SID now claims four sub-authorities but only two are there
    with pytest.raises(OSError, match="overruns"):
        winsec._parse_ace(bytes(overrun), 0)
    # An object ACE that names both GUIDs and then ends: the SID would start past the end.
    no_sid = struct.pack("<BBHII", 5, 0, 44, 0x1F01FF, 3) + GUID * 2
    with pytest.raises(OSError, match="bad SID"):
        winsec._parse_ace(no_sid, 0)


def test_read_ace_failure_still_frees_everything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The unsupported-ACE error must reach the caller (fail closed) AND release the descriptor.
    target = tmp_path / "d"
    target.mkdir()
    api = winsec._api()
    freed: list[object] = []
    real_free = api.k32.LocalFree

    def counting_free(address: object) -> object:
        freed.append(address)
        return real_free(address)

    def refuse(raw: bytes, index: int) -> object:
        raise OSError("unsupported ACE type 99 at index 0")

    monkeypatch.setattr(api.k32, "LocalFree", counting_free)
    monkeypatch.setattr(winsec, "_parse_ace", refuse)
    with pytest.raises(OSError, match="unsupported ACE type"):
        winsec.read_acl_of_path(str(target))
    assert len(freed) == 2  # the owner SID string and the descriptor itself


def test_describe_descriptor_reads_object_and_callback_aces() -> None:
    guid_a = "bf967aba-0de6-11d0-a285-00aa003049e2"
    guid_b = "4c164200-20c0-11d0-a768-00aa006e0529"
    sddl = (
        f"D:P(OA;;CC;{guid_a};{guid_b};SY)(OD;;CC;{guid_a};;BA)(OA;;CC;;{guid_b};BG)"
        "(OA;;CC;;;AU)(XA;;FA;;;S-1-5-21-1-2-3-1001;(Member_of{SID(BA)}))"
        "(XD;;FA;;;S-1-5-21-1-2-3-1002;(Member_of{SID(BA)}))(A;;FA;;;WD)"
    )
    with winsec.SecurityDescriptor.from_sddl(sddl) as sd:
        acl = winsec.describe_descriptor(sd)
    assert [(a.sid, a.allowed) for a in acl.aces] == [
        (winsec.SYSTEM_SID, True),
        (winsec.ADMINISTRATORS_SID, False),
        ("S-1-5-32-546", True),
        (winsec.AUTHENTICATED_USERS_SID, True),
        ("S-1-5-21-1-2-3-1001", True),
        ("S-1-5-21-1-2-3-1002", False),
        (winsec.WORLD_SID, True),
    ]
    assert all(a.mask for a in acl.aces)


# --- lookup failures, destructor, leaks -----------------------------------------------------


@pytest.mark.parametrize("error", [OSError("boom"), ValueError("boom"), ctypes.ArgumentError("x")])
def test_a_failing_account_lookup_never_fails_the_read(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    api = winsec._api()

    def failing_lookup(*args: object) -> int:
        raise error

    monkeypatch.setattr(api.adv, "LookupAccountSidW", failing_lookup)
    with winsec.SecurityDescriptor.private(include_system=True) as sd:
        acl = winsec.describe_descriptor(sd)
    assert [a.name for a in acl.aces] == [None, None]
    assert _sids(acl) == {winsec.current_user_sid(), winsec.SYSTEM_SID}


def test_a_lookup_that_reports_failure_gives_no_name_but_a_normal_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = winsec._api()
    with winsec.SecurityDescriptor.private() as sd:
        monkeypatch.setattr(api.adv, "LookupAccountSidW", lambda *args: 0)
        monkeypatch.setattr(winsec, "_last_error", lambda: 1332)  # ERROR_NONE_MAPPED
        acl = winsec.describe_descriptor(sd)
    assert [a.name for a in acl.aces] == [None]


def test_every_windows_allocated_string_is_freed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = winsec._api()
    freed: list[object] = []
    real_free = api.k32.LocalFree

    def counting_free(address: object) -> object:
        freed.append(address)
        return real_free(address)

    target = tmp_path / "d"
    target.mkdir()
    winsec.set_private_acl(str(target))
    monkeypatch.setattr(api.k32, "LocalFree", counting_free)

    acl = winsec.read_acl_of_path(str(target))
    # psd + owner SID string + one SID string per ACE + the SDDL string
    assert len(freed) == len(acl.aces) + 3

    freed.clear()
    with winsec.SecurityDescriptor.private() as sd, _pipe(sd.attributes) as name:
        pipe_acl = winsec.read_acl_of_pipe(name)
        freed.clear()
        # (a second probe: the first one was only needed to learn how many ACEs to expect)
        winsec.read_acl_of_pipe(name)
        assert len(freed) == len(pipe_acl.aces) + 3

    freed.clear()
    winsec.current_user_sid()
    assert len(freed) == 1  # the SID string; the token handle is covered by the handle test


def test_repeated_calls_do_not_leak_handles(tmp_path: Path) -> None:
    probes = 30
    with winsec.SecurityDescriptor.private() as sd, _pipe(sd.attributes, instances=40) as name:
        # Warm up everything that allocates once (library loading, caches).
        winsec.read_acl_of_pipe(name)
        winsec.current_user_sid()
        winsec.read_acl_of_path(str(tmp_path))
        gc.collect()
        before = _handle_count()

        for _ in range(probes):
            winsec.read_acl_of_pipe(name)  # each probe opens and must close one client handle
        for _ in range(300):
            winsec.current_user_sid()  # each call opens and must close the process token
        for _ in range(100):
            winsec.read_acl_of_path(str(tmp_path))
        for _ in range(100):
            with pytest.raises(FileNotFoundError):
                winsec.read_acl_of_path(str(tmp_path / "missing"))
            with pytest.raises(FileNotFoundError):
                winsec.read_acl_of_pipe("\\\\.\\pipe\\boundkeep-test-missing-" + name[-8:])
            with pytest.raises(OSError):  # noqa: PT011
                winsec.SecurityDescriptor.from_sddl("D:P(A;;GA;;;ZZZZ)")
        gc.collect()
        after = _handle_count()
    assert after - before <= 3, f"leaked {after - before} handles"


# --- long paths ------------------------------------------------------------------------------


def test_long_paths_with_the_extended_length_prefix(tmp_path: Path) -> None:
    deep = tmp_path
    for index in range(10):
        deep = deep / (f"segment-{index:02d}-" + "x" * 40)
    extended = "\\\\?\\" + str(deep)
    assert len(extended) > 300
    os.makedirs(extended)
    winsec.set_private_acl(extended)
    acl = winsec.read_acl_of_path(extended)
    assert acl.dacl_protected
    assert _sids(acl) == {winsec.current_user_sid(), winsec.SYSTEM_SID}
    assert fsperm.check_private(extended) == []
    # Without the prefix the answer is either the same ACL or an OSError, never a different one.
    try:
        plain = winsec.read_acl_of_path(str(deep))
    except OSError:
        return
    assert plain == acl
