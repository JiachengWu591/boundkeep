"""Windows security helpers (ctypes only): build a private security descriptor, read ACLs back.

WHY this exists: the named pipe the hook client talks to is created by the daemon with ctypes and
an explicit DACL that grants the current user only. The standard library's default grants Everyone
and Anonymous read access (measured in M0a, docs/hook-behavior.md E10). "Mode 0600" means nothing on
Windows, so the audit log and the boundkeep home directory also need real ACL code, and ``doctor``
and the tests need to READ ACLs back to prove that things are private.

Rules this module follows:

* It imports cleanly on every platform (POSIX test runs import it). Only calls into Windows APIs
  fail elsewhere, with ``OSError("Windows only")``. Every ``ctypes.windll`` / ``WinDLL`` /
  ``WinError`` use sits behind a ``sys.platform`` guard so mypy is happy on both platforms.
* Every foreign function gets explicit ``argtypes`` and ``restype``. Handles and pointers are
  ``c_void_p`` (never ``int``): ctypes' default ``int`` conversion truncates 64-bit values.
* Every Windows-allocated buffer is released with ``LocalFree`` and every handle with
  ``CloseHandle``, also on error paths.
* Failures raise ``OSError`` (``ctypes.WinError``); nothing is silently ignored. The one deliberate
  exception is account-name lookup: an unresolvable SID yields ``name=None`` and never fails a read.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import struct
import sys
import threading
import weakref
from dataclasses import dataclass
from typing import Any, NamedTuple

WORLD_SID = "S-1-1-0"
ANONYMOUS_SID = "S-1-5-7"
AUTHENTICATED_USERS_SID = "S-1-5-11"
BUILTIN_USERS_SID = "S-1-5-32-545"
SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
CREATOR_OWNER_SID = "S-1-3-0"
# Placeholder for "whoever owns the object". Python 3.12.4+ puts it in the ACL that
# os.mkdir(mode=0o700) creates on Windows, so the privacy check has to know it.
OWNER_RIGHTS_SID = "S-1-3-4"

_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1  # TOKEN_INFORMATION_CLASS: TokenUser
_ERROR_INSUFFICIENT_BUFFER = 122
_SE_FILE_OBJECT = 1
_SE_KERNEL_OBJECT = 6
_OWNER_SECURITY_INFORMATION = 0x1
_DACL_SECURITY_INFORMATION = 0x4
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SDDL_REVISION_1 = 1
_SE_DACL_PROTECTED = 0x1000
_INHERITED_ACE = 0x10
_READ_CONTROL = 0x00020000
_FILE_SHARE_READ_WRITE = 0x3
_OPEN_EXISTING = 3
_ACL_SIZE_INFORMATION = 2  # ACL_INFORMATION_CLASS: AclSizeInformation
_INVALID_HANDLE = ctypes.c_void_p(-1).value
_FILE_TYPE_PIPE = 3
_ERROR_PIPE_BUSY = 231
_PIPE_BUSY_WAIT_MS = 250  # per attempt; see read_acl_of_pipe
_PIPE_BUSY_RETRIES = 2
_PIPE_PREFIX = "\\\\.\\pipe\\"
_MAX_SID_SUBAUTHORITIES = 15
_MIN_ACE_SIZE = 16  # ACE header (4) + access mask (4) + the smallest SID (8)

# ACE types that can appear in a DACL. Allow and deny, plain / object / callback variants.
_ALLOW_ACE_TYPES = frozenset({0, 5, 9, 11})
_DENY_ACE_TYPES = frozenset({1, 6, 10, 12})
_OBJECT_ACE_TYPES = frozenset({5, 6, 11, 12})
_MAX_ACES = 4096  # an ACL is at most 64 KiB; refuse absurd counts from a corrupted structure


class SECURITY_ATTRIBUTES(ctypes.Structure):
    """The ``SECURITY_ATTRIBUTES`` structure for ``CreateNamedPipeW`` / ``CreateFileW``."""

    _fields_ = [
        ("nLength", ctypes.c_uint32),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", ctypes.c_int),
    ]


class _OwnedSecurityAttributes(SECURITY_ATTRIBUTES):
    """A ``SECURITY_ATTRIBUTES`` that keeps the ``SecurityDescriptor`` it points into alive.

    WHY: a plain structure holds only a raw address. If the descriptor is garbage collected (a
    temporary in ``SecurityDescriptor.private().attributes``) the address dangles, and the old
    workaround of writing NULL there is worse: a NULL ``lpSecurityDescriptor`` means "default
    security", which for a named pipe grants Everyone and Anonymous read access (M0a E10). With the
    owner reference the descriptor cannot be freed while this structure exists.
    """

    _owner: object


# Zero bytes are a descriptor with revision 0, which every security API rejects (CreateNamedPipeW
# fails with ERROR_REVISION_MISMATCH). SecurityDescriptor.close() points every SECURITY_ATTRIBUTES
# it has handed out at this buffer, so late use FAILS LOUDLY instead of getting the permissive
# default. Process-lifetime object, never freed.
_INVALID_DESCRIPTOR = ctypes.create_string_buffer(64)


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [
        ("AceCount", ctypes.c_uint32),
        ("AclBytesInUse", ctypes.c_uint32),
        ("AclBytesFree", ctypes.c_uint32),
    ]


@dataclass(frozen=True)
class AceInfo:
    """One access control entry of a DACL."""

    sid: str
    name: str | None
    allowed: bool
    mask: int
    inherited: bool


@dataclass(frozen=True)
class AclInfo:
    """A security descriptor reduced to what the privacy checks need.

    ``dacl_present`` is False for a NULL DACL, which grants everybody full access. It is never
    confused with an empty DACL (present, no ACEs: nobody has access) or a private one.
    """

    owner_sid: str | None
    dacl_present: bool
    dacl_protected: bool
    aces: tuple[AceInfo, ...]
    sddl: str


# --- guarded access to the Windows-only parts of ctypes ------------------------------------


def _winerror(code: int | None = None) -> OSError:
    """An ``OSError`` for a Windows error code (the thread's last error when ``code`` is None)."""
    if sys.platform != "win32":
        return OSError("Windows only")
    return ctypes.WinError(ctypes.get_last_error() if code is None else code)


def _last_error() -> int:
    if sys.platform != "win32":
        raise OSError("Windows only")
    return ctypes.get_last_error()


def _check(ok: object) -> None:
    """Raise the thread's last Windows error when a BOOL-returning call reports failure."""
    if not ok:
        raise _winerror()


def _check_code(code: int) -> None:
    """Raise for the DWORD error code returned by the ``*SecurityInfo`` family (0 is success)."""
    if code != 0:
        raise _winerror(code)


class _Api:
    """The configured kernel32 / advapi32 entry points, built once on first use."""

    k32: Any
    adv: Any

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise OSError("Windows only")
        # Private library instances (use_last_error=True): configuring argtypes here never
        # touches the shared ctypes.windll objects other code may rely on.
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.adv = ctypes.WinDLL("advapi32", use_last_error=True)
        vp = ctypes.c_void_p
        u32 = ctypes.c_uint32
        pvp = ctypes.POINTER(ctypes.c_void_p)
        pu32 = ctypes.POINTER(ctypes.c_uint32)
        pint = ctypes.POINTER(ctypes.c_int)

        def sig(lib: Any, name: str, restype: Any, *argtypes: Any) -> None:
            fn = getattr(lib, name)
            fn.argtypes = list(argtypes)
            fn.restype = restype

        k, a = self.k32, self.adv
        sig(k, "GetCurrentProcess", vp)
        sig(k, "CloseHandle", ctypes.c_int, vp)
        sig(k, "LocalFree", vp, vp)
        sig(
            k,
            "CreateFileW",
            vp,
            ctypes.c_wchar_p,
            u32,
            u32,
            vp,
            u32,
            u32,
            vp,
        )
        sig(k, "GetFileType", u32, vp)
        sig(k, "WaitNamedPipeW", ctypes.c_int, ctypes.c_wchar_p, u32)
        sig(a, "OpenProcessToken", ctypes.c_int, vp, u32, pvp)
        sig(a, "GetTokenInformation", ctypes.c_int, vp, ctypes.c_int, vp, u32, pu32)
        sig(a, "ConvertSidToStringSidW", ctypes.c_int, vp, pvp)
        sig(
            a,
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            ctypes.c_int,
            ctypes.c_wchar_p,
            u32,
            pvp,
            pu32,
        )
        sig(
            a,
            "ConvertSecurityDescriptorToStringSecurityDescriptorW",
            ctypes.c_int,
            vp,
            u32,
            u32,
            pvp,
            pu32,
        )
        sig(
            a,
            "GetNamedSecurityInfoW",
            u32,
            ctypes.c_wchar_p,
            ctypes.c_int,
            u32,
            pvp,
            pvp,
            pvp,
            pvp,
            pvp,
        )
        sig(a, "GetSecurityInfo", u32, vp, ctypes.c_int, u32, pvp, pvp, pvp, pvp, pvp)
        sig(a, "SetNamedSecurityInfoW", u32, ctypes.c_wchar_p, ctypes.c_int, u32, vp, vp, vp, vp)
        sig(a, "GetSecurityDescriptorDacl", ctypes.c_int, vp, pint, pvp, pint)
        sig(a, "GetSecurityDescriptorOwner", ctypes.c_int, vp, pvp, pint)
        sig(
            a,
            "GetSecurityDescriptorControl",
            ctypes.c_int,
            vp,
            ctypes.POINTER(ctypes.c_uint16),
            pu32,
        )
        sig(a, "GetAclInformation", ctypes.c_int, vp, vp, u32, ctypes.c_int)
        sig(a, "GetAce", ctypes.c_int, vp, u32, pvp)
        sig(a, "LookupAccountSidW", ctypes.c_int, ctypes.c_wchar_p, vp, vp, pu32, vp, pu32, pint)


_api_lock = threading.Lock()
_api_cache: _Api | None = None


def _api() -> _Api:
    global _api_cache
    if sys.platform != "win32":
        raise OSError("Windows only")
    with _api_lock:
        if _api_cache is None:
            _api_cache = _Api()
        return _api_cache


# --- SIDs ----------------------------------------------------------------------------------


def _take_string(buffer: ctypes.c_void_p) -> str:
    """Copy a Windows-allocated wide string into Python and free the original (LocalFree)."""
    address = buffer.value
    if not address:
        raise OSError("Windows returned a NULL string")
    try:
        return ctypes.wstring_at(address)
    finally:
        _api().k32.LocalFree(address)


def _sid_to_string(sid_addr: int) -> str:
    out = ctypes.c_void_p()
    _check(_api().adv.ConvertSidToStringSidW(sid_addr, ctypes.byref(out)))
    return _take_string(out)


def current_user_sid() -> str:
    """The string SID (``S-1-5-21-...``) of the user of this process's token."""
    api = _api()
    token = ctypes.c_void_p()
    _check(api.adv.OpenProcessToken(api.k32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)))
    try:
        needed = ctypes.c_uint32(0)
        api.adv.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(needed))
        if _last_error() != _ERROR_INSUFFICIENT_BUFFER or needed.value == 0:
            raise _winerror()
        buf = ctypes.create_string_buffer(needed.value)
        _check(
            api.adv.GetTokenInformation(token, _TOKEN_USER, buf, needed.value, ctypes.byref(needed))
        )
        # TOKEN_USER starts with SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes }.
        sid_addr = ctypes.c_void_p.from_buffer(buf).value
        if not sid_addr:
            raise OSError("token user has no SID")
        return _sid_to_string(sid_addr)
    finally:
        api.k32.CloseHandle(token)


def private_sddl(*, include_system: bool = False) -> str:
    """SDDL for a protected DACL that grants generic-all to the current user (and SYSTEM)."""
    sddl = f"D:P(A;;GA;;;{current_user_sid()})"
    if include_system:
        sddl += "(A;;GA;;;SY)"
    return sddl


# --- security descriptor -------------------------------------------------------------------


class SecurityDescriptor:
    """Owns a security descriptor allocated by ``ConvertStringSecurityDescriptor...``.

    ``attributes`` is the ``SECURITY_ATTRIBUTES`` to pass (``ctypes.byref``) to
    ``CreateNamedPipeW`` / ``CreateFileW``. The kernel copies the descriptor when the object is
    created, so closing afterwards is fine.

    Lifetime is tied together and fails closed:

    * every ``attributes`` object keeps this descriptor alive, so dropping the descriptor (or
      ``SecurityDescriptor.private().attributes``, which drops it at once) never leaves a dangling
      pointer behind;
    * ``close()`` frees the memory right away and re-points every ``attributes`` object that is
      still alive at a deliberately invalid descriptor, so creating an object from it afterwards
      FAILS (``OSError``) instead of silently getting the permissive default security that a NULL
      descriptor would mean;
    * asking a closed instance for ``attributes`` or ``address`` raises ``ValueError``.
    """

    def __init__(self, address: int) -> None:
        self._address: int | None = address
        self._lock = threading.Lock()
        # Weak references (not the objects: that would be a reference cycle, and ctypes structures
        # are unhashable so a WeakSet is out) to the attributes handed out, for close() to re-point.
        self._issued: list[weakref.ReferenceType[_OwnedSecurityAttributes]] = []

    @classmethod
    def from_sddl(cls, sddl: str) -> SecurityDescriptor:
        if not sddl.strip():
            # An empty SDDL converts to a descriptor WITHOUT a DACL, i.e. everybody has full access.
            raise ValueError("SDDL must not be empty")
        if "\0" in sddl:
            raise ValueError("SDDL must not contain NUL")
        api = _api()
        out = ctypes.c_void_p()
        _check(
            api.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, _SDDL_REVISION_1, ctypes.byref(out), None
            )
        )
        if not out.value:
            raise OSError("ConvertStringSecurityDescriptor returned a NULL descriptor")
        return cls(out.value)

    @classmethod
    def private(cls, *, include_system: bool = False) -> SecurityDescriptor:
        return cls.from_sddl(private_sddl(include_system=include_system))

    @property
    def address(self) -> int:
        """The descriptor's memory address, for passing to other security APIs."""
        if self._address is None:
            raise ValueError("SecurityDescriptor is closed")
        return self._address

    @property
    def attributes(self) -> SECURITY_ATTRIBUTES:
        """A new ``SECURITY_ATTRIBUTES`` for this descriptor (``bInheritHandle`` FALSE).

        Every call returns a fresh object; each one keeps this descriptor alive (see the class
        docstring).
        """
        with self._lock:
            if self._address is None:
                raise ValueError("SecurityDescriptor is closed")
            attributes = _OwnedSecurityAttributes(
                ctypes.sizeof(SECURITY_ATTRIBUTES), self._address, 0
            )
            attributes._owner = self
            self._issued = [ref for ref in self._issued if ref() is not None]
            self._issued.append(weakref.ref(attributes))
            return attributes

    def close(self) -> None:
        """Free the descriptor and poison the attributes handed out. Safe to call twice."""
        with self._lock:
            address, self._address = self._address, None
            issued, self._issued = self._issued, []
            # Re-point FIRST, free afterwards: no live structure ever points at freed memory, and
            # none is ever left NULL (= default, permissive security).
            for ref in issued:
                attributes = ref()
                if attributes is not None:
                    attributes.lpSecurityDescriptor = ctypes.addressof(_INVALID_DESCRIPTOR)
        if address is not None:
            _api().k32.LocalFree(address)

    def __enter__(self) -> SecurityDescriptor:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __del__(self) -> None:
        # A destructor must never raise (it may run during interpreter shutdown, when module
        # globals are already gone); the descriptor is process memory, so a lost free is harmless.
        with contextlib.suppress(Exception):
            self.close()


# --- reading ACLs --------------------------------------------------------------------------


def _lookup_account(sid_addr: int) -> str | None:
    """``DOMAIN\\name`` for a SID, or None. Never raises: an unresolvable SID is normal."""
    try:
        api = _api()
        name_len = ctypes.c_uint32(256)
        dom_len = ctypes.c_uint32(256)
        for _ in range(2):
            name_buf = ctypes.create_unicode_buffer(name_len.value)
            dom_buf = ctypes.create_unicode_buffer(dom_len.value)
            use = ctypes.c_int(0)
            ok = api.adv.LookupAccountSidW(
                None,
                sid_addr,
                name_buf,
                ctypes.byref(name_len),
                dom_buf,
                ctypes.byref(dom_len),
                ctypes.byref(use),
            )
            if ok:
                name, domain = name_buf.value, dom_buf.value
                if not name:
                    return None
                return f"{domain}\\{name}" if domain else name
            if _last_error() != _ERROR_INSUFFICIENT_BUFFER:
                return None
            # name_len / dom_len now hold the required sizes; retry once with them.
        return None
    except (OSError, ValueError, ctypes.ArgumentError):
        return None


class _AceLayout(NamedTuple):
    """What ``_parse_ace`` finds in the raw bytes of one ACE."""

    allowed: bool
    mask: int
    flags: int
    sid_offset: int


def _parse_ace(raw: bytes, index: int) -> _AceLayout:
    """Interpret the raw bytes of one ACE (header, mask, optional object GUIDs, SID).

    Pure (no Windows calls), so the layout arithmetic and the fail-closed branches are testable
    with hand-built bytes. ``raw`` must be exactly as long as the size in the ACE header.
    """
    if len(raw) < _MIN_ACE_SIZE:
        raise OSError(f"malformed ACE {index}: size {len(raw)}")
    ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", raw, 0)
    if ace_size != len(raw):
        raise OSError(f"malformed ACE {index}: header size {ace_size}, have {len(raw)} bytes")
    if ace_type in _ALLOW_ACE_TYPES:
        allowed = True
    elif ace_type in _DENY_ACE_TYPES:
        allowed = False
    else:
        # Fail closed: an ACE we cannot interpret must not be silently skipped.
        raise OSError(f"unsupported ACE type {ace_type} at index {index}")
    (mask,) = struct.unpack_from("<I", raw, 4)
    sid_offset = 8
    if ace_type in _OBJECT_ACE_TYPES:
        if len(raw) < 12:
            raise OSError(f"malformed ACE {index}: truncated object ACE")
        (object_flags,) = struct.unpack_from("<I", raw, 8)
        sid_offset = 12
        if object_flags & 0x1:  # ACE_OBJECT_TYPE_PRESENT: a 16-byte GUID follows
            sid_offset += 16
        if object_flags & 0x2:  # ACE_INHERITED_OBJECT_TYPE_PRESENT: another one
            sid_offset += 16
    if sid_offset + 8 > ace_size or raw[sid_offset] != 1:
        raise OSError(f"malformed ACE {index}: bad SID")
    subauthorities = raw[sid_offset + 1]
    if subauthorities > _MAX_SID_SUBAUTHORITIES:
        raise OSError(f"malformed ACE {index}: SID with {subauthorities} sub-authorities")
    if sid_offset + 8 + 4 * subauthorities > ace_size:
        raise OSError(f"malformed ACE {index}: SID overruns the ACE")
    return _AceLayout(allowed, mask, ace_flags, sid_offset)


def _read_ace(acl_addr: int, index: int) -> AceInfo:
    api = _api()
    ace_ptr = ctypes.c_void_p()
    _check(api.adv.GetAce(acl_addr, index, ctypes.byref(ace_ptr)))
    ace_addr = ace_ptr.value
    if not ace_addr:
        raise OSError(f"GetAce returned NULL for ACE {index}")
    (_, _, ace_size) = struct.unpack("<BBH", ctypes.string_at(ace_addr, 4))
    if ace_size < _MIN_ACE_SIZE:
        raise OSError(f"malformed ACE {index}: size {ace_size}")
    layout = _parse_ace(ctypes.string_at(ace_addr, ace_size), index)
    sid_addr = ace_addr + layout.sid_offset
    return AceInfo(
        sid=_sid_to_string(sid_addr),
        name=_lookup_account(sid_addr),
        allowed=layout.allowed,
        mask=layout.mask,
        inherited=bool(layout.flags & _INHERITED_ACE),
    )


def _describe(descriptor_addr: int) -> AclInfo:
    """Turn a (self-relative) security descriptor in memory into an ``AclInfo``."""
    api = _api()
    adv = api.adv

    owner_ptr = ctypes.c_void_p()
    defaulted = ctypes.c_int(0)
    _check(
        adv.GetSecurityDescriptorOwner(
            descriptor_addr, ctypes.byref(owner_ptr), ctypes.byref(defaulted)
        )
    )
    owner_sid = _sid_to_string(owner_ptr.value) if owner_ptr.value else None

    control = ctypes.c_uint16(0)
    revision = ctypes.c_uint32(0)
    _check(
        adv.GetSecurityDescriptorControl(
            descriptor_addr, ctypes.byref(control), ctypes.byref(revision)
        )
    )

    present = ctypes.c_int(0)
    acl_ptr = ctypes.c_void_p()
    _check(
        adv.GetSecurityDescriptorDacl(
            descriptor_addr, ctypes.byref(present), ctypes.byref(acl_ptr), ctypes.byref(defaulted)
        )
    )
    # "Present but NULL" and "not present" both mean no access control: everybody has full access.
    dacl_present = bool(present.value) and bool(acl_ptr.value)

    aces: list[AceInfo] = []
    if dacl_present:
        info = _AclSizeInformation()
        _check(
            adv.GetAclInformation(
                acl_ptr.value, ctypes.byref(info), ctypes.sizeof(info), _ACL_SIZE_INFORMATION
            )
        )
        if info.AceCount > _MAX_ACES:
            raise OSError(f"implausible ACE count {info.AceCount}")
        aces = [_read_ace(acl_ptr.value or 0, i) for i in range(info.AceCount)]

    sddl_ptr = ctypes.c_void_p()
    _check(
        adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor_addr,
            _SDDL_REVISION_1,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(sddl_ptr),
            None,
        )
    )
    sddl = _take_string(sddl_ptr)

    return AclInfo(
        owner_sid=owner_sid,
        dacl_present=dacl_present,
        dacl_protected=bool(control.value & _SE_DACL_PROTECTED),
        aces=tuple(aces),
        sddl=sddl,
    )


def describe_descriptor(descriptor: SecurityDescriptor) -> AclInfo:
    """Read an in-memory ``SecurityDescriptor`` the same way the file and pipe readers do."""
    return _describe(descriptor.address)


def _path_arg(path: str | os.PathLike[str]) -> str:
    """Normalize a path argument to ``str`` before it reaches a ``c_wchar_p`` parameter.

    WHY: ``c_wchar_p`` silently truncates at the first NUL, so ``"<dir>\\0junk"`` would act on
    ``<dir>`` (wrong object, wrong inheritance flags, no error); ``bytes`` and ``Path`` objects
    raise ``ctypes.ArgumentError`` (not an ``OSError``). Both are decided here, up front:
    ``os.PathLike`` is accepted, ``bytes`` is a ``TypeError``, a NUL is a ``ValueError``.
    """
    text = os.fspath(path)
    if not isinstance(text, str):
        raise TypeError(f"path must be str or os.PathLike[str], not {type(text).__name__}")
    if "\0" in text:
        raise ValueError("path must not contain a NUL character")
    return text


def _pipe_arg(pipe_name: str | os.PathLike[str]) -> str:
    r"""Validate ``\\.\pipe\<name>``: one path component after the prefix, nothing else.

    WHY: Win32 normalizes ``..`` in ``\\.\`` paths, so a bare prefix test would let
    ``\\.\pipe\..\C:\Windows\notepad.exe`` open an arbitrary file. A pipe name has no backslash.
    """
    text = _path_arg(pipe_name)
    leaf = text[len(_PIPE_PREFIX) :]
    if (
        not text.lower().startswith(_PIPE_PREFIX)
        or not leaf
        or "\\" in leaf
        or "/" in leaf
        or leaf in {".", ".."}
    ):
        raise ValueError(f"not a local named pipe path: {text!r}")
    return text


def read_acl_of_path(path: str | os.PathLike[str]) -> AclInfo:
    """Owner and DACL of a file or directory (``GetNamedSecurityInfoW``, ``SE_FILE_OBJECT``).

    Raises ``FileNotFoundError`` (an ``OSError``) when the path does not exist, ``ValueError`` for
    a path with a NUL and ``TypeError`` for ``bytes``. If ``path`` is a symbolic link or a
    junction, the ACL of the link itself is returned, not that of its target.
    """
    path = _path_arg(path)
    api = _api()
    psd = ctypes.c_void_p()
    code = api.adv.GetNamedSecurityInfoW(
        path,
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        None,
        None,
        None,
        None,
        ctypes.byref(psd),
    )
    _check_code(code)
    try:
        if not psd.value:
            raise OSError("GetNamedSecurityInfo returned a NULL descriptor")
        return _describe(psd.value)
    finally:
        api.k32.LocalFree(psd)


def read_acl_of_pipe(pipe_name: str | os.PathLike[str]) -> AclInfo:
    r"""Owner and DACL of a named pipe, by full path such as ``\\.\pipe\name``.

    The pipe is opened with ``READ_CONTROL`` only and ``GetSecurityInfo`` is called on the handle.

    Side effects on the server, which callers (``doctor``) must know about: opening a pipe client
    handle CONNECTS to a free server instance. After the probe closes its handle that instance
    stays out of service until the server notices the broken connection and recycles it
    (``DisconnectNamedPipe`` then ``ConnectNamedPipe`` again). With a single-instance pipe every
    real client therefore gets ``ERROR_PIPE_BUSY`` (231) until the daemon has recycled it, so the
    daemon's pool must recycle on ``ERROR_BROKEN_PIPE`` and ``doctor`` must not probe a pipe that
    has only one instance. Conversely, when every instance is already connected the open fails
    with winerror 231 after a short wait (2 retries of ``WaitNamedPipeW``, 250 ms each): a busy
    daemon is "unable to verify", not a privacy error, and callers should treat 231 that way.

    Only a real named pipe is accepted: the name must be one path component after
    ``\\.\pipe\`` (no ``..``, no separators), and the opened handle must be of type
    ``FILE_TYPE_PIPE``, otherwise ``OSError``.
    """
    pipe_name = _pipe_arg(pipe_name)
    api = _api()
    handle = None
    for attempt in range(_PIPE_BUSY_RETRIES + 1):
        handle = api.k32.CreateFileW(
            pipe_name, _READ_CONTROL, _FILE_SHARE_READ_WRITE, None, _OPEN_EXISTING, 0, None
        )
        if handle is not None and handle != _INVALID_HANDLE:
            break
        error = _last_error()
        if error != _ERROR_PIPE_BUSY or attempt == _PIPE_BUSY_RETRIES:
            raise _winerror(error)
        # The wait's own result is irrelevant: the next CreateFileW decides, and a timeout there
        # ends in the same ERROR_PIPE_BUSY error after the last attempt.
        api.k32.WaitNamedPipeW(pipe_name, _PIPE_BUSY_WAIT_MS)
    psd = ctypes.c_void_p()
    try:
        if api.k32.GetFileType(handle) != _FILE_TYPE_PIPE:
            raise OSError(f"not a named pipe: {pipe_name!r}")
        code = api.adv.GetSecurityInfo(
            handle,
            _SE_KERNEL_OBJECT,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            ctypes.byref(psd),
        )
        _check_code(code)
        if not psd.value:
            raise OSError("GetSecurityInfo returned a NULL descriptor")
        return _describe(psd.value)
    finally:
        if psd.value:
            api.k32.LocalFree(psd)
        api.k32.CloseHandle(handle)


# --- writing ACLs --------------------------------------------------------------------------


def _file_sddl(*, is_dir: bool, include_system: bool) -> str:
    """Protected DACL for a file or directory: full control for the current user (and SYSTEM).

    ``FA`` (FILE_ALL_ACCESS) rather than ``GA``: a stored ACE should carry specific rights, not
    generic ones. Directories get object- and container-inherit so files created later are private.
    """
    flags = "OICI" if is_dir else ""
    sddl = f"D:P(A;{flags};FA;;;{current_user_sid()})"
    if include_system:
        sddl += f"(A;{flags};FA;;;SY)"
    return sddl


def set_private_acl(path: str | os.PathLike[str], *, include_system: bool = True) -> None:
    """Replace the DACL of an existing file or directory by a protected, private one.

    "Protected" means no inheritance from the parent. For a directory the ACEs are inheritable, and
    existing children that inherit are updated by Windows. Raises ``OSError`` on any failure
    (including a nonexistent path); never leaves the old DACL in place silently. A path with a NUL
    is a ``ValueError`` and ``bytes`` a ``TypeError``, both raised before anything is changed.

    A symbolic link or junction is NOT followed: its own ACL is replaced, not its target's. Callers
    that care (``fsperm`` does) must reject links first.
    """
    path = _path_arg(path)
    api = _api()
    sddl = _file_sddl(is_dir=os.path.isdir(path), include_system=include_system)
    with SecurityDescriptor.from_sddl(sddl) as descriptor:
        present = ctypes.c_int(0)
        acl_ptr = ctypes.c_void_p()
        defaulted = ctypes.c_int(0)
        _check(
            api.adv.GetSecurityDescriptorDacl(
                descriptor.address,
                ctypes.byref(present),
                ctypes.byref(acl_ptr),
                ctypes.byref(defaulted),
            )
        )
        if not present.value or not acl_ptr.value:
            raise OSError("private descriptor has no DACL")
        code = api.adv.SetNamedSecurityInfoW(
            path,
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            acl_ptr,
            None,
        )
        _check_code(code)
