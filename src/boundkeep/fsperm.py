"""Private files and directories: create them private, and check that they still are.

The audit log, the endpoint token and the policy live under the boundkeep home directory and must
not be readable by other users. POSIX uses mode bits (0700 / 0600). Windows has no such thing, so
this module reads and writes real ACLs through ``boundkeep.ipc.winsec``.

Fail closed: ``ensure_*`` raise ``OSError`` rather than leave something readable by others, and
``check_private`` reports an unreadable ACL as an error, never as "fine".

Links: on Windows the ACL APIs act on a symbolic link or junction ITSELF, not on its target, so an
ACL judged (or rewritten) on a link says nothing about where the data really lands. The POSIX
branch follows links (``os.stat`` / ``os.chmod``) and judges the real target, which is consistent.
The Windows branch refuses instead: ``check_private`` reports an error and ``ensure_*`` raise.
Point the boundkeep home at the real directory, not at a junction to it.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import os
import stat
import sys
from dataclasses import dataclass
from typing import Literal

from boundkeep.ipc import winsec

# Principals that may appear in an ALLOW entry on Windows without making a path "not private":
# the user, the OS itself, local administrators (who can take ownership anyway) and the
# placeholders that stand for "the owner" (see _OWNER_RELATIVE_SIDS for when they stop being safe).
_TRUSTED_SYSTEM_SIDS = frozenset(
    {
        winsec.SYSTEM_SID,
        winsec.ADMINISTRATORS_SID,
        winsec.CREATOR_OWNER_SID,
        # "The owner of this object": Python 3.12.4+ puts it into the ACL that
        # os.makedirs(mode=0o700) creates on Windows.
        winsec.OWNER_RIGHTS_SID,
    }
)

# These two grant access to WHOEVER owns the object, so they are only as trustworthy as the owner.
_OWNER_RELATIVE_SIDS = frozenset({winsec.CREATOR_OWNER_SID, winsec.OWNER_RIGHTS_SID})

# English labels for well-known SIDs, so a message names the principal even when the account
# lookup fails or returns a localized name.
_WELL_KNOWN_NAMES = {
    winsec.WORLD_SID: "Everyone",
    winsec.ANONYMOUS_SID: "ANONYMOUS LOGON",
    winsec.AUTHENTICATED_USERS_SID: "Authenticated Users",
    winsec.BUILTIN_USERS_SID: "BUILTIN\\Users",
    winsec.SYSTEM_SID: "SYSTEM",
    winsec.ADMINISTRATORS_SID: "BUILTIN\\Administrators",
    winsec.CREATOR_OWNER_SID: "CREATOR OWNER",
    winsec.OWNER_RIGHTS_SID: "OWNER RIGHTS",
}

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
# Reparse tags that REDIRECT to another object: symbolic links and mount points (junctions).
_REDIRECTING_REPARSE_TAGS = frozenset({0xA000000C, 0xA0000003})


@dataclass(frozen=True)
class PermProblem:
    """One reason a path is not private."""

    path: str
    severity: Literal["error", "warning"]
    message: str


def _principal(sid: str, name: str | None) -> str:
    """``name (SID)`` so that a user can act on the message whichever of the two they know."""
    label = name or _WELL_KNOWN_NAMES.get(sid.upper())
    if label and label.lower() != sid.lower():
        return f"{label} ({sid})"
    return f"{sid} (account name not resolvable)"


def _problems_from_acl(
    path: str, acl: winsec.AclInfo, user_sid: str, *, is_dir: bool = True
) -> list[PermProblem]:
    """Judge an ACL. Pure (no OS calls) so the Windows policy is testable on any platform."""
    trusted = {user_sid.upper(), *_TRUSTED_SYSTEM_SIDS}
    # Owners that do not make an owner-relative ACE dangerous.
    trusted_owners = {user_sid.upper(), winsec.SYSTEM_SID, winsec.ADMINISTRATORS_SID}
    owner = acl.owner_sid
    owner_is_trusted = owner is not None and owner.upper() in trusted_owners
    problems: list[PermProblem] = []

    if not acl.dacl_present:
        return [
            PermProblem(
                path,
                "error",
                "has a NULL DACL (no access control): Everyone (S-1-1-0) has full access",
            )
        ]

    untrusted_seen = False
    for ace in acl.aces:
        who = _principal(ace.sid, ace.name)
        origin = "inherited " if ace.inherited else ""
        sid = ace.sid.upper()
        if ace.allowed:
            if sid not in trusted:
                untrusted_seen = True
                problems.append(
                    PermProblem(
                        path,
                        "error",
                        f"{origin}ACL entry grants access to {who} (access mask 0x{ace.mask:08X})",
                    )
                )
            elif sid in _OWNER_RELATIVE_SIDS and not owner_is_trusted:
                # "Whoever owns it" is somebody else, so this entry hands them the access.
                untrusted_seen = True
                owner_text = _principal(owner, None) if owner is not None else "an unknown account"
                problems.append(
                    PermProblem(
                        path,
                        "error",
                        f"{origin}ACL entry grants access to {who}, which means the owner of "
                        f"this object, and the owner is {owner_text}, not the current user "
                        f"(access mask 0x{ace.mask:08X})",
                    )
                )
        else:
            problems.append(PermProblem(path, "warning", f"{origin}ACL has a deny entry for {who}"))

    if owner is not None and not owner_is_trusted:
        # An owner can always rewrite the DACL, so a foreign owner is worth a look.
        problems.append(
            PermProblem(
                path,
                "warning",
                f"owner is {_principal(owner, None)}, not the current user",
            )
        )

    if not acl.aces:
        problems.append(
            PermProblem(path, "warning", "DACL is empty: nobody, not even the owner, has access")
        )
    elif is_dir and not acl.dacl_protected and not untrusted_seen:
        # Only for directories: a file is SUPPOSED to inherit from its private directory (that is
        # how ensure_private_file works), so warning about it would make every audit log "dirty".
        problems.append(
            PermProblem(
                path,
                "warning",
                "DACL inherits from the parent directory (not protected); "
                "only trusted principals appear for now",
            )
        )
    return problems


def _is_redirecting_link(path: str) -> bool:
    """True when ``path`` itself is a symbolic link or junction (Windows), dangling or not."""
    try:
        st = os.lstat(path)
    except (OSError, ValueError):
        return False
    attributes = getattr(st, "st_file_attributes", 0)
    tag = getattr(st, "st_reparse_tag", 0)
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT) and tag in _REDIRECTING_REPARSE_TAGS


def _link_message(path: str) -> str:
    target = ""
    with contextlib.suppress(OSError, ValueError):
        target = f' (it points to "{os.path.realpath(path)}")'
    return (
        f"is a symbolic link or junction{target}: the ACL of a link says nothing about the "
        "directory it leads to, so boundkeep does not treat it as private; "
        "use the real directory instead"
    )


def _check_windows(path: str) -> list[PermProblem]:
    if _is_redirecting_link(path):
        return [PermProblem(path, "error", _link_message(path))]
    try:
        acl = winsec.read_acl_of_path(path)
        user_sid = winsec.current_user_sid()
    except (OSError, ValueError, ctypes.ArgumentError) as exc:
        return [PermProblem(path, "error", f"cannot read the ACL: {exc}")]
    return _problems_from_acl(path, acl, user_sid, is_dir=os.path.isdir(path))


def _check_posix(path: str) -> list[PermProblem]:
    if sys.platform == "win32":
        raise OSError("POSIX only")
    try:
        st = os.stat(path)
    except OSError as exc:
        return [PermProblem(path, "error", f"cannot stat: {exc}")]
    problems: list[PermProblem] = []
    if st.st_mode & 0o077:
        problems.append(
            PermProblem(
                path,
                "error",
                f"mode is {stat.S_IMODE(st.st_mode):04o}; group and others must have no access",
            )
        )
    euid = os.geteuid()
    if st.st_uid != euid:
        problems.append(
            PermProblem(path, "error", f"owned by uid {st.st_uid}, not the current user ({euid})")
        )
    return problems


def _path_text(path: str | os.PathLike[str]) -> str:
    """``path`` as ``str``. ``os.PathLike`` is accepted; ``bytes`` is a ``TypeError``; a NUL is an
    ``OSError`` (``EINVAL``), so the ``ensure_*`` functions only ever raise ``OSError`` for a bad
    path and never touch the disk with a path the Windows API would silently truncate."""
    text = os.fspath(path)
    if not isinstance(text, str):
        raise TypeError(f"path must be str or os.PathLike[str], not {type(text).__name__}")
    if "\0" in text:
        raise OSError(errno.EINVAL, "path must not contain a NUL character")
    return text


def check_private(path: str | os.PathLike[str]) -> list[PermProblem]:
    """Why ``path`` is not private to the current user; an empty list when it is.

    Never raises for a bad path: a nonexistent path, a NUL, a wrong type or an unreadable ACL each
    come back as an error-level problem.
    """
    try:
        text = _path_text(path)
    except (TypeError, OSError) as exc:
        return [PermProblem(repr(path), "error", f"invalid path: {exc}")]
    if not os.path.lexists(text):
        return [PermProblem(text, "error", "does not exist")]
    if sys.platform == "win32":
        return _check_windows(text)
    return _check_posix(text)


def _refuse_link(text: str) -> None:
    """Raise ``OSError`` when ``text`` is a symbolic link or junction (Windows only)."""
    if sys.platform == "win32" and _is_redirecting_link(text):
        raise OSError(f"could not make {text!r} private: it {_link_message(text)}")


def _require_private(text: str) -> None:
    """Raise ``OSError`` if ``text`` still has an error-level problem (belt and braces)."""
    errors = [p.message for p in check_private(text) if p.severity == "error"]
    if errors:
        raise OSError(f"could not make {text!r} private: " + "; ".join(errors))


def ensure_private_dir(path: str | os.PathLike[str]) -> None:
    """Create ``path`` if needed and make the LEAF directory private to the current user.

    Parents are created with default permissions and never touched. Idempotent. On Windows a
    symbolic link or junction is refused (see the module docstring). Raises ``OSError`` on any
    failure, and verifies the result before returning.
    """
    text = _path_text(path)
    _refuse_link(text)
    os.makedirs(text, mode=0o700, exist_ok=True)
    if sys.platform == "win32":
        # Re-check right before the write: shrinks the window in which the directory could be
        # swapped for a junction. _require_private below catches a swap that still got through.
        _refuse_link(text)
        winsec.set_private_acl(text, include_system=True)
    else:
        os.chmod(text, 0o700)
    _require_private(text)


def ensure_private_file(path: str | os.PathLike[str]) -> None:
    """Make an existing file private.

    On Windows a file normally inherits a private ACL from its private directory; it is only
    rewritten when the current ACL grants access to somebody else. A symbolic link is refused on
    Windows. Raises ``OSError`` on any failure, and verifies the result before returning.
    """
    text = _path_text(path)
    if sys.platform == "win32":
        _refuse_link(text)
        needs_fix = any(p.severity == "error" for p in check_private(text))
        if needs_fix:
            winsec.set_private_acl(text, include_system=True)
    else:
        os.chmod(text, 0o600)
    _require_private(text)
