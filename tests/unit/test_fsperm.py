"""fsperm: private directories and files, and the privacy check.

The ACL judgement (``_problems_from_acl``) is a pure function, so its policy is tested on every
platform with hand-built ``AclInfo`` values. The POSIX branch runs under ``pytest.mark.posix``
and the Windows branch under ``pytest.mark.windows`` (real ACLs on tmp_path only).
"""

from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from boundkeep import fsperm
from boundkeep.fsperm import PermProblem
from boundkeep.ipc.winsec import (
    ADMINISTRATORS_SID,
    ANONYMOUS_SID,
    AUTHENTICATED_USERS_SID,
    BUILTIN_USERS_SID,
    CREATOR_OWNER_SID,
    OWNER_RIGHTS_SID,
    SYSTEM_SID,
    WORLD_SID,
    AceInfo,
    AclInfo,
)

ME = "S-1-5-21-1000-2000-3000-1001"
OTHER = "S-1-5-21-1000-2000-3000-1002"


def ace(
    sid: str, *, allowed: bool = True, name: str | None = None, inherited: bool = False
) -> AceInfo:
    return AceInfo(sid=sid, name=name, allowed=allowed, mask=0x1F01FF, inherited=inherited)


def acl(
    *aces: AceInfo,
    owner: str | None = ME,
    protected: bool = True,
    present: bool = True,
) -> AclInfo:
    return AclInfo(owner, present, protected, tuple(aces), "D:...")


def judge(info: AclInfo) -> list[PermProblem]:
    return fsperm._problems_from_acl("p", info, ME)


def errors(problems: list[PermProblem]) -> list[PermProblem]:
    return [p for p in problems if p.severity == "error"]


# --- the Windows policy, on any platform ------------------------------------------------------


def test_private_acl_has_no_problems() -> None:
    assert judge(acl(ace(ME), ace(SYSTEM_SID))) == []


def test_trusted_principals_are_allowed() -> None:
    info = acl(ace(ME), ace(SYSTEM_SID), ace(ADMINISTRATORS_SID), ace(CREATOR_OWNER_SID))
    assert judge(info) == []


def test_user_sid_comparison_ignores_case() -> None:
    assert judge(acl(ace(ME.lower()))) == []


@pytest.mark.parametrize(
    ("sid", "label"),
    [
        (WORLD_SID, "Everyone"),
        (ANONYMOUS_SID, "ANONYMOUS LOGON"),
        (AUTHENTICATED_USERS_SID, "Authenticated Users"),
        (BUILTIN_USERS_SID, "Users"),
        (OTHER, "account name not resolvable"),
    ],
)
def test_other_principals_are_errors_that_name_them(sid: str, label: str) -> None:
    problems = judge(acl(ace(ME), ace(sid)))
    assert len(errors(problems)) == 1
    message = errors(problems)[0].message
    assert sid in message
    assert label in message


def test_resolved_name_is_shown_next_to_the_sid() -> None:
    problems = judge(acl(ace(OTHER, name="PC\\bob")))
    assert "PC\\bob" in problems[0].message
    assert OTHER in problems[0].message


def test_inherited_allow_entries_count_too() -> None:
    problems = judge(acl(ace(WORLD_SID, inherited=True), protected=False))
    assert len(errors(problems)) == 1
    assert "inherited" in problems[0].message


def test_null_dacl_is_an_error_and_says_everyone() -> None:
    problems = judge(acl(present=False))
    assert [p.severity for p in problems] == ["error"]
    assert "NULL DACL" in problems[0].message
    assert WORLD_SID in problems[0].message


def test_deny_entry_is_only_a_warning() -> None:
    problems = judge(acl(ace(OTHER, allowed=False), ace(ME)))
    assert errors(problems) == []
    assert [p.severity for p in problems] == ["warning"]
    assert OTHER in problems[0].message


def test_unprotected_dacl_with_trusted_principals_is_only_a_warning() -> None:
    problems = judge(acl(ace(ME), ace(SYSTEM_SID), protected=False))
    assert [p.severity for p in problems] == ["warning"]
    assert "inherits" in problems[0].message


def test_unprotected_file_is_fine_because_files_inherit_by_design() -> None:
    info = acl(ace(ME, inherited=True), ace(SYSTEM_SID, inherited=True), protected=False)
    assert fsperm._problems_from_acl("p", info, ME, is_dir=False) == []


def test_owner_rights_placeholder_is_trusted() -> None:
    # Python 3.12.4+ puts it in the ACL created by os.makedirs(mode=0o700) on Windows.
    assert judge(acl(ace(ME), ace(OWNER_RIGHTS_SID), ace(ADMINISTRATORS_SID))) == []


def test_unprotected_with_untrusted_principal_reports_the_error_only() -> None:
    problems = judge(acl(ace(ME), ace(WORLD_SID), protected=False))
    assert [p.severity for p in problems] == ["error"]


def test_foreign_owner_is_a_warning() -> None:
    problems = judge(acl(ace(ME), owner=OTHER))
    assert [p.severity for p in problems] == ["warning"]
    assert OTHER in problems[0].message
    assert judge(acl(ace(ME), owner=ADMINISTRATORS_SID)) == []
    assert judge(acl(ace(ME), owner=None)) == []


def test_empty_dacl_is_a_warning_not_a_pass() -> None:
    problems = judge(acl())
    assert [p.severity for p in problems] == ["warning"]
    assert "empty" in problems[0].message


# --- platform neutral behaviour ---------------------------------------------------------------


def test_nonexistent_path_is_one_error_not_an_exception(tmp_path: Path) -> None:
    problems = fsperm.check_private(str(tmp_path / "missing"))
    assert len(problems) == 1
    assert problems[0].severity == "error"
    assert "does not exist" in problems[0].message
    assert problems[0].path == str(tmp_path / "missing")


@pytest.mark.parametrize("hostile", ["", "bad\0name", "x" * 5000])
def test_hostile_paths_do_not_raise(hostile: str) -> None:
    problems = fsperm.check_private(hostile)
    assert problems
    assert all(p.severity == "error" for p in problems)


def test_ensure_private_dir_creates_nested_dirs_and_is_idempotent(tmp_path: Path) -> None:
    leaf = tmp_path / "a" / "b" / "leaf"
    fsperm.ensure_private_dir(str(leaf))
    assert leaf.is_dir()
    assert fsperm.check_private(str(leaf)) == []
    fsperm.ensure_private_dir(str(leaf))
    assert fsperm.check_private(str(leaf)) == []


def test_ensure_private_dir_fails_when_a_file_is_in_the_way(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(FileExistsError):
        fsperm.ensure_private_dir(str(blocker))


def test_ensure_private_file_on_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        fsperm.ensure_private_file(str(tmp_path / "missing"))


def test_ensure_private_file_in_private_dir(tmp_path: Path) -> None:
    home = tmp_path / "home"
    fsperm.ensure_private_dir(str(home))
    f = home / "audit.jsonl"
    f.write_text("{}\n", encoding="utf-8")
    fsperm.ensure_private_file(str(f))
    assert fsperm.check_private(str(f)) == []
    fsperm.ensure_private_file(str(f))
    assert fsperm.check_private(str(f)) == []


def test_ensure_private_dir_with_chinese_and_spaces(tmp_path: Path) -> None:
    leaf = tmp_path / "含 空格" / "守界 home"
    fsperm.ensure_private_dir(str(leaf))
    f = leaf / "审计 日志.jsonl"
    f.write_text("{}\n", encoding="utf-8")
    fsperm.ensure_private_file(str(f))
    assert fsperm.check_private(str(leaf)) == []
    assert fsperm.check_private(str(f)) == []


# --- POSIX branch -----------------------------------------------------------------------------


@pytest.mark.posix
def test_posix_modes(tmp_path: Path) -> None:
    d = tmp_path / "d"
    fsperm.ensure_private_dir(str(d))
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    assert fsperm.check_private(str(d)) == []

    os.chmod(d, 0o755)  # noqa: S103 - the test needs a deliberately wide mode
    problems = fsperm.check_private(str(d))
    assert [p.severity for p in problems] == ["error"]
    assert "0755" in problems[0].message
    fsperm.ensure_private_dir(str(d))
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700


@pytest.mark.posix
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o666, 0o660, 0o606])
def test_posix_group_or_other_access_is_an_error(tmp_path: Path, mode: int) -> None:
    f = tmp_path / "f"
    f.write_text("x", encoding="utf-8")
    os.chmod(f, mode)
    assert [p.severity for p in fsperm.check_private(str(f))] == ["error"]
    fsperm.ensure_private_file(str(f))
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
    assert fsperm.check_private(str(f)) == []


@pytest.mark.posix
def test_posix_owner_only_modes_are_fine(tmp_path: Path) -> None:
    f = tmp_path / "f"
    f.write_text("x", encoding="utf-8")
    for mode in (0o600, 0o400, 0o700):
        os.chmod(f, mode)
        assert fsperm.check_private(str(f)) == []


@pytest.mark.posix
def test_posix_foreign_owner_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = tmp_path / "f"
    f.write_text("x", encoding="utf-8")
    os.chmod(f, 0o600)
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(f).st_uid + 1)
    problems = fsperm.check_private(str(f))
    assert [p.severity for p in problems] == ["error"]
    assert "owned by uid" in problems[0].message


@pytest.mark.posix
def test_posix_parents_are_not_touched(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    os.chmod(parent, 0o755)  # noqa: S103 - the test needs a deliberately wide mode
    fsperm.ensure_private_dir(str(parent / "leaf"))
    assert stat.S_IMODE(os.stat(parent).st_mode) == 0o755


# --- Windows branch ---------------------------------------------------------------------------


def _icacls_grant_everyone(path: Path) -> None:
    exe = os.path.join(os.environ["SYSTEMROOT"], "System32", "icacls.exe")
    result = subprocess.run(
        [exe, str(path), "/grant", "*S-1-1-0:(OI)(CI)R"], capture_output=True, check=False
    )
    assert result.returncode == 0


@pytest.mark.windows
def test_windows_ensure_private_dir_replaces_a_wide_open_acl(tmp_path: Path) -> None:
    d = tmp_path / "d"
    d.mkdir()
    _icacls_grant_everyone(d)
    assert errors(fsperm.check_private(str(d)))
    fsperm.ensure_private_dir(str(d))
    assert fsperm.check_private(str(d)) == []
    fsperm.ensure_private_dir(str(d))
    assert fsperm.check_private(str(d)) == []


@pytest.mark.windows
def test_windows_ensure_private_file_tightens_only_when_needed(tmp_path: Path) -> None:
    from boundkeep.ipc import winsec

    home = tmp_path / "home"
    fsperm.ensure_private_dir(str(home))
    f = home / "f.txt"
    f.write_text("x", encoding="utf-8")
    before = winsec.read_acl_of_path(str(f))
    fsperm.ensure_private_file(str(f))
    # Inherited and already private: left alone (still inherited, not rewritten as protected).
    assert winsec.read_acl_of_path(str(f)) == before

    exe = os.path.join(os.environ["SYSTEMROOT"], "System32", "icacls.exe")
    result = subprocess.run([exe, str(f), "/grant", "*S-1-1-0:R"], capture_output=True, check=False)
    assert result.returncode == 0
    problems = fsperm.check_private(str(f))
    assert errors(problems)
    assert any("S-1-1-0" in p.message for p in errors(problems))
    fsperm.ensure_private_file(str(f))
    assert fsperm.check_private(str(f)) == []


@pytest.mark.windows
def test_windows_parent_acl_is_not_touched(tmp_path: Path) -> None:
    from boundkeep.ipc import winsec

    parent = tmp_path / "parent"
    parent.mkdir()
    before = winsec.read_acl_of_path(str(parent))
    fsperm.ensure_private_dir(str(parent / "leaf"))
    assert winsec.read_acl_of_path(str(parent)) == before


@pytest.mark.windows
def test_windows_private_dir_has_exactly_user_and_system(tmp_path: Path) -> None:
    from boundkeep.ipc import winsec

    d = tmp_path / "d"
    fsperm.ensure_private_dir(str(d))
    acl_info = winsec.read_acl_of_path(str(d))
    assert acl_info.dacl_protected
    assert {a.sid for a in acl_info.aces} == {winsec.current_user_sid(), SYSTEM_SID}


@pytest.mark.windows
def test_windows_check_private_on_unreadable_acl_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from boundkeep.ipc import winsec

    def boom(path: str) -> AclInfo:
        raise PermissionError("denied")

    monkeypatch.setattr(winsec, "read_acl_of_path", boom)
    d = tmp_path / "d"
    d.mkdir()
    problems = fsperm.check_private(str(d))
    assert [p.severity for p in problems] == ["error"]
    assert "cannot read the ACL" in problems[0].message


# --- owner-relative entries (OWNER RIGHTS / CREATOR OWNER) -----------------------------------


@pytest.mark.parametrize("sid", [OWNER_RIGHTS_SID, CREATOR_OWNER_SID])
def test_owner_relative_entry_with_a_foreign_owner_is_an_error(sid: str) -> None:
    # "OWNER RIGHTS" means whoever owns the object. If that is somebody else, they have the access.
    problems = judge(acl(ace(ME), ace(sid), owner=OTHER))
    assert len(errors(problems)) == 1
    message = errors(problems)[0].message
    assert OTHER in message
    assert "owner" in message
    assert any(p.severity == "warning" and "owner is" in p.message for p in problems)


@pytest.mark.parametrize("sid", [OWNER_RIGHTS_SID, CREATOR_OWNER_SID])
def test_owner_relative_entry_with_an_unknown_owner_is_an_error(sid: str) -> None:
    problems = judge(acl(ace(ME), ace(sid), owner=None))
    assert len(errors(problems)) == 1
    assert "unknown" in errors(problems)[0].message


@pytest.mark.parametrize("sid", [OWNER_RIGHTS_SID, CREATOR_OWNER_SID])
@pytest.mark.parametrize("owner", [ME, SYSTEM_SID, ADMINISTRATORS_SID])
def test_owner_relative_entry_with_a_trusted_owner_is_fine(sid: str, owner: str) -> None:
    assert judge(acl(ace(ME), ace(sid), owner=owner)) == []


def test_owner_relative_deny_entry_is_not_an_error() -> None:
    problems = judge(acl(ace(ME), ace(OWNER_RIGHTS_SID, allowed=False), owner=OTHER))
    assert errors(problems) == []


def test_owner_relative_error_suppresses_the_inherits_warning() -> None:
    problems = judge(acl(ace(ME), ace(OWNER_RIGHTS_SID), owner=OTHER, protected=False))
    assert not any("inherits" in p.message for p in problems)


# --- hostile and unusual path arguments --------------------------------------------------------


def test_check_private_accepts_pathlike(tmp_path: Path) -> None:
    d = tmp_path / "d"
    fsperm.ensure_private_dir(str(d))
    assert fsperm.check_private(d) == []
    missing = fsperm.check_private(tmp_path / "missing")
    assert [p.severity for p in missing] == ["error"]
    assert missing[0].path == str(tmp_path / "missing")


@pytest.mark.parametrize("bad", [b"some/bytes", 42, None, object()])
def test_check_private_with_a_wrong_type_is_an_error_not_an_exception(bad: object) -> None:
    problems = fsperm.check_private(bad)  # type: ignore[arg-type]
    assert [p.severity for p in problems] == ["error"]
    assert "invalid path" in problems[0].message


def test_check_private_with_a_nul_names_the_problem(tmp_path: Path) -> None:
    existing = tmp_path / "exists"
    existing.mkdir()
    for hostile in (str(existing) + "\0junk", "\0", "bad\0name"):
        problems = fsperm.check_private(hostile)
        assert [p.severity for p in problems] == ["error"]
        assert "NUL" in problems[0].message


def test_ensure_functions_accept_pathlike(tmp_path: Path) -> None:
    home = tmp_path / "home"
    fsperm.ensure_private_dir(home)
    f = home / "x.log"
    f.write_text("x", encoding="utf-8")
    fsperm.ensure_private_file(f)
    assert fsperm.check_private(home) == []
    assert fsperm.check_private(f) == []


def test_ensure_functions_reject_bytes_before_touching_the_disk(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        fsperm.ensure_private_dir(os.fsencode(tmp_path / "never"))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        fsperm.ensure_private_file(os.fsencode(tmp_path))  # type: ignore[arg-type]
    assert not (tmp_path / "never").exists()


def test_ensure_functions_raise_oserror_for_a_nul_and_create_nothing(tmp_path: Path) -> None:
    with pytest.raises(OSError, match="NUL"):
        fsperm.ensure_private_dir(str(tmp_path / "a" / "x\0junk"))
    assert not (tmp_path / "a").exists(), "nothing may be created for a path we cannot honour"
    f = tmp_path / "f.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(OSError, match="NUL"):
        fsperm.ensure_private_file(str(f) + "\0junk")


# --- ensure_* never report success on a path that is still not private -------------------------


def _fake_check(path: str) -> list[PermProblem]:
    return [PermProblem(path, "error", "ACL entry grants access to Everyone (S-1-1-0)")]


def test_ensure_private_dir_raises_when_the_result_is_still_not_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fsperm, "check_private", _fake_check)
    with pytest.raises(OSError, match="Everyone") as raised:
        fsperm.ensure_private_dir(str(tmp_path / "d"))
    assert "S-1-1-0" in str(raised.value)
    assert "could not make" in str(raised.value)


def test_ensure_private_file_raises_when_the_result_is_still_not_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = tmp_path / "f.txt"
    f.write_text("x", encoding="utf-8")
    monkeypatch.setattr(fsperm, "check_private", _fake_check)
    with pytest.raises(OSError, match="Everyone"):
        fsperm.ensure_private_file(str(f))


def test_warnings_alone_do_not_make_ensure_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def only_a_warning(path: str) -> list[PermProblem]:
        return [PermProblem(path, "warning", "a deny entry exists")]

    monkeypatch.setattr(fsperm, "check_private", only_a_warning)
    fsperm.ensure_private_dir(str(tmp_path / "d"))


# --- links ---------------------------------------------------------------------------------------


class _FakeStat:
    def __init__(self, attributes: int, tag: int) -> None:
        self.st_file_attributes = attributes
        self.st_reparse_tag = tag


@pytest.mark.parametrize(
    ("attributes", "tag", "expected"),
    [
        (0x410, 0xA0000003, True),  # junction (mount point)
        (0x400, 0xA000000C, True),  # symbolic link
        (0x10, 0, False),  # plain directory
        (0x20, 0, False),  # plain file
        (0x400, 0x9000001A, False),  # cloud placeholder: a reparse point that does not redirect
    ],
)
def test_redirecting_links_are_recognized_by_attribute_and_tag(
    monkeypatch: pytest.MonkeyPatch, attributes: int, tag: int, expected: bool
) -> None:
    monkeypatch.setattr(os, "lstat", lambda path: _FakeStat(attributes, tag))
    assert fsperm._is_redirecting_link("anything") is expected


def test_a_path_that_cannot_be_lstatted_is_not_a_link(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(path: str) -> object:
        raise PermissionError("denied")

    monkeypatch.setattr(os, "lstat", refuse)
    assert fsperm._is_redirecting_link("anything") is False


@pytest.mark.posix
def test_posix_symlink_is_followed_and_the_target_judged(tmp_path: Path) -> None:
    real = tmp_path / "real"
    fsperm.ensure_private_dir(str(real))
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    assert fsperm.check_private(str(link)) == []
    os.chmod(real, 0o755)  # noqa: S103 - the test needs a deliberately wide mode
    assert [p.severity for p in fsperm.check_private(str(link))] == ["error"]
    fsperm.ensure_private_dir(str(link))
    assert stat.S_IMODE(os.stat(real).st_mode) == 0o700


@contextmanager
def _junction(link: Path, target: Path) -> Iterator[Path]:
    """``mklink /J`` (no privilege needed); the junction itself is removed on exit."""
    cmd = os.path.join(os.environ["SYSTEMROOT"], "System32", "cmd.exe")
    result = subprocess.run(
        [cmd, "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False
    )
    assert result.returncode == 0, result.stdout[-300:] + result.stderr[-300:]
    try:
        yield link
    finally:
        os.rmdir(link)  # removes the junction only, never its target


@pytest.mark.windows
def test_windows_junction_to_a_public_directory_is_not_reported_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from boundkeep.ipc import winsec

    target = tmp_path / "public-target"
    target.mkdir()
    _icacls_grant_everyone(target)
    before = winsec.read_acl_of_path(str(target))
    writes: list[str] = []
    monkeypatch.setattr(
        winsec, "set_private_acl", lambda path, include_system=True: writes.append(path)
    )
    with _junction(tmp_path / "home", target) as home:
        problems = fsperm.check_private(str(home))
        assert [p.severity for p in problems] == ["error"]
        assert "junction" in problems[0].message
        assert str(target) in problems[0].message

        with pytest.raises(OSError, match="junction"):
            fsperm.ensure_private_dir(str(home))
        with pytest.raises(OSError, match="junction"):
            fsperm.ensure_private_file(str(home))
    # Refused BEFORE any ACL is written: neither the target nor the junction itself was touched.
    assert writes == []
    assert winsec.read_acl_of_path(str(target)) == before


@pytest.mark.windows
def test_windows_dangling_junction_is_an_error(tmp_path: Path) -> None:
    target = tmp_path / "gone-soon"
    target.mkdir()
    with _junction(tmp_path / "home", target) as home:
        os.rmdir(target)
        problems = fsperm.check_private(str(home))
        assert [p.severity for p in problems] == ["error"]
        assert "junction" in problems[0].message
        with pytest.raises(OSError, match="junction"):
            fsperm.ensure_private_dir(str(home))


@pytest.mark.windows
def test_windows_a_real_directory_below_a_junction_is_judged_for_what_it_is(
    tmp_path: Path,
) -> None:
    # Only the LEAF matters: a link higher up leads to the real directory, whose ACL is what counts.
    real = tmp_path / "real"
    fsperm.ensure_private_dir(str(real))
    with _junction(tmp_path / "via", real) as via:
        leaf = via / "leaf"
        fsperm.ensure_private_dir(str(leaf))
        assert fsperm.check_private(str(leaf)) == []
        assert (real / "leaf").is_dir()


# --- Windows: ensure_* failure paths ---------------------------------------------------------


@pytest.mark.windows
def test_windows_ensure_private_dir_raises_when_the_acl_could_not_be_fixed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from boundkeep.ipc import winsec

    d = tmp_path / "d"
    d.mkdir()
    _icacls_grant_everyone(d)
    monkeypatch.setattr(winsec, "set_private_acl", lambda path, include_system=True: None)
    with pytest.raises(OSError, match="Everyone") as raised:
        fsperm.ensure_private_dir(str(d))
    assert "S-1-1-0" in str(raised.value)


@pytest.mark.windows
def test_windows_ensure_private_file_raises_when_the_acl_could_not_be_fixed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from boundkeep.ipc import winsec

    f = tmp_path / "f.txt"
    f.write_text("x", encoding="utf-8")
    exe = os.path.join(os.environ["SYSTEMROOT"], "System32", "icacls.exe")
    granted = subprocess.run(
        [exe, str(f), "/grant", "*S-1-1-0:R"], capture_output=True, check=False
    )
    assert granted.returncode == 0
    monkeypatch.setattr(winsec, "set_private_acl", lambda path, include_system=True: None)
    with pytest.raises(OSError, match="Everyone"):
        fsperm.ensure_private_file(str(f))


@pytest.mark.windows
def test_windows_an_error_from_set_private_acl_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from boundkeep.ipc import winsec

    def denied(path: str, include_system: bool = True) -> None:
        raise PermissionError("denied")

    d = tmp_path / "d"
    d.mkdir()
    _icacls_grant_everyone(d)
    monkeypatch.setattr(winsec, "set_private_acl", denied)
    with pytest.raises(PermissionError):
        fsperm.ensure_private_dir(str(d))
    f = tmp_path / "f.txt"
    f.write_text("x", encoding="utf-8")
    exe = os.path.join(os.environ["SYSTEMROOT"], "System32", "icacls.exe")
    subprocess.run([exe, str(f), "/grant", "*S-1-1-0:R"], capture_output=True, check=True)
    with pytest.raises(PermissionError):
        fsperm.ensure_private_file(str(f))


@pytest.mark.windows
def test_windows_nul_path_leaves_the_real_acl_alone(tmp_path: Path) -> None:
    from boundkeep.ipc import winsec

    victim = tmp_path / "victim"
    victim.mkdir()
    before = winsec.read_acl_of_path(str(victim))
    with pytest.raises(OSError, match="NUL"):
        fsperm.ensure_private_file(str(victim) + "\0junk")
    with pytest.raises(OSError, match="NUL"):
        fsperm.ensure_private_dir(str(victim) + "\0junk")
    assert winsec.read_acl_of_path(str(victim)) == before


@pytest.mark.windows
def test_windows_owner_rights_entry_with_a_foreign_owner_is_an_error_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from boundkeep.ipc import winsec

    d = tmp_path / "d"
    fsperm.ensure_private_dir(str(d))
    real = winsec.read_acl_of_path(str(d))
    foreign = AclInfo(
        OTHER,
        real.dacl_present,
        real.dacl_protected,
        (*real.aces, AceInfo(OWNER_RIGHTS_SID, None, True, 0x1F01FF, False)),
        real.sddl,
    )
    monkeypatch.setattr(winsec, "read_acl_of_path", lambda path: foreign)
    problems = fsperm.check_private(str(d))
    assert any(p.severity == "error" and OTHER in p.message for p in problems)


@pytest.mark.windows
def test_windows_long_path_with_extended_prefix(tmp_path: Path) -> None:
    deep = tmp_path
    for index in range(10):
        deep = deep / (f"part-{index:02d}-" + "y" * 40)
    extended = "\\\\?\\" + str(deep)
    fsperm.ensure_private_dir(extended)
    assert fsperm.check_private(extended) == []
