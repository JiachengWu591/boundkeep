"""Spec revision 41: the review of revision 40 (docs/reviews/M3a-rev40-review.md).

* R40-1 (from revision 40): for every directory whose name ends in a dot, the walk asked the disk
  (``lstat``) whether the sibling a Win32 call opens exists, inside the loop that lists the parent.
  That loop is where the clock is read, so the calls were charged to the walk's 0.35 s; revision 39
  made its one call per such directory when the directory's turn came, where no clock is read.
  With thousands of dotted directories and no sibling, the first budget ended early and a ``.env``
  listed after them was not found: revision 39 denied, revision 40 asked. Now the sibling is
  read off what the parent listed, when the directory's turn comes: no disk call for a sibling
  that is not there.
* R40-3 (before revision 40): a dotted folder written by its 8.3 short name (``SECRET~1`` for
  ``secretstorage.``) was gray and sent with a backend: the written form is not walked, and the
  resolved key drops the dot. Now the names as on disk are resolved once more and walked.
* R40-4 (text): which link texts a symbolic-link sibling is entered for, pinned here.

R40-2 (the second walk's time counts against the daemon's 2 s) is a written cost, not code.
"""

from __future__ import annotations

import os
import shutil
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from boundkeep.normalize import event, paths, subtree
from tests.unit.test_m3a_rev39_review_fixes import (
    _assert_denied,
    _decide,
    _gray,
    _junction,
    _mkdir,
    _put,
    _refs,
    _reparse_point,
    _scan,
    _xp,
    windows_only,
)


@pytest.fixture(name="tree")
def _tree(tmp_path: Path) -> Iterator[Path]:
    """A folder for one layout; junctions are removed first (never what they point to), then
    the rest through extended paths (as in the revision 40 tests)."""
    root = tmp_path / "t"
    root.mkdir()
    yield root
    for dirpath, dirnames, _files in os.walk(_xp(root)):
        for name in list(dirnames):
            full = os.path.join(dirpath, name)
            if _reparse_point(full):
                os.rmdir(full)
                dirnames.remove(name)
    shutil.rmtree(_xp(root), ignore_errors=True)


# ------------------------------------------------------------------ R40-1: the sibling, listed


@windows_only
def test_a_slow_disk_is_not_charged_for_dotted_folders_while_their_parent_is_listed(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 200 dotted folders without a sibling, then the folder that holds .env. Every lstat costs
    # 10 ms of a made-up clock: revision 40 made one per dotted folder while it listed "sub",
    # and the clock, read every 64 entries, ended the walk (0.35 s) before "zz" was opened.
    for i in range(200):
        _mkdir(tree / "sub" / f"d{i:03}.")
    _put(tree / "sub" / "zz" / ".env")
    clock = [0.0]
    real_lstat = os.lstat

    def slow_lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
        clock[0] += 0.01
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", slow_lstat)
    monkeypatch.setattr(subtree, "time", types.SimpleNamespace(monotonic=lambda: clock[0]))
    result, budget = _scan(tree / "sub", defer=True)
    assert result.status == "ok"
    assert {h.rel for h in result.hits} == {"zz/.env"}
    assert budget.entries == 202
    # one lstat per folder since spec revision 42 (R41-1: NTFS may open a name the listing does
    # not show), made when each folder's turn comes, where revision 39 opened it: none of it
    # while "sub" was listed, so "zz" is still reached
    assert clock[0] == pytest.approx(2.0)


@windows_only
def test_a_sibling_the_parent_did_not_list_is_asked_once_when_its_turn_comes(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # no sibling ("d0." .. "d4."), or a plain file of that name ("e"; the listing keeps only
    # folders and links): revision 39 opened each once and failed; revision 40 asked lstat for
    # each while listing "sub"; revision 41 asked nothing, and missed the folders NTFS opens by
    # an 8.3 name; since revision 42 each is asked once, when its turn comes (R41-1)
    for i in range(5):
        _mkdir(tree / "sub" / f"d{i}.")
    _mkdir(tree / "sub" / "e.")
    _put(tree / "sub" / "e", "x\n")
    _put(tree / "sub" / "zz" / ".env")
    opened: list[str] = []
    asked: list[str] = []
    real_scandir = os.scandir

    def scandir(path: Any) -> Any:
        opened.append(os.path.basename(path))
        return real_scandir(path)

    def alias_state(path: str) -> int:
        asked.append(path)
        return subtree._MISSING

    monkeypatch.setattr(os, "scandir", scandir)
    monkeypatch.setattr(subtree, "_alias_state", alias_state)
    result, _ = _scan(tree / "sub", defer=True)
    assert opened == ["sub", "zz"]
    assert sorted(os.path.basename(p) for p in asked) == ["d0", "d1", "d2", "d3", "d4", "e"]
    assert {h.rel for h in result.hits} == {"zz/.env"}
    assert len(result.deferred) == 6  # the names as on disk: for the second walk, as before


@windows_only
def test_a_sibling_that_is_a_folder_is_opened_where_revision_39_opened_it(tree: Path) -> None:
    # breadth first: "a." stands before "b" in the listing, so what a Win32 reader lists for
    # "a." (the folder "a") is walked before "b", under the name "a."
    _put(tree / "sub" / "a" / ".env")
    _mkdir(tree / "sub" / "a.")
    _put(tree / "sub" / "b" / ".env")
    result, _ = _scan(tree / "sub", defer=True)
    assert [h.rel for h in result.hits if not h.extra] == ["a/.env", "a./.env", "b/.env"]


@windows_only
def test_a_sibling_spelled_in_another_case_is_the_one_a_win32_reader_lists(tree: Path) -> None:
    _mkdir(tree / "sub" / "Inner.")
    _put(tree / "sub" / "INNER" / ".env")
    result, _ = _scan(tree / "sub", defer=True)
    assert {h.rel for h in result.hits if not h.extra} == {"INNER/.env", "Inner./.env"}


@windows_only
def test_a_sibling_that_is_a_junction_is_entered_without_asking(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mkdir(tree / "sub" / "inner2.")
    _put(tree / "secretsz" / ".env")
    _junction(tree / "sub" / "inner2", tree / "secretsz")
    asked: list[str] = []
    monkeypatch.setattr(subtree, "_alias_state", lambda path: asked.append(path) or subtree._ENTER)
    result, _ = _scan(tree / "sub", defer=True)
    assert {h.rel for h in result.hits if not h.extra} == {"inner2./.env"}
    assert asked == []


@windows_only
def test_a_sibling_the_walk_may_not_open_is_not_opened(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # (a stand-in for a symbolic link to a share: the refusal is made when the folder's turn
    # comes, and nothing below the sibling is read)
    _mkdir(tree / "sub" / "inner.")
    _put(tree / "sub" / "inner" / "deep" / ".env")
    opened: list[str] = []
    real_scandir = os.scandir

    def scandir(path: Any) -> Any:
        opened.append(os.path.basename(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", scandir)
    monkeypatch.setattr(
        subtree,
        "_sibling_state",
        lambda listed, name, path: subtree._REFUSE if name == "inner" else subtree._MISSING,
    )
    result, _ = _scan(tree / "sub", defer=True)
    assert result.status == "unreadable"
    assert opened == ["sub", "inner", "deep"]  # "inner" as itself, once; never for "inner."
    assert {h.rel for h in result.hits} == {"inner/deep/.env"}


class _Entry:
    """A stand-in for an ``os.DirEntry`` (no symlink privilege on the test machine)."""

    def __init__(
        self, *, folder: bool = False, reparse: bool = False, symlink: bool = False
    ) -> None:
        self._folder, self._reparse, self._symlink = folder, reparse, symlink
        self.broken = False

    def is_symlink(self) -> bool:
        if self.broken:
            raise OSError("cannot classify")
        return self._symlink

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        return self._folder

    def stat(self, *, follow_symlinks: bool = True) -> Any:
        return types.SimpleNamespace(st_file_attributes=0x400 if self._reparse else 0)


@windows_only
def test_what_the_listing_says_of_a_sibling(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []
    monkeypatch.setattr(subtree, "_alias_state", lambda path: asked.append(path) or subtree._REFUSE)
    listed = subtree._Listed()
    odd = _Entry()
    odd.broken = True
    entries: dict[str, Any] = {
        "folder": _Entry(folder=True),
        "junction": _Entry(folder=True, reparse=True),
        "reparse": _Entry(reparse=True),  # some other reparse point: opened as revision 39 did
        "link": _Entry(symlink=True),
        "odd": odd,
        "UPPER": _Entry(folder=True),
    }
    listed.names.update(entries)
    states = {name: subtree._sibling_state(listed, name, "P:" + name) for name in entries}
    states["upper"] = subtree._sibling_state(listed, "upper", "P:upper")
    states["absent"] = subtree._sibling_state(listed, "absent", "P:absent")
    assert states == {
        "folder": subtree._ENTER,
        "junction": subtree._ENTER,
        "reparse": subtree._ENTER,
        "link": subtree._REFUSE,  # asked of the disk, as revision 40 asked
        "odd": subtree._REFUSE,  # could not be classified: asked too
        "UPPER": subtree._ENTER,
        "upper": subtree._ENTER,  # the name NTFS compares equal
        "absent": subtree._REFUSE,  # not listed: asked of the disk (revision 42, R41-1)
    }
    assert asked == ["P:link", "P:odd", "P:absent"]


@windows_only
def test_an_entry_that_could_not_be_classified_is_still_found_as_a_sibling(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "inner" cannot be classified while "sub" is listed (the walk says unreadable and treats it
    # as a file); what a Win32 reader lists for "inner." is that entry all the same
    _mkdir(tree / "sub" / "inner.")
    _put(tree / "sub" / "inner" / ".env")
    real_is_link = subtree._is_link
    failed: list[str] = []

    def is_link(entry: Any) -> bool:
        if entry.name == "inner" and not failed:
            failed.append(entry.name)
            raise OSError("cannot classify")
        return real_is_link(entry)

    monkeypatch.setattr(subtree, "_is_link", is_link)
    result, _ = _scan(tree / "sub", defer=True)
    assert failed == ["inner"]
    assert result.status == "unreadable"
    assert {h.rel for h in result.hits if not h.extra} == {"inner./.env"}


# ------------------------------------------------------------------ R40-3: 8.3 short names


def _short(path: Path) -> str:
    """The 8.3 name of ``path``'s last segment (the test is skipped on a volume without them)."""
    import ctypes

    buffer = ctypes.create_unicode_buffer(1024)
    length = ctypes.windll.kernel32.GetShortPathNameW(_xp(path), buffer, 1024)  # type: ignore[attr-defined,unused-ignore]
    name = os.path.basename(buffer.value.rstrip("\\")) if length else ""
    if "~" not in name:
        pytest.skip("this volume makes no 8.3 names")
    return name


@windows_only
@pytest.mark.parametrize(
    ("tool", "template"),
    [
        ("Bash", "rg made {}"),
        ("Bash", "grep -r made {}"),
        ("Bash", "tar -czf o.tgz {}"),
        ("Bash", "cp -r {} b"),
        ("PowerShell", "Copy-Item -Recurse {} b"),
        ("Grep", "{}"),
    ],
)
def test_a_dotted_folder_written_by_its_short_name_is_denied(
    tree: Path, tool: str, template: str
) -> None:
    # Git Bash's grep -rl SECRET~1 lists SECRET~1/.env (measured in the review)
    _put(tree / "secretstorage." / ".env")
    _assert_denied(tree, tool, template.format(_short(tree / "secretstorage.")))


@windows_only
@pytest.mark.parametrize(
    ("tool", "template"),
    [("Bash", "rg made {}/k9."), ("PowerShell", "Copy-Item -Recurse {}\\k9. b")],
)
def test_a_dotted_folder_below_a_short_name_is_denied(tree: Path, tool: str, template: str) -> None:
    _put(tree / "deeperfolder" / "k9." / ".env")
    _assert_denied(tree, tool, template.format(_short(tree / "deeperfolder")))


@windows_only
def test_a_dotted_junction_below_a_short_name_is_a_path_of_its_own(tree: Path) -> None:
    _put(tree / "deeperfolder" / "k9" / "a.txt", "x\n")
    _put(tree / "secretsz" / ".env")
    _junction(tree / "deeperfolder" / "k9.", tree / "secretsz")
    short = _short(tree / "deeperfolder")
    target = paths.windows_fold(str(tree / "secretsz").replace("\\", "/"))
    refs = [r for r in _refs(tree, "Bash", f"rg made {short}/k9.") if r.key == target]
    assert len(refs) == 1
    assert paths.EXTRA_READING in refs[0].reasons
    _assert_denied(tree, "Bash", f"rg made {short}/k9.")


@windows_only
def test_a_clean_dotted_folder_written_by_its_short_name_stays_gray(tree: Path) -> None:
    _put(tree / "cleanstorage." / "a.txt", "x\n")
    short = _short(tree / "cleanstorage.")
    decision, _ = _decide(tree, "Bash", f"rg made {short}", backend=False)
    assert (decision.decision, decision.decided_by) == ("ask", "gray")
    decision, fake = _decide(tree, "Bash", f"rg made {short}", backend=True)
    assert fake is not None
    assert fake.requests  # still for the model, as before


@windows_only
def test_the_short_names_lookup_is_one_of_the_reading_lookups(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _put(tree / "secretstorage." / ".env")
    short = _short(tree / "secretstorage.")
    assert "budget:reading-lookups" not in _gray(tree, "Bash", f"rg made {short}")
    monkeypatch.setattr(event, "MAX_READING_DISK_KEYS", 0)
    assert "budget:reading-lookups" in _gray(tree, "Bash", f"rg made {short}")
    decision, fake = _decide(tree, "Bash", f"rg made {short}", backend=True)
    assert decision.decision == "ask"
    assert fake is not None
    assert not fake.requests  # not analysed whole: never sent


@windows_only
def test_git_add_looks_into_a_dotted_folder_written_by_its_short_name(tree: Path) -> None:
    _put(tree / "secretstorage." / ".env")
    short = _short(tree / "secretstorage.")
    assert "git-add-may-stage-protected" in _gray(tree, "Bash", f"git add {short}")


@windows_only
def test_a_short_name_without_a_dotted_name_behind_it_adds_no_lookup(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _put(tree / "plainlongfolder" / "a.txt", "x\n")
    short = _short(tree / "plainlongfolder")
    monkeypatch.setattr(event, "MAX_READING_DISK_KEYS", 0)  # any reading lookup would leave a note
    assert "budget:reading-lookups" not in _gray(tree, "Bash", f"rg made {short}")


# ------------------------------------------------------------------ R40-4: link texts (pinned)


def test_a_symlinked_sibling_is_entered_for_three_ways_to_write_its_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # X:\..., \\?\X:\... and a relative text; any other way to write a local target is refused
    # (gray), a written cost of revision 40 that revision 41 spells out
    link = "\\\\?\\C:\\p\\inner"
    symlink = os.stat_result((0o120777,) + (0,) * 9)
    real_lstat = os.lstat
    target = ""

    def lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if path == link:
            return symlink
        if isinstance(path, str) and path.startswith("\\\\?\\C:\\made-up-"):
            raise FileNotFoundError(path)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "readlink", lambda path, *a, **k: target)
    monkeypatch.setattr(paths, "is_fixed_drive", lambda letter: letter.lower() == "c")
    for target, state in [
        ("C:\\made-up-x", subtree._ENTER),
        ("\\\\?\\C:\\made-up-x", subtree._ENTER),
        ("made-up-x", subtree._ENTER),
        ("\\made-up-x", subtree._REFUSE),
        ("C:/made-up-x", subtree._REFUSE),
        ("C:made-up-x", subtree._REFUSE),
        ("\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\x", subtree._REFUSE),
        ("\\\\.\\C:\\made-up-x", subtree._REFUSE),
    ]:
        assert subtree._alias_state(link) == state, target


# ------------------------------------------------------------------ revision 40: spent expansion


@windows_only
def test_a_spent_second_expansion_leaves_the_rest_of_the_line_on_disk(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the glob again with the names as on disk runs out of its time: a gray, unanalysed note,
    # and nothing raises, so a deny only the disk shows later in the line stays (revision 40
    # had no test of its own for this; a timing failure in another test had counted as one)
    _put(tree / "secretsz" / ".env")
    _junction(tree / "docs", tree / "secretsz")
    _mkdir(tree / "ka.")
    real = paths.expand_glob
    second: list[str] = []

    def expand_glob(path: paths.NormPath, **kwargs: Any) -> paths.GlobResult:
        if kwargs.get("literal"):
            second.append(path.raw)
            return paths.GlobResult((), "budget")
        return real(path, **kwargs)

    monkeypatch.setattr(paths, "expand_glob", expand_glob)
    assert "budget:reading-lookups" in _gray(tree, "Bash", "ls ka*")
    assert second
    _assert_denied(tree, "Bash", "ls ka*; rg made docs")
