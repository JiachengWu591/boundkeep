"""Spec revision 42: the review of revision 41 (docs/reviews/M3a-rev41-review.md).

* R41-1 (from revision 41): the sibling a Win32 call opens for a dotted name was looked up only
  among the long names its parent listed. NTFS also opens a folder by its 8.3 name, and compares
  case by the volume's table, which merges more than ``windows_fold``. A folder ``JLONGN~1.``
  next to the junction ``jlongname`` (8.3 name ``JLONGN~1``) let ``Grep`` read what the junction
  leads to while the rule allowed it. Now a name the listing does not show is asked of the disk
  when the folder's turn comes, as revision 39 opened it.
* R41-3 (before revision 40): the ways of writing a dotted folder R40-3 left out: an 8.3 name
  followed by a dot (``VAULTS~1.``), a long name that looks like an 8.3 name (``notes~1.``), and
  a ``cd`` into an 8.3 name. Now they are walked too.
* R41-4 (before revision 40): a glob whose written part holds an 8.3 name was not expanded:
  ``cat PLAINL~1/.e*`` was gray and sent with a backend, and Git Bash printed the ``.env``.

R41-2 (R40-3's lookup and walk share revision 40's per-request budgets) is a written cost.

The last two tests close gaps the mutants of revision 42 showed: the room the second glob
expansion is left (revision 40's own test never left it more than its room; earlier mutant runs
counted chance failures of other tests as catches), and that a sibling the listing shows is not
asked of the disk.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterator
from pathlib import Path

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
from tests.unit.test_m3a_rev40_review_fixes import _short


@pytest.fixture(name="tree")
def _tree(tmp_path: Path) -> Iterator[Path]:
    """A project folder for one layout (``tmp_path/o`` is outside it); junctions are removed
    first (never what they point to), then the rest through extended paths."""
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


def _outside_secret(tree: Path) -> Path:
    """A folder outside the project that holds a made-up ``.env``."""
    folder = tree.parent / "o" / "secretsz"
    _put(folder / ".env")
    return folder


# ------------------------------------------------------------------ R41-1: names NTFS also opens


@windows_only
@pytest.mark.parametrize(
    ("tool", "text"),
    [
        ("Grep", "."),
        ("Bash", "rg made ."),
        ("Bash", "tar -czf ../o.tgz ."),
        ("PowerShell", "Copy-Item -Recurse . ..\\b"),
    ],
)
def test_a_dotted_folder_named_after_a_junctions_short_name_is_followed(
    tree: Path, tool: str, text: str
) -> None:
    # a Win32 open of "JLONGN~1." opens "JLONGN~1", the junction's 8.3 name, and reads what it
    # leads to (cmd's findstr /s, Python's os.walk and .NET's GetFiles listed .env; measured)
    _junction(tree / "jlongname", _outside_secret(tree))
    _mkdir(tree / (_short(tree / "jlongname") + "."))
    _assert_denied(tree, tool, text)


@windows_only
def test_a_dotted_folder_named_after_the_short_name_of_git_is_walked_by_grep(tree: Path) -> None:
    # Grep does not read .git; a Win32 reader of "GIT~1." reads it all the same
    _put(tree / ".git" / ".env")
    _mkdir(tree / (_short(tree / ".git") + "."))
    _assert_denied(tree, "Grep", ".")


@windows_only
def test_a_sibling_ntfs_compares_equal_by_its_case_table_is_followed(tree: Path) -> None:
    # U+1F80 and U+1F88: windows_fold keeps them apart (it is made for keys), NTFS compares them
    # equal (RtlUpcaseUnicodeChar; the review counted 27 such pairs in the basic plane)
    _junction(tree / "dataᾈ", _outside_secret(tree))
    _mkdir(tree / "dataᾀ.")
    try:
        os.lstat(_xp(tree / "dataᾀ"))
    except FileNotFoundError:
        pytest.skip("this volume's case table keeps the two apart")
    assert paths.windows_fold("dataᾀ") != paths.windows_fold("dataᾈ")
    _assert_denied(tree, "Grep", ".")
    _assert_denied(tree, "Bash", "rg made .")


@windows_only
def test_without_the_dotted_folder_a_junction_is_still_not_followed_by_grep(tree: Path) -> None:
    # (the control: ripgrep does not follow a junction; only the Win32 sibling leads there)
    _junction(tree / "jlongname", _outside_secret(tree))
    decision, _ = _decide(tree, "Grep", ".", backend=False)
    assert (decision.decision, decision.decided_by) == ("none", "rule:read-inside-project")


# ------------------------------------------------------------------ R41-3: other spellings


@windows_only
@pytest.mark.parametrize(
    ("tool", "template"),
    [("Bash", "rg made {}."), ("Grep", "{}."), ("PowerShell", "Copy-Item -Recurse {}. b")],
)
def test_a_short_name_followed_by_a_dot_is_walked_where_win32_reads_it(
    tree: Path, tool: str, template: str
) -> None:
    # "VAULTS~1." is no name on disk; a Win32 reader drops the dot and opens VAULTS~1, which is
    # vaultstorage. (cmd's dir /s read .env through it)
    _put(tree / "vaultstorage." / ".env")
    _assert_denied(tree, tool, template.format(_short(tree / "vaultstorage.")))


@windows_only
@pytest.mark.parametrize(
    ("tool", "text"),
    [("Bash", "rg made notes~1."), ("Grep", "notes~1."), ("Bash", "tar -czf o.tgz notes~1.")],
)
def test_a_long_dotted_name_that_looks_like_a_short_name_is_walked(
    tree: Path, tool: str, text: str
) -> None:
    # Git Bash's grep -rl lists notes~1./.env; the disk gives the written key back unchanged
    _put(tree / "notes~1." / ".env")
    _assert_denied(tree, tool, text)


@windows_only
@pytest.mark.parametrize(
    ("tool", "template"),
    [
        ("Bash", "cd {} && rg made sub"),
        ("Bash", "cd {} && tar -czf ../o.tgz sub"),
        ("PowerShell", "Set-Location {}; Copy-Item -Recurse sub ..\\b"),
    ],
)
def test_a_folder_after_a_cd_into_a_short_name_is_walked(
    tree: Path, tool: str, template: str
) -> None:
    # Git Bash's "cd PLAINL~1 && grep -rl MADE sub" lists sub/.env
    _put(tree / "plainlongfolder" / "sub" / ".env")
    _assert_denied(tree, tool, template.format(_short(tree / "plainlongfolder")))


@windows_only
def test_a_dotted_folder_after_a_cd_into_a_short_name_is_walked(tree: Path) -> None:
    _put(tree / "deeperfolder" / "k9." / ".env")
    _assert_denied(tree, "Bash", f"cd {_short(tree / 'deeperfolder')} && rg made k9.")


@windows_only
def test_a_cd_into_a_dotted_folder_below_a_short_name_keeps_its_dot(tree: Path) -> None:
    # the folder is outside the clean project, so only the cd target can lead to the .env; the
    # working directory keeps the dot, as for "cd k9." (revision 40)
    folder = tree.parent / "o" / "deeperfolder"
    _put(folder / "k9." / ".env")
    _put(tree / "a.txt", "x\n")
    target = str(tree.parent / "o" / _short(folder) / "k9.").replace("\\", "/")
    _assert_denied(tree, "Bash", f"cd '{target}' && rg made .")


@windows_only
def test_the_written_dots_are_looked_up_when_the_disk_gives_nothing_back(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # (resolve_on_disk returns a path unchanged when it cannot look: the written text that keeps
    # its dots is still looked up through \\?\)
    _put(tree / "notes~1." / ".env")
    monkeypatch.setattr(paths, "resolve_on_disk", lambda path: path)
    _assert_denied(tree, "Bash", "rg made notes~1.")


@windows_only
def test_a_cd_into_a_short_name_keeps_the_unknown_working_directory(tree: Path) -> None:
    # where it leads is added; "unknown" stays, so the allow side sees no more than before
    _put(tree / "plainlongfolder" / "a.txt", "x\n")
    short = _short(tree / "plainlongfolder")
    assert "cwd-unknown" in _gray(tree, "Bash", f"cd {short} && cat a.txt")
    decision, _ = _decide(tree, "Bash", f"cd {short} && cat a.txt", backend=False)
    assert decision.decision == "ask"


@windows_only
def test_the_cd_lookup_is_one_of_the_reading_lookups(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _put(tree / "plainlongfolder" / "sub" / ".env")
    short = _short(tree / "plainlongfolder")
    monkeypatch.setattr(event, "MAX_READING_DISK_KEYS", 0)
    assert "budget:reading-lookups" in _gray(tree, "Bash", f"cd {short} && rg made sub")
    decision, fake = _decide(tree, "Bash", f"cd {short} && rg made sub", backend=True)
    assert decision.decision == "ask"
    assert fake is not None
    assert not fake.requests  # not analysed whole: never sent


@windows_only
def test_a_cd_target_unsure_for_another_reason_is_not_looked_up(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # an invalid character beside the 8.3 name: the disk cannot say where that leads, so it is
    # not asked (no lookup is spent), and the working directory stays unknown, as before
    _put(tree / "plainlongfolder" / "sub" / ".env")
    short = _short(tree / "plainlongfolder")
    monkeypatch.setattr(event, "MAX_READING_DISK_KEYS", 0)
    grays = _gray(tree, "Bash", f"cd '{short}/a<b' && rg made sub")
    assert "cwd-unknown" in grays
    assert "budget:reading-lookups" not in grays


@windows_only
def test_a_cd_into_a_short_name_that_is_not_there_changes_nothing(tree: Path) -> None:
    _put(tree / "sub" / "a.txt", "x\n")
    assert "cwd-unknown" in _gray(tree, "Bash", "cd NOPEXX~1 && rg made sub")


# ------------------------------------------------------------------ R41-4: globs below 8.3 names


@windows_only
@pytest.mark.parametrize("template", ["cat {}/.e*", "rg made {}/s*", "rg made {}/*"])
def test_a_glob_below_a_short_name_is_expanded(tree: Path, template: str) -> None:
    # Git Bash's "cat PLAINL~1/.e*" printed the made-up .env (measured in the review)
    _put(tree / "plainlongfolder" / ".env")
    _put(tree / "plainlongfolder" / "sub" / ".env")
    _assert_denied(tree, "Bash", template.format(_short(tree / "plainlongfolder")))


@windows_only
def test_a_dotted_match_below_a_short_name_is_walked_by_its_name_on_disk(tree: Path) -> None:
    # Git Bash's "grep -rl MADE DEEPER~1/k*" lists DEEPER~1/k9./.env
    _put(tree / "deeperfolder" / "k9." / ".env")
    _assert_denied(tree, "Bash", f"rg made {_short(tree / 'deeperfolder')}/k*")


@windows_only
def test_a_clean_glob_below_a_short_name_stays_gray(tree: Path) -> None:
    _put(tree / "plainlongfolder" / "a.txt", "x\n")
    short = _short(tree / "plainlongfolder")
    decision, _ = _decide(tree, "Bash", f"cat {short}/a*", backend=False)
    assert (decision.decision, decision.decided_by) == ("ask", "gray")
    decision, fake = _decide(tree, "Bash", f"cat {short}/a*", backend=True)
    assert fake is not None
    assert fake.requests  # still for the model, as before


@windows_only
def test_expand_glob_takes_a_short_name_in_the_written_part(tree: Path) -> None:
    _put(tree / "plainlongfolder" / "a.txt", "x\n")
    short = _short(tree / "plainlongfolder")
    text = str(tree / short).replace("\\", "/") + "/*.txt"
    norm = paths.normalize_path(text, cwd=None, home=None, dialect="bash")
    assert "short-name-unresolved" in norm.reasons
    found = paths.expand_glob(norm)
    assert found.status == "ok"
    assert [os.path.basename(m) for m in found.matches] == ["a.txt"]


def test_short_reading_only() -> None:
    short = "short-name-unresolved"
    assert paths.short_reading_only((short,))
    assert paths.short_reading_only((short, "trailing-dots-spaces-ambiguous"))
    assert not paths.short_reading_only(("trailing-dots-spaces-ambiguous",))
    assert not paths.short_reading_only((short, "glob"))


# ------------------------------------------------------------------ gaps the mutants showed


@windows_only
def test_the_second_glob_expansion_keeps_to_the_room_the_first_left(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the two expansions of "kq./*" look in two folders, the Win32 one in kq and the one that
    # keeps the dot in kq.: the second finds two the first did not, and there is room for one
    _put(tree / "kq" / "a.txt", "x\n")
    _put(tree / "kq." / "b.txt", "x\n")
    _put(tree / "kq." / "c.txt", "x\n")
    monkeypatch.setattr(event, "MAX_GLOB_MATCHES", 2)
    raws = [r.raw for r in _refs(tree, "Bash", "cat kq./*")]
    assert any(raw.endswith("\\kq\\a.txt") for raw in raws)
    assert any(raw.endswith("\\kq.\\b.txt") for raw in raws)
    assert not any(raw.endswith("\\kq.\\c.txt") for raw in raws)
    assert "glob-too-many-matches" in _gray(tree, "Bash", "cat kq./*")
    monkeypatch.setattr(event, "MAX_GLOB_MATCHES", 3)
    assert "glob-too-many-matches" not in _gray(tree, "Bash", "cat kq./*")


@windows_only
def test_a_listed_sibling_the_reader_skips_is_opened_without_asking_the_disk(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Grep skips .git, yet its listing keeps the name (spec revision 41): a Win32 reader of the
    # empty ".git." opens ".git". Only a name the listing does not show is asked of the disk.
    _mkdir(tree / "repo" / ".git.")
    _put(tree / "repo" / ".git" / "config", "[core]\n")
    asked: list[str] = []
    real = subtree._alias_state

    def spy(path: str) -> int:
        asked.append(path)
        return real(path)

    monkeypatch.setattr(subtree, "_alias_state", spy)
    result, _ = _scan(tree / "repo", skip_names=subtree.VCS_DIR_NAMES)
    assert "c:/p/.git/config" in {h.key for h in result.hits}
    assert asked == []
