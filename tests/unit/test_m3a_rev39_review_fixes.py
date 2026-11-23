"""Spec revision 40: the review of revision 39 (docs/reviews/M3a-rev39-review.md).

Up to revision 39 the rule layer read the disk with Win32 names in four places, and a Win32 call
drops trailing dots (``kq.`` opens ``kq``), while Git Bash and Node keep them:

* F-A (since M1): the subtree walk opened the next level through Win32 paths. ``sub\\inner.``
  holding ``.env`` was "missing", skipped as vanished, and ``grep -r x sub`` / ``rg x sub`` /
  ``Grep path=sub`` were ALLOWED by rule. ``.aws.`` was matched as on disk: ``**/.aws/**`` missed.
* R39-2: a recursive read walked the key only. A real folder ``kq.`` holding ``.env`` was gray.
* R39-1: a glob's match had no reading that keeps the dots, and a match ``kq.`` without ``kq``
  was dropped by the final Win32 existence check.
* F-D: ``cat kq./.e*`` expanded in ``kq`` (the key), gray, while ``cat kq./.env`` was denied.

Revision 40 reads the names as on disk and keeps walking the Win32 reading as before; what only
revision 40 looks at is walked after every other root, on a budget of its own (R39-3: the shared
budget of revision 39 is a written cost, pinned here).
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.normalize import event, paths, subtree
from boundkeep.normalize.event import normalize_event
from tests.unit.test_m3a_pipeline import policy
from tests.unit.test_m3a_x1_fixes import WIN_HOME, manipulated

windows_only = pytest.mark.skipif(
    sys.platform != "win32", reason="Windows names with a trailing dot and junctions"
)

SESSION = "00000000-0000-4000-8000-0000000000c1"


def _xp(path: Path | str) -> str:
    return "\\\\?\\" + str(path)


def _mkdir(path: Path) -> None:
    os.makedirs(_xp(path), exist_ok=True)


def _put(path: Path, text: str = "MADE_UP=1\n") -> None:
    _mkdir(path.parent)
    with open(_xp(path), "w", encoding="utf-8") as f:
        f.write(text)


def _junction(link: Path, target: Path) -> None:
    import _winapi  # type: ignore[import-not-found,unused-ignore]  # (Windows only)

    _winapi.CreateJunction(str(target), _xp(link))


def _many(folder: Path, count: int) -> None:
    _mkdir(folder)
    for i in range(count):
        with open(_xp(folder / f"f{i:04}.txt"), "w", encoding="utf-8") as f:
            f.write("x")


@pytest.fixture
def tree(tmp_path: Path) -> Iterator[Path]:
    """A folder for one layout; junctions are removed first (never what they point to), then
    the rest through ``\\\\?\\`` (without it Win32 would open ``kq`` for ``kq.``)."""
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


def _reparse_point(path: str) -> bool:
    try:
        return bool(getattr(os.lstat(path), "st_file_attributes", 0) & 0x400)
    except OSError:
        return False


def _event(proj: Path, tool: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": SESSION,
        "cwd": str(proj),
        "project_dir": str(proj),
        "tool_name": tool,
        "tool_input": tool_input,
    }


def _input(tool: str, text: str, proj: Path) -> dict[str, Any]:
    if tool == "Grep":
        return {"pattern": "made", "path": str(proj / text) if text != "." else str(proj)}
    return {"command": text}


def _decide(
    proj: Path, tool: str, text: str, *, backend: bool, env: dict[str, str] | None = None
) -> tuple[Any, FakeBackend | None]:
    pol = policy(llm=backend)
    auditor, fake = manipulated(pol) if backend else (None, None)
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        _event(proj, tool, _input(tool, text, proj)),
        mode="enforce",
        policy=pol,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": WIN_HOME, **(env or {})},
        home=WIN_HOME,
        scan_disk=True,
        auditor=auditor,
    )
    return decision, fake


def _refs(proj: Path, tool: str, text: str, env: dict[str, str] | None = None) -> list[Any]:
    actions = normalize_event(
        _event(proj, tool, _input(tool, text, proj)),
        platform="windows",
        env={"USERPROFILE": WIN_HOME, **(env or {})},
        home=WIN_HOME,
        budget_s=5,
    )
    return [r for a in actions for r in a.paths]


def _gray(proj: Path, tool: str, text: str) -> list[str]:
    actions = normalize_event(
        _event(proj, tool, _input(tool, text, proj)),
        platform="windows",
        env={"USERPROFILE": WIN_HOME},
        home=WIN_HOME,
        budget_s=5,
    )
    return [g for a in actions for g in a.gray_reasons]


def _assert_denied(proj: Path, tool: str, text: str, rule: str = "rule:no-secret-read") -> None:
    for backend in (False, True):
        decision, fake = _decide(proj, tool, text, backend=backend)
        assert (decision.decision, decision.decided_by) == ("deny", rule), (text, backend)
        assert fake is None or not fake.requests


# ------------------------------------------------------------------ the Win32 rules (strings)


def test_canonical_rel_removes_trailing_dots_and_spaces_of_every_segment() -> None:
    assert subtree.canonical_rel("inner./.env") == "inner/.env"
    assert subtree.canonical_rel(".aws. /credentials") == ".aws/credentials"
    assert subtree.canonical_rel("a. ./b..") == "a/b"
    assert subtree.canonical_rel(".../x") == ".../x"  # nothing else: kept as it is
    assert subtree.canonical_rel("plain/name.txt") == "plain/name.txt"


def test_the_win32_listing_name_drops_one_dot_after_a_non_dot() -> None:
    cases = {"a.": "a", "a..": "a..", "a ": "a ", "a. ": "a. ", "a .": "a ", "a. .": "a. "}
    for name, listed in cases.items():
        assert subtree.win32_list_name(name) == listed, name
    assert subtree.win32_open_name("a. .") == "a"
    assert subtree.win32_open_name("...") == ""


@windows_only
def test_the_win32_rules_agree_with_the_kernel() -> None:
    from nt import _getfullpathname  # type: ignore[attr-defined]

    names = "a.|a..|a...|a |a. |a .|a. .|a .. |...|. .| .|x.y.|con.|a.b|.git.|.aws.|a\u3002."
    names += "|a\t.|a.  .|a. . .|inner2."
    for name in names.split("|"):
        listed = _getfullpathname("C:\\_\\" + name + "\\*.*")  # what os.scandir asks for
        assert listed == "C:\\_\\" + subtree.win32_list_name(name) + "\\*.*", name
        opened = _getfullpathname("C:\\_\\" + name)
        assert opened.rstrip("\\") == ("C:\\_\\" + subtree.win32_open_name(name)).rstrip("\\")


# ------------------------------------------------------------------ the walk (subtree.scan)


def _scan(root: Path, **kw: Any) -> tuple[subtree.ScanResult, subtree.ScanBudget]:
    budget = subtree.ScanBudget()
    result = subtree.scan(
        str(root),
        ["c:/p"],
        windows=kw.pop("windows", True),
        matcher=subtree.matcher_for(subtree.DEFAULT_PROTECTED_GLOBS),
        budget=budget,
        **kw,
    )
    return result, budget


@windows_only
def test_a_dotted_folder_in_a_walk_is_opened_by_its_name_on_disk(tree: Path) -> None:
    _put(tree / "sub" / "a.txt", "x\n")
    _put(tree / "sub" / "inner." / ".env")
    result, _ = _scan(tree / "sub")
    keys = {h.key for h in result.hits}
    assert keys == {"c:/p/inner./.env", "c:/p/inner/.env"}  # as on disk, and as a key has it
    assert result.status == "ok"
    assert not result.deferred  # (no ``defer``: walked at the end of the same walk)


@windows_only
def test_a_deferred_dotted_folder_costs_nothing_until_it_is_resumed(tree: Path) -> None:
    # the first pass spends what revision 39 spent: a Win32 open of "inner." found nothing
    _put(tree / "sub" / "a.txt", "x\n")
    _many(tree / "sub" / "inner.", 50)
    _put(tree / "sub" / "z" / ".env")
    result, budget = _scan(tree / "sub", defer=True)
    assert budget.entries == 4  # a.txt, inner., z, z/.env: revision 39's count
    assert [h.key for h in result.hits] == ["c:/p/z/.env"]
    assert [rel for _path, rel, _inside in result.deferred] == ["inner."]
    again, budget2 = _scan(tree / "sub", resume=result)
    assert budget2.entries == 50
    assert again.status == "ok"


@windows_only
def test_the_win32_sibling_of_a_dotted_folder_is_walked_where_revision_39_read_it(
    tree: Path,
) -> None:
    # the design review's layout: an empty "inner2." and a junction "inner2" to a folder with
    # .env. A Win32 lister of "inner2." reads the junction; only "\\?\" would lose that deny.
    _mkdir(tree / "sub2" / "inner2.")
    _put(tree / "secretsz" / ".env")
    _junction(tree / "sub2" / "inner2", tree / "secretsz")
    result, budget = _scan(tree / "sub2", defer=True)
    keys = {h.key for h in result.hits}
    assert "c:/p/inner2./.env" in keys
    assert "c:/p/inner2/.env" in keys
    assert budget.entries == 3  # sub2's two entries and .env: revision 39's count, first pass
    assert result.dir_links  # the junction itself, listed on its own, is not followed
    assert [rel for _p, rel, _i in result.deferred] == ["inner2."]  # (empty as on disk)


@windows_only
def test_a_dotted_file_is_asked_what_revision_39_asked_of_its_win32_name(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # a Win32 stat of "x." is a stat of "x": its link count, and whether a link leads to a folder
    _put(tree / "sub" / "other.txt", "x\n")
    os.link(tree / "sub" / "other.txt", tree / "sub" / "x")
    _put(tree / "sub" / "x.", "x\n")
    result, _ = _scan(tree / "sub", select=lambda rel, name: name == "x.")
    assert result.hard_links  # "x." itself has one name; "x" (what Win32 opens) has two
    _put(tree / "links" / "y.", "x\n")
    _mkdir(tree / "links" / "y")
    monkeypatch.setattr(subtree, "_is_link", lambda entry: entry.name == "y.")
    result, _ = _scan(tree / "links")
    assert result.dir_links  # (no symlink privilege here: "y." stands in for a file link)


@windows_only
def test_a_dotted_protected_folder_matches_with_its_dots_removed(tree: Path) -> None:
    _put(tree / "sub" / ".aws." / "credentials")
    result, _ = _scan(tree / "sub")
    assert {(h.key, h.is_dir) for h in result.hits} == {("c:/p/.aws.", True), ("c:/p/.aws", True)}
    # an empty ".git." next to ".git": the Win32 sibling is walked, ".git" itself is skipped
    _mkdir(tree / "repo" / ".git.")
    _put(tree / "repo" / ".git" / "config", "[core]\n")
    result, _ = _scan(tree / "repo", skip_names=subtree.VCS_DIR_NAMES)
    assert "c:/p/.git/config" in {h.key for h in result.hits}


@windows_only
def test_a_walk_of_another_flavor_reads_as_before(tree: Path) -> None:
    # windows=False: no "\\?\" root, no sibling, no key without the dots (POSIX is unchanged)
    _put(tree / "sub" / "inner." / ".env")
    result, budget = _scan(tree / "sub", windows=False)
    assert result.hits == []
    assert budget.entries == 1


@windows_only
def test_the_hit_cap_counts_entries_not_keys(tree: Path) -> None:
    for i in range(40):
        _put(tree / "sub" / f"s{i:02}.pem.", "x\n")  # each one reported under two keys
    result, _ = _scan(tree / "sub")
    assert len({h.rel for h in result.hits}) == 40  # revision 39 reported up to 64 entries
    assert len(result.hits) == 80


def test_a_symlinked_sibling_is_entered_only_on_a_fixed_drive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # the link is read as text, never followed to find out where it goes (a share would get
    # the user's credentials before any verdict)
    link, local, chain = "\\\\?\\C:\\p\\inner", "\\\\?\\C:\\elsewhere", "\\\\?\\C:\\chain"
    symlink = os.stat_result((0o120777,) + (0,) * 9)
    folder = os.stat_result((0o040777,) + (0,) * 9)
    real_lstat, real_readlink = os.lstat, os.readlink
    target = ""

    def lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if path in (link, chain):
            return symlink
        if path == local:
            return folder
        return real_lstat(path, *args, **kwargs)

    def readlink(path: Any, *args: Any, **kwargs: Any) -> Any:
        return target if path == link else real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)  # (other paths reach the real ones)
    monkeypatch.setattr(os, "readlink", readlink)
    monkeypatch.setattr(paths, "is_fixed_drive", lambda letter: letter.lower() == "c")
    for target, enterable in [
        ("\\\\?\\UNC\\server\\share", False),
        ("\\\\server\\share", False),
        ("\\rooted", False),
        ("D:\\elsewhere", False),
        ("C:\\chain", False),  # a link to a link: not followed further (a written cost)
        ("C:\\elsewhere", True),
    ]:
        assert subtree._alias_enterable(link) is enterable, target


@windows_only
def test_a_sibling_the_walk_may_not_open_makes_the_walk_unreadable(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mkdir(tree / "sub" / "inner.")
    _mkdir(tree / "sub" / "inner")
    # (revision 41: the walk reads a plain sibling off the listing; the stand-in is at that seam)
    monkeypatch.setattr(subtree, "_sibling_state", lambda listed, name, path: subtree._REFUSE)
    result, _ = _scan(tree / "sub", defer=True)
    assert result.status == "unreadable"


# ------------------------------------------------------------------ glob expansion


def _glob(text: str, **kw: Any) -> paths.GlobResult:
    norm = paths.normalize_path(text, cwd=None, home=None, dialect="tool", literal=True)
    return paths.expand_glob(norm, **kw)


@windows_only
def test_a_dotted_match_without_its_sibling_survives_the_literal_expansion(tree: Path) -> None:
    _put(tree / "kq." / ".env")
    win32 = _glob(str(tree / "???"))
    assert win32.matches == ()  # revision 39: dropped by the Win32 lexists
    assert win32.dotted
    literal = _glob(str(tree / "???"), literal=True)
    assert [m.casefold() for m in literal.matches] == [str(tree / "kq.").casefold()]
    below = _glob(str(tree / "???" / ".e*"), literal=True)
    assert [m.casefold() for m in below.matches] == [str(tree / "kq." / ".env").casefold()]


@windows_only
def test_a_glob_without_dotted_names_expands_as_before(tree: Path) -> None:
    for name in ("a.txt", "b.txt"):
        _put(tree / name, "x\n")
    plain = _glob(str(tree / "*.txt"))
    assert not plain.dotted
    assert len(plain.matches) == 2
    assert _glob(str(tree / "*.txt"), literal=True).matches == plain.matches


@windows_only
def test_a_kept_text_is_expanded_with_its_dots(tree: Path) -> None:
    _put(tree / "kq." / ".env")
    kept = paths.reading_text(str(tree / "kq." / ".e*"), cwd=None, home=None)
    assert kept is not None
    norm = paths.NormPath(kept, paths.windows_fold(kept), "windows", True, True, ("glob",))
    assert len(paths.expand_glob(norm, literal=True).matches) == 1
    assert paths.expand_glob(norm).matches == ()  # through Win32 "kq." is "kq": nothing


# ------------------------------------------------------------------ whole verdicts: F-A


@windows_only
@pytest.mark.parametrize("layout", ["N", "N2", "DD"])
@pytest.mark.parametrize(
    ("tool", "text"),
    [
        ("Bash", "grep -r made sub"),  # revision 39: allowed (allow-read-filters)
        ("Bash", "rg made sub"),  # revision 39: allowed (allow-rg-inside-project)
        ("Bash", "tar -czf o.tgz sub"),
        ("PowerShell", "Copy-Item -Recurse sub b"),
        ("Grep", "sub"),  # revision 39: allowed (read-inside-project)
    ],
)
def test_a_secret_in_a_dotted_folder_below_a_read_directory_is_denied(
    tree: Path, layout: str, tool: str, text: str
) -> None:
    _put(tree / "sub" / "a.txt", "x\n")
    if layout == "DD":
        _put(tree / "sub" / "a." / "b." / ".env")  # two dotted levels
    else:
        _put(tree / "sub" / "inner." / ".env")
    if layout == "N2":
        _put(tree / "sub" / "inner" / "b.txt", "x\n")  # a plain sibling with nothing in it
    _assert_denied(tree, tool, text)


@windows_only
@pytest.mark.parametrize(
    ("tool", "text"),
    [("Bash", "grep -r made sub"), ("Bash", "rg made sub"), ("Grep", "sub")],
)
def test_a_dotted_credential_store_below_a_read_directory_is_denied(
    tree: Path, tool: str, text: str
) -> None:
    _put(tree / "sub" / ".aws." / "credentials")
    _assert_denied(tree, tool, text, "rule:no-credential-store-read")


@windows_only
def test_the_git_config_behind_an_empty_dotted_twin_is_seen_by_grep(tree: Path) -> None:
    _mkdir(tree / ".git.")
    _put(tree / ".git" / "config", "[core]\n")
    _assert_denied(tree, "Grep", ".", "rule:no-credential-store-read")


@windows_only
@pytest.mark.parametrize(
    ("tool", "text"),
    [
        ("Bash", "grep -r made sub2"),
        ("Bash", "rg made sub2"),
        ("PowerShell", "Copy-Item -Recurse sub2 b"),
        ("Grep", "sub2"),
    ],
)
def test_the_junction_a_win32_reader_lists_for_a_dotted_folder_stays_denied(
    tree: Path, tool: str, text: str
) -> None:
    # denied in revision 39 too; a walk through "\\?\" alone would allow the Grep tool
    _mkdir(tree / "sub2" / "inner2.")
    _put(tree / "secretsz" / ".env")
    _junction(tree / "sub2" / "inner2", tree / "secretsz")
    _assert_denied(tree, tool, text)


@windows_only
def test_a_plain_tree_is_still_allowed(tree: Path) -> None:
    _put(tree / "sub" / "a.txt", "x\n")
    for tool, text, rule in [
        ("Bash", "rg made sub", "rule:allow-rg-inside-project"),
        ("Grep", "sub", "rule:read-inside-project"),
    ]:
        decision, _ = _decide(tree, tool, text, backend=False)
        assert decision.decided_by == rule


# ------------------------------------------------------------------ R39-2, R39-1, F-D


@windows_only
@pytest.mark.parametrize(
    ("tool", "text"),
    [
        ("Bash", "rg made kq."),
        ("Bash", "tar -czf o.tgz kq."),
        ("Bash", "grep -r made kq."),
        ("Bash", "cd kq. && rg made ."),
        ("PowerShell", "Set-Location kq.; rg made ."),
        ("PowerShell", "Copy-Item -Recurse -LiteralPath '{xp}' b"),
        ("Bash", "rg made ???"),
        ("Bash", "tar -czf o.tgz kq*"),
        ("Bash", "cat ???/.e*"),
        ("Bash", "cat kq./.e*"),
        ("PowerShell", "Get-Content kq.\\.e*"),
        ("PowerShell", "Copy-Item -Recurse ??? b"),
    ],
)
@pytest.mark.parametrize("sibling", [False, True])
def test_a_secret_in_a_real_dotted_folder_is_denied(
    tree: Path, tool: str, text: str, sibling: bool
) -> None:
    # R39-2 (written name, cd, \\?\), R39-1 (glob), F-D (glob with a dotted literal part)
    _put(tree / "kq." / ".env")
    if sibling:
        _put(tree / "kq" / "a.txt", "x\n")
    _assert_denied(tree, tool, text.format(xp=_xp(tree / "kq.")))


@windows_only
@pytest.mark.parametrize("name", ["k$x.", "a%b%."])
def test_a_dotted_match_is_read_by_its_spelling_not_expanded_again(tree: Path, name: str) -> None:
    _put(tree / name / ".env")
    first = name[0]
    _assert_denied(tree, "Bash", f"rg made {first}*")
    _assert_denied(tree, "PowerShell", f"Copy-Item -Recurse {first}* b")


@windows_only
@pytest.mark.parametrize("sibling", [False, True])
def test_a_dotted_junction_matched_by_a_glob_is_followed(tree: Path, sibling: bool) -> None:
    # R39-1: "kq." is itself a junction to a folder with .env (layouts JR, JR0)
    _put(tree / "secretsz" / ".env")
    if sibling:
        _put(tree / "kq" / "a.txt", "x\n")
    _junction(tree / "kq.", tree / "secretsz")
    for tool, text in [
        ("Bash", "rg made ???"),
        ("Bash", "grep -r made ???"),
        ("Bash", "cp -r ??? b"),
        ("PowerShell", "Copy-Item -Recurse ??? b"),
        ("Bash", "cat kq./.e*"),
    ]:
        _assert_denied(tree, tool, text)
    refs = _refs(tree, "Bash", "rg made ???")
    kept = [r for r in refs if paths.KEPT_READING in r.reasons]
    assert any(
        r.key.endswith("/secretsz")
        and {"resolved-on-disk", "glob-match"} <= set(r.reasons)
        and r.uncertain
        for r in kept
    )


@windows_only
def test_revision_38s_layout_stays_denied(tree: Path) -> None:
    # "kq." empty, "kq" a junction to secretsz: the Win32 expansion found .env, and still does
    _mkdir(tree / "kq.")
    _put(tree / "secretsz" / ".env")
    _junction(tree / "kq", tree / "secretsz")
    for tool, text in [
        ("Bash", "rg made ???"),
        ("Bash", "cat ???/.e*"),
        ("Bash", "cat kq?/.e*"),
        ("PowerShell", "Get-Content kq?\\.e*"),
        ("Bash", "rg made kq."),
    ]:
        _assert_denied(tree, tool, text)


@windows_only
def test_git_add_looks_at_the_dotted_folder_as_well(tree: Path) -> None:
    # R39-4: "kq." without "kq" was not looked at by the staging check; the verdict stays ask
    _put(tree / "kq." / ".env")
    assert "git-add-may-stage-protected" in _gray(tree, "Bash", "git add kq.")
    decision, _ = _decide(tree, "Bash", "git add kq.", backend=False)
    assert decision.decision == "ask"


@windows_only
def test_no_kept_walk_off_a_fixed_drive(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _put(tree / "kq." / ".env")
    monkeypatch.setattr(paths, "is_fixed_drive", lambda letter: False)
    decision, _ = _decide(tree, "Bash", "rg made kq.", backend=False)
    assert (decision.decision, decision.decided_by) == ("ask", "gray")  # as in revision 39


# ------------------------------------------------------------------ budgets


@pytest.fixture
def small_scan(monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr(subtree, "MAX_SCAN_ENTRIES", 200)
    monkeypatch.setattr(subtree, "SCAN_TIME_BUDGET_S", 30.0)
    return 201


@windows_only
@pytest.mark.parametrize("text", ["rg made sub", "rg made sub zz", "rg made zz sub"])
def test_a_big_dotted_folder_in_a_walk_spends_the_second_budget(
    tree: Path, small_scan: int, text: str
) -> None:
    # layout W: without the deferral the first two became ask
    _many(tree / "sub" / "inner.", small_scan)
    _put(tree / "sub" / "z" / "deeper" / ".env")
    _put(tree / "zz" / ".env")
    _assert_denied(tree, "Bash", text)


@windows_only
@pytest.mark.parametrize("text", ["rg made kq. zz", "rg made zz kq.", "rg made ??? zz"])
def test_a_big_kept_reading_spends_the_second_budget(
    tree: Path, small_scan: int, text: str
) -> None:
    _many(tree / "kq.", small_scan)  # layout BUD
    _put(tree / "zz" / ".env")
    _assert_denied(tree, "Bash", text)


@windows_only
def test_a_dotted_junctions_target_found_by_a_glob_spends_the_second_budget(
    tree: Path, small_scan: int
) -> None:
    # the target is a PathRef only revision 40 finds: it is walked on the second budget ("???"
    # does not match "bigdir" itself)
    _many(tree / "bigdir", small_scan)
    _junction(tree / "kq.", tree / "bigdir")
    _put(tree / "zz" / ".env")
    _assert_denied(tree, "Bash", "rg made ??? zz")


@windows_only
def test_the_second_budget_is_not_the_one_the_next_command_walks_on(
    tree: Path, small_scan: int
) -> None:
    _many(tree / "kq.", small_scan)
    _put(tree / "zz" / ".env")
    _assert_denied(tree, "Bash", "rg made kq.; rg made zz")


@windows_only
def test_a_kept_reading_after_a_spent_first_pass_is_still_walked(
    tree: Path, small_scan: int
) -> None:
    _many(tree / "big", small_scan)  # spends the first budget
    _put(tree / "kq." / ".env")
    _assert_denied(tree, "Bash", "rg made big kq.")


@windows_only
def test_the_second_expansion_fills_only_the_room_the_first_left(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _put(tree / "ka" / "a.txt", "x\n")  # found by the Win32 expansion
    _put(tree / "kb." / "b.txt", "x\n")  # found by the second one only
    monkeypatch.setattr(event, "MAX_GLOB_MATCHES", 1)
    refs = _refs(tree, "Bash", "rg made k*")
    assert any(r.key.endswith("/ka") for r in refs)
    assert not any(r.key.endswith("/kb") for r in refs)
    assert "glob-too-many-matches" in _gray(tree, "Bash", "rg made k*")


@windows_only
def test_a_big_dotted_folder_with_nothing_in_it_is_asked_not_sent(
    tree: Path, small_scan: int
) -> None:
    _many(tree / "sub" / "inner.", small_scan)  # revision 39: skipped, allowed
    decision, fake = _decide(tree, "Bash", "rg made sub", backend=True)
    assert (decision.decision, decision.decided_by) == ("ask", "gray-unanalysed")
    assert fake is not None
    assert not fake.requests
    assert "recursive-scan-budget" in _gray(tree, "Bash", "rg made sub")


@windows_only
def test_the_shared_budget_of_revision_39_is_a_written_cost(tree: Path, small_scan: int) -> None:
    # R39-3: a glob's match that is unsure only of its reading uses the shared budget up
    _many(tree / "kq", small_scan)
    _mkdir(tree / "kq.")
    _put(tree / "secretsz" / ".env")
    decision, _ = _decide(tree, "Bash", "rg made ??? secretsz", backend=False)
    assert (decision.decision, decision.decided_by) == ("ask", "gray")
    _assert_denied(tree, "Bash", "rg made secretsz ???")


@windows_only
def test_revision_40s_lookups_have_a_count_of_their_own(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("ka.", "kb."):
        _put(tree / name / "a.txt", "x\n")
    monkeypatch.setattr(event, "MAX_READING_DISK_KEYS", 1)
    monkeypatch.setattr(event, "MAX_GLOB_DISK_KEYS", 0)  # revision 39's own: none used here
    gray = _gray(tree, "Bash", "rg made k*")
    assert "budget:reading-lookups" in gray
    assert not any(g.startswith("budget:") and g != "budget:reading-lookups" for g in gray)
    decision, fake = _decide(tree, "Bash", "rg made k*", backend=True)
    assert decision.decided_by == "gray-unanalysed"  # not sent, never lexical mode
    assert fake is not None
    assert not fake.requests


# ------------------------------------------------------------------ requests


@windows_only
def test_hits_below_an_expanded_root_carry_its_markers(tree: Path) -> None:
    _put(tree / "sub" / ".env")
    _put(tree / "kq." / ".env")
    env = {"WORK_DIR": str(tree)}
    refs = _refs(tree, "PowerShell", "Set-Location $env:WORK_DIR; rg made sub", env)
    hits = [r for r in refs if "recursive-scan" in r.reasons]
    assert hits
    assert all("variable-expanded" in r.reasons for r in hits)
    assert not any("glob-match" in r.reasons for r in hits)
    refs = _refs(tree, "PowerShell", "Set-Location $env:WORK_DIR; rg made ???", env)
    hits = [r for r in refs if "recursive-scan" in r.reasons]
    assert hits
    assert all({"variable-expanded", "glob-match"} <= set(r.reasons) for r in hits)
    plain = [r for r in _refs(tree, "Bash", "rg made sub") if "recursive-scan" in r.reasons]
    assert plain
    assert all(r.reasons == ("recursive-scan",) for r in plain)


@windows_only
def test_a_still_sent_call_shows_the_new_matches_by_key_and_hides_expanded_ones(
    tree: Path,
) -> None:
    _put(tree / "kq." / "a.txt", "x\n")  # nothing protected: still gray, still sent
    _, fake = _decide(tree, "Bash", "rg made ???", backend=True)
    assert fake is not None
    shown = [p["path"] for a in json.loads(fake.requests[0].content)["actions"] for p in a["paths"]]
    assert shown == ["<project>/???", "<project>/kq"]
    _, fake = _decide(
        tree,
        "PowerShell",
        "Set-Location $env:WORK_DIR; rg made ???",
        backend=True,
        env={"WORK_DIR": str(tree)},
    )
    assert fake is not None
    actions = json.loads(fake.requests[0].content)["actions"]
    assert [p["path"] for p in actions[-1]["paths"]] == ["???"]


# ------------------------------------------------------------------ the review of the change


@windows_only
def test_a_dotted_junction_to_a_file_does_not_cloud_the_whole_call(tree: Path) -> None:
    # realpath of such a junction raises: the whole call was one gray action (written names
    # since revision 13; every glob over the folder in the first draft of revision 40)
    _put(tree / ".env")
    _put(tree / "f.txt", "x\n")
    _junction(tree / "jf.", tree / "f.txt")
    for tool, text in [
        ("Bash", "cat .env; ls *"),
        ("Bash", "cat .env ???"),
        ("PowerShell", "Get-Content .env; Get-ChildItem *"),
        ("Bash", "cat .env jf."),
    ]:
        _assert_denied(tree, tool, text)
    assert "internal-error:reading-lookup" in _gray(tree, "Bash", "ls *")
    # (the failed lookup is remembered: every action that meets it gets the note)
    assert _gray(tree, "Bash", "ls *; ls *").count("internal-error:reading-lookup") == 2
    decision, fake = _decide(tree, "Bash", "ls *", backend=True)
    assert decision.decided_by == "gray-unanalysed"  # never sent
    assert fake is not None
    assert not fake.requests


@windows_only
def test_the_first_pass_asks_a_dotted_file_only_what_revision_39_asked(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # revision 39 made one (failing) stat of "x" per dotted file "x."; a second one, of "x."
    # itself, would spend the shared time budget sooner
    _put(tree / "sub" / "other.txt", "x\n")
    os.link(_xp(tree / "sub" / "other.txt"), _xp(tree / "sub" / "x."))  # "x." has two names
    _put(tree / "sub" / "y.", "x\n")
    asked: list[str] = []
    real = subtree._hard_linked

    def counting(entry: os.DirEntry[str]) -> bool:
        asked.append(entry.name)
        return real(entry)

    monkeypatch.setattr(subtree, "_hard_linked", counting)
    dotted_only = {"select": lambda rel, name: name.endswith(".")}  # (other.txt is not read)
    result, _ = _scan(tree / "sub", defer=True, **dotted_only)
    assert asked == []  # only "x" and "y" were asked, what Win32 opens (both missing)
    assert not result.hard_links
    assert sorted(os.path.basename(p) for p in result.deferred_files) == ["x.", "y."]
    again, _ = _scan(tree / "sub", resume=result, **dotted_only)
    assert again.hard_links  # "x." itself, asked on the second budget


@windows_only
def test_the_second_expansion_has_a_time_of_its_own(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _put(tree / ".env")
    _put(tree / "ka." / "a.txt", "x\n")
    monkeypatch.setattr(event, "EXTRA_TIME_S", 0.0)
    gray = _gray(tree, "Bash", "ls k*")
    assert "budget:reading-lookups" in gray
    assert "budget:time" not in gray  # never raises, never lexical mode
    _assert_denied(tree, "Bash", "ls k*; cat .env")


@windows_only
def test_a_glob_match_found_both_ways_stays_in_the_first_pass(tree: Path, small_scan: int) -> None:
    # "k?." finds "kq." only through the second expansion; "kq?" finds the same text through the
    # Win32 one. The second must not move the first's walk of "kq" to the second budget.
    _many(tree / "bigdir" / "inner.", small_scan)  # spends the second budget first
    _put(tree / "kq" / ".env")
    _put(tree / "kq." / "a.txt", "x\n")
    _assert_denied(tree, "Bash", "ls k?. ; rg made bigdir kq?")
    _assert_denied(tree, "PowerShell", "Get-ChildItem k?.; rg made bigdir kq?")


@windows_only
def test_paths_only_revision_40_finds_are_counted_apart(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for i in range(40):
        _put(tree / "kq." / f".env.{i:02}")  # found by the kept walk only
    _put(tree / "zz" / ".env")
    monkeypatch.setattr(event, "MAX_REFS", 20)
    _assert_denied(tree, "Bash", "rg made kq. zz")  # revision 39's own paths stay under 20
    monkeypatch.setattr(event, "MAX_EXTRA_REFS", 5)
    _assert_denied(tree, "Bash", "rg made kq. zz")
    gray = _gray(tree, "Bash", "rg made kq. zz")
    assert "budget:extra-paths" in gray
    assert "budget:paths" not in gray


def test_a_late_walk_reads_the_clock_at_every_folder(tmp_path: Path) -> None:
    for i in range(50):
        (tmp_path / "ed" / f"d{i:02}").mkdir(parents=True)  # folders that list nothing
    late = subtree.ScanBudget(seconds=0.0)
    result = subtree.scan(
        str(tmp_path / "ed"),
        ["c:/p"],
        windows=False,
        matcher=subtree.matcher_for(subtree.DEFAULT_PROTECTED_GLOBS),
        budget=late,
        late=True,
    )
    assert result.status == "budget"
    first = subtree.ScanBudget(seconds=0.0)
    result = subtree.scan(
        str(tmp_path / "ed"),
        ["c:/p"],
        windows=False,
        matcher=subtree.matcher_for(subtree.DEFAULT_PROTECTED_GLOBS),
        budget=first,
    )
    assert result.status == "ok"  # revision 39's walk reads the clock at entries only, as before


@windows_only
@pytest.mark.parametrize(("tool", "text"), [("Bash", "rg made sub"), ("Grep", "sub")])
def test_a_name_ending_in_a_space_is_matched_without_it(tree: Path, tool: str, text: str) -> None:
    _put(tree / "sub" / "a.txt", "x\n")
    _put(tree / "sub" / ".env ")
    _assert_denied(tree, tool, text)


@windows_only
@pytest.mark.parametrize("text", ["rg made kq./sub", "cd kq. && rg made sub"])
def test_a_kept_reading_with_a_dotted_middle_segment_is_walked(tree: Path, text: str) -> None:
    _put(tree / "kq." / "sub" / ".env")
    _assert_denied(tree, "Bash", text)


@windows_only
@pytest.mark.parametrize(("tool", "text"), [("Bash", "rg made sub"), ("Grep", "sub")])
def test_a_win32_sibling_below_a_win32_sibling_is_walked(tree: Path, tool: str, text: str) -> None:
    # "x." lists as the junction "x" -> mid; mid's "y." lists as the junction "y" -> secretsz
    _mkdir(tree / "sub" / "x.")
    _mkdir(tree / "mid" / "y.")
    _put(tree / "secretsz" / ".env")
    _junction(tree / "sub" / "x", tree / "mid")
    _junction(tree / "mid" / "y", tree / "secretsz")
    _assert_denied(tree, tool, text)


@windows_only
def test_the_second_passs_time_is_given_back_to_the_request(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _put(tree / "kq." / "a.txt", "x\n")
    _put(tree / "zz" / ".env")
    real = subtree.scan

    def slow(*args: Any, **kwargs: Any) -> subtree.ScanResult:
        if kwargs.get("late"):  # a slow disk on the second budget
            time.sleep(0.4)
            kwargs["budget"].elapsed += 0.4
        return real(*args, **kwargs)

    monkeypatch.setattr(subtree, "scan", slow)
    monkeypatch.setattr(subtree, "SCAN_TIME_BUDGET_S", 5.0)
    _assert_denied(tree, "Bash", "rg made kq.; rg made zz")


# ------------------------------------------------------------------ the second review of the change


@windows_only
@pytest.mark.parametrize(
    ("folder", "inside", "rule"),
    [
        (".ssh ", "id_rsa", "rule:no-secret-read"),
        (".boundkeep.", ".env", "rule:no-secret-read"),
    ],
)
@pytest.mark.parametrize(("tool", "text"), [("Bash", "rg made d"), ("Grep", "d")])
def test_a_folder_only_the_dotless_key_protects_is_still_walked(
    tree: Path, folder: str, inside: str, rule: str, tool: str, text: str
) -> None:
    # revision 39 walked into it and found the file a deny rule names; the folder's own rule
    # (an ask for the guard's state, or the credential store's) must not take its place
    _put(tree / "d" / folder / inside)
    for backend in (False, True):
        decision, fake = _decide(tree, tool, text, backend=backend)
        assert decision.decision == "deny", (text, backend)
        assert rule.removeprefix("rule:") in decision.decided_by
        assert fake is None or not fake.requests


@windows_only
def test_the_first_pass_matches_what_revision_39_matched(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "config." is not a name revision 39 matched against the globs; its key without the dot,
    # "config", is (a candidate of **/.git/config): matched on the second budget only
    for i in range(1, 30):
        _put(tree / "cf" / ("config" + "." * i), "x\n")
    matched: list[str] = []
    real = subtree.ProtectedMatcher.match

    def counting(self: subtree.ProtectedMatcher, key: str) -> bool:
        matched.append(key)
        return real(self, key)

    monkeypatch.setattr(subtree.ProtectedMatcher, "match", counting)
    result, _ = _scan(tree / "cf", defer=True)
    assert matched == []
    assert len(result.deferred_checks) == 29
    _scan(tree / "cf", resume=result)
    assert len(matched) == 29


@windows_only
def test_dotted_candidates_do_not_spend_the_first_budget(tree: Path) -> None:
    for i in range(1, 201):
        _put(tree / "cf" / ("config" + "." * i), "x\n")
    _put(tree / "zz" / ".env")
    _assert_denied(tree, "Bash", "rg made cf zz")
    _assert_denied(tree, "Grep", ".")


def test_the_literal_expansion_reads_the_clock_within_a_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for i in range(10):
        (tmp_path / f"a{i}.txt").write_text("x\n", encoding="utf-8")
    norm = paths.normalize_path(str(tmp_path / "*.txt"), cwd=None, home=None, dialect="tool")
    segments = len(norm.key.split("/")) - 1  # the clock is read at each one
    ticks = iter([0.0] * segments + [100.0] * 50)

    class Clock:
        @staticmethod
        def monotonic() -> float:
            return next(ticks, 100.0)

    monkeypatch.setattr(paths, "time", Clock)
    literal = paths.expand_glob(norm, deadline=50.0, literal=True)
    if os.name == "nt":
        assert literal.status == "budget"  # (the listing started before the deadline)
    ticks = iter([0.0] * segments + [100.0] * 50)
    assert paths.expand_glob(norm, deadline=50.0).status == "ok"  # the Win32 one: as before


# ------------------------------------------------------------------ the third review of the change


def _clock(monkeypatch: pytest.MonkeyPatch, zeros: int) -> None:
    """``subtree``'s clock: ``zeros`` reads of 0, then 100 (a budget of 50 s is spent)."""
    ticks = iter([0.0] * zeros)

    class Clock:
        @staticmethod
        def monotonic() -> float:
            return next(ticks, 100.0)

    monkeypatch.setattr(subtree, "time", Clock)


def _late(root: Path, *, windows: bool, **kw: Any) -> tuple[subtree.ScanResult, subtree.ScanBudget]:
    budget = subtree.ScanBudget(seconds=50.0)
    result = subtree.scan(
        str(root),
        ["c:/p"],
        windows=windows,
        matcher=subtree.matcher_for(subtree.DEFAULT_PROTECTED_GLOBS),
        budget=budget,
        **kw,
    )
    return result, budget


def test_a_late_walk_reads_the_clock_before_each_full_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # a full match can take a millisecond or more (names like "config...."): 64 of them between
    # two reads of the clock overshot the 0.35 s of the second budget by up to 0.08 s
    for i in range(10):
        (tmp_path / f".env.{i}").write_text("x\n", encoding="utf-8")
    _clock(monkeypatch, 3)  # scan's start, the folder, the first entry's match
    result, _ = _late(tmp_path, windows=False, late=True)
    assert result.status == "budget"
    assert len(result.hits) == 1
    _clock(monkeypatch, 1)  # revision 39's own walk keeps its rhythm: every 64 entries
    result, _ = _late(tmp_path, windows=False, defer=True)
    assert result.status == "ok"
    assert len(result.hits) == 10


@windows_only
def test_a_late_walk_reads_the_clock_before_each_match_by_the_dotless_key(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for i in range(1, 8):
        _put(tree / "cf" / ("id_rsa" + "." * i), "x\n")
    result, _ = _late(tree / "cf", windows=True, late=True)
    assert result.status == "ok"
    assert len({h.rel for h in result.hits}) == 7  # (each one by its key without the dots)
    zeros = 2 + 1  # scan's start, the folder; then the first entry's match only
    _clock(monkeypatch, zeros)
    result, _ = _late(tree / "cf", windows=True, late=True)
    assert result.status == "budget"
    assert len({h.rel for h in result.hits}) <= 1


def test_the_second_budget_stops_the_put_off_matches_on_time() -> None:
    # one full match each: the clock is read before every one, not every 64th
    left = subtree.ScanResult()
    left.deferred_checks = [("id_rsa.", False), ("id_rsa..", False), ("id_rsa...", False)]
    spent = subtree.ScanBudget(seconds=0.0)
    matcher = subtree.matcher_for(subtree.DEFAULT_PROTECTED_GLOBS)
    again = subtree.scan("x", ["c:/p"], windows=True, matcher=matcher, budget=spent, resume=left)
    assert again.status == "budget"
    assert again.hits == []
    fresh = subtree.ScanBudget(seconds=50.0)
    again = subtree.scan("x", ["c:/p"], windows=True, matcher=matcher, budget=fresh, resume=left)
    assert again.status == "ok"
    assert {h.key for h in again.hits} >= {"c:/p/id_rsa.", "c:/p/id_rsa"}
    assert all(h.extra for h in again.hits)  # what revision 39 never reported: counted apart
    assert (again.slots, again.extras) == (0, 3)


@pytest.mark.parametrize("field", ["deferred_files", "deferred_links"])
def test_the_second_budget_stops_the_put_off_disk_asks_on_time(field: str) -> None:
    left = subtree.ScanResult()
    setattr(left, field, [f"no-such-place-{i}" for i in range(70)])  # one ask each
    matcher = subtree.matcher_for(subtree.DEFAULT_PROTECTED_GLOBS)
    spent = subtree.ScanBudget(seconds=0.0)
    again = subtree.scan("x", ["c:/p"], windows=True, matcher=matcher, budget=spent, resume=left)
    assert again.status == "budget"  # (read every 64 asks: a stat is quick)
    fresh = subtree.ScanBudget(seconds=50.0)
    again = subtree.scan("x", ["c:/p"], windows=True, matcher=matcher, budget=fresh, resume=left)
    assert again.status == "ok"


@windows_only
def test_a_dotted_links_own_target_is_asked_on_the_second_budget(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # revision 39 asked whether "y" (what Win32 opens for "y.") is a folder; "y." itself later
    _put(tree / "links" / "y.", "x\n")
    asked: list[str] = []

    def link_to_dir(entry: os.DirEntry[str]) -> bool:
        asked.append(entry.name)
        return False

    monkeypatch.setattr(subtree, "_is_link", lambda entry: entry.name == "y.")
    monkeypatch.setattr(subtree, "_link_to_dir", link_to_dir)
    monkeypatch.setattr(subtree, "_is_dir_path", lambda path: path.endswith("y."))
    result, _ = _scan(tree / "links", defer=True)
    assert asked == []
    assert not result.dir_links
    assert [os.path.basename(p) for p in result.deferred_links] == ["y."]
    again, _ = _scan(tree / "links", resume=result)
    assert again.dir_links


@windows_only
def test_a_late_walk_asks_a_dotted_files_own_link_count(tree: Path) -> None:
    _put(tree / "sub" / "other.txt", "x\n")
    os.link(_xp(tree / "sub" / "other.txt"), _xp(tree / "sub" / "x."))  # no "x"
    dotted_only = {"select": lambda rel, name: name.endswith(".")}
    result, _ = _late(tree / "sub", windows=True, late=True, **dotted_only)
    assert result.hard_links
    assert not result.deferred_files


@windows_only
def test_a_late_walk_stops_at_the_cap_of_hits_only_revision_40_finds(tree: Path) -> None:
    for i in range(70):
        _put(tree / "d" / f"b{i:02}" / ".ssh." / "x.txt", "x\n")
    result, budget = _late(tree / "d", windows=True, late=True)
    assert result.extras == subtree.MAX_SCAN_HITS
    assert budget.entries < 70 + 70  # it stopped at the 64th folder; nothing below it walked


def _decide_input(proj: Path, tool_input: dict[str, Any], *, backend: bool) -> tuple[Any, Any]:
    pol = policy(llm=backend)
    auditor, fake = manipulated(pol) if backend else (None, None)
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        _event(proj, "Grep", tool_input),
        mode="enforce",
        policy=pol,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": WIN_HOME},
        home=WIN_HOME,
        scan_disk=True,
        auditor=auditor,
    )
    return decision, fake


@windows_only
@pytest.mark.parametrize("narrow", [{"glob": "*.py"}, {"type": "py"}])
def test_a_grep_glob_reads_a_dotless_protected_folder_as_one(
    tree: Path, narrow: dict[str, str]
) -> None:
    # a written cost: the folder is reported as itself, whatever the glob selects in it (".ssh"
    # with the same glob is walked and nothing in it is selected: allowed, as in revision 39)
    _put(tree / "d" / ".ssh " / "notes.txt", "x\n")
    _put(tree / "e" / ".ssh" / "notes.txt", "x\n")
    for backend in (False, True):
        tool_input = {"pattern": "made", "path": str(tree / "d"), **narrow}
        decision, fake = _decide_input(tree, tool_input, backend=backend)
        assert decision.decision == "deny", backend
        assert fake is None or not fake.requests
    decision, _ = _decide_input(
        tree, {"pattern": "made", "path": str(tree / "e"), **narrow}, backend=False
    )
    assert decision.decided_by == "rule:read-inside-project"


@windows_only
def test_a_file_a_grep_glob_does_not_read_is_not_matched_by_its_dotless_key(tree: Path) -> None:
    _put(tree / "d" / "id_rsa.", "x\n")
    _put(tree / "d" / "a.py", "x\n")
    decision, _ = _decide_input(
        tree, {"pattern": "made", "path": str(tree / "d"), "glob": "*.py"}, backend=False
    )
    assert decision.decided_by == "rule:read-inside-project"  # as in revision 39
    decision, _ = _decide_input(
        tree, {"pattern": "made", "path": str(tree / "d"), "glob": "id_*"}, backend=False
    )
    assert (decision.decision, decision.decided_by) == ("deny", "rule:no-credential-store-read")


def test_revision_40s_own_time_is_counted_and_given_back() -> None:
    budget = event._Budget(deadline=time.monotonic() + 100.0)
    assert budget.reading_slot()
    budget.extra_s = event.EXTRA_TIME_S
    assert not budget.reading_slot()  # its own 0.25 s is spent
    budget.extra_s = 0.0
    budget.deadline = time.monotonic() - 1.0
    assert not budget.reading_slot()  # the request's time is spent
    deadline = budget.deadline
    budget.extra_time(time.monotonic() - 0.5)
    assert budget.extra_s >= 0.5
    assert budget.deadline >= deadline + 0.5  # given back to the request


def test_the_second_expansion_does_not_start_after_the_requests_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def never(*args: Any, **kwargs: Any) -> paths.GlobResult:
        raise AssertionError("expanded after the deadline")

    monkeypatch.setattr(paths, "expand_glob", never)
    ctx: Any = types.SimpleNamespace(budget=event._Budget(deadline=time.monotonic() - 1.0))
    norm = paths.normalize_path("C:\\p\\k*", cwd=None, home=None, dialect="tool")
    notes: list[str] = []
    assert event._literal_glob_refs(ctx, norm, "read", notes, False, None, []) == []
    assert notes == ["budget:reading-lookups"]


@windows_only
def test_paths_a_second_expansion_finds_are_counted_apart(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for i in range(20):
        _mkdir(tree / f"k{i:02}.")  # found by the second expansion only
    _put(tree / ".env")
    monkeypatch.setattr(event, "MAX_REFS", 10)
    gray = _gray(tree, "Bash", "ls k*")
    assert not any(g.startswith("budget:") for g in gray)
    marked = [r for r in _refs(tree, "Bash", "ls k*") if paths.EXTRA_READING in r.reasons]
    assert len(marked) >= 20  # more than MAX_REFS, none of them counted against it
    _assert_denied(tree, "Bash", "ls k*; cat .env")


@windows_only
def test_a_symlinked_siblings_relative_or_dangling_text_on_a_fixed_drive_is_entered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    link, local, chain = "\\\\?\\C:\\p\\inner", "\\\\?\\C:\\p\\elsewhere", "\\\\?\\C:\\chain"
    symlink = os.stat_result((0o120777,) + (0,) * 9)
    folder = os.stat_result((0o040777,) + (0,) * 9)
    real_lstat = os.lstat
    target = ""

    def lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if path in (link, chain):
            return symlink
        if path == local:
            return folder
        if path == "\\\\?\\C:\\nowhere-made-up":
            raise FileNotFoundError(path)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "readlink", lambda path, *a, **k: target)
    monkeypatch.setattr(paths, "is_fixed_drive", lambda letter: letter.lower() == "c")
    for target, state in [
        ("elsewhere", subtree._ENTER),  # relative: next to the link
        ("..\\chain", subtree._REFUSE),  # relative, to a link
        ("C:\\nowhere-made-up", subtree._ENTER),  # dangling: nothing to open there
    ]:
        assert subtree._alias_state(link) == state, target


# ------------------------------------------------------------------ what the mutants left


@windows_only
def test_files_a_selector_does_not_read_do_not_take_the_room_of_one_it_reads(tree: Path) -> None:
    # the dotless key of a file the reader does not read is never matched: put off to the second
    # budget, such files filled its cap of hits before the file the reader does read
    for i in range(1, subtree.MAX_SCAN_HITS + 6):
        _put(tree / "a" / ("id_rsa" + "." * i), "x\n")
    _put(tree / "z" / "id_rsa.", "x\n")
    picked = {"select": lambda rel, name: rel.startswith("z/")}
    result, _ = _scan(tree, defer=True, **picked)
    assert [rel for rel, _is_dir in result.deferred_checks] == ["z/id_rsa."]
    again, _ = _scan(tree, resume=result, **picked)
    assert {h.rel for h in again.hits} == {"z/id_rsa."}


@windows_only
def test_a_late_walk_goes_on_below_a_folder_only_the_dotless_key_protects(tree: Path) -> None:
    # the folder is reported, then walked as revision 39 walked it (the file below it may be what
    # a deny rule names); the first pass walks it too, but a late walk is the only one for a
    # folder only a name as on disk leads to
    _put(tree / "d" / ".ssh " / "id_rsa", "x\n")
    result, _ = _late(tree / "d", windows=True, late=True)
    assert {h.rel for h in result.hits} == {".ssh ", ".ssh /id_rsa"}


@windows_only
def test_a_selector_does_not_hide_a_folder_only_the_dotless_key_protects(tree: Path) -> None:
    # the written cost of a Grep glob, in a late walk as in the first pass and its resumption
    _put(tree / "d" / ".ssh " / "notes.txt", "x\n")
    py_only = {"select": lambda rel, name: name.endswith(".py")}
    result, _ = _late(tree / "d", windows=True, late=True, **py_only)
    assert {h.rel for h in result.hits} == {".ssh "}
    first, _ = _scan(tree / "d", defer=True, **py_only)
    again, _ = _scan(tree / "d", resume=first, **py_only)
    assert {h.rel for h in again.hits} == {".ssh "}


@windows_only
def test_a_hit_only_the_dotless_key_finds_is_counted_apart_in_any_walk(tree: Path) -> None:
    # revision 39's walk never reported "id_rsa." (only its key without the dot is protected):
    # extra in a walk that is neither put off nor late as well, so it takes no room of the others
    _put(tree / "d" / "id_rsa", "x\n")
    _put(tree / "d" / "id_rsa.", "x\n")
    result, _ = _scan(tree / "d")
    assert {(h.rel, h.extra) for h in result.hits} == {("id_rsa", False), ("id_rsa.", True)}
    assert (result.slots, result.extras) == (1, 1)


@windows_only
def test_the_second_expansions_time_is_counted_against_its_own(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # a slow disk: the first glob's expansion as on disk spends the 0.25 s, so the second glob's
    # is not made (and the time is given back to the request)
    _mkdir(tree / "ka.")
    _mkdir(tree / "kb.")
    assert "budget:reading-lookups" not in _gray(tree, "Bash", "ls ka*; ls kb*")
    real = paths.expand_glob

    def slow(*args: Any, **kwargs: Any) -> paths.GlobResult:
        found = real(*args, **kwargs)
        if kwargs.get("literal"):
            time.sleep(event.EXTRA_TIME_S + 0.05)
        return found

    monkeypatch.setattr(paths, "expand_glob", slow)
    assert "budget:reading-lookups" in _gray(tree, "Bash", "ls ka*; ls kb*")


@windows_only
def test_spent_reading_lookups_leave_the_rest_of_the_line_on_disk(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # revision 40's own lookups never raise: the line is not read without the disk from there on,
    # so a deny only the disk shows (a junction to a folder holding a secret) stays
    _put(tree / "secretsz" / ".env")
    _junction(tree / "docs", tree / "secretsz")
    _mkdir(tree / "ka.")
    monkeypatch.setattr(event, "MAX_READING_DISK_KEYS", 0)
    assert "budget:reading-lookups" in _gray(tree, "Bash", "ls ka*; rg made docs")
    _assert_denied(tree, "Bash", "ls ka*; rg made docs")
