"""Spec revision 43: the review of revision 42 (docs/reviews/M3a-rev42-review.md).

* R42-1 (from revision 42): the disk call for a dotted folder's sibling the listing lacked was
  charged to the walk's clock when it was next read, so R40-1's layout with 64 more entries after
  it was asked again; and the listing held no files, so a file sibling was asked of the disk and
  listed. Now the listing holds files, and the time spent on siblings is booked apart from the
  clock, with a limit of its own (1.5 s; the walk's own 0.35 s at first was too close).
* R42-2 (before revision 40): over ``MAX_CWDS`` the newest working directory was dropped: after
  three ``cd`` a fourth one's place was never looked at, and a read below ``.kube`` was sent to
  the model. Now the step's own targets are kept first, and a line that dropped a directory is not
  sent: keeping the newest dropped ``.kube`` in ``cd <out>/.kube; cd q; cd r; cd s; cat config``.
* R42-4, R42-5, R42-6 (before revision 40): a clean folder named ``VAULTS~1.`` hid where Win32
  reads ``VAULTS~1``; a long name that looks like an 8.3 one (``data~1``) was never walked, nor
  what a glob matched there (found when the fix was verified); below a dotted folder reached
  through an 8.3 name the Win32 siblings were not looked for.

R42-3 (the shared budgets) is a written cost; R42-7 and R42-8 are text.
"""

from __future__ import annotations

import json
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
    _reparse_point,
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
    for dirpath, dirnames, _files in os.walk(_xp(tmp_path)):
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


def _fwd(path: Path) -> str:
    return str(path).replace("\\", "/")


# ------------------------------------------------------------------ R42-1: the siblings' time


def _slow_lstat(monkeypatch: pytest.MonkeyPatch, step: float) -> list[float]:
    """Every ``os.lstat`` costs ``step`` seconds of a made-up clock (the walk's only clock)."""
    clock = [0.0]
    real_lstat = os.lstat

    def slow_lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
        clock[0] += step
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", slow_lstat)
    monkeypatch.setattr(subtree, "time", types.SimpleNamespace(monotonic=lambda: clock[0]))
    return clock


def _walk(root: Path, budget: subtree.ScanBudget) -> subtree.ScanResult:
    return subtree.scan(
        str(root),
        ["c:/p"],
        windows=True,
        matcher=subtree.matcher_for(subtree.DEFAULT_PROTECTED_GLOBS),
        budget=budget,
        defer=True,
    )


@windows_only
def test_the_time_spent_on_siblings_is_not_charged_to_the_clock(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # R40-1's layout in small: 60 dotted folders without a sibling (5 ms of a made-up clock for
    # each lstat), a folder of 64 files whose listing reads the clock, then zz9/.env; an earlier
    # operand's walk spent 0.1 s. Revision 42 charged the 0.3 s of lstat when the clock was next
    # read (0.4 s against 0.35 s) and the walk stopped before zz9.
    for i in range(60):
        _mkdir(tree / f"d{i:02}.")
    for i in range(64):
        _put(tree / "zz0" / f"f{i:02}.txt", "x\n")
    _put(tree / "zz9" / ".env")
    clock = _slow_lstat(monkeypatch, 0.005)
    budget = subtree.ScanBudget()
    budget.elapsed = 0.1
    result = _walk(tree, budget)
    assert result.status == "ok"
    assert {h.rel for h in result.hits} == {"zz9/.env"}
    assert clock[0] == pytest.approx(0.3)
    assert budget.sibling_s == pytest.approx(0.3)
    assert not budget.spent


@windows_only
def test_the_siblings_may_take_longer_than_the_walk_s_own_seconds(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 100 of them at 5 ms: 0.5 s, past the walk's 0.35 s but not the siblings' own 1.5 s. The
    # limit was 0.35 s at first, and R40-1's layout (0.25 to 0.31 s) ran into it on a slower run
    for i in range(100):
        _mkdir(tree / f"d{i:02}.")
    _put(tree / "zz9" / ".env")
    _slow_lstat(monkeypatch, 0.005)
    budget = subtree.ScanBudget()
    result = _walk(tree, budget)
    assert result.status == "ok"
    assert {h.rel for h in result.hits} == {"zz9/.env"}
    assert budget.sibling_s == pytest.approx(0.5)
    assert budget.sibling_s > budget.seconds
    assert not budget.spent


@windows_only
def test_the_time_spent_on_siblings_has_a_limit_of_its_own(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 400 of them at 5 ms: past 1.5 s of their own the walk stops (recursive-scan-budget, asked
    # and not sent), so a slow disk cannot hold the walk for long
    assert subtree.SIBLING_TIME_LIMIT_S == 1.5
    for i in range(400):
        _mkdir(tree / f"d{i:03}.")
    _put(tree / "zz9" / ".env")
    _slow_lstat(monkeypatch, 0.005)
    budget = subtree.ScanBudget()
    result = _walk(tree, budget)
    assert result.status == "budget"
    assert result.hits == []
    assert budget.sibling_s == pytest.approx(1.5, abs=0.006)
    assert budget.spent


@windows_only
def test_a_sibling_that_is_a_file_is_read_off_the_listing(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "p0." .. "p4." next to the files "p0" .. "p4": revision 42 asked lstat of each (the listing
    # held folders and links only), took it as something to enter and listed a file
    for i in range(5):
        _mkdir(tree / f"p{i}.")
        _put(tree / f"p{i}", "x\n")
    _put(tree / "zz" / ".env")
    asked: list[str] = []
    opened: list[str] = []
    real_scandir = os.scandir

    def scandir(path: Any) -> Any:
        opened.append(os.path.basename(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", scandir)
    monkeypatch.setattr(subtree, "_alias_state", lambda path: asked.append(path) or subtree._ENTER)
    result = _walk(tree, subtree.ScanBudget())
    assert asked == []
    assert opened == [tree.name, "zz"]
    assert {h.rel for h in result.hits} == {"zz/.env"}


# ------------------------------------------------------------------ R42-2: the newest directory


def test_over_the_limit_the_steps_own_targets_are_kept() -> None:
    old = tuple(f"c:/p/{i}" for i in range(8))
    # revision 39 kept old[:7] and dropped the target; the first one (where the line started)
    # stays, then the target, then the later of the others
    assert event._merge_cwds(old, ("c:/o/.kube",)) == (old[0], *old[3:], "c:/o/.kube", None)
    # more targets than room: the later ones
    new = tuple(f"c:/n/{i}" for i in range(9))
    assert event._merge_cwds(("c:/p",), new) == ("c:/p", *new[3:], None)
    # a step with no known target: the later of the old ones
    assert event._merge_cwds(old, (None,)) == (old[0], *old[2:], None)
    # under the limit nothing changes
    assert event._merge_cwds(("c:/p",), ("c:/p/a", None)) == ("c:/p", "c:/p/a", None)
    assert event._merge_cwds(old[:4], old[4:]) == old


@windows_only
@pytest.mark.parametrize(
    ("tool", "text"),
    [
        ("Bash", "cd q && cd r && cd s && cd {o} && cat config"),
        ("Bash", "cd q; cd r; cd s; cd {o}; cat config"),
        ("Bash", "cd {s} && cd x && cd y && cd {o} && cat config"),
        (
            "PowerShell",
            "Set-Location q; Set-Location r; Set-Location s; Set-Location {ow}; Get-Content config",
        ),
    ],
)
def test_a_fourth_cd_is_looked_at(tree: Path, tool: str, text: str) -> None:
    # "config" itself names nothing; only its folder makes it protected (four cd were sent to
    # the model on revisions 39 to 42, three cd and an 8.3 name on revision 42; Git Bash read it)
    _mkdir(tree / "q" / "r" / "s")
    _mkdir(tree / "srcfolderlong" / "x" / "y")
    kube = tree.parent / "o" / ".kube"
    _put(kube / "config")
    short = _short(tree / "srcfolderlong") if "{s}" in text else ""
    command = text.format(o=_fwd(kube), ow=str(kube), s=short)
    _assert_denied(tree, tool, command, rule="rule:no-credential-store-read")


@windows_only
def test_over_the_limit_the_allow_side_still_sees_an_unknown_directory(tree: Path) -> None:
    _put(tree / "q" / "r" / "s" / "x" / "a.txt", "x\n")
    text = "cd q && cd r && cd s && cd x && cat a.txt"
    assert "cwd-unknown" in _gray(tree, "Bash", text)
    decision, _ = _decide(tree, "Bash", text, backend=False)
    assert decision.decision == "ask"


def _assert_asked_and_not_sent(proj: Path, tool: str, text: str) -> None:
    assert event._CWDS_DROPPED in _gray(proj, tool, text), text
    for backend in (False, True):
        decision, fake = _decide(proj, tool, text, backend=backend)
        assert decision.decision == "ask", (text, backend)
        assert decision.decided_by.startswith("gray"), (text, backend)
        assert fake is None or not fake.requests, text


@windows_only
@pytest.mark.parametrize(
    ("tool", "text"),
    [
        ("Bash", "cd {o}; cd q; cd r; cd s; cat config"),
        ("Bash", "cd {o} && cd q && cd r && cd s && cat config"),
        ("Bash", "cd {o}; cd q; cd r; cd s; cd t; cat config"),
        ("Bash", "cd q; cd {o}; cd r; cd s; cat config"),
        (
            "PowerShell",
            "Set-Location {ow}; Set-Location q; Set-Location r; Set-Location s; Get-Content config",
        ),
    ],
)
def test_a_line_that_dropped_a_directory_is_not_sent(tree: Path, tool: str, text: str) -> None:
    # the other way round: whichever directory the limit drops, a line can make it the one that
    # matters. Keeping the newest targets dropped ``.kube`` here, and the line went from denied
    # (revision 42) to sent; now it is asked and not sent
    kube = tree.parent / "o" / ".kube"
    _put(kube / "config")
    _assert_asked_and_not_sent(tree, tool, text.format(o=_fwd(kube), ow=str(kube)))


@windows_only
@pytest.mark.parametrize(
    "text",
    [
        "cd q && cd r && cd s && cd x && cat a.txt",
        # an unknown directory pushes a known one out: popd, pushd alone, a variable, CDPATH
        "cd q; cd r; cd s; popd; cat a.txt",
        "cd q; cd r; cd s; pushd; cat a.txt",
        "cd q; cd r; cd s; cd $X; cat a.txt",
        "cd q; cd r; cd s; export CDPATH=/x; cat a.txt",
    ],
)
def test_a_clean_line_over_the_limit_is_not_sent_either(tree: Path, text: str) -> None:
    _put(tree / "q" / "r" / "s" / "x" / "a.txt", "x\n")
    _assert_asked_and_not_sent(tree, "Bash", text)


@windows_only
@pytest.mark.parametrize(
    "text",
    ["cd q && cd r && cd s && cat a.txt", "cd q; popd; cat a.txt", "cd q; cd r; cd s; cat a.txt"],
)
def test_a_line_within_the_limit_is_decided_as_before(tree: Path, text: str) -> None:
    # eight known directories, or fewer with the unknown one: nothing is dropped. All known and
    # inside the project: allowed by the rules; with the unknown one (popd): sent to the model
    _put(tree / "q" / "r" / "s" / "a.txt", "x\n")
    assert event._CWDS_DROPPED not in _gray(tree, "Bash", text)
    decision, fake = _decide(tree, "Bash", text, backend=True)
    assert decision.decision == "none"
    assert fake is not None
    allowed = "rule:allow-cd-family,allow-cat-inside-project"
    assert decision.decided_by == ("llm" if "popd" in text else allowed)
    assert bool(fake.requests) == ("popd" in text)


# ------------------------------------------------------------------ R42-4: both readings


@windows_only
@pytest.mark.parametrize(
    ("tool", "text"),
    [
        ("Bash", "rg made {s}."),
        ("Grep", "{s}."),
        ("Bash", "tar -czf o.tgz {s}."),
        ("PowerShell", "Copy-Item -Recurse {s}. b"),
    ],
)
def test_a_clean_folder_named_like_the_spelling_does_not_hide_the_win32_reading(
    tree: Path, tool: str, text: str
) -> None:
    # Win32 reads "VAULTS~1" (vaultstorage.); Git Bash reads the clean "VAULTS~1." beside it
    # (cmd's findstr /s and dir /s, Python's os.listdir read the .env; measured)
    _put(tree / "vaultstorage." / ".env")
    short = _short(tree / "vaultstorage.")
    _put(tree / (short + ".") / "a.txt", "x\n")
    _assert_denied(tree, tool, text.format(s=short))


@windows_only
def test_a_junction_named_like_the_spelling_does_not_hide_the_win32_reading(tree: Path) -> None:
    # "VAULTS~1." is a junction to a clean folder outside: the place the text that keeps the dot
    # leads to is not the written key's, so only the key's own lookup finds vaultstorage. (the
    # Win32 reading); revision 42 stopped at the first that existed
    _put(tree / "vaultstorage." / ".env")
    short = _short(tree / "vaultstorage.")
    clean = tree.parent / "o" / "clean"
    _put(clean / "a.txt", "x\n")
    _junction(tree / (short + "."), clean)
    _assert_denied(tree, "Bash", f"rg made {short}.")


@windows_only
def test_a_cd_written_so_adds_both_places(tree: Path) -> None:
    out = tree.parent / "o"
    _put(out / "vaultstorage." / "sub" / ".env")
    short = _short(out / "vaultstorage.")
    _put(out / (short + ".") / "sub" / "a.txt", "x\n")
    _assert_denied(tree, "Bash", f"cd {_fwd(out)}/{short}. && rg made sub")


# ------------------------------------------------------------------ R42-5: long names like 8.3


def test_a_name_the_disk_gave_back_is_a_long_name() -> None:
    norm = paths.normalize_path("C:\\p\\data~1", cwd=None, home=None, dialect="tool", literal=True)
    assert norm.uncertain
    assert "short-name-unresolved" in norm.reasons
    sure = paths.on_disk_names(norm)
    assert not sure.uncertain
    assert "short-name-unresolved" not in sure.reasons
    assert sure.key == norm.key
    # anything else that makes it unsure stays
    dotted = paths.normalize_path(
        "C:\\p\\data~1\\x.", cwd=None, home=None, dialect="tool", literal=True
    )
    kept = paths.on_disk_names(dotted)
    assert kept.uncertain
    assert "short-name-unresolved" not in kept.reasons
    relative = paths.normalize_path("data~1", cwd=None, home=None, dialect="tool", literal=True)
    assert paths.on_disk_names(relative) == relative


@windows_only
@pytest.mark.parametrize(
    ("tool", "text"),
    [
        ("Bash", "rg made data~1"),
        ("Grep", "data~1"),
        ("Bash", "tar -czf o.tgz data~1"),
        ("PowerShell", "Copy-Item -Recurse data~1 b"),
        ("Bash", "rg made data~1/sub"),
        ("Bash", "rg made data~1."),
        ("Bash", "cd data~1 && rg made sub"),
        ("Bash", "cd data~1. && rg made sub"),
        ("Bash", "cd 'data~1 ' && rg made sub"),
        ("PowerShell", "Set-Location data~1; rg made sub"),
    ],
)
def test_a_long_name_that_looks_like_an_8_3_name_is_walked(
    tree: Path, tool: str, text: str
) -> None:
    # (Git Bash's grep -rl and cmd's dir /s read data~1/sub/.env; four revisions sent these)
    _put(tree / "data~1" / "sub" / ".env")
    _assert_denied(tree, tool, text)


@windows_only
def test_an_8_3_name_below_such_a_long_name_is_walked(tree: Path) -> None:
    _put(tree / "data~1" / "plainlongfolder" / ".env")
    short = _short(tree / "data~1" / "plainlongfolder")
    _assert_denied(tree, "Bash", f"rg made data~1/{short}")


@windows_only
def test_the_written_long_name_stays_unsure_for_the_allow_side(tree: Path) -> None:
    _put(tree / "data~1" / "a.txt", "x\n")
    decision, _ = _decide(tree, "Bash", "cat data~1/a.txt", backend=False)
    assert decision.decision == "ask"


@windows_only
@pytest.mark.parametrize(
    ("tool", "text"),
    [
        ("Bash", "rg made *"),
        ("Bash", "rg made d*"),
        ("Bash", "rg made data~1/*"),
        ("Bash", "tar -czf o.tgz d*"),
        ("PowerShell", "Copy-Item -Recurse data~1/* b"),
    ],
)
def test_a_glob_match_that_looks_like_an_8_3_name_is_walked(
    tree: Path, tool: str, text: str
) -> None:
    # the glob matched data~1 or data~1/sub, unsure as the written name is: revision 43 at first
    # walked only the written forms, and these were sent (found when it was verified)
    _put(tree / "data~1" / "sub" / ".env")
    _assert_denied(tree, tool, text)


@windows_only
def test_a_clean_glob_match_so_named_is_still_sent(tree: Path) -> None:
    # the match stays unsure (the allow side sees what it saw); its certain form is shown as a
    # written one's is (the same text twice, R42-5), and left out with the match when a variable
    # was expanded (spec revision 38, R37-1)
    _put(tree / "data~1" / "sub" / "a.txt", "x\n")
    decision, fake = _decide(tree, "Bash", "rg made *", backend=True)
    assert (decision.decision, decision.decided_by) == ("none", "llm")
    assert fake is not None
    actions = json.loads(fake.requests[0].content)["actions"]
    shown = [p["path"] for a in actions for p in a["paths"]]
    assert shown == ["<project>/*", "<project>/data~1", "<project>/data~1"]
    text = "Set-Location $env:WORK_DIR; rg made *"
    env = {"WORK_DIR": str(tree)}
    decision, fake = _decide(tree, "PowerShell", text, backend=True, env=env)
    assert (decision.decision, decision.decided_by) == ("none", "llm")
    assert fake is not None
    actions = json.loads(fake.requests[0].content)["actions"]
    assert [p["path"] for p in actions[-1]["paths"]] == ["*"]


@windows_only
@pytest.mark.parametrize(
    ("tool", "text"),
    [
        ("Bash", "rg made data~1/k*"),
        ("Bash", "rg made data~1/*"),
        ("PowerShell", "Copy-Item -Recurse data~1/k* b"),
    ],
)
def test_a_dotted_glob_match_below_such_a_long_name_is_walked(
    tree: Path, tool: str, text: str
) -> None:
    # the match data~1/k9. is unsure of its 8.3-like name and of its dot; where its name as on
    # disk leads has the match's own key, so it is walked for that PathRef, which cannot be
    # walked itself (revision 42; no test covered it once the written forms were walked)
    _put(tree / "data~1" / "k9." / ".env")
    _assert_denied(tree, tool, text)


# ------------------------------------------------------------------ R42-6: Win32 inside


@windows_only
@pytest.mark.parametrize(
    ("tool", "text"),
    [
        ("Grep", "{s}"),
        ("Grep", "{s}."),
        ("Bash", "rg made {s}"),
        ("Bash", "rg made {s}."),
        ("PowerShell", "Copy-Item -Recurse {s} b"),
    ],
)
def test_a_win32_sibling_inside_a_dotted_folder_reached_by_its_8_3_name_is_followed(
    tree: Path, tool: str, text: str
) -> None:
    # a Win32 program gets into "archivefolder." by its 8.3 name and opens "cfg." as "cfg", a
    # junction to a folder outside with .env (cmd's findstr /s read cfg\.env and cfg.\.env)
    _mkdir(tree / "archivefolder." / "cfg.")
    _junction(tree / "archivefolder." / "cfg", _outside_secret(tree))
    short = _short(tree / "archivefolder.")
    _assert_denied(tree, tool, text.format(s=short))
