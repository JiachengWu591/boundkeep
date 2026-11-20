"""Spec revision 39: the review of revision 38 (docs/reviews/M3a-rev38-review.md).

R38-1, R38-2: a recursive read walks a directory that is certain, or unsure only of its reading
(revision 13). "glob-match" was neither a reading nor an informational reason, so a glob's match
whose name ends in a dot was not walked (since M3a), and once revision 38 put "glob-match" on its
form on disk, that form was not walked either: next to ``kq.`` a junction ``kq`` to a folder with
``.env`` turned ``rg x ???`` from deny to gray. "glob-match" is informational now.

R38-3: after a cd through a variable to the event's own cwd, a glob's matches in the project are
left out as well (a cost written in the spec, pinned here).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.normalize import paths
from boundkeep.normalize.event import normalize_event
from tests.unit.test_m3a_pipeline import policy
from tests.unit.test_m3a_x1_fixes import WIN_HOME, manipulated

windows_only = pytest.mark.skipif(
    sys.platform != "win32", reason="Windows names with a trailing dot and junctions"
)


def _extended(path: Path) -> str:
    return "\\\\?\\" + str(path)


@pytest.fixture(params=["junction", "plain"])
def dotted(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[tuple[Path, str]]:
    """``proj\\kq.`` (made through ``\\\\?\\``) next to ``proj\\kq``: a junction to ``secretsz``,
    which holds ``.env``, or a plain folder holding ``.env``. ``???`` matches ``kq.`` only."""
    proj = tmp_path / "proj"
    inner = proj / ("secretsz" if request.param == "junction" else "kq")
    inner.mkdir(parents=True)
    (inner / ".env").write_text("MADE_UP=1\n", encoding="utf-8")
    os.mkdir(_extended(proj / "kq."))
    link = proj / "kq"
    if request.param == "junction":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(inner)], check=True, capture_output=True
        )
    yield proj, request.param
    if request.param == "junction":
        os.rmdir(link)  # the junction only, never what it points to
    os.rmdir(_extended(proj / "kq."))  # without the prefix Win32 would open "kq"


def _decide(proj: Path, tool: str, text: str, *, backend: bool) -> tuple[Any, FakeBackend | None]:
    pol = policy(llm=backend)
    auditor, fake = manipulated(pol) if backend else (None, None)
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        {
            "hook_event_name": "PreToolUse",
            "session_id": "00000000-0000-4000-8000-0000000000b1",
            "cwd": str(proj),
            "project_dir": str(proj),
            "tool_name": tool,
            "tool_input": {"command": text},
        },
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


# ------------------------------------------------------------------ R38-1, R38-2


def test_glob_match_is_an_informational_reason() -> None:
    assert paths.reading_only(("trailing-dots-spaces-ambiguous", "glob-match"))
    assert paths.reading_only(
        ("trailing-dots-spaces-ambiguous", "resolved-on-disk", "glob-match", "variable-expanded")
    )
    assert not paths.reading_only(("glob-match",))  # not unsure of a reading: nothing to say
    assert not paths.reading_only(("trailing-dots-spaces-ambiguous", "no-cwd", "glob-match"))


@windows_only
@pytest.mark.parametrize(
    ("tool", "text"),
    [
        ("Bash", "rg made ???"),
        ("Bash", "tar -czf out.tgz ???"),
        ("Bash", "grep -r made ???"),
        ("PowerShell", "rg made ???"),
        ("PowerShell", "Copy-Item -Recurse ??? backup"),
    ],
)
@pytest.mark.parametrize("backend", [False, True])
def test_a_glob_match_unsure_of_its_reading_is_walked(
    dotted: tuple[Path, str], tool: str, text: str, backend: bool
) -> None:
    # revision 38: gray with a junction (deny in revision 37); gray with a plain folder since M3a
    proj, _layout = dotted
    decision, fake = _decide(proj, tool, text, backend=backend)
    assert decision.decision == "deny"
    assert decision.decided_by == "rule:no-secret-read"
    assert fake is None or not fake.requests


@windows_only
def test_the_name_written_out_was_denied_all_along(dotted: tuple[Path, str]) -> None:
    proj, _layout = dotted
    decision, _ = _decide(proj, "Bash", "rg made kq.", backend=False)
    assert decision.decided_by == "rule:no-secret-read"


@windows_only
def test_the_disk_form_keeps_glob_match_and_is_walked(dotted: tuple[Path, str]) -> None:
    proj, layout = dotted
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "00000000-0000-4000-8000-0000000000b2",
        "cwd": str(proj),
        "project_dir": str(proj),
        "tool_name": "Bash",
        "tool_input": {"command": "rg made ???"},
    }
    actions = normalize_event(
        payload, platform="windows", env={"USERPROFILE": WIN_HOME}, home=WIN_HOME, budget_s=5
    )
    refs = [r for a in actions for r in a.paths]
    matches = [r for r in refs if "glob-match" in r.reasons]
    assert matches
    assert all(r.uncertain for r in matches)  # unsure of the reading only
    hits = [r.key.casefold() for r in refs if "recursive-scan" in r.reasons]
    assert any(k.endswith("/kq/.env") for k in hits)  # the match itself is walked (R38-2)
    if layout == "junction":
        resolved = [r for r in matches if "resolved-on-disk" in r.reasons]
        assert any(r.key.casefold().endswith("/secretsz") for r in resolved)  # revision 38 kept
        assert any(k.endswith("/secretsz/.env") for k in hits)  # and its form on disk (R38-1)


# ------------------------------------------------------------------ R38-3


@windows_only
@pytest.mark.parametrize("cd", ["Set-Location $env:PROJ_DIR", "Set-Location $PWD"])
def test_a_glob_after_a_cd_to_the_cwd_through_a_variable_is_sent_as_written_only(
    tmp_path: Path, cd: str
) -> None:
    # a cost written in the spec (revision 39): the matches in the project are not shown either
    proj = tmp_path / "projg"
    proj.mkdir()
    for name in ("a.txt", "b.txt"):
        (proj / name).write_text("x\n", encoding="utf-8")
    pol = policy(llm=True)
    auditor, fake = manipulated(pol)
    pipeline.decide(
        protocol.EVENT_PRE,
        {
            "hook_event_name": "PreToolUse",
            "session_id": "00000000-0000-4000-8000-0000000000b3",
            "cwd": str(proj),
            "project_dir": str(proj),
            "tool_name": "PowerShell",
            "tool_input": {"command": f"{cd}; Get-Content *.txt"},
        },
        mode="enforce",
        policy=pol,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": WIN_HOME, "PROJ_DIR": str(proj)},
        home=WIN_HOME,
        scan_disk=True,
        auditor=auditor,
    )
    actions = json.loads(fake.requests[0].content)["actions"]
    assert [p["path"] for p in actions[-1]["paths"]] == ["*.txt"]
