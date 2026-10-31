"""The spec changes accepted after the X1 review of M3a (PROJECT_SPEC.md revision 7).

* P-F1 (F1): a session that read untrusted content and wrote into a project marks it; the dev tools
  then ask in every session there (``ask-devtools-after-untrusted-project-write``) until the user
  runs ``boundkeep taint clear`` in a terminal.
* P-F6 (F6): the taint window is used up only by the taint step's asks, not by every call; the
  default window is 3.
* P-F2: the MCP resource tools are default taint sources (their reproduction is in
  ``test_m3a_x1_fixes.py``; the names come from the hook experiment in docs/hook-behavior.md).

Inert payloads only: made-up machine paths, ``.invalid`` hosts; the LLM is ``FakeBackend``.
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from boundkeep import doctor, paths, protocol, taintcmd, trust
from boundkeep.audit.auditor import Auditor
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.normalize.event import normalize_event
from boundkeep.policy import PolicyError
from boundkeep.policy.schema import DEFAULT_TAINT_SOURCES
from boundkeep.session import store as store_mod
from boundkeep.session.facts import FRESH, SessionFacts
from boundkeep.session.marks import ALL_LOCATIONS, location_key, marked, written_locations
from boundkeep.session.store import SessionStore, UnavailableStore
from tests.unit.test_m3a_pipeline import HOME, PROJECT, SID, bash, decide, event, policy, post
from tests.unit.test_m3a_schema_cli import parse

OTHER_SID = "00000000-0000-4000-8000-0000000000dd"
OTHER_PROJECT = "/home/testuser/other"
MARK_RULE = "ask-devtools-after-untrusted-project-write"


@pytest.fixture
def store(tmp_path: Path) -> Any:
    s = SessionStore(str(tmp_path / "session.sqlite"))
    yield s
    s.close()


def in_other_session(payload: dict[str, Any], project: str = PROJECT) -> dict[str, Any]:
    return dict(payload, session_id=OTHER_SID, cwd=project, project_dir=project)


def locations(s: SessionStore) -> list[str]:
    marks = s.marks()
    assert marks is not None
    return [m.location for m in marks]


# ------------------------------------------------------------------ P-F1: marking the project

WRITES = [
    event("Write", {"file_path": f"{PROJECT}/tests/test_x.py", "content": "x"}),
    event("Edit", {"file_path": f"{PROJECT}/conftest.py", "old_string": "a", "new_string": "b"}),
    bash("echo x > tests/test_y.py"),
    bash("cp /home/testuser/notes.txt tests/test_z.py"),
    bash("tee tests/test_w.py < /dev/null"),
]


@pytest.mark.parametrize("write", WRITES, ids=lambda p: str(p["tool_input"])[:40])
def test_a_write_after_untrusted_content_makes_the_dev_tools_ask_in_other_sessions(
    store: SessionStore, write: dict[str, Any]
) -> None:
    pol = policy(trusted=True)
    post("WebFetch", store, pol)
    decide(write, pol, store=store)
    assert locations(store) == [PROJECT]
    asked = decide(in_other_session(bash("pytest -q")), pol, store=store)
    assert asked.decision == protocol.DECISION_ASK
    assert asked.rule_ids == (MARK_RULE,)
    assert "taint clear" in asked.reason


@pytest.mark.parametrize(
    "call",
    [
        event("Read", {"file_path": f"{PROJECT}/src/app.py"}),
        event("Grep", {"pattern": "x", "path": f"{PROJECT}/src"}),
        bash("cat src/app.py"),
        bash("git status"),
        bash("ls -la tests"),
    ],
    ids=lambda p: str(p["tool_input"])[:30],
)
def test_reads_after_untrusted_content_leave_no_mark(
    store: SessionStore, call: dict[str, Any]
) -> None:
    pol = policy(trusted=True)
    post("WebFetch", store, pol)
    decide(call, pol, store=store)
    assert locations(store) == []
    ran = decide(in_other_session(bash("pytest -q")), pol, store=store)
    assert ran.decision == protocol.DECISION_NONE  # allowed in the trusted project, unasked


def test_a_write_in_a_session_that_read_nothing_untrusted_leaves_no_mark(
    store: SessionStore,
) -> None:
    pol = policy(trusted=True)
    decide(WRITES[0], pol, store=store)
    assert locations(store) == []
    assert decide(in_other_session(bash("pytest -q")), pol, store=store).decision == "none"


def test_a_write_into_another_project_marks_that_path(store: SessionStore) -> None:
    pol = policy(trusted=True)
    post("WebFetch", store, pol)
    target = f"{OTHER_PROJECT}/tests/test_x.py"
    decide(event("Write", {"file_path": target, "content": "x"}), pol, store=store)
    assert target in locations(store)
    there = decide(in_other_session(bash("pytest -q"), OTHER_PROJECT), pol, store=store)
    assert MARK_RULE in there.rule_ids
    # the session's own project was not written: its dev tools run as before
    assert decide(in_other_session(bash("pytest -q")), pol, store=store).decision == "none"


def test_a_mark_outlives_the_session_cleanup_and_a_restart(tmp_path: Path) -> None:
    path = str(tmp_path / "s.sqlite")
    now = [1_000.0]
    first = SessionStore(path, clock=lambda: now[0])
    pol = policy(trusted=True)
    post("WebFetch", first, pol)
    decide(WRITES[0], pol, store=first)
    now[0] += 400 * 24 * 3600  # far beyond the retention of the session itself
    first.cleanup()
    first.close()
    again = SessionStore(path, clock=lambda: now[0])
    try:
        assert locations(again) == [PROJECT]
        assert decide(in_other_session(bash("pytest -q")), pol, store=again).decision == "ask"
    finally:
        again.close()


def test_clearing_the_marks_lets_the_dev_tools_run_again(store: SessionStore) -> None:
    pol = policy(trusted=True)
    post("WebFetch", store, pol)
    decide(WRITES[0], pol, store=store)
    assert store.clear_marks("/home/testuser/elsewhere") == []
    assert store.clear_marks(PROJECT) == [PROJECT]
    assert decide(in_other_session(bash("pytest -q")), pol, store=store).decision == "none"


def test_too_many_places_become_one_mark_for_every_project(
    store: SessionStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_mod, "MAX_MARKS", 3)
    assert store.mark_written(["/a/one", "/a/two", "/a/three"], sources=("WebFetch",))
    assert store.mark_written(["/a/four"])
    assert locations(store) == [ALL_LOCATIONS, "/a/one", "/a/three", "/a/two"]
    facts = store.tool_call(OTHER_SID, "Bash", sources=DEFAULT_TAINT_SOURCES, window=3)
    assert marked("/b/unrelated", None, facts.marks)
    assert store.clear_marks(None) is not None
    assert locations(store) == []


def test_marks_that_cannot_be_read_count_as_written() -> None:
    pol = policy(trusted=True)
    unread = SessionFacts(known=True, tainted=False, read_untrusted=False, marks_known=False)
    result = pipeline.review(
        bash("pytest -q"), pol, platform="posix", env={"HOME": HOME}, home=HOME,
        scan_disk=False, session=unread,
    )  # fmt: skip
    assert result.verdict.decision == "ask"
    assert result.verdict.rule_ids == (MARK_RULE,)
    stand_in = UnavailableStore("disk full")
    assert stand_in.mark_written([PROJECT]) is False
    assert stand_in.marks() is None
    assert stand_in.clear_marks(None) is None


def test_the_rule_field_is_only_for_deny_and_ask_rules() -> None:
    rule = (
        "rules:\n  - id: r\n    tool: [Bash]\n"
        "    match: {program: [make], project_written_after_untrusted: true}\n"
    )
    assert parse(rule + "    action: ask\n    reason: x\n").rules[0].match
    with pytest.raises(PolicyError, match="deny and ask"):
        parse(rule + "    action: allow\n")


# ------------------------------------------------------------- P-F1: which places, which match


def actions_of(payload: dict[str, Any]) -> list[Any]:
    return list(normalize_event(payload, platform="posix", env={"HOME": HOME}, home=HOME))


def test_written_locations_takes_the_project_for_inside_writes_and_the_path_for_outside() -> None:
    assert written_locations(actions_of(WRITES[0])) == (PROJECT,)
    assert written_locations(actions_of(bash("cat a b"))) == ()
    outside = written_locations(actions_of(bash(f"echo x > {OTHER_PROJECT}/t.py")))
    assert outside == (f"{OTHER_PROJECT}/t.py",)
    unsure = written_locations(actions_of(bash("echo x > $TARGET/t.py")))
    assert unsure == (PROJECT,)


@pytest.mark.parametrize(
    ("project", "resolved", "marks", "expected"),
    [
        ("/home/u/proj", None, (), False),
        ("/home/u/proj", None, ("/home/u/proj",), True),
        ("/home/u/proj", None, ("/home/u/proj/tests/test_x.py",), True),  # a write inside
        ("/home/u/proj/sub", None, ("/home/u/proj",), True),  # a project below a marked one
        ("/home/u/proj2", None, ("/home/u/proj",), False),  # whole segments only
        ("/home/u/proj", None, ("/home/u/other",), False),
        ("/home/u/link", "/data/proj", ("/data/proj",), True),  # the resolved form counts
        (None, None, ("/home/u/other",), True),  # the project is not known
        (None, None, (), False),
        ("/home/u/proj", None, (ALL_LOCATIONS,), True),
        ("c:/Users/U/Proj", None, ("C:/users/u/proj/t.py",), True),  # Windows keys casefold
        ("/Home/u/proj", None, ("/home/u/proj",), False),  # POSIX keys do not
        ("c:/users/u/proj", None, ("/users/u/proj",), False),  # another flavor never matches
    ],
)
def test_marked(project: str | None, resolved: str | None, marks: tuple[str, ...], expected: bool):
    assert marked(project, resolved, marks) is expected


def test_location_keys_refuse_what_cannot_be_compared() -> None:
    for bad in ("", "relative/x", "//server/share", "c:", "c:/", "/", "/a/../b", "/a\x00b"):
        assert location_key(bad) is None
    assert location_key("C:/Users/X/") == "c:/users/x"
    assert location_key("/home/U/") == "/home/U"


# --------------------------------------------------------------------- P-F6: the taint window


def manipulated() -> tuple[Any, Auditor, FakeBackend]:
    pol = policy(llm=True)
    backend = FakeBackend.answering()
    return pol, Auditor(pol.llm_audit, backend), backend


def test_only_the_taint_steps_asks_use_up_the_window(store: SessionStore) -> None:
    pol, auditor, _backend = manipulated()
    assert pol.taint.window == 3
    decide(event("WebFetch", {"url": "https://example.invalid", "prompt": "p"}), pol, store=store)
    for i in range(20):  # padding: harmless calls use up nothing
        decide(event("Read", {"file_path": f"{PROJECT}/f{i}.py"}), pol, store=store)
    outcomes = [decide(bash("make release"), pol, store=store, auditor=auditor) for _ in range(4)]
    assert [o.decision for o in outcomes[:3]] == ["ask"] * 3
    assert all(o.llm and "tainted-sensitive" in o.llm["steps"] for o in outcomes[:3])
    # the user was asked three times: the window is used up, the model's allow stands
    assert outcomes[3].decision == protocol.DECISION_NONE
    assert outcomes[3].taint is not None
    assert outcomes[3].taint["taint_asks"] == 3


def test_audit_only_asks_nobody_and_uses_up_nothing(store: SessionStore) -> None:
    pol, auditor, _backend = manipulated()
    post("WebFetch", store, pol)
    for _ in range(5):
        logged = decide(bash("make release"), pol, store=store, auditor=auditor, mode="audit-only")
        assert logged.would_be == "ask"
    assert store.facts(SID, window=3).taint_asks == 0
    assert decide(bash("make release"), pol, store=store, auditor=auditor).decision == "ask"


def test_a_new_source_call_restarts_the_used_up_window(store: SessionStore) -> None:
    pol, auditor, _backend = manipulated()
    post("WebFetch", store, pol)
    for _ in range(3):
        decide(bash("make release"), pol, store=store, auditor=auditor)
    assert decide(bash("make release"), pol, store=store, auditor=auditor).decision == "none"
    post("mcp__docs__search", store, pol)
    assert decide(bash("make release"), pol, store=store, auditor=auditor).decision == "ask"


def test_a_schema_1_database_is_migrated_and_every_window_starts_again(tmp_path: Path) -> None:
    path = tmp_path / "session.sqlite"
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE sessions (session_id TEXT PRIMARY KEY, first_seen REAL NOT NULL,"
        " last_seen REAL NOT NULL, calls_since_taint INTEGER,"
        " sources TEXT NOT NULL DEFAULT '[]') WITHOUT ROWID;"
        "CREATE TABLE prompts (session_id TEXT NOT NULL, seq INTEGER NOT NULL, at REAL NOT NULL,"
        " text TEXT NOT NULL, PRIMARY KEY (session_id, seq)) WITHOUT ROWID;"
        "INSERT INTO sessions VALUES ('old', 1.0, 1.0, 500, '[\"WebFetch\"]');"
        "INSERT INTO sessions VALUES ('clean', 1.0, 1.0, NULL, '[]');"
        "PRAGMA user_version=1;"
    )
    conn.close()
    s = SessionStore(str(path))
    try:
        old = s.facts("old", window=3)
        assert (old.read_untrusted, old.tainted, old.taint_asks) == (True, True, 0)
        assert old.sources == ("WebFetch",)
        assert not s.facts("clean", window=3).read_untrusted
        assert locations(s) == []
    finally:
        s.close()
    check = sqlite3.connect(path)
    assert check.execute("PRAGMA user_version").fetchone()[0] == store_mod.SCHEMA_VERSION
    check.close()


# ------------------------------------------------------------- P-F1: boundkeep taint list|clear


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(paths.HOME_ENV, str(tmp_path / "bk"))
    (tmp_path / "bk").mkdir()
    for name in trust.AGENT_ENV:
        monkeypatch.delenv(name, raising=False)
    return tmp_path / "bk"


def clear_args(project_dir: str | None = None, everything: bool = False) -> argparse.Namespace:
    return argparse.Namespace(project_dir=project_dir, all=everything)


def seeded(home: Path, *places: str) -> None:
    s = SessionStore(paths.session_db_file(str(home)))
    s.mark_written(places, sources=("WebFetch",))
    s.close()


def test_taint_clear_refuses_inside_claude_code(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seeded(home, PROJECT)
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setattr(taintcmd, "_stdin_is_tty", lambda: True)
    assert taintcmd.cmd_clear(clear_args(everything=True)) == taintcmd.EXIT_PROBLEM
    assert "refuses to run inside a process Claude Code started" in capsys.readouterr().err
    s = SessionStore(paths.session_db_file(str(home)))
    assert locations(s) == [PROJECT]
    s.close()


def test_taint_clear_refuses_without_a_terminal(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seeded(home, PROJECT)
    monkeypatch.setattr(taintcmd, "_stdin_is_tty", lambda: False)
    assert taintcmd.cmd_clear(clear_args(everything=True)) == taintcmd.EXIT_PROBLEM
    assert "needs an interactive terminal" in capsys.readouterr().err


def test_taint_list_and_clear_in_a_terminal(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    key = taintcmd._keys(str(project))[0]
    seeded(home, key, f"{key}/tests/test_x.py", "/elsewhere/kept")
    monkeypatch.setattr(taintcmd, "_stdin_is_tty", lambda: True)
    assert taintcmd.cmd_list(argparse.Namespace()) == taintcmd.EXIT_OK
    listed = capsys.readouterr().out
    assert "3" in listed
    assert "WebFetch" in listed
    assert taintcmd.cmd_clear(clear_args(str(project))) == taintcmd.EXIT_OK
    out = capsys.readouterr().out
    assert out.count("cleared:") == 2
    s = SessionStore(paths.session_db_file(str(home)))
    assert locations(s) == ["/elsewhere/kept"]
    s.close()
    assert taintcmd.cmd_clear(clear_args(everything=True)) == taintcmd.EXIT_OK
    s = SessionStore(paths.session_db_file(str(home)))
    assert locations(s) == []
    s.close()


def test_taint_commands_without_a_database_create_none(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(taintcmd, "_stdin_is_tty", lambda: True)
    assert taintcmd.cmd_list(argparse.Namespace()) == taintcmd.EXIT_OK
    assert taintcmd.cmd_clear(clear_args(everything=True)) == taintcmd.EXIT_OK
    assert capsys.readouterr().out.count("no project marks") == 2
    assert not Path(paths.session_db_file(str(home))).exists()


def test_doctor_lists_the_marks(home: Path) -> None:
    assert doctor.check_project_marks(str(home))[0].detail == "no project marks"
    seeded(home, PROJECT)
    (check,) = doctor.check_project_marks(str(home))
    assert check.status == doctor.INFO
    assert PROJECT in check.detail
    assert "taint clear" in check.fix


def test_a_fresh_session_sees_no_marks(store: SessionStore) -> None:
    facts = store.tool_call(SID, "Read", sources=DEFAULT_TAINT_SOURCES, window=3)
    assert facts == FRESH
