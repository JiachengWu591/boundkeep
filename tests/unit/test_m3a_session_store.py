"""Session state in SQLite (session/store.py): taint window, sticky bit, intents, concurrency,
cleanup, and every failure path ending in "unknown" (judged as tainted)."""

from __future__ import annotations

import itertools
import multiprocessing
import os
import sqlite3
import sys
import threading
from pathlib import Path

import pytest

from boundkeep import fsperm
from boundkeep.policy.schema import MAX_TAINT_WINDOW
from boundkeep.session import store as store_mod
from boundkeep.session.facts import FRESH, UNKNOWN, is_taint_source
from boundkeep.session.store import (
    COUNT_CAP,
    MAX_SOURCES,
    SessionStore,
    SessionStoreError,
    UnavailableStore,
    open_store,
)

SOURCES = ("WebFetch", "WebSearch", "mcp__*")
SID = "00000000-0000-4000-8000-0000000000aa"


@pytest.fixture
def store(tmp_path: Path) -> SessionStore:
    s = SessionStore(str(tmp_path / "session.sqlite"))
    yield s
    s.close()


def call(
    s: SessionStore | UnavailableStore, tool: str = "Read", sid: object = SID, window: int = 8
):
    return s.tool_call(sid, tool, sources=SOURCES, window=window)


_IDS = itertools.count()


def approved(s: SessionStore, sid: str = SID) -> bool:
    """One ask of the taint step that the user approved and whose tool ran: recorded with its
    tool_use_id, counted when the PostToolUse of that id arrives (revision 8, P-R3)."""
    tool_use_id = f"toolu_{os.getpid()}_{next(_IDS)}"
    return s.taint_asked(sid, tool_use_id) and s.tool_result(
        sid, "Bash", sources=SOURCES, tool_use_id=tool_use_id
    )


# ------------------------------------------------------------------------------ taint window


def test_a_new_session_is_fresh(store: SessionStore) -> None:
    facts = call(store)
    assert (facts.known, facts.tainted, facts.read_untrusted) == (True, False, False)
    assert facts.sources == ()


def test_only_the_taint_steps_asks_use_up_the_window_and_the_bit_stays(store: SessionStore) -> None:
    fetch = call(store, "WebFetch")
    # the source call is judged in the state before it
    assert not fetch.tainted
    assert not fetch.read_untrusted
    # revision 7, P-F6: calls the taint step did not change use up nothing
    seen = [call(store, window=3) for _ in range(10)]
    assert all(f.tainted for f in seen)
    assert {f.taint_asks for f in seen} == {0}
    assert seen[0].sources == ("WebFetch",)
    states = []
    for _ in range(5):
        states.append(call(store, window=3).tainted)
        assert approved(store)
    assert states == [True, True, True, False, False]
    assert call(store, window=3).read_untrusted  # sticky: the window does not end it


def test_a_post_tool_use_of_a_source_restarts_the_window(store: SessionStore) -> None:
    call(store, "WebFetch")
    for _ in range(3):
        approved(store)
    assert not call(store, window=3).tainted
    assert store.tool_result(SID, "WebFetch", sources=SOURCES)
    assert call(store, window=3).taint_asks == 0
    assert all(call(store, window=3).tainted for _ in range(7))


def test_a_taint_ask_without_a_source_counts_nothing(store: SessionStore) -> None:
    call(store)
    assert approved(store)
    assert approved(store, "never-seen")
    assert call(store) == FRESH


def test_an_ask_without_a_usable_tool_use_id_is_not_recorded(store: SessionStore) -> None:
    call(store, "WebFetch")
    for bad in (None, "", " padded ", "x" * 129, "bad\x00id", 42):
        assert store.taint_asked(SID, bad) is False
        store.tool_result(SID, "Bash", sources=SOURCES, tool_use_id=bad)
    assert call(store).taint_asks == 0


def test_a_post_alone_marks_the_session(store: SessionStore) -> None:
    # the PreToolUse of the source was never seen (a restart in between)
    assert store.tool_result(SID, "mcp__github__get_issue", sources=SOURCES)
    facts = call(store)
    assert facts.tainted
    assert facts.read_untrusted
    assert facts.sources == ("mcp__github__get_issue",)


def test_other_tools_never_mark(store: SessionStore) -> None:
    for tool in ("Read", "Bash", "PowerShell", "Write", "Agent", "mcp_", "WebFetchX", "webfetch"):
        assert store.tool_result(SID, tool, sources=SOURCES)
        call(store, tool)
    assert not call(store).read_untrusted


def test_a_source_called_again_inside_the_window_extends_it(store: SessionStore) -> None:
    call(store, "WebSearch")
    for _ in range(5):
        call(store)
    call(store, "WebFetch")
    seen = [call(store) for _ in range(8)]
    assert all(f.tainted for f in seen)
    assert set(seen[-1].sources) == {"WebSearch", "WebFetch"}


def test_the_window_comes_from_the_caller_every_time(store: SessionStore) -> None:
    call(store, "WebFetch")
    for _ in range(3):
        approved(store)
    assert not store.tool_call(SID, "Read", sources=SOURCES, window=2).tainted
    assert store.tool_call(SID, "Read", sources=SOURCES, window=50).tainted


def test_the_count_stops_at_the_cap(store: SessionStore) -> None:
    assert COUNT_CAP == MAX_TAINT_WINDOW + 1
    call(store, "WebFetch")
    with store._transaction() as conn:  # jump ahead instead of 1000 asks
        conn.execute("UPDATE sessions SET taint_asks = ?", (COUNT_CAP - 1,))
    assert approved(store)
    assert call(store, window=MAX_TAINT_WINDOW).taint_asks == COUNT_CAP
    for _ in range(3):
        approved(store)
    facts = call(store, window=MAX_TAINT_WINDOW)
    assert facts.taint_asks == COUNT_CAP
    assert not facts.tainted
    assert facts.read_untrusted


def test_source_names_are_kept_short_and_bounded(store: SessionStore) -> None:
    for i in range(40):
        store.tool_result(SID, f"mcp__s{i}__" + "t" * 300, sources=SOURCES)
    facts = call(store)
    assert len(facts.sources) == MAX_SOURCES
    assert all(len(s) <= store_mod.MAX_SOURCE_CHARS for s in facts.sources)


@pytest.mark.parametrize(
    "sid", [None, "", "  padded ", "x" * 201, "bad\x00id", "line\nbreak", 42, ["list"]]
)
def test_an_unusable_session_id_is_unknown(store: SessionStore, sid: object) -> None:
    facts = call(store, sid=sid)
    assert (facts.known, facts.tainted, facts.read_untrusted) == (False, True, True)
    assert facts.marks_known  # the project marks need no session id
    assert UNKNOWN.tainted
    assert UNKNOWN.read_untrusted
    assert not UNKNOWN.known
    assert not UNKNOWN.marks_known
    assert store.tool_result(sid, "WebFetch", sources=SOURCES) is False
    assert store.add_prompt(sid, "text", keep=3) is False
    assert store.taint_asked(sid) is False


def test_sessions_are_apart(store: SessionStore) -> None:
    call(store, "WebFetch", sid="a")
    assert call(store, sid="a").tainted
    assert call(store, sid="b") == FRESH


def test_reading_the_facts_and_plain_calls_count_nothing(store: SessionStore) -> None:
    call(store, "WebFetch")
    for _ in range(3):
        assert store.facts(SID, window=8).taint_asks == 0
        assert call(store).taint_asks == 0
    approved(store)
    assert store.facts(SID, window=8).taint_asks == 1


def test_is_taint_source_reads_patterns_like_the_matcher() -> None:
    assert is_taint_source("mcp__x__y", ("mcp__*",))
    assert is_taint_source("WebFetch", ("WebFetch",))
    assert not is_taint_source("WebFetch2", ("WebFetch",))
    assert not is_taint_source("", ("mcp__*",))


# ------------------------------------------------------------------------------ the E9 facts


def test_resume_and_compact_keep_the_session_and_a_clear_starts_a_new_one(tmp_path: Path) -> None:
    path = str(tmp_path / "session.sqlite")
    first = SessionStore(path)
    first.tool_call(SID, "WebFetch", sources=SOURCES, window=8)
    first.close()
    # the daemon restarts; Claude Code resumes (or compacts): same session_id (E9)
    again = SessionStore(path)
    facts = again.tool_call(SID, "Read", sources=SOURCES, window=8)
    assert facts.tainted
    assert facts.read_untrusted
    # /clear: a new session_id, nothing carried over
    assert (
        again.tool_call("11111111-1111-4111-8111-111111111111", "Read", sources=SOURCES, window=8)
        == FRESH
    )
    again.close()


def test_calls_of_a_subagent_share_the_session(store: SessionStore) -> None:
    # sub-agent events carry the parent's session_id (fixture PreToolUse__PowerShell_in_subagent)
    store.tool_result(SID, "WebFetch", sources=SOURCES)  # the sub-agent fetched a page
    assert call(store, "PowerShell").tainted  # the main agent's next call


# ------------------------------------------------------------------------------ task intents


def test_prompts_keep_the_latest_n_in_order(store: SessionStore) -> None:
    for i in range(6):
        assert store.add_prompt(SID, f"prompt {i}", keep=3)
    facts = store.tool_call(SID, "Read", sources=SOURCES, window=8, intents=3)
    assert facts.intents == ("prompt 3", "prompt 4", "prompt 5")
    assert store.tool_call(SID, "Read", sources=SOURCES, window=8, intents=1).intents == (
        "prompt 5",
    )
    assert store.tool_call(SID, "Read", sources=SOURCES, window=8).intents == ()


def test_purging_prompts_keeps_the_taint(store: SessionStore) -> None:
    store.add_prompt(SID, "my task", keep=3)
    call(store, "WebFetch")
    assert store.purge_prompts() == 1
    facts = store.tool_call(SID, "Read", sources=SOURCES, window=8, intents=3)
    assert facts.intents == ()
    assert facts.tainted


def test_an_empty_prompt_is_not_stored(store: SessionStore) -> None:
    assert store.add_prompt(SID, "", keep=3) is False
    assert store.session_count() == 0


# ------------------------------------------------------------------------------ cleanup


def test_cleanup_removes_idle_sessions_and_their_prompts(tmp_path: Path) -> None:
    now = [1_000_000.0]
    s = SessionStore(str(tmp_path / "s.sqlite"), clock=lambda: now[0])
    s.tool_call("old", "WebFetch", sources=SOURCES, window=8)
    s.add_prompt("old", "old task", keep=3)
    now[0] += store_mod.RETENTION_S - 10
    s.tool_call("young", "WebFetch", sources=SOURCES, window=8)
    now[0] += 20
    assert s.cleanup() == 1
    assert s.tool_call("old", "Read", sources=SOURCES, window=8, intents=3) == FRESH
    assert s.tool_call("young", "Read", sources=SOURCES, window=8).read_untrusted
    with s._transaction() as conn:
        assert conn.execute("SELECT COUNT(*) FROM prompts").fetchone()[0] == 0
    s.close()


def test_an_active_tainted_session_is_kept_alive(tmp_path: Path) -> None:
    now = [5_000.0]
    s = SessionStore(str(tmp_path / "s.sqlite"), clock=lambda: now[0])
    s.tool_call(SID, "WebFetch", sources=SOURCES, window=8)
    with s._transaction() as conn:  # the window used up: only the hourly touch writes
        conn.execute("UPDATE sessions SET taint_asks = ?", (COUNT_CAP,))
    for _ in range(40):  # 40 days of activity, one call a day
        now[0] += 24 * 3600
        s.tool_call(SID, "Read", sources=SOURCES, window=8)
    s.cleanup()
    assert s.tool_call(SID, "Read", sources=SOURCES, window=8).read_untrusted
    s.close()


def test_cleanup_drops_the_least_recently_active_above_the_cap(tmp_path: Path) -> None:
    now = [10.0]
    s = SessionStore(str(tmp_path / "s.sqlite"), clock=lambda: now[0])
    for i in range(12):
        now[0] += 1
        s.tool_call(f"s{i:02d}", "WebFetch", sources=SOURCES, window=8)
    assert s.cleanup(max_sessions=5) == 7
    assert s.session_count() == 5
    assert s.tool_call("s00", "Read", sources=SOURCES, window=8) == FRESH
    assert s.tool_call("s11", "Read", sources=SOURCES, window=8).read_untrusted
    s.close()


# ------------------------------------------------------------------------------ concurrency


def _call_and_ask(s: SessionStore) -> None:
    s.tool_call(SID, "Read", sources=SOURCES, window=1000)
    approved(s)


def test_parallel_tool_calls_lose_no_update(store: SessionStore) -> None:
    call(store, "WebFetch")
    threads = [
        threading.Thread(target=lambda: [_call_and_ask(store) for _ in range(100)])
        for _ in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert store.facts(SID, window=1000).taint_asks == 800


def test_two_stores_on_one_file_lose_no_update(tmp_path: Path) -> None:
    path = str(tmp_path / "shared.sqlite")
    a, b = SessionStore(path), SessionStore(path)
    a.tool_call(SID, "WebFetch", sources=SOURCES, window=8)
    threads = [
        threading.Thread(target=lambda s=s: [_call_and_ask(s) for _ in range(60)])
        for s in (a, b, a, b)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert a.error_count == 0
    assert b.error_count == 0
    assert a.facts(SID, window=1000).taint_asks == 240
    a.close()
    b.close()


def _count_in_process(path: str, n: int) -> None:
    s = SessionStore(path)
    for _ in range(n):
        _call_and_ask(s)
    s.close()


def test_two_processes_lose_no_update(tmp_path: Path) -> None:
    path = str(tmp_path / "proc.sqlite")
    first = SessionStore(path)
    first.tool_call(SID, "WebFetch", sources=SOURCES, window=8)
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_count_in_process, args=(path, 100)) for _ in range(2)]
    for p in procs:
        p.start()
    for _ in range(100):
        _call_and_ask(first)
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    assert first.facts(SID, window=1000).taint_asks == 300
    first.close()


# ------------------------------------------------------------------------------ failure paths


def test_a_corrupt_file_cannot_be_opened_and_the_stand_in_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "session.sqlite"
    path.write_bytes(b"this is not a database" * 100)
    with pytest.raises(SessionStoreError):
        SessionStore(str(path))
    stand_in = open_store(str(path))
    assert isinstance(stand_in, UnavailableStore)
    assert call(stand_in) == UNKNOWN
    assert stand_in.tool_result(SID, "WebFetch", sources=SOURCES) is False
    assert stand_in.add_prompt(SID, "x", keep=3) is False
    assert stand_in.cleanup() is None


def test_a_newer_schema_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "session.sqlite"
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version=99")
    conn.close()
    with pytest.raises(SessionStoreError, match="schema version 99"):
        SessionStore(str(path))


def test_a_closed_store_answers_unknown(tmp_path: Path) -> None:
    s = SessionStore(str(tmp_path / "s.sqlite"))
    s.close()
    assert call(s) == UNKNOWN
    assert s.tool_result(SID, "WebFetch", sources=SOURCES) is False
    assert s.error_count == 2
    assert s.last_error is not None
    assert SID not in s.last_error


def test_a_broken_table_answers_unknown_and_is_counted(store: SessionStore) -> None:
    with store._transaction() as conn:
        conn.execute("DROP TABLE sessions")
    assert call(store) == UNKNOWN
    assert store.error_count == 1
    assert store.cleanup() is None


def test_a_database_a_directory_cannot_be_opened(tmp_path: Path) -> None:
    (tmp_path / "dir.sqlite").mkdir()
    assert isinstance(open_store(str(tmp_path / "dir.sqlite")), UnavailableStore)


def test_the_file_is_private_and_in_wal_mode(tmp_path: Path) -> None:
    home = tmp_path / "home"
    fsperm.ensure_private_dir(home)
    path = home / "session.sqlite"
    s = SessionStore(str(path))
    s.tool_call(SID, "WebFetch", sources=SOURCES, window=8)
    assert [p for p in fsperm.check_private(path) if p.severity == "error"] == []
    if sys.platform != "win32":
        assert (os.stat(path).st_mode & 0o777) == 0o600
    other = sqlite3.connect(path)
    assert other.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    other.close()
    s.close()


def test_nothing_but_names_and_counters_is_stored(store: SessionStore) -> None:
    store.tool_result(SID, "WebFetch", sources=SOURCES)
    with store._transaction() as conn:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(sessions)")]
        marks = [row[1] for row in conn.execute("PRAGMA table_info(project_marks)")]
    assert columns == ["session_id", "first_seen", "last_seen", "taint_asks", "sources"]
    assert marks == ["location", "first_marked", "last_marked", "sources", "kinds"]
