"""PROJECT_SPEC.md revision 8, second batch: P-R2, P-R3, P-R9 (X1 re-review of the M3a fixes,
R-2, R-3, R-9; docs/reviews/M3a-rereview.md; hook tests in docs/hook-behavior.md).

P-R2: with an LLM backend, a gray call that runs project code (``npm test``) in a marked project
went to the model, and in another session its allow was the outcome. Now it is not sent and asks.
P-R3: the taint window was used up by asks the user refused or never saw. Now an ask counts only
when the PostToolUse of the same ``tool_use_id`` arrives (the user approved, the tool ran).
P-R9: ``--fork-session`` gives a new session id (SessionStart ``source: fork``, no parent id), so a
fork lost the sticky bit and the window. Now a resume, compact or fork whose id the store does not
know starts as having read untrusted content.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from boundkeep import doctor, hook_main, install, ownhook, protocol
from boundkeep.audit.auditor import Auditor
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.policy.loader import post_matcher_for, taint_sources_to_matcher
from boundkeep.policy.schema import DEFAULT_TAINT_SOURCES
from boundkeep.session.store import MAX_PENDING_ASKS, SessionStore, UnavailableStore
from tests.unit.test_hook_client import _bytes, _deadline, fake_daemon  # noqa: F401 - fixture
from tests.unit.test_m3a_pipeline import PROJECT, SID, bash, decide, event, policy, post
from tests.unit.test_m3a_rereview_fixes import layer, policy_home

OTHER_SID = "00000000-0000-4000-8000-0000000000ff"
STICKY_RULE = "ask-devtools-after-untrusted-content"


@pytest.fixture
def store(tmp_path: Path) -> Any:
    s = SessionStore(str(tmp_path / "session.sqlite"))
    yield s
    s.close()


def manipulated(*, trusted: bool = False) -> tuple[Any, Auditor, FakeBackend]:
    """A policy with an LLM backend whose model allows everything (fully manipulated)."""
    pol = policy(llm=True, trusted=trusted)
    backend = FakeBackend.answering()
    return pol, Auditor(pol.llm_audit, backend), backend


def ran(store: SessionStore, pol: Any, tool_use_id: str, tool: str = "Bash", **more: Any) -> None:
    """The PostToolUse of a call that the user approved and that ran."""
    payload = {"hook_event_name": "PostToolUse", "session_id": SID, "tool_name": tool}
    payload["tool_use_id"] = tool_use_id
    payload.update(more)
    decide(payload, pol, store=store, kind=protocol.EVENT_POST)


def release(n: int) -> dict[str, Any]:
    """A gray, sensitive call outside any project. Inside one, the first such call of a session
    that read untrusted content marks the project (P-R6), and from then on P-R2 keeps every call
    that runs code there from the model (``test_after_a_run_step_the_project_keeps_...``)."""
    call = bash("make release") | {"tool_use_id": f"toolu_{n}"}
    return {k: v for k, v in call.items() if k not in ("cwd", "project_dir")}


def started(store: SessionStore, pol: Any, source: object, sid: str = SID) -> None:
    payload: dict[str, Any] = {"hook_event_name": "SessionStart", "session_id": sid}
    if source is not None:
        payload["source"] = source
    decide(payload, pol, store=store, kind=protocol.EVENT_SESSION)


# ------------------------------------------------------- P-R2: marks reach the LLM path


def mark_the_project(store: SessionStore, pol: Any) -> None:
    """Session SID reads a web page and writes a test file: the project is marked."""
    post("WebFetch", store, pol)
    decide(
        event("Write", {"file_path": f"{PROJECT}/tests/test_x.py", "content": "x"}),
        pol,
        store=store,
    )


@pytest.mark.parametrize("command", ["npm test", "make test", "python -m unittest", "tox"])
def test_in_a_marked_project_exec_gray_calls_are_not_sent(
    store: SessionStore, command: str
) -> None:
    pol, auditor, backend = manipulated(trusted=True)
    mark_the_project(store, pol)
    asked = decide(bash(command) | {"session_id": OTHER_SID}, pol, store=store, auditor=auditor)
    assert asked.decision == protocol.DECISION_ASK
    assert asked.decided_by == "gray-marked-project"
    assert "taint clear" in asked.reason
    assert backend.requests == []


def test_in_an_unmarked_project_the_llm_still_decides(store: SessionStore) -> None:
    pol, auditor, backend = manipulated(trusted=True)
    allowed = decide(bash("npm test"), pol, store=store, auditor=auditor)
    assert allowed.decision == protocol.DECISION_NONE
    assert allowed.decided_by == "llm"
    assert len(backend.requests) == 1


def test_unreadable_marks_keep_exec_gray_calls_from_the_llm() -> None:
    pol, auditor, backend = manipulated()
    asked = decide(bash("npm test"), pol, store=UnavailableStore("broken"), auditor=auditor)
    assert asked.decision == protocol.DECISION_ASK
    assert asked.decided_by == "gray-marked-project"
    assert backend.requests == []


def test_after_a_run_step_the_project_keeps_its_code_from_the_model(store: SessionStore) -> None:
    pol, auditor, backend = manipulated()
    post("WebFetch", store, pol)
    first = decide(bash("make release"), pol, store=store, auditor=auditor)
    assert first.decision == protocol.DECISION_ASK  # the taint step, after the model's allow
    assert len(backend.requests) == 1
    # that call may write anything in the project (P-R6): the project is marked, and the model is
    # not asked about code run there again, whatever the window says, until 'taint clear' (P-R2)
    later = decide(bash("make release"), pol, store=store, auditor=auditor)
    assert later.decided_by == "gray-marked-project"
    assert len(backend.requests) == 1


def test_without_an_llm_a_marked_project_changes_nothing(store: SessionStore) -> None:
    pol = policy(trusted=True)
    mark_the_project(store, pol)
    asked = decide(bash("npm test") | {"session_id": OTHER_SID}, pol, store=store)
    assert (asked.decision, asked.decided_by) == (protocol.DECISION_ASK, "gray")


# --------------------------------------------- P-R3: the window counts approved, executed asks


def test_an_ask_counts_only_when_its_tool_ran(store: SessionStore) -> None:
    pol, auditor, _backend = manipulated()
    post("WebFetch", store, pol)
    asked = decide(release(1), pol, store=store, auditor=auditor)
    assert asked.decision == protocol.DECISION_ASK
    assert store.facts(SID, window=3).taint_asks == 0  # asked, not yet approved
    ran(store, pol, "toolu_1")
    assert store.facts(SID, window=3).taint_asks == 1
    ran(store, pol, "toolu_1")  # a second PostToolUse of the same call counts nothing
    assert store.facts(SID, window=3).taint_asks == 1


def test_refused_or_unseen_asks_never_use_up_the_window(store: SessionStore) -> None:
    pol, auditor, _backend = manipulated()
    post("WebFetch", store, pol)
    for n in range(10):  # refused ten times (or asked where nobody can answer): no PostToolUse
        assert decide(release(n), pol, store=store, auditor=auditor).decision == "ask"
    assert store.facts(SID, window=3).taint_asks == 0
    assert decide(release(99), pol, store=store, auditor=auditor).decision == "ask"


def test_three_approved_asks_use_up_the_window(store: SessionStore) -> None:
    pol, auditor, _backend = manipulated()
    post("WebFetch", store, pol)
    for n in range(3):
        assert decide(release(n), pol, store=store, auditor=auditor).decision == "ask"
        ran(store, pol, f"toolu_{n}")
    after = decide(release(3), pol, store=store, auditor=auditor)
    assert after.decision == protocol.DECISION_NONE
    assert after.taint is not None
    assert after.taint["taint_asks"] == 3


def test_a_post_tool_use_of_another_call_or_session_counts_nothing(store: SessionStore) -> None:
    pol, auditor, _backend = manipulated()
    post("WebFetch", store, pol)
    decide(release(1), pol, store=store, auditor=auditor)
    ran(store, pol, "toolu_2")  # another call
    ran(store, pol, "toolu_1", session_id=OTHER_SID)  # the same id in another session
    assert store.facts(SID, window=3).taint_asks == 0


def test_an_ask_without_a_tool_use_id_is_never_counted(store: SessionStore) -> None:
    pol, auditor, _backend = manipulated()
    post("WebFetch", store, pol)
    decide(bash("make release"), pol, store=store, auditor=auditor)
    ran(store, pol, "")
    assert store.facts(SID, window=3).taint_asks == 0


def test_a_new_source_call_drops_the_pending_asks(store: SessionStore) -> None:
    pol, auditor, _backend = manipulated()
    post("WebFetch", store, pol)
    decide(release(1), pol, store=store, auditor=auditor)
    post("WebSearch", store, pol)  # the window starts again; the earlier ask is forgotten
    ran(store, pol, "toolu_1")
    assert store.facts(SID, window=3).taint_asks == 0


def test_audit_only_records_no_pending_ask(store: SessionStore) -> None:
    pol, auditor, _backend = manipulated()
    post("WebFetch", store, pol)
    decide(release(1), pol, store=store, auditor=auditor, mode="audit-only")
    ran(store, pol, "toolu_1")
    assert store.facts(SID, window=3).taint_asks == 0


def test_pending_asks_are_capped_per_session(store: SessionStore) -> None:
    store.tool_result(SID, "WebFetch", sources=DEFAULT_TAINT_SOURCES)
    for n in range(MAX_PENDING_ASKS + 6):
        assert store.taint_asked(SID, f"toolu_{n}")
    store.tool_result(SID, "Bash", sources=DEFAULT_TAINT_SOURCES, tool_use_id="toolu_0")
    assert store.facts(SID, window=3).taint_asks == 0  # the oldest were dropped: not counted
    last = f"toolu_{MAX_PENDING_ASKS + 5}"
    store.tool_result(SID, "Bash", sources=DEFAULT_TAINT_SOURCES, tool_use_id=last)
    assert store.facts(SID, window=3).taint_asks == 1


def test_cleanup_drops_the_pending_asks_of_deleted_sessions(tmp_path: Path) -> None:
    now = [1000.0]
    s = SessionStore(str(tmp_path / "s.sqlite"), clock=lambda: now[0])
    try:
        s.tool_result(SID, "WebFetch", sources=DEFAULT_TAINT_SOURCES)
        s.taint_asked(SID, "toolu_1")
        now[0] += 100 * 24 * 3600
        assert s.cleanup() == 1
        with sqlite3.connect(tmp_path / "s.sqlite") as conn:
            assert conn.execute("SELECT COUNT(*) FROM pending_asks").fetchone()[0] == 0
    finally:
        s.close()


def test_a_schema_2_database_gets_the_pending_table(tmp_path: Path) -> None:
    path = tmp_path / "session.sqlite"
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE sessions (session_id TEXT PRIMARY KEY, first_seen REAL NOT NULL,"
        " last_seen REAL NOT NULL, taint_asks INTEGER, sources TEXT NOT NULL DEFAULT '[]')"
        " WITHOUT ROWID;"
        "CREATE TABLE prompts (session_id TEXT NOT NULL, seq INTEGER NOT NULL, at REAL NOT NULL,"
        " text TEXT NOT NULL, PRIMARY KEY (session_id, seq)) WITHOUT ROWID;"
        "CREATE TABLE project_marks (location TEXT PRIMARY KEY, first_marked REAL NOT NULL,"
        " last_marked REAL NOT NULL, sources TEXT NOT NULL DEFAULT '[]') WITHOUT ROWID;"
        "INSERT INTO sessions VALUES ('old', 1.0, 1.0, 2, '[\"WebFetch\"]');"
        "PRAGMA user_version=2;"
    )
    conn.close()
    s = SessionStore(str(path))
    try:
        assert s.facts("old", window=3).taint_asks == 2  # kept: schema 2 already counted asks
        assert s.taint_asked("old", "toolu_1")
        assert s.tool_result("old", "Bash", sources=DEFAULT_TAINT_SOURCES, tool_use_id="toolu_1")
        assert s.facts("old", window=3).taint_asks == 3
    finally:
        s.close()


def test_the_post_tool_use_matcher_follows_the_llm_backend() -> None:
    assert post_matcher_for(policy(llm=True)) == "*"
    assert post_matcher_for(policy()) == taint_sources_to_matcher(DEFAULT_TAINT_SOURCES)


def test_doctor_wants_the_star_matcher_with_an_llm_backend(tmp_path: Path) -> None:
    home = policy_home(tmp_path, None)
    text = Path(home, "policy.yaml").read_text(encoding="utf-8")
    with_llm = text.replace(
        "  backend: none",
        "  backend: openai_compatible\n  openai_compatible:\n"
        "    base_url: https://llm.example.invalid/v1\n    model: m",
        1,
    )
    Path(home, "policy.yaml").write_text(with_llm, encoding="utf-8")
    sources = taint_sources_to_matcher(DEFAULT_TAINT_SOURCES)
    (check,) = doctor.check_taint_sources(home, [layer(tmp_path, sources)])
    assert check.status == doctor.WARN
    assert "'*'" in check.detail
    assert doctor.check_taint_sources(home, [layer(tmp_path, "*")]) == []


# ------------------------------------------------- P-R9: sessions that carry an old context


@pytest.mark.parametrize("source", ["fork", "resume", "compact", "teleport", None, 7])
def test_an_unknown_session_with_an_old_context_starts_as_untrusted(
    store: SessionStore, source: object
) -> None:
    pol = policy(trusted=True)
    started(store, pol, source)
    facts = store.facts(SID, window=3)
    assert facts.read_untrusted
    assert facts.tainted
    assert facts.sources[0].startswith("inherited:")
    asked = decide(bash("pytest -q"), pol, store=store)
    assert asked.decision == protocol.DECISION_ASK
    assert STICKY_RULE in asked.rule_ids


@pytest.mark.parametrize("source", ["startup", "clear"])
def test_a_new_or_cleared_session_starts_clean(store: SessionStore, source: str) -> None:
    pol = policy(trusted=True)
    started(store, pol, source)
    assert not store.facts(SID, window=3).read_untrusted
    assert decide(bash("pytest -q"), pol, store=store).decision == protocol.DECISION_NONE


def test_a_known_clean_session_stays_clean_when_resumed(store: SessionStore) -> None:
    pol = policy(trusted=True)
    started(store, pol, "startup")
    decide(bash("git status"), pol, store=store)
    started(store, pol, "resume")
    started(store, pol, "compact")
    assert not store.facts(SID, window=3).read_untrusted


def test_a_session_start_without_a_usable_id_changes_nothing(store: SessionStore) -> None:
    pol = policy()
    started(store, pol, "fork", sid="")
    assert store.session_count() == 0


def test_the_session_start_event_has_no_decision(store: SessionStore) -> None:
    pol = policy()
    payload = {"hook_event_name": "SessionStart", "session_id": SID, "source": "fork"}
    decision = decide(payload, pol, store=store, kind=protocol.EVENT_SESSION)
    assert decision.decision == protocol.DECISION_NONE


def test_session_start_is_one_of_our_hooks() -> None:
    assert ownhook.SUBCOMMANDS["SessionStart"] == protocol.EVENT_SESSION
    assert protocol.EVENT_SESSION in protocol.HOOK_EVENTS


def test_init_registers_session_start_without_a_matcher() -> None:
    cmd = install.HookCommand("C:\\Python312\\python.exe", ("-I", "-S", SCRIPT))
    groups = install.build_hook_groups(cmd, post_matcher="*")
    assert "matcher" not in groups["SessionStart"]
    (entry,) = groups["SessionStart"]["hooks"]
    assert entry["args"][-1] == "session"
    assert entry["timeout"] >= hook_main.MIN_ENTRY_TIMEOUT_S["session"]
    assert groups["PostToolUse"]["matcher"] == "*"


SCRIPT = "E:\\proj\\boundkeep\\src\\boundkeep\\hook_client.py"


def own_settings(*, session: bool) -> dict[str, Any]:
    cmd = install.HookCommand("C:\\Python312\\python.exe", ("-I", "-S", SCRIPT))
    groups = install.build_hook_groups(cmd, post_matcher="WebFetch")
    if not session:
        del groups["SessionStart"]
    return {"hooks": {event: [group] for event, group in groups.items()}}


def record(events: list[str] | None) -> dict[str, Any]:
    item: dict[str, Any] = {
        "hook_command": "C:\\Python312\\python.exe",
        "hook_args": ["-I", "-S", SCRIPT],
        "post_matcher": "WebFetch",
    }
    if events is not None:
        item["events"] = events
    return item


def test_an_install_from_before_revision_8_is_not_called_altered() -> None:
    # the ConfigChange check must not block every settings change of an older install
    assert hook_main.record_problem(own_settings(session=False), record(None)) is None


def test_an_install_that_had_session_start_must_keep_it() -> None:
    events = [*ownhook.SUBCOMMANDS]
    assert hook_main.record_problem(own_settings(session=True), record(events)) is None
    problem = hook_main.record_problem(own_settings(session=False), record(events))
    assert problem == "boundkeep's SessionStart hook was removed or altered"


def test_the_record_cannot_drop_a_required_hook() -> None:
    settings = own_settings(session=True)
    del settings["hooks"]["PreToolUse"]
    problem = hook_main.record_problem(settings, record(["SessionStart"]))
    assert problem == "boundkeep's PreToolUse hook was removed or altered"


def test_the_manifest_round_trips_the_events(tmp_path: Path) -> None:
    rec = install.InstallRecord(
        settings_path=str(tmp_path / "settings.json"),
        scope="user",
        created_file=True,
        hook_command="C:\\Python312\\python.exe",
        hook_args=("-I", "-S", SCRIPT),
        post_matcher="*",
        installed_at="2026-10-31T00:00:00Z",
        events=tuple(ownhook.SUBCOMMANDS),
    )
    path = str(tmp_path / "manifest.json")
    install.save_manifest(path, [rec])
    (loaded,) = install.load_manifest(path)
    assert loaded.events == tuple(ownhook.SUBCOMMANDS)
    old = json.loads(Path(path).read_text(encoding="utf-8"))
    del old["installs"][0]["events"]
    Path(path).write_text(json.dumps(old), encoding="utf-8")
    assert install.load_manifest(path)[0].events is None


def test_a_session_start_hook_fails_quiet(fake_daemon: Callable[..., list[bytes]]) -> None:  # noqa: F811
    fake_daemon(raises=OSError("down"))
    event_bytes = _bytes({"hook_event_name": "SessionStart", "source": "fork"})
    out = hook_main.process("session", event_bytes, _deadline())
    assert (out.stdout, out.stderr, out.exit_code) == (b"", b"", 0)
    sent = fake_daemon("deny", "ignored for this event")
    out = hook_main.process("session", event_bytes, _deadline())
    assert (out.stdout, out.stderr, out.exit_code) == (b"", b"", 0)
    assert json.loads(sent[0])["event"] == "session"
