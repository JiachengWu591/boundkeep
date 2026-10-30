"""Session state in SQLite (WAL): taint marks and the task intent, per Claude Code ``session_id``.

What is stored, and nothing else: per session when it was first and last seen, how many tool calls
have passed since the latest call of a taint source (NULL: none so far) and the names of the source
tools (at most ``MAX_SOURCES``); and, only while an LLM audit is configured, the user's latest
prompts as ``intent.extract_intent`` leaves them (IDE blocks removed, pasted text left out, secrets
redacted, cut). No tool input, no tool output, no file content.

Taint (PROJECT_SPEC.md §7): a tool call is *tainted* when it is one of the ``window`` calls after a
call of a taint source; a session has *read untrusted content* once any source was called (sticky:
the window does not end it, only a new session does: ``/clear`` gives a new session_id, resume and
compact keep it, docs/hook-behavior.md E9). A source is marked when its PreToolUse arrives and again
when its PostToolUse does: the hook client drops a failed PostToolUse silently (it has no decision
to degrade to), so marking only there would fail open; marking at PreToolUse may count a call that
is then refused, which is the safe direction.

Concurrency: one connection and one lock per store; every read-modify-write runs in a ``BEGIN
IMMEDIATE`` transaction, so the call counter of parallel tool calls never loses an update, also
when another process (another store on the same file) writes at the same time: it waits up to the
busy timeout. WAL with ``synchronous=NORMAL``: a commit does not wait for the disk, a crash of the
machine (not of the process) may lose the last commits.

Failure: no method raises. A tool call whose state cannot be read or written comes back
``UNKNOWN``, which the pipeline treats as tainted (fail closed); writes report False. The latest
error is ``last_error`` (no session ids or text in it).

Cleanup (``cleanup``): sessions idle for ``RETENTION_S`` go, with their prompts; above
``MAX_SESSIONS`` the least recently active go first. The retention is long on purpose: a resumed
session keeps its session_id, and forgetting its row would forget that untrusted content is in its
context.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from boundkeep.session.facts import UNKNOWN, SessionFacts, is_taint_source

SCHEMA_VERSION = 1
RETENTION_S = 30 * 24 * 3600
MAX_SESSIONS = 5000
MAX_SOURCES = 16
MAX_SOURCE_CHARS = 128
MAX_SESSION_ID_CHARS = 200
MAX_PROMPTS_KEPT = 10
MAX_PROMPT_CHARS = 4000
BUSY_TIMEOUT_S = 2.0
TOUCH_EVERY_S = 3600.0  # last_seen of a session that needs no other write is refreshed this often
# calls_since_taint stops counting here: beyond the largest window the policy allows
# (policy.schema.MAX_TAINT_WINDOW, 1000; a unit test keeps the two in step) it changes nothing.
# Not imported: the policy package imports the matcher, which imports session.facts.
COUNT_CAP = 1001

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS sessions ("
    " session_id TEXT PRIMARY KEY,"
    " first_seen REAL NOT NULL,"
    " last_seen REAL NOT NULL,"
    " calls_since_taint INTEGER,"
    " sources TEXT NOT NULL DEFAULT '[]'"
    ") WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS sessions_last_seen ON sessions (last_seen)",
    "CREATE TABLE IF NOT EXISTS prompts ("
    " session_id TEXT NOT NULL,"
    " seq INTEGER NOT NULL,"
    " at REAL NOT NULL,"
    " text TEXT NOT NULL,"
    " PRIMARY KEY (session_id, seq)"
    ") WITHOUT ROWID",
)


def usable_session_id(value: object) -> str | None:
    if (
        isinstance(value, str)
        and 0 < len(value) <= MAX_SESSION_ID_CHARS
        and value.isprintable()
        and value == value.strip()
    ):
        return value
    return None


def _source_name(tool: str) -> str:
    name = "".join(ch if ch.isprintable() else "?" for ch in tool[:MAX_SOURCE_CHARS])
    return name or "?"


def _sources_of(raw: object) -> list[str]:
    try:
        value = json.loads(raw) if isinstance(raw, str) else []
    except ValueError:
        return []
    if not isinstance(value, list):
        return []
    return [s for s in value if isinstance(s, str)][:MAX_SOURCES]


def _with_source(current: list[str], tool: str) -> str:
    name = _source_name(tool)
    if name not in current and len(current) < MAX_SOURCES:
        current = [*current, name]
    return json.dumps(current, ensure_ascii=True)


class SessionStoreError(Exception):
    """The store could not be opened (the message names no session data)."""


class SessionStore:
    """One SQLite database of session state; safe to share between threads (see the module)."""

    def __init__(
        self,
        path: str,
        *,
        clock: Callable[[], float] = time.time,
        busy_timeout_s: float = BUSY_TIMEOUT_S,
    ) -> None:
        """Open (and if needed create) the database. Raises ``SessionStoreError``."""
        self._path = path
        self._clock = clock
        self._lock = threading.Lock()
        self._last_error: str | None = None
        self._errors = 0
        self._closed = False
        memory = path == ":memory:"
        try:
            if not memory:
                _create_private(path)
            self._conn = sqlite3.connect(
                path, timeout=busy_timeout_s, isolation_level=None, check_same_thread=False
            )
        except (OSError, sqlite3.Error) as exc:
            raise SessionStoreError(f"cannot open the session database ({_why(exc)})") from None
        try:
            self._prepare(memory)
        except (OSError, sqlite3.Error, SessionStoreError) as exc:
            self._conn.close()
            if isinstance(exc, SessionStoreError):
                raise
            raise SessionStoreError(f"cannot use the session database ({_why(exc)})") from None

    def _prepare(self, memory: bool) -> None:
        conn = self._conn
        if not memory:
            mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()
            if not mode or str(mode[0]).lower() != "wal":
                self._last_error = "the session database is not in WAL mode"
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA trusted_schema=OFF")
        # deleted rows (trimmed, cleaned up or purged task intents) are overwritten, not left in
        # free pages; the database is small, so the extra writes cost nothing that matters
        conn.execute("PRAGMA secure_delete=ON")
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, SCHEMA_VERSION):
            raise SessionStoreError(
                f"the session database has schema version {version}, this boundkeep knows "
                f"{SCHEMA_VERSION}: stop the daemon and delete {os.path.basename(self._path)}*"
            )
        if version == 0:
            conn.execute("BEGIN IMMEDIATE")
            try:
                for statement in _SCHEMA:
                    conn.execute(statement)
                conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    @property
    def path(self) -> str:
        return self._path

    @property
    def last_error(self) -> str | None:
        return self._last_error

    @property
    def error_count(self) -> int:
        """How many operations have failed so far (the daemon reports new ones)."""
        return self._errors

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                try:
                    self._conn.close()
                except sqlite3.Error as exc:
                    self._last_error = f"close: {_why(exc)}"

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """Hold the lock and an IMMEDIATE transaction; roll back when the body raises."""
        with self._lock:
            if self._closed:
                raise sqlite3.ProgrammingError("the session store is closed")
            conn = self._conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")

    def _failed(self, what: str, exc: BaseException) -> None:
        self._last_error = f"{what}: {_why(exc)}"
        self._errors += 1

    # ---------------------------------------------------------------------------- events

    def tool_call(
        self,
        session_id: object,
        tool: object,
        *,
        sources: tuple[str, ...],
        window: int,
        intents: int = 0,
    ) -> SessionFacts:
        """Count one PreToolUse and return the state THIS call is judged in.

        The call's own taint is the state before it: a source call is not tainted by itself. A
        call of a source then marks the session (the next ``window`` calls are tainted).
        ``intents`` > 0 also returns that many of the latest task intents.
        """
        sid = usable_session_id(session_id)
        if sid is None:
            return UNKNOWN
        name = tool if isinstance(tool, str) else ""
        try:
            now = self._clock()
            source = is_taint_source(name, sources)
            with self._transaction() as conn:
                row = conn.execute(
                    "SELECT calls_since_taint, sources, last_seen FROM sessions "
                    "WHERE session_id = ?",
                    (sid,),
                ).fetchone()
                facts = _facts(row, window)
                if source:
                    current = _sources_of(row[1]) if row is not None else []
                    conn.execute(
                        "INSERT INTO sessions (session_id, first_seen, last_seen, "
                        "calls_since_taint, sources) VALUES (?, ?, ?, 0, ?) "
                        "ON CONFLICT (session_id) DO UPDATE SET last_seen = excluded.last_seen, "
                        "calls_since_taint = 0, sources = excluded.sources",
                        (sid, now, now, _with_source(current, name)),
                    )
                elif row is not None:
                    count = row[0]
                    if count is not None and count < COUNT_CAP:
                        conn.execute(
                            "UPDATE sessions SET calls_since_taint = ?, last_seen = ? "
                            "WHERE session_id = ?",
                            (count + 1, now, sid),
                        )
                    elif now - float(row[2]) >= TOUCH_EVERY_S:
                        conn.execute(
                            "UPDATE sessions SET last_seen = ? WHERE session_id = ?", (now, sid)
                        )
                if intents > 0:
                    facts = _with_intents(facts, conn, sid, intents)
            return facts
        except Exception as exc:  # noqa: BLE001 - unknown state is answered as tainted, never raised
            self._failed("tool call", exc)
            return UNKNOWN

    def tool_result(self, session_id: object, tool: object, *, sources: tuple[str, ...]) -> bool:
        """A PostToolUse: a source's result marks the session again (the window restarts now)."""
        sid = usable_session_id(session_id)
        name = tool if isinstance(tool, str) else ""
        if sid is None or not is_taint_source(name, sources):
            return sid is not None
        try:
            now = self._clock()
            with self._transaction() as conn:
                row = conn.execute(
                    "SELECT sources FROM sessions WHERE session_id = ?", (sid,)
                ).fetchone()
                current = _sources_of(row[0]) if row is not None else []
                conn.execute(
                    "INSERT INTO sessions (session_id, first_seen, last_seen, calls_since_taint, "
                    "sources) VALUES (?, ?, ?, 0, ?) ON CONFLICT (session_id) DO UPDATE SET "
                    "last_seen = excluded.last_seen, calls_since_taint = 0, "
                    "sources = excluded.sources",
                    (sid, now, now, _with_source(current, name)),
                )
            return True
        except Exception as exc:  # noqa: BLE001 - reported through last_error
            self._failed("tool result", exc)
            return False

    def add_prompt(self, session_id: object, text: str, *, keep: int) -> bool:
        """Store one task intent (already extracted) and keep only the latest ``keep``."""
        sid = usable_session_id(session_id)
        if sid is None or not isinstance(text, str) or not text:
            return False
        keep = max(1, min(keep, MAX_PROMPTS_KEPT))
        try:
            now = self._clock()
            with self._transaction() as conn:
                conn.execute(
                    "INSERT INTO sessions (session_id, first_seen, last_seen) VALUES (?, ?, ?) "
                    "ON CONFLICT (session_id) DO UPDATE SET last_seen = excluded.last_seen",
                    (sid, now, now),
                )
                last = conn.execute(
                    "SELECT COALESCE(MAX(seq), 0) FROM prompts WHERE session_id = ?", (sid,)
                ).fetchone()[0]
                conn.execute(
                    "INSERT INTO prompts (session_id, seq, at, text) VALUES (?, ?, ?, ?)",
                    (sid, last + 1, now, text[:MAX_PROMPT_CHARS]),
                )
                conn.execute(
                    "DELETE FROM prompts WHERE session_id = ? AND seq <= ?",
                    (sid, last + 1 - keep),
                )
            return True
        except Exception as exc:  # noqa: BLE001 - reported through last_error
            self._failed("prompt", exc)
            return False

    # ---------------------------------------------------------------------------- reading

    def facts(self, session_id: object, *, window: int, intents: int = 0) -> SessionFacts:
        """The state a new call of a non-source tool would be judged in, without counting it."""
        sid = usable_session_id(session_id)
        if sid is None:
            return UNKNOWN
        try:
            with self._transaction() as conn:
                row = conn.execute(
                    "SELECT calls_since_taint, sources, last_seen FROM sessions "
                    "WHERE session_id = ?",
                    (sid,),
                ).fetchone()
                facts = _facts(row, window)
                if intents > 0:
                    facts = _with_intents(facts, conn, sid, intents)
            return facts
        except Exception as exc:  # noqa: BLE001 - unknown state is answered as tainted
            self._failed("read", exc)
            return UNKNOWN

    def session_count(self) -> int | None:
        try:
            with self._transaction() as conn:
                return int(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0])
        except Exception as exc:  # noqa: BLE001 - reported through last_error
            self._failed("count", exc)
            return None

    # ---------------------------------------------------------------------------- upkeep

    def cleanup(
        self, *, retention_s: float = RETENTION_S, max_sessions: int = MAX_SESSIONS
    ) -> int | None:
        """Delete idle sessions (and the oldest beyond ``max_sessions``); the number deleted."""
        try:
            cutoff = self._clock() - retention_s
            with self._transaction() as conn:
                gone = conn.execute("DELETE FROM sessions WHERE last_seen < ?", (cutoff,)).rowcount
                count = int(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0])
                if count > max_sessions:
                    gone += conn.execute(
                        "DELETE FROM sessions WHERE session_id IN (SELECT session_id FROM "
                        "sessions ORDER BY last_seen ASC, session_id ASC LIMIT ?)",
                        (count - max_sessions,),
                    ).rowcount
                conn.execute(
                    "DELETE FROM prompts WHERE session_id NOT IN (SELECT session_id FROM sessions)"
                )
            return gone
        except Exception as exc:  # noqa: BLE001 - reported through last_error
            self._failed("cleanup", exc)
            return None

    def purge_prompts(self) -> int | None:
        """Delete every stored task intent (``boundkeep log --purge``); taint marks stay.

        With ``secure_delete`` the freed pages are zeroed; the checkpoint then copies them into the
        database and truncates the WAL, whose older frames still held the text (fully only when no
        other connection, such as a running daemon, is reading at that moment; the daemon's own
        checkpoints overwrite those frames later).
        """
        try:
            with self._transaction() as conn:
                removed = conn.execute("DELETE FROM prompts").rowcount
            with self._lock:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            return removed
        except Exception as exc:  # noqa: BLE001 - reported through last_error
            self._failed("purge", exc)
            return None


class UnavailableStore:
    """Stands in for a store that could not be opened: every call is judged in an unknown state
    (tainted, fail closed) and nothing is written."""

    path: str | None = None

    def __init__(self, reason: str) -> None:
        self.reason = reason

    @property
    def last_error(self) -> str | None:
        return self.reason

    @property
    def error_count(self) -> int:
        return 0

    def tool_call(
        self,
        session_id: object,
        tool: object,
        *,
        sources: tuple[str, ...],
        window: int,
        intents: int = 0,
    ) -> SessionFacts:
        return UNKNOWN

    def tool_result(self, session_id: object, tool: object, *, sources: tuple[str, ...]) -> bool:
        return False

    def add_prompt(self, session_id: object, text: str, *, keep: int) -> bool:
        return False

    def cleanup(
        self, *, retention_s: float = RETENTION_S, max_sessions: int = MAX_SESSIONS
    ) -> int | None:
        return None

    def purge_prompts(self) -> int | None:
        return None

    def session_count(self) -> int | None:
        return None

    def close(self) -> None:
        return None


def open_store(path: str) -> SessionStore | UnavailableStore:
    """The store at ``path``, or a stand-in that says why it could not be opened. Never raises."""
    try:
        return SessionStore(path)
    except SessionStoreError as exc:
        return UnavailableStore(str(exc))
    except Exception as exc:  # noqa: BLE001 - the daemon must start; the stand-in fails closed
        return UnavailableStore(f"cannot open the session database ({type(exc).__name__})")


def _facts(row: tuple[object, ...] | None, window: int) -> SessionFacts:
    if row is None or row[0] is None:
        sources = tuple(_sources_of(row[1])) if row is not None else ()
        return SessionFacts(known=True, tainted=False, read_untrusted=False, sources=sources)
    count = row[0]
    if isinstance(count, bool) or not isinstance(count, int):
        return UNKNOWN
    since = min(count + 1, COUNT_CAP)
    return SessionFacts(
        known=True,
        tainted=since <= window,
        read_untrusted=True,
        sources=tuple(_sources_of(row[1])),
        calls_since_taint=since,
    )


def _with_intents(
    facts: SessionFacts, conn: sqlite3.Connection, sid: str, keep: int
) -> SessionFacts:
    rows = conn.execute(
        "SELECT text FROM prompts WHERE session_id = ? ORDER BY seq DESC LIMIT ?",
        (sid, max(1, min(keep, MAX_PROMPTS_KEPT))),
    ).fetchall()
    texts = tuple(str(r[0]) for r in reversed(rows) if isinstance(r[0], str))
    return SessionFacts(
        known=facts.known,
        tainted=facts.tainted,
        read_untrusted=facts.read_untrusted,
        sources=facts.sources,
        calls_since_taint=facts.calls_since_taint,
        intents=texts,
    )


def _create_private(path: str) -> None:
    """Create the database file private to the user before SQLite opens it (0600 on POSIX; on
    Windows it inherits the private ACL of the boundkeep home). SQLite gives the -wal and -shm
    files the database file's permissions."""
    if os.path.exists(path):
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return
    os.close(fd)
    if sys.platform != "win32":
        os.chmod(path, 0o600)


def _why(exc: BaseException) -> str:
    """A short description of a database error: its type and SQLite's own message (no data)."""
    message = str(exc)[:120] if isinstance(exc, (sqlite3.Error, OSError)) else ""
    return f"{type(exc).__name__}: {message}" if message else type(exc).__name__
