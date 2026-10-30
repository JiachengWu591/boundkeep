"""The resident process: request handling, policy reload, audit records, serving.

One request line in, one response line out (``boundkeep.protocol``). ``handle`` never raises: any
failure becomes an error response, which the hook client turns into ``ask`` (fail closed).
The policy file is re-read whenever its modification time or size changes, so ``boundkeep mode``
takes effect on the next event without restarting the daemon. An unreadable or invalid policy
makes PreToolUse answer ``ask`` until it is fixed.

The decision itself (normalize the tool call, evaluate the rules, the LLM audit, and the policy
reload) does not run on the event loop: a hostile command can make the parser work for seconds,
and a blocked loop would stall every other request, ``ping`` included. PreToolUse decisions run on
a small pool of daemon threads under a deadline (the rules' 2 s, plus the LLM budget and
``LLM_SLACK_S`` when an audit is configured, counted from the submission, so a queued job gets it
too). When the deadline passes the client is answered ``ask`` (``llm_audit.on_failure`` in enforce
mode when an audit was configured) and the worker is abandoned (a thread cannot be killed); how
many abandoned workers may pile up is bounded, see :class:`_DecisionPool`. A call answered without
a review (late before it started, or the daemon busy) still marks a taint source.

Session state (M3a) lives in ``<home>/session.sqlite`` (``session.store``). UserPromptSubmit and
PostToolUse only write to it; they run in a worker thread too (``asyncio.to_thread``), never on
the loop and never in the decision pool, so a stuck review cannot hold up a taint mark. A store that
cannot be opened is replaced by a stand-in that judges every call as tainted (fail closed); the
console and ``ping`` say so. Idle sessions are cleaned up at start and every hour.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import datetime
import os
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from boundkeep import console, install, paths, protocol
from boundkeep.audit.auditor import Auditor
from boundkeep.daemon import pipeline
from boundkeep.ipc.base import DEFAULT_INSTANCES, create_server
from boundkeep.ipc.endpoint import Endpoint
from boundkeep.logstore import AuditLog
from boundkeep.normalize import psparse
from boundkeep.policy import Policy, PolicyError, load_policy
from boundkeep.policy.schema import LlmAudit
from boundkeep.session.store import SessionStore, UnavailableStore, open_store

POLICY_RETRY_S = (
    1.0  # an unusable policy is read again after this long, even if the file is unchanged
)
DEFAULT_DECISION_TIMEOUT_S = 2.0  # the hook client's own budget for a PreToolUse is 10 s
DEFAULT_POOL_SIZE = 4
SESSION_CLEANUP_EVERY_S = 3600.0

LLM_SLACK_S = 0.5  # on top of the LLM budget: the auditor's own bookkeeping and the late check
REASON_TOO_SLOW = "boundkeep: review took too long"
REASON_LLM_TOO_SLOW = "boundkeep: the review with the LLM audit took too long"
REASON_BUSY = "boundkeep: daemon busy (earlier reviews are still stuck)"
DECIDED_BY_TIMEOUT = "timeout"
DECIDED_BY_LLM_TIMEOUT = "timeout-llm"  # abandoned while an LLM audit may have been running
DECIDED_BY_BUSY = "busy"
# For these the audit record carries the command's length, never its text: the review never
# finished, so nothing is known about what the text is.
_NO_COMMAND_LOG = frozenset({DECIDED_BY_TIMEOUT, DECIDED_BY_BUSY, DECIDED_BY_LLM_TIMEOUT})
_PS_POLL_TICKS = 4  # the serve loop wakes every 0.5 s: poll the PowerShell helper every 2 s

_LOG_FIELDS = (
    "session_id",
    "agent_id",
    "permission_mode",
    "hook_event_name",
    "tool_name",
    "tool_use_id",
    "mcp_server",
    "source",
    "cwd",
)


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="milliseconds")


def build_record(
    request: protocol.Request,
    decision: pipeline.Decision,
    *,
    mode: str,
    latency_ms: float,
    prev_audit_ms: float | None = None,
    include_command: bool = True,
) -> dict[str, object]:
    """The audit record for one event. Content fields are redacted and clipped by AuditLog.

    ``latency_ms`` is the time from the request line to the decision; the record cannot contain
    the time of its own write, so ``prev_audit_ms`` is how long the previous record took to write
    (handler time is about ``latency_ms + prev_audit_ms``). With ``include_command=False`` a shell
    command is represented by its length (``command_chars``) only.

    Not recorded: the prompt text (only its length), file contents, tool output.
    """
    payload = request.payload
    record: dict[str, object] = {
        "ts": _now(),
        "id": request.request_id,
        "event": request.event,
        "decision": decision.decision,
        "decided_by": decision.decided_by,
        "mode": mode,
        "latency_ms": round(latency_ms, 2),
    }
    if prev_audit_ms is not None:
        record["prev_audit_ms"] = round(prev_audit_ms, 2)
    if decision.reason:
        record["reason"] = decision.reason
    if decision.would_be:
        record["would_be"] = decision.would_be
    if decision.verdict:
        record["verdict"] = decision.verdict
    if decision.rule_ids:
        record["rules"] = list(decision.rule_ids)
    if decision.programs:
        record["programs"] = list(decision.programs)
    if decision.gray_reasons:
        record["gray_reasons"] = list(decision.gray_reasons)
    if decision.taint is not None:
        record["taint"] = dict(decision.taint)
    if decision.llm is not None:
        record["llm"] = dict(decision.llm)
    for key in _LOG_FIELDS:
        value = payload.get(key)
        if isinstance(value, str):
            record[key] = value
    command = pipeline.shell_command(payload)
    if command is not None:
        if include_command:
            record["command"] = command
        else:
            record["command_chars"] = len(command)
    prompt = payload.get("prompt")
    if request.event == protocol.EVENT_PROMPT and isinstance(prompt, str):
        record["prompt_chars"] = len(prompt)
    if request.event == protocol.EVENT_CONFIG:
        for key in ("file_path", "local_decision", "local_reason"):
            value = payload.get(key)
            if isinstance(value, str):
                record[key] = value
    return record


# --------------------------------------------------------------------------------------------
# Running decisions off the event loop
# --------------------------------------------------------------------------------------------


class _Job:
    __slots__ = ("abandoned", "finished", "fn", "future", "replaced")

    def __init__(self, fn: Callable[[], Any]) -> None:
        self.fn = fn
        self.future: concurrent.futures.Future[Any] = concurrent.futures.Future()
        self.abandoned = False  # the caller gave up while the job was running
        self.finished = False
        self.replaced = False  # a replacement worker was started when it was abandoned


class _DecisionPool:
    """``size`` daemon threads that run decisions, and a count of abandoned (stuck) ones.

    A worker whose caller gave up cannot be stopped. While it runs it is "stuck": a replacement
    thread takes its place in the pool (so one stuck decision does not halve the capacity), and
    the stuck thread ends itself when it finally returns. At most ``size`` stuck workers exist
    (so at most ``2 * size`` threads): once ``stuck`` reaches ``size`` the daemon stops starting
    new work and answers ``ask`` at once, until some of them return.

    The threads are daemons on purpose: ``concurrent.futures.ThreadPoolExecutor`` joins its
    threads at interpreter exit, so one stuck worker would keep a stopped daemon alive.
    """

    def __init__(self, size: int) -> None:
        self._size = size
        self._queue: queue.SimpleQueue[_Job | None] = queue.SimpleQueue()
        self._lock = threading.Lock()
        self._live = 0  # threads that take jobs from the queue
        self._created = 0
        self._stuck = 0
        self._closed = False

    @property
    def size(self) -> int:
        return self._size

    @property
    def stuck(self) -> int:
        return self._stuck

    def submit(self, fn: Callable[[], Any]) -> _Job:
        job = _Job(fn)
        with self._lock:
            if self._closed:
                raise RuntimeError("the decision pool is closed")
            while self._live < self._size:
                self._spawn_locked()
        self._queue.put(job)
        return job

    def abandon(self, job: _Job) -> bool:
        """The caller gives up on ``job``: a queued job is dropped, a running one is "stuck".
        True when the job never started (and now never will)."""
        if job.future.cancel():
            return True
        with self._lock:
            if job.finished or job.abandoned:
                return False
            job.abandoned = True
            self._stuck += 1
            if self._stuck <= self._size and not self._closed:
                job.replaced = True
                self._spawn_locked()
        return False

    def close(self) -> None:
        """Stop idle workers; never waits for stuck ones."""
        with self._lock:
            self._closed = True
            count = self._live
        for _ in range(count):
            self._queue.put(None)

    def _spawn_locked(self) -> None:
        self._live += 1
        self._created += 1
        threading.Thread(
            target=self._work, name=f"boundkeep-decide-{self._created}", daemon=True
        ).start()

    def _work(self) -> None:
        while True:
            job = self._queue.get()
            if job is None:
                with self._lock:
                    self._live -= 1
                return
            if not job.future.set_running_or_notify_cancel():
                continue  # cancelled while it waited in the queue
            try:
                result = job.fn()
            except BaseException as exc:  # noqa: BLE001 - handed to the caller through the future
                job.future.set_exception(exc)
            else:
                job.future.set_result(result)
            with self._lock:
                job.finished = True
                if job.abandoned:
                    self._stuck -= 1
                    if job.replaced:
                        self._live -= 1
                        return  # a replacement took this thread's place


MAX_TRUST_SESSIONS = 512  # sessions whose trusted_projects snapshot is kept (oldest dropped)
MAX_SESSION_ID_CHARS = 200
DECIDED_BY_TRUST_SNAPSHOT = "trust-snapshot"


class _TrustSnapshots:
    """``trusted_projects`` as it was when each session was first seen (X1 review, H-5).

    An injected agent that gets ``boundkeep trust add`` (or a direct write of the policy file)
    past the user cannot use it in the SAME session: an entry that appeared after the session's
    first event does not count for that session, only new sessions get it. An entry removed from
    the policy stops counting at once. A session without a usable id gets no trusted project at
    all (real events always carry one). The snapshots live in memory: a restarted daemon starts
    them again, so an entry added shortly before a restart counts for the sessions it meets
    afterwards (a known limit; the daemon restarts are the user's).
    """

    def __init__(self, limit: int = MAX_TRUST_SESSIONS) -> None:
        self._limit = limit
        self._lock = threading.Lock()
        # session id -> (entries at the first event, added entries already reported)
        self._seen: dict[str, tuple[tuple[str, ...], frozenset[str]]] = {}

    def effective(
        self, session_id: object, current: tuple[str, ...]
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """(the entries that count for this session, entries added since it began and not yet
        reported for it)."""
        if (
            not isinstance(session_id, str)
            or not session_id
            or len(session_id) > MAX_SESSION_ID_CHARS
        ):
            return (), ()
        with self._lock:
            first, reported = self._seen.pop(session_id, (current, frozenset()))
            added = tuple(key for key in current if key not in first)
            fresh = tuple(key for key in added if key not in reported)
            # (re-inserted: the most recently used session is the last one)
            self._seen[session_id] = (first, reported | frozenset(fresh))
            while len(self._seen) > self._limit:
                del self._seen[next(iter(self._seen))]
            return tuple(key for key in current if key in first), fresh


@dataclass(frozen=True)
class _PolicyState:
    """What the daemon currently decides with; replaced as a whole, never edited."""

    policy: Policy | None = None
    mode: str = pipeline.MODE_ENFORCE
    error: str | None = "policy not loaded yet"


class Daemon:
    def __init__(
        self,
        endpoint: Endpoint,
        *,
        home: str | None = None,
        policy_path: str | None = None,
        log: AuditLog | None = None,
        instances: int = DEFAULT_INSTANCES,
        report: Callable[[str], None] = console.err,
        decision_timeout_s: float = DEFAULT_DECISION_TIMEOUT_S,
        pool_size: int = DEFAULT_POOL_SIZE,
        session: SessionStore | UnavailableStore | None = None,
        auditor_factory: Callable[[LlmAudit], Auditor | None] = Auditor.build,
    ) -> None:
        """``decision_timeout_s`` is the deadline of one PreToolUse decision (normalize, rules and
        policy reload; an LLM audit's budget comes on top); ``pool_size`` the number of worker
        threads (and of stuck ones tolerated). ``session``: the session store (default: the one in
        the home directory); ``auditor_factory`` builds the LLM auditor of a policy (tests pass
        one with a fake backend)."""
        if decision_timeout_s <= 0:
            raise ValueError("decision_timeout_s must be positive")
        if pool_size < 1:
            raise ValueError("pool_size must be at least 1")
        self._endpoint = endpoint
        self._home = home if home is not None else paths.home_dir()
        self._policy_path = policy_path or paths.policy_file(self._home)
        self._log = log or AuditLog(paths.audit_log_file(self._home))
        self._instances = instances
        self._report = report
        self._deadline_s = decision_timeout_s
        self._pool = _DecisionPool(pool_size)
        self._policy_lock = threading.Lock()
        self._trust = _TrustSnapshots()
        self._policy_key: tuple[int, int] | bool | None = False  # False: never loaded
        self._state = _PolicyState()
        self._user_home = os.path.expanduser("~")
        self._policy_retry_at = 0.0
        self._requests = 0
        self._timeouts = 0
        self._log_failures = 0
        self._last_audit_ms: float | None = None
        self._session = (
            session if session is not None else open_store(paths.session_db_file(self._home))
        )
        if isinstance(self._session, UnavailableStore):
            self._report(
                f"session state unavailable: {self._session.reason}; every tool call is judged "
                "as if the session had read untrusted content"
            )
        self._auditor_factory = auditor_factory
        self._auditor: Auditor | None = None
        self._auditor_llm: LlmAudit | None = None
        self._retired_auditors: list[Auditor] = []
        self._session_failures = 0

    @property
    def requests_served(self) -> int:
        return self._requests

    # -- policy ------------------------------------------------------------------------------

    def _refresh_policy(self) -> _PolicyState:
        """Reload the policy if its file changed; returns what to decide with. Thread-safe."""
        with self._policy_lock:
            self._refresh_locked()
            return self._state

    def _set_error(self, message: str, *, retry: bool) -> None:
        if message != self._state.error:
            self._report(f"policy problem: {message}")
        self._state = _PolicyState(self._state.policy, self._state.mode, message)
        if retry:
            self._policy_retry_at = time.monotonic() + POLICY_RETRY_S

    def _runtime(self, policy: Policy) -> tuple[Policy, str | None]:
        """``policy`` plus the machine-dependent rules, and why they could not be added."""
        return pipeline.runtime_policy_checked(policy, os.environ, self._user_home)

    def _refresh_locked(self) -> None:
        try:
            info = os.stat(self._policy_path)
            key: tuple[int, int] | None = (info.st_mtime_ns, info.st_size)
        except FileNotFoundError:
            key = None
        except OSError as exc:
            # Not the same as "no file": forget the key, so that the next successful stat loads.
            self._policy_key = False
            self._set_error(f"cannot read the policy file ({exc.strerror})", retry=False)
            return
        if key == self._policy_key:
            # Same file as last time. If it failed to load, try again now and then: the failure may
            # have been a lock held by an editor or a virus scanner, not the content.
            retry = (
                key is not None
                and self._state.error is not None
                and time.monotonic() >= self._policy_retry_at
            )
            if not retry:
                return
        if key is None:
            self._set_error(f"policy file not found: {self._policy_path}", retry=False)
            self._policy_key = None
            return
        # Nothing below may leave the previous policy active with no error recorded, and the key
        # only moves on once the outcome (a policy, or an error) is stored.
        try:
            policy = load_policy(self._policy_path, home=self._user_home)
            runtime, problem = self._runtime(policy)
        except PolicyError as exc:
            self._set_error(str(exc), retry=True)
            self._policy_key = key
            return
        except Exception as exc:  # noqa: BLE001 - whatever the loader did, the answer is "ask"
            detail = f"{type(exc).__name__}: {str(exc)[:200]}"
            self._set_error(f"the policy could not be loaded ({detail})", retry=True)
            self._policy_key = key
            return
        self._update_auditor(policy.llm_audit)
        if problem is not None:
            # An unusable runtime addition (e.g. the CLAUDE_CONFIG_DIR protection) is an error:
            # the gate would have a hole nobody knows about.
            self._state = _PolicyState(runtime, policy.mode, self._state.error)
            self._set_error(problem, retry=True)
            self._policy_key = key
            return
        self._state = _PolicyState(runtime, policy.mode, None)
        self._policy_key = key
        self._report(f"policy loaded: mode={policy.mode}, {len(policy.rules)} rules")

    def _update_auditor(self, llm: LlmAudit) -> None:
        """Rebuild the LLM auditor when the policy's ``llm_audit`` changed (under the policy lock).

        The old one is not closed here: a review on another thread may still be using its client;
        it is closed when the daemon stops.
        """
        if llm == self._auditor_llm:
            return
        try:
            auditor = self._auditor_factory(llm)
        except Exception as exc:  # noqa: BLE001 - an unbuildable auditor is reported, never fatal
            self._report(f"the LLM audit could not be set up ({type(exc).__name__})")
            auditor = Auditor(llm, None, "the LLM audit could not be set up")
        if self._auditor is not None:
            self._retired_auditors.append(self._auditor)
        self._auditor, self._auditor_llm = auditor, llm
        if auditor is None:
            return
        backend = auditor.backend
        if backend is None:
            self._report(
                f"LLM audit ({llm.backend}) is configured but not usable; gray actions get "
                f"on_failure ({llm.on_failure})"
            )
        else:
            self._report(
                f"LLM audit: {backend.name}, model {backend.model}, transport "
                f"{backend.transport}, budget {auditor.budget_s:g} s"
            )

    def _current_auditor(self, state: _PolicyState) -> Auditor | None:
        policy = state.policy
        if policy is None or policy.llm_audit.backend == "none":
            return None
        return self._auditor

    def _session_policy(self, state: _PolicyState, payload: dict[str, Any]) -> Policy | None:
        """``state.policy`` with the ``trusted_projects`` that count for this event's session."""
        policy = state.policy
        if policy is None:
            # still note the session, with nothing trusted: when the policy comes back, an entry
            # that appeared meanwhile must not count for a session that began without it (R-7)
            self._trust.effective(payload.get("session_id"), ())
            return None
        counted, added = self._trust.effective(payload.get("session_id"), policy.trusted_projects)
        if added:
            self._report(
                f"trusted_projects grew while a session was running ({len(added)} new): the "
                "new entries do not apply to that session, only to sessions that start later"
            )
            with contextlib.suppress(Exception):  # the trace is best effort
                self._log.append(
                    {
                        "ts": _now(),
                        "event": "trust-changed",
                        "decision": "none",
                        "decided_by": DECIDED_BY_TRUST_SNAPSHOT,
                        "added": len(added),
                        "session_id": payload.get("session_id"),
                    }
                )
        if counted == policy.trusted_projects:
            return policy
        return policy.model_copy(update={"trusted_projects": counted})

    # -- requests ----------------------------------------------------------------------------

    async def handle(self, line: bytes) -> bytes:
        started = time.perf_counter()
        try:
            request = protocol.decode_request(line)
        except protocol.ProtocolError as exc:
            return protocol.encode_error("-", protocol.ERR_BAD_REQUEST, str(exc))
        try:
            if request.event == protocol.EVENT_PING:
                self._refresh_policy()
                return protocol.encode_response(request.request_id, reason=self._status_text())
            if request.event == protocol.EVENT_PRE:
                decision, mode = await self._decide_off_loop(request)
            else:
                # Nothing to review (the pipeline answers "no decision" at once, after the session
                # bookkeeping): no pool, so these never queue behind a stuck review, and a thread
                # of their own so a slow disk never blocks the loop.
                decision, mode = await asyncio.to_thread(self._observe, request)
            self._audit(request, decision, mode, started)
            self._requests += 1
            return protocol.encode_response(
                request.request_id, decision=decision.decision, reason=decision.reason
            )
        except Exception as exc:  # noqa: BLE001 - becomes an error response, i.e. ask at the client
            self._report(f"request failed: {type(exc).__name__}")
            self._log_failed_request(request)
            return protocol.encode_error(
                request.request_id, protocol.ERR_INTERNAL, "internal error"
            )

    def _observe(self, request: protocol.Request) -> tuple[pipeline.Decision, str]:
        """A prompt, post or config event: the session bookkeeping, then "no decision"."""
        state = self._refresh_policy()
        self._session_policy(state, request.payload)  # the session is first seen here
        decision = pipeline.decide(
            request.event,
            request.payload,
            mode=state.mode,
            policy=state.policy,
            policy_error=state.error,
            env=os.environ,
            home=self._user_home,
            session=self._session,
        )
        self._check_session()
        return decision, state.mode

    def _review(
        self, request: protocol.Request, extra: list[float] | None = None
    ) -> tuple[pipeline.Decision, str]:
        """The decision for one PreToolUse event (runs on a pool thread) and the mode it used.

        ``extra`` receives the LLM budget as soon as the policy is known, so that the waiting loop
        can extend the deadline by it (the policy is only loaded here, off the event loop).
        """
        state = self._refresh_policy()
        auditor = self._current_auditor(state)
        if extra is not None and auditor is not None:
            extra.append(auditor.budget_s)
        decision = pipeline.decide(
            request.event,
            request.payload,
            mode=state.mode,
            policy=self._session_policy(state, request.payload),
            policy_error=state.error,
            env=os.environ,
            home=self._user_home,
            session=self._session,
            auditor=auditor,
        )
        self._check_session()
        return decision, state.mode

    def _check_session(self) -> None:
        """Report new session store errors (now and then, not on every event)."""
        count = self._session.error_count
        if count <= self._session_failures:
            return
        before, self._session_failures = self._session_failures, count
        if any(n in (1, 10, 100) or n % 1000 == 0 for n in range(before + 1, count + 1)):
            self._report(
                f"session state: {self._session.last_error} ({count} failure(s) so far); calls "
                "whose state could not be read were judged as tainted"
            )

    async def _decide_off_loop(self, request: protocol.Request) -> tuple[pipeline.Decision, str]:
        """Run the review on the pool, under the deadline (the rules' own, plus the LLM budget
        when the review's policy has an audit); ``ask`` when it is late or no worker is free.
        Raises whatever the review raised (``handle`` turns that into an error response)."""
        if self._pool.stuck >= self._pool.size:
            self._mark_unreviewed(request)
            return self._gave_up(DECIDED_BY_BUSY, REASON_BUSY)
        # The LLM budget extends the deadline. It is known from the last policy at once (a job
        # that waits in the queue needs it as much as a running one) and from the worker's own
        # policy once that is loaded; the larger counts.
        known = self._current_auditor(self._state)
        extra: list[float] = [known.budget_s] if known is not None else []
        job = self._pool.submit(lambda: self._review(request, extra))
        waiter = asyncio.wrap_future(job.future)
        deadline = self._deadline_s
        waited = 0.0
        try:
            while True:
                budget = self._deadline_s + (max(extra) + LLM_SLACK_S if extra else 0.0)
                if budget <= waited:
                    done: set[Any] = set()
                    break
                deadline = budget
                done, _pending = await asyncio.wait({waiter}, timeout=budget - waited)
                waited = budget
                if done:
                    break
        except asyncio.CancelledError:
            waiter.cancel()
            self._pool.abandon(job)
            raise
        if not done:
            waiter.cancel()
            if self._pool.abandon(job):
                self._mark_unreviewed(request)  # it never ran: its taint mark has to be made here
            self._timeouts += 1
            if self._timeouts in (1, 10, 100) or self._timeouts % 1000 == 0:
                self._report(
                    f"a review took longer than {deadline:g} s and was abandoned "
                    f"({self._timeouts} so far, {self._pool.stuck} still running)"
                )
            if extra:
                return self._llm_gave_up()
            return self._gave_up(DECIDED_BY_TIMEOUT, REASON_TOO_SLOW)
        decision, mode = waiter.result()
        return decision, mode

    def _gave_up(self, decided_by: str, reason: str) -> tuple[pipeline.Decision, str]:
        return (
            pipeline.Decision(protocol.DECISION_ASK, reason, decided_by),
            self._state.mode,
        )

    def _llm_gave_up(self) -> tuple[pipeline.Decision, str]:
        """A review with an LLM audit ran out of time: ``llm_audit.on_failure``, as for any other
        failure of the audit (the rules may have finished long before). In audit-only mode it is
        ``ask``, like every review the daemon gave up on."""
        policy = self._state.policy
        on_failure = policy.llm_audit.on_failure if policy is not None else "ask"
        if on_failure != "deny" or self._state.mode == pipeline.MODE_AUDIT_ONLY:
            return self._gave_up(DECIDED_BY_LLM_TIMEOUT, f"{REASON_LLM_TOO_SLOW}; asking")
        reason = f"{REASON_LLM_TOO_SLOW}; refusing (llm_audit.on_failure)"
        decision = pipeline.Decision(protocol.DECISION_DENY, reason, DECIDED_BY_LLM_TIMEOUT)
        return decision, self._state.mode

    def _mark_unreviewed(self, request: protocol.Request) -> None:
        """A PreToolUse that is answered without a review still marks a call of a taint source
        (the user may approve it). In a thread of its own, best effort: the answer does not wait."""
        payload = request.payload
        sources, _window = pipeline.taint_settings(self._state.policy)
        session = self._session

        def mark() -> None:
            with contextlib.suppress(Exception):
                session.tool_result(
                    payload.get("session_id"), payload.get("tool_name"), sources=sources
                )

        with contextlib.suppress(Exception):
            threading.Thread(target=mark, name="boundkeep-taint-mark", daemon=True).start()

    def _audit(
        self, request: protocol.Request, decision: pipeline.Decision, mode: str, started: float
    ) -> None:
        record = build_record(
            request,
            decision,
            mode=mode,
            latency_ms=(time.perf_counter() - started) * 1000,
            prev_audit_ms=self._last_audit_ms,
            include_command=decision.decided_by not in _NO_COMMAND_LOG,
        )
        began = time.perf_counter()
        written = self._log.append(record)
        self._last_audit_ms = (time.perf_counter() - began) * 1000
        if not written:
            self._note_log_failure()

    def _log_failed_request(self, request: protocol.Request) -> None:
        """A request that blew up still leaves a trace in the audit log. Never raises."""
        with contextlib.suppress(Exception):  # the trace is best effort
            self._log.append(
                {
                    "ts": _now(),
                    "id": request.request_id,
                    "event": request.event,
                    "decision": "error",
                    "decided_by": "internal-error",
                }
            )

    def _status_text(self) -> str:
        state = self._state
        ps = psparse.status()
        ps_text = f"powershell={ps.get('state', '?')}"
        if ps.get("retry_in_s") is not None:
            ps_text += f"; powershell_retry_s={int(ps['retry_in_s'])}"
        if ps.get("job_degraded"):
            ps_text += "; powershell_job=no"
        if ps.get("throttled_s"):
            ps_text += f"; powershell_throttled_s={int(ps['throttled_s'])}"
        store = getattr(self, "_session", None)
        session = "ok" if isinstance(store, SessionStore) else "unavailable"
        llm = state.policy.llm_audit.backend if state.policy is not None else "-"
        # session and llm come before the PowerShell fields: config_dir stays last (doctor reads
        # it up to "; policy error:") and "powershell=...; config_dir" keeps its old shape
        text = (
            f"mode={state.mode}; requests={self._requests}; timeouts={self._timeouts}; "
            f"stuck={self._pool.stuck}; session={session}; llm={llm}; {ps_text}; "
            f"config_dir={os.environ.get('CLAUDE_CONFIG_DIR') or '-'}"
        )
        if state.error is not None:
            text += f"; policy error: {state.error}"
        return text

    def _note_log_failure(self) -> None:
        self._log_failures += 1
        if self._log_failures in (1, 10, 100) or self._log_failures % 1000 == 0:
            self._report(
                f"audit log write failed ({self._log_failures} so far): {self._log.last_error}"
            )

    def _log_lifecycle(self, action: str) -> None:
        record: dict[str, Any] = {
            "ts": _now(),
            "event": "daemon",
            "action": action,
            "mode": self._state.mode,
            "pid": os.getpid(),
        }
        if not self._log.append(record):
            self._note_log_failure()

    # -- serving -----------------------------------------------------------------------------

    def _check_install_integrity(self) -> None:
        """Warn loudly (never refuse to start) when a hook file differs from what init recorded.

        The hook scripts and the interpreter are hashed by ``init`` (security review M-4). A daemon
        that refused to start would turn a swapped file into "every tool call asks"; the warning
        goes to the console and the audit log, and ``boundkeep doctor`` fails on it. Never raises.
        """
        try:
            problems = install.integrity_report(
                install.load_manifest(paths.manifest_file(self._home))
            )
        except Exception as exc:  # noqa: BLE001 - startup must go on, but not in silence
            problems = [f"the install manifest could not be checked ({type(exc).__name__})"]
        if not problems:
            return
        for problem in problems:
            self._report(f"WARNING integrity: {problem}")
        self._report(
            "WARNING integrity: the hook files above are not what 'boundkeep init' recorded; "
            "if you did not change them, treat this machine's gate as untrusted "
            "('boundkeep doctor' has the details; 'boundkeep init' records the current files)"
        )
        with contextlib.suppress(Exception):
            self._log.append(
                {
                    "ts": _now(),
                    "event": "daemon",
                    "action": "integrity-warning",
                    "problems": len(problems),
                    "pid": os.getpid(),
                }
            )

    async def serve(self, stop: asyncio.Event) -> None:
        """Serve until ``stop`` is set. Raises ``ServerStartError`` / ``AddressInUse`` on start."""
        self._refresh_policy()
        self._check_install_integrity()
        server = create_server(
            self._endpoint,
            self.handle,
            instances=self._instances,
            on_error=lambda message: self._report(f"transport: {message}"),
        )
        # The PowerShell parser takes ~2 s to start (1.8 - 2.3 s measured): begin before the pipe
        # opens so the first calls find it ready. It is a background thread; a failed start of the
        # server kills the child again.
        psparse.warm_up()
        try:
            await server.start()
        except BaseException:
            psparse.shutdown()
            raise
        self._log_lifecycle("start")
        self._report(
            f"listening on {server.address} (mode={self._state.mode}, "
            f"policy={self._policy_path}, log={self._log.path})"
        )
        await asyncio.to_thread(self.clean_sessions)
        next_cleanup = time.monotonic() + SESSION_CLEANUP_EVERY_S
        try:
            ticks = 0
            while not stop.is_set():
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=0.5)
                ticks += 1
                if ticks % _PS_POLL_TICKS == 0:
                    # Idempotent and non-blocking: restarts a helper that died while idle and lets a
                    # half-open breaker or an unavailable retry run without waiting for a request.
                    with contextlib.suppress(Exception):
                        psparse.warm_up()
                if time.monotonic() >= next_cleanup:
                    next_cleanup = time.monotonic() + SESSION_CLEANUP_EVERY_S
                    await asyncio.to_thread(self.clean_sessions)
        finally:
            await server.close()
            self._pool.close()  # stuck workers are daemon threads: they cannot hold us up
            psparse.shutdown()
            self._close_session_and_auditors()
            self._log_lifecycle("stop")
            self._report("stopped")

    def clean_sessions(self) -> int | None:
        """Delete idle session state (``session.store`` cleanup policy). Never raises."""
        try:
            removed = self._session.cleanup()
        except Exception as exc:  # noqa: BLE001 - upkeep must not take the daemon down
            self._report(f"session cleanup failed ({type(exc).__name__})")
            return None
        if removed is None and not isinstance(self._session, UnavailableStore):
            self._report(f"session cleanup failed: {self._session.last_error}")
        elif removed:
            self._report(f"session cleanup: {removed} idle session(s) removed")
        return removed

    def _close_session_and_auditors(self) -> None:
        for auditor in (*self._retired_auditors, self._auditor):
            if auditor is not None:
                auditor.close()
        with contextlib.suppress(Exception):
            self._session.close()
