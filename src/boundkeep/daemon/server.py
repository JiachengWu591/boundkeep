"""The resident process: request handling, policy reload, audit records, serving.

One request line in, one response line out (``boundkeep.protocol``). ``handle`` never raises: any
failure becomes an error response, which the hook client turns into ``ask`` (fail closed).
The policy file is re-read whenever its modification time or size changes, so ``boundkeep mode``
takes effect on the next event without restarting the daemon. An unreadable or invalid policy
makes PreToolUse answer ``ask`` until it is fixed.

The decision itself (normalize the tool call, evaluate the rules, and the policy reload) does not
run on the event loop: a hostile command can make the parser work for seconds, and a blocked loop
would stall every other request, ``ping`` included. PreToolUse decisions run on a small pool of
daemon threads under a deadline. When the deadline passes the client is answered ``ask`` and the
worker is abandoned (a thread cannot be killed); how many abandoned workers may pile up is
bounded, see :class:`_DecisionPool`.
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
from boundkeep.daemon import pipeline
from boundkeep.ipc.base import DEFAULT_INSTANCES, create_server
from boundkeep.ipc.endpoint import Endpoint
from boundkeep.logstore import AuditLog
from boundkeep.normalize import psparse
from boundkeep.policy import Policy, PolicyError, load_policy

POLICY_RETRY_S = (
    1.0  # an unusable policy is read again after this long, even if the file is unchanged
)
DEFAULT_DECISION_TIMEOUT_S = 2.0  # the hook client's own budget for a PreToolUse is 10 s
DEFAULT_POOL_SIZE = 4

REASON_TOO_SLOW = "boundkeep: review took too long"
REASON_BUSY = "boundkeep: daemon busy (earlier reviews are still stuck)"
DECIDED_BY_TIMEOUT = "timeout"
DECIDED_BY_BUSY = "busy"
# For these the audit record carries the command's length, never its text: the review never
# finished, so nothing is known about what the text is.
_NO_COMMAND_LOG = frozenset({DECIDED_BY_TIMEOUT, DECIDED_BY_BUSY})
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

    def abandon(self, job: _Job) -> None:
        """The caller gives up on ``job``: a queued job is dropped, a running one is "stuck"."""
        if job.future.cancel():
            return  # it never started and now never will
        with self._lock:
            if job.finished or job.abandoned:
                return
            job.abandoned = True
            self._stuck += 1
            if self._stuck <= self._size and not self._closed:
                job.replaced = True
                self._spawn_locked()

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
    ) -> None:
        """``decision_timeout_s`` is the deadline of one PreToolUse decision (normalize, rules and
        policy reload); ``pool_size`` the number of worker threads (and of stuck ones tolerated)."""
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
        self._policy_key: tuple[int, int] | bool | None = False  # False: never loaded
        self._state = _PolicyState()
        self._user_home = os.path.expanduser("~")
        self._policy_retry_at = 0.0
        self._requests = 0
        self._timeouts = 0
        self._log_failures = 0
        self._last_audit_ms: float | None = None

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
                # Nothing to review (the pipeline answers "no decision" at once): no pool, so
                # these never queue behind a stuck review.
                state = self._refresh_policy()
                decision = pipeline.decide(
                    request.event,
                    request.payload,
                    mode=state.mode,
                    policy=state.policy,
                    policy_error=state.error,
                    env=os.environ,
                    home=self._user_home,
                )
                mode = state.mode
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

    def _review(self, request: protocol.Request) -> tuple[pipeline.Decision, str]:
        """The decision for one PreToolUse event (runs on a pool thread) and the mode it used."""
        state = self._refresh_policy()
        decision = pipeline.decide(
            request.event,
            request.payload,
            mode=state.mode,
            policy=state.policy,
            policy_error=state.error,
            env=os.environ,
            home=self._user_home,
        )
        return decision, state.mode

    async def _decide_off_loop(self, request: protocol.Request) -> tuple[pipeline.Decision, str]:
        """Run the review on the pool, under the deadline; ``ask`` when it is late or no worker is
        free. Raises whatever the review raised (``handle`` turns that into an error response)."""
        if self._pool.stuck >= self._pool.size:
            return self._gave_up(DECIDED_BY_BUSY, REASON_BUSY)
        job = self._pool.submit(lambda: self._review(request))
        waiter = asyncio.wrap_future(job.future)
        try:
            done, _pending = await asyncio.wait({waiter}, timeout=self._deadline_s)
        except asyncio.CancelledError:
            waiter.cancel()
            self._pool.abandon(job)
            raise
        if not done:
            waiter.cancel()
            self._pool.abandon(job)
            self._timeouts += 1
            if self._timeouts in (1, 10, 100) or self._timeouts % 1000 == 0:
                self._report(
                    f"a review took longer than {self._deadline_s:g} s and was abandoned "
                    f"({self._timeouts} so far, {self._pool.stuck} still running)"
                )
            return self._gave_up(DECIDED_BY_TIMEOUT, REASON_TOO_SLOW)
        decision, mode = waiter.result()
        return decision, mode

    def _gave_up(self, decided_by: str, reason: str) -> tuple[pipeline.Decision, str]:
        return (
            pipeline.Decision(protocol.DECISION_ASK, reason, decided_by),
            self._state.mode,
        )

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
        text = (
            f"mode={state.mode}; requests={self._requests}; timeouts={self._timeouts}; "
            f"stuck={self._pool.stuck}; {ps_text}; "
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
        finally:
            await server.close()
            self._pool.close()  # stuck workers are daemon threads: they cannot hold us up
            psparse.shutdown()
            self._log_lifecycle("stop")
            self._report("stopped")
