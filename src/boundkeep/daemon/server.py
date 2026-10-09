"""The resident process: request handling, policy reload, audit records, serving.

One request line in, one response line out (``boundkeep.protocol``). ``handle`` never raises: any
failure becomes an error response, which the hook client turns into ``ask`` (fail closed).
The policy file is re-read whenever its modification time or size changes, so ``boundkeep mode``
takes effect on the next event without restarting the daemon. An unreadable or invalid policy
makes PreToolUse answer ``ask`` until it is fixed.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import os
import time
from collections.abc import Callable
from typing import Any

from boundkeep import console, paths, protocol
from boundkeep.daemon import pipeline
from boundkeep.ipc.base import DEFAULT_INSTANCES, create_server
from boundkeep.ipc.endpoint import Endpoint
from boundkeep.logstore import AuditLog
from boundkeep.policy import PolicyError, load_policy

POLICY_RETRY_S = (
    1.0  # an unusable policy is read again after this long, even if the file is unchanged
)

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
) -> dict[str, object]:
    """The audit record for one event. Content fields are redacted and clipped by AuditLog.

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
    if decision.reason:
        record["reason"] = decision.reason
    if decision.would_be:
        record["would_be"] = decision.would_be
    for key in _LOG_FIELDS:
        value = payload.get(key)
        if isinstance(value, str):
            record[key] = value
    command = pipeline.shell_command(payload)
    if command is not None:
        record["command"] = command
    prompt = payload.get("prompt")
    if request.event == protocol.EVENT_PROMPT and isinstance(prompt, str):
        record["prompt_chars"] = len(prompt)
    if request.event == protocol.EVENT_CONFIG:
        for key in ("file_path", "local_decision", "local_reason"):
            value = payload.get(key)
            if isinstance(value, str):
                record[key] = value
    return record


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
    ) -> None:
        self._endpoint = endpoint
        self._home = home if home is not None else paths.home_dir()
        self._policy_path = policy_path or paths.policy_file(self._home)
        self._log = log or AuditLog(paths.audit_log_file(self._home))
        self._instances = instances
        self._report = report
        self._policy_key: tuple[int, int] | bool | None = False  # False: never loaded
        self._mode = pipeline.MODE_ENFORCE
        self._policy_error: str | None = "policy not loaded yet"
        self._policy_retry_at = 0.0
        self._requests = 0
        self._log_failures = 0

    @property
    def requests_served(self) -> int:
        return self._requests

    # -- policy ------------------------------------------------------------------------------

    def _refresh_policy(self) -> None:
        try:
            info = os.stat(self._policy_path)
            key: tuple[int, int] | None = (info.st_mtime_ns, info.st_size)
        except FileNotFoundError:
            key = None
        except OSError as exc:
            key = None
            self._policy_error = f"cannot read the policy file ({exc.strerror})"
        if key == self._policy_key:
            # Same file as last time. If it failed to load, try again now and then: the failure may
            # have been a lock held by an editor or a virus scanner, not the content.
            retry = (
                key is not None
                and self._policy_error is not None
                and time.monotonic() >= self._policy_retry_at
            )
            if not retry:
                return
        self._policy_key = key
        if key is None:
            self._policy_error = f"policy file not found: {self._policy_path}"
            self._report(f"policy problem: {self._policy_error}")
            return
        try:
            policy = load_policy(self._policy_path)
        except PolicyError as exc:
            if str(exc) != self._policy_error:
                self._report(f"policy problem: {exc}")
            self._policy_error = str(exc)
            self._policy_retry_at = time.monotonic() + POLICY_RETRY_S
            return
        self._mode = policy.mode
        self._policy_error = None
        self._report(f"policy loaded: mode={policy.mode}")

    # -- requests ----------------------------------------------------------------------------

    async def handle(self, line: bytes) -> bytes:
        started = time.perf_counter()
        try:
            request = protocol.decode_request(line)
        except protocol.ProtocolError as exc:
            return protocol.encode_error("-", protocol.ERR_BAD_REQUEST, str(exc))
        try:
            self._refresh_policy()
            if request.event == protocol.EVENT_PING:
                return protocol.encode_response(request.request_id, reason=self._status_text())
            decision = pipeline.decide(
                request.event,
                request.payload,
                mode=self._mode,
                policy_error=self._policy_error,
            )
            record = build_record(
                request,
                decision,
                mode=self._mode,
                latency_ms=(time.perf_counter() - started) * 1000,
            )
            if not self._log.append(record):
                self._note_log_failure()
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
        text = f"mode={self._mode}; requests={self._requests}"
        if self._policy_error is not None:
            text += f"; policy error: {self._policy_error}"
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
            "mode": self._mode,
            "pid": os.getpid(),
        }
        if not self._log.append(record):
            self._note_log_failure()

    # -- serving -----------------------------------------------------------------------------

    async def serve(self, stop: asyncio.Event) -> None:
        """Serve until ``stop`` is set. Raises ``ServerStartError`` / ``AddressInUse`` on start."""
        self._refresh_policy()
        server = create_server(
            self._endpoint,
            self.handle,
            instances=self._instances,
            on_error=lambda message: self._report(f"transport: {message}"),
        )
        await server.start()
        self._log_lifecycle("start")
        self._report(
            f"listening on {server.address} (mode={self._mode}, policy={self._policy_path}, "
            f"log={self._log.path})"
        )
        try:
            while not stop.is_set():
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=0.5)
        finally:
            await server.close()
            self._log_lifecycle("stop")
            self._report("stopped")
