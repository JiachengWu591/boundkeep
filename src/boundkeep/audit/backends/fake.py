"""A scripted backend for every test: no network, no key, the same output validation.

Each step of the script is the JSON text a model would write (it goes through ``parse_verdict``
like a real answer), a ``BackendError`` to raise, or a function of the request that returns either.
A function on its own answers every call. ``requests`` keeps what was "sent", so a test can check
that nothing outside the whitelist got through. ``delay_s`` simulates a slow model against the
deadline.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable

from boundkeep.audit.backends.base import (
    AuditResult,
    BackendError,
    GatedRequest,
    Usage,
    parse_verdict,
    verdict_json,
)

Step = str | BackendError | Callable[[GatedRequest], str | BackendError]
FAKE_USAGE = Usage(prompt_tokens=100, completion_tokens=20, total_tokens=120)


class FakeBackend:
    def __init__(
        self,
        script: Iterable[Step] | Callable[[GatedRequest], str | BackendError],
        *,
        model: str = "fake-model",
        transport: str = "fake",
        delay_s: float = 0.0,
        usage: Usage = FAKE_USAGE,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._every = script if callable(script) else None
        self._steps: list[Step] = [] if callable(script) else list(script)
        self._model = model
        self._transport = transport
        self._delay_s = delay_s
        self._usage = usage
        self._sleep = sleep
        self.requests: list[GatedRequest] = []

    @classmethod
    def answering(cls, **verdict: object) -> FakeBackend:
        """A backend that gives the same verdict every time (keywords of ``verdict_json``)."""
        text = verdict_json(**verdict)  # type: ignore[arg-type]
        return cls(lambda _request: text)

    @property
    def name(self) -> str:
        return "fake"

    @property
    def model(self) -> str:
        return self._model

    @property
    def transport(self) -> str:
        return self._transport

    def audit(self, request: GatedRequest, *, deadline: float) -> AuditResult:
        if not isinstance(request, GatedRequest):
            raise TypeError("a backend only takes a GatedRequest")
        started = time.monotonic()
        self.requests.append(request)
        if self._every is not None:
            step: Step = self._every
        elif self._steps:
            step = self._steps.pop(0)
        else:
            raise BackendError("network", "the fake backend's script is exhausted")
        if self._delay_s:
            self._sleep(self._delay_s)
        if time.monotonic() > deadline:
            raise BackendError("timeout", "the fake backend answered after the deadline")
        answer = step(request) if callable(step) else step
        if isinstance(answer, BackendError):
            raise answer
        verdict = parse_verdict(answer)
        return AuditResult(
            verdict=verdict,
            usage=self._usage,
            latency_ms=(time.monotonic() - started) * 1000.0,
        )
