"""One LLM audit of a gray tool call: send gate, cache, backend, then the code's ruling.

``Auditor.review`` never raises and never returns ``allow`` on any failure: whatever goes wrong
(no backend, the gate refuses, a timeout, an error, an output off the schema, a late answer, an
exception) ends in ``on_failure``. The reason shown to Claude Code is built from the validated
structured fields only; the model's free text (``reasoning``, ``reason_for_user``) goes to the
audit log, cut and cleaned, and never back into the agent's context, where a model that was steered
by the command text could otherwise talk to the agent.

The budget of one review is ``timeout_ms``, at most ``MAX_BUDGET_MS``: the hook client answers a
PreToolUse within 10 s whatever happens, and the daemon's rule deadline (2 s) comes on top.
"""

from __future__ import annotations

import contextlib
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from boundkeep.audit.backends import build_backend
from boundkeep.audit.backends.base import AuditBackend, AuditResult, BackendError, ModelVerdict
from boundkeep.audit.cache import VerdictCache, cache_key
from boundkeep.audit.prompt import system_prompt
from boundkeep.audit.send_gate import MIN_SECRET_CHARS, gate
from boundkeep.audit.verdict import Decision, Failure, rule_on
from boundkeep.normalize.model import Action
from boundkeep.policy.schema import LlmAudit
from boundkeep.session.facts import SessionFacts

MAX_BUDGET_MS: Final = 6000
_LATE_GRACE_S: Final = 0.05
_TEXT_CHARS: Final = 300
# substrings, so PGPASSWORD and HF_TOKEN count; not PWD (the working directory is in every path)
_SECRET_NAME = re.compile(r"key|token|secret|passw|credential|auth(?!or)|cookie", re.I)


def secret_values(env: Mapping[str, str], api_key_env: str | None = None) -> tuple[str, ...]:
    """The values of the environment variables whose names look like they hold a secret, the API
    key's variable among them: the send gate refuses a request that carries one (a path such as
    ``$GITHUB_TOKEN/x`` is expanded with this environment)."""
    out: dict[str, None] = {}
    for name, value in env.items():
        if not isinstance(value, str) or len(value) < MIN_SECRET_CHARS:
            continue
        if name == api_key_env or _SECRET_NAME.search(name):
            out[value] = None
    return tuple(out)


@dataclass(frozen=True, slots=True)
class AuditOutcome:
    final: Decision
    decided_by: str  # llm | llm-cache | llm-failure:<kind>
    reason: str  # for the hook output: structured facts only
    record: dict[str, Any]  # the "llm" entry of the audit log record


def budget_ms(llm: LlmAudit) -> int:
    return min(llm.timeout_ms, MAX_BUDGET_MS)


def _clean(text: object, limit: int = _TEXT_CHARS) -> str:
    raw = text if isinstance(text, str) else str(text)
    shown = "".join(ch if ch.isprintable() else " " for ch in raw[: limit + 1])
    return shown[: limit - 3] + "..." if len(shown) > limit else shown


class Auditor:
    """The configured audit: the backend (None: it could not be built), its cache, the budget."""

    def __init__(
        self,
        llm: LlmAudit,
        backend: AuditBackend | None,
        unavailable: str | None = None,
        *,
        cache: VerdictCache | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._llm = llm
        self._backend = backend
        self._unavailable = unavailable or (
            None if backend is not None else "no backend is configured"
        )
        self._cache = cache if cache is not None else VerdictCache(llm.cache_ttl_s)
        self._clock = clock

    @classmethod
    def build(cls, llm: LlmAudit, env: Mapping[str, str] | None = None) -> Auditor | None:
        """The auditor for a policy's ``llm_audit``; None when the backend is ``none``."""
        if llm.backend == "none":
            return None
        backend, why = build_backend(llm, env)
        return cls(llm, backend, why)

    @property
    def llm(self) -> LlmAudit:
        return self._llm

    @property
    def backend(self) -> AuditBackend | None:
        return self._backend

    @property
    def budget_s(self) -> float:
        return budget_ms(self._llm) / 1000.0

    @property
    def wants_intents(self) -> int:
        """How many task intents a review uses (0: none are sent)."""
        return self._llm.intent_prompts if self._llm.send_task_intent else 0

    def close(self) -> None:
        close = getattr(self._backend, "close", None)
        if callable(close):
            # closing a client must not take anything down
            with contextlib.suppress(Exception):
                close()

    def review(
        self,
        actions: Sequence[Action],
        *,
        tool: object,
        facts: SessionFacts,
        sensitive_tags: Sequence[str],
        home: str | None,
        env: Mapping[str, str] | None = None,
    ) -> AuditOutcome:
        """``env``: the environment the actions were normalized with (default: the process's)."""
        try:
            return self._review(
                actions,
                tool=tool,
                facts=facts,
                sensitive_tags=sensitive_tags,
                home=home,
                env=env if env is not None else os.environ,
            )
        except Exception as exc:  # noqa: BLE001 - a broken audit fails to on_failure
            ruling = rule_on(
                None, "internal", tainted=True, sensitive=True, on_failure=self._llm.on_failure
            )
            record = {
                "backend": self._llm.backend,
                "outcome": "internal",
                "detail": _clean(type(exc).__name__, 80),
                "final": ruling.final,
            }
            return AuditOutcome(
                ruling.final, "llm-failure:internal", self._failure_reason("internal", ""), record
            )

    def _review(
        self,
        actions: Sequence[Action],
        *,
        tool: object,
        facts: SessionFacts,
        sensitive_tags: Sequence[str],
        home: str | None,
        env: Mapping[str, str],
    ) -> AuditOutcome:
        started = self._clock()
        deadline = started + self.budget_s
        wanted = set(sensitive_tags)
        sensitive = any(tag in wanted for action in actions for tag in action.risk_tags)
        backend = self._backend
        prompt = system_prompt()
        record: dict[str, Any] = {
            "backend": self._llm.backend,
            "model": backend.model if backend is not None else self._configured_model(),
            "transport": backend.transport if backend is not None else None,
            "prompt": f"v{prompt.version}:{prompt.short_hash}",
            "tainted": facts.tainted,
            "sensitive": sensitive,
        }
        failure: Failure | None = None
        detail = ""
        result: AuditResult | None = None
        cache_state = "off" if not self._cache.enabled else "miss"
        if backend is None:
            failure, detail = "unavailable", self._unavailable or ""
        else:
            gated = gate(
                actions,
                tool=tool,
                facts=facts,
                send_task_intent=self._llm.send_task_intent,
                intent_prompts=self._llm.intent_prompts,
                home=home,
                secrets=secret_values(env, self._api_key_env()),
            )
            if gated.request is None:
                failure, detail = "refused", gated.refused or ""
            else:
                key = cache_key(
                    backend=backend.name,
                    model=backend.model,
                    transport=backend.transport,
                    prompt_hash=gated.request.prompt_hash,
                    content=gated.request.content,
                )
                result = self._cache.get(key)
                if result is not None:
                    cache_state = "hit"
                else:
                    try:
                        result = backend.audit(gated.request, deadline=deadline)
                    except BackendError as exc:
                        failure, detail = exc.kind, exc.detail
                    if result is not None and self._clock() > deadline + _LATE_GRACE_S:
                        failure, detail = "timeout", "the answer came after the budget"
                        result = None
                    if result is not None:
                        self._cache.put(key, result)
        model: ModelVerdict | None = result.verdict if result is not None else None
        ruling = rule_on(
            model,
            failure,
            tainted=facts.tainted,
            sensitive=sensitive,
            on_failure=self._llm.on_failure,
        )
        record["cache"] = cache_state
        record["outcome"] = failure or "ok"
        if detail:
            record["detail"] = _clean(detail, 200)
        record["final"] = ruling.final
        if ruling.steps:
            record["steps"] = list(ruling.steps)
        record["latency_ms"] = round((self._clock() - started) * 1000.0, 2)
        if result is not None and model is not None:
            record["model_verdict"] = model.verdict
            record["risk"] = model.risk
            record["deviates"] = model.deviates_from_task
            record["attempts"] = result.attempts
            tokens = result.usage.as_record()
            if tokens and cache_state != "hit":
                record["tokens"] = tokens
            record["reasoning"] = _clean(model.reasoning)
            if model.reason_for_user:
                record["reason_for_user"] = _clean(model.reason_for_user, 200)
        if failure is not None or model is None:
            kind = failure or "internal"
            return AuditOutcome(
                ruling.final, f"llm-failure:{kind}", self._failure_reason(kind, detail), record
            )
        by = "llm-cache" if cache_state == "hit" else "llm"
        reason = self._verdict_reason(ruling.final, model, facts)
        return AuditOutcome(ruling.final, by, reason, record)

    def _configured_model(self) -> str | None:
        block = getattr(self._llm, self._llm.backend, None)
        model = getattr(block, "model", None)
        return model if isinstance(model, str) and model else None

    def _api_key_env(self) -> str | None:
        block = getattr(self._llm, self._llm.backend, None)
        name = getattr(block, "api_key_env", None)
        return name if isinstance(name, str) and name else None

    def _failure_reason(self, failure: str, detail: str) -> str:
        verb = "refusing" if self._llm.on_failure == "deny" else "asking"
        shown = f" ({_clean(detail, 120)})" if detail else ""
        return (
            f"boundkeep: no rule decides this action and the LLM audit failed: {failure}{shown}; "
            f"{verb} (llm_audit.on_failure)"
        )

    @staticmethod
    def _verdict_reason(final: Decision, model: ModelVerdict, facts: SessionFacts) -> str:
        notes = [f"risk {model.risk} of 3"]
        if model.deviates_from_task:
            notes.append("it does not fit the user's task")
        if facts.tainted:
            notes.append("the session recently read untrusted content")
        what = ", ".join(notes)
        if final == "deny":
            return f"boundkeep (llm-audit): the LLM audit refuses this action ({what})"
        if final == "ask":
            return f"boundkeep: the LLM audit asks about this action ({what})"
        return f"boundkeep: allowed by the LLM audit ({what})"
