"""The backend contract of the LLM audit (PROJECT_SPEC.md §9.1, §9.3).

``AuditBackend.audit(request, deadline=...)`` either returns an ``AuditResult`` whose verdict passed
``parse_verdict`` or raises ``BackendError`` with one of ``FAILURE_KINDS``. Every adapter shares the
output schema (``VERDICT_SCHEMA``), the parser and the error classes; they differ only in how the
request travels. A backend never sees anything but a ``GatedRequest``, which only
``audit.send_gate`` builds: the field whitelist and the redaction happen there, once, for all of
them.

The model's output is not trusted: it must be exactly the five fields, of exactly the right types
and sizes, in valid JSON without duplicate keys; anything else is ``invalid_output``, never
"repaired". What the code then does with a valid output is ``audit.verdict``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Final, Literal, Protocol

FailureKind = Literal[
    "timeout", "rate_limit", "http_5xx", "http_4xx", "invalid_output", "auth", "network"
]
# The six kinds of the spec plus ``http_4xx`` (a request the service refused that is neither an
# authentication error nor a rate limit: a wrong model name, a parameter it does not take).
FAILURE_KINDS: Final[tuple[FailureKind, ...]] = (
    "timeout",
    "rate_limit",
    "http_5xx",
    "http_4xx",
    "invalid_output",
    "auth",
    "network",
)
ModelDecision = Literal["allow", "ask", "deny"]
VERDICT_TOOL_NAME: Final = "report_verdict"
MAX_OUTPUT_CHARS: Final = 8192  # the whole JSON the model wrote
MAX_REASONING_CHARS: Final = 1200  # "at most 60 words": generous for Chinese and English alike
MAX_REASON_FOR_USER_CHARS: Final = 400
_FIELDS: Final = ("reasoning", "deviates_from_task", "risk", "verdict", "reason_for_user")

# The tool / response schema of §9.3: vendor-neutral, fixed field order, the reasoning first.
VERDICT_SCHEMA: Final[dict[str, object]] = {
    "type": "object",
    "properties": {
        "reasoning": {
            "type": "string",
            "description": "At most 60 words. Name the input fields the judgement rests on.",
        },
        "deviates_from_task": {"type": "boolean"},
        "risk": {"type": "integer", "enum": [0, 1, 2, 3]},
        "verdict": {"type": "string", "enum": ["allow", "ask", "deny"]},
        "reason_for_user": {"type": "string"},
    },
    "required": list(_FIELDS),
    "additionalProperties": False,
}
VERDICT_TOOL_DESCRIPTION: Final = (
    "Report the audit verdict for the one tool call described in the user message."
)


class BackendError(Exception):
    """A failed audit call. ``detail`` is safe to log: it never holds the request body, the
    response body or a key (adapters build it from status codes and their own words)."""

    def __init__(
        self,
        kind: FailureKind,
        detail: str,
        *,
        retryable: bool = False,
        retry_after_s: float | None = None,
    ) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind: FailureKind = kind
        self.detail = detail
        self.retryable = retryable
        self.retry_after_s = retry_after_s


# Only ``send_gate`` holds this; ``GatedRequest`` refuses to be built without it, so a caller cannot
# hand a backend content that skipped the whitelist and the redaction by accident.
_SEAL: Final = object()


@dataclass(frozen=True, slots=True)
class GatedRequest:
    """What may be sent: the user message (JSON text) and the fixed system prompt."""

    content: str
    system_prompt: str
    prompt_hash: str
    prompt_version: str
    seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.seal is not _SEAL:
            raise TypeError("a GatedRequest is built by boundkeep.audit.send_gate only")


@dataclass(frozen=True, slots=True)
class ModelVerdict:
    reasoning: str
    deviates_from_task: bool
    risk: int
    verdict: ModelDecision
    reason_for_user: str


@dataclass(frozen=True, slots=True)
class Usage:
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None

    def as_record(self) -> dict[str, int]:
        out = {
            "prompt": self.prompt_tokens,
            "completion": self.completion_tokens,
            "total": self.total_tokens,
        }
        return {key: value for key, value in out.items() if value is not None}


@dataclass(frozen=True, slots=True)
class AuditResult:
    verdict: ModelVerdict
    usage: Usage = Usage()
    latency_ms: float = 0.0
    attempts: int = 1


class AuditBackend(Protocol):
    """An adapter. ``name`` / ``model`` / ``transport`` go into the audit log and the cache key."""

    @property
    def name(self) -> str: ...

    @property
    def model(self) -> str: ...

    @property
    def transport(self) -> str: ...

    def audit(self, request: GatedRequest, *, deadline: float) -> AuditResult:
        """``deadline`` is a ``time.monotonic()`` value; raises ``BackendError``."""
        ...


def invalid(detail: str) -> BackendError:
    return BackendError("invalid_output", detail)


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            # {"verdict":"deny","verdict":"allow"}: JSON says nothing about which one counts
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _no_constants(name: str) -> object:
    raise ValueError(f"{name} is not JSON")


def strict_json(text: str) -> object:
    """``json.loads`` that refuses duplicate keys, NaN / Infinity; raises ``ValueError``."""
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except RecursionError:
        raise ValueError("nested too deeply") from None


def parse_verdict(text: object) -> ModelVerdict:
    """The model's verdict from the JSON text it wrote; ``BackendError("invalid_output")`` for
    anything that is not exactly the schema (no repair, no coercion)."""
    if not isinstance(text, str):
        raise invalid("the verdict is not a JSON string")
    if len(text) > MAX_OUTPUT_CHARS:
        raise invalid(f"the verdict is longer than {MAX_OUTPUT_CHARS} characters")
    try:
        obj = strict_json(text)
    except ValueError as exc:
        raise invalid(f"the verdict is not valid JSON ({str(exc)[:60]})") from None
    if not isinstance(obj, dict):
        raise invalid("the verdict is not a JSON object")
    keys = set(obj)
    missing = [name for name in _FIELDS if name not in keys]
    extra = sorted(keys - set(_FIELDS))
    if missing:
        raise invalid(f"the verdict lacks {', '.join(missing)}")
    if extra:
        raise invalid(f"the verdict has fields the schema does not ({len(extra)})")
    reasoning = obj["reasoning"]
    deviates = obj["deviates_from_task"]
    risk = obj["risk"]
    verdict = obj["verdict"]
    reason = obj["reason_for_user"]
    if not isinstance(reasoning, str) or len(reasoning) > MAX_REASONING_CHARS:
        raise invalid(f"reasoning is not a string of at most {MAX_REASONING_CHARS} characters")
    if type(deviates) is not bool:
        raise invalid("deviates_from_task is not a boolean")
    if type(risk) is not int or risk not in (0, 1, 2, 3):
        raise invalid("risk is not one of the integers 0, 1, 2, 3")
    if verdict not in ("allow", "ask", "deny"):
        raise invalid("verdict is not allow, ask or deny")
    if not isinstance(reason, str) or len(reason) > MAX_REASON_FOR_USER_CHARS:
        raise invalid(
            f"reason_for_user is not a string of at most {MAX_REASON_FOR_USER_CHARS} characters"
        )
    return ModelVerdict(
        reasoning=reasoning,
        deviates_from_task=deviates,
        risk=risk,
        verdict=verdict,
        reason_for_user=reason,
    )


def verdict_json(
    *,
    verdict: str = "allow",
    risk: int = 0,
    deviates: bool = False,
    reasoning: str = "the action matches the task",
    reason_for_user: str = "",
) -> str:
    """A verdict as a model would write it (for the fake backend and for tests)."""
    return json.dumps(
        {
            "reasoning": reasoning,
            "deviates_from_task": deviates,
            "risk": risk,
            "verdict": verdict,
            "reason_for_user": reason_for_user,
        },
        ensure_ascii=False,
    )
