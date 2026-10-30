"""The code's own ruling on a model verdict (PROJECT_SPEC.md §9.5): a pure, total function.

    final = model.verdict
    if model.deviates_from_task:   final = max(final, ASK)
    if model.risk >= 2:            final = max(final, ASK)
    if model.risk == 3:            final = DENY
    if tainted and the call has a sensitive tag and final == ALLOW:   final = ASK
    the call failed / timed out / its output is off the schema:      final = on_failure

Only the five validated fields count (``backends.base.parse_verdict``); nothing the model writes in
``reasoning`` or ``reason_for_user`` can change the outcome. A model can make a call stricter than
these lines, never looser: an ``allow`` that comes with a deviation or a risk of 2 or more is an
``ask``, a risk of 3 is a ``deny`` whatever verdict came with it. ``on_failure`` is ``ask`` or
``deny`` (the schema refuses ``allow``; anything else is read as ``ask`` here, so the function stays
total). ``tests/unit/test_m3a_verdict.py`` checks every combination against a table.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from boundkeep.audit.backends.base import FAILURE_KINDS, FailureKind, ModelVerdict

Decision = Literal["allow", "ask", "deny"]
# besides the backend's own failures: the send gate refused the content, no backend could be built
# (``unavailable``), or something unexpected broke in between (``internal``)
Failure = FailureKind | Literal["refused", "unavailable", "internal"]
FAILURES: Final[tuple[Failure, ...]] = (*FAILURE_KINDS, "refused", "unavailable", "internal")
_RANK: Final[dict[str, int]] = {"allow": 0, "ask": 1, "deny": 2}


@dataclass(frozen=True, slots=True)
class Ruling:
    final: Decision
    steps: tuple[str, ...]  # which lines of §9.5 changed the outcome, for the audit log


def _at_least(current: Decision, floor: Decision) -> Decision:
    return current if _RANK[current] >= _RANK[floor] else floor


def rule_on(
    model: ModelVerdict | None,
    failure: Failure | None,
    *,
    tainted: bool,
    sensitive: bool,
    on_failure: str,
) -> Ruling:
    """The final verdict of one audited call (see the module docstring)."""
    fallback: Decision = "deny" if on_failure == "deny" else "ask"
    if failure is not None or model is None:
        return Ruling(fallback, (f"failure:{failure or 'no-verdict'}",))
    steps: list[str] = []
    final: Decision = model.verdict if model.verdict in _RANK else "ask"
    if model.deviates_from_task:
        raised = _at_least(final, "ask")
        if raised != final:
            steps.append("deviates")
        final = raised
    if model.risk >= 2:
        raised = _at_least(final, "ask")
        if raised != final:
            steps.append("risk>=2")
        final = raised
    if model.risk == 3 and final != "deny":
        steps.append("risk=3")
        final = "deny"
    if tainted and sensitive and final == "allow":
        steps.append("tainted-sensitive")
        final = "ask"
    return Ruling(final, tuple(steps))
