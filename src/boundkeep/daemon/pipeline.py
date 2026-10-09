"""The M0 decision pipeline: a placeholder that proves the path, not a rule engine.

In ``enforce`` mode a shell command (``Bash`` / ``PowerShell``) that contains ``BOUNDKEEP_CANARY``
is denied; everything else gets "no decision" (Claude Code's normal permission flow). In
``audit-only`` mode nothing is returned to Claude Code, but what ``enforce`` would have done is
recorded. If the policy file is unusable, PreToolUse events are answered with ``ask`` (fail closed).

Until M1 lands there are NO rules: apart from the canary, M0 does not review anything, and no
document may suggest otherwise.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from boundkeep import protocol

CANARY = "BOUNDKEEP_CANARY"
SHELL_TOOLS = frozenset({"Bash", "PowerShell"})
MODE_ENFORCE = "enforce"
MODE_AUDIT_ONLY = "audit-only"


@dataclass(frozen=True)
class Decision:
    decision: str  # protocol.DECISION_DENY / ASK / NONE
    reason: str
    decided_by: str
    would_be: str | None = None  # audit-only: what enforce mode would have answered


def shell_command(payload: Mapping[str, Any]) -> str | None:
    """The command text of a shell tool call, or None for any other event."""
    name = payload.get("tool_name")
    if not isinstance(name, str) or name not in SHELL_TOOLS:
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, Mapping):
        return None
    command = tool_input.get("command")
    return command if isinstance(command, str) else None


def decide(
    event: str, payload: Mapping[str, Any], *, mode: str, policy_error: str | None
) -> Decision:
    if event != protocol.EVENT_PRE:
        return Decision(protocol.DECISION_NONE, "", "no-decision-for-event")
    if policy_error is not None:
        return Decision(
            protocol.DECISION_ASK,
            f"boundkeep: the policy file is not usable ({policy_error}); "
            "fix it or run 'boundkeep doctor'",
            "policy-invalid",
        )
    command = shell_command(payload)
    if command is None or CANARY not in command:
        return Decision(protocol.DECISION_NONE, "", "no-rule")
    if mode == MODE_AUDIT_ONLY:
        return Decision(protocol.DECISION_NONE, "", "audit-only", would_be=protocol.DECISION_DENY)
    return Decision(
        protocol.DECISION_DENY,
        f"boundkeep: blocked (M0 canary rule: the command contains {CANARY})",
        "canary",
    )
