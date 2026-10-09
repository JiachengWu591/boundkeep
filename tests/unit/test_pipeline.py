from __future__ import annotations

from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.daemon import pipeline


def pre(tool: str, command: object, **extra: Any) -> dict[str, Any]:
    return {"tool_name": tool, "tool_input": {"command": command, **extra}}


@pytest.mark.parametrize("tool", ["PowerShell", "Bash"])
def test_the_canary_in_a_shell_command_is_denied_in_enforce_mode(tool: str) -> None:
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        pre(tool, "echo hello BOUNDKEEP_CANARY world"),
        mode="enforce",
        policy_error=None,
    )
    assert decision.decision == protocol.DECISION_DENY
    assert pipeline.CANARY in decision.reason
    assert decision.decided_by == "canary"


@pytest.mark.parametrize(
    "payload",
    [
        pre("PowerShell", "Get-ChildItem"),
        pre("PowerShell", "你好 ✓"),
        pre("PowerShell", "boundkeep_canary"),  # the marker is case-sensitive
        {"tool_name": "Write", "tool_input": {"content": "BOUNDKEEP_CANARY"}},  # not a shell tool
        {"tool_name": "PowerShell", "tool_input": "BOUNDKEEP_CANARY"},  # input is not an object
        pre("PowerShell", ["BOUNDKEEP_CANARY"]),  # command is not a string
        pre("PowerShell", None),
        {"tool_name": 7, "tool_input": {"command": "BOUNDKEEP_CANARY"}},
        {"tool_input": {"command": "BOUNDKEEP_CANARY"}},
        {},
    ],
)
def test_everything_else_gets_no_decision(payload: dict[str, Any]) -> None:
    decision = pipeline.decide(protocol.EVENT_PRE, payload, mode="enforce", policy_error=None)
    assert decision.decision == protocol.DECISION_NONE
    assert decision.reason == ""


@pytest.mark.parametrize(
    "event", [protocol.EVENT_POST, protocol.EVENT_PROMPT, protocol.EVENT_CONFIG]
)
def test_only_pre_tool_use_events_ever_get_a_decision(event: str) -> None:
    decision = pipeline.decide(
        event, pre("PowerShell", "BOUNDKEEP_CANARY"), mode="enforce", policy_error=None
    )
    assert decision.decision == protocol.DECISION_NONE


def test_audit_only_never_answers_but_remembers_what_enforce_would_do() -> None:
    decision = pipeline.decide(
        protocol.EVENT_PRE, pre("Bash", "BOUNDKEEP_CANARY"), mode="audit-only", policy_error=None
    )
    assert decision.decision == protocol.DECISION_NONE
    assert decision.would_be == protocol.DECISION_DENY
    assert decision.decided_by == "audit-only"
    quiet = pipeline.decide(
        protocol.EVENT_PRE, pre("Bash", "ls"), mode="audit-only", policy_error=None
    )
    assert quiet.would_be is None


def test_an_unusable_policy_makes_pre_tool_use_ask_even_for_harmless_commands() -> None:
    harmless = pipeline.decide(
        protocol.EVENT_PRE, pre("Bash", "ls"), mode="enforce", policy_error="line 3: bad"
    )
    assert harmless.decision == protocol.DECISION_ASK
    assert "line 3: bad" in harmless.reason
    assert harmless.decided_by == "policy-invalid"
    canary = pipeline.decide(
        protocol.EVENT_PRE, pre("Bash", "BOUNDKEEP_CANARY"), mode="enforce", policy_error="x"
    )
    assert canary.decision == protocol.DECISION_ASK  # never silently weaker than ask
    for event in (protocol.EVENT_POST, protocol.EVENT_PROMPT):
        assert (
            pipeline.decide(event, {}, mode="enforce", policy_error="x").decision
            == protocol.DECISION_NONE
        )


def test_shell_command_helper() -> None:
    assert pipeline.shell_command(pre("PowerShell", "x")) == "x"
    assert pipeline.shell_command({"tool_name": "Read", "tool_input": {"command": "x"}}) is None
    assert pipeline.shell_command({"tool_name": "Bash", "tool_input": {"command": 3}}) is None
