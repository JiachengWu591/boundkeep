"""The M1 decision pipeline: normalize -> rules -> strictest wins -> hook decision.

A PreToolUse payload becomes a list of ``Action`` (one per simple command of a shell line, one for
other tools); the policy rules are evaluated per action and merged strictest-first (deny > ask >
gray > allow). With no LLM backend (M3) a gray outcome is an ``ask``. ``allow`` is only ever
emitted to Claude Code when the policy sets ``defaults.emit_allow``; by default an allow is "no
decision" and Claude Code's own permission flow continues.

M0's canary is a built-in rule of ``policy.evaluate``. If the policy file is unusable, PreToolUse
events are answered with ``ask`` (fail closed). A deny reason reads ``boundkeep (<rule-id>): ...``;
every reason shown or stored is sanitized (``_clean``): gray reasons carry text the agent wrote.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from boundkeep import protocol
from boundkeep.normalize import paths as norm_paths
from boundkeep.normalize.event import HARMLESS_TOOLS, normalize_event
from boundkeep.normalize.model import Action, Platform
from boundkeep.policy import Policy, Verdict, evaluate
from boundkeep.policy.glob import MAX_PATTERN_LENGTH
from boundkeep.policy.schema import Rule, escape_glob_literal

SHELL_TOOLS = frozenset({"Bash", "PowerShell"})
MODE_ENFORCE = "enforce"
MODE_AUDIT_ONLY = "audit-only"
MAX_REASON_PARTS = 4
PART_CHARS = 100  # one reason part (a rule's reason fits; attacker text is cut harder)
GRAY_PART_CHARS = 80  # gray reasons, program names: text the agent controls
MAX_REASON_CHARS = 600  # the whole reason shown to the user


def local_platform() -> Platform:
    return "windows" if sys.platform == "win32" else "posix"


@dataclass(frozen=True)
class Decision:
    decision: str  # protocol.DECISION_*
    reason: str
    decided_by: str
    would_be: str | None = None  # audit-only: what enforce mode would have answered
    verdict: str | None = None  # deny | ask | allow | gray (the policy's own outcome)
    rule_ids: tuple[str, ...] = ()
    programs: tuple[str, ...] = ()
    gray_reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class Review:
    """Normalized actions and the policy's verdict for one PreToolUse payload."""

    actions: tuple[Action, ...]
    verdict: Verdict


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


class _RuntimeRuleSkipped(Exception):
    """The machine-dependent rules cannot be built; the message says why (already sanitized)."""


_CONFIG_DIR_RULE_ID = "protect-guard-config-dir"
_CONFIG_DIR_READ_RULE_ID = "no-claude-config-dir-secret-read"


def _config_dir_rules(env: Mapping[str, str], home: str | None) -> tuple[Rule, ...]:
    """The rules for ``CLAUDE_CONFIG_DIR`` (empty: not set). Raises ``_RuntimeRuleSkipped``."""
    config_dir = env.get("CLAUDE_CONFIG_DIR")
    if not config_dir:
        return ()
    if not isinstance(config_dir, str):
        raise _RuntimeRuleSkipped("CLAUDE_CONFIG_DIR is not a string")
    shown = _clean(config_dir, 60)
    norm = norm_paths.normalize_path(config_dir, cwd=None, home=home, env=env, dialect="tool")
    if not norm.absolute:
        raise _RuntimeRuleSkipped(
            f"CLAUDE_CONFIG_DIR ({shown}) is not an absolute path; its settings and credentials "
            "are not protected by the runtime rules"
        )
    # A directory with "[", "*" or "?" in its name is uncertain only because of the glob marker:
    # the characters are escaped below, so the literal directory is what gets protected.
    blocking = [reason for reason in norm.reasons if reason != "glob"]
    if blocking or (norm.uncertain and not norm.reasons):
        why = _clean(", ".join(blocking) or "unknown", 60)
        raise _RuntimeRuleSkipped(
            f"CLAUDE_CONFIG_DIR ({shown}) cannot be resolved ({why}); its settings and "
            "credentials are not protected by the runtime rules"
        )
    base = escape_glob_literal(norm.key).rstrip("/")
    settings_glob = f"{base}/settings*.json"
    globs = (f"{base}/.credentials.json", f"{base}/projects/**")
    if max(len(settings_glob), *(len(g) for g in globs)) > MAX_PATTERN_LENGTH:
        raise _RuntimeRuleSkipped(
            f"CLAUDE_CONFIG_DIR is too long ({len(config_dir)} characters) for a policy glob "
            f"(limit {MAX_PATTERN_LENGTH}); its settings and credentials are not protected by the "
            "runtime rules"
        )
    return (
        Rule.model_validate(
            {
                "id": _CONFIG_DIR_RULE_ID,
                "match": {"path_glob": [settings_glob], "access": "write"},
                "action": "deny",
                "reason": "do not modify the Claude Code settings (CLAUDE_CONFIG_DIR)",
            }
        ),
        Rule.model_validate(
            {
                "id": _CONFIG_DIR_READ_RULE_ID,
                "match": {"path_glob": list(globs), "access": "read"},
                "action": "deny",
                "reason": "reading Claude Code credentials or transcripts is not allowed",
            }
        ),
    )


def runtime_policy_checked(
    policy: Policy, env: Mapping[str, str], home: str | None
) -> tuple[Policy, str | None]:
    """``policy`` plus rules that depend on this machine, and an error text if some are missing.

    ``protect-guard-config`` names ``~/.claude``, but ``CLAUDE_CONFIG_DIR`` can move it; when it
    is set, that directory's settings files get the same write protection and its credentials and
    transcripts a read denial (glob characters in the name are escaped). NEVER raises: when the
    rules cannot be built (a relative or unresolvable directory, one longer than a glob may be,
    any unexpected error) the policy comes back unchanged together with a short, printable
    message, so the caller can log it and keep serving with a policy it knows is incomplete,
    instead of failing the reload and silently keeping an OLDER policy. ``(policy, None)`` means
    there was nothing to add or everything was added.
    """
    try:
        rules = tuple(
            rule
            for rule in _config_dir_rules(env, home)
            if not any(existing.id == rule.id for existing in policy.rules)
        )
        if not rules:
            return policy, None
        return policy.model_copy(update={"rules": (*rules, *policy.rules)}), None
    except _RuntimeRuleSkipped as exc:
        return policy, str(exc)
    except Exception as exc:  # noqa: BLE001 - this must never take the daemon's reload down
        return policy, (
            "CLAUDE_CONFIG_DIR: the runtime rules could not be built "
            f"({_clean(type(exc).__name__, 40)}); its settings are not protected by them"
        )


def runtime_policy(policy: Policy, env: Mapping[str, str], home: str | None) -> Policy:
    """``runtime_policy_checked`` without the error text (never raises)."""
    return runtime_policy_checked(policy, env, home)[0]


def review(
    payload: Mapping[str, Any],
    policy: Policy,
    *,
    platform: Platform | None = None,
    env: Mapping[str, str] | None = None,
    home: str | None = None,
) -> Review:
    """Normalize ``payload`` and evaluate ``policy`` on it (never raises)."""
    platform = platform or local_platform()
    env = env if env is not None else os.environ
    actions = tuple(normalize_event(payload, platform=platform, env=env, home=home))
    verdict = evaluate(policy, actions, platform=platform)
    tool = payload.get("tool_name")
    if verdict.decision == "gray" and isinstance(tool, str) and tool in HARMLESS_TOOLS:
        # Tools that touch nothing on the machine need no rule; they are never gray.
        verdict = Verdict("allow", (), ("harmless-tool",), verdict.actions)
    return Review(actions, verdict)


def _clean(text: object, limit: int) -> str:
    """``text`` made safe to show and to store: control, format (bidi) and other non-printable
    characters become ``?``, and it is cut to ``limit`` characters (``...`` marks the cut).

    Gray reasons carry text the agent controls (``git-unknown-subcommand:<what it typed>``), so
    nothing reaches the confirmation dialog or the audit log without passing through here.
    """
    raw = text if isinstance(text, str) else str(text)
    shown = "".join(ch if ch.isprintable() else "?" for ch in raw[: limit + 1])
    return shown[: limit - 3] + "..." if len(shown) > limit else shown


def _text(parts: tuple[str, ...], limit: int = MAX_REASON_PARTS) -> str:
    """The first ``limit`` parts, each sanitized and cut, joined; the whole is capped as well."""
    shown = "; ".join(_clean(part, PART_CHARS) for part in parts[:limit])
    whole = shown + (f" (+{len(parts) - limit} more)" if len(parts) > limit else "")
    return _clean(whole, MAX_REASON_CHARS)


def _from_verdict(verdict: Verdict, policy: Policy) -> tuple[str, str, str]:
    """(protocol decision, reason, decided_by) for the policy's verdict."""
    ids = ",".join(verdict.rule_ids[:MAX_REASON_PARTS])
    by = f"rule:{ids}" if ids else "rule"
    if verdict.decision == "deny":
        why = _text(verdict.reasons) or "blocked by policy"
        return protocol.DECISION_DENY, f"boundkeep ({ids or 'policy'}): {why}", by
    if verdict.decision == "ask":
        reason = _text(verdict.reasons) or "the policy asks for confirmation"
        return protocol.DECISION_ASK, f"boundkeep: {reason}", by
    if verdict.decision == "gray":
        why = _text(tuple(_clean(r, GRAY_PART_CHARS) for r in dict.fromkeys(verdict.reasons)), 3)
        return (
            protocol.DECISION_ASK,
            f"boundkeep: no rule decides this action ({why or 'no rule applies'}); "
            "asking (no LLM audit is configured)",
            "gray",
        )
    if policy.defaults.emit_allow:
        return protocol.DECISION_ALLOW, f"boundkeep: allowed by {ids or 'policy'}", by
    return protocol.DECISION_NONE, "", by if ids else "rule-allow"


def _finish(result: Review, mode: str, policy: Policy) -> Decision:
    decision, reason, decided_by = _from_verdict(result.verdict, policy)
    programs = tuple(
        dict.fromkeys(_clean(a.program, GRAY_PART_CHARS) for a in result.actions if a.program)
    )[:8]
    gray = tuple(
        dict.fromkeys(_clean(r, GRAY_PART_CHARS) for a in result.actions for r in a.gray_reasons)
    )[:6]
    common: dict[str, Any] = {
        "verdict": result.verdict.decision,
        "rule_ids": result.verdict.rule_ids,
        "programs": programs,
        "gray_reasons": gray,
    }
    if mode == MODE_AUDIT_ONLY:
        would = decision if decision != protocol.DECISION_NONE else None
        return Decision(protocol.DECISION_NONE, "", "audit-only", would_be=would, **common)
    return Decision(decision, reason, decided_by, **common)


def decide(
    event: str,
    payload: Mapping[str, Any],
    *,
    mode: str,
    policy: Policy | None,
    policy_error: str | None,
    platform: Platform | None = None,
    env: Mapping[str, str] | None = None,
    home: str | None = None,
) -> Decision:
    if event != protocol.EVENT_PRE:
        return Decision(protocol.DECISION_NONE, "", "no-decision-for-event")
    if policy_error is not None or policy is None:
        return Decision(
            protocol.DECISION_ASK,
            f"boundkeep: the policy file is not usable ({_clean(policy_error, 200)}); "
            "fix it or run 'boundkeep doctor'",
            "policy-invalid",
        )
    result = review(payload, policy, platform=platform, env=env, home=home)
    return _finish(result, mode, policy)
