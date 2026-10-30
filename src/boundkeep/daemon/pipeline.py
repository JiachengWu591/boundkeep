"""The decision pipeline: normalize -> rules (with the session's taint state) -> taint step ->
LLM audit of gray calls (optional) -> the code's ruling -> hook decision.

A PreToolUse payload becomes a list of ``Action`` (one per simple command of a shell line, one for
other tools); the policy rules are evaluated per action and merged strictest-first (deny > ask >
gray > allow). With no LLM backend a gray outcome is an ``ask``; with one, ``audit.auditor`` asks
the model and ``audit.verdict`` rules on its answer (any failure: ``llm_audit.on_failure``). A gray
call the normalizer did not see whole (``incomplete_analysis``) is not sent and asks.
``allow`` is only ever emitted to Claude Code when the policy sets ``defaults.emit_allow``; by
default an allow is "no decision" and Claude Code's own permission flow continues.

Session state (M3a): UserPromptSubmit stores the task intent (only while an LLM audit is configured
and allowed to send it), PostToolUse marks a call of a taint source, and every PreToolUse is counted
and judged in its session's taint state (``session.store``; a call of a source marks the session
there too). Rules see that state through ``session_read_untrusted``; the taint step of
PROJECT_SPEC.md §7 turns an allow that no rule made of a sensitive action into an ask while the
session is tainted (the LLM's allows get the same step in ``audit.verdict``). Without a session
layer (``boundkeep test``, ``explain``, the rules-only evaluation) every call is judged as in a
fresh session.

M0's canary is a built-in rule of ``policy.evaluate``. If the policy file is unusable, PreToolUse
events are answered with ``ask`` (fail closed). A deny reason reads ``boundkeep (<rule-id>): ...``;
every reason shown or stored is sanitized (``_clean``): gray reasons carry text the agent wrote.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Protocol

from boundkeep import protocol
from boundkeep.audit.auditor import Auditor, AuditOutcome
from boundkeep.normalize import paths as norm_paths
from boundkeep.normalize.event import HARMLESS_TOOLS, normalize_event
from boundkeep.normalize.model import Action, Platform
from boundkeep.normalize.subtree import RuleGlob
from boundkeep.policy import Policy, Verdict, evaluate
from boundkeep.policy.glob import MAX_PATTERN_LENGTH
from boundkeep.policy.schema import (
    DEFAULT_TAINT_SOURCES,
    DEFAULT_TAINT_WINDOW,
    Rule,
    escape_glob_literal,
)
from boundkeep.session.facts import FRESH, SessionFacts
from boundkeep.session.intent import extract_intent

SHELL_TOOLS = frozenset({"Bash", "PowerShell"})
MODE_ENFORCE = "enforce"
MODE_AUDIT_ONLY = "audit-only"
MAX_REASON_PARTS = 4
PART_CHARS = 100  # one reason part (a rule's reason fits; attacker text is cut harder)
GRAY_PART_CHARS = 80  # gray reasons, program names: text the agent controls
MAX_REASON_CHARS = 600  # the whole reason shown to the user
HARMLESS_ID = "harmless-tool"  # the verdict of a tool that touches nothing (no rule needed)
TAINT_STEP_ID = "taint-step"  # an allow that no rule made, turned into an ask by the taint step


def local_platform() -> Platform:
    return "windows" if sys.platform == "win32" else "posix"


class SessionAccess(Protocol):
    """What the pipeline needs of a session store (``session.store.SessionStore`` and its
    stand-in ``UnavailableStore``)."""

    def tool_call(
        self,
        session_id: object,
        tool: object,
        *,
        sources: tuple[str, ...],
        window: int,
        intents: int = 0,
    ) -> SessionFacts: ...

    def tool_result(
        self, session_id: object, tool: object, *, sources: tuple[str, ...]
    ) -> bool: ...

    def add_prompt(self, session_id: object, text: str, *, keep: int) -> bool: ...


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
    taint: Mapping[str, Any] | None = None  # the session's taint state (when there is a store)
    llm: Mapping[str, Any] | None = None  # the LLM audit of a gray call (when one ran)


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

# X1 review of M1c-2 (H-6): a hard link to a protected file is the file under another name, so the
# rules that work on names miss every later write through it. Creating the link is refused with the
# protected globs (policies: deny-link-to-guard-files); the machine-dependent protections below get
# the same twin. Their globs are access-read globs that must NOT become "protected names" of a
# recursive read (a Grep over a directory that holds a settings file), hence the common prefix.
LINK_RULE_PREFIX = "deny-link-"
# Exact ids, not the prefix (X1 re-review R-9): a rule of the user's that merely starts with the
# prefix keeps its protection of recursive reads.
LINK_RULE_IDS = frozenset(
    {
        "deny-link-to-guard-files",
        "deny-link-copy-of-guard-files",
        f"{LINK_RULE_PREFIX}protect-guard-config-dir",
        f"{LINK_RULE_PREFIX}copy-protect-guard-config-dir",
        f"{LINK_RULE_PREFIX}protect-guard-code",
        f"{LINK_RULE_PREFIX}copy-protect-guard-code",
    }
)
_LINK_REASON = "a link to a protected file would let a later write change it"


def _link_twins(rule: Rule) -> tuple[Rule, ...]:
    """The two rules (``ln`` / ``New-Item``, ``cp -l``) that refuse to link to ``rule``'s paths."""
    globs = list(rule.match.path_glob or ())
    if not globs:
        return ()
    base = {"path_glob": globs, "access": "read"}
    return (
        Rule.model_validate(
            {
                "id": f"{LINK_RULE_PREFIX}{rule.id}",
                "match": {"program": ["ln", "New-Item"], **base},
                "action": "deny",
                "reason": _LINK_REASON,
            }
        ),
        Rule.model_validate(
            {
                "id": f"{LINK_RULE_PREFIX}copy-{rule.id}",
                "match": {"program": ["cp"], "flags_any": ["-l", "--link"], **base},
                "action": "deny",
                "reason": _LINK_REASON,
            }
        ),
    )


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


_GUARD_CODE_RULE_ID = "protect-guard-code"
_GUARD_DIRS_RULE_ID = "protect-guard-dirs"


def _guard_key(path: object) -> str | None:
    """The canonical key of an absolute, certain path (None for anything else)."""
    if not isinstance(path, str) or not path or "\x00" in path:
        return None
    norm = norm_paths.normalize_path(path, cwd=None, home=None, dialect="tool", literal=True)
    if not norm.absolute or norm.uncertain or norm.is_device or not norm.key:
        return None
    return norm.key


def _guard_globs(key: str, *, tree: bool) -> str | None:
    """``key`` as a literal glob (``/**`` appended for a whole tree); None when it is unusable."""
    base = escape_glob_literal(key).rstrip("/")
    glob = f"{base}/**" if tree else base
    if not base or len(glob) > MAX_PATTERN_LENGTH:
        return None
    return glob


def _installed_paths() -> tuple[list[str], list[str], list[str]]:
    """(directories to protect as trees, files to protect, the boundkeep home) of this install.

    Everything the gate runs from: the package directory (its modules, the hook scripts and the
    default policy file inside it) and, in a source checkout, the policies directory; the
    interpreter that runs the daemon, the base interpreter, the ``boundkeep-hook`` launcher and
    whatever ``init`` recorded in ``installs.json`` (the hook command and its script); the home
    directory with the policy, the endpoint and the audit log. Nothing here raises.
    """
    import boundkeep
    from boundkeep import hookcmd, install
    from boundkeep import paths as bk_paths

    trees: list[str] = []
    files: list[str] = []
    homes: list[str] = []
    package = os.path.dirname(os.path.abspath(boundkeep.__file__))
    trees.append(package)
    trees.append(os.path.realpath(package))
    checkout = os.path.dirname(os.path.dirname(package))
    if os.path.isfile(os.path.join(checkout, "pyproject.toml")):
        policies = os.path.join(checkout, "policies")
        if os.path.isdir(policies):
            trees.append(policies)
    for script in ("hook_client.py", "hook_main.py"):
        files.append(os.path.join(package, script))
    for interpreter in (sys.executable, getattr(sys, "_base_executable", None)):
        if isinstance(interpreter, str) and interpreter:
            files.append(os.path.abspath(interpreter))
            files.append(os.path.realpath(interpreter))
    files.append(hookcmd.launcher_path())
    homes.append(bk_paths.home_dir())
    try:
        records = install.load_manifest(bk_paths.manifest_file())
    except Exception:  # noqa: BLE001 - a missing or corrupt manifest only means fewer paths
        records = []
    for record in records:
        files.append(record.hook_command)
        files.extend(arg for arg in record.hook_args if arg.lower().endswith(".py"))
        for index, arg in enumerate(record.hook_args[:-1]):
            if arg == "--home":
                homes.append(record.hook_args[index + 1])
    return trees, files, homes


def _guard_rules(env: Mapping[str, str], home: str | None) -> tuple[tuple[Rule, ...], list[str]]:
    """The rules that protect what the gate itself runs from, and problems that left holes.

    * ``protect-guard-code``: no write (``unknown`` access counts) to the installed package, the
      hook scripts, the policy source files, the interpreters, the ``boundkeep-hook`` launcher or
      boundkeep's home. Without it a ``Set-Content hook_main.py`` is only a question.
    * ``protect-guard-dirs``: no write to the DIRECTORIES ``.claude`` (any depth: the project's and
      the user's), ``.boundkeep``, boundkeep's home or ``CLAUDE_CONFIG_DIR`` themselves: the rules
      on ``.claude/settings*.json`` guard the files, but renaming, moving or deleting the
      directory (``Rename-Item ~\\.claude x``, ``robocopy <empty> .claude /mir``) removes them
      all at once.
    """
    problems: list[str] = []
    trees, files, homes = _installed_paths()
    code: dict[str, None] = {}
    for path in trees:
        key = _guard_key(path)
        glob = _guard_globs(key, tree=True) if key else None
        if glob is None:
            if path == trees[0]:
                problems.append("the boundkeep package directory cannot be protected by a rule")
            continue
        code[glob] = None
    for path in files:
        key = _guard_key(path)
        glob = _guard_globs(key, tree=False) if key else None
        if glob is not None:
            code[glob] = None
    dirs: dict[str, None] = {"**/.claude": None, "**/.boundkeep": None}
    for path in homes:
        key = _guard_key(path)
        glob = _guard_globs(key, tree=True) if key else None
        if glob is not None:
            code[glob] = None
        glob = _guard_globs(key, tree=False) if key else None
        if glob is not None:
            dirs[glob] = None
    config_dir = env.get("CLAUDE_CONFIG_DIR")
    if isinstance(config_dir, str) and config_dir:
        norm = norm_paths.normalize_path(config_dir, cwd=None, home=home, env=env, dialect="tool")
        glob = _guard_globs(norm.key, tree=False) if norm.absolute else None
        if glob is not None and not [r for r in norm.reasons if r != "glob"]:
            dirs[glob] = None
    rules: list[Rule] = []
    if code:
        rules.append(
            Rule.model_validate(
                {
                    "id": _GUARD_CODE_RULE_ID,
                    "match": {"path_glob": list(code), "access": "write"},
                    "action": "deny",
                    "reason": "do not modify boundkeep's code, interpreter or home directory",
                }
            )
        )
    rules.append(
        Rule.model_validate(
            {
                "id": _GUARD_DIRS_RULE_ID,
                "match": {"path_glob": list(dirs), "access": "write"},
                "action": "deny",
                "reason": "do not move, rename or delete a Claude Code or boundkeep directory",
            }
        )
    )
    return tuple(rules), problems


def runtime_policy_checked(
    policy: Policy, env: Mapping[str, str], home: str | None
) -> tuple[Policy, str | None]:
    """``policy`` plus rules that depend on this machine, and an error text if some are missing.

    ``protect-guard-config`` names ``~/.claude``, but ``CLAUDE_CONFIG_DIR`` can move it; when it
    is set, that directory's settings files get the same write protection and its credentials and
    transcripts a read denial (glob characters in the name are escaped). Independently of it,
    ``_guard_rules`` protects the installed code, the interpreter and the guarded directories.
    NEVER raises: when the rules cannot be built (a relative or unresolvable directory, one
    longer than a glob may be, any unexpected error) the policy comes back with what could be
    built together with a short, printable message, so the caller can log it and keep serving
    with a policy it knows is incomplete, instead of failing the reload and silently keeping an
    OLDER policy. ``(policy, None)`` means there was nothing to add; an extended policy with
    ``None`` that everything was added.
    """
    built: list[Rule] = []
    problems: list[str] = []
    try:
        built.extend(_config_dir_rules(env, home))
    except _RuntimeRuleSkipped as exc:
        problems.append(str(exc))
    except Exception as exc:  # noqa: BLE001 - this must never take the daemon's reload down
        problems.append(
            "CLAUDE_CONFIG_DIR: the runtime rules could not be built "
            f"({_clean(type(exc).__name__, 40)}); its settings are not protected by them"
        )
    try:
        guard, guard_problems = _guard_rules(env, home)
        built.extend(guard)
        problems.extend(guard_problems)
    except Exception as exc:  # noqa: BLE001 - never raises
        problems.append(
            "the runtime rules that protect boundkeep's own code could not be built "
            f"({_clean(type(exc).__name__, 40)})"
        )
    for rule in tuple(built):
        if rule.id in (_CONFIG_DIR_RULE_ID, _GUARD_CODE_RULE_ID):
            built.extend(_link_twins(rule))
    rules = tuple(r for r in built if not any(existing.id == r.id for existing in policy.rules))
    error = _clean("; ".join(problems), 400) if problems else None
    if not rules:
        return policy, error
    return policy.model_copy(update={"rules": (*rules, *policy.rules)}), error


def runtime_policy(policy: Policy, env: Mapping[str, str], home: str | None) -> Policy:
    """``runtime_policy_checked`` without the error text (never raises)."""
    return runtime_policy_checked(policy, env, home)[0]


def protected_read_globs(policy: Policy) -> tuple[str, ...]:
    """Every path glob of a deny or ask rule that can fire on a READ (access read or unspecified).

    The normalizer checks the subtree of a directory that a command reads recursively (Grep on a
    project, ``grep -r``, ``tar c``) against these, so a protected file inside it becomes a read
    path of the action and the rules above decide on it. Rules are taken whatever their ``tool``
    filter says: a few extra paths cost nothing, a missing one is a bypass.
    """
    out: dict[str, None] = {}
    for rule in policy.rules:
        match = rule.match
        if rule.action == "allow" or match.path_glob is None:
            continue
        if match.access is not None and match.access != "read":
            continue
        if rule.id in LINK_RULE_IDS:
            continue  # names the target of a link being CREATED; reading the file is another rule
        out.update(dict.fromkeys(match.path_glob))
    return tuple(out)


def rule_path_globs(policy: Policy) -> tuple[RuleGlob, ...]:
    """Every path glob of a deny or ask rule (write rules included), with the programs and the
    access of its rule.

    The normalizer uses them, once its budget has run out, to leave out of the verdict's work the
    paths inside the project that no such rule can select (``cat f1 f2 ... f9000``): an allow rule
    never decides there, the line already carries a gray budget marker. Rules are taken whatever
    their ``tool`` filter says (a missing path is a bypass, an extra one costs nothing).
    """
    out: dict[RuleGlob, None] = {}
    for rule in policy.rules:
        match = rule.match
        if rule.action == "allow" or match.path_glob is None:
            continue
        programs = tuple(match.program) if match.program is not None else None
        for pattern in match.path_glob:
            out[RuleGlob(pattern, programs, match.access)] = None
    return tuple(out)


def sensitive_action(actions: tuple[Action, ...] | list[Action], policy: Policy) -> bool:
    """Some action of the call carries one of ``taint.sensitive_tags``."""
    wanted = set(policy.taint.sensitive_tags)
    return any(tag in wanted for action in actions for tag in action.risk_tags)


def taint_step(
    verdict: Verdict, actions: tuple[Action, ...], session: SessionFacts, policy: Policy
) -> Verdict:
    """PROJECT_SPEC.md §7: while the session is tainted, an allow that no rule made (a tool that
    touches nothing) of an action with a sensitive tag becomes an ask. A rule's allow stays; the
    LLM's allows get the same step in ``audit.verdict``."""
    if (
        verdict.decision != "allow"
        or verdict.rule_ids != (HARMLESS_ID,)
        or not session.tainted
        or not sensitive_action(actions, policy)
    ):
        return verdict
    sources = ", ".join(session.sources[:3]) or "a source whose name is not known"
    return Verdict(
        "ask",
        (f"the session recently read untrusted content ({sources}) and this action is sensitive",),
        (TAINT_STEP_ID,),
        verdict.actions,
    )


def review(
    payload: Mapping[str, Any],
    policy: Policy,
    *,
    platform: Platform | None = None,
    env: Mapping[str, str] | None = None,
    home: str | None = None,
    scan_disk: bool = True,
    session: SessionFacts = FRESH,
) -> Review:
    """Normalize ``payload`` and evaluate ``policy`` on it in the taint state ``session`` (never
    raises). The taint step is applied; the LLM audit of a gray outcome is not (``decide``).

    ``scan_disk`` False turns off the look into the subtree of a directory that is read
    recursively (Grep on a directory, ``grep -r`` ...). It is for fake machines (``boundkeep test``
    runs the policy's tests on made-up home and project paths): there the real disk behind a
    made-up path must not decide the verdict.
    """
    platform = platform or local_platform()
    env = env if env is not None else os.environ
    actions = tuple(
        normalize_event(
            payload,
            platform=platform,
            env=env,
            home=home,
            protected_globs=protected_read_globs(policy) if scan_disk else (),
            rule_globs=rule_path_globs(policy),
        )
    )
    verdict = evaluate(policy, actions, platform=platform, session=session)
    tool = payload.get("tool_name")
    if verdict.decision == "gray" and isinstance(tool, str) and tool in HARMLESS_TOOLS:
        # Tools that touch nothing on the machine need no rule; they are never gray.
        verdict = Verdict("allow", (), (HARMLESS_ID,), verdict.actions)
    return Review(actions, taint_step(verdict, actions, session, policy))


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
    if verdict.rule_ids == (TAINT_STEP_ID,):
        by = "taint"
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


def _from_audit(outcome: AuditOutcome, policy: Policy) -> tuple[str, str, str]:
    """(protocol decision, reason, decided_by) for the code's ruling on an LLM audit."""
    reason = _clean(outcome.reason, MAX_REASON_CHARS)
    if outcome.final == "deny":
        return protocol.DECISION_DENY, reason, outcome.decided_by
    if outcome.final == "ask":
        return protocol.DECISION_ASK, reason, outcome.decided_by
    if policy.defaults.emit_allow:
        return protocol.DECISION_ALLOW, reason, outcome.decided_by
    return protocol.DECISION_NONE, "", outcome.decided_by


_UNANALYSED_PREFIXES: Final = (
    "budget:",
    "normalize-budget",
    "recursive-scan-",
    "internal-error",
    "classify-internal-error",
    "ps-internal-error",
    "ps-helper-",
    "ps-too-large",
    "mcp-arguments-not-all-seen",
    "mcp-command",
)


def incomplete_analysis(actions: Sequence[Action]) -> str | None:
    """Why the normalizer did not see the whole call (a budget ran out, a parser failed, a part
    was left out), or None. Such a call is not sent to the LLM audit: the model would be shown
    part of it, or nothing at all, and its allow would cover what nobody looked at."""
    for action in actions:
        for reason in action.gray_reasons:
            if reason.startswith(_UNANALYSED_PREFIXES):
                return _clean(reason, GRAY_PART_CHARS)
    if not any(a.program or a.paths or a.domains or a.mcp_tool for a in actions):
        return "nothing of the call was understood"
    return None


def taint_record(facts: SessionFacts) -> dict[str, Any]:
    """The session's taint state as it goes into the audit log (names of source tools only)."""
    record: dict[str, Any] = {"tainted": facts.tainted, "read_untrusted": facts.read_untrusted}
    if not facts.known:
        record["state"] = "unknown"
    if facts.sources:
        record["sources"] = [_clean(s, GRAY_PART_CHARS) for s in facts.sources[:4]]
    if facts.calls_since_taint is not None:
        record["calls_since_taint"] = facts.calls_since_taint
    return record


def _finish(
    result: Review,
    mode: str,
    policy: Policy,
    *,
    facts: SessionFacts = FRESH,
    auditor: Auditor | None = None,
    tool: object = None,
    home: str | None = None,
    env: Mapping[str, str] | None = None,
    taint: Mapping[str, Any] | None = None,
) -> Decision:
    decision, reason, decided_by = _from_verdict(result.verdict, policy)
    llm: Mapping[str, Any] | None = None
    if result.verdict.decision == "gray" and auditor is not None:
        unseen = incomplete_analysis(result.actions)
        if unseen is not None:
            # the model would judge a part of the call: it stays the user's question
            reason = (
                f"boundkeep: no rule decides this action and it was not fully analysed ({unseen}); "
                "asking (not sent to the LLM audit)"
            )
            decided_by = "gray-unanalysed"
            llm = {"backend": policy.llm_audit.backend, "outcome": "not-sent", "detail": unseen}
        else:
            outcome = auditor.review(
                result.actions,
                tool=tool,
                facts=facts,
                sensitive_tags=policy.taint.sensitive_tags,
                home=home,
                env=env,
            )
            decision, reason, decided_by = _from_audit(outcome, policy)
            llm = outcome.record
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
        "taint": taint,
        "llm": llm,
    }
    if mode == MODE_AUDIT_ONLY:
        would = decision if decision != protocol.DECISION_NONE else None
        return Decision(protocol.DECISION_NONE, "", "audit-only", would_be=would, **common)
    return Decision(decision, reason, decided_by, **common)


def taint_settings(policy: Policy | None) -> tuple[tuple[str, ...], int]:
    """The taint sources and window to count with; the defaults when the policy is unusable (a
    broken policy must not stop the marking: the calls still happen once the user approves)."""
    if policy is None:
        return DEFAULT_TAINT_SOURCES, DEFAULT_TAINT_WINDOW
    return policy.taint.sources, policy.taint.window


def _note_prompt(
    payload: Mapping[str, Any], policy: Policy | None, session: SessionAccess | None
) -> None:
    """Store the task intent, only while an LLM audit is configured and may send it."""
    if session is None or policy is None:
        return
    llm = policy.llm_audit
    if llm.backend == "none" or not llm.send_task_intent:
        return
    text = extract_intent(payload.get("prompt"), llm.intent_chars)
    if text:
        session.add_prompt(payload.get("session_id"), text, keep=llm.intent_prompts)


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
    scan_disk: bool = True,
    session: SessionAccess | None = None,
    auditor: Auditor | None = None,
) -> Decision:
    """The decision for one event. ``session`` None: no session layer (every call is judged as
    in a fresh session, nothing is recorded). ``auditor`` None: gray calls ask."""
    sources, window = taint_settings(policy)
    if event == protocol.EVENT_PROMPT:
        _note_prompt(payload, policy, session)
        return Decision(protocol.DECISION_NONE, "", "no-decision-for-event")
    if event == protocol.EVENT_POST:
        if session is not None:
            session.tool_result(
                payload.get("session_id"), payload.get("tool_name"), sources=sources
            )
        return Decision(protocol.DECISION_NONE, "", "no-decision-for-event")
    if event != protocol.EVENT_PRE:
        return Decision(protocol.DECISION_NONE, "", "no-decision-for-event")
    facts = FRESH
    taint: Mapping[str, Any] | None = None
    if session is not None:
        # counted (and a source call marked) before anything else, also when the policy is broken
        facts = session.tool_call(
            payload.get("session_id"),
            payload.get("tool_name"),
            sources=sources,
            window=window,
            intents=auditor.wants_intents if auditor is not None else 0,
        )
        taint = taint_record(facts)
    if policy_error is not None or policy is None:
        return Decision(
            protocol.DECISION_ASK,
            f"boundkeep: the policy file is not usable ({_clean(policy_error, 200)}); "
            "fix it or run 'boundkeep doctor'",
            "policy-invalid",
            taint=taint,
        )
    result = review(
        payload,
        policy,
        platform=platform,
        env=env,
        home=home,
        scan_disk=scan_disk,
        session=facts,
    )
    return _finish(
        result,
        mode,
        policy,
        facts=facts,
        auditor=auditor if policy.llm_audit.backend != "none" else None,
        tool=payload.get("tool_name"),
        home=home,
        env=env,
        taint=taint,
    )
