"""The decision pipeline: normalize -> rules (with the session's taint state) -> taint step ->
LLM audit of gray calls (optional) -> the code's ruling -> hook decision.

A PreToolUse payload becomes a list of ``Action`` (one per simple command of a shell line, one for
other tools); the policy rules are evaluated per action and merged strictest-first (deny > ask >
gray > allow). With no LLM backend a gray outcome is an ``ask``; with one, ``audit.auditor`` asks
the model and ``audit.verdict`` rules on its answer (any failure: ``llm_audit.on_failure``). A gray
call the normalizer did not see whole (``incomplete_analysis``), with code or arguments the
request cannot show (``unshown_input``), or that touches a Windows device (``device_path``), is not
sent and asks.
``allow`` is only ever emitted to Claude Code when the policy sets ``defaults.emit_allow``; by
default an allow is "no decision" and Claude Code's own permission flow continues.

Session state (M3a): UserPromptSubmit stores the task intent (only while an LLM audit is configured
and allowed to send it), PostToolUse marks a call of a taint source, and every PreToolUse is counted
and judged in its session's taint state (``session.store``; a call of a source marks the session
there too; a shell call that reads remote text, ``session.sources``, is a source at both events;
revision 8, P-R5). Rules see that state through ``session_read_untrusted``; the taint step of
PROJECT_SPEC.md §7 turns an allow that no rule made of a sensitive action into an ask while the
session is tainted (the LLM's allows get the same step in ``audit.verdict``), and each such ask uses
up one call of the taint window once its tool ran: the PostToolUse of the same ``tool_use_id``
(revision 7, P-F6; revision 8, P-R3). A call of a session that read untrusted content marks the
places it may write (``session.marks``; P-F1, P-R6, P-R7), which every session's rules see through
``project_written_after_untrusted``; a gray call that runs code in such a project is not sent to
the LLM (P-R2). SessionStart of a resumed, compacted or forked session the store does not know
starts it as having read untrusted content (P-R9), and so does any call of a session the store does
not know where every install registers that hook (revision 9, P-S1). Without a session layer
(``boundkeep test``, ``explain``, the rules-only evaluation) every call is judged as in a fresh
session.

M0's canary is a built-in rule of ``policy.evaluate``. If the policy file is unusable, PreToolUse
events are answered with ``ask`` (fail closed). A deny reason reads ``boundkeep (<rule-id>): ...``;
every reason shown or stored is sanitized (``_clean``): gray reasons carry text the agent wrote.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Protocol

from boundkeep import protocol
from boundkeep.audit.auditor import Auditor, AuditOutcome
from boundkeep.normalize import paths as norm_paths
from boundkeep.normalize.event import HARMLESS_TOOLS, normalize_event
from boundkeep.normalize.model import Action, PathRef, Platform
from boundkeep.normalize.subtree import RuleGlob
from boundkeep.policy import Policy, Verdict, evaluate
from boundkeep.policy.glob import MAX_PATTERN_LENGTH
from boundkeep.policy.schema import (
    DEFAULT_TAINT_SOURCES,
    DEFAULT_TAINT_WINDOW,
    Rule,
    escape_glob_literal,
)
from boundkeep.session.facts import (
    FRESH,
    NO_SESSION_START_SOURCE,
    SessionFacts,
    is_taint_source,
)
from boundkeep.session.intent import extract_intent
from boundkeep.session.marks import marked, written_places
from boundkeep.session.sources import NETWORK_SOURCE_PREFIX, network_source

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
        unknown_inherited: bool = False,
    ) -> SessionFacts: ...

    def tool_result(
        self,
        session_id: object,
        tool: object,
        *,
        sources: tuple[str, ...],
        tool_use_id: object = None,
    ) -> bool: ...

    def source_seen(self, session_id: object, name: str) -> bool: ...

    def session_start(self, session_id: object, source: object) -> bool: ...

    def taint_asked(self, session_id: object, tool_use_id: object = None) -> bool: ...

    def mark_written(
        self,
        locations: Iterable[str],
        *,
        sources: Iterable[str] = (),
        kinds: Mapping[str, Iterable[str]] | None = None,
    ) -> bool: ...

    def add_prompt(
        self, session_id: object, text: str, *, keep: int, unknown_inherited: bool = False
    ) -> bool: ...


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


# Gray reasons for text the request cannot show: a string piped into PowerShell's interpreter is its
# code, an assignment (``$env:NODE_OPTIONS = ...``) is not an action with words of its own, and the
# request names a program as folded, so ``sed`` with U+017F for its "s" would read as plain ``sed``,
# and ``BOUNDK~1`` found by Git Bash's PATH, or by a path the disk layer cannot expand, says
# nothing of the program it is (spec revisions 18 and 19). The request lists commands with their
# arguments, so a PowerShell expression or statement that is in no command's arguments is not in
# it: ``git status; [IO.File]::ReadAllText('.env')`` (``pscmd.OUTSIDE_COMMAND_GRAY``, revision 21).
# Nor is the computed value of a switch (``-Force:(...)``), the value of an option of ``uv run``
# and the other runners (``uv run --env-file .env pytest``, both dialects, revision 25) or a
# word a Bash wrapper took (``sudo -u root pytest``, ``timeout 60 pytest``, revision 26): the
# normalizer drops those words.
_UNSHOWN_REASONS: Final = (
    "ps-pipe-to-interpreter",
    "ps-compound:AssignmentStatementAst",
    "ps-outside-command",
    "ps-switch-value",
    "ps-runner-value",
    "runner-option-value",
    "wrapper-option-value",
    "program-fold-variant",
    "program-short-name-unresolved",
)


def unshown_input(actions: Sequence[Action]) -> str | None:
    """What of the call the request to the LLM audit cannot carry, or None (X1 review of M3a, F3
    and F4). The send gate shows each command's words, paths and hosts, never a here-document or
    here-string (the code of ``python3 <<EOF``, the SQL of ``psql``), the value of a ``NAME=value``
    assignment (``NODE_OPTIONS``, ``DATABASE_URL``), a string piped into an interpreter or assigned
    in PowerShell, or the arguments of an MCP call. The model would allow what it was not shown,
    so such a call is not sent either, like one the normalizer did not see whole."""
    for action in actions:
        if action.unshown:
            return _clean(", ".join(action.unshown[:3]), GRAY_PART_CHARS)
        for reason in action.gray_reasons:
            if reason.startswith(_UNSHOWN_REASONS):
                return _clean(reason, GRAY_PART_CHARS)
        if action.tool.startswith("mcp__"):
            return "the arguments of an MCP call"
    return None


# NUL discards what is written and reads empty, and ``2>NUL`` is everywhere in shell commands. Only
# the bare name and a prefix with nothing else: with a directory or a drive, what is there may be an
# ordinary file named nul, and the model and the cache could not tell (the key is ``//./nul`` for
# all). The bare name at worst is such a file in the working directory. Read from the text as
# written, so a variable, a wildcard or anything added later is not exempt.
_REALLY_NUL: Final = re.compile(r"(?:\\\\[.?]\\|\\\?\?\\|//[.?]/)nul|nul[. ]*", re.IGNORECASE)
# Not files: the key cannot say what listens there, whichever server it names
_IPC_SHARE: Final = re.compile(r"//[^/]+/(?:pipe|mailslot|ipc\$)(?:/|$)")


def device_path(actions: Sequence[Action]) -> bool:
    """A path in the Windows device namespace, NUL aside (revisions 10, 11). Its key does not say
    where it leads: ``//./globalroot/device/mup/srv/share/x`` is a network share, ``//./pipe/x``
    and ``//localhost/pipe/x`` whatever listens there, ``//./c:`` a whole volume, ``//./aux`` maybe
    ``C:\\proj\\aux.py``. The model would be allowing a string, so such a call is not sent. The
    rules have already run: ``no-raw-disk-access`` still denies."""

    def counts(action: Action, ref: PathRef) -> bool:
        if ref.key.startswith("//./"):
            return not (action.shell is not None and _REALLY_NUL.fullmatch(ref.raw))
        return ref.flavor == "windows" and _IPC_SHARE.match(ref.key) is not None

    return any(counts(action, ref) for action in actions for ref in action.paths)


def runs_in_marked_project(actions: Sequence[Action], facts: SessionFacts) -> bool:
    """An action that runs code (``exec``) is in a project with a mark, read as the rule field
    ``project_written_after_untrusted`` reads it (marks that could not be read count). Such a
    gray call is not sent to the LLM audit (revision 8, P-R2)."""
    if facts.marks_known and not facts.marks:
        return False
    return any(
        "exec" in action.risk_tags
        and (not facts.marks_known or marked(action.project, action.project_resolved, facts.marks))
        for action in actions
    )


def taint_record(facts: SessionFacts) -> dict[str, Any]:
    """The session's taint state as it goes into the audit log (names of source tools only)."""
    record: dict[str, Any] = {"tainted": facts.tainted, "read_untrusted": facts.read_untrusted}
    if not facts.known:
        record["state"] = "unknown"
    if facts.sources:
        record["sources"] = [_clean(s, GRAY_PART_CHARS) for s in facts.sources[:4]]
    if facts.taint_asks is not None:
        record["taint_asks"] = facts.taint_asks
    if facts.marks:
        record["marked_places"] = len(facts.marks)
    elif not facts.marks_known:
        record["marks"] = "unknown"
    return record


def used_taint_window(result: Review, decision: Decision) -> bool:
    """The taint step turned this call's allow into an ask: the pipeline's own step (a tool that
    touches nothing) or §9.5's line on the LLM's allow (revision 7, P-F6)."""
    if result.verdict.rule_ids == (TAINT_STEP_ID,):
        return True
    steps = decision.llm.get("steps") if decision.llm is not None else None
    return isinstance(steps, (list, tuple)) and "tainted-sensitive" in steps


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
    if (
        result.verdict.decision == "gray"
        and auditor is not None
        and runs_in_marked_project(result.actions, facts)
    ):
        # P-R2: the dev-tool rule only names its tools; other commands that run the project's
        # code (npm test, make test) would be the model's to allow in a session that read nothing
        reason = (
            "boundkeep: no rule decides this action, it runs code in a project that a session "
            "wrote after reading untrusted content; asking (not sent to the LLM audit; the user "
            "can clear the mark with 'boundkeep taint clear')"
        )
        decided_by = "gray-marked-project"
        llm = {"backend": policy.llm_audit.backend, "outcome": "not-sent", "detail": "marked"}
    elif result.verdict.decision == "gray" and auditor is not None:
        unseen = incomplete_analysis(result.actions)
        hidden = unshown_input(result.actions) if unseen is None else None
        if unseen is not None or hidden is not None:
            # the model would judge a part of the call: it stays the user's question
            why = (
                f"it was not fully analysed ({unseen})"
                if unseen is not None
                else f"the LLM audit could not be shown all of it ({hidden})"
            )
            reason = (
                f"boundkeep: no rule decides this action and {why}; "
                "asking (not sent to the LLM audit)"
            )
            decided_by = "gray-unanalysed"
            llm = {
                "backend": policy.llm_audit.backend,
                "outcome": "not-sent",
                "detail": unseen if unseen is not None else hidden,
            }
        elif device_path(result.actions):
            # No path in the reason or the record: they go into the audit log
            reason = (
                "boundkeep: no rule decides this action and it touches a Windows device path, "
                "which the LLM audit could not judge; asking (not sent to the LLM audit)"
            )
            decided_by = "gray-device-path"
            llm = {
                "backend": policy.llm_audit.backend,
                "outcome": "not-sent",
                "detail": "device-path",
            }
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
    payload: Mapping[str, Any],
    policy: Policy | None,
    session: SessionAccess | None,
    *,
    unknown_inherited: bool,
) -> None:
    """Store the task intent, only while an LLM audit is configured and may send it."""
    if session is None or policy is None:
        return
    llm = policy.llm_audit
    if llm.backend == "none" or not llm.send_task_intent:
        return
    text = extract_intent(payload.get("prompt"), llm.intent_chars)
    if text:
        session.add_prompt(
            payload.get("session_id"),
            text,
            keep=llm.intent_prompts,
            unknown_inherited=unknown_inherited,
        )


def _note_shell_result(
    payload: Mapping[str, Any],
    session: SessionAccess,
    *,
    platform: Platform | None,
    env: Mapping[str, str] | None,
    home: str | None,
) -> None:
    """A shell call that reads remote text is marked at its PostToolUse too, like a source tool: its
    PreToolUse may never have reached the daemon (second re-review of M3a, S-3). The call ran, so
    no verdict matters here, and only the programs do: no look into directories. Only reaches the
    daemon where the matcher is ``*`` (``policy.loader.post_matcher_for``: an LLM backend)."""
    if not shell_command(payload):
        return
    actions = normalize_event(
        payload,
        platform=platform or local_platform(),
        env=env if env is not None else os.environ,
        home=home,
        protected_globs=(),
    )
    network = network_source(actions)
    if network is not None:
        session.source_seen(payload.get("session_id"), f"{NETWORK_SOURCE_PREFIX}{network}")


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
    session_start_expected: bool = False,
) -> Decision:
    """The decision for one event. ``session`` None: no session layer (every call is judged as
    in a fresh session, nothing is recorded). ``auditor`` None: gray calls ask.
    ``session_start_expected``: every install registers SessionStart, so a session the store does
    not know missed it (revision 9, P-S1)."""
    sources, window = taint_settings(policy)
    if event == protocol.EVENT_PROMPT:
        _note_prompt(payload, policy, session, unknown_inherited=session_start_expected)
        return Decision(protocol.DECISION_NONE, "", "no-decision-for-event")
    if event == protocol.EVENT_POST:
        if session is not None:
            session.tool_result(
                payload.get("session_id"),
                payload.get("tool_name"),
                sources=sources,
                tool_use_id=payload.get("tool_use_id"),
            )
            _note_shell_result(payload, session, platform=platform, env=env, home=home)
        return Decision(protocol.DECISION_NONE, "", "no-decision-for-event")
    if event == protocol.EVENT_SESSION:
        if session is not None:
            session.session_start(payload.get("session_id"), payload.get("source"))
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
            unknown_inherited=session_start_expected,
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
    tool = payload.get("tool_name")
    # P-R5: a shell call that reads remote text is a source by what it does (not when it is denied)
    network = network_source(result.actions) if result.verdict.decision != "deny" else None
    new_sources = [f"{NETWORK_SOURCE_PREFIX}{network}"] if network is not None else []
    if isinstance(tool, str) and is_taint_source(tool, sources):
        new_sources.append(tool)
    # P-S7: a call a rule denies never runs (in audit-only mode it does). P-S1: a session whose only
    # source is a missed SessionStart asks itself but leaves no mark: that the daemon started late
    # must not become a state of the project.
    denied = mode == MODE_ENFORCE and result.verdict.decision == "deny"
    read_it = facts.read_untrusted and facts.sources != (NO_SESSION_START_SOURCE,)
    if session is not None and not denied and (read_it or new_sources):
        # P-F1: what this session writes stays in the project after the session (marked at
        # PreToolUse like a source call: a write that is then refused is the safe direction).
        # A source call is judged in the state before it but marks in the state after it, so its
        # own write counts (revision 8, P-R6).
        decisions = {v.index: v.decision for v in result.verdict.actions}
        places = written_places(
            result.actions, tuple(decisions.get(i) for i in range(len(result.actions)))
        )
        if places:
            session.mark_written(places, sources=(*facts.sources, *new_sources), kinds=places)
    decision = _finish(
        result,
        mode,
        policy,
        facts=facts,
        auditor=auditor if policy.llm_audit.backend != "none" else None,
        tool=tool,
        home=home,
        env=env,
        taint=taint,
    )
    if session is not None and mode == MODE_ENFORCE and used_taint_window(result, decision):
        # P-F6: only an ask the user actually gets uses up the window (audit-only asks nobody);
        # P-R3: and only once its tool ran, when the PostToolUse of this tool_use_id arrives
        session.taint_asked(payload.get("session_id"), payload.get("tool_use_id"))
    if session is not None and network is not None and decision.decision != protocol.DECISION_DENY:
        # after the verdict: an LLM deny stops the call too (in audit-only mode it runs)
        session.source_seen(payload.get("session_id"), new_sources[0])
    return decision
