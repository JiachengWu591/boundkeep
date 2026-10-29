"""Rule matching and verdict merging: pure functions, no I/O, no environment.

The contract is docs/m1-design.md ("模块 D"); the short version:

* A rule matches an ``Action`` when its ``tool`` and ``platform`` filters pass and EVERY ``match``
  field matches (AND across fields; a list inside a field is an OR).
* ``program`` / ``subcommand`` / ``flags_any`` compare exactly; for PowerShell actions the
  comparison ignores case (flags: only cmdlet parameters and ``/switches``; an external
  program's short flags stay case-sensitive). ``path_glob`` runs over ``PathRef.key`` (both
  sides casefolded) and, when ``access`` is given, only over paths whose access equals it or is
  ``unknown`` ("may read, may write" counts as a match).
* ``path_glob`` (+ ``access``) and ``path_outside_project`` must hold for the SAME path: one path
  matches a glob, is access-compatible and is not definitely inside. Without a glob,
  ``path_outside_project`` matches when ANY path is not definitely inside. ``path_inside_project``
  needs at least one path and ALL of them definitely inside (with a glob, one of them must also
  match it).
* ``path_in_scratchpad`` needs at least one path and ALL of them (every form of a path: the lexical
  one and the on-disk resolved one) inside the current session's scratchpad
  (``PathRef.in_scratchpad``, set by the normalizer; False whenever unsure). It combines with the
  other fields by AND and is checked like ``path_inside_project``: unknown is "no match".
  ``path_in_session_tool_results`` is the same for the current session's tool-results directory
  (``PathRef.in_session_tool_results``).
* ``except_session_tool_results`` qualifies ``path_glob`` like ``access``: the glob is not checked
  against a path (a form of it) shown to be in the current session's tool-results directory. Each
  form counts on its own, so a link there that resolves elsewhere is still checked by its target.
* ``flags_none`` takes the same entries and the same case folding as ``flags_any`` and matches
  only if NONE of the action's flags equals a listed one (no flags: matches).
  ``paths_read_only`` matches only if EVERY path has access exactly ``read`` (``write`` and
  ``unknown`` do not count; no paths: matches, since ``pwd`` or ``echo hi`` touch nothing).
* ``project_trusted`` matches only if the action's project directory (``Action.project``, and
  ``Action.project_resolved`` when set: both must qualify) is the same as, or inside, one of the
  policy's ``trusted_projects`` (canonical keys), compared on whole path segments (``/a/proj2`` is
  not inside ``/a/proj``), casefolded for Windows-flavor keys and exact for POSIX ones; a key of
  the other flavor never matches. An unknown, unusable or too-broad project directory is "not
  trusted" for an allow rule and "matches" for a deny / ask rule (the usual direction).
* ``network`` is ``Action.network``; ``domain_not_in`` needs ``network`` and (no known domain or
  ANY domain outside the list); ``domain_in`` needs ``network`` and at least one domain and ALL
  of them in the list. Host comparison is exact or a true subdomain (``evilgithub.com`` and
  ``github.com.evil.com`` are not ``github.com``).
* A gray ``Action`` never matches an allow rule, and neither does an ``Action`` with ``wrappers``
  (``sudo ls``, ``env X=1 ls``: a different action than ``ls``); deny and ask rules still match
  the known parts of both.

Merging is strictest-wins: per action deny > ask > allow, no hit = gray; overall any deny, else
any ask, else any gray (an ``Action.gray`` included), and only an all-allow list allows. An empty
list is gray. The built-in ``m0-canary`` rule is evaluated before every YAML rule and is not
part of the policy file.

Direction of every fallback: when something unexpected happens while evaluating a deny or ask
rule, the rule counts as matched; an allow rule counts as not matched. A key longer than the glob
limit is treated the same way.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from boundkeep.normalize.domains import canonical_host, host_matches
from boundkeep.normalize.model import Action, PathRef, Platform
from boundkeep.normalize.psprograms import is_cmdlet_name
from boundkeep.policy.glob import MAX_KEY_LENGTH, first_match
from boundkeep.policy.schema import Match, Policy, Rule, mcp_declared_read_only

# the gray reason the normalizer gives every MCP call (normalize/event.py MCP_GRAY; not imported
# from there: the matcher stays free of the normalizer's internals)
MCP_GRAY: Final = "mcp-tool-not-reviewed"

CANARY_RULE_ID: Final = "m0-canary"
CANARY_MARKER: Final = "BOUNDKEEP_CANARY"
# The pipeline prefixes a deny reason with "boundkeep (<rule id>): ", so no prefix here.
CANARY_REASON: Final = f"blocked (M0 canary rule: the command contains {CANARY_MARKER})"

VerdictDecision = Literal["deny", "ask", "allow", "gray"]
_RANK: Final = {"allow": 0, "gray": 1, "ask": 2, "deny": 3}


@dataclass(frozen=True, slots=True)
class RuleHit:
    """One rule that matched one action, with why (for ``explain`` and the audit log)."""

    rule_id: str
    decision: Literal["deny", "ask", "allow"]
    reason: str
    detail: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ActionVerdict:
    """The outcome for one action: every hit, the strictest decision and what decided it."""

    index: int
    decision: VerdictDecision
    hits: tuple[RuleHit, ...]
    gray_reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Verdict:
    """The merged outcome. ``reasons`` and ``rule_ids`` are those that decided ``decision``."""

    decision: VerdictDecision
    reasons: tuple[str, ...]
    rule_ids: tuple[str, ...]
    actions: tuple[ActionVerdict, ...]


# --------------------------------------------------------------------------- field matchers


def _tool_matches(patterns: tuple[str, ...], tool: str) -> bool:
    return any(tool.startswith(p[:-1]) if p.endswith("*") else tool == p for p in patterns)


def _fold(action: Action, text: str) -> str:
    return text.casefold() if action.shell == "powershell" else text


def _fold_flag(action: Action, text: str) -> str:
    """Flags fold only for cmdlet parameters and Windows ``/switches``: external programs'
    short flags are case-sensitive (``git branch -d`` is not ``-D``)."""
    if action.shell != "powershell":
        return text
    if text.startswith("/") or is_cmdlet_name(action.program or ""):
        return text.casefold()
    return text


def _host_in(domain: str, allowed: tuple[str, ...]) -> bool:
    """``normalize.domains.host_matches`` on an action's domain string (unparseable: not in)."""
    host = canonical_host(domain)
    return host is not None and host_matches(host, allowed)


def _comparison_key(key: str) -> str | None:
    """A project or trusted-project key in comparison form, or None when it is unusable.

    Usable: an absolute canonical key (``c:/dir`` or ``/dir``) with at least one segment below the
    anchor (a drive or filesystem root is never a project), no ``.`` / ``..`` / empty segment and
    no NUL. Trailing separators are dropped; Windows-flavor keys (a drive) are casefolded.
    """
    if not key or "\x00" in key or len(key) > MAX_KEY_LENGTH:
        return None
    if len(key) >= 3 and key[0].isascii() and key[0].isalpha() and key[1:3] == ":/":
        anchor = key[:3].casefold()
        body = key[3:].casefold()
        if "\\" in body:
            return None
    elif key.startswith("/") and not key.startswith("//"):
        anchor, body = "/", key[1:]
    else:
        return None
    body = body.rstrip("/")
    if not body or any(segment in ("", ".", "..") for segment in body.split("/")):
        return None
    return anchor + body


def _within(key: str, root: str) -> bool:
    return key == root or key.startswith(root + "/")


def _project_trust(action: Action, trusted: tuple[str, ...]) -> bool | None:
    """True: the project is inside a trusted project; False: it is not; None: cannot tell."""
    if action.project is None:
        return None
    keys: list[str] = []
    for raw in (action.project, action.project_resolved):
        if raw is None:
            continue
        key = _comparison_key(raw)
        if key is None:
            return None
        keys.append(key)
    roots = [root for root in map(_comparison_key, trusted) if root is not None]
    return all(any(_within(key, root) for root in roots) for key in keys)


def project_trust_line(action: Action, trusted_projects: tuple[str, ...]) -> str:
    """The ``explain`` line for ``project_trusted``: why the project is or is not trusted."""
    state = _project_trust(action, trusted_projects)
    if state is True:
        return "project_trusted: project is inside a trusted project"
    if state is None:
        return (
            "project_trusted: project is not trusted (the project directory is unknown or unusable)"
        )
    return "project_trusted: project is not trusted"


def _glob_detail(match: Match, path: PathRef, rule: Rule) -> str | None:
    """Detail text if this one path matches a glob and is access-compatible; else None."""
    assert match.path_glob is not None
    if match.access is not None and path.access not in (match.access, "unknown"):
        return None
    if match.except_session_tool_results is not None and path.in_session_tool_results:
        # this form of the path is shown to be in the current session's tool-results directory:
        # the glob is not checked against it (another form, or another path, still is)
        return None
    if len(path.key) > MAX_KEY_LENGTH:
        if rule.action != "allow":
            return f"path_glob: key longer than {MAX_KEY_LENGTH} characters"
        return None
    hit = first_match(match.path_glob, path.key)
    if hit is not None:
        return f"path_glob: {path.key} ~ {hit} (access {path.access})"
    return None


def _outside_detail(path: PathRef) -> str | None:
    if path.inside_project is True:
        return None
    state = "outside" if path.inside_project is False else "not known to be inside"
    return f"path_outside_project: {path.key} is {state} the project"


def _path_details(match: Match, action: Action, rule: Rule) -> tuple[str, ...] | None:
    """Lines for the path conditions, or None if they do not hold. Empty: no path condition.

    ``path_glob`` (with ``access``) and ``path_outside_project`` are about the SAME path: one path
    must match a glob, be access-compatible and be outside the project, so ``cp /tmp/a ./b`` (the
    outside path is only read, the written one is inside) does not satisfy "write outside the
    project". ``path_inside_project`` is about ALL paths (an allow rule must know every path is
    inside); combined with a glob, one path must also match it.
    """
    if match.path_glob is None and match.path_outside_project is None:
        if match.path_inside_project is None:
            return ()
        if not action.paths or any(p.inside_project is not True for p in action.paths):
            return None
        return ("path_inside_project: every path is inside the project",)
    if match.path_inside_project is not None and (
        not action.paths or any(p.inside_project is not True for p in action.paths)
    ):
        return None
    for path in action.paths:
        lines: list[str] = []
        if match.path_glob is not None:
            glob_line = _glob_detail(match, path, rule)
            if glob_line is None:
                continue
            lines.append(glob_line)
        if match.path_outside_project is not None:
            outside_line = _outside_detail(path)
            if outside_line is None:
                continue
            lines.append(outside_line)
        if match.path_inside_project is not None:
            lines.append("path_inside_project: every path is inside the project")
        return tuple(lines)
    return None


def _declared_mcp(action: Action, declared: tuple[str, ...]) -> bool:
    """A call of an MCP tool the policy declares read-only, gray for no other reason."""
    return action.gray_reasons == (MCP_GRAY,) and mcp_declared_read_only(action.tool, declared)


def _match_detail(
    rule: Rule,
    action: Action,
    platform: Platform,
    trusted: tuple[str, ...] = (),
    mcp_read_only: tuple[str, ...] = (),
) -> tuple[str, ...] | None:
    """Why ``rule`` matches ``action`` (one line per matched field), or None if it does not.

    ``trusted``: the policy's ``trusted_projects`` (canonical keys) for ``project_trusted``.
    ``mcp_read_only``: the policy's declared read-only MCP tools, for the field of that name.
    """
    if rule.platform is not None and platform not in rule.platform:
        return None
    if rule.tool is not None and not _tool_matches(rule.tool, action.tool):
        return None
    match = rule.match
    declared = match.mcp_read_only is not None and _declared_mcp(action, mcp_read_only)
    if rule.action == "allow" and (
        (action.gray and not declared) or action.wrappers or action.dynamic_args
    ):
        # An allow rule describes the bare command; behind sudo / env / nohup ... it is a
        # different action (privileges, environment, background), so it never rides the rule. The
        # same for a word the shell expands that is no path (X1 re-review R-1, R-2, R-4): what the
        # program receives is not what the rule saw. The one gray action an allow rule may take is
        # a call of an MCP tool the user declared read-only, when nothing else made it gray.
        return None
    details: list[str] = []

    if match.program is not None:
        if action.program is None:
            return None
        program = _fold(action, action.program)
        if program not in {_fold(action, p) for p in match.program}:
            return None
        details.append(f"program: {action.program}")
    if match.subcommand is not None:
        if action.subcommand is None:
            return None
        sub = _fold(action, action.subcommand)
        if sub not in {_fold(action, s) for s in match.subcommand}:
            return None
        details.append(f"subcommand: {action.subcommand}")
    if match.flags_any is not None:
        wanted = {_fold_flag(action, f) for f in match.flags_any}
        found = next((f for f in action.flags if _fold_flag(action, f) in wanted), None)
        if found is None:
            return None
        details.append(f"flags_any: {found}")
    if match.flags_none is not None:
        banned = {_fold_flag(action, f) for f in match.flags_none}
        present = next((f for f in action.flags if _fold_flag(action, f) in banned), None)
        if present is not None:
            return None
        details.append(f"flags_none: none of {', '.join(match.flags_none)} is present")
    path_lines = _path_details(match, action, rule)
    if path_lines is None:
        return None
    details.extend(path_lines)
    if match.path_in_scratchpad is not None:
        # At least one path and every path (each form of it: lexical and on-disk resolved) is
        # inside the current session's scratchpad. Unknown stays "no": a deny / ask rule with this
        # field does not match a path that is not shown to be in the scratchpad either.
        if not action.paths or any(not p.in_scratchpad for p in action.paths):
            return None
        details.append("path_in_scratchpad: every path is inside the session scratchpad")
    if match.path_in_session_tool_results is not None:
        # Same shape as path_in_scratchpad, for the session's tool-results directory.
        if not action.paths or any(not p.in_session_tool_results for p in action.paths):
            return None
        details.append(
            "path_in_session_tool_results: every path is inside the session tool-results directory"
        )
    if match.paths_read_only is not None:
        # Exactly "read": "write" and "unknown" (may write) both fail. No paths: vacuously true.
        if any(p.access != "read" for p in action.paths):
            return None
        details.append("paths_read_only: every path is only read")
    if match.project_trusted is not None:
        state = _project_trust(action, trusted)
        if state is True:
            details.append(project_trust_line(action, trusted))
        elif state is None and rule.action != "allow":
            # Cannot tell whether the project is trusted: a deny / ask rule errs toward matching.
            details.append("project_trusted: project directory unknown or unusable (a match)")
        else:
            return None
    if match.network is not None:
        if not action.network:
            return None
        details.append("network: true")
    if match.destination is not None:
        if not action.network:
            return None
        if (match.destination == "known") != bool(action.domains):
            return None
        details.append(f"destination: {match.destination}")
    if match.domain_not_in is not None:
        if not action.network:
            return None
        if not action.domains:
            details.append("domain_not_in: network action with no known domain")
        else:
            stranger = next(
                (d for d in action.domains if not _host_in(d, match.domain_not_in)), None
            )
            if stranger is None:
                return None
            details.append(f"domain_not_in: {stranger}")
    if match.domain_in is not None:
        if not action.network or not action.domains:
            return None
        if not all(_host_in(d, match.domain_in) for d in action.domains):
            return None
        details.append(f"domain_in: {', '.join(action.domains)}")
    if match.mcp_server is not None:
        if action.mcp_server is None or action.mcp_server not in match.mcp_server:
            return None
        details.append(f"mcp_server: {action.mcp_server}")
    if match.mcp_read_only is not None:
        if not declared:
            return None
        details.append(f"mcp_read_only: {action.tool} is declared read-only")
    return tuple(details)


def _safe_detail(
    rule: Rule,
    action: Action,
    platform: Platform,
    trusted: tuple[str, ...] = (),
    mcp_read_only: tuple[str, ...] = (),
) -> tuple[str, ...] | None:
    try:
        return _match_detail(rule, action, platform, trusted, mcp_read_only)
    except Exception:  # noqa: BLE001 - matching must never raise; fail toward deny/ask
        if rule.action == "allow":
            return None
        return ("internal-error: treated as a match",)


def match_rule(
    rule: Rule,
    action: Action,
    *,
    platform: Platform,
    trusted_projects: tuple[str, ...] = (),
    mcp_read_only: tuple[str, ...] = (),
) -> bool:
    """True if ``rule`` matches ``action`` on a resident process running on ``platform``.

    Pure and total: it never raises. An unexpected internal error counts as a match for deny and
    ask rules and as no match for allow rules. ``trusted_projects`` is ``Policy.trusted_projects``
    (only ``project_trusted`` looks at it; none given means no project is trusted);
    ``mcp_read_only`` is ``Policy.mcp_read_only`` (none given: no tool is declared).
    """
    return _safe_detail(rule, action, platform, trusted_projects, mcp_read_only) is not None


def explain_rule(
    rule: Rule,
    action: Action,
    *,
    platform: Platform,
    trusted_projects: tuple[str, ...] = (),
    mcp_read_only: tuple[str, ...] = (),
) -> tuple[str, ...] | None:
    """Like ``match_rule`` but returns one line per matched field (None: no match)."""
    return _safe_detail(rule, action, platform, trusted_projects, mcp_read_only)


# --------------------------------------------------------------------------- evaluation


def _canary_hit(action: Action) -> RuleHit | None:
    if action.command_text is not None and CANARY_MARKER in action.command_text:
        return RuleHit(
            CANARY_RULE_ID, "deny", CANARY_REASON, (f"command_text contains {CANARY_MARKER}",)
        )
    return None


def _evaluate_action(
    policy: Policy, action: Action, index: int, platform: Platform
) -> ActionVerdict:
    hits: list[RuleHit] = []
    canary = _canary_hit(action)
    if canary is not None:
        hits.append(canary)
    for rule in policy.rules:
        detail = _safe_detail(rule, action, platform, policy.trusted_projects, policy.mcp_read_only)
        if detail is not None:
            hits.append(RuleHit(rule.id, rule.action, rule.reason, detail))
    decision: VerdictDecision = "gray"
    for level in ("deny", "ask", "allow"):
        if any(hit.decision == level for hit in hits):
            decision = level
            break
    gray_reasons = action.gray_reasons if decision == "gray" else ()
    return ActionVerdict(index, decision, tuple(hits), gray_reasons)


def evaluate(
    policy: Policy, actions: tuple[Action, ...] | list[Action], *, platform: Platform
) -> Verdict:
    """Merge the per-action outcomes into one ``Verdict`` (strictest wins; see module docs).

    ``actions`` empty is gray: nothing was understood, so nothing can be allowed. Pure; never
    allows unless every action was matched by at least one allow rule and by no deny or ask rule.
    """
    results = tuple(
        _evaluate_action(policy, action, index, platform) for index, action in enumerate(actions)
    )
    if not results:
        return Verdict("gray", ("no action to evaluate",), (), ())
    decision: VerdictDecision = "allow"
    for result in results:
        if _RANK[result.decision] > _RANK[decision]:
            decision = result.decision
    reasons: list[str] = []
    rule_ids: list[str] = []
    for result in results:
        if decision == "gray":
            if result.decision == "gray":
                reasons.extend(result.gray_reasons or ("no rule matched",))
            continue
        for hit in result.hits:
            if hit.decision == decision:
                rule_ids.append(hit.rule_id)
                if hit.reason:
                    reasons.append(hit.reason)
    return Verdict(
        decision,
        tuple(dict.fromkeys(reasons)),
        tuple(dict.fromkeys(rule_ids)),
        results,
    )
