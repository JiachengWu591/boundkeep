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
from boundkeep.policy.schema import Match, Policy, Rule

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


def _glob_detail(match: Match, path: PathRef, rule: Rule) -> str | None:
    """Detail text if this one path matches a glob and is access-compatible; else None."""
    assert match.path_glob is not None
    if match.access is not None and path.access not in (match.access, "unknown"):
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


def _match_detail(rule: Rule, action: Action, platform: Platform) -> tuple[str, ...] | None:
    """Why ``rule`` matches ``action`` (one line per matched field), or None if it does not."""
    if rule.platform is not None and platform not in rule.platform:
        return None
    if rule.tool is not None and not _tool_matches(rule.tool, action.tool):
        return None
    if rule.action == "allow" and (action.gray or action.wrappers):
        # An allow rule describes the bare command; behind sudo / env / nohup ... it is a
        # different action (privileges, environment, background), so it never rides the rule.
        return None
    match = rule.match
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
    path_lines = _path_details(match, action, rule)
    if path_lines is None:
        return None
    details.extend(path_lines)
    if match.network is not None:
        if not action.network:
            return None
        details.append("network: true")
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
    return tuple(details)


def _safe_detail(rule: Rule, action: Action, platform: Platform) -> tuple[str, ...] | None:
    try:
        return _match_detail(rule, action, platform)
    except Exception:  # noqa: BLE001 - matching must never raise; fail toward deny/ask
        if rule.action == "allow":
            return None
        return ("internal-error: treated as a match",)


def match_rule(rule: Rule, action: Action, *, platform: Platform) -> bool:
    """True if ``rule`` matches ``action`` on a resident process running on ``platform``.

    Pure and total: it never raises. An unexpected internal error counts as a match for deny and
    ask rules and as no match for allow rules.
    """
    return _safe_detail(rule, action, platform) is not None


def explain_rule(rule: Rule, action: Action, *, platform: Platform) -> tuple[str, ...] | None:
    """Like ``match_rule`` but returns one line per matched field (None: no match)."""
    return _safe_detail(rule, action, platform)


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
        detail = _safe_detail(rule, action, platform)
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
