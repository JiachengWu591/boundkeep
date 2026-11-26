"""The deterministic checks of a policy proposal (PROJECT_SPEC.md §8.1).

Everything here is code: what a proposal says about itself (``summary``, ``impact``) never decides
a finding. Two levels: ``refuse`` (the proposal cannot be written) and ``warn`` (shown; writing
still needs the user's typed ``yes``), plus ``note`` for plain information.

Why the checks look at one direction: rules merge strictest-wins and a gray action never matches
an allow rule (``policy/matcher.py``), so ADDING rules cannot weaken an existing deny or ask. The
only way a proposal loosens the gate is a new allow rule taking over actions that were gray (and
a rule's allow skips the taint step and the LLM audit). So:

* syntactic refusals for allow rules: a shell tool without a program, a program that runs code
  (shells, interpreters, launchers; PowerShell's code-running cmdlets), ``path_outside_project``,
  network conditions without ``domain_in``;
* the canaries (``canaries.py``): none may go from not-allowed to allowed, in a fresh session or a
  tainted one;
* the tests, on the fake machines of ``boundkeep test``: the existing ones must all pass; a new
  test whose verdict a new rule decides must match its ``expect``; a new test the existing policy
  decides is written with the verdict it really gets (the proposer only saw rule ids);
* at least ``MIN_HITS`` tests where each new rule fires and ``MIN_MISSES`` where it does not;
* warnings: a new rule shadowed by a stricter existing one, one that changes nothing on its
  tests, two new rules that disagree on a test, an allow for a program that runs the repository's
  code, and what the replay (``replay.py``) finds.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from boundkeep import policycli
from boundkeep.compiler import writer
from boundkeep.compiler.canaries import CANARIES
from boundkeep.compiler.proposal import Proposal, shown
from boundkeep.normalize.bash import WRAPPERS
from boundkeep.normalize.event import BUILD_FILES, INTERPRETERS
from boundkeep.normalize.model import Platform
from boundkeep.normalize.programs import EXEC_PROGRAMS, canonical_name
from boundkeep.normalize.psprograms import EXEC_CMDLETS
from boundkeep.policy import Policy, PolicyError, Rule, parse_policy_text
from boundkeep.policy.matcher import Verdict
from boundkeep.policy.schema import RESERVED_RULE_IDS, PolicyTest
from boundkeep.session.facts import FRESH, SessionFacts, tainted_facts

Level = Literal["refuse", "warn", "note"]
MACHINES: Final[tuple[Platform, ...]] = ("windows", "posix")
MIN_HITS: Final = 3
MIN_MISSES: Final = 3
RANK: Final[dict[str, int]] = {"allow": 0, "gray": 1, "ask": 2, "deny": 3, "error": 2}
SHELL_TOOLS: Final = frozenset({"Bash", "PowerShell"})
_SHOWN_CHARS: Final = 90

# Programs whose allow rule would let anything run: a shell, an interpreter, a launcher, a
# wrapper, a cmdlet that runs code. Compared by canonical name, without case. The normalizer's
# own verdict (``ProgramProbe``) is the main check; this list is the second.
RUNS_CODE: Final[frozenset[str]] = frozenset(
    name.lower()
    for name in (
        EXEC_PROGRAMS
        | INTERPRETERS
        | WRAPPERS
        | frozenset(EXEC_CMDLETS.values())
        | {"npx", "pnpx", "bunx", "uvx", "pipx", "pythonw", "ipython", "jupyter", "tsx",
           "ts-node", "jshell", "irb", "groovy", "julia", "r", "scala", "kotlin",
           "mshta", "rundll32", "regsvr32", "cscript", "wscript", "installutil", "msiexec",
           "conhost", "forfiles", "pcalua", "cmstp", "wmic"}
    )
)  # fmt: skip
# Programs that run the repository's own code (build files, tests, package scripts).
RUNS_REPO_CODE: Final[frozenset[str]] = frozenset(BUILD_FILES) | frozenset(
    {
        "pytest", "py.test", "tox", "nox", "jest", "vitest", "mocha", "go", "cargo", "dotnet",
        "msbuild", "gradlew", "mvnw", "pip", "pip3", "uv", "poetry", "pdm", "hatch", "composer",
        "bundle", "rake", "mix", "swift", "flutter", "dart",
    }
)  # fmt: skip
RUNS_REPO_CODE_FOLDED: Final[frozenset[str]] = frozenset(n.lower() for n in RUNS_REPO_CODE)
FILE_TOOLS: Final = frozenset(
    {"Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Glob", "Grep"}
)
NETWORK_TOOLS: Final = frozenset({"WebFetch", "WebSearch"})
# the match fields that keep an allow rule's paths inside the project or the session's own dirs
SCOPE_FIELDS: Final = (
    "path_inside_project",
    "path_in_scratchpad",
    "path_in_session_tool_results",
    "path_in_project_memory",
)


@dataclass(frozen=True)
class Finding:
    level: Level
    code: str
    message: str


@dataclass
class Run:
    """One test (or canary) judged on one fake machine."""

    index: int  # 1-based position in the candidate policy's tests
    new: bool
    machine: Platform
    tool: str
    shown: str
    expect: str
    got: str = "skipped"
    old: str | None = None  # the verdict under the current policy (new tests only)
    fired: tuple[str, ...] = ()  # new rules that matched some action
    deciding: tuple[str, ...] = ()  # the rules that decided the verdict
    outcome: str = "skipped"  # pass | fail | corrected | skipped


@dataclass
class Report:
    source: str
    findings: list[Finding] = field(default_factory=list)
    runs: list[Run] = field(default_factory=list)
    tests_to_write: list[dict[str, Any]] = field(default_factory=list)
    new_text: str | None = None
    added_rules_text: str = ""
    added_tests_text: str = ""
    skipped_powershell: int = 0
    canaries_checked: int = 0
    canaries_skipped: int = 0  # PowerShell canaries without a parser
    old_tests: int = 0  # the current policy's test count: proposed test k is index old_tests + k
    # existing tests a new rule makes stricter: 0-based index -> the new ``expect``
    expect_updates: dict[int, str] = field(default_factory=dict)
    changed: list[Run] = field(default_factory=list)

    @property
    def refused(self) -> bool:
        return any(f.level == "refuse" for f in self.findings)

    def add(self, level: Level, code: str, message: str) -> None:
        self.findings.append(Finding(level, code, message))


def shown_input(tool: str, data: Mapping[str, Any]) -> str:
    text = f"{tool} " + json.dumps(dict(data), ensure_ascii=False)
    text = "".join(ch if ch.isprintable() else "?" for ch in text)
    return text if len(text) <= _SHOWN_CHARS else text[: _SHOWN_CHARS - 3] + "..."


class Judge:
    """One policy text on both fake machines (``boundkeep test``'s)."""

    def __init__(self, text: str) -> None:
        self.policies: dict[Platform, Policy] = {
            m: parse_policy_text(text, home=policycli._FAKE[m]["home"]) for m in MACHINES
        }

    def verdict(
        self,
        machine: Platform,
        tool: str,
        data: Mapping[str, Any],
        *,
        cwd: str | None = None,
        project: str | None = None,
        session_id: str | None = None,
        session: SessionFacts = FRESH,
    ) -> Verdict:
        review = policycli._run_one(
            self.policies[machine], machine, tool, data, cwd, project, session_id, session
        )
        return review.verdict

    def test_verdict(self, machine: Platform, case: PolicyTest) -> Verdict:
        return self.verdict(
            machine,
            case.tool,
            case.input.thaw(),
            cwd=case.cwd,
            project=case.project_dir,
            session_id=case.session_id,
            session=policycli._test_session(case.tainted, case.project_marked),
        )


def fired_rules(verdict: Verdict, ids: frozenset[str]) -> tuple[str, ...]:
    hit: dict[str, None] = {}
    for action in verdict.actions:
        for h in action.hits:
            if h.rule_id in ids:
                hit[h.rule_id] = None
    return tuple(hit)


def _covers(tools: tuple[str, ...] | None, name: str) -> bool:
    """Does a rule's ``tool`` filter (exact names, ``prefix*`` patterns; None = all) take
    ``name``?"""
    if tools is None:
        return True
    return any(t == name or (t.endswith("*") and name.startswith(t[:-1])) for t in tools)


class ProgramProbe:
    """What the normalizer makes of a bare program name, in Bash and in PowerShell: the risk tags
    and gray reasons of the action (``boundkeep test``'s fake machines, an empty policy)."""

    def __init__(self, ps_ready: bool) -> None:
        self.ps_ready = ps_ready
        self._policies = {m: parse_policy_text("version: 1\n", home=policycli._FAKE[m]["home"])
                          for m in MACHINES}  # fmt: skip
        self._seen: dict[tuple[str, str], tuple[frozenset[str], bool]] = {}

    def look(self, shell: str, program: str) -> tuple[frozenset[str], bool] | None:
        """(risk tags, gray) of ``program`` run in ``shell``; None when it cannot be looked at."""
        if shell == "PowerShell" and not self.ps_ready:
            return None
        key = (shell, program)
        if key not in self._seen:
            machine: Platform = "windows" if shell == "PowerShell" else "posix"
            review = policycli._run_one(
                self._policies[machine], machine, shell, {"command": program}, None, None
            )
            tags = frozenset(t for a in review.actions for t in a.risk_tags)
            gray = not review.actions or any(a.gray for a in review.actions)
            self._seen[key] = (tags, gray)
        return self._seen[key]


def _syntactic(rule: Rule, report: Report, probe: ProgramProbe | None = None) -> None:
    if rule.action != "allow":
        return
    match = rule.match
    tools = rule.tool
    shells = [t for t in ("Bash", "PowerShell") if _covers(tools, t)]
    if shells and match.program is None:
        report.add(
            "refuse",
            "allow-shell-any",
            f"rule '{rule.id}' allows a shell tool (Bash / PowerShell) without naming a program: "
            "it would allow almost any command",
        )
    programs = match.program or ()
    runs: dict[str, str] = {}
    repo: dict[str, None] = {}
    network: dict[str, None] = {}
    for program in programs:
        folded = canonical_name(program).lower()
        if folded in RUNS_CODE or program.lower() in RUNS_CODE:
            runs[program] = "it runs whatever code it is given"
            continue
        for shell in shells or ["Bash"]:
            seen = probe.look(shell, program) if probe is not None else None
            if seen is None:
                continue
            tags, _gray = seen
            if "network_egress" in tags:
                network[program] = None
            if "exec" not in tags:
                continue
            if folded in RUNS_REPO_CODE_FOLDED:
                repo[program] = None
            else:
                runs[program] = (
                    f"boundkeep's parser marks it ({shell}) as running code, or does not know "
                    "what it does"
                )
        if folded in RUNS_REPO_CODE_FOLDED:
            repo[program] = None
    for program, why in runs.items():
        report.add("refuse", "allow-runs-code", f"rule '{rule.id}' allows {program}: {why}")
    scoped = any(getattr(match, name) for name in SCOPE_FIELDS)
    file_tools = sorted(t for t in FILE_TOOLS if _covers(tools, t))
    if match.path_outside_project:
        report.add(
            "refuse",
            "allow-outside-project",
            f"rule '{rule.id}' allows actions on paths outside the project",
        )
    elif not scoped and (match.path_glob is not None or (tools is not None and file_tools)):
        what = "path_glob" if match.path_glob is not None else ", ".join(file_tools)
        report.add(
            "refuse",
            "allow-outside-project",
            f"rule '{rule.id}' allows {what} without keeping the paths inside the project: add "
            "path_inside_project: true (or one of the session's own directories)",
        )
    net = (
        match.network
        or match.destination
        or match.domain_not_in
        or any(_covers(tools, t) for t in NETWORK_TOOLS if tools is not None)
        or bool(network)
    )
    if net and not match.domain_in:
        report.add(
            "refuse",
            "allow-network",
            f"rule '{rule.id}' allows network access without a domain_in list",
        )
    for program in [p for p in repo if p not in runs]:
        report.add(
            "warn",
            "allow-repo-code",
            f"rule '{rule.id}' allows {program}, which runs the repository's own code "
            "(build files, tests, package scripts): only for repositories you wrote or reviewed",
        )


def check(
    policy_text: str,
    proposal: Proposal,
    *,
    source: str,
    ps_ready: bool,
    note: str,
    real_home: str | None = None,
    progress: Callable[[str], None] | None = None,
) -> Report:
    """Run every check of a proposal against ``policy_text`` (the current policy, without BOM).

    ``ps_ready``: the PowerShell parser helper is up (PowerShell tests and canaries are skipped,
    visibly, when it is not). ``note`` is the comment line above the added blocks. ``real_home``
    is the home the written policy is verified with. Never writes anything."""
    report = Report(source=source)
    say = progress or (lambda _text: None)
    try:
        old = Judge(policy_text)
    except PolicyError as exc:
        report.add("refuse", "merge", f"the current policy does not load: {exc}")
        return report
    taken = {r.id for r in old.policies["windows"].rules} | set(RESERVED_RULE_IDS)
    clash = [i for i in proposal.rule_ids if i in taken]
    if clash:
        report.add(
            "refuse",
            "merge",
            f"rule id(s) {', '.join(clash)} already exist: a proposal only adds rules (edit the "
            "policy file yourself to change an existing one)",
        )
        return report
    try:
        first_text = writer.merge_text(policy_text, proposal.rules, proposal.tests, note=note)
        candidate = Judge(first_text)
    except (writer.MergeError, PolicyError) as exc:
        report.add("refuse", "merge", str(exc))
        return report
    new_rules = candidate.policies["windows"].rules[len(old.policies["windows"].rules) :]
    new_ids = frozenset(r.id for r in new_rules)
    probe = ProgramProbe(ps_ready)
    for rule in new_rules:
        _syntactic(rule, report, probe)
    say("running the policy's tests")
    report.old_tests = len(old.policies["windows"].tests)
    _run_tests(old, candidate, report.old_tests, new_ids, ps_ready, report)
    _rule_coverage(new_rules, report)
    say("checking the canaries")
    _canaries(old, candidate, ps_ready, report)
    tests_to_write = _tests_to_write(proposal, report)
    report.tests_to_write = tests_to_write
    if report.refused:
        return report
    try:
        final = writer.merge_text(
            policy_text,
            proposal.rules,
            tests_to_write,
            note=note,
            expect_updates=report.expect_updates,
        )
        writer.verify_merge(
            policy_text,
            final,
            proposal.rules,
            tests_to_write,
            home=real_home,
            expect_updates=report.expect_updates,
        )
    except writer.MergeError as exc:
        report.add("refuse", "merge", str(exc))
        return report
    report.new_text = final
    report.added_rules_text = "\n".join(
        shown(line) for rule in proposal.rules for line in writer._dump("rules", [rule], 2)
    )
    report.added_tests_text = "\n".join(
        shown(line) for line in writer._dump("tests", tests_to_write, 2)
    )
    return report


def _run_tests(
    old: Judge,
    candidate: Judge,
    old_count: int,
    new_ids: frozenset[str],
    ps_ready: bool,
    report: Report,
) -> None:
    failures_old: list[Run] = []
    failures_new: list[Run] = []
    stricter: dict[int, list[Run]] = {}
    ran_old: dict[int, list[Run]] = {}
    for machine in MACHINES:
        policy = candidate.policies[machine]
        for index, case in enumerate(policy.tests, start=1):
            if case.platform is not None and machine not in case.platform:
                continue
            new = index > old_count
            run = Run(
                index=index,
                new=new,
                machine=machine,
                tool=case.tool,
                shown=shown_input(case.tool, case.input.thaw()),
                expect=case.expect,
            )
            if case.tool == "PowerShell" and not ps_ready:
                report.skipped_powershell += 1
                if new:
                    report.runs.append(run)
                continue
            verdict = candidate.test_verdict(machine, case)
            run.got = verdict.decision
            run.deciding = tuple(verdict.rule_ids)
            run.fired = fired_rules(verdict, new_ids)
            if not new:
                ran_old.setdefault(index, []).append(run)
                if run.got != run.expect:
                    run.old = old.test_verdict(machine, case).decision
                    if run.old != run.expect and RANK[run.got] >= RANK[run.old]:
                        # failing without the proposal too, and not loosened by it
                        report.add(
                            "note",
                            "tests-already-failing",
                            f"existing test #{index} on {machine} ({run.shown}) already fails "
                            f"without the proposal (expects {run.expect}, got {run.old}, now "
                            f"{run.got})",
                        )
                        continue
                    if (
                        run.old == run.expect
                        and RANK[run.got] > RANK[run.expect]
                        and set(run.deciding) & new_ids
                    ):
                        # the tightening the proposal is for: the expectation follows it
                        run.outcome = "updated"
                        stricter.setdefault(index, []).append(run)
                        continue
                    run.outcome = "fail"
                    failures_old.append(run)
                continue
            run.old = old.test_verdict(machine, case).decision
            if run.got == run.expect:
                run.outcome = "pass"
            elif not set(run.deciding) & new_ids:
                run.outcome = "corrected"
            else:
                run.outcome = "fail"
                failures_new.append(run)
            report.runs.append(run)
    for index, runs in sorted(stricter.items()):
        if len({r.got for r in runs}) == 1 and len(runs) == len(ran_old[index]):
            report.expect_updates[index - 1] = runs[0].got
            report.changed.extend(runs)
        else:  # one expectation cannot follow two machines: the user edits it
            for run in runs:
                run.outcome = "fail"
            failures_old.append(runs[0])
    for run in failures_old[:5]:
        report.add(
            "refuse",
            "tests-fail",
            f"existing test #{run.index} on {run.machine} ({run.shown}) expected {run.expect}, "
            f"now gets {run.got} (from {', '.join(run.deciding) or 'no rule'})",
        )
    if len(failures_old) > 5:
        report.add("refuse", "tests-fail", f"and {len(failures_old) - 5} more existing tests fail")
    for run in failures_new[:5]:
        report.add(
            "refuse",
            "tests-fail",
            f"proposed test #{run.index - old_count} on {run.machine} ({run.shown}) expected "
            f"{run.expect}, the new rule(s) {', '.join(sorted(set(run.deciding) & new_ids))} "
            f"give {run.got}",
        )
    if len(failures_new) > 5:
        report.add("refuse", "tests-fail", f"and {len(failures_new) - 5} more proposed tests fail")
    if report.expect_updates:
        shown = "; ".join(
            f"#{r.index} {r.shown}: {r.expect} -> {r.got}" for r in report.changed[:5]
        )
        more = " ..." if len(report.changed) > 5 else ""
        report.add(
            "warn",
            "existing-tests-changed",
            f"{len(report.expect_updates)} existing test(s) get a stricter verdict from the "
            f"new rule(s) and their expect is rewritten ({shown}{more}); many of them means "
            "the rules may be broad",
        )
    corrected = [r for r in report.runs if r.outcome == "corrected"]
    for run in corrected[:5]:
        report.add(
            "note",
            "test-expect",
            f"proposed test #{run.index - old_count} on {run.machine} ({run.shown}): the "
            f"proposer expected {run.expect}, the policy gives {run.got} (no new rule decides "
            "it); written with the real verdict",
        )
    if len(corrected) > 5:
        report.add("note", "test-expect", f"and {len(corrected) - 5} more such tests")


def _rule_coverage(new_rules: Sequence[Rule], report: Report) -> None:
    runs = [r for r in report.runs if r.new and r.outcome != "skipped"]
    by_test: dict[int, list[Run]] = {}
    for run in runs:
        by_test.setdefault(run.index, []).append(run)
    actions: dict[str, str] = {r.id: r.action for r in new_rules}
    for rule in new_rules:
        hits = {i for i, rs in by_test.items() if any(rule.id in r.fired for r in rs)}
        misses = {i for i, rs in by_test.items() if all(rule.id not in r.fired for r in rs)}
        if len(hits) < MIN_HITS or len(misses) < MIN_MISSES:
            report.add(
                "refuse",
                "tests-few",
                f"rule '{rule.id}' has {len(hits)} test(s) it matches and {len(misses)} it does "
                f"not match; at least {MIN_HITS} and {MIN_MISSES} are needed (include near "
                "misses: another flag, a neighbouring path, a similar host)",
            )
        fired = [r for r in runs if rule.id in r.fired]
        if fired:
            stricter = [r for r in fired if RANK[r.got] > RANK[rule.action]]
            if len(stricter) == len(fired):
                by = sorted({i for r in stricter for i in r.deciding} - set(actions))
                report.add(
                    "warn",
                    "shadowed",
                    f"rule '{rule.id}' ({rule.action}) is overruled on every test it matches"
                    + (f" by {', '.join(by)}" if by else "")
                    + ": it changes no verdict there. Rules take the strictest result; to loosen "
                    "an existing rule, edit the policy file yourself",
                )
            elif stricter:
                report.add(
                    "warn",
                    "shadowed",
                    f"rule '{rule.id}' ({rule.action}) is overruled by a stricter rule on "
                    f"{len(stricter)} of the {len(fired)} test runs it matches",
                )
            elif all(r.old == r.got for r in fired):
                report.add(
                    "warn",
                    "no-change",
                    f"rule '{rule.id}' changes nothing on the tests it matches: the current "
                    "policy already gives the same verdicts",
                )
    for run in runs:
        acts = {actions[i] for i in run.fired}
        if len(acts) > 1:
            report.add(
                "warn",
                "conflict",
                f"new rules {', '.join(run.fired)} disagree ({', '.join(sorted(acts))}) on "
                f"{run.shown} ({run.machine})",
            )
            break


def _canaries(old: Judge, candidate: Judge, ps_ready: bool, report: Report) -> None:
    sessions = (("a fresh session", FRESH), ("a session that read untrusted content",
                                              tainted_facts()))  # fmt: skip
    found = 0
    for canary in CANARIES:
        if canary.tool == "PowerShell" and not ps_ready:
            report.canaries_skipped += 1
            continue
        hit = False
        for machine in canary.platforms:
            for label, session in sessions:
                if hit:
                    break
                report.canaries_checked += 1
                after = candidate.verdict(machine, canary.tool, canary.input, session=session)
                if after.decision != "allow":
                    continue
                before = old.verdict(machine, canary.tool, canary.input, session=session)
                if before.decision == "allow":
                    continue
                hit = True
                found += 1
                if found <= 3:
                    report.add(
                        "refuse",
                        "canary",
                        f"the proposal would allow: {canary.what} "
                        f"({shown_input(canary.tool, canary.input)}, {machine}, {label}; "
                        f"before: {before.decision}; allowed by {', '.join(after.rule_ids)})",
                    )
    if found > 3:
        report.add("refuse", "canary", f"and {found - 3} more canary actions would be allowed")


def _tests_to_write(proposal: Proposal, report: Report) -> list[dict[str, Any]]:
    """The proposal's tests as they will be written: ``expect`` replaced by the real verdict where
    no new rule decides it, split per machine where the two machines differ."""
    out: list[dict[str, Any]] = []
    for offset, test in enumerate(proposal.tests, start=1):
        runs = [r for r in report.runs if r.new and r.index == report.old_tests + offset]
        verdicts: dict[Platform, str] = {}
        for run in runs:
            if run.outcome in ("pass", "fail"):
                verdicts[run.machine] = run.expect
            elif run.outcome == "corrected":
                verdicts[run.machine] = run.got
        if not verdicts or all(v == test.get("expect") for v in verdicts.values()):
            out.append(dict(test))
            continue
        if len(set(verdicts.values())) == 1 and len(verdicts) == len(runs):
            out.append(dict(test) | {"expect": next(iter(verdicts.values()))})
            continue
        for machine in MACHINES:
            if machine in verdicts:
                out.append(dict(test) | {"platform": [machine], "expect": verdicts[machine]})
            elif any(r.machine == machine for r in runs):  # skipped there: keep as proposed
                out.append(dict(test) | {"platform": [machine]})
    return out
