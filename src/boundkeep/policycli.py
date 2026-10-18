"""``boundkeep test`` (run a policy's built-in tests) and ``boundkeep explain`` (why one event got
the verdict it got).

Both run the real pipeline (normalize -> rules -> hook decision) with a fixed fake machine
(home directory, project, environment) per platform, so the result does not depend on the
developer's own files; a policy test written with Windows paths passes the same on Linux. Only the
lexical layer is meaningful for fake paths: nothing exists on disk, so nothing is resolved.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping
from typing import Any

from boundkeep import console, hook_main, paths, protocol
from boundkeep.cli import printable
from boundkeep.daemon import pipeline
from boundkeep.normalize.model import Platform
from boundkeep.policy import (
    Policy,
    PolicyError,
    default_policy_text,
    load_policy,
    parse_policy_text,
)

EXIT_OK = 0
EXIT_PROBLEM = 1

# A fake machine per platform: the policy tests run against it, never against this computer.
_FAKE: dict[str, dict[str, Any]] = {
    "windows": {
        "home": "C:\\Users\\testuser",
        "project": "C:\\Users\\testuser\\proj",
        "env": {
            "USERPROFILE": "C:\\Users\\testuser",
            "APPDATA": "C:\\Users\\testuser\\AppData\\Roaming",
            "LOCALAPPDATA": "C:\\Users\\testuser\\AppData\\Local",
        },
    },
    "posix": {
        "home": "/home/testuser",
        "project": "/home/testuser/proj",
        "env": {"HOME": "/home/testuser"},
    },
}


def _load(policy_file: str | None, platform: str) -> Policy:
    home = _FAKE[platform]["home"]
    if policy_file:
        return load_policy(policy_file, home=home)
    return parse_policy_text(default_policy_text(), home=home)


def _platforms(choice: str) -> list[Platform]:
    if choice == "all":
        return ["windows", "posix"]
    return [choice]  # type: ignore[list-item]


def _run_one(
    policy: Policy,
    platform: Platform,
    tool: str,
    tool_input: Mapping[str, Any],
    cwd: str | None,
    project: str | None,
) -> pipeline.Review:
    fake = _FAKE[platform]
    payload = {
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": cwd or fake["project"],
        "project_dir": project or fake["project"],
        "session_id": "policy-test",
    }
    runtime, _problem = _runtime(policy, fake["env"], fake["home"])
    # The fake machines are not on this disk: a look into real directories would make the verdict
    # depend on whatever the host happens to hold (`../..` from the fake project is a real dir).
    return pipeline.review(
        payload, runtime, platform=platform, env=fake["env"], home=fake["home"], scan_disk=False
    )


def cmd_test(args: argparse.Namespace) -> int:
    from boundkeep.normalize import psparse

    psparse.warm_up(wait_s=10)  # PowerShell policy tests need the parser helper to be ready
    # A host without PowerShell cannot parse PowerShell commands (they come back gray), which says
    # nothing about the policy: those cases are skipped visibly, never counted as passes or fails.
    no_ps = _ps_unavailable(psparse.status())
    failures = 0
    skipped = 0
    ran = 0
    ran_on: dict[str, int] = {}
    total_tests = 0
    for platform in _platforms(args.platform):
        try:
            policy = _load(args.policy, platform)
        except (PolicyError, OSError) as exc:
            console.err(f"boundkeep test: {exc}")
            return EXIT_PROBLEM
        console.out(
            f"== platform: {platform} ({len(policy.rules)} rules, {len(policy.tests)} tests)"
        )
        total_tests = len(policy.tests)
        ran_on[platform] = 0
        for index, case in enumerate(policy.tests, start=1):
            if case.platform is not None and platform not in case.platform:
                continue
            if no_ps and case.tool == "PowerShell":
                skipped += 1
                shown = json.dumps(case.input.thaw(), ensure_ascii=False)[:90]
                console.out(
                    f"  [SKIP] #{index} {case.tool} {shown} (no PowerShell parser on this host)"
                )
                continue
            ran += 1
            ran_on[platform] += 1
            result = _run_one(
                policy,
                platform,
                case.tool,
                case.input.thaw(),
                case.cwd,
                case.project_dir,
            )
            got = result.verdict.decision
            label = f"#{index} {case.tool} {json.dumps(case.input.thaw(), ensure_ascii=False)[:90]}"
            if got == case.expect:
                console.out(f"  [PASS] {label} -> {got}")
            else:
                failures += 1
                console.out(f"  [FAIL] {label}: expected {case.expect}, got {got}")
                for reason in result.verdict.reasons[:3]:
                    console.out(f"         why: {reason}")
    summary = f"{ran} test(s) run, {failures} failed"
    if skipped:
        summary += f", {skipped} skipped"
    console.out(summary)
    # A run that checked nothing proves nothing: it must not look like a pass.
    if args.platform != "all" and ran == 0:
        console.err(
            f"boundkeep test: no test ran for platform {args.platform} "
            f"({_why_none(total_tests, args.platform)})"
        )
        return EXIT_PROBLEM
    if ran == 0:
        console.err(f"boundkeep test: no test ran ({_why_none(total_tests, 'all')})")
        return EXIT_PROBLEM
    return EXIT_PROBLEM if failures else EXIT_OK


def _ps_unavailable(status: Mapping[str, Any]) -> bool:
    """Is there no PowerShell parser on this host (not found / unusable language mode)?

    Only ``unavailable``: a helper that is merely slow to start or whose breaker is open on a host
    that does have PowerShell must keep failing the PowerShell tests where somebody can see it.
    """
    return status.get("state") == "unavailable"


def _why_none(total: int, platform: str) -> str:
    if total == 0:
        return "the policy has no tests: section; add tests so that a pass means something"
    where = "this platform" if platform == "all" else platform
    return f"the policy has {total} test(s), none of them applies to {where}"


# Event fields are attacker-controlled text: every printed field is cleaned and capped.
_TOOL_CHARS = 80
_ARGS_CHARS = 120
_PATH_CHARS = 200
_REASON_CHARS = 300


def _project_dir(payload: Mapping[str, Any]) -> tuple[str | None, str]:
    """The project directory the daemon would see, and where it came from.

    The hook client forwards ``CLAUDE_PROJECT_DIR`` as the event's ``project_dir``, so explain's
    own environment is asked first (as if it were the hook's), then the event file's
    ``project_dir``, then its ``cwd`` (what the pipeline falls back to).
    """
    from_env = os.environ.get("CLAUDE_PROJECT_DIR")
    if from_env:
        return from_env, "CLAUDE_PROJECT_DIR in this environment"
    from_event = payload.get("project_dir")
    if isinstance(from_event, str) and from_event:
        return from_event, "the event's project_dir"
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd:
        return cwd, "the event's cwd (no CLAUDE_PROJECT_DIR, no project_dir)"
    return None, "nowhere: no CLAUDE_PROJECT_DIR, project_dir or cwd"


def _runtime(policy: Policy, env: Mapping[str, str], home: str | None) -> tuple[Policy, str | None]:
    """The policy the daemon would run (machine-dependent rules added), and why that failed."""
    return pipeline.runtime_policy_checked(policy, env, home)


def cmd_explain(args: argparse.Namespace) -> int:
    """Explain one hook event with the REAL machine (this user's home and environment), the way
    the daemon would see it; ``--policy`` defaults to the active policy, else the shipped one."""
    from boundkeep.normalize import psparse

    psparse.warm_up(wait_s=10)
    try:
        if args.event == "-":
            raw = sys.stdin.buffer.read()
        else:
            with open(args.event, "rb") as handle:
                raw = handle.read()
        payload = json.loads(raw.decode("utf-8-sig"))
    except (OSError, ValueError) as exc:
        console.err(f"boundkeep explain: cannot read the event: {exc}")
        return EXIT_PROBLEM
    if not isinstance(payload, dict):
        console.err("boundkeep explain: the event must be a JSON object")
        return EXIT_PROBLEM
    platform = pipeline.local_platform()
    home = os.path.expanduser("~")
    active = args.policy or paths.policy_file()
    try:
        if args.policy or os.path.exists(active):
            policy = load_policy(active, home=home)
        else:
            policy = parse_policy_text(default_policy_text(), home=home)
    except (PolicyError, OSError) as exc:
        console.err(f"boundkeep explain: {exc}")
        return EXIT_PROBLEM
    project, project_source = _project_dir(payload)
    if project is not None:
        payload["project_dir"] = project
    else:
        payload.pop("project_dir", None)
    runtime, problem = _runtime(policy, os.environ, home)
    result = pipeline.review(payload, runtime, platform=platform, env=os.environ, home=home)
    shown_tool = printable(str(payload.get("tool_name")), _TOOL_CHARS)
    console.out(f"tool: {shown_tool}   platform: {platform}   policy: {printable(active, 300)}")
    console.out(f"project dir: {printable(project or '-', 300)} (from {project_source})")
    if problem:
        console.out(
            f"warning: {printable(problem, _REASON_CHARS)}; the daemon treats the policy as "
            "unusable and asks for every PreToolUse event"
        )
    for index, action in enumerate(result.actions):
        verdict = result.verdict.actions[index]
        name = printable(action.program or action.tool, _TOOL_CHARS)
        sub = f" {printable(action.subcommand, _TOOL_CHARS)}" if action.subcommand else ""
        console.out(f"action {index}: {name}{sub}  -> {verdict.decision}")
        if action.args:
            console.out(f"    args: {printable(' '.join(action.args), _ARGS_CHARS)}")
        for ref in action.paths:
            unsure = " uncertain" if ref.uncertain else ""
            console.out(
                f"    path: {printable(repr(ref.raw), _PATH_CHARS)} -> "
                f"{printable(ref.key, _PATH_CHARS)} [{ref.access}] "
                f"inside_project={ref.inside_project}{unsure}"
            )
        if action.domains or action.network:
            hosts = ", ".join(action.domains) or "-"
            console.out(f"    network: {action.network} domains: {printable(hosts, _PATH_CHARS)}")
        if action.risk_tags:
            console.out(f"    tags: {printable(', '.join(action.risk_tags), _ARGS_CHARS)}")
        for hit in verdict.hits:
            rule = printable(hit.rule_id, _TOOL_CHARS)
            console.out(
                f"    rule {rule} ({hit.decision}): {printable(hit.reason or '-', _REASON_CHARS)}"
            )
        for reason in verdict.gray_reasons:
            console.out(f"    gray: {printable(reason, _REASON_CHARS)}")
    final = result.verdict
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        payload,
        mode="enforce",
        policy=runtime,
        policy_error=problem,
        platform=platform,
        env=os.environ,
        home=home,
    )
    rule_ids = printable(", ".join(final.rule_ids) or "-", 300)
    console.out(f"verdict: {final.decision}   rules: {rule_ids}")
    if decision.decision == protocol.DECISION_NONE:
        console.out("hook output: (nothing: no decision, Claude Code's own flow continues)")
    else:
        out = hook_main.render_pre_decision(decision.decision, decision.reason)
        console.out(f"hook output: {out.decode('ascii').strip()}")
    return EXIT_OK
