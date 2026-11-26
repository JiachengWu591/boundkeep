"""``boundkeep policy``: propose, check, write and undo policy rules (PROJECT_SPEC.md §8.1, M4).

* ``prompt "<sentence>"`` prints the prompt to paste into any LLM tool (no network);
* ``check FILE [--apply]`` checks a proposal the user saved, and with ``--apply`` writes it;
* ``add "<sentence>"`` asks the configured backend for a proposal, then works like ``check``;
* ``undo`` restores the policy as it was before the newest write not undone yet;
* ``history`` lists the writes and undos.

Writing changes the gate, so ``--apply``, ``add`` and ``undo`` do what ``trust add`` does: they
refuse inside a process Claude Code started and without a real console, show everything and need
the word ``yes``. There is no ``--yes``: without a console the commands stop after the checks.
The default policy also refuses every ``boundkeep policy`` call of the agent (the replay prints
other sessions' commands from the audit log, and ``add`` costs money).
"""

from __future__ import annotations

import argparse
import datetime
import functools
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

from boundkeep import console, paths, trust
from boundkeep.audit import send_gate
from boundkeep.audit.backends import build_proposer
from boundkeep.audit.backends.base import BackendError
from boundkeep.compiler import checks, proposal, replay, writer
from boundkeep.compiler.prompt import OFFLINE_HEADER, offline_text
from boundkeep.evalkit import dataset
from boundkeep.logstore import AuditLog
from boundkeep.policy import PolicyError, parse_policy_text

EXIT_OK: Final = 0
EXIT_PROBLEM: Final = 1
DEFAULT_TIMEOUT_S: Final = 60.0
MIN_TIMEOUT_S: Final = 5.0
MAX_TIMEOUT_S: Final = 300.0
_MAX_FILE_BYTES: Final = 4 * proposal.MAX_PROPOSAL_CHARS
_TEXT_SHOWN: Final = 300


def _fail(message: str) -> int:
    console.err(f"boundkeep policy: {message}")
    return EXIT_PROBLEM


def _clean(text: str, limit: int = _TEXT_SHOWN) -> str:
    out = "".join(ch if ch.isprintable() else "?" for ch in text)
    return out if len(out) <= limit else out[: limit - 3] + "..."


def _policy_path(args: argparse.Namespace) -> str:
    return str(args.policy) if getattr(args, "policy", None) else paths.policy_file()


def _home() -> str:
    return trust.home_for_policy()


def _console_ok() -> bool:
    return trust._stdin_is_tty()


def _write_guard(what: str) -> str | None:
    """Why ``what`` must not write here (the two checks of ``trust add``), or None."""
    marker = trust.agent_environment()
    if marker is not None:
        return (
            f"{what} refuses to run inside a process Claude Code started ({marker} is set): it "
            "changes the gate, so it is a command for you, in your own terminal"
        )
    if not _console_ok():
        return (
            f"{what} needs an interactive terminal (it changes the gate, so it is not run from "
            "a pipe, a script or by the agent); the checks above are all it did"
        )
    return None


def _users_only(
    command: Callable[[argparse.Namespace], int],
) -> Callable[[argparse.Namespace], int]:
    """Every ``policy`` command refuses inside a process Claude Code started, whatever the policy
    says (a policy file installed before spec revision 44 does not refuse the agent's call):
    ``check`` and ``add`` print other sessions' commands from the audit log, ``add`` spends the
    user's money, and the rest change or show the gate's rules."""

    @functools.wraps(command)
    def run(args: argparse.Namespace) -> int:
        marker = trust.agent_environment()
        if marker is not None:
            return _fail(
                f"refused inside a process Claude Code started ({marker} is set): 'boundkeep "
                "policy' is a command for you, in your own terminal. If this IS your own "
                f"terminal, start it from outside Claude Code or unset {marker}"
            )
        return command(args)

    return run


def _confirm(question: str) -> bool:
    try:
        return input(f"{question} Type 'yes' to go on: ").strip().lower() == "yes"
    except (EOFError, KeyboardInterrupt):
        return False


def _ps_ready() -> bool:
    from boundkeep.evalkit.runner import ps_helper_ready

    try:
        return ps_helper_ready()
    except Exception:  # noqa: BLE001 - no parser is "skip the PowerShell cases", visibly
        return False


def _log_record(entry: writer.Entry) -> None:
    record: dict[str, object] = {
        "ts": datetime.datetime.now(datetime.UTC).isoformat(timespec="milliseconds"),
        "event": "policy",
        "action": entry.op,
        "source": entry.source,
        "rules": list(entry.rules),
        "tests": entry.tests,
        "before_sha256": entry.before_sha256,
        "after_sha256": entry.after_sha256,
        "backup": entry.backup,
    }
    if not AuditLog(paths.audit_log_file()).append(record):
        console.err("boundkeep policy: warning: the audit log could not record the change")


# --------------------------------------------------------------------------- reading


def _read_current(policy_path: str) -> tuple[bytes, str, str]:
    data, bom, text = writer.current_bytes(policy_path)
    parse_policy_text(text, home=_home())  # an unusable policy is an error, with its message
    return data, bom, text


def _rule_ids(text: str) -> list[str]:
    policy = parse_policy_text(text, home=_home())
    return [rule.id for rule in policy.rules]


def _read_proposal_file(path: str) -> str:
    with open(path, "rb") as handle:
        data = handle.read(_MAX_FILE_BYTES + 1)
    if len(data) > _MAX_FILE_BYTES:
        raise proposal.ProposalError(f"the file is larger than {_MAX_FILE_BYTES} bytes")
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise proposal.ProposalError("the file is not valid UTF-8") from None


# --------------------------------------------------------------------------- the report


def _print_report(
    prop: proposal.Proposal, report: checks.Report, sections: list[replay.Section]
) -> None:
    out = console.out
    out(f"== proposal from {report.source}")
    if prop.summary:
        out(f"summary (the proposer's words, not verified): {_clean(prop.summary)}")
    if prop.impact:
        out(f"impact (the proposer's words, not verified): {_clean(prop.impact, 600)}")
    if report.new_text is not None:
        out("")
        out("== rules to add (after the last rule of the policy)")
        out(report.added_rules_text)
        out("")
        out("== tests to add (after the last test of the policy)")
        out(report.added_tests_text)
        if report.expect_updates:
            out("")
            out("== existing tests whose expect is rewritten (a new rule makes them stricter)")
            seen: set[int] = set()
            for run in report.changed:
                if run.index not in seen:
                    seen.add(run.index)
                    out(f"  #{run.index} {run.shown}: expect {run.expect} -> {run.got}")
    new_runs = [r for r in report.runs if r.new]
    out("")
    out(
        f"== tests: {sum(1 for r in new_runs if r.outcome == 'pass')} proposed test run(s) pass, "
        f"{sum(1 for r in new_runs if r.outcome == 'corrected')} written with the real verdict, "
        f"{sum(1 for r in new_runs if r.outcome == 'fail')} fail; the policy's "
        f"{report.old_tests} existing test(s) ran on both fake machines"
        + (
            f"; {report.skipped_powershell} PowerShell run(s) skipped (no parser)"
            if report.skipped_powershell
            else ""
        )
    )
    out(f"== canaries: {report.canaries_checked} judgment(s)")
    for section in sections:
        out("")
        out(f"== replay: {section.name}")
        if not section.available:
            out(f"  {section.note}")
            continue
        out(
            f"  judged {section.judged}; newly asked or denied {len(section.tighter)}; newly "
            f"allowed or loosened {len(section.looser)}"
        )
        for sign, changes in (("+", section.tighter), ("-", section.looser)):
            for change in changes[: replay.EXAMPLES]:
                out(f"  {sign} {change.label}: {change.old} -> {change.new}")
            if len(changes) > replay.EXAMPLES:
                out(f"  {sign} ... and {len(changes) - replay.EXAMPLES} more")
        if section.note:
            out(f"  note: {section.note}")
    out("")
    out("== findings")
    order = {"refuse": 0, "warn": 1, "note": 2}
    shown = sorted(report.findings, key=lambda f: order[f.level])
    if not shown:
        out("  none")
    for finding in shown:
        label = {"refuse": "REFUSED", "warn": "WARNING", "note": "note"}[finding.level]
        out(f"  {label} [{finding.code}] {finding.message}")
    refused = sum(1 for f in report.findings if f.level == "refuse")
    warned = sum(1 for f in report.findings if f.level == "warn")
    out("")
    if refused:
        out(f"== result: refused ({refused} problem(s)); nothing can be written")
    else:
        out(f"== result: no refusal, {warned} warning(s)")


def _evaluate(
    policy_path: str,
    prop: proposal.Proposal,
    *,
    source: str,
    log_limit: int,
    dataset_root: Path,
) -> tuple[checks.Report, list[replay.Section], bytes, str]:
    data, bom, text = _read_current(policy_path)
    stamp = time.strftime("%Y-%m-%d %H:%M")
    note = f"added by 'boundkeep policy' {stamp}, from {source}"
    ps_ready = _ps_ready()
    report = checks.check(
        text,
        prop,
        source=source,
        ps_ready=ps_ready,
        note=note,
        real_home=_home(),
        progress=lambda step: console.out(f"... {step}"),
    )
    sections: list[replay.Section] = []
    if report.new_text is not None and not report.refused:
        console.out("... replaying past verdicts")
        old = checks.Judge(text)
        candidate = checks.Judge(report.new_text)
        sections = replay.replay(
            text,
            report.new_text,
            old,
            candidate,
            ps_ready=ps_ready,
            log_limit=log_limit,
            dataset_root=dataset_root,
        )
        report.findings.extend(replay.findings(sections))
    return report, sections, data, bom


def _apply(
    policy_path: str,
    prop: proposal.Proposal,
    report: checks.Report,
    before: bytes,
    bom: str,
    source: str,
) -> int:
    reason = _write_guard("writing the policy")
    if reason is not None:
        return _fail(reason)
    assert report.new_text is not None
    warned = sum(1 for f in report.findings if f.level == "warn")
    rewritten = (
        f", rewrite the expect of {len(report.expect_updates)} existing test(s)"
        if report.expect_updates
        else ""
    )
    question = (
        f"Add {len(prop.rules)} rule(s) and {len(report.tests_to_write)} test(s){rewritten} to "
        f"{policy_path}" + (f" despite {warned} warning(s)?" if warned else "?")
    )
    if not _confirm(question):
        return _fail("not written: confirmation not given")
    try:
        entry = writer.apply(
            policy_path,
            expected_before=before,
            new_text=report.new_text,
            bom=bom,
            source=source,
            rule_ids=prop.rule_ids,
            tests=len(report.tests_to_write),
        )
    except writer.NotRecorded as exc:
        _log_record(exc.entry)
        return _fail(
            f"WRITTEN, but {exc}: 'boundkeep policy undo' will not find this change; the "
            f"policy as it was is kept at {exc.backup}"
        )
    except (writer.MergeError, PolicyError, OSError) as exc:
        return _fail(f"not written: {exc}")
    _log_record(entry)
    console.out(f"written: {policy_path}")
    console.out(f"backup : {os.path.join(writer.history_dir(), entry.backup)}")
    console.out("'boundkeep policy undo' puts the previous policy back.")
    console.out("A running daemon picks the change up on the next event.")
    return EXIT_OK


# --------------------------------------------------------------------------- commands


@_users_only
def cmd_prompt(args: argparse.Namespace) -> int:
    policy_path = _policy_path(args)
    try:
        _, _, text = _read_current(policy_path)
        ids = _rule_ids(text)
    except PolicyError as exc:
        return _fail(f"policy: {exc}")
    gated = send_gate.gate_policy_request(args.text, ids, home=_home(), secrets=_secret_values())
    if gated.request is None:
        return _fail(f"the description cannot be used: {gated.refused}")
    body = offline_text(gated.request.system_prompt, gated.request.content)
    if args.out:
        try:
            with open(args.out, "x", encoding="utf-8", newline="\n") as handle:
                handle.write(body)
        except OSError as exc:
            return _fail(f"cannot write {args.out} ({exc.strerror or type(exc).__name__})")
        console.out(f"written: {args.out}")
        console.out(OFFLINE_HEADER.replace("everything below this line", "the file's text"))
        return EXIT_OK
    console.out(OFFLINE_HEADER)
    console.out("-" * 72)
    console.out(body)
    return EXIT_OK


@_users_only
def cmd_check(args: argparse.Namespace) -> int:
    policy_path = _policy_path(args)
    source = f"file {_clean(os.path.basename(args.file), 80)}"
    try:
        prop = proposal.parse_proposal_text(_read_proposal_file(args.file))
    except proposal.ProposalError as exc:
        return _fail(f"{args.file}: {exc}")
    except OSError as exc:
        return _fail(f"cannot read {args.file} ({exc.strerror or type(exc).__name__})")
    return _check_and_maybe_write(args, policy_path, prop, source, apply=args.apply)


def _check_and_maybe_write(
    args: argparse.Namespace,
    policy_path: str,
    prop: proposal.Proposal,
    source: str,
    *,
    apply: bool,
) -> int:
    try:
        report, sections, before, bom = _evaluate(
            policy_path,
            prop,
            source=source,
            log_limit=args.log_limit,
            dataset_root=Path(args.dataset) if args.dataset else dataset.DEFAULT_DIR,
        )
    except PolicyError as exc:
        return _fail(f"policy: {exc}")
    _print_report(prop, report, sections)
    if report.refused or report.new_text is None:
        return EXIT_PROBLEM
    if not apply:
        return EXIT_OK
    return _apply(policy_path, prop, report, before, bom, source)


@_users_only
def cmd_add(args: argparse.Namespace) -> int:
    policy_path = _policy_path(args)
    if not MIN_TIMEOUT_S <= args.timeout <= MAX_TIMEOUT_S:
        return _fail(f"--timeout must be between {MIN_TIMEOUT_S:g} and {MAX_TIMEOUT_S:g} seconds")
    try:
        _, _, text = _read_current(policy_path)
        policy = parse_policy_text(text, home=_home())
    except PolicyError as exc:
        return _fail(f"policy: {exc}")
    backend, why = build_proposer(policy.llm_audit)
    if backend is None:
        return _fail(
            f"{why}. Without a backend: 'boundkeep policy prompt \"...\"' prints a prompt to "
            "paste into any LLM tool, and 'boundkeep policy check <file>' checks its answer"
        )
    gated = send_gate.gate_policy_request(
        args.text, [rule.id for rule in policy.rules], home=_home(), secrets=_secret_values()
    )
    if gated.request is None or gated.payload is None:
        return _fail(f"nothing was sent: {gated.refused}")
    host = getattr(backend, "host", "?")
    console.out(f"sending to {host} (model {_clean(backend.model, 80)}):")
    console.out(f"  request: {_clean(str(gated.payload['request']), 600)}")
    console.out(f"  and the ids of the policy's {len(policy.rules)} rule(s); nothing else")
    try:
        result = backend.propose(gated.request, deadline=time.monotonic() + args.timeout)
    except BackendError as exc:
        return _fail(f"the backend failed ({exc.kind}): {_clean(exc.detail)}; nothing was written")
    usage = result.usage.as_record()
    console.out(
        f"answer in {result.latency_ms / 1000:.1f} s"
        + (f", tokens {usage}" if usage else "")
        + f", prompt {gated.request.prompt_hash[:16]}"
    )
    try:
        body = proposal.text_from_json(result.data)
    except proposal.ProposalError as exc:
        return _fail(f"the backend's proposal: {exc}")
    if args.out:
        try:
            with open(args.out, "x", encoding="utf-8", newline="\n") as handle:
                handle.write(body)
            console.out(f"proposal saved: {args.out} (edit it and run 'boundkeep policy check')")
        except OSError as exc:
            console.err(f"boundkeep policy: cannot save {args.out} ({type(exc).__name__})")
    try:
        prop = proposal.parse_proposal_text(body)
    except proposal.ProposalError as exc:
        return _fail(f"the backend's proposal is not usable: {exc}")
    source = f"{backend.name} {_clean(backend.model, 60)}"
    return _check_and_maybe_write(args, policy_path, prop, source, apply=not args.dry_run)


def _secret_values() -> list[str]:
    from boundkeep.audit.auditor import secret_values

    try:
        return list(secret_values(os.environ))
    except Exception:  # noqa: BLE001 - the gate still redacts; this is the extra check
        return []


@_users_only
def cmd_undo(args: argparse.Namespace) -> int:
    policy_path = _policy_path(args)
    reason = _write_guard("policy undo")
    if reason is not None:
        return _fail(reason)
    try:
        plan = writer.plan_undo(policy_path)
    except (writer.MergeError, PolicyError, OSError) as exc:
        return _fail(str(exc))
    target = plan.target
    console.out(f"undo the write of {target.ts} ({_clean(target.source, 120)})")
    console.out(f"  it added rule(s) {', '.join(target.rules) or '-'} and {target.tests} test(s)")
    console.out(f"  the policy goes back to the copy {target.backup}")
    if plan.changed_since:
        console.out(
            "  WARNING: the policy file was changed after that write; undoing it also drops "
            "those later changes (the current file is kept in the history as well)"
        )
    if not _confirm("Undo it?"):
        return _fail("not undone: confirmation not given")
    try:
        entry = writer.undo(policy_path, plan)
    except writer.NotRecorded as exc:
        _log_record(exc.entry)
        return _fail(
            f"UNDONE, but {exc}: a later undo will not see this one; the file it replaced "
            f"is kept at {exc.backup}"
        )
    except (writer.MergeError, PolicyError, OSError) as exc:
        return _fail(f"not undone: {exc}")
    _log_record(entry)
    console.out(f"undone: {policy_path} is the copy from before {target.ts}")
    return EXIT_OK


@_users_only
def cmd_history(args: argparse.Namespace) -> int:
    try:
        entries = writer.read_history()
    except (writer.MergeError, OSError) as exc:
        return _fail(str(exc))
    if not entries:
        console.out("no policy writes recorded")
        return EXIT_OK
    for entry in entries:
        what = (
            f"added {', '.join(entry.rules) or '-'} (+{entry.tests} tests)"
            if entry.op == "apply"
            else f"undid {entry.undoes}"
        )
        console.out(f"{entry.ts}  {entry.op:<5}  {what}  [{_clean(entry.source, 80)}]")
    return EXIT_OK


def add_parser(sub: Any) -> None:
    """Register ``policy`` (prompt / check / add / undo / history) on the top-level subparsers."""
    p = sub.add_parser(
        "policy",
        help="propose, check and add policy rules from a sentence; undo",
        description="Policy proposals (a user command: the agent must not run it). A proposal "
        "only adds rules and tests; it is checked, replayed and shown before anything is "
        "written, and writing needs a terminal and the word yes.",
    )
    inner = p.add_subparsers(dest="policy_command", required=True, metavar="action")

    def common(q: Any) -> None:
        q.add_argument("--policy", help="the policy file (default: boundkeep's own)")

    def replay_options(q: Any) -> None:
        q.add_argument(
            "--log-limit",
            type=int,
            default=replay.DEFAULT_LOG_LIMIT,
            help=f"replay this many of the newest logged tool calls (default "
            f"{replay.DEFAULT_LOG_LIMIT}; 0 skips the log)",
        )
        q.add_argument("--dataset", help="the evaluation set directory (default: the checkout's)")

    q = inner.add_parser("prompt", help="print a prompt to paste into any LLM tool (offline)")
    q.add_argument("text", help="the rule you want, in one sentence")
    q.add_argument("--out", help="write the prompt to this new file instead")
    common(q)
    q.set_defaults(func=cmd_prompt)

    q = inner.add_parser("check", help="check a proposal file; --apply to write it")
    q.add_argument("file", help="the proposal (YAML; a pasted ```yaml block is fine)")
    q.add_argument("--apply", action="store_true", help="write it after the checks (asks)")
    common(q)
    replay_options(q)
    q.set_defaults(func=cmd_check)

    q = inner.add_parser("add", help="ask the configured LLM backend for a proposal")
    q.add_argument("text", help="the rule you want, in one sentence")
    q.add_argument("--dry-run", action="store_true", help="stop after the checks")
    q.add_argument("--out", help="also save the proposal (YAML) to this new file")
    q.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_S,
        help=f"seconds for the backend (default {DEFAULT_TIMEOUT_S:g})",
    )
    common(q)
    replay_options(q)
    q.set_defaults(func=cmd_add)

    q = inner.add_parser("undo", help="put back the policy from before the newest write")
    common(q)
    q.set_defaults(func=cmd_undo)

    q = inner.add_parser("history", help="list the writes and undos")
    q.set_defaults(func=cmd_history)
