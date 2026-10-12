"""The ``boundkeep`` command line: init, uninstall, serve, mode, log, doctor.

``init`` validates everything first (hook command, settings file, policy, a self check that
launches the hook the way Claude Code does) and only then writes anything, so a failure leaves the
machine as it was. All text I/O names its encoding: on a Chinese Windows the default code page
would silently misread UTF-8 text (docs/hook-behavior.md E18).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from collections.abc import Sequence

from boundkeep import __version__, console, fsperm, hookcmd, install, paths, settings_io
from boundkeep.daemon.lifecycle import AlreadyRunning, SingleInstance, install_stop_handlers
from boundkeep.daemon.server import Daemon
from boundkeep.ipc.base import ServerStartError
from boundkeep.ipc.endpoint import EndpointError, new_endpoint, read_endpoint, write_endpoint
from boundkeep.logstore import AuditLog
from boundkeep.policy import (
    Mode,
    PolicyError,
    default_policy_text,
    load_policy,
    parse_policy_text,
    set_mode,
    taint_sources_to_matcher,
    write_default_policy,
)
from boundkeep.settings_io import SettingsError

EXIT_OK = 0
EXIT_PROBLEM = 1


def _fail(message: str) -> int:
    console.err(f"boundkeep: {message}")
    return EXIT_PROBLEM


def _printable(text: str) -> str:
    """``text`` with control, bidi and other non-printing characters replaced by ``?``.

    Audit records hold text the agent controls; printed raw it could clear the screen, retitle the
    window or forge log lines.
    """
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def printable(text: str, limit: int | None = None) -> str:
    """:func:`_printable` for text of any length: cut to ``limit`` characters (with ``...``)."""
    shown = text if limit is None or len(text) <= limit else text[:limit] + "..."
    return _printable(shown)


def _project_dir(args: argparse.Namespace) -> str:
    return os.path.abspath(args.project_dir or os.getcwd())


# --------------------------------------------------------------------------------------------
# init
# --------------------------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    home = paths.home_dir()
    try:
        command = hookcmd.resolve_hook_command(args.hook_style, args.python)
    except hookcmd.HookCommandError as exc:
        console.err("boundkeep init: the hook command cannot be used:")
        for problem in exc.problems:
            console.err(f"  - {problem}")
        return EXIT_PROBLEM
    command = install.HookCommand(command.command, hookcmd.with_home(command.base_args, home))
    try:
        if args.scope == "project" and not os.path.isdir(_project_dir(args)):
            return _fail(f"the project directory {_project_dir(args)} does not exist")
        settings_path = install.resolve_settings_path(
            args.scope, cwd=_project_dir(args), env=os.environ
        )
        doc = settings_io.load_settings(settings_path)
        install.load_manifest(paths.manifest_file(home))  # damaged: stop before writing anything
    except (SettingsError, ValueError) as exc:
        return _fail(str(exc))
    policy_path = paths.policy_file(home)
    old_problem: str | None = None
    try:
        if args.reset_policy:
            # The file in place is about to be replaced, so it does not have to load: whatever is
            # wrong with it is what --reset-policy is for. The new policy's taint sources count.
            policy = parse_policy_text(default_policy_text())
            old_problem = _policy_problem(policy_path)
        elif os.path.exists(policy_path):
            policy = load_policy(policy_path)
        else:
            policy = parse_policy_text(default_policy_text())
        post_matcher = taint_sources_to_matcher(policy.taint.sources)
    except PolicyError as exc:
        return _fail(
            f"policy: {exc}\n  fix {policy_path} by hand, or run 'boundkeep init --reset-policy' "
            "to replace it with the default policy (a backup is kept)"
        )
    try:
        groups = install.build_hook_groups(command, post_matcher=post_matcher)
        merged, report = install.merge_hooks(doc.data, groups)
    except (SettingsError, ValueError) as exc:
        return _fail(str(exc))

    # Launch the hook exactly as Claude Code will, in a scratch home so the check neither needs
    # nor writes to the real one. A hook that cannot work would leave the gate silently open.
    with tempfile.TemporaryDirectory(prefix="boundkeep-selfcheck-") as scratch:
        scratch_command = install.HookCommand(
            command.command, hookcmd.with_home(command.base_args, scratch)
        )
        results = install.run_self_check(
            scratch_command, env={**os.environ, paths.HOME_ENV: scratch}
        )
    failed = [r for r in results if not r.ok]
    if failed:
        console.err("boundkeep init: the hook command failed its self check; nothing was written:")
        for r in failed:
            console.err(f"  - {r.subcommand} ({r.env_variant}): {r.detail}")
        return EXIT_PROBLEM

    console.out(f"hook command : {command.command} {' '.join(command.base_args)}".rstrip())
    console.out(f"settings file: {settings_path} ({args.scope} scope)")
    unchanged = (
        report.unchanged and not doc.had_bom
    )  # a BOM is rewritten even if the hooks are fine
    if unchanged:
        console.out("hook entries : already installed and up to date")
    else:
        console.out(
            f"hook entries : add {', '.join(report.added) or '-'}; "
            f"replace {', '.join(report.replaced) or '-'}"
        )
    if doc.had_bom:
        console.out("note         : the settings file had a UTF-8 BOM; it is rewritten without one")
    if args.dry_run:
        if args.reset_policy and os.path.exists(policy_path):
            mode = _current_mode(policy_path)
            why = f"; the current file does not load: {old_problem}" if old_problem else ""
            console.out(
                f"policy       : would be reset to the default policy (mode {mode}{why}); "
                "a backup is kept"
            )
        console.out("dry run      : nothing was written")
        return EXIT_OK

    try:
        return _apply_init(args, home, settings_path, doc, merged, unchanged, command, post_matcher)
    except (OSError, SettingsError) as exc:
        return _fail(f"init stopped part-way ({type(exc).__name__}: {exc}); run it again")


def _apply_init(
    args: argparse.Namespace,
    home: str,
    settings_path: str,
    doc: settings_io.SettingsDoc,
    merged: dict[str, object],
    unchanged: bool,
    command: install.HookCommand,
    post_matcher: str,
) -> int:
    for directory in (home, paths.log_dir(home), paths.backups_dir(home)):
        fsperm.ensure_private_dir(directory)
    endpoint_path = paths.endpoint_file(home)
    damaged = False
    if os.path.exists(endpoint_path) and not args.rotate_endpoint:
        try:
            read_endpoint(endpoint_path)
        except EndpointError as exc:
            damaged = True
            console.out(f"endpoint     : the endpoint file was damaged ({exc}); writing a new one")
    if args.rotate_endpoint or damaged or not os.path.exists(endpoint_path):
        if (args.rotate_endpoint or damaged) and os.path.exists(endpoint_path):
            console.out(
                "endpoint     : replaced; restart 'boundkeep serve' so it listens on the new name"
            )
        write_endpoint(endpoint_path, new_endpoint(home))
    fsperm.ensure_private_file(endpoint_path)
    policy_path = paths.policy_file(home)
    if args.reset_policy and os.path.exists(policy_path):
        _reset_policy(policy_path, home)
    elif write_default_policy(policy_path):
        console.out(f"policy       : wrote the default policy to {policy_path}")
    else:
        try:
            if not load_policy(policy_path, home=os.path.expanduser("~")).rules:
                console.out(
                    "policy       : your policy has no rules (written by M0), so every shell "
                    "command asks; run 'boundkeep init --reset-policy' to install the default rules"
                )
        except PolicyError:
            pass  # doctor reports an unusable policy
    fsperm.ensure_private_file(policy_path)

    if not unchanged:
        backup = settings_io.backup_file(settings_path, paths.backups_dir(home))
        settings_io.write_atomic(
            settings_path, settings_io.render_settings(doc, merged), expect_raw=doc.raw
        )
        console.out(f"backup       : {backup}" if backup else "backup       : (file did not exist)")

    manifest_path = paths.manifest_file(home)
    record = install.InstallRecord(
        settings_path=settings_path,
        scope=args.scope,
        created_file=not doc.exists,
        hook_command=command.command,
        hook_args=command.base_args,
        post_matcher=post_matcher,
        installed_at=_utc_now(),
    )
    records = install.upsert_record(install.load_manifest(manifest_path), record)
    install.save_manifest(manifest_path, records)
    fsperm.ensure_private_file(manifest_path)

    endpoint = read_endpoint(endpoint_path)
    console.out(f"ipc endpoint : {endpoint.address}")
    console.out("")
    console.out("Next: start the daemon with 'boundkeep serve', then run 'boundkeep doctor'.")
    for line in _epilogue(policy_path):
        console.out(line)
    return EXIT_OK


def _epilogue(policy_path: str) -> list[str]:
    """What the user should know after init, as true of the policy that is now in place."""
    try:
        policy = load_policy(policy_path, home=os.path.expanduser("~"))
    except (PolicyError, OSError) as exc:
        summary = (
            f"Policy: it could not be loaded ({exc}); every shell command asks until it is "
            "fixed ('boundkeep doctor' says what is wrong)."
        )
    else:
        summary = (
            f"Policy: {len(policy.rules)} rules loaded (mode: {policy.mode}). Every command or "
            "tool call that no rule decides asks for confirmation. To watch what boundkeep "
            "would do before it asks or blocks anything, run 'boundkeep mode audit-only' first "
            "(decisions are then only logged; 'boundkeep mode enforce' switches back)."
        )
    return [
        summary,
        "PowerShell commands are not parsed until M1b, so no rule can judge them: every "
        "PowerShell command asks for confirmation.",
        "See what the rules do with 'boundkeep test' (the policy's own tests) and "
        "'boundkeep explain <event.json>' (why one event got its verdict).",
        "Until the daemon runs, every tool call asks for confirmation (fail closed).",
    ]


def _policy_problem(policy_path: str) -> str | None:
    """Why the policy file does not load, or None when it is fine or does not exist."""
    if not os.path.exists(policy_path):
        return None
    try:
        load_policy(policy_path, home=os.path.expanduser("~"))
    except PolicyError as exc:
        return str(exc).splitlines()[0] if str(exc) else "invalid"
    return None


def _current_mode(policy_path: str) -> Mode:
    """The mode of the policy in place, 'enforce' when it does not load."""
    try:
        return load_policy(policy_path, home=os.path.expanduser("~")).mode
    except PolicyError:
        return "enforce"


def _reset_policy(policy_path: str, home: str) -> None:
    """Replace the policy with the shipped default, keeping a backup and the current mode.

    Works on a policy that does not load: the old file is the backup, the mode falls back to
    enforce.
    """
    problem = _policy_problem(policy_path)
    mode = _current_mode(policy_path)
    backup = settings_io.backup_file(policy_path, paths.backups_dir(home))
    write_default_policy(policy_path, overwrite=True)
    if mode != "enforce":
        set_mode(policy_path, mode)
    why = f"; the old file did not load: {problem}" if problem else ""
    console.out(f"policy       : reset to the default policy (mode {mode}{why}); backup: {backup}")


def _utc_now() -> str:
    import datetime

    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------------------------
# uninstall
# --------------------------------------------------------------------------------------------


def cmd_uninstall(args: argparse.Namespace) -> int:
    home = paths.home_dir()
    try:
        settings_path = install.resolve_settings_path(
            args.scope, cwd=_project_dir(args), env=os.environ
        )
        doc = settings_io.load_settings(settings_path)
    except (SettingsError, ValueError) as exc:
        return _fail(str(exc))
    manifest_path = paths.manifest_file(home)
    try:
        records = install.load_manifest(manifest_path)
    except SettingsError as exc:
        console.err(f"boundkeep: warning: {exc}; removing entries by shape instead")
        records = []
    record = install.find_record(records, settings_path)

    if not doc.exists:
        console.out(f"{settings_path} does not exist; nothing to remove")
    else:
        remaining, removed = install.remove_hooks(doc.data)
        if removed == 0:
            console.out(f"no boundkeep hook entries in {settings_path}")
        else:
            try:
                backup = settings_io.backup_file(settings_path, paths.backups_dir(home))
                if not remaining and record is not None and record.created_file:
                    os.unlink(settings_path)  # init created it and nothing else is in it
                    console.out(f"removed {removed} hook entries and the file init created")
                else:
                    settings_io.write_atomic(
                        settings_path,
                        settings_io.render_settings(doc, remaining),
                        expect_raw=doc.raw,
                    )
                    console.out(f"removed {removed} hook entries from {settings_path}")
                if backup:
                    console.out(f"backup: {backup}")
            except (OSError, SettingsError) as exc:
                return _fail(f"cannot update {settings_path}: {exc}")
    if record is not None:
        try:
            install.save_manifest(manifest_path, install.drop_record(records, settings_path))
        except (OSError, SettingsError) as exc:
            return _fail(f"cannot update the install manifest: {exc}")
    console.out("Restart open Claude Code sessions so they stop using the old hook configuration.")
    return EXIT_OK


# --------------------------------------------------------------------------------------------
# serve
# --------------------------------------------------------------------------------------------


def cmd_serve(args: argparse.Namespace) -> int:
    home = paths.home_dir()
    try:
        endpoint = read_endpoint(paths.endpoint_file(home))
    except EndpointError as exc:
        return _fail(str(exc))
    for problem in fsperm.check_private(home):
        console.err(f"boundkeep: {problem.severity}: {problem.message}")
    lock = SingleInstance(paths.lock_file(home), paths.pid_file(home))
    try:
        lock.acquire()
    except AlreadyRunning as exc:
        return _fail(str(exc))
    except OSError as exc:
        return _fail(f"cannot take the daemon lock in {home} ({exc})")
    try:
        daemon = Daemon(
            endpoint, home=home, instances=args.instances, report=console.BackgroundErr()
        )
        asyncio.run(_serve(daemon))
    except ServerStartError as exc:
        return _fail(str(exc))
    except KeyboardInterrupt:
        pass
    finally:
        lock.release()
    return EXIT_OK


async def _serve(daemon: Daemon) -> None:
    stop = asyncio.Event()
    restore = install_stop_handlers(asyncio.get_running_loop(), stop)
    console.out("boundkeep daemon: press Ctrl+C to stop")
    try:
        await daemon.serve(stop)
    finally:
        restore()


# --------------------------------------------------------------------------------------------
# mode, log
# --------------------------------------------------------------------------------------------


def cmd_mode(args: argparse.Namespace) -> int:
    policy_path = paths.policy_file()
    try:
        if args.value is not None:
            set_mode(policy_path, args.value)
        policy = load_policy(policy_path)
    except PolicyError as exc:
        return _fail(f"policy: {exc}")
    console.out(f"mode: {policy.mode}")
    if args.value is not None:
        console.out("A running daemon picks the change up on the next event.")
    return EXIT_OK


def _summary(record: dict[str, object]) -> str:
    """What the text log line shows after the tool: matched rules, then the command or the reason.

    ``--json`` has every field; this is the quick view (rule ids tell you WHY at a glance).
    """
    head = ""
    rules = record.get("rules")
    if isinstance(rules, list) and rules:
        head = "[" + ",".join(_printable(str(r))[:40] for r in rules[:3]) + "] "
    for key in ("command", "reason", "local_reason"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return head + _printable(value)[:100]
    gray = record.get("gray_reasons")
    if isinstance(gray, list) and gray:
        return head + "gray: " + _printable("; ".join(str(g) for g in gray[:3]))[:100]
    chars = record.get("prompt_chars")
    if isinstance(chars, int):
        return f"prompt of {chars} characters"
    verdict = record.get("verdict")
    return head + (f"({_printable(str(verdict))})" if isinstance(verdict, str) else "")


def cmd_log(args: argparse.Namespace) -> int:
    log = AuditLog(paths.audit_log_file())
    if args.purge:
        console.out(f"removed {log.purge()} log file(s)")
        return EXIT_OK
    for record in log.tail(args.tail):
        if args.json:
            console.out(json.dumps(record, ensure_ascii=False))
            continue
        stamp = _printable(str(record.get("ts", ""))[:23])
        event = _printable(str(record.get("event", "")))
        decision = _printable(str(record.get("decision", record.get("action", ""))))
        tool = _printable(str(record.get("tool_name", "")))
        console.out(f"{stamp}  {event:<6} {decision:<5} {tool:<12} {_summary(record)}")
    if log.last_error:
        console.err(f"boundkeep: warning: {log.last_error}")
    return EXIT_OK


def cmd_test(args: argparse.Namespace) -> int:
    from boundkeep import policycli

    return policycli.cmd_test(args)


def cmd_explain(args: argparse.Namespace) -> int:
    from boundkeep import policycli

    return policycli.cmd_explain(args)


def cmd_doctor(args: argparse.Namespace) -> int:
    from boundkeep import doctor

    return doctor.run(args)


# --------------------------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------------------------


def _add_scope_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--scope",
        choices=("project", "user"),
        default="project",
        help="which Claude Code settings file: project (.claude/settings.json in --project-dir) "
        "or user (~/.claude/settings.json); default: project",
    )
    parser.add_argument(
        "--project-dir",
        help="the project directory for --scope project (default: current directory)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="boundkeep",
        description="Runtime guardrail for coding agents (Claude Code first). Not a sandbox.",
    )
    parser.add_argument("--version", action="version", version=f"boundkeep {__version__}")
    parser.add_argument(
        "--home", help="boundkeep home directory (default: $BOUNDKEEP_HOME or ~/.boundkeep)"
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

    p = sub.add_parser("init", help="install the hooks into a Claude Code settings file")
    _add_scope_options(p)
    p.add_argument(
        "--hook-style",
        choices=(hookcmd.STYLE_PYTHON, hookcmd.STYLE_LAUNCHER),
        default=hookcmd.STYLE_PYTHON,
        help="python: python.exe -I -S hook_client.py (default, fastest); "
        "launcher: the boundkeep-hook console script",
    )
    p.add_argument("--python", help="interpreter for --hook-style python (absolute path)")
    p.add_argument(
        "--dry-run", action="store_true", help="validate and show the plan, write nothing"
    )
    p.add_argument(
        "--rotate-endpoint", action="store_true", help="generate a new random pipe or socket name"
    )
    p.add_argument(
        "--reset-policy",
        action="store_true",
        help="replace policy.yaml with the shipped default rules (keeps a backup and the mode)",
    )
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("uninstall", help="remove boundkeep's hook entries from a settings file")
    _add_scope_options(p)
    p.set_defaults(func=cmd_uninstall)

    p = sub.add_parser("serve", help="run the resident daemon in this terminal")
    p.add_argument("--instances", type=int, default=8, help="pipe instances (Windows), default 8")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("mode", help="show or set the mode: enforce or audit-only")
    p.add_argument("value", nargs="?", choices=("enforce", "audit-only"))
    p.set_defaults(func=cmd_mode)

    p = sub.add_parser("log", help="show the recent audit log")
    p.add_argument("--tail", type=int, default=20, help="number of records (default 20)")
    p.add_argument("--json", action="store_true", help="one JSON object per line")
    p.add_argument("--purge", action="store_true", help="delete the audit log")
    p.set_defaults(func=cmd_log)

    p = sub.add_parser(
        "test", help="run the policy's built-in tests (the real pipeline, fake machine)"
    )
    p.add_argument("--policy", help="a policy file (default: the shipped default policy)")
    p.add_argument(
        "--platform",
        choices=("windows", "posix", "all"),
        default="all",
        help="run the lexical tests with Windows or POSIX semantics (default: both)",
    )
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("explain", help="explain the verdict for one hook event (a JSON file or -)")
    p.add_argument("event", help="a PreToolUse event as JSON; '-' reads stdin")
    p.add_argument("--policy", help="a policy file (default: the active policy)")
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser("doctor", help="check that the gate is installed and cannot be silently off")
    p.add_argument("--project-dir", help="the project to check (default: current directory)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_doctor)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    console.configure()
    args = build_parser().parse_args(argv)
    if args.home:
        os.environ[paths.HOME_ENV] = os.path.abspath(args.home)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        console.err("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
