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
    try:
        policy = (
            load_policy(policy_path)
            if os.path.exists(policy_path)
            else parse_policy_text(default_policy_text())
        )
        post_matcher = taint_sources_to_matcher(policy.taint.sources)
    except PolicyError as exc:
        return _fail(f"policy: {exc}")
    try:
        groups = install.build_hook_groups(command, post_matcher=post_matcher)
        merged, report = install.merge_hooks(doc.data, groups)
    except (SettingsError, ValueError) as exc:
        return _fail(str(exc))

    # Launch the hook exactly as Claude Code will, in a scratch home so the check neither needs
    # nor writes to the real one. A hook that cannot work would leave the gate silently open.
    with tempfile.TemporaryDirectory(prefix="boundkeep-selfcheck-") as scratch:
        results = install.run_self_check(command, env={**os.environ, paths.HOME_ENV: scratch})
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
    if write_default_policy(policy_path):
        console.out(f"policy       : wrote the default policy to {policy_path}")
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
    console.out(
        "M0 only blocks commands that contain BOUNDKEEP_CANARY; real rules arrive in M1. "
        "Until the daemon runs, every tool call asks for confirmation (fail closed)."
    )
    return EXIT_OK


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
    for key in ("command", "reason", "local_reason"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return _printable(value)[:100]
    chars = record.get("prompt_chars")
    return f"prompt of {chars} characters" if isinstance(chars, int) else ""


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
