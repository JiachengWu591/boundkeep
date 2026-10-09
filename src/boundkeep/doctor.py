"""``boundkeep doctor``: is the gate installed, and can it be silently off?

Every way the gate can fail without a sound is a check here: a hook command that cannot start,
``disableAllHooks`` in any settings layer, hook entries edited or removed, a narrowed matcher, a
daemon nobody started, managed settings that drop user and project hooks, a private directory that
is not private. Claude Code itself says nothing about any of them (M0a E6, E12, E22), so this is
the only place a user can find out. A check that crashes is reported as a failure, never skipped.
"""

from __future__ import annotations

import argparse
import functools
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from boundkeep import (
    claude_settings,
    console,
    fsperm,
    hook_main,
    hookcmd,
    install,
    ownhook,
    paths,
    protocol,
    settings_io,
)
from boundkeep.ipc import client as ipc_client
from boundkeep.ipc.endpoint import TRANSPORT_NAMED_PIPE, Endpoint, EndpointError, read_endpoint
from boundkeep.logstore import AuditLog
from boundkeep.policy import PolicyError, load_policy

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"
_PING_TIMEOUT_S = 3.0
_MAX_CLAUDE_JSON_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str
    fix: str = ""


@dataclass(frozen=True)
class Layer:
    name: str
    path: str
    doc: settings_io.SettingsDoc | None
    error: str | None


# --------------------------------------------------------------------------------------------
# Individual checks
# --------------------------------------------------------------------------------------------


def check_python() -> list[Check]:
    version = ".".join(str(part) for part in sys.version_info[:3])
    if sys.version_info[:2] < hookcmd.MIN_PYTHON:
        return [Check("python", FAIL, f"Python {version}; 3.11 or newer is required")]
    return [Check("python", OK, f"Python {version}")]


def _problems_to_checks(name: str, what: str, problems: list[fsperm.PermProblem]) -> list[Check]:
    if not problems:
        return [Check(name, OK, f"{what} is private to this user")]
    checks: list[Check] = []
    for problem in problems:
        status = FAIL if problem.severity == "error" else WARN
        checks.append(Check(name, status, f"{what}: {problem.message}"))
    return checks


def check_files(home: str) -> list[Check]:
    if not os.path.isdir(home):
        return [Check("home", FAIL, f"{home} does not exist", "run 'boundkeep init'")]
    checks = _problems_to_checks("home", f"the home directory {home}", fsperm.check_private(home))
    for label, path in (
        ("endpoint file", paths.endpoint_file(home)),
        ("policy file", paths.policy_file(home)),
        ("install manifest", paths.manifest_file(home)),
        ("log directory", paths.log_dir(home)),
        ("audit log", paths.audit_log_file(home)),
    ):
        if os.path.exists(path):
            checks += _problems_to_checks("home", f"the {label}", fsperm.check_private(path))
    return checks


def check_endpoint(home: str) -> tuple[list[Check], Endpoint | None]:
    try:
        endpoint = read_endpoint(paths.endpoint_file(home))
    except EndpointError as exc:
        return [Check("endpoint", FAIL, str(exc), "run 'boundkeep init'")], None
    return [Check("endpoint", OK, f"{endpoint.transport} {endpoint.address}")], endpoint


def check_policy(home: str) -> list[Check]:
    path = paths.policy_file(home)
    try:
        policy = load_policy(path)
    except PolicyError as exc:
        return [
            Check("policy", FAIL, str(exc), f"fix {path} or delete it and run 'boundkeep init'")
        ]
    detail = f"{path} (mode: {policy.mode})"
    if policy.mode != "enforce":
        return [Check("policy", WARN, detail, "run 'boundkeep mode enforce' to block again")]
    return [Check("policy", OK, detail)]


def check_daemon(endpoint: Endpoint | None) -> list[Check]:
    if endpoint is None:
        return [Check("daemon", FAIL, "no endpoint to connect to")]
    started = time.monotonic()
    try:
        request_id = protocol.new_request_id()
        line = protocol.encode_request(protocol.EVENT_PING, {}, request_id)
        answer = ipc_client.call(endpoint, line, timeout_s=_PING_TIMEOUT_S)
        response = protocol.decode_response(answer, request_id)
    except ipc_client.DaemonUnavailable as exc:
        return [
            Check(
                "daemon",
                FAIL,
                f"not reachable ({exc}); every tool call asks for confirmation meanwhile",
                "run 'boundkeep serve' in a terminal",
            )
        ]
    except (ipc_client.IpcError, protocol.ProtocolError) as exc:
        return [Check("daemon", FAIL, f"unhealthy ({type(exc).__name__}: {exc})")]
    elapsed_ms = (time.monotonic() - started) * 1000
    status = WARN if "policy error" in response.reason else OK
    checks = [Check("daemon", status, f"running ({response.reason}); ping {elapsed_ms:.1f} ms")]
    if endpoint.transport == TRANSPORT_NAMED_PIPE and sys.platform == "win32":
        checks += _check_pipe_acl(endpoint)
    return checks


def _check_pipe_acl(endpoint: Endpoint) -> list[Check]:
    from boundkeep.ipc import winsec

    try:
        acl = winsec.read_acl_of_pipe(endpoint.address)
        me = winsec.current_user_sid()
    except OSError as exc:
        return [Check("pipe-acl", WARN, f"could not read the pipe's ACL ({exc})")]
    if not acl.dacl_present:
        return [Check("pipe-acl", FAIL, "the pipe has no DACL: every user can connect")]
    others = sorted({a.sid for a in acl.aces if a.allowed and a.sid != me})
    if others:
        return [
            Check(
                "pipe-acl",
                FAIL,
                f"the pipe grants access to other principals: {', '.join(others)}",
                "stop the daemon and start it again with this version of boundkeep",
            )
        ]
    return [Check("pipe-acl", OK, "only the current user can connect to the pipe")]


def load_layers(project_dir: str) -> list[Layer]:
    project = install.resolve_settings_path("project", cwd=project_dir, env=os.environ)
    layers = [
        ("user", install.resolve_settings_path("user", cwd=project_dir, env=os.environ)),
        ("project", project),
        ("local", os.path.join(os.path.dirname(project), "settings.local.json")),
    ]
    result: list[Layer] = []
    for name, path in layers:
        try:
            result.append(Layer(name, path, settings_io.load_settings(path), None))
        except settings_io.SettingsError as exc:
            result.append(Layer(name, path, None, str(exc)))
    return result


def check_layer(layer: Layer, record: install.InstallRecord | None) -> list[Check]:
    name = f"settings:{layer.name}"
    if layer.error is not None or layer.doc is None:
        return [
            Check(
                name,
                FAIL,
                f"{layer.error}",
                "a settings file Claude Code cannot read may switch every hook off; fix it",
            )
        ]
    if not layer.doc.exists:
        if record is not None:
            return [Check(name, FAIL, f"{layer.path} is gone but init installed hooks there")]
        return [Check(name, INFO, f"{layer.path} does not exist")]
    checks: list[Check] = []
    data = layer.doc.data
    if layer.doc.had_bom:
        checks.append(
            Check(
                name,
                WARN,
                f"{layer.path} starts with a UTF-8 BOM (some readers ignore such files)",
                "re-save it without BOM, or run 'boundkeep init' which rewrites it without one",
            )
        )
    if ownhook.disables_hooks(data):
        checks.append(
            Check(
                name,
                FAIL,
                f"{layer.path} sets disableAllHooks: every hook is off, with no warning anywhere",
                "remove the disableAllHooks entry",
            )
        )
    for finding in claude_settings.find_suspicious_top_level_keys(data):
        if finding.severity == "warning":
            checks.append(Check(name, WARN, f"{layer.path}: {finding.message}"))
    own = list(ownhook.own_hooks_in(data))
    if not own:
        if record is not None:
            checks.append(
                Check(
                    name,
                    FAIL,
                    f"{layer.path} no longer contains boundkeep's hooks",
                    "run 'boundkeep init' again",
                )
            )
        else:
            checks.append(Check(name, INFO, f"no boundkeep hooks in {layer.path}"))
        return checks
    checks += _check_own_hooks(name, layer.path, own, record, data)
    return checks


def _check_own_hooks(
    name: str,
    path: str,
    own: list[tuple[str, str | None, dict[str, Any]]],
    record: install.InstallRecord | None,
    data: dict[str, Any],
) -> list[Check]:
    checks: list[Check] = []
    present = {event for event, _matcher, _hook in own}
    missing = sorted(set(ownhook.SUBCOMMANDS) - present)
    if missing:
        checks.append(
            Check(
                name,
                FAIL,
                f"{path}: no boundkeep hook for {', '.join(missing)}",
                "run 'boundkeep init' again",
            )
        )
    # The same rules the ConfigChange hook enforces (hook_main), so that doctor cannot call an
    # entry fine that the product itself would call altered.
    for event, matcher, hook in own:
        sub = ownhook.SUBCOMMANDS.get(event)
        args = hook.get("args")
        last = args[-1] if isinstance(args, list) and args else None
        if sub is None or last != sub:
            checks.append(
                Check(
                    name,
                    FAIL,
                    f"{path}: the {event} entry runs the {last!r} handler, so the event is not "
                    "handled as it should be",
                    "run 'boundkeep init' again",
                )
            )
            continue
        if not hook_main.entry_intact(hook, sub):
            checks.append(
                Check(
                    name,
                    FAIL,
                    f"{path}: the {event} entry has extra fields or a timeout outside "
                    f"{hook_main.MIN_ENTRY_TIMEOUT_S[sub]:g}-{hook_main.MAX_ENTRY_TIMEOUT_S:g} s "
                    f"(found {hook.get('timeout')!r}); Claude Code could skip or cut off the hook",
                    "run 'boundkeep init' again",
                )
            )
        if event != "PostToolUse" and not hook_main.matcher_acceptable(event, matcher, None):
            checks.append(
                Check(
                    name,
                    FAIL,
                    f"{path}: the {event} matcher is {matcher!r}, so some events skip the hook",
                    "run 'boundkeep init' again",
                )
            )
    if record is not None:
        problem = hook_main.record_problem(
            data,
            {
                "hook_command": record.hook_command,
                "hook_args": list(record.hook_args),
                "post_matcher": record.post_matcher,
            },
        )
        if problem:
            checks.append(
                Check(
                    name,
                    FAIL,
                    f"{path}: {problem}",
                    "run 'boundkeep init' again, or investigate who changed it",
                )
            )
    env_problem = hook_main.env_violation(data)
    if env_problem:
        checks.append(Check(name, FAIL, f"{path}: {env_problem}", "remove that env entry"))
    commands = {(h.get("command"), tuple(h.get("args", [])[:-1])) for _e, _m, h in own}
    for command, base_args in sorted(commands, key=repr):
        if not isinstance(command, str):
            continue
        problems = hookcmd.command_problems(command, [*base_args, "pre"])
        for problem in problems:
            checks.append(
                Check(
                    name, FAIL, f"{path}: hook command {command}: {problem}", "run 'boundkeep init'"
                )
            )
    if not any(c.status in (FAIL, WARN) for c in checks):
        checks.append(Check(name, OK, f"{path}: all {len(present)} boundkeep hooks are in place"))
    return checks


def check_hook_command_self_test(layers: list[Layer]) -> list[Check]:
    seen: dict[tuple[str, tuple[str, ...]], str] = {}
    for layer in layers:
        if layer.doc is None:
            continue
        for _event, _matcher, hook in ownhook.own_hooks_in(layer.doc.data):
            command = hook.get("command")
            args = hook.get("args")
            if isinstance(command, str) and isinstance(args, list):
                seen.setdefault((command, tuple(str(a) for a in args[:-1])), layer.name)
    if not seen:
        return []
    checks: list[Check] = []
    for (command, base_args), layer_name in seen.items():
        if hookcmd.command_problems(command, [*base_args, "pre"]):
            continue  # reported above; do not try to launch what cannot start
        with tempfile.TemporaryDirectory(prefix="boundkeep-doctor-") as scratch:
            results = install.run_self_check(
                install.HookCommand(command, base_args), env={**os.environ, paths.HOME_ENV: scratch}
            )
        bad = [r for r in results if not r.ok]
        if bad:
            for r in bad:
                checks.append(
                    Check(
                        "hook-command",
                        FAIL,
                        f"({layer_name}) {r.subcommand} [{r.env_variant}]: {r.detail}",
                        "the gate would be silently open; run 'boundkeep init'",
                    )
                )
        else:
            slowest = max(r.elapsed_s for r in results) * 1000
            checks.append(
                Check(
                    "hook-command",
                    OK,
                    f"({layer_name}) launches correctly with and without PYTHON* variables "
                    f"({len(results)} runs, slowest {slowest:.0f} ms)",
                )
            )
    return checks


def check_managed_settings() -> list[Check]:
    if sys.platform != "win32":
        return [
            Check(
                "managed-settings",
                INFO,
                "not checked here: where managed settings live is unverified on this platform",
            )
        ]
    found: list[tuple[str, dict[str, Any]]] = []
    file_path = os.path.join(
        os.environ.get("PROGRAMFILES", r"C:\Program Files"), "ClaudeCode", "managed-settings.json"
    )
    try:
        with open(file_path, "rb") as f:
            parsed = json.loads(f.read(1024 * 1024).decode("utf-8-sig"))
        if isinstance(parsed, dict):
            found.append((file_path, parsed))
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        return [Check("managed-settings", WARN, f"{file_path} could not be read ({exc})")]
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\ClaudeCode") as key:
            value, _kind = winreg.QueryValueEx(key, "Settings")
        parsed_reg = json.loads(value)
        if isinstance(parsed_reg, dict):
            found.append(("HKLM\\SOFTWARE\\Policies\\ClaudeCode", parsed_reg))
    except (OSError, ValueError, TypeError):
        pass
    if not found:
        return [Check("managed-settings", OK, "no managed settings found")]
    checks: list[Check] = []
    for where, settings in found:
        if ownhook.disables_hooks(settings):
            checks.append(
                Check(
                    "managed-settings",
                    FAIL,
                    f"{where} sets disableAllHooks: every hook is off",
                    "ask whoever manages this machine to remove it",
                )
            )
        elif settings.get("allowManagedHooksOnly"):
            checks.append(
                Check(
                    "managed-settings",
                    FAIL,
                    f"{where} sets allowManagedHooksOnly: user and project hooks are dropped",
                    "ask whoever manages this machine to allow boundkeep's hooks",
                )
            )
        else:
            checks.append(
                Check("managed-settings", INFO, f"{where} exists; it does not drop hooks")
            )
    return checks


def check_workspace_trust(project_dir: str) -> list[Check]:
    path = os.path.join(os.path.expanduser("~"), ".claude.json")
    try:
        with open(path, "rb") as f:
            data = f.read(_MAX_CLAUDE_JSON_BYTES + 1)
        if len(data) > _MAX_CLAUDE_JSON_BYTES:
            return [Check("workspace-trust", INFO, "~/.claude.json is too large to inspect")]
        parsed = json.loads(data.decode("utf-8-sig"))
    except FileNotFoundError:
        return [Check("workspace-trust", INFO, "~/.claude.json not found; trust state unknown")]
    except (OSError, ValueError):
        return [Check("workspace-trust", INFO, "~/.claude.json could not be parsed")]
    projects = parsed.get("projects") if isinstance(parsed, dict) else None
    wanted = project_dir.replace("\\", "/").rstrip("/").casefold()
    if isinstance(projects, dict):
        for key, entry in projects.items():
            if isinstance(key, str) and key.replace("\\", "/").rstrip("/").casefold() == wanted:
                trusted = isinstance(entry, dict) and entry.get("hasTrustDialogAccepted") is True
                if trusted:
                    return [Check("workspace-trust", OK, f"{project_dir} is trusted")]
                break
    return [
        Check(
            "workspace-trust",
            WARN,
            f"{project_dir} is not marked trusted in ~/.claude.json: Claude Code is documented to "
            "skip hooks in untrusted folders (the VS Code extension still ran them in M0a; "
            "unverified)",
            "open the folder in Claude Code once and accept the trust dialog",
        )
    ]


def _run_version(executable: str) -> str | None:
    try:
        result = subprocess.run(  # noqa: S603 - fixed arguments, no shell
            [executable, "--version"], capture_output=True, timeout=20, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = result.stdout.decode("utf-8", "replace").strip()
    return text.splitlines()[0] if result.returncode == 0 and text else None


def check_claude_code() -> list[Check]:
    checks: list[Check] = []
    on_path = shutil.which("claude")
    if on_path:
        version = _run_version(on_path)
        if version:
            checks.append(Check("claude-code", INFO, f"{on_path}: {version}"))
        else:
            checks.append(
                Check(
                    "claude-code",
                    WARN,
                    f"'claude' on PATH ({on_path}) does not run (a broken shim?); "
                    "boundkeep tested Claude Code 2.1.291 and 2.1.292",
                )
            )
    pattern = os.path.join(
        os.path.expanduser("~"), ".vscode", "extensions", "anthropic.claude-code-*", "resources",
        "native-binary", "claude.exe" if sys.platform == "win32" else "claude",
    )  # fmt: skip
    for candidate in sorted(glob.glob(pattern))[-1:]:
        version = _run_version(candidate)
        checks.append(
            Check("claude-code", INFO, f"VS Code extension: {version or 'version unknown'}")
        )
    if not checks:
        checks.append(Check("claude-code", INFO, "no claude executable found to ask for a version"))
    return checks


def check_environment() -> list[Check]:
    checks: list[Check] = []
    if "ANTHROPIC_API_KEY" in os.environ:  # presence only: the value is never read or shown
        checks.append(
            Check(
                "environment",
                WARN,
                "ANTHROPIC_API_KEY is set in this environment: Claude Code then bills the API "
                "instead of your subscription",
                "unset it unless you want that",
            )
        )
    if sys.platform == "win32":
        git_bash = os.environ.get("CLAUDE_CODE_GIT_BASH_PATH")
        tools = "PowerShell" + (f" and Git Bash ({git_bash})" if git_bash else "")
        checks.append(
            Check(
                "environment",
                INFO,
                f"shell tools Claude Code can use here: {tools}; the PreToolUse matcher '*' covers "
                "both",
            )
        )
    return checks


def check_activity(home: str) -> list[Check]:
    log = AuditLog(paths.audit_log_file(home))
    records = [r for r in log.tail(50) if r.get("event") != "daemon"]
    if not records:
        return [
            Check(
                "activity",
                INFO,
                "no hook events logged yet: use Claude Code once, then run doctor again "
                "(boundkeep cannot tell by itself whether a host fires hooks)",
            )
        ]
    last = records[-1]
    return [Check("activity", INFO, f"last event: {last.get('ts')} {last.get('event')}")]


# --------------------------------------------------------------------------------------------
# Running everything
# --------------------------------------------------------------------------------------------


def _guard(name: str, fn: Callable[[], list[Check]]) -> list[Check]:
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - a crashing check must show up as a failure
        return [Check(name, FAIL, f"the check itself crashed ({type(exc).__name__}: {exc})")]


def run_checks(project_dir: str, home: str | None = None) -> list[Check]:
    home = home if home is not None else paths.home_dir()
    checks: list[Check] = []
    checks += _guard("python", check_python)
    checks += _guard("home", lambda: check_files(home))
    endpoint_checks, endpoint = _guard_endpoint(home)
    checks += endpoint_checks
    checks += _guard("policy", lambda: check_policy(home))
    checks += _guard("daemon", lambda: check_daemon(endpoint))

    try:
        layers = load_layers(project_dir)
    except (settings_io.SettingsError, ValueError) as exc:
        checks.append(Check("settings", FAIL, str(exc)))
        layers = []
    try:
        records = install.load_manifest(paths.manifest_file(home))
    except settings_io.SettingsError as exc:
        checks.append(
            Check(
                "manifest",
                FAIL,
                str(exc),
                "move installs.json away, then run 'boundkeep init' (it refuses to touch "
                "anything while the manifest is damaged)",
            )
        )
        records = []
    for layer in layers:
        record = install.find_record(records, layer.path)
        checks += _guard(f"settings:{layer.name}", functools.partial(check_layer, layer, record))
    installed = any(
        layer.doc is not None and any(True for _ in ownhook.own_hooks_in(layer.doc.data))
        for layer in layers
    )
    if not installed:
        checks.append(
            Check(
                "install",
                FAIL,
                "boundkeep's hooks are not in any settings file Claude Code reads for this project",
                "run 'boundkeep init' (project scope) or 'boundkeep init --scope user'",
            )
        )
    checks += _guard("hook-command", lambda: check_hook_command_self_test(layers))
    checks += _guard("managed-settings", check_managed_settings)
    checks += _guard("workspace-trust", lambda: check_workspace_trust(project_dir))
    checks += _guard("claude-code", check_claude_code)
    checks += _guard("environment", check_environment)
    checks += _guard("activity", lambda: check_activity(home))
    return checks


def _guard_endpoint(home: str) -> tuple[list[Check], Endpoint | None]:
    try:
        return check_endpoint(home)
    except Exception as exc:  # noqa: BLE001
        return [Check("endpoint", FAIL, f"the check itself crashed ({type(exc).__name__})")], None


_TAGS = {OK: "[ OK ]", WARN: "[WARN]", FAIL: "[FAIL]", INFO: "[info]"}


def run(args: argparse.Namespace) -> int:
    project_dir = os.path.abspath(args.project_dir or os.getcwd())
    checks = run_checks(project_dir)
    if args.json:
        console.out(json.dumps([asdict(c) for c in checks], ensure_ascii=False, indent=2))
    else:
        for check in checks:
            console.out(f"{_TAGS[check.status]} {check.name}: {check.detail}")
            if check.fix and check.status in (FAIL, WARN):
                console.out(f"       fix: {check.fix}")
        failures = sum(1 for c in checks if c.status == FAIL)
        warnings = sum(1 for c in checks if c.status == WARN)
        console.out("")
        console.out(
            f"{failures} problem(s), {warnings} warning(s)."
            if failures or warnings
            else "All checks passed."
        )
    return 1 if any(c.status == FAIL for c in checks) else 0
