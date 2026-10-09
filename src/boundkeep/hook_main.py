"""The logic of boundkeep-hook, the Claude Code hook client.

The file Claude Code launches is ``hook_client.py``, a few lines that only put the package on
``sys.path`` and call ``entry`` here: a main script is compiled from source on every start while
an imported module comes from cached bytecode, so the logic lives in this module.

Claude Code starts this process for every hook event, writes the event JSON to stdin and reads
the decision from stdout and the exit code. It forwards the event to the daemon over local IPC
and turns the answer into a Claude Code hook output.

Every rule below exists because breaking it is a SILENT failure: Claude Code treats a crash, a
timeout, a non-0/non-2 exit code, invalid JSON, a missing command... all as "no decision" and the
tool call simply runs (measured in M0a, docs/hook-behavior.md E6/E18/E22):

* Byte I/O only. stdin is read as bytes and decoded as UTF-8 explicitly; stdout is written as
  bytes and is either empty or one ``json.dumps(..., ensure_ascii=True)`` document. Text-mode
  stdin decodes with the ANSI code page (gbk on zh-CN Windows) and does NOT fail: it silently
  misreads the text (Chinese becomes mojibake, a check mark becomes a lone surrogate that crashes
  later), so rules stop matching paths and commands that contain such text
  (experiments/probe_stdin_encoding.py). Nothing here depends on PYTHONIOENCODING, PYTHONUTF8 or
  the code page.
* Exit code 0 (with a valid decision or nothing) or 2 (block, with a reason on stderr). Never 1,
  never an unhandled exception: everything is caught, down to BaseException.
* Own deadline. The whole run (reading stdin and the IPC round trip) is bounded from process
  start by a worker thread plus ``join`` and ends with ``os._exit``; the budget is smaller than
  the ``timeout`` that ``boundkeep init`` writes into settings.json, so the client answers before
  Claude Code kills it.
* Uncertain means ask. Any failure for a PreToolUse event (daemon down, pipe busy past the
  budget, bad response, oversize or unparsable event, internal error) produces ``ask`` with the
  reason. For events that carry no decision (PostToolUse, UserPromptSubmit) the degraded result is
  a no-op. For ConfigChange it is a block (exit 2).
* The event type comes from ``hook_event_name`` in the event, the command-line argument is only a
  cross-check; a missing or different argument degrades (older Claude Code versions are reported
  to drop ``args``).

Import-light on purpose (``python -I -S``, no site, nothing but the standard library): every
import is paid on every tool call, so no dataclasses / typing / socket here.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time

from boundkeep import __version__, ownhook, paths, protocol
from boundkeep.ipc import client as ipc_client
from boundkeep.ipc import endpoint as ipc_endpoint

TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Any

# Per-event total budget in seconds, counted from process start. Must stay below the ``timeout``
# values boundkeep init writes (install.HookTimeouts: pre 15, prompt 10, post 10, config 10).
BUDGET_S = {"pre": 10.0, "prompt": 5.0, "post": 5.0, "config": 5.0}
DEFAULT_BUDGET_S = 10.0
EXIT_RESERVE_S = 0.3  # kept free for rendering and exiting after the IPC deadline
# ``timeout`` of our own settings entries must leave room for the budget above (config check).
MIN_ENTRY_TIMEOUT_S = {"pre": 11.0, "prompt": 6.0, "post": 6.0, "config": 6.0}

MAX_STDIN_BYTES = 64 * 1024 * 1024
SMALL_EVENT_BYTES = 256 * 1024  # below this nothing is elided and no size is computed
ELIDE_ABOVE_CHARS = 64 * 1024
ELIDE_KEYS = ("content", "new_string", "old_string", "new_source")
MAX_ENTRY_TIMEOUT_S = 3600.0
MAX_SETTINGS_BYTES = 4 * 1024 * 1024
CONFIG_NOTIFY_BUDGET_S = 1.0

_FALLBACK_ASK = (
    b'{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask",'
    b'"permissionDecisionReason":"boundkeep: internal error in the hook client"}}\n'
)


class Outcome:
    """What to write to stdout and stderr and which exit code to return."""

    __slots__ = ("exit_code", "stderr", "stdout")

    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", exit_code: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code


class _BadInput(Exception):
    """The event (or a file that must be evaluated) is unusable; the message is safe to print."""


# --------------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------------


def render_pre_decision(decision: str, reason: str) -> bytes:
    """The PreToolUse hook output for ``ask`` or ``deny``; ASCII-only JSON built by json.dumps."""
    body = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason[: protocol.MAX_REASON_CHARS],
        }
    }
    return json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"


def _ascii_line(text: str) -> bytes:
    return text[: protocol.MAX_REASON_CHARS].encode("ascii", "backslashreplace") + b"\n"


def degraded(kind: str | None, reason: str) -> Outcome:
    """The safe result when the event cannot be decided; see the module docstring."""
    if kind is None or kind == protocol.EVENT_PRE:
        # Unknown event type: the PreToolUse shape is the one that fails safe.
        return Outcome(stdout=render_pre_decision("ask", reason))
    if kind == protocol.EVENT_CONFIG:
        return Outcome(
            stderr=_ascii_line("boundkeep: settings change blocked: " + reason), exit_code=2
        )
    return Outcome()


# --------------------------------------------------------------------------------------------
# Reading and shaping the event
# --------------------------------------------------------------------------------------------


def _read_stdin() -> bytes:
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(0, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_STDIN_BYTES:
                raise _BadInput("event is larger than 64 MiB")
            chunks.append(chunk)
    except OSError as exc:
        raise _BadInput("event could not be read from stdin") from exc
    return b"".join(chunks)


def _parse_event(data: bytes) -> dict[str, Any]:
    if not data:
        raise _BadInput("empty event on stdin")
    try:
        # utf-8-sig: tolerate a BOM; invalid UTF-8 raises UnicodeDecodeError (a ValueError).
        obj = json.loads(data.decode("utf-8-sig"))
    except (ValueError, RecursionError) as exc:
        raise _BadInput("event is not valid UTF-8 JSON") from exc
    if not isinstance(obj, dict):
        raise _BadInput("event is not a JSON object")
    return obj


def _prepare_payload(event: dict[str, Any], raw_size: int) -> dict[str, Any]:
    """Shrink very large events before forwarding; ``command`` and ``prompt`` are never touched.

    File contents and tool output are never needed for a decision (and are never sent to an LLM),
    but they can be many megabytes. Only their length is forwarded. A giant ``command`` is NOT
    elided: truncating it would let padding hide the part that matters.
    """
    if raw_size <= SMALL_EVENT_BYTES:
        return event
    out = dict(event)
    tool_input = out.get("tool_input")
    if isinstance(tool_input, dict):
        shrunk = dict(tool_input)
        for key in ELIDE_KEYS:
            value = shrunk.get(key)
            if isinstance(value, str) and len(value) > ELIDE_ABOVE_CHARS:
                shrunk[key] = f"<elided {len(value)} chars>"
        out["tool_input"] = shrunk
    response = out.get("tool_response")
    if response is not None:
        try:
            size = len(json.dumps(response, ensure_ascii=False))
        except (TypeError, ValueError, RecursionError):
            size = raw_size
        if size > ELIDE_ABOVE_CHARS:
            out["tool_response"] = {"_elided_chars": size}
    return out


# --------------------------------------------------------------------------------------------
# ConfigChange: refuse settings changes that switch the gate off
# --------------------------------------------------------------------------------------------


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def _load_json_file(path: str, what: str) -> Any | None:
    """Parsed JSON of ``path``, None when the file does not exist; ``_BadInput`` otherwise."""
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_SETTINGS_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _BadInput(f"{what} could not be read") from exc
    if len(data) > MAX_SETTINGS_BYTES:
        raise _BadInput(f"{what} is larger than 4 MiB")
    try:
        # JavaScript's JSON.parse (Claude Code) refuses NaN and Infinity; so must we, or a file it
        # rejects (and drops our hooks with) would look fine here.
        return json.loads(data.decode("utf-8-sig"), parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise _BadInput(f"{what} is not valid JSON") from exc


def _manifest_records_for(file_path: str) -> list[dict[str, Any]]:
    """Install records (from ``boundkeep init``) that describe ``file_path``; [] if none."""
    manifest = _load_json_file(paths.manifest_file(), "boundkeep install manifest")
    if manifest is None:
        return []
    installs = manifest.get("installs") if isinstance(manifest, dict) else None
    if not isinstance(installs, list):
        raise _BadInput("boundkeep install manifest is malformed (run 'boundkeep doctor')")
    return [
        item
        for item in installs
        if isinstance(item, dict)
        and isinstance(item.get("settings_path"), str)
        and paths.same_file(item["settings_path"], file_path)
    ]


def entry_intact(hook: dict[str, Any], sub: str) -> bool:
    """Our hook entry has no extra fields (such as ``if``) and a timeout that makes sense.

    Too short and Claude Code kills the hook before it answers (which lets the call run); absurdly
    long (above an hour) risks overflowing a timer on the other side and cancelling the hook.
    """
    if not set(hook) <= {"type", "command", "args", "timeout"}:
        return False
    if "timeout" in hook:
        timeout = hook["timeout"]
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            return False
        if not MIN_ENTRY_TIMEOUT_S[sub] <= timeout <= MAX_ENTRY_TIMEOUT_S:
            return False
    return True


def matcher_acceptable(event: str, matcher: str | None, post_matcher: object) -> bool:
    """Our entry's group still applies to everything it must see.

    Only PostToolUse carries a matcher of its own (the one ``init`` recorded); every other entry
    must match everything: a narrowed PreToolUse matcher lets other tools skip the gate, and a
    ConfigChange matcher (it matches the ``source``) could make settings edits never reach us.
    """
    if event == "PostToolUse":
        return matcher == post_matcher
    return matcher in (None, "", "*")


def record_problem(settings: Any, record: dict[str, Any]) -> str | None:
    """Why ``settings`` no longer carries the entries that ``record`` says init installed."""
    command = record.get("hook_command")
    base_args = record.get("hook_args")
    if not isinstance(command, str) or not isinstance(base_args, list):
        return "boundkeep install manifest is malformed (run 'boundkeep doctor')"
    present = list(ownhook.own_hooks_in(settings))
    for event, sub in ownhook.SUBCOMMANDS.items():
        wanted_args = [*base_args, sub]
        for found_event, matcher, hook in present:
            if found_event != event or hook.get("command") != command:
                continue
            if hook.get("args") != wanted_args or not entry_intact(hook, sub):
                continue
            if not matcher_acceptable(event, matcher, record.get("post_matcher")):
                continue
            break
        else:
            return f"boundkeep's {event} hook was removed or altered"
    return None


# Environment variables that, set through the settings ``env`` block, would point the hook client
# at another boundkeep home (a fake daemon that answers "none") or make Claude Code skip hooks.
_RISKY_ENV_NAMES = frozenset(
    {
        "USERPROFILE",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "CLAUDE_CONFIG_DIR",
        "CLAUDE_CODE_SIMPLE",
        "CLAUDE_CODE_SAFE_MODE",
    }
)


def env_violation(settings: dict[str, Any]) -> str | None:
    """A settings ``env`` block that could redirect or bypass the hook client, else None."""
    env = settings.get("env")
    if env is None:
        return None
    if not isinstance(env, dict):
        return "the settings 'env' entry is not an object"
    for name in env:
        upper = str(name).upper()
        if upper.startswith("BOUNDKEEP_") or upper in _RISKY_ENV_NAMES:
            return f"the settings 'env' block sets {name}, which could redirect or bypass boundkeep"
    return None


def config_violation(file_path: str) -> str | None:
    """Why the settings file at ``file_path`` must not be accepted, or None when it is fine.

    Blocks: a settings document that cannot be evaluated (fail closed), ``disableAllHooks`` set,
    a settings file recorded by ``init`` that was deleted, or one in which boundkeep's entries
    were removed, pointed elsewhere, narrowed or given a timeout too short to answer.
    """
    records = _manifest_records_for(file_path)
    settings = _load_json_file(file_path, "settings file")
    if settings is None:
        return "a settings file that carries boundkeep's hooks was removed" if records else None
    if not isinstance(settings, dict):
        raise _BadInput("settings file is not a JSON object")
    if ownhook.disables_hooks(settings):
        return "the change sets disableAllHooks, which would switch every hook off"
    env_problem = env_violation(settings)
    if env_problem:
        return env_problem
    for record in records:
        problem = record_problem(settings, record)
        if problem:
            return problem
    return None


def _handle_config(event: dict[str, Any], deadline: float) -> Outcome:
    source = event.get("source")
    if source == "policy_settings":
        return Outcome()  # managed policy: Claude Code does not let hooks block it
    if source == "skills":
        return Outcome()  # a skill file, not a settings document
    file_path = event.get("file_path")
    if not isinstance(file_path, str) or not file_path:
        problem: str | None = "the settings change cannot be evaluated (no file_path in the event)"
    else:
        try:
            problem = config_violation(file_path)
        except _BadInput as exc:
            problem = f"the settings change cannot be evaluated ({exc})"
    _notify_config(event, problem, deadline)
    if problem is None:
        return Outcome()
    return degraded(protocol.EVENT_CONFIG, problem)


def _notify_config(event: dict[str, Any], problem: str | None, deadline: float) -> None:
    """Best effort: tell the daemon so the attempt lands in the audit log. Never raises.

    Runs in a helper thread that is given at most ``CONFIG_NOTIFY_BUDGET_S``: a daemon that
    accepts the connection but never answers must not hold up (and so fail) a harmless change.
    """
    worker = threading.Thread(
        target=_notify_config_now, args=(event, problem, deadline), daemon=True
    )
    worker.start()
    worker.join(CONFIG_NOTIFY_BUDGET_S + 0.2)


def _notify_config_now(event: dict[str, Any], problem: str | None, deadline: float) -> None:
    try:
        endpoint = ipc_endpoint.read_endpoint(paths.endpoint_file())
        payload = dict(event)
        payload["local_decision"] = "deny" if problem else "none"
        payload["local_reason"] = problem or ""
        request_id = protocol.new_request_id()
        line = protocol.encode_request(protocol.EVENT_CONFIG, payload, request_id)
        ipc_client.transact(
            endpoint, line, min(deadline, time.monotonic() + CONFIG_NOTIFY_BUDGET_S)
        )
    except Exception:  # noqa: BLE001, S110 - a down daemon must not change the decision
        pass


# --------------------------------------------------------------------------------------------
# One hook invocation
# --------------------------------------------------------------------------------------------


def process(sub: str | None, data: bytes, deadline: float) -> Outcome:
    """Decide one event. ``sub`` is the command-line argument, ``data`` the raw stdin bytes."""
    arg_kind = sub if sub in protocol.HOOK_EVENTS else None
    try:
        event = _parse_event(data)
    except _BadInput as exc:
        return degraded(arg_kind, f"boundkeep: {exc}")
    name = event.get("hook_event_name")
    if not isinstance(name, str):
        return degraded(arg_kind, "boundkeep: the event has no hook_event_name")
    kind = ownhook.SUBCOMMANDS.get(name)
    if kind is None:
        if arg_kind is None:
            return Outcome()  # an event we are not registered for: nothing to decide
        # We were registered for this event but it arrives under a name we do not know (renamed,
        # misspelled, padded): do not silently allow.
        return degraded(arg_kind, f"boundkeep: unexpected event name {name[:40]!r} for this hook")
    if arg_kind != kind:
        return degraded(
            kind, f"boundkeep: hook registration mismatch (argument {sub!r}, event {name})"
        )
    if kind == protocol.EVENT_CONFIG:
        return _handle_config(event, deadline)
    try:
        endpoint = ipc_endpoint.read_endpoint(paths.endpoint_file())
        payload = _prepare_payload(event, len(data))
        request_id = protocol.new_request_id()
        line = protocol.encode_request(kind, payload, request_id)
        response = protocol.decode_response(
            ipc_client.transact(endpoint, line, deadline), request_id
        )
    except ipc_endpoint.EndpointError as exc:
        return degraded(kind, f"boundkeep is not set up ({exc}); run 'boundkeep init'")
    except ipc_client.DaemonUnavailable:
        return degraded(kind, "boundkeep daemon is not running; start it with 'boundkeep serve'")
    except ipc_client.DaemonBusy:
        return degraded(kind, "boundkeep daemon is busy and did not accept the request in time")
    except ipc_client.DaemonTimeout:
        return degraded(kind, "boundkeep daemon did not answer in time")
    except protocol.ProtocolError as exc:
        return degraded(kind, f"boundkeep: invalid exchange with the daemon ({exc})")
    except Exception as exc:  # noqa: BLE001 - every failure must degrade, never escape
        return degraded(kind, f"boundkeep: internal error ({type(exc).__name__})")
    if not response.ok:
        return degraded(kind, f"boundkeep daemon refused the request ({response.error})")
    if kind != protocol.EVENT_PRE or response.decision == protocol.DECISION_NONE:
        return Outcome()
    return Outcome(stdout=render_pre_decision(response.decision, response.reason))


def run_hook(sub: str | None, deadline: float) -> Outcome:
    """Read stdin and decide. Runs in the worker thread."""
    try:
        data = _read_stdin()
    except _BadInput as exc:
        return degraded(sub if sub in protocol.HOOK_EVENTS else None, f"boundkeep: {exc}")
    return process(sub, data, deadline)


def _fallback_outcome(sub: str | None) -> Outcome:
    """Used when even ``process`` blew up: no exception detail, nothing that can fail."""
    if sub is None or sub == protocol.EVENT_PRE or sub not in protocol.HOOK_EVENTS:
        return Outcome(stdout=_FALLBACK_ASK)
    if sub == protocol.EVENT_CONFIG:
        return Outcome(stderr=b"boundkeep: settings change blocked: internal error\n", exit_code=2)
    return Outcome()


# --------------------------------------------------------------------------------------------
# Process entry
# --------------------------------------------------------------------------------------------


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _deliver(outcome: Outcome) -> int:
    """Write the outcome with raw fd writes; returns the exit code (0 or 2, never 1)."""
    stdout = outcome.stdout
    if stdout and not stdout.isascii():  # invariant guard: stdout is ASCII or nothing
        stdout = _FALLBACK_ASK
    try:
        if stdout:
            _write_all(1, stdout)
    except OSError:
        # The decision could not be delivered (stdout closed): blocking is the only safe answer.
        try:  # noqa: SIM105 - contextlib would be one more import on every tool call
            _write_all(2, b"boundkeep: could not deliver the hook decision\n")
        except OSError:
            pass
        return 2
    if outcome.stderr:
        try:  # noqa: SIM105
            _write_all(2, outcome.stderr)
        except OSError:
            pass  # exit code 2 still blocks without the text
    return 2 if outcome.exit_code == 2 else 0


def _budget_for(sub: str | None) -> float:
    """The total budget in seconds. ``BOUNDKEEP_HOOK_BUDGET_S`` can only SHORTEN it (tests use
    this): a longer budget could outlive Claude Code's own hook timeout, which is a silent allow."""
    budget = BUDGET_S.get(sub or "", DEFAULT_BUDGET_S)
    override = os.environ.get("BOUNDKEEP_HOOK_BUDGET_S")
    if override:
        try:  # noqa: SIM105
            budget = min(budget, max(0.2, float(override)))
        except ValueError:
            pass
    return budget


def main(argv: list[str] | None = None, *, t0: float | None = None) -> int:
    """Run one hook invocation and return the exit code; the caller exits the process."""
    started = time.monotonic() if t0 is None else t0
    try:
        args = list(sys.argv[1:] if argv is None else argv)
        if args == ["--version"]:
            _write_all(1, f"boundkeep-hook {__version__}\n".encode("ascii", "replace"))
            return 0
        sub = args[0] if args else None
        hard_end = started + _budget_for(sub)
        deadline = hard_end - EXIT_RESERVE_S
        box: list[Outcome] = []

        def work() -> None:
            try:
                box.append(run_hook(sub, deadline))
            except BaseException:  # noqa: BLE001 - the worker must always leave an answer
                box.append(_fallback_outcome(sub))

        worker = threading.Thread(target=work, name="boundkeep-hook", daemon=True)
        try:
            worker.start()
        except RuntimeError:
            work()  # cannot start a thread: run inline, the IPC deadline still applies
        else:
            worker.join(max(0.0, hard_end - time.monotonic()))
        if box:
            outcome = box[0]
        else:
            outcome = degraded(
                sub if sub in protocol.HOOK_EVENTS else None, "boundkeep hook client timed out"
            )
        return _deliver(outcome)
    except BaseException:  # noqa: BLE001 - last resort: never let anything escape as exit code 1
        return _deliver(Outcome(stdout=_FALLBACK_ASK))


def entry(t0: float | None = None) -> None:
    """Exit immediately with the hook's exit code, skipping interpreter teardown.

    ``os._exit`` skips shutdown (faster, and cannot hang on a stuck worker thread). Everything has
    been written with raw fd writes, so nothing is left in a buffer. ``t0`` is the process start
    time taken by the entry script (``hook_client.py``).
    """
    os._exit(main(t0=t0))
