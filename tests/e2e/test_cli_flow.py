"""The whole M0 path with real processes: init, daemon, hooks exactly as Claude Code would start
them, audit log, doctor, kill, uninstall.

Everything runs against a throwaway user profile (USERPROFILE and HOME point at a temp directory),
so the real ~/.boundkeep and ~/.claude are never read or written. The hook command is taken from
the settings file that ``init`` wrote, i.e. the same argv Claude Code would spawn.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.ipc import client as ipc_client
from boundkeep.ipc import endpoint as ipc_endpoint
from tests.conftest import FIXTURES_DIR, scrubbed_env

pytestmark = pytest.mark.e2e

CANARY = "BOUNDKEEP_CANARY"


class Machine:
    """A throwaway user profile plus a project directory, and ways to run things in them."""

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.user = root / "user"
        self.project = root / "project"
        self.user.mkdir()
        self.project.mkdir()
        self.home = self.user / ".boundkeep"
        self.settings = self.project / ".claude" / "settings.json"
        self.env = scrubbed_env(
            {"USERPROFILE": str(self.user), "HOME": str(self.user), "APPDATA": str(self.user)}
        )
        self.env.pop("CLAUDE_CONFIG_DIR", None)

    def cli(self, *args: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "boundkeep", *args],
            capture_output=True,
            env=self.env,
            cwd=str(self.project),
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )

    def init(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return self.cli("init", "--project-dir", str(self.project), *extra)

    def hook_argv(self, event: str) -> list[str]:
        settings = json.loads(self.settings.read_text(encoding="utf-8"))
        entry = settings["hooks"][event][0]["hooks"][0]
        return [entry["command"], *entry["args"]]

    def hook(
        self, event: str, payload: bytes, timeout: float = 30
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            self.hook_argv(event),
            input=payload,
            capture_output=True,
            env=self.env,
            timeout=timeout,
            check=False,
        )

    def pre_event(self, command: str, tool: str = "PowerShell") -> bytes:
        event = json.loads(
            (FIXTURES_DIR / "PreToolUse__PowerShell.json").read_text(encoding="utf-8")
        )
        event["tool_name"] = tool
        event["tool_input"] = {"command": command, "description": "e2e"}
        return json.dumps(event, ensure_ascii=False).encode("utf-8")

    def endpoint(self) -> ipc_endpoint.Endpoint:
        return ipc_endpoint.read_endpoint(str(self.home / "endpoint.json"))

    def ping(self, timeout_s: float = 2.0) -> str:
        request_id = protocol.new_request_id()
        line = protocol.encode_request(protocol.EVENT_PING, {}, request_id)
        answer = ipc_client.call(self.endpoint(), line, timeout_s=timeout_s)
        return protocol.decode_response(answer, request_id).reason

    def log_records(self) -> list[dict[str, Any]]:
        path = self.home / "logs" / "audit.jsonl"
        if not path.exists():
            return []
        lines = path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines if line.strip()]


@pytest.fixture
def machine(tmp_path: Path) -> Machine:
    return Machine(tmp_path)


class RunningDaemon:
    def __init__(self, machine: Machine) -> None:
        self.machine = machine
        self.out = open(machine.root / "daemon.out", "wb")  # noqa: SIM115 - closed in stop()
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0  # type: ignore[attr-defined]
        self.process = subprocess.Popen(
            [sys.executable, "-m", "boundkeep", "serve"],
            env=machine.env,
            cwd=str(machine.project),
            stdout=self.out,
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )
        deadline = time.monotonic() + 30
        while True:
            try:
                machine.ping()
                return
            except (ipc_client.IpcError, FileNotFoundError, ipc_endpoint.EndpointError):
                if time.monotonic() > deadline or self.process.poll() is not None:
                    self.stop()
                    raise AssertionError(f"daemon did not come up:\n{self.output()}") from None
                time.sleep(0.1)

    def output(self) -> str:
        self.out.flush()
        return (self.machine.root / "daemon.out").read_text(encoding="utf-8", errors="replace")

    def real_pid(self) -> int:
        return int((self.machine.home / "serve.pid").read_text(encoding="ascii").strip())

    def kill(self) -> None:
        """Abrupt death, like a crash: no cleanup runs."""
        with contextlib.suppress(OSError):
            os.kill(self.real_pid(), signal.SIGTERM)
        self.process.wait(timeout=20)

    def stop_gracefully(self) -> int:
        if sys.platform == "win32":
            self.process.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
        else:
            self.process.send_signal(signal.SIGTERM)
        return self.process.wait(timeout=30)

    def stop(self) -> None:
        if self.process.poll() is None:
            with contextlib.suppress(Exception):
                self.kill()
            with contextlib.suppress(Exception):
                self.process.kill()
        self.out.close()


@pytest.fixture
def daemon(machine: Machine) -> Iterator[RunningDaemon]:
    assert machine.init().returncode == 0
    running = RunningDaemon(machine)
    try:
        yield running
    finally:
        running.stop()


def decision_of(proc: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    assert proc.returncode == 0, proc.stderr
    proc.stdout.decode("ascii")
    return json.loads(proc.stdout)["hookSpecificOutput"]  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------------------------
# init and uninstall
# ---------------------------------------------------------------------------------------------


def test_dry_run_validates_and_writes_nothing(machine: Machine) -> None:
    result = machine.init("--dry-run")
    assert result.returncode == 0, result.stderr
    assert "nothing was written" in result.stdout
    assert not machine.home.exists()
    assert not machine.settings.exists()


def test_init_writes_everything_it_promises_and_is_idempotent(machine: Machine) -> None:
    result = machine.init()
    assert result.returncode == 0, result.stderr + result.stdout
    for name in ("endpoint.json", "policy.yaml", "installs.json"):
        assert (machine.home / name).is_file(), name
    settings = json.loads(machine.settings.read_text(encoding="utf-8"))
    assert sorted(settings["hooks"]) == [
        "ConfigChange",
        "PostToolUse",
        "PreToolUse",
        "UserPromptSubmit",
    ]
    pre = settings["hooks"]["PreToolUse"][0]
    assert pre["matcher"] == "*"
    entry = pre["hooks"][0]
    assert os.path.isabs(entry["command"])
    assert entry["args"][:2] == ["-I", "-S"]
    assert entry["args"][-1] == "pre"
    assert entry["timeout"] == 15

    first = machine.settings.read_bytes()
    manifest = (machine.home / "installs.json").read_bytes()
    again = machine.init()
    assert again.returncode == 0
    assert "already installed" in again.stdout
    assert machine.settings.read_bytes() == first
    record = json.loads(manifest)["installs"][0]
    assert record["created_file"] is True
    assert (
        json.loads((machine.home / "installs.json").read_text(encoding="utf-8"))["installs"][0][
            "created_file"
        ]
        is True
    )  # a second run must not forget that the first one created the file

    from boundkeep import fsperm

    for path in (machine.home, machine.home / "endpoint.json", machine.home / "logs"):
        assert fsperm.check_private(str(path)) == [], path


def test_init_refuses_a_broken_settings_file_and_touches_nothing(machine: Machine) -> None:
    machine.settings.parent.mkdir(parents=True)
    machine.settings.write_text('{"permissions": ', encoding="utf-8")
    result = machine.init()
    assert result.returncode == 1
    assert "settings" in result.stderr.lower()
    assert machine.settings.read_text(encoding="utf-8") == '{"permissions": '
    assert not machine.home.exists()


def test_init_refuses_a_shim_interpreter(machine: Machine) -> None:
    shim = machine.root / "shims" / "python.exe"
    shim.parent.mkdir()
    shim.write_bytes(b"MZ")
    result = machine.init("--python", str(shim))
    assert result.returncode == 1
    assert "shim" in result.stderr
    assert not machine.home.exists()
    assert not machine.settings.exists()


def test_init_keeps_everything_else_in_the_settings_file_and_uninstall_restores_it(
    machine: Machine,
) -> None:
    original = {
        "permissions": {"allow": ["Read"], "deny": ["Bash(rm *)"]},
        "env": {"通用": "中文值 ✓"},
        "hooks": {
            "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "x"}]}]
        },
    }
    machine.settings.parent.mkdir(parents=True)
    raw = (json.dumps(original, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    machine.settings.write_bytes(raw)
    assert machine.init().returncode == 0
    installed = json.loads(machine.settings.read_text(encoding="utf-8"))
    assert installed["permissions"] == original["permissions"]
    assert installed["env"] == original["env"]
    assert installed["hooks"]["PreToolUse"][0] == original["hooks"]["PreToolUse"][0]  # theirs first
    assert len(installed["hooks"]["PreToolUse"]) == 2
    backups = list((machine.home / "backups").glob("*.bak"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == raw

    result = machine.cli("uninstall", "--project-dir", str(machine.project))
    assert result.returncode == 0, result.stderr
    assert machine.settings.read_bytes() == raw  # byte for byte
    assert (
        json.loads((machine.home / "installs.json").read_text(encoding="utf-8"))["installs"] == []
    )


def test_uninstall_deletes_a_settings_file_that_init_created(machine: Machine) -> None:
    assert machine.init().returncode == 0
    assert machine.settings.exists()
    assert machine.cli("uninstall", "--project-dir", str(machine.project)).returncode == 0
    assert not machine.settings.exists()


# ---------------------------------------------------------------------------------------------
# the daemon and the hooks
# ---------------------------------------------------------------------------------------------


def test_the_hook_blocks_the_canary_lets_the_rest_through_and_everything_is_logged(
    machine: Machine, daemon: RunningDaemon
) -> None:
    denied = decision_of(machine.hook("PreToolUse", machine.pre_event(f"echo {CANARY}")))
    assert denied["permissionDecision"] == "deny"
    assert CANARY in denied["permissionDecisionReason"]

    bash = decision_of(machine.hook("PreToolUse", machine.pre_event(f"echo {CANARY}", tool="Bash")))
    assert bash["permissionDecision"] == "deny"

    harmless = machine.hook("PreToolUse", machine.pre_event("Get-ChildItem"))
    assert (harmless.returncode, harmless.stdout) == (0, b"")

    command = 'Write-Output "你好，世界 ✓"'  # noqa: RUF001 - Chinese punctuation on purpose
    assert machine.hook("PreToolUse", machine.pre_event(command)).stdout == b""

    records = machine.log_records()
    by_command = {r.get("command"): r for r in records if r.get("event") == "pre"}
    assert by_command[f"echo {CANARY}"]["decision"] == "deny"
    assert by_command["Get-ChildItem"]["decision"] == "none"
    # what the log holds is exactly what the event said, not text the hook misread
    assert command in by_command
    assert by_command[command]["session_id"]
    assert machine.pre_event("x")  # the helper itself is sane


def test_prompt_post_and_config_events_are_logged_without_content(
    machine: Machine, daemon: RunningDaemon
) -> None:
    prompt = json.loads(
        (FIXTURES_DIR / "UserPromptSubmit__chinese.json").read_text(encoding="utf-8")
    )
    quiet = machine.hook("UserPromptSubmit", json.dumps(prompt, ensure_ascii=False).encode())
    assert (quiet.returncode, quiet.stdout) == (0, b"")
    post = (FIXTURES_DIR / "PostToolUse__WebFetch.json").read_bytes()
    assert machine.hook("PostToolUse", post).stdout == b""
    records = machine.log_records()
    prompt_record = next(r for r in records if r.get("event") == "prompt")
    assert prompt_record["prompt_chars"] == len(prompt["prompt"])
    assert prompt["prompt"] not in json.dumps(records, ensure_ascii=False)
    assert any(r.get("event") == "post" and r.get("tool_name") == "WebFetch" for r in records)


def test_audit_only_mode_records_but_does_not_block_and_takes_effect_live(
    machine: Machine, daemon: RunningDaemon
) -> None:
    assert machine.cli("mode", "audit-only").returncode == 0
    assert machine.hook("PreToolUse", machine.pre_event(f"echo {CANARY}")).stdout == b""
    last = machine.log_records()[-1]
    assert last["mode"] == "audit-only"
    assert last["would_be"] == "deny"
    assert machine.cli("mode", "enforce").returncode == 0
    assert (
        decision_of(machine.hook("PreToolUse", machine.pre_event(f"echo {CANARY}")))[
            "permissionDecision"
        ]
        == "deny"
    )
    assert machine.cli("mode").stdout.strip() == "mode: enforce"


def test_32_hook_processes_at_once_lose_no_request(machine: Machine, daemon: RunningDaemon) -> None:
    """M0 acceptance: concurrent hooks, nothing lost, every answer correct."""

    def one(i: int) -> tuple[int, bool, bytes]:
        blocked = i % 2 == 0
        command = f"echo {CANARY} {i}" if blocked else f"echo plain {i}"
        proc = machine.hook("PreToolUse", machine.pre_event(command), timeout=60)
        return (
            i,
            blocked,
            proc.stdout if proc.returncode == 0 else b"EXIT" + str(proc.returncode).encode(),
        )

    with concurrent.futures.ThreadPoolExecutor(32) as pool:
        results = list(pool.map(one, range(96)))
    for i, blocked, out in results:
        if blocked:
            assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny", (i, out)
        else:
            assert out == b"", (i, out)
    logged = [r for r in machine.log_records() if r.get("event") == "pre"]
    assert len(logged) == 96
    assert len({r["command"] for r in logged}) == 96


def test_a_killed_daemon_makes_the_hook_ask_and_a_new_one_takes_over(
    machine: Machine, daemon: RunningDaemon
) -> None:
    daemon.kill()
    started = time.monotonic()
    asked = decision_of(machine.hook("PreToolUse", machine.pre_event("Get-ChildItem")))
    assert asked["permissionDecision"] == "ask"
    assert "not running" in asked["permissionDecisionReason"]
    assert time.monotonic() - started < 5
    # prompts and tool results are not decisions: they stay quiet instead of asking
    assert (
        machine.hook(
            "PostToolUse", (FIXTURES_DIR / "PostToolUse__WebFetch.json").read_bytes()
        ).stdout
        == b""
    )

    restarted = RunningDaemon(
        machine
    )  # the stale pid file and the dead lock must not get in the way
    try:
        assert "mode=enforce" in machine.ping()
        assert (
            decision_of(machine.hook("PreToolUse", machine.pre_event(f"echo {CANARY}")))[
                "permissionDecision"
            ]
            == "deny"
        )
    finally:
        restarted.stop()


def test_a_second_daemon_is_refused(machine: Machine, daemon: RunningDaemon) -> None:
    second = machine.cli("serve", timeout=60)
    assert second.returncode == 1
    assert "already" in second.stderr.lower()
    assert "mode=enforce" in machine.ping()  # the first one is untouched


@pytest.mark.skipif(sys.platform != "win32", reason="Ctrl+Break is how a Windows console stops it")
def test_the_daemon_stops_cleanly_on_ctrl_break(machine: Machine, daemon: RunningDaemon) -> None:
    pid_file = machine.home / "serve.pid"
    assert pid_file.exists()
    daemon.stop_gracefully()
    assert not pid_file.exists()  # clean shutdown removes it
    actions = [r["action"] for r in machine.log_records() if r.get("event") == "daemon"]
    assert actions == ["start", "stop"]
    with pytest.raises(ipc_client.DaemonUnavailable):
        machine.ping()


def test_log_command_shows_records_in_both_formats_and_purges(
    machine: Machine, daemon: RunningDaemon
) -> None:
    machine.hook("PreToolUse", machine.pre_event(f"echo {CANARY}"))
    text = machine.cli("log", "--tail", "5")
    assert text.returncode == 0
    assert CANARY in text.stdout
    assert "deny" in text.stdout
    as_json = machine.cli("log", "--json", "--tail", "50")
    parsed = [json.loads(line) for line in as_json.stdout.splitlines()]
    assert any(r.get("decided_by") == "canary" for r in parsed)
    assert machine.cli("log", "--purge").returncode == 0


# ---------------------------------------------------------------------------------------------
# ConfigChange and doctor
# ---------------------------------------------------------------------------------------------


def test_the_config_hook_blocks_disable_all_hooks_and_removal(
    machine: Machine, daemon: RunningDaemon
) -> None:
    assert machine.settings.exists()
    local = machine.settings.parent / "settings.local.json"
    local.write_text('{"disableAllHooks": true}', encoding="utf-8")
    event = json.dumps(
        {"hook_event_name": "ConfigChange", "source": "local_settings", "file_path": str(local)}
    ).encode()
    blocked = machine.hook("ConfigChange", event)
    assert blocked.returncode == 2
    assert blocked.stdout == b""
    assert b"disableAllHooks" in blocked.stderr
    assert any(
        r.get("event") == "config" and r.get("local_decision") == "deny"
        for r in machine.log_records()
    )

    local.write_text("{}", encoding="utf-8")
    assert machine.hook("ConfigChange", event).returncode == 0

    original = machine.settings.read_text(encoding="utf-8")
    stripped = json.loads(original)
    del stripped["hooks"]["PreToolUse"]
    machine.settings.write_text(json.dumps(stripped), encoding="utf-8")
    event = json.dumps(
        {
            "hook_event_name": "ConfigChange",
            "source": "project_settings",
            "file_path": str(machine.settings),
        }
    ).encode()
    removed = machine.hook("ConfigChange", event)
    assert removed.returncode == 2
    assert b"PreToolUse" in removed.stderr
    machine.settings.write_text(original, encoding="utf-8")
    assert machine.hook("ConfigChange", event).returncode == 0


def doctor(machine: Machine) -> dict[str, list[dict[str, str]]]:
    result = machine.cli("doctor", "--json", "--project-dir", str(machine.project), timeout=180)
    checks = json.loads(result.stdout)
    grouped: dict[str, list[dict[str, str]]] = {}
    for check in checks:
        grouped.setdefault(check["name"], []).append(check)
    return grouped


def statuses(grouped: dict[str, list[dict[str, str]]], name: str) -> set[str]:
    return {c["status"] for c in grouped.get(name, [])}


def test_doctor_is_green_where_it_should_be_with_the_daemon_running(
    machine: Machine, daemon: RunningDaemon
) -> None:
    grouped = doctor(machine)
    assert statuses(grouped, "daemon") == {"ok"}
    assert statuses(grouped, "endpoint") == {"ok"}
    assert statuses(grouped, "policy") == {"ok"}
    assert statuses(grouped, "home") == {"ok"}
    assert statuses(grouped, "settings:project") == {"ok"}
    assert statuses(grouped, "hook-command") == {"ok"}
    assert "fail" not in statuses(grouped, "install")
    if sys.platform == "win32":
        assert statuses(grouped, "pipe-acl") == {"ok"}
    result = machine.cli("doctor", "--project-dir", str(machine.project), timeout=180)
    assert "[ OK ] daemon" in result.stdout


def test_doctor_finds_every_way_the_gate_can_be_silently_off(machine: Machine) -> None:
    assert machine.init().returncode == 0
    grouped = doctor(machine)
    assert statuses(grouped, "daemon") == {"fail"}  # nobody started it
    assert statuses(grouped, "settings:project") == {"ok"}

    local = machine.settings.parent / "settings.local.json"
    local.write_text('{"disableAllHooks": true}', encoding="utf-8")
    assert "fail" in statuses(doctor(machine), "settings:local")
    local.write_text("{}", encoding="utf-8")

    settings = json.loads(machine.settings.read_text(encoding="utf-8"))
    good = json.dumps(settings)

    broken = json.loads(good)
    broken["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = str(
        machine.root / "no" / "python.exe"
    )
    machine.settings.write_text(json.dumps(broken), encoding="utf-8")
    assert "fail" in statuses(doctor(machine), "settings:project")

    narrowed = json.loads(good)
    narrowed["hooks"]["PreToolUse"][0]["matcher"] = "Bash"
    machine.settings.write_text(json.dumps(narrowed), encoding="utf-8")
    assert any(
        "matcher" in c["detail"]
        for c in doctor(machine)["settings:project"]
        if c["status"] == "fail"
    )

    no_pre = json.loads(good)
    del no_pre["hooks"]["PreToolUse"]
    machine.settings.write_text(json.dumps(no_pre), encoding="utf-8")
    assert any(
        "PreToolUse" in c["detail"]
        for c in doctor(machine)["settings:project"]
        if c["status"] == "fail"
    )

    machine.settings.write_bytes(b"\xef\xbb\xbf" + good.encode())
    assert "warn" in statuses(doctor(machine), "settings:project")

    machine.settings.write_text("{not json", encoding="utf-8")
    assert "fail" in statuses(doctor(machine), "settings:project")

    machine.settings.unlink()
    grouped = doctor(machine)
    assert "fail" in statuses(grouped, "install")
    assert machine.cli("doctor", "--project-dir", str(machine.project), timeout=180).returncode == 1


def test_doctor_without_any_init_says_to_run_init(machine: Machine) -> None:
    grouped = doctor(machine)
    assert statuses(grouped, "home") == {"fail"}
    assert statuses(grouped, "endpoint") == {"fail"}
    assert statuses(grouped, "install") == {"fail"}


def test_the_hook_without_init_asks_and_says_why(machine: Machine) -> None:
    assert machine.init().returncode == 0
    for name in ("endpoint.json",):
        (machine.home / name).unlink()
    asked = decision_of(machine.hook("PreToolUse", machine.pre_event("Get-ChildItem")))
    assert asked["permissionDecision"] == "ask"
    assert "boundkeep init" in asked["permissionDecisionReason"]


def test_everything_works_under_a_path_with_chinese_characters_and_spaces(tmp_path: Path) -> None:
    """The dev machine's Git lives under a Chinese-named folder: paths like that must just work.

    The hook command, the settings file, the endpoint, the log and the project all sit below a
    directory called "用户 数据" here; the hook is launched as an exec-form argv (no shell, no
    quoting), exactly as Claude Code does.
    """
    machine = Machine(tmp_path / "用户 数据")
    assert machine.init().returncode == 0
    settings = json.loads(machine.settings.read_text(encoding="utf-8"))
    entry = settings["hooks"]["PreToolUse"][0]["hooks"][0]
    script = entry["args"][2]
    assert os.path.isfile(script)
    running = RunningDaemon(machine)
    try:
        denied = decision_of(machine.hook("PreToolUse", machine.pre_event(f"echo {CANARY}")))
        assert denied["permissionDecision"] == "deny"
        assert machine.hook("PreToolUse", machine.pre_event("Get-ChildItem")).stdout == b""
        records = [r for r in machine.log_records() if r.get("event") == "pre"]
        assert [r["decision"] for r in records] == ["deny", "none"]
        assert machine.cli("doctor", "--project-dir", str(machine.project)).returncode == 0
    finally:
        running.stop()
