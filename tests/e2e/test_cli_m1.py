"""The M1 commands: ``test``, ``explain``, ``init --reset-policy`` and the doctor policy checks."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from boundkeep.policy import default_policy_text
from tests.conftest import REPO_ROOT
from tests.e2e.test_cli_flow import (  # noqa: F401 - the fixtures
    Machine,
    RunningDaemon,
    daemon,
    machine,
)

pytestmark = pytest.mark.e2e


def test_boundkeep_test_passes_the_shipped_policies_on_both_platforms(machine: Machine) -> None:
    for policy in ("default.yaml", "strict.yaml"):
        result = machine.cli("test", "--policy", str(REPO_ROOT / "policies" / policy))
        assert result.returncode == 0, result.stdout + result.stderr
        assert "== platform: windows" in result.stdout
        assert "== platform: posix" in result.stdout
        assert " 0 failed" in result.stdout
    only = machine.cli("test", "--platform", "posix")
    assert "== platform: windows" not in only.stdout


def test_boundkeep_test_fails_and_says_which_case_when_a_policy_test_does_not_hold(
    machine: Machine, tmp_path: Path
) -> None:
    text = default_policy_text()
    broken = text.replace(
        'input: { command: "rm -rf /" },                    expect: deny',
        'input: { command: "rm -rf /" },                    expect: allow',
    )
    assert broken != text
    policy = tmp_path / "p.yaml"
    policy.write_text(broken, encoding="utf-8")
    result = machine.cli("test", "--policy", str(policy))
    assert result.returncode == 1
    assert "[FAIL]" in result.stdout
    assert "expected allow, got deny" in result.stdout


def test_boundkeep_test_reports_an_unusable_policy_file(machine: Machine, tmp_path: Path) -> None:
    policy = tmp_path / "bad.yaml"
    policy.write_text("version: 1\nrules:\n  - id: Bad Id\n", encoding="utf-8")
    result = machine.cli("test", "--policy", str(policy))
    assert result.returncode == 1
    assert "line" in result.stderr


def test_explain_shows_actions_rules_and_the_hook_output(machine: Machine, tmp_path: Path) -> None:
    event = {
        "tool_name": "Bash",
        "tool_input": {"command": "cat ~/.ssh/id_rsa && pytest -q"},
        "cwd": str(machine.project),
    }
    path = tmp_path / "event.json"
    path.write_text(json.dumps(event), encoding="utf-8")
    result = machine.cli(
        "explain", str(path), "--policy", str(REPO_ROOT / "policies" / "default.yaml")
    )
    assert result.returncode == 0, result.stderr
    assert "rule no-secret-read (deny)" in result.stdout
    assert "verdict: deny" in result.stdout
    assert '"permissionDecision":"deny"' in result.stdout
    plain = {
        "tool_name": "Read",
        "tool_input": {"file_path": str(machine.project / "a.py")},
        "cwd": str(machine.project),
    }
    path.write_text(json.dumps(plain), encoding="utf-8")
    quiet = machine.cli(
        "explain", str(path), "--policy", str(REPO_ROOT / "policies" / "default.yaml")
    )
    assert "verdict: allow" in quiet.stdout
    assert "hook output: (nothing" in quiet.stdout


def test_explain_refuses_unreadable_input(machine: Machine, tmp_path: Path) -> None:
    missing = machine.cli("explain", str(tmp_path / "nope.json"))
    assert missing.returncode == 1
    not_object = tmp_path / "x.json"
    not_object.write_text("[1]", encoding="utf-8")
    assert machine.cli("explain", str(not_object)).returncode == 1


def test_init_installs_the_default_rules_and_reset_policy_upgrades_an_m0_file(
    machine: Machine,
) -> None:
    assert machine.init().returncode == 0
    policy = machine.home / "policy.yaml"
    assert "rules:" in policy.read_text(encoding="utf-8")
    # what an M0 install left behind: four keys, audit-only
    policy.write_text("version: 1\nmode: audit-only\n", encoding="utf-8")
    warned = machine.cli("doctor", "--project-dir", str(machine.project), "--json")
    assert "the policy has no rules" in warned.stdout
    result = machine.init("--reset-policy")
    assert result.returncode == 0, result.stderr
    assert "reset to the default policy (mode audit-only)" in result.stdout
    text = policy.read_text(encoding="utf-8")
    assert "rules:" in text
    assert "mode: audit-only" in text
    assert any((machine.home / "backups").glob("policy*"))


def test_doctor_warns_when_emit_allow_is_on(machine: Machine) -> None:
    assert machine.init().returncode == 0
    policy = machine.home / "policy.yaml"
    policy.write_text(
        policy.read_text(encoding="utf-8").replace("emit_allow: false", "emit_allow: true"),
        encoding="utf-8",
    )
    result = machine.cli("doctor", "--project-dir", str(machine.project), "--json")
    assert "emit_allow is on" in result.stdout


DEFAULT_POLICY = str(REPO_ROOT / "policies" / "default.yaml")


def cli_with_env(
    machine: Machine, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Like ``machine.cli`` but with extra environment variables."""
    full = {**machine.env, **(env or {})}
    return subprocess.run(
        [sys.executable, "-m", "boundkeep", *args],
        capture_output=True,
        env=full,
        cwd=str(machine.project),
        timeout=120,
        check=False,
        encoding="utf-8",
        errors="replace",
    )


# --------------------------------------------------------------------------------------------
# init: a truthful M1 epilogue, --reset-policy over a policy that does not load
# --------------------------------------------------------------------------------------------


def test_init_tells_the_truth_about_m1_and_does_not_claim_m0(machine: Machine) -> None:
    result = machine.init()
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "M0 only blocks" not in out
    assert "BOUNDKEEP_CANARY" not in out
    assert " rules loaded" in out
    assert "mode: enforce" in out
    assert "no rule decides" in out
    assert "asks" in out
    assert "boundkeep mode audit-only" in out
    assert "PowerShell" in out
    assert "M1b" in out
    assert "boundkeep test" in out
    assert "boundkeep explain" in out


def test_init_epilogue_describes_the_policy_that_is_in_place(machine: Machine) -> None:
    assert machine.init().returncode == 0
    (machine.home / "policy.yaml").write_text("version: 1\nmode: audit-only\n", encoding="utf-8")
    again = machine.init()
    assert again.returncode == 0, again.stderr
    assert "0 rules loaded" in again.stdout  # an M0 policy: every shell command asks
    assert "mode: audit-only" in again.stdout


BROKEN_POLICY = "version: 1\nmode: audit-only\nrules:\n  - id: Bad Id\n"


def test_plain_init_over_an_invalid_policy_fails_and_points_at_reset_policy(
    machine: Machine,
) -> None:
    assert machine.init().returncode == 0
    policy = machine.home / "policy.yaml"
    policy.write_text(BROKEN_POLICY, encoding="utf-8")
    result = machine.init()
    assert result.returncode == 1
    assert "--reset-policy" in result.stderr
    assert "policy" in result.stderr
    assert policy.read_text(encoding="utf-8") == BROKEN_POLICY  # untouched


def test_reset_policy_repairs_an_invalid_policy_and_keeps_a_backup(machine: Machine) -> None:
    assert machine.init().returncode == 0
    policy = machine.home / "policy.yaml"
    policy.write_text(BROKEN_POLICY, encoding="utf-8")
    result = machine.init("--reset-policy")
    assert result.returncode == 0, result.stderr
    assert "reset to the default policy" in result.stdout
    assert " rules loaded" in result.stdout
    text = policy.read_text(encoding="utf-8")
    assert "rules:" in text
    assert "Bad Id" not in text
    backups = list((machine.home / "backups").glob("policy*"))
    assert any(b.read_text(encoding="utf-8") == BROKEN_POLICY for b in backups)
    assert machine.cli("test").returncode == 0  # the repaired policy loads


def test_reset_policy_dry_run_over_an_invalid_policy_reports_and_changes_nothing(
    machine: Machine,
) -> None:
    assert machine.init().returncode == 0
    policy = machine.home / "policy.yaml"
    policy.write_text(BROKEN_POLICY, encoding="utf-8")
    result = machine.init("--reset-policy", "--dry-run")
    assert result.returncode == 0, result.stderr
    assert "would be reset" in result.stdout
    assert "nothing was written" in result.stdout
    assert policy.read_text(encoding="utf-8") == BROKEN_POLICY
    assert not list((machine.home / "backups").glob("policy*"))


# --------------------------------------------------------------------------------------------
# test: zero tests is not a pass
# --------------------------------------------------------------------------------------------

WINDOWS_ONLY_TESTS = """\
version: 1
rules:
  - id: no-rm-root
    tool: [Bash]
    match: { program: rm }
    action: deny
    reason: rm is not allowed here
tests:
  - { tool: Bash, platform: [windows], input: { command: "rm -rf /" }, expect: deny }
"""


def test_a_policy_without_tests_does_not_pass_silently(machine: Machine, tmp_path: Path) -> None:
    policy = tmp_path / "no-tests.yaml"
    policy.write_text("version: 1\n", encoding="utf-8")
    for platform in ("all", "windows", "posix"):
        result = machine.cli("test", "--policy", str(policy), "--platform", platform)
        assert result.returncode == 1, (platform, result.stdout)
        assert "no test" in result.stderr


def test_an_explicit_platform_with_no_applicable_tests_fails(
    machine: Machine, tmp_path: Path
) -> None:
    policy = tmp_path / "windows-only.yaml"
    policy.write_text(WINDOWS_ONLY_TESTS, encoding="utf-8")
    posix = machine.cli("test", "--policy", str(policy), "--platform", "posix")
    assert posix.returncode == 1, posix.stdout
    assert "posix" in posix.stderr
    assert "no test" in posix.stderr
    windows = machine.cli("test", "--policy", str(policy), "--platform", "windows")
    assert windows.returncode == 0, windows.stdout + windows.stderr
    assert "1 test(s) run, 0 failed" in windows.stdout
    both = machine.cli("test", "--policy", str(policy))  # "all": one platform ran something
    assert both.returncode == 0, both.stdout + both.stderr


# --------------------------------------------------------------------------------------------
# explain: the project directory the daemon would use, and no raw control characters
# --------------------------------------------------------------------------------------------


def _write_event(path: Path, event: dict[str, object]) -> str:
    path.write_text(json.dumps(event), encoding="utf-8")
    return str(path)


def test_explain_uses_claude_project_dir_before_the_event_and_the_cwd(
    machine: Machine, tmp_path: Path
) -> None:
    elsewhere = machine.root / "elsewhere"
    elsewhere.mkdir()
    event: dict[str, object] = {
        "tool_name": "Read",
        "tool_input": {"file_path": str(machine.project / "a.py")},
        "cwd": str(elsewhere),
    }
    path = _write_event(tmp_path / "e.json", event)
    # the hook forwards CLAUDE_PROJECT_DIR: that is the project the daemon sees
    with_env = cli_with_env(
        machine,
        "explain",
        path,
        "--policy",
        DEFAULT_POLICY,
        env={"CLAUDE_PROJECT_DIR": str(machine.project)},
    )
    assert with_env.returncode == 0, with_env.stderr
    assert "verdict: allow" in with_env.stdout
    assert "CLAUDE_PROJECT_DIR" in with_env.stdout
    # without it and without a project_dir in the event, the cwd is the project: the file is outside
    without = cli_with_env(machine, "explain", path, "--policy", DEFAULT_POLICY)
    assert "verdict: allow" not in without.stdout
    assert "cwd" in without.stdout
    # the event's own project_dir comes before the cwd
    event["project_dir"] = str(machine.project)
    path = _write_event(tmp_path / "e2.json", event)
    from_event = cli_with_env(machine, "explain", path, "--policy", DEFAULT_POLICY)
    assert "verdict: allow" in from_event.stdout
    assert "the event" in from_event.stdout
    # the environment wins over the event
    other = machine.root / "other-project"
    other.mkdir()
    both = cli_with_env(
        machine,
        "explain",
        path,
        "--policy",
        DEFAULT_POLICY,
        env={"CLAUDE_PROJECT_DIR": str(other)},
    )
    assert "verdict: allow" not in both.stdout


def test_explain_does_not_print_control_characters_from_the_event(
    machine: Machine, tmp_path: Path
) -> None:
    evil = "echo hi\x1b[2J\x1b]0;pwned\x07 ‮fdp.exe ; cat \x1b[31m~/.ssh/id_rsa"
    event = {
        "tool_name": "Bash",
        "tool_input": {"command": evil},
        "cwd": str(machine.project),
    }
    path = _write_event(tmp_path / "evil.json", event)
    result = machine.cli("explain", path, "--policy", DEFAULT_POLICY)
    assert result.returncode == 0, result.stderr
    for bad in ("\x1b", "\x07", "‮"):
        assert bad not in result.stdout, repr(bad)
    assert "verdict: deny" in result.stdout  # the text stays, only the control characters go
    assert "id_rsa" in result.stdout
    assert "args:" in result.stdout


def test_explain_sanitizes_the_tool_name_and_caps_very_long_fields(
    machine: Machine, tmp_path: Path
) -> None:
    event = {
        "tool_name": "Bash\x1b[2J",
        "tool_input": {"command": "cat " + "a" * 50_000},
        "cwd": str(machine.project),
    }
    path = _write_event(tmp_path / "long.json", event)
    result = machine.cli("explain", path, "--policy", DEFAULT_POLICY)
    assert result.returncode == 0, result.stderr
    assert "\x1b" not in result.stdout
    assert max(len(line) for line in result.stdout.splitlines()) < 1500


# --------------------------------------------------------------------------------------------
# doctor: CLAUDE_CONFIG_DIR must be the same for the daemon and for Claude Code
# --------------------------------------------------------------------------------------------


def _checks(result: subprocess.CompletedProcess[str], name: str) -> list[dict[str, str]]:
    return [c for c in json.loads(result.stdout) if c["name"] == name]


def test_doctor_notes_claude_config_dir_and_warns_when_the_daemon_has_another_value(
    machine: Machine, daemon: RunningDaemon
) -> None:
    config = str(machine.root / "claude-config")
    unset = cli_with_env(machine, "doctor", "--project-dir", str(machine.project), "--json")
    assert _checks(unset, "config-dir") == []  # nothing to say when neither side sets it
    result = cli_with_env(
        machine,
        "doctor",
        "--project-dir",
        str(machine.project),
        "--json",
        env={"CLAUDE_CONFIG_DIR": config},
    )
    checks = _checks(result, "config-dir")
    statuses = {c["status"] for c in checks}
    assert "info" in statuses
    assert "warn" in statuses  # the daemon was started without it
    warning = next(c for c in checks if c["status"] == "warn")
    assert "daemon" in warning["detail"]
    assert config in warning["detail"]
    assert "config_dir=-" in machine.ping()


def test_doctor_does_not_warn_about_claude_config_dir_when_daemon_and_doctor_agree(
    machine: Machine,
) -> None:
    assert machine.init().returncode == 0
    config = str(machine.root / "claude-config")
    machine.env["CLAUDE_CONFIG_DIR"] = config
    running = RunningDaemon(machine)
    try:
        assert f"config_dir={config}" in machine.ping()
        result = machine.cli("doctor", "--project-dir", str(machine.project), "--json")
        checks = _checks(result, "config-dir")
        assert checks
        assert {c["status"] for c in checks} == {"info"}
    finally:
        running.stop()
