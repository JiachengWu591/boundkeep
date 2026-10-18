"""Security review round 2 (docs/reviews/M1-M1b-security-review.md): H-3, M-6, M-4 integrity and the
``--emit-allow`` pin, reproduced through the real CLI in a throwaway user profile and project.

Everything runs against ``Machine`` (tests/e2e/test_cli_flow.py): USERPROFILE, HOME and the
boundkeep home point at a temporary directory, CLAUDE_CONFIG_DIR is removed, so neither the real
~/.boundkeep nor the real ~/.claude (nor this repository's settings) is read or written.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.e2e.test_cli_flow import Machine

pytestmark = pytest.mark.e2e


@pytest.fixture
def machine(tmp_path: Path) -> Machine:
    return Machine(tmp_path)


def _write_project_settings(m: Machine, data: dict[str, Any]) -> None:
    m.settings.parent.mkdir(parents=True, exist_ok=True)
    m.settings.write_text(json.dumps(data), encoding="utf-8")


# ---- H-3 ------------------------------------------------------------------------------------


def test_h3_project_install_says_it_only_covers_that_folder(machine: Machine) -> None:
    result = machine.init()
    assert result.returncode == 0, result.stderr
    assert "only" in result.stdout.lower()
    assert str(machine.project) in result.stdout
    assert "--scope user" in result.stdout


def test_h3_doctor_without_project_dir_names_the_directory_it_checks(machine: Machine) -> None:
    assert machine.init().returncode == 0
    result = machine.cli("doctor")  # cwd is the project: no --project-dir given
    assert str(machine.project) in result.stdout
    assert "only" in result.stdout.lower()


# ---- M-6 ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [
        {"disableAllHooks": True},
        {"env": {"BOUNDKEEP_HOME": "C:\\somewhere"}},
    ],
)
def test_m6_init_refuses_a_file_that_switches_the_gate_off(
    machine: Machine, data: dict[str, Any]
) -> None:
    _write_project_settings(machine, data)
    before = machine.settings.read_bytes()
    result = machine.init()
    assert result.returncode == 1, result.stdout
    assert machine.settings.read_bytes() == before


@pytest.mark.parametrize(
    "data",
    [
        {"foo": 1, "PreToolUse": []},
        {"permissions": {"defaultMode": "bypassPermissions"}},
        {"permissions": {"allow": ["Bash(*)"]}},
        {"statusLine": {"type": "command", "command": "x"}},
        {"env": {"NODE_OPTIONS": "--require x"}},
    ],
)
def test_m6_init_warns_about_a_file_that_may_weaken_the_gate(
    machine: Machine, data: dict[str, Any]
) -> None:
    _write_project_settings(machine, data)
    result = machine.init()
    assert result.returncode == 0, result.stderr
    assert "warning" in (result.stdout + result.stderr).lower()


@pytest.mark.parametrize("layer", ["user", "local"])
def test_m6_doctor_checks_env_in_every_layer(machine: Machine, layer: str) -> None:
    assert machine.init().returncode == 0
    if layer == "user":
        path = machine.user / ".claude" / "settings.json"
    else:
        path = machine.project / ".claude" / "settings.local.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"env": {"BOUNDKEEP_HOME": "C:\\evil"}}), encoding="utf-8")
    result = machine.cli("doctor", "--project-dir", str(machine.project))
    assert "BOUNDKEEP_HOME" in result.stdout
    assert result.returncode == 1


# ---- M-4 ------------------------------------------------------------------------------------


def test_m4_installs_json_records_hashes_of_the_hook_files(machine: Machine) -> None:
    assert machine.init().returncode == 0
    text = (machine.home / "installs.json").read_text(encoding="utf-8")
    assert "sha256" in text


def test_m4_doctor_fails_when_a_hook_script_no_longer_matches_the_recorded_hash(
    machine: Machine,
) -> None:
    # The installed scripts are this repository's own files, which must not be edited by a test:
    # the recorded hash is changed instead (the same mismatch, without touching the source tree).
    assert machine.init().returncode == 0
    manifest = machine.home / "installs.json"
    text = manifest.read_text(encoding="utf-8")
    doc = json.loads(text)
    files = doc["installs"][0]["hook_files"]
    files[0]["sha256"] = "0" * 64
    manifest.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    result = machine.cli("doctor", "--project-dir", str(machine.project))
    assert "no longer matches" in result.stdout
    assert result.returncode == 1


# ---- H-3: more ------------------------------------------------------------------------------


def test_h3_user_scope_install_says_it_covers_every_folder(machine: Machine) -> None:
    config_dir = machine.root / "claude-config"
    machine.env["CLAUDE_CONFIG_DIR"] = str(config_dir)
    result = machine.cli("init", "--scope", "user")
    assert result.returncode == 0, result.stderr
    assert "USER-LEVEL" in result.stdout
    assert "PROJECT-LEVEL" not in result.stdout
    assert (config_dir / "settings.json").exists()
    assert not machine.settings.exists()


def test_h3_dry_run_prints_the_notice_too(machine: Machine) -> None:
    result = machine.init("--dry-run")
    assert result.returncode == 0, result.stderr
    assert "PROJECT-LEVEL" in result.stdout
    assert not machine.settings.exists()


def test_h3_doctor_with_project_dir_does_not_warn_about_the_directory(machine: Machine) -> None:
    assert machine.init().returncode == 0
    result = machine.cli("doctor", "--project-dir", str(machine.project), "--json")
    checks = json.loads(result.stdout)
    scope = [c for c in checks if c["name"] == "scope"]
    assert [c["status"] for c in scope] == ["info"]
    assert "only to Claude Code sessions opened in" in scope[0]["detail"]


def test_h3_doctor_without_project_dir_warns_for_a_project_level_install(
    machine: Machine,
) -> None:
    assert machine.init().returncode == 0
    checks = json.loads(machine.cli("doctor", "--json").stdout)
    scope = [c for c in checks if c["name"] == "scope"]
    assert [c["status"] for c in scope] == ["warn"]
    assert "the current directory" in scope[0]["detail"]
    assert "--scope user" in scope[0]["fix"]


def test_h3_doctor_without_project_dir_only_informs_for_a_user_level_install(
    machine: Machine,
) -> None:
    machine.env["CLAUDE_CONFIG_DIR"] = str(machine.root / "claude-config")
    assert machine.cli("init", "--scope", "user").returncode == 0
    checks = json.loads(machine.cli("doctor", "--json").stdout)
    assert [c["status"] for c in checks if c["name"] == "scope"] == ["info"]


def test_h3_workspace_trust_reads_the_claude_config_dir(machine: Machine) -> None:
    config_dir = machine.root / "claude-config"
    config_dir.mkdir()
    state = {
        "projects": {str(machine.project).replace("\\", "/"): {"hasTrustDialogAccepted": True}}
    }
    (config_dir / ".claude.json").write_text(json.dumps(state), encoding="utf-8")
    machine.env["CLAUDE_CONFIG_DIR"] = str(config_dir)
    checks = json.loads(
        machine.cli("doctor", "--project-dir", str(machine.project), "--json").stdout
    )
    trust = [c for c in checks if c["name"] == "workspace-trust"]
    assert [c["status"] for c in trust] == ["ok"], trust


# ---- M-6: more ------------------------------------------------------------------------------


def test_m6_init_refuses_a_broken_env_block(machine: Machine) -> None:
    _write_project_settings(machine, {"env": ["x"]})
    result = machine.init()
    assert result.returncode == 1
    assert "nothing was written" in result.stderr


def test_m6_a_refused_init_leaves_no_manifest_entry(machine: Machine) -> None:
    _write_project_settings(machine, {"disableAllHooks": True})
    assert machine.init().returncode == 1
    assert not (machine.home / "installs.json").exists()


def test_m6_init_refuses_gate_off_in_dry_run_too(machine: Machine) -> None:
    _write_project_settings(machine, {"disableAllHooks": "false"})
    assert machine.init("--dry-run").returncode == 1


def test_m6_init_warns_when_another_layer_switches_hooks_off(machine: Machine) -> None:
    user_settings = machine.user / ".claude" / "settings.json"
    user_settings.parent.mkdir(parents=True)
    user_settings.write_text(json.dumps({"disableAllHooks": True}), encoding="utf-8")
    result = machine.init()
    assert result.returncode == 0, result.stderr
    assert "WARNING" in result.stdout
    assert str(user_settings) in result.stdout
    assert "disableAllHooks" in result.stdout


def test_m6_init_names_the_unreadable_layer(machine: Machine) -> None:
    local = machine.project / ".claude" / "settings.local.json"
    local.parent.mkdir(parents=True)
    local.write_text("{not json", encoding="utf-8")
    result = machine.init()
    assert result.returncode == 0, result.stderr
    assert "WARNING" in result.stdout
    assert "settings.local.json" in result.stdout


@pytest.mark.parametrize(
    ("data", "needle"),
    [
        ({"permissions": {"allow": ["Bash(*)", "PowerShell(*)", "Write(*)"]}}, "permissions.allow"),
        ({"permissions": {"defaultMode": "bypassPermissions"}}, "bypassPermissions"),
        ({"skipDangerousModePermissionPrompt": True}, "skipDangerousModePermissionPrompt"),
        ({"env": {"PATH": "C:\\x"}}, "PATH"),
        ({"env": {"PYTHONPATH": "C:\\x"}}, "PYTHONPATH"),
        ({"env": {"CLAUDE_PROJECT_DIR": "C:\\x"}}, "CLAUDE_PROJECT_DIR"),
        (
            {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "x"}]}]}},
            "PreToolUse",
        ),
        ({"hooks": {"PreToolUze": []}}, "PreToolUze"),
    ],
)
def test_m6_doctor_fails_for_each_weakening_setting_in_the_user_layer(
    machine: Machine, data: dict[str, Any], needle: str
) -> None:
    assert machine.init().returncode == 0
    user_settings = machine.user / ".claude" / "settings.json"
    user_settings.parent.mkdir(parents=True, exist_ok=True)
    user_settings.write_text(json.dumps(data), encoding="utf-8")
    checks = json.loads(
        machine.cli("doctor", "--project-dir", str(machine.project), "--json").stdout
    )
    hits = [c for c in checks if c["name"] == "settings:user" and needle in c["detail"]]
    assert hits, [(c["name"], c["status"], c["detail"][:80]) for c in checks]


def test_m6_doctor_fails_for_a_misplaced_event_next_to_our_hooks(machine: Machine) -> None:
    assert machine.init().returncode == 0
    doc = json.loads(machine.settings.read_text(encoding="utf-8"))
    doc["PreToolUse"] = []
    machine.settings.write_text(json.dumps(doc), encoding="utf-8")
    checks = json.loads(
        machine.cli("doctor", "--project-dir", str(machine.project), "--json").stdout
    )
    hits = [c for c in checks if c["name"] == "settings:project" and "'PreToolUse'" in c["detail"]]
    assert [c["status"] for c in hits] == ["fail"]


def test_m6_an_unknown_top_level_key_warns_next_to_our_hooks(machine: Machine) -> None:
    assert machine.init().returncode == 0
    doc = json.loads(machine.settings.read_text(encoding="utf-8"))
    doc["someFutureKey"] = 1
    machine.settings.write_text(json.dumps(doc), encoding="utf-8")
    checks = json.loads(
        machine.cli("doctor", "--project-dir", str(machine.project), "--json").stdout
    )
    hits = [c for c in checks if c["name"] == "settings:project" and "someFutureKey" in c["detail"]]
    assert [c["status"] for c in hits] == ["warn"]


def test_m6_a_statusline_present_at_init_is_the_baseline_and_a_change_fails(
    machine: Machine,
) -> None:
    _write_project_settings(machine, {"statusLine": {"type": "command", "command": "echo one"}})
    assert machine.init().returncode == 0
    base = json.loads(machine.cli("doctor", "--project-dir", str(machine.project), "--json").stdout)
    assert not [c for c in base if "statusLine" in c["detail"] and c["status"] in ("fail", "warn")]
    doc = json.loads(machine.settings.read_text(encoding="utf-8"))
    doc["statusLine"]["command"] = "echo two"
    machine.settings.write_text(json.dumps(doc), encoding="utf-8")
    changed = json.loads(
        machine.cli("doctor", "--project-dir", str(machine.project), "--json").stdout
    )
    hits = [c for c in changed if "statusLine" in c["detail"]]
    assert [c["status"] for c in hits] == ["fail"]
    assert "boundkeep init" in hits[0]["fix"]


def test_m6_a_foreign_pre_tool_use_hook_at_init_warns_then_is_the_baseline(
    machine: Machine,
) -> None:
    foreign = {"hooks": [{"type": "command", "command": "C:\\other\\fmt.exe"}]}
    _write_project_settings(machine, {"hooks": {"PreToolUse": [foreign]}})
    result = machine.init()
    assert result.returncode == 0, result.stderr
    assert "WARNING" in result.stdout
    assert "PreToolUse" in result.stdout
    checks = json.loads(
        machine.cli("doctor", "--project-dir", str(machine.project), "--json").stdout
    )
    assert not [c for c in checks if "not boundkeep's" in c["detail"] and c["status"] != "info"]


# ---- M-4: more ------------------------------------------------------------------------------


def test_m4_init_records_the_interpreter_and_both_hook_scripts(machine: Machine) -> None:
    assert machine.init().returncode == 0
    doc = json.loads((machine.home / "installs.json").read_text(encoding="utf-8"))
    files = doc["installs"][0]["hook_files"]
    names = sorted(Path(f["path"]).name.lower() for f in files)
    assert names == sorted(
        ["hook_client.py", "hook_main.py", Path(doc["installs"][0]["hook_command"]).name.lower()]
    )
    assert all(len(f["sha256"]) == 64 for f in files)


def test_m4_doctor_is_ok_with_untouched_files(machine: Machine) -> None:
    assert machine.init().returncode == 0
    checks = json.loads(
        machine.cli("doctor", "--project-dir", str(machine.project), "--json").stdout
    )
    hits = [c for c in checks if "match the hashes" in c["detail"]]
    assert [c["status"] for c in hits] == ["ok"]


def test_m4_doctor_warns_about_a_record_without_hashes(machine: Machine) -> None:
    assert machine.init().returncode == 0
    manifest = machine.home / "installs.json"
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    del doc["installs"][0]["hook_files"]
    manifest.write_text(json.dumps(doc), encoding="utf-8")
    result = machine.cli("doctor", "--project-dir", str(machine.project), "--json")
    checks = json.loads(result.stdout)
    hits = [c for c in checks if "no file hashes" in c["detail"]]
    assert [c["status"] for c in hits] == ["warn"]
    assert "init" in hits[0]["fix"]
    # a warning, not a failure: an old install keeps working (the daemon is not running here, so
    # the exit code is 1 for that reason alone: nothing about the settings layer fails)
    assert not [c for c in checks if c["name"] == "settings:project" and c["status"] == "fail"]


def test_m4_init_again_refreshes_the_hashes(machine: Machine) -> None:
    assert machine.init().returncode == 0
    manifest = machine.home / "installs.json"
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    doc["installs"][0]["hook_files"][0]["sha256"] = "f" * 64
    manifest.write_text(json.dumps(doc), encoding="utf-8")
    assert machine.cli("doctor", "--project-dir", str(machine.project)).returncode == 1
    assert machine.init().returncode == 0
    again = json.loads(
        machine.cli("doctor", "--project-dir", str(machine.project), "--json").stdout
    )
    assert not [c for c in again if c["name"] == "settings:project" and c["status"] == "fail"]
    after = json.loads(manifest.read_text(encoding="utf-8"))
    assert after["installs"][0]["hook_files"][0]["sha256"] != "f" * 64


# ---- --emit-allow pin -----------------------------------------------------------------------


def _hook_args(m: Machine) -> list[list[str]]:
    doc = json.loads(m.settings.read_text(encoding="utf-8"))
    return [group["hooks"][0]["args"] for groups in doc["hooks"].values() for group in groups]


def test_emit_allow_off_is_not_pinned(machine: Machine) -> None:
    assert machine.init().returncode == 0
    for args in _hook_args(machine):
        assert "--emit-allow" not in args
        assert "--home" in args


def test_emit_allow_on_in_the_policy_is_pinned_into_every_hook(machine: Machine) -> None:
    assert machine.init().returncode == 0
    policy = machine.home / "policy.yaml"
    policy.write_text(
        policy.read_text(encoding="utf-8").replace("emit_allow: false", "emit_allow: true"),
        encoding="utf-8",
    )
    result = machine.init()
    assert result.returncode == 0, result.stderr
    assert "emit_allow" in result.stdout
    args_lists = _hook_args(machine)
    assert len(args_lists) == 4
    for args in args_lists:
        assert args.count("--emit-allow") == 1
        assert args[-1] in ("pre", "post", "prompt", "config")  # the subcommand stays last
        assert args[args.index("--home") + 1] == str(machine.home)
    recorded = json.loads((machine.home / "installs.json").read_text(encoding="utf-8"))
    assert "--emit-allow" in recorded["installs"][0]["hook_args"]


def test_emit_allow_turned_off_again_removes_the_pin(machine: Machine) -> None:
    assert machine.init().returncode == 0
    policy = machine.home / "policy.yaml"
    text = policy.read_text(encoding="utf-8")
    policy.write_text(text.replace("emit_allow: false", "emit_allow: true"), encoding="utf-8")
    assert machine.init().returncode == 0
    policy.write_text(text, encoding="utf-8")
    assert machine.init().returncode == 0
    for args in _hook_args(machine):
        assert "--emit-allow" not in args


def test_doctor_warns_when_the_pin_and_the_policy_differ(machine: Machine) -> None:
    assert machine.init().returncode == 0
    policy = machine.home / "policy.yaml"
    policy.write_text(
        policy.read_text(encoding="utf-8").replace("emit_allow: false", "emit_allow: true"),
        encoding="utf-8",
    )
    checks = json.loads(
        machine.cli("doctor", "--project-dir", str(machine.project), "--json").stdout
    )
    hits = [c for c in checks if c["name"] == "emit-allow"]
    assert [c["status"] for c in hits] == ["warn"]
    assert "does not carry --emit-allow" in hits[0]["detail"]
    # ... and init again makes them agree.
    assert machine.init().returncode == 0
    checks = json.loads(
        machine.cli("doctor", "--project-dir", str(machine.project), "--json").stdout
    )
    assert not [c for c in checks if c["name"] == "emit-allow"]


def test_doctor_warns_about_a_pin_the_policy_does_not_ask_for(machine: Machine) -> None:
    assert machine.init().returncode == 0
    doc = json.loads(machine.settings.read_text(encoding="utf-8"))
    for groups in doc["hooks"].values():
        for group in groups:
            args = group["hooks"][0]["args"]
            args.insert(len(args) - 1, "--emit-allow")
    machine.settings.write_text(json.dumps(doc), encoding="utf-8")
    checks = json.loads(
        machine.cli("doctor", "--project-dir", str(machine.project), "--json").stdout
    )
    hits = [c for c in checks if c["name"] == "emit-allow"]
    assert [c["status"] for c in hits] == ["warn"]
    assert "carries --emit-allow but the policy" in hits[0]["detail"]
