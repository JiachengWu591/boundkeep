"""M1b review fixes in the built-in policies: Windows persistence / account / shutdown commands."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from boundkeep import policycli
from boundkeep.policy import parse_policy_text

POLICIES = Path(__file__).resolve().parents[2] / "policies"
NEW_PROGRAMS = [
    "Copy-ItemProperty", "Move-ItemProperty", "Rename-ItemProperty", "Clear-ItemProperty",
    "Set-WmiInstance", "New-CimInstance", "Register-ScheduledJob", "Register-ObjectEvent",
    "New-LocalUser", "Add-LocalGroupMember", "Remove-Service", "Disable-ScheduledTask",
    "Remove-NetFirewallRule", "Enable-NetFirewallRule", "Disable-NetFirewallRule",
    "Set-NetFirewallSetting", "Remove-MpPreference", "Clear-EventLog", "setx", "vssadmin",
    "wevtutil", "takeown", "cipher", "Stop-Computer", "Restart-Computer",
]  # fmt: skip
OLD_PROGRAMS = ["schtasks", "Register-ScheduledTask", "New-Service", "sc", "reg", "netsh", "wmic"]


def _rules(name: str) -> dict[str, dict[str, Any]]:
    data = yaml.safe_load((POLICIES / f"{name}.yaml").read_text(encoding="utf-8"))
    return {rule["id"]: rule for rule in data["rules"]}


@pytest.fixture(params=["default", "strict"])
def rules(request: pytest.FixtureRequest) -> dict[str, dict[str, Any]]:
    return _rules(request.param)


def test_persistence_commands_rule_names_every_reviewed_program(
    rules: dict[str, dict[str, Any]],
) -> None:
    rule = rules["windows-persistence-commands"]
    names = {p.lower() for p in rule["match"]["program"]}
    assert rule["action"] == "ask"
    assert set(rule["tool"]) == {"Bash", "PowerShell"}
    missing = [p for p in NEW_PROGRAMS + OLD_PROGRAMS if p.lower() not in names]
    assert missing == []


def test_default_and_strict_persistence_lists_agree() -> None:
    a = _rules("default")["windows-persistence-commands"]["match"]["program"]
    b = _rules("strict")["windows-persistence-commands"]["match"]["program"]
    assert sorted(a) == sorted(b)


def test_net_account_changes_rule_exists_in_both(rules: dict[str, dict[str, Any]]) -> None:
    rule = rules["ask-net-account-changes"]
    assert rule["action"] == "ask"
    assert {"net", "net1"} <= set(rule["match"]["program"])
    assert {"user", "localgroup", "group"} <= set(rule["match"]["subcommand"])


def test_git_discard_rule_covers_restore_as_its_comment_says(
    rules: dict[str, dict[str, Any]],
) -> None:
    subs = rules["ask-git-discard-paths"]["match"]["subcommand"]
    assert {"checkout", "restore"} <= set(subs)


def test_both_policies_still_load_and_carry_the_new_tests() -> None:
    for name in ("default", "strict"):
        text = (POLICIES / f"{name}.yaml").read_text(encoding="utf-8")
        policy = parse_policy_text(text, home="C:/Users/testuser")
        commands = " ".join(str(t.input.get("command", "")) for t in policy.tests)
        for program in ("Stop-Computer", "vssadmin delete", "net user bob /add", "git restore"):
            assert program in commands, (name, program)


@pytest.mark.skipif(sys.platform != "win32", reason="PowerShell parsing needs the Windows helper")
@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize(
    "command",
    [
        "Stop-Computer",
        "Restart-Computer -Force",
        "Clear-EventLog -LogName System",
        "vssadmin delete shadows /all",
        "wevtutil cl Security",
        "net user bob /add",
        "setx API_TOKEN x",
        "Add-LocalGroupMember -Group Administrators -Member bob",
        "git restore src/a.py",
    ],
)
def test_reviewed_commands_ask_through_the_whole_pipeline(name: str, command: str) -> None:
    text = (POLICIES / f"{name}.yaml").read_text(encoding="utf-8")
    policy = parse_policy_text(text, home=policycli._FAKE["windows"]["home"])
    result = policycli._run_one(
        policy,
        "windows",
        "PowerShell",
        {"command": command},
        None,
        None,  # type: ignore[arg-type]
    )
    assert result.verdict.decision in ("ask", "deny"), result.verdict
