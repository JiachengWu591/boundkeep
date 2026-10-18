"""X1 review round 2, policy side: M-11 (credential carriers), M-5 (own CLI), M-4 (YAML part).

The shipped policies are checked three ways: rule-level facts read from the YAML (so a dropped glob
fails loudly), actions built by hand for the forms the normalizer cannot produce yet (a
``subcommand`` for boundkeep), and the real pipeline on the fake machines.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from boundkeep import policycli
from boundkeep.normalize.model import Action
from boundkeep.policy import Policy, evaluate, parse_policy_text

POLICIES = Path(__file__).resolve().parents[2] / "policies"
NAMES = ["default", "strict"]


def _data(name: str) -> dict[str, Any]:
    return yaml.safe_load((POLICIES / f"{name}.yaml").read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _rules(name: str) -> dict[str, dict[str, Any]]:
    return {rule["id"]: rule for rule in _data(name)["rules"]}


def _globs(name: str, rule_id: str) -> set[str]:
    return set(_rules(name)[rule_id]["match"]["path_glob"])


def _policy(name: str, platform: str = "posix") -> Policy:
    text = (POLICIES / f"{name}.yaml").read_text(encoding="utf-8")
    return parse_policy_text(text, home=policycli._FAKE[platform]["home"])


def _decide(name: str, tool: str, tool_input: dict[str, Any], platform: str = "posix") -> str:
    result = policycli._run_one(_policy(name, platform), platform, tool, tool_input, None, None)  # type: ignore[arg-type]
    return result.verdict.decision


# ---------------------------------------------------------------------------- M-11 rule facts

SECRET_NAMES = [
    "**/*.env",
    "**/env",
    "**/secrets.yml",
    "**/secrets.yaml",
    "**/secrets.json",
    "**/secrets.toml",
    "**/key.txt",
    "**/.htpasswd",
    "**/kubeconfig",
    "**/local.settings.json",
    "**/*.kdbx",
]


@pytest.mark.parametrize("name", NAMES)
def test_no_secret_read_lists_the_project_internal_secret_names(name: str) -> None:
    assert set(SECRET_NAMES) <= _globs(name, "no-secret-read")


@pytest.mark.parametrize("name", NAMES)
def test_credential_carriers_are_in_the_deny_rules(name: str) -> None:
    assert {"**/.git/credentials", "**/id_rsa*"} <= _globs(name, "no-credential-store-read")
    assert {"**/.claude/settings*.json", "**/.mcp.json"} <= _globs(name, "no-agent-state-read")


@pytest.mark.parametrize("name", NAMES)
def test_harmless_names_are_not_listed(name: str) -> None:
    every = set()
    for rule_id in ("no-secret-read", "no-credential-store-read", "no-agent-state-read"):
        every |= _globs(name, rule_id)
    for harmless in ("docker-compose", "README", "env.py", "kubeconfig.go", "Dockerfile"):
        assert not any(harmless.lower() in g.lower() for g in every), harmless


def test_strict_read_deny_lists_contain_the_default_ones() -> None:
    for rule_id in (
        "no-secret-read",
        "no-credential-store-read",
        "no-agent-state-read",
        "no-history-read",
        "protect-guard-config",
    ):
        assert _globs("default", rule_id) <= _globs("strict", rule_id), rule_id


def test_strict_exec_config_contains_the_default_ask_list() -> None:
    assert _globs("default", "ask-agent-exec-config") <= _globs("strict", "deny-agent-exec-config")


# ---------------------------------------------------------------------------- M-5 rule facts


@pytest.mark.parametrize("name", NAMES)
def test_boundkeep_cli_rules_exist_with_the_right_actions(name: str) -> None:
    rules = _rules(name)
    state = rules["deny-boundkeep-state-commands"]
    assert state["action"] == "deny"
    assert {"boundkeep", "boundkeep-hook"} <= set(state["match"]["program"])
    assert {"mode", "uninstall", "init", "serve"} <= set(state["match"]["subcommand"])
    flags = rules["deny-boundkeep-state-flags"]
    assert flags["action"] == "deny"
    assert {"--reset-policy", "--purge", "--python"} <= set(flags["match"]["flags_any"])
    assert rules["deny-boundkeep-hook-run"]["action"] == "deny"
    # Reading commands stay ask (never deny): doctor, test, explain, log --tail.
    assert rules["ask-boundkeep-cli"]["action"] == "ask"
    for rule_id in ("deny-boundkeep-state-commands", "deny-boundkeep-state-flags"):
        assert "log" not in (rules[rule_id]["match"].get("subcommand") or [])


@pytest.mark.parametrize("name", NAMES)
def test_every_new_command_rule_covers_both_shell_tools(name: str) -> None:
    rules = _rules(name)
    ids = [
        "deny-boundkeep-state-commands",
        "deny-boundkeep-state-flags",
        "deny-boundkeep-hook-run",
        "ask-boundkeep-cli",
        "ask-claude-cli",
        "ask-kill-processes",
    ]
    ids.append("ask-package-uninstall" if name == "default" else "deny-package-uninstall")
    for rule_id in ids:
        assert set(rules[rule_id]["tool"]) == {"Bash", "PowerShell"}, rule_id


def test_kill_and_claude_programs_are_listed() -> None:
    for name in NAMES:
        rules = _rules(name)
        assert {"taskkill", "pkill", "killall", "kill", "Stop-Process"} <= set(
            rules["ask-kill-processes"]["match"]["program"]
        )
        assert rules["ask-claude-cli"]["match"]["program"] == ["claude"]


def test_claude_dangerous_flags_ask_in_default_and_deny_in_strict() -> None:
    assert "deny-claude-cli-flags" not in _rules("default")
    strict = _rules("strict")["deny-claude-cli-flags"]
    assert strict["action"] == "deny"
    assert {"--settings", "--permission-mode", "--dangerously-skip-permissions"} <= set(
        strict["match"]["flags_any"]
    )


# ---------------------------------------------------------------------------- M-5 by hand
# The normalizer reports no subcommand for programs it has no table for (boundkeep), so the
# subcommand rule is exercised with hand-built actions: it fires as soon as the normalizer does.


def _bk(name: str, program: str, sub: str | None, flags: tuple[str, ...] = ()) -> str:
    action = Action(
        tool="Bash",
        platform="posix",
        program=program,
        subcommand=sub,
        flags=flags,
    )
    return evaluate(_policy(name), [action], platform="posix").decision


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("sub", ["mode", "uninstall", "init", "serve"])
@pytest.mark.parametrize("program", ["boundkeep", "boundkeep-hook"])
def test_state_changing_subcommands_are_denied(name: str, sub: str, program: str) -> None:
    assert _bk(name, program, sub) == "deny"


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("sub", ["doctor", "test", "explain", "log", "llm", None])
def test_reading_subcommands_are_asked_not_denied(name: str, sub: str | None) -> None:
    assert _bk(name, "boundkeep", sub) == "ask"


@pytest.mark.parametrize("name", NAMES)
def test_log_with_purge_is_denied_but_log_tail_asks(name: str) -> None:
    assert _bk(name, "boundkeep", "log", ("--purge",)) == "deny"
    assert _bk(name, "boundkeep", "log", ("--tail",)) == "ask"


@pytest.mark.parametrize("name", NAMES)
def test_deny_wins_over_ask_in_the_reason(name: str) -> None:
    action = Action(tool="Bash", platform="posix", program="boundkeep", subcommand="mode")
    verdict = evaluate(_policy(name), [action], platform="posix")
    assert verdict.decision == "deny"
    assert "deny-boundkeep-state-commands" in verdict.rule_ids
    assert "ask-boundkeep-cli" not in verdict.rule_ids


# ---------------------------------------------------------------------------- end to end


@pytest.mark.parametrize(
    ("tool", "tool_input", "default", "strict"),
    [
        ("Bash", {"command": "boundkeep init --reset-policy"}, "deny", "deny"),
        ("Bash", {"command": "boundkeep log --purge"}, "deny", "deny"),
        ("Bash", {"command": "boundkeep init --python /tmp/x"}, "deny", "deny"),
        ("Bash", {"command": "boundkeep-hook pre"}, "deny", "deny"),
        ("Bash", {"command": "boundkeep doctor"}, "ask", "ask"),
        ("Bash", {"command": "boundkeep log --tail 20"}, "ask", "ask"),
        ("Bash", {"command": "claude config set -g disableAllHooks true"}, "ask", "ask"),
        ("Bash", {"command": "claude --dangerously-skip-permissions"}, "ask", "deny"),
        ("Bash", {"command": "claude --settings x.json"}, "ask", "deny"),
        ("Bash", {"command": "claude --permission-mode bypassPermissions"}, "ask", "deny"),
        ("Bash", {"command": "taskkill /F /IM python.exe"}, "ask", "ask"),
        ("Bash", {"command": "pkill -f boundkeep"}, "ask", "ask"),
        ("Bash", {"command": "pip uninstall -y boundkeep"}, "ask", "deny"),
        ("Bash", {"command": "python -m pip uninstall boundkeep"}, "ask", "deny"),
        ("Bash", {"command": "pipx uninstall boundkeep"}, "ask", "deny"),
        ("Bash", {"command": "pip list"}, "gray", "gray"),
        ("Read", {"file_path": ".claude/settings.local.json"}, "deny", "deny"),
        ("Read", {"file_path": ".mcp.json"}, "deny", "deny"),
        ("Read", {"file_path": "prod.env"}, "deny", "deny"),
        ("Read", {"file_path": "docker-compose.yml"}, "allow", "allow"),
        ("Read", {"file_path": "README.md"}, "allow", "allow"),
        ("Bash", {"command": "rm -r .claude"}, "deny", "deny"),
        ("Bash", {"command": "mv .boundkeep x"}, "deny", "deny"),
        ("Write", {"file_path": "managed-settings.json", "content": "x"}, "deny", "deny"),
        ("Write", {"file_path": ".claude/rules/r.md", "content": "x"}, "ask", "deny"),
        ("Write", {"file_path": ".claude/output-styles/s.md", "content": "x"}, "ask", "deny"),
        ("Write", {"file_path": ".claude/statusline.sh", "content": "x"}, "ask", "deny"),
        ("Write", {"file_path": ".claude/plugins/p/x.js", "content": "x"}, "ask", "deny"),
        ("Read", {"file_path": "~/.boundkeep/policy.yaml"}, "ask", "ask"),
    ],
)
@pytest.mark.parametrize("platform", ["posix", "windows"])
def test_end_to_end_verdicts(
    tool: str, tool_input: dict[str, Any], default: str, strict: str, platform: str
) -> None:
    assert _decide("default", tool, tool_input, platform) == default
    assert _decide("strict", tool, tool_input, platform) == strict
