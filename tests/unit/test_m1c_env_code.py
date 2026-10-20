"""M1c: environment prefixes that redirect git or ripgrep keep a command out of the allow rules."""

from __future__ import annotations

import pytest

from boundkeep import policycli
from boundkeep.normalize.programs import is_code_env
from boundkeep.policy import default_policy_text, parse_policy_text

NAMES = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_EXEC_PATH",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_TEMPLATE_DIR",
    "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR",
    "GIT_CONFIG",
    "XDG_CONFIG_HOME",
    "RIPGREP_CONFIG_PATH",
    "LESS",
    "LESSKEY",
    "MANPAGER",
    "git_dir",  # environment names are case-insensitive on Windows
]
COMMANDS = ["git status", "git diff", "git log", "rg foo src"]


@pytest.mark.parametrize("name", NAMES)
def test_these_names_are_code_environment(name: str) -> None:
    assert is_code_env(name)


@pytest.mark.parametrize("platform", ["posix", "windows"])
@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("command", COMMANDS)
def test_a_prefixed_command_is_never_allow(platform: str, name: str, command: str) -> None:
    policy = parse_policy_text(default_policy_text(), home=policycli._FAKE[platform]["home"])
    result = policycli._run_one(
        policy, platform, "Bash", {"command": f"{name}=/x {command}"}, None, None
    )
    assert result.verdict.decision != "allow", (name, command)
    reasons = {g for action in result.actions for g in action.gray_reasons}
    assert any(r.startswith("env-code-injection") for r in reasons), reasons


@pytest.mark.parametrize("platform", ["posix", "windows"])
@pytest.mark.parametrize("command", COMMANDS)
def test_the_same_commands_without_a_prefix_stay_allow(platform: str, command: str) -> None:
    policy = parse_policy_text(default_policy_text(), home=policycli._FAKE[platform]["home"])
    result = policycli._run_one(policy, platform, "Bash", {"command": command}, None, None)
    assert result.verdict.decision == "allow", (command, result.verdict.reasons)
