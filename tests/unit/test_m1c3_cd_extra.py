"""M1c-3: a `cd` with more than one argument is gray (zsh's `cd old new` rewrites the path)."""

from __future__ import annotations

import pytest

from boundkeep import policycli
from boundkeep.policy import default_policy_text, parse_policy_text

REASON = "cd-extra-arguments"


def _run(platform: str, command: str) -> tuple[str, set[str]]:
    policy = parse_policy_text(default_policy_text(), home=policycli._FAKE[platform]["home"])
    result = policycli._run_one(policy, platform, "Bash", {"command": command}, None, None)
    return result.verdict.decision, {g for a in result.actions for g in a.gray_reasons}


@pytest.mark.parametrize("platform", ["posix", "windows"])
@pytest.mark.parametrize(
    "command",
    [
        "cd src x && git status",
        "cd src x; git status",
        "cd old new && pwd",
        "cd -P src x && git status",
        "cd -- src x && git status",
        "pushd src x && git status",
        "cd src x",
        "cd . x && git status",
    ],
)
def test_a_cd_with_extra_arguments_is_gray(platform: str, command: str) -> None:
    decision, reasons = _run(platform, command)
    assert decision != "allow", command
    assert REASON in reasons, (command, reasons)


@pytest.mark.parametrize("platform", ["posix", "windows"])
@pytest.mark.parametrize(
    "command",
    [
        "cd src && git status",
        "cd . && git status",
        "cd -P src && git status",
        "cd -- src && git status",
        "pushd src && git status",
    ],
)
def test_a_cd_with_one_argument_is_unchanged(platform: str, command: str) -> None:
    decision, reasons = _run(platform, command)
    assert decision == "allow", (command, reasons)
    assert REASON not in reasons
