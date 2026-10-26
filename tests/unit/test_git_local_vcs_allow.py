"""allow-git-add, allow-git-commit-message and allow-git-stash: what they allow, what they must not.

The default policy allows the three everyday local git commands in their plain forms. Every option
that starts a program, reaches another work tree, stages ignored files or destroys a stash keeps the
call out of the allow rule. Strict has no such rule.
"""

from __future__ import annotations

from functools import cache

import pytest

from boundkeep import policycli
from boundkeep.normalize import programs
from boundkeep.policy import Policy, default_policy_text, parse_policy_text

PLATFORMS = ("windows", "posix")
PLATFORM_IDS = [f"on-{p}" for p in PLATFORMS]  # conftest.py skips ids that are the bare words


@cache
def _policy(platform: str) -> Policy:
    return parse_policy_text(default_policy_text(), home=policycli._FAKE[platform]["home"])


@cache
def _strict(platform: str) -> Policy:
    from pathlib import Path

    text = (Path(__file__).resolve().parents[2] / "policies" / "strict.yaml").read_text(
        encoding="utf-8"
    )
    return parse_policy_text(text, home=policycli._FAKE[platform]["home"])


def _run(platform: str, command: str, policy: Policy | None = None) -> tuple[str, tuple[str, ...]]:
    review = policycli._run_one(
        policy or _policy(platform),
        platform,
        "Bash",
        {"command": command},
        None,
        None,  # type: ignore[arg-type]
    )
    return str(review.verdict.decision), tuple(review.verdict.rule_ids)


ALLOWED = [
    ("git add -A", "allow-git-add"),
    ("git add .", "allow-git-add"),
    ("git add src/app.py tests", "allow-git-add"),
    ("git add -Av", "allow-git-add"),
    ("git add -u", "allow-git-add"),
    ("git add -n .", "allow-git-add"),
    ("git commit -m 'fix typo'", "allow-git-commit-message"),
    ("git commit -am fix", "allow-git-commit-message"),
    ("git commit --message=fix", "allow-git-commit-message"),
    ("git commit --amend --no-edit", "allow-git-commit-message"),
    ("git commit -m x --no-verify", "allow-git-commit-message"),
    ("git stash", "allow-git-stash"),
    ("git stash push -m wip", "allow-git-stash"),
    ("git stash list", "allow-git-stash"),
    ("git stash show -p", "allow-git-stash"),
    ("git stash apply", "allow-git-stash"),
    ("git stash pop", "allow-git-stash"),
    ("git stash -u", "allow-git-stash"),
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("command", "rule"), ALLOWED)
def test_the_plain_forms_are_allowed(platform: str, command: str, rule: str) -> None:
    decision, rules = _run(platform, command)
    assert decision == "allow", (command, decision, rules)
    assert rule in rules


def test_a_line_of_allowed_commands_is_allowed() -> None:
    for platform in PLATFORMS:
        decision, rules = _run(platform, "git add . && git commit -m wip && git stash list")
        assert decision == "allow", (platform, rules)


NOT_ALLOWED = [
    # add
    "git add -f build/x",
    "git add --force build/x",
    "git add --forc build/x",
    "git add --fo build/x",
    "git add -e",
    "git add --edit",
    "git add --pathspec-from-file=list.txt",
    "git add --pathspec-from-fi=list.txt",
    # commit
    "git commit",
    "git commit -e -m x",
    "git commit --edit -m x",
    "git commit -S -m x",
    "git commit --gpg-sign -m x",
    "git commit --gpg -m x",
    'git commit -m "$(date)"',
    "git commit -m $MSG",
    # stash
    "git stash drop",
    "git stash drop stash@{1}",
    "git stash clear",
    "git stash branch topic",
    "git stash create",
    "git stash store abc1234",
    "git stash -a",
    "git stash --all",
    "git stash push --all",
    "git stash -- src/a.py",
    "git stash --pathspec-from-file=list.txt",
    # the global options (another repository, a program from the configuration)
    "git -C ../other add .",
    "git -c core.editor=x commit -m x",
    "git -c core.fsmonitor=x add .",
    "git --git-dir=../x/.git add .",
    "git --work-tree=../x add .",
    "git --paginate stash list",
    "git add --help",
    # wrappers and environment that carries code
    "sudo git add .",
    "env X=1 git add .",
    "GIT_EDITOR=x git commit -m x",
    "GIT_SSH_COMMAND=x git add .",
    "time git add .",
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("command", NOT_ALLOWED)
def test_the_risky_forms_are_never_allowed(platform: str, command: str) -> None:
    decision, rules = _run(platform, command)
    assert decision != "allow", (command, rules)


PROTECTED = [
    ("git add .env", "deny"),
    ("git add -f .env", "deny"),
    ("git add .git/config", "deny"),
    ("git add ~/.ssh/id_rsa", "deny"),
    ("git commit -m x .env", "deny"),
    ("git stash push .env", "deny"),
    ("git stash push -- .env", "deny"),
    ("git add ../other/x", "ask"),
    ("git commit -F ../msg.txt -m x", "ask"),
    ("git commit -m x && git push", "ask"),
    ("git add . && git push --force", "ask"),
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("command", "decision"), PROTECTED)
def test_protected_paths_and_the_rest_of_the_line_still_decide(
    platform: str, command: str, decision: str
) -> None:
    got, rules = _run(platform, command)
    assert got == decision, (command, got, rules)


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_strict_has_no_allow_rule_for_them(platform: str) -> None:
    for command, _rule in ALLOWED:
        decision, _rules = _run(platform, command, _strict(platform))
        assert decision != "allow", command


def test_the_stash_marker_is_set_for_every_subcommand_that_is_not_plain() -> None:
    def flags(command: str) -> tuple[str, ...]:
        review = policycli._run_one(
            _policy("posix"), "posix", "Bash", {"command": command}, None, None
        )
        return review.actions[0].flags

    for plain in (
        "git stash",
        "git stash push",
        "git stash list",
        "git stash show",
        "git stash apply",
        "git stash pop",
    ):
        assert programs.GIT_STASH_OTHER_FLAG not in flags(plain), plain
    for other in (
        "git stash drop",
        "git stash clear",
        "git stash branch x",
        "git stash create",
        "git stash whatever",
    ):
        assert programs.GIT_STASH_OTHER_FLAG in flags(other), other


def test_the_stash_rule_lists_the_marker_and_the_flag_lists_match_the_guard() -> None:
    from pathlib import Path

    import yaml

    data = yaml.safe_load(
        (Path(__file__).resolve().parents[2] / "policies" / "default.yaml").read_text(
            encoding="utf-8"
        )
    )
    rules = {rule["id"]: rule for rule in data["rules"]}
    assert programs.GIT_STASH_OTHER_FLAG in rules["allow-git-stash"]["match"]["flags_none"]
    assert set(rules["allow-git-commit-message"]["match"]["flags_any"]) == {
        "-m",
        "--message",
        "--no-edit",
    }
    for rule_id in ("allow-git-add", "allow-git-commit-message", "allow-git-stash"):
        none = set(rules[rule_id]["match"]["flags_none"])
        assert {
            "-c",
            "-C",
            "--config-env",
            "--git-dir",
            "--work-tree",
            "--exec-path",
            "--paginate",
        } <= none
        assert rules[rule_id]["match"]["program"] == ["git"]
        assert "path_glob" not in rules[rule_id]["match"]
