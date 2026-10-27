"""allow-git-add, allow-git-commit-message and allow-git-stash: what they allow, what they must not.

The default policy allows the three everyday local git commands in their plain forms. Every option
that starts a program, reaches another work tree, stages ignored files or destroys a stash keeps the
call out of the allow rule. Strict has no such rule.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path

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
    ("git stash show --stat", "allow-git-stash"),
    ("git stash list --oneline", "allow-git-stash"),
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
    "git add --pathspec-file-nul",
    "git add -p",
    "git add --inter",
    "git add --intera",
    "git add --interac",
    "git add --interact",
    "git add --interacti",
    "git commit -m x --inter",
    "git commit -m x --interacti",
    # a `--` is honoured by git's stash list parser: the options after it still take effect (R4-1)
    "git stash list -- --output=zz.txt",
    "git stash list -- --format=%b --output=conftest.py",
    "git stash list -- --output=.claude/settings.json",
    "git stash list -- -p",
    "git stash list -- --ext-diff",
    "git stash show -- --output=zz.txt",
    "git stash show --stat -- --output=zz.txt",
    "git add -i",
    "git add --patch",
    "git add --interactive",
    "git -p add .",
    # commit: the file named by --pathspec-from-file is read by git and echoed in its error (R3-1)
    "git commit -m x --allow-empty --pathspec-from-file=notes.txt",
    "git commit -m x --allow-empty --pathspec-fr=notes.txt",
    "git commit -m x --allow-empty --pathspec-from-fil=notes.txt",
    "git commit -m x --allow-empty --pathspec-from-file notes.txt",
    "git commit -m x --allow-empty --pathspec-file-nul",
    "git commit -m x -p",
    "git commit -m x --patch",
    "git commit -m x --interactive",
    # stash list / show carry the option set of git log / git diff: an allowlist (R3-2, R3-4)
    "git stash list --format=%b --output=conftest.py",
    "git stash list --format=%b --output=Makefile",
    "git stash list --format=%b --outp=package.json",
    "git stash list --format=%b --o=pytest.ini",
    "git stash show -p --output=conftest.py",
    "git stash show -p",
    "git stash list -p",
    "git stash list --patch",
    "git stash list --stat -p",
    "git stash list --cc",
    "git stash show --ext-diff",
    "git stash show --textconv -p",
    "git stash show -O orderfile",
    "git stash list --format=%H",
    "git stash show --stat --output=x.txt",
    "git stash push -p",
    "git stash push --patch",
    "git commit --pathspec-from-file=notes.txt -m x",
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
    # R3-1: the file named by --pathspec-from-file is a path that is read: the secret rules judge it
    ("git commit -m x --allow-empty --pathspec-from-file=id_rsa", "deny"),
    ("git commit -m x --allow-empty --pathspec-from-file=credentials.json", "deny"),
    ("git commit -m x --allow-empty --pathspec-from-file=server.key", "deny"),
    ("git commit -m x --allow-empty --pathspec-from-file=.env", "deny"),
    ("git commit -m x --allow-empty --pathspec-fr=id_rsa", "deny"),
    ("git commit -m x --allow-empty --pathspec-from-file=../x", "ask"),
    ("git add --pathspec-from-file=id_rsa", "deny"),
    ("git stash push --pathspec-from-file=id_rsa", "deny"),
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


# ------------------------------------------------ the repository root above the project (R3-5)


def _disk_review(tmp_path: Path, command: str, *, repo_at_project: bool) -> tuple[str, list[str]]:
    import os

    from boundkeep.daemon import pipeline

    top = tmp_path / "top"
    project = top / "proj"
    project.mkdir(parents=True)
    ((project if repo_at_project else top) / ".git").mkdir()
    home = str(tmp_path / "home")
    os.makedirs(home, exist_ok=True)
    policy = parse_policy_text(default_policy_text(), home=home)
    env = {k: v for k, v in os.environ.items() if k.upper() in ("SYSTEMROOT", "PATH", "TEMP")}
    env["USERPROFILE"] = env["HOME"] = home
    runtime, _problem = pipeline.runtime_policy_checked(policy, env, home)
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(project),
        "project_dir": str(project),
        "session_id": "s",
    }
    result = pipeline.review(
        payload, runtime, platform=pipeline.local_platform(), env=env, home=home
    )
    reasons = [r for a in result.verdict.actions for r in a.gray_reasons]
    return str(result.verdict.decision), reasons


WHOLE_TREE_COMMANDS = ["git add -A", "git add .", "git commit -a -m x", "git stash", "git stash -u"]


@pytest.mark.parametrize("command", WHOLE_TREE_COMMANDS)
def test_a_repository_above_the_project_makes_the_whole_tree_commands_ask(
    tmp_path: Path, command: str
) -> None:
    decision, reasons = _disk_review(tmp_path, command, repo_at_project=False)
    assert decision != "allow", (command, reasons)
    assert "git-root-above-project" in reasons


@pytest.mark.parametrize("command", WHOLE_TREE_COMMANDS)
def test_a_repository_at_the_project_root_keeps_them_allowed(tmp_path: Path, command: str) -> None:
    decision, reasons = _disk_review(tmp_path, command, repo_at_project=True)
    assert decision == "allow", (command, reasons)
    assert "git-root-above-project" not in reasons


def test_a_directory_that_is_not_a_repository_is_left_alone(tmp_path: Path) -> None:
    import os

    from boundkeep.daemon import pipeline

    project = tmp_path / "proj"
    project.mkdir()
    home = str(tmp_path / "home")
    os.makedirs(home, exist_ok=True)
    policy = parse_policy_text(default_policy_text(), home=home)
    env = {k: v for k, v in os.environ.items() if k.upper() in ("SYSTEMROOT", "PATH", "TEMP")}
    env["USERPROFILE"] = env["HOME"] = home
    runtime, _problem = pipeline.runtime_policy_checked(policy, env, home)
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "git add -A"},
        "cwd": str(project),
        "project_dir": str(project),
    }
    result = pipeline.review(
        payload, runtime, platform=pipeline.local_platform(), env=env, home=home
    )
    assert str(result.verdict.decision) == "allow"


# ----------------------------------- git add and a protected file that is not ignored (R3-3)


def _tree_review(
    tmp_path: Path, files: list[str], command: str, *, cwd: str = ""
) -> tuple[str, list[str]]:
    import os

    from boundkeep.daemon import pipeline

    project = tmp_path / "proj"
    (project / ".git").mkdir(parents=True, exist_ok=True)
    for name in files:
        target = project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x\n", encoding="utf-8")
    home = str(tmp_path / "home")
    os.makedirs(home, exist_ok=True)
    policy = parse_policy_text(default_policy_text(), home=home)
    env = {k: v for k, v in os.environ.items() if k.upper() in ("SYSTEMROOT", "PATH", "TEMP")}
    env["USERPROFILE"] = env["HOME"] = home
    runtime, _problem = pipeline.runtime_policy_checked(policy, env, home)
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(project / cwd) if cwd else str(project),
        "project_dir": str(project),
        "session_id": "s",
    }
    result = pipeline.review(
        payload, runtime, platform=pipeline.local_platform(), env=env, home=home
    )
    reasons = [r for a in result.verdict.actions for r in a.gray_reasons]
    return str(result.verdict.decision), reasons


@pytest.mark.parametrize("command", ["git add -A", "git add .", "git add --all", "git add src"])
def test_git_add_of_a_tree_with_an_unignored_secret_asks(tmp_path: Path, command: str) -> None:
    decision, reasons = _tree_review(tmp_path, ["src/a.py", "src/.env", "id_rsa"], command)
    assert decision != "allow", (command, reasons)
    assert "git-add-may-stage-protected" in reasons


def test_git_add_of_a_tree_without_protected_names_is_allowed(tmp_path: Path) -> None:
    for command in ("git add -A", "git add .", "git add src"):
        decision, reasons = _tree_review(tmp_path, ["src/a.py", "README.md"], command)
        assert decision == "allow", (command, reasons)


def test_a_virtual_environment_and_dependencies_do_not_count(tmp_path: Path) -> None:
    files = [
        "src/a.py",
        ".venv/lib/site-packages/certifi/cacert.pem",
        "node_modules/pkg/credentials.json",
    ]
    decision, reasons = _tree_review(tmp_path, files, "git add -A")
    assert decision == "allow", reasons


def test_a_named_file_or_another_directory_is_not_blocked_by_a_secret_elsewhere(
    tmp_path: Path,
) -> None:
    files = ["src/a.py", "other/.env", "README.md"]
    for command in ("git add src/a.py", "git add README.md", "git add src", "git add -u"):
        decision, reasons = _tree_review(tmp_path, files, command)
        assert decision == "allow", (command, reasons)
    decision, reasons = _tree_review(tmp_path, files, "git add other")
    assert decision != "allow"
    assert "git-add-may-stage-protected" in reasons


@pytest.mark.parametrize(
    "command",
    [
        "git add -A",
        "git add --all",
        "git add --al",
        "git add :/",
        "git add ':(top)'",
        "git add ':/src'",
        # R6-1: the same reach by other spellings
        "git add --no-ignore-removal",
        "git add --no-i",
        "git add --no-ignore",
        "git add ':!x'",
        "git add ':^x'",
        "git add ':(exclude)x'",
        "git add ':!/x'",
        "git add ':(exclude,top)x'",
        "git add -- ':/'",
        "git add -Av",
        "git add -vA",
    ],
)
def test_the_whole_repository_forms_are_looked_at_from_a_sub_directory(
    tmp_path: Path, command: str
) -> None:
    # R5-1: from src/ these still stage the whole repository, so the project root is scanned too
    files = ["src/a.py", ".env"]
    decision, reasons = _tree_review(tmp_path, files, command, cwd="src")
    assert decision != "allow", (command, reasons)
    assert "git-add-may-stage-protected" in reasons


def test_a_plain_dot_from_a_sub_directory_only_looks_at_that_directory(tmp_path: Path) -> None:
    decision, reasons = _tree_review(tmp_path, ["src/a.py", ".env"], "git add .", cwd="src")
    assert decision == "allow", reasons
