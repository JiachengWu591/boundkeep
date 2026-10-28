"""allow-version-probe, allow-git-ls-files and `which`: what they allow, what they must not.

These are information commands: they print a version, a program's location or file names, and read
no file content. Anything that adds an argument, an option outside the normalizer's allowlist, a
redirect, a wrapper or an expanding word keeps the call out of the allow rules. Strict has none.
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
ROOT = Path(__file__).resolve().parents[2]


@cache
def _policy(platform: str) -> Policy:
    return parse_policy_text(default_policy_text(), home=policycli._FAKE[platform]["home"])


@cache
def _strict(platform: str) -> Policy:
    text = (ROOT / "policies" / "strict.yaml").read_text(encoding="utf-8")
    return parse_policy_text(text, home=policycli._FAKE[platform]["home"])


def _run(platform: str, command: str, policy: Policy | None = None) -> tuple[str, tuple[str, ...]]:
    review = policycli._run_one(
        policy or _policy(platform),
        platform,  # type: ignore[arg-type]
        "Bash",
        {"command": command},
        None,
        None,
    )
    return str(review.verdict.decision), tuple(review.verdict.rule_ids)


PROGRAMS = sorted(programs.VERSION_PROBE_PROGRAMS)


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("program", PROGRAMS)
def test_a_version_probe_is_allowed(platform: str, program: str) -> None:
    decision, rules = _run(platform, f"{program} --version")
    assert decision == "allow", (program, decision, rules)
    assert "allow-version-probe" in rules or program == "git"


NOT_PROBES = [
    "python3 --version -c 'print(1)'",
    "python3 --version script.py",
    "python3 -c 'print(1)' --version",
    "node --version x.js",
    "node -v",
    "node --version --eval 1",
    "pip --version install x",
    "npm --version install",
    "cargo --version build",
    "uv --version run x",
    "docker --version run x",
    "python3 --version $X",
    "python3 --version ~/x",
    "python3 --version > v.txt",
    "python3 --version | tee v.txt",
    "sudo python3 --version",
    "env X=1 python3 --version",
    "time python3 --version",
    "PYTHONSTARTUP=x python3 --version",
    "LD_PRELOAD=x python3 --version",
    "./python3 --version",
    "/tmp/python3 --version",
    "python3 --versio",
    "python3 -V",
    "python3 --version=1",
    "$PROG --version",
    "ruby --version",
    "python3 --help",
    "PYENV_VERSION=3.0 python --version",  # X1 review R7-1: any env prefix, not only code-carrying
    "MISE_TRUSTED_CONFIG_PATHS=/ python3 --version",
    "RUSTUP_TOOLCHAIN=x cargo --version",
    "GIT_TRACE=conftest.py git --version",
    "GIT_TRACE2_EVENT=Makefile git --version",
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("command", NOT_PROBES)
def test_anything_but_the_plain_probe_is_not_allowed(platform: str, command: str) -> None:
    decision, rules = _run(platform, command)
    assert decision != "allow", (command, rules)


def test_the_extra_argument_marker_is_set_only_when_something_follows() -> None:
    def flags(command: str) -> tuple[str, ...]:
        review = policycli._run_one(
            _policy("posix"), "posix", "Bash", {"command": command}, None, None
        )
        return review.actions[0].flags

    assert programs.VERSION_EXTRA_FLAG not in flags("python3 --version")
    assert programs.VERSION_EXTRA_FLAG in flags("python3 --version -c x")
    assert programs.VERSION_EXTRA_FLAG in flags("python3 --version x.py")
    assert programs.VERSION_EXTRA_FLAG in flags("python3 --version $X")


LS_ALLOWED = [
    "git ls-files",
    "git ls-files -o",
    "git ls-files --others",
    "git ls-files --others --exclude-standard",
    "git ls-files -m",
    "git ls-files -d",
    "git ls-files -z",
    "git ls-files --cached",
    "git ls-files | head -n 20",
    "git ls-files src",
    "git ls-files '*.py'",
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("command", LS_ALLOWED)
def test_plain_ls_files_is_allowed(platform: str, command: str) -> None:
    decision, rules = _run(platform, command)
    if "'*.py'" in command:
        assert decision != "allow" or "allow-git-ls-files" in rules  # a quoted glob: not expanded
        return
    assert decision == "allow", (command, decision, rules)


LS_NOT_ALLOWED = [
    "git ls-files --exclude-from=ignore.txt",
    "git ls-files --exclude-from ignore.txt",
    "git ls-files --exclude-f=ignore.txt",
    "git ls-files --ex=ignore.txt",
    "git ls-files -X ignore.txt",
    "git ls-files --exclude-per-directory=.gitignore",
    "git ls-files --format=%(path)",
    "git ls-files --format=%(objectname)",
    "git ls-files --debug",
    "git ls-files -s",
    "git ls-files --stage",
    "git ls-files -c",
    "git ls-files -co",
    "git ls-files --oth",
    "git ls-files --with-tree=HEAD~5",
    "git ls-files --error-unmatch x",
    "git ls-files -- src",
    "git ls-files -- --exclude-from=x",
    "git ls-files ../other",
    "git -C ../other ls-files",
    "git -c core.pager=x ls-files",
    "git --git-dir=../x/.git ls-files",
    "git --work-tree=../x ls-files",
    "git --paginate ls-files",
    "git ls-files --help",
    "GIT_DIR=../x git ls-files",
    "sudo git ls-files",
    "git ls-files > out.txt",
    "GIT_TRACE=conftest.py git ls-files",  # X1 review R7-1
    "GIT_TRACE2_EVENT=Makefile git ls-files",
    "FOO=1 git ls-files",
    "git ls-files :/",  # R7-4: pathspec magic
    "git ls-files ':(top)'",
    "git ls-files ':!src'",
    "git ls-files ':(exclude)src'",
    "git ls-files -p",  # R7-6
    "git ls-files -P",
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("command", LS_NOT_ALLOWED)
def test_ls_files_with_other_options_is_not_allowed(platform: str, command: str) -> None:
    decision, rules = _run(platform, command)
    assert decision != "allow", (command, rules)


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_which_is_allowed_only_for_a_plain_name(platform: str) -> None:
    assert _run(platform, "which python3")[0] == "allow"
    assert _run(platform, "which -a git")[0] == "allow"
    for command in (
        "which $TOOL",
        "which $(echo x)",
        "which python3 > out.txt",
        "sudo which x",
        "which -i x < ../other/aliases",  # X1 review R7-3: stdin from outside the project
    ):
        assert _run(platform, command)[0] != "allow", command


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_strict_allows_none_of_them(platform: str) -> None:
    for command in ("which python3", "python3 --version", "git --version", "git ls-files"):
        assert _run(platform, command, _strict(platform))[0] != "allow", command


def test_the_ls_files_marker_and_the_rule_lists_agree() -> None:
    import yaml

    data = yaml.safe_load((ROOT / "policies" / "default.yaml").read_text(encoding="utf-8"))
    rules = {rule["id"]: rule for rule in data["rules"]}
    assert programs.GIT_OTHER_OPTION_FLAG in rules["allow-git-ls-files"]["match"]["flags_none"]
    assert programs.VERSION_EXTRA_FLAG in rules["allow-version-probe"]["match"]["flags_none"]
    assert set(rules["allow-version-probe"]["match"]["program"]) == programs.VERSION_PROBE_PROGRAMS
    assert rules["allow-version-probe"]["match"]["flags_any"] == ["--version"]
    guard = rules["ask-git-read-outside-project"]["match"]["subcommand"]
    assert "ls-files" in guard


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    "file_name",
    sorted(
        TOOLCHAIN_SELECTOR_FILES := [
            "mise.toml",
            ".mise.toml",
            "mise.local.toml",
            ".mise.local.toml",
            ".mise/config.toml",
            ".tool-versions",
            ".python-version",
            ".node-version",
            ".nvmrc",
            ".ruby-version",
            ".sdkmanrc",
            "global.json",
            "uv.toml",
            "sub/dir/.python-version",
            # X1 review R8-1: the other places mise reads, and the volta/pyenv/rtx names
            ".config/mise/config.toml",
            ".config/mise/conf.d/a.toml",
            "mise/config.toml",
            "mise/config.local.toml",
            "mise/conf.d/a.toml",
            ".mise/config.local.toml",
            ".mise/conf.d/a.toml",
            "mise.dev.toml",
            ".mise.dev.toml",
            ".rtx.toml",
            "rtx.toml",
            ".python-versions",
            ".volta/hooks.json",
        ]
    ),
)
def test_writing_a_file_a_version_manager_shim_reads_asks_in_default_and_denies_in_strict(
    platform: str, file_name: str
) -> None:
    for tool_input in ({"file_path": file_name, "content": "x"},):
        review = policycli._run_one(_policy(platform), platform, "Write", tool_input, None, None)  # type: ignore[arg-type]
        assert str(review.verdict.decision) == "ask", (file_name, review.verdict)
        assert "ask-toolchain-selector-write" in review.verdict.rule_ids
        strict = policycli._run_one(_strict(platform), platform, "Write", tool_input, None, None)  # type: ignore[arg-type]
        assert str(strict.verdict.decision) == "deny", (file_name, strict.verdict)
        assert "deny-toolchain-selector-write" in strict.verdict.rule_ids


def test_the_selector_rule_has_the_same_globs_in_both_policies_and_fits_the_schema() -> None:
    import yaml

    def glob_list(name: str, rule_id: str) -> list[str]:
        data = yaml.safe_load((ROOT / "policies" / f"{name}.yaml").read_text(encoding="utf-8"))
        return next(r for r in data["rules"] if r["id"] == rule_id)["match"]["path_glob"]

    default = glob_list("default", "ask-toolchain-selector-write")
    assert default == glob_list("strict", "deny-toolchain-selector-write")
    assert len(default) <= 64
    # the autorun lists did not grow past the schema limit either
    assert len(glob_list("default", "ask-project-autorun-files")) <= 64
