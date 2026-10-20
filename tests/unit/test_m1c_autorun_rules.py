"""M1c: the `*-project-autorun-files` rule in both shipped policies.

Files that make code run later (build, test, CI, IDE, container and pre-commit configuration,
language start-up hooks) must ask in the default policy and be denied in strict whenever they are
WRITTEN, by any tool, before any project-internal write allow rule exists. The rule facts are read
from the YAML (a dropped glob fails loudly); the decisions go through the real pipeline on the fake
machines. The end-to-end corpus is tests/corpus/pipeline_m1c_autorun.yaml.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from boundkeep import policycli
from boundkeep.policy import Policy, parse_policy_text

POLICIES = Path(__file__).resolve().parents[2] / "policies"
RULE_IDS = {"default": "ask-project-autorun-files", "strict": "deny-project-autorun-files"}
ACTIONS = {"default": "ask", "strict": "deny"}
# What an ordinary project write / read of a non-autorun file decides: the default policy has the
# M1c allow rules for them (tests/unit/test_m1c_allow_rules.py), strict has none: no rule decides.
ORDINARY_WRITE = {"default": "allow", "strict": "gray"}

PROJECT_GLOBS = {
    "**/package.json",
    "**/Makefile",
    "**/makefile",
    "**/GNUmakefile",
    "**/pyproject.toml",
    "**/setup.py",
    "**/setup.cfg",
    "**/tox.ini",
    "**/noxfile.py",
    "**/conftest.py",
    "**/sitecustomize.py",
    "**/usercustomize.py",
    "**/*.pth",
    "**/.pre-commit-config.yaml",
    "**/.gitattributes",
    "**/.gitmodules",
    "**/.envrc",
    "**/.husky/**",
    "**/.github/workflows/**",
    "**/.github/actions/**",
    "**/.gitlab-ci.yml",
    "**/.circleci/**",
    "**/Jenkinsfile",
    "**/azure-pipelines.yml",
    "**/.travis.yml",
    "**/bitbucket-pipelines.yml",
    "**/Dockerfile*",
    "**/docker-compose*.yml",
    "**/docker-compose*.yaml",
    "**/compose.yml",
    "**/compose.yaml",
    "**/.devcontainer/**",
    "**/.vscode/tasks.json",
    "**/.vscode/settings.json",
    "**/.vscode/launch.json",
    "**/.vscode/extensions.json",
    "**/.vscode/mcp.json",
    "**/.idea/runConfigurations/**",
    "**/.cargo/config.toml",
    "**/.cargo/config",
    "**/build.rs",
    "**/rust-toolchain",
    "**/rust-toolchain.toml",
    "**/.npmrc",
    "**/.yarnrc*",
    "**/.pnpmfile.cjs",
}
USER_GLOBS = {
    "~/.cargo/config.toml",
    "~/.gradle/init.d/**",
    "~/.condarc",
    "~/.yarnrc*",
    "~/.terraformrc",
    "~/.aws/config",
    "~/AppData/Roaming/pip/pip.ini",
    "~/.config/pip/pip.conf",
}
# Names that must NOT become autorun files: the false-positive cost has to stay low.
NOT_LISTED_FRAGMENTS = [
    "readme",
    ".md",
    "tsconfig",
    "lock",
    ".gitignore",
    ".editorconfig",
    "gemfile",
    "**/*.py",
    "**/src/**",
]


def _rules(name: str) -> dict[str, dict[str, Any]]:
    data = yaml.safe_load((POLICIES / f"{name}.yaml").read_text(encoding="utf-8"))
    return {rule["id"]: rule for rule in data["rules"]}


def _rule(name: str) -> dict[str, Any]:
    return _rules(name)[RULE_IDS[name]]


def _globs(name: str) -> set[str]:
    return set(_rule(name)["match"]["path_glob"])


def _policy(name: str, platform: str) -> Policy:
    text = (POLICIES / f"{name}.yaml").read_text(encoding="utf-8")
    return parse_policy_text(text, home=policycli._FAKE[platform]["home"])


def _decide(name: str, platform: str, tool: str, tool_input: dict[str, Any]) -> tuple[str, Any]:
    result = policycli._run_one(_policy(name, platform), platform, tool, tool_input, None, None)  # type: ignore[arg-type]
    return result.verdict.decision, result.verdict


def _rule_ids_of(verdict: Any) -> set[str]:
    return {hit.rule_id for action in verdict.actions for hit in action.hits}


# ---------------------------------------------------------------------------- rule facts


@pytest.mark.parametrize("name", ["default", "strict"])
def test_rule_shape_mirrors_the_agent_exec_config_precedent(name: str) -> None:
    rule = _rule(name)
    assert rule["action"] == ACTIONS[name]
    assert rule["match"]["access"] == "write"
    # No tool filter: Write/Edit/MultiEdit and every shell write go through PathRef access=write.
    assert "tool" not in rule
    assert "platform" not in rule
    assert set(rule["match"]) == {"path_glob", "access"}
    other = "ask-agent-exec-config" if name == "default" else "deny-agent-exec-config"
    precedent = _rules(name)[other]
    assert precedent["match"]["access"] == rule["match"]["access"]
    assert "tool" not in precedent


@pytest.mark.parametrize("name", ["default", "strict"])
def test_rule_lists_every_reviewed_glob(name: str) -> None:
    globs = _globs(name)
    assert globs >= PROJECT_GLOBS, sorted(PROJECT_GLOBS - globs)
    assert globs >= USER_GLOBS, sorted(USER_GLOBS - globs)
    # The two Compose spellings must not become a prefix glob that catches composer.json & co.
    assert "**/compose*" not in {g.lower() for g in globs}


def test_strict_is_a_superset_of_default() -> None:
    assert _globs("default") <= _globs("strict")
    assert _rule("default")["match"]["access"] == _rule("strict")["match"]["access"]


def test_rule_ids_are_unique_and_the_pair_exists() -> None:
    for name in ("default", "strict"):
        data = yaml.safe_load((POLICIES / f"{name}.yaml").read_text(encoding="utf-8"))
        ids = [r["id"] for r in data["rules"]]
        assert len(ids) == len(set(ids))
        assert RULE_IDS[name] in ids


@pytest.mark.parametrize("name", ["default", "strict"])
def test_globs_stay_narrow(name: str) -> None:
    lowered = [g.lower() for g in _globs(name)]
    for fragment in NOT_LISTED_FRAGMENTS:
        assert not [g for g in lowered if fragment in g], (fragment, name)


@pytest.mark.parametrize("name", ["default", "strict"])
def test_embedded_tests_cover_each_family_and_the_negatives(name: str) -> None:
    text = (POLICIES / f"{name}.yaml").read_text(encoding="utf-8")
    policy = parse_policy_text(text, home="C:/Users/testuser")
    seen = {
        (t.tool, str(t.input.get("file_path") or t.input.get("command") or ""), t.expect)
        for t in policy.tests
    }
    want = ACTIONS[name]
    assert ("Write", "package.json", want) in seen
    assert ("Edit", "Makefile", want) in seen
    assert ("Bash", "echo x > Makefile", want) in seen
    assert ("PowerShell", "Set-Content package.json x", want) in seen
    # an ordinary project write: allow in the default policy (allow-project-file-writes), still
    # gray in strict (which has no allow rule for it)
    ordinary = ORDINARY_WRITE[name]
    for path in ("src/app.py", "README.md", "package-lock.json", "tsconfig.json"):
        assert ("Write", path, ordinary) in seen, path


# ---------------------------------------------------------------------------- decisions

WRITE_PATHS = [
    "package.json",
    "packages/web/package.json",
    "Makefile",
    "makefile",
    "GNUmakefile",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "tox.ini",
    "noxfile.py",
    "tests/conftest.py",
    "sitecustomize.py",
    "usercustomize.py",
    "site-packages/x.pth",
    ".pre-commit-config.yaml",
    ".gitattributes",
    ".gitmodules",
    ".envrc",
    ".husky/pre-commit",
    ".github/workflows/ci.yml",
    ".github/actions/setup/action.yml",
    ".gitlab-ci.yml",
    ".circleci/config.yml",
    "Jenkinsfile",
    "azure-pipelines.yml",
    ".travis.yml",
    "bitbucket-pipelines.yml",
    "Dockerfile",
    "docker/Dockerfile.dev",
    "docker-compose.yml",
    "docker-compose.override.yaml",
    "compose.yaml",
    "compose.prod.yml",
    ".devcontainer/devcontainer.json",
    ".vscode/tasks.json",
    ".vscode/settings.json",
    ".vscode/launch.json",
    ".vscode/extensions.json",
    ".vscode/mcp.json",
    ".idea/runConfigurations/app.xml",
    ".cargo/config.toml",
    ".cargo/config",
    "build.rs",
    "rust-toolchain",
    "rust-toolchain.toml",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
    ".pnpmfile.cjs",
    "~/.cargo/config.toml",
    "~/.gradle/init.d/x.gradle",
    "~/.condarc",
    "~/.yarnrc",
    "~/.terraformrc",
    "~/.aws/config",
    "~/.config/pip/pip.conf",
]
NEGATIVE_PATHS = [
    "src/app.py",
    "README.md",
    "docs/guide.md",
    "package-lock.json",
    "yarn.lock",
    "Cargo.lock",
    "tsconfig.json",
    ".gitignore",
    ".editorconfig",
    "Gemfile",
    "tests/test_app.py",
    "src/myconftest.py",
    "package.json.bak",
    "mypackage.json",
    "composer.yml",
    "docs/Makefile.md",
    ".vscode/snippets.json",
    ".github/CODEOWNERS",
]


@pytest.mark.parametrize("platform", ["windows", "posix"])
@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize("path", WRITE_PATHS)
@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit"])
def test_file_tools_writing_an_autorun_file_hit_the_rule(
    tool: str, path: str, name: str, platform: str
) -> None:
    tool_input: dict[str, Any] = {"file_path": path}
    if tool == "Write":
        tool_input["content"] = "x"
    elif tool == "Edit":
        tool_input.update(old_string="a", new_string="b")
    else:
        tool_input["edits"] = [{"old_string": "a", "new_string": "b"}]
    decision, verdict = _decide(name, platform, tool, tool_input)
    assert decision == ACTIONS[name], (path, verdict.reasons)
    assert RULE_IDS[name] in _rule_ids_of(verdict), path


@pytest.mark.parametrize("platform", ["windows", "posix"])
@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize("path", NEGATIVE_PATHS)
@pytest.mark.parametrize("tool", ["Write", "Edit"])
def test_ordinary_files_stay_outside_the_rule(
    tool: str, path: str, name: str, platform: str
) -> None:
    tool_input: dict[str, Any] = {"file_path": path}
    if tool == "Write":
        tool_input["content"] = "x"
    else:
        tool_input.update(old_string="a", new_string="b")
    decision, verdict = _decide(name, platform, tool, tool_input)
    assert RULE_IDS[name] not in _rule_ids_of(verdict), path
    assert decision == ORDINARY_WRITE[name], (path, decision)


@pytest.mark.parametrize("platform", ["windows", "posix"])
@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize(
    "command",
    [
        "echo x > Makefile",
        "echo x >> package.json",
        "echo x | tee Makefile",
        "cp /tmp/x package.json",
        "mv /tmp/x pyproject.toml",
        "mv Makefile Makefile.bak",
        "sed -i 's/a/b/' pyproject.toml",
        "rm package.json",
        "touch Makefile",
        "echo x > MAKEFILE",
        "echo x > .github/workflows/ci.yml",
        "echo x > ~/.cargo/config.toml",
        "echo x > /mnt/c/Users/someone/AppData/Roaming/pip/pip.ini",
    ],
)
def test_bash_writes_to_autorun_files_hit_the_rule(command: str, name: str, platform: str) -> None:
    decision, verdict = _decide(name, platform, "Bash", {"command": command})
    assert decision == ACTIONS[name], (command, verdict.reasons)
    assert RULE_IDS[name] in _rule_ids_of(verdict), command


@pytest.mark.parametrize("platform", ["windows", "posix"])
@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize(
    ("command", "default_decision"),
    [
        ("cat package.json", "allow"),  # a read-only inspection inside the project (M1c)
        ("grep test Makefile", "allow"),
        ("echo x > src/app.py", "gray"),  # a redirect is a write: no allow rule for it
        ("echo x > README.md", "gray"),
    ],
)
def test_bash_reads_and_ordinary_writes_stay_outside_the_rule(
    command: str, default_decision: str, name: str, platform: str
) -> None:
    decision, verdict = _decide(name, platform, "Bash", {"command": command})
    assert RULE_IDS[name] not in _rule_ids_of(verdict), command
    # strict has no allow rule besides read-inside-project: every one of them is gray there
    assert decision == (default_decision if name == "default" else "gray"), (command, decision)


@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize("tool", ["Read", "Grep"])
def test_reading_an_autorun_file_is_not_affected(name: str, tool: str) -> None:
    tool_input = (
        {"file_path": "package.json"} if tool == "Read" else {"pattern": "x", "path": "Makefile"}
    )
    decision, verdict = _decide(name, "posix", tool, tool_input)
    assert RULE_IDS[name] not in _rule_ids_of(verdict)
    assert decision == "allow"


@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize(
    "path",
    [
        "package.json.",
        "package.json ",
        "package.json::$DATA",
        "Makefile...",
        "Makefile:stream",
        "Package.JSON",
        "..\\proj\\package.json",
        "src\\..\\Makefile",
        ".github.\\workflows\\ci.yml",
        "C:/Users/testuser/proj/MAKEFILE",
        "~\\AppData\\Roaming\\pip\\pip.ini",
        "C:\\Users\\testuser\\AppData\\Roaming\\pip\\pip.ini",
    ],
)
def test_windows_spellings_of_the_same_file_hit_the_rule(name: str, path: str) -> None:
    decision, verdict = _decide(name, "windows", "Write", {"file_path": path, "content": "x"})
    assert decision == ACTIONS[name], (path, verdict.reasons)
    assert RULE_IDS[name] in _rule_ids_of(verdict), path


@pytest.mark.skipif(sys.platform != "win32", reason="PowerShell parsing needs the Windows helper")
@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize(
    "command",
    [
        "Set-Content package.json x",
        "Set-Content -Path .\\package.json -Value x",
        "'x' | Out-File Makefile",
        "'x' > Makefile",
        "Add-Content setup.py x",
        "Remove-Item package.json",
        "Rename-Item Makefile Makefile.bak",
        "Copy-Item x.txt pyproject.toml",
        "Set-Content .github\\workflows\\ci.yml x",
        "Set-Content $env:APPDATA\\pip\\pip.ini x",
        "Set-Content package.json::$DATA x",
        "Set-Content package.json. x",
    ],
)
def test_powershell_writes_to_autorun_files_hit_the_rule(command: str, name: str) -> None:
    decision, verdict = _decide(name, "windows", "PowerShell", {"command": command})
    assert decision == ACTIONS[name], (command, verdict.reasons)
    assert RULE_IDS[name] in _rule_ids_of(verdict), command


@pytest.mark.skipif(sys.platform != "win32", reason="PowerShell parsing needs the Windows helper")
@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize(
    ("command", "default_decision"),
    [("Get-Content package.json", "allow"), ("Set-Content src\\app.py x", "gray")],
)
def test_powershell_reads_and_ordinary_writes_stay_outside_the_rule(
    command: str, default_decision: str, name: str
) -> None:
    decision, verdict = _decide(name, "windows", "PowerShell", {"command": command})
    assert RULE_IDS[name] not in _rule_ids_of(verdict), command
    assert decision == (default_decision if name == "default" else "gray"), (command, decision)
