"""M1c-2 step 2: the policy rules for dev tools in trusted projects, `trust`, tool configuration
files and PowerShell data shaping.

* rule facts, read from the YAML (a dropped flag or program fails loudly), and the consistency of
  ``flags_none`` with ``programs.DEVTOOL_RISKY_FLAGS`` and of the guard rule with the allow rule;
* the default policy text with ``trusted_projects`` inserted (the fake project of the platform) run
  through the whole pipeline on tests/corpus/pipeline_m1c2_trusted.yaml, trusted and as shipped;
* every risky flag of every tool in every spelling (and unique abbreviation) is never allow;
* the hard invariants under the TRUSTED policy: no ``adv`` shell entry of any corpus is allow, and
  nothing of ``must-block`` / ``keep-ask`` / ``t3-exec`` in tests/corpus/workflow_benign.yaml is.

No command is ever executed: they are only normalized.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from functools import cache
from pathlib import Path
from typing import Any

import pytest
import yaml

from boundkeep import policycli
from boundkeep.normalize import programs, psprograms
from boundkeep.policy import Policy, default_policy_text, parse_policy_text

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"
CORPUS_DIR = ROOT / "tests" / "corpus"
TRUSTED_CORPUS = CORPUS_DIR / "pipeline_m1c2_trusted.yaml"
WORKFLOW = CORPUS_DIR / "workflow_benign.yaml"
DOC = ROOT / "docs" / "policy-reference.md"
PLATFORMS = ("windows", "posix")
PLATFORM_IDS = [f"on-{p}" for p in PLATFORMS]  # conftest.py skips ids that are the bare words
SHELL_TOOLS = ("Bash", "PowerShell")
TOOLS = tuple(sorted(programs.DEVTOOLS))
_RANK = {"allow": 0, "gray": 1, "ask": 2, "deny": 3}


# ---------------------------------------------------------------------------- helpers


def _text(name: str) -> str:
    return (POLICIES / f"{name}.yaml").read_text(encoding="utf-8")


def _rules(name: str) -> dict[str, dict[str, Any]]:
    data = yaml.safe_load(_text(name))
    return {rule["id"]: rule for rule in data["rules"]}


def _with_trusted(text: str, platform: str, mode: str) -> str:
    """``text`` with a ``trusted_projects`` block: the fake project ("trusted"), nothing ("empty"),
    or the text as shipped ("untrusted")."""
    if mode == "untrusted":
        return text
    block = "trusted_projects: []\n"
    if mode == "trusted":
        block = f"trusted_projects:\n  - '{policycli._FAKE[platform]['project']}'\n"
    assert "\nrules:\n" in text
    return text.replace("\nrules:\n", "\n" + block + "rules:\n", 1)


@cache
def _policy(name: str, platform: str, mode: str) -> Policy:
    text = _with_trusted(_text(name), platform, mode)
    return parse_policy_text(text, home=policycli._FAKE[platform]["home"])


@cache
def _ps_ready() -> bool:
    if sys.platform != "win32":
        return False
    from boundkeep.normalize import psparse

    psparse.warm_up(wait_s=15)
    return bool(psparse.status().get("state") == "ready")


def _needs_ps(tool: str) -> None:
    if tool == "PowerShell" and not _ps_ready():
        pytest.skip("PowerShell entries need the real parser helper (Windows only)")


def _run(
    name: str,
    platform: str,
    mode: str,
    tool: str,
    command: str,
    *,
    cwd: str | None = None,
    project_dir: str | None = None,
) -> Any:
    _needs_ps(tool)
    return policycli._run_one(
        _policy(name, platform, mode),
        platform,  # type: ignore[arg-type]
        tool,
        {"command": command},
        cwd,
        project_dir,
    )


def _decide(name: str, platform: str, mode: str, tool: str, command: str, **kw: Any) -> str:
    return str(_run(name, platform, mode, tool, command, **kw).verdict.decision)


def _hit_ids(review: Any) -> set[str]:
    return {hit.rule_id for action in review.verdict.actions for hit in action.hits}


def _mode_of(entry: dict[str, Any]) -> str:
    """The policy an entry of the trusted corpus runs with: trusted, or an EMPTY trusted list."""
    return "empty" if entry.get("trust") == "empty" else "trusted"


def _merged_risky_flags() -> list[str]:
    seen: dict[str, None] = {}
    for flags in programs.DEVTOOL_RISKY_FLAGS.values():
        seen.update(dict.fromkeys(flags))
    return list(seen)


# ---------------------------------------------------------------------------- rule facts


def test_the_dev_tool_lists_of_the_two_dialects_agree() -> None:
    assert set(programs.DEVTOOLS) == set(psprograms.DEV_TOOLS)
    assert set(programs.DEVTOOL_RISKY_FLAGS) == set(programs.DEVTOOLS)


def test_the_allow_rule_lists_exactly_the_dev_tools_and_the_risky_flags() -> None:
    rule = _rules("default")["allow-devtools-trusted-project"]
    assert rule["action"] == "allow"
    assert rule["tool"] == ["Bash", "PowerShell"]
    assert set(rule["match"]) == {"program", "project_trusted", "flags_none"}
    assert rule["match"]["project_trusted"] is True
    assert set(rule["match"]["program"]) == set(programs.DEVTOOLS)
    # the flag list is programs.DEVTOOL_RISKY_FLAGS, every tool's list merged, nothing else
    listed = rule["match"]["flags_none"]
    assert len(listed) == len(set(listed))
    assert set(listed) == set(_merged_risky_flags())
    assert listed == _merged_risky_flags()  # same order too: the YAML is generated from the table


def test_the_guard_rule_has_the_same_programs_and_asks_for_outside_paths() -> None:
    rules = _rules("default")
    allow = rules["allow-devtools-trusted-project"]
    guard = rules["ask-devtools-path-outside-project"]
    assert guard["action"] == "ask"
    assert guard["tool"] == allow["tool"]
    assert set(guard["match"]["program"]) == set(allow["match"]["program"])
    assert guard["match"]["path_outside_project"] is True
    assert guard["match"]["project_trusted"] is True
    # no glob and no access: a "**" glob of a read rule would become a protected NAME for the
    # subtree scan of recursive reads (see test_m1c_allow_rules.py)
    assert set(guard["match"]) == {"program", "project_trusted", "path_outside_project"}


def test_strict_has_no_dev_tool_rule_and_still_one_allow_rule() -> None:
    strict = _rules("strict")
    assert "allow-devtools-trusted-project" not in strict
    assert "ask-devtools-path-outside-project" not in strict
    assert "allow-ps-data-shaping" not in strict
    assert "allow-cd-family" not in strict  # M1c-3: default only
    assert [i for i, r in strict.items() if r["action"] == "allow"] == ["read-inside-project"]
    assert all("project_trusted" not in r["match"] for r in strict.values())


@pytest.mark.parametrize("name", ["default", "strict"])
def test_no_shipped_policy_trusts_a_project(name: str) -> None:
    assert "trusted_projects" not in yaml.safe_load(_text(name))
    assert _policy(name, "posix", "untrusted").trusted_projects == ()
    assert parse_policy_text(default_policy_text(), home="/home/testuser").trusted_projects == ()


@pytest.mark.parametrize("name", ["default", "strict"])
def test_trust_is_a_denied_boundkeep_subcommand(name: str) -> None:
    rules = _rules(name)
    rule = rules["deny-boundkeep-state-commands"]
    assert rule["action"] == "deny"
    assert set(rule["match"]["subcommand"]) == {"mode", "uninstall", "init", "serve", "trust"}
    assert rule["match"]["program"] == ["boundkeep", "boundkeep-hook"]


@pytest.mark.parametrize("name", ["default", "strict"])
def test_the_python_tool_config_rule_is_in_both_policies_with_the_same_globs(name: str) -> None:
    rule_id = (
        "ask-python-tool-config-write" if name == "default" else "deny-python-tool-config-write"
    )
    rules = _rules(name)
    rule = rules[rule_id]
    assert rule["action"] == ("ask" if name == "default" else "deny")
    assert rule["match"]["access"] == "write"
    assert "tool" not in rule
    assert set(rule["match"]["path_glob"]) == set(PYTHON_CONFIG_GLOBS)
    assert len(rule["match"]["path_glob"]) == len(PYTHON_CONFIG_GLOBS)
    # nothing of the older autorun list changed: identical lists in both policies
    autorun_default = _rules("default")["ask-project-autorun-files"]["match"]["path_glob"]
    autorun_strict = _rules("strict")["deny-project-autorun-files"]["match"]["path_glob"]
    assert autorun_default == autorun_strict


PYTHON_CONFIG_GLOBS = [
    "**/mypy.ini",
    "**/.mypy.ini",
    "**/pylintrc",
    "**/.pylintrc",
    "**/pylintrc.toml",
    "**/.pylintrc.toml",
    "**/.flake8",
    "**/.coveragerc",
    "**/pytest.ini",
    "**/.pytest.ini",
]


def test_the_data_shaping_rule_names_exactly_the_reviewed_cmdlets() -> None:
    rule = _rules("default")["allow-ps-data-shaping"]
    assert rule["action"] == "allow"
    assert rule["tool"] == ["PowerShell"]
    assert set(rule["match"]["program"]) == {
        "Select-Object",
        "Out-String",
        "Out-Null",
        "Format-Table",
        "Format-List",
        "Sort-Object",
        "Group-Object",
        "ConvertTo-Json",
        "ConvertFrom-Json",
        "Where-Object",
    }
    assert rule["match"]["paths_read_only"] is True
    assert rule["match"]["flags_none"] == ["-InputObject"]
    names = {p.casefold() for p in rule["match"]["program"]}
    # these write files, run code or run script blocks: never in this rule
    for left_out in (
        "foreach-object",
        "out-file",
        "set-content",
        "add-content",
        "tee-object",
        "export-csv",
        "export-clixml",
        "invoke-expression",
        "invoke-command",
        "invoke-webrequest",
        "write-output",
        "write-host",
    ):
        assert left_out not in names, left_out


def test_the_docs_describe_the_new_rules_and_the_risk() -> None:
    text = DOC.read_text(encoding="utf-8")
    for rule_id in (
        "allow-devtools-trusted-project",
        "ask-devtools-path-outside-project",
        "allow-ps-data-shaping",
        "ask-python-tool-config-write",
        "deny-python-tool-config-write",
    ):
        assert f"`{rule_id}`" in text, rule_id
    assert "write-then-run" in text
    assert "boundkeep trust add" in text
    assert "ps-pipeline-head-dynamic" in (ROOT / "docs" / "powershell-dialect.md").read_text(
        encoding="utf-8"
    )


# ---------------------------------------------------------------------------- the corpus


def _trusted_entries() -> list[Any]:
    data = yaml.safe_load(TRUSTED_CORPUS.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    return data


def _entry_params() -> Iterator[Any]:
    for entry in _trusted_entries():
        for platform in PLATFORMS:
            if entry.get("platform") not in (None, platform):
                continue
            yield pytest.param(entry, platform, id=f"{entry['id']}-{platform}")


def test_the_trusted_corpus_is_big_unique_and_well_formed() -> None:
    entries = _trusted_entries()
    ids = [e["id"] for e in entries]
    assert len(set(ids)) == len(ids)
    assert len(entries) >= 250
    assert all(e.get("trusted") is True for e in entries)
    assert all(e["expect"] in _RANK for e in entries)
    assert sum(1 for e in entries if e["expect"] == "allow") >= 40
    adv = [e for e in entries if e.get("adv")]
    assert len(adv) >= 150
    assert all(e["expect"] != "allow" and e.get("expect_untrusted", "gray") != "allow" for e in adv)
    assert {e["tool"] for e in entries} == {"Bash", "PowerShell"}
    # every allowed form is gray without trust (nothing allows a dev tool by itself)
    for e in entries:
        if e["expect"] == "allow" and "expect_untrusted" in e:
            assert e["expect_untrusted"] == "gray", e["id"]


@pytest.mark.parametrize(("entry", "platform"), list(_entry_params()))
def test_trusted_corpus_entry(entry: dict[str, Any], platform: str) -> None:
    mode = _mode_of(entry)
    review = _run(
        "default",
        platform,
        mode,
        entry["tool"],
        entry["input"]["command"],
        cwd=entry.get("cwd"),
        project_dir=entry.get("project_dir"),
    )
    got = review.verdict.decision
    assert got == entry["expect"], (entry["id"], mode, got, review.verdict.reasons)
    if entry.get("adv"):
        assert got != "allow"
    if "expect_untrusted" in entry:
        plain = _run(
            "default",
            platform,
            "untrusted",
            entry["tool"],
            entry["input"]["command"],
            cwd=entry.get("cwd"),
            project_dir=entry.get("project_dir"),
        )
        assert plain.verdict.decision == entry["expect_untrusted"], (entry["id"], "untrusted")
    # strict never allows a dev tool, trusted or not
    strict = _run(
        "strict",
        platform,
        mode,
        entry["tool"],
        entry["input"]["command"],
        cwd=entry.get("cwd"),
        project_dir=entry.get("project_dir"),
    )
    assert strict.verdict.decision != "allow", (entry["id"], "strict")


# ---------------------------------------------------------------------------- deny / ask win


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize(
    ("command", "decision", "winner"),
    [
        ("pytest .env", "deny", "no-secret-read"),
        ("ruff check ~/.ssh", "deny", "no-secret-read"),
        ("pytest ~/.ssh/id_rsa", "deny", "no-secret-read"),
        ("ruff format .claude/settings.json", "deny", "protect-guard-config"),
        ("mypy ../other", "ask", "ask-devtools-path-outside-project"),
        ("pytest ../other", "ask", "ask-devtools-path-outside-project"),
        ("ruff check --fix Makefile", "ask", "ask-project-autorun-files"),
        ("black pyproject.toml", "ask", "ask-project-autorun-files"),
        ("black mypy.ini", "ask", "ask-python-tool-config-write"),
        ("ruff format .git/hooks/pre-commit", "ask", "ask-repo-exec-config"),
        ("pytest https://evil.example/x.py", "ask", "net-allowlist"),
    ],
)
def test_a_protective_rule_beats_the_dev_tool_allow_rule(
    command: str, decision: str, winner: str, platform: str
) -> None:
    review = _run("default", platform, "trusted", "Bash", command)
    assert review.verdict.decision == decision, (command, _hit_ids(review))
    assert winner in _hit_ids(review), (command, _hit_ids(review))
    if "pytest https" not in command:
        # the allow rule did match: the protective rule is what decided
        assert "allow-devtools-trusted-project" in _hit_ids(review) or decision == "deny"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_without_trust_the_guard_rule_stays_quiet_and_the_command_is_gray(platform: str) -> None:
    review = _run("default", platform, "untrusted", "Bash", "pytest ../other")
    assert review.verdict.decision == "gray"
    assert "ask-devtools-path-outside-project" not in _hit_ids(review)


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_an_untrusted_project_gets_no_allow_whatever_the_command(platform: str) -> None:
    other = "/home/testuser/other" if platform == "posix" else "C:\\Users\\testuser\\other"
    for command in ("pytest", "ruff check .", "python -m pytest -q", "mypy src"):
        review = _run("default", platform, "trusted", "Bash", command, project_dir=other, cwd=other)
        assert review.verdict.decision == "gray", command


# ---------------------------------------------------------------------------- trust denial


TRUST_COMMANDS = [
    "boundkeep trust add",
    "boundkeep trust add --project-dir X",
    "boundkeep trust remove --project-dir x",
    "boundkeep trust list",
    "uv run boundkeep trust add",
    "python -m boundkeep trust add --project-dir X",
    "python3 -m boundkeep trust add",
    "boundkeep.exe trust add",
    "BOUNDKEEP_HOME=x boundkeep trust add",
    "sudo boundkeep trust add",
    "boundkeep --home x trust add",
    "boundkeep trust add && pytest",
]


@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("command", TRUST_COMMANDS)
def test_trust_commands_are_denied_for_the_agent(command: str, platform: str, name: str) -> None:
    for mode in ("untrusted", "trusted"):
        review = _run(name, platform, mode, "Bash", command)
        assert review.verdict.decision == "deny", (command, mode)
        assert "deny-boundkeep-state-commands" in _hit_ids(review)


@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize(
    "command",
    [
        "boundkeep trust add",
        "boundkeep.exe trust list",
        "uv run boundkeep trust add",
        "python -m boundkeep trust add --project-dir X",
    ],
)
def test_trust_commands_are_denied_in_powershell_too(command: str, name: str) -> None:
    assert _decide(name, "windows", "untrusted", "PowerShell", command) == "deny"


def test_the_other_read_only_boundkeep_commands_still_only_ask() -> None:
    # `trust list` cannot be told from `trust add` by a rule (it sees the subcommand only), so every
    # trust form is refused; doctor, test, explain and log keep their ask
    for name in ("default", "strict"):
        for command in ("boundkeep doctor", "boundkeep test", "boundkeep log --tail 5"):
            assert _decide(name, "posix", "untrusted", "Bash", command) == "ask", command


# ---------------------------------------------------------------------------- tool configuration


CONFIG_NAMES = [
    "mypy.ini",
    ".mypy.ini",
    "pylintrc",
    ".pylintrc",
    "pylintrc.toml",
    ".pylintrc.toml",
    ".flake8",
    ".coveragerc",
    "pytest.ini",
    ".pytest.ini",
]


def _file_input(tool: str, path: str) -> dict[str, Any]:
    if tool == "Write":
        return {"file_path": path, "content": "x"}
    if tool == "Edit":
        return {"file_path": path, "old_string": "a", "new_string": "b"}
    return {"file_path": path, "edits": [{"old_string": "a", "new_string": "b"}]}


@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("path", [*CONFIG_NAMES, *(f"sub/dir/{n}" for n in CONFIG_NAMES)])
@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit"])
def test_writing_a_python_tool_config_file_asks_or_is_refused(
    tool: str, path: str, platform: str, name: str
) -> None:
    expected = "ask" if name == "default" else "deny"
    for mode in ("untrusted", "trusted"):
        review = policycli._run_one(
            _policy(name, platform, mode),
            platform,  # type: ignore[arg-type]
            tool,
            _file_input(tool, path),
            None,
            None,
        )
        assert review.verdict.decision == expected, (tool, path, mode, review.verdict.reasons)


@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("path", CONFIG_NAMES)
def test_shell_writes_of_a_python_tool_config_file_ask_or_are_refused(
    path: str, platform: str, name: str
) -> None:
    expected = "ask" if name == "default" else "deny"
    for command in (f"echo x > {path}", f"touch {path}", f"cp /tmp/x {path}", f"tee {path}"):
        assert _decide(name, platform, "trusted", "Bash", command) == expected, command


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("path", ["MYPY.INI", "Mypy.Ini", ".FLAKE8", "PyLintRc"])
def test_python_tool_config_names_are_matched_without_case_on_every_platform(
    path: str, platform: str
) -> None:
    review = policycli._run_one(
        _policy("default", platform, "untrusted"),
        platform,  # type: ignore[arg-type]
        "Write",
        _file_input("Write", path),
        None,
        None,
    )
    assert review.verdict.decision == "ask"


@pytest.mark.skipif(sys.platform != "win32", reason="PowerShell parsing needs the Windows helper")
@pytest.mark.parametrize("path", CONFIG_NAMES)
def test_powershell_writes_of_a_python_tool_config_file_ask(path: str) -> None:
    for command in (f'Set-Content {path} "x"', f'"x" | Out-File {path}', f'"x" > {path}'):
        assert _decide("default", "windows", "trusted", "PowerShell", command) == "ask", command
        assert _decide("strict", "windows", "trusted", "PowerShell", command) == "deny", command


@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize("path", ["ruff.toml", ".ruff.toml", "setup.cfg.bak", "docs/mypy.ini.md"])
def test_names_that_load_nothing_are_not_in_the_config_rule(path: str, name: str) -> None:
    review = policycli._run_one(
        _policy(name, "posix", "untrusted"),
        "posix",
        "Write",
        _file_input("Write", path),
        None,
        None,
    )
    ids = _hit_ids(review)
    assert "ask-python-tool-config-write" not in ids
    assert "deny-python-tool-config-write" not in ids


# ---------------------------------------------------------------------------- data shaping


SHAPING_ALLOWED = [
    "Get-ChildItem | Select-Object Name",
    "Get-ChildItem | Select-Object -First 3",
    "Get-Content src\\app.py | Select-Object -First 20",
    "Get-ChildItem | Sort-Object Name",
    "Get-ChildItem | Where-Object Name -like 'a*'",
    "Get-ChildItem | Group-Object Extension",
    "Get-ChildItem | Format-Table",
    "Get-ChildItem | Format-List",
    "Get-ChildItem | Out-String",
    "Get-ChildItem | Out-Null",
    "Get-ChildItem | ConvertTo-Json",
    "Get-Content package.json | ConvertFrom-Json",
    "'{}' | ConvertFrom-Json",
    "Get-ChildItem | Measure-Object",
]
SHAPING_NOT_ALLOWED = [
    "$env:SECRET_TOKEN | Select-Object",
    "$env:SECRET_TOKEN | Out-String",
    "$x | Out-String",
    "$x | Select-Object",
    "$x | Format-List",
    "$x | ConvertTo-Json",
    "(Get-Content f) | Select-Object -First 3",
    "Select-Object -InputObject $env:SECRET_TOKEN",
    "Out-String -InputObject $env:SECRET_TOKEN",
    "Format-List -InputObject $env:SECRET_TOKEN",
    "Get-ChildItem | Where-Object { $_.Length -gt 1 }",
    "Get-ChildItem | Select-Object -Property @{n='a';e={1}}",
    "Get-ChildItem | Sort-Object { $_.Name }",
    "Get-ChildItem | Group-Object { $_.Extension }",
    "Get-ChildItem | ForEach-Object { $_.Name }",
    "Get-ChildItem | Out-File x.txt",
    "Get-ChildItem | Set-Content x.txt",
    "Get-ChildItem | Add-Content x.txt",
    "Get-ChildItem | Tee-Object x.txt",
    "Get-ChildItem | Export-Csv x.csv",
    "Get-ChildItem | Export-Clixml x.xml",
    "Get-ChildItem | Invoke-Expression",
    "Get-ChildItem | Select-Object Name > x.txt",
    "Get-ChildItem | Select-Object Name | Out-File x.txt",
    "Get-ChildItem C:\\Windows | Select-Object Name",
    "Get-ChildItem | Remove-Item",
    "Get-Process | Select-Object Name",
    "Get-ChildItem | Select-Object Name; Remove-Item x",
]


@pytest.mark.parametrize("command", SHAPING_ALLOWED)
def test_data_shaping_after_an_allowed_command_is_allowed(command: str) -> None:
    review = _run("default", "windows", "untrusted", "PowerShell", command)
    assert review.verdict.decision == "allow", (command, review.verdict.reasons)


@pytest.mark.parametrize("command", SHAPING_NOT_ALLOWED)
def test_data_shaping_never_prints_a_value_nobody_judged(command: str) -> None:
    for name in ("default", "strict"):
        review = _run(name, "windows", "trusted", "PowerShell", command)
        assert review.verdict.decision != "allow", (name, command, _hit_ids(review))


@pytest.mark.parametrize("command", SHAPING_ALLOWED)
def test_strict_does_not_allow_data_shaping(command: str) -> None:
    assert _decide("strict", "windows", "trusted", "PowerShell", command) != "allow"


def test_the_pipeline_head_of_a_shaping_line_is_judged_on_its_own() -> None:
    # the whole line is allow only if every command of it is
    assert (
        _decide(
            "default", "windows", "untrusted", "PowerShell", "Get-ChildItem | Select-Object Name"
        )
        == "allow"
    )
    assert (
        _decide(
            "default", "windows", "untrusted", "PowerShell", "Get-Content .env | Select-Object Name"
        )
        == "deny"
    )
    assert (
        _decide(
            "default",
            "windows",
            "untrusted",
            "PowerShell",
            "Get-Content ..\\x | Select-Object Name",
        )
        == "gray"
    )


# ---------------------------------------------------------------------------- every risky flag


def _spellings(tool: str, flag: str) -> list[str]:
    """Command lines that use ``flag`` of ``tool`` in every way it can be typed."""
    out = []
    if flag.startswith("--"):
        out += [f"{tool} {flag}", f"{tool} {flag}=x", f"{tool} {flag} x", f"{tool} {flag}=x src"]
    else:
        letter = flag[1:]
        out += [
            f"{tool} {flag}",
            f"{tool} {flag} x",
            f"{tool} {flag}x",
            f"{tool} -q{letter} x",
            f"{tool} -{letter}{letter} x" if len(letter) == 1 else f"{tool} {flag}=x",
        ]
    out.append(f"python -m {tool} {flag} x")
    out.append(
        f"python -u -m {tool} {flag}=x" if flag.startswith("--") else f"python -u -m {tool} {flag}"
    )
    return out


def _flag_cases() -> Iterator[Any]:
    for tool, flags in programs.DEVTOOL_RISKY_FLAGS.items():
        for flag in flags:
            yield pytest.param(tool, flag, id=f"{tool}{flag}")


@pytest.mark.parametrize(("tool", "flag"), list(_flag_cases()))
def test_every_risky_flag_in_every_spelling_is_never_allowed_bash(tool: str, flag: str) -> None:
    for platform in PLATFORMS:
        for command in _spellings(tool, flag):
            review = _run("default", platform, "trusted", "Bash", command)
            assert review.verdict.decision != "allow", (platform, command, _hit_ids(review))


@pytest.mark.skipif(sys.platform != "win32", reason="PowerShell parsing needs the Windows helper")
@pytest.mark.parametrize(("tool", "flag"), list(_flag_cases()))
def test_every_risky_flag_in_every_spelling_is_never_allowed_powershell(
    tool: str, flag: str
) -> None:
    for command in _spellings(tool, flag):
        review = _run("default", "windows", "trusted", "PowerShell", command)
        assert review.verdict.decision != "allow", (command, _hit_ids(review))


def _abbreviation_cases() -> Iterator[Any]:
    for tool, flags in programs.DEVTOOL_RISKY_FLAGS.items():
        opts = programs._DEVSPECS[tool].opts
        for flag in flags:
            if not flag.startswith("--") or not (flag in opts.long or flag in opts.long_flags):
                continue
            body = flag[2:]
            for size in range(3, len(body)):
                prefix = "--" + body[:size]
                if prefix in opts.long or prefix in opts.long_flags:
                    continue  # a real option of its own (pytest-cov's --cov), not an abbreviation
                yield pytest.param(tool, prefix, id=f"{tool}{prefix}")


@pytest.mark.parametrize(("tool", "prefix"), list(_abbreviation_cases()))
def test_unique_abbreviations_of_a_risky_flag_are_never_allowed(tool: str, prefix: str) -> None:
    """The tool tables resolve a unique prefix to the full flag (and an ambiguous one to all of its
    candidates), so an abbreviation of a risky long flag stays a risky flag."""
    for command in (f"{tool} {prefix}=x", f"python -m {tool} {prefix} x"):
        review = _run("default", "posix", "trusted", "Bash", command)
        assert review.verdict.decision != "allow", (command, _hit_ids(review))


def test_a_flag_that_is_not_risky_does_not_block_the_allow_rule() -> None:
    for command in (
        "pytest -q",
        "pytest -x -vv",
        "pytest --maxfail=1",
        "ruff check --select E,F .",
        "ruff check --fix-only .",
        "mypy --strict src",
        "black --diff .",
        "isort --profile black .",
        "flake8 --max-line-length=100 src",
        "pylint --disable=C0114 src",
    ):
        assert _decide("default", "posix", "trusted", "Bash", command) == "allow", command


# ---------------------------------------------------------------------------- the invariants


def _pipeline_entries() -> list[tuple[dict[str, Any], str]]:
    out = []
    for path in sorted(CORPUS_DIR.glob("pipeline*.yaml")):
        for entry in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            for platform in PLATFORMS:
                if entry.get("platform") in (None, platform):
                    out.append((entry, platform))
    return out


def test_no_adversarial_shell_entry_of_any_corpus_is_allow_in_a_trusted_project() -> None:
    """Hard invariant 1, under the TRUSTED policy (the project of the fake machine is trusted)."""
    checked = 0
    offenders: list[str] = []
    for entry, platform in _pipeline_entries():
        if not entry.get("adv") or entry["tool"] not in SHELL_TOOLS:
            continue
        if entry["tool"] == "PowerShell" and not _ps_ready():
            continue
        checked += 1
        review = policycli._run_one(
            _policy("default", platform, _mode_of(entry)),
            platform,  # type: ignore[arg-type]
            entry["tool"],
            entry["input"],
            entry.get("cwd"),
            entry.get("project_dir"),
            entry.get("session_id"),
        )
        if review.verdict.decision == "allow":
            offenders.append(f"{entry['id']} ({platform})")
    assert checked > 500
    assert not offenders, offenders


def test_the_devtool_adversarial_entries_of_the_m1c2_corpora_are_not_allow_when_trusted() -> None:
    names = sorted(p.name for p in CORPUS_DIR.glob("pipeline_m1c2_*.yaml"))
    assert "pipeline_m1c2_devtools.yaml" in names
    count = 0
    for path in CORPUS_DIR.glob("pipeline_m1c2_*.yaml"):
        for entry in yaml.safe_load(path.read_text(encoding="utf-8")):
            if not entry.get("adv") or entry["tool"] not in SHELL_TOOLS:
                continue
            for platform in PLATFORMS:
                if entry.get("platform") not in (None, platform):
                    continue
                if entry["tool"] == "PowerShell" and not _ps_ready():
                    continue
                count += 1
                review = policycli._run_one(
                    _policy("default", platform, _mode_of(entry)),
                    platform,  # type: ignore[arg-type]
                    entry["tool"],
                    entry["input"],
                    entry.get("cwd"),
                    entry.get("project_dir"),
                    entry.get("session_id"),
                )
                assert review.verdict.decision != "allow", (path.name, entry["id"], platform)
    assert count > 100


def test_nothing_that_must_block_keep_asking_or_run_code_is_allow_when_trusted() -> None:
    """Hard invariant 2, under the TRUSTED policy."""
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    checked = 0
    offenders: list[str] = []
    for entry in data:
        if entry["tier"] not in ("must-block", "keep-ask", "t3-exec"):
            continue
        for platform in PLATFORMS:
            if entry.get("platform") not in (None, platform):
                continue
            if entry["tool"] == "PowerShell" and not _ps_ready():
                continue
            checked += 1
            review = policycli._run_one(
                _policy("default", platform, "trusted"),
                platform,  # type: ignore[arg-type]
                entry["tool"],
                entry["input"],
                None,
                None,
                entry.get("session_id"),
            )
            if review.verdict.decision == "allow":
                offenders.append(f"{entry['id']} ({platform})")
    assert checked > 200
    assert not offenders, offenders


def test_the_trusted_policy_has_exactly_the_untrusted_verdicts_except_for_dev_tools() -> None:
    """Trusting a project changes nothing but the dev-tool forms: every other entry of the shipped
    corpora gets the same verdict trusted and untrusted."""
    different: list[str] = []
    for entry, platform in _pipeline_entries():
        if entry["tool"] == "PowerShell" and not _ps_ready():
            continue
        if entry["tool"] in SHELL_TOOLS:
            command = str(entry["input"].get("command", ""))
            lowered = command.casefold()
            if any(
                tool in lowered
                for tool in (*programs.DEVTOOLS, "python -m", "python3 -m", "py -m", ".venv")
            ):
                continue
        a = policycli._run_one(
            _policy("default", platform, "untrusted"),
            platform,  # type: ignore[arg-type]
            entry["tool"],
            entry["input"],
            entry.get("cwd"),
            entry.get("project_dir"),
            entry.get("session_id"),
        )
        b = policycli._run_one(
            _policy("default", platform, "trusted"),
            platform,  # type: ignore[arg-type]
            entry["tool"],
            entry["input"],
            entry.get("cwd"),
            entry.get("project_dir"),
            entry.get("session_id"),
        )
        if a.verdict.decision != b.verdict.decision:
            different.append(f"{entry['id']} ({platform})")
    assert not different, different
