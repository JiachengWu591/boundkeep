"""M4: regression tests for the review of revision 44 (R44-1 to R44-7, docs/reports/M4.md 6a).

Each test is a reproduction from the review: before the fix the proposal passed (or the command
misreported, or crashed); now it is refused or reported as it really is.
"""

from __future__ import annotations

import builtins
import json
from pathlib import Path
from typing import Any

import pytest

from boundkeep import cli, trust
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.compiler import checks, command, proposal, writer
from boundkeep.policy import Rule, default_policy_text
from tests.unit.test_m4_checks import CURL_DENY, CURL_TESTS, MINI, bash, codes, make, read


def _allow(program: Any, tools: list[str] | None = None, **match: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": "allow-x",
        "match": {"program": program, **match},
        "action": "allow",
    }
    if tools is not None:
        rule["tool"] = tools
    return rule


def _syntax(rule: dict[str, Any], ps_ready: bool = False) -> set[str]:
    model = Rule.model_validate(rule, context={"home": "/home/testuser"})
    report = checks.Report(source="t")
    checks._syntactic(model, report, checks.ProgramProbe(ps_ready))
    return codes(report, "refuse") | {f"warn:{c}" for c in codes(report, "warn")}


# --------------------------------------------------------------------------- R44-1


@pytest.mark.parametrize(
    "program",
    [
        "pythonw",
        "py",
        "python3.12",
        "PY",
        "ipython",
        "tsx",
        "ts-node",
        "julia",
        "irb",
        "nice",
        "nohup",
        "stdbuf",
        "installutil",
        "mshta",
        "rundll32",
        "cscript",
        "some-unknown-tool",
    ],
)
def test_a_program_that_runs_code_or_is_unknown_cannot_be_allowed(program: str) -> None:
    assert "allow-runs-code" in _syntax(_allow(program, ["Bash"]))


@pytest.mark.parametrize("program", ["git", "rg", "jq", "ls"])
def test_known_programs_that_run_no_code_pass_the_program_check(program: str) -> None:
    assert _syntax(_allow(program, ["Bash"])) == set()


@pytest.mark.parametrize("program", ["make", "npm", "pytest", "cargo"])
def test_build_and_package_tools_are_a_warning_not_a_refusal(program: str) -> None:
    assert _syntax(_allow(program, ["Bash"])) == {"warn:allow-repo-code"}


@pytest.mark.windows
def test_a_case_variant_in_powershell_is_probed_there() -> None:
    from boundkeep.evalkit.runner import ps_helper_ready

    if not ps_helper_ready():
        pytest.skip("the PowerShell parser helper did not start")
    rule = _allow("Python", ["PowerShell"], path_inside_project=True)
    assert "allow-runs-code" in _syntax(rule, ps_ready=True)
    nice = _allow("nice", ["PowerShell"])
    assert "allow-runs-code" in _syntax(nice, ps_ready=True)


def test_the_review_reproduction_is_refused_against_the_default_policy() -> None:
    tests = [
        bash("pythonw a.py", "allow"),
        bash("pythonw b.py", "allow"),
        bash("pythonw -m x", "allow"),
        bash("ls", "allow"),
        bash("git status", "allow"),
        bash("pwd", "allow"),
    ]
    report = checks.check(
        default_policy_text(),
        make([_allow("pythonw", ["Bash"])], tests),
        source="t",
        ps_ready=False,
        note="n",
    )
    assert "allow-runs-code" in codes(report, "refuse")
    assert report.new_text is None


# --------------------------------------------------------------------------- R44-2, network


@pytest.mark.parametrize(
    ("rule", "code"),
    [
        (
            {"tool": ["Write", "Edit"], "match": {"path_glob": ["~/AppData/Roaming/Code/User/**"]}},
            "allow-outside-project",
        ),
        (
            {"tool": ["Read"], "match": {"path_glob": ["c:/users/someone/**"]}},
            "allow-outside-project",
        ),
        ({"tool": ["Read"], "match": {"paths_read_only": True}}, "allow-outside-project"),
        ({"match": {"program": "cat", "path_glob": ["**/*.md"]}}, "allow-outside-project"),
        ({"tool": ["WebFetch"], "match": {"paths_read_only": True}}, "allow-network"),
        ({"tool": ["WebSearch"], "match": {"paths_read_only": True}}, "allow-network"),
        ({"tool": ["Bash"], "match": {"program": "curl"}}, "allow-network"),
    ],
)
def test_allow_rules_must_keep_paths_and_hosts_in_bounds(rule: dict[str, Any], code: str) -> None:
    assert code in _syntax({"id": "allow-x", "action": "allow", **rule})


@pytest.mark.parametrize(
    "rule",
    [
        {
            "tool": ["Read", "Grep"],
            "match": {"path_glob": ["**/docs/**"], "path_inside_project": True},
        },
        {"tool": ["Write"], "match": {"path_in_scratchpad": True}},
        {"tool": ["WebFetch"], "match": {"network": True, "domain_in": ["docs.python.org"]}},
        {"tool": ["Bash"], "match": {"program": "curl", "domain_in": ["pypi.org"]}},
        {"tool": ["mcp__github__get_*"], "match": {"mcp_read_only": True}},
    ],
)
def test_scoped_allow_rules_pass_these_checks(rule: dict[str, Any]) -> None:
    assert _syntax({"id": "allow-x", "action": "allow", **rule}) == set()


def test_the_vscode_settings_reproduction_is_refused() -> None:
    rule = {
        "id": "allow-vscode-user",
        "tool": ["Write", "Edit"],
        "match": {"path_glob": ["~/AppData/Roaming/Code/User/**"]},
        "action": "allow",
    }
    write = lambda p, e: {"tool": "Write", "input": {"file_path": p, "content": "x"}, "expect": e}  # noqa: E731
    tests = [
        write("~/AppData/Roaming/Code/User/settings.json", "allow"),
        write("~/AppData/Roaming/Code/User/tasks.json", "allow"),
        write("~/AppData/Roaming/Code/User/keybindings.json", "allow"),
        write("src/a.py", "allow"),
        read("src/a.py", "allow"),
        write("~/notes.txt", "gray"),
    ]
    report = checks.check(
        default_policy_text(), make([rule], tests), source="t", ps_ready=False, note="n"
    )
    assert "allow-outside-project" in codes(report, "refuse")


# --------------------------------------------------------------------------- R44-3


def test_an_already_failing_test_that_gets_looser_is_refused() -> None:
    policy = MINI.replace(
        '  - { tool: Bash, input: { command: "git push" }, expect: gray }\n',
        '  - { tool: Bash, input: { command: "git push" }, expect: gray }\n'
        '  - { tool: Bash, input: { command: "make deploy" }, expect: deny }\n',
    )
    rule = _allow("make", ["Bash"])
    tests = [
        bash("make", "allow"),
        bash("make all", "allow"),
        bash("make -k", "allow"),
        bash("cmake .", "gray"),
        bash("ls", "gray"),
        bash("nmake", "gray"),
    ]
    report = checks.check(policy, make([rule], tests), source="t", ps_ready=False, note="n")
    assert "tests-fail" in codes(report, "refuse")
    assert any("make deploy" in f.message and "allow" in f.message for f in report.findings)


def test_an_already_failing_test_note_shows_the_new_verdict() -> None:
    policy = MINI.replace(
        'command: "git push" }, expect: gray', 'command: "git push" }, expect: allow'
    )
    report = checks.check(
        policy, make([CURL_DENY], CURL_TESTS), source="t", ps_ready=False, note="n"
    )
    note = next(f.message for f in report.findings if f.code == "tests-already-failing")
    assert "got gray, now gray" in note


# --------------------------------------------------------------------------- R44-4


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("BOUNDKEEP_HOME", str(tmp_path / "bk"))
    (tmp_path / "bk").mkdir()
    return tmp_path / "bk"


def test_a_history_that_cannot_be_written_says_the_policy_was_written(home: Path) -> None:
    policy = home / "policy.yaml"
    policy.write_text(MINI, encoding="utf-8")
    (home / "policy-history" / writer.INDEX_NAME).mkdir(parents=True)  # appending must fail
    data = policy.read_bytes()
    new = writer.merge_text(MINI, [CURL_DENY], [], note="n")
    with pytest.raises(writer.NotRecorded) as caught:
        writer.apply(
            str(policy),
            expected_before=data,
            new_text=new,
            bom="",
            source="t",
            rule_ids=["deny-curl"],
            tests=0,
        )
    assert "deny-curl" in policy.read_text("utf-8")  # it WAS written
    assert Path(caught.value.backup).read_bytes() == data


def test_the_command_reports_written_when_only_the_history_failed(
    boundkeep_home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for name in trust.AGENT_ENV:
        monkeypatch.delenv(name, raising=False)
    boundkeep_home.mkdir()
    (boundkeep_home / "policy.yaml").write_text(MINI, encoding="utf-8")
    (boundkeep_home / "policy-history" / writer.INDEX_NAME).mkdir(parents=True)
    monkeypatch.setattr(command, "_console_ok", lambda: True)
    monkeypatch.setattr(command, "_ps_ready", lambda: False)
    monkeypatch.setattr(builtins, "input", lambda _q="": "yes")
    path = tmp_path / "p.yaml"
    path.write_text(
        proposal.text_from_json({"proposal": 1, "rules": [CURL_DENY], "tests": CURL_TESTS}),
        encoding="utf-8",
    )
    empty = tmp_path / "empty"
    empty.mkdir()
    code = cli.main(
        [
            "--home",
            str(boundkeep_home),
            "policy",
            "check",
            str(path),
            "--apply",
            "--log-limit",
            "0",
            "--dataset",
            str(empty),
        ]
    )
    err = capsys.readouterr().err
    assert code == 1
    assert "WRITTEN, but the history could not be recorded" in err
    assert "not written" not in err


# --------------------------------------------------------------------------- R44-5, R44-6, R44-7


def test_a_deeply_nested_backend_answer_is_not_usable_not_a_crash() -> None:
    deep: Any = "x"
    for _ in range(900):
        deep = [deep]
    with pytest.raises(proposal.ProposalError):
        proposal.text_from_json({"proposal": 1, "rules": deep})


def test_hidden_characters_in_tests_are_shown_escaped() -> None:
    tests = [*CURL_TESTS[:-1], bash("echo curl\u202e\u200b", "gray")]
    report = checks.check(MINI, make([CURL_DENY], tests), source="t", ps_ready=False, note="n")
    assert report.new_text is not None
    assert "\\u202e\\u200b" in report.added_tests_text
    assert "\u202e" not in report.added_tests_text
    assert "\u200b" not in report.added_tests_text


def test_skipped_powershell_canaries_are_counted() -> None:
    report = checks.check(MINI, make([CURL_DENY], CURL_TESTS), source="t", ps_ready=False, note="n")
    assert report.canaries_skipped == sum(1 for c in checks.CANARIES if c.tool == "PowerShell")


def test_prompt_refuses_a_secret_environment_value(
    boundkeep_home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in trust.AGENT_ENV:
        monkeypatch.delenv(name, raising=False)
    boundkeep_home.mkdir()
    (boundkeep_home / "policy.yaml").write_text(MINI, encoding="utf-8")
    monkeypatch.setenv("MY_SERVICE_TOKEN", "plain-value-of-the-token-42")
    code = cli.main(
        [
            "--home",
            str(boundkeep_home),
            "policy",
            "prompt",
            "deny sending plain-value-of-the-token-42 anywhere",
        ]
    )
    assert code == 1
    assert "secret environment variable" in capsys.readouterr().err
    assert json is not None
    assert FakeBackend is not None
