"""X1 re-review of the fixes (docs/reviews/M1c2-fixes-rereview.md): R-1 to R-9 and the low findings.

Batch 1  R-2  a switch's colon value (``-Stream:$env:TOKEN``) is no longer dropped without a trace;
         R-3  the subtree scan of a recursive read looks at the link count of the files it reads.
Batch 2  R-1/R-4  an allow rule never rides a non-path word that expands or globs.
Batch 3  R-5, R-6, R-8, R-9 and the low findings.

No command is executed: they are only normalized.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

from boundkeep.daemon import pipeline
from boundkeep.normalize import subtree
from boundkeep.policy import default_policy_text, parse_policy_text
from tests.unit.test_m1c2_review_fixes import _decide

PLATFORMS = ("windows", "posix")
PLATFORM_IDS = [f"on-{p}" for p in PLATFORMS]  # conftest.py skips ids that are the bare words


# ---------------------------------------------------------------------------- R-2: switch values

# every PowerShell program an allow rule covers, with the switches it takes (as the review listed)
SWITCH_CASES = [
    ("Out-String", "-Stream"),
    ("ConvertTo-Json", "-Compress"),
    ("ConvertFrom-Json", "-AsHashtable"),
    ("Select-Object", "-Unique"),
    ("Select-Object", "-Last:1 -Wait"),
    ("Sort-Object", "-Descending"),
    ("Sort-Object", "-Unique"),
    ("Format-Table", "-AutoSize"),
    ("Format-Table", "-Wrap"),
    ("Format-List", "-Force"),
    ("Group-Object", "-NoElement"),
    ("Where-Object", "-Not"),
    ("Measure-Object", "-Line"),
    ("Measure-Object", "-Sum"),
    ("Get-Location", "-Stack"),
    ("Get-Date", "-AsUTC"),
    ("Get-Content a.txt", "-Raw"),
    ("Get-Content a.txt", "-Wait"),
    ("Get-Content a.txt", "-Force"),
    ("Get-Content a.txt", "-Verbose"),
    ("Get-Content a.txt", "-Debug"),
    ("Select-String x a.txt", "-Quiet"),
    ("Select-String x a.txt", "-CaseSensitive"),
    ("Select-String x a.txt", "-SimpleMatch"),
    ("Test-Path a.txt", "-IsValid"),
    ("Get-Item a.txt", "-Force"),
    ("Resolve-Path a.txt", "-Relative"),
    ("Get-ChildItem", "-Recurse"),
    ("Get-ChildItem", "-Force"),
    ("Get-ChildItem", "-Name"),
    ("Get-ChildItem", "-File"),
    ("Get-ChildItem", "-Directory"),
    ("Get-ChildItem", "-Hidden"),
    ("Set-Location .", "-PassThru"),
    ("Push-Location .", "-PassThru"),
]
EXPANDING_VALUES = [
    "$env:SECRET_TOKEN",
    '"$env:SECRET_TOKEN"',
    "${env:SECRET_TOKEN}",
    "$x",
    "$global:S",
]


@pytest.mark.parametrize(("head", "switch"), SWITCH_CASES, ids=lambda v: str(v)[:40])
@pytest.mark.parametrize("value", EXPANDING_VALUES)
def test_a_switchs_colon_value_that_expands_is_gray(head: str, switch: str, value: str) -> None:
    flag = switch.split()[-1] if " " in switch else switch
    command = f"{head} {flag}:{value}"
    for trusted in (False, True):
        assert _decide("windows", "PowerShell", command, trusted=trusted) in (
            "gray",
            "ask",
        ), command


# (PowerShell 7 only, or needing a property: gray for other reasons, so not a boolean-literal case)
NOT_IN_5_1 = {"-AsHashtable", "-AsUTC", "-Not"}


@pytest.mark.parametrize(
    ("head", "switch"),
    [c for c in SWITCH_CASES if c[1] not in NOT_IN_5_1],
    ids=lambda v: str(v)[:40],
)
@pytest.mark.parametrize("value", ["$true", "$false", "$True", "$null"])
def test_a_switchs_boolean_literal_is_still_understood(head: str, switch: str, value: str) -> None:
    flag = switch.split()[-1] if " " in switch else switch
    command = f"{head} {flag}:{value}"
    assert _decide("windows", "PowerShell", command) == "allow", command


def test_the_reason_is_named() -> None:
    from boundkeep.policy import default_policy_text as _  # noqa: F401 - the text is not needed

    result = _run_ps("Out-String -Stream:$env:SECRET_TOKEN")
    reasons = [r for a in result.verdict.actions for r in a.gray_reasons]
    assert "ps-switch-value" in reasons, reasons


def _run_ps(command: str) -> Any:
    from boundkeep import policycli
    from tests.unit.test_m1c2_review_fixes import _ps_ready

    if not _ps_ready():
        pytest.skip("PowerShell entries need the real parser helper (Windows only)")
    policy = parse_policy_text(default_policy_text(), home=policycli._FAKE["windows"]["home"])
    return policycli._run_one(policy, "windows", "PowerShell", {"command": command}, None, None)


# ---------------------------------------------------------------------------- R-3: subtree scan


def _link_or_skip(target: Path, link: Path) -> None:
    try:
        os.link(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("this file system has no hard links")


@pytest.fixture
def disk(tmp_path: Path) -> dict[str, Path]:
    home = tmp_path / "home"
    project = tmp_path / "proj"
    (home / ".ssh").mkdir(parents=True)
    (project / "sub").mkdir(parents=True)
    secret = home / ".ssh" / "id_rsa"
    secret.write_text("-----BEGIN INERT TEST KEY-----\n", encoding="utf-8")
    (project / "readme.md").write_text("hello\n", encoding="utf-8")
    (project / "sub" / "app.py").write_text("print(1)\n", encoding="utf-8")
    return {"home": home, "project": project, "secret": secret}


def _scan(root: Path, **kw: Any) -> subtree.ScanResult:
    key = str(root).replace("\\", "/").casefold() if sys.platform == "win32" else str(root)
    return subtree.scan(
        str(root),
        [key],
        windows=sys.platform == "win32",
        matcher=subtree.matcher_for(subtree.DEFAULT_PROTECTED_GLOBS),
        budget=subtree.ScanBudget(),
        **kw,
    )


def test_the_scan_reports_a_file_with_more_than_one_name(disk: dict[str, Path]) -> None:
    project = disk["project"]
    assert _scan(project).hard_links is False
    _link_or_skip(disk["secret"], project / "notes.txt")
    assert _scan(project).hard_links is True
    (project / "notes.txt").unlink()
    assert _scan(project).hard_links is False


def test_a_hard_link_deep_in_the_tree_and_with_a_plain_name_is_found(disk: dict[str, Path]) -> None:
    project = disk["project"]
    deep = project / "a" / "b" / "c"
    deep.mkdir(parents=True)
    _link_or_skip(disk["secret"], deep / "readme.md")
    assert _scan(project).hard_links is True


def test_directories_and_single_files_are_not_hard_links(disk: dict[str, Path]) -> None:
    project = disk["project"]
    (project / "empty").mkdir()
    assert _scan(project).hard_links is False


def test_a_file_the_command_does_not_read_is_not_looked_at(disk: dict[str, Path]) -> None:
    project = disk["project"]
    _link_or_skip(disk["secret"], project / "notes.txt")
    only_python = _scan(project, select=lambda rel, name: name.endswith(".py"))
    assert only_python.hard_links is False  # a Grep glob that cannot reach it
    everything = _scan(project, select=lambda rel, name: True)
    assert everything.hard_links is True


def test_skipped_names_are_not_looked_at(disk: dict[str, Path]) -> None:
    project = disk["project"]
    (project / ".git").mkdir()
    _link_or_skip(disk["secret"], project / ".git" / "packed-refs")
    assert _scan(project, skip_names=subtree.VCS_DIR_NAMES).hard_links is False
    assert _scan(project).hard_links is True


def _review(disk: dict[str, Path], tool: str, tool_input: dict[str, Any]) -> Any:
    home = str(disk["home"])
    policy = parse_policy_text(default_policy_text(), home=home)
    env = {k: v for k, v in os.environ.items() if k.upper() in ("SYSTEMROOT", "PATH", "TEMP")}
    env["USERPROFILE"] = env["HOME"] = home
    runtime, _problem = pipeline.runtime_policy_checked(policy, env, home)
    payload = {
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": str(disk["project"]),
        "project_dir": str(disk["project"]),
        "session_id": "s",
    }
    return pipeline.review(payload, runtime, platform=pipeline.local_platform(), env=env, home=home)


def _reasons(result: Any) -> list[str]:
    return [r for a in result.verdict.actions for r in a.gray_reasons]


DIRECTORY_READS = [
    ("Grep", {"pattern": "BEGIN"}),
    ("Grep", {"pattern": "BEGIN", "output_mode": "content"}),
    ("Grep", {"pattern": "BEGIN", "path": "."}),
    ("Bash", {"command": "grep -rn BEGIN ."}),
    ("Bash", {"command": "grep -r BEGIN"}),
    ("Bash", {"command": "rg BEGIN"}),
    ("Bash", {"command": "rg -n BEGIN sub"}),
]


@pytest.mark.parametrize(("tool", "inp"), DIRECTORY_READS, ids=lambda v: str(v)[:50])
def test_a_directory_read_over_a_hard_link_is_no_longer_allow(
    disk: dict[str, Path], tool: str, inp: dict[str, Any]
) -> None:
    project = disk["project"]
    if tool == "Bash" and "sub" in inp["command"]:
        _link_or_skip(disk["secret"], project / "sub" / "readme.md")
    else:
        _link_or_skip(disk["secret"], project / "notes.txt")
    got = _review(disk, tool, inp)
    assert got.verdict.decision != "allow", (tool, inp, got.verdict.decision)
    assert "recursive-scan-hardlink" in _reasons(got)


@pytest.mark.parametrize(("tool", "inp"), DIRECTORY_READS, ids=lambda v: str(v)[:50])
def test_the_same_directory_reads_without_a_hard_link_are_still_allow(
    disk: dict[str, Path], tool: str, inp: dict[str, Any]
) -> None:
    got = _review(disk, tool, inp)
    assert got.verdict.decision == "allow", (tool, inp, got.verdict.decision, _reasons(got))


def test_a_hard_link_that_is_removed_stops_mattering(disk: dict[str, Path]) -> None:
    link = disk["project"] / "notes.txt"
    _link_or_skip(disk["secret"], link)
    assert _review(disk, "Grep", {"pattern": "x"}).verdict.decision != "allow"
    link.unlink()
    assert _review(disk, "Grep", {"pattern": "x"}).verdict.decision == "allow"


def test_a_grep_glob_that_cannot_reach_the_link_is_unaffected(disk: dict[str, Path]) -> None:
    _link_or_skip(disk["secret"], disk["project"] / "notes.txt")
    got = _review(disk, "Grep", {"pattern": "x", "glob": "*.py"})
    assert got.verdict.decision == "allow", _reasons(got)


def test_the_scan_budget_leaves_room_for_the_link_count() -> None:
    # the link count costs about 5 us a file on Windows (os.stat): the time budget grew with it
    assert subtree.SCAN_TIME_BUDGET_S >= 0.3
    assert subtree.MAX_SCAN_ENTRIES == 30000


# ------------------------------------------------------------------------ R-1 / R-4: dynamic words


def _action(platform: str, tool: str, command: str) -> Any:
    from boundkeep import policycli
    from tests.unit.test_m1c2_review_fixes import _policy, _ps_ready

    if tool == "PowerShell" and not _ps_ready():
        pytest.skip("PowerShell entries need the real parser helper (Windows only)")
    result = policycli._run_one(
        _policy("default", platform, False),
        platform,  # type: ignore[arg-type]
        tool,
        {"command": command},
        None,
        None,
    )
    return result.actions[0]


# value words that expand (or glob) and are NOT paths: the review's R-1 and R-4 commands
DYNAMIC_VALUES = [
    ("Bash", 'pytest -k "${u}@args.txt"'),
    ("Bash", 'pytest -k "${X:-@args.txt}"'),
    ("Bash", "pytest -k $u@args.txt"),
    ("Bash", 'pytest -k "$0@a.txt"'),
    ("Bash", 'ruff check --select "${u}@args.txt" .'),
    ("Bash", "pytest -k ?args.txt"),
    ("Bash", "ruff check --select [@]r.txt ."),
    ("Bash", 'pylint --disable "${u}@x" src'),
    ("Bash", 'mypy --python-version "$u@x" src'),
    ("Bash", 'ruff check --select "$SECRET_TOKEN" .'),
    ("Bash", 'head -n "$SECRET_TOKEN" f'),
    ("Bash", "git log -n $SECRET_TOKEN"),
    ("PowerShell", 'pytest -k "$u@args.txt"'),
    ("PowerShell", "pytest -k $u@args.txt"),
    ("PowerShell", 'pytest -k "${env:NOSUCH}@a.txt"'),
    ("PowerShell", 'ruff check --select "$u@r.txt" .'),
    ("PowerShell", "ruff check --select $env:SECRET_TOKEN ."),
    ("PowerShell", "mypy --python-version $env:SECRET_TOKEN src"),
    ("PowerShell", "git log -n $env:SECRET_TOKEN"),
    ("PowerShell", "Select-String -Pattern $pattern src\\app.py"),
    ("PowerShell", "Get-Content a.txt -Tail $n"),
]
# the same commands with the dynamic word turned into a constant, and path words that expand
NOT_DYNAMIC = [
    ("Bash", "pytest -k 'not slow'"),
    ("Bash", "pytest -q tests"),
    ("Bash", "ruff check --select E501 ."),
    ("Bash", "git log -n 5"),
    ("Bash", "head -n 5 f"),
    ("Bash", 'cat "$HOME/a.txt"'),
    ("Bash", "ls $PWD"),
    ("Bash", 'ls "$PWD/src"'),
    ("Bash", "ls src/*.py"),
    ("Bash", "pytest tests/*.py"),
    ("PowerShell", "pytest -k 'not slow'"),
    ("PowerShell", "git log -n 5"),
    ("PowerShell", "Get-Content $HOME\\a.txt"),
    ("PowerShell", "Get-Content a.txt -Tail 5"),
    ("PowerShell", "Format-Table -AutoSize:$true"),
    ("PowerShell", "Get-ChildItem | Select-Object -First 5"),
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("tool", "command"), DYNAMIC_VALUES, ids=lambda v: str(v)[:60])
def test_a_non_path_word_that_expands_marks_the_action(
    platform: str, tool: str, command: str
) -> None:
    if tool == "PowerShell" and platform != "windows":
        pytest.skip("PowerShell runs on the Windows fake machine")
    assert _action(platform, tool, command).dynamic_args is True, command


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("tool", "command"), NOT_DYNAMIC, ids=lambda v: str(v)[:60])
def test_constants_and_path_words_do_not_mark_the_action(
    platform: str, tool: str, command: str
) -> None:
    if tool == "PowerShell" and platform != "windows":
        pytest.skip("PowerShell runs on the Windows fake machine")
    assert _action(platform, tool, command).dynamic_args is False, command


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("tool", "command"), DYNAMIC_VALUES, ids=lambda v: str(v)[:60])
def test_the_reviewed_commands_are_never_allow(platform: str, tool: str, command: str) -> None:
    if tool == "PowerShell" and platform != "windows":
        pytest.skip("PowerShell runs on the Windows fake machine")
    for name in ("default", "strict"):
        for trusted in (False, True):
            got = _decide(platform, tool, command, name=name, trusted=trusted)
            assert got != "allow", (name, trusted, command)


def test_deny_and_ask_rules_are_not_weakened_by_the_marker() -> None:
    # the marker only keeps ALLOW rules away: `cat $FILE`-like words are judged by the path rules
    for command in ("rm -rf $X", "git push --force origin main", "cat ~/.ssh/id_rsa $X"):
        assert _decide("posix", "Bash", command) in ("deny", "ask", "gray"), command
    assert _decide("posix", "Bash", "git push --force origin main") == "ask"
    assert _decide("posix", "Bash", "cat ~/.ssh/id_rsa $X") == "deny"


def test_a_glob_only_counts_for_a_dev_tool() -> None:
    # `grep -rn x --include=*.py .` has an unquoted glob in an option value: the shell passes it on
    # unchanged when nothing matches and no argument file is involved; a dev tool reads `@files`
    assert _action("posix", "Bash", "grep -rn x --include=*.py .").dynamic_args is False
    assert _action("posix", "Bash", "pytest -k test_*").dynamic_args is True


def test_the_marker_is_part_of_the_action_model() -> None:
    from boundkeep.normalize.model import Action

    assert Action.model_fields["dynamic_args"].default is False


# ---------------------------------------------------------------------------- batch 3


def _file_decision(platform: str, tool: str, path: str, *, name: str = "default") -> str:
    from boundkeep import policycli
    from tests.unit.test_m1c2_review_fixes import _policy

    inputs: dict[str, Any] = {
        "Write": {"file_path": path, "content": "x"},
        "Read": {"file_path": path},
    }
    result = policycli._run_one(
        _policy(name, platform, False),
        platform,  # type: ignore[arg-type]
        tool,
        inputs[tool],
        None,
        None,
    )
    return str(result.verdict.decision)


ENV_DIRS = [
    "venv/bin/pytest",
    "venv/pyvenv.cfg",
    "env/bin/pytest",
    ".tox/py312/bin/pytest",
    ".nox/tests/bin/python",
    ".conda/bin/pytest",
    ".pixi/envs/default/bin/pytest",
    ".direnv/python-3.12/bin/pytest",
    "__pypackages__/3.12/lib/x.py",
    "lib/python3.12/dist-packages/x.py",
    "sub/venv/Scripts/pytest.exe",
]


@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("path", ENV_DIRS)
def test_r5_writing_into_any_environment_directory_asks_or_is_refused(
    platform: str, name: str, path: str
) -> None:
    expected = "ask" if name == "default" else "deny"
    assert _file_decision(platform, "Write", path, name=name) == expected, path
    assert _file_decision(platform, "Read", path, name=name) == "allow"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    "path", ["environment/x.py", "venv_helpers/x.py", "src/envelope.py", "docs/envs.md"]
)
def test_r5_names_that_only_look_like_an_environment_are_the_projects_source(
    platform: str, path: str
) -> None:
    assert _file_decision(platform, "Write", path) == "allow"


PATH_QUALIFIED_ALLOWED = [
    ("Bash", "./venv/bin/pytest -q"),
    ("Bash", "./env/bin/python -m pytest"),
    ("Bash", ".tox/py312/bin/ruff check ."),
    ("Bash", "./.venv/bin/pytest -q"),
    ("PowerShell", ".\\venv\\Scripts\\pytest.exe -q"),
    ("PowerShell", ".\\.venv\\Scripts\\ruff.exe check ."),
    ("PowerShell", "& '.\\.venv\\Scripts\\python.exe' -m pytest"),
]
PATH_QUALIFIED_NOT_ALLOWED = [
    ("Bash", "./pytest -q"),
    ("Bash", "bin/pytest -q"),
    ("Bash", "tools/ruff check ."),
    ("Bash", "./pytest.exe"),
    ("Bash", "./scripts/python -m pytest"),
    ("Bash", "./venvx/bin/pytest -q"),
    ("PowerShell", ".\\pytest.exe -q"),
    ("PowerShell", ".\\tools\\ruff.exe check ."),
    ("PowerShell", "& '.\\bin\\python.exe' -m pytest"),
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("tool", "command"), PATH_QUALIFIED_ALLOWED, ids=lambda v: str(v)[:60])
def test_r5_a_dev_tool_in_an_environment_directory_is_still_allowed(
    platform: str, tool: str, command: str
) -> None:
    if tool == "PowerShell" and platform != "windows":
        pytest.skip("PowerShell runs on the Windows fake machine")
    assert _decide(platform, tool, command, trusted=True) == "allow", command


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("tool", "command"), PATH_QUALIFIED_NOT_ALLOWED, ids=lambda v: str(v)[:60])
def test_r5_a_path_qualified_dev_tool_elsewhere_in_the_project_is_not_allowed(
    platform: str, tool: str, command: str
) -> None:
    if tool == "PowerShell" and platform != "windows":
        pytest.skip("PowerShell runs on the Windows fake machine")
    for name in ("default", "strict"):
        assert _decide(platform, tool, command, name=name, trusted=True) != "allow", command
    marked = _action(platform, tool, command)
    assert "unvetted-exe" in marked.wrappers, (command, marked.wrappers)


def test_r5_the_environment_directory_names() -> None:
    from boundkeep.normalize import programs

    for text in (".venv/bin/x", "a/venv/bin/x", "C:\\p\\env\\Scripts\\x.exe", ".tox\\py\\x"):
        assert programs.devtool_exe_in_env(text), text
    for text in ("pytest", "./pytest", "bin/x", "venv", "tools/venv-like/x", "/usr/bin/python3"):
        assert not programs.devtool_exe_in_env(text), text  # (the last segment is the file itself)


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_r5_a_global_interpreter_is_still_asked_about(platform: str) -> None:
    command = (
        "/usr/bin/python3 -m pytest -q"
        if platform == "posix"
        else "C:/Python312/python.exe -m pytest -q"
    )
    assert _decide(platform, "Bash", command, trusted=True) in ("ask", "gray")


# R-8: pytest --debug names a file it truncates and writes
@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    "command",
    [
        "pytest --debug=conftest.py",
        "pytest --debug=.env",
        "pytest --debug=../x",
        "pytest --debug ../x",
        "pytest --debug=.git/config",
        "pytest --debug .claude/settings.json",
        "pytest --debu=conftest.py",
    ],
)
def test_r8_pytest_debug_is_a_written_path(platform: str, command: str) -> None:
    assert _decide(platform, "Bash", command, trusted=True) in ("ask", "deny"), command
    assert _decide(platform, "Bash", command, name="strict", trusted=True) in ("ask", "deny")


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_r8_a_plain_pytest_debug_and_a_log_inside_the_project_still_work(platform: str) -> None:
    assert _decide(platform, "Bash", "pytest --debug", trusted=True) == "allow"
    assert _decide(platform, "Bash", "pytest --debug=pytestdebug.log", trusted=True) == "allow"
    assert _decide(platform, "Bash", "pytest --debug=logs/dbg.txt -q", trusted=True) == "allow"


# R-11: pytest's own warning filter imports the category module
@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    "command",
    [
        "pytest -W error::evil.Cls",
        "pytest -Werror::evil.Cls",
        "pytest --pythonwarnings=error::pkg.Warn",
        "pytest -W ignore::a.b.C -q",
    ],
)
def test_r11_a_dotted_warning_category_is_gray(platform: str, command: str) -> None:
    assert _decide(platform, "Bash", command, trusted=True) != "allow", command


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    "command",
    ["pytest -W error", "pytest -W ignore::DeprecationWarning", "pytest -W error::UserWarning -q"],
)
def test_r11_plain_warning_filters_stay_allowed(platform: str, command: str) -> None:
    assert _decide(platform, "Bash", command, trusted=True) == "allow", command


# R-12: the harmless environment names carry harmless values
@pytest.mark.parametrize(
    ("name", "value", "ok"),
    [
        ("CI", "1", True),
        ("CI", "true", True),
        ("NO_COLOR", "", True),
        ("LC_ALL", "C.UTF-8", True),
        ("LANG", "en_US.UTF-8", True),
        ("TZ", "UTC", True),
        ("TZ", "America/New_York", True),
        ("PYTHONHASHSEED", "0", True),
        ("PYTHONIOENCODING", "utf-8", True),
        ("LC_ALL", "/home/x", False),
        ("LANG", "../../x", False),
        ("TZ", ":/home/testuser/.ssh/id_rsa", False),
        ("TZ", "../zoneinfo/x", False),
        ("LC_ALL", "C:\\x", False),
        ("LC_ALL", "a b", False),
        ("LC_ALL", "'x'", False),
        ("LC_ALL", "$X", False),
        ("TERM", "xterm;x", False),
        ("RUFF_OUTPUT_FILE", "x", False),
    ],
)
def test_r12_environment_values(name: str, value: str, ok: bool) -> None:
    from boundkeep.normalize import programs

    assert programs.devtool_env_is_safe(name, value) is ok


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_r12_a_path_valued_locale_makes_the_command_gray(platform: str) -> None:
    assert _decide(platform, "Bash", "LC_ALL=/home/testuser/x pytest", trusted=True) != "allow"
    assert _decide(platform, "Bash", "LC_ALL=C.UTF-8 pytest", trusted=True) == "allow"


# R-9: exact ids, so a user's rule named like a link rule keeps its protection
def test_r9_only_the_shipped_link_rules_are_left_out_of_the_protected_read_names() -> None:
    from boundkeep import policycli

    text = default_policy_text()
    extra = (
        "  - id: deny-link-vault-read\n    match:\n      path_glob: ['**/vault/**']\n"
        "      access: read\n    action: deny\n    reason: 'a vault'\n"
    )
    assert "\nrules:\n" in text
    text = text.replace("\nrules:\n", "\nrules:\n" + extra, 1)
    policy = parse_policy_text(text, home=policycli._FAKE["posix"]["home"])
    protected = pipeline.protected_read_globs(policy)
    assert "**/vault/**" in protected
    assert "**/.claude/settings*.json" not in protected
    assert "**/.boundkeep/**" in protected
    assert {"deny-link-to-guard-files", "deny-link-copy-of-guard-files"} <= pipeline.LINK_RULE_IDS
    assert "deny-link-vault-read" not in pipeline.LINK_RULE_IDS


def test_r9_the_runtime_twins_are_in_the_exact_set(tmp_path: Path) -> None:
    home = str(tmp_path / "home")
    policy = parse_policy_text(default_policy_text(), home=home)
    runtime, _problem = pipeline.runtime_policy_checked(
        policy, {"CLAUDE_CONFIG_DIR": str(tmp_path / "cfg")}, home
    )
    twins = {r.id for r in runtime.rules if r.id.startswith(pipeline.LINK_RULE_PREFIX)}
    assert twins <= pipeline.LINK_RULE_IDS
    assert len(twins) == 6


# R-14: more directories of keys and application data
def test_r14_more_guard_trees() -> None:
    from boundkeep.policy.schema import home_guard_tree_reason

    home = "c:/users/testuser"
    for name in (
        ".azure",
        ".password-store",
        ".cache",
        ".local",
        ".vscode",
        "library",
        ".terraform.d",
    ):
        assert home_guard_tree_reason(f"{home}/{name}/x", home) is not None, name
    assert home_guard_tree_reason(f"{home}/work/app", home) is None
    assert home_guard_tree_reason(f"{home}/cache-tools", home) is None


# R-7 and R-6 (daemon / trust) live in test_m1c2_trust_cli.py and the trust-links test file


def test_the_docs_name_the_new_reasons_and_markers() -> None:
    root = Path(__file__).resolve().parents[2]
    text = (root / "docs" / "policy-reference.md").read_text(encoding="utf-8")
    text += (root / "docs" / "powershell-dialect.md").read_text(encoding="utf-8")
    for word in (
        "dynamic_args",
        "ps-switch-value",
        "recursive-scan-hardlink",
        "devtool-warning-filter",
        "unvetted-exe",
        "trust remove",
    ):
        assert word in text, word
