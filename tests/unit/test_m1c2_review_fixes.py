"""X1 review of M1c / M1c-2 (docs/reviews/M1c2-security-review.md), findings H-1 to H-4.

* H-1  ``@FILE`` (an argument file) in the arguments of a dev tool, in either dialect, any position;
* H-2  pylint ``--output-format=REPORTER:FILE`` and ``--output-format=module.Class``;
* H-3  ``NAME=value`` prefixes in front of a dev tool (Bash): only a short list of harmless names;
* H-4  PowerShell: an expanding value (``$env:TOKEN``) in the arguments of a cmdlet an allow rule
        covers is gray, except in a position the path layer judges.

Three layers: the classifiers (``programs.classify`` / ``psprograms.classify_ps``), the whole
pipeline with the default policy plus a trusted project (and as shipped, and strict), and the
rule files' own ``tests:``. No command is executed: they are only normalized.
"""

from __future__ import annotations

import sys
from functools import cache
from pathlib import Path
from typing import Any

import pytest
import yaml

from boundkeep import policycli
from boundkeep.normalize import programs, psprograms
from boundkeep.normalize.model import Word
from boundkeep.policy import Policy, parse_policy_text

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"
CORPUS = ROOT / "tests" / "corpus" / "pipeline_m1c2_trusted.yaml"
PLATFORMS = ("windows", "posix")
PLATFORM_IDS = [f"on-{p}" for p in PLATFORMS]  # conftest.py skips ids that are the bare words
TOOLS = tuple(sorted(programs.DEVTOOLS))
ARGFILE = programs.DEVTOOL_ARGFILE_GRAY
FORMAT = programs.DEVTOOL_OUTPUT_FORMAT_GRAY
ENV_PREFIX = programs.DEVTOOL_ENV_GRAY
DYNAMIC = psprograms.DYNAMIC_ARG_GRAY


# ---------------------------------------------------------------------------- helpers


@cache
def _policy(name: str, platform: str, trusted: bool) -> Policy:
    text = (POLICIES / f"{name}.yaml").read_text(encoding="utf-8")
    if trusted:
        block = f"trusted_projects:\n  - '{policycli._FAKE[platform]['project']}'\n"
        assert "\nrules:\n" in text
        text = text.replace("\nrules:\n", "\n" + block + "rules:\n", 1)
    return parse_policy_text(text, home=policycli._FAKE[platform]["home"])


@cache
def _ps_ready() -> bool:
    if sys.platform != "win32":
        return False
    from boundkeep.normalize import psparse

    psparse.warm_up(wait_s=15)
    return bool(psparse.status().get("state") == "ready")


def _decide(
    platform: str, tool: str, command: str, *, name: str = "default", trusted: bool = True
) -> str:
    if tool == "PowerShell" and not _ps_ready():
        pytest.skip("PowerShell entries need the real parser helper (Windows only)")
    result = policycli._run_one(
        _policy(name, platform, trusted),
        platform,  # type: ignore[arg-type]
        tool,
        {"command": command},
        None,
        None,
    )
    return str(result.verdict.decision)


def _words(*texts: str) -> list[Word]:
    return [Word(t) for t in texts]


def _bash(program: str, *texts: str, env: tuple[tuple[str, str], ...] = ()) -> Any:
    return programs.classify(  # noqa: S604 - "bash" is a dialect, not a subprocess option
        program, _words(*texts), shell="bash", env=[(k, Word(v)) for k, v in env]
    )


def _ps_dev(tool: str, *texts: str) -> Any:
    return psprograms.classify_ps(tool, _words(*texts))


def _ps_cmdlet(name: str, *words: Word) -> Any:
    return psprograms.classify_ps(name, list(words))


def _expanding(text: str) -> Word:
    return Word(text, expands=True)


# ---------------------------------------------------------------------------- H-1: @file


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize(
    "args",
    [
        ("@args.txt",),
        ("check", "@args.txt"),
        ("-q", "@args.txt", "tests"),
        ("-k", "@args.txt"),  # an option VALUE is expanded too
        ("--", "@args.txt"),
        ("@..\\..\\x.txt",),
        ("@/abs/x.txt",),
        ("@C:\\Users\\x\\a.txt",),
    ],
    ids=lambda a: "|".join(a),
)
def test_an_argument_file_makes_every_dev_tool_gray_in_both_dialects(
    tool: str, args: tuple[str, ...]
) -> None:
    assert ARGFILE in _bash(tool, *args).gray
    assert ARGFILE in _ps_dev(tool, *args).gray


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize(
    "args",
    [(), ("-q",), ("tests",), ("--version",), ("a@b.py",), ("@",), ("-k", "a and not b"), ("--",)],
    ids=lambda a: "|".join(a) or "no-args",
)
def test_ordinary_arguments_do_not_get_the_argument_file_reason(
    tool: str, args: tuple[str, ...]
) -> None:
    assert ARGFILE not in _bash(tool, *args).gray
    assert ARGFILE not in _ps_dev(tool, *args).gray


def test_the_reason_reaches_the_action_through_the_whole_normalizer() -> None:
    # (classify is only the last step: python -m, quoting and the PowerShell binder come first)
    for platform in PLATFORMS:
        result = policycli._run_one(
            _policy("default", platform, True),
            platform,  # type: ignore[arg-type]
            "Bash",
            {"command": "python -m pytest '@args.txt'"},
            None,
            None,
        )
        reasons = [r for a in result.verdict.actions for r in a.gray_reasons]
        assert ARGFILE in reasons, reasons


# ---------------------------------------------------------------------------- H-2: pylint format


@pytest.mark.parametrize(
    "args",
    [
        ("--output-format=text:/tmp/x",),
        ("--output-format", "json:/tmp/x"),
        ("--output-format=json:out.json,colorized",),
        ("--output-format=text:C:\\Users\\x\\.bashrc", "src"),
        ("--output-format=evil.Reporter", "src"),
        ("--output-format=pkg.mod.Class",),
        ("--output-format=",),
        ("--output-format=Text",),  # unknown: case matters to pylint
        ("--output-format=text,evil.R",),
        ("--output-format=text;json",),
        ("--output-format=text ",),
        ("--output-format=nothing-i-know",),
        ("--output-form=text:/tmp/x",),  # unique abbreviation
        ("--output-f", "text:/tmp/x"),
        ("-f", "text:/tmp/x"),
        ("-ftext:/tmp/x",),
        ("-f=evil.R",),
    ],
    ids=lambda a: "|".join(a),
)
def test_pylint_output_format_with_a_file_or_a_class_is_gray(args: tuple[str, ...]) -> None:
    assert FORMAT in _bash("pylint", *args).gray
    assert FORMAT in _ps_dev("pylint", *args).gray


@pytest.mark.parametrize(
    "args",
    [
        ("--output-format=text",),
        ("--output-format", "json"),
        ("--output-format=json2", "src"),
        ("--output-format=parseable",),
        ("--output-format=colorized",),
        ("--output-format=msvs",),
        ("--output-format=github",),
        ("--output-format=text,json",),
        ("-f", "json"),
        ("-fjson",),
        ("--msg-template={path}:{line}", "src"),
        ("--disable=all", "src"),
    ],
    ids=lambda a: "|".join(a),
)
def test_pylint_built_in_reporters_stay_understood(args: tuple[str, ...]) -> None:
    assert FORMAT not in _bash("pylint", *args).gray
    assert FORMAT not in _ps_dev("pylint", *args).gray


@pytest.mark.parametrize("tool", [t for t in TOOLS if t != "pylint"])
def test_the_output_format_check_is_pylints_alone(tool: str) -> None:
    # ruff --output-format takes a fixed list of names, mypy --output a format name: no file there
    assert FORMAT not in _bash(tool, "--output-format=github").gray
    assert FORMAT not in _ps_dev(tool, "--output-format=github").gray


# ---------------------------------------------------------------------------- H-3: env prefix


UNSAFE_ENV = [
    "RUFF_OUTPUT_FILE",
    "RUFF_CACHE_DIR",
    "COVERAGE_FILE",
    "COVERAGE_RCFILE",
    "COVERAGE_PROCESS_START",
    "PYTEST_DEBUG_TEMPROOT",
    "PYTHONPYCACHEPREFIX",
    "MYPY_CACHE_DIR",
    "BLACK_CACHE_DIR",
    "XDG_CACHE_HOME",
    "PYTHONEXECUTABLE",
    "PYTHONDEVMODE",
    "PYTHONINSPECT",
    "PYTHONSAFEPATH",
    "TMPDIR",
    "TEMP",
    "HOME",
    "FOO",
    "ruff_output_file",  # names are case-insensitive for the check
    "PYTEST_ADDOPTS",  # already code-injection: still not understood
    "PYTHONPATH",
]
SAFE_ENV = [
    "CI",
    "NO_COLOR",
    "FORCE_COLOR",
    "CLICOLOR",
    "TERM",
    "COLUMNS",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "PYTHONHASHSEED",
    "PYTHONUTF8",
    "PYTHONIOENCODING",
    "PYTHONUNBUFFERED",
    "PYTHONDONTWRITEBYTECODE",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
    "ci",
]


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("name", UNSAFE_ENV)
def test_an_unlisted_environment_prefix_makes_a_dev_tool_gray(tool: str, name: str) -> None:
    info = _bash(tool, "-q", env=((name, "/home/testuser/.bashrc"),))
    assert any(r.startswith(ENV_PREFIX) for r in info.gray), info.gray


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("name", SAFE_ENV)
def test_a_listed_environment_prefix_leaves_a_dev_tool_understood(tool: str, name: str) -> None:
    info = _bash(tool, "-q", env=((name, "1"),))
    assert not any(r.startswith(ENV_PREFIX) for r in info.gray), info.gray


def test_the_environment_check_is_not_applied_to_other_programs() -> None:
    info = _bash("ls", env=(("FOO", "1"),))
    assert not any(r.startswith(ENV_PREFIX) for r in info.gray)


def test_one_unlisted_name_is_enough() -> None:
    info = _bash("pytest", "-q", env=(("CI", "1"), ("RUFF_OUTPUT_FILE", "/x")))
    assert [r for r in info.gray if r.startswith(ENV_PREFIX)] == [f"{ENV_PREFIX}:RUFF_OUTPUT_FILE"]


def test_the_safe_list_has_no_name_that_moves_output_or_caches() -> None:
    for name in ("python_colors", "pytest_disable_plugin_autoload", "lc_all"):
        assert programs.devtool_env_is_safe(name)
    for bad in (
        "RUFF_OUTPUT_FILE",
        "COVERAGE_FILE",
        "PYTHONPYCACHEPREFIX",
        "XDG_CACHE_HOME",
        "TMPDIR",
        "HOME",
        "PYTHONPATH",
    ):
        assert not programs.devtool_env_is_safe(bad)


# ---------------------------------------------------------------------------- H-4: PowerShell


NOPATH_CMDLETS = [
    "ConvertTo-Json",
    "ConvertFrom-Json",
    "Select-Object",
    "Where-Object",
    "Sort-Object",
    "Group-Object",
    "Format-Table",
    "Format-List",
    "Out-String",
    "Out-Null",
    "Measure-Object",
    "Get-Date",
    "Get-Location",
]
EXPANDING = [
    "$env:SECRET_TOKEN",
    '"$env:SECRET_TOKEN"',
    "${env:SECRET_TOKEN}",
    "$global:SECRET",
    "$x",
]


@pytest.mark.parametrize("cmdlet", NOPATH_CMDLETS)
@pytest.mark.parametrize("text", EXPANDING)
def test_an_expanding_argument_of_a_no_path_cmdlet_is_gray(cmdlet: str, text: str) -> None:
    assert DYNAMIC in _ps_cmdlet(cmdlet, _expanding(text)).gray  # positional
    assert DYNAMIC in _ps_cmdlet(cmdlet, Word("-Property"), _expanding(text)).gray  # a value
    assert DYNAMIC in _ps_cmdlet(cmdlet, Word("-Depth"), Word("1"), _expanding(text)).gray


@pytest.mark.parametrize("cmdlet", NOPATH_CMDLETS)
def test_constants_and_the_boolean_literals_stay_understood(cmdlet: str) -> None:
    assert DYNAMIC not in _ps_cmdlet(cmdlet).gray
    assert DYNAMIC not in _ps_cmdlet(cmdlet, Word("-Property"), Word("Name")).gray
    assert DYNAMIC not in _ps_cmdlet(cmdlet, Word("Name", quoted=True)).gray
    assert DYNAMIC not in _ps_cmdlet(cmdlet, Word("-AutoSize"), _expanding("$true")).gray
    assert DYNAMIC not in _ps_cmdlet(cmdlet, Word("-Compress"), _expanding("$False")).gray
    assert DYNAMIC not in _ps_cmdlet(cmdlet, Word("-X"), _expanding("$null")).gray


READ_CMDLETS = [
    "Get-Content",
    "Select-String",
    "Test-Path",
    "Get-Item",
    "Resolve-Path",
    "Get-ChildItem",
]


@pytest.mark.parametrize("cmdlet", READ_CMDLETS)
def test_a_non_path_value_that_expands_is_gray_for_the_read_cmdlets(cmdlet: str) -> None:
    for param in (
        "-TotalCount",
        "-Tail",
        "-Encoding",
        "-Depth",
        "-Include",
        "-Filter",
        "-PathType",
    ):
        info = _ps_cmdlet(cmdlet, Word("a.txt"), Word(param), _expanding("$env:SECRET_TOKEN"))
        # (a parameter this cmdlet does not have makes its value a loose, unknown-access path:
        # either way the allow rules, which need every path read-only, do not match)
        assert DYNAMIC in info.gray or any(a != "read" for _w, a in info.paths), param


def test_a_path_that_expands_is_still_the_path_layers_business() -> None:
    # $HOME\a.txt as the PATH of Get-Content is judged by the path rules, not by this reason
    for cmdlet in ("Get-Content", "Get-Item", "Test-Path", "Resolve-Path", "Get-ChildItem"):
        info = _ps_cmdlet(cmdlet, _expanding("$HOME\\a.txt"))
        assert DYNAMIC not in info.gray, cmdlet


# The commands of the review, through the whole pipeline: never allow, whatever the project says.
H1_COMMANDS = [
    ("PowerShell", "pytest '@args.txt'"),
    ("PowerShell", 'mypy "@args.txt"'),
    ("PowerShell", "ruff check '@args.txt'"),
    ("PowerShell", "ruff check `@args.txt"),
    ("PowerShell", "python -m pytest '@args.txt'"),
    ("PowerShell", ".\\.venv\\Scripts\\ruff.exe check '@args.txt'"),
    ("PowerShell", "pytest --foo '@args.txt'"),
    ("PowerShell", "ruff check -- '@args.txt'"),
    ("PowerShell", "pytest -k '@args.txt'"),
    ("PowerShell", "pytest '@C:\\Users\\testuser\\x.txt'"),
    ("PowerShell", "black '@args.txt'"),
    ("PowerShell", "isort '@args.txt'"),
    ("PowerShell", "flake8 '@args.txt'"),
    ("PowerShell", "pylint '@args.txt'"),
    ("Bash", "ruff check @args.txt"),
    ("Bash", "ruff check -- @args.txt"),
    ("Bash", "ruff check @../../x.txt"),
    ("Bash", "ruff check @/home/testuser/x.txt"),
    ("Bash", "ruff @args.txt"),
    ("Bash", "python -m ruff check @args.txt"),
    ("Bash", "black @args.txt"),
    ("Bash", "pytest @args.txt"),
    ("Bash", "mypy @args.txt"),
    ("Bash", "pytest -k @args.txt"),
    ("Bash", "pylint '@args.txt'"),
]
H2_COMMANDS = [
    ("PowerShell", "pylint --output-format=text:C:\\Users\\testuser\\.boundkeep\\policy.yaml src"),
    ("PowerShell", "pylint --output-format=text:..\\..\\x src"),
    ("PowerShell", "pylint --msg-template='x' --output-format=text:..\\x src"),
    ("PowerShell", "pylint --output-format 'text:C:\\x.txt' src"),
    ("PowerShell", "pylint -f text:x src"),
    ("PowerShell", "pylint --output-format=evil.Reporter src"),
    ("Bash", "pylint --msg-template='x' --output-format=text:/home/testuser/.bashrc src"),
    ("Bash", "pylint --output-format=json:out.json src"),
    ("Bash", "pylint --output-format=evil.Reporter src"),
    ("Bash", "python -m pylint --output-format=text:/tmp/x src"),
    ("Bash", "pylint -f text:/tmp/x src"),
]
H3_COMMANDS = [
    ("Bash", "RUFF_OUTPUT_FILE=/home/testuser/.bashrc ruff check ."),
    ("Bash", "COVERAGE_FILE=/home/testuser/.bashrc pytest --cov"),
    ("Bash", "PYTHONPYCACHEPREFIX=/home/testuser/x pytest"),
    ("Bash", "RUFF_CACHE_DIR=/home/testuser/.ssh ruff check ."),
    ("Bash", "MYPY_CACHE_DIR=/home/testuser/x mypy src"),
    ("Bash", "BLACK_CACHE_DIR=/home/testuser/x black ."),
    ("Bash", "XDG_CACHE_HOME=/tmp/x ruff check ."),
    ("Bash", "PYTEST_DEBUG_TEMPROOT=/home/testuser/x pytest"),
    ("Bash", "COVERAGE_PROCESS_START=/home/testuser/x pytest"),
    ("Bash", "COVERAGE_RCFILE=/home/testuser/x pytest --cov"),
    ("Bash", "PYTHONEXECUTABLE=/x pytest"),
    ("Bash", "TMPDIR=/home/testuser/x pytest"),
    ("Bash", "FOO=1 pytest"),
    ("Bash", "CI=1 FOO=1 pytest -q"),
    ("Bash", "CI=1 RUFF_OUTPUT_FILE=/x ruff check ."),
    ("Bash", "FOO=1 python -m pytest"),
    ("Bash", "FOO=1 ./.venv/bin/pytest"),
]
H4_COMMANDS = [
    ("PowerShell", "ConvertTo-Json $env:SECRET_TOKEN"),
    ("PowerShell", 'ConvertTo-Json "$env:SECRET_TOKEN"'),
    ("PowerShell", "ConvertTo-Json ${env:SECRET_TOKEN}"),
    ("PowerShell", "ConvertTo-Json $global:SECRET"),
    ("PowerShell", "ConvertTo-Json -Compress $env:SECRET_TOKEN"),
    ("PowerShell", "ConvertTo-Json $env:SECRET_TOKEN -Depth 1"),
    ("PowerShell", "ConvertFrom-Json $env:SECRET_TOKEN"),
    ("PowerShell", "Get-ChildItem | ConvertTo-Json $env:SECRET_TOKEN"),
    ("PowerShell", "Get-ChildItem | Select-Object -Property $env:SECRET_TOKEN"),
    ("PowerShell", "Get-ChildItem | Select-Object $env:SECRET_TOKEN"),
    ("PowerShell", "Get-ChildItem | Select-Object -ExpandProperty $env:SECRET_TOKEN"),
    ("PowerShell", "Get-ChildItem | Select-Object -First $env:SECRET_TOKEN"),
    ("PowerShell", "Get-ChildItem | Format-Table $env:SECRET_TOKEN"),
    ("PowerShell", "Get-ChildItem | Format-List -Property $env:SECRET_TOKEN"),
    ("PowerShell", "Get-ChildItem | Sort-Object $env:SECRET_TOKEN"),
    ("PowerShell", "Get-ChildItem | Group-Object $env:SECRET_TOKEN"),
    ("PowerShell", "Get-ChildItem | Where-Object Name -eq $env:SECRET_TOKEN"),
    ("PowerShell", "Get-ChildItem | Out-String -Width $env:SECRET_TOKEN"),
    ("PowerShell", 'Get-ChildItem | Out-String -Width "$env:SECRET_TOKEN"'),
    ("PowerShell", "Out-String $env:SECRET_TOKEN"),
    ("PowerShell", "Measure-Object -Property $env:SECRET_TOKEN"),
    ("PowerShell", "Get-ChildItem | Measure-Object $env:SECRET_TOKEN"),
    ("PowerShell", "Get-Date $env:SECRET_TOKEN"),
    ("PowerShell", "Get-Location $env:SECRET_TOKEN"),
    ("PowerShell", "'x' | Select-Object -Property $env:SECRET_TOKEN"),
    ("PowerShell", "Get-Content a.txt -TotalCount $env:SECRET_TOKEN"),
    ("PowerShell", "Get-Content a.txt -Tail $env:SECRET_TOKEN"),
    ("PowerShell", "Get-ChildItem -Depth $env:SECRET_TOKEN"),
    ("PowerShell", "Get-ChildItem -Filter $env:SECRET_TOKEN"),
    ("PowerShell", "Get-ChildItem -Include $env:SECRET_TOKEN"),
    ("PowerShell", "Select-String -Pattern $env:SECRET_TOKEN a.txt"),
    ("PowerShell", "Select-String x a.txt -Context $env:SECRET_TOKEN"),
    ("PowerShell", "Test-Path a.txt -PathType $env:SECRET_TOKEN"),
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    ("tool", "command"),
    [*H1_COMMANDS, *H2_COMMANDS, *H3_COMMANDS],
    ids=lambda v: str(v)[:70],
)
def test_the_reviewed_dev_tool_commands_are_never_allow(
    platform: str, tool: str, command: str
) -> None:
    if tool == "PowerShell" and platform != "windows":
        pytest.skip("PowerShell runs on the Windows fake machine")
    assert _decide(platform, tool, command, trusted=True) != "allow", command
    assert _decide(platform, tool, command, trusted=False) != "allow", command
    assert _decide(platform, tool, command, name="strict", trusted=True) != "allow", command


@pytest.mark.parametrize(("tool", "command"), H4_COMMANDS, ids=lambda v: str(v)[:70])
def test_the_reviewed_powershell_commands_are_gray_with_or_without_trust(
    tool: str, command: str
) -> None:
    for trusted in (False, True):
        assert _decide("windows", tool, command, trusted=trusted) in ("gray", "ask"), command
    assert _decide("windows", tool, command, name="strict", trusted=True) in ("gray", "ask")


# What must keep working, so that the fixes are not a blanket gray.
STILL_ALLOWED_TRUSTED = [
    ("Bash", "pytest -q"),
    ("Bash", "python -m pytest -q tests"),
    ("Bash", "ruff check ."),
    ("Bash", "mypy src"),
    ("Bash", "pylint src"),
    ("Bash", "pylint --output-format=json src"),
    ("Bash", "pylint --output-format=text,json src"),
    ("Bash", "pylint -f colorized src"),
    ("Bash", "pylint --msg-template='{path}:{line}' src"),
    ("Bash", "CI=1 pytest -q"),
    ("Bash", "NO_COLOR=1 ruff check ."),
    ("Bash", "PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 pytest"),
    ("Bash", "LC_ALL=C.UTF-8 pytest"),
    ("Bash", "pytest tests/test_a.py::T::test_b a@b.py"),
    ("Bash", "pytest -k 'alpha and not beta'"),
    ("PowerShell", "pytest -q"),
    ("PowerShell", "python -m pytest -q"),
    ("PowerShell", "ruff check ."),
    ("PowerShell", "pylint --output-format=json src"),
    ("PowerShell", "pylint -f parseable src"),
    ("PowerShell", "mypy src"),
]
STILL_ALLOWED_ALWAYS = [
    ("PowerShell", "Get-ChildItem | Select-Object -First 5"),
    ("PowerShell", "Get-ChildItem | Sort-Object Length"),
    ("PowerShell", "Get-ChildItem | Sort-Object -Property Length -Descending"),
    ("PowerShell", "Get-ChildItem | Format-Table Name, Length"),
    ("PowerShell", "Get-ChildItem | Format-List *"),
    ("PowerShell", "Get-ChildItem | Group-Object Extension"),
    ("PowerShell", "Get-ChildItem | Where-Object Name -like '*.py'"),
    ("PowerShell", "Get-ChildItem | Out-String"),
    ("PowerShell", "Get-ChildItem | Measure-Object"),
    ("PowerShell", "Get-Content a.txt | Measure-Object -Line -Word"),
    ("PowerShell", "Get-Content a.json | ConvertFrom-Json | ConvertTo-Json -Depth 3"),
    ("PowerShell", "Get-Content a.json | ConvertFrom-Json | Select-Object name"),
    ("PowerShell", "Get-Content a.txt -Tail 5"),
    ("PowerShell", "Get-Content a.txt -TotalCount 20"),
    ("PowerShell", "Get-ChildItem tests | Select-Object -First 5"),
    ("PowerShell", "Get-ChildItem -Recurse -Filter test_*.py | Measure-Object"),
    ("PowerShell", "Get-ChildItem -Depth 2"),
    ("PowerShell", "Select-String -Pattern TODO -Path a.txt"),
    ("PowerShell", "Test-Path a.txt"),
    ("PowerShell", "Get-Date"),
    ("PowerShell", "Get-Location"),
    ("PowerShell", "Get-Content $HOME\\..\\proj\\a.txt"),
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("tool", "command"), STILL_ALLOWED_TRUSTED, ids=lambda v: str(v)[:70])
def test_the_ordinary_dev_tool_forms_are_still_allowed_in_a_trusted_project(
    platform: str, tool: str, command: str
) -> None:
    if tool == "PowerShell" and platform != "windows":
        pytest.skip("PowerShell runs on the Windows fake machine")
    assert _decide(platform, tool, command, trusted=True) == "allow", command
    assert _decide(platform, tool, command, trusted=False) != "allow", command  # needs trust


@pytest.mark.parametrize(("tool", "command"), STILL_ALLOWED_ALWAYS, ids=lambda v: str(v)[:70])
def test_the_ordinary_read_and_shaping_commands_are_still_allowed(tool: str, command: str) -> None:
    for trusted in (False, True):
        got = _decide("windows", tool, command, trusted=trusted)
        # $HOME\..\proj\a.txt is outside or inside depending on the fake home: allow or ask, but
        # never the new reason (the last entry only checks that a path expansion is not gray)
        if "$HOME" in command:
            assert got in ("allow", "ask", "gray")
        else:
            assert got == "allow", command


# ---------------------------------------------------------------------------- rule files and corpus


def _rule_tests(name: str) -> list[dict[str, Any]]:
    data = yaml.safe_load((POLICIES / f"{name}.yaml").read_text(encoding="utf-8"))
    return list(data["tests"])


def test_the_default_policys_own_tests_cover_the_powershell_findings() -> None:
    commands = {t["input"]["command"] for t in _rule_tests("default") if t["tool"] == "PowerShell"}
    for command in (
        "ConvertTo-Json $env:SECRET_TOKEN",
        "Get-ChildItem | Select-Object -Property $env:SECRET_TOKEN",
        "Measure-Object -Property $env:SECRET_TOKEN",
        "Get-Date $env:SECRET_TOKEN",
        "Get-Content a.txt -TotalCount $env:SECRET_TOKEN",
    ):
        assert command in commands, command
    by_command = {
        t["input"]["command"]: t for t in _rule_tests("default") if t["tool"] == "PowerShell"
    }
    assert by_command["ConvertTo-Json $env:SECRET_TOKEN"]["expect"] == "gray"
    assert by_command["Get-ChildItem | Select-Object -First 5"]["expect"] == "allow"


def test_the_trusted_corpus_has_the_adversarial_entries_of_the_review() -> None:
    entries = yaml.safe_load(CORPUS.read_text(encoding="utf-8"))
    ids = {e["id"] for e in entries}
    review = {e["id"] for e in entries if e["id"].startswith("m2r-")}
    assert len(review) >= 80
    assert all(e.get("adv") and e.get("trusted") for e in entries if e["id"].startswith("m2r-"))
    assert {"m2r-h1-ps-pytest-quoted", "m2r-h2-ps-pylint-policy", "m2r-h3-bash-ruff-output"} <= ids
    for e in entries:
        if e["id"].startswith("m2r-"):
            assert e["expect"] in ("gray", "ask", "deny"), e["id"]


def test_the_docs_name_the_new_gray_reasons() -> None:
    text = (ROOT / "docs" / "policy-reference.md").read_text(encoding="utf-8")
    for reason in (ARGFILE, FORMAT, ENV_PREFIX, DYNAMIC):
        assert reason in text, reason
