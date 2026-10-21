"""M1c-2: a dev tool that runs repository code is gray when the same line wrote what it loads."""

from __future__ import annotations

import sys

import pytest

from boundkeep import policycli
from boundkeep.policy import default_policy_text, parse_policy_text

GRAY = "exec-of-written-file"

BASH = [
    "echo x > conftest.py; pytest",
    "echo x > tests/conftest.py && pytest -q",
    "echo x > pytest.ini; pytest",
    "echo x > tox.ini; pytest",
    "echo x > setup.cfg; pytest",
    "echo x > pyproject.toml; pytest",
    "echo x > tests/test_a.py; pytest",
    "echo x > tests/a_test.py; pytest",
    "echo x > tests/TEST_B.PY; pytest",
    "echo x > conftest.py; python -m pytest",
    "echo x > mypy.ini; mypy src",
    "echo x > .mypy.ini; python -m mypy src",
    "echo x > setup.cfg; mypy src",
    "echo x > .pylintrc; pylint src",
    "echo x > pylintrc; python -m pylint src",
    "echo x > pyproject.toml; pylint src",
    "echo x > .flake8; flake8",
    "echo x > tox.ini; python -m flake8 src",
    "echo x > plugin.py; pytest plugin.py",
]
# A path-qualified interpreter after a write on the same line stays gray as a whole (the Bash
# normalizer refuses to trust the program path then); the reason is one of the two.
PATH_QUALIFIED = [
    "echo x > conftest.py; ./.venv/bin/python -m pytest -q",
    "echo x > tests/test_a.py; ./.venv/bin/pytest",
    "echo x > mypy.ini; ./.venv/bin/mypy src",
]
CONTROLS = [
    "echo x > notes.md; pytest",
    "echo x > README.md; mypy src",
    "echo x > src/app.py; ruff check .",
    "echo x > .gitignore; flake8",
    "echo x > data.json; pytest",
]
POWERSHELL = [
    "Set-Content conftest.py 'x'; pytest",
    "Set-Content tests\\test_a.py 'x'; python -m pytest",
    "Set-Content mypy.ini 'x'; mypy src",
    "Set-Content .pylintrc 'x'; pylint src",
    "Set-Content .flake8 'x'; flake8",
]


def _reasons(platform: str, tool: str, command: str) -> tuple[str, set[str]]:
    policy = parse_policy_text(default_policy_text(), home=policycli._FAKE[platform]["home"])
    result = policycli._run_one(policy, platform, tool, {"command": command}, None, None)
    return result.verdict.decision, {g for a in result.actions for g in a.gray_reasons}


@pytest.mark.parametrize("platform", ["posix", "windows"])
@pytest.mark.parametrize("command", BASH)
def test_a_loaded_file_written_on_the_same_line_makes_the_line_gray(
    platform: str, command: str
) -> None:
    decision, reasons = _reasons(platform, "Bash", command)
    assert decision != "allow", command
    assert GRAY in reasons, (command, reasons)


@pytest.mark.parametrize("platform", ["posix", "windows"])
@pytest.mark.parametrize("command", PATH_QUALIFIED)
def test_a_path_qualified_tool_after_a_write_is_gray(platform: str, command: str) -> None:
    decision, reasons = _reasons(platform, "Bash", command)
    assert decision != "allow", command
    assert reasons & {GRAY, "program-path-qualified"}, (command, reasons)


@pytest.mark.parametrize("platform", ["posix", "windows"])
@pytest.mark.parametrize("command", CONTROLS)
def test_an_unrelated_file_does_not_trigger_the_reason(platform: str, command: str) -> None:
    _decision, reasons = _reasons(platform, "Bash", command)
    assert GRAY not in reasons, (command, reasons)


@pytest.mark.skipif(sys.platform != "win32", reason="needs the real PowerShell parser helper")
@pytest.mark.parametrize("command", POWERSHELL)
def test_powershell_forms_are_gray_too(command: str) -> None:
    decision, reasons = _reasons("windows", "PowerShell", command)
    assert decision != "allow", command
    assert GRAY in reasons, (command, reasons)
