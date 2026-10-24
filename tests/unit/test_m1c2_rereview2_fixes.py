"""X1 second re-review (docs/reviews/M1c2-fixes-rereview-2.md): R2-1 and R2-2.

R2-1  "this word was already taken as a path" is an exact test, not a text suffix, so
      ``"$u@a.txt=tests"`` next to a path word ``tests`` is still a word that expands.
R2-2  ``./venv/../pytest`` is ``./pytest``: ``..`` and ``.`` are collapsed before the environment
      directory is looked for.

No command is executed: they are only normalized.
"""

from __future__ import annotations

import pytest

from boundkeep.normalize.event import _consumed_as_path
from boundkeep.normalize.programs import devtool_exe_in_env
from tests.unit.test_m1c2_rereview_fixes import PLATFORM_IDS, PLATFORMS, _action
from tests.unit.test_m1c2_review_fixes import _decide

NOT_ALLOWED = ("gray", "ask", "deny")


# ---------------------------------------------------------------------------- R2-1: exact test


@pytest.mark.parametrize(
    ("word", "path", "consumed"),
    [
        ("src", "src", True),
        ("--select=src", "src", True),
        ("--select:src", "src", True),
        ("-Path:src", "src", True),
        ("-osrc", "src", True),
        ("--config=a=b", "a=b", True),  # the value is everything after the FIRST separator
        # the review's suffix forms
        ("$u@a.txt=tests", "tests", False),
        ("${u}@a.txt:tests", "tests", False),
        ("?a.txt=tests", "tests", False),
        ("[@]a.txt=tests", "tests", False),
        ("$SECRET_TOKEN=src", "src", False),
        ("$env:SECRET_TOKEN=a.txt", "a.txt", False),
        ("x=src", "src", False),
        ("a:src", "src", False),
        ("=src", "src", False),
        ("-n$X=src", "src", False),
        # an option part that itself expands or globs is not plain text
        ("--$u=src", "src", False),
        ("-$u=src", "src", False),
        ("--*=src", "src", False),
        ("--?x=src", "src", False),
        ("-[a]=src", "src", False),
        ("$src", "$src", True),  # the whole word is the path text: the path layer judges it
        ("-$osrc", "src", False),
        ("-`osrc", "src", False),
        ("--o", "o", False),
    ],
)
def test_consumed_as_path_is_exact(word: str, path: str, consumed: bool) -> None:
    assert _consumed_as_path(word, path) is consumed, (word, path)


# option-value position of every dev tool, with a path word the suffix equals
SUFFIX_TOOLS = [
    ("pytest tests", "-k"),
    ("pytest tests", "-n"),
    ("pytest tests", "-p"),
    ("pytest tests", "--maxfail"),
    ("python -m pytest tests", "-k"),
    ("ruff check src", "--select"),
    ("ruff check src", "--ignore"),
    ("mypy src", "--python-version"),
    ("black --check src", "--line-length"),
    ("pylint src", "--disable"),
    ("flake8 src", "--select"),
    ("isort --check src", "--profile"),
]
SUFFIXES = ["=src", ":src", "=tests", ":tests", "=.", ":."]
EXPANDING_PREFIXES = ["${u}@a.txt", "$u@a.txt", "$SECRET_TOKEN", "?a.txt", "[@]a.txt"]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("head", "option"), SUFFIX_TOOLS, ids=lambda v: str(v)[:30])
@pytest.mark.parametrize("prefix", EXPANDING_PREFIXES)
def test_a_path_suffix_does_not_hide_an_expanding_option_value(
    platform: str, head: str, option: str, prefix: str
) -> None:
    for suffix in SUFFIXES:
        if platform == "windows" and "${" in prefix:
            continue  # ${u}@ is a Bash spelling; PowerShell gets the $u forms
        tool = "PowerShell" if platform == "windows" else "Bash"
        glob = prefix[:1] in "?["  # a glob only means something unquoted (and in Bash)
        if glob and platform == "windows":
            continue
        word = f"{prefix}{suffix}" if glob else f'"{prefix}{suffix}"'
        command = f"{head} {option} {word}"
        for name in ("default", "strict"):
            for trusted in (False, True):
                got = _decide(platform, tool, command, name=name, trusted=trusted)
                assert got != "allow", (name, trusted, command)


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    "command",
    [
        'pytest tests -k "${u}@a.txt=tests"',
        'pytest tests -k "${u}@a.txt:tests"',
        'pytest -k "${u}@a.txt=." .',
        'ruff check src --select "${u}@r.txt=src"',
        "pytest tests -k ?a.txt=tests",
        "pytest tests -k [@]a.txt=tests",
        'git log -n "$SECRET_TOKEN=src" -- src',
        'ls -w "$SECRET_TOKEN=src" src',
        'find . -maxdepth "$SECRET_TOKEN=."',
        'tail -n "$SECRET_TOKEN=src" src',
        'tree -L "$SECRET_TOKEN=src" src',
        'head -n "$SECRET_TOKEN=src" src',
        'git log -n "$SECRET_TOKEN:src" -- src',
    ],
)
def test_the_reviews_reproductions_are_no_longer_allowed(platform: str, command: str) -> None:
    for name in ("default", "strict"):
        for trusted in (False, True):
            got = _decide(platform, "Bash", command, name=name, trusted=trusted)
            assert got != "allow", (name, trusted, command)


@pytest.mark.parametrize(
    "command",
    [
        'pytest tests -k "$u@a.txt=tests"',
        'ruff check --select "$u@r.txt=src" src',
        'git log -n "$env:SECRET_TOKEN=a.txt" -- a.txt',
        'mypy --python-version "$u@m.txt=src" src',
        'python -m pytest tests -k "$u@a.txt=tests"',
    ],
)
def test_the_reviews_powershell_reproductions_are_no_longer_allowed(command: str) -> None:
    for name in ("default", "strict"):
        for trusted in (False, True):
            got = _decide("windows", "PowerShell", command, name=name, trusted=trusted)
            assert got != "allow", (name, trusted, command)


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    "command",
    [
        "pytest tests -k smoke",
        "pytest tests -n 4",
        "pytest --maxfail=2 tests",
        "ruff check src --select=E,F",
        "ruff check --select E501 src",
        "git log -n 5 -- src",
        "git log --oneline -n 20",
        "ls -w 80 src",
        "find . -maxdepth 2",
        "tail -n 20 src",
    ],
)
def test_a_literal_option_value_still_understood(platform: str, command: str) -> None:
    got = _decide(platform, "Bash", command, trusted=True)
    assert got in ("allow", "ask"), (command, got)
    assert _action(platform, "Bash", command).dynamic_args is False, command


def test_an_option_value_that_is_a_path_word_is_still_consumed() -> None:
    # `--select=src` where src is also a path of the command: the path layer owns it
    action = _action("posix", "Bash", "ruff check src --select=src")
    assert action.dynamic_args is False
    action = _action("posix", "Bash", "git log -n 5 -- src")
    assert action.dynamic_args is False


# ---------------------------------------------------------------------------- R2-2: dot segments


@pytest.mark.parametrize(
    ("text", "in_env"),
    [
        ("./venv/bin/pytest", True),
        (".venv/bin/pytest", True),
        (".\\.venv\\Scripts\\pytest.exe", True),
        ("C:\\Users\\testuser\\proj\\venv\\Scripts\\pytest.exe", True),
        ("/home/testuser/proj/.venv/bin/ruff", True),
        ("tools/env/bin/ruff", True),
        ("./venv/../pytest", False),
        ("venv/../pytest", False),
        ("./.venv/../pytest", False),
        ("./env/../tools/ruff", False),
        ("./tests/../venv/../pytest", False),
        ("/home/testuser/proj/venv/../pytest", False),
        ("./venv/../python", False),
        ("./venv/bin/../../python", False),
        (".\\venv\\..\\pytest.exe", False),
        (".\\venv\\Scripts\\..\\..\\pytest.exe", False),
        ("C:\\Users\\testuser\\proj\\venv\\..\\pytest.exe", False),
        ("./venv/./bin/pytest", True),
        ("./venv/bin/../bin/pytest", True),
        ("./pytest", False),
        ("./bin/pytest", False),
        ("tools/ruff", False),
        (".\\Scripts\\pytest.exe", False),
        ("../venv/bin/pytest", False),  # an environment outside the project
        ("./../venv/bin/pytest", False),
        ("pytest", False),
    ],
)
def test_devtool_exe_in_env_collapses_dot_segments(text: str, in_env: bool) -> None:
    assert devtool_exe_in_env(text) is in_env, text


POSIX_ESCAPES = [
    "./venv/../pytest -q",
    "venv/../pytest",
    "./.venv/../pytest",
    "./env/../tools/ruff check .",
    "./tests/../venv/../pytest",
    "/home/testuser/proj/venv/../pytest",
    "./venv/../python -m pytest",
    "./venv/bin/../../python -m pytest",
]
WINDOWS_ESCAPES = [
    ".\\venv\\..\\pytest.exe -q",
    ".\\venv\\Scripts\\..\\..\\pytest.exe",
    "& '.\\venv\\..\\pytest.exe'",
    "C:\\Users\\testuser\\proj\\venv\\..\\pytest.exe",
]


@pytest.mark.parametrize("command", POSIX_ESCAPES)
def test_posix_dotdot_out_of_the_environment_is_unvetted(command: str) -> None:
    for name in ("default", "strict"):
        assert _decide("posix", "Bash", command, name=name, trusted=True) != "allow", command
    assert "unvetted-exe" in _action("posix", "Bash", command).wrappers, command


@pytest.mark.parametrize("command", WINDOWS_ESCAPES)
def test_windows_dotdot_out_of_the_environment_is_unvetted(command: str) -> None:
    for name in ("default", "strict"):
        for tool in ("PowerShell", "Bash"):
            if tool == "Bash" and command.startswith("&"):
                continue
            got = _decide("windows", tool, command, name=name, trusted=True)
            assert got != "allow", (tool, command)
    assert "unvetted-exe" in _action("windows", "PowerShell", command).wrappers, command


@pytest.mark.parametrize(
    "command",
    ["./venv/bin/pytest -q", "./.venv/bin/ruff check .", "./venv/./bin/pytest -q"],
)
def test_the_environments_own_tools_are_still_allowed(command: str) -> None:
    assert _decide("posix", "Bash", command, trusted=True) == "allow", command
    assert "unvetted-exe" not in _action("posix", "Bash", command).wrappers


@pytest.mark.parametrize(
    "command",
    [".\\venv\\Scripts\\pytest.exe -q", ".\\.venv\\Scripts\\ruff.exe check ."],
)
def test_the_windows_environments_own_tools_are_still_allowed(command: str) -> None:
    assert _decide("windows", "PowerShell", command, trusted=True) == "allow", command


# ---------------------------------------------------------------------------- R2-5: env values


@pytest.mark.parametrize(
    ("name", "value", "safe"),
    [
        ("LC_ALL", "C.UTF-8", True),
        ("LANG", "en_US.UTF-8", True),
        ("TZ", "America/New_York", True),
        ("TZ", "UTC", True),
        ("COLUMNS", "120", True),
        ("PYTHONIOENCODING", "utf-8", True),
        ("LC_ALL", "./x", False),
        ("LC_ALL", "x/y", False),
        ("COLUMNS", "x/y", False),
        ("LC_ALL", "-x", False),
        ("LC_ALL", "@x", False),
        ("LC_ALL", "a..b", False),
        ("LC_ALL", "/x", False),
        ("LC_ALL", "../x", False),
        ("TZ", "../x", False),
        ("TZ", "/etc/passwd", False),
        ("LC_ALL", "$X", False),
    ],
)
def test_env_values_with_a_slash_are_only_for_tz(name: str, value: str, safe: bool) -> None:
    from boundkeep.normalize.programs import devtool_env_is_safe

    assert devtool_env_is_safe(name, value) is safe, (name, value)


# ---------------------------------------------------------------------------- R2-4: trust list


def test_trust_list_marks_an_entry_the_loader_no_longer_refuses(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import argparse

    from boundkeep import trust

    monkeypatch.setattr(trust, "read_entries", lambda _path: ["~/.claude"])
    monkeypatch.setattr(trust, "guard_tree_reason", lambda _p: "a settings tree")
    assert trust.cmd_list(argparse.Namespace()) == 0
    out = capsys.readouterr().out
    assert "should not be trusted" in out
    assert "a settings tree" in out


def test_trust_list_marks_nothing_for_an_ordinary_entry(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import argparse

    from boundkeep import trust

    monkeypatch.setattr(trust, "read_entries", lambda _path: ["~/proj"])
    monkeypatch.setattr(trust, "guard_tree_reason", lambda _p: None)
    assert trust.cmd_list(argparse.Namespace()) == 0
    assert "should not be trusted" not in capsys.readouterr().out
