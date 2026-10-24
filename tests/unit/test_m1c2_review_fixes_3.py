"""X1 review of M1c / M1c-2 (docs/reviews/M1c2-security-review.md): M-1, M-3, the cheap part of L-1.

* M-1  ``pytest.toml`` / ``.pytest.toml`` / ``.pdbrc`` are tool configuration like ``pytest.ini``;
* the installed code (``.venv``, ``site-packages``, ``node_modules``) is not the project's source:
  writing into it asks (strict: refused);
* M-3  ``trusted_projects`` entries inside the home directory's key/settings/app-data trees are
        refused, and ``trust add`` makes the user confirm a directory that holds other repositories;
* L-1  ``python -X pycache_prefix=...`` / ``-W error::pkg.Cls`` are not a dev-tool call, and a
        drive-relative path in an option value (``--debug=C:x``) is gray.

No command is executed: they are only normalized.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from boundkeep import policycli, trust
from boundkeep.normalize import programs
from boundkeep.policy import PolicyError, default_policy_text, parse_policy_text
from tests.unit.test_m1c2_review_fixes import _bash, _decide, _policy, _ps_dev

PLATFORMS = ("windows", "posix")
PLATFORM_IDS = [f"on-{p}" for p in PLATFORMS]  # conftest.py skips ids that are the bare words


def _file_decision(
    platform: str, tool: str, path: str, *, name: str = "default", trusted: bool = False
) -> str:
    inputs: dict[str, Any] = {
        "Write": {"file_path": path, "content": "x"},
        "Edit": {"file_path": path, "old_string": "a", "new_string": "b"},
        "Read": {"file_path": path},
    }
    result = policycli._run_one(
        _policy(name, platform, trusted),
        platform,  # type: ignore[arg-type]
        tool,
        inputs[tool],
        None,
        None,
    )
    return str(result.verdict.decision)


# ---------------------------------------------------------------------------- M-1: tool config


@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("path", ["pytest.toml", ".pytest.toml", ".pdbrc", "sub/dir/pytest.toml"])
@pytest.mark.parametrize("tool", ["Write", "Edit"])
def test_pytest_toml_and_pdbrc_are_tool_configuration(
    platform: str, name: str, path: str, tool: str
) -> None:
    expected = "ask" if name == "default" else "deny"
    assert _file_decision(platform, tool, path, name=name) == expected


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("name", ["pytest.toml", ".pytest.toml", ".pdbrc"])
def test_a_line_that_writes_such_a_file_and_runs_pytest_is_not_allow(
    platform: str, name: str
) -> None:
    for command in (f"echo x > {name}; pytest", f"touch {name} && pytest -q"):
        assert _decide(platform, "Bash", command, trusted=True) != "allow", command


def test_the_same_line_detector_knows_the_new_names() -> None:
    from boundkeep.normalize.event import _BUILD_FILES

    assert {"pytest.toml", ".pytest.toml"} <= _BUILD_FILES["pytest"]


# ---------------------------------------------------------------------------- installed code


INSTALLED = [
    ".venv/Lib/site-packages/requests/__init__.py",
    ".venv/Scripts/pytest-script.py",
    ".venv/bin/pytest",
    ".venv/pyvenv.cfg",
    "env/lib/python3.12/site-packages/x.py",
    "node_modules/left-pad/index.js",
    "packages/web/node_modules/x/index.js",
    "sub/.venv/x.py",
]


@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("path", INSTALLED)
@pytest.mark.parametrize("tool", ["Write", "Edit"])
def test_writing_installed_code_asks_or_is_refused(
    platform: str, name: str, path: str, tool: str
) -> None:
    expected = "ask" if name == "default" else "deny"
    assert _file_decision(platform, tool, path, name=name) == expected, path


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("path", INSTALLED)
def test_reading_installed_code_is_as_before(platform: str, path: str) -> None:
    assert _file_decision(platform, "Read", path) == "allow"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    "path",
    ["src/app.py", "venv_helpers/x.py", "docs/node_modules_notes.md", "src/site_packages.py"],
)
def test_the_projects_own_source_is_still_written_without_a_question(
    platform: str, path: str
) -> None:
    assert _file_decision(platform, "Write", path) == "allow"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    "command",
    [
        "echo x > .venv/bin/pytest",
        "touch .venv/marker",
        "mkdir node_modules/x",
        "cp evil.py .venv/Lib/site-packages/requests/__init__.py",
        "sed -i s/a/b/ node_modules/x/index.js",
        "tee .venv/bin/ruff",
    ],
)
def test_shell_writes_into_installed_code_ask(platform: str, command: str) -> None:
    assert _decide(platform, "Bash", command, trusted=True) in ("ask", "deny"), command


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    "command",
    [
        "pytest -q",
        "ruff check --fix .",
        "./.venv/bin/pytest -q",
        "./.venv/bin/python -m pytest",
        "ls .venv",
        "cat .venv/pyvenv.cfg",
    ],
)
def test_running_and_reading_the_environment_still_works(platform: str, command: str) -> None:
    if command.startswith("ls ") or command.startswith("cat "):
        assert _decide(platform, "Bash", command) == "allow", command
    else:
        assert _decide(platform, "Bash", command, trusted=True) == "allow", command


@pytest.mark.parametrize("name", ["default", "strict"])
def test_the_installed_code_rule_has_the_expected_shape(name: str) -> None:
    import yaml

    from tests.unit.test_m1c2_review_fixes import POLICIES

    data = yaml.safe_load((POLICIES / f"{name}.yaml").read_text(encoding="utf-8"))
    rid = f"{'ask' if name == 'default' else 'deny'}-installed-package-dirs-write"
    (rule,) = [r for r in data["rules"] if r["id"] == rid]
    assert rule["match"]["path_glob"] == [
        "**/.venv/**",
        "**/venv/**",
        "**/env/**",
        "**/.tox/**",
        "**/.nox/**",
        "**/.conda/**",
        "**/.pixi/**",
        "**/.direnv/**",
        "**/__pypackages__/**",
        "**/site-packages/**",
        "**/dist-packages/**",
        "**/node_modules/**",
    ]
    assert rule["match"]["access"] == "write"
    assert rule["action"] == ("ask" if name == "default" else "deny")
    assert "tool" not in rule


# ---------------------------------------------------------------------------- M-3: trusted scope


def _entry_error(entry: str, home: str = "C:\\Users\\testuser") -> str | None:
    text = trust.add_entry_text(default_policy_text(), entry)
    try:
        parse_policy_text(text, home=home)
    except PolicyError as exc:
        return str(exc)
    return None


@pytest.mark.parametrize(
    "entry",
    [
        "C:\\Users\\testuser\\.ssh",
        "C:\\Users\\testuser\\.ssh\\keys",
        "C:\\Users\\testuser\\.claude",
        "C:\\Users\\testuser\\.claude\\projects",
        "C:\\Users\\testuser\\.boundkeep",
        "C:\\Users\\testuser\\.aws",
        "C:\\Users\\testuser\\.gnupg",
        "C:\\Users\\testuser\\.config",
        "C:\\Users\\testuser\\.config\\nvim",
        "C:\\Users\\testuser\\AppData",
        "C:\\Users\\testuser\\AppData\\Local\\Temp",
        "C:\\Users\\testuser\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "c:\\users\\TESTUSER\\APPDATA\\Local",
        "~/.ssh",
        "~/.claude",
        "~/AppData/Roaming",
    ],
)
def test_keys_settings_and_app_data_directories_are_not_projects(
    entry: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # X1 re-review R-6: `trust add` and `doctor` judge this; the policy LOADER no longer does (an
    # entry written before the check existed must not make the whole policy unloadable)
    assert _entry_error(entry) is None, entry
    monkeypatch.setattr(trust, "home_for_policy", lambda: "C:\\Users\\testuser")
    path = entry.replace("~", "C:\\Users\\testuser", 1) if entry.startswith("~") else entry
    reason = trust.guard_tree_reason(path)
    assert reason is not None, entry
    assert "keys, settings or application data" in reason


@pytest.mark.parametrize(
    "entry",
    [
        "C:\\Users\\testuser\\proj",
        "C:\\Users\\testuser\\dev\\work\\app",
        "C:\\Users\\testuser\\.claudex",  # a different name
        "C:\\Users\\testuser\\.sshfs-mount\\p",
        "C:\\Users\\testuser\\myAppData\\p",
        "~/proj",
        "E:\\dev",
    ],
)
def test_ordinary_project_directories_are_still_accepted(
    entry: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _entry_error(entry) is None, entry
    monkeypatch.setattr(trust, "home_for_policy", lambda: "C:\\Users\\testuser")
    path = entry.replace("~", "C:\\Users\\testuser", 1) if entry.startswith("~") else entry
    assert trust.guard_tree_reason(path) is None, entry


def test_the_posix_home_trees_are_judged_too(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(trust, "home_for_policy", lambda: "/home/testuser")
    for entry in ("/home/testuser/.ssh", "/home/testuser/.config/x", "/home/testuser/.claude"):
        assert trust.guard_tree_reason(entry) is not None, entry
    assert trust.guard_tree_reason("/home/testuser/work/app") is None
    assert trust.guard_tree_reason("/srv/other/.ssh") is None  # not under the home directory


def _repo(path: Path, *, file_marker: bool = False) -> None:
    path.mkdir(parents=True)
    if file_marker:
        (path / ".git").write_text("gitdir: ../x\n", encoding="utf-8")
    else:
        (path / ".git").mkdir()


def test_nested_repositories_are_found_below_the_directory(tmp_path: Path) -> None:
    root = tmp_path / "dev"
    _repo(root / "a")
    _repo(root / "group" / "b")
    _repo(root / "group" / "deep" / "c", file_marker=True)  # a worktree / submodule: a .git FILE
    (root / "plain" / "dir").mkdir(parents=True)
    found, cut = trust.nested_repositories(str(root))
    assert [Path(f).as_posix() for f in found] == ["a", "group/b", "group/deep/c"]
    assert cut is False


def test_the_directory_itself_and_dependency_directories_are_not_reported(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    _repo(root)  # the root is a repository: that is the usual choice, not a warning
    _repo(root / "node_modules" / "pkg")
    _repo(root / ".venv" / "lib" / "pkg")
    (root / ".git" / "modules" / "x").mkdir(parents=True)
    assert trust.nested_repositories(str(root)) == ([], False)


def test_the_search_is_bounded_in_depth_and_in_entries(tmp_path: Path) -> None:
    root = tmp_path / "dev"
    too_deep = root.joinpath(*(["d"] * (trust.NESTED_MAX_DEPTH + 1)))
    _repo(too_deep)
    found, cut = trust.nested_repositories(str(root))
    assert found == []
    assert cut is True
    big = tmp_path / "big"
    big.mkdir()
    for n in range(40):
        (big / f"d{n}").mkdir()
    old = trust.NESTED_MAX_ENTRIES
    try:
        trust.NESTED_MAX_ENTRIES = 10
        assert trust.nested_repositories(str(big))[1] is True
    finally:
        trust.NESTED_MAX_ENTRIES = old


def test_a_missing_directory_is_not_an_error() -> None:
    assert trust.nested_repositories(str(Path("nope") / "nothing")) == ([], False)


def test_the_confirmation_needs_the_word_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    for answer, expected in (
        ("yes", True),
        (" YES ", True),
        ("y", False),
        ("", False),
        ("no", False),
    ):
        monkeypatch.setattr("builtins.input", lambda _p, a=answer: a)
        assert trust._confirm("Is that what you want?") is expected, answer

    def eof(_prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert trust._confirm("q") is False


# ---------------------------------------------------------------------------- L-1: interpreter


@pytest.mark.parametrize(
    ("flag", "value", "ok"),
    [
        ("-X", "dev", True),
        ("-X", "utf8", True),
        ("-X", "utf8=1", True),
        ("-X", "importtime", True),
        ("-X", "faulthandler", True),
        ("-X", "tracemalloc=5", True),
        ("-X", "frozen_modules=off", True),
        ("-X", "int_max_str_digits=0", True),
        ("-X", "cpu_count=4", True),
        ("-X", "pycache_prefix=C:\\out", False),
        ("-X", "pycache_prefix=/tmp/x", False),
        ("-X", "pycache_prefix", False),
        ("-X", "presite=evil", False),
        ("-X", "", False),
        ("-X", "dev;x", False),
        ("-W", "error", True),
        ("-W", "ignore", True),
        ("-W", "default", True),
        ("-W", "ignore::DeprecationWarning", True),
        ("-W", "error::UserWarning:mod", True),
        ("-W", "ignore:some message:DeprecationWarning", True),
        ("-W", "error::evil.Cls", False),
        ("-W", "error::pkg.mod.Warn:x:1", False),
        ("-W", "ERROR", False),
        ("-W", "", False),
        ("-W", "a:b:c:d:e:f", False),
        ("-c", "dev", False),
    ],
)
def test_the_interpreter_option_values_a_dev_tool_call_may_carry(
    flag: str, value: str, ok: bool
) -> None:
    assert programs.python_option_value_ok(flag, value) is ok


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    ("tool", "command"),
    [
        ("Bash", "python -X pycache_prefix=/home/testuser/out -m pytest -q"),
        ("Bash", "python -Xpycache_prefix=/home/testuser/out -m pytest -q"),
        ("Bash", "python -W error::evil.Cls -m pytest -q"),
        ("Bash", "python -Werror::evil.Cls -m pytest"),
        ("Bash", "python3 -X dev -X pycache_prefix=/x -m ruff check ."),
        ("PowerShell", "python -X pycache_prefix=C:\\Users\\testuser\\out -m pytest -q"),
        ("PowerShell", "python -W error::evil.Cls -m pytest -q"),
        ("PowerShell", "py -X pycache_prefix=C:\\x -m mypy src"),
    ],
    ids=lambda v: str(v)[:60],
)
def test_such_interpreter_options_make_it_an_ordinary_python_call(
    platform: str, tool: str, command: str
) -> None:
    if tool == "PowerShell" and platform != "windows":
        pytest.skip("PowerShell runs on the Windows fake machine")
    assert _decide(platform, tool, command, trusted=True) != "allow", command


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    ("tool", "command"),
    [
        ("Bash", "python -X dev -m pytest -q"),
        ("Bash", "python -u -B -X dev -W error -m pytest"),
        ("Bash", "python -W ignore::DeprecationWarning -m pytest"),
        ("Bash", "python -X frozen_modules=off -m pytest"),
        ("PowerShell", "python -X dev -m pytest -q"),
        ("PowerShell", "python -W error -m pytest"),
    ],
    ids=lambda v: str(v)[:60],
)
def test_the_ordinary_interpreter_options_stay_a_dev_tool_call(
    platform: str, tool: str, command: str
) -> None:
    if tool == "PowerShell" and platform != "windows":
        pytest.skip("PowerShell runs on the Windows fake machine")
    assert _decide(platform, tool, command, trusted=True) == "allow", command


DRIVE_RELATIVE = programs.DEVTOOL_DRIVE_RELATIVE_GRAY


@pytest.mark.parametrize("tool", sorted(programs.DEVTOOLS))
@pytest.mark.parametrize(
    "args",
    [
        ("--debug=C:x",),
        ("--output-file=D:out.txt",),
        ("--junitxml=c:r.xml",),
        ("C:file.py",),
        ("-oC:x",),
        ("--cache-dir=E:..\\x",),
    ],
    ids=lambda a: "|".join(a),
)
def test_a_drive_relative_path_in_an_option_value_is_gray(tool: str, args: tuple[str, ...]) -> None:
    assert DRIVE_RELATIVE in _bash(tool, *args).gray
    assert DRIVE_RELATIVE in _ps_dev(tool, *args).gray


@pytest.mark.parametrize("tool", sorted(programs.DEVTOOLS))
@pytest.mark.parametrize(
    "args",
    [
        ("C:\\x\\a.py",),
        ("C:/x/a.py",),
        ("--debug=C:\\x",),
        ("tests/test_a.py::TestA::test_b",),
        ("t::x",),
        ("--tb=short",),
        ("-k", "alpha"),
        ("src",),
        ("a:",),
        ("http://localhost/x",),
    ],
    ids=lambda a: "|".join(a),
)
def test_absolute_paths_node_ids_and_urls_are_not_drive_relative(
    tool: str, args: tuple[str, ...]
) -> None:
    assert DRIVE_RELATIVE not in _bash(tool, *args).gray
    assert DRIVE_RELATIVE not in _ps_dev(tool, *args).gray


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_the_reviewed_drive_relative_commands_are_not_allow(platform: str) -> None:
    for tool, command in (("Bash", "pytest --debug=C:x"), ("PowerShell", "pytest --debug=C:x")):
        if tool == "PowerShell" and platform != "windows":
            continue
        assert _decide(platform, tool, command, trusted=True) != "allow", command
