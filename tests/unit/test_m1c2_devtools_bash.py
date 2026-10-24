"""M1c-2: dev tools (pytest, ruff, mypy, black, isort, flake8, pylint) in the Bash dialect.

The CONTRACT (programs.py "Developer tools"; the PowerShell classifier mirrors it): ``TOOL args``
and ``python [harmless flags] -m TOOL args`` both come out as the program ``TOOL`` (no subcommand,
known, ``exec`` tag, no gray reason, no wrapper marker); a path-qualified executable keeps its own
path as a READ operand instead of the gray ``program-path-qualified``; everything that is not
exactly that form is classified as before (the NOT-dev-tool table pins the old answers).
"""

from __future__ import annotations

from typing import Any

import pytest

from boundkeep import policycli
from boundkeep.normalize import programs
from boundkeep.normalize.bash import parse_bash
from boundkeep.normalize.event import normalize_event
from boundkeep.normalize.model import Action, Word
from boundkeep.normalize.programs import DEVTOOL_RISKY_FLAGS, DEVTOOLS, classify, devtool_form

# NB: tests/conftest.py skips a test whose id is exactly "posix" or "windows" on the wrong host
PLATFORMS = [pytest.param("posix", id="bashposix"), pytest.param("windows", id="bashwin")]
TOOLS = sorted(DEVTOOLS)


def _actions(command: str, platform: str = "posix") -> list[Action]:
    fake = policycli._FAKE[platform]
    payload: dict[str, Any] = {
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": fake["project"],
        "project_dir": fake["project"],
        "session_id": "t",
    }
    return normalize_event(payload, platform=platform, env=fake["env"], home=fake["home"])  # type: ignore[arg-type]


def _one(command: str, platform: str = "posix") -> Action:
    acts = _actions(command, platform)
    assert len(acts) == 1, [(a.program, a.gray_reasons) for a in acts]
    return acts[0]


def _is_devtool(action: Action, tool: str) -> None:
    assert action.program == tool
    assert action.subcommand is None
    assert action.wrappers == ()
    assert action.gray_reasons == ()
    assert not action.gray
    assert "exec" in action.risk_tags
    assert not action.network
    assert action.domains == ()


def _paths(action: Action) -> list[tuple[str, str]]:
    return [(p.raw, p.access) for p in action.paths]


# --- A: the program is a dev tool, bare or as ``python -m TOOL`` -----


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("tool", TOOLS)
def test_a_bare_tool(tool: str, platform: str) -> None:
    action = _one(f"{tool} -q", platform)
    _is_devtool(action, tool)
    assert action.flags == ("-q",)
    assert action.paths == ()


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("tool", TOOLS)
def test_a_exe_suffix(tool: str, platform: str) -> None:
    action = _one(f"{tool}.exe -q", platform)
    _is_devtool(action, tool)
    assert action.flags == ("-q",)


def test_a_windows_is_case_insensitive_posix_is_not_a_dev_tool() -> None:
    _is_devtool(_one("PYTEST.EXE -q", "windows"), "pytest")
    upper = _one("PYTEST -q", "posix")
    assert upper.program == "pytest"
    assert any(r.startswith("program-case-variant") for r in upper.gray_reasons)  # as any program


LAUNCHERS = ["python", "python3", "python3.12", "py", "python.exe", "python3.12.exe", "py.exe"]


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("launcher", LAUNCHERS)
def test_a_python_dash_m_tool(launcher: str, tool: str, platform: str) -> None:
    action = _one(f"{launcher} -m {tool} -q", platform)
    _is_devtool(action, tool)
    assert action.flags == ("-q",)  # the interpreter's ``-m`` is not a flag of the tool
    assert action.paths == ()  # bare ``python`` is found on PATH: no extra path


HARMLESS = [
    "-I",
    "-u",
    "-B",
    "-E",
    "-s",
    "-S",
    "-q",
    "-O",
    "-OO",
    "-Bu",
    "-IuB",
    "-X utf8",
    "-X importtime",
    "-Xutf8",
    "-W error",
    "-W ignore::DeprecationWarning",
    "-Werror",
    "-I -u -B -E -s -S -q -O -OO -X dev -W error",
]


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("flags", HARMLESS)
def test_a_harmless_interpreter_flags(flags: str, platform: str) -> None:
    action = _one(f"python {flags} -m pytest tests -x", platform)
    _is_devtool(action, "pytest")
    assert action.flags == ("-x",)
    assert _paths(action) == [("tests", "unknown")]


def test_a_the_tools_own_dash_m_and_dash_x_are_the_tools_not_the_interpreters() -> None:
    action = _one("python -m pytest -m slow -x")
    _is_devtool(action, "pytest")
    assert action.flags == ("-m", "-x")
    assert action.paths == ()  # ``slow`` is the value of -m, not an operand


def test_a_subcommand_is_none_and_ruff_subcommand_is_not_a_path() -> None:
    for command in (
        "ruff check .",
        "ruff format --check .",
        "python -m ruff check .",
        "py -m ruff check .",
    ):
        action = _one(command)
        _is_devtool(action, "ruff")
        assert _paths(action) == [(".", "unknown")], command
    assert _paths(_one("ruff check check")) == [("check", "unknown")]  # the SECOND ``check``
    assert _paths(_one("ruff --isolated check src")) == [("src", "unknown")]


# --- B: path-qualified executables -----

QUALIFIED = [
    # (command, platform, program path as listed, inside the project?)
    ("./.venv/bin/python -m pytest", "posix", "./.venv/bin/python", True),
    ("./.venv/bin/python -m pytest -q", "windows", "./.venv/bin/python", True),
    (
        "/home/testuser/proj/.venv/bin/python3 -m pytest",
        "posix",
        "/home/testuser/proj/.venv/bin/python3",
        True,
    ),
    ("/usr/bin/python3 -m pytest", "posix", "/usr/bin/python3", False),
    ("/opt/venv/bin/python3.12 -m mypy src", "posix", "/opt/venv/bin/python3.12", False),
    (
        "'C:\\Users\\testuser\\proj\\.venv\\Scripts\\python.exe' -m pytest -q",
        "windows",
        "C:\\Users\\testuser\\proj\\.venv\\Scripts\\python.exe",
        True,
    ),
    ("'C:\\Python312\\python.exe' -m pytest -q", "windows", "C:\\Python312\\python.exe", False),
    (
        '"C:\\proj\\.venv\\Scripts\\python.exe" -m pytest -q',
        "windows",
        "C:\\proj\\.venv\\Scripts\\python.exe",
        False,
    ),
    (
        "C:/Users/testuser/proj/.venv/Scripts/python.exe -m pytest",
        "windows",
        "C:/Users/testuser/proj/.venv/Scripts/python.exe",
        True,
    ),
    ("'.venv\\Scripts\\python.exe' -m ruff check .", "windows", ".venv\\Scripts\\python.exe", True),
    ("./.venv/bin/pytest -q", "posix", "./.venv/bin/pytest", True),
    ("./.venv/bin/ruff check .", "posix", "./.venv/bin/ruff", True),
    ("'.venv\\Scripts\\pytest.exe' -q", "windows", ".venv\\Scripts\\pytest.exe", True),
    ("/opt/tools/mypy src", "posix", "/opt/tools/mypy", False),
    ("../other/.venv/bin/black --check .", "posix", "../other/.venv/bin/black", False),
    ("./venv/bin/py -m pylint src", "posix", "./venv/bin/py", True),
]


@pytest.mark.parametrize(("command", "platform", "program_path", "inside"), QUALIFIED)
def test_b_path_qualified_dev_tool_lists_its_own_path_as_a_read(
    command: str, platform: str, program_path: str, inside: bool
) -> None:
    action = _one(command, platform)
    assert action.program in DEVTOOLS
    assert "program-path-qualified" not in action.gray_reasons
    assert action.gray_reasons == ()
    # X1 re-review R-5: an executable outside any virtual-environment directory is marked so that
    # no allow rule matches it (it is any file the agent may have written)
    unvetted = () if programs.devtool_exe_in_env(program_path) else (programs.UNVETTED_EXE,)
    assert action.wrappers == unvetted
    assert "exec" in action.risk_tags
    reads = [p for p in action.paths if p.raw == program_path]
    # a path that exists on the host (e.g. /usr/bin/python3 in a Linux container, usually a
    # symlink) also gets its resolved form as a second ref: both must carry the same verdict
    assert reads, [p.raw for p in action.paths]
    assert all(p.access == "read" for p in reads)
    assert all(p.inside_project is inside for p in reads)
    if inside and len({p.key for p in action.paths}) == 1:
        assert action.inside_project is True
    if not inside:
        assert action.inside_project is not True  # the policy can demand path_inside_project


def test_b_bare_names_get_no_extra_path() -> None:
    assert _one("pytest -q").paths == ()
    assert _one("python -m pytest -q").paths == ()
    assert _one("pytest.exe").paths == ()


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize(
    "command",
    [
        "./.venv/bin/python -m pip list",
        "./.venv/bin/python script.py",
        "./.venv/bin/python -c 'x'",
        "./.venv/bin/python -m venv x",
        "./.venv/bin/node x.js",
        "./tools/pytest-wrapper -q",
        "./bin/mytool check .",
        "./bin/pytests -q",
        "./.venv/bin/pytest.py -q",
        "./.venv/bin/Pytest -q",
        "./.venv/bin/python -i -m pytest",
        "./.venv/bin/python3.12.1 -m pytest",
        "./.venv/bin/pythonw -m pytest",
    ],
)
def test_b_other_path_qualified_programs_keep_the_gray_reason(command: str, platform: str) -> None:
    acts = _actions(command, platform)
    assert "program-path-qualified" in acts[0].gray_reasons, command


def test_b_tilde_and_variable_program_words_are_not_recognised() -> None:
    for command in ("~/.venv/bin/python -m pytest", "$HOME/.venv/bin/python -m pytest"):
        acts = _actions(command)
        assert acts[0].program == "python"
        assert "program-path-qualified" in acts[0].gray_reasons


# --- D / NOT a dev-tool form: classified exactly as before -----
# (program, flags, tags, gray reasons, wrappers) per action, measured on the code before M1c-2.

_EX = ("exec",)
_PQ = "program-path-qualified"


def _act(
    program: str | None,
    flags: tuple[str, ...] = (),
    tags: tuple[str, ...] = _EX,
    gray: tuple[str, ...] = (),
    wrappers: tuple[str, ...] = (),
) -> tuple[Any, ...]:
    return (program, flags, tags, gray, wrappers)


_INLINE_C = _act(None, gray=("exec:interpreter-c:python",))
_PY_DASH_M = _act("python", ("-m",))

UNCHANGED: list[tuple[str, tuple[tuple[Any, ...], ...]]] = [
    ("python script.py", (_act("python"),)),
    ('python -c "import os"', (_act("python", ("-c",), gray=("inline-code:-c",)), _INLINE_C)),
    ("python -m pip list", (_PY_DASH_M,)),
    ("python -m venv .venv", (_act("python", ("-m",), ("file_write", "exec")),)),
    ("python -m boundkeep status", (_act("boundkeep", (), (), (), ("python-m",)),)),
    (
        "python - < x.py",
        (
            _act("python"),
            _act(
                None,
                gray=("exec:stdin-to-interpreter:python", "exec:redirect-to-interpreter:python"),
            ),
        ),
    ),
    ("python -i -m pytest", (_act("python", ("-i", "-m")),)),
    ("python -x -m pytest", (_act("python", ("-x", "-m")),)),
    (
        "python --check-hash-based-pycs always -m pytest",
        (_act("python", ("--check-hash-based-pycs", "-m")),),
    ),
    ("python -m pytest_xdist", (_PY_DASH_M,)),
    ("python -mpytest", (_act("python", ("-mpytest", "-m")),)),
    ("python -m PyTest", (_PY_DASH_M,)),
    ("python -m foo -m pytest", (_PY_DASH_M,)),
    ("python -m", (_PY_DASH_M,)),
    ("python", (_act("python"),)),
    ("python3.12.1 -m pytest", (_act("python3.12.1", ("-m",)),)),
    ("pythonw -m pytest", (_act("pythonw", ("-m",), ()),)),
    (
        "python $X -m pytest",
        (
            _act("python", ("-m",), ("file_write", "exec")),
            _act(None, (), (), ("dynamic-interpreter-args:python",)),
        ),
    ),
    ("python -u script.py -m pytest", (_act("python", ("-u", "-m")),)),
    ("python -Bm pytest", (_act("python", ("-Bm", "-B", "-m")),)),
    (
        "python -c 'x' -m pytest",
        (_act("python", ("-c", "-m"), gray=("inline-code:-c",)), _INLINE_C),
    ),
    ("python -W", (_act("python", ("-W",)),)),
    ("py -3 -m pytest", (_act("py", ("-3", "-m")),)),
    ("python2 -m pytest", (_act("python2", ("-m",)),)),
    ("python -m pytest.main", (_PY_DASH_M,)),
    ("./.venv/bin/python -m pip list", (_act("python", ("-m",), gray=(_PQ,)),)),
    ("./.venv/bin/python script.py", (_act("python", gray=(_PQ,)),)),
    (
        "./.venv/bin/python -c 'x'",
        (_act("python", ("-c",), gray=("inline-code:-c", _PQ)), _INLINE_C),
    ),
    ("./.venv/bin/node x.js", (_act("node", gray=(_PQ,)),)),
    ("./tools/pytest-wrapper -q", (_act("pytest-wrapper", ("-q",), (), (_PQ,)),)),
    ("./bin/mytool check .", (_act("mytool", (), ("file_write",), (_PQ,)),)),
    (
        "/opt/x/pip install y",
        (_act("pip", (), ("network_egress", "file_write", "exec"), (_PQ,)),),
    ),
    (
        "$HOME/.venv/bin/python -m pytest",
        (_act("python", ("-m",), gray=(_PQ,)), _act(None, (), (), ("dynamic-command-name",))),
    ),
    ("~/.venv/bin/python -m pytest", (_act("python", ("-m",), gray=(_PQ,)),)),
    ("node x.js", (_act("node"),)),
    ("npm test", (_act("npm"),)),
    ("'C:\\proj\\.venv\\Scripts\\python.exe' -m pip list", (_act("python", ("-m",), gray=(_PQ,)),)),
]


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize(("command", "expected"), UNCHANGED)
def test_d_everything_else_is_classified_as_before(
    command: str, expected: tuple[tuple[Any, ...], ...], platform: str
) -> None:
    got = tuple(
        (a.program, a.flags, a.risk_tags, a.gray_reasons, a.wrappers)
        for a in _actions(command, platform)
    )
    assert got == expected


def test_d_form_recogniser_rejects_the_non_forms() -> None:
    def words(text: str) -> list[Word]:
        return [Word(t) for t in text.split()]

    for text in (
        "python script.py",
        "python -c x -m pytest",
        "python -m pip",
        "python -m boundkeep",
        "python -i -m pytest",
        "python -x -m pytest",
        "python - -m pytest",
        "python -m -m pytest",
        "python -X",
        "python -X -m pytest",
        "python -W -m pytest",
        "python --version -m pytest",
        "python -mpytest",
        "python -m PyTest",
        "python -m pytest_cov",
        "py -3 -m pytest",
        "pythonw -m pytest",
        "python3.12.1 -m pytest",
        "node -m pytest",
        "pip -m pytest",
        "pytests",
        "Pytest",
        "ruff.py",
    ):
        assert devtool_form(words(text)) is None, text
    assert devtool_form([]) is None
    assert devtool_form([Word("$X"), Word("-m", False), Word("pytest")]) is None
    assert devtool_form([Word("python", expands=True), Word("-m"), Word("pytest")]) is None
    assert devtool_form([Word("python"), Word("-m"), Word("$T", expands=True)]) is None
    assert devtool_form([Word("python"), Word("-m"), Word("pytest*", glob=True)]) is None
    assert (
        devtool_form([Word("python"), Word("$F", expands=True), Word("-m"), Word("pytest")]) is None
    )


def test_d_form_recogniser_positions() -> None:
    form = devtool_form([Word("python"), Word("-u"), Word("-m"), Word("ruff"), Word("check")])
    assert form is not None
    assert (form.tool, form.start, form.path) == ("ruff", 4, None)
    form = devtool_form([Word("./v/bin/pytest"), Word("-q")])
    assert form is not None
    assert (form.tool, form.start) == ("pytest", 1)
    assert form.path == Word("./v/bin/pytest")


# --- environment, wrappers, runners -----


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("command", ["pytest -q", "python -m pytest -q", "./.venv/bin/pytest"])
@pytest.mark.parametrize(
    "name",
    [
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PATH",
        "LD_PRELOAD",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "PYLINTRC",
        "PYTHONBREAKPOINT",
        "PYTHONWARNINGS",
        "PYTHONUSERBASE",
        "pythonpath",
    ],
)
def test_env_code_prefix_keeps_the_command_gray(command: str, name: str, platform: str) -> None:
    acts = _actions(f"{name}=/x {command}", platform)
    reasons = {r for a in acts for r in a.gray_reasons}
    assert any(r.startswith("env-code-injection") for r in reasons), reasons
    assert all(a.gray for a in acts if a.program == "pytest")


@pytest.mark.parametrize("platform", PLATFORMS)
def test_harmless_env_prefix_is_still_a_dev_tool(platform: str) -> None:
    for command in ("CI=1 pytest -q", "CI=true python -m pytest", "NO_COLOR=1 ruff check ."):
        action = _one(command, platform)
        assert action.program in DEVTOOLS
        assert action.gray_reasons == ()


@pytest.mark.parametrize("platform", PLATFORMS)
def test_an_unlisted_env_prefix_is_still_a_dev_tool_but_gray(platform: str) -> None:
    # X1 review of M1c-2 (H-3): the prefix is not interpreted by name any more; only a short list of
    # harmless names leaves the call understood (docs/reviews/M1c2-security-review.md)
    for command in ("FOO=1 pytest -q", "RUFF_OUTPUT_FILE=/x ruff check ."):
        action = _one(command, platform)
        assert action.program in DEVTOOLS
        assert any(r.startswith("devtool-env-prefix:") for r in action.gray_reasons)


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize(
    ("command", "wrappers"),
    [
        ("sudo pytest", ("sudo",)),
        ("sudo python -m pytest", ("sudo",)),
        ("env X=1 pytest", ("env",)),
        ("env X=1 python -m ruff check .", ("env",)),
        ("timeout 5 pytest", ("timeout",)),
        ("nohup pytest", ("nohup",)),
        ("time pytest -q", ("time",)),
        ("nice -n 5 python -m pytest", ("nice",)),
        ("uv run pytest", ("uv-run",)),
        ("uv run python -m pytest", ("uv-run",)),
        ("poetry run pytest", ("poetry-run",)),
        ("poetry run python -m mypy src", ("poetry-run",)),
        ("uvx ruff check .", ("uvx",)),
    ],
)
def test_wrappers_keep_the_wrapper_marker(
    command: str, wrappers: tuple[str, ...], platform: str
) -> None:
    acts = [a for a in _actions(command, platform) if a.program in DEVTOOLS]
    assert acts, command
    for action in acts:
        assert action.wrappers == wrappers
        assert "exec" in action.risk_tags


@pytest.mark.parametrize("platform", PLATFORMS)
def test_shell_dash_c_carrier_is_its_own_action(platform: str) -> None:
    """``bash -c 'pytest'``: the inner command inherits the carrier's wrappers (none), as for any
    program; the ``bash`` action itself is not a dev tool and no allow rule matches it."""
    acts = _actions("bash -c 'python -m pytest -q'", platform)
    assert [a.program for a in acts] == ["bash", "pytest"]
    _is_devtool(acts[1], "pytest")
    assert acts[1].flags == ("-q",)
    acts = _actions("sudo bash -c 'pytest -q'", platform)
    assert acts[-1].program == "pytest"
    assert acts[-1].wrappers == ("sudo",)


def test_xargs_dev_tool_is_gray_arguments_from_stdin() -> None:
    action = next(a for a in _actions("echo x | xargs pytest") if a.program == "pytest")
    assert "arguments-from-stdin" in action.gray_reasons
    assert action.wrappers == ("xargs",)


# --- E: a command line that writes a file and then runs it -----


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize(
    "command",
    [
        "echo x > t.py; python -m pytest t.py",
        "echo x > t.py && pytest t.py",
        "echo x > t.py; py -m pytest t.py",
        "printf x > conftest.py; python -m pytest",
        "printf x > conftest.py; pytest -q",
        "echo x > t.py; ./.venv/bin/python t.py",
    ],
)
def test_e_exec_of_written_file_still_fires(command: str, platform: str) -> None:
    reasons = {r for a in _actions(command, platform) for r in a.gray_reasons}
    assert "exec-of-written-file" in reasons, (command, reasons)


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize(
    "command",
    [
        "echo x > .venv/bin/ruff; .venv/bin/ruff check .",
        "echo x > .venv/bin/pytest; .venv/bin/pytest",
        "echo x > .venv/bin/python; .venv/bin/python -m ruff check .",
        "echo x > .venv/bin/python; .venv/bin/python -m pytest",
        "cp /tmp/evil .venv/bin/mypy; .venv/bin/mypy src",
        "mkdir x; .venv/bin/ruff check .",
        "tee .venv/bin/black < /tmp/x; .venv/bin/black .",
    ],
)
def test_e_a_written_executable_is_never_a_path_qualified_dev_tool(
    command: str, platform: str
) -> None:
    """The program path of a dev tool is only trusted when nothing earlier may have written it."""
    acts = _actions(command, platform)
    reasons = {r for a in acts for r in a.gray_reasons}
    assert "program-path-qualified" in reasons, (command, reasons)
    last = acts[-1]
    assert last.gray, command


@pytest.mark.parametrize("platform", PLATFORMS)
def test_e_harmless_earlier_commands_do_not_block_a_path_qualified_dev_tool(platform: str) -> None:
    for command in (
        "cd src && ./.venv/bin/python -m pytest",
        "ls && ./.venv/bin/pytest -q",
        "echo hi; ./.venv/bin/ruff check .",
        "ruff format . && ./.venv/bin/pytest -q",
        "pytest -q && ./.venv/bin/mypy src",
    ):
        acts = _actions(command, platform)
        last = acts[-1]
        assert last.program in DEVTOOLS
        assert last.gray_reasons == (), (command, last.gray_reasons)


def test_e_an_earlier_redirect_blocks_the_path_qualified_form() -> None:
    acts = _actions("ls > out.txt; ./.venv/bin/pytest")
    assert "program-path-qualified" in acts[-1].gray_reasons


# --- C: operands, option values, the flags that name something to load -----


@pytest.mark.parametrize("platform", PLATFORMS)
def test_c_operands_are_unknown_paths(platform: str) -> None:
    action = _one(
        "pytest tests/test_a.py::TestA::test_x src . -k 'a and b/c' -x --tb=short -n 4", platform
    )
    _is_devtool(action, "pytest")
    assert _paths(action) == [
        ("tests/test_a.py", "unknown"),
        ("src", "unknown"),
        (".", "unknown"),
    ]
    assert all(p.inside_project is True for p in action.paths)
    assert action.flags == ("-k", "-x", "--tb", "-n")
    assert "file_write" in action.risk_tags  # unknown access means "may write"


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("mypy src tests", [("src", "unknown"), ("tests", "unknown")]),
        ("mypy -p pkg -m mod -c 'x = 1'", []),
        ("black --check --diff src", [("src", "unknown")]),
        ("black -l 100 -t py312 -", []),
        ("black -c 'x'", []),
        ("isort --profile black -l 100 src", [("src", "unknown")]),
        ("isort --check-only --diff .", [(".", "unknown")]),
        ("flake8 --max-line-length 100 --extend-ignore E203 src", [("src", "unknown")]),
        ("pylint -j 4 -d C0114 src/pkg", [("src/pkg", "unknown")]),
        ("pylint --disable=all --enable=E src", [("src", "unknown")]),
        ("ruff check --select E,F --fix src", [("src", "unknown")]),
        ("ruff format --line-length 100 .", [(".", "unknown")]),
        ("pytest -p no:cacheprovider", []),
        ("pytest -pno:cacheprovider tests", [("tests", "unknown")]),
        ("pytest -qk smoke", []),
        ("pytest --maxfail=2 --durations 10 tests", [("tests", "unknown")]),
        ("pytest -- tests/a.py", [("tests/a.py", "unknown")]),
        ("pytest ::weird", [("::weird", "unknown")]),
    ],
)
def test_c_option_values_are_not_operands(command: str, expected: list[tuple[str, str]]) -> None:
    action = _one(command)
    assert action.program in DEVTOOLS
    assert [(p.raw, p.access) for p in action.paths] == expected, command


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("tool", TOOLS)
def test_c_risky_flags_stay_flags_in_every_spelling(tool: str, platform: str) -> None:
    assert DEVTOOL_RISKY_FLAGS[tool]
    for flag in DEVTOOL_RISKY_FLAGS[tool]:
        spellings = [f"{tool} {flag} v src", f"python -m {tool} {flag} v src"]
        if flag.startswith("--"):
            spellings += [f"{tool} {flag}=v src", f"{tool} {flag[: len(flag) - 1]}=v src"]
        for command in spellings:
            action = _one(command, platform)
            assert action.program == tool, command
            assert flag in action.flags, (command, action.flags)
            assert action.gray_reasons == (), command


def test_c_the_contract_flags_are_all_listed() -> None:
    contract = {
        "pytest": "-p -c --rootdir --confcutdir --basetemp --junitxml --cov-report",
        "ruff": "--config",
        "mypy": "--config-file --python-executable --install-types --non-interactive "
        "--cache-dir --junit-xml",
        "black": "--config",
        "isort": "--settings-path --settings-file",
        "flake8": "--config --append-config",
        "pylint": "--rcfile --load-plugins --init-hook",
    }
    for tool, flags in contract.items():
        assert set(flags.split()) <= set(DEVTOOL_RISKY_FLAGS[tool]), tool


def test_c_path_valued_risky_flags_also_list_their_value_as_an_unknown_path() -> None:
    action = _one("pytest --rootdir=/etc -c ../x.ini --junitxml out/x.xml")
    assert action.flags == ("--rootdir", "-c", "--junitxml")
    assert sorted(_paths(action)) == [
        ("../x.ini", "unknown"),
        ("/etc", "unknown"),
        ("out/x.xml", "unknown"),
    ]
    assert action.gray_reasons == ()
    action = _one("mypy --config-file /elsewhere/mypy.ini --python-executable /x/python src")
    assert action.flags == ("--config-file", "--python-executable")
    assert ("/x/python", "unknown") in _paths(action)


def test_c_flag_abbreviations_report_the_full_flag() -> None:
    assert "--rootdir" in _one("pytest --root=/x").flags
    assert "--confcutdir" in _one("pytest --confcut=/x").flags
    assert "--config-file" in _one("mypy --config=/x src").flags
    assert "--init-hook" in _one("pylint --init=x src").flags
    assert "--python-executable" in _one("mypy --python-exec /x src").flags
    assert "--settings-path" in _one("isort --settings-p /x .").flags


def test_c_case_of_flags_is_kept_as_typed() -> None:
    action = _one("pytest -X dev -W error -Q")
    assert "-Q" in action.flags
    assert "-q" not in action.flags


@pytest.mark.parametrize("platform", PLATFORMS)
def test_c_word_rules_for_dynamic_operands(platform: str) -> None:
    glob = _one("pytest tests/*.py", platform)
    assert glob.paths[0].uncertain
    assert "glob-not-expanded" in glob.gray_reasons
    lone = _one("pytest $ARGS", platform)
    assert "dynamic-argument-may-be-option" in lone.gray_reasons
    sub = _actions("ruff check $(cat files.txt)", platform)[-1]
    assert sub.program == "ruff"
    assert sub.gray
    cmdsub = _actions("python -m pytest $(cat files.txt)", platform)
    assert any(a.gray for a in cmdsub)


def test_c_argument_files_are_gray() -> None:
    for command in ("pytest @args.txt", "mypy @args.txt", "python -m pytest @args.txt"):
        action = _one(command)
        assert "devtool-argument-file" in action.gray_reasons
        assert ("args.txt", "read") in _paths(action)
    # X1 review of M1c-2 (H-1): ruff reads argument files too (checked against the real tool), and
    # so does every other dev tool: an `@` word is gray for all of them
    for command in ("ruff check @weird", "black @weird", "pylint -k @weird"):
        assert "devtool-argument-file" in _one(command).gray_reasons


def test_c_urls_in_operands_are_still_network() -> None:
    action = _one("pytest https://example.org/x.py")
    assert action.network
    assert action.domains == ("example.org",)


def test_c_secret_and_config_operands_are_seen_by_the_tags() -> None:
    assert "secret_access" in _one("pytest id_rsa").risk_tags
    assert "config_tamper" in _one("pytest --junitxml=.claude/settings.json").risk_tags
    assert "secret_access" in _one("ruff check ~/.ssh/id_rsa").risk_tags


# --- the parser's view -----


def test_parser_rewrites_python_dash_m_into_the_tool() -> None:
    cmd = parse_bash("python -u -m pytest -q tests").commands[0]
    assert [w.text for w in cmd.argv] == ["pytest", "-q", "tests"]
    assert cmd.wrappers == ()
    assert cmd.redirects == ()


def test_parser_adds_the_program_path_as_a_read_redirect() -> None:
    cmd = parse_bash("./.venv/bin/python -m pytest -q").commands[0]
    assert [w.text for w in cmd.argv] == ["pytest", "-q"]
    assert [(r.op, r.target.text if r.target else None, r.fd) for r in cmd.redirects] == [
        ("<", "./.venv/bin/python", "program")
    ]
    cmd = parse_bash("./.venv/bin/pytest -q < in.txt").commands[0]
    assert [w.text for w in cmd.argv] == ["pytest", "-q"]
    assert [r.op for r in cmd.redirects] == ["<", "<"]


def test_parser_leaves_a_bare_tool_alone() -> None:
    cmd = parse_bash("pytest -q").commands[0]
    assert [w.text for w in cmd.argv] == ["pytest", "-q"]
    assert cmd.redirects == ()


def test_the_program_word_keeps_its_quotes_for_the_path() -> None:
    cmd = parse_bash("'C:\\p q\\python.exe' -m pytest").commands[0]
    assert cmd.redirects[0].target is not None
    assert cmd.redirects[0].target.text == "C:\\p q\\python.exe"


# --- classify() directly: the same handler, as a PowerShell caller would reach it -----


def test_classify_known_tools() -> None:
    for tool in TOOLS:
        info = classify(tool, [Word("-q"), Word("src")], shell="bash")  # noqa: S604
        assert info.known
        assert info.subcommand is None
        assert info.gray == ()
        assert "exec" in info.tags
        assert info.flags == ("-q",)
        assert [(w.text, a) for w, a in info.paths] == [("src", "unknown")]


def test_classify_a_code_env_prefix_is_gray() -> None:
    info = classify("pytest", [], shell="bash", env=[("PYTEST_ADDOPTS", Word("-p x"))])  # noqa: S604
    assert info.gray == ("devtool-env-prefix:PYTEST_ADDOPTS", "env-code-injection:PYTEST_ADDOPTS")


def test_exports() -> None:
    assert set(programs.DEVTOOLS) == {
        "pytest",
        "ruff",
        "mypy",
        "black",
        "isort",
        "flake8",
        "pylint",
    }
    assert set(DEVTOOL_RISKY_FLAGS) == set(DEVTOOLS)
