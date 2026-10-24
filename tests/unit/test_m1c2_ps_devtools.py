"""M1c-2 task 1: the dev tools (pytest ruff mypy black isort flake8 pylint) on the PowerShell side.

Three layers are tested: ``psprograms.dev_tool_invocation`` (which words ARE a dev-tool call),
``pscmd.build`` (the SimpleCmd the rest of the normalizer sees) and ``psprograms.classify_ps``
(facts of the call), plus end to end through the real parser helper (Windows only, nothing parsed
here is ever executed). The contract (mirror of the Bash side):

* the Action's ``program`` is the TOOL (``pytest``), also for ``python -m pytest``; ``subcommand``
  None; the ``exec`` tag; NO gray reason and NO wrapper marker;
* a path-qualified program (the tool's or python's ``.exe``) is listed as a READ path operand and
  does not get ``program-path-qualified``;
* flags that point at arbitrary code / config stay FLAGS and their values are not resolved;
* everything that is not exactly the dev-tool form stays as before.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from boundkeep.normalize import programs, psprograms
from boundkeep.normalize.model import Action, Word

from .test_norm_event import WORLDS, run
from .test_norm_pscmd import P, S, V, build, cmd, rep

needs_ps = pytest.mark.skipif(sys.platform != "win32", reason="needs the PowerShell parser helper")
WIN = WORLDS["windows"]
TOOLS = ("pytest", "ruff", "mypy", "black", "isort", "flake8", "pylint")


def W(text: str) -> Word:
    """A word the way pscmd builds it for an external program (``--x`` is a quoted bare word)."""
    return Word(text, quoted=text.startswith("--"))


def ws(*texts: str) -> list[Word]:
    return [W(t) for t in texts]


def texts_of(words: Any) -> list[str]:
    return [w.text for w in words]


# --------------------------------------------------------------------------------------------
# 1. which calls are dev-tool calls
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("spelling", ["{t}", "{t}.exe", "{T}", "{T}.EXE", "{t}.Exe"])
def test_bare_tool_names_are_dev_tools(tool: str, spelling: str) -> None:
    name = spelling.format(t=tool, T=tool.upper())
    got = psprograms.dev_tool_invocation(name, ws("-q", "x"))
    assert got is not None
    assert got.tool == tool
    assert texts_of(got.args) == ["-q", "x"]
    assert got.exe is None


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize(
    "path",
    [
        "E:\\proj\\.venv\\Scripts\\{t}.exe",
        ".\\.venv\\Scripts\\{t}.exe",
        "..\\x\\{t}.EXE",
        "C:/proj/.venv/Scripts/{t}.exe",
        "~\\bin\\{t}.exe",
        "\\\\srv\\share\\{t}.exe",
        "C:\\Program Files (x86)\\x\\{t}.exe",
    ],
)
def test_path_qualified_tool_exe_is_a_dev_tool_with_its_path(tool: str, path: str) -> None:
    text = path.format(t=tool)
    got = psprograms.dev_tool_invocation(text, ws("x"))
    assert got is not None
    assert got.tool == tool
    assert got.exe is not None
    assert got.exe.text == text


@pytest.mark.parametrize("python", ["python", "python3", "python3.12", "python3.9", "py", "PYTHON"])
@pytest.mark.parametrize("ext", ["", ".exe", ".EXE"])
@pytest.mark.parametrize("tool", TOOLS)
def test_python_dash_m_tool(python: str, ext: str, tool: str) -> None:
    got = psprograms.dev_tool_invocation(python + ext, ws("-m", tool, "-q", "x"))
    assert got is not None
    assert got.tool == tool
    assert texts_of(got.args) == ["-q", "x"]
    assert got.exe is None


@pytest.mark.parametrize(
    "path",
    [
        "E:\\p\\.venv\\Scripts\\python.exe",
        ".\\.venv\\Scripts\\python.exe",
        "C:\\Python312\\python.exe",
    ],
)
def test_path_qualified_python_keeps_its_path(path: str) -> None:
    got = psprograms.dev_tool_invocation(path, ws("-m", "pytest", "tests"))
    assert got is not None
    assert got.tool == "pytest"
    assert got.exe is not None
    assert got.exe.text == path
    assert texts_of(got.args) == ["tests"]


@pytest.mark.parametrize(
    "flags",
    [
        ["-I"],
        ["-u"],
        ["-B"],
        ["-E"],
        ["-s"],
        ["-S"],
        ["-q"],
        ["-O"],
        ["-OO"],
        ["-X", "utf8"],
        ["-W", "error"],
        ["-I", "-u", "-B", "-E", "-s", "-S", "-q", "-O", "-OO"],
        ["-X", "dev", "-W", "ignore", "-I"],
        ["-u", "-X", "importtime", "-B"],
    ],
)
def test_harmless_interpreter_flags_before_dash_m(flags: list[str]) -> None:
    got = psprograms.dev_tool_invocation("python", ws(*flags, "-m", "pytest", "--co"))
    assert got is not None
    assert got.tool == "pytest"
    assert texts_of(got.args) == ["--co"]


@pytest.mark.parametrize(
    "args",
    [
        ["-c", "import os"],
        ["-c", "x", "-m", "pytest"],
        ["script.py"],
        ["script.py", "-m", "pytest"],
        [".\\t.py"],
        ["-m", "pip", "install", "x"],
        ["-m", "venv", ".venv"],
        ["-m", "boundkeep", "log"],
        ["-m", "foo"],
        ["-m", "foo", "-m", "pytest"],
        ["-m", "pytestx"],
        ["-m", "PyTest"],
        ["-m", "Pytest"],
        ["-m", "pytest.__main__"],
        ["-m", "ruff.exe"],
        ["-m"],
        ["-mpytest"],
        ["-i", "-m", "pytest"],
        ["-"],
        ["-", "-m", "pytest"],
        ["-b", "-m", "pytest"],
        ["-bb", "-m", "pytest"],
        ["-d", "-m", "pytest"],
        ["-v", "-m", "pytest"],
        ["-3", "-m", "pytest"],
        ["-OOO", "-m", "pytest"],
        ["-Xutf8", "-m", "pytest"],
        ["-Wignore", "-m", "pytest"],
        ["-X"],
        ["-X", "utf8"],
        ["-W"],
        ["--version"],
        ["--help", "-m", "pytest"],
        ["-V"],
        ["-x", "-m", "pytest"],
        ["--", "-m", "pytest"],
        ["-p", "-m", "pytest"],
        [],
        ["pytest"],
    ],
)
def test_other_python_forms_are_not_dev_tool_calls(args: list[str]) -> None:
    assert psprograms.dev_tool_invocation("python", ws(*args)) is None


@pytest.mark.parametrize(
    "args",
    [
        [Word("$x"), Word("-m"), Word("pytest")],
        [Word("-m"), Word("$tool", expands=True)],
        [Word("-m"), Word("pytest", expands=True)],
        [Word("-m"), Word("pytest", glob=True)],
        [Word("-I", expands=True), Word("-m"), Word("pytest")],
        [Word("-X"), Word("$o", expands=True), Word("-m"), Word("pytest")],
        [Word("-W"), Word("e*", glob=True), Word("-m"), Word("pytest")],
    ],
)
def test_a_dynamic_interpreter_word_is_not_a_dev_tool_call(args: list[Word]) -> None:
    assert psprograms.dev_tool_invocation("python", args) is None


@pytest.mark.parametrize(
    "name",
    [
        "pytest.cmd",
        "pytest.bat",
        "pytest.ps1",
        "pytest.py",
        "pytest.exe.bak",
        "pytestx",
        "xpytest",
        "ruffx",
        "ruff-lsp",
        "pytest-xdist",
        "mypyc",
        "dmypy",
        "isort.exe.exe",
        "python2",
        "python4",
        "pythonw",
        "pyw",
        "python3.x",
        "python3.",
        "pythonx",
        "pip",
        "node",
        "npm",
        "uv",
        "git",
        "",
        " ",
        "E:\\p\\Scripts\\ruff",
        "E:\\p\\Scripts\\ruff.cmd",
        "E:\\p\\Scripts\\pytest.ps1",
        ".\\pytest",
        "./ruff",
        "$x\\ruff.exe",
        "E:\\p\\$v\\ruff.exe",
        "E:\\p\\r*.exe",
        "E:\\p\\ruff.exe;x",
        "ruff.exe|x",
        "(ruff)",
    ],
)
def test_names_that_are_not_dev_tools(name: str) -> None:
    assert psprograms.dev_tool_invocation(name, ws("-m", "pytest")) is None
    if name.lower().startswith(("py", "python")):
        return  # (python-like names are also tried with their own argument forms above)
    assert psprograms.dev_tool_invocation(name, ws("x")) is None


def test_the_dev_tool_list_is_the_documented_one() -> None:
    assert frozenset(TOOLS) == psprograms.DEV_TOOLS


# --------------------------------------------------------------------------------------------
# 2. pscmd: the SimpleCmd of a dev-tool call
# --------------------------------------------------------------------------------------------


def one(reply: Any) -> Any:
    res = build(reply)
    assert len(res.commands) == 1
    return res, res.commands[0]


def test_bare_tool_is_unchanged_and_not_gray() -> None:
    res, c = one(rep(cmd("pytest", P("q"), S("tests"))))
    assert texts_of(c.argv) == ["pytest", "-q", "tests"]
    assert c.wrappers == ()
    assert c.env == ()
    assert res.gray == ()
    assert res.exec_reasons == ()


def test_exe_suffix_and_case_are_folded_to_the_tool_name() -> None:
    _, c = one(rep(cmd("RUFF.exe", S("check"), S("."))))
    assert texts_of(c.argv) == ["ruff", "check", "."]
    _, c = one(rep(cmd("Pytest", P("x"))))
    assert texts_of(c.argv) == ["pytest", "-x"]


def test_python_dash_m_tool_becomes_the_tool() -> None:
    res, c = one(rep(cmd("python", P("m"), S("pytest"), P("q"), S("tests"))))
    assert texts_of(c.argv) == ["pytest", "-q", "tests"]
    assert c.wrappers == ()
    assert c.env == ()
    assert res.gray == ()


def test_python_flags_are_dropped_with_the_interpreter() -> None:
    reply = rep(
        cmd(
            "python3.12.exe",
            P("I"),
            P("X"),
            S("utf8"),
            P("W"),
            S("error"),
            P("m"),
            S("mypy"),
            S("src"),
        )
    )
    _, c = one(reply)
    assert texts_of(c.argv) == ["mypy", "src"]


def test_path_qualified_tool_keeps_its_path_in_env_not_in_the_name() -> None:
    path = "E:\\proj\\.venv\\Scripts\\ruff.exe"
    res, c = one(rep(cmd(path, S("check"), S("."))))
    assert texts_of(c.argv) == ["ruff", "check", "."]
    assert c.env == ((psprograms.DEV_EXE_ENV, Word(path)),)
    assert res.gray == ()
    assert res.exec_reasons == ()


def test_path_qualified_python_keeps_its_path_in_env() -> None:
    path = "C:\\Python312\\python.exe"
    _, c = one(rep(cmd(path, P("m"), S("pytest"), S("tests"))))
    assert texts_of(c.argv) == ["pytest", "tests"]
    assert c.env == ((psprograms.DEV_EXE_ENV, Word(path)),)


def test_call_operator_with_a_quoted_path() -> None:
    path = "C:\\Program Files\\Py\\python.exe"
    res, c = one(rep(cmd(path, P("m"), S("black"), S("."), kind="single", invoke="&")))
    assert texts_of(c.argv) == ["black", "."]
    assert c.env == ((psprograms.DEV_EXE_ENV, Word(path, quoted=False)),)
    assert res.gray == ()


@pytest.mark.parametrize(
    "reply",
    [
        rep(cmd("python", P("c"), S("print(1)"))),
        rep(cmd("python", S("script.py"))),
        rep(cmd("python", P("m"), S("pip"), S("install"), S("x"))),
        rep(cmd("python", P("m"), S("venv"), S(".venv"))),
        rep(cmd("python", P("m"), S("foo"), P("m"), S("pytest"))),
        rep(cmd("python", P("i"), P("m"), S("pytest"))),
        rep(cmd("python", P("m"), S("PyTest"))),
        rep(cmd("python", P("m"), V("tool"))),
        rep(cmd("python2", P("m"), S("pytest"))),
        rep(cmd("pythonw", P("m"), S("pytest"))),
        rep(cmd("node", S("x.js"))),
        rep(cmd("npm", S("test"))),
    ],
)
def test_non_dev_tool_forms_keep_the_program_word_and_no_env(reply: Any) -> None:
    res = build(reply)
    (c,) = res.commands
    assert c.argv[0].text == reply["commands"][0]["name"]["v"].lower().replace(".exe", "")
    assert c.env == ()


def test_path_qualified_non_exe_is_not_a_dev_tool_and_stays_script_exec() -> None:
    res, c = one(rep(cmd("E:\\p\\Scripts\\ruff", S("check"))))
    assert c.argv[0].text == "E:\\p\\Scripts\\ruff"
    assert c.env == ()
    assert "ps-script-exec" in res.gray
    res, c = one(rep(cmd(".\\ruff.cmd", S("check"))))
    assert c.argv[0].text == ".\\ruff.cmd"
    assert "ps-script-exec" in res.gray


def test_dynamic_names_and_arguments_stay_gray() -> None:
    res, _ = one(rep(cmd("pytest", V("args", splat=True))))
    assert "ps-dynamic-value:Splat" in res.gray
    res = build(rep(cmd("$tool", S("x"), kind="variable")))
    assert "ps-dynamic-command-name" in res.gray
    res = build(rep(cmd("E:\\p\\$v\\ruff.exe", S("x"))))
    assert "ps-dynamic-command-name" in res.gray


def test_dot_sourcing_a_tool_stays_gray() -> None:
    res, _ = one(rep(cmd("pytest", invoke=".")))
    assert "ps-dot-source" in res.gray


def test_a_shadowed_tool_name_is_dynamic_not_the_tool() -> None:
    reply = rep(cmd("Set-Alias", S("pytest"), S("Remove-Item")), cmd("pytest", S("x")))
    res = build(reply)
    assert "ps-alias-shadowed" in res.gray
    assert res.commands[1].argv[0].text.startswith("$(")
    assert res.commands[1].env == ()


def test_runners_are_not_touched() -> None:
    """``uv run`` still peels to the inner command with its wrapper marker (allow rules skip it)."""
    res, c = one(rep(cmd("uv", S("run"), S("python"), P("m"), S("pytest"))))
    assert texts_of(c.argv) == ["python", "-m", "pytest"]
    assert c.wrappers == ("uv-run",)
    assert c.env == ()
    res, c = one(rep(cmd("uv", S("run"), S("pytest"), P("q"))))
    assert c.argv[0].text == "pytest"
    assert c.wrappers == ("uv-run",)
    assert res.gray == ()


def test_environment_assignment_prefix_stays_compound_gray() -> None:
    reply = rep(cmd("pytest"), compound=("AssignmentStatementAst",))
    res = build(reply)
    assert "ps-compound:AssignmentStatementAst" in res.gray


def test_written_exe_is_gray_when_an_earlier_command_names_it() -> None:
    path = "E:\\p\\.venv\\Scripts\\ruff.exe"
    reply = rep(cmd("Set-Content", S(path), S("x")), cmd(path, S("check")))
    assert "exec-of-written-file" in build(reply).gray
    reply = rep(cmd("Set-Content", S("ruff.exe"), S("x")), cmd(path, S("check")))
    assert "exec-of-written-file" in build(reply).gray
    reply = rep(cmd("Copy-Item", S("C:\\x\\RUFF.EXE"), S("E:\\p\\.venv\\Scripts\\")), cmd(path))
    assert "exec-of-written-file" in build(reply).gray
    reply = rep(cmd("Set-Content", S("r*.exe"), S("x")), cmd(path))
    assert "exec-of-written-file" in build(reply).gray
    reply = rep(cmd("Set-Content", V("f"), S("x")), cmd(path))
    assert "exec-of-written-file" in build(reply).gray
    reply = rep(
        cmd(
            "Set-Content",
            S("a.txt"),
            S("x"),
            redirects=[{"op": ">", "target": S(path), "merge": None}],
        ),
        cmd(path),
    )
    assert "exec-of-written-file" in build(reply).gray


def test_written_exe_check_does_not_fire_for_unrelated_commands() -> None:
    path = "E:\\p\\.venv\\Scripts\\ruff.exe"
    reply = rep(cmd("Set-Content", S("a.txt"), S("x")), cmd(path, S("check")))
    assert "exec-of-written-file" not in build(reply).gray
    # a bare tool name resolves through PATH: nothing lexical to compare
    reply = rep(cmd("Set-Content", S("ruff.exe"), S("x")), cmd("ruff", S("check")))
    assert "exec-of-written-file" not in build(reply).gray


# --------------------------------------------------------------------------------------------
# 3. classify_ps: the facts of a dev-tool call
# --------------------------------------------------------------------------------------------


def info(tool: str, *args: str, env: Any = (), redirects: Any = ()) -> Any:
    return psprograms.classify_ps(tool, ws(*args), env=env, redirects=redirects)


def path_texts(i: Any) -> list[str]:
    return [w.text for w, _ in i.paths]


@pytest.mark.parametrize("tool", TOOLS)
def test_a_plain_call_is_known_exec_and_clean(tool: str) -> None:
    i = info(tool)
    assert i.known is True
    assert "exec" in i.tags
    assert i.gray == ()
    assert i.subcommand is None
    assert i.paths == ()
    assert i.urls == ()
    assert i.network is False


@pytest.mark.parametrize("tool", TOOLS)
def test_operands_are_unknown_access_paths(tool: str) -> None:
    i = info(tool, "src", "tests\\a.py")
    assert i.paths == ((Word("src"), "unknown"), (Word("tests\\a.py"), "unknown"))
    assert "exec" in i.tags
    assert i.gray == ()


def test_short_flags_and_groups_are_flags() -> None:
    i = info("pytest", "-q", "-xv", "tests")
    assert {"-q", "-xv", "-x", "-v"} <= set(i.flags)
    assert path_texts(i) == ["tests"]


def test_pytest_node_ids_name_the_file_only() -> None:
    i = info("pytest", "tests\\test_a.py::TestX::test_y[1-2]", "tests/b.py::t")
    assert path_texts(i) == ["tests\\test_a.py", "tests/b.py"]
    assert all(not w.glob for w, _ in i.paths)
    i = psprograms.classify_ps("pytest", [Word("tests\\*.py::t", glob=True)])
    assert path_texts(i) == ["tests\\*.py"]
    assert i.paths[0][0].glob is True


def test_pytest_node_id_of_an_expansion_is_left_alone() -> None:
    i = psprograms.classify_ps("pytest", [Word("$d\\t.py::x", expands=True)])
    assert path_texts(i) == ["$d\\t.py::x"]


def test_ruff_subcommand_word_is_not_a_path() -> None:
    assert path_texts(info("ruff", "check", "src")) == ["src"]
    assert path_texts(info("ruff", "format", "--check", ".")) == ["."]
    assert path_texts(info("ruff", "--isolated", "check", "src")) == ["src"]
    assert info("ruff", "check").paths == ()
    assert info("ruff", "version").paths == ()
    # only the FIRST operand can be a subcommand
    assert path_texts(info("ruff", "src", "check")) == ["src", "check"]
    assert info("ruff", "check").subcommand is None


def test_a_dynamic_operand_may_be_an_option_so_the_call_is_gray() -> None:
    i = psprograms.classify_ps("pytest", [Word("$args", expands=True)])
    assert "dynamic-argument-may-be-option" in i.gray
    i = psprograms.classify_ps("ruff", [Word("check"), Word("$p", expands=True)])
    assert "dynamic-argument-may-be-option" in i.gray


def test_dash_dash_ends_the_options() -> None:
    i = info("pytest", "--", "-q")
    assert path_texts(i) == ["-q"]
    assert "-q" not in i.flags


def test_redirects_are_written_paths() -> None:
    i = info("pytest", redirects=[psprograms.Redirect(">", Word("out.txt"))])
    assert (Word("out.txt"), "write") in i.paths
    assert "file_write" in i.tags
    assert "exec" in i.tags


def test_exe_path_in_env_is_a_read_operand() -> None:
    exe = Word("E:\\p\\.venv\\Scripts\\ruff.exe")
    i = info("ruff", "check", env=[(psprograms.DEV_EXE_ENV, exe)])
    assert (exe, "read") in i.paths
    assert i.gray == ()
    assert psprograms.DEV_EXE_ENV not in i.flags


def test_real_env_prefixes_of_a_dev_tool_still_make_it_gray_when_they_run_code() -> None:
    i = info("pytest", env=[("PYTHONSTARTUP", Word("x.py"))])
    assert any(r.startswith("env-code-injection") for r in i.gray)


@pytest.mark.parametrize(
    ("tool", "flag", "takes_value"),
    [
        ("pytest", "-p", True),
        ("pytest", "-c", True),
        ("pytest", "--rootdir", True),
        ("pytest", "--confcutdir", True),
        ("pytest", "--basetemp", True),
        ("pytest", "--junitxml", True),
        ("pytest", "--cov-report", True),
        ("pytest", "-o", True),
        ("pytest", "--override-ini", True),
        ("pytest", "--config-file", True),
        ("ruff", "--config", True),
        ("mypy", "--config-file", True),
        ("mypy", "--python-executable", True),
        ("mypy", "--install-types", False),
        ("mypy", "--non-interactive", False),
        ("mypy", "--cache-dir", True),
        ("mypy", "--junit-xml", True),
        ("black", "--config", True),
        ("black", "--settings-path", True),
        ("black", "--settings-file", True),
        ("isort", "--config", True),
        ("isort", "--settings-path", True),
        ("isort", "--settings-file", True),
        ("flake8", "--config", True),
        ("flake8", "--append-config", True),
        ("pylint", "--rcfile", True),
        ("pylint", "--load-plugins", True),
        ("pylint", "--init-hook", True),
    ],
)
def test_dangerous_flags_stay_flags_and_their_values_are_not_resolved(
    tool: str, flag: str, takes_value: bool
) -> None:
    if not takes_value:
        i = info(tool, flag, "src")
        assert flag in i.flags
        assert path_texts(i) == ["src"]
        return
    if flag.startswith("--"):
        for args in ([f"{flag}=VAL.cfg", "src"], [flag, "VAL.cfg", "src"]):
            i = info(tool, *args)
            assert flag in i.flags, args
            assert "VAL.cfg" not in path_texts(i), args
            assert path_texts(i) == ["src"], args
            assert i.gray == (), args
    else:  # a short flag: the value is attached or the next word
        for args in ([flag, "VAL.cfg", "src"], [f"{flag}VAL.cfg", "src"]):
            i = info(tool, *args)
            assert flag in i.flags, args
            assert "VAL.cfg" not in path_texts(i), args
            assert path_texts(i) == ["src"], args


@pytest.mark.parametrize(
    ("tool", "typed", "full"),
    [
        ("pytest", "--rootd", "--rootdir"),
        ("pytest", "--confc", "--confcutdir"),
        ("pytest", "--basetemp", "--basetemp"),
        ("pytest", "--junitx", "--junitxml"),
        ("pytest", "--cov-rep", "--cov-report"),
        ("pytest", "--config", "--config-file"),
        ("pytest", "--override", "--override-ini"),
        ("ruff", "--conf", "--config"),
        ("mypy", "--config", "--config-file"),
        ("mypy", "--python-exec", "--python-executable"),
        ("mypy", "--install", "--install-types"),
        ("mypy", "--non-inter", "--non-interactive"),
        ("mypy", "--cache", "--cache-dir"),
        ("mypy", "--junit", "--junit-xml"),
        ("black", "--conf", "--config"),
        ("isort", "--settings", "--settings-path"),
        ("isort", "--settings", "--settings-file"),
        ("isort", "--sett", "--settings-path"),
        ("isort", "--sp", "--settings-path"),
        ("isort", "--sp", "--settings-file"),
        ("flake8", "--app", "--append-config"),
        ("flake8", "--conf", "--config"),
        ("pylint", "--rc", "--rcfile"),
        ("pylint", "--load", "--load-plugins"),
        ("pylint", "--init", "--init-hook"),
    ],
)
def test_unique_prefixes_of_dangerous_flags_report_the_full_flag_too(
    tool: str, typed: str, full: str
) -> None:
    i = info(tool, f"{typed}=VAL", "src")
    assert full in i.flags, i.flags


@pytest.mark.parametrize(
    ("tool", "flag"),
    [
        ("pytest", "--Rootdir"),
        ("pytest", "--ROOTDIR"),
        ("ruff", "--CONFIG"),
        ("mypy", "--Config-File"),
        ("pytest", "-P"),
        ("pytest", "-C"),
    ],
)
def test_flag_case_is_kept_for_the_matcher_to_fold(tool: str, flag: str) -> None:
    i = info(tool, flag, "VAL", "src")
    assert flag in i.flags  # the matcher folds case for PowerShell actions


def test_safe_common_options_do_not_look_dangerous() -> None:
    i = info(
        "pytest",
        "-k",
        "a or b",
        "-m",
        "not slow",
        "-n",
        "4",
        "--maxfail=2",
        "--tb=short",
        "--cov=src",
        "-W",
        "error",
        "-rA",
        "tests",
    )
    assert path_texts(i) == ["tests"]
    assert "--cov-report" not in i.flags
    assert "-p" not in i.flags
    assert "-c" not in i.flags
    assert "--rootdir" not in i.flags
    assert "--confcutdir" not in i.flags
    assert i.gray == ()
    i = info("ruff", "check", "--fix", "--select", "E,F", "--line-length=100", "src")
    assert path_texts(i) == ["src"]
    assert "--config" not in i.flags
    i = info(
        "mypy", "--strict", "--ignore-missing-imports", "-p", "pkg", "--python-version", "3.12"
    )
    assert path_texts(i) == []
    assert "--python-executable" not in i.flags
    assert "--config-file" not in i.flags
    assert "--install-types" not in i.flags
    i = info("black", "--check", "--line-length", "100", "src")
    assert path_texts(i) == ["src"]
    i = info("flake8", "--max-line-length=100", "--extend-ignore", "E203", "src")
    assert path_texts(i) == ["src"]
    assert "--config" not in i.flags
    assert "--append-config" not in i.flags
    i = info("pylint", "--disable=C0114", "-j", "4", "src")
    assert path_texts(i) == ["src"]
    assert "--rcfile" not in i.flags
    assert "--load-plugins" not in i.flags


@pytest.mark.parametrize(
    ("tool", "args", "written"),
    [
        ("ruff", ["check", "--output-file", "out.txt", "."], "out.txt"),
        ("ruff", ["check", "-o", "out.txt"], "out.txt"),
        ("ruff", ["check", "--cache-dir=.c"], ".c"),
        ("mypy", ["--html-report", "rep", "src"], "rep"),
        ("mypy", ["--txt-report=rep", "src"], "rep"),
        ("flake8", ["--output-file", "o.txt"], "o.txt"),
        ("pylint", ["--output=o.txt", "src"], "o.txt"),
        ("pytest", ["--log-file=l.txt"], "l.txt"),
    ],
)
def test_other_output_file_options_are_resolved_as_written_paths(
    tool: str, args: list[str], written: str
) -> None:
    i = info(tool, *args)
    assert (W(written), "write") in i.paths or any(
        w.text == written and a == "write" for w, a in i.paths
    )


def test_provider_and_url_operands_keep_their_meaning() -> None:
    i = info("pytest", "HKLM:\\Software")
    assert any(r.startswith("ps-provider-path") for r in i.gray)
    i = info("black", "https://example.com/x.py")
    assert i.urls == ("https://example.com/x.py",)


_WORDS = st.builds(
    Word,
    st.text(max_size=14) | st.sampled_from(["-m", "-X", "-W", "-I", "pytest", "ruff", "--", "-p"]),
    st.booleans(),
    st.booleans(),
    st.booleans(),
)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    name=st.text(max_size=20)
    | st.sampled_from(["python", "py", "pytest.exe", "E:\\x\\python3.12.exe", "RUFF"]),
    args=st.lists(_WORDS, max_size=6),
)
def test_arbitrary_words_never_raise_and_a_dev_call_is_always_known(
    name: str, args: list[Word]
) -> None:
    got = psprograms.dev_tool_invocation(name, args)
    if got is None:
        return
    assert got.tool in TOOLS
    info_ = psprograms.classify_ps(got.tool, got.args)
    assert info_.known is True
    assert "exec" in info_.tags


def test_classify_never_raises_on_odd_arguments() -> None:
    for tool in TOOLS:
        for args in (["--"], ["-"], ["", ""], ["--=", "-=x"], ["-\x00"], ["--" + "a" * 5000]):
            got = psprograms.classify_ps(tool, [Word(a) for a in args])
            assert got.known is True


# --------------------------------------------------------------------------------------------
# 4. end to end through the real parser helper (Windows)
# --------------------------------------------------------------------------------------------


def acts(command: str) -> list[Action]:
    return run(WIN, command, tool="PowerShell")


def tool_action(command: str, program: str) -> Action:
    found = [a for a in acts(command) if a.program == program]
    assert len(found) == 1, [(a.program, a.gray_reasons) for a in acts(command)]
    return found[0]


CLEAN_CALLS = [
    ("pytest", "pytest"),
    ("pytest -q tests", "pytest"),
    ("PYTEST -q", "pytest"),
    ("Pytest.EXE -q", "pytest"),
    ("& pytest -q", "pytest"),
    ("& 'pytest' -q", "pytest"),
    ('& "pytest.exe" -q', "pytest"),
    ("pytest -k 'a or b' -x --tb=short tests\\test_a.py::test_x[1]", "pytest"),
    ("ruff check .", "ruff"),
    ("ruff check --fix src", "ruff"),
    ("ruff format --check src", "ruff"),
    ("RUFF check .", "ruff"),
    ("mypy src", "mypy"),
    ("mypy --strict -p boundkeep", "mypy"),
    ("black --check .", "black"),
    ("isort --check-only .", "isort"),
    ("flake8 src", "flake8"),
    ("pylint src", "pylint"),
    ("python -m pytest -q", "pytest"),
    ("python -m pytest", "pytest"),
    ("python3 -m pytest", "pytest"),
    ("python3.12 -m pytest", "pytest"),
    ("py -m pytest", "pytest"),
    ("python.exe -m ruff check .", "ruff"),
    ("PYTHON -m mypy src", "mypy"),
    ("python -I -m pytest", "pytest"),
    ("python -u -B -E -s -S -q -O -OO -m pytest", "pytest"),
    ("python -X utf8 -m pytest", "pytest"),
    ("python -W error -m pytest", "pytest"),
    ("python -X utf8 -W ignore -I -m black --check .", "black"),
    ("python -m black .", "black"),
    ("python -m isort .", "isort"),
    ("python -m flake8", "flake8"),
    ("python -m pylint src", "pylint"),
    ("python -m pytest > out.txt", "pytest"),
    ("python -m pytest 2>&1", "pytest"),
]


@needs_ps
@pytest.mark.parametrize(("command", "program"), CLEAN_CALLS)
def test_clean_dev_tool_call_end_to_end(command: str, program: str) -> None:
    a = tool_action(command, program)
    assert a.program == program
    assert a.subcommand is None
    assert a.wrappers == ()
    assert a.gray is False
    assert a.gray_reasons == ()
    assert "exec" in a.risk_tags
    assert "-m" not in a.flags
    assert "python" not in a.args
    assert "-m" not in a.args
    assert all(act.gray is False for act in acts(command))


@needs_ps
def test_python_dash_m_pytest_arguments_are_the_tools() -> None:
    a = tool_action("python -m pytest -q tests\\test_a.py::t[1]", "pytest")
    assert a.args == ("-q", "tests\\test_a.py::t[1]")
    assert [p.raw for p in a.paths] == ["tests\\test_a.py"]
    assert a.paths[0].access == "unknown"
    assert a.paths[0].inside_project is True


PATH_CALLS = [
    (r".\.venv\Scripts\ruff.exe check .", "ruff", r".\.venv\Scripts\ruff.exe", True),
    (r"& '.\.venv\Scripts\ruff.exe' check .", "ruff", r".\.venv\Scripts\ruff.exe", True),
    (r"& .\.venv\Scripts\ruff.exe check .", "ruff", r".\.venv\Scripts\ruff.exe", True),
    (r".\.VENV\Scripts\RUFF.EXE check .", "ruff", r".\.VENV\Scripts\RUFF.EXE", True),
    (r".\.venv\Scripts\mypy.exe src", "mypy", r".\.venv\Scripts\mypy.exe", True),
    (r".\.venv\Scripts\pytest.exe -q", "pytest", r".\.venv\Scripts\pytest.exe", True),
    (
        r"C:\Users\bob\proj\.venv\Scripts\python.exe -m pytest -q",
        "pytest",
        r"C:\Users\bob\proj\.venv\Scripts\python.exe",
        True,
    ),
    (r"& '.\.venv\Scripts\python.exe' -m pytest -q", "pytest", r".\.venv\Scripts\python.exe", True),
    (r".\.venv\Scripts\python.exe -I -m ruff check .", "ruff", r".\.venv\Scripts\python.exe", True),
    (r"E:\proj\.venv\Scripts\ruff.exe check .", "ruff", r"E:\proj\.venv\Scripts\ruff.exe", False),
    (r"C:\Python312\python.exe -m pytest", "pytest", r"C:\Python312\python.exe", False),
    (r"& 'C:\Python312\python.exe' -m mypy src", "mypy", r"C:\Python312\python.exe", False),
    (r"~\bin\ruff.exe check .", "ruff", r"~\bin\ruff.exe", False),
    (r"..\other\.venv\Scripts\ruff.exe check .", "ruff", r"..\other\.venv\Scripts\ruff.exe", False),
    (r"\\srv\share\python.exe -m pytest", "pytest", r"\\srv\share\python.exe", False),
]


@needs_ps
@pytest.mark.parametrize(("command", "program", "exe", "inside"), PATH_CALLS)
def test_path_qualified_call_lists_the_exe_as_a_read_path_and_is_not_gray(
    command: str, program: str, exe: str, inside: bool
) -> None:
    a = tool_action(command, program)
    assert "program-path-qualified" not in a.gray_reasons
    assert "ps-script-exec" not in a.gray_reasons
    exe_refs = [p for p in a.paths if p.raw == exe]
    assert len(exe_refs) == 1, [p.raw for p in a.paths]
    assert exe_refs[0].access == "read"
    assert (exe_refs[0].inside_project is True) is inside  # (None: not provably inside)
    if "unc-network" in a.gray_reasons:
        assert exe.startswith("\\\\")  # UNC paths stay as they are judged by the path layer
    else:
        assert a.gray is False
    assert "exec" in a.risk_tags
    # X1 re-review R-5: an executable outside any virtual-environment directory is marked so that
    # no allow rule matches it
    unvetted = () if programs.devtool_exe_in_env(exe) else (programs.UNVETTED_EXE,)
    assert a.wrappers == unvetted
    assert a.subcommand is None


@needs_ps
@pytest.mark.parametrize(
    ("command", "program", "flag", "value"),
    [
        ("pytest -p myplug tests", "pytest", "-p", "myplug"),
        ("pytest -pmyplug tests", "pytest", "-p", "myplug"),
        ("pytest -c evil.ini tests", "pytest", "-c", "evil.ini"),
        ("pytest --rootdir=C:\\x tests", "pytest", "--rootdir", "C:\\x"),
        ("pytest --rootdir C:\\x tests", "pytest", "--rootdir", "C:\\x"),
        ("pytest --confcutdir=.. tests", "pytest", "--confcutdir", ".."),
        ("pytest --basetemp=C:\\x tests", "pytest", "--basetemp", "C:\\x"),
        ("pytest --junitxml=C:\\x\\r.xml tests", "pytest", "--junitxml", "C:\\x\\r.xml"),
        ("pytest --cov-report=html:C:\\x tests", "pytest", "--cov-report", "html:C:\\x"),
        ("python -m pytest -p myplug", "pytest", "-p", "myplug"),
        ("python -m pytest --rootdir=C:\\x", "pytest", "--rootdir", "C:\\x"),
        ("ruff check --config C:\\x\\r.toml .", "ruff", "--config", "C:\\x\\r.toml"),
        ("ruff check --config=C:\\x\\r.toml .", "ruff", "--config", "C:\\x\\r.toml"),
        ("mypy --config-file C:\\x\\m.ini src", "mypy", "--config-file", "C:\\x\\m.ini"),
        (
            "mypy --python-executable C:\\x\\py.exe src",
            "mypy",
            "--python-executable",
            "C:\\x\\py.exe",
        ),
        ("mypy --cache-dir=C:\\x src", "mypy", "--cache-dir", "C:\\x"),
        ("mypy --junit-xml C:\\x\\j.xml src", "mypy", "--junit-xml", "C:\\x\\j.xml"),
        ("black --config C:\\x\\b.toml .", "black", "--config", "C:\\x\\b.toml"),
        ("isort --settings-path C:\\x .", "isort", "--settings-path", "C:\\x"),
        ("isort --settings-file=C:\\x\\i.cfg .", "isort", "--settings-file", "C:\\x\\i.cfg"),
        ("flake8 --config C:\\x\\f.cfg src", "flake8", "--config", "C:\\x\\f.cfg"),
        ("flake8 --append-config C:\\x\\f.cfg src", "flake8", "--append-config", "C:\\x\\f.cfg"),
        ("pylint --rcfile=C:\\x\\p.rc src", "pylint", "--rcfile", "C:\\x\\p.rc"),
        ("pylint --load-plugins evilmod src", "pylint", "--load-plugins", "evilmod"),
        ("pylint --init-hook 'import os' src", "pylint", "--init-hook", "import os"),
        ("& 'C:\\Python312\\python.exe' -m pytest -p myplug", "pytest", "-p", "myplug"),
    ],
)
def test_dangerous_flags_end_to_end(command: str, program: str, flag: str, value: str) -> None:
    a = tool_action(command, program)
    assert flag in a.flags
    assert value not in [p.raw for p in a.paths]
    if not command.startswith("& 'C:"):
        assert a.gray is False


@needs_ps
@pytest.mark.parametrize(
    "command",
    [
        "python script.py",
        "python .\\t.py",
        'python -c "print(1)"',
        "python -m pip install x",
        "python -m venv .venv",
        "python -m boundkeep log",
        "python -m foo -m pytest",
        "python -i -m pytest",
        "python -m PyTest",
        "python -mpytest",
        "python -Xutf8 -m pytest",
        "python -b -m pytest",
        "python2 -m pytest",
        "pythonw -m pytest",
        "python -m pytest.__main__",
        "python -m",
        "python -",
        "python --version",
        "node x.js",
        "npm test",
    ],
)
def test_other_python_and_node_forms_are_not_rewritten(command: str) -> None:
    got = acts(command)
    programs_ = [a.program for a in got if a.program is not None]
    assert programs_, command
    assert programs_[0] not in TOOLS or command.startswith(programs_[0]), (command, programs_)
    if command.startswith("python -m boundkeep"):
        assert got[0].program == "boundkeep"
        assert got[0].wrappers == ("python-m",)
    elif command.startswith(("python", "node", "npm")):
        assert programs_[0] in ("python", "python2", "pythonw", "node", "npm"), programs_


@needs_ps
@pytest.mark.parametrize(
    ("command", "reason"),
    [
        ('python -c "import pytest"', "inline-code:-c"),
        (r".\.venv\Scripts\ruff check .", "program-path-qualified"),
        (r".\.venv\Scripts\ruff.cmd check .", "program-path-qualified"),
        ("pytest.cmd", "ps-script-exec"),
        (r".\.venv\Scripts\pytest.exe.bak", "program-path-qualified"),
        ("$env:X='v'; pytest", "ps-compound:AssignmentStatementAst"),
        ("& $tool -q", "ps-dynamic-command-name"),
        ("pytest @args", "ps-dynamic-value:Splat"),
        ("pytest $x", "dynamic-argument-may-be-option"),
        ("python -m pytest $x", "dynamic-argument-may-be-option"),
        ("Set-Alias pytest Remove-Item; pytest x", "ps-alias-shadowed"),
        (". pytest", "ps-dot-source"),
        ("pytest `$(Get-Date)", None),
    ],
)
def test_things_around_dev_tools_stay_gray(command: str, reason: str | None) -> None:
    got = acts(command)
    reasons: set[str] = {r for a in got for r in a.gray_reasons}
    if reason is None:
        return
    assert reason in reasons, (command, reasons)
    assert any(a.gray for a in got)


@needs_ps
def test_uv_run_keeps_its_wrapper_marker() -> None:
    got = acts("uv run pytest -q")
    a = next(a for a in got if a.program == "pytest")
    assert a.wrappers == ("uv-run",)
    got = acts("uv run python -m pytest")
    a = next(a for a in got if a.program == "python")
    assert a.wrappers == ("uv-run",)


@needs_ps
@pytest.mark.parametrize(
    "command",
    [
        "Set-Content t.py 'x'; python -m pytest t.py",
        "Set-Content t.py 'x'; pytest t.py",
        "Set-Content conftest.py 'x'; python -m pytest",
        "Set-Content t.py 'x'; .\\.venv\\Scripts\\python.exe -m pytest t.py",
        "Set-Content .venv\\Scripts\\ruff.exe 'x'; .\\.venv\\Scripts\\ruff.exe check .",
        "cd .venv\\Scripts; Set-Content ruff.exe 'x'; .\\ruff.exe check ..",
        "Copy-Item C:\\Temp\\ruff.exe .venv\\Scripts\\; .\\.venv\\Scripts\\ruff.exe check .",
        "'x' > .venv\\Scripts\\mypy.exe; .\\.venv\\Scripts\\mypy.exe src",
    ],
)
def test_exec_of_written_file_still_fires(command: str) -> None:
    got = acts(command)
    reasons = {r for a in got for r in a.gray_reasons}
    assert "exec-of-written-file" in reasons, (command, reasons)


@needs_ps
def test_a_tool_after_unrelated_writes_is_not_gray() -> None:
    got = acts("Set-Content notes.txt 'x'; ruff check src")
    assert all(not a.gray for a in got)
    got = acts("Set-Content notes.txt 'x'; .\\.venv\\Scripts\\ruff.exe check src")
    assert all(not a.gray for a in got), [(a.program, a.gray_reasons) for a in got]


@needs_ps
def test_compound_line_with_two_tools_gives_two_clean_actions() -> None:
    got = acts("ruff check .; python -m pytest -q; mypy src")
    assert [a.program for a in got] == ["ruff", "pytest", "mypy"]
    assert all(not a.gray for a in got)


@needs_ps
def test_dev_tool_in_a_pipeline_stage_is_still_recognised() -> None:
    got = acts("Get-Content t.txt | python -m pytest -q")
    assert [a.program for a in got] == ["get-content", "pytest"]
    got = acts("python -m pytest -q | Out-String")
    assert got[0].program == "pytest"
    assert not got[0].gray
