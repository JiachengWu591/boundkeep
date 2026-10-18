"""Second security review, M-8 / M-9 (programs part): normalize.programs / psprograms facts.

M-8: "consumer" programs (gzip -k, git mv / add / rm / stash / update-index, rsync
--remove-source-files ...) read their operands, so the operand access is ``unknown`` (may read AND
write) and a read-deny rule sees it. M-9: ``CmdInfo.recursive`` marks the commands that read the
whole subtree of their directory operands; ``REV:PATH`` operands of git are reads of PATH.
"""

# ruff: noqa: S604  (``shell=`` is the dialect argument of classify(), not subprocess)

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

from boundkeep.normalize.bash import parse_bash
from boundkeep.normalize.model import Word
from boundkeep.normalize.programs import CmdInfo, _rev_path, classify, peel_runner

R, W_, U = "read", "write", "unknown"


def run(program: str, args: Sequence[str | Word] = (), *, shell: Any = "bash") -> CmdInfo:
    words = [a if isinstance(a, Word) else Word(a) for a in args]
    return classify(program, words, shell=shell)


def paths(info: CmdInfo) -> set[tuple[str, str]]:
    return {(w.text, access) for w, access in info.paths}


# ------------------------------------------------------------------------------------- M-8

M8_SOURCES = [
    pytest.param("gzip", ["-k", ".env"], {(".env", U)}, id="gzip-k"),
    pytest.param("gzip", [".env"], {(".env", U)}, id="gzip-plain"),
    pytest.param("gunzip", ["x.gz"], {("x.gz", U)}, id="gunzip"),
    pytest.param("bzip2", ["-k", ".env"], {(".env", U)}, id="bzip2-k"),
    pytest.param("xz", ["-k", ".env"], {(".env", U)}, id="xz-k"),
    pytest.param("zstd", ["-o", "x.zst", ".env"], {("x.zst", W_), (".env", U)}, id="zstd-o"),
    pytest.param("zstd", ["--output=x.zst", ".env"], {("x.zst", W_), (".env", U)}, id="zstd-long"),
    pytest.param("lz4", [".env"], {(".env", U)}, id="lz4"),
    pytest.param("gzip", ["-c", ".env"], {(".env", R)}, id="gzip-c-stdout-is-read"),
    pytest.param("gzip", ["-l", "x.gz"], {("x.gz", R)}, id="gzip-list-is-read"),
    pytest.param("git", ["mv", ".env", "x.txt"], {(".env", U), ("x.txt", U)}, id="git-mv"),
    pytest.param("git", ["add", "-f", ".env"], {(".env", U)}, id="git-add-f"),
    pytest.param("git", ["add", ".env"], {(".env", U)}, id="git-add"),
    pytest.param("git", ["update-index", "--add", ".env"], {(".env", U)}, id="git-update-index"),
    pytest.param("git", ["rm", "--cached", ".env"], {(".env", U)}, id="git-rm-cached"),
    pytest.param("git", ["rm", ".env"], {(".env", U)}, id="git-rm"),
    pytest.param("git", ["checkout-index", ".env"], {(".env", U)}, id="git-checkout-index"),
    pytest.param("git", ["stash", "push", ".env"], {(".env", U)}, id="git-stash-push"),
    pytest.param("git", ["stash", "push", "--", ".env"], {(".env", U)}, id="git-stash-push-dd"),
    pytest.param(
        "git", ["stash", "push", "-m", "msg", "secrets/k"], {("secrets/k", U)}, id="stash-m"
    ),
    pytest.param("git", ["commit", "-m", "x", ".env"], {(".env", U)}, id="git-commit-path"),
    pytest.param(
        "rsync",
        ["--remove-source-files", ".env", "/tmp/x"],
        {(".env", U), ("/tmp/x", W_), ("/tmp/x/.env", W_)},
        id="rsync-remove-source",
    ),
]


@pytest.mark.parametrize(("program", "args", "expect"), M8_SOURCES)
def test_m8_source_operands_are_read_and_written(
    program: str, args: list[str], expect: set[tuple[str, str]]
) -> None:
    assert paths(run(program, args)) >= expect


@pytest.mark.parametrize(
    ("program", "args", "path"),
    [
        ("gzip", ["-k", "a.py"], "a.py"),
        ("git", ["mv", "a.py", "b.py"], "a.py"),
        ("git", ["add", "-f", "a.py"], "a.py"),
        ("git", ["rm", "a.py"], "a.py"),
    ],
)
def test_m8_ordinary_operands_get_the_same_access_and_no_gray(
    program: str, args: list[str], path: str
) -> None:
    info = run(program, args)
    assert (path, U) in paths(info)
    assert info.gray == ()  # nothing is unknowable: the verdict stays "no rule matched"


def test_m8_plain_write_programs_are_unchanged() -> None:
    assert paths(run("rm", ["-rf", "x"])) == {("x", W_)}
    assert paths(run("touch", ["f"])) == {("f", W_)}
    assert (".env", W_) in paths(run("git", ["restore", ".env"]))  # restore only overwrites
    assert (".env", W_) in paths(run("git", ["clean", "-f", ".env"]))


def test_m8_moves_and_copies_still_read_the_source() -> None:
    assert {("a", R), ("a", W_)} <= paths(run("mv", ["a", "b"]))
    assert ("a", R) in paths(run("cp", ["a", "b"]))


# ------------------------------------------------------------------------------------- M-9 (b)


@pytest.mark.parametrize(
    ("text", "expect"),
    [
        ("HEAD:.env", ".env"),
        (":.env", ".env"),
        (":0:.env", ".env"),
        (":3:sub/.env", "sub/.env"),
        ("HEAD~1:a/b/.env", "a/b/.env"),
        ("HEAD@{1}:.env", ".env"),
        ("stash@{0}:.env", ".env"),
        ("origin/main:.env", ".env"),
        ("HEAD:./.env", "./.env"),
        ("HEAD", None),
        ("HEAD:", None),
        (":", None),
        ("", None),
        ("-x:y", None),
        ("https://h/x:80", None),
        ("C:\\x\\.env", None),
        ("C:/x/.env", None),
    ],
)
def test_rev_path(text: str, expect: str | None) -> None:
    assert _rev_path(text) == expect


@pytest.mark.parametrize(
    ("args", "path"),
    [
        (["show", "HEAD:.env"], ".env"),
        (["show", ":.env"], ".env"),
        (["show", ":0:.env"], ".env"),
        (["show", "--stat", "HEAD:.env"], ".env"),
        (["cat-file", "-p", "HEAD:.env"], ".env"),
        (["cat-file", "blob", "HEAD:secrets/id_rsa"], "secrets/id_rsa"),
        (["diff", "HEAD~1:.env", "HEAD:.env"], ".env"),
        (["archive", "HEAD", ".env"], ".env"),
        (["archive", "HEAD:secrets"], "secrets"),
        (["grep", "x", "HEAD:.env"], ".env"),
        (["blame", "secrets/key.pem"], "secrets/key.pem"),
        (["blame", "HEAD", "--", "secrets/key.pem"], "secrets/key.pem"),
        (["log", "-L", "1,5:.env"], ".env"),
        (["log", "-L1,5:.env"], ".env"),
        (["log", "-L", ":main:src/a.py"], "src/a.py"),
    ],
)
def test_m9_git_rev_path_and_file_operands_are_reads(args: list[str], path: str) -> None:
    info = run("git", args)
    assert (path, R) in paths(info), info.paths
    assert all(access == R for _, access in info.paths)


def test_m9_rev_path_with_dynamic_rev_keeps_the_dynamic_flag() -> None:
    info = classify("git", [Word("show"), Word("$REV:.env", expands=True)], shell="bash")
    got = [(w.text, w.expands, a) for w, a in info.paths]
    assert (".env", True, R) in got  # the dynamic revision does not make PATH a clean literal


def test_m9_rev_path_in_a_dash_c_directory_is_scoped() -> None:
    info = run("git", ["-C", "proj", "show", "HEAD:.env"])
    assert (".env", R) in paths(info)
    assert ("proj/.env", R) in paths(info)


def test_m9_cat_file_batch_is_gray() -> None:
    assert "git-cat-file-batch" in run("git", ["cat-file", "--batch"]).gray
    assert "git-cat-file-batch" not in run("git", ["cat-file", "-p", "HEAD:a"]).gray


# ------------------------------------------------------------------------------------- M-9 (a)

RECURSIVE_TABLE = [
    # searchers
    ("grep", ["-r", "x", "."], True),
    ("grep", ["-R", "x"], True),
    ("grep", ["--recursive", "x", "d"], True),
    ("grep", ["-rn", "x", "d"], True),
    ("grep", ["-d", "recurse", "x", "d"], True),
    ("grep", ["--directories=recurse", "x", "d"], True),
    ("grep", ["x", "f"], False),
    ("egrep", ["-r", "x", "."], True),
    ("fgrep", ["-r", "x", "."], True),
    ("rg", ["x"], True),
    ("rg", ["--hidden", "x"], True),
    ("rg", ["x", "d"], True),
    ("ag", ["x"], True),
    ("ack", ["x"], True),
    ("diff", ["-r", "a", "b"], True),
    ("diff", ["a", "b"], False),
    # round 3 (U-3): ``ls -R`` only lists names, it is not a recursive READ
    ("ls", ["-R", "~"], False),
    ("ls", ["--recursive"], False),
    ("ls", ["-la"], False),
    # archivers and copiers
    ("tar", ["cf", "x.tar", "~"], True),
    ("tar", ["-czf", "x.tgz", "d"], True),
    ("tar", ["-rf", "x.tar", "d"], True),
    ("tar", ["-uf", "x.tar", "d"], True),
    ("tar", ["-c", "-T", "list", "-f", "x.tar"], True),
    ("tar", ["xf", "x.tar"], False),
    ("tar", ["tf", "x.tar"], False),
    ("zip", ["-r", "x.zip", "."], True),
    ("zip", ["-qr", "x.zip", "d"], True),
    ("zip", ["x.zip", "f"], False),
    ("7z", ["a", "x.7z", "."], True),
    ("7za", ["a", "x.7z", "d"], True),
    ("7z", ["u", "x.7z", "d"], True),
    ("7z", ["x", "x.7z"], False),
    ("7z", ["l", "x.7z"], False),
    ("cp", ["-r", "d", "x"], True),
    ("cp", ["-R", "d", "x"], True),
    ("cp", ["-a", "d", "x"], True),
    ("cp", ["-r", ".", "x"], True),
    ("cp", ["a", "b"], False),
    ("rsync", ["-a", "./", "/tmp/x/"], True),
    ("rsync", ["-r", "d", "/tmp/x"], True),
    ("rsync", ["-avz", "d", "/tmp/x"], True),
    ("rsync", ["a", "/tmp/x"], False),
    # find walks the tree; it READS it with -exec / -ok (round 3, U-3: -fprint only writes NAMES)
    ("find", [".", "-type", "f", "-exec", "cat", "{}", "+"], True),
    ("find", [".", "-execdir", "cat", "{}", ";"], True),
    ("find", [".", "-ok", "cat", "{}", ";"], True),
    ("find", [".", "-fprint", "out"], False),
    ("find", [".", "-name", "x"], False),
    # git
    ("git", ["grep", "SECRET"], True),
    ("git", ["archive", "HEAD"], True),
    ("git", ["log", "-p"], True),
    ("git", ["log", "--patch"], True),
    ("git", ["log", "--cc"], True),
    ("git", ["show"], True),
    ("git", ["show", "HEAD"], True),
    ("git", ["stash", "show", "-p"], True),
    ("git", ["add", "-f", "d"], True),
    ("git", ["log"], False),
    ("git", ["log", "--oneline"], False),
    ("git", ["show", "--stat", "HEAD"], False),
    ("git", ["show", "--name-only"], False),
    ("git", ["status"], False),
    ("git", ["stash", "list"], False),
    ("git", ["add", "a.py"], False),
    ("cat", ["f"], False),
]


@pytest.mark.parametrize(("program", "args", "expect"), RECURSIVE_TABLE)
def test_m9_recursive_flag(program: str, args: list[str], expect: bool) -> None:
    assert run(program, args).recursive is expect


def test_m9_recursive_defaults_to_false_on_cmdinfo() -> None:
    info = CmdInfo(
        known=True, subcommand=None, flags=(), paths=(), urls=(), network=False, tags=(), gray=()
    )
    assert info.recursive is False


@pytest.mark.parametrize(
    ("program", "args", "root"),
    [
        ("grep", ["-r", "x"], "."),
        ("rg", ["x"], "."),
        ("ag", ["x"], "."),
        ("git", ["grep", "x"], "."),
        ("git", ["log", "-p"], "."),
        ("git", ["show"], "."),
        ("git", ["archive", "HEAD"], "."),
        ("git", ["stash", "show", "-p"], "."),
        ("find", ["-exec", "cat", "{}", ";"], "."),
    ],
)
def test_m9_recursive_commands_without_a_path_name_the_current_directory(
    program: str, args: list[str], root: str
) -> None:
    info = run(program, args)
    assert info.recursive
    assert (root, R) in paths(info)


def test_m9_a_restricting_pathspec_replaces_the_current_directory_root() -> None:
    info = run("git", ["log", "-p", "--", "src"])
    assert info.recursive
    assert paths(info) == {("src", R)}
    info = run("git", ["archive", "HEAD", "src"])
    assert info.recursive
    assert ("src", R) in paths(info)
    assert (".", R) not in paths(info)
    info = run("git", ["-C", "proj", "log", "-p"])
    assert info.recursive
    assert ("proj", R) in paths(info)


def test_m9_tar_operands_are_still_read_roots() -> None:
    info = run("tar", ["cf", "x.tar", "~"])
    assert info.recursive
    assert paths(info) == {("x.tar", W_), ("~", R)}


def test_m9_7z_handler_facts() -> None:
    info = run("7z", ["a", "-tzip", "-pSECRET", "x.zip", "d"])
    assert info.known
    assert info.subcommand == "a"
    assert paths(info) == {("x.zip", W_), ("d", R)}
    assert info.recursive
    assert "-pSECRET" not in info.flags  # a switch keeps only its first two characters
    assert "-p" in info.flags
    info = run("7z", ["x", "x.7z", "-oout"])
    assert ("x.7z", R) in paths(info)
    assert ("out", W_) in paths(info)
    assert "archive-members-unknown" in info.gray
    info = run("7z", ["x", "x.7z", "a.txt", "-oout"])
    assert ("out/a.txt", W_) in paths(info)
    assert run("7z", ["a", "-sdel", "x.7z", ".env"]).paths[-1][1] == U


# ------------------------------------------------------------------------------------- M-9 (c)

PS_RECURSIVE = [
    ("Compress-Archive", ["-Path", "~", "-DestinationPath", "x.zip"], True),
    ("Compress-Archive", ["~", "x.zip"], True),
    ("Compress-Archive", ["-Path", "a.txt", "-DestinationPath", "x.zip"], True),
    # round 3 (U-3): a listing is not a recursive read
    ("Get-ChildItem", ["-Recurse", "~"], False),
    ("Get-ChildItem", ["-Recurse"], False),
    ("Get-ChildItem", ["-Depth", "2", "d"], False),
    ("Get-ChildItem", ["d"], False),
    ("Get-ChildItem", ["-Force", "d"], False),
    ("Copy-Item", ["-Recurse", "d", "e"], True),
    ("Copy-Item", ["a.txt", "b.txt"], False),
    ("xcopy", ["~", "h", "/s", "/e", "/h"], True),
    ("xcopy", ["~", "h", "/E"], True),
    ("xcopy", ["~", "h", "/S"], True),
    ("xcopy", ["a.txt", "h"], False),
    ("robocopy", ["~", "h"], True),
    ("robocopy", ["d", "e", "/MIR"], True),
    ("tar", ["cf", "x.tar", "~"], True),
    ("tar.exe", ["cf", "x.tar", "."], True),
    ("tar", ["xf", "x.tar"], False),
    ("7z", ["a", "x.7z", "~"], True),
    ("Get-Content", ["f"], False),
]


@pytest.mark.parametrize(("program", "args", "expect"), PS_RECURSIVE)
def test_m9_powershell_recursive_flag(program: str, args: list[str], expect: bool) -> None:
    info = run(program, args, shell="powershell")
    assert info.recursive is expect, info


def test_m9_powershell_directory_operands_are_read_roots() -> None:
    info = run("Compress-Archive", ["-Path", "~", "-DestinationPath", "x.zip"], shell="powershell")
    assert paths(info) == {("~", R), ("x.zip", W_)}
    info = run("xcopy", ["~", "h", "/s", "/e", "/h"], shell="powershell")
    assert ("~", R) in paths(info)
    assert ("h", W_) in paths(info)
    info = run("tar", ["cf", "x.tar", "~"], shell="powershell")
    assert paths(info) == {("x.tar", W_), ("~", R)}
    info = run("Get-ChildItem", ["-Recurse"], shell="powershell")
    assert paths(info) == {(".", R)}  # no path: the current directory is the root


def test_m9_powershell_single_file_behaviour_is_unchanged() -> None:
    info = run("Get-Content", ["a.txt"], shell="powershell")
    assert paths(info) == {("a.txt", R)}
    assert not info.recursive
    info = run("Copy-Item", ["a.txt", "b.txt"], shell="powershell")
    assert {("a.txt", R), ("b.txt", W_)} <= paths(info)
    assert not info.recursive


def test_m9_powershell_m8_consumers_through_the_bash_tables() -> None:
    assert (".env", U) in paths(run("git", ["mv", ".env", "x.txt"], shell="powershell"))
    assert (".env", U) in paths(run("gzip", ["-k", ".env"], shell="powershell"))
    assert (".env", R) in paths(run("git", ["show", "HEAD:.env"], shell="powershell"))


# ------------------------------------------------------------- boundkeep, runners, python -m

BK_CASES = [
    (["mode", "audit-only"], "mode"),
    (["uninstall"], "uninstall"),
    (["init", "--reset-policy"], "init"),
    (["--home", "D", "uninstall"], "uninstall"),
    (["--home=D", "serve"], "serve"),
    (["--ho", "D", "mode", "enforce"], "mode"),
    (["init", "--scope", "user", "--project-dir", "p"], "init"),
    (["serve"], "serve"),
    (["log", "--tail", "5"], "log"),
]


@pytest.mark.parametrize(("args", "sub"), BK_CASES)
@pytest.mark.parametrize("program", ["boundkeep", "boundkeep-hook"])
def test_boundkeep_subcommand_is_the_first_positional(
    program: str, args: list[str], sub: str
) -> None:
    info = run(program, args)
    assert info.known
    assert info.subcommand == sub


def test_boundkeep_without_arguments_has_no_subcommand() -> None:
    assert run("boundkeep", []).subcommand is None


def test_boundkeep_home_and_project_dir_are_paths() -> None:
    info = run("boundkeep", ["--home", "~/.boundkeep", "uninstall"])
    assert ("~/.boundkeep", U) in paths(info)
    info = run("boundkeep", ["init", "--project-dir", "p"])
    assert ("p", U) in paths(info)


def test_py_launcher_pip_uninstall_has_the_subcommand() -> None:
    assert run("py", ["-m", "pip", "uninstall", "boundkeep"]).subcommand == "uninstall"
    assert run("python", ["-m", "pip", "uninstall", "boundkeep"]).subcommand == "uninstall"


def w(*texts: str) -> list[Word]:
    return [Word(t) for t in texts]


def peeled(*texts: str) -> Any:
    got = peel_runner(w(*texts))
    if got is None or isinstance(got, str):
        return got
    n, marker, synthetic = got
    rest = ([synthetic.text] if synthetic is not None else []) + list(texts)[n:]
    return rest, marker


@pytest.mark.parametrize(
    ("argv", "rest", "marker"),
    [
        (["uv", "run", "boundkeep", "uninstall"], ["boundkeep", "uninstall"], "uv-run"),
        (["uv", "run", "--with", "x", "-p", "3.12", "cmd", "-q"], ["cmd", "-q"], "uv-run"),
        (["uv", "run", "--with=x", "--isolated", "cmd"], ["cmd"], "uv-run"),
        (["uv", "run", "--", "rm", "-rf"], ["rm", "-rf"], "uv-run"),
        (["uv", "run", "--", "--odd"], ["--odd"], "uv-run"),
        (["UV.EXE", "run", "cmd"], ["cmd"], "uv-run"),
        (["uv", "tool", "run", "cmd", "a"], ["cmd", "a"], "uvx"),
        (["uvx", "cmd"], ["cmd"], "uvx"),
        (["uvx", "--from", "pkg", "cmd", "x"], ["cmd", "x"], "uvx"),
        (["pipx", "run", "--spec", "pkg", "cmd"], ["cmd"], "pipx-run"),
        (["poetry", "run", "cmd", "-x"], ["cmd", "-x"], "poetry-run"),
        (["poetry", "run", "-q", "cmd"], ["cmd"], "poetry-run"),
        (
            ["python", "-m", "boundkeep", "mode", "enforce"],
            ["boundkeep", "mode", "enforce"],
            "python-m",
        ),
        (["python3.12", "-u", "-m", "boundkeep", "init"], ["boundkeep", "init"], "python-m"),
        (["py", "-3.12", "-m", "boundkeep", "init"], ["boundkeep", "init"], "python-m"),
        (["python", "-W", "ignore", "-m", "boundkeep", "x"], ["boundkeep", "x"], "python-m"),
        (["python", "-mboundkeep", "x"], ["boundkeep", "x"], "python-m"),
        (["/usr/bin/python3", "-m", "boundkeep"], ["boundkeep"], "python-m"),
    ],
)
def test_peel_runner(argv: list[str], rest: list[str], marker: str) -> None:
    assert peeled(*argv) == (rest, marker)


@pytest.mark.parametrize(
    "argv",
    [
        ["uv"],
        ["uv", "run"],
        ["uv", "pip", "install", "x"],
        ["uv", "tool", "install", "x"],
        ["uvx"],
        ["pipx", "install", "x"],
        ["poetry", "install"],
        ["python", "-m", "pip", "install"],
        ["python", "-m", "http.server"],
        ["python", "-c", "x"],
        ["python", "script.py"],
        ["python", "-m"],
        ["python", "-Wm", "boundkeep"],
        ["ls", "-m", "boundkeep"],
        [],
    ],
)
def test_peel_runner_ignores_everything_else(argv: list[str]) -> None:
    assert peel_runner(w(*argv)) is None


@pytest.mark.parametrize(
    "argv",
    [
        ["uv", "run", "--weird", "boundkeep", "uninstall"],
        ["uv", "run", "-m", "boundkeep"],
        ["uvx", "--bogus", "x"],
        ["poetry", "run", "--bogus", "x"],
    ],
)
def test_peel_runner_unsure_options_are_reported(argv: list[str]) -> None:
    assert peel_runner(w(*argv)) == "unsure"


def test_peel_runner_dynamic_words() -> None:
    assert peel_runner([Word("uv"), Word("run"), Word("$X", expands=True), Word("a")]) == "unsure"
    got = peel_runner([Word("uv"), Word("run"), Word("$X/cmd", expands=True)])
    assert got == (2, "uv-run", None)
    assert peel_runner([Word("$X", expands=True), Word("run"), Word("a")]) is None
    assert peel_runner([Word("python"), Word("-m", expands=True), Word("boundkeep")]) is None


def commands(text: str) -> list[tuple[list[str], tuple[str, ...]]]:
    return [([x.text for x in c.argv], c.wrappers) for c in parse_bash(text).commands]


def test_bash_parser_peels_runners_with_a_marker() -> None:
    assert commands("uv run boundkeep uninstall") == [(["boundkeep", "uninstall"], ("uv-run",))]
    assert commands("sudo uv run rm -rf ~") == [(["rm", "-rf", "~"], ("sudo", "uv-run"))]
    assert commands("uv run python -m boundkeep mode x") == [
        (["boundkeep", "mode", "x"], ("uv-run", "python-m"))
    ]
    assert commands("python -m boundkeep init") == [(["boundkeep", "init"], ("python-m",))]
    assert commands("python -mboundkeep init") == [(["boundkeep", "init"], ("python-m",))]
    assert commands("uv pip install x") == [(["uv", "pip", "install", "x"], ())]
    assert commands("python -m pip install x") == [(["python", "-m", "pip", "install", "x"], ())]


def test_bash_parser_grays_runner_with_unknown_options() -> None:
    res = parse_bash("uv run --weird boundkeep uninstall")
    assert "wrapper-options:uv" in res.gray
    assert [x.text for x in res.commands[0].argv] == [
        "uv",
        "run",
        "--weird",
        "boundkeep",
        "uninstall",
    ]
