"""Round 3, U-3 (programs part): pure LISTING programs are not recursive reads.

``CmdInfo.recursive`` makes the event layer look for protected names in the subtree of a directory
operand. A command that only lists NAMES (``ls -R``, ``tree``, ``du -a``, ``find`` without -exec,
``Get-ChildItem -Recurse``, ``robocopy /L``, ``rsync --list-only``) leaks no file content, so it
must not be denied because the subtree holds ``.env``; its directory operand is still a path for the
normal path rules. Programs that read CONTENT stay recursive, and the content readers that used to
be only gray (``gzip -r``, ``zstd -r``, ``bsdtar``, ``pax -w``, ``docker cp DIR``) now are too.
Nothing here executes a command: the commands are only classified or reviewed.
"""

# ruff: noqa: S604  (``shell=`` is the dialect argument of classify(), not subprocess)

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from boundkeep.daemon import pipeline
from boundkeep.normalize.model import Word
from boundkeep.normalize.programs import CmdInfo, classify
from boundkeep.policy import Policy, default_policy_text, parse_policy_text

R, W_, U = "read", "write", "unknown"
IS_WIN = sys.platform == "win32"
needs_ps = pytest.mark.skipif(not IS_WIN, reason="needs the PowerShell parser helper")


def run(program: str, args: Sequence[str | Word] = (), *, shell: Any = "bash") -> CmdInfo:
    words = [a if isinstance(a, Word) else Word(a) for a in args]
    return classify(program, words, shell=shell)


def paths(info: CmdInfo) -> set[tuple[str, str]]:
    return {(w.text, access) for w, access in info.paths}


# --- the classification facts --------------------------------------------------------------------

LISTERS = [
    ("ls", ["-R"]),
    ("ls", ["-laR"]),
    ("ls", ["-lR", "src"]),
    ("ls", ["--recursive", "-a"]),
    ("dir", ["-R"]),
    ("tree", []),
    ("tree", ["-a"]),
    ("tree", ["-a", "src"]),
    ("du", ["-a"]),
    ("du", ["-ah", "src"]),
    ("find", ["."]),
    ("find", [".", "-type", "f", "-name", "*.py"]),
    ("find", [".", "-print0"]),
    ("find", [".", "-ls"]),
    ("find", [".", "-fprint", "out.txt"]),
    ("find", [".", "-fprintf", "out.txt", "%p\\n"]),
    ("rsync", ["-a", "--list-only", "src/"]),
]


@pytest.mark.parametrize(("program", "args"), LISTERS)
def test_pure_listers_are_not_recursive_reads(program: str, args: list[str]) -> None:
    assert run(program, args).recursive is False


@pytest.mark.parametrize(
    ("program", "args", "root"),
    [
        ("ls", ["-R"], "."),
        ("ls", ["-laR"], "."),
        ("tree", ["-a"], "."),
        ("du", ["-a"], "."),
        ("find", ["-name", "x"], "."),
    ],
)
def test_listers_still_name_the_current_directory_as_a_read_path(
    program: str, args: list[str], root: str
) -> None:
    assert (root, R) in paths(run(program, args))


def test_listers_still_list_their_directory_operand_for_the_path_rules() -> None:
    assert paths(run("ls", ["-R", "~/.ssh"])) == {("~/.ssh", R)}
    assert paths(run("tree", ["-a", "~/.aws"])) == {("~/.aws", R)}
    assert paths(run("du", ["-a", "/etc"])) == {("/etc", R)}
    assert ("~/.ssh", R) in paths(run("find", ["~/.ssh", "-type", "f"]))
    assert ("out.txt", W_) in paths(run("find", [".", "-fprint", "out.txt"]))


CONTENT_READERS = [
    ("grep", ["-r", "x", "."]),
    ("rg", ["x"]),
    ("ag", ["x"]),
    ("diff", ["-r", "a", "b"]),
    ("tar", ["cf", "x.tar", "."]),
    ("zip", ["-r", "x.zip", "."]),
    ("7z", ["a", "x.7z", "."]),
    ("cp", ["-r", "d", "x"]),
    ("rsync", ["-a", "./", "/tmp/x/"]),
    ("find", [".", "-exec", "cat", "{}", "+"]),
    ("find", [".", "-ok", "cat", "{}", ";"]),
    ("git", ["grep", "x"]),
    ("git", ["archive", "HEAD"]),
    # newly recursive in round 3 (they were only gray before)
    ("gzip", ["-r", "."]),
    ("gzip", ["-rk", "d"]),
    ("gzip", ["--recursive", "d"]),
    ("zstd", ["-r", "d"]),
    ("zstd", ["-r", "-o", "x.zst", "d"]),
    ("bzip2", ["-r", "d"]),
    ("bsdtar", ["cf", "x.tar", "."]),
    ("bsdtar", ["-czf", "x.tgz", "d"]),
    ("gtar", ["cf", "x.tar", "."]),
    ("pax", ["-w", "."]),
    ("pax", ["-w", "-f", "x.tar", "d"]),
    ("pax", ["-rw", "src", "dest"]),
    ("docker", ["cp", ".", "ctr:/x"]),
    ("docker", ["cp", "./dir", "ctr:/x"]),
    ("docker", ["cp", "file.txt", "ctr:/x"]),  # a file operand: the scan of a file is a no-op
    ("podman", ["cp", ".", "ctr:/x"]),
]


@pytest.mark.parametrize(("program", "args"), CONTENT_READERS)
def test_content_readers_stay_recursive(program: str, args: list[str]) -> None:
    assert run(program, args).recursive is True


@pytest.mark.parametrize(
    ("program", "args"),
    [
        ("gzip", ["a.py"]),
        ("gzip", ["-k", "a.py"]),
        ("gzip", ["-d", "a.gz"]),
        ("zstd", ["-o", "x.zst", "a.py"]),
        ("tar", ["xf", "x.tar"]),
        ("bsdtar", ["xf", "x.tar"]),
        ("bsdtar", ["tf", "x.tar"]),
        ("pax", ["-r", "-f", "x.tar"]),
        ("pax", ["-f", "x.tar"]),
        ("docker", ["cp", "ctr:/x", "./out"]),  # the source is in the container
        ("docker", ["ps"]),
    ],
)
def test_ordinary_single_file_operands_are_not_recursive(program: str, args: list[str]) -> None:
    assert run(program, args).recursive is False


def test_gzip_r_operands_are_read_roots() -> None:
    info = run("gzip", ["-r", "d"])
    assert ("d", U) in paths(info)  # compresses (reads) and replaces: may read AND write
    assert info.recursive


def test_bsdtar_and_gtar_are_tar() -> None:
    for name in ("bsdtar", "gtar"):
        info = run(name, ["cf", "x.tar", "~"])
        assert paths(info) == {("x.tar", W_), ("~", R)}
        info = run(name, ["xf", "x.tar"])
        assert "archive-members-unknown" in info.gray


def test_pax_modes() -> None:
    info = run("pax", ["-w", "-f", "out.tar", "d"])
    assert info.recursive
    assert paths(info) == {("out.tar", W_), ("d", R)}
    info = run("pax", ["-w"])  # the names come from stdin
    assert "pax-names-from-stdin" in info.gray
    assert not info.recursive
    info = run("pax", ["-rw", "src", "dest"])
    assert info.recursive
    assert paths(info) == {("src", R), ("dest", W_)}
    assert "directory-write" in info.gray
    info = run("pax", ["-r", "-f", "x.tar"])
    assert not info.recursive
    assert ("x.tar", R) in paths(info)
    assert (".", W_) in paths(info)
    assert "archive-members-unknown" in info.gray
    assert paths(run("pax", ["-f", "x.tar"])) == {("x.tar", R)}  # listing an archive


def test_docker_cp_local_source_is_a_read_root() -> None:
    info = run("docker", ["cp", ".", "ctr:/x"])
    assert (".", R) in paths(info)
    info = run("docker", ["cp", "ctr:/x", "out"])
    assert ("out", W_) in paths(info)
    assert (".", R) not in paths(info)


# --- PowerShell ----------------------------------------------------------------------------------

PS_LISTERS = [
    ("Get-ChildItem", ["-Recurse"]),
    ("Get-ChildItem", ["-Recurse", "-Force", "d"]),
    ("Get-ChildItem", ["-Depth", "2", "d"]),
    ("Get-ChildItem", ["-Recurse", "-Name"]),
    ("Get-ChildItem", ["-Recurse", "-Hidden", "~"]),
    ("tree", ["/f"]),
    ("robocopy", ["src", "dst", "/L", "/E"]),
    ("robocopy", ["src", "dst", "/l"]),
    ("xcopy", ["src", "dst", "/L", "/S"]),
]


@pytest.mark.parametrize(("program", "args"), PS_LISTERS)
def test_powershell_listers_are_not_recursive_reads(program: str, args: list[str]) -> None:
    assert run(program, args, shell="powershell").recursive is False


def test_powershell_listing_keeps_its_path_operands() -> None:
    info = run("Get-ChildItem", ["-Recurse", "~\\.ssh"], shell="powershell")
    assert paths(info) == {("~\\.ssh", R)}
    info = run("Get-ChildItem", ["-Recurse"], shell="powershell")
    assert paths(info) == {(".", R)}  # no path: the current directory
    info = run("Get-ChildItem", ["-Depth", "1"], shell="powershell")
    assert paths(info) == {(".", R)}


@pytest.mark.parametrize(
    ("program", "args"),
    [
        ("Copy-Item", ["-Recurse", "d", "e"]),
        ("Compress-Archive", ["-Path", "~", "-DestinationPath", "x.zip"]),
        ("robocopy", ["src", "dst", "/E"]),
        ("robocopy", ["src", "dst"]),
        ("xcopy", ["src", "dst", "/S"]),
        ("tar", ["cf", "x.tar", "."]),
        ("bsdtar", ["cf", "x.tar", "."]),
        ("gzip", ["-r", "d"]),
        ("docker", ["cp", ".", "ctr:/x"]),
    ],
)
def test_powershell_content_readers_stay_recursive(program: str, args: list[str]) -> None:
    assert run(program, args, shell="powershell").recursive is True


# --- end to end: a made-up project that holds a .env, nothing is executed ------------------------


class World:
    def __init__(self, tmp: Path) -> None:
        self.home = tmp / "home"
        self.proj = self.home / "proj"
        self.proj.mkdir(parents=True)
        self.env = {"USERPROFILE": str(self.home)} if IS_WIN else {"HOME": str(self.home)}
        self.platform = "windows" if IS_WIN else "posix"
        self.policy: Policy = parse_policy_text(default_policy_text(), home=str(self.home))

    def file(self, rel: str, text: str = "CANARY-TEXT") -> None:
        path = self.proj / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def review(self, command: str, tool: str = "Bash") -> pipeline.Review:
        payload = {
            "tool_name": tool,
            "tool_input": {"command": command},
            "cwd": str(self.proj),
            "project_dir": str(self.proj),
        }
        return pipeline.review(
            payload,
            self.policy,
            platform=self.platform,  # type: ignore[arg-type]
            env=self.env,
            home=str(self.home),
        )

    def decision(self, command: str, tool: str = "Bash") -> str:
        return self.review(command, tool).verdict.decision


@pytest.fixture
def w(tmp_path: Path) -> World:
    world = World(tmp_path)
    world.file("src/app.py", "x = 1")
    world.file(".env")
    world.file("sub/deep/.env.production")
    world.file("certs/server.pem")
    return world


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        # M1c: ls, dir, tree and find inside the project are allow rules (names only: the
        # directory listing is not a read of the files below it); before M1c every one was gray
        ("ls -R", "allow"),
        ("ls -laR", "allow"),
        ("ls -R .", "allow"),
        ("ls --recursive", "allow"),
        ("tree", "allow"),
        ("tree -a", "allow"),
        ("du -a", "gray"),  # no allow rule: gray (ask), never deny
        ("find .", "allow"),
        ("find . -type f", "allow"),
        ("find . -name '*.py' -print", "allow"),
        ("find . -fprint out.txt", "gray"),  # writes a file: no allow rule
        ("dir -R", "allow"),
    ],
)
def test_a_listing_is_not_denied_for_the_names_in_the_subtree(
    w: World, command: str, expected: str
) -> None:
    review = w.review(command)
    assert review.verdict.decision == expected, command  # never deny: names only
    assert "no-secret-read" not in review.verdict.rule_ids


def test_the_listed_directory_itself_is_still_judged_by_the_path_rules(w: World) -> None:
    (w.home / ".ssh").mkdir()
    (w.home / ".ssh" / "id_rsa").write_text("CANARY-TEXT", encoding="utf-8")
    for command in ("ls -R ~/.ssh", "tree -a ~/.ssh", "find ~/.ssh -type f", "du -a ~/.ssh"):
        assert w.decision(command) == "deny", command


@pytest.mark.parametrize(
    "command",
    [
        "grep -r CANARY .",
        "grep -rn CANARY",
        "rg CANARY",
        "tar cf x.tar .",
        "bsdtar cf x.tar .",
        "gtar czf x.tgz .",
        "zip -r x.zip .",
        "7z a x.7z .",
        "cp -r . /tmp/x",
        "find . -type f -exec cat {} +",
        "find . -name '*.py' -exec grep CANARY {} \\;",
        "gzip -r .",
        "gzip -rk .",
        "zstd -r .",
        "pax -w .",
        "pax -w -f x.tar .",
        "docker cp . ctr:/x",
        "git grep CANARY",
    ],
)
def test_content_readers_of_a_tree_with_a_protected_file_are_denied(w: World, command: str) -> None:
    review = w.review(command)
    assert review.verdict.decision == "deny", command
    assert "no-secret-read" in review.verdict.rule_ids


@pytest.mark.parametrize(
    "command",
    [
        "gzip -r src",
        "zstd -r src",
        "bsdtar cf x.tar src",
        "pax -w src",
        "docker cp src ctr:/x",
        "docker cp src/app.py ctr:/x",
        "gzip -k src/app.py",
    ],
)
def test_content_readers_of_a_clean_directory_are_not_denied(w: World, command: str) -> None:
    assert w.decision(command) != "deny", command


# a lister whose output is piped into a reader is a different command (the reader): it is gray,
# because the reader takes its operands from the pipe


@pytest.mark.parametrize(
    "command",
    [
        "ls -R | xargs cat",
        "ls -R | xargs -n1 cat",
        "find . | xargs cat",
        "find . -type f -print0 | xargs -0 cat",
        "tree -fi | xargs cat",
    ],
)
def test_a_lister_piped_into_xargs_is_gray_because_the_reader_takes_pipe_arguments(
    w: World, command: str
) -> None:
    review = w.review(command)
    assert review.verdict.decision != "allow", command
    reasons = {r for a in review.actions for r in a.gray_reasons}
    assert "arguments-from-stdin" in reasons, command


@needs_ps
@pytest.mark.parametrize(
    "command",
    [
        "Get-ChildItem -Recurse",
        "Get-ChildItem -Recurse -Force",
        "Get-ChildItem -Recurse -Name",
        "Get-ChildItem -Depth 2",
        "dir -Recurse",
    ],
)
def test_ps_listing_is_not_denied_for_the_names_in_the_subtree(w: World, command: str) -> None:
    review = w.review(command, "PowerShell")
    # M1c: Get-ChildItem is an allow rule (allow-ps-list-here); it was gray before. Names only.
    assert review.verdict.decision == "allow", command
    assert "no-secret-read" not in review.verdict.rule_ids


@needs_ps
@pytest.mark.parametrize(
    "command",
    [
        "Get-ChildItem -Recurse | Get-Content",
        "Get-ChildItem -Recurse | Select-String CANARY",
        "Get-ChildItem -Recurse -Force | Get-Content",
        "dir -Recurse | gc",
        "Get-ChildItem -Recurse | ForEach-Object { Get-Content $_.FullName }",
        "Get-ChildItem -Recurse | % { Get-Content $_ }",
    ],
)
def test_ps_listing_piped_into_a_reader_is_never_allowed(w: World, command: str) -> None:
    assert w.decision(command, "PowerShell") != "allow", command


@needs_ps
def test_ps_listing_of_a_protected_directory_is_still_denied(w: World) -> None:
    (w.home / ".ssh").mkdir()
    (w.home / ".ssh" / "id_rsa").write_text("CANARY-TEXT", encoding="utf-8")
    assert w.decision("Get-ChildItem -Recurse ~\\.ssh", "PowerShell") == "deny"


@needs_ps
@pytest.mark.parametrize(
    "command",
    [
        "Copy-Item -Recurse . ..\\x",
        "Compress-Archive . x.zip",
        "robocopy . ..\\x /E",
        "xcopy . ..\\x /S /E",
        "tar cf x.tar .",
        "bsdtar cf x.tar .",
        "gzip -r .",
    ],
)
def test_ps_content_readers_of_a_tree_with_a_protected_file_are_denied(
    w: World, command: str
) -> None:
    assert w.decision(command, "PowerShell") == "deny", command
