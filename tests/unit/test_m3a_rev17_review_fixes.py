"""Spec revision 18: the findings of the review of revision 17 (docs/reviews/M3a-rev17-review.md)
and the two found while fixing them. Each was measured with real git or Git Bash:

- R17-1: ``git diff HEAD:src`` compares the sub-tree as if it were the root and prints every
  tracked file (the fake ``.env`` and key); a rule allowed it.
- ``git show HEAD HEAD:src`` prints all of HEAD; the ``REV:PATH`` beside the commit kept the
  tree from being scanned, and a rule allowed it.
- R17-3: ``git archive ':/seed'`` packs the whole tree of the commit found by its message.
- R17-4: ``git archive --mtime 2020-01-01 HEAD``: the option was not in the table, so its value
  was taken for the tree-ish and ``HEAD`` for a pathspec that narrowed the scan.
- From a sub-directory ``git log -p``, ``git show HEAD``, ``git stash show -p`` still print the
  whole repository, and ``:/secrets`` is the top's ``secrets``; only the sub-directory was read,
  so a rule allowed them. ``git grep`` and ``git archive`` do act on the current directory.
- R17-2: Git Bash runs ``.../BOUNDK~1`` as ``.../BOUNDK~1.exe``, and a bare ``BOUNDK~1`` found by
  PATH. PowerShell 5.1 runs neither.

The tree tests use real directories with made-up files; nothing is run.
"""

from __future__ import annotations

import ctypes
import os
import re
import sys
from pathlib import Path

import pytest

from boundkeep.daemon import pipeline
from boundkeep.normalize import programs
from boundkeep.normalize.model import Word
from boundkeep.policy import default_policy_text, parse_policy_text

SHELL_TOOLS = ["Bash", pytest.param("PowerShell", marks=pytest.mark.windows)]
FULL = ["src/a.py", "README.md", ".env", "secrets/id_rsa", "sub/b.txt"]
CLEAN = ["src/a.py", "README.md", "docs/b.md", "sub/b.txt"]


def _result(
    tmp_path: Path, files: list[str], command: str, *, tool: str, cwd: str = "", path: str = ""
) -> pipeline.Review:
    project = tmp_path / "proj"
    (project / ".git").mkdir(parents=True, exist_ok=True)
    for name in files:
        target = project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("made up\n", encoding="utf-8")
    home = str(tmp_path / "home")
    os.makedirs(home, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if k.upper() in ("SYSTEMROOT", "PATH", "TEMP")}
    if path:
        env["PATH"] = path + os.pathsep + env.get("PATH", "")
    env["USERPROFILE"] = env["HOME"] = home
    runtime, _problem = pipeline.runtime_policy_checked(
        parse_policy_text(default_policy_text(), home=home), env, home
    )
    payload = {
        "tool_name": tool,
        "tool_input": {"command": command},
        "cwd": str(project / cwd) if cwd else str(project),
        "project_dir": str(project),
        "session_id": "s",
    }
    return pipeline.review(payload, runtime, platform=pipeline.local_platform(), env=env, home=home)


def _review(
    tmp_path: Path, files: list[str], command: str, *, tool: str, cwd: str = "", path: str = ""
) -> tuple[str, list[str], list[str]]:
    """(verdict, rule ids, gray reasons) for ``command`` in a real project with ``files``."""
    result = _result(tmp_path, files, command, tool=tool, cwd=cwd, path=path)
    grays = [r for a in result.actions for r in a.gray_reasons]
    return str(result.verdict.decision), list(result.verdict.rule_ids), grays


def _top(*args: str) -> set[str]:
    words = [Word(a, quoted=a.startswith(":")) for a in args]
    info = programs.classify("git", words, shell="bash")  # noqa: S604 - a dialect
    return {w.text for w, _access in info.top_paths}


# --- R17-1: ``git diff`` with a sub-tree ---------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "git diff HEAD:src",
        "git diff HEAD:secrets",
        "git diff HEAD HEAD:src",
        "git diff HEAD:src HEAD",
        "git diff --cached HEAD:src",
        "git diff -p --stat HEAD:src",
    ],
)
@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_a_diff_against_a_sub_tree_reads_the_whole_repository(
    tmp_path: Path, command: str, tool: str
) -> None:
    verdict, rules, grays = _review(tmp_path, FULL, command, tool=tool)
    assert verdict == "deny", (command, rules, grays)


@pytest.mark.parametrize(
    "command",
    [
        "git diff HEAD~1",  # IR-7 is the user's call: not changed
        "git diff",
        "git diff HEAD:src HEAD~1:src",  # two sub-trees: only src
        "git diff HEAD:src/a.py HEAD~1:src/a.py",  # two blobs
        "git diff --stat HEAD:src",  # names and counts only
        "git diff HEAD:src -- a.py",  # a.py and src
    ],
)
@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_other_diffs_are_still_allowed(tmp_path: Path, command: str, tool: str) -> None:
    verdict, rules, grays = _review(tmp_path, FULL, command, tool=tool)
    assert verdict == "allow", (command, rules, grays)


@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_a_diff_against_a_sub_tree_of_a_clean_project_is_allowed(tmp_path: Path, tool: str) -> None:
    verdict, rules, grays = _review(tmp_path, CLEAN, "git diff HEAD:src", tool=tool)
    assert verdict == "allow", (rules, grays)


# --- ``git show`` with a commit beside a REV:PATH ----------------------------------------------


@pytest.mark.parametrize(
    "command", ["git show HEAD HEAD:src", "git show HEAD:src HEAD", "git show HEAD :src/a.py"]
)
@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_a_commit_beside_a_rev_path_is_shown_whole(tmp_path: Path, command: str, tool: str) -> None:
    verdict, rules, grays = _review(tmp_path, FULL, command, tool=tool)
    assert verdict == "deny", (command, rules, grays)


@pytest.mark.parametrize(
    "command", ["git show HEAD:src", "git show HEAD:src/a.py HEAD:README.md", "git show :src/a.py"]
)
@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_rev_paths_alone_are_still_allowed(tmp_path: Path, command: str, tool: str) -> None:
    verdict, rules, grays = _review(tmp_path, FULL, command, tool=tool)
    assert verdict == "allow", (command, rules, grays)


# --- R17-3, R17-4: ``git archive`` ---------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "git archive ':/seed'",
        "git archive -- ':/seed'",
        "git archive -o x.tar ':/seed'",
        "git archive --mtime 2020-01-01 HEAD",
        "git archive --add-virtual-file a.txt:b HEAD",
        "git archive --no-such-option x HEAD:src",  # may eat the next word: no narrowing
    ],
)
@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_these_archives_read_the_whole_tree(tmp_path: Path, command: str, tool: str) -> None:
    verdict, rules, grays = _review(tmp_path, FULL, command, tool=tool)
    assert verdict == "deny", (command, rules, grays)


@pytest.mark.parametrize(
    "command",
    [
        "git archive HEAD:src",
        "git archive HEAD src",
        "git archive --mtime 2020-01-01 HEAD src",
        "git archive --mtime=2020-01-01 HEAD:src",
        "git archive --verbose HEAD:src",
    ],
)
@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_a_narrowed_archive_is_not_denied(tmp_path: Path, command: str, tool: str) -> None:
    verdict, rules, grays = _review(tmp_path, FULL, command, tool=tool)
    assert verdict != "deny", (command, rules, grays)


# --- reads of the whole repository from a sub-directory -----------------------------------------


def test_which_commands_read_from_the_top() -> None:
    assert _top("log", "-p") == {""}
    assert _top("show", "HEAD") == {""}
    assert _top("stash", "show", "-p") == {""}
    assert _top("diff", "HEAD:src") == {""}
    assert _top("log", "-p", "--", ":/secrets") == {"secrets"}
    assert _top("log", "-p", ":/secrets") == {"", "secrets"}  # before --: maybe a commit (rev. 17)
    assert _top("log", "-p", ":(top)src") == {"src"}
    assert _top("log", "-p", ":!b.txt") == {""}
    assert _top("checkout", ":(top).claude/settings.json") == {".claude/settings.json"}
    # the current directory: grep and archive act on it; a plain pathspec is relative to it
    assert _top("grep", "-e", "x") == set()
    assert _top("grep", "-e", "x", ":!b.txt") == set()  # an exclusion alone: still there
    assert _top("grep", "-e", "x", ":(top)") == {""}  # but ``top`` reaches the top (measured)
    assert _top("archive", "HEAD") == set()
    assert _top("log", "-p", "--", "b.txt") == set()
    assert _top("log", "--oneline") == set()
    # another repository
    assert _top("-C", "..", "log", "-p") == set()
    assert _top("--git-dir", "x/.git", "log", "-p", ":/secrets") == set()


@pytest.mark.parametrize(
    "command",
    [
        "git log -p",
        "git show HEAD",
        "git stash show -p",
        "git log -p ':/secrets'",
        "git log -p ':(top)'",
        "git log -p ':!b.txt'",
        "git diff HEAD:src",
    ],
)
@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_from_a_sub_directory_the_whole_repository_is_read(
    tmp_path: Path, command: str, tool: str
) -> None:
    verdict, rules, grays = _review(tmp_path, FULL, command, tool=tool, cwd="sub")
    assert verdict == "deny", (command, rules, grays)


@pytest.mark.parametrize(
    "command",
    [
        "git log -p -- .",
        "git log -p -- b.txt",
        "git log -p ':(top)src'",
        "git log --oneline",
        "git status",
        "git diff",
    ],
)
@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_from_a_sub_directory_these_are_still_allowed(
    tmp_path: Path, command: str, tool: str
) -> None:
    verdict, rules, grays = _review(tmp_path, FULL, command, tool=tool, cwd="sub")
    assert verdict == "allow", (command, rules, grays)


@pytest.mark.parametrize("command", ["git grep -e x", "git archive HEAD"])
@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_grep_and_archive_act_on_the_current_directory(
    tmp_path: Path, command: str, tool: str
) -> None:
    verdict, rules, grays = _review(tmp_path, FULL, command, tool=tool, cwd="sub")
    assert verdict != "deny", (command, rules, grays)


@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_a_working_directory_outside_the_project_is_another_repository(
    tmp_path: Path, tool: str
) -> None:
    # git there acts on that repository, not on the project: its root is not read
    other = tmp_path / "other"
    (other / ".git").mkdir(parents=True)
    (other / "c.txt").write_text("made up\n", encoding="utf-8")
    verdict, rules, grays = _review(tmp_path, FULL, "git log -p", tool=tool, cwd="../other")
    assert verdict != "deny", (rules, grays)


@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_at_the_root_nothing_is_read_twice(tmp_path: Path, tool: str) -> None:
    # the project root is the working directory: the same verdicts as before revision 18
    for command, want in (("git log -p ':(top)src'", "allow"), ("git log -p", "deny")):
        verdict, rules, grays = _review(tmp_path, FULL, command, tool=tool)
        assert verdict == want, (command, rules, grays)


# --- R17-2: 8.3 short names in Git Bash ---------------------------------------------------------


def _short_path(path: Path) -> str:
    buf = ctypes.create_unicode_buffer(1024)
    if not ctypes.windll.kernel32.GetShortPathNameW(str(path), buf, 1024):  # type: ignore[attr-defined]
        return str(path)
    return buf.value


@pytest.fixture
def short_boundkeep(tmp_path: Path) -> tuple[str, str]:
    """(the 8.3 short path, its directory) of a made-up ``boundkeep.exe``."""
    if sys.platform != "win32":
        pytest.skip("8.3 short names are a Windows thing")
    tools = tmp_path / "longtoolsdirectory"
    tools.mkdir()
    target = tools / "boundkeep.exe"
    target.write_bytes(b"MZ")
    short = _short_path(target)
    if not re.search(r"~\d+\.EXE$", short, re.IGNORECASE):
        pytest.skip("this volume makes no 8.3 short names")
    return short, str(tools)


def _msys(path: str) -> str:
    return "/" + path[0].lower() + path[2:].replace("\\", "/")


@pytest.mark.windows
def test_git_bash_finds_a_short_name_without_exe(
    tmp_path: Path, short_boundkeep: tuple[str, str]
) -> None:
    short, _tools = short_boundkeep
    for word in (_msys(short), _msys(short)[:-4]):
        command = f"'{word}' mode audit-only"
        verdict, rules, grays = _review(tmp_path / "w", CLEAN, command, tool="Bash")
        assert verdict == "deny", (command, grays)
        assert "deny-boundkeep-state-commands" in rules
        assert "program-short-name" in grays


@pytest.mark.windows
def test_a_short_name_with_no_file_even_with_exe_stays_gray(
    tmp_path: Path, short_boundkeep: tuple[str, str]
) -> None:
    short, _tools = short_boundkeep
    command = "'{}' mode audit-only".format(_msys(short.rsplit("\\", 1)[0]) + "/NOSUCH~1")
    verdict, rules, grays = _review(tmp_path / "w", CLEAN, command, tool="Bash")
    assert verdict != "allow", (command, rules)
    assert "program-short-name" not in grays


@pytest.mark.windows
@pytest.mark.parametrize("name", ["BOUNDK~1", "BOUNDK~1.EXE", "boundk~1"])
def test_a_bare_short_name_in_git_bash_is_not_sent_to_the_model(
    tmp_path: Path, short_boundkeep: tuple[str, str], name: str
) -> None:
    _short, tools = short_boundkeep
    command = f"{name} mode audit-only"
    result = _result(tmp_path / "w", CLEAN, command, tool="Bash", path=tools)
    grays = [r for a in result.actions for r in a.gray_reasons]
    assert str(result.verdict.decision) != "allow"
    assert "program-short-name-unresolved" in grays
    assert pipeline.unshown_input(result.actions) is not None


@pytest.mark.windows
def test_powershell_and_plain_names_are_not_affected(
    tmp_path: Path, short_boundkeep: tuple[str, str]
) -> None:
    _short, tools = short_boundkeep
    # PowerShell 5.1 does not run a bare short name (measured): nothing to add there
    _v, _r, grays = _review(tmp_path / "w", CLEAN, "BOUNDK~1 mode audit-only", tool="PowerShell")
    assert "program-short-name-unresolved" not in grays
    for command in ("git status", "boundkeep mode audit-only", "ls"):
        _v, _r, grays = _review(tmp_path / "w", CLEAN, command, tool="Bash", path=tools)
        assert "program-short-name-unresolved" not in grays, command
