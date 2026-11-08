"""Revision 17: git operands before ``--`` that begin with ``:`` (IR-2), ``REV:dir`` of ``git
archive`` and ``git grep`` (IR-3), and 8.3 short program names (IR-4).

The independent review of revisions 13 to 16 (docs/reviews/M3a-rev13-16-independent-review.md)
found three old ways past a deny rule, each measured with real git or PowerShell 5.1:

- IR-2: ``git show ':!README.md'`` read the word only as the index path ``!README.md`` and did not
  scan the work tree, so a rule allowed it; git takes it as a pathspec and prints ``.env``.
  ``git checkout ':(top).claude/settings.json'`` had no path at all; git restores that file.
- IR-3: ``git archive HEAD:secrets`` and ``git grep -e x HEAD:secrets`` read only the directory
  name, not what is below it; git packs / searches every file there. ``git archive -- HEAD:x``:
  git's option parser takes that ``--``, so ``HEAD:x`` is still the tree-ish.
- IR-4: ``& 'C:\\tools\\BOUNDK~1.EXE' mode audit-only`` runs ``boundkeep.exe``; the name read as
  ``boundk~1`` and ``deny-boundkeep-state-commands`` did not see it.

The tree tests use real directories with made-up files; nothing is run.
"""

from __future__ import annotations

import ctypes
import os
import re
import sys
from pathlib import Path

import pytest

from boundkeep import protocol
from boundkeep.audit.auditor import Auditor
from boundkeep.audit.backends.base import verdict_json
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.normalize import programs
from boundkeep.normalize.model import Word
from boundkeep.policy import default_policy_text, parse_policy_text

SHELL_TOOLS = ["Bash", pytest.param("PowerShell", marks=pytest.mark.windows)]
FULL = ["src/a.py", "README.md", ".env", "secrets/id_rsa", ".claude/settings.json"]
CLEAN = ["src/a.py", "README.md", "docs/b.md"]
ROOT_ENV_ONLY = ["src/a.py", "README.md", ".env"]


def _review(
    tmp_path: Path, files: list[str], command: str, *, tool: str = "Bash", cwd: str = ""
) -> tuple[str, list[str], list[str], list[str]]:
    """(verdict, rule ids, gray reasons, programs) for ``command`` in a real project with
    ``files``."""
    project = tmp_path / "proj"
    (project / ".git").mkdir(parents=True, exist_ok=True)
    for name in files:
        target = project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("made up\n", encoding="utf-8")
    home = str(tmp_path / "home")
    os.makedirs(home, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if k.upper() in ("SYSTEMROOT", "PATH", "TEMP")}
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
    result = pipeline.review(
        payload, runtime, platform=pipeline.local_platform(), env=env, home=home
    )
    grays = [r for a in result.actions for r in a.gray_reasons]
    progs = [str(a.program) for a in result.actions]
    return str(result.verdict.decision), list(result.verdict.rule_ids), grays, progs


# --- the kinds of a ``:`` operand --------------------------------------------------------------


@pytest.mark.parametrize(
    ("word", "kind"),
    [
        (":.env", "index"),
        (":0:.env", "index"),
        (":/fix", "search"),
        (":/", "search"),
        (":/:src", "search"),
        (":!README.md", "pathspec"),
        (":^x", "pathspec"),
        (":(top)src", "pathspec"),
        ("::x", "pathspec"),
        ("HEAD:.env", None),
        ("src", None),
    ],
)
def test_the_kind_of_a_colon_operand(word: str, kind: str | None) -> None:
    assert programs._colon_kind(word) == kind


def _path_texts(*args: str) -> set[str]:
    words = [Word(a, quoted=a.startswith(":")) for a in args]
    info = programs.classify("git", words, shell="bash")  # noqa: S604 - a dialect
    return {w.text for w, _access in info.paths}


def test_operands_that_are_no_pathspecs_are_not_read_as_paths() -> None:
    # ``cat-file`` names objects only; the tree-ish of ``archive`` is a revision, also after ``--``
    assert "./src" in _path_texts("show", ":(top)src")  # the control: show takes a pathspec
    assert "./src" not in _path_texts("cat-file", "-p", ":(top)src")
    archived = _path_texts("archive", "--", "HEAD:src")
    assert "src" in archived  # the REV:PATH reading of the tree-ish
    assert not any(t.startswith("HEAD") for t in archived), archived


# --- IR-2: a ``:`` operand before ``--`` is also a pathspec ------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "git show ':!README.md'",
        "git show ':^README.md'",
        "git show ':(exclude)README.md'",
        "git show ':(top)'",
        "git show ':(top)secrets'",
        "git show HEAD ':!README.md'",
        "git show ':/fix'",  # a commit found by its message: the whole commit is printed
        "git grep FAKE ':(top)'",
        "git grep FAKE ':!README.md'",
        "git grep 'key:value'",  # the pattern is no REV:PATH that scopes the search
        "git log -p ':!README.md'",
        "git log -p ':/fix'",
    ],
)
@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_content_commands_with_magic_before_the_dashes_scan_the_tree(
    tmp_path: Path, command: str, tool: str
) -> None:
    verdict, rules, grays, _ = _review(tmp_path, FULL, command, tool=tool)
    assert verdict == "deny", (command, rules, grays)
    plain, _r, _g, _p = _review(tmp_path, FULL, "git show", tool=tool)
    assert plain == "deny"  # the spelling without magic, for comparison


@pytest.mark.parametrize(
    "command",
    ["git show ':!README.md'", "git show ':(top)'", "git show ':(top)secrets'"],
)
@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_without_protected_names_they_are_still_allowed(
    tmp_path: Path, command: str, tool: str
) -> None:
    verdict, rules, grays, _ = _review(tmp_path, CLEAN, command, tool=tool)
    assert verdict == "allow", (command, rules, grays)


@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_a_pathspec_before_the_dashes_scopes_the_read_like_one_after_them(
    tmp_path: Path, tool: str
) -> None:
    # git reads only src here: the same verdict as the spelling with ``--`` (spec revision 16)
    for command in ("git log -p ':(top)src'", "git show ':(top)src'"):
        verdict, rules, grays, _ = _review(tmp_path, ROOT_ENV_ONLY, command, tool=tool)
        dashed = command.replace(" ':(top)src'", " -- ':(top)src'")
        assert verdict == _review(tmp_path, ROOT_ENV_ONLY, dashed, tool=tool)[0], command
        assert verdict == "allow", (command, rules, grays)


@pytest.mark.parametrize(
    ("command", "rule"),
    [
        ("git log -p ':(top).env'", "no-secret-read"),
        ("git diff ':(top).env'", "no-secret-read"),
        ("git checkout ':(top).claude/settings.json'", "protect-guard-config"),
        ("git checkout ':/.claude/settings.json'", "protect-guard-config"),
        ("git checkout '::.claude/settings.json'", "protect-guard-config"),
    ],
)
@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_a_protected_name_behind_magic_before_the_dashes_is_denied(
    tmp_path: Path, command: str, rule: str, tool: str
) -> None:
    verdict, rules, grays, _ = _review(tmp_path, CLEAN, command, tool=tool)
    assert verdict == "deny", (command, rules, grays)
    assert rule in rules, (command, rules)


def test_checkout_is_denied_on_a_fake_machine_too() -> None:
    home, project = "C:\\Users\\bob", "C:\\proj"
    policy = parse_policy_text(default_policy_text(), home=home)
    result = pipeline.decide(
        protocol.EVENT_PRE,
        {
            "hook_event_name": "PreToolUse",
            "session_id": "s",
            "cwd": project,
            "project_dir": project,
            "tool_name": "Bash",
            "tool_input": {"command": "git checkout ':(top).claude/settings.json'"},
        },
        mode="enforce",
        policy=policy,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": home},
        home=home,
        scan_disk=False,
        auditor=Auditor(policy.llm_audit, FakeBackend(lambda _r: verdict_json(verdict="allow"))),
    )
    assert result.decision == protocol.DECISION_DENY
    assert "protect-guard-config" in result.decided_by


@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_what_did_not_change(tmp_path: Path, tool: str) -> None:
    unchanged = {
        "git show :.env": "deny",  # an index file is one blob
        "git show HEAD:src/a.py": "allow",
        "git show HEAD:secrets": "allow",  # a tree: only the names
        "git diff ':!x'": "allow",  # everything but x, as ``git diff`` (spec revision 16)
        "git log --oneline ':(top)src'": "allow",
        "git log --oneline :/fix": "allow",
        "git status": "allow",
        # an index file (stage 0) is a revision, never a pathspec on NTFS: not read as ``0:src/...``
        "git show :0:src/a.py": "allow",
        "git rev-parse :0:src/a.py": "allow",
    }
    for command, want in unchanged.items():
        verdict, rules, grays, _ = _review(tmp_path, FULL, command, tool=tool)
        assert verdict == want, (command, rules, grays)


# --- IR-3: REV:dir of archive and grep, the tree-ish after ``--`` ------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "git archive HEAD:secrets",
        "git archive -- HEAD:secrets",
        "git archive -o x.tar -- HEAD:secrets",
        "git archive --format=tar HEAD:secrets",
        "git grep -e x HEAD:secrets",
        "git grep -e x HEAD:secrets -- .",
        "git archive -- HEAD",  # the tree-ish after ``--`` and no pathspec: the whole tree
    ],
)
@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_a_tree_operand_reads_what_is_below_it(tmp_path: Path, command: str, tool: str) -> None:
    verdict, rules, grays, _ = _review(tmp_path, FULL, command, tool=tool)
    assert verdict == "deny", (command, rules, grays)


@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_an_archive_of_a_clean_tree_is_not_denied(tmp_path: Path, tool: str) -> None:
    for command in ("git archive HEAD:src", "git archive -- HEAD:src", "git archive HEAD src"):
        verdict, rules, grays, _ = _review(tmp_path, FULL, command, tool=tool)
        assert verdict != "deny", (command, rules, grays)


# --- IR-4: 8.3 short program names --------------------------------------------------------------


def _short_path(path: Path) -> str:
    buf = ctypes.create_unicode_buffer(1024)
    if not ctypes.windll.kernel32.GetShortPathNameW(str(path), buf, 1024):  # type: ignore[attr-defined]
        return str(path)
    return buf.value


def _run_by_path(path: str, tool: str) -> str:
    """``boundkeep mode audit-only`` run by ``path`` in the tool's shell."""
    if tool == "PowerShell":
        return f"& '{path}' mode audit-only"
    return "'{}' mode audit-only".format(path.replace("\\", "/"))


@pytest.fixture
def short_boundkeep(tmp_path: Path) -> tuple[str, str]:
    """(the 8.3 short path, the long path) of a made-up ``boundkeep.exe``."""
    if sys.platform != "win32":
        pytest.skip("8.3 short names are a Windows thing")
    tools = tmp_path / "tools"
    tools.mkdir()
    target = tools / "boundkeep.exe"
    target.write_bytes(b"MZ")
    short = _short_path(target)
    if not re.search(r"~\d+\.EXE$", short, re.IGNORECASE):
        pytest.skip("this volume makes no 8.3 short names")
    return short, str(target)


@pytest.mark.windows
@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_a_short_program_name_is_the_long_one(
    tmp_path: Path, short_boundkeep: tuple[str, str], tool: str
) -> None:
    short, long_path = short_boundkeep
    for word, extra in ((short, ["program-short-name"]), (long_path, [])):
        command = _run_by_path(word, tool)
        verdict, rules, grays, progs = _review(tmp_path / "w", CLEAN, command, tool=tool)
        assert verdict == "deny", (command, grays)
        assert "deny-boundkeep-state-commands" in rules, (command, rules)
        assert "boundkeep" in progs
        for reason in extra:
            assert reason in grays, (command, grays)
        if not extra:
            assert "program-short-name" not in grays


@pytest.mark.windows
@pytest.mark.parametrize("tool", SHELL_TOOLS)
def test_a_short_name_that_is_not_there_stays_gray(
    tmp_path: Path, short_boundkeep: tuple[str, str], tool: str
) -> None:
    short, _long = short_boundkeep
    command = _run_by_path(short.rsplit("\\", 1)[0] + "\\NOSUCH~1.EXE", tool)
    verdict, rules, grays, progs = _review(tmp_path / "w", CLEAN, command, tool=tool)
    assert verdict != "allow", (command, rules)
    assert "program-path-qualified" in grays
    assert "program-short-name" not in grays
    assert "nosuch~1" in progs
