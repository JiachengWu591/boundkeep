"""Review round 3 (core): R-1, U-1, U-3 of ``docs/reviews/M1-M1b-fixes-rereview.md``.

* R-1: ripgrep includes the files a ``-g`` glob matches whatever ``--type`` says ("glob wins"); a
  glob that only negates leaves ``--type`` in force; ``--type`` alone narrows. The semantics below
  are what ripgrep 15.0.0 printed for a project with ``.env``, ``sub/.env``, ``certs/x.pem``,
  ``a.py`` (only file names were listed, nothing was read).
* U-1: Claude Code's Grep tool passes ``--glob '!.git'`` (and .svn .hg .bzr .jj .sl) when the caller
  gave no ``glob``, so ``.git/config`` is not read; a user ``glob`` can re-include it. ``git grep``
  and friends read the object database, not ``.git/config``.
* U-3: the Glob tool only lists names: no look inside the directory.

Everything runs on a made-up tree under ``tmp_path``; no command is executed.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from boundkeep.daemon import pipeline
from boundkeep.normalize import event as ev
from boundkeep.normalize import subtree
from boundkeep.policy import Policy, default_policy_text, parse_policy_text

IS_WIN = sys.platform == "win32"
CANARY = "CANARY-TEXT"
VCS = (".git", ".svn", ".hg", ".bzr", ".jj", ".sl")


class World:
    def __init__(self, tmp: Path) -> None:
        self.home = tmp / "home"
        self.proj = self.home / "proj"
        self.proj.mkdir(parents=True)
        self.env = {"USERPROFILE": str(self.home)} if IS_WIN else {"HOME": str(self.home)}
        self.platform = "windows" if IS_WIN else "posix"
        self.policy: Policy = parse_policy_text(default_policy_text(), home=str(self.home))

    def file(self, rel: str, text: str = CANARY) -> Path:
        path = self.proj / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def review(self, tool: str, tool_input: dict[str, Any]) -> pipeline.Review:
        payload = {
            "tool_name": tool,
            "tool_input": tool_input,
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

    def verdict(self, tool: str, tool_input: dict[str, Any]) -> str:
        return self.review(tool, tool_input).verdict.decision

    def grep(self, **extra: Any) -> str:
        return self.verdict("Grep", {"pattern": "CANARY", "path": str(self.proj), **extra})


@pytest.fixture
def w(tmp_path: Path) -> World:
    world = World(tmp_path)
    world.file("a.py", "x = 1")
    return world


@pytest.fixture
def secrets(w: World) -> World:
    """The tree of the re-review: ``.env``, ``sub/.env``, ``certs/x.pem``, ``a.py``."""
    w.file(".env")
    w.file("sub/.env")
    w.file("certs/x.pem")
    return w


def reasons_of(review: pipeline.Review) -> set[str]:
    return {r for a in review.actions for r in a.gray_reasons}


# --- R-1: glob + type --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("glob", "kind"),
    [
        (".e?v", "py"),  # ripgrep lists .env and sub/.env
        ("[.]env", "json"),
        ("*.p[e]m", "py"),  # ripgrep lists certs/x.pem
        (".e\\nv", "py"),  # ripgrep reads \n as an escaped n: .env
        (".e?v", "markdown"),
        (".env", "py"),
        ("*.pem", "py"),
        ("*", "py"),
        ("**/.env", "json"),
        ("{.env,x}", "rust"),
        ("*.py *.pem", "py"),
    ],
)
def test_a_positive_glob_wins_over_the_type(secrets: World, glob: str, kind: str) -> None:
    assert secrets.grep(glob=glob, type=kind) == "deny", (glob, kind)
    assert secrets.grep(glob=glob) == "deny", glob  # (the glob alone was right already)


@pytest.mark.parametrize("glob", ["[", "[.", "\\", "a\\b", ".e\x01v", "x" * 600])
def test_a_glob_that_cannot_be_compiled_does_not_narrow_at_all(secrets: World, glob: str) -> None:
    # ripgrep may well understand it (and list .env): the scan must not be narrower than that
    for extra in ({}, {"type": "py"}, {"type": "no-such-type"}):
        assert secrets.grep(glob=glob, **extra) in ("deny", "gray"), (glob, extra)
    assert secrets.grep(glob=".e\\nv", type="py") == "deny"


def test_a_glob_with_too_many_alternatives_does_not_narrow(secrets: World) -> None:
    glob = "{" + ",".join(f"f{i}" for i in range(64)) + "}"
    assert secrets.grep(glob=glob, type="py") == "deny"


def test_a_backslash_leading_glob_stays_gray_and_never_allow(secrets: World) -> None:
    # a glob that looks like a path (\.e?v) is the "glob-pattern-path" case: ask, not allow
    for kind in (None, "py"):
        extra: dict[str, Any] = {"glob": "\\.e?v"}
        if kind:
            extra["type"] = kind
        assert secrets.grep(**extra) != "allow"


@pytest.mark.parametrize("glob", ["*.py", "a.py", "src/**/*.py", "!*.env *.py"])
def test_a_glob_that_selects_no_protected_file_is_allowed_with_or_without_a_type(
    secrets: World, glob: str
) -> None:
    assert secrets.grep(glob=glob) == "allow", glob
    # the type is ignored (glob wins): the files the glob selects are still the only ones read
    assert secrets.grep(glob=glob, type="json") == "allow", glob
    assert secrets.grep(glob=glob, type="py") == "allow", glob


def test_a_type_alone_still_narrows(secrets: World) -> None:
    assert secrets.grep(type="py") == "allow"
    secrets.file("credentials.json")
    assert secrets.grep(type="json") == "deny"  # lists credentials.json
    assert secrets.grep(type="py") == "allow"
    assert secrets.grep(type="no-such-type") == "deny"  # unknown type: not narrowed


@pytest.mark.parametrize("glob", ["!*.md", "!*.txt", "!*.md !*.txt", "!*.md,!*.txt"])
def test_negated_globs_alone_leave_the_type_in_force(secrets: World, glob: str) -> None:
    assert secrets.grep(glob=glob, type="py") == "allow", glob  # ripgrep lists a.py only
    assert secrets.grep(glob=glob) == "deny", glob  # no type: everything is read


def test_a_positive_glob_without_a_usable_pattern_is_not_understood() -> None:
    assert ev._glob_alternatives("/") is None  # positive, but nothing left to match with
    assert ev._glob_alternatives("!*.md") == []  # only negations: the type stays in force
    assert "*.py" in (ev._glob_alternatives("*.py !*.md") or [])
    assert ev._search_selector({"glob": "/", "type": "py"}) is None


def test_the_selector_itself() -> None:
    f = ev._search_selector
    assert f({"pattern": "x"}) is None
    assert f({"glob": "[", "type": "py"}) is None
    assert f({"glob": ".e?v", "type": "py"}) is not None
    select = f({"glob": ".e?v", "type": "py"})
    assert select is not None
    assert select(".env", ".env")
    assert select("sub/.env", ".env")
    assert not select("a.py", "a.py")  # a glob selects by itself; the type adds nothing
    only_type = f({"type": "py"})
    assert only_type is not None
    assert only_type("a.py", "a.py")
    assert not only_type(".env", ".env")
    negated = f({"glob": "!*.md", "type": "py"})
    assert negated is not None
    assert negated("a.py", "a.py")
    assert not negated(".env", ".env")


# --- U-1: version-control directories ------------------------------------------------------------


@pytest.mark.parametrize("vcs", VCS)
def test_grep_without_a_glob_does_not_read_the_vcs_directories(w: World, vcs: str) -> None:
    w.file(f"{vcs}/config", "[core]")
    w.file(f"{vcs}/.env")  # (a protected name below one: ripgrep never gets there)
    w.file(f"sub/{vcs}/.env")  # (at any depth)
    assert w.grep() == "allow"
    assert w.verdict("Grep", {"pattern": "x"}) == "allow"  # the working directory
    assert w.grep(type="py") == "allow"
    assert w.grep(glob="") == "allow"  # an empty glob is no glob


def test_a_git_repository_is_greppable(w: World) -> None:
    w.file(".git/config", "[remote]")
    w.file(".git/HEAD", "ref: x")
    w.file("src/b.py", "y = 2")
    assert w.grep() == "allow"
    assert w.grep(path="src") == "allow"


@pytest.mark.parametrize("vcs", VCS)
def test_a_user_glob_re_includes_the_vcs_directories(w: World, vcs: str) -> None:
    w.file(f"{vcs}/.env")
    for glob in ("*", ".env", "**/.env", "*.env", ".e?v"):
        assert w.grep(glob=glob) == "deny", glob
    assert w.grep(glob="*", type="py") == "deny"
    assert w.grep(glob="*.py") == "allow"
    # a negated glob is still a glob given by the user: keep looking (the cautious side)
    assert w.grep(glob="!*.md") == "deny"


def test_the_git_config_is_still_protected_when_a_glob_re_includes_it(w: World) -> None:
    w.file(".git/config", "[credential]")
    assert w.grep() == "allow"
    assert w.grep(glob="*") == "deny"
    assert w.grep(glob="config") == "deny"


def test_a_vcs_directory_that_is_the_target_is_read(w: World) -> None:
    w.file(".git/config", "[credential]")
    assert w.grep(path=str(w.proj / ".git")) == "deny"  # an explicit path is not excluded


def test_only_the_exact_vcs_names_are_skipped(w: World) -> None:
    w.file(".github/.env")
    w.file(".gitx/.env")
    assert w.grep() == "deny"
    (w.proj / ".github" / ".env").unlink()
    assert w.grep() == "deny"  # .gitx
    (w.proj / ".gitx" / ".env").unlink()
    assert w.grep() == "allow"


def test_a_vcs_name_that_is_a_file_is_skipped_too(w: World) -> None:
    w.file(".git", "gitdir: ../elsewhere")  # a worktree / submodule pointer
    assert w.grep() == "allow"


def test_the_vcs_skip_does_not_cost_budget(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    for i in range(50):
        w.file(f".git/objects/{i}", "x")
    monkeypatch.setattr(subtree, "MAX_SCAN_ENTRIES", 20)
    assert w.grep() == "allow"  # the objects are not looked at, so the budget is not spent
    assert w.grep(glob="*") == "gray"  # with a glob they are


def _git_world(w: World) -> World:
    w.file(".git/config", "[credential]")
    w.file("src/b.py", "y = 2")
    return w


@pytest.mark.parametrize(
    "command",
    [
        "git grep CANARY .",
        "git grep CANARY",
        "git archive HEAD",
        "git log -p",
        "git show HEAD",
        "git stash show -p",
    ],
)
def test_git_commands_do_not_read_dot_git_config(w: World, command: str) -> None:
    _git_world(w)
    review = w.review("Bash", {"command": command})
    assert review.verdict.decision != "deny", (command, review.verdict.rule_ids)
    assert not any(r.key.endswith(".git/config") for a in review.actions for r in a.paths), command


def test_git_still_sees_a_protected_file_in_the_work_tree(w: World) -> None:
    _git_world(w)
    w.file("certs/x.pem")
    assert w.verdict("Bash", {"command": "git grep CANARY ."}) == "deny"
    assert w.verdict("Bash", {"command": "git archive HEAD ."}) == "deny"


@pytest.mark.parametrize("command", ["grep -r CANARY .", "tar cf x.tar .", "cp -r . ../copy"])
def test_other_programs_do_read_dot_git_config(w: World, command: str) -> None:
    _git_world(w)
    review = w.review("Bash", {"command": command})
    assert review.verdict.decision == "deny", command
    assert any(r.key.endswith(".git/config") for a in review.actions for r in a.paths), command


def test_the_skip_names_argument_of_scan(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("x", encoding="utf-8")
    (tmp_path / "keep").mkdir()
    (tmp_path / "keep" / ".git").mkdir()
    (tmp_path / "keep" / ".git" / "config").write_text("x", encoding="utf-8")
    m = subtree.ProtectedMatcher(["**/.git/config"])
    root = str(tmp_path).replace("\\", "/").casefold() if IS_WIN else str(tmp_path)
    plain = subtree.scan(
        str(tmp_path), [root], windows=IS_WIN, matcher=m, budget=subtree.ScanBudget()
    )
    assert len(plain.hits) == 2
    skipped = subtree.scan(
        str(tmp_path),
        [root],
        windows=IS_WIN,
        matcher=m,
        budget=subtree.ScanBudget(),
        skip_names=subtree.VCS_DIR_NAMES,
    )
    assert skipped.hits == []
    assert skipped.status == "ok"
    assert set(subtree.VCS_DIR_NAMES) == {".git", ".svn", ".hg", ".bzr", ".jj", ".sl"}


# --- U-3: the Glob tool lists names ---------------------------------------------------------------


def test_the_glob_tool_does_not_look_inside_the_directory(secrets: World) -> None:
    for pattern in ("*", "**/*", "**/*.pem", "**/.env", "*.py", "src/*.py"):
        review = secrets.review("Glob", {"pattern": pattern})
        assert review.verdict.decision == "allow", pattern
        assert not any("recursive-scan" in r.reasons for a in review.actions for r in a.paths)
        assert not reasons_of(review)
    assert secrets.verdict("Glob", {"pattern": "*", "path": str(secrets.proj)}) == "allow"


def test_the_glob_tool_does_not_walk_the_tree(
    secrets: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Glob must not scan")

    monkeypatch.setattr(subtree, "scan", boom)
    assert secrets.verdict("Glob", {"pattern": "**/*"}) == "allow"


def test_the_glob_tool_still_checks_its_base_path(w: World) -> None:
    (w.home / ".ssh").mkdir()
    (w.home / ".ssh" / "id_rsa").write_text(CANARY, encoding="utf-8")
    assert w.verdict("Glob", {"pattern": "*", "path": str(w.home / ".ssh")}) == "deny"
    assert w.verdict("Glob", {"pattern": "*", "path": "../.ssh"}) == "deny"
    # a pattern that carries its own location is still looked at
    assert w.verdict("Glob", {"pattern": "../.ssh/*"}) == "deny"
    assert w.verdict("Glob", {"pattern": "../*.pem"}) != "allow"


def test_the_grep_tool_still_scans(secrets: World) -> None:
    assert secrets.grep() == "deny"
