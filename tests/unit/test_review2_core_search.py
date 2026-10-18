"""Review round 2, H-1 and M-9 (core): reads of a directory look inside it.

``Grep`` / ``Glob`` on a directory, and commands that read the whole subtree of their directory
operand (``CmdInfo.recursive``), used to be judged by the directory's own path only: "inside the
project" is an allow although the tree holds ``.env`` or ``certs/a.pem``. The subtree is now walked
within a budget and the protected files become read paths. Everything here runs on a made-up tree
under ``tmp_path``; no command is executed.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from boundkeep.daemon import pipeline
from boundkeep.normalize import event as ev
from boundkeep.normalize import paths, subtree
from boundkeep.policy import Policy, default_policy_text, parse_policy_text

IS_WIN = sys.platform == "win32"
CANARY = "CANARY-TEXT"


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

    def payload(self, tool: str, tool_input: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_name": tool,
            "tool_input": tool_input,
            "cwd": str(self.proj),
            "project_dir": str(self.proj),
        }

    def review(self, tool: str, tool_input: dict[str, Any], **kw: Any) -> pipeline.Review:
        return pipeline.review(
            self.payload(tool, tool_input),
            self.policy,
            platform=self.platform,  # type: ignore[arg-type]
            env=self.env,
            home=str(self.home),
            **kw,
        )

    def verdict(self, tool: str, tool_input: dict[str, Any], **kw: Any) -> str:
        return self.review(tool, tool_input, **kw).verdict.decision


@pytest.fixture
def w(tmp_path: Path) -> World:
    world = World(tmp_path)
    world.file("src/app.py", "x = 1")
    return world


def grep(w: World, **extra: Any) -> str:
    return w.verdict("Grep", {"pattern": "CANARY", **extra})


def reasons_of(review: pipeline.Review) -> set[str]:
    return {r for a in review.actions for r in a.gray_reasons}


# --- H-1: Grep / Glob on a directory -------------------------------------------------------------


def test_a_clean_tree_is_still_allowed(w: World) -> None:
    assert grep(w, path=str(w.proj)) == "allow"
    assert grep(w) == "allow"
    assert w.verdict("Glob", {"pattern": "**/*.py"}) == "allow"


@pytest.mark.parametrize(
    "secret",
    [
        ".env",
        "certs/a.pem",
        "infra/terraform.tfstate",
        "credentials.json",
        "deploy/prod.tfvars",
        "keys/server.key",
        ".ssh/config",
        "deep/er/est/.env.production",
    ],
)
def test_grep_on_a_directory_with_a_protected_file_is_denied(w: World, secret: str) -> None:
    w.file(secret)
    assert grep(w, path=str(w.proj)) == "deny"
    assert grep(w) == "deny"  # no path: the working directory


def test_grep_default_directory_and_relative_directory_are_scanned(w: World) -> None:
    w.file("sub/.env")
    assert grep(w, path="sub") == "deny"
    assert grep(w, path="src") == "allow"
    assert grep(w, path=".") == "deny"


@pytest.mark.parametrize("glob", [".e?v", "*.env", ".env", ".en[v]", "*", "**/.env", "{.env,x}"])
def test_a_grep_glob_that_selects_the_protected_name_is_denied(w: World, glob: str) -> None:
    w.file(".env")
    assert grep(w, path=str(w.proj), glob=glob) == "deny", glob


@pytest.mark.parametrize("glob", ["*.py", "src/**/*.py", "*.{py,pyi}", "!*.env *.py", "app.py"])
def test_a_grep_glob_that_cannot_select_a_protected_file_is_allowed(w: World, glob: str) -> None:
    w.file(".env")
    w.file("certs/a.pem")
    assert grep(w, path=str(w.proj), glob=glob) == "allow", glob


def test_a_grep_type_narrows_only_for_the_types_it_knows(w: World) -> None:
    w.file(".env")
    assert grep(w, path=str(w.proj), type="py") == "allow"
    assert grep(w, path=str(w.proj), type="no-such-type") == "deny"  # unknown: not narrowed
    w.file("credentials.json")
    assert grep(w, path=str(w.proj), type="json") == "deny"
    assert grep(w, path=str(w.proj), type="py") == "allow"


def test_glob_tool_on_a_tree(w: World) -> None:
    # round 3 (U-3): the Glob tool only lists names, it reads no content: no look inside the tree
    w.file("certs/a.pem")
    w.file(".env")
    assert w.verdict("Glob", {"pattern": "**/*.pem"}) == "allow"
    assert w.verdict("Glob", {"pattern": "*"}) == "allow"
    assert w.verdict("Glob", {"pattern": "**/*.py"}) == "allow"
    assert w.verdict("Glob", {"pattern": "*.py", "path": str(w.proj)}) == "allow"
    assert w.verdict("Glob", {"pattern": "src/*.py"}) == "allow"


def test_no_directory_name_is_skipped(w: World) -> None:
    # (round 3, U-1: the version-control directories are the one exception, and only for a Grep
    # without a `glob`: Claude Code excludes them itself; see test_review3_core_search.py)
    for name in ("node_modules", "dist", "__pycache__", "vendor"):
        w.file(f"{name}/pkg/.env")
        assert grep(w, path=str(w.proj)) == "deny", name
        (w.proj / name / "pkg" / ".env").unlink()
    w.file(".git/pkg/.env")
    assert grep(w, path=str(w.proj), glob="*") == "deny"  # a user glob re-includes .git
    assert grep(w, path=str(w.proj)) == "allow"


def test_a_protected_directory_is_reported_as_itself(w: World) -> None:
    w.file(".aws/anything")
    review = w.review("Grep", {"pattern": "x", "path": str(w.proj)})
    assert review.verdict.decision == "deny"
    keys = {r.key for a in review.actions for r in a.paths}
    assert any(k.endswith("/.aws") for k in keys)


def test_with_a_narrowing_glob_files_below_a_protected_directory_are_reported(w: World) -> None:
    w.file(".ssh/known_hosts")
    w.file(".ssh/notes.txt")
    assert grep(w, path=str(w.proj), glob="*.py") == "allow"
    assert grep(w, path=str(w.proj), glob="*.txt") == "deny"


def test_the_protected_refs_are_read_paths_inside_the_project(w: World) -> None:
    w.file("certs/a.pem")
    actions = ev.normalize_event(
        w.payload("Grep", {"pattern": "x", "path": str(w.proj)}),
        platform=w.platform,  # type: ignore[arg-type]
        env=w.env,
        home=str(w.home),
    )
    refs = [r for a in actions for r in a.paths if "recursive-scan" in r.reasons]
    assert [r.key.rsplit("/", 1)[-1] for r in refs] == ["a.pem"]
    assert refs[0].access == "read"
    assert refs[0].inside_project is True
    assert not refs[0].uncertain


def test_default_protected_globs_are_used_without_a_policy(w: World) -> None:
    w.file(".env")
    actions = ev.normalize_event(
        w.payload("Grep", {"pattern": "x"}),
        platform=w.platform,  # type: ignore[arg-type]
        env=w.env,
        home=str(w.home),
    )
    assert any(r.key.endswith("/.env") for a in actions for r in a.paths)
    off = ev.normalize_event(
        w.payload("Grep", {"pattern": "x"}),
        platform=w.platform,  # type: ignore[arg-type]
        env=w.env,
        home=str(w.home),
        protected_globs=(),
    )
    assert not any(r.key.endswith("/.env") for a in off for r in a.paths)


def test_scan_disk_false_does_not_look_inside(w: World) -> None:
    w.file(".env")
    off = w.verdict("Grep", {"pattern": "x", "path": str(w.proj)}, scan_disk=False)
    assert off == "allow"  # (for fake machines only)
    assert grep(w, path=str(w.proj)) == "deny"


def test_the_protected_globs_come_from_the_policy(w: World) -> None:
    globs = pipeline.protected_read_globs(w.policy)
    assert "**/.env" in globs
    assert "**/*.pem" in globs
    mixed = (
        "version: 1\nrules:\n"
        "  - {id: w, match: {path_glob: ['**/only-write'], access: write},\n"
        "     action: deny, reason: x}\n"
        "  - {id: a, match: {path_glob: ['**/allowed'], access: read}, action: allow}\n"
        "  - {id: k, match: {path_glob: ['**/asks'], access: read}, action: ask, reason: x}\n"
    )
    assert pipeline.protected_read_globs(parse_policy_text(mixed, home=str(w.home))) == (
        "**/asks",
    )  # write-only and allow rules do not name protected reads
    text = (
        "version: 1\nrules:\n"
        "  - {id: r, match: {path_glob: ['**/hush.txt']}, action: deny, reason: x}\n"
    )
    custom = parse_policy_text(text, home=str(w.home))
    assert pipeline.protected_read_globs(custom) == ("**/hush.txt",)
    w.file("a/hush.txt")
    w.file(".env")
    w.policy = custom
    review = w.review("Grep", {"pattern": "x", "path": str(w.proj)})
    assert review.verdict.rule_ids == ("r",)
    assert not any(r.key.endswith("/.env") for a in review.actions for r in a.paths)


def test_an_empty_policy_set_turns_the_look_off(w: World) -> None:
    w.file(".env")
    w.policy = parse_policy_text("version: 1\n", home=str(w.home))
    assert pipeline.protected_read_globs(w.policy) == ()
    assert grep(w, path=str(w.proj)) == "gray"  # no rule decides; still never an allow


def test_a_path_glob_in_the_pattern_is_not_scanned_twice(w: World) -> None:
    w.file(".env")
    review = w.review("Glob", {"pattern": "../*.pem"})
    assert review.verdict.decision != "allow"
    assert "glob-pattern-path" in reasons_of(review)


# --- budgets: never a silent pass -------------------------------------------------------------


def test_a_tree_over_the_entry_budget_is_gray_never_allow(
    w: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    for i in range(40):
        w.file(f"many/f{i}.txt", "x")
    monkeypatch.setattr(subtree, "MAX_SCAN_ENTRIES", 20)
    review = w.review("Grep", {"pattern": "x", "path": str(w.proj)})
    assert review.verdict.decision == "gray"
    assert "recursive-scan-budget" in reasons_of(review)
    assert grep(w, path=str(w.proj / "src")) == "allow"  # a small subtree is fine


def test_a_tree_over_the_time_budget_is_gray(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subtree, "SCAN_TIME_BUDGET_S", 0.0)
    review = w.review("Grep", {"pattern": "x", "path": str(w.proj)})
    assert review.verdict.decision == "gray"
    assert "recursive-scan-budget" in reasons_of(review)


def test_a_secret_near_the_root_is_found_before_the_budget_ends(
    w: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    w.file(".env")
    for i in range(40):
        w.file(f"zz/deep/er/f{i}.txt", "x")
    monkeypatch.setattr(subtree, "MAX_SCAN_ENTRIES", 12)
    assert grep(w, path=str(w.proj)) == "deny"  # breadth first


def test_an_unreadable_directory_is_gray(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    w.file("locked/x.txt", "x")
    real = subtree.os.scandir

    def scandir(path: Any = ".") -> Any:
        if str(path).endswith("locked"):
            raise PermissionError("denied")
        return real(path)

    monkeypatch.setattr(subtree.os, "scandir", scandir)
    review = w.review("Grep", {"pattern": "x", "path": str(w.proj)})
    assert review.verdict.decision == "gray"
    assert "recursive-scan-unreadable" in reasons_of(review)


def test_a_missing_directory_is_not_gray(w: World) -> None:
    review = w.review("Grep", {"pattern": "x", "path": str(w.proj / "nope")})
    assert review.verdict.decision == "allow"
    assert not reasons_of(review)


def test_a_file_target_is_not_scanned(w: World) -> None:
    assert grep(w, path=str(w.proj / "src" / "app.py")) == "allow"


def test_the_scan_budget_is_shared_by_a_request(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    for i in range(15):
        w.file(f"a/f{i}", "x")
        w.file(f"b/f{i}", "x")
    monkeypatch.setattr(subtree, "MAX_SCAN_ENTRIES", 20)
    monkeypatch.setattr(ev.programs, "classify", _recursive(ev.programs.classify))
    review = w.review("Bash", {"command": "grep -r x a b"})
    assert "recursive-scan-budget" in reasons_of(review)
    assert review.verdict.decision != "allow"


# --- links ------------------------------------------------------------------------------------


def _link_dir(target: Path, link: Path) -> None:
    if IS_WIN:
        import _winapi  # type: ignore[import-not-found,unused-ignore]

        try:
            _winapi.CreateJunction(str(target), str(link))
        except OSError as exc:  # pragma: no cover - environment
            pytest.skip(f"cannot create a junction here: {exc}")
    else:
        os.symlink(target, link, target_is_directory=True)


def test_links_are_not_followed_by_grep_but_make_a_recursive_shell_read_gray(
    w: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = w.home / "outside"
    outside.mkdir()
    (outside / ".env").write_text(CANARY, encoding="utf-8")
    _link_dir(outside, w.proj / "lnk")
    # ripgrep does not follow links: nothing to see, nothing gray
    review = w.review("Grep", {"pattern": "x", "path": str(w.proj)})
    assert review.verdict.decision == "allow"
    # a command that may follow them is gray: the tree behind the link was not looked at
    monkeypatch.setattr(ev.programs, "classify", _recursive(ev.programs.classify))
    shell = w.review("Bash", {"command": "grep -R x ."})
    assert "recursive-scan-link" in reasons_of(shell)
    assert shell.verdict.decision != "allow"


# --- M-9: CmdInfo.recursive -------------------------------------------------------------


def _recursive(real: Any) -> Any:
    """``programs.classify`` whose result also says "reads the whole subtree" (the field the
    programs layer is to add as ``CmdInfo.recursive``)."""

    def classify(*args: Any, **kwargs: Any) -> Any:
        info = real(*args, **kwargs)
        return SimpleNamespace(
            known=info.known,
            subcommand=info.subcommand,
            flags=info.flags,
            paths=info.paths,
            urls=info.urls,
            network=info.network,
            tags=info.tags,
            gray=info.gray,
            recursive=True,
        )

    return classify


def test_a_recursive_command_on_a_directory_sees_the_protected_files(
    w: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    w.file("certs/a.pem")
    monkeypatch.setattr(ev.programs, "classify", _recursive(ev.programs.classify))
    for command in ("grep -r CANARY .", "grep -r CANARY certs", "tar cf x.tar ."):
        review = w.review("Bash", {"command": command})
        assert review.verdict.decision == "deny", command
        assert "no-secret-read" in review.verdict.rule_ids


def test_a_recursive_command_on_a_clean_directory_is_not_denied(
    w: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ev.programs, "classify", _recursive(ev.programs.classify))
    assert w.verdict("Bash", {"command": "grep -r x src"}) != "deny"


def test_only_the_read_operands_of_a_recursive_command_are_scanned(
    w: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    w.file("dest/.env")
    monkeypatch.setattr(ev.programs, "classify", _recursive(ev.programs.classify))
    review = w.review("Bash", {"command": "cp -r src dest"})
    assert review.verdict.decision != "deny"
    assert not any("recursive-scan" in r.reasons for a in review.actions for r in a.paths)


def test_recursive_glob_operands_are_scanned_through_their_matches(
    w: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    w.file("pkg1/.env")
    w.file("pkg2/x.py", "x")
    monkeypatch.setattr(ev.programs, "classify", _recursive(ev.programs.classify))
    assert w.verdict("Bash", {"command": "grep -r CANARY pkg*"}) == "deny"


def test_a_recursive_scan_outside_the_project_finds_credentials(
    w: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    (w.home / ".ssh").mkdir()
    (w.home / ".ssh" / "id_rsa").write_text(CANARY, encoding="utf-8")
    monkeypatch.setattr(ev.programs, "classify", _recursive(ev.programs.classify))
    review = w.review("Bash", {"command": "tar cf - ~"})
    assert review.verdict.decision == "deny"
    assert any(r.key.endswith("/.ssh") for a in review.actions for r in a.paths)


# --- the matcher itself -----------------------------------------------------------------------


def test_the_protected_matcher_filters_by_name_and_decides_by_full_key() -> None:
    m = subtree.ProtectedMatcher(["**/.env", "**/*.pem", "**/.ssh/**", "/etc/shadow*", "**/a**b"])
    assert m.candidate(".env")
    assert m.candidate("x.pem")
    assert m.candidate(".ssh")
    assert m.candidate("shadow-")
    assert m.candidate("b")
    assert m.match("c:/p/.env")
    assert not m.match("c:/p/x.env")
    assert m.match("/home/u/.ssh")
    assert m.match("/home/u/.ssh/id_rsa")
    assert m.match("/etc/shadow-")
    assert not m.match("/tmp/etc/shadow")
    assert subtree.ProtectedMatcher([]).empty
    assert not subtree.ProtectedMatcher(["**/.env"]).candidate("readme.md")


def test_scan_reports_nothing_for_a_missing_directory(tmp_path: Path) -> None:
    m = subtree.ProtectedMatcher(["**/.env"])
    result = subtree.scan(
        str(tmp_path / "nope"), ["/nope"], windows=False, matcher=m, budget=subtree.ScanBudget()
    )
    assert result.status == "absent"
    assert not result.hits


def test_native_dir_refuses_what_it_cannot_scan(tmp_path: Path) -> None:
    ref = paths.normalize_path(str(tmp_path), cwd=None, home=None, literal=True)
    assert ev._native_dir(ev.PathRef(raw=str(tmp_path), key=ref.key, flavor=ref.flavor)) is not None
    assert (
        ev._native_dir(ev.PathRef(raw="x", key="//srv/share/x", flavor="windows", uncertain=False))
        is None
    )
    assert (
        ev._native_dir(ev.PathRef(raw="x", key=ref.key, flavor=ref.flavor, uncertain=True)) is None
    )
