"""Project marks (PROJECT_SPEC.md §7, revision 7, P-F1): where a session that read untrusted
content wrote, and whether an action's project holds such a place.

The sticky bit stays with its session, but what the session wrote stays in the project: session A
reads a web page and writes a test file, session B runs pytest there (X1 review of M3a, F1). So a
call of a session that read untrusted content marks the places its actions may write, and the rule
field ``project_written_after_untrusted`` sees them from every session until the user clears them
in a terminal (``boundkeep taint clear``).

A mark is a canonical key (``PathRef.key`` / ``Action.project``): the action's project directory
for a write that is not certainly outside it, the path itself for a write certainly outside the
project (another project's file). Revision 8 adds two cases (X1 re-review of the M3a fixes, R-6 and
R-7): a write that shows no path (``git stash pop``, ``python gen.py``, an MCP write with a relative
path) marks the project directory, and a dev-tool configuration file written outside the project
(``~/pytest.ini``) marks its directory, so that every project below it matches; at a drive or file
system root (``E:\\pytest.ini``) that is every place, since no key names a root (revision 9, P-S6).
Pure functions, no I/O; nothing here imports the policy package.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from boundkeep.normalize.mcpnames import mcp_access
from boundkeep.normalize.model import Action

ALL_LOCATIONS = "*"  # stored once there are more than MAX_MARKS places: every project matches
MAX_MARKS = 1000
MAX_LOCATION_CHARS = 4096
# What kind of call marked a place (revision 9, P-S7; ``boundkeep taint list`` shows it)
KIND_WRITE = "write"  # a path that may be written
KIND_HIDDEN_WRITE = "hidden-write"  # a write that shows no path
KIND_RUN = "run"  # a command that runs code no rule allowed

# Configuration files that dev tools find by walking up from the project, or read from where they
# are named: the names of the policy's ask-python-tool-config-write rule, plus the project files
# that pytest, tox, setuptools and ruff read. Outside the project the directory is marked (P-R7).
TOOL_CONFIG_NAMES: Final = frozenset(
    {
        "mypy.ini",
        ".mypy.ini",
        "pylintrc",
        ".pylintrc",
        "pylintrc.toml",
        ".pylintrc.toml",
        ".flake8",
        ".coveragerc",
        "pytest.ini",
        ".pytest.ini",
        "pytest.toml",
        ".pytest.toml",
        ".pdbrc",
        "pyproject.toml",
        "setup.cfg",
        "tox.ini",
        "conftest.py",
        "ruff.toml",
        ".ruff.toml",
    }
)
# git subcommands that change the working tree without naming the files they write (P-R6), whatever
# a rule says about them (``git stash pop`` is allowed by a rule; a policy of the user's may allow
# others). Without a rule's allow, a subcommand with a write_hint marks anyway (``file_write``).
_GIT_WORKTREE: Final = frozenset(
    {
        "checkout",
        "restore",
        "switch",
        "apply",
        "am",
        "merge",
        "pull",
        "reset",
        "cherry-pick",
        "rebase",
        "revert",
        "bisect",
        "sparse-checkout",
        "checkout-index",
    }
)
# ... and those that do so only with one of these words (``git worktree list`` writes nothing)
_GIT_WORKTREE_WITH: Final[dict[str, frozenset[str]]] = {
    "stash": frozenset({"pop", "apply", "branch"}),
    "worktree": frozenset({"add"}),
    "submodule": frozenset({"update", "add"}),
}
# The normalizer's gray reasons for a subcommand not in its tables: an alias or an external
# ``git-foo``, which may be anything (``git co main``) and has no tag to mark by (S-5)
_GIT_UNKNOWN_SUBCOMMAND: Final = ("git-unknown-subcommand:", "git-dynamic-subcommand")


def location_key(key: str) -> str | None:
    """``key`` in comparison form, or None when it cannot be a mark (or be compared with one).

    Usable: an absolute canonical key (``c:/dir`` or ``/dir``) with at least one segment below the
    anchor, no ``.`` / ``..`` / empty segment, no control character. Trailing separators are
    dropped; Windows-flavor keys (a drive) are casefolded, POSIX keys compared exactly (the
    matcher's reading of ``project_trusted``).
    """
    if not key or len(key) > MAX_LOCATION_CHARS or not key.isprintable():
        return None
    if len(key) >= 3 and key[0].isascii() and key[0].isalpha() and key[1:3] == ":/":
        anchor, body = key[:3].casefold(), key[3:].casefold()
        if "\\" in body:
            return None
    elif key.startswith("/") and not key.startswith("//"):
        anchor, body = "/", key[1:]
    else:
        return None
    body = body.rstrip("/")
    if not body or any(segment in ("", ".", "..") for segment in body.split("/")):
        return None
    return anchor + body


def within(key: str, root: str) -> bool:
    """``key`` is ``root`` or below it (both in comparison form; whole segments)."""
    return key == root or key.startswith(root + "/")


def _config_mark(key: str) -> str:
    """The mark for a dev-tool configuration file at ``key`` (a usable key): its directory, or
    every place when that is a root."""
    head = key.rpartition("/")[0]
    return head if location_key(head) is not None else ALL_LOCATIONS


def hidden_write(action: Action, decision: str | None) -> bool:
    """The action may write files it shows no path for (revision 8, P-R6).

    An MCP tool whose verb is not a read (its paths may be relative, which are not resolved); a
    git subcommand that changes the working tree; any other action that no rule allowed
    (``decision`` is the action's own verdict; None, not known, counts as not allowed) and that
    runs code (``exec``: it writes wherever it likes, whatever paths it shows), writes without
    showing where (``file_write`` and no path that may be written) or is a git subcommand nobody
    knows.
    """
    return _hidden_write_kind(action, decision) is not None


def _hidden_write_kind(action: Action, decision: str | None) -> str | None:
    """``KIND_RUN`` or ``KIND_HIDDEN_WRITE`` for a ``hidden_write``, else None."""
    if action.tool.startswith("mcp__") and action.program is None:
        return KIND_HIDDEN_WRITE if mcp_access(action.mcp_tool) != "read" else None
    program = (action.program or "").casefold().removesuffix(".exe")
    git = program == "git" and action.subcommand is not None
    if git and _git_changes_worktree(action):
        return KIND_HIDDEN_WRITE
    if decision == "allow":
        return None
    if "exec" in action.risk_tags:
        return KIND_RUN
    if git and any(r.startswith(_GIT_UNKNOWN_SUBCOMMAND) for r in action.gray_reasons):
        return KIND_HIDDEN_WRITE
    if "file_write" in action.risk_tags and all(p.access == "read" for p in action.paths):
        return KIND_HIDDEN_WRITE
    return None


def _git_changes_worktree(action: Action) -> bool:
    sub = action.subcommand
    if sub in _GIT_WORKTREE:
        return True
    if sub == "read-tree":
        return "-u" in action.flags  # without it only the index changes
    words = _GIT_WORKTREE_WITH.get(sub or "")
    return words is not None and not words.isdisjoint(action.args)


def written_places(
    actions: Sequence[Action], decisions: Sequence[str | None] = ()
) -> dict[str, tuple[str, ...]]:
    """The places ``actions`` may write to, as marks (canonical keys), each with the kinds of
    call that may write there (``KIND_*``).

    A path whose access is ``write`` or ``unknown``: the action's project directory (and its
    resolved form) when the path is not certainly outside the project; the path itself when it is
    certain and not certainly inside (a write into another directory or another project), or
    ``_config_mark`` for a dev-tool configuration file (``TOOL_CONFIG_NAMES``). An action that may
    write without showing a path (``hidden_write``; ``decisions`` are the actions' own verdicts, by
    position) marks its project directory. The project directory is ``project_root``, which is set
    even when the session's working directory is outside the project (``project`` is None there).
    """
    out: dict[str, dict[str, None]] = {}

    def note(places: Sequence[str], kind: str) -> None:
        for place in places:
            out.setdefault(place, {})[kind] = None

    for index, action in enumerate(actions):
        keys = (
            action.project,
            action.project_resolved,
            action.project_root,
            action.project_root_resolved,
        )
        projects = list(dict.fromkeys(p for p in keys if p))
        decision = decisions[index] if index < len(decisions) else None
        hidden = _hidden_write_kind(action, decision)
        if hidden is not None:
            note(projects, hidden)
        for path in action.paths:
            if path.access == "read":
                continue
            if path.inside_project is not False:
                note(projects, KIND_WRITE)
            certain = not path.uncertain and location_key(path.key) is not None
            if certain and path.inside_project is not True:
                name = path.key.rpartition("/")[2].casefold()
                config = name in TOOL_CONFIG_NAMES
                note([_config_mark(path.key) if config else path.key], KIND_WRITE)
    return {
        k: tuple(v) for k, v in out.items() if k == ALL_LOCATIONS or location_key(k) is not None
    }


def written_locations(
    actions: Sequence[Action], decisions: Sequence[str | None] = ()
) -> tuple[str, ...]:
    """The keys of ``written_places``."""
    return tuple(written_places(actions, decisions))


def marked(project: str | None, resolved: str | None, marks: Sequence[str]) -> bool:
    """The project directory (``Action.project``, or its resolved form ``project_resolved`` when
    set) holds a mark, or lies below one. An unknown project (None) is marked once any mark exists;
    so is a project key that cannot be compared."""
    if not marks:
        return False
    if ALL_LOCATIONS in marks or project is None:
        return True
    roots = [k for k in map(location_key, marks) if k is not None]
    for candidate in (project, resolved):
        if candidate is None:
            continue
        key = location_key(candidate)
        if key is None:
            return True
        if any(within(root, key) or within(key, root) for root in roots):
            return True
    return False
