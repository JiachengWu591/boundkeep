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
(``~/pytest.ini``) marks its directory, so that every project below it matches. Pure functions, no
I/O; nothing here imports the policy package.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from boundkeep.normalize.mcpnames import mcp_access
from boundkeep.normalize.model import Action

ALL_LOCATIONS = "*"  # stored once there are more than MAX_MARKS places: every project matches
MAX_MARKS = 1000
MAX_LOCATION_CHARS = 4096

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
# git subcommands that change the working tree without naming the files they write (P-R6);
# ``stash`` only with ``pop`` or ``apply`` (``git stash pop`` is allowed by a rule)
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
    }
)
_GIT_STASH_WRITES: Final = frozenset({"pop", "apply"})


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


def _parent(key: str) -> str | None:
    """The directory of a file's canonical key, when that is still a usable mark."""
    head, sep, _name = key.rpartition("/")
    return head if sep and location_key(head) is not None else None


def hidden_write(action: Action, decision: str | None) -> bool:
    """The action may write files it shows no path for (revision 8, P-R6).

    An MCP tool whose verb is not a read (its paths may be relative, which are not resolved); a
    git subcommand that changes the working tree; any other action that no rule allowed
    (``decision`` is the action's own verdict; None, not known, counts as not allowed) and that
    runs code (``exec``: it writes wherever it likes, whatever paths it shows) or writes without
    showing where (``file_write`` and no path that may be written).
    """
    if action.tool.startswith("mcp__") and action.program is None:
        return mcp_access(action.mcp_tool) != "read"
    program = (action.program or "").casefold().removesuffix(".exe")
    if program == "git" and action.subcommand is not None:
        if action.subcommand in _GIT_WORKTREE:
            return True
        if action.subcommand == "stash" and _GIT_STASH_WRITES & set(action.args[1:]):
            return True
    if decision == "allow":
        return False
    if "exec" in action.risk_tags:
        return True
    return "file_write" in action.risk_tags and all(p.access == "read" for p in action.paths)


def written_locations(
    actions: Sequence[Action], decisions: Sequence[str | None] = ()
) -> tuple[str, ...]:
    """The places ``actions`` may write to, as marks (canonical keys, de-duplicated).

    A path whose access is ``write`` or ``unknown``: the action's project directory (and its
    resolved form) when the path is not certainly outside the project; the path itself when it is
    certain and not certainly inside (a write into another directory or another project), or its
    directory for a dev-tool configuration file (``TOOL_CONFIG_NAMES``). An action that may write
    without showing a path (``hidden_write``; ``decisions`` are the actions' own verdicts, by
    position) marks its project directory. The project directory is ``project_root``, which is set
    even when the session's working directory is outside the project (``project`` is None there).
    """
    out: dict[str, None] = {}
    for index, action in enumerate(actions):
        keys = (
            action.project,
            action.project_resolved,
            action.project_root,
            action.project_root_resolved,
        )
        projects = list(dict.fromkeys(p for p in keys if p))
        decision = decisions[index] if index < len(decisions) else None
        if hidden_write(action, decision):
            out.update(dict.fromkeys(projects))
        for path in action.paths:
            if path.access == "read":
                continue
            if path.inside_project is not False:
                out.update(dict.fromkeys(projects))
            certain = not path.uncertain and location_key(path.key) is not None
            if certain and path.inside_project is not True:
                name = path.key.rpartition("/")[2].casefold()
                parent = _parent(path.key) if name in TOOL_CONFIG_NAMES else None
                out[parent or path.key] = None
    return tuple(k for k in out if location_key(k) is not None)


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
