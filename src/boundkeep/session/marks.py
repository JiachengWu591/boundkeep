"""Project marks (PROJECT_SPEC.md §7, revision 7, P-F1): where a session that read untrusted
content wrote, and whether an action's project holds such a place.

The sticky bit stays with its session, but what the session wrote stays in the project: session A
reads a web page and writes a test file, session B runs pytest there (X1 review of M3a, F1). So a
call of a session that read untrusted content marks the places its actions may write, and the rule
field ``project_written_after_untrusted`` sees them from every session until the user clears them
in a terminal (``boundkeep taint clear``).

A mark is a canonical key (``PathRef.key`` / ``Action.project``): the action's project directory
for a write that is not certainly outside it, the path itself for a write certainly outside the
project (another project's file). Pure functions, no I/O; nothing here imports the policy package.
"""

from __future__ import annotations

from collections.abc import Sequence

from boundkeep.normalize.model import Action

ALL_LOCATIONS = "*"  # stored once there are more than MAX_MARKS places: every project matches
MAX_MARKS = 1000
MAX_LOCATION_CHARS = 4096


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


def written_locations(actions: Sequence[Action]) -> tuple[str, ...]:
    """The places ``actions`` may write to, as marks (canonical keys, de-duplicated).

    A path whose access is ``write`` or ``unknown``: the action's project directory (and its
    resolved form) when the path is not certainly outside the project; the path itself when it is
    certain and not certainly inside (a write into another directory or another project). The
    project directory is ``project_root``, which is set even when the session's working directory
    is outside the project (``project`` is None there).
    """
    out: dict[str, None] = {}
    for action in actions:
        keys = (
            action.project,
            action.project_resolved,
            action.project_root,
            action.project_root_resolved,
        )
        projects = list(dict.fromkeys(p for p in keys if p))
        for path in action.paths:
            if path.access == "read":
                continue
            if path.inside_project is not False:
                out.update(dict.fromkeys(projects))
            certain = not path.uncertain and location_key(path.key) is not None
            if certain and path.inside_project is not True:
                out[path.key] = None
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
