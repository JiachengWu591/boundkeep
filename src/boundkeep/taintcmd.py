"""``boundkeep taint``: the project marks (PROJECT_SPEC.md §7, revision 7, P-F1).

A session that read untrusted content (a web page, a search result, an MCP answer) and then wrote
into a project leaves a mark there; while it is there, the dev tools ask in every session in that
project (``ask-devtools-after-untrusted-project-write``). ``list`` shows the marks; ``clear``
removes them. Clearing lets the project's own code run unasked again, so it is a command for the
USER, in a terminal, like ``trust add``: it refuses to run inside a process Claude Code started or
without a real console, and the policy refuses every ``boundkeep taint`` call of the agent.
"""

from __future__ import annotations

import argparse
import os
import time
from typing import Any

from boundkeep import console, paths
from boundkeep.normalize import paths as norm_paths
from boundkeep.session.marks import ALL_LOCATIONS, location_key, within
from boundkeep.session.store import Mark, SessionStore, SessionStoreError
from boundkeep.trust import _stdin_is_tty, agent_environment, canonical_dir, printable_entry

EXIT_OK = 0
EXIT_PROBLEM = 1


def _fail(message: str) -> int:
    console.err(f"boundkeep: {message}")
    return EXIT_PROBLEM


def _open() -> SessionStore | None:
    """The session database, or None when there is none yet (nothing was ever marked)."""
    path = paths.session_db_file()
    if not os.path.exists(path):
        return None
    return SessionStore(path)


def _shown(location: str) -> str:
    if location == ALL_LOCATIONS:
        return "every project (more places were marked than are kept)"
    return printable_entry(location)


def _keys(directory: str) -> list[str]:
    """The canonical keys of ``directory`` as typed and with links resolved (the daemon marks
    both forms of a project directory)."""
    out: list[str] = []
    for form in (os.path.abspath(os.path.expanduser(directory)), canonical_dir(directory)):
        norm = norm_paths.normalize_path(form, cwd=None, home=None, dialect="tool", literal=True)
        if norm.absolute and not norm.uncertain and norm.key and norm.key not in out:
            out.append(norm.key)
    return out


def cmd_list(_args: argparse.Namespace) -> int:
    try:
        store = _open()
    except SessionStoreError as exc:
        return _fail(str(exc))
    if store is None:
        console.out("no project marks")
        return EXIT_OK
    try:
        marks = store.marks()
    finally:
        store.close()
    if marks is None:
        return _fail(f"cannot read the project marks ({store.last_error})")
    if not marks:
        console.out("no project marks")
        return EXIT_OK
    console.out(
        f"places written by sessions that had read untrusted content ({len(marks)}); the dev "
        "tools ask in projects that hold one:"
    )
    for mark in marks:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(mark.last_marked))
        sources = printable_entry(", ".join(mark.sources), 80) or "?"
        console.out(f"  {when}  {_shown(mark.location)}  (after {sources})")
    console.out("Clear one with 'boundkeep taint clear --project-dir DIR', all with --all.")
    return EXIT_OK


def cmd_clear(args: argparse.Namespace) -> int:
    marker = agent_environment()
    if marker is not None:
        return _fail(
            f"taint clear refuses to run inside a process Claude Code started ({marker} is set in "
            "the environment): it lets the project's own code run unasked again, so it is a "
            "command for you, in your own terminal. If this IS your own terminal, start it from "
            f"outside Claude Code or unset {marker}"
        )
    if not _stdin_is_tty():
        return _fail(
            "taint clear needs an interactive terminal (it lets the project's own code run "
            "unasked again, so it is not run from a pipe, a script or by the agent); run it "
            "yourself in a terminal"
        )
    try:
        store = _open()
    except SessionStoreError as exc:
        return _fail(str(exc))
    if store is None:
        console.out("no project marks")
        return EXIT_OK
    gone: list[str] | None
    remaining: list[Mark] = []
    keys: list[str] = []
    try:
        if args.all:
            gone = store.clear_marks(None)
        else:
            keys = _keys(args.project_dir or os.getcwd())
            if not keys:
                return _fail("the directory cannot be resolved to an absolute path")
            gone = []
            for key in keys:
                removed = store.clear_marks(key)
                if removed is None:
                    gone = None
                    break
                gone.extend(removed)
            remaining = store.marks() or []
    finally:
        store.close()
    if gone is None:
        return _fail(f"cannot clear the project marks ({store.last_error})")
    for location in gone:
        console.out(f"cleared: {_shown(location)}")
    if not gone:
        console.out("no mark at or below that directory")
    roots = [k for k in map(location_key, keys) if k is not None]
    for mark in remaining:
        mark_key = location_key(mark.location)
        covers = mark_key is not None and any(within(r, mark_key) for r in roots)
        if mark.location == ALL_LOCATIONS or covers:
            console.out(
                f"still marked: {_shown(mark.location)} covers this directory; clear it too "
                "(or use --all)"
            )
    console.out("A running daemon sees the change on the next tool call.")
    return EXIT_OK


def add_parser(sub: Any) -> None:
    """Register ``taint`` (with list / clear) on the top-level subparsers."""
    p = sub.add_parser(
        "taint",
        help="show or clear the marks left by sessions that read untrusted content",
        description="Project marks: the dev tools ask in a project that a session wrote into "
        "after reading web or MCP content (a user command: the agent must not run it).",
    )
    inner = p.add_subparsers(dest="taint_command", required=True, metavar="action")
    q = inner.add_parser("list", help="show the marked places")
    q.set_defaults(func=cmd_list)
    q = inner.add_parser("clear", help="clear the marks of a directory (default: the current one)")
    target = q.add_mutually_exclusive_group()
    target.add_argument("--project-dir", help="the directory (default: current directory)")
    target.add_argument("--all", action="store_true", help="clear every mark")
    q.set_defaults(func=cmd_clear)
