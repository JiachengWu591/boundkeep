"""``boundkeep trust``: the user's list of trusted projects in the active policy.

``trusted_projects`` in the policy names directories whose own code (tests, linters) boundkeep
lets dev tools run without asking. Adding to it widens what runs unreviewed, so it is a command
for the USER (policy rules keep the agent away from it), and it edits the policy file by TEXT, like
``boundkeep mode`` does: comments, key order, line endings and a BOM stay byte for byte; only the
``trusted_projects`` block changes. The edited text is validated with the real policy loader
BEFORE the file is replaced, so a refused edit (too broad a directory, a policy that does not load)
leaves the file untouched.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from typing import Any

import yaml

from boundkeep import console, fsperm, paths
from boundkeep.normalize import paths as norm_paths
from boundkeep.policy import PolicyError, load_policy, parse_policy_text
from boundkeep.policy.loader import _atomic_write, _decode, _read_policy_bytes
from boundkeep.policy.schema import home_guard_tree_reason

KEY = "trusted_projects"
KEY_COMMENT = (
    "# projects whose own code (tests, linters) boundkeep lets dev tools run without asking; "
    "managed by `boundkeep trust`"
)
WARNING = (
    "A trusted project is one whose own code you let tools run without asking: a prompt "
    "injection that gets the agent to write a test file and run pytest would then execute that "
    "code unreviewed. Do not trust a repository you did not write or audit."
)
DOCTOR_RISK = (
    "trusted projects let dev tools run their own code (tests, linters) without asking: a prompt "
    "injection that gets the agent to write a test file and run pytest there would execute it "
    "unreviewed; list only repositories you wrote or audited"
)

EXIT_OK = 0
EXIT_PROBLEM = 1

_LINE_SPLIT = re.compile(r"(\r\n|\n|\r)")
_DEFAULT_ITEM_INDENT = 2


class TrustEditError(Exception):
    """The policy text cannot be edited safely by this command (edit it by hand)."""


# --------------------------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------------------------


def _strip_extended_prefix(path: str) -> str:
    if path.startswith("\\\\?\\"):
        rest = path[4:]
        return "\\\\" + rest[4:] if rest[:4].upper() == "UNC\\" else rest
    return path


def canonical_dir(path: str) -> str:
    """The spelling a trusted entry is stored in: absolute, symlinks and junctions resolved
    (``realpath``, the way the daemon resolves the project directory), no ``\\\\?\\`` prefix,
    native separators (so ``C:/Users/x/p`` and ``C:\\Users\\x\\p`` give the same entry)."""
    return _strip_extended_prefix(os.path.realpath(os.path.abspath(os.path.expanduser(path))))


def path_key(path: str) -> str:
    """A comparison key: normalised separators and, on Windows, case folded."""
    return os.path.normcase(os.path.normpath(path))


def expand_entry(entry: str) -> str:
    """An entry as written in the policy (absolute or ``~/...``) as a native path."""
    return os.path.normpath(os.path.expanduser(entry))


def is_inside(path: str, directory: str) -> bool:
    """``path`` is ``directory`` or below it (lexical, by :func:`path_key`)."""
    a, b = path_key(path), path_key(directory)
    return a == b or a.startswith(b.rstrip("\\/") + os.sep)


def _matches(entry: str, canonical: str, given: str) -> bool:
    """Does the policy ``entry`` name the directory ``canonical`` (or the path as typed)?"""
    expanded = expand_entry(entry)
    wanted = {path_key(canonical), path_key(given)}
    if path_key(expanded) in wanted:
        return True
    try:
        return path_key(canonical_dir(expanded)) in wanted
    except (OSError, ValueError):
        return False


def printable_entry(text: str, limit: int = 300) -> str:
    """``text`` safe to print (non-printing characters become ``?``), cut to ``limit``."""
    shown = text if len(text) <= limit else text[:limit] + "..."
    return "".join(ch if ch.isprintable() else "?" for ch in shown)


def _quote(value: str) -> str:
    """``value`` as a YAML double-quoted scalar (backslashes and quotes escaped)."""
    if any(unicodedata.category(ch).startswith("C") for ch in value):
        raise TrustEditError("the path contains a control or non-printing character")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


# --------------------------------------------------------------------------------------------
# Text editing
# --------------------------------------------------------------------------------------------


@dataclass
class _Layout:
    lines: list[str]
    eols: list[str]
    style: str  # the file's usual line ending
    top_indent: int
    version_index: int
    key_index: int | None = None
    flow_rest: str = ""  # what follows "[]" / the colon on the key line (a comment or "")
    empty_flow: bool = False
    items: list[tuple[int, str]] = field(default_factory=list)  # (line index, entry)
    item_indent: int = _DEFAULT_ITEM_INDENT
    last_index: int = 0  # last line of the block: the last item, else the key line


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_item(stripped: str) -> bool:
    return stripped == "-" or stripped.startswith("- ")


def _layout(text: str) -> _Layout:
    pieces = _LINE_SPLIT.split(text)
    lines = pieces[0::2]
    eols = [*pieces[1::2], ""]
    style = next((e for e in eols if e), "\n")
    content = [
        i
        for i, line in enumerate(lines)
        if line.strip()
        and not line.strip().startswith(("#", "%"))
        and line.strip() not in ("---", "...")
    ]
    if not content:
        raise TrustEditError("the policy has no content to edit")
    top = _indent(lines[content[0]])
    at_top = [i for i in content if _indent(lines[i]) == top]
    versions = [i for i in at_top if re.match(r"version[ \t]*:", lines[i].lstrip(" "))]
    if len(versions) != 1:
        raise TrustEditError("expected exactly one top-level 'version:' line; edit by hand")
    out = _Layout(lines, eols, style, top, versions[0])
    keys = [i for i in at_top if re.match(rf"{KEY}[ \t]*:", lines[i].lstrip(" "))]
    if len(keys) > 1:
        raise TrustEditError(f"more than one top-level '{KEY}:' line; refusing to guess")
    if not keys:
        return out
    k = keys[0]
    out.key_index = k
    out.last_index = k
    rest = lines[k].lstrip(" ")
    rest = rest[rest.index(":") + 1 :].strip()
    flow = re.fullmatch(r"\[\s*\](?:\s+(#.*))?", rest)
    if rest == "" or rest.startswith("#"):
        out.flow_rest = rest
    elif flow is not None:
        out.empty_flow = True
        out.flow_rest = flow.group(1) or ""
    else:
        raise TrustEditError(f"the '{KEY}:' line has an unusual form; edit it by hand")
    j = k + 1
    while j < len(lines):
        line = lines[j]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            j += 1
            continue
        indent = _indent(line)
        if line[indent : indent + 1] == "\t":
            raise TrustEditError("a tab in the indentation; edit by hand")
        if indent < top or (indent == top and not _is_item(stripped)):
            break
        if not _is_item(stripped):
            raise TrustEditError(f"unusual content inside '{KEY}'; edit by hand")
        if out.empty_flow:
            raise TrustEditError(f"'{KEY}: []' is followed by items; edit by hand")
        try:
            value = yaml.safe_load(stripped[1:].strip()) if stripped != "-" else None
        except yaml.YAMLError:
            value = None
        if not isinstance(value, str):
            raise TrustEditError(f"an item of '{KEY}' is not a plain string; edit by hand")
        if not out.items:
            out.item_indent = indent
        out.items.append((j, value))
        out.last_index = j
        j += 1
    return out


def _insert_after(lay: _Layout, index: int, new: list[str]) -> None:
    """Insert ``new`` lines after line ``index`` in the line ending of that line."""
    original = lay.eols[index]
    use = original or lay.style
    lay.eols[index] = use
    lay.lines[index + 1 : index + 1] = new
    lay.eols[index + 1 : index + 1] = [use] * (len(new) - 1) + [original]


def _join(lay: _Layout) -> str:
    return "".join(line + eol for line, eol in zip(lay.lines, lay.eols, strict=True))


def entries_of(text: str) -> list[str]:
    """The entries of ``trusted_projects`` as written (empty when the key is absent)."""
    return [value for _i, value in _layout(text).items]


def add_entry_text(text: str, entry: str) -> str:
    """``text`` with ``- "<entry>"`` appended to ``trusted_projects`` (the key is created right
    after ``version:`` when absent). Everything else is untouched."""
    lay = _layout(text)
    quoted = _quote(entry)
    if lay.key_index is None:
        pad = " " * (lay.top_indent + _DEFAULT_ITEM_INDENT)
        block = [
            "",
            " " * lay.top_indent + KEY_COMMENT,
            " " * lay.top_indent + f"{KEY}:",
            pad + f"- {quoted}",
        ]
        nxt = lay.version_index + 1
        if nxt < len(lay.lines) and lay.lines[nxt].strip():
            block.append("")
        _insert_after(lay, lay.version_index, block)
        return _join(lay)
    pad = " " * lay.item_indent
    if lay.empty_flow:
        suffix = f" {lay.flow_rest}" if lay.flow_rest else ""
        lay.lines[lay.key_index] = " " * lay.top_indent + f"{KEY}:{suffix}"
    _insert_after(lay, lay.last_index, [pad + f"- {quoted}"])
    return _join(lay)


def remove_entries_text(text: str, victims: set[int]) -> str:
    """``text`` without the items at the given line indexes (see ``_layout``)."""
    lay = _layout(text)
    for i in sorted(victims, reverse=True):
        if i not in {idx for idx, _v in lay.items}:
            raise TrustEditError("internal error: not an item line")
        del lay.lines[i]
        del lay.eols[i]
    if lay.key_index is not None and len(victims) == len(lay.items):
        suffix = f" {lay.flow_rest}" if lay.flow_rest else ""
        lay.lines[lay.key_index] = " " * lay.top_indent + f"{KEY}: []{suffix}"
    return _join(lay)


def _data(text: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        raise TrustEditError("the policy is not plain YAML this command can compare") from None
    if not isinstance(data, dict):
        raise TrustEditError("the top level of the policy is not a mapping")
    return data


def _verify(old_text: str, new_text: str, expected: list[str]) -> None:
    """The edit changed ``trusted_projects`` to ``expected`` and nothing else."""
    old, new = _data(old_text), _data(new_text)
    rest_old = {k: v for k, v in old.items() if k != KEY}
    rest_new = {k: v for k, v in new.items() if k != KEY}
    if rest_old != rest_new:
        raise TrustEditError("the edit would change more than the trusted_projects block")
    got = new.get(KEY, [])
    if got != expected:
        raise TrustEditError("the edited list does not read back as intended; edit by hand")


# --------------------------------------------------------------------------------------------
# Reading (list, doctor)
# --------------------------------------------------------------------------------------------


def home_for_policy() -> str:
    return os.path.expanduser("~")


def read_entries(policy_path: str) -> list[str]:
    """The trusted entries of a policy that LOADS (raises ``PolicyError`` otherwise)."""
    load_policy(policy_path, home=home_for_policy())
    _bom, text = _decode(_read_policy_bytes(policy_path), policy_path)
    return entries_of(text)


# --------------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------------


def _fail(message: str) -> int:
    console.err(f"boundkeep: {message}")
    return EXIT_PROBLEM


def _stdin_is_tty() -> bool:
    """A person at a console: ``isatty`` is not enough on Windows, where the NUL device claims to
    be a terminal, so the handle must also accept ``GetConsoleMode``."""
    try:
        if sys.stdin is None or not sys.stdin.isatty():
            return False
        if sys.platform != "win32":
            return True
        import ctypes
        import msvcrt
        from ctypes import wintypes

        handle = msvcrt.get_osfhandle(sys.stdin.fileno())
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetConsoleMode.restype = wintypes.BOOL
        mode = wintypes.DWORD()
        return bool(kernel32.GetConsoleMode(wintypes.HANDLE(handle), ctypes.byref(mode)))
    except (ValueError, OSError, AttributeError):
        return False


def _read_text(policy_path: str) -> tuple[str, str]:
    return _decode(_read_policy_bytes(policy_path), policy_path)


def _commit(policy_path: str, bom: str, old_text: str, new_text: str, expected: list[str]) -> None:
    """Validate ``new_text`` with the real loader and replace the file atomically and privately."""
    _verify(old_text, new_text, expected)
    try:
        parse_policy_text(new_text, home=home_for_policy())
    except PolicyError as exc:
        raise exc.with_path(policy_path) from None
    _atomic_write(policy_path, (bom + new_text).encode("utf-8"))
    try:
        fsperm.ensure_private_file(policy_path)
    except OSError as exc:
        console.err(f"boundkeep: warning: could not make {policy_path} private ({exc})")


def guard_tree_reason(path: str) -> str | None:
    """Why ``path`` (a directory) cannot be a trusted project because it is one of the home
    directory's key, settings or application-data trees (``~/.ssh``, ``~/.claude``, ``AppData``);
    None when it is not. Checked by ``trust add`` and ``doctor``, not by the policy loader (an old
    entry must not make the whole policy unloadable, X1 re-review R-6)."""
    try:
        key = norm_paths.normalize_path(path, cwd=None, home=None, dialect="tool", literal=True).key
        home = norm_paths.normalize_path(
            home_for_policy(), cwd=None, home=None, dialect="tool", literal=True
        ).key
    except Exception:  # noqa: BLE001 - a helper for a warning must not stop the command
        return None
    return home_guard_tree_reason(key, home)


# Claude Code sets these in every shell it starts for the agent, and a child process inherits them,
# including one started with Start-Process / `cmd /c start` (which DOES get a real console: the
# terminal check below cannot tell a person from an agent's child, X1 review of M1c-2, H-5).
AGENT_ENV = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT")


def agent_environment() -> str | None:
    """The name of the first variable that marks this process as started by Claude Code."""
    for name in AGENT_ENV:
        if os.environ.get(name):
            return name
    return None


# X1 review of M1c-2 (M-3): an entry means "this directory and everything under it", so trusting
# `~/dev` also trusts every repository later cloned into it. `trust add` looks for repositories
# below the directory (bounded) and makes the user say yes to them.
NESTED_MAX_DEPTH = 3
NESTED_MAX_ENTRIES = 5000
NESTED_SHOWN = 5
_NESTED_SKIP = frozenset({".git", "node_modules", ".venv", "venv", "site-packages", "__pycache__"})


_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT


def _is_junction(entry: os.DirEntry[str]) -> bool:
    """A Windows junction or any reparse point: ``is_dir(follow_symlinks=False)`` is True for it
    (X1 re-review R-10), and the search must not go through it."""
    if sys.platform != "win32":
        return False
    attributes = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
    return bool(attributes & _REPARSE_POINT)


def nested_repositories(directory: str) -> tuple[list[str], bool]:
    """(repositories below ``directory``, whether the search was cut short).

    A repository is a directory that holds ``.git`` (a directory, or the file a worktree or a
    submodule has). ``directory`` itself is not listed. Looks ``NESTED_MAX_DEPTH`` levels down in at
    most ``NESTED_MAX_ENTRIES`` entries, never inside ``.git`` or dependency directories, never
    through a link. Never raises.
    """
    found: list[str] = []
    seen = 0
    cut = False
    stack: list[tuple[str, int]] = [(directory, 0)]
    try:
        while stack:
            current, depth = stack.pop()
            try:
                with os.scandir(current) as entries:
                    children = list(entries)
            except OSError:
                continue
            names = {child.name for child in children}
            if depth > 0 and ".git" in names:
                found.append(os.path.relpath(current, directory))
            for child in children:
                seen += 1
                if seen > NESTED_MAX_ENTRIES:
                    return sorted(found), True
                if child.name in _NESTED_SKIP:
                    continue
                try:
                    if not child.is_dir(follow_symlinks=False) or _is_junction(child):
                        continue
                except OSError:
                    continue
                if depth + 1 > NESTED_MAX_DEPTH:
                    cut = True
                    continue
                stack.append((child.path, depth + 1))
    except Exception:  # noqa: BLE001 - a warning helper must not stop `trust add`
        return sorted(found), True
    return sorted(found), cut


def _confirm(question: str) -> bool:
    """Ask the person at the terminal; only the word ``yes`` counts."""
    try:
        return input(f"{question} Type 'yes' to trust it anyway: ").strip().lower() == "yes"
    except (EOFError, KeyboardInterrupt):
        return False


def cmd_add(args: argparse.Namespace) -> int:
    policy_path = paths.policy_file()
    marker = agent_environment()
    if marker is not None:
        return _fail(
            f"trust add refuses to run inside a process Claude Code started ({marker} is set in "
            "the environment): it widens what runs without asking, so it is a command for you, "
            "in your own terminal. If this IS your own terminal, start it from outside Claude "
            f"Code or unset {marker}"
        )
    if not _stdin_is_tty():
        return _fail(
            "trust add needs an interactive terminal (it widens what runs without asking, so "
            "it is not run from a pipe, a script or by the agent); run it yourself in a terminal"
        )
    given = args.project_dir or os.getcwd()
    canonical = canonical_dir(given)
    if not os.path.isdir(canonical):
        return _fail(f"{canonical} is not an existing directory")
    guard = guard_tree_reason(canonical)
    if guard is not None:
        return _fail(f"{canonical} cannot be a trusted project: {guard}")
    try:
        bom, text = _read_text(policy_path)
        entries = entries_of(text)
        if any(_matches(e, canonical, given) for e in entries):
            console.out(f"already trusted: {canonical}")
            return EXIT_OK
        nested, cut = nested_repositories(canonical)
        if nested:
            shown = ", ".join(printable_entry(n, 80) for n in nested[:NESTED_SHOWN])
            more = f" and {len(nested) - NESTED_SHOWN} more" if len(nested) > NESTED_SHOWN else ""
            noun = "repository" if len(nested) == 1 else "repositories"
            partial = " (the search was cut short)" if cut else ""
            console.out(
                f"{canonical} contains {len(nested)} other {noun}{partial}: {shown}{more}. "
                "Trusting it trusts them too, and anything cloned into it later."
            )
            if not _confirm("Is that what you want?"):
                return _fail("not trusted: confirmation not given")
        elif not os.path.exists(os.path.join(canonical, ".git")):
            console.out(
                f"note: {canonical} is not the root of a git repository; everything below it is "
                "trusted (a repository's own root is the usual choice)"
            )
        new_text = add_entry_text(text, canonical)
        _commit(policy_path, bom, text, new_text, [*entries, canonical])
    except PolicyError as exc:
        return _fail(f"policy: {exc}")
    except TrustEditError as exc:
        return _fail(f"{policy_path}: {exc}")
    console.out(f"trusted: {canonical}")
    console.out(f"policy : {policy_path}")
    console.out("")
    console.out(WARNING)
    console.out("A running daemon picks the change up on the next event.")
    return EXIT_OK


def cmd_remove(args: argparse.Namespace) -> int:
    policy_path = paths.policy_file()
    given = args.project_dir or os.getcwd()
    canonical = canonical_dir(given)
    try:
        bom, text = _read_text(policy_path)
        lay = _layout(text)
        hits = [(i, v) for i, v in lay.items if _matches(v, canonical, given)]
        if not hits:
            parse_policy_text(text, home=home_for_policy())  # an unusable policy is an error
            console.out(f"not in the trusted list: {canonical}")
            return EXIT_OK
        gone = {i for i, _v in hits}
        remaining = [v for i, v in lay.items if i not in gone]
        new_text = remove_entries_text(text, gone)
        _commit(policy_path, bom, text, new_text, remaining)
    except PolicyError as exc:
        return _fail(f"policy: {exc}")
    except TrustEditError as exc:
        return _fail(f"{policy_path}: {exc}")
    for _i, value in hits:
        console.out(f"no longer trusted: {value}")
    console.out("A running daemon picks the change up on the next event.")
    return EXIT_OK


def cmd_list(_args: argparse.Namespace) -> int:
    policy_path = paths.policy_file()
    try:
        entries = read_entries(policy_path)
    except PolicyError as exc:
        return _fail(f"policy: {exc}")
    except TrustEditError as exc:
        return _fail(f"{policy_path}: {exc}")
    if not entries:
        console.out("no trusted projects")
        return EXIT_OK
    console.out(f"trusted projects ({len(entries)}) in {policy_path}:")
    for entry in entries:
        state = "exists" if os.path.isdir(expand_entry(entry)) else "missing"
        console.out(f"  {state:<7} {printable_entry(entry)}")
    return EXIT_OK


def add_parser(sub: Any) -> None:
    """Register ``trust`` (with add / remove / list) on the top-level subparsers."""
    p = sub.add_parser(
        "trust",
        help="manage the projects whose own code dev tools may run without asking",
        description="Manage trusted_projects in the active policy (a user command: the agent "
        "must not run it).",
    )
    inner = p.add_subparsers(dest="trust_command", required=True, metavar="action")
    for name, func, text in (
        ("add", cmd_add, "trust a project directory (default: the current directory)"),
        ("remove", cmd_remove, "stop trusting a project directory (default: the current one)"),
    ):
        q = inner.add_parser(name, help=text)
        q.add_argument("--project-dir", help="the directory (default: current directory)")
        q.set_defaults(func=func)
    q = inner.add_parser("list", help="show the trusted projects")
    q.set_defaults(func=cmd_list)
