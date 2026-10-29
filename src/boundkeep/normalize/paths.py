"""Path normalization for the M1 rules: one canonical comparison *key* per path.

Two layers (PROJECT_SPEC.md section 5.1, docs/m1-design.md module A):

* The **lexical layer** (``normalize_path``, ``inside_project``, ``key_of_home``) is pure: no file
  system access, no ``os.environ`` (the environment arrives as a parameter), no ``os.path``. Windows
  and POSIX semantics are implemented by hand, so Windows paths can be tested on any platform.
* The **file system layer** (``resolve_on_disk``) is the only function that touches the disk. It
  expands symlinks, junctions and 8.3 short names of paths that exist on this machine.

Key format (what ``path_glob`` and ``inside_project`` compare):

* Windows flavor: all forward slashes, ``.``/``..`` and repeated separators collapsed, no trailing
  slash (roots excepted), the whole key ``casefold``-ed: ``c:/users/bob/.ssh/id_rsa``. UNC is
  ``//server/share/...``, a device is ``//./nul`` (or ``//./pipe/name``).
* POSIX flavor: the same, but case is kept: ``/home/dev/proj/a.py``.
* A relative path with no usable ``cwd`` keeps a relative key (``a/b``, ``../x``) and is
  ``uncertain``. An unresolved variable stays in the key verbatim (``$foo/x`` after casefolding).

``SessionDir`` says whether a path is inside one directory of the CURRENT session:
``scratchpad_for`` gives ``<temp dir>/claude/<one segment>/<session id>/scratchpad`` (match field
``path_in_scratchpad``), ``tool_results_for`` gives
``<home>/.claude/projects/<one segment>/<session id>/tool-results``, where Claude Code saves a tool
output too long for the conversation and tells the agent to read it (match fields
``path_in_session_tool_results`` and ``except_session_tool_results``). The temp directory and the
home come from the ``env`` / ``home`` passed in, never from the real machine.

Direction rule: this module only ever produces *information*. ``inside_project`` answers ``True``
only when the path is definitely inside; everything doubtful is ``None`` and a definite outsider is
``False``. Nothing here can make an action allowed by itself.

Known limits are listed in the docstrings of the individual helpers; the short version: the lexical
layer cannot know the real target of an 8.3 short name, an unresolved variable, a glob, a Git Bash
root (``/tmp``) or a drive-relative path, and says so through ``uncertain`` and ``reasons``.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import functools
import ntpath
import os
import posixpath
import re
import stat
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from boundkeep.normalize.model import Flavor, Platform

__all__ = [
    "GlobResult",
    "NormPath",
    "SessionDir",
    "expand_glob",
    "expanded_text",
    "inside_project",
    "is_local_disk",
    "key_of_home",
    "memory_for",
    "normalize_path",
    "project_slug",
    "resolve_on_disk",
    "scratch_plain",
    "scratchpad_for",
    "temp_dir_text",
    "tool_results_for",
]

Dialect = Literal["bash", "powershell", "tool"]

# Longer inputs are truncated (and marked uncertain): the work below is linear, this only bounds it.
_MAX_LEN = 65536

_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{d}" for d in "123456789\u00b9\u00b2\u00b3"}
    | {f"LPT{d}" for d in "123456789\u00b9\u00b2\u00b3"}
)
_LOCAL_SERVERS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]", "."})
_PERCENT_FORBIDDEN = frozenset('%/\\:*?"<>|')
_STREAM_TYPES = frozenset({"DATA", "INDEX_ALLOCATION", "I30", "BITMAP", "ATTRIBUTE_LIST"})
_AMBIGUOUS_DOTS = "trailing-dots-spaces-ambiguous"

# Reasons that only describe what was done to the path and do not make it uncertain.
_INFO_REASONS = frozenset(
    {
        "ads-stripped",
        "trailing-dots-spaces",
        "extended-prefix",
        "device-prefix",
        "nt-prefix",
        "unc",
        "msys-translated",
        "cygdrive-translated",
        "wsl-translated",
        "admin-share-local",
        "variable-expanded",
        "home-expanded",
        "resolved-on-disk",
        "hard-linked",
    }
)

HARD_LINKED = "hard-linked"  # the file has more than one name (see ``_hard_linked``)


@dataclass(frozen=True, slots=True)
class NormPath:
    """A normalized path.

    ``key`` is the canonical comparison key (see the module docstring). ``absolute`` is true when
    the key is anchored (a drive, a UNC share, a device or the POSIX root) -- a relative input that
    was resolved against ``cwd`` is therefore ``absolute`` -- and false for keys that are still
    relative, for ``C:foo`` and for ``\\foo`` without a known drive. ``uncertain`` means the real
    target cannot be known lexically; ``reasons`` says why (stable short tags such as
    ``unresolved-variable:FOO``, ``glob``, ``drive-relative``, ``device:NUL``, ``ads-stripped``,
    ``msys-translated``, ``git-bash-root``, ``short-name-unresolved``, ``unc``).
    """

    raw: str
    key: str
    flavor: Flavor
    absolute: bool
    uncertain: bool
    reasons: tuple[str, ...]
    is_device: bool = False


@dataclass(slots=True)
class _Ctx:
    """What the caller told us about the world (already normalized)."""

    cwd: NormPath | None
    cwd_raw: str | None
    home: NormPath | None
    home_raw: str | None
    env: Mapping[str, str] | None
    dialect: str
    windows_ctx: bool


@dataclass(slots=True)
class _Shape:
    """The lexical structure of one path before collapsing and key assembly."""

    flavor: Flavor
    anchor: str | None  # "c:/", "//srv/share", "//./", "/" ... or None for a relative path
    parts: list[str]
    absolute: bool
    uncertain: bool = False
    is_device: bool = False


_MAX_DETAIL_TAGS = (
    16  # "name:detail" tags (one per variable...): bounded so input cannot bloat them
)


def _add(reasons: list[str], tag: str) -> None:
    if tag in reasons:
        return
    if ":" in tag and sum(1 for r in reasons if ":" in r) >= _MAX_DETAIL_TAGS:
        return
    reasons.append(tag)


# --------------------------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------------------------


def normalize_path(
    raw: str,
    *,
    cwd: str | None,
    home: str | None,
    env: Mapping[str, str] | None = None,
    dialect: Dialect = "tool",
    literal: bool = False,
    glob_literal: bool = False,
) -> NormPath:
    """Normalize ``raw`` to a ``NormPath`` (lexical layer: pure, no file system, no ``os.environ``).

    ``cwd`` anchors relative paths, ``home`` is what ``~`` and ``$HOME`` mean, ``env`` supplies
    other variables (``%APPDATA%``, ``$env:TEMP``, ...). ``dialect`` says how the string reached us:
    ``bash`` (a shell word after quote removal; backslashes are not separators unless the path is
    unmistakably a Windows one), ``powershell`` or ``tool`` (a ``file_path`` from a hook event).
    ``glob_literal`` says ``*``, ``?``, ``[`` and ``{`` are ordinary characters of the name (a file
    tool's ``app/[id]/page.tsx``); ``~`` and variables are still expanded. ``literal`` says the
    text is a real path value: nothing is expanded or taken for a glob (the paths found on disk).
    Never raises: an internal error yields an uncertain result with reason ``internal-error``.
    Whatever cannot be known lexically sets ``uncertain``; nothing is ever assumed safe.
    """
    text = raw if isinstance(raw, str) else ""
    try:
        return _normalize(text, cwd, home, env, dialect, literal, glob_literal)
    except Exception:  # noqa: BLE001 - the contract is "never raises"; fail as uncertain
        return NormPath(text, text[:512], "posix", False, True, ("internal-error",))


def expanded_text(
    raw: str,
    *,
    cwd: str | None,
    home: str | None,
    env: Mapping[str, str] | None = None,
    dialect: Dialect = "tool",
) -> str | None:
    """``raw`` after ``~``/variable expansion and anchoring to ``cwd``, with ``.``/``..`` KEPT.

    The lexical key collapses ``link/../x`` to ``x``; the kernel resolves the link first. This is
    the text to hand to ``os.path.realpath`` to see where such a path really leads. None when the
    text cannot be expanded with certainty (unknown variable, command substitution, no ``cwd`` for
    a relative path, empty). Pure; never raises.
    """
    try:
        if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
            return None
        norm_cwd = _norm(cwd, _literal_ctx(), literal=True) if cwd and cwd.strip() else None
        norm_home = _norm(home, _literal_ctx(), literal=True) if home and home.strip() else None
        windows_ctx = (
            norm_cwd.flavor == "windows"
            if norm_cwd is not None
            else norm_home.flavor == "windows"
            if norm_home is not None
            else dialect == "powershell"
        )
        ctx = _Ctx(
            norm_cwd,
            cwd if norm_cwd is not None else None,
            norm_home,
            home if norm_home is not None else None,
            env,
            dialect if dialect in ("bash", "powershell", "tool") else "tool",
            windows_ctx,
        )
        reasons: list[str] = []
        text, uncertain = _expand(raw, ctx, reasons)
        if uncertain or not text.strip():
            return None
        if text[0] in "/\\" or (len(text) > 1 and text[1] == ":"):
            return text
        if ctx.cwd_raw is None:
            return None
        return ctx.cwd_raw.rstrip("/\\") + "/" + text
    except Exception:  # noqa: BLE001 - never raise from a helper
        return None


def inside_project(path: NormPath, project_root: NormPath | None) -> bool | None:
    """True only when ``path`` is *definitely* inside ``project_root``; None if unsure, else False.

    None covers: no project root, an uncertain or non-absolute path or root, a device, a different
    flavor, a different drive or share (junctions and ``subst`` make "different drive" unknowable
    lexically). Inside means equal to the root or below it, compared on whole path segments
    (``/proj2`` is not inside ``/proj``); Windows-flavor keys are already casefolded, POSIX keys
    keep their case. Never raises.
    """
    try:
        return _inside_project(path, project_root)
    except Exception:  # noqa: BLE001 - never raise from a decision helper; None means "unsure"
        return None


def resolve_on_disk(path: NormPath) -> NormPath:
    """File system layer: expand symlinks, junctions and 8.3 short names of an existing path.

    Only for a path that is absolute, certain (or uncertain *only* because of an unresolved short
    name), not a device, not a UNC path (it could block on the network) and of this machine's
    flavor. The result is re-normalized, keeps ``raw`` and gets the reason ``resolved-on-disk``
    when the key changed. Never raises; on any failure the path is returned unchanged.
    """
    try:
        return _resolve_on_disk(path)
    except Exception:  # noqa: BLE001 - never raise; unchanged is the safe failure
        return path


def key_of_home(home: str) -> str:
    """The key of a home directory (for expanding ``~/`` in policy globs at load time).

    ``home`` is taken literally (no variable expansion). Never raises; an empty or unusable value
    gives an empty key.
    """
    try:
        return _norm(home, _literal_ctx(), literal=True).key
    except Exception:  # noqa: BLE001 - never raise
        return ""


# --------------------------------------------------------------------------------------------
# The session's own directories: the scratchpad, the tool-results directory, the project memory
# --------------------------------------------------------------------------------------------

# Claude Code's session ids are UUIDs and so is the name of the session's directory below
# ``<temp>/claude/<project slug>/`` and ``~/.claude/projects/<project slug>/``. Anything else is
# never the session's directory (no ``..``, no wildcard, no separator, no other length).
# ``fullmatch``: no trailing newline is tolerated either.
_SESSION_ID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", re.ASCII)
# The segments below the root, in order: a literal name, the project slug (any one segment but
# ``.`` / ``..``) or the session id. Below a session id the slug is not recomputed from the
# project directory: the id already picks one session. The project memory has no session id, so
# there the slug must be one of the names computed for the current project (``memory_for``).
_SLUG = "<slug>"
_SESSION = "<session>"
_SCRATCH_LAYOUT = ("claude", _SLUG, _SESSION, "scratchpad")  # below the temp directory
_TOOL_RESULTS_LAYOUT = (".claude", "projects", _SLUG, _SESSION, "tool-results")  # below the home
_MEMORY_LAYOUT = (".claude", "projects", _SLUG, "memory")  # below the home
# Claude Code names a project's directory below ~/.claude/projects by turning every character of
# its path that is not an ASCII letter or digit into "-" (``E:\boundkeep`` -> ``E--boundkeep``)
_NOT_IN_SLUG = re.compile(r"[^A-Za-z0-9]")
# What the path layer may have done to a path that still counts as "the scratchpad": spellings of
# the SAME file (an NTFS stream name, one trailing dot, the ``\\?\`` / ``\\.\`` / ``\??\`` prefixes,
# the on-disk resolved form). Anything else (a translated MSYS / Cygwin / WSL path, an admin share,
# a UNC name, an expanded ``~`` or variable, a reason added later) is a reading the daemon cannot
# tell is what the tool will do, and is never marked.
_PLAIN_REASONS = frozenset(
    {
        "ads-stripped",
        "trailing-dots-spaces",
        "extended-prefix",
        "device-prefix",
        "nt-prefix",
        "resolved-on-disk",
    }
)
# A name with one of these may be a pattern for some tool (a brace list, a bracket class), and a
# Windows name cannot contain them at all. ``normalize.event`` never lets a path OPERAND of a file
# or search tool that has one count as the scratchpad (``scratch_plain``); the file name a Grep
# ``glob`` is probed with is exempt, it is not a path anything opens.
SCRATCH_METACHARS = frozenset('*?[]{}<>|"')


def scratch_plain(key: str) -> bool:
    """True when ``key`` has none of the characters that may make a name a pattern."""
    return not any(ch in SCRATCH_METACHARS for ch in key)


def temp_dir_text(
    platform: Platform, env: Mapping[str, str] | None, home: str | None
) -> str | None:
    """The temp directory of the machine the daemon runs on, as text; None when unknown.

    Derived from the ``env`` and ``home`` the caller passes (never from ``tempfile`` or the real
    machine, so a fake machine is deterministic). Windows: ``TEMP``, else ``TMP``, else
    ``%LOCALAPPDATA%\\Temp``, else ``<home>\\AppData\\Local\\Temp`` (names compare without case; the
    first non-blank one decides, an unusable value does not fall through to the next; two spellings
    of the same name with different values are a doubt: None). POSIX: ``TMPDIR``, else ``/tmp``.
    """
    try:
        values = env or {}
        if platform == "windows":
            found: dict[str, set[str]] = {}
            for key, value in values.items():
                if isinstance(key, str) and isinstance(value, str) and value.strip():
                    found.setdefault(key.upper(), set()).add(value)
            if any(len(found.get(name, ())) > 1 for name in ("TEMP", "TMP", "LOCALAPPDATA")):
                return None
            for name in ("TEMP", "TMP"):
                if name in found:
                    return next(iter(found[name]))
            if "LOCALAPPDATA" in found:
                return next(iter(found["LOCALAPPDATA"])).rstrip("\\/") + "\\Temp"
            if home and home.strip():
                return home.rstrip("\\/") + "\\AppData\\Local\\Temp"
            return None
        tmpdir = values.get("TMPDIR")
        if isinstance(tmpdir, str) and tmpdir.strip():
            return tmpdir
        return "/tmp"  # noqa: S108
    except Exception:  # noqa: BLE001 - never raise; None means "no scratchpad"
        return None


class SessionDir:
    """One directory of the current session: ``<root>/<layout>``, for example the scratchpad
    ``<temp>/claude/<one segment>/<session id>/scratchpad``.

    ``contains`` says whether a normalized path is the directory itself or below it. The caller
    asks for each form of a path (its lexical key and, when a symlink / junction / short name
    changes it, the on-disk resolved key) and a path only counts when EVERY form does: a junction
    inside the directory that leads elsewhere, or a session directory that is itself a link to
    somewhere else, makes the resolved form leave the resolved root.

    Only this exact session counts (the id compares without case), only below THIS machine's root
    (the temp directory, ``temp_dir_text``, or the home), only one segment for the project slug
    (one of ``slugs`` when they are given), and the literal names compare without case on Windows
    and exactly on POSIX. The root is resolved on disk lazily, once, and only when a path got that
    far.
    """

    __slots__ = ("_resolved", "_resolved_done", "_root", "flavor", "layout", "session", "slugs")

    def __init__(
        self,
        session: str,
        root: NormPath,
        layout: tuple[str, ...],
        slugs: frozenset[str] | None = None,
    ) -> None:
        self.session = session.casefold()
        self.flavor: Flavor = root.flavor
        self.layout = layout
        # Windows keys are casefolded, so the names are too (the drive letter's case differs
        # between the CLI and VS Code); POSIX keeps case
        self.slugs = (
            None
            if slugs is None
            else frozenset(s.casefold() for s in slugs)
            if root.flavor == "windows"
            else slugs
        )
        self._root = root
        self._resolved: str | None = None
        self._resolved_done = False

    def _resolved_root(self) -> str | None:
        """The key of the root after link and short-name resolution (None: unusable)."""
        if not self._resolved_done:
            self._resolved_done = True
            resolved = resolve_on_disk(self._root)
            if _usable_root(resolved, self.flavor):
                self._resolved = resolved.key
        return self._resolved

    def _lexical_root(self) -> str | None:
        # A root spelled with an 8.3 short name is "uncertain" lexically; the paths Claude Code
        # reports then name it in full, so the resolved spelling is the root to compare with.
        if not self._root.uncertain:
            return self._root.key
        return self._resolved_root()

    def contains(self, path: NormPath, *, resolved: bool) -> bool:
        """Is ``path`` the directory or below it? ``resolved``: it is an on-disk resolved form.

        Never raises; anything doubtful (uncertain, relative, device, other flavor, a key that is
        not clean) is False.
        """
        try:
            if path.uncertain or path.is_device or not path.absolute or path.flavor != self.flavor:
                return False
            if not _clean_key(path.key) or not set(path.reasons) <= _PLAIN_REASONS:
                return False
            root = self._resolved_root() if resolved else self._lexical_root()
            if root is None:
                return False
            return self._below(path.key, root)
        except Exception:  # noqa: BLE001 - a guard that raises would be worse than saying no
            return False

    def _below(self, key: str, root: str) -> bool:
        prefix = root if root.endswith("/") else root + "/"
        if not key.startswith(prefix):
            return False
        parts = key[len(prefix) :].split("/")
        if len(parts) < len(self.layout):
            return False
        for part, want in zip(parts, self.layout, strict=False):
            if want == _SLUG:
                ok = bool(part) and part not in (".", "..")
                ok = ok and (self.slugs is None or part in self.slugs)
            elif want == _SESSION:
                ok = part.casefold() == self.session
            elif self.flavor == "windows":
                ok = part.casefold() == want
            else:
                ok = part == want
            if not ok:
                return False
        return True


def _usable_root(root: NormPath, flavor: Flavor) -> bool:
    """A directory that may root a session directory: absolute, certain, on a local-looking
    anchor."""
    if root.uncertain or root.is_device or not root.absolute or root.flavor != flavor:
        return False
    if not _clean_key(root.key) or not scratch_plain(root.key):
        return False
    anchor = _anchor_of(root.key, flavor)
    if flavor == "posix":
        return anchor == "/"
    # a drive letter ("c:"): never a UNC share (a network directory) or a device
    return anchor is not None and len(anchor) == 2 and anchor[1] == ":"


def _session_root(text: str, platform: Platform) -> NormPath | None:
    """``text`` (the temp directory or the home) as a root for a ``SessionDir``, or None."""
    root = normalize_path(text, cwd=None, home=None, dialect="tool", literal=True)
    flavor: Flavor = "windows" if platform == "windows" else "posix"
    if root.flavor != flavor or set(root.reasons) - {"short-name-unresolved"}:
        return None  # (an odd spelling of the directory: no session directory)
    if not scratch_plain(root.key):
        return None  # (a pattern character: `literal` skipped the glob check)
    if root.uncertain:
        # only an unresolved 8.3 short name may be repaired (by the disk lookup); any other
        # doubt (a variable, a glob, a relative path ...) means there is no session directory
        blocking = [r for r in root.reasons if r not in _INFO_REASONS]
        if blocking != ["short-name-unresolved"]:
            return None
    elif not _usable_root(root, flavor):
        return None
    return root


def scratchpad_for(
    session_id: str | None,
    platform: Platform,
    env: Mapping[str, str] | None,
    home: str | None,
) -> SessionDir | None:
    """The scratchpad of the session ``session_id`` on this (possibly fake) machine, or None.

    None unless the id is a UUID and the temp directory (``temp_dir_text``) is usable. Pure: the
    disk is not touched here (see ``SessionDir`` for the lazy lookup). Never raises.
    """
    try:
        if not isinstance(session_id, str) or _SESSION_ID.fullmatch(session_id) is None:
            return None
        text = temp_dir_text(platform, env, home)
        if text is None:
            return None
        root = _session_root(text, platform)
        return None if root is None else SessionDir(session_id, root, _SCRATCH_LAYOUT)
    except Exception:  # noqa: BLE001 - never raise; None means "no scratchpad"
        return None


def tool_results_for(
    session_id: str | None, platform: Platform, home: str | None
) -> SessionDir | None:
    """The tool-results directory of the session ``session_id``, or None.

    ``<home>/.claude/projects/<one segment>/<session id>/tool-results``: Claude Code saves a tool
    output that is too long for the conversation there (a subagent's too, under the parent
    session's id, which is the ``session_id`` its hook events carry) and tells the agent to read
    it. Only ``~/.claude`` counts; a ``CLAUDE_CONFIG_DIR`` elsewhere is never this directory.
    None unless the id is a UUID and the home is usable. Pure, never raises.
    """
    try:
        if not isinstance(session_id, str) or _SESSION_ID.fullmatch(session_id) is None:
            return None
        if not isinstance(home, str) or not home.strip():
            return None
        root = _session_root(home, platform)
        return None if root is None else SessionDir(session_id, root, _TOOL_RESULTS_LAYOUT)
    except Exception:  # noqa: BLE001 - never raise; None means "no tool-results directory"
        return None


def project_slug(text: str) -> str:
    """Claude Code's name for the directory of ``text`` below ``~/.claude/projects``."""
    return _NOT_IN_SLUG.sub("-", text)


def memory_for(project: NormPath | None, platform: Platform, home: str | None) -> SessionDir | None:
    """The current project's auto memory directory, ``<home>/.claude/projects/<slug>/memory``.

    Claude Code derives ``<slug>`` from the git repository root, or the project root outside a
    repository (code.claude.com/docs/en/memory, "Storage location", checked 2026-10-29). The git
    root is the project directory or one of its ancestors and is not looked up here, so the slug of
    the project directory and of each ancestor counts, up to but not including the home directory
    or a drive / filesystem root (a session in one project must not read another project's notes,
    and the home is not a project). Not recognized, so never "the memory": a slug Claude Code
    shortens (a very long path), ``autoMemoryDirectory``, ``CLAUDE_CODE_PROJECT_DIR_NAME``, a
    ``CLAUDE_CONFIG_DIR`` elsewhere. None when the project or the home is unusable. Pure, never
    raises.
    """
    try:
        if project is None or project.uncertain or project.is_device or not project.absolute:
            return None
        if not isinstance(home, str) or not home.strip():
            return None
        root = _session_root(home, platform)
        if root is None:
            return None
        path_mod = ntpath if platform == "windows" else posixpath
        same = (lambda a, b: a.casefold() == b.casefold()) if platform == "windows" else str.__eq__
        stop = path_mod.normpath(home)
        text = path_mod.normpath(project.raw)
        slugs: set[str] = set()
        for _ in range(64):  # a path deeper than this is not a project anyone launched
            parent = path_mod.dirname(text)
            if parent == text or same(text, stop):
                break
            slugs.add(project_slug(text))
            text = parent
        if not slugs:
            return None
        return SessionDir("", root, _MEMORY_LAYOUT, frozenset(slugs))
    except Exception:  # noqa: BLE001 - never raise; None means "no memory directory"
        return None


# --------------------------------------------------------------------------------------------
# Context
# --------------------------------------------------------------------------------------------


def _literal_ctx() -> _Ctx:
    return _Ctx(None, None, None, None, None, "tool", False)


@functools.lru_cache(maxsize=512)
def _literal_norm(text: str) -> NormPath:
    """The key of a real path value (the working directory, the home): pure, and the same few
    strings come back for every path of a command line, so the result is remembered."""
    return _norm(text, _literal_ctx(), literal=True)


def _normalize(
    text: str,
    cwd: str | None,
    home: str | None,
    env: Mapping[str, str] | None,
    dialect: str,
    literal: bool = False,
    glob_literal: bool = False,
) -> NormPath:
    if dialect not in ("bash", "powershell", "tool"):
        dialect = "tool"
    cwd_n = _literal_norm(cwd) if isinstance(cwd, str) and cwd.strip() else None
    home_n = _literal_norm(home) if isinstance(home, str) and home.strip() else None
    if cwd_n is not None:
        windows_ctx = cwd_n.flavor == "windows"
    elif home_n is not None:
        windows_ctx = home_n.flavor == "windows"
    else:
        windows_ctx = dialect == "powershell"
    ctx = _Ctx(
        cwd_n,
        cwd if cwd_n is not None else None,
        home_n,
        home if home_n is not None else None,
        env,
        dialect,
        windows_ctx,
    )
    return _norm(text, ctx, literal=literal, glob_literal=glob_literal)


def _default_flavor(ctx: _Ctx) -> Flavor:
    if ctx.cwd is not None:
        return ctx.cwd.flavor
    return "windows" if ctx.windows_ctx else "posix"


# --------------------------------------------------------------------------------------------
# Variable and tilde expansion
# --------------------------------------------------------------------------------------------


def _env_get(env: Mapping[str, str] | None, name: str, case_insensitive: bool) -> str | None:
    if not env or not name:
        return None
    value = env.get(name)
    if isinstance(value, str):
        return value
    if case_insensitive:
        low = name.casefold()
        for key, val in env.items():
            if isinstance(key, str) and isinstance(val, str) and key.casefold() == low:
                return val
    return None


def _tilde_value(ctx: _Ctx) -> str | None:
    if ctx.home_raw is not None and ctx.home_raw.strip():
        return ctx.home_raw
    for name in ("HOME", "USERPROFILE") if ctx.dialect != "bash" else ("HOME",):
        value = _env_get(ctx.env, name, ctx.dialect != "bash")
        if value and value.strip():
            return value
    return None


# Variables a Windows machine always has, with their standard values; only used when the
# environment handed to us does not carry them (a hook environment can be stripped).
_WINDOWS_DEFAULTS = {"PROGRAMDATA": "C:\\ProgramData", "ALLUSERSPROFILE": "C:\\ProgramData"}


def _lookup(name: str, syntax: str, ctx: _Ctx) -> str | None:
    """The value of a variable, or None when it is not known. Names are case-sensitive in bash."""
    ci = ctx.dialect != "bash" or syntax in ("env-colon", "percent")
    key = name.upper() if ci else name
    if key == "PWD" and syntax in ("dollar", "brace") and ctx.cwd_raw is not None:
        return ctx.cwd_raw
    value = _env_get(ctx.env, name, ci)
    if value is not None:
        return value
    if key == "HOME":
        if ctx.dialect != "bash":
            value = _env_get(ctx.env, "USERPROFILE", True)
            if value is not None:
                return value
        return ctx.home_raw
    if key == "USERPROFILE" and ctx.dialect != "bash":
        return ctx.home_raw
    if ctx.windows_ctx and ci and key in _WINDOWS_DEFAULTS:
        return _WINDOWS_DEFAULTS[key]  # absent from the environment: the standard location
    return None


def _native_syntax(name: str, syntax: str, dialect: str) -> bool:
    """Does the dialect really expand this syntax (else we over-match and stay uncertain)?"""
    if dialect == "bash":
        return syntax in ("dollar", "brace")
    if dialect == "powershell":
        if syntax == "env-colon":
            return True
        return syntax in ("dollar", "brace") and name.upper() in ("HOME", "PWD")
    return False


def _looks_absolute(value: str) -> bool:
    if value[:1] in ("/", "\\", "~"):
        return True
    return len(value) >= 2 and value[1] == ":" and value[0].isascii() and value[0].isalpha()


def _is_ident(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch == "_")


def _expand(text: str, ctx: _Ctx, reasons: list[str]) -> tuple[str, bool]:
    """Expand ``~`` and known variables in one left-to-right pass (values are not rescanned).

    Unknown variables stay in the text verbatim and make the path uncertain.
    """
    n = len(text)
    out: list[str] = []
    uncertain = False
    i = 0
    if text[0] == "~":
        if n == 1 or text[1] in "/\\":
            value = _tilde_value(ctx)
            if value is None:
                _add(reasons, "unresolved-home")
                uncertain = True
            else:
                out.append(value)
                i = 1
                _add(reasons, "home-expanded")
        else:
            # ~user, ~+, ~-: nothing below can be trusted, and expanding further could turn
            # the key into something that expands differently the next time it is normalized
            _add(reasons, "tilde-user")
            return text, True
    no_more_brace = False
    no_more_percent = False
    while i < n:
        ch = text[i]
        name = ""
        syntax = ""
        end = i + 1
        if ch == "$":
            nxt = text[i + 1] if i + 1 < n else ""
            if nxt == "(":
                _add(reasons, "command-substitution")
                uncertain = True
            elif nxt == "{":
                j = -1 if no_more_brace else text.find("}", i + 2)
                if j == -1:
                    no_more_brace = True
                    _add(reasons, "unresolved-expansion")
                    uncertain = True
                else:
                    inner = text[i + 2 : j]
                    if inner[:4].lower() == "env:":
                        name, syntax = inner[4:], "env-colon"
                    else:
                        name, syntax = inner, "brace"
                    end = j + 1
            elif text[i + 1 : i + 5].lower() == "env:":
                j = i + 5
                while j < n and _is_ident(text[j]):
                    j += 1
                name, syntax, end = text[i + 5 : j], "env-colon", j
            elif nxt and _is_ident(nxt) and not nxt.isdigit():
                j = i + 1
                while j < n and _is_ident(text[j]):
                    j += 1
                name, syntax, end = text[i + 1 : j], "dollar", j
            elif nxt and nxt in "0123456789@*#?!$-":
                _add(reasons, f"unresolved-variable:{nxt}")
                uncertain = True
                out.append(text[i : i + 2])
                i += 2
                continue
        elif ch == "%":
            j = -1 if no_more_percent else text.find("%", i + 1)
            if j == -1:
                no_more_percent = True
            elif 0 < j - i - 1 <= 64:
                cand = text[i + 1 : j]
                if not any(c in _PERCENT_FORBIDDEN or c.isspace() for c in cand):
                    name, syntax, end = cand, "percent", j + 1
        if not syntax:
            out.append(ch)
            i += 1
            continue
        if syntax == "dollar" and i > 0 and text[i - 1] == ":" and name.upper() in _STREAM_TYPES:
            # ``::$DATA`` is an NTFS stream type, not a variable: leave it for the ADS stripper
            out.append(text[i:end])
            i = end
            continue
        value = _lookup(name, syntax, ctx)
        shown = name or "?"
        if value is None:
            _add(reasons, f"unresolved-variable:{shown}")
            uncertain = True
            out.append(text[i:end])
        elif not value.strip():
            _add(reasons, f"empty-variable:{shown}")
            uncertain = True
            out.append(text[i:end])
        else:
            _add(reasons, "variable-expanded")
            if not _native_syntax(name, syntax, ctx.dialect):
                _add(reasons, "variable-syntax-mismatch")
                uncertain = True
            if out and _looks_absolute(value):
                _add(reasons, "variable-mid-path")
                uncertain = True
            out.append(value)
        i = end
    return "".join(out), uncertain


# --------------------------------------------------------------------------------------------
# Lexical helpers
# --------------------------------------------------------------------------------------------


def _ext_prefix_len(text: str) -> int:
    """4 for ``\\\\?\\``, ``\\\\.\\``, ``//?/``, ``//./`` and the NT form ``\\??\\``, else 0."""
    if text.startswith("\\??\\"):
        return 4
    if (
        len(text) >= 4
        and text[0] in "\\/"
        and text[1] in "\\/"
        and text[2] in "?."
        and text[3] in "\\/"
    ):
        return 4
    return 0


def _glob_reasons(body: str) -> list[str]:
    out: list[str] = []
    if any(c in body for c in "*?["):
        out.append("glob")
    k = body.find("{")
    if k >= 0:
        close = body.find("}", k)
        seg = body[k:] if close == -1 else body[k:close]
        if "," in seg or ".." in seg:
            out.append("brace")
    return out


def _win_part(part: str, reasons: list[str], *, final: bool) -> str:
    """One Windows path component without NTFS stream suffix and trailing dots and spaces.

    ``name:stream`` and ``name::$DATA`` name the same file as ``name``. Win32 drops *all* trailing
    dots and spaces of the last component of a path that does not end in a separator, but of any
    other component only one trailing dot. Stripping more than Win32 would is still what the key
    does (a deny rule should match the possible target), but the path is then marked ambiguous so
    that ``inside_project`` never says True for it. A component made only of dots and spaces
    becomes ``..`` when it holds two or more dots (the escaping reading, the cautious one) and
    ``.`` otherwise.
    """
    if ":" in part:
        # An unresolved ``$env:NAME`` / ``${env:NAME}`` is a variable, not a stream: keep its name
        # in the key (``$env:name/x``) so the path stays recognisable and uncertain.
        prefix = ""
        if part[:5].lower() == "$env:":
            prefix, part = part[:5], part[5:]
        elif part[:6].lower() == "${env:" and "}" in part:
            cut = part.index("}") + 1
            prefix, part = part[:cut], part[cut:]
        if ":" in part:
            part = part.split(":", 1)[0]
            _add(reasons, "ads-stripped")
        part = prefix + part
        if part == "":
            return "."
    if part in (".", ".."):
        return part
    stripped = part.rstrip(" .")
    if stripped == part:
        return part
    _add(reasons, "trailing-dots-spaces")
    exact = stripped != "" and (final or (part.endswith(".") and part[:-1] == stripped))
    if not exact:
        _add(reasons, _AMBIGUOUS_DOTS)
    if stripped == "":
        return ".." if part.count(".") >= 2 else "."
    return stripped


def _win_parts(comps: list[str], reasons: list[str], *, ends_sep: bool | None = None) -> list[str]:
    """``_win_part`` over the components of a path; the last one is "final" unless a separator
    follows it (``ends_sep``, inferred from a trailing empty component when not given)."""
    if ends_sep is None:
        ends_sep = bool(comps) and comps[-1] == ""
    kept = [c for c in comps if c != ""]
    last = len(kept) - 1
    return [_win_part(c, reasons, final=(i == last and not ends_sep)) for i, c in enumerate(kept)]


def _collapse(parts: list[str], *, rooted: bool) -> list[str]:
    """Fold ``.``, ``..`` and empty components; ``..`` cannot climb above a root."""
    out: list[str] = []
    for p in parts:
        if p in ("", "."):
            continue
        if p == "..":
            if out and out[-1] != "..":
                out.pop()
            elif not rooted:
                out.append("..")
            continue
        out.append(p)
    return out


def _is_short_name(part: str) -> bool:
    """Does the component look like an 8.3 short name (``PROGRA~1``, ``PROJ~1.TXT``)?"""
    if "." in part:
        stem, ext = part.rsplit(".", 1)
    else:
        stem, ext = part, ""
    if len(ext) > 3:
        return False
    i = stem.rfind("~")
    if i < 1 or len(stem) > 8:
        return False
    digits = stem[i + 1 :]
    return digits.isascii() and digits.isdigit()


def _device_base(part: str) -> str | None:
    """``NUL``, ``COM1`` ... when the component names a DOS device (``NUL.txt`` too), else None."""
    base = part.split(".", 1)[0].rstrip(" ")
    if not base.isascii() and not any(c in base for c in "\u00b9\u00b2\u00b3"):
        return None
    up = base.upper()
    return up if up in _DEVICE_NAMES else None


def _match_msys(comps: list[str]) -> tuple[str, list[str], str] | None:
    """``/c/x`` (MSYS), ``/cygdrive/c/x`` and ``/mnt/c/x`` (WSL) -> (drive, rest, reason)."""

    def letter(s: str) -> bool:
        return len(s) == 1 and s.isascii() and s.isalpha()

    if not comps:
        return None
    if letter(comps[0]):
        return comps[0].lower(), comps[1:], "msys-translated"
    if comps[0] == "cygdrive" and len(comps) > 1 and letter(comps[1]):
        return comps[1].lower(), comps[2:], "cygdrive-translated"
    if comps[0] == "mnt" and len(comps) > 1 and letter(comps[1]):
        return comps[1].lower(), comps[2:], "wsl-translated"
    return None


def _split_key(key: str, flavor: Flavor) -> tuple[str, list[str]] | None:
    """Anchor and parts of an absolute key, or None for devices and relative keys."""
    if flavor == "windows":
        if len(key) >= 3 and key[1] == ":" and key[2] == "/":
            anchor, rest = key[:3], key[3:]
        elif key.startswith("//") and not key.startswith("//./"):
            seg = key[2:].split("/")
            if len(seg) >= 2:
                anchor, rest = "//" + seg[0] + "/" + seg[1], "/".join(seg[2:])
            else:
                anchor, rest = "//" + seg[0], ""
        else:
            return None
    else:
        if not key.startswith("/"):
            return None
        anchor, rest = "/", key[1:]
    return anchor, [p for p in rest.split("/") if p]


def _join(anchor: str, parts: list[str]) -> str:
    if anchor.endswith(("/", "\\")):
        return anchor + "/".join(parts)
    return anchor + "/" + "/".join(parts) if parts else anchor


# --------------------------------------------------------------------------------------------
# Shapes: classify the (expanded) text and produce anchor + parts
# --------------------------------------------------------------------------------------------


def _unc_shape(comps: list[str], ctx: _Ctx, reasons: list[str]) -> _Shape:
    # "." and ".." before the share name cannot mean anything: a share is the root
    comps = _win_parts(comps, reasons)
    head: list[str] = []
    while comps and len(head) < 2:
        part = comps.pop(0)
        if part not in (".", ".."):
            head.append(part)
    comps = head + comps
    if not comps:
        _add(reasons, "unc-incomplete")
        return _Shape("windows", "//", [], absolute=False, uncertain=True)
    server = comps[0]
    if server == "?":
        # "\\?" is the extended-length prefix spelled with too many separators (or stripped of
        # decoration): read it as that, never as a server, so the key cannot be misread later
        _add(reasons, "odd-leading-separators")
        shape = _shape_prefixed("\\\\?\\" + "\\".join(comps[1:]), 4, ctx, reasons)
        shape.uncertain = True
        return shape
    if len(comps) == 1:
        _add(reasons, "unc")
        _add(reasons, "unc-incomplete")
        return _Shape("windows", "//" + server, [], absolute=True, uncertain=True)
    share = comps[1]
    rest = comps[2:]
    admin = len(share) == 2 and share[1] == "$" and share[0].isascii() and share[0].isalpha()
    if admin:
        local = server.casefold() in _LOCAL_SERVERS
        computer = _env_get(ctx.env, "COMPUTERNAME", True)
        if computer and server.casefold() == computer.casefold():
            local = True
        if local:
            # \\localhost\c$\x is C:\x: do not let the share spelling hide a drive path
            _add(reasons, "admin-share-local")
            return _Shape("windows", f"{share[0].lower()}:/", rest, absolute=True)
        _add(reasons, "admin-share")
        _add(reasons, "unc")
        return _Shape("windows", f"//{server}/{share}", rest, absolute=True, uncertain=True)
    _add(reasons, "unc")
    return _Shape("windows", f"//{server}/{share}", rest, absolute=True)


def _shape_prefixed(text: str, plen: int, ctx: _Ctx, reasons: list[str]) -> _Shape:
    """``\\\\?\\...``, ``\\\\.\\...``, ``//./...`` and ``\\??\\...`` forms."""
    ns = "?" if text.startswith("\\??\\") else text[2]
    _add(
        reasons,
        "nt-prefix"
        if text.startswith("\\??\\")
        else "extended-prefix"
        if ns == "?"
        else "device-prefix",
    )
    raw_body = text[plen:]
    uncertain = False
    literal_ns = ns == "?" and text[0] == "\\" and text[1] in "\\?"
    if literal_ns and ("/" in raw_body or any(s in (".", "..") for s in raw_body.split("\\"))):
        # In the real \\?\ namespace these are literal characters, not path operators.
        _add(reasons, "extended-path-dots")
        uncertain = True
    comps = raw_body.replace("\\", "/").split("/")
    first = comps[0]
    if first.upper() == "UNC":
        shape = _unc_shape(comps[1:], ctx, reasons)
        shape.uncertain = shape.uncertain or uncertain
        return shape
    if len(first) == 2 and first[1] == ":" and first[0].isascii() and first[0].isalpha():
        return _Shape(
            "windows", f"{first[0].lower()}:/", _win_parts(comps[1:], reasons), True, uncertain
        )
    # A device or volume path: \\.\NUL, \\.\pipe\x, \\?\Volume{...}\x, \\?\GLOBALROOT\...
    parts = _win_parts(comps, reasons)
    name = (parts[0] if parts else "").upper()
    _add(reasons, f"device:{name}")
    return _Shape("windows", "//./", parts, absolute=True, uncertain=True, is_device=True)


def _shape_drive(text: str, ctx: _Ctx, reasons: list[str]) -> _Shape:
    d = text[0].lower()
    rest = text[2:].replace("\\", "/")
    comps = rest.split("/")
    if rest[:1] == "/":
        return _Shape("windows", f"{d}:/", _win_parts(comps, reasons), absolute=True)
    # C:foo is relative to the current directory *of drive C*, which only the cwd can tell
    _add(reasons, "drive-relative")
    parts = _win_parts(comps, reasons)
    base = _cwd_base(ctx)
    if base is not None and base[0] == f"{d}:/":
        return _Shape("windows", base[0], base[1] + parts, absolute=False, uncertain=True)
    return _Shape("windows", f"{d}:/", parts, absolute=False, uncertain=True)


def _cwd_base(ctx: _Ctx) -> tuple[str, list[str]] | None:
    cwd = ctx.cwd
    if cwd is None or not cwd.absolute or cwd.is_device:
        return None
    return _split_key(cwd.key, cwd.flavor)


def _shape_rooted_windows(
    comps: list[str], ctx: _Ctx, reasons: list[str], ends_sep: bool
) -> _Shape:
    """``\\foo`` (and ``/foo`` outside Git Bash): rooted on the *current* drive of the cwd."""
    parts = _win_parts(comps, reasons, ends_sep=ends_sep)
    base = _cwd_base(ctx)
    if base is not None and ctx.cwd is not None and ctx.cwd.flavor == "windows":
        _add(reasons, "rooted-current-drive")
        return _Shape("windows", base[0], parts, absolute=True, uncertain=True)
    # The key keeps its leading backslash: "/foo" would read as a POSIX or MSYS path next time
    _add(reasons, "rooted-no-drive")
    return _Shape("windows", "\\", parts, absolute=False, uncertain=True)


def _shape_relative(text: str, ctx: _Ctx, reasons: list[str]) -> _Shape:
    has_bs = "\\" in text
    uncertain = False
    flavor: Flavor
    if ctx.cwd is not None:
        flavor = ctx.cwd.flavor
    else:
        flavor = "windows" if (has_bs or ctx.dialect == "powershell") else "posix"
        _add(reasons, "no-cwd")
        uncertain = True
        if has_bs and ctx.dialect == "bash":
            _add(reasons, "backslash-ambiguous")
    if flavor == "windows":
        parts = _win_parts(text.replace("\\", "/").split("/"), reasons)
    else:
        parts = text.split("/")
    # A path that *starts* with something unknowable ($FOO/x, ~bob/x) has no known anchor; the
    # test looks at the visible text so that normalizing the key again decides the same way.
    unanchored = bool(parts) and parts[0][:1] in ("$", "%", "~")
    if unanchored:
        _add(reasons, "unanchored")
        uncertain = True
        if "tilde-user" in reasons and parts[0] == "~":
            parts[0] = "~."  # keep "~" (stripped of dots, spaces or a stream) from reading as home
    if ctx.cwd is not None and not unanchored:
        base = _cwd_base(ctx)
        if base is None:
            _add(reasons, "cwd-unusable")
            return _Shape(flavor, None, parts, absolute=False, uncertain=True)
        if ctx.cwd.uncertain:
            _add(reasons, "cwd-uncertain")
            for r in ctx.cwd.reasons:
                _add(reasons, r)
            uncertain = True
        return _Shape(flavor, base[0], base[1] + parts, absolute=True, uncertain=uncertain)
    return _Shape(flavor, None, parts, absolute=False, uncertain=uncertain)


def _shape(text: str, plen: int, ctx: _Ctx, reasons: list[str]) -> _Shape:
    if plen:
        return _shape_prefixed(text, plen, ctx, reasons)
    if len(text) >= 2 and text[1] == ":" and text[0].isascii() and text[0].isalpha():
        return _shape_drive(text, ctx, reasons)
    c0 = text[0]
    if c0 in "\\/":
        lead = len(text) - len(text.lstrip("\\/"))
        uncertain = False
        if lead >= 2:
            if text.startswith("\\\\") or (ctx.windows_ctx and ("\\" in text[:lead] or lead == 2)):
                if lead > 2:
                    _add(reasons, "odd-leading-separators")
                shape = _unc_shape(text.replace("\\", "/").split("/"), ctx, reasons)
                shape.uncertain = shape.uncertain or lead > 2
                return shape
            if lead == 2 and text[:2] == "//":
                # POSIX collapses "//x" to "/x"; Windows and Git Bash read it as a UNC path
                _add(reasons, "double-slash-root")
                uncertain = True
        t_slash = text.replace("\\", "/")
        # Collapse first: /tmp/../c/x is /c/x, and /c/../x is /x (not a path on drive c)
        comps_nz = _collapse(t_slash.split("/"), rooted=True)
        if c0 == "\\":
            return _shape_rooted_windows(comps_nz, ctx, reasons, t_slash.endswith("/"))
        msys = _match_msys(comps_nz)
        if msys is not None:
            drive, rest, tag = msys
            _add(reasons, tag)
            return _Shape(
                "windows",
                f"{drive}:/",
                _win_parts(rest, reasons, ends_sep=t_slash.endswith("/")),
                absolute=True,
                uncertain=uncertain,
            )
        if ctx.windows_ctx and ctx.dialect == "bash":
            # Git Bash maps "/" to its own install directory and /tmp, /usr, /home to places
            # under it: there is no reliable mapping to a Windows path.
            _add(reasons, "git-bash-root")
            return _Shape("posix", "/", comps_nz, absolute=True, uncertain=True)
        if ctx.windows_ctx:
            shape = _shape_rooted_windows(comps_nz, ctx, reasons, t_slash.endswith("/"))
            shape.uncertain = shape.uncertain or uncertain
            return shape
        return _Shape("posix", "/", text.split("/"), absolute=True, uncertain=uncertain)
    return _shape_relative(text, ctx, reasons)


# --------------------------------------------------------------------------------------------
# The normalizer proper
# --------------------------------------------------------------------------------------------


def _norm(raw: str | None, ctx: _Ctx, *, literal: bool, glob_literal: bool = False) -> NormPath:
    """``literal`` skips ``~``/variable expansion and glob detection (for real path values);
    ``glob_literal`` only skips the glob detection."""
    text = raw if isinstance(raw, str) else ""
    reasons: list[str] = []
    uncertain = False
    if len(text) > _MAX_LEN:
        text = text[:_MAX_LEN]
        _add(reasons, "too-long")
        uncertain = True
    if "\x00" in text:
        _add(reasons, "nul-byte")
        uncertain = True
    if not literal and text.strip():
        text, unc = _expand(text, ctx, reasons)
        uncertain = uncertain or unc
    if not text.strip():
        _add(reasons, "empty")
        return NormPath(raw or "", "", _default_flavor(ctx), False, True, tuple(reasons))

    plen = _ext_prefix_len(text)
    body = text[plen:]
    if not literal and not glob_literal:
        for tag in _glob_reasons(body):
            _add(reasons, tag)
            uncertain = True
    invalid_char = any(c in body for c in '<>"|')

    shape = _shape(text, plen, ctx, reasons)
    uncertain = uncertain or shape.uncertain
    parts = _collapse(shape.parts, rooted=shape.anchor is not None)
    if _AMBIGUOUS_DOTS in reasons:
        uncertain = True
    anchor = shape.anchor
    absolute = shape.absolute
    is_device = shape.is_device

    if shape.flavor == "windows":
        if invalid_char and not literal:
            _add(reasons, "invalid-char")
            uncertain = True
        if any(_is_short_name(p) for p in parts):
            _add(reasons, "short-name-unresolved")
            uncertain = True
        for p in parts[:-1] if not is_device else []:
            base = _device_base(p)
            if base is not None:
                _add(reasons, f"device-component:{base}")
                uncertain = True
        if parts and not is_device:
            base = _device_base(parts[-1])
            if base is not None:
                anchor, parts, absolute, is_device = "//./", [base.lower()], True, True
                _add(reasons, f"device:{base}")
        if is_device:
            uncertain = True

    key = ("/".join(parts) or ".") if anchor is None else _join(anchor, parts)
    if shape.flavor == "windows":
        key = key.casefold()
    if not key.strip():
        # a relative path made of blanks only: say "empty" the way the next pass would
        key = ""
        _add(reasons, "empty")
        uncertain = True
    return NormPath(raw or "", key, shape.flavor, absolute, uncertain, tuple(reasons), is_device)


# --------------------------------------------------------------------------------------------
# inside_project
# --------------------------------------------------------------------------------------------


def _anchor_of(key: str, flavor: Flavor) -> str | None:
    if flavor == "posix":
        return "/" if key.startswith("/") else None
    if len(key) >= 3 and key[1] == ":" and key[2] == "/":
        return key[:2]
    if key.startswith("//") and not key.startswith("//./"):
        seg = key[2:].split("/")
        return "//" + seg[0] + ("/" + seg[1] if len(seg) > 1 else "")
    return None


def _clean_key(key: str) -> bool:
    if not key or "\x00" in key:
        return False
    body = key.split("/")
    return not any(seg in (".", "..") for seg in body[1:]) and body[-1] not in (".", "..")


def _inside_project(path: NormPath, root: NormPath | None) -> bool | None:
    if root is None:
        return None
    for p in (path, root):
        if p.uncertain or p.is_device or not p.absolute or not _clean_key(p.key):
            return None
    if path.flavor != root.flavor:
        return None
    anchor = _anchor_of(path.key, path.flavor)
    if anchor is None or anchor != _anchor_of(root.key, root.flavor):
        return None
    prefix = root.key if root.key.endswith("/") else root.key + "/"
    return path.key == root.key or path.key.startswith(prefix)


# --------------------------------------------------------------------------------------------
# File system layer
# --------------------------------------------------------------------------------------------


_DRIVE_FIXED = 3  # GetDriveType: a local, fixed disk (not removable, remote, RAM or unknown)


def _drive_type(letter: str) -> int:
    """The Win32 drive type of ``letter`` (3 = fixed, 4 = network); 3 on other platforms."""
    if sys.platform != "win32":
        return _DRIVE_FIXED
    import ctypes

    return int(ctypes.windll.kernel32.GetDriveTypeW(f"{letter.upper()}:\\"))


def is_local_disk(path: NormPath) -> bool:
    """May this path be looked up on disk without risking a hang on a network or odd device?

    True only for an absolute, certain-enough path of THIS machine's flavor: a POSIX path on a
    POSIX host, or a drive path on a fixed local drive on Windows. UNC, device, network-drive,
    relative and foreign-flavor paths are False (nothing is touched to find out; the drive type
    is a cheap query that does not block). Never raises.
    """
    try:
        if path.is_device or not path.absolute or not path.key or "\x00" in path.key:
            return False
        if (path.flavor == "windows") != (os.name == "nt"):
            return False
        if path.flavor == "posix":
            return True
        key = path.key
        if len(key) >= 3 and key[1] == ":" and key[2] == "/" and key[0].isascii():
            return _drive_type(key[0]) == _DRIVE_FIXED
        return False
    except Exception:  # noqa: BLE001 - a guard that raises would be worse than saying no
        return False


GlobStatus = Literal["ok", "none", "too-many", "budget", "unsupported"]


@dataclass(frozen=True, slots=True)
class GlobResult:
    """What ``expand_glob`` found: native paths that exist, and why the list may be incomplete."""

    matches: tuple[str, ...]
    status: GlobStatus


_GLOB_CHARS = "*?["
_MAX_GLOB_DEPTH = 64


def expand_glob(
    path: NormPath,
    *,
    limit: int = 64,
    max_entries: int = 4096,
    deadline: float | None = None,
    dotfiles: bool = False,
) -> GlobResult:
    """File system layer: the existing paths a glob-carrying ``path`` can stand for (bash rules).

    ``*``, ``?`` and ``[...]`` work inside one component (no ``**``), a leading dot must be matched
    by a dot in the pattern, unless ``dotfiles`` (PowerShell: its wildcards match ``.env`` for
    ``*env``, ``*.*`` and ``[.]e*``). Bounded: more than ``limit`` matches, or a directory with
    more than ``max_entries`` entries, gives status ``too-many`` (the matches found so far are
    returned and the list is incomplete); a passed ``deadline`` (``time.monotonic()`` value) gives
    ``budget``.
    ``none`` means nothing matched or a directory does not exist; ``unsupported`` means the path is
    not one we may enumerate (relative, UNC, device, network drive, foreign flavor, unresolved
    variable, too deep). The caller keeps the unexpanded text as an uncertain path in every case.
    Never raises.
    """
    try:
        return _expand_glob(path, limit, max_entries, deadline, dotfiles)
    except Exception:  # noqa: BLE001 - never raise; "unsupported" keeps the caller cautious
        return GlobResult((), "unsupported")


def _glob_pattern(segment: str) -> str:
    return segment.replace("[^", "[!") if "[^" in segment else segment


def _expand_glob(
    path: NormPath, limit: int, max_entries: int, deadline: float | None, dotfiles: bool = False
) -> GlobResult:
    blocking = [r for r in path.reasons if r not in _INFO_REASONS and r not in ("glob", "brace")]
    if blocking or not is_local_disk(path):
        return GlobResult((), "unsupported")
    split = _split_key(path.key, path.flavor)
    if split is None or split[0].startswith("//") or len(split[1]) > _MAX_GLOB_DEPTH:
        return GlobResult((), "unsupported")
    anchor, parts = split
    windows = path.flavor == "windows"
    current = [anchor.replace("/", "\\") if windows else anchor]
    for segment in parts:
        if deadline is not None and time.monotonic() >= deadline:
            return GlobResult((), "budget")
        if not any(c in segment for c in _GLOB_CHARS):
            current = [os.path.join(base, segment) for base in current]
            continue
        pattern = _glob_pattern(segment)
        nxt: list[str] = []
        for base in current:
            try:
                with os.scandir(base) as entries:
                    for count, entry in enumerate(entries):
                        if count >= max_entries:
                            return GlobResult(tuple(nxt), "too-many")
                        name = entry.name
                        if name.startswith(".") and not segment.startswith(".") and not dotfiles:
                            continue
                        if fnmatch.fnmatchcase(name.casefold() if windows else name, pattern):
                            nxt.append(os.path.join(base, name))
                            if len(nxt) > limit:
                                return GlobResult(tuple(nxt[:limit]), "too-many")
            except OSError:
                continue
        current = nxt
        if not current:
            return GlobResult((), "none")
    found = tuple(p for p in current if os.path.lexists(p))
    return GlobResult(found, "ok" if found else "none")


def _hard_linked(native: str) -> bool:
    """Is ``native`` an existing regular file with more than one name (a hard link)?

    A hard link is the same file under another name: a path inside the project can BE the policy
    file, a settings file or a secret, and no path rule can tell (X1 review of M1c-2, H-6). The
    answer is used only to stop allow rules from trusting the path. One ``stat`` of a path that
    ``realpath`` has just visited; False on any error (a file that cannot be examined is not
    reported as linked: the other layers still judge its name).
    """
    try:
        info = os.stat(native)
    except (OSError, ValueError):
        return False
    return stat.S_ISREG(info.st_mode) and info.st_nlink > 1


def _resolve_on_disk(path: NormPath) -> NormPath:
    if path.is_device or not path.absolute or not path.key or "\x00" in path.key:
        return path
    blocking = [r for r in path.reasons if r not in _INFO_REASONS and r != "short-name-unresolved"]
    if path.uncertain and blocking:
        return path
    if (path.flavor == "windows") != (os.name == "nt"):
        return path
    if not is_local_disk(path):
        return path  # network paths, UNC, remote drives: a dead server could block this call
    native = path.key.replace("/", "\\") if path.flavor == "windows" else path.key
    resolved = os.path.realpath(native)
    new = _norm(resolved, _literal_ctx(), literal=True)
    if not new.absolute or new.is_device:
        return path
    reasons = [r for r in path.reasons if r != "short-name-unresolved"]
    for r in new.reasons:
        _add(reasons, r)
    if new.key != path.key:
        _add(reasons, "resolved-on-disk")
    if _hard_linked(resolved):
        _add(reasons, HARD_LINKED)
    return dataclasses.replace(
        new, raw=path.raw, reasons=tuple(reasons), uncertain=new.uncertain or bool(blocking)
    )
