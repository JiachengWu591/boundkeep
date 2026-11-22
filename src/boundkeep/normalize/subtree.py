"""Bounded look into the subtree of a directory that a command reads recursively.

``Grep``/``Glob`` on a directory, ``grep -r``, ``tar c``, ``cp -r``, ``Compress-Archive`` ... read
every file below their directory operand, but the event normalizer only knows the operand's own
path. Without a look inside, ``Grep path=<project>`` is "inside the project" (an allow) although the
tree holds ``.env``, ``certs/a.pem`` or ``terraform.tfstate``. ``scan`` walks the subtree (the file
system layer, like ``paths.expand_glob``) and reports the entries the policy's read-protection
globs select, so the normal rule evaluation sees them as read paths of the action.

* **Matching** is the policy's own glob over the full canonical key of each entry, behind a cheap
  filter on the entry NAME (the last segment of every pattern: a literal goes into a set, a
  wildcard segment into one regex). A pattern that cannot be filtered by its last segment is tried
  on every entry. A directory selected by a ``dir/**`` pattern is reported as itself (its key is
  matched by the pattern), and nothing below it is visited unless a narrowing filter (a Grep
  ``glob``) is in play; then every selected file below it is reported.
* **No directory names are skipped** (``node_modules``, ``.git`` ...): a hostile project can create
  them. The one exception is the caller's ``skip_names=VCS_DIR_NAMES``, for readers that are known
  not to read the version-control directories (Claude Code's Grep without a ``glob``, ``git grep``
  and the like); everything else scans them. Symbolic links and junctions are NOT followed (what
  ripgrep, ``grep -r``, ``tar`` and ``cp -r`` do by default); ``ScanResult.dir_links`` says one
  was seen, for tools that may follow.
* **Bounded**: ``ScanBudget`` caps the entries visited and the wall time, per request. Over it, the
  status is ``budget`` and the caller makes the action gray; an unreadable directory is
  ``unreadable``. Never a silent pass.
* **Names as they are on disk, and as Win32 reads them** (spec revision 40): on Windows the walk
  opens ``\\\\?\\`` paths, so ``inner.`` is opened as itself, not as ``inner`` (a Win32 path drops
  that dot: up to revision 39 the folder was "missing" and skipped, and the tree passed as clean).
  What a Win32 reader lists for such a directory, the sibling with one dot less, is walked as
  well, at the place the old walk read it; the name as it is on disk is left for later
  (``ScanResult.deferred``), so the old walk's entries, order and stats stay as they were. A name
  that ends in dots or spaces is also matched with them removed, as a key has them. What the old
  walk did not report is marked ``ScanHit.extra`` and counted apart.

Nothing here decides anything: it only finds names. Never raises.
"""

from __future__ import annotations

import fnmatch
import functools
import os
import re
import stat
import sys
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Literal

from boundkeep.normalize import paths
from boundkeep.policy.glob import Glob, GlobError, compile_glob

MAX_SCAN_ENTRIES = 30000  # entries (files and directories) looked at per request
SCAN_TIME_BUDGET_S = (
    0.35  # wall time of all scans of one request (0.2 before the link count: +5 us/file)
)
MAX_SCAN_HITS = 64  # reported entries per scan; the first few already decide the verdict
_TIME_CHECK_MASK = 63  # the clock is read every 64 entries
_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT (symlinks and junctions on Windows)
_EXTENDED = "\\\\?\\"
_SYMLINK_TAG = 0xA000000C  # IO_REPARSE_TAG_SYMLINK

# Which reading of the names a directory on the walk stands for (spec revision 40): every reading
# (no name on the way there is read differently), the Win32 one (reached through the sibling a
# Win32 call lists for a name that ends in a dot) or the one that keeps the names as on disk.
_BOTH, _WIN32, _KEPT = 0, 1, 2

# The version-control directories Claude Code's Grep tool excludes itself (``--glob '!.git'`` and
# the like) when the caller gave no ``glob``. ripgrep's own glob is case-sensitive, so is this.
VCS_DIR_NAMES: frozenset[str] = frozenset({".git", ".svn", ".hg", ".bzr", ".jj", ".sl"})

# Read-protection globs used when no policy was passed to the normalizer (tests, tools). They are
# the secret-bearing names of the default policy; the daemon passes the loaded policy's own.
DEFAULT_PROTECTED_GLOBS: tuple[str, ...] = (
    "**/.env",
    "**/.env.*",
    "**/*.env",
    "**/.ssh/**",
    "**/*.pem",
    "**/*.key",
    "**/*.jks",
    "**/*.keystore",
    "**/*.p12",
    "**/*.pfx",
    "**/*.ppk",
    "**/*.tfstate*",
    "**/*.tfvars",
    "**/*.tfvars.json",
    "**/service-account*.json",
    "**/credentials.json",
    "**/id_rsa",
    "**/id_dsa",
    "**/id_ecdsa",
    "**/id_ed25519",
    "**/.aws/**",
    "**/.azure/**",
    "**/.gnupg/**",
    "**/.kube/config",
    "**/.docker/config.json",
    "**/.git-credentials",
    "**/.git/config",
    "**/.npmrc",
    "**/.pypirc",
    "**/.netrc",
    "**/_netrc",
    "**/.pgpass",
    "**/.claude/.credentials.json",
    "**/.claude.json",
    "**/.claude/projects/**",
)

ScanStatus = Literal["ok", "budget", "unreadable", "absent"]
Selector = Callable[[str, str], bool]  # (path relative to the scanned root, entry name) -> selected


class ProtectedMatcher:
    """The read-protection globs, indexed by the last segment of each pattern."""

    __slots__ = ("_always", "_globs", "_literals", "_regex", "patterns")

    def __init__(self, patterns: Sequence[str]) -> None:
        self.patterns = tuple(dict.fromkeys(patterns))
        globs: list[Glob] = []
        literals: set[str] = set()
        regexes: list[str] = []
        always: list[Glob] = []
        for pattern in self.patterns:
            try:
                glob = compile_glob(pattern)
            except GlobError:
                continue  # the policy loader refuses these; nothing to match
            globs.append(glob)
            last = _last_segment(pattern)
            if last is None:
                always.append(glob)
            elif not any(c in last for c in "*?["):
                literals.add(last)
            else:
                try:
                    regexes.append(fnmatch.translate(last.replace("[^", "[!")))
                except re.error:
                    always.append(glob)
        self._globs = tuple(globs)
        self._always = tuple(always)
        self._literals = frozenset(literals)
        self._regex = re.compile("|".join(regexes)) if regexes else None

    @property
    def empty(self) -> bool:
        return not self._globs

    def candidate(self, name_folded: str) -> bool:
        """May a pattern select an entry with this (casefolded) name? A filter only."""
        if self._always or name_folded in self._literals:
            return True
        return self._regex is not None and self._regex.match(name_folded) is not None

    def match(self, key: str) -> bool:
        """The full policy-glob test of one canonical key."""
        return any(glob.match(key) for glob in self._globs)


class PathScreen:
    """A cheap, one-sided test: could ANY of these globs select a key? (never a decision)

    Used to leave out of a verdict's work the paths that no deny / ask rule can look at. Every
    pattern is reduced to ONE anchor, its last whole segment without ``**`` (a literal goes into a
    set, a wildcard segment into one regex); a key that has no segment equal to or matching an
    anchor cannot be selected by that pattern, because a pattern's segments are bounded by ``/``
    and are matched against whole key segments. A pattern without such an anchor (``**``,
    ``a**b``) makes every key a candidate. So ``candidate`` may say True for a key no glob selects,
    never False for one a glob selects.
    """

    __slots__ = ("_always", "_literals", "_regex")

    def __init__(self, patterns: Sequence[str]) -> None:
        literals: set[str] = set()
        regexes: list[str] = []
        always = False
        for pattern in dict.fromkeys(patterns):
            try:
                compile_glob(pattern)
            except GlobError:
                continue  # the policy loader refuses these; nothing to match
            body = pattern
            while body.endswith("/**"):
                body = body[:-3]
            anchor = next(
                (s for s in reversed(body.casefold().split("/")) if s and "**" not in s), None
            )
            if anchor is None:
                always = True
            elif not any(c in anchor for c in "*?["):
                literals.add(anchor)
            else:
                try:
                    regexes.append(fnmatch.translate(anchor.replace("[^", "[!")))
                except re.error:
                    always = True
        self._always = always
        self._literals = frozenset(literals)
        self._regex = re.compile("|".join(regexes)) if regexes else None

    def candidate(self, key: str) -> bool:
        if self._always:
            return True
        regex = self._regex
        for segment in key.casefold().split("/"):
            if segment in self._literals or (regex is not None and regex.match(segment)):
                return True
        return False


@dataclass(frozen=True, slots=True)
class RuleGlob:
    """One ``path_glob`` of a deny / ask rule, with the other conditions that decide whether a path
    can reach it: the programs the rule is restricted to (None: any) and its access (None: any)."""

    pattern: str
    programs: tuple[str, ...] | None = None
    access: str | None = None


class RuleScreens:
    """``PathScreen`` per (program, access): can a rule's path glob select this path of this action?

    Over-approximates (case-folded program names, every tool): True for a path that no rule would
    match, never False for one a rule could match. Built once per policy (``rule_screens_for``).
    """

    __slots__ = ("_by_program", "_cache", "_generic")

    def __init__(self, globs: Sequence[RuleGlob]) -> None:
        self._generic: list[RuleGlob] = []
        self._by_program: dict[str, list[RuleGlob]] = {}
        for glob in dict.fromkeys(globs):
            if glob.programs is None:
                self._generic.append(glob)
            else:
                for program in glob.programs:
                    self._by_program.setdefault(program.casefold(), []).append(glob)
        self._cache: dict[tuple[str | None, str], PathScreen] = {}

    def candidate(self, program: str | None, access: str, key: str) -> bool:
        """May some rule glob select ``key`` for a command ``program`` that reads / writes it?"""
        folded = program.casefold() if program else None
        slot = folded if folded in self._by_program else None
        screen = self._cache.get((slot, access))
        if screen is None:
            pool = self._generic + (self._by_program[slot] if slot is not None else [])
            screen = PathScreen(
                [
                    g.pattern
                    for g in pool
                    if g.access is None or access == "unknown" or g.access == access
                ]
            )
            self._cache[(slot, access)] = screen
        return screen.candidate(key)


@functools.lru_cache(maxsize=16)
def rule_screens_for(globs: tuple[RuleGlob, ...]) -> RuleScreens:
    return RuleScreens(globs)


def _last_segment(pattern: str) -> str | None:
    """The casefolded final path segment of ``pattern`` (without a ``/**`` tail), None when the
    pattern has no usable one (empty, or a ``**`` inside it that may span directories)."""
    body = pattern
    while body.endswith("/**"):
        body = body[:-3]
    last = body.rsplit("/", 1)[-1].casefold()
    if not last or "**" in last:
        return None
    return last


@functools.lru_cache(maxsize=32)
def matcher_for(patterns: tuple[str, ...]) -> ProtectedMatcher:
    return ProtectedMatcher(patterns)


@dataclass(slots=True)
class ScanBudget:
    """What one request may spend on subtree scans (shared by all of its scans)."""

    max_entries: int = MAX_SCAN_ENTRIES
    seconds: float = SCAN_TIME_BUDGET_S
    entries: int = 0
    elapsed: float = 0.0

    @property
    def spent(self) -> bool:
        return self.entries >= self.max_entries or self.elapsed >= self.seconds


@dataclass(frozen=True, slots=True)
class ScanHit:
    key: str  # canonical key of the entry (prefix key + relative path)
    rel: str  # path relative to the scanned root, forward slashes
    is_dir: bool
    # a hit revision 39 did not report (spec revision 40): the key without the dots, an entry only
    # that key protects, or anything a walk of the second budget finds. Counted apart.
    extra: bool = False


@dataclass(slots=True)
class ScanResult:
    hits: list[ScanHit] = field(default_factory=list)
    status: ScanStatus = "ok"
    dir_links: bool = False  # a symlink / junction to a directory was met and not followed
    # a file with more than one name was met among the files the command reads (X1 re-review R-3):
    # it can BE a protected file under an ordinary name, and a name-based scan cannot tell
    hard_links: bool = False
    # Left by a scan with ``defer`` for ``scan(..., resume=<this result>)`` on the second budget
    # (spec revision 40): directories whose name on disk a Win32 call does not open (``inner.``:
    # (os path, rel, inside)); files ``x.`` whose link count, and links ``x.`` whose target, as
    # named on disk are still to be asked (revision 39 asked that only of ``x``, what Win32 opens);
    # entries whose key without the dots is still to be matched (``config.``, ``.aws./x``)
    deferred: list[tuple[str, str, bool]] = field(default_factory=list)
    deferred_files: list[str] = field(default_factory=list)
    deferred_links: list[str] = field(default_factory=list)  # a link "x." that may lead to a folder
    deferred_checks: list[tuple[str, bool]] = field(default_factory=list)  # (rel, is_dir): the key
    slots: int = 0  # hits as revision 39 counted them: one per prefix key per entry
    extras: int = 0  # entries reported only as ``ScanHit.extra`` (capped like revision 39's)

    @property
    def left(self) -> bool:
        """Did a scan with ``defer`` leave anything for the second budget?"""
        return bool(
            self.deferred or self.deferred_files or self.deferred_links or self.deferred_checks
        )


def win32_list_name(name: str) -> str:
    """The name a Win32 call opens for the directory ``name`` when it lists it.

    ``os.scandir`` lists ``name\\*.*``, so ``name`` is a middle segment: one trailing dot goes,
    and only when the character before it is not a dot; spaces stay (``a.`` -> ``a``, ``a..``,
    ``a `` and ``a. `` unchanged, ``a. .`` -> ``a. ``). Measured with ``GetFullPathNameW`` on
    Windows 11 build 26200; a test checks it against the kernel.
    """
    return name[:-1] if len(name) >= 2 and name[-1] == "." and name[-2] != "." else name


def win32_open_name(name: str) -> str:
    """The name a Win32 call opens for a last segment ``name``: every trailing dot and space goes
    (empty: the directory that holds it)."""
    return name.rstrip(". ")


def canonical_rel(rel: str) -> str:
    """``rel`` with the trailing dots and spaces of every segment removed, as a key has them (a
    segment that is nothing else stays as it is)."""
    return "/".join(segment.rstrip(". ") or segment for segment in rel.split("/"))


def _extended_root(os_root: str) -> str | None:
    """``os_root`` as a ``\\\\?\\`` path (a drive path only; None for anything else)."""
    if os_root.startswith(_EXTENDED):
        return os_root
    if len(os_root) >= 3 and os_root[1] == ":" and os_root[2] == "\\" and os_root[0].isascii():
        return _EXTENDED + os_root if os_root[0].isalpha() else None
    return None


def _is_link(entry: os.DirEntry[str]) -> bool:
    if entry.is_symlink():
        return True
    if sys.platform == "win32":
        attributes = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
        return bool(attributes & _REPARSE_POINT)
    return False


def _hard_linked(entry: os.DirEntry[str]) -> bool:
    """Is `entry` a regular file with more than one name? (False when it cannot be told.)

    `DirEntry.stat` reports no link count on Windows (`st_nlink` is 0 there), so a second
    `os.stat` is the price of the answer; POSIX has it from the entry.
    """
    try:
        info = entry.stat(follow_symlinks=False)
        if not info.st_nlink and sys.platform == "win32":
            info = os.stat(entry.path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_nlink > 1


def _hard_linked_path(path: str) -> bool:
    """``_hard_linked`` for a path a Win32 call opens instead of the entry (revision 39 asked this
    of it: ``x.`` opens as ``x``)."""
    try:
        info = os.stat(path)
    except (OSError, ValueError):
        return False
    return stat.S_ISREG(info.st_mode) and info.st_nlink > 1


def _is_dir_path(path: str) -> bool:
    """``DirEntry.is_dir(follow_symlinks=True)`` for a path: False when it is missing, True when it
    cannot be told (the cautious answer of ``_link_to_dir``)."""
    try:
        return stat.S_ISDIR(os.stat(path).st_mode)
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        return True


def _is_symlink_info(info: os.stat_result) -> bool:
    return getattr(info, "st_reparse_tag", 0) == _SYMLINK_TAG or stat.S_ISLNK(info.st_mode)


_MISSING, _ENTER, _REFUSE = 0, 1, 2


def _alias_state(path: str) -> int:
    """May the walk open ``path``, the sibling a Win32 call lists for a dotted name? A plain
    directory or a junction, yes (a junction always leads to a local volume); a symbolic link
    only when its text names a fixed local drive and what it names is no symbolic link itself:
    opening a share sends the user's credentials to the server before any verdict, so the link
    is read as text (``readlink``) and not opened to find out. A missing one: nothing to open
    (revision 39's walk opened it and found nothing; this asks once, as that did)."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return _MISSING
    except (OSError, ValueError):
        return _REFUSE
    if not _is_symlink_info(info):
        return _ENTER
    try:
        target = os.readlink(path)
    except (OSError, ValueError):
        return _REFUSE
    if target.startswith(_EXTENDED):
        target = target[len(_EXTENDED) :]
    elif not (len(target) >= 2 and target[1] == ":") and not target.startswith(("\\", "/")):
        here = path[len(_EXTENDED) :] if path.startswith(_EXTENDED) else path
        target = os.path.normpath(os.path.join(os.path.dirname(here), target))  # relative text
    if not (len(target) >= 3 and target[1] == ":" and target[2] == "\\"):
        return _REFUSE
    if not paths.is_fixed_drive(target[0]):
        return _REFUSE
    try:
        return _REFUSE if _is_symlink_info(os.lstat(_EXTENDED + target)) else _ENTER
    except FileNotFoundError:
        return _ENTER
    except (OSError, ValueError):
        return _REFUSE


def _alias_enterable(path: str) -> bool:
    return _alias_state(path) != _REFUSE


def scan(
    os_root: str,
    prefix_keys: Sequence[str],
    *,
    windows: bool,
    matcher: ProtectedMatcher,
    budget: ScanBudget,
    select: Selector | None = None,
    skip_names: frozenset[str] = frozenset(),
    defer: bool = False,
    late: bool = False,
    kept: bool = False,
    resume: ScanResult | None = None,
) -> ScanResult:
    """The protected entries below the directory ``os_root`` (never raises).

    ``prefix_keys``: the canonical keys the root is known by (lexical and resolved forms); an
    entry is tried under each. ``windows``: keys are casefolded. ``select`` narrows WHICH files are
    read (a Grep ``glob``); None means every file. ``skip_names``: entries (files or directories,
    at any depth, exact spelling) that the reader does not read at all and that cost nothing;
    only for readers that are known to skip them (``VCS_DIR_NAMES``). The root itself is never
    skipped. Status ``absent``: ``os_root`` is not a directory (nothing to read there).

    Spec revision 40. On Windows a drive root is opened as a ``\\\\?\\`` path and every entry by
    its name on disk. ``defer``: everything revision 39's walk did not ask is left in the result
    (``ScanResult.deferred`` and the lists after it) instead of being asked now, so this walk
    asks and spends what that one did. ``late``: a walk only revision 40 makes (the second
    budget): every hit is ``extra``, and the clock is read at every directory (and, in any walk
    without ``defer``, before every full match of a key). ``kept``:
    ``os_root`` is a reading that keeps the names as on disk (no Win32 sibling below it).
    ``resume``: ask and walk what an earlier scan with ``defer`` left (a late walk).
    """
    result = ScanResult()
    started = time.monotonic()
    native = windows and sys.platform == "win32"
    if native and resume is None:
        extended = _extended_root(os_root)
        native = extended is not None
        os_root = extended or os_root
    try:
        if resume is None or _resume_asks(
            resume, prefix_keys, windows, matcher, budget, result, started
        ):
            _walk(
                os_root,
                prefix_keys,
                windows,
                matcher,
                budget,
                select,
                skip_names,
                result,
                started,
                native=native,
                defer=defer,
                late=late or resume is not None,
                reading=_KEPT if kept or resume is not None else _BOTH,
                resume=resume,
            )
    except Exception:  # noqa: BLE001 - a scan that fails is a scan that could not vouch for the tree
        result.status = "unreadable"
    finally:
        budget.elapsed += time.monotonic() - started
    return result


def _out_of_time(budget: ScanBudget, started: float) -> bool:
    return budget.elapsed + (time.monotonic() - started) >= budget.seconds


def _resume_asks(
    resume: ScanResult,
    prefix_keys: Sequence[str],
    windows: bool,
    matcher: ProtectedMatcher,
    budget: ScanBudget,
    result: ScanResult,
    started: float,
) -> bool:
    """What a scan with ``defer`` left to ask (spec revision 40): the link count and the link
    target of dotted names as on disk, and the keys without the dots. False when the budget
    ran out (status ``budget``)."""
    prefixes = [p.rstrip("/") for p in prefix_keys]
    asks = 0
    for path in resume.deferred_files:
        if result.hard_links:
            break
        asks += 1
        if not asks & _TIME_CHECK_MASK and _out_of_time(budget, started):
            result.status = "budget"
            return False
        result.hard_links = _hard_linked_path(path)
    for path in resume.deferred_links:
        if result.dir_links:
            break
        asks += 1
        if not asks & _TIME_CHECK_MASK and _out_of_time(budget, started):
            result.status = "budget"
            return False
        result.dir_links = _is_dir_path(path)
    for rel, is_dir in resume.deferred_checks:
        # (each is a full match, which can take a millisecond or more: the clock before each)
        if _out_of_time(budget, started):
            result.status = "budget"
            return False
        if result.extras >= MAX_SCAN_HITS:
            break
        shown = rel.casefold() if windows else rel
        if _by_key(matcher, prefixes, shown):
            _report(result, prefixes, rel, windows, is_dir, False)
    return True


def _by_key(matcher: ProtectedMatcher, prefixes: Sequence[str], shown: str) -> bool:
    """Is ``shown`` protected under the key a written path gets, every segment's trailing dots
    and spaces removed (and only so)?"""
    canon = canonical_rel(shown)
    return canon != shown and any(matcher.match(f"{p}/{canon}") for p in prefixes)


def _walk(
    os_root: str,
    prefix_keys: Sequence[str],
    windows: bool,
    matcher: ProtectedMatcher,
    budget: ScanBudget,
    select: Selector | None,
    skip_names: frozenset[str],
    result: ScanResult,
    started: float,
    *,
    native: bool = False,
    defer: bool = False,
    late: bool = False,
    reading: int = _BOTH,
    resume: ScanResult | None = None,
) -> None:
    prefixes = [p.rstrip("/") for p in prefix_keys]
    # Breadth first: the entries near the root (.env, .ssh, certs/) are seen before the budget ends.
    # (os dir, rel, inside, reading, dotted rel): ``native`` (a Windows walk through ``\\?\``
    # paths) opens the names as they are on disk and walks what a Win32 call lists for a dotted
    # directory too; "dotted rel": a name on the way there ends in a dot or a space.
    stack: deque[tuple[str, str, bool, int, bool]]
    if resume is not None:
        stack = deque((path, rel, inside, _KEPT, True) for path, rel, inside in resume.deferred)
    else:
        stack = deque([(os_root, "", False, reading, False)])
    first = resume is None
    while stack:
        current, rel, inside, reading, dotted_rel = stack.popleft()
        # (a directory that lists nothing costs no entry: revision 39 read the clock only at
        # entries, and its walk keeps doing so; a late walk reads it at every directory too)
        if late and _out_of_time(budget, started):
            result.status = "budget"
            return
        try:
            iterator = os.scandir(current)
        except (FileNotFoundError, NotADirectoryError):
            if first:
                result.status = "absent"
                return
            continue  # vanished while we walked: nothing there to read
        except OSError:
            if first:
                result.status = "unreadable"
                return
            result.status = "unreadable"
            continue
        first = False
        with iterator:
            for entry in iterator:
                if skip_names and entry.name in skip_names:
                    continue
                budget.entries += 1
                if budget.entries > budget.max_entries or (
                    not budget.entries & _TIME_CHECK_MASK and _out_of_time(budget, started)
                ):
                    result.status = "budget"
                    return
                name = entry.name
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                    link = _is_link(entry)
                except OSError:
                    result.status = "unreadable"
                    is_dir, link = False, False
                    # an entry we cannot even classify: treat it as a file, still name-tested
                rel_path = f"{rel}/{name}" if rel else name
                dotted = windows and name[-1:] in (".", " ")
                # a Win32 reader of this directory opens this entry under another name (revision
                # 39's walk did: its paths were Win32 paths)
                win32 = native and dotted and reading != _KEPT
                if link:
                    to_dir = is_dir
                    if not to_dir and win32:  # revision 39 asked this of "x" (Win32 opens it)
                        to_dir = _is_dir_path(_win32_open_path(current, name))
                        if not to_dir and defer:
                            result.deferred_links.append(entry.path)  # "x." itself: later
                        elif not to_dir:
                            to_dir = _link_to_dir(entry)
                    elif not to_dir:
                        to_dir = _link_to_dir(entry)
                    if to_dir:
                        result.dir_links = True
                        is_dir = False
                read = is_dir or select is None or select(rel_path, name)
                # protected as named on disk: what revision 39 asked, the same way
                as_written = False
                candidate = not inside and matcher.candidate(name.casefold())
                if candidate and not defer and _out_of_time(budget, started):
                    # a full match can take a millisecond or more: a walk that is not revision
                    # 39's own reads the clock before each (that one keeps its rhythm)
                    result.status = "budget"
                    return
                if candidate:
                    shown = rel_path.casefold() if windows else rel_path
                    as_written = any(matcher.match(f"{p}/{shown}") for p in prefixes)
                # ... or only by the key without the dots: asked later in a walk of the first
                # budget, now in a late one
                by_key = False
                if windows and not inside and not as_written and read and (dotted or dotted_rel):
                    bare = name.rstrip(". ") or name if dotted else name
                    if candidate or (bare != name and matcher.candidate(bare.casefold())):
                        if defer:
                            result.deferred_checks.append((rel_path, is_dir))
                        elif _out_of_time(budget, started):
                            result.status = "budget"
                            return
                        else:
                            by_key = _by_key(
                                matcher, prefixes, rel_path.casefold() if windows else rel_path
                            )
                # what revision 39's walk reported too: reached as it read, protected as it saw
                old = not late and reading != _KEPT and (as_written or inside)
                if is_dir:
                    if not inside and (by_key or (as_written and select is None)):
                        _report(result, prefixes, rel_path, windows, True, old)
                        if late and result.extras >= MAX_SCAN_HITS:
                            return
                        if as_written:
                            continue  # revision 39 reported it and did not look inside
                        # (only the key without the dots protects it: walked as revision 39 did)
                    below = inside or as_written
                    below_dotted = dotted_rel or dotted
                    alias = win32_list_name(name) if win32 else name
                    if alias == name:
                        stack.append((entry.path, rel_path, below, reading, below_dotted))
                        continue
                    # what a Win32 call lists for this name, at the place revision 39 read it
                    alias_path = os.path.join(current, alias)
                    state = _alias_state(alias_path)
                    if state == _ENTER:
                        stack.append((alias_path, rel_path, below, _WIN32, True))
                    elif state == _REFUSE:
                        result.status = "unreadable"
                    if reading == _BOTH:  # the name as on disk: later, or on the next budget
                        kept_dir = (entry.path, rel_path, below)
                        if defer:
                            result.deferred.append(kept_dir)
                        else:
                            stack.append((*kept_dir, _KEPT, True))
                    continue
                if read and not result.hard_links:
                    if not win32:
                        result.hard_links = _hard_linked(entry)
                    elif _hard_linked_path(_win32_open_path(current, name)):
                        result.hard_links = True  # what revision 39 asked: Win32 opens "x"
                    elif defer:
                        result.deferred_files.append(entry.path)  # "x." itself: later
                    else:
                        result.hard_links = _hard_linked(entry)
                if (as_written or by_key or inside) and read:
                    _report(result, prefixes, rel_path, windows, False, old)
                if result.slots >= MAX_SCAN_HITS or (late and result.extras >= MAX_SCAN_HITS):
                    return


def _win32_open_path(directory: str, name: str) -> str:
    """The path a Win32 call opens for ``name`` in ``directory`` (``x.`` -> ``x``)."""
    opened = win32_open_name(name)
    return os.path.join(directory, opened) if opened else directory


def _link_to_dir(entry: os.DirEntry[str]) -> bool:
    try:
        return entry.is_dir(follow_symlinks=True)
    except OSError:
        return True  # cannot tell: assume it leads to a directory (the cautious answer)


def _report(
    result: ScanResult, prefixes: Sequence[str], rel: str, windows: bool, is_dir: bool, old: bool
) -> None:
    """One protected entry, under each prefix key. ``old``: revision 39's walk reported it too;
    its key as on disk counts against ``MAX_SCAN_HITS`` as before. Otherwise every key is
    ``extra`` and the entry is counted apart (``ScanResult.extras``, up to the same cap)."""
    if not old and result.extras >= MAX_SCAN_HITS:
        return
    shown = rel.casefold() if windows else rel
    # the key a written path gets has the trailing dots and spaces removed (spec revision 40): that
    # one is reported too, so a rule that names ``.aws`` sees ``.aws./credentials``
    canon = canonical_rel(shown) if windows else shown
    for prefix in prefixes:
        result.hits.append(ScanHit(f"{prefix}/{shown}", rel, is_dir, extra=not old))
        if canon != shown:
            result.hits.append(ScanHit(f"{prefix}/{canon}", rel, is_dir, extra=True))
    if old:
        result.slots += len(prefixes)
    else:
        result.extras += 1
