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

from boundkeep.policy.glob import Glob, GlobError, compile_glob

MAX_SCAN_ENTRIES = 30000  # entries (files and directories) looked at per request
SCAN_TIME_BUDGET_S = (
    0.35  # wall time of all scans of one request (0.2 before the link count: +5 us/file)
)
MAX_SCAN_HITS = 64  # reported entries per scan; the first few already decide the verdict
_TIME_CHECK_MASK = 63  # the clock is read every 64 entries
_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT (symlinks and junctions on Windows)

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


@dataclass(slots=True)
class ScanResult:
    hits: list[ScanHit] = field(default_factory=list)
    status: ScanStatus = "ok"
    dir_links: bool = False  # a symlink / junction to a directory was met and not followed
    # a file with more than one name was met among the files the command reads (X1 re-review R-3):
    # it can BE a protected file under an ordinary name, and a name-based scan cannot tell
    hard_links: bool = False


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


def scan(
    os_root: str,
    prefix_keys: Sequence[str],
    *,
    windows: bool,
    matcher: ProtectedMatcher,
    budget: ScanBudget,
    select: Selector | None = None,
    skip_names: frozenset[str] = frozenset(),
) -> ScanResult:
    """The protected entries below the directory ``os_root`` (never raises).

    ``prefix_keys``: the canonical keys the root is known by (lexical and resolved forms); an
    entry is tried under each. ``windows``: keys are casefolded. ``select`` narrows WHICH files are
    read (a Grep ``glob``); None means every file. ``skip_names``: entries (files or directories,
    at any depth, exact spelling) that the reader does not read at all and that cost nothing;
    only for readers that are known to skip them (``VCS_DIR_NAMES``). The root itself is never
    skipped. Status ``absent``: ``os_root`` is not a directory (nothing to read there).
    """
    result = ScanResult()
    started = time.monotonic()
    try:
        _walk(os_root, prefix_keys, windows, matcher, budget, select, skip_names, result, started)
    except Exception:  # noqa: BLE001 - a scan that fails is a scan that could not vouch for the tree
        result.status = "unreadable"
    finally:
        budget.elapsed += time.monotonic() - started
    return result


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
) -> None:
    prefixes = [p.rstrip("/") for p in prefix_keys]
    # Breadth first: the entries near the root (.env, .ssh, certs/) are seen before the budget ends.
    stack: deque[tuple[str, str, bool]] = deque([(os_root, "", False)])  # (os dir, rel, inside)
    first = True
    while stack:
        current, rel, inside = stack.popleft()
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
                    not budget.entries & _TIME_CHECK_MASK
                    and budget.elapsed + (time.monotonic() - started) >= budget.seconds
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
                if link and (is_dir or _link_to_dir(entry)):
                    result.dir_links = True
                    is_dir = False
                protected = False
                if not inside and matcher.candidate(name.casefold()):
                    shown = rel_path.casefold() if windows else rel_path
                    protected = any(matcher.match(f"{p}/{shown}") for p in prefixes)
                if is_dir:
                    if inside:
                        stack.append((entry.path, rel_path, True))
                    elif protected and select is None:
                        _hit(result, prefixes, rel_path, windows, True)
                    else:
                        stack.append((entry.path, rel_path, protected))
                    continue
                read = select is None or select(rel_path, name)
                if read and not result.hard_links and _hard_linked(entry):
                    result.hard_links = True
                reported = (protected or inside) and read
                if reported:
                    _hit(result, prefixes, rel_path, windows, False)
                if len(result.hits) >= MAX_SCAN_HITS:
                    return


def _link_to_dir(entry: os.DirEntry[str]) -> bool:
    try:
        return entry.is_dir(follow_symlinks=True)
    except OSError:
        return True  # cannot tell: assume it leads to a directory (the cautious answer)


def _hit(
    result: ScanResult, prefixes: Sequence[str], rel: str, windows: bool, is_dir: bool
) -> None:
    shown = rel.casefold() if windows else rel
    for prefix in prefixes:
        result.hits.append(ScanHit(f"{prefix}/{shown}", rel, is_dir))
