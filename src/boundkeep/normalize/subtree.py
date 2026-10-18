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
  them. Symbolic links and junctions are NOT followed (what ripgrep, ``grep -r``, ``tar`` and
  ``cp -r`` do by default); ``ScanResult.dir_links`` says one was seen, for tools that may follow.
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
import sys
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Literal

from boundkeep.policy.glob import Glob, GlobError, compile_glob

MAX_SCAN_ENTRIES = 30000  # entries (files and directories) looked at per request
SCAN_TIME_BUDGET_S = 0.2  # wall time of all scans of one request
MAX_SCAN_HITS = 64  # reported entries per scan; the first few already decide the verdict
_TIME_CHECK_MASK = 63  # the clock is read every 64 entries
_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT (symlinks and junctions on Windows)

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


def _is_link(entry: os.DirEntry[str]) -> bool:
    if entry.is_symlink():
        return True
    if sys.platform == "win32":
        attributes = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
        return bool(attributes & _REPARSE_POINT)
    return False


def scan(
    os_root: str,
    prefix_keys: Sequence[str],
    *,
    windows: bool,
    matcher: ProtectedMatcher,
    budget: ScanBudget,
    select: Selector | None = None,
) -> ScanResult:
    """The protected entries below the directory ``os_root`` (never raises).

    ``prefix_keys``: the canonical keys the root is known by (lexical and resolved forms); an
    entry is tried under each. ``windows``: keys are casefolded. ``select`` narrows WHICH files are
    read (a Grep ``glob``); None means every file. Status ``absent``: ``os_root`` is not a
    directory (nothing to read there).
    """
    result = ScanResult()
    started = time.monotonic()
    try:
        _walk(os_root, prefix_keys, windows, matcher, budget, select, result, started)
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
                reported = (protected or inside) and (select is None or select(rel_path, name))
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
