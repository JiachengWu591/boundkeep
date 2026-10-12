"""Refuse policy files that contain something shaped like a secret.

Secrets never belong in a policy (``api_key_env`` names an environment variable instead): the file
is read by other tools, copied into bug reports and shown by ``doctor``. ``find_secret`` walks the
raw document (mappings, lists, strings) and returns where the first suspicious string is and what
kind of secret it looks like, never the string itself, so an error message cannot leak it.

The detectors are deliberately conservative about *shape* only; none of them can backtrack
badly (no nested quantifiers, bounded character classes), and any string longer than
``MAX_SCAN_CHARS`` is refused rather than scanned.

Two things keep the scan from refusing legitimate policies. ``Policy`` skips the ``input`` of
every ``tests`` entry (``skip_policy_test_inputs``): a regression test for secret handling has to
contain secret-shaped text, and it only ever runs against a fake machine. And the assignment
shape (``token: <value>``) only fires when the value looks random (letters and digits mixed, not a
path), so a reason such as ``credentials: /home/user/.aws/credentials/foo`` is not mistaken for a
secret.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Final

MAX_SCAN_CHARS: Final = 4096
_MAX_NODES: Final = 50_000
_MAX_DEPTH: Final = 64

_TOKEN_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = tuple(
    (label, re.compile(pattern))
    for label, pattern in (
        ("an API key (sk-...)", r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_\-]{16,}"),
        (
            "an AWS access key id",
            r"(?<![A-Z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}",
        ),
        (
            "a GitHub token",
            r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})",
        ),
        ("a GitLab token", r"(?<![A-Za-z0-9])glpat-[A-Za-z0-9_\-]{20,}"),
        ("an npm token", r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{30,}"),
        ("a Stripe key", r"(?<![A-Za-z0-9])[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"),
        ("a Slack token", r"(?<![A-Za-z0-9])xox[abeprs]-[A-Za-z0-9\-]{10,}"),
        ("a Google API key", r"(?<![A-Za-z0-9])AIza[A-Za-z0-9_\-]{30,}"),
        ("a private key block", r"-----BEGIN[ A-Z]{0,40}PRIVATE KEY"),
        ("a JSON web token", r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\."),
        ("a bearer credential", r"(?i)bearer\s+[A-Za-z0-9._~+/\-]{20,}"),
        (
            "a basic-auth credential",
            r"(?i)authorization[\"']?\s{0,5}[:=]\s{0,5}[\"']?basic\s+[A-Za-z0-9+/]{16,}={0,2}",
        ),
        ("a password inside a URL", r"://[^/\s:@]{1,200}:[^/\s@]{1,200}@"),
        (
            "a private key given as 64 hex digits",
            r"(?i)(?:private|secret|signing|master)[_-]?key[\"']?\s{0,5}[:=]\s{0,5}[\"']?"
            r"[0-9a-f]{64}(?![0-9A-Za-z])",
        ),
    )
)

# The assignment shape is checked in code (see ``_assignment_kind``): a regular expression finds
# the candidate, the code decides whether its value looks random rather than like a path or a word.
_ASSIGNMENT: Final = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|passw(?:or)?d|credential)s?[\"']?\s{0,5}[:=]"
    r"\s{0,5}[\"']?(?P<value>[A-Za-z0-9/+_\-.=~]{20,})"
)
_ASSIGNMENT_KIND: Final = "a key/token assignment followed by a long random value"
_PATH_START: Final = ("/", "~", "./", "../", ".\\", "..\\")

_SECRET_KEY_NAME: Final = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|passw(?:or)?d|credential|auth)"
)
_HEX_KEY_NAME: Final = re.compile(r"(?i)(?:key|private|seed|signing|secret)")
_SECRET_KEY_SAFE_SUFFIX: Final = ("_env", "_file", "_name", "_var", "_path", "_dir")
_LONG_RANDOM: Final = re.compile(r"[A-Za-z0-9/+_\-.=]{20,}")
_HEX64: Final = re.compile(r"[0-9A-Fa-f]{64}")


def _looks_random(value: str) -> bool:
    """Letters and digits mixed, and not the start of a path: what a generated secret looks like."""
    if value.startswith(_PATH_START):
        return False
    return any(ch.isdigit() for ch in value) and any(ch.isalpha() for ch in value)


def _assignment_kind(text: str) -> str | None:
    for found in _ASSIGNMENT.finditer(text):
        if _looks_random(found.group("value")):
            return _ASSIGNMENT_KIND
    return None


def _text_kind(text: str) -> str | None:
    if len(text) > MAX_SCAN_CHARS:
        return f"a string longer than {MAX_SCAN_CHARS} characters (not scanned)"
    for label, pattern in _TOKEN_PATTERNS:
        if pattern.search(text) is not None:
            return label
    return _assignment_kind(text)


def _pair_kind(key: object, value: str) -> str | None:
    """A long unbroken random-looking value under a key named like a secret."""
    if not isinstance(key, str) or len(value) > MAX_SCAN_CHARS:
        return None
    lowered = key.lower()
    if lowered.endswith(_SECRET_KEY_SAFE_SUFFIX):
        return None
    if _HEX64.fullmatch(value) is not None and _HEX_KEY_NAME.search(key) is not None:
        return "a 64-digit hex value under a key named like a secret"
    if _SECRET_KEY_NAME.search(key) is None or _LONG_RANDOM.fullmatch(value) is None:
        return None
    if not _looks_random(value):
        return None
    return "a long random value under a key named like a secret"


def skip_policy_test_inputs(path: tuple[str | int, ...]) -> bool:
    """True for ``tests[<n>].input``: regression inputs may contain secret-shaped text."""
    return len(path) == 3 and path[0] == "tests" and isinstance(path[1], int) and path[2] == "input"


def find_secret(
    data: object, *, skip: Callable[[tuple[str | int, ...]], bool] | None = None
) -> tuple[tuple[str | int, ...], str] | None:
    """The location (keys and list indexes) and kind of the first secret-looking string, or None.

    Both mapping keys and values are scanned; a hit in a key is reported as ``<key>`` below the
    mapping that holds it (the key itself is never echoed). ``skip`` (default: skip nothing) is
    called with the location of every node and may exclude a whole subtree from the scan.
    Walks at most ``_MAX_NODES`` nodes and ``_MAX_DEPTH`` levels; a hostile structure that is
    bigger or deeper is reported as a finding instead of being walked (fail closed).
    """
    stack: list[tuple[tuple[str | int, ...], object, object]] = [((), None, data)]
    seen = 0
    while stack:
        path, key, node = stack.pop()
        seen += 1
        if seen > _MAX_NODES or len(path) > _MAX_DEPTH:
            return path[:_MAX_DEPTH], "a structure too large or too deep to scan"
        if skip is not None and skip(path):
            continue
        if isinstance(node, str):
            kind = _text_kind(node) or _pair_kind(key, node)
            if kind is not None:
                return path, kind
        elif isinstance(node, Mapping):
            entries: list[tuple[tuple[str | int, ...], object, object]] = []
            for k, v in node.items():
                step = k if isinstance(k, str | int) else str(k)
                if isinstance(k, str):
                    kind = _text_kind(k)
                    if kind is not None:
                        return (*path, "<key>"), kind  # never echo the key itself
                entries.append(((*path, step), k, v))
            stack.extend(reversed(entries))
        elif isinstance(node, list | tuple):
            stack.extend(
                ((*path, index), key, item) for index, item in reversed(list(enumerate(node)))
            )
    return None
