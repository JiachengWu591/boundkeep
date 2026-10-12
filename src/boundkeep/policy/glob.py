"""Path globs for policy rules: a small, linear-time matcher over canonical path keys.

A ``path_glob`` is matched against ``PathRef.key`` (forward slashes, Windows keys already
casefolded; see ``normalize/paths.py``). Both sides are casefolded here, so a deny or ask rule
over-matches rather than under-matches (a case-variant of ``.ssh`` is still ``.ssh`` on Windows and
macOS, and over-matching is the safe direction for a rule that blocks).

Syntax (forward slashes only; a backslash is an error, not an escape):

* ``*``   any run of characters except ``/`` (possibly empty);
* ``?``   exactly one character except ``/``;
* ``[abc]``, ``[a-z]``, ``[!abc]`` / ``[^abc]``: one character except ``/``; a class never
  matches ``/`` and may not contain one; ``]`` first in the class is a literal;
* ``**/`` at the start of a segment: zero or more whole directories, so ``**/.env`` matches
  ``.env``, ``/home/u/.env`` and ``c:/x/y/.env``;
* a trailing ``/**``: the directory itself and everything below it, so ``~/.ssh/**`` matches
  ``<home>/.ssh`` and ``<home>/.ssh/id_rsa`` (over-matching the directory is the safe direction);
* ``**`` anywhere else (``a**b``, ``**.pem``): any run of characters including ``/``;
* everything else is literal. To match a literal ``*``, ``?`` or ``[`` write ``[*]``, ``[?]`` or
  ``[[]``. A pattern may not be empty and may not end in ``/`` (write ``dir/**``).

How matching stays linear. The pattern is compiled to a token list (literal, ``?``, class, ``*``,
``**``, ``**/``) and matched as a Thompson NFA whose state set is one Python integer used as a
bit set (position *i* set means "about to consume token *i*"). Each input character costs a
constant number of big-integer operations on a word-sized-to-``len(pattern)/64`` integer, plus an
epsilon closure over a chain of consecutive optional tokens, which compile-time collapsing of
adjacent stars keeps to a handful. There is no backtracking, so ``*a*a*a*a*b`` against a long
run of ``a`` costs the same as against anything else: ``O(len(key))`` big-int steps.
Pattern length, key length and the per-pattern token count are bounded (see ``MAX_*``). A
literal-prefix and a literal-suffix pre-check only skip work; the NFA alone decides.
"""

from __future__ import annotations

import functools
from collections.abc import Iterable
from typing import Final

MAX_PATTERN_LENGTH: Final = 512
MAX_TOKENS: Final = 1024
MAX_KEY_LENGTH: Final = 32768
_MASK_CACHE_LIMIT: Final = 2048

# Token kinds.
_LIT, _ANYONE, _CLASS, _STAR, _ANYSTAR, _DSEG = range(6)


class GlobError(ValueError):
    """A ``path_glob`` that cannot be compiled; the message never includes more than 40 characters
    of the pattern and is plain printable ASCII."""


def _show(pattern: str) -> str:
    return "'" + ascii(pattern[:40])[1:-1] + ("..." if len(pattern) > 40 else "") + "'"


class _Token:
    __slots__ = ("kind", "lit", "negated", "pairs", "singles")

    def __init__(
        self,
        kind: int,
        lit: str = "",
        singles: frozenset[str] = frozenset(),
        pairs: tuple[tuple[str, str], ...] = (),
        negated: bool = False,
    ) -> None:
        self.kind = kind
        self.lit = lit
        self.singles = singles
        self.pairs = pairs
        self.negated = negated


def _parse_class(pattern: str, start: int) -> tuple[_Token, int]:
    """Parse ``[...]`` whose ``[`` is at ``start``; return the token and the index after ``]``."""
    i = start + 1
    n = len(pattern)
    negated = False
    if i < n and pattern[i] in "!^":
        negated = True
        i += 1
    singles: set[str] = set()
    pairs: list[tuple[str, str]] = []
    first = True
    while True:
        if i >= n:
            raise GlobError(f"unterminated '[' in glob {_show(pattern)}")
        ch = pattern[i]
        if ch == "]" and not first:
            i += 1
            break
        first = False
        if ch == "/":
            raise GlobError(f"'/' inside a [...] class in glob {_show(pattern)}")
        if i + 2 < n and pattern[i + 1] == "-" and pattern[i + 2] != "]":
            lo, hi = ch, pattern[i + 2]
            if hi == "/":
                raise GlobError(f"'/' inside a [...] class in glob {_show(pattern)}")
            if lo > hi:
                raise GlobError(f"reversed range {lo}-{hi} in glob {_show(pattern)}")
            pairs.append((lo, hi))
            fl, fh = lo.casefold(), hi.casefold()
            if len(fl) == 1 and len(fh) == 1 and fl <= fh:
                pairs.append((fl, fh))
            i += 3
            continue
        singles.add(ch)
        singles.update(ch.casefold())
        i += 1
    return _Token(_CLASS, singles=frozenset(singles), pairs=tuple(pairs), negated=negated), i


def _tokenize(pattern: str) -> tuple[list[_Token], bool]:
    """Tokens of the pattern minus a trailing ``/**``, and whether that tail was present."""
    tail = False
    body = pattern
    while body.endswith("/**"):
        body = body[:-3]
        tail = True
    tokens: list[_Token] = []
    i, n = 0, len(body)
    while i < n:
        ch = body[i]
        at_segment_start = i == 0 or body[i - 1] == "/"
        if ch == "*":
            j = i
            while j < n and body[j] == "*":
                j += 1
            run = j - i
            if run == 2 and at_segment_start and j < n and body[j] == "/":
                if not tokens or tokens[-1].kind != _DSEG:
                    tokens.append(_Token(_DSEG))
                i = j + 1  # the "/" belongs to the "**/" token
                continue
            # A run of stars is one token (runs are maximal, so two star tokens are never
            # adjacent and the epsilon closure never has to walk a long chain of them).
            tokens.append(_Token(_STAR if run == 1 else _ANYSTAR))
            i = j
        elif ch == "?":
            tokens.append(_Token(_ANYONE))
            i += 1
        elif ch == "[":
            token, i = _parse_class(body, i)
            tokens.append(token)
        else:
            for folded in ch.casefold():
                tokens.append(_Token(_LIT, lit=folded))
            i += 1
        if len(tokens) > MAX_TOKENS:
            raise GlobError(f"glob {_show(pattern)} is too complex")
    return tokens, tail


def _class_matches(token: _Token, ch: str) -> bool:
    if ch == "/":
        return False
    hit = ch in token.singles or any(lo <= ch <= hi for lo, hi in token.pairs)
    return hit != token.negated


class Glob:
    """A compiled glob. Immutable apart from an internal per-character mask cache."""

    __slots__ = (
        "_accept",
        "_anyone",
        "_anystar",
        "_cache",
        "_classes",
        "_dseg_entry",
        "_dseg_loop",
        "_eps1",
        "_lit",
        "_prefix",
        "_star",
        "_start",
        "_suffix",
        "pattern",
    )

    def __init__(self, pattern: str) -> None:
        if not isinstance(pattern, str):
            raise GlobError("a glob must be a string")
        if not pattern:
            raise GlobError("a glob must not be empty")
        if len(pattern) > MAX_PATTERN_LENGTH:
            raise GlobError(f"a glob is longer than {MAX_PATTERN_LENGTH} characters")
        if "\\" in pattern:
            raise GlobError(
                f"backslash in glob {_show(pattern)}: write paths with '/' "
                "(use [[] style classes, not escapes, for literal wildcards)"
            )
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in pattern):
            raise GlobError(f"control character in glob {_show(pattern)}")
        if pattern.endswith("/") and not pattern.endswith("/**"):
            raise GlobError(f"glob {_show(pattern)} ends with '/': write 'dir/**' instead")
        self.pattern = pattern
        tokens, tail = _tokenize(pattern)
        # NFA positions: one per token, two for "**/" (an entry state that may be skipped, and a
        # loop state that consumes characters until a "/").
        lit: dict[str, int] = {}
        anyone = star = anystar = dseg_entry = dseg_loop = 0
        classes: list[tuple[int, _Token]] = []
        pos = 0
        for token in tokens:
            bit = 1 << pos
            if token.kind == _LIT:
                lit[token.lit] = lit.get(token.lit, 0) | bit
            elif token.kind == _ANYONE:
                anyone |= bit
            elif token.kind == _CLASS:
                classes.append((bit, token))
            elif token.kind == _STAR:
                star |= bit
            elif token.kind == _ANYSTAR:
                anystar |= bit
            else:
                dseg_entry |= bit
                dseg_loop |= bit << 1
                pos += 1
            pos += 1
        accept = 1 << pos
        if tail:
            # "/" then "**" after the body; the body's end is accepting too ("dir/**" is "dir").
            lit["/"] = lit.get("/", 0) | (1 << pos)
            anystar |= 1 << (pos + 1)
            accept = (1 << (pos + 2)) | (1 << pos)
        self._lit = lit
        self._anyone = anyone
        self._classes = tuple(classes)
        self._star = star
        self._anystar = anystar
        self._dseg_entry = dseg_entry
        self._dseg_loop = dseg_loop
        self._eps1 = star | anystar
        self._accept = accept
        self._start = self._close(1)
        self._cache: dict[str, tuple[int, int, int]] = {}
        prefix: list[str] = []
        for token in tokens:
            if token.kind != _LIT:
                break
            prefix.append(token.lit)
        self._prefix = "".join(prefix)
        suffix: list[str] = []
        if not tail:
            for token in reversed(tokens):
                if token.kind != _LIT:
                    break
                suffix.append(token.lit)
        self._suffix = "".join(reversed(suffix))

    def _close(self, state: int) -> int:
        """Epsilon closure: a star may match nothing (+1); an entered ``**/`` may be skipped."""
        eps1, eps2 = self._eps1, self._dseg_entry
        while True:
            grown = state | ((state & eps1) << 1) | ((state & eps2) << 2)
            if grown == state:
                return state
            state = grown

    def _masks(self, ch: str) -> tuple[int, int, int]:
        """(advance by one, advance by two, stay) position masks for the character ``ch``."""
        cached = self._cache.get(ch)
        if cached is not None:
            return cached
        one = self._lit.get(ch, 0) | self._dseg_entry  # "**/" entry: any char starts its loop
        two = 0
        if ch == "/":
            two = self._dseg_entry  # ... and a "/" may also be the one that ends it
            one |= self._dseg_loop
        else:
            one |= self._anyone
        for bit, token in self._classes:
            if _class_matches(token, ch):
                one |= bit
        stay = self._anystar | self._dseg_loop | (self._star if ch != "/" else 0)
        if len(self._cache) >= _MASK_CACHE_LIMIT:
            self._cache.clear()
        masks = (one, two, stay)
        self._cache[ch] = masks
        return masks

    def match(self, key: str) -> bool:
        """True if ``key`` (casefolded here) is selected by the pattern.

        An empty key or a key longer than ``MAX_KEY_LENGTH`` is never matched here; the rule
        matcher decides what that means for deny/ask versus allow rules.
        """
        if not isinstance(key, str) or not key or len(key) > MAX_KEY_LENGTH:
            return False
        folded = key.casefold()
        if self._prefix and not folded.startswith(self._prefix):
            return False
        if self._suffix and not folded.endswith(self._suffix):
            return False
        state = self._start
        eps1, eps2 = self._eps1, self._dseg_entry
        for ch in folded:
            one, two, stay = self._masks(ch)
            state = ((state & one) << 1) | ((state & two) << 2) | (state & stay)
            if not state:
                return False
            while True:
                grown = state | ((state & eps1) << 1) | ((state & eps2) << 2)
                if grown == state:
                    break
                state = grown
        return bool(state & self._accept)

    def __repr__(self) -> str:
        return f"Glob({self.pattern!r})"


@functools.lru_cache(maxsize=4096)
def compile_glob(pattern: str) -> Glob:
    """Compile ``pattern``; raises ``GlobError`` (a ``ValueError``) for anything unusable."""
    return Glob(pattern)


def first_match(patterns: Iterable[str], key: str) -> str | None:
    """The first of ``patterns`` that selects ``key``, or None."""
    for pattern in patterns:
        if compile_glob(pattern).match(key):
            return pattern
    return None
