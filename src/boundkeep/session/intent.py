"""The task intent: what the user asked for, taken from a UserPromptSubmit ``prompt`` (spec §9.2).

The prompt is not only the user's words. The VS Code extension splices IDE context into it
(``<ide_opened_file>``, and ``<ide_selection>`` with the SELECTED FILE TEXT inside) and wraps text
the user pasted in ``<pasted_content id="...">`` (M0a E3, docs/hook-behavior.md). So:

* every ``<ide_*>`` block is removed whole, and so are a few host blocks that carry tool output or
  host notes (``<system-reminder>``, ``<local-command-stdout>``, ...) [未验证: these were not seen
  in a captured prompt; removing them only means sending less];
* a ``<pasted_content>`` block is untrusted text (copied from a page, a log, an issue): it is not
  taken at all, a marker with its length stands in for it. The spec allows "a truncated summary or
  nothing"; nothing it is, because pasted text is the easiest way for injected instructions to pose
  as the user's intent;
* a block runs to the LAST closing tag of its name in the prompt, and an unclosed one to the end:
  the host does not escape the text it splices in, so a selected file that contains
  ``</ide_selection>`` must not end the block early. Removing too much is the safe direction;
* that "last closing tag" may sit inside a LATER block (pasted text that carries
  ``</ide_opened_file>``): then the removed region holds the opening tag of that other block, and
  the region grows to the end of that block too, again and again until no opening tag is left
  inside it (self-review of M3a: otherwise the rest of the paste was kept as the user's words);
* after ``MAX_BLOCKS`` host blocks everything that follows is dropped (each block costs a search
  over the prompt; a prompt made of thousands of differently named tags must not cost minutes);
* then non-printing characters become spaces and whitespace runs collapse; when the kept text had
  to be cut, the word the cut went through is dropped; secrets are redacted and only after that the
  text is cut to its final length (a key cut in half no longer looks like a key).

Bounded time: tags are found with ``str.find`` / ``str.rfind``, no regex runs over the prompt, the
last closing tag of each name is looked up once, and the kept text is bounded before redaction.
"""

from __future__ import annotations

from boundkeep.redact import redact_text

PASTED_MARK = "[pasted text left out: {chars} characters]"
_BLOCK_PREFIXES = ("ide_",)
_BLOCK_NAMES = frozenset(
    {
        "system-reminder",
        "local-command-stdout",
        "local-command-stderr",
        "local-command-caveat",
        "bash-stdout",
        "bash-stderr",
    }
)
_PASTED = "pasted_content"
_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-")
_MAX_TAG_CHARS = 512  # an opening or closing tag longer than this is not a tag of the host's
_KEEP_FACTOR = 4  # kept text is bounded at this many times the final length before redaction
MAX_BLOCKS = 64  # host blocks (nested ones included) handled before the rest is dropped
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _tag_name(low: str, start: int) -> str | None:
    """The lowercase name of the tag that opens at ``start`` (``low[start] == "<"``), or None."""
    end = start + 1
    stop = min(len(low), start + 1 + 64)
    while end < stop and low[end] in _NAME_CHARS:
        end += 1
    if end == start + 1 or end >= len(low):
        return None
    if low[end] not in "> \t\r\n/":
        return None
    return low[start + 1 : end]


def _wanted(name: str) -> bool:
    return name == _PASTED or name in _BLOCK_NAMES or name.startswith(_BLOCK_PREFIXES)


class _TooMany(Exception):
    """More host blocks than ``MAX_BLOCKS``: the rest of the prompt is dropped."""


class _Closings:
    """The position of the last ``</name`` in the prompt, looked up once per name."""

    def __init__(self, low: str) -> None:
        self._low = low
        self._last: dict[str, int] = {}

    def last(self, name: str) -> int:
        found = self._last.get(name)
        if found is None:
            found = self._last[name] = self._low.rfind("</" + name)
        return found


def _block_end(low: str, name: str, body: int, closings: _Closings) -> tuple[int, int]:
    """(where the content ends, where the block ends) for the block whose opening tag ends at
    ``body``: at the LAST ``</name...>``, or both at the end of the text when there is none."""
    n = len(low)
    close = closings.last(name)
    if close < body:
        return n, n
    after = close + 2 + len(name)
    if after < n and low[after] not in "> \t\r\n":
        # ``</ide_selectionX``: not the closing tag of this name; the block runs to the end
        return n, n
    gt = low.find(">", after, after + _MAX_TAG_CHARS)
    return (n, n) if gt < 0 else (close, gt + 1)


def _region(
    low: str, start: int, name: str, closings: _Closings, count: list[int]
) -> tuple[int, int, int]:
    """(where the content starts, where it ends, where the removed region ends) for the host block
    that opens at ``start``. The region grows over every other host block whose opening tag lies
    inside it (see the module docstring); ``count`` counts every block looked at."""
    n = len(low)
    gt = low.find(">", start, start + _MAX_TAG_CHARS)
    if gt < 0:
        return n, n, n  # an opening tag that never closes: the rest goes
    body = gt + 1
    content_end, end = _block_end(low, name, body, closings)
    scan = body
    while scan < end:
        nxt = low.find("<", scan, end)
        if nxt < 0:
            break
        other = _tag_name(low, nxt)
        if other is not None and _wanted(other):
            count[0] += 1
            if count[0] > MAX_BLOCKS:
                raise _TooMany
            other_gt = low.find(">", nxt, nxt + _MAX_TAG_CHARS)
            if other_gt < 0:
                return body, content_end, n
            end = max(end, _block_end(low, other, other_gt + 1, closings)[1])
        scan = nxt + 1
    return body, content_end, end


def _strip_blocks(text: str, budget: int) -> tuple[str, bool]:
    """``text`` without the host blocks (pasted text replaced by a marker), at most ``budget``
    characters of it, and whether it was cut there (a cut through the kept text, not the drop of
    everything after ``MAX_BLOCKS`` blocks, which ends at a tag)."""
    low = text.translate(_ASCII_LOWER)  # ASCII only: keeps every index of ``text`` valid
    closings = _Closings(low)
    count = [0]
    out: list[str] = []
    kept = 0
    i = 0
    n = len(text)
    while i < n and kept <= budget:
        lt = text.find("<", i)
        if lt < 0:
            lt = n
        piece = text[i:lt]
        out.append(piece)
        kept += len(piece)
        i = lt
        if lt >= n:
            break
        name = _tag_name(low, lt)
        if name is None or not _wanted(name):
            out.append("<")
            kept += 1
            i = lt + 1
            continue
        count[0] += 1
        try:
            if count[0] > MAX_BLOCKS:
                raise _TooMany
            body, content_end, end = _region(low, lt, name, closings, count)
        except _TooMany:
            i = n
            break
        if name == _PASTED:
            mark = " " + PASTED_MARK.format(chars=max(0, content_end - body)) + " "
            out.append(mark)
            kept += len(mark)
        else:
            out.append(" ")
            kept += 1
        i = end
    joined = "".join(out)
    return joined[:budget], len(joined) > budget


def _printable_words(text: str) -> str:
    """Non-printing characters (controls, bidi and other format characters) become spaces; runs
    of whitespace collapse to one space."""
    cleaned = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(cleaned.split())


def extract_intent(prompt: object, max_chars: int) -> str:
    """The task intent of one prompt: host blocks removed, pasted text left out, secrets redacted,
    at most ``max_chars`` characters ("" when nothing of the user's own words is left).

    Never raises: anything that is not a string, or any unexpected failure, gives "".
    """
    if not isinstance(prompt, str) or max_chars < 1:
        return ""
    try:
        kept, cut = _strip_blocks(prompt, _KEEP_FACTOR * max_chars)
        words = _printable_words(kept)
        if cut:
            # the cut may go through a secret whose shape needs its end (``://user:pw@host``):
            # drop the word it went through, so no fragment is left for the redactor to miss
            space = words.rfind(" ")
            words = words[:space] if space >= 0 else ""
        words = redact_text(words)
        if len(words) > max_chars:
            words = words[: max_chars - 1].rstrip() + "…"
        return words
    except Exception:  # noqa: BLE001 - an intent that cannot be built is simply absent
        return ""
