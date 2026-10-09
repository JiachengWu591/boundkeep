"""Redaction of secrets from text and from JSON-like records (spec section 11).

Everything boundkeep writes to its audit log, and (from M3a) everything it sends to an LLM
backend, passes through here first. Three properties matter more than coverage:

* The secret never survives. Where a pattern is ambiguous we redact more, not less.
* Linear time. The daemon redacts text that the agent (and whoever steers it) controls, so a
  regex that backtracks catastrophically is a denial of service on the hook path. Every pattern
  below is either anchored on a literal, bounded, or protected by a lookbehind / atomic group so
  that a failing attempt is never retried from inside the region it already scanned. Constructs
  that cannot be expressed that way (shell-style values, private key headers) are matched by a
  small set of unrolled quoted-string patterns plus explicit position bookkeeping in Python.
* Bounded work. Linear is not enough: a 2 MB command made of 330000 tiny assignments costs
  seconds in Python even when every step is linear. Each call therefore owns a budget of
  Python-level candidate checks. A text that exhausts it is not an ordinary command; we keep a
  redacted head of it and drop the rest (``[REDACTED]``) instead of stalling the hook path.
  Cheap substring gates skip every pass whose trigger word is absent, so ordinary text costs
  almost nothing however long it is.

Standard library only. Python 3.11+ is required for the atomic groups.
"""

from __future__ import annotations

import re

__all__ = ["REDACTED", "TRUNCATED", "redact_obj", "redact_text"]

REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"

# Redaction output can unlock a pattern that a lookbehind blocked in the previous round (for
# example "AKIA<16 chars>sk-..." leaves "sk-..." behind a "]"). We therefore rerun the pipeline
# until nothing changes. That makes redact_text idempotent by construction. Two rounds are normal;
# the cap is only a guard, and hitting it fails closed.
_MAX_ROUNDS = 8

# Work budgets (Python-level candidate checks, shared by every pass and round of one call).
# Four to eight microseconds each, so a hostile text costs a quarter of a second at worst.
_ATTEMPTS_TEXT = 30_000
_ATTEMPTS_OBJ = 60_000
# When the budget runs out we keep this many leading characters (cut at whitespace) and redact them.
_FALLBACK_HEAD = 16_384
_FALLBACK_CUT_WINDOW = 1_024

# redact_obj limits. The depth cap keeps recursion well below the interpreter limit; the node
# budget stops a shared (non-cyclic) structure that fans out exponentially from hanging us.
_HARD_DEPTH = 100
_MAX_NODES = 200_000

_FLAGS = re.IGNORECASE | re.ASCII

# Characters that end an unquoted shell word. Only ASCII whitespace: NBSP, U+2028, U+0085 and the
# C0 separators are ordinary word characters to bash and PowerShell, so the tail of a value that
# contains one is still part of the secret.
_WS = " \t\r\n"


class _Overload(Exception):  # control flow inside this module, never escapes
    """The work budget of one redaction call is spent."""


class _Work:
    """Budget of Python-level candidate checks shared by all passes of one call."""

    __slots__ = ("remaining",)

    def __init__(self, remaining: int) -> None:
        self.remaining = remaining

    def charge(self) -> None:
        self.remaining -= 1
        if self.remaining < 0:
            raise _Overload


# --------------------------------------------------------------------------------------------
# Token-shaped secrets
# --------------------------------------------------------------------------------------------

# "sk-" must not sit inside an ordinary ASCII word ("disk-usage-report-..."): require something
# other than [A-Za-z0-9_] (or the start of the text) before it. The class is spelled out instead of
# \w on purpose: \w counts every Unicode letter, so "\u5bc6\u94a5sk-..." (a key glued to Chinese
# prose, which has no spaces) or "caf\u00e9sk-..." would hide a real key.
_SK_KEY = re.compile(r"(?<![A-Za-z0-9_])sk-[A-Za-z0-9_-]{16,}")
# No boundary requirement on the next two: a key glued to other text is still a key.
_AWS_KEY = re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")
_GITHUB_TOKEN = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}")
# Extra: well-known vendor token shapes (Slack, Google API, Stripe, npm, GitLab, JWT).
_VENDOR_TOKEN = re.compile(
    r"xox[abprs]-[A-Za-z0-9-]{10,}|AIza[A-Za-z0-9_-]{30,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"
    r"|npm_[A-Za-z0-9]{30,}|glpat-[A-Za-z0-9_-]{16,}"
    r"|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
)
_VENDOR_TRIGGERS = ("xox", "aiza", "_live_", "_test_", "npm_", "glpat-", "eyj")
# Extra: custom credential headers (X-Api-Key, X-Auth-Token, ...): the value up to the closing
# quote or the end of the line.
_X_HEADER = re.compile(
    r"(\bx-[a-z0-9-]{0,30}(?:key|token|auth|secret)[a-z0-9-]{0,10}[ \t]*+:[ \t]*+)[^\r\n\"']+",
    _FLAGS,
)
_BEARER = re.compile(r"(\bbearer[ \t]+)[A-Za-z0-9._~+/=-]{8,}", _FLAGS)
# Extra: HTTP Basic credentials in an Authorization header (base64 of user:password).
_BASIC_AUTH = re.compile(
    r"(\bauthorization[ \t]*[:=][ \t]*[\"']?basic[ \t]+)[A-Za-z0-9+/=_-]{8,}", _FLAGS
)
# Extra: any other Authorization header value ("Token x", "ApiKey x", a bare key): everything up to
# the closing quote or the end of the line. Bearer and Basic are left to the two patterns above.
_AUTH_HEADER = re.compile(
    r"(\bauthorization[ \t]*+:[ \t]*+)(?!(?:bearer|basic)[ \t])[^\r\n\"']+", _FLAGS
)
# Extra: scheme://user:password@host. Anchored on the literal "://"; the user part is bounded and
# the password run stops at "/" or whitespace, so each attempt scans only up to the next such
# character. The greedy run backtracks to the last "@" so a password containing "@" is covered.
# file:// is excluded: it carries no credentials, and file://C:\Users\bob@corp\x is a path.
_URL_PASSWORD = re.compile(r"(?<!file)(://[^\s/:@]{0,64}:)[^\s/]+@", _FLAGS)

# Private key blocks. "-----BEGIN " opens a candidate; the header up to "PRIVATE KEY-----" may be
# any length but may not span lines. Pairing BEGIN markers with terminators is done with sorted
# position lists and two forward-only pointers (see _pass_private_keys): a regex with an unbounded
# header would rescan the rest of the line from every BEGIN. Matching is case-insensitive.
_PK_BEGIN = re.compile(r"-----BEGIN ", _FLAGS)
_PK_TERM = re.compile(r"PRIVATE KEY(?: BLOCK)?-----", _FLAGS)
_PK_END = re.compile(r"-----END [^\r\n]{0,64}?PRIVATE KEY(?: BLOCK)?-----", _FLAGS)
_EOL = re.compile(r"[\r\n]")
_PK_BEGIN_LEN = len("-----BEGIN ")

# --------------------------------------------------------------------------------------------
# Quoted strings and shell-style words
# --------------------------------------------------------------------------------------------

# Double-quoted: backslash and backtick (PowerShell) escape the next character, a doubled quote
# is a literal quote (PowerShell, and shell word concatenation). Single-quoted: only a doubled
# quote. Both are "unrolled loops": the alternatives start with different characters, so a failed
# match backtracks in O(n) total, never exponentially.
_DQ = r'"[^"\\`]*(?:(?:\\[\s\S]|`[\s\S]|"")[^"\\`]*)*"'
_SQ = r"'[^']*(?:''[^']*)*'"
_QUOTED = re.compile(_DQ + "|" + _SQ)
# A shell word: unquoted runs, backslash escapes ("abc\ def" is one word, so is a backslash-newline
# continuation) and quoted segments back to back, up to unquoted ASCII whitespace.
_WORD = re.compile(r"(?:[^ \t\r\n\"'\\]+|\\[\s\S]|\\|" + _DQ + "|" + _SQ + r")*")
# The same inside a string that is still open around the name: its own quote ends the word.
_WORD_IN_DQ = re.compile(r"(?:[^ \t\r\n\"'\\]+|\\[\s\S]|\\|" + _SQ + r")*")
_WORD_IN_SQ = re.compile(r"(?:[^ \t\r\n\"'\\]+|\\[\s\S]|\\|" + _DQ + r")*")
# Body of a quote-enclosed assignment ("NAME=value") up to and including the closing quote.
_DQ_TAIL = re.compile(r'[^"\\`]*(?:(?:\\[\s\S]|`[\s\S])[^"\\`]*)*"')
_SQ_TAIL = re.compile(r"[^']*'")
_SPACES = re.compile(r"[ \t]*")
_ARG = re.compile(r"[^\s,)]+")  # unquoted argument of SetEnvironmentVariable
# PowerShell string concatenation after a literal: ... + "more" + $var
_CONCAT_SEGMENT = re.compile(_DQ + "|" + _SQ + r"|[^ \t\r\n\"'+;,)]+")
# cmd.exe: the value of "set NAME=value" runs to the end of the command: an unquoted & | < > or
# the end of the line. "^" escapes the next character and quoted text protects the operators.
_CMD_VALUE = re.compile(r'(?:[^&|<>^"\r\n]+|\^[^\r\n]?|"[^"\r\n]*"?)*')
_SET_BEFORE = re.compile(r"(?:^|[^A-Za-z0-9_.-])set[ \t]+(?:/[A-Za-z][ \t]+)*\Z", _FLAGS)

# After a closing quote these end the value (it is a complete literal, not a word concatenation).
_AFTER_QUOTE_STOPS = frozenset(";,)]}&|<>")
# Characters that end an unquoted shell word as operators (not the whitespace in _WS).
_SHELL_OPERATORS = frozenset(";&|<>)")
# How far back to look (within the line) when deciding whether a name sits inside an open quote.
_QUOTE_WINDOW = 512

# --------------------------------------------------------------------------------------------
# Assignments of variables whose name looks secret
# --------------------------------------------------------------------------------------------

_ASSIGN_WORDS = "key|token|secret|password|passwd"
_ASSIGN_WORD_LIST = tuple(_ASSIGN_WORDS.split("|"))
_NAME_CHARS = "A-Za-z0-9_.-"
_ASSIGN_ANY = re.compile(_ASSIGN_WORDS, _FLAGS)
# A name run containing a keyword that is directly followed by "=" (optionally "+=", optionally
# after spaces, after the "}" of ${env:NAME}, or after the closing quote and bracket of
# os.environ['NAME'] / @{ "NAME" = ... }). The lookbehind restricts attempts to run starts and
# the atomic group commits to the first keyword, so every character is examined a bounded number
# of times however many keywords a run contains.
_ASSIGN_RUN = re.compile(
    r"(?<![" + _NAME_CHARS + r"])"
    r"(?>[" + _NAME_CHARS + r"]*?(?:" + _ASSIGN_WORDS + r")[" + _NAME_CHARS + r"]*)"
    r"(?=\}?[\"']?\]?[ \t]*\+?=)",
    _FLAGS,
)

# [Environment]::SetEnvironmentVariable("NAME", "value", ...), os.putenv("NAME", "value") and
# os.environ.setdefault("NAME", "value"): redact the value argument only.
_SET_ENV_VAR = re.compile(
    r"(?:SetEnvironmentVariable|putenv|setdefault)"
    r"[ \t\r\n]*\([ \t\r\n]*([\"'])([^\"'\r\n]{0,128})\1[ \t\r\n]*,[ \t\r\n]*",
    _FLAGS,
)
# PowerShell: the plaintext argument of ConvertTo-SecureString is a secret by definition.
_SECURE_STRING = re.compile(r"ConvertTo-SecureString[ \t]+(?:-String[ \t]+)?(?=[\"'])", _FLAGS)
# cmd: setx [/M] NAME value
_SETX = re.compile(
    r"(?<![A-Za-z0-9_])setx[ \t]+(?:/[A-Za-z][ \t]+)*([\"']?)([A-Za-z0-9_.-]+)\1[ \t]+", _FLAGS
)
# Command line flags that take a secret as the next word: --password hunter2, --token "a b".
_SECRET_FLAG = re.compile(
    r"(?<![A-Za-z0-9_-])--(?:password|passwd|token|secret|api-key|api_key|apikey|access-token"
    r"|auth-token|client-secret|private-token|pass|passphrase|pwd)[ \t]+",
    _FLAGS,
)

# JSON-like pairs: a quoted key containing a keyword, then ":". The quote may be written with up
# to four backslashes in front (JSON inside a double-quoted shell argument, or JSON inside a JSON
# string): \"api_key\": \"value\". The lookahead (bounded, cannot cross a quote) checks for the
# keyword so Python only sees real candidates. The optional backslashes are bounded, so each start
# position costs a constant.
_JSON_WORDS = _ASSIGN_WORDS + "|authorization|credential"
_JSON_PAIR = re.compile(
    r"(?P<q>\\{0,4}[\"'])(?=[^\"'\\\r\n]{0,100}?(?:"
    + _JSON_WORDS
    + r"))[^\"'\\\r\n]{0,100}(?P=q)[ \t\r\n]*:[ \t\r\n]*",
    _FLAGS,
)
_JSON_OPEN = re.compile(r"(\\{0,4})([\"'])")
_JSON_WORD_LIST = (*_ASSIGN_WORD_LIST, "authorization", "credential")

# redact_obj: dict keys whose string values are secrets even when the value matches no pattern.
_SENSITIVE_KEY = re.compile(
    r"key|token|secret|password|passwd|authorization|credential", re.IGNORECASE | re.ASCII
)

# Substrings (lowercase) that can start any pattern above. Used to decide whether a text needs
# any work at all once the work budget is gone.
_ANY_TRIGGER = (
    "sk-",
    "akia",
    "asia",
    "gh",
    "github_pat_",
    "xox",
    "aiza",
    "_live_",
    "_test_",
    "npm_",
    "glpat-",
    "eyj",
    "x-",
    "--pass",
    "--pwd",
    "bearer",
    "authorization",
    "credential",
    "://",
    "-----begin",
    "setx",
    "environmentvariable",
    "putenv",
    "setdefault",
    "securestring",
    *_ASSIGN_WORD_LIST,
)

_Edit = tuple[int, int, str]


def _splice(text: str, edits: list[_Edit]) -> str:
    """Apply ascending, non-overlapping (start, end, replacement) edits."""
    if not edits:
        return text
    parts: list[str] = []
    last = 0
    for start, end, replacement in edits:
        parts.append(text[last:start])
        parts.append(replacement)
        last = end
    parts.append(text[last:])
    return "".join(parts)


def _contains_any(low: str, needles: tuple[str, ...]) -> bool:
    return any(needle in low for needle in needles)


# --------------------------------------------------------------------------------------------
# Passes
# --------------------------------------------------------------------------------------------


def _pass_private_keys(text: str, work: _Work) -> str:
    """Replace whole PEM-style private key blocks; an unterminated block runs to the end."""
    begins = [m.start() for m in _PK_BEGIN.finditer(text)]
    terms = [(m.start(), m.end()) for m in _PK_TERM.finditer(text)]
    if not begins or not terms:
        return text
    n = len(text)
    edits: list[_Edit] = []
    pos = 0  # end of the last block; BEGIN markers inside it are part of it
    ti = 0  # first terminator that can still belong to the current or a later BEGIN
    eol = -1  # next line end at or after the current BEGIN (n when there is none)
    for begin in begins:
        if begin < pos:
            continue
        work.charge()
        header_start = begin + _PK_BEGIN_LEN
        while ti < len(terms) and terms[ti][0] < header_start:
            ti += 1
        if ti == len(terms):
            break  # no terminator after this BEGIN, hence none after any later one either
        if eol < begin:
            found = _EOL.search(text, begin)
            eol = found.start() if found is not None else n
        term_start, term_end = terms[ti]
        if eol < term_start:
            continue  # the line of this BEGIN has no PRIVATE KEY terminator
        end = _PK_END.search(text, term_end)
        stop = n if end is None else end.end()
        edits.append((begin, stop, REDACTED))
        pos = stop
    return _splice(text, edits)


def _pass_tokens(text: str, low: str) -> str:
    # sk- comes last: removing an AWS id or a GitHub token in front of it unlocks its lookbehind.
    if "akia" in low or "asia" in low:
        text = _AWS_KEY.sub(REDACTED, text)
    if "gh" in low or "github_pat_" in low:  # "github" itself has no "gh" in it
        text = _GITHUB_TOKEN.sub(REDACTED, text)
    if _contains_any(low, _VENDOR_TRIGGERS):
        text = _VENDOR_TOKEN.sub(REDACTED, text)
    if "x-" in low:
        text = _X_HEADER.sub(r"\1" + REDACTED, text)
    if "bearer" in low:
        text = _BEARER.sub(r"\1" + REDACTED, text)
    if "authorization" in low:
        text = _BASIC_AUTH.sub(r"\1" + REDACTED, text)
        text = _AUTH_HEADER.sub(r"\1" + REDACTED, text)
    if "://" in low:
        text = _URL_PASSWORD.sub(r"\1" + REDACTED + "@", text)
    if "sk-" in low:
        text = _SK_KEY.sub(REDACTED, text)
    return text


def _enclosing_quote(text: str, pos: int) -> str:
    """The quote character (or "") of the string that ``pos`` most likely sits inside.

    A heuristic on the text just before ``pos`` on the same line: an odd number of quotes of one
    kind means one of them is still open. It only decides where an unquoted value ends, never
    whether it is redacted.
    """
    segment = text[max(0, pos - _QUOTE_WINDOW) : pos]
    segment = segment[segment.rfind("\n") + 1 :]
    double = segment.count('"') % 2 == 1
    single = segment.count("'") % 2 == 1
    if double and single:
        return '"' if segment.rfind('"') > segment.rfind("'") else "'"
    if double:
        return '"'
    return "'" if single else ""


def _concat_end(text: str, end: int) -> int:
    """End of a PowerShell ``"a" + "b" + $c`` chain that continues after ``end`` (or ``end``)."""
    n = len(text)
    while True:
        j = _skip_spaces(text, end)
        if j + 1 >= n or text[j] != "+" or text[j + 1] == "=":
            return end
        k = _skip_spaces(text, j + 1)
        segment = _CONCAT_SEGMENT.match(text, k)
        if segment is None or segment.end() == k:
            return end
        end = segment.end()


def _value_edit(
    text: str, v: int, *, single_only: bool, name_start: int = -1, concat: bool = False
) -> _Edit | None:
    """Edit that hides the value starting at ``v``, or None when there is nothing to hide.

    A value that is exactly one quoted literal keeps its quotes ("NAME=\"[REDACTED]\""); anything
    else (an unquoted word, a concatenation, an unterminated quote) becomes a bare [REDACTED].
    ``single_only`` accepts just one quoted literal and never extends it into a word (used where
    the value is an argument or a spaced assignment, not a shell word). ``name_start`` is the
    position of the variable name: an unquoted value that ends at a quote which closes a string the
    name sits in ("...?token=abc" -o out) stops there instead of swallowing the rest of the text.
    ``concat`` follows PowerShell ``+`` chains after a literal.
    """
    n = len(text)
    if v >= n:
        return None
    first = text[v]
    if first in "\"'":
        quoted = _QUOTED.match(text, v)
        if quoted is None:
            # Unterminated quote (truncated command): everything after it may be the secret.
            return (v, n, REDACTED)
        end = quoted.end()
        if single_only or end >= n or text[end] in _WS or text[end] in _AFTER_QUOTE_STOPS:
            if concat:
                chained = _concat_end(text, end)
                if chained != end:
                    return (v, chained, REDACTED)
            if end - v == 2 or text[v + 1 : end - 1] == REDACTED:
                return None  # empty literal, or already redacted: nothing to hide
            return (v, end, first + REDACTED + first)
    word = _WORD.match(text, v)
    end = word.end() if word is not None else v
    enclosing = ""
    if name_start >= 0 and (
        (end < n and text[end] in "\"'")
        or text.find('"', v, end) >= 0
        or text.find("'", v, end) >= 0
    ):
        # curl "http://x/?token=abc" -o out: the quote after abc closes the string the name sits
        # in. Read the word again so that it stops there instead of pairing it with the next one.
        enclosing = _enclosing_quote(text, name_start)
        if enclosing:
            restricted = _WORD_IN_DQ if enclosing == '"' else _WORD_IN_SQ
            word = restricted.match(text, v)
            end = word.end() if word is not None else v
    if end < n and text[end] in "\"'" and text[end] != enclosing:
        end = n  # an unterminated quote inside the word
    if end == v:
        return None
    if text.startswith(REDACTED, v):
        # Already redacted by an earlier edit or round. Without this a bare marker followed by
        # punctuation ("$env:T = [REDACTED]; ls") would be read as a word and swallow the ";".
        after = v + len(REDACTED)
        if after >= n or text[after] in _WS or text[after] in _SHELL_OPERATORS:
            return None
    return (v, end, REDACTED)


def _enclosed_edit(text: str, v: int, quote: str, name_start: int) -> _Edit | None:
    """``"NAME=value"`` (set "NAME=value", docker -e "NAME=value"): hide up to the closing quote."""
    n = len(text)
    if v >= n:
        return None
    if text[v] == quote:
        # Either an empty value ("NAME=" then the closing quote) or a value that repeats the
        # quote ("API_KEY="hunter2"): the character after decides.
        after = text[v + 1] if v + 1 < n else ""
        if after == "" or after in _WS or after in _AFTER_QUOTE_STOPS:
            return None
        return _value_edit(text, v, single_only=False, name_start=name_start)
    tail = (_DQ_TAIL if quote == '"' else _SQ_TAIL).match(text, v)
    if tail is None:
        return (v, n, REDACTED)
    close = tail.end() - 1
    if close == v or text[v:close] == REDACTED:
        return None
    return (v, close, REDACTED)


def _cmd_set_edit(text: str, v: int) -> _Edit | None:
    """The value of cmd's ``set NAME=value``: the rest of the command, spaces and all."""
    start = _skip_spaces(text, v)
    match = _CMD_VALUE.match(text, start)
    end = match.end() if match is not None else start
    end = start + len(text[start:end].rstrip(" \t"))
    if end <= start or text[start:end] == REDACTED:
        return None
    return (start, end, REDACTED)


def _skip_spaces(text: str, i: int) -> int:
    """Index of the first character at or after ``i`` that is not a space or tab."""
    match = _SPACES.match(text, i)
    return match.end() if match is not None else i


def _env_prefix(text: str, s: int) -> int:
    """1 when the name at ``s`` follows ``$env:``, 2 when it follows ``${env:``, else 0."""
    if s >= 5 and text[s - 5 : s].lower() == "$env:":
        return 1
    if s >= 6 and text[s - 6 : s].lower() == "${env:":
        return 2
    return 0


def _preceded_by_set(text: str, s: int) -> bool:
    """True when the name at ``s`` is the argument of cmd's ``set`` (``set NAME``, ``set /p N``)."""
    return _SET_BEFORE.search(text[max(0, s - 64) : s]) is not None


def _assignment_edit(text: str, s: int, e: int) -> _Edit | None:
    n = len(text)
    env = _env_prefix(text, s)
    i = e
    quoted_name = False
    if env == 2:
        if i < n and text[i] == "}":
            i += 1
    elif i < n and text[i] in "\"'":
        # os.environ['NAME'] = ..., @{ "NAME" = ... }: the name carries its own closing quote.
        quoted_name = True
        i += 1
        if i < n and text[i] == "]":
            i += 1
    elif i < n and text[i] == "]" and s > 0 and text[s - 1] == "[":
        quoted_name = True  # os.environ[NAME] = ...
        i += 1
    k = _skip_spaces(text, i)
    if k >= n:
        return None
    if text[k] == "+" and k + 1 < n and text[k + 1] == "=":
        k += 1
    if text[k] != "=":
        return None
    v = k + 1
    spaced_before = k > i
    after_spaces = _skip_spaces(text, v)
    if quoted_name:
        if after_spaces < n and text[after_spaces] in "\"'":
            return _value_edit(text, after_spaces, single_only=True)
        if not spaced_before and after_spaces == v and v < n and text[v] != "=":
            return _value_edit(text, v, single_only=False)  # export "NAME"=value
        return None
    if not spaced_before and env == 0 and s > 0 and text[s - 1] in "\"'":
        return _enclosed_edit(text, v, text[s - 1], s)
    if env:
        # $env:NAME = "value" is the normal PowerShell spelling, spaces and all.
        return _value_edit(text, after_spaces, single_only=False, name_start=s, concat=True)
    if _preceded_by_set(text, s):
        # cmd stores everything after "=" (spaces included) and "set NAME = value" is common.
        return _cmd_set_edit(text, v)
    if spaced_before or after_spaces > v:
        # Generic "name = value" (config files, source code): only a quoted literal counts, so
        # prose and comparisons ("tokens = 3", "key == x") are left alone.
        if after_spaces < n and text[after_spaces] in "\"'":
            return _value_edit(text, after_spaces, single_only=True)
        return None
    return _value_edit(text, v, single_only=False, name_start=s)


def _pass_assignments(text: str, work: _Work) -> str:
    edits: list[_Edit] = []
    pos = 0
    search = _ASSIGN_RUN.search
    while True:
        match = search(text, pos)
        if match is None:
            break
        work.charge()
        start, end = match.span()
        pos = end
        edit = _assignment_edit(text, start, end)
        if edit is not None:
            edits.append(edit)
            pos = edit[1]
    return _splice(text, edits)


def _pass_set_env_calls(text: str, work: _Work) -> str:
    """Value argument of SetEnvironmentVariable / putenv / setdefault for a secret-looking name."""
    edits: list[_Edit] = []
    pos = 0
    while True:
        match = _SET_ENV_VAR.search(text, pos)
        if match is None:
            break
        work.charge()
        pos = match.end()
        if _ASSIGN_ANY.search(match.group(2)) is None:
            continue
        v = match.end()
        if v < len(text) and text[v] in "\"'":
            edit = _value_edit(text, v, single_only=True)
        else:
            arg = _ARG.match(text, v)
            edit = (v, arg.end(), REDACTED) if arg is not None else None
        if edit is not None and text[edit[0] : edit[1]] != REDACTED:
            edits.append(edit)
            pos = edit[1]
    return _splice(text, edits)


def _pass_secure_string(text: str, work: _Work) -> str:
    """The plaintext literal handed to PowerShell's ConvertTo-SecureString."""
    edits: list[_Edit] = []
    pos = 0
    while True:
        match = _SECURE_STRING.search(text, pos)
        if match is None:
            break
        work.charge()
        pos = match.end()
        edit = _value_edit(text, pos, single_only=True)
        if edit is not None:
            edits.append(edit)
            pos = edit[1]
    return _splice(text, edits)


def _pass_setx(text: str, work: _Work) -> str:
    edits: list[_Edit] = []
    pos = 0
    while True:
        match = _SETX.search(text, pos)
        if match is None:
            break
        work.charge()
        # Advance minimally: the name may itself be the next "setx".
        pos = match.start() + 4
        if _ASSIGN_ANY.search(match.group(2)) is None:
            continue
        edit = _value_edit(text, match.end(), single_only=False)
        if edit is not None:
            edits.append(edit)
            pos = edit[1]
    return _splice(text, edits)


def _pass_secret_flags(text: str, work: _Work) -> str:
    edits: list[_Edit] = []
    pos = 0
    n = len(text)
    while True:
        match = _SECRET_FLAG.search(text, pos)
        if match is None:
            break
        work.charge()
        v = match.end()
        pos = v
        if v < n and text[v] != "-":
            edit = _value_edit(text, v, single_only=False, name_start=match.start())
            if edit is not None:
                edits.append(edit)
                pos = edit[1]
    return _splice(text, edits)


def _json_value_edit(text: str, v: int) -> _Edit | None:
    """Edit for the value after ``"key":``; the value quotes may carry backslashes too."""
    n = len(text)
    opener = _JSON_OPEN.match(text, v)
    if opener is None:
        return None
    if opener.group(1) == "":
        return _value_edit(text, v, single_only=True)
    # \"value\": the content ends at the next identical escaped quote.
    token = opener.group(0)
    start = opener.end()
    close = text.find(token, start)
    if close < 0:
        return (start, n, REDACTED)  # unterminated: the rest may be the secret
    if close == start or text[start:close] == REDACTED:
        return None
    return (start, close, REDACTED)


def _pass_json_pairs(text: str, work: _Work) -> str:
    edits: list[_Edit] = []
    pos = 0
    while True:
        match = _JSON_PAIR.search(text, pos)
        if match is None:
            break
        work.charge()
        v = match.end()
        pos = v
        edit = _json_value_edit(text, v)
        if edit is not None:
            edits.append(edit)
            pos = edit[1]
    return _splice(text, edits)


def _redact_once(text: str, work: _Work) -> str:
    low = text.lower()
    if "-----begin " in low:
        changed = _pass_private_keys(text, work)
        if changed != text:
            text, low = changed, changed.lower()
    changed = _pass_tokens(text, low)
    if changed != text:
        text, low = changed, changed.lower()
    if _contains_any(low, ("environmentvariable", "putenv", "setdefault")):
        changed = _pass_set_env_calls(text, work)
        if changed != text:
            text, low = changed, changed.lower()
    if "securestring" in low:
        changed = _pass_secure_string(text, work)
        if changed != text:
            text, low = changed, changed.lower()
    if "setx" in low:
        changed = _pass_setx(text, work)
        if changed != text:
            text, low = changed, changed.lower()
    if _contains_any(low, _ASSIGN_WORD_LIST):
        changed = _pass_assignments(text, work)
        if changed != text:
            text, low = changed, changed.lower()
    if "--" in low:  # --pass and --pwd carry no assignment word, the others do; scan for all
        changed = _pass_secret_flags(text, work)
        if changed != text:
            text, low = changed, changed.lower()
    if _contains_any(low, _JSON_WORD_LIST):
        text = _pass_json_pairs(text, work)
    return text


def _redact_rounds(text: str, work: _Work) -> str:
    current = text
    for _ in range(_MAX_ROUNDS):
        following = _redact_once(current, work)
        if following == current:
            return current
        current = following
    return REDACTED


def _redact_head(text: str) -> str:
    """Fallback for a text that spent its budget: a redacted head plus a marker, or nothing."""
    head = text[:_FALLBACK_HEAD]
    cut = max(head.rfind("\n"), head.rfind(" "))
    if cut < len(head) - _FALLBACK_CUT_WINDOW:
        # No whitespace near the cut: it could fall inside a token and leave a fragment of it.
        return REDACTED
    # The head is short, so its own work is bounded by its length; it needs no budget.
    return _redact_rounds(head[:cut] + " " + REDACTED, _Work(1 << 60))


def _redact_str(text: str, work: _Work) -> str:
    if work.remaining <= 0:
        # An earlier string of the same record already spent the budget. Text that cannot
        # contain any trigger is still safe to keep; the rest is dropped.
        return REDACTED if _contains_any(text.lower(), _ANY_TRIGGER) else text
    try:
        return _redact_rounds(text, work)
    except _Overload:
        work.remaining = 0
        return _redact_head(text)


def redact_text(text: str) -> str:
    """Replace the secret parts of ``text`` with ``[REDACTED]`` and keep everything else.

    Never raises. If anything unexpected goes wrong, or the rounds do not converge, the whole
    text is replaced: losing a log line is better than leaking a key. A text so full of candidate
    assignments that it exhausts the work budget (tens of thousands) keeps only a redacted head.
    """
    try:
        if not isinstance(text, str):
            return redact_text(repr(text))
        return _redact_str(text, _Work(_ATTEMPTS_TEXT))
    except Exception:  # noqa: BLE001 - fail closed: this runs on the audit path and must not raise
        return REDACTED


# --------------------------------------------------------------------------------------------
# Structures
# --------------------------------------------------------------------------------------------


def _safe_repr(value: object) -> str:
    try:
        return repr(value)
    except Exception:  # noqa: BLE001 - a hostile __repr__ must not break redaction
        return f"<unrepresentable {type(value).__name__}>"


def _walk(
    value: object,
    depth: int,
    max_depth: int,
    budget: list[int],
    active: set[int],
    work: _Work,
    sensitive: bool,
) -> object:
    """Redacted copy of ``value``; ``sensitive`` means it is stored under a secret-looking key."""
    if depth > max_depth:
        return TRUNCATED
    budget[0] -= 1
    if budget[0] < 0:
        return TRUNCATED
    if isinstance(value, str):
        return REDACTED if sensitive else _redact_str(str.__str__(value), work)
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, dict | list | tuple):
        # The same container reached again while we are still inside it is a cycle: without
        # this a self-referencing list with two slots would fan out 2**max_depth times.
        ident = id(value)
        if ident in active:
            return TRUNCATED
        active.add(ident)
        try:
            if isinstance(value, dict):
                return _walk_dict(value, depth, max_depth, budget, active, work)
            # A list under a secret-looking key ("api_keys": [...]) is a list of secrets.
            items = [
                _walk(item, depth + 1, max_depth, budget, active, work, sensitive)
                for item in list(value)
            ]
            return tuple(items) if isinstance(value, tuple) else items
        finally:
            active.discard(ident)
    if sensitive:
        # bytes, bytearray, sets, SecretStr-like objects: repr() would print the secret.
        return REDACTED
    return _redact_str(_safe_repr(value), work)


def _unique_key(out: dict[object, object], key: object) -> object:
    """``key``, or ``key#2``, ``key#3``... when redaction made two different keys equal."""
    if key not in out or not isinstance(key, str):
        return key
    index = 2
    while f"{key}#{index}" in out:
        index += 1
    return f"{key}#{index}"


def _walk_dict(
    value: dict[object, object],
    depth: int,
    max_depth: int,
    budget: list[int],
    active: set[int],
    work: _Work,
) -> dict[object, object]:
    out: dict[object, object] = {}
    for key, item in list(value.items()):
        new_key: object
        sensitive = False
        if isinstance(key, str):
            new_key = _redact_str(str.__str__(key), work)
            sensitive = _SENSITIVE_KEY.search(key) is not None
        elif key is None or isinstance(key, bool | int | float):
            new_key = key
        else:
            new_key = _redact_str(_safe_repr(key), work)
        out[_unique_key(out, new_key)] = _walk(
            item, depth + 1, max_depth, budget, active, work, sensitive
        )
    return out


def redact_obj(obj: object, *, max_depth: int = 32) -> object:
    """A redacted copy of ``obj``; the input is never modified.

    dict, list and tuple are walked, strings go through :func:`redact_text`, other JSON scalars
    pass through, anything else becomes ``repr()`` and is redacted as text. Under a key that looks
    secret (key, token, secret, password, passwd, authorization, credential) every string is
    replaced outright, also the strings of a list stored there, and so is any value that is not a
    number, bool, None or container (bytes and the like would leak through their repr).
    Numbers, booleans and None are kept, and a dict stored under such a key is walked normally
    (its own keys decide). Two keys that redaction makes equal get a ``#2``, ``#3`` suffix so no
    entry is lost. Anything deeper than ``max_depth`` (capped at 100), any cycle, and any
    structure beyond 200000 nodes becomes ``"[TRUNCATED]"``.

    The whole structure shares one work budget (see the module docstring): once it is spent,
    strings that contain any trigger word are replaced by ``"[REDACTED]"``.

    Never raises: on an unexpected error the whole value becomes ``"[REDACTED]"``.
    """
    try:
        return _walk(
            obj,
            0,
            min(max_depth, _HARD_DEPTH),
            [_MAX_NODES],
            set(),
            _Work(_ATTEMPTS_OBJ),
            False,
        )
    except Exception:  # noqa: BLE001 - fail closed: this runs on the audit path and must not raise
        return REDACTED
