"""The single way content reaches an LLM backend (PROJECT_SPEC.md §9.2, §9.6, §11).

A field whitelist first, redaction second. Only structured fields of the normalized actions leave:
the tool name, per action the program, subcommand, flags, words, paths (shown relative to
``<project>`` or ``~``, with their access and whether they are inside the project), hosts, risk
tags, wrappers and the short reasons the rules could not decide; whether the working directory is
inside the project; the taint bits and the names of the source tools; the task intent (already
stripped of IDE blocks and pasted text, redacted and cut when it was stored). Never a file's
content, a tool's output, the working directory or a hook field the list does not name. A path
whose key came from expanding an environment variable is shown in its unexpanded form (the
daemon's environment holds secrets, the API key among them). ``redact_obj`` runs over the whole
payload.

A Bash or PowerShell call also carries its whole command text (``command``, spec revision 30),
with the home directory written as ``~``. A script can read its own text (Claude Code leaves it in
``$__claudeCodeScript`` and ``$BASH_EXECUTION_STRING``), so a comment, a constant that is only
printed or the text of a condition can become a path or code: the actions alone hid that from the
model (review of revision 29, O-7).

Refused (nothing is sent; the audit fails to ``on_failure``):

* too much to show whole: more than ``MAX_ACTIONS`` actions, an action with more than
  ``MAX_WORDS`` words, ``MAX_PATHS`` paths or ``MAX_DOMAINS`` hosts, a word longer than
  ``MAX_WORD_CHARS``, a program name longer than ``MAX_NAME_CHARS`` (in PowerShell the name can
  be an expression: ``& $(...; 'Get-Date')``), a command text longer than ``MAX_COMMAND_CHARS``,
  a payload above ``MAX_CONTENT_CHARS``. A cut view could hide the part that matters behind
  padding, and a model can only allow what it was shown;
* a word, path or command text with a control or format character other than tab, CR and LF (bidi
  overrides, zero-width characters, terminal escapes, NUL): such text reads differently from what
  runs;
* a command text that the redactor would change: its patterns can swallow a whole span (a private
  key block from BEGIN to END), and what they swallow the model would not see; a command that
  carries a secret is the user's to decide about;
* a shell call without its command text;
* a secret that only shows across words (``--password X``, ``-Password 'X'``, ``curl -u u:pw``):
  redacting the command's words one by one would miss it, so the words are redacted as one line
  as well, and a difference means the command carries a secret (the user decides about that);
* a serialized request that the redactor would still change (a secret formed across fields):
  the redactor works on shell text, so its edits on JSON are not trusted to keep the structure;
* a request that contains the value of a secret-looking environment variable (``secrets``), as
  written or as the serialization writes it (``"``, ``\\`` and control characters escaped: spec
  revision 36, R35-1).

The system prompt comes from ``audit.prompt`` and holds no user data.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

from boundkeep.audit.backends.base import _SEAL, GatedRequest
from boundkeep.audit.prompt import system_prompt
from boundkeep.normalize.event import SHELL_TOOLS
from boundkeep.normalize.model import Action, PathRef
from boundkeep.normalize.paths import key_of_home
from boundkeep.redact import redact_obj, redact_text
from boundkeep.session.facts import SessionFacts

SCHEMA_TAG: Final = "boundkeep.audit-request/2"
MAX_ACTIONS: Final = 8
MAX_WORDS: Final = 32
MAX_WORD_CHARS: Final = 400
MAX_PATHS: Final = 16
MAX_DOMAINS: Final = 16
MAX_FLAGS: Final = 32
MAX_UNCLEAR: Final = 6
MAX_UNCLEAR_CHARS: Final = 120
MAX_NAME_CHARS: Final = 128
MAX_INTENT_CHARS: Final = 2000
MAX_COMMAND_CHARS: Final = 4000
MAX_CONTENT_CHARS: Final = 16_000
MIN_SECRET_CHARS: Final = 8  # shorter values of secret-looking variables are not looked for
_ALLOWED_CONTROLS: Final = frozenset("\t\r\n")
_EXPANDED: Final = "variable-expanded"  # normalize.paths: a variable in the word was expanded
# Where a written home directory may end and begin (spec revisions 31, 32): anything else continues
# a name or a path ("<home>x", "<home>.CORP", "<home>{2,3}", "./c/Users/...", "/x/home/me").
# In a command text, or a word the rules did not read as one path (code, a list, a glued option):
_ENDS: Final = re.escape("/'\"`;|&()<>,:}")
_TEXT_AFTER_SLASH: Final = r"(?=\Z|[\s" + _ENDS + "])"  # "\" escapes in Bash: "/home/me\2"
# A single trailing dot before an end is the home itself to Win32 ("C:\Users\me.\notes.txt").
_TEXT_AFTER_DRIVE: Final = r"(?=\.?(?:\Z|[\s\\" + _ENDS + "]))"
# In a word the rules read as one path: the word is split already, so a space, a quote or a bracket
# is part of the name. "," and ";" end it, and so does ":" (spec revision 34, R33-1): the rules
# record a list after an option as one path ("-Wl,-rpath,<home>,-z,now", "-DX=<home>;/opt").
# No Windows name holds a colon: "C:\Users\me:s" is a stream of the home itself.
_PATH_AFTER_DRIVE: Final = r"(?=\.?(?:\Z|[\\/:,;]))"
_PATH_AFTER_WINDOWS: Final = r"(?=\Z|[\\/:,;])"  # "/c/Users/me\x" is under the home (Git Bash too)
_PATH_AFTER_POSIX: Final = r"(?=\Z|[/:,;])"
# An option glued to it is a beginning and is kept ("-isystem/home/me", "/FoC:\Users\me\build\"),
# if the option itself begins a word.
_OPTION_START: Final = r"(?<![\w./\\~-])"
_BEFORE_DRIVE: Final = r"(?:(?P<drive_option>" + _OPTION_START + r"(?:--?|/)[A-Za-z]+)|(?<!\w))"
_BEFORE_SLASH: Final = r"(?:(?P<slash_option>" + _OPTION_START + r"--?[A-Za-z]+)|(?<![\w./\\~]))"
# A UNC form after ".", "\", "/", "~" or a drive's colon is another path ("C:\\server\..." is a
# folder on C:, ".\\server\..." a relative path): spec revision 34, R33-3. Another colon is a
# beginning ("FileSystem::\\server\..."), and a glued option may end with one ("/OUT:\\server\...",
# "/F:"): spec revision 35, R34-1.
_DRIVE_COLON: Final = r"(?<!(?<!\w)[A-Za-z]:)"
_BEFORE_UNC: Final = (
    r"(?:(?P<unc_option>"
    + _OPTION_START
    + r"(?:--?|/)[A-Za-z]+:?)|(?<![\w./\\~])"
    + _DRIVE_COLON
    + ")"
)
# An option before a path the rules read in the same word ("--directory=<path>", "-isystem<path>",
# "-Path:<path>"): the path keeps the boundaries of a path (spec revision 33, R32-2).
_OPTION_PREFIX: Final = re.compile(r"(?:--?|/)[A-Za-z][A-Za-z0-9_-]*[=:]?")
_OPTION_GROUPS: Final = ("drive_option", "unc_option", "slash_option")


@dataclass(frozen=True, slots=True)
class GateResult:
    """``request`` to send, or ``refused`` (why nothing may be sent); ``payload`` is what the
    request carries (redacted), for the audit log and for tests."""

    request: GatedRequest | None
    refused: str | None
    payload: dict[str, Any] | None


class _Refused(Exception):
    pass


def _clean_name(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return "".join(ch if ch.isprintable() else "?" for ch in value[:MAX_NAME_CHARS])


def _checked_text(value: str, what: str, limit: int = MAX_WORD_CHARS) -> str:
    if len(value) > limit:
        raise _Refused(f"{what} is longer than {limit} characters")
    if any(not ch.isprintable() and ch not in _ALLOWED_CONTROLS for ch in value):
        raise _Refused(f"{what} holds a control or format character")
    return value


def _caseless(text: str) -> str:
    """``text`` as a pattern that ignores the case of single characters only: the long s (U+017F)
    is not ``s`` and the Kelvin sign is not ``k`` (a name that only folding makes equal is another
    name)."""
    parts = []
    for ch in text:
        variants = sorted({v for v in (ch, ch.lower(), ch.upper()) if len(v) == 1})
        if len(variants) > 1:
            parts.append("[" + "".join(re.escape(v) for v in variants) + "]")
        else:
            parts.append(re.escape(ch))
    return "".join(parts)


def _home_forms(home: str) -> list[tuple[str, bool]]:
    """How a command may write the home directory, longest first: (text, a Windows form that
    starts with a drive or with backslashes, where "\\" ends the name).

    ``C:\\Users\\me`` is also written ``C:/Users/me``, ``C:\\\\Users\\\\me`` (escaped in a string),
    ``/c/Users/me`` (Git Bash, MSYS), ``/mnt/c/Users/me`` (WSL) and ``/cygdrive/c/Users/me``
    (Cygwin). A UNC home ``\\\\server\\share\\me`` also escaped and as ``//server/share/me`` (spec
    revision 33). Any other home only as it is, with either slash."""
    home = home.rstrip("\\/")
    drive = re.fullmatch(r"([A-Za-z]):[\\/]+(.+)", home)
    unc = re.fullmatch(r"\\\\([^\\/].*)", home)
    if unc is not None:
        parts = [p for p in re.split(r"[\\/]+", unc.group(1)) if p]
        forms = [
            ("\\\\" + "\\".join(parts), True),
            ("\\\\\\\\" + "\\\\".join(parts), True),
            ("//" + "/".join(parts), False),
        ]
    elif drive is None:
        forms = [(home, False), (home.replace("\\", "/"), False)]
    else:
        letter = drive.group(1)
        parts = [p for p in re.split(r"[\\/]+", drive.group(2)) if p]
        posix = "/".join(parts)
        lower = letter.lower()
        forms = [
            (letter + ":\\" + "\\".join(parts), True),
            (letter + ":/" + posix, True),
            (letter + ":\\\\" + "\\\\".join(parts), True),
            (f"/{lower}/{posix}", False),
            (f"/mnt/{lower}/{posix}", False),
            (f"/cygdrive/{lower}/{posix}", False),
        ]
    kept = [f for f in dict.fromkeys(forms) if len(f[0]) > 3]
    return sorted(kept, key=lambda f: len(f[0]), reverse=True)


def _home_pattern(home: str, *, path: bool) -> re.Pattern[str] | None:
    """The forms of ``home`` with the boundaries of a command text, or of a word that is a path.
    A home with drive or backslashed forms is a Windows home: in a path, "\\" is a separator after
    its slash forms too. Backslashed UNC forms begin like a drive form but not after ".", "\\",
    "/", "~" or a drive's colon (spec revisions 34, 35)."""
    forms = _home_forms(home)
    windows = [text for text, drive in forms if drive]
    drives = [_caseless(text) for text in windows if not text.startswith("\\\\")]
    uncs = [_caseless(text) for text in windows if text.startswith("\\\\")]
    slashes = [_caseless(text) for text, drive in forms if not drive]
    after_windows = _PATH_AFTER_DRIVE if path else _TEXT_AFTER_DRIVE
    parts = []
    if drives:
        parts.append(_BEFORE_DRIVE + "(?:" + "|".join(drives) + ")" + after_windows)
    if uncs:
        parts.append(_BEFORE_UNC + "(?:" + "|".join(uncs) + ")" + after_windows)
    if slashes:
        if not path:
            after = _TEXT_AFTER_SLASH
        else:
            after = _PATH_AFTER_WINDOWS if windows else _PATH_AFTER_POSIX
        parts.append(_BEFORE_SLASH + "(?:" + "|".join(slashes) + ")" + after)
    return re.compile("|".join(parts)) if parts else None


def _option_of(match: re.Match[str]) -> str:
    """The option glued before a written home ("-isystem"), or "" (a POSIX home has no drive or
    UNC forms, so those groups may be missing)."""
    groups = match.groupdict()
    return next((groups[name] for name in _OPTION_GROUPS if groups.get(name)), "")


def _tilde(match: re.Match[str]) -> str:
    return _option_of(match) + "~"


class _Places:
    """Shows paths and words relative to the project and the home directory."""

    def __init__(self, home: str | None, project: str | None) -> None:
        self._home_key = key_of_home(home) if home else ""
        self._project_key = project or ""
        self._text_re = _home_pattern(home, path=False) if home else None
        self._path_re = _home_pattern(home, path=True) if home else None

    def key(self, key: str) -> str:
        project = self._project_key.rstrip("/")
        if project and (key == project or key.startswith(project + "/")):
            return "<project>" + key[len(project) :]
        home = self._home_key.rstrip("/")
        if home and (key == home or key.startswith(home + "/")):
            return "~" + key[len(home) :]
        return key

    def word(self, word: str, *, path: bool = False) -> str:
        """A command word or text with the home directory written as ``~`` (spec revisions 31-35).

        Best effort: the forms of ``_home_forms`` in any case, only where a name may end after
        them (review of revision 30, R30-1). ``path``: the word is one path, so only a separator
        or its end ends the name (review of revision 31, R31-2). The match is made on the text
        itself: positions found in a lowercased copy are off after U+0130, whose lowercase is two
        characters, and the text after the home directory was cut instead (R30-4)."""
        pattern = self._path_re if path else self._text_re
        return pattern.sub(_tilde, word) if pattern is not None else word

    def home_begins_before(self, word: str, cut: int) -> bool:
        """A written home in ``word`` (with the boundaries of a text) begins before ``cut``, or
        ``cut`` falls inside the option glued to it: the text before ``cut`` is then part of a path
        or of that option (spec revision 34, R33-2; revision 35, R34-3): "/c" in "/c/Users/me/x",
        "-C:" in "-C:\\Users\\me\\x", "/root" for the home /root, "-isyst" in "-isystem/home/me".

        The boundaries of a path would find more only where a slash form of a Windows or UNC home
        is followed by "\\", which ends it in a path only (spec revision 36, R35-3): a "/" option
        that is part of its first part ("/cyg" in "/cygdrive/c/Users/me\\x"), or a cut inside a
        "-" option glued to it ("-isyst" in "-isystem/c/Users/me\\x"). That home is kept as
        written either way: the path text after the cut holds no written home there, and a text
        does not end it at "\\"."""
        pattern = self._text_re
        if pattern is None:
            return False
        for m in pattern.finditer(word):
            begins = m.start() + len(_option_of(m))
            if m.start() < cut and begins != cut:
                return True
        return False


def _word(word: str, raws: Sequence[str], places: _Places) -> str:
    """A command word or flag as it is sent. ``raws``: the action's path texts, longest first.
    The whole word is one of them, or an option and then one of them: that path ends only where a
    path ends (spec revisions 32 to 35). Anything else is shown like the command text.

    An option is cut off only if no written home begins inside it and the cut is not inside an
    option glued to one, and a "/" option only before a path that does not begin with "/"
    ("/srv/home/me" is another path): spec revisions 34 (R33-2) and 35 (R34-3)."""
    for raw in raws:
        if word == raw:
            return places.word(word, path=True)
        if not raw or not word.endswith(raw):
            continue
        cut = len(word) - len(raw)
        option = word[:cut]
        if (
            _OPTION_PREFIX.fullmatch(option)
            and not (option.startswith("/") and raw.startswith("/"))
            and not places.home_begins_before(word, cut)
        ):
            return option + places.word(raw, path=True)
    return places.word(word)


def _path(ref: PathRef, places: _Places) -> dict[str, Any]:
    raw = _checked_text(ref.raw, "a path")
    key = _checked_text(ref.key, "a path")
    # ``$TOKEN/x`` was expanded with the daemon's environment: its key carries the value
    shown = places.word(raw, path=True) if _EXPANDED in ref.reasons else places.key(key)
    return {"path": shown, "access": ref.access, "inside_project": ref.inside_project}


def _secret_across_words(words: Sequence[str]) -> bool:
    """The words, redacted as one command line, hide more than redacted one by one.

    Each word is shell-quoted on both sides, so a pattern that runs to the end of a line (an
    ``Authorization:`` header value) ends at its word's closing quote, as in a real command."""
    if len(words) < 2:
        return False
    quoted = [shlex.quote(w) for w in words]
    return redact_text(" ".join(quoted)) != " ".join(redact_text(q) for q in quoted)


def _carries(folded: str, secret: str) -> bool:
    """The casefolded serialized request ``folded`` holds ``secret``, as written or as the
    serialization writes it: ``json.dumps`` escapes ``"``, ``\\`` and control characters, so a
    value with one of them is not there as written (spec revision 36, R35-1)."""
    if len(secret) < MIN_SECRET_CHARS:
        return False
    escaped = json.dumps(secret, ensure_ascii=False)[1:-1]
    return secret.casefold() in folded or escaped.casefold() in folded


def _command(actions: Sequence[Action], places: _Places) -> str:
    """The command text of a shell call as it is sent: whole, the home directory as ``~`` (spec
    revision 30). Every action of the call carries the same text (``Action.command_text``)."""
    texts = {a.command_text for a in actions}
    if len(texts) != 1:
        raise _Refused("the command text of a shell call is missing")
    (command,) = texts
    if not isinstance(command, str):
        raise _Refused("the command text of a shell call is missing")
    shown = places.word(_checked_text(command, "the command text", MAX_COMMAND_CHARS))
    if redact_text(shown) != shown:
        raise _Refused("the command text carries text that looks like a secret")
    return shown


def _action(action: Action, places: _Places) -> dict[str, Any]:
    if len(action.args) > MAX_WORDS:
        raise _Refused(f"a command has more than {MAX_WORDS} words")
    if _secret_across_words((*((action.program,) if action.program else ()), *action.args)):
        raise _Refused("a command carries a secret across its words (a password or token flag)")
    if len(action.paths) > MAX_PATHS:
        raise _Refused(f"a command touches more than {MAX_PATHS} paths")
    if len(action.domains) > MAX_DOMAINS:
        raise _Refused(f"a command names more than {MAX_DOMAINS} hosts")
    if len(action.flags) > MAX_FLAGS:
        raise _Refused(f"a command has more than {MAX_FLAGS} flags")
    if action.program and len(action.program) > MAX_NAME_CHARS:
        raise _Refused(f"a program name is longer than {MAX_NAME_CHARS} characters")
    out: dict[str, Any] = {}
    program = _clean_name(action.program)
    if program:
        out["program"] = program
    subcommand = _clean_name(action.subcommand)
    if subcommand:
        out["subcommand"] = subcommand
    raws = sorted({ref.raw for ref in action.paths}, key=len, reverse=True)
    if action.flags:
        # a flag may carry a glued home directory ("-I/home/me/inc"): R31-5, spec revision 32
        out["flags"] = [_word(_checked_text(f, "a flag"), raws, places) for f in action.flags]
    if action.args:
        out["args"] = [_word(_checked_text(a, "a command word"), raws, places) for a in action.args]
    if action.paths:
        out["paths"] = [_path(ref, places) for ref in action.paths]
    if action.domains:
        out["domains"] = [_checked_text(d, "a host") for d in action.domains]
    out["network"] = action.network
    out["risk_tags"] = list(action.risk_tags)
    if action.wrappers:
        out["wrappers"] = [w for w in (_clean_name(x) for x in action.wrappers) if w]
    unclear = [
        "".join(ch if ch.isprintable() else "?" for ch in reason[:MAX_UNCLEAR_CHARS])
        for reason in action.gray_reasons[:MAX_UNCLEAR]
    ]
    if unclear:
        out["unclear"] = unclear
    if action.dynamic_args:
        out["dynamic_args"] = True
    mcp_server = _clean_name(action.mcp_server)
    if mcp_server:
        out["mcp_server"] = mcp_server
    mcp_tool = _clean_name(action.mcp_tool)
    if mcp_tool:
        out["mcp_tool"] = mcp_tool
    return out


def gate(
    actions: Sequence[Action],
    *,
    tool: object,
    facts: SessionFacts,
    send_task_intent: bool,
    intent_prompts: int,
    home: str | None,
    secrets: Sequence[str] = (),
) -> GateResult:
    """The request for one gray tool call, or why it must not be sent. Never raises.

    ``secrets``: values that must never be sent (the auditor passes the values of the daemon's
    secret-looking environment variables, the API key's among them); compared without case, since
    Windows path keys are casefolded, as written and as the serialization escapes them."""
    try:
        return _gate(
            actions,
            tool=tool,
            facts=facts,
            send_task_intent=send_task_intent,
            intent_prompts=intent_prompts,
            home=home,
            secrets=secrets,
        )
    except _Refused as exc:
        return GateResult(None, str(exc), None)
    except Exception as exc:  # noqa: BLE001 - nothing leaves when the gate itself fails
        return GateResult(None, f"the send gate failed ({type(exc).__name__})", None)


def _gate(
    actions: Sequence[Action],
    *,
    tool: object,
    facts: SessionFacts,
    send_task_intent: bool,
    intent_prompts: int,
    home: str | None,
    secrets: Sequence[str],
) -> GateResult:
    if not actions:
        raise _Refused("there is no action to show")
    if len(actions) > MAX_ACTIONS:
        raise _Refused(f"the call has more than {MAX_ACTIONS} commands")
    project = next((a.project for a in actions if a.project), None)
    places = _Places(home, project)
    intent: list[str] | None = None
    if send_task_intent:
        intent = [
            text[:MAX_INTENT_CHARS]
            for text in facts.intents[-max(1, intent_prompts) :]
            if isinstance(text, str) and text
        ]
    shown = [_action(action, places) for action in actions]
    payload: dict[str, Any] = {
        "schema": SCHEMA_TAG,
        "task_intent": intent,
        "tool": _clean_name(tool) or "?",
    }
    # only shell actions carry a command text; either sign is enough
    shell = (isinstance(tool, str) and tool in SHELL_TOOLS) or any(
        a.command_text is not None for a in actions
    )
    if shell:
        payload["command"] = _command(actions, places)
        if redact_obj(shown) != shown:
            # A word the redactor changes is in the command text as well, where the text's own
            # redaction need not find it (its patterns read words and lines differently): the
            # command carries a secret, and the text must not take it along in clear
            raise _Refused("a command carries text that looks like a secret")
    payload |= {
        "actions": shown,
        "cwd_inside_project": True if project else None,
        "tainted": facts.tainted,
        "taint_sources": [s for s in (_clean_name(x) for x in facts.sources) if s],
        "read_untrusted": facts.read_untrusted,
    }
    redacted = redact_obj(payload)
    if not isinstance(redacted, dict):
        raise _Refused("the payload could not be redacted")
    # spaced separators: the redactor's patterns stop at whitespace, so a URL in one field and an
    # ``@`` in the next do not read as ``://user:pw@`` (and refuse the request) for lack of one
    content = json.dumps(redacted, ensure_ascii=False, separators=(", ", ": "))
    if len(content) > MAX_CONTENT_CHARS:
        raise _Refused(f"the request would be longer than {MAX_CONTENT_CHARS} characters")
    if redact_text(content) != content:
        # Something still looks like a secret once the fields are put together. The redactor's
        # patterns are for shell text: on JSON an edit can run across fields and drop whole
        # actions while the result still parses (self-review of M3a), so nothing is sent.
        raise _Refused("the request would carry text that looks like a secret across its fields")
    folded = content.casefold()
    if any(_carries(folded, s) for s in secrets):
        raise _Refused("the request would carry the value of a secret environment variable")
    prompt = system_prompt()
    request = GatedRequest(
        content=content,
        system_prompt=prompt.text,
        prompt_hash=prompt.sha256,
        prompt_version=prompt.version,
        seal=_SEAL,
    )
    return GateResult(request, None, redacted)
