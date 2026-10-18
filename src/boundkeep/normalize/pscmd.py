"""PowerShell AST digest (the helper's JSON) -> the SimpleCmd / Word / Redirect structures of Bash.

``build(reply, source=text)`` turns the reply of ``pshelper.ps1`` (docs/m1b-design.md section 2: one
digest of every ``CommandAst`` of the script, plus the compound / dynamic constructs and parse
errors it saw) into a ``BashResult``, so ONE set of rules judges both shells. The conventions the
rest of the normalizer relies on (see also ``psprograms``):

* ``argv[0]`` is the CANONICAL cmdlet name (aliases restored, ``rm`` -> ``Remove-Item``) or the
  name of an external program (``git.exe`` -> ``git``); parameters follow in source order as
  ``-CanonicalName`` words (``-Rec`` -> ``-Recurse``; ``-Path:x`` -> ``-Path``, ``x``); a value
  that starts with ``-`` is marked ``quoted=True`` so it can never pass for a parameter;
* a literal is a plain Word; ``$var`` / an expandable string is ``expands=True`` with its text kept
  (``$env:USERPROFILE\\.ssh``): the path layer resolves what it knows; ``Word.glob`` is set for
  ``* ? [`` unless the value belongs to ``-LiteralPath``; an element the helper could not read
  (parenthesised expression, script block, member access, ...) becomes ``$(<text>)`` with
  ``expands=True``, which every layer below treats as unknowable;
* anything not understood is a gray reason of the LINE (``BashResult.gray``: the digest has no
  per-command gray); reasons that mean "runs code we cannot see" are also in ``exec_reasons``.

``build`` never raises and works with bounded effort: replies that are not the documented shape,
hostile strings (lone surrogates, NUL) and oversized replies (more than ``MAX_COMMANDS`` commands
or ``MAX_ELEMENTS`` elements) degrade to gray.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from boundkeep.normalize import psaliases, psprograms
from boundkeep.normalize.model import BashResult, Redirect, SimpleCmd, Word
from boundkeep.normalize.programs import peel_runner

__all__ = ["MAX_COMMANDS", "MAX_ELEMENTS", "build"]

MAX_COMMANDS = 4000
MAX_ELEMENTS = 20000
MAX_STRING = 1 << 16  # one value / name / text of the digest
MAX_DEPTH = 12  # nesting of arrays and parameter arguments
MAX_REASONS = 64
_MAX_RAW = 512
_MAX_TAG = 64
_REDIRECT_CHARS = frozenset("0123456789*<>&")
_BAREISH = ("bare", "single", "double")
_LITERAL_PARAMS = frozenset({"-literalpath", "-pspath"})
_DYNAMIC_PREFIX = "$("
_ARRAY_SEP = Word(",")  # between the elements of an array argument of a cmdlet
# Built-in FUNCTIONS (not aliases, not cmdlets) that are Set-Location with a fixed argument: the
# helper reports the whole token (``cd..``, ``cd\``) as the command name. Mapped to
# ``Set-Location <arg>`` so the working directory is tracked exactly like ``cd ..``.
_CD_FUNCTIONS = {"cd..": "..", "cd\\": "\\"}


class _TooLarge(Exception):
    """The reply is bigger than the budget (commands, elements or one string)."""


@dataclass(slots=True)
class _State:
    source: str
    cmds: list[SimpleCmd] = field(default_factory=list)
    gray: dict[str, None] = field(default_factory=dict)
    exec_: dict[str, None] = field(default_factory=dict)
    elements: int = 0
    dynamic_kinds: frozenset[str] = frozenset()
    shadowed: set[str] = field(default_factory=set)  # names the line redefined (Set-Alias, ...)
    shadow_all: bool = False  # a redefinition with an unknowable name: every alias is suspect

    def add_gray(self, reason: str) -> None:
        if len(self.gray) < MAX_REASONS:
            self.gray.setdefault(reason, None)

    def add_exec(self, reason: str) -> None:
        """A reason the line runs code we cannot see: gray as well."""
        self.add_gray(reason)
        if len(self.exec_) < MAX_REASONS:
            self.exec_.setdefault(reason, None)

    def tick(self) -> None:
        self.elements += 1
        if self.elements > MAX_ELEMENTS:
            raise _TooLarge


def _tag(value: object) -> str:
    """A short, printable form of an AST type name for a gray reason."""
    if not isinstance(value, str):
        return "?"
    text = value
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in text[:_MAX_TAG]) or "?"


def _str(value: object, st: _State) -> str:
    """A string of the digest, bounded and safe to hand on (no lone surrogates, no NUL)."""
    if not isinstance(value, str):
        st.add_gray("ps-internal-error")
        return ""
    if len(value) > MAX_STRING:
        raise _TooLarge
    if value.isascii() and "\x00" not in value:
        return value
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        st.add_gray("ps-invalid-text")
        value = "".join("�" if "\ud800" <= c <= "\udfff" else c for c in value)
    if "\x00" in value:
        st.add_gray("ps-invalid-text")
        value = value.replace("\x00", "�")
    return value


def _glob(text: str) -> bool:
    return "*" in text or "?" in text or "[" in text


def _word(text: str, *, expands: bool = False, glob: bool = False, quoted: bool = False) -> Word:
    """A value word. A value that starts with ``-`` is quoted by convention (never a parameter)."""
    return Word(text, expands, glob, quoted or text.startswith("-"))


def _dynamic_word(text: str) -> Word:
    """A value we cannot read: ``$(<text>)``, dynamic for the path layer and ``_dynamic``."""
    return Word(_DYNAMIC_PREFIX + text + ")", expands=True)


def _strip_expandable(text: str) -> str:
    """Remove the quotes of an expandable string if the helper kept them (``"x"``, ``@"x"@``)."""
    if len(text) >= 4 and text.startswith('@"') and text.endswith('"@'):
        return text[2:-2].strip("\r\n")
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    return text


def _var_text(name: str, *, splat: bool) -> str:
    plain = all(c.isalnum() or c in "_:?" for c in name) and bool(name)
    body = name if plain else "{" + name + "}"
    return ("@" if splat else "$") + body


def _convert(e: object, st: _State, depth: int = 0, *, sep: bool = False) -> list[Word]:
    """The Words of one command element.

    An array becomes several words; with ``sep`` (cmdlet arguments) they are joined by the
    separator word ``,`` so ``psprograms`` still sees ONE argument (``Copy-Item a,b d``).
    """
    st.tick()
    if depth > MAX_DEPTH or not isinstance(e, Mapping):
        st.add_gray("ps-dynamic-value:Unreadable")
        return [_dynamic_word("unreadable")]
    kind_t = e.get("t")
    if kind_t == "str":
        text = _str(e.get("v"), st)
        quote = e.get("kind", "bare")
        if "`" in text:
            st.add_gray("ps-backtick")
        if text == "--%" and quote == "bare":
            st.add_gray("ps-stop-parsing")
        return [_word(text, glob=_glob(text), quoted=quote != "bare")]
    if kind_t == "expstr":
        text = _strip_expandable(_str(e.get("v"), st))
        if e.get("subexpr") is True or "$(" in text:
            st.add_gray("ps-subexpression")
        if "`" in text:
            st.add_gray("ps-backtick")
        return [_word(text, expands=True, glob=_glob(text))]
    if kind_t == "var":
        name = _str(e.get("name"), st)
        if e.get("splat") is True:
            # ``@paths`` hands over parameters AND values we cannot see: dynamic like ``$(...)``.
            st.add_gray("ps-dynamic-value:Splat")
            return [_dynamic_word(_var_text(name, splat=True))]
        return [_word(_var_text(name, splat=False), expands=True)]
    if kind_t == "num":
        return [_word(_str(e.get("v"), st))]
    if kind_t == "array":
        items = e.get("items")
        if not isinstance(items, list):
            st.add_gray("ps-internal-error")
            return [_dynamic_word("array")]
        out: list[Word] = []
        for item in items:
            if sep and out:
                out.append(_ARRAY_SEP)
            out.extend(_convert(item, st, depth + 1, sep=sep))
        return out
    if kind_t == "other":
        st.add_gray(f"ps-dynamic-value:{_tag(e.get('ast'))}")
        return [_dynamic_word(_str(e.get("text"), st))]
    st.add_gray("ps-dynamic-value:Unknown")
    return [_dynamic_word("unknown")]


# ---------------------------------------------------------------------------------------------
# Names and parameters
# ---------------------------------------------------------------------------------------------


def _canonical_command(name: str) -> str | None:
    try:
        answer = psaliases.canonical_command(name)
    except Exception:  # noqa: BLE001 - a lookup that raises must degrade to "not a known name"
        return None
    return answer if isinstance(answer, str) and answer else None


def _canonical_param(cmdlet: str, token: str) -> str | None:
    """The canonical ``-Name`` for a typed parameter, or None (unknown or ambiguous)."""
    try:
        answer = psaliases.canonical_param(cmdlet, token)
    except Exception:  # noqa: BLE001 - a lookup that raises must degrade to "unresolved"
        return None
    if not isinstance(answer, str) or not answer:
        return None
    return answer if answer.startswith("-") else "-" + answer


def _strip_exe(text: str) -> str:
    if not ("/" in text or "\\" in text) and text.lower().endswith(".exe") and len(text) > 4:
        return text[:-4]
    return text


def _program(name: object, st: _State) -> tuple[Word, str | None, bool]:
    """(the program word, canonical cmdlet name or None, the name is dynamic).

    ``psaliases.canonical_command`` decides what a name is: an alias or cmdlet comes back as the
    canonical cmdlet name; a path or ``x.exe`` comes back unchanged (an external program); an
    unknown bare name is None (an unknown cmdlet when it looks like ``Verb-Noun``, else an
    external program such as ``git``).
    """
    if not isinstance(name, Mapping):
        st.add_gray("ps-internal-error")
        st.add_exec("ps-dynamic-command-name")
        return _dynamic_word("unknown command"), None, True
    kind = name.get("kind")
    text = _str(name.get("v"), st)
    quoted = kind != "bare"
    if kind not in _BAREISH:
        st.add_exec("ps-dynamic-command-name")
        if kind == "variable":
            return Word(_var_text(text.lstrip("$"), splat=False), expands=True), None, True
        return _dynamic_word(text), None, True
    if "`" in text:
        st.add_gray("ps-backtick")
    low = text.lower()
    canon = "Set-Location" if low in _CD_FUNCTIONS else _canonical_command(text)
    external = canon is None or "/" in canon or "\\" in canon or canon.lower().endswith(".exe")
    if low in st.shadowed or (
        st.shadow_all and not external and canon is not None and canon.lower() != low
    ):
        # An alias the line redefined (or may have): the name no longer means what the tables say.
        st.add_exec("ps-alias-shadowed")
        return _dynamic_word(text), None, True
    if canon is not None and not external:
        return Word(canon, quoted=quoted), canon, False
    shown = text if canon is None else canon
    if psprograms.dynamic_name(shown):
        st.add_exec("ps-dynamic-command-name")
        return _dynamic_word(text), None, True
    if canon is None and text.isascii() and text.isalpha():
        # PowerShell runs `Content x` as `Get-Content x` when nothing else has that name.
        implicit = _canonical_command("Get-" + text)
        if (
            implicit is not None
            and "-" in implicit
            and "\\" not in implicit
            and "." not in implicit
        ):
            st.add_gray("ps-implicit-get-verb")
            if st.shadow_all:
                st.add_exec("ps-alias-shadowed")
                return _dynamic_word(text), None, True
            return Word(implicit, quoted=quoted), implicit, False
    if canon is None and psprograms.is_cmdlet_name(text):
        return Word(text, quoted=quoted), text, False
    return Word(_strip_exe(shown), quoted=quoted), None, False


def _fd_of(op: str) -> str | None:
    head = op[:1]
    if head.isdigit():
        return head
    return "*" if head == "*" else "1" if ">" in op else None


def _redirects(c: Mapping[str, Any], st: _State) -> list[Redirect]:
    raw = c.get("redirects", [])
    if not isinstance(raw, list):
        st.add_gray("ps-internal-error")
        return []
    out: list[Redirect] = []
    for r in raw:
        st.tick()
        if not isinstance(r, Mapping):
            st.add_gray("ps-internal-error")
            continue
        merge = r.get("merge")
        if isinstance(merge, str) and merge:
            text = _str(merge, st)[:8]
            out.append(Redirect(text, None, _fd_of(text)))
            continue
        op = r.get("op")
        if not isinstance(op, str) or not op or len(op) > 8 or not set(op) <= _REDIRECT_CHARS:
            st.add_gray("ps-internal-error")
            op = ">"  # unknown operator with a target: assume it writes
        words = _convert(r.get("target"), st) if r.get("target") is not None else []
        if not words:
            st.add_gray("ps-internal-error")
        out.extend(Redirect(op, w, _fd_of(op)) for w in words)
    return out


def _external_param(token: str, arg: object, st: _State) -> list[Word]:
    """A parameter of an external program: PowerShell passes ``-name:value`` as ONE word."""
    if arg is None:
        return [Word(token)]
    words = _convert(arg, st)
    joined = ",".join(w.text for w in words)
    return [
        Word(
            f"{token}:{joined}",
            expands=any(w.expands for w in words),
            glob=any(w.glob for w in words),
        )
    ]


def _elements(c: Mapping[str, Any], st: _State, cmdlet: str | None) -> list[Word]:
    """argv[1:]: parameters resolved to canonical names, values converted."""
    raw = c.get("elements", [])
    if not isinstance(raw, list):
        st.add_gray("ps-internal-error")
        return []
    out: list[Word] = []
    literal_next = False
    stop_next = False  # the previous element was the stop-parsing token ``--%``
    for e in raw:
        if not (isinstance(e, Mapping) and e.get("t") == "param"):
            if stop_next and isinstance(e, Mapping) and e.get("t") == "str":
                # ``--%`` hands the rest of the line over as ONE string: split it on whitespace
                # into the words the program will see (``%VAR%`` stays visible as dynamic).
                stop_next = False
                st.tick()
                rest = _str(e.get("v"), st)
                out.extend(
                    _word(tok, expands="%" in tok or "$" in tok, glob=_glob(tok))
                    for tok in rest.split()
                )
                continue
            stop_next = (
                isinstance(e, Mapping)
                and e.get("t") == "str"
                and e.get("kind", "bare") == "bare"
                and e.get("v") == "--%"
            )
            words = _convert(e, st, sep=cmdlet is not None)
            if literal_next:
                words = [replace(w, glob=False) for w in words]
                literal_next = False
            out.extend(words)
            continue
        st.tick()
        literal_next = False
        stop_next = False
        name = _str(e.get("name"), st)
        arg = e.get("arg")
        if name == "-":  # the "--" token: everything after it is a value
            out.append(Word("--"))
            continue
        typed = "-" + (name or "?")
        if cmdlet is None:
            out.extend(_external_param(typed, arg, st))
            continue
        token = _canonical_param(cmdlet, typed)
        if token is None:
            st.add_gray(f"ps-param-unresolved:{_tag(cmdlet)}:{typed[:_MAX_TAG]}")
            token = typed
            takes: bool | None = None
        else:
            takes = psprograms.param_takes_value(cmdlet, token)
        out.append(Word(token))
        literal = token.lower() in _LITERAL_PARAMS
        if arg is not None:
            words = _convert(arg, st, sep=True)  # converted even if dropped: stays visible
            if takes is not False:  # a switch's `:$false` is not a value
                out.extend([replace(w, glob=False) for w in words] if literal else words)
        elif literal and takes is not False:
            literal_next = True
    return out


def _raw(st: _State, pos: object) -> str:
    """The source text of a command (informational only; offsets are UTF-16 units)."""
    if (
        isinstance(pos, list)
        and len(pos) == 2
        and all(type(p) is int and p >= 0 for p in pos)
        and pos[0] < pos[1]
    ):
        return st.source[pos[0] : min(pos[1], pos[0] + _MAX_RAW)]
    return ""


_MAX_RUNNER_LAYERS = 16


def _peel_runners(
    program: Word, args: list[Word], st: _State
) -> tuple[Word, list[Word], tuple[str, ...]]:
    """``uv run CMD``, ``uvx CMD``, ``pipx run CMD``, ``poetry run CMD`` and ``python -m boundkeep``
    start another program: peel them like ``sudo`` so the inner command is what gets judged (the
    marker in ``wrappers`` keeps allow rules away). An option the tables do not know is gray."""
    wrappers: list[str] = []
    for _ in range(_MAX_RUNNER_LAYERS):
        words = [program, *args]
        peeled = peel_runner(words)
        if peeled is None:
            break
        if isinstance(peeled, str):
            st.add_gray("ps-runner-options")
            break
        n_drop, marker, synthetic = peeled
        rest = ([synthetic] if synthetic is not None else []) + words[n_drop:]
        if not rest:
            break
        wrappers.append(marker)
        program = Word(_strip_exe(rest[0].text), rest[0].expands, rest[0].glob, rest[0].quoted)
        args = rest[1:]
    return program, args, tuple(wrappers)


def _command(c: object, st: _State) -> SimpleCmd | None:
    if not isinstance(c, Mapping):
        st.add_gray("ps-internal-error")
        return None
    st.tick()
    invoke = c.get("invoke", "")
    if invoke not in ("", "&", "."):
        st.add_gray("ps-internal-error")
    program, cmdlet, dynamic = _program(c.get("name"), st)
    args = _elements(c, st, cmdlet)
    if not dynamic and program.text == "Set-Location":
        name = c.get("name")
        fixed = None
        if isinstance(name, Mapping):
            fixed = _CD_FUNCTIONS.get(str(name.get("v", "")).lower())
        if fixed is not None:
            args = [Word(fixed), *args]
    wrappers: tuple[str, ...] = ()
    if not dynamic and cmdlet is None:
        program, args, wrappers = _peel_runners(program, args, st)
    redirects = _redirects(c, st)
    if invoke == ".":
        st.add_exec("ps-dot-source")
    if not dynamic:
        for reason in psprograms.exec_reasons_of(program.text, args):
            st.add_exec(reason)
        names, unknowable = psprograms.alias_definitions(program.text, args)
        if names or unknowable:
            st.add_gray("ps-alias-redefined")
            st.shadowed |= names
            st.shadow_all = st.shadow_all or unknowable
    stage = c.get("stage")
    of = stage.get("of") if isinstance(stage, Mapping) else None
    index = stage.get("index") if isinstance(stage, Mapping) else None
    in_pipeline = type(of) is int and of > 1
    if (
        in_pipeline
        and type(index) is int
        and index > 0
        and not dynamic
        and psprograms.reads_stdin_as_code(program.text, args)
    ):
        st.add_exec("ps-pipe-to-interpreter")
    nested = c.get("nested") is True
    origin = "top"
    if nested:
        only_blocks = "ScriptBlockExpressionAst" in st.dynamic_kinds
        origin = (
            "scriptblock"
            if only_blocks and "SubExpressionAst" not in st.dynamic_kinds
            else "subexpr"
        )
    return SimpleCmd(
        argv=(program, *args),
        redirects=tuple(redirects),
        wrappers=wrappers,
        origin=origin,
        raw=_raw(st, c.get("pos")),
        in_pipeline=in_pipeline,
    )


def _type_names(reply: Mapping[str, Any], key: str, st: _State) -> list[str]:
    """The AST type names of ``compound`` / ``dynamic`` (a missing or malformed list is gray)."""
    raw = reply.get(key)
    if not isinstance(raw, list):
        st.add_gray("ps-internal-error")
        return []
    return [_tag(t) for t in raw[:MAX_REASONS]]


def _run(reply: object, st: _State) -> None:
    if not isinstance(reply, Mapping):
        st.add_gray("ps-internal-error")
        return
    if reply.get("ok", True) is not True:
        st.add_gray("ps-too-large" if reply.get("error") == "too-large" else "ps-internal-error")
        return
    mode = reply.get("mode")
    if isinstance(mode, str) and mode != "FullLanguage":
        st.add_gray("ps-helper-unavailable")
    errors = reply.get("parse_errors")
    if not isinstance(errors, list):
        st.add_gray("ps-internal-error")
    elif errors:
        st.add_gray("ps-parse-error")
    for name in _type_names(reply, "compound", st):
        st.add_gray(f"ps-compound:{name}")
    dynamic = _type_names(reply, "dynamic", st)
    st.dynamic_kinds = frozenset(dynamic)
    for name in dynamic:
        st.add_exec(f"ps-dynamic:{name}")
    commands = reply.get("commands")
    if not isinstance(commands, list):
        st.add_gray("ps-internal-error")
        return
    if len(commands) > MAX_COMMANDS:
        st.add_gray("ps-too-large")
        commands = commands[:MAX_COMMANDS]
    for c in commands:
        built = _command(c, st)
        if built is not None:
            st.cmds.append(built)


def build(reply: Mapping[str, Any], *, source: str) -> BashResult:
    """The ``BashResult`` of one helper reply (the digest of ``source``).

    One ``SimpleCmd`` per entry of ``reply["commands"]`` (``origin`` ``top`` / ``subexpr`` /
    ``scriptblock``), line-level ``gray`` for everything not understood (compound statements,
    dynamic constructs, parse errors, unresolved parameters, dynamic command names, ...) and
    ``exec_reasons`` for what runs code we cannot see (Invoke-Expression, Start-Process,
    ``.`` dot-sourcing, ``-EncodedCommand``, scripts, nested shells, ``| iex``).

    Never raises. A reply that is not a mapping, lacks ``commands`` / ``compound`` / ``dynamic`` /
    ``parse_errors`` or has them in the wrong type is gray (``ps-internal-error``); a reply with
    more than ``MAX_COMMANDS`` commands, ``MAX_ELEMENTS`` elements or a string over ``MAX_STRING``
    characters is gray (``ps-too-large``); the commands built before the limit are kept.
    """
    st = _State(source if isinstance(source, str) else "")
    try:
        _run(reply, st)
    except _TooLarge:
        st.add_gray("ps-too-large")
    except Exception:  # noqa: BLE001 - a builder that raises would fail the gate open
        st.add_gray("ps-internal-error")
    return BashResult(tuple(st.cmds), tuple(st.gray), tuple(st.exec_))
