"""Conservative Bash command-line parser (hand written; no bashlex, no new dependency).

``parse_bash`` turns the command line an agent wants to run into a flat list of simple commands
(``SimpleCmd``) that later rules can match on. The command line is attacker-influenced text, so
the guiding rules are: every simple command that could execute appears in ``commands`` (also the
ones hidden behind ``$(...)``, backticks, ``bash -c``, ``eval``, ``xargs``, ``find -exec``,
here-docs
fed to a shell, pipeline stages and ``&&`` chains), and whenever the parser cannot be sure it has
seen everything it says so in ``gray``. The parser never produces an "allow" signal, only
information. It is pure text-in / data-out (no file system, no environment), linear time (every
loop advances, shared token / word budgets bound the work), never raises, and never executes or
expands anything: ``$X`` stays in ``Word.text`` with ``expands=True``.

Grammar subset
--------------
Lexing is context dependent in Bash, so lexer and recursive-descent parser are one class working
on the source string directly. Understood: single / double quotes (``\\``, ``$``, backtick rules),
``$'..'`` (escapes decoded), ``$".."``, backslash escapes and line continuation, ``# comments``
(only at word start), operators ``| |& || && ; & newline``, redirections (``> >> < << <<- <<< <>
>| >& <& &> &>>`` with ``n>`` / ``{fd}>`` prefixes), here-docs (bodies are data, except that they
are scanned for substitutions when the delimiter is unquoted and parsed as commands when fed to a
shell), subshells ``( )``, brace groups ``{ ; }``, ``$( )`` and backtick substitutions
(parsed recursively), prefix assignments, ``!``, and best-effort walking of ``if/while/for/case/
[[ ]]/function`` so that the commands inside are still listed.

Output conventions (the contract in docs/m1-design.md is silent on these)
-------------------------------------------------------------------------
* Command order: a substitution's commands come BEFORE the command containing it (it runs first);
  a ``bash -c`` / ``eval`` / ``find -exec`` / here-doc inner command comes AFTER its carrier
  (the carrier stays in ``commands`` with its own argv, so rules see both); here-doc bodies come
  after the line that introduced them.
* Assignment-only (``A=1``), redirect-only (``> f``, ``exec 3>f``) commands and the redirections
  applied to a group (``{ a; } > f``, ``( a ) 2>&1``) are a ``SimpleCmd`` with ``argv == ()``;
  ``env`` / ``redirects`` carry the information. Every other command has a non-empty ``argv``.
* ``env`` holds prefix assignments and the ``NAME=value`` operands of ``env`` / ``sudo``; ``+=``
  and ``name[idx]=`` are recorded under the bare name. Assignment values never have ``glob`` set
  (no pathname expansion happens in assignments).
* ``expands`` is true for ``$name ${..} $(..) `..` $((..)) <(..) >(..)`` outside single quotes and
  for an unquoted ``~`` at word start or after ``=`` / ``:`` (over-approximation). A command name
  whose word contains a variable / command / arithmetic expansion or a glob is "dynamic" and
  grays the line (``dynamic-command-name``); a bare tilde does not.
* ``glob`` is true for unquoted ``* ?`` and a ``[`` followed by ``]``, extglob ``@(..)`` and
  brace expansion ``{a,b}`` / ``{1..3}`` (they all make a word stand for many words).
* ``origin``: ``top``, ``subshell`` (``( )``), ``substitution`` (``$( )``, backticks), ``procsub``
  (``<( )``), ``bash-c``, ``eval``, ``trap``, ``heredoc`` (body / here-string fed to a shell),
  ``find-exec``. Brace groups keep the origin of their surroundings. Inner commands of
  ``bash -c`` etc. inherit the carrier's wrappers (``sudo bash -c 'rm x'`` -> ``rm`` has
  ``wrappers == ("sudo",)``).
* ``find -exec CMD {} ;`` yields an extra SimpleCmd for ``CMD`` with ``args_from_stdin=True``
  (arguments are supplied at run time, as for ``xargs``).
* A wrapper with nothing left to run (``sudo``, ``exec >f``) or whose options cannot be parsed
  stays as the program (not stripped); an unparsable wrapper grays the line.
* ``in_pipeline`` marks every command of a pipeline with at least two stages (compound stages
  such as ``a | ( b; c )`` mark the commands inside the group, substitutions inside a stage have
  their own context); ``background`` marks every command of an and-or list followed by ``&``.
  Keyword-structured loops (``while ..; done | cat``) are not tracked (they are gray anyway).
* ``exec_reasons`` always come with a ``gray`` entry ``exec:<reason>``.
* Internal errors keep the commands parsed so far and set ``gray == ("internal-error",)``.
  Empty / comment-only input yields ``gray == ("no-command",)``.

Gray reasons (stable short tokens)
----------------------------------
limits: ``too-long`` (only the first ``max_length`` chars are parsed), ``too-many-words``,
``too-many-tokens``, ``nesting-too-deep`` (structural nesting > 32), ``depth-exceeded``
(``bash -c`` / eval / here-doc recursion > ``max_depth``), ``nul-byte``, ``internal-error``,
``no-command``.  Unterminated: ``unterminated-quote|paren|brace|case|expansion|backtick|test|
heredoc``; ``syntax-error``.  Constructs: ``compound:<keyword>`` (if then elif else fi while until
do done for select case esac function coproc negation ``[[``), ``arithmetic`` (``(( ))``,
``$(( ))``, ``$[ ]``; when not a trivially pure expression the inside is parsed as a subshell so
nothing can hide), ``array-assignment``, ``process-substitution``, ``brace-expansion``,
``extglob``, ``trap``, ``alias``, ``ambiguous-quote`` (a ``'`` inside ``"${..}"``, treated as
literal as Bash 5 does).  Dynamic: ``dynamic-command-name``, ``dynamic-code:<what>``
(eval, trap, heredoc, herestring, param-prompt for ``${x@P}``),
``dynamic-interpreter-args:<name>``.  Wrappers: ``wrapper-options:<name>`` (unknown / dynamic
option), ``wrapper-option:<name>:<opt>`` (option whose argument is a path or command, e.g.
``sudo -D``, ``env -C``, ``xargs -a``, ``time -o``), ``wrapper-layers``.  Others:
``foreign-shell:<name>``, ``find-exec-unterminated`` and every ``exec:<reason>``.

Exec reasons: ``eval``, ``source``, ``interpreter-c:<name>`` (``python -c``, ``node -e``, ...),
``shell-stdin:<name>`` (``bash -s``), ``pipe|heredoc|herestring|redirect-to-interpreter:<name>``
(``curl | sh``, ``bash <<EOF`` ...), ``decode-pipe-to-interpreter:<name>`` (``base64 -d | bash``),
``stdin-to-interpreter:<name>`` (``python -``), ``script-from-procsub:<name>``,
``xargs-interpreter:<name>``, ``find-exec``, ``dynamic-shell-c:<name>``, ``wrapper-shell:<name>``
(``sudo -s cmd``), ``env-split-string``, ``interpreter:<name>`` (pwsh / cmd), and
``command-runner:<name>`` (watch, flock, su, ... which run a command we do not peel).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import NamedTuple

from boundkeep.normalize.model import BashResult, Redirect, SimpleCmd, Word
from boundkeep.normalize.programs import (
    DEVTOOLS,
    UNVETTED_EXE,
    devtool_exe_in_env,
    devtool_form,
    is_code_env,
    peel_runner,
)

__all__ = ["parse_bash"]

_MAX_NEST = 32  # structural nesting ($(, (, {, ${, `...`, bash -c, ...): bounds Python recursion
_TICK_FACTOR = 16  # token budget = factor * max_words
_MAX_WRAPPER_LAYERS = 64  # nice nice nice ... : each layer is one linear pass over the arguments
_DEFAULT_MAX_DEPTH = 8  # bash -c / eval / here-doc recursion (the global word budget still applies)
_RAW_CAP = 2048  # SimpleCmd.raw is for audit only and truncated

_PLAIN = re.compile(r"[^ \t\n;&|()<>$`'\"\\]+")
_BLANK = re.compile(r"[ \t]+")
_DQ_RUN = re.compile(r'[^"\\$`]+')
_HD_RUN = re.compile(r"[^\\$`]+")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
_ARRAY_PREFIX = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
_FD_REDIR = re.compile(r"(?:[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\})(?=[<>])")
_FUNC = re.compile(r"\([ \t]*\)")
# the start of a compound command: what may follow ``time`` / ``coproc NAME`` as a reserved word
_COMPOUND_START = (
    r"(?:\{(?=[ \t\n])|\((?!\))|(?:if|while|until|for|select|case)(?=[ \t\n;(])"
    r"|\[\[(?=[ \t])|!(?=[ \t]))"
)
_TIME_RESERVED = re.compile(r"(?:[ \t]+(?:-p|--)(?=[ \t]))*[ \t]+(?=" + _COMPOUND_START + ")")
_COPROC_NAME = re.compile(r"[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]+(?=" + _COMPOUND_START + ")")
_BT_STOP = re.compile(r"[\\`]")
_ANSI_STOP = re.compile(r"['\\]")
_SCAN_RUN = re.compile(r"[^\\$`'\"{}()\[\]]+")
_HEX = "0123456789abcdefABCDEF"
_ARITH_OK = frozenset(
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_ \t+-*/%<>=!&|^~?:,.#[]"
)
_NEUTRAL = "\x00"

_UNTERMINATED = {
    ")": "unterminated-paren",
    "}": "unterminated-brace",
    "case": "unterminated-case",
}

_KEYWORD_SKIP = frozenset(
    {"if", "then", "elif", "else", "fi", "while", "until", "do", "done", "esac", "coproc", "!", "}"}
)
_KEYWORD_NAME = {"!": "negation", "[[": "[["}
_RESERVED_AFTER_COPROC = frozenset(
    {"if", "while", "until", "for", "select", "case", "time", "function", "coproc", "do", "then"}
)  # a reserved word right after ``coproc`` is the command, not the coprocess NAME

_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "yash", "rbash"})
_FOREIGN_SHELLS = frozenset({"csh", "tcsh", "fish"})
_STDIN_PATHS = frozenset({"/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"})
_DECODERS = frozenset({"base64", "xxd", "gunzip", "zcat", "bzcat", "xzcat", "uudecode", "openssl"})
_FIND_EXEC = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
_RUNNERS = frozenset(
    {
        "watch", "parallel", "flock", "chroot", "nsenter", "unshare", "runuser", "su", "pkexec",
        "systemd-run", "script", "strace", "ltrace", "gdb", "taskset", "chrt", "prlimit",
        "setpriv", "busybox", "proxychains", "proxychains4", "tsocks", "fakeroot", "unbuffer",
        "eatmydata", "firejail", "caffeinate", "at", "batch", "valgrind", "perf", "cpulimit",
        "winpty", "start", "dbus-launch", "rlwrap", "torsocks", "runas", "faketime",
    }
)  # fmt: skip
_NET_DEVICES = ("/dev/tcp/", "/dev/udp/")
# builtins that evaluate (parts of) their operands as arithmetic / array subscripts, which runs a
# command substitution hidden in a subscript (``a[$(cmd)]``): the "sinks" of dynamic-code:subscript
_SUBSCRIPT_SINKS = frozenset(
    {"let", "declare", "typeset", "local", "unset", "read", "test", "[", "mapfile", "readarray"}
)  # fmt: skip
# builtins that assign to (or unset) the variables they are given
_ASSIGNERS = frozenset(
    {"export", "declare", "typeset", "readonly", "local", "unset", "read", "mapfile", "readarray",
     "let", "getopts", "printf"}
)  # fmt: skip


class _Abort(Exception):
    """Stop the whole parse (budget exhausted); the reason becomes a gray entry."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _Shared:
    """State shared by the top-level parser and every recursive sub-parser."""

    __slots__ = (
        "commands",
        "exec_reasons",
        "gray",
        "max_depth",
        "max_ticks",
        "max_words",
        "quoted_subst",
        "sink",
        "ticks",
        "words",
    )

    def __init__(self, max_depth: int, max_words: int) -> None:
        self.commands: list[SimpleCmd] = []
        self.gray: dict[str, None] = {}
        self.exec_reasons: dict[str, None] = {}
        self.quoted_subst = False  # a quoted literal that CONTAINS $( ... ) / backticks / ${
        self.sink = False  # something that evaluates operands as arithmetic / subscripts
        self.words = 0
        self.ticks = 0
        self.max_words = max_words
        self.max_ticks = max(_TICK_FACTOR * max_words, 1000)
        self.max_depth = max_depth

    def add_gray(self, reason: str) -> None:
        self.gray.setdefault(reason, None)


class _W(NamedTuple):
    """A word plus parser-private facts."""

    word: Word
    dyn: bool  # contains a variable / command / arithmetic expansion (a bare tilde is not one)
    uq: str  # aligned with word.text; literal unquoted characters, NUL for everything else


class _B:
    """Word builder: ``text`` and ``uq`` grow in lockstep (one uq char per text char)."""

    __slots__ = ("dyn", "expands", "extglob", "quoted", "text", "uq")

    def __init__(self) -> None:
        self.text: list[str] = []
        self.uq: list[str] = []
        self.dyn = False
        self.expands = False
        self.extglob = False
        self.quoted = False

    def plain(self, t: str) -> None:
        self.text.append(t)
        self.uq.append(t)

    def lit(self, t: str) -> None:
        if t:
            self.text.append(t)
            self.uq.append(_NEUTRAL * len(t))


class _Heredoc:
    __slots__ = ("delim", "quoted", "shell", "strip", "wrappers")

    def __init__(self, delim: str, strip: bool, quoted: bool) -> None:
        self.delim = delim
        self.strip = strip
        self.quoted = quoted
        self.shell = False
        self.wrappers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _Spec:
    """Option grammar of a wrapper program."""

    flags: str = ""  # short options without argument
    args: str = ""  # short options with an argument (attached or next word)
    optargs: str = ""  # short options with an optional, attached argument
    long_flags: frozenset[str] = frozenset()  # long options without argument (``=v`` tolerated)
    long_args: frozenset[str] = frozenset()  # long options with an argument
    risky: frozenset[str] = frozenset()  # options whose argument is a path / command -> gray
    noexec: frozenset[str] = frozenset()  # options meaning "does not run a command" -> unsure
    numeric: bool = False  # nice: -5
    operands: int = 0  # operands to skip after the options (timeout DURATION)
    assigns: bool = False  # NAME=value operands before the command
    dash: bool = False  # a lone "-" is an option (env -)


def _fs(*names: str) -> frozenset[str]:
    return frozenset(names)


_WRAPPERS: dict[str, _Spec] = {
    "sudo": _Spec(
        flags="AbEHiKknPSsVv",
        args="CDRTUacgprtu",
        long_flags=_fs(
            "--preserve-env", "--login", "--shell", "--non-interactive", "--stdin",
            "--background", "--set-home", "--reset-timestamp", "--remove-timestamp",
            "--validate", "--askpass", "--version", "--bell",
        ),
        long_args=_fs(
            "--user", "--group", "--prompt", "--chdir", "--chroot", "--role", "--type",
            "--close-from", "--other-user", "--command-timeout", "--login-class",
        ),
        risky=_fs("-D", "-R", "--chdir", "--chroot"),
        noexec=_fs("-e", "-l", "--edit", "--list"),
        assigns=True,
    ),
    "doas": _Spec(flags="ns", args="uC", risky=_fs("-C")),
    "env": _Spec(
        flags="i0v",
        args="uCSPa",
        long_flags=_fs("--ignore-environment", "--null", "--debug"),
        long_args=_fs(
            "--unset", "--chdir", "--split-string", "--block-signal", "--default-signal",
            "--ignore-signal", "--argv0",
        ),
        risky=_fs("-C", "-P", "--chdir"),
        assigns=True,
        dash=True,
    ),
    "nohup": _Spec(),
    "time": _Spec(
        flags="pvla",
        args="fo",
        long_flags=_fs("--append", "--portability", "--verbose", "--quiet"),
        long_args=_fs("--format", "--output"),
        risky=_fs("-o", "--output"),
    ),
    "command": _Spec(flags="pvV"),
    "builtin": _Spec(),
    "exec": _Spec(flags="cl", args="a"),
    "nice": _Spec(args="n", long_args=_fs("--adjustment"), numeric=True),
    "ionice": _Spec(
        flags="t",
        args="cnpPu",
        long_flags=_fs("--ignore"),
        long_args=_fs("--class", "--classdata", "--pid", "--pgid", "--uid"),
        noexec=_fs("-p", "-P", "-u", "--pid", "--pgid", "--uid"),
    ),
    "timeout": _Spec(
        flags="v",
        args="ks",
        long_flags=_fs("--preserve-status", "--foreground", "--verbose"),
        long_args=_fs("--kill-after", "--signal"),
        operands=1,
    ),
    "stdbuf": _Spec(args="ioe", long_args=_fs("--input", "--output", "--error")),
    "setsid": _Spec(flags="cfw", long_flags=_fs("--ctty", "--fork", "--wait")),
    # Windows Subsystem for Linux: without -e / --exec the rest is a command LINE for the Linux
    # shell (handled in _emit like ``sudo -s``); management options (--shutdown, -l, ...) are
    # unknown here, so they are not stripped and the line is gray.
    "wsl": _Spec(
        flags="e",
        args="du",
        long_flags=_fs("--exec", "--system"),
        long_args=_fs("--distribution", "--user", "--cd", "--shell-type", "--distribution-id"),
        risky=_fs("--cd"),
    ),
    "sshpass": _Spec(flags="hVv", args="fdpP", optargs="e", risky=_fs("-f")),
    "gosu": _Spec(operands=1),  # gosu USER[:GROUP] COMMAND ...
    "su-exec": _Spec(operands=1),
    "ssh-agent": _Spec(flags="cDdksu", args="aEOPt", noexec=_fs("-k")),
    "tini": _Spec(flags="hsvwgl", args="pe"),
    "chronic": _Spec(flags="ev"),
    "torify": _Spec(),
    "numactl": _Spec(
        flags="alt",
        args="CNmip",
        long_flags=_fs("--all", "--localalloc", "--touch"),
        long_args=_fs(
            "--cpunodebind", "--cpubind", "--physcpubind", "--membind", "--interleave",
            "--preferred",
        ),
    ),
    "xargs": _Spec(
        flags="0oprtx",
        args="adEILnPs",
        optargs="ile",
        long_flags=_fs(
            "--null", "--open-tty", "--no-run-if-empty", "--interactive", "--verbose", "--exit",
            "--show-limits", "--replace", "--eof", "--max-lines",
        ),
        long_args=_fs(
            "--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-chars",
            "--process-slot-var",
        ),
        risky=_fs("-a", "--arg-file"),
    ),
}  # fmt: skip


@dataclass(frozen=True, slots=True)
class _IScan:
    """How to find "code / script / stdin" in an interpreter's command line."""

    code: str = ""  # short options introducing inline code
    code_takes_arg: bool = True  # False for shells (-c is a flag; the code is the first operand)
    args: str = ""  # short options taking an argument
    attach: str = ""  # short options whose argument is the rest of the cluster
    module: str = ""  # python -m
    script: str = ""  # php -f
    stdin_flag: str = ""  # shells: -s
    code_long: frozenset[str] = frozenset()
    arg_long: frozenset[str] = frozenset()


_SCAN: dict[str, _IScan] = {
    "shell": _IScan(code="c", code_takes_arg=False, args="oO", stdin_flag="s",
                    arg_long=_fs("--init-file", "--rcfile")),
    "foreign": _IScan(code="cC", code_takes_arg=False),
    "python": _IScan(code="c", args="WXQ", module="m"),
    "node": _IScan(
        code="ep", args="rC", code_long=_fs("--eval", "--print"),
        arg_long=_fs("--require", "--import", "--loader", "--experimental-loader",
                     "--input-type", "--conditions"),
    ),
    "perl": _IScan(code="eE", args="I", attach="iMmFxdDVC"),
    "ruby": _IScan(code="e", args="rICEF", attach="KxWi"),
    "php": _IScan(code="rRBE", args="dcnz", script="f"),
    "lua": _IScan(code="e", args="l"),
    "deno": _IScan(),
}  # fmt: skip


def _family(name: str) -> str | None:
    if name in _SHELLS:
        return "shell"
    if name in _FOREIGN_SHELLS:
        return "foreign"
    if name == "py" or name in ("pypy", "pypy3"):
        return "python"
    if name.startswith("python") and all(ch.isdigit() or ch == "." for ch in name[6:]):
        return "python"
    if name in ("node", "nodejs", "bun"):
        return "node"
    if name in ("perl", "ruby", "php", "lua", "deno"):
        return name
    if name in ("pwsh", "powershell"):
        return "ps"
    if name == "cmd":
        return "cmd"
    return None


_HOME_NAMES = frozenset({"home", "pwd", "oldpwd"})


def _cluster_has(text: str, letter: str) -> bool:
    """True for a short-option cluster (``-tC``) that contains ``letter``."""
    return text.startswith("-") and not text.startswith("--") and letter in text[1:]


def _target_name(text: str) -> str:
    """The variable an assignment word names: ``NAME=v`` / ``NAME+=v`` / ``NAME[i]=v`` -> NAME."""
    return text.partition("=")[0].partition("[")[0].rstrip("+")


def _assign_targets(name: str, args: list[_W]) -> list[str]:
    """Names of the variables a builtin (export, declare, unset, read, printf -v, ...) assigns."""
    texts = [a.word.text for a in args]
    if name == "printf":
        for k, t in enumerate(texts):
            if t == "-v" and k + 1 < len(texts):
                return [_target_name(texts[k + 1])]
            if t.startswith("-v") and len(t) > 2:
                return [_target_name(t[2:])]
        return []
    if name == "getopts":
        return [_target_name(t) for t in texts[1:2]]
    return [_target_name(t) for t in texts if not t.startswith("-")]


def _canon(text: str) -> str:
    """Program name for table lookups: basename, ``.exe`` stripped (case-folded for ``.exe``)."""
    j = max(text.rfind("/"), text.rfind("\\"))
    base = text[j + 1 :]
    low = base.lower()
    if low.endswith(".exe"):
        return low[:-4]
    return base


# M1c-2: programs that cannot create or change a file unless a redirect says so, and the redirect
# operators that cannot either. A path-qualified dev tool is only recognised as one when every
# earlier command of the line is of this kind: a command that may have WRITTEN the executable
# (``echo x > .venv/bin/ruff; .venv/bin/ruff check``) leaves the line as it always was (gray,
# ``program-path-qualified``). The dev tools themselves run the repository's code anyway.
_NO_WRITE_PROGRAMS = frozenset(
    {
        "cd", "pushd", "popd", "pwd", "ls", "dir", "echo", "printf", "true", "false", ":", "test",
        "[", "which", "type", "cat", "head", "tail", "wc", "export", "unset", *DEVTOOLS,
    }
)  # fmt: skip
_READ_REDIRECTS = frozenset({"<", "<<", "<<-", "<<<", "<&"})


def _may_write(cmd: SimpleCmd) -> bool:
    for r in cmd.redirects:
        if r.op in _READ_REDIRECTS:
            continue
        digit = r.target is not None and (r.target.text == "-" or r.target.text.isdigit())
        if not (r.op == ">&" and digit):
            return True
    return bool(cmd.argv) and _canon(cmd.argv[0].text) not in _NO_WRITE_PROGRAMS


class _Stripped(NamedTuple):
    rest: list[_W]
    assigns: list[tuple[str, Word]]
    seen: set[str]
    optargs: list[tuple[str, str]]


class _IScanResult(NamedTuple):
    kind: str  # code | module | script | stdin | none
    operand: int | None  # index of the first operand
    dyn_operand: bool  # first operand is an unquoted dynamic word (may split into options)


def _scan_interp(sc: _IScan, args: list[_W]) -> _IScanResult:
    n = len(args)
    i = 0
    code = module = script = explicit = False
    while i < n:
        a = args[i]
        t = a.word.text
        if (a.dyn or a.word.glob) and not t.startswith("-"):
            break  # a dynamic word: treated as the first operand
        if t == "--":
            i += 1
            break
        if t == "-":
            explicit = True
            i += 1
            break
        if t.startswith("--"):
            nm, eq, _ = t.partition("=")
            if nm in sc.code_long:
                code = True
                i += 1 if eq else 2
            elif nm in sc.arg_long:
                i += 1 if eq else 2
            else:
                i += 1
            continue
        if len(t) > 1 and t[0] in "-+":
            k = 1
            consumed_next = False
            while k < len(t):
                ch = t[k]
                if ch in sc.code:
                    code = True
                    if sc.code_takes_arg:
                        consumed_next = k + 1 >= len(t)
                        break
                elif sc.stdin_flag and ch == sc.stdin_flag:
                    explicit = True
                elif ch in sc.module or ch in sc.script:
                    module = module or ch in sc.module
                    script = script or ch in sc.script
                    consumed_next = k + 1 >= len(t)
                    break
                elif ch in sc.args:
                    consumed_next = k + 1 >= len(t)
                    break
                elif ch in sc.attach:
                    break
                k += 1
            i += 2 if consumed_next else 1
            if module or script:
                break
            continue
        break
    operand = i if i < n else None
    if code:
        kind = "code"
    elif module:
        kind = "module"
    elif script:
        kind = "script"
    elif explicit:
        kind = "stdin"
    elif operand is not None:
        kind = "script"
    else:
        kind = "none"
    dyn_operand = (
        operand is not None
        and kind in ("script", "code")
        and args[operand].dyn
        and not args[operand].word.quoted
    )
    return _IScanResult(kind, operand, dyn_operand)


def _has_brace_expansion(uq: str) -> bool:
    """True if the unquoted text holds ``{a,b}`` or ``{1..3}`` (linear stack scan)."""
    stack: list[bool] = []
    i = 0
    n = len(uq)
    while i < n:
        ch = uq[i]
        if ch == "{":
            stack.append(False)
        elif ch == "}":
            if stack and stack.pop():
                return True
        elif stack and (ch == "," or (ch == "." and uq[i + 1 : i + 2] == ".")):
            stack[-1] = True
        i += 1
    return False


def _decode_ansi_c(body: str) -> tuple[str, bool]:
    """Decode the inside of ``$'...'``. Returns (text, truncated_at_NUL)."""
    out: list[str] = []
    pend = bytearray()

    def flush() -> None:
        if pend:
            out.append(pend.decode("utf-8", errors="surrogateescape"))
            pend.clear()

    simple = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r",
              "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}  # fmt: skip
    j = 0
    n = len(body)
    while j < n:
        k = body.find("\\", j)
        if k == -1:
            flush()
            out.append(body[j:])
            break
        if k > j:
            flush()
            out.append(body[j:k])
        j = k + 1
        if j >= n:
            flush()
            out.append("\\")
            break
        c = body[j]
        if c in simple:
            flush()
            out.append(simple[c])
            j += 1
        elif c in "01234567":
            e = j
            while e < n and e < j + 3 and body[e] in "01234567":
                e += 1
            v = int(body[j:e], 8) & 0xFF
            if v == 0:
                flush()
                return "".join(out), True
            pend.append(v)
            j = e
        elif c in "xuU":
            lim = {"x": 2, "u": 4, "U": 8}[c]
            e = j + 1
            while e < n and e < j + 1 + lim and body[e] in _HEX:
                e += 1
            if e == j + 1:
                flush()
                out.append("\\" + c)
                j += 1
                continue
            v = int(body[j + 1 : e], 16)
            if v == 0:
                flush()
                return "".join(out), True
            if c == "x":
                pend.append(v)
            else:
                flush()
                out.append(chr(v) if v <= 0x10FFFF else "\\" + c + body[j + 1 : e])
            j = e
        elif c == "c" and j + 1 < n:
            v = 0x7F if body[j + 1] == "?" else ord(body[j + 1]) & 0x1F
            if v == 0:
                flush()
                return "".join(out), True
            flush()
            out.append(chr(v))
            j += 2
        else:
            flush()
            out.append("\\" + c)
            j += 1
    flush()
    return "".join(out), False


class _Parser:
    """Lexer plus recursive-descent parser over one source string."""

    __slots__ = (
        "base_wrappers",
        "depth",
        "emitted",
        "i",
        "n",
        "nest",
        "origin",
        "pending",
        "piped",
        "s",
        "sh",
        "stage",
    )

    def __init__(
        self,
        s: str,
        sh: _Shared,
        *,
        depth: int,
        nest: int,
        origin: str,
        base_wrappers: tuple[str, ...],
        piped: bool,
    ) -> None:
        if nest > _MAX_NEST:
            raise _Abort("nesting-too-deep")
        self.s = s
        self.n = len(s)
        self.i = 0
        self.sh = sh
        self.depth = depth
        self.nest = nest
        self.origin = origin
        self.base_wrappers = base_wrappers
        self.piped = piped
        self.pending: list[_Heredoc] = []
        self.stage: list[str] = []  # programs of the earlier stages of the current pipeline
        self.emitted: list[int] = []  # indices of commands emitted by the command being parsed

    # ------------------------------------------------------------------ helpers

    def run(self) -> None:
        self._parse_list(None, self.origin)
        if self.pending:
            self.sh.add_gray("unterminated-heredoc")
            self.pending.clear()

    def _gray(self, reason: str) -> None:
        self.sh.add_gray(reason)

    def _exec(self, reason: str) -> None:
        self.sh.exec_reasons.setdefault(reason, None)
        self.sh.add_gray("exec:" + reason)

    def _tick(self) -> None:
        sh = self.sh
        sh.ticks += 1
        if sh.ticks > sh.max_ticks:
            raise _Abort("too-many-tokens")

    def _boundary(self, j: int) -> bool:
        return j >= self.n or self.s[j] in " \t\n;&|()<>"

    def _lit_subst(self, text: str) -> None:
        """Remember a quoted literal that holds ``$(``, a backtick or ``${``: not run here, but a
        later arithmetic / subscript evaluation of the value runs it (dynamic-code:subscript)."""
        if "$(" in text or "`" in text or "${" in text:
            self.sh.quoted_subst = True

    def _escaped_subst(self, ch: str, after: int) -> None:
        """A backslash-escaped ``\\`` + backtick or ``\\$(`` / ``\\${`` leaves a literal behind."""
        if ch == "`" or (ch == "$" and self.s[after : after + 1] in ("(", "{")):
            self.sh.quoted_subst = True

    def _skip_blanks(self) -> None:
        s = self.s
        n = self.n
        i = self.i
        while i < n:
            m = _BLANK.match(s, i)
            if m is not None:
                i = m.end()
                continue
            if s.startswith("\\\n", i):
                self._tick()
                i += 2
                continue
            break
        self.i = i

    def _skip_comment(self) -> None:
        j = self.s.find("\n", self.i)
        self.i = self.n if j == -1 else j

    def _skip_blanks_nl(self) -> None:
        """Skip blanks, comments and newlines (reading pending here-docs at newlines)."""
        while True:
            self._skip_blanks()
            if self.i >= self.n:
                return
            c = self.s[self.i]
            if c == "#":
                self._skip_comment()
            elif c == "\n":
                self._tick()
                self.i += 1
                if self.pending:
                    self._flush_heredocs()
            else:
                return

    def _mark(self, idxs: list[int], *, pipeline: bool = False, background: bool = False) -> None:
        cmds = self.sh.commands
        for k in idxs:
            c = cmds[k]
            if (pipeline and not c.in_pipeline) or (background and not c.background):
                cmds[k] = replace(
                    c,
                    in_pipeline=c.in_pipeline or pipeline,
                    background=c.background or background,
                )

    def _add(self, cmd: SimpleCmd) -> None:
        self.emitted.append(len(self.sh.commands))
        self.sh.commands.append(cmd)

    def _sub_parser(self, text: str, origin: str, depth: int, wrappers: tuple[str, ...]) -> _Parser:
        return _Parser(
            text,
            self.sh,
            depth=depth,
            nest=self.nest + 1,
            origin=origin,
            base_wrappers=wrappers,
            piped=self.piped,
        )

    def _recurse(self, text: str, origin: str, wrappers: tuple[str, ...]) -> None:
        """Parse ``text`` as a command line one ``bash -c`` level deeper."""
        if self.depth + 1 > self.sh.max_depth:
            self._gray("depth-exceeded")
            return
        self._sub_parser(text, origin, self.depth + 1, wrappers).run()

    # ------------------------------------------------------------------ lists

    def _parse_list(self, closer: str | None, origin: str, propagate: bool = False) -> str:
        """Parse commands until EOF or the closer; returns eof | close | sep | esac."""
        s = self.s
        n = self.n
        saved_origin = self.origin
        saved_stage = self.stage
        saved_emitted = self.emitted
        base_piped = self.piped
        self.origin = origin
        self.stage = []
        have_cmd = expect = next_piped = False
        list_idx: list[int] = []
        pipe_idx: list[int] = []
        all_idx: list[int] = []
        result = "eof"
        while True:
            self._skip_blanks()
            i = self.i
            if i >= n:
                if closer is not None:
                    self._gray(_UNTERMINATED[closer])
                if expect:
                    self._gray("syntax-error")
                break
            self._tick()
            c = s[i]
            if c == "#":
                self._skip_comment()
                continue
            if c == "\n":
                self.i = i + 1
                if self.pending:
                    self._flush_heredocs()
                if not expect:
                    have_cmd = next_piped = False
                    self.stage = []
                    list_idx = []
                    pipe_idx = []
                continue
            if c in ";&|" and not s.startswith("&>", i):
                two = s[i : i + 2]
                if c == ";" and two in (";;", ";&"):
                    if closer == "case":
                        self.i = i + (3 if s.startswith(";;&", i) else 2)
                        result = "sep"
                        break
                    self._gray("syntax-error")
                    self.i = i + 2
                    have_cmd = False
                    continue
                if not have_cmd:
                    self._gray("syntax-error")
                if two in ("&&", "||"):
                    self.i = i + 2
                    expect = True
                    next_piped = False
                    self.stage = []
                    pipe_idx = []
                elif c == "|":
                    self.i = i + (2 if two == "|&" else 1)
                    expect = True
                    next_piped = True
                    self._mark(pipe_idx, pipeline=True)
                    pipe_idx = []
                else:  # ; or &
                    self.i = i + 1
                    if c == "&":
                        self._mark(list_idx, background=True)
                    expect = next_piped = False
                    self.stage = []
                    list_idx = []
                    pipe_idx = []
                have_cmd = False
                continue
            if c == ")":
                self.i = i + 1
                if closer == ")":
                    if expect:
                        self._gray("syntax-error")
                    result = "close"
                    break
                self._gray("syntax-error")
                continue
            if c == "}" and self._boundary(i + 1) and closer == "}":
                self.i = i + 1
                if expect:
                    self._gray("syntax-error")
                result = "close"
                break
            if closer == "case" and s.startswith("esac", i) and self._boundary(i + 4):
                self.i = i + 4
                result = "esac"
                break
            self.piped = base_piped or next_piped
            mine: list[int] = []
            self.emitted = mine
            self._parse_command()
            self.emitted = saved_emitted
            self.piped = base_piped
            list_idx += mine
            all_idx += mine
            if next_piped:
                self._mark(mine, pipeline=True)
            else:
                pipe_idx += mine
            have_cmd = True
            expect = False
            if self.i == i:  # pragma: no cover - defensive progress guard, never loop forever
                self.i = i + 1
                self._gray("syntax-error")
        self.origin = saved_origin
        self.stage = saved_stage
        self.emitted = saved_emitted
        self.piped = base_piped
        if propagate:
            saved_emitted.extend(all_idx)
        return result

    def _nested_list(self, closer: str, origin: str, propagate: bool) -> None:
        self.nest += 1
        if self.nest > _MAX_NEST:
            raise _Abort("nesting-too-deep")
        self._parse_list(closer, origin, propagate)
        self.nest -= 1

    # ------------------------------------------------------------------ commands

    def _parse_command(self) -> None:
        s = self.s
        i = self.i
        if s[i] == "(":
            if s.startswith("((", i):
                end = self._arith_end(i + 2, False)
                self._gray("arithmetic")
                if end != -1:
                    self.i = end
                    return
            self.i = i + 1
            self._nested_list(")", "subshell", True)
            self._group_redirects(i)
            return
        self._parse_simple()

    def _arith_end(self, j: int, allow_semi: bool) -> int:
        """End index of a trivially pure ``(( expr ))`` starting after the ``((``, or -1."""
        s = self.s
        depth = 0
        lim = min(self.n, j + 4096)
        while j < lim:
            ch = s[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                if depth == 0:
                    return j + 2 if s[j + 1 : j + 2] == ")" else -1
                depth -= 1
            elif ch not in _ARITH_OK and not (allow_semi and ch == ";"):
                return -1
            j += 1
        return -1

    def _at_redirect(self) -> bool:
        s = self.s
        i = self.i
        c = s[i]
        if c in "<>":
            return s[i + 1 : i + 2] != "("
        if c == "&":
            return s[i + 1 : i + 2] == ">"
        return _FD_REDIR.match(s, i) is not None

    def _group_redirects(self, start: int) -> None:
        redirs: list[Redirect] = []
        hds: list[_Heredoc] = []
        while True:
            self._skip_blanks()
            if self.i >= self.n or not self._at_redirect():
                break
            self._redirect(redirs, hds)
        if redirs:
            self._emit([], [], redirs, self.s[start : self.i], hds)

    def _redirect(self, redirs: list[Redirect], hds: list[_Heredoc]) -> None:
        """Parse one redirection at the cursor (optional fd prefix, operator, target)."""
        s = self.s
        self._tick()
        fd: str | None = None
        m = _FD_REDIR.match(s, self.i)
        if m is not None:
            fd = m.group(0)
            self.i = m.end()
        i = self.i
        op = ""
        for cand in ("<<<", "<<-", "&>>", "<<", "<&", "<>", ">>", ">&", ">|", "&>", "<", ">"):
            if s.startswith(cand, i):
                op = cand
                break
        self.i = i + len(op)
        self._skip_blanks()
        target = self._read_word()
        if target is None:
            self._gray("syntax-error")
            redirs.append(Redirect(op, None, fd))
            return
        t = target.word.text
        if op in ("<<", "<<-"):
            hd = _Heredoc(t, op == "<<-", target.word.quoted)
            self.pending.append(hd)
            hds.append(hd)
            redirs.append(Redirect(op, None, fd))
        elif op in (">&", "<&") and not target.dyn and (t == "-" or t.rstrip("-").isdecimal()):
            redirs.append(Redirect(op, None, fd))
        else:
            redirs.append(Redirect(op, target.word, fd))

    def _parse_simple(self) -> None:
        s = self.s
        n = self.n
        start = self.i
        words: list[_W] = []
        env: list[tuple[str, Word]] = []
        redirs: list[Redirect] = []
        hds: list[_Heredoc] = []
        emitted = False
        try:
            while True:
                self._skip_blanks()
                i = self.i
                if i >= n:
                    break
                c = s[i]
                if c in "\n;)|":
                    break
                if c == "#":
                    self._skip_comment()
                    continue
                if c == "&" and not s.startswith("&>", i):
                    break
                if c == "(":
                    m = _FUNC.match(s, i)
                    if len(words) == 1 and not env and not redirs and m is not None:
                        self._gray("compound:function")
                        self.i = m.end()
                        return
                    self._gray("syntax-error")
                    break
                if self._at_redirect():
                    self._redirect(redirs, hds)
                    continue
                wi = self._read_word()
                if wi is None:  # pragma: no cover - every char reaching here starts a word
                    self._gray("syntax-error")
                    self.i += 1
                    continue
                if not words:
                    am = _ASSIGN.match(wi.uq)
                    if am is not None:
                        env.append(self._assignment(wi, am.end()))
                        continue
                    if not env and not redirs and not wi.word.quoted:
                        kw = wi.word.text
                        if kw in ("{",):
                            self.nest += 1
                            if self.nest > _MAX_NEST:
                                raise _Abort("nesting-too-deep")
                            self._parse_list("}", self.origin, True)
                            self.nest -= 1
                            self._group_redirects(start)
                            return
                        if kw == "time" and not self.piped:
                            # (only at the START of a pipeline: bash rejects ``a | time { x; }``)
                            tm = _TIME_RESERVED.match(s, self.i)
                            if tm is not None:
                                # ``time { rm x; }`` / ``time -p ( ... )``: ``time`` is a reserved
                                # word here and the compound command after it starts a new command
                                self.i = tm.end()
                                return
                        if self._keyword(kw):
                            return
                words.append(wi)
            if words or env or redirs:
                emitted = True
                self._emit(words, env, redirs, s[start : self.i], hds)
        except _Abort:
            if not emitted and (words or env or redirs):
                self._emit(words, env, redirs, s[start : self.i], hds)
            raise

    def _assignment(self, wi: _W, k: int) -> tuple[str, Word]:
        nm = _NAME.match(wi.uq)
        name = wi.uq[: nm.end()] if nm is not None else ""
        value = wi.word.text[k:]
        vuq = wi.uq[k:]
        if "[" in wi.uq[:k]:
            self._gray("array-assignment")
        if value.startswith("(") and vuq.startswith(_NEUTRAL):
            self._gray("array-assignment")
        tilde = vuq.startswith("~") or ":~" in vuq
        return name, Word(value, expands=wi.dyn or tilde, glob=False, quoted=wi.word.quoted)

    def _keyword(self, kw: str) -> bool:
        """Handle a reserved word at command start; True if consumed (nothing to emit)."""
        if kw in _KEYWORD_SKIP or kw in ("for", "select", "case", "function", "[["):
            if kw == "}":
                self._gray("syntax-error")
                return True
            self._gray("compound:" + _KEYWORD_NAME.get(kw, kw))
            if kw in ("for", "select"):
                self._for_loop()
            elif kw == "case":
                self._parse_case()
            elif kw == "coproc":
                # ``coproc NAME { cmd; }``: NAME is not a command (only before a compound command)
                cm = _COPROC_NAME.match(self.s, self.i)
                if cm is not None and cm.group(1) not in _RESERVED_AFTER_COPROC:
                    self.i = cm.end()
            elif kw == "function":
                self._skip_blanks()
                self._read_word()
                self._skip_blanks()
                m = _FUNC.match(self.s, self.i)
                if m is not None:
                    self.i = m.end()
            elif kw == "[[":
                self._dbl_bracket()
            return True
        return False

    def _for_loop(self) -> None:
        s = self.s
        self._skip_blanks()
        if s.startswith("((", self.i):
            end = self._arith_end(self.i + 2, True)
            self._gray("arithmetic")
            if end != -1:
                self.i = end
            return
        if self.i >= self.n or s[self.i] in "\n;":
            return
        self._read_word()
        self._skip_blanks_nl()
        if s.startswith("in", self.i) and self._boundary(self.i + 2):
            self.i += 2
            while True:
                self._skip_blanks()
                if self.i >= self.n or s[self.i] in "\n;":
                    break
                if s[self.i] == "#":
                    self._skip_comment()
                    continue
                if self._read_word() is None:
                    break

    def _parse_case(self) -> None:
        s = self.s
        self._skip_blanks()
        if self._read_word() is None:
            self._gray("syntax-error")
        self._skip_blanks_nl()
        if s.startswith("in", self.i) and self._boundary(self.i + 2):
            self.i += 2
        else:
            self._gray("syntax-error")
        while True:
            self._skip_blanks_nl()
            if self.i >= self.n:
                self._gray("unterminated-case")
                return
            if s.startswith("esac", self.i) and self._boundary(self.i + 4):
                self.i += 4
                return
            if s[self.i] == "(":
                self.i += 1
            while True:  # patterns
                self._skip_blanks()
                if self._read_word() is None:
                    self._gray("syntax-error")
                    break
                self._skip_blanks()
                if s[self.i : self.i + 1] == "|":
                    self.i += 1
                    continue
                if s[self.i : self.i + 1] == ")":
                    self.i += 1
                else:
                    self._gray("syntax-error")
                break
            self.nest += 1
            if self.nest > _MAX_NEST:
                raise _Abort("nesting-too-deep")
            r = self._parse_list("case", self.origin, True)
            self.nest -= 1
            if r == "esac":
                return
            if r == "eof":
                return

    def _dbl_bracket(self) -> None:
        s = self.s
        start = self.i - 2
        words: list[_W] = [_W(Word("[["), False, "[[")]
        while True:
            self._skip_blanks_nl()
            if self.i >= self.n:
                self._gray("unterminated-test")
                break
            c = s[self.i]
            if c == ";":
                self._gray("syntax-error")
                break
            if c in "()&|<>":
                two = s[self.i : self.i + 2]
                tok = two if two in ("&&", "||") else c
                self._tick()
                self.i += len(tok)
                words.append(_W(Word(tok), False, tok))
                continue
            wi = self._read_word()
            if wi is None:  # pragma: no cover - every other char starts a word
                self.i += 1
                continue
            words.append(wi)
            if wi.word.text == "]]" and not wi.word.quoted:
                break
        self._emit(words, [], [], s[start : self.i], [])

    # ------------------------------------------------------------------ words

    def _read_word(self) -> _W | None:
        """Read one shell word at the cursor; None if nothing was consumed."""
        s = self.s
        n = self.n
        start = self.i
        b = _B()
        i = start
        while i < n:
            m = _PLAIN.match(s, i)
            if m is not None:
                b.plain(m.group(0))
                i = m.end()
                continue
            c = s[i]
            if c in " \t\n;&|)":
                break
            if c in "<>":
                if s[i + 1 : i + 2] == "(":
                    self.i = i
                    self._procsub(b)
                    i = self.i
                    continue
                break
            self._tick()
            if c == "(":
                lastu = b.uq[-1][-1] if b.uq else ""
                if lastu and lastu in "?*+@!":
                    self.i = i
                    self._extglob(b)
                    i = self.i
                    continue
                if lastu == "=" and _ARRAY_PREFIX.fullmatch("".join(b.uq)):
                    self.i = i
                    self._array_literal(b)
                    i = self.i
                    continue
                break
            if c == "\\":
                nx = s[i + 1 : i + 2]
                if nx == "\n":
                    i += 2
                elif nx:
                    b.lit(nx)
                    b.quoted = True
                    self._escaped_subst(nx, i + 2)
                    i += 2
                else:
                    b.lit("\\")
                    b.quoted = True
                    i += 1
            elif c == "'":
                j = s.find("'", i + 1)
                b.quoted = True
                if j == -1:
                    self._gray("unterminated-quote")
                    b.lit(s[i + 1 :])
                    self._lit_subst(s[i + 1 :])
                    i = n
                else:
                    b.lit(s[i + 1 : j])
                    self._lit_subst(s[i + 1 : j])
                    i = j + 1
            elif c == '"':
                self.i = i
                self._dq(b)
                i = self.i
            elif c == "$":
                self.i = i
                self._dollar(b, False)
                i = self.i
            else:  # backtick
                self.i = i
                self._backtick(b, False)
                i = self.i
        self.i = i
        if i == start:
            return None
        sh = self.sh
        sh.words += 1
        if sh.words > sh.max_words:
            raise _Abort("too-many-words")
        text = "".join(b.text)
        uq = "".join(b.uq)
        lb = uq.find("[")
        glob = "*" in uq or "?" in uq or b.extglob or (lb != -1 and uq.find("]", lb + 1) != -1)
        if "{" in uq and _has_brace_expansion(uq):
            glob = True
            self._gray("brace-expansion")
        tilde = uq.startswith("~") or "=~" in uq or ":~" in uq
        return _W(Word(text, b.expands or b.dyn or tilde, glob, b.quoted), b.dyn, uq)

    def _dq(self, b: _B) -> None:
        s = self.s
        n = self.n
        i = self.i + 1
        b.quoted = True
        while True:
            m = _DQ_RUN.match(s, i)
            if m is not None:
                b.lit(m.group(0))
                i = m.end()
            if i >= n:
                self._gray("unterminated-quote")
                break
            c = s[i]
            if c == '"':
                i += 1
                break
            self._tick()
            if c == "\\":
                nx = s[i + 1 : i + 2]
                if nx == "\n":
                    i += 2
                elif nx and nx in '$`"\\':
                    b.lit(nx)
                    self._escaped_subst(nx, i + 2)
                    i += 2
                else:
                    b.lit("\\")
                    i += 1
            elif c == "$":
                self.i = i
                self._dollar(b, True)
                i = self.i
            else:
                self.i = i
                self._backtick(b, True)
                i = self.i
        self.i = i

    def _dollar(self, b: _B, in_dq: bool) -> None:
        s = self.s
        i = self.i
        nx = s[i + 1 : i + 2]
        if nx == "(":
            if s.startswith("$((", i):
                end = self._arith_end(i + 3, False)
                if end != -1:
                    self._gray("arithmetic")
                    b.lit(s[i:end])
                    b.dyn = b.expands = True
                    self.i = end
                    return
                self._gray("arithmetic")
            self.i = i + 2
            self._nested_list(")", "substitution", False)
            b.lit(s[i : self.i])
            b.dyn = b.expands = True
        elif nx == "{":
            self.nest += 1
            if self.nest > _MAX_NEST:
                raise _Abort("nesting-too-deep")
            end = self._scan_until(i + 2, "}", None, in_dq)
            self.nest -= 1
            if s[end - 3 : end] == "@P}":  # prompt expansion runs $(...) found in the value
                self._gray("dynamic-code:param-prompt")
            inner = s[i + 2 : end - 1] if end != -1 else s[i + 2 :]
            if inner[:1] == "!" or ":" in inner or "[" in inner:
                self.sh.sink = True  # indirection, offsets and subscripts evaluate arithmetic
            self._finish_scan(b, i, end, "unterminated-expansion")
        elif nx == "[":
            self._gray("arithmetic")
            self.nest += 1
            if self.nest > _MAX_NEST:
                raise _Abort("nesting-too-deep")
            end = self._scan_until(i + 2, "]", "[", in_dq)
            self.nest -= 1
            self._finish_scan(b, i, end, "unterminated-expansion")
        elif nx == "'" and not in_dq:
            self._ansi_c(b)
        elif nx == '"' and not in_dq:
            self.i = i + 1
            self._dq(b)
        else:
            m = _NAME.match(s, i + 1)
            if m is not None:
                b.lit(s[i : m.end()])
                b.dyn = b.expands = True
                self.i = m.end()
            elif nx and ((nx.isdecimal() and nx.isascii()) or nx in "@*#?-$!"):
                b.lit(s[i : i + 2])
                b.dyn = b.expands = True
                self.i = i + 2
            else:
                b.lit("$")
                self.i = i + 1

    def _finish_scan(self, b: _B, start: int, end: int, reason: str) -> None:
        if end == -1:
            self._gray(reason)
            end = self.n
        b.lit(self.s[start:end])
        b.dyn = b.expands = True
        self.i = end

    def _scan_until(self, j: int, close: str, nest_open: str | None, in_dq: bool) -> int:
        """Index after the matching ``close`` (skipping quotes / substitutions), or -1 at EOF."""
        s = self.s
        n = self.n
        depth = 0
        while j < n:
            m = _SCAN_RUN.match(s, j)
            if m is not None:
                j = m.end()
                if j >= n:
                    break
            self._tick()
            c = s[j]
            if c == close:
                if depth == 0:
                    return j + 1
                depth -= 1
                j += 1
            elif nest_open is not None and c == nest_open:
                depth += 1
                j += 1
            elif c == "\\":
                j += 2
            elif c == "$":
                if s[j + 1 : j + 2] in ("(", "{", "["):
                    tmp = _B()
                    self.i = j
                    self._dollar(tmp, in_dq)
                    j = self.i
                else:
                    j += 1
            elif c == "`":
                tmp = _B()
                self.i = j
                self._backtick(tmp, in_dq)
                j = self.i
            elif c == "'":
                if in_dq:
                    self._gray("ambiguous-quote")
                    j += 1
                else:
                    k = s.find("'", j + 1)
                    if k == -1:
                        self._gray("unterminated-quote")
                        return -1
                    j = k + 1
            elif c == '"':
                tmp = _B()
                self.i = j
                self._dq(tmp)
                j = self.i
            else:
                j += 1
        return -1

    def _backtick(self, b: _B, in_dq: bool) -> None:
        s = self.s
        n = self.n
        start = self.i
        j = start + 1
        parts: list[str] = []
        closed = False
        while j < n:
            m = _BT_STOP.search(s, j)
            if m is None:
                parts.append(s[j:])
                j = n
                break
            k = m.start()
            parts.append(s[j:k])
            self._tick()
            if s[k] == "`":
                j = k + 1
                closed = True
                break
            nx = s[k + 1 : k + 2]
            if nx == "\n":
                pass
            elif nx and (nx in "$`\\" or (in_dq and nx == '"')):
                parts.append(nx)
            else:
                parts.append("\\" + nx)
            j = k + 2
        if not closed:
            self._gray("unterminated-backtick")
            j = min(j, n)
        b.lit(s[start:j])
        b.dyn = b.expands = True
        self.i = j
        inner = "".join(parts)
        self._sub_parser(inner, "substitution", self.depth, ()).run()

    def _ansi_c(self, b: _B) -> None:
        s = self.s
        n = self.n
        start = self.i + 2
        j = start
        closed = False
        while j < n:
            m = _ANSI_STOP.search(s, j)
            if m is None:
                j = n
                break
            self._tick()
            if s[m.start()] == "'":
                j = m.start()
                closed = True
                break
            j = m.start() + 2
        body = s[start : min(j, n)]
        if not closed:
            self._gray("unterminated-quote")
            self.i = n
        else:
            self.i = j + 1
        text, truncated = _decode_ansi_c(body)
        if truncated:
            self._gray("nul-byte")
        b.lit(text)
        self._lit_subst(text)
        b.quoted = True

    def _procsub(self, b: _B) -> None:
        start = self.i
        self._gray("process-substitution")
        self.i = start + 2
        self._nested_list(")", "procsub", False)
        b.lit(self.s[start : self.i])
        b.dyn = b.expands = True

    def _extglob(self, b: _B) -> None:
        start = self.i
        self._gray("extglob")
        self.nest += 1
        if self.nest > _MAX_NEST:
            raise _Abort("nesting-too-deep")
        end = self._scan_until(start + 1, ")", "(", False)
        self.nest -= 1
        if end == -1:
            self._gray("unterminated-paren")
            end = self.n
        raw = self.s[start:end]
        b.lit(raw)
        b.extglob = True
        if "$" in raw or "`" in raw:
            b.dyn = b.expands = True
        self.i = end

    def _array_literal(self, b: _B) -> None:
        start = self.i
        self._gray("array-assignment")
        self.nest += 1
        if self.nest > _MAX_NEST:
            raise _Abort("nesting-too-deep")
        self.i = start + 1
        while True:
            self._skip_blanks_nl()
            if self.i >= self.n:
                self._gray("unterminated-paren")
                break
            if self.s[self.i] == ")":
                self.i += 1
                break
            wi = self._read_word()
            if wi is None:
                self._gray("syntax-error")
                self.i += 1
            elif wi.dyn:
                b.dyn = b.expands = True
        self.nest -= 1
        b.lit(self.s[start : self.i])

    # ------------------------------------------------------------------ here-docs

    def _flush_heredocs(self) -> None:
        pend = self.pending
        self.pending = []
        for hd in pend:
            body = self._heredoc_body(hd)
            expanded = False
            if not hd.quoted:
                p = self._sub_parser(body, "substitution", self.depth, ())
                expanded = p.scan_heredoc_expansions()
            if hd.shell:
                if expanded:
                    self._gray("dynamic-code:heredoc")
                text = body
                if hd.strip:
                    text = "\n".join(line.lstrip("\t") for line in body.split("\n"))
                self._recurse(text, "heredoc", hd.wrappers)

    def _heredoc_body(self, hd: _Heredoc) -> str:
        s = self.s
        n = self.n
        start = self.i
        delim = hd.delim
        if "\n" in delim:
            self._gray("syntax-error")
            self._gray("unterminated-heredoc")
            self.i = n
            return s[start:]
        if delim == "":
            j = start
            while True:
                self._tick()
                if j >= n:
                    break
                e = s.find("\n", j)
                line = s[j:] if e == -1 else s[j:e]
                if (line.lstrip("\t") if hd.strip else line) == "":
                    self.i = n if e == -1 else e + 1
                    return s[start:j]
                if e == -1:
                    break
                j = e + 1
            self._gray("unterminated-heredoc")
            self.i = n
            return s[start:]
        pos = start
        while True:
            self._tick()
            k = s.find(delim, pos)
            if k == -1:
                self._gray("unterminated-heredoc")
                self.i = n
                return s[start:]
            ls = k
            if hd.strip:
                while ls > start and s[ls - 1] == "\t":
                    ls -= 1
            end = k + len(delim)
            if (ls == start or s[ls - 1] == "\n") and (end >= n or s[end] == "\n"):
                self.i = min(n, end + 1)
                return s[start:ls]
            pos = k + 1

    def scan_heredoc_expansions(self) -> bool:
        """Expose substitutions inside an unquoted here-doc body; True if any expansion exists."""
        s = self.s
        n = self.n
        i = 0
        found = False
        while i < n:
            m = _HD_RUN.match(s, i)
            if m is not None:
                i = m.end()
                continue
            self._tick()
            c = s[i]
            if c == "\\":
                i += 2
                continue
            tmp = _B()
            self.i = i
            if c == "$":
                self._dollar(tmp, True)
            else:
                self._backtick(tmp, True)
            found = found or tmp.dyn
            i = self.i
        return found

    # ------------------------------------------------------------------ emission

    def _strip(self, name: str, spec: _Spec, args: list[_W]) -> _Stripped | None:
        """Strip a wrapper's options; None if they cannot be parsed with certainty."""
        n = len(args)
        i = 0
        seen: set[str] = set()
        optargs: list[tuple[str, str]] = []
        while i < n:
            a = args[i]
            t = a.word.text
            if (a.dyn or a.word.glob) and not t.startswith("-"):
                break
            if a.dyn or a.word.glob:
                return None
            if t == "--":
                i += 1
                break
            if t.startswith("--"):
                nm, eq, val = t.partition("=")
                if nm in spec.long_flags:
                    seen.add(nm)
                    i += 1
                    continue
                if nm in spec.long_args:
                    seen.add(nm)
                    if eq:
                        v = val
                        i += 1
                    else:
                        if i + 1 >= n:
                            return None
                        v = args[i + 1].word.text
                        i += 2
                    optargs.append((nm, v))
                    continue
                return None
            if len(t) > 1 and t[0] == "-":
                if spec.numeric and t[1:].isdecimal() and t.isascii():
                    i += 1
                    continue
                k = 1
                adv = 1
                while k < len(t):
                    ch = t[k]
                    if ch in spec.flags:
                        seen.add("-" + ch)
                        k += 1
                    elif ch in spec.args:
                        seen.add("-" + ch)
                        rest = t[k + 1 :]
                        if rest:
                            v = rest
                        else:
                            if i + 1 >= n:
                                return None
                            v = args[i + 1].word.text
                            adv = 2
                        optargs.append(("-" + ch, v))
                        break
                    elif ch in spec.optargs:
                        seen.add("-" + ch)
                        break
                    else:
                        return None
                i += adv
                continue
            if t == "-" and spec.dash:
                i += 1
                continue
            break
        if seen & spec.noexec:
            return None
        for opt, _ in optargs:
            if opt in spec.risky:
                self._gray(f"wrapper-option:{name}:{opt}")
        i = min(n, i + spec.operands)
        assigns: list[tuple[str, Word]] = []
        if spec.assigns:
            while i < n:
                am = _ASSIGN.match(args[i].uq)
                if am is None or args[i].word.glob:
                    break
                am_name = _NAME.match(args[i].uq)
                aname = args[i].uq[: am_name.end()] if am_name is not None else ""
                w = args[i].word
                assigns.append((aname, Word(w.text[am.end() :], w.expands, w.glob, w.quoted)))
                i += 1
        return _Stripped(args[i:], assigns, seen, optargs)

    def _emit(
        self,
        words: list[_W],
        env: list[tuple[str, Word]],
        redirs: list[Redirect],
        raw: str,
        hds: list[_Heredoc],
        *,
        origin: str | None = None,
        base_wrappers: tuple[str, ...] | None = None,
        args_from_stdin: bool = False,
    ) -> None:
        """Strip wrappers, record the command and run the semantic hooks (recursion, exec)."""
        raw = raw.strip()[:_RAW_CAP]
        org = self.origin if origin is None else origin
        wrappers = list(self.base_wrappers if base_wrappers is None else base_wrappers)
        envl = list(env)
        if not words and any(
            r.target is not None and r.target.text.startswith(_NET_DEVICES) for r in redirs
        ):
            # `{ cat f; } > /dev/tcp/h/80`, `3<>/dev/tcp/h/80`: Bash opens a socket. Emitted as
            # `exec` (as `exec 3<>/dev/tcp/h/80` is) so the program layer sees the network.
            words = [_W(Word("exec"), False, "exec")]
        for name, _ in envl:
            self._check_env_name(name)
        if not words:
            self._add(SimpleCmd((), tuple(envl), tuple(redirs), tuple(wrappers), org, False, raw))
            return
        cur = words
        afs = args_from_stdin
        for _ in range(_MAX_WRAPPER_LAYERS):
            w0 = cur[0]
            if w0.dyn or w0.word.glob:
                break
            name = _canon(w0.word.text)
            spec = _WRAPPERS.get(name)
            if spec is None:
                peeled = peel_runner([w.word for w in cur])
                if peeled is None:
                    break
                if isinstance(peeled, str):
                    self._gray(f"wrapper-options:{name}")
                    break
                n_drop, marker, synthetic = peeled
                lead = [_W(synthetic, False, synthetic.text)] if synthetic is not None else []
                wrappers.append(marker)
                cur = lead + cur[n_drop:]
                continue
            res = self._strip(name, spec, cur[1:])
            if res is None:
                self._gray(f"wrapper-options:{name}")
                break
            if name == "command" and res.seen & {"-v", "-V"}:
                break
            shell_mode = (
                name in ("sudo", "doas") and bool(res.seen & {"-s", "-i", "--shell", "--login"})
            ) or (name == "wsl" and not res.seen & {"-e", "--exec"})  # wsl: the rest is a LINE
            for aname, _ in res.assigns:
                self._check_env_name(aname)
            if shell_mode and res.rest:
                self._exec(f"wrapper-shell:{name}")
                text = " ".join(w.word.text for w in res.rest)
                self._recurse(text, "bash-c", (*wrappers, name))
            if name == "env" and res.seen & {"-S", "--split-string"}:
                parts = [v for o, v in res.optargs if o in ("-S", "--split-string")]
                self._exec("env-split-string")
                text = " ".join([*parts, *(w.word.text for w in res.rest)])
                self._recurse(text, "bash-c", (*wrappers, name))
                break
            if not res.rest:
                break
            wrappers.append(name)
            envl.extend(res.assigns)
            if name == "xargs":
                afs = True
            cur = res.rest
        else:
            self._gray("wrapper-layers")
        # M1c-2 dev tools: ``python -m pytest -q`` and ``./.venv/bin/pytest -q`` are the program
        # ``pytest`` with the arguments ``-q``. The interpreter flags and ``-m`` are dropped, and a
        # path-qualified executable keeps its path as an extra READ redirect (a synthetic one,
        # ``fd="program"``) so the path rules see it without a gray "program-path-qualified".
        cmd_redirs = tuple(redirs)
        form = devtool_form([w.word for w in cur])
        if (
            form is not None
            and (form.path is not None or form.start != 1)
            and (form.path is None or not any(_may_write(c) for c in self.sh.commands))
        ):
            cur = [_W(Word(form.tool), False, form.tool), *cur[form.start :]]
            if form.path is not None:
                cmd_redirs += (Redirect("<", form.path, "program"),)
                if not devtool_exe_in_env(form.path.text):
                    wrappers.append(UNVETTED_EXE)  # R-5: no allow rule for an exe outside any env
        p = cur[0]
        pname: str | None = None
        if p.dyn or p.word.glob:
            self._gray("dynamic-command-name")
        else:
            pname = _canon(p.word.text)
        self._add(
            SimpleCmd(
                tuple(w.word for w in cur),
                tuple(envl),
                cmd_redirs,
                tuple(wrappers),
                org,
                afs,
                raw,
            )
        )
        if pname is not None:
            self._semantics(pname, cur, tuple(wrappers), redirs, hds)
            self.stage.append(pname)

    def _check_env_name(self, name: str) -> None:
        """Gray for an assigned variable that injects code or moves ``~`` / the cwd."""
        if not name:
            return
        if "$" in name or "`" in name:
            self._gray("dynamic-env-name")  # the variable being assigned is not known
        elif is_code_env(name):
            self._gray(f"env-code-injection:{name}")
        elif name.lower() in _HOME_NAMES:
            self._gray("home-reassigned")
        elif name.lower() == "cdpath":
            self._gray("cdpath-set")

    def _fed(self, redirs: list[Redirect]) -> list[str]:
        fed: list[str] = []
        if self.piped:
            fed.append("pipe")
        for r in redirs:
            if r.fd not in (None, "0"):
                continue
            kind = {"<<": "heredoc", "<<-": "heredoc", "<<<": "herestring", "<": "redirect"}.get(
                r.op
            )
            if kind is not None and kind not in fed:
                fed.append(kind)
        return fed

    def _semantics(
        self,
        name: str,
        cur: list[_W],
        wrappers: tuple[str, ...],
        redirs: list[Redirect],
        hds: list[_Heredoc],
    ) -> None:
        args = cur[1:]
        if name in _ASSIGNERS:
            for target in _assign_targets(name, args):
                self._check_env_name(target)
        if name in _SUBSCRIPT_SINKS or (
            name == "printf" and any(a.word.text.startswith("-v") for a in args)
        ):
            self.sh.sink = True
        if name == "eval":
            self._exec("eval")
            if "xargs" in wrappers:
                self._exec("xargs-interpreter:eval")
            if args and not args[0].dyn and not args[0].word.glob and args[0].word.text == "--":
                args = args[1:]  # ``eval -- cmd``: eval ends its options at ``--`` like any builtin
            text = " ".join(a.word.text for a in args)
            if any(a.dyn or a.word.glob for a in args):
                self._gray("dynamic-code:eval")
            if text.strip():
                self._recurse(text, "eval", wrappers)
        elif name in (".", "source"):
            self._exec("source")
        elif name == "trap":
            ops = [a for a in args if not (a.word.text.startswith("-") and a.word.text != "-")]
            if ops and not any(a.word.text in ("-l", "-p") for a in args):
                action = ops[0]
                if action.dyn or action.word.glob:
                    self._gray("dynamic-code:trap")
                if action.word.text not in ("", "-"):  # "" ignores, "-" resets: no code
                    self._gray("trap")
                    self._recurse(action.word.text, "trap", wrappers)
        elif name == "alias":
            self._gray("alias")
        elif name in ("mapfile", "readarray"):
            if any(_cluster_has(a.word.text, "C") for a in args):
                self._exec("mapfile-callback")  # -C runs a command for every chunk of lines read
        elif name == "enable":
            if any(_cluster_has(a.word.text, "f") for a in args):
                self._exec("enable-f")  # -f loads a shared object into the shell
        elif name == "find":
            self._find_exec(args, wrappers)
        elif (fam := _family(name)) is not None:
            self._interpreter(name, fam, args, wrappers, redirs, hds)
        elif name in _RUNNERS:
            self._exec(f"command-runner:{name}")
            if name in ("su", "runuser", "script"):
                for k, a in enumerate(args):
                    t = a.word.text
                    if t in ("-c", "--command") and k + 1 < len(args):
                        self._recurse(args[k + 1].word.text, "bash-c", wrappers)
                    elif t.startswith("--command="):
                        self._recurse(t[10:], "bash-c", wrappers)

    def _find_exec(self, args: list[_W], wrappers: tuple[str, ...]) -> None:
        i = 0
        n = len(args)
        while i < n:
            a = args[i]
            if a.dyn or a.word.text not in _FIND_EXEC:
                i += 1
                continue
            j = i + 1
            sub: list[_W] = []
            terminated = False
            while j < n:
                t = args[j]
                if not t.dyn and not t.word.glob and t.word.text in (";", "+"):
                    terminated = True
                    break
                sub.append(t)
                j += 1
            if not terminated:
                self._gray("find-exec-unterminated")
            self._exec("find-exec")
            if sub:
                raw = " ".join(w.word.text for w in sub)
                self._emit(
                    sub, [], [], raw, [], origin="find-exec", base_wrappers=wrappers,
                    args_from_stdin=True,
                )  # fmt: skip
            i = j + 1

    def _interpreter(
        self,
        name: str,
        fam: str,
        args: list[_W],
        wrappers: tuple[str, ...],
        redirs: list[Redirect],
        hds: list[_Heredoc],
    ) -> None:
        if fam in ("ps", "cmd"):
            self._exec(f"interpreter:{name}")
            self._gray(f"foreign-shell:{name}")
            return
        if "xargs" in wrappers:
            self._exec(f"xargs-interpreter:{name}")
        shell = fam in ("shell", "foreign")
        if fam == "deno":
            first = next((a for a in args if not a.word.text.startswith("-")), None)
            if first is not None and first.word.text == "eval":
                self._exec(f"interpreter-c:{name}")
            return
        r = _scan_interp(_SCAN[fam], args)
        kind = r.kind
        explicit = kind == "stdin"
        if kind == "script" and r.operand is not None:
            if args[r.operand].word.text in _STDIN_PATHS:
                kind = "stdin"
                explicit = True
            elif args[r.operand].word.text.startswith("<("):
                self._exec(f"script-from-procsub:{name}")
        if r.dyn_operand:
            self._gray(f"dynamic-interpreter-args:{name}")
        if kind == "code":
            if not shell:
                self._exec(f"interpreter-c:{name}")
            elif r.operand is not None:
                w = args[r.operand]
                if w.dyn or w.word.glob:
                    self._exec(f"dynamic-shell-c:{name}")
                if fam == "foreign":
                    self._gray(f"foreign-shell:{name}")
                self._recurse(w.word.text, "bash-c", wrappers)
            return
        if kind not in ("stdin", "none"):
            return
        fed = self._fed(redirs)
        if explicit:
            self._exec(f"shell-stdin:{name}" if shell else f"stdin-to-interpreter:{name}")
        for f in fed:
            self._exec(f"{f}-to-interpreter:{name}")
        if "pipe" in fed and any(p in _DECODERS for p in self.stage):
            self._exec(f"decode-pipe-to-interpreter:{name}")
        if not shell:
            return
        if "heredoc" in fed:
            for hd in hds:
                hd.shell = True
                hd.wrappers = wrappers
        if "herestring" in fed:
            for r2 in redirs:
                if r2.op == "<<<" and r2.fd in (None, "0") and r2.target is not None:
                    if r2.target.expands or r2.target.glob:
                        self._gray("dynamic-code:herestring")
                    self._recurse(r2.target.text, "heredoc", wrappers)


def parse_bash(
    command: str,
    *,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    max_words: int = 4000,
    max_length: int = 1 << 20,
) -> BashResult:
    """Split a Bash command line into simple commands; see the module docstring for the rules.

    Pure and total: it never raises and never touches the file system or the environment.
    Anything it cannot be sure about is reported in ``BashResult.gray`` (and the commands it did
    understand are still returned); ``exec_reasons`` lists why the line deserves the "exec" tag.
    Limits: only the first ``max_length`` characters are parsed (``too-long``), at most
    ``max_words`` words (``too-many-words``), ``bash -c`` / eval / here-doc recursion at most
    ``max_depth`` deep (``depth-exceeded``), and structural nesting at most 32 levels.
    Any internal error yields ``gray == ("internal-error",)`` together with the commands found
    so far.
    """
    sh = _Shared(max_depth, max_words)
    try:
        if not isinstance(command, str):
            return BashResult((), ("internal-error",))
        text = command
        if len(text) > max_length:
            text = text[: max(max_length, 0)]
            sh.add_gray("too-long")
        if "\x00" in text:
            sh.add_gray("nul-byte")
        parser = _Parser(text, sh, depth=0, nest=0, origin="top", base_wrappers=(), piped=False)
        try:
            parser.run()
        except _Abort as abort:
            sh.add_gray(abort.reason)
        if sh.quoted_subst and (sh.sink or "arithmetic" in sh.gray or "compound:[[" in sh.gray):
            # x='a[$(cmd)]' is inert text until something evaluates it as arithmetic / a subscript
            sh.add_gray("dynamic-code:subscript")
        if not sh.commands and not sh.gray:
            sh.add_gray("no-command")
        return BashResult(tuple(sh.commands), tuple(sh.gray), tuple(sh.exec_reasons))
    except Exception:  # noqa: BLE001 - the parser must never raise; a bug becomes gray
        return BashResult(tuple(sh.commands), ("internal-error",))
