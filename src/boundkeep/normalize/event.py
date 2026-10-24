"""hook event -> list of Action (the assembler of the M1 normalizer).

Glue only: the Bash parser (``bash``), the program knowledge tables (``programs``), path
normalization (``paths``) and host extraction (``domains``) do the work. Nothing here decides
whether something is allowed: it only describes the action, and anything it cannot describe is
marked ``gray`` (policy.evaluate then never lets an allow rule match it).

What this layer adds on top of the pieces:

* the **working directory** of every command of a line: a SET of possible directories (``cd``
  can fail, subshells and pipelines may or may not keep it, ``cd -`` is unknowable), one PathRef
  per possibility for every relative path;
* the **canonical program name** (``/bin/rm``, ``rm.exe`` and ``RM`` are ``rm``) and the wrappers;
* **brace and glob words** expanded (braces exactly, globs against the disk), the resolved
  (symlink / junction / 8.3 / ``..``-after-symlink) form of every path next to the lexical one;
* arguments that arrive **at run time** (``xargs``, ``find -exec``): a synthetic uncertain path;
* lines that **write a file and then execute it**, or reassign ``HOME``/``PWD``/``OLDPWD``: gray;
* a **work budget** (time, action count, disk lookups): over it, the rest of the line is classified
  lexically only (no glob expansion, no disk, no subtree scan: a recursive read such as
  ``grep -r x .`` stays gray there) and one gray Action ``normalize-budget-exceeded`` is added, so a
  deny that the words alone show never turns into a gray. EVERY remaining command is classified (no
  count cap; see ``_LexicalPass`` for what keeps the work bounded). ``normalize_event`` runs on the
  daemon's event loop;
* **recursive reads**: a directory that Grep / Glob search, or that a command reads with all of its
  subtree (``CmdInfo.recursive``), is walked within a budget (``normalize.subtree``) and the files
  the policy protects against reads become read paths of the action; a walk that cannot finish
  makes the action gray. The Glob tool only lists names and is not walked. Grep without a ``glob``
  (and ``git`` commands) skip the VCS directories, as Claude Code's own search does;
* **UNC and WebDAV paths** (``\\\\host\\share``, ``host@80``) are network access: the host goes into
  ``Action.domains`` and the action is gray (``unc-network``).

``normalize_event`` never raises: an internal error becomes one gray Action.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from boundkeep.normalize import bash, domains, paths, programs, psparse, subtree
from boundkeep.normalize.model import (
    Access,
    Action,
    PathRef,
    Platform,
    RiskTag,
    Shell,
    SimpleCmd,
    Word,
)
from boundkeep.normalize.programs import DEVTOOLS
from boundkeep.policy.glob import GlobError, compile_glob
from boundkeep.policy.schema import too_broad

SHELL_TOOLS: dict[str, Shell] = {"Bash": "bash", "PowerShell": "powershell"}
FILE_WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
FILE_READ_TOOLS = frozenset({"Read"})
SEARCH_TOOLS = frozenset({"Glob", "Grep"})
# Tools that touch nothing on the machine: still "known", so a policy may allow them by name.
HARMLESS_TOOLS = frozenset({"ToolSearch", "TodoWrite"})

MAX_GIT_WALK = 16  # levels find_git_root climbs
PS_PARSE_BUDGET_S = 0.3  # the PowerShell helper's own limit (not charged to TIME_BUDGET_S)
TIME_BUDGET_S = 0.25  # normalize_event runs on the daemon's event loop
MAX_ACTIONS = 256  # simple commands handled per command line
MAX_DISK_KEYS = 64  # distinct paths looked up on disk per request
MAX_GLOB_DISK_KEYS = 256  # ... for the files a glob matched (a budget of their own)
# After the budget above ran out, ALL remaining commands are still classified, lexically only (no
# glob expansion, no disk lookups, no subtree scans), so a deny rule still sees their paths. There
# is no cap on how many: the pass is bounded by the size of the input (``MAX_PARSE_WORDS``), by the
# path count below and by the wall-clock limit, and commands that look the same to the rules are
# kept once. Recursive reads (``grep -r x .``) are not scanned in this mode and stay gray.
MAX_LEXICAL_REFS = 16384
MAX_LEXICAL_PATHS = 1024  # distinct paths that some rule could look at, kept in that mode
_MAX_SCREEN_KEY = 4096  # a longer key is never screened out
LEXICAL_TIME_BUDGET_S = 0.8
MAX_PARSE_WORDS = 20000  # words of a bash line that are parsed (the parser's own default is 4000)
MAX_KEY_DEPTH = 64  # path components; deeper keys are uncertain and never looked up
MAX_CWDS = 8  # possible working directories tracked at once (one of them may be "unknown")
MAX_BRACE_RESULTS = 64
MAX_GLOB_MATCHES = 64
MAX_REFS = 1024  # PathRefs per request
_MAX_TEXT = 1 << 22
_MAX_BRACE_TEXT = 1024
_MAX_BRACE_DEPTH = 16

_PS_CD = {"set-location": "cd", "push-location": "pushd", "pop-location": "popd"}
_CD_FLAGS = frozenset({"-L", "-P", "-e", "-@", "--"})
_PLACEHOLDER = "./{}"  # stands for the arguments xargs appends
_SYNTHETIC_KEY = "{args-from-stdin}"

# Variables whose reassignment changes what "~", "$HOME" and relative paths mean.
_WATCHED_VARS = frozenset({"HOME", "PWD", "OLDPWD"})
_ASSIGNERS = frozenset(
    {"export", "declare", "typeset", "readonly", "local", "unset", "read", "printf", "set"}
)

# Interpreters that run a file named in their arguments, and build tools that run their own file.
_INTERPRETERS = frozenset(
    {
        "bash", "sh", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash", "busybox",
        "python", "python2", "python3", "pypy", "pypy3", "perl", "ruby", "node", "nodejs",
        "deno", "bun", "php", "lua", "luajit", "tclsh", "Rscript", "awk", "gawk", "mawk",
        "source", ".", "exec", "pwsh", "powershell", "cmd", "osascript", "java", "dotnet",
    }
)  # fmt: skip
_BUILD_FILES: dict[str, frozenset[str]] = {
    "make": frozenset({"makefile", "gnumakefile"}),
    "gmake": frozenset({"makefile", "gnumakefile"}),
    "nmake": frozenset({"makefile"}),
    "ninja": frozenset({"build.ninja"}),
    "just": frozenset({"justfile"}),
    "rake": frozenset({"rakefile"}),
    "npm": frozenset({"package.json"}),
    "yarn": frozenset({"package.json"}),
    "pnpm": frozenset({"package.json"}),
    "bun": frozenset({"package.json"}),
    "cargo": frozenset({"build.rs", "cargo.toml"}),
    "gradle": frozenset({"build.gradle", "build.gradle.kts", "settings.gradle"}),
    "mvn": frozenset({"pom.xml"}),
    "cmake": frozenset({"cmakelists.txt"}),
    "tox": frozenset({"tox.ini"}),
    "nox": frozenset({"noxfile.py"}),
    "invoke": frozenset({"tasks.py"}),
    # M1c-2: dev tools that run repository code; a file written earlier on the same line that they
    # load as code or configuration (plugins, init hooks, conftest) makes the line gray
    "pytest": frozenset(
        {
            "conftest.py",
            "pytest.ini",
            ".pytest.ini",
            "pytest.toml",
            ".pytest.toml",
            "tox.ini",
            "setup.cfg",
            "pyproject.toml",
        }
    ),
    "mypy": frozenset({"mypy.ini", ".mypy.ini", "setup.cfg", "pyproject.toml"}),
    "pylint": frozenset(
        {".pylintrc", "pylintrc", ".pylintrc.toml", "pylintrc.toml", "setup.cfg", "pyproject.toml"}
    ),
    "flake8": frozenset({".flake8", "setup.cfg", "tox.ini"}),
}

# pytest also runs the test modules it discovers: one written earlier on the line counts
_PYTEST_TEST_FILE = re.compile(r"^(test_.*|.*_test)\.py$", re.IGNORECASE)

# Directories whose programs are the system's own (an allow rule may rely on the name there).
_POSIX_SYSTEM_DIRS = frozenset(
    {
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
        "/opt/homebrew/bin", "/opt/homebrew/sbin",
    }
)  # fmt: skip
_WINDOWS_SYSTEM_PREFIXES = (
    "/program files/git/",
    "/program files (x86)/git/",
    "/msys64/",
    "/msys32/",
    "/cygwin64/",
    "/cygwin/",
    "/windows/system32",
    "/windows/syswow64",
)


class _BudgetExceeded(Exception):
    """The request used up its time, action, lookup or path budget (see ``TIME_BUDGET_S``)."""

    def __init__(self, why: str) -> None:
        super().__init__(why)
        self.why = why


@dataclass(slots=True)
class _Budget:
    deadline: float
    resolved: dict[tuple[str, tuple[str, ...]], paths.NormPath] = field(default_factory=dict)
    realpaths: dict[str, str] = field(default_factory=dict)
    glob_resolved: dict[tuple[str, tuple[str, ...]], paths.NormPath] = field(default_factory=dict)
    refs: int = 0
    lexical: bool = False  # the budget ran out: classify without touching the disk
    scan: subtree.ScanBudget = field(
        default_factory=lambda: subtree.ScanBudget(
            subtree.MAX_SCAN_ENTRIES, subtree.SCAN_TIME_BUDGET_S
        )
    )

    def check(self) -> None:
        if time.monotonic() >= self.deadline:
            raise _BudgetExceeded("time")

    def disk_slot(self, *, glob: bool = False) -> None:
        """Account for one more distinct disk lookup (those for glob matches count apart)."""
        self.check()
        if glob:
            if len(self.glob_resolved) >= MAX_GLOB_DISK_KEYS:
                raise _BudgetExceeded("glob-matches")
        elif len(self.resolved) + len(self.realpaths) >= MAX_DISK_KEYS:
            raise _BudgetExceeded("disk-lookups")

    def add_refs(self, count: int) -> None:
        self.refs += count
        if self.refs > (MAX_LEXICAL_REFS if self.lexical else MAX_REFS):
            raise _BudgetExceeded("paths")


@dataclass(frozen=True)
class _Ctx:
    platform: Platform
    env: Mapping[str, str]
    home: str | None
    cwd: str | None
    root: paths.NormPath | None
    root_resolved: (
        paths.NormPath | None
    )  # the project root after symlink/junction/short-name resolution
    base: dict[str, Any]  # fields every Action of this event shares
    budget: _Budget
    protected: subtree.ProtectedMatcher = field(
        default_factory=lambda: subtree.matcher_for(subtree.DEFAULT_PROTECTED_GLOBS)
    )  # the read-protection globs a recursive read is checked against
    rule_screen: subtree.RuleScreens | None = None  # path globs of the deny / ask rules, or None
    scratch: paths.Scratchpad | None = None  # this session's scratchpad (None: no valid session)


@dataclass(slots=True)
class _Line:
    """What is known about the command line so far (one per shell tool call)."""

    cwds: tuple[str | None, ...]  # possible working directories; None = unknown
    written: set[str] = field(default_factory=set)  # keys written by earlier commands
    last_find: list[tuple[Word, Access]] = field(default_factory=list)
    line_gray: list[str] = field(default_factory=list)
    shell: str = "bash"  # bash | powershell: picks the parser, the path dialect and the tables


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and len(value) <= _MAX_TEXT else None


def _gray(ctx: _Ctx, tool: str, *reasons: str, **extra: Any) -> Action:
    return Action(
        tool=tool, gray=True, gray_reasons=tuple(reasons or ("unknown",)), **ctx.base, **extra
    )


# --------------------------------------------------------------------------------------------
# Project root
# --------------------------------------------------------------------------------------------


def find_git_root(cwd: str) -> str | None:
    """The nearest ancestor of ``cwd`` that holds a ``.git`` entry, on this machine; else None.

    Only a plain local path is looked at: a UNC, ``\\\\?\\`` or device path, a network or other
    non-fixed drive, a relative path and a path of the other platform's flavor return None without
    touching the disk (a dead server would block the daemon's event loop). Climbs at most
    ``MAX_GIT_WALK`` levels. Never raises.
    """
    try:
        if not cwd or cwd[:2] in ("\\\\", "//") or "\x00" in cwd:
            return None
        norm = paths.normalize_path(cwd, cwd=None, home=None, dialect="tool", literal=True)
        if norm.uncertain or not paths.is_local_disk(norm):
            return None
        current = os.path.abspath(cwd)
        for _ in range(MAX_GIT_WALK):
            if os.path.exists(os.path.join(current, ".git")):
                return current
            parent = os.path.dirname(current)
            if parent == current:
                return None
            current = parent
    except (OSError, ValueError):
        return None
    return None


_too_broad = too_broad  # shared with the ``trusted_projects`` check (policy/schema.py)


def _home_of(home: str | None, env: Mapping[str, str]) -> paths.NormPath | None:
    raw = home or env.get("HOME") or env.get("USERPROFILE")
    if not raw or not raw.strip():
        return None
    norm = paths.normalize_path(raw, cwd=None, home=None, dialect="tool", literal=True)
    return norm if norm.absolute and not norm.uncertain else None


def _project_root(
    payload: Mapping[str, Any], env: Mapping[str, str], home: str | None
) -> tuple[paths.NormPath | None, paths.NormPath | None]:
    """(project root, the same after resolving links), or (None, None).

    A root that is a filesystem root, a drive root, a home directory or an ancestor of one is
    refused: with it every file under the home directory would be "inside the project".
    """
    candidates: list[str] = []
    project_dir = _text(payload.get("project_dir"))
    if project_dir:
        candidates.append(project_dir)
    cwd = _text(payload.get("cwd"))
    if cwd and not project_dir:
        git_root = find_git_root(cwd)
        if git_root:
            candidates.append(git_root)
    home_norm = _home_of(home, env)
    for raw in candidates:
        root = paths.normalize_path(raw, cwd=None, home=home, env=env, dialect="tool")
        if not root.absolute or root.uncertain or _too_broad(root, home_norm):
            continue
        resolved = paths.resolve_on_disk(root)
        if resolved.key != root.key and _too_broad(resolved, home_norm):
            continue
        return root, resolved
    return None, None


def _project_keys(
    cwd: str | None,
    root: paths.NormPath | None,
    root_resolved: paths.NormPath | None,
    home: str | None,
    env: Mapping[str, str],
) -> tuple[str | None, str | None]:
    """(``Action.project``, ``Action.project_resolved``): the project root's canonical keys.

    Both None when there is no (acceptable) root. They are also None when the session's working
    directory is known and NOT definitely inside the project, lexically or after link resolution:
    a command that runs somewhere else does not run this project's code, so the ``project_trusted``
    match field must not apply. An absent ``cwd`` does not change anything (real events always
    carry one; relative paths are then gray anyway). ``project_resolved`` is only set when it
    differs from ``project``. Never raises.
    """
    try:
        if root is None:
            return None, None
        if cwd:
            norm = paths.normalize_path(cwd, cwd=None, home=home, env=env, dialect="tool")
            if paths.inside_project(norm, root) is not True:
                return None, None
            if (
                norm.key != root.key
            ):  # cwd is the project root itself: already resolved, no 2nd lookup
                resolved_cwd = paths.resolve_on_disk(norm)
                if resolved_cwd.key != norm.key and (
                    paths.inside_project(resolved_cwd, root_resolved or root) is not True
                ):
                    return None, None
        project = root.key
        resolved_key = root_resolved.key if root_resolved is not None else project
        return project, (resolved_key if resolved_key != project else None)
    except Exception:  # noqa: BLE001 - a failure here only means "no trusted project"
        return None, None


def _inside(refs: Sequence[PathRef]) -> bool | None:
    if not refs:
        return None
    states = [ref.inside_project for ref in refs]
    if all(state is True for state in states):
        return True
    return False if any(state is False for state in states) else None


# --------------------------------------------------------------------------------------------
# Words: dynamic, brace expansion
# --------------------------------------------------------------------------------------------

_KNOWN_VARS = ("HOME", "PWD")  # what the path layer resolves for a bash word
_PS_KNOWN_VARS = frozenset({"home", "pwd", "profile"})  # PowerShell names are case-insensitive


def _is_ident(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch == "_")


def _ps_var_end(rest: str) -> int:
    """How many characters of ``rest`` (the text after a ``$``) are a variable the path layer
    knows in PowerShell: ``$HOME`` ``$PWD`` ``$PROFILE`` (any case), ``$env:NAME`` and the
    ``${...}`` forms of those. 0 when it is anything else (or the name runs on into characters
    this scan cannot vouch for: non-ASCII, ``:`` and ``?`` continue a PowerShell variable name).

    ``$env:NAME`` is accepted whatever NAME is: the path layer resolves the names it can and marks
    the rest uncertain, with the variable named in the key.
    """
    if rest.startswith("{"):
        close = rest.find("}")
        inner = rest[1:close] if close > 0 else ""
        if not inner or "$" in inner or "`" in inner or not inner.isascii():
            return 0
        if inner.lower() in _PS_KNOWN_VARS or (inner[:4].lower() == "env:" and len(inner) > 4):
            return close + 1
        return 0
    start = 4 if rest[:4].lower() == "env:" else 0
    j = start
    while j < len(rest) and (rest[j].isalnum() or rest[j] == "_"):
        j += 1
    name = rest[start:j]
    if not name or not name.isascii() or rest[j : j + 1] in (":", "?"):
        return 0
    if start or name.lower() in _PS_KNOWN_VARS:
        return j
    return 0


def _has_unknown_dollar(text: str, shell: str = "bash") -> bool:
    i = text.find("$")
    while i >= 0:
        rest = text[i + 1 :]
        if shell == "powershell":
            used = _ps_var_end(rest)
            if not used:
                return True
            i += used + 1
            i = text.find("$", i)
            continue
        for name in _KNOWN_VARS:
            if rest.startswith("{" + name + "}"):
                i += len(name) + 3
                break
            if rest.startswith(name) and not _is_ident(rest[len(name) : len(name) + 1] or " "):
                i += len(name) + 1
                break
        else:
            return True
        i = text.find("$", i)
    return False


def _dynamic(word: Word, *, globs: bool = True, shell: str = "bash") -> bool:
    """Is the path this word stands for unknowable from its text?

    True for glob characters, command substitution and any ``$`` expansion other than the
    variables the path layer resolves (``$HOME``, ``${HOME}``, ``$PWD``; for PowerShell also
    ``$env:NAME`` and ``$PROFILE``, in any case). A bare leading ``~`` is not dynamic:
    ``normalize_path`` expands it (``~user`` and unknown homes it marks uncertain).
    """
    if word.glob:
        return globs
    if not word.expands:
        return False
    text = word.text
    return "`" in text or "$(" in text or _has_unknown_dollar(text, shell)


class _TooMany(Exception):
    pass


def _sequence(inner: str, limit: int) -> list[str] | None:
    """``1..5``, ``a..e``, ``01..10``, ``1..10..3`` -> the items; None when it is not a sequence."""
    parts = inner.split("..")
    if len(parts) not in (2, 3):
        return None
    first, last = parts[0], parts[1]

    def as_int(s: str) -> int | None:
        body = s[1:] if s[:1] in "+-" else s
        return int(s) if body.isascii() and body.isdigit() and len(body) <= 12 else None

    step = 1
    if len(parts) == 3:
        raw_step = as_int(parts[2])
        if raw_step is None or raw_step == 0:
            return None
        step = abs(raw_step)
    a, b = as_int(first), as_int(last)
    if a is not None and b is not None:
        if abs(b - a) // step + 1 > limit:
            raise _TooMany
        width = 0
        for s in (first, last):
            digits = s.lstrip("+-")
            if len(digits) > 1 and digits[0] == "0":
                width = max(width, len(s))
        direction = 1 if b >= a else -1
        return [
            str(v).zfill(width) if width else str(v)
            for v in range(a, b + direction, direction * step)
        ]
    if (
        len(first) == 1
        and len(last) == 1
        and first.isascii()
        and last.isascii()
        and first.isalpha()
        and last.isalpha()
    ):
        lo, hi = ord(first), ord(last)
        direction = 1 if hi >= lo else -1
        return [chr(c) for c in range(lo, hi + direction, direction * step)]
    return None


def _find_group(text: str, limit: int) -> tuple[int, int, list[str]] | None:
    """The first brace expression of ``text``: (index of ``{``, index of ``}``, alternatives)."""
    n = len(text)
    i = text.find("{")
    while i >= 0:
        if i == 0 or text[i - 1] != "$":
            depth = 1
            commas: list[int] = []
            j = i + 1
            while j < n:
                c = text[j]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        break
                elif c == "," and depth == 1:
                    commas.append(j)
                j += 1
            if depth == 0 and j < n:
                inner = text[i + 1 : j]
                if commas:
                    cuts = [i, *commas, j]
                    return i, j, [text[cuts[k] + 1 : cuts[k + 1]] for k in range(len(cuts) - 1)]
                seq = _sequence(inner, limit)
                if seq is not None:
                    return i, j, seq
        i = text.find("{", i + 1)
    return None


def _expand_braces(text: str, limit: int, depth: int) -> list[str]:
    if depth > _MAX_BRACE_DEPTH:
        raise _TooMany
    group = _find_group(text, limit)
    if group is None:
        return [text]
    start, end, alternatives = group
    prefix, suffix = text[:start], text[end + 1 :]
    out: list[str] = []
    for alternative in alternatives:
        out.extend(_expand_braces(prefix + alternative + suffix, limit, depth + 1))
        if len(out) > limit:
            raise _TooMany
    return out


def expand_braces(text: str, limit: int = MAX_BRACE_RESULTS) -> list[str] | None:
    """Bash brace expansion of one word, exactly (``a{b,c}`` ``{1..3}`` ``{a..e..2}``, nesting).

    Pure text. Returns ``[text]`` when the word holds no brace expression (``${HOME}``, ``{}``,
    ``{a}``, an unclosed ``{`` are not expansions), and None when the word is too long, nests too
    deeply or expands to more than ``limit`` results: the caller then stays uncertain.
    """
    if len(text) > _MAX_BRACE_TEXT:
        return None
    try:
        return _expand_braces(text, limit, 0)
    except _TooMany:
        return None


# --------------------------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------------------------


def _posix_host() -> bool:
    return os.name != "nt"


def _realpath(path: str) -> str:
    return os.path.realpath(path)


def _relative_text(text: str) -> bool:
    if not text or text[0] in "/\\~$%":
        return False
    return not (len(text) >= 2 and text[1] == ":")


def _ps_literal_glob(ctx: _Ctx, word: Word) -> bool:
    """A PowerShell word whose wildcard characters the command line parser cleared (a
    ``-LiteralPath`` value): ``[id]`` is a file name there, not a character class.

    On Windows ``*`` and ``?`` cannot be part of a name, so a word that holds them stays a
    pattern (uncertain) even when it was cleared; only brackets become literal.
    """
    if word.glob:
        return False
    text = word.text
    if not any(c in text for c in "*?["):
        return False
    return not (ctx.platform == "windows" and ("*" in text or "?" in text))


def _uses_pwd(text: str, dialect: str) -> bool:
    """Does the word mention ``$PWD`` / ``${PWD}``? Its value is the working directory, so each
    possible working directory is a different path (PowerShell names are case-insensitive)."""
    if "$" not in text or dialect not in ("bash", "powershell"):
        return False
    shown = text if dialect == "bash" else text.lower()
    name = "PWD" if dialect == "bash" else "pwd"
    return "$" + name in shown or "${" + name + "}" in shown


_PS_PROFILE_FILE = "Microsoft.PowerShell_profile.ps1"


def _profile_texts(ctx: _Ctx) -> list[str]:
    """Where ``$PROFILE`` (the current user's profile of the current host) can point.

    The shell that runs the command is not known (Windows PowerShell 5.1 or ``pwsh``), so both
    profile files are listed; they are what ``protect-windows-persistence`` guards. A OneDrive
    redirected Documents folder is covered by that rule's ``**/documents/...`` patterns only when
    the real path is spelled out, not through this variable: a known limit.
    """
    if ctx.platform == "windows":
        return [
            f"~\\Documents\\{folder}\\{_PS_PROFILE_FILE}"
            for folder in ("WindowsPowerShell", "PowerShell")
        ]
    return [f"~/.config/powershell/{_PS_PROFILE_FILE}"]


def _has_dotdot(text: str) -> bool:
    return ".." in text.replace("\\", "/").split("/")


def _with(reasons: Sequence[str], *more: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys([*reasons, *more]))


def _make_ref(
    ctx: _Ctx,
    raw: str,
    norm: paths.NormPath,
    access: Access,
    *,
    uncertain: bool,
    reasons: Sequence[str],
    resolved: bool = False,
) -> PathRef:
    root = (ctx.root_resolved or ctx.root) if resolved else ctx.root
    scratch = ctx.scratch
    return PathRef(
        raw=raw,
        key=norm.key,
        flavor=norm.flavor,
        access=access,
        inside_project=None if uncertain else paths.inside_project(norm, root),
        uncertain=uncertain,
        in_scratchpad=(
            not uncertain and scratch is not None and scratch.contains(norm, resolved=resolved)
        ),
        reasons=tuple(reasons),
    )


def _mark_hard_linked(refs: list[PathRef], resolved: paths.NormPath) -> list[PathRef]:
    """A path that is a hard link is not shown to be where its name says (X1 review, H-6).

    The file has another name somewhere else: inside the project it can be the policy, a settings
    file or a secret, and every rule that works on the name misses it. No allow rule may rely on
    ``inside_project`` or the scratchpad for it (the deny / ask rules still see the name, and a
    ``path_outside_project`` rule sees "not known to be inside").
    """
    if paths.HARD_LINKED not in resolved.reasons:
        return refs
    return [
        ref.model_copy(
            update={
                "inside_project": None if ref.inside_project is True else ref.inside_project,
                "in_scratchpad": False,
                "reasons": _with(ref.reasons, paths.HARD_LINKED),
            }
        )
        for ref in refs
    ]


def _disk_resolve(ctx: _Ctx, norm: paths.NormPath, *, glob: bool = False) -> paths.NormPath:
    """``paths.resolve_on_disk`` with the request's budget and a per-request memo.

    ``glob``: the path is one a wildcard matched; those lookups are counted on their own, so a
    ``cat *`` in a big directory cannot use up the lookups of the paths the command names.
    """
    memo_key = (norm.key, norm.reasons)
    cached = ctx.budget.resolved.get(memo_key) or ctx.budget.glob_resolved.get(memo_key)
    if cached is not None:
        return cached
    ctx.budget.disk_slot(glob=glob)
    result = paths.resolve_on_disk(norm)
    (ctx.budget.glob_resolved if glob else ctx.budget.resolved)[memo_key] = result
    return result


def _disk_realpath(ctx: _Ctx, text: str) -> str:
    cached = ctx.budget.realpaths.get(text)
    if cached is not None:
        return cached
    ctx.budget.disk_slot()
    result = _realpath(text)
    ctx.budget.realpaths[text] = result
    return result


def _glob_refs(
    ctx: _Ctx,
    norm: paths.NormPath,
    access: Access,
    notes: list[str],
    *,
    dotfiles: bool = False,
) -> list[PathRef]:
    """PathRefs for the files an unquoted glob matches on disk (the text itself stays uncertain).

    ``dotfiles``: the wildcard also matches names that start with a dot (PowerShell, unlike Bash).
    """
    ctx.budget.check()
    found = paths.expand_glob(
        norm, limit=MAX_GLOB_MATCHES, deadline=ctx.budget.deadline, dotfiles=dotfiles
    )
    if found.status == "budget":
        raise _BudgetExceeded("time")
    if found.status == "too-many":
        notes.append("glob-too-many-matches")
    elif found.status != "ok":
        notes.append("glob-not-expanded")
    refs: list[PathRef] = []
    for match in found.matches[:MAX_GLOB_MATCHES]:
        found_norm = paths.normalize_path(match, cwd=None, home=None, dialect="tool", literal=True)
        refs += _resolved_forms(ctx, match, found_norm, access, ("glob-match",))
    return refs


def _resolved_forms(
    ctx: _Ctx,
    raw: str,
    norm: paths.NormPath,
    access: Access,
    extra_reasons: Sequence[str],
) -> list[PathRef]:
    """A certain path as a PathRef, plus its on-disk resolved form when that differs."""
    refs = [
        _make_ref(
            ctx,
            raw,
            norm,
            access,
            uncertain=norm.uncertain,
            reasons=(*norm.reasons, *extra_reasons),
        )
    ]
    if norm.key.count("/") > MAX_KEY_DEPTH:
        return refs
    resolved = _disk_resolve(ctx, norm, glob="glob-match" in extra_reasons)
    if resolved.key != norm.key:
        refs.append(
            _make_ref(
                ctx,
                raw,
                resolved,
                access,
                uncertain=resolved.uncertain,
                reasons=_with(resolved.reasons, "resolved-on-disk"),
                resolved=True,
            )
        )
    return _mark_hard_linked(refs, resolved)


def _refs_one(
    ctx: _Ctx,
    notes: list[str],
    text: str,
    access: Access,
    *,
    cwd: str | None,
    dialect: str,
    dynamic: bool,
    glob_literal: bool,
) -> list[PathRef]:
    """The PathRef(s) for one path text in one working directory."""
    norm = paths.normalize_path(
        text,
        cwd=cwd,
        home=ctx.home,
        env=ctx.env,
        dialect=dialect,  # type: ignore[arg-type]
        glob_literal=glob_literal,
    )
    reasons = list(norm.reasons)
    uncertain = norm.uncertain or dynamic
    if dynamic and "dynamic-word" not in reasons:
        reasons.append("dynamic-word")
    if "$" in norm.key or "`" in norm.key:
        uncertain = True
        reasons.append("unresolved-expansion")
    deep = norm.key.count("/") > MAX_KEY_DEPTH
    if deep:
        uncertain = True
        reasons.append("path-too-deep")
    refs = [_make_ref(ctx, text, norm, access, uncertain=uncertain, reasons=reasons)]
    if dynamic or deep or ctx.budget.lexical:
        return refs  # (lexical mode: the budget ran out; no glob expansion, no disk lookups)
    if "glob" in norm.reasons and not glob_literal:
        return refs + _glob_refs(ctx, norm, access, notes, dotfiles=dialect == "powershell")
    if "brace" in norm.reasons:
        return refs
    # Disk forms: a symlink / junction / 8.3 name that leads somewhere else (paths.resolve_on_disk
    # itself refuses anything uncertain for other reasons than an unresolved short name).
    if (
        norm.absolute
        and (not norm.uncertain or "short-name-unresolved" in norm.reasons)
        and paths.is_local_disk(norm)
    ):
        resolved = _disk_resolve(ctx, norm)
        if resolved.key != norm.key:
            refs.append(
                _make_ref(
                    ctx,
                    text,
                    resolved,
                    access,
                    uncertain=resolved.uncertain,
                    reasons=_with(resolved.reasons, "resolved-on-disk"),
                    resolved=True,
                )
            )
        refs = _mark_hard_linked(refs, resolved)
    if not uncertain and norm.flavor == "posix" and _posix_host() and _has_dotdot(text):
        refs += _dotdot_forms(ctx, text, norm, access, cwd, dialect, refs)
    return refs


def _dotdot_forms(
    ctx: _Ctx,
    text: str,
    norm: paths.NormPath,
    access: Access,
    cwd: str | None,
    dialect: str,
    existing: Sequence[PathRef],
) -> list[PathRef]:
    """``link/../x``: the kernel follows the link first; the lexical key collapses ``..`` first."""
    uncollapsed = paths.expanded_text(
        text,
        cwd=cwd,
        home=ctx.home,
        env=ctx.env,
        dialect=dialect,  # type: ignore[arg-type]
    )
    if uncollapsed is None:
        return []
    real = paths.normalize_path(
        _disk_realpath(ctx, uncollapsed), cwd=None, home=None, dialect="tool", literal=True
    )
    if real.key == norm.key or any(r.key == real.key for r in existing):
        return []
    return [
        _make_ref(
            ctx,
            text,
            real,
            access,
            uncertain=real.uncertain,
            reasons=_with(real.reasons, "resolved-on-disk", "dotdot-after-symlink"),
            resolved=True,
        )
    ]


def _refs(
    ctx: _Ctx,
    notes: list[str],
    raw: str,
    access: Access,
    *,
    cwds: Sequence[str | None],
    dialect: str = "bash",
    dynamic: bool = False,
    glob_literal: bool = False,
) -> list[PathRef]:
    """All PathRefs of one path word: per brace result, per possible working directory."""
    ctx.budget.check()
    texts = [raw]
    if dialect == "bash" and "{" in raw:
        expanded = expand_braces(raw)
        if expanded is None:
            notes.append("brace-expansion-too-large")
            dynamic = True
        else:
            texts = expanded
    if dialect == "powershell" and len(texts) == 1 and raw.lower() in ("$profile", "${profile}"):
        texts = _profile_texts(ctx)
    out: dict[tuple[str, str, str, bool, tuple[str, ...]], PathRef] = {}
    for text in texts:
        relative = _relative_text(text) or _uses_pwd(text, dialect)
        for cwd in cwds if relative else cwds[:1]:
            if relative and cwd is None:
                notes.append("cwd-unknown")
            for ref in _refs_one(
                ctx,
                notes,
                text,
                access,
                cwd=cwd,
                dialect=dialect,
                dynamic=dynamic,
                glob_literal=glob_literal,
            ):
                out.setdefault((ref.raw, ref.key, ref.access, ref.uncertain, ref.reasons), ref)
    ctx.budget.add_refs(len(out))
    return list(out.values())


def _synthetic_ref(ctx: _Ctx, raw: str, access: Access) -> PathRef:
    """The path of an argument that arrives at run time: unknown, so never shown inside."""
    return PathRef(
        raw=raw,
        key=_SYNTHETIC_KEY,
        flavor="windows" if ctx.platform == "windows" else "posix",
        access=access,
        inside_project=None,
        uncertain=True,
        reasons=("args-from-stdin", "unknown-target"),
    )


# --------------------------------------------------------------------------------------------
# UNC / WebDAV paths are network access
# --------------------------------------------------------------------------------------------

# Servers of a UNC path that are this machine (or its WSL), not the network.
_LOCAL_UNC_SERVERS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]", "wsl$", "wsl.localhost"})


def _unc_server(ctx: _Ctx, key: str) -> str | None:
    """The remote server named by a UNC key (``//server/share/...``), None for anything else.

    WebDAV spellings ``server@80``, ``server@SSL`` and ``server@SSL@8443`` name ``server``. The
    machine's own name (COMPUTERNAME), ``localhost`` and the WSL providers are not remote.
    """
    if not key.startswith("//") or key.startswith("//./") or key.startswith("///"):
        return None
    server = key[2:].split("/", 1)[0].split("@", 1)[0]
    if not server or server == "?":
        return None
    low = server.casefold()
    computer = ctx.env.get("COMPUTERNAME") or ctx.env.get("computername")
    if low in _LOCAL_UNC_SERVERS or (computer and low == computer.casefold()):
        return None
    return server


def _unc_refs(ctx: _Ctx, refs: Sequence[PathRef]) -> tuple[tuple[str, ...], bool]:
    """(canonical remote hosts, whether one had no usable host name) of the UNC paths in ``refs``.

    A UNC path is a network access: reading it sends the user's NTLM credentials to the server,
    writing it uploads. The host goes into ``Action.domains`` so ``net-allowlist`` sees it.
    """
    names: list[str] = []
    unknown = False
    for ref in refs:
        if ref.flavor != "windows":
            continue
        if ctx.platform != "windows" and "\\" not in ref.raw:
            continue  # on a POSIX machine ``//host/x`` is just ``/host/x``: a local path
        server = _unc_server(ctx, ref.key)
        if server is None:
            continue
        host = domains.canonical_host(server)
        if host is None or host.kind == "unknown":
            unknown = True
        elif host.kind == "localhost" or (host.kind == "ip" and host.name in ("127.0.0.1", "::1")):
            continue
        else:
            names.append(host.name)
    return tuple(dict.fromkeys(names)), unknown


# --------------------------------------------------------------------------------------------
# Recursive reads: what is below a directory
# --------------------------------------------------------------------------------------------


def _native_dir(ref: PathRef) -> str | None:
    """The directory ``ref`` names, as a path this machine can scan; None when it cannot be."""
    if ref.uncertain or not ref.key or ref.key == _SYNTHETIC_KEY:
        return None
    norm = paths.NormPath(ref.raw, ref.key, ref.flavor, True, False, ())
    if not paths.is_local_disk(norm):
        return None
    return ref.key.replace("/", "\\") if ref.flavor == "windows" else ref.key


def _scan_refs(
    ctx: _Ctx,
    notes: list[str],
    refs: Sequence[PathRef],
    access: Access,
    *,
    select: subtree.Selector | None = None,
    follow_links: bool = True,
    skip_names: frozenset[str] = frozenset(),
) -> list[PathRef]:
    """Read refs for the protected files below the directories among ``refs``.

    ``refs`` are the PathRefs of ONE operand (its lexical and resolved forms, or what its glob
    matched). Each directory is walked (``normalize.subtree``, breadth first, within the request's
    scan budget) and the entries selected by the read-protection globs become PathRefs, so the
    policy sees ``<dir>/.env`` where the command only named ``<dir>``. A walk that could not finish
    (budget, unreadable directory) adds a gray note: the caller must not treat the tree as clean.
    ``follow_links``: the command may follow a link to a directory (``Get-ChildItem -Recurse``,
    ``grep -R``): one that is met makes the action gray; ripgrep never follows them.
    ``skip_names``: entry names the reader is known not to read (``subtree.VCS_DIR_NAMES``).
    """
    if ctx.budget.lexical or ctx.protected.empty:
        return []
    out: list[PathRef] = []
    seen: set[str] = set()
    for ref in refs:
        root = _native_dir(ref)
        if root is None or ref.key in seen:
            continue
        seen.add(ref.key)
        if ctx.budget.scan.spent:
            notes.append("recursive-scan-budget")
            break
        before = ctx.budget.scan.elapsed
        result = subtree.scan(
            root,
            [ref.key],
            windows=ref.flavor == "windows",
            matcher=ctx.protected,
            budget=ctx.budget.scan,
            select=select,
            skip_names=skip_names,
        )
        ctx.budget.deadline += ctx.budget.scan.elapsed - before  # not charged to the request
        if result.status == "budget":
            notes.append("recursive-scan-budget")
        elif result.status == "unreadable":
            notes.append("recursive-scan-unreadable")
        if result.dir_links and follow_links:
            notes.append("recursive-scan-link")
        if result.hard_links:
            notes.append("recursive-scan-hardlink")  # R-3: a name proves nothing about the file
        for hit in result.hits:
            norm = paths.NormPath(
                f"{ref.raw}/{hit.rel}"[:512], hit.key, ref.flavor, True, False, ()
            )
            out.append(
                _make_ref(
                    ctx,
                    norm.raw,
                    norm,
                    access,
                    uncertain=False,
                    reasons=("recursive-scan",),
                    resolved="resolved-on-disk" in ref.reasons,
                )
            )
    ctx.budget.add_refs(len(out))
    return list(dict.fromkeys(out))


# --------------------------------------------------------------------------------------------
# Shell tools
# --------------------------------------------------------------------------------------------


def _cd_target(ctx: _Ctx, text: str, cwd: str | None, dialect: str = "bash") -> str | None:
    """The key of the directory ``cd text`` leads to from ``cwd``, or None when unknowable."""
    norm = paths.normalize_path(
        text,
        cwd=cwd,
        home=ctx.home,
        env=ctx.env,
        dialect=dialect,  # type: ignore[arg-type]
    )
    if norm.uncertain or not norm.absolute or norm.is_device or not norm.key:
        return None
    if norm.key.count("/") > MAX_KEY_DEPTH:
        return None
    return norm.key


def _merge_cwds(old: Sequence[str | None], new: Sequence[str | None]) -> tuple[str | None, ...]:
    merged = list(dict.fromkeys([*old, *new]))
    known = [c for c in merged if c is not None]
    unknown = None in merged
    if len(known) + int(unknown) > MAX_CWDS:
        known = known[: MAX_CWDS - 1]
        unknown = True
    return (*known, *((None,) if unknown else ()))


def _after_cd(ctx: _Ctx, st: _Line, cmd: SimpleCmd, program: str) -> None:
    """Update the possible working directories after ``cd`` / ``pushd`` / ``popd``.

    ``cd`` can fail and a subshell, pipeline stage or ``bash -c`` may or may not keep the new
    directory, so the old directories stay possible next to the new ones; what cannot be known
    (``cd -``, ``popd``, ``$(...)``, a glob, several arguments, a very deep path) adds an
    "unknown" directory instead.
    """
    if program == "popd":
        st.cwds = _merge_cwds(st.cwds, (None,))
        return
    words = [w for w in cmd.argv[1:] if w.text not in _CD_FLAGS]
    if st.shell == "powershell":  # canonical parameters (-Path, -PassThru, ...) are not directories
        words = [w for w in words if w.quoted or not w.text.startswith("-")]
    if not words:
        if program == "pushd":  # swaps the top two directories
            st.cwds = _merge_cwds(st.cwds, (None,))
            return
        text = "~"
    elif (
        len(words) > 1
        or words[0].text in ("-", "")
        or _dynamic(words[0], shell=st.shell)
        or (program == "pushd" and words[0].text[:1] in "+-" and words[0].text[1:].isdigit())
    ):
        st.cwds = _merge_cwds(st.cwds, (None,))
        return
    else:
        text = words[0].text
    st.cwds = _merge_cwds(st.cwds, [_cd_target(ctx, text, cwd, st.shell) for cwd in st.cwds])


def _domains_of(urls: Sequence[str]) -> tuple[tuple[str, ...], bool]:
    """(canonical host names, whether some target had no usable host)."""
    names: list[str] = []
    unknown = False
    for url in urls:
        hosts = domains.hosts_of([url])
        usable = [h for h in hosts if h.kind != "unknown"]
        if not usable or len(usable) != len(hosts):
            unknown = True
        names.extend(h.name for h in usable)
    return tuple(dict.fromkeys(names)), unknown


def _system_dir(directory: str, platform: Platform) -> bool:
    text = directory.replace("\\", "/")
    segments = text.split("/")
    if any(s in (".", "..") for s in segments[1:]):
        return False
    text = text.rstrip("/") or "/"
    if text in _POSIX_SYSTEM_DIRS:
        return True
    if platform != "windows":
        return False
    low = text.casefold()
    if len(low) >= 2 and low[1] == ":":
        low = low[2:]
    return low in _POSIX_SYSTEM_DIRS or low.startswith(_WINDOWS_SYSTEM_PREFIXES)


def _canonical_program(ctx: _Ctx, word: Word) -> tuple[str, list[str]]:
    """(the canonical program name, gray reasons for how it was spelled).

    The basename of a path, ``.exe`` stripped, case-folded on Windows: ``/bin/rm``, ``rm.exe`` and
    ``RM`` are all ``rm``. A path-qualified name outside the system directories (``./rm``) is the
    same program name for deny and ask rules but gray, so that no allow rule trusts it.
    """
    text = word.text
    if _dynamic(word) or not text or "\x00" in text:
        return text, []
    cut = max(text.rfind("/"), text.rfind("\\"))
    name = text[cut + 1 :] if cut >= 0 else text
    if not name:
        return text, []
    if name.lower().endswith(".exe") and len(name) > 4:
        name = name[:-4]
    if ctx.platform == "windows":
        name = name.casefold()
    grays: list[str] = []
    if cut >= 0 and not _system_dir(text[:cut] or "/", ctx.platform):
        grays.append("program-path-qualified")
    return name, grays


def _scan_assignments(st: _Line, cmd: SimpleCmd, program: str | None) -> None:
    """Note reassignments of HOME, PWD, OLDPWD (and CDPATH): the ``~`` expansion would be wrong."""
    names = [name for name, _ in cmd.env]
    if program in _ASSIGNERS:
        names += [w.text.split("=", 1)[0].lstrip("-+") for w in cmd.argv[1:]]
    upper = {n.upper() for n in names}
    if upper & _WATCHED_VARS and "home-reassigned" not in st.line_gray:
        st.line_gray.append("home-reassigned")
    if "CDPATH" in upper:
        if "cdpath-assigned" not in st.line_gray:
            st.line_gray.append("cdpath-assigned")
        st.cwds = _merge_cwds(st.cwds, (None,))


def _executes_written(
    ctx: _Ctx, st: _Line, cmd: SimpleCmd, program: str, refs: Sequence[PathRef]
) -> bool:
    """Does this command run (or read as code) a file an earlier command of the line wrote?"""
    if not st.written:
        return False
    if program in _INTERPRETERS or program in _BUILD_FILES:
        for ref in refs:
            if ref.access != "write" and (ref.key in st.written or ref.uncertain):
                return True
        names = _BUILD_FILES.get(program, frozenset())
        if any(key.rsplit("/", 1)[-1].lower() in names for key in st.written):
            return True
        if program == "pytest" and any(
            _PYTEST_TEST_FILE.match(key.rsplit("/", 1)[-1]) for key in st.written
        ):
            return True
    raw = cmd.argv[0].text if cmd.argv else ""
    if "/" in raw or "\\" in raw:
        for cwd in st.cwds:
            norm = paths.normalize_path(raw, cwd=cwd, home=ctx.home, env=ctx.env, dialect="bash")
            if norm.key in st.written:
                return True
    return False


def _placeholder_refs(
    ctx: _Ctx,
    notes: list[str],
    st: _Line,
    cmd: SimpleCmd,
    word: Word,
    access: Access,
) -> list[PathRef]:
    """Refs for the ``{}`` of ``find -exec`` / the appended arguments of ``xargs``."""
    refs: list[PathRef] = []
    if cmd.origin == "find-exec":
        for start, _ in st.last_find:
            refs += _refs(
                ctx,
                notes,
                word.text.replace("{}", start.text),
                access,
                cwds=st.cwds,
                dynamic=_dynamic(start, globs=False),
            )
    refs.append(_synthetic_ref(ctx, "{}", access))
    return refs


def _peel_busybox(cmd: SimpleCmd) -> SimpleCmd:
    """``busybox rm -rf x`` runs the applet ``rm``: peel the launcher like any other wrapper."""
    if len(cmd.argv) < 2 or _dynamic(cmd.argv[0]) or _dynamic(cmd.argv[1]):
        return cmd
    name = cmd.argv[0].text.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name not in ("busybox", "busybox.exe") or cmd.argv[1].text.startswith("-"):
        return cmd
    return replace(cmd, argv=cmd.argv[1:], wrappers=(*cmd.wrappers, "busybox"))


_BOOLEAN_LITERALS = frozenset({"$true", "$false", "$null"})


def _consumed_as_path(word: str, path_text: str) -> bool:
    """Did the path layer take ``word`` (or the value attached to it) as the path ``path_text``?"""
    if word == path_text:
        return True
    if word.endswith(("=" + path_text, ":" + path_text)):  # --opt=VALUE, -opt:VALUE
        return True
    return word[:1] == "-" and word[1:2] != "-" and word[2:] == path_text  # -oVALUE


def _has_dynamic_args(
    program: str | None, args: Sequence[Word], path_words: Sequence[Word]
) -> bool:
    """Does the command carry a word that expands (or, for a dev tool, globs) which is not a path?

    ``cat $FILE`` and ``Get-Content $HOME\\a.txt`` are paths: the path layer judges them. What is
    left are values of options and parameters: ``pytest -k "$u@args.txt"`` (an argument file once
    the shell has expanded it), ``ConvertTo-Json $env:TOKEN`` (printed), ``ruff --select $env:X``
    (echoed by the error). Nothing about those words is known, so no allow rule may rely on the
    command being what it looks like.
    """
    glob_counts = program in DEVTOOLS
    texts = [w.text for w in path_words]
    for word in args:
        if not (word.expands or (glob_counts and word.glob)):
            continue
        if word.text.lower() in _BOOLEAN_LITERALS:
            continue
        if any(_consumed_as_path(word.text, t) for t in texts):
            continue
        return True
    return False


def _command_action(
    ctx: _Ctx, tool: str, st: _Line, cmd: SimpleCmd, common: dict[str, Any]
) -> Action:
    cmd = _peel_busybox(cmd)
    notes: list[str] = []
    program: str | None = None
    gray_reasons: list[str]
    classify_args: list[Word] = list(cmd.argv[1:])
    exec_child = cmd.args_from_stdin
    if exec_child and cmd.origin != "find-exec" and not any("{}" in w.text for w in classify_args):
        classify_args.append(Word(_PLACEHOLDER))
    if not cmd.argv:
        # Assignment-only (or redirect-only) command: nothing runs, but a redirect still writes.
        info = programs.CmdInfo(
            known=True,
            subcommand=None,
            flags=(),
            paths=tuple(
                (r.target, "write" if ">" in r.op else "read")
                for r in cmd.redirects
                if r.target is not None
            ),
            urls=(),
            network=False,
            tags=(),
            gray=(),
        )
        gray_reasons = list(info.gray)
    else:
        program, spelling = _canonical_program(ctx, cmd.argv[0])
        info = programs.classify(
            program,
            classify_args,
            shell=st.shell,  # type: ignore[arg-type]
            redirects=cmd.redirects,
            env=cmd.env,
        )
        gray_reasons = [*info.gray, *spelling]
        if ctx.platform != "windows" and any(
            r.startswith("program-case-variant") for r in info.gray
        ):
            program = program.lower()
    _scan_assignments(st, cmd, program)
    if cmd.argv and _dynamic(cmd.argv[0]):
        gray_reasons.append("dynamic-program")
    if cmd.args_from_stdin:
        gray_reasons.append("arguments-from-stdin")
    refs: list[PathRef] = []
    if "program-path-qualified" in gray_reasons:
        refs += _refs(
            ctx, notes, cmd.argv[0].text, "read", cwds=st.cwds, dialect=st.shell, dynamic=False
        )
    recursive = bool(getattr(info, "recursive", False))  # reads the whole subtree of a directory
    for word, access in info.paths:
        if exec_child and "{}" in word.text:
            refs += _placeholder_refs(ctx, notes, st, cmd, word, access)
        else:
            word_refs = _refs(
                ctx,
                notes,
                word.text,
                access,
                cwds=st.cwds,
                dialect=st.shell,
                dynamic=_dynamic(word, globs=False, shell=st.shell),
                glob_literal=_ps_literal_glob(ctx, word) if st.shell == "powershell" else False,
            )
            refs += word_refs
            if recursive and access != "write":
                # ``git grep / log -p / show / archive`` read tracked files and the object
                # database, never ``.git/config``: they skip the VCS directories. Every other
                # program (grep -r, rg, find, tar, cp -r ...) does read them.
                refs += _scan_refs(
                    ctx,
                    notes,
                    word_refs,
                    access,
                    skip_names=subtree.VCS_DIR_NAMES if program == "git" else frozenset(),
                )
    names, unknown_host = _domains_of(info.urls)
    if unknown_host:
        gray_reasons.append("unparseable-url")
    unc_names, unc_unknown = _unc_refs(ctx, refs)
    if unc_names or unc_unknown:
        names = tuple(dict.fromkeys([*names, *unc_names]))
        gray_reasons.append("unc-network")
    network = info.network or bool(info.urls) or bool(unc_names) or unc_unknown
    tags: list[RiskTag] = list(info.tags)
    if network and "network_egress" not in tags:
        tags.append("network_egress")
    if "file_write" not in tags and any(ref.access == "write" for ref in refs):
        tags.append("file_write")
    if program and _executes_written(ctx, st, cmd, program, refs):
        gray_reasons.append("exec-of-written-file")
    st.written.update(ref.key for ref in refs if ref.access == "write")
    if program == "find" and cmd.origin != "find-exec":
        st.last_find = list(info.paths)
    cd_program = program
    if st.shell == "powershell":
        # cmdlet names are case-insensitive: ``program`` is only case-folded on a Windows platform
        cd_program = _PS_CD.get((program or "").lower())
    if cd_program in ("cd", "pushd", "popd"):
        _after_cd(ctx, st, cmd, cd_program)
    gray_reasons.extend(notes)
    reasons = tuple(dict.fromkeys(gray_reasons))
    return Action(
        tool=tool,
        program=program,
        subcommand=info.subcommand,
        wrappers=cmd.wrappers,
        args=tuple(w.text for w in cmd.argv[1:]),
        flags=info.flags,
        paths=tuple(refs),
        domains=names,
        network=network or unknown_host,
        inside_project=_inside(refs),
        risk_tags=tuple(tags),
        gray=bool(reasons),
        gray_reasons=reasons,
        dynamic_args=_has_dynamic_args(program, classify_args, [w for w, _a in info.paths]),
        **ctx.base,
        **common,
    )


def _shell_actions(ctx: _Ctx, tool: str, shell: Shell, command: str) -> list[Action]:
    common: dict[str, Any] = {"shell": shell, "command_text": command}
    if shell == "powershell":
        # The helper process parses (AST only, never executes); not ready, timeout, crash and
        # every other failure come back as gray reasons, never as an exception.
        started = time.monotonic()
        result = psparse.parse_powershell(command, budget_s=PS_PARSE_BUDGET_S)
        ctx.budget.deadline += time.monotonic() - started  # the helper has its own time limit
    else:
        result = bash.parse_bash(command, max_words=MAX_PARSE_WORDS)
    actions: list[Action] = []
    st = _Line(cwds=(ctx.cwd,), shell=shell)
    marker: Action | None = None
    lexical: _LexicalPass | None = None
    for cmd in result.commands:
        kept: Action | None
        try:
            if lexical is None and len(actions) >= MAX_ACTIONS:
                raise _BudgetExceeded("actions")
            ctx.budget.check()  # (in lexical mode: the wall-clock limit of that pass)
            action = _command_action(ctx, tool, st, cmd, common)
            kept = action if lexical is None else lexical.admit(action)
        except _BudgetExceeded as exc:
            if lexical is not None:
                break  # the lexical pass ran out as well (time, paths): nothing more can be said
            # The budget ran out. A deny that is visible from the words alone must stay a deny, so
            # this command and the rest are classified again without glob expansion, disk lookups
            # and subtree scans (see ``_LexicalPass``); the gray marker below still keeps the line
            # from being allowed.
            marker = _budget_action(ctx, tool, exc, **common)
            lexical = _LexicalPass(ctx, actions)
            _enter_lexical_mode(ctx)
            try:
                kept = lexical.admit(_command_action(ctx, tool, st, cmd, common))
            except _BudgetExceeded:
                break
        if kept is not None:
            actions.append(kept)
    if marker is None:
        try:
            ctx.budget.check()
        except _BudgetExceeded as exc:
            marker = _budget_action(ctx, tool, exc, **common)
    if result.gray or not result.commands:
        reasons = result.gray or ("empty-command",)
        tags_extra: tuple[RiskTag, ...] = ("exec",) if result.exec_reasons else ()
        actions.append(_gray(ctx, tool, *reasons, risk_tags=tags_extra, **common))
    elif result.exec_reasons:
        # The line runs code the parser cannot see inside (eval, python -c, curl | sh).
        actions.append(
            _gray(
                ctx,
                tool,
                *(f"exec:{r}" for r in result.exec_reasons),
                risk_tags=("exec",),
                **common,
            )
        )
    if st.line_gray:
        actions.append(_gray(ctx, tool, *st.line_gray, **common))
    if marker is not None:
        actions.append(marker)
    return actions


def _rule_view(action: Action, paths: tuple[PathRef, ...]) -> tuple[Any, ...]:
    """Everything of ``action`` that a rule, the verdict or a gray reason can depend on, as a hash
    key. Not ``args`` (no rule matches on them; what they name that matters is in ``paths`` and
    ``domains``) and not ``command_text``: two commands with the same view add nothing to a verdict.
    """
    return (
        action.tool,
        action.program,
        action.subcommand,
        action.wrappers,
        action.flags,
        paths,
        bool(action.paths),
        action.domains,
        action.network,
        action.inside_project,
        action.risk_tags,
        action.gray_reasons,
    )


class _LexicalPass:
    """Which of the commands classified after the budget ran out become Actions.

    There is NO cap on the number of commands: each one is classified, so a deny that comes after
    any number of distinct commands is still found. What keeps the verdict's work bounded instead:

    * a command that looks the same to the rules as one already kept (``echo c1;`` ...
      ``echo c9999;``: same program, flags, tags and no path) adds nothing and is dropped;
    * a path that is certainly inside the project and that no deny / ask rule's path glob can
      select (``cat f1 f2 ...``) cannot be looked at by any rule, so it is not carried (the first
      path of an action is kept so that "every path is inside" still holds); only paths that some
      rule could look at (or whose place is uncertain) count against ``MAX_LEXICAL_PATHS``;
    * the wall-clock limit ``LEXICAL_TIME_BUDGET_S`` and the input size (``MAX_PARSE_WORDS``).

    Over the last two the rest of the line is not classified; the gray ``budget:*`` marker then
    still keeps it from being allowed (never an allow, at worst an ask).
    """

    __slots__ = ("_paths", "_screen", "_seen")

    def __init__(self, ctx: _Ctx, earlier: Sequence[Action]) -> None:
        self._screen = ctx.rule_screen
        self._seen: set[tuple[Any, ...]] = {_rule_view(a, a.paths) for a in earlier}
        self._paths = 0

    def _relevant(self, program: str | None, ref: PathRef) -> bool:
        screen = self._screen
        if screen is None or ref.uncertain or ref.inside_project is not True:
            return True
        return len(ref.key) > _MAX_SCREEN_KEY or screen.candidate(program, ref.access, ref.key)

    def admit(self, action: Action) -> Action | None:
        """``action`` (irrelevant paths possibly left out), or None when it adds nothing."""
        refs = action.paths
        relevant = tuple(ref for ref in refs if self._relevant(action.program, ref))
        key = _rule_view(action, relevant)
        if key in self._seen:
            return None
        self._paths += len(relevant)
        if self._paths > MAX_LEXICAL_PATHS:
            raise _BudgetExceeded("paths")
        self._seen.add(key)
        if len(relevant) < len(refs):
            return action.model_copy(update={"paths": relevant or refs[:1]})
        return action


def _enter_lexical_mode(ctx: _Ctx) -> None:
    """From now on classify without the disk (all remaining commands, see ``_shell_actions``)."""
    ctx.budget.lexical = True
    ctx.budget.deadline = time.monotonic() + LEXICAL_TIME_BUDGET_S


def _budget_action(ctx: _Ctx, tool: str, exc: _BudgetExceeded, **extra: Any) -> Action:
    return _gray(ctx, tool, "normalize-budget-exceeded", f"budget:{exc.why}", **extra)


# --------------------------------------------------------------------------------------------
# Other tools
# --------------------------------------------------------------------------------------------


def _plain_operands(refs: Sequence[PathRef]) -> list[PathRef]:
    """``refs`` with ``in_scratchpad`` cleared on every path whose name has a pattern character.

    The operand of a file or search tool is a path, not a pattern: a name with ``* ? [ ] { }`` in
    it (a Next.js ``[id]`` directory, a brace list) may mean more than it says to some tool, and the
    scratchpad rule does not guess: such a path is never "in the scratchpad". Only the operands of
    the tool (not the file name a Grep ``glob`` is probed with, which nothing opens).
    """
    return [
        ref.model_copy(update={"in_scratchpad": False})
        if ref.in_scratchpad and not paths.scratch_plain(ref.key)
        else ref
        for ref in refs
    ]


def _file_action(ctx: _Ctx, tool: str, raw: str | None, access: Access) -> Action:
    if raw is None or not raw.strip():
        return _gray(ctx, tool, "no-file-path")
    notes: list[str] = []
    # "[", "*" and "?" are ordinary characters of a file name here (Next.js ``app/[id]/page.tsx``);
    # a Windows name cannot hold "*" or "?", so there they can only be a pattern: stay uncertain.
    literal = not (ctx.platform == "windows" and ("*" in raw or "?" in raw))
    refs = _plain_operands(
        _refs(ctx, notes, raw, access, cwds=(ctx.cwd,), dialect="tool", glob_literal=literal)
    )
    tags: list[RiskTag] = ["file_write"] if access == "write" else []
    names, unknown = _unc_refs(ctx, refs)
    if names or unknown:
        notes.append("unc-network")
        tags.append("network_egress")
    return Action(
        tool=tool,
        paths=tuple(refs),
        domains=names,
        network=bool(names) or unknown,
        inside_project=_inside(refs),
        risk_tags=tuple(tags),
        gray=bool(notes),
        gray_reasons=tuple(dict.fromkeys(notes)),
        **ctx.base,
    )


def _dotdot_segment(segment: str) -> bool:
    """Can this glob segment stand for ``..`` (``..``, ``[.][.]``, ``{..,x}``, ``.{.,x}``)?"""
    plain = segment.replace("[.]", ".")
    if plain == "..":
        return True
    if "{" in plain:
        alternatives = expand_braces(plain)
        return alternatives is None or any(a == ".." for a in alternatives)
    return False


def _pattern_is_path(pattern: str) -> bool:
    """A glob pattern that carries its own location: absolute, ``~``, ``$VAR`` or climbing out."""
    if not pattern:
        return False
    if pattern[0] in "/\\~$" or (len(pattern) > 1 and pattern[1] == ":"):
        return True
    return any(_dotdot_segment(s) for s in pattern.replace("\\", "/").split("/"))


# ripgrep file types (``Grep type=py``) that narrow a search to files with these names. Only the
# types listed here narrow; any other type name leaves the search unnarrowed (the cautious side).
_RG_TYPES: dict[str, tuple[str, ...]] = {
    "py": ("*.py", "*.pyi"),
    "python": ("*.py", "*.pyi"),
    "js": ("*.js", "*.jsx", "*.mjs", "*.cjs"),
    "ts": ("*.ts", "*.tsx", "*.mts", "*.cts"),
    "rust": ("*.rs",),
    "rs": ("*.rs",),
    "go": ("*.go",),
    "java": ("*.java",),
    "md": ("*.md", "*.markdown"),
    "markdown": ("*.md", "*.markdown"),
    "json": ("*.json",),
    "yaml": ("*.yaml", "*.yml"),
    "toml": ("*.toml",),
    "html": ("*.html", "*.htm"),
    "css": ("*.css",),
}
_MAX_SELECTOR_PATTERNS = 32


def _glob_alternatives(text: str) -> list[str] | None:
    """The positive gitignore-style globs ``text`` stands for; None when they cannot be known.

    ``text`` as a whole, its whitespace- and comma-separated parts, and every brace alternative of
    those are all taken (more patterns select more files: the cautious side). ``!negations`` are
    dropped: a file they exclude is still treated as searched.
    """
    parts = {text}
    for sep in (",", None):
        parts.update(p for p in text.split(sep) if p)
    found: list[str] = []
    for part in sorted(parts):
        part = part.strip()
        if not part or part.startswith("!"):
            continue
        alternatives = expand_braces(part)
        if alternatives is None:
            return None
        usable = [a.strip("/") for a in alternatives if a.strip("/")]
        if not usable:
            return None  # a positive glob with nothing to match by: not understood
        found.extend(usable)
        if len(found) > _MAX_SELECTOR_PATTERNS:
            return None
    return found


def _search_selector(tool_input: Mapping[str, Any]) -> subtree.Selector | None:
    """Which files a Grep call reads below its directory; None means every file.

    ripgrep's rules (measured with 15.0.0): a file that a positive ``-g`` glob matches is read
    whatever ``--type`` says (the glob wins), and a file no positive glob matches is not read; a
    glob that only negates (``!*.md``) leaves ``--type`` in force; ``--type`` alone narrows. So:

    * any positive ``glob`` decides ALONE: ``type`` is ignored. A glob that cannot be understood
      (it does not compile, it has too many alternatives, ``\\n`` escapes ...) does not narrow
      anything: every file is selected, which is never narrower than what ripgrep reads.
    * with only negated globs (or none) the ``type`` narrows, for the types listed in ``_RG_TYPES``.

    A glob without ``/`` selects by file name at any depth; one with ``/`` is tried both anchored
    at the directory and at any depth. Case is ignored (the policy's glob compiler folds case).
    """
    text = _text(tool_input.get("glob"))
    if text and text.strip():
        alternatives = _glob_alternatives(text)
        if alternatives is None:
            return None  # not understood: do not narrow (and ``type`` must not either)
        if alternatives:
            name_globs: list[Any] = []
            path_globs: list[Any] = []
            try:
                for pattern in alternatives:
                    if "/" in pattern:
                        path_globs.append(compile_glob(pattern))
                        path_globs.append(compile_glob("**/" + pattern))
                    else:
                        name_globs.append(compile_glob(pattern))
            except GlobError:
                return None  # ripgrep may understand what we cannot: read everything
            return lambda rel, name: (
                any(g.match(name) for g in name_globs) or any(g.match(rel) for g in path_globs)
            )
    elif tool_input.get("glob") not in (None, ""):
        return None  # a glob that is not a plain string (or is huge): not understood
    kind = _text(tool_input.get("type"))
    if kind and kind.strip().lower() in _RG_TYPES:
        type_globs = [compile_glob(p) for p in _RG_TYPES[kind.strip().lower()]]
        return lambda rel, name: any(g.match(name) for g in type_globs)
    return None


def _search_action(ctx: _Ctx, tool: str, tool_input: Mapping[str, Any]) -> Action:
    directory = _text(tool_input.get("path")) or ctx.cwd
    if not directory:
        return _gray(ctx, tool, "no-search-directory")
    notes: list[str] = []
    refs = _plain_operands(
        _refs(ctx, notes, directory, "read", cwds=(ctx.cwd,), dialect="tool", glob_literal=True)
    )
    pattern = _text(tool_input.get("pattern" if tool == "Glob" else "glob"))
    if tool == "Grep" and not (pattern and _pattern_is_path(pattern)):
        # A directory target reads everything below it that the glob / type lets through: look
        # for protected files there (ripgrep does not follow links). The Glob tool only LISTS
        # names, it reads no content: no look inside (its base path was checked above).
        # Without a ``glob`` Claude Code's Grep excludes the VCS directories itself
        # (``--glob '!.git'``); a user glob can re-include them, then they are scanned as well.
        user_glob = tool_input.get("glob") not in (None, "")
        refs += _scan_refs(
            ctx,
            notes,
            refs,
            "read",
            select=_search_selector(tool_input),
            follow_links=False,
            skip_names=frozenset() if user_glob else subtree.VCS_DIR_NAMES,
        )
    if pattern and _pattern_is_path(pattern):
        # A pattern that carries its own (possibly absolute or climbing) location reads there too.
        base = paths.normalize_path(
            directory, cwd=ctx.cwd, home=ctx.home, env=ctx.env, dialect="tool", glob_literal=True
        )
        anchor = base.key if base.absolute and not base.uncertain else None
        refs += _refs(ctx, notes, pattern, "read", cwds=(anchor,), dialect="tool", dynamic=True)
        notes.append("glob-pattern-path")
    elif pattern and tool == "Grep":
        # Grep's `glob` narrows WHICH files under `path` are searched: `path=<dir> glob=.env` reads
        # <dir>/.env, so the policy has to see that name (a literal child, not a wildcard).
        joined = directory.rstrip("/\\") + "/" + pattern
        refs += _refs(
            ctx, notes, joined, "read", cwds=(ctx.cwd,), dialect="tool", glob_literal=True
        )
    names, unknown = _unc_refs(ctx, refs)
    if names or unknown:
        notes.append("unc-network")
    reasons = tuple(dict.fromkeys(notes))
    return Action(
        tool=tool,
        paths=tuple(refs),
        domains=names,
        network=bool(names) or unknown,
        inside_project=_inside(refs),
        risk_tags=("network_egress",) if names or unknown else (),
        gray=bool(reasons),
        gray_reasons=reasons,
        **ctx.base,
    )


def _web_action(ctx: _Ctx, tool: str, tool_input: Mapping[str, Any]) -> Action:
    url = _text(tool_input.get("url"))
    if not url:
        return _gray(ctx, tool, "no-url")
    names, unknown = _domains_of([url])
    return Action(
        tool=tool,
        domains=names,
        network=True,
        risk_tags=("network_egress",),
        gray=unknown,
        gray_reasons=("unparseable-url",) if unknown else (),
        **ctx.base,
    )


def _mcp_action(ctx: _Ctx, tool: str) -> Action:
    parts = tool.split("__", 2)
    server = parts[1] if len(parts) >= 2 and parts[1] else None
    name = parts[2] if len(parts) == 3 and parts[2] else None
    return _gray(ctx, tool, "mcp-tool-not-reviewed", mcp_server=server, mcp_tool=name)


# --------------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------------


def normalize_event(
    payload: Mapping[str, Any],
    *,
    platform: Platform,
    env: Mapping[str, str] | None = None,
    home: str | None = None,
    budget_s: float = TIME_BUDGET_S,
    protected_globs: Sequence[str] | None = None,
    rule_globs: Sequence[subtree.RuleGlob] | None = None,
) -> list[Action]:
    """The Actions for one PreToolUse payload (never raises; never empty).

    Runs on the daemon's event loop, so the work is bounded: after ``budget_s`` seconds, more than
    ``MAX_ACTIONS`` commands, more than ``MAX_DISK_KEYS`` distinct disk lookups or ``MAX_REFS``
    paths, the rest of a shell line is classified lexically only (no glob expansion, no disk) and
    one gray Action whose reasons start with ``normalize-budget-exceeded`` is added last: the
    paths the words name still meet the deny and ask rules, the line can never be allowed.

    ``protected_globs``: the read-protection path globs (canonical keys) a recursive read of a
    directory is checked against (Grep / Glob on a directory, ``grep -r``, ...): the daemon derives
    them from the loaded policy; None means ``subtree.DEFAULT_PROTECTED_GLOBS``, an empty
    sequence turns the subtree look off.

    ``rule_globs``: every path glob of the policy's deny and ask rules, with the programs and access
    of its rule (``pipeline.rule_path_globs``). Only used once the budget has run out: from then on
    a path that is certainly inside the project and that none of them can select for this command
    is not carried into the Actions (no rule could look at it), which keeps the verdict's work
    small however many distinct commands follow. None: nothing is left out.
    """
    env = env if env is not None else os.environ
    base: dict[str, Any] = {"platform": platform}
    budget = _Budget(deadline=time.monotonic() + budget_s)
    ctx: _Ctx | None = None
    try:
        for key in ("session_id", "cwd", "permission_mode", "agent_id"):
            value = _text(payload.get(key))
            if value is not None:
                base[key] = value
        root, root_resolved = _project_root(payload, env, home)
        project, project_resolved = _project_keys(base.get("cwd"), root, root_resolved, home, env)
        if project is not None:  # on every Action of the event (``base`` is shared)
            base["project"] = project
            if project_resolved is not None:
                base["project_resolved"] = project_resolved
        ctx = _Ctx(
            platform=platform,
            env=env,
            home=home,
            cwd=base.get("cwd"),
            root=root,
            root_resolved=root_resolved,
            base=base,
            budget=budget,
            protected=subtree.matcher_for(
                subtree.DEFAULT_PROTECTED_GLOBS
                if protected_globs is None
                else tuple(protected_globs)
            ),
            rule_screen=None if rule_globs is None else subtree.rule_screens_for(tuple(rule_globs)),
            scratch=paths.scratchpad_for(base.get("session_id"), platform, env, home),
        )
        tool = payload.get("tool_name")
        if not isinstance(tool, str) or not tool:
            return [_gray(ctx, "?", "no-tool-name")]
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, Mapping):
            return [_gray(ctx, tool, "no-tool-input")]
        return _dispatch(ctx, tool, tool_input) or [_gray(ctx, tool, "no-action")]
    except _BudgetExceeded as exc:
        name = payload.get("tool_name")
        return [
            Action(
                tool=name if isinstance(name, str) and name else "?",
                gray=True,
                gray_reasons=("normalize-budget-exceeded", f"budget:{exc.why}"),
                **base,
            )
        ]
    except Exception as exc:  # noqa: BLE001 - normalization must never take the daemon down
        return [
            Action(
                tool="?",
                gray=True,
                gray_reasons=(f"internal-error:{type(exc).__name__}",),
                platform=platform,
                **{k: v for k, v in base.items() if k in ("project", "project_resolved")},
            )
        ]


def _dispatch(ctx: _Ctx, tool: str, tool_input: Mapping[str, Any]) -> list[Action]:
    if tool in SHELL_TOOLS:
        command = _text(tool_input.get("command"))
        if command is None:
            return [_gray(ctx, tool, "no-command", shell=SHELL_TOOLS[tool])]
        return _shell_actions(ctx, tool, SHELL_TOOLS[tool], command)
    if tool in FILE_READ_TOOLS:
        return [_file_action(ctx, tool, _text(tool_input.get("file_path")), "read")]
    if tool in FILE_WRITE_TOOLS:
        raw = _text(tool_input.get("file_path")) or _text(tool_input.get("notebook_path"))
        return [_file_action(ctx, tool, raw, "write")]
    if tool in SEARCH_TOOLS:
        return [_search_action(ctx, tool, tool_input)]
    if tool in ("WebFetch",):
        return [_web_action(ctx, tool, tool_input)]
    if tool == "WebSearch":
        return [Action(tool=tool, **ctx.base)]
    if tool in HARMLESS_TOOLS:
        return [Action(tool=tool, **ctx.base)]
    if tool.startswith("mcp__"):
        return [_mcp_action(ctx, tool)]
    return [_gray(ctx, tool, "unknown-tool")]
