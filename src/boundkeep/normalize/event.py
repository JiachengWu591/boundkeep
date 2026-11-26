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

import functools
import os
import re
import shlex
import time
from collections import deque
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Final

from boundkeep.normalize import bash, domains, paths, programs, psparse, subtree
from boundkeep.normalize.mcpnames import mcp_access
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
from boundkeep.normalize.psprograms import DEV_EXE_ENV
from boundkeep.policy.glob import GlobError, compile_glob
from boundkeep.policy.schema import too_broad

SHELL_TOOLS: dict[str, Shell] = {"Bash": "bash", "PowerShell": "powershell"}
FILE_WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
FILE_READ_TOOLS = frozenset({"Read"})
SEARCH_TOOLS = frozenset({"Glob", "Grep"})
# Tools that touch nothing on the machine: still "known", so a policy may allow them by name.
HARMLESS_TOOLS = frozenset({"ToolSearch", "TodoWrite"})

MAX_GIT_WALK = 16  # levels find_git_root climbs
MAX_GIT_WALK_ABOVE = 128  # levels the "repository root above the project" check climbs (R3-5)
PS_PARSE_BUDGET_S = 0.3  # the PowerShell helper's own limit (not charged to TIME_BUDGET_S)
TIME_BUDGET_S = 0.25  # normalize_event runs on the daemon's event loop
MAX_ACTIONS = 256  # simple commands handled per command line
MAX_DISK_KEYS = 64  # distinct paths looked up on disk per request
MAX_GLOB_DISK_KEYS = 256  # ... for the files a glob matched (a budget of their own)
# ... for the names as they are on disk that revision 40 adds (a glob match's own spelling, the
# matches only the second expansion finds): counted apart, and running out never raises
MAX_READING_DISK_KEYS = 64
# PathRefs only revision 40 finds, per request (apart from MAX_REFS; each costs rule time, about a
# millisecond, so the cap is small)
MAX_EXTRA_REFS = 128
# wall time of revision 40's second glob expansions and its disk lookups, per request: given back
# to the request's deadline, so it is not charged to the normalize budget
EXTRA_TIME_S = 0.25
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

# Package managers, task runners and build tools: most of their subcommands run the project's own
# code (scripts in package.json, a Makefile, setup hooks, build scripts, ``uv run``, ``npx``). The
# tables know some of them, so the ``exec`` tag below does not come from "not known" alone.
_CODE_RUNNERS: Final = frozenset(
    {
        "npm", "npx", "pnpm", "pnpx", "yarn", "bun", "bunx", "deno", "corepack",
        "pip", "pip3", "pipx", "pipenv", "poetry", "pdm", "hatch", "uv", "uvx", "rye", "tox", "nox",
        "conda", "mamba", "micromamba", "pixi", "invoke", "inv",
        "composer", "cargo", "go", "gradle", "gradlew", "mvn", "mvnw", "ant", "sbt", "lein",
        "make", "gmake", "nmake", "cmake", "ninja", "meson", "bazel", "bazelisk", "buck", "scons",
        "rake", "bundle", "gem", "dotnet", "msbuild", "just", "task", "mix", "swift", "flutter",
        "dart",
    }
)  # fmt: skip
_EXE_SUFFIXES: Final = (".exe", ".cmd", ".bat", ".ps1", ".com")


def _runs_project_code(program: str | None) -> bool:
    if not program:
        return False
    name = program.lower()
    for suffix in _EXE_SUFFIXES:
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name in _CODE_RUNNERS


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

# Directories whose programs are the system's own (an allow rule may rely on the name there). On a
# Windows host these count only in the bash dialect and without a drive letter: Git Bash keeps them
# under Git's own directory, where PATH finds ``cat`` too (measured).
_POSIX_SYSTEM_DIRS = frozenset(
    {
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
        "/opt/homebrew/bin", "/opt/homebrew/sbin",
    }
)  # fmt: skip
# The Windows ones (spec revision 15): exactly these directories, with a drive letter, under a
# variable of the daemon's own environment, or its Windows default when the variable is missing. No
# subdirectory counts (users may write ``System32\Tasks``), nor does another drive, ``\msys64`` or
# ``\cygwin`` (a folder made in ``C:\`` is writable by every authenticated user): measured ACLs.
_GIT_PROGRAM_DIRS = ("Git/cmd", "Git/bin", "Git/usr/bin", "Git/mingw64/bin", "Git/mingw32/bin")
_WINDOWS_SYSTEM_ROOTS: Final = (
    ("SystemRoot", "C:\\Windows", ("System32", "SysWOW64")),
    ("ProgramFiles", "C:\\Program Files", _GIT_PROGRAM_DIRS),
    ("ProgramFiles(x86)", "C:\\Program Files (x86)", _GIT_PROGRAM_DIRS),
)
_DRIVE_ABSOLUTE = re.compile(r'[A-Za-z]:(/[^/:*?"<>|]+)+')


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
    # Spec revision 40. ``kept_dirs``: (raw, key) of a PathRef -> the ``\\?\`` directories its
    # reading that keeps the names as on disk leads to, when a walk from the key does not get
    # there; walked after the operand's other roots, on ``late_scan``, as are the PathRefs marked
    # ``paths.EXTRA_READING``, so the walks revision 39 made keep their budget. ``extra_refs``:
    # those PathRefs so far (``MAX_EXTRA_REFS``); ``extra_s``: the time of revision 40's second
    # expansions and disk lookups (``EXTRA_TIME_S``).
    reading_lookups: dict[Any, Any] = field(default_factory=dict)
    kept_dirs: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    # those of ``kept_dirs`` an 8.3 name's Win32 reading leads to: Win32 programs get inside and
    # read the names there their own way, so they are walked with both readings (spec revision
    # 43, R42-6)
    kept_win32: set[str] = field(default_factory=set)
    extra_refs: int = 0
    extra_s: float = 0.0
    late_scan: subtree.ScanBudget = field(
        default_factory=lambda: subtree.ScanBudget(
            subtree.MAX_SCAN_ENTRIES, subtree.SCAN_TIME_BUDGET_S
        )
    )

    def reading_slot(self) -> bool:
        """May revision 40 look one more name up on disk? (``MAX_READING_DISK_KEYS``,
        ``EXTRA_TIME_S``, the request's deadline; never raises)"""
        return (
            len(self.reading_lookups) < MAX_READING_DISK_KEYS
            and self.extra_s < EXTRA_TIME_S
            and time.monotonic() < self.deadline
        )

    def extra_time(self, started: float) -> None:
        """Book the time since ``started`` as revision 40's own: given back to the deadline."""
        took = time.monotonic() - started
        self.extra_s += took
        self.deadline += took

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
    scratch: paths.SessionDir | None = None  # this session's scratchpad (None: no valid session)
    tool_results: paths.SessionDir | None = None  # this session's tool-results directory
    memory: paths.SessionDir | None = None  # this project's auto memory directory


@dataclass(slots=True)
class _Line:
    """What is known about the command line so far (one per shell tool call)."""

    cwds: tuple[str | None, ...]  # possible working directories; None = unknown
    # those that came from expanding a variable (``Set-Location $env:X``): a path resolved
    # against one is marked as expanded, or its key would carry the value (spec revision 37)
    expanded_cwds: set[str] = field(default_factory=set)
    written: set[str] = field(default_factory=set)  # keys written by earlier commands
    last_find: list[tuple[Word, Access]] = field(default_factory=list)
    line_gray: list[str] = field(default_factory=list)
    # what the line binds that no command carries (``BashResult.unshown``, spec revision 28)
    unshown: tuple[str, ...] = ()
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


def find_git_root(cwd: str, *, limit: int = MAX_GIT_WALK) -> str | None:
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
        for _ in range(limit):
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

# `git add -A`, `git commit -a` and `git stash` act on the whole work tree of the repository, with
# no operand that names a path: the paths they touch are the repository's, not the project's.
_GIT_WHOLE_TREE = frozenset({"add", "commit", "stash"})

# Directories `git add .` is not expected to stage: dependencies, caches and version control. The
# scan for protected names in `_add_may_stage_protected` leaves them out (a virtual environment
# holds files named like secrets, cacert.pem, and is almost always ignored).
_STAGE_SCAN_SKIP = subtree.VCS_DIR_NAMES | frozenset(
    {
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".hypothesis",
    }
)


def _stages_whole_repository(info: programs.CmdInfo) -> bool:
    """Does this `git add` stage the whole repository, whatever directory it runs in?

    `-A`, `--all` and `--no-ignore-removal` (each also by unique abbreviation) do, and so does any
    pathspec that starts with `:` (`:/`, `:(top)`, and the exclude-only magic `:!x`, `:^x`,
    `:(exclude)x`, which select everything but x; X1 review R5-1, R6-1). Only plain paths do not.
    """
    flags = set(info.flags)
    if "-A" in flags:
        return True
    if any(f.startswith("--a") and "--all".startswith(f) for f in flags):
        return True
    if any(f.startswith("--no-i") and "--no-ignore-removal".startswith(f) for f in flags):
        return True
    return info.pathspec_magic


def _add_may_stage_protected(
    ctx: _Ctx, st: _Line, info: programs.CmdInfo, notes: list[str]
) -> bool:
    """X1 review R3-3: could this `git add` put a protected file into the index?

    `git add -A` (or `.`, or a directory) stages an untracked `.env` that is not ignored, and the
    already allowed `git diff --cached` then prints it. The tree below the operand directories (the
    working directory when there is none) is looked at for names the read rules protect; one found
    makes the action gray (ask), never deny: the scan does not read `.gitignore`, so a deny would
    hit every project that keeps an ignored `.env` on disk. `-u` stages only tracked files and is
    left out.
    """
    if {"-u", "--update"} & set(info.flags):
        return False
    words = [w for w, _access in info.paths] or [Word(".")]
    targets = [w.text for w in words]
    if _stages_whole_repository(info) and ctx.root is not None:
        # from a sub-directory `-A`, `--all`, `:/` and `:(top)` still stage the whole repository
        # (X1 review R5-1): the project root is looked at too, not only the working directory
        targets.append(ctx.root.raw)
    for target in targets:
        refs = _refs(
            ctx,
            notes,
            target,
            "read",
            cwds=st.cwds,
            expanded_cwds=st.expanded_cwds,
            dialect=st.shell,
            dynamic=False,
        )
        # (a directory that only the reading keeping the dots finds, ``kq.`` without ``kq``, is
        # looked at as well: spec revision 40, R39-4)
        directories = [
            r
            for r in refs
            if (native := _native_dir(r)) is not None
            and (os.path.isdir(native) or (r.raw, r.key) in ctx.budget.kept_dirs)
        ]
        if directories and _scan_refs(ctx, notes, directories, "read", skip_names=_STAGE_SCAN_SKIP):
            return True
    return False


def _cwds_below_project(ctx: _Ctx, st: _Line) -> bool:
    """Is every possible working directory inside the project, and one of them below its root?

    Lexical, so it holds on the fake machines too. A working directory that is not known, or one
    outside the project (another repository, perhaps), is a no.
    """
    if ctx.root is None:
        return False
    starts = list(st.cwds) if st.cwds else [ctx.cwd]
    known = [c for c in starts if c]
    if not known or len(known) != len(starts):
        return False
    roots = {ctx.root.key.rstrip("/")}
    if ctx.root_resolved is not None:
        roots.add(ctx.root_resolved.key.rstrip("/"))
    below = False
    for start in known:
        key = paths.normalize_path(
            start, cwd=None, home=ctx.home, env=ctx.env, dialect="tool", literal=True
        ).key.rstrip("/")
        if key in roots:
            continue
        if not any(key.startswith(root + "/") for root in roots):
            return False
        below = True
    return below


def _top_words(ctx: _Ctx, st: _Line, info: programs.CmdInfo) -> list[tuple[Word, Access]]:
    """``info.top_paths`` as paths below the project root (spec revision 18).

    git reads them from the top of the repository whatever the working directory: ``git log -p``
    from a sub-directory prints the top-level ``.env`` (measured). Like the whole-repository check
    of ``git add`` (X1 review R5-1) the project root stands for that top; nothing is added unless
    the working directory is below the root (at the root they are the paths already listed).
    """
    if not info.top_paths or ctx.root is None or not _cwds_below_project(ctx, st):
        return []
    root = ctx.root.raw.rstrip("/\\")
    out: list[tuple[Word, Access]] = []
    for word, access in info.top_paths:
        text = root if word.text in ("", ".") else f"{root}/{word.text}"
        out.append((Word(text, word.expands, word.glob, word.quoted), access))
    return out


def _git_root_above_project(ctx: _Ctx, st: _Line) -> bool:
    """X1 review R3-5: is the repository root a strict ancestor of the project directory?

    Then a command with no path operand reaches files above the project (a monorepo sub-directory,
    a dotfiles repository in the home directory). Looks at the disk, so it is off wherever the
    subtree look is off (the fake machines of ``boundkeep test`` and the evaluation).
    """
    if ctx.protected.empty or ctx.budget.lexical or ctx.root is None:
        return False
    starts = [c for c in st.cwds if c] or ([ctx.cwd] if ctx.cwd else [])
    if not starts or len(starts) != len(st.cwds):
        return False  # a directory that is not known is gray on its own
    project_keys = {ctx.root.key} | ({ctx.root_resolved.key} if ctx.root_resolved else set())
    for start in starts:
        top = find_git_root(start, limit=MAX_GIT_WALK_ABOVE)
        if top is None:
            continue
        repo = paths.normalize_path(
            top, cwd=None, home=ctx.home, env=ctx.env, dialect="tool", literal=True
        ).key.rstrip("/")
        if any(key != repo and key.startswith(repo + "/") for key in project_keys):
            return True
    return False


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


_EXPANDED: Final = "variable-expanded"  # paths: a variable in the text was expanded
# paths: not relative, yet the key took the working directory's drive or path (``C:x``, ``\x``)
_CWD_READINGS: Final = frozenset({"drive-relative", "rooted-current-drive"})


def _expanded(ref: PathRef) -> PathRef:
    """``ref`` marked as coming from an expanded variable: the send gate shows it as written,
    never its key (spec revision 37, R36-1). Only a note: it makes nothing uncertain."""
    if _EXPANDED in ref.reasons:
        return ref
    return ref.model_copy(update={"reasons": _with(ref.reasons, _EXPANDED)})


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
    results = ctx.tool_results
    memory = ctx.memory
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
        in_session_tool_results=(
            not uncertain and results is not None and results.contains(norm, resolved=resolved)
        ),
        in_project_memory=(
            not uncertain and memory is not None and memory.contains(norm, resolved=resolved)
        ),
        reasons=tuple(reasons),
    )


def _mark_hard_linked(refs: list[PathRef], resolved: paths.NormPath) -> list[PathRef]:
    """A path that is a hard link is not shown to be where its name says (X1 review, H-6).

    The file has another name somewhere else: inside the project it can be the policy, a settings
    file or a secret, and every rule that works on the name misses it. No allow rule may rely on
    ``inside_project``, the scratchpad, the tool-results directory or the project memory for it,
    and no deny rule may skip it as such a file (the deny / ask rules still see the name, and a
    ``path_outside_project`` rule sees "not known to be inside").
    """
    if paths.HARD_LINKED not in resolved.reasons:
        return refs
    return [
        ref.model_copy(
            update={
                "inside_project": None if ref.inside_project is True else ref.inside_project,
                "in_scratchpad": False,
                "in_session_tool_results": False,
                "in_project_memory": False,
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


_READING_LOOKUPS_SPENT: Final = "budget:reading-lookups"
_EXTRA_PATHS_SPENT: Final = "budget:extra-paths"
# A reading's disk lookup failed (``realpath`` of a junction that leads to a file raises): this
# action is not analysed whole, the rest of the line is (an "internal-error" is never sent)
_LOOKUP_FAILED: Final = "internal-error:reading-lookup"
_FAILED: Final = object()  # (a memoized lookup that failed)


def _note(notes: list[str], note: str) -> None:
    if note not in notes:
        notes.append(note)


def _reading_lookup(ctx: _Ctx, notes: list[str], memo_key: Any, compute: Any) -> Any:
    """A disk lookup revision 40 adds, memoized; None when ``MAX_READING_DISK_KEYS`` (or the
    request's time) is spent, or when it fails. Either leaves a gray, unanalysed note and nothing
    raises: the lookups revision 39 made keep their count, and nothing here sends the line into
    lexical mode or makes the whole call one gray action."""
    memo = ctx.budget.reading_lookups
    if memo_key in memo:
        value = memo[memo_key]
        if value is _FAILED:
            _note(notes, _LOOKUP_FAILED)
            return None
        return value
    if not ctx.budget.reading_slot():
        _note(notes, _READING_LOOKUPS_SPENT)
        return None
    started = time.monotonic()
    try:
        value = compute()
    except (OSError, ValueError):
        _note(notes, _LOOKUP_FAILED)
        value = _FAILED
    finally:
        ctx.budget.extra_time(started)
    memo[memo_key] = value
    return None if value is _FAILED else value


def _existing_realpath(native: str) -> str | None:
    """``realpath`` of ``native``, when what it leads to is there (None: it is not)."""
    found = _realpath(native)
    return found if os.path.lexists(found) else None


def _all_on_disk(
    ctx: _Ctx, notes: list[str], candidates: Sequence[str | None]
) -> list[tuple[str, int]]:
    """Each of ``candidates`` (texts of drive paths) that leads to something on disk, as
    ``realpath`` gives it through ``\\\\?\\``, with its index; each one asked is one of revision
    40's lookups (``_reading_lookup``; spent: a gray note). Every candidate is asked: revision 42
    stopped at the first that existed, and a clean folder named ``VAULTS~1.`` then hid where
    Win32 reads ``VAULTS~1`` (spec revision 43, R42-4)."""
    out: list[tuple[str, int]] = []
    asked: set[str] = set()
    for index, candidate in enumerate(candidates):
        if not candidate or candidate in asked:
            continue
        asked.add(candidate)
        native = _extended_native(candidate.replace("/", "\\"))
        if native is None:
            continue
        found = _reading_lookup(
            ctx, notes, ("on-disk", native), lambda native=native: _existing_realpath(native)
        )
        if found is not None:
            out.append((str(found), index))
    return out


def _short_and_reading(reasons: Sequence[str]) -> bool:
    """Unsure because an 8.3 short name was not expanded and of which reading a program takes,
    and of nothing else (``VAULTS~1.``, ``notes~1.``, ``DEEPER~1/k9.``; spec revision 42)."""
    return paths.short_reading_only(reasons) and paths.reading_only(
        [r for r in reasons if r != "short-name-unresolved"]
    )


def _admit_extra(ctx: _Ctx, notes: list[str], refs: Sequence[PathRef]) -> list[PathRef]:
    """The PathRefs only revision 40 finds that fit in ``MAX_EXTRA_REFS``; the rest are left out
    with a gray, unanalysed note. Never raises: they cannot push revision 39's own PathRefs over
    ``MAX_REFS`` (spec revision 40)."""
    room = max(0, MAX_EXTRA_REFS - ctx.budget.extra_refs)
    kept = list(refs[:room])
    ctx.budget.extra_refs += len(kept)
    if len(kept) < len(refs):
        _note(notes, _EXTRA_PATHS_SPENT)
    return kept


def _extended_native(text: str) -> str | None:
    """``text`` as a ``\\\\?\\`` path, when it is a path on a fixed local drive (else None)."""
    body = text[4:] if text.startswith("\\\\?\\") else text
    if len(body) < 3 or body[1] != ":" or body[2] != "\\" or "/" in body or "\x00" in body:
        return None
    if any(part in (".", "..") for part in body[3:].split("\\")):
        return None
    return "\\\\?\\" + body if paths.is_fixed_drive(body[0]) else None


def _record_kept_dir(
    ctx: _Ctx, owner: tuple[str, str], resolved: str, *, win32: bool = False
) -> None:
    """Remember where the reading that keeps the names as on disk leads (``resolved``, a real
    path), for the PathRef ``owner`` (raw, key), when a walk from the key does not get there:
    a name on the way ends in a dot or a space (spec revision 40, R39-2). ``win32``: the place is
    where the Win32 reading of an 8.3 name leads; it is walked with both readings (R42-6)."""
    native = _extended_native(resolved)
    if native is None:
        return
    if not any(part.endswith((".", " ")) for part in native[7:].split("\\")):
        return
    dirs = ctx.budget.kept_dirs.setdefault(owner, [])
    if native not in dirs:
        dirs.append(native)
    if win32:
        ctx.budget.kept_win32.add(native)


def _glob_refs(
    ctx: _Ctx,
    norm: paths.NormPath,
    access: Access,
    notes: list[str],
    *,
    dotfiles: bool = False,
    kept_text: str | None = None,
) -> list[PathRef]:
    """PathRefs for the files an unquoted glob matches on disk (the text itself stays uncertain).

    ``dotfiles``: the wildcard also matches names that start with a dot (PowerShell, unlike Bash).
    ``kept_text``: the glob as a program that keeps trailing dots reads it (``paths.reading_text``),
    when that differs from the key. The expansion is the Win32 one first, as before; a match whose
    name ends in a dot or a space, or such a ``kept_text``, makes a second one with the names read
    as they are on disk (spec revision 40, R39-1).
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
    matches = found.matches[:MAX_GLOB_MATCHES]
    for match in matches:
        found_norm = paths.normalize_path(match, cwd=None, home=None, dialect="tool", literal=True)
        # (``data~1`` or what is below it, a long name like an 8.3 one: walked as when written,
        # spec revision 43, R42-5. The second expansion's matches have a name ending in a dot or
        # a space on the way, so they are unsure of their reading too: ``_match_kept_forms``)
        forms = _resolved_forms(ctx, match, found_norm, access, ("glob-match",), long_notes=notes)
        refs += forms + _match_kept_forms(ctx, notes, match, found_norm, access, forms)
    if (
        norm.flavor == "windows"
        and os.name == "nt"
        and found.status != "unsupported"
        and (found.dotted or kept_text is not None)
    ):
        refs += _literal_glob_refs(ctx, norm, access, notes, dotfiles, kept_text, matches)
    return refs


def _literal_glob_refs(
    ctx: _Ctx,
    norm: paths.NormPath,
    access: Access,
    notes: list[str],
    dotfiles: bool,
    kept_text: str | None,
    earlier: Sequence[str],
) -> list[PathRef]:
    """The glob again with the names read as they are on disk (``\\\\?\\`` paths), its literal
    part as ``kept_text`` keeps it: ``kq./.e*`` looks in ``kq.``, ``???`` keeps ``kq.`` when there
    is no ``kq`` (spec revision 40). Only the matches the Win32 expansion did not find, after
    those, up to ``MAX_GLOB_MATCHES`` in all; marked ``paths.EXTRA_READING``, so they are walked
    after the operand's other roots. Its time is its own (``EXTRA_TIME_S``, given back to
    the request's deadline); when that is spent the expansion stops with a gray, unanalysed note
    and nothing raises."""
    source = norm
    if kept_text is not None:
        source = paths.NormPath(
            kept_text,
            paths.windows_fold(kept_text),
            "windows",
            True,
            True,
            ("glob", paths.KEPT_READING),
        )
    started = time.monotonic()
    left = EXTRA_TIME_S - ctx.budget.extra_s
    if left <= 0 or started >= ctx.budget.deadline:
        # (its own time is spent, or the request's is: then revision 39 is about to stop too)
        _note(notes, _READING_LOOKUPS_SPENT)
        return []
    again = paths.expand_glob(
        source,
        limit=MAX_GLOB_MATCHES,
        deadline=started + left,
        dotfiles=dotfiles,
        literal=True,
    )
    ctx.budget.extra_time(started)  # not charged to the request
    if again.status == "budget":
        _note(notes, _READING_LOOKUPS_SPENT)
        return []
    incomplete = again.status == "too-many"
    if again.status == "unsupported" and "glob-not-expanded" not in notes:
        notes.append("glob-not-expanded")
    seen = {paths.windows_fold(m) for m in earlier}
    fresh: list[str] = []
    for match in again.matches:
        folded = paths.windows_fold(match)
        if folded not in seen:
            seen.add(folded)
            fresh.append(match)
    room = max(0, MAX_GLOB_MATCHES - len(earlier))
    if len(fresh) > room:
        fresh, incomplete = fresh[:room], True
    if incomplete:
        _note(notes, "glob-too-many-matches")
    refs: list[PathRef] = []
    for match in fresh:
        found_norm = paths.normalize_path(match, cwd=None, home=None, dialect="tool", literal=True)
        forms = _resolved_forms(
            ctx, match, found_norm, access, ("glob-match", paths.EXTRA_READING), notes=notes
        )
        refs += forms + _match_kept_forms(ctx, notes, match, found_norm, access, forms)
    return refs


def _match_kept_forms(
    ctx: _Ctx,
    notes: list[str],
    match: str,
    found_norm: paths.NormPath,
    access: Access,
    existing: Sequence[PathRef],
) -> list[PathRef]:
    """Where a glob match that is unsure only of its reading leads with its name as on disk
    (``\\\\?\\`` and the match: Git Bash and Node read ``kq.``, not ``kq``; spec revision 40,
    R39-1, R39-2). The match is its spelling on disk, never expanded again: a ``$`` or ``%`` in a
    name is a character. A place other than the key's is a PathRef of its own ("glob-match",
    ``paths.EXTRA_READING``); the same key is remembered for the walk. A match under a written
    8.3 name (``DEEPER~1/k*`` matched ``k9.``) is looked up the same way: ``\\\\?\\`` takes the
    short name on disk (spec revision 42, R41-4)."""
    if not (
        found_norm.uncertain
        and (paths.reading_only(found_norm.reasons) or _short_and_reading(found_norm.reasons))
    ):
        return []
    if found_norm.flavor != "windows" or os.name != "nt" or not paths.is_local_disk(found_norm):
        return []
    if found_norm.key.count("/") > MAX_KEY_DEPTH:
        return []
    native = _extended_native(match)
    if native is None:
        return []
    resolved = _reading_lookup(ctx, notes, ("realpath", native), lambda: _realpath(native))
    if resolved is None:
        return []
    real = paths.normalize_path(resolved, cwd=None, home=None, dialect="tool", literal=True)
    if real.is_device or not paths.is_local_disk(real):
        return []
    _record_kept_dir(ctx, (match, real.key), resolved)
    if any(ref.key == real.key for ref in existing):
        return []
    return [
        _make_ref(
            ctx,
            match,
            real,
            access,
            uncertain=True,
            reasons=_with(
                real.reasons,
                "resolved-on-disk",
                paths.KEPT_READING,
                "glob-match",
                paths.EXTRA_READING,
            ),
            resolved=True,
        )
    ]


def _resolved_forms(
    ctx: _Ctx,
    raw: str,
    norm: paths.NormPath,
    access: Access,
    extra_reasons: Sequence[str],
    *,
    notes: list[str] | None = None,
    long_notes: list[str] | None = None,
) -> list[PathRef]:
    """A certain path as a PathRef, plus its on-disk resolved form when that differs; both carry
    ``extra_reasons`` ("glob-match": the send gate leaves out an expanded match's disk form too,
    whose text is the match all the same, spec revision 38, R37-1). "glob-match" only describes
    the path (``paths._INFO_REASONS``): a recursive read still walks a match that is unsure only
    of its reading, and its disk form (spec revision 39, R38-1). ``notes`` given: the lookup is
    one revision 40 adds (``_reading_lookup``), not counted with the earlier ones.
    ``long_notes`` given: a match named like an 8.3 name that the disk gives back as it is gets
    the certain form a written one gets (``_long_name_forms``, spec revision 43, R42-5)."""
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
    if notes is None:
        resolved = _disk_resolve(ctx, norm, glob="glob-match" in extra_reasons)
    else:
        memo_key = (norm.key, norm.reasons)
        known = ctx.budget.resolved.get(memo_key) or ctx.budget.glob_resolved.get(memo_key)
        resolved = known or _reading_lookup(
            ctx, notes, ("resolve", memo_key), lambda: paths.resolve_on_disk(norm)
        )
        if resolved is None:
            return refs
    if resolved.key != norm.key:
        refs.append(
            _make_ref(
                ctx,
                raw,
                resolved,
                access,
                uncertain=resolved.uncertain,
                reasons=_with(resolved.reasons, "resolved-on-disk", *extra_reasons),
                resolved=True,
            )
        )
    refs = _mark_hard_linked(refs, resolved)
    if long_notes is not None:
        refs += _long_name_forms(ctx, long_notes, raw, resolved, access, refs, extra_reasons)
    return refs


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
        kept_text = None
        if norm.flavor == "windows" and os.name == "nt":
            kept_text = paths.reading_text(
                text,
                cwd=cwd,
                home=ctx.home,
                env=ctx.env,
                dialect=dialect,  # type: ignore[arg-type]
            )
        return refs + _glob_refs(
            ctx, norm, access, notes, dotfiles=dialect == "powershell", kept_text=kept_text
        )
    if "brace" in norm.reasons:
        return refs
    # Disk forms: a symlink / junction / 8.3 name that leads somewhere else (paths.resolve_on_disk
    # itself refuses anything uncertain for other reasons than an unresolved short name or which
    # reading a program takes: unsure of the reading, a deny rule still has to see the target).
    reading = norm.uncertain and paths.reading_only(norm.reasons)
    if (
        norm.absolute
        and (not norm.uncertain or "short-name-unresolved" in norm.reasons or reading)
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
        if reading:
            refs += _kept_forms(ctx, notes, text, access, cwd, dialect, refs)
        elif norm.uncertain and "short-name-unresolved" in norm.reasons:
            # (also when the disk gives the same key: ``notes~1.`` is a long name, R41-3)
            refs += _resolved_kept_forms(
                ctx, notes, text, norm, resolved, access, cwd, dialect, refs
            )
        refs += _long_name_forms(ctx, notes, text, resolved, access, refs)
    if not uncertain and norm.flavor == "posix" and _posix_host() and _has_dotdot(text):
        refs += _dotdot_forms(ctx, text, norm, access, cwd, dialect, refs)
    return refs


def _long_name_forms(
    ctx: _Ctx,
    notes: list[str],
    text: str,
    resolved: paths.NormPath,
    access: Access,
    existing: Sequence[PathRef],
    extra_reasons: Sequence[str] = (),
) -> list[PathRef]:
    """A name that looks like an 8.3 one (``data~1``, ``notes~1``) and that the disk gives back as
    it is: when it exists it is a long name, not a short one left unexpanded (spec revision 43,
    R42-5). ``realpath`` keeps such a name, so the resolved form stayed unsure and was never
    walked. One of revision 40's lookups (``_reading_lookup``) asks whether it exists; then a
    certain PathRef of that place is added and walked. The written PathRef stays unsure, so the
    allow side sees what it saw. Unsure for another reason, or only of a reading (that is
    ``_resolved_kept_forms``'s): nothing. ``extra_reasons``: those of a glob match's other forms
    ("glob-match": the request does not show it, ``_resolved_forms``)."""
    if not (resolved.uncertain and "short-name-unresolved" in resolved.reasons):
        return []
    if not paths.short_reading_only(resolved.reasons) or _short_and_reading(resolved.reasons):
        return []
    if resolved.flavor != "windows" or os.name != "nt" or not paths.is_local_disk(resolved):
        return []
    if resolved.key.count("/") > MAX_KEY_DEPTH:
        return []
    native = _extended_native(resolved.key.replace("/", "\\"))
    if native is None:
        return []
    found = _reading_lookup(ctx, notes, ("on-disk", native), lambda: _existing_realpath(native))
    if found is None:
        return []
    real = paths.on_disk_names(
        paths.normalize_path(str(found), cwd=None, home=None, dialect="tool", literal=True)
    )
    if real.uncertain or real.key != resolved.key or not paths.is_local_disk(real):
        return []
    if any(ref.key == real.key and not ref.uncertain for ref in existing):
        return []
    ref = _make_ref(
        ctx,
        text,
        real,
        access,
        uncertain=False,
        reasons=_with(real.reasons, "resolved-on-disk", *extra_reasons),
        resolved=True,
    )
    return _mark_hard_linked([ref], resolved)  # (a hard link found on the way stays one)


def _resolved_kept_forms(
    ctx: _Ctx,
    notes: list[str],
    text: str,
    norm: paths.NormPath,
    resolved: paths.NormPath,
    access: Access,
    cwd: str | None,
    dialect: str,
    existing: Sequence[PathRef],
) -> list[PathRef]:
    """A path written with an 8.3 short name whose form on disk is unsure only of its reading
    (``SECRET~1`` is ``secretstorage.`` there, ``DEEPER~1/k9.``; spec revision 41, R40-3), or
    whose written text is (``VAULTS~1.``, and ``notes~1.``, a long name that looks like a short
    one: the disk gives it the same key; revision 42, R41-3).

    The written form is not walked (an unresolved short name is not a reading), and the walk from
    the resolved key opens the names without their dots. So the names as on disk are resolved once
    more through ``\\\\?\\``: the text that keeps the written dots (``paths.reading_text``) and
    the key, the one Win32 opens (``VAULTS~1.`` is not a name on disk, ``VAULTS~1`` is; a clean
    folder named ``VAULTS~1.`` beside it is, and both are looked up, spec revision 43, R42-4).
    Each is one of revision 40's own lookups (``_reading_lookup``). Each place is remembered for
    the second walk (``_record_kept_dir``; the key's is walked with both readings, R42-6); a place
    other than every PathRef so far (``k9.`` is a junction) is a PathRef of its own, marked
    ``paths.EXTRA_READING``. A name the disk gives back as it is written (``data~1``) is a long
    name there (``paths.on_disk_names``, R42-5). A short name with no dotted name behind it costs
    no lookup.
    """
    if not (
        (resolved.uncertain and paths.reading_only(resolved.reasons))
        or _short_and_reading(norm.reasons)
    ):
        return []
    if norm.flavor != "windows" or os.name != "nt" or not paths.is_local_disk(resolved):
        return []
    kept = paths.reading_text(
        text,
        cwd=cwd,
        home=ctx.home,
        env=ctx.env,
        dialect=dialect,  # type: ignore[arg-type]
    )
    out: list[PathRef] = []
    # (both readings, each where it leads, spec revision 43, R42-4; index 1, the key, is what a
    # Win32 program opens through the 8.3 name, and it reads the names inside its own way, R42-6)
    for found, index in _all_on_disk(ctx, notes, (kept, norm.key)):
        real = paths.on_disk_names(
            paths.normalize_path(found, cwd=None, home=None, dialect="tool", literal=True)
        )
        if real.is_device or not paths.is_local_disk(real):
            continue
        _record_kept_dir(ctx, (text, real.key), found, win32=index == 1)
        # (a PathRef of that place that cannot be walked does not count: ``data~1`` written
        # has the key of the long name the disk gave back, and stays unsure, R42-5)
        if any(ref.key == real.key and _native_dir(ref) is not None for ref in (*existing, *out)):
            continue
        out.append(
            _make_ref(
                ctx,
                text,
                real,
                access,
                uncertain=True,
                reasons=_with(
                    real.reasons, "resolved-on-disk", paths.KEPT_READING, paths.EXTRA_READING
                ),
                resolved=True,
            )
        )
    return out


def _kept_forms(
    ctx: _Ctx,
    notes: list[str],
    text: str,
    access: Access,
    cwd: str | None,
    dialect: str,
    existing: Sequence[PathRef],
) -> list[PathRef]:
    """``keys./x``: where the reading that keeps the dots goes (Git Bash, Node's file reads).

    The key has them stripped, so ``resolve_on_disk`` follows the other reading. ``keys.`` next to
    ``keys`` can be a link of its own. The path stays uncertain whatever this finds. A real
    folder ``keys.`` has the key of ``keys``: no PathRef of its own, but a recursive read walks it
    all the same (``_record_kept_dir``, spec revision 40, R39-2).
    """
    kept = paths.reading_text(
        text,
        cwd=cwd,
        home=ctx.home,
        env=ctx.env,
        dialect=dialect,  # type: ignore[arg-type]
    )
    if kept is None:
        return []
    try:
        resolved = _disk_realpath(ctx, "\\\\?\\" + kept.replace("/", "\\"))
    except (OSError, ValueError):
        # (a junction that leads to a file: up to revision 39 this made the whole call one gray
        # action; now only this action is not analysed whole, spec revision 40)
        _note(notes, _LOOKUP_FAILED)
        return []
    real = paths.normalize_path(resolved, cwd=None, home=None, dialect="tool", literal=True)
    if not real.is_device and paths.is_local_disk(real):
        _record_kept_dir(ctx, (text, real.key), resolved)
    if any(ref.key == real.key for ref in existing):
        return []
    return [
        _make_ref(
            ctx,
            text,
            real,
            access,
            uncertain=True,
            reasons=_with(real.reasons, "resolved-on-disk", paths.KEPT_READING),
            resolved=True,
        )
    ]


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
    expanded_cwds: Collection[str] = frozenset(),
) -> list[PathRef]:
    """All PathRefs of one path word: per brace result, per possible working directory.

    ``expanded_cwds``: the working directories that came from expanding a variable (spec revision
    37, R36-1). A relative path resolved against one is marked as expanded, and so are ``C:x``
    and ``\\x`` when the first working directory is one (revision 38); so is every form the disk
    gives a path whose own text was expanded (a link's target, an 8.3 name, a kept reading, ``..``
    after a link, a glob's matches and their targets), whose keys carry the value just the same.
    The same path from two working directories that are one directory, one of them expanded, is
    kept once, marked (revision 38)."""
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
            refs = _refs_one(
                ctx,
                notes,
                text,
                access,
                cwd=cwd,
                dialect=dialect,
                dynamic=dynamic,
                glob_literal=glob_literal,
            )
            # the first one is the path as written (``_refs_one``); ``C:x`` and ``\x`` take the
            # first working directory's path or drive as well (spec revision 38, R37-3)
            if refs and (
                (
                    (relative or not _CWD_READINGS.isdisjoint(refs[0].reasons))
                    and cwd is not None
                    and cwd in expanded_cwds
                )
                or _EXPANDED in refs[0].reasons
            ):
                refs = [_expanded(ref) for ref in refs]
            for ref in refs:
                # one directory can be two working directories (the event's cwd is its text, a
                # cd target its key): the same path from both, one marked, is one ref, marked
                # (spec revision 38, R37-2)
                slot = (
                    ref.raw,
                    ref.key,
                    ref.access,
                    ref.uncertain,
                    tuple(r for r in ref.reasons if r != _EXPANDED),
                )
                if slot not in out or _EXPANDED in ref.reasons:
                    out[slot] = ref
    refs = list(out.values())
    extra = [r for r in refs if paths.EXTRA_READING in r.reasons]
    ctx.budget.add_refs(len(refs) - len(extra))
    if not extra:
        return refs
    admitted = {id(r) for r in _admit_extra(ctx, notes, extra)}
    return [r for r in refs if paths.EXTRA_READING not in r.reasons or id(r) in admitted]


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
    # Not casefold: Windows does not read \\localho{U+017F}t as this machine (measured)
    low = paths.windows_fold(server)
    computer = ctx.env.get("COMPUTERNAME") or ctx.env.get("computername")
    if low in _LOCAL_UNC_SERVERS or (computer and low == paths.windows_fold(computer)):
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
        if host is None or host.kind == "unknown" or not server.isascii():
            # IDNA reads U+017F as "s", so a non-ASCII name could pass for localhost or an allowed
            # domain. A share is not a URL: that is not what Windows reads there (measured).
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
    if (ref.uncertain and not paths.reading_only(ref.reasons)) or not ref.key:
        return None
    if ref.key == _SYNTHETIC_KEY:
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

    Two passes (spec revision 40): the first walks what revision 39 walked, the same roots in the
    same order on the shared budget, asking what it asked (a directory whose name on disk a Win32
    call does not open, and the link count of ``x.`` as named on disk, are put off); the second,
    on a budget of its own, walks what only revision 40 looks at: the directories the names as on
    disk lead to (``_Budget.kept_dirs``), the PathRefs marked ``paths.EXTRA_READING`` and what the
    first pass put off. The hits revision 39 did not report are marked too and counted apart
    (``_admit_extra``), so a deny the first pass finds stays whatever the second one meets.
    """
    if ctx.budget.lexical or ctx.protected.empty:
        return []
    out: list[PathRef] = []  # the hits revision 39 reported too
    extra: list[PathRef] = []
    seen: set[str] = set()
    walked: set[tuple[str, str]] = set()
    later: list[tuple[str, PathRef, subtree.ScanResult | None, bool]] = []
    stopped = False
    for ref in refs:
        root = _native_dir(ref)
        if root is None:
            # (a place the disk showed for it is walked all the same: ``notes~1.`` stays unsure,
            # a long name that looks like a short one, spec revision 42, R41-3)
            later.extend(
                (kept, ref, None, True) for kept in ctx.budget.kept_dirs.get((ref.raw, ref.key), ())
            )
            continue
        if paths.EXTRA_READING in ref.reasons:
            later.append((root, ref, None, False))
        elif ref.key not in seen and not stopped:
            seen.add(ref.key)
            if ctx.budget.scan.spent:
                notes.append("recursive-scan-budget")
                stopped = True  # (revision 39 stopped here; the second pass still runs)
            else:
                walked.add((_fold_root(ref, root), ref.key))
                result = _scan_one(
                    ctx,
                    notes,
                    root,
                    ref,
                    access,
                    ctx.budget.scan,
                    out,
                    extra,
                    select=select,
                    follow_links=follow_links,
                    skip_names=skip_names,
                    defer=True,
                )
                if result.left:
                    later.append(("", ref, result, False))
        later.extend(
            (kept, ref, None, True) for kept in ctx.budget.kept_dirs.get((ref.raw, ref.key), ())
        )
    for root, ref, resume, kept in later:
        if resume is None:
            slot = (_fold_root(ref, root), ref.key)
            if slot in walked:
                continue
            walked.add(slot)
        if ctx.budget.late_scan.spent:
            notes.append("recursive-scan-budget")
            break
        _scan_one(
            ctx,
            notes,
            root,
            ref,
            access,
            ctx.budget.late_scan,
            extra,
            extra,
            select=select,
            follow_links=follow_links,
            skip_names=skip_names,
            late=True,
            # (one an 8.3 name's Win32 reading leads to: Win32 programs read inside it their own
            # way, so it is walked with both readings, spec revision 43, R42-6)
            kept=kept and root not in ctx.budget.kept_win32,
            resume=resume,
        )
    ctx.budget.add_refs(len(out))
    return list(dict.fromkeys(out + _admit_extra(ctx, notes, list(dict.fromkeys(extra)))))


def _fold_root(ref: PathRef, root: str) -> str:
    return paths.windows_fold(root) if ref.flavor == "windows" else root


def _scan_one(
    ctx: _Ctx,
    notes: list[str],
    root: str,
    ref: PathRef,
    access: Access,
    budget: subtree.ScanBudget,
    out: list[PathRef],
    extra: list[PathRef],
    *,
    select: subtree.Selector | None,
    follow_links: bool,
    skip_names: frozenset[str],
    defer: bool = False,
    late: bool = False,
    kept: bool = False,
    resume: subtree.ScanResult | None = None,
) -> subtree.ScanResult:
    """One walk of ``_scan_refs``: its notes, and its hits as PathRefs, appended to ``out`` (what
    revision 39 reported too) or ``extra`` (marked ``paths.EXTRA_READING``)."""
    before = budget.elapsed
    result = subtree.scan(
        root,
        [ref.key],
        windows=ref.flavor == "windows",
        matcher=ctx.protected,
        budget=budget,
        select=select,
        skip_names=skip_names,
        defer=defer,
        late=late,
        kept=kept,
        resume=resume,
    )
    ctx.budget.deadline += budget.elapsed - before  # not charged to the request
    if result.status == "budget":
        notes.append("recursive-scan-budget")
    elif result.status == "unreadable":
        notes.append("recursive-scan-unreadable")
    if result.dir_links and follow_links:
        notes.append("recursive-scan-link")
    if result.hard_links:
        notes.append("recursive-scan-hardlink")  # R-3: a name proves nothing about the file
    # Below a root whose text was expanded, a hit's key holds the value too: it carries the
    # root's markers, so the send gate shows it as written or leaves it out (spec revision 40)
    carried: tuple[str, ...] = ()
    if _EXPANDED in ref.reasons:
        carried = (_EXPANDED, *(("glob-match",) if "glob-match" in ref.reasons else ()))
    for hit in result.hits:
        norm = paths.NormPath(f"{ref.raw}/{hit.rel}"[:512], hit.key, ref.flavor, True, False, ())
        reasons = ("recursive-scan", *carried, *((paths.EXTRA_READING,) if hit.extra else ()))
        (extra if hit.extra else out).append(
            _make_ref(
                ctx,
                norm.raw,
                norm,
                access,
                uncertain=False,
                reasons=reasons,
                resolved="resolved-on-disk" in ref.reasons,
            )
        )
    return result


# --------------------------------------------------------------------------------------------
# Shell tools
# --------------------------------------------------------------------------------------------


def _cd_target(
    ctx: _Ctx, text: str, cwd: str | None, dialect: str = "bash"
) -> tuple[str | None, bool]:
    """The key of the directory ``cd text`` leads to from ``cwd`` (None when unknowable), and
    whether a variable in ``text`` was expanded to find it (spec revision 37, R36-1)."""
    norm = paths.normalize_path(
        text,
        cwd=cwd,
        home=ctx.home,
        env=ctx.env,
        dialect=dialect,  # type: ignore[arg-type]
    )
    expanded = _EXPANDED in norm.reasons
    if not norm.absolute or norm.is_device or not norm.key:
        return None, expanded
    if norm.key.count("/") > MAX_KEY_DEPTH:
        return None, expanded
    if not norm.uncertain:
        return norm.key, expanded
    if not paths.reading_only(norm.reasons):
        return None, expanded
    # Unsure of the reading, not of the place: what is below it is looked at, and stays uncertain
    # because this text keeps its dots ("cd keys." leads to .ssh when keys is a link to it)
    kept = paths.reading_text(
        text,
        cwd=cwd,
        home=ctx.home,
        env=ctx.env,
        dialect=dialect,  # type: ignore[arg-type]
    )
    return kept, expanded


def _cd_short_target(
    ctx: _Ctx, notes: list[str], text: str, cwd: str | None, dialect: str
) -> list[str]:
    """Where ``cd text`` leads on disk when ``_cd_target`` cannot say because an 8.3 name in it
    was not expanded (and maybe of its reading): ``cd PLAINL~1``, ``cd DEEPER~1/k9.`` (spec
    revision 42, R41-3). Resolved through ``\\\\?\\`` (``_all_on_disk``: the text that keeps the
    dots and the key, both, revision 43, R42-4; revision 40's lookups). For each place found: its
    key, or the text that keeps its dots when a name on the way ends in a dot or a space (as
    ``_cd_target`` gives a reading); a name the disk gives back as written (``data~1``) is a long
    name (``paths.on_disk_names``, R42-5). Empty when nothing is there. The caller keeps the
    unknown working directory beside them."""
    if os.name != "nt" or ctx.budget.lexical:
        return []
    norm = paths.normalize_path(
        text,
        cwd=cwd,
        home=ctx.home,
        env=ctx.env,
        dialect=dialect,  # type: ignore[arg-type]
    )
    if not norm.absolute or norm.is_device or not norm.key or norm.flavor != "windows":
        return []
    if norm.key.count("/") > MAX_KEY_DEPTH or not paths.short_reading_only(norm.reasons):
        return []
    if not paths.is_local_disk(norm):
        return []
    kept = paths.reading_text(
        text,
        cwd=cwd,
        home=ctx.home,
        env=ctx.env,
        dialect=dialect,  # type: ignore[arg-type]
    )
    targets: list[str] = []
    for found, _index in _all_on_disk(ctx, notes, (kept, norm.key)):
        real = paths.on_disk_names(
            paths.normalize_path(found, cwd=None, home=None, dialect="tool", literal=True)
        )
        if real.is_device or not real.absolute or not paths.is_local_disk(real):
            continue
        if not real.uncertain:
            targets.append(real.key)
        elif paths.reading_only(real.reasons):
            reading = paths.reading_text(found, cwd=None, home=None, dialect="tool")
            if reading is not None:
                targets.append(reading)
    return list(dict.fromkeys(targets))


def _merge_cwds(old: Sequence[str | None], new: Sequence[str | None]) -> tuple[str | None, ...]:
    """The working directories after a step: the old ones (it may fail) and ``new``, in that
    order. Over ``MAX_CWDS`` the first one stays (where the line started: every step may fail),
    then the step's own targets (the later ones when they are more than the room), then the later
    of the other old ones; the order stays and "unknown" is added. Revision 39 kept the first
    ones and dropped the newest target, so after three ``cd`` a fourth one's place was never
    looked at (spec revision 43, R42-2)."""
    merged = list(dict.fromkeys([*old, *new]))
    known = [c for c in merged if c is not None]
    unknown = None in merged
    if len(known) + int(unknown) > MAX_CWDS:
        room = MAX_CWDS - 1
        targets = {c for c in new if c is not None}
        keep = [known[0]]
        for group in ([c for c in known if c in targets], [c for c in known if c not in targets]):
            for c in reversed(group):
                if len(keep) < room and c not in keep:
                    keep.append(c)
        kept = set(keep)
        known = [c for c in known if c in kept]
        unknown = True
    return (*known, *((None,) if unknown else ()))


_CWDS_DROPPED: Final = "budget:working-directories"


def _set_cwds(st: _Line, new: Sequence[str | None]) -> None:
    """``st.cwds`` after a step (``_merge_cwds``). When the limit dropped a known directory the
    line is not sent to the audit (a ``budget:`` gray reason): whichever one is dropped, a line can
    be written so that it is the one that mattered. Keeping the newest targets,
    ``cd <out>/.kube; cd q; cd r; cd s; cat config`` drops ``.kube`` (spec revision 43)."""
    merged = _merge_cwds(st.cwds, new)
    before = {c for c in (*st.cwds, *new) if c is not None}
    if before - set(merged) and _CWDS_DROPPED not in st.line_gray:
        st.line_gray.append(_CWDS_DROPPED)
    st.cwds = merged


def _after_cd(ctx: _Ctx, st: _Line, cmd: SimpleCmd, program: str, notes: list[str]) -> None:
    """Update the possible working directories after ``cd`` / ``pushd`` / ``popd``.

    ``cd`` can fail and a subshell, pipeline stage or ``bash -c`` may or may not keep the new
    directory, so the old directories stay possible next to the new ones; what cannot be known
    (``cd -``, ``popd``, ``$(...)``, a glob, several arguments, a very deep path) adds an
    "unknown" directory instead. A target written with an 8.3 name adds where it leads on disk
    as well, next to that "unknown" one (spec revision 42, R41-3): what is below it is looked
    at, and the allow side still sees ``cwd-unknown``. ``notes``: the ``cd`` action's own.
    """
    if program == "popd":
        _set_cwds(st, (None,))
        return
    words = [w for w in cmd.argv[1:] if w.text not in _CD_FLAGS]
    if st.shell == "powershell":  # canonical parameters (-Path, -PassThru, ...) are not directories
        words = [w for w in words if w.quoted or not w.text.startswith("-")]
    if not words:
        if program == "pushd":  # swaps the top two directories
            _set_cwds(st, (None,))
            return
        text = "~"
    elif (
        len(words) > 1
        or words[0].text in ("-", "")
        or _dynamic(words[0], shell=st.shell)
        or (program == "pushd" and words[0].text[:1] in "+-" and words[0].text[1:].isdigit())
    ):
        _set_cwds(st, (None,))
        return
    else:
        text = words[0].text
    relative = _relative_text(text) or _uses_pwd(text, st.shell)
    targets: list[str | None] = []
    for cwd in st.cwds:
        target, expanded = _cd_target(ctx, text, cwd, st.shell)
        if target is None:
            for short in _cd_short_target(ctx, notes, text, cwd, st.shell):
                if expanded or (relative and cwd in st.expanded_cwds):
                    st.expanded_cwds.add(short)
                targets.append(short)  # (and the unknown one, below)
        # ``Set-Location $env:X``, or a relative step from such a directory: a path resolved
        # against it would carry the value (spec revision 37, R36-1)
        if target is not None and (expanded or (relative and cwd in st.expanded_cwds)):
            st.expanded_cwds.add(target)
        targets.append(target)
    _set_cwds(st, targets)


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


def _env_value(env: Mapping[str, str] | None, name: str) -> str | None:
    """A variable of the environment, its name matched as Windows does for ASCII names."""
    if not env:
        return None
    value = env.get(name)
    if value is None:
        upper = name.upper()
        value = next((v for k, v in env.items() if k.isascii() and k.upper() == upper), None)
    return value if isinstance(value, str) else None


@functools.lru_cache(maxsize=16)
def _windows_system_dirs(roots: tuple[str | None, ...]) -> frozenset[str]:
    """The Windows system directories, folded, for these root variables (None: missing)."""
    out: set[str] = set()
    for (_name, default, subdirs), value in zip(_WINDOWS_SYSTEM_ROOTS, roots, strict=True):
        base = (default if value is None else value).replace("\\", "/").rstrip("/")
        segments = base.split("/")[1:]
        # Not an absolute path on a drive, or one Win32 would read otherwise: no directory at all
        if not _DRIVE_ABSOLUTE.fullmatch(base) or any(s != s.rstrip(". ") for s in segments):
            continue
        out.update(paths.windows_fold(f"{base}/{sub}") for sub in subdirs)
    return frozenset(out)


def _system_dir(
    directory: str,
    platform: Platform,
    *,
    shell: str = "bash",
    env: Mapping[str, str] | None = None,
) -> bool:
    text = directory.replace("\\", "/")
    segments = text.split("/")
    if any(s in (".", "..") for s in segments[1:]):
        return False
    text = text.rstrip("/") or "/"
    if platform != "windows":
        return text in _POSIX_SYSTEM_DIRS
    # Not casefold: C:\Windows and the same with U+017F for its "s" are two directories on NTFS
    low = paths.windows_fold(text)
    # Git Bash's own; in PowerShell ``/usr/bin`` is ``\usr\bin`` on the current drive (measured)
    if shell == "bash" and low in _POSIX_SYSTEM_DIRS:
        return True
    roots = tuple(_env_value(env, name) for name, _default, _subdirs in _WINDOWS_SYSTEM_ROOTS)
    return low in _windows_system_dirs(roots)


def _canonical_program(ctx: _Ctx, word: Word, shell: str = "bash") -> tuple[str, list[str]]:
    """(the canonical program name, gray reasons for how it was spelled).

    The basename of a path, ``.exe`` stripped, case-folded on Windows: ``/bin/rm``, ``rm.exe`` and
    ``RM`` are all ``rm``. A path-qualified name outside the system directories (``./rm``) is the
    same program name for deny and ask rules but gray, so that no allow rule trusts it. So is a name
    only casefold reads that way (``sudo`` with U+017F for its "s"): NTFS and PATH keep it apart
    from ``sudo`` and PowerShell does not resolve it to a cmdlet (measured), yet it may be meant so.
    On Windows trailing dots and spaces go first (spec revision 16): PowerShell 5.1 runs
    ``C:\\tools\\boundkeep.exe.`` as ``boundkeep.exe`` (measured), so that is the name the deny and
    ask rules see; the call is gray, so that no allow rule relies on a spelling Git Bash would not
    run.
    """
    text = word.text
    if _dynamic(word) or not text or "\x00" in text:
        return text, []
    cut = max(text.rfind("/"), text.rfind("\\"))
    name = text[cut + 1 :] if cut >= 0 else text
    if not name:
        return text, []
    grays: list[str] = []
    if ctx.platform == "windows":
        stripped = name.rstrip(". ")
        if stripped and stripped != name:  # not "." or "..": those are no program names
            grays.append("program-name-trailing-dots")
            name = stripped
    if name.lower().endswith(".exe") and len(name) > 4:
        name = name[:-4]
    if ctx.platform == "windows":
        if name.casefold() != paths.windows_fold(name):
            grays.append("program-fold-variant")
        name = name.casefold()
    if cut >= 0 and not _system_dir(text[:cut] or "/", ctx.platform, shell=shell, env=ctx.env):
        grays.append("program-path-qualified")
    return name, grays


def _expanded_names(ctx: _Ctx, notes: list[str], st: _Line, text: str) -> set[str]:
    """The last segments of ``text`` as the disk layer expands it (its 8.3 short names gone)."""
    refs = _refs(
        ctx,
        notes,
        text,
        "read",
        cwds=st.cwds,
        expanded_cwds=st.expanded_cwds,
        dialect=st.shell,
        dynamic=False,
    )
    return {
        ref.key.rsplit("/", 1)[-1]
        for ref in refs
        if ref.flavor == "windows" and "short-name-unresolved" not in ref.reasons
    }


def _bare_short_name(ctx: _Ctx, st: _Line, word: Word) -> bool:
    """A bare program name that looks like an 8.3 short name, in Git Bash on Windows.

    Git Bash finds ``BOUNDK~1`` by PATH and runs ``boundkeep.exe`` (measured; revision 18, R17-2);
    the rules cannot tell which program that is. PowerShell 5.1 does not run it (measured).
    """
    text = word.text
    if ctx.platform != "windows" or st.shell != "bash" or _dynamic(word) or not text:
        return False
    if "/" in text or "\\" in text or "\x00" in text:
        return False
    return paths.is_short_name(text.rstrip(". "))


def _short_named_path(ctx: _Ctx, word: Word, shell: str = "bash") -> bool:
    """A program run by a path whose last segment is, as written, an 8.3 short name.

    When the disk layer gives no single long name for it (``_short_name_program`` is None) the
    rules cannot tell which program runs: after ``cd`` into a short-named directory the working
    directory is not known, yet Git Bash runs ``./BOUNDK~1`` and PowerShell ``.\\BOUNDK~1.EXE``
    there (measured; spec revision 19, review R18-4). A last segment with a variable or a glob in
    it is no short name as written. PowerShell's dynamic command name (``& "$d\\BOUNDK~1.EXE"``)
    arrives wrapped as ``$(<text>)`` (``pscmd._dynamic_word``); the text inside is what was written.
    """
    text = word.text
    if ctx.platform != "windows" or not text or "\x00" in text:
        return False
    if shell == "powershell" and text.startswith("$(") and text.endswith(")"):
        text = text[2:-1]
    cut = max(text.rfind("/"), text.rfind("\\"))
    if cut < 0:
        return False
    last = text[cut + 1 :]
    if any(c in last for c in "$`*?["):
        return False
    return paths.is_short_name(last.rstrip(". "))


def _short_name_program(ctx: _Ctx, notes: list[str], st: _Line, word: Word) -> str | None:
    """The long name of a program run by a path whose last segment is an 8.3 short name
    (``C:\\tools\\BOUNDK~1.EXE``), as the disk layer expands it; None when there is none.

    PowerShell 5.1 runs such a path (measured; independent review IR-4), so the deny and ask rules
    see the long name (spec revision 17). The path layer lists the lexical form (still marked
    ``short-name-unresolved``) and, for a file that is there, the expanded one; the names of the
    expanded forms must agree. A file that is not there gives None and the short name stays (gray
    ``program-short-name-unresolved``, spec revision 19). Only the last segment is looked at.
    """
    text = word.text
    if ctx.platform != "windows" or _dynamic(word) or not text or "\x00" in text:
        return None
    cut = max(text.rfind("/"), text.rfind("\\"))
    if cut < 0 or not paths.is_short_name(text[cut + 1 :].rstrip(". ")):
        return None
    names = _expanded_names(ctx, notes, st, text)
    if not names and st.shell == "bash" and not text.lower().endswith(".exe"):
        # Git Bash runs ``…/BOUNDK~1`` as ``…/BOUNDK~1.exe`` (measured; revision 18, R17-2)
        names = _expanded_names(ctx, notes, st, text + ".exe")
    if len(names) != 1:
        return None
    name = names.pop().rstrip(". ")
    if name.lower().endswith(".exe") and len(name) > 4:
        name = name[:-4]
    if not name or paths.is_short_name(name):
        return None
    return name.casefold()


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
        _set_cwds(st, (None,))


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
                expanded_cwds=st.expanded_cwds,
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


# characters that make the part of a word before its value dynamic (a name that expands or globs)
_DYNAMIC_NAME_CHARS = frozenset("$`*?[{")


def _consumed_as_path(word: str, path_text: str) -> bool:
    """Did the path layer take exactly this ``word`` (or the value attached to an option) as the
    path ``path_text``?

    Exact only (X1 second re-review R2-1): the whole word, ``-oVALUE``, ``--opt=VALUE`` or
    ``-opt:VALUE`` with the value after the FIRST ``=`` / ``:`` equal to the path, and an option
    part that is itself plain text. A suffix match let ``"$u@a.txt=tests"`` pass as the path
    ``tests``.
    """
    if word == path_text:
        return True
    if word[:1] != "-":
        return False
    if word[1:2] != "-" and len(word) > 2 and word[2:] == path_text:  # -oVALUE
        return word[1] not in _DYNAMIC_NAME_CHARS
    separators = [i for i in (word.find("="), word.find(":")) if i > 0]
    if not separators:
        return False
    cut = min(separators)
    return word[cut + 1 :] == path_text and not (set(word[:cut]) & _DYNAMIC_NAME_CHARS)


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
        program, spelling = _canonical_program(ctx, cmd.argv[0], st.shell)
        long_name = _short_name_program(ctx, notes, st, cmd.argv[0])
        if long_name is not None and long_name != program:
            program = long_name
            spelling.append("program-short-name")  # no allow rule relies on it (revision 17)
        elif _bare_short_name(ctx, st, cmd.argv[0]) or (
            long_name is None and _short_named_path(ctx, cmd.argv[0], st.shell)
        ):
            # not sent to the model: a bare short name (revision 18) or one by a path the disk
            # layer cannot expand (revision 19)
            spelling.append("program-short-name-unresolved")
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
    if program == "git" and info.subcommand in _GIT_WHOLE_TREE and _git_root_above_project(ctx, st):
        gray_reasons.append("git-root-above-project")
    if cmd.argv and _dynamic(cmd.argv[0]):
        gray_reasons.append("dynamic-program")
    if cmd.args_from_stdin:
        gray_reasons.append("arguments-from-stdin")
    refs: list[PathRef] = []
    if "program-path-qualified" in gray_reasons:
        refs += _refs(
            ctx,
            notes,
            cmd.argv[0].text,
            "read",
            cwds=st.cwds,
            expanded_cwds=st.expanded_cwds,
            dialect=st.shell,
            dynamic=False,
        )
    recursive = bool(getattr(info, "recursive", False))  # reads the whole subtree of a directory
    for word, access in (*info.paths, *_top_words(ctx, st, info)):
        if exec_child and "{}" in word.text:
            refs += _placeholder_refs(ctx, notes, st, cmd, word, access)
        else:
            word_refs = _refs(
                ctx,
                notes,
                word.text,
                access,
                cwds=st.cwds,
                expanded_cwds=st.expanded_cwds,
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
    if (
        program == "git"
        and info.subcommand == "add"
        and _add_may_stage_protected(ctx, st, info, notes)
    ):
        gray_reasons.append("git-add-may-stage-protected")
    names, unknown_host = _domains_of(info.urls)
    if unknown_host:
        gray_reasons.append("unparseable-url")
    unc_names, unc_unknown = _unc_refs(ctx, refs)
    if unc_names or unc_unknown:
        names = tuple(dict.fromkeys([*names, *unc_names]))
        gray_reasons.append("unc-network")
    network = info.network or bool(info.urls) or bool(unc_names) or unc_unknown
    tags: list[RiskTag] = list(info.tags)
    if (not info.known or _runs_project_code(program)) and "exec" not in tags:
        # A program the tables do not classify (a build tool, a project script, a path-qualified
        # executable, an unknown subcommand), or a package manager or task runner, runs code
        # nobody looked at. Tags decide no rule; they feed the taint step of the LLM audit
        # (PROJECT_SPEC.md §9.5) and what the auditor sees.
        tags.append("exec")
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
        _after_cd(ctx, st, cmd, cd_program, notes)
    gray_reasons.extend(notes)
    reasons = tuple(dict.fromkeys(gray_reasons))
    # what the action does not carry (the values of assignments, here-documents): the LLM audit
    # could not be shown it (X1 review of M3a, F3 and F4)
    unshown = tuple(
        dict.fromkeys(
            [
                *(f"env:{name}" for name, _value in cmd.env if name != DEV_EXE_ENV),
                *cmd.stdin_text,
                *st.unshown,
            ]
        )
    )
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
        unshown=unshown,
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
    st = _Line(cwds=(ctx.cwd,), shell=shell, unshown=result.unshown)
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
        # nothing of the line understood: it may run anything (the same reading as an unknown
        # program, for the taint step)
        tags_extra: tuple[RiskTag, ...] = (
            ("exec",) if result.exec_reasons or not result.commands else ()
        )
        actions.append(
            _gray(ctx, tool, *reasons, risk_tags=tags_extra, unshown=result.unshown, **common)
        )
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
    """``refs`` with ``in_scratchpad``, ``in_session_tool_results`` and ``in_project_memory``
    cleared on every path whose name has a pattern character.

    The operand of a file or search tool is a path, not a pattern: a name with ``* ? [ ] { }`` in
    it (a Next.js ``[id]`` directory, a brace list) may mean more than it says to some tool, and the
    session-directory rules do not guess: such a path is never "in the scratchpad", "in the
    tool-results directory" or "in the project memory". Only the operands of the tool (not the file
    name a Grep ``glob`` is probed with, which nothing opens).
    """
    marked = ("in_scratchpad", "in_session_tool_results", "in_project_memory")
    return [
        ref.model_copy(update=dict.fromkeys(marked, False))
        if any(getattr(ref, name) for name in marked) and not paths.scratch_plain(ref.key)
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
        known = base.absolute and (not base.uncertain or paths.reading_only(base.reasons))
        anchor = (
            base.key if known else None
        )  # ``dynamic``: what comes of it is uncertain either way
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


# MCP tool inputs (PROJECT_SPEC.md section 7, after the M2 evaluation). The call itself stays
# gray: what a server does is unknown. What the arguments show is given to the deny and ask rules:
# a local path, a command to run, a URL.
MCP_GRAY: Final = "mcp-tool-not-reviewed"
# keys as compared: casefolded, without "_" and "-" (file_name, fileName and file-name are one)
_MCP_PATH_KEYS: Final = frozenset(
    {
        "path", "paths", "file", "files", "filepath", "filename", "source", "sources",
        "destination", "dest", "src", "dst", "target", "targetfile", "targetpath", "directory",
        "dir", "folder", "root", "cwd", "oldpath", "newpath", "workingdirectory", "location",
        "pathname", "abspath", "repopath", "notebookpath", "uri",
    }
)  # fmt: skip
_MCP_COMMAND_KEYS: Final = frozenset(
    {"command", "commands", "cmd", "script", "shell", "shellcommand", "commandline", "code"}
)
_MCP_ARGS_KEYS: Final = frozenset({"args", "arguments", "argv"})
# a value under these keys names a host even without a scheme ("c.example.invalid/x")
_MCP_HOST_KEYS: Final = frozenset(
    {
        "url", "uri", "href", "link", "endpoint", "host", "hostname", "domain", "server",
        "address", "baseurl", "webhook", "webhookurl", "callbackurl", "targeturl", "website",
    }
)  # fmt: skip
# which MCP tools only read their paths: normalize.mcpnames.mcp_access (by the tool's verb)
_MCP_WALK_NODES: Final = 500
_MCP_WALK_DEPTH: Final = 6
_MCP_WALK_WIDTH: Final = 100
_URL_IN_TEXT = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s'\"<>]+")
_INVISIBLE: Final = "﻿​‌‍⁠᠎"
_FILE_URI = re.compile(r"(?i)^file:(?://)?")
_DRIVE_RELATIVE = re.compile(r"^[A-Za-z]:(?![/\\])")
# SQL: the first word says whether it looks like a statement; a read statement is one statement
# that starts with one of the read words and holds none of the write words anywhere
_SQL_FIRST: Final = frozenset(
    {
        "select", "with", "show", "describe", "desc", "explain", "values", "insert", "update",
        "delete", "drop", "alter", "create", "grant", "revoke", "truncate", "merge", "replace",
        "copy", "call", "exec", "execute", "set", "begin", "commit", "rollback", "lock",
        "vacuum", "attach", "detach", "pragma", "load", "use", "do",
    }
)  # fmt: skip
_SQL_READ_FIRST: Final = frozenset(
    {"select", "with", "show", "describe", "desc", "explain", "values"}
)
_SQL_WRITE_WORD = re.compile(
    r"(?i)\b(insert|update|delete|drop|alter|create|grant|revoke|truncate|merge|replace|copy|"
    r"call|exec|execute|into|lock|vacuum|attach|detach|pragma|set|load|outfile|dumpfile)\b"
)


def _mcp_key(key: object) -> str:
    return str(key).casefold().replace("-", "").replace("_", "")


def _mcp_walk(value: object) -> tuple[list[tuple[str, object]], bool]:
    """(every (key, scalar) pair below ``value``, whether the walk was cut short).

    Breadth first, so the top-level arguments are always seen before a big nested one can use up
    the budget. List items carry their list's key; a list of strings under a command key is given
    as one command line. Cut short (too many nodes, too deep, a long list or mapping, a text too
    long to look at) means some argument was not looked at: the call must not be allowed.
    """
    out: list[tuple[str, object]] = []
    queue: deque[tuple[str, object, int]] = deque([("", value, 0)])
    cut = False
    while queue:
        if len(out) >= _MCP_WALK_NODES:
            return out, True
        key, item, depth = queue.popleft()
        if isinstance(item, Mapping | list | tuple):
            if depth >= _MCP_WALK_DEPTH:
                cut = True
                continue
            items = list(item.items()) if isinstance(item, Mapping) else list(item)
            if len(items) > _MCP_WALK_WIDTH:
                cut = True
            items = items[:_MCP_WALK_WIDTH]
            if isinstance(item, Mapping):
                queue.extend((_mcp_key(k), v, depth + 1) for k, v in items)
                continue
            words = [v for v in items if isinstance(v, str)]
            if key in _MCP_COMMAND_KEYS and words and len(words) == len(items):
                out.append((key, shlex.join(words)))  # ["rm", "-rf", "~"]
                continue
            queue.extend((key, v, depth + 1) for v in items)
        else:
            if isinstance(item, str) and _text(item) is None:
                cut = True  # too long to look at
            out.append((key, item))
    return out, cut


def _mcp_sql_kind(key: str) -> str | None:
    """ "sql": anything not shown to be a read statement may write; "query": a search text is
    fine, only what may write counts; None: not a SQL argument."""
    if "sql" in key or "statement" in key:
        return "sql"
    if key in ("query", "q") or key.endswith("query"):
        return "query"
    return None


def _local_path_text(text: str) -> tuple[str | None, bool]:
    """(the local path a value names, whether it may name one that cannot be read here).

    Any argument, whatever its key: an absolute, ``~`` or UNC path, or a ``file:`` URI (as its
    path). A relative value is left alone (it may be a path in a remote repository). A value
    that starts with a variable (``$HOME/...``, ``%USERPROFILE%\\...``) and has a separator is a
    path nobody can resolve here: unclear.
    """
    value = text.strip().strip(_INVISIBLE).strip()  # a byte-order mark is no whitespace (R10-2)
    if not value or "\n" in value:
        return None, False
    if re.match(r"^\.\.([/\\]|$)", value):
        return None, True  # climbs out of wherever it is relative to: no remote repo path (R10-2)
    if _FILE_URI.match(value):
        value = _FILE_URI.sub("", value, count=1)
        if re.match(r"^/[A-Za-z]:[/\\]", value):
            value = value[1:]  # file:///C:/x
        elif not value.startswith("/"):
            value = "//" + value  # file://host/share: a UNC path
    if value.startswith(("/", "\\", "~")):
        return value, False
    if (
        len(value) >= 3
        and value[0].isascii()
        and value[0].isalpha()
        and value[1:3] in (":/", ":\\")
    ):
        return value, False
    if value[0] in "$%" and ("/" in value or "\\" in value):
        return None, True
    return None, False


def sql_is_read_only(text: str) -> bool | None:
    """True: one read statement; False: it may write; None: it does not look like SQL.

    The first word is taken after comments and leading ``;`` / ``(``; the write words and a
    second statement are looked for in the raw text, comments included (MySQL runs ``/*! ... */``).
    Text that does not start like SQL but has a statement separator followed by a word is
    treated as SQL that may write.
    """
    stripped = re.sub(r"(?s)/\*.*?\*/|--[^\n]*", " ", text).lstrip(" \t\r\n;(")
    first = stripped.split(None, 1)[0].casefold().rstrip("(;") if stripped else ""
    raw = text.strip().rstrip(";").rstrip()
    if first not in _SQL_FIRST:
        return False if re.search(r";\s*\w", raw) else None
    return first in _SQL_READ_FIRST and ";" not in raw and not _SQL_WRITE_WORD.search(raw)


def _mcp_actions(ctx: _Ctx, tool: str, tool_input: Mapping[str, Any]) -> list[Action]:
    parts = tool.split("__", 2)
    server = parts[1] if len(parts) >= 2 and parts[1] else None
    name = parts[2] if len(parts) == 3 and parts[2] else None
    pairs, cut = _mcp_walk(tool_input)
    notes: list[str] = ["mcp-arguments-not-all-seen"] if cut else []
    refs: list[PathRef] = []
    access = mcp_access(name)
    urls: list[str] = []
    commands: list[str] = []
    for key, value in pairs:
        text = _text(value)
        if text is None or not text.strip():
            continue
        local, unclear = _local_path_text(text)
        if local is not None:
            refs += _plain_operands(
                _refs(ctx, notes, local, access, cwds=(ctx.cwd,), dialect="tool", glob_literal=True)
            )
        elif unclear or (key in _MCP_PATH_KEYS and _DRIVE_RELATIVE.match(text.strip())):
            notes.append("mcp-path-unclear")
        # every URL in the value, whatever its scheme or position (a file: URI is a path, above);
        # under a host key a bare host or host/path counts too (X1 review R10-1)
        found = [u for u in _URL_IN_TEXT.findall(text) if not u.casefold().startswith("file:")]
        bare = text.strip().strip(_INVISIBLE).strip()
        if not found and key in _MCP_HOST_KEYS and local is None and not _FILE_URI.match(bare):
            found = [bare if "://" in bare else "https://" + bare]
        urls += found
        if key in _MCP_COMMAND_KEYS:
            commands.append(text)
        kind = _mcp_sql_kind(key)
        if kind is not None:
            read_only = sql_is_read_only(text)
            # under a SQL key anything not shown to be a read statement may write; a ``query``
            # may be a search text, so there only what may write counts
            if read_only is False or (read_only is None and kind == "sql"):
                notes.append("mcp-sql-not-read-only")
    extra = next((v for k, v in tool_input.items() if _mcp_key(k) in _MCP_ARGS_KEYS), None)
    if len(commands) == 1 and isinstance(extra, list) and all(isinstance(a, str) for a in extra):
        # {"command": "rm", "args": ["-rf", "~"]}: the server runs the program with these words
        commands = [" ".join([commands[0], *(shlex.quote(a) for a in extra)])]
    names, unknown = _domains_of(urls)
    unc, unc_unknown = _unc_refs(ctx, refs)
    names = tuple(dict.fromkeys((*names, *unc)))
    if unknown:
        notes.append("unparseable-url")
    network = bool(urls) or bool(unc) or unc_unknown
    if commands:
        notes.append("mcp-command")
    main = Action(
        tool=tool,
        paths=tuple(refs),
        domains=names,
        network=network,
        inside_project=_inside(refs),
        # a server does whatever its tool does, and may reach the network whatever the arguments
        # show: for the taint step it is code that runs and data that may leave
        risk_tags=("network_egress", "exec"),
        gray=True,
        gray_reasons=tuple(dict.fromkeys((MCP_GRAY, *notes))),
        mcp_server=server,
        mcp_tool=name,
        **ctx.base,
    )
    out = [main]
    for command in commands:
        # The server runs it: the Bash dialect is a guess, so these actions stay gray (they can
        # never be allowed) and only give the deny and ask rules something to look at.
        for action in _shell_actions(ctx, "Bash", "bash", command):
            reasons = tuple(dict.fromkeys((*action.gray_reasons, f"mcp-command:{tool}")))
            out.append(action.model_copy(update={"gray": True, "gray_reasons": reasons}))
    return out


# --------------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------------


def normalize_event(
    payload: Mapping[str, Any],
    *,
    platform: Platform,
    env: Mapping[str, str] | None = None,
    home: str | None = None,
    budget_s: float | None = None,
    protected_globs: Sequence[str] | None = None,
    rule_globs: Sequence[subtree.RuleGlob] | None = None,
) -> list[Action]:
    """The Actions for one PreToolUse payload (never raises; never empty).

    Runs on the daemon's event loop, so the work is bounded: after ``budget_s`` seconds (None:
    ``TIME_BUDGET_S``, read at call time so that tests can widen it), more than
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
    budget = _Budget(deadline=time.monotonic() + (TIME_BUDGET_S if budget_s is None else budget_s))
    ctx: _Ctx | None = None
    try:
        for key in ("session_id", "cwd", "permission_mode", "agent_id"):
            value = _text(payload.get(key))
            if value is not None:
                base[key] = value
        root, root_resolved = _project_root(payload, env, home)
        if root is not None:  # whatever the working directory: where a write is marked
            base["project_root"] = root.key
            if root_resolved is not None and root_resolved.key != root.key:
                base["project_root_resolved"] = root_resolved.key
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
            tool_results=paths.tool_results_for(base.get("session_id"), platform, home),
            memory=paths.memory_for(root, platform, home),
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
        return _mcp_actions(ctx, tool, tool_input)
    return [_gray(ctx, tool, "unknown-tool", risk_tags=("exec",))]
