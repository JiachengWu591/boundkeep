"""The policy schema: strict, immutable, no unknown keys.

A policy file is security configuration, so a typo that is silently ignored (``modee:
audit-only``) would be a silent failure of the gate. Every model therefore forbids unknown keys,
and every field is validated in strict mode (no ``"yes"`` -> ``True`` or ``1.0`` -> ``1``
coercion). Top-level keys:

* ``version``: always ``1``.
* ``mode``: ``enforce`` (decisions go back to Claude Code) or ``audit-only`` (decisions are only
  recorded).
* ``defaults.emit_allow``: whether an ALLOW verdict is emitted as an explicit hook "allow"
  (which skips Claude Code's own confirmation) instead of "no decision".
* ``taint.sources``: tool names (or ``prefix*`` patterns) whose results taint the session. They
  decide the PostToolUse matcher.
* ``llm_audit`` (M1: structure only, no backend is implemented): see ``LlmAudit``.
* ``trusted_projects``: directories whose own code the user lets tools run (see
  ``Policy.trusted_projects``); the ``project_trusted`` match field refers to them.
* ``rules``: ``Rule`` entries (see ``policy/matcher.py`` for the exact semantics).
* ``tests``: ``PolicyTest`` regression cases run by ``boundkeep test``.

An M0 file with only ``version`` / ``mode`` / ``defaults`` / ``taint`` stays valid: the new keys
default to "no LLM audit, no rules, no tests".

Every ``path_glob`` is expanded and compiled while the policy is validated: ``~`` / ``~/...`` become
the home directory key (``home`` in the validation context, else the real home directory), so a
``Policy`` never holds an unexpanded ``~`` and a bad glob never survives loading. Errors raised
here may carry an ``at`` context (a path below the error location) so the loader can point at the
exact list item.
"""

from __future__ import annotations

import difflib
import ipaddress
import math
import os
import re
from collections.abc import Iterator, Mapping
from typing import Annotated, Any, Final, Literal
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainValidator,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

from boundkeep.normalize.paths import NormPath, inside_project, key_of_home, normalize_path
from boundkeep.policy.glob import GlobError, compile_glob
from boundkeep.policy.secretscan import find_secret, skip_policy_test_inputs

Mode = Literal["enforce", "audit-only"]

MAX_TAINT_SOURCES = 64
MAX_TAINT_SOURCE_LENGTH = 128
DEFAULT_TAINT_SOURCES: tuple[str, ...] = ("WebFetch", "WebSearch", "mcp__*")

# Letters, digits, underscore, hyphen and dot, then at most one trailing "*". An explicit ASCII
# class and ``fullmatch`` (not ``$``, which tolerates a trailing newline, and not ``\w``, which
# matches non-ASCII letters) keep this exact. A bare "*" is rejected: it would taint on every tool
# and is almost certainly a mistake; say "mcp__*" or list the tools instead.
_SOURCE_RE = re.compile(r"[A-Za-z0-9_.\-]+\*?")

_STRICT = ConfigDict(frozen=True, extra="forbid", strict=True)


def _shorten(value: str, limit: int = 40) -> str:
    """A bounded, printable, pure-ASCII rendering of an untrusted string for error messages.

    ``ascii()`` escapes every non-ASCII character, so a look-alike (a Cyrillic "o" in a tool name)
    cannot be mistaken for the real letter in the message.
    """
    body = ascii(value[:limit])[1:-1]  # drop the quotes ascii() adds; we add our own
    return f"'{body}{'...' if len(value) > limit else ''}'"


def check_taint_source(source: object) -> str:
    """Return ``source`` if it is a valid taint source, else raise ``ValueError``.

    Shared by the schema and by ``taint_sources_to_matcher`` so a value that parses can always be
    turned into a matcher, and a value that would not make a safe matcher never parses.
    """
    if not isinstance(source, str):
        raise ValueError("taint source must be a string")
    if not source:
        raise ValueError("taint source must not be empty")
    if len(source) > MAX_TAINT_SOURCE_LENGTH:
        raise ValueError(f"taint source is longer than {MAX_TAINT_SOURCE_LENGTH} characters")
    if _SOURCE_RE.fullmatch(source) is None:
        raise ValueError(
            f"taint source {_shorten(source)} is not allowed: use letters, digits, '_', '-', '.' "
            "and at most one trailing '*' (with at least one character before it)"
        )
    return source


class Defaults(BaseModel):
    model_config = _STRICT

    emit_allow: bool = False


class Taint(BaseModel):
    """Taint sources.

    ``sources`` is a tuple, not a list: a frozen model with a mutable list inside is not frozen
    (any holder of a shared ``Policy`` could append an unvalidated entry, and the model would not
    be hashable). The YAML list is converted before validation.

    Duplicates are silently removed (first occurrence wins, order kept): a repeated name is
    harmless and rejecting it would only annoy, whereas the 64-entry limit is checked on the raw
    list so an absurdly long file is still refused. An empty list is valid (no taint source), but
    it has no PostToolUse matcher: ``taint_sources_to_matcher`` refuses it and callers must
    handle that case themselves (for example by not registering the PostToolUse hook).
    """

    model_config = _STRICT

    # The per-item validator gives errors the index (``sources[1]``); the validator below adds
    # the count limit and the de-duplication.
    sources: tuple[Annotated[str, AfterValidator(check_taint_source)], ...] = DEFAULT_TAINT_SOURCES

    @field_validator("sources", mode="before")
    @classmethod
    def _list_to_tuple(cls, value: Any) -> Any:
        # Strict mode refuses a list for a tuple field, but YAML only produces lists. Convert
        # exactly that type: anything else (a string, a mapping, a tuple smuggled in through
        # model_validate) keeps failing as before.
        return tuple(value) if type(value) is list else value

    @field_validator("sources", mode="after")
    @classmethod
    def _check_sources(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_TAINT_SOURCES:
            raise ValueError(f"at most {MAX_TAINT_SOURCES} taint sources are allowed")
        seen: dict[str, None] = {}
        for entry in value:
            seen.setdefault(entry, None)
        return tuple(seen)


# --------------------------------------------------------------------------- shared helpers

Platform = Literal["posix", "windows"]
Decision = Literal["deny", "ask", "allow"]
Expect = Literal["deny", "ask", "allow", "gray"]

MAX_RULES: Final = 500
MAX_TESTS: Final = 2000
MAX_LIST_ITEMS: Final = 64
MAX_WORD_CHARS: Final = 256
MAX_REASON_CHARS: Final = 300
MAX_RULE_ID_CHARS: Final = 64
RESERVED_RULE_IDS: Final = frozenset({"m0-canary"})  # the built-in rule, see policy/matcher.py
_RULE_ID_RE = re.compile(r"[a-z0-9-]+")
_HOST_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_LOOPBACK_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1"})


def _at_error(message: str, *at: str | int) -> PydanticCustomError:
    """A validation error located ``at`` (keys and indexes) below the field being validated."""
    return PydanticCustomError("policy_value", message, {"at": at})


def _list_to_tuple(value: Any) -> Any:
    # Strict mode refuses a list for a tuple field, but YAML only produces lists. Convert exactly
    # that type: a string, a mapping or a set keeps failing as before.
    return tuple(value) if type(value) is list else value


def _one_or_list_to_tuple(value: Any) -> Any:
    # `program: git` is shorthand for `program: [git]` (PROJECT_SPEC.md section 8 uses it).
    if isinstance(value, str):
        return (value,)
    return _list_to_tuple(value)


def _true_only(value: Any) -> Any:
    if type(value) is not bool or value is not True:
        raise ValueError("only 'true' is supported here (omit the field instead of writing false)")
    return value


def _check_words(values: tuple[str, ...]) -> tuple[str, ...]:
    for index, word in enumerate(values):
        if not word or len(word) > MAX_WORD_CHARS or not word.isprintable() or word != word.strip():
            raise _at_error(
                f"entries must be non-empty printable text without surrounding spaces, at most "
                f"{MAX_WORD_CHARS} characters (got {_shorten(word)})",
                index,
            )
    return values


# Tool names a rule may name. A name that is not here (and does not start with ``mcp__``) is a
# typo or a tool this boundkeep does not know: either way the rule would silently never match, so
# loading fails instead. ``NON_PATH_TOOLS`` never carry a file path (see normalize/event.py).
NON_PATH_TOOLS: Final = frozenset(
    {
        "WebSearch",
        "ToolSearch",
        "TodoWrite",
        "Agent",
        "Task",
        "BashOutput",
        "KillShell",
        "ExitPlanMode",
        "AskUserQuestion",
        "Skill",
        "SlashCommand",
    }
)
KNOWN_TOOLS: Final = (
    "Bash",
    "PowerShell",
    "Read",
    "Write",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
    "Glob",
    "Grep",
    "WebFetch",
    *sorted(NON_PATH_TOOLS),
)
_MCP_PREFIX: Final = "mcp__"


def _suggest_tool(tool: str) -> str | None:
    for known in KNOWN_TOOLS:
        if known.casefold() == tool.casefold():
            return known
    close = difflib.get_close_matches(tool, KNOWN_TOOLS, n=1, cutoff=0.6)
    return close[0] if close else None


def _check_known_tool(tool: str, index: int) -> None:
    if tool.endswith("*"):
        prefix = tool[:-1]
        if (
            prefix.startswith(_MCP_PREFIX)
            or _MCP_PREFIX.startswith(prefix)
            or any(known.startswith(prefix) for known in KNOWN_TOOLS)
        ):
            return
        raise _at_error(
            f"unknown tool pattern {_shorten(tool)}: a pattern must start like a tool name or "
            "like 'mcp__' (for example 'mcp__*' or 'mcp__github__*')",
            index,
        )
    if tool in KNOWN_TOOLS or tool.startswith(_MCP_PREFIX):
        return
    suggestion = _suggest_tool(tool)
    hint = (
        f" (did you mean '{suggestion}'?)"
        if suggestion
        else f"; known tools: {', '.join(KNOWN_TOOLS)}, or an 'mcp__server__tool' name"
    )
    raise _at_error(f"unknown tool {_shorten(tool)}{hint}; tool names are case-sensitive", index)


def _check_tools(values: tuple[str, ...]) -> tuple[str, ...]:
    for index, tool in enumerate(values):
        try:
            check_taint_source(tool)  # same grammar: a tool name or a ``prefix*`` pattern
        except ValueError:
            raise _at_error(
                f"tool {_shorten(tool)} is not allowed: use a tool name, or a prefix ending in "
                "'*' such as 'mcp__*'",
                index,
            ) from None
        _check_known_tool(tool, index)
    return values


def _check_program_names(values: tuple[str, ...]) -> tuple[str, ...]:
    """A program is matched by its basename: a space or a path separator can never match."""
    for index, word in enumerate(values):
        if any(ch.isspace() or ch in "/\\" for ch in word):
            raise _at_error(
                f"{_shorten(word)} is not a program name: write the bare name ('rm', not "
                "'/bin/rm' or 'rm -rf'); the matcher compares the program's basename",
                index,
            )
    return values


def _check_subcommand_names(values: tuple[str, ...]) -> tuple[str, ...]:
    for index, word in enumerate(values):
        if any(ch.isspace() for ch in word):
            raise _at_error(
                f"{_shorten(word)} is not a subcommand: a subcommand is one word ('push', 'prune')",
                index,
            )
    return values


def _check_flag_names(values: tuple[str, ...]) -> tuple[str, ...]:
    for index, word in enumerate(values):
        if not word.startswith("-"):
            raise _at_error(
                f"{_shorten(word)} is not a flag: flags_any / flags_none entries must start "
                "with '-' (for example '-r', '--force', '-Recurse')",
                index,
            )
    return values


def _canonical_host_entry(entry: str) -> str:
    if entry != entry.strip() or not entry.isascii() or not entry.isprintable():
        raise ValueError(
            "a host must be printable ASCII (write internationalized names as punycode)"
        )
    lowered = entry.lower()
    try:
        return str(ipaddress.ip_address(lowered))
    except ValueError:
        pass
    if any(ch in lowered for ch in "*/@:?#[] ") or "://" in lowered:
        raise ValueError(
            "write a bare host name such as 'github.com' (subdomains are included; no scheme, "
            "port, path, wildcard or user name)"
        )
    labels = lowered.split(".")
    if not all(_HOST_LABEL_RE.fullmatch(label) for label in labels) or len(lowered) > 253:
        raise ValueError("not a valid host name")
    if labels[-1].isdigit():
        raise ValueError("a host name does not end in a number (write an IP address in full)")
    return lowered


def _check_hosts(values: tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    for index, entry in enumerate(values):
        try:
            out.append(_canonical_host_entry(entry))
        except ValueError as exc:
            raise _at_error(f"host {_shorten(entry)}: {exc}", index) from None
    return tuple(out)


# --- immutable JSON values -------------------------------------------------------------------

_MAX_JSON_DEPTH: Final = 6
_MAX_JSON_NODES: Final = 500


class FrozenMap(Mapping[str, Any]):
    """A read-only, hashable mapping (values are scalars, tuples or ``FrozenMap``).

    Policy models are frozen; a plain ``dict`` inside one would not be. ``thaw`` converts back.
    """

    __slots__ = ("_data",)

    def __init__(self, items: Mapping[str, Any]) -> None:
        self._data = dict(items)

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __hash__(self) -> int:
        return hash(tuple(self._data.items()))

    def __repr__(self) -> str:
        return f"FrozenMap({self._data!r})"

    def thaw(self) -> dict[str, Any]:
        """A fresh, mutable ``dict`` (lists for tuples, dicts for ``FrozenMap``), e.g. for JSON."""
        return {key: thaw_json(value) for key, value in self._data.items()}


def thaw_json(value: Any) -> Any:
    """The inverse of the freezing done by the schema: ``FrozenMap`` -> dict, tuple -> list."""
    if isinstance(value, FrozenMap):
        return value.thaw()
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    return value


def _freeze(value: Any, depth: int, budget: list[int]) -> Any:
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError(f"more than {_MAX_JSON_NODES} values")
    if depth > _MAX_JSON_DEPTH:
        raise ValueError(f"nested deeper than {_MAX_JSON_DEPTH} levels")
    if isinstance(value, dict):
        items: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("mapping keys must be strings")
            items[key] = _freeze(item, depth + 1, budget)
        return FrozenMap(items)
    if isinstance(value, list | tuple):
        return tuple(_freeze(item, depth + 1, budget) for item in value)
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise ValueError(f"unsupported value of type {type(value).__name__} (use plain JSON values)")


def _to_frozen_map(value: Any) -> FrozenMap:
    if not isinstance(value, Mapping):
        raise ValueError("must be a mapping")
    frozen = _freeze(dict(value), 0, [_MAX_JSON_NODES])
    assert isinstance(frozen, FrozenMap)
    return frozen


_Frozen = Annotated[FrozenMap, PlainValidator(_to_frozen_map)]


# --- home directory and glob expansion --------------------------------------------------------


def _looks_absolute(path: str) -> bool:
    """An absolute POSIX path, a UNC or rooted path, or a drive path such as ``c:/users``."""
    if path.startswith(("/", "\\")):
        return True
    return len(path) >= 3 and path[0].isalpha() and path[1] == ":" and path[2] in "/\\"


def _home_key(home: str) -> str:
    """The comparison key of a home directory (``normalize.paths.key_of_home``), validated.

    A relative, drive-relative, empty or otherwise unusable home is refused here, whatever the
    normalizer would make of it: a ``~/`` glob expanded against a bogus root would silently never
    match, which for a deny rule means no protection.
    """
    if not _looks_absolute(home):
        raise ValueError("the home directory must be an absolute path")
    key = key_of_home(home)
    if not _looks_absolute(key):
        raise ValueError("the home directory has no usable key")
    return key


def _resolve_home_key(context: object) -> str:
    home: object = context.get("home") if isinstance(context, dict) else None
    if home is None:
        home = os.path.expanduser("~")
        if home == "~":
            raise ValueError("cannot expand '~': the home directory is unknown (pass home=...)")
    if not isinstance(home, str) or not home or "\0" in home:
        raise ValueError("cannot expand '~': the home directory is not a usable path")
    return _home_key(home)


def _escape_glob_literal(text: str) -> str:
    """``text`` as a glob that matches exactly it (up to a backslash).

    A glob has no escape character and refuses a backslash, but Linux allows one in a directory
    name (``/home/we\\ird``). A backslash therefore becomes ``?`` (any one character except
    ``/``): the pattern still matches the real directory, and over-matching is the safe direction
    for a rule that blocks. A key never contains a backslash except in such a POSIX name.
    """
    return "".join({"*": "[*]", "?": "[?]", "[": "[[]", "\\": "?"}.get(ch, ch) for ch in text)


escape_glob_literal = _escape_glob_literal  # public: runtime rules (daemon.pipeline) need it


def expand_home(pattern: str, context: object) -> str:
    """Replace a leading ``~`` or ``~/`` with the (glob-escaped) home directory key.

    ``~user`` forms are refused (they would silently never match). Raises ``ValueError``.
    """
    if not pattern.startswith("~"):
        return pattern
    if pattern != "~" and not pattern.startswith("~/"):
        raise ValueError(
            f"{_shorten(pattern)}: only '~' and '~/...' are supported "
            "(write '**/~name' to match a file whose name starts with '~')"
        )
    home = _escape_glob_literal(_resolve_home_key(context)).rstrip("/")
    return home + pattern[1:]


def _is_anchored(pattern: str) -> bool:
    if pattern.startswith(("/", "**")):
        return True
    first = pattern.split("/", 1)[0]
    return len(first) >= 2 and first.endswith(":")  # a drive such as "c:" or "[a-z]:"


def _check_dead_segments(raw: str) -> None:
    """Refuse globs with a part no canonical key has, which would silently never match.

    Keys have no ``.`` or ``..`` segments, no empty segments (``a//b``) and no surrounding
    whitespace, so a pattern such as ``~/.ssh/../.aws/**`` (meant as ``~/.aws/**``) protects
    nothing. A leading ``//`` is a UNC path (``//server/share/**``) and ``//./`` the Windows device
    namespace (``//./physicaldrive*``), both real key shapes. (A trailing ``/`` never gets here:
    the glob compiler refuses it first.)
    """
    body = raw
    if body.startswith("//") and not body.startswith("///"):
        body = body[2:]
        if body.startswith("./"):
            body = body[2:]
    elif body.startswith("/"):
        body = body[1:]
    for segment in body.split("/"):
        if segment == "":
            raise ValueError(
                f"{_shorten(raw)} has an empty path segment (a doubled '/'): no path key has one, "
                "so the pattern would never match"
            )
        if segment in (".", ".."):
            raise ValueError(
                f"{_shorten(raw)} has a '{segment}' segment: keys are already normalized and never "
                "contain one, so the pattern would never match (write the final path)"
            )


def _check_globs(values: tuple[str, ...], info: ValidationInfo) -> tuple[str, ...]:
    out: list[str] = []
    for index, raw in enumerate(values):
        try:
            if raw != raw.strip():
                raise ValueError(
                    f"{_shorten(raw)} has leading or trailing whitespace: no path key does, so "
                    "the pattern would never match"
                )
            pattern = expand_home(raw, info.context)
            compile_glob(pattern)  # syntax first: its message is the more specific one
            _check_dead_segments(raw)
            if not _is_anchored(pattern):
                raise ValueError(
                    f"{_shorten(raw)} is not anchored: a path_glob must start with '/', '**/', "
                    "'~/' or a drive such as 'c:/' (keys are absolute, so a bare "
                    "'.env' or '*.pem' would never match)"
                )
        except (GlobError, ValueError) as exc:
            raise _at_error(str(exc), index) from None
        out.append(pattern)
    return tuple(out)


# --- trusted projects -------------------------------------------------------------------------

MAX_TRUSTED_PROJECTS: Final = 64
MAX_TRUSTED_PROJECT_CHARS: Final = 1024
_TRUSTED_FORBIDDEN_CHARS: Final = "*?[$%"

# Directories that hold many projects (or the whole system): trusting one means trusting everything
# below it. Compared on the casefolded key, whatever the flavor (macOS and Windows are
# case-insensitive, and over-matching is the safe direction here).
_BROAD_POSIX_EXACT: Final = frozenset(
    {
        "/home", "/users", "/root", "/tmp", "/var", "/var/tmp", "/usr", "/usr/local", "/opt",  # noqa: S108
        "/srv", "/mnt", "/media", "/volumes", "/private", "/private/tmp",
    }
)  # fmt: skip
_BROAD_POSIX_TREES: Final = ("/bin", "/sbin", "/lib", "/etc", "/boot", "/proc", "/sys", "/dev")
_BROAD_WINDOWS_EXACT: Final = frozenset(
    {"users", "temp", "tmp", "programdata", "users/public", "users/default", "users/all users"}
)
_BROAD_HOME_CHILDREN: Final = ("documents", "desktop", "downloads")
# X1 review of M1c-2 (M-3): the directories of keys, settings and application data inside the home
# directory are not projects, and nothing below them is either (a typo or a copy-paste must not
# trust ``~/.claude`` or ``~/.ssh``). Compared casefolded, like the list above. NOT checked by the
# policy loader (X1 re-review R-6: an entry written before this check existed would make the whole
# policy unloadable, and an agent cannot edit the file anyway): ``boundkeep trust add`` refuses
# them and ``boundkeep doctor`` warns about the ones already listed, see ``home_guard_tree_reason``.
_GUARD_HOME_TREES: Final = (
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".config", ".claude", ".boundkeep",
    ".password-store", ".terraform.d", ".vscode", ".cache", ".local", "appdata", "library",
)  # fmt: skip


def home_guard_tree_reason(key: str, home_key: str) -> str | None:
    """Why a directory (canonical ``/`` key) inside the home directory holds keys, settings or
    application data and so cannot be a trusted project; None when it does not."""
    folded = key.casefold()
    home = home_key.casefold().rstrip("/")
    if home and any(
        folded == f"{home}/{d}" or folded.startswith(f"{home}/{d}/") for d in _GUARD_HOME_TREES
    ):
        return "it is a directory of keys, settings or application data in your home directory"
    return None


def is_anchor_key(key: str) -> bool:
    """A filesystem root, a drive root or a UNC share root (a path key with nothing below)."""
    if key == "/" or (len(key) == 3 and key[1:] == ":/"):
        return True
    return key.startswith("//") and len([p for p in key[2:].split("/") if p]) <= 2


def too_broad(root: NormPath, home: NormPath | None) -> bool:
    """A root that is a filesystem or drive root, or holds the home directory (or is it).

    Shared by the normalizer (a project root like this is refused: every file under the home
    directory would be "inside the project") and by the ``trusted_projects`` check below.
    """
    if is_anchor_key(root.key):
        return True
    return home is not None and inside_project(home, root) is True


def _broad_reason(key: str, home_key: str) -> str | None:
    """Why a trusted-project key is too broad, or None. Keys are canonical (``/`` separators)."""
    folded = key.casefold()
    if len(folded) >= 3 and folded[1] == ":" and folded[2] == "/":
        rest = folded[3:]
        if rest in _BROAD_WINDOWS_EXACT:
            return "it holds the profiles or shared folders of the machine"
        first = rest.split("/", 1)[0]
        if first == "windows" or first == "program files" or first.startswith("program files "):
            return "it is a Windows system or program directory"  # incl. "program files (x86)"
    else:
        if folded in _BROAD_POSIX_EXACT:
            return "it holds the home directories or shared folders of the machine"
        if any(folded == tree or folded.startswith(tree + "/") for tree in _BROAD_POSIX_TREES):
            return "it is a system directory"
    home = home_key.casefold().rstrip("/")
    if any(folded == f"{home}/{child}" for child in _BROAD_HOME_CHILDREN):
        return "it is one of your Documents, Desktop or Downloads folders (it holds many things)"
    return None


def _is_absolute_entry(raw: str) -> bool:
    if raw.startswith("/"):
        return True
    return (
        len(raw) >= 3
        and raw[0].isascii()
        and raw[0].isalpha()
        and raw[1] == ":"
        and raw[2] in "/\\"
    )


def _canonical_trusted_project(raw: str, context: object) -> str:
    """The canonical key of one ``trusted_projects`` entry. Raises ``ValueError`` (clear text).

    An entry means "this directory and everything under it". It is validated like a path the
    gate relies on: anything ambiguous (relative, UNC, ``..``, a variable, a wildcard, an NTFS
    stream, a translated MSYS / WSL form) is refused, and so is a directory that is too broad to
    be called a project (the home directory and its ancestors, a drive or filesystem root, the
    folders that hold other people's or many projects' files, system directories).
    """
    if not raw.strip():
        raise ValueError("is empty")
    if len(raw) > MAX_TRUSTED_PROJECT_CHARS:
        raise ValueError(f"is longer than {MAX_TRUSTED_PROJECT_CHARS} characters")
    if not raw.isprintable():
        raise ValueError("contains a control or other non-printable character")
    if raw != raw.strip():
        raise ValueError("has leading or trailing whitespace")
    bad = next((ch for ch in raw if ch in _TRUSTED_FORBIDDEN_CHARS), None)
    if bad is not None:
        raise ValueError(
            f"contains '{bad}': an entry is a plain directory, not a pattern or a variable "
            "(it already means 'this directory and everything under it')"
        )
    if ".." in re.split(r"[\\/]", raw):
        raise ValueError("has a '..' segment: write the final path")
    if raw.startswith(("\\\\", "//")):
        raise ValueError("is a UNC (network) path: a network share cannot be a trusted project")
    home_key = _resolve_home_key(context)
    home_windows = len(home_key) >= 3 and home_key[1] == ":"
    if raw.startswith("~"):
        if raw == "~":
            raise ValueError("is your home directory itself: far too broad for a trusted project")
        if raw[1] not in "/\\":
            raise ValueError("only '~/...' (or '~\\...') is supported, not '~user'")
        rest = raw[2:]
        if not rest.strip("/\\"):
            raise ValueError("is your home directory itself: far too broad for a trusted project")
        if home_windows:
            rest = rest.replace("\\", "/")
        elif "\\" in rest:
            raise ValueError("uses a backslash below '~' on a POSIX home: write it with '/'")
        text = home_key.rstrip("/") + "/" + rest
    elif _is_absolute_entry(raw):
        text = raw
    else:
        raise ValueError(
            "is not an absolute path: write 'C:\\...', 'C:/...', '/...' or '~/...' (a relative "
            "path has no fixed meaning)"
        )
    norm = normalize_path(text, cwd=None, home=None, dialect="tool", literal=True)
    if (
        not norm.absolute
        or norm.uncertain
        or norm.is_device
        or norm.reasons
        or not norm.key
        or "\x00" in norm.key
    ):
        why = f" ({', '.join(norm.reasons)})" if norm.reasons else ""
        hint = (
            "; a path whose first directory is one letter reads as a drive here, "
            "write the drive form (C:\\...) instead"
            if "msys-translated" in norm.reasons
            else ""
        )
        raise ValueError(f"is not a plain absolute directory path{why}{hint}")
    if norm.flavor == "posix" and "\\" in norm.key:
        raise ValueError(
            "has a backslash in a POSIX path: ambiguous, rename or write it another way"
        )
    home_norm = normalize_path(home_key, cwd=None, home=None, dialect="tool", literal=True)
    if too_broad(norm, home_norm):
        raise ValueError(
            "is too broad: it is a drive or filesystem root, your home directory, or a "
            "directory that contains your home directory"
        )
    reason = _broad_reason(norm.key, home_key)
    if reason is not None:
        raise ValueError(f"is too broad: {reason}")
    return norm.key


def _check_trusted_projects(values: tuple[str, ...], info: ValidationInfo) -> tuple[str, ...]:
    """Canonical keys of the entries, duplicates removed (first occurrence wins, order kept)."""
    if len(values) > MAX_TRUSTED_PROJECTS:
        raise ValueError(f"at most {MAX_TRUSTED_PROJECTS} trusted projects are allowed")
    out: dict[str, None] = {}
    for index, raw in enumerate(values):
        try:
            out.setdefault(_canonical_trusted_project(raw, info.context), None)
        except ValueError as exc:
            raise _at_error(f"{_shorten(raw)} {exc}", index) from None
    return tuple(out)


_Words = Annotated[
    tuple[str, ...],
    BeforeValidator(_one_or_list_to_tuple),
    Field(min_length=1, max_length=MAX_LIST_ITEMS),
    AfterValidator(_check_words),
]
_Programs = Annotated[
    tuple[str, ...],
    BeforeValidator(_one_or_list_to_tuple),
    Field(min_length=1, max_length=MAX_LIST_ITEMS),
    AfterValidator(_check_program_names),
    AfterValidator(_check_words),
]
_Subcommands = Annotated[
    tuple[str, ...],
    BeforeValidator(_one_or_list_to_tuple),
    Field(min_length=1, max_length=MAX_LIST_ITEMS),
    AfterValidator(_check_subcommand_names),
    AfterValidator(_check_words),
]
_Flags = Annotated[
    tuple[str, ...],
    BeforeValidator(_one_or_list_to_tuple),
    Field(min_length=1, max_length=MAX_LIST_ITEMS),
    AfterValidator(_check_words),
    AfterValidator(_check_flag_names),
]
_Tools = Annotated[
    tuple[str, ...],
    BeforeValidator(_one_or_list_to_tuple),
    Field(min_length=1, max_length=MAX_LIST_ITEMS),
    AfterValidator(_check_tools),
]
_Hosts = Annotated[
    tuple[str, ...],
    BeforeValidator(_one_or_list_to_tuple),
    Field(min_length=1, max_length=MAX_LIST_ITEMS),
    AfterValidator(_check_hosts),
]
_Globs = Annotated[
    tuple[str, ...],
    BeforeValidator(_one_or_list_to_tuple),
    Field(min_length=1, max_length=MAX_LIST_ITEMS),
    AfterValidator(_check_globs),
]
_Platforms = Annotated[
    tuple[Platform, ...],
    BeforeValidator(_one_or_list_to_tuple),
    Field(min_length=1, max_length=2),
]
_TrueOnly = Annotated[Literal[True], BeforeValidator(_true_only)]


def _check_env_name(value: str) -> str:
    if _ENV_NAME_RE.fullmatch(value) is None:
        raise ValueError(
            "api_key_env is the NAME of an environment variable (letters, digits, '_'), "
            "never the key itself"
        )
    if value.upper() == "ANTHROPIC_API_KEY":
        raise ValueError(
            "ANTHROPIC_API_KEY is not read by boundkeep (it would change Claude Code's own "
            "billing path); use BOUNDKEEP_LLM_API_KEY or another variable"
        )
    return value


_EnvName = Annotated[str, AfterValidator(_check_env_name)]


# --------------------------------------------------------------------------- llm_audit


class OpenAICompatible(BaseModel):
    """``llm_audit.openai_compatible``: any OpenAI-compatible chat endpoint (structure only)."""

    model_config = _STRICT

    base_url: str
    model: Annotated[str, Field(min_length=1, max_length=MAX_WORD_CHARS)]
    api_key_env: _EnvName = "BOUNDKEEP_LLM_API_KEY"
    transport: Literal["tool_call", "json_object"] = "tool_call"
    extra_body: _Frozen | None = None

    @field_validator("base_url")
    @classmethod
    def _https_only(cls, value: str) -> str:
        try:
            parts = urlsplit(value)
            host = (parts.hostname or "").lower()
            _ = parts.port  # raises ValueError for a malformed port
        except ValueError:
            raise ValueError("base_url is not a valid URL") from None
        if parts.username is not None or parts.password is not None:
            raise ValueError("base_url must not contain credentials")
        if not host or parts.fragment or not value.isprintable():
            raise ValueError("base_url must be a plain https URL")
        if parts.scheme == "https":
            return value
        if parts.scheme == "http" and host in _LOOPBACK_HOSTS:
            return value
        raise ValueError("base_url must be https (plain http only for localhost / 127.0.0.1 / ::1)")


class AnthropicBackend(BaseModel):
    """``llm_audit.anthropic``: the Anthropic API backend (structure only)."""

    model_config = _STRICT

    model: Annotated[str, Field(max_length=MAX_WORD_CHARS)] = ""
    api_key_env: _EnvName = "BOUNDKEEP_LLM_API_KEY"


class LlmAudit(BaseModel):
    """The optional LLM intent audit. Validated here, implemented in M3.

    ``on_failure`` is ``ask`` or ``deny``, never ``allow``: a failing auditor must not wave
    anything through. A backend named in ``backend`` must have its block.
    """

    model_config = _STRICT

    backend: Literal["none", "openai_compatible", "anthropic"] = "none"
    timeout_ms: Annotated[int, Field(ge=100, le=60_000)] = 4000
    on_failure: Literal["ask", "deny"] = "ask"
    send_task_intent: bool = True
    cache_ttl_s: Annotated[int, Field(ge=0, le=86_400)] = 600
    openai_compatible: OpenAICompatible | None = None
    anthropic: AnthropicBackend | None = None

    @field_validator("on_failure", mode="before")
    @classmethod
    def _never_allow(cls, value: Any) -> Any:
        if value == "allow":
            raise ValueError("on_failure must be 'ask' or 'deny': a failing audit never allows")
        return value

    @model_validator(mode="after")
    def _backend_has_its_block(self) -> LlmAudit:
        if self.backend != "none" and getattr(self, self.backend) is None:
            raise _at_error(
                f"backend is '{self.backend}' but the llm_audit.{self.backend} block is missing",
                "backend",
            )
        return self


# --------------------------------------------------------------------------- rules


def _refuse_nulls(data: Any, fields: Mapping[str, Any]) -> None:
    """Refuse an explicit null (``key:`` with nothing after it, ``null``, ``~``) for a field.

    "Absent" means "don't care", so a null that quietly meant the same would let a stray blank
    line widen an allow rule (``path_inside_project:`` dropping a condition) or make a rule apply
    to every tool or platform. Say so instead and point at the key.
    """
    if not isinstance(data, Mapping):
        return
    for key, value in data.items():
        if value is None and isinstance(key, str) and key in fields:
            raise _at_error(
                f"'{key}' is null (a blank or '~' value): omit the field to mean 'any', or give "
                "it a value; a null would silently drop the condition",
                key,
            )


class Match(BaseModel):
    """What a rule matches on. Fields are ANDed, list entries ORed; see ``policy/matcher.py``.

    A boolean field may only be ``true``; an absent field is "don't care". Lists must not be
    empty (an empty OR can never match, so the rule would be dead without saying so).
    """

    model_config = _STRICT

    path_glob: _Globs | None = None
    access: Literal["read", "write"] | None = None
    program: _Programs | None = None
    subcommand: _Subcommands | None = None
    flags_any: _Flags | None = None
    flags_none: _Flags | None = None  # same entries as flags_any; matches when NONE is present
    path_outside_project: _TrueOnly | None = None
    path_inside_project: _TrueOnly | None = None
    # at least one path and EVERY path is inside this session's scratchpad (never true for a path
    # that is uncertain or whose resolved form leaves it); says nothing about tool or program
    path_in_scratchpad: _TrueOnly | None = None
    paths_read_only: _TrueOnly | None = None  # every path is read-only (no paths: vacuously true)
    project_trusted: _TrueOnly | None = None  # the project directory is in trusted_projects
    network: _TrueOnly | None = None
    domain_not_in: _Hosts | None = None
    domain_in: _Hosts | None = None
    mcp_server: _Words | None = None  # case-sensitive: "GitHub" is not "github"

    @model_validator(mode="before")
    @classmethod
    def _no_null_fields(cls, data: Any) -> Any:
        _refuse_nulls(data, cls.model_fields)
        return data

    @model_validator(mode="after")
    def _access_needs_globs(self) -> Match:
        if self.access is not None and self.path_glob is None:
            raise ValueError("'access' only qualifies 'path_glob'; add path_glob or remove it")
        return self

    @model_validator(mode="after")
    def _inside_and_outside_exclude_each_other(self) -> Match:
        if self.path_outside_project is not None and self.path_inside_project is not None:
            raise ValueError(
                "path_outside_project and path_inside_project together can never match "
                "(one needs a path that is not inside, the other every path inside)"
            )
        return self

    @model_validator(mode="after")
    def _flags_any_and_none_are_disjoint(self) -> Match:
        if self.flags_any is not None and self.flags_none is not None:
            both = sorted(set(self.flags_any) & set(self.flags_none))
            if both:
                raise ValueError(
                    f"flags_any and flags_none both list {_shorten(both[0])}: no action can have "
                    "the flag and not have it, so the rule could never match"
                )
        return self

    def is_empty(self) -> bool:
        """True when no field is set (such a match selects every action)."""
        return all(getattr(self, name) is None for name in type(self).model_fields)


class Rule(BaseModel):
    """One policy rule. ``tool`` / ``platform`` filter first, then ``match``; see the matcher."""

    model_config = _STRICT

    id: Annotated[str, Field(min_length=1, max_length=MAX_RULE_ID_CHARS)]
    tool: _Tools | None = None
    platform: _Platforms | None = None
    match: Match
    action: Decision
    reason: Annotated[str, Field(max_length=MAX_REASON_CHARS)] = Field(
        default="", validate_default=True
    )

    @model_validator(mode="before")
    @classmethod
    def _no_null_filters(cls, data: Any) -> Any:
        # Only the filters: a null ``id`` / ``action`` / ``reason`` already fails the strict types.
        _refuse_nulls(data, {"tool": None, "platform": None})
        return data

    @field_validator("id")
    @classmethod
    def _id_shape(cls, value: str) -> str:
        if _RULE_ID_RE.fullmatch(value) is None:
            raise ValueError("a rule id may only use lowercase letters, digits and '-'")
        if value in RESERVED_RULE_IDS:
            raise ValueError(f"'{value}' is the id of a built-in rule and cannot be reused")
        return value

    @field_validator("reason")
    @classmethod
    def _reason_for_deny_and_ask(cls, value: str, info: ValidationInfo) -> str:
        if value and (not value.isprintable() or value != value.strip()):
            raise ValueError("reason must be printable text without surrounding spaces")
        if info.data.get("action") in ("deny", "ask") and not value:
            raise ValueError("a deny or ask rule needs a reason (shown to the user)")
        return value

    @model_validator(mode="after")
    def _path_conditions_need_a_tool_with_paths(self) -> Rule:
        if self.tool is not None and all(t in NON_PATH_TOOLS for t in self.tool):
            match = self.match
            if any(
                getattr(match, name) is not None
                for name in (
                    "path_glob",
                    "access",
                    "path_outside_project",
                    "path_inside_project",
                    "path_in_scratchpad",
                )
            ):
                raise _at_error(
                    "the listed tools never touch file paths, so a path condition (path_glob, "
                    "access, path_outside_project, path_inside_project, path_in_scratchpad) can "
                    "never match",
                    "tool",
                )
        return self

    @model_validator(mode="after")
    def _allow_needs_a_condition(self) -> Rule:
        if self.action == "allow" and self.match.is_empty():
            raise _at_error(
                "an allow rule needs at least one match field (an empty match would allow "
                "every action of the listed tools)",
                "match",
            )
        if self.action == "allow" and self.tool is None and self.match.program is None:
            raise _at_error(
                "an allow rule must name a tool or a program: a rule that only narrows by "
                "flags/paths would allow almost everything",
                "match",
            )
        return self


class PolicyTest(BaseModel):
    """A regression case: the hook's ``tool_input`` for ``tool`` and the expected verdict."""

    model_config = _STRICT

    tool: Annotated[str, Field(min_length=1, max_length=MAX_WORD_CHARS)]
    input: _Frozen
    platform: _Platforms | None = None
    cwd: Annotated[str, Field(min_length=1, max_length=1024)] | None = None
    project_dir: Annotated[str, Field(min_length=1, max_length=1024)] | None = None
    # The event's session_id (default: a fixed non-UUID one). A test of ``path_in_scratchpad`` needs
    # a UUID: the scratchpad is `<fake temp dir>/claude/<slug>/<session id>/scratchpad`.
    session_id: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    expect: Expect


class Policy(BaseModel):
    model_config = _STRICT

    version: Literal[1]
    mode: Mode = "enforce"
    defaults: Defaults = Field(default_factory=Defaults)
    taint: Taint = Field(default_factory=Taint)
    llm_audit: LlmAudit = Field(default_factory=LlmAudit)
    # Directories whose own code the user lets tools run without asking (``project_trusted``).
    # Stored as canonical path keys (``normalize.paths``: ``/`` separators, casefolded for the
    # Windows flavor, ``~`` expanded); an entry of the other platform's flavor never matches.
    trusted_projects: Annotated[
        tuple[str, ...],
        BeforeValidator(_list_to_tuple),
        AfterValidator(_check_trusted_projects),
    ] = ()
    rules: Annotated[tuple[Rule, ...], BeforeValidator(_list_to_tuple)] = ()
    tests: Annotated[tuple[PolicyTest, ...], BeforeValidator(_list_to_tuple)] = ()

    @model_validator(mode="before")
    @classmethod
    def _no_secrets(cls, data: Any) -> Any:
        found = (
            find_secret(data, skip=skip_policy_test_inputs) if isinstance(data, Mapping) else None
        )
        if found is not None:
            where = "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in found[0])
            raise ValueError(
                f"the value at '{where.lstrip('.') or '(top level)'}' looks like {found[1]}: "
                "never put secrets in a policy (name an environment variable with api_key_env)"
            )
        return data

    @field_validator("version", mode="before")
    @classmethod
    def _version_is_a_plain_int(cls, value: Any) -> Any:
        # Pydantic's Literal[1] accepts True and 1.0 even in strict mode.
        if type(value) is not int:
            raise ValueError("version must be the integer 1")
        return value

    @field_validator("rules", mode="after")
    @classmethod
    def _unique_rule_ids(cls, value: tuple[Rule, ...]) -> tuple[Rule, ...]:
        if len(value) > MAX_RULES:
            raise ValueError(f"at most {MAX_RULES} rules are allowed")
        first_seen: dict[str, int] = {}
        for index, rule in enumerate(value):
            if rule.id in first_seen:
                raise _at_error(
                    f"duplicate rule id '{rule.id}' (first used by rules[{first_seen[rule.id]}])",
                    index,
                    "id",
                )
            first_seen[rule.id] = index
        return value

    @field_validator("tests", mode="after")
    @classmethod
    def _limit_tests(cls, value: tuple[PolicyTest, ...]) -> tuple[PolicyTest, ...]:
        if len(value) > MAX_TESTS:
            raise ValueError(f"at most {MAX_TESTS} tests are allowed")
        return value
