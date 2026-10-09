"""Parse, load, edit and ship the boundkeep policy file.

The policy file is security configuration and hostile input: it may be edited by the user, by a
tool the agent ran, or by an attacker who got a write primitive. Everything here fails closed.
The daemon treats any ``PolicyError`` as "ask"; ``doctor`` reports it.

YAML hardening, all in ``_StrictLoader`` and ``parse_policy_text``:

* safe construction only (``SafeLoader`` subclass, pure Python, no arbitrary tags); explicit tags
  (``!!int``, ``!!bool``, ``!!python/...``) are refused altogether, since the schema never needs
  them and PyYAML's constructors for them raise plain ``KeyError`` / ``IndexError`` on bad input;
* duplicate keys are errors (PyYAML silently keeps the last one, so ``mode: audit-only`` after
  ``mode: enforce`` would win without anyone noticing);
* anchors, aliases and merge keys are errors (alias expansion is a denial-of-service vector and
  the schema has no use for them);
* booleans are only ``true`` / ``false`` (YAML 1.1 ``yes`` / ``on`` are plain strings here, so
  ``emit_allow: yes`` is a type error instead of silently switching off Claude Code's own
  confirmation prompt; a ``%YAML 1.2`` directive is therefore not misleading in the dangerous
  direction);
* nesting depth, scalar length and node count are bounded (PyYAML is pure Python and quadratic on
  some inputs, for example ``1:1:1:...``), and multi-document streams are errors;
* U+0085, U+2028 and U+2029 are refused: YAML treats them as line breaks, so they can end a
  comment and let a ``mode: audit-only`` hide inside what every line-based tool shows as a
  comment. A U+FEFF anywhere but the very start is refused for the same hiding-place reason.

The loader is cheap for a real policy but not free for a hostile one near the size limit; the
daemon already re-reads the file only when its mtime or size changes, and it must keep doing so.
"""

from __future__ import annotations

import contextlib
import importlib.resources
import os
import re
import stat
import sys
import tempfile
import time
from collections.abc import Iterator, Sequence
from typing import Any

import yaml
from pydantic import ValidationError

from boundkeep.policy.schema import MAX_TAINT_SOURCES, Mode, Policy, check_taint_source

MAX_POLICY_BYTES = 256 * 1024

_MAX_DEPTH = 32
_MAX_SCALAR_CHARS = 1024  # the longest legitimate value is a 128-character taint source
_MAX_NODES = 10_000  # a real M0 policy has a few dozen nodes; M1 may raise this deliberately
_MAX_MESSAGE_CHARS = 300
_MAX_PATH_CHARS = 400
_MAX_REPORTED_ERRORS = 5
_MODES: tuple[str, ...] = ("enforce", "audit-only")
_MERGE_TAG = "tag:yaml.org,2002:merge"
_BOOL_TAG = "tag:yaml.org,2002:bool"
_TRUE_FALSE = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")
_DEFAULT_RESOURCE_PACKAGE = "boundkeep"
_DEFAULT_RESOURCE_NAME = "data/default.yaml"

# Characters PyYAML treats as line breaks although a line-based tool does not (see module docs).
_HIDDEN_BREAKS = re.compile(r"[\x85\u2028\u2029]")
_ANY_LINE_BREAK = re.compile(r"\r\n|\n|\r")

# os.replace over a file that another process has open fails on Windows (Python opens files
# without FILE_SHARE_DELETE). Readers (the daemon, an editor, a virus scanner) hold files only
# briefly, so a short bounded retry turns a random failure into a success. Total wait about 1 s.
_REPLACE_RETRY_DELAYS: tuple[float, ...] = (0.05, 0.1, 0.2, 0.2, 0.2, 0.3)
_RETRY_REPLACE = sys.platform == "win32"


class PolicyError(Exception):
    """An unusable policy. ``str(error)`` is safe to print: bounded, printable, no file content.

    ``path`` keeps the caller's raw value; the message shows it cleaned and truncated, because a
    path can carry terminal escapes, lone surrogates (unencodable on a gbk console) or be huge.
    """

    def __init__(self, reason: str, *, path: str | None = None, line: int | None = None) -> None:
        self.reason = reason
        self.path = path
        self.line = line
        where = ""
        if path is not None:
            where = _clean(path, _MAX_PATH_CHARS)
        if line is not None:
            where = f"{where}:{line}" if where else f"line {line}"
        super().__init__(f"{where}: {reason}" if where else reason)

    def with_path(self, path: str) -> PolicyError:
        """The same error, tagged with the file it came from."""
        return PolicyError(self.reason, path=path, line=self.line)


def _clean(text: object, limit: int = _MAX_MESSAGE_CHARS) -> str:
    """Printable, bounded rendering of text that may come from a hostile file."""
    raw = str(text)
    out = "".join(ch if ch.isprintable() else "?" for ch in raw[: limit + 1])
    return out[: limit - 3] + "..." if len(out) > limit else out


def _escape(text: object, limit: int) -> str:
    """Bounded pure-ASCII rendering: non-ASCII becomes ``\\uXXXX``.

    Used for keys, so a look-alike (a Cyrillic "o" in ``mode``) is visibly different from the
    word the user thinks they typed instead of printing as "unknown key 'mode'".
    """
    raw = str(text)
    return ascii(raw[:limit])[1:-1] + ("..." if len(raw) > limit else "")


def _check_path(path: object) -> None:
    """Refuse values that are not a usable file name before any OS call sees them."""
    if not isinstance(path, str):
        raise PolicyError("the policy path must be a string")
    if "\0" in path:
        # The OS layer raises ValueError for this; a bad path must be a PolicyError like any
        # other policy failure so callers have one exception type to fail closed on.
        raise PolicyError("the policy path contains a NUL character", path=path)


# --------------------------------------------------------------------------- YAML


def _mark_line(mark: Any) -> int | None:
    return int(mark.line) + 1 if mark is not None else None


def _strict_bool_resolvers() -> dict[Any, list[tuple[str, re.Pattern[str]]]]:
    """SafeLoader's implicit resolvers with the YAML 1.1 boolean rule narrowed to true / false."""
    table: dict[Any, list[tuple[str, re.Pattern[str]]]] = {
        first: [(tag, regexp) for tag, regexp in resolvers if tag != _BOOL_TAG]
        for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    for first in "tTfF":
        table.setdefault(first, []).insert(0, (_BOOL_TAG, _TRUE_FALSE))
    return table


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate keys, anchors, aliases, merge keys, explicit tags,
    1.1-only booleans and oversized or deeply nested documents."""

    yaml_implicit_resolvers = _strict_bool_resolvers()

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._depth = 0
        self._nodes = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()  # type: ignore[no-untyped-call]
        line = _mark_line(event.start_mark)
        if isinstance(event, yaml.events.AliasEvent):
            raise PolicyError("YAML aliases are not allowed", line=line)
        if getattr(event, "anchor", None) is not None:
            raise PolicyError("YAML anchors are not allowed", line=line)
        if getattr(event, "tag", None) is not None:
            raise PolicyError("YAML tags are not allowed", line=line)
        value = getattr(event, "value", None)
        if isinstance(value, str) and len(value) > _MAX_SCALAR_CHARS:
            # Checked before the scalar is resolved or constructed: PyYAML's integer
            # construction of a sexagesimal ``1:1:1:...`` token is quadratic in its length.
            raise PolicyError(f"a value is longer than {_MAX_SCALAR_CHARS} characters", line=line)
        self._nodes += 1
        if self._nodes > _MAX_NODES:
            raise PolicyError(f"YAML has more than {_MAX_NODES} nodes", line=line)
        self._depth += 1
        if self._depth > _MAX_DEPTH:
            raise PolicyError(f"YAML is nested deeper than {_MAX_DEPTH} levels", line=line)
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        for key_node, _ in node.value:
            if key_node.tag == _MERGE_TAG:
                raise PolicyError(
                    "YAML merge keys ('<<') are not allowed", line=key_node.start_mark.line + 1
                )
        mapping: dict[Any, Any] = super().construct_mapping(node, deep=deep)
        if len(mapping) != len(node.value):
            seen: set[Any] = set()
            for key_node, _ in node.value:
                marker = (type(key_node).__name__, getattr(key_node, "value", None))
                if isinstance(key_node.value, str) and marker in seen:
                    raise PolicyError(
                        f"duplicate key '{_escape(key_node.value, 60)}'",
                        line=key_node.start_mark.line + 1,
                    )
                seen.add(marker)
            # Keys that are different spellings of one value (1 and 1.0, say).
            raise PolicyError("duplicate keys in a mapping", line=node.start_mark.line + 1)
        return mapping


def _node_line(root: yaml.Node, loc: Sequence[Any]) -> int | None:
    """Best-effort line (1-based) of the node a pydantic error location points at."""
    node: yaml.Node = root
    line: int | None = node.start_mark.line + 1
    for part in loc:
        if isinstance(node, yaml.MappingNode):
            for key_node, value_node in node.value:
                if isinstance(key_node, yaml.ScalarNode) and key_node.value == str(part):
                    line = key_node.start_mark.line + 1
                    node = value_node
                    break
            else:
                return line
        elif isinstance(node, yaml.SequenceNode) and isinstance(part, int):
            if not 0 <= part < len(node.value):
                return line
            node = node.value[part]
            line = node.start_mark.line + 1
        else:
            return line
    return line


def _format_loc(loc: Sequence[Any]) -> str:
    out = ""
    for part in loc:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += ("." if out else "") + _escape(part, 60)
    return out or "(top level)"


def _describe_validation_error(exc: ValidationError, root: yaml.Node) -> PolicyError:
    """Short messages from pydantic: location and message only, never the offending input."""
    errors = exc.errors(include_input=False, include_url=False, include_context=False)
    parts: list[str] = []
    first_line: int | None = None
    for index, err in enumerate(errors[:_MAX_REPORTED_ERRORS]):
        loc = err["loc"]
        line = _node_line(root, loc)
        if index == 0:
            first_line = line
        if err["type"] == "extra_forbidden":
            text = f"unknown key '{_format_loc(loc)}'"
        else:
            text = f"{_format_loc(loc)}: {_clean(err['msg'], 160)}"
        if index > 0 and line is not None:
            text += f" (line {line})"
        parts.append(text)
    if len(errors) > _MAX_REPORTED_ERRORS:
        parts.append(f"and {len(errors) - _MAX_REPORTED_ERRORS} more")
    return PolicyError("invalid policy: " + "; ".join(parts), line=first_line)


def _describe_yaml_error(exc: yaml.YAMLError) -> PolicyError:
    mark = getattr(exc, "problem_mark", None)
    line = mark.line + 1 if mark is not None else None
    problem = getattr(exc, "problem", None) or getattr(exc, "reason", None)
    if problem is None:
        return PolicyError("invalid YAML", line=line)
    return PolicyError(f"invalid YAML: {_clean(problem, 160)}", line=line)


def _refuse_hidden_line_breaks(text: str) -> None:
    """Reject characters YAML treats as line breaks (or BOMs) but line-based tools do not show."""
    match = _HIDDEN_BREAKS.search(text)
    if match is not None:
        raise PolicyError(
            f"the character U+{ord(match.group()):04X} is a YAML line break that most tools "
            "show as part of the line; it is not allowed in a policy",
            line=len(_ANY_LINE_BREAK.findall(text, 0, match.start())) + 1,
        )
    bom = text.find("\ufeff", 1)  # one leading BOM is the file's own business (load_policy)
    if bom != -1:
        raise PolicyError(
            "the character U+FEFF is not allowed inside a policy",
            line=len(_ANY_LINE_BREAK.findall(text, 0, bom)) + 1,
        )


def parse_policy_text(text: str) -> Policy:
    """Parse and validate a policy. Raises only ``PolicyError`` for any input."""
    if not isinstance(text, str):
        # PyYAML would happily sniff the encoding of bytes (UTF-16 included); never let it.
        raise PolicyError("the policy text must be a string")
    if len(text) > MAX_POLICY_BYTES:
        raise PolicyError(f"policy is larger than {MAX_POLICY_BYTES} bytes")
    _refuse_hidden_line_breaks(text)
    loader: _StrictLoader | None = None
    try:
        try:
            # The constructor already reads the text, so control characters fail here.
            loader = _StrictLoader(text)
            root = loader.get_single_node()
            if root is None:
                raise PolicyError("the policy file is empty")
            if not isinstance(root, yaml.MappingNode):
                raise PolicyError(
                    "the top level of a policy must be a mapping", line=root.start_mark.line + 1
                )
            data = loader.construct_document(root)
        except PolicyError:
            raise
        except yaml.YAMLError as exc:
            raise _describe_yaml_error(exc) from None
        except Exception as exc:  # noqa: BLE001 - deliberate catch-all, see below
            # Why a blanket catch: PyYAML's constructors leak plain exceptions of any type on
            # hostile scalars (ValueError / OverflowError for the timestamp 2001-13-45 or a
            # 5000-digit integer; KeyError, IndexError and AttributeError historically for bad
            # explicit-tag values), and RecursionError / MemoryError are possible for shapes the
            # limits did not foresee. The contract is "PolicyError or a Policy, nothing else":
            # the daemon fails closed on PolicyError only. Only the exception's class name is
            # kept, never its text, which may echo file content.
            raise PolicyError(f"invalid YAML: {_clean(type(exc).__name__)}") from None
        try:
            return Policy.model_validate(data)
        except ValidationError as exc:
            raise _describe_validation_error(exc, root) from None
    finally:
        if loader is not None:
            loader.dispose()


# --------------------------------------------------------------------------- files


def _read_policy_bytes(path: str) -> bytes:
    _check_path(path)
    try:
        info = os.stat(path)
        if not stat.S_ISREG(info.st_mode):
            raise PolicyError("not a regular file", path=path)
        if info.st_size > MAX_POLICY_BYTES:
            raise PolicyError(f"larger than {MAX_POLICY_BYTES} bytes", path=path)
        with open(path, "rb") as handle:
            data = handle.read(MAX_POLICY_BYTES + 1)
    except FileNotFoundError:
        raise PolicyError("policy file not found", path=path) from None
    except OSError as exc:
        raise PolicyError(
            f"cannot read policy file ({_clean(exc.strerror or 'I/O error')})", path=path
        ) from None
    except ValueError as exc:
        # Other bad path strings the OS layer rejects with ValueError ("path too long for
        # Windows", a lone surrogate that cannot be encoded).
        raise PolicyError(f"invalid policy path ({_clean(exc, 80)})", path=path) from None
    if len(data) > MAX_POLICY_BYTES:
        raise PolicyError(f"larger than {MAX_POLICY_BYTES} bytes", path=path)
    return data


def _decode(data: bytes, path: str) -> tuple[str, str]:
    """(BOM, text). The BOM is returned separately so an edit can put it back unchanged."""
    bom = ""
    if data.startswith(b"\xef\xbb\xbf"):
        bom = "\ufeff"
        data = data[3:]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise PolicyError("not valid UTF-8", path=path) from None
    if text.startswith("\ufeff"):
        raise PolicyError("the file starts with more than one byte order mark", path=path)
    return bom, text


def load_policy(path: str) -> Policy:
    """Read and validate the policy at ``path`` (a UTF-8 BOM is tolerated)."""
    _, text = _decode(_read_policy_bytes(path), path)
    try:
        return parse_policy_text(text)
    except PolicyError as exc:
        raise exc.with_path(path) from None


def _replace_with_retry(source: str, target: str) -> None:
    """``os.replace``, retried briefly on Windows while another process holds ``target`` open.

    Without the retry, ``boundkeep mode audit-only`` fails at random whenever the daemon, an
    editor or a scanner is reading the policy at that instant - exactly when a user is trying to
    get out of a blocking state. A PermissionError because ``target`` is a directory is final
    at once, and so is every error on other platforms (there it means real missing permission).
    """
    delays = iter(_REPLACE_RETRY_DELAYS if _RETRY_REPLACE else ())
    while True:
        try:
            os.replace(source, target)
            return
        except PermissionError:
            delay = next(delays, None)
            if delay is None or os.path.isdir(target):
                raise
            time.sleep(delay)


def _atomic_write(path: str, data: bytes) -> None:
    """Write ``data`` to ``path`` through a temp file in the same directory and ``os.replace``.

    The temp file is created by ``mkstemp`` (private to the current user on POSIX); a reader sees
    either the old file or the new one, never a half-written policy.
    """
    _check_path(path)
    tmp_path: str | None = None
    try:
        directory = os.path.dirname(os.path.abspath(path))
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".policy-", suffix=".tmp")
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _replace_with_retry(tmp_path, path)
        tmp_path = None
    except OSError as exc:
        hint = "; is the file open in another program?" if isinstance(exc, PermissionError) else ""
        raise PolicyError(
            f"cannot write policy file ({_clean(exc.strerror or 'I/O error')}{hint})", path=path
        ) from None
    except ValueError as exc:
        raise PolicyError(f"invalid policy path ({_clean(exc, 80)})", path=path) from None
    finally:
        if tmp_path is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)


_LINE_SPLIT = re.compile(r"(\r\n|\n|\r)")
_MODE_LINE = re.compile(
    r"^(?P<indent> *)(?P<key>mode[ \t]*:[ \t]*)(?P<quote>[\"']?)(?P<value>[^\s\"'#]+)(?P=quote)"
    r"(?P<rest>[ \t]*(?:#.*)?)$"
)
_MODE_KEY_START = re.compile(r"^ *mode[ \t]*:")


def _content_lines(lines: list[str]) -> Iterator[tuple[int, str]]:
    """Lines (index, text) that are neither blank, comments, directives nor document markers."""
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "%")) or stripped in ("---", "..."):
            continue
        yield index, line


def _replace_mode_line(text: str, mode: str) -> str:
    """Return ``text`` with only the value of the top-level ``mode:`` line replaced."""
    pieces = _LINE_SPLIT.split(text)  # even indexes: lines, odd indexes: their line endings
    lines = pieces[0::2]
    content = list(_content_lines(lines))
    if not content:
        raise PolicyError("no top-level 'mode:' line to edit")
    top_indent = len(content[0][1]) - len(content[0][1].lstrip(" "))
    candidates = [
        index
        for index, line in content
        if len(line) - len(line.lstrip(" ")) == top_indent and _MODE_KEY_START.match(line)
    ]
    if not candidates:
        raise PolicyError("no top-level 'mode:' line to edit (add one by hand)")
    if len(candidates) > 1:
        raise PolicyError("more than one top-level 'mode:' line; refusing to guess")
    index = candidates[0]
    match = _MODE_LINE.match(lines[index])
    if match is None:
        raise PolicyError("the 'mode:' line has an unusual form; edit it by hand", line=index + 1)
    quote = match.group("quote")
    lines[index] = (
        f"{match.group('indent')}{match.group('key')}{quote}{mode}{quote}{match.group('rest')}"
    )
    pieces[0::2] = lines
    return "".join(pieces)


def set_mode(path: str, mode: Mode) -> None:
    """Switch the policy's ``mode`` by editing only that line.

    Comments, key order, newline style (also mixed), a BOM and a trailing inline comment are kept
    byte for byte. The edit is validated before anything is replaced: the new text must parse and
    must equal the old policy except for ``mode`` (so a ``mode:`` look-alike inside a multi-line
    string is caught), and the file is replaced atomically. Raises ``PolicyError`` when the
    current file is invalid or has no top-level ``mode:`` line (nothing is inserted: guessing
    where could change meaning). Not safe against a concurrent writer; the policy has one editor.
    """
    if mode not in _MODES:
        raise PolicyError(f"unknown mode {_clean(repr(mode), 40)}; expected one of {_MODES}")
    bom, text = _decode(_read_policy_bytes(path), path)
    try:
        current = parse_policy_text(text)
        new_text = _replace_mode_line(text, mode)
        updated = parse_policy_text(new_text)
        if updated != current.model_copy(update={"mode": mode}):
            raise PolicyError("the edit would change more than 'mode'; refusing")
    except PolicyError as exc:
        raise exc.with_path(path) from None
    if new_text == text:
        return
    _atomic_write(path, (bom + new_text).encode("utf-8"))


# --------------------------------------------------------------------------- shipped default


def _repo_default_path() -> str:
    # src/boundkeep/policy/loader.py -> repo root is three directories above this package.
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(os.path.dirname(here)))
    return os.path.join(root, "policies", "default.yaml")


def _read_default_bytes() -> bytes:
    try:
        resource = importlib.resources.files(_DEFAULT_RESOURCE_PACKAGE).joinpath(
            *_DEFAULT_RESOURCE_NAME.split("/")
        )
        return resource.read_bytes()
    except (OSError, ModuleNotFoundError, ValueError):
        pass  # Not in a wheel: fall back to the source checkout below.
    try:
        with open(_repo_default_path(), "rb") as handle:
            return handle.read(MAX_POLICY_BYTES + 1)
    except OSError:
        raise PolicyError("the shipped default policy is missing") from None


def default_policy_text() -> str:
    """The shipped default policy, with LF newlines and no BOM; verified to parse.

    Read from package data (the wheel carries ``policies/default.yaml`` as
    ``boundkeep/data/default.yaml``), falling back to ``<repo root>/policies/default.yaml``.
    """
    data = _read_default_bytes()
    if len(data) > MAX_POLICY_BYTES:
        raise PolicyError("the shipped default policy is too large")
    _, text = _decode(data, "default policy")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    try:
        parse_policy_text(text)
    except PolicyError as exc:
        raise PolicyError(f"the shipped default policy is invalid: {exc.reason}") from None
    return text


def write_default_policy(path: str, *, overwrite: bool = False) -> bool:
    """Write the default policy to ``path``. False (and nothing written) if it exists.

    ``init`` must never silently replace a policy the user has edited; ``overwrite=True`` is for
    an explicit reset. Parent directories are created. The existence check and the replace are
    not one atomic step: concurrent ``init`` runs are not supported.
    """
    _check_path(path)
    text = default_policy_text()
    if os.path.lexists(path) and not overwrite:
        return False
    parent = path
    try:
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
    except OSError as exc:
        raise PolicyError(
            f"cannot create directory ({_clean(exc.strerror or 'I/O error')})", path=parent
        ) from None
    except ValueError as exc:
        raise PolicyError(f"invalid policy path ({_clean(exc, 80)})", path=path) from None
    _atomic_write(path, text.encode("utf-8"))
    return True


# --------------------------------------------------------------------------- matcher


def taint_sources_to_matcher(sources: Sequence[str]) -> str:
    """The Claude Code PostToolUse matcher for ``sources``.

    Claude Code treats a matcher made only of letters, digits, underscore, hyphen, comma, space
    and ``|`` as an exact, case-sensitive list of tool names; anything else is a JavaScript
    regular expression. So plain names give ``A|B|C``, and any glob (or a name containing ``.``,
    which would be a regex wildcard in the list form) gives an anchored regex
    ``^(?:A|B|prefix.*)$`` with ``.`` escaped and a trailing ``*`` turned into ``.*``. Names are
    de-duplicated, order kept. An empty list raises: an empty matcher means "all tools", which is
    not what ``taint.sources`` means. ``sources`` must be a list or tuple of names, at most
    ``MAX_TAINT_SOURCES`` of them, like the schema; a bare string (which is also a ``Sequence``
    of one-character strings) is refused, since ``"WebFetch"`` would otherwise silently become the
    matcher ``W|e|b|F|t|c|h`` and the real tool would never be watched.
    """
    if isinstance(sources, (str, bytes, bytearray)) or not isinstance(sources, Sequence):
        raise PolicyError("taint sources must be a list of names, not a single string")
    if len(sources) > MAX_TAINT_SOURCES:
        raise PolicyError(f"at most {MAX_TAINT_SOURCES} taint sources are allowed")
    names: dict[str, None] = {}
    for source in sources:
        try:
            names.setdefault(check_taint_source(source), None)
        except ValueError as exc:
            raise PolicyError(f"invalid taint source: {_clean(exc)}") from None
    if not names:
        raise PolicyError("no taint sources: an empty matcher would match every tool")
    if all(re.fullmatch(r"[A-Za-z0-9_\-]+", name) for name in names):
        return "|".join(names)
    alternatives: list[str] = []
    for name in names:
        prefix = name.removesuffix("*")
        alternatives.append(prefix.replace(".", r"\.") + (".*" if name.endswith("*") else ""))
    return "^(?:" + "|".join(alternatives) + ")$"
