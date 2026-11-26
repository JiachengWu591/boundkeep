"""Add a proposal to the policy file, keep backups, undo (PROJECT_SPEC.md §8.1).

The policy file is the user's: its comments and layout stay. New rules go after the last item of
the ``rules:`` list, new tests after the last item of ``tests:``, each block under one comment line
that says when and from where; a missing key is added at the end of the file, a list written in
flow style (``rules: []``) is refused. The new text is then read by the real loader and must give
exactly the old rules plus the new ones and the old tests plus the new ones, every other setting
unchanged; anything else and nothing is written (``merge_text`` / ``verify_merge``).

``apply`` copies the current file into ``~/.boundkeep/policy-history/`` (private, the newest
``KEEP`` copies kept), replaces the policy atomically and appends a line to
``policy-history/index.jsonl``. ``undo`` puts back the copy taken before the newest write that was
not undone yet, byte for byte. Neither asks anything: the command layer does the two checks of
``trust add`` and the typed ``yes`` first.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

import yaml

from boundkeep import fsperm, paths
from boundkeep.compiler.proposal import dump_rule, dump_test
from boundkeep.policy.loader import (
    MAX_POLICY_BYTES,
    PolicyError,
    _atomic_write,
    _decode,
    _read_policy_bytes,
    parse_policy_text,
    read_strict_mapping,
)
from boundkeep.policy.schema import Policy

KEEP: Final = 20
INDEX_NAME: Final = "index.jsonl"
_MAX_INDEX_BYTES: Final = 4 * 1024 * 1024
_BACKUP_RE: Final = re.compile(r"policy-\d{8}T\d{6}-\d{3,}\.yaml")


class MergeError(Exception):
    """The proposal cannot be added to this policy file as it is written. Safe to print."""


class NotRecorded(Exception):
    """The policy file WAS replaced, but its line in ``index.jsonl`` could not be written:
    ``undo`` will not find this change. ``backup`` is the copy of the file before it."""

    def __init__(self, entry: Entry, backup: str, reason: str) -> None:
        super().__init__(f"the history could not be recorded ({reason})")
        self.entry = entry
        self.backup = backup


# --------------------------------------------------------------------------- text


def _top_value(root: yaml.MappingNode, key: str) -> yaml.Node | None:
    for key_node, value_node in root.value:
        if isinstance(key_node, yaml.ScalarNode) and key_node.value == key:
            node: yaml.Node = value_node
            return node
    return None


def _end_index(node: yaml.Node) -> int:
    """The index just after the last character of ``node``'s own text. A block collection's end
    mark is where the NEXT token starts (after comments and blank lines), so it is taken from its
    leaves; a flow collection ends at its bracket."""
    if isinstance(node, yaml.ScalarNode):
        return int(node.end_mark.index)
    if getattr(node, "flow_style", False):
        return int(node.end_mark.index)
    ends = [int(node.start_mark.index)]
    if isinstance(node, yaml.MappingNode):
        for key_node, value_node in node.value:
            ends.append(_end_index(key_node))
            ends.append(_end_index(value_node))
    elif isinstance(node, yaml.SequenceNode):
        ends.extend(_end_index(item) for item in node.value)
    return max(ends)


def _clean_note(text: str) -> str:
    out = "".join(ch if " " <= ch <= "~" else "?" for ch in text)
    return out[:160]


def merge_text(
    text: str,
    rules: Sequence[dict[str, Any]],
    tests: Sequence[dict[str, Any]],
    *,
    note: str,
    expect_updates: Mapping[int, str] | None = None,
) -> str:
    """``text`` (a policy, without BOM) with ``rules`` and ``tests`` appended to its lists,
    and the ``expect`` of the existing tests in ``expect_updates`` (0-based index -> verdict)
    replaced in place."""
    if expect_updates:
        text = _replace_expects(text, expect_updates)
    try:
        _, root = read_strict_mapping(text, limit=MAX_POLICY_BYTES)
    except PolicyError as exc:
        raise MergeError(f"the policy file cannot be read ({exc})") from None
    comment = f"# {_clean_note(note)}"
    lines = text.splitlines(keepends=True)
    eol = "\r\n" if "\r\n" in text else "\n"
    inserts: list[tuple[int, list[str]]] = []
    appended: list[str] = []
    for key, items in (("rules", rules), ("tests", tests)):
        if not items:
            continue
        node = _top_value(root, key)
        if node is None:
            appended.append(f"{key}:")
            appended.append("  " + comment)
            appended.extend(_dump(key, items, 2))
            continue
        if not isinstance(node, yaml.SequenceNode) or not node.value:
            raise MergeError(
                f"the policy's '{key}:' is not a list of items; write it as a block list "
                f"('{key}:' and then '  - ...' lines) and try again"
            )
        if node.flow_style:
            raise MergeError(
                f"the policy's '{key}:' is written in flow style ([...]); write it as a block "
                f"list ('{key}:' and then '  - ...' lines) and try again"
            )
        first = node.value[0]
        row = lines[first.start_mark.line] if first.start_mark.line < len(lines) else ""
        dash = row.rfind("-", 0, first.start_mark.column)
        if dash < 0 or row[:dash].strip():
            raise MergeError(f"the layout of the policy's '{key}:' list is not understood")
        last_char = _end_index(node.value[-1]) - 1
        after_line = text.count("\n", 0, max(last_char, 0))
        block = [" " * dash + comment, *_dump(key, items, dash)]
        inserts.append((after_line, block))
    for after_line, block in sorted(inserts, key=lambda pair: pair[0], reverse=True):
        if after_line >= len(lines):
            raise MergeError("the policy file ended where a list item was expected")
        if not lines[after_line].endswith(("\n", "\r")):
            lines[after_line] += eol
        lines[after_line + 1 : after_line + 1] = [line + eol for line in block]
    if appended:
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += eol
        lines.extend(line + eol for line in appended)
    return "".join(lines)


_VERDICTS: Final = frozenset({"allow", "ask", "deny", "gray"})


def _replace_expects(text: str, updates: Mapping[int, str]) -> str:
    """Replace the ``expect`` value of the listed tests, and nothing else."""
    try:
        _, root = read_strict_mapping(text, limit=MAX_POLICY_BYTES)
    except PolicyError as exc:
        raise MergeError(f"the policy file cannot be read ({exc})") from None
    node = _top_value(root, "tests")
    if not isinstance(node, yaml.SequenceNode):
        raise MergeError("the policy has no tests: list to update")
    spans: list[tuple[int, int, str]] = []
    for index, verdict in updates.items():
        if verdict not in _VERDICTS or not 0 <= index < len(node.value):
            raise MergeError("an expectation to update is not one of the policy's tests")
        item = node.value[index]
        value = _top_value(item, "expect") if isinstance(item, yaml.MappingNode) else None
        if not isinstance(value, yaml.ScalarNode):
            raise MergeError(f"test #{index + 1} has no expect value to update")
        spans.append((int(value.start_mark.index), int(value.end_mark.index), verdict))
    for start, end, verdict in sorted(spans, reverse=True):
        text = text[:start] + verdict + text[end:]
    return text


def _dump(key: str, items: Sequence[dict[str, Any]], indent: int) -> list[str]:
    out: list[str] = []
    for item in items:
        if key == "rules":
            out.extend(dump_rule(item, indent))
        else:
            out.append(dump_test(item, indent))
    return out


def verify_merge(
    old_text: str,
    new_text: str,
    rules: Sequence[dict[str, Any]],
    tests: Sequence[dict[str, Any]],
    *,
    home: str | None,
    expect_updates: Mapping[int, str] | None = None,
) -> Policy:
    """``new_text`` read by the real loader must be ``old_text``'s policy plus exactly ``rules``
    and ``tests``; returns it. Raises ``MergeError`` (including for a policy that does not load,
    with the loader's message: duplicate ids, limits)."""
    try:
        old = parse_policy_text(old_text, home=home)
    except PolicyError as exc:
        raise MergeError(f"the current policy does not load ({exc})") from None
    try:
        new = parse_policy_text(new_text, home=home)
    except PolicyError as exc:
        raise MergeError(f"the policy with the proposal added does not load ({exc})") from None
    try:
        added = Policy.model_validate(
            {"version": 1, "rules": list(rules), "tests": list(tests)}, context={"home": home}
        )
    except Exception as exc:  # noqa: BLE001 - the proposal was validated before; fail closed
        raise MergeError(f"the proposal's rules do not validate ({type(exc).__name__})") from None
    old_tests = tuple(
        case.model_copy(update={"expect": expect_updates[i]})
        if expect_updates and i in expect_updates
        else case
        for i, case in enumerate(old.tests)
    )
    if new.rules != old.rules + added.rules or new.tests != old_tests + added.tests:
        raise MergeError("adding the proposal changed more than the rules and tests it adds")
    for name in Policy.model_fields:
        if name not in ("rules", "tests") and getattr(new, name) != getattr(old, name):
            raise MergeError(f"adding the proposal changed the policy's '{name}'")
    return new


# --------------------------------------------------------------------------- history


@dataclass(frozen=True)
class Entry:
    """One line of ``index.jsonl``."""

    ts: str
    op: str  # "apply" | "undo"
    source: str
    before_sha256: str
    after_sha256: str
    backup: str
    rules: tuple[str, ...]
    tests: int
    undoes: str | None = None  # undo: the ``ts`` of the write it undid
    path: str = ""  # the policy file written (absolute)

    def as_json(self) -> str:
        return json.dumps(
            {
                "ts": self.ts,
                "op": self.op,
                "source": self.source,
                "before_sha256": self.before_sha256,
                "after_sha256": self.after_sha256,
                "backup": self.backup,
                "rules": list(self.rules),
                "tests": self.tests,
                "undoes": self.undoes,
                "path": self.path,
            },
            ensure_ascii=True,
        )


def history_dir(home: str | None = None) -> str:
    return os.path.join(paths.home_dir() if home is None else home, "policy-history")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now() -> tuple[str, str]:
    """(an ISO timestamp, a backup file name), unique to the millisecond."""
    t = time.time()
    stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime(t)) + f"-{int(t * 1000) % 1000:03d}"
    iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t)) + f".{int(t * 1000) % 1000:03d}"
    return iso, f"policy-{stamp}.yaml"


def read_history(home: str | None = None) -> list[Entry]:
    """The entries of ``index.jsonl``, oldest first; unreadable lines are skipped."""
    path = os.path.join(history_dir(home), INDEX_NAME)
    try:
        with open(path, "rb") as handle:
            data = handle.read(_MAX_INDEX_BYTES + 1)
    except FileNotFoundError:
        return []
    if len(data) > _MAX_INDEX_BYTES:
        raise MergeError(f"{path} is larger than {_MAX_INDEX_BYTES} bytes")
    out: list[Entry] = []
    for raw in data.decode("utf-8", errors="replace").splitlines():
        try:
            obj = json.loads(raw)
            out.append(
                Entry(
                    ts=str(obj["ts"]),
                    op=str(obj["op"]),
                    source=str(obj.get("source", "")),
                    before_sha256=str(obj["before_sha256"]),
                    after_sha256=str(obj["after_sha256"]),
                    backup=str(obj["backup"]),
                    rules=tuple(str(r) for r in obj.get("rules", [])),
                    tests=int(obj.get("tests", 0)),
                    undoes=obj.get("undoes") if isinstance(obj.get("undoes"), str) else None,
                    path=str(obj.get("path", "")),
                )
            )
        except (ValueError, KeyError, TypeError):
            continue
    return out


def _same_path(a: str, b: str) -> bool:
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def pending_undo(entries: Sequence[Entry], policy_path: str) -> Entry | None:
    """The newest write of ``policy_path`` that has not been undone."""
    undone = {e.undoes for e in entries if e.op == "undo" and e.undoes}
    for entry in reversed(entries):
        if (
            entry.op == "apply"
            and entry.ts not in undone
            and entry.path
            and _same_path(entry.path, policy_path)
        ):
            return entry
    return None


def _ensure_private_dir(directory: str) -> None:
    os.makedirs(directory, exist_ok=True)
    with contextlib.suppress(OSError):
        fsperm.ensure_private_dir(directory)


def _append_index(directory: str, entry: Entry) -> None:
    path = os.path.join(directory, INDEX_NAME)
    with open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(entry.as_json() + "\n")
    with contextlib.suppress(OSError):
        fsperm.ensure_private_file(path)


def _record(directory: str, entry: Entry, backup: str) -> None:
    """Append ``entry``; the policy file is already replaced, so a failure is ``NotRecorded``
    (the caller must say the change was made), never an error that reads "not written"."""
    try:
        _append_index(directory, entry)
    except OSError as exc:
        raise NotRecorded(entry, backup, exc.strerror or type(exc).__name__) from None


def _prune(directory: str, keep_names: set[str]) -> None:
    names = sorted(n for n in os.listdir(directory) if _BACKUP_RE.fullmatch(n))
    for name in names[:-KEEP] if len(names) > KEEP else []:
        if name not in keep_names:
            with contextlib.suppress(OSError):
                os.remove(os.path.join(directory, name))


def current_bytes(policy_path: str) -> tuple[bytes, str, str]:
    """(the file's bytes, its BOM, its text). Raises ``PolicyError``."""
    data = _read_policy_bytes(policy_path)
    bom, text = _decode(data, policy_path)
    return data, bom, text


def apply(
    policy_path: str,
    *,
    expected_before: bytes,
    new_text: str,
    bom: str,
    source: str,
    rule_ids: Sequence[str],
    tests: int,
    home: str | None = None,
) -> Entry:
    """Back up the current file, replace it with ``new_text`` and record the write.

    ``expected_before`` is what the checks ran on: a file that changed since is not replaced
    (``MergeError``), so nothing the user did in between is lost."""
    data, _, _ = current_bytes(policy_path)
    if data != expected_before:
        raise MergeError("the policy file changed while the proposal was being checked; run again")
    directory = history_dir(home)
    _ensure_private_dir(directory)
    ts, name = _now()
    backup = os.path.join(directory, name)
    _atomic_write(backup, data)
    with contextlib.suppress(OSError):
        fsperm.ensure_private_file(backup)
    after = (bom + new_text).encode("utf-8")
    _atomic_write(policy_path, after)
    with contextlib.suppress(OSError):
        fsperm.ensure_private_file(policy_path)
    entry = Entry(
        ts=ts,
        op="apply",
        source=_clean_note(source),
        before_sha256=sha256(data),
        after_sha256=sha256(after),
        backup=name,
        rules=tuple(rule_ids),
        tests=tests,
        path=os.path.abspath(policy_path),
    )
    _record(directory, entry, backup)
    _prune(directory, {name})
    return entry


@dataclass(frozen=True)
class UndoPlan:
    target: Entry
    backup_path: str
    current: bytes
    changed_since: bool  # the file is not what that write left


def plan_undo(policy_path: str, home: str | None = None) -> UndoPlan:
    """What ``undo`` would do; ``MergeError`` when there is nothing to undo or no backup."""
    entries = read_history(home)
    target = pending_undo(entries, policy_path)
    if target is None:
        raise MergeError(f"there is no write of 'boundkeep policy' to {policy_path} to undo")
    if not _BACKUP_RE.fullmatch(target.backup):
        raise MergeError("the history names a backup file that is not one of boundkeep's")
    backup_path = os.path.join(history_dir(home), target.backup)
    if not os.path.isfile(backup_path):
        raise MergeError(f"the backup {target.backup} is gone; nothing was changed")
    current, _, _ = current_bytes(policy_path)
    return UndoPlan(target, backup_path, current, sha256(current) != target.after_sha256)


def undo(policy_path: str, plan: UndoPlan, home: str | None = None) -> Entry:
    """Put back ``plan``'s backup, byte for byte, and record the undo."""
    current, _, _ = current_bytes(policy_path)
    if current != plan.current:
        raise MergeError("the policy file changed since the undo was planned; run again")
    with open(plan.backup_path, "rb") as handle:
        data = handle.read(MAX_POLICY_BYTES + 1)
    if len(data) > MAX_POLICY_BYTES or sha256(data) != plan.target.before_sha256:
        raise MergeError("the backup is not the file it was taken from; nothing was changed")
    directory = history_dir(home)
    ts, name = _now()
    # the file being replaced is kept too: an undo can be undone by hand
    kept = os.path.join(directory, name)
    _atomic_write(kept, current)
    _atomic_write(policy_path, data)
    with contextlib.suppress(OSError):
        fsperm.ensure_private_file(policy_path)
    entry = Entry(
        ts=ts,
        op="undo",
        source=f"undo of {plan.target.ts}",
        before_sha256=sha256(current),
        after_sha256=sha256(data),
        backup=name,
        rules=plan.target.rules,
        tests=plan.target.tests,
        undoes=plan.target.ts,
        path=os.path.abspath(policy_path),
    )
    _record(directory, entry, kept)
    _prune(directory, {name, plan.target.backup})
    return entry
