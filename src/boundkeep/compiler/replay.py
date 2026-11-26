"""Replay preview: which past verdicts a proposal would change (PROJECT_SPEC.md §8.1).

The current policy and the candidate (the proposal added) judge the same events under the same
conditions, so every difference comes from the policy alone. Two sources:

* the dev split of the evaluation set (``rules-only``, the fake machines): only the ``attacks/``
  and ``benign/`` directories are read, only samples with ``split: dev``; ``holdout/`` is never
  opened and the test split is never used. The set only exists in a source checkout. A sample is
  shown by id, label and category, never by its content;
* the newest PreToolUse records of the audit log that are shell calls with their command text
  (``Bash`` / ``PowerShell``): the record's ``cwd`` stands for the project (the log does not keep
  the project directory), the real home and environment, no look at the disk, a fresh session.
  The log does not keep the paths of file tools, so those records, records without a command and
  commands cut by the log's length limit are counted as not replayable. A command the log's
  redaction rewrote is judged as written there.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from boundkeep import paths, policycli
from boundkeep.compiler.checks import MACHINES, RANK, Finding, Judge
from boundkeep.daemon import pipeline
from boundkeep.evalkit import dataset
from boundkeep.evalkit.schema import FAKE_SESSION, Sample
from boundkeep.logstore import AuditLog
from boundkeep.normalize.model import Platform
from boundkeep.policy import Policy, PolicyError, parse_policy_text
from boundkeep.redact import TRUNCATED

DEFAULT_LOG_LIMIT: Final = 1000
MAX_LOG_LIMIT: Final = 20_000
EXAMPLES: Final = 5
BROAD_SHARE: Final = 0.10
_COMMAND_SHOWN: Final = 100
_SHELLS: Final = frozenset({"Bash", "PowerShell"})


@dataclass(frozen=True)
class Change:
    label: str
    old: str
    new: str
    malicious: bool = False


@dataclass
class Section:
    name: str
    available: bool = True
    note: str = ""
    judged: int = 0
    unreplayable: int = 0
    benign: int = 0  # judged events that are not labeled malicious (dev) / every event (log)
    tighter: list[Change] = field(default_factory=list)
    looser: list[Change] = field(default_factory=list)

    @property
    def benign_tighter(self) -> int:
        return sum(1 for c in self.tighter if not c.malicious)

    @property
    def malicious_allowed(self) -> int:
        return sum(1 for c in self.looser if c.malicious and c.new == "allow")


def _diff(section: Section, label: str, old: str, new: str, malicious: bool) -> None:
    if old == new:
        return
    change = Change(label, old, new, malicious)
    if RANK.get(new, 2) > RANK.get(old, 2):
        section.tighter.append(change)
    else:
        section.looser.append(change)


# --------------------------------------------------------------------------- the dev split


def dev_samples(root: Path = dataset.DEFAULT_DIR) -> list[Sample]:
    """The dev split of ``attacks/`` and ``benign/`` under ``root`` (samples whose label the user
    confirmed, as in the evaluation report); never ``holdout/``."""
    files: list[Path] = []
    for sub in ("attacks", "benign"):
        directory = root / sub
        if directory.is_dir():
            files.extend(sorted(directory.rglob("*.jsonl")))
    if not files:
        raise dataset.DatasetError(f"{root}: no dataset files")
    located = [item for file in files for item in dataset.load_file(file)]
    samples = dataset.validate(located)
    return [s for s in samples if s.split == "dev" and s.holdout is None and s.label_confirmed]


def replay_dev(
    old: Judge, candidate: Judge, *, ps_ready: bool, root: Path = dataset.DEFAULT_DIR
) -> Section:
    section = Section("the dev split of the evaluation set (rules-only, fake machines)")
    try:
        samples = dev_samples(root)
    except (dataset.DatasetError, OSError) as exc:
        section.available = False
        section.note = (
            "skipped: the evaluation set is only in a source checkout of boundkeep "
            f"({str(exc)[:120]})"
        )
        return section
    for sample in samples:
        machines: tuple[Platform, ...] = (
            MACHINES if sample.platform == "any" else (sample.platform,)
        )
        for machine in machines:
            if sample.tool == "PowerShell" and not ps_ready:
                section.unreplayable += 1
                continue
            before = old.verdict(machine, sample.tool, sample.input, session_id=FAKE_SESSION)
            after = candidate.verdict(machine, sample.tool, sample.input, session_id=FAKE_SESSION)
            malicious = sample.label == "malicious"
            section.judged += 1
            if not malicious:
                section.benign += 1
            label = f"{sample.id} ({sample.label}, {sample.category}, {machine})"
            _diff(section, label, before.decision, after.decision, malicious)
    if section.unreplayable:
        section.note = f"{section.unreplayable} PowerShell sample run(s) skipped (no parser)"
    return section


# --------------------------------------------------------------------------- the audit log


def _shown_command(tool: str, command: str) -> str:
    text = " ".join(command.split())
    text = "".join(ch if ch.isprintable() else "?" for ch in text)
    if len(text) > _COMMAND_SHOWN:
        text = text[: _COMMAND_SHOWN - 3] + "..."
    return f"{tool}: {text}"


def log_events(limit: int, log_path: str | None = None) -> tuple[list[dict[str, Any]], int]:
    """(the newest ``limit`` PreToolUse records that can be replayed, how many of the newest
    ``limit`` PreToolUse records cannot)."""
    log = AuditLog(log_path or paths.audit_log_file())
    records = log.tail(min(limit * 4, MAX_LOG_LIMIT * 4))
    pre = [r for r in records if r.get("event") == "pre"][-limit:]
    usable: list[dict[str, Any]] = []
    skipped = 0
    for record in pre:
        tool = record.get("tool_name")
        command = record.get("command")
        cwd = record.get("cwd")
        if (
            tool not in _SHELLS
            or not isinstance(command, str)
            or not command
            or TRUNCATED in command
            or not isinstance(cwd, str)
            or not cwd
        ):
            skipped += 1
            continue
        usable.append(record)
    return usable, skipped


def replay_log(
    old_text: str,
    new_text: str,
    *,
    limit: int,
    log_path: str | None = None,
    home: str | None = None,
    env: Mapping[str, str] | None = None,
) -> Section:
    section = Section(f"the newest {limit} tool calls in the audit log (shell calls only)")
    if limit <= 0:
        section.available = False
        section.note = "skipped (--log-limit 0)"
        return section
    try:
        events, skipped = log_events(limit, log_path)
    except OSError as exc:
        section.available = False
        section.note = f"skipped: the audit log cannot be read ({type(exc).__name__})"
        return section
    section.unreplayable = skipped
    if not events and not skipped:
        section.available = False
        section.note = "skipped: the audit log has no tool calls yet"
        return section
    home = home if home is not None else os.path.expanduser("~")
    env = env if env is not None else os.environ
    platform = pipeline.local_platform()
    try:
        before_policy = parse_policy_text(old_text, home=home)
        after_policy = parse_policy_text(new_text, home=home)
    except PolicyError as exc:
        section.available = False
        section.note = f"skipped: {exc}"
        return section
    runtime_before, _ = policycli._runtime(before_policy, env, home)
    runtime_after, _ = policycli._runtime(after_policy, env, home)
    for record in events:
        payload = {
            "tool_name": record["tool_name"],
            "tool_input": {"command": record["command"]},
            "cwd": record["cwd"],
            "project_dir": record["cwd"],
            "session_id": "policy-replay",
        }
        before = _judge(payload, runtime_before, platform, env, home)
        after = _judge(payload, runtime_after, platform, env, home)
        section.judged += 1
        section.benign += 1
        _diff(
            section,
            _shown_command(str(record["tool_name"]), str(record["command"])),
            before,
            after,
            False,
        )
    if skipped:
        section.note = (
            f"{skipped} record(s) not replayable: file tools (the log keeps no paths), records "
            "without a command, or commands the log cut"
        )
    return section


def _judge(
    payload: Mapping[str, Any],
    policy: Policy,
    platform: Platform,
    env: Mapping[str, str],
    home: str,
) -> str:
    try:
        review = pipeline.review(
            payload, policy, platform=platform, env=env, home=home, scan_disk=False
        )
        return str(review.verdict.decision)
    except Exception:  # noqa: BLE001 - review never raises; if it does, count it as an ask
        return "error"


def replay(
    old_text: str,
    new_text: str,
    old: Judge,
    candidate: Judge,
    *,
    ps_ready: bool,
    log_limit: int,
    log_path: str | None = None,
    dataset_root: Path = dataset.DEFAULT_DIR,
    progress: Callable[[str], None] | None = None,
) -> list[Section]:
    say = progress or (lambda _text: None)
    say("replaying the dev split")
    sections = [replay_dev(old, candidate, ps_ready=ps_ready, root=dataset_root)]
    say("replaying the audit log")
    sections.append(replay_log(old_text, new_text, limit=log_limit, log_path=log_path))
    return sections


def findings(sections: list[Section]) -> list[Finding]:
    """The warnings of the replay: a malicious dev sample newly allowed (strong), and more than
    ``BROAD_SHARE`` of the benign events newly asked or denied (too broad)."""
    out: list[Finding] = []
    for section in sections:
        if not section.available:
            continue
        allowed = [c for c in section.looser if c.malicious and c.new == "allow"]
        if allowed:
            shown = "; ".join(c.label for c in allowed[:EXAMPLES])
            out.append(
                Finding(
                    "warn",
                    "replay-malicious-allowed",
                    f"WARNING: {len(allowed)} sample run(s) labeled malicious would be allowed "
                    f"in {section.name}: {shown}",
                )
            )
        if section.benign and section.benign_tighter / section.benign > BROAD_SHARE:
            out.append(
                Finding(
                    "warn",
                    "replay-broad",
                    f"{section.benign_tighter} of {section.benign} benign event(s) "
                    f"({100 * section.benign_tighter // section.benign}%) in {section.name} "
                    "would now be asked or denied: the rules may be too broad",
                )
            )
    return out
