"""Load, validate and fingerprint the evaluation datasets (JSONL, one sample per line).

``load_dir`` is strict on purpose: a bad line, a duplicate id, a duplicate event, a split that does
not match the content hash, or something that looks like real data stops the load. The message
names the file and line so the sample can be fixed. ``split_hash`` is the fingerprint the report
records for the frozen test split.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from boundkeep.evalkit import redact
from boundkeep.evalkit.schema import (
    ATTACK_CATEGORIES,
    Sample,
    Split,
    action_key,
    content_key,
    split_of,
)

DEFAULT_DIR = Path(__file__).resolve().parents[3] / "eval" / "datasets"


class DatasetError(Exception):
    """A dataset file is not valid; the message names the file and the line."""


@dataclass(frozen=True)
class Located:
    sample: Sample
    file: str
    line: int


def _strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def inert_problems(sample: Sample) -> list[str]:
    """Reasons a sample is not safe to commit: a secret, a personal path, a real host."""
    texts = [sample.task_intent, sample.rationale, *_strings(sample.input)]
    attack = sample.label == "malicious"
    problems: list[str] = []
    for text in texts:
        problems.extend(str(leak) for leak in redact.find_leaks(text, strict_hosts=attack))
    return problems


def parse_line(raw: str, where: str) -> Sample:
    try:
        return Sample.model_validate_json(raw)
    except ValidationError as exc:
        details = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        raise DatasetError(f"{where}: {details}") from None


def load_file(path: Path) -> list[Located]:
    out: list[Located] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DatasetError(f"{path}: cannot read ({exc})") from exc
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        sample = parse_line(raw, f"{path.name}:{number}")
        out.append(Located(sample, path.name, number))
    return out


def load_dir(root: Path = DEFAULT_DIR) -> list[Sample]:
    """Every sample under ``root`` (recursively, ``*.jsonl``), validated as a set."""
    files = sorted(root.rglob("*.jsonl"))
    if not files:
        raise DatasetError(f"{root}: no *.jsonl files")
    located: list[Located] = []
    for file in files:
        located.extend(load_file(file))
    return validate(located)


def validate(located: Sequence[Located]) -> list[Sample]:
    ids: dict[str, Located] = {}
    events: dict[str, Located] = {}
    pair_splits: dict[str, Split] = {}
    for item in located:
        sample, where = item.sample, f"{item.file}:{item.line}"
        if sample.id in ids:
            first = ids[sample.id]
            raise DatasetError(
                f"{where}: duplicate id {sample.id!r} (first at {first.file}:{first.line})"
            )
        ids[sample.id] = item
        key = content_key(sample)
        if key in events:
            first = events[key]
            raise DatasetError(
                f"{where}: same event as {first.sample.id!r} ({first.file}:{first.line})"
            )
        events[key] = item
        problems = inert_problems(sample)
        if problems:
            raise DatasetError(f"{where}: not inert / not redacted: {', '.join(problems[:3])}")
        if (
            sample.pair is not None
            and pair_splits.setdefault(sample.pair, sample.split) != sample.split
        ):
            raise DatasetError(f"{where}: pair {sample.pair!r} straddles the splits")
        if sample.category == "injection-deviation" and sample.pair is None:
            raise DatasetError(f"{where}: an injection-deviation sample needs a pair key")
    # a holdout sample measures rules that were never tuned on it: the same action (with another
    # task intent) already in dev or test would leak it back
    tuned = {action_key(item.sample) for item in located if item.sample.split != "holdout"}
    for item in located:
        if item.sample.split == "holdout" and action_key(item.sample) in tuned:
            raise DatasetError(
                f"{item.file}:{item.line}: holdout sample {item.sample.id!r} repeats an action "
                "that is already in dev or test"
            )
    return [item.sample for item in located]


def split_hash(samples: Iterable[Sample], split: Split) -> str:
    """A fingerprint of one split: the sorted ids and event keys hashed together."""
    chosen = sorted((s.id, content_key(s), s.label) for s in samples if s.split == split)
    blob = json.dumps(chosen, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def counts(samples: Iterable[Sample]) -> dict[str, Counter[str]]:
    """Sample counts by label, category, platform, split and origin."""
    items = list(samples)
    return {
        "label": Counter(s.label for s in items),
        "category": Counter(s.category for s in items),
        "platform": Counter(s.platform for s in items),
        "split": Counter(s.split for s in items),
        "origin": Counter(s.origin for s in items),
        "provenance": Counter(s.provenance for s in items),
    }


def stamp_file(path: Path) -> int:
    """Fill in (or correct) the ``split`` of every line of ``path`` in place; returns lines changed.

    The author writes a sample without a split, or with a wrong one; the hash decides. Comment and
    blank lines are kept. Key order of a line is kept (``split`` goes last when it was missing).
    """
    changed = 0
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            lines.append(raw)
            continue
        data = json.loads(raw)
        probe = Sample.model_construct(**{**data, "split": "dev"})
        want = split_of(probe)
        if data.get("split") != want:
            data["split"] = want
            changed += 1
        lines.append(json.dumps(data, ensure_ascii=False))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return changed


def confirm_file(
    path: Path, ids: Iterable[str] | None = None, *, except_ids: Iterable[str] = ()
) -> int:
    """Mark samples of ``path`` as confirmed by a person; returns how many lines changed.

    ``ids`` None means every sample in the file. ``except_ids`` stay as they are. Only the
    ``label_confirmed`` key changes; everything else on the line is kept as it was.
    """
    wanted = None if ids is None else set(ids)
    skipped = set(except_ids)
    changed = 0
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            lines.append(raw)
            continue
        data = json.loads(raw)
        take = (wanted is None or data.get("id") in wanted) and data.get("id") not in skipped
        if take and data.get("label_confirmed") is not True:
            data["label_confirmed"] = True
            changed += 1
        lines.append(json.dumps(data, ensure_ascii=False))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return changed


def sealed(samples: Iterable[Sample]) -> tuple[list[Sample], list[Sample]]:
    """(the samples a normal run measures, the holdout samples it must leave alone)."""
    items = list(samples)
    return [s for s in items if s.split != "holdout"], [s for s in items if s.split == "holdout"]


def only_confirmed(samples: Iterable[Sample]) -> tuple[list[Sample], int]:
    """(the confirmed samples, how many were left out)."""
    items = list(samples)
    kept = [s for s in items if s.label_confirmed]
    return kept, len(items) - len(kept)


def expected_categories() -> tuple[str, ...]:
    return ATTACK_CATEGORIES
