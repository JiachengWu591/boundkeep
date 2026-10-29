"""The holdout ledger: every time a sealed holdout batch is measured, a line is appended.

The holdout gives the one unbiased number for rules that were never tuned on it. That only holds
until somebody has seen its results and changes the rules afterwards, so ``run_eval.py
--open-holdout BATCH`` records each opening (batch, date, batch fingerprint, policy fingerprint)
in ``eval/holdout-ledger.jsonl``, a file that is committed with the results. A later opening of
the same batch under another policy, or of a batch whose samples changed after it was opened, is
declared contaminated in the report automatically; nobody has to remember to pass a flag. Each
batch has its own history: opening h1 again says nothing about h2.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: the ledger named no batch while there was only one; those lines are h1's
UNNAMED_BATCH = "h1"


@dataclass(frozen=True)
class Status:
    openings: tuple[dict[str, Any], ...]  # earlier openings of the batch, oldest first
    contaminated: bool
    why: str = ""


def batch_of(entry: dict[str, Any]) -> str:
    return str(entry.get("batch", UNNAMED_BATCH))


def read(path: Path, batch: str | None = None) -> list[dict[str, Any]]:
    """The recorded openings (of ``batch`` only, when given; none when there is no ledger yet)."""
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            entry = json.loads(raw)
            if batch is None or batch_of(entry) == batch:
                out.append(entry)
    return out


def status(path: Path, batch: str, holdout_hash: str, policy_sha256: str) -> Status:
    """Whether measuring ``batch`` now is still the first, clean look at it.

    Contaminated when an earlier opening of the batch was made under a different policy text (the
    rules may have been changed after its results were seen) or of other samples (samples were
    added, removed or relabeled after it had been opened).
    """
    earlier = read(path, batch)
    for entry in earlier:
        if entry.get("policy_sha256") != policy_sha256:
            return Status(
                tuple(earlier),
                True,
                f"opened on {entry.get('date')} under policy {str(entry.get('policy_sha256'))[:16]}"
                " and the policy changed since",
            )
        if entry.get("holdout_hash") != holdout_hash:
            return Status(
                tuple(earlier),
                True,
                f"opened on {entry.get('date')} with other samples (batch "
                f"{str(entry.get('holdout_hash'))[:16]}) and the samples changed since",
            )
    return Status(tuple(earlier), False)


def record(
    path: Path,
    *,
    batch: str,
    date: str,
    holdout_hash: str,
    policy_sha256: str,
    samples: int,
    config: str,
) -> None:
    entry = {
        "batch": batch,
        "date": date,
        "config": config,
        "holdout_hash": holdout_hash,
        "policy_sha256": policy_sha256,
        "samples": samples,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
