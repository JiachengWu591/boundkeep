"""The holdout ledger: every time the sealed holdout split is measured, a line is appended.

The holdout gives the one unbiased number for rules that were never tuned on it. That only holds
until somebody has seen its results and changes the rules afterwards, so ``run_eval.py
--open-holdout`` records each opening (date, holdout fingerprint, policy fingerprint) in
``eval/holdout-ledger.jsonl``, a file that is committed with the results. A later opening under
another policy, or of a holdout whose samples changed after it was opened, is declared
contaminated in the report automatically; nobody has to remember to pass a flag.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Status:
    openings: tuple[dict[str, Any], ...]  # earlier openings, oldest first
    contaminated: bool
    why: str = ""


def read(path: Path) -> list[dict[str, Any]]:
    """The recorded openings (none when the ledger does not exist yet)."""
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            out.append(json.loads(raw))
    return out


def status(path: Path, holdout_hash: str, policy_sha256: str) -> Status:
    """Whether measuring the holdout now is still the first, clean look at it.

    Contaminated when an earlier opening was made under a different policy text (the rules may
    have been changed after its results were seen) or of a different holdout (samples were added,
    removed or relabeled after it had been opened).
    """
    earlier = read(path)
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
                f"opened on {entry.get('date')} with other samples (holdout "
                f"{str(entry.get('holdout_hash'))[:16]}) and the samples changed since",
            )
    return Status(tuple(earlier), False)


def record(
    path: Path, *, date: str, holdout_hash: str, policy_sha256: str, samples: int, config: str
) -> None:
    entry = {
        "date": date,
        "config": config,
        "holdout_hash": holdout_hash,
        "policy_sha256": policy_sha256,
        "samples": samples,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
