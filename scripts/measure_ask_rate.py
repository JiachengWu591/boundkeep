"""Asks per 100 actions of a policy on a synthetic 'typical development workflow' (M1c measuring stick).

What it does: runs every entry of ``tests/corpus/workflow_benign.yaml`` through the real pipeline
(``boundkeep.policycli._run_one``, on the same fake machines ``boundkeep test`` uses: nothing here
touches your files, your home directory or the network) for each policy you name, and prints, per
platform and per tier:

  * how many entries got allow / gray / ask / deny (and ``error`` if the pipeline itself failed);
  * 'asks per 100 actions': an action counts as asked when the verdict is ask OR gray, because both
    prompt the user (``llm_audit.backend: none`` turns gray into ask), plus the same figure for the
    verdicts the corpus DESIGNS the policy to give (``expect_after``), as the target to reach;
  * the entries whose verdict differs from ``expect_after``. Comparison is by prompt class: allow,
    deny, and 'prompt' (ask and gray count as the same class, since the user is asked either way).

Corpus entries: ``{id, tool, platform?, input, tier, expect_after, expect_trusted?, today?,
session_id?}`` (``session_id``: the hook event's session id, a UUID for the scratchpad tier);
``expect_after`` may be a mapping ``{windows: ..., posix: ...}`` when the two machines are designed
to differ. ``expect_trusted`` is the verdict designed for a project listed in ``trusted_projects``
(the dev-tool entries of the ``t3-dev`` tier: ask untrusted, allow trusted); ``--trusted`` runs the
corpus with the fake machine's project trusted and compares against it. PowerShell
entries need the parser helper (Windows PowerShell 5.1 or pwsh); when it is not ready they are
skipped with a visible note, never counted.

It is a measuring tool: the exit code is 0 whatever the numbers are, 1 when the corpus or a policy
file cannot be read. Pure stdlib + boundkeep, deterministic, no network, writes only to stdout.

Usage (from the repository, with the venv):
    python scripts/measure_ask_rate.py                                  # the shipped default policy
    python scripts/measure_ask_rate.py --policy old.yaml --policy new.yaml
    python scripts/measure_ask_rate.py --platform posix --corpus tests/corpus/workflow_benign.yaml
    python scripts/measure_ask_rate.py --trusted                        # the project is trusted
Compare the committed policy with the working copy:
    git show HEAD:policies/default.yaml > %TEMP%\\default_head.yaml   (any scratch path)
    python scripts/measure_ask_rate.py --policy %TEMP%\\default_head.yaml --policy policies/default.yaml
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

import yaml

from boundkeep import policycli
from boundkeep.policy import Policy, PolicyError

DEFAULT_CORPUS = Path(__file__).resolve().parents[1] / "tests" / "corpus" / "workflow_benign.yaml"
PLATFORMS = ("windows", "posix")
VERDICTS = ("allow", "gray", "ask", "deny", "error")
REQUIRED = ("id", "tool", "input", "tier", "expect_after")
PROMPTING = ("ask", "gray", "error")  # error fails closed: a pipeline failure prompts as well

RunOne = Callable[..., str]  # (policy, platform, tool, input[, session_id=...]) -> verdict


class CorpusError(Exception):
    """The corpus file is unreadable or malformed."""


def load_corpus(path: Path) -> list[dict[str, Any]]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise CorpusError(f"cannot read the corpus {path}: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise CorpusError(f"the corpus {path} must be a non-empty list of entries")
    for index, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise CorpusError(f"corpus entry #{index + 1} is not a mapping")
        missing = [key for key in REQUIRED if key not in entry]
        if missing:
            raise CorpusError(f"corpus entry #{index + 1} lacks: {', '.join(missing)}")
        if not isinstance(entry["input"], dict):
            raise CorpusError(f"corpus entry {entry['id']}: input must be a mapping")
    return data


def resolve(value: Any, platform: str) -> str | None:
    """A verdict field is a plain word, or a ``{platform: word}`` mapping."""
    if isinstance(value, Mapping):
        picked = value.get(platform)
        return None if picked is None else str(picked)
    return None if value is None else str(value)


def verdict_class(verdict: str) -> str:
    """allow | deny | prompt (ask, gray and error all end in a question to the user)."""
    return verdict if verdict in ("allow", "deny") else "prompt"


def asks_per_100(counts: Mapping[str, int]) -> float:
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return 100.0 * sum(counts.get(v, 0) for v in PROMPTING) / total


@dataclass
class Mismatch:
    id: str
    tier: str
    platform: str
    expected: str
    got: str


@dataclass
class PlatformResult:
    platform: str
    by_tier: dict[str, Counter[str]] = field(default_factory=dict)
    target_by_tier: dict[str, Counter[str]] = field(default_factory=dict)
    mismatches: list[Mismatch] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def total(self) -> Counter[str]:
        out: Counter[str] = Counter()
        for counts in self.by_tier.values():
            out.update(counts)
        return out

    def target_total(self) -> Counter[str]:
        out: Counter[str] = Counter()
        for counts in self.target_by_tier.values():
            out.update(counts)
        return out


def default_run_one(
    policy: Policy,
    platform: str,
    tool: str,
    tool_input: Mapping[str, Any],
    session_id: str | None = None,
) -> str:
    result = policycli._run_one(policy, platform, tool, tool_input, None, None, session_id)  # type: ignore[arg-type]
    return str(result.verdict.decision)


def trust_fake_project(policy: Policy, platform: str) -> Policy:
    """``policy`` with the fake machine's project directory in ``trusted_projects`` (in memory only).

    What ``boundkeep trust add`` would do on that machine; the shipped policy files are not touched.
    """
    from boundkeep.normalize.paths import normalize_path

    project = policycli._FAKE[platform]["project"]
    key = normalize_path(project, cwd=None, home=None, dialect="tool", literal=True).key
    return policy.model_copy(update={"trusted_projects": (*policy.trusted_projects, key)})


def measure_platform(
    entries: Sequence[Mapping[str, Any]],
    policy: Policy,
    platform: str,
    *,
    ps_available: bool,
    run_one: RunOne = default_run_one,
    trusted: bool = False,
) -> PlatformResult:
    out = PlatformResult(platform)
    for entry in entries:
        only = entry.get("platform")
        if only is not None and only != platform:
            continue
        if entry["tool"] == "PowerShell" and not ps_available:
            out.skipped.append(str(entry["id"]))
            continue
        tier = str(entry["tier"])
        # an entry may carry the hook event's session_id (the scratchpad tier needs a UUID one);
        # only then is it passed on, so a run_one that takes four arguments keeps working
        extra = {"session_id": str(entry["session_id"])} if entry.get("session_id") else {}
        try:
            got = run_one(policy, platform, str(entry["tool"]), entry["input"], **extra)
        except Exception:  # a broken entry must not stop the measurement
            got = "error"
        out.by_tier.setdefault(tier, Counter())[got] += 1
        design = (
            entry["expect_trusted"]
            if trusted and "expect_trusted" in entry
            else entry["expect_after"]
        )
        expected = resolve(design, platform)
        if expected is None:
            continue
        out.target_by_tier.setdefault(tier, Counter())[expected] += 1
        if verdict_class(got) != verdict_class(expected):
            out.mismatches.append(Mismatch(str(entry["id"]), tier, platform, expected, got))
    return out


def ps_helper_ready() -> bool:
    """Start the parser helper and wait a little; True only when it can parse PowerShell."""
    from boundkeep.normalize import psparse

    psparse.warm_up(wait_s=10)
    return bool(psparse.status().get("state") == "ready")


def _row(label: str, counts: Mapping[str, int], target: Mapping[str, int]) -> str:
    total = sum(counts.values())
    cells = "".join(f"{counts.get(v, 0):>7}" for v in VERDICTS)
    return (
        f"  {label:<12}{total:>6}{cells}{asks_per_100(counts):>12.1f}{asks_per_100(target):>10.1f}"
    )


def render(label: str, results: Sequence[PlatformResult], out: TextIO) -> None:
    def say(text: str = "") -> None:
        out.write(text + "\n")

    for result in results:
        say()
        say(f"== {label} / {result.platform}")
        header = f"  {'tier':<12}{'n':>6}" + "".join(f"{v:>7}" for v in VERDICTS)
        say(header + f"{'asks/100':>12}{'target':>10}")
        for tier in sorted(result.by_tier):
            say(_row(tier, result.by_tier[tier], result.target_by_tier.get(tier, Counter())))
        say(_row("ALL", result.total(), result.target_total()))
        if result.skipped:
            say(
                f"  note: {len(result.skipped)} PowerShell entries SKIPPED "
                "(the PowerShell parser helper is not ready on this host); they are not counted"
            )
        say("  asks/100 = (ask + gray) per 100 actions; target = the same figure for expect_after")
        say(f"  entries whose verdict differs from expect_after: {len(result.mismatches)}")
        for m in result.mismatches:
            say(f"    {m.id:<34} {m.tier:<11} expect {m.expected:<6} got {m.got}")


def main(argv: Sequence[str] | None = None, out: TextIO | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument(
        "--policy",
        action="append",
        help="a policy file; repeat to compare (default: the shipped default policy)",
    )
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--platform", choices=[*PLATFORMS, "all"], default="all")
    parser.add_argument(
        "--trusted",
        action="store_true",
        help="run with the fake machine's project in trusted_projects (in memory): the target "
        "of an entry is its expect_trusted when it has one",
    )
    args = parser.parse_args(argv)
    out = out or sys.stdout
    try:
        entries = load_corpus(Path(args.corpus))
    except CorpusError as exc:
        sys.stderr.write(f"measure_ask_rate: {exc}\n")
        return 1
    platforms = list(PLATFORMS) if args.platform == "all" else [args.platform]
    wants_ps = "windows" in platforms and any(e["tool"] == "PowerShell" for e in entries)
    ps_available = ps_helper_ready() if wants_ps else False
    paths: list[str | None] = list(args.policy) if args.policy else [None]
    out.write(f"corpus: {args.corpus} ({len(entries)} entries)\n")
    for path in paths:
        label = os.path.basename(path) if path else "the shipped default policy"
        if args.trusted:
            label += " (project trusted)"
        results = []
        for platform in platforms:
            try:
                policy = policycli._load(path, platform)
            except (PolicyError, OSError) as exc:
                sys.stderr.write(f"measure_ask_rate: cannot load the policy {path}: {exc}\n")
                return 1
            if args.trusted:
                policy = trust_fake_project(policy, platform)
            results.append(
                measure_platform(
                    entries, policy, platform, ps_available=ps_available, trusted=args.trusted
                )
            )
        render(label, results, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
