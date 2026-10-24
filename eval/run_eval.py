"""Run the evaluation: ``uv run python eval/run_eval.py --config rules-only``.

Offline (no network, no key, no Claude Code): the samples under eval/datasets go through the real
rule pipeline on the fake machines of ``boundkeep test``. Writes eval/report.md and
eval/results/<config>.json.

    python eval/run_eval.py --config rules-only            # run and write the report
    python eval/run_eval.py --check                         # validate the datasets, show counts
    python eval/run_eval.py --stamp eval/datasets/x.jsonl   # fill in / correct the splits
    python eval/run_eval.py --config rules-only --policy policies/strict.yaml --out-dir %TEMP%\\ev

Exit code: 0 on success, 1 when a dataset or an option is invalid.
"""

from __future__ import annotations

import argparse
import datetime
import platform
import sys
from pathlib import Path

from boundkeep import __version__
from boundkeep.evalkit import dataset, metrics, report, runner

ROOT = Path(__file__).resolve().parent


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--config", default="rules-only", choices=list(runner.CONFIGS))
    p.add_argument("--policy", help="policy file (default: the shipped policies/default.yaml)")
    p.add_argument("--datasets", type=Path, default=ROOT / "datasets")
    p.add_argument("--out-dir", type=Path, default=ROOT)
    p.add_argument("--date", help="run date to print (default: today, UTC)")
    p.add_argument("--check", action="store_true", help="validate the datasets and stop")
    p.add_argument(
        "--include-unconfirmed",
        action="store_true",
        help="also measure samples no person has confirmed (never for a published report)",
    )
    p.add_argument("--stamp", type=Path, nargs="+", help="set the split of every sample in FILE")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.stamp:
        for path in args.stamp:
            print(f"{path}: {dataset.stamp_file(path)} line(s) changed")  # noqa: T201
        return 0
    try:
        samples = dataset.load_dir(args.datasets)
    except dataset.DatasetError as exc:
        print(f"eval: {exc}", file=sys.stderr)  # noqa: T201
        return 1
    if not args.include_unconfirmed:
        samples, left_out = dataset.only_confirmed(samples)
    else:
        left_out = 0
    if not samples and not args.check:
        print("eval: no confirmed samples to measure", file=sys.stderr)  # noqa: T201
        return 1
    counts = dataset.counts(samples)
    dev_hash = dataset.split_hash(samples, "dev")
    test_hash = dataset.split_hash(samples, "test")
    print(  # noqa: T201
        f"{len(samples)} samples: {dict(counts['label'])}, splits {dict(counts['split'])}, "
        f"dev {dev_hash[:16]}, test {test_hash[:16]}; {left_out} unconfirmed left out"
    )
    if args.check:
        return 0
    if not runner.CONFIGS[args.config]:
        print(f"eval: configuration {args.config} cannot run yet", file=sys.stderr)  # noqa: T201
        return 1
    result = runner.run(samples, config=args.config, policy_file=args.policy)
    trusted = runner.run(samples, config=args.config, policy_file=args.policy, trusted=True)
    computed = metrics.compute(result, trusted)
    info = {
        "date": args.date or datetime.datetime.now(datetime.UTC).date().isoformat(),
        "version": __version__,
        "python": platform.python_version(),
        "host": platform.system(),
        "dev_hash": dataset.split_hash(samples, "dev"),
        "test_hash": dataset.split_hash(samples, "test"),
        "samples": len(samples),
        "left_out_unconfirmed": left_out,
        "include_unconfirmed": bool(args.include_unconfirmed),
    }
    out_dir: Path = args.out_dir
    (out_dir / "results").mkdir(parents=True, exist_ok=True)
    (out_dir / "results" / f"{args.config}.json").write_text(
        report.to_json(computed, info), encoding="utf-8", newline="\n"
    )
    (out_dir / "report.md").write_text(
        report.to_markdown(computed, samples, info), encoding="utf-8", newline="\n"
    )
    print(f"wrote {out_dir / 'report.md'} and results/{args.config}.json")  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
