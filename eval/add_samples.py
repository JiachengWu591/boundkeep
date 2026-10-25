"""Turn a plain text list of attack samples you wrote into a validated dataset file.

    python eval/add_samples.py eval/authoring/obfuscation.txt --category obfuscation

The input is one sample per line, fields separated by `` ### `` (blank lines and lines starting with
``#`` are ignored):

    platform ### tool ### verdict ### command or path ### why it is malicious [### tainted]

* platform: ``posix``, ``windows`` or ``any``
* tool: ``Bash`` or ``PowerShell`` (the field after it is a command), ``Read`` (a file path)
* verdict: ``ask`` (asking is enough) or ``deny`` (must be refused)
* the last optional field ``tainted`` marks a call made after external web content was read

The output file (``eval/datasets/attacks/<category>-v2.jsonl`` by default) is rewritten from the
input every time, so fix a line and run it again. Nothing is written unless the whole dataset,
including your new lines, validates; the error names the input line. Sample ids start at 100.

Exit code: 0 when written, 1 when a line or the dataset is invalid.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from boundkeep.evalkit import dataset
from boundkeep.evalkit.schema import Sample, split_of

ROOT = Path(__file__).resolve().parent
PREFIX = {"obfuscation": "atk-obf", "path-evasion": "atk-path"}
SEPARATOR = " ### "
DEFAULT_INTENT = "修复 utils.py 里的类型错误"
FIRST_NUMBER = 100


class LineError(Exception):
    pass


def parse_line(text: str, number: int) -> dict[str, object]:
    parts = [p.strip() for p in text.split(SEPARATOR)]
    if len(parts) not in (5, 6):
        raise LineError(f"line {number}: expected 5 fields separated by ' ### ' (got {len(parts)})")
    platform, tool, verdict, body, why = parts[:5]
    tainted = len(parts) == 6 and parts[5].lower() == "tainted"
    if len(parts) == 6 and not tainted:
        raise LineError(f"line {number}: the 6th field can only be 'tainted'")
    if platform not in ("posix", "windows", "any"):
        raise LineError(f"line {number}: platform must be posix, windows or any")
    if tool not in ("Bash", "PowerShell", "Read"):
        raise LineError(f"line {number}: tool must be Bash, PowerShell or Read")
    if verdict not in ("ask", "deny"):
        raise LineError(f"line {number}: verdict must be ask or deny")
    if not body or not why:
        raise LineError(f"line {number}: the command and the reason cannot be empty")
    tool_input = {"file_path": body} if tool == "Read" else {"command": body}
    return {
        "platform": platform,
        "tool": tool,
        "input": tool_input,
        "expected_min_verdict": verdict,
        "rationale": why,
        "tainted": tainted,
    }


def build(rows: list[dict[str, object]], category: str) -> list[dict[str, object]]:
    out = []
    for index, row in enumerate(rows):
        full: dict[str, object] = {
            "id": f"{PREFIX[category]}-{FIRST_NUMBER + index:03d}",
            "category": category,
            "label": "malicious",
            "task_intent": DEFAULT_INTENT,
            "taint_sources": ["web-content"] if row["tainted"] else [],
            "provenance": "handwritten",
            "runs_repo_code": False,
            "label_confirmed": True,  # written by the person who confirms
            "split": "dev",
            **row,
        }
        full["split"] = split_of(Sample.model_construct(**{**full, "pair": None}))
        out.append(full)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("input", type=Path, help="the text file with one sample per line")
    p.add_argument("--category", required=True, choices=sorted(PREFIX))
    p.add_argument("--out", type=Path, help="default: eval/datasets/attacks/<category>-v2.jsonl")
    p.add_argument("--datasets", type=Path, default=ROOT / "datasets")
    args = p.parse_args(argv)
    out: Path = args.out or args.datasets / "attacks" / f"{args.category}-v2.jsonl"
    try:
        lines = args.input.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        print(f"add_samples: cannot read {args.input}: {exc}", file=sys.stderr)  # noqa: T201
        return 1
    parsed: list[dict[str, object]] = []
    origin: list[int] = []
    try:
        for number, raw in enumerate(lines, start=1):
            if raw.strip() and not raw.lstrip().startswith("#"):
                parsed.append(parse_line(raw, number))
                origin.append(number)
    except LineError as exc:
        print(f"add_samples: {exc}", file=sys.stderr)  # noqa: T201
        return 1
    if not parsed:
        print("add_samples: no sample lines found", file=sys.stderr)  # noqa: T201
        return 1
    rows = build(parsed, args.category)
    try:
        existing = [
            item
            for path in sorted(args.datasets.rglob("*.jsonl"))
            if path.resolve() != out.resolve()
            for item in dataset.load_file(path)
        ]
        located = [
            dataset.Located(
                dataset.parse_line(json.dumps(row), f"{args.input.name}:{number}"),
                args.input.name,
                number,
            )
            for row, number in zip(rows, origin, strict=True)
        ]
        dataset.validate([*existing, *located])
    except dataset.DatasetError as exc:
        print(f"add_samples: {exc}", file=sys.stderr)  # noqa: T201
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
        encoding="utf-8",
        newline="\n",
    )
    print(f"wrote {len(rows)} sample(s) to {out}")  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
