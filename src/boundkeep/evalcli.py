"""``boundkeep eval``: build the real-session part of the evaluation datasets.

    boundkeep eval import-session PATH...   redact a Claude Code session into candidate samples
    boundkeep eval confirm FILE --ids ...   mark samples a person has reviewed (user command)
    boundkeep eval promote FILE             move the confirmed samples into eval/datasets/benign

Imported samples land in ``eval/staging/`` (git-ignored) with ``label_confirmed: false`` and a
review sheet next to them. Nothing reaches ``eval/datasets`` until a person confirmed it and ran
``promote``; the evaluation leaves unconfirmed samples out of every number.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from boundkeep import console, trust
from boundkeep.evalkit import dataset, importer

EXIT_OK = 0
EXIT_PROBLEM = 1
DEFAULT_DATASETS = Path("eval") / "datasets"
DEFAULT_OUT = Path("eval") / "staging" / "import.jsonl"
PROMOTED = "real.jsonl"


def _split_ids(text: str | None) -> list[str]:
    return [part.strip() for part in (text or "").split(",") if part.strip()]


def _existing(datasets: Path) -> list[Any]:
    """The samples already under `datasets` (none when the directory is empty or absent)."""
    if not datasets.is_dir() or not any(datasets.rglob("*.jsonl")):
        return []
    return dataset.load_dir(datasets)


def _known_keys(datasets: Path) -> set[str]:
    try:
        return {_key(s) for s in _existing(datasets)}
    except dataset.DatasetError as exc:
        console.err(f"boundkeep eval: {exc}")
        raise


def _key(sample: Any) -> str:
    from boundkeep.evalkit.schema import content_key

    return content_key(sample)


def review_sheet(rows: list[dict[str, Any]]) -> str:
    """A table for the person who confirms: what the call is, in which task, and the guess."""
    lines = [
        "# 真实会话导入：待确认样本",
        "",
        "每条都是**候选的正常样本**，已脱敏，但没有人确认过。请逐条看：这是一个正常的开发动作吗？",
        "是 → 用 `boundkeep eval confirm FILE --ids ...` 确认；不是（该拦的、含敏感信息的、你不想入库的）→ 不确认并从文件里删掉。",
        "`runs_repo_code` 是自动猜的（测试、检查器、构建、安装），请顺手核对。",
        "",
        "非 ASCII 列为“是”的样本带有中文等文字（常是你的项目或文件名），入库前请格外留意。",
        "",
        "| # | id | 平台 | 任务意图 | 工具 | 输入 | runs_repo_code | 非 ASCII | 你的结论 |",
        "|---:|---|---|---|---|---|---:|---:|---|",
    ]
    for number, row in enumerate(rows, start=1):
        shown = (
            row["input"].get("command")
            or row["input"].get("file_path")
            or json.dumps(row["input"], ensure_ascii=False)
        )
        text = str(shown).replace("|", "\\|").replace("\n", "\\n").replace("`", "'")
        intent = "" if row["task_intent"] == importer.NO_INTENT else row["task_intent"]
        nonascii = (
            "是" if not (json.dumps(row["input"], ensure_ascii=False) + intent).isascii() else ""
        )
        lines.append(
            f"| {number} | {row['id']} | {row['platform']} | {row['task_intent'].replace('|', '/')} | "
            f"{row['tool']} | `{text[:200]}` | {row['runs_repo_code']} | {nonascii} | |"
        )
    return "\n".join(lines) + "\n"


def cmd_import(args: argparse.Namespace) -> int:
    stats = importer.ImportStats()
    out = Path(args.out)
    try:
        known = _known_keys(Path(args.datasets))
    except dataset.DatasetError:
        return EXIT_PROBLEM
    rows: list[dict[str, Any]] = []
    sources = [Path(p) for p in args.paths]
    missing = [p for p in sources if not p.exists()]
    if missing:
        console.err(f"boundkeep eval: not found: {', '.join(map(str, missing))}")
        return EXIT_PROBLEM
    for file in importer.iter_session_files(sources):
        room = None if args.max is None else args.max - len(rows)
        if room is not None and room <= 0:
            break
        if args.per_file is not None:
            room = args.per_file if room is None else min(room, args.per_file)
        rows += importer.import_session(
            file,
            stats,
            project_dir=args.project_dir,
            home=args.home_dir,
            known=known,
            keep_intent=not args.no_intent,
            limit=room,
            shape_limit=args.shape_limit,
        )
    if rows:
        out.parent.mkdir(parents=True, exist_ok=True)
        body = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
        out.write_text(body, encoding="utf-8", newline="\n")
        sheet = out.with_suffix(".review.md")
        sheet.write_text(review_sheet(rows), encoding="utf-8", newline="\n")
        console.out(f"wrote {len(rows)} candidate sample(s) to {out} and {sheet}")
    else:
        console.out("no sample was kept; nothing was written")
    for line in stats.lines():
        console.out(f"  {line}")
    secrets = sum(n for reason, n in stats.dropped.items() if reason.startswith("secret:"))
    if secrets:
        console.out(f"  ({secrets} call(s) dropped because they looked like they held a secret)")
    console.out("These samples are NOT confirmed: review the sheet, then 'boundkeep eval confirm'.")
    return EXIT_OK


def cmd_confirm(args: argparse.Namespace) -> int:
    agent = trust.agent_environment()
    if agent:
        console.err(
            f"boundkeep eval confirm: refused: this looks like an agent session ({agent} is set). "
            "Confirming a label is the reviewer's decision; run it in your own terminal."
        )
        return EXIT_PROBLEM
    path = Path(args.file)
    ids = _split_ids(args.ids)
    if not ids and not args.all:
        console.err("boundkeep eval confirm: say which samples: --ids a,b or --all")
        return EXIT_PROBLEM
    try:
        changed = dataset.confirm_file(
            path, None if args.all else ids, except_ids=_split_ids(args.skip)
        )
    except (OSError, ValueError) as exc:
        console.err(f"boundkeep eval confirm: {exc}")
        return EXIT_PROBLEM
    console.out(f"{path}: {changed} sample(s) marked as confirmed")
    return EXIT_OK


def cmd_promote(args: argparse.Namespace) -> int:
    path = Path(args.file)
    datasets = Path(args.datasets)
    try:
        located = dataset.load_file(path)
    except dataset.DatasetError as exc:
        console.err(f"boundkeep eval promote: {exc}")
        return EXIT_PROBLEM
    ready = [item for item in located if item.sample.label_confirmed]
    if not ready:
        console.out("no confirmed sample in the file; nothing promoted")
        return EXIT_OK
    try:
        existing = _existing(datasets)
        dataset.validate([dataset.Located(s, "datasets", 0) for s in existing] + ready)
    except dataset.DatasetError as exc:
        console.err(f"boundkeep eval promote: {exc}")
        return EXIT_PROBLEM
    target = datasets / "benign" / PROMOTED
    target.parent.mkdir(parents=True, exist_ok=True)
    ready_ids = {item.sample.id for item in ready}
    with target.open("a", encoding="utf-8", newline="\n") as handle:
        for raw in path.read_text(encoding="utf-8").splitlines():
            if (
                raw.strip()
                and not raw.lstrip().startswith("#")
                and json.loads(raw)["id"] in ready_ids
            ):
                handle.write(raw + "\n")
    rest = [
        raw
        for raw in path.read_text(encoding="utf-8").splitlines()
        if not (
            raw.strip() and not raw.lstrip().startswith("#") and json.loads(raw)["id"] in ready_ids
        )
    ]
    path.write_text("".join(r + "\n" for r in rest), encoding="utf-8", newline="\n")
    console.out(f"promoted {len(ready)} sample(s) to {target}; {len(rest)} line(s) stay in {path}")
    return EXIT_OK


def add_parser(sub: Any) -> None:
    """Register ``eval`` (import-session / confirm / promote) on the top-level subparsers."""
    p = sub.add_parser(
        "eval",
        help="build the real-session samples of the evaluation datasets",
        description="Import, confirm and promote evaluation samples (see docs/eval-methodology.md).",
    )
    inner = p.add_subparsers(dest="eval_command", required=True, metavar="action")

    q = inner.add_parser(
        "import-session",
        help="redact Claude Code session files into candidate benign samples",
        description="Reads session JSONL files (or directories of them), drops calls that look "
        "like they hold a secret, rewrites paths to the fake machine and writes candidates "
        "to the staging file. Needs no network.",
    )
    q.add_argument("paths", nargs="+", help="session .jsonl files or directories holding them")
    q.add_argument("--out", default=str(DEFAULT_OUT), help=f"staging file (default {DEFAULT_OUT})")
    q.add_argument("--datasets", default=str(DEFAULT_DATASETS), help="existing datasets, for dedup")
    q.add_argument("--project-dir", help="the session's project directory (default: its cwd)")
    q.add_argument("--home-dir", help="the home directory to rewrite (default: derived)")
    q.add_argument("--max", type=int, help="stop after this many candidates")
    q.add_argument("--per-file", type=int, help="at most this many from each session file")
    q.add_argument(
        "--shape-limit",
        type=int,
        default=3,
        help="keep at most this many calls of the same shape (0 = no limit; default 3)",
    )
    q.add_argument("--no-intent", action="store_true", help="do not keep the user's prompt")
    q.set_defaults(func=cmd_import)

    q = inner.add_parser("confirm", help="mark samples as reviewed (a person's command)")
    q.add_argument("file", help="a staging or dataset .jsonl file")
    q.add_argument("--ids", help="comma-separated sample ids")
    q.add_argument("--all", action="store_true", help="every sample in the file")
    q.add_argument("--skip", help="comma-separated ids to leave unconfirmed (with --all)")
    q.set_defaults(func=cmd_confirm)

    q = inner.add_parser("promote", help="move confirmed samples into the datasets")
    q.add_argument("file", help="a staging .jsonl file")
    q.add_argument("--datasets", default=str(DEFAULT_DATASETS))
    q.set_defaults(func=cmd_promote)
