"""Aggregate statistics of the tool calls in YOUR OWN Claude Code sessions (M1c, local, read-only).

What it does: reads the session transcripts under ``~/.claude/projects`` (JSONL), takes the tool
calls the assistant made (Bash, PowerShell, Read, Write, Edit, ...), runs each one through boundkeep's
normalizer and rule engine with the policy you name, and prints COUNTS.

What it prints (and nothing else):
  * how many tool calls there were per tool name;
  * the verdict distribution (allow / gray / ask / deny) per tool, for every policy you pass;
  * the program names of the shell commands whose verdict was NOT allow, only when the name occurs
    at least ``--min-count`` times and looks like a plain program name (so a personal script name
    that occurs twice never shows up);
  * the gray reasons, cut at the first ':' (``ps-exec`` instead of ``ps-exec:Invoke-Expression``).

What it NEVER prints: a command, an argument, a path, a file content, a prompt, a session id, a
project name or anything else from the transcripts. It writes nothing anywhere except stdout.
What it reads: the transcripts, and - because it runs boundkeep's real normalizer on every command -
metadata of the paths the commands name (does the path exist, is it inside the project) and, for
recursive reads of a directory, the NAMES (never the contents) of the files below it, exactly as the
daemon would. Run it yourself, read the output, and paste it only if you are comfortable with it.

Usage (from the repository, with the venv):
    uv run python scripts/session_command_stats.py                      # the shipped default policy
    uv run python scripts/session_command_stats.py --policy a.yaml --policy b.yaml
    uv run python scripts/session_command_stats.py --since-days 30 --min-count 8
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any, TextIO

SHELL_TOOLS = ("Bash", "PowerShell")
FILE_TOOLS = ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Grep", "Glob")
HANDLED = SHELL_TOOLS + FILE_TOOLS
_PLAIN_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.+-]{0,39}$")
VERDICTS = ("allow", "gray", "ask", "deny")


def iter_tool_calls(
    root: Path, since_days: float, limit: int
) -> Iterator[tuple[str, dict[str, Any], str | None]]:
    """(tool name, tool input, cwd) of the assistant's tool calls, newest files first."""
    cutoff = time.time() - since_days * 86400
    files = [p for p in root.rglob("*.jsonl") if p.is_file() and p.stat().st_mtime >= cutoff]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    seen = 0
    for path in files:
        try:
            handle = path.open("r", encoding="utf-8", errors="replace")
        except OSError:
            continue
        with handle:
            for line in handle:
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(obj, dict) or obj.get("type") != "assistant":
                    continue
                message = obj.get("message")
                content = message.get("content") if isinstance(message, dict) else None
                if not isinstance(content, list):
                    continue
                cwd = obj.get("cwd") if isinstance(obj.get("cwd"), str) else None
                for block in content:
                    if not (isinstance(block, dict) and block.get("type") == "tool_use"):
                        continue
                    name, tool_input = block.get("name"), block.get("input")
                    if isinstance(name, str) and isinstance(tool_input, dict):
                        yield name, tool_input, cwd
                        seen += 1
                        if seen >= limit:
                            return


def _plain_program(program: str | None) -> str | None:
    if not program:
        return None
    name = re.split(r"[\\/]", program)[-1]
    return name if _PLAIN_NAME.match(name) else None


# Only these kinds are followed by an AST node type name (never by user text); every other reason
# is cut at the first colon because its detail can be a program name or a path.
DETAIL_KINDS = ("ps-compound", "ps-dynamic", "ps-dynamic-value")


def _reason_detail(reason: str) -> str | None:
    kind, _, rest = reason.partition(":")
    if kind not in DETAIL_KINDS:
        return None
    # several node types can be joined by commas: keep only plain AST class names
    names = [n for n in rest.split(",") if re.match(r"^[A-Z][A-Za-z]{2,40}Ast$", n)]
    return f"{kind}:{names[0]}" if names else None


def where_is_it(ref: Any, tmp_key: str, home_key: str) -> str:
    """A fixed label for where a path is, never the path: the statistics must not leak locations."""
    if ref.inside_project is True:
        return "inside the project"
    key = str(ref.key)
    if ref.uncertain:
        return "path not knowable (variable, glob, ...)"
    if tmp_key and (key == tmp_key or key.startswith(tmp_key + "/")):
        return "the temp directory"
    if home_key and (key == home_key or key.startswith(home_key + "/")):
        return "the user home (outside the project)"
    return "elsewhere outside the project"


def _reason_kind(reason: str) -> str:
    kind = reason.split(":", 1)[0]
    return kind if re.match(r"^[a-z][a-z0-9-]{0,40}$", kind) else "other"


def analyse(
    calls: Iterator[tuple[str, dict[str, Any], str | None]],
    policies: list[Any],
    home: str,
    self_protection: bool = True,
) -> dict[str, Any]:
    from boundkeep.daemon import pipeline

    platform = pipeline.local_platform()
    fold = (lambda s: s.replace("\\", "/").lower()) if platform == "windows" else (lambda s: s)
    tmp_key = fold(tempfile.gettempdir())
    home_key = fold(home)
    runtimes = []
    for policy in policies:
        runtime, _problem = pipeline.runtime_policy_checked(policy, os.environ, home)
        if not self_protection:
            # measurement only: what the policy would say for a project that is NOT boundkeep's own
            # installed package (the runtime rule protect-guard-code guards that directory)
            runtime = runtime.model_copy(
                update={"rules": tuple(r for r in runtime.rules if r.id != "protect-guard-code")}
            )
        runtimes.append(runtime)
    tools: Counter[str] = Counter()
    verdicts: list[Counter[tuple[str, str]]] = [Counter() for _ in policies]
    programs: list[Counter[tuple[str, str]]] = [Counter() for _ in policies]
    reasons: list[Counter[str]] = [Counter() for _ in policies]
    details: list[Counter[str]] = [Counter() for _ in policies]
    places: list[Counter[tuple[str, str]]] = [Counter() for _ in policies]
    rules: list[Counter[tuple[str, str]]] = [Counter() for _ in policies]
    blockers: list[Counter[tuple[str, str]]] = [Counter() for _ in policies]
    for name, tool_input, cwd in calls:
        tools[name if name in HANDLED else "(other tools)"] += 1
        if name not in HANDLED:
            continue
        payload: dict[str, Any] = {"tool_name": name, "tool_input": tool_input}
        if cwd:
            payload["cwd"] = cwd
            payload["project_dir"] = cwd
        for index, runtime in enumerate(runtimes):
            try:
                result = pipeline.review(
                    payload, runtime, platform=platform, env=os.environ, home=home
                )
            except Exception:  # a transcript line must never stop the statistics
                verdicts[index][(name, "error")] += 1
                continue
            decision = result.verdict.decision
            verdicts[index][(name, decision)] += 1
            if decision == "allow":
                continue
            if name in FILE_TOOLS:
                first = next((p for a in result.actions for p in a.paths), None)
                label = where_is_it(first, tmp_key, home_key) if first else "no path in the call"
                places[index][(name, label)] += 1
            for rule_id in result.verdict.rule_ids:
                if re.match(r"^[A-Za-z0-9_-]{1,60}$", rule_id):
                    rules[index][(name, rule_id)] += 1
            kinds = sorted(
                {_reason_kind(r) for action in result.actions for r in action.gray_reasons}
            )
            blockers[index][
                (name, "+".join(kinds) if kinds else "(no gray reason: a rule asked)")
            ] += 1
            for action in result.actions:
                program = _plain_program(action.program) if name in SHELL_TOOLS else None
                if program:
                    programs[index][(name, program)] += 1
                for reason in action.gray_reasons:
                    reasons[index][_reason_kind(reason)] += 1
                    detail = _reason_detail(reason)
                    if detail:
                        details[index][detail] += 1
    return {
        "tools": tools,
        "verdicts": verdicts,
        "programs": programs,
        "reasons": reasons,
        "rules": rules,
        "blockers": blockers,
        "places": places,
        "details": details,
    }


def render(stats: dict[str, Any], labels: list[str], min_count: int, out: TextIO) -> None:
    def say(text: str = "") -> None:
        out.write(text + "\n")

    say("== tool calls per tool name")
    for name, count in stats["tools"].most_common():
        say(f"  {name:<14} {count}")
    for index, label in enumerate(labels):
        say()
        say(f"== policy {index + 1}: {label}")
        say("   verdict distribution per tool (allow means: no prompt from boundkeep)")
        per_tool: dict[str, Counter[str]] = {}
        for (tool, decision), count in stats["verdicts"][index].items():
            per_tool.setdefault(tool, Counter())[decision] += count
        for tool in sorted(per_tool):
            row = per_tool[tool]
            total = sum(row.values())
            cells = "  ".join(f"{v}={row[v]}" for v in (*VERDICTS, "error") if row[v])
            share = 100.0 * row["allow"] / total if total else 0.0
            say(f"   {tool:<12} total={total:<6} {cells}   allow={share:.1f}%")
        shown = [(k, c) for k, c in stats["programs"][index].most_common() if c >= min_count]
        hidden = sum(c for k, c in stats["programs"][index].items() if c < min_count)
        say(f"   shell programs whose verdict was not allow (names seen >= {min_count} times):")
        for (tool, program), count in shown[:40]:
            say(f"     {tool:<10} {program:<28} {count}")
        say(f"     (+ {hidden} occurrences of rarer program names, not shown)")
        say("   gray reasons (cut at the first ':'):")
        for kind, count in stats["reasons"][index].most_common(15):
            say(f"     {kind:<30} {count}")
        say("   file-tool calls that were not allowed, by where the FIRST path is (labels only):")
        for (tool, label), count in stats["places"][index].most_common(20):
            say(f"     {tool:<10} {label:<46} {count}")
        say("   AST node types behind ps-compound / ps-dynamic (class names only):")
        for detail, count in stats["details"][index].most_common(20):
            say(f"     {detail:<44} {count}")
        say(
            "   rules behind the non-allow verdicts (rule ids are policy names, never your content):"
        )
        for (tool, rule_id), count in stats["rules"][index].most_common(20):
            say(f"     {tool:<10} {rule_id:<40} {count}")
        say("   what blocks an allow, per call: the SET of gray-reason kinds of the whole call")
        say("   (a call blocked by one kind alone is the cheapest to unblock):")
        for (tool, kinds), count in stats["blockers"][index].most_common(20):
            say(f"     {tool:<10} {kinds:<60} {count}")


def main(argv: list[str] | None = None, out: TextIO | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--root", default=os.path.join(os.path.expanduser("~"), ".claude", "projects")
    )
    parser.add_argument(
        "--policy",
        action="append",
        help="a policy file; repeat to compare (default: the shipped one)",
    )
    parser.add_argument(
        "--trust",
        action="append",
        metavar="DIR",
        help="for the SHIPPED policy only: pretend this project directory is trusted (what "
        "`boundkeep trust add DIR` would do), to measure the dev-tools preset; nothing is written",
    )
    parser.add_argument(
        "--no-self-protection",
        action="store_true",
        help="measurement only: drop the runtime rule protect-guard-code (it guards boundkeep's "
        "own installed package, so sessions that develop boundkeep itself are skewed by it)",
    )
    parser.add_argument("--since-days", type=float, default=90.0)
    parser.add_argument("--min-count", type=int, default=5)
    parser.add_argument("--limit", type=int, default=20000, help="maximum number of tool calls")
    args = parser.parse_args(argv)
    out = out or sys.stdout
    root = Path(args.root)
    if not root.is_dir():
        sys.stderr.write(f"no transcripts under {root}\n")
        return 1
    from boundkeep.normalize import psparse
    from boundkeep.policy import default_policy_text, load_policy, parse_policy_text

    psparse.warm_up(wait_s=10)
    home = os.path.expanduser("~")
    policies: list[Any] = []
    labels: list[str] = []
    for path in args.policy or []:
        policies.append(load_policy(path, home=home))
        labels.append(os.path.basename(path))
    if not policies:
        text = default_policy_text()
        label = "the shipped default policy"
        if args.trust:
            from boundkeep import trust

            for directory in args.trust:
                text = trust.add_entry_text(text, trust.canonical_dir(directory))
            label += " + dev-tools preset trusted for %d project(s)" % len(args.trust)
        policies.append(parse_policy_text(text, home=home))
        labels.append(label)
    elif args.trust:
        sys.stderr.write("--trust only applies to the shipped policy (no --policy)\n")
        return 1
    stats = analyse(
        iter_tool_calls(root, args.since_days, args.limit),
        policies,
        home,
        self_protection=not args.no_self_protection,
    )
    if args.no_self_protection:
        labels = [label + " (without the runtime rule protect-guard-code)" for label in labels]
    render(stats, labels, max(args.min_count, 1), out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
