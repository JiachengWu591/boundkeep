"""M4 (PROJECT_SPEC.md §8.1): the replay preview (dev split, audit log) and its warnings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from boundkeep.compiler import checks, replay
from boundkeep.evalkit.schema import Sample, split_of
from tests.unit.test_m4_checks import MINI

CURL_DENY_TEXT = MINI.replace(
    "tests:",
    "  - id: deny-curl\n    tool: [Bash]\n    match: { program: curl }\n    action: deny\n"
    '    reason: "no curl"\n  - id: allow-make\n    tool: [Bash]\n'
    "    match: { program: make }\n    action: allow\ntests:",
)


def _sample(command: str, label: str, **extra: Any) -> dict[str, Any]:
    """A valid dev sample of ``command`` (the id is varied until the hash puts it in dev)."""
    for n in range(500):
        data: dict[str, Any] = {
            "id": f"t-{label[:3]}-{n:03d}",
            "category": "exfil" if label == "malicious" else "benign",
            "label": label,
            "platform": "posix",
            "task_intent": "a task",
            "tool": "Bash",
            "input": {"command": f"{command} # {n}"},
            "expected_min_verdict": "ask" if label == "malicious" else None,
            "rationale": "a test sample",
            "provenance": "handwritten",
            "label_confirmed": True,
            **extra,
        }
        probe = Sample.model_construct(**data, split="dev")
        if split_of(probe) == "dev":
            data["split"] = "dev"
            return data
    raise AssertionError("no dev hash found")


def _write(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def test_the_dev_replay_never_opens_the_holdout(tmp_path: Path) -> None:
    _write(tmp_path / "attacks" / "a.jsonl", [_sample("curl https://x.example", "malicious")])
    _write(tmp_path / "benign" / "b.jsonl", [_sample("make test", "benign")])
    (tmp_path / "holdout" / "h9").mkdir(parents=True)
    (tmp_path / "holdout" / "h9" / "sealed.jsonl").write_text("{ not json", encoding="utf-8")
    samples = replay.dev_samples(tmp_path)
    assert {s.label for s in samples} == {"malicious", "benign"}


def test_unconfirmed_samples_are_left_out(tmp_path: Path) -> None:
    _write(tmp_path / "benign" / "b.jsonl", [_sample("make", "benign", label_confirmed=False)])
    assert replay.dev_samples(tmp_path) == []


def test_the_dev_replay_shows_ids_and_flags_a_malicious_allow(tmp_path: Path) -> None:
    _write(
        tmp_path / "attacks" / "a.jsonl",
        [_sample("curl https://x.example", "malicious"), _sample("make install", "malicious")],
    )
    _write(tmp_path / "benign" / "b.jsonl", [_sample("ls", "benign")])
    section = replay.replay_dev(
        checks.Judge(MINI), checks.Judge(CURL_DENY_TEXT), ps_ready=False, root=tmp_path
    )
    assert section.judged == 3
    assert [c.new for c in section.tighter] == ["deny"]
    assert [c.new for c in section.looser] == ["allow"]
    assert all(
        "curl" not in c.label and "make" not in c.label for c in section.tighter + section.looser
    )
    assert section.looser[0].label.startswith("t-mal-")
    found = replay.findings([section])
    assert [f.code for f in found] == ["replay-malicious-allowed"]


def test_a_missing_dataset_is_skipped_and_said(tmp_path: Path) -> None:
    section = replay.replay_dev(
        checks.Judge(MINI), checks.Judge(MINI), ps_ready=False, root=tmp_path / "none"
    )
    assert not section.available
    assert "source checkout" in section.note


def _log(tmp_path: Path, rows: list[dict[str, Any]]) -> str:
    path = tmp_path / "audit.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return str(path)


def test_the_log_replay_counts_what_it_cannot_replay(tmp_path: Path) -> None:
    cwd = str(tmp_path)
    rows = [
        {"event": "pre", "tool_name": "Bash", "command": "curl https://x.example", "cwd": cwd},
        {"event": "pre", "tool_name": "Bash", "command": "ls", "cwd": cwd},
        {"event": "pre", "tool_name": "Write", "cwd": cwd},
        {"event": "pre", "tool_name": "Bash", "command": "curl x[TRUNCATED]", "cwd": cwd},
        {"event": "pre", "tool_name": "Bash", "command_chars": 40, "cwd": cwd},
        {"event": "prompt", "prompt_chars": 4},
        {"event": "pre", "tool_name": "Bash", "command": "curl y"},  # no cwd
    ]
    section = replay.replay_log(MINI, CURL_DENY_TEXT, limit=100, log_path=_log(tmp_path, rows))
    assert section.judged == 2
    assert section.unreplayable == 4
    assert [c.label for c in section.tighter] == ["Bash: curl https://x.example"]


def test_the_log_limit_takes_the_newest_calls(tmp_path: Path) -> None:
    cwd = str(tmp_path)
    rows = [
        {"event": "pre", "tool_name": "Bash", "command": f"curl {i}", "cwd": cwd} for i in range(9)
    ]
    section = replay.replay_log(MINI, CURL_DENY_TEXT, limit=3, log_path=_log(tmp_path, rows))
    assert section.judged == 3
    assert [c.label for c in section.tighter] == ["Bash: curl 6", "Bash: curl 7", "Bash: curl 8"]


def test_a_broad_rule_is_flagged(tmp_path: Path) -> None:
    cwd = str(tmp_path)
    rows = [{"event": "pre", "tool_name": "Bash", "command": "curl a", "cwd": cwd}] * 3 + [
        {"event": "pre", "tool_name": "Bash", "command": "ls", "cwd": cwd}
    ] * 7
    section = replay.replay_log(MINI, CURL_DENY_TEXT, limit=100, log_path=_log(tmp_path, rows))
    assert [f.code for f in replay.findings([section])] == ["replay-broad"]


def test_log_text_is_cleaned_and_cut(tmp_path: Path) -> None:
    cwd = str(tmp_path)
    rows = [
        {"event": "pre", "tool_name": "Bash", "command": "curl \x1b[2J" + "a" * 300, "cwd": cwd}
    ]
    section = replay.replay_log(MINI, CURL_DENY_TEXT, limit=10, log_path=_log(tmp_path, rows))
    (change,) = section.tighter
    assert "\x1b" not in change.label
    assert len(change.label) <= 6 + replay._COMMAND_SHOWN


@pytest.mark.parametrize("limit", [0, -1])
def test_log_limit_zero_skips(tmp_path: Path, limit: int) -> None:
    section = replay.replay_log(MINI, MINI, limit=limit, log_path=str(tmp_path / "none"))
    assert not section.available
