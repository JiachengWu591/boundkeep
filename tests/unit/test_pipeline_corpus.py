"""The end-to-end corpus (tests/corpus/pipeline.yaml): tool call -> verdict of the default policy.

Adversarial entries carry a second guarantee on top of their expected verdict: whatever the
expectation says, the verdict must never be ``allow`` for a shell command (the default policy has
no shell allow rules) and never milder than the expectation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from boundkeep import policycli
from boundkeep.policy import default_policy_text, parse_policy_text

CORPUS_DIR = Path(__file__).resolve().parents[1] / "corpus"
CORPUS_FILES = sorted(CORPUS_DIR.glob("pipeline*.yaml"))  # pipeline.yaml plus per-topic additions
_STRICTNESS = {"allow": 0, "gray": 1, "ask": 2, "deny": 3}


def _load() -> list[Any]:
    data: list[Any] = []
    for path in CORPUS_FILES:
        data += yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return data


def _entries() -> list[Any]:
    data = _load()
    params = []
    for entry in data:
        for platform in ("windows", "posix"):
            only = entry.get("platform")
            if only is not None and only != platform:
                continue
            params.append(pytest.param(entry, platform, id=f"{entry['id']}-{platform}"))
    return params


@pytest.fixture(scope="module", params=["windows", "posix"])
def policies(request: pytest.FixtureRequest) -> Any:
    return request.param


def _policy(platform: str) -> Any:
    return parse_policy_text(default_policy_text(), home=policycli._FAKE[platform]["home"])


def test_the_corpus_is_big_and_has_enough_adversarial_entries() -> None:
    data = _load()
    assert len(data) >= 150
    assert sum(1 for e in data if e.get("adv")) >= 60
    assert len({e["id"] for e in data}) == len(data)


@pytest.mark.parametrize(("entry", "platform"), _entries())
def test_corpus_entry(entry: dict[str, Any], platform: str) -> None:
    policy = _policy(platform)
    result = policycli._run_one(
        policy,
        platform,
        entry["tool"],
        entry["input"],
        None,
        None,  # type: ignore[arg-type]
    )
    got = result.verdict.decision
    assert got == entry["expect"], (
        f"{entry['id']} on {platform}: expected {entry['expect']}, got {got}; "
        f"reasons: {result.verdict.reasons}"
    )
    if entry.get("adv"):
        assert _STRICTNESS[got] >= _STRICTNESS[entry["expect"]]
        if entry["tool"] in ("Bash", "PowerShell"):
            assert got != "allow"
