"""M4: the policy-compilation benchmark's cases file, and golden runs of a few of its cases.

The whole benchmark (50 cases, about 8 s each) is ``eval/run_policy_bench.py``; here the cases file
is validated and a handful of cases, one per outcome, go through the same code with the fake
backend (input, the backend's answer, the expected conclusion).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from boundkeep.policy import default_policy_text, parse_policy_text

ROOT = Path(__file__).resolve().parents[2]
_OUTCOMES = ("accepted", "not-usable", "invalid-output", "not-sent")


def _bench() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "run_policy_bench", ROOT / "eval" / "run_policy_bench.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["run_policy_bench"] = module
    spec.loader.exec_module(module)
    return module


def _cases() -> list[dict[str, Any]]:
    data = yaml.safe_load((ROOT / "eval" / "policy-compile" / "cases.yaml").read_text("utf-8"))
    assert isinstance(data, list)
    return data


def test_the_cases_file_has_50_well_formed_cases() -> None:
    cases = _cases()
    assert len(cases) == 50
    assert len({c["id"] for c in cases}) == 50
    for case in cases:
        expect = str(case["expect"])
        assert expect in _OUTCOMES or expect.startswith("refused:"), case["id"]
        assert ("answer" in case) != ("answer_text" in case), case["id"]
        assert isinstance(case["request"], str)
        assert case["request"].strip()
    categories = {c["category"] for c in cases}
    assert {"tighten-windows", "vague", "contradictory", "broad", "injection"} <= categories
    assert sum(1 for c in cases if c.get("dangerous")) >= 8


@pytest.mark.parametrize("case_id", ["pc-02", "pc-23", "pc-35", "pc-40", "pc-41", "pc-45", "pc-47"])
def test_golden_cases_end_as_expected(case_id: str) -> None:
    bench = _bench()
    case = next(c for c in _cases() if c["id"] == case_id)
    text = default_policy_text()
    ids = [r.id for r in parse_policy_text(text, home=bench.HOME).rules]
    result = bench.run_case(case, text, ids, bench._fake_for(case), False, 30.0)
    assert result.matches(), (result.outcome, result.codes, result.detail)


def test_the_report_is_written_with_the_metrics(tmp_path: Path) -> None:
    bench = _bench()
    case = next(c for c in _cases() if c["id"] == "pc-45")
    result = bench.Result(case, outcome="not-sent")
    out = tmp_path / "r.md"
    bench.write_report([result], out, backend_label="fake", fake=True, ps_ready=False, policy="p")
    text = out.read_text("utf-8")
    assert "**The answers are hand-written**" in text
    assert "| outcome as expected | 1/1 (100.0%) |" in text
    assert "## Review sheet" in text
