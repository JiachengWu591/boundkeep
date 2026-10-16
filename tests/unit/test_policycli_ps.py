"""``boundkeep test`` on a host without a PowerShell parser: PowerShell cases are skipped."""

from __future__ import annotations

import argparse
from typing import Any

import pytest

from boundkeep import policycli
from boundkeep.normalize import psparse


def _args(platform: str = "windows") -> argparse.Namespace:
    return argparse.Namespace(platform=platform, policy=None)


def test_ps_unavailable_only_for_the_unavailable_state() -> None:
    assert policycli._ps_unavailable({"state": "unavailable"})
    for state in ("ready", "warming", "disabled"):
        assert not policycli._ps_unavailable({"state": state})
    assert not policycli._ps_unavailable({})


def test_powershell_cases_are_skipped_not_failed_without_a_parser(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(psparse, "warm_up", lambda **_: False)
    monkeypatch.setattr(psparse, "status", lambda: {"state": "unavailable", "reason": "none"})
    real = policycli._run_one
    ran_tools: list[str] = []

    def spy(*a: Any, **k: Any) -> Any:
        ran_tools.append(a[2])
        return real(*a, **k)

    monkeypatch.setattr(policycli, "_run_one", spy)
    code = policycli.cmd_test(_args())
    out = capsys.readouterr().out
    assert code == policycli.EXIT_OK, out
    assert "[SKIP]" in out
    assert "(no PowerShell parser on this host)" in out
    assert "PowerShell" not in ran_tools
    assert "0 failed" in out
    assert " skipped" in out
    assert "[FAIL]" not in out


def test_powershell_cases_still_run_when_the_parser_is_merely_not_ready(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(psparse, "warm_up", lambda **_: False)
    monkeypatch.setattr(psparse, "status", lambda: {"state": "warming"})
    real = policycli._run_one
    ran_tools: list[str] = []

    def spy(*a: Any, **k: Any) -> Any:
        ran_tools.append(a[2])
        return real(*a, **k)

    monkeypatch.setattr(policycli, "_run_one", spy)
    policycli.cmd_test(_args())
    out = capsys.readouterr().out
    assert "PowerShell" in ran_tools
    assert "[SKIP]" not in out
