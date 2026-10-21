"""``boundkeep trust`` as a real process, in a throwaway profile (never the real ~/.boundkeep)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.e2e.test_cli_flow import Machine

pytestmark = pytest.mark.e2e


@pytest.fixture
def machine(tmp_path: Path) -> Machine:
    return Machine(tmp_path)


def _run(machine: Machine, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "boundkeep", *args],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        env=machine.env,
        cwd=str(machine.project),
        timeout=120,
        check=False,
        encoding="utf-8",
        errors="replace",
    )


def test_trust_add_refuses_without_a_terminal_and_list_and_remove_work(machine: Machine) -> None:
    assert machine.init("--dry-run").returncode == 0  # nothing is written by a dry run
    assert machine.init().returncode == 0
    before = (machine.home / "policy.yaml").read_bytes()
    refused = _run(machine, "trust", "add")
    assert refused.returncode == 1
    assert "interactive terminal" in refused.stderr
    assert (machine.home / "policy.yaml").read_bytes() == before
    listed = _run(machine, "trust", "list")
    assert listed.returncode == 0
    assert "no trusted projects" in listed.stdout
    removed = _run(machine, "trust", "remove")
    assert removed.returncode == 0
    assert "not in the trusted list" in removed.stdout


def test_trust_is_in_the_help(machine: Machine) -> None:
    result = _run(machine, "--help")
    assert result.returncode == 0
    assert "trust" in result.stdout
    sub = _run(machine, "trust", "--help")
    assert sub.returncode == 0
    for action in ("add", "remove", "list"):
        assert action in sub.stdout
