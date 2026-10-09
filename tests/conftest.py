"""Shared test configuration.

Markers (see pyproject.toml): ``windows`` / ``posix`` are skipped on the other platform, ``live``
is skipped unless ``--live`` is given, ``e2e`` marks tests that spawn real processes.

Tests never touch the real ``~/.boundkeep`` or ``~/.claude``: use the ``boundkeep_home`` fixture
(or ``tmp_path``) for every file the code under test writes.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "hook_events" / "windows"

# Environment variables that must not leak from the developer's shell into subprocess tests.
# PYTHON*: a global PYTHONIOENCODING once hid a real bug (M0a, docs/hook-behavior.md E18).
_SCRUBBED_PREFIXES = ("PYTHON", "CLAUDE", "BOUNDKEEP", "ANTHROPIC")


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--live",
        action="store_true",
        default=False,
        help="run tests marked 'live' (real external services or a real Claude Code)",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    skip_live = pytest.mark.skip(reason="live test: pass --live to run")
    skip_windows = pytest.mark.skip(reason="needs Windows")
    skip_posix = pytest.mark.skip(reason="needs POSIX")
    for item in items:
        if "live" in item.keywords and not config.getoption("--live"):
            item.add_marker(skip_live)
        if "windows" in item.keywords and sys.platform != "win32":
            item.add_marker(skip_windows)
        if "posix" in item.keywords and sys.platform == "win32":
            item.add_marker(skip_posix)


def scrubbed_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """A copy of the environment without PYTHON*, CLAUDE*, BOUNDKEEP* and ANTHROPIC* variables.

    Keeps what a process needs to start on Windows (SystemRoot, PATH, TEMP, USERPROFILE, ...).
    """
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(_SCRUBBED_PREFIXES)}
    if extra:
        env.update(extra)
    return env


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def fixtures_dir() -> Path:
    """Sanitized real hook events captured in M0a (Windows, Claude Code 2.1.291)."""
    return FIXTURES_DIR


@pytest.fixture
def load_fixture() -> Callable[[str], dict[str, Any]]:
    """``load_fixture("PreToolUse__PowerShell")`` -> the parsed event (fresh copy each call)."""

    def _load(name: str) -> dict[str, Any]:
        data = json.loads((FIXTURES_DIR / f"{name}.json").read_text(encoding="utf-8"))
        assert isinstance(data, dict)
        return data

    return _load


@pytest.fixture
def fixture_bytes() -> Callable[[str], bytes]:
    """The raw UTF-8 bytes of a fixture, as Claude Code would write them to a hook's stdin."""

    def _bytes(name: str) -> bytes:
        return (FIXTURES_DIR / f"{name}.json").read_bytes()

    return _bytes


@pytest.fixture
def boundkeep_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty, not yet created boundkeep home; BOUNDKEEP_HOME points at it for this test."""
    home = tmp_path / "bk-home"
    monkeypatch.setenv("BOUNDKEEP_HOME", str(home))
    monkeypatch.delenv("BOUNDKEEP_LLM_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    return home


@pytest.fixture
def hook_env(boundkeep_home: Path) -> dict[str, str]:
    """Environment for running the hook client or the CLI as a subprocess."""
    return scrubbed_env({"BOUNDKEEP_HOME": str(boundkeep_home)})
