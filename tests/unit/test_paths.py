from __future__ import annotations

import os
from pathlib import Path

import pytest

from boundkeep import paths


def test_home_dir_defaults_to_dot_boundkeep_in_user_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(paths.HOME_ENV, raising=False)
    assert paths.home_dir() == os.path.join(os.path.expanduser("~"), ".boundkeep")


def test_home_dir_respects_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(paths.HOME_ENV, str(tmp_path / "x"))
    assert paths.home_dir() == str(tmp_path / "x")


def test_files_are_under_the_given_home(tmp_path: Path) -> None:
    home = str(tmp_path)
    assert paths.endpoint_file(home) == os.path.join(home, "endpoint.json")
    assert paths.policy_file(home) == os.path.join(home, "policy.yaml")
    assert paths.manifest_file(home) == os.path.join(home, "installs.json")
    assert paths.audit_log_file(home) == os.path.join(home, "logs", "audit.jsonl")
    assert paths.lock_file(home) == os.path.join(home, "serve.lock")
    assert paths.pid_file(home) == os.path.join(home, "serve.pid")
    assert paths.backups_dir(home) == os.path.join(home, "backups")


def test_conftest_fixture_points_home_at_a_temp_dir(boundkeep_home: Path) -> None:
    assert paths.home_dir() == str(boundkeep_home)
    assert not boundkeep_home.exists()
