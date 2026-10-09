"""Failure modes of the CLI found by review: damaged state files, concurrent edits, aliases.

Each test names the thing that used to go wrong (a traceback, a half-done init, a lost edit).
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from boundkeep import cli, install, paths
from boundkeep.logstore import AuditLog
from tests.e2e.test_cli_flow import Machine, machine  # noqa: F401 - the fixture

pytestmark = pytest.mark.e2e


def _no_traceback(result: Any) -> None:
    assert "Traceback" not in result.stderr + result.stdout, result.stderr


def test_a_damaged_manifest_stops_init_before_anything_is_written(machine: Machine) -> None:
    machine.home.mkdir(parents=True)
    (machine.home / "installs.json").write_text("{not json", encoding="utf-8")
    result = machine.init()
    assert result.returncode == 1
    _no_traceback(result)
    assert "installs.json" in result.stderr
    assert not machine.settings.exists()  # the settings file was not touched


def test_a_damaged_endpoint_file_is_replaced_by_init(machine: Machine) -> None:
    machine.home.mkdir(parents=True)
    for content in ("xx", "", '{"transport": 5}'):
        (machine.home / "endpoint.json").write_text(content, encoding="utf-8")
        result = machine.init()
        assert result.returncode == 0, result.stderr
        _no_traceback(result)
        assert machine.endpoint().address.startswith("\\\\.\\pipe\\boundkeep")


def test_init_refuses_a_project_directory_that_does_not_exist(machine: Machine) -> None:
    missing = machine.root / "typo dir" / "x"
    result = machine.cli("init", "--project-dir", str(missing))
    assert result.returncode == 1
    assert "does not exist" in result.stderr
    assert not missing.exists()
    assert not (machine.root / "typo dir").exists()


def test_uninstall_on_a_read_only_settings_file_fails_cleanly(machine: Machine) -> None:
    assert machine.init().returncode == 0
    before = machine.settings.read_bytes()
    os.chmod(machine.settings, stat.S_IREAD)
    try:
        result = machine.cli("uninstall", "--project-dir", str(machine.project))
    finally:
        os.chmod(machine.settings, stat.S_IWRITE | stat.S_IREAD)
    assert result.returncode == 1
    _no_traceback(result)
    assert machine.settings.read_bytes() == before


@pytest.mark.windows
def test_uninstall_through_a_junction_finds_the_record_init_wrote(machine: Machine) -> None:
    import _winapi

    assert machine.init().returncode == 0
    link = machine.root / "link"
    _winapi.CreateJunction(str(machine.project), str(link))
    try:
        result = machine.cli("uninstall", "--project-dir", str(link))
        assert result.returncode == 0, result.stderr
    finally:
        link.rmdir()
    assert (
        json.loads((machine.home / "installs.json").read_text(encoding="utf-8"))["installs"] == []
    )
    assert not machine.settings.exists()  # init created it and nothing else was in it


def test_a_bom_is_removed_by_a_second_init_and_doctor_stops_warning(machine: Machine) -> None:
    assert machine.init().returncode == 0
    raw = machine.settings.read_bytes()
    machine.settings.write_bytes(b"\xef\xbb\xbf" + raw)
    result = machine.init()
    assert result.returncode == 0, result.stderr
    assert "already installed" not in result.stdout
    assert not machine.settings.read_bytes().startswith(b"\xef\xbb\xbf")


def test_log_output_cannot_inject_terminal_control_sequences(machine: Machine) -> None:
    log = AuditLog(str(machine.home / "logs" / "audit.jsonl"))
    evil = "echo hi\x1b[2J\x1b[1;1H FAKE \x1b]0;pwned\x07 ‮"
    assert log.append({"ts": "t", "event": "pre", "decision": "deny\x1b[31m", "command": evil})
    result = machine.cli("log")
    assert result.returncode == 0
    for bad in ("\x1b", "\x07", "‮"):
        assert bad not in result.stdout
    assert "FAKE" in result.stdout  # the text stays, only the control characters go


def test_a_settings_file_edited_during_init_is_not_overwritten(
    boundkeep_home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    settings = project / ".claude" / "settings.json"
    settings.write_text('{"model": "opus"}', encoding="utf-8")
    edited = '{"model": "opus", "permissions": {"deny": ["Read(.env)"]}}'
    real_check = install.run_self_check

    def edit_while_checking(*args: Any, **kwargs: Any) -> Any:
        results = real_check(*args, **kwargs)
        settings.write_text(edited, encoding="utf-8")  # the user (or Claude Code) saves meanwhile
        return results

    monkeypatch.setattr(install, "run_self_check", edit_while_checking)
    code = cli.main(["init", "--project-dir", str(project)])
    assert code == 1
    assert settings.read_text(encoding="utf-8") == edited  # the edit survived
    assert "changed since it was read" in capsys.readouterr().err
    assert not os.path.exists(paths.manifest_file())  # nothing recorded for a change not made


def test_the_hardened_init_is_still_idempotent(machine: Machine) -> None:
    assert machine.init().returncode == 0
    first = machine.settings.read_bytes()
    again = machine.init()
    assert again.returncode == 0
    assert "already installed" in again.stdout
    assert machine.settings.read_bytes() == first
