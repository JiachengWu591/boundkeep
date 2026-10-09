"""Windows-only: a real open handle on the log makes rotation fail, and that must not cost events.

On Windows ``os.replace`` raises ``PermissionError`` when another handle (a reader, an antivirus
scan, ``Get-Content -Wait``) is open on the file. The unit tests simulate that; here the handle is
real.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from boundkeep.logstore import AuditLog

pytestmark = pytest.mark.windows


class FakeClock:
    def __init__(self) -> None:
        self.now = 5000.0

    def __call__(self) -> float:
        return self.now


def _ids(path: str) -> list[int]:
    with open(path, "rb") as handle:
        return [json.loads(line)["i"] for line in handle.read().splitlines()]


def _fill(log: AuditLog, start: int, count: int) -> None:
    for i in range(start, start + count):
        assert log.append({"i": i, "pad": "p" * 30}) is True


def test_held_handle_blocks_rotation_but_not_appends(tmp_path: Path) -> None:
    path = str(tmp_path / "audit.jsonl")
    clock = FakeClock()
    log = AuditLog(path, max_bytes=300, backups=2, clock=clock)
    _fill(log, 0, 3)  # ~150 bytes: below the limit
    assert log.last_error is None

    held = open(path, "ab")  # noqa: SIM115 - the handle must stay open across several appends
    try:
        # Cross the limit while the handle is held: the rotation attempt fails with a real
        # PermissionError, but every append still succeeds.
        _fill(log, 3, 12)
        assert os.path.getsize(path) > 300
        assert not os.path.exists(path + ".1")
        assert log.last_error is not None
        assert "rotate" in log.last_error
        assert _ids(path) == list(range(15))  # nothing lost
        assert [r["i"] for r in log.tail(100)] == list(range(15))

        # Still inside the retry interval: more appends, still no rotation, still nothing lost.
        clock.now += 4.0
        _fill(log, 15, 5)
        assert not os.path.exists(path + ".1")
        assert _ids(path) == list(range(20))
    finally:
        held.close()

    # The handle is gone but the retry interval has not passed yet: no rotation.
    _fill(log, 20, 1)
    assert not os.path.exists(path + ".1")

    # After the interval the next append rotates, and the record that triggers it opens the
    # fresh file.
    clock.now += 1.5
    _fill(log, 21, 1)
    assert os.path.exists(path + ".1")
    assert _ids(path + ".1") == list(range(21))
    assert _ids(path) == [21]
    assert [r["i"] for r in log.tail(100)] == list(range(22))


def test_held_handle_with_backups_in_place_loses_no_rotated_file(tmp_path: Path) -> None:
    path = str(tmp_path / "audit.jsonl")
    clock = FakeClock()
    log = AuditLog(path, max_bytes=200, backups=2, clock=clock)
    _fill(log, 0, 20)
    assert os.path.exists(path + ".1")
    before: dict[str, list[int]] = {
        name: _ids(name) for name in (path, path + ".1", path + ".2") if os.path.exists(name)
    }
    held: Any = open(path + ".1", "rb")  # noqa: SIM115 - a reader on an already rotated file
    try:
        # Make the current file full, then append: the shift cannot move .1 and must not lose
        # data or reorder files.
        next_id = 20
        while os.path.getsize(path) < 200:
            _fill(log, next_id, 1)
            next_id += 1
        clock.now += 10
        _fill(log, next_id, 1)
        assert log.last_error is not None
        seen: list[int] = []
        for name in (path + ".2", path + ".1", path):
            if os.path.exists(name):
                ids = _ids(name)
                assert ids == sorted(ids)
                seen.extend(ids)
        assert seen == sorted(seen)
        assert len(seen) == len(set(seen))
        assert seen[-1] == next_id
        assert before  # the scenario really had rotated files
    finally:
        held.close()

    clock.now += 10
    _fill(log, next_id + 1, 1)
    assert os.path.exists(path + ".1")
    ids = _ids(path)
    assert ids == [next_id + 1]


def test_appends_succeed_while_another_process_style_reader_has_the_file_open(
    tmp_path: Path,
) -> None:
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path, max_bytes=10_000_000)
    _fill(log, 0, 1)
    with open(path, "rb") as reader:  # like Get-Content -Wait or a scanner
        _fill(log, 1, 5)
        assert reader.read().count(b"\n") == 6
    assert log.last_error is None


def test_purge_reports_what_it_could_not_remove(tmp_path: Path) -> None:
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path, max_bytes=200, backups=2)
    _fill(log, 0, 20)
    held = open(path + ".1", "rb")  # noqa: SIM115 - a reader blocks deletion on Windows
    try:
        removed = log.purge()
        assert log.last_error is not None
        assert os.path.exists(path + ".1")
        assert removed >= 1
    finally:
        held.close()
    assert log.purge() >= 1
    assert not os.path.exists(path + ".1")
