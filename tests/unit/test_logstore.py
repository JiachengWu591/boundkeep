"""Tests for boundkeep.logstore.AuditLog (portable: rotation failures are simulated here, the
real Windows file-handle case lives in tests/platform/test_logstore_windows.py)."""

from __future__ import annotations

import json
import math
import os
import stat
import threading
from pathlib import Path
from typing import Any

import pytest

from boundkeep import logstore
from boundkeep.logstore import AuditLog
from boundkeep.redact import REDACTED

SECRET = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


class FakeClock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def log_path(tmp_path: Path) -> str:
    # The parent directory does not exist yet on purpose: append must create it.
    return str(tmp_path / "logs" / "audit.jsonl")


def read_lines(path: str) -> list[bytes]:
    with open(path, "rb") as handle:
        return handle.read().splitlines()


def read_ids(path: str) -> list[int]:
    ids: list[int] = []
    for line in read_lines(path):
        record = json.loads(line)
        ids.append(record["i"])
    return ids


# --------------------------------------------------------------------------------------------
# Format
# --------------------------------------------------------------------------------------------


def test_append_writes_compact_utf8_jsonl_and_creates_the_directory(log_path: str) -> None:
    log = AuditLog(log_path)
    assert log.append({"event": "x", "text": "中文 café", "n": 1, "nested": {"a": [1, 2]}})
    assert log.append({"event": "y"})
    with open(log_path, "rb") as handle:
        raw = handle.read()
    assert raw.endswith(b"\n")
    assert b"\r" not in raw
    lines = raw.split(b"\n")[:-1]
    assert len(lines) == 2
    # ensure_ascii=False and compact separators.
    assert lines[0].decode("utf-8") == (
        '{"event":"x","text":"中文 café","n":1,"nested":{"a":[1,2]}}'
    )
    assert json.loads(lines[1]) == {"event": "y"}
    assert log.last_error is None


def test_append_does_not_mutate_the_record(log_path: str) -> None:
    record: dict[str, object] = {"cmd": f"echo {SECRET}", "list": [1, {"k": "v"}]}
    snapshot = json.dumps(record)
    assert AuditLog(log_path).append(record)
    assert json.dumps(record) == snapshot


def test_constructor_validates_arguments(log_path: str) -> None:
    with pytest.raises(ValueError, match="max_bytes"):
        AuditLog(log_path, max_bytes=0)
    with pytest.raises(ValueError, match="backups"):
        AuditLog(log_path, backups=-1)
    with pytest.raises(ValueError, match="max_string_chars"):
        AuditLog(log_path, max_string_chars=0)


@pytest.mark.posix
def test_log_file_is_private_on_posix(log_path: str) -> None:
    AuditLog(log_path).append({"a": 1})
    assert stat.S_IMODE(os.stat(log_path).st_mode) == 0o600


# --------------------------------------------------------------------------------------------
# Redaction and truncation
# --------------------------------------------------------------------------------------------


def test_redaction_is_applied_before_the_write(log_path: str) -> None:
    log = AuditLog(log_path)
    assert log.append(
        {
            "command": f"curl -H 'x-key: {SECRET}' && export MY_API_KEY=hunter2",
            "env": {"api_key": "hunter2", "other": "fine"},
            f"{SECRET}": 1,
        }
    )
    with open(log_path, encoding="utf-8") as handle:
        text = handle.read()
    assert SECRET not in text
    assert "hunter2" not in text
    assert REDACTED in text
    assert "fine" in text


def test_secret_straddling_the_length_limit_leaves_no_fragment(log_path: str) -> None:
    # Truncating first would cut the key in half and leave a short fragment that no pattern
    # matches; redacting first turns the whole key into [REDACTED] before the cut.
    command = "x" * 4090 + " " + "sk-" + "a" * 40
    log = AuditLog(log_path, max_string_chars=4096)
    assert log.append({"command": command})
    (record,) = log.tail(1)
    value = record["command"]
    assert isinstance(value, str)
    assert "sk-" not in value
    assert "aaaa" not in value


def test_custom_redactor_is_used_and_called_with_a_copy(log_path: str) -> None:
    seen: list[object] = []

    def redactor(value: object) -> object:
        seen.append(value)
        assert isinstance(value, dict)
        return {"replaced": True}

    original = {"a": 1}
    assert AuditLog(log_path, redactor=redactor).append(original)
    assert seen == [{"a": 1}]
    assert seen[0] is not original
    assert read_lines(log_path) == [b'{"replaced":true}']


def test_failing_redactor_writes_nothing_and_reports(log_path: str) -> None:
    def broken(_: object) -> object:
        raise RuntimeError("redactor exploded")

    log = AuditLog(log_path, redactor=broken)
    assert log.append({"secret": SECRET}) is False
    assert log.last_error is not None
    assert "redactor exploded" in log.last_error
    assert not os.path.exists(log_path)


def test_redactor_returning_a_non_dict_is_wrapped(log_path: str) -> None:
    log = AuditLog(log_path, redactor=lambda _: "[REDACTED]")
    assert log.append({"a": 1})
    assert log.tail() == [{"record": "[REDACTED]"}]


def test_long_strings_are_truncated_with_a_marker(log_path: str) -> None:
    log = AuditLog(log_path, max_string_chars=10)
    assert log.append(
        {
            "exact": "0123456789",
            "long": "0123456789abcdef",
            "nested": {"list": ["x" * 25]},
            "k" * 12: "v",
        }
    )
    (record,) = log.tail()
    assert record["exact"] == "0123456789"
    assert record["long"] == "0123456789...[truncated 6 chars]"
    assert record["nested"] == {"list": ["x" * 10 + "...[truncated 15 chars]"]}
    assert ("k" * 10 + "...[truncated 2 chars]") in record


def test_a_huge_command_cannot_flood_the_log(log_path: str) -> None:
    log = AuditLog(log_path)
    assert log.append({"command": "echo " + "A" * 5_000_000})
    assert os.path.getsize(log_path) < 6000
    (record,) = log.tail()
    command = record["command"]
    assert isinstance(command, str)
    assert command.endswith(f"...[truncated {len('echo ') + 5_000_000 - 4096} chars]")


# --------------------------------------------------------------------------------------------
# Non-JSON values
# --------------------------------------------------------------------------------------------


class _Opaque:
    def __repr__(self) -> str:
        return "<Opaque api_key=sk-0123456789abcdef0123>"


def test_non_json_values_become_redacted_repr(log_path: str) -> None:
    log = AuditLog(log_path)
    assert log.append(
        {
            "obj": _Opaque(),
            "set": {1},
            "bytes": b"abc",
            "path": Path("a") / "b",
            "complex": 1 + 2j,
            "tuple_key": {(1, 2): "v"},
            "nan": math.nan,
            "inf": math.inf,
        }
    )
    (record,) = log.tail()
    assert record["obj"] == "<Opaque api_key=[REDACTED]>"  # only the secret goes, not the ">"
    assert record["set"] == "{1}"
    assert record["bytes"] == "b'abc'"
    assert record["complex"] == "(1+2j)"
    assert record["tuple_key"] == {"(1, 2)": "v"}
    assert record["nan"] == "nan"
    assert record["inf"] == "inf"
    assert "sk-0123456789abcdef0123" not in open(log_path, encoding="utf-8").read()  # noqa: SIM115


def test_non_json_values_pass_through_the_redactor_even_with_a_custom_one(log_path: str) -> None:
    calls: list[object] = []

    def identity(value: object) -> object:
        calls.append(value)
        if isinstance(value, str):
            return value.replace("SECRETVALUE", "[x]")
        return value

    log = AuditLog(log_path, redactor=identity)

    class Leaky:
        def __repr__(self) -> str:
            return "Leaky(SECRETVALUE)"

    assert log.append({"o": Leaky()})
    assert log.tail() == [{"o": "Leaky([x])"}]


def test_append_never_raises_type_error_for_odd_values(log_path: str) -> None:
    class Bad:
        def __repr__(self) -> str:
            raise RuntimeError("no repr")

    log = AuditLog(log_path)
    assert log.append({"bad": Bad(), "gen": (x for x in [1]), "fn": print, "type": int})
    (record,) = log.tail()
    assert record["bad"] == "<unrepresentable Bad>"


def test_lone_surrogates_and_control_characters_are_written(log_path: str) -> None:
    log = AuditLog(log_path)
    assert log.append({"s": "a\ud800b\x00c\x1f\u2028d"})
    with open(log_path, "rb") as handle:
        raw = handle.read()
    raw.decode("utf-8")  # must be valid UTF-8
    assert raw.count(b"\n") == 1
    (record,) = log.tail()
    assert isinstance(record["s"], str)
    assert "a" in record["s"]
    assert "\x00c\x1f" in record["s"]


def test_huge_int_and_deep_nesting_and_cycles_do_not_break_append(log_path: str) -> None:
    deep: object = "bottom"
    for _ in range(200):
        deep = [deep]
    cyclic: list[object] = []
    cyclic.append(cyclic)
    log = AuditLog(log_path, redactor=lambda value: value)  # a redactor that bounds nothing
    assert log.append({"big": 10**5000, "deep": deep, "cyclic": cyclic})
    (record,) = log.tail()
    assert isinstance(record["big"], str)
    assert record["cyclic"] == ["[TRUNCATED]"]
    node: object = record["deep"]
    while isinstance(node, list):
        node = node[0]
    assert node == "[TRUNCATED]"


def test_non_mapping_record_does_not_raise(log_path: str) -> None:
    log = AuditLog(log_path)
    assert log.append(None) is False  # type: ignore[arg-type]
    assert log.last_error is not None


# --------------------------------------------------------------------------------------------
# I/O problems
# --------------------------------------------------------------------------------------------


def test_path_is_a_directory(tmp_path: Path) -> None:
    directory = tmp_path / "audit.jsonl"
    directory.mkdir()
    log = AuditLog(str(directory), max_bytes=1)
    assert log.append({"a": 1}) is False
    assert log.last_error is not None
    assert directory.is_dir()  # never renamed away by rotation
    assert not (tmp_path / "audit.jsonl.1").exists()


def test_parent_is_a_file(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    log = AuditLog(str(blocker / "audit.jsonl"))
    assert log.append({"a": 1}) is False
    assert log.last_error is not None
    assert log.tail() == []


def test_last_error_is_none_until_a_failure_and_stays_after_success(
    tmp_path: Path, log_path: str
) -> None:
    log = AuditLog(log_path)
    assert log.last_error is None
    assert log.append({"a": 1})
    assert log.last_error is None
    broken = AuditLog(str(tmp_path))  # a directory
    assert broken.append({"a": 1}) is False
    first = broken.last_error
    assert first
    assert broken.append({"a": 2}) is False
    assert broken.last_error == first


def test_append_returns_false_on_os_error_without_raising(
    log_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: object, **__: object) -> int:
        raise OSError(28, "No space left on device")

    log = AuditLog(log_path)
    assert log.append({"a": 1})
    monkeypatch.setattr(os, "write", boom)
    assert log.append({"a": 2}) is False
    assert log.last_error is not None
    assert "No space left" in log.last_error
    monkeypatch.undo()
    assert log.append({"a": 3})
    assert [r["a"] for r in log.tail()] == [1, 3]


def test_short_writes_are_completed(log_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
    real_write = os.write

    def short_write(fd: int, data: Any) -> int:
        return real_write(fd, bytes(data[:7]))

    log = AuditLog(log_path)
    monkeypatch.setattr(os, "write", short_write)
    assert log.append({"message": "a fairly long line to be written in pieces"})
    monkeypatch.undo()
    assert log.tail() == [{"message": "a fairly long line to be written in pieces"}]


# --------------------------------------------------------------------------------------------
# Rotation
# --------------------------------------------------------------------------------------------


def _fill(log: AuditLog, count: int, start: int = 0) -> None:
    for i in range(start, start + count):
        assert log.append({"i": i, "pad": "p" * 30})


def test_rotation_order_and_backups_limit(log_path: str) -> None:
    log = AuditLog(log_path, max_bytes=200, backups=2)
    _fill(log, 40)
    assert os.path.exists(log_path)
    assert os.path.exists(log_path + ".1")
    assert os.path.exists(log_path + ".2")
    assert not os.path.exists(log_path + ".3")
    oldest, middle, newest = (read_ids(p) for p in (log_path + ".2", log_path + ".1", log_path))
    combined = oldest + middle + newest
    # Chronological, gap free, ending with the last record; the earliest ones were dropped.
    assert combined == list(range(combined[0], 40))
    assert combined[0] > 0
    # Rotated files are full (>= max_bytes) but not by more than one line.
    for rotated in (log_path + ".1", log_path + ".2"):
        assert 200 <= os.path.getsize(rotated) < 200 + 80
    assert os.path.getsize(log_path) < 200 + 80
    assert log.last_error is None


def test_rotation_happens_only_when_the_file_is_full(log_path: str) -> None:
    log = AuditLog(log_path, max_bytes=10_000, backups=3)
    _fill(log, 20)
    assert not os.path.exists(log_path + ".1")
    assert read_ids(log_path) == list(range(20))


def test_rotation_with_zero_backups_starts_a_fresh_file(log_path: str) -> None:
    log = AuditLog(log_path, max_bytes=200, backups=0)
    _fill(log, 30)
    assert not os.path.exists(log_path + ".1")
    ids = read_ids(log_path)
    assert ids[-1] == 29
    assert len(ids) < 30


def test_failed_rotation_keeps_appending_and_retries_later_not_every_time(
    log_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock()
    log = AuditLog(log_path, max_bytes=200, backups=2, clock=clock)
    _fill(log, 5)  # 5 * ~50 bytes: over the limit, nothing rotated yet
    assert os.path.getsize(log_path) >= 200
    replace_calls: list[tuple[str, str]] = []
    real_replace = os.replace

    def locked_replace(src: Any, dst: Any) -> None:
        replace_calls.append((str(src), str(dst)))
        raise PermissionError(13, "The process cannot access the file (simulated)")

    monkeypatch.setattr(os, "replace", locked_replace)
    _fill(log, 3, start=5)  # first append attempts a rotation and fails; two more do not retry
    assert len(replace_calls) == 1
    assert log.last_error is not None
    assert "rotate" in log.last_error
    assert not os.path.exists(log_path + ".1")
    clock.now += 4.9
    _fill(log, 3, start=8)
    assert len(replace_calls) == 1  # still inside the retry interval
    clock.now += 0.2  # 5.1 seconds after the failure
    _fill(log, 1, start=11)
    assert len(replace_calls) == 2  # one retry, then the interval starts over
    _fill(log, 3, start=12)
    assert len(replace_calls) == 2

    # The lock goes away: the next retry after the interval rotates.
    monkeypatch.setattr(os, "replace", real_replace)
    clock.now += 5.1
    _fill(log, 1, start=15)
    assert os.path.exists(log_path + ".1")
    assert read_ids(log_path) == [15]
    # Nothing was lost across the failed attempts.
    assert read_ids(log_path + ".1") == list(range(15))


def test_oldest_first_shift_never_overwrites_newer_with_older(
    log_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = AuditLog(log_path, max_bytes=200, backups=3, clock=FakeClock())
    _fill(log, 12)  # fills base, .1, .2 (and maybe .3)
    next_id = 12
    while os.path.getsize(log_path) < 200:  # make sure the next append triggers a rotation
        _fill(log, 1, start=next_id)
        next_id += 1
    before = {p: read_ids(p) for p in (log_path + ".1", log_path + ".2") if os.path.exists(p)}
    real_replace = os.replace
    state = {"calls": 0}

    def fail_second(src: Any, dst: Any) -> None:
        state["calls"] += 1
        if state["calls"] == 2:
            raise PermissionError(13, "simulated")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", fail_second)
    _fill(log, 1, start=100)
    monkeypatch.undo()
    assert log.last_error is not None
    # Whatever state the shift stopped in, every file is still ordered and no id is duplicated.
    seen: list[int] = []
    for path in (log_path + ".3", log_path + ".2", log_path + ".1", log_path):
        if os.path.exists(path):
            ids = read_ids(path)
            assert ids == sorted(ids)
            seen.extend(ids)
    assert len(seen) == len(set(seen))
    assert seen == sorted(seen)
    assert before  # sanity: the scenario really had rotated files


# --------------------------------------------------------------------------------------------
# tail
# --------------------------------------------------------------------------------------------


def test_tail_returns_the_last_n_in_chronological_order(log_path: str) -> None:
    log = AuditLog(log_path, max_bytes=10_000_000)
    _fill(log, 50)
    assert [r["i"] for r in log.tail(5)] == [45, 46, 47, 48, 49]
    assert [r["i"] for r in log.tail()] == list(range(30, 50))
    assert len(log.tail(1000)) == 50
    assert log.tail(0) == []
    assert log.tail(-3) == []


def test_tail_of_a_missing_log_is_empty(log_path: str) -> None:
    assert AuditLog(log_path).tail() == []


def test_tail_continues_into_rotated_files(log_path: str) -> None:
    log = AuditLog(log_path, max_bytes=200, backups=4)
    _fill(log, 30)
    current = read_ids(log_path)
    assert len(current) < 20  # so a tail(20) must reach into the rotated files
    result = [r["i"] for r in log.tail(20)]
    assert result == list(range(10, 30))
    # Asking for more than exists returns everything that is left, in order.
    everything = [r["i"] for r in log.tail(1000)]
    assert everything == sorted(everything)
    assert everything[-1] == 29


def test_tail_skips_corrupt_and_partial_lines(log_path: str) -> None:
    log = AuditLog(log_path)
    _fill(log, 3)
    with open(log_path, "ab") as handle:
        handle.write(b"this is not json\n")
        handle.write(b'{"i": 3, "broken": \n')
        handle.write(b"\xff\xfe\x00 not utf8\n")
        handle.write(b"\n   \n")
        handle.write(b"[1, 2, 3]\n")
        handle.write(b'"just a string"\n')
        handle.write(b"42\n")
    _fill(log, 2, start=3)
    with open(log_path, "ab") as handle:
        handle.write(b'{"i": 99, "pad": "half writ')  # a record being written right now
    assert [r["i"] for r in log.tail(20)] == [0, 1, 2, 3, 4]
    assert [r["i"] for r in log.tail(2)] == [3, 4]


def test_tail_accepts_a_complete_last_line_without_newline(log_path: str) -> None:
    log = AuditLog(log_path)
    _fill(log, 2)
    with open(log_path, "ab") as handle:
        handle.write(b'{"i":2}')
    assert [r["i"] for r in log.tail()] == [0, 1, 2]


def test_tail_when_the_only_line_is_partial(log_path: str) -> None:
    os.makedirs(os.path.dirname(log_path))
    with open(log_path, "wb") as handle:
        handle.write(b'{"i": 1, "pa')
    assert AuditLog(log_path).tail() == []


def test_tail_handles_records_larger_than_a_block(log_path: str) -> None:
    log = AuditLog(log_path, max_bytes=50_000_000, max_string_chars=300_000)
    big = "b" * 200_000  # spans several 64 KiB blocks
    assert log.append({"i": 0, "big": big})
    _fill(log, 3, start=1)
    assert log.append({"i": 4, "big": big + "x"})
    records = log.tail(20)
    assert [r["i"] for r in records] == [0, 1, 2, 3, 4]
    assert records[0]["big"] == big
    assert records[4]["big"] == big + "x"
    assert [r["i"] for r in log.tail(1)] == [4]


def test_tail_stops_reading_once_it_has_enough(
    log_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = AuditLog(log_path, max_bytes=50_000_000)
    # Written directly: 30000 redacted appends would make the test slow without testing tail.
    os.makedirs(os.path.dirname(log_path))
    with open(log_path, "wb") as handle:
        for i in range(30_000):
            handle.write(
                json.dumps({"i": i, "pad": "p" * 80}, separators=(",", ":")).encode() + b"\n"
            )
    size = os.path.getsize(log_path)
    assert size > 3_000_000
    read_bytes = {"n": 0}
    real_open = open

    class Counting:
        def __init__(self, handle: Any) -> None:
            self._handle = handle

        def __enter__(self) -> Counting:
            return self

        def __exit__(self, *exc: object) -> None:
            self._handle.close()

        def read(self, size: int = -1) -> bytes:
            data: bytes = self._handle.read(size)
            read_bytes["n"] += len(data)
            return data

        def __getattr__(self, name: str) -> Any:
            return getattr(self._handle, name)

    def counting_open(*args: Any, **kwargs: Any) -> Counting:
        return Counting(real_open(*args, **kwargs))

    monkeypatch.setattr(logstore, "open", counting_open, raising=False)
    assert [r["i"] for r in log.tail(20)] == list(range(29_980, 30_000))
    assert read_bytes["n"] <= 2 * 64 * 1024


def test_tail_tolerates_a_file_removed_between_listing_and_reading(
    log_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = AuditLog(log_path, max_bytes=200, backups=3)
    _fill(log, 20)
    real_open = open

    def flaky_open(path: Any, *args: Any, **kwargs: Any) -> Any:
        if str(path).endswith(".1"):
            raise FileNotFoundError(path)  # rotated away while we were reading
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(logstore, "open", flaky_open, raising=False)
    result = [r["i"] for r in log.tail(100)]
    assert result == sorted(result)
    assert result[-1] == 19


def test_tail_survives_concurrent_appends_and_rotation(log_path: str) -> None:
    log = AuditLog(log_path, max_bytes=2000, backups=3)
    stop = threading.Event()
    errors: list[BaseException] = []

    def writer() -> None:
        i = 0
        while not stop.is_set():
            log.append({"i": i, "pad": "p" * 40})
            i += 1

    def reader() -> None:
        try:
            for _ in range(200):
                records = log.tail(15)
                assert all(isinstance(r["i"], int) for r in records)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        reader()
    finally:
        stop.set()
        thread.join()
    assert errors == []


# --------------------------------------------------------------------------------------------
# purge
# --------------------------------------------------------------------------------------------


def test_purge_removes_the_log_and_rotated_files(log_path: str) -> None:
    log = AuditLog(log_path, max_bytes=200, backups=3)
    _fill(log, 30)
    directory = os.path.dirname(log_path)
    # Files that are not ours stay.
    for name in ("other.jsonl", "audit.jsonl.bak", "audit.jsonl.old.1", "xaudit.jsonl"):
        with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
            handle.write("keep")
    # A rotated file left over from a run with a larger "backups" setting goes too.
    with open(log_path + ".9", "w", encoding="utf-8") as handle:
        handle.write("{}\n")
    assert sorted(n for n in os.listdir(directory) if n.startswith("audit.jsonl.")) == [
        "audit.jsonl.1",
        "audit.jsonl.2",
        "audit.jsonl.3",
        "audit.jsonl.9",
        "audit.jsonl.bak",
        "audit.jsonl.old.1",
    ]
    assert log.purge() == 5  # audit.jsonl, .1, .2, .3, .9
    assert sorted(os.listdir(directory)) == [
        "audit.jsonl.bak",
        "audit.jsonl.old.1",
        "other.jsonl",
        "xaudit.jsonl",
    ]
    assert log.tail() == []
    assert log.purge() == 0


def test_purge_on_a_missing_directory_and_missing_files(tmp_path: Path, log_path: str) -> None:
    assert AuditLog(log_path).purge() == 0
    os.makedirs(os.path.dirname(log_path))
    assert AuditLog(log_path).purge() == 0


def test_log_is_usable_after_purge(log_path: str) -> None:
    log = AuditLog(log_path)
    _fill(log, 3)
    assert log.purge() == 1
    assert log.append({"i": 7})
    assert [r["i"] for r in log.tail()] == [7]


# --------------------------------------------------------------------------------------------
# Concurrency
# --------------------------------------------------------------------------------------------


def _run_threads(target: Any, count: int) -> None:
    threads = [threading.Thread(target=target, args=(t,)) for t in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def test_concurrent_appends_from_8_threads_produce_intact_lines(log_path: str) -> None:
    log = AuditLog(log_path, max_bytes=100_000_000)
    results: list[bool] = []
    lock = threading.Lock()

    def work(thread_id: int) -> None:
        for n in range(100):
            ok = log.append({"t": thread_id, "n": n, "payload": f"{thread_id}-{n}-" + "z" * 3000})
            with lock:
                results.append(ok)

    _run_threads(work, 8)
    assert results == [True] * 800
    lines = read_lines(log_path)
    assert len(lines) == 800
    seen = set()
    for line in lines:
        record = json.loads(line)
        assert record["payload"] == f"{record['t']}-{record['n']}-" + "z" * 3000
        seen.add((record["t"], record["n"]))
    assert len(seen) == 800


def test_concurrent_appends_with_rotation_lose_nothing(log_path: str) -> None:
    log = AuditLog(log_path, max_bytes=20_000, backups=500)

    def work(thread_id: int) -> None:
        for n in range(100):
            assert log.append({"t": thread_id, "n": n, "pad": "q" * 100})

    _run_threads(work, 8)
    directory = os.path.dirname(log_path)
    seen = set()
    for name in os.listdir(directory):
        for line in read_lines(os.path.join(directory, name)):
            record = json.loads(line)
            seen.add((record["t"], record["n"]))
    assert len(seen) == 800
    assert log.last_error is None


def test_files_are_closed_after_every_append(log_path: str) -> None:
    # If a handle were kept, removing the file would fail on Windows.
    log = AuditLog(log_path)
    assert log.append({"a": 1})
    os.remove(log_path)
    assert log.append({"a": 2})
    assert [r["a"] for r in log.tail()] == [2]
