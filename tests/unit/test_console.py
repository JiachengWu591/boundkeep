"""Console output must never block or crash the CLI or the daemon."""

from __future__ import annotations

import io
import sys
import threading
import time

import pytest

from boundkeep import console


def test_missing_streams_are_not_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdout", None)  # pythonw.exe
    monkeypatch.setattr(sys, "stderr", None)
    console.out("x")
    console.err("x")


class _Broken(io.StringIO):
    def write(self, text: str) -> int:
        raise OSError("pipe is gone")


def test_a_broken_stream_is_not_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stderr", _Broken())
    console.err("x")


def test_background_err_never_blocks_the_caller_when_the_stream_stalls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()

    class Stalled(io.StringIO):
        def write(self, text: str) -> int:
            release.wait(30)  # an unread pipe: the writer is stuck
            return len(text)

    monkeypatch.setattr(sys, "stderr", Stalled())
    report = console.BackgroundErr(maxsize=10)
    started = time.monotonic()
    for i in range(5000):
        report(f"line {i}")
    assert time.monotonic() - started < 2  # dropped when full, never waiting for the stream
    release.set()
