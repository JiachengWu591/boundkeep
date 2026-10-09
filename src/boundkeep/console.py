"""Console output for the CLI.

On a Chinese Windows the text layer of redirected stdout/stderr uses the ANSI code page (gbk),
which cannot encode a check mark: printing one raises ``UnicodeEncodeError`` and the command dies
with a traceback. ``configure`` switches both streams to UTF-8 with ``errors="replace"`` so output
never crashes a command; a real console already works in Unicode (PEP 528) and is unaffected.
Nothing here is used by the hook client (its stdout is a protocol channel, see hook_client.py).
"""

from __future__ import annotations

import contextlib
import queue
import sys
import threading


def configure() -> None:
    """Make stdout and stderr UTF-8 with ``errors="replace"``; best effort, never raises."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            continue


def _write(stream: object, text: str) -> None:
    """Write a line; a missing stream (pythonw.exe) or a broken one is not an error."""
    if stream is None:
        return
    try:
        stream.write(text + "\n")  # type: ignore[attr-defined]
        stream.flush()  # type: ignore[attr-defined]
    except (OSError, ValueError, AttributeError):
        pass


def out(text: str = "") -> None:
    _write(sys.stdout, text)


def err(text: str = "") -> None:
    _write(sys.stderr, text)


class BackgroundErr:
    """``err`` that can never block the caller.

    A daemon that writes to a stderr nobody reads (a full pipe) would freeze its event loop and
    stop answering. Lines go through a bounded queue to a writer thread and are dropped when the
    queue is full.
    """

    def __init__(self, maxsize: int = 200) -> None:
        self._queue: queue.Queue[str] = queue.Queue(maxsize)
        threading.Thread(target=self._drain, name="boundkeep-stderr", daemon=True).start()

    def __call__(self, text: str) -> None:
        with contextlib.suppress(queue.Full):
            self._queue.put_nowait(text)

    def _drain(self) -> None:
        while True:
            err(self._queue.get())
