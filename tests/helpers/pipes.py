"""A pipe server on its own event loop in a background thread, for tests that need a real daemon
stand-in with controllable misbehaviour (never answers, holds instances, ...)."""

from __future__ import annotations

import asyncio
import contextlib
import os
import threading
from collections.abc import Callable, Coroutine, Iterator
from typing import Any

from boundkeep.ipc.endpoint import TRANSPORT_NAMED_PIPE, Endpoint, pipe_address


def new_pipe_endpoint() -> Endpoint:
    return Endpoint(TRANSPORT_NAMED_PIPE, pipe_address(os.urandom(8).hex()))


@contextlib.contextmanager
def threaded_pipe_server(
    endpoint: Endpoint,
    handler: Callable[[bytes], Coroutine[Any, Any, bytes]],
    **options: Any,
) -> Iterator[None]:
    from boundkeep.ipc.named_pipe import NamedPipeServer

    ready = threading.Event()
    stop = threading.Event()
    problems: list[BaseException] = []

    def serve() -> None:
        async def main() -> None:
            server = NamedPipeServer(endpoint.address, handler, **options)
            try:
                await server.start()
            except BaseException as exc:
                problems.append(exc)
                ready.set()
                return
            ready.set()
            while not stop.is_set():
                await asyncio.sleep(0.02)
            await server.close()

        asyncio.run(main())

    thread = threading.Thread(target=serve, name="test-pipe-server", daemon=True)
    thread.start()
    assert ready.wait(10)
    if problems:
        raise problems[0]
    try:
        yield
    finally:
        stop.set()
        thread.join(15)
