"""Windows named-pipe server, built directly on kernel32 through ctypes.

Why not asyncio's pipe server: it creates the pipe with a NULL security descriptor (measured in
M0a: Everyone and Anonymous get read access, nothing rejects remote clients), asyncio on Windows
has no Unix sockets, and there is no way to ask for the first-instance flag. So:

* every instance is created with an explicit DACL that grants the current user only
  (``winsec.SecurityDescriptor.private``), ``PIPE_REJECT_REMOTE_CLIENTS``, and the first one with
  ``FILE_FLAG_FIRST_PIPE_INSTANCE`` (creation fails with ``AddressInUse`` when the name is taken);
* a pool of instances is created up front (``instances``, default 8): with a single instance 4
  concurrent clients hit "pipe busy" on 76-85% of first attempts, with 8 on 2-4% (M0a E10);
* one worker thread per instance, all I/O overlapped with a deadline, so a client that connects
  and says nothing, or never reads the answer, cannot hold an instance forever;
* requests are handed to the asyncio event loop of the daemon (``handler``) and the worker waits
  for the answer in short slices, so closing the server never deadlocks against the loop.

Each connection is one request line and one response line, then the instance is recycled.
Transport-level problems (oversize or late requests, a handler that fails or is too slow) are
answered with a protocol error line that carries the placeholder id ``-``.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import ctypes
import sys
import threading
import time

from boundkeep import protocol
from boundkeep.ipc import winsec
from boundkeep.ipc.base import (
    DEFAULT_HANDLER_TIMEOUT_S,
    DEFAULT_INSTANCES,
    DEFAULT_READ_TIMEOUT_S,
    AddressInUse,
    ErrorSink,
    Handler,
    ServerStartError,
)
from boundkeep.ipc.endpoint import PIPE_PREFIX

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("boundkeep.ipc.named_pipe is only available on Windows")
assert sys.platform == "win32"  # lets mypy skip the rest on other platforms

_HANDLE = ctypes.c_void_p
_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int

_PIPE_ACCESS_DUPLEX = 0x00000003
_FILE_FLAG_OVERLAPPED = 0x40000000
_FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
_PIPE_TYPE_BYTE = 0x0
_PIPE_READMODE_BYTE = 0x0
_PIPE_WAIT = 0x0
_PIPE_REJECT_REMOTE_CLIENTS = 0x8
_PIPE_UNLIMITED_INSTANCES = 255
_PIPE_MODE = _PIPE_TYPE_BYTE | _PIPE_READMODE_BYTE | _PIPE_WAIT | _PIPE_REJECT_REMOTE_CLIENTS
_BUFFER_BYTES = 64 * 1024

_ERROR_ACCESS_DENIED = 5
_ERROR_BROKEN_PIPE = 109
_ERROR_PIPE_BUSY = 231
_ERROR_NO_DATA = 232
_ERROR_PIPE_NOT_CONNECTED = 233
_ERROR_PIPE_CONNECTED = 535
_ERROR_OPERATION_ABORTED = 995
_ERROR_IO_PENDING = 997
_CLIENT_GONE = frozenset(
    {_ERROR_BROKEN_PIPE, _ERROR_NO_DATA, _ERROR_PIPE_NOT_CONNECTED, _ERROR_OPERATION_ABORTED}
)

_WAIT_OBJECT_0 = 0x0
_WAIT_TIMEOUT = 0x102
_INFINITE = 0xFFFFFFFF
_INVALID_HANDLE = ctypes.c_void_p(-1).value

_TRANSPORT_ERROR_ID = "-"
_DRAIN_TIMEOUT_S = 0.5  # time the client gets to read the answer before the instance is recycled
# A client writes its request right after connecting; one that stays silent this long holds an
# instance for nothing (8 silent clients would otherwise starve the pool for the read timeout).
_FIRST_BYTE_TIMEOUT_S = 1.0
_HANDLER_POLL_S = 0.1
_MAX_CONSECUTIVE_FAILURES = 50


class _Overlapped(ctypes.Structure):
    _fields_ = (
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", _DWORD),
        ("OffsetHigh", _DWORD),
        ("hEvent", _HANDLE),
    )


class _Api:
    def __init__(self) -> None:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        ov_p = ctypes.POINTER(_Overlapped)
        dw_p = ctypes.POINTER(_DWORD)

        self.CreateNamedPipeW = k32.CreateNamedPipeW
        self.CreateNamedPipeW.argtypes = [
            ctypes.c_wchar_p,
            _DWORD,
            _DWORD,
            _DWORD,
            _DWORD,
            _DWORD,
            _DWORD,
            ctypes.POINTER(winsec.SECURITY_ATTRIBUTES),
        ]
        self.CreateNamedPipeW.restype = _HANDLE
        self.ConnectNamedPipe = k32.ConnectNamedPipe
        self.ConnectNamedPipe.argtypes = [_HANDLE, ov_p]
        self.ConnectNamedPipe.restype = _BOOL
        self.DisconnectNamedPipe = k32.DisconnectNamedPipe
        self.DisconnectNamedPipe.argtypes = [_HANDLE]
        self.DisconnectNamedPipe.restype = _BOOL
        self.ReadFile = k32.ReadFile
        self.ReadFile.argtypes = [_HANDLE, ctypes.c_void_p, _DWORD, dw_p, ov_p]
        self.ReadFile.restype = _BOOL
        self.WriteFile = k32.WriteFile
        self.WriteFile.argtypes = [_HANDLE, ctypes.c_char_p, _DWORD, dw_p, ov_p]
        self.WriteFile.restype = _BOOL
        self.CancelIoEx = k32.CancelIoEx
        self.CancelIoEx.argtypes = [_HANDLE, ov_p]
        self.CancelIoEx.restype = _BOOL
        self.GetOverlappedResult = k32.GetOverlappedResult
        self.GetOverlappedResult.argtypes = [_HANDLE, ov_p, dw_p, _BOOL]
        self.GetOverlappedResult.restype = _BOOL
        self.CreateEventW = k32.CreateEventW
        self.CreateEventW.argtypes = [ctypes.c_void_p, _BOOL, _BOOL, ctypes.c_wchar_p]
        self.CreateEventW.restype = _HANDLE
        self.SetEvent = k32.SetEvent
        self.SetEvent.argtypes = [_HANDLE]
        self.SetEvent.restype = _BOOL
        self.CloseHandle = k32.CloseHandle
        self.CloseHandle.argtypes = [_HANDLE]
        self.CloseHandle.restype = _BOOL
        self.WaitForMultipleObjects = k32.WaitForMultipleObjects
        self.WaitForMultipleObjects.argtypes = [_DWORD, ctypes.POINTER(_HANDLE), _BOOL, _DWORD]
        self.WaitForMultipleObjects.restype = _DWORD


_api_instance: _Api | None = None
_api_lock = threading.Lock()


def _api() -> _Api:
    global _api_instance
    with _api_lock:
        if _api_instance is None:
            _api_instance = _Api()
        return _api_instance


class _Win32Error(Exception):
    def __init__(self, code: int) -> None:
        super().__init__(f"win32 error {code}")
        self.code = code


class _Stopping(Exception):
    """The server is shutting down."""


class _TimedOut(Exception):
    """An I/O deadline passed."""


class _ClientGone(Exception):
    """The client closed or aborted the connection."""


class _TooLarge(Exception):
    """The request exceeded the size limit."""


class NamedPipeServer:
    """Serves ``handler`` on the pipe ``address`` (``\\\\.\\pipe\\boundkeep-<token>``)."""

    def __init__(
        self,
        address: str,
        handler: Handler,
        *,
        instances: int = DEFAULT_INSTANCES,
        read_timeout_s: float = DEFAULT_READ_TIMEOUT_S,
        handler_timeout_s: float = DEFAULT_HANDLER_TIMEOUT_S,
        on_error: ErrorSink | None = None,
        max_request_bytes: int = protocol.MAX_REQUEST_BYTES,
    ) -> None:
        if not address.startswith(PIPE_PREFIX):
            raise ServerStartError(f"not a pipe address: {address!r}")
        if not 1 <= instances <= 64:
            raise ServerStartError("instances must be between 1 and 64")
        self._address = address
        self._handler = handler
        self._instances = instances
        self._read_timeout_s = read_timeout_s
        self._handler_timeout_s = handler_timeout_s
        self._on_error = on_error
        self._max_request_bytes = max_request_bytes
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stopping = threading.Event()
        self._stop_handle: int | None = None
        self._threads: list[threading.Thread] = []
        self._started = False
        self._closed = False

    @property
    def address(self) -> str:
        return self._address

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._start_sync()

    async def close(self) -> None:
        if self._closed or not self._started:
            self._closed = True
            return
        # joining the workers can take a moment and they may be waiting for the event loop:
        # never do it on the loop thread
        await asyncio.get_running_loop().run_in_executor(None, self._close_sync)

    # -- lifecycle ---------------------------------------------------------------------------

    def _report(self, message: str) -> None:
        if self._on_error is not None:
            with contextlib.suppress(Exception):  # reporting must never break serving
                self._on_error(message)

    def _start_sync(self) -> None:
        if self._started:
            raise ServerStartError("server already started")
        api = _api()
        stop_handle = api.CreateEventW(None, 1, 0, None)
        if not stop_handle:
            raise ServerStartError(
                f"cannot create the stop event: {ctypes.WinError(ctypes.get_last_error())}"
            )
        handles: list[int] = []
        try:
            # The descriptor must stay alive while the instances are created; the kernel copies it.
            with winsec.SecurityDescriptor.private() as descriptor:
                attributes = descriptor.attributes
                for index in range(self._instances):
                    flags = _PIPE_ACCESS_DUPLEX | _FILE_FLAG_OVERLAPPED
                    if index == 0:
                        flags |= _FILE_FLAG_FIRST_PIPE_INSTANCE
                    handle = api.CreateNamedPipeW(
                        self._address,
                        flags,
                        _PIPE_MODE,
                        _PIPE_UNLIMITED_INSTANCES,
                        _BUFFER_BYTES,
                        _BUFFER_BYTES,
                        0,
                        ctypes.byref(attributes),
                    )
                    if not handle or handle == _INVALID_HANDLE:
                        code = ctypes.get_last_error()
                        if index == 0 and code in (_ERROR_ACCESS_DENIED, _ERROR_PIPE_BUSY):
                            raise AddressInUse(
                                f"the pipe {self._address} already exists (is another "
                                "'boundkeep serve' running?)"
                            )
                        raise ServerStartError(
                            f"cannot create pipe instance {index}: {ctypes.WinError(code)}"
                        )
                    handles.append(handle)
        except BaseException:
            for handle in handles:
                api.CloseHandle(handle)
            api.CloseHandle(stop_handle)
            raise
        self._stop_handle = stop_handle
        self._started = True
        for index, handle in enumerate(handles):
            worker = _Worker(self, index, handle)
            thread = threading.Thread(
                target=worker.run, name=f"boundkeep-pipe-{index}", daemon=True
            )
            self._threads.append(thread)
            thread.start()

    def _close_sync(self) -> None:
        self._closed = True
        self._stopping.set()
        api = _api()
        if self._stop_handle is not None:
            api.SetEvent(self._stop_handle)
        for thread in self._threads:
            thread.join(timeout=5.0)
        stuck = [t.name for t in self._threads if t.is_alive()]
        if stuck:
            self._report(f"pipe workers did not stop in time: {', '.join(stuck)}")
        else:
            if self._stop_handle is not None:
                api.CloseHandle(self._stop_handle)
                self._stop_handle = None

    # -- request handling (called by the workers) ---------------------------------------------

    def _run_handler(self, line: bytes) -> bytes:
        loop = self._loop
        if loop is None or loop.is_closed():
            return protocol.encode_error(
                _TRANSPORT_ERROR_ID, protocol.ERR_INTERNAL, "server is stopping"
            )
        future: concurrent.futures.Future[bytes]
        try:
            future = asyncio.run_coroutine_threadsafe(self._handler(line), loop)
        except RuntimeError:
            return protocol.encode_error(
                _TRANSPORT_ERROR_ID, protocol.ERR_INTERNAL, "server is stopping"
            )
        deadline = time.monotonic() + self._handler_timeout_s
        while True:
            try:
                response = future.result(timeout=_HANDLER_POLL_S)
                break
            except concurrent.futures.TimeoutError:
                if self._stopping.is_set() or time.monotonic() >= deadline:
                    future.cancel()
                    return protocol.encode_error(
                        _TRANSPORT_ERROR_ID,
                        protocol.ERR_TIMEOUT,
                        "the daemon did not answer in time",
                    )
            except Exception as exc:  # noqa: BLE001 - a failing handler must not kill the worker
                self._report(f"handler failed: {type(exc).__name__}")
                return protocol.encode_error(
                    _TRANSPORT_ERROR_ID, protocol.ERR_INTERNAL, "internal error"
                )
        if (
            not isinstance(response, bytes)
            or not response.endswith(b"\n")
            or len(response) > protocol.MAX_RESPONSE_BYTES + 1
        ):
            self._report("handler returned an invalid response")
            return protocol.encode_error(
                _TRANSPORT_ERROR_ID, protocol.ERR_INTERNAL, "internal error"
            )
        return response


class _Worker:
    """One pipe instance and the thread that serves it."""

    def __init__(self, server: NamedPipeServer, index: int, handle: int) -> None:
        self._srv = server
        self._index = index
        self._handle = handle
        self._api = _api()
        self._event: int | None = None
        self._buffer = ctypes.create_string_buffer(_BUFFER_BYTES)

    def run(self) -> None:
        srv = self._srv
        api = self._api
        self._event = api.CreateEventW(None, 1, 0, None)
        if not self._event:
            srv._report(f"pipe worker {self._index}: cannot create an event")
            api.CloseHandle(self._handle)
            return
        failures = 0
        try:
            while not srv._stopping.is_set():
                try:
                    self._serve_one()
                    failures = 0
                except _Stopping:
                    break
                except Exception as exc:  # noqa: BLE001 - keep the instance alive, but never spin
                    failures += 1
                    srv._report(f"pipe worker {self._index}: {type(exc).__name__}: {exc}")
                    if failures >= _MAX_CONSECUTIVE_FAILURES:
                        srv._report(f"pipe worker {self._index}: giving up after repeated failures")
                        break
                    time.sleep(min(0.5, 0.01 * failures))
        finally:
            api.DisconnectNamedPipe(self._handle)
            api.CloseHandle(self._handle)
            api.CloseHandle(self._event)

    # -- one connection ----------------------------------------------------------------------

    def _serve_one(self) -> None:
        api = self._api
        try:
            self._connect()
            try:
                line = self._read_request()
            except _TimedOut:
                response = protocol.encode_error(
                    _TRANSPORT_ERROR_ID, protocol.ERR_TIMEOUT, "no complete request line in time"
                )
            except _TooLarge:
                response = protocol.encode_error(
                    _TRANSPORT_ERROR_ID, protocol.ERR_TOO_LARGE, "request too large"
                )
            except _ClientGone:
                return
            else:
                response = self._srv._run_handler(line)
            try:
                self._write(response)
                self._wait_for_client_to_close()
            except (_TimedOut, _ClientGone):
                pass
        finally:
            api.DisconnectNamedPipe(self._handle)

    def _new_overlapped(self) -> _Overlapped:
        overlapped = _Overlapped()
        overlapped.hEvent = self._event
        return overlapped

    def _cancel(self, overlapped: _Overlapped) -> None:
        # The OVERLAPPED and the buffer must stay valid until the operation has really finished.
        api = self._api
        api.CancelIoEx(self._handle, ctypes.byref(overlapped))
        transferred = _DWORD(0)
        api.GetOverlappedResult(
            self._handle, ctypes.byref(overlapped), ctypes.byref(transferred), 1
        )

    def _finish(self, overlapped: _Overlapped, started: bool, timeout_s: float | None) -> int:
        """Wait for an overlapped operation; returns the bytes transferred."""
        api = self._api
        srv = self._srv
        if not started:
            code = ctypes.get_last_error()
            if code != _ERROR_IO_PENDING:
                raise _Win32Error(code)
            assert srv._stop_handle is not None
            timeout_ms = _INFINITE if timeout_s is None else max(0, int(timeout_s * 1000))
            handles = (_HANDLE * 2)(self._event, srv._stop_handle)
            result = api.WaitForMultipleObjects(2, handles, 0, timeout_ms)
            if result != _WAIT_OBJECT_0:
                self._cancel(overlapped)
                if result == _WAIT_OBJECT_0 + 1:
                    raise _Stopping
                if result == _WAIT_TIMEOUT:
                    raise _TimedOut
                raise _Win32Error(ctypes.get_last_error())
        transferred = _DWORD(0)
        if not api.GetOverlappedResult(
            self._handle, ctypes.byref(overlapped), ctypes.byref(transferred), 0
        ):
            raise _Win32Error(ctypes.get_last_error())
        return int(transferred.value)

    def _connect(self) -> None:
        overlapped = self._new_overlapped()
        started = bool(self._api.ConnectNamedPipe(self._handle, ctypes.byref(overlapped)))
        if not started and ctypes.get_last_error() == _ERROR_PIPE_CONNECTED:
            return  # a client connected between creation (or recycling) and this call
        self._finish(overlapped, started, None)

    def _read_request(self) -> bytes:
        api = self._api
        srv = self._srv
        deadline = time.monotonic() + srv._read_timeout_s
        data = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _TimedOut
            if not data:
                remaining = min(remaining, _FIRST_BYTE_TIMEOUT_S)
            overlapped = self._new_overlapped()
            started = bool(
                api.ReadFile(
                    self._handle, self._buffer, _BUFFER_BYTES, None, ctypes.byref(overlapped)
                )
            )
            try:
                count = self._finish(overlapped, started, remaining)
            except _Win32Error as exc:
                if exc.code in _CLIENT_GONE:
                    raise _ClientGone from exc
                raise
            if count == 0:
                raise _ClientGone
            data += self._buffer.raw[:count]
            newline = data.find(b"\n")
            if newline >= 0:
                # the limit applies to a complete line too, not only to one still being received
                if newline > srv._max_request_bytes:
                    raise _TooLarge
                return bytes(data[:newline])
            if len(data) > srv._max_request_bytes:
                raise _TooLarge

    def _write(self, data: bytes) -> None:
        api = self._api
        view = memoryview(data)
        deadline = time.monotonic() + max(self._srv._read_timeout_s, 1.0)
        while view:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _TimedOut
            chunk = bytes(view[:_BUFFER_BYTES])
            overlapped = self._new_overlapped()
            started = bool(
                api.WriteFile(self._handle, chunk, len(chunk), None, ctypes.byref(overlapped))
            )
            try:
                written = self._finish(overlapped, started, remaining)
            except _Win32Error as exc:
                if exc.code in _CLIENT_GONE:
                    raise _ClientGone from exc
                raise
            if written == 0:
                raise _ClientGone
            view = view[written:]

    def _wait_for_client_to_close(self) -> None:
        """DisconnectNamedPipe discards unread data, so let the client finish reading first.

        The client reads its one response line and closes the pipe; that shows up here as a
        broken-pipe error (or EOF) on a read. A client that never closes only costs the timeout.
        """
        api = self._api
        overlapped = self._new_overlapped()
        started = bool(
            api.ReadFile(self._handle, self._buffer, _BUFFER_BYTES, None, ctypes.byref(overlapped))
        )
        try:
            self._finish(overlapped, started, _DRAIN_TIMEOUT_S)
        except _Win32Error as exc:
            if exc.code not in _CLIENT_GONE:
                raise
