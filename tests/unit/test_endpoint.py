from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from boundkeep.ipc import endpoint as ep
from boundkeep.ipc.client import DaemonUnavailable, call


def test_new_named_pipe_endpoints_are_valid_and_unique() -> None:
    first = ep.new_endpoint("home", transport=ep.TRANSPORT_NAMED_PIPE)
    second = ep.new_endpoint("home", transport=ep.TRANSPORT_NAMED_PIPE)
    ep.validate_endpoint(first)
    assert first.address.startswith("\\\\.\\pipe\\boundkeep-")
    assert first.address != second.address
    assert len(first.address) == len("\\\\.\\pipe\\boundkeep-") + 32


def test_unix_endpoint_prefers_a_socket_in_home_and_falls_back_for_deep_homes() -> None:
    short = ep.new_endpoint("/home/u/.boundkeep", transport=ep.TRANSPORT_UNIX)
    assert short.address == os.path.join("/home/u/.boundkeep", "serve.sock")
    deep = ep.new_endpoint("/" + "d" * 200, transport=ep.TRANSPORT_UNIX)
    assert deep.address.startswith("/tmp/bk-")
    assert len(deep.address) <= ep.MAX_UNIX_SOCKET_PATH


def test_unknown_transport_is_refused() -> None:
    with pytest.raises(ep.EndpointError):
        ep.new_endpoint("home", transport="smoke-signals")
    with pytest.raises(ep.EndpointError):
        ep.validate_endpoint(ep.Endpoint("smoke-signals", "x"))


@pytest.mark.parametrize(
    "bad",
    [
        ep.Endpoint(ep.TRANSPORT_NAMED_PIPE, "\\\\.\\pipe\\other-name"),
        ep.Endpoint(ep.TRANSPORT_NAMED_PIPE, "\\\\.\\pipe\\boundkeep-"),
        ep.Endpoint(ep.TRANSPORT_NAMED_PIPE, "\\\\.\\pipe\\boundkeep-a\\..\\b"),
        ep.Endpoint(ep.TRANSPORT_NAMED_PIPE, "\\\\other-host\\pipe\\boundkeep-abc"),
        ep.Endpoint(ep.TRANSPORT_NAMED_PIPE, "\\\\.\\pipe\\boundkeep-abc\n"),
        ep.Endpoint(ep.TRANSPORT_UNIX, "relative/serve.sock"),
        ep.Endpoint(ep.TRANSPORT_UNIX, "/" + "x" * 200),
    ],
)
def test_invalid_endpoints_are_refused(bad: ep.Endpoint) -> None:
    with pytest.raises(ep.EndpointError):
        ep.validate_endpoint(bad)


def test_write_then_read_round_trip(tmp_path: Path) -> None:
    path = str(tmp_path / "sub" / "endpoint.json")
    endpoint = ep.new_endpoint(str(tmp_path), transport=ep.TRANSPORT_NAMED_PIPE)
    ep.write_endpoint(path, endpoint)
    assert ep.read_endpoint(path) == endpoint
    assert [p.name for p in (tmp_path / "sub").iterdir()] == ["endpoint.json"]  # no temp file left


def test_write_failure_leaves_the_original_and_no_temp_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = str(tmp_path / "endpoint.json")
    good = ep.new_endpoint(str(tmp_path), transport=ep.TRANSPORT_NAMED_PIPE)
    ep.write_endpoint(path, good)

    def boom(src: str, dst: str) -> None:
        raise OSError("disk on fire")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="disk on fire"):
        ep.write_endpoint(path, ep.new_endpoint(str(tmp_path), transport=ep.TRANSPORT_NAMED_PIPE))
    monkeypatch.undo()
    assert ep.read_endpoint(path) == good
    assert sorted(p.name for p in tmp_path.iterdir()) == ["endpoint.json"]


def test_read_missing_file_mentions_init(tmp_path: Path) -> None:
    with pytest.raises(ep.EndpointError, match="init"):
        ep.read_endpoint(str(tmp_path / "nope.json"))


_GOOD = {"v": 1, "transport": "named_pipe", "address": "\\\\.\\pipe\\boundkeep-abc123"}


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"\xff\xfe",
        b"not json",
        b"[]",
        pytest.param(b"x" * (ep.MAX_ENDPOINT_FILE_BYTES + 1), id="oversize"),
        json.dumps({**_GOOD, "v": 2}).encode(),
        json.dumps({**_GOOD, "v": True}).encode(),
        json.dumps({**_GOOD, "transport": "carrier-pigeon"}).encode(),
        json.dumps({**_GOOD, "transport": 7}).encode(),
        json.dumps({**_GOOD, "address": 7}).encode(),
        json.dumps({"v": 1, "transport": "named_pipe"}).encode(),
        json.dumps({**_GOOD, "address": "\\\\.\\pipe\\not-ours"}).encode(),
        pytest.param(b"[" * 3000, id="deep-nesting"),
    ],
)
def test_invalid_endpoint_files_are_refused(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "endpoint.json"
    path.write_bytes(content)
    with pytest.raises(ep.EndpointError):
        ep.read_endpoint(str(path))


def test_read_a_directory_is_an_endpoint_error(tmp_path: Path) -> None:
    with pytest.raises(ep.EndpointError):
        ep.read_endpoint(str(tmp_path))


@pytest.mark.posix
def test_written_endpoint_file_is_private_on_posix(tmp_path: Path) -> None:
    path = tmp_path / "endpoint.json"
    ep.write_endpoint(str(path), ep.new_endpoint(str(tmp_path), transport=ep.TRANSPORT_UNIX))
    assert path.stat().st_mode & 0o077 == 0


@pytest.mark.windows
def test_client_reports_a_missing_pipe_as_unavailable_quickly() -> None:
    endpoint = ep.new_endpoint("home", transport=ep.TRANSPORT_NAMED_PIPE)
    started = time.monotonic()
    with pytest.raises(DaemonUnavailable):
        call(endpoint, b'{"x":1}\n', timeout_s=5)
    assert time.monotonic() - started < 1.0


@pytest.mark.posix
def test_client_reports_a_missing_socket_as_unavailable(tmp_path: Path) -> None:
    endpoint = ep.Endpoint(ep.TRANSPORT_UNIX, str(tmp_path / "nope.sock"))
    with pytest.raises(DaemonUnavailable):
        call(endpoint, b'{"x":1}\n', timeout_s=5)


def test_default_transport_matches_the_platform() -> None:
    expected = ep.TRANSPORT_NAMED_PIPE if sys.platform == "win32" else ep.TRANSPORT_UNIX
    assert ep.default_transport() == expected
