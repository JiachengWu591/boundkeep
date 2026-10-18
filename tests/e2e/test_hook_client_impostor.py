"""Review H-2, client side: a daemon (or impostor) that answers ``allow`` is not obeyed unless the
hook command carries ``--emit-allow``.

The "impostor" is a fake daemon on a unique pipe in a throwaway home (nothing of the user's is
touched); the client is a real ``python -I -S hook_client.py`` process with ``--home`` pinned.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.ipc import endpoint as ipc_endpoint
from tests.conftest import REPO_ROOT
from tests.helpers.pipes import new_pipe_endpoint, threaded_pipe_server

pytestmark = [pytest.mark.e2e, pytest.mark.windows]

HOOK = REPO_ROOT / "src" / "boundkeep" / "hook_client.py"


def _run(
    flags: list[str], sub: str, stdin: bytes, env: dict[str, str]
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-I", "-S", str(HOOK), *flags, sub],
        input=stdin,
        capture_output=True,
        env=env,
        timeout=30,
        check=False,
    )


def _answering(decision: str) -> Any:
    async def handler(line: bytes) -> bytes:
        request = protocol.decode_request(line)
        return protocol.encode_response(request.request_id, decision=decision, reason="fake")

    return handler


async def _garbage(line: bytes) -> bytes:
    return b"this is not json\n"


def _permission(proc: subprocess.CompletedProcess[bytes]) -> str | None:
    assert proc.returncode == 0, proc.stderr
    if not proc.stdout:
        return None
    out = json.loads(proc.stdout)["hookSpecificOutput"]
    return str(out["permissionDecision"])


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "throwaway-home"
    path.mkdir()
    return path


def _event(fixture_bytes: Any) -> bytes:
    return bytes(fixture_bytes("PreToolUse__PowerShell"))


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        pytest.param(["--home", "HOME"], None, id="no-pin-allow-is-no-decision"),
        pytest.param(["--home", "HOME", "--emit-allow"], "allow", id="home-then-pin"),
        pytest.param(["--emit-allow", "--home", "HOME"], "allow", id="pin-then-home"),
        pytest.param(["--home", "HOME", "--bogus", "--emit-allow"], "ask", id="unknown-flag-asks"),
    ],
)
def test_an_allow_from_the_daemon_is_only_obeyed_with_the_pin(
    flags: list[str],
    expected: str | None,
    home: Path,
    hook_env: dict[str, str],
    fixture_bytes: Any,
) -> None:
    endpoint = new_pipe_endpoint()
    ipc_endpoint.write_endpoint(str(home / "endpoint.json"), endpoint)
    argv = [str(home) if part == "HOME" else part for part in flags]
    with threaded_pipe_server(endpoint, _answering("allow")):
        proc = _run(argv, "pre", _event(fixture_bytes), hook_env)
    assert _permission(proc) == expected


@pytest.mark.parametrize("decision", ["deny", "ask"])
@pytest.mark.parametrize("pinned", [False, True])
def test_deny_and_ask_from_the_daemon_always_get_through(
    decision: str, pinned: bool, home: Path, hook_env: dict[str, str], fixture_bytes: Any
) -> None:
    endpoint = new_pipe_endpoint()
    ipc_endpoint.write_endpoint(str(home / "endpoint.json"), endpoint)
    flags = ["--home", str(home), *(["--emit-allow"] if pinned else [])]
    with threaded_pipe_server(endpoint, _answering(decision)):
        proc = _run(flags, "pre", _event(fixture_bytes), hook_env)
    assert _permission(proc) == decision


@pytest.mark.parametrize("pinned", [False, True])
def test_garbage_from_the_daemon_still_asks(
    pinned: bool, home: Path, hook_env: dict[str, str], fixture_bytes: Any
) -> None:
    endpoint = new_pipe_endpoint()
    ipc_endpoint.write_endpoint(str(home / "endpoint.json"), endpoint)
    flags = ["--home", str(home), *(["--emit-allow"] if pinned else [])]
    with threaded_pipe_server(endpoint, _garbage):
        proc = _run(flags, "pre", _event(fixture_bytes), hook_env)
    assert _permission(proc) == "ask"


def test_post_events_print_nothing_even_when_the_daemon_says_allow(
    home: Path, hook_env: dict[str, str], fixture_bytes: Any
) -> None:
    endpoint = new_pipe_endpoint()
    ipc_endpoint.write_endpoint(str(home / "endpoint.json"), endpoint)
    event = json.loads(fixture_bytes("PreToolUse__PowerShell"))
    event["hook_event_name"] = "PostToolUse"
    flags = ["--home", str(home), "--emit-allow"]
    with threaded_pipe_server(endpoint, _answering("allow")):
        proc = _run(flags, "post", json.dumps(event).encode("utf-8"), hook_env)
    assert (proc.returncode, proc.stdout) == (0, b"")


def test_an_impostor_cannot_join_the_running_daemons_pipe(
    home: Path, hook_env: dict[str, str], fixture_bytes: Any
) -> None:
    """The reported attack: adding an instance to the daemon's pipe to answer in its place.

    Creating the instance is refused (access denied), so the client keeps talking to the real
    handler, which denies.
    """
    from tests.platform.test_winsec_pipe_instances import (
        _ERROR_ACCESS_DENIED,
        _try_to_add_an_instance,
    )

    endpoint = new_pipe_endpoint()
    ipc_endpoint.write_endpoint(str(home / "endpoint.json"), endpoint)
    with threaded_pipe_server(endpoint, _answering("deny")):
        assert _try_to_add_an_instance(endpoint.address, private_dacl=True) == _ERROR_ACCESS_DENIED
        proc = _run(["--home", str(home), "--emit-allow"], "pre", _event(fixture_bytes), hook_env)
    assert _permission(proc) == "deny"
