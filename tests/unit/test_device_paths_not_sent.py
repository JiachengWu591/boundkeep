"""A gray call that touches the Windows device namespace is not sent to the LLM audit (revision 10).

The key of such a path does not say where it leads: ``//./globalroot/device/mup/srv/share/x`` is a
network share, ``//./pipe/x`` whatever service listens on that pipe, ``//./c:`` a whole volume. The
model would be allowing a string. ``NUL`` is the exception: it discards what is written and reads
empty, and ``2>NUL`` is everywhere. Rules still come first; without a backend nothing changes.
"""

from __future__ import annotations

import ctypes
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.audit.auditor import Auditor
from boundkeep.audit.backends.base import verdict_json
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.policy import Policy, default_policy_text, parse_policy_text
from boundkeep.session.store import SessionStore

HOME = "C:\\Users\\bob"
PROJECT = "C:\\proj"
LLM_BLOCK = (
    "  backend: openai_compatible\n"
    "  openai_compatible:\n"
    "    base_url: https://llm.example.invalid/v1\n"
    "    model: test-model\n"
)
DEVICE = "gray-device-path"


def llm_policy() -> Policy:
    text, found = re.subn(
        r"^  backend: none.*$",
        lambda _m: LLM_BLOCK.rstrip("\n"),
        default_policy_text(),
        count=1,
        flags=re.M,
    )
    assert found == 1
    return parse_policy_text(text, home=HOME)


POLICY = llm_policy()


def payload(tool: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "s",
        "cwd": PROJECT,
        "project_dir": PROJECT,
        "tool_name": tool,
        "tool_input": tool_input,
    }


def decide(
    tool: str, tool_input: dict[str, Any], *, mode: str = "enforce"
) -> tuple[pipeline.Decision, FakeBackend]:
    """The verdict with a backend that allows whatever it is shown, and that backend."""
    backend = FakeBackend(lambda _r: verdict_json(verdict="allow"))
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        payload(tool, tool_input),
        mode=mode,
        policy=POLICY,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": HOME},
        home=HOME,
        scan_disk=False,
        auditor=Auditor(POLICY.llm_audit, backend),
    )
    return decision, backend


DEVICE_PATHS = [
    # reach a network share, a volume or a service with no share or drive in the key's first place
    "\\\\.\\GLOBALROOT\\Device\\Mup\\srv\\share\\x",
    "\\\\?\\GLOBALROOT\\Device\\Mup\\srv\\share\\x",
    "\\??\\GLOBALROOT\\Device\\Mup\\srv\\share\\x",
    "\\\\?\\Volume{1234}\\x",
    "\\\\?\\Volume{1234}",
    "\\\\.\\HarddiskVolume1\\x",
    "\\\\.\\pipe\\x",
    "//./pipe/x",
    "\\\\.\\foo\\..\\pipe\\x",
    # hardware and the console, by the prefix and by the bare DOS name
    "\\\\.\\COM1",
    "COM1",
    "\\\\.\\CON",
    "CON",
    # not NUL itself: something under it
    "\\\\.\\NUL\\x",
    # ... or a file with the key of NUL. All of them are ordinary files to Windows 11 (build 26200),
    # and the key hides where they are, from the rules and from the model
    "nul.txt",
    "nul.bat",
    "NUL.tar.gz",
    "nul .txt",
    "nul:x",
    "nul:x.bat",
    "C:\\proj\\nul.txt",
    "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\nul.bat",
    "\\\\srv\\share\\nul",
    "\\\\srv\\share\\nul.txt",
    "\\\\.\\nul.txt",
    "\\\\.\\foo\\..\\NUL",
    # the same for the other names
    "aux.py",
    "src/con.py",
    "C:\\proj\\aux",
    "C:\\proj\\com1.txt",
    "\\\\srv\\share\\aux.txt",
    # the volume itself: nothing after the drive
    "\\\\.\\C:",
    "\\\\?\\C:",
    "\\??\\C:",
    "//./C:",
    "\\\\.\\D:",
    "\\\\.\\C:.",
    "\\\\.\\foo\\..\\C:",
]


@pytest.mark.parametrize("raw", DEVICE_PATHS)
@pytest.mark.parametrize(
    ("tool", "extra"), [("Read", {}), ("Write", {"content": "x"}), ("Edit", {"old_string": "a"})]
)
def test_a_device_path_is_asked_without_the_model(
    raw: str, tool: str, extra: dict[str, str]
) -> None:
    decision, backend = decide(tool, {"file_path": raw, **extra})
    assert decision.decided_by == DEVICE
    assert decision.decision == protocol.DECISION_ASK
    assert backend.requests == []


@pytest.mark.parametrize(
    "command",
    [
        "cat '\\\\.\\pipe\\x'",
        "cat //./pipe/x",
        "foo '\\\\.\\pipe\\x'",
        "foo //./GLOBALROOT/Device/Mup/srv/share/x",
        "foo --out='\\\\.\\pipe\\x'",
        "foo > '\\\\.\\pipe\\x'",
        "foo '\\\\.\\pipe\\x' 2>NUL",
        "foo a.txt '\\\\.\\pipe\\x'",
        "foo a.txt && bar '\\\\.\\pipe\\x'",
        "dd if=x of='\\\\.\\C:'",
        "dd if='\\\\.\\C:' of=x",
    ],
)
def test_a_device_path_in_a_shell_command(command: str) -> None:
    decision, backend = decide("Bash", {"command": command})
    assert decision.decided_by == DEVICE
    assert decision.decision == protocol.DECISION_ASK
    assert backend.requests == []


@pytest.mark.skipif(sys.platform != "win32", reason="needs the PowerShell parser helper")
@pytest.mark.parametrize(
    "command",
    [
        "Get-Content '\\\\.\\pipe\\x'",
        "Get-Content '\\\\.\\C:'",
        "foo '\\\\.\\pipe\\x'",
        "foo '\\\\?\\GLOBALROOT\\Device\\Mup\\srv\\share\\x'",
    ],
)
def test_a_device_path_in_powershell(command: str) -> None:
    decision, backend = decide("PowerShell", {"command": command})
    assert decision.decided_by == DEVICE
    assert decision.decision == protocol.DECISION_ASK
    assert backend.requests == []


# --- what stays the model's to judge ------------------------------------------------------------


REALLY_NUL = [
    "NUL",
    "nul",
    "Nul",
    "nul.",
    "nul ",
    "C:\\proj\\NUL",
    "C:\\proj\\sub\\nul",
    "src/nul",
    "..\\nul",
    "\\\\.\\NUL",
    "\\\\?\\NUL",
    "\\??\\nul",
    "//./nul",
]


@pytest.mark.parametrize("raw", REALLY_NUL)
def test_nul_still_goes_to_the_model(raw: str) -> None:
    decision, backend = decide("Read", {"file_path": raw})
    assert decision.decided_by == "llm"
    assert len(backend.requests) == 1


@pytest.mark.skipif(sys.platform != "win32", reason="asks Win32")
@pytest.mark.parametrize("raw", REALLY_NUL)
def test_what_is_exempt_is_nul_to_win32(raw: str) -> None:
    # GetFullPathNameW is lexical: it touches neither the disk nor the network
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    kernel32.GetFullPathNameW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_ulong,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
    ]
    kernel32.GetFullPathNameW.restype = ctypes.c_ulong
    buffer = ctypes.create_unicode_buffer(4096)
    assert kernel32.GetFullPathNameW(raw, 4096, buffer, None) > 0
    assert buffer.value.casefold() in ("\\\\.\\nul", "\\\\?\\nul")


@pytest.mark.parametrize(
    "command",
    [
        "foo > NUL",
        "foo 2>NUL",
        "foo < NUL",
        "foo > nul 2>&1",
        "cp a.txt NUL",
        "foo > /dev/null",
        "foo 2>/dev/null",
    ],
)
def test_a_redirect_to_nul_still_goes_to_the_model(command: str) -> None:
    decision, backend = decide("Bash", {"command": command})
    assert decision.decided_by == "llm"
    assert len(backend.requests) == 1


@pytest.mark.skipif(sys.platform != "win32", reason="needs the PowerShell parser helper")
@pytest.mark.parametrize("command", ["foo > NUL", "foo 2>NUL", "foo > $null"])
def test_a_redirect_to_nul_in_powershell_still_goes_to_the_model(command: str) -> None:
    decision, backend = decide("PowerShell", {"command": command})
    assert decision.decided_by != DEVICE
    assert len(backend.requests) == 1


@pytest.mark.parametrize(
    "command",
    [
        "ps aux",
        "foo aux",
        "foo con",
        "foo com1",
        "make con",
        "npm run aux",
        "echo con",
        "python x.py con",
        "python x.py --mode aux",
        "foo --name=con",
    ],
)
def test_a_word_that_names_a_device_is_not_a_device_path(command: str) -> None:
    decision, backend = decide("Bash", {"command": command})
    assert decision.decided_by == "llm"
    assert len(backend.requests) == 1


@pytest.mark.parametrize(
    "raw",
    [
        "C:\\",  # a directory, plainly
        "\\\\.\\C:\\",  # the root directory of the volume, not the volume
        "\\\\?\\C:\\",
        "D:\\data\\x.txt",
        "\\\\.\\D:\\data\\x.txt",
    ],
)
def test_a_drive_with_a_path_is_not_a_device(raw: str) -> None:
    decision, backend = decide("Read", {"file_path": raw})
    assert decision.decided_by == "llm"
    assert len(backend.requests) == 1


# --- rules come first, and nothing else moves -----------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "tool_input", "decided_by", "verdict"),
    [
        (
            "Read",
            {"file_path": "\\\\.\\PhysicalDrive0"},
            "rule:no-raw-disk-access",
            protocol.DECISION_DENY,
        ),
        (
            "Read",
            {"file_path": "\\\\.\\UNC\\srv\\share\\x"},
            "rule:net-allowlist",
            protocol.DECISION_ASK,
        ),
        (
            "Bash",
            {"command": "rm -rf '\\\\.\\C:'"},
            "rule:rm-outside-project",
            protocol.DECISION_DENY,
        ),
    ],
)
def test_rules_still_decide_first(
    tool: str, tool_input: dict[str, Any], decided_by: str, verdict: str
) -> None:
    decision, backend = decide(tool, tool_input)
    assert decision.decided_by == decided_by
    assert decision.decision == verdict
    assert backend.requests == []


def test_a_project_file_is_still_allowed_by_its_rule() -> None:
    decision, backend = decide("Read", {"file_path": "C:\\proj\\a.txt"})
    assert decision.decided_by == "rule:read-inside-project"
    assert backend.requests == []


def test_without_a_backend_nothing_changes() -> None:
    policy = parse_policy_text(default_policy_text(), home=HOME)
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        payload("Read", {"file_path": "\\\\.\\pipe\\x"}),
        mode="enforce",
        policy=policy,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": HOME},
        home=HOME,
        scan_disk=False,
    )
    assert decision.decision == protocol.DECISION_ASK
    assert decision.decided_by != DEVICE
    assert decision.llm is None


def test_audit_only_records_what_enforce_would_do_and_sends_nothing() -> None:
    decision, backend = decide("Read", {"file_path": "\\\\.\\pipe\\x"}, mode="audit-only")
    assert decision.decision == protocol.DECISION_NONE
    assert decision.would_be == protocol.DECISION_ASK
    assert decision.llm is not None
    assert decision.llm["detail"] == "device-path"
    assert backend.requests == []


def test_the_reason_and_the_record_do_not_carry_the_path() -> None:
    # They go into the audit log, which holds only what went through the send gate or was cleaned
    decision, _ = decide("Read", {"file_path": "\\\\.\\pipe\\a-name-of-the-callers"})
    assert "not sent to the LLM audit" in decision.reason
    assert "a-name-of-the-callers" not in decision.reason
    assert decision.llm is not None
    assert decision.llm["outcome"] == "not-sent"
    assert "a-name-of-the-callers" not in json.dumps(dict(decision.llm))


def _run_in_tainted_session(store: SessionStore, tool_input: dict[str, Any]) -> pipeline.Decision:
    """The verdict on a shell call, and its PostToolUse: the call was approved and ran."""
    call = {**payload("Bash", tool_input), "tool_use_id": "toolu_1"}
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        call,
        mode="enforce",
        policy=POLICY,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": HOME},
        home=HOME,
        scan_disk=False,
        auditor=Auditor(POLICY.llm_audit, FakeBackend(lambda _r: verdict_json(verdict="allow"))),
        session=store,
    )
    pipeline.decide(
        protocol.EVENT_POST,
        {**call, "hook_event_name": "PostToolUse"},
        mode="enforce",
        policy=POLICY,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": HOME},
        home=HOME,
        session=store,
    )
    return decision


@pytest.mark.parametrize(
    ("command", "decided_by", "counted"),
    [
        ("foo '\\\\.\\pipe\\x'", DEVICE, 0),  # asked because of the device, not the taint
        ("foo a.txt", "llm", 1),  # the comparison: an ask the taint step made is counted
    ],
)
def test_only_the_taint_steps_own_asks_use_up_the_window(
    tmp_path: Path, command: str, decided_by: str, counted: int
) -> None:
    store = SessionStore(str(tmp_path / "session.sqlite"))
    try:
        store.source_seen("s", "WebFetch")
        decision = _run_in_tainted_session(store, {"command": command})
        assert decision.decided_by == decided_by
        assert decision.decision == protocol.DECISION_ASK
        assert store.facts("s", window=3).taint_asks == counted
    finally:
        store.close()
