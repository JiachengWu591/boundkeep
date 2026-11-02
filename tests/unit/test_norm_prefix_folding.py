"""Prefixed paths whose first component only shows after folding (``\\\\.\\foo\\..\\UNC\\srv\\s``).

Win32 folds ``.`` and ``..`` and empty components of the whole tail before it reads the first one,
and the prefix is the only root. Reading the first component as written gave these a device key, so
rules about network shares and home files did not match them; with an LLM backend the model could
then allow what the rule asks about. The keys are in ``test_norm_paths.LEXICAL``; here is what Win32
says about them, and what the rules do with them.
"""

from __future__ import annotations

import ctypes
import re
import sys
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.audit.auditor import Auditor
from boundkeep.audit.backends.base import verdict_json
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.normalize.paths import normalize_path
from boundkeep.policy import Policy, default_policy_text, parse_policy_text

HOME = "C:\\Users\\bob"
PROJECT = "C:\\proj"
LLM_BLOCK = (
    "  backend: openai_compatible\n"
    "  openai_compatible:\n"
    "    base_url: https://llm.example.invalid/v1\n"
    "    model: test-model\n"
)
NET_RULE = "rule:net-allowlist"


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


def decide(tool: str, tool_input: dict[str, Any]) -> tuple[pipeline.Decision, FakeBackend]:
    """The verdict with a backend that allows whatever it is shown, and that backend."""
    backend = FakeBackend(lambda _r: verdict_json(verdict="allow"))
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "s",
        "cwd": PROJECT,
        "project_dir": PROJECT,
        "tool_name": tool,
        "tool_input": tool_input,
    }
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        payload,
        mode="enforce",
        policy=POLICY,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": HOME},
        home=HOME,
        scan_disk=False,
        auditor=Auditor(POLICY.llm_audit, backend),
    )
    return decision, backend


UNC_SPELLINGS = [
    "\\\\.\\foo\\..\\UNC\\srv\\share\\x",
    "\\\\.\\foo\\bar\\..\\..\\UNC\\srv\\share\\x",
    "\\\\.\\.\\UNC\\srv\\share\\x",
    "\\\\.\\\\UNC\\srv\\share\\x",
    "//./foo/../UNC/srv/share/x",
    "\\\\.\\UNC.\\srv\\share\\x",
    "\\\\.\\UNC:x\\srv\\share\\x",
    "\\\\?\\\\\\.\\UNC\\srv\\share\\x",
    "\\\\?\\foo\\..\\UNC\\srv\\share\\x",
    "\\??\\foo\\..\\UNC\\srv\\share\\x",
    "\\\\.\\UNC\\other\\..\\srv\\share\\x",
]


@pytest.mark.parametrize("raw", ["\\\\srv\\share\\x", "\\\\.\\UNC\\srv\\share\\x", *UNC_SPELLINGS])
@pytest.mark.parametrize(
    ("tool", "extra"), [("Read", {}), ("Write", {"content": "x"}), ("Edit", {"old_string": "a"})]
)
def test_a_share_behind_folding_is_the_network_rules_question(
    raw: str, tool: str, extra: dict[str, str]
) -> None:
    decision, backend = decide(tool, {"file_path": raw, **extra})
    assert decision.decided_by == NET_RULE
    assert decision.decision == protocol.DECISION_ASK
    assert backend.requests == []


@pytest.mark.parametrize(
    "command",
    [
        "cat '\\\\.\\foo\\..\\UNC\\srv\\share\\x'",
        "cat '//./foo/../UNC/srv/share/x'",
    ],
)
def test_a_share_behind_folding_in_a_shell_command(command: str) -> None:
    decision, backend = decide("Bash", {"command": command})
    assert decision.decided_by == NET_RULE
    assert decision.decision == protocol.DECISION_ASK
    assert backend.requests == []


@pytest.mark.parametrize(
    "raw",
    [
        "\\\\.\\foo\\..\\C:\\Users\\bob\\.claude\\settings.json",
        "\\\\.\\.\\C:\\Users\\bob\\.claude\\settings.json",
        "\\\\.\\\\C:\\Users\\bob\\.claude\\settings.json",
        "\\\\.\\C:.\\Users\\bob\\.claude\\settings.json",
        "\\\\.\\D:\\..\\C:\\Users\\bob\\.claude\\settings.json",
    ],
)
def test_a_drive_behind_folding_reaches_the_rules_of_its_file(raw: str) -> None:
    plain, _ = decide(
        "Write", {"file_path": "C:\\Users\\bob\\.claude\\settings.json", "content": "x"}
    )
    assert plain.decided_by.startswith("rule:")

    decision, backend = decide("Write", {"file_path": raw, "content": "x"})
    assert decision.decision == plain.decision
    assert decision.decided_by == plain.decided_by
    assert backend.requests == []


def test_a_folded_drive_is_not_the_project_it_looks_like() -> None:
    # Win32 reads this as the device "proj": the key must not say it is inside C:\proj
    decision, _ = decide("Read", {"file_path": "\\\\.\\C:\\..\\proj\\a.txt"})
    assert decision.decided_by != "rule:read-inside-project"


@pytest.mark.parametrize(
    "raw",
    [
        "\\\\.\\foo\\..\\C:\\proj\\a.txt",
        "\\\\.\\C:\\proj\\sub\\..\\a.txt",
        "\\\\.\\\\C:\\proj\\a.txt",
        "\\\\.\\C:.\\proj\\a.txt",
    ],
)
def test_an_odd_spelling_of_a_project_file_is_never_allowed_by_a_rule(raw: str) -> None:
    decision, _ = decide("Read", {"file_path": raw})
    assert decision.decided_by != "rule:read-inside-project"


@pytest.mark.parametrize(
    "raw", ["C:\\proj\\a.txt", "\\\\.\\C:\\proj\\a.txt", "\\\\?\\C:\\proj\\a.txt"]
)
def test_the_plain_spellings_of_a_project_file_stay_allowed(raw: str) -> None:
    decision, backend = decide("Read", {"file_path": raw})
    assert decision.decided_by == "rule:read-inside-project"
    assert backend.requests == []


# --- what Win32 says ----------------------------------------------------------------------------

AGREES_WITH_WIN32 = [
    "\\\\.\\foo\\..\\UNC\\srv\\share\\x",
    "\\\\.\\foo\\bar\\..\\..\\UNC\\srv\\share\\x",
    "\\\\.\\.\\UNC\\srv\\share\\x",
    "\\\\.\\\\UNC\\srv\\share\\x",
    "//./foo/../UNC/srv/share/x",
    "\\\\.\\UNC.\\srv\\share\\x",
    "\\\\.\\UNC\\other\\..\\srv\\share\\x",
    "\\\\.\\UNC\\srv\\share\\..\\x",
    "\\\\.\\UNC\\..\\foo",
    "\\\\.\\foo\\..\\C:\\Users\\bob",
    "\\\\.\\.\\C:\\Users\\bob",
    "\\\\.\\\\C:\\Users\\bob",
    "\\\\.\\C:.\\Users\\bob",
    "\\\\.\\C:\\..\\foo",
    "\\\\.\\C:\\..\\D:\\x",
    "\\\\.\\C:\\proj\\..\\x",
    "\\\\.\\foo\\..\\NUL",
    "\\\\.\\foo\\..\\pipe\\x",
    "\\\\.\\foo\\..",
    # no folding at all
    "\\\\.\\UNC\\srv\\share\\x",
    "\\\\.\\C:\\Users\\bob",
    "\\\\.\\pipe\\x",
]


def _key(raw: str) -> str:
    return normalize_path(raw, cwd=PROJECT, home=HOME, env={}, dialect="tool").key


@pytest.mark.skipif(sys.platform != "win32", reason="asks Win32")
@pytest.mark.parametrize("raw", AGREES_WITH_WIN32)
def test_the_key_says_what_win32_says(raw: str) -> None:
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
    assert _key(raw) == _key(buffer.value)
