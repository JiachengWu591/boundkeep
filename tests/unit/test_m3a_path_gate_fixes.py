"""The findings of the path gate review that revision 11 fixes (reviews/M3a-path-gate-review.md).

``GetFullPathNameW`` is not what opening a path does: it strips the dots a ``\\\\?\\`` path keeps
and calls ``\\\\.\\C:\\x\\nul`` NUL. So the Windows checks here ask for the NT path ``CreateFileW``
is handed (``RtlDosPathNameToNtPathName_U_WithStatus``), which opens nothing. Every verdict uses a
fake backend that allows whatever it is shown.
"""

from __future__ import annotations

import ctypes
import os
import re
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.audit.auditor import Auditor
from boundkeep.audit.backends.base import verdict_json
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.normalize import paths
from boundkeep.normalize.paths import NormPath, normalize_path, resolve_on_disk
from boundkeep.policy import Policy, default_policy_text, parse_policy_text

HOME = "C:\\Users\\bob"
PROJECT = "C:\\proj"
LLM_BLOCK = (
    "  backend: openai_compatible\n"
    "  openai_compatible:\n"
    "    base_url: https://llm.example.invalid/v1\n"
    "    model: test-model"
)
DEVICE = "gray-device-path"
ENV = {"USERPROFILE": HOME, "COMPUTERNAME": "MYPC"}
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="asks Win32")


def llm_policy(text: str | None = None) -> Policy:
    new, found = re.subn(
        r"^  backend: none.*$",
        lambda _m: LLM_BLOCK,
        text if text is not None else default_policy_text(),
        count=1,
        flags=re.M,
    )
    assert found == 1
    return parse_policy_text(new, home=HOME)


POLICY = llm_policy()
NO_BACKEND = parse_policy_text(default_policy_text(), home=HOME)


def decide(
    tool: str,
    tool_input: dict[str, Any],
    *,
    policy: Policy = POLICY,
    cwd: str = PROJECT,
    scan_disk: bool = False,
    auditor: Auditor | None = None,
) -> tuple[pipeline.Decision, FakeBackend]:
    backend = FakeBackend(lambda _r: verdict_json(verdict="allow"))
    decision = pipeline.decide(
        protocol.EVENT_PRE,
        {
            "hook_event_name": "PreToolUse",
            "session_id": "s",
            "cwd": cwd,
            "project_dir": cwd,
            "tool_name": tool,
            "tool_input": tool_input,
        },
        mode="enforce",
        policy=policy,
        policy_error=None,
        platform="windows",
        env=ENV,
        home=HOME,
        scan_disk=scan_disk,
        auditor=auditor or Auditor(policy.llm_audit, backend),
    )
    return decision, backend


def norm(raw: str, *, cwd: str = PROJECT, home: str = HOME, dialect: Any = "tool") -> NormPath:
    return normalize_path(raw, cwd=cwd, home=home, env=ENV, dialect=dialect)


def nt_path(raw: str) -> str:
    """The NT path ``CreateFileW`` would be handed. Nothing is opened."""

    class Unicode(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("Max", wintypes.USHORT),
            ("Buffer", ctypes.c_void_p),
        ]

    ntdll = ctypes.WinDLL("ntdll")  # type: ignore[attr-defined,unused-ignore]
    convert = ntdll.RtlDosPathNameToNtPathName_U_WithStatus
    convert.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(Unicode),
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    convert.restype = ctypes.c_long
    ntdll.RtlFreeUnicodeString.argtypes = [ctypes.POINTER(Unicode)]
    out = Unicode()
    assert convert(raw, ctypes.byref(out), None, None) >= 0, raw
    text = ctypes.wstring_at(out.Buffer, out.Length // 2)
    ntdll.RtlFreeUnicodeString(ctypes.byref(out))
    return text


# --- G-1: the NUL exemption -----------------------------------------------------------------------


EXEMPT = [
    "NUL",
    "nul",
    "Nul",
    "nul.",
    "nul ",
    "nul...",
    "\\\\.\\NUL",
    "\\\\?\\NUL",
    "\\??\\nul",
    "//./nul",
    "//?/nul",
]
NOT_EXEMPT = [
    # a directory or a drive: what is there may be an ordinary file named nul
    "C:\\proj\\NUL",
    "C:\\proj\\sub\\nul",
    "C:\\Users\\bob\\.ssh\\nul",
    "src/nul",
    "..\\nul",
    ".\\nul",
    # a prefix and a drive: the NT path is that file
    "\\\\.\\C:\\Users\\bob\\.ssh\\nul",
    "\\\\?\\C:\\Users\\bob\\.ssh\\nul",
    "\\??\\C:\\Users\\bob\\.ssh\\nul",
    "//./C:/Users/bob/.ssh/nul",
    "//?/C:/Users/bob/.ssh/nul",
    "\\\\?\\C:\\proj\\nul.",
    # ordinary to Win32, no prefix at all
    "C:\\Users\\bob\\.ssh\\nul\\.",
    "C:\\Users\\bob\\.ssh\\nul\\",
    "nul\\",
    "nul.\\",
    # literal: this is not the device
    "\\\\?\\nul.",
    # not the name
    "nul.txt",
    "nul:x",
    "\\\\srv\\share\\nul",
    "\\\\.\\NUL\\x",
    "\\\\.\\foo\\..\\NUL",
    "$HOME/nul",
    "%TEMP%\\nul",
    "~/nul",
    "C:\\pro?\\nul",
    "C:nul",
    "\\nul",
]


@pytest.mark.parametrize("raw", EXEMPT)
def test_a_shell_command_may_use_nul_itself(raw: str) -> None:
    decision, backend = decide("Bash", {"command": f"foo > '{raw}'"})
    assert decision.decided_by == "llm"
    assert len(backend.requests) == 1


@windows_only
@pytest.mark.parametrize("raw", EXEMPT)
def test_what_is_exempt_is_nul_when_opened(raw: str) -> None:
    assert nt_path(raw).casefold() == "\\??\\nul"


@pytest.mark.parametrize("raw", NOT_EXEMPT)
def test_any_other_spelling_is_not_exempt_in_a_shell_command(raw: str) -> None:
    decision, backend = decide("Bash", {"command": f"foo > '{raw}'"})
    assert decision.decision == protocol.DECISION_ASK
    assert backend.requests == []


@pytest.mark.parametrize(
    "raw", ["NUL", "nul", "\\\\.\\NUL", "C:\\proj\\nul", "C:\\Users\\bob\\.ssh\\nul\\."]
)
@pytest.mark.parametrize(
    ("tool", "extra"), [("Read", {}), ("Write", {"content": "x"}), ("Edit", {"old_string": "a"})]
)
def test_a_file_tool_gets_no_exemption(raw: str, tool: str, extra: dict[str, str]) -> None:
    decision, backend = decide(tool, {"file_path": raw, **extra})
    assert decision.decided_by == DEVICE
    assert decision.decision == protocol.DECISION_ASK
    assert backend.requests == []


@windows_only
@pytest.mark.parametrize(
    "raw",
    [
        "\\\\.\\C:\\Users\\bob\\.ssh\\nul",
        "\\\\?\\C:\\Users\\bob\\.ssh\\nul",
        "\\??\\C:\\Users\\bob\\.ssh\\nul",
        "C:\\Users\\bob\\.ssh\\nul\\.",
    ],
)
def test_win32_keeps_the_directory_of_a_file_named_nul(raw: str) -> None:
    assert nt_path(raw).casefold() == "\\??\\c:\\users\\bob\\.ssh\\nul"


def test_the_model_never_answers_for_such_a_file_from_the_cache_of_nul() -> None:
    backend = FakeBackend(lambda _r: verdict_json(verdict="allow"))
    auditor = Auditor(POLICY.llm_audit, backend)
    first, _ = decide("Bash", {"command": "foo > NUL"}, auditor=auditor)
    second, _ = decide("Bash", {"command": "foo > '\\\\.\\C:\\x\\nul'"}, auditor=auditor)
    assert first.decided_by == "llm"
    assert second.decided_by == DEVICE
    assert len(backend.requests) == 1


def test_on_failure_does_not_touch_the_gate_or_nul() -> None:
    # T-2 of the review: asking here is not an audit failure
    text, found = re.subn(
        r"^  on_failure: ask\b", "  on_failure: deny", default_policy_text(), flags=re.M
    )
    assert found == 1
    policy = llm_policy(text)
    decision, backend = decide("Read", {"file_path": "\\\\.\\pipe\\x"}, policy=policy)
    assert decision.decision == protocol.DECISION_ASK
    assert decision.decided_by == DEVICE
    assert backend.requests == []
    decision, backend = decide("Bash", {"command": "foo > NUL"}, policy=policy)
    assert decision.decided_by == "llm"
    assert len(backend.requests) == 1


# --- G-2: a trailing dot that may not go away -----------------------------------------------------


UNSURE_DOTS = [
    # literal characters under \\?\ and \??\: the directory is really "proj."
    "\\\\?\\C:\\proj.\\a.txt",
    "\\??\\C:\\proj.\\a.txt",
    "\\\\?\\C:\\proj \\a.txt",
    "\\\\?\\C:\\proj\\sub.\\a.txt",
    # the last component too: its name is really "a.txt."
    "\\\\?\\C:\\proj\\a.txt.",
    "\\??\\C:\\proj\\a.txt ",
    # Win32 strips one dot of a middle component here, Node none (measured with fs.readFileSync)
    "C:\\proj.\\a.txt",
    "c:\\PROJ.\\a.txt",
    "C:\\proj\\sub.\\a.txt",
    "\\\\.\\C:\\proj.\\a.txt",
    "//?/C:/proj./a.txt",
    # the last component without a prefix: revision 12, see test_m3a_dots_and_folding.py
    "C:\\proj\\a.txt.",
    "C:\\proj\\a.txt ",
]


@pytest.mark.parametrize("raw", UNSURE_DOTS)
def test_a_trailing_dot_that_may_stay_is_uncertain(raw: str) -> None:
    assert norm(raw).uncertain


@pytest.mark.parametrize("raw", UNSURE_DOTS)
@pytest.mark.parametrize(("tool", "extra"), [("Read", {}), ("Write", {"content": "x"})])
def test_no_rule_allows_a_trailing_dot_that_may_stay(
    raw: str, tool: str, extra: dict[str, str]
) -> None:
    decision, _ = decide(tool, {"file_path": raw, **extra}, policy=NO_BACKEND)
    assert decision.decision == protocol.DECISION_ASK


@pytest.mark.parametrize(
    "raw", ["\\\\?\\C:\\proj.\\a.txt", "\\??\\C:\\proj.\\a.txt", "\\\\?\\C:\\proj\\sub.\\a.txt"]
)
def test_literal_dots_are_never_inside_the_project(raw: str) -> None:
    assert paths.inside_project(norm(raw), norm(PROJECT)) is None


@windows_only
@pytest.mark.parametrize(
    ("raw", "opened"),
    [
        ("\\\\?\\C:\\proj.\\a.txt", "\\??\\C:\\proj.\\a.txt"),
        ("\\??\\C:\\proj.\\a.txt", "\\??\\C:\\proj.\\a.txt"),
        ("\\\\?\\C:\\proj\\a.txt.", "\\??\\C:\\proj\\a.txt."),
    ],
)
def test_win32_keeps_the_literal_dot(raw: str, opened: str) -> None:
    assert nt_path(raw) == opened


@pytest.mark.parametrize(
    ("raw", "key"),
    [
        ("C:\\proj\\a.txt", "c:/proj/a.txt"),
        ("\\\\?\\C:\\proj\\a.txt", "c:/proj/a.txt"),
        ("\\\\.\\C:\\proj\\a.b.txt", "c:/proj/a.b.txt"),
        ("C:\\proj\\.hidden\\x", "c:/proj/.hidden/x"),
    ],
)
def test_other_dots_stay_certain(raw: str, key: str) -> None:
    got = norm(raw)
    assert got.key == key
    assert not got.uncertain


@windows_only
def test_a_real_directory_with_a_trailing_dot_is_not_allowed(tmp_path: Path) -> None:
    base = "\\\\?\\" + str(tmp_path)
    project, outside = str(tmp_path / "proj"), base + "\\proj."
    os.mkdir(project)
    os.mkdir(outside)
    target = outside + "\\data.txt"
    try:
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("outside the project")
        assert os.listdir(project) == []
        with open(target, encoding="utf-8") as handle:
            assert handle.read() == "outside the project"
        decision, _ = decide(
            "Read", {"file_path": target}, policy=NO_BACKEND, cwd=project, scan_disk=True
        )
        assert decision.decision == protocol.DECISION_ASK
    finally:
        if os.path.exists(target):
            os.remove(target)
        os.rmdir(outside)


# --- G-3: a pipe through a UNC name ---------------------------------------------------------------


LOCAL_PIPES = [
    "\\\\localhost\\pipe\\x",
    "//localhost/pipe/x",
    "\\\\127.0.0.1\\pipe\\x",
    "\\\\?\\UNC\\localhost\\pipe\\x",
    "\\\\.\\UNC\\127.0.0.1\\pipe\\x",
    "\\\\MYPC\\pipe\\x",
    "\\\\localhost\\PIPE\\x",
    "\\\\localhost\\pipe",
    "\\\\localhost\\mailslot\\x",
    "\\\\localhost\\IPC$\\x",
    "\\\\127.0.0.1\\ipc$",
    # the allowlist is about hosts: this is still not a file
    "\\\\pypi.org\\pipe\\x",
]


@pytest.mark.parametrize("raw", LOCAL_PIPES)
@pytest.mark.parametrize(("tool", "extra"), [("Read", {}), ("Write", {"content": "x"})])
def test_a_pipe_through_a_unc_name_is_not_sent(raw: str, tool: str, extra: dict[str, str]) -> None:
    decision, backend = decide(tool, {"file_path": raw, **extra})
    assert decision.decided_by == DEVICE
    assert decision.decision == protocol.DECISION_ASK
    assert backend.requests == []


@pytest.mark.parametrize(
    "raw", ["\\\\127.1\\pipe\\x", "\\\\0x7f.0.0.1\\pipe\\x", "\\\\2130706433\\pipe\\x"]
)
def test_a_pipe_on_another_spelling_of_this_machine_is_not_sent(raw: str) -> None:
    decision, backend = decide("Read", {"file_path": raw})
    assert decision.decision == protocol.DECISION_ASK
    assert backend.requests == []


@pytest.mark.parametrize(
    "command",
    [
        "foo > '\\\\localhost\\pipe\\x'",
        "cat '\\\\localhost\\pipe\\x'",
        "cat //127.0.0.1/pipe/x",
    ],
)
def test_a_pipe_through_a_unc_name_in_a_shell_command(command: str) -> None:
    decision, backend = decide("Bash", {"command": command})
    assert decision.decided_by == DEVICE
    assert backend.requests == []


@pytest.mark.skipif(sys.platform != "win32", reason="needs the PowerShell parser helper")
@pytest.mark.parametrize(
    "command", ["Get-Content '\\\\localhost\\pipe\\x'", "Test-Path '\\\\localhost\\pipe\\x'"]
)
def test_a_pipe_through_a_unc_name_in_powershell(command: str) -> None:
    decision, backend = decide("PowerShell", {"command": command})
    assert decision.decided_by == DEVICE
    assert backend.requests == []


@pytest.mark.parametrize(
    "raw",
    [
        "\\\\127.0.0.1\\share\\x",  # the key says where it is
        "\\\\localhost\\pipes\\x",
        "\\\\localhost\\share\\pipe\\x",
        "\\\\wsl$\\Ubuntu\\pipe\\x",
    ],
)
def test_an_ordinary_local_share_still_goes_to_the_model(raw: str) -> None:
    decision, backend = decide("Read", {"file_path": raw})
    assert decision.decided_by == "llm"
    assert len(backend.requests) == 1


def test_a_remote_pipe_is_still_the_network_rule() -> None:
    decision, backend = decide("Read", {"file_path": "\\\\srv\\pipe\\x"})
    assert decision.decided_by == "rule:net-allowlist"
    assert backend.requests == []


# --- G-4: a link to a device, and looking at where a link leads -----------------------------------


@pytest.fixture
def fake_link(monkeypatch: pytest.MonkeyPatch) -> Any:
    """``E:\\proj\\link.txt`` leads to the given target. ``os.stat`` only records: no real link is
    made, and nothing is opened."""
    stats: list[str] = []

    def install(target: str) -> list[str]:
        monkeypatch.setattr(paths, "_drive_type", lambda _letter: paths._DRIVE_FIXED)
        monkeypatch.setattr(paths.os.path, "realpath", lambda _p, **_k: target)

        def fake_stat(path: Any, *_a: Any, **_k: Any) -> os.stat_result:
            stats.append(str(path))
            raise OSError("not looked at")

        monkeypatch.setattr(paths.os, "stat", fake_stat)
        return stats

    return install


LINK = "E:\\proj\\link.txt"
CWD = "E:\\proj"


@windows_only
@pytest.mark.parametrize(
    ("target", "key"),
    [
        ("\\\\.\\pipe\\x", "//./pipe/x"),
        ("\\\\?\\Volume{1234}\\x", "//./volume{1234}/x"),
        ("\\\\?\\GLOBALROOT\\Device\\Mup\\srv\\share\\x", "//./globalroot/device/mup/srv/share/x"),
    ],
)
def test_a_link_to_a_device_has_the_key_of_the_device(
    fake_link: Any, target: str, key: str
) -> None:
    fake_link(target)
    got = resolve_on_disk(norm(LINK, cwd=CWD))
    assert got.key == key
    assert got.is_device
    assert got.uncertain
    assert got.raw == LINK
    assert "resolved-on-disk" in got.reasons


@windows_only
def test_a_link_to_a_device_is_not_allowed_or_sent(fake_link: Any) -> None:
    fake_link("\\\\.\\pipe\\x")
    decision, backend = decide("Read", {"file_path": LINK}, cwd=CWD, scan_disk=True)
    assert decision.decided_by == DEVICE
    assert decision.decision == protocol.DECISION_ASK
    assert backend.requests == []


@windows_only
def test_a_link_to_nul_is_not_exempt(fake_link: Any) -> None:
    fake_link("\\\\.\\nul")
    decision, backend = decide("Bash", {"command": "cat link.txt"}, cwd=CWD, scan_disk=True)
    assert decision.decision == protocol.DECISION_ASK
    assert backend.requests == []


@windows_only
def test_a_link_to_a_physical_disk_is_denied(fake_link: Any) -> None:
    fake_link("\\\\.\\PhysicalDrive0")
    decision, _ = decide("Read", {"file_path": LINK}, cwd=CWD, scan_disk=True)
    assert decision.decided_by == "rule:no-raw-disk-access"
    assert decision.decision == protocol.DECISION_DENY


@windows_only
def test_where_a_link_leads_is_not_looked_at_over_the_network(fake_link: Any) -> None:
    stats = fake_link("\\\\srv\\share\\x")
    decision, _ = decide("Read", {"file_path": LINK}, cwd=CWD, scan_disk=True)
    assert decision.decided_by == "rule:net-allowlist"
    assert stats == []


@windows_only
def test_a_link_to_a_network_drive_is_not_looked_at(
    fake_link: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    stats = fake_link("Z:\\x")
    monkeypatch.setattr(
        paths, "_drive_type", lambda letter: 4 if letter.lower() == "z" else paths._DRIVE_FIXED
    )
    got = resolve_on_disk(norm(LINK, cwd=CWD))
    assert got.key == "z:/x"
    assert stats == []


@windows_only
def test_a_link_to_a_local_file_is_still_checked_for_hard_links(fake_link: Any) -> None:
    stats = fake_link("D:\\x")
    got = resolve_on_disk(norm(LINK, cwd=CWD))
    assert got.key == "d:/x"
    assert stats == ["D:\\x"]


# --- G-5: which looks a path up -------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "which //srv/share/x",
        "which -a //srv/share/x",
        "which '\\\\srv\\share\\x'",
        "which python3 //srv/share/x",
    ],
)
@pytest.mark.parametrize("policy", [POLICY, NO_BACKEND], ids=["backend", "no-backend"])
def test_which_with_a_network_path_is_the_network_rule(command: str, policy: Policy) -> None:
    decision, backend = decide("Bash", {"command": command}, policy=policy)
    assert decision.decided_by.startswith("rule:net-allowlist")
    assert decision.decision == protocol.DECISION_ASK
    assert backend.requests == []


@pytest.mark.parametrize(
    "command",
    [
        "which '\\\\.\\pipe\\x'",
        "which //./pipe/x",
        "which //./GLOBALROOT/Device/Mup/srv/share/x",
        "which '\\\\localhost\\pipe\\x'",
    ],
)
@pytest.mark.parametrize("policy", [POLICY, NO_BACKEND], ids=["backend", "no-backend"])
def test_which_with_a_device_path_asks(command: str, policy: Policy) -> None:
    decision, backend = decide("Bash", {"command": command}, policy=policy)
    assert decision.decision == protocol.DECISION_ASK
    assert backend.requests == []


@pytest.mark.parametrize(
    "command", ["which python3", "which -a git", "which ./x", "which C:/Windows/notepad.exe"]
)
def test_which_with_anything_else_is_still_allowed(command: str) -> None:
    decision, backend = decide("Bash", {"command": command})
    assert decision.decided_by == "rule:allow-no-path-commands"
    assert backend.requests == []


# --- G-9: a drive that is not a letter ------------------------------------------------------------


@pytest.mark.parametrize(
    "raw", ["1:\\credentials", "1:/credentials", "é:\\credentials", "1:\\x\\y"]
)
def test_a_drive_that_is_not_a_letter_is_uncertain(raw: str) -> None:
    got = norm(raw)
    assert got.uncertain
    assert "non-letter-drive" in got.reasons
    assert paths.inside_project(got, norm(PROJECT)) is None


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Read", {"file_path": "1:\\credentials"}),
        ("Read", {"file_path": "é:\\credentials"}),
        ("Write", {"file_path": "1:\\settings.json", "content": "x"}),
        ("Bash", {"command": "cat '1:\\credentials'"}),
    ],
)
def test_no_rule_allows_a_drive_that_is_not_a_letter(tool: str, tool_input: dict[str, str]) -> None:
    decision, _ = decide(tool, tool_input, policy=NO_BACKEND)
    assert decision.decision == protocol.DECISION_ASK


@windows_only
def test_win32_reads_a_digit_as_a_drive() -> None:
    assert nt_path("1:\\credentials") == "\\??\\1:\\credentials"


@pytest.mark.parametrize(
    ("raw", "key"), [("C:\\x", "c:/x"), ("a.txt:stream", "c:/proj/a.txt"), ("ab:c", "c:/proj/ab")]
)
def test_a_letter_and_a_stream_are_unchanged(raw: str, key: str) -> None:
    got = norm(raw)
    assert got.key == key
    assert not got.uncertain


def test_on_posix_a_digit_and_a_colon_are_a_name() -> None:
    got = normalize_path("1:x", cwd="/home/dev/proj", home="/home/dev", env={}, dialect="tool")
    assert got.key == "/home/dev/proj/1:x"
    assert not got.uncertain


# --- G-13: the key of an unknown start ------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "key"),
    [
        ("$FOO\\..", "$foo/.."),
        ("$FOO\\..\\a", "$foo/../a"),
        ("$FOO\\..\\..", "$foo/../.."),
        ("$FOO\\x\\..", "$foo"),
        ("~x\\..", "~x/.."),
        ("%\\..", "%/.."),
    ],
)
def test_an_unknown_start_is_not_folded_away(raw: str, key: str) -> None:
    got = norm(raw)
    assert got.key == key
    assert got.uncertain
    assert not got.absolute


@pytest.mark.parametrize(
    "raw",
    [
        "$FOO\\..",
        "$FOO/..",
        "~x\\..",
        "$FOO\\..\\a",
        "%\\..",
        "~C:\\..",
        "$FOO\\x\\..\\..\\y",
        ".//D:x",  # with no cwd: not a drive, and the key must not turn into one
        "a/../D:x",
    ],
)
@pytest.mark.parametrize("dialect", ["bash", "powershell", "tool"])
@pytest.mark.parametrize(
    ("cwd", "home"),
    [(PROJECT, HOME), ("/home/dev/proj", "/home/dev"), (None, None)],
    ids=["windows", "posix", "unknown"],
)
def test_an_unknown_start_has_a_stable_key(
    raw: str, dialect: Any, cwd: str | None, home: str | None
) -> None:
    first = normalize_path(raw, cwd=cwd, home=home, env={}, dialect=dialect)
    second = normalize_path(first.key, cwd=cwd, home=home, env={}, dialect=dialect)
    assert second.key == first.key
