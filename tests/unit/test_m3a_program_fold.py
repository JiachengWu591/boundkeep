"""Revision 14: RV-7 of the review (reviews/M3a-dots-and-folding-review.md).

``str.casefold`` merges characters NTFS keeps apart, so ``C:\\Windows`` with ``U+017F`` for its
``s`` counted as the system's directory, and ``ls`` with ``U+017F`` as ``ls``. Neither is: on NTFS
they are another directory and another file, Git Bash finds the other file through PATH, and
PowerShell 5.1 does not resolve ``Test-Path`` so spelled to the cmdlet (measured). Deny and ask
rules still read the name as casefold does. Every verdict uses a fake backend that allows whatever
it is shown; nothing is run and no file is written.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.audit.auditor import Auditor
from boundkeep.audit.backends.base import verdict_json
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.normalize import event, paths, psparse
from boundkeep.normalize.model import Action
from boundkeep.policy import Policy, default_policy_text, parse_policy_text

HOME = "C:\\Users\\bob"
PROJECT = "C:\\proj"
LLM_BLOCK = (
    "  backend: openai_compatible\n"
    "  openai_compatible:\n"
    "    base_url: https://llm.example.invalid/v1\n"
    "    model: test-model"
)
LONG_S, KELVIN, SHARP_S, FF, FI, ST = "\u017f", "\u212a", "\u00df", "\ufb00", "\ufb01", "\ufb06"
FOLD = "program-fold-variant"
QUALIFIED = "program-path-qualified"
# Every character of the basic plane casefold turns into something holding ASCII, computed here so
# that a Unicode update cannot quietly leave one out.
TO_ASCII = tuple(
    chr(code)
    for code in range(0x80, 0x10000)
    if not 0xD800 <= code < 0xE000 and any(ord(c) < 128 for c in chr(code).casefold())
)
_TEXT = default_policy_text()
NO_BACKEND = parse_policy_text(_TEXT, home=HOME)
BACKEND = parse_policy_text(
    re.sub(r"^  backend: none.*$", lambda _m: LLM_BLOCK, _TEXT, count=1, flags=re.M), home=HOME
)


@dataclass(frozen=True)
class Verdict:
    decision: str | None
    decided_by: str
    sent: tuple[str, ...]


def decide(tool: str, command: str, *, policy: Policy = NO_BACKEND) -> Verdict:
    backend = FakeBackend(lambda _r: verdict_json(verdict="allow"))
    result = pipeline.decide(
        protocol.EVENT_PRE,
        {
            "hook_event_name": "PreToolUse",
            "session_id": "s",
            "cwd": PROJECT,
            "project_dir": PROJECT,
            "tool_name": tool,
            "tool_input": {"command": command},
        },
        mode="enforce",
        policy=policy,
        policy_error=None,
        platform="windows",
        env={"USERPROFILE": HOME, "COMPUTERNAME": "MYPC"},
        home=HOME,
        scan_disk=False,
        auditor=Auditor(policy.llm_audit, backend),
    )
    return Verdict(result.decision, result.decided_by, tuple(r.content for r in backend.requests))


def allowed_by_a_rule(verdict: Verdict) -> bool:
    undecided = verdict.decision in (None, "none", protocol.DECISION_ALLOW)
    return undecided and verdict.decided_by.startswith("rule:")


def actions(command: str, *, platform: Any = "windows", tool: str = "Bash") -> list[Action]:
    return list(
        event.normalize_event(
            {
                "hook_event_name": "PreToolUse",
                "session_id": "s",
                "cwd": PROJECT if platform == "windows" else "/proj",
                "project_dir": PROJECT if platform == "windows" else "/proj",
                "tool_name": tool,
                "tool_input": {"command": command},
            },
            platform=platform,
            env={"USERPROFILE": HOME, "HOME": "/home/bob"},
            home=HOME if platform == "windows" else "/home/bob",
        )
    )


@pytest.fixture(scope="module")
def powershell() -> None:
    psparse.reset()
    psparse.warm_up(wait_s=30)
    if psparse.status().get("state") != "ready":
        pytest.skip("the PowerShell parser helper is not available")


def test_every_character_casefold_turns_into_ascii_stays_itself_in_the_windows_fold() -> None:
    assert LONG_S in TO_ASCII
    assert KELVIN in TO_ASCII
    assert SHARP_S in TO_ASCII
    assert FI in TO_ASCII
    for char in TO_ASCII:
        assert not any(ord(c) < 128 for c in paths.windows_fold(char)), hex(ord(char))


# --- the directory ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "directory",
    [
        "/bin",
        "/usr/bin",
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "C:/Windows/System32",
        "C:\\Windows\\System32",
        "C:/WINDOWS/SYSTEM32",
        "c:/windows/syswow64",
        "C:/Program Files/Git/usr/bin",
        "C:/Program Files (x86)/Git/usr/bin",
        "C:/msys64/usr/bin",
        "C:/cygwin64/bin",
        # the prefix is what counts, as before: a name below it may hold any character
        "C:/Program Files/Git/\u7528\u6237",
        f"C:/Windows/System32/Wei{SHARP_S}",
        f"C:/Windows/System32/{LONG_S}",
    ],
)
def test_the_system_directories_are_still_system_directories(directory: str) -> None:
    assert event._system_dir(directory, "windows")


def _twins() -> list[str]:
    """Each system directory with one spot written as a character casefold reads as its letters."""
    plain = [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/local/sbin",
        "/opt/homebrew/sbin",
        "C:/Windows/System32",
        "C:/Windows/SysWOW64",
        "C:/Program Files/Git/usr/bin",
        "C:/Program Files (x86)/Git/usr/bin",
        "C:/msys64/usr/bin",
        "C:/msys32/usr/bin",
        "C:/cygwin64/bin",
        "C:/cygwin/bin",
    ]
    out: list[str] = []
    for directory in plain:
        for char in TO_ASCII:
            target = char.casefold()
            if all(ord(c) < 128 for c in target):
                at = directory.lower().find(target)
                if at >= 0:
                    out.append(directory[:at] + char + directory[at + len(target) :])
    return out


def test_the_twins_cover_what_they_should() -> None:
    twins = _twins()
    assert f"/u{LONG_S}r/bin" in twins
    assert f"C:/Window{LONG_S}/System32" in twins
    assert f"C:/Windows/Sy{ST}em32" in twins
    assert f"C:/Program {FI}les/Git/usr/bin" in twins
    assert f"C:/m{LONG_S}ys64/usr/bin" in twins
    assert f"C:/Program File{LONG_S}/Git/usr/bin" in twins


@pytest.mark.parametrize("directory", _twins())
def test_a_twin_of_a_system_directory_is_not_one(directory: str) -> None:
    assert not event._system_dir(directory, "windows"), directory.encode("unicode_escape")


@pytest.mark.parametrize(
    ("command", "allowed_by"),
    [
        ("/usr/bin/cat a.txt", "rule:allow-cat-inside-project"),
        ("C:/Windows/System32/git.exe status", "rule:allow-git-read-only"),
        ("C:/WINDOWS/system32/GIT.EXE status", "rule:allow-git-read-only"),
        ('"C:\\Program Files\\Git\\usr\\bin\\cat.exe" a.txt', "rule:allow-cat-inside-project"),
    ],
)
def test_the_plain_programs_are_still_allowed(command: str, allowed_by: str) -> None:
    for policy in (NO_BACKEND, BACKEND):
        verdict = decide("Bash", command, policy=policy)
        assert verdict.decided_by == allowed_by
        assert allowed_by_a_rule(verdict)


@pytest.mark.parametrize(
    "command",
    [
        f"/u{LONG_S}r/bin/cat a.txt",
        f"C:/Window{LONG_S}/System32/git.exe status",
        f"C:/Windows/Sy{LONG_S}tem32/git.exe status",
        f"C:/Windows/Sy{ST}em32/git.exe status",
        f'"C:\\Program File{LONG_S}\\Git\\usr\\bin\\cat.exe" a.txt',
    ],
)
def test_a_program_in_a_twin_directory_is_not_allowed(command: str) -> None:
    action = actions(command)[0]
    assert QUALIFIED in action.gray_reasons
    assert FOLD not in action.gray_reasons
    assert decide("Bash", command).decision == protocol.DECISION_ASK
    with_backend = decide("Bash", command, policy=BACKEND)
    assert not allowed_by_a_rule(with_backend)


def test_the_model_is_shown_the_twin_directory_as_written() -> None:
    verdict = decide("Bash", f"/u{LONG_S}r/bin/sed -n 1p a.py", policy=BACKEND)
    assert len(verdict.sent) == 1, verdict
    assert f"/u{LONG_S}r/bin/sed" in verdict.sent[0] or "/u\\u017fr/bin/sed" in verdict.sent[0]
    assert QUALIFIED in verdict.sent[0]


def test_a_directory_below_a_system_prefix_stays_where_it_is() -> None:
    """Below ``C:\\Program Files\\Git`` every name is the installation's, however it is written."""
    command = f'"C:\\Program Files\\Git\\u{LONG_S}r\\bin\\cat.exe" a.txt'
    assert QUALIFIED not in actions(command)[0].gray_reasons


# --- the name -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "program"),
    [
        (f"l{LONG_S} a.txt", "ls"),
        (f"{FI}nd . -name x", "find"),
        (f"ru{FF} check .", "ruff"),
        (f"{LONG_S}ed -n 1p a.py", "sed"),
        (f"/usr/bin/l{LONG_S} a.txt", "ls"),
        (f"C:/Windows/System32/l{LONG_S}.exe a.txt", "ls"),
        (f"l{LONG_S}.EXE a.txt", "ls"),
        (f"ma{KELVIN}e", "make"),
        (f"{SHARP_S}h host", "ssh"),
    ],
)
def test_a_name_only_casefold_reads_as_a_program_is_gray_and_keeps_the_name(
    command: str, program: str
) -> None:
    action = actions(command)[0]
    assert action.program == program
    assert FOLD in action.gray_reasons


@pytest.mark.parametrize(
    "command",
    [
        f"l{LONG_S} a.txt",
        f"{FI}nd . -name x",
        f"/usr/bin/l{LONG_S} a.txt",
        f"C:/Windows/System32/l{LONG_S}.exe a.txt",
        f"bash -c 'l{LONG_S} a.txt'",
        f"sh -c '{FI}nd . -name x'",
        f"cd sub && l{LONG_S} a.txt",
        f"cat a.txt | l{LONG_S}",
    ],
)
def test_such_a_name_is_not_allowed_and_not_sent(command: str) -> None:
    assert decide("Bash", command).decision == protocol.DECISION_ASK
    with_backend = decide("Bash", command, policy=BACKEND)
    assert with_backend.decision == protocol.DECISION_ASK
    assert with_backend.decided_by == "gray-unanalysed"
    assert with_backend.sent == ()


@pytest.mark.parametrize("wrapper", ["env", "nohup", "time", "command", "xargs", "timeout 5"])
def test_a_wrapper_does_not_open_the_allow_side_again(wrapper: str) -> None:
    command = f"{wrapper} l{LONG_S} a.txt"
    assert not allowed_by_a_rule(decide("Bash", command))
    assert not allowed_by_a_rule(decide("Bash", command, policy=BACKEND))


def test_the_model_would_have_been_told_the_plain_name() -> None:
    """Why it is not sent: the request names the program as folded, nothing shows the spelling."""
    plain = decide("Bash", "sed -n 1p a.py", policy=BACKEND)
    assert len(plain.sent) == 1
    assert plain.decided_by == "llm"
    assert pipeline.unshown_input(actions(f"{LONG_S}ed -n 1p a.py")) == FOLD
    assert pipeline.unshown_input(actions("sed -n 1p a.py")) is None
    assert decide("Bash", f"{LONG_S}ed -n 1p a.py", policy=BACKEND).sent == ()


@pytest.mark.parametrize(
    ("command", "decision", "rule"),
    [
        (f"mkf{LONG_S} x.img", protocol.DECISION_DENY, "deny-disk-tools"),
        (f"di{LONG_S}kpart", protocol.DECISION_DENY, "deny-disk-tools"),
        (f"bound{KELVIN}eep mode audit-only", protocol.DECISION_DENY, "deny-boundkeep-state"),
        (f"{LONG_S}udo rm -rf x", protocol.DECISION_ASK, "ask-privilege-escalation"),
        (f"{LONG_S}udo cat a.txt", protocol.DECISION_ASK, "ask-privilege-escalation"),
        (f"{LONG_S}{LONG_S}h host", protocol.DECISION_ASK, "net-allowlist"),
        (f"{SHARP_S}h host", protocol.DECISION_ASK, "net-allowlist"),
        (f"/u{LONG_S}r/bin/{LONG_S}udo cat a.txt", protocol.DECISION_ASK, "ask-privilege"),
    ],
)
def test_deny_and_ask_rules_still_read_the_name_as_casefold_does(
    command: str, decision: str, rule: str
) -> None:
    for policy in (NO_BACKEND, BACKEND):
        verdict = decide("Bash", command, policy=policy)
        assert verdict.decision == decision, verdict
        assert rule in verdict.decided_by, verdict
        assert verdict.sent == ()


@pytest.mark.parametrize(
    "command",
    [
        "git status",
        "GIT status",
        "Git.EXE status",
        "C:/Windows/System32/GIT.exe status",
        "\u6d4b\u8bd5.exe a.txt",  # no case at all
        "\u0424\u0410\u0419\u041b a.txt",  # Cyrillic upper case folds the same both ways
        "\u00c9t\u00e9.exe a.txt",  # so does Latin with an accent
        "\u03a3\u03a3 a.txt",  # capital sigma: NTFS merges it with the plain small one
        f"C:/Users/Wei{SHARP_S}/.venv/Scripts/pytest.exe -q",  # only the name counts here
    ],
)
def test_an_ordinary_name_is_no_fold_variant(command: str) -> None:
    assert FOLD not in actions(command)[0].gray_reasons


@pytest.mark.parametrize("char", TO_ASCII)
def test_every_such_character_makes_a_fold_variant(char: str) -> None:
    assert FOLD in actions(f"a{char}b a.txt")[0].gray_reasons


def test_a_posix_host_is_not_touched() -> None:
    action = actions(f"{LONG_S}ed -n 1p a.py", platform="posix")[0]
    assert FOLD not in action.gray_reasons
    assert action.program == f"{LONG_S}ed"
    assert not event._system_dir(f"/u{LONG_S}r/bin", "posix")
    assert event._system_dir("/usr/bin", "posix")


# --- PowerShell ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        f"Te{LONG_S}t-Path a.txt",
        f"Select-{LONG_S}tring x a.txt",
        f"C:/Window{LONG_S}/System32/git.exe status",
        f"& 'C:\\Window{LONG_S}\\System32\\git.exe' status",
        f"C:/Windows/System32/gi{chr(0x74)}{LONG_S}.exe status",
    ],
)
def test_powershell_is_not_allowed_either(powershell: None, command: str) -> None:
    assert decide("PowerShell", command).decision == protocol.DECISION_ASK
    assert not allowed_by_a_rule(decide("PowerShell", command, policy=BACKEND))


@pytest.mark.parametrize(
    ("command", "allowed_by"),
    [
        ("Test-Path a.txt", "rule:allow-ps-inspect-inside-project"),
        ("test-path a.txt", "rule:allow-ps-inspect-inside-project"),
        ("Select-String x a.txt", "rule:allow-ps-inspect-inside-project"),
        ("C:/Windows/System32/git.exe status", "rule:allow-git-read-only"),
        ("git status", "rule:allow-git-read-only"),
    ],
)
def test_powershell_keeps_the_plain_forms(powershell: None, command: str, allowed_by: str) -> None:
    assert decide("PowerShell", command).decided_by == allowed_by


def test_a_cmdlet_so_spelled_is_not_sent(powershell: None) -> None:
    verdict = decide("PowerShell", f"Te{LONG_S}t-Path a.txt", policy=BACKEND)
    assert verdict.decided_by == "gray-unanalysed"
    assert verdict.sent == ()
