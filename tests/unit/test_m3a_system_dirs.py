"""Revision 15: which directories hold the system's own programs on a Windows host.

Revision 14's record (docs/reports/M3a-program-fold.md, section 7) found that the check dropped the
drive letter and trusted whole prefixes: ``D:/Windows/System32/git.exe status``,
``C:/Windows/System32evil/git.exe status`` and ``C:/msys64/home/x/cat a.txt`` were allowed by a
rule, and an ordinary account can write all of those places (measured ACLs). Now only these
directories count, exactly and with a drive letter: ``%SystemRoot%\\System32`` and ``SysWOW64``,
and Git's program directories under ``%ProgramFiles%`` and ``%ProgramFiles(x86)%``; and, in the
bash dialect only, the POSIX ones without a drive letter (Git Bash's own). Every verdict uses a
fake backend that allows whatever it is shown; nothing is run and no file is written.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass

import pytest

from boundkeep import protocol
from boundkeep.audit.auditor import Auditor
from boundkeep.audit.backends.base import verdict_json
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.normalize import event, psparse
from boundkeep.policy import Policy, default_policy_text, parse_policy_text

HOME = "C:\\Users\\bob"
PROJECT = "C:\\proj"
ENV: dict[str, str] = {"USERPROFILE": HOME, "COMPUTERNAME": "MYPC"}
REAL_ENV = {
    **ENV,
    "SystemRoot": "C:\\WINDOWS",
    "ProgramFiles": "C:\\Program Files",
    "ProgramFiles(x86)": "C:\\Program Files (x86)",
}
LLM_BLOCK = (
    "  backend: openai_compatible\n"
    "  openai_compatible:\n"
    "    base_url: https://llm.example.invalid/v1\n"
    "    model: test-model"
)
QUALIFIED = "program-path-qualified"
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


def decide(
    tool: str,
    command: str,
    *,
    policy: Policy = NO_BACKEND,
    env: Mapping[str, str] = ENV,
) -> Verdict:
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
        env=env,
        home=HOME,
        scan_disk=False,
        auditor=Auditor(policy.llm_audit, backend),
    )
    return Verdict(result.decision, result.decided_by, tuple(r.content for r in backend.requests))


def allowed_by_a_rule(verdict: Verdict) -> bool:
    undecided = verdict.decision in (None, "none", protocol.DECISION_ALLOW)
    return undecided and verdict.decided_by.startswith("rule:")


def gray_reasons(command: str, *, tool: str = "Bash", env: Mapping[str, str] = ENV) -> set[str]:
    actions = event.normalize_event(
        {
            "hook_event_name": "PreToolUse",
            "session_id": "s",
            "cwd": PROJECT,
            "project_dir": PROJECT,
            "tool_name": tool,
            "tool_input": {"command": command},
        },
        platform="windows",
        env=env,
        home=HOME,
    )
    return {reason for action in actions for reason in action.gray_reasons}


@pytest.fixture(scope="module")
def powershell() -> None:
    psparse.reset()
    psparse.warm_up(wait_s=30)
    if psparse.status().get("state") != "ready":
        pytest.skip("the PowerShell parser helper is not available")


# --- the set ------------------------------------------------------------------------------------


def test_the_windows_system_directories_are_exactly_these() -> None:
    assert event._windows_system_dirs((None, None, None)) == {
        "c:/windows/system32",
        "c:/windows/syswow64",
        *(
            f"{root}/git/{sub}"
            for root in ("c:/program files", "c:/program files (x86)")
            for sub in ("cmd", "bin", "usr/bin", "mingw64/bin", "mingw32/bin")
        ),
    }


@pytest.mark.parametrize(
    "system_root",
    [
        "",
        "Windows",
        "\\Windows",
        "C:",
        "C:\\",
        "C:Windows",
        "\\\\srv\\share\\Windows",
        "\\\\?\\C:\\Windows",
        "C:\\Windows.",
        "C:\\Windows ",
        "C:\\..\\Windows",
        "C:\\x\\.\\Windows",
        "C:\\Windows:x",
        "C:\\Win*",
        "1:\\Windows",
    ],
)
def test_a_root_variable_that_is_no_plain_absolute_path_gives_no_directory(
    system_root: str,
) -> None:
    dirs = event._windows_system_dirs((system_root, None, None))
    assert not any(d.endswith(("/system32", "/syswow64")) for d in dirs), dirs
    assert "c:/program files/git/usr/bin" in dirs  # the other variables are untouched


def test_the_root_variables_move_the_directories() -> None:
    dirs = event._windows_system_dirs(("D:\\WinNT\\", "E:\\Apps", None))
    assert "d:/winnt/system32" in dirs
    assert "c:/windows/system32" not in dirs
    assert "e:/apps/git/usr/bin" in dirs
    assert "c:/program files/git/usr/bin" not in dirs
    assert "c:/program files (x86)/git/usr/bin" in dirs  # its default


# --- what stays ---------------------------------------------------------------------------------


@pytest.mark.parametrize("env", [ENV, REAL_ENV], ids=["no-variables", "variables"])
@pytest.mark.parametrize(
    ("tool", "command", "allowed_by"),
    [
        ("Bash", "C:/Windows/System32/git.exe status", "rule:allow-git-read-only"),
        ("Bash", "'c:\\windows\\system32\\GIT.EXE' status", "rule:allow-git-read-only"),
        ("Bash", "C:/WINDOWS/SysWOW64/git status", "rule:allow-git-read-only"),
        (
            "Bash",
            '"C:\\Program Files\\Git\\usr\\bin\\cat.exe" a.txt',
            "rule:allow-cat-inside-project",
        ),
        ("Bash", '"C:/Program Files/Git/cmd/git.exe" status', "rule:allow-git-read-only"),
        ("Bash", '"C:/Program Files/Git/mingw64/bin/git.exe" status', "rule:allow-git-read-only"),
        ("Bash", '"C:/Program Files (x86)/Git/bin/git.exe" status', "rule:allow-git-read-only"),
        ("Bash", "/usr/bin/cat a.txt", "rule:allow-cat-inside-project"),
        ("Bash", "/bin/cat a.txt", "rule:allow-cat-inside-project"),
        ("Bash", "/usr/bin/git status", "rule:allow-git-read-only"),
    ],
)
def test_the_system_programs_are_still_allowed(
    tool: str, command: str, allowed_by: str, env: Mapping[str, str]
) -> None:
    assert QUALIFIED not in gray_reasons(command, env=env)
    for policy in (NO_BACKEND, BACKEND):
        verdict = decide(tool, command, policy=policy, env=env)
        assert verdict.decided_by == allowed_by, verdict
        assert allowed_by_a_rule(verdict)


@pytest.mark.parametrize(
    "command",
    [
        "C:/Windows/System32/git.exe status",
        "& 'C:\\Windows\\System32\\git.exe' status",
        "& 'C:\\Program Files\\Git\\bin\\git.exe' status",
        "& 'C:\\Program Files\\Git\\cmd\\git.exe' status",
    ],
)
def test_powershell_keeps_them_too(powershell: None, command: str) -> None:
    for env in (ENV, REAL_ENV):
        assert decide("PowerShell", command, env=env).decided_by == "rule:allow-git-read-only"


# --- what goes ----------------------------------------------------------------------------------

# Each of these was allowed by a rule before revision 15 (measured on fef9fe9)
DROPPED_BOTH = [
    "D:/Windows/System32/git.exe status",
    "E:/Windows/System32/git.exe status",
    "C:/Windows/System32evil/git.exe status",
    "C:/Windows/SysWOW64evil/git.exe status",
    "C:/Windows/System32/spool/drivers/color/git.exe status",
    "C:/Windows/System32/Tasks/git.exe status",
    "C:/Windows/System32/OpenSSH/git.exe status",
    "/Windows/System32/git.exe status",
]
DROPPED_BASH = [
    "E:/usr/bin/cat a.txt",
    "D:/usr/bin/cat a.txt",
    "C:/usr/bin/cat a.txt",
    "D:/bin/cat a.txt",
    "C:/msys64/home/x/cat a.txt",
    "C:/msys64/usr/bin/cat.exe a.txt",
    "C:/cygwin/tmp/cat.exe a.txt",
    "C:/cygwin64/bin/cat a.txt",
    '"C:\\Program Files\\Git\\tmp\\cat.exe" a.txt',
    '"C:\\Program Files\\Git\\usr\\cat.exe" a.txt',
    '"C:/Program Files/Git/mingw64/libexec/git-core/git.exe" status',
    '"D:/Program Files/Git/usr/bin/cat.exe" a.txt',
    '"/Program Files/Git/usr/bin/cat.exe" a.txt',
]


@pytest.mark.parametrize("env", [ENV, REAL_ENV], ids=["no-variables", "variables"])
@pytest.mark.parametrize("command", DROPPED_BOTH + DROPPED_BASH)
def test_the_other_directories_are_not_trusted(command: str, env: Mapping[str, str]) -> None:
    assert QUALIFIED in gray_reasons(command, env=env)
    no_backend = decide("Bash", command, env=env)
    assert no_backend.decision in (protocol.DECISION_ASK, protocol.DECISION_DENY), no_backend
    assert not allowed_by_a_rule(decide("Bash", command, policy=BACKEND, env=env))


@pytest.mark.parametrize("command", DROPPED_BOTH)
def test_powershell_does_not_trust_them_either(powershell: None, command: str) -> None:
    assert decide("PowerShell", command).decision in (
        protocol.DECISION_ASK,
        protocol.DECISION_DENY,
    )
    assert not allowed_by_a_rule(decide("PowerShell", command, policy=BACKEND))


@pytest.mark.parametrize(
    "command",
    ["/usr/bin/git.exe status", "/usr/bin/git status", "& '/usr/bin/git.exe' status"],
)
def test_a_posix_directory_in_powershell_is_the_current_drive(
    powershell: None, command: str
) -> None:
    """``/usr/bin`` in PowerShell is ``E:\\usr\\bin`` when the location is on E: (measured)."""
    assert QUALIFIED in gray_reasons(command, tool="PowerShell")
    assert not allowed_by_a_rule(decide("PowerShell", command))
    assert not allowed_by_a_rule(decide("PowerShell", command, policy=BACKEND))


def test_the_same_posix_directory_in_bash_is_git_bash_s_own() -> None:
    assert QUALIFIED not in gray_reasons("/usr/bin/git.exe status")
    assert allowed_by_a_rule(decide("Bash", "/usr/bin/git.exe status"))


def test_the_model_is_shown_where_the_program_is() -> None:
    verdict = decide("Bash", "D:/Windows/System32/sed.exe -n 1p a.py", policy=BACKEND)
    assert len(verdict.sent) == 1, verdict
    assert "d:/windows/system32/sed.exe" in verdict.sent[0]  # the key: folded, drive kept
    assert QUALIFIED in verdict.sent[0]


# --- the environment ----------------------------------------------------------------------------


def test_the_system_root_comes_from_the_environment() -> None:
    env = {**ENV, "SystemRoot": "D:\\Windows"}
    assert QUALIFIED not in gray_reasons("D:/Windows/System32/git.exe status", env=env)
    assert QUALIFIED in gray_reasons("C:/Windows/System32/git.exe status", env=env)
    assert allowed_by_a_rule(decide("Bash", "D:/Windows/System32/git.exe status", env=env))
    assert not allowed_by_a_rule(decide("Bash", "C:/Windows/System32/git.exe status", env=env))


def test_program_files_comes_from_the_environment() -> None:
    env = {**ENV, "ProgramFiles": "D:\\Program Files"}
    on_d = '"D:/Program Files/Git/usr/bin/cat.exe" a.txt'
    on_c = '"C:/Program Files/Git/usr/bin/cat.exe" a.txt'
    assert QUALIFIED not in gray_reasons(on_d, env=env)
    assert QUALIFIED in gray_reasons(on_c, env=env)
    assert QUALIFIED not in gray_reasons(
        '"C:/Program Files (x86)/Git/usr/bin/cat.exe" a.txt', env=env
    )


def test_a_directory_from_the_environment_is_compared_as_ntfs_compares() -> None:
    """``lower()`` reads the Kelvin sign as ``k``; NTFS keeps ``\\u212aits`` and ``kits`` apart."""
    env = {**ENV, "ProgramFiles": "D:\\kits"}
    assert QUALIFIED not in gray_reasons('"D:/kits/Git/usr/bin/cat.exe" a.txt', env=env)
    assert QUALIFIED not in gray_reasons('"D:/KITS/Git/usr/bin/cat.exe" a.txt', env=env)
    assert QUALIFIED in gray_reasons('"D:/\u212aits/Git/usr/bin/cat.exe" a.txt', env=env)


def test_the_variable_names_match_as_windows_matches_them() -> None:
    env = {**ENV, "SYSTEMROOT": "D:\\Windows", "programfiles": "D:\\Program Files"}
    assert QUALIFIED not in gray_reasons("D:/Windows/System32/git.exe status", env=env)
    assert QUALIFIED not in gray_reasons('"D:/Program Files/Git/bin/git.exe" status', env=env)
    assert QUALIFIED in gray_reasons("C:/Windows/System32/git.exe status", env=env)


def test_a_broken_system_root_trusts_no_windows_directory() -> None:
    env = {**ENV, "SystemRoot": "\\\\srv\\share\\Windows"}
    assert QUALIFIED in gray_reasons("C:/Windows/System32/git.exe status", env=env)
    assert QUALIFIED in gray_reasons("//srv/share/Windows/System32/git.exe status", env=env)
    assert QUALIFIED not in gray_reasons("/usr/bin/git status", env=env)


@pytest.mark.skipif(sys.platform != "win32", reason="reads this host's own environment")
def test_this_host_s_environment_names_its_own_system_directory() -> None:
    root = os.environ["SYSTEMROOT"]
    assert event._system_dir(root + "\\System32", "windows", env=os.environ)
    assert not event._system_dir(root + "\\System32\\Tasks", "windows", env=os.environ)


# --- the deny and ask side, other hosts ---------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "decision", "rule"),
    [
        ("D:/Windows/System32/diskpart.exe", protocol.DECISION_DENY, "deny-disk-tools"),
        ("C:/msys64/usr/bin/mkfs.exe x.img", protocol.DECISION_DENY, "deny-disk-tools"),
        ("E:/usr/bin/rm -rf x", protocol.DECISION_DENY, "rm-outside-project"),
        ("D:/Windows/System32/git.exe push", protocol.DECISION_ASK, "net-"),
    ],
)
def test_deny_and_ask_rules_still_read_the_name(command: str, decision: str, rule: str) -> None:
    for policy in (NO_BACKEND, BACKEND):
        verdict = decide("Bash", command, policy=policy)
        assert verdict.decision == decision, verdict
        assert rule in verdict.decided_by, verdict


def test_a_posix_host_is_not_touched() -> None:
    assert event._system_dir("/usr/bin", "posix")
    assert event._system_dir("/usr/local/bin", "posix")
    assert not event._system_dir("C:/Windows/System32", "posix")
    assert not event._system_dir("/usr/bin/x", "posix")
    assert not event._system_dir("/USR/BIN", "posix")
