"""Revision 12: GR-1 and GR-2 of the re-review (reviews/M3a-path-gate-rereview.md).

Two ways the key said "inside the project" of a place that is not. A last component with a trailing
dot or space: Git Bash and Node's file reads keep it (``cd ../proj.`` enters ``proj.``). A character
``str.casefold`` merges and NTFS does not: ``work`` with ``U+212A`` for its ``k``, next to the
project ``work``. Every verdict uses a fake backend that allows whatever it is shown; the real
directories are below ``tmp_path``.
"""

from __future__ import annotations

import ctypes
import os
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.audit.auditor import Auditor
from boundkeep.audit.backends.base import verdict_json
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.normalize import paths
from boundkeep.normalize.paths import NormPath, normalize_path, resolve_on_disk, windows_fold
from boundkeep.policy import Policy, default_policy_text, parse_policy_text
from boundkeep.policy.matcher import _comparison_key, _within

HOME = "C:\\Users\\bob"
PROJECT = "C:\\proj"
WORK = "C:\\work"
LLM_BLOCK = (
    "  backend: openai_compatible\n"
    "  openai_compatible:\n"
    "    base_url: https://llm.example.invalid/v1\n"
    "    model: test-model"
)
ENV = {"USERPROFILE": HOME, "COMPUTERNAME": "MYPC", "TEMP": HOME + "\\AppData\\Local\\Temp"}
SID = "ffffffff-2222-3333-4444-555555555555"
KELVIN, LONG_S, SHARP_S = "\u212a", "\u017f", "\u00df"
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="asks Win32")
NO_BACKEND = parse_policy_text(default_policy_text(), home=HOME)
BACKEND = parse_policy_text(
    re.sub(
        r"^  backend: none.*$", lambda _m: LLM_BLOCK, default_policy_text(), count=1, flags=re.M
    ),
    home=HOME,
)


def decide(
    tool: str,
    tool_input: dict[str, Any],
    *,
    policy: Policy = NO_BACKEND,
    cwd: str = PROJECT,
    scan_disk: bool = False,
) -> pipeline.Decision:
    backend = FakeBackend(lambda _r: verdict_json(verdict="allow"))
    return pipeline.decide(
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
        auditor=Auditor(policy.llm_audit, backend),
    )


def norm(raw: str, *, cwd: str = PROJECT) -> NormPath:
    return normalize_path(raw, cwd=cwd, home=HOME, env=ENV, dialect="tool")


# --- GR-1: a trailing dot or space on the last component ------------------------------------------


LAST_DOTS = [
    "C:\\proj.",
    "C:\\proj..",
    "C:\\proj. ",
    "C:\\proj ",
    "C:/proj.",
    "..\\proj.",
    "../proj.",
    "\\\\?\\C:\\proj.",
    "\\\\.\\C:\\proj.",
    "//?/C:/proj.",
    "C:\\proj\\a.txt.",
    "C:\\proj\\a.txt ",
    "a.txt.",
    # the dot is still there once the stream is gone: the NT path keeps it
    "C:\\proj.:s",
    "C:\\proj.::$DATA",
    "\\\\?\\C:\\proj.:s",
    "\\\\?\\C:\\proj.::$DATA",
]


@pytest.mark.parametrize("raw", LAST_DOTS)
def test_a_trailing_dot_on_the_last_component_is_uncertain(raw: str) -> None:
    got = norm(raw)
    assert got.uncertain
    assert paths.inside_project(got, norm(PROJECT)) is None


@pytest.mark.parametrize(
    ("raw", "key"),
    [
        ("C:\\proj\\a.txt.", "c:/proj/a.txt"),
        ("C:\\proj\\a.txt ", "c:/proj/a.txt"),
        ("C:\\proj.", "c:/proj"),
        ("C:\\proj.:s", "c:/proj"),
    ],
)
def test_the_key_still_strips_them(raw: str, key: str) -> None:
    assert norm(raw).key == key


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Read", {"file_path": "C:\\proj."}),
        ("Read", {"file_path": "..\\proj."}),
        ("Read", {"file_path": "\\\\?\\C:\\proj.::$DATA"}),
        ("Write", {"file_path": "C:\\proj.", "content": "x"}),
        ("Write", {"file_path": "C:\\proj.:s", "content": "x"}),
        ("Write", {"file_path": "\\\\?\\C:\\proj.:s", "content": "x"}),
        ("Grep", {"pattern": "x", "path": "C:\\proj."}),
        ("Grep", {"pattern": "x", "path": "../proj."}),
        ("Glob", {"pattern": "*", "path": "C:\\proj."}),
        ("Bash", {"command": "cd ../proj. && cat a.txt"}),
        ("Bash", {"command": "cd C:/proj. && cat a.txt"}),
        ("Bash", {"command": "cd /c/proj. && cat a.txt"}),
        ("Bash", {"command": "cd ../proj. && ls"}),
        ("Bash", {"command": "cd '../proj ' && cat a.txt"}),
        ("Bash", {"command": "ls ../proj."}),
        ("Bash", {"command": "ls C:/proj."}),
        ("Bash", {"command": "ls /c/proj."}),
        ("Bash", {"command": "cat ../proj."}),
        ("Bash", {"command": "mkdir ../proj."}),
        ("Bash", {"command": "mkdir '../proj  '"}),
    ],
)
def test_no_rule_allows_a_last_component_with_a_trailing_dot(
    tool: str, tool_input: dict[str, str]
) -> None:
    assert decide(tool, tool_input).decision == protocol.DECISION_ASK


@pytest.mark.skipif(sys.platform != "win32", reason="needs the PowerShell parser helper")
@pytest.mark.parametrize(
    "command",
    [
        "Set-Location ..\\proj.; Get-Content a.txt",
        "cd ..\\proj.; Get-Content a.txt",
        "Get-ChildItem ..\\proj.",
        "Get-Content ..\\proj.",
    ],
)
def test_no_rule_allows_it_in_powershell(command: str) -> None:
    assert decide("PowerShell", {"command": command}).decision == protocol.DECISION_ASK


@pytest.mark.parametrize(
    ("tool", "raw"),
    [
        ("Read", "C:\\Users\\bob\\.ssh\\id_rsa."),
        ("Read", "C:\\Users\\bob\\.ssh\\id_rsa "),
        ("Read", "\\\\?\\C:\\Users\\bob\\.ssh\\id_rsa."),
        ("Read", ".env."),
        ("Read", "C:\\Users\\bob\\.aws\\credentials."),
        ("Write", "C:\\Users\\bob\\.ssh\\id_rsa."),
        ("Write", "C:\\proj\\.claude\\settings.json."),
    ],
)
def test_a_deny_rule_still_matches(tool: str, raw: str) -> None:
    tool_input = {"file_path": raw} if tool == "Read" else {"file_path": raw, "content": "x"}
    assert decide(tool, tool_input).decision == protocol.DECISION_DENY


@pytest.mark.parametrize(
    ("raw", "key"),
    [
        ("C:\\proj\\a.b.txt", "c:/proj/a.b.txt"),
        ("C:\\proj\\.hidden", "c:/proj/.hidden"),
        ("C:\\proj\\.", "c:/proj"),
        ("C:\\proj\\sub\\..", "c:/proj"),
        ("C:\\proj\\sub\\", "c:/proj/sub"),
        ("C:\\proj\\a.txt::$DATA", "c:/proj/a.txt"),
        ("C:\\proj\\a.txt:s", "c:/proj/a.txt"),
    ],
)
def test_other_paths_stay_certain(raw: str, key: str) -> None:
    got = norm(raw)
    assert got.key == key
    assert not got.uncertain


def test_on_posix_a_trailing_dot_is_a_name() -> None:
    got = normalize_path("/home/dev/proj/a.", cwd="/home/dev/proj", home="/home/dev", env={})
    assert got.key == "/home/dev/proj/a."
    assert not got.uncertain


@windows_only
def test_a_real_sibling_with_a_trailing_dot_is_not_allowed(tmp_path: Path) -> None:
    base = "\\\\?\\" + str(tmp_path)
    project, sibling = str(tmp_path / "work"), base + "\\work."
    os.mkdir(project)
    os.mkdir(sibling)
    target = sibling + "\\left.txt"
    try:
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("outside the project")
        assert os.listdir(project) == []
        for tool, tool_input in [
            ("Bash", {"command": "cd ../work. && cat left.txt"}),
            ("Bash", {"command": "ls ../work."}),
            ("Grep", {"pattern": "outside", "path": "../work."}),
            ("Glob", {"pattern": "*", "path": str(tmp_path) + "\\work."}),
        ]:
            decision = decide(tool, tool_input, cwd=project, scan_disk=True)
            assert decision.decision == protocol.DECISION_ASK, tool_input
    finally:
        if os.path.exists(target):
            os.remove(target)
        os.rmdir(sibling)


# --- GR-2: the key folds the way NTFS compares names ----------------------------------------------


@pytest.mark.parametrize(
    ("text", "folded"),
    [
        ("C:/Users/BOB/.SSH", "c:/users/bob/.ssh"),
        ("\u00c4\u0414\u03a3", "\u00e4\u0434\u03c3"),  # Latin, Cyrillic, Greek pairs NTFS folds too
        (KELVIN, KELVIN),
        (LONG_S, LONG_S),
        (SHARP_S, SHARP_S),
        ("\u1e9e", "\u1e9e"),
        ("\ufb01", "\ufb01"),
        ("\u212b", "\u212b"),
        ("\u1c80", "\u1c80"),
        ("\u03c2", "\u03c2"),
        ("\U00010400", "\U00010400"),  # outside the basic plane NTFS has no case
        ("\U00010428", "\U00010428"),
    ],
)
def test_windows_fold(text: str, folded: str) -> None:
    assert windows_fold(text) == folded
    assert windows_fold(folded) == folded


TWINS = [
    (WORK, "C:\\wor" + KELVIN),
    ("C:\\sub", "C:\\" + LONG_S + "ub"),
    ("C:\\pross", "C:\\pro" + SHARP_S),
    ("C:\\fix", "C:\\\ufb01x"),
    ("C:\\test", "C:\\te\ufb06"),
    ("C:\\\u00c5sa", "C:\\\u212bsa"),  # not only ASCII: U+00C5 and U+212B are two directories
    ("C:\\\u0432\u0430\u0441\u044f", "C:\\\u1c80\u0430\u0441\u044f"),  # U+0432 and U+1C80
    ("C:\\\U00010400", "C:\\\U00010428"),
]


@pytest.mark.parametrize(("project", "twin"), TWINS)
def test_a_directory_that_only_folds_the_same_is_not_inside(project: str, twin: str) -> None:
    got = norm(twin + "\\data.txt", cwd=project)
    assert not got.uncertain
    assert got.key != norm(project + "\\data.txt", cwd=project).key
    assert paths.inside_project(got, norm(project, cwd=project)) is False


@pytest.mark.parametrize(("project", "twin"), TWINS)
@pytest.mark.parametrize(
    ("tool", "extra"), [("Read", {}), ("Write", {"content": "x"})], ids=["read", "write"]
)
def test_no_rule_allows_it(project: str, twin: str, tool: str, extra: dict[str, str]) -> None:
    tool_input = {"file_path": twin + "\\data.py", **extra}
    assert decide(tool, tool_input, cwd=project).decision == protocol.DECISION_ASK


@pytest.mark.parametrize(
    "command",
    [
        f"cat 'C:/wor{KELVIN}/data.txt'",
        f"cd 'C:/wor{KELVIN}' && cat data.txt",
        f"ls 'C:/wor{KELVIN}'",
        f"mkdir 'C:/wor{KELVIN}/deeper'",
    ],
)
def test_no_rule_allows_it_in_a_shell_command(command: str) -> None:
    assert decide("Bash", {"command": command}, cwd=WORK).decision == protocol.DECISION_ASK


@pytest.mark.parametrize(
    ("project", "same"),
    [
        (WORK, "c:\\WORK"),
        ("C:\\\u00c5sa", "C:\\\u00e5SA"),
        ("C:\\\u041f\u0440\u043e\u0435\u043a\u0442", "C:\\\u041f\u0420\u041e\u0415\u041a\u0422"),
        ("C:\\\u03a3\u03b1", "C:\\\u03c3\u0391"),
    ],
)
def test_a_real_case_variant_is_still_inside(project: str, same: str) -> None:
    got = norm(same + "\\data.txt", cwd=project)
    assert not got.uncertain
    assert paths.inside_project(got, norm(project, cwd=project)) is True


@pytest.mark.parametrize(
    "project",
    [
        "C:\\Users\\Wei" + SHARP_S + "\\p",
        "C:\\Stra" + SHARP_S + "e",
        "C:\\\u039d\u03af\u03ba\u03bf\u03c2",  # a final sigma
        "C:\\\u041f\u0440\u043e\u0435\u043a\u0442",
    ],
)
def test_such_a_character_in_the_project_itself_costs_nothing(project: str) -> None:
    got = norm(project + "\\a.txt", cwd=project)
    assert not got.uncertain
    assert paths.inside_project(got, norm(project, cwd=project)) is True
    decision = decide("Read", {"file_path": project + "\\a.txt"}, cwd=project)
    assert decision.decided_by == "rule:read-inside-project"


@pytest.mark.parametrize(
    ("tool", "raw"),
    [
        ("Read", f"C:\\Users\\bob\\.{LONG_S}{LONG_S}h\\id_rsa"),
        ("Read", f"C:\\Users\\bob\\.aw{LONG_S}\\credentials"),
        ("Read", f"C:\\Users\\bob\\.aws\\credential{LONG_S}"),
        ("Write", f"C:\\Users\\bob\\.{LONG_S}{LONG_S}h\\authorized_keys"),
        ("Write", f"C:\\proj\\.claude\\{LONG_S}ettings.json"),
    ],
)
def test_a_deny_rule_still_over_matches(tool: str, raw: str) -> None:
    tool_input = {"file_path": raw} if tool == "Read" else {"file_path": raw, "content": "x"}
    assert decide(tool, tool_input).decision == protocol.DECISION_DENY


def test_the_model_is_shown_what_the_path_really_says() -> None:
    backend = FakeBackend(lambda _r: verdict_json(verdict="allow"))
    tool_input = {"file_path": "C:\\wor" + KELVIN + "\\data.txt"}
    pipeline.decide(
        protocol.EVENT_PRE,
        {
            "hook_event_name": "PreToolUse",
            "session_id": "s",
            "cwd": WORK,
            "project_dir": WORK,
            "tool_name": "Read",
            "tool_input": tool_input,
        },
        mode="enforce",
        policy=BACKEND,
        policy_error=None,
        platform="windows",
        env=ENV,
        home=HOME,
        scan_disk=False,
        auditor=Auditor(BACKEND.llm_audit, backend),
    )
    assert len(backend.requests) == 1
    assert "c:/work/data.txt" not in str(backend.requests[0])


def test_a_trusted_project_is_not_its_twin() -> None:
    trusted, twin = _comparison_key("c:/work"), _comparison_key(f"c:/wor{KELVIN}/x")
    assert trusted is not None
    assert twin is not None
    assert not _within(twin, trusted)
    below = _comparison_key("C:/WORK/x")
    assert below is not None
    assert _within(below, trusted)


@pytest.mark.parametrize(
    "template",
    [
        "C:\\Users\\bob\\AppData\\Local\\Temp\\claude\\abc\\{sid}\\" + LONG_S + "cratchpad\\a.txt",
        "C:\\User" + LONG_S + "\\bob\\AppData\\Local\\Temp\\claude\\abc\\{sid}\\scratchpad\\a.txt",
        "C:\\Users\\bob\\AppData\\Local\\Temp\\claude\\abc\\{twin}\\scratchpad\\a.txt",
        "C:\\Users\\bob\\AppData\\Local\\Temp\\claude\\abc\\{sid}\\scratchpad\\a.txt.",
        "C:\\Users\\bob\\AppData\\Local\\Temp\\claude\\abc\\{sid}\\scratchpad.\\a.txt",
    ],
)
def test_the_scratchpad_is_not_its_twin(template: str) -> None:
    directory = paths.scratchpad_for(SID, "windows", ENV, HOME)
    assert directory is not None
    plain = template.format(sid=SID, twin=SID).replace(LONG_S, "s").replace(".\\a", "\\a")
    assert directory.contains(norm(plain.removesuffix(".")), resolved=False)
    raw = template.format(sid=SID, twin=SID.replace("ff", "\ufb00"))
    assert not directory.contains(norm(raw), resolved=False)


@pytest.mark.parametrize(
    "raw", ["C:\\wor" + KELVIN + "\\x\\..\\y", "C:\\pro" + SHARP_S + "\\a.txt"]
)
def test_the_key_is_stable(raw: str) -> None:
    first = norm(raw)
    assert norm(first.key).key == first.key


# --- against the real thing -----------------------------------------------------------------------


def _upcase() -> Any:
    function = ctypes.WinDLL("ntdll").RtlUpcaseUnicodeChar  # type: ignore[attr-defined,unused-ignore]
    function.argtypes = [ctypes.c_wchar]
    function.restype = ctypes.c_wchar
    return function


BASIC_PLANE = [chr(c) for c in range(0x10000) if not 0xD800 <= c <= 0xDFFF]
measured_unicode = pytest.mark.skipif(
    unicodedata.unidata_version != "15.0.0", reason="the list was measured with Unicode 15.0"
)


@windows_only
@measured_unicode
def test_the_list_is_what_the_kernel_says() -> None:
    upcase = _upcase()
    expected = {
        c for c in BASIC_PLANE if len(c.casefold()) > 1 or upcase(c) != upcase(c.casefold())
    }
    assert expected == paths._NTFS_KEEPS_APART


@windows_only
@measured_unicode
def test_one_key_is_never_two_kernel_classes() -> None:
    upcase = _upcase()
    classes: dict[str, set[str]] = {}
    for c in BASIC_PLANE:
        classes.setdefault(windows_fold(c), set()).add(upcase(c))
    assert [key for key, seen in classes.items() if len(seen) > 1] == []


@windows_only
@measured_unicode
def test_two_keys_for_one_kernel_class_are_only_greek_with_iota_subscript() -> None:
    # The cautious direction: same file, two keys, so the allow side says no
    upcase = _upcase()
    keys: dict[str, set[str]] = {}
    for c in BASIC_PLANE:
        keys.setdefault(upcase(c), set()).add(windows_fold(c))
    split = {up for up, seen in keys.items() if len(seen) > 1}
    assert len(split) == 27
    assert all("\u1f80" <= up <= "\u1fff" for up in split)


@windows_only
@pytest.mark.parametrize(("name", "twin"), [("work", "wor" + KELVIN), ("\u0432", "\u1c80")])
def test_a_real_twin_directory_is_not_allowed(tmp_path: Path, name: str, twin: str) -> None:
    project, other = tmp_path / name, tmp_path / twin
    project.mkdir()
    other.mkdir()
    assert not os.path.samefile(project, other)
    target = other / "data.txt"
    target.write_text("outside the project", encoding="utf-8")
    assert list(project.iterdir()) == []
    assert resolve_on_disk(norm(str(target), cwd=str(project))).key.endswith(f"/{twin}/data.txt")
    for tool, tool_input in [
        ("Read", {"file_path": str(target)}),
        ("Write", {"file_path": str(other / "new.py"), "content": "x"}),
        ("Bash", {"command": f"cat '{target.as_posix()}'"}),
    ]:
        decision = decide(tool, tool_input, cwd=str(project), scan_disk=True)
        assert decision.decision == protocol.DECISION_ASK, tool


@windows_only
def test_a_wildcard_finds_a_name_with_such_a_character(tmp_path: Path) -> None:
    (tmp_path / f"{SHARP_S}a.txt").write_text("x", encoding="utf-8")
    found = paths.expand_glob(norm(str(tmp_path / f"{SHARP_S}*.txt")))
    assert found.status == "ok"
    assert [os.path.basename(m) for m in found.matches] == [f"{SHARP_S}a.txt"]
