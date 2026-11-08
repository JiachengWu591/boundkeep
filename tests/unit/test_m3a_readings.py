"""Revision 13: RV-1, RV-2 and RV-3 of the review (reviews/M3a-dots-and-folding-review.md).

"Which reading does a program take" is a question for the allow side. A path that is uncertain only
about that is still looked up on disk, or a junction in the project hides a target a deny rule names
(RV-1). In Git Bash ``work:s`` is a directory of its own (RV-2). Windows does not read ``localho`` +
``U+017F`` + ``t`` as this machine (RV-3). Every verdict uses a fake backend that allows whatever it
is shown; the real files are below ``tmp_path``, with made-up content, and nothing is ever opened on
a share.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.audit.auditor import Auditor
from boundkeep.audit.backends.base import verdict_json
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.normalize import event, paths, programs, psparse
from boundkeep.normalize.model import PathRef, Word
from boundkeep.normalize.paths import (
    inside_project,
    normalize_path,
    reading_only,
    reading_text,
    resolve_on_disk,
)
from boundkeep.policy import Policy, default_policy_text, parse_policy_text

HOME = "C:\\Users\\bob"
PROJECT = "C:\\proj"
LLM_BLOCK = (
    "  backend: openai_compatible\n"
    "  openai_compatible:\n"
    "    base_url: https://llm.example.invalid/v1\n"
    "    model: test-model"
)
LONG_S, KELVIN, CYGWIN_COLON = "\u017f", "\u212a", "\uf03a"
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="real junctions")


def policies(home: str) -> tuple[Policy, Policy]:
    text = default_policy_text()
    with_backend = re.sub(r"^  backend: none.*$", lambda _m: LLM_BLOCK, text, count=1, flags=re.M)
    return parse_policy_text(text, home=home), parse_policy_text(with_backend, home=home)


NO_BACKEND, BACKEND = policies(HOME)


@dataclass(frozen=True)
class Verdict:
    decision: str | None
    decided_by: str
    sent: int


def decide(
    tool: str,
    tool_input: dict[str, Any],
    *,
    policy: Policy = NO_BACKEND,
    cwd: str = PROJECT,
    home: str = HOME,
    computer: str = "MYPC",
    scan_disk: bool = False,
) -> Verdict:
    backend = FakeBackend(lambda _r: verdict_json(verdict="allow"))
    result = pipeline.decide(
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
        env={"USERPROFILE": home, "COMPUTERNAME": computer},
        home=home,
        scan_disk=scan_disk,
        auditor=Auditor(policy.llm_audit, backend),
    )
    return Verdict(result.decision, result.decided_by, len(backend.requests))


def allowed_by_a_rule(verdict: Verdict) -> bool:
    """No decision (or an allow) because a rule said so, not because the fake model did."""
    undecided = verdict.decision in (None, "none", protocol.DECISION_ALLOW)
    return undecided and verdict.decided_by.startswith("rule:")


def test_allowed_by_a_rule_can_say_yes() -> None:
    assert allowed_by_a_rule(decide("Read", {"file_path": "C:\\proj\\a.txt"}))
    assert not allowed_by_a_rule(decide("Read", {"file_path": "C:\\Users\\bob\\.ssh\\id_rsa"}))


# --- RV-1: a link in the project, a trailing dot, no look at the disk ----------------------------


@dataclass(frozen=True)
class Machine:
    """A fake home, a project with junctions that hide where they lead, both policies."""

    home: str
    project: str
    private: str
    no_backend: Policy
    backend: Policy

    def both(self, tool: str, tool_input: dict[str, Any]) -> tuple[Verdict, Verdict]:
        return tuple(  # type: ignore[return-value]
            decide(tool, tool_input, policy=p, cwd=self.project, home=self.home, scan_disk=True)
            for p in (self.no_backend, self.backend)
        )


def _unlink_junctions(root: str) -> None:
    for base, dirs, _files in os.walk("\\\\?\\" + root, topdown=False):
        for name in dirs:
            path = base + "\\" + name
            if os.path.isjunction(path):
                os.unlink(path)


@pytest.fixture
def machine(tmp_path: Path) -> Iterator[Machine]:
    import _winapi  # type: ignore[import-not-found, unused-ignore]

    root = str(tmp_path)
    home, project, private = root + "\\home", root + "\\work", root + "\\private"
    for directory in (".ssh", ".aws", ".boundkeep", ".claude"):
        os.makedirs(f"{home}\\{directory}")
    os.makedirs(project + "\\sub")
    os.makedirs(project + "\\clean")
    os.makedirs(project + "\\deep")
    os.makedirs(private)
    for name, text in {
        home + "\\.ssh\\config": "FAKE",
        home + "\\.aws\\config": "FAKE",
        home + "\\.boundkeep\\policy.yaml": "FAKE",
        home + "\\.claude\\settings.json": "{}",
        private + "\\notes.txt": "PRIVATE",
        project + "\\a.txt": "inside",
        project + "\\sub\\.env": "FAKE=1",
        project + "\\clean\\c.txt": "c",
    }.items():
        with open(name, "w", encoding="utf-8") as handle:
            handle.write(text)
    for name, target in {
        "keys": home + "\\.ssh",
        "guard": home + "\\.boundkeep",
        "cc": home + "\\.claude",
        "out": private,
        "deep\\inner": home + "\\.ssh",
    }.items():
        _winapi.CreateJunction(target, f"{project}\\{name}")
    no_backend, backend = policies(home)
    yield Machine(home, project, private, no_backend, backend)
    _unlink_junctions(root)


@pytest.fixture(scope="module")
def powershell() -> None:
    psparse.reset()
    psparse.warm_up(wait_s=30)
    if psparse.status().get("state") != "ready":
        pytest.skip("the PowerShell parser helper is not available")


def _deny(verdicts: tuple[Verdict, Verdict], rule: str) -> None:
    for verdict in verdicts:
        assert verdict.decision == protocol.DECISION_DENY, verdict
        assert rule in verdict.decided_by, verdict
        assert verdict.sent == 0, verdict


LINKED_TOOLS = [
    ("Read", "keys\\config{dot}", "no-secret-read"),
    ("Write", "keys\\config{dot}", "deny-ssh-write"),
    ("Write", "guard\\policy.yaml{dot}", "protect-guard-config"),
    ("Write", "cc\\settings.json{dot}", "protect-guard-config"),
    ("Read", "cc\\settings.json{dot}", "no-agent-state-read"),
    ("Read", "keys{dot}\\config", "no-secret-read"),
    ("Write", "keys{dot}\\config", "deny-ssh-write"),
    ("Write", "guard{dot}\\policy.yaml", "protect-guard-config"),
]
# Win32 opens these: dir::$INDEX_ALLOCATION\x reads dir\x (measured)
STREAM_OF_A_LINK = [
    "keys::$INDEX_ALLOCATION\\config",
    "keys:$I30:$INDEX_ALLOCATION\\config",
    "keys:s\\config",
]


@windows_only
@pytest.mark.parametrize("relative", STREAM_OF_A_LINK)
def test_a_stream_name_before_the_last_component_does_not_hide_a_link(
    machine: Machine, relative: str
) -> None:
    _deny(machine.both("Read", {"file_path": f"{machine.project}\\{relative}"}), "no-secret-read")


@windows_only
@pytest.mark.usefixtures("powershell")
@pytest.mark.parametrize("relative", STREAM_OF_A_LINK[:2])
def test_powershell_reading_through_a_stream_name_is_denied(
    machine: Machine, relative: str
) -> None:
    command = f"Get-Content -LiteralPath '{relative}'"
    _deny(machine.both("PowerShell", {"command": command}), "no-secret-read")


@windows_only
@pytest.mark.parametrize("dot", [".", " ", "..", ". "])
@pytest.mark.parametrize(("tool", "relative", "rule"), LINKED_TOOLS)
def test_a_file_tool_sees_through_a_link_with_a_dot(
    machine: Machine, tool: str, relative: str, rule: str, dot: str
) -> None:
    path = machine.project + "\\" + relative.format(dot=dot)
    tool_input = {"file_path": path, "content": "x"} if tool == "Write" else {"file_path": path}
    _deny(machine.both(tool, tool_input), rule)


LINKED_BASH = [
    ("cat keys/config.", "no-secret-read"),
    ("cat keys./config", "no-secret-read"),
    ("echo x > keys/config.", "deny-ssh-write"),
    ("echo x > guard/policy.yaml.", "protect-guard-config"),
    ("cat cc/settings.json.", "no-agent-state-read"),
    ("cat k*/config.", "no-secret-read"),
    ("ls keys.", "no-secret-read"),
    ("grep -r x keys.", "no-secret-read"),
    ("cd keys. && cat config", "no-secret-read"),
    ("cd keys. && ls", "no-secret-read"),
    ("cd keys./ && cat config", "no-secret-read"),
    ("cat sub/.env.", "no-secret-read"),
]


@windows_only
@pytest.mark.parametrize(("command", "rule"), LINKED_BASH)
def test_bash_sees_through_a_link_with_a_dot(machine: Machine, command: str, rule: str) -> None:
    _deny(machine.both("Bash", {"command": command}), rule)


LINKED_POWERSHELL = [
    ("Get-Content keys\\config.", "no-secret-read"),
    ("Get-Content -LiteralPath keys\\config.", "no-secret-read"),
    ("Set-Content keys\\config. x", "deny-ssh-write"),
    ("x > keys\\config.", "deny-ssh-write"),
    ("Set-Content guard\\policy.yaml. x", "protect-guard-config"),
    ("Set-Content guard.\\policy.yaml x", "protect-guard-config"),
    ("Set-Content cc\\settings.json. x", "protect-guard-config"),
    ("Get-Content k*\\config.", "no-secret-read"),
    ("Get-ChildItem keys.", "no-secret-read"),
    ("Set-Location keys.; Get-Content config", "no-secret-read"),
]


@windows_only
@pytest.mark.usefixtures("powershell")
@pytest.mark.parametrize(("command", "rule"), LINKED_POWERSHELL)
def test_powershell_sees_through_a_link_with_a_dot(
    machine: Machine, command: str, rule: str
) -> None:
    _deny(machine.both("PowerShell", {"command": command}), rule)


@windows_only
@pytest.mark.parametrize(
    ("tool", "extra", "name", "rule"),
    [
        ("Grep", {"pattern": "x"}, "sub.", "no-secret-read"),
        ("Grep", {"pattern": "x"}, "keys.", "no-secret-read"),
        ("Grep", {"pattern": "x"}, "keys ", "no-secret-read"),
        ("Glob", {"pattern": "*"}, "keys.", "no-secret-read"),
        ("Grep", {"pattern": "x"}, "cc.", "no-agent-state-read"),
    ],
)
def test_a_directory_with_a_dot_is_still_scanned(
    machine: Machine, tool: str, extra: dict[str, str], name: str, rule: str
) -> None:
    _deny(machine.both(tool, {**extra, "path": f"{machine.project}\\{name}"}), rule)


ALLOW_STAYS_OUT = [
    ("Read", {"file_path": "{p}\\out\\notes.txt."}),
    ("Read", {"file_path": "{p}\\a.txt."}),
    ("Write", {"file_path": "{p}\\out\\new.", "content": "x"}),
    ("Grep", {"pattern": "x", "path": "{p}\\clean."}),
    ("Grep", {"pattern": "x", "path": "{p}\\out."}),
    ("Glob", {"pattern": "*", "path": "{p}\\clean."}),
    ("Bash", {"command": "cat clean/c.txt."}),
    ("Bash", {"command": "cd clean. && cat c.txt"}),
    ("Bash", {"command": "cd clean. && cd .. && cat a.txt"}),
    ("Bash", {"command": "cd out. && cat notes.txt"}),
    ("Bash", {"command": "ls clean."}),
]


@windows_only
@pytest.mark.parametrize(("tool", "template"), ALLOW_STAYS_OUT)
def test_looking_at_the_disk_gives_the_allow_side_nothing(
    machine: Machine, tool: str, template: dict[str, str]
) -> None:
    tool_input = {k: v.replace("{p}", machine.project) for k, v in template.items()}
    for verdict in machine.both(tool, tool_input):
        assert not allowed_by_a_rule(verdict), (tool_input, verdict)


@windows_only
def test_no_backend_asks_and_a_backend_is_asked_for_a_place_no_rule_names(
    machine: Machine,
) -> None:
    no_backend, backend = machine.both("Read", {"file_path": machine.project + "\\out\\notes.txt."})
    assert no_backend.decision == protocol.DECISION_ASK
    assert backend.sent == 1


@windows_only
def test_the_reading_that_keeps_the_dot_is_looked_at_too(machine: Machine) -> None:
    import _winapi  # type: ignore[import-not-found, unused-ignore]

    literal = "\\\\?\\" + machine.project + "\\lit."
    _winapi.CreateJunction(machine.home + "\\.ssh", literal)
    os.mkdir(machine.project + "\\lit")  # empty: the reading without the dot finds nothing there
    try:
        for tool, tool_input in [
            ("Read", {"file_path": machine.project + "\\lit.\\config"}),
            ("Bash", {"command": "cat lit./config"}),
            ("Bash", {"command": "cd lit. && cat config"}),
        ]:
            _deny(machine.both(tool, tool_input), "no-secret-read")
    finally:
        os.unlink(literal)


@windows_only
def test_every_form_of_a_path_unsure_of_its_reading_stays_uncertain(machine: Machine) -> None:
    import _winapi  # type: ignore[import-not-found, unused-ignore]

    literal = "\\\\?\\" + machine.project + "\\lit."
    _winapi.CreateJunction(machine.home + "\\.ssh", literal)
    try:
        actions = event.normalize_event(
            {
                "hook_event_name": "PreToolUse",
                "session_id": "s",
                "cwd": machine.project,
                "project_dir": machine.project,
                "tool_name": "Read",
                "tool_input": {"file_path": machine.project + "\\lit.\\config"},
            },
            platform="windows",
            env={"USERPROFILE": machine.home},
            home=machine.home,
        )
    finally:
        os.unlink(literal)
    refs = [ref for action in actions for ref in action.paths]
    assert any(ref.key.endswith("/.ssh/config") for ref in refs), refs
    assert all(ref.uncertain for ref in refs), refs
    assert all(ref.inside_project is None for ref in refs), refs


@windows_only
def test_a_resolved_path_stays_unsure_of_its_reading(machine: Machine) -> None:
    path = normalize_path(
        machine.project + "\\keys\\config.",
        cwd=machine.project,
        home=machine.home,
        env={},
        dialect="tool",
    )
    resolved = resolve_on_disk(path)
    assert resolved.key.endswith("/.ssh/config")
    assert resolved.uncertain


@windows_only
def test_only_a_path_unsure_of_its_reading_is_scanned(tmp_path: Path) -> None:
    key = normalize_path(str(tmp_path), cwd=None, home=None, dialect="tool", literal=True).key
    ref = PathRef(raw=str(tmp_path), key=key, flavor="windows", access="read", uncertain=True)
    unsure = ("trailing-dots-spaces", "trailing-dots-spaces-ambiguous")
    assert event._native_dir(ref.model_copy(update={"reasons": unsure})) is not None
    blocked = ("trailing-dots-spaces-ambiguous", "unresolved-variable:FOO")
    assert event._native_dir(ref.model_copy(update={"reasons": blocked})) is None
    assert event._native_dir(ref) is None


# ``cd keys.`` is denied for ``keys`` itself; these look at what is below a directory no rule names.
BELOW_A_CD = [
    ("Bash", "cd deep. && cat inner/config"),
    ("Bash", "cd deep./ && cat inner/config"),
    ("Bash", "cd 'deep ' && cat inner/config"),
    ("PowerShell", "Set-Location deep.; Get-Content inner\\config"),
]


@windows_only
@pytest.mark.usefixtures("powershell")
@pytest.mark.parametrize(("tool", "command"), BELOW_A_CD)
def test_what_is_below_a_cd_with_a_dot_is_looked_at(
    machine: Machine, tool: str, command: str
) -> None:
    _deny(machine.both(tool, {"command": command}), "no-secret-read")


@windows_only
def test_below_a_cd_the_reading_that_keeps_the_dot_counts_too(machine: Machine) -> None:
    import _winapi  # type: ignore[import-not-found, unused-ignore]

    literal = "\\\\?\\" + machine.project + "\\plain."
    os.mkdir(literal)
    _winapi.CreateJunction(machine.home + "\\.ssh", literal + "\\inner")
    try:
        _deny(
            machine.both("Bash", {"command": "cd plain. && cat inner/config"}),
            "no-secret-read",
        )
    finally:
        os.unlink(literal + "\\inner")
        os.rmdir(literal)


@windows_only
def test_the_kept_reading_of_a_plain_sibling_adds_nothing_and_asks(machine: Machine) -> None:
    sibling = "\\\\?\\" + machine.project + "\\plain."
    os.mkdir(sibling)
    try:
        verdict = decide(
            "Bash",
            {"command": "cat plain./a.txt"},
            policy=machine.no_backend,
            cwd=machine.project,
            home=machine.home,
            scan_disk=True,
        )
        assert verdict.decision == protocol.DECISION_ASK
    finally:
        os.rmdir(sibling)


def test_reading_only() -> None:
    assert reading_only(("trailing-dots-spaces", "trailing-dots-spaces-ambiguous"))
    assert reading_only(("ads-stripped", "stream-name-ambiguous"))
    assert reading_only(("cwd-uncertain", "trailing-dots-spaces-ambiguous", "resolved-on-disk"))
    assert not reading_only(())
    assert not reading_only(("ads-stripped",))  # certain: nothing to be unsure of
    assert not reading_only(("trailing-dots-spaces-ambiguous", "unresolved-variable:FOO"))
    assert not reading_only(("cwd-uncertain", "unresolved-variable:FOO"))
    assert not reading_only(("trailing-dots-spaces-ambiguous", "dynamic-word"))
    assert not reading_only(("trailing-dots-spaces-ambiguous", "drive-relative"))
    assert not reading_only(("trailing-dots-spaces-ambiguous", "device:NUL"))


@pytest.mark.parametrize(
    ("raw", "dialect", "expected"),
    [
        ("keys.\\config", "tool", "c:/proj/keys./config"),
        ("keys/config.", "bash", "c:/proj/keys/config."),
        ("C:\\proj\\keys \\x", "powershell", "c:/proj/keys /x"),
        ("\\\\?\\C:\\proj\\keys.\\x", "tool", "c:/proj/keys./x"),
        ("/c/proj/keys./x", "bash", "c:/proj/keys./x"),
        ("../work./x/../y", "bash", "c:/work./y"),
        ("a.txt.:s", "tool", "c:/proj/a.txt."),
        ("../work:s/x", "bash", f"c:/work{CYGWIN_COLON}s/x"),
        ("a:b", "bash", None),  # a drive-relative path, whose text is taken as such
        ("ab:c", "bash", f"c:/proj/ab{CYGWIN_COLON}c"),
        # Says nothing the key does not
        ("keys\\config", "tool", None),
        ("a.txt:s", "tool", None),
        # A colon before the last component: no program but Git Bash opens that
        ("sub:s\\x.", "tool", None),
        # Not a plain drive path
        ("\\\\srv\\share.\\x", "tool", None),
        ("\\\\c\\share.\\x", "tool", None),  # a server named c, not /c/share. on drive C
        ("\\\\.\\pipe\\x.", "tool", None),
        ("$FOO\\x.", "tool", None),
    ],
)
def test_reading_text(raw: str, dialect: Any, expected: str | None) -> None:
    assert reading_text(raw, cwd=PROJECT, home=HOME, env={}, dialect=dialect) == expected


# --- RV-2: in Git Bash a colon is part of the name ------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "mkdir ../proj:s",
        "touch ../proj:s/new.txt",
        "cat ../proj:s/left.txt",
        "cd ../proj:s && cat left.txt",
        "cd ../proj:s && ls",
        "ls ../proj:s",
        "ls C:/proj:s",
        "ls /c/proj:s",
        "cat ../proj::\\$DATA/left.txt",
        "cat a.txt:s",
    ],
)
def test_a_colon_in_bash_is_not_a_stream_of_the_project(command: str) -> None:
    verdict = decide("Bash", {"command": command})
    assert not allowed_by_a_rule(verdict), verdict


@pytest.mark.parametrize(
    "raw",
    [
        "C:\\proj:s\\a.txt",
        "..\\proj:s\\a.txt",
        "C:\\proj\\sub:s\\a.txt",
        "C:\\proj::$DATA\\a.txt",
        "\\\\?\\C:\\proj:s\\a.txt",
        ":\\a.txt",
        "1a:\\a.txt",
        "C1:\\a.txt",
    ],
)
@pytest.mark.parametrize("dialect", ["tool", "powershell", "bash"])
def test_a_colon_before_the_last_component_is_uncertain(raw: str, dialect: Any) -> None:
    root = normalize_path(PROJECT, cwd=None, home=None, dialect="tool", literal=True)
    path = normalize_path(raw, cwd=PROJECT, home=HOME, env={}, dialect=dialect)
    assert path.uncertain, path
    assert inside_project(path, root) is None, path


@pytest.mark.parametrize("dialect", ["tool", "powershell"])
@pytest.mark.parametrize("raw", ["C:\\proj\\a.txt:s", "C:\\proj\\a.txt::$DATA", "a.txt:s:$DATA"])
def test_a_stream_of_the_last_component_stays_certain_outside_bash(raw: str, dialect: Any) -> None:
    path = normalize_path(raw, cwd=PROJECT, home=HOME, env={}, dialect=dialect)
    assert path.key == "c:/proj/a.txt"
    assert not path.uncertain
    assert path.reasons == ("ads-stripped",)


@pytest.mark.parametrize(
    "tool_input",
    [{"file_path": "C:\\proj\\a.txt:s"}, {"file_path": "C:\\proj\\a.txt::$DATA"}],
)
def test_a_file_tool_may_still_read_a_stream_of_a_project_file(tool_input: dict[str, str]) -> None:
    assert decide("Read", tool_input).decided_by == "rule:read-inside-project"


@pytest.mark.parametrize(
    ("tool", "tool_input", "rule"),
    [
        ("Read", {"file_path": "C:\\Users\\bob\\.ssh:x\\id_rsa"}, "no-secret-read"),
        ("Read", {"file_path": "C:\\proj\\.env:s"}, "no-secret-read"),
        ("Bash", {"command": "cat ../proj:s/.env"}, "no-secret-read"),
        ("Bash", {"command": "cat ~/.ssh:x/id_rsa"}, "no-secret-read"),
    ],
)
def test_a_deny_rule_still_matches_the_stripped_name(
    tool: str, tool_input: dict[str, str], rule: str
) -> None:
    verdict = decide(tool, tool_input)
    assert verdict.decision == protocol.DECISION_DENY, verdict
    assert rule in verdict.decided_by


def test_the_key_of_a_cd_into_a_colon_is_the_name_git_bash_gives() -> None:
    """Below ``cd ../proj:s`` the place is known, and it is not the project."""
    verdict = decide("Bash", {"command": "cd ../proj:s && cat .env"})
    assert verdict.decision == protocol.DECISION_DENY


@windows_only
def test_a_junction_with_a_colon_in_git_bash_is_seen(machine: Machine) -> None:
    import _winapi  # type: ignore[import-not-found, unused-ignore]

    link = f"{machine.project}{CYGWIN_COLON}s"
    _winapi.CreateJunction(machine.home + "\\.ssh", link)
    try:
        for command in ("cat ../work:s/config", "cd ../work:s && cat config"):
            _deny(machine.both("Bash", {"command": command}), "no-secret-read")
    finally:
        os.unlink(link)


# --- git reads its own pathspec magic ------------------------------------------------------------
# Revision 13 first called every colon in Git Bash a name of its own. The full run caught what that
# did to ordinary commands: ``git diff -- ':!x'`` went from allowed to a question. Git parses these
# words and never opens them (measured with real git in both shells).


PATHSPEC_MAGIC = [
    "git add :/",
    "git add ':!x'",
    "git add -- ':!x' .",
    "git add ':^x'",
    "git diff -- ':!x'",
    "git diff -- . ':!x'",
    "git diff -- ':(exclude)x'",
    "git diff HEAD -- ':/'",
    "git diff --stat -- ':!eval/results'",
    "git log -- ':/src'",
    "git log -- ':!x'",
    "git log --oneline -- ':(top)src'",
    "git status -- ':!x'",
    "git status --short -- ':!eval'",
    "git stash push -- ':!x'",
    "git commit -m x -- ':!y'",
]


@pytest.mark.parametrize("command", PATHSPEC_MAGIC)
def test_git_bash_leaves_the_magic_of_git_to_git(command: str) -> None:
    assert allowed_by_a_rule(decide("Bash", {"command": command})), command


@windows_only
@pytest.mark.parametrize("command", PATHSPEC_MAGIC)
def test_powershell_leaves_the_magic_of_git_to_git(powershell: None, command: str) -> None:
    assert allowed_by_a_rule(decide("PowerShell", {"command": command})), command


def _path_refs(command: str) -> list[PathRef]:
    actions = event.normalize_event(
        {
            "hook_event_name": "PreToolUse",
            "session_id": "s",
            "cwd": PROJECT,
            "project_dir": PROJECT,
            "tool_name": "Bash",
            "tool_input": {"command": command},
        },
        platform="windows",
        env={"USERPROFILE": HOME},
        home=HOME,
    )
    return [ref for action in actions for ref in action.paths]


@pytest.mark.parametrize(
    ("command", "keys"),
    [
        ("git diff -- ':!x'", {"c:/proj"}),
        ("git diff -- ':/'", {"c:/proj"}),
        ("git log -- ':/src'", {"c:/proj/src"}),
        # revision 16: the long form keeps its path, and an exclusion is the whole repository (git
        # acts on everything but that path, measured); revision 13 pinned ".", "./b" and "./b"
        ("git log -- ':(top)src'", {"c:/proj/src"}),
        ("git diff -- ':!a/b'", {"c:/proj"}),
        ("git diff -- ':!a\\b'", {"c:/proj"}),
        ("git rm ':/a.py'", {"c:/proj/a.py"}),
        ("git restore ':/a.py'", {"c:/proj/a.py"}),
        ("git clean ':!x'", {"c:/proj"}),
        ("git archive HEAD -- ':/a.py'", {"c:/proj/a.py"}),
        ("git -C sub diff -- ':!x'", {"c:/proj", "c:/proj/sub"}),
        # Spec revision 17: a ``:`` word before ``--`` is read as a pathspec too, the same as after
        # it (relative to the cwd and to the -C directory; listing one more only costs a check)
        ("git -C sub checkout ':/x'", {"c:/proj/sub", "c:/proj/sub/x", "c:/proj/x"}),
        ("git -C sub checkout -- ':/x'", {"c:/proj/sub", "c:/proj/sub/x", "c:/proj/x"}),
    ],
)
def test_the_magic_reads_as_git_reads_it(command: str, keys: set[str]) -> None:
    refs = _path_refs(command)
    assert {ref.key for ref in refs} == keys, command
    assert not any(ref.uncertain for ref in refs), command


@pytest.mark.parametrize(
    "command",
    [
        # git takes these as plain names, so the colon is still a question of which reading
        "git diff --no-index ':x' y",
        "git apply ':x'",
        "git hash-object ':x'",
        "git blame -- ':/a.py'",
        "git mv ':x' y",
        "git update-index ':x'",
        "git checkout-index ':x'",
        "git --git-dir=:x/.git status",
        "git --work-tree=:x status",
        "git -C :x status",
        "git add --pathspec-from-file=:x",
        "git bundle create ':x' HEAD",
        "git diff -- a:b",
        "git add a:b",
        "git add sub:s/a.py",
        # not git
        "cat ':x'",
        "ls ':/'",
        "head ':!x'",
    ],
)
def test_a_colon_git_does_not_read_as_magic_stays_uncertain(command: str) -> None:
    assert not allowed_by_a_rule(decide("Bash", {"command": command})), command
    assert any(ref.uncertain for ref in _path_refs(command)), command


@pytest.mark.parametrize(
    "command",
    ["git add ':/../x'", "git diff -- ':/../x'", "git log -- ':/../x/y'", "git diff -- ':/../x/y'"],
)
def test_a_pathspec_that_climbs_out_is_not_allowed(command: str) -> None:
    assert not allowed_by_a_rule(decide("Bash", {"command": command})), command


@pytest.mark.parametrize(
    "command",
    # (``git add ':^x/.env'`` was here: it excludes x/.env and adds the rest, revision 16; see
    # test_m3a_pathspec_and_dotted_names.py for that and for the long forms)
    ["git diff -- ':/.env'", "git log -p -- ':/.env'", "git add ':/.env'", "git add ':(top).env'"],
)
def test_a_protected_name_in_a_pathspec_is_still_seen(command: str) -> None:
    assert decide("Bash", {"command": command}).decision == protocol.DECISION_DENY, command


@windows_only
def test_a_junction_below_a_pathspec_is_still_seen(machine: Machine) -> None:
    _deny(machine.both("Bash", {"command": "git diff -- ':/keys/config'"}), "no-secret-read")


def test_the_magic_is_noted_for_the_whole_repository_check() -> None:
    def noted(*words: str) -> bool:
        info = programs.classify("git", [Word(w) for w in words], shell="bash")  # noqa: S604
        return info.pathspec_magic

    assert noted("add", ":/")
    assert noted("add", "--", ":!x")
    assert not noted("add", "a.py")
    assert not noted("apply", ":x")


@pytest.mark.parametrize(
    ("word", "text"),
    [
        (Word(":/$X", expands=True), "./$X"),
        (Word(":/*.py", glob=True), "./*.py"),
        (Word(":/a b", quoted=True), "./a b"),
    ],
)
def test_the_magic_keeps_what_the_word_was(word: Word, text: str) -> None:
    info = programs.classify("git", [Word("log"), Word("--"), word], shell="bash")  # noqa: S604
    seen = info.paths[0][0]
    assert seen == Word(text, word.expands, word.glob, word.quoted)


# --- RV-3: a server name that only folds to this machine ------------------------------------------


REMOTE_ADMIN = [
    f"\\\\localho{LONG_S}t\\c$\\proj\\a.txt",
    f"\\\\LOCALHO{LONG_S}T\\C$\\proj\\a.txt",
    f"\\\\my{KELVIN}pc\\c$\\proj\\a.txt",
    f"\\\\de{LONG_S}k\\c$\\proj\\a.txt",
]


@pytest.mark.parametrize("raw", REMOTE_ADMIN)
def test_a_server_that_only_folds_to_this_machine_is_not_a_local_drive(raw: str) -> None:
    root = normalize_path(PROJECT, cwd=None, home=None, dialect="tool", literal=True)
    env = {"COMPUTERNAME": "DESK"}
    path = normalize_path(raw, cwd=PROJECT, home=HOME, env=env, dialect="tool")
    assert path.key.startswith("//"), path
    assert path.uncertain
    assert "admin-share" in path.reasons
    assert "admin-share-local" not in path.reasons
    assert inside_project(path, root) is None


@pytest.mark.parametrize(
    "raw",
    [
        "\\\\localhost\\c$\\proj\\a.txt",
        "\\\\LocalHost\\C$\\proj\\a.txt",
        "\\\\127.0.0.1\\c$\\proj\\a.txt",
    ],
)
def test_the_real_spellings_of_this_machine_are_still_a_local_drive(raw: str) -> None:
    path = normalize_path(raw, cwd=PROJECT, home=HOME, env={}, dialect="tool")
    assert path.key == "c:/proj/a.txt"
    assert not path.uncertain
    assert path.reasons == ("admin-share-local",)


def test_the_computer_name_still_counts_in_any_case() -> None:
    path = normalize_path(
        "\\\\my-PC\\c$\\proj\\a.txt", cwd=PROJECT, home=HOME, env={"COMPUTERNAME": "MY-pc"}
    )
    assert path.key == "c:/proj/a.txt"
    assert allowed_by_a_rule(decide("Read", {"file_path": "\\\\mypc\\c$\\proj\\a.txt"}))


def test_a_computer_name_with_such_a_character_is_still_this_machine() -> None:
    computer = "WEI\u00df"
    path = normalize_path(
        "\\\\wei\u00df\\c$\\proj\\a.txt",
        cwd=PROJECT,
        home=HOME,
        env={"COMPUTERNAME": computer},
    )
    assert path.key == "c:/proj/a.txt"
    mine = decide("Read", {"file_path": "\\\\wei\u00df\\share\\x.txt"}, computer=computer)
    assert "net-" not in mine.decided_by
    other = decide("Read", {"file_path": "\\\\weiss\\share\\x.txt"}, computer=computer)
    assert "net-allowlist" in other.decided_by


# Named by a rule only from the home, and only a pattern that climbs carries a location of its own:
# nothing but the directory it starts from can make these match.
@pytest.mark.parametrize(
    "pattern",
    [
        "../AppData/Roaming/Microsoft/Credentials/*",
        "../AppData/Local/Google/Chrome/User Data/*",
    ],
)
def test_a_glob_that_climbs_from_a_directory_with_a_dot_still_lands(pattern: str) -> None:
    # The path is not the working directory: without it the pattern would start from the project
    plain = decide("Glob", {"pattern": pattern, "path": HOME + "\\sub"})
    dotted = decide("Glob", {"pattern": pattern, "path": HOME + "\\sub."})
    assert plain.decision == protocol.DECISION_DENY, plain
    assert dotted.decision == protocol.DECISION_DENY, dotted


@pytest.mark.parametrize("policy", [NO_BACKEND, BACKEND], ids=["no-backend", "backend"])
@pytest.mark.parametrize(
    "raw",
    [
        *REMOTE_ADMIN,
        f"\\\\localho{LONG_S}t\\share\\x.txt",
        f"\\\\w{LONG_S}l$\\Ubuntu\\x.txt",
        f"\\\\w{LONG_S}l.localhost\\Ubuntu\\x.txt",
        "\\\\\uff11\uff12\uff17.0.0.1\\share\\x.txt",  # IDNA reads the full-width digits as 127
        f"\\\\pypi.org{LONG_S}\\share\\x.txt",
    ],
)
@pytest.mark.parametrize(
    ("tool", "form"),
    [
        ("Read", lambda p: {"file_path": p}),
        ("Write", lambda p: {"file_path": p, "content": "x"}),
        ("Bash", lambda p: {"command": f"cat '{p}'"}),
    ],
)
def test_a_server_that_only_looks_local_is_an_unknown_destination(
    raw: str, policy: Policy, tool: str, form: Any
) -> None:
    verdict = decide(tool, form(raw), policy=policy)
    assert verdict.decision == protocol.DECISION_ASK, verdict
    assert "net-unknown-destination" in verdict.decided_by, verdict
    assert verdict.sent == 0


def test_a_plain_remote_server_still_goes_to_the_allowlist_rule() -> None:
    verdict = decide("Read", {"file_path": "\\\\evil\\share\\x.txt"})
    assert verdict.decision == protocol.DECISION_ASK
    assert "net-allowlist" in verdict.decided_by


def test_the_module_exports_the_reading_helpers() -> None:
    assert {"reading_only", "reading_text"} <= set(paths.__all__)
