"""The current session's tool-results directory: ``~/.claude/projects/<slug>/<id>/tool-results``.

Claude Code saves a tool output too long for the conversation there and tells the agent to read
it; ``no-agent-state-read`` used to deny that read (holdout h1, ``hold-real-9e27e3-0005``). The
path layer marks a path in THIS session's directory (``PathRef.in_session_tool_results``), the deny
rule for transcripts skips it (``except_session_tool_results``) and the default policy lets the
file tools read it (``path_in_session_tool_results``). The verdicts of the shipped policies are in
their ``tests:``.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from boundkeep.normalize import paths
from boundkeep.normalize.model import Action, PathRef
from boundkeep.policy import Match, Rule, match_rule

SID = "19513824-5f23-476c-bd11-f2f49fb38457"
OTHER = "29513824-5f23-476c-bd11-f2f49fb38457"
WIN_HOME = "C:\\Users\\testuser"
POSIX_HOME = "/home/testuser"


def _norm(text: str) -> paths.NormPath:
    return paths.normalize_path(text, cwd=None, home=None, dialect="tool", literal=True)


def _dir(platform: str, home: str = "") -> paths.SessionDir:
    found = paths.tool_results_for(
        SID,
        platform,  # type: ignore[arg-type]
        home or (WIN_HOME if platform == "windows" else POSIX_HOME),
    )
    assert found is not None
    return found


# ---------------------------------------------------------------------------- the path layer

WIN_IN = [
    f"C:\\Users\\testuser\\.claude\\projects\\e--proj\\{SID}\\tool-results",
    f"C:\\Users\\testuser\\.claude\\projects\\e--proj\\{SID}\\tool-results\\b50fdq7fi.txt",
    f"C:\\Users\\testuser\\.claude\\projects\\E--boundkeep-boundkeep\\{SID}\\tool-results\\a\\b.txt",
    f"c:\\users\\TESTUSER\\.CLAUDE\\Projects\\x\\{SID.upper()}\\TOOL-RESULTS\\b.txt",
]
WIN_OUT = [
    f"C:\\Users\\testuser\\.claude\\projects\\e--proj\\{OTHER}\\tool-results\\x.txt",
    f"C:\\Users\\testuser\\.claude\\projects\\e--proj\\{SID}.jsonl",
    f"C:\\Users\\testuser\\.claude\\projects\\e--proj\\{SID}",
    f"C:\\Users\\testuser\\.claude\\projects\\e--proj\\{SID}\\subagents\\agent-a.jsonl",
    f"C:\\Users\\testuser\\.claude\\projects\\e--proj\\{SID}\\tool-results2\\x.txt",
    f"C:\\Users\\testuser\\.claude\\projects\\{SID}\\tool-results\\x.txt",
    f"C:\\Users\\testuser\\.claude\\e--proj\\{SID}\\tool-results\\x.txt",
    f"C:\\Users\\other\\.claude\\projects\\e--proj\\{SID}\\tool-results\\x.txt",
    f"D:\\Users\\testuser\\.claude\\projects\\e--proj\\{SID}\\tool-results\\x.txt",
    f"C:\\Users\\testuser\\.claude\\projects\\e--proj\\{SID}\\tool-results\\..\\..\\x.jsonl",
    f"C:\\Users\\testuser\\AppData\\Local\\Temp\\claude\\e--proj\\{SID}\\scratchpad\\x.txt",
    "tool-results\\x.txt",
]


@pytest.mark.parametrize("text", WIN_IN)
def test_windows_paths_inside_the_session_directory(text: str) -> None:
    assert _dir("windows").contains(_norm(text), resolved=False)


@pytest.mark.parametrize("text", WIN_OUT)
def test_windows_paths_outside_the_session_directory(text: str) -> None:
    assert not _dir("windows").contains(_norm(text), resolved=False)


def test_posix_names_are_case_sensitive() -> None:
    found = _dir("posix")
    base = f"/home/testuser/.claude/projects/-home-testuser-proj/{SID}/tool-results/x.txt"
    assert found.contains(_norm(base), resolved=False)
    for wrong in (".Claude", "Projects", "Tool-Results"):
        old = wrong.lower() if wrong != ".Claude" else ".claude"
        assert not found.contains(_norm(base.replace(old, wrong, 1)), resolved=False), wrong
    assert not found.contains(_norm(base.replace(SID, OTHER)), resolved=False)


@pytest.mark.parametrize(
    ("session", "home"),
    [
        (None, WIN_HOME),
        ("policy-test", WIN_HOME),
        (SID + "\n", WIN_HOME),
        (SID, None),
        (SID, "   "),
        (SID, "\\\\server\\share\\testuser"),  # a network home is never a root
        (SID, "C:\\Users\\*"),  # a pattern character
        (SID, "Users\\testuser"),  # relative
    ],
)
def test_no_tool_results_directory_when_in_doubt(session: str | None, home: str | None) -> None:
    assert paths.tool_results_for(session, "windows", home) is None


def test_the_scratchpad_is_unchanged_by_the_shared_code() -> None:
    sp = paths.scratchpad_for(
        SID, "windows", {"TEMP": "C:\\Users\\testuser\\AppData\\Local\\Temp"}, WIN_HOME
    )
    assert sp is not None
    inside = f"C:\\Users\\testuser\\AppData\\Local\\Temp\\claude\\e--proj\\{SID}\\scratchpad\\x"
    assert sp.contains(_norm(inside), resolved=False)
    tool_results = f"C:\\Users\\testuser\\.claude\\projects\\e--proj\\{SID}\\tool-results\\x"
    assert not sp.contains(_norm(tool_results), resolved=False)


# ---------------------------------------------------------------------------- schema and matcher


def test_except_session_tool_results_only_qualifies_a_glob() -> None:
    with pytest.raises(ValidationError, match="only qualifies 'path_glob'"):
        Match.model_validate({"except_session_tool_results": True})
    with pytest.raises(ValidationError):
        Match.model_validate({"path_glob": ["**"], "except_session_tool_results": False})
    Match.model_validate(
        {"path_glob": ["**/.claude/projects/**"], "except_session_tool_results": True},
        context={"home": POSIX_HOME},
    )


def _ref(key: str, *, inside: bool, access: str = "read") -> PathRef:
    return PathRef(
        raw=key,
        key=key,
        flavor="posix",
        access=access,  # type: ignore[arg-type]
        inside_project=False,
        in_session_tool_results=inside,
    )


def _read(*refs: PathRef, tool: str = "Read") -> Action:
    return Action(tool=tool, platform="posix", paths=tuple(refs))


def _rule(match: dict[str, Any], action: str, tool: list[str] | None = None) -> Rule:
    data: dict[str, Any] = {"id": "r", "match": match, "action": action}
    if tool is not None:
        data["tool"] = tool
    if action != "allow":
        data["reason"] = "because"
    return Rule.model_validate(data, context={"home": POSIX_HOME})


DENY = {
    "path_glob": ["**/.claude/projects/**"],
    "access": "read",
    "except_session_tool_results": True,
}
ALLOW = {"path_in_session_tool_results": True, "paths_read_only": True}
T = f"/home/testuser/.claude/projects/p/{SID}/tool-results/x.txt"
TRANSCRIPT = f"/home/testuser/.claude/projects/p/{OTHER}.jsonl"


def test_the_deny_rule_skips_only_the_forms_shown_to_be_in_the_directory() -> None:
    deny = _rule(DENY, "deny")
    assert not match_rule(deny, _read(_ref(T, inside=True)), platform="posix")
    # the same name without the mark (another session, a doubt): denied
    assert match_rule(deny, _read(_ref(T, inside=False)), platform="posix")
    # a link in the directory whose resolved form is a transcript: that form is still checked
    linked = _read(_ref(T, inside=True), _ref(TRANSCRIPT, inside=False))
    assert match_rule(deny, linked, platform="posix")
    # without the qualifier the glob sees every path
    plain = _rule({"path_glob": ["**/.claude/projects/**"], "access": "read"}, "deny")
    assert match_rule(plain, _read(_ref(T, inside=True)), platform="posix")


def test_the_allow_rule_needs_every_path_inside_and_only_reads() -> None:
    allow = _rule(ALLOW, "allow", ["Read", "Grep", "Glob"])
    assert match_rule(allow, _read(_ref(T, inside=True)), platform="posix")
    assert not match_rule(allow, _read(), platform="posix")  # no path at all
    mixed = _read(_ref(T, inside=True), _ref("/home/testuser/x", inside=False))
    assert not match_rule(allow, mixed, platform="posix")
    write = _read(_ref(T, inside=True, access="write"))
    assert not match_rule(allow, write, platform="posix")
    unknown = _read(_ref(T, inside=True, access="unknown"))
    assert not match_rule(allow, unknown, platform="posix")
    assert not match_rule(allow, _read(_ref(T, inside=True), tool="Write"), platform="posix")


def test_the_hard_link_and_pattern_guards_clear_the_mark() -> None:
    from boundkeep.normalize import event

    hard = paths.NormPath(
        raw=T, key=T, flavor="posix", absolute=True, uncertain=False, reasons=(paths.HARD_LINKED,)
    )
    (cleared,) = event._mark_hard_linked([_ref(T, inside=True)], hard)
    assert not cleared.in_session_tool_results
    (plain,) = event._plain_operands([_ref(T.replace("x.txt", "[x].txt"), inside=True)])
    assert not plain.in_session_tool_results
    (kept,) = event._plain_operands([_ref(T, inside=True)])
    assert kept.in_session_tool_results
