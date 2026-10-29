"""Claude Code's auto memory for the current project: ``~/.claude/projects/<slug>/memory``.

Claude Code keeps notes for itself there and reads them back throughout a session;
``no-session-transcript-read`` denied that read (holdout h2, docs/reports/holdout-h2.md section 7).
The path layer marks a path in THIS project's memory directory (``PathRef.in_project_memory``), the
deny rule for transcripts skips it (``except_project_memory``) and the default policy lets the
file tools read it (``path_in_project_memory``); writing there is asked about. The verdicts of the
shipped policies are in their ``tests:``.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from boundkeep.normalize import paths
from boundkeep.normalize.model import Action, PathRef
from boundkeep.policy import Match, Rule, match_rule

WIN_HOME = "C:\\Users\\testuser"
POSIX_HOME = "/home/testuser"


def _norm(text: str) -> paths.NormPath:
    return paths.normalize_path(text, cwd=None, home=None, dialect="tool", literal=True)


def _root(text: str) -> paths.NormPath:
    root = _norm(text)
    assert root.absolute
    assert not root.uncertain
    return root


# ---------------------------------------------------------------------------- the project slug


@pytest.mark.parametrize(
    ("text", "slug"),
    [
        ("E:\\boundkeep", "E--boundkeep"),
        ("e:\\boundkeep", "e--boundkeep"),
        (
            "C:\\Users\\a\\AppData\\Local\\Claude-Data\\claude_x",
            "C--Users-a-AppData-Local-Claude-Data-claude-x",
        ),
        ("E:\\2026项目", "E--2026--"),
        ("/home/testuser/proj", "-home-testuser-proj"),
        ("/home/testuser/my.proj", "-home-testuser-my-proj"),
    ],
)
def test_project_slug_matches_claude_codes_directory_names(text: str, slug: str) -> None:
    assert paths.project_slug(text) == slug


# ---------------------------------------------------------------------------- memory_for


def _memory(platform: str, project: str, home: str | None = None) -> paths.SessionDir:
    found = paths.memory_for(
        _root(project),
        platform,  # type: ignore[arg-type]
        home or (WIN_HOME if platform == "windows" else POSIX_HOME),
    )
    assert found is not None
    return found


W = "C:\\Users\\testuser\\.claude\\projects\\"


@pytest.mark.parametrize(
    "text",
    [
        W + "C--Users-testuser-proj\\memory",
        W + "C--Users-testuser-proj\\memory\\MEMORY.md",
        W + "c--users-testuser-proj\\memory\\user_role.md",  # VS Code spells the drive in lowercase
        W + "C--Users-testuser-proj\\memory\\sub\\x.md",
        "c:\\users\\TESTUSER\\.CLAUDE\\Projects\\C--USERS-TESTUSER-PROJ\\MEMORY\\x.md",
    ],
)
def test_windows_paths_in_the_project_memory(text: str) -> None:
    assert _memory("windows", "C:\\Users\\testuser\\proj").contains(_norm(text), resolved=False)


@pytest.mark.parametrize(
    "text",
    [
        W + "C--Users-testuser-other\\memory\\MEMORY.md",  # another project
        W + "C--Users-testuser\\memory\\MEMORY.md",  # the home is not a project
        W + "C--Users\\memory\\MEMORY.md",
        W + "C-\\memory\\MEMORY.md",  # the drive root is not a project either
        W + "C--Users-testuser-proj\\memory2\\x.md",
        W + "C--Users-testuser-proj\\x.jsonl",
        W + "C--Users-testuser-proj\\memory\\..\\x.jsonl",
        W + "C--Users-testuser-proj\\aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\\memory\\x.md",
        "C:\\Users\\other\\.claude\\projects\\C--Users-testuser-proj\\memory\\x.md",
        "D:\\Users\\testuser\\.claude\\projects\\C--Users-testuser-proj\\memory\\x.md",
        "memory\\x.md",
    ],
)
def test_windows_paths_outside_the_project_memory(text: str) -> None:
    assert not _memory("windows", "C:\\Users\\testuser\\proj").contains(_norm(text), resolved=False)


def test_the_git_root_above_the_project_counts_but_not_a_sibling() -> None:
    found = _memory("windows", "C:\\Users\\testuser\\work\\repo\\sub")
    for slug in (
        "C--Users-testuser-work-repo-sub",
        "C--Users-testuser-work-repo",
        "C--Users-testuser-work",
    ):
        assert found.contains(_norm(W + slug + "\\memory\\MEMORY.md"), resolved=False), slug
    for slug in ("C--Users-testuser-work-other", "C--Users-testuser", "C--Users"):
        assert not found.contains(_norm(W + slug + "\\memory\\MEMORY.md"), resolved=False), slug


def test_a_project_outside_the_home_stops_at_the_drive_root() -> None:
    found = _memory("windows", "E:\\FYP\\proposal")
    assert found.contains(_norm(W + "E--FYP-proposal\\memory\\x.md"), resolved=False)
    assert found.contains(_norm(W + "E--FYP\\memory\\x.md"), resolved=False)
    assert not found.contains(_norm(W + "E-\\memory\\x.md"), resolved=False)


def test_posix_memory_names_are_case_sensitive() -> None:
    found = _memory("posix", "/home/testuser/proj")
    base = "/home/testuser/.claude/projects/-home-testuser-proj/memory/MEMORY.md"
    assert found.contains(_norm(base), resolved=False)
    assert not found.contains(_norm(base.replace("-home-", "-Home-")), resolved=False)
    assert not found.contains(_norm(base.replace("memory", "Memory")), resolved=False)
    assert not found.contains(_norm(base.replace("proj", "other")), resolved=False)


@pytest.mark.parametrize(
    ("project", "home"),
    [
        (None, WIN_HOME),
        ("C:\\Users\\testuser\\proj", None),
        ("C:\\Users\\testuser\\proj", "   "),
        ("C:\\Users\\testuser\\proj", "\\\\server\\share\\testuser"),
        ("C:\\Users\\testuser", WIN_HOME),  # the home itself: no project below it
        ("C:\\", WIN_HOME),
    ],
)
def test_no_memory_directory_when_in_doubt(project: str | None, home: str | None) -> None:
    root = None if project is None else _norm(project)
    assert paths.memory_for(root, "windows", home) is None


def test_an_uncertain_project_has_no_memory_directory() -> None:
    root = paths.normalize_path("$X\\proj", cwd=None, home=None, dialect="tool")
    assert root.uncertain
    assert paths.memory_for(root, "windows", WIN_HOME) is None


def test_the_other_session_directories_still_take_any_slug() -> None:
    sid = "19513824-5f23-476c-bd11-f2f49fb38457"
    results = paths.tool_results_for(sid, "windows", WIN_HOME)
    assert results is not None
    assert results.slugs is None
    assert results.contains(_norm(W + f"anything\\{sid}\\tool-results\\x.txt"), resolved=False)


# ---------------------------------------------------------------------------- schema


def test_except_project_memory_only_qualifies_a_glob() -> None:
    with pytest.raises(ValidationError, match="only qualifies 'path_glob'"):
        Match.model_validate({"except_project_memory": True}, context={"home": POSIX_HOME})
    Match.model_validate(
        {"path_glob": ["**/.claude/projects/**"], "except_project_memory": True},
        context={"home": POSIX_HOME},
    )
    with pytest.raises(ValidationError, match="never touch file paths"):
        Rule.model_validate(
            {
                "id": "r",
                "tool": ["WebSearch"],
                "match": {"path_in_project_memory": True},
                "action": "deny",
                "reason": "x",
            },
            context={"home": POSIX_HOME},
        )


# ---------------------------------------------------------------------------- matcher


def _ref(key: str, **fields: Any) -> PathRef:
    data: dict[str, Any] = {
        "raw": key,
        "key": key,
        "flavor": "posix",
        "access": "read",
        "inside_project": False,
    }
    data.update(fields)
    return PathRef(**data)


def _rule(match: dict[str, Any], action: str, tool: list[str] | None = None) -> Rule:
    data: dict[str, Any] = {"id": "r", "match": match, "action": action}
    if tool is not None:
        data["tool"] = tool
    if action != "allow":
        data["reason"] = "because"
    return Rule.model_validate(data, context={"home": POSIX_HOME})


def _read(*refs: PathRef) -> Action:
    return Action(tool="Read", platform="posix", paths=tuple(refs))


MEMORY = "/home/testuser/.claude/projects/-home-testuser-proj/memory/MEMORY.md"
TRANSCRIPT = "/home/testuser/.claude/projects/-home-testuser-proj/s.jsonl"


def test_the_transcript_rule_skips_only_forms_in_the_project_memory() -> None:
    deny = _rule(
        {"path_glob": ["**/.claude/projects/**"], "access": "read", "except_project_memory": True},
        "deny",
    )
    assert not match_rule(deny, _read(_ref(MEMORY, in_project_memory=True)), platform="posix")
    # the same name without the mark (another project, a doubt): denied
    assert match_rule(deny, _read(_ref(MEMORY)), platform="posix")
    # a link in the memory directory whose resolved form is a transcript: that form still counts
    linked = _read(_ref(MEMORY, in_project_memory=True), _ref(TRANSCRIPT))
    assert match_rule(deny, linked, platform="posix")


def test_the_memory_allow_rule_needs_every_path_inside_and_only_reads() -> None:
    allow = _rule(
        {"path_in_project_memory": True, "paths_read_only": True}, "allow", ["Read", "Grep", "Glob"]
    )
    marked = _ref(MEMORY, in_project_memory=True)
    assert match_rule(allow, _read(marked), platform="posix")
    assert not match_rule(allow, _read(), platform="posix")  # no path at all
    assert not match_rule(allow, _read(marked, _ref("/home/testuser/x")), platform="posix")
    write = _ref(MEMORY, access="write", in_project_memory=True)
    assert not match_rule(allow, _read(write), platform="posix")
    unknown = _ref(MEMORY, access="unknown", in_project_memory=True)
    assert not match_rule(allow, _read(unknown), platform="posix")


def test_the_hard_link_and_pattern_guards_clear_the_memory_mark() -> None:
    from boundkeep.normalize import event

    hard = paths.NormPath(
        raw=MEMORY,
        key=MEMORY,
        flavor="posix",
        absolute=True,
        uncertain=False,
        reasons=(paths.HARD_LINKED,),
    )
    (cleared,) = event._mark_hard_linked([_ref(MEMORY, in_project_memory=True)], hard)
    assert not cleared.in_project_memory
    (plain,) = event._plain_operands(
        [_ref(MEMORY.replace("MEMORY", "[M]"), in_project_memory=True)]
    )
    assert not plain.in_project_memory
    (kept,) = event._plain_operands([_ref(MEMORY, in_project_memory=True)])
    assert kept.in_project_memory
