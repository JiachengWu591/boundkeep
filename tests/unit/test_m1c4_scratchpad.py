"""M1c-4: the session scratchpad (``path_in_scratchpad`` + ``allow-session-scratchpad``).

Claude Code keeps a per-session scratchpad for the agent's intermediate files:
``<temp dir>/claude/<project slug>/<session id>/scratchpad``, and the hook event's ``session_id`` is
that session-id directory name. This file pins

* the normalizer: ``PathRef.in_scratchpad`` is True ONLY for a path (every form of it: lexical and
  link-resolved) inside the CURRENT session's scratchpad below the daemon's temp directory;
* the match field ``path_in_scratchpad`` (matcher, schema, docs) and the default-only rule
  ``allow-session-scratchpad`` (file tools only: no shell command gets an allow because of it);
* the safety invariants: another session, another temp directory, ``..``, a malformed or hostile
  session id, ``scratchpad2``, the parents of the root, uncertain paths, links that lead out, and
  every protected name inside the scratchpad stay exactly as strict as before. The differential
  tests compare against the policy of the ``m1c3-done`` tag when git can show it.

No command is ever executed: shell commands are only normalized.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
from collections.abc import Callable
from functools import cache
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from boundkeep import policycli
from boundkeep.daemon import pipeline
from boundkeep.normalize import paths
from boundkeep.normalize.model import Action, PathRef
from boundkeep.policy import (
    Match,
    Policy,
    PolicyError,
    Rule,
    evaluate,
    explain_rule,
    match_rule,
    parse_policy_text,
)

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"
CORPUS_DIR = ROOT / "tests" / "corpus"
NEW_CORPUS = CORPUS_DIR / "pipeline_m1c4_scratchpad.yaml"
WORKFLOW = CORPUS_DIR / "workflow_benign.yaml"
DOC = ROOT / "docs" / "policy-reference.md"
PLATFORMS = ("windows", "posix")
PLATFORM_IDS = [f"on-{p}" for p in PLATFORMS]  # conftest.py skips ids that are the bare words
RULE_ID = "allow-session-scratchpad"
RULE_TOOLS = ["Write", "Edit", "MultiEdit", "NotebookEdit", "Read", "Grep", "Glob"]
_RANK = {"allow": 0, "gray": 1, "ask": 2, "deny": 3}

SID = "19513824-5f23-476c-bd11-f2f49fb38457"
OTHER_SID = "19513824-5f23-476c-bd11-f2f49fb38458"
SLUG = {"windows": "e--bk-lab-m1b-proj", "posix": "-home-testuser-proj"}
TMP = {"windows": "C:\\Users\\testuser\\AppData\\Local\\Temp", "posix": "/tmp"}


# ---------------------------------------------------------------------------- helpers


def _sep(platform: str) -> str:
    return "\\" if platform == "windows" else "/"


def _join(platform: str, *parts: str) -> str:
    return _sep(platform).join(parts)


def pad(platform: str, sid: str = SID, slug: str | None = None, tmp: str | None = None) -> str:
    """The scratchpad of session ``sid`` on the fake machine of ``platform``."""
    return _join(
        platform, tmp or TMP[platform], "claude", slug or SLUG[platform], sid, "scratchpad"
    )


def at(platform: str, *names: str, **kw: Any) -> str:
    return _join(platform, pad(platform, **kw), *names)


def _text(name: str) -> str:
    return (POLICIES / f"{name}.yaml").read_text(encoding="utf-8")


def _with_trusted(text: str, platform: str) -> str:
    block = f"trusted_projects:\n  - '{policycli._FAKE[platform]['project']}'\n"
    assert "\nrules:\n" in text
    return text.replace("\nrules:\n", "\n" + block + "rules:\n", 1)


@cache
def _policy(name: str, platform: str, trusted: bool = False) -> Policy:
    text = _text(name)
    if trusted:
        text = _with_trusted(text, platform)
    return parse_policy_text(text, home=policycli._FAKE[platform]["home"])


@cache
def _m1c3_text() -> str | None:
    """The default policy of the ``m1c3-done`` tag (before this milestone); None if git has none."""
    try:
        done = subprocess.run(
            ["git", "show", "m1c3-done:policies/default.yaml"],
            cwd=ROOT,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0 or not done.stdout:
        return None
    return done.stdout.decode("utf-8")


def _m1c3_policy(platform: str, trusted: bool = False) -> Policy:
    text = _m1c3_text()
    if text is None:
        pytest.skip("git cannot show m1c3-done:policies/default.yaml here")
    if trusted:
        text = _with_trusted(text, platform)
    return parse_policy_text(text, home=policycli._FAKE[platform]["home"])


@cache
def _ps_ready() -> bool:
    if sys.platform != "win32":
        return False
    from boundkeep.normalize import psparse

    psparse.warm_up(wait_s=15)
    return bool(psparse.status().get("state") == "ready")


def _tool_input(tool: str, target: str) -> dict[str, Any]:
    if tool in ("Bash", "PowerShell"):
        return {"command": target}
    if tool == "Write":
        return {"file_path": target, "content": "x"}
    if tool == "Edit":
        return {"file_path": target, "old_string": "a", "new_string": "b"}
    if tool == "MultiEdit":
        return {"file_path": target, "edits": [{"old_string": "a", "new_string": "b"}]}
    if tool == "NotebookEdit":
        return {"notebook_path": target, "new_source": "x"}
    if tool == "Read":
        return {"file_path": target}
    if tool == "Grep":
        return {"pattern": "needle", "path": target}
    if tool == "Glob":
        return {"pattern": "*.py", "path": target}
    raise AssertionError(tool)


def _review(
    policy: Policy,
    platform: str,
    tool: str,
    tool_input: dict[str, Any],
    *,
    sid: str | None = SID,
    cwd: str | None = None,
) -> Any:
    """The pipeline on the fake machine; ``sid`` None leaves ``session_id`` out of the event."""
    if tool in ("PowerShell",) and not _ps_ready():
        pytest.skip("PowerShell needs the real parser helper (Windows only)")
    fake = policycli._FAKE[platform]
    payload: dict[str, Any] = {
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": cwd or fake["project"],
        "project_dir": fake["project"],
    }
    if sid is not None:
        payload["session_id"] = sid
    runtime, _problem = pipeline.runtime_policy_checked(policy, fake["env"], fake["home"])
    return pipeline.review(
        payload, runtime, platform=platform, env=fake["env"], home=fake["home"], scan_disk=False
    )


def _decide(
    name: str,
    platform: str,
    tool: str,
    tool_input: dict[str, Any],
    *,
    sid: str | None = SID,
    cwd: str | None = None,
    trusted: bool = False,
) -> str:
    review = _review(_policy(name, platform, trusted), platform, tool, tool_input, sid=sid, cwd=cwd)
    return str(review.verdict.decision)


def _decide_old(
    platform: str,
    tool: str,
    tool_input: dict[str, Any],
    *,
    sid: str | None = SID,
    cwd: str | None = None,
    trusted: bool = False,
) -> str:
    review = _review(_m1c3_policy(platform, trusted), platform, tool, tool_input, sid=sid, cwd=cwd)
    return str(review.verdict.decision)


def _hit_ids(review: Any) -> set[str]:
    return {hit.rule_id for action in review.verdict.actions for hit in action.hits}


def _rule(rule_id: str = RULE_ID) -> Rule:
    return {r.id: r for r in _policy("default", "posix").rules}[rule_id]


def _ref(
    key: str = "/tmp/claude/p/s/scratchpad/a.py", *, scratch: bool = True, **kw: Any
) -> PathRef:
    fields: dict[str, Any] = {"access": "write", "inside_project": False}
    fields.update(kw)
    return PathRef(raw=key, key=key, flavor="posix", in_scratchpad=scratch, **fields)


def _action(*refs: PathRef, **fields: Any) -> Action:
    base: dict[str, Any] = {"tool": "Write", "platform": "posix"}
    base.update(fields)
    return Action(paths=refs, **base)


# ---------------------------------------------------------------------------- rule facts


def test_the_rule_is_in_default_only_with_exactly_this_text() -> None:
    default = yaml.safe_load(_text("default"))
    rule = next(r for r in default["rules"] if r["id"] == RULE_ID)
    assert rule["action"] == "allow"
    assert rule["tool"] == RULE_TOOLS
    assert rule["match"] == {"path_in_scratchpad": True}
    assert "platform" not in rule
    strict = yaml.safe_load(_text("strict"))
    assert RULE_ID not in {r["id"] for r in strict["rules"]}
    assert "path_in_scratchpad" not in _text("strict").replace("# ", "#").split("rules:")[1]
    allow = [r["id"] for r in strict["rules"] if r["action"] == "allow"]
    assert allow == ["read-inside-project"]


def test_no_shell_tool_is_covered_by_the_rule() -> None:
    assert not {"Bash", "PowerShell"} & set(_rule().tool or ())
    assert not any("*" in t for t in _rule().tool or ())


def test_the_docs_name_the_field_the_rule_and_the_residual_risks() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert f"`{RULE_ID}`" in text
    assert "`path_in_scratchpad: true`" in text
    assert "Session scratchpad" in text or "scratchpad" in text.lower()
    row = next(line for line in text.splitlines() if line.startswith(f"| `{RULE_ID}`"))
    for needle in ("scratchpad", "Bash", "PowerShell"):
        assert needle in row, needle


# ---------------------------------------------------------------------------- schema


def test_path_in_scratchpad_is_a_match_field_and_makes_a_match_non_empty() -> None:
    assert "path_in_scratchpad" in Match.model_fields
    match = Match.model_validate({"path_in_scratchpad": True})
    assert match.path_in_scratchpad is True
    assert not match.is_empty()


@pytest.mark.parametrize("value", ["false", "null", "'yes'", "1", "[true]", "'true'"])
def test_path_in_scratchpad_is_true_only(value: str) -> None:
    text = (
        "version: 1\nrules:\n  - id: r\n    tool: [Write]\n    action: allow\n"
        f"    match: {{path_in_scratchpad: {value}}}\n"
    )
    with pytest.raises(PolicyError):
        parse_policy_text(text, home="/home/dev")


def test_a_blank_path_in_scratchpad_is_refused_as_null() -> None:
    text = (
        "version: 1\nrules:\n  - id: r\n    tool: [Write]\n    action: allow\n"
        "    match:\n      path_in_scratchpad:\n"
    )
    with pytest.raises(PolicyError, match="null"):
        parse_policy_text(text, home="/home/dev")


def test_path_in_scratchpad_alone_does_not_satisfy_the_allow_guard() -> None:
    data = {"id": "r", "match": {"path_in_scratchpad": True}, "action": "allow"}
    with pytest.raises(ValidationError, match="must name a tool or a program"):
        Rule.model_validate(data)
    Rule.model_validate({**data, "tool": ["Write"]})
    Rule.model_validate({**data, "match": {"path_in_scratchpad": True, "program": ["cat"]}})


def test_path_in_scratchpad_needs_a_tool_that_touches_paths() -> None:
    data = {
        "id": "r",
        "tool": ["WebSearch"],
        "match": {"path_in_scratchpad": True},
        "action": "allow",
    }
    with pytest.raises(ValidationError, match="never touch file paths"):
        Rule.model_validate(data)


# ---------------------------------------------------------------------------- matcher level


def _scratch_rule(extra: dict[str, Any] | None = None, *, action: str = "allow") -> Rule:
    data: dict[str, Any] = {
        "id": "r1",
        "tool": ["Write", "Read"],
        "match": {"path_in_scratchpad": True, **(extra or {})},
        "action": action,
    }
    if action != "allow":
        data["reason"] = "because r1"
    return Rule.model_validate(data)


@pytest.mark.parametrize("action", ["allow", "ask", "deny"])
def test_one_path_in_the_scratchpad_matches(action: str) -> None:
    assert match_rule(_scratch_rule(action=action), _action(_ref()), platform="posix")


@pytest.mark.parametrize("action", ["allow", "ask", "deny"])
def test_no_path_never_matches(action: str) -> None:
    assert not match_rule(_scratch_rule(action=action), _action(), platform="posix")


@pytest.mark.parametrize("action", ["allow", "ask", "deny"])
def test_every_path_must_be_in_the_scratchpad(action: str) -> None:
    rule = _scratch_rule(action=action)
    both = _action(_ref(), _ref("/tmp/claude/p/s/scratchpad/b.py"))
    assert match_rule(rule, both, platform="posix")
    one_out = _action(_ref(), _ref("/etc/x", scratch=False))
    assert not match_rule(rule, one_out, platform="posix")
    only_out = _action(_ref("/etc/x", scratch=False))
    assert not match_rule(rule, only_out, platform="posix")


def test_the_resolved_form_of_a_path_must_be_in_the_scratchpad_too() -> None:
    lexical = _ref("/tmp/claude/p/s/scratchpad/link/f.py")
    resolved = _ref("/home/testuser/proj/f.py", scratch=False, reasons=("resolved-on-disk",))
    assert not match_rule(_scratch_rule(), _action(lexical, resolved), platform="posix")
    assert match_rule(_scratch_rule(), _action(lexical), platform="posix")


def test_an_uncertain_path_is_not_in_the_scratchpad_by_default() -> None:
    ref = PathRef(raw="x", key="x", flavor="posix", uncertain=True)
    assert ref.in_scratchpad is False
    assert not match_rule(_scratch_rule(), _action(ref), platform="posix")


def test_other_fields_combine_by_and() -> None:
    rule = _scratch_rule({"path_glob": ["**/*.py"], "access": "write"})
    assert match_rule(rule, _action(_ref()), platform="posix")
    assert not match_rule(rule, _action(_ref("/tmp/claude/p/s/scratchpad/a.txt")), platform="posix")
    assert not match_rule(rule, _action(_ref(access="read")), platform="posix")
    outside = _scratch_rule({"path_outside_project": True})
    assert match_rule(outside, _action(_ref()), platform="posix")
    assert not match_rule(outside, _action(_ref(inside_project=True)), platform="posix")
    program = Rule.model_validate(
        {
            "id": "r2",
            "match": {"program": ["cat"], "path_in_scratchpad": True},
            "action": "allow",
        }
    )
    assert match_rule(program, _action(_ref(), tool="Bash", program="cat"), platform="posix")
    assert not match_rule(program, _action(_ref(), tool="Bash", program="ls"), platform="posix")
    assert not match_rule(
        program, _action(_ref(access="read", scratch=False), program="cat"), platform="posix"
    )


@pytest.mark.parametrize("wrapper", ["sudo", "env", "nohup", "time"])
def test_a_wrapper_never_rides_the_allow_rule(wrapper: str) -> None:
    assert not match_rule(_scratch_rule(), _action(_ref(), wrappers=(wrapper,)), platform="posix")


def test_a_gray_action_never_rides_the_allow_rule_but_a_deny_rule_still_sees_it() -> None:
    gray = _action(_ref(), gray=True, gray_reasons=("x",))
    assert not match_rule(_scratch_rule(), gray, platform="posix")
    assert match_rule(_scratch_rule(action="deny"), gray, platform="posix")


def test_the_explain_line_names_the_field() -> None:
    lines = explain_rule(_scratch_rule(), _action(_ref()), platform="posix")
    assert lines is not None
    assert any(line.startswith("path_in_scratchpad:") for line in lines)


def test_the_shipped_rule_in_the_matcher() -> None:
    rule = _rule()
    assert match_rule(rule, _action(_ref()), platform="posix")
    assert not match_rule(rule, _action(_ref(scratch=False)), platform="posix")
    assert not match_rule(rule, _action(_ref(), tool="Bash"), platform="posix")  # a shell tool
    assert not match_rule(rule, _action(_ref(), tool="WebFetch"), platform="posix")


def test_a_deny_rule_beats_the_allow_rule_on_the_same_action() -> None:
    policy = _policy("default", "posix")
    plain = _action(_ref("/tmp/claude/p/s/scratchpad/a.py"))
    assert evaluate(policy, [plain], platform="posix").decision == "allow"
    protected = _ref(
        "/tmp/claude/p/s/scratchpad/.env"
    )  # a write to a marked path with a secret name
    verdict = evaluate(policy, [_action(protected)], platform="posix")
    assert verdict.decision == "ask"
    assert {RULE_ID, "ask-secret-file-write"} <= {
        hit.rule_id for a in verdict.actions for hit in a.hits
    }


# ---------------------------------------------------------------------------- temp directory


@pytest.mark.parametrize(
    ("platform", "env", "home", "expected"),
    [
        ("windows", {"TEMP": "D:\\t", "TMP": "E:\\u"}, "C:\\h", "D:\\t"),
        ("windows", {"temp": "D:\\t"}, "C:\\h", "D:\\t"),
        ("windows", {"TMP": "E:\\u"}, "C:\\h", "E:\\u"),
        ("windows", {"TEMP": "  ", "TMP": "E:\\u"}, "C:\\h", "E:\\u"),
        ("windows", {"TEMP": "", "LOCALAPPDATA": "C:\\L"}, "C:\\h", "C:\\L\\Temp"),
        ("windows", {"LOCALAPPDATA": "C:\\L\\"}, "C:\\h", "C:\\L\\Temp"),
        ("windows", {}, "C:\\h", "C:\\h\\AppData\\Local\\Temp"),
        ("windows", {}, "C:\\h\\", "C:\\h\\AppData\\Local\\Temp"),
        ("windows", {}, None, None),
        ("windows", {"TEMP": "D:\\t", "Temp": "D:\\other"}, "C:\\h", None),  # two spellings: doubt
        ("windows", {"TEMP": "D:\\t", "temp": "D:\\t"}, "C:\\h", "D:\\t"),  # the same value twice
        ("posix", {"TMPDIR": "/var/folders/x"}, "/home/h", "/var/folders/x"),
        ("posix", {"TMPDIR": " "}, "/home/h", "/tmp"),
        ("posix", {}, "/home/h", "/tmp"),
        ("posix", {"TEMP": "/elsewhere"}, "/home/h", "/tmp"),  # TEMP is a Windows name
    ],
)
def test_temp_dir_text(
    platform: Any, env: dict[str, str], home: str | None, expected: str | None
) -> None:
    assert paths.temp_dir_text(platform, env, home) == expected


def test_the_fake_machines_have_their_own_temp_directory() -> None:
    for platform in PLATFORMS:
        fake = policycli._FAKE[platform]
        assert paths.temp_dir_text(platform, fake["env"], fake["home"]) == TMP[platform]  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "sid",
    [
        None,
        "",
        " ",
        "policy-test",
        "..",
        "*",
        "a/b",
        "a\\b",
        SID + "\n",
        " " + SID,
        SID + " ",
        SID[:-1],
        SID + "0",
        SID.replace("-", ""),
        "{" + SID + "}",
        "19513824-5f23-476c-bd11-f2f49fb3845g",
        "١٩٥١٣٨٢٤-5f23-476c-bd11-f2f49fb38457",
        SID * 20,
        "x" * 10_000,
        SID + "/..",
        "../" + SID,
    ],
)
def test_no_scratchpad_without_a_well_formed_session_id(sid: Any) -> None:
    for platform in PLATFORMS:
        fake = policycli._FAKE[platform]
        assert paths.scratchpad_for(sid, platform, fake["env"], fake["home"]) is None  # type: ignore[arg-type]


def test_a_uuid_session_id_makes_a_scratchpad_in_either_case() -> None:
    for sid in (SID, SID.upper(), SID.lower()):
        fake = policycli._FAKE["windows"]
        assert paths.scratchpad_for(sid, "windows", fake["env"], fake["home"]) is not None


@pytest.mark.parametrize(
    "env",
    [
        {"TEMP": "relative\\dir"},
        {"TEMP": "\\\\server\\share\\tmp"},
        {"TEMP": "\\\\?\\UNC\\server\\share\\tmp"},
        {"TEMP": "%UNDEFINED%\\x"},
        {"TEMP": "C:\\a\\*"},
        {"TEMP": "NUL"},
        {"TEMP": "\\\\.\\C:\\tmp"},
        {"TEMP": "/tmp"},  # no drive: Git Bash style, not a path this layer can place
    ],
)
def test_an_unusable_temp_directory_means_no_scratchpad(env: dict[str, str]) -> None:
    assert paths.scratchpad_for(SID, "windows", env, "C:\\Users\\testuser") is None


def test_a_drive_root_temp_directory_is_a_usable_if_silly_root() -> None:
    sp = paths.scratchpad_for(SID, "windows", {"TEMP": "C:\\"}, "C:\\Users\\testuser")
    assert sp is not None
    inside = paths.normalize_path(
        "C:\\claude\\p\\" + SID + "\\scratchpad\\x", cwd=None, home=None, literal=True
    )
    assert sp.contains(inside, resolved=False)
    outside = paths.normalize_path("C:\\x", cwd=None, home=None, literal=True)
    assert not sp.contains(outside, resolved=False)


def _norm(platform: str, text: str) -> paths.NormPath:
    return paths.normalize_path(text, cwd=None, home=None, dialect="tool", literal=True)


def _sp(platform: str) -> paths.Scratchpad:
    fake = policycli._FAKE[platform]
    found = paths.scratchpad_for(SID, platform, fake["env"], fake["home"])  # type: ignore[arg-type]
    assert found is not None
    return found


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_contains_is_exactly_the_scratchpad_subtree(platform: str) -> None:
    sp = _sp(platform)
    base = pad(platform)

    def inside(text: str) -> bool:
        return sp.contains(_norm(platform, text), resolved=False)

    sep = _sep(platform)
    assert inside(base)
    assert inside(base + sep + "x.py")
    assert inside(base + sep + "a" + sep + "b" + sep + "c.py")
    assert not inside(base + "2")
    assert not inside(base + "2" + sep + "x.py")
    assert not inside(base + ".x" + sep + "x.py")
    assert not inside(base.rsplit(sep, 1)[0])  # the session directory
    assert not inside(base.rsplit(sep, 2)[0])  # the project slug directory
    assert not inside(TMP[platform])
    assert not inside(pad(platform, sid=OTHER_SID) + sep + "x.py")
    assert not inside(base + sep + ".." + sep + "x.py")
    assert not inside(at(platform, "x.py", tmp=TMP[platform] + sep + "sub"))


def test_resolved_forms_are_judged_against_the_resolved_temp_directory() -> None:
    sp = _sp("windows")
    norm = _norm("windows", at("windows", "x.py"))
    assert sp.contains(norm, resolved=True)  # nothing to resolve on a fake machine: the same root
    foreign = _norm("windows", "D:\\elsewhere\\claude\\p\\" + SID + "\\scratchpad\\x.py")
    assert not sp.contains(foreign, resolved=True)
    assert not sp.contains(foreign, resolved=False)


def test_an_uncertain_or_relative_or_foreign_path_is_never_contained() -> None:
    sp = _sp("windows")
    for text in (
        at("windows", "*.py"),
        at("windows", "$x", "f"),
        "claude\\p\\" + SID + "\\scratchpad\\x",
        "/tmp/claude/p/" + SID + "/scratchpad/x",
        "\\\\server\\share\\claude\\p\\" + SID + "\\scratchpad\\x",
        "\\\\.\\GLOBALROOT\\Device\\HarddiskVolume3\\claude\\p\\" + SID + "\\scratchpad\\x",
        # readings of the same text that a file tool does not share (translated paths, admin share)
        "/c/Users/testuser/AppData/Local/Temp/claude/p/" + SID + "/scratchpad/x",
        "/cygdrive/c/Users/testuser/AppData/Local/Temp/claude/p/" + SID + "/scratchpad/x",
        "/mnt/c/Users/testuser/AppData/Local/Temp/claude/p/" + SID + "/scratchpad/x",
        "\\\\localhost\\c$\\Users\\testuser\\AppData\\Local\\Temp\\claude\\p\\"
        + SID
        + "\\scratchpad\\x",
        "~\\AppData\\Local\\Temp\\claude\\p\\" + SID + "\\scratchpad\\x",
    ):
        norm = paths.normalize_path(
            text, cwd=None, home="C:\\Users\\testuser", env=policycli._FAKE["windows"]["env"]
        )
        assert not sp.contains(norm, resolved=False), text
        assert not sp.contains(norm, resolved=True), text


def test_the_spellings_of_the_same_file_do_count() -> None:
    sp = _sp("windows")
    plain = at("windows", "x.py")
    for text in (
        plain,
        "\\\\?\\" + plain,
        "\\\\.\\" + plain,
        "\\??\\" + plain,
        plain + ":stream",
        plain.replace("\\x.py", "\\sub\\..\\x.py"),
    ):
        norm = paths.normalize_path(text, cwd=None, home=None, dialect="tool", literal=False)
        assert sp.contains(norm, resolved=False), text


def test_scratch_plain_names() -> None:
    assert paths.scratch_plain("c:/a/b/c.py")
    assert paths.scratch_plain("/tmp/claude/a b/(1)/笔记.md")
    for bad in ("a*b", "a?b", "a[1]", "{a,b}", "a<b", "a|b", 'a"b'):
        assert not paths.scratch_plain("c:/" + bad), bad


# ---------------------------------------------------------------------------- positives

NAMES = [
    ("x.py",),
    ("data.json",),
    ("a", "b", "c", "deep.py"),
    ("a" * 120 + ".py",),
    ("笔记", "数据.json"),
    ("with space", "notes (1).txt"),
    ("run.sh",),
    ("x.ps1",),
    ("no-extension",),
    ("out.log",),
]


def _name_id(names: tuple[str, ...]) -> str:
    return "/".join(names)[:24]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("names", NAMES, ids=_name_id)
@pytest.mark.parametrize("tool", RULE_TOOLS)
def test_the_session_scratchpad_is_allowed_for_the_file_tools(
    tool: str, names: tuple[str, ...], platform: str
) -> None:
    review = _review(
        _policy("default", platform), platform, tool, _tool_input(tool, at(platform, *names))
    )
    assert review.verdict.decision == "allow", (tool, names, review.verdict.reasons)
    assert RULE_ID in _hit_ids(review)
    for action in review.actions:
        assert action.paths
        assert all(ref.in_scratchpad for ref in action.paths)


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("tool", ["Grep", "Glob", "Read", "Write"])
def test_the_scratchpad_directory_itself_counts(tool: str, platform: str) -> None:
    got = _decide("default", platform, tool, _tool_input(tool, pad(platform)))
    assert got == "allow", tool


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_the_session_id_compares_without_case(platform: str) -> None:
    for sid in (SID.upper(), SID.lower()):
        for tool in ("Write", "Read"):
            got = _decide(
                "default", platform, tool, _tool_input(tool, at(platform, "x.py")), sid=sid
            )
            assert got == "allow", (tool, sid)
    # and the directory name may be spelled in either case as well
    upper = at(platform, "x.py", sid=SID.upper())
    assert _decide("default", platform, "Write", _tool_input("Write", upper)) == "allow"


def test_windows_names_compare_without_case_and_accept_other_spellings() -> None:
    plain = at("windows", "x.py")
    for target in (
        plain.upper(),
        plain.lower(),
        plain.replace("\\", "/"),
        plain.replace("claude", "CLAUDE").replace("scratchpad", "ScratchPad"),
        "\\\\?\\" + plain,
        "\\\\.\\" + plain,
        "\\??\\" + plain,
        plain.replace("\\x.py", "\\.\\x.py"),
        plain.replace("\\x.py", "\\\\x.py"),
        plain.replace("\\x.py", "\\sub\\..\\x.py"),
        plain.replace("\\scratchpad", "\\scratchpad."),  # Win32 drops ONE trailing dot
    ):
        for tool in ("Write", "Read"):
            assert _decide("default", "windows", tool, _tool_input(tool, target)) == "allow", (
                tool,
                target,
            )


def test_a_windows_stream_name_is_the_same_file() -> None:
    target = at("windows", "x.py") + ":stream"
    assert _decide("default", "windows", "Write", _tool_input("Write", target)) == "allow"


def test_posix_names_compare_exactly() -> None:
    plain = at("posix", "x.py")
    assert _decide("default", "posix", "Write", _tool_input("Write", plain)) == "allow"
    for target in (
        plain.replace("/claude/", "/Claude/"),
        plain.replace("/scratchpad/", "/Scratchpad/"),
        plain.replace("/tmp/", "/TMP/"),
        plain.replace("/scratchpad/", "/SCRATCHPAD/"),
    ):
        assert _decide("default", "posix", "Write", _tool_input("Write", target)) != "allow", target
    assert (
        _decide("default", "posix", "Write", _tool_input("Write", plain.replace("/./", "/")))
        == "allow"
    )


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_a_relative_path_is_judged_through_the_existing_relative_logic(platform: str) -> None:
    here = pad(platform)
    sub = at(platform, "sub")
    up = ".." + _sep(platform) + "x.py"
    for tool in ("Write", "Read", "Edit"):
        assert _decide("default", platform, tool, _tool_input(tool, "x.py"), cwd=here) == "allow", (
            tool
        )
        assert _decide("default", platform, tool, _tool_input(tool, "x.py"), cwd=sub) == "allow", (
            tool
        )
        # a relative climb out of the scratchpad is not
        assert _decide("default", platform, tool, _tool_input(tool, up), cwd=here) != "allow", tool
        assert (
            _decide(
                "default",
                platform,
                tool,
                _tool_input(tool, "x.py"),
                cwd=_join(platform, here, ".."),
            )
            != "allow"
        ), tool
    # without that cwd the same relative name is a project path, not a scratchpad one
    assert RULE_ID not in _hit_ids(
        _review(_policy("default", platform), platform, "Write", _tool_input("Write", "x.py"))
    )


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_grep_and_glob_with_a_glob_inside_the_scratchpad(platform: str) -> None:
    base = pad(platform)
    for tool_input in (
        {"pattern": "needle", "path": base, "glob": "*.py"},
        {"pattern": "needle", "path": base, "type": "py"},
        {"pattern": "needle", "path": base, "output_mode": "content", "-n": True},
    ):
        assert _decide("default", platform, "Grep", tool_input) == "allow", tool_input
    assert _decide("default", platform, "Glob", {"pattern": "**/*.py", "path": base}) == "allow"
    assert _decide("default", platform, "Glob", {"pattern": "*.json", "path": base}) == "allow"


# ---------------------------------------------------------------------------- protected names win

# Under the scratchpad a protected NAME is protected exactly as in the project (`expect` is the
# default policy's verdict for a Write; Read: see READ_PROTECTED).
PROTECTED_WRITES = [
    (".env", "ask"),
    (".env.local", "ask"),
    ("config/prod.env", "ask"),
    ("id_rsa", "ask"),
    ("certs/server.pem", "ask"),
    ("secrets.yml", "ask"),
    (".aws/credentials", "ask"),
    (".netrc", "ask"),
    (".npmrc", "ask"),
    ("Makefile", "ask"),
    ("package.json", "ask"),
    ("pyproject.toml", "ask"),
    ("conftest.py", "ask"),
    ("tests/conftest.py", "ask"),
    ("Dockerfile", "ask"),
    (".github/workflows/x.yml", "ask"),
    (".claude/settings.json", "deny"),
    (".claude/settings.local.json", "deny"),
    (".boundkeep/policy.yaml", "deny"),
    (".mcp.json", "ask"),
    ("CLAUDE.md", "ask"),
    (".claude/hooks/h.sh", "ask"),
    (".git/hooks/pre-commit", "ask"),
    (".git/config", "ask"),
    (".git/HEAD", "ask"),
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("name", "expected"), PROTECTED_WRITES)
@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit"])
def test_a_protected_name_inside_the_scratchpad_is_still_protected(
    tool: str, name: str, expected: str, platform: str
) -> None:
    target = at(platform, *name.split("/"))
    review = _review(_policy("default", platform), platform, tool, _tool_input(tool, target))
    assert review.verdict.decision == expected, (tool, name, review.verdict.reasons)
    assert RULE_ID in _hit_ids(review)  # the allow rule hits too: the strictest hit decides
    assert _decide("strict", platform, tool, _tool_input(tool, target)) != "allow"


READ_PROTECTED = [
    (".env", "deny"),
    ("id_rsa", "deny"),
    (".ssh/id_rsa", "deny"),
    ("secrets.env", "deny"),
    (".aws/credentials", "deny"),
    (".git/config", "deny"),
    (".claude/settings.local.json", "deny"),
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("name", "expected"), READ_PROTECTED)
def test_reading_a_protected_name_inside_the_scratchpad_is_still_denied(
    name: str, expected: str, platform: str
) -> None:
    target = at(platform, *name.split("/"))
    assert _decide("default", platform, "Read", _tool_input("Read", target)) == expected


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_the_allow_hit_and_the_protective_hit_both_show_and_the_strictest_wins(
    platform: str,
) -> None:
    review = _review(
        _policy("default", platform),
        platform,
        "Write",
        _tool_input("Write", at(platform, ".env")),
    )
    assert {RULE_ID, "ask-secret-file-write"} <= _hit_ids(review)
    assert review.verdict.decision == "ask"
    read = _review(
        _policy("default", platform), platform, "Read", _tool_input("Read", at(platform, ".env"))
    )
    assert {RULE_ID, "no-secret-read"} <= _hit_ids(read)
    assert read.verdict.decision == "deny"


# ---------------------------------------------------------------------------- negatives

SEP_FREE_CASES: list[tuple[str, Callable[[str], str | None]]] = [
    ("other-session", lambda p: at(p, "x.py", sid=OTHER_SID)),
    ("other-session-uuid", lambda p: at(p, "x.py", sid="00000000-0000-4000-8000-000000000000")),
    ("session-dir-itself", lambda p: pad(p).rsplit(_sep(p), 1)[0]),
    ("session-dir-file", lambda p: _join(p, pad(p).rsplit(_sep(p), 1)[0], "x.py")),
    ("slug-dir", lambda p: pad(p).rsplit(_sep(p), 2)[0]),
    ("claude-dir", lambda p: _join(p, TMP[p], "claude")),
    ("claude-dir-file", lambda p: _join(p, TMP[p], "claude", "x.py")),
    ("tmp-dir", lambda p: TMP[p]),
    ("tmp-file", lambda p: _join(p, TMP[p], "x.py")),
    ("scratchpad2", lambda p: pad(p) + "2" + _sep(p) + "x.py"),
    ("scratchpad2-itself", lambda p: pad(p) + "2"),
    ("scratchpad-dot-x", lambda p: pad(p) + ".x" + _sep(p) + "x.py"),
    ("scratchpad-dash", lambda p: pad(p) + "-old" + _sep(p) + "x.py"),
    ("scratchpa", lambda p: pad(p)[:-1] + _sep(p) + "x.py"),
    ("scratch-file-named-like-it", lambda p: _join(p, pad(p).rsplit(_sep(p), 1)[0], "scratchpad2")),
    ("climb-three", lambda p: _join(p, pad(p), "..", "..", "..", "x")),
    ("climb-one", lambda p: _join(p, pad(p), "..", "x.py")),
    ("climb-two", lambda p: _join(p, pad(p), "..", "..", "x.py")),
    (
        "climb-to-project",
        lambda p: _join(p, pad(p), *[".."] * 6, "Users", "testuser", "proj", "a.py"),
    ),
    ("climb-via-sub", lambda p: _join(p, pad(p), "sub", "..", "..", "x.py")),
    ("climb-inside-name", lambda p: _join(p, pad(p), "..", "scratchpad2", "x.py")),
    (
        "wrong-tmp-dir",
        lambda p: (
            "E:\\x\\claude\\foo\\" + SID + "\\scratchpad\\f"
            if p == "windows"
            else "/var/tmp/claude/foo/" + SID + "/scratchpad/f"
        ),
    ),
    (
        "wrong-tmp-dir-inside-project",
        lambda p: _join(p, policycli._FAKE[p]["project"], "claude", "x", SID, "scratchpad", "f"),
    ),
    (
        "wrong-tmp-dir-inside-home",
        lambda p: _join(p, policycli._FAKE[p]["home"], "claude", "x", SID, "scratchpad", "f"),
    ),
    (
        "different-drive-or-root",
        lambda p: (
            "D:\\Users\\testuser\\AppData\\Local\\Temp\\claude\\p\\" + SID + "\\scratchpad\\f"
            if p == "windows"
            else "/mnt/tmp/claude/p/" + SID + "/scratchpad/f"
        ),
    ),
    (
        "temp-subdir-instead-of-temp",
        lambda p: at(p, "x.py", tmp=_join(p, TMP[p], "sub")),
    ),
    (
        "temp-parent-instead-of-temp",
        lambda p: (
            at(p, "x.py", tmp="C:\\Users\\testuser\\AppData\\Local")
            if p == "windows"
            else "/claude/" + SLUG[p] + "/" + SID + "/scratchpad/x.py"
        ),
    ),
    ("claude-twice", lambda p: _join(p, TMP[p], "claude", "claude", "p", SID, "scratchpad", "f")),
    ("missing-slug", lambda p: _join(p, TMP[p], "claude", SID, "scratchpad", "x.py")),
    (
        "two-slug-segments",
        lambda p: _join(p, TMP[p], "claude", "a", "b", SID, "scratchpad", "x.py"),
    ),
    ("climb-into-claude", lambda p: _join(p, pad(p), "..", "..", "..", "claude", "x.py")),
    ("no-claude", lambda p: _join(p, TMP[p], "other", "p", SID, "scratchpad", "x.py")),
    ("uncertain-variable", lambda p: _join(p, pad(p), "$x", "f.py")),
    (
        "uncertain-variable-prefix",
        lambda p: _join(p, TMP[p], "claude", "$x", SID, "scratchpad", "f"),
    ),
    ("uncertain-home", lambda p: "~" + _sep(p) + "x.py"),
    ("uncertain-slug-var", lambda p: _join(p, TMP[p], "claude", "$SLUG", SID, "scratchpad", "f")),
    ("uncertain-brace", lambda p: _join(p, pad(p), "{a,b}", "f")),
    (
        "other-flavor",
        lambda p: (
            "/tmp/claude/p/" + SID + "/scratchpad/x.py"
            if p == "windows"
            else "C:\\Users\\testuser\\AppData\\Local\\Temp\\claude\\p\\"
            + SID
            + "\\scratchpad\\x.py"
        ),
    ),
    ("home-expanded-tmp", lambda p: "~/claude/p/" + SID + "/scratchpad/x.py"),
]

# only for the Windows fake machine: names the Windows path layer must not let through
WINDOWS_ONLY_CASES: list[tuple[str, Callable[[str], str]]] = [
    ("short-name-scratchpad", lambda p: _join(p, pad(p).rsplit("\\", 1)[0], "SCRATC~1", "x.py")),
    ("short-name-claude", lambda p: _join(p, TMP[p], "CLAUDE~1", "p", SID, "scratchpad", "x.py")),
    (
        "short-name-slug",
        lambda p: _join(p, TMP[p], "claude", "E--BK-~1", SID, "scratchpad", "x.py"),
    ),
    (
        "short-name-temp",
        lambda p: (
            "C:\\Users\\TESTUS~1\\AppData\\Local\\Temp\\claude\\p\\" + SID + "\\scratchpad\\x.py"
        ),
    ),
    ("ads-dotdot", lambda p: _join(p, pad(p), "..:s", "x.py")),
    ("ads-in-dotdot", lambda p: _join(p, pad(p), "..:s", "..:s", "x.py")),
    (
        "msys-style",
        lambda p: "/c/Users/testuser/AppData/Local/Temp/claude/p/" + SID + "/scratchpad/x",
    ),
    (
        "cygdrive-style",
        lambda p: "/cygdrive/c/Users/testuser/AppData/Local/Temp/claude/p/" + SID + "/scratchpad/x",
    ),
    (
        "wsl-style",
        lambda p: "/mnt/c/Users/testuser/AppData/Local/Temp/claude/p/" + SID + "/scratchpad/x",
    ),
    ("device-globalroot", lambda p: "\\\\.\\GLOBALROOT\\Device\\HarddiskVolume3\\" + pad(p)[3:]),
    ("device-pipe", lambda p: "\\\\.\\pipe\\" + SID + "\\scratchpad\\x.py"),
    ("star-segment", lambda p: _join(p, pad(p), "a*b", "f")),
    ("bracket-segment", lambda p: _join(p, pad(p), "[id]", "page.tsx")),
    ("question-segment", lambda p: _join(p, pad(p), "a?b")),
    ("trailing-dots-pad", lambda p: pad(p) + ".." + "\\x.py"),
    ("trailing-space-pad", lambda p: pad(p) + " \\x.py"),
    ("trailing-spaces-and-dots-pad", lambda p: pad(p) + ". .\\x.py"),
    ("dots-only-component", lambda p: _join(p, pad(p), "...", "x.py")),
    ("space-dots-component", lambda p: _join(p, pad(p), ". .", "x.py")),
    ("dotdot-space", lambda p: _join(p, pad(p), ".. ", "x.py")),
    ("trailing-dot-slug", lambda p: _join(p, TMP[p], "claude", "p..", SID, "scratchpad", "x.py")),
    (
        "unc-local",
        lambda p: (
            "\\\\localhost\\c$\\Users\\testuser\\AppData\\Local\\Temp\\claude\\p\\"
            + SID
            + "\\scratchpad\\x.py"
        ),
    ),
    ("unc-server", lambda p: "\\\\server\\share\\claude\\p\\" + SID + "\\scratchpad\\x.py"),
    (
        "unc-extended",
        lambda p: "\\\\?\\UNC\\server\\share\\claude\\p\\" + SID + "\\scratchpad\\x.py",
    ),
    ("nt-prefix-other", lambda p: "\\??\\D:\\claude\\p\\" + SID + "\\scratchpad\\x.py"),
    ("drive-relative", lambda p: "C:claude\\p\\" + SID + "\\scratchpad\\x.py"),
    ("rooted-no-drive", lambda p: "\\claude\\p\\" + SID + "\\scratchpad\\x.py"),
    ("device-name", lambda p: _join(p, pad(p), "NUL")),
    ("device-name-ext", lambda p: _join(p, pad(p), "COM1.txt")),
    ("percent-var", lambda p: "%TEMP%\\claude\\p\\" + SID + "\\scratchpad\\x.py"),
    ("wildcard-name", lambda p: _join(p, pad(p), "*.py")),
    ("question-name", lambda p: _join(p, pad(p), "x?.py")),
]

POSIX_ONLY_CASES: list[tuple[str, Callable[[str], str]]] = [
    ("case-claude", lambda p: "/tmp/Claude/p/" + SID + "/scratchpad/x.py"),
    ("case-scratchpad", lambda p: "/tmp/claude/p/" + SID + "/Scratchpad/x.py"),
    ("case-tmp", lambda p: "/TMP/claude/p/" + SID + "/scratchpad/x.py"),
    ("backslash-name", lambda p: "/tmp/claude/p/" + SID + "\\scratchpad/x.py"),
    ("backslash-climb", lambda p: pad(p) + "/..\\x.py/../.."),
    (
        "dotdot-to-sibling-session",
        lambda p: "/tmp/claude/p/" + SID + "/../" + SID + "2/scratchpad/x",
    ),
    ("star-segment", lambda p: _join(p, pad(p), "a*b", "f")),
    ("bracket-segment", lambda p: _join(p, pad(p), "[id]", "page.tsx")),
    ("question-segment", lambda p: _join(p, pad(p), "a?b")),
    (
        "wsl-style",
        lambda p: "/mnt/c/Users/testuser/AppData/Local/Temp/claude/p/" + SID + "/scratchpad/x",
    ),
]


def _neg_cases() -> list[Any]:
    out: list[Any] = []
    for label, make in SEP_FREE_CASES:
        for platform in PLATFORMS:
            target = make(platform)
            if target is not None:
                out.append(pytest.param(platform, label, target, id=f"{platform}-{label}"))
    for label, make in WINDOWS_ONLY_CASES:
        out.append(pytest.param("windows", label, make("windows"), id=f"windows-{label}"))
    for label, make in POSIX_ONLY_CASES:
        out.append(pytest.param("posix", label, make("posix"), id=f"posix-{label}"))
    return out


NEG_CASES = _neg_cases()


@pytest.mark.parametrize(("platform", "label", "target"), NEG_CASES)
@pytest.mark.parametrize("tool", RULE_TOOLS)
def test_anything_but_the_current_scratchpad_is_never_allowed(
    tool: str, platform: str, label: str, target: str
) -> None:
    review = _review(_policy("default", platform), platform, tool, _tool_input(tool, target))
    assert RULE_ID not in _hit_ids(review), (label, target)
    assert (
        review.verdict.decision != "allow"
        or "allow-project-file-writes" in _hit_ids(review)
        or ("read-inside-project" in _hit_ids(review))
    ), (label, target, review.verdict.reasons)


@pytest.mark.parametrize(("platform", "label", "target"), NEG_CASES)
@pytest.mark.parametrize("tool", ["Write", "Read", "Grep"])
def test_a_negative_has_the_verdict_it_had_before_the_rule_existed(
    tool: str, platform: str, label: str, target: str
) -> None:
    """The differential check: same verdict under the m1c3-done default policy."""
    now = _decide("default", platform, tool, _tool_input(tool, target))
    before = _decide_old(platform, tool, _tool_input(tool, target))
    assert now == before, (label, target, now, before)


@pytest.mark.parametrize(("platform", "label", "target"), NEG_CASES)
def test_a_negative_is_not_allowed_under_the_trusted_policy_either(
    platform: str, label: str, target: str
) -> None:
    for tool in ("Write", "Read"):
        now = _decide("default", platform, tool, _tool_input(tool, target), trusted=True)
        assert now == _decide("default", platform, tool, _tool_input(tool, target)), (label, tool)


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    "sid",
    [
        None,
        "",
        " ",
        "policy-test",
        "..",
        "*",
        "a/b",
        "a\\b",
        SID + "\n",
        " " + SID,
        SID[:-1],
        SID + "0",
        SID.replace("-", ""),
        "{" + SID + "}",
        OTHER_SID,
        "x" * 5000,
        SID + "/..",
        "../" + SID,
        SID + "\x00",
        "19513824-5f23-476c-bd11-f2f49fb3845ǥ",
    ],
    ids=lambda v: repr(v)[:20],
)
@pytest.mark.parametrize("tool", ["Write", "Read", "Grep", "Glob"])
def test_a_missing_blank_or_hostile_session_id_marks_nothing(
    tool: str, sid: Any, platform: str
) -> None:
    target = at(platform, "x.py")
    review = _review(
        _policy("default", platform), platform, tool, _tool_input(tool, target), sid=sid
    )
    assert RULE_ID not in _hit_ids(review)
    assert all(not ref.in_scratchpad for action in review.actions for ref in action.paths)
    assert review.verdict.decision != "allow"
    old = _review(_m1c3_policy(platform), platform, tool, _tool_input(tool, target), sid=sid)
    assert review.verdict.decision == old.verdict.decision


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_a_session_id_that_is_not_a_string_marks_nothing(platform: str) -> None:
    fake = policycli._FAKE[platform]
    policy = _policy("default", platform)
    for sid in (123, ["x"], {"a": 1}, None, True):
        payload = {
            "tool_name": "Write",
            "tool_input": _tool_input("Write", at(platform, "x.py")),
            "cwd": fake["project"],
            "project_dir": fake["project"],
            "session_id": sid,
        }
        result = pipeline.review(
            payload,
            policy,
            platform=platform,
            env=fake["env"],
            home=fake["home"],
            scan_disk=False,  # type: ignore[arg-type]
        )
        assert result.verdict.decision != "allow", sid


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_a_wrong_temp_directory_in_the_environment_moves_the_scratchpad(platform: str) -> None:
    """The daemon's own temp directory decides: the same path is not a scratchpad on a machine
    whose temp directory is elsewhere (that is also how a hostile project cannot name one)."""
    fake = policycli._FAKE[platform]
    env = dict(fake["env"])
    other = "D:\\Elsewhere" if platform == "windows" else "/var/elsewhere"
    env["TEMP" if platform == "windows" else "TMPDIR"] = other
    policy = _policy("default", platform)
    target = at(platform, "x.py")
    payload = {
        "tool_name": "Write",
        "tool_input": _tool_input("Write", target),
        "cwd": fake["project"],
        "project_dir": fake["project"],
        "session_id": SID,
    }
    runtime, _ = pipeline.runtime_policy_checked(policy, env, fake["home"])
    moved = pipeline.review(
        payload,
        runtime,
        platform=platform,
        env=env,
        home=fake["home"],
        scan_disk=False,  # type: ignore[arg-type]
    )
    assert moved.verdict.decision == "gray"
    # ... and the scratchpad of the OTHER temp directory now counts
    payload["tool_input"] = _tool_input("Write", at(platform, "x.py", tmp=other))
    there = pipeline.review(
        payload,
        runtime,
        platform=platform,
        env=env,
        home=fake["home"],
        scan_disk=False,  # type: ignore[arg-type]
    )
    assert there.verdict.decision == "allow"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_a_hostile_project_cannot_name_a_scratchpad_by_directory_names(platform: str) -> None:
    project = policycli._FAKE[platform]["project"]
    fake_root = _join(platform, project, "claude", "slug", SID, "scratchpad", "x.py")
    for tool in ("Write", "Read"):
        review = _review(_policy("default", platform), platform, tool, _tool_input(tool, fake_root))
        assert RULE_ID not in _hit_ids(review)
    # ... such a path is still an ordinary in-project one, with its own rule
    assert _decide("default", platform, "Write", _tool_input("Write", fake_root)) == "allow"
    review = _review(
        _policy("default", platform), platform, "Write", _tool_input("Write", fake_root)
    )
    assert "allow-project-file-writes" in _hit_ids(review)


# ---------------------------------------------------------------------------- several paths


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_a_search_whose_glob_leaves_the_scratchpad_is_not_allowed(platform: str) -> None:
    base = pad(platform)
    sep = _sep(platform)
    for glob in (".." + sep + ".." + sep + "x", "../../x", "../x/*.py", "..\\..\\x"):
        tool_input = {"pattern": "needle", "path": base, "glob": glob}
        assert RULE_ID not in _hit_ids(
            _review(_policy("default", platform), platform, "Grep", tool_input)
        ), glob
        assert _decide("default", platform, "Grep", tool_input) != "allow", glob
    # a search pattern that carries its own location is uncertain: not allowed
    for pattern in ("/etc/*", "~/x/**", "../../x/**", "$HOME/*", "C:\\x\\**"):
        tool_input = {"pattern": pattern, "path": base}
        assert _decide("default", platform, "Glob", tool_input) != "allow", pattern


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_a_search_of_the_project_or_the_tmp_dir_is_not_a_scratchpad_search(platform: str) -> None:
    assert RULE_ID not in _hit_ids(
        _review(
            _policy("default", platform), platform, "Grep", {"pattern": "x", "path": TMP[platform]}
        )
    )
    assert _decide("default", platform, "Grep", {"pattern": "x", "path": TMP[platform]}) != "allow"
    assert (
        _decide("default", platform, "Glob", {"pattern": "**/*", "path": TMP[platform]}) != "allow"
    )
    assert (
        _decide(
            "default",
            platform,
            "Grep",
            {"pattern": "x", "path": _join(platform, TMP[platform], "claude")},
        )
        != "allow"
    )


# ---------------------------------------------------------------------------- shell is not covered

SHELL_ON_SCRATCH_BASH = [
    "python {p}/x.py",
    "python3 {p}/x.py",
    "node {p}/x.js",
    "bash {p}/run.sh",
    "sh {p}/run.sh",
    "{p}/run.sh",
    "cat {p}/x.py",
    "cat {p}/data.json",
    "ls {p}",
    "ls -la {p}",
    "head -n 5 {p}/x.py",
    "grep -r needle {p}",
    "rg needle {p}",
    "find {p} -name '*.py'",
    "cp {p}/x.py ./x.py",
    "cp ./a.py {p}/a.py",
    "mv {p}/x.py ./x.py",
    "rm {p}/x.py",
    "rm -rf {p}",
    "mkdir -p {p}/sub",
    "touch {p}/x.py",
    "echo hi > {p}/x.py",
    "tee {p}/x.py",
    "chmod +x {p}/run.sh",
    "pytest {p}",
    "git -C {p} status",
    "cd {p} && ls",
    "cd {p} && python x.py",
    "cd {p}; cat x.py",
    "source {p}/env.sh",
    ". {p}/env.sh",
    "curl -o {p}/x.zip https://example.invalid/x.zip",
    "ruff check {p}",
    "sed -i s/a/b/ {p}/x.py",
]

SHELL_ON_SCRATCH_PS = [
    "python {p}\\x.py",
    "& {p}\\x.ps1",
    ". {p}\\x.ps1",
    "{p}\\x.ps1",
    "powershell -File {p}\\x.ps1",
    "Get-Content {p}\\x.py",
    "Get-Content -LiteralPath {p}\\x.py",
    "Get-ChildItem {p}",
    "ls {p}",
    "cat {p}\\x.py",
    "Set-Content {p}\\x.py 'a'",
    "'a' | Set-Content {p}\\x.py",
    "Out-File {p}\\x.py",
    "Remove-Item {p}\\x.py",
    "Remove-Item -Recurse {p}",
    "Copy-Item {p}\\x.py .\\x.py",
    "Copy-Item .\\a.py {p}\\a.py",
    "New-Item -ItemType Directory {p}\\sub",
    "Set-Location {p}",
    "Set-Location {p}; Get-ChildItem",
    "cd {p}; python x.py",
    "Invoke-Expression (Get-Content {p}\\x.ps1 -Raw)",
    "Select-String needle {p}\\x.py",
    "Test-Path {p}\\x.py",
    "pytest {p}",
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("template", SHELL_ON_SCRATCH_BASH)
def test_bash_commands_on_the_scratchpad_are_exactly_as_before(
    template: str, platform: str
) -> None:
    command = template.replace(
        "{p}", pad(platform).replace("\\", "/") if platform == "windows" else pad(platform)
    )
    now = _decide("default", platform, "Bash", {"command": command})
    before = _decide_old(platform, "Bash", {"command": command})
    assert now == before, (command, now, before)
    assert now != "allow", command
    assert _decide("default", platform, "Bash", {"command": command}, trusted=True) != "allow"


@pytest.mark.parametrize("template", SHELL_ON_SCRATCH_PS)
def test_powershell_commands_on_the_scratchpad_are_exactly_as_before(template: str) -> None:
    command = template.replace("{p}", pad("windows"))
    now = _decide("default", "windows", "PowerShell", {"command": command})
    before = _decide_old("windows", "PowerShell", {"command": command})
    assert now == before, (command, now, before)
    assert now != "allow", command
    assert (
        _decide("default", "windows", "PowerShell", {"command": command}, trusted=True) != "allow"
    )


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_a_shell_tool_that_names_a_scratchpad_path_is_not_marked_allowed_by_the_rule(
    platform: str,
) -> None:
    target = at(platform, "x.py")
    command = f"cat {target}" if platform == "posix" else f"cat '{target}'"
    review = _review(_policy("default", platform), platform, "Bash", {"command": command})
    assert RULE_ID not in _hit_ids(review)
    # the normalizer still marks the path (it is the rule's tool list that keeps the shell out)
    assert any(ref.in_scratchpad for a in review.actions for ref in a.paths)


# ---------------------------------------------------------------------------- the differential


def _positive_targets(platform: str) -> list[tuple[str, str]]:
    out = []
    for tool in RULE_TOOLS:
        for names in NAMES[:5]:
            out.append((tool, at(platform, *names)))
    return out


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_the_positives_are_the_only_verdicts_that_changed(platform: str) -> None:
    for tool, target in _positive_targets(platform):
        now = _decide("default", platform, tool, _tool_input(tool, target))
        before = _decide_old(platform, tool, _tool_input(tool, target))
        assert now == "allow", (tool, target)
        assert before != "allow", (tool, target, before)  # it really is the rule that moved them


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_strict_gives_the_scratchpad_no_allow(platform: str) -> None:
    for tool, target in _positive_targets(platform):
        assert _decide("strict", platform, tool, _tool_input(tool, target)) != "allow", (
            tool,
            target,
        )


# ---------------------------------------------------------------------------- real disk


def _disk_platform() -> Any:
    return "windows" if sys.platform == "win32" else "posix"


def _env_for(platform: str, tmp: Path, home: Path) -> dict[str, str]:
    if platform == "windows":
        return {
            "USERPROFILE": str(home),
            "TEMP": str(tmp),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
        }
    return {"HOME": str(home), "TMPDIR": str(tmp)}


def _make_link(target: Path, link: Path) -> None:
    """A directory symlink, or a junction on Windows when symlinks need a privilege."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        if sys.platform != "win32":
            pytest.skip("cannot create symlinks here")
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False
    )
    if result.returncode != 0:
        pytest.skip("cannot create symlinks or junctions here")


def _make_junction(target: Path, link: Path) -> None:
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False
    )
    if result.returncode != 0:
        pytest.skip("cannot create a junction here")


def _make_symlink(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symlinks")


class Disk:
    """A real temp dir, project and home under ``tmp_path`` and a real scratchpad in it."""

    def __init__(self, tmp_path: Path) -> None:
        self.platform = _disk_platform()
        self.home = tmp_path / "home"
        self.project = self.home / "proj"
        self.tmp = tmp_path / "Temp"
        self.slug = "e--proj"
        self.root = self.tmp / "claude" / self.slug / SID
        self.pad = self.root / "scratchpad"
        self.pad.mkdir(parents=True)
        self.project.mkdir(parents=True)
        (self.project / "src").mkdir()
        (self.project / "src" / "app.py").write_text("x", encoding="utf-8")
        self.outside = tmp_path / "outside"
        self.outside.mkdir()
        (self.outside / "f.py").write_text("x", encoding="utf-8")
        self.env = _env_for(self.platform, self.tmp, self.home)
        self.policy = parse_policy_text(_text("default"), home=str(self.home))

    def review(
        self,
        tool: str,
        tool_input: dict[str, Any],
        *,
        scan: bool = True,
        env: dict[str, str] | None = None,
        sid: str | None = SID,
    ) -> Any:
        payload = {
            "tool_name": tool,
            "tool_input": tool_input,
            "cwd": str(self.project),
            "project_dir": str(self.project),
            "session_id": sid,
        }
        env = env or self.env
        runtime, _ = pipeline.runtime_policy_checked(self.policy, env, str(self.home))
        return pipeline.review(
            payload, runtime, platform=self.platform, env=env, home=str(self.home), scan_disk=scan
        )

    def decide(self, tool: str, target: Path | str, **kw: Any) -> str:
        return str(self.review(tool, _tool_input(tool, str(target)), **kw).verdict.decision)

    def hits(self, tool: str, target: Path | str, **kw: Any) -> set[str]:
        return _hit_ids(self.review(tool, _tool_input(tool, str(target)), **kw))


@pytest.fixture
def disk(tmp_path: Path) -> Disk:
    return Disk(tmp_path)


def test_disk_a_real_scratchpad_file_is_allowed_and_the_refs_are_marked(disk: Disk) -> None:
    (disk.pad / "x.py").write_text("x", encoding="utf-8")
    for tool in RULE_TOOLS:
        review = disk.review(tool, _tool_input(tool, str(disk.pad / "x.py")))
        assert review.verdict.decision == "allow", (tool, review.verdict.reasons)
    new = disk.pad / "new" / "deeper" / "file.py"  # does not exist yet
    assert disk.decide("Write", new) == "allow"
    assert disk.decide("Read", disk.pad) == "allow"
    assert disk.decide("Grep", disk.pad) == "allow"
    assert disk.decide("Glob", disk.pad) == "allow"


def test_disk_other_places_are_not_the_scratchpad(disk: Disk) -> None:
    for target in (
        disk.root,
        disk.root.parent,
        disk.tmp / "claude",
        disk.tmp,
        disk.root / "scratchpad2" / "x.py",
        disk.outside / "f.py",
        disk.tmp / "claude" / disk.slug / OTHER_SID / "scratchpad" / "x.py",
    ):
        assert RULE_ID not in disk.hits("Write", target), target
        assert disk.decide("Write", target) != "allow", target
    assert disk.decide("Write", disk.pad / "x.py", sid=OTHER_SID) != "allow"
    assert disk.decide("Write", disk.pad / "x.py", sid=None) != "allow"


def _junction_cases(disk: Disk, make: Callable[[Path, Path], None]) -> None:
    link_to_project = disk.pad / "to-project"
    link_to_outside = disk.pad / "to-outside"
    make(disk.project, link_to_project)
    make(disk.outside, link_to_outside)
    for tool in ("Write", "Read", "Edit", "Grep", "Glob"):
        for link in (link_to_project, link_to_outside):
            for target in (link, link / "f.py", link / "new" / "f.py", link / "src" / "app.py"):
                review = disk.review(tool, _tool_input(tool, str(target)))
                assert RULE_ID not in _hit_ids(review), (tool, target)
                assert (
                    review.verdict.decision != "allow"
                    or "read-inside-project" in _hit_ids(review)
                    or ("allow-project-file-writes" in _hit_ids(review))
                ), (tool, target)
    # a link inside the scratchpad to ANOTHER place inside it is still the scratchpad
    inner = disk.pad / "real"
    inner.mkdir()
    (inner / "ok.py").write_text("x", encoding="utf-8")
    make(inner, disk.pad / "alias")
    assert disk.decide("Write", disk.pad / "alias" / "ok.py") == "allow"
    assert disk.decide("Read", disk.pad / "alias" / "ok.py") == "allow"


@pytest.mark.windows
def test_disk_a_junction_inside_the_scratchpad_that_leads_out_is_not_marked(disk: Disk) -> None:
    _junction_cases(disk, _make_junction)


def test_disk_a_symlink_inside_the_scratchpad_that_leads_out_is_not_marked(disk: Disk) -> None:
    _junction_cases(disk, _make_symlink)


def _root_link_cases(disk: Disk, make: Callable[[Path, Path], None], what: str) -> None:
    disk.pad.rmdir()
    if what == "pad":
        make(disk.outside, disk.pad)
    elif what == "session":
        disk.root.rmdir()
        make(disk.outside, disk.root)
    elif what == "slug":
        disk.root.rmdir()
        disk.root.parent.rmdir()
        make(disk.outside, disk.root.parent)
    else:
        raise AssertionError(what)
    for tool in ("Write", "Read", "Edit"):
        for target in (disk.pad, disk.pad / "f.py", disk.pad / "new.py"):
            review = disk.review(tool, _tool_input(tool, str(target)))
            assert RULE_ID not in _hit_ids(review), (what, tool, target)
            assert review.verdict.decision != "allow", (what, tool, target)


@pytest.mark.windows
@pytest.mark.parametrize("what", ["pad", "session", "slug"])
def test_disk_the_scratchpad_root_being_a_junction_elsewhere_is_not_marked(
    disk: Disk, what: str
) -> None:
    _root_link_cases(disk, _make_junction, what)


@pytest.mark.parametrize("what", ["pad", "session", "slug"])
def test_disk_the_scratchpad_root_being_a_symlink_elsewhere_is_not_marked(
    disk: Disk, what: str
) -> None:
    _root_link_cases(disk, _make_symlink, what)


def test_disk_a_temp_directory_that_is_itself_a_link_still_works(tmp_path: Path) -> None:
    real = tmp_path / "realtmp"
    real.mkdir()
    link = tmp_path / "Temp"
    _make_link(real, link)
    home = tmp_path / "home"
    project = home / "proj"
    project.mkdir(parents=True)
    pad_dir = real / "claude" / "e--proj" / SID / "scratchpad"
    pad_dir.mkdir(parents=True)
    env = _env_for(_disk_platform(), link, home)
    policy = parse_policy_text(_text("default"), home=str(home))
    runtime, _ = pipeline.runtime_policy_checked(policy, env, str(home))

    def decide(tool: str, target: Path) -> str:
        payload = {
            "tool_name": tool,
            "tool_input": _tool_input(tool, str(target)),
            "cwd": str(project),
            "project_dir": str(project),
            "session_id": SID,
        }
        return str(
            pipeline.review(
                payload, runtime, platform=_disk_platform(), env=env, home=str(home)
            ).verdict.decision
        )

    # as Claude Code names it (through TEMP) and as the disk names it
    assert decide("Write", link / "claude" / "e--proj" / SID / "scratchpad" / "x.py") == "allow"
    assert (
        decide("Write", link / "claude" / "e--proj" / OTHER_SID / "scratchpad" / "x.py") != "allow"
    )


@pytest.mark.windows
def test_disk_a_temp_directory_given_with_an_8_3_short_name(tmp_path: Path) -> None:
    long_tmp = tmp_path / "A Long Temp Name"
    pad_dir = long_tmp / "claude" / "e--proj" / SID / "scratchpad"
    pad_dir.mkdir(parents=True)
    buf = ctypes.create_unicode_buffer(1024)
    ctypes.windll.kernel32.GetShortPathNameW(str(long_tmp), buf, 1024)  # type: ignore[attr-defined]
    short = buf.value
    if not short or short.lower() == str(long_tmp).lower():
        pytest.skip("8.3 short names are disabled on this volume")
    home = tmp_path / "home"
    project = home / "proj"
    project.mkdir(parents=True)
    env = _env_for("windows", Path(short), home)
    policy = parse_policy_text(_text("default"), home=str(home))
    runtime, _ = pipeline.runtime_policy_checked(policy, env, str(home))

    def decide(target: str) -> str:
        payload = {
            "tool_name": "Write",
            "tool_input": _tool_input("Write", target),
            "cwd": str(project),
            "project_dir": str(project),
            "session_id": SID,
        }
        return str(
            pipeline.review(
                payload, runtime, platform="windows", env=env, home=str(home)
            ).verdict.decision
        )

    # Claude Code names the scratchpad in full: the short TEMP is resolved to compare with it
    assert decide(str(pad_dir / "x.py")) == "allow"
    # a path that spells the short name is uncertain lexically: never marked
    assert decide(str(Path(short) / "claude" / "e--proj" / SID / "scratchpad" / "x.py")) != "allow"


def test_disk_the_subtree_scan_of_a_search_of_the_scratchpad_keeps_working(disk: Disk) -> None:
    (disk.pad / "a.py").write_text("x", encoding="utf-8")
    assert disk.decide("Grep", disk.pad) == "allow"
    nested = disk.pad / "deep" / "er"
    nested.mkdir(parents=True)
    (nested / "ok.py").write_text("x", encoding="utf-8")
    assert disk.decide("Grep", disk.pad) == "allow"
    (nested / ".env").write_text("x", encoding="utf-8")
    review = disk.review("Grep", _tool_input("Grep", str(disk.pad)))
    assert review.verdict.decision == "deny"
    assert "no-secret-read" in _hit_ids(review)
    (disk.pad / "a.py").write_text("x", encoding="utf-8")
    only = disk.review("Grep", {"pattern": "x", "path": str(disk.pad), "glob": "*.py"})
    assert only.verdict.decision in ("allow", "deny")  # the glob narrows the scan


def test_disk_a_protected_file_is_found_through_every_search_form(disk: Disk) -> None:
    (disk.pad / "id_rsa").write_text("x", encoding="utf-8")
    assert disk.decide("Grep", disk.pad) == "deny"
    assert disk.decide("Grep", disk.pad / "id_rsa") == "deny"
    assert disk.decide("Read", disk.pad / "id_rsa") == "deny"
    review = disk.review("Grep", {"pattern": "x", "path": str(disk.pad), "glob": "id_rsa"})
    assert review.verdict.decision == "deny"


def test_disk_a_directory_link_in_the_scratchpad_is_not_followed_by_a_search(disk: Disk) -> None:
    secret_dir = disk.outside / "keys"
    secret_dir.mkdir()
    (secret_dir / "id_rsa").write_text("x", encoding="utf-8")
    _make_link(secret_dir, disk.pad / "link")
    # Grep (ripgrep) does not follow the link; the link target itself is outside the scratchpad
    review = disk.review("Grep", _tool_input("Grep", str(disk.pad / "link")))
    assert review.verdict.decision != "allow"
    assert RULE_ID not in _hit_ids(review)


# ---------------------------------------------------------------------------- embedded tests


def _embedded() -> list[Any]:
    return list(_policy("default", "posix").tests)


def test_the_embedded_tests_pin_the_rule_on_both_platforms() -> None:
    cases = [t for t in _embedded() if t.session_id is not None]
    assert cases, "tests: entries with a session_id are missing"
    assert {tuple(t.platform or ()) for t in cases} >= {("windows",), ("posix",)}
    for t in cases:
        assert t.platform is not None, "a scratchpad path is per platform"
        assert len(t.platform) == 1
    assert sum(1 for t in cases if t.expect == "allow") >= 6
    assert sum(1 for t in cases if t.expect != "allow") >= 8


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_every_embedded_scratchpad_test_gets_its_verdict(platform: str) -> None:
    policy = _policy("default", platform)
    ran = 0
    for case in policy.tests:
        if case.session_id is None or platform not in (case.platform or ()):
            continue
        if case.tool == "PowerShell" and not _ps_ready():
            continue
        result = policycli._run_one(
            policy,
            platform,
            case.tool,
            case.input.thaw(),
            case.cwd,
            case.project_dir,
            case.session_id,  # type: ignore[arg-type]
        )
        assert result.verdict.decision == case.expect, (case.tool, case.input.thaw())
        ran += 1
    assert ran >= 6


def test_a_policy_test_may_carry_a_session_id() -> None:
    text = (
        "version: 1\nrules:\n  - id: r\n    tool: [Write]\n    match: {path_in_scratchpad: true}\n"
        "    action: allow\n"
        "tests:\n  - tool: Write\n    platform: posix\n    session_id: " + SID + "\n"
        f"    input: {{file_path: {at('posix', 'x.py')}, content: x}}\n    expect: allow\n"
        "  - tool: Write\n    platform: posix\n"
        f"    input: {{file_path: {at('posix', 'x.py')}, content: x}}\n    expect: gray\n"
    )
    policy = parse_policy_text(text, home="/home/testuser")
    assert [t.session_id for t in policy.tests] == [SID, None]
    for case in policy.tests:
        got = policycli._run_one(
            policy,
            "posix",
            case.tool,
            case.input.thaw(),
            case.cwd,
            case.project_dir,
            case.session_id,
        )
        assert got.verdict.decision == case.expect


def test_a_policy_test_session_id_is_bounded() -> None:
    text = (
        "version: 1\ntests:\n  - tool: Write\n    session_id: " + "x" * 200 + "\n"
        "    input: {file_path: a, content: x}\n    expect: gray\n"
    )
    with pytest.raises(PolicyError, match="session_id"):
        parse_policy_text(text, home="/home/testuser")


def test_run_one_defaults_to_a_session_id_that_is_not_a_scratchpad() -> None:
    policy = _policy("default", "posix")
    review = policycli._run_one(
        policy, "posix", "Write", _tool_input("Write", at("posix", "x.py")), None, None
    )
    assert review.verdict.decision == "gray"
    again = policycli._run_one(
        policy, "posix", "Write", _tool_input("Write", at("posix", "x.py")), None, None, SID
    )
    assert again.verdict.decision == "allow"


# ---------------------------------------------------------------------------- the corpora


def _new_entries() -> list[dict[str, Any]]:
    data = yaml.safe_load(NEW_CORPUS.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    return data


def test_the_new_pipeline_corpus_is_big_unique_and_adversarial() -> None:
    entries = _new_entries()
    assert len(entries) >= 80
    ids = [e["id"] for e in entries]
    assert len(set(ids)) == len(ids)
    assert sum(1 for e in entries if e.get("adv")) >= 40
    assert all(e["expect"] != "allow" for e in entries if e.get("adv"))
    assert sum(1 for e in entries if e["expect"] == "allow") >= 12
    assert {e["tool"] for e in entries} >= {"Write", "Read", "Grep", "Glob", "Bash", "PowerShell"}
    for entry in entries:
        sid = entry.get("session_id")
        assert sid is None or isinstance(sid, str), entry["id"]
    assert sum(1 for e in entries if e.get("session_id") == SID) >= 60


def test_an_allow_entry_of_the_new_corpus_is_a_file_tool_in_the_rule() -> None:
    for entry in _new_entries():
        if entry["expect"] == "allow":
            assert entry["tool"] in RULE_TOOLS, entry["id"]
            assert str(entry.get("session_id")).casefold() == SID, entry["id"]


def test_the_workflow_corpus_has_the_scratchpad_tier() -> None:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    scratch = [e for e in data if e["tier"] == "t2-scratch"]
    assert len(scratch) >= 10
    assert all(e["expect_after"] == "allow" for e in scratch)
    carrying = [e for e in data if "session_id" in e]
    assert len(carrying) >= 20
    assert all(e["session_id"] == SID for e in carrying)
    # the dangerous ones sit in the tiers that may never be allow
    dangerous = [e for e in carrying if e["tier"] in ("must-block", "keep-ask", "t3-exec")]
    assert len(dangerous) >= 8
    assert not any(
        (e["expect_after"] if isinstance(e["expect_after"], str) else "ask") == "allow"
        for e in dangerous
    )


# ---------------------------------------------------------------------------- the measuring tool


def _measure_tool() -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "measure_ask_rate_m1c4", ROOT / "scripts" / "measure_ask_rate.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_measuring_tool_passes_the_session_id_only_when_an_entry_has_one() -> None:
    tool = _measure_tool()
    seen: list[tuple[str, dict[str, Any]]] = []

    def run_one(
        policy: Any, platform: str, name: str, tool_input: Any, **extra: Any
    ) -> str:  # a stand-in for _run_one
        seen.append((name, extra))
        return "allow"

    entries = [
        {
            "id": "a",
            "tool": "Write",
            "input": {"file_path": "x"},
            "tier": "t2-scratch",
            "expect_after": "allow",
            "session_id": SID,
        },
        {
            "id": "b",
            "tool": "Read",
            "input": {"file_path": "x"},
            "tier": "t1-read",
            "expect_after": "allow",
        },
    ]
    result = tool.measure_platform(
        entries, _policy("default", "posix"), "posix", ps_available=False, run_one=run_one
    )
    assert seen == [("Write", {"session_id": SID}), ("Read", {})]
    assert not result.mismatches


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_the_scratch_tier_of_the_workflow_corpus_is_allow_and_nothing_dangerous_is(
    platform: str,
) -> None:
    tool = _measure_tool()
    entries = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    result = tool.measure_platform(
        entries, _policy("default", platform), platform, ps_available=_ps_ready()
    )
    assert not result.mismatches, [(m.id, m.expected, m.got) for m in result.mismatches]
    assert tool.asks_per_100(result.by_tier["t2-scratch"]) == 0.0
    assert result.by_tier["t2-scratch"].get("allow", 0) >= 9
    for tier in ("must-block", "keep-ask", "t3-exec"):
        assert result.by_tier[tier].get("allow", 0) == 0, tier
    before = tool.measure_platform(
        entries, _m1c3_policy(platform), platform, ps_available=_ps_ready()
    )
    assert tool.asks_per_100(before.by_tier["t2-scratch"]) == 100.0  # what the rule changes


# ---------------------------------------------------------------------------- explain


def test_explain_shows_the_scratchpad_mark_and_the_rule(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    boundkeep_home: Path,
) -> None:
    from boundkeep import cli

    tmp = tmp_path / "Temp"
    pad_dir = tmp / "claude" / "e--proj" / SID / "scratchpad"
    pad_dir.mkdir(parents=True)
    project = tmp_path / "proj"
    project.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    for name in ("TEMP", "TMP", "TMPDIR"):
        monkeypatch.setenv(name, str(tmp))
    for name in ("USERPROFILE", "HOME"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    event = {
        "tool_name": "Write",
        "tool_input": {"file_path": str(pad_dir / "x.py"), "content": "x"},
        "cwd": str(project),
        "project_dir": str(project),
        "session_id": SID,
    }
    path = tmp_path / "event.json"
    path.write_text(json.dumps(event), encoding="utf-8")
    code = cli.main(
        [
            "--home",
            str(boundkeep_home),
            "explain",
            str(path),
            "--policy",
            str(POLICIES / "default.yaml"),
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "in_scratchpad" in out
    assert RULE_ID in out
    assert "verdict: allow" in out
    event["session_id"] = OTHER_SID
    path.write_text(json.dumps(event), encoding="utf-8")
    cli.main(
        [
            "--home",
            str(boundkeep_home),
            "explain",
            str(path),
            "--policy",
            str(POLICIES / "default.yaml"),
        ]
    )
    other = capsys.readouterr().out
    assert "in_scratchpad" not in other
    assert RULE_ID not in other
