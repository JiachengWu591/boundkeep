"""X1 review of M1c / M1c-2 (docs/reviews/M1c2-security-review.md), findings H-5 and H-6.

* H-5  an agent can make a project "trusted" through a child process that has a real console. The
        cheap fixes: ``trust add`` refuses in a process Claude Code started (tests in
        test_m1c2_trust_cli.py) and the daemon keeps ``trusted_projects`` as it was when each
        session began (here);
* H-6  a hard link to a protected file inside the project is the protected file: a path with more
        than one name is never "shown to be inside the project" (real files, here), and creating
        such a link to a guard file is refused (rules, here).

Everything runs against temporary directories. No command is executed: they are only normalized.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from boundkeep import policycli, trust
from boundkeep.daemon import pipeline
from boundkeep.daemon.server import MAX_TRUST_SESSIONS, _TrustSnapshots
from boundkeep.normalize import paths as norm_paths
from boundkeep.policy import default_policy_text, parse_policy_text
from tests.unit.test_daemon import Harness

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"
PLATFORMS = ("windows", "posix")
PLATFORM_IDS = [f"on-{p}" for p in PLATFORMS]  # conftest.py skips ids that are the bare words


# ---------------------------------------------------------------------------- H-5: snapshots


def test_a_session_keeps_the_trust_it_began_with() -> None:
    snaps = _TrustSnapshots()
    assert snaps.effective("s1", ("a",)) == (("a",), ())
    # an entry added later does not count for the session, and is reported once
    assert snaps.effective("s1", ("a", "b")) == (("a",), ("b",))
    assert snaps.effective("s1", ("a", "b")) == (("a",), ())
    # a new session gets the current list
    assert snaps.effective("s2", ("a", "b")) == (("a", "b"), ())
    # an entry removed stops counting at once, and counts again if it comes back
    assert snaps.effective("s2", ("a",)) == (("a",), ())
    assert snaps.effective("s2", ("a", "b")) == (("a", "b"), ())


def test_a_session_that_began_without_trust_never_gains_it() -> None:
    snaps = _TrustSnapshots()
    assert snaps.effective("s1", ()) == ((), ())
    assert snaps.effective("s1", ("a",)) == ((), ("a",))
    assert snaps.effective("s1", ("a", "b")) == ((), ("b",))


@pytest.mark.parametrize("session_id", [None, "", 7, ["s"], "x" * 201, b"s"])
def test_a_session_without_a_usable_id_gets_no_trust(session_id: object) -> None:
    assert _TrustSnapshots().effective(session_id, ("a",)) == ((), ())


def test_the_snapshots_are_bounded_and_the_oldest_session_is_forgotten() -> None:
    snaps = _TrustSnapshots(limit=3)
    for n in range(3):
        snaps.effective(f"s{n}", ())
    snaps.effective("s0", ())  # s0 is now the most recent
    snaps.effective("s3", ())  # drops s1, the oldest
    assert snaps.effective("s1", ("a",)) == (("a",), ())  # forgotten: it is a new session
    assert snaps.effective("s0", ("a",)) == ((), ("a",))  # remembered: no trust gained
    assert MAX_TRUST_SESSIONS >= 100


def _trusted_text(project: str) -> str:
    return trust.add_entry_text(default_policy_text(), project)


def _write(harness: Harness, text: str) -> None:
    Path(harness.policy).write_text(text, encoding="utf-8")


def _pytest_event(session_id: object, request: str = "r") -> dict[str, Any]:
    event: dict[str, Any] = {
        "hook_event_name": "PreToolUse",
        "cwd": "E:\\proj",
        "project_dir": "E:\\proj",
        "tool_name": "Bash",
        "tool_use_id": f"toolu_{request}",
        "tool_input": {"command": "pytest -q"},
    }
    if session_id is not None:
        event["session_id"] = session_id
    return event


def _verdict(harness: Harness, session_id: object, n: int = 0) -> str:
    """``none`` (the rules allow it: no decision) or ``ask``."""
    response = harness.send("pre", _pytest_event(session_id, str(n)), f"r{n}")
    assert response.ok
    return str(response.decision)


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path / "home")


def test_the_daemon_denies_a_trust_added_in_the_middle_of_a_session(harness: Harness) -> None:
    assert _verdict(harness, "session-a", 1) == "ask"  # nobody is trusted yet
    _write(harness, _trusted_text("E:\\proj"))  # `trust add`, or an agent's edit of the file
    assert _verdict(harness, "session-a", 2) == "ask"  # not for the session that was running
    assert _verdict(harness, "session-b", 3) == "none"  # a session that starts later has it
    assert _verdict(harness, "session-a", 4) == "ask"
    assert any("trusted_projects grew" in m for m in harness.messages)
    records = [r for r in harness.log.tail(1000) if r.get("event") == "trust-changed"]
    assert len(records) == 1  # reported once per session and entry, not on every event
    assert records[0]["decided_by"] == "trust-snapshot"
    assert records[0]["session_id"] == "session-a"


def test_the_first_event_of_a_session_may_be_a_prompt(harness: Harness) -> None:
    prompt = {"hook_event_name": "UserPromptSubmit", "prompt": "hi", "session_id": "s-prompt"}
    assert harness.send("prompt", prompt, "p1").ok
    _write(harness, _trusted_text("E:\\proj"))
    assert _verdict(harness, "s-prompt", 1) == "ask"


def test_a_trust_that_was_there_at_the_start_works_and_is_removed_at_once(
    harness: Harness,
) -> None:
    _write(harness, _trusted_text("E:\\proj"))
    assert _verdict(harness, "session-a", 1) == "none"
    assert _verdict(harness, "session-a", 2) == "none"
    _write(harness, default_policy_text())  # `trust remove`
    assert _verdict(harness, "session-a", 3) == "ask"  # narrowing takes effect immediately
    _write(harness, _trusted_text("E:\\proj"))  # added back: it was in the session's snapshot
    assert _verdict(harness, "session-a", 4) == "none"


def test_a_second_project_added_later_does_not_count_for_the_running_session(
    harness: Harness,
) -> None:
    _write(harness, _trusted_text("E:\\proj"))
    assert _verdict(harness, "session-a", 1) == "none"
    _write(harness, trust.add_entry_text(_trusted_text("E:\\proj"), "E:\\other"))
    other = _pytest_event("session-a", "o")
    other["cwd"] = other["project_dir"] = "E:\\other"
    assert harness.send("pre", other, "o1").decision == "ask"
    assert _verdict(harness, "session-a", 2) == "none"  # the first project still counts
    other["session_id"] = "session-b"
    assert harness.send("pre", other, "o2").decision == "none"


@pytest.mark.parametrize("session_id", [None, "", 7, "x" * 201])
def test_an_event_without_a_usable_session_id_gets_no_trusted_project(
    harness: Harness, session_id: object
) -> None:
    _write(harness, _trusted_text("E:\\proj"))
    assert _verdict(harness, session_id, 1) == "ask"


def test_the_snapshot_applies_to_pretooluse_only_and_changes_no_other_rule(
    harness: Harness,
) -> None:
    _write(harness, _trusted_text("E:\\proj"))
    event = _pytest_event("s")
    event["tool_input"] = {"command": "rm -rf /"}
    assert harness.send("pre", event, "d1").decision == "deny"  # the other rules are untouched


# ---------------------------------------------------------------------------- H-6: hard links


def _link_or_skip(target: Path, link: Path) -> None:
    try:
        os.link(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("this file system has no hard links")


@pytest.fixture
def tree(tmp_path: Path) -> dict[str, Path]:
    home = tmp_path / "home"
    project = tmp_path / "proj"
    guard = home / ".boundkeep"
    guard.mkdir(parents=True)
    project.mkdir()
    secret = home / "outside.txt"
    policy = guard / "policy.yaml"
    policy.write_text("version: 1\n", encoding="utf-8")
    secret.write_text("secret\n", encoding="utf-8")
    (project / "plain.txt").write_text("x", encoding="utf-8")
    return {"home": home, "project": project, "policy": policy, "secret": secret}


def _review(tree: dict[str, Path], tool: str, tool_input: dict[str, Any]) -> Any:
    home = str(tree["home"])
    policy = parse_policy_text(default_policy_text(), home=home)
    env = {k: v for k, v in os.environ.items() if k.upper() in ("SYSTEMROOT", "PATH", "TEMP")}
    env["USERPROFILE"] = env["HOME"] = home
    runtime, _problem = pipeline.runtime_policy_checked(policy, env, home)
    payload = {
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": str(tree["project"]),
        "project_dir": str(tree["project"]),
        "session_id": "s",
    }
    return pipeline.review(payload, runtime, platform=pipeline.local_platform(), env=env, home=home)


def test_a_hard_link_is_reported_by_the_disk_layer(tree: dict[str, Path]) -> None:
    link = tree["project"] / "hard.yaml"
    _link_or_skip(tree["policy"], link)
    norm = norm_paths.normalize_path(str(link), cwd=None, home=None, dialect="tool", literal=True)
    assert norm_paths.HARD_LINKED in norm_paths.resolve_on_disk(norm).reasons
    plain = norm_paths.normalize_path(
        str(tree["project"] / "plain.txt"), cwd=None, home=None, dialect="tool", literal=True
    )
    assert norm_paths.HARD_LINKED not in norm_paths.resolve_on_disk(plain).reasons
    # a directory, a path that does not exist and a file with one name are not "hard linked"
    for other in (tree["project"], tree["project"] / "missing.txt"):
        n = norm_paths.normalize_path(str(other), cwd=None, home=None, dialect="tool", literal=True)
        assert norm_paths.HARD_LINKED not in norm_paths.resolve_on_disk(n).reasons


@pytest.mark.parametrize(
    ("tool", "key"),
    [
        ("Write", "file_path"),
        ("Edit", "file_path"),
        ("Read", "file_path"),
        ("NotebookEdit", "notebook_path"),
    ],
)
def test_a_file_tool_on_a_hard_link_is_no_longer_allow(
    tree: dict[str, Path], tool: str, key: str
) -> None:
    link = tree["project"] / "hard.yaml"
    plain = tree["project"] / "plain.txt"
    _link_or_skip(tree["policy"], link)
    extra = {"content": "x"} if tool == "Write" else {}
    # the control: a file with one name is allowed, exactly as before
    assert _review(tree, tool, {key: str(plain), **extra}).verdict.decision == "allow"
    got = _review(tree, tool, {key: str(link), **extra}).verdict.decision
    assert got != "allow", got
    # the same file under its ordinary name in the project is allowed again once the link is gone
    link.unlink()
    assert _review(tree, tool, {key: str(link), **extra}).verdict.decision == "allow"


def test_the_marked_path_says_why_and_keeps_its_name(tree: dict[str, Path]) -> None:
    link = tree["project"] / "hard.yaml"
    _link_or_skip(tree["secret"], link)
    result = _review(tree, "Write", {"file_path": str(link), "content": "x"})
    (action,) = result.actions
    refs = [r for r in action.paths if norm_paths.HARD_LINKED in r.reasons]
    assert refs
    assert all(r.inside_project is None and not r.in_scratchpad for r in refs)
    assert any(r.key.endswith("/proj/hard.yaml") for r in refs)  # the name still reaches deny rules


def test_a_hard_link_to_a_secret_is_still_judged_by_its_name_and_by_the_link_rule(
    tree: dict[str, Path],
) -> None:
    link = tree["project"] / ".env"
    _link_or_skip(tree["secret"], link)
    assert _review(tree, "Read", {"file_path": str(link)}).verdict.decision == "deny"


def test_a_directory_listing_is_not_hard_linked_and_stays_allowed(tree: dict[str, Path]) -> None:
    assert _review(tree, "Glob", {"pattern": "*.txt"}).verdict.decision == "allow"
    assert _review(
        tree, "Grep", {"pattern": "x", "path": str(tree["project"])}
    ).verdict.decision == ("allow")


# ---------------------------------------------------------------------------- H-6: the link rules


def _guard_globs(name: str, rule_id: str) -> list[str]:
    data = yaml.safe_load((POLICIES / f"{name}.yaml").read_text(encoding="utf-8"))
    (rule,) = [r for r in data["rules"] if r["id"] == rule_id]
    return list(rule["match"]["path_glob"])


@pytest.mark.parametrize("name", ["default", "strict"])
def test_the_link_rules_protect_exactly_what_protect_guard_config_protects(name: str) -> None:
    config = _guard_globs(name, "protect-guard-config")
    assert _guard_globs(name, "deny-link-to-guard-files") == config
    assert _guard_globs(name, "deny-link-copy-of-guard-files") == config


@pytest.mark.parametrize("name", ["default", "strict"])
def test_the_link_rules_are_deny_rules_on_read_access_with_the_expected_programs(
    name: str,
) -> None:
    data = yaml.safe_load((POLICIES / f"{name}.yaml").read_text(encoding="utf-8"))
    rules = {r["id"]: r for r in data["rules"]}
    link = rules["deny-link-to-guard-files"]
    assert (link["action"], link["match"]["access"]) == ("deny", "read")
    assert set(link["match"]["program"]) == {"ln", "New-Item"}
    assert "tool" not in link  # a read rule never filters by tool (test_policy_rules.py)
    copy = rules["deny-link-copy-of-guard-files"]
    assert (copy["action"], copy["match"]["access"]) == ("deny", "read")
    assert copy["match"]["program"] == ["cp"]
    assert set(copy["match"]["flags_any"]) == {"-l", "--link"}


def _decide(platform: str, tool: str, command: str, name: str = "default") -> str:
    text = (POLICIES / f"{name}.yaml").read_text(encoding="utf-8")
    policy = parse_policy_text(text, home=policycli._FAKE[platform]["home"])
    if tool == "PowerShell" and sys.platform != "win32":
        pytest.skip("PowerShell entries need the real parser helper (Windows only)")
    result = policycli._run_one(policy, platform, tool, {"command": command}, None, None)  # type: ignore[arg-type]
    return str(result.verdict.decision)


WIN = "C:\\Users\\testuser"
LINKS_TO_GUARD_FILES = [
    ("Bash", "ln C:/Users/testuser/.boundkeep/policy.yaml hard.yaml"),
    ("Bash", "ln /home/testuser/.boundkeep/policy.yaml hard.yaml"),
    ("Bash", "ln ~/.boundkeep/policy.yaml hard.yaml"),
    ("Bash", "ln ~/.boundkeep/audit.jsonl hard.jsonl"),
    ("Bash", "ln -f ~/.boundkeep/policy.yaml hard.yaml"),
    ("Bash", "ln -s ~/.boundkeep/policy.yaml soft.yaml"),
    ("Bash", "ln -s ~/.boundkeep soft"),
    ("Bash", "ln .claude/settings.json hard.json"),
    ("Bash", "ln .claude/settings.local.json hard.json"),
    ("Bash", "ln ~/.claude/settings.json hard.json"),
    ("Bash", "ln /home/testuser/proj/.claude/settings.json hard.json"),
    ("Bash", "ln ~/.claude hardclaude"),
    ("Bash", "ln -t . ~/.boundkeep/policy.yaml"),
    ("Bash", "ln ~/.boundkeep/policy.yaml ~/.boundkeep/policy.copy"),
    ("Bash", "ln managed-settings.json x"),
    ("Bash", "cp -l ~/.boundkeep/policy.yaml hard.yaml"),
    ("Bash", "cp --link ~/.boundkeep/policy.yaml hard.yaml"),
    ("Bash", "cp -al ~/.claude/settings.json x"),
    ("Bash", "cp -lr ~/.boundkeep x"),
    ("Bash", "cp -l .claude/settings.json x"),
    (
        "PowerShell",
        f"New-Item -ItemType HardLink -Path hard.yaml -Value '{WIN}\\.boundkeep\\policy.yaml'",
    ),
    ("PowerShell", f"New-Item -ItemType HardLink -Name l -Target '{WIN}\\.boundkeep\\policy.yaml'"),
    ("PowerShell", "New-Item -ItemType HardLink -Path hard.yaml -Value ~\\.boundkeep\\policy.yaml"),
    ("PowerShell", "New-Item -ItemType SymbolicLink -Path l -Target ~\\.boundkeep\\policy.yaml"),
    ("PowerShell", "New-Item -ItemType Junction -Path l -Target ~\\.boundkeep"),
    ("PowerShell", "New-Item -ItemType HardLink -Path hard.json -Value .claude\\settings.json"),
    ("PowerShell", "New-Item -ItemType HardLink -Path hard.json -Value ~\\.claude\\settings.json"),
    ("PowerShell", "ni -ItemType HardLink -Path hard.yaml -Value ~\\.boundkeep\\policy.yaml"),
    ("PowerShell", "New-Item hard.yaml -ItemType HardLink -Value ~\\.boundkeep\\policy.yaml"),
    ("PowerShell", "New-Item -Type HardLink -Path hard.yaml -Value ~\\.boundkeep\\policy.yaml"),
    ("PowerShell", "ln ~\\.boundkeep\\policy.yaml hard.yaml"),
]


@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("tool", "command"), LINKS_TO_GUARD_FILES, ids=lambda v: str(v)[:70])
def test_a_link_to_a_guard_file_is_denied(
    platform: str, tool: str, command: str, name: str
) -> None:
    if tool == "PowerShell" and platform != "windows":
        pytest.skip("PowerShell runs on the Windows fake machine")
    assert _decide(platform, tool, command, name) == "deny", command


LINKS_THAT_ARE_NOT_DENIED = [
    ("Bash", "ln a.txt b.txt"),
    ("Bash", "ln -s src dst"),
    ("Bash", "ln -s ../README.md readme"),
    ("Bash", "cp -l a.txt b.txt"),
    ("Bash", "cp a.txt b.txt"),
    ("Bash", "cp -r src backup"),
    ("Bash", "cp ~/.boundkeep/policy.yaml x"),  # a copy is a read: ask-guard-state-read, not a link
    ("Bash", "cat ~/.boundkeep/policy.yaml"),
    ("PowerShell", "New-Item notes.txt -ItemType File"),
    ("PowerShell", "New-Item -ItemType Directory -Path build"),
    ("PowerShell", "New-Item -ItemType HardLink -Path b.txt -Value a.txt"),
    ("PowerShell", "New-Item -ItemType SymbolicLink -Path l -Target src"),
    ("PowerShell", "Get-Content ~\\.boundkeep\\policy.yaml"),
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("tool", "command"), LINKS_THAT_ARE_NOT_DENIED, ids=lambda v: str(v)[:70])
def test_other_links_and_copies_keep_their_old_verdicts(
    platform: str, tool: str, command: str
) -> None:
    if tool == "PowerShell" and platform != "windows":
        pytest.skip("PowerShell runs on the Windows fake machine")
    assert _decide(platform, tool, command) != "deny", command


def test_a_copy_of_a_guard_file_is_still_only_an_ask() -> None:
    for platform in PLATFORMS:
        assert _decide(platform, "Bash", "cp ~/.boundkeep/policy.yaml x") == "ask"


def test_the_link_rules_do_not_make_a_directory_search_find_a_settings_file() -> None:
    # reading the project's .claude/settings.json is allowed on purpose: a Grep over a directory
    # must not treat it as a protected name just because a LINK rule names it
    policy = parse_policy_text(default_policy_text(), home=policycli._FAKE["windows"]["home"])
    protected = pipeline.protected_read_globs(policy)
    assert "**/.claude/settings*.json" not in protected
    assert "**/.boundkeep/**" in protected  # (from ask-guard-state-read: unchanged)
    assert "~/.claude/settings*.json" not in protected


def test_the_machine_dependent_protections_get_link_rules_too(tmp_path: Path) -> None:
    config_dir = str(tmp_path / "cfg")
    home = str(tmp_path / "home")
    policy = parse_policy_text(default_policy_text(), home=home)
    env = {"CLAUDE_CONFIG_DIR": config_dir}
    runtime, _problem = pipeline.runtime_policy_checked(policy, env, home)
    ids = {r.id for r in runtime.rules}
    assert {"deny-link-protect-guard-config-dir", "deny-link-copy-protect-guard-config-dir"} <= ids
    assert {"deny-link-protect-guard-code", "deny-link-copy-protect-guard-code"} <= ids
    for rule in runtime.rules:
        if rule.id.startswith(pipeline.LINK_RULE_PREFIX):
            assert rule.action == "deny"
            assert rule.match.access == "read"
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": f"ln {config_dir.replace(chr(92), '/')}/settings.json hard.json"},
        "cwd": str(tmp_path / "proj"),
        "project_dir": str(tmp_path / "proj"),
        "session_id": "s",
    }
    result = pipeline.review(
        payload, runtime, platform=pipeline.local_platform(), env=env, home=home
    )
    assert result.verdict.decision == "deny"
    assert "deny-link-protect-guard-config-dir" in result.verdict.rule_ids
