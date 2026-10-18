"""Security review round 2, pure logic: what may weaken the gate (M-6), the install record's file
hashes (M-4), the ``--emit-allow`` pin, the scope notice (H-3) and the daemon's startup warning.

No real ``~/.boundkeep`` or ``~/.claude`` is touched: every file lives under ``tmp_path`` and the
environment variables that point at user directories are redirected there.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from boundkeep import claude_settings, doctor, hook_main, install, paths, settings_io
from boundkeep.claude_settings import assess_settings, blocking_reasons, watched_fingerprints
from boundkeep.daemon.server import Daemon
from boundkeep.ipc.endpoint import TRANSPORT_NAMED_PIPE, Endpoint
from boundkeep.logstore import AuditLog

PY = "C:\\uv\\python\\python.exe"
SCRIPT = "E:\\proj\\boundkeep\\src\\boundkeep\\hook_client.py"
OUR_PRE = {
    "type": "command",
    "command": PY,
    "args": ["-I", "-S", SCRIPT, "pre"],
    "timeout": 15,
}
FOREIGN = {"type": "command", "command": "C:\\other\\fmt.exe"}


def _levels(data: dict[str, Any], baseline: dict[str, str] | None = None) -> dict[str, str]:
    result: dict[str, str] = {}
    for concern in assess_settings(data, baseline=baseline):
        result.setdefault(concern.key, concern.level)
    return result


# ---- M-6: what may weaken the gate ----------------------------------------------------------


def test_the_home_redirect_env_names_match_the_config_change_hook() -> None:
    # hook_main keeps its own copy (it must stay import-light); they must not drift apart.
    # (Once hook_main takes its list from claude_settings this has nothing left to compare.)
    theirs = getattr(hook_main, "_RISKY_ENV_NAMES", None)
    if theirs is None:
        pytest.skip("hook_main no longer keeps its own list")
    assert theirs <= claude_settings.HOME_REDIRECT_ENV | claude_settings.EXTRA_RISKY_ENV
    assert theirs | claude_settings.EXTRA_RISKY_ENV >= claude_settings.HOME_REDIRECT_ENV


@pytest.mark.parametrize(
    "rule",
    [
        "Bash(*)",
        "Bash",
        "Bash(**)",
        "Bash(:*)",
        " PowerShell(*) ",
        "PowerShell",
        "Write(*)",
        "Edit(*)",
        "MultiEdit",
        "NotebookEdit(*)",
        "*",
        "bash(*)",
    ],
)
def test_blanket_allow_rules_block(rule: str) -> None:
    assert _levels({"permissions": {"allow": ["Read(src/**)", rule]}}) == {
        "permissions.allow": "block"
    }


@pytest.mark.parametrize(
    "rule",
    [
        "Bash(git status)",
        "Bash(npm run test:*)",
        "Read(*)",
        "Write(docs/**)",
        "WebFetch(domain:x.y)",
        5,
    ],
)
def test_narrow_or_unrelated_allow_rules_do_not_block(rule: object) -> None:
    assert _levels({"permissions": {"allow": [rule]}}) == {}


def test_a_malformed_permissions_block_is_ignored_not_crashed_on() -> None:
    for value in ("x", ["Bash(*)"], None, {"allow": "Bash(*)"}, {"allow": None}):
        assert _levels({"permissions": value}) == {}


@pytest.mark.parametrize("mode", ["bypassPermissions", "BYPASSPERMISSIONS"])
def test_bypass_permissions_blocks(mode: str) -> None:
    assert _levels({"permissions": {"defaultMode": mode}}) == {"permissions.defaultMode": "block"}


def test_other_default_modes_do_not_block() -> None:
    for mode in ("default", "acceptEdits", "plan", "dontAsk", None, 3):
        assert _levels({"permissions": {"defaultMode": mode}}) == {}
    assert _levels({"permissions": {"defaultMode": "auto"}}) == {"permissions.defaultMode": "warn"}


@pytest.mark.parametrize("value", [True, "true", 1, "false", {"a": 1}])
def test_skip_dangerous_prompt_blocks_unless_false_or_null(value: object) -> None:
    assert _levels({"skipDangerousModePermissionPrompt": value}) == {
        "skipDangerousModePermissionPrompt": "block"
    }
    assert _levels({"skipDangerousModePermissionPrompt": False}) == {}
    assert _levels({"skipDangerousModePermissionPrompt": None}) == {}


@pytest.mark.parametrize(
    "name",
    [
        "PATH",
        "Path",
        "PATHEXT",
        "COMSPEC",
        "NODE_OPTIONS",
        "CLAUDE_CODE_GIT_BASH_PATH",
        "PSModulePath",
        "PYTHONPATH",
        "PYTHONHOME",
        "pythonstartup",
        "CLAUDE_PROJECT_DIR",
    ],
)
def test_risky_env_names_block(name: str) -> None:
    assert _levels({"env": {name: "x"}}) == {"env": "block"}


@pytest.mark.parametrize("name", ["BOUNDKEEP_HOME", "boundkeep_x", "USERPROFILE", "HOME"])
def test_home_redirecting_env_names_are_refused_by_init(name: str) -> None:
    [concern] = assess_settings({"env": {name: "x"}})
    assert concern.level == "block"
    assert concern.refuse is True


def test_env_that_only_blocks_is_not_refused() -> None:
    [concern] = assess_settings({"env": {"PATH": "x"}})
    assert concern.refuse is False


def test_harmless_and_noteworthy_env() -> None:
    assert _levels({"env": {"FOO": "1", "DEBUG": "x", "ANTHROPIC_MODEL": "m"}}) == {}
    assert _levels({"env": {"ANTHROPIC_BASE_URL": "https://gw.example"}}) == {"env": "info"}


def test_an_env_block_that_is_not_an_object_is_refused() -> None:
    [concern] = assess_settings({"env": ["PATH"]})
    assert (concern.level, concern.refuse) == ("block", True)


def test_disable_all_hooks_is_refused() -> None:
    [concern] = assess_settings({"disableAllHooks": True})
    assert (concern.key, concern.level, concern.refuse) == ("disableAllHooks", "block", True)
    assert assess_settings({"disableAllHooks": False}) == []


def test_every_message_says_may_not_certainly() -> None:
    data: dict[str, Any] = {
        "permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]},
        "skipDangerousModePermissionPrompt": True,
        "env": {"PATH": "x"},
    }
    for concern in assess_settings(data):
        assert "may" in concern.message, concern.message


def test_exec_keys_are_noted_without_a_baseline() -> None:
    for key in claude_settings.EXEC_KEYS:
        assert _levels({key: {"type": "command", "command": "x"}}) == {key: "info"}


def test_exec_keys_with_a_baseline_block_only_when_added_or_changed() -> None:
    base = watched_fingerprints({"statusLine": {"command": "a"}})
    assert _levels({"statusLine": {"command": "a"}}, base) == {}
    assert _levels({"statusLine": {"command": "b"}}, base) == {"statusLine": "block"}
    assert _levels({"apiKeyHelper": "x"}, base) == {"apiKeyHelper": "block"}
    assert _levels({}, base) == {}  # removed: not a weakening
    assert _levels({"statusLine": {"command": "a"}}, {}) == {"statusLine": "block"}


def test_the_fingerprint_does_not_depend_on_key_order() -> None:
    one = watched_fingerprints({"statusLine": {"type": "command", "command": "x"}})
    two = watched_fingerprints({"statusLine": {"command": "x", "type": "command"}})
    assert one == two


def test_a_foreign_pre_tool_use_hook_warns_then_is_a_baseline() -> None:
    data = {
        "hooks": {"PreToolUse": [{"hooks": [OUR_PRE]}, {"matcher": "Bash", "hooks": [FOREIGN]}]}
    }
    assert _levels(data) == {"hooks.PreToolUse": "warn"}
    base = watched_fingerprints(data)
    assert _levels(data, base) == {}
    other = {
        "hooks": {"PreToolUse": [{"hooks": [OUR_PRE]}, {"matcher": "Edit", "hooks": [FOREIGN]}]}
    }
    assert _levels(other, base) == {"hooks.PreToolUse": "block"}
    two = {"hooks": {"PreToolUse": [{"hooks": [OUR_PRE, FOREIGN, {**FOREIGN, "command": "y"}]}]}}
    assert _levels(two, base) == {"hooks.PreToolUse": "block"}


def test_our_own_entries_and_other_events_are_not_foreign_hooks() -> None:
    data = {
        "hooks": {
            "PreToolUse": [{"matcher": "*", "hooks": [OUR_PRE]}],
            "PostToolUse": [{"hooks": [FOREIGN]}],
            "SessionStart": [{"hooks": [FOREIGN]}],
        }
    }
    assert _levels(data) == {}


def test_a_permission_request_hook_is_watched_like_a_pre_tool_use_hook() -> None:
    data = {"hooks": {"PermissionRequest": [{"hooks": [FOREIGN]}]}}
    assert _levels(data) == {"hooks.PermissionRequest": "warn"}


def test_a_misplaced_event_blocks_only_where_our_hooks_are() -> None:
    plain = {"PreToolUse": []}
    assert [c.level for c in assess_settings(plain)] == ["block"]
    assert blocking_reasons(plain) == []  # no boundkeep hooks in this file: not its business
    ours = {**plain, "hooks": {"PreToolUse": [{"hooks": [OUR_PRE]}]}}
    assert len(blocking_reasons(ours)) == 1


def test_hook_event_misspellings_block_and_unknown_names_warn() -> None:
    near = {"hooks": {"PreToolUze": [], "posttooluse": []}}
    assert [(c.key, c.level) for c in assess_settings(near)] == [
        ("hooks.PreToolUze", "block"),
        ("hooks.posttooluse", "block"),
    ]
    far = {"hooks": {"SomethingCompletelyNew": []}}
    assert [(c.key, c.level) for c in assess_settings(far)] == [
        ("hooks.SomethingCompletelyNew", "warn")
    ]
    assert assess_settings({"hooks": {"PreToolUse": [], "Stop": []}}) == []


def test_an_unknown_top_level_key_warns_and_a_known_one_does_not() -> None:
    assert _levels({"someFutureKey": 1}) == {"someFutureKey": "warn"}
    assert _levels({"model": "x", "theme": "dark", "$schema": "x"}) == {}


def test_blocking_reasons_lists_every_blocker() -> None:
    data = {
        "disableAllHooks": True,
        "permissions": {"allow": ["Bash(*)"]},
        "statusLine": {"command": "x"},
    }
    reasons = blocking_reasons(data, {})
    assert len(reasons) == 3
    assert blocking_reasons({"model": "x"}) == []


def test_assess_settings_never_crashes_on_odd_documents() -> None:
    odd: list[dict[str, Any]] = [
        {"hooks": []},
        {"hooks": {"PreToolUse": "x"}},
        {"hooks": {"PreToolUse": [1, None, {"hooks": 5}, {"hooks": [7]}]}},
        {"hooks": {1: []}},
        {"env": {"A": None}, "permissions": {"allow": [None, 5, {"a": 1}]}},
        {"statusLine": None},
    ]
    for data in odd:
        assess_settings(data)
        blocking_reasons(data, {})


# ---- the emit-allow pin ---------------------------------------------------------------------


def test_with_emit_allow_adds_and_removes_the_flag() -> None:
    base = ("-I", "-S", SCRIPT, "--home", "C:\\h")
    on = install.with_emit_allow(base, True)
    assert on == (*base, "--emit-allow")
    assert install.with_emit_allow(on, True) == on  # no duplicate
    assert install.with_emit_allow(on, False) == base
    assert install.with_emit_allow(base, False) == base


def test_has_emit_allow_looks_before_the_subcommand_only() -> None:
    assert install.has_emit_allow(["-I", "--emit-allow", "pre"]) is True
    assert install.has_emit_allow(["-I", "pre"]) is False
    assert install.has_emit_allow(["--emit-allow"]) is False  # that is the subcommand slot
    assert install.has_emit_allow([]) is False


def test_the_pinned_command_is_still_our_own_entry_in_every_group() -> None:
    cmd = install.HookCommand(
        PY, install.with_emit_allow(("-I", "-S", SCRIPT, "--home", "C:\\h"), True)
    )
    groups = install.build_hook_groups(cmd, post_matcher="*")
    assert set(groups) == set(hook_main.ownhook.SUBCOMMANDS)
    for group in groups.values():
        [entry] = group["hooks"]
        assert entry["args"][-1] in hook_main.ownhook.SUBCOMMANDS.values()
        assert entry["args"].count("--emit-allow") == 1
        assert hook_main.entry_intact(entry, entry["args"][-1])


# ---- M-4: file hashes -----------------------------------------------------------------------


def _hook_dir(tmp_path: Path) -> tuple[Path, install.HookCommand]:
    package = tmp_path / "boundkeep"
    package.mkdir()
    (package / "hook_client.py").write_bytes(b"client\r\n")
    (package / "hook_main.py").write_bytes(b"main\n")
    exe = tmp_path / "python.exe"
    exe.write_bytes(b"MZ-not-really")
    command = install.HookCommand(str(exe), ("-I", "-S", str(package / "hook_client.py")))
    return package, command


def test_hook_files_for_hashes_the_exe_and_both_scripts(tmp_path: Path) -> None:
    package, command = _hook_dir(tmp_path)
    files = install.hook_files_for(command)
    assert [Path(f.path).name for f in files] == ["python.exe", "hook_client.py", "hook_main.py"]
    assert files[1].sha256 == install.file_sha256(str(package / "hook_client.py"))
    assert len(files[0].sha256) == 64


def test_raw_bytes_are_hashed_so_a_line_ending_change_is_noticed(tmp_path: Path) -> None:
    package, command = _hook_dir(tmp_path)
    files = install.hook_files_for(command)
    assert install.hook_file_problems(files) == []
    (package / "hook_client.py").write_bytes(b"client\n")
    [problem] = install.hook_file_problems(files)
    assert "hook_client.py" in problem
    assert "no longer matches" in problem


def test_hook_file_problems_names_a_swapped_interpreter_and_a_missing_file(
    tmp_path: Path,
) -> None:
    package, command = _hook_dir(tmp_path)
    files = install.hook_files_for(command)
    Path(command.command).write_bytes(b"evil")
    (package / "hook_main.py").unlink()
    problems = install.hook_file_problems(files)
    assert len(problems) == 2
    assert "python.exe" in problems[0]
    assert "cannot be read" in problems[1]


def test_hook_files_for_refuses_a_file_it_cannot_read(tmp_path: Path) -> None:
    package, command = _hook_dir(tmp_path)
    (package / "hook_main.py").unlink()
    with pytest.raises(OSError, match="hook_main"):
        install.hook_files_for(command)


def test_the_launcher_style_hashes_this_installations_scripts(tmp_path: Path) -> None:
    launcher = tmp_path / "boundkeep-hook.exe"
    launcher.write_bytes(b"launcher")
    files = install.hook_files_for(install.HookCommand(str(launcher), ()))
    assert [Path(f.path).name for f in files] == [
        "boundkeep-hook.exe",
        "hook_client.py",
        "hook_main.py",
    ]


def _record(**overrides: Any) -> install.InstallRecord:
    fields: dict[str, Any] = {
        "settings_path": "C:\\p\\.claude\\settings.json",
        "scope": "project",
        "created_file": False,
        "hook_command": PY,
        "hook_args": ("-I", "-S", SCRIPT),
        "post_matcher": "*",
        "installed_at": "2026-10-18T00:00:00Z",
    }
    fields.update(overrides)
    return install.InstallRecord(**fields)


def test_the_manifest_round_trips_hashes_and_baseline(tmp_path: Path) -> None:
    record = _record(
        hook_files=(install.HookFile("C:\\a.py", "ab" * 32), install.HookFile("C:\\b", "cd" * 32)),
        watched=(("statusLine", "ef" * 32),),
    )
    path = tmp_path / "installs.json"
    install.save_manifest(str(path), [record])
    assert install.load_manifest(str(path)) == [record]
    stored = json.loads(path.read_text(encoding="utf-8"))["installs"][0]
    assert stored["hook_files"][0] == {"path": "C:\\a.py", "sha256": "ab" * 32}
    assert stored["watched"] == {"statusLine": "ef" * 32}


def test_an_old_record_has_no_hashes_and_no_baseline(tmp_path: Path) -> None:
    path = tmp_path / "installs.json"
    install.save_manifest(str(path), [_record()])
    stored = json.loads(path.read_text(encoding="utf-8"))["installs"][0]
    assert "hook_files" not in stored
    assert "watched" not in stored  # the old format round-trips unchanged
    [loaded] = install.load_manifest(str(path))
    assert loaded.hook_files == ()
    assert loaded.watched is None


def test_an_empty_baseline_is_not_the_same_as_none(tmp_path: Path) -> None:
    path = tmp_path / "installs.json"
    install.save_manifest(str(path), [_record(watched=())])
    [loaded] = install.load_manifest(str(path))
    assert loaded.watched == ()


@pytest.mark.parametrize(
    "bad",
    [
        {"hook_files": "x"},
        {"hook_files": [1]},
        {"hook_files": [{"path": "", "sha256": "a"}]},
        {"hook_files": [{"path": "p"}]},
        {"hook_files": [{"path": "p", "sha256": 5}]},
        {"watched": []},
        {"watched": {"a": 1}},
    ],
)
def test_malformed_new_record_fields_are_refused(tmp_path: Path, bad: dict[str, Any]) -> None:
    path = tmp_path / "installs.json"
    install.save_manifest(str(path), [_record()])
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["installs"][0].update(bad)
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(settings_io.SettingsError, match=r"installs\.json"):
        install.load_manifest(str(path))


def test_upsert_keeps_the_new_fields() -> None:
    new = _record(hook_files=(install.HookFile("p", "h"),), watched=(("k", "v"),))
    [kept] = install.upsert_record([_record()], new)
    assert kept.hook_files == new.hook_files
    assert kept.watched == new.watched


def test_integrity_report(tmp_path: Path) -> None:
    package, command = _hook_dir(tmp_path)
    files = install.hook_files_for(command)
    good = _record(hook_files=files)
    assert install.integrity_report([good]) == []
    assert (
        install.integrity_report(
            [good, _record(settings_path="C:\\q\\settings.json", hook_files=files)]
        )
        == []
    )
    [unhashed] = install.integrity_report([_record()])
    assert "no file hashes" in unhashed
    (package / "hook_client.py").write_bytes(b"swapped")
    twice = install.integrity_report(
        [good, _record(settings_path="C:\\q\\settings.json", hook_files=files)]
    )
    assert len(twice) == 1  # the same file is reported once, not once per record
    assert "hook_client.py" in twice[0]


# ---- doctor ---------------------------------------------------------------------------------


def _layer(name: str, tmp_path: Path, data: dict[str, Any] | None) -> doctor.Layer:
    path = tmp_path / f"{name}-settings.json"
    if data is not None:
        path.write_text(json.dumps(data), encoding="utf-8")
    return doctor.Layer(name, str(path), settings_io.load_settings(str(path)), None)


def _ours() -> dict[str, Any]:
    return {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [OUR_PRE]}]}}


def test_env_is_checked_in_a_layer_without_boundkeep_hooks(tmp_path: Path) -> None:
    layer = _layer("user", tmp_path, {"env": {"BOUNDKEEP_HOME": "C:\\evil"}})
    checks = doctor.check_layer(layer, None)
    assert [c.status for c in checks if "BOUNDKEEP_HOME" in c.detail] == [doctor.FAIL]


def test_a_key_typo_in_a_file_without_our_hooks_only_warns(tmp_path: Path) -> None:
    layer = _layer("user", tmp_path, {"PreToolUse": []})
    checks = doctor.check_layer(layer, None)
    assert [c.status for c in checks if "'PreToolUse'" in c.detail] == [doctor.WARN]


def test_a_baseline_less_record_warns_when_watched_entries_exist(tmp_path: Path) -> None:
    layer = _layer("project", tmp_path, {**_ours(), "statusLine": {"command": "x"}})
    checks = doctor.check_layer(layer, _record(settings_path=layer.path))
    assert [c.status for c in checks if "install record has no baseline" in c.detail] == [
        doctor.WARN
    ]


def test_record_integrity_checks(tmp_path: Path) -> None:
    package, command = _hook_dir(tmp_path)
    files = install.hook_files_for(command)
    ok = doctor.check_record_integrity("n", "p", _record(hook_files=files))
    assert [c.status for c in ok] == [doctor.OK]
    old = doctor.check_record_integrity("n", "p", _record())
    assert [c.status for c in old] == [doctor.WARN]
    (package / "hook_main.py").write_bytes(b"swapped")
    bad = doctor.check_record_integrity("n", "p", _record(hook_files=files))
    assert [c.status for c in bad] == [doctor.FAIL]
    assert "no longer matches" in bad[0].detail
    assert "boundkeep init" in bad[0].fix


def test_check_scope_variants(tmp_path: Path) -> None:
    project_only = [_layer("user", tmp_path, {}), _layer("project", tmp_path, _ours())]
    user_level = [_layer("user", tmp_path, _ours()), _layer("project", tmp_path, {})]
    nothing = [_layer("user", tmp_path, {}), _layer("project", tmp_path, {})]
    here = str(tmp_path)

    [warn] = doctor.check_scope(here, False, project_only)
    assert warn.status == doctor.WARN
    assert here in warn.detail
    assert "only to Claude Code sessions opened in" in warn.detail
    assert "--scope user" in warn.fix

    [given] = doctor.check_scope(here, True, project_only)
    assert given.status == doctor.INFO
    assert "only to Claude Code sessions opened in" in given.detail

    [cwd_info] = doctor.check_scope(here, False, user_level)
    assert cwd_info.status == doctor.INFO
    assert "only to Claude Code sessions" not in cwd_info.detail
    assert doctor.check_scope(here, True, user_level) == []
    assert [c.status for c in doctor.check_scope(here, False, nothing)] == [doctor.INFO]


def _policy_home(tmp_path: Path, emit_allow: bool) -> str:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    text = (
        Path(__file__)
        .resolve()
        .parents[2]
        .joinpath("policies", "default.yaml")
        .read_text(encoding="utf-8")
    )
    text = text.replace("emit_allow: false", f"emit_allow: {str(emit_allow).lower()}")
    Path(paths.policy_file(str(home))).write_text(text, encoding="utf-8")
    return str(home)


def _pinned(on: bool) -> dict[str, Any]:
    entry = dict(OUR_PRE)
    entry["args"] = ["-I", "-S", SCRIPT, *(["--emit-allow"] if on else []), "pre"]
    return {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [entry]}]}}


@pytest.mark.parametrize(("policy_on", "pin_on"), [(False, False), (True, True)])
def test_emit_allow_agreement_is_silent(tmp_path: Path, policy_on: bool, pin_on: bool) -> None:
    home = _policy_home(tmp_path, policy_on)
    layers = [_layer("project", tmp_path, _pinned(pin_on))]
    assert doctor.check_emit_allow(home, layers) == []


@pytest.mark.parametrize(("policy_on", "pin_on"), [(False, True), (True, False)])
def test_emit_allow_disagreement_warns(tmp_path: Path, policy_on: bool, pin_on: bool) -> None:
    home = _policy_home(tmp_path, policy_on)
    layers = [_layer("project", tmp_path, _pinned(pin_on)), _layer("user", tmp_path, {})]
    [check] = doctor.check_emit_allow(home, layers)
    assert check.status == doctor.WARN
    assert "project" in check.detail
    assert "init" in check.fix


def test_emit_allow_check_stays_quiet_when_the_policy_does_not_load(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    Path(paths.policy_file(str(home))).write_text("not: [valid", encoding="utf-8")
    assert doctor.check_emit_allow(str(home), [_layer("project", tmp_path, _ours())]) == []


def test_workspace_trust_follows_claude_config_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_home = tmp_path / "userhome"
    fake_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    project = tmp_path / "proj"
    project.mkdir()
    state = {"projects": {str(project).replace("\\", "/"): {"hasTrustDialogAccepted": True}}}

    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    assert doctor.claude_json_path() == str(fake_home / ".claude.json")
    [absent] = doctor.check_workspace_trust(str(project))
    assert absent.status == doctor.INFO
    assert str(fake_home / ".claude.json") in absent.detail

    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    (config_dir / ".claude.json").write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(config_dir))
    assert doctor.claude_json_path() == str(config_dir / ".claude.json")
    [trusted] = doctor.check_workspace_trust(str(project))
    assert trusted.status == doctor.OK

    (config_dir / ".claude.json").write_text(json.dumps({"projects": {}}), encoding="utf-8")
    [untrusted] = doctor.check_workspace_trust(str(project))
    assert untrusted.status == doctor.WARN
    assert str(config_dir / ".claude.json") in untrusted.detail  # not the hard-coded ~/.claude.json


def test_activity_stays_informational_even_when_events_came_from_other_folders(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    log = AuditLog(paths.audit_log_file(str(home)))
    other = tmp_path / "other"
    project = tmp_path / "proj"
    assert log.append({"ts": "t1", "event": "pre", "decision": "ask", "cwd": str(other)})
    [elsewhere] = doctor.check_activity(str(home), str(project))
    assert elsewhere.status == doctor.INFO
    assert str(project) in elsewhere.detail
    assert "nothing about it" in elsewhere.detail
    assert log.append({"ts": "t2", "event": "pre", "decision": "ask", "cwd": str(project / "src")})
    [here] = doctor.check_activity(str(home), str(project))
    assert here.status == doctor.INFO
    assert "none of the last" not in here.detail
    [no_dir] = doctor.check_activity(str(home))
    assert "none of the last" not in no_dir.detail


# ---- the daemon's startup warning -----------------------------------------------------------


def _daemon(tmp_path: Path) -> tuple[Daemon, list[str], str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    messages: list[str] = []
    endpoint = Endpoint(TRANSPORT_NAMED_PIPE, "\\\\.\\pipe\\boundkeep-unit-test-integrity")
    log = AuditLog(paths.audit_log_file(str(home)))
    daemon = Daemon(endpoint, home=str(home), log=log, report=messages.append)
    return daemon, messages, str(home)


def test_the_daemon_is_quiet_without_a_manifest(tmp_path: Path) -> None:
    daemon, messages, _home = _daemon(tmp_path)
    daemon._check_install_integrity()
    assert messages == []


def test_the_daemon_warns_loudly_about_a_swapped_hook_file_and_still_starts(
    tmp_path: Path,
) -> None:
    daemon, messages, home = _daemon(tmp_path)
    package, command = _hook_dir(tmp_path)
    files = install.hook_files_for(command)
    install.save_manifest(paths.manifest_file(home), [_record(hook_files=files)])
    daemon._check_install_integrity()
    assert messages == []
    (package / "hook_client.py").write_bytes(b"swapped")
    daemon._check_install_integrity()  # returns, does not raise: starting is not refused
    assert any("WARNING integrity" in m and "hook_client.py" in m for m in messages)
    assert any("treat this machine's gate as untrusted" in m for m in messages)
    log = AuditLog(paths.audit_log_file(home))
    assert any(r.get("action") == "integrity-warning" for r in log.tail(10))


def test_the_daemon_warns_about_a_record_without_hashes(tmp_path: Path) -> None:
    daemon, messages, home = _daemon(tmp_path)
    install.save_manifest(paths.manifest_file(home), [_record()])
    daemon._check_install_integrity()
    assert any("no file hashes" in m for m in messages)


def test_the_daemon_survives_a_damaged_manifest(tmp_path: Path) -> None:
    daemon, messages, home = _daemon(tmp_path)
    Path(paths.manifest_file(home)).write_text("{not json", encoding="utf-8")
    daemon._check_install_integrity()
    assert any("could not be checked" in m for m in messages)
