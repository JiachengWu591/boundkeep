"""Security review round 3 (docs/reviews/M1-M1b-fixes-rereview.md): C-2 (what is watched), C-3 (what
no longer blocks, and what the sticky block says).

Decisions from the lead's measurement on 2026-10-18 (Claude Code CLI engine, ``claude -p``, haiku):
with the boundkeep hook asking, ``permissions.allow: ["PowerShell(*)"]`` and
``defaultMode: bypassPermissions`` did NOT make the command run. So they are warnings. The re-review
also showed that 39 environment mutations never made the hook client exit with anything but 0 or 2.

Pure functions plus temp files only: no real ``~/.boundkeep``, ``~/.claude`` or project settings.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from boundkeep import claude_settings, doctor, hook_main, settings_io
from boundkeep.claude_settings import assess_settings, blocking_reasons
from tests.unit.test_review3_config_lookalike import OWN, _intact, _write_install

FOREIGN = {"type": "command", "command": "C:\\other\\tool.exe", "args": ["--x"]}
HTTP_HOOK = {"type": "http", "url": "https://hooks.example/x"}

EVENTS_BESIDES_OURS = [
    "SessionStart",
    "SessionEnd",
    "Setup",
    "Stop",
    "SubagentStop",
    "Notification",
    "PreCompact",
    "PostCompact",
    "PostToolUseFailure",
    "PermissionRequest",
    "PermissionDenied",
    "InstructionsLoaded",
    "FileChanged",
    "CwdChanged",
]
# Events boundkeep also installs an entry in: a foreign hook next to ours there counts too.
OUR_EVENTS = ["UserPromptSubmit", "PreToolUse", "PostToolUse", "ConfigChange"]


def _levels(
    data: dict[str, Any], baseline: dict[str, str] | None = None
) -> dict[str, tuple[str, str]]:
    return {
        c.key: (c.level, c.kind)
        for c in assess_settings(data, baseline=baseline, own=OWN)
        if c.kind == "watched"
    }


def _with_hook(event: str, hook: dict[str, Any]) -> dict[str, Any]:
    data = _intact()
    groups = data["hooks"].setdefault(event, [])
    groups.append({"hooks": [copy.deepcopy(hook)]})
    return data


# ---- C-2: foreign hooks in every event are watched ---------------------------------------------


@pytest.mark.parametrize("event", [*EVENTS_BESIDES_OURS, *OUR_EVENTS])
def test_a_foreign_command_hook_added_after_init_blocks_in_every_event(event: str) -> None:
    baseline = claude_settings.make_baseline(_intact(), OWN)
    data = _with_hook(event, FOREIGN)
    reasons = blocking_reasons(data, baseline, OWN)
    assert len(reasons) == 1, reasons
    assert "boundkeep init" in reasons[0]


@pytest.mark.parametrize("event", ["SessionStart", "Stop", "UserPromptSubmit", "PostToolUse"])
def test_through_config_violation_a_new_foreign_hook_blocks_until_init_is_rerun(
    event: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    baseline = claude_settings.make_baseline(_intact(), OWN)
    path = _write_install(tmp_path, monkeypatch, _with_hook(event, FOREIGN), watched=baseline)
    problem = hook_main.config_violation(str(path))
    assert problem is not None
    assert event in problem


def test_a_foreign_hook_present_at_init_is_the_baseline_not_a_block() -> None:
    data = _with_hook("SessionStart", FOREIGN)
    baseline = claude_settings.make_baseline(data, OWN)
    assert blocking_reasons(data, baseline, OWN) == []
    assert "hooks.SessionStart" in baseline
    changed = _with_hook("SessionStart", dict(FOREIGN, command="C:\\other\\evil.exe"))
    assert len(blocking_reasons(changed, baseline, OWN)) == 1


def test_hooks_that_start_no_program_are_not_counted_outside_the_decision_events() -> None:
    data = _with_hook("Stop", HTTP_HOOK)
    assert _levels(data) == {}
    assert _levels(_with_hook("Stop", {"type": "prompt", "prompt": "x"})) == {}
    # ... but in PreToolUse every foreign entry counts, whatever its type
    assert _levels(_with_hook("PreToolUse", HTTP_HOOK)) == {"hooks.PreToolUse": ("warn", "watched")}


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("enabledPlugins", {"evil@market": True}),
        ("extraKnownMarketplaces", {"m": {"source": {"source": "github", "repo": "a/b"}}}),
        ("mcpServers", {"x": {"command": "C:\\x\\server.exe"}}),
        ("appendPlugins", ["a"]),
        ("pluginConfigs", {"a": {"b": 1}}),
        ("enableAllProjectMcpServers", True),
        ("enabledMcpjsonServers", ["x"]),
    ],
)
def test_plugin_and_mcp_keys_added_after_init_block(key: str, value: object) -> None:
    baseline = claude_settings.make_baseline(_intact(), OWN)
    data = {**_intact(), key: value}
    reasons = blocking_reasons(data, baseline, OWN)
    assert len(reasons) == 1, reasons
    assert key in reasons[0]
    assert "boundkeep init" in reasons[0]


def test_a_plugin_key_present_at_init_is_the_baseline() -> None:
    start = {**_intact(), "enabledPlugins": {"a@m": True, "b@m": True}}
    baseline = claude_settings.make_baseline(start, OWN)
    assert blocking_reasons(start, baseline, OWN) == []
    more = {**_intact(), "enabledPlugins": {"a@m": True, "b@m": True, "c@m": True}}
    assert len(blocking_reasons(more, baseline, OWN)) == 1
    assert claude_settings.watched_fingerprints({"enabledPlugins": {}}) == {}
    assert claude_settings.watched_fingerprints({"mcpServers": {}}) == {}


def test_removing_a_watched_entry_is_not_a_weakening() -> None:
    start = _with_hook("Stop", FOREIGN)
    baseline = claude_settings.make_baseline(start, OWN)
    assert blocking_reasons(_intact(), baseline, OWN) == []


# ---- C-2: files with no baseline are noted, never blocked ---------------------------------------


@pytest.mark.parametrize("event", ["SessionStart", "Stop", "PreToolUse"])
def test_a_file_without_a_baseline_only_warns_and_says_it_does_not_block(event: str) -> None:
    data = _with_hook(event, FOREIGN)
    assert blocking_reasons(data) == []
    assert blocking_reasons(data, None, OWN) == []
    [concern] = [c for c in assess_settings(data, own=OWN) if c.kind == "watched"]
    assert concern.level == "warn"
    assert "NOT blocked" in concern.message
    assert "no baseline" in concern.message


def test_command_keys_without_a_baseline_are_info_and_say_so() -> None:
    data = {"statusLine": {"type": "command", "command": "x"}, "enabledPlugins": {"a@m": True}}
    concerns = {c.key: c for c in assess_settings(data) if c.kind == "watched"}
    assert {c.level for c in concerns.values()} == {"info"}
    assert all("NOT blocked" in c.message for c in concerns.values())
    assert blocking_reasons(data) == []


def test_a_user_level_file_with_no_record_is_not_blocked_through_config_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_install(tmp_path, monkeypatch, _intact())
    other = tmp_path / "userhome" / "settings.json"
    other.parent.mkdir()
    other.write_text(
        json.dumps(
            {"statusLine": {"command": "x"}, "hooks": {"SessionStart": [{"hooks": [FOREIGN]}]}}
        ),
        encoding="utf-8",
    )
    assert hook_main.config_violation(str(other)) is None


# ---- baselines made by an older boundkeep --------------------------------------------------------


def test_an_old_baseline_still_judges_what_it_covered_and_only_warns_about_the_rest() -> None:
    old = claude_settings.watched_fingerprints(_intact(), OWN)  # no marker: the round-2 format
    assert claude_settings.BASELINE_MARK not in old
    stat = {**_intact(), "statusLine": {"command": "x"}}
    assert len(blocking_reasons(stat, old, OWN)) == 1  # covered before: still a block
    pre = _with_hook("PreToolUse", FOREIGN)
    assert len(blocking_reasons(pre, old, OWN)) == 1
    stop = _with_hook("Stop", FOREIGN)
    assert blocking_reasons(stop, old, OWN) == []  # not covered by that baseline: warn only
    [concern] = [c for c in assess_settings(stop, baseline=old, own=OWN) if c.kind == "watched"]
    assert concern.level == "warn"
    assert "boundkeep init" in concern.message
    plug = {**_intact(), "enabledPlugins": {"a@m": True}}
    assert blocking_reasons(plug, old, OWN) == []


# ---- C-3: the sticky block says what to do -------------------------------------------------------


def test_the_baseline_block_tells_the_user_to_run_init_and_that_all_changes_are_blocked() -> None:
    baseline = claude_settings.make_baseline(_intact(), OWN)
    [reason] = blocking_reasons({**_intact(), "statusLine": {"command": "x"}}, baseline, OWN)
    assert "boundkeep init" in reason
    assert "accept the new command-running entries" in reason
    assert "every settings change to this file is blocked" in reason


def test_any_change_to_the_file_is_blocked_until_init_records_the_new_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    baseline = claude_settings.make_baseline(_intact(), OWN)
    drifted = {**_with_hook("SessionStart", FOREIGN), "theme": "dark"}  # /config changed the theme
    path = _write_install(tmp_path, monkeypatch, drifted, watched=baseline)
    problem = hook_main.config_violation(str(path))
    assert problem is not None
    assert "boundkeep init" in problem
    # what 'boundkeep init' does for this file: record the baseline of the file as it is now
    fresh = claude_settings.make_baseline(drifted, OWN)
    _write_install(tmp_path, monkeypatch, drifted, watched=fresh)
    assert hook_main.config_violation(str(path)) is None


def test_doctor_gives_the_same_instruction_for_a_baseline_drift(tmp_path: Path) -> None:
    baseline = claude_settings.make_baseline(_intact(), OWN)
    data = _with_hook("SessionStart", FOREIGN)
    layer_path = tmp_path / "settings.json"
    layer_path.write_text(json.dumps(data), encoding="utf-8")
    layer = doctor.Layer(
        "project", str(layer_path), settings_io.load_settings(str(layer_path)), None
    )
    record = _doctor_record(str(layer_path), baseline)
    checks = doctor.check_layer(layer, record)
    hits = [c for c in checks if "SessionStart hook that is not boundkeep's" in c.detail]
    assert [c.status for c in hits] == [doctor.FAIL]
    assert "boundkeep init" in hits[0].fix


def _doctor_record(settings_path: str, baseline: dict[str, str]) -> Any:
    from boundkeep import install
    from tests.unit.test_review3_config_lookalike import BASE_ARGS, PY

    return install.InstallRecord(
        settings_path=settings_path,
        scope="project",
        created_file=False,
        hook_command=PY,
        hook_args=tuple(BASE_ARGS),
        post_matcher="*",
        installed_at="2026-10-18T00:00:00Z",
        watched=tuple(sorted(baseline.items())),
    )


# ---- C-3: permissions are warnings, with the measured wording --------------------------------

WORDING = (
    "observed on 2026-10-18 (Claude Code CLI engine, -p mode): the hook's ask still took "
    "precedence; behaviour in other modes/hosts is untested"
)


@pytest.mark.parametrize(
    "data",
    [
        {"permissions": {"allow": ["PowerShell(*)"]}},
        {"permissions": {"allow": ["Bash(*)", "Write"]}},
        {"permissions": {"defaultMode": "bypassPermissions"}},
        {"skipDangerousModePermissionPrompt": True},
    ],
)
def test_blanket_permissions_are_warnings_with_the_measured_wording(data: dict[str, Any]) -> None:
    [concern] = assess_settings(data)
    assert concern.level == "warn"
    assert WORDING in concern.message
    assert "may weaken" in concern.message
    assert blocking_reasons({**_intact(), **data}, None, OWN) == []


def test_the_allow_pattern_list_was_not_widened() -> None:
    for rule in ("Bash(python:*)", "Bash(git status)", "Bash(*:*)", "Read(*)", "Write(//**)"):
        assert assess_settings({"permissions": {"allow": [rule]}}) == [], rule


def test_a_blanket_allow_does_not_block_a_config_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = {
        **_intact(),
        "permissions": {"allow": ["PowerShell(*)"], "defaultMode": "bypassPermissions"},
    }
    path = _write_install(
        tmp_path, monkeypatch, data, watched=claude_settings.make_baseline(_intact(), OWN)
    )
    assert hook_main.config_violation(str(path)) is None


def test_doctor_reports_blanket_permissions_as_warn_not_fail(tmp_path: Path) -> None:
    layer_path = tmp_path / "settings.json"
    layer_path.write_text(
        json.dumps({"permissions": {"allow": ["PowerShell(*)"]}}), encoding="utf-8"
    )
    layer = doctor.Layer("user", str(layer_path), settings_io.load_settings(str(layer_path)), None)
    hits = [c for c in doctor.check_layer(layer, None) if "permissions.allow" in c.detail]
    assert [c.status for c in hits] == [doctor.WARN]
    assert "2026-10-18" in hits[0].detail


# ---- C-3: the environment names ------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "USERPROFILE",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "CLAUDE_CONFIG_DIR",
        "CLAUDE_CODE_SIMPLE",
        "CLAUDE_CODE_SAFE_MODE",
        "CLAUDE_PROJECT_DIR",
        "BOUNDKEEP_HOME",
        "boundkeep_anything",
    ],
)
def test_env_names_that_redirect_the_home_or_the_root_or_switch_hooks_off_still_block(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = {**_intact(), "env": {name: "x"}}
    path = _write_install(tmp_path, monkeypatch, data)
    assert hook_main.config_violation(str(path)) is not None
    assert [c.level for c in assess_settings({"env": {name: "x"}})] == ["block"]


@pytest.mark.parametrize(
    "name",
    [
        "PATH",
        "Path",
        "PATHEXT",
        "COMSPEC",
        "PSModulePath",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PYTHONUTF8",
        "PYTHONPATH",
        "PYTHONIOENCODING",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
    ],
)
def test_env_names_without_a_demonstrated_attack_no_longer_block(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = {**_intact(), "env": {name: "x"}}
    path = _write_install(tmp_path, monkeypatch, data)
    assert hook_main.config_violation(str(path)) is None
    assert blocking_reasons(data, None, OWN) == []
    assert all(c.level != "block" for c in assess_settings(data))


def test_the_blocking_env_sets_of_hook_main_and_claude_settings_are_the_same() -> None:
    assert hook_main._RISKY_ENV_NAMES == claude_settings.BLOCKING_ENV
    assert claude_settings.BLOCKING_ENV_PREFIXES == ("BOUNDKEEP_",)
    for gone in ("PATH", "PATHEXT", "COMSPEC", "PSMODULEPATH", "NODE_OPTIONS", "NODE_PATH"):
        assert gone not in hook_main._RISKY_ENV_NAMES
        assert gone in claude_settings.WARN_ENV


def test_doctor_shows_path_like_env_as_warn_and_python_env_as_info(tmp_path: Path) -> None:
    layer_path = tmp_path / "settings.json"
    layer_path.write_text(
        json.dumps({"env": {"PATH": "C:\\x", "PYTHONUTF8": "1"}}), encoding="utf-8"
    )
    layer = doctor.Layer("user", str(layer_path), settings_io.load_settings(str(layer_path)), None)
    status = {
        c.detail.split("sets ")[1].split(",")[0].split(";")[0]: c.status
        for c in doctor.check_layer(layer, None)
        if "sets " in c.detail
    }
    assert status == {"PATH": doctor.WARN, "PYTHONUTF8": doctor.INFO}
