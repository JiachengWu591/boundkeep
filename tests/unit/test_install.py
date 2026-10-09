"""install: hook entries, merge / remove, settings paths, manifest, launch self check, goldens."""

from __future__ import annotations

import copy
import json
import os
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st

from boundkeep.install import (
    HookCommand,
    HookTimeouts,
    InstallRecord,
    MergeReport,
    SelfCheckResult,
    build_hook_groups,
    drop_record,
    load_manifest,
    merge_hooks,
    remove_hooks,
    resolve_settings_path,
    run_self_check,
    save_manifest,
    upsert_record,
)
from boundkeep.ownhook import SUBCOMMANDS, is_own_hook, own_hooks_in
from boundkeep.settings_io import SettingsError, load_settings, render_settings

POST = "WebFetch|WebSearch|mcp__.*"
PY_CMD = HookCommand(
    "C:\\Users\\dev\\proj\\.venv\\Scripts\\python.exe",
    ("-I", "-S", "C:\\Users\\dev\\proj\\src\\boundkeep\\hook_client.py"),
)
EXE_CMD = HookCommand("C:\\Users\\dev\\proj\\.venv\\Scripts\\boundkeep-hook.exe")
POSIX_CMD = HookCommand("/home/dev/proj/.venv/bin/boundkeep-hook")
POSIX_PY_CMD = HookCommand(
    "/home/dev/proj/.venv/bin/python",
    ("-I", "-S", "/home/dev/proj/src/boundkeep/hook_client.py"),
)
CJK_CMD = HookCommand(
    "C:\\Users\\张三\\My Tools\\.venv\\Scripts\\python.exe",
    ("-I", "-S", "C:\\Users\\张三\\My Tools\\boundkeep\\src\\boundkeep\\hook_client.py"),
)
OLD_CMD = HookCommand(
    "D:\\old\\.venv\\Scripts\\python.exe",
    ("-I", "-S", "D:\\old\\boundkeep\\src\\boundkeep\\hook_client.py"),
)
ALL_COMMANDS = [PY_CMD, EXE_CMD, POSIX_CMD, POSIX_PY_CMD, CJK_CMD]
EVENTS = list(SUBCOMMANDS)


def groups_for(cmd: HookCommand = PY_CMD, post: str = POST) -> dict[str, dict[str, Any]]:
    return build_hook_groups(cmd, post_matcher=post)


def foreign(command: str, **extra: Any) -> dict[str, Any]:
    return {"type": "command", "command": command, **extra}


def count_own(settings: Any) -> int:
    return sum(1 for _ in own_hooks_in(settings))


def same(a: Any, b: Any) -> bool:
    return json.dumps(a) == json.dumps(b)


# ---- HookCommand / build_hook_groups --------------------------------------------------------


def test_hook_command_argv() -> None:
    assert PY_CMD.args_for("pre") == [
        "-I",
        "-S",
        "C:\\Users\\dev\\proj\\src\\boundkeep\\hook_client.py",
        "pre",
    ]
    assert PY_CMD.argv_for("pre")[0] == PY_CMD.command
    assert EXE_CMD.args_for("post") == ["post"]
    assert EXE_CMD.argv_for("post") == [EXE_CMD.command, "post"]


@pytest.mark.parametrize("cmd", ALL_COMMANDS)
def test_build_hook_groups_shapes(cmd: HookCommand) -> None:
    groups = groups_for(cmd)
    assert list(groups) == EVENTS
    assert "matcher" not in groups["UserPromptSubmit"]
    assert "matcher" not in groups["ConfigChange"]
    assert groups["PreToolUse"]["matcher"] == "*"
    assert groups["PostToolUse"]["matcher"] == POST
    expected_timeouts = {
        "UserPromptSubmit": 10,
        "PreToolUse": 15,
        "PostToolUse": 10,
        "ConfigChange": 10,
    }
    for event, group in groups.items():
        assert set(group) <= {"matcher", "hooks"}
        [entry] = group["hooks"]
        assert list(entry) == ["type", "command", "args", "timeout"]
        assert entry["type"] == "command"
        assert entry["command"] == cmd.command
        assert entry["args"] == cmd.args_for(SUBCOMMANDS[event])
        assert entry["args"][-1] == SUBCOMMANDS[event]
        assert entry["timeout"] == expected_timeouts[event]
        assert is_own_hook(entry)


@pytest.mark.parametrize("cmd", ALL_COMMANDS)
def test_groups_survive_json_round_trip(cmd: HookCommand) -> None:
    groups = groups_for(cmd)
    assert json.loads(json.dumps(groups)) == groups
    assert json.loads(json.dumps(groups, ensure_ascii=False)) == groups
    assert (
        json.loads(json.dumps(groups, ensure_ascii=False).encode("utf-8").decode("utf-8")) == groups
    )


def test_windows_backslashes_are_escaped_in_json_text() -> None:
    text = json.dumps(groups_for(PY_CMD))
    assert "C:\\\\Users\\\\dev\\\\proj\\\\.venv\\\\Scripts\\\\python.exe" in text


def test_path_with_spaces_and_chinese_is_kept_verbatim_without_quotes() -> None:
    [entry] = groups_for(CJK_CMD)["PreToolUse"]["hooks"]
    assert entry["command"] == "C:\\Users\\张三\\My Tools\\.venv\\Scripts\\python.exe"
    assert '"' not in entry["command"]
    assert all(not a.startswith('"') for a in entry["args"])


def test_custom_timeouts() -> None:
    groups = build_hook_groups(
        PY_CMD, post_matcher=POST, timeouts=HookTimeouts(prompt=6, pre=12, post=7, config=8)
    )
    assert [groups[e]["hooks"][0]["timeout"] for e in EVENTS] == [6, 12, 7, 8]


@pytest.mark.parametrize("bad", [0, -1])
def test_non_positive_timeouts_are_refused(bad: int) -> None:
    with pytest.raises(ValueError, match="timeout"):
        build_hook_groups(PY_CMD, post_matcher=POST, timeouts=HookTimeouts(pre=bad))


@pytest.mark.parametrize("matcher", ["", " ", "\t\n"])
def test_empty_post_matcher_is_refused(matcher: str) -> None:
    with pytest.raises(ValueError, match="post_matcher"):
        build_hook_groups(PY_CMD, post_matcher=matcher)


@pytest.mark.parametrize(
    "command", ["python.exe", ".\\python.exe", "bin/boundkeep-hook", "", "C:python.exe"]
)
def test_relative_command_is_refused(command: str) -> None:
    with pytest.raises(ValueError, match="absolute"):
        build_hook_groups(
            HookCommand(command, ("-I", "-S", "boundkeep/hook_client.py")), post_matcher=POST
        )


def test_command_that_uninstall_could_not_recognize_is_refused() -> None:
    cmd = HookCommand("C:\\Python312\\python.exe", ("-I", "-S", "C:\\tools\\other\\hook_client.py"))
    with pytest.raises(ValueError, match="recognized"):
        build_hook_groups(cmd, post_matcher=POST)
    with pytest.raises(ValueError, match="recognized"):
        build_hook_groups(HookCommand("C:\\bin\\something.exe"), post_matcher=POST)


def test_unc_and_posix_absolute_paths_are_accepted() -> None:
    build_hook_groups(HookCommand("\\\\server\\share\\boundkeep-hook.exe"), post_matcher=POST)
    build_hook_groups(HookCommand("/usr/local/bin/boundkeep-hook"), post_matcher=POST)


def test_each_call_returns_fresh_objects() -> None:
    first = groups_for()
    first["PreToolUse"]["hooks"][0]["args"].append("tampered")
    assert groups_for()["PreToolUse"]["hooks"][0]["args"][-1] == "pre"


# ---- merge_hooks ----------------------------------------------------------------------------

USER_PRE = {"matcher": "Bash", "hooks": [foreign("echo bash-guard")]}
USER_PRE2 = {"matcher": "Write|Edit", "hooks": [foreign("echo write-guard", timeout=3)]}
USER_POST = {"matcher": "Edit", "hooks": [foreign("npm run lint")]}
UNRELATED: dict[str, Any] = {
    "model": "opus",
    "permissions": {"allow": ["Read"], "deny": ["Bash(curl:*)"]},
    "env": {"A": "1"},
    "statusLine": {"type": "command", "command": "echo hi"},
}
USER_HOOKS: dict[str, Any] = {
    "permissions": {"allow": ["Read"]},
    "hooks": {
        "PreToolUse": [USER_PRE, USER_PRE2],
        "PostToolUse": [USER_POST],
        "Stop": [{"hooks": [foreign("echo done")]}],
    },
    "model": "x",
}
# Documents without any entry of ours; merge then remove must give them back exactly.
CLEAN_DOCS: dict[str, dict[str, Any]] = {
    "empty": {},
    "unrelated": UNRELATED,
    "user_hooks": USER_HOOKS,
    "only_other_events": {"hooks": {"Stop": [{"hooks": [foreign("x")]}], "Notification": []}},
    "unicode": {"说明": "中文 \u2713", "hooks": {"PreToolUse": [USER_PRE]}},
}


def own_group(cmd: HookCommand, event: str, matcher: str | None) -> dict[str, Any]:
    group: dict[str, Any] = {} if matcher is None else {"matcher": matcher}
    group["hooks"] = [groups_for(cmd)[event]["hooks"][0]]
    return group


def test_merge_into_empty_settings() -> None:
    merged, report = merge_hooks({}, groups_for())
    assert list(merged) == ["hooks"]
    assert list(merged["hooks"]) == EVENTS
    assert merged["hooks"] == {event: [group] for event, group in groups_for().items()}
    assert report == MergeReport(added=tuple(EVENTS), replaced=(), unchanged=False)


def test_merge_keeps_unrelated_keys_and_order_and_appends_hooks_last() -> None:
    merged, report = merge_hooks(UNRELATED, groups_for())
    assert list(merged) == [*UNRELATED, "hooks"]
    assert {k: v for k, v in merged.items() if k != "hooks"} == UNRELATED
    assert report.added == tuple(EVENTS)


def test_merge_appends_after_users_own_hooks_without_touching_them() -> None:
    merged, report = merge_hooks(USER_HOOKS, groups_for())
    hooks = merged["hooks"]
    assert list(merged) == list(USER_HOOKS)  # "hooks" keeps its position
    assert hooks["PreToolUse"][:2] == [USER_PRE, USER_PRE2]
    assert hooks["PreToolUse"][2] == groups_for()["PreToolUse"]
    assert len(hooks["PreToolUse"]) == 3
    assert hooks["PostToolUse"][0] == USER_POST
    assert hooks["PostToolUse"][1] == groups_for()["PostToolUse"]
    assert hooks["Stop"] == USER_HOOKS["hooks"]["Stop"]
    assert list(hooks) == ["PreToolUse", "PostToolUse", "Stop", "UserPromptSubmit", "ConfigChange"]
    assert set(report.added) == set(EVENTS)
    assert report.replaced == ()


def test_merge_into_event_with_empty_list_appends() -> None:
    merged, report = merge_hooks({"hooks": {"PreToolUse": []}}, groups_for())
    assert merged["hooks"]["PreToolUse"] == [groups_for()["PreToolUse"]]
    assert "PreToolUse" in report.added


def test_old_entries_at_a_different_python_path_are_replaced_in_place() -> None:
    old = {
        event: [own_group(OLD_CMD, event, groups_for()[event].get("matcher"))] for event in EVENTS
    }
    settings = {
        "hooks": {
            "PreToolUse": [USER_PRE, old["PreToolUse"][0], USER_PRE2],
            "PostToolUse": [old["PostToolUse"][0], USER_POST],
            "UserPromptSubmit": old["UserPromptSubmit"],
            "ConfigChange": old["ConfigChange"],
        }
    }
    merged, report = merge_hooks(settings, groups_for(PY_CMD))
    hooks = merged["hooks"]
    assert hooks["PreToolUse"] == [USER_PRE, groups_for()["PreToolUse"], USER_PRE2]
    assert hooks["PostToolUse"] == [groups_for()["PostToolUse"], USER_POST]
    assert hooks["UserPromptSubmit"] == [groups_for()["UserPromptSubmit"]]
    assert report.added == ()
    assert set(report.replaced) == set(EVENTS)
    assert not report.unchanged
    assert "D:\\\\old" in json.dumps(settings)  # control: the JSON text does contain it before
    assert "D:\\\\old" not in json.dumps(merged)


def test_launcher_style_entry_is_replaced_by_python_style_entry() -> None:
    settings, _ = merge_hooks({}, groups_for(EXE_CMD))
    merged, report = merge_hooks(settings, groups_for(PY_CMD))
    assert merged == merge_hooks({}, groups_for(PY_CMD))[0]
    assert set(report.replaced) == set(EVENTS)


def test_duplicates_of_ours_collapse_into_the_first_position() -> None:
    ours = own_group(OLD_CMD, "PreToolUse", "*")
    settings = {
        "hooks": {
            "PreToolUse": [
                USER_PRE,
                ours,
                USER_PRE2,
                copy.deepcopy(ours),
                {"matcher": "Read", "hooks": [copy.deepcopy(ours["hooks"][0]), foreign("keep")]},
            ]
        }
    }
    merged, report = merge_hooks(settings, {"PreToolUse": groups_for()["PreToolUse"]})
    assert merged["hooks"]["PreToolUse"] == [
        USER_PRE,
        groups_for()["PreToolUse"],
        USER_PRE2,
        {"matcher": "Read", "hooks": [foreign("keep")]},
    ]
    assert report.replaced == ("PreToolUse",)
    assert count_own(merged) == 1


def test_duplicates_inside_one_group_collapse() -> None:
    entry = own_group(OLD_CMD, "PreToolUse", "*")["hooks"][0]
    settings = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [entry, copy.deepcopy(entry)]}]}}
    merged, _ = merge_hooks(settings, {"PreToolUse": groups_for()["PreToolUse"]})
    assert merged["hooks"]["PreToolUse"] == [groups_for()["PreToolUse"]]


def test_group_mixing_foreign_and_our_entries_keeps_the_foreign_ones() -> None:
    entry = own_group(OLD_CMD, "PreToolUse", "*")["hooks"][0]
    mixed = {"matcher": "*", "hooks": [foreign("first"), entry, foreign("last")], "note": "x"}
    merged, report = merge_hooks(
        {"hooks": {"PreToolUse": [mixed]}}, {"PreToolUse": groups_for()["PreToolUse"]}
    )
    [group] = merged["hooks"]["PreToolUse"]
    assert group["matcher"] == "*"
    assert group["note"] == "x"
    assert group["hooks"] == [
        foreign("first"),
        groups_for()["PreToolUse"]["hooks"][0],
        foreign("last"),
    ]
    assert report.replaced == ("PreToolUse",)


def test_our_entry_under_a_narrower_foreign_matcher_is_moved_into_its_own_group() -> None:
    # Left in a "Bash" group our PreToolUse hook would only see Bash calls: a silent gap.
    entry = own_group(OLD_CMD, "PreToolUse", "*")["hooks"][0]
    shared = {"matcher": "Bash", "hooks": [foreign("first"), entry, foreign("last")]}
    settings = {"hooks": {"PreToolUse": [shared, USER_PRE2]}}
    merged, report = merge_hooks(settings, {"PreToolUse": groups_for()["PreToolUse"]})
    assert merged["hooks"]["PreToolUse"] == [
        {"matcher": "Bash", "hooks": [foreign("first"), foreign("last")]},
        groups_for()["PreToolUse"],
        USER_PRE2,
    ]
    assert report.replaced == ("PreToolUse",)
    again, report2 = merge_hooks(merged, {"PreToolUse": groups_for()["PreToolUse"]})
    assert report2.unchanged
    assert again == merged


def test_group_that_is_only_ours_takes_the_new_matcher() -> None:
    old = own_group(PY_CMD, "PostToolUse", "WebFetch")
    old["x-keep"] = 1
    merged, report = merge_hooks(
        {"hooks": {"PostToolUse": [old]}},
        {"PostToolUse": groups_for(post="mcp__.*")["PostToolUse"]},
    )
    [group] = merged["hooks"]["PostToolUse"]
    assert group["matcher"] == "mcp__.*"
    assert group["x-keep"] == 1
    assert report.replaced == ("PostToolUse",)


def test_stale_matcher_on_unmatchered_event_is_dropped() -> None:
    old = own_group(PY_CMD, "ConfigChange", "*")
    merged, _ = merge_hooks(
        {"hooks": {"ConfigChange": [old]}}, {"ConfigChange": groups_for()["ConfigChange"]}
    )
    assert merged["hooks"]["ConfigChange"] == [groups_for()["ConfigChange"]]


@pytest.mark.parametrize("bad", [[], "hooks", None, 5, [{"PreToolUse": []}]])
def test_wrong_typed_hooks_is_refused(bad: Any) -> None:
    settings = {"model": "x", "hooks": bad}
    snapshot = copy.deepcopy(settings)
    with pytest.raises(SettingsError, match='"hooks" must be an object'):
        merge_hooks(settings, groups_for())
    assert settings == snapshot


@pytest.mark.parametrize("bad", [{}, "x", None, 3, {"hooks": []}])
def test_wrong_typed_event_value_is_refused(bad: Any) -> None:
    settings = {"hooks": {"Stop": [], "PostToolUse": bad}}
    with pytest.raises(SettingsError, match=r"hooks\.PostToolUse must be a list"):
        merge_hooks(settings, groups_for())


def test_junk_inside_event_lists_is_left_alone() -> None:
    junk = ["text", 7, None, {"matcher": "x"}, {"hooks": "nope"}, {"hooks": [1, "a", None]}]
    merged, report = merge_hooks({"hooks": {"PreToolUse": copy.deepcopy(junk)}}, groups_for())
    assert merged["hooks"]["PreToolUse"][: len(junk)] == junk
    assert merged["hooks"]["PreToolUse"][-1] == groups_for()["PreToolUse"]
    assert "PreToolUse" in report.added


def test_merging_no_groups_changes_nothing_and_creates_no_hooks_key() -> None:
    merged, report = merge_hooks(UNRELATED, {})
    assert merged == UNRELATED
    assert "hooks" not in merged
    assert report == MergeReport((), (), True)


@pytest.mark.parametrize("name", list(CLEAN_DOCS))
@pytest.mark.parametrize("cmd", [PY_CMD, EXE_CMD])
def test_merge_is_idempotent(name: str, cmd: HookCommand) -> None:
    once, first = merge_hooks(CLEAN_DOCS[name], groups_for(cmd))
    twice, second = merge_hooks(once, groups_for(cmd))
    assert same(once, twice)
    assert not first.unchanged
    assert second == MergeReport((), (), True)


def test_merge_is_idempotent_for_stale_and_duplicated_documents() -> None:
    old = own_group(OLD_CMD, "PreToolUse", "*")
    settings = {
        "hooks": {
            "PreToolUse": [old, USER_PRE, copy.deepcopy(old)],
            "PostToolUse": [
                {
                    "matcher": "Edit",
                    "hooks": [
                        foreign("a"),
                        copy.deepcopy(own_group(OLD_CMD, "PostToolUse", None)["hooks"][0]),
                    ],
                }
            ],
        }
    }
    once, _ = merge_hooks(settings, groups_for())
    twice, report = merge_hooks(once, groups_for())
    assert same(once, twice)
    assert report.unchanged


@pytest.mark.parametrize("name", list(CLEAN_DOCS))
def test_merge_never_mutates_or_aliases_its_input(name: str) -> None:
    original = CLEAN_DOCS[name]
    snapshot = copy.deepcopy(original)
    groups = groups_for()
    groups_snapshot = copy.deepcopy(groups)
    merged, _ = merge_hooks(original, groups)
    assert same(original, snapshot)
    assert groups == groups_snapshot
    # Mutating the result must not reach the input or the groups.
    merged["hooks"]["PreToolUse"][-1]["hooks"][0]["args"].append("tampered")
    merged["hooks"].setdefault("Stop", []).append("junk")
    assert same(original, snapshot)
    assert groups == groups_snapshot


def test_merge_preserves_unknown_keys_everywhere() -> None:
    future: dict[str, Any] = {
        "futureKey": {"a": [1, 2]},
        "hooks": {
            "FutureEvent": [{"hooks": [foreign("x")]}],
            "PreToolUse": [
                {"matcher": "Bash", "futureField": True, "hooks": [foreign("y", future=1)]}
            ],
        },
    }
    merged, _ = merge_hooks(future, groups_for())
    assert merged["futureKey"] == {"a": [1, 2]}
    assert merged["hooks"]["FutureEvent"] == future["hooks"]["FutureEvent"]
    assert merged["hooks"]["PreToolUse"][0] == future["hooks"]["PreToolUse"][0]


def test_foreign_hooks_that_merely_look_similar_are_not_ours() -> None:
    lookalikes = [
        foreign("C:\\tools\\boundkeep-hook-wrapper.exe", args=["pre"]),
        foreign("python", args=["-m", "other", "pre"]),
        {"type": "command", "command": "echo boundkeep pre"},
        {"type": "prompt", "prompt": "boundkeep"},
        foreign("C:\\x\\python.exe", args=["C:\\x\\hook_client.py", "pre"]),  # not under boundkeep
    ]
    settings = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": lookalikes}]}}
    merged, report = merge_hooks(settings, groups_for())
    assert merged["hooks"]["PreToolUse"][0] == settings["hooks"]["PreToolUse"][0]
    assert report.added == tuple(EVENTS)


# ---- remove_hooks ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", list(CLEAN_DOCS))
@pytest.mark.parametrize("cmd", [PY_CMD, EXE_CMD, CJK_CMD])
def test_merge_then_remove_restores_the_original(name: str, cmd: HookCommand) -> None:
    original = CLEAN_DOCS[name]
    merged, _ = merge_hooks(original, groups_for(cmd))
    restored, removed = remove_hooks(merged)
    assert removed == len(EVENTS)
    assert same(restored, original)  # values AND key order


def test_remove_counts_each_entry_and_drops_empty_containers() -> None:
    merged, _ = merge_hooks({"model": "x"}, groups_for())
    restored, removed = remove_hooks(merged)
    assert removed == 4
    assert restored == {"model": "x"}
    assert "hooks" not in restored


def test_remove_keeps_foreign_entries_in_a_shared_group_and_drops_empty_groups() -> None:
    entry = own_group(PY_CMD, "PreToolUse", "*")["hooks"][0]
    settings = {
        "hooks": {
            "PreToolUse": [
                {"matcher": "*", "hooks": [foreign("a"), entry, foreign("b")], "x": 1},
                own_group(EXE_CMD, "PreToolUse", "*"),
            ],
            "ConfigChange": [own_group(PY_CMD, "ConfigChange", None)],
            "Stop": [{"hooks": [foreign("s")]}],
        },
        "other": 1,
    }
    restored, removed = remove_hooks(settings)
    assert removed == 3
    assert restored == {
        "hooks": {
            "PreToolUse": [{"matcher": "*", "hooks": [foreign("a"), foreign("b")], "x": 1}],
            "Stop": [{"hooks": [foreign("s")]}],
        },
        "other": 1,
    }


def test_remove_is_idempotent_and_does_not_mutate() -> None:
    merged, _ = merge_hooks(USER_HOOKS, groups_for())
    snapshot = copy.deepcopy(merged)
    once, n1 = remove_hooks(merged)
    twice, n2 = remove_hooks(once)
    assert same(merged, snapshot)
    assert (n1, n2) == (4, 0)
    assert same(once, twice)


def test_remove_leaves_documents_without_our_entries_untouched() -> None:
    for original in CLEAN_DOCS.values():
        restored, removed = remove_hooks(original)
        assert removed == 0
        assert same(restored, original)


def test_remove_keeps_containers_that_were_empty_before() -> None:
    settings: dict[str, Any] = {"hooks": {"PreToolUse": [], "Stop": [{"hooks": []}]}}
    restored, removed = remove_hooks(settings)
    assert removed == 0
    assert restored == settings


@pytest.mark.parametrize("bad", [None, [], "x", 3, {"PreToolUse": "nope", "Stop": {"hooks": 1}}])
def test_remove_tolerates_malformed_hooks(bad: Any) -> None:
    settings = {"hooks": bad, "k": 1}
    restored, removed = remove_hooks(settings)
    assert removed == 0
    assert restored == settings


def test_remove_handles_stale_and_duplicate_entries_from_any_path() -> None:
    settings = {
        "hooks": {
            "PreToolUse": [
                own_group(OLD_CMD, "PreToolUse", "*"),
                USER_PRE,
                own_group(PY_CMD, "PreToolUse", "*"),
                own_group(POSIX_CMD, "PreToolUse", "*"),
            ]
        }
    }
    restored, removed = remove_hooks(settings)
    assert removed == 3
    assert restored == {"hooks": {"PreToolUse": [USER_PRE]}}


# ---- resolve_settings_path ------------------------------------------------------------------


WIN_ENV = {"USERPROFILE": "C:\\Users\\dev"}
POSIX_ENV = {"HOME": "/home/dev"}


def test_project_scope_windows_and_posix() -> None:
    assert (
        resolve_settings_path("project", cwd="C:\\Users\\dev\\proj", env={})
        == "C:\\Users\\dev\\proj\\.claude\\settings.json"
    )
    assert (
        resolve_settings_path("project", cwd="/home/dev/proj", env={})
        == "/home/dev/proj/.claude/settings.json"
    )
    assert (
        resolve_settings_path("project", cwd="D:\\项目 一\\应用", env={})
        == "D:\\项目 一\\应用\\.claude\\settings.json"
    )


def test_project_scope_ignores_claude_config_dir() -> None:
    env = {"CLAUDE_CONFIG_DIR": "D:\\cfg"}
    assert resolve_settings_path("project", cwd="/p", env=env) == "/p/.claude/settings.json"


@pytest.mark.parametrize("cwd", ["", "proj", ".", "relative\\dir", "C:proj", "../up"])
def test_project_scope_refuses_relative_cwd(cwd: str) -> None:
    with pytest.raises(SettingsError, match="absolute"):
        resolve_settings_path("project", cwd=cwd, env={})


def test_user_scope_with_claude_config_dir() -> None:
    assert (
        resolve_settings_path(
            "user", cwd="/x", env={**WIN_ENV, "CLAUDE_CONFIG_DIR": "D:\\cfg\\claude"}
        )
        == "D:\\cfg\\claude\\settings.json"
    )
    assert (
        resolve_settings_path(
            "user", cwd="/x", env={**POSIX_ENV, "CLAUDE_CONFIG_DIR": "/etc/claude"}
        )
        == "/etc/claude/settings.json"
    )


@pytest.mark.parametrize("env_extra", [{}, {"CLAUDE_CONFIG_DIR": ""}])
def test_user_scope_default_windows_style(env_extra: dict[str, str]) -> None:
    env = {**WIN_ENV, **env_extra}
    assert (
        resolve_settings_path("user", cwd="/x", env=env) == "C:\\Users\\dev\\.claude\\settings.json"
    )


@pytest.mark.parametrize("env_extra", [{}, {"CLAUDE_CONFIG_DIR": ""}])
def test_user_scope_default_posix_style(env_extra: dict[str, str]) -> None:
    env = {**POSIX_ENV, **env_extra}
    assert resolve_settings_path("user", cwd="/x", env=env) == "/home/dev/.claude/settings.json"


@pytest.mark.windows
def test_user_scope_prefers_userprofile_over_home_on_windows() -> None:
    # Git Bash may set HOME somewhere else; Claude Code on Windows uses %USERPROFILE%.
    env = {"USERPROFILE": "C:\\Users\\dev", "HOME": "C:\\msys\\home\\dev"}
    assert (
        resolve_settings_path("user", cwd="C:\\x", env=env)
        == "C:\\Users\\dev\\.claude\\settings.json"
    )


@pytest.mark.posix
def test_user_scope_prefers_home_on_posix() -> None:
    env = {"USERPROFILE": "C:\\Users\\dev", "HOME": "/home/dev"}
    assert resolve_settings_path("user", cwd="/x", env=env) == "/home/dev/.claude/settings.json"


def test_user_scope_falls_back_to_expanduser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    path = resolve_settings_path("user", cwd=str(tmp_path), env={})
    assert os.path.normcase(path) == os.path.normcase(
        os.path.join(str(tmp_path), ".claude", "settings.json")
    )


def test_user_scope_refuses_relative_config_dir() -> None:
    with pytest.raises(SettingsError, match="CLAUDE_CONFIG_DIR"):
        resolve_settings_path("user", cwd="/x", env={"CLAUDE_CONFIG_DIR": "cfg"})


def test_unknown_scope_is_refused() -> None:
    with pytest.raises(ValueError, match="scope"):
        resolve_settings_path("local", cwd="/x", env={})  # type: ignore[arg-type]


def test_resolving_never_touches_the_filesystem(tmp_path: Path) -> None:
    target = tmp_path / "nonexistent-project"
    resolve_settings_path("project", cwd=str(target), env={})
    assert not target.exists()


# ---- manifest -------------------------------------------------------------------------------


def record(path: str = "C:\\proj\\.claude\\settings.json", **overrides: Any) -> InstallRecord:
    fields: dict[str, Any] = {
        "settings_path": path,
        "scope": "project",
        "created_file": False,
        "hook_command": PY_CMD.command,
        "hook_args": PY_CMD.base_args,
        "post_matcher": POST,
        "installed_at": "2026-10-07T08:00:00Z",
    }
    fields.update(overrides)
    return InstallRecord(**fields)


def test_manifest_missing_file_is_empty(tmp_path: Path) -> None:
    assert load_manifest(str(tmp_path / "nope" / "installs.json")) == []


def test_manifest_round_trip_and_format(tmp_path: Path) -> None:
    path = tmp_path / "home" / "installs.json"
    records = [
        record(),
        record("D:\\项目\\应用\\.claude\\settings.json", created_file=True, hook_args=()),
        record("/home/dev/.claude/settings.json", scope="user"),
    ]
    save_manifest(str(path), records)
    assert load_manifest(str(path)) == records
    raw = path.read_bytes()
    assert raw.endswith(b"\n")
    assert b"\r" not in raw
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert raw.decode("utf-8").startswith('{\n  "version": 1,\n  "installs": [\n    {\n')
    assert "项目".encode() in raw  # not \u-escaped
    assert [p.name for p in path.parent.iterdir()] == ["installs.json"]


def test_manifest_empty_list_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "installs.json"
    save_manifest(str(path), [])
    assert load_manifest(str(path)) == []


def test_manifest_save_overwrites_atomically(tmp_path: Path) -> None:
    path = tmp_path / "installs.json"
    save_manifest(str(path), [record()])
    save_manifest(str(path), [record("C:\\other\\.claude\\settings.json")])
    assert [r.settings_path for r in load_manifest(str(path))] == [
        "C:\\other\\.claude\\settings.json"
    ]


def test_manifest_tolerates_a_bom(tmp_path: Path) -> None:
    path = tmp_path / "installs.json"
    save_manifest(str(path), [record()])
    path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
    assert load_manifest(str(path)) == [record()]


def good_manifest() -> dict[str, Any]:
    return {
        "version": 1,
        "installs": [
            {
                "settings_path": "C:\\p\\.claude\\settings.json",
                "scope": "project",
                "created_file": True,
                "hook_command": "C:\\py.exe",
                "hook_args": ["-I", "pre"],
                "post_matcher": "x",
                "installed_at": "2026-10-07T00:00:00Z",
            }
        ],
    }


def corrupt(base: dict[str, Any], **changes: Any) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in changes.items():
        if key.startswith("rec_"):
            if value is ...:
                del result["installs"][0][key[4:]]
            else:
                result["installs"][0][key[4:]] = value
        else:
            result[key] = value
    return result


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b"[]",
        b'{"version": 1, "installs": {}}',
        b'{"version": 2, "installs": []}',
        b'{"installs": []}',
        b'{"version": 1}',
        b'{"version": 1, "version": 1, "installs": []}',
        b'{"version": 1, "installs": [1]}',
        b'{"version": 1, "installs": [{}]}',
    ],
)
def test_corrupt_manifest_is_refused(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "installs.json"
    path.write_bytes(raw)
    with pytest.raises(SettingsError):
        load_manifest(str(path))


@pytest.mark.parametrize(
    "changes",
    [
        {"rec_settings_path": ...},
        {"rec_settings_path": ""},
        {"rec_settings_path": 5},
        {"rec_scope": None},
        {"rec_created_file": "yes"},
        {"rec_created_file": 1},
        {"rec_created_file": ...},
        {"rec_hook_args": "pre"},
        {"rec_hook_args": ["a", 1]},
        {"rec_hook_command": None},
        {"rec_post_matcher": ["x"]},
        {"rec_installed_at": 20261007},
    ],
)
def test_manifest_records_are_validated(tmp_path: Path, changes: dict[str, Any]) -> None:
    path = tmp_path / "installs.json"
    path.write_text(json.dumps(corrupt(good_manifest(), **changes)), encoding="utf-8")
    with pytest.raises(SettingsError, match=r"installs\.json"):
        load_manifest(str(path))


def test_manifest_good_fixture_loads(tmp_path: Path) -> None:
    path = tmp_path / "installs.json"
    path.write_text(json.dumps(good_manifest()), encoding="utf-8")
    [rec] = load_manifest(str(path))
    assert rec.created_file is True
    assert rec.hook_args == ("-I", "pre")


def test_upsert_appends_new_and_replaces_in_place() -> None:
    a, b = record("C:\\a\\.claude\\settings.json"), record("C:\\b\\.claude\\settings.json")
    records = upsert_record(upsert_record([], a), b)
    assert records == [a, b]
    newer = record("C:\\a\\.claude\\settings.json", installed_at="2026-10-08T00:00:00Z")
    assert upsert_record(records, newer) == [newer, b]
    assert records == [a, b]  # input untouched


def test_upsert_matches_windows_paths_case_insensitively() -> None:
    first = record("C:\\Proj\\.claude\\settings.json")
    again = record("c:/proj/.claude/settings.json", installed_at="later")
    assert upsert_record([first], again) == [again]


def test_upsert_keeps_posix_paths_case_sensitive() -> None:
    a, b = record("/home/Dev/.claude/settings.json"), record("/home/dev/.claude/settings.json")
    assert upsert_record([a], b) == [a, b]


def test_upsert_does_not_forget_that_the_first_run_created_the_file() -> None:
    first = record(created_file=True)
    second = record(created_file=False, installed_at="later")
    [merged] = upsert_record([first], second)
    assert merged.created_file is True
    assert merged.installed_at == "later"


def test_upsert_collapses_duplicate_records_for_one_path() -> None:
    a1, a2 = record("C:\\a\\s.json", installed_at="1"), record("c:\\A\\s.json", installed_at="2")
    new = record("C:\\a\\s.json", installed_at="3")
    assert upsert_record([a1, record("D:\\x.json"), a2], new) == [new, record("D:\\x.json")]


def test_drop_record() -> None:
    a, b = record("C:\\a\\s.json"), record("C:\\b\\s.json")
    assert drop_record([a, b], "c:/A/s.json") == [b]
    assert drop_record([a, b], "C:\\zzz\\s.json") == [a, b]
    assert drop_record([], "x") == []


# ---- run_self_check -------------------------------------------------------------------------

GOOD_PRE = (
    b'{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", '
    b'"permissionDecisionReason": "boundkeep daemon is not running"}}'
)
SENTINEL = "sentinel-secret-9f8e7d6c5b4a"
SUB_TO_EVENT = {v: k for k, v in SUBCOMMANDS.items()}


def make_hook(
    tmp_path: Path,
    name: str,
    *,
    stdout: bytes | None = None,
    stderr: bytes = b"",
    code: int = 0,
    only: str = "",
    hang: bool = False,
    check_stdin: bool = False,
    fail_on_python_env: bool = False,
    leak_env: bool = False,
    break_check: bool = False,
) -> HookCommand:
    """A fake hook client; ``only`` limits the misbehaviour to one subcommand, others are good."""
    script = tmp_path / f"{name}.py"
    body = f"""
        import json, os, sys, time
        sub = sys.argv[-1]
        data = sys.stdin.buffer.read()
        GOOD_PRE = {GOOD_PRE!r}
        STDOUT = {stdout!r}
        STDERR = {stderr!r}
        EVENTS = {SUB_TO_EVENT!r}
        if {break_check!r}:
            EVENTS = {{k: "NotAnEvent" for k in EVENTS}}
        if {check_stdin!r}:
            try:
                event = json.loads(data.decode("utf-8"))
                assert event["hook_event_name"] == EVENTS[sub], "wrong event"
                if sub in ("pre", "prompt", "post"):
                    assert any(ord(c) > 127 for c in json.dumps(event, ensure_ascii=False)), "ascii"
                if sub == "pre":
                    assert "\\u4f60\\u597d \\u2713" in event["tool_input"]["command"], "sample"
            except Exception as exc:
                sys.stderr.write("bad stdin: " + repr(exc))
                sys.exit(1)
        if {only!r} and sub != {only!r}:
            if sub == "pre":
                sys.stdout.buffer.write(GOOD_PRE)
            sys.exit(0)
        if {hang!r}:
            time.sleep(60)
        if {fail_on_python_env!r} and any(k.upper().startswith("PYTHON") for k in os.environ):
            sys.stderr.write("a PYTHON* variable is set")
            sys.exit(1)
        if {leak_env!r}:
            STDERR = os.environ.get("BK_SENTINEL", "").encode() + b" is the secret"
            STDOUT = (STDOUT or b"") + os.environ.get("BK_SENTINEL", "").encode()
        if STDOUT is None:
            STDOUT = GOOD_PRE if sub == "pre" else b""
        sys.stdout.buffer.write(STDOUT)
        sys.stderr.buffer.write(STDERR)
        sys.exit({code!r})
    """
    script.write_text(textwrap.dedent(body), encoding="utf-8")
    return HookCommand(sys.executable, ("-I", "-S", str(script)))


def base_env(**extra: str) -> dict[str, str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.upper().startswith(("PYTHON", "CLAUDE", "BOUNDKEEP", "ANTHROPIC"))
    }
    env.update(extra)
    return env


def check(cmd: HookCommand, **kwargs: Any) -> list[SelfCheckResult]:
    kwargs.setdefault("env", base_env())
    return run_self_check(cmd, **kwargs)


def only_results(results: list[SelfCheckResult], sub: str) -> list[SelfCheckResult]:
    return [r for r in results if r.subcommand == sub]


def test_self_check_covers_every_subcommand_and_both_env_variants(tmp_path: Path) -> None:
    results = check(make_hook(tmp_path, "good", check_stdin=True))
    assert [(r.subcommand, r.env_variant) for r in results] == [
        (sub, variant) for sub in SUBCOMMANDS.values() for variant in ("inherited", "no-python-env")
    ]
    assert all(r.ok for r in results), [r.detail for r in results if not r.ok]
    assert all(r.exit_code == 0 and r.elapsed_s >= 0 for r in results)
    pre = only_results(results, "pre")[0]
    assert "ask" in pre.detail


def test_self_check_feeds_utf8_events_of_the_right_type(tmp_path: Path) -> None:
    # check_stdin makes the fake hook exit 1 unless stdin is strict UTF-8 JSON of the right event
    # type, with the Chinese text and the check mark U+2713 in the PreToolUse command.
    results = check(make_hook(tmp_path, "stdin", check_stdin=True))
    assert all(r.ok for r in results), [r.detail for r in results if not r.ok]


def test_the_stdin_check_of_the_fake_hook_really_can_fail(tmp_path: Path) -> None:
    # Control for the test above: a fake hook that expects different events must be flagged,
    # otherwise "all ok" proves nothing.
    results = check(make_hook(tmp_path, "stdin-bad", check_stdin=True, break_check=True))
    assert not any(r.ok for r in results)
    assert all("bad stdin" in r.detail for r in results)


def test_exit_code_1_is_not_ok(tmp_path: Path) -> None:
    results = check(make_hook(tmp_path, "crash", code=1, stderr=b"Traceback ... boom"))
    assert not any(r.ok for r in results)
    assert all(r.exit_code == 1 for r in results)
    assert "exit code 1" in results[0].detail
    assert "silently open" in results[0].detail
    assert "boom" in results[0].detail


@pytest.mark.parametrize("code", [3, 127, 255])
def test_other_exit_codes_are_not_ok(tmp_path: Path, code: int) -> None:
    results = check(make_hook(tmp_path, f"code{code}", code=code))
    assert not any(r.ok for r in results)


def test_non_ascii_stdout_is_not_ok(tmp_path: Path) -> None:
    body = (
        '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", '
        '"permissionDecisionReason": "你好"}}'
    )
    results = check(make_hook(tmp_path, "nonascii", stdout=body.encode("utf-8"), only="pre"))
    [pre] = only_results(results, "pre")[:1]
    assert not pre.ok
    assert "non-ASCII" in pre.detail
    assert all(r.ok for r in results if r.subcommand != "pre")


def test_invalid_json_stdout_is_not_ok(tmp_path: Path) -> None:
    results = check(make_hook(tmp_path, "badjson", stdout=b"not json at all"))
    assert not any(r.ok for r in results)
    assert "not valid JSON" in results[0].detail


@pytest.mark.parametrize(
    "stdout",
    [
        b"[1, 2]",
        b'"ask"',
        b"{}",
        b'{"decision": "ask"}',
        b'{"hookSpecificOutput": {"permissionDecision": "ask"}}',
        b'{"hookSpecificOutput": {"hookEventName": "PostToolUse", "permissionDecision": "ask"}}',
        b'{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "maybe"}}',
        b'{"hookSpecificOutput": {"hookEventName": "PreToolUse"}}',
        b'{"hookSpecificOutput": "ask"}',
    ],
)
def test_pre_output_must_be_a_pretooluse_decision(tmp_path: Path, stdout: bytes) -> None:
    results = check(make_hook(tmp_path, "badpre", stdout=stdout, only="pre"))
    assert not only_results(results, "pre")[0].ok
    assert not only_results(results, "pre")[1].ok


@pytest.mark.parametrize("decision", ["allow", "deny", "ask", "defer"])
def test_every_valid_pre_decision_is_ok(tmp_path: Path, decision: str) -> None:
    out = json.dumps(
        {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision}}
    ).encode()
    results = check(make_hook(tmp_path, f"pre-{decision}", stdout=out, only="pre"))
    assert all(r.ok for r in results), [r.detail for r in results if not r.ok]


def test_json_object_is_fine_for_other_subcommands_but_array_is_not(tmp_path: Path) -> None:
    ok = check(make_hook(tmp_path, "post-json", stdout=b'{"continue": true}', only="post"))
    assert all(r.ok for r in ok)
    bad = check(make_hook(tmp_path, "post-array", stdout=b"[]", only="post"))
    assert [r.ok for r in only_results(bad, "post")] == [False, False]


def test_exit_2_without_stderr_is_not_ok(tmp_path: Path) -> None:
    results = check(make_hook(tmp_path, "exit2-silent", code=2))
    assert not any(r.ok for r in results)
    assert results[0].exit_code == 2
    assert "without a reason" in results[0].detail


def test_exit_2_with_stderr_is_ok(tmp_path: Path) -> None:
    results = check(make_hook(tmp_path, "exit2", code=2, stderr=b"blocked: reason", stdout=b""))
    assert all(r.ok for r in results), [r.detail for r in results if not r.ok]
    assert all(r.exit_code == 2 for r in results)


def test_hang_times_out_without_raising_and_in_bounded_time(tmp_path: Path) -> None:
    cmd = make_hook(tmp_path, "hang", hang=True, only="pre")
    started = time.monotonic()
    results = check(cmd, timeout_s=1.0)
    wall = time.monotonic() - started
    pre = only_results(results, "pre")
    assert len(pre) == 2
    assert not any(r.ok for r in pre)
    assert all(r.exit_code is None and "timed out" in r.detail for r in pre)
    assert all(1.0 <= r.elapsed_s < 10 for r in pre)
    assert all(r.ok for r in results if r.subcommand != "pre")
    assert wall < 30


def test_nonexistent_executable_is_not_ok_and_does_not_raise(tmp_path: Path) -> None:
    cmd = HookCommand(str(tmp_path / "no-such-dir" / "boundkeep-hook.exe"))
    results = check(cmd)
    assert len(results) == 8
    assert not any(r.ok for r in results)
    assert all(r.exit_code is None for r in results)
    assert all("cannot launch" in r.detail for r in results)


def test_file_that_is_not_an_executable_is_not_ok_and_does_not_raise(tmp_path: Path) -> None:
    text = tmp_path / "boundkeep-hook.txt"
    text.write_text("this is not a program\n", encoding="utf-8")
    results = check(HookCommand(str(text)))
    assert not any(r.ok for r in results)
    assert all(r.exit_code is None and "cannot launch" in r.detail for r in results)


def test_directory_as_executable_is_not_ok_and_does_not_raise(tmp_path: Path) -> None:
    results = check(HookCommand(str(tmp_path)))
    assert not any(r.ok for r in results)


def test_embedded_nul_in_command_does_not_raise(tmp_path: Path) -> None:
    results = check(HookCommand("C:\\bad\0path\\x.exe"))
    assert not any(r.ok for r in results)


def test_python_env_variables_are_removed_in_the_second_variant(tmp_path: Path) -> None:
    cmd = make_hook(tmp_path, "pyenv", fail_on_python_env=True)
    env = base_env(PYTHONFOO="1", PythonBar="2")
    results = check(cmd, env=env)
    inherited = [r for r in results if r.env_variant == "inherited"]
    clean = [r for r in results if r.env_variant == "no-python-env"]
    assert len(inherited) == len(clean) == 4
    assert not any(r.ok for r in inherited)  # the hook notices PYTHON* and fails
    assert all(r.ok for r in clean), [r.detail for r in clean if not r.ok]


def test_env_none_uses_the_process_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in list(os.environ):
        if name.upper().startswith("PYTHON"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("PYTHONBK", "1")
    results = run_self_check(make_hook(tmp_path, "envnone", fail_on_python_env=True))
    assert [r.ok for r in results if r.env_variant == "inherited"] == [False] * 4
    assert [r.ok for r in results if r.env_variant == "no-python-env"] == [True] * 4


def test_details_never_contain_environment_values(tmp_path: Path) -> None:
    cmd = make_hook(tmp_path, "leak", leak_env=True, code=1)
    results = check(cmd, env=base_env(BK_SENTINEL=SENTINEL))
    assert not any(r.ok for r in results)
    assert all(SENTINEL not in r.detail for r in results)
    assert all("exit code 1" in r.detail for r in results)
    # Same when the secret arrives on stdout of an otherwise "successful" exit.
    results = check(
        make_hook(tmp_path, "leak2", leak_env=True, code=0, stdout=b"x"),
        env=base_env(BK_SENTINEL=SENTINEL),
    )
    assert all(SENTINEL not in r.detail for r in results)
    assert not any(r.ok for r in results)


def test_details_are_ascii_even_for_non_ascii_stderr(tmp_path: Path) -> None:
    cmd = make_hook(tmp_path, "cjk", code=1, stderr="错误 \u2713".encode())
    results = check(cmd)
    assert all(r.detail.isascii() for r in results)


def test_stderr_excerpt_is_bounded(tmp_path: Path) -> None:
    cmd = make_hook(tmp_path, "loud", code=1, stderr=b"x" * 100_000)
    [first, *_] = check(cmd)
    assert len(first.detail) < 1000


def test_hook_that_ignores_stdin_is_not_a_problem(tmp_path: Path) -> None:
    script = tmp_path / "noread.py"
    script.write_text("import sys\nsys.stdout.write('')\n", encoding="utf-8")
    results = check(HookCommand(sys.executable, ("-I", "-S", str(script))))
    assert all(r.ok for r in results)


def test_self_check_launches_without_a_shell(tmp_path: Path) -> None:
    # A path with spaces, Chinese and shell metacharacters must work exactly as in Claude Code's
    # exec form: no quoting, no shell interpretation.
    odd = tmp_path / "我的 工具 & (copy) ; x"
    odd.mkdir()
    cmd = make_hook(odd, "good")
    assert all(r.ok for r in check(cmd)), [r.detail for r in check(cmd) if not r.ok]


# ---- golden files ---------------------------------------------------------------------------

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "settings"
CASES = sorted(p.name[: -len(".before.json")] for p in GOLDEN.glob("*.before.json"))
GOLDEN_CMD = CJK_CMD
BOM = b"\xef\xbb\xbf"


def golden(name: str) -> bytes:
    # git normalizes files under tests/golden to LF; be robust against a CRLF checkout anyway.
    return (GOLDEN / name).read_bytes().replace(b"\r\n", b"\n")


def variant_bytes(lf: bytes, variant: str) -> bytes:
    data = lf.replace(b"\n", b"\r\n") if "crlf" in variant else lf
    return BOM + data if variant.startswith("bom") else data


def expected_bytes(lf: bytes, variant: str) -> bytes:
    """What we write for a variant: same line endings as the input, never a BOM."""
    return lf.replace(b"\n", b"\r\n") if "crlf" in variant else lf


_GONE = object()


def _strip(value: Any) -> Any:
    if is_own_hook(value):
        return _GONE
    if isinstance(value, list):
        kept = [x for x in (_strip(v) for v in value) if x is not _GONE]
        return kept if kept or not value else _GONE  # emptied by the removal: drop the container
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            new = _strip(item)
            if new is not _GONE:
                out[key] = new
        if isinstance(value.get("hooks"), list) and value["hooks"] and "hooks" not in out:
            return _GONE  # a matcher group that lost all its hooks
        return out if out or not value else _GONE
    return value


def strip_own(document: dict[str, Any]) -> dict[str, Any]:
    """Independent of remove_hooks: the document minus our entries and what they leave empty."""
    result = _strip(document)
    return {} if result is _GONE else dict(result)


def test_there_are_enough_realistic_golden_cases() -> None:
    assert len(CASES) >= 6
    for case in CASES:
        assert (GOLDEN / f"{case}.after.json").is_file(), f"missing {case}.after.json"


@pytest.mark.parametrize("variant", ["lf", "crlf", "bom", "bom-crlf"])
@pytest.mark.parametrize("case", CASES)
def test_golden_merge_and_remove(tmp_path: Path, case: str, variant: str) -> None:
    before_lf, after_lf = golden(f"{case}.before.json"), golden(f"{case}.after.json")
    removed_file = GOLDEN / f"{case}.removed.json"
    removed_lf = golden(removed_file.name) if removed_file.exists() else before_lf

    path = tmp_path / "settings.json"
    path.write_bytes(variant_bytes(before_lf, variant))
    doc = load_settings(str(path))
    assert doc.had_bom == variant.startswith("bom")

    merged, report = merge_hooks(doc.data, groups_for(GOLDEN_CMD))
    after = render_settings(doc, merged)
    assert after == expected_bytes(after_lf, variant)  # BYTES, including style and no BOM
    assert not report.unchanged
    assert count_own(merged) == 4
    assert json.loads(after.decode("utf-8")) == merged

    path.write_bytes(after)
    doc_after = load_settings(str(path))
    again, report2 = merge_hooks(doc_after.data, groups_for(GOLDEN_CMD))
    assert report2.unchanged  # idempotent
    assert render_settings(doc_after, again) == after

    restored, removed = remove_hooks(doc_after.data)
    assert removed == 4
    assert render_settings(doc_after, restored) == expected_bytes(removed_lf, variant)
    assert restored == strip_own(doc.data) or same(restored, strip_own(doc.data))


@pytest.mark.parametrize("case", CASES)
def test_golden_foreign_content_is_untouched(case: str) -> None:
    doc = load_settings(str(GOLDEN / f"{case}.before.json"))
    merged, _ = merge_hooks(doc.data, groups_for(GOLDEN_CMD))
    foreign_before = strip_own(doc.data)
    foreign_after = strip_own(merged)
    assert same(foreign_before, foreign_after)
    for key, value in doc.data.items():
        if key != "hooks":
            assert same(merged[key], value)
            assert list(merged).index(key) == list(doc.data).index(key)


def test_golden_before_files_that_are_canonical_round_trip_exactly() -> None:
    canonical = {"basic_permissions", "empty_object", "env_statusline_four_space", "minified"}
    assert canonical <= set(CASES)
    for case in canonical:
        raw = golden(f"{case}.before.json")
        doc = load_settings(str(GOLDEN / f"{case}.before.json"))
        assert render_settings(doc, doc.data) == raw.replace(b"\n", doc.newline.encode())


def test_golden_stale_case_replaces_in_place_and_drops_duplicates() -> None:
    doc = load_settings(str(GOLDEN / "stale_boundkeep_entries.before.json"))
    merged, report = merge_hooks(doc.data, groups_for(GOLDEN_CMD))
    assert report.added == ("ConfigChange",)
    assert set(report.replaced) == {"UserPromptSubmit", "PreToolUse", "PostToolUse"}
    pre = merged["hooks"]["PreToolUse"]
    assert [g["matcher"] for g in pre] == ["Bash", "*", "Read"]  # ours kept the 2nd position
    text = json.dumps(merged)
    assert "D:\\\\old" not in text
    assert "Scripts\\\\boundkeep-hook.exe" not in text


def test_golden_tab_and_four_space_styles_are_detected() -> None:
    four = load_settings(str(GOLDEN / "env_statusline_four_space.before.json"))
    assert four.indent == 4
    mini = load_settings(str(GOLDEN / "minified.before.json"))
    assert mini.indent is None
    assert mini.compact_separators is True


def test_golden_tab_indent_variant(tmp_path: Path) -> None:
    before = golden("basic_permissions.before.json")
    lines = []
    for line in before.decode("utf-8").split("\n"):
        stripped = line.lstrip(" ")
        lines.append("\t" * ((len(line) - len(stripped)) // 2) + stripped)
    tabbed = "\n".join(lines).encode("utf-8")
    path = tmp_path / "settings.json"
    path.write_bytes(tabbed)
    doc = load_settings(str(path))
    assert doc.indent == "\t"
    merged, _ = merge_hooks(doc.data, groups_for(GOLDEN_CMD))
    after = render_settings(doc, merged)
    expected = golden("basic_permissions.after.json").decode("utf-8")
    expected_lines = []
    for line in expected.split("\n"):
        stripped = line.lstrip(" ")
        expected_lines.append("\t" * ((len(line) - len(stripped)) // 2) + stripped)
    assert after == "\n".join(expected_lines).encode("utf-8")
    restored, _ = remove_hooks(load_settings_from(tmp_path, after).data)
    assert render_settings(doc, restored) == tabbed


def load_settings_from(tmp_path: Path, data: bytes) -> Any:
    path = tmp_path / "again.json"
    path.write_bytes(data)
    return load_settings(str(path))


# ---- regression tests for the adversarial review --------------------------------------------
# Each test below failed against the first implementation (see the finding it names).


# Finding: a .cmd shim started fine under Popen (cmd.exe) although Claude Code fails on it with
# spawn EINVAL and shows only a non-blocking notice: the self check reported a healthy gate.
BATCH_COMMANDS = [
    "C:\\Users\\dev\\.local\\bin\\python.cmd",
    "C:\\Users\\dev\\bin\\PYTHON.CMD",
    "C:\\tools\\boundkeep\\run.bat",
    "C:\\tools\\boundkeep\\run.BAT",
    "C:\\tools\\boundkeep\\python.cmd ",  # Windows ignores trailing spaces and dots
    "C:\\tools\\boundkeep\\python.cmd.",
    "/usr/local/bin/python.cmd",
]


@pytest.mark.parametrize("command", BATCH_COMMANDS)
def test_batch_file_command_is_refused_by_build_hook_groups(command: str) -> None:
    cmd = HookCommand(command, ("-I", "-S", "C:\\tools\\boundkeep\\hook_client.py"))
    with pytest.raises(ValueError, match=r"\.cmd"):
        build_hook_groups(cmd, post_matcher=POST)


@pytest.mark.parametrize("command", BATCH_COMMANDS)
def test_self_check_never_accepts_a_batch_file_command(command: str) -> None:
    results = run_self_check(
        HookCommand(command, ("-I", "-S", "C:\\tools\\boundkeep\\hook_client.py")), env=base_env()
    )
    assert len(results) == 8
    assert not any(r.ok for r in results)
    assert all(r.exit_code is None for r in results)
    assert all("EINVAL" in r.detail and "cannot launch" in r.detail for r in results)


@pytest.mark.windows
def test_a_real_cmd_shim_is_not_launched_and_not_ok(tmp_path: Path) -> None:
    # The shim would work if Popen started it (it forwards to the real python); the point is that
    # we refuse it BEFORE launching, because Claude Code cannot launch it.
    hook = make_hook(tmp_path, "boundkeep-real")
    package = tmp_path / "boundkeep"
    package.mkdir()
    script = package / "hook_client.py"
    script.write_text(Path(hook.base_args[2]).read_text(encoding="utf-8"), encoding="utf-8")
    marker = tmp_path / "shim-ran.txt"
    shim = tmp_path / "python.cmd"
    shim.write_bytes(f'@echo off\r\necho x> "{marker}"\r\n"{sys.executable}" %*\r\n'.encode())
    cmd = HookCommand(str(shim), ("-I", "-S", str(script)))
    with pytest.raises(ValueError, match=r"\.cmd"):
        build_hook_groups(cmd, post_matcher=POST)
    results = run_self_check(cmd, env=base_env())
    assert not any(r.ok for r in results)
    assert not marker.exists()
    # Control: the same hook through the real executable is fine.
    assert all(
        r.ok for r in run_self_check(HookCommand(sys.executable, cmd.base_args), env=base_env())
    )


# Finding: timeouts were only checked to be positive, but the hook client's ConfigChange check
# counts an entry with a shorter timeout as "altered" and then blocks every settings change.
def test_minimum_timeouts_match_the_hook_client() -> None:
    from boundkeep import hook_main
    from boundkeep.install import MIN_TIMEOUTS_S

    assert {SUBCOMMANDS[event]: float(s) for event, s in MIN_TIMEOUTS_S.items()} == (
        hook_main.MIN_ENTRY_TIMEOUT_S
    )


@pytest.mark.parametrize("cmd", ALL_COMMANDS)
def test_default_entries_pass_the_hook_clients_own_intactness_check(cmd: HookCommand) -> None:
    from boundkeep import hook_main

    for event, group in groups_for(cmd).items():
        assert hook_main.entry_intact(group["hooks"][0], SUBCOMMANDS[event])


@pytest.mark.parametrize(
    ("field", "too_low"), [("prompt", 5), ("pre", 10), ("post", 5), ("config", 5)]
)
def test_timeouts_the_hook_client_would_call_altered_are_refused(field: str, too_low: int) -> None:
    with pytest.raises(ValueError, match="timeout"):
        build_hook_groups(PY_CMD, post_matcher=POST, timeouts=HookTimeouts(**{field: too_low}))


def test_timeouts_at_the_minimum_are_accepted_and_intact() -> None:
    from boundkeep import hook_main

    groups = build_hook_groups(
        PY_CMD, post_matcher=POST, timeouts=HookTimeouts(prompt=6, pre=11, post=6, config=6)
    )
    assert [groups[e]["hooks"][0]["timeout"] for e in EVENTS] == [6, 11, 6, 6]
    assert all(hook_main.entry_intact(g["hooks"][0], SUBCOMMANDS[e]) for e, g in groups.items())


# Finding: truncation happened before scrubbing, so a secret straddling the cut leaked its first
# characters; longer values hiding behind a shorter prefix value and values under 6 characters
# were not scrubbed at all.
def make_noisy_hook(
    tmp_path: Path, name: str, *, pad: int, print_vars: tuple[str, ...]
) -> HookCommand:
    script = tmp_path / f"{name}.py"
    body = f"""
        import os, sys
        sys.stdin.buffer.read()
        values = [os.environ.get(name, "") for name in {print_vars!r}]
        sys.stderr.write("x" * {pad} + " ".join(values) + " tail")
        sys.exit(1)
    """
    script.write_text(textwrap.dedent(body), encoding="utf-8")
    return HookCommand(sys.executable, ("-I", "-S", str(script)))


@pytest.mark.parametrize("pad", [0, 100, 280, 290, 292, 295, 297, 299, 300, 305])
def test_secret_straddling_the_excerpt_cut_does_not_leak(tmp_path: Path, pad: int) -> None:
    secret = "SUPERSECRETVALUE-0123456789"
    cmd = make_noisy_hook(tmp_path, f"straddle{pad}", pad=pad, print_vars=("BK_S",))
    [first, *rest] = check(cmd, env=base_env(BK_S=secret))
    for result in [first, *rest]:
        for k in range(4, len(secret) + 1):
            assert secret[:k] not in result.detail
            assert secret[-k:] not in result.detail
    assert "exit code 1" in first.detail


@hyp_settings(max_examples=300, deadline=None)
@given(
    values=st.lists(st.text(alphabet="abc", min_size=4, max_size=9), min_size=1, max_size=4),
    pieces=st.lists(st.text(alphabet="abcxy ", max_size=6), min_size=0, max_size=12),
)
def test_scrub_leaves_no_value_or_fragment_behind(values: list[str], pieces: list[str]) -> None:
    # Overlapping and nested occurrences (the alphabet is tiny on purpose) must be merged and
    # replaced as one span: neither a whole value nor the tail of a longer one may survive.
    from boundkeep.install import _scrub

    env = {f"V{n}": v for n, v in enumerate(values)}
    text = "".join(p + values[n % len(values)] for n, p in enumerate(pieces)) + "".join(pieces)
    scrubbed = _scrub(text, env)
    assert all(v not in scrubbed for v in values)
    # Nothing but the marker was added: what is left is the input with some spans cut out.
    remaining = iter(text)
    assert all(ch in remaining for ch in scrubbed.replace("<env>", ""))
    # And text without any value in it is returned untouched.
    if not any(v in text for v in values):
        assert scrubbed == text


def test_value_that_has_a_shorter_value_as_prefix_is_scrubbed_whole(tmp_path: Path) -> None:
    cmd = make_noisy_hook(tmp_path, "prefix", pad=0, print_vars=("BK_LONG",))
    env = base_env(BK_SHORT="abcdefgh", BK_LONG="abcdefghIJKLMNOPQRST")
    [first, *_] = check(cmd, env=env)
    assert "IJKLMNOP" not in first.detail
    assert "abcdefgh" not in first.detail


@pytest.mark.parametrize("secret", ["ab12x", "tok4"])
def test_short_secret_values_are_scrubbed_too(tmp_path: Path, secret: str) -> None:
    cmd = make_noisy_hook(tmp_path, f"short{secret}", pad=0, print_vars=("BK_T",))
    [first, *_] = check(cmd, env=base_env(BK_T=secret))
    assert secret not in first.detail
    assert "exit code 1" in first.detail


def test_non_ascii_secret_value_is_scrubbed(tmp_path: Path) -> None:
    secret = "密码-很长的秘密-\u2713"
    script = tmp_path / "cjk-secret.py"
    script.write_text(
        "import os, sys\nsys.stdin.buffer.read()\n"
        "sys.stderr.buffer.write(os.environ['BK_S'].encode('utf-8'))\nsys.exit(1)\n",
        encoding="utf-8",
    )
    cmd = HookCommand(sys.executable, ("-I", "-S", str(script)))
    [first, *_] = check(cmd, env=base_env(BK_S=secret))
    assert first.detail.isascii()
    assert "\\u5bc6" not in first.detail  # not even the escaped form of the value
    assert "<env>" in first.detail


# Finding: closing the pipes of a killed hook blocked forever when a grandchild still held them
# (a hook client that starts the daemon would hang `init` and `doctor`).
def make_grandchild_hook(
    tmp_path: Path, name: str, *, parent_exits: bool, child_seconds: int
) -> HookCommand:
    script = tmp_path / f"{name}.py"
    body = f"""
        import subprocess, sys, time
        sub = sys.argv[-1]
        sys.stdin.buffer.read()
        if sub != "pre":
            sys.exit(0)
        # The child inherits stdout and stderr, i.e. the pipes of the self check.
        subprocess.Popen([sys.executable, "-c", "import time; time.sleep({child_seconds})"])
        if {parent_exits!r}:
            sys.stdout.buffer.write({GOOD_PRE!r})
            sys.exit(0)
        time.sleep(100)
    """
    script.write_text(textwrap.dedent(body), encoding="utf-8")
    return HookCommand(sys.executable, ("-I", "-S", str(script)))


def test_hook_whose_child_keeps_the_pipes_open_after_a_timeout_does_not_hang(
    tmp_path: Path,
) -> None:
    cmd = make_grandchild_hook(tmp_path, "gc-hang", parent_exits=False, child_seconds=40)
    started = time.monotonic()
    results = check(cmd, timeout_s=1.5)
    wall = time.monotonic() - started
    pre = only_results(results, "pre")
    assert len(pre) == 2
    assert not any(r.ok for r in pre)
    assert all("timed out" in r.detail for r in pre)
    assert all(r.ok for r in results if r.subcommand != "pre")
    assert wall < 25, wall


def test_hook_that_exits_but_leaves_a_child_holding_the_pipes_is_not_ok_and_does_not_hang(
    tmp_path: Path,
) -> None:
    # Claude Code may wait for the pipes to close, not only for the exit; a hook that leaks them
    # can therefore look like a hang to it. Report that instead of blocking.
    cmd = make_grandchild_hook(tmp_path, "gc-exit", parent_exits=True, child_seconds=9)
    started = time.monotonic()
    results = check(cmd, timeout_s=15.0)
    wall = time.monotonic() - started
    pre = only_results(results, "pre")
    assert not any(r.ok for r in pre)
    assert all("still" in r.detail and "open" in r.detail for r in pre)
    assert all(r.ok for r in results if r.subcommand != "pre")
    assert wall < 14, wall


# Finding: the matcher was only checked for emptiness; a padded or malformed one is written into
# settings.json and the PostToolUse (taint) hook may then never fire.
@pytest.mark.parametrize(
    "matcher",
    [
        " WebFetch",
        "WebFetch ",
        "WebFetch | Read",
        "Web Fetch",
        "WebFetch\n",
        "WebFetch|",
        "|WebFetch",
        "WebFetch||Read",
        "(",
        "WebFetch|(",
        "[a-",
        ".*",
        "(WebFetch)?",
    ],
)
def test_malformed_or_padded_post_matchers_are_refused(matcher: str) -> None:
    with pytest.raises(ValueError, match="post_matcher"):
        build_hook_groups(PY_CMD, post_matcher=matcher)


@pytest.mark.parametrize(
    "matcher",
    ["WebFetch", "WebFetch|WebSearch|mcp__.*", "mcp__.*", "*", "Read", "mcp__gh__get_issue|Bash"],
)
def test_valid_post_matchers_are_accepted_verbatim(matcher: str) -> None:
    assert build_hook_groups(PY_CMD, post_matcher=matcher)["PostToolUse"]["matcher"] == matcher


# Finding: copy.deepcopy raised a bare RecursionError on a deeply nested but loadable document.
def deep_list(depth: int) -> Any:
    value: Any = []
    for _ in range(depth):
        value = [value]
    return value


def test_merge_and_remove_refuse_absurdly_deep_documents_with_settings_error() -> None:
    settings = {"x": deep_list(5000)}
    with pytest.raises(SettingsError, match="nested"):
        merge_hooks(settings, groups_for())
    with pytest.raises(SettingsError, match="nested"):
        remove_hooks(settings)


def test_the_deepest_document_load_settings_accepts_can_be_merged_rendered_and_removed(
    tmp_path: Path,
) -> None:
    from boundkeep.settings_io import MAX_NESTING_DEPTH

    text = '{"x": ' + "[" * (MAX_NESTING_DEPTH - 1) + "]" * (MAX_NESTING_DEPTH - 1) + "}"
    path = tmp_path / "deep.json"
    path.write_text(text, encoding="utf-8")
    doc = load_settings(str(path))
    merged, _ = merge_hooks(doc.data, groups_for())
    out = render_settings(doc, merged)
    restored, removed = remove_hooks(load_settings_from(tmp_path, out).data)
    assert removed == 4
    assert same(restored, doc.data)


# Finding: Linux paths containing a backslash were treated as Windows paths.
def test_posix_paths_containing_a_backslash_stay_posix() -> None:
    assert (
        resolve_settings_path("project", cwd="/home/u/a\\b", env={})
        == "/home/u/a\\b/.claude/settings.json"
    )
    assert (
        resolve_settings_path("user", cwd="/x", env={"CLAUDE_CONFIG_DIR": "/etc/a\\b"})
        == "/etc/a\\b/settings.json"
    )
    assert (
        resolve_settings_path("user", cwd="/x", env={"HOME": "/home/u\\x"})
        == "/home/u\\x/.claude/settings.json"
    )


def test_windows_paths_with_forward_slashes_and_drive_letters_stay_windows() -> None:
    assert (
        resolve_settings_path("project", cwd="C:/Users/dev/proj", env={})
        == "C:/Users/dev/proj\\.claude\\settings.json"
    )


# Finding: the manifest key did not canonicalize Windows path aliases.
@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("C:\\Users\\x\\.claude\\settings.json", "\\\\?\\C:\\Users\\x\\.claude\\settings.json"),
        ("\\\\srv\\share\\p\\settings.json", "\\\\?\\UNC\\srv\\share\\p\\settings.json"),
        ("C:\\Users\\x\\.claude\\settings.json", "C:\\Users\\x.\\.claude\\settings.json"),
        ("C:\\Users\\x\\.claude\\settings.json", "C:\\Users\\x \\.claude\\settings.json"),
        ("C:\\Users\\x\\.claude\\settings.json", "c:/users/x/./y/../.claude/settings.json"),
    ],
)
def test_windows_path_aliases_share_one_manifest_key(a: str, b: str) -> None:
    first, second = record(a), record(b, installed_at="later")
    assert upsert_record([first], second) == [second]
    assert drop_record([first], b) == []
    assert drop_record([second], a) == []


def test_different_windows_paths_still_get_different_keys() -> None:
    a, b = record("C:\\Users\\x\\.claude\\settings.json"), record("C:\\Users\\y\\.claude\\s.json")
    assert upsert_record([a], b) == [a, b]
    c = record("\\\\?\\D:\\Users\\x\\.claude\\settings.json")
    assert upsert_record([a], c) == [a, c]


@pytest.mark.windows
def test_short_8_3_names_share_the_key_of_the_long_name(tmp_path: Path) -> None:
    import ctypes

    long_dir = tmp_path / "A Rather Long Directory Name" / ".claude"
    long_dir.mkdir(parents=True)
    buffer = ctypes.create_unicode_buffer(1024)
    length = ctypes.windll.kernel32.GetShortPathNameW(str(long_dir), buffer, 1024)  # type: ignore[attr-defined]
    if not length or buffer.value.lower() == str(long_dir).lower():
        pytest.skip("8.3 short names are not enabled on this volume")
    long_path = str(long_dir / "settings.json")
    short_path = os.path.join(buffer.value, "settings.json")
    first, second = record(long_path), record(short_path, installed_at="later")
    assert upsert_record([first], second) == [second]
    assert drop_record([first], short_path) == []


# Documented limit (review finding "merge then remove does not restore empty containers"): an
# event list or hooks object that was ALREADY empty cannot be told apart from one our entries
# emptied, and the contract says to drop containers the removal leaves empty.
@pytest.mark.parametrize("original", [{"hooks": {}}, {"hooks": {"PreToolUse": []}}])
def test_pre_existing_empty_hook_containers_are_dropped_by_merge_then_remove(
    original: dict[str, Any],
) -> None:
    merged, _ = merge_hooks(original, groups_for())
    restored, removed = remove_hooks(merged)
    assert removed == 4
    assert restored == {}
