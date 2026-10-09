"""claude_settings: warnings and infos about top-level keys, never errors."""

from __future__ import annotations

import pytest

from boundkeep import claude_settings as cs
from boundkeep.claude_settings import (
    GLOBAL_CONFIG_ONLY_KEYS,
    HOOK_EVENT_NAMES,
    KNOWN_TOP_LEVEL_KEYS,
    SettingsFinding,
    find_suspicious_top_level_keys,
)
from boundkeep.ownhook import SUBCOMMANDS


def only(key: str, value: object = None) -> list[SettingsFinding]:
    return find_suspicious_top_level_keys({key: value})


def test_snapshot_metadata_is_recorded() -> None:
    assert cs.SNAPSHOT_DATE.startswith("20")
    assert cs.SOURCE_URL.startswith("https://")
    assert isinstance(cs.SNAPSHOT_COMPLETE, bool)
    assert len(KNOWN_TOP_LEVEL_KEYS) > 100


def test_snapshot_contains_the_keys_boundkeep_itself_relies_on() -> None:
    for key in ("hooks", "disableAllHooks", "permissions", "env", "model", "statusLine", "sandbox"):
        assert key in KNOWN_TOP_LEVEL_KEYS


def test_snapshot_is_free_of_dotted_and_blank_keys() -> None:
    for key in KNOWN_TOP_LEVEL_KEYS:
        assert key
        assert key == key.strip()
        assert "." not in key, f"{key} is a nested key, list its top-level parent"


def test_global_config_keys_are_kept_apart() -> None:
    assert not (GLOBAL_CONFIG_ONLY_KEYS & KNOWN_TOP_LEVEL_KEYS)


def test_every_hook_event_boundkeep_uses_is_a_known_event_name() -> None:
    assert set(SUBCOMMANDS) <= HOOK_EVENT_NAMES


@pytest.mark.parametrize("key", ["hooks", "disableAllHooks"])
def test_hooks_and_disable_all_hooks_are_never_flagged(key: str) -> None:
    assert only(key) == []
    assert only(key, True) == []
    assert only(key, "garbage") == []


def test_known_keys_produce_no_findings() -> None:
    data = dict.fromkeys(sorted(KNOWN_TOP_LEVEL_KEYS), 1)
    assert find_suspicious_top_level_keys(data) == []


def test_no_known_key_is_mistaken_for_a_typo_of_the_hook_settings() -> None:
    # The typo rule must never fire on a documented setting.
    for key in KNOWN_TOP_LEVEL_KEYS:
        assert find_suspicious_top_level_keys({key: 1}) == []


def test_empty_settings_have_no_findings() -> None:
    assert find_suspicious_top_level_keys({}) == []


# ---- class 1: hook event names at the top level ---------------------------------------------


@pytest.mark.parametrize("event", sorted(HOOK_EVENT_NAMES))
def test_event_name_at_top_level_is_a_warning(event: str) -> None:
    [finding] = only(event, [{"hooks": []}])
    assert finding.key == event
    assert finding.severity == "warning"
    assert '"hooks"' in finding.message
    assert "not verified" in finding.message


def test_event_name_next_to_a_real_hooks_object() -> None:
    data = {"hooks": {"PostToolUse": []}, "PreToolUse": [{"hooks": []}], "model": "x"}
    findings = find_suspicious_top_level_keys(data)
    assert [(f.key, f.severity) for f in findings] == [("PreToolUse", "warning")]


def test_event_name_with_wrong_case_is_still_flagged() -> None:
    [finding] = only("pretooluse")
    assert finding.severity == "warning"


# ---- class 2: typos of hooks / disableAllHooks ----------------------------------------------


@pytest.mark.parametrize(
    ("key", "target"),
    [
        ("Hooks", "hooks"),
        ("HOOKS", "hooks"),
        ("hook", "hooks"),
        ("hookss", "hooks"),
        ("hocks", "hooks"),
        ("hoks", "hooks"),
        ("hoooks", "hooks"),
        ("DisableAllHooks", "disableAllHooks"),
        ("disableallhooks", "disableAllHooks"),
        ("disableAllHook", "disableAllHooks"),
        ("disableAllHoks", "disableAllHooks"),
        ("disableAllHooksx", "disableAllHooks"),
        ("disbleAllHooks", "disableAllHooks"),
        ("disableAllHookz", "disableAllHooks"),
    ],
)
def test_typo_of_hook_settings_is_a_warning(key: str, target: str) -> None:
    [finding] = only(key)
    assert finding.key == key
    assert finding.severity == "warning"
    assert repr(target) in finding.message
    assert "not verified" in finding.message


@pytest.mark.parametrize("key", ["hoo", "hookers", "disableHooks", "disable_all_hooks", "hooksx2"])
def test_two_or_more_edits_are_not_typos(key: str) -> None:
    [finding] = only(key)
    assert finding.severity == "info"


# ---- class 3: unknown keys ------------------------------------------------------------------


@pytest.mark.parametrize("key", ["somethingNew", "my_custom_key", "x", "钩子"])
def test_unknown_key_is_info_only(key: str) -> None:
    [finding] = only(key)
    assert finding.severity == "info"
    assert finding.key == key
    assert cs.SNAPSHOT_DATE in finding.message
    assert "lag" in finding.message


def test_global_config_key_gets_a_specific_info() -> None:
    [finding] = only("autoConnectIde", True)
    assert finding.severity == "info"
    assert "~/.claude.json" in finding.message


def test_no_finding_is_ever_an_error() -> None:
    data = {"PreToolUse": 1, "Hooks": 1, "weird": 1, "autoConnectIde": 1, "model": "x"}
    findings = find_suspicious_top_level_keys(data)
    assert {f.severity for f in findings} <= {"warning", "info"}
    assert {f.key for f in findings} == {"PreToolUse", "Hooks", "weird", "autoConnectIde"}


def test_findings_follow_document_order_and_do_not_mutate_input() -> None:
    data = {"zzz": 1, "PreToolUse": [], "aaa": 2}
    snapshot = dict(data)
    findings = find_suspicious_top_level_keys(data)
    assert [f.key for f in findings] == ["zzz", "PreToolUse", "aaa"]
    assert data == snapshot
