"""doctor must be as strict about our entries as the ConfigChange hook is (they share the rules)."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from boundkeep import doctor, install, settings_io

PY = "C:\\uv\\python\\python.exe"
SCRIPT = "E:\\proj\\boundkeep\\src\\boundkeep\\hook_client.py"
POST_MATCHER = "^(?:WebFetch|WebSearch|mcp__.*)$"


def _entry(sub: str, **extra: Any) -> dict[str, Any]:
    timeout = {"pre": 15, "prompt": 10, "post": 10, "config": 10}[sub]
    return {
        "type": "command",
        "command": PY,
        "args": ["-I", "-S", SCRIPT, sub],
        "timeout": timeout,
        **extra,
    }


def _settings() -> dict[str, Any]:
    return {
        "hooks": {
            "UserPromptSubmit": [{"hooks": [_entry("prompt")]}],
            "PreToolUse": [{"matcher": "*", "hooks": [_entry("pre")]}],
            "PostToolUse": [{"matcher": POST_MATCHER, "hooks": [_entry("post")]}],
            "ConfigChange": [{"hooks": [_entry("config")]}],
        }
    }


def _record(path: str) -> install.InstallRecord:
    return install.InstallRecord(
        settings_path=path,
        scope="project",
        created_file=False,
        hook_command=PY,
        hook_args=("-I", "-S", SCRIPT),
        post_matcher=POST_MATCHER,
        installed_at="2026-10-08T00:00:00Z",
    )


def _checks(tmp_path: Path, data: dict[str, Any], with_record: bool = True) -> list[doctor.Check]:
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    layer = doctor.Layer("project", str(path), settings_io.load_settings(str(path)), None)
    return doctor.check_layer(layer, _record(str(path)) if with_record else None)


def _failures(checks: list[doctor.Check]) -> list[str]:
    return [c.detail for c in checks if c.status == doctor.FAIL and "hook command" not in c.detail]


def _mutate(change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    data = copy.deepcopy(_settings())
    change(data)
    return data


MUTATIONS: dict[str, Callable[[dict[str, Any]], None]] = {
    "extra-field": lambda d: d["hooks"]["PreToolUse"][0]["hooks"][0].update({"if": "Bash(git *)"}),
    "async": lambda d: d["hooks"]["PreToolUse"][0]["hooks"][0].update({"async": True}),
    "timeout-7": lambda d: d["hooks"]["PreToolUse"][0]["hooks"][0].update({"timeout": 7}),
    "timeout-string": lambda d: d["hooks"]["PreToolUse"][0]["hooks"][0].update({"timeout": "1"}),
    "timeout-huge": lambda d: d["hooks"]["PreToolUse"][0]["hooks"][0].update({"timeout": 10**9}),
    "post-matcher": lambda d: d["hooks"]["PostToolUse"][0].update({"matcher": "Nothing"}),
    "config-matcher": lambda d: d["hooks"]["ConfigChange"][0].update({"matcher": "user_settings"}),
    "pre-runs-prompt-handler": lambda d: d["hooks"]["PreToolUse"][0]["hooks"][0][
        "args"
    ].__setitem__(-1, "prompt"),
    "env-redirect": lambda d: d.update({"env": {"BOUNDKEEP_HOME": "C:\\evil"}}),
    "disable-all": lambda d: d.update({"disableAllHooks": True}),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
@pytest.mark.parametrize("with_record", [True, False])
def test_doctor_fails_for_every_edit_the_config_change_hook_would_block(
    tmp_path: Path, name: str, with_record: bool
) -> None:
    if with_record is False and name == "post-matcher":
        pytest.skip("without a record there is no expected post matcher to compare with")
    checks = _checks(tmp_path, _mutate(MUTATIONS[name]), with_record)
    assert _failures(checks), [(c.status, c.detail) for c in checks]


def test_an_untouched_installation_has_no_failures_from_the_entry_rules(tmp_path: Path) -> None:
    assert _failures(_checks(tmp_path, _settings())) == []
