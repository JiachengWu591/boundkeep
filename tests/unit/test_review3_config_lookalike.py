"""Security review round 3 (docs/reviews/M1-M1b-fixes-rereview.md, C-1): an extra hook entry that
merely LOOKS like boundkeep's must not count as ours.

``ownhook.is_own_hook`` only checks the shape. Three imitations passed both
``claude_settings.blocking_reasons`` and ``hook_main.record_problem`` in the re-review. Now an entry
is ours only when its command and arguments equal an install record's ``hook_command`` and
``[*hook_args, subcommand]`` exactly; everything else is foreign, and one that looks like ours
blocks the change.

Pure functions plus temp files only: no real ``~/.boundkeep``, ``~/.claude`` or project settings.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from boundkeep import claude_settings, hook_main, ownhook

PY = "C:\\py\\python.exe"
HOME = "C:\\Users\\dev\\.boundkeep"
BASE_ARGS = ["-I", "-S", "E:\\proj\\boundkeep\\src\\boundkeep\\hook_client.py", "--home", HOME]
LAUNCHER = "C:\\tools\\boundkeep-hook.exe"
TIMEOUT = {"pre": 15, "prompt": 10, "post": 10, "config": 10}
EVENTS = {
    "UserPromptSubmit": "prompt",
    "PreToolUse": "pre",
    "PostToolUse": "post",
    "ConfigChange": "config",
}


def _entry(sub: str, command: str = PY, base: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "command",
        "command": command,
        "args": [*(BASE_ARGS if base is None else base), sub],
        "timeout": TIMEOUT[sub],
    }


def _intact() -> dict[str, Any]:
    hooks: dict[str, Any] = {}
    for event, sub in EVENTS.items():
        group: dict[str, Any] = {"hooks": [_entry(sub)]}
        if event == "PreToolUse":
            group["matcher"] = "*"
        if event == "PostToolUse":
            group["matcher"] = "*"
        hooks[event] = [group]
    return {"hooks": hooks}


def _record(command: str = PY, base: list[str] | None = None) -> dict[str, Any]:
    return {
        "hook_command": command,
        "hook_args": list(BASE_ARGS if base is None else base),
        "post_matcher": "*",
    }


OWN = [(PY, BASE_ARGS)]

# The three imitations of the re-review (C-1) plus variations.
IMITATIONS: dict[str, dict[str, Any]] = {
    "evil-launcher-exe": {
        "type": "command",
        "command": "C:\\evil\\boundkeep-hook.exe",
        "args": ["pre"],
    },
    "python-evil-boundkeep-dir": {
        "type": "command",
        "command": "C:\\py\\python.exe",
        "args": ["C:\\evil\\boundkeep\\hook_client.py", "pre"],
    },
    "real-launcher-other-home": {
        "type": "command",
        "command": LAUNCHER,
        "args": ["--home", "C:\\evil", "pre"],
    },
    "our-command-other-home": {
        "type": "command",
        "command": PY,
        "args": [*BASE_ARGS[:-1], "C:\\evil", "pre"],
    },
    "our-command-extra-flag": {
        "type": "command",
        "command": PY,
        "args": [*BASE_ARGS, "--emit-allow", "pre"],
    },
}


def _with_extra(variant: str, imitation: dict[str, Any]) -> dict[str, Any]:
    data = _intact()
    pre = data["hooks"]["PreToolUse"]
    if variant == "own-group":
        pre[0]["hooks"].append(imitation)
    elif variant == "own-group-first":
        pre[0]["hooks"].insert(0, imitation)
    elif variant == "separate-group":
        pre.append({"matcher": "*", "hooks": [imitation]})
    elif variant == "narrow-matcher-first":
        pre.insert(0, {"matcher": "Bash", "hooks": [imitation]})
    elif variant == "other-event":
        data["hooks"]["Stop"] = [{"hooks": [imitation]}]
    else:  # pragma: no cover
        raise AssertionError(variant)
    return data


VARIANTS = ["own-group", "own-group-first", "separate-group", "narrow-matcher-first", "other-event"]


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("name", sorted(IMITATIONS))
def test_record_problem_names_an_extra_hook_that_looks_like_ours(name: str, variant: str) -> None:
    data = _with_extra(variant, copy.deepcopy(IMITATIONS[name]))
    assert ownhook.is_own_hook(IMITATIONS[name]), "the fixture must be one that passes the shape"
    problem = hook_main.record_problem(data, _record())
    assert problem is not None
    assert "looks like boundkeep's" in problem


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("name", sorted(IMITATIONS))
def test_blocking_reasons_blocks_an_extra_hook_that_looks_like_ours(
    name: str, variant: str
) -> None:
    data = _with_extra(variant, copy.deepcopy(IMITATIONS[name]))
    reasons = claude_settings.blocking_reasons(data, None, OWN)
    assert any("looks like boundkeep's" in r for r in reasons), reasons


def test_the_intact_install_has_no_extra_entry() -> None:
    assert hook_main.record_problem(_intact(), _record()) is None
    assert claude_settings.blocking_reasons(_intact(), None, OWN) == []


def test_an_exact_duplicate_of_our_entry_is_still_ours() -> None:
    data = _intact()
    data["hooks"]["PreToolUse"].append({"matcher": "*", "hooks": [_entry("pre")]})
    assert hook_main.record_problem(data, _record()) is None
    assert claude_settings.blocking_reasons(data, None, OWN) == []


def test_our_arguments_under_the_wrong_event_are_not_ours() -> None:
    data = _intact()
    data["hooks"]["Stop"] = [{"hooks": [_entry("pre")]}]
    assert "looks like boundkeep's" in str(hook_main.record_problem(data, _record()))


def test_the_launcher_style_record_is_compared_exactly_too() -> None:
    record = _record(LAUNCHER, ["--home", HOME])
    data: dict[str, Any] = {"hooks": {}}
    for event, sub in EVENTS.items():
        group: dict[str, Any] = {"hooks": [_entry(sub, LAUNCHER, ["--home", HOME])]}
        if event in ("PreToolUse", "PostToolUse"):
            group["matcher"] = "*"
        data["hooks"][event] = [group]
    assert hook_main.record_problem(data, record) is None
    data["hooks"]["PreToolUse"][0]["hooks"].append(IMITATIONS["real-launcher-other-home"])
    assert "looks like boundkeep's" in str(hook_main.record_problem(data, record))


def test_without_a_record_the_shape_is_all_there_is_and_nothing_blocks_on_it() -> None:
    data = _with_extra("separate-group", copy.deepcopy(IMITATIONS["evil-launcher-exe"]))
    assert claude_settings.blocking_reasons(data) == []
    assert claude_settings.blocking_reasons(data, None, None) == []
    assert ownhook.lookalike_hooks(data, []) == []


def test_a_foreign_hook_that_does_not_even_look_like_ours_is_watched_not_blocked() -> None:
    data = _intact()
    data["hooks"]["PreToolUse"].append(
        {"hooks": [{"type": "command", "command": "C:\\x\\fmt.exe"}]}
    )
    assert claude_settings.blocking_reasons(data, None, OWN) == []
    assert hook_main.record_problem(data, _record()) is None


def test_the_look_alike_makes_the_baseline_fingerprint_change_as_well() -> None:
    clean = claude_settings.watched_fingerprints(_intact(), OWN)
    dirty = claude_settings.watched_fingerprints(
        _with_extra("separate-group", copy.deepcopy(IMITATIONS["evil-launcher-exe"])), OWN
    )
    assert clean != dirty
    assert "hooks.PreToolUse" in dirty


def test_the_message_is_short_and_does_not_echo_a_huge_command() -> None:
    evil = dict(
        IMITATIONS["evil-launcher-exe"], command="C:\\evil\\" + "x" * 5000 + "\\boundkeep-hook"
    )
    problem = hook_main.record_problem(_with_extra("separate-group", evil), _record())
    assert problem is not None
    assert len(problem) < 600


def test_doctor_fails_for_an_imitation_when_a_record_exists_and_only_infers_without_one(
    tmp_path: Path,
) -> None:
    from boundkeep import doctor, install, settings_io

    data = _with_extra("separate-group", copy.deepcopy(IMITATIONS["python-evil-boundkeep-dir"]))
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    layer = doctor.Layer("project", str(path), settings_io.load_settings(str(path)), None)
    record = install.InstallRecord(
        settings_path=str(path),
        scope="project",
        created_file=False,
        hook_command=PY,
        hook_args=tuple(BASE_ARGS),
        post_matcher="*",
        installed_at="2026-10-18T00:00:00Z",
    )
    with_record = doctor.check_layer(layer, record)
    assert [c.status for c in with_record if "looks like boundkeep's" in c.detail] == [doctor.FAIL]
    without = doctor.check_layer(layer, None)  # no record: the shape heuristic only, no verdict
    assert not [c for c in without if "looks like boundkeep's" in c.detail]


# ---- through config_violation (the real ConfigChange path) -----------------------------------


def _write_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    data: dict[str, Any],
    **record_fields: Any,
) -> Path:
    """A settings file plus an install manifest for it, in a temp boundkeep home (never ~)."""
    home = tmp_path / "bk-home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("BOUNDKEEP_HOME", str(home))
    settings = tmp_path / "proj" / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps(data), encoding="utf-8")
    record = {
        "settings_path": str(settings),
        "scope": "project",
        "created_file": False,
        "installed_at": "2026-10-18T00:00:00Z",
        **_record(),
        **record_fields,
    }
    (home / "installs.json").write_text(
        json.dumps({"version": 1, "installs": [record]}), encoding="utf-8"
    )
    return settings


@pytest.mark.parametrize("name", sorted(IMITATIONS))
def test_config_violation_blocks_each_imitation(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _with_extra("separate-group", copy.deepcopy(IMITATIONS[name]))
    path = _write_install(tmp_path, monkeypatch, data)
    problem = hook_main.config_violation(str(path))
    assert problem is not None
    assert "looks like boundkeep's" in problem


def test_config_violation_accepts_the_intact_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_install(tmp_path, monkeypatch, _intact())
    assert hook_main.config_violation(str(path)) is None
