"""The targeted X1 re-review of the M3a fixes (docs/reviews/M3a-rereview.md): R-1, R-4, R-10.

R-1: a write into the project from a session whose working directory is outside it left no mark
(``Action.project`` is None there), so the project's dev tools ran unasked in other sessions.
R-4: ``python -m boundkeep.cli`` (or ``boundkeep.__main__``) is the whole CLI, but only
``python -m boundkeep`` was recognized as boundkeep, so the state commands were a gray python call.
R-10: doctor did not say that an installed policy lacks the default taint sources, or that the
PostToolUse matcher does not follow the policy's sources.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from boundkeep import doctor, paths, protocol, settings_io
from boundkeep.audit.auditor import Auditor
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.normalize.event import normalize_event
from boundkeep.policy.loader import taint_sources_to_matcher
from boundkeep.policy.schema import DEFAULT_TAINT_SOURCES
from boundkeep.session.marks import written_locations
from boundkeep.session.store import SessionStore
from tests.unit.test_m3a_pipeline import HOME, PROJECT, bash, decide, event, policy, post

OTHER_SID = "00000000-0000-4000-8000-0000000000dd"
MARK_RULE = "ask-devtools-after-untrusted-project-write"
STATE_RULE = "deny-boundkeep-state-commands"
NOTES = "/home/testuser/notes"  # a directory next to the project (an added working directory)


@pytest.fixture
def store(tmp_path: Path) -> Any:
    s = SessionStore(str(tmp_path / "session.sqlite"))
    yield s
    s.close()


def in_other_session(payload: dict[str, Any]) -> dict[str, Any]:
    return dict(payload, session_id=OTHER_SID, cwd=PROJECT, project_dir=PROJECT)


def locations(s: SessionStore) -> list[str]:
    marks = s.marks()
    assert marks is not None
    return [m.location for m in marks]


def without_cwd(payload: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in payload.items() if k != "cwd"}


# ------------------------------------------------------------------ R-1: cwd outside the project

OUTSIDE_WRITES = [
    event("Write", {"file_path": f"{PROJECT}/tests/test_x.py", "content": "x"}, cwd=NOTES),
    event(
        "Edit",
        {"file_path": f"{PROJECT}/tests/test_x.py", "old_string": "a", "new_string": "b"},
        cwd=NOTES,
    ),
    event("Write", {"file_path": f"{PROJECT}/conftest.py", "content": "x"}, cwd=NOTES),
    bash(f"echo x > {PROJECT}/tests/test_y.py") | {"cwd": NOTES},
    bash("echo x > $TARGET/tests/test_z.py") | {"cwd": NOTES},  # not certainly anywhere
    without_cwd(event("Write", {"file_path": f"{PROJECT}/tests/test_x.py", "content": "x"})),
]


@pytest.mark.parametrize("write", OUTSIDE_WRITES, ids=lambda p: str(p["tool_input"])[:40])
def test_a_write_into_the_project_from_outside_it_marks_the_project(
    store: SessionStore, write: dict[str, Any]
) -> None:
    pol = policy(trusted=True)
    post("WebFetch", store, pol)
    decide(write, pol, store=store)
    assert locations(store) == [PROJECT]
    asked = decide(in_other_session(bash("pytest -q")), pol, store=store)
    assert asked.decision == protocol.DECISION_ASK
    assert asked.rule_ids == (MARK_RULE,)


def test_the_project_root_is_kept_on_the_actions_whatever_the_working_directory() -> None:
    (action,) = normalize_event(OUTSIDE_WRITES[0], platform="posix", env={"HOME": HOME}, home=HOME)
    assert action.project is None  # project_trusted must not apply to a command run elsewhere
    assert action.project_root == PROJECT
    assert written_locations([action]) == (PROJECT,)


def test_a_write_outside_the_project_from_outside_it_marks_only_that_path(
    store: SessionStore,
) -> None:
    pol = policy(trusted=True)
    post("WebFetch", store, pol)
    decide(bash("echo x > tests/test_x.py") | {"cwd": NOTES}, pol, store=store)
    assert locations(store) == [f"{NOTES}/tests/test_x.py"]
    ran = decide(in_other_session(bash("pytest -q")), pol, store=store)
    assert ran.decision == protocol.DECISION_NONE


def test_a_read_from_outside_the_project_still_marks_nothing(store: SessionStore) -> None:
    pol = policy(trusted=True)
    post("WebFetch", store, pol)
    decide(event("Read", {"file_path": f"{PROJECT}/src/app.py"}, cwd=NOTES), pol, store=store)
    assert locations(store) == []


# --------------------------------------------------------- R-4: python -m boundkeep.<module>

STATE_COMMANDS = [
    "python -m boundkeep.cli mode audit-only",
    "python -m boundkeep.cli uninstall",
    "python -m boundkeep.cli init --reset-policy",
    "python -m boundkeep.cli taint clear --all",
    "python -m boundkeep.cli trust add .",
    "python -m boundkeep.__main__ mode audit-only",
    "python3 -m boundkeep.cli mode audit-only",
    "python -mboundkeep.cli mode audit-only",
    "python -I -m boundkeep.cli serve",
    "uv run python -m boundkeep.cli mode audit-only",
    "python -m BOUNDKEEP.CLI mode audit-only",
]


@pytest.mark.parametrize("command", STATE_COMMANDS)
@pytest.mark.parametrize("llm", [False, True], ids=["rules", "llm-allows-everything"])
def test_running_a_boundkeep_module_is_running_boundkeep(command: str, llm: bool) -> None:
    pol = policy(llm=llm)
    auditor = Auditor(pol.llm_audit, FakeBackend.answering()) if llm else None
    denied = decide(bash(command), pol, auditor=auditor)
    assert denied.decision == protocol.DECISION_DENY
    assert STATE_RULE in denied.rule_ids  # init --reset-policy is also deny-boundkeep-state-flags


@pytest.mark.parametrize(
    ("command", "program", "subcommand"),
    [
        ("python -m boundkeep.cli mode enforce", "boundkeep", "mode"),
        ("python -m boundkeep.__main__ doctor", "boundkeep", "doctor"),
        ("python -mboundkeep.cli log", "boundkeep", "log"),
        ("python -m boundkeep.hook_client pre", "boundkeep-hook", None),
        ("python -m boundkeepx mode audit-only", "python", None),  # another package
        ("python -m boundkeep_cli mode audit-only", "python", None),
        ("python -m runpy boundkeep mode audit-only", "python", None),  # gray: see threat model
        ("python -c 'from boundkeep.cli import main; main()'", "python", None),
    ],
)
def test_the_module_names_that_are_boundkeep(
    command: str, program: str, subcommand: str | None
) -> None:
    actions = normalize_event(bash(command), platform="posix", env={"HOME": HOME}, home=HOME)
    assert actions[0].program == program
    if subcommand is not None:
        assert actions[0].subcommand == subcommand
    if program != "python":
        assert "python-m" in actions[0].wrappers  # no allow rule matches the wrapped line


# ------------------------------------------------- R-10: doctor and the installed taint sources

PY = "C:\\Python312\\python.exe"
SCRIPT = "E:\\proj\\boundkeep\\src\\boundkeep\\hook_client.py"
OLD_SOURCES = ["WebFetch", "WebSearch", "mcp__*"]


def policy_home(tmp_path: Path, sources: list[str] | None) -> str:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    text = (Path(__file__).resolve().parents[2] / "policies" / "default.yaml").read_text(
        encoding="utf-8"
    )
    if sources is not None:
        start = text.index("  sources:")
        end = text.index("  window:", start)
        listed = "".join(f"    - '{s}'\n" for s in sources)
        text = text[:start] + "  sources:\n" + listed + text[end:]
    Path(paths.policy_file(str(home))).write_text(text, encoding="utf-8")
    return str(home)


def layer(tmp_path: Path, post_matcher: str | None) -> doctor.Layer:
    hook = {"type": "command", "command": PY, "timeout": 15}
    data: dict[str, Any] = {
        "hooks": {
            "PreToolUse": [
                {"matcher": "*", "hooks": [dict(hook, args=["-I", "-S", SCRIPT, "pre"])]}
            ]
        }
    }
    if post_matcher is not None:
        post_hook = dict(hook, args=["-I", "-S", SCRIPT, "post"])
        data["hooks"]["PostToolUse"] = [{"matcher": post_matcher, "hooks": [post_hook]}]
    path = tmp_path / "user-settings.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return doctor.Layer("user", str(path), settings_io.load_settings(str(path)), None)


def test_doctor_is_quiet_when_the_policy_and_the_matcher_have_the_default_sources(
    tmp_path: Path,
) -> None:
    home = policy_home(tmp_path, None)
    matcher = taint_sources_to_matcher(DEFAULT_TAINT_SOURCES)
    assert doctor.check_taint_sources(home, [layer(tmp_path, matcher)]) == []


def test_doctor_warns_when_an_old_policy_lacks_default_sources(tmp_path: Path) -> None:
    home = policy_home(tmp_path, OLD_SOURCES)
    matcher = taint_sources_to_matcher(OLD_SOURCES)
    (check,) = doctor.check_taint_sources(home, [layer(tmp_path, matcher)])
    assert check.status == doctor.WARN
    for name in ("ListMcpResourcesTool", "ReadMcpResourceTool", "ReadMcpResourceDirTool"):
        assert name in check.detail
    assert "window" not in check.detail  # the shipped window: nothing to say
    assert "taint.sources" in check.fix


def test_doctor_names_an_old_window_next_to_old_sources(tmp_path: Path) -> None:
    home = policy_home(tmp_path, OLD_SOURCES)
    text = Path(paths.policy_file(home)).read_text(encoding="utf-8")
    Path(paths.policy_file(home)).write_text(
        text.replace("  window: 3", "  window: 8"), encoding="utf-8"
    )
    (check,) = doctor.check_taint_sources(home, [layer(tmp_path, None)])
    assert "taint.window is 8" in check.detail
    assert "boundkeep init" in check.fix


def test_doctor_warns_when_the_matcher_does_not_follow_the_policy(tmp_path: Path) -> None:
    home = policy_home(tmp_path, None)
    old = taint_sources_to_matcher(OLD_SOURCES)
    (check,) = doctor.check_taint_sources(home, [layer(tmp_path, old)])
    assert check.status == doctor.WARN
    assert "PostToolUse" in check.detail
    assert "user" in check.detail
    assert check.fix == "run 'boundkeep init' again"


def test_doctor_leaves_an_unloadable_policy_and_a_missing_post_hook_to_other_checks(
    tmp_path: Path,
) -> None:
    home = policy_home(tmp_path, None)
    assert doctor.check_taint_sources(home, [layer(tmp_path, None)]) == []
    Path(paths.policy_file(home)).write_text("not: [valid", encoding="utf-8")
    assert doctor.check_taint_sources(home, [layer(tmp_path, "WebFetch")]) == []
