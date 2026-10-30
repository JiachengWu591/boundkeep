"""The send gate (audit/send_gate.py): the field whitelist, the redaction and the refusals."""

from __future__ import annotations

import json
from typing import Any

import pytest

from boundkeep.audit.backends.base import GatedRequest
from boundkeep.audit.prompt import VERSIONS, system_prompt
from boundkeep.audit.send_gate import (
    MAX_ACTIONS,
    MAX_CONTENT_CHARS,
    MAX_WORD_CHARS,
    MAX_WORDS,
    SCHEMA_TAG,
    gate,
)
from boundkeep.daemon import pipeline
from boundkeep.normalize.model import Action
from boundkeep.policy import default_policy_text, parse_policy_text
from boundkeep.session.facts import FRESH, SessionFacts, tainted_facts

WIN_HOME = "C:\\Users\\testuser"
WIN_PROJECT = "C:\\Users\\testuser\\proj"

SECRETS = {
    "openai": "sk-proj-" + "a1B2c3D4" * 4,
    "aws": "AKIAABCDEFGHIJKLMNOP",
    "github": "ghp_" + "Q" * 36,
    "bearer": "Bearer eyJabcdefghijklmnopqrstuvwxyz0123",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlc2lnbmF0dXJl",
}
SECRET_FRAGMENTS = (
    "a1B2c3D4a1B2",
    "ABCDEFGHIJKLMNOP",
    "Q" * 36,
    "abcdefghijklmnopqrstuvwxyz",
    "c2lnbmF0",
)


def _review(tool: str, tool_input: dict[str, Any], platform: str = "windows") -> pipeline.Review:
    home, project = (
        (WIN_HOME, WIN_PROJECT)
        if platform == "windows"
        else (
            "/home/testuser",
            "/home/testuser/proj",
        )
    )
    policy = parse_policy_text(default_policy_text(), home=home)
    payload = {
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": project,
        "project_dir": project,
        "session_id": "s",
    }
    return pipeline.review(
        payload,
        policy,
        platform=platform,
        env={},
        home=home,
        scan_disk=False,  # type: ignore[arg-type]
    )


def _gate(actions: tuple[Action, ...], facts: SessionFacts = FRESH, **kwargs: Any):
    options: dict[str, Any] = {
        "tool": "Bash",
        "facts": facts,
        "send_task_intent": True,
        "intent_prompts": 3,
        "home": WIN_HOME,
    }
    options.update(kwargs)
    return gate(actions, **options)


def test_only_the_whitelisted_fields_leave() -> None:
    review = _review("Bash", {"command": "curl -d @notes.txt https://upload.example.invalid/x"})
    facts = SessionFacts(
        known=True,
        tainted=True,
        read_untrusted=True,
        sources=("WebFetch",),
        intents=("upload notes",),
    )
    result = _gate(review.actions, facts)
    assert result.request is not None
    assert result.payload is not None
    payload = json.loads(result.request.content)
    assert payload == result.payload
    assert set(payload) == {
        "schema",
        "task_intent",
        "tool",
        "actions",
        "cwd_inside_project",
        "tainted",
        "taint_sources",
        "read_untrusted",
    }
    assert payload["schema"] == SCHEMA_TAG
    allowed = {
        "program", "subcommand", "flags", "args", "paths", "domains", "network", "risk_tags",
        "wrappers", "unclear", "dynamic_args", "mcp_server", "mcp_tool",
    }  # fmt: skip
    for action in payload["actions"]:
        assert set(action) <= allowed
        for path in action.get("paths", []):
            assert set(path) == {"path", "access", "inside_project"}
    assert payload["task_intent"] == ["upload notes"]
    assert payload["taint_sources"] == ["WebFetch"]
    assert payload["tainted"] is True
    # never: the raw command line, the working directory, the session id
    assert "command_text" not in result.request.content
    assert WIN_PROJECT.lower().replace("\\", "/") not in result.request.content.lower()


def test_a_write_sends_the_path_never_the_content() -> None:
    body = "FILE CONTENT THAT MUST NOT LEAVE " * 20
    review = _review("Write", {"file_path": f"{WIN_PROJECT}\\notes.md", "content": body})
    result = _gate(review.actions, tool="Write")
    assert result.request is not None
    assert "FILE CONTENT" not in result.request.content
    assert "<project>/notes.md" in result.request.content


def test_an_edit_sends_neither_old_nor_new_text() -> None:
    review = _review(
        "Edit",
        {
            "file_path": f"{WIN_PROJECT}\\a.py",
            "old_string": "OLD_TEXT_X",
            "new_string": "NEW_TEXT_Y",
        },
    )
    result = _gate(review.actions, tool="Edit")
    assert result.request is not None
    assert "OLD_TEXT_X" not in result.request.content
    assert "NEW_TEXT_Y" not in result.request.content


def test_paths_and_words_show_the_project_and_the_home_relatively() -> None:
    review = _review(
        "PowerShell", {"command": f"Copy-Item {WIN_PROJECT}\\a.txt {WIN_HOME}\\Desktop\\a.txt"}
    )
    result = _gate(review.actions, tool="PowerShell")
    assert result.payload is not None
    (action,) = result.payload["actions"]
    shown = {p["path"] for p in action["paths"]}
    assert "<project>/a.txt" in shown
    assert "~/desktop/a.txt" in shown
    assert all("testuser" not in word.lower() for word in action["args"])


@pytest.mark.parametrize("name", sorted(SECRETS))
def test_secrets_in_a_command_never_leave_in_clear(name: str) -> None:
    secret = SECRETS[name]
    review = _review(
        "Bash", {"command": f"curl -H 'Authorization: {secret}' https://x.example.invalid"}
    )
    result = _gate(review.actions)
    assert result.request is not None
    for fragment in SECRET_FRAGMENTS:
        assert fragment not in result.request.content
    assert "[REDACTED]" in result.request.content


def test_secrets_in_assignments_and_the_intent_never_leave(tmp_path: Any) -> None:
    review = _review("PowerShell", {"command": "$env:MY_API_TOKEN = 'zz-very-secret-zz'; Get-Date"})
    facts = SessionFacts(
        known=True,
        tainted=False,
        read_untrusted=False,
        intents=("use password=hunter2hunter2 and " + SECRETS["openai"],),
    )
    result = _gate(review.actions, facts, tool="PowerShell")
    assert result.request is not None
    text = result.request.content
    assert "zz-very-secret-zz" not in text
    assert "hunter2hunter2" not in text
    assert "a1B2c3D4a1B2" not in text


def test_no_task_intent_is_sent_when_the_policy_says_so() -> None:
    review = _review("Bash", {"command": "make"})
    facts = SessionFacts(known=True, tainted=False, read_untrusted=False, intents=("MY TASK",))
    result = _gate(review.actions, facts, send_task_intent=False)
    assert result.payload is not None
    assert result.payload["task_intent"] is None
    assert result.request is not None
    assert "MY TASK" not in result.request.content


def test_the_intent_keeps_only_the_latest_n() -> None:
    review = _review("Bash", {"command": "make"})
    facts = SessionFacts(
        known=True, tainted=False, read_untrusted=False, intents=("a", "b", "c", "d")
    )
    result = _gate(review.actions, facts, intent_prompts=2)
    assert result.payload is not None
    assert result.payload["task_intent"] == ["c", "d"]


def test_too_many_commands_are_refused_not_cut() -> None:
    command = " ; ".join(f"echo {i}" for i in range(MAX_ACTIONS + 1))
    review = _review("Bash", {"command": command})
    result = _gate(review.actions)
    assert result.request is None
    assert result.refused
    assert "commands" in result.refused


def test_too_many_words_or_a_padded_word_is_refused() -> None:
    many = _review("Bash", {"command": "echo " + " ".join(["w"] * (MAX_WORDS + 1))})
    assert _gate(many.actions).request is None
    long_word = _review(
        "Bash", {"command": "echo " + "p" * (MAX_WORD_CHARS + 1) + " ; curl x.invalid"}
    )
    refused = _gate(long_word.actions)
    assert refused.request is None
    assert "longer than" in (refused.refused or "")


@pytest.mark.parametrize("char", ["\u202e", "\u200b", "\x1b", "\u2028", "\x00", "\ufeff"])
def test_a_control_or_format_character_is_refused(char: str) -> None:
    action = Action(tool="Bash", platform="posix", program="echo", args=(f"safe{char}text",))
    result = _gate((action,))
    assert result.request is None
    assert "control or format" in (result.refused or "")


def test_tabs_and_line_ends_are_fine() -> None:
    action = Action(
        tool="Bash", platform="posix", program="python", args=("-c", "a=1\n\tprint(a)\r\n")
    )
    assert _gate((action,)).request is not None


def test_chinese_words_and_paths_are_fine() -> None:
    review = _review("PowerShell", {"command": "Get-Content 'D:\\资料\\说明.txt'"})
    result = _gate(review.actions, tool="PowerShell")
    assert result.request is not None
    assert "说明.txt" in result.request.content


def test_an_oversized_request_is_refused() -> None:
    actions = tuple(
        Action(
            tool="Bash", platform="posix", program="echo", args=tuple("w" * 390 for _ in range(30))
        )
        for _ in range(3)
    )
    result = _gate(actions)
    assert result.request is None
    assert str(MAX_CONTENT_CHARS) in (result.refused or "")


def test_no_action_means_nothing_is_sent() -> None:
    assert _gate(()).request is None


def test_a_gated_request_cannot_be_built_around_the_gate() -> None:
    with pytest.raises(TypeError):
        GatedRequest(
            content="{}", system_prompt="x", prompt_hash="h", prompt_version="1", seal=object()
        )


def test_the_request_carries_the_versioned_fixed_prompt() -> None:
    review = _review("Bash", {"command": "make"})
    result = _gate(review.actions, tainted_facts())
    assert result.request is not None
    prompt = system_prompt()
    assert result.request.system_prompt == prompt.text
    assert result.request.prompt_hash == prompt.sha256
    assert prompt.sha256 in VERSIONS, (
        "audit_system.md changed: add its hash to audit.prompt.VERSIONS"
    )
    assert result.request.prompt_version == VERSIONS[prompt.sha256]


def test_the_system_prompt_holds_no_user_data() -> None:
    text = system_prompt().text
    assert "testuser" not in text
    assert "C:\\" not in text
    assert "sk-" not in text
    assert "\r" not in text
