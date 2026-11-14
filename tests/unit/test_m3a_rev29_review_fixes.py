"""Spec revision 30: the request to the LLM audit carries the whole command text of a shell call
(review of revision 29, docs/reviews/M3a-rev29-review.md, O-7 and R29-1).

O-7. A script can read its own text. Claude Code's PowerShell tool leaves the script in
``$__claudeCodeScript``; Bash has ``$BASH_EXECUTION_STRING`` and ``/proc/$$/cmdline``. So text that
is in no command (a comment, a constant that is only printed, the text of a condition, a switch
label) can become a path or code, and the request, which listed the commands only, did not show
it. Measured in this session's real tools: a path written only in a comment was read, code in a
comment ran through Invoke-Expression.

R29-1. A comparison in a condition that raises puts its text into $Error (an invalid -like
pattern, a -lt operand that does not convert, an invalid switch -Wildcard label). The text of a
condition is now in the request with the rest.

The command text is sent whole: the home directory as ``~``; longer than MAX_COMMAND_CHARS, with a
control or format character, or with anything the redactor would change, nothing is sent.

Nothing is run: the helper only parses, the model is a fake one.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from boundkeep import protocol
from boundkeep.audit import send_gate
from boundkeep.audit.auditor import Auditor
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.audit.prompt import VERSIONS, system_prompt
from boundkeep.normalize.model import Action
from boundkeep.session.facts import FRESH

from .test_m3a_pipeline import HOME, bash, decide, policy
from .test_m3a_ps_expression_output import _decide
from .test_m3a_x1_fixes import CANARY, WIN_HOME, assert_not_sent, audited

ERRMSG = "Get-Content (($Error[0].Exception.Message -split [char]34)[1])"
LIKE = "Get-Content (($Error[0].Exception.Message -split ': ', 2)[1].TrimEnd('['))"


def _sent(decision: Any, backend: FakeBackend) -> dict[str, Any]:
    assert backend.requests, decision.reason
    (request,) = backend.requests
    payload = json.loads(request.content)
    assert payload["schema"] == "boundkeep.audit-request/2"
    return payload


def _bash(command: str) -> dict[str, Any]:
    return _sent(*audited(bash(command)))


def _ps(command: str) -> dict[str, Any]:
    return _sent(*_decide(command, llm=True))


def _gate(*actions: Action, tool: str = "Bash") -> send_gate.GateResult:
    return send_gate.gate(
        actions, tool=tool, facts=FRESH, send_task_intent=False, intent_prompts=1, home=WIN_HOME
    )


def _shell(text: str, **fields: Any) -> Action:
    return Action(tool="Bash", platform="posix", program="make", command_text=text, **fields)


# --- the field ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "make release",
        "make release # tag it afterwards",
        "make release && make docs\nmake clean",
    ],
)
def test_a_bash_call_carries_its_whole_text(command: str) -> None:
    payload = _bash(command)
    assert payload["command"] == command
    assert list(payload)[:4] == ["schema", "task_intent", "tool", "command"]


@pytest.mark.parametrize(
    "command",
    [
        "make release",
        "make release # tag it afterwards",
        "make release; if ($LASTEXITCODE -ne 0) { make clean }",
    ],
)
def test_a_powershell_call_carries_its_whole_text(command: str) -> None:
    assert _ps(command)["command"] == command


def test_the_home_directory_is_written_as_a_tilde() -> None:
    payload = _ps(f"make release # see {WIN_HOME}\\notes.txt and {WIN_HOME.upper()}\\x")
    assert payload["command"] == "make release # see ~\\notes.txt and ~\\x"
    assert _bash(f"make release # see {HOME}/notes.txt")["command"] == (
        "make release # see ~/notes.txt"
    )


# --- O-7: the script reads its own text ----------------------------------------------------------

SELF_READ_PS = [
    "Get-Content ($__claudeCodeScript -split ('#' + 'BK '))[1].Split([char]10)[0].Trim()"
    f" #BK {CANARY}",
    "Invoke-Expression ($__claudeCodeScript -split ('#' + 'BK '))[1].Split([char]10)[0]"
    f" #BK {CANARY}",
    f"<#BK {CANARY} #> Get-Content ($__claudeCodeScript -split ('#' + 'BK '))[1].Split(' ')[0]",
    f"'{CANARY}'; Get-Content ($__claudeCodeScript -split [char]39)[1]",
    f"'Write-Output {CANARY}'; Invoke-Expression ($__claudeCodeScript -split [char]39)[1]",
    f"if ('{CANARY}' -like '*') {{ }}; Get-Content ($__claudeCodeScript -split [char]39)[1]",
    "Get-Content ((Get-Content variable:__claudeCodeScript) -split ('#' + 'BK '))[1]"
    f".Split([char]10)[0] #BK {CANARY}",
]
SELF_READ_BASH = [
    'cat "$(printf %s "$BASH_EXECUTION_STRING" | sed -n \'s/.*[#]BK \\([A-Z]*\\).*/\\1/p\')"'
    f" #BK {CANARY}",
    "cat \"$(tr '\\0' ' ' < /proc/$$/cmdline | sed -n 's/.*[#]BK \\([A-Z]*\\).*/\\1/p')\""
    f" #BK {CANARY}",
    'eval "$(printf %s "$BASH_EXECUTION_STRING" | sed -n \'s/.*[#]BK \\([A-Z]*\\).*/\\1/p\')"'
    f" #BK {CANARY}",
    f"cat \"$(set | sed -n 's/.*[#]BK \\([A-Z]*\\).*/\\1/p' | head -1)\" #BK {CANARY}",
]


@pytest.mark.parametrize("command", SELF_READ_PS)
def test_what_a_powershell_script_reads_of_itself_is_in_the_request(command: str) -> None:
    payload = _ps(command)
    assert CANARY in payload["command"]
    assert CANARY not in json.dumps(payload["actions"])  # the actions alone did not show it


@pytest.mark.parametrize("command", SELF_READ_BASH)
def test_what_a_bash_script_reads_of_itself_is_in_the_request(command: str) -> None:
    payload = _bash(command)
    assert CANARY in payload["command"]
    assert CANARY not in json.dumps(payload["actions"])


# --- R29-1: a comparison in a condition raises with its text ------------------------------------

RAISING = [
    f"if ('a' -like '{CANARY}[') {{ }}; {LIKE}",
    f"if ('a' -like '{CANARY}[') {{ }}; Invoke-Expression "
    "(($Error[0].Exception.Message -split ': ', 2)[1].TrimEnd('['))",
    f"if ('a' -notlike '{CANARY}[') {{ }}; {LIKE}",
    f"if ('a' -clike '{CANARY}[') {{ }}; {LIKE}",
    f"try {{ if ('a' -like '{CANARY}[') {{ }} }} catch "
    "{ Get-Content (($_.Exception.Message -split ': ', 2)[1].TrimEnd('[')) }",
    f"function f {{ if ('a' -like '{CANARY}[') {{ }}; {LIKE} }}; f",
    f"if (1 -lt '{CANARY}') {{ }}; {ERRMSG}",
    f"while (1 -gt '{CANARY}') {{ }}; {ERRMSG}",
    f"if ($false) {{ }} elseif (1 -ge '{CANARY}') {{ }}; {ERRMSG}",
    f"do {{ }} until (1 -le '{CANARY}'); {ERRMSG}",
    f"for (; 1 -clt '{CANARY}'; ) {{ }}; {ERRMSG}",
    f"switch -Wildcard ($env:OS) {{ '{CANARY}[' {{ }} }}; {LIKE}",
    f"switch -Regex ($env:OS) {{ '{CANARY}(' {{ }} }}; {ERRMSG}",
    f"switch -Wildcard ($PWD) {{ '{CANARY}[' {{ }} }}; {LIKE}",
]


@pytest.mark.parametrize("command", RAISING)
def test_the_text_of_a_condition_is_in_the_request(command: str) -> None:
    payload = _ps(command)
    assert CANARY in payload["command"]
    assert CANARY not in json.dumps(payload["actions"])


# --- what is refused ----------------------------------------------------------------------------


def test_a_command_text_over_the_limit_is_refused_not_cut() -> None:
    limit = send_gate.MAX_COMMAND_CHARS
    assert limit == 4000
    fits = "make " + "x" * (limit - 5)
    assert _gate(_shell(fits)).request is not None
    result = _gate(_shell(fits + "y"))
    assert result.request is None
    assert f"longer than {limit}" in (result.refused or "")


@pytest.mark.parametrize("char", ["\x00", "\x1b", "\u202e", "\u200b", "\u2028", "\ufeff", "\x7f"])
def test_a_control_or_format_character_in_the_text_is_refused(char: str) -> None:
    """Also where no word has it: in a comment, or where the parser left it out (``a<NUL>b`` reads
    as ``a b`` to the PowerShell parser)."""
    result = _gate(_shell(f"make release # note{char}here"))
    assert result.request is None
    assert "control or format" in (result.refused or "")


def test_tabs_and_line_ends_in_the_text_are_fine() -> None:
    assert _gate(_shell("make release\r\n\tmake docs\n")).request is not None


def test_a_nul_the_parser_drops_is_no_longer_sent() -> None:
    decision, backend = _decide("Write-Output a\x00b", llm=True)
    assert backend.requests == []
    assert decision.llm is not None
    assert decision.llm["outcome"] == "refused"
    assert decision.decision == protocol.DECISION_ASK


@pytest.mark.parametrize(
    "text",
    [
        "make release # token ghp_" + "Q" * 36,
        "make release # Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123",
        "make release # -----BEGIN RSA PRIVATE KEY-----\n# x\n# -----END RSA PRIVATE KEY-----",
        "make release; $env:MY_API_TOKEN = 'zz-very-secret-zz'",
    ],
)
def test_a_text_the_redactor_would_change_is_refused(text: str) -> None:
    """Redacting it would hide a span from the model (a key block swallows what is between its
    lines); a command that carries a secret is the user's to decide about."""
    result = _gate(_shell(text))
    assert result.request is None
    assert result.payload is None
    assert "looks like a secret" in (result.refused or "")


def test_a_redacted_word_refuses_the_call_even_where_the_text_reads_clean() -> None:
    """The text's own redaction need not find what a word's does: the word is in the text too."""
    action = _shell("make release", args=("ghp_" + "Q" * 36,))
    result = _gate(action)
    assert result.request is None
    assert "a command carries text that looks like a secret" in (result.refused or "")


def test_a_shell_call_without_its_text_is_refused() -> None:
    bare = Action(tool="Bash", platform="posix", program="make")
    result = _gate(bare)
    assert result.request is None
    assert "missing" in (result.refused or "")


def test_actions_that_disagree_on_the_text_are_refused() -> None:
    result = _gate(_shell("make a"), _shell("make b"))
    assert result.request is None
    assert "missing" in (result.refused or "")


def test_the_text_counts_as_shell_even_when_the_tool_name_is_lost() -> None:
    result = _gate(_shell("make release # x"), tool="?")
    assert result.payload is not None
    assert result.payload["command"] == "make release # x"


def test_other_tools_carry_no_command_text() -> None:
    action = Action(tool="Write", platform="windows", program=None)
    result = _gate(action, tool="Write")
    assert result.payload is not None
    assert "command" not in result.payload


# --- what stays the same ------------------------------------------------------------------------


@pytest.mark.parametrize("command", [SELF_READ_PS[0], RAISING[0]])
def test_without_a_backend_these_are_asked_as_before(command: str) -> None:
    decision, backend = _decide(command, llm=False)
    assert backend is None
    assert decision.decision == protocol.DECISION_ASK
    assert decision.decided_by == "gray"


@pytest.mark.parametrize(
    "command",
    [
        f"cat > notes.txt <<'EOF'\n{CANARY}\nEOF",
        f"python3 - <<'EOF'\nprint('{CANARY}')\nEOF",
        f"NODE_OPTIONS='--require ./{CANARY}.js' node app.js",
        f'for p in {CANARY}; do cat "$p"; done',
    ],
)
def test_what_the_request_could_not_show_is_still_not_sent(command: str) -> None:
    """Here-documents never leave the machine; the other not-sent cases are not relaxed (spec
    revision 30 leaves that for after a real backend has been evaluated)."""
    assert_not_sent(*audited(bash(command)))


def test_the_write_tool_still_sends_no_content() -> None:
    write = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "/tmp/x/notes.md", "content": f"{CANARY} body"},
        "cwd": "/home/testuser/proj",
        "session_id": "s",
    }
    decision, backend = audited(write)
    assert backend.requests, decision.reason  # it was sent: what it carried is what counts
    for request in backend.requests:
        assert CANARY not in request.content
        assert '"command"' not in request.content


# --- the cache and the prompt --------------------------------------------------------------------


def test_a_comment_makes_a_different_question_for_the_cache() -> None:
    pol = policy(llm=True)
    backend = FakeBackend.answering()
    auditor = Auditor(pol.llm_audit, backend)

    def ask(text: str) -> str:
        outcome = auditor.review(
            (_shell(text),), tool="Bash", facts=FRESH, sensitive_tags=(), home=None
        )
        return str(outcome.record["cache"])

    assert ask("make release # a") == "miss"
    assert ask("make release # b") == "miss"  # same actions, another text
    assert ask("make release # a") == "hit"
    assert len(backend.requests) == 2


def test_the_prompt_is_version_2_and_explains_the_text() -> None:
    prompt = system_prompt()
    assert VERSIONS[prompt.sha256] == "2"
    assert '"command"' in prompt.text
    assert "$__claudeCodeScript" in prompt.text
    assert "$BASH_EXECUTION_STRING" in prompt.text
    assert "obfuscated execution" in prompt.text
    assert "1" in VERSIONS.values()  # every text the prompt has had stays listed


def test_the_rules_layer_is_untouched() -> None:
    """The verdict without a backend does not depend on the text around the commands."""
    pol = policy()
    plain = decide(bash("make release"), pol)
    commented = decide(bash("make release # cat ~/.ssh/id_rsa"), pol)
    assert (plain.decision, plain.decided_by) == (commented.decision, commented.decided_by)
