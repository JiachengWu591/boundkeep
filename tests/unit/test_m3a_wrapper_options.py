"""Spec revision 26: the words a Bash wrapper takes are in no action's words (W-1, found while
fixing O-2; docs/reports/M3a-runner-options.md).

``sudo``, ``env``, ``time``, ``nice``, ``timeout``, ``xargs`` and the other wrappers of the Bash
dialect are peeled off and the command they start is what gets judged. What they took went with
them: the request for ``sudo -u <user> pytest -q`` held ``pytest -q`` and the marker ``sudo``,
nothing of the user; the one for ``env -C <dir> pytest -q`` nothing of the directory.

Now a call whose wrapper took a word that is no flag (an option's value, ``nice -5``, the operand of
``timeout 60`` or ``gosu user``) is not sent to the LLM audit: gray ``wrapper-option-value``. A
wrapper with flags only is sent as before; so is ``env -S``, whose value is parsed again as
commands, and a wrapper with no command after it, which is not peeled.

Nothing is run: the model is a fake one.
"""

from __future__ import annotations

import pytest

from boundkeep import protocol
from boundkeep.normalize.bash import WRAPPER_OPTION_VALUE_GRAY, parse_bash

from .test_m3a_pipeline import bash, decide, policy
from .test_m3a_x1_fixes import CANARY, assert_not_sent, audited

TAKEN = [
    f"sudo -u {CANARY} pytest -q",
    f"sudo -u{CANARY} pytest -q",
    f"sudo --user {CANARY} pytest -q",
    f"sudo --user={CANARY} pytest -q",
    f"sudo -n -u {CANARY} pytest -q",
    f"sudo -nu {CANARY} pytest -q",
    f"sudo -g {CANARY} pytest -q",
    f"sudo -D {CANARY} pytest -q",
    f"sudo -- -u {CANARY}",  # not peeled as an option: "-u" is the command
    f"doas -u {CANARY} pytest -q",
    f"env -C {CANARY} pytest -q",
    f"env --chdir={CANARY} pytest -q",
    f"env -u {CANARY} pytest -q",
    f"env -i -C {CANARY} pytest -q",
    f"time -o {CANARY}.txt pytest -q",
    f"time -f {CANARY} pytest -q",
    f"exec -a {CANARY} pytest -q",
    f"nice -n 10 pytest -q {CANARY}",
    "nice -5 pytest -q",
    "nice --adjustment=5 pytest -q",
    f"ionice -c 3 pytest -q {CANARY}",
    f"timeout 60 pytest -q {CANARY}",
    f"timeout -s KILL 60 pytest -q {CANARY}",
    f"timeout --signal=KILL 60 pytest -q {CANARY}",
    f"stdbuf -oL pytest -q {CANARY}",
    f"wsl -d {CANARY} -e pytest -q",
    f"sshpass -p {CANARY} ssh host true",
    f"gosu {CANARY} pytest -q",
    f"su-exec {CANARY} pytest -q",
    f"ssh-agent -a {CANARY}.sock pytest -q",
    f"tini -p SIGTERM pytest -q {CANARY}",
    f"numactl --membind=0 pytest -q {CANARY}",
    f"find . -name '*.py' | xargs -n 1 wc -l {CANARY}",
    f"find . -name '*.py' | xargs -a {CANARY}.txt wc -l",
    f"find . -name '*.py' | xargs -I {{}} wc -l {{}} {CANARY}",
    f"find . -name '*.py' | xargs -i{{}} wc -l {{}} {CANARY}",
    f"find . -name '*.py' | xargs -d , wc -l {CANARY}",
    f"sudo -u {CANARY} nice -n 5 pytest -q",
    f"nohup sudo -u {CANARY} pytest -q",
    f"git status; sudo -u {CANARY} pytest -q",
]


def _grays(command: str) -> set[str]:
    return set(parse_bash(command).gray)


@pytest.mark.parametrize("command", [c for c in TAKEN if "-- -u" not in c])
def test_the_parser_marks_a_wrapper_that_took_a_value(command: str) -> None:
    assert WRAPPER_OPTION_VALUE_GRAY in _grays(command)


@pytest.mark.parametrize("command", [c for c in TAKEN if "-- -u" not in c])
def test_such_a_call_is_not_sent(command: str) -> None:
    """xargs and ``sshpass ... ssh`` are asked by a rule before any of this."""
    decision, backend = audited(bash(command))
    assert backend.requests == []
    if "xargs" in command or "ssh host" in command:
        assert decision.verdict == "ask"
        return
    assert decision.verdict == "gray"
    assert_not_sent(decision, backend)
    assert decision.llm["detail"] == WRAPPER_OPTION_VALUE_GRAY


def test_after_double_dash_the_words_are_the_command() -> None:
    """``sudo -- -u x`` runs a program called ``-u``: nothing was taken, everything is shown."""
    assert WRAPPER_OPTION_VALUE_GRAY not in _grays(f"sudo -- -u {CANARY}")


FLAGS_ONLY = [
    "sudo -n pytest -q",
    "sudo -E -H pytest -q",
    "sudo -- pytest -q",
    "doas -n pytest -q",
    "env -i pytest -q",
    "env - pytest -q",
    "nohup pytest -q",
    "time pytest -q",
    "time -p pytest -q",
    "command pytest -q",
    "exec pytest -q",
    "nice pytest -q",
    "setsid -w pytest -q",
    "timeout --foreground -v",  # no operand left, nothing peeled
    "stdbuf pytest -q",
    "chronic -e pytest -q",
    "find . -name '*.py' | xargs wc -l",
    "find . -name '*.py' -print0 | xargs -0 -r wc -l",
    "find . -name '*.py' | xargs -i wc -l",
    f"sudo -n pytest --junitxml {CANARY}.xml",  # the inner command's own option
]


@pytest.mark.parametrize("command", FLAGS_ONLY)
def test_a_wrapper_with_flags_only_is_not_marked(command: str) -> None:
    assert WRAPPER_OPTION_VALUE_GRAY not in _grays(command)


@pytest.mark.parametrize("command", FLAGS_ONLY)
def test_a_wrapper_with_flags_only_is_sent_as_before(command: str) -> None:
    decision, backend = audited(bash(command))
    if "xargs" in command:  # asked by a rule
        assert decision.verdict == "ask"
        return
    assert len(backend.requests) == 1, decision.reason
    assert decision.decided_by == "llm"


def test_the_inner_command_s_own_option_is_in_the_request() -> None:
    _decision, backend = audited(bash(f"sudo -n pytest --junitxml {CANARY}.xml"))
    assert CANARY in backend.requests[0].content


@pytest.mark.parametrize(
    "command",
    [
        f"timeout {CANARY}",
        f"sudo -u {CANARY}",
        f"nice -n {CANARY}",
        f"env -C {CANARY}",
    ],
)
def test_a_wrapper_with_nothing_to_run_is_not_peeled_and_not_marked(command: str) -> None:
    """Its words are the command's own words, all of them in the request."""
    assert WRAPPER_OPTION_VALUE_GRAY not in _grays(command)


def test_env_split_string_alone_is_shown_as_commands() -> None:
    grays = _grays("env -S 'pytest -q'")
    assert WRAPPER_OPTION_VALUE_GRAY not in grays
    assert "exec:env-split-string" in grays


@pytest.mark.parametrize(
    "command",
    [
        f"env -C {CANARY} -S 'pytest -q'",
        f"env --chdir {CANARY} --split-string 'pytest -q'",
        f"env -u {CANARY} -S ''",
        f"env -C {CANARY} -S 'pytest -q' tests",  # words after the value: env joins them to it
    ],
)
def test_with_env_split_string_the_env_command_is_kept_whole(command: str) -> None:
    """``env -S`` is not peeled: the env command is one of the commands, with all its words, so
    what it took is in the request."""
    result = parse_bash(command)
    assert WRAPPER_OPTION_VALUE_GRAY not in result.gray
    assert any(
        c.argv[0].text == "env" and CANARY in [w.text for w in c.argv] for c in result.commands
    )
    decision, backend = audited(bash(command))
    assert len(backend.requests) == 1, decision.reason
    assert CANARY in backend.requests[0].content


def test_an_assignment_is_not_sent_as_before_and_is_no_value_of_this_kind() -> None:
    assert WRAPPER_OPTION_VALUE_GRAY not in _grays(f"env A={CANARY} pytest -q")
    decision, backend = audited(bash(f"env A={CANARY} pytest -q"))
    assert_not_sent(decision, backend)


@pytest.mark.parametrize("command", [*TAKEN, *FLAGS_ONLY])
def test_without_a_backend_nothing_changes_level(command: str) -> None:
    """No allow rule takes a wrapped action; without a backend every one of these is asked or
    denied by a rule, as before."""
    decision = decide(bash(command), policy(llm=False))
    assert decision.verdict != "allow"
    assert decision.decision in (protocol.DECISION_ASK, protocol.DECISION_DENY)


@pytest.mark.parametrize(
    "command",
    [
        "sudo -u root boundkeep mode audit-only",
        "timeout 60 boundkeep uninstall",
        f"env -C {CANARY} cat .env",
    ],
)
def test_a_deny_behind_a_wrapper_is_still_a_deny(command: str) -> None:
    decision, backend = audited(bash(command))
    assert decision.verdict == "deny"
    assert backend.requests == []


def test_the_inner_command_is_still_what_is_judged() -> None:
    cmd = parse_bash(f"sudo -u {CANARY} pytest -q").commands[0]
    assert [w.text for w in cmd.argv] == ["pytest", "-q"]
    assert cmd.wrappers == ("sudo",)


def test_powershell_does_not_peel_these_names() -> None:
    """There ``sudo`` and ``env`` are programs: their arguments are in the request."""
    from .test_m3a_ps_expression_output import _actions

    actions = _actions(f"env -C {CANARY} pytest -q")
    assert actions[0].program == "env"
    assert WRAPPER_OPTION_VALUE_GRAY not in {r for a in actions for r in a.gray_reasons}
