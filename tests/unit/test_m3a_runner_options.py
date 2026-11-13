"""Spec revision 25: the options of a runner are in no action's words (finding O-2 of
docs/reviews/M3a-rev21-22-review.md).

``uv run``, ``uv tool run``, ``uvx``, ``pipx run`` and ``poetry run`` are peeled off and the command
they start is what gets judged. Their own options went with them: the request for ``uv run
--env-file .env pytest -q`` held ``pytest -q`` and the marker ``uv-run``, nothing of the file; the
one for ``uv run --index-url https://… pytest`` nothing of the host. Spec revision 21 kept a call
from being sent when such a value held a variable, in PowerShell only.

Now a call whose runner carries an option WITH A VALUE is not sent to the LLM audit, in both
dialects: gray ``runner-option-value`` (Bash) or ``ps-runner-value`` (PowerShell). Options without
a value (``--frozen``, ``-q``) say nothing the marker does not say, and such a call is sent as
before.

Nothing is run: the model is a fake one.
"""

from __future__ import annotations

import pytest

from boundkeep import protocol
from boundkeep.normalize import pscmd
from boundkeep.normalize.model import Word
from boundkeep.normalize.programs import peel_runner, peel_runner_options

from .test_m3a_pipeline import bash, decide, policy
from .test_m3a_ps_expression_output import _actions as ps_actions
from .test_m3a_ps_expression_output import _decide as ps_decide
from .test_m3a_x1_fixes import CANARY, assert_not_sent, audited


def w(*texts: str) -> list[Word]:
    return [Word(t) for t in texts]


# --- which runner calls carry an option with a value ----------------------------------------------

WITH_A_VALUE = [
    ["uv", "run", "--with", "x", "pytest"],
    ["uv", "run", "--with=x", "pytest"],
    ["uv", "run", "-p", "3.12", "pytest"],
    ["uv", "run", "--python", "3.12", "--frozen", "pytest"],
    ["uv", "run", "--frozen", "--env-file", ".env", "pytest"],
    ["uv", "run", "--env-file=.env", "pytest"],
    ["uv", "run", "--index-url", "https://example.com/simple", "pytest"],
    ["uv", "run", "--directory", "..", "pytest"],
    ["uv", "run", "--with", "x", "--", "pytest"],
    ["uv", "tool", "run", "--from", "pkg", "cowsay"],
    ["uvx", "--from", "pkg", "cowsay", "hi"],
    ["uvx", "--with", "x", "cowsay"],
    ["pipx", "run", "--spec", "pkg", "cowsay"],
    ["pipx", "run", "--index-url", "https://example.com/simple", "cowsay"],
    ["poetry", "run", "-C", "..", "pytest"],
    ["UV.EXE", "run", "--with", "x", "pytest"],
    # the interpreter as a launcher: its own -W / -X / -Q take a value
    ["python", "-W", "ignore", "-m", "boundkeep", "doctor"],
    ["python", "-u", "-X", "importtime", "-m", "boundkeep.cli", "doctor"],
    ["py", "-W", "error::x.Y", "-mboundkeep", "doctor"],
]

WITHOUT_A_VALUE = [
    ["uv", "run", "pytest"],
    ["uv", "run", "pytest", "--with", "x"],  # the inner command's own option
    ["uv", "run", "--frozen", "-q", "pytest"],
    ["uv", "run", "--no-project", "--isolated", "pytest", "-k", "x"],
    ["uv", "run", "--", "pytest"],
    ["uv", "tool", "run", "cowsay"],
    ["uvx", "cowsay", "hi"],
    ["pipx", "run", "cowsay"],
    ["pipx", "run", "--no-cache", "cowsay"],
    ["poetry", "run", "pytest"],
    ["poetry", "run", "-q", "pytest", "-x"],
    ["python", "-m", "boundkeep", "doctor"],
    ["python", "-u", "-B", "-m", "boundkeep", "doctor"],
    ["python", "-Xutf8", "-m", "boundkeep", "doctor"],
]


@pytest.mark.parametrize("argv", WITH_A_VALUE)
def test_an_option_with_a_value_is_reported(argv: list[str]) -> None:
    got = peel_runner_options(w(*argv))
    assert isinstance(got, tuple)
    assert got[3] is True
    assert got[:3] == peel_runner(w(*argv))


@pytest.mark.parametrize("argv", WITHOUT_A_VALUE)
def test_options_without_a_value_are_not(argv: list[str]) -> None:
    got = peel_runner_options(w(*argv))
    assert isinstance(got, tuple)
    assert got[3] is False
    assert got[:3] == peel_runner(w(*argv))


@pytest.mark.parametrize(
    "argv",
    [
        ["uv", "run"],
        ["uv", "pip", "install", "x"],
        ["ls", "-la"],
        [],
        ["uv", "run", "--weird", "x"],
        ["uvx", "--bogus", "x"],
    ],
)
def test_it_answers_what_peel_runner_answers_otherwise(argv: list[str]) -> None:
    assert peel_runner_options(w(*argv)) == peel_runner(w(*argv))


def test_a_value_that_expands_counts_like_any_other() -> None:
    argv = [Word("uv"), Word("run"), Word("--with"), Word("$PKG", expands=True), Word("pytest")]
    got = peel_runner_options(argv)
    assert isinstance(got, tuple)
    assert got == (4, "uv-run-remote", None, True)


# --- such a call is not sent, in both dialects ----------------------------------------------------

HIDDEN = [
    f"uv run --env-file {CANARY}.env pytest -q",
    f"uv run --env-file={CANARY}.env pytest -q",
    f"uv run --index-url https://{CANARY}.example.com/simple pytest -q",
    f"uv run --with {CANARY}-pkg pytest -q",
    f"uv run --with https://{CANARY}.example.com/x.whl pytest -q",
    f"uv run --frozen --python {CANARY} pytest",
    f"uv tool run --from {CANARY}-pkg cowsay hi",
    f"uvx --from {CANARY}-pkg cowsay hi",
    f"pipx run --spec {CANARY}-pkg cowsay hi",
    f"poetry run -C {CANARY} pytest",
]


@pytest.mark.parametrize("command", HIDDEN)
def test_bash_a_runner_with_a_valued_option_is_not_sent(command: str) -> None:
    decision, backend = audited(bash(command))
    assert decision.verdict == "gray"
    assert_not_sent(decision, backend)
    assert decision.llm["detail"].startswith("runner-option-value")


@pytest.mark.windows
@pytest.mark.parametrize("command", HIDDEN)
def test_powershell_a_runner_with_a_valued_option_is_not_sent(command: str) -> None:
    decision, backend = ps_decide(command, llm=True)
    assert decision.verdict == "gray"
    assert_not_sent(decision, backend)
    assert decision.llm["detail"].startswith(pscmd.RUNNER_VALUE_GRAY)


@pytest.mark.parametrize(
    "command",
    [
        f"uv run --with ${CANARY} pytest",
        f'uv run --with "${CANARY}" pytest',
        f"uv run --env-file $HOME/{CANARY} pytest",
        f"uvx --from $({CANARY}) cowsay",
    ],
)
def test_bash_a_value_with_a_variable_is_not_sent_either(command: str) -> None:
    """Revision 21 saw to this in PowerShell only."""
    decision, backend = audited(bash(command))
    assert decision.verdict == "gray"
    assert backend.requests == []
    assert decision.decision == protocol.DECISION_ASK


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        f"uv run --with $env:{CANARY} pytest",
        f"uv run --with ([IO.File]::ReadAllText('{CANARY}')) pytest",
    ],
)
def test_powershell_a_value_with_a_variable_is_not_sent_as_before(command: str) -> None:
    decision, backend = ps_decide(command, llm=True)
    assert_not_sent(decision, backend)


SHOWN = [
    "uv run pytest -q",
    "uv run --frozen pytest -q",
    "uv run -q --no-project pytest -q",
    "uv run -- pytest -q",
    "uvx cowsay hi",
    "pipx run cowsay hi",
    "poetry run pytest -q",
    f"uv run pytest --junitxml {CANARY}.xml",
]


@pytest.mark.parametrize("command", SHOWN)
def test_bash_a_runner_without_one_is_sent_as_before(command: str) -> None:
    decision, backend = audited(bash(command))
    assert len(backend.requests) == 1, decision.reason
    assert decision.decided_by == "llm"


@pytest.mark.windows
@pytest.mark.parametrize("command", SHOWN)
def test_powershell_a_runner_without_one_is_sent_as_before(command: str) -> None:
    decision, backend = ps_decide(command, llm=True)
    assert len(backend.requests) == 1, decision.reason
    assert decision.decided_by == "llm"


def test_the_inner_command_s_own_options_are_in_the_request() -> None:
    _decision, backend = audited(bash(f"uv run pytest --junitxml {CANARY}.xml"))
    assert CANARY in backend.requests[0].content


# --- the rule layer is what it was ----------------------------------------------------------------


@pytest.mark.parametrize("command", [*HIDDEN, *SHOWN])
def test_without_a_backend_every_one_of_them_is_asked_as_before(command: str) -> None:
    decision = decide(bash(command), policy(llm=False))
    assert decision.decision == protocol.DECISION_ASK


@pytest.mark.parametrize(
    "command",
    [
        "uv run --with x boundkeep mode audit-only",
        "uvx --from x boundkeep uninstall",
    ],
)
def test_a_deny_behind_a_runner_is_still_a_deny(command: str) -> None:
    decision, backend = audited(bash(command))
    assert decision.verdict == "deny"
    assert backend.requests == []


@pytest.mark.parametrize(
    "command",
    [
        "python -m boundkeep log",
        "python -u -m boundkeep log",
        f"python -W error::{CANARY}.Warn -m boundkeep log",
        f"python -X {CANARY} -m boundkeep.cli log",
    ],
)
def test_the_interpreter_as_a_launcher_only_starts_what_a_rule_decides(command: str) -> None:
    """Its value flags count as valued for the sake of one meaning; the verdict never hangs on
    it, because a rule asks about or denies boundkeep's own command line whatever starts it."""
    decision, backend = audited(bash(command))
    assert decision.verdict == "ask"
    assert decision.decided_by.startswith("rule:")
    assert backend.requests == []


@pytest.mark.windows
def test_powershell_the_inner_command_is_still_what_is_judged() -> None:
    actions = ps_actions("uv run --with x pytest -q")
    assert [a.program for a in actions if a.program] == ["pytest"]
    assert pscmd.RUNNER_VALUE_GRAY in {r for a in actions for r in a.gray_reasons}
