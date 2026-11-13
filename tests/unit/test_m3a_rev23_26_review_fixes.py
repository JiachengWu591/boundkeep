"""Spec revision 27: three findings of the review of revisions 23 to 26
(docs/reviews/M3a-rev23-26-review.md). Each left part of a call out of the request to the LLM
audit while the call was still sent.

O-4. The PowerShell helper reports a string over 32768 characters (a pipeline head over 4096) as
``TooLongString`` with its first 200 characters. Two hundred characters are under the send gate's
limit for a word, so the gate could not tell, and the call was sent: ``Invoke-Expression`` and
``Add-Type`` ran or compiled a tail nobody was shown (measured, PowerShell 5.1). Now such a line is
``ps-too-large``, never sent.

RV26-1. A long flag of a Bash wrapper written ``--name=value`` (``sudo --preserve-env=LIST``,
``xargs --replace=R``) lost its value with the wrapper and the call was sent without the mark of
revision 26. Now the value counts as a word the wrapper took: ``wrapper-option-value``.

RV24-1. The builder reads at most 64 entries of each of the helper's ``compound`` / ``dynamic`` /
``loose`` lists and dropped the rest without a mark. Out of reach today (the helper deduplicates
them, and PowerShell 5.1 has 64 concrete AST types in all), but a dropped
``AssignmentStatementAst`` would be a line sent; now a cut list makes the line ``ps-too-large``.

Nothing is run: the helper only parses, the model is a fake one.
"""

from __future__ import annotations

import pytest

from boundkeep import protocol
from boundkeep.daemon import pipeline
from boundkeep.normalize import pscmd
from boundkeep.normalize.bash import WRAPPER_OPTION_VALUE_GRAY, parse_bash

from .test_m3a_pipeline import bash, decide, policy
from .test_m3a_ps_expression_output import _actions, _decide, _reply
from .test_m3a_x1_fixes import CANARY, assert_not_sent, audited
from .test_norm_pscmd import RD, A, O, P, S, build, cmd, rep

TOO_LARGE = "ps-too-large"
CUT = "TooLongString"
PAD = "#" * 33000  # over the helper's MaxString (32768)
HEAD_PAD = "#" * 5000  # over its MaxHeadString (4096), under MaxString


def _grays(command: str) -> set[str]:
    return {r for a in _actions(command) for r in a.gray_reasons}


def _cut_elements(e: object) -> list[dict[str, object]]:
    """Every ``TooLongString`` element anywhere below ``e``."""
    if isinstance(e, dict):
        found = [e] if e.get("t") == "other" and e.get("ast") == CUT else []
        return found + [x for v in e.values() for x in _cut_elements(v)]
    if isinstance(e, list):
        return [x for v in e for x in _cut_elements(v)]
    return []


# --- O-4: a string the helper cut short -----------------------------------------------------------

LONG = [
    f"Invoke-Expression '{PAD}`n'{CANARY}''",
    f"iex '{PAD}`n'{CANARY}''",
    f"Add-Type -TypeDefinition '//{PAD}`npublic static class {CANARY} {{}}'",
    f"python -c '{PAD} {CANARY}'",
    f'Write-Output "{PAD} $x {CANARY}"',
    f"Get-Date; Write-Output -InputObject '{PAD}{CANARY}'",
    f"'{HEAD_PAD}{CANARY}' | Out-File x.txt",
    f"param($x = '{PAD}{CANARY}') Get-Date; $x",
    f"Get-Date > '{PAD}{CANARY}.txt'",
]


@pytest.mark.windows
@pytest.mark.parametrize("command", LONG, ids=range(len(LONG)))
def test_the_helper_sends_only_the_start_of_such_a_string(command: str) -> None:
    cut = _cut_elements(_reply(command))
    assert cut, "no TooLongString in the reply"
    assert all(len(str(e["text"])) == 200 for e in cut)
    assert all(CANARY not in str(e["text"]) for e in cut)


@pytest.mark.windows
@pytest.mark.parametrize("command", LONG, ids=range(len(LONG)))
def test_a_line_with_a_cut_string_is_not_seen_whole(command: str) -> None:
    actions = _actions(command)
    assert pipeline.incomplete_analysis(actions) == TOO_LARGE


@pytest.mark.windows
@pytest.mark.parametrize("command", LONG, ids=range(len(LONG)))
def test_a_line_with_a_cut_string_is_not_sent(command: str) -> None:
    decision, backend = _decide(command, llm=True)
    assert_not_sent(decision, backend)
    assert decision.verdict == "gray"


@pytest.mark.windows
@pytest.mark.parametrize("command", LONG, ids=range(len(LONG)))
def test_without_a_backend_the_level_is_the_same(command: str) -> None:
    decision, _ = _decide(command, llm=False)
    assert decision.verdict == "gray"
    assert decision.decision == protocol.DECISION_ASK


@pytest.mark.windows
def test_a_rule_still_decides_before_the_cut() -> None:
    decision, _ = _decide(f"Get-Content .env; Invoke-Expression '{PAD}'", llm=True)
    assert decision.verdict == "deny"


@pytest.mark.windows
@pytest.mark.parametrize(
    ("command", "cut"),
    [
        (f"Write-Output '{'#' * 32768}'", False),
        (f"Write-Output '{'#' * 32769}'", True),
        (f"'{'#' * 4096}' | Out-File x.txt", False),
        (f"'{'#' * 4097}' | Out-File x.txt", True),
    ],
    ids=["32768", "32769", "head-4096", "head-4097"],
)
def test_only_a_string_over_the_helper_s_limit_is_cut(command: str, cut: bool) -> None:
    assert bool(_cut_elements(_reply(command))) is cut
    assert (TOO_LARGE in _grays(command)) is cut


@pytest.mark.windows
def test_a_long_string_that_is_not_cut_is_refused_by_the_send_gate_as_before() -> None:
    """Over 400 characters and not cut: the whole word is there, and the gate refuses it."""
    decision, backend = _decide(f"Invoke-Expression '{'#' * 1000} {CANARY}'", llm=True)
    assert backend.requests == []
    assert TOO_LARGE not in _grays(f"Invoke-Expression '{'#' * 1000} {CANARY}'")
    assert decision.decision == protocol.DECISION_ASK


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        f"Invoke-Expression '{CANARY}'",
        f"Add-Type -TypeDefinition 'public static class {CANARY} {{}}'",
        f"python -c 'print(1) # {CANARY}'",
    ],
)
def test_a_short_string_is_sent_with_its_text_as_before(command: str) -> None:
    decision, backend = _decide(command, llm=True)
    assert len(backend.requests) == 1, decision.reason
    assert CANARY in backend.requests[0].content


def test_the_builder_marks_a_cut_string_wherever_it_is() -> None:
    cut = O(CUT, "#" * 200)
    for reply in (
        rep(cmd("Invoke-Expression", cut)),
        rep(cmd("Invoke-Expression", P("Command", cut))),
        rep(cmd("python", S("-c"), A(S("a"), cut))),
        rep(cmd("Get-Date", redirects=[RD(">", cut)])),
        rep({**cmd("", cut), "name": {"kind": "output", "v": ""}}),
    ):
        res = build(reply)
        assert TOO_LARGE in res.gray, reply
        assert f"ps-dynamic-value:{CUT}" in res.gray


def test_another_expression_the_helper_could_not_render_is_not_marked() -> None:
    res = build(rep(cmd("Write-Output", O("BinaryExpressionAst", "1 + 2"))))
    assert TOO_LARGE not in res.gray
    assert "ps-dynamic-value:BinaryExpressionAst" in res.gray


# --- RV24-1: the helper's lists of AST types ------------------------------------------------------


def _names(count: int) -> tuple[str, ...]:
    return tuple(f"Kind{i:02d}Ast" for i in range(count))


@pytest.mark.parametrize("key", ["compound", "dynamic", "loose"])
def test_a_list_of_64_types_is_read_whole(key: str) -> None:
    res = build(rep(cmd("Get-Date"), **{key: _names(pscmd.MAX_REASONS)}))
    assert TOO_LARGE not in res.gray
    assert len(res.gray) == pscmd.MAX_REASONS


@pytest.mark.parametrize("key", ["compound", "dynamic", "loose"])
def test_a_longer_list_is_cut_and_the_line_is_not_seen_whole(key: str) -> None:
    res = build(rep(cmd("Get-Date"), **{key: _names(pscmd.MAX_REASONS + 1)}))
    assert res.gray[0] == TOO_LARGE


def test_an_assignment_cut_off_the_list_still_keeps_the_line_from_being_sent() -> None:
    kinds = (*_names(pscmd.MAX_REASONS), "AssignmentStatementAst")
    res = build(rep(cmd("Get-Date"), compound=kinds))
    assert "ps-compound:AssignmentStatementAst" not in res.gray
    assert res.gray[0] == TOO_LARGE


# --- RV26-1: a long flag of a wrapper with a value ------------------------------------------------

EQ_TAKEN = [
    f"sudo --preserve-env={CANARY} pytest -q",
    f"env --ignore-environment={CANARY} pytest -q",
    f"setsid --wait={CANARY} pytest -q",
    f"time --verbose={CANARY} pytest -q",
    f"numactl --localalloc={CANARY} pytest -q",
    f"ionice --ignore={CANARY} pytest -q",
    f"nohup sudo --preserve-env={CANARY} pytest -q",
    f"find . -name '*.py' | xargs --replace={CANARY} wc -l",
    f"find . -name '*.py' | xargs --eof={CANARY} wc -l",
    f"find . -name '*.py' | xargs --max-lines=1 wc -l {CANARY}",
]


@pytest.mark.parametrize("command", EQ_TAKEN)
def test_the_value_of_a_long_flag_counts_as_taken(command: str) -> None:
    assert WRAPPER_OPTION_VALUE_GRAY in parse_bash(command).gray


@pytest.mark.parametrize("command", EQ_TAKEN)
def test_such_a_call_is_not_sent(command: str) -> None:
    decision, backend = audited(bash(command))
    assert backend.requests == []
    if "xargs" in command:  # asked by a rule (arguments-from-stdin) before any of this
        assert decision.verdict == "ask"
        return
    assert_not_sent(decision, backend)
    assert decision.llm["detail"] == WRAPPER_OPTION_VALUE_GRAY


@pytest.mark.parametrize(
    "command",
    [
        "sudo --preserve-env pytest -q",
        "env --ignore-environment pytest -q",
        "setsid --wait pytest -q",
        "time --verbose pytest -q",
        "find . -name '*.py' | xargs --null wc -l",
    ],
)
def test_the_same_flags_without_a_value_are_not_marked(command: str) -> None:
    assert WRAPPER_OPTION_VALUE_GRAY not in parse_bash(command).gray


def test_a_flag_without_a_value_is_sent_as_before() -> None:
    decision, backend = audited(bash("sudo --preserve-env pytest -q"))
    assert len(backend.requests) == 1, decision.reason


@pytest.mark.parametrize("command", EQ_TAKEN)
def test_without_a_backend_nothing_changes_level(command: str) -> None:
    decision = decide(bash(command), policy(llm=False))
    assert decision.verdict != "allow"
