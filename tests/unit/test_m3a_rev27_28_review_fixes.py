"""Spec revision 29: four findings of the review of revisions 27 and 28
(docs/reviews/M3a-rev27-28-review.md). Each left part of a call out of the request to the LLM
audit while the call was still sent.

O-6. The Bash parser stops part way: more than 32 levels of nesting, too many words or tokens, more
than 1 MiB, ``bash -c`` / ``eval`` more than 8 deep. What follows is in no command, so neither the
rules nor the request saw it: ``pytest -q; { { ... cat .env; }; ... }`` 40 levels deep was sent
with ``pytest -q`` alone (Git Bash runs it: measured). Now such a line counts as not seen whole.

R28-1 to R28-3. Three more places where PowerShell binds a value written on the line (revision 28
covered parameter defaults, foreach, switch, the head of a pipeline and function bodies):
- a class property's initial value: ``class C { static [string]$p = '<code>' }; Invoke-Expression
  ([C]::p)``;
- a thrown value: it goes into $Error, and into $_ of a catch or a trap: ``try { throw '<code>' }
  catch { Invoke-Expression $_.Exception.Message }``. The review suggested counting it only where
  the line catches it; a finally block and ``ErrorActionPreference`` set to SilentlyContinue reach
  it too (measured), so it always counts outside a function;
- the left side of -match outside command arguments: ``if ('<code>' -match '.*') {
  Invoke-Expression $Matches[0] }``.
Measured on PowerShell 5.1: all three read a made-up file and ran the code. A known value there is
recorded in ``unshown`` (``ps-bound-value:property|throw|match``); one that is not known is shown
as ``Write-Output``.

Nothing is run: the helper only parses, the model is a fake one.
"""

from __future__ import annotations

import shlex

import pytest

from boundkeep.daemon import pipeline
from boundkeep.normalize.bash import parse_bash

from .test_m3a_pipeline import bash, decide, policy
from .test_m3a_ps_expression_output import _actions, _decide, _reply, out
from .test_m3a_x1_fixes import CANARY, assert_not_sent, audited
from .test_norm_pscmd import S, build, cmd, rep

BOUND = "ps-bound-value"
STOPS = ("nesting-too-deep", "too-many-words", "too-many-tokens", "too-long", "depth-exceeded")


def _nested_bash(inner: str, levels: int) -> str:
    for _ in range(levels):
        inner = "bash -c " + shlex.quote(inner)
    return inner


# --- O-6: the Bash parser stopped part way -------------------------------------------------------

STOPPED = [
    ("pytest -q; " + "{ " * 40 + "cat .env; " + "}; " * 40, "nesting-too-deep"),
    ("pytest -q; " + "( " * 40 + "cat .env" + " )" * 40, "nesting-too-deep"),
    ("git status; " + "{ " * 33 + f"cat {CANARY}; " + "}; " * 33, "nesting-too-deep"),
    ("pytest -q; case x in " + "a|" * 20001 + "a) ;; esac; cat .env", "too-many-words"),
    ("pytest -q" + "\n" * 400_000 + "cat .env", "too-many-tokens"),
    ("pytest -q" + " " * (1 << 20) + "; cat .env", "too-long"),
    ("pytest -q; " + _nested_bash("cat .env", 9), "depth-exceeded"),
]
IDS = [reason + f"-{i}" for i, (_c, reason) in enumerate(STOPPED)]


@pytest.mark.parametrize(("command", "reason"), STOPPED, ids=IDS)
def test_the_parser_says_where_it_stopped(command: str, reason: str) -> None:
    assert reason in parse_bash(command, max_words=20000).gray


@pytest.mark.parametrize(("command", "reason"), STOPPED, ids=IDS)
def test_a_line_the_parser_did_not_finish_is_not_sent(command: str, reason: str) -> None:
    decision, backend = audited(bash(command))
    assert_not_sent(decision, backend)
    assert decision.llm["detail"] in STOPS


@pytest.mark.parametrize(("command", "reason"), STOPPED, ids=IDS)
def test_without_a_backend_it_is_asked_as_before(command: str, reason: str) -> None:
    """What follows the stop is in no command, so a deny there is not seen: the line is gray and
    asked, the same as before (a parse that fails degrades to ask)."""
    assert decide(bash(command), policy(llm=False)).verdict == "gray"


@pytest.mark.parametrize("reason", STOPS)
def test_each_reason_counts_as_not_seen_whole(reason: str) -> None:
    assert reason.startswith(pipeline._UNANALYSED_PREFIXES)


@pytest.mark.parametrize(
    "command",
    [
        "pytest -q; " + "{ " * 30 + "cat .env; " + "}; " * 30,
        "pytest -q; " + "( " * 30 + "cat .env" + " )" * 30,
        "pytest -q; " + _nested_bash("cat .env", 7),
    ],
)
def test_below_the_limits_the_parser_finishes_and_the_rule_denies(command: str) -> None:
    assert not set(STOPS) & set(parse_bash(command).gray)
    assert decide(bash(command), policy(llm=False)).verdict == "deny"


def test_an_ordinary_gray_line_is_still_sent() -> None:
    decision, backend = audited(bash(f"pytest -q {CANARY}"))
    assert len(backend.requests) == 1, decision.reason
    assert CANARY in backend.requests[0].content


@pytest.mark.parametrize(
    "reason",
    ["glob-too-many-matches", "brace-expansion-too-large", "path-too-deep", "ps-input-too-large"],
)
def test_other_reasons_with_too_in_them_are_not_caught_by_the_new_entries(reason: str) -> None:
    assert not reason.startswith(STOPS)


# --- R28-1 to R28-3: three more places where PowerShell binds a value ----------------------------

PS_BOUND_29 = [
    (f"class C {{ static [string]$p = '{CANARY}' }}; Invoke-Expression ([C]::p)", "property"),
    (f"class C {{ [string]$p = '{CANARY}' }}; Get-Content ([C]::new().p)", "property"),
    (f"class C {{ hidden static [string]$p = '~\\.ssh\\{CANARY}' }}; gc ([C]::p)", "property"),
    (f"try {{ throw '{CANARY}' }} catch {{ Invoke-Expression $_.Exception.Message }}", "throw"),
    (f"try {{ throw '{CANARY}' }} catch {{ Get-Content $_ }}", "throw"),
    (f"trap {{ Get-Content $_.Exception.Message; continue }} throw '{CANARY}'", "throw"),
    (f"try {{ throw '{CANARY}' }} catch {{}}; Get-Content $Error[0].Exception.Message", "throw"),
    (f"try {{ try {{ throw '{CANARY}' }} finally {{ }} }} catch {{ iex $_ }}", "throw"),
    (f"if ('{CANARY}' -match '.*') {{ Invoke-Expression $Matches[0] }}", "match"),
    (f"while ('{CANARY}' -match '.*') {{ Get-Content $Matches[0]; break }}", "match"),
    (f"if ($false) {{ }} elseif ('{CANARY}' -cmatch '.*') {{ iex $Matches[0] }}", "match"),
    (f"if (-not ('{CANARY}' -notmatch '.*')) {{ Invoke-Expression $Matches[0] }}", "match"),
    (f"do {{ }} while (-not ('{CANARY}' -imatch '.*')); Invoke-Expression $Matches[0]", "match"),
    (f"for (; '{CANARY}' -match '.*'; ) {{ Invoke-Expression $Matches[0]; break }}", "match"),
    (f"if ('~\\.ssh\\{CANARY}' -inotmatch 'x') {{ Get-Content $Matches[0] }}", "match"),
    (f"function f {{ if ('{CANARY}' -match '.*') {{ iex $Matches[0] }} }}; f", "match"),
    (f"'{CANARY}' -match '.*'; Get-Content $Matches[0]", "match"),
]


def _binds(command: str) -> list[str]:
    return [
        str(c.get("bind"))
        for c in _reply(command)["commands"]
        if c["name"]["kind"] == "output" and "bind" in c
    ]


def _unshown(command: str) -> set[str]:
    return {u for a in _actions(command) for u in a.unshown}


@pytest.mark.windows
@pytest.mark.parametrize(("command", "where"), PS_BOUND_29)
def test_the_helper_marks_the_new_places(command: str, where: str) -> None:
    assert where in _binds(command)


@pytest.mark.windows
@pytest.mark.parametrize(("command", "where"), PS_BOUND_29)
def test_the_line_records_them_as_unshown(command: str, where: str) -> None:
    assert f"{BOUND}:{where}" in _unshown(command)


@pytest.mark.windows
@pytest.mark.parametrize(("command", "where"), PS_BOUND_29)
def test_such_a_call_is_not_sent(command: str, where: str) -> None:
    decision, backend = _decide(command, llm=True)
    assert_not_sent(decision, backend)
    assert decision.llm["detail"].startswith(BOUND)


@pytest.mark.windows
@pytest.mark.parametrize(("command", "where"), PS_BOUND_29)
def test_without_a_backend_nothing_is_allowed(command: str, where: str) -> None:
    decision, _ = _decide(command, llm=False)
    assert decision.verdict in ("gray", "ask", "deny")


@pytest.mark.windows
def test_the_bound_entry_has_the_shape_of_a_default() -> None:
    entry = next(c for c in _reply("class C { static [string]$p = 'x' }")["commands"])
    shape = {"pos", "invoke", "name", "elements", "redirects", "stage", "nested", "bind"}
    assert set(entry) == shape
    assert entry["name"] == {"kind": "output", "v": ""}
    assert entry["stage"] == {"index": 0, "of": 1}
    assert entry["nested"] is True
    assert entry["bind"] == "property"
    assert len(entry["elements"]) == 1


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        "enum E { A = 1; B = 2 }; Get-Date",  # an enum member's value is a number
        "class C { [string]$p }; Get-Date",  # no initial value
        "class C { [int] M() { return 1 } }; Get-Date",
    ],
)
def test_enums_and_properties_without_a_value_are_not_marked(command: str) -> None:
    assert "property" not in _binds(command)
    assert f"{BOUND}:property" not in _unshown(command)


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        f"pytest; if (-not $?) {{ throw '{CANARY}' }}",
        f"Get-Date; throw '{CANARY}'",
        f"Get-Date; if ($LASTEXITCODE) {{ throw '{CANARY} failed' }}",
        f"try {{ throw '{CANARY}' }} finally {{ Invoke-Expression $Error[0].Exception.Message }}",
        f"Set-Variable ErrorActionPreference SilentlyContinue; throw '{CANARY}'; iex $Error[0]",
    ],
)
def test_a_throw_nobody_catches_is_bound_as_well(command: str) -> None:
    """The review suggested a throw counts only where the line catches it. Not enough: a finally
    block reads it from $Error, and after ErrorActionPreference is SilentlyContinue a throw does
    not end the script (both measured, PowerShell 5.1). Outside a function it always counts."""
    assert "throw" in _binds(command)
    decision, backend = _decide(command, llm=True)
    assert_not_sent(decision, backend)


@pytest.mark.windows
def test_a_return_is_still_printed() -> None:
    """Nothing of the line runs after a return, and no variable holds the value."""
    command = f"Get-Date; return '{CANARY}'"
    assert _binds(command) == []
    decision, backend = _decide(command, llm=True)
    assert len(backend.requests) == 1, decision.reason


@pytest.mark.windows
def test_a_throw_in_a_function_is_still_a_body() -> None:
    command = f"function f {{ throw '{CANARY}' }}; try {{ f }} catch {{ Invoke-Expression $_ }}"
    assert f"{BOUND}:body" in _unshown(command)
    assert f"{BOUND}:throw" not in _unshown(command)


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        f"Get-ChildItem | Where-Object {{ $_.Name -match '{CANARY}' }}",
        f"Get-ChildItem | ForEach-Object {{ if ($_ -match '{CANARY}') {{ $Matches[0] }} }}",
    ],
)
def test_match_in_a_command_s_arguments_is_not_marked(command: str) -> None:
    """In an argument the text is in that command's words."""
    assert "match" not in _binds(command)
    assert f"{BOUND}:match" not in _unshown(command)
    decision, backend = _decide(command, llm=True)
    assert len(backend.requests) == 1, decision.reason
    assert CANARY in backend.requests[0].content


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        f"if ('{CANARY}' -like '*x*') {{ Get-Date }}",
        f"if ('{CANARY}' -eq 'x') {{ Get-Date }}",
        f"if ('{CANARY}' -replace 'x', 'y') {{ Get-Date }}",
    ],
)
def test_operators_that_fill_no_matches_are_not_marked(command: str) -> None:
    """A condition binds nothing with these; its text is not in the request (revision 22 left
    that), and the line is sent as before."""
    assert "match" not in _binds(command)
    assert f"{BOUND}:match" not in _unshown(command)
    decision, backend = _decide(command, llm=True)
    if decision.verdict == "gray" and "ps-outside-command" not in str(decision.llm):
        assert len(backend.requests) == 1, decision.reason


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        f"if ($env:{CANARY} -match '.*') {{ Invoke-Expression $Matches[0] }}",
        f"class C {{ static [string]$p = $env:{CANARY} }}; Invoke-Expression ([C]::p)",
        f"try {{ throw $env:{CANARY} }} catch {{ Invoke-Expression $_ }}",
    ],
)
def test_a_value_that_is_not_known_is_shown_as_write_output(command: str) -> None:
    assert not any(u.startswith(BOUND) for u in _unshown(command))
    decision, backend = _decide(command, llm=True)
    assert len(backend.requests) == 1, decision.reason
    assert CANARY in backend.requests[0].content


@pytest.mark.windows
def test_the_left_side_that_only_wraps_commands_is_not_reported_again() -> None:
    """``(Get-Content README.md) -match 'x'``: the command is reported on its own."""
    command = "if ((Get-Content README.md) -match 'x') { Get-Date }"
    assert _binds(command) == []
    assert [c["name"].get("v") for c in _reply(command)["commands"]] == ["Get-Content", "Get-Date"]


@pytest.mark.windows
def test_a_rule_still_decides_first() -> None:
    decision, _ = _decide("if ('x' -match 'x') { Get-Content .env }", llm=True)
    assert decision.verdict == "deny"


@pytest.mark.parametrize("where", ["property", "throw", "match"])
def test_the_builder_records_the_new_places_like_the_old(where: str) -> None:
    res = build(rep({**out(S("x", "single")), "bind": where}, cmd("Get-Date")))
    assert res.unshown == (f"{BOUND}:{where}",)
    assert [[w.text for w in c.argv] for c in res.commands] == [["Get-Date"]]
    assert res.gray == ()
