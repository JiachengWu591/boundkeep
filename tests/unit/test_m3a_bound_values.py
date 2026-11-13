"""Spec revision 28: a value written on the command line and bound to a variable is in no command,
so the request to the LLM audit does not carry it (O-5, found while fixing the review of revisions
23 to 26; docs/reports/M3a-rev23-26-review-fixes.md).

PowerShell. Revisions 22 and 24 let a value that is known (a constant, ``$true`` / ``$false`` /
``$null``) make no ``Write-Output``: printing it shows nothing the line does not. But a parameter
default, the collection of a ``foreach``, the condition of a ``switch``, the head of a pipeline and
a statement in a function, filter, class method, script block expression or data section do not
print it: they bind it to a variable, or hand it to a caller. ``param($p = '~\\.ssh\\id_rsa')
Get-Content $p`` was sent with ``Get-Content $p`` in the request (the path written plainly is a
deny), ``param($x = '<code>') Invoke-Expression $x`` without the code.

Bash. The words of ``for NAME in WORDS`` and ``select NAME in WORDS`` are in no command either:
``for p in ~/.ssh/id_rsa; do cat "$p"; done`` was sent with ``cat $p``.

Now such a line carries ``ps-bound-value:<where>`` / ``for-words`` in ``Action.unshown``: no rule
looks at it, so no level changes, and a gray call with it is not sent. Assignments were not sent
already (revision 7).

Nothing is run: the helper only parses, the model is a fake one.
"""

from __future__ import annotations

import pytest

from boundkeep import protocol
from boundkeep.daemon import pipeline
from boundkeep.normalize import pscmd
from boundkeep.normalize.bash import parse_bash

from .test_m3a_pipeline import bash, decide, policy
from .test_m3a_ps_expression_output import _actions, _decide, _reply, out
from .test_m3a_x1_fixes import CANARY, assert_not_sent, audited
from .test_norm_pscmd import A, N, S, V, build, cmd, rep

BOUND = "ps-bound-value"


def _unshown(command: str) -> set[str]:
    return {u for a in _actions(command) for u in a.unshown}


def _binds(command: str) -> list[str]:
    return [
        str(c.get("bind"))
        for c in _reply(command)["commands"]
        if c["name"]["kind"] == "output" and "bind" in c
    ]


# --- PowerShell: where a known value is bound -----------------------------------------------------

PS_BOUND = [
    (f"param($p = '~\\.ssh\\{CANARY}') Get-Content $p", "default"),
    (f"param($x = '{CANARY}') Invoke-Expression $x", "default"),
    (f"function f($x = '{CANARY}') {{ Invoke-Expression $x }}; f", "default"),
    (f"function f {{ param($x = '{CANARY}') Invoke-Expression $x }}; f", "default"),
    (f"param($p = '{CANARY}.exe') & $p", "default"),
    (f"foreach ($c in '{CANARY}') {{ Invoke-Expression $c }}", "foreach"),
    (f"foreach ($p in '~\\.ssh\\{CANARY}', 'b') {{ Get-Content $p }}", "foreach"),
    (f"switch ('{CANARY}') {{ default {{ Invoke-Expression $_ }} }}", "switch"),
    (f"'{CANARY}' | ForEach-Object {{ Invoke-Expression $_ }}", "head"),
    (f"function f {{ '{CANARY}' }}; Invoke-Expression (f)", "body"),
    (f"function f {{ return '~\\.ssh\\{CANARY}' }}; Get-Content (f)", "body"),
    (f"filter g {{ '{CANARY}' }}; Invoke-Expression (Get-Date | g)", "body"),
    (f"data v {{ '{CANARY}' }}; Invoke-Expression $v", "body"),
    ("param($n = $true) Write-Output $n", "default"),
]


@pytest.mark.windows
@pytest.mark.parametrize(("command", "where"), PS_BOUND)
def test_the_helper_marks_where_a_value_is_bound(command: str, where: str) -> None:
    assert where in _binds(command)


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        "{ 'x' } | ForEach-Object { & $_ }",
        "class C { [string] M() { return 'x' } }",
        "function f { if ($true) { 'x' } }",
    ],
)
def test_what_a_script_block_or_a_method_outputs_goes_to_a_caller(command: str) -> None:
    assert "body" in _binds(command)


@pytest.mark.windows
def test_switch_file_binds_a_file_and_is_left_to_loose() -> None:
    """``switch -File path`` binds the file's lines, not a value of the line; revision 21 keeps
    it from being sent already, under its own reason."""
    command = f"switch -File {CANARY}.txt {{ default {{ Get-Date }} }}"
    assert _binds(command) == []
    decision, backend = _decide(command, llm=True)
    assert_not_sent(decision, backend)
    assert decision.llm["detail"].startswith(pscmd.OUTSIDE_COMMAND_GRAY)


@pytest.mark.windows
def test_a_line_with_no_command_records_it_as_well() -> None:
    assert f"{BOUND}:foreach" in _unshown("foreach ($c in 'x') { }")


@pytest.mark.windows
@pytest.mark.parametrize(("command", "where"), PS_BOUND)
def test_the_line_records_the_bound_value_as_unshown(command: str, where: str) -> None:
    assert f"{BOUND}:{where}" in _unshown(command)


@pytest.mark.windows
@pytest.mark.parametrize(("command", "where"), PS_BOUND)
def test_such_a_call_is_not_sent(command: str, where: str) -> None:
    decision, backend = _decide(command, llm=True)
    assert_not_sent(decision, backend)


@pytest.mark.windows
def test_the_reason_given_is_the_bound_value() -> None:
    actions = _actions(PS_BOUND[0][0])
    assert pipeline.incomplete_analysis(actions) is None
    assert pipeline.unshown_input(actions) == f"{BOUND}:default"


@pytest.mark.windows
@pytest.mark.parametrize(("command", "where"), PS_BOUND)
def test_without_a_backend_nothing_changes_level(command: str, where: str) -> None:
    decision, _ = _decide(command, llm=False)
    assert decision.verdict in ("gray", "ask", "deny")


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        "param($n = 5) Get-Date",
        "param($s = 'text', $f = $false, $z = $null) Get-Date",
        "param($code = $LASTEXITCODE) Get-Date",
    ],
)
def test_a_line_allowed_by_rule_stays_allowed(command: str) -> None:
    """``unshown`` is no rule's business: only a gray call is kept from being sent."""
    assert any(u.startswith(BOUND) for u in _unshown(command))
    decision, backend = _decide(command, llm=True)
    assert decision.verdict == "allow"
    assert backend.requests == []


PRINTED = [
    "Get-Date; 'done'",
    "'done'; Get-Date",
    "Get-Date; 'a', 'b'",
    "Get-Date; $true",
]


@pytest.mark.windows
@pytest.mark.parametrize("command", PRINTED)
def test_a_known_value_that_is_printed_is_not_marked(command: str) -> None:
    assert _binds(command) == []
    assert not any(u.startswith(BOUND) for u in _unshown(command))
    decision, _ = _decide(command, llm=False)
    assert decision.verdict == "allow"


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        f"Get-Date; return '{CANARY}'",
        f"Write-Output $env:A; '{CANARY}'",
        f"Get-Date; if ($true) {{ '{CANARY}' }}",
        f"Get-Date; try {{ '{CANARY}' }} catch {{ 'failed' }}",
    ],
)
def test_a_gray_line_that_prints_a_known_value_is_sent_as_before(command: str) -> None:
    decision, backend = _decide(command, llm=True)
    assert len(backend.requests) == 1, decision.reason


@pytest.mark.windows
@pytest.mark.parametrize(
    "command",
    [
        f"foreach ($c in $env:{CANARY}) {{ Invoke-Expression $c }}",
        f"param($x = $env:{CANARY}) Invoke-Expression $x",
        f"$env:{CANARY} | ForEach-Object {{ Invoke-Expression $_ }}",
    ],
)
def test_a_value_that_is_not_known_is_still_shown_as_write_output(command: str) -> None:
    assert not any(u.startswith(BOUND) for u in _unshown(command))
    decision, backend = _decide(command, llm=True)
    assert len(backend.requests) == 1, decision.reason
    assert CANARY in backend.requests[0].content


@pytest.mark.windows
def test_a_value_in_a_command_s_arguments_is_shown_and_not_marked() -> None:
    command = f"Get-Date | ForEach-Object {{ param($x = '{CANARY}') Invoke-Expression $x }}"
    assert not any(u.startswith(BOUND) for u in _unshown(command))
    decision, backend = _decide(command, llm=True)
    assert len(backend.requests) == 1, decision.reason
    assert CANARY in backend.requests[0].content


@pytest.mark.windows
def test_a_rule_still_decides_first() -> None:
    decision, _ = _decide("param($p = 'x') Get-Content .env; Get-Content $p", llm=True)
    assert decision.verdict == "deny"


def test_the_builder_records_a_known_bound_value_and_makes_no_command() -> None:
    for where in ("default", "foreach", "switch", "head", "body"):
        res = build(rep({**out(S("x", "single")), "bind": where}, cmd("Get-Date")))
        assert res.unshown == (f"{BOUND}:{where}",)
        assert [[w.text for w in c.argv] for c in res.commands] == [["Get-Date"]]
        assert res.gray == ()


def test_the_builder_records_each_place_once() -> None:
    entries = [{**out(e), "bind": "foreach"} for e in (S("a", "single"), N("1"), V("true"))]
    res = build(rep(*entries, {**out(A(S("b", "single"))), "bind": "head"}))
    assert res.unshown == (f"{BOUND}:foreach", f"{BOUND}:head")


def test_the_builder_shows_a_value_that_is_not_known_as_before() -> None:
    res = build(rep({**out(V("env:TOKEN")), "bind": "foreach"}))
    assert res.unshown == ()
    assert [[w.text for w in c.argv] for c in res.commands] == [["Write-Output", "$env:TOKEN"]]


def test_the_builder_does_not_mark_a_known_value_that_is_printed() -> None:
    res = build(rep(out(S("done", "single")), cmd("Get-Date")))
    assert res.unshown == ()


def test_a_bind_that_is_no_string_is_an_internal_error() -> None:
    res = build(rep({**out(S("x", "single")), "bind": 1}))
    assert "ps-internal-error" in res.gray


def test_the_name_of_the_place_is_kept_short() -> None:
    res = build(rep({**out(S("x", "single")), "bind": "w" * 500}))
    assert all(len(u) <= len(BOUND) + 1 + pscmd._MAX_TAG for u in res.unshown)


# --- Bash: the words of for and select ------------------------------------------------------------

FOR = [
    f'for p in ~/.ssh/{CANARY}; do cat "$p"; done',
    f"for c in '{CANARY}'; do eval \"$c\"; done",
    f'for c in {CANARY}; do "$c"; done',
    f'select c in {CANARY}; do eval "$c"; done',
    f'for f in a.py {CANARY}.py; do ruff check "$f"; done',
    'for f in *.py; do wc -l "$f"; done',
    f'for f in $(ls {CANARY}); do wc -l "$f"; done',
    f'git status; for p in ~/.ssh/{CANARY}\ndo cat "$p"\ndone',
]


@pytest.mark.parametrize("command", FOR)
def test_the_parser_records_the_words_of_for_and_select(command: str) -> None:
    assert parse_bash(command).unshown == ("for-words",)


@pytest.mark.parametrize("command", FOR)
def test_a_loop_over_words_is_not_sent(command: str) -> None:
    decision, backend = audited(bash(command))
    assert backend.requests == []
    if decision.verdict != "gray":
        return  # asked or denied by a rule first
    assert_not_sent(decision, backend)
    assert decision.llm["detail"] == "for-words"


@pytest.mark.parametrize("command", FOR)
def test_without_a_backend_a_loop_is_not_allowed_as_before(command: str) -> None:
    assert decide(bash(command), policy(llm=False)).verdict != "allow"


@pytest.mark.parametrize(
    "command",
    [
        'for x; do echo "$x"; done',
        "for ((i = 0; i < 3; i++)); do echo $i; done",
        "for x in; do echo x; done",
        'case "$1" in a) echo a;; esac',
        "while true; do break; done",
        "git status",
        "echo for in done",
    ],
)
def test_no_word_list_no_mark(command: str) -> None:
    assert parse_bash(command).unshown == ()


def test_the_command_substitution_in_the_words_is_still_a_command() -> None:
    result = parse_bash(f'for f in $(ls {CANARY}); do wc -l "$f"; done')
    assert [c.argv[0].text for c in result.commands] == ["ls", "wc"]


def test_without_the_mark_the_loop_would_be_sent() -> None:
    """The request holds the body's command, ``cat $p``, and nothing of the words."""
    decision = decide(bash(f'for p in ~/.ssh/{CANARY}; do cat "$p"; done'), policy(llm=False))
    assert decision.verdict == "gray"
    assert decision.decision == protocol.DECISION_ASK
