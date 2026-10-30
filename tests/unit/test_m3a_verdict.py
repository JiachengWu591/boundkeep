"""The code's ruling on a model verdict (PROJECT_SPEC.md §9.5), every combination as a table.

The table is written out by hand from the spec, not computed from the implementation: for each
(model verdict, deviates_from_task, risk) the outcome without taint and the outcome when the session
is tainted AND the call carries a sensitive tag (the only combination of the two bits that changes
anything). Together with the two other taint combinations that is all 3 x 2 x 4 x 2 x 2 = 96 cases;
every failure kind x on_failure x tainted x sensitive x (a model verdict present or not) comes on
top.
"""

from __future__ import annotations

import itertools

import pytest
from hypothesis import given
from hypothesis import strategies as st

from boundkeep.audit.backends.base import FAILURE_KINDS, ModelVerdict
from boundkeep.audit.verdict import FAILURES, rule_on

# (verdict, deviates, risk): (the final verdict when not tainted-and-sensitive, when it is)
TABLE: dict[tuple[str, bool, int], tuple[str, str]] = {
    ("allow", False, 0): ("allow", "ask"),
    ("allow", False, 1): ("allow", "ask"),
    ("allow", False, 2): ("ask", "ask"),
    ("allow", False, 3): ("deny", "deny"),
    ("allow", True, 0): ("ask", "ask"),
    ("allow", True, 1): ("ask", "ask"),
    ("allow", True, 2): ("ask", "ask"),
    ("allow", True, 3): ("deny", "deny"),
    ("ask", False, 0): ("ask", "ask"),
    ("ask", False, 1): ("ask", "ask"),
    ("ask", False, 2): ("ask", "ask"),
    ("ask", False, 3): ("deny", "deny"),
    ("ask", True, 0): ("ask", "ask"),
    ("ask", True, 1): ("ask", "ask"),
    ("ask", True, 2): ("ask", "ask"),
    ("ask", True, 3): ("deny", "deny"),
    ("deny", False, 0): ("deny", "deny"),
    ("deny", False, 1): ("deny", "deny"),
    ("deny", False, 2): ("deny", "deny"),
    ("deny", False, 3): ("deny", "deny"),
    ("deny", True, 0): ("deny", "deny"),
    ("deny", True, 1): ("deny", "deny"),
    ("deny", True, 2): ("deny", "deny"),
    ("deny", True, 3): ("deny", "deny"),
}

CASES = [
    (verdict, deviates, risk, tainted, sensitive)
    for (verdict, deviates, risk) in TABLE
    for tainted, sensitive in itertools.product((False, True), repeat=2)
]


def _model(verdict: str, deviates: bool, risk: int) -> ModelVerdict:
    return ModelVerdict(
        reasoning="r",
        deviates_from_task=deviates,
        risk=risk,
        verdict=verdict,  # type: ignore[arg-type]
        reason_for_user="u",
    )


def test_the_table_has_every_combination() -> None:
    assert len(TABLE) == 3 * 2 * 4
    assert len(CASES) == 96
    assert set(TABLE) == set(
        itertools.product(("allow", "ask", "deny"), (False, True), (0, 1, 2, 3))
    )


@pytest.mark.parametrize(("verdict", "deviates", "risk", "tainted", "sensitive"), CASES)
@pytest.mark.parametrize("on_failure", ["ask", "deny"])
def test_every_model_verdict_combination(
    verdict: str, deviates: bool, risk: int, tainted: bool, sensitive: bool, on_failure: str
) -> None:
    plain, tainted_sensitive = TABLE[(verdict, deviates, risk)]
    expected = tainted_sensitive if (tainted and sensitive) else plain
    ruling = rule_on(
        _model(verdict, deviates, risk),
        None,
        tainted=tainted,
        sensitive=sensitive,
        on_failure=on_failure,
    )
    assert ruling.final == expected  # on_failure plays no part when the call worked


@pytest.mark.parametrize("failure", FAILURES)
@pytest.mark.parametrize("on_failure", ["ask", "deny"])
@pytest.mark.parametrize(("tainted", "sensitive"), list(itertools.product((False, True), repeat=2)))
@pytest.mark.parametrize("with_model", [False, True])
def test_every_failure_ends_in_on_failure(
    failure: str, on_failure: str, tainted: bool, sensitive: bool, with_model: bool
) -> None:
    # a model verdict that would allow, handed in next to a failure, must not count
    model = _model("allow", False, 0) if with_model else None
    ruling = rule_on(
        model,
        failure,  # type: ignore[arg-type]
        tainted=tainted,
        sensitive=sensitive,
        on_failure=on_failure,
    )
    assert ruling.final == on_failure
    assert ruling.steps == (f"failure:{failure}",)


def test_the_failure_kinds_are_the_spec_ones_plus_the_gate_and_setup() -> None:
    assert set(FAILURE_KINDS) == {
        "timeout",
        "rate_limit",
        "http_5xx",
        "http_4xx",
        "invalid_output",
        "auth",
        "network",
    }
    assert set(FAILURES) == {*FAILURE_KINDS, "refused", "unavailable", "internal"}


def test_no_model_verdict_and_no_failure_is_still_a_failure() -> None:
    ruling = rule_on(None, None, tainted=False, sensitive=False, on_failure="deny")
    assert ruling.final == "deny"


@pytest.mark.parametrize("on_failure", ["allow", "", "yes", "ALLOW"])
def test_an_on_failure_that_is_not_deny_reads_as_ask_never_allow(on_failure: str) -> None:
    # the schema refuses on_failure: allow; the function stays total and safe anyway
    assert rule_on(
        None, "timeout", tainted=False, sensitive=False, on_failure=on_failure
    ).final == ("ask")


def test_the_steps_name_what_changed_the_outcome() -> None:
    assert rule_on(
        _model("allow", True, 3), None, tainted=True, sensitive=True, on_failure="ask"
    ).steps == ("deviates", "risk=3")
    assert rule_on(
        _model("allow", False, 0), None, tainted=True, sensitive=True, on_failure="ask"
    ).steps == ("tainted-sensitive",)
    assert (
        rule_on(
            _model("deny", False, 0), None, tainted=True, sensitive=True, on_failure="ask"
        ).steps
        == ()
    )


@given(
    verdict=st.sampled_from(["allow", "ask", "deny"]),
    deviates=st.booleans(),
    risk=st.sampled_from([0, 1, 2, 3]),
    tainted=st.booleans(),
    sensitive=st.booleans(),
)
def test_properties_of_the_ruling(
    verdict: str, deviates: bool, risk: int, tainted: bool, sensitive: bool
) -> None:
    final = rule_on(
        _model(verdict, deviates, risk),
        None,
        tainted=tainted,
        sensitive=sensitive,
        on_failure="ask",
    ).final
    order = {"allow": 0, "ask": 1, "deny": 2}
    assert order[final] >= order[verdict]  # the code never loosens the model
    if final == "allow":
        assert verdict == "allow"
        assert not deviates
        assert risk <= 1
        assert not (tainted and sensitive)
    assert (final == "deny") == (verdict == "deny" or risk == 3)
