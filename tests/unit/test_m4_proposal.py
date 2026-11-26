"""M4 (PROJECT_SPEC.md §8.1): reading a policy proposal, and the prompt / send gate it uses."""

from __future__ import annotations

import json

import pytest

from boundkeep.audit import send_gate
from boundkeep.compiler import prompt, proposal
from boundkeep.compiler.proposal import POLICY_KEYS, ProposalError, parse_proposal_text

GOOD = """proposal: 1
summary: deny curl to unknown hosts
rules:
  - id: deny-curl
    tool: [Bash]
    match: { program: curl }
    action: deny
    reason: "no curl"
tests:
  - { tool: Bash, input: { command: "curl https://x.example" }, expect: deny }
"""


def _err(text: str) -> ProposalError:
    with pytest.raises(ProposalError) as caught:
        parse_proposal_text(text)
    return caught.value


def test_a_good_proposal_reads_with_its_rules_and_tests_as_written() -> None:
    got = parse_proposal_text(GOOD)
    assert got.rule_ids == ("deny-curl",)
    assert got.rules[0]["match"] == {"program": "curl"}
    assert got.tests[0]["expect"] == "deny"
    assert got.summary == "deny curl to unknown hosts"
    assert got.impact is None


@pytest.mark.parametrize("key", sorted(POLICY_KEYS))
def test_a_policy_key_is_refused_with_where_to_change_it(key: str) -> None:
    value = "{}" if key in ("defaults", "llm_audit", "taint") else "x"
    error = _err(GOOD + f"{key}: {value}\n")
    assert error.code == "parse"
    assert f"'{key}' is not one of them" in str(error)
    assert error.line is not None


def test_emit_allow_cannot_ride_along() -> None:
    error = _err(GOOD + "defaults:\n  emit_allow: true\n")
    assert "only add rules and tests" in str(error)


def test_an_unknown_top_level_key_is_refused() -> None:
    assert "unknown key 'override'" in str(_err(GOOD + "override: true\n"))


@pytest.mark.parametrize(
    "head", ["", "proposal: 2\n", "proposal: true\n", "proposal: '1'\n", "proposal: 1.0\n"]
)
def test_the_format_version_must_be_the_integer_1(head: str) -> None:
    body = GOOD.replace("proposal: 1\n", head)
    assert "proposal: 1" in str(_err(body))


def test_no_rules_with_a_summary_reports_what_the_proposer_said() -> None:
    error = _err('proposal: 1\nsummary: "cannot: that would \\e[2J loosen deny"\nrules: []\n')
    assert "the proposer says: cannot: that would ?[2J loosen deny" in str(error)
    assert "\x1b" not in str(error)


def test_no_rules_at_all_is_refused() -> None:
    assert "at least one new rule" in str(_err("proposal: 1\nrules: []\n"))


def test_too_many_rules_or_tests_are_refused() -> None:
    rule = {"id": "r", "match": {"program": "git"}, "action": "deny", "reason": "x"}
    rules = [rule | {"id": f"r{i}"} for i in range(proposal.MAX_RULES + 1)]
    assert "at most" in str(_err(json.dumps({"proposal": 1, "rules": rules})))
    test = {"tool": "Bash", "input": {"command": "git"}, "expect": "deny"}
    many = {"proposal": 1, "rules": [rule], "tests": [test] * (proposal.MAX_TESTS + 1)}
    assert "at most" in str(_err(json.dumps(many)))


@pytest.mark.parametrize(
    "text",
    [
        GOOD + "summary: again\n",  # duplicate key
        GOOD.replace("tool: [Bash]", "tool: &t [Bash]") + "x: *t\n",  # anchor
        GOOD.replace("action: deny", "action: !!str deny"),  # tag
        "proposal: 1\n" + "rules:\n" + "  - " * 70 + "x\n",  # deep
    ],
)
def test_the_strict_yaml_rules_of_the_policy_file_apply(text: str) -> None:
    assert _err(text).code == "parse"


def test_a_secret_is_refused_in_a_test_input_too() -> None:
    body = GOOD.replace(
        'curl https://x.example"', 'curl -H \\"Authorization: Bearer abcdefghijklmnopqrstuvwx\\""'
    )
    error = _err(body)
    assert error.code == "secret"
    assert "tests[0].input.command" in str(error)
    assert "abcdefghij" not in str(error)


def test_a_secret_in_a_reason_is_refused() -> None:
    error = _err(GOOD.replace('"no curl"', '"token ghp_abcdefghijklmnopqrstuvwxyz0123456789"'))
    assert error.code == "secret"


def test_an_invalid_rule_is_reported_by_field_and_line() -> None:
    error = _err(GOOD.replace("program: curl", "program: curl, command_regex: x"))
    assert "unknown key 'rules[0].match.command_regex'" in str(error)
    assert error.line == 6


def test_a_pasted_answer_with_one_yaml_block_is_read() -> None:
    pasted = f"Here you go:\n\n```yaml\n{GOOD}```\n\nLet me know!"
    assert parse_proposal_text(pasted).rule_ids == ("deny-curl",)


def test_two_yaml_blocks_or_another_fence_are_refused() -> None:
    assert "more than one" in str(_err(f"```yaml\n{GOOD}```\n```yaml\n{GOOD}```\n"))
    assert "no ```yaml block" in str(_err(f"```json\n{{}}\n```\n{GOOD}"))


def test_an_oversized_proposal_is_refused_before_reading() -> None:
    assert "longer than" in str(_err(GOOD + "#" * proposal.MAX_PROPOSAL_CHARS))


def test_json_from_a_backend_becomes_the_same_yaml() -> None:
    data = parse_proposal_text(GOOD)
    obj = {"tests": list(data.tests), "rules": list(data.rules), "proposal": 1, "summary": "s"}
    text = proposal.text_from_json(obj)
    assert text.startswith("proposal: 1\nsummary: s\nrules:")
    again = parse_proposal_text(text)
    assert again.rules == data.rules
    assert again.tests == data.tests
    with pytest.raises(ProposalError):
        proposal.text_from_json(["not", "an", "object"])


# --------------------------------------------------------------------------- prompt and gate


def test_the_prompt_carries_both_schemas_and_its_example_is_a_valid_proposal() -> None:
    system = prompt.system_prompt()
    assert "{{" not in system.text
    assert '"path_glob"' in system.text
    assert '"expect"' in system.text
    example = system.text[system.text.index("proposal: 1\nsummary: Deny") :]
    assert parse_proposal_text(example).rule_ids == ("deny-kube-config",)
    assert len(system.sha256) == 64
    assert system.version == prompt.PROMPT_VERSION


_SUBCOMMAND_SENTENCE = "Only these programs report a subcommand: "


def _listed_subcommand_programs() -> tuple[list[str], list[str]]:
    text = prompt.system_prompt().text
    start = text.index(_SUBCOMMAND_SENTENCE) + len(_SUBCOMMAND_SENTENCE)
    sentence = text[start : text.index(". For any other program", start)]
    sentence = sentence.split(" (in PowerShell", 1)[0]
    bash_part, ps_part = sentence.split(", and in PowerShell also ")
    return [p.strip() for p in bash_part.split(",")], [p.strip() for p in ps_part.split(",")]


def test_the_programs_the_prompt_lists_do_report_a_subcommand() -> None:
    from boundkeep import policycli
    from boundkeep.policy import parse_policy_text

    policy = parse_policy_text("version: 1\n", home="/home/testuser")
    bash, _ = _listed_subcommand_programs()
    verbs = {"systemctl": "restart", "launchctl": "load", "openssl": "genrsa", "go": "build"}
    for program in bash:
        verb = verbs.get(program, "install" if program not in ("git", "gh", "docker") else "status")
        if program in ("gh",):
            verb = "issue"
        review = policycli._run_one(
            policy, "posix", "Bash", {"command": f"{program} {verb} x"}, None, None
        )
        assert any(a.subcommand == verb for a in review.actions), program
    review = policycli._run_one(policy, "posix", "Bash", {"command": "terraform apply"}, None, None)
    assert all(a.subcommand is None for a in review.actions)


@pytest.mark.windows
def test_the_powershell_tools_the_prompt_lists_report_a_subcommand() -> None:
    from boundkeep import policycli
    from boundkeep.evalkit.runner import ps_helper_ready
    from boundkeep.policy import parse_policy_text

    if not ps_helper_ready():
        pytest.skip("the PowerShell parser helper did not start")
    policy = parse_policy_text("version: 1\n", home="C:\\Users\\testuser")
    _, tools = _listed_subcommand_programs()
    for tool in tools:
        review = policycli._run_one(
            policy, "windows", "PowerShell", {"command": f"{tool}.exe query x"}, None, None
        )
        assert any(a.subcommand == "query" for a in review.actions), tool


def test_the_gate_sends_only_the_sentence_and_the_rule_ids() -> None:
    result = send_gate.gate_policy_request(
        "deny reading C:\\Users\\alice\\vault\\*",
        ["no-secret-read", "git-x"],
        home="C:\\Users\\alice",
    )
    assert result.request is not None
    assert result.payload is not None
    assert result.request.purpose == "policy"
    content = json.loads(result.request.content)
    assert set(content) == {"schema", "request", "existing_rule_ids"}
    assert content["request"] == "deny reading ~\\vault\\*"
    assert content["existing_rule_ids"] == ["no-secret-read", "git-x"]
    assert result.request.system_prompt == prompt.system_prompt().text
    assert "alice" not in result.request.content


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("allow curl with token ghp_abcdefghijklmnopqrstuvwxyz0123456789", "looks like a secret"),
        ("x" * (send_gate.MAX_POLICY_REQUEST_CHARS + 1), "longer than"),
        ("deny rm \x1b[2J", "control or format"),
        ("deny rm \u202e", "control or format"),
        ("   ", "empty"),
    ],
)
def test_the_gate_refuses_what_must_not_leave(text: str, why: str) -> None:
    result = send_gate.gate_policy_request(text, [], home=None)
    assert result.request is None
    assert why in (result.refused or "")


def test_the_gate_refuses_a_secret_environment_value_and_odd_rule_ids() -> None:
    secret = "s3cr3t-value-of-a-token"
    refused = send_gate.gate_policy_request(f"deny {secret}", [], home=None, secrets=[secret])
    assert refused.request is None
    odd = send_gate.gate_policy_request("deny rm", ["ok", "Not An Id"], home=None)
    assert odd.request is None


def test_an_audit_request_cannot_be_used_for_a_proposal_and_back() -> None:
    from boundkeep.audit.backends.base import check_purpose

    policy = send_gate.gate_policy_request("deny rm", [], home=None).request
    assert policy is not None
    with pytest.raises(TypeError):
        check_purpose(policy, "audit")
    with pytest.raises(TypeError):
        check_purpose("raw text", "policy")
