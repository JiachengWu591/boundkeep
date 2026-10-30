"""M3a's policy keys, the new rule in the shipped policies, and ``boundkeep llm check``."""

from __future__ import annotations

import re
import typing
from pathlib import Path
from typing import Any

import pytest
import yaml

from boundkeep import cli
from boundkeep.audit.backends.base import verdict_json
from boundkeep.normalize.model import RiskTag
from boundkeep.policy import PolicyError, default_policy_text, parse_policy_text
from boundkeep.policy.schema import (
    DEFAULT_SENSITIVE_TAGS,
    EXTRA_BODY_RESERVED,
    MAX_TAINT_WINDOW,
    RiskTagName,
)
from boundkeep.session.store import COUNT_CAP
from tests.helpers.llm_server import FakeLLMServer, Reply, json_answer, tool_call_answer

HOME = "/home/testuser"
ROOT = Path(__file__).resolve().parents[2]
KEY = "bk-llmcheck-Vq3x8W2mN4pR8tY1zZ"


def parse(body: str) -> Any:
    return parse_policy_text("version: 1\n" + body, home=HOME)


# ------------------------------------------------------------------------------ schema


def test_the_risk_tag_names_match_the_normalizer() -> None:
    assert set(typing.get_args(RiskTagName)) == set(typing.get_args(RiskTag))
    assert set(DEFAULT_SENSITIVE_TAGS) == set(typing.get_args(RiskTag))
    assert COUNT_CAP == MAX_TAINT_WINDOW + 1


def test_taint_window_and_sensitive_tags_have_defaults_and_bounds() -> None:
    policy = parse("")
    assert policy.taint.window == 8
    assert policy.taint.sensitive_tags == DEFAULT_SENSITIVE_TAGS
    assert parse("taint:\n  window: 1\n").taint.window == 1
    assert parse(f"taint:\n  window: {MAX_TAINT_WINDOW}\n").taint.window == MAX_TAINT_WINDOW
    for bad in ("0", "-1", str(MAX_TAINT_WINDOW + 1), "true", "'8'", "8.0"):
        with pytest.raises(PolicyError):
            parse(f"taint:\n  window: {bad}\n")
    assert parse("taint:\n  sensitive_tags: [exec, exec]\n").taint.sensitive_tags == ("exec",)
    assert parse("taint:\n  sensitive_tags: []\n").taint.sensitive_tags == ()
    with pytest.raises(PolicyError):
        parse("taint:\n  sensitive_tags: [execute]\n")


def test_session_read_untrusted_is_only_for_deny_and_ask_rules() -> None:
    rule = (
        "rules:\n  - id: r\n    tool: [Bash]\n"
        "    match: {program: [make], session_read_untrusted: true}\n"
    )
    assert parse(rule + "    action: ask\n    reason: x\n").rules[0].match.session_read_untrusted
    with pytest.raises(PolicyError, match="deny and ask"):
        parse(rule + "    action: allow\n")
    for bad in ("false", "'yes'", "1"):
        with pytest.raises(PolicyError):
            parse(
                "rules:\n  - id: r\n    tool: [Bash]\n    action: ask\n    reason: x\n"
                f"    match: {{program: [make], session_read_untrusted: {bad}}}\n"
            )


def test_intent_settings_have_bounds() -> None:
    policy = parse("")
    assert (policy.llm_audit.intent_prompts, policy.llm_audit.intent_chars) == (3, 300)
    for key, bad in (("intent_prompts", 0), ("intent_prompts", 11), ("intent_chars", 39)):
        with pytest.raises(PolicyError):
            parse(f"llm_audit:\n  {key}: {bad}\n")


@pytest.mark.parametrize("key", sorted(EXTRA_BODY_RESERVED))
def test_extra_body_cannot_replace_what_the_adapter_sets(key: str) -> None:
    with pytest.raises(PolicyError, match="extra_body must not set"):
        parse(
            "llm_audit:\n  backend: openai_compatible\n  openai_compatible:\n"
            "    base_url: https://llm.example.invalid/v1\n    model: m\n"
            f"    extra_body: {{{key}: 1}}\n"
        )


def test_extra_body_may_add_vendor_options() -> None:
    policy = parse(
        "llm_audit:\n  backend: openai_compatible\n  openai_compatible:\n"
        "    base_url: https://llm.example.invalid/v1\n    model: m\n"
        "    extra_body: {thinking: {type: disabled}, temperature: 0.2}\n"
    )
    assert policy.llm_audit.openai_compatible is not None


def test_a_policy_test_may_say_its_session_is_tainted() -> None:
    policy = parse(
        "tests:\n  - {tool: Bash, tainted: true, input: {command: ls}, expect: allow}\n"
        "  - {tool: Bash, input: {command: ls}, expect: allow}\n"
    )
    assert [t.tainted for t in policy.tests] == [True, False]
    with pytest.raises(PolicyError):
        parse("tests:\n  - {tool: Bash, tainted: 'yes', input: {command: ls}, expect: allow}\n")


# ------------------------------------------------------------------------------ the shipped rule


def _rules(name: str) -> dict[str, dict[str, Any]]:
    data = yaml.safe_load((ROOT / "policies" / f"{name}.yaml").read_text(encoding="utf-8"))
    return {rule["id"]: rule for rule in data["rules"]}


def test_the_new_rule_lists_the_dev_tools_and_is_the_same_in_both_policies() -> None:
    default, strict = _rules("default"), _rules("strict")
    rule = default["ask-devtools-after-untrusted-content"]
    assert rule == strict["ask-devtools-after-untrusted-content"]
    assert rule["action"] == "ask"
    assert rule["match"]["session_read_untrusted"] is True
    allow = default["allow-devtools-trusted-project"]
    assert set(rule["match"]["program"]) == set(allow["match"]["program"])
    assert rule["tool"] == allow["tool"]
    assert set(rule["match"]) == {"program", "session_read_untrusted"}  # trusted or not


@pytest.mark.parametrize("name", ["default", "strict"])
def test_the_shipped_policies_state_the_taint_settings(name: str) -> None:
    data = yaml.safe_load((ROOT / "policies" / f"{name}.yaml").read_text(encoding="utf-8"))
    assert data["taint"]["window"] == 8
    assert set(data["taint"]["sensitive_tags"]) == set(typing.get_args(RiskTag))


# ------------------------------------------------------------------------------ llm check


def _policy_file(tmp_path: Path, base_url: str | None, **keys: str) -> Path:
    text = default_policy_text()
    if base_url is not None:
        block = (
            "  backend: openai_compatible\n  openai_compatible:\n"
            f"    base_url: {base_url}\n    model: check-model\n"
        )
        if keys.get("transport"):
            block += f"    transport: {keys['transport']}\n"
        text = re.sub(r"^  backend: none.*$", block.rstrip("\n"), text, count=1, flags=re.M)
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize("transport", ["tool_call", "json_object"])
def test_llm_check_reports_the_conclusion_and_the_tokens(
    transport: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    boundkeep_home: Path,
) -> None:
    monkeypatch.setenv("BOUNDKEEP_LLM_API_KEY", KEY)
    wrap = tool_call_answer if transport == "tool_call" else json_answer
    answer = wrap(verdict_json(verdict="allow", reasoning="MODEL_TEXT_NOT_SHOWN"))
    with FakeLLMServer(Reply(body=answer)) as server:
        path = _policy_file(tmp_path, server.base_url, transport=transport)
        code = cli.main(["llm", "check", "--policy", str(path)])
        (seen,) = server.requests
    out = capsys.readouterr().out
    assert code == 0, out
    assert "llm check: ok" in out
    assert f"transport {transport}" in out
    assert "model check-model" in out
    assert "tokens: prompt 900, completion 60, total 960" in out
    assert "schema valid (verdict allow, risk 0)" in out
    assert KEY not in out
    assert "MODEL_TEXT_NOT_SHOWN" not in out
    body = seen.json()
    assert "connectivity test" in body["messages"][1]["content"]  # the fixed, harmless request


@pytest.mark.parametrize(
    ("reply", "kind"),
    [
        (Reply(status=401), "auth"),
        (Reply(status=503), "http_5xx"),
        (Reply(body=tool_call_answer("not json")), "invalid_output"),
    ],
)
def test_llm_check_reports_a_failure_and_exits_1(
    reply: Reply,
    kind: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    boundkeep_home: Path,
) -> None:
    monkeypatch.setenv("BOUNDKEEP_LLM_API_KEY", KEY)
    with FakeLLMServer(reply) as server:
        code = cli.main(["llm", "check", "--policy", str(_policy_file(tmp_path, server.base_url))])
    out = capsys.readouterr().out
    assert code == 1
    assert f"llm check: FAILED: {kind}" in out
    assert KEY not in out


def test_llm_check_without_a_key_says_which_variable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], boundkeep_home: Path
) -> None:
    with FakeLLMServer(Reply(body=tool_call_answer(verdict_json()))) as server:
        code = cli.main(["llm", "check", "--policy", str(_policy_file(tmp_path, server.base_url))])
        assert server.requests == []
    out = capsys.readouterr().out
    assert code == 1
    assert "BOUNDKEEP_LLM_API_KEY is not set" in out


def test_llm_check_with_no_backend_has_nothing_to_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], boundkeep_home: Path
) -> None:
    code = cli.main(["llm", "check", "--policy", str(_policy_file(tmp_path, None))])
    assert code == 0
    assert "nothing to check" in capsys.readouterr().out


def test_llm_check_with_anthropic_says_it_is_not_implemented(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], boundkeep_home: Path
) -> None:
    text = re.sub(
        r"^  backend: none.*$",
        "  backend: anthropic\n  anthropic:\n    model: x",
        default_policy_text(),
        count=1,
        flags=re.M,
    )
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    assert cli.main(["llm", "check", "--policy", str(path)]) == 1
    assert "not implemented" in capsys.readouterr().out


def test_doctor_reads_the_session_state_and_the_llm_backend_from_the_ping_text() -> None:
    from boundkeep import doctor

    ok = doctor.check_session_state("mode=enforce; session=ok; llm=none; config_dir=-")
    assert [(c.name, c.status) for c in ok] == [("session-state", doctor.OK)]
    bad = doctor.check_session_state(
        "mode=enforce; session=unavailable; llm=openai_compatible; config_dir=-"
    )
    assert [(c.name, c.status) for c in bad] == [
        ("session-state", doctor.WARN),
        ("llm-audit", doctor.INFO),
    ]
    assert doctor.check_session_state("mode=enforce; config_dir=-") == []  # an older daemon


def test_log_purge_removes_the_stored_intents(
    capsys: pytest.CaptureFixture[str], boundkeep_home: Path
) -> None:
    from boundkeep import paths
    from boundkeep.session.store import SessionStore

    boundkeep_home.mkdir(parents=True)
    store = SessionStore(paths.session_db_file())
    store.add_prompt("s1", "my task", keep=3)
    store.tool_result("s1", "WebFetch", sources=("WebFetch",))
    store.close()
    assert cli.main(["log", "--purge"]) == 0
    assert "removed 1 stored task intent(s)" in capsys.readouterr().out
    store = SessionStore(paths.session_db_file())
    facts = store.facts("s1", window=8, intents=3)
    store.close()
    assert facts.intents == ()
    assert facts.read_untrusted
