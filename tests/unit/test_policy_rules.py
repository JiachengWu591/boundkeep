"""Tests for the M1 policy: schema errors, secrets, home expansion, rule matching, merging.

Actions are built by hand (the normalizer is another module). Test secrets are assembled at run
time from pieces so that no complete token-shaped literal appears in this file.
"""

from __future__ import annotations

import json
import os
from itertools import permutations
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from boundkeep.normalize.model import Action, PathRef
from boundkeep.policy import (
    FrozenMap,
    Policy,
    PolicyError,
    Rule,
    default_policy_text,
    evaluate,
    explain_rule,
    load_policy,
    match_rule,
    parse_policy_text,
)
from boundkeep.policy import matcher as matcher_module
from boundkeep.policy import schema as schema_module
from boundkeep.policy.glob import MAX_KEY_LENGTH, compile_glob
from boundkeep.policy.schema import expand_home, thaw_json
from boundkeep.policy.secretscan import find_secret

REPO = Path(__file__).resolve().parents[2]
POSIX_HOME = "/home/dev"
WIN_HOME = "C:\\Users\\Bob"

# ---------------------------------------------------------------------------- helpers


def pol(body: str, *, home: str = POSIX_HOME) -> Policy:
    """A policy from a YAML snippet (``version: 1`` is added)."""
    return parse_policy_text("version: 1\n" + body, home=home)


def line_of(text: str, marker: str, nth: int = 1) -> int:
    """1-based line number of the ``nth`` line containing ``marker``."""
    seen = 0
    for number, line in enumerate(text.splitlines(), start=1):
        if marker in line:
            seen += 1
            if seen == nth:
                return number
    raise AssertionError(f"{marker!r} not found")


def make_rule(
    match: dict[str, Any],
    *,
    action: str = "deny",
    tool: list[str] | None = None,
    platform: list[str] | None = None,
    rule_id: str = "r1",
    home: str = POSIX_HOME,
) -> Rule:
    data: dict[str, Any] = {"id": rule_id, "match": match, "action": action}
    if action != "allow":
        data["reason"] = f"because {rule_id}"
    if tool is not None:
        data["tool"] = tool
    if platform is not None:
        data["platform"] = platform
    return Rule.model_validate(data, context={"home": home})


def A(
    *paths: tuple[str, str, bool | None],
    **fields: Any,
) -> Action:
    """An Action; each path is (key, access, inside_project)."""
    refs = tuple(
        PathRef(raw=key, key=key, flavor="posix", access=access, inside_project=inside)  # type: ignore[arg-type]
        for key, access, inside in paths
    )
    base: dict[str, Any] = {"tool": "Bash", "shell": "bash", "platform": "posix"}
    if "sh" in fields:
        base["shell"] = fields.pop("sh")
    base.update(fields)
    return Action(paths=refs, **base)


def policy_of(*rules: dict[str, Any]) -> Policy:
    return Policy.model_validate({"version": 1, "rules": list(rules)}, context={"home": POSIX_HOME})


def rdict(
    rule_id: str, action: str, match: dict[str, Any], tool: list[str] | None = None
) -> dict[str, Any]:
    data: dict[str, Any] = {"id": rule_id, "action": action, "match": match}
    if action != "allow":
        data["reason"] = f"reason {rule_id}"
    if tool is not None:
        data["tool"] = tool
    return data


def secrets_for_tests() -> dict[str, str]:
    """Secret-shaped strings assembled at run time (never written out whole in the source)."""
    return {
        "sk": "sk-" + "a1B2c3D4" * 4,
        "sk-ant": "sk-" + "ant-" + "x" * 30,
        "aws": "AK" + "IA" + "ABCDEFGHIJKLMNOP",
        "github": "gh" + "p_" + "a" * 36,
        "github-pat": "github" + "_pat_" + "A" * 30,
        "slack": "xo" + "xb-" + "1234567890-abc",
        "google": "AI" + "za" + "x" * 35,
        "pem": "-----BEGIN " + "RSA PRIVATE" + " KEY-----",
        "jwt": "ey" + "J" + "a" * 12 + ".ey" + "J" + "b" * 12 + ".sig",
        "bearer": "Bea" + "rer " + "z" * 30,
        "url-password": "https://user:" + "hunter22" + "@example.com/x",
        "assignment": "tok" + "en=" + "a1" * 15,
    }


# ---------------------------------------------------------------------------- M0 compatibility


def test_m0_policy_keeps_working_and_gets_empty_m1_sections() -> None:
    policy = parse_policy_text("version: 1\nmode: audit-only\ndefaults:\n  emit_allow: true\n")
    assert policy.mode == "audit-only"
    assert policy.defaults.emit_allow is True
    assert policy.rules == ()
    assert policy.tests == ()
    assert policy.llm_audit.backend == "none"
    assert policy.llm_audit.on_failure == "ask"
    assert policy.llm_audit.timeout_ms == 4000
    assert policy.llm_audit.send_task_intent is True
    assert policy.llm_audit.cache_ttl_s == 600


def test_policy_is_frozen_and_hashable_with_rules_and_tests() -> None:
    policy = pol(
        "rules:\n  - {id: a, action: ask, reason: r, match: {network: true}}\n"
        "tests:\n  - {tool: Bash, input: {command: ls, nested: {k: [1, 2]}}, expect: gray}\n"
        "llm_audit:\n  backend: openai_compatible\n  openai_compatible:\n"
        "    base_url: https://llm.example.com/v1\n    model: m\n"
        "    extra_body: {thinking: {type: disabled}}\n"
    )
    assert hash(policy) == hash(pol(_same_text()))
    assert policy == pol(_same_text())
    with pytest.raises(ValidationError):
        policy.rules = ()  # type: ignore[misc]
    body = policy.tests[0].input
    assert isinstance(body, FrozenMap)
    assert thaw_json(body) == {"command": "ls", "nested": {"k": [1, 2]}}
    with pytest.raises(TypeError):
        body["x"] = 1  # type: ignore[index]
    extra = policy.llm_audit.openai_compatible
    assert extra is not None
    assert extra.extra_body is not None
    assert extra.extra_body.thaw() == {"thinking": {"type": "disabled"}}
    assert repr(body).startswith("FrozenMap(")
    assert len(body) == 2
    assert list(body) == ["command", "nested"]


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8080/v1",
        "http://127.0.0.1/v1",
        "http://[::1]:1234/v1",
        "https://x.example",
    ],
)
def test_base_url_allows_https_and_plain_http_only_on_loopback(url: str) -> None:
    policy = pol(
        f"llm_audit:\n  backend: openai_compatible\n  openai_compatible:\n    base_url: {url}\n"
        "    model: m\n    api_key_env: MY_LLM_KEY\n"
        "    extra_body: {temperature: 0.5, stop: [a, b], n: 1}\n"
    )
    block = policy.llm_audit.openai_compatible
    assert block is not None
    assert block.base_url == url
    assert block.api_key_env == "MY_LLM_KEY"
    assert block.transport == "tool_call"
    assert block.extra_body is not None
    assert block.extra_body.thaw() == {"temperature": 0.5, "stop": ["a", "b"], "n": 1}


def _same_text() -> str:
    return (
        "rules:\n  - {id: a, action: ask, reason: r, match: {network: true}}\n"
        "tests:\n  - {tool: Bash, input: {command: ls, nested: {k: [1, 2]}}, expect: gray}\n"
        "llm_audit:\n  backend: openai_compatible\n  openai_compatible:\n"
        "    base_url: https://llm.example.com/v1\n    model: m\n"
        "    extra_body: {thinking: {type: disabled}}\n"
    )


def test_scalar_shorthand_for_single_entry_lists() -> None:
    policy = pol(
        "rules:\n  - id: r\n    tool: Bash\n    platform: windows\n    action: ask\n    reason: x\n"
        "    match:\n      program: git\n      subcommand: push\n      path_glob: '**/.env'\n"
    )
    rule = policy.rules[0]
    assert rule.tool == ("Bash",)
    assert rule.platform == ("windows",)
    assert rule.match.program == ("git",)
    assert rule.match.subcommand == ("push",)


def test_spec_sample_rule_shapes_validate() -> None:
    policy = pol(
        "rules:\n"
        "  - id: git-force-push\n    tool: [Bash, PowerShell]\n    action: ask\n"
        "    reason: x\n    match:\n      program: git\n      subcommand: push\n"
        '      flags_any: ["--force", "-f"]\n'
        "  - id: read-inside-project\n    tool: [Read, Glob, Grep]\n    action: allow\n"
        "    match: {path_inside_project: true}\n"
    )
    assert [r.id for r in policy.rules] == ["git-force-push", "read-inside-project"]
    assert policy.rules[1].reason == ""


# ---------------------------------------------------------------------------- schema errors

RULE_HEAD = "rules:\n  - id: r1\n    action: deny\n    reason: why\n    match:\n"

ERROR_CASES: list[Any] = [
    pytest.param(
        RULE_HEAD + "      path_globs: ['**/x']\n",
        ["unknown key", "rules[0].match.path_globs"],
        "path_globs",
        id="unknown-match-field",
    ),
    pytest.param(
        RULE_HEAD + "      network: true\n    colour: red\n",
        ["unknown key", "rules[0].colour"],
        "colour",
        id="unknown-rule-field",
    ),
    pytest.param("modee: enforce\n", ["unknown key", "modee"], "modee", id="unknown-top-level-key"),
    pytest.param(
        RULE_HEAD + "      network: true\n  - id: r1\n    action: ask\n    reason: y\n"
        "    match: {network: true}\n",
        ["duplicate rule id 'r1'", "rules[1].id", "rules[0]"],
        ("id: r1", 2),
        id="duplicate-rule-id",
    ),
    pytest.param(
        "rules:\n  - id: Bad_Id\n    action: deny\n    reason: x\n    match: {network: true}\n",
        ["rules[0].id", "lowercase"],
        "Bad_Id",
        id="id-charset",
    ),
    pytest.param(
        "rules:\n  - id: m0-canary\n    action: deny\n    reason: x\n    match: {network: true}\n",
        ["rules[0].id", "built-in"],
        "m0-canary",
        id="reserved-id",
    ),
    pytest.param(
        "rules:\n  - id: ''\n    action: deny\n    reason: x\n    match: {network: true}\n",
        ["rules[0].id"],
        "id: ''",
        id="empty-id",
    ),
    pytest.param(
        "rules:\n  - id: r1\n    action: deny\n    match: {network: true}\n",
        ["rules[0].reason", "needs a reason"],
        "id: r1",
        id="deny-without-reason",
    ),
    pytest.param(
        "rules:\n  - id: r1\n    action: ask\n    reason: ''\n    match: {network: true}\n",
        ["rules[0].reason", "needs a reason"],
        "reason",
        id="ask-with-empty-reason",
    ),
    pytest.param(
        "rules:\n  - id: r1\n    action: deny\n"
        '    reason: "bad\\nreason"\n    match: {network: true}\n',
        ["rules[0].reason"],
        "reason",
        id="reason-with-newline",
    ),
    pytest.param(
        "rules:\n  - id: r1\n    action: allow\n    match: {}\n",
        ["rules[0].match", "allow rule needs at least one match field"],
        "match: {}",
        id="allow-with-empty-match",
    ),
    pytest.param(
        "rules:\n  - id: r1\n    action: block\n    reason: x\n    match: {network: true}\n",
        ["rules[0].action"],
        "block",
        id="unknown-action",
    ),
    pytest.param(
        "rules:\n  - id: r1\n    action: deny\n    reason: x\n",
        ["rules[0].match", "required"],
        "id: r1",
        id="missing-match",
    ),
    pytest.param(
        RULE_HEAD + "      program: []\n",
        ["rules[0].match.program"],
        "program",
        id="empty-list",
    ),
    pytest.param(
        RULE_HEAD + "      program: [rm, '']\n",
        ["rules[0].match.program[1]", "non-empty"],
        "program",
        id="empty-list-entry",
    ),
    pytest.param(
        RULE_HEAD + "      network: false\n",
        ["rules[0].match.network", "only 'true'"],
        "network: false",
        id="false-boolean",
    ),
    pytest.param(
        RULE_HEAD + "      path_outside_project: 1\n",
        ["rules[0].match.path_outside_project"],
        "path_outside_project",
        id="integer-for-boolean",
    ),
    pytest.param(
        RULE_HEAD + "      access: read\n",
        ["rules[0].match", "'access' only qualifies"],
        "match:",
        id="access-without-glob",
    ),
    pytest.param(
        RULE_HEAD + "      path_glob: ['**/x']\n      access: execute\n",
        ["rules[0].match.access"],
        "execute",
        id="bad-access",
    ),
    pytest.param(
        RULE_HEAD + "      path_glob: ['**/ok', '.env']\n",
        ["rules[0].match.path_glob[1]", "not anchored"],
        "path_glob",
        id="unanchored-glob",
    ),
    pytest.param(
        RULE_HEAD + "      path_glob: ['/a/[bc']\n",
        ["rules[0].match.path_glob[0]", "unterminated"],
        "path_glob",
        id="unterminated-class",
    ),
    pytest.param(
        RULE_HEAD + "      path_glob: ['/a/b/']\n",
        ["path_glob[0]", "ends with '/'"],
        "path_glob",
        id="trailing-slash",
    ),
    pytest.param(
        RULE_HEAD + "      path_glob: ['c:\\\\Users\\\\**']\n",
        ["path_glob[0]", "backslash"],
        "path_glob",
        id="backslash-glob",
    ),
    pytest.param(
        RULE_HEAD + "      path_glob: ['~bob/.ssh/**']\n",
        ["path_glob[0]", "only '~' and '~/...'"],
        "path_glob",
        id="tilde-user",
    ),
    pytest.param(
        RULE_HEAD + "      path_glob: ['/a', '/b', 5]\n",
        ["rules[0].match.path_glob[2]"],
        "path_glob",
        id="glob-not-a-string",
    ),
    pytest.param(
        RULE_HEAD + "      domain_not_in: ['*.github.com']\n",
        ["rules[0].match.domain_not_in[0]", "bare host name"],
        "domain_not_in",
        id="wildcard-host",
    ),
    pytest.param(
        RULE_HEAD + "      domain_in: ['https://github.com']\n",
        ["rules[0].match.domain_in[0]"],
        "domain_in",
        id="url-as-host",
    ),
    pytest.param(
        RULE_HEAD + "      domain_in: ['github.com:443']\n",
        ["domain_in[0]"],
        "domain_in",
        id="host-with-port",
    ),
    pytest.param(
        RULE_HEAD + "      domain_in: ['b\u00fccher.example']\n",
        ["domain_in[0]", "punycode"],
        "domain_in",
        id="idn-host",
    ),
    pytest.param(
        RULE_HEAD + "      domain_in: ['127.1']\n",
        ["domain_in[0]", "number"],
        "domain_in",
        id="numeric-tld",
    ),
    pytest.param(
        RULE_HEAD + "      domain_in: ['-bad.example']\n",
        ["domain_in[0]", "not a valid host name"],
        "domain_in",
        id="bad-host-label",
    ),
    pytest.param(
        "llm_audit:\n  openai_compatible:\n    base_url: https://user@h.example\n    model: m\n",
        ["base_url", "credentials"],
        "base_url",
        id="userinfo-in-base-url",
    ),
    pytest.param(
        "llm_audit:\n  openai_compatible:\n    base_url: https://h.example\n    model: m\n"
        "    extra_body: {1: x}\n",
        ["extra_body", "keys must be strings"],
        "extra_body",
        id="extra-body-non-string-key",
    ),
    pytest.param(
        "llm_audit:\n  openai_compatible:\n    base_url: https://h.example\n    model: m\n"
        "    extra_body: {k: [" + ", ".join(["1"] * 501) + "]}\n",
        ["extra_body", "more than 500 values"],
        "extra_body",
        id="extra-body-too-many-values",
    ),
    pytest.param(
        "rules:\n  - id: r\n    tool: ['Ba sh']\n    action: ask\n    reason: x\n"
        "    match: {network: true}\n",
        ["rules[0].tool[0]", "not allowed"],
        "tool",
        id="bad-tool-name",
    ),
    pytest.param(
        "rules:\n  - id: r\n    tool: ['*']\n    action: ask\n    reason: x\n"
        "    match: {network: true}\n",
        ["rules[0].tool[0]"],
        "tool",
        id="bare-star-tool",
    ),
    pytest.param(
        "rules:\n  - id: r\n    platform: [linux]\n    action: ask\n    reason: x\n"
        "    match: {network: true}\n",
        ["rules[0].platform[0]"],
        "platform",
        id="bad-platform",
    ),
    pytest.param(
        "rules:\n  - id: r\n    platform: []\n    action: ask\n    reason: x\n"
        "    match: {network: true}\n",
        ["rules[0].platform"],
        "platform",
        id="empty-platform",
    ),
    pytest.param(
        "llm_audit:\n  on_failure: allow\n",
        ["llm_audit.on_failure", "never allows"],
        "on_failure",
        id="llm-on-failure-allow",
    ),
    pytest.param(
        "llm_audit:\n  backend: openai_compatible\n",
        ["llm_audit.backend", "block is missing"],
        "backend",
        id="backend-without-block",
    ),
    pytest.param(
        "llm_audit:\n  backend: anthropic\n  openai_compatible: {base_url: 'https://a.example', "
        "model: m}\n",
        ["llm_audit.backend", "llm_audit.anthropic block is missing"],
        "backend",
        id="wrong-block-for-backend",
    ),
    pytest.param(
        "llm_audit:\n  backend: gemini\n", ["llm_audit.backend"], "gemini", id="unknown-backend"
    ),
    pytest.param(
        "llm_audit:\n  timeout_ms: 5\n", ["llm_audit.timeout_ms"], "timeout_ms", id="timeout-low"
    ),
    pytest.param(
        "llm_audit:\n  timeout_ms: 4000.5\n",
        ["llm_audit.timeout_ms"],
        "timeout_ms",
        id="timeout-float",
    ),
    pytest.param(
        "llm_audit:\n  cache_ttl_s: -1\n",
        ["llm_audit.cache_ttl_s"],
        "cache_ttl_s",
        id="ttl-negative",
    ),
    pytest.param(
        "llm_audit:\n  send_task_intent: yes\n",
        ["llm_audit.send_task_intent"],
        "send_task_intent",
        id="yes-is-not-a-boolean",
    ),
    pytest.param(
        "llm_audit:\n  backend: none\n  extra: 1\n",
        ["unknown key", "llm_audit.extra"],
        "extra",
        id="unknown-llm-key",
    ),
    pytest.param(
        "llm_audit:\n  openai_compatible:\n    base_url: http://llm.example.com\n    model: m\n",
        ["llm_audit.openai_compatible.base_url", "https"],
        "base_url",
        id="plain-http-base-url",
    ),
    pytest.param(
        "llm_audit:\n  openai_compatible:\n    base_url: ftp://llm.example.com\n    model: m\n",
        ["base_url", "https"],
        "base_url",
        id="ftp-base-url",
    ),
    pytest.param(
        "llm_audit:\n  openai_compatible:\n    base_url: https://\n    model: m\n",
        ["base_url"],
        "base_url",
        id="no-host-base-url",
    ),
    pytest.param(
        "llm_audit:\n  openai_compatible:\n    base_url: https://h.example:99999\n    model: m\n",
        ["base_url", "not a valid URL"],
        "base_url",
        id="bad-port-base-url",
    ),
    pytest.param(
        "llm_audit:\n  openai_compatible:\n    base_url: https://h.example/x#frag\n    model: m\n",
        ["base_url"],
        "base_url",
        id="fragment-base-url",
    ),
    pytest.param(
        "llm_audit:\n  openai_compatible:\n    base_url: https://h.example\n    model: m\n"
        "    api_key_env: my key\n",
        ["api_key_env", "NAME of an environment variable"],
        "api_key_env",
        id="env-name-with-space",
    ),
    pytest.param(
        "llm_audit:\n  anthropic:\n    api_key_env: ANTHROPIC_API_KEY\n",
        ["llm_audit.anthropic.api_key_env", "not read by boundkeep"],
        "api_key_env",
        id="anthropic-api-key-env-refused",
    ),
    pytest.param(
        "llm_audit:\n  openai_compatible:\n    base_url: https://h.example\n    model: m\n"
        "    transport: sse\n",
        ["transport"],
        "transport",
        id="bad-transport",
    ),
    pytest.param(
        "llm_audit:\n  openai_compatible:\n    base_url: https://h.example\n    model: m\n"
        "    extra_body: {when: 2001-01-01}\n",
        ["extra_body", "unsupported value"],
        "extra_body",
        id="extra-body-date",
    ),
    pytest.param(
        "llm_audit:\n  openai_compatible:\n    base_url: https://h.example\n    model: m\n"
        "    extra_body: [1, 2]\n",
        ["extra_body", "must be a mapping"],
        "extra_body",
        id="extra-body-list",
    ),
    pytest.param(
        "llm_audit:\n  openai_compatible:\n    base_url: https://h.example\n    model: m\n"
        "    extra_body: {a: {b: {c: {d: {e: {f: {g: 1}}}}}}}\n",
        ["extra_body", "nested deeper"],
        "extra_body",
        id="extra-body-too-deep",
    ),
    pytest.param(
        "llm_audit:\n  openai_compatible:\n    base_url: https://h.example\n    model: m\n"
        "    extra_body: {a: .inf}\n",
        ["extra_body", "unsupported value"],
        "extra_body",
        id="extra-body-infinity",
    ),
    pytest.param(
        "tests:\n  - {tool: Bash, input: {command: ls}, expect: maybe}\n",
        ["tests[0].expect"],
        "expect",
        id="bad-expect",
    ),
    pytest.param(
        "tests:\n  - {tool: Bash, expect: deny}\n", ["tests[0].input"], "tool: Bash", id="no-input"
    ),
    pytest.param(
        "tests:\n  - {tool: Bash, input: {command: ls}, expect: deny, platform: [mac]}\n",
        ["tests[0].platform[0]"],
        "platform",
        id="test-bad-platform",
    ),
    pytest.param(
        "tests:\n  - {tool: Bash, input: {command: ls}, expect: deny, note: x}\n",
        ["unknown key", "tests[0].note"],
        "note",
        id="test-unknown-field",
    ),
    pytest.param(
        "tests:\n  - {tool: Bash, input: ls, expect: deny}\n",
        ["tests[0].input", "mapping"],
        "input",
        id="test-input-not-a-mapping",
    ),
    pytest.param(
        RULE_HEAD + "      network: true\n      network: true\n",
        ["duplicate key 'network'"],
        ("network", 2),
        id="duplicate-yaml-key",
    ),
    pytest.param(
        RULE_HEAD + "      network: &n true\n", ["anchors are not allowed"], "&n", id="anchor"
    ),
    pytest.param(
        "rules:\n  - id: r1\n    action: deny\n    reason: x\n    match: &m {network: true}\n"
        "  - id: r2\n    action: deny\n    reason: x\n    match: *m\n",
        ["not allowed"],
        "&m",
        id="alias",
    ),
]


@pytest.mark.parametrize(("body", "needles", "marker"), ERROR_CASES)
def test_schema_errors_name_the_field_path_and_the_line(
    body: str, needles: list[str], marker: str | tuple[str, int]
) -> None:
    text = "version: 1\n" + body
    with pytest.raises(PolicyError) as info:
        parse_policy_text(text, home=POSIX_HOME)
    message = str(info.value)
    for needle in needles:
        assert needle in message, message
    where = line_of(text, marker) if isinstance(marker, str) else line_of(text, *marker)
    assert info.value.line == where, message
    assert message.startswith(f"line {where}: "), message
    assert message.isascii()


def test_error_in_a_file_names_the_path_and_line(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text(
        "version: 1\nrules:\n  - id: r1\n    action: deny\n    reason: x\n    match:\n"
        "      path_globs: [x]\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError) as info:
        load_policy(str(path), home=POSIX_HOME)
    assert ":7: " in str(info.value)
    assert "rules[0].match.path_globs" in str(info.value)


def test_several_errors_are_reported_each_with_its_line() -> None:
    text = (
        "version: 1\nrules:\n"
        "  - id: A\n    action: deny\n    reason: x\n    match: {network: true}\n"
        "  - id: b\n    action: deny\n    match: {program: []}\n"
    )
    with pytest.raises(PolicyError) as info:
        parse_policy_text(text, home=POSIX_HOME)
    message = str(info.value)
    assert "rules[0].id" in message
    assert "rules[1].reason" in message
    assert "(line " in message


def test_at_most_five_errors_are_listed() -> None:
    body = "".join(
        f"  - id: BAD{i}\n    action: deny\n    reason: x\n    match: {{network: true}}\n"
        for i in range(8)
    )
    with pytest.raises(PolicyError, match="and 3 more"):
        pol("rules:\n" + body)


def test_rule_count_limit() -> None:
    def many(count: int) -> str:
        return "rules:\n" + "".join(
            f"  - {{id: r{i}, action: ask, reason: x, match: {{network: true}}}}\n"
            for i in range(count)
        )

    assert len(pol(many(500)).rules) == 500
    with pytest.raises(PolicyError, match="at most 500 rules"):
        pol(many(501))


def test_test_count_limit() -> None:
    def many(count: int) -> dict[str, Any]:
        entry = {"tool": "Bash", "input": {"command": "ls"}, "expect": "gray"}
        return {"version": 1, "tests": [entry] * count}

    assert len(Policy.model_validate(many(2000)).tests) == 2000
    with pytest.raises(ValidationError, match="at most 2000 tests"):
        Policy.model_validate(many(2001))


def test_a_validator_that_blows_up_still_gives_a_policy_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("secret-content-from-validator")

    monkeypatch.setattr(Policy, "model_validate", boom)
    with pytest.raises(PolicyError, match="RuntimeError") as info:
        parse_policy_text("version: 1\n")
    assert "secret-content" not in str(info.value)


# ---------------------------------------------------------------------------- secrets


def test_the_test_secrets_do_not_appear_whole_in_this_file() -> None:
    source = Path(__file__).read_text(encoding="utf-8")
    assert all(value not in source for value in secrets_for_tests().values())


@pytest.mark.parametrize("name", sorted(secrets_for_tests()))
def test_secret_shaped_values_are_refused_wherever_they_are(name: str) -> None:
    secret = secrets_for_tests()[name]
    placements = {
        "reason": f'rules:\n  - id: r1\n    action: deny\n    reason: "see {secret}"\n'
        "    match: {network: true}\n",
        "extra-body-value": "llm_audit:\n  openai_compatible:\n    base_url: https://h.example\n"
        f'    model: m\n    extra_body: {{k: "{secret}"}}\n',
        "extra-body-key": "llm_audit:\n  openai_compatible:\n    base_url: https://h.example\n"
        f'    model: m\n    extra_body: {{"{secret}": 1}}\n',
        "api-key-env": f'llm_audit:\n  anthropic:\n    api_key_env: "{secret}"\n',
        # ``tests[].input`` is deliberately not scanned (see the review-fix tests below)
        "test-cwd": "tests:\n  - {tool: Bash, input: {command: ls}, expect: gray, "
        f'cwd: "/x/{secret}"}}\n',
    }
    for where, body in placements.items():
        text = "version: 1\n" + body
        with pytest.raises(PolicyError) as info:
            parse_policy_text(text, home=POSIX_HOME)
        message = str(info.value)
        assert "looks like" in message, (where, message)
        assert "secret" in message, (where, message)
        assert secret not in message, (where, message)
        assert secret[:12] not in message, (where, message)
        assert info.value.line is not None
        assert info.value.line >= 2
        assert message.isascii()


def test_secret_error_points_at_the_line_and_path() -> None:
    secret = secrets_for_tests()["github"]
    text = (
        "version: 1\nrules:\n  - id: r1\n    action: deny\n"
        f'    reason: "token {secret}"\n    match: {{network: true}}\n'
    )
    with pytest.raises(PolicyError) as info:
        parse_policy_text(text, home=POSIX_HOME)
    assert info.value.line == 5
    assert "rules[0].reason" in str(info.value)


def test_a_secret_is_refused_by_direct_validation_too() -> None:
    secret = secrets_for_tests()["sk"]
    data = {"version": 1, "llm_audit": {"anthropic": {"model": secret}}}
    with pytest.raises(ValidationError) as info:
        Policy.model_validate(data)
    assert secret not in str(info.value)
    assert "llm_audit.anthropic.model" in str(info.value)


def test_key_named_like_a_secret_with_a_long_random_value() -> None:
    long_value = "Zx9" * 10
    assert find_secret({"api_key": long_value}) is not None
    assert find_secret({"password": [long_value]}) is not None
    assert find_secret({"api_key_env": long_value}) is None  # names an env var, not a key
    assert find_secret({"api_key": "short"}) is None
    assert find_secret({"api_key": "x" * 25}) is None  # no digit: not random-looking
    assert find_secret({"note": long_value}) is None  # the key name is innocent
    assert find_secret({5: "x", "k": ["a", ("b", 6)]}) is None


def test_ordinary_policy_text_is_not_mistaken_for_a_secret() -> None:
    for value in (
        "deepseek-flash",
        "BOUNDKEEP_LLM_API_KEY",
        "the task-description is sent",
        "https://api.deepseek.com/v1",
        "writing a shell startup file (persistence)",
        "**/.claude/settings*.json",
        "mcp__server__tool_name_that_is_rather_long",
        "ask-ssh-write",
        "tokens are counted, not stored",
    ):
        assert find_secret({"k": value}) is None, value


def test_find_secret_bounds_its_own_work() -> None:
    assert find_secret({"k": "a" * 5000}) is not None
    deep: Any = "x"
    for _ in range(100):
        deep = [deep]
    found = find_secret(deep)
    assert found is not None
    assert "too" in found[1]
    wide = {str(i): "v" for i in range(60_000)}
    found = find_secret(wide)
    assert found is not None
    assert "too" in found[1]


# ---------------------------------------------------------------------------- home expansion


@pytest.mark.parametrize(
    ("home", "expected"),
    [
        pytest.param("C:\\Users\\Bob", "c:/users/bob/.ssh/**", id="windows-native"),
        pytest.param("c:/users/bob", "c:/users/bob/.ssh/**", id="windows-forward"),
        pytest.param("C:\\Users\\Bob\\", "c:/users/bob/.ssh/**", id="windows-trailing-slash"),
        pytest.param("/home/dev", "/home/dev/.ssh/**", id="unix-style"),
        pytest.param("/home/dev/", "/home/dev/.ssh/**", id="posix-trailing-slash"),
        pytest.param("/Users/Dev", "/Users/Dev/.ssh/**", id="posix-case-kept"),
        pytest.param("/", "/.ssh/**", id="root-home"),
    ],
)
def test_tilde_is_expanded_while_loading(home: str, expected: str) -> None:
    policy = pol(
        "rules:\n  - {id: r, action: deny, reason: x, match: {path_glob: ['~/.ssh/**']}}\n",
        home=home,
    )
    assert policy.rules[0].match.path_glob == (expected,)


def test_windows_key_matches_the_expanded_home_glob() -> None:
    policy = pol(
        "rules:\n  - {id: r, action: deny, reason: x, match: {path_glob: ['~/.ssh/**']}}\n",
        home="C:\\Users\\Bob",
    )
    (glob,) = policy.rules[0].match.path_glob or ()
    assert compile_glob(glob).match("c:/users/bob/.ssh/id_rsa")
    assert compile_glob(glob).match("c:/users/bob/.ssh")
    assert not compile_glob(glob).match("c:/users/alice/.ssh/id_rsa")
    assert not compile_glob(glob).match("c:/users/bob/.ssh-old/x")


def test_glob_metacharacters_in_the_home_directory_are_literal() -> None:
    policy = pol(
        "rules:\n  - {id: r, action: deny, reason: x, match: {path_glob: ['~/x', '~']}}\n",
        home="/home/we[ir]d*?",
    )
    first, second = policy.rules[0].match.path_glob or ()
    assert compile_glob(first).match("/home/we[ir]d*?/x")
    assert not compile_glob(first).match("/home/weid/x")
    assert not compile_glob(first).match("/home/we[ir]dab/x")
    assert compile_glob(second).match("/home/we[ir]d*?")


def test_tilde_only_expands_at_the_start() -> None:
    policy = pol(
        "rules:\n  - {id: r, action: deny, reason: x, match: {path_glob: ['**/~$*.docx']}}\n"
    )
    assert policy.rules[0].match.path_glob == ("**/~$*.docx",)


@pytest.mark.parametrize("home", ["relative/dir", "", "C:", "~"])
def test_a_home_directory_that_is_not_absolute_is_refused(home: str) -> None:
    with pytest.raises(PolicyError, match="home"):
        pol(
            "rules:\n  - {id: r, action: deny, reason: x, match: {path_glob: ['~/.ssh/**']}}\n",
            home=home,
        )


def test_home_defaults_to_the_current_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", "/home/envuser")
    monkeypatch.setenv("USERPROFILE", "/home/envuser")
    policy = parse_policy_text(
        "version: 1\nrules:\n  - {id: r, action: deny, reason: x, match: {path_glob: ['~/a']}}\n"
    )
    assert policy.rules[0].match.path_glob == ("/home/envuser/a",)


def test_unknown_home_only_matters_when_a_glob_needs_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os.path, "expanduser", lambda p: p)
    assert parse_policy_text("version: 1\n").rules == ()
    needs = (
        "version: 1\nrules:\n  - {id: r, action: deny, reason: x, match: {path_glob: ['~/a']}}\n"
    )
    with pytest.raises(PolicyError, match="home directory is unknown"):
        parse_policy_text(needs)
    assert parse_policy_text(needs, home="/home/h").rules[0].match.path_glob == ("/home/h/a",)


def test_home_must_be_a_usable_string() -> None:
    needs = (
        "version: 1\nrules:\n  - {id: r, action: deny, reason: x, match: {path_glob: ['~/a']}}\n"
    )
    with pytest.raises(PolicyError, match="not a usable path"):
        parse_policy_text(needs, home="/a\0b")
    with pytest.raises(PolicyError):
        parse_policy_text(needs, home=5)  # type: ignore[arg-type]


def test_load_policy_passes_home_on(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text(
        "version: 1\nrules:\n  - {id: r, action: deny, reason: x, match: {path_glob: ['~/a']}}\n",
        encoding="utf-8",
    )
    assert load_policy(str(path), home="/home/h").rules[0].match.path_glob == ("/home/h/a",)


def test_expand_home_helper_directly() -> None:
    assert expand_home("/x", None) == "/x"
    assert expand_home("~/x", {"home": "/home/h"}) == "/home/h/x"
    with pytest.raises(ValueError, match="only '~'"):
        expand_home("~root/x", {"home": "/home/h"})


def test_home_key_comes_from_the_normalizers_function(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(schema_module, "key_of_home", lambda home: "/custom" + home)
    assert expand_home("~/x", {"home": "/home/h"}) == "/custom/home/h/x"
    monkeypatch.setattr(schema_module, "key_of_home", lambda _home: "")
    with pytest.raises(ValueError, match="no usable key"):
        expand_home("~/x", {"home": "/home/h"})


# ---------------------------------------------------------------------------- tool / platform

TOOL_CASES = [
    pytest.param(["Bash"], "Bash", True, id="exact"),
    pytest.param(["Bash"], "bash", False, id="case-sensitive"),
    pytest.param(["Bash"], "PowerShell", False, id="other-tool"),
    pytest.param(["Bash", "Read"], "Read", True, id="list-is-or"),
    pytest.param(["mcp__*"], "mcp__srv__tool", True, id="prefix-star"),
    pytest.param(["mcp__*"], "mcp_srv", False, id="prefix-star-needs-prefix"),
    pytest.param(["mcp__github__*"], "mcp__github__create", True, id="server-prefix"),
    pytest.param(["mcp__github__*"], "mcp__gitlab__create", False, id="other-server"),
    pytest.param(None, "Anything", True, id="no-tool-means-all"),
]


@pytest.mark.parametrize(("tools", "tool", "expected"), TOOL_CASES)
def test_tool_filter(tools: list[str] | None, tool: str, expected: bool) -> None:
    rule = make_rule({"network": True}, tool=tools)
    assert match_rule(rule, A(tool=tool, network=True), platform="posix") is expected


@pytest.mark.parametrize(
    ("rule_platform", "process", "expected"),
    [
        pytest.param(None, "posix", True, id="none-posix"),
        pytest.param(None, "windows", True, id="none-windows"),
        pytest.param(["windows"], "windows", True, id="windows-on-windows"),
        pytest.param(["windows"], "posix", False, id="windows-on-posix"),
        pytest.param(["posix"], "windows", False, id="posix-on-windows"),
        pytest.param(["posix", "windows"], "windows", True, id="both"),
    ],
)
def test_platform_filter_uses_the_process_platform(
    rule_platform: list[str] | None, process: str, expected: bool
) -> None:
    rule = make_rule({"network": True}, platform=rule_platform)
    action = A(network=True)  # the action's own platform is not what filters
    assert match_rule(rule, action, platform=process) is expected  # type: ignore[arg-type]


# ---------------------------------------------------------------------------- match fields

# (match, action, expected): one row per behaviour, positive and negative.
RW = ("/home/dev/.ssh/id_rsa", "read", None)
FIELD_CASES = [
    # path_glob / access
    pytest.param({"path_glob": ["/home/dev/.ssh/**"]}, A(RW), True, id="glob-hit"),
    pytest.param(
        {"path_glob": ["/home/dev/.ssh/**"]},
        A(("/home/dev/x", "read", None)),
        False,
        id="glob-miss",
    ),
    pytest.param({"path_glob": ["/a/**", "/home/**"]}, A(RW), True, id="glob-second-pattern"),
    pytest.param(
        {"path_glob": ["/home/dev/.ssh/**"]},
        A(("/other", "read", None), RW),
        True,
        id="glob-second-path",
    ),
    pytest.param({"path_glob": ["/home/dev/.ssh/**"]}, A(), False, id="glob-no-paths"),
    pytest.param(
        {"path_glob": ["/home/dev/.ssh/**"]},
        A(("/HOME/DEV/.SSH/ID_RSA", "read", None)),
        True,
        id="glob-key-case-insensitive",
    ),
    pytest.param(
        {"path_glob": ["/HOME/Dev/.SSH/**"]}, A(RW), True, id="glob-pattern-case-insensitive"
    ),
    pytest.param(
        {"path_glob": ["**/.env"], "access": "read"},
        A(("/p/.env", "read", True)),
        True,
        id="access-equal-read",
    ),
    pytest.param(
        {"path_glob": ["**/.env"], "access": "read"},
        A(("/p/.env", "write", True)),
        False,
        id="access-write-vs-read-rule",
    ),
    pytest.param(
        {"path_glob": ["**/.env"], "access": "write"},
        A(("/p/.env", "read", True)),
        False,
        id="access-read-vs-write-rule",
    ),
    pytest.param(
        {"path_glob": ["**/.env"], "access": "read"},
        A(("/p/.env", "unknown", True)),
        True,
        id="access-unknown-matches-read-rule",
    ),
    pytest.param(
        {"path_glob": ["**/.env"], "access": "write"},
        A(("/p/.env", "unknown", True)),
        True,
        id="access-unknown-matches-write-rule",
    ),
    pytest.param(
        {"path_glob": ["**/.env"], "access": "write"},
        A(("/p/.env", "read", True), ("/q/.env", "write", True)),
        True,
        id="access-checked-per-path",
    ),
    pytest.param(
        {"path_glob": ["**/.env"]},
        A(("/p/.env", "read", True)),
        True,
        id="no-access-means-any",
    ),
    pytest.param(
        {"path_glob": ["**/.env"], "access": "read"},
        A(("/p/.envrc", "read", True)),
        False,
        id="envrc-is-not-env",
    ),
    # program / subcommand / flags_any
    pytest.param({"program": ["rm"]}, A(program="rm"), True, id="program-hit"),
    pytest.param({"program": ["rm"]}, A(program="RM"), False, id="program-bash-case-sensitive"),
    pytest.param({"program": ["rm", "mv"]}, A(program="mv"), True, id="program-or"),
    pytest.param({"program": ["rm"]}, A(program="rmdir"), False, id="program-exact-not-prefix"),
    pytest.param({"program": ["rm"]}, A(), False, id="program-absent"),
    pytest.param(
        {"program": ["Remove-Item"]},
        A(program="remove-item", sh="powershell"),
        True,
        id="program-powershell-case-insensitive",
    ),
    pytest.param(
        {"program": ["remove-item"]},
        A(program="Remove-Item", sh="powershell"),
        True,
        id="program-powershell-case-insensitive-rule-side",
    ),
    pytest.param(
        {"program": ["Remove-Item"]},
        A(program="remove-item", sh="bash"),
        False,
        id="program-bash-ignores-powershell-rule-case",
    ),
    pytest.param(
        {"program": ["Remove-Item"]},
        A(program="remove-item", sh=None),
        False,
        id="program-no-shell-is-case-sensitive",
    ),
    pytest.param({"subcommand": ["push"]}, A(subcommand="push"), True, id="subcommand-hit"),
    pytest.param({"subcommand": ["push"]}, A(subcommand="pull"), False, id="subcommand-miss"),
    pytest.param({"subcommand": ["push"]}, A(), False, id="subcommand-absent"),
    pytest.param(
        {"subcommand": ["push"]},
        A(subcommand="PUSH", sh="powershell"),
        True,
        id="subcommand-powershell-case-insensitive",
    ),
    pytest.param(
        {"flags_any": ["-rf", "--force"]}, A(flags=("-r", "-f", "-rf")), True, id="flag-hit"
    ),
    pytest.param({"flags_any": ["--force"]}, A(flags=("-f",)), False, id="flag-miss"),
    pytest.param({"flags_any": ["-r"]}, A(flags=("-R",)), False, id="flag-bash-case-sensitive"),
    pytest.param({"flags_any": ["-r"]}, A(), False, id="flag-absent"),
    pytest.param(
        {"flags_any": ["-Recurse"]},
        A(flags=("-recurse",), sh="powershell", program="Remove-Item"),
        True,
        id="flag-powershell-case-insensitive",
    ),
    pytest.param(
        {"flags_any": ["-D"]},
        A(flags=("-d",), sh="powershell", program="git"),
        False,
        id="flag-powershell-external-case-sensitive",
    ),
    # path_outside_project / path_inside_project
    pytest.param(
        {"path_outside_project": True}, A(("/x", "read", False)), True, id="outside-definitely"
    ),
    pytest.param(
        {"path_outside_project": True}, A(("/x", "read", None)), True, id="outside-when-unsure"
    ),
    pytest.param(
        {"path_outside_project": True}, A(("/x", "read", True)), False, id="outside-not-when-inside"
    ),
    pytest.param(
        {"path_outside_project": True},
        A(("/x", "read", True), ("/y", "read", False)),
        True,
        id="outside-any-path",
    ),
    pytest.param({"path_outside_project": True}, A(), False, id="outside-needs-a-path"),
    pytest.param(
        {"path_inside_project": True}, A(("/x", "read", True)), True, id="inside-definitely"
    ),
    pytest.param(
        {"path_inside_project": True},
        A(("/x", "read", True), ("/y", "read", True)),
        True,
        id="inside-all-paths",
    ),
    pytest.param(
        {"path_inside_project": True},
        A(("/x", "read", True), ("/y", "read", None)),
        False,
        id="inside-one-unsure",
    ),
    pytest.param(
        {"path_inside_project": True},
        A(("/x", "read", True), ("/y", "read", False)),
        False,
        id="inside-one-outside",
    ),
    pytest.param({"path_inside_project": True}, A(), False, id="inside-needs-a-path"),
    pytest.param(
        {"path_inside_project": True}, A(("/x", "read", None)), False, id="inside-unsure-is-no"
    ),
    # network / domains
    pytest.param({"network": True}, A(network=True), True, id="network-hit"),
    pytest.param({"network": True}, A(network=False), False, id="network-miss"),
    pytest.param(
        {"domain_not_in": ["github.com"]},
        A(network=True, domains=("evil.example",)),
        True,
        id="not-in-stranger",
    ),
    pytest.param(
        {"domain_not_in": ["github.com"]},
        A(network=True, domains=("github.com",)),
        False,
        id="not-in-allowed",
    ),
    pytest.param(
        {"domain_not_in": ["github.com"]},
        A(network=True, domains=("api.github.com",)),
        False,
        id="not-in-subdomain-is-allowed",
    ),
    pytest.param(
        {"domain_not_in": ["github.com"]},
        A(network=True, domains=("evilgithub.com",)),
        True,
        id="not-in-lookalike-suffix",
    ),
    pytest.param(
        {"domain_not_in": ["github.com"]},
        A(network=True, domains=("github.com.evil.example",)),
        True,
        id="not-in-lookalike-prefix",
    ),
    pytest.param(
        {"domain_not_in": ["github.com"]},
        A(network=True, domains=("github.com", "evil.example")),
        True,
        id="not-in-any-stranger",
    ),
    pytest.param(
        {"domain_not_in": ["github.com"]},
        A(network=True, domains=("GitHub.COM.",)),
        False,
        id="not-in-case-and-trailing-dot",
    ),
    pytest.param(
        {"domain_not_in": ["github.com"]}, A(network=True), True, id="not-in-unknown-destination"
    ),
    pytest.param(
        {"domain_not_in": ["github.com"]},
        A(network=False, domains=("evil.example",)),
        False,
        id="not-in-needs-network",
    ),
    pytest.param(
        {"domain_not_in": ["10.0.0.1"]},
        A(network=True, domains=("10.0.0.1",)),
        False,
        id="not-in-ip-exact",
    ),
    pytest.param(
        {"domain_not_in": ["10.0.0.1"]},
        A(network=True, domains=("evil.10.0.0.1",)),
        True,
        id="not-in-ip-is-not-a-suffix-domain",
    ),
    pytest.param(
        {"domain_in": ["github.com", "pypi.org"]},
        A(network=True, domains=("github.com", "pypi.org")),
        True,
        id="in-all-allowed",
    ),
    pytest.param(
        {"domain_in": ["github.com"]},
        A(network=True, domains=("github.com", "evil.example")),
        False,
        id="in-one-stranger",
    ),
    pytest.param({"domain_in": ["github.com"]}, A(network=True), False, id="in-no-domains"),
    pytest.param(
        {"domain_in": ["github.com"]},
        A(network=False, domains=("github.com",)),
        False,
        id="in-needs-network",
    ),
    pytest.param(
        {"domain_in": ["github.com"]},
        A(network=True, domains=("github.com@evil.example",)),
        False,
        id="in-userinfo-trick-is-not-github",
    ),
    pytest.param(
        {"domain_in": ["::1"]}, A(network=True, domains=("::1",)), True, id="in-ipv6-exact"
    ),
    # mcp_server
    pytest.param({"mcp_server": ["github"]}, A(mcp_server="github"), True, id="mcp-hit"),
    pytest.param({"mcp_server": ["github"]}, A(mcp_server="gitlab"), False, id="mcp-miss"),
    pytest.param({"mcp_server": ["github"]}, A(), False, id="mcp-absent"),
    pytest.param(
        {"mcp_server": ["github"]}, A(mcp_server="GitHub"), False, id="mcp-case-sensitive"
    ),
    # AND across fields
    pytest.param(
        {"program": ["git"], "subcommand": ["push"], "flags_any": ["--force"]},
        A(program="git", subcommand="push", flags=("--force",)),
        True,
        id="and-all-fields",
    ),
    pytest.param(
        {"program": ["git"], "subcommand": ["push"], "flags_any": ["--force"]},
        A(program="git", subcommand="push", flags=("-v",)),
        False,
        id="and-one-field-fails",
    ),
    pytest.param(
        {"program": ["rm"], "path_outside_project": True},
        A(("/x", "write", False), program="rm"),
        True,
        id="and-program-and-outside",
    ),
    pytest.param(
        {"program": ["rm"], "path_outside_project": True},
        A(("/x", "write", True), program="rm"),
        False,
        id="and-program-but-inside",
    ),
    pytest.param(
        {"network": True, "domain_not_in": ["github.com"], "program": ["curl"]},
        A(network=True, domains=("x.example",), program="wget"),
        False,
        id="and-network-but-other-program",
    ),
]


@pytest.mark.parametrize(("match", "action", "expected"), FIELD_CASES)
def test_every_match_field_positive_and_negative(
    match: dict[str, Any], action: Action, expected: bool
) -> None:
    for decision in ("deny", "ask"):
        rule = make_rule(match, action=decision)
        assert match_rule(rule, action, platform="posix") is expected
    allow = make_rule(match, action="allow")
    assert match_rule(allow, action, platform="posix") is expected  # not gray: same answer


def test_a_gray_action_never_matches_an_allow_rule_but_still_matches_deny_and_ask() -> None:
    match = {"program": ["ls"]}
    gray = A(program="ls", gray=True, gray_reasons=("opaque",))
    assert not match_rule(make_rule(match, action="allow"), gray, platform="posix")
    assert match_rule(make_rule(match, action="ask"), gray, platform="posix")
    assert match_rule(make_rule(match, action="deny"), gray, platform="posix")


def test_explain_rule_gives_one_line_per_matched_field() -> None:
    rule = make_rule(
        {"program": ["rm"], "path_glob": ["/h/**"], "access": "write", "path_outside_project": True}
    )
    action = A(("/h/x", "write", False), program="rm")
    lines = explain_rule(rule, action, platform="posix")
    assert lines is not None
    assert lines[0] == "program: rm"
    assert any(line.startswith("path_glob: /h/x ~ /h/**") for line in lines)
    assert any("outside" in line for line in lines)
    assert explain_rule(rule, A(program="ls"), platform="posix") is None
    details = explain_rule(
        make_rule({"domain_not_in": ["a.example"]}), A(network=True), platform="posix"
    )
    assert details == ("domain_not_in: network action with no known domain",)


def test_unsure_inside_state_is_described_as_such() -> None:
    rule = make_rule({"path_outside_project": True})
    lines = explain_rule(rule, A(("/x", "read", None)), platform="posix")
    assert lines is not None
    assert "not known to be inside" in lines[0]


# ---------------------------------------------------------------------------- evaluation table

R_DENY_RM = rdict("deny-rm", "deny", {"program": ["rm"]})
R_ASK_RM_F = rdict("ask-rm-f", "ask", {"program": ["rm"], "flags_any": ["-f"]})
R_ALLOW_RM = rdict("allow-rm", "allow", {"program": ["rm"]})
R_ALLOW_LS = rdict("allow-ls", "allow", {"program": ["ls"]})
R_ASK_LS_L = rdict("ask-ls-l", "ask", {"program": ["ls"], "flags_any": ["-l"]})
R_DENY_LS_X = rdict("deny-ls-x", "deny", {"program": ["ls"], "flags_any": ["-x"]})
R_ASK_NET = rdict("ask-net", "ask", {"network": True})

LS = A(program="ls")
LS_L = A(program="ls", flags=("-l",))
LS_X = A(program="ls", flags=("-x", "-l"))
RM = A(program="rm")
RM_F = A(program="rm", flags=("-f",))
CAT = A(program="cat")  # matched by nothing
GRAY_LS = A(program="ls", gray=True, gray_reasons=("opaque substitution",))
CURL = A(program="curl", network=True)

EVAL_CASES: list[Any] = [
    pytest.param([R_ALLOW_LS], [LS], "allow", ["allow-ls"], id="allow-single"),
    pytest.param([R_ALLOW_LS], [LS, LS], "allow", ["allow-ls"], id="allow-all-actions"),
    pytest.param(
        [R_ALLOW_LS, R_ALLOW_RM], [LS, RM], "allow", ["allow-ls", "allow-rm"], id="allow-two-rules"
    ),
    pytest.param([R_ALLOW_LS], [LS, CAT], "gray", [], id="allow-plus-unmatched-is-gray"),
    pytest.param([R_ALLOW_LS], [CAT], "gray", [], id="unmatched-is-gray"),
    pytest.param([R_ALLOW_LS], [], "gray", [], id="empty-is-gray"),
    pytest.param([], [], "gray", [], id="empty-without-rules"),
    pytest.param([], [LS], "gray", [], id="no-rules-is-gray"),
    pytest.param([R_ALLOW_LS], [GRAY_LS], "gray", [], id="gray-action-never-allowed"),
    pytest.param([R_ALLOW_LS], [LS, GRAY_LS], "gray", [], id="allow-plus-gray-action-is-gray"),
    # same action, several rules: strictest wins
    pytest.param(
        [R_ALLOW_LS, R_ASK_LS_L], [LS_L], "ask", ["ask-ls-l"], id="same-action-allow-vs-ask"
    ),
    pytest.param(
        [R_ALLOW_LS, R_DENY_LS_X], [LS_X], "deny", ["deny-ls-x"], id="same-action-allow-vs-deny"
    ),
    pytest.param(
        [R_ALLOW_LS, R_ASK_LS_L, R_DENY_LS_X],
        [LS_X],
        "deny",
        ["deny-ls-x"],
        id="same-action-all-three",
    ),
    pytest.param(
        [R_ASK_RM_F, R_DENY_RM], [RM_F], "deny", ["deny-rm"], id="same-action-ask-vs-deny"
    ),
    pytest.param([R_DENY_RM, R_ASK_RM_F], [RM_F], "deny", ["deny-rm"], id="same-action-order-free"),
    pytest.param(
        [R_ALLOW_RM, R_ASK_RM_F], [RM_F], "ask", ["ask-rm-f"], id="same-action-ask-over-allow"
    ),
    # merging across actions
    pytest.param([R_ALLOW_LS, R_DENY_RM], [LS, RM], "deny", ["deny-rm"], id="allow-and-deny"),
    pytest.param([R_ALLOW_LS, R_ASK_NET], [LS, CURL], "ask", ["ask-net"], id="allow-and-ask"),
    pytest.param([R_ASK_NET], [CURL, CAT], "ask", ["ask-net"], id="ask-beats-gray"),
    pytest.param([R_DENY_RM], [RM, CAT], "deny", ["deny-rm"], id="deny-beats-gray"),
    pytest.param([R_DENY_RM, R_ASK_NET], [CURL, RM], "deny", ["deny-rm"], id="deny-beats-ask"),
    pytest.param(
        [R_ASK_NET, R_ASK_LS_L],
        [CURL, LS_L],
        "ask",
        ["ask-net", "ask-ls-l"],
        id="two-asks-both-listed",
    ),
    pytest.param([R_DENY_RM], [GRAY_LS, RM], "deny", ["deny-rm"], id="gray-action-and-deny"),
    pytest.param(
        [R_ASK_LS_L],
        [A(program="ls", flags=("-l",), gray=True)],
        "ask",
        ["ask-ls-l"],
        id="gray-action-still-asked-by-ask-rule",
    ),
    pytest.param(
        [R_DENY_LS_X],
        [A(program="ls", flags=("-x",), gray=True)],
        "deny",
        ["deny-ls-x"],
        id="gray-action-still-denied-by-deny-rule",
    ),
    pytest.param(
        [rdict("tool-only", "allow", {"program": ["ls"]}, tool=["Read"])],
        [LS],
        "gray",
        [],
        id="allow-rule-for-another-tool-does-not-apply",
    ),
]


@pytest.mark.parametrize(("rules", "actions", "decision", "rule_ids"), EVAL_CASES)
def test_evaluate_merges_strictest_wins(
    rules: list[dict[str, Any]], actions: list[Action], decision: str, rule_ids: list[str]
) -> None:
    policy = policy_of(*rules)
    verdict = evaluate(policy, actions, platform="posix")
    assert verdict.decision == decision
    assert list(verdict.rule_ids) == rule_ids
    assert len(verdict.actions) == len(actions)
    # Order of rules and of actions never changes the decision.
    for shuffled in permutations(rules):
        assert evaluate(policy_of(*shuffled), actions, platform="posix").decision == decision
    for shuffled_actions in permutations(actions):
        assert evaluate(policy, list(shuffled_actions), platform="posix").decision == decision


def test_the_verdict_carries_reasons_rule_ids_and_per_action_detail() -> None:
    policy = policy_of(R_ALLOW_LS, R_ASK_LS_L, R_DENY_RM)
    verdict = evaluate(policy, [LS_L, RM, CAT], platform="posix")
    assert verdict.decision == "deny"
    assert verdict.rule_ids == ("deny-rm",)
    assert verdict.reasons == ("reason deny-rm",)
    first, second, third = verdict.actions
    assert (first.index, first.decision) == (0, "ask")
    assert [h.rule_id for h in first.hits] == ["allow-ls", "ask-ls-l"]
    assert first.hits[1].reason == "reason ask-ls-l"
    assert first.hits[1].detail == (
        "program: ls",
        "flags_any: -l",
    )
    assert second.decision == "deny"
    assert third.decision == "gray"
    assert third.hits == ()


def test_a_deduplicated_reason_and_rule_id_per_verdict() -> None:
    policy = policy_of(R_DENY_RM)
    verdict = evaluate(policy, [RM, RM_F, RM], platform="posix")
    assert verdict.rule_ids == ("deny-rm",)
    assert verdict.reasons == ("reason deny-rm",)


def test_gray_verdict_reasons_come_from_the_actions() -> None:
    verdict = evaluate(policy_of(R_ALLOW_LS), [GRAY_LS, CAT], platform="posix")
    assert verdict.decision == "gray"
    assert verdict.reasons == ("opaque substitution", "no rule matched")
    assert evaluate(policy_of(), [], platform="posix").reasons == ("no action to evaluate",)


def test_allow_verdict_without_reasons_has_no_reason_text() -> None:
    verdict = evaluate(policy_of(R_ALLOW_LS), [LS], platform="posix")
    assert verdict.decision == "allow"
    assert verdict.reasons == ()


def test_platform_filtering_in_evaluate() -> None:
    win_only = rdict("win", "deny", {"program": ["rm"]})
    win_only["platform"] = ["windows"]
    policy = policy_of(win_only)
    assert evaluate(policy, [RM], platform="windows").decision == "deny"
    assert evaluate(policy, [RM], platform="posix").decision == "gray"


# ---------------------------------------------------------------------------- canary


def canary_action(**kw: Any) -> Action:
    return A(program="echo", command_text="echo BOUNDKEEP_CANARY", **kw)


def test_canary_denies_even_with_no_rules() -> None:
    verdict = evaluate(policy_of(), [canary_action()], platform="posix")
    assert verdict.decision == "deny"
    assert verdict.rule_ids == ("m0-canary",)
    assert "M0 canary" in verdict.reasons[0]
    assert verdict.actions[0].hits[0].detail == ("command_text contains BOUNDKEEP_CANARY",)


def test_canary_is_evaluated_first_and_beats_an_allow_rule() -> None:
    allow_echo = rdict("allow-echo", "allow", {"program": ["echo"]})
    verdict = evaluate(policy_of(allow_echo), [canary_action()], platform="posix")
    assert verdict.decision == "deny"
    assert verdict.rule_ids == ("m0-canary",)
    assert [h.rule_id for h in verdict.actions[0].hits] == ["m0-canary", "allow-echo"]


def test_canary_applies_to_gray_actions_and_to_any_one_action_of_many() -> None:
    gray = canary_action(gray=True)
    assert evaluate(policy_of(), [gray], platform="posix").decision == "deny"
    verdict = evaluate(policy_of(R_ALLOW_LS), [LS, canary_action()], platform="posix")
    assert verdict.decision == "deny"


@pytest.mark.parametrize(
    "text",
    [None, "", "echo boundkeep_canary", "echo BOUNDKEEP_CANAR", "echo BOUNDKEEP_ CANARY", "ls"],
    ids=["none", "empty", "lowercase", "truncated", "split", "unrelated"],
)
def test_canary_needs_the_exact_marker_in_command_text(text: str | None) -> None:
    action = A(program="echo", command_text=text)
    assert evaluate(policy_of(), [action], platform="posix").decision == "gray"


def test_canary_id_cannot_be_reused_by_a_yaml_rule() -> None:
    with pytest.raises(PolicyError, match="built-in"):
        pol("rules:\n  - {id: m0-canary, action: allow, match: {network: true}}\n")


def test_canary_in_a_two_megabyte_command_is_found_quickly() -> None:
    action = A(program="echo", command_text="x" * 2_000_000 + "BOUNDKEEP_CANARY")
    assert evaluate(policy_of(), [action], platform="posix").decision == "deny"


# ---------------------------------------------------------------------------- hostile inputs


def test_overlong_keys_match_deny_and_ask_rules_but_never_allow_rules() -> None:
    key = "/" + "a" * (MAX_KEY_LENGTH + 1)
    action = A((key, "read", True))
    match = {"path_glob": ["/**"]}
    assert match_rule(make_rule(match, action="deny"), action, platform="posix")
    assert match_rule(make_rule(match, action="ask"), action, platform="posix")
    assert not match_rule(make_rule(match, action="allow"), action, platform="posix")
    lines = explain_rule(make_rule(match), action, platform="posix")
    assert lines is not None
    assert "longer than" in lines[0]


def test_odd_keys_and_texts_never_raise() -> None:
    policy = pol("rules:\n  - {id: r, action: deny, reason: x, match: {path_glob: ['**/.env']}}\n")
    nasty = [
        "",
        "\x00",
        "\ud800",
        "a\x00/.env",
        "/" + "\u202e" * 1000,
        "\U0010ffff/.env",
        "." * 5000,
    ]
    for key in nasty:
        action = Action(
            tool="Read",
            platform="posix",
            paths=(PathRef(raw=key, key=key, flavor="posix"),),
            command_text=key,
            program=key,
            flags=(key,),
            domains=(key,),
            network=True,
        )
        assert evaluate(policy, [action], platform="posix").decision in {
            "deny",
            "ask",
            "allow",
            "gray",
        }


def test_many_actions_and_many_rules_stay_fast() -> None:
    rules = [
        rdict(f"r{i}", "ask", {"program": [f"p{i}"], "path_glob": [f"/x{i}/**"]})
        for i in range(200)
    ]
    policy = policy_of(*rules)
    actions = [A(("/y/z", "read", None), program=f"p{i}") for i in range(300)]
    assert evaluate(policy, actions, platform="posix").decision == "gray"


def test_an_internal_error_fails_toward_deny_and_ask_never_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("bug")

    monkeypatch.setattr(matcher_module, "_match_detail", boom)
    deny = make_rule({"program": ["rm"]}, action="deny")
    ask = make_rule({"program": ["rm"]}, action="ask", rule_id="r2")
    allow = make_rule({"program": ["rm"]}, action="allow", rule_id="r3")
    assert match_rule(deny, RM, platform="posix") is True
    assert match_rule(ask, RM, platform="posix") is True
    assert match_rule(allow, RM, platform="posix") is False
    verdict = evaluate(policy_of(R_ALLOW_RM), [RM], platform="posix")
    assert verdict.decision == "gray"
    verdict = evaluate(policy_of(R_DENY_RM), [RM], platform="posix")
    assert verdict.decision == "deny"
    assert verdict.actions[0].hits[0].detail == ("internal-error: treated as a match",)


# ---------------------------------------------------------------------------- shipped policies

POLICY_FILES = ["default", "strict"]


def read_policy_text(name: str) -> str:
    return (REPO / "policies" / f"{name}.yaml").read_text(encoding="utf-8")


@pytest.mark.parametrize("name", POLICY_FILES)
@pytest.mark.parametrize("home", [POSIX_HOME, WIN_HOME], ids=["posix-home", "windows-home"])
def test_shipped_policy_validates_with_unique_ids(name: str, home: str) -> None:
    policy = parse_policy_text(read_policy_text(name), home=home)
    ids = [rule.id for rule in policy.rules]
    assert len(ids) == len(set(ids))
    assert len(ids) >= 10
    assert policy.mode == "enforce"
    assert policy.defaults.emit_allow is False
    assert policy.llm_audit.backend == "none"
    assert policy.llm_audit.on_failure in ("ask", "deny")
    for rule in policy.rules:
        assert (rule.action == "allow") or rule.reason, rule.id
        for glob in rule.match.path_glob or ():
            assert "~" not in glob.split("/")[0], (rule.id, glob)
            compile_glob(glob)


def test_the_loader_default_text_is_the_repo_file() -> None:
    assert default_policy_text() == read_policy_text("default").replace("\r\n", "\n")


@pytest.mark.parametrize("name", POLICY_FILES)
def test_every_rule_has_a_comment_giving_its_reason(name: str) -> None:
    lines = read_policy_text(name).splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith("  - id: ")]
    assert starts
    for index in starts:
        following = lines[index + 1]
        assert following.strip().startswith("#"), f"{lines[index].strip()} has no reason comment"
        assert len(following.strip()) > 30, lines[index]


@pytest.mark.parametrize("name", POLICY_FILES)
def test_shipped_policy_tests_section_is_well_formed(name: str) -> None:
    policy = parse_policy_text(read_policy_text(name), home=POSIX_HOME)
    assert len(policy.tests) >= 15
    assert {t.expect for t in policy.tests} >= {"deny", "ask", "gray"}
    assert any(t.platform == ("windows",) for t in policy.tests)
    assert any(t.platform == ("posix",) for t in policy.tests)


def test_default_policy_keeps_the_spec_example_tests() -> None:
    policy = parse_policy_text(read_policy_text("default"), home=POSIX_HOME)
    seen = {
        (t.tool, t.expect, t.input.get("command") or t.input.get("file_path")) for t in policy.tests
    }
    for expected in [
        ("Bash", "deny", "rm -rf /"),
        ("Read", "deny", "~/.ssh/id_rsa"),
        ("Bash", "ask", "git push --force origin main"),
        ("Bash", "gray", "pytest -q"),
        ("Read", "allow", "./src/app.py"),
        ("Read", "deny", "~\\.SSH\\id_rsa"),
        ("PowerShell", "deny", "Remove-Item -Recurse -Force C:\\"),
    ]:
        assert expected in seen


def decide(policy: Policy, platform: str, *actions: Action) -> str:
    return evaluate(policy, list(actions), platform=platform).decision  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def default_posix() -> Policy:
    return parse_policy_text(read_policy_text("default"), home=POSIX_HOME)


@pytest.fixture(scope="module")
def default_windows() -> Policy:
    return parse_policy_text(read_policy_text("default"), home=WIN_HOME)


@pytest.fixture(scope="module")
def strict_posix() -> Policy:
    return parse_policy_text(read_policy_text("strict"), home=POSIX_HOME)


def win_action(key: str, access: str, **kw: Any) -> Action:
    ref = PathRef(raw=key, key=key, flavor="windows", access=access, inside_project=False)  # type: ignore[arg-type]
    return Action(tool=kw.pop("tool", "Read"), platform="windows", paths=(ref,), **kw)


DEFAULT_POSIX_CASES = [
    pytest.param(A(("/home/dev/.ssh/id_rsa", "read", False), tool="Read"), "deny", id="ssh-key"),
    pytest.param(A(("/home/dev/.aws/credentials", "read", False), tool="Read"), "deny", id="aws"),
    pytest.param(
        A(("/home/dev/.config/gh/hosts.yml", "read", False), tool="Read"), "deny", id="gh"
    ),
    pytest.param(
        A(("/home/dev/proj/.env", "read", True), tool="Read"), "deny", id="env-in-project"
    ),
    pytest.param(
        A(("/home/dev/proj/.env.local", "read", True), tool="Read"), "deny", id="env-local"
    ),
    pytest.param(
        A(("/home/dev/proj/.envrc", "read", True), tool="Read"), "allow", id="envrc-is-fine"
    ),
    pytest.param(A(("/home/dev/proj/xenv", "read", True), tool="Read"), "allow", id="xenv-is-fine"),
    pytest.param(A(("/home/dev/proj/k.pem", "read", True), tool="Read"), "deny", id="pem"),
    pytest.param(
        A(("/home/dev/proj/src/a.py", "read", True), tool="Read"), "allow", id="read-inside"
    ),
    pytest.param(
        A(("/home/dev/proj/src/a.py", "read", None), tool="Read"), "gray", id="read-unsure"
    ),
    pytest.param(A(("/etc/hosts", "read", False), tool="Read"), "gray", id="read-outside-is-gray"),
    pytest.param(
        A(("/home/dev/proj/.claude/settings.json", "write", True), tool="Write"),
        "deny",
        id="guard-config-write",
    ),
    pytest.param(
        A(("/home/dev/.claude/settings.local.json", "write", False), tool="Edit"),
        "deny",
        id="user-guard-config-write",
    ),
    pytest.param(
        # Review round 2 (M-11): the settings files carry tokens in their "env" block, so the
        # project-internal allow rule no longer wins for reads (writes stay denied).
        A(("/home/dev/proj/.claude/settings.json", "read", True), tool="Read"),
        "deny",
        id="guard-config-read-is-denied",
    ),
    pytest.param(
        A(("/home/dev/proj/.claude/settings.json.bak", "read", True), tool="Read"),
        "allow",
        id="settings-backup-read-is-fine",
    ),
    pytest.param(
        A(("/home/dev/proj/.boundkeep/policy.yaml", "unknown", True), program="vim"),
        "deny",
        id="unknown-access-counts-as-write",
    ),
    pytest.param(A(("/home/dev/.bashrc", "write", False), program="tee"), "ask", id="bashrc"),
    pytest.param(
        A(("/home/dev/.ssh/authorized_keys", "write", False), tool="Write"), "ask", id="ssh-write"
    ),
    pytest.param(A(program="crontab"), "ask", id="crontab"),
    pytest.param(
        A(("/home/dev/proj", "write", True), program="rm", flags=("-r", "-f", "-rf")),
        "gray",
        id="rm-inside-project",
    ),
    pytest.param(
        A(("/", "write", False), program="rm", flags=("-r", "-f", "-rf")), "deny", id="rm-root"
    ),
    pytest.param(
        A(("/tmp/x*", "write", None), program="rm", flags=("-r",)), "deny", id="rm-unsure-path"
    ),
    pytest.param(A(("/tmp/x", "write", False), program="rm"), "ask", id="rm-single-outside"),
    pytest.param(
        A(program="git", subcommand="push", flags=("--force",)), "ask", id="git-force-push"
    ),
    pytest.param(A(program="git", subcommand="push", flags=("-v",)), "gray", id="git-push"),
    pytest.param(
        A(program="curl", network=True, domains=("evil.example",)), "ask", id="curl-stranger"
    ),
    pytest.param(
        A(program="curl", network=True, domains=("github.com",)), "gray", id="curl-allowlisted"
    ),
    pytest.param(
        A(program="curl", network=True, domains=("evilgithub.com",)), "ask", id="curl-lookalike"
    ),
    pytest.param(A(program="curl", network=True), "ask", id="curl-unknown-destination"),
    pytest.param(A(program="pytest"), "gray", id="pytest"),
    pytest.param(A(program="echo", command_text="BOUNDKEEP_CANARY"), "deny", id="canary"),
]


@pytest.mark.parametrize(("action", "expected"), DEFAULT_POSIX_CASES)
def test_default_policy_on_posix_actions(
    default_posix: Policy, action: Action, expected: str
) -> None:
    assert decide(default_posix, "posix", action) == expected


def test_default_policy_windows_rules(default_windows: Policy) -> None:
    ssh = win_action("c:/users/bob/.ssh/id_rsa", "read")
    assert decide(default_windows, "windows", ssh) == "deny"
    for key in (
        "c:/users/bob/appdata/roaming/microsoft/credentials/abc",
        "c:/users/bob/appdata/local/google/chrome/user data/default/login data",
        "c:/users/bob/appdata/local/microsoft/edge/user data/default/cookies",
        "c:/users/bob/appdata/roaming/mozilla/firefox/profiles/x.default/logins.json",
        "d:/windows/system32/config/sam",
        "c:/users/bob/.config/gh/hosts.yml",
    ):
        assert decide(default_windows, "windows", win_action(key, "read")) == "deny", key
    for key in (
        "c:/users/bob/documents/windowspowershell/microsoft.powershell_profile.ps1",
        "c:/users/bob/appdata/roaming/microsoft/windows/start menu/programs/startup/x.lnk",
        "c:/programdata/microsoft/windows/start menu/programs/startup/x.bat",
    ):
        assert (
            decide(default_windows, "windows", win_action(key, "write", tool="Write")) == "ask"
        ), key
    assert (
        decide(
            default_windows,
            "windows",
            win_action("c:/users/bob/documents/notes.txt", "write", tool="Write"),
        )
        == "gray"
    )
    assert decide(default_windows, "windows", A(program="schtasks", platform="windows")) == "ask"
    # No rule carries a platform filter: a Windows path seen by a POSIX daemon (WSL) is denied too,
    # by the home-independent patterns, whichever user and drive it names.
    for key in (
        "c:/users/bob/appdata/roaming/microsoft/credentials/abc",
        "c:/users/other/.ssh/config",
        "d:/users/x/appdata/local/google/chrome/user data/default/cookies",
        "c:/windows/system32/config/sam",
        "c:/windows/repair/sam",
    ):
        assert decide(default_windows, "posix", win_action(key, "read")) == "deny", key
    for key in (
        "c:/users/x/appdata/roaming/microsoft/windows/start menu/programs/startup/x.bat",
        "c:/users/x/documents/windowspowershell/profile.ps1",
    ):
        assert decide(default_windows, "posix", win_action(key, "write", tool="Write")) == "ask"
    # The posix browser locations hold on a Windows daemon too (they cannot match anything there
    # unless such a directory exists).
    posix_chrome = A(("c:/users/bob/.mozilla/firefox/p/x", "read", False), tool="Read")
    assert decide(default_windows, "windows", posix_chrome) == "deny"


def test_strict_policy_is_stricter(strict_posix: Policy, default_posix: Policy) -> None:
    cases = [
        (A(program="curl", network=True, domains=("github.com",)), "ask", "gray"),
        (A(program="git", subcommand="push", flags=("--force",)), "deny", "ask"),
        (A(program="git", subcommand="push"), "ask", "gray"),
        (A(("/home/dev/.bashrc", "write", False), program="tee"), "deny", "ask"),
        (A(("/tmp/x", "write", False), program="rm"), "deny", "ask"),
        (A(("/home/dev/proj/build", "write", True), program="rm", flags=("-r",)), "ask", "gray"),
        (A(("/home/dev/other/x.txt", "write", False), tool="Write"), "ask", "gray"),
        (A(("/home/dev/other/x.txt", "read", False), tool="Read"), "ask", "gray"),
    ]
    for action, strict_decision, default_decision in cases:
        assert decide(strict_posix, "posix", action) == strict_decision, action
        assert decide(default_posix, "posix", action) == default_decision, action
    inside = A(("/home/dev/proj/a.py", "read", True), tool="Read")
    assert decide(strict_posix, "posix", inside) == "allow"
    assert strict_posix.llm_audit.on_failure == "deny"


# ---------------------------------------------------------------------------- hypothesis

TOOLS = ["Bash", "PowerShell", "Read", "Write", "Edit", "WebFetch", "Glob", "mcp__srv__tool", "Odd"]
KEYS = [
    "/home/dev/.ssh/id_rsa",
    "/home/dev/proj/a.py",
    "/home/dev/proj/.env",
    "c:/users/bob/.ssh/id_rsa",
    "/x/.claude/settings.json",
    "/",
]
short_text = st.text(max_size=12)
key_strategy = st.one_of(
    st.sampled_from(KEYS),
    st.text(alphabet="ab./~:-_ ", max_size=24),
    short_text,
    st.just("\ud800/x"),
)
pathref_strategy = st.builds(
    PathRef,
    raw=short_text,
    key=key_strategy,
    flavor=st.sampled_from(["windows", "posix"]),
    access=st.sampled_from(["read", "write", "unknown"]),
    inside_project=st.sampled_from([True, False, None]),
    uncertain=st.booleans(),
)
action_strategy = st.builds(
    Action,
    tool=st.sampled_from(TOOLS),
    shell=st.sampled_from([None, "bash", "powershell"]),
    platform=st.sampled_from(["posix", "windows"]),
    program=st.one_of(
        st.none(), st.sampled_from(["rm", "git", "ls", "Remove-Item", "curl", "cat"]), short_text
    ),
    subcommand=st.one_of(st.none(), st.sampled_from(["push", "pull"]), short_text),
    flags=st.lists(
        st.one_of(st.sampled_from(["-r", "-rf", "-f", "--force", "-Recurse", "-l"]), short_text),
        max_size=4,
    ).map(tuple),
    paths=st.lists(pathref_strategy, max_size=3).map(tuple),
    domains=st.lists(
        st.one_of(st.sampled_from(["github.com", "evil.com", "pypi.org", "1.2.3.4"]), short_text),
        max_size=3,
    ).map(tuple),
    network=st.booleans(),
    gray=st.booleans(),
    gray_reasons=st.lists(short_text, max_size=2).map(tuple),
    mcp_server=st.one_of(st.none(), st.sampled_from(["srv", "github"]), short_text),
    command_text=st.one_of(st.none(), short_text, st.just("echo BOUNDKEEP_CANARY")),
)

HYP_ALLOW_RULES = [
    rdict("h-allow-ls", "allow", {"program": ["ls", "cat"]}),
    rdict("h-allow-read", "allow", {"path_inside_project": True}, tool=["Read", "Glob"]),
    rdict("h-allow-net", "allow", {"domain_in": ["github.com", "pypi.org"]}),
]


@pytest.fixture(scope="module")
def hyp_policies(default_posix: Policy, strict_posix: Policy) -> list[Policy]:
    extra_rules = [rdict(f"h-{i}", "deny", {"program": [p]}) for i, p in enumerate(["rm"])]
    mixed = policy_of(*HYP_ALLOW_RULES, *extra_rules)
    return [default_posix, strict_posix, mixed, policy_of(*HYP_ALLOW_RULES)]


@settings(max_examples=150, deadline=None)
@given(st.lists(action_strategy, max_size=4), st.sampled_from(["posix", "windows"]))
def test_matching_never_raises_and_returns_a_known_decision(
    hyp_policies: list[Policy], actions: list[Action], platform: str
) -> None:
    for policy in hyp_policies:
        verdict = evaluate(policy, actions, platform=platform)  # type: ignore[arg-type]
        assert verdict.decision in {"deny", "ask", "allow", "gray"}
        for rule in policy.rules:
            for action in actions:
                assert match_rule(rule, action, platform=platform) in (True, False)  # type: ignore[arg-type]


@settings(max_examples=200, deadline=None)
@given(st.lists(action_strategy, max_size=4), st.sampled_from(["posix", "windows"]))
def test_never_allow_unless_every_action_is_positively_allowed(
    hyp_policies: list[Policy], actions: list[Action], platform: str
) -> None:
    for policy in hyp_policies:
        verdict = evaluate(policy, actions, platform=platform)  # type: ignore[arg-type]
        if verdict.decision != "allow":
            continue
        assert actions, "an empty list must be gray"
        for action, result in zip(actions, verdict.actions, strict=True):
            assert not action.gray
            assert "BOUNDKEEP_CANARY" not in (action.command_text or "")
            kinds = {hit.decision for hit in result.hits}
            assert "allow" in kinds
            assert not kinds & {"deny", "ask"}
            assert any(
                match_rule(rule, action, platform=platform)  # type: ignore[arg-type]
                for rule in policy.rules
                if rule.action == "allow"
            )


@settings(max_examples=150, deadline=None)
@given(action_strategy, st.sampled_from(["posix", "windows"]))
def test_allow_rules_never_match_a_gray_action(
    hyp_policies: list[Policy], action: Action, platform: str
) -> None:
    gray = action.model_copy(update={"gray": True})
    for policy in hyp_policies:
        for rule in policy.rules:
            if rule.action == "allow":
                assert not match_rule(rule, gray, platform=platform)  # type: ignore[arg-type]
        assert evaluate(policy, [gray], platform=platform).decision != "allow"  # type: ignore[arg-type]


@settings(max_examples=100, deadline=None)
@given(st.lists(action_strategy, min_size=1, max_size=4), st.randoms(use_true_random=False))
def test_action_order_does_not_change_the_decision(
    hyp_policies: list[Policy], actions: list[Action], rnd: Any
) -> None:
    shuffled = list(actions)
    rnd.shuffle(shuffled)
    for policy in hyp_policies:
        assert (
            evaluate(policy, actions, platform="posix").decision
            == evaluate(policy, shuffled, platform="posix").decision
        )


def test_hypothesis_actions_cover_the_interesting_decisions(hyp_policies: list[Policy]) -> None:
    """Guards the property tests above against silently generating only gray verdicts."""
    seen: set[str] = set()
    for action in [
        A(program="ls"),
        A(program="rm"),
        A(program="curl", network=True),
        A(program="zzz"),
        A(("/home/dev/proj/a", "read", True), tool="Read"),
    ]:
        seen.add(evaluate(hyp_policies[2], [action], platform="posix").decision)
    assert seen >= {"allow", "deny", "gray"}


# ---------------------------------------------------------------------------- review fixes
# Everything below pins a finding of the M1 review round (null fields, silent never-match typos,
# dead globs, per-path correlation, allow rules and wrappers, secret scan, tool-agnostic rules).


def _rule_text(match: str, *, head: str = "", action: str = "deny") -> str:
    reason = "" if action == "allow" else "    reason: why\n"
    return f"rules:\n  - id: r1\n{head}    action: {action}\n{reason}    match:\n{match}"


NULL_CASES: list[Any] = [
    pytest.param(
        _rule_text("      program: cat\n      path_inside_project:\n", action="allow"),
        "rules[0].match.path_inside_project",
        "path_inside_project",
        id="blank-bool-widens-an-allow-rule",
    ),
    pytest.param(
        _rule_text("      program: cat\n      path_inside_project: null\n", action="allow"),
        "rules[0].match.path_inside_project",
        "path_inside_project",
        id="explicit-null-bool",
    ),
    pytest.param(
        _rule_text("      program: cat\n      path_inside_project: ~\n", action="allow"),
        "rules[0].match.path_inside_project",
        "path_inside_project",
        id="tilde-null-bool",
    ),
    pytest.param(
        _rule_text("      network: true\n      program:\n"),
        "rules[0].match.program",
        "program",
        id="blank-program",
    ),
    pytest.param(
        _rule_text("      path_glob: ['**/x']\n      access:\n"),
        "rules[0].match.access",
        "access",
        id="blank-access",
    ),
    pytest.param(
        _rule_text("      network: true\n      path_glob:\n"),
        "rules[0].match.path_glob",
        "path_glob",
        id="blank-path-glob",
    ),
    pytest.param(
        _rule_text("      network: true\n      domain_not_in:\n"),
        "rules[0].match.domain_not_in",
        "domain_not_in",
        id="blank-domain-list",
    ),
    pytest.param(
        _rule_text("      network: true\n", head="    tool:\n"),
        "rules[0].tool",
        "tool:",
        id="blank-tool-means-all-tools",
    ),
    pytest.param(
        _rule_text("      network: true\n", head="    platform:\n"),
        "rules[0].platform",
        "platform:",
        id="blank-platform-means-all-platforms",
    ),
]


@pytest.mark.parametrize(("body", "path", "marker"), NULL_CASES)
def test_a_null_or_blank_field_is_an_error_not_a_dropped_condition(
    body: str, path: str, marker: str
) -> None:
    text = "version: 1\n" + body
    with pytest.raises(PolicyError) as info:
        parse_policy_text(text, home=POSIX_HOME)
    message = str(info.value)
    assert path in message, message
    assert "null" in message, message
    assert info.value.line == line_of(text, marker), message


def test_null_fields_are_refused_by_direct_validation_too() -> None:
    base: dict[str, Any] = {"id": "r1", "action": "ask", "reason": "x"}
    for match in ({"program": None}, {"network": True, "access": None}, {"path_glob": None}):
        with pytest.raises(ValidationError, match="null"):
            Rule.model_validate({**base, "match": match})
    for extra in ({"tool": None}, {"platform": None}):
        with pytest.raises(ValidationError, match="null"):
            Rule.model_validate({**base, "match": {"network": True}, **extra})


TOOL_ERRORS: list[Any] = [
    pytest.param("[Bsh]", ["rules[0].tool[0]", "unknown tool 'Bsh'", "did you mean 'Bash'"]),
    pytest.param("[bash]", ["unknown tool 'bash'", "did you mean 'Bash'"]),
    pytest.param("[Read, Wite]", ["rules[0].tool[1]", "did you mean 'Write'"]),
    pytest.param("[PowerShel]", ["did you mean 'PowerShell'"]),
    pytest.param("[Zzz*]", ["rules[0].tool[0]", "unknown tool pattern 'Zzz*'"]),
    pytest.param("[mcp_srv__x]", ["unknown tool 'mcp_srv__x'"]),
    pytest.param("[Qqqq]", ["unknown tool 'Qqqq'", "known tools"]),
]


@pytest.mark.parametrize(("tools", "needles"), TOOL_ERRORS)
def test_an_unknown_tool_name_is_a_load_error_with_a_suggestion(
    tools: str, needles: list[str]
) -> None:
    text = "version: 1\n" + _rule_text("      network: true\n", head=f"    tool: {tools}\n")
    with pytest.raises(PolicyError) as info:
        parse_policy_text(text, home=POSIX_HOME)
    message = str(info.value)
    for needle in needles:
        assert needle in message, message
    assert info.value.line == line_of(text, "tool:")


def test_every_known_tool_and_mcp_pattern_is_accepted() -> None:
    names = (
        "[Bash, PowerShell, Read, Write, Edit, MultiEdit, NotebookEdit, Glob, Grep, WebFetch, "
        "WebSearch, ToolSearch, TodoWrite, Agent, 'mcp__*', mcp__github__create_issue, "
        "'mcp__gh*', 'mcp*', 'Re*', 'Web*']"
    )
    policy = pol(_rule_text("      network: true\n", head=f"    tool: {names}\n"))
    assert policy.rules[0].tool is not None
    assert len(policy.rules[0].tool) == 20


def test_flags_must_look_like_flags() -> None:
    for bad in ("force", "'f'", "'rf'", "Recurse"):
        text = "version: 1\n" + _rule_text(f"      program: rm\n      flags_any: [{bad}]\n")
        with pytest.raises(PolicyError) as info:
            parse_policy_text(text, home=POSIX_HOME)
        assert "rules[0].match.flags_any[0]" in str(info.value)
        assert "must start with '-'" in str(info.value)
    ok = pol(
        _rule_text("      program: rm\n      flags_any: ['-r', '--force', '-Recurse', '--']\n")
    )
    assert ok.rules[0].match.flags_any == ("-r", "--force", "-Recurse", "--")


@pytest.mark.parametrize("bad", ["git push", "/bin/rm", "bin\\rm", "a/b", "'rm '", "'a\tb'"])
def test_a_program_name_has_no_spaces_or_path_separators(bad: str) -> None:
    text = "version: 1\n" + _rule_text(f"      program: [{bad}]\n")
    with pytest.raises(PolicyError) as info:
        parse_policy_text(text, home=POSIX_HOME)
    assert "rules[0].match.program[0]" in str(info.value)
    assert "program name" in str(info.value)


def test_a_subcommand_is_one_word() -> None:
    text = "version: 1\n" + _rule_text(
        "      program: docker\n      subcommand: ['system prune']\n"
    )
    with pytest.raises(PolicyError, match=r"rules\[0\]\.match\.subcommand\[0\].*one word"):
        parse_policy_text(text, home=POSIX_HOME)


def test_program_names_with_dots_and_dashes_are_fine() -> None:
    policy = pol(_rule_text("      program: [mkfs.ext4, Remove-Item, python3.12, g++]\n"))
    assert policy.rules[0].match.program == ("mkfs.ext4", "Remove-Item", "python3.12", "g++")


@pytest.mark.parametrize(
    "match",
    [
        "      path_glob: ['**/x']\n      access: read\n",
        "      path_glob: ['**/x']\n",
        "      path_outside_project: true\n",
        "      path_inside_project: true\n",
    ],
)
def test_path_conditions_on_tools_that_never_touch_paths_are_errors(match: str) -> None:
    text = "version: 1\n" + _rule_text(match, head="    tool: [WebSearch, Agent]\n")
    with pytest.raises(PolicyError) as info:
        parse_policy_text(text, home=POSIX_HOME)
    assert "rules[0].tool" in str(info.value)
    assert "never touch" in str(info.value)
    # One tool that does touch paths is enough, and so is no tool filter at all.
    assert len(pol(_rule_text(match, head="    tool: [WebSearch, Read]\n")).rules) == 1
    assert len(pol(_rule_text(match)).rules) == 1


def test_inside_and_outside_together_can_never_match() -> None:
    text = "version: 1\n" + _rule_text(
        "      path_outside_project: true\n      path_inside_project: true\n"
    )
    with pytest.raises(PolicyError, match=r"rules\[0\]\.match.*can never match"):
        parse_policy_text(text, home=POSIX_HOME)


@pytest.mark.parametrize(
    ("pattern", "needle"),
    [
        ("~/.ssh/../.aws/**", "'..'"),
        ("**/./x", "'.'"),
        ("~/a//b", "empty"),
        ("/a/b/..", "'..'"),
        ("/a/./b", "'.'"),
        ("c:/users/../x/**", "'..'"),
        ("///etc/x", "empty"),
        ("  /etc/x", "whitespace"),
        ("/etc/x ", "whitespace"),
        ("**/x\n", "whitespace"),
    ],
)
def test_globs_that_can_never_match_a_canonical_key_are_refused(pattern: str, needle: str) -> None:
    text = "version: 1\n" + _rule_text(f"      path_glob: [{json.dumps(pattern)}]\n")
    with pytest.raises(PolicyError) as info:
        parse_policy_text(text, home=POSIX_HOME)
    message = str(info.value)
    assert "rules[0].match.path_glob[0]" in message, message
    assert needle in message, message


@pytest.mark.parametrize(
    "pattern",
    [
        "//server/share/**",
        "//./physicaldrive*",
        "/a/**",
        "**/.env",
        "?:/windows/**",
        "c:/users/**",
        "~",
        "~/.ssh/**",
    ],
)
def test_ordinary_globs_are_still_fine(pattern: str) -> None:
    policy = pol(_rule_text(f"      path_glob: [{json.dumps(pattern)}]\n"))
    assert policy.rules[0].match.path_glob


# ---- per-path correlation


def match_of(match: dict[str, Any], action: str = "ask") -> Rule:
    return make_rule(match, action=action)


def cp_like(*paths: tuple[str, str, bool | None]) -> Action:
    return A(*paths, program="cp")


STRICT_WRITE_OUTSIDE = {"path_glob": ["**"], "access": "write", "path_outside_project": True}


def test_write_outside_needs_the_same_path_to_be_written_and_outside() -> None:
    rule = match_of(STRICT_WRITE_OUTSIDE)
    # cp /tmp/src.txt ./dest.txt: the READ source is outside, the WRITE target is inside.
    inside_target = cp_like(
        ("/tmp/src.txt", "read", False), ("/home/dev/proj/dest.txt", "write", True)
    )
    assert not match_rule(rule, inside_target, platform="posix")
    # cp ./src.txt /tmp/dest.txt: now the written path is outside.
    outside_target = cp_like(
        ("/home/dev/proj/src.txt", "read", True), ("/tmp/dest.txt", "write", False)
    )
    assert match_rule(rule, outside_target, platform="posix")
    # unknown access may be a write; unsure inside counts as outside
    assert match_rule(rule, cp_like(("/x", "unknown", False)), platform="posix")
    assert match_rule(rule, cp_like(("/x", "write", None)), platform="posix")
    assert not match_rule(rule, cp_like(("/x", "read", False)), platform="posix")
    assert not match_rule(rule, cp_like(), platform="posix")


def test_glob_and_outside_must_hold_for_one_path() -> None:
    rule = match_of({"path_glob": ["**/*.md"], "path_outside_project": True})
    split = cp_like(("/home/dev/proj/a.md", "read", True), ("/tmp/b.txt", "write", False))
    assert not match_rule(rule, split, platform="posix")  # the .md is inside, the outside is .txt
    assert match_rule(rule, cp_like(("/tmp/a.md", "read", False)), platform="posix")
    both = cp_like(("/home/dev/proj/a.md", "read", True), ("/tmp/b.md", "read", None))
    assert match_rule(rule, both, platform="posix")


def test_glob_access_and_outside_all_on_one_path() -> None:
    rule = match_of({"path_glob": ["/etc/**"], "access": "write", "path_outside_project": True})
    action = cp_like(("/etc/hosts", "read", False), ("/etc/new", "write", True))
    assert not match_rule(rule, action, platform="posix")  # a read of /etc, a write "inside"
    assert match_rule(rule, cp_like(("/etc/hosts", "write", False)), platform="posix")
    assert not match_rule(rule, cp_like(("/etc/hosts", "write", True)), platform="posix")


def test_inside_with_glob_means_every_path_inside_and_one_path_matching() -> None:
    rule = match_of({"path_glob": ["**/*.md"], "path_inside_project": True}, action="allow")
    inside = "/home/dev/proj"
    assert match_rule(rule, A((f"{inside}/a.md", "read", True)), platform="posix")
    both = A((f"{inside}/a.md", "read", True), (f"{inside}/b.py", "read", True))
    assert match_rule(rule, both, platform="posix")
    assert not match_rule(rule, A((f"{inside}/a.py", "read", True)), platform="posix")
    mixed = A((f"{inside}/a.md", "read", True), ("/etc/passwd", "read", False))
    assert not match_rule(rule, mixed, platform="posix")
    assert not match_rule(rule, A((f"{inside}/a.md", "read", None)), platform="posix")


def test_inside_with_access_requires_a_compatible_path_that_matches() -> None:
    rule = match_of(
        {"path_glob": ["**"], "access": "read", "path_inside_project": True}, action="allow"
    )
    assert match_rule(rule, A(("/p/a", "read", True)), platform="posix")
    assert not match_rule(rule, A(("/p/a", "write", True)), platform="posix")
    assert match_rule(rule, A(("/p/a", "write", True), ("/p/b", "read", True)), platform="posix")


def test_outside_alone_still_means_any_path_and_the_explain_text_names_it() -> None:
    rule = match_of({"path_outside_project": True})
    action = A(("/p/a", "read", True), ("/tmp/b", "write", False))
    lines = explain_rule(rule, action, platform="posix")
    assert lines is not None
    assert any("/tmp/b" in line and "outside" in line for line in lines)


def test_correlated_explain_lines_name_the_one_path() -> None:
    rule = match_of(STRICT_WRITE_OUTSIDE)
    action = cp_like(("/tmp/src", "read", False), ("/tmp/dst", "write", False))
    lines = explain_rule(rule, action, platform="posix")
    assert lines is not None
    assert any(line.startswith("path_glob: /tmp/dst ~ **") for line in lines)
    assert any("/tmp/dst" in line and "outside" in line for line in lines)
    assert not any("/tmp/src" in line for line in lines)


def test_an_overlong_key_still_matches_deny_and_ask_correlation_but_not_allow() -> None:
    key = "/" + "a" * (MAX_KEY_LENGTH + 1)
    action = A((key, "write", False))
    assert match_rule(match_of(STRICT_WRITE_OUTSIDE), action, platform="posix")
    allow = match_of({"path_glob": ["**"], "path_inside_project": True}, action="allow")
    assert not match_rule(allow, A((key, "read", True)), platform="posix")


# ---- allow rules and wrappers


@pytest.mark.parametrize(
    "wrappers", [("sudo",), ("env",), ("sudo", "env"), ("nohup", "time"), ("whatever",)]
)
def test_an_allow_rule_never_matches_a_wrapped_action(wrappers: tuple[str, ...]) -> None:
    allow = make_rule({"program": ["ls"]}, action="allow")
    assert match_rule(allow, A(program="ls"), platform="posix")
    wrapped = A(program="ls", wrappers=wrappers)
    assert not match_rule(allow, wrapped, platform="posix")
    policy = policy_of(rdict("allow-ls", "allow", {"program": ["ls"]}))
    assert evaluate(policy, [wrapped], platform="posix").decision == "gray"
    path_allow = make_rule({"path_inside_project": True}, action="allow", tool=["Read"])
    read = A(("/p/a", "read", True), tool="Read", wrappers=wrappers)
    assert not match_rule(path_allow, read, platform="posix")


def test_deny_and_ask_rules_still_see_a_wrapped_action() -> None:
    wrapped = A(("/", "write", False), program="rm", flags=("-r",), wrappers=("sudo",))
    for action in ("deny", "ask"):
        rule = make_rule({"program": ["rm"], "path_outside_project": True}, action=action)
        assert match_rule(rule, wrapped, platform="posix")


# ---- secret scan


def more_secrets() -> dict[str, str]:
    return {
        "npm": "np" + "m_" + "A1b2" * 9,
        "gitlab": "gl" + "pat-" + "x9" * 12,
        "stripe": "sk" + "_live_" + "a1B2c3D4" * 3,
        "stripe-restricted": "rk" + "_live_" + "a1B2c3D4" * 3,
        "basic-auth": "Authoriz" + "ation: Bas" + "ic " + "dXNlcjpwYXNzd29yZDEyMzQ1Njc4OTA=",
        "hex-key": "private" + "_key: " + "a1b2c3d4" * 8,
        "secret-key-hex": "secret" + "-key=" + "0f" * 32,
    }


def test_the_extra_test_secrets_do_not_appear_whole_in_this_file() -> None:
    source = Path(__file__).read_text(encoding="utf-8")
    assert all(value not in source for value in more_secrets().values())


@pytest.mark.parametrize("name", sorted(more_secrets()))
def test_more_secret_shapes_are_refused(name: str) -> None:
    secret = more_secrets()[name]
    text = (
        "version: 1\nrules:\n  - id: r1\n    action: deny\n"
        f"    reason: {json.dumps('see ' + secret)}\n    match: {{network: true}}\n"
    )
    with pytest.raises(PolicyError) as info:
        parse_policy_text(text, home=POSIX_HOME)
    message = str(info.value)
    assert "looks like" in message
    assert secret not in message
    assert find_secret({"k": secret}) is not None


def test_a_long_hex_value_under_a_key_name_is_a_secret() -> None:
    value = "a1b2c3d4" * 8
    for key in ("private_key", "key", "secret_key", "signing_key", "seed", "PrivateKey"):
        assert find_secret({key: value}) is not None, key
    assert find_secret({"private_key_file": value}) is None
    assert find_secret({"commit": value}) is None  # an innocent key name: a hash
    assert find_secret({"key": "a1b2c3d4" * 7}) is None  # not 64 characters


def test_test_inputs_may_contain_secret_shaped_text_but_nothing_else_may() -> None:
    secret = secrets_for_tests()["github"]
    entry = {
        "tool": "Bash",
        "input": {"command": "echo " + secret, "nested": [secret], secret: 1},
        "expect": "gray",
    }

    def parse(data: dict[str, Any]) -> Policy:
        return parse_policy_text(
            json.dumps({"version": 1, **data}), home=POSIX_HOME
        )  # JSON is YAML

    assert len(parse({"tests": [entry]}).tests) == 1
    # ... but the same value in any other field of a test, or anywhere else, is still refused.
    for field in ("cwd", "project_dir"):
        bad = {"tests": [{**entry, "input": {"command": "ls"}, field: "/x/" + secret}]}
        with pytest.raises(PolicyError, match="looks like"):
            parse(bad)
    rule = {"id": "r", "action": "deny", "reason": secret, "match": {"network": True}}
    with pytest.raises(PolicyError, match="looks like"):
        parse({"tests": [entry], "rules": [rule]})
    with pytest.raises(ValidationError, match="looks like"):
        Policy.model_validate({"version": 1, "rules": [rule]})
    # find_secret itself skips nothing by default
    assert find_secret({"tests": [{"input": {"command": secret}}]}) is not None


@pytest.mark.parametrize(
    "reason",
    [
        "credentials: /home/user/.aws/credentials/foo",
        "token: /var/run/secrets/kubernetes.io/serviceaccount/token",
        "password: ~/.config/some/password-store/entry",
        "secret=reading_the_credentials_file_is_not_allowed",
        "credential: C:/Users/bob/AppData/Roaming/Microsoft/Credentials/ABCDEF",
        "authorization: basic authentication handling is not touched here",
        "see the sha256 of the policy: " + "a1b2c3d4" * 8,
    ],
)
def test_reason_text_that_merely_mentions_credentials_is_not_a_secret(reason: str) -> None:
    assert find_secret({"reason": reason}) is None, reason
    text = (
        "version: 1\nrules:\n  - id: r\n    action: deny\n"
        f"    reason: {json.dumps(reason)}\n    match: {{network: true}}\n"
    )
    assert parse_policy_text(text, home=POSIX_HOME).rules[0].reason == reason


def test_the_assignment_shape_still_catches_a_real_looking_value() -> None:
    for text in (
        "token=" + "a1" * 15,
        "api_key: " + "Zx9" * 8,
        "password = '" + "q1" * 12 + "'",
        "client_secret: " + "AbC123" * 5,
    ):
        assert find_secret({"reason": text}) is not None, text


# ---- the shipped policies: tool-agnostic secret rules


@pytest.mark.parametrize("name", POLICY_FILES)
def test_read_deny_and_ask_rules_do_not_filter_by_tool(name: str) -> None:
    """A tool filter on a read rule lets Grep, Glob or another tool walk around it."""
    policy = parse_policy_text(read_policy_text(name), home=POSIX_HOME)
    read_rules = [
        r for r in policy.rules if r.action in ("deny", "ask") and r.match.access == "read"
    ]
    assert len(read_rules) >= 5
    for rule in read_rules:
        assert rule.tool is None, rule.id
    for rule in policy.rules:
        if rule.match.path_glob is not None and rule.action != "allow" and not rule.match.program:
            assert rule.tool is None, rule.id  # path rules: whichever tool carries the path
        assert rule.platform is None, rule.id  # globs that cannot match on a host need no filter


@pytest.mark.parametrize("name", POLICY_FILES)
@pytest.mark.parametrize("tool", ["Read", "Grep", "Glob", "Bash", "WebFetch", "Edit"])
def test_secret_reads_are_denied_whichever_tool_carries_the_path(name: str, tool: str) -> None:
    policy = parse_policy_text(read_policy_text(name), home=POSIX_HOME)
    for key in (
        "/home/dev/proj/.env",
        "/home/dev/proj/certs/server.pem",
        "/home/dev/.ssh/id_rsa",
        "/home/dev/.aws/credentials",
        "/home/dev/.claude/.credentials.json",
    ):
        action = A((key, "read", True), tool=tool)
        assert decide(policy, "posix", action) == "deny", (tool, key)


def test_strict_write_outside_does_not_fire_for_a_copy_into_the_project(
    strict_posix: Policy, default_posix: Policy
) -> None:
    """The reviewed false positive: cp /tmp/src.txt ./dest.txt only READS the outside path."""
    into = cp_like(("/tmp/src.txt", "read", False), ("/home/dev/proj/dest.txt", "write", True))
    out_of = cp_like(("/home/dev/proj/src.txt", "read", True), ("/tmp/dest.txt", "write", False))
    into_ids = evaluate(strict_posix, [into], platform="posix").rule_ids
    assert "ask-write-outside-project" not in into_ids
    assert "ask-read-outside-project" in into_ids  # still asks, for the right reason
    assert (
        "ask-write-outside-project" in evaluate(strict_posix, [out_of], platform="posix").rule_ids
    )
    assert evaluate(default_posix, [into], platform="posix").decision == "gray"


def test_the_shipped_policies_never_allow_a_wrapped_command(default_posix: Policy) -> None:
    wrapped = A(("/home/dev/proj/a", "read", True), tool="Read", wrappers=("sudo",))
    assert decide(default_posix, "posix", wrapped) == "gray"
    assert (
        decide(default_posix, "posix", A(("/home/dev/proj/a", "read", True), tool="Read"))
        == "allow"
    )
