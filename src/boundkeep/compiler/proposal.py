"""Read a policy proposal (PROJECT_SPEC.md §8.1): new rules and tests, nothing else.

A proposal is hostile input twice over: an LLM wrote it, from a sentence that may carry a prompt
injection, or the user pasted it back from a tool of their choice. It is read with the policy
file's own strict YAML reader (no duplicate keys, anchors, aliases, tags or merge keys; bounded
size, depth and node count) and then:

* the top level holds ``proposal: 1``, ``rules`` (1 to ``MAX_RULES``), optional ``tests`` (up to
  ``MAX_TESTS``), ``summary`` and ``impact`` (shown, never trusted); a policy key (``defaults``,
  ``trusted_projects``, ``mode`` ...) is refused with the command or edit that changes it, since a
  proposal may only ADD rules and tests;
* a string shaped like a secret is refused anywhere, the ``input`` of a test included (the policy
  file skips test inputs, a proposal does not);
* rules and tests must be valid in the policy schema on their own (``Policy`` with just them);
  whether they fit the current policy (ids, limits) is ``checks``' business.

An answer pasted with Markdown around it is accepted when it holds exactly one fenced ``yaml``
block: only that block is read. The JSON a backend returns is turned into YAML text first
(``text_from_json``), so both sources are read, reported (line numbers) and saved the same way.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Final, Literal

import yaml
from pydantic import ValidationError

from boundkeep.policy.loader import (
    PolicyError,
    describe_validation_error,
    node_line,
    read_strict_mapping,
    secret_location,
)
from boundkeep.policy.schema import Policy
from boundkeep.policy.secretscan import find_secret

FORMAT_VERSION: Final = 1
MAX_PROPOSAL_CHARS: Final = 64 * 1024
MAX_RULES: Final = 20
MAX_TESTS: Final = 300
MAX_SUMMARY_CHARS: Final = 500
MAX_IMPACT_CHARS: Final = 2000
_NEUTRAL_HOME: Final = "/home/boundkeep-proposal-check"

# Policy keys a proposal must not carry, and where the user changes them instead.
POLICY_KEYS: Final[dict[str, str]] = {
    "version": "it is part of the policy file, not of a proposal",
    "mode": "use 'boundkeep mode' in your terminal",
    "defaults": "edit the policy file yourself (defaults.emit_allow decides whether boundkeep "
    "approves calls on Claude Code's behalf)",
    "llm_audit": "edit the policy file yourself",
    "taint": "edit the policy file yourself",
    "trusted_projects": "use 'boundkeep trust add' in your terminal",
    "mcp_read_only": "edit the policy file yourself",
}
_KEYS: Final = ("proposal", "summary", "impact", "rules", "tests")

_FENCE = re.compile(r"^[ \t]*```[ \t]*(yaml|yml)[ \t]*\r?\n(.*?)^[ \t]*```[ \t]*$", re.M | re.S)
_ANY_FENCE = re.compile(r"^[ \t]*```", re.M)

Code = Literal["parse", "secret"]


class ProposalError(Exception):
    """A proposal that cannot be used. ``str()`` is safe to print: no proposal text in it."""

    def __init__(self, reason: str, *, line: int | None = None, code: Code = "parse") -> None:
        self.reason = reason
        self.line = line
        self.code: Code = code
        super().__init__(f"line {line}: {reason}" if line is not None else reason)


@dataclass(frozen=True)
class Proposal:
    """A proposal that passed the reader. ``rules`` / ``tests`` are the mappings as written (the
    writer serializes these, not the validated models, whose globs have ``~`` expanded)."""

    text: str
    summary: str | None
    impact: str | None
    rules: tuple[dict[str, Any], ...]
    tests: tuple[dict[str, Any], ...]

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(str(rule["id"]) for rule in self.rules)


def extract_yaml(text: str) -> str:
    """The text to read: the one fenced ``yaml`` block of a pasted answer, or ``text`` itself."""
    blocks = _FENCE.findall(text)
    if len(blocks) > 1:
        raise ProposalError("the text holds more than one ```yaml block; keep only the proposal")
    if blocks:
        return str(blocks[0][1])
    if _ANY_FENCE.search(text):
        raise ProposalError(
            "the text has a ``` fence but no ```yaml block; save only the YAML of the proposal"
        )
    return text


def parse_proposal_text(text: str, *, home: str | None = None) -> Proposal:
    """Read and validate ``text`` (see the module docstring). Raises only ``ProposalError``."""
    if not isinstance(text, str):
        raise ProposalError("the proposal must be text")
    if len(text) > MAX_PROPOSAL_CHARS:
        raise ProposalError(f"the proposal is longer than {MAX_PROPOSAL_CHARS} characters")
    body = extract_yaml(text)
    try:
        data, root = read_strict_mapping(body, limit=MAX_PROPOSAL_CHARS, what="proposal")
    except PolicyError as exc:
        raise ProposalError(exc.reason, line=exc.line) from None
    _check_keys(data, root)
    found = find_secret(data)
    if found is not None:
        location, kind = found
        raise ProposalError(
            f"{secret_location(location)} looks like {kind}; a proposal must not carry secrets "
            "(test inputs included)",
            line=node_line(root, location),
            code="secret",
        )
    rules = data["rules"]
    tests = data.get("tests", [])
    try:
        Policy.model_validate(
            {"version": 1, "rules": rules, "tests": tests},
            context={"home": home or _NEUTRAL_HOME},
        )
    except ValidationError as exc:
        error = describe_validation_error(exc, root, "proposal")
        raise ProposalError(error.reason, line=error.line) from None
    except Exception as exc:  # noqa: BLE001 - "ProposalError or a Proposal", like the loader
        raise ProposalError(f"invalid proposal ({type(exc).__name__})") from None
    return Proposal(
        text=body,
        summary=data.get("summary"),
        impact=data.get("impact"),
        rules=tuple(rules),
        tests=tuple(tests),
    )


def _check_keys(data: dict[Any, Any], root: yaml.MappingNode) -> None:
    def line_of(key: str) -> int | None:
        return node_line(root, (key,))

    for key in data:
        if not isinstance(key, str):
            raise ProposalError("every top-level key must be a word")
        if key in POLICY_KEYS:
            raise ProposalError(
                f"a proposal may only add rules and tests; '{key}' is not one of them "
                f"({POLICY_KEYS[key]})",
                line=line_of(key),
            )
        if key not in _KEYS:
            shown = ascii(key[:40])[1:-1]
            raise ProposalError(
                f"unknown key '{shown}' (a proposal has proposal, summary, impact, rules and "
                "tests)",
                line=line_of(key),
            )
    version = data.get("proposal")
    if type(version) is not int or version != FORMAT_VERSION:
        raise ProposalError(
            f"the proposal must start with 'proposal: {FORMAT_VERSION}' (the format version)",
            line=line_of("proposal") if "proposal" in data else None,
        )
    rules = data.get("rules")
    if isinstance(rules, list) and not rules and isinstance(data.get("summary"), str):
        # a proposer that cannot do what was asked says so in the summary
        said = "".join(ch if ch.isprintable() else "?" for ch in data["summary"][:300])
        raise ProposalError(f"the proposal adds no rule; the proposer says: {said}")
    if not isinstance(rules, list) or not rules:
        raise ProposalError("'rules' must be a list of at least one new rule")
    if len(rules) > MAX_RULES:
        raise ProposalError(f"a proposal adds at most {MAX_RULES} rules", line=line_of("rules"))
    if not all(isinstance(rule, dict) for rule in rules):
        raise ProposalError("every entry of 'rules' must be a mapping", line=line_of("rules"))
    tests = data.get("tests", [])
    if not isinstance(tests, list):
        raise ProposalError("'tests' must be a list", line=line_of("tests"))
    if len(tests) > MAX_TESTS:
        raise ProposalError(f"a proposal adds at most {MAX_TESTS} tests", line=line_of("tests"))
    if not all(isinstance(test, dict) for test in tests):
        raise ProposalError("every entry of 'tests' must be a mapping", line=line_of("tests"))
    for key, limit in (("summary", MAX_SUMMARY_CHARS), ("impact", MAX_IMPACT_CHARS)):
        value = data.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            raise ProposalError(f"'{key}' must be text", line=line_of(key))
        if len(value) > limit:
            raise ProposalError(f"'{key}' is longer than {limit} characters", line=line_of(key))


def text_from_json(obj: object) -> str:
    """The YAML text of a proposal a backend returned as JSON (an object): the same reader then
    reads it, and ``--out`` saves it. Raises ``ProposalError`` for anything but an object."""
    if not isinstance(obj, dict):
        raise ProposalError("the backend's proposal is not a JSON object")
    ordered = {key: obj[key] for key in _KEYS if key in obj}
    ordered |= {key: value for key, value in obj.items() if key not in ordered}
    try:
        return yaml.safe_dump(
            ordered, sort_keys=False, allow_unicode=True, default_flow_style=False, width=100
        )
    except (yaml.YAMLError, RecursionError, ValueError, TypeError):
        # RecursionError: a reply nested hundreds of levels deep (json reads ~1000)
        raise ProposalError("the backend's proposal cannot be written as YAML") from None


def shown(text: str) -> str:
    """``text`` for a terminal: every character that does not print (controls, bidi overrides,
    zero-width characters) as ``\\uXXXX``, so what is shown cannot differ unseen from what is
    written (R44-6)."""
    return "".join(ch if ch.isprintable() else f"\\u{ord(ch):04x}" for ch in text)


def dump_rule(rule: dict[str, Any], indent: int) -> list[str]:
    """``rule`` as block YAML lines, the first one starting with ``- `` at ``indent``."""
    text = yaml.safe_dump(
        [rule], sort_keys=False, allow_unicode=True, default_flow_style=False, width=1000
    )
    pad = " " * indent
    return [pad + line for line in text.splitlines()]


def dump_test(test: dict[str, Any], indent: int) -> str:
    """``test`` as one flow-style line (``- { tool: ..., expect: ... }``), as the shipped policies
    write their tests."""
    text = json.dumps(test, ensure_ascii=False)
    # JSON is valid YAML flow syntax; yaml.safe_dump would fold long lines
    return " " * indent + "- " + text
