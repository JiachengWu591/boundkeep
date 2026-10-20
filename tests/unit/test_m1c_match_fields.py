"""M1c: the ``flags_none`` and ``paths_read_only`` match fields (allow rules for everyday use).

* ``flags_none``: same entries and case folding as ``flags_any``; matches only if NONE of the
  action's flags equals a listed one (no flags: matches).
* ``paths_read_only: true``: matches only if EVERY path has access exactly ``read`` (``write`` and
  ``unknown`` do not count; no paths: matches).

Actions are built by hand. The flags below are made-up names on purpose: no test here says anything
about what a real program's switch does.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from boundkeep.normalize.model import Action, PathRef
from boundkeep.policy import (
    Policy,
    PolicyError,
    Rule,
    evaluate,
    explain_rule,
    match_rule,
    parse_policy_text,
)
from boundkeep.policy import matcher as matcher_module

HOME = "/home/dev"
INSIDE_R = ("/proj/a.txt", "read", True)
INSIDE_W = ("/proj/a.txt", "write", True)
INSIDE_U = ("/proj/a.txt", "unknown", True)
OUTSIDE_R = ("/etc/hosts", "read", False)


def act(*paths: tuple[str, str, bool | None], **fields: Any) -> Action:
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


def rule_of(match: dict[str, Any], *, action: str = "allow", tool: list[str] | None = None) -> Rule:
    data: dict[str, Any] = {"id": "r1", "match": match, "action": action}
    if action != "allow":
        data["reason"] = "because r1"
    if tool is None and action == "allow" and "program" not in match:
        tool = ["Bash"]  # an allow rule must name a tool or a program
    if tool is not None:
        data["tool"] = tool
    return Rule.model_validate(data, context={"home": HOME})


def hits(match: dict[str, Any], action: Action, *, rule_action: str = "allow") -> bool:
    return match_rule(rule_of(match, action=rule_action), action, platform="posix")


# ---------------------------------------------------------------------------- flags_none

FLAGS_NONE_CASES = [
    pytest.param({"flags_none": ["--zap"]}, act(), True, id="no-flags-matches"),
    pytest.param({"flags_none": ["--zap"]}, act(flags=("-l", "-a")), True, id="other-flags-match"),
    pytest.param({"flags_none": ["--zap"]}, act(flags=("--zap",)), False, id="listed-flag-blocks"),
    pytest.param(
        {"flags_none": ["--zap", "-q"]}, act(flags=("-l", "-q")), False, id="any-listed-blocks"
    ),
    pytest.param(
        {"flags_none": ["--zap", "-q"]}, act(flags=("--zap", "-q")), False, id="all-listed-blocks"
    ),
    pytest.param({"flags_none": ["-q"]}, act(flags=("-Q",)), True, id="bash-short-flag-case"),
    pytest.param({"flags_none": ["-Q"]}, act(flags=("-q",)), True, id="bash-short-flag-case-2"),
    pytest.param(
        {"flags_none": ["--zap"]}, act(flags=("--ZAP",)), True, id="bash-long-flag-case-sensitive"
    ),
    # PowerShell: cmdlet parameters fold case; an external program's flags do not.
    pytest.param(
        {"flags_none": ["-Recurse"]},
        act(flags=("-recurse",), sh="powershell", program="Get-ChildItem"),
        False,
        id="ps-cmdlet-parameter-folds",
    ),
    pytest.param(
        {"flags_none": ["-recurse"]},
        act(flags=("-RECURSE",), sh="powershell", program="Get-ChildItem"),
        False,
        id="ps-cmdlet-parameter-folds-rule-side",
    ),
    pytest.param(
        {"flags_none": ["-Recurse"]},
        act(flags=("-Path",), sh="powershell", program="Get-ChildItem"),
        True,
        id="ps-cmdlet-other-parameter",
    ),
    pytest.param(
        {"flags_none": ["-D"]},
        act(flags=("-d",), sh="powershell", program="git"),
        True,
        id="ps-external-short-flag-case-sensitive",
    ),
    pytest.param(
        {"flags_none": ["-D"]},
        act(flags=("-D",), sh="powershell", program="git"),
        False,
        id="ps-external-exact-flag-blocks",
    ),
    pytest.param(
        {"flags_none": ["-Recurse"]},
        act(flags=("-recurse",), sh="bash", program="Get-ChildItem"),
        True,
        id="bash-never-folds",
    ),
    # combined with program / subcommand (AND)
    pytest.param(
        {"program": ["git"], "subcommand": ["status"], "flags_none": ["--zap"]},
        act(program="git", subcommand="status", flags=("-s",)),
        True,
        id="and-program-subcommand-all-hold",
    ),
    pytest.param(
        {"program": ["git"], "subcommand": ["status"], "flags_none": ["--zap"]},
        act(program="git", subcommand="status", flags=("--zap",)),
        False,
        id="and-program-subcommand-flag-blocks",
    ),
    pytest.param(
        {"program": ["git"], "subcommand": ["status"], "flags_none": ["--zap"]},
        act(program="git", subcommand="push"),
        False,
        id="and-subcommand-misses",
    ),
    pytest.param(
        {"program": ["git"], "flags_none": ["--zap"]},
        act(program="hg"),
        False,
        id="and-program-misses",
    ),
    pytest.param(
        {"flags_any": ["-l"], "flags_none": ["--zap"]},
        act(flags=("-l",)),
        True,
        id="with-flags-any-both-hold",
    ),
    pytest.param(
        {"flags_any": ["-l"], "flags_none": ["--zap"]},
        act(flags=("-l", "--zap")),
        False,
        id="with-flags-any-none-blocks",
    ),
    pytest.param(
        {"flags_any": ["-l"], "flags_none": ["--zap"]},
        act(flags=("-a",)),
        False,
        id="with-flags-any-any-misses",
    ),
    pytest.param(
        {"flags_none": ["--zap"], "path_inside_project": True},
        act(INSIDE_R, flags=("-l",)),
        True,
        id="with-inside-hold",
    ),
    pytest.param(
        {"flags_none": ["--zap"], "path_inside_project": True},
        act(OUTSIDE_R, flags=("-l",)),
        False,
        id="with-inside-path-outside",
    ),
    pytest.param(
        {"flags_none": ["--zap"], "path_inside_project": True},
        act(INSIDE_R, flags=("--zap",)),
        False,
        id="with-inside-flag-blocks",
    ),
]


@pytest.mark.parametrize(("match", "action", "expected"), FLAGS_NONE_CASES)
def test_flags_none(match: dict[str, Any], action: Action, expected: bool) -> None:
    assert hits(match, action) is expected
    # Evaluating as a deny rule gives the same answer when nothing goes wrong.
    assert hits(match, action, rule_action="deny") is expected


# ---------------------------------------------------------------------------- paths_read_only

PATHS_READ_ONLY_CASES = [
    pytest.param({"paths_read_only": True}, act(), True, id="zero-paths-vacuous"),
    pytest.param({"paths_read_only": True}, act(program="pwd"), True, id="pwd"),
    pytest.param({"paths_read_only": True}, act(INSIDE_R), True, id="one-read"),
    pytest.param(
        {"paths_read_only": True}, act(INSIDE_R, OUTSIDE_R), True, id="reads-need-not-be-inside"
    ),
    pytest.param(
        {"paths_read_only": True}, act(("/p/x", "read", None), INSIDE_R), True, id="all-reads"
    ),
    pytest.param({"paths_read_only": True}, act(INSIDE_W), False, id="one-write"),
    pytest.param({"paths_read_only": True}, act(INSIDE_U), False, id="one-unknown"),
    pytest.param({"paths_read_only": True}, act(INSIDE_R, INSIDE_W), False, id="read-and-write"),
    pytest.param({"paths_read_only": True}, act(INSIDE_R, INSIDE_U), False, id="read-and-unknown"),
    pytest.param({"paths_read_only": True}, act(INSIDE_W, INSIDE_U), False, id="write-and-unknown"),
    pytest.param(
        {"paths_read_only": True},
        act(INSIDE_R, ("/q/b", "read", True), ("/q/c", "unknown", True)),
        False,
        id="one-bad-among-many",
    ),
    # combined with program / subcommand / path_inside_project (AND)
    pytest.param(
        {"program": ["ls"], "paths_read_only": True},
        act(INSIDE_R, program="ls"),
        True,
        id="and-program-holds",
    ),
    pytest.param(
        {"program": ["ls"], "paths_read_only": True},
        act(INSIDE_W, program="ls"),
        False,
        id="and-program-holds-path-writes",
    ),
    pytest.param(
        {"program": ["ls"], "paths_read_only": True},
        act(INSIDE_R, program="cat"),
        False,
        id="and-program-misses",
    ),
    pytest.param(
        {"program": ["git"], "subcommand": ["log"], "paths_read_only": True},
        act(INSIDE_R, program="git", subcommand="log"),
        True,
        id="and-subcommand-holds",
    ),
    pytest.param(
        {"program": ["git"], "subcommand": ["log"], "paths_read_only": True},
        act(INSIDE_R, program="git", subcommand="push"),
        False,
        id="and-subcommand-misses",
    ),
    pytest.param(
        {"paths_read_only": True, "path_inside_project": True},
        act(INSIDE_R),
        True,
        id="and-inside-both",
    ),
    pytest.param(
        {"paths_read_only": True, "path_inside_project": True},
        act(OUTSIDE_R),
        False,
        id="and-inside-read-but-outside",
    ),
    pytest.param(
        {"paths_read_only": True, "path_inside_project": True},
        act(INSIDE_U),
        False,
        id="and-inside-inside-but-unknown",
    ),
    pytest.param(
        {"paths_read_only": True, "path_inside_project": True},
        act(),
        False,
        id="and-inside-needs-a-path",
    ),
    pytest.param(
        {"paths_read_only": True, "path_glob": ["**/*.txt"]},
        act(INSIDE_R),
        True,
        id="and-glob-holds",
    ),
    pytest.param(
        {"paths_read_only": True, "path_glob": ["**/*.md"]},
        act(INSIDE_R),
        False,
        id="and-glob-misses",
    ),
    pytest.param(
        {"paths_read_only": True, "path_outside_project": True},
        act(OUTSIDE_R),
        True,
        id="and-outside-read",
    ),
    pytest.param(
        {"paths_read_only": True, "path_outside_project": True},
        act(("/etc/x", "write", False)),
        False,
        id="and-outside-write",
    ),
    pytest.param(
        {"paths_read_only": True, "flags_none": ["--zap"]},
        act(INSIDE_R, flags=("--zap",)),
        False,
        id="and-flags-none-blocks",
    ),
    pytest.param(
        {"paths_read_only": True, "flags_none": ["--zap"]},
        act(flags=("-l",)),
        True,
        id="and-flags-none-zero-paths",
    ),
]


@pytest.mark.parametrize(("match", "action", "expected"), PATHS_READ_ONLY_CASES)
def test_paths_read_only(match: dict[str, Any], action: Action, expected: bool) -> None:
    assert hits(match, action) is expected
    assert hits(match, action, rule_action="deny") is expected


def test_paths_read_only_is_about_the_access_of_every_pathref_not_the_tool() -> None:
    # A Read tool call (the path is only read) and a Write tool call (it is written).
    reader = act(INSIDE_R, tool="Read", shell=None)
    writer = act(INSIDE_W, tool="Write", shell=None)
    rule = rule_of({"paths_read_only": True}, tool=["Read", "Write"])
    assert match_rule(rule, reader, platform="posix") is True
    assert match_rule(rule, writer, platform="posix") is False


# ---------------------------------------------------------------------------- explain output


def test_explain_lines_name_the_new_fields() -> None:
    rule = rule_of({"program": ["ls"], "flags_none": ["--zap"], "paths_read_only": True})
    lines = explain_rule(rule, act(INSIDE_R, program="ls", flags=("-l",)), platform="posix")
    assert lines is not None
    text = "\n".join(lines)
    assert "flags_none: none of --zap is present" in text
    assert "paths_read_only:" in text
    assert explain_rule(rule, act(INSIDE_W, program="ls"), platform="posix") is None


# ---------------------------------------------------------------------------- failure direction


def test_unfoldable_flag_allow_rule_does_not_match_deny_and_ask_rules_do(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(action: Action, text: str) -> str:
        raise RuntimeError("cannot fold")

    monkeypatch.setattr(matcher_module, "_fold_flag", boom)
    action = act(flags=("-l",), program="ls")
    match = {"flags_none": ["--zap"]}
    assert hits(match, action, rule_action="allow") is False
    assert hits(match, action, rule_action="deny") is True
    assert hits(match, action, rule_action="ask") is True
    # The failure also leaves a trace in explain for the strict side, none for allow.
    assert explain_rule(rule_of(match, action="allow"), action, platform="posix") is None
    assert explain_rule(rule_of(match, action="deny"), action, platform="posix") == (
        "internal-error: treated as a match",
    )


def test_unreadable_path_access_allow_rule_does_not_match_deny_and_ask_rules_do() -> None:
    # model_construct skips validation: a path object without ``access`` makes the matcher raise.
    fields: dict[str, Any] = {"tool": "Bash", "platform": "posix", "paths": (object(),)}
    broken = Action.model_construct(program="ls", **fields)
    match = {"paths_read_only": True}
    assert hits(match, broken, rule_action="allow") is False
    assert hits(match, broken, rule_action="deny") is True
    assert hits(match, broken, rule_action="ask") is True


def test_failure_in_a_new_field_cannot_turn_a_policy_into_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(action: Action, text: str) -> str:
        raise RuntimeError("cannot fold")

    monkeypatch.setattr(matcher_module, "_fold_flag", boom)
    policy = Policy.model_validate(
        {
            "version": 1,
            "rules": [
                {
                    "id": "allow-ls",
                    "action": "allow",
                    "match": {"program": ["ls"], "flags_none": ["--zap"]},
                },
            ],
        },
        context={"home": HOME},
    )
    verdict = evaluate(policy, [act(program="ls")], platform="posix")
    assert verdict.decision == "gray"


# ---------------------------------------------------------------------------- schema


def _text(match_lines: str, action: str = "allow") -> str:
    reason = "    reason: r\n" if action != "allow" else ""
    return (
        "version: 1\nrules:\n  - id: r1\n"
        f"    action: {action}\n{reason}    match:\n      program: ls\n{match_lines}"
    )


def _load(match_lines: str, action: str = "allow") -> Policy:
    return parse_policy_text(_text(match_lines, action), home=HOME)


def test_fields_load_and_are_stored_as_tuple_and_true() -> None:
    policy = _load("      flags_none: ['--zap', -Q]\n      paths_read_only: true\n")
    match = policy.rules[0].match
    assert match.flags_none == ("--zap", "-Q")
    assert match.paths_read_only is True
    assert not match.is_empty()


def test_a_scalar_flag_is_the_usual_one_element_shorthand() -> None:
    assert _load("      flags_none: --zap\n").rules[0].match.flags_none == ("--zap",)


def _allow(head: str, match_lines: str) -> str:
    return f"version: 1\nrules:\n  - id: r1\n    action: allow\n{head}    match:\n{match_lines}"


@pytest.mark.parametrize(
    "match_lines",
    [
        "      paths_read_only: true\n",
        "      flags_none: ['--zap']\n",
        "      path_inside_project: true\n",
        "      paths_read_only: true\n      flags_none: ['--zap']\n"
        "      path_inside_project: true\n",
        "      flags_any: ['-l']\n",
        "      network: true\n",
    ],
)
def test_an_allow_rule_must_name_a_tool_or_a_program(match_lines: str) -> None:
    with pytest.raises(PolicyError) as info:
        parse_policy_text(_allow("", match_lines), home=HOME)
    message = str(info.value)
    assert "an allow rule must name a tool or a program" in message
    assert "rules[0].match" in message


def test_an_allow_rule_with_a_tool_a_program_or_both_loads() -> None:
    narrow = "      paths_read_only: true\n      flags_none: ['--zap']\n"
    tool_only = parse_policy_text(_allow("    tool: Bash\n", narrow), home=HOME)
    assert tool_only.rules[0].tool == ("Bash",)
    program_only = parse_policy_text(_allow("", "      program: ls\n" + narrow), home=HOME)
    assert program_only.rules[0].match.program == ("ls",)
    both = parse_policy_text(
        _allow("    tool: [Bash]\n", "      program: ls\n" + narrow), home=HOME
    )
    assert both.rules[0].tool == ("Bash",)
    assert both.rules[0].match.program == ("ls",)


def test_the_guard_does_not_apply_to_deny_and_ask_rules() -> None:
    for action in ("deny", "ask"):
        for body in ("paths_read_only: true", "flags_none: ['--zap']", "path_inside_project: true"):
            text = (
                f"version: 1\nrules:\n  - id: r1\n    action: {action}\n    reason: r\n"
                f"    match:\n      {body}\n"
            )
            policy = parse_policy_text(text, home=HOME)
            assert policy.rules[0].tool is None
            assert policy.rules[0].match.program is None


def test_an_allow_rule_with_an_empty_match_keeps_its_older_message() -> None:
    text = "version: 1\nrules:\n  - id: r1\n    action: allow\n    tool: Bash\n    match: {}\n"
    with pytest.raises(PolicyError) as info:
        parse_policy_text(text, home=HOME)
    assert "allow rule needs at least one match field" in str(info.value)


@pytest.mark.parametrize(
    "bad",
    [
        "[]",
        "{a: b}",
        "5",
        "true",
        "[force]",
        "['-ok', rf]",
        "['']",
        "[' -x']",
        "['-x ']",
        "[5]",
        "[[-x]]",
        "[null]",
    ],
)
def test_flags_none_rejects_bad_values(bad: str) -> None:
    with pytest.raises(PolicyError) as info:
        _load(f"      flags_none: {bad}\n")
    assert "rules[0].match.flags_none" in str(info.value)


def test_flags_none_error_for_a_non_flag_names_the_index_and_the_rule() -> None:
    with pytest.raises(PolicyError) as info:
        _load("      flags_none: ['-ok', zap]\n")
    message = str(info.value)
    assert "rules[0].match.flags_none[1]" in message
    assert "must start with '-'" in message


def test_flags_none_has_the_same_size_limits_as_flags_any() -> None:
    ok = ", ".join(f"-f{i}" for i in range(64))
    assert len(_load(f"      flags_none: [{ok}]\n").rules[0].match.flags_none or ()) == 64
    too_many = ", ".join(f"-f{i}" for i in range(65))
    for field in ("flags_none", "flags_any"):
        with pytest.raises(PolicyError):
            _load(f"      {field}: [{too_many}]\n")
    too_long = "-" + "x" * 256
    for field in ("flags_none", "flags_any"):
        with pytest.raises(PolicyError):
            _load(f"      {field}: ['{too_long}']\n")


def test_flags_none_null_is_refused_like_every_other_field() -> None:
    with pytest.raises(PolicyError) as info:
        _load("      flags_none:\n")
    assert "rules[0].match.flags_none" in str(info.value)
    assert "null" in str(info.value)


@pytest.mark.parametrize("bad", ["false", "'yes'", "1", "0", "[true]", "{a: b}", "null", "~"])
def test_paths_read_only_rejects_everything_but_true(bad: str) -> None:
    with pytest.raises(PolicyError) as info:
        _load(f"      paths_read_only: {bad}\n")
    assert "rules[0].match.paths_read_only" in str(info.value)


def test_paths_read_only_blank_value_is_refused_as_null() -> None:
    with pytest.raises(PolicyError) as info:
        _load("      paths_read_only:\n")
    assert "null" in str(info.value)


def test_flags_any_and_flags_none_may_not_share_an_entry() -> None:
    with pytest.raises(PolicyError) as info:
        _load("      flags_any: ['-a', '--zap']\n      flags_none: ['--zap']\n")
    assert "could never match" in str(info.value)
    ok = _load("      flags_any: ['-a']\n      flags_none: ['--zap']\n")
    assert ok.rules[0].match.flags_any == ("-a",)


def test_unknown_neighbours_of_the_new_fields_are_still_rejected() -> None:
    for typo in ("flag_none: ['-x']", "flags_not: ['-x']", "paths_readonly: true"):
        with pytest.raises(PolicyError):
            _load(f"      {typo}\n")


def test_rule_model_validate_rejects_empty_flags_none_directly() -> None:
    with pytest.raises(ValidationError):
        rule_of({"flags_none": []})
    with pytest.raises(ValidationError):
        rule_of({"paths_read_only": False})


# ---------------------------------------------------------------------------- end to end

ALLOW_LS = {
    "id": "allow-ls-readonly",
    "action": "allow",
    "tool": ["Bash"],
    "match": {
        "program": ["ls"],
        "flags_none": ["--made-up-danger"],
        "paths_read_only": True,
        "path_inside_project": True,
    },
}
ALLOW_PWD = {
    "id": "allow-pwd",
    "action": "allow",
    "tool": ["Bash"],
    "match": {"program": ["pwd"], "paths_read_only": True},
}
DENY_MADE_UP = {
    "id": "deny-made-up-flag-everywhere",
    "action": "deny",
    "reason": "made-up flag",
    "match": {"flags_any": ["--made-up-danger"]},
}


def _policy(*rules: dict[str, Any]) -> Policy:
    return Policy.model_validate({"version": 1, "rules": list(rules)}, context={"home": HOME})


def _decision(policy: Policy, *actions: Action) -> str:
    return evaluate(policy, list(actions), platform="posix").decision


def ls(*paths: tuple[str, str, bool | None], **fields: Any) -> Action:
    return act(*paths, program="ls", **fields)


def test_end_to_end_allow_only_when_every_condition_holds() -> None:
    policy = _policy(ALLOW_LS)
    assert _decision(policy, ls(INSIDE_R, flags=("-l", "-a"))) == "allow"
    assert _decision(policy, ls(INSIDE_R)) == "allow"
    assert _decision(policy, ls(INSIDE_R, ("/proj/b", "read", True), flags=("-l",))) == "allow"

    # each condition broken on its own
    assert _decision(policy, ls(INSIDE_R, flags=("--made-up-danger",))) == "gray"  # flags_none
    assert _decision(policy, ls(INSIDE_W)) == "gray"  # access write
    assert _decision(policy, ls(INSIDE_U)) == "gray"  # access unknown
    assert _decision(policy, ls(INSIDE_R, INSIDE_W)) == "gray"  # one path writes
    assert _decision(policy, ls(OUTSIDE_R)) == "gray"  # read-only but outside
    assert _decision(policy, ls(("/proj/a", "read", None))) == "gray"  # inside unsure
    assert _decision(policy, ls()) == "gray"  # path_inside_project needs a path
    assert _decision(policy, act(INSIDE_R, program="cat")) == "gray"  # other program
    assert _decision(policy, act(INSIDE_R, program="LS")) == "gray"  # bash is case-sensitive
    assert _decision(policy, act(INSIDE_R, program="ls", tool="PowerShell")) == "gray"  # tool


def test_end_to_end_gray_and_wrapped_actions_never_ride_the_allow_rule() -> None:
    policy = _policy(ALLOW_LS, ALLOW_PWD)
    assert _decision(policy, ls(INSIDE_R)) == "allow"
    assert _decision(policy, ls(INSIDE_R, wrappers=("sudo",))) == "gray"
    assert _decision(policy, ls(INSIDE_R, wrappers=("env",), flags=("-l",))) == "gray"
    assert _decision(policy, ls(INSIDE_R, gray=True, gray_reasons=("could not parse",))) == "gray"
    assert _decision(policy, act(program="pwd", wrappers=("nohup",))) == "gray"
    assert _decision(policy, act(program="pwd", gray=True, gray_reasons=("x",))) == "gray"
    # the matcher says so directly, too
    allow_rule = Rule.model_validate(ALLOW_LS, context={"home": HOME})
    assert match_rule(allow_rule, ls(INSIDE_R), platform="posix") is True
    assert match_rule(allow_rule, ls(INSIDE_R, wrappers=("sudo",)), platform="posix") is False
    assert match_rule(allow_rule, ls(INSIDE_R, gray=True), platform="posix") is False


def test_end_to_end_zero_path_command_and_the_merge() -> None:
    policy = _policy(ALLOW_LS, ALLOW_PWD)
    assert _decision(policy, act(program="pwd")) == "allow"  # vacuously read-only
    assert _decision(policy, act(INSIDE_W, program="pwd")) == "gray"
    # every action of a command line needs an allow rule
    assert _decision(policy, act(program="pwd"), ls(INSIDE_R, flags=("-l",))) == "allow"
    assert _decision(policy, act(program="pwd"), ls(INSIDE_W)) == "gray"
    assert _decision(policy, act(program="pwd"), act(program="rm")) == "gray"
    assert _decision(policy, ls(INSIDE_R), ls(INSIDE_R, flags=("--made-up-danger",))) == "gray"


def test_end_to_end_a_deny_rule_still_wins_over_the_allow_rule() -> None:
    policy = _policy(ALLOW_LS, DENY_MADE_UP)
    # flags_none already keeps the allow rule away, and the deny rule hits the flag anyway
    assert _decision(policy, ls(INSIDE_R, flags=("--made-up-danger",))) == "deny"
    assert _decision(policy, ls(INSIDE_R)) == "allow"
    # an allow rule without flags_none would also lose to the deny rule
    broad = dict(ALLOW_LS, id="allow-ls-broad", match={"program": ["ls"]})
    assert _decision(_policy(broad, DENY_MADE_UP), ls(flags=("--made-up-danger",))) == "deny"


def test_end_to_end_yaml_policy_roundtrip() -> None:
    text = (
        "version: 1\n"
        "rules:\n"
        "  - id: allow-ls-readonly\n"
        "    action: allow\n"
        "    tool: Bash\n"
        "    match:\n"
        "      program: ls\n"
        "      flags_none: ['--made-up-danger']\n"
        "      paths_read_only: true\n"
        "      path_inside_project: true\n"
    )
    policy = parse_policy_text(text, home=HOME)
    assert _decision(policy, ls(INSIDE_R, flags=("-l",))) == "allow"
    assert _decision(policy, ls(INSIDE_U, flags=("-l",))) == "gray"
    assert _decision(policy, ls(INSIDE_R, flags=("--made-up-danger",))) == "gray"
