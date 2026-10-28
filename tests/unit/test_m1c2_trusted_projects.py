"""M1c-2: the ``trusted_projects`` policy key and the ``project_trusted`` match field.

A rule that lets a project's own dev tools run (they execute repository code) must apply only to
projects the user explicitly trusts. Covered here:

* the loader: accepted entries (both flavors, ``~`` expansion, duplicates folded) and every kind of
  rejected entry, fail closed, naming the entry;
* the field: segment-prefix matching on canonical keys, per-flavor case rules, unknown / unusable /
  too-broad projects, the direction of the fallbacks (allow: no match; deny / ask: match);
* end to end through ``daemon.pipeline.review`` with a tiny policy;
* ``Action.project`` is set by the normalizer for every action of an event.

Everything runs on made-up machines (``home=`` and ``project_dir``), never the real home.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from boundkeep.daemon.pipeline import review
from boundkeep.normalize import paths as norm_paths
from boundkeep.normalize.event import normalize_event
from boundkeep.normalize.model import Action
from boundkeep.policy import (
    Match,
    Policy,
    PolicyError,
    Rule,
    default_policy_text,
    evaluate,
    explain_rule,
    match_rule,
    parse_policy_text,
)
from boundkeep.policy.matcher import project_trust_line

POSIX_HOME = "/home/dev"
WIN_HOME = "C:\\Users\\dev"


def load(
    entries: Any, *, home: str = POSIX_HOME, rules: list[dict[str, Any]] | None = None
) -> Policy:
    data: dict[str, Any] = {"version": 1, "trusted_projects": entries}
    if rules is not None:
        data["rules"] = rules
    return parse_policy_text(yaml.safe_dump(data, allow_unicode=True), home=home)


# ------------------------------------------------------------------------------ loader: accept

ACCEPTED = [
    # (home, entries, canonical keys stored)
    (WIN_HOME, ["C:\\Work\\proj"], ["c:/work/proj"]),
    (WIN_HOME, ["c:/Work/Proj/"], ["c:/work/proj"]),
    (WIN_HOME, ["D:\\code"], ["d:/code"]),
    (WIN_HOME, ["~/proj"], ["c:/users/dev/proj"]),
    (WIN_HOME, ["~\\code\\proj"], ["c:/users/dev/code/proj"]),
    (WIN_HOME, ["~/Documents/proj"], ["c:/users/dev/documents/proj"]),
    (WIN_HOME, ["C:\\My Projects\\a b"], ["c:/my projects/a b"]),
    (WIN_HOME, ["C:\\\u4ee3\u7801\\\u9879\u76ee"], ["c:/\u4ee3\u7801/\u9879\u76ee"]),
    (WIN_HOME, ["C:\\Users\\other\\proj"], ["c:/users/other/proj"]),
    (WIN_HOME, ["C:\\Windows Projects\\x"], ["c:/windows projects/x"]),
    (WIN_HOME, ["/home/other/proj"], ["/home/other/proj"]),  # other flavor: stored, never matches
    (WIN_HOME, ["/opt/work/proj"], ["/opt/work/proj"]),
    (POSIX_HOME, ["~/proj"], ["/home/dev/proj"]),
    (POSIX_HOME, ["~\\proj"], ["/home/dev/proj"]),
    (POSIX_HOME, ["/srv/app/proj"], ["/srv/app/proj"]),
    (POSIX_HOME, ["/Users/dev/code"], ["/Users/dev/code"]),
    (POSIX_HOME, ["/tmp/work/proj"], ["/tmp/work/proj"]),
    (POSIX_HOME, ["/home/dev/Documents/proj"], ["/home/dev/Documents/proj"]),
    (POSIX_HOME, ["/home/dev/Proj"], ["/home/dev/Proj"]),  # POSIX keys keep their case
    (POSIX_HOME, ["C:\\Work\\proj"], ["c:/work/proj"]),  # other flavor on a POSIX home
    (POSIX_HOME, ["/" + "d" * 1023], ["/" + "d" * 1023]),  # exactly 1024 characters
    (POSIX_HOME, [], []),
]


@pytest.mark.parametrize(("home", "entries", "expected"), ACCEPTED)
def test_accepted_entries_are_stored_as_canonical_keys(
    home: str, entries: list[str], expected: list[str]
) -> None:
    assert load(entries, home=home).trusted_projects == tuple(expected)


def test_a_missing_key_or_an_empty_list_is_no_trusted_project() -> None:
    assert parse_policy_text("version: 1\n", home=POSIX_HOME).trusted_projects == ()
    assert (
        parse_policy_text("version: 1\ntrusted_projects: []\n", home=POSIX_HOME).trusted_projects
        == ()
    )


def test_shipped_policies_load_without_trusted_projects() -> None:
    policy = parse_policy_text(default_policy_text(), home=POSIX_HOME)
    assert policy.trusted_projects == ()


def test_duplicates_are_folded_after_normalising_first_wins() -> None:
    policy = load(
        ["C:\\Work\\proj", "c:/work/PROJ/", "~/x", "D:\\y", "C:/work/proj"], home=WIN_HOME
    )
    assert policy.trusted_projects == ("c:/work/proj", "c:/users/dev/x", "d:/y")
    posix = load(["/ab/b", "/ab/b/", "/ab/B", "/ab//b"], home=POSIX_HOME)
    assert posix.trusted_projects == ("/ab/b", "/ab/B")  # case differs: a different POSIX directory


def test_exactly_64_entries_are_fine_65_are_not() -> None:
    assert len(load([f"/work/p{i}" for i in range(64)]).trusted_projects) == 64
    with pytest.raises(PolicyError, match="at most 64"):
        load([f"/work/p{i}" for i in range(65)])


def test_home_expansion_follows_the_loader_home() -> None:
    assert load(["~/p"], home="C:\\Users\\Zed").trusted_projects == ("c:/users/zed/p",)
    assert load(["~/p"], home="/Users/zed").trusted_projects == ("/Users/zed/p",)


# ------------------------------------------------------------------------------ loader: reject

REJECTED = [
    # empty / whitespace
    (POSIX_HOME, "", "is empty"),
    (POSIX_HOME, "   ", "is empty"),
    (POSIX_HOME, " /a/b", "leading or trailing whitespace"),
    (POSIX_HOME, "/ab/b ", "leading or trailing whitespace"),
    (POSIX_HOME, "/a/b", "plain absolute"),  # a one-letter first directory reads as a drive
    # relative
    (POSIX_HOME, "proj/x", "not an absolute path"),
    (POSIX_HOME, "./proj", "not an absolute path"),
    (WIN_HOME, "C:proj", "not an absolute path"),
    (WIN_HOME, "\\proj", "not an absolute path"),
    (WIN_HOME, "proj", "not an absolute path"),
    # UNC / network / extended prefix
    (WIN_HOME, "\\\\srv\\share\\p", "UNC"),
    (WIN_HOME, "//srv/share/p", "UNC"),
    (WIN_HOME, "\\\\.\\C:\\x", "UNC"),
    (WIN_HOME, "\\\\?\\C:\\x", "contains '?'"),
    (POSIX_HOME, "//srv/share/p", "UNC"),
    # wildcards and variables
    (POSIX_HOME, "/a/*", "contains '*'"),
    (POSIX_HOME, "/a/**", "contains '*'"),
    (POSIX_HOME, "/a/p?", "contains '?'"),
    (POSIX_HOME, "/a/[ab]", "contains '['"),
    (POSIX_HOME, "/a/$HOME", "contains '$'"),
    (WIN_HOME, "%USERPROFILE%\\a", "contains '%'"),
    (WIN_HOME, "C:\\a\\$env:TEMP", "contains '$'"),
    (WIN_HOME, "C:\\a\\*", "contains '*'"),
    # ".." segments
    (POSIX_HOME, "/a/../b", "'..' segment"),
    (WIN_HOME, "C:\\a\\..\\b", "'..' segment"),
    (WIN_HOME, "C:/a/../b", "'..' segment"),
    (POSIX_HOME, "~/../x", "'..' segment"),
    (WIN_HOME, "..\\x", "'..' segment"),
    # control characters
    (POSIX_HOME, "/a\nb", "non-printable"),
    (POSIX_HOME, "/a\x00b", "non-printable"),
    (POSIX_HOME, "/a\tb", "non-printable"),
    (WIN_HOME, "C:\\a\x1bb", "non-printable"),
    # ambiguous spellings
    (WIN_HOME, "C:\\a:stream", "plain absolute"),
    (WIN_HOME, "C:\\a.", "plain absolute"),
    (WIN_HOME, "/mnt/c/Users/dev/x", "plain absolute"),
    (WIN_HOME, "/c/Users/dev/x", "plain absolute"),
    (POSIX_HOME, "/home/we\\ird", "backslash"),
    (POSIX_HOME, "~/a\\b", "backslash"),
    (POSIX_HOME, "~\\a\\b", "backslash"),
    (POSIX_HOME, "~dev/x", "~user"),
    (WIN_HOME, "~dev\\x", "~user"),
    # too broad: home, its ancestors, roots
    (WIN_HOME, "~", "home directory itself"),
    (WIN_HOME, "~/", "home directory itself"),
    (POSIX_HOME, "~", "home directory itself"),
    (POSIX_HOME, "~/.", "too broad"),
    (WIN_HOME, "C:\\Users\\dev", "too broad"),
    (WIN_HOME, "c:/users/DEV/", "too broad"),
    (POSIX_HOME, "/home/dev", "too broad"),
    (POSIX_HOME, "/home/dev/", "too broad"),
    (WIN_HOME, "C:\\", "too broad"),
    (WIN_HOME, "c:/", "too broad"),
    (WIN_HOME, "D:\\", "too broad"),
    (WIN_HOME, "C:\\Users", "too broad"),
    (WIN_HOME, "C:\\Users\\Public", "too broad"),
    (POSIX_HOME, "/", "too broad"),
    (POSIX_HOME, "/home", "too broad"),
    (WIN_HOME, "/home", "too broad"),
    (POSIX_HOME, "/Users", "too broad"),
    (POSIX_HOME, "/tmp", "too broad"),
    (POSIX_HOME, "/tmp/", "too broad"),
    (POSIX_HOME, "/var/tmp", "too broad"),
    (POSIX_HOME, "/usr", "too broad"),
    (POSIX_HOME, "/etc/x", "too broad"),
    (POSIX_HOME, "/opt", "too broad"),
    (WIN_HOME, "C:\\Windows", "too broad"),
    (WIN_HOME, "C:\\Windows\\System32", "too broad"),
    (WIN_HOME, "C:\\Program Files", "too broad"),
    (WIN_HOME, "C:\\Program Files (x86)\\x", "too broad"),
    (WIN_HOME, "D:\\Program Files\\y", "too broad"),
    (POSIX_HOME, "C:\\Windows", "too broad"),  # still refused when it is another flavor
    # Documents / Desktop / Downloads roots
    (WIN_HOME, "~/Documents", "too broad"),
    (WIN_HOME, "C:\\Users\\dev\\documents\\", "too broad"),
    (WIN_HOME, "~/Desktop", "too broad"),
    (WIN_HOME, "~\\Downloads", "too broad"),
    (POSIX_HOME, "~/Documents", "too broad"),
    (POSIX_HOME, "/home/dev/Desktop", "too broad"),
    (POSIX_HOME, "~/Downloads/", "too broad"),
]


@pytest.mark.parametrize(("home", "entry", "fragment"), REJECTED)
def test_rejected_entries_fail_closed_and_name_the_entry(
    home: str, entry: str, fragment: str
) -> None:
    with pytest.raises(PolicyError) as info:
        load(["/ok/proj", entry], home=home)
    message = str(info.value)
    assert "trusted_projects[1]" in message  # the index of the offending entry, not the good one
    assert fragment in message


def test_a_bad_entry_is_not_silently_dropped_next_to_good_ones() -> None:
    with pytest.raises(PolicyError, match=r"trusted_projects\[2\]"):
        load(["/ab/b", "/cd/d", "relative"])


def test_too_long_entries_are_rejected() -> None:
    too_long = "/" + "d" * 1024
    with pytest.raises(PolicyError):
        load([too_long])  # the loader's own scalar limit or ours, either way an error
    with pytest.raises(ValidationError, match="longer than 1024"):
        Policy.model_validate(
            {"version": 1, "trusted_projects": [too_long]}, context={"home": POSIX_HOME}
        )


@pytest.mark.parametrize("value", ["123", "[123]", "[null]", "[[a]]", "{a: b}", "'/a/b'", "null"])
def test_wrong_shapes_are_rejected(value: str) -> None:
    with pytest.raises(PolicyError):
        parse_policy_text(f"version: 1\ntrusted_projects: {value}\n", home=POSIX_HOME)


def test_the_key_is_not_a_glob_it_never_widens() -> None:
    # a wildcard is refused, so "everything under it" is the only breadth an entry has
    for entry in ("/work/*", "/work/**/proj", "C:\\work\\*"):
        with pytest.raises(PolicyError):
            load([entry], home=WIN_HOME)


# ------------------------------------------------------------------------------ the match field


def rule_of(match: dict[str, Any], *, action: str = "allow") -> Rule:
    data: dict[str, Any] = {"id": "r1", "match": match, "action": action}
    if action == "allow":
        data["tool"] = ["Bash"]
    else:
        data["reason"] = "because r1"
    return Rule.model_validate(data, context={"home": POSIX_HOME})


def act(project: str | None, *, platform: str = "posix", **fields: Any) -> Action:
    return Action(  # noqa: S604 - "shell" is the Action's dialect field, not a subprocess flag
        tool="Bash",
        shell="bash",
        platform=platform,  # type: ignore[arg-type]
        program="pwd",
        project=project,
        **fields,
    )


def trusted_hit(
    project: str | None, trusted: tuple[str, ...], *, rule_action: str = "allow", **fields: Any
) -> bool:
    rule = rule_of({"project_trusted": True}, action=rule_action)
    return match_rule(rule, act(project, **fields), platform="posix", trusted_projects=trusted)


POSIX_TRUSTED = ("/home/dev/proj",)
WINDOWS_TRUSTED = ("c:/work/proj",)

# (project key, trusted keys, matches)
FIELD_CASES = [
    # POSIX flavor: segment prefix, exact case
    pytest.param("/home/dev/proj", POSIX_TRUSTED, True, id="posix-equal"),
    pytest.param("/home/dev/proj/sub/deep", POSIX_TRUSTED, True, id="posix-inside"),
    pytest.param("/home/dev/proj/", POSIX_TRUSTED, True, id="posix-trailing-separator"),
    pytest.param("/home/dev/proj2", POSIX_TRUSTED, False, id="posix-sibling-with-common-prefix"),
    pytest.param("/home/dev/pro", POSIX_TRUSTED, False, id="posix-shorter-name"),
    pytest.param("/home/dev/proj-old/x", POSIX_TRUSTED, False, id="posix-prefix-with-dash"),
    pytest.param("/home/dev", POSIX_TRUSTED, False, id="posix-parent"),
    pytest.param("/home/dev/other/proj", POSIX_TRUSTED, False, id="posix-outside"),
    pytest.param("/home/dev/Proj", POSIX_TRUSTED, False, id="posix-case-differs"),
    pytest.param("/home/dev/PROJ/sub", POSIX_TRUSTED, False, id="posix-case-differs-below"),
    pytest.param("/home/dev/proj", ("/home/dev/PROJ",), False, id="posix-entry-case-differs"),
    pytest.param("/", POSIX_TRUSTED, False, id="posix-filesystem-root"),
    pytest.param("/home/dev/proj", (), False, id="no-trusted-projects"),
    pytest.param(
        "/home/dev/b/x", ("/home/dev/a", "/home/dev/b"), True, id="posix-second-entry-matches"
    ),
    pytest.param("/home/dev/proj", ("/home/dev/proj/sub",), False, id="posix-entry-is-below"),
    # Windows flavor: casefolded, drive-aware
    pytest.param("c:/work/proj", WINDOWS_TRUSTED, True, id="win-equal"),
    pytest.param("c:/work/proj/src", WINDOWS_TRUSTED, True, id="win-inside"),
    pytest.param("C:/Work/PROJ", WINDOWS_TRUSTED, True, id="win-case-insensitive-project"),
    pytest.param("c:/work/proj", ("C:/WORK/Proj",), True, id="win-case-insensitive-entry"),
    pytest.param("c:/work/proj/", WINDOWS_TRUSTED, True, id="win-trailing-separator"),
    pytest.param("c:/work/proj2", WINDOWS_TRUSTED, False, id="win-sibling-with-common-prefix"),
    pytest.param("d:/work/proj", WINDOWS_TRUSTED, False, id="win-other-drive"),
    pytest.param("c:/work", WINDOWS_TRUSTED, False, id="win-parent"),
    pytest.param("c:/", WINDOWS_TRUSTED, False, id="win-drive-root"),
    pytest.param("c:\\work\\proj", WINDOWS_TRUSTED, False, id="win-backslashes-are-not-a-key"),
    # other flavor entries never match
    pytest.param("c:/work/proj", ("/work/proj",), False, id="windows-project-posix-entry"),
    pytest.param("/work/proj", ("c:/work/proj",), False, id="posix-project-windows-entry"),
    pytest.param("/c:/work/proj", ("c:/work/proj",), False, id="posix-lookalike-of-a-drive"),
    # unknown / unusable projects
    pytest.param(None, POSIX_TRUSTED, False, id="unknown-project"),
    pytest.param("", POSIX_TRUSTED, False, id="empty-project"),
    pytest.param("proj", POSIX_TRUSTED, False, id="relative-project"),
    pytest.param("/home/dev/proj/../x", POSIX_TRUSTED, False, id="dotdot-in-project"),
    pytest.param("/home/dev/proj/./x", POSIX_TRUSTED, False, id="dot-in-project"),
    pytest.param("/home/dev/proj//x", POSIX_TRUSTED, False, id="empty-segment-in-project"),
    pytest.param("//srv/share/proj", ("//srv/share/proj",), False, id="unc-project"),
    pytest.param("/home/dev/proj\x00", POSIX_TRUSTED, False, id="nul-in-project"),
    pytest.param("/" + "a" * 40000, POSIX_TRUSTED, False, id="huge-key"),
]


@pytest.mark.parametrize(("project", "trusted", "expected"), FIELD_CASES)
def test_project_trusted_matching_table(
    project: str | None, trusted: tuple[str, ...], expected: bool
) -> None:
    assert trusted_hit(project, trusted) is expected


def test_a_too_broad_project_never_matches_even_if_something_trusted_is_above_it() -> None:
    # (the normalizer already refuses such a root; the matcher does not rely on that)
    assert not trusted_hit("/", ("/home/dev/proj",))
    assert not trusted_hit("c:/", ("c:/work/proj",))


def test_project_resolved_must_be_trusted_too() -> None:
    trusted = ("/home/dev/proj",)
    rule = rule_of({"project_trusted": True})

    def hit(project: str | None, resolved: str | None) -> bool:
        action = act(project, project_resolved=resolved)
        return match_rule(rule, action, platform="posix", trusted_projects=trusted)

    assert hit("/home/dev/proj", None)
    assert hit("/home/dev/proj/a", "/home/dev/proj/b")
    assert not hit("/home/dev/proj", "/home/dev/elsewhere")  # a link out of the trusted tree
    assert not hit("/home/dev/proj", "/")
    assert not hit("/home/dev/proj", "relative")
    assert not hit(None, "/home/dev/proj")


def test_trusted_entries_compile_through_the_policy_and_match_per_flavor() -> None:
    policy = load(["~/work/proj", "C:\\Work\\Proj", "/srv/app"], home=POSIX_HOME)
    rule = rule_of({"project_trusted": True})
    cases = [
        ("/home/dev/work/proj/sub", True),
        ("/home/dev/work/proj2", False),
        ("c:/work/proj/x", True),  # the Windows entry, compared casefolded
        ("C:/WORK/proj", True),
        ("/srv/app", True),
        ("/srv/apple", False),
    ]
    for project, expected in cases:
        got = match_rule(
            rule, act(project), platform="posix", trusted_projects=policy.trusted_projects
        )
        assert got is expected, project


def test_gray_and_wrapped_actions_never_match_an_allow_rule_with_project_trusted() -> None:
    assert trusted_hit("/home/dev/proj", POSIX_TRUSTED)
    assert not trusted_hit("/home/dev/proj", POSIX_TRUSTED, gray=True, gray_reasons=("x",))
    assert not trusted_hit("/home/dev/proj", POSIX_TRUSTED, wrappers=("sudo",))


def test_allow_rule_direction_any_problem_means_no_match() -> None:
    for project in (None, "", "/", "rel", "/a/../b", "/home/dev/proj/../proj"):
        assert not trusted_hit(project, POSIX_TRUSTED), project


def test_deny_and_ask_rules_with_project_trusted_err_toward_matching() -> None:
    for rule_action in ("deny", "ask"):
        # a trusted project: matches
        assert trusted_hit("/home/dev/proj", POSIX_TRUSTED, rule_action=rule_action)
        # known and not trusted: does not match
        assert not trusted_hit("/home/dev/other", POSIX_TRUSTED, rule_action=rule_action)
        assert not trusted_hit("/home/dev/proj2", POSIX_TRUSTED, rule_action=rule_action)
        # cannot tell: matches (the restrictive direction)
        for project in (None, "", "/", "rel", "/a/../b", "c:/"):
            assert trusted_hit(project, POSIX_TRUSTED, rule_action=rule_action), project
        # no trusted list but a usable project: known to be untrusted
        assert not trusted_hit("/home/dev/proj", (), rule_action=rule_action)


def test_explain_lines() -> None:
    rule = rule_of({"project_trusted": True})
    inside = explain_rule(
        rule, act("/home/dev/proj/x"), platform="posix", trusted_projects=POSIX_TRUSTED
    )
    assert inside == ("project_trusted: project is inside a trusted project",)
    assert (
        explain_rule(rule, act("/home/dev/o"), platform="posix", trusted_projects=POSIX_TRUSTED)
        is None
    )
    assert project_trust_line(act("/home/dev/proj"), POSIX_TRUSTED).endswith(
        "is inside a trusted project"
    )
    assert project_trust_line(act("/home/dev/o"), POSIX_TRUSTED).endswith("is not trusted")
    assert "is not trusted" in project_trust_line(act(None), POSIX_TRUSTED)


def test_evaluate_threads_the_policys_trusted_list_to_the_rules() -> None:
    policy = load(
        ["~/proj"],
        rules=[
            {
                "id": "allow-pwd",
                "tool": ["Bash"],
                "match": {"program": ["pwd"], "project_trusted": True},
                "action": "allow",
            },
            {
                "id": "ask-pwd-when-unknown",
                "tool": ["Bash"],
                "match": {"program": ["pwd"], "project_trusted": True},
                "action": "ask",
                "reason": "check the project",
            },
        ],
    )
    # allow and ask both fire in a trusted project: the stricter one wins
    assert evaluate(policy, [act("/home/dev/proj")], platform="posix").decision == "ask"
    # an untrusted project: neither fires
    assert evaluate(policy, [act("/home/dev/x")], platform="posix").decision == "gray"
    # an unknown project: the ask rule errs toward matching, the allow rule does not
    unknown = evaluate(policy, [act(None)], platform="posix")
    assert unknown.decision == "ask"
    assert unknown.rule_ids == ("ask-pwd-when-unknown",)
    allow_only = load(
        ["~/proj"],
        rules=[
            {
                "id": "allow-pwd",
                "tool": ["Bash"],
                "match": {"program": ["pwd"], "project_trusted": True},
                "action": "allow",
            }
        ],
    )
    assert evaluate(allow_only, [act("/home/dev/proj")], platform="posix").decision == "allow"
    assert evaluate(allow_only, [act(None)], platform="posix").decision == "gray"


def test_without_a_trusted_list_the_default_is_nothing_is_trusted() -> None:
    rule = rule_of({"project_trusted": True})
    assert not match_rule(rule, act("/home/dev/proj"), platform="posix")


# ------------------------------------------------------------------------------ schema rules

MATCH_FIELD_SAMPLES: dict[str, Any] = {
    "path_glob": ["**/.env"],
    "access": None,  # only valid together with path_glob, covered below
    "program": ["cat"],
    "subcommand": ["push"],
    "flags_any": ["-f"],
    "flags_none": ["-f"],
    "path_outside_project": True,
    "path_inside_project": True,
    "path_in_scratchpad": True,
    "paths_read_only": True,
    "project_trusted": True,
    "network": True,
    "destination": "known",
    "domain_not_in": ["github.com"],
    "domain_in": ["github.com"],
    "mcp_server": ["github"],
    "mcp_read_only": True,
}


def test_every_match_field_is_in_this_table_and_parses() -> None:
    assert set(MATCH_FIELD_SAMPLES) == set(Match.model_fields), "add the new field to the table"
    for name, value in MATCH_FIELD_SAMPLES.items():
        if value is None:
            continue
        match = Match.model_validate({name: value}, context={"home": POSIX_HOME})
        assert getattr(match, name) is not None
        assert not match.is_empty()


@pytest.mark.parametrize("value", ["false", "null", "'yes'", "1", "[true]"])
def test_project_trusted_is_true_only(value: str) -> None:
    text = (
        "version: 1\nrules:\n  - id: r\n    tool: [Bash]\n    action: allow\n"
        f"    match: {{project_trusted: {value}}}\n"
    )
    with pytest.raises(PolicyError):
        parse_policy_text(text, home=POSIX_HOME)


def test_project_trusted_alone_does_not_satisfy_the_allow_guard() -> None:
    data = {"id": "r", "match": {"project_trusted": True}, "action": "allow"}
    with pytest.raises(ValidationError, match="must name a tool or a program"):
        Rule.model_validate(data)
    Rule.model_validate({**data, "tool": ["Bash"]})
    Rule.model_validate({**data, "match": {"project_trusted": True, "program": ["cat"]}})


def test_project_trusted_is_an_allowed_condition_for_tools_without_paths() -> None:
    # it says nothing about file paths, so it is fine next to tools that touch none
    Rule.model_validate(
        {"id": "r", "tool": ["WebSearch"], "match": {"project_trusted": True}, "action": "allow"}
    )


# ------------------------------------------------------------------------------ end to end

E2E_POLICY = """
version: 1
trusted_projects:
  - ~/work/proj
rules:
  - id: allow-cat-trusted
    tool: [Bash]
    match: {program: [cat], path_inside_project: true, project_trusted: true}
    action: allow
  - id: allow-pwd-trusted
    tool: [Bash]
    match: {program: [pwd], project_trusted: true}
    action: allow
  - id: allow-write-trusted
    tool: [Write]
    match: {path_inside_project: true, project_trusted: true}
    action: allow
  - id: deny-dotenv
    match: {path_glob: ["**/.env"]}
    action: deny
    reason: no env files
"""
PROJECT = "/home/dev/work/proj"


def bash(
    command: str, *, project_dir: str | None = PROJECT, cwd: str | None = PROJECT
) -> dict[str, Any]:
    payload: dict[str, Any] = {"tool_name": "Bash", "tool_input": {"command": command}}
    if cwd is not None:
        payload["cwd"] = cwd
    if project_dir is not None:
        payload["project_dir"] = project_dir
    return payload


def decide(payload: dict[str, Any], policy: Policy | None = None, **kwargs: Any) -> str:
    policy = policy or parse_policy_text(E2E_POLICY, home=POSIX_HOME)
    kwargs.setdefault("platform", "posix")
    kwargs.setdefault("home", POSIX_HOME)
    result = review(payload, policy, env={}, scan_disk=False, **kwargs)
    return result.verdict.decision


def test_e2e_allow_only_in_a_trusted_project() -> None:
    assert decide(bash("pwd")) == "allow"
    assert decide(bash("cat README.md")) == "allow"
    assert (
        decide(bash("pwd", project_dir="/home/dev/work/proj/sub", cwd="/home/dev/work/proj/sub"))
        == "allow"
    )


def test_e2e_untrusted_projects_get_no_allow() -> None:
    other = "/home/dev/other"
    assert decide(bash("pwd", project_dir=other, cwd=other)) == "gray"
    assert decide(bash("cat README.md", project_dir=other, cwd=other)) == "gray"
    sibling = "/home/dev/work/proj2"
    assert decide(bash("pwd", project_dir=sibling, cwd=sibling)) == "gray"
    parent = "/home/dev/work"
    assert decide(bash("pwd", project_dir=parent, cwd=parent)) == "gray"


def test_e2e_unknown_or_too_broad_project_is_not_trusted() -> None:
    assert decide(bash("pwd", project_dir=None)) == "gray"  # no project dir, no .git
    assert decide(bash("pwd", project_dir="/home/dev", cwd="/home/dev")) == "gray"
    assert decide(bash("pwd", project_dir="/", cwd="/")) == "gray"
    assert decide(bash("pwd", project_dir="work/proj")) == "gray"  # relative
    review_all = review(
        bash("pwd", project_dir="/home/dev", cwd="/home/dev"),
        parse_policy_text(E2E_POLICY, home=POSIX_HOME),
        platform="posix",
        env={},
        home=POSIX_HOME,
        scan_disk=False,
    )
    assert all(a.project is None for a in review_all.actions)


def test_e2e_a_session_whose_cwd_is_outside_the_project_is_not_trusted() -> None:
    # the project is trusted, but the command runs somewhere else
    assert decide(bash("pwd", cwd="/home/dev/elsewhere")) == "gray"
    assert decide(bash("pwd", cwd="/home/dev/work")) == "gray"
    assert decide(bash("pwd", cwd="relative/dir")) == "gray"


def test_e2e_wrapper_and_gray_actions_never_ride_the_rule() -> None:
    for command in (
        "sudo pwd",
        "env X=1 pwd",
        "nohup pwd",
        "cat $(whoami)",
        'cat "$UNSET_VAR"',
        "eval pwd",
    ):
        assert decide(bash(command)) != "allow", command
    wrapped = review(
        bash("sudo pwd"),
        parse_policy_text(E2E_POLICY, home=POSIX_HOME),
        platform="posix",
        env={},
        home=POSIX_HOME,
        scan_disk=False,
    )
    assert not any(h.decision == "allow" for av in wrapped.verdict.actions for h in av.hits)


def test_e2e_deny_rules_still_win() -> None:
    assert decide(bash("cat .env")) == "deny"
    assert decide(bash("pwd && cat .env")) == "deny"
    assert decide(bash("cat .env", project_dir="/home/dev/other", cwd="/home/dev/other")) == "deny"


def test_e2e_file_tools() -> None:
    write = {
        "tool_name": "Write",
        "tool_input": {"file_path": PROJECT + "/notes.txt"},
        "cwd": PROJECT,
        "project_dir": PROJECT,
    }
    assert decide(write) == "allow"
    assert decide({**write, "project_dir": "/home/dev/other", "cwd": "/home/dev/other"}) == "gray"
    outside = {**write, "tool_input": {"file_path": "/home/dev/other/notes.txt"}}
    assert decide(outside) == "gray"  # trusted project, but the file is not inside it
    assert decide({**write, "tool_input": {"file_path": PROJECT + "/.env"}}) == "deny"


def test_e2e_windows_machine_keys_and_case() -> None:
    policy = parse_policy_text(
        E2E_POLICY.replace("~/work/proj", "C:\\Users\\dev\\Work\\Proj"), home=WIN_HOME
    )
    assert policy.trusted_projects == ("c:/users/dev/work/proj",)
    project = "C:\\Users\\dev\\Work\\Proj"

    def write(directory: str, file_path: str) -> dict[str, Any]:
        return {
            "tool_name": "Write",
            "tool_input": {"file_path": file_path},
            "cwd": directory,
            "project_dir": directory,
        }

    def verdict(payload: dict[str, Any]) -> str:
        return decide(payload, policy, platform="windows", home=WIN_HOME)

    assert verdict(write(project, project + "\\a.txt")) == "allow"
    shouted = "c:/USERS/DEV/work/PROJ"
    assert verdict(write(shouted, shouted + "/a.txt")) == "allow"  # Windows keys fold case
    sibling = project + "2"
    assert verdict(write(sibling, sibling + "\\a.txt")) == "gray"
    assert verdict(write("D:\\Work\\Proj", "D:\\Work\\Proj\\a.txt")) == "gray"
    assert verdict(write("C:\\", "C:\\a.txt")) == "gray"


def test_e2e_an_entry_of_the_other_flavor_never_matches() -> None:
    policy = parse_policy_text(E2E_POLICY.replace("~/work/proj", "C:\\work\\proj"), home=POSIX_HOME)
    assert policy.trusted_projects == ("c:/work/proj",)
    assert decide(bash("pwd"), policy) == "gray"  # a POSIX project, a Windows-only trust list


def test_e2e_a_project_that_resolves_elsewhere_needs_both_places_trusted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same as the symlink test below, with the disk lookup faked (no privilege needed)."""
    link, real = "/home/dev/work/link", "/home/dev/elsewhere/real"
    real_resolve = norm_paths.resolve_on_disk

    def fake_resolve(path: norm_paths.NormPath) -> norm_paths.NormPath:
        if path.key == link or path.key.startswith(link + "/"):
            return dataclasses.replace(path, key=real + path.key[len(link) :])
        return real_resolve(path)

    monkeypatch.setattr(norm_paths, "resolve_on_disk", fake_resolve)
    payload = bash("pwd", project_dir=link, cwd=link)

    def verdict(trusted: str) -> str:
        policy = parse_policy_text(E2E_POLICY.replace("~/work/proj", trusted), home=POSIX_HOME)
        return decide(payload, policy)

    assert verdict("~/work/link") == "gray"  # the link is trusted, where it leads is not
    assert verdict("~/elsewhere/real") == "gray"  # where it leads is trusted, the link is not
    actions = normalize_event(payload, platform="posix", env={}, home=POSIX_HOME)
    assert [(a.project, a.project_resolved) for a in actions] == [(link, real)]
    both = E2E_POLICY.replace("- ~/work/proj", "- ~/work/link\n  - ~/elsewhere/real")
    assert decide(payload, parse_policy_text(both, home=POSIX_HOME)) == "allow"
    # a cwd below the link resolves below the resolved project: still inside, still trusted
    sub = bash("pwd", project_dir=link, cwd=link + "/sub")
    assert decide(sub, parse_policy_text(both, home=POSIX_HOME)) == "allow"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlinks")
def test_e2e_a_link_into_an_untrusted_place_is_not_trusted(tmp_path: Path) -> None:
    home = "C:\\Users\\nobody" if os.name == "nt" else "/home/nobody"
    platform: Any = "windows" if os.name == "nt" else "posix"
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        os.symlink(real, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create a symlink here")

    def verdict(trusted: list[str]) -> str:
        policy = parse_policy_text(
            yaml.safe_dump(
                {
                    "version": 1,
                    "trusted_projects": trusted,
                    "rules": [
                        {
                            "id": "allow-pwd",
                            "tool": ["Bash"],
                            "match": {"program": ["pwd"], "project_trusted": True},
                            "action": "allow",
                        }
                    ],
                }
            ),
            home=home,
        )
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "pwd"},
            "cwd": str(link),
            "project_dir": str(link),
        }
        result = review(payload, policy, platform=platform, env={}, home=home, scan_disk=False)
        return result.verdict.decision

    assert verdict([str(link)]) == "gray"  # the link is trusted, where it leads is not
    assert verdict([str(real)]) == "gray"  # where it leads is trusted, the link's own path is not
    assert verdict([str(link), str(real)]) == "allow"


# ------------------------------------------------------------------------------ Action.project


def project_of(payload: dict[str, Any], **kwargs: Any) -> list[str | None]:
    actions = normalize_event(payload, platform="posix", env={}, home=POSIX_HOME, **kwargs)
    assert actions
    return [a.project for a in actions]


EVENTS: list[tuple[str, dict[str, Any]]] = [
    ("bash-simple", {"tool_name": "Bash", "tool_input": {"command": "pwd"}}),
    ("bash-several", {"tool_name": "Bash", "tool_input": {"command": "ls; cat a.txt && pwd"}}),
    ("bash-gray-parse", {"tool_name": "Bash", "tool_input": {"command": "echo $(("}}),
    ("bash-eval", {"tool_name": "Bash", "tool_input": {"command": "eval ls"}}),
    ("bash-empty", {"tool_name": "Bash", "tool_input": {"command": ""}}),
    ("bash-no-command", {"tool_name": "Bash", "tool_input": {}}),
    ("powershell", {"tool_name": "PowerShell", "tool_input": {"command": "Get-Location"}}),
    ("write", {"tool_name": "Write", "tool_input": {"file_path": PROJECT + "/a.txt"}}),
    ("write-no-path", {"tool_name": "Write", "tool_input": {}}),
    ("edit", {"tool_name": "Edit", "tool_input": {"file_path": "a.txt"}}),
    ("read-outside", {"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}}),
    ("grep", {"tool_name": "Grep", "tool_input": {"pattern": "x", "path": PROJECT}}),
    ("glob", {"tool_name": "Glob", "tool_input": {"pattern": "*.py"}}),
    ("webfetch", {"tool_name": "WebFetch", "tool_input": {"url": "https://example.org/"}}),
    ("websearch", {"tool_name": "WebSearch", "tool_input": {"query": "q"}}),
    ("mcp", {"tool_name": "mcp__srv__tool", "tool_input": {}}),
    ("unknown-tool", {"tool_name": "Frobnicate", "tool_input": {}}),
    ("no-tool-input", {"tool_name": "Bash"}),
]


@pytest.mark.parametrize(("name", "event"), EVENTS, ids=[n for n, _ in EVENTS])
def test_action_project_is_set_for_every_action_of_every_kind_of_event(
    name: str, event: dict[str, Any]
) -> None:
    payload = {**event, "cwd": PROJECT, "project_dir": PROJECT}
    projects = project_of(payload, protected_globs=())
    assert projects, name
    assert all(p == PROJECT for p in projects), (name, projects)


def test_action_project_is_the_canonical_key_of_the_project_dir() -> None:
    event = {"tool_name": "Bash", "tool_input": {"command": "pwd"}}
    spellings = {
        PROJECT + "/": PROJECT,
        PROJECT + "/./": PROJECT,
        "~/work/proj": PROJECT,
        "/home/dev/work/../work/proj": PROJECT,
    }
    for spelling, key in spellings.items():
        assert project_of({**event, "cwd": PROJECT, "project_dir": spelling}) == [key], spelling
    windows = normalize_event(
        {**event, "cwd": "C:\\Users\\Dev\\Proj", "project_dir": "C:\\Users\\Dev\\Proj\\"},
        platform="windows",
        env={},
        home=WIN_HOME,
    )
    assert [a.project for a in windows] == ["c:/users/dev/proj"]  # same key format as PathRef.key
    assert [a.project_resolved for a in windows] == [None]  # equal to project: not repeated


def test_action_project_is_none_when_unknown_or_too_broad() -> None:
    event = {"tool_name": "Write", "tool_input": {"file_path": "/home/dev/work/proj/a"}}
    for project_dir in (None, "/", "/home/dev", "/home", "relative/x", ""):
        payload = dict(event)
        if project_dir is not None:
            payload["project_dir"] = project_dir
        assert project_of({**payload, "cwd": PROJECT}) == [None], project_dir
    for project_dir in ("C:\\", "C:\\Users", "C:\\Users\\dev"):
        windows = normalize_event(
            {**event, "cwd": project_dir, "project_dir": project_dir},
            platform="windows",
            env={},
            home=WIN_HOME,
        )
        assert [a.project for a in windows] == [None], project_dir


def test_action_project_is_none_when_the_session_cwd_is_outside_the_project() -> None:
    event = {"tool_name": "Bash", "tool_input": {"command": "pwd"}, "project_dir": PROJECT}
    assert project_of({**event, "cwd": "/home/dev/work"}) == [None]
    assert project_of({**event, "cwd": "/home/dev/work/proj2"}) == [None]
    assert project_of({**event, "cwd": "/home/dev/work/proj/sub"}) == [PROJECT]
    assert project_of(event) == [PROJECT]  # no cwd at all: the project dir stands
