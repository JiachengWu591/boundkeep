"""M1c: the allow rules for everyday use (default policy), and what keeps them safe.

With ``defaults.emit_allow`` false an ``allow`` verdict means "no decision": Claude Code's own flow
decides. These rules only stop boundkeep from asking about well-understood actions, so the tests
here are about the other direction: nothing dangerous, protected or outside the project may ever
become ``allow``.

* rule facts, read from the YAML (a dropped flag or glob fails loudly);
* per rule: every ``flags_none`` entry blocks, a wrapper or a gray action never matches;
* decisions through the real pipeline on the fake machines, for both policies;
* the hard invariants over the corpora: no ``adv`` shell entry is allow, no ``must-block`` /
  ``keep-ask`` / ``t3-exec`` entry of tests/corpus/workflow_benign.yaml is allow, every embedded
  ``tests:`` entry of an allow rule is backed by enough positive and negative cases.

The end-to-end corpus is tests/corpus/pipeline_m1c_allow.yaml. No command here is ever executed:
they are only normalized.
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from boundkeep import policycli
from boundkeep.normalize.model import Action, PathRef
from boundkeep.policy import Policy, Rule, evaluate, match_rule, parse_policy_text

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"
CORPUS_DIR = ROOT / "tests" / "corpus"
WORKFLOW = CORPUS_DIR / "workflow_benign.yaml"
DOC = ROOT / "docs" / "policy-reference.md"
PLATFORMS = ("windows", "posix")
# Ids other than the bare words windows / posix: conftest.py skips every test with such an id.
PLATFORM_IDS = [f"on-{p}" for p in PLATFORMS]

EXPECTED_ALLOW_IDS = {
    "read-inside-project",
    "allow-list-inside-project",
    "allow-tree-inside-project",
    "allow-find-inside-project",
    "allow-rg-inside-project",
    "allow-cat-inside-project",
    "allow-read-filters",
    "allow-no-path-commands",
    "allow-git-read-only",
    "allow-git-branch-list",
    "allow-ps-inspect-inside-project",
    "allow-ps-list-here",
    "allow-ps-no-path-commands",
    "allow-mkdir-touch-inside-project",
    "allow-project-file-writes",
    "allow-ps-data-shaping",
    "allow-cd-family",  # M1c-3 (tests/unit/test_m1c3_cd_allow.py)
    "allow-devtools-trusted-project",
}
NEW_ASK_IDS = {"ask-secret-file-write", "ask-credential-file-write", "ask-git-internals-write"}
GUARD_IDS = {"ask-shell-read-outside-project", "ask-git-read-outside-project"}
_RANK = {"allow": 0, "gray": 1, "ask": 2, "deny": 3}


# ---------------------------------------------------------------------------- helpers


def _text(name: str) -> str:
    return (POLICIES / f"{name}.yaml").read_text(encoding="utf-8")


def _data(name: str) -> dict[str, Any]:
    data = yaml.safe_load(_text(name))
    assert isinstance(data, dict)
    return data


def _rules(name: str) -> dict[str, dict[str, Any]]:
    return {rule["id"]: rule for rule in _data(name)["rules"]}


def _allow_rules(name: str) -> dict[str, dict[str, Any]]:
    return {i: r for i, r in _rules(name).items() if r["action"] == "allow"}


@cache
def _policy(name: str, platform: str) -> Policy:
    return parse_policy_text(_text(name), home=policycli._FAKE[platform]["home"])


@cache
def _ps_ready() -> bool:
    if sys.platform != "win32":
        return False
    from boundkeep.normalize import psparse

    psparse.warm_up(wait_s=15)
    return bool(psparse.status().get("state") == "ready")


def _needs_ps(tool: str) -> None:
    if tool == "PowerShell" and not _ps_ready():
        pytest.skip("PowerShell entries need the real parser helper (Windows only)")


def _run(name: str, platform: str, tool: str, tool_input: dict[str, Any]) -> Any:
    _needs_ps(tool)
    return policycli._run_one(_policy(name, platform), platform, tool, tool_input, None, None)  # type: ignore[arg-type]


def _decide(name: str, platform: str, tool: str, tool_input: dict[str, Any]) -> str:
    return str(_run(name, platform, tool, tool_input).verdict.decision)


def _hit_ids(review: Any) -> set[str]:
    return {hit.rule_id for action in review.verdict.actions for hit in action.hits}


def _flags(rule: dict[str, Any], key: str) -> set[str]:
    return set(rule["match"].get(key) or ())


def _tool_input(tool: str, target: str) -> dict[str, Any]:
    if tool in ("Bash", "PowerShell"):
        return {"command": target}
    if tool == "Write":
        return {"file_path": target, "content": "x"}
    if tool == "Edit":
        return {"file_path": target, "old_string": "a", "new_string": "b"}
    if tool == "MultiEdit":
        return {"file_path": target, "edits": [{"old_string": "a", "new_string": "b"}]}
    if tool == "NotebookEdit":
        return {"notebook_path": target, "new_source": "x"}
    raise AssertionError(tool)


def _ref(
    access: str, inside: bool | None = True, key: str = "/home/testuser/proj/a.txt"
) -> PathRef:
    return PathRef(raw=key, key=key, flavor="posix", access=access, inside_project=inside)  # type: ignore[arg-type]


def _action(**fields: Any) -> Action:
    base: dict[str, Any] = {"tool": "Bash", "shell": "bash", "platform": "posix"}
    if "sh" in fields:  # short spelling: the shell= keyword trips the security lint
        base["shell"] = fields.pop("sh")
    base.update(fields)
    return Action(**base)


def _rule(name: str, rule_id: str) -> Rule:
    rules = {r.id: r for r in _policy(name, "posix").rules}
    return rules[rule_id]


# ---------------------------------------------------------------------------- rule facts


@pytest.mark.parametrize("name", ["default", "strict"])
def test_emit_allow_stays_off(name: str) -> None:
    assert _data(name)["defaults"]["emit_allow"] is False
    assert _policy(name, "posix").defaults.emit_allow is False


def test_default_has_exactly_the_reviewed_allow_rules() -> None:
    assert set(_allow_rules("default")) == EXPECTED_ALLOW_IDS


def test_strict_keeps_read_inside_project_as_its_only_allow_rule() -> None:
    allow = _allow_rules("strict")
    assert set(allow) == {"read-inside-project"}
    assert allow["read-inside-project"] == _allow_rules("default")["read-inside-project"]


def test_strict_allow_rules_are_a_subset_of_defaults() -> None:
    assert set(_allow_rules("strict")) <= set(_allow_rules("default"))


_TWIN_EXCEPTIONS = {
    "ask-devtools-path-outside-project": "ask-read-outside-project",
    "net-allowlist": "net-always-ask",
    # strict reads outside the project with one rule for every program
    "ask-shell-read-outside-project": "ask-read-outside-project",
    "ask-git-read-outside-project": "ask-read-outside-project",
}


def _twin(default_id: str) -> str:
    if default_id in _TWIN_EXCEPTIONS:
        return _TWIN_EXCEPTIONS[default_id]
    return "deny-" + default_id[4:] if default_id.startswith("ask-") else default_id


def test_every_default_deny_and_ask_rule_has_an_equal_or_stricter_twin_in_strict() -> None:
    default, strict = _rules("default"), _rules("strict")
    for rule_id, rule in default.items():
        if rule["action"] == "allow":
            continue
        # default rules whose strict twin keeps the name or turns ask- into deny-
        twin = strict.get(rule_id) or strict.get(_twin(rule_id))
        assert twin is not None, f"strict has no twin for {rule_id}"
        assert _RANK[twin["action"]] >= _RANK[rule["action"]], (rule_id, twin["id"])


def test_the_new_ask_rules_exist_in_both_policies_with_the_same_globs() -> None:
    default, strict = _rules("default"), _rules("strict")
    for rule_id in NEW_ASK_IDS:
        assert rule_id in default, rule_id
        assert rule_id in strict, rule_id
        assert default[rule_id] == strict[rule_id], rule_id
        assert default[rule_id]["action"] == "ask"
        assert default[rule_id]["match"]["access"] == "write"
        assert "tool" not in default[rule_id]
        assert "platform" not in default[rule_id]


@pytest.mark.parametrize("name", ["default", "strict"])
def test_the_write_rules_copy_the_read_rule_globs_exactly(name: str) -> None:
    rules = _rules(name)
    assert (
        rules["ask-secret-file-write"]["match"]["path_glob"]
        == rules["no-secret-read"]["match"]["path_glob"]
    )
    assert (
        rules["ask-credential-file-write"]["match"]["path_glob"]
        == rules["no-credential-store-read"]["match"]["path_glob"]
    )
    assert rules["ask-git-internals-write"]["match"]["path_glob"] == ["**/.git/**"]


@pytest.mark.parametrize("rule_id", sorted(EXPECTED_ALLOW_IDS - {"read-inside-project"}))
def test_every_new_allow_rule_names_a_tool_or_a_program_and_is_in_default_only(
    rule_id: str,
) -> None:
    rule = _allow_rules("default")[rule_id]
    assert rule.get("tool") or rule["match"].get("program"), rule_id
    assert rule_id not in _rules("strict")
    forbidden = {"network", "domain_in", "domain_not_in", "mcp_server", "path_outside_project"}
    assert not forbidden & set(rule["match"]), rule_id


SHELL_ALLOW = sorted(
    {
        "allow-list-inside-project",
        "allow-tree-inside-project",
        "allow-find-inside-project",
        "allow-rg-inside-project",
        "allow-cat-inside-project",
        "allow-read-filters",
        "allow-no-path-commands",
        "allow-git-read-only",
        "allow-git-branch-list",
        "allow-ps-inspect-inside-project",
        "allow-ps-list-here",
        "allow-ps-no-path-commands",
        "allow-cd-family",
    }
)


@pytest.mark.parametrize("rule_id", SHELL_ALLOW)
def test_every_shell_allow_rule_is_read_only(rule_id: str) -> None:
    match = _allow_rules("default")[rule_id]["match"]
    assert match["paths_read_only"] is True
    assert "program" in match
    assert "path_glob" not in match  # an allow rule never picks paths by name


def test_write_allow_rules_require_a_path_inside_the_project() -> None:
    rules = _allow_rules("default")
    writes = rules["allow-project-file-writes"]
    assert writes["tool"] == ["Write", "Edit", "MultiEdit", "NotebookEdit"]
    assert writes["match"] == {
        "path_glob": ["**"],
        "access": "write",
        "path_inside_project": True,
    }
    mk = rules["allow-mkdir-touch-inside-project"]
    assert mk["tool"] == ["Bash"]  # PowerShell's mkdir is New-Item underneath: stays ask
    assert mk["match"]["program"] == ["mkdir", "touch"]
    assert mk["match"]["path_inside_project"] is True


def _programs(rule: dict[str, Any]) -> set[str]:
    return {p.casefold() for p in rule["match"].get("program", ())}


NO_PATH_RULES = ("allow-no-path-commands", "allow-ps-no-path-commands", "allow-ps-data-shaping")


def test_every_allow_rule_without_path_inside_project_is_covered_by_a_guard_rule() -> None:
    rules = _rules("default")
    guard_programs = _programs(rules["ask-shell-read-outside-project"])
    git_guard = rules["ask-git-read-outside-project"]
    for rule_id, rule in _allow_rules("default").items():
        if "program" not in rule["match"] or rule["match"].get("path_inside_project"):
            continue
        if rule["match"]["program"] == ["git"] or rule_id in NO_PATH_RULES:
            continue
        if (
            rule_id == "allow-devtools-trusted-project"
        ):  # its guard is ask-devtools-path-outside-project
            continue
        assert _programs(rule) <= guard_programs, (rule_id, _programs(rule) - guard_programs)
    # the guard is not wider than the rules it guards
    guarded: set[str] = set()
    for rule_id in ("allow-read-filters", "allow-ps-list-here"):
        guarded |= _programs(rules[rule_id])
    assert guard_programs == guarded
    # git: the guard names every subcommand some git allow rule allows
    allowed: set[str] = set()
    for rule_id in ("allow-git-read-only", "allow-git-branch-list"):
        allowed |= set(rules[rule_id]["match"]["subcommand"])
    assert set(git_guard["match"]["subcommand"]) == allowed
    assert git_guard["match"]["program"] == ["git"]


def test_the_no_path_rules_only_name_programs_the_normalizer_knows_take_no_path() -> None:
    from boundkeep.normalize import programs, psprograms

    bash_no_path = set(programs._NO_PATH_PROGRAMS)
    ps_no_path = {name.casefold() for name in psprograms._NOPATH}
    rules = _allow_rules("default")
    assert _programs(rules["allow-no-path-commands"]) <= bash_no_path
    assert _programs(rules["allow-ps-no-path-commands"]) <= ps_no_path
    assert _programs(rules["allow-ps-data-shaping"]) <= ps_no_path


@pytest.mark.parametrize("guard_id", sorted(GUARD_IDS))
def test_the_guard_rules_ask_for_paths_that_are_not_inside_the_project(guard_id: str) -> None:
    rule = _rules("default")[guard_id]
    assert rule["action"] == "ask"
    assert rule["tool"] == ["Bash", "PowerShell"]
    assert rule["match"]["path_outside_project"] is True
    # No path_glob / access: a "**" glob of a read rule would become a protected name for the
    # subtree scan of recursive reads (every file below a directory would count as protected).
    assert "path_glob" not in rule["match"]
    assert "access" not in rule["match"]


# The options each rule leaves out, with the reason (see the comments in policies/default.yaml).
REQUIRED_FLAGS_NONE: dict[str, set[str]] = {
    "allow-list-inside-project": {"--time-style"},  # prints the literal format string
    "allow-tree-inside-project": {"-o", "--output", "-R", "-H", "-T", "--timefmt"},
    "allow-find-inside-project": {
        "-delete",
        "-exec",
        "-execdir",
        "-ok",
        "-okdir",
        "-fprint",
        "-fprint0",
        "-fprintf",
        "-fls",
        "-files0-from",
        "-printf",  # prints its format string
    },
    "allow-rg-inside-project": {
        "--pre",
        "--hostname-bin",  # run a command
        "-r",
        "--replace",  # print the replacement
        "--context-separator",
        "--field-context-separator",
        "--field-match-separator",
        "--path-separator",
    },
    "allow-read-filters": {"--files0-from", "--label"},  # names read from a file / printed label
    "allow-git-read-only": {
        "-c",
        "--config-env",
        "-C",
        "--git-dir",
        "--work-tree",
        "--exec-path",
        "--paginate",
        "--ext-diff",
        "--textconv",
        "--output",
        "--no-index",
        "--open-files-in-pager",
        "--ignore-revs-file",
        "--help",
        # options that print a string given on the command line
        "--format",
        "--pretty",
        "--src-prefix",
        "--dst-prefix",
        "--line-prefix",
        "--date",
        "--sq-quote",
        "--default",
    },
    "allow-git-branch-list": {
        "-d",
        "-D",
        "--delete",
        "-m",
        "-M",
        "--move",
        "-c",
        "-C",
        "--copy",
        "-f",
        "--force",
        "-u",
        "--set-upstream-to",
        "--unset-upstream",
        "--edit-description",
        "--git-dir",
        "--work-tree",
        "--exec-path",
        "--paginate",
        "--help",
        "--format",
    },
    "allow-ps-no-path-commands": {"-Format", "-UFormat", "-Date"},  # print the format string
    "allow-mkdir-touch-inside-project": {"-r", "--reference"},
}


@pytest.mark.parametrize("rule_id", sorted(REQUIRED_FLAGS_NONE))
def test_flags_none_lists_every_reviewed_option(rule_id: str) -> None:
    rule = _allow_rules("default")[rule_id]
    missing = REQUIRED_FLAGS_NONE[rule_id] - _flags(rule, "flags_none")
    assert not missing, sorted(missing)


def test_git_abbreviations_of_the_exec_options_are_listed_too() -> None:
    listed = _flags(_allow_rules("default")["allow-git-read-only"], "flags_none")
    # git accepts any unique prefix of a long option
    for abbreviation in ("--ext", "--ext-", "--ext-d", "--ext-di", "--ext-dif"):
        assert abbreviation in listed
    for abbreviation in ("--textc", "--textco", "--textcon"):
        assert abbreviation in listed


def test_git_branch_only_allows_the_listing_forms() -> None:
    rule = _allow_rules("default")["allow-git-branch-list"]
    assert _flags(rule, "flags_any") == {
        "-a",
        "-r",
        "--list",
        "-l",
        "--all",
        "--remotes",
        "--show-current",
    }
    # `git branch -v NAME` creates the branch, so -v / -vv are not listing forms
    assert not {"-v", "-vv"} & _flags(rule, "flags_any")
    assert not _flags(rule, "flags_any") & _flags(rule, "flags_none")
    assert rule["match"]["subcommand"] == ["branch"]


def test_git_read_only_allows_exactly_the_reviewed_subcommands() -> None:
    rule = _allow_rules("default")["allow-git-read-only"]
    assert rule["match"]["subcommand"] == ["status", "diff", "log", "show", "blame", "rev-parse"]
    # `git stash` (even `stash list`) is not read-only: the rule language cannot see `list`
    assert "stash" not in rule["match"]["subcommand"]
    assert "branch" not in rule["match"]["subcommand"]
    assert rule["tool"] == ["Bash", "PowerShell"]


def test_no_allow_rule_covers_version_probes_or_interpreters() -> None:
    programs: set[str] = set()
    for rule in _allow_rules("default").values():
        programs |= _programs(rule)
    # echo / Write-Output / Select-Object print what the shell expands into them (secrets)
    for printing in ("echo", "printf", "printenv", "env", "write-output", "write-host"):
        assert printing not in programs
    # Select-Object is back, but only with -InputObject excluded and behind the pipeline-head check
    assert "-InputObject" in _flags(_allow_rules("default")["allow-ps-data-shaping"], "flags_none")
    # pytest, ruff, ... are in allow-devtools-trusted-project only, which needs a trusted project
    for exec_program in ("python", "python3", "node", "npm", "cargo", "go", "make", "uv"):
        assert exec_program not in programs
    for write_program in ("cp", "mv", "rm", "sed", "tee", "chmod", "ln", "new-item", "set-content"):
        assert write_program not in programs


def test_the_docs_table_names_every_new_rule() -> None:
    text = DOC.read_text(encoding="utf-8")
    for rule_id in sorted((EXPECTED_ALLOW_IDS - {"read-inside-project"}) | NEW_ASK_IDS | GUARD_IDS):
        assert f"`{rule_id}`" in text, rule_id


# ---------------------------------------------------------------------------- per rule behaviour

# One action each rule must match (a sanity check of the table below, and the base of the others).
CANON: dict[str, dict[str, Any]] = {
    "allow-list-inside-project": {"program": "ls", "paths": [("read", True)]},
    "allow-tree-inside-project": {"program": "tree", "paths": [("read", True)]},
    "allow-find-inside-project": {"program": "find", "paths": [("read", True)]},
    "allow-rg-inside-project": {"program": "rg", "paths": [("read", True)]},
    "allow-cat-inside-project": {"program": "cat", "paths": [("read", True)]},
    "allow-read-filters": {"program": "head", "paths": []},
    "allow-no-path-commands": {"program": "pwd", "paths": []},
    "allow-git-read-only": {"program": "git", "subcommand": "status", "paths": []},
    "allow-git-branch-list": {
        "program": "git",
        "subcommand": "branch",
        "flags": ("-a",),
        "paths": [],
    },
    "allow-ps-inspect-inside-project": {
        "tool": "PowerShell",
        "shell": "powershell",
        "program": "get-content",
        "paths": [("read", True)],
    },
    "allow-ps-list-here": {
        "tool": "PowerShell",
        "shell": "powershell",
        "program": "get-childitem",
        "paths": [],
    },
    "allow-ps-no-path-commands": {
        "tool": "PowerShell",
        "shell": "powershell",
        "program": "get-date",
        "paths": [],
    },
    "allow-mkdir-touch-inside-project": {"program": "mkdir", "paths": [("write", True)]},
    "allow-cd-family": {"program": "cd", "paths": [("read", True)]},
    "allow-project-file-writes": {
        "tool": "Write",
        "shell": None,
        "paths": [("write", True)],
    },
}


def _canon(rule_id: str, **override: Any) -> Action:
    fields = dict(CANON[rule_id])
    refs = tuple(_ref(access, inside) for access, inside in fields.pop("paths"))
    fields.update(override)
    return _action(paths=refs, **fields)


@pytest.mark.parametrize("rule_id", sorted(CANON))
def test_the_canonical_action_matches_its_rule(rule_id: str) -> None:
    assert match_rule(_rule("default", rule_id), _canon(rule_id), platform="posix")


@pytest.mark.parametrize("rule_id", sorted(CANON))
def test_a_wrapper_or_a_gray_marker_never_rides_an_allow_rule(rule_id: str) -> None:
    rule = _rule("default", rule_id)
    for wrapper in ("sudo", "env", "nohup", "time"):
        assert not match_rule(rule, _canon(rule_id, wrappers=(wrapper,)), platform="posix")
    assert not match_rule(rule, _canon(rule_id, gray=True, gray_reasons=("x",)), platform="posix")


_WRITE_RULES = ("allow-mkdir-touch-inside-project", "allow-project-file-writes")


@pytest.mark.parametrize("rule_id", sorted(r for r in CANON if CANON[r]["paths"]))
def test_a_path_that_is_written_or_unsure_is_never_allowed(rule_id: str) -> None:
    rule = _rule("default", rule_id)
    base = {k: v for k, v in CANON[rule_id].items() if k != "paths"}
    has_inside = _allow_rules("default")[rule_id]["match"].get("path_inside_project") is True
    if rule_id not in _WRITE_RULES:
        # a read-only rule: a written path and a may-write path break it
        for access in ("write", "unknown"):
            action = _action(paths=(_ref(access, True),), **base)
            assert not match_rule(rule, action, platform="posix"), access
    if has_inside:
        # the rules that name `path_inside_project`: an outside or unsure path breaks them
        # (the others leave that to the guard rules: test_the_guard_rules_win_...)
        access = "write" if rule_id in _WRITE_RULES else "read"
        for inside in (None, False):
            action = _action(paths=(_ref(access, inside),), **base)
            assert not match_rule(rule, action, platform="posix"), inside
        two = _action(paths=(_ref(access, True), _ref(access, False, "/etc/x")), **base)
        assert not match_rule(rule, two, platform="posix")


def _flag_cases() -> Iterator[Any]:
    for rule_id, flags in sorted(REQUIRED_FLAGS_NONE.items()):
        for flag in sorted(flags):
            yield pytest.param(rule_id, flag, id=f"{rule_id}{flag}")


@pytest.mark.parametrize(("rule_id", "flag"), list(_flag_cases()))
def test_every_flag_a_rule_leaves_out_blocks_it(rule_id: str, flag: str) -> None:
    rule = _rule("default", rule_id)
    canon = _canon(rule_id)
    assert match_rule(rule, canon, platform="posix")
    blocked = canon.model_copy(update={"flags": (*canon.flags, flag)})
    assert not match_rule(rule, blocked, platform="posix"), flag


def test_the_git_rules_match_only_their_own_subcommands() -> None:
    read = _rule("default", "allow-git-read-only")
    branch = _rule("default", "allow-git-branch-list")
    for sub in ("status", "diff", "log", "show", "blame", "rev-parse"):
        assert match_rule(read, _action(program="git", subcommand=sub), platform="posix")
        assert not match_rule(branch, _action(program="git", subcommand=sub), platform="posix")
    for sub in (
        "branch",
        "stash",
        "add",
        "commit",
        "push",
        "pull",
        "fetch",
        "clone",
        "checkout",
        "switch",
        "restore",
        "reset",
        "clean",
        "merge",
        "rebase",
        "tag",
        "config",
        "remote",
        "grep",
        "ls-files",
        "cat-file",
        "reflog",
        "worktree",
        "submodule",
    ):
        assert not match_rule(read, _action(program="git", subcommand=sub), platform="posix"), sub
    assert not match_rule(read, _action(program="git"), platform="posix")  # `git --version`
    # without a list flag `git branch` is not allowed
    assert not match_rule(branch, _action(program="git", subcommand="branch"), platform="posix")
    assert not match_rule(
        branch, _action(program="git", subcommand="branch", flags=("-v",)), platform="posix"
    )


def test_a_program_that_looks_like_an_allowed_one_is_not_allowed() -> None:
    for rule_id, lookalike in (
        ("allow-list-inside-project", "LS"),
        ("allow-list-inside-project", "lsd"),
        ("allow-cat-inside-project", "tac"),
        ("allow-read-filters", "zcat"),
        ("allow-read-filters", "sort"),
        ("allow-find-inside-project", "fd"),
        ("allow-rg-inside-project", "ag"),
        ("allow-no-path-commands", "printf"),
        ("allow-mkdir-touch-inside-project", "mktemp"),
    ):
        canon = CANON[rule_id]
        action = _action(program=lookalike, paths=tuple(_ref(a, i) for a, i in canon["paths"]))
        assert not match_rule(_rule("default", rule_id), action, platform="posix"), lookalike


def test_the_bash_rules_do_not_apply_to_powershell_and_the_reverse() -> None:
    bash_rule = _rule("default", "allow-list-inside-project")
    ps_action = _action(tool="PowerShell", sh="powershell", program="ls", paths=(_ref("read"),))
    assert not match_rule(bash_rule, ps_action, platform="posix")
    ps_rule = _rule("default", "allow-ps-inspect-inside-project")
    bash_action = _action(program="Get-Content", paths=(_ref("read"),))
    assert not match_rule(ps_rule, bash_action, platform="posix")  # tool filter
    ps_get_content = _action(
        tool="PowerShell", sh="powershell", program="Get-Content", paths=(_ref("read"),)
    )
    assert match_rule(ps_rule, ps_get_content, platform="posix")  # names ignore case


def test_pipeline_fed_path_cmdlets_have_no_path_and_are_not_allowed() -> None:
    for program in ("get-content", "select-string", "get-item", "resolve-path", "test-path"):
        action = _action(tool="PowerShell", sh="powershell", program=program)
        rule = _rule("default", "allow-ps-inspect-inside-project")
        assert not match_rule(rule, action, platform="posix"), program
        no_path = _rule("default", "allow-ps-no-path-commands")
        assert not match_rule(no_path, action, platform="posix"), program


def test_the_guard_rules_win_over_the_path_free_allow_rules() -> None:
    policy = _policy("default", "posix")
    outside = (_ref("read", False, "/etc/passwd"),)
    uncertain = (_ref("read", None, "/home/testuser/proj/*.py"),)
    for paths in (outside, uncertain):
        for program in ("head", "tail", "wc", "grep", "egrep", "fgrep"):
            verdict = evaluate(policy, [_action(program=program, paths=paths)], platform="posix")
            assert verdict.decision == "ask", (program, paths)
        # cat has a path rule of its own (path_inside_project): outside it nothing matches
        cat = evaluate(policy, [_action(program="cat", paths=paths)], platform="posix")
        assert cat.decision == "gray", paths
        for sub in ("status", "diff", "log", "show", "blame", "rev-parse"):
            verdict = evaluate(
                policy, [_action(program="git", subcommand=sub, paths=paths)], platform="posix"
            )
            assert verdict.decision == "ask", sub
        ps = _action(tool="PowerShell", sh="powershell", program="get-childitem", paths=paths)
        assert evaluate(policy, [ps], platform="posix").decision == "ask"
    inside = (_ref("read", True),)
    for program in ("cat", "head", "tail", "wc", "grep"):
        verdict = evaluate(policy, [_action(program=program, paths=inside)], platform="posix")
        assert verdict.decision == "allow", program


# ---------------------------------------------------------------------------- decisions

ALLOWED_BASH = [
    "ls",
    "ls -la src",
    "ls src tests",
    "ls -R",
    "dir src",
    "tree",
    "tree -L 2 src",
    "find . -name '*.py'",
    "find src -type f",
    "rg TODO src",
    "rg -n 'def main' src",
    "cat README.md",
    "cat src/pkg/sub/module.py",
    "cat package.json",
    "head -n 20 src/app.py",
    "tail -n 50 build.log",
    "wc -l src/app.py tests/test_x.py",
    "grep -rn TODO src",
    "grep -n def src/app.py",
    "egrep 'a|b' src/app.py",
    "fgrep -n x src/app.py",
    "pwd",
    "git status",
    "git status -s",
    "git diff",
    "git diff --stat",
    "git diff HEAD~1",
    "git log --oneline -n 20",
    "git log --oneline -n 10 -- src/app.py",
    "git show HEAD --stat",
    "git blame src/app.py",
    "git rev-parse HEAD",
    "git branch -a",
    "git branch --list",
    "git status && git diff --stat",
    "git log --oneline | head -n 5",
    "ls src | wc -l",
    "grep -rn TODO src | wc -l",
    "mkdir -p build/out",
    "mkdir docs/new",
    "touch notes.md",
    "touch src/__init__.py",
]
ALLOWED_PS = [
    "Get-ChildItem",
    "Get-ChildItem src -Recurse",
    "ls",
    "dir src",
    "Get-Location",
    "Get-Content src\\app.py",
    "Get-Content README.md -TotalCount 20",
    "cat README.md",
    "Select-String TODO src\\app.py",
    "Get-Date",
    "Test-Path src",
    "Get-Item README.md",
    "Resolve-Path src",
    "Get-ChildItem src | Measure-Object",
    "git status",
    "git diff --stat",
    "git log --oneline -n 20",
    "git branch -a",
]
WRITE_TOOLS = ["Write", "Edit", "MultiEdit", "NotebookEdit"]
ALLOWED_WRITE_TARGETS = [
    "src/app.py",
    "README.md",
    "docs/notes.md",
    "package-lock.json",
    "tsconfig.json",
    ".gitignore",
    "src/pkg/sub/helpers.py",
    "tests/test_x.py",
    "brand/new/dir/file.txt",
    "src/../docs/a.md",
    ".claude/settings.json.bak",
    ".github/CODEOWNERS",
]


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("command", ALLOWED_BASH)
def test_everyday_bash_commands_are_allowed(command: str, platform: str) -> None:
    review = _run("default", platform, "Bash", {"command": command})
    assert review.verdict.decision == "allow", (command, review.verdict.reasons)


@pytest.mark.parametrize("command", ALLOWED_PS)
def test_everyday_powershell_commands_are_allowed(command: str) -> None:
    review = _run("default", "windows", "PowerShell", {"command": command})
    assert review.verdict.decision == "allow", (command, review.verdict.reasons)


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("target", ALLOWED_WRITE_TARGETS)
@pytest.mark.parametrize("tool", WRITE_TOOLS)
def test_ordinary_project_writes_are_allowed(tool: str, target: str, platform: str) -> None:
    if tool == "NotebookEdit":
        target = "notebooks/analysis.ipynb"
    review = _run("default", platform, tool, _tool_input(tool, target))
    assert review.verdict.decision == "allow", (tool, target, review.verdict.reasons)
    assert "allow-project-file-writes" in _hit_ids(review)


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("command", ALLOWED_BASH)
def test_strict_allows_none_of_the_everyday_commands(command: str, platform: str) -> None:
    decision = _decide("strict", platform, "Bash", {"command": command})
    assert decision in ("gray", "ask", "deny"), command


@pytest.mark.parametrize("command", ALLOWED_PS)
def test_strict_allows_none_of_the_everyday_powershell_commands(command: str) -> None:
    decision = _decide("strict", "windows", "PowerShell", {"command": command})
    assert decision in ("gray", "ask", "deny"), command


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("target", ALLOWED_WRITE_TARGETS)
@pytest.mark.parametrize("tool", WRITE_TOOLS)
def test_strict_allows_no_project_write(tool: str, target: str, platform: str) -> None:
    if tool == "NotebookEdit":
        target = "notebooks/analysis.ipynb"
    decision = _decide("strict", platform, tool, _tool_input(tool, target))
    assert decision in ("gray", "ask", "deny"), (tool, target)


@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize("platform", PLATFORMS)
def test_reading_inside_the_project_is_still_allowed_in_both_policies(
    name: str, platform: str
) -> None:
    for tool, tool_input in (
        ("Read", {"file_path": "src/app.py"}),
        ("Grep", {"pattern": "TODO", "path": "src"}),
        ("Glob", {"pattern": "**/*.py"}),
    ):
        assert _decide(name, platform, tool, tool_input) == "allow", tool


# Names that must still ask / be denied / stay gray with the write allow rule in place
# (`expect` is the default policy's verdict; strict must be at least as strict).
PROTECTED_WRITES = [
    (".env", "ask"),
    (".env.local", "ask"),
    ("config/prod.env", "ask"),
    ("env", "ask"),
    ("certs/server.pem", "ask"),
    ("deploy/server.key", "ask"),
    ("id_rsa", "ask"),
    ("secrets.yml", "ask"),
    ("terraform.tfstate", "ask"),
    ("prod.tfvars", "ask"),
    (".htpasswd", "ask"),
    ("kubeconfig", "ask"),
    ("vault/passwords.kdbx", "ask"),
    (".aws/credentials", "ask"),
    (".git-credentials", "ask"),
    (".netrc", "ask"),
    (".npmrc", "ask"),
    (".docker/config.json", "ask"),
    ("Makefile", "ask"),
    ("package.json", "ask"),
    ("pyproject.toml", "ask"),
    ("tests/conftest.py", "ask"),
    ("Dockerfile", "ask"),
    (".github/workflows/x.yml", "ask"),
    (".claude/settings.json", "deny"),
    (".claude/settings.local.json", "deny"),
    ("managed-settings.json", "deny"),
    (".boundkeep/policy.yaml", "deny"),
    (".mcp.json", "ask"),
    ("CLAUDE.md", "ask"),
    (".claude/hooks/h.sh", "ask"),
    (".git/hooks/pre-commit", "ask"),
    (".git/config", "ask"),
    (".git/HEAD", "ask"),
    (".git/index", "ask"),
    (".git/info/attributes", "ask"),
    (".git/modules/sub/hooks/post-commit", "ask"),
    (".git/modules/sub/config", "ask"),
    ("vendor/lib/.git/hooks/pre-push", "ask"),
    ("~/.bashrc", "ask"),
    ("~/.ssh/authorized_keys", "ask"),
    ("~/.gitconfig", "ask"),
    ("../outside.txt", "gray"),
    ("src/../../outside.txt", "gray"),
    ("a/b/../../../outside.txt", "gray"),
    ("~/notes.txt", "gray"),
    ("src/../package.json", "ask"),
    ("src/../.env", "ask"),
    ("src/../.claude/settings.json", "deny"),
]


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize(("target", "expected"), PROTECTED_WRITES)
@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit"])
def test_protected_names_and_outside_paths_stay_out_of_the_write_allow_rule(
    tool: str, target: str, expected: str, platform: str
) -> None:
    review = _run("default", platform, tool, _tool_input(tool, target))
    assert review.verdict.decision == expected, (tool, target, review.verdict.reasons)
    strict = _decide("strict", platform, tool, _tool_input(tool, target))
    assert _RANK[strict] >= _RANK[expected], (tool, target, strict)
    assert strict != "allow"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_notebook_edit_follows_the_same_protection(platform: str) -> None:
    for target, expected in (
        (".env", "ask"),
        (".claude/settings.json", "deny"),
        ("../outside.ipynb", "gray"),
        ("notebooks/analysis.ipynb", "allow"),
    ):
        got = _decide("default", platform, "NotebookEdit", _tool_input("NotebookEdit", target))
        assert got == expected, target


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("C:\\Users\\testuser\\proj\\src\\app.py", "allow"),
        ("src\\app.py", "allow"),
        ("C:\\Users\\testuser\\proj\\.ENV", "ask"),
        (".env.", "ask"),
        (".env::$DATA", "ask"),
        (".CLAUDE\\Settings.JSON", "deny"),
        (".GIT\\HEAD", "ask"),
        ("src\\..\\..\\outside.txt", "gray"),
        ("C:\\Users\\testuser\\other\\x.txt", "gray"),
        ("C:\\Users\\testuser\\proj-evil\\x.py", "gray"),
        ("D:\\x.txt", "gray"),
        ("\\\\?\\C:\\Users\\testuser\\proj\\src\\app.py", "allow"),
    ],
)
def test_windows_spellings_of_the_same_paths(target: str, expected: str) -> None:
    got = _decide("default", "windows", "Write", _tool_input("Write", target))
    assert got == expected, target


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("/home/testuser/proj/src/app.py", "allow"),
        ("/home/testuser/proj/../other/x.py", "gray"),
        ("/home/testuser/proj-evil/x.py", "gray"),
        ("/home/testuser/PROJ/src/app.py", "gray"),  # POSIX paths are case-sensitive
        ("/home/testuser/proj/.env", "ask"),
        ("/home/testuser/proj/.git/hooks/pre-commit", "ask"),
        ("/etc/hosts", "gray"),
    ],
)
def test_posix_spellings_of_the_same_paths(target: str, expected: str) -> None:
    got = _decide("default", "posix", "Write", _tool_input("Write", target))
    if target == "/etc/hosts":
        assert got in ("gray", "ask")
    else:
        assert got == expected, target


NOT_ALLOWED_BASH = [
    # dangerous options of the allowed programs
    "find . -delete",
    "find . -name '*.pyc' -delete",
    "find . -exec cat {} +",
    "find . -execdir ls {} \\;",
    "find . -ok rm {} \\;",
    "find . -okdir rm {} \\;",
    "find . -fprint out.txt",
    "find . -fprint0 out.txt",
    "find . -fprintf out.txt %p",
    "find . -fls out.txt",
    "find . -files0-from list.txt",
    "rg --pre cat TODO src",
    "rg --pre=cat TODO src",
    "rg --hostname-bin x TODO",
    "tree -o out.txt",
    "tree -R",
    "wc --files0-from=list.txt",
    "git -c core.pager=x log",
    "git -c core.fsmonitor=x status",
    "git -C . status",
    "git --git-dir=sub/.git log",
    "git --work-tree=sub status",
    "git --exec-path=sub status",
    "git --paginate log",
    "git log -p --ext-diff",
    "git log -p --ext",
    "git show --ext-d",
    "git log -p --textconv",
    "git show --textc HEAD",
    "git diff --output=patch.txt",
    "git diff --outp=patch.txt",
    "git diff --no-index a.txt b.txt",
    "git blame --ignore-revs-file list.txt src/app.py",
    "git log --help",
    "git branch -a --help",
    "git branch",
    "git branch topic",
    "git branch -v topic",
    "git branch -vv topic",
    "git branch -d topic",
    "git branch -D topic",
    "git branch -a --delete topic",
    "git branch -m old new",
    "git branch -a --move old new",
    "git branch -c old new",
    "git branch -f topic HEAD~3",
    "git branch -u origin/main",
    "git branch --set-upstream-to=origin/main",
    "git branch --edit-description",
    "git stash list",
    "git stash",
    "git --version",
    "git add .",
    "git commit -m x",
    "touch -r ../x notes.md",
    "touch --reference=README.md notes.md",
    # outside the project
    "ls ..",
    "ls /etc",
    "ls ~",
    "cat /etc/passwd",
    "cat ../outside.txt",
    "cat ~/notes.txt",
    "cat src/../../outside.txt",
    "cat README.md ../outside.txt",
    "cat < /etc/passwd",
    "head -n 5 ../outside.txt",
    "tail -n 5 /var/log/syslog",
    "wc -l /etc/passwd",
    "grep -rn TODO /etc",
    "grep -rn TODO ..",
    "rg TODO ../other",
    "find / -name x",
    "find .. -name x",
    "tree ..",
    "git -C ../other status",
    "git diff -- ../outside.txt",
    "git log -- /etc/passwd",
    "git show HEAD:../x",
    "git blame --contents ../x.txt src/app.py",
    "git diff --no-index /etc/passwd /etc/hosts",
    "mkdir ../outside",
    "mkdir -p ~/x",
    "mkdir -p src/../../x",
    "touch ../x",
    "touch /tmp/x",
    "cd .. && ls",
    "cd /etc && cat passwd",
    # protected files
    "cat .env",
    "cat src/../.env",
    "head -n 1 .env",
    "tail -f .env",
    "wc -l .env",
    "grep SECRET .env",
    "rg SECRET .env",
    "ls .env",
    "find . -newer .env",
    "cat ~/.ssh/id_rsa",
    "cat certs/server.pem",
    "cat secrets.yml",
    "cat .mcp.json",
    "cat .claude/settings.local.json",
    "cat ~/.bash_history",
    "git show HEAD:.env",
    "git show :.env",
    "git log -p -- .env",
    "git blame .env",
    "echo $(cat .env)",
    "cat .env | head -n 1",
    "ls && cat .env",
    "git status; cat .env",
    "touch Makefile",
    "touch package.json",
    "touch .env",
    "touch .envrc",
    "touch .git/hooks/pre-commit",
    "touch .git/HEAD",
    "mkdir -p .git/hooks",
    "mkdir .claude",
    "touch .claude/settings.json",
    "touch ~/.bashrc",
    "touch ~/.ssh/authorized_keys",
    "touch id_rsa",
    "touch .aws/credentials",
    # writes
    "echo x > out.txt",
    "echo x >> README.md",
    "echo x > Makefile",
    "echo A=1 > .env",
    "echo x >> ~/.bashrc",
    "echo x > .git/hooks/pre-commit",
    "cat a.txt > b.txt",
    "ls > files.txt",
    "grep -rn TODO src > todo.txt",
    "git log > log.txt",
    "git diff > package.json",
    "pwd > p.txt",
    "echo x | tee out.txt",
    "sed -i s/a/b/ src/app.py",
    "cp a.txt b.txt",
    "mv a.txt b.txt",
    "rm src/old.py",
    "ln -s a.txt b.txt",
    "sort -o out.txt in.txt",
    # wrappers, environment, expansions, gray constructs
    "sudo ls",
    "sudo git status",
    "sudo cat README.md",
    "sudo mkdir x",
    "env ls",
    "env X=1 git status",
    "nohup ls",
    "LD_PRELOAD=x.so ls",
    "PATH=. ls",
    "BASH_ENV=x.sh ls",
    "GIT_PAGER=x git log",
    "PAGER=x git log",
    "GIT_EXTERNAL_DIFF=x git diff",
    "GIT_CONFIG_COUNT=1 git status",
    "GIT_SSH_COMMAND=x git status",
    "HOME=/tmp git status",
    "ls *.py",
    "ls $HOME",
    "ls $(pwd)",
    "cat $FILE",
    "cat $(ls)",
    "touch *.py",
    "touch $HOME/x",
    "mkdir -p a/{b,c}",
    "echo $(rm x)",
    "ls && rm x",
    "pwd; rm -rf /",
    "git status; curl https://example.invalid/x",
    "cat README.md | sh",
    "ls | xargs rm",
    "ls | xargs wc -l",
    "cat README.md | python -c 'x'",
    "eval ls",
    "bash -c 'ls'",
    "bash -c 'cat .env'",
    "(cat .env)",
    "mkdir -p b; touch b/x.sh; ./b/x.sh",
    # not covered on purpose
    "python --version",
    "node --version",
    "npm --version",
    "du -sh src",
    "date",
    "printenv",
    "env",
    "pytest",
    "make test",
    "npm test",
]


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("command", NOT_ALLOWED_BASH)
def test_dangerous_and_outside_bash_commands_are_never_allowed(command: str, platform: str) -> None:
    review = _run("default", platform, "Bash", {"command": command})
    assert review.verdict.decision != "allow", (command, _hit_ids(review))


NOT_ALLOWED_PS = [
    "Get-Content ..\\outside.txt",
    "Get-Content C:\\Windows\\win.ini",
    "Get-Content .env",
    "Get-Content ~\\.ssh\\id_rsa",
    "Get-Content $env:USERPROFILE\\.ssh\\id_rsa",
    "type secrets.yml",
    "Select-String KEY .env",
    "Select-String x ..\\y.txt",
    "Select-String -Path src\\*.py -Pattern TODO",
    "Get-Content src\\*.py",
    "Get-Content HKLM:\\Software\\X",
    "Get-ChildItem Env:",
    "Get-ChildItem C:\\Windows",
    "Get-ChildItem ..",
    "Get-ChildItem \\\\server\\share",
    "Get-ChildItem -Path . -Credential x",
    "Test-Path C:\\Windows",
    "Get-Item ..\\x",
    "Resolve-Path C:\\Windows",
    "Get-ChildItem -Recurse | Get-Content",
    "Get-ChildItem | Select-String foo",
    "Get-ChildItem | Get-Item",
    "Get-ChildItem | Resolve-Path",
    "Get-Content",
    "Select-String foo",
    "'..\\x' | Get-Content",
    "Write-Output hi > out.txt",
    "Write-Output hi > Makefile",
    "Write-Output hi | Out-File out.txt",
    "Get-Content src\\app.py | Set-Content out.txt",
    "Get-ChildItem | Remove-Item",
    "Get-ChildItem | Where-Object { $_.Name -like 'a*' }",
    "Get-ChildItem | ForEach-Object { Remove-Item $_ }",
    "Select-Object -Property @{n='a';e={1}}",
    "Write-Output $(Get-Content .env)",
    "Get-Content (Get-Location)",
    "Invoke-Expression 'Get-Date'",
    "& $env:SOME_TOOL status",
    "git -c core.pager=x log",
    "git diff --output=x.txt",
    "git log -p --ext-diff",
    "git -C ..\\other status",
    "git branch topic",
    "git branch -a -d topic",
    "git add .",
    "git status; Remove-Item src\\old.py",
    "mkdir build",
    "New-Item -ItemType Directory build",
    "New-Item -ItemType SymbolicLink -Path link -Target C:\\Windows",
    "New-Item -ItemType Junction -Path j -Target C:\\Users",
    "python --version",
    "Get-Process",
]


@pytest.mark.parametrize("command", NOT_ALLOWED_PS)
def test_dangerous_and_outside_powershell_commands_are_never_allowed(command: str) -> None:
    review = _run("default", "windows", "PowerShell", {"command": command})
    assert review.verdict.decision != "allow", (command, _hit_ids(review))


# X1 review L-7: "once someone writes an allow for echo, secrets can be printed". An environment
# value that reaches the agent's context is the harm, so nothing that prints what the shell expands
# into its arguments (or what is piped into it) is an allow rule, in either policy.
SECRET_PRINTING_BASH = [
    "echo $ANTHROPIC_API_KEY",
    'echo "$X_TOKEN"',
    "echo ${PASSWORD}",
    "echo token=$X_TOKEN",
    "echo hello",
    "echo",
    "printenv",
    "printenv X_TOKEN",
    "env | grep TOKEN",
    "echo $(cat .env)",
    "pwd; echo $X_TOKEN",
    "ls && echo $X_TOKEN",
    "find . -printf $X_TOKEN",
    'find . -maxdepth 0 -printf "$X_TOKEN"',
    "rg -r $X_TOKEN x src",
    "rg --replace=$X_TOKEN x src",
    "rg -C1 --context-separator=$X_TOKEN x src",
    "grep -H --label=$X_TOKEN x",
    "ls -l --time-style=+$X_TOKEN",
    "tree -H . -T $X_TOKEN",
    "git log --format=$X_TOKEN",
    "git log --form=$X_TOKEN",
    "git log --pretty=format:$X_TOKEN",
    "git show --format=$X_TOKEN",
    "git diff --src-prefix=$X_TOKEN",
    "git log --date=format:$X_TOKEN",
    "git branch -a --format=$X_TOKEN",
    "git rev-parse --sq-quote $X_TOKEN",
]
SECRET_PRINTING_PS = [
    "Write-Output $env:SECRET_TOKEN",
    'Write-Output "$env:SECRET_TOKEN"',
    "Write-Output hi",
    "echo $env:SECRET_TOKEN",
    "$env:SECRET_TOKEN | Select-Object",
    "Select-Object -InputObject $env:SECRET_TOKEN",
    "Get-Date -Format $env:SECRET_TOKEN",
    "Get-Date -UFormat %Y",
    "Get-Date -Date $env:SECRET_TOKEN",
    "git log --format=$env:SECRET_TOKEN",
    "Write-Output $(Get-Content .env)",
]


@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("command", SECRET_PRINTING_BASH)
def test_nothing_that_prints_an_environment_value_is_allowed_bash(
    command: str, platform: str, name: str
) -> None:
    review = _run(name, platform, "Bash", {"command": command})
    assert review.verdict.decision != "allow", (command, _hit_ids(review))


@pytest.mark.parametrize("name", ["default", "strict"])
@pytest.mark.parametrize("command", SECRET_PRINTING_PS)
def test_nothing_that_prints_an_environment_value_is_allowed_powershell(
    command: str, name: str
) -> None:
    review = _run(name, "windows", "PowerShell", {"command": command})
    assert review.verdict.decision != "allow", (command, _hit_ids(review))


def test_the_secret_printing_commands_that_read_a_secret_file_are_denied() -> None:
    for name in ("default", "strict"):
        for platform in PLATFORMS:
            assert _decide(name, platform, "Bash", {"command": "echo $(cat .env)"}) == "deny"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_a_deny_or_ask_rule_always_beats_an_allow_hit_on_the_same_action(platform: str) -> None:
    # an action that is hit by an allow rule AND a protective rule: the protective one decides
    for tool, target, protective in (
        ("Write", ".env", "ask-secret-file-write"),
        ("Write", ".aws/credentials", "ask-credential-file-write"),
        ("Write", ".git/HEAD", "ask-git-internals-write"),
        ("Write", "Makefile", "ask-project-autorun-files"),
        ("Write", ".claude/settings.json", "protect-guard-config"),
        ("Bash", "touch .env", "ask-secret-file-write"),
        ("Bash", "cat .env", "no-secret-read"),
        ("Bash", "head -n 1 ../x", "ask-shell-read-outside-project"),
        ("Bash", "git -C ../x status", "ask-git-read-outside-project"),
    ):
        review = _run("default", platform, tool, _tool_input(tool, target))
        assert protective in _hit_ids(review), (target, _hit_ids(review))
        assert review.verdict.decision in ("ask", "deny"), target
    both = _run("default", platform, "Write", _tool_input("Write", ".env"))
    assert {"allow-project-file-writes", "ask-secret-file-write"} <= _hit_ids(both)
    assert both.verdict.decision == "ask"


# ---------------------------------------------------------------------------- the corpora

SHELL_TOOLS = ("Bash", "PowerShell")


def _pipeline_entries() -> list[tuple[dict[str, Any], str]]:
    out: list[tuple[dict[str, Any], str]] = []
    for path in sorted(CORPUS_DIR.glob("pipeline*.yaml")):
        for entry in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            for platform in PLATFORMS:
                if entry.get("platform") in (None, platform):
                    out.append((entry, platform))
    return out


def test_no_adversarial_shell_entry_of_any_pipeline_corpus_is_allowed() -> None:
    """Hard invariant 1: every `adv: true` shell entry stays non-allow under the default policy."""
    checked = 0
    offenders: list[str] = []
    for entry, platform in _pipeline_entries():
        if not entry.get("adv") or entry["tool"] not in SHELL_TOOLS:
            continue
        if entry["tool"] == "PowerShell" and not _ps_ready():
            continue
        checked += 1
        got = _decide("default", platform, entry["tool"], entry["input"])
        if got == "allow":
            offenders.append(f"{entry['id']} ({platform})")
    assert checked > 100
    assert not offenders, offenders


def test_the_m1c_corpus_covers_the_allowed_and_the_adversarial_forms() -> None:
    entries = yaml.safe_load((CORPUS_DIR / "pipeline_m1c_allow.yaml").read_text(encoding="utf-8"))
    assert len(entries) >= 400
    ids = [e["id"] for e in entries]
    assert len(set(ids)) == len(ids)
    adv = [e for e in entries if e.get("adv")]
    assert len(adv) >= 300
    assert all(e["expect"] != "allow" for e in adv)
    assert sum(1 for e in entries if e["expect"] == "allow") >= 100
    shell_adv = {e["tool"] for e in adv}
    assert {"Bash", "PowerShell", "Write", "Edit", "MultiEdit", "NotebookEdit"} <= shell_adv


def _workflow() -> list[dict[str, Any]]:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    return data


def test_nothing_that_must_block_keep_asking_or_run_code_is_allowed() -> None:
    """Hard invariant 2, on tests/corpus/workflow_benign.yaml."""
    checked = 0
    offenders: list[str] = []
    for entry in _workflow():
        if entry["tier"] not in ("must-block", "keep-ask", "t3-exec"):
            continue
        for platform in PLATFORMS:
            if entry.get("platform") not in (None, platform):
                continue
            if entry["tool"] == "PowerShell" and not _ps_ready():
                continue
            checked += 1
            got = _decide("default", platform, entry["tool"], entry["input"])
            if got == "allow":
                offenders.append(f"{entry['id']} ({platform})")
    assert checked > 200
    assert not offenders, offenders


def _measure_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "measure_ask_rate_m1c", ROOT / "scripts" / "measure_ask_rate.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_the_default_policy_reaches_the_design_target_of_the_workflow_corpus(
    platform: str,
) -> None:
    tool = _measure_tool()
    result = tool.measure_platform(
        _workflow(), _policy("default", platform), platform, ps_available=_ps_ready()
    )
    assert not result.mismatches, [(m.id, m.expected, m.got) for m in result.mismatches]
    # the everyday tiers no longer prompt
    assert tool.asks_per_100(result.by_tier["t2-write"]) == 0.0
    assert tool.asks_per_100(result.by_tier["t1-read"]) == 0.0
    # and the tiers that must prompt still do, and the must-block ones still deny or ask
    assert tool.asks_per_100(result.by_tier["t3-exec"]) == 100.0
    assert tool.asks_per_100(result.by_tier["keep-ask"]) == 100.0
    assert result.by_tier["must-block"].get("allow", 0) == 0


# ---------------------------------------------------------------------------- subtree scan

# A read rule with a catch-all glob ("**") is taken as a protected NAME by the subtree scan of
# recursive reads: every entry of a directory then matches, the scan stops at the first level and
# a `certs/a.pem` below it is never looked at (found while adding the guard rules).


@pytest.mark.parametrize("name", ["default", "strict"])
def test_no_read_rule_has_a_catch_all_glob(name: str) -> None:
    from boundkeep.daemon import pipeline

    globs = pipeline.protected_read_globs(_policy(name, "posix"))
    assert "**" not in globs
    assert "**/*" not in globs
    assert len(globs) > 30  # the secret, credential and agent-state globs are still there


@pytest.mark.parametrize("name", ["default", "strict"])
def test_a_recursive_read_still_finds_a_nested_secret(name: str, tmp_path: Path) -> None:
    from boundkeep.daemon import pipeline

    home = tmp_path / "home"
    proj = home / "proj"
    (proj / "certs").mkdir(parents=True)
    (proj / "src").mkdir()
    (proj / "certs" / "a.pem").write_text("x", encoding="utf-8")
    (proj / "src" / "app.py").write_text("x", encoding="utf-8")
    on_windows = sys.platform == "win32"
    env = {"USERPROFILE": str(home)} if on_windows else {"HOME": str(home)}
    policy = parse_policy_text(_text(name), home=str(home))

    def verdict(tool: str, tool_input: dict[str, Any]) -> str:
        payload = {
            "tool_name": tool,
            "tool_input": tool_input,
            "cwd": str(proj),
            "project_dir": str(proj),
        }
        review = pipeline.review(
            payload,
            policy,
            platform="windows" if on_windows else "posix",
            env=env,
            home=str(home),
        )
        return str(review.verdict.decision)

    assert verdict("Grep", {"pattern": "x", "path": str(proj)}) == "deny"
    assert verdict("Grep", {"pattern": "x"}) == "deny"
    assert verdict("Bash", {"command": "grep -r x ."}) == "deny"
    assert verdict("Bash", {"command": "rg x"}) == "deny"
    assert verdict("Grep", {"pattern": "x", "path": "src"}) == "allow"


# ---------------------------------------------------------------------------- embedded tests


def _embedded_cases(name: str) -> list[Any]:
    return list(_policy(name, "posix").tests)


@cache
def _embedded_reviews() -> tuple[tuple[int, Any, Any], ...]:
    """(index, case, review) of every embedded test of the default policy, run on the platform
    it names (the first one it applies to), PowerShell cases only when the helper is ready."""
    out = []
    for index, case in enumerate(_embedded_cases("default")):
        if case.tool == "PowerShell" and not _ps_ready():
            continue
        platform = next(p for p in PLATFORMS if case.platform is None or p in case.platform)
        review = policycli._run_one(
            _policy("default", platform),
            platform,  # type: ignore[arg-type]
            case.tool,
            case.input.thaw(),
            case.cwd,
            case.project_dir,
        )
        out.append((index, case, review))
    return tuple(out)


@pytest.mark.parametrize("rule_id", sorted(EXPECTED_ALLOW_IDS - {"read-inside-project"}))
def test_every_allow_rule_has_embedded_positive_and_negative_tests(rule_id: str) -> None:
    if rule_id == "allow-devtools-trusted-project":
        # the shipped policy trusts no project, so no embedded test can reach this rule; its
        # positives and negatives are tests/corpus/pipeline_m1c2_trusted.yaml
        pytest.skip("needs a trusted project: see test_m1c2_trusted_policy.py")
    rule = _rule("default", rule_id)
    if rule.tool == ("PowerShell",) and not _ps_ready():
        pytest.skip("PowerShell embedded tests need the real parser helper (Windows only)")
    programs = {p.casefold() for p in (rule.match.program or ())}
    positives: set[int] = set()
    negatives: set[int] = set()
    for index, case, review in _embedded_reviews():
        hit_this_rule = any(
            hit.rule_id == rule_id for verdict in review.verdict.actions for hit in verdict.hits
        )
        if case.expect == "allow" and hit_this_rule:
            positives.add(index)
        elif case.expect != "allow":
            touches = any(
                (action.program or "").casefold() in programs
                if programs
                else (rule.tool is not None and action.tool in rule.tool)
                for action in review.actions
            )
            if touches:
                negatives.add(index)
    assert len(positives) >= 3, (rule_id, len(positives))
    assert len(negatives) >= 3, (rule_id, len(negatives))


@pytest.mark.parametrize("name", ["default", "strict"])
def test_the_embedded_tests_pin_the_new_ask_rules(name: str) -> None:
    seen = {
        (t.tool, str(t.input.get("file_path") or t.input.get("command") or ""), t.expect)
        for t in _embedded_cases(name)
    }
    for target in (".env", "certs/server.pem", ".aws/credentials", ".git/HEAD"):
        assert ("Write", target, "ask") in seen, (name, target)
    assert ("Edit", ".env", "ask") in seen
    assert ("Bash", "touch .env", "ask") in seen
