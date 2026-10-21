"""M1c-3: the allow rule for the directory-changing commands (``allow-cd-family``), default only.

``cd`` only changes the working directory (no read, no write, no exec, no network), and the
normalizer already follows the new directory for the commands after it (``cd`` / ``pushd`` /
``popd`` / ``Set-Location`` / ``Push-Location`` / ``Pop-Location``, ``cd -``, ``cd ..`` ...), so
without an allow rule for ``cd`` itself every ``Set-Location 'proj'; <anything>`` line was gray even
when the rest of the line was allow. The rule allows a cd whose target is KNOWN to be inside the
project. It deliberately has no wider form: a no-path command after a cd (``git status``, ``pwd``)
takes its directory from the cd and has no path of its own for any rule to judge, so allowing a
cd out of the project would make ``cd ../other && git status`` allow while ``git -C ../other
status`` asks. This file pins:

* the rule text and its place in the policies (default only; strict keeps its one allow rule);
* the classification of every spelling the normalizer produces (program names, flags, paths);
* the hard invariants, on both fake machines, PowerShell on the Windows one, under the DEFAULT and
  the TRUSTED-project policy: after a cd the commands that follow are judged against the NEW
  directory, and a line is never more lenient than it was before the rule existed;
* the consistency of the embedded ``tests:`` with the rule.

No command is ever executed: they are only normalized.
"""

from __future__ import annotations

import sys
from functools import cache
from pathlib import Path
from typing import Any

import pytest
import yaml

from boundkeep import policycli
from boundkeep.normalize.model import Action, PathRef
from boundkeep.policy import Policy, Rule, evaluate, match_rule, parse_policy_text

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"
CORPUS_DIR = ROOT / "tests" / "corpus"
CD_CORPUS = CORPUS_DIR / "pipeline_m1c3_cd.yaml"
WORKFLOW = CORPUS_DIR / "workflow_benign.yaml"
DOC = ROOT / "docs" / "policy-reference.md"
PLATFORMS = ("windows", "posix")
PLATFORM_IDS = [f"on-{p}" for p in PLATFORMS]  # conftest.py skips ids that are the bare words
RULE_ID = "allow-cd-family"
SHELL_TOOLS = ("Bash", "PowerShell")
_RANK = {"allow": 0, "gray": 1, "ask": 2, "deny": 3}


# ---------------------------------------------------------------------------- helpers


def _text(name: str) -> str:
    return (POLICIES / f"{name}.yaml").read_text(encoding="utf-8")


def _rules(name: str) -> dict[str, dict[str, Any]]:
    data = yaml.safe_load(_text(name))
    return {rule["id"]: rule for rule in data["rules"]}


def _with_trusted(text: str, platform: str, trusted: bool) -> str:
    if not trusted:
        return text
    block = f"trusted_projects:\n  - '{policycli._FAKE[platform]['project']}'\n"
    assert "\nrules:\n" in text
    return text.replace("\nrules:\n", "\n" + block + "rules:\n", 1)


@cache
def _policy(name: str, platform: str, trusted: bool = False) -> Policy:
    text = _with_trusted(_text(name), platform, trusted)
    return parse_policy_text(text, home=policycli._FAKE[platform]["home"])


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


def _run(
    name: str, platform: str, tool: str, command: str, *, trusted: bool = False, **kw: Any
) -> Any:
    _needs_ps(tool)
    return policycli._run_one(
        _policy(name, platform, trusted),
        platform,  # type: ignore[arg-type]
        tool,
        {"command": command},
        kw.get("cwd"),
        kw.get("project_dir"),
    )


def _decide(
    name: str, platform: str, tool: str, command: str, *, trusted: bool = False, **kw: Any
) -> str:
    return str(_run(name, platform, tool, command, trusted=trusted, **kw).verdict.decision)


def _hit_ids(review: Any, index: int | None = None) -> set[str]:
    actions = review.verdict.actions if index is None else [review.verdict.actions[index]]
    return {hit.rule_id for action in actions for hit in action.hits}


def _rule(rule_id: str = RULE_ID) -> Rule:
    return {r.id: r for r in _policy("default", "posix").rules}[rule_id]


def _ref(access: str, inside: bool | None = True, key: str = "/home/testuser/proj/src") -> PathRef:
    return PathRef(raw=key, key=key, flavor="posix", access=access, inside_project=inside)  # type: ignore[arg-type]


def _action(**fields: Any) -> Action:
    base: dict[str, Any] = {"tool": "Bash", "shell": "bash", "platform": "posix"}
    if "sh" in fields:  # short spelling: the shell= keyword trips the security lint
        base["shell"] = fields.pop("sh")
    base.update(fields)
    return Action(**base)


# ---------------------------------------------------------------------------- rule facts


def test_the_rule_is_in_default_only_and_names_exactly_the_reviewed_programs() -> None:
    rule = _rules("default")[RULE_ID]
    assert rule["action"] == "allow"
    assert rule["tool"] == ["Bash", "PowerShell"]
    # the normalizer gives `sl`, `chdir` and `cd` in PowerShell the canonical name Set-Location and
    # `pushd` the name Push-Location (psaliases), so the four names cover every spelling
    assert rule["match"]["program"] == ["cd", "pushd", "Set-Location", "Push-Location"]
    assert RULE_ID not in _rules("strict")
    strict_allow = [i for i, r in _rules("strict").items() if r["action"] == "allow"]
    assert strict_allow == ["read-inside-project"]


def test_the_rule_requires_a_known_inside_path_that_is_only_read_and_nothing_else() -> None:
    match = _rules("default")[RULE_ID]["match"]
    assert set(match) == {"program", "path_inside_project", "paths_read_only"}
    assert match["path_inside_project"] is True
    assert match["paths_read_only"] is True
    # an allow rule never picks paths by name or reaches the network
    assert not {"path_glob", "path_outside_project", "network", "domain_in", "flags_any"} & set(
        match
    )


def test_the_rule_does_not_name_popd_or_the_cd_forms_without_a_path() -> None:
    # popd / Pop-Location / a bare cd / `cd -` carry no path to prove anything about: the rule
    # language cannot say "no path, or a path inside", so they stay gray (see the docs)
    names = {p.casefold() for p in _rules("default")[RULE_ID]["match"]["program"]}
    assert not names & {"popd", "pop-location", "chdir", "sl"}


def test_the_docs_table_names_the_rule_and_what_decides_the_cd_targets() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert f"`{RULE_ID}`" in text
    row = next(line for line in text.splitlines() if line.startswith(f"| `{RULE_ID}`"))
    for needle in ("Set-Location", "pushd", "popd", "no-secret-read"):
        assert needle in row, needle


@pytest.mark.parametrize("name", ["default", "strict"])
def test_emit_allow_stays_off(name: str) -> None:
    assert _policy(name, "posix").defaults.emit_allow is False


# ---------------------------------------------------------------------------- matcher level

CANON = {"program": "cd", "paths": [("read", True)]}


def _canon(**override: Any) -> Action:
    fields = dict(CANON)
    refs = tuple(_ref(access, inside) for access, inside in fields.pop("paths"))
    fields.update(override)
    return _action(paths=refs, **fields)


def test_the_canonical_actions_match() -> None:
    rule = _rule()
    assert match_rule(rule, _canon(), platform="posix")
    assert match_rule(rule, _canon(program="pushd"), platform="posix")
    ps = {"tool": "PowerShell", "sh": "powershell"}
    for program in ("set-location", "Set-Location", "SET-LOCATION", "push-location"):
        assert match_rule(rule, _canon(program=program, **ps), platform="posix"), program


@pytest.mark.parametrize("wrapper", ["sudo", "env", "nohup", "time"])
def test_a_wrapper_never_rides_the_rule(wrapper: str) -> None:
    assert not match_rule(_rule(), _canon(wrappers=(wrapper,)), platform="posix")


def test_a_gray_action_never_matches() -> None:
    action = _canon(gray=True, gray_reasons=("glob-not-expanded",))
    assert not match_rule(_rule(), action, platform="posix")


@pytest.mark.parametrize("access", ["write", "unknown"])
def test_a_path_that_is_written_or_may_be_written_breaks_it(access: str) -> None:
    action = _action(program="cd", paths=(_ref("read"), _ref(access)))
    assert not match_rule(_rule(), action, platform="posix")


@pytest.mark.parametrize("inside", [None, False])
def test_a_target_that_is_outside_or_unsure_is_never_allowed(inside: bool | None) -> None:
    action = _action(program="cd", paths=(_ref("read", inside, "/home/testuser/x"),))
    assert not match_rule(_rule(), action, platform="posix")
    two = _action(program="cd", paths=(_ref("read"), _ref("read", inside, "/home/testuser/x")))
    assert not match_rule(_rule(), two, platform="posix")


def test_no_path_at_all_is_not_a_match() -> None:
    # `cd`, `cd -`, `popd`, `pushd` without a directory: the target is home or unknown
    for program in ("cd", "pushd", "popd"):
        assert not match_rule(_rule(), _action(program=program), platform="posix")


def test_look_alike_programs_do_not_match() -> None:
    for program in ("chdir", "CD", "Pop-Location", "popd", "cdd", "cd.exe", "z", "j", "Set-Item"):
        action = _action(program=program, paths=(_ref("read"),))
        assert not match_rule(_rule(), action, platform="posix"), program


def test_the_protective_rules_still_win_at_the_matcher_level() -> None:
    policy = _policy("default", "posix")
    secret = _action(program="cd", paths=(_ref("read", False, "/home/testuser/.ssh"),))
    verdict = evaluate(policy, [secret], platform="posix")
    assert verdict.decision == "deny"
    # an inside path the secret rules also name: the allow rule matches, the deny rule wins
    env = _action(program="cd", paths=(_ref("read", True, "/home/testuser/proj/.env"),))
    verdict = evaluate(policy, [env], platform="posix")
    assert verdict.decision == "deny"
    assert RULE_ID in {h.rule_id for a in verdict.actions for h in a.hits}


# ---------------------------------------------------------------------------- classification


def _classify(platform: str, tool: str, command: str) -> tuple[Action, ...]:
    return tuple(_run("default", platform, tool, command).actions)


# (command, program, flags, [(path key suffix, access, inside)]) for the first action
BASH_FORMS: list[tuple[str, str, tuple[str, ...], list[tuple[str, str, bool | None]]]] = [
    ("cd src", "cd", (), [("/proj/src", "read", True)]),
    ("cd ./src", "cd", (), [("/proj/src", "read", True)]),
    ("cd .", "cd", (), [("/proj", "read", True)]),
    ("cd ..", "cd", (), [("/testuser", "read", False)]),
    ("cd -P src", "cd", ("-P",), [("/proj/src", "read", True)]),
    ("cd -L src", "cd", ("-L",), [("/proj/src", "read", True)]),
    ("cd -- src", "cd", (), [("/proj/src", "read", True)]),
    ("cd -", "cd", (), []),
    ("cd", "cd", (), []),
    ("cd $x", "cd", (), [("$x", "read", None)]),
    ("pushd src", "pushd", (), [("/proj/src", "read", True)]),
    ("pushd -n src", "pushd", ("-n",), [("/proj/src", "read", True)]),
    ("pushd", "pushd", (), []),
    ("popd", "popd", (), []),
    ("popd -n", "popd", ("-n",), []),
    ("chdir src", "chdir", (), []),  # not a bash builtin: an unknown program
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("command", "program", "flags", "paths"), BASH_FORMS)
def test_bash_classification_table(
    command: str,
    program: str,
    flags: tuple[str, ...],
    paths: list[tuple[str, str, bool | None]],
    platform: str,
) -> None:
    action = _classify(platform, "Bash", command)[0]
    assert action.program == program
    assert action.flags == flags
    assert action.wrappers == ()
    assert len(action.paths) == len(paths)
    for ref, (suffix, access, inside) in zip(action.paths, paths, strict=True):
        assert ref.key.endswith(suffix), (ref.key, suffix)
        assert ref.access == access
        assert ref.inside_project is inside


PS_FORMS: list[tuple[str, str, tuple[str, ...], list[tuple[str, str, bool | None]]]] = [
    ("Set-Location src", "set-location", (), [("/proj/src", "read", True)]),
    ("SET-LOCATION src", "set-location", (), [("/proj/src", "read", True)]),
    ("sl src", "set-location", (), [("/proj/src", "read", True)]),
    ("cd src", "set-location", (), [("/proj/src", "read", True)]),
    ("chdir src", "set-location", (), [("/proj/src", "read", True)]),
    ("cd ..", "set-location", (), [("/testuser", "read", False)]),
    ("cd..", "set-location", (), [("/testuser", "read", False)]),
    ("Set-Location -Path src", "set-location", ("-Path",), [("/proj/src", "read", True)]),
    (
        "Set-Location -LiteralPath src",
        "set-location",
        ("-LiteralPath",),
        [("/proj/src", "read", True)],
    ),
    (
        "Set-Location -Path src -PassThru",
        "set-location",
        ("-Path", "-PassThru"),
        [("/proj/src", "read", True)],
    ),
    ("Set-Location src -PassThru", "set-location", ("-PassThru",), [("/proj/src", "read", True)]),
    (
        "Set-Location -StackName s src",
        "set-location",
        ("-StackName",),
        [("/proj/src", "read", True)],
    ),
    ("Set-Location 'C:\\Users\\testuser\\proj'", "set-location", (), [("/proj", "read", True)]),
    ("Set-Location C:\\", "set-location", (), [("c:/", "read", False)]),
    ("Set-Location $x", "set-location", (), [("$x", "read", None)]),
    ("Set-Location", "set-location", (), []),
    ("Set-Location -", "set-location", (), []),
    ("Push-Location src", "push-location", (), [("/proj/src", "read", True)]),
    ("pushd src", "push-location", (), [("/proj/src", "read", True)]),
    (
        "Push-Location -Path src -PassThru",
        "push-location",
        ("-Path", "-PassThru"),
        [("/proj/src", "read", True)],
    ),
    (
        "Push-Location -StackName s src",
        "push-location",
        ("-StackName",),
        [("/proj/src", "read", True)],
    ),
    ("Push-Location", "push-location", (), []),
    ("Pop-Location", "pop-location", (), []),
    ("popd", "pop-location", (), []),
    ("Pop-Location -StackName s", "pop-location", ("-StackName",), []),
]


@pytest.mark.parametrize(("command", "program", "flags", "paths"), PS_FORMS)
def test_powershell_classification_table(
    command: str,
    program: str,
    flags: tuple[str, ...],
    paths: list[tuple[str, str, bool | None]],
) -> None:
    _needs_ps("PowerShell")
    action = _classify("windows", "PowerShell", command)[0]
    assert action.program == program
    assert action.flags == flags
    assert action.wrappers == ()
    assert len(action.paths) == len(paths)
    for ref, (suffix, access, inside) in zip(action.paths, paths, strict=True):
        assert ref.key.endswith(suffix), (ref.key, suffix)
        assert ref.access == access
        assert ref.inside_project is inside


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("wrapper", ["sudo", "env X=1", "nohup", "time"])
def test_wrapped_cd_keeps_its_marker(wrapper: str, platform: str) -> None:
    action = _classify(platform, "Bash", f"{wrapper} cd src")[0]
    assert action.program == "cd"
    assert action.wrappers
    assert _decide("default", platform, "Bash", f"{wrapper} cd src") != "allow"


# ---------------------------------------------------------------------------- decisions

# Every line the rule makes allow: the whole line, through the real pipeline, both machines.
ALLOWED_BASH = [
    "cd src",
    "cd ./src",
    "cd src/pkg",
    "cd src/",
    "cd .",
    "cd ./",
    "cd src/..",
    "cd -P src",
    "cd -L src",
    "cd -- src",
    "pushd src",
    "pushd -n src",
    "cd src && ls",
    "cd src; ls",
    "cd src && ls -la",
    "cd src && git status",
    "cd . && git status",
    "cd src && git log --oneline -n 5",
    "cd src && git diff --stat",
    "cd src && cat README.md",
    "cd src && head -n 3 a.txt",
    "cd src && grep -rn TODO .",
    "cd src && find . -name '*.py'",
    "cd src && rg TODO",
    "cd src && tree",
    "cd src && pwd",
    "cd src && mkdir -p build/out",
    "cd src && touch notes.md",
    "cd src && cd lib && ls",
    "cd src && cd lib && git status",
    "pushd src && ls",
    "(cd src && ls)",
    "cd src || ls",
    "cd src && ls | wc -l",
    "cd ~/proj/src",
]
ALLOWED_BASH_ON = {
    "windows": [
        "cd 'C:\\Users\\testuser\\proj' && git status",
        "cd C:/Users/testuser/proj/src && ls",
        "cd c:/users/testuser/proj && git status",
    ],
    "posix": [
        "cd /home/testuser/proj/src && ls",
        "cd /home/testuser/proj && git status",
        "cd $HOME/proj && git status",
        "cd ~/proj && git status",
    ],
}
ALLOWED_PS = [
    "Set-Location src",
    "Set-Location .\\src",
    "Set-Location src\\pkg",
    "Set-Location .",
    "Set-Location -Path src",
    "Set-Location -LiteralPath src",
    "Set-Location -Path src -PassThru",
    "Set-Location src -PassThru",
    "Set-Location -StackName s src",
    "Set-Location src -ErrorAction Stop",
    "SET-LOCATION src",
    "set-location src",
    "sl src",
    "cd src",
    "chdir src",
    "Push-Location src",
    "Push-Location -Path src -PassThru",
    "Push-Location -StackName s src",
    "pushd src",
    "Set-Location src; Get-ChildItem",
    "Set-Location src; Get-Location",
    "Set-Location src; Get-Date",
    "Set-Location src; Get-Content README.md",
    "Set-Location src; cat README.md",
    "Set-Location src; Test-Path x",
    "Set-Location src; git status",
    "Set-Location src; git log --oneline -n 5",
    "Set-Location src; Get-ChildItem | Select-Object Name",
    "Set-Location src; Get-ChildItem | Measure-Object",
    "sl src; ls",
    "cd src; ls",
    "cd .; git status",
    "Push-Location src; Get-ChildItem",
    "Push-Location -StackName s src; Get-ChildItem",
    "pushd src; Get-ChildItem",
    "Set-Location 'C:\\Users\\testuser\\proj'; git status",
    "Set-Location 'C:\\Users\\testuser\\proj'; Get-ChildItem",
    "Set-Location C:\\Users\\testuser\\proj\\src; ls",
    "Set-Location C:\\USERS\\TESTUSER\\PROJ\\src; ls",
    "cd C:\\Users\\testuser\\proj",
    "cd C:\\Users\\testuser\\proj\\src",
    "Set-Location src; Set-Location lib; Get-ChildItem",
    "'src' | Set-Location",  # a constant string fed to the cmdlet is its path (pipeline head)
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("command", ALLOWED_BASH)
def test_cd_into_the_project_is_allowed_bash(command: str, platform: str) -> None:
    review = _run("default", platform, "Bash", command)
    assert review.verdict.decision == "allow", (command, review.verdict.reasons)
    assert RULE_ID in _hit_ids(review, 0)


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_cd_into_the_project_is_allowed_bash_machine_specific(platform: str) -> None:
    for command in ALLOWED_BASH_ON[platform]:
        review = _run("default", platform, "Bash", command)
        assert review.verdict.decision == "allow", (command, review.verdict.reasons)
        assert RULE_ID in _hit_ids(review, 0)


@pytest.mark.parametrize("command", ALLOWED_PS)
def test_cd_into_the_project_is_allowed_powershell(command: str) -> None:
    review = _run("default", "windows", "PowerShell", command)
    assert review.verdict.decision == "allow", (command, review.verdict.reasons)
    assert RULE_ID in _hit_ids(review, 0)


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("command", ALLOWED_BASH)
def test_strict_allows_none_of_them_bash(command: str, platform: str) -> None:
    assert _decide("strict", platform, "Bash", command) != "allow"


@pytest.mark.parametrize("command", ALLOWED_PS)
def test_strict_allows_none_of_them_powershell(command: str) -> None:
    assert _decide("strict", "windows", "PowerShell", command) != "allow"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_the_allowed_lines_stay_allow_in_a_trusted_project(platform: str) -> None:
    for command in [*ALLOWED_BASH, *ALLOWED_BASH_ON[platform]]:
        assert _decide("default", platform, "Bash", command, trusted=True) == "allow", command


def test_the_allowed_powershell_lines_stay_allow_in_a_trusted_project() -> None:
    for command in ALLOWED_PS:
        assert _decide("default", "windows", "PowerShell", command, trusted=True) == "allow", (
            command
        )


# The lines that must keep EXACTLY the verdict they had before the rule: (command, windows, posix).
# The verdicts are those of the m1c2-done policy (a cd had no allow rule, so a line with a cd was
# never allow); the new rule must not make any of them more lenient. Protected targets are decided
# by the existing deny / ask rules through the directory path the cd carries, and the commands after
# the cd are judged against the new directory.
UNCHANGED_BASH: list[tuple[str, str, str]] = [
    # (1) the commands after a cd are judged against the new directory
    ("cd ~/.ssh && cat id_rsa", "deny", "deny"),
    ("cd .. && cat .env", "deny", "deny"),
    ("cd ../other && cat secrets.env", "deny", "deny"),
    ("cd /etc && cat shadow", "gray", "deny"),
    ("cd $HOME && cat .ssh/id_rsa", "deny", "deny"),
    ("cd .. && rm -rf x", "deny", "deny"),
    ("cd .. && ls", "gray", "gray"),
    ("cd /tmp && ls", "gray", "gray"),
    ("cd ~ && cat README.md", "gray", "gray"),
    ("cd ..; cd ..; cat .ssh/id_rsa", "deny", "deny"),
    ("cd x && cd .. && cat .env", "deny", "deny"),
    ("popd; cat x", "gray", "gray"),
    ("pushd .. && ls", "gray", "gray"),
    ("cd src; cd ..; ls", "gray", "gray"),
    ("cd src && (cd ..; ls)", "gray", "gray"),
    ("cd src && cd .. && cat .env", "deny", "deny"),
    ("cd src && cat ../.env", "deny", "deny"),
    ("cd src && cat ../../outside.txt", "gray", "gray"),
    ("cd .. && touch x", "gray", "gray"),
    ("cd .. && pwd", "gray", "gray"),
    ("cd .. && git status", "gray", "gray"),
    # a cd into a place the existing rules protect, followed by a read there
    ("cd .git && cat config", "deny", "deny"),
    ("cd .claude && cat settings.local.json", "deny", "deny"),
    ("cd ~/.aws && cat credentials", "deny", "deny"),
    ("cd ~/.claude && cat settings.json", "deny", "deny"),
    # a cd to a protected target is decided by the rules that protect it
    ("cd ~/.ssh", "deny", "deny"),
    ("cd ~/.aws", "deny", "deny"),
    ("cd .env", "deny", "deny"),
    # outside the project, or not provably inside: still gray, like before
    ("cd ..", "gray", "gray"),
    ("cd /tmp", "gray", "gray"),
    ("cd ~", "gray", "gray"),
    ("cd ~/.claude", "gray", "gray"),
    ("cd src/../..", "gray", "gray"),
    ("cd ../other && git log -p", "ask", "ask"),
    ("cd /tmp && git status", "gray", "gray"),
    # (5) a cd with something that is not allow stays not-allow
    ("cd src && pip install x", "ask", "ask"),
    ("cd src && python script.py", "gray", "gray"),
    ("cd src && pytest", "gray", "gray"),
    ("cd src && rm -rf x", "gray", "gray"),
    ("cd src && echo hi", "gray", "gray"),
    ("cd src && touch .env", "ask", "ask"),
    ("cd src && touch Makefile", "ask", "ask"),
    ("cd src | cat", "gray", "gray"),
    # dynamic targets stay what they were
    ("cd $x && git status", "gray", "gray"),
    ('cd "$(pwd)" && git status', "gray", "gray"),
    ("cd - && git status", "gray", "gray"),
    ("cd && git status", "gray", "gray"),
    ("cd * && git status", "gray", "gray"),
    ("cd $x", "gray", "gray"),
    ("cd -", "gray", "gray"),
    ("cd", "gray", "gray"),
    ("cd *", "gray", "gray"),
    ("pushd", "gray", "gray"),
    ("popd", "gray", "gray"),
    ("pushd src; popd", "gray", "gray"),
    ("pushd src && ls && popd", "gray", "gray"),
    # wrappers, environment prefixes, redirects
    ("sudo cd src && ls", "gray", "gray"),
    ("env X=1 cd src", "gray", "gray"),
    ("nohup cd src", "gray", "gray"),
    ("time cd src", "gray", "gray"),
    ("CDPATH=/etc cd src", "gray", "gray"),
    ("HOME=/tmp cd", "gray", "gray"),
    ("cd src > out.txt", "gray", "gray"),
    ("bash -c 'cd src && ls'", "gray", "gray"),
    ("chdir src", "gray", "gray"),
]
UNCHANGED_BASH_ON = {
    "windows": [
        ("cd C:/Users/testuser/proj-evil && ls", "gray"),
        ("cd D:/x && ls", "gray"),
    ],
    "posix": [
        ("cd /home/testuser/proj-evil && ls", "gray"),
        ("cd /home/testuser/PROJ && ls", "gray"),
        ("cd /home/testuser/proj/../other && ls", "gray"),
    ],
}
UNCHANGED_PS: list[tuple[str, str]] = [
    ("Set-Location ~\\.ssh; Get-Content id_rsa", "deny"),
    ("Set-Location ..; Get-Content .env", "deny"),
    ("cd .. ; Remove-Item -Recurse -Force x", "deny"),
    ("cd .. && rm -rf x", "deny"),
    ("Set-Location ..; Get-ChildItem", "gray"),
    ("cd ..; cd ..; cat .ssh/id_rsa", "deny"),
    ("pushd ..; Get-ChildItem", "gray"),
    ("Push-Location C:\\; Get-ChildItem", "gray"),
    ("popd; cat x", "gray"),
    ("Set-Location src; Get-Content ..\\.env", "deny"),
    ("Set-Location src; Set-Content a b", "gray"),
    ("Set-Location src; pip install x", "ask"),
    ("Set-Location src; python script.py", "gray"),
    ("Set-Location src; pytest", "gray"),
    ("Set-Location src; Remove-Item x", "gray"),
    ("Set-Location src; Write-Output hi", "gray"),
    ("Set-Location src; $x = 1", "gray"),
    ("Set-Location src; Invoke-Expression 'x'", "gray"),
    ("Set-Location src; .\\x.ps1", "gray"),
    ("Set-Location src; Get-Content", "gray"),
    ("Set-Location src; Select-String foo", "gray"),
    ("pushd src; popd", "gray"),
    ("pushd src; Get-ChildItem; popd", "gray"),
    ("Set-Location .git; Get-Content config", "deny"),
    ("Set-Location .claude; Get-Content settings.local.json", "deny"),
    ("Set-Location ~\\.aws", "deny"),
    ("Set-Location .env", "deny"),
    ("Set-Location ..", "gray"),
    ("Set-Location C:\\", "gray"),
    ("Set-Location D:\\x", "gray"),
    ("Set-Location C:\\Users\\testuser\\proj-evil", "gray"),
    ("Set-Location ..\\other; git log -p", "ask"),
    ("Set-Location \\\\server\\share", "ask"),
    ("Set-Location HKLM:\\", "gray"),
    ("Set-Location Env:", "gray"),
    # dynamic targets
    ("Set-Location $x", "gray"),
    ("Set-Location -Path $x; git status", "gray"),
    ("Set-Location $env:USERPROFILE; git status", "gray"),
    ("Set-Location *; git status", "gray"),
    ("Set-Location -; git status", "gray"),
    ("Set-Location; git status", "gray"),
    ("cd; git status", "gray"),
    ("$d = 'src'; Set-Location $d; ls", "gray"),
    ("'..' | Set-Location", "gray"),
    ("'~\\.ssh' | Set-Location", "deny"),
    ("'~\\.ssh' | Set-Location; Get-Content id_rsa", "deny"),
    ("'..' | Set-Location; Get-ChildItem", "gray"),
    ("$d | Set-Location; Get-Content id_rsa", "deny"),
    # (6) a cd inside a compound the normalizer marks gray
    ("if ($true) { cd x }", "gray"),
    ("if ($true) { cd src }; ls", "gray"),
    ("cd (Get-Item x)", "gray"),
    ("Set-Location (Get-Item x)", "gray"),
    ("foreach ($i in 1) { cd x }", "gray"),
    ("while ($true) { Set-Location src }", "gray"),
    ("try { Set-Location src } catch { }", "gray"),
    ("& { Set-Location src }", "gray"),
    ("Get-ChildItem | ForEach-Object { Set-Location $_ }", "gray"),
    # parameters the parser could not resolve, redirects, credentials
    ("Set-Location src -WhatIf", "gray"),
    ("Set-Location src -Confirm", "gray"),
    ("Set-Location src -Foo", "gray"),
    ("Set-Location src -Credential x", "gray"),
    ("Set-Location src > out.txt", "gray"),
    ("Set-Location src | Out-File x", "gray"),
    ("cd src && ls", "gray"),  # `&&` is a parse error in Windows PowerShell 5.1
]


@pytest.mark.parametrize("trusted", [False, True], ids=["default", "trusted"])
@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("command", "windows", "posix"), UNCHANGED_BASH)
def test_the_lines_that_must_not_get_more_lenient_bash(
    command: str, windows: str, posix: str, platform: str, trusted: bool
) -> None:
    expected = windows if platform == "windows" else posix
    got = _decide("default", platform, "Bash", command, trusted=trusted)
    if trusted and "pytest" in command:
        # the dev-tool preset: pytest is allow in the trusted project when the cd is allow too
        assert got == expected or (expected == "gray" and got == "allow"), (command, got)
        return
    assert got == expected, (command, trusted, got)


@pytest.mark.parametrize("trusted", [False, True], ids=["default", "trusted"])
@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_the_machine_specific_lines_that_must_not_get_more_lenient(
    platform: str, trusted: bool
) -> None:
    for command, expected in UNCHANGED_BASH_ON[platform]:
        got = _decide("default", platform, "Bash", command, trusted=trusted)
        assert got == expected, (command, trusted, got)


@pytest.mark.parametrize("trusted", [False, True], ids=["default", "trusted"])
@pytest.mark.parametrize(("command", "expected"), UNCHANGED_PS)
def test_the_lines_that_must_not_get_more_lenient_powershell(
    command: str, expected: str, trusted: bool
) -> None:
    got = _decide("default", "windows", "PowerShell", command, trusted=trusted)
    if trusted and "pytest" in command:
        assert got == expected or (expected == "gray" and got == "allow"), (command, got)
        return
    assert got == expected, (command, trusted, got)


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("command", [c for c, _, _ in UNCHANGED_BASH])
def test_strict_never_allows_the_lines_that_must_not_get_more_lenient(
    command: str, platform: str
) -> None:
    assert _decide("strict", platform, "Bash", command) != "allow"


@pytest.mark.parametrize("command", [c for c, _ in UNCHANGED_PS])
def test_strict_never_allows_the_powershell_lines_either(command: str) -> None:
    assert _decide("strict", "windows", "PowerShell", command) != "allow"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_trusting_the_project_does_not_let_a_cd_out_become_allow(platform: str) -> None:
    for command in ("cd ../other && pytest", "cd /tmp && ruff check .", "cd .. && mypy src"):
        assert _decide("default", platform, "Bash", command, trusted=True) != "allow", command


def test_the_dev_tool_after_an_allowed_cd_follows_the_trust() -> None:
    # `cd src && pytest` is only allow because the project is trusted: untrusted it is gray
    for platform in PLATFORMS:
        assert _decide("default", platform, "Bash", "cd src && pytest") == "gray"
        assert _decide("default", platform, "Bash", "cd src && pytest", trusted=True) == "allow"
        assert _decide("strict", platform, "Bash", "cd src && pytest", trusted=True) != "allow"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_a_cd_into_a_protected_directory_stays_decided_by_the_protective_rules(
    platform: str,
) -> None:
    for command, rule in (
        ("cd ~/.ssh", "no-secret-read"),
        ("cd ~/.aws", "no-credential-store-read"),
        ("cd .env", "no-secret-read"),
    ):
        review = _run("default", platform, "Bash", command)
        assert review.verdict.decision == "deny", command
        assert rule in _hit_ids(review), (command, _hit_ids(review))
    # the allow rule did not even need to be asked about: nothing allow-ish matched the secret path
    for command in ("cd .git && cat config", "cd .claude && cat settings.local.json"):
        review = _run("default", platform, "Bash", command)
        assert review.verdict.decision == "deny", command
        assert RULE_ID in _hit_ids(review, 0), command  # the cd is allow ...
        assert _hit_ids(review, 1) & {
            "no-credential-store-read",
            "no-agent-state-read",
        }  # ... the read is not


@pytest.mark.parametrize(
    ("command", "rule"),
    [
        ("Set-Location ~\\.ssh", "no-secret-read"),
        ("Set-Location ~\\.aws", "no-credential-store-read"),
        ("Set-Location .env", "no-secret-read"),
        ("Set-Location \\\\server\\share", "net-allowlist"),
    ],
)
def test_powershell_cd_targets_that_the_protective_rules_decide(command: str, rule: str) -> None:
    review = _run("default", "windows", "PowerShell", command)
    assert review.verdict.decision in ("deny", "ask"), command
    assert rule in _hit_ids(review), (command, _hit_ids(review))


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_commands_after_an_allowed_cd_are_judged_against_the_new_directory(platform: str) -> None:
    review = _run("default", platform, "Bash", "cd src && cat ../.env")
    assert review.verdict.decision == "deny"
    assert RULE_ID in _hit_ids(review, 0)
    assert "no-secret-read" in _hit_ids(review, 1)
    # `cd` can fail, so the old directory stays possible next to the new one: a path that leaves
    # the project from the PROJECT ROOT (`..`) is outside even though from src/ it would be inside
    for command in ("cd src && cat ../README.md", "cd src && cat ../../x.txt"):
        assert _decide("default", platform, "Bash", command) == "gray", command
    assert _decide("default", platform, "Bash", "cd src && cat README.md") == "allow"
    assert _decide("default", platform, "Bash", "cd src && cat ./sub/a.txt") == "allow"


def test_commands_after_an_allowed_powershell_cd_are_judged_against_the_new_directory() -> None:
    review = _run("default", "windows", "PowerShell", "Set-Location src; Get-Content ..\\.env")
    assert review.verdict.decision == "deny"
    review = _run("default", "windows", "PowerShell", "Set-Location src; Get-Content ..\\..\\x.txt")
    assert review.verdict.decision != "allow"
    # the old directory stays possible next to the new one (a cd can fail): `..` leaves the project
    review = _run("default", "windows", "PowerShell", "Set-Location src; Get-Content ..\\README.md")
    assert review.verdict.decision == "gray"
    review = _run("default", "windows", "PowerShell", "Set-Location src; Get-Content README.md")
    assert review.verdict.decision == "allow"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_the_session_cwd_below_the_project_root_is_handled(platform: str) -> None:
    project = policycli._FAKE[platform]["project"]
    sep = "\\" if platform == "windows" else "/"
    cwd = f"{project}{sep}tests"
    # from tests/ the parent is the project root: inside; two levels up are outside
    assert _decide("default", platform, "Bash", "cd .. && git status", cwd=cwd) == "allow"
    assert _decide("default", platform, "Bash", "cd ../.. && git status", cwd=cwd) == "gray"
    assert _decide("default", platform, "Bash", "cd ../src && ls", cwd=cwd) == "allow"


# ---------------------------------------------------------------------------- the corpora


def _cd_entries() -> list[dict[str, Any]]:
    data = yaml.safe_load(CD_CORPUS.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    return data


def test_the_cd_corpus_is_big_unique_and_mostly_adversarial() -> None:
    entries = _cd_entries()
    ids = [e["id"] for e in entries]
    assert len(set(ids)) == len(ids)
    assert len(entries) >= 60
    adv = [e for e in entries if e.get("adv")]
    assert len(adv) >= 40
    assert all(e["expect"] != "allow" for e in adv)
    assert sum(1 for e in entries if e["expect"] == "allow") >= 10
    assert {"Bash", "PowerShell"} <= {e["tool"] for e in entries}
    assert all(e["id"].startswith("m1c3-") for e in entries)


def _pipeline_entries() -> list[tuple[dict[str, Any], str]]:
    out: list[tuple[dict[str, Any], str]] = []
    for path in sorted(CORPUS_DIR.glob("pipeline*.yaml")):
        for entry in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            for platform in PLATFORMS:
                if entry.get("platform") in (None, platform):
                    out.append((entry, platform))
    return out


@pytest.mark.parametrize("trusted", [False, True], ids=["default", "trusted"])
def test_no_adversarial_shell_entry_of_any_corpus_is_allow(trusted: bool) -> None:
    """Hard invariant 3 (the whole pipeline corpus, with the new cd rule), default and trusted."""
    checked = 0
    offenders: list[str] = []
    for entry, platform in _pipeline_entries():
        if not entry.get("adv") or entry["tool"] not in SHELL_TOOLS:
            continue
        if entry["tool"] == "PowerShell" and not _ps_ready():
            continue
        checked += 1
        # entries of the trusted corpus with `trust: empty` run with an EMPTY trusted list
        use_trust = trusted and entry.get("trust") != "empty"
        review = policycli._run_one(
            _policy("default", platform, use_trust),
            platform,  # type: ignore[arg-type]
            entry["tool"],
            entry["input"],
            entry.get("cwd"),
            entry.get("project_dir"),
        )
        if review.verdict.decision == "allow":
            offenders.append(f"{entry['id']} ({platform})")
    assert checked > 500
    assert not offenders, offenders


def test_the_cd_entries_with_a_directory_change_are_all_exercised_by_a_shell_tool() -> None:
    commands = [str(e["input"]["command"]) for e in _cd_entries()]
    for needle in ("cd ", "pushd", "popd", "Set-Location", "Push-Location", "Pop-Location"):
        assert any(needle in c for c in commands), needle


def _workflow() -> list[dict[str, Any]]:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    return data


@pytest.mark.parametrize("trusted", [False, True], ids=["default", "trusted"])
def test_no_must_block_keep_ask_or_t3_exec_entry_of_the_workflow_corpus_is_allow(
    trusted: bool,
) -> None:
    """Hard invariant 4, default and trusted."""
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
            review = policycli._run_one(
                _policy("default", platform, trusted),
                platform,  # type: ignore[arg-type]
                entry["tool"],
                entry["input"],
                None,
                None,
            )
            if review.verdict.decision == "allow":
                offenders.append(f"{entry['id']} ({platform})")
    assert checked > 200
    assert not offenders, offenders


def test_the_workflow_corpus_has_the_cd_entries_in_the_right_tiers() -> None:
    cd_entries = [
        e
        for e in _workflow()
        if any(
            w in str(e["input"].get("command", ""))
            for w in ("cd ", "pushd", "Set-Location", "Push-Location")
        )
    ]
    assert len(cd_entries) >= 12
    tiers = {e["tier"] for e in cd_entries}
    assert {"t1-read", "must-block", "keep-ask"} <= tiers
    for e in cd_entries:
        if e["tier"] in ("must-block", "keep-ask"):
            assert e["expect_after"] != "allow", e["id"]
        if e["tier"] == "t1-read":
            assert e["expect_after"] == "allow", e["id"]


# ---------------------------------------------------------------------------- embedded tests


def _embedded() -> list[Any]:
    return list(_policy("default", "posix").tests)


def _cd_cases() -> list[Any]:
    return [
        t
        for t in _embedded()
        if t.tool in SHELL_TOOLS
        and any(
            w in str(t.input.get("command", ""))
            for w in ("cd ", "pushd", "popd", "Set-Location", "Push-Location", "Pop-Location")
        )
    ]


def test_the_embedded_tests_cover_both_shells_with_positives_and_negatives() -> None:
    cases = _cd_cases()
    for tool in SHELL_TOOLS:
        positives = [t for t in cases if t.tool == tool and t.expect == "allow"]
        negatives = [t for t in cases if t.tool == tool and t.expect != "allow"]
        assert len(positives) >= 3, tool
        assert len(negatives) >= 3, tool
    # the negatives pin what decides the protected targets, not only gray
    verdicts = {t.expect for t in cases}
    assert {"allow", "gray", "deny"} <= verdicts


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_the_embedded_cd_cases_hold(platform: str) -> None:
    for case in _cd_cases():
        if case.platform is not None and platform not in case.platform:
            continue
        if case.tool == "PowerShell" and not _ps_ready():
            continue
        review = policycli._run_one(
            _policy("default", platform),
            platform,  # type: ignore[arg-type]
            case.tool,
            case.input.thaw(),
            case.cwd,
            case.project_dir,
        )
        assert review.verdict.decision == case.expect, (platform, case.input.get("command"))
