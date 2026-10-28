"""The rules after M2 (docs/reports/M2-rules-3.md): MCP arguments, declared read-only MCP tools,
the network destination split, service-manager verbs, and persistence / delete as deny.

MCP calls stay gray; their local paths, commands and URLs reach the deny and ask rules. A tool the
user declares in ``mcp_read_only`` can be allowed, and only when nothing else about the call is
unclear. Strict has no such allow and is at least as strict as default on every new deny.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

import pytest

from boundkeep import policycli
from boundkeep.normalize import event
from boundkeep.policy import Policy, default_policy_text, matcher, parse_policy_text
from boundkeep.policy.loader import PolicyError

ROOT = Path(__file__).resolve().parents[2]
PLATFORMS = ("windows", "posix")
PLATFORM_IDS = [f"on-{p}" for p in PLATFORMS]  # conftest.py skips ids that are the bare words

DECLARED = (
    "mcp_read_only:\n"
    '  - "mcp__github__get_*"\n'
    '  - "mcp__github__list_*"\n'
    '  - "mcp__db__query"\n'
    '  - "mcp__filesystem__read_file"\n'
    '  - "mcp__docs__*"\n'
    '  - "mcp__shell__run_command"\n'
)


@cache
def _policy(platform: str, declared: bool = False) -> Policy:
    text = default_policy_text()
    if declared:
        assert text.count("\nmcp_read_only: []\n") == 1
        text = text.replace("\nmcp_read_only: []\n", "\n" + DECLARED)
    return parse_policy_text(text, home=policycli._FAKE[platform]["home"])


@cache
def _strict(platform: str) -> Policy:
    text = (ROOT / "policies" / "strict.yaml").read_text(encoding="utf-8")
    return parse_policy_text(text, home=policycli._FAKE[platform]["home"])


def _review(
    platform: str, tool: str, tool_input: dict[str, Any], policy: Policy | None = None
) -> Any:
    return policycli._run_one(
        policy or _policy(platform),
        platform,
        tool,
        tool_input,
        None,
        None,  # type: ignore[arg-type]
    )


def _decide(platform: str, tool: str, tool_input: dict[str, Any], **kw: Any) -> str:
    return str(_review(platform, tool, tool_input, **kw).verdict.decision)


def _project(platform: str) -> str:
    return str(policycli._FAKE[platform]["project"])


# ---------------------------------------------------------------------------- MCP arguments


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_local_paths_in_mcp_arguments_meet_the_path_rules(platform: str) -> None:
    assert _decide(platform, "mcp__fs__read_file", {"path": "~/.aws/credentials"}) == "deny"
    assert _decide(platform, "mcp__fs__write_file", {"path": "~/.bashrc", "content": "x"}) == "deny"
    moved = {"source": "~/.ssh/id_rsa", "destination": "~/x"}
    assert _decide(platform, "mcp__fs__move_file", moved) == "deny"
    nested = {"edits": [{"files": [{"path": "~/.ssh/config"}]}]}
    assert _decide(platform, "mcp__fs__apply_edits", nested) == "deny"


def test_relative_paths_are_not_taken_as_local_files() -> None:
    # a relative path may be a path in a remote repository: no path rule, the call stays gray
    review = _review("posix", "mcp__github__get_file_contents", {"path": ".env"})
    assert str(review.verdict.decision) == "gray"
    assert review.actions[0].paths == ()


def test_the_access_comes_from_the_tool_name() -> None:
    def access(tool: str) -> str:
        review = _review("posix", tool, {"path": "/home/testuser/proj/a.txt"})
        return str(review.actions[0].paths[0].access)

    assert access("mcp__fs__read_file") == "read"
    assert access("mcp__fs__list_directory") == "read"
    assert access("mcp__gh__getFileContents") == "read"
    assert access("mcp__fs__write_file") == "unknown"
    assert access("mcp__fs__read_and_delete") == "unknown"  # a write word wins
    assert access("mcp__fs__frobnicate") == "unknown"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_a_command_argument_is_parsed_for_deny_and_ask_only(platform: str) -> None:
    assert _decide(platform, "mcp__shell__run_command", {"command": "rm -rf ~"}) == "deny"
    assert _decide(platform, "mcp__shell__run", {"command": "rm", "args": ["-rf", "~"]}) == "deny"
    review = _review(platform, "mcp__shell__run_command", {"command": "git status"})
    assert str(review.verdict.decision) == "gray"
    nested = review.actions[1:]
    assert nested
    assert all(a.gray and "mcp-command:mcp__shell__run_command" in a.gray_reasons for a in nested)
    # even a declared tool is never allowed when it runs a command
    declared = _policy(platform, declared=True)
    assert (
        _decide(platform, "mcp__shell__run_command", {"command": "git status"}, policy=declared)
        == "gray"
    )


def test_urls_in_mcp_arguments_meet_the_network_rules() -> None:
    review = _review("posix", "mcp__browser__navigate", {"url": "https://c.example.invalid/x"})
    assert str(review.verdict.decision) == "ask"
    assert "net-allowlist" in review.verdict.rule_ids
    assert review.actions[0].domains == ("c.example.invalid",)
    assert review.actions[0].network


@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        ("SELECT id FROM users LIMIT 10", True),
        ("  select count(*) from orders;", True),
        ("WITH x AS (SELECT 1) SELECT * FROM x", True),
        ("EXPLAIN SELECT 1", True),
        ("SHOW TABLES", True),
        ("DELETE FROM users", False),
        ("DROP TABLE users", False),
        ("SELECT 1; DROP TABLE users", False),
        ("SELECT * INTO backup FROM users", False),
        ("WITH d AS (DELETE FROM jobs RETURNING *) SELECT * FROM d", False),
        ("GRANT ALL ON db TO x", False),
        ("/* hi */ UPDATE t SET a = 1", False),
        ("label:bug state:open", None),  # a search query, not SQL
        ("; delete from t", False),  # X1 review R9-2: a leading separator or parenthesis
        ("(delete from t)", False),
        ("x; delete from t", False),
        ("SELECT 1 /*! ; DROP TABLE t */", False),  # MySQL runs /*! ... */
        ("", None),
    ],
)
def test_sql_read_only_detection(sql: str, expected: bool | None) -> None:
    assert event.sql_is_read_only(sql) is expected


def test_the_matcher_and_the_normalizer_agree_on_the_mcp_gray_reason() -> None:
    assert matcher.MCP_GRAY == event.MCP_GRAY


# ---------------------------------------------------------------------------- mcp_read_only


@pytest.mark.parametrize(
    "entry",
    ["mcp__*", "mcp__*__get", "github__get_issue", "mcp__github", "mcp__gh__get issue", "*"],
)
def test_a_bad_declaration_is_refused(entry: str) -> None:
    text = default_policy_text().replace("\nmcp_read_only: []\n", f'\nmcp_read_only: ["{entry}"]\n')
    with pytest.raises(PolicyError, match="is not an MCP tool"):
        parse_policy_text(text, home="/home/testuser")


def test_the_shipped_policies_declare_nothing() -> None:
    assert _policy("posix").mcp_read_only == ()
    assert _strict("posix").mcp_read_only == ()


ALLOWED_WHEN_DECLARED = [
    ("mcp__github__get_issue", {"owner": "example", "repo": "proj", "issue_number": 7}),
    ("mcp__github__list_pull_requests", {"owner": "example", "repo": "proj", "state": "open"}),
    ("mcp__db__query", {"sql": "SELECT status, count(*) FROM jobs GROUP BY status"}),
    ("mcp__docs__lookup", {"library": "fastapi", "topic": "dependencies"}),
    ("mcp__docs__fetch_page", {"url": "https://github.com/example/proj/blob/main/README.md"}),
]


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(("tool", "tool_input"), ALLOWED_WHEN_DECLARED)
def test_a_declared_tool_is_allowed_only_when_declared(
    platform: str, tool: str, tool_input: dict[str, Any]
) -> None:
    assert _decide(platform, tool, tool_input) == "gray"  # the shipped policy declares nothing
    review = _review(platform, tool, tool_input, policy=_policy(platform, declared=True))
    assert str(review.verdict.decision) == "allow", review.verdict
    assert review.verdict.rule_ids == ("allow-declared-read-only-mcp",)
    assert _decide(platform, tool, tool_input, policy=_strict(platform)) != "allow"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_a_declared_tool_is_not_allowed_when_its_call_is_unclear(platform: str) -> None:
    declared = _policy(platform, declared=True)
    project = _project(platform)
    sep = "\\" if platform == "windows" else "/"

    def decide(tool: str, tool_input: dict[str, Any]) -> str:
        return _decide(platform, tool, tool_input, policy=declared)

    assert decide("mcp__filesystem__read_file", {"path": f"{project}{sep}src{sep}a.py"}) == "allow"
    assert decide("mcp__db__query", {"sql": "DELETE FROM users"}) == "gray"
    assert decide("mcp__db__query", {"sql": "SELECT 1; DROP TABLE t"}) == "gray"
    assert decide("mcp__docs__fetch_page", {"url": "https://c.example.invalid/x"}) == "ask"
    outside = "/opt/data/x.txt" if platform == "posix" else "D:\\data\\x.txt"
    assert decide("mcp__filesystem__read_file", {"path": outside}) == "ask"
    assert decide("mcp__filesystem__read_file", {"path": "~/.ssh/id_rsa"}) == "deny"
    # not declared: write_file is not in the list
    assert decide("mcp__filesystem__write_file", {"path": f"{project}{sep}a.md"}) == "gray"
    # a declared prefix of another server does not cover this one
    assert decide("mcp__githubx__get_issue", {"issue_number": 1}) == "gray"


# ---------------------------------------------------------------------------- network


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_unknown_destination_and_outside_host_are_two_rules(platform: str) -> None:
    unknown = _review(platform, "Bash", {"command": "git fetch origin"})
    assert str(unknown.verdict.decision) == "ask"
    assert unknown.verdict.rule_ids == ("net-unknown-destination",)
    stranger = _review(platform, "Bash", {"command": "curl https://c.example.invalid/x"})
    assert "net-allowlist" in stranger.verdict.rule_ids
    assert "net-unknown-destination" not in stranger.verdict.rule_ids
    for host in ("raw.githubusercontent.com", "static.crates.io", "proxy.golang.org"):
        review = _review(platform, "Bash", {"command": f"curl -sS https://{host}/x"})
        assert "net-allowlist" not in review.verdict.rule_ids, host
        assert str(review.verdict.decision) != "allow", host  # the list allows nothing by itself


# ---------------------------------------------------------------------------- persistence, delete

DENIED_IN_DEFAULT = [
    ("posix", "Bash", {"command": "crontab -e"}),
    ("posix", "Bash", {"command": "crontab jobs.txt"}),
    ("posix", "Bash", {"command": "systemctl --user enable foo.service"}),
    ("posix", "Bash", {"command": "sudo systemctl enable foo"}),
    ("posix", "Bash", {"command": "launchctl load x.plist"}),
    ("posix", "Bash", {"command": "find ~/cache -delete"}),
    ("posix", "Bash", {"command": "chown -R me ~/shared"}),
    ("posix", "Bash", {"command": "wipefs -a disk.img"}),
    ("posix", "Write", {"file_path": "~/.zshrc", "content": "x"}),
    ("posix", "Write", {"file_path": "/etc/cron.d/x", "content": "x"}),
    ("posix", "Write", {"file_path": "~/.ssh/config", "content": "x"}),
    ("windows", "Write", {"file_path": "~\\Documents\\PowerShell\\profile.ps1", "content": "x"}),
]


@pytest.mark.parametrize(("platform", "tool", "tool_input"), DENIED_IN_DEFAULT)
def test_persistence_and_destruction_outside_the_project_are_denied(
    platform: str, tool: str, tool_input: dict[str, Any]
) -> None:
    assert _decide(platform, tool, tool_input) == "deny"
    assert _decide(platform, tool, tool_input, policy=_strict(platform)) == "deny"


STILL_ASKED_OR_GRAY = [
    ("posix", "Bash", {"command": "crontab -l"}, "ask"),
    ("posix", "Bash", {"command": "systemctl --user status foo"}, "ask"),
    ("posix", "Bash", {"command": "launchctl list"}, "ask"),
    ("posix", "Bash", {"command": "find . -name '*.pyc' -delete"}, "gray"),
    ("posix", "Bash", {"command": "chmod -R u+x scripts"}, "gray"),
    ("posix", "Write", {"file_path": "~/.local/bin/tool", "content": "x"}, "ask"),
    (
        "posix",
        "Write",
        {"file_path": "/home/testuser/proj/.git/hooks/pre-commit", "content": "x"},
        "ask",
    ),
]


@pytest.mark.parametrize(("platform", "tool", "tool_input", "expected"), STILL_ASKED_OR_GRAY)
def test_inside_the_project_and_read_only_forms_are_not_denied(
    platform: str, tool: str, tool_input: dict[str, Any], expected: str
) -> None:
    assert _decide(platform, tool, tool_input) == expected


def test_the_service_manager_verb_is_the_subcommand() -> None:
    review = _review("posix", "Bash", {"command": "systemctl --user --now enable foo"})
    assert review.actions[0].subcommand == "enable"
    dynamic = _review("posix", "Bash", {"command": "systemctl --user $VERB foo"})
    assert str(dynamic.verdict.decision) == "ask"  # ask-user-services; not denied, not allowed


# ---------------------------------------------------------------------------- X1 review R9


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    "tool_input",
    [
        {"file_name": "~/.ssh/id_rsa"},  # any key: an absolute or ~ value is a path
        {"folder": "~/.ssh"},
        {"location": "  ~/.ssh/id_rsa"},  # surrounding space
        {"uri": "file://~/.ssh/id_rsa"},
        {"input": {"deep": [{"x": "~/.aws/credentials"}]}},
        {"path": "~/.ssh/id_rsa", "zz": [str(i) for i in range(600)]},  # a big sibling
    ],
)
def test_a_declared_tool_never_reads_a_secret_however_the_path_is_given(
    platform: str, tool_input: dict[str, Any]
) -> None:
    declared = _policy(platform, declared=True)
    assert _decide(platform, "mcp__filesystem__read_file", tool_input, policy=declared) == "deny"


def test_a_file_uri_is_its_path() -> None:
    review = _review("posix", "mcp__fs__read_file", {"uri": "file:///home/testuser/.ssh/id_rsa"})
    assert str(review.verdict.decision) == "deny"
    win = _review("windows", "mcp__fs__read_file", {"uri": "file:///C:/Users/testuser/.ssh/id_rsa"})
    assert str(win.verdict.decision) == "deny"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    "tool_input",
    [
        {"path": "$HOME/.ssh/id_rsa"},  # a variable nobody resolves here
        {"path": "%USERPROFILE%\\.ssh\\id_rsa"},
        {"file_name": "C:secret.txt"},  # drive-relative
        {"a": [[[[[[["deep"]]]]]]]},  # deeper than the walk looks
        {"many": [str(i) for i in range(150)]},  # wider than the walk looks
        {"many": {f"k{i}": "v" for i in range(150)}},
    ],
)
def test_a_declared_tool_is_not_allowed_when_not_every_argument_was_seen(
    platform: str, tool_input: dict[str, Any]
) -> None:
    declared = _policy(platform, declared=True)
    assert _decide(platform, "mcp__filesystem__read_file", tool_input, policy=declared) == "gray"


def test_a_text_too_long_to_look_at_is_not_allowed() -> None:
    declared = _policy("posix", declared=True)
    huge = {"library": "x" * ((1 << 22) + 1)}
    review = _review("posix", "mcp__docs__lookup", huge, policy=declared)
    assert str(review.verdict.decision) == "gray"
    assert "mcp-arguments-not-all-seen" in review.actions[0].gray_reasons


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_sql_that_may_write_is_never_allowed_on_a_declared_query_tool(platform: str) -> None:
    declared = _policy(platform, declared=True)
    for sql in (
        "; delete from t",
        "(delete from t)",
        "SELECT 1 /*! ; DROP TABLE t */",
        "not sql at all",
    ):
        assert _decide(platform, "mcp__db__query", {"sql": sql}, policy=declared) == "gray", sql
    # under `query` (often a search text) only what may write counts
    assert (
        _decide(platform, "mcp__docs__search", {"query": "how to set up ci"}, policy=declared)
        == "allow"
    )
    assert (
        _decide(platform, "mcp__docs__search", {"query": "x; delete from t"}, policy=declared)
        == "gray"
    )


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
def test_a_command_given_as_a_list_is_one_command_line(platform: str) -> None:
    assert _decide(platform, "mcp__shell__exec", {"command": ["rm", "-rf", "~"]}) == "deny"
    assert _decide(platform, "mcp__shell__exec", {"cmd": "rm", "argv": ["-rf", "~"]}) == "deny"


@pytest.mark.parametrize(
    "command",
    [
        "systemctl --legend no enable foo",  # X1 review R9-3: a value option before the verb
        "systemctl --check-inhibitors yes link ./foo.service",
        "systemctl --preset-mode full preset foo",
        "systemctl --user --frobnicate x enable foo",  # an unknown option with a value
    ],
)
def test_registration_is_denied_whatever_comes_before_the_verb(command: str) -> None:
    assert _decide("posix", "Bash", {"command": command}) == "deny", command


def test_the_registration_verbs_and_the_rule_agree() -> None:
    import yaml

    from boundkeep.normalize import programs

    for name in ("default", "strict"):
        data = yaml.safe_load((ROOT / "policies" / f"{name}.yaml").read_text(encoding="utf-8"))
        rule = next(r for r in data["rules"] if r["id"] == "deny-service-registration")
        assert set(rule["match"]["subcommand"]) == programs.SERVICE_REGISTER_VERBS, name


@pytest.mark.parametrize("command", ["crontab -V", "crontab --help"])
def test_crontab_version_and_help_are_not_denied(command: str) -> None:
    assert _decide("posix", "Bash", {"command": command}) == "ask"


# ---------------------------------------------------------------------------- X1 review R10


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("mcp__docs__fetch_page", {"url": "c.example.invalid/x"}),  # no scheme, under a host key
        ("mcp__docs__fetch_page", {"target": "ftp://c.example.invalid/x"}),  # another scheme
        ("mcp__docs__fetch_page", {"target": "wss://c.example.invalid/x"}),
        ("mcp__docs__lookup", {"note": "see https://c.example.invalid/x for details"}),  # in text
    ],
)
def test_every_url_form_reaches_the_network_rules(
    platform: str, tool: str, tool_input: dict[str, Any]
) -> None:
    declared = _policy(platform, declared=True)
    assert _decide(platform, tool, tool_input, policy=declared) != "allow", tool_input


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    "tool_input",
    [
        {"shell": "git status"},
        {"commands": ["git status"]},
        {"code": "print(1)"},
        {"sqlQuery": "delete from t"},
        {"sql_text": "update t set a = 1"},
        {"q": "x; drop table t"},
    ],
)
def test_command_and_sql_key_variants_are_never_allowed(
    platform: str, tool_input: dict[str, Any]
) -> None:
    declared = _policy(platform, declared=True)
    assert _decide(platform, "mcp__docs__lookup", tool_input, policy=declared) != "allow"


def test_a_tool_is_read_only_only_when_its_name_starts_with_a_read_word() -> None:
    def access(tool: str) -> str:
        review = _review("posix", tool, {"path": "/home/testuser/proj/a.txt"})
        return str(review.actions[0].paths[0].access)

    assert access("mcp__gh__get_and_store") == "unknown"  # X1 review R10-1
    assert access("mcp__gh__file_get") == "unknown"
    assert access("mcp__gh__get_file") == "read"


def test_a_declared_get_tool_that_stores_cannot_write_autorun_files() -> None:
    declared = _policy("posix", declared=True)
    hook = {"path": "/home/testuser/proj/.git/hooks/pre-commit"}
    assert _decide("posix", "mcp__github__get_and_store", hook, policy=declared) != "allow"
    pkg = {"path": "/home/testuser/proj/package.json"}
    assert _decide("posix", "mcp__github__get_and_store", pkg, policy=declared) != "allow"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize(
    "tool_input",
    [
        {"path": "\ufeff~/.ssh/id_rsa"},  # a byte-order mark before the path (X1 review R10-2)
        {"path": "\u200b~/.ssh/id_rsa"},
    ],
)
def test_an_invisible_prefix_does_not_hide_a_path(
    platform: str, tool_input: dict[str, Any]
) -> None:
    declared = _policy(platform, declared=True)
    assert _decide(platform, "mcp__filesystem__read_file", tool_input, policy=declared) == "deny"


@pytest.mark.parametrize("platform", PLATFORMS, ids=PLATFORM_IDS)
@pytest.mark.parametrize("value", ["../.ssh/id_rsa", "..\\..\\x", ".."])
def test_a_climbing_relative_path_is_unclear(platform: str, value: str) -> None:
    declared = _policy(platform, declared=True)
    review = _review(platform, "mcp__filesystem__read_file", {"path": value}, policy=declared)
    assert str(review.verdict.decision) == "gray"
    assert "mcp-path-unclear" in review.actions[0].gray_reasons
