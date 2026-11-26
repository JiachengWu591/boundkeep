"""M4 (PROJECT_SPEC.md §8.1): appending a proposal to the policy text, backups, undo."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from boundkeep.compiler import writer
from boundkeep.policy import default_policy_text, parse_policy_text
from boundkeep.policy import loader as policy_loader

RULE: dict[str, Any] = {
    "id": "deny-curl",
    "tool": ["Bash"],
    "match": {"program": "curl"},
    "action": "deny",
    "reason": "no curl: it talks to the network",
}
TEST: dict[str, Any] = {"tool": "Bash", "input": {"command": "curl x"}, "expect": "deny"}
SMALL = """version: 1
# my own policy
rules:
  - id: a
    match: { program: git }   # trailing comment
    action: deny
    reason: "no git"

# the tests
tests:
  - { tool: Bash, input: { command: "git x" }, expect: deny }
"""


def merged(text: str, rules: list[dict[str, Any]] | None = None, tests: Any = None) -> str:
    return writer.merge_text(
        text, [RULE] if rules is None else rules, [TEST] if tests is None else tests, note="n"
    )


def test_items_go_after_the_last_item_and_comments_stay() -> None:
    out = merged(SMALL)
    assert "# my own policy" in out
    assert "# trailing comment" in out
    assert "# the tests" in out
    lines = out.splitlines()
    assert lines.index("  # n") < lines.index("# the tests")  # the rule block before the gap
    assert out.rstrip().endswith('"expect": "deny"}')
    writer.verify_merge(SMALL, out, [RULE], [TEST], home="/home/x")


def test_the_default_policy_takes_a_proposal_and_verifies() -> None:
    text = default_policy_text()
    out = merged(text)
    policy = writer.verify_merge(text, out, [RULE], [TEST], home="/home/x")
    assert policy.rules[-1].id == "deny-curl"
    assert out.count("\n") == text.count("\n") + 10


def test_missing_lists_are_added_at_the_end() -> None:
    out = merged("version: 1\nmode: enforce\n")
    assert out.endswith(
        "tests:\n  # n\n"
        + '  - {"tool": "Bash", "input": {"command": "curl x"}, "expect": "deny"}\n'
    )
    writer.verify_merge("version: 1\nmode: enforce\n", out, [RULE], [TEST], home=None)


@pytest.mark.parametrize(
    "text",
    [
        "version: 1\nrules: []\n",
        "version: 1\nrules: [{id: a, match: {program: git}, action: deny, reason: r}]\n",
    ],
)
def test_a_flow_style_list_is_refused(text: str) -> None:
    with pytest.raises(writer.MergeError, match=r"flow style|not a list"):
        merged(text)


def test_a_file_without_a_final_newline_and_crlf_files() -> None:
    no_eol = SMALL.rstrip("\n")
    out = merged(no_eol)
    writer.verify_merge(no_eol, out, [RULE], [TEST], home=None)
    crlf = SMALL.replace("\n", "\r\n")
    out = merged(crlf)
    assert "\n" not in out.replace("\r\n", "")
    writer.verify_merge(crlf, out, [RULE], [TEST], home=None)


def test_block_scalars_and_nested_items_end_where_they_end() -> None:
    text = (
        "version: 1\nrules:\n  - id: a\n    match:\n      program: git\n    action: deny\n"
        "    reason: >-\n      a folded\n      reason\n\n# after\ntests: []\n"
    )
    out = merged(text, tests=[])
    writer.verify_merge(text, out, [RULE], [], home=None)
    assert out.index("deny-curl") < out.index("# after")


def test_verify_refuses_any_other_change() -> None:
    out = merged(SMALL).replace("version: 1\n", "version: 1\nmode: audit-only\n")
    with pytest.raises(writer.MergeError, match="'mode'"):
        writer.verify_merge(SMALL, out, [RULE], [TEST], home=None)
    out = merged(SMALL).replace('reason: "no git"', 'reason: "no gits"')
    with pytest.raises(writer.MergeError, match="changed more"):
        writer.verify_merge(SMALL, out, [RULE], [TEST], home=None)


def test_a_duplicate_id_does_not_load() -> None:
    out = merged(SMALL, rules=[RULE | {"id": "a"}])
    with pytest.raises(writer.MergeError, match="does not load"):
        writer.verify_merge(SMALL, out, [RULE | {"id": "a"}], [TEST], home=None)


# --------------------------------------------------------------------------- files


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("BOUNDKEEP_HOME", str(tmp_path / "bk"))
    (tmp_path / "bk").mkdir()
    return tmp_path / "bk"


def _apply(path: Path, text: str) -> writer.Entry:
    data = path.read_bytes()
    new = merged(text)
    return writer.apply(
        str(path),
        expected_before=data,
        new_text=new,
        bom="",
        source="t",
        rule_ids=["deny-curl"],
        tests=1,
    )


def test_apply_backs_up_replaces_and_records(home: Path) -> None:
    policy = home / "policy.yaml"
    policy.write_bytes(SMALL.encode())
    entry = _apply(policy, SMALL)
    assert parse_policy_text(policy.read_text("utf-8"), home=None).rules[-1].id == "deny-curl"
    backup = home / "policy-history" / entry.backup
    assert backup.read_bytes() == SMALL.encode()
    history = writer.read_history()
    assert [e.op for e in history] == ["apply"]
    assert history[0].before_sha256 == writer.sha256(SMALL.encode())
    assert history[0].after_sha256 == writer.sha256(policy.read_bytes())
    assert history[0].path == str(policy)


def test_apply_refuses_a_file_that_changed_since_the_check(home: Path) -> None:
    policy = home / "policy.yaml"
    policy.write_bytes(SMALL.encode())
    with pytest.raises(writer.MergeError, match="changed while"):
        writer.apply(
            str(policy),
            expected_before=b"other",
            new_text=merged(SMALL),
            bom="",
            source="t",
            rule_ids=[],
            tests=0,
        )
    assert policy.read_bytes() == SMALL.encode()


def test_a_failed_replace_leaves_the_old_policy_and_no_temp_file(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = home / "policy.yaml"
    policy.write_bytes(SMALL.encode())
    real = policy_loader._replace_with_retry

    def failing(source: str, target: str) -> None:
        if os.path.basename(target) == "policy.yaml":
            raise PermissionError(13, "denied")
        real(source, target)

    monkeypatch.setattr(policy_loader, "_replace_with_retry", failing)
    with pytest.raises(policy_loader.PolicyError):
        _apply(policy, SMALL)
    assert policy.read_bytes() == SMALL.encode()
    assert not [n for n in os.listdir(home) if n.endswith(".tmp")]
    assert writer.read_history() == []


def test_undo_restores_byte_for_byte_and_walks_back(home: Path) -> None:
    policy = home / "policy.yaml"
    policy.write_bytes(("﻿" + SMALL).encode())
    _apply(policy, SMALL)
    once = policy.read_bytes()
    second = merged(once.decode("utf-8").lstrip("﻿"), rules=[RULE | {"id": "deny-wget"}], tests=[])
    writer.apply(
        str(policy),
        expected_before=once,
        new_text=second,
        bom="﻿",
        source="t",
        rule_ids=["deny-wget"],
        tests=0,
    )
    plan = writer.plan_undo(str(policy))
    assert plan.target.rules == ("deny-wget",)
    assert not plan.changed_since
    writer.undo(str(policy), plan)
    assert policy.read_bytes() == once
    writer.undo(str(policy), writer.plan_undo(str(policy)))
    assert policy.read_bytes() == ("﻿" + SMALL).encode()
    with pytest.raises(writer.MergeError, match="no write"):
        writer.plan_undo(str(policy))


def test_undo_says_when_the_file_changed_after_the_write(home: Path) -> None:
    policy = home / "policy.yaml"
    policy.write_bytes(SMALL.encode())
    _apply(policy, SMALL)
    policy.write_bytes(policy.read_bytes() + b"# edited by hand\n")
    plan = writer.plan_undo(str(policy))
    assert plan.changed_since
    writer.undo(str(policy), plan)
    assert policy.read_bytes() == SMALL.encode()
    kept = next(e.backup for e in writer.read_history() if e.op == "undo")
    assert (home / "policy-history" / kept).read_bytes().endswith(b"# edited by hand\n")


def test_undo_only_touches_the_file_that_was_written(home: Path, tmp_path: Path) -> None:
    policy = home / "policy.yaml"
    policy.write_bytes(SMALL.encode())
    _apply(policy, SMALL)
    other = tmp_path / "other.yaml"
    other.write_bytes(SMALL.encode())
    with pytest.raises(writer.MergeError, match="no write"):
        writer.plan_undo(str(other))


def test_undo_refuses_a_backup_that_was_swapped(home: Path) -> None:
    policy = home / "policy.yaml"
    policy.write_bytes(SMALL.encode())
    entry = _apply(policy, SMALL)
    (home / "policy-history" / entry.backup).write_bytes(b"version: 1\nmode: audit-only\n")
    after = policy.read_bytes()
    with pytest.raises(writer.MergeError, match="not the file"):
        writer.undo(str(policy), writer.plan_undo(str(policy)))
    assert policy.read_bytes() == after


def test_only_the_newest_backups_are_kept(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = home / "policy.yaml"
    policy.write_bytes(SMALL.encode())
    counter = iter(range(1000))
    monkeypatch.setattr(
        writer,
        "_now",
        lambda: (f"t{next(counter):04d}", f"policy-20260101T000000-{next(counter):04d}.yaml"),
    )
    text = SMALL
    for index in range(writer.KEEP + 5):
        data = policy.read_bytes()
        new = merged(text, rules=[RULE | {"id": f"r{index}"}], tests=[])
        writer.apply(
            str(policy),
            expected_before=data,
            new_text=new,
            bom="",
            source="t",
            rule_ids=[f"r{index}"],
            tests=0,
        )
        text = new
    backups = [n for n in os.listdir(home / "policy-history") if n.endswith(".yaml")]
    assert len(backups) == writer.KEEP
