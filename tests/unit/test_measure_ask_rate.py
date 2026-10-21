"""scripts/measure_ask_rate.py and its corpus tests/corpus/workflow_benign.yaml.

The corpus records a DESIGN TARGET (``expect_after``) that the policy only reaches once the M1c
allow rules land, so nothing here requires today's policy to meet it. What is checked instead: the
corpus is well formed and inert, the tool's arithmetic is right on a tiny synthetic corpus and
policy, and ``today`` (the starting point recorded in the corpus) has not drifted from what the
policy gives.
"""

from __future__ import annotations

import importlib.util
import io
import re
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from boundkeep import policycli
from boundkeep.policy import default_policy_text, parse_policy_text

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "measure_ask_rate.py"
CORPUS = ROOT / "tests" / "corpus" / "workflow_benign.yaml"

TIERS = {"t1-read", "t2-write", "t3-exec", "t3-dev", "keep-ask", "must-block"}
VERDICTS = {"allow", "ask", "deny", "gray"}
SHELL_TOOLS = {"Bash", "PowerShell"}
FILE_TOOLS = {"Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Grep", "Glob"}
KNOWN_TOOLS = SHELL_TOOLS | FILE_TOOLS | {"WebFetch", "WebSearch"}


def _load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("measure_ask_rate", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tool = _load_tool()


def _corpus() -> list[dict[str, Any]]:
    data = yaml.safe_load(CORPUS.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    return data


def _verdicts(value: Any) -> set[str]:
    return set(value.values()) if isinstance(value, dict) else {value}


# ---- the corpus -------------------------------------------------------------------------------


def test_corpus_is_not_picked_up_by_the_exact_verdict_runner() -> None:
    assert not CORPUS.name.startswith("pipeline")


def test_corpus_entries_have_the_required_fields() -> None:
    for entry in _corpus():
        for key in ("id", "tool", "input", "tier", "expect_after"):
            assert key in entry, f"{entry.get('id')} lacks {key}"
        allowed = {
            "id",
            "tool",
            "platform",
            "input",
            "tier",
            "expect_after",
            "expect_trusted",
            "today",
        }
        assert set(entry) <= allowed
        assert isinstance(entry["input"], dict), entry["id"]
        assert entry["tool"] in KNOWN_TOOLS, entry["id"]
        assert entry.get("platform") in (None, "windows", "posix"), entry["id"]


def test_corpus_is_big_unique_and_covers_every_tier_and_tool() -> None:
    data = _corpus()
    assert len(data) >= 160
    ids = [e["id"] for e in data]
    assert len(set(ids)) == len(ids)
    assert all(re.fullmatch(r"[a-z0-9-]+", i) for i in ids)
    assert {e["tier"] for e in data} == TIERS
    assert {e["tool"] for e in data} >= SHELL_TOOLS | FILE_TOOLS


def test_corpus_tiers_and_verdict_values_are_valid() -> None:
    for entry in _corpus():
        assert entry["tier"] in TIERS, entry["id"]
        assert _verdicts(entry["expect_after"]) <= VERDICTS, entry["id"]
        if "today" in entry:
            assert _verdicts(entry["today"]) <= VERDICTS, entry["id"]


def test_corpus_design_verdicts_follow_the_tier() -> None:
    for entry in _corpus():
        expect = _verdicts(entry["expect_after"])
        tier = entry["tier"]
        if tier in ("t1-read", "t2-write"):
            assert expect == {"allow"}, entry["id"]
        elif tier in ("t3-exec", "keep-ask", "t3-dev"):
            assert expect <= {"ask", "gray"}, entry["id"]
            # a dev tool is allowed once its project is trusted; nothing else has a trusted verdict
            if tier == "t3-dev":
                assert _verdicts(entry["expect_trusted"]) == {"allow"}, entry["id"]
            else:
                assert "expect_trusted" not in entry, entry["id"]
        else:
            assert expect <= {"ask", "deny"}, entry["id"]


def test_corpus_inputs_have_the_shape_of_their_tool() -> None:
    for entry in _corpus():
        inp = entry["input"]
        name = entry["tool"]
        if name in SHELL_TOOLS:
            assert isinstance(inp.get("command"), str), entry["id"]
            assert inp["command"], entry["id"]
        elif name == "NotebookEdit":
            assert isinstance(inp.get("notebook_path"), str), entry["id"]
        elif name in ("Read", "Write", "Edit", "MultiEdit"):
            assert isinstance(inp.get("file_path"), str), entry["id"]
        elif name in ("Grep", "Glob"):
            assert isinstance(inp.get("pattern"), str), entry["id"]
        if name == "PowerShell":
            assert entry.get("platform") == "windows", entry["id"]


_SECRET_SHAPES = [
    r"AKIA[0-9A-Z]{16}",
    r"gh[pousr]_[A-Za-z0-9]{20,}",
    r"sk-[A-Za-z0-9_-]{20,}",
    r"xox[abprs]-[A-Za-z0-9-]{10,}",
    r"eyJ[A-Za-z0-9_-]{20,}",
    r"-----BEGIN",
    r"[A-Fa-f0-9]{32,}",
    r"[A-Za-z0-9+/]{40,}={0,2}",
    r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9]{8,}",
]


def test_corpus_has_no_secret_shaped_text_and_only_reserved_hosts() -> None:
    text = CORPUS.read_text(encoding="utf-8")
    for pattern in _SECRET_SHAPES:
        assert re.search(pattern, text) is None, f"secret-shaped text: {pattern}"
    hosts = re.findall(r"https?://([^/\s\"'\\]+)", text)
    assert hosts, "the corpus should contain network commands"
    for host in hosts:
        assert host.endswith(".invalid"), f"not a reserved host: {host}"
    # no bare real-looking domains either (commands like `ping foo.com`)
    assert re.search(r"\b[a-z0-9-]+\.(com|net|org|io|dev|cn|ru)\b", text) is None


# ---- drift: `today` stays honest --------------------------------------------------------------


def _ps_ready() -> bool:
    if sys.platform != "win32":
        return False
    from boundkeep.normalize import psparse

    psparse.warm_up(wait_s=15)
    return bool(psparse.status().get("state") == "ready")


def test_today_has_not_drifted_from_the_current_policy() -> None:
    """The recorded starting point is either still true, or the policy has moved to the design
    target (``expect_after``, once the M1c rules land). Any third verdict means the policy changed
    in a way nobody designed. Entries whose today == expect_after must not move at all."""
    ps_ready = _ps_ready()
    policies = {
        p: parse_policy_text(default_policy_text(), home=policycli._FAKE[p]["home"])
        for p in ("windows", "posix")
    }
    failures: list[str] = []
    checked = 0
    for entry in _corpus():
        if "today" not in entry:
            continue
        if entry["tool"] == "PowerShell" and not ps_ready:
            continue
        platforms = [entry["platform"]] if entry.get("platform") else ["windows", "posix"]
        for platform in platforms:
            got = tool.default_run_one(policies[platform], platform, entry["tool"], entry["input"])
            today = tool.resolve(entry["today"], platform)
            design = tool.resolve(entry["expect_after"], platform)
            checked += 1
            if got not in (today, design):
                failures.append(
                    f"{entry['id']} on {platform}: today={today} design={design} got={got}"
                )
    assert checked > 0
    assert not failures, "\n".join(failures)


# ---- the tool on a tiny synthetic corpus and policy -------------------------------------------

_POLICY = """\
version: 1
mode: enforce
rules:
  - id: allow-echo
    tool: [Bash]
    match: {program: echo}
    action: allow
  - id: ask-curl
    tool: [Bash]
    match: {program: curl}
    action: ask
    reason: "network"
  - id: deny-rm
    tool: [Bash]
    match: {program: rm}
    action: deny
    reason: "no deletes"
"""


def _entry(
    id_: str, command: str, tier: str, expect: Any, platform: str | None = None, name: str = "Bash"
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": id_,
        "tool": name,
        "input": {"command": command},
        "tier": tier,
        "expect_after": expect,
    }
    if platform:
        entry["platform"] = platform
    return entry


def _synthetic() -> list[dict[str, Any]]:
    return [
        _entry("e1", "echo hello", "t1-read", "allow"),
        _entry("e2", "echo again", "t1-read", "allow"),
        _entry("e3", "git status", "t1-read", "allow"),  # gray under this policy: differs
        _entry("e4", "pytest", "t3-exec", "ask"),  # gray vs ask: same prompt class, no mismatch
        _entry("e5", "curl https://example.invalid/x", "keep-ask", "ask"),
        _entry("e6", "rm -rf /", "must-block", "deny"),
    ]


def _policy(platform: str) -> Any:
    return parse_policy_text(_POLICY, home=policycli._FAKE[platform]["home"])


def test_asks_per_100_arithmetic() -> None:
    assert tool.asks_per_100(Counter()) == 0.0
    assert tool.asks_per_100(Counter(allow=3)) == 0.0
    assert tool.asks_per_100(Counter(allow=2, gray=1, ask=1)) == 50.0
    assert tool.asks_per_100(Counter(deny=1, gray=1, ask=1, allow=1)) == 50.0
    assert tool.asks_per_100(Counter(allow=1, error=1)) == 50.0  # a pipeline failure prompts too
    assert round(tool.asks_per_100(Counter(allow=2, gray=1)), 1) == 33.3


def test_verdict_class_treats_ask_and_gray_alike() -> None:
    assert tool.verdict_class("ask") == tool.verdict_class("gray") == "prompt"
    assert tool.verdict_class("allow") == "allow"
    assert tool.verdict_class("deny") == "deny"


def test_resolve_accepts_a_word_or_a_platform_mapping() -> None:
    assert tool.resolve("ask", "posix") == "ask"
    assert tool.resolve({"windows": "ask", "posix": "allow"}, "posix") == "allow"
    assert tool.resolve({"windows": "ask"}, "posix") is None


def test_measure_counts_per_tier_and_lists_the_entry_that_differs() -> None:
    result = tool.measure_platform(_synthetic(), _policy("posix"), "posix", ps_available=False)
    assert result.by_tier["t1-read"] == Counter(allow=2, gray=1)
    assert result.by_tier["t3-exec"] == Counter(gray=1)
    assert result.by_tier["keep-ask"] == Counter(ask=1)
    assert result.by_tier["must-block"] == Counter(deny=1)
    assert result.total() == Counter(allow=2, gray=2, ask=1, deny=1)
    assert round(tool.asks_per_100(result.by_tier["t1-read"]), 1) == 33.3
    assert tool.asks_per_100(result.total()) == 50.0  # 3 of 6 prompted
    assert tool.asks_per_100(result.target_total()) == pytest.approx(100 * 2 / 6)
    assert [(m.id, m.expected, m.got) for m in result.mismatches] == [("e3", "allow", "gray")]


def test_platform_limited_entries_run_only_on_their_platform() -> None:
    entries = [
        _entry("both", "echo hi", "t1-read", "allow"),
        _entry("only-win", "echo hi", "t1-read", "allow", platform="windows"),
        _entry("only-posix", "echo hi", "t1-read", "allow", platform="posix"),
    ]
    win = tool.measure_platform(entries, _policy("windows"), "windows", ps_available=False)
    posix = tool.measure_platform(entries, _policy("posix"), "posix", ps_available=False)
    assert win.total() == Counter(allow=2)
    assert posix.total() == Counter(allow=2)


def test_powershell_entries_are_skipped_visibly_without_the_helper() -> None:
    entries = [
        _entry("bash-one", "echo hi", "t1-read", "allow"),
        _entry("ps-one", "Get-Date", "t1-read", "allow", platform="windows", name="PowerShell"),
    ]
    result = tool.measure_platform(entries, _policy("windows"), "windows", ps_available=False)
    assert result.skipped == ["ps-one"]
    assert result.total() == Counter(allow=1)
    out = io.StringIO()
    tool.render("synthetic", [result], out)
    assert "SKIPPED" in out.getvalue()


def test_a_failing_run_is_counted_as_an_error_and_as_asked() -> None:
    def boom(*_args: Any) -> str:
        raise RuntimeError("pipeline failure")

    entries = [_entry("e1", "echo hi", "t1-read", "allow")]
    result = tool.measure_platform(
        entries, _policy("posix"), "posix", ps_available=False, run_one=boom
    )
    assert result.total() == Counter(error=1)
    assert tool.asks_per_100(result.total()) == 100.0
    assert [m.id for m in result.mismatches] == ["e1"]


def _write(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_main_prints_every_policy_and_always_exits_zero(tmp_path: Path) -> None:
    corpus = _write(tmp_path / "c.yaml", yaml.safe_dump(_synthetic()))
    permissive = _POLICY.replace("action: deny", "action: ask")
    first = _write(tmp_path / "first.yaml", _POLICY)
    second = _write(tmp_path / "second.yaml", permissive)
    out = io.StringIO()
    code = tool.main(
        ["--corpus", corpus, "--policy", first, "--policy", second, "--platform", "posix"], out
    )
    text = out.getvalue()
    assert code == 0
    assert "first.yaml / posix" in text
    assert "second.yaml / posix" in text
    assert "windows" not in text
    assert "50.0" in text  # 3 of 6 asked under the first policy
    assert "e3" in text  # the entry that differs from expect_after
    assert "differs from expect_after: 1" in text
    # under the second policy rm asks instead of denying: 4 of 6 asked, and e6 now differs
    assert "differs from expect_after: 2" in text


def test_main_runs_both_platforms_by_default(tmp_path: Path) -> None:
    corpus = _write(tmp_path / "c.yaml", yaml.safe_dump(_synthetic()))
    policy = _write(tmp_path / "p.yaml", _POLICY)
    out = io.StringIO()
    assert tool.main(["--corpus", corpus, "--policy", policy], out) == 0
    assert "p.yaml / windows" in out.getvalue()
    assert "p.yaml / posix" in out.getvalue()


def test_main_exits_one_on_unreadable_input(tmp_path: Path) -> None:
    good_corpus = _write(tmp_path / "c.yaml", yaml.safe_dump(_synthetic()))
    good_policy = _write(tmp_path / "p.yaml", _POLICY)
    bad_policy = _write(tmp_path / "bad.yaml", "version: 1\nrules: [not a rule]\n")
    out = io.StringIO()
    assert tool.main(["--corpus", str(tmp_path / "missing.yaml")], out) == 1
    assert tool.main(["--corpus", _write(tmp_path / "e.yaml", "[]")], out) == 1
    assert tool.main(["--corpus", _write(tmp_path / "m.yaml", "- {id: x}")], out) == 1
    assert tool.main(["--corpus", _write(tmp_path / "y.yaml", "a: [")], out) == 1
    assert tool.main(["--corpus", good_corpus, "--policy", str(tmp_path / "nope.yaml")], out) == 1
    assert tool.main(["--corpus", good_corpus, "--policy", bad_policy], out) == 1
    assert (
        tool.main(["--corpus", good_corpus, "--policy", good_policy, "--platform", "posix"], out)
        == 0
    )


def test_the_shipped_corpus_runs_with_the_default_policy_and_is_deterministic() -> None:
    first, second = io.StringIO(), io.StringIO()
    assert tool.main(["--platform", "posix"], first) == 0
    assert tool.main(["--platform", "posix"], second) == 0
    assert first.getvalue() == second.getvalue()
    assert "asks/100" in first.getvalue()


# ---- --trusted: the fake project is trusted (in memory), the target is expect_trusted ------------

_TRUST_POLICY = """\
version: 1
mode: enforce
rules:
  - id: allow-pytest-when-trusted
    tool: [Bash]
    match: {program: pytest, project_trusted: true}
    action: allow
"""


def _trust_entries() -> list[dict[str, Any]]:
    dev = _entry("dev", "pytest", "t3-dev", "ask")
    dev["expect_trusted"] = "allow"
    return [dev, _entry("plain", "ls", "keep-ask", "ask")]


def test_trust_fake_project_adds_the_fake_project_of_the_platform() -> None:
    for platform in ("windows", "posix"):
        base = parse_policy_text(_TRUST_POLICY, home=policycli._FAKE[platform]["home"])
        assert base.trusted_projects == ()
        trusted = tool.trust_fake_project(base, platform)
        assert len(trusted.trusted_projects) == 1
        expected = policycli._FAKE[platform]["project"].replace("\\", "/").casefold()
        assert trusted.trusted_projects[0].casefold() == expected
        assert base.trusted_projects == ()  # the original is untouched


@pytest.mark.parametrize("platform", ["windows", "posix"], ids=["on-windows", "on-posix"])
def test_trusted_measure_uses_expect_trusted_and_the_policy_allows_only_when_trusted(
    platform: str,
) -> None:
    base = parse_policy_text(_TRUST_POLICY, home=policycli._FAKE[platform]["home"])
    untrusted = tool.measure_platform(_trust_entries(), base, platform, ps_available=False)
    assert untrusted.by_tier["t3-dev"] == Counter(gray=1)
    assert untrusted.mismatches == []  # ask is the target and gray prompts the same
    trusted_policy = tool.trust_fake_project(base, platform)
    # measured against the untrusted target the allow is a mismatch ...
    wrong = tool.measure_platform(_trust_entries(), trusted_policy, platform, ps_available=False)
    assert [m.id for m in wrong.mismatches] == ["dev"]
    # ... and against expect_trusted it is the design
    right = tool.measure_platform(
        _trust_entries(), trusted_policy, platform, ps_available=False, trusted=True
    )
    assert right.by_tier["t3-dev"] == Counter(allow=1)
    assert right.mismatches == []
    assert tool.asks_per_100(right.target_by_tier["t3-dev"]) == 0.0


def test_main_trusted_labels_the_run_and_uses_the_trusted_target(tmp_path: Path) -> None:
    corpus = _write(tmp_path / "c.yaml", yaml.safe_dump(_trust_entries()))
    policy = _write(tmp_path / "p.yaml", _TRUST_POLICY)
    plain, trusted = io.StringIO(), io.StringIO()
    assert tool.main(["--corpus", corpus, "--policy", policy, "--platform", "posix"], plain) == 0
    assert (
        tool.main(
            ["--corpus", corpus, "--policy", policy, "--platform", "posix", "--trusted"], trusted
        )
        == 0
    )
    assert "(project trusted)" not in plain.getvalue()
    assert "p.yaml (project trusted) / posix" in trusted.getvalue()
    assert "differs from expect_after: 0" in plain.getvalue()
    assert "differs from expect_after: 0" in trusted.getvalue()
    assert "t3-dev" in trusted.getvalue()


@pytest.mark.parametrize("platform", ["windows", "posix"], ids=["on-windows", "on-posix"])
def test_the_shipped_default_policy_meets_the_design_trusted_and_untrusted(platform: str) -> None:
    entries = _corpus()
    ps_ready = _ps_ready()
    base = parse_policy_text(default_policy_text(), home=policycli._FAKE[platform]["home"])
    untrusted = tool.measure_platform(entries, base, platform, ps_available=ps_ready)
    assert untrusted.mismatches == []
    assert tool.asks_per_100(untrusted.by_tier["t3-dev"]) == 100.0
    trusted = tool.measure_platform(
        entries,
        tool.trust_fake_project(base, platform),
        platform,
        ps_available=ps_ready,
        trusted=True,
    )
    assert trusted.mismatches == []
    assert tool.asks_per_100(trusted.by_tier["t3-dev"]) == 0.0
    # the entries that must prompt still do, trusted or not (t3-exec, keep-ask, must-block)
    for tier in ("t3-exec", "keep-ask"):
        assert tool.asks_per_100(trusted.by_tier[tier]) == 100.0, tier
    assert trusted.by_tier["must-block"].get("allow", 0) == 0
