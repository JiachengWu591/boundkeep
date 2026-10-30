"""Regression tests for the findings of the M3a self-review (docs/reports/M3a.md §6).

One section per finding: the task intent of overlapping host blocks and of a cut through a URL
password; prompts left in the database file after a purge; the send gate's refusals (a secret
across fields or across words, the value of a secret environment variable, variable-expanded
paths); calls that were not analysed whole are not sent; MCP, unknown tools and package runners
are tagged ``exec``; the daemon's deadline for queued and LLM reviews and the taint mark of a call
that was never reviewed; a client that cannot be set up; the evaluation's "clean" reference.
"""

from __future__ import annotations

import random
import re
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from boundkeep import cli, protocol
from boundkeep.audit import send_gate
from boundkeep.audit.auditor import Auditor, secret_values
from boundkeep.audit.backends import openai_compatible
from boundkeep.audit.backends.base import BackendError, verdict_json
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.daemon import pipeline
from boundkeep.daemon.server import DECIDED_BY_LLM_TIMEOUT, _DecisionPool
from boundkeep.evalkit import metrics, report, runner
from boundkeep.normalize.model import Action, PathRef
from boundkeep.policy import Policy, default_policy_text, parse_policy_text
from boundkeep.session.facts import FRESH
from boundkeep.session.intent import extract_intent
from boundkeep.session.store import SessionStore
from tests.contract.conftest import make_backend, request
from tests.helpers.llm_server import FakeLLMServer, Reply, tool_call_answer
from tests.unit.test_evalkit import _benign, _sample
from tests.unit.test_m3a_daemon import KEY, SID, Harness, bash, policy_text, pre

HOME = "/home/testuser"
PROJECT = "/home/testuser/proj"
LLM_BLOCK = (
    "  backend: openai_compatible\n"
    "  openai_compatible:\n"
    "    base_url: https://llm.example.invalid/v1\n"
    "    model: test-model\n"
)


def llm_policy(**llm_keys: object) -> Policy:
    text = re.sub(
        r"^  backend: none.*$", LLM_BLOCK.rstrip("\n"), default_policy_text(), count=1, flags=re.M
    )
    for key, value in llm_keys.items():
        text, found = re.subn(rf"^  {key}: .*$", f"  {key}: {value}", text, count=1, flags=re.M)
        assert found == 1, key
    return parse_policy_text(text, home=HOME)


def decide(
    payload: dict[str, Any], pol: Policy, backend: FakeBackend, env: dict[str, str] | None = None
) -> pipeline.Decision:
    return pipeline.decide(
        protocol.EVENT_PRE,
        payload,
        mode="enforce",
        policy=pol,
        policy_error=None,
        platform="posix",
        env=env if env is not None else {"HOME": HOME},
        home=HOME,
        scan_disk=False,
        auditor=Auditor(pol.llm_audit, backend),
    )


def event(tool: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "s",
        "cwd": PROJECT,
        "project_dir": PROJECT,
        "tool_name": tool,
        "tool_input": tool_input,
    }


def gate(actions: tuple[Action, ...], **kwargs: Any) -> send_gate.GateResult:
    options: dict[str, Any] = {
        "tool": "Bash",
        "facts": FRESH,
        "send_task_intent": False,
        "intent_prompts": 1,
        "home": HOME,
    }
    options.update(kwargs)
    return send_gate.gate(actions, **options)


def command(program: str, *args: str) -> Action:
    return Action(tool="Bash", platform="posix", program=program, args=args)


# ------------------------------------------------------------------ #1, #2: the task intent

WANTED = ("ide_opened_file", "ide_selection", "pasted_content", "system-reminder")


def test_a_closing_tag_inside_a_later_paste_does_not_keep_the_rest_of_the_paste() -> None:
    prompt = (
        "<ide_opened_file>a.py</ide_opened_file> my words "
        '<pasted_content id="1">INJECTED </ide_opened_file> STILL PASTED</pasted_content> end'
    )
    got = extract_intent(prompt, 300)
    assert "INJECTED" not in got
    assert "STILL" not in got
    assert got.endswith("end")


def test_every_word_between_a_first_opener_and_its_last_closer_is_dropped() -> None:
    """Property, 3000 random prompts: for every host block name, nothing between its first
    opening tag and its last closing tag (or the end, without one) is kept."""
    rng = random.Random(20261030)  # noqa: S311 - fixed seed test data, not security
    for case in range(3000):
        pieces: list[str] = []
        for index in range(rng.randint(1, 18)):
            roll = rng.random()
            name = rng.choice(WANTED)
            if roll < 0.25:
                pieces.append(f"<{name}>")
            elif roll < 0.45:
                pieces.append(f"</{name}>")
            else:
                pieces.append(f"w{index}x")
        prompt = " ".join(pieces)
        kept = set(extract_intent(prompt, 2000).split())
        for name in WANTED:
            first = prompt.find(f"<{name}>")
            if first < 0:
                continue
            last = prompt.rfind(f"</{name}>")
            stop = last if last > first else len(prompt)
            inside = set(re.findall(r"w\d+x", prompt[first:stop]))
            assert not inside & kept, (case, prompt)


def test_a_cut_through_a_url_password_drops_the_whole_word() -> None:
    # control characters collapse to one space, so the cut word survives the final length
    prompt = "\x01" * 140 + "https://bob:hunter2hunter2@example.com/x"
    got = extract_intent(prompt, 40)
    assert "hunter2" not in got
    assert "bob:" not in got


# ------------------------------------------------------------------ #3: purge leaves no residue


def test_purged_prompts_leave_no_bytes_in_the_database_or_its_wal(tmp_path: Path) -> None:
    db = tmp_path / "session.sqlite"
    store = SessionStore(str(db))
    marker = "UNIQUEPROMPTMARKER" * 4
    assert store.add_prompt("s1", f"please {marker}", keep=3)
    assert store.purge_prompts() == 1
    files = [p for p in tmp_path.iterdir() if p.name.startswith("session.sqlite")]
    for path in files:
        assert marker.encode() not in path.read_bytes(), path.name
    store.close()


# ------------------------------------------------------------------ #4, #5, #6: the send gate


@pytest.mark.parametrize(
    "words",
    [
        ("mysql", "-u", "root", "--password", "hunter2hunter2"),
        ("deploy", "-Password", "hunter2hunter2"),
        ("curl", "-u", "bob:hunter2hunter2", "https://x.example.invalid"),
        ("tool", "--api-key", "plainvalue12345"),
    ],
)
def test_a_secret_that_only_shows_across_words_is_refused(words: tuple[str, ...]) -> None:
    result = gate((command(*words),))
    assert result.request is None
    assert "across its words" in (result.refused or "")


def test_a_header_value_in_one_word_is_still_sent_redacted() -> None:
    secret = "sk-proj-" + "a1B2c3D4" * 4
    action = command("curl", "-H", f"Authorization: {secret}", "https://x.example.invalid")
    result = gate((action,))
    assert result.request is not None, result.refused
    assert "a1B2c3D4" not in result.request.content
    assert "x.example.invalid" in result.request.content


def test_a_request_the_redactor_would_still_change_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = send_gate.redact_text

    def picky(text: str) -> str:
        # stands for a pattern that only matches the serialized request as a whole
        return real(text).replace('"schema"', '"[REDACTED]"')

    monkeypatch.setattr(send_gate, "redact_text", picky)
    result = gate((command("make", "release"),))
    assert result.request is None
    assert "across its fields" in (result.refused or "")


def test_a_url_with_a_port_next_to_an_at_sign_is_not_a_false_refusal() -> None:
    action = command("tool", "http://localhost:3000", "user@example.com")
    assert gate((action,)).request is not None


def test_the_value_of_a_secret_environment_variable_is_refused_in_any_case() -> None:
    action = command("make", "deploy-ghsecretvalue12345")
    refused = gate((action,), secrets=("GHSECRETVALUE12345",))
    assert refused.request is None
    assert "secret environment variable" in (refused.refused or "")
    assert gate((action,), secrets=("short",)).request is not None  # under MIN_SECRET_CHARS


def test_a_variable_expanded_path_is_shown_unexpanded() -> None:
    expanded = f"{PROJECT}/ghsecretvalue12345/x"
    ref = PathRef(
        raw="$GITHUB_TOKEN/x",
        key=expanded,
        flavor="posix",
        access="read",
        inside_project=True,
        reasons=("variable-expanded",),
    )
    action = Action(tool="Bash", platform="posix", project=PROJECT, program="tool", paths=(ref,))
    result = gate((action,))
    assert result.payload is not None
    assert result.payload["actions"][0]["paths"][0]["path"] == "$GITHUB_TOKEN/x"
    assert result.request is not None
    assert "ghsecretvalue12345" not in result.request.content


def test_secret_values_takes_secret_looking_names_and_the_key_variable() -> None:
    env = {
        "GITHUB_TOKEN": "ghsecretvalue12345",
        "PGPASSWORD": "pgsecretvalue123",
        "MY_LLM": "the-api-key-value-1",
        "PWD": "/home/testuser/proj",
        "GIT_AUTHOR_NAME": "Test User Name",
        "SHORT_TOKEN": "abc",
        "PATH": "/usr/bin:/bin",
    }
    got = set(secret_values(env, "MY_LLM"))
    assert got == {"ghsecretvalue12345", "pgsecretvalue123", "the-api-key-value-1"}


def test_the_auditor_refuses_a_call_that_carries_an_env_secret() -> None:
    pol = llm_policy(on_failure="deny")
    backend = FakeBackend(lambda _r: verdict_json(verdict="allow"))
    env = {"HOME": HOME, "DEPLOY_TOKEN": "ghsecretvalue12345"}
    decision = decide(event("Bash", {"command": "make ghsecretvalue12345"}), pol, backend, env)
    assert backend.requests == []
    assert decision.decision == protocol.DECISION_DENY
    assert decision.decided_by == "llm-failure:refused"


# ------------------------------------------------------------------ #10: not analysed whole


@pytest.mark.parametrize(
    "reasons",
    [
        ("normalize-budget-exceeded", "budget:actions"),
        ("internal-error",),
        ("ps-helper-not-ready",),
        ("recursive-scan-budget",),
        ("mcp-arguments-not-all-seen",),
        ("mcp-command:mcp__x__run",),
    ],
)
def test_incomplete_analysis_is_recognised(reasons: tuple[str, ...]) -> None:
    action = Action(tool="Bash", platform="posix", program="x", gray=True, gray_reasons=reasons)
    assert pipeline.incomplete_analysis((action,)) is not None


def test_a_plain_gray_command_counts_as_analysed() -> None:
    action = Action(
        tool="Bash", platform="posix", program="make", gray=True, gray_reasons=("unknown-program",)
    )
    assert pipeline.incomplete_analysis((action,)) is None
    assert pipeline.incomplete_analysis((Action(tool="X", platform="posix"),)) is not None


@pytest.mark.parametrize(
    "payload",
    [
        event("SomeBrandNewTool", {"x": 1}),
        event("mcp__runner__exec", {"command": "make release"}),
    ],
    ids=["unknown-tool", "mcp-command"],
)
@pytest.mark.parametrize("on_failure", ["ask", "deny"])
def test_a_call_that_was_not_analysed_whole_is_not_sent_and_asks(
    payload: dict[str, Any], on_failure: str
) -> None:
    pol = llm_policy(on_failure=on_failure)
    backend = FakeBackend(lambda _r: verdict_json(verdict="allow"))
    decision = decide(payload, pol, backend)
    assert backend.requests == []
    assert decision.decision == protocol.DECISION_ASK  # the user's question, whatever on_failure
    assert decision.decided_by == "gray-unanalysed"
    assert "not sent to the LLM audit" in decision.reason
    assert decision.llm is not None
    assert decision.llm["outcome"] == "not-sent"


def test_an_ordinary_mcp_call_is_still_sent() -> None:
    pol = llm_policy()
    backend = FakeBackend(lambda _r: verdict_json(verdict="ask"))
    decide(event("mcp__docs__search", {"query": "release notes"}), pol, backend)
    assert len(backend.requests) == 1


# ------------------------------------------------------------------ #11, #14: exec tags


def _tags(payload: dict[str, Any]) -> set[str]:
    review = pipeline.review(
        payload,
        parse_policy_text(default_policy_text(), home=HOME),
        platform="posix",
        env={"HOME": HOME},
        home=HOME,
        scan_disk=False,
    )
    return {tag for action in review.actions for tag in action.risk_tags}


@pytest.mark.parametrize(
    "payload",
    [
        event("mcp__docs__search", {"query": "x"}),
        event("SomeBrandNewTool", {}),
        event("Bash", {"command": "npm test"}),
        event("Bash", {"command": "make"}),
        event("Bash", {"command": "cargo build"}),
        event("Bash", {"command": "uv run pytest"}),
    ],
    ids=["mcp", "unknown-tool", "npm", "make", "cargo", "uv"],
)
def test_code_that_runs_unseen_is_tagged_exec(payload: dict[str, Any]) -> None:
    assert "exec" in _tags(payload)


def test_an_mcp_call_may_send_data_out() -> None:
    assert "network_egress" in _tags(event("mcp__docs__search", {"query": "x"}))


def test_a_known_read_only_command_gets_no_exec_tag() -> None:
    assert "exec" not in _tags(event("Bash", {"command": "ls"}))


# ------------------------------------------------------------------ #12, #13: the daemon


def test_a_job_that_never_started_is_reported_as_such() -> None:
    pool = _DecisionPool(1)
    release = threading.Event()
    first = pool.submit(release.wait)
    deadline = time.monotonic() + 2
    while not first.future.running() and time.monotonic() < deadline:
        time.sleep(0.01)
    second = pool.submit(lambda: None)
    assert pool.abandon(second) is True
    assert pool.abandon(first) is False
    release.set()
    pool.close()


def _slow_review(seconds: float) -> Any:
    def review(_request: Any, _extra: list[float] | None = None) -> Any:
        time.sleep(seconds)
        return pipeline.Decision(protocol.DECISION_NONE, "", "rule-allow"), "enforce"

    return review


def test_a_queued_review_gets_the_llm_budget_known_at_submission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BOUNDKEEP_LLM_API_KEY", KEY)
    with FakeLLMServer(Reply(body=tool_call_answer(verdict_json()))) as server:
        h = Harness(
            tmp_path / "home",
            policy_text(base_url=server.base_url, timeout_ms=1000),
            decision_timeout_s=0.2,
        )
        h.send("ping", {})  # the policy, and so the auditor, are known now
        # a review that never publishes a budget itself (it waited in the queue, say)
        monkeypatch.setattr(h.daemon, "_review", _slow_review(0.8))
        response = h.send("pre", bash(tmp_path, "make release"))
    assert response.decision == "none"
    assert h.records()[-1]["decided_by"] == "rule-allow"


@pytest.mark.parametrize("on_failure", ["ask", "deny"])
def test_a_review_with_the_llm_that_runs_out_of_time_ends_in_on_failure(
    on_failure: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BOUNDKEEP_LLM_API_KEY", KEY)
    with FakeLLMServer(Reply(body=tool_call_answer(verdict_json()))) as server:
        h = Harness(
            tmp_path / "home",
            policy_text(base_url=server.base_url, timeout_ms=200, on_failure=on_failure),
            decision_timeout_s=0.2,
        )
        h.send("ping", {})
        monkeypatch.setattr(h.daemon, "_review", _slow_review(2.5))
        started = time.monotonic()
        response = h.send("pre", bash(tmp_path, "make release"))
        elapsed = time.monotonic() - started
    assert response.decision == on_failure
    assert h.records()[-1]["decided_by"] == DECIDED_BY_LLM_TIMEOUT
    assert 0.8 < elapsed < 2.0  # 0.2 s rules + 0.2 s budget + 0.5 s slack


def test_a_busy_daemon_still_marks_a_taint_source(tmp_path: Path) -> None:
    store = SessionStore(str(tmp_path / "s.sqlite"))
    h = Harness(tmp_path / "home", policy_text(), session=store)
    h.send("ping", {})
    h.daemon._pool._stuck = h.daemon._pool.size  # every worker is stuck
    project = tmp_path / "proj"
    response = h.send("pre", pre(project, "WebFetch", {"url": "https://example.invalid"}))
    assert response.decision == "ask"
    assert h.records()[-1]["decided_by"] == "busy"
    deadline = time.monotonic() + 3
    while not store.facts(SID, window=8).tainted and time.monotonic() < deadline:
        time.sleep(0.02)
    facts = store.facts(SID, window=8)
    assert facts.tainted
    assert "WebFetch" in facts.sources
    h.daemon._pool._stuck = 0
    h.daemon._close_session_and_auditors()


# ------------------------------------------------------------------ #7, #9: the adapter


def test_a_client_that_cannot_be_set_up_is_a_network_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(**_kwargs: Any) -> Any:
        raise ImportError("Using SOCKS proxy, but the 'socksio' package is not installed.")

    with FakeLLMServer(Reply(body=tool_call_answer(verdict_json()))) as server:
        backend = make_backend(server, "tool_call")
        monkeypatch.setattr(openai_compatible.httpx, "AsyncClient", broken)
        with pytest.raises(BackendError) as caught:
            backend.audit(request(), deadline=time.monotonic() + 2)
        assert server.requests == []
    assert caught.value.kind == "network"
    assert "could not be set up (ImportError)" in caught.value.detail
    assert "socksio" not in caught.value.detail


def test_llm_check_reports_an_adapter_bug_as_a_failed_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("adapter bug")

    monkeypatch.setenv("BOUNDKEEP_LLM_API_KEY", KEY)
    with FakeLLMServer(Reply(body=tool_call_answer(verdict_json()))) as server:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(policy_text(base_url=server.base_url), encoding="utf-8")
        monkeypatch.setattr(openai_compatible.OpenAICompatibleBackend, "audit", boom)
        code = cli.main(["llm", "check", "--policy", str(policy_file)])
    assert code != 0
    assert "FAILED: internal: RuntimeError" in capsys.readouterr().out


# ------------------------------------------------------------------ #15: the eval reference


def _sensitivity(samples: list[Any]) -> dict[str, Any]:
    plain = runner.run(samples, ps_ready=False)
    tainted = runner.run(samples, config="rules+taint", ps_ready=False, taint_all=True)
    trusted = runner.run(samples, ps_ready=False, trusted=True)
    computed = dict(metrics.compute(plain))
    computed["taint_delta"] = metrics.delta(
        plain, runner.run(samples, config="rules+taint", ps_ready=False)
    )
    computed["taint_sensitivity"] = {
        "clean": metrics.reference(plain),
        "tainted": metrics.reference(tainted),
        "trusted_clean": metrics.reference(trusted),
        "trusted_tainted": metrics.reference(tainted),
        "benign_tainted": sum(1 for s in samples if s.label == "benign" and s.tainted),
    }
    return computed


INFO = {
    "date": "d",
    "version": "0",
    "python": "3",
    "host": "H",
    "dev_hash": "a" * 64,
    "test_hash": "b" * 64,
}


def test_the_reference_says_no_benign_sample_is_tainted_only_when_none_is() -> None:
    samples = [_benign("ben-test-001", "pytest -q", repo=True), _sample()]
    md = report.to_markdown(_sensitivity(samples), samples, INFO)
    assert "正常样本没有一条标了 `tainted`" in md
    assert "“会话干净”两列取自 `rules-only`" in md


def test_the_reference_counts_benign_tainted_samples_when_there_are_some() -> None:
    tainted = _benign("ben-test-003", "pytest -q", repo=True).model_copy(update={"tainted": True})
    samples = [tainted, _sample()]
    md = report.to_markdown(_sensitivity(samples), samples, INFO)
    assert "没有一条" not in md.split("## 局限性")[0]
    assert "只有 1 条正常样本标了 `tainted`" in md
    assert "标了 `tainted` 的正常样本有 1 条" in md


def test_run_eval_takes_the_clean_columns_from_rules_only() -> None:
    source = (Path(__file__).resolve().parents[2] / "eval" / "run_eval.py").read_text(
        encoding="utf-8"
    )
    block = source[source.index("taint_sensitivity = {") :].split("}", 1)[0]
    assert '"clean": metrics.reference(plain["rules-only"])' in block
    assert '"trusted_clean": metrics.reference(trusted["rules-only"])' in block
