"""The daemon with session state and the LLM audit, end to end except the transport.

Failure injection (M3a acceptance): through the real OpenAI-compatible adapter against the local
fake server, a timeout, a 5xx, a rate limit, an invalid output, a dead endpoint and a missing key
all end in ``on_failure``. Egress: secrets in the command and in the prompt never reach the request
body, the audit log or an error message in clear, and neither does the API key.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any

import pytest

from boundkeep import paths, protocol
from boundkeep.audit.backends.base import verdict_json
from boundkeep.daemon.server import Daemon
from boundkeep.ipc.endpoint import TRANSPORT_NAMED_PIPE, Endpoint
from boundkeep.logstore import AuditLog
from boundkeep.policy import default_policy_text
from boundkeep.session.store import SessionStore, UnavailableStore
from tests.helpers.llm_server import FakeLLMServer, Reply, tool_call_answer

ENDPOINT = Endpoint(TRANSPORT_NAMED_PIPE, "\\\\.\\pipe\\boundkeep-m3a-test")
SID = "00000000-0000-4000-8000-0000000000cc"
KEY = "bk-daemon-test-Kq3x8W2mN4pR8tY1zZ"  # no redaction pattern knows this shape
SECRET = "sk-proj-" + "Zx9Yw8Vu" * 4
SECRET_FRAGMENT = "Zx9Yw8VuZx9Y"


def policy_text(
    *, base_url: str | None = None, trusted: Path | None = None, **llm_keys: object
) -> str:
    text = default_policy_text()
    if base_url is not None:
        block = (
            "  backend: openai_compatible\n"
            "  openai_compatible:\n"
            f"    base_url: {base_url}\n"
            "    model: daemon-test-model\n"
        )
        text = re.sub(r"^  backend: none.*$", block.rstrip("\n"), text, count=1, flags=re.M)
    for key, value in llm_keys.items():
        text, found = re.subn(rf"^  {key}: .*$", f"  {key}: {value}", text, count=1, flags=re.M)
        assert found == 1, key
    if trusted is not None:
        entry = str(trusted).replace("'", "''")
        text = text.replace("\nrules:\n", f"\ntrusted_projects:\n  - '{entry}'\nrules:\n", 1)
    return text


class Harness:
    def __init__(self, home: Path, text: str, **daemon_kwargs: Any) -> None:
        home.mkdir(parents=True, exist_ok=True)
        self.home = home
        Path(paths.policy_file(str(home))).write_text(text, encoding="utf-8")
        self.log = AuditLog(paths.audit_log_file(str(home)))
        self.messages: list[str] = []
        self.daemon = Daemon(
            ENDPOINT, home=str(home), log=self.log, report=self.messages.append, **daemon_kwargs
        )

    def send(self, event: str, payload: dict[str, Any]) -> protocol.Response:
        line = protocol.encode_request(event, payload, "r1").rstrip(b"\n")
        raw = asyncio.run(self.daemon.handle(line))
        return protocol.decode_response(raw.rstrip(b"\n"), "r1")

    def records(self) -> list[dict[str, Any]]:
        return [r for r in self.log.tail(1000) if r.get("event") not in ("daemon",)]

    def log_text(self) -> str:
        return Path(self.log.path).read_text(encoding="utf-8")


@pytest.fixture
def project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    (proj / "tests").mkdir(parents=True)
    return proj


def pre(project: Path, tool: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": SID,
        "cwd": str(project),
        "project_dir": str(project),
        "tool_name": tool,
        "tool_input": tool_input,
    }


def bash(project: Path, command: str) -> dict[str, Any]:
    return pre(project, "Bash", {"command": command})


def post(tool: str) -> dict[str, Any]:
    return {"hook_event_name": "PostToolUse", "session_id": SID, "tool_name": tool}


def prompt(text: str) -> dict[str, Any]:
    return {"hook_event_name": "UserPromptSubmit", "session_id": SID, "prompt": text}


# ------------------------------------------------------------------------------ session state


def test_a_web_read_makes_the_next_trusted_dev_tool_run_ask(tmp_path: Path, project: Path) -> None:
    h = Harness(tmp_path / "home", policy_text(trusted=project))
    assert h.send("pre", bash(project, "pytest -q")).decision == "none"
    h.send("post", post("WebFetch"))
    response = h.send("pre", bash(project, "pytest -q"))
    assert response.decision == "ask"
    record = h.records()[-1]
    assert record["rules"] == ["ask-devtools-after-untrusted-content"]
    assert record["taint"] == {
        "tainted": True,
        "read_untrusted": True,
        "sources": ["WebFetch"],
        "calls_since_taint": 1,
    }


def test_the_taint_survives_a_daemon_restart(tmp_path: Path, project: Path) -> None:
    first = Harness(tmp_path / "home", policy_text(trusted=project))
    first.send("post", post("mcp__docs__fetch"))
    first.daemon._close_session_and_auditors()
    second = Harness(tmp_path / "home", policy_text(trusted=project))
    assert second.send("pre", bash(project, "ruff check .")).decision == "ask"


def test_an_unavailable_store_is_reported_and_fails_closed(tmp_path: Path, project: Path) -> None:
    h = Harness(
        tmp_path / "home", policy_text(trusted=project), session=UnavailableStore("disk full")
    )
    assert any("session state unavailable" in m for m in h.messages)
    assert h.send("pre", bash(project, "pytest -q")).decision == "ask"
    assert h.records()[-1]["taint"]["state"] == "unknown"
    ping = h.send("ping", {})
    assert "session=unavailable" in ping.reason


def test_a_corrupt_database_is_reported_at_start(tmp_path: Path, project: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    Path(paths.session_db_file(str(home))).write_bytes(b"garbage" * 200)
    h = Harness(home, policy_text(trusted=project))
    assert any("session state unavailable" in m for m in h.messages)
    assert h.send("pre", bash(project, "pytest -q")).decision == "ask"


def test_cleanup_runs_on_the_store(tmp_path: Path, project: Path) -> None:
    now = [1000.0]
    store = SessionStore(str(tmp_path / "s.sqlite"), clock=lambda: now[0])
    store.tool_result("old", "WebFetch", sources=("WebFetch",))
    now[0] += 40 * 24 * 3600
    h = Harness(tmp_path / "home", policy_text(), session=store)
    assert h.daemon.clean_sessions() == 1
    assert any("1 idle session" in m for m in h.messages)


def test_prompts_are_stored_with_a_backend_and_never_logged(tmp_path: Path, project: Path) -> None:
    with FakeLLMServer(Reply(body=tool_call_answer(verdict_json()))) as server:
        h = Harness(tmp_path / "home", policy_text(base_url=server.base_url))
        text = f"<ide_selection>FILE BODY</ide_selection> ship the release, key {SECRET}"
        h.send("prompt", prompt(text))
        store = SessionStore(paths.session_db_file(str(h.home)))
        (intent,) = store.facts(SID, window=8, intents=3).intents
        store.close()
    assert intent.startswith("ship the release")
    assert SECRET_FRAGMENT not in intent
    assert "FILE BODY" not in intent
    log = h.log_text()
    assert "ship the release" not in log
    assert SECRET_FRAGMENT not in log
    assert h.records()[-1]["prompt_chars"] == len(text)


# ------------------------------------------------------------------------------ the LLM path


def _audit_once(
    tmp_path: Path, project: Path, reply: Reply, monkeypatch: pytest.MonkeyPatch, **keys: object
) -> tuple[protocol.Response, dict[str, Any], FakeLLMServer, Harness]:
    monkeypatch.setenv("BOUNDKEEP_LLM_API_KEY", KEY)
    with FakeLLMServer(reply) as server:
        h = Harness(tmp_path / "home", policy_text(base_url=server.base_url, **keys))
        response = h.send("pre", bash(project, "make release"))
    return response, h.records()[-1], server, h


def test_a_gray_call_is_audited_and_logged(
    tmp_path: Path, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    response, record, server, h = _audit_once(
        tmp_path, project, Reply(body=tool_call_answer(verdict_json(verdict="allow"))), monkeypatch
    )
    assert response.decision == "none"
    assert record["decided_by"] == "llm"
    assert record["verdict"] == "gray"
    llm = record["llm"]
    assert llm["backend"] == "openai_compatible"
    assert llm["model"] == "daemon-test-model"
    assert llm["transport"] == "tool_call"
    assert llm["prompt"].startswith("v1:")
    assert llm["outcome"] == "ok"
    assert llm["final"] == "allow"
    assert llm["cache"] == "miss"
    assert llm["tokens"]["total"] == 960
    assert len(server.requests) == 1
    assert KEY not in h.log_text()
    assert any("LLM audit: openai_compatible" in m for m in h.messages)


FAILURES = {
    "timeout": (Reply(body=tool_call_answer(verdict_json()), delay_s=1.5), "timeout"),
    "http_5xx": (Reply(status=503), "http_5xx"),
    "rate_limit": (Reply(status=429), "rate_limit"),
    "invalid_output": (Reply(body=tool_call_answer('{"verdict": "allow"}')), "invalid_output"),
    "auth": (Reply(status=401), "auth"),
}


@pytest.mark.parametrize("name", sorted(FAILURES))
@pytest.mark.parametrize("on_failure", ["ask", "deny"])
def test_failure_injection_ends_in_on_failure(
    name: str, on_failure: str, tmp_path: Path, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reply, kind = FAILURES[name]
    response, record, _server, _h = _audit_once(
        tmp_path, project, reply, monkeypatch, timeout_ms=500, on_failure=on_failure
    )
    assert response.decision == on_failure
    assert record["decided_by"] == f"llm-failure:{kind}"
    assert record["llm"]["outcome"] == kind


@pytest.mark.parametrize("on_failure", ["ask", "deny"])
def test_a_dead_endpoint_ends_in_on_failure(
    on_failure: str, tmp_path: Path, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BOUNDKEEP_LLM_API_KEY", KEY)
    with FakeLLMServer() as gone:
        url = gone.base_url
    h = Harness(tmp_path / "home", policy_text(base_url=url, on_failure=on_failure))
    response = h.send("pre", bash(project, "make release"))
    assert response.decision == on_failure
    assert h.records()[-1]["llm"]["outcome"] in ("network", "timeout")


@pytest.mark.parametrize("on_failure", ["ask", "deny"])
def test_a_missing_key_ends_in_on_failure(
    on_failure: str, tmp_path: Path, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("BOUNDKEEP_LLM_API_KEY", raising=False)
    with FakeLLMServer(Reply(body=tool_call_answer(verdict_json()))) as server:
        h = Harness(tmp_path / "home", policy_text(base_url=server.base_url, on_failure=on_failure))
        response = h.send("pre", bash(project, "make release"))
        assert server.requests == []
    assert response.decision == on_failure
    record = h.records()[-1]
    assert record["llm"]["outcome"] == "auth"
    assert "BOUNDKEEP_LLM_API_KEY" in record["llm"]["detail"]


def test_the_review_deadline_grows_by_the_llm_budget(
    tmp_path: Path, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the model takes longer than the rules' own 2 s deadline but less than the LLM budget
    response, record, _server, _h = _audit_once(
        tmp_path,
        project,
        Reply(body=tool_call_answer(verdict_json(verdict="ask")), delay_s=2.3),
        monkeypatch,
        timeout_ms=4000,
    )
    assert record["decided_by"] == "llm", record
    assert response.decision == "ask"


def test_the_auditor_is_rebuilt_when_the_policy_changes(
    tmp_path: Path, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BOUNDKEEP_LLM_API_KEY", KEY)
    with FakeLLMServer(Reply(body=tool_call_answer(verdict_json(verdict="deny")))) as server:
        h = Harness(tmp_path / "home", policy_text())
        assert h.send("pre", bash(project, "make release")).decision == "ask"  # no backend
        Path(paths.policy_file(str(h.home))).write_text(
            policy_text(base_url=server.base_url, cache_ttl_s=0), encoding="utf-8"
        )
        assert h.send("pre", bash(project, "make release")).decision == "deny"
        assert len(server.requests) == 1


# ------------------------------------------------------------------------------ egress


def test_secrets_never_reach_the_body_the_log_or_an_error(
    tmp_path: Path, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BOUNDKEEP_LLM_API_KEY", KEY)
    secrets = {
        "openai": SECRET,
        "aws": "AKIAQWERTYUIOPASDFGH",
        "github": "ghp_" + "M" * 36,
        "pem": (
            "-----BEGIN OPENSSH PRIVATE KEY-----\\nb3BlbnNzaC1rZXk\\n"
            "-----END OPENSSH PRIVATE KEY-----"
        ),
    }
    fragments = (SECRET_FRAGMENT, "QWERTYUIOPASDFGH", "M" * 36, "b3BlbnNzaC1rZXk")

    def echo(seen: Any) -> Reply:
        # a careless server: its error repeats the key and the whole request
        return Reply(
            status=400,
            body={"error": {"code": KEY, "message": seen.body.decode("utf-8", "replace")}},
        )

    with FakeLLMServer(echo) as server:
        h = Harness(tmp_path / "home", policy_text(base_url=server.base_url))
        h.send("prompt", prompt(f"deploy with {secrets['openai']} and {secrets['aws']}"))
        command = (
            f"python deploy.py --token {secrets['github']} --aws {secrets['aws']} "
            f"--note '{secrets['pem']}' --api {secrets['openai']}"
        )
        response = h.send("pre", bash(project, command))
        bodies = [seen.body.decode("utf-8") for seen in server.requests]
        headers = [json.dumps(seen.headers) for seen in server.requests]
    assert response.decision == "ask"  # the 400 failed the audit: on_failure
    assert bodies, "the audit was sent"
    for body in bodies:
        for fragment in fragments:
            assert fragment not in body
        assert KEY not in body
    assert all(KEY in header for header in headers)  # it travelled in the header only
    log = h.log_text()
    for fragment in (*fragments, KEY):
        assert fragment not in log
    record = h.records()[-1]
    assert KEY not in json.dumps(record)
    assert record["llm"]["outcome"] == "http_4xx"
    assert all(KEY not in m for m in h.messages)


def test_the_log_record_of_a_gray_call_holds_no_file_content(
    tmp_path: Path, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BOUNDKEEP_LLM_API_KEY", KEY)
    with FakeLLMServer(Reply(body=tool_call_answer(verdict_json(verdict="ask")))) as server:
        h = Harness(tmp_path / "home", policy_text(base_url=server.base_url))
        write = pre(project, "Write", {"file_path": str(project / "Makefile"), "content": "BODY_X"})
        h.send("pre", write)
        bodies = [seen.body.decode("utf-8") for seen in server.requests]
    assert all("BODY_X" not in body for body in bodies)
    assert "BODY_X" not in h.log_text()
