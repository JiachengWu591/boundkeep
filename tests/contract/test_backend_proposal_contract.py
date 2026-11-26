"""The proposal contract of every adapter (M4, PROJECT_SPEC.md §8.1).

``propose`` shares the transport of ``audit`` (retry, budget, size limit, failure kinds; that part
is the audit contract suite's); here: a proposal object comes back whole, anything that is not one
strict JSON object of bounded size is ``invalid_output``, the request carries the proposal tool and
the larger token allowance, and a request built for the other purpose is refused.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from boundkeep.audit import send_gate
from boundkeep.audit.backends.base import (
    MAX_PROPOSAL_OUTPUT_CHARS,
    PROPOSAL_TOOL_NAME,
    BackendError,
    GatedRequest,
)
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.audit.backends.openai_compatible import MAX_PROPOSAL_TOKENS
from tests.contract.conftest import HTTP_ADAPTERS, make_backend, request
from tests.helpers.llm_server import FakeLLMServer, Reply, json_answer, tool_call_answer

ALL_ADAPTERS = ("fake", *HTTP_ADAPTERS)
BUDGET_S = 3.0
VALID = json.dumps(
    {
        "proposal": 1,
        "summary": "deny curl",
        "rules": [
            {"id": "deny-curl", "match": {"program": "curl"}, "action": "deny", "reason": "r"}
        ],
        "tests": [],
    }
)
INVALID = {
    "not-json": "Here are the rules: deny curl",
    "array": json.dumps([json.loads(VALID)]),
    "duplicate-key": VALID[:-1] + ', "rules": []}',
    "nan": VALID.replace('"proposal": 1', '"proposal": NaN'),
    "huge": json.dumps({"summary": "z" * (MAX_PROPOSAL_OUTPUT_CHARS + 1)}),
    "empty": "",
}


def policy_request() -> GatedRequest:
    result = send_gate.gate_policy_request("deny curl", ["no-secret-read"], home=None)
    assert result.request is not None
    return result.request


def _backend(name: str, text: str, server: FakeLLMServer) -> Any:
    if name == "fake":
        return FakeBackend([text])
    transport = name.split("/")[1]
    if transport == "tool_call":
        server.reply = Reply(body=tool_call_answer(text, name=PROPOSAL_TOOL_NAME))
    else:
        server.reply = Reply(body=json_answer(text))
    return make_backend(server, transport)


@pytest.mark.parametrize("adapter", ALL_ADAPTERS)
def test_a_proposal_comes_back_whole(adapter: str, server: FakeLLMServer) -> None:
    result = _backend(adapter, VALID, server).propose(
        policy_request(), deadline=time.monotonic() + BUDGET_S
    )
    assert result.data == json.loads(VALID)


@pytest.mark.parametrize("adapter", ALL_ADAPTERS)
@pytest.mark.parametrize("case", sorted(INVALID))
def test_anything_but_one_json_object_is_invalid_output(
    adapter: str, case: str, server: FakeLLMServer
) -> None:
    with pytest.raises(BackendError) as caught:
        _backend(adapter, INVALID[case], server).propose(
            policy_request(), deadline=time.monotonic() + BUDGET_S
        )
    assert caught.value.kind == "invalid_output"


@pytest.mark.parametrize("adapter", ALL_ADAPTERS)
def test_requests_are_not_interchangeable(adapter: str, server: FakeLLMServer) -> None:
    backend = _backend(adapter, VALID, server)
    with pytest.raises(TypeError):
        backend.propose(request(), deadline=time.monotonic() + BUDGET_S)
    with pytest.raises(TypeError):
        backend.audit(policy_request(), deadline=time.monotonic() + BUDGET_S)


def test_the_verdict_tool_is_not_a_proposal(server: FakeLLMServer) -> None:
    server.reply = Reply(body=tool_call_answer(VALID))  # report_verdict
    backend = make_backend(server, "tool_call")
    with pytest.raises(BackendError) as caught:
        backend.propose(policy_request(), deadline=time.monotonic() + BUDGET_S)
    assert caught.value.kind == "invalid_output"
    assert PROPOSAL_TOOL_NAME in caught.value.detail


@pytest.mark.parametrize("transport", ["tool_call", "json_object"])
def test_the_request_body_of_a_proposal(transport: str, server: FakeLLMServer) -> None:
    backend = _backend(f"openai_compatible/{transport}", VALID, server)
    body = backend.body(policy_request())
    assert body["max_tokens"] == MAX_PROPOSAL_TOKENS
    assert body["messages"][0]["content"].startswith("You write proposals for boundkeep")
    assert json.loads(body["messages"][1]["content"])["request"] == "deny curl"
    if transport == "tool_call":
        assert body["tools"][0]["function"]["name"] == PROPOSAL_TOOL_NAME
        assert body["tool_choice"]["function"]["name"] == PROPOSAL_TOOL_NAME
    else:
        assert body["response_format"] == {"type": "json_object"}
    audit_body = backend.body(request())
    assert audit_body["max_tokens"] < MAX_PROPOSAL_TOKENS


@pytest.mark.parametrize("status", [500, 503])
def test_a_proposal_is_retried_once_like_an_audit(status: int, server: FakeLLMServer) -> None:
    replies = [Reply(status=status), Reply(body=tool_call_answer(VALID, name=PROPOSAL_TOOL_NAME))]
    server.reply = lambda _seen: replies.pop(0)
    backend = make_backend(server, "tool_call")
    result = backend.propose(policy_request(), deadline=time.monotonic() + BUDGET_S)
    assert result.attempts == 2
    assert result.data["proposal"] == 1
