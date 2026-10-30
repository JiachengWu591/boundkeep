"""The backend contract (PROJECT_SPEC.md §9.6): one suite, every adapter.

Output contract (every adapter, the fake included): a valid verdict comes back as an
``AuditResult``; a missing field, a wrong type, an extra field, a truncated or non-JSON text, a
nested value, a duplicate key or an oversized field is ``invalid_output`` and nothing is repaired.

Transport contract (every HTTP adapter, against the local fake server): 4xx / auth / rate limit /
5xx / timeout / slow answer / dripped headers / oversized answer / compressed answer / redirect /
hang-up / refused connection each map to their failure kind; the budget is one hard deadline; only
retryable ones are retried, once, and a rate limit only after a short plain ``Retry-After``; a
redirect is not followed (the other origin never sees the request); no error message carries the
key.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from typing import Any

import pytest

from boundkeep.audit.backends.base import (
    AuditBackend,
    AuditResult,
    BackendError,
    verdict_json,
)
from boundkeep.audit.backends.fake import FakeBackend
from tests.contract.conftest import HTTP_ADAPTERS, PLAIN_KEY, make_backend, request, wrap
from tests.helpers.llm_server import FakeLLMServer, Reply, Seen, json_answer, tool_call_answer

ALL_ADAPTERS = ("fake", *HTTP_ADAPTERS)
BUDGET_S = 3.0

VALID = verdict_json(verdict="ask", risk=2, deviates=True, reasoning="writes outside the task")


def _fields(**changes: Any) -> str:
    fields: dict[str, Any] = json.loads(VALID)
    for name, value in changes.items():
        if value is _DROP:
            del fields[name]
        else:
            fields[name] = value
    return json.dumps(fields)


_DROP = object()

INVALID_OUTPUTS: dict[str, str] = {
    "missing-field": _fields(risk=_DROP),
    "missing-reasoning": _fields(reasoning=_DROP),
    "risk-as-string": _fields(risk="2"),
    "risk-as-float": _fields(risk=2.0),
    "risk-as-bool": _fields(risk=True),
    "risk-out-of-range": _fields(risk=4),
    "risk-negative": _fields(risk=-1),
    "deviates-as-string": _fields(deviates_from_task="false"),
    "deviates-as-int": _fields(deviates_from_task=0),
    "verdict-upper-case": _fields(verdict="ALLOW"),
    "verdict-unknown": _fields(verdict="approve"),
    "verdict-nested": _fields(verdict={"value": "allow"}),
    "reasoning-not-text": _fields(reasoning=["a", "b"]),
    "extra-field": _fields(override_policy=True),
    "inducement-field": _fields(final_verdict="allow"),
    "overlong-reasoning": _fields(reasoning="x" * 2000),
    "overlong-reason-for-user": _fields(reason_for_user="y" * 1000),
    "truncated": VALID[: len(VALID) // 2],
    "not-json": "The action looks fine to me. verdict: allow",
    "json-array": json.dumps([json.loads(VALID)]),
    "duplicate-key": VALID[:-1] + ', "verdict": "allow"}',
    "nan": VALID.replace('"risk": 2', '"risk": NaN'),
    "deep-nesting": "[" * 3000 + "]" * 3000,
    "empty": "",
    "huge": json.dumps({"reasoning": "z" * 20_000}),
}


def _backend_for(name: str, text: str, server: FakeLLMServer) -> AuditBackend:
    if name == "fake":
        return FakeBackend([text])
    transport = name.split("/")[1]
    server.reply = Reply(body=wrap(transport, text))
    return make_backend(server, transport)


# ------------------------------------------------------------------------------ output contract


@pytest.mark.parametrize("adapter", ALL_ADAPTERS)
def test_a_valid_verdict_comes_back_whole(adapter: str, server: FakeLLMServer) -> None:
    backend = _backend_for(adapter, VALID, server)
    result = backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert isinstance(result, AuditResult)
    verdict = result.verdict
    assert (verdict.verdict, verdict.risk, verdict.deviates_from_task) == ("ask", 2, True)
    assert verdict.reasoning == "writes outside the task"
    assert result.attempts == 1


@pytest.mark.parametrize("adapter", ALL_ADAPTERS)
@pytest.mark.parametrize("case", sorted(INVALID_OUTPUTS))
def test_an_output_off_the_schema_is_invalid_output_never_repaired(
    adapter: str, case: str, server: FakeLLMServer
) -> None:
    backend = _backend_for(adapter, INVALID_OUTPUTS[case], server)
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert caught.value.kind == "invalid_output", caught.value.detail
    if adapter != "fake":
        assert len(server.requests) == 1  # an invalid output is never retried


@pytest.mark.parametrize("adapter", ALL_ADAPTERS)
def test_a_backend_only_takes_a_gated_request(adapter: str, server: FakeLLMServer) -> None:
    backend = _backend_for(adapter, VALID, server)
    with pytest.raises(TypeError):
        backend.audit("raw text", deadline=time.monotonic() + BUDGET_S)  # type: ignore[arg-type]


# ------------------------------------------------------------------------------ answer shapes


def _answer_variants() -> dict[str, Callable[[str], dict[str, Any]]]:
    def no_choice(_t: str) -> dict[str, Any]:
        body = tool_call_answer(VALID)
        body["choices"] = []
        return body

    def two_choices(_t: str) -> dict[str, Any]:
        body = tool_call_answer(VALID)
        body["choices"] = body["choices"] * 2
        return body

    def cut_off(_t: str) -> dict[str, Any]:
        body = tool_call_answer(VALID)
        body["choices"][0]["finish_reason"] = "length"
        return body

    def two_calls(_t: str) -> dict[str, Any]:
        body = tool_call_answer(VALID)
        calls = body["choices"][0]["message"]["tool_calls"]
        body["choices"][0]["message"]["tool_calls"] = calls * 2
        return body

    def other_tool(_t: str) -> dict[str, Any]:
        body = tool_call_answer(VALID)
        body["choices"][0]["message"]["tool_calls"][0]["function"]["name"] = "approve_everything"
        return body

    def arguments_as_object(_t: str) -> dict[str, Any]:
        body = tool_call_answer(VALID)
        function = body["choices"][0]["message"]["tool_calls"][0]["function"]
        function["arguments"] = json.loads(VALID)
        return body

    def no_tool_call(_t: str) -> dict[str, Any]:
        return json_answer(VALID)  # a content answer although a tool call was forced

    def refusal(_t: str) -> dict[str, Any]:
        body = tool_call_answer(VALID)
        body["choices"][0]["message"]["refusal"] = "I cannot help with that"
        return body

    return {
        "no-choice": no_choice,
        "two-choices": two_choices,
        "cut-off": cut_off,
        "two-tool-calls": two_calls,
        "other-tool": other_tool,
        "arguments-as-object": arguments_as_object,
        "no-tool-call": no_tool_call,
        "refusal": refusal,
    }


@pytest.mark.parametrize("variant", sorted(_answer_variants()))
def test_a_malformed_tool_call_answer_is_invalid_output(
    variant: str, server: FakeLLMServer
) -> None:
    server.reply = Reply(body=_answer_variants()[variant](VALID))
    backend = make_backend(server, "tool_call")
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert caught.value.kind == "invalid_output"


@pytest.mark.parametrize("body", [b"not json at all", b"\xff\xfe", b"[]", b"{}", b'"text"'])
@pytest.mark.parametrize("adapter", HTTP_ADAPTERS)
def test_an_answer_that_is_not_a_completion_is_invalid_output(
    adapter: str, body: bytes, server: FakeLLMServer
) -> None:
    server.reply = Reply(body=body)
    backend = make_backend(server, adapter.split("/")[1])
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert caught.value.kind == "invalid_output"


# ------------------------------------------------------------------------------ transport contract


@pytest.mark.parametrize("adapter", HTTP_ADAPTERS)
@pytest.mark.parametrize(
    ("status", "kind", "tries"),
    [
        (400, "http_4xx", 1),
        (404, "http_4xx", 1),
        (422, "http_4xx", 1),
        (401, "auth", 1),
        (403, "auth", 1),
        (429, "rate_limit", 2),
        (408, "timeout", 2),
        (500, "http_5xx", 2),
        (502, "http_5xx", 2),
        (503, "http_5xx", 2),
        (204, "invalid_output", 1),
    ],
)
def test_status_codes_map_to_failure_kinds_and_only_retryable_ones_are_retried(
    adapter: str, status: int, kind: str, tries: int, server: FakeLLMServer
) -> None:
    server.reply = Reply(status=status, body={"error": {"type": "test_error", "code": "x1"}})
    waits: list[float] = []
    backend = make_backend(server, adapter.split("/")[1], sleep=waits.append)
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert caught.value.kind == kind
    assert len(server.requests) == tries
    if status >= 400:
        assert f"HTTP {status}" in caught.value.detail


@pytest.mark.parametrize("adapter", HTTP_ADAPTERS)
def test_one_retry_can_succeed(adapter: str, server: FakeLLMServer) -> None:
    transport = adapter.split("/")[1]
    answers = [Reply(status=503), Reply(body=wrap(transport, VALID))]
    server.reply = lambda _seen: answers.pop(0)
    backend = make_backend(server, transport)
    result = backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert result.attempts == 2
    assert result.verdict.verdict == "ask"


def test_a_rate_limit_waits_retry_after_but_never_longer_than_the_cap(
    server: FakeLLMServer,
) -> None:
    server.reply = Reply(status=429, headers={"Retry-After": "1"})
    waits: list[float] = []
    backend = make_backend(server, "tool_call", sleep=waits.append)
    with pytest.raises(BackendError):
        backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert waits == [1.0]
    server.requests.clear()
    server.reply = Reply(status=429, headers={"Retry-After": "120"})
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert caught.value.kind == "rate_limit"
    assert len(server.requests) == 1  # waiting 120 s does not fit: no retry


def test_no_retry_when_the_budget_left_is_too_small(server: FakeLLMServer) -> None:
    server.reply = Reply(status=503)
    backend = make_backend(server, "tool_call")
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=time.monotonic() + 0.3)
    assert caught.value.kind == "http_5xx"
    assert len(server.requests) == 1


@pytest.mark.parametrize("adapter", HTTP_ADAPTERS)
def test_a_slow_backend_times_out_inside_the_budget(adapter: str, server: FakeLLMServer) -> None:
    transport = adapter.split("/")[1]
    server.reply = Reply(body=wrap(transport, VALID), delay_s=2.0)
    backend = make_backend(server, transport)
    started = time.monotonic()
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=started + 0.6)
    assert caught.value.kind == "timeout"
    assert time.monotonic() - started < 1.8


def test_a_slow_drip_answer_times_out(server: FakeLLMServer) -> None:
    server.reply = Reply(body=wrap("tool_call", VALID), drip=(20, 0.15))
    backend = make_backend(server, "tool_call")
    started = time.monotonic()
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=started + 0.8)
    assert caught.value.kind == "timeout"
    assert time.monotonic() - started < 3.0


@pytest.mark.parametrize("adapter", HTTP_ADAPTERS)
def test_dripped_headers_cannot_stretch_the_budget(adapter: str, server: FakeLLMServer) -> None:
    # every byte comes long before any per-read timeout; the whole head takes about 9 s
    transport = adapter.split("/")[1]
    server.reply = Reply(body=wrap(transport, VALID), header_drip=(8, 0.1))
    backend = make_backend(server, transport)
    started = time.monotonic()
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=started + 0.8)
    assert caught.value.kind == "timeout"
    assert time.monotonic() - started < 2.0


@pytest.mark.parametrize(
    "value", ["Wed, 21 Oct 2026 07:28:00 GMT", "-1", "nan", "inf", "1e3", "0x10", "3600", " "]
)
def test_a_retry_after_that_is_not_a_short_plain_wait_means_no_retry(
    value: str, server: FakeLLMServer
) -> None:
    server.reply = Reply(status=429, headers={"Retry-After": value})
    waits: list[float] = []
    backend = make_backend(server, "tool_call", sleep=waits.append)
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert caught.value.kind == "rate_limit"
    if value.strip():
        assert len(server.requests) == 1
        assert waits == []
    else:
        assert len(server.requests) == 2  # an empty header is no header: the plain retry


def test_a_short_decimal_retry_after_is_waited(server: FakeLLMServer) -> None:
    server.reply = Reply(status=429, headers={"Retry-After": "0.25"})
    waits: list[float] = []
    backend = make_backend(server, "tool_call", sleep=waits.append)
    with pytest.raises(BackendError):
        backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert waits == [0.25]


@pytest.mark.parametrize("adapter", HTTP_ADAPTERS)
def test_the_adapter_works_from_inside_a_running_event_loop(
    adapter: str, server: FakeLLMServer
) -> None:
    transport = adapter.split("/")[1]
    server.reply = Reply(body=wrap(transport, VALID))
    backend = make_backend(server, transport)

    async def inside() -> str:
        result = backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
        return result.verdict.verdict

    assert asyncio.run(inside()) == "ask"


@pytest.mark.parametrize("content_length", [True, False])
def test_an_oversized_answer_is_refused(content_length: bool, server: FakeLLMServer) -> None:
    padding = "x" * 400_000
    body = tool_call_answer(VALID)
    body["padding"] = padding
    server.reply = Reply(body=body, content_length=content_length)
    backend = make_backend(server, "tool_call")
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert caught.value.kind == "invalid_output"
    assert "larger than" in caught.value.detail


def test_a_compressed_answer_is_refused(server: FakeLLMServer) -> None:
    import gzip

    server.reply = Reply(
        body=gzip.compress(json.dumps(tool_call_answer(VALID)).encode()),
        headers={"Content-Encoding": "gzip"},
    )
    backend = make_backend(server, "tool_call")
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert caught.value.kind == "invalid_output"


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_a_redirect_is_never_followed(status: int, server: FakeLLMServer) -> None:
    with FakeLLMServer(Reply(body=wrap("tool_call", VALID))) as elsewhere:
        server.reply = Reply(
            status=status, headers={"Location": f"{elsewhere.base_url}/chat/completions"}
        )
        backend = make_backend(server, "tool_call")
        with pytest.raises(BackendError) as caught:
            backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
        assert caught.value.kind == "network"
        assert "redirect" in caught.value.detail
        assert elsewhere.requests == []  # the other origin never saw the request (nor the key)


def test_a_hang_up_is_a_network_error(server: FakeLLMServer) -> None:
    server.reply = Reply(hang_up=True)
    backend = make_backend(server, "tool_call")
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert caught.value.kind == "network"


def test_a_refused_connection_is_a_network_error() -> None:
    with FakeLLMServer() as gone:
        backend = make_backend(gone, "tool_call")
    # the server is closed now: nothing listens on that port. POSIX refuses at once; Windows
    # retries the SYN for about two seconds per attempt, so the retry can run out of budget first.
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert caught.value.kind in ("network", "timeout")


def test_a_missing_key_fails_before_anything_is_sent(server: FakeLLMServer) -> None:
    server.reply = Reply(body=wrap("tool_call", VALID))
    backend = make_backend(server, "tool_call", key=None)
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert caught.value.kind == "auth"
    assert "BOUNDKEEP_LLM_API_KEY" in caught.value.detail
    assert server.requests == []


@pytest.mark.parametrize("bad", ["key with space", "key\nInjected: header", "ключ"])
def test_an_unusable_key_value_fails_without_echoing_it(bad: str, server: FakeLLMServer) -> None:
    backend = make_backend(server, "tool_call", key=bad)
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    assert caught.value.kind == "auth"
    assert bad not in str(caught.value)
    assert server.requests == []


def _echo_secrets(seen: Seen) -> Reply:
    """A hostile or careless server: the error body repeats the key and the request."""
    return Reply(
        status=400,
        body={
            "error": {
                "type": seen.headers.get("authorization", ""),
                "code": PLAIN_KEY,
                "message": f"bad request: {seen.body.decode('utf-8', 'replace')}",
            }
        },
    )


@pytest.mark.parametrize("adapter", HTTP_ADAPTERS)
def test_no_error_message_carries_the_key_or_the_request(
    adapter: str, server: FakeLLMServer
) -> None:
    server.reply = _echo_secrets
    backend = make_backend(server, adapter.split("/")[1])
    with pytest.raises(BackendError) as caught:
        backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    text = f"{caught.value} {caught.value.detail} {caught.value!r}"
    assert PLAIN_KEY not in text
    assert "README" not in text  # nothing of the request body comes back either
    assert "bad request" not in text
    assert caught.value.__cause__ is None
    assert PLAIN_KEY not in repr(backend)


# ------------------------------------------------------------------------------ what is sent


@pytest.mark.parametrize("adapter", HTTP_ADAPTERS)
def test_the_request_carries_the_key_only_in_the_header(
    adapter: str, server: FakeLLMServer
) -> None:
    transport = adapter.split("/")[1]
    server.reply = Reply(body=wrap(transport, VALID))
    backend = make_backend(server, transport, extra_body={"thinking": {"type": "disabled"}})
    backend.audit(request(), deadline=time.monotonic() + BUDGET_S)
    (seen,) = server.requests
    assert seen.path == "/v1/chat/completions"
    assert seen.headers["authorization"] == f"Bearer {PLAIN_KEY}"
    assert seen.headers["accept-encoding"] == "identity"
    assert PLAIN_KEY.encode() not in seen.body
    body = seen.json()
    assert body["model"] == "contract-model"
    assert body["stream"] is False
    assert body["thinking"] == {"type": "disabled"}  # extra_body is passed through
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    if transport == "tool_call":
        assert body["tool_choice"] == {"type": "function", "function": {"name": "report_verdict"}}
        assert body["tools"][0]["function"]["parameters"]["additionalProperties"] is False
        assert "response_format" not in body
    else:
        assert body["response_format"] == {"type": "json_object"}
        assert "tools" not in body
        assert "JSON object" in body["messages"][0]["content"]  # the prompt asks for JSON too


def test_usage_is_reported(server: FakeLLMServer) -> None:
    server.reply = Reply(
        body=tool_call_answer(
            VALID, usage={"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
        )
    )
    result = make_backend(server, "tool_call").audit(
        request(), deadline=time.monotonic() + BUDGET_S
    )
    assert result.usage.as_record() == {"prompt": 11, "completion": 7, "total": 18}


@pytest.mark.parametrize(
    "usage", [{"prompt_tokens": "11"}, {"prompt_tokens": -1}, {"prompt_tokens": True}, "x"]
)
def test_odd_usage_fields_are_left_out_not_trusted(usage: Any, server: FakeLLMServer) -> None:
    body = tool_call_answer(VALID)
    body["usage"] = usage
    server.reply = Reply(body=body)
    result = make_backend(server, "tool_call").audit(
        request(), deadline=time.monotonic() + BUDGET_S
    )
    assert result.usage.prompt_tokens is None
