from __future__ import annotations

import contextlib
import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from boundkeep import protocol as p


def test_request_round_trip_is_ascii_one_line() -> None:
    payload = {"command": 'Write-Output "你好 ✓"', "n": 3}
    line = p.encode_request(p.EVENT_PRE, payload, "abc123")
    assert line.endswith(b"\n")
    assert line.count(b"\n") == 1
    line.decode("ascii")  # raises if anything non-ASCII slipped through
    req = p.decode_request(line.rstrip(b"\n"))
    assert (req.request_id, req.event, req.payload) == ("abc123", "pre", payload)


def test_response_round_trip() -> None:
    line = p.encode_response("r1", decision=p.DECISION_DENY, reason="nope ✓ 不")
    line.decode("ascii")
    resp = p.decode_response(line.rstrip(b"\n"), "r1")
    assert resp.ok
    assert resp.decision == "deny"
    assert resp.reason == "nope ✓ 不"


def test_error_response_round_trip() -> None:
    line = p.encode_error("r1", p.ERR_BAD_REQUEST, "why")
    resp = p.decode_response(line.rstrip(b"\n"), "r1")
    assert not resp.ok
    assert resp.error == "bad_request"
    assert resp.detail == "why"


@pytest.mark.parametrize(
    "line",
    [
        b"",
        b"not json",
        b"[]",
        b"null",
        b'"x"',
        b"\xff\xfe",
        b'{"v":2,"id":"a","event":"pre","payload":{}}',
        b'{"v":true,"id":"a","event":"pre","payload":{}}',
        b'{"v":1,"id":"","event":"pre","payload":{}}',
        b'{"v":1,"id":"a b","event":"pre","payload":{}}',
        b'{"v":1,"id":"' + b"a" * 65 + b'","event":"pre","payload":{}}',
        b'{"v":1,"id":7,"event":"pre","payload":{}}',
        b'{"v":1,"id":"a","event":"nope","payload":{}}',
        b'{"v":1,"id":"a","event":7,"payload":{}}',
        b'{"v":1,"id":"a","event":"pre","payload":[]}',
        b'{"v":1,"id":"a","event":"pre"}',
        pytest.param(b"[" * 100000, id="recursion-bomb"),
        pytest.param(
            b'{"v":1,"id":"a","event":"pre","payload":{"x":' + b"9" * 5000 + b"}}", id="huge-int"
        ),
    ],
)
def test_bad_requests_raise_protocol_error(line: bytes) -> None:
    with pytest.raises(p.ProtocolError):
        p.decode_request(line)


def test_oversized_request_is_refused_both_ways() -> None:
    with pytest.raises(p.ProtocolError):
        p.encode_request(p.EVENT_PRE, {"x": "a" * p.MAX_REQUEST_BYTES}, "a")
    with pytest.raises(p.ProtocolError):
        p.decode_request(b"x" * (p.MAX_REQUEST_BYTES + 1))


def test_encode_request_rejects_bad_inputs() -> None:
    with pytest.raises(p.ProtocolError):
        p.encode_request("bogus", {}, "a")
    with pytest.raises(p.ProtocolError):
        p.encode_request(p.EVENT_PRE, {}, "bad id")
    with pytest.raises(p.ProtocolError):
        p.encode_request(p.EVENT_PRE, {"x": float("nan")}, "a")
    with pytest.raises(p.ProtocolError):
        p.encode_request(p.EVENT_PRE, {"x": object()}, "a")


@pytest.mark.parametrize(
    "line",
    [
        b"",
        b"garbage",
        b"[]",
        b'{"v":1,"id":"other","ok":true,"decision":"none","reason":""}',  # wrong id
        b'{"v":1,"id":"r1","ok":"yes","decision":"none"}',
        b'{"v":1,"id":"r1","ok":true,"decision":"allow","reason":""}',  # allow is not a decision
        b'{"v":1,"id":"r1","ok":true,"decision":7}',
        b'{"v":1,"id":"r1","ok":true,"decision":"ask","reason":7}',
        b'{"v":2,"id":"r1","ok":true,"decision":"ask","reason":""}',
        b'{"v":1,"id":"r1","ok":false,"error":7}',
        b'{"v":1,"id":"r1","ok":false,"error":"e","detail":[]}',
    ],
)
def test_bad_responses_raise_protocol_error(line: bytes) -> None:
    with pytest.raises(p.ProtocolError):
        p.decode_response(line, "r1")


def test_overlong_reason_is_rejected_by_the_client_and_clipped_by_the_daemon() -> None:
    long = "x" * (p.MAX_REASON_CHARS + 10)
    clipped = p.encode_response("r1", decision="ask", reason=long)
    assert len(p.decode_response(clipped.rstrip(b"\n"), "r1").reason) == p.MAX_REASON_CHARS
    forged = json.dumps({"v": 1, "id": "r1", "ok": True, "decision": "ask", "reason": long})
    with pytest.raises(p.ProtocolError):
        p.decode_response(forged.encode(), "r1")


def test_oversized_response_is_refused() -> None:
    with pytest.raises(p.ProtocolError):
        p.decode_response(b"x" * (p.MAX_RESPONSE_BYTES + 1), "r1")


@given(st.binary(max_size=2000))
def test_decode_request_only_ever_raises_protocol_error(data: bytes) -> None:
    with contextlib.suppress(p.ProtocolError):
        p.decode_request(data)


@given(st.binary(max_size=2000))
def test_decode_response_only_ever_raises_protocol_error(data: bytes) -> None:
    with contextlib.suppress(p.ProtocolError):
        p.decode_response(data, "r1")


@given(st.text(max_size=300), st.sampled_from(sorted(p.DECISIONS)))
def test_response_round_trip_for_any_text(reason: str, decision: str) -> None:
    try:
        line = p.encode_response("r1", decision=decision, reason=reason)
    except p.ProtocolError:
        return
    line.decode("ascii")
    resp = p.decode_response(line.rstrip(b"\n"), "r1")
    assert resp.decision == decision
    assert resp.reason == reason[: p.MAX_REASON_CHARS]
