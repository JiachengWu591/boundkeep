"""Wire protocol between the hook client and the daemon (one JSON line each way).

Standard library only and import-light: the hook client imports this under ``python -I -S`` and
every import is paid on every tool call (measured: ``dataclasses`` +11 ms, ``typing`` +2.6 ms), so
no dataclasses and no runtime ``typing`` here.

Request (client -> daemon), one line::

    {"v":1,"id":"<hex>","event":"pre","payload":{...Claude Code hook event...}}

Response (daemon -> client), one line::

    {"v":1,"id":"<hex>","ok":true,"decision":"deny|ask|none","reason":"..."}
    {"v":1,"id":"<hex>","ok":false,"error":"<code>","detail":"..."}

``decision`` is abstract: the client owns the Claude Code output format (so everything it prints
is built in one place, ASCII-only). ``none`` means "no decision": exit 0 and print nothing, which
hands the call back to Claude Code's normal permission flow.

Both directions are strictly validated; anything unexpected raises ``ProtocolError``. A change
that old peers cannot understand must bump ``PROTOCOL_VERSION``.
"""

from __future__ import annotations

import json
import os

TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Any

PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_REASON_CHARS = 2000
MAX_ID_CHARS = 64

EVENT_PRE = "pre"
EVENT_POST = "post"
EVENT_PROMPT = "prompt"
EVENT_CONFIG = "config"
# What the hook client sends (one per Claude Code hook it is registered for) ...
HOOK_EVENTS = frozenset({EVENT_PRE, EVENT_POST, EVENT_PROMPT, EVENT_CONFIG})
# ... plus a read-only probe used by ``boundkeep doctor``: answered, never logged.
EVENT_PING = "ping"
EVENTS = HOOK_EVENTS | {EVENT_PING}

DECISION_DENY = "deny"
DECISION_ASK = "ask"
DECISION_NONE = "none"
DECISIONS = frozenset({DECISION_DENY, DECISION_ASK, DECISION_NONE})

ERR_BAD_REQUEST = "bad_request"
ERR_TOO_LARGE = "too_large"
ERR_VERSION = "unsupported_version"
ERR_TIMEOUT = "timeout"
ERR_INTERNAL = "internal"

_ID_ALPHABET = frozenset("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-")


class ProtocolError(Exception):
    """A request or response violated the protocol."""


class Request:
    __slots__ = ("event", "payload", "request_id")

    def __init__(self, request_id: str, event: str, payload: dict[str, Any]) -> None:
        self.request_id = request_id
        self.event = event
        self.payload = payload

    def __repr__(self) -> str:
        return f"Request(request_id={self.request_id!r}, event={self.event!r})"


class Response:
    __slots__ = ("decision", "detail", "error", "ok", "reason", "request_id")

    def __init__(
        self,
        request_id: str,
        ok: bool,
        decision: str = DECISION_NONE,
        reason: str = "",
        error: str = "",
        detail: str = "",
    ) -> None:
        self.request_id = request_id
        self.ok = ok
        self.decision = decision
        self.reason = reason
        self.error = error
        self.detail = detail

    def __repr__(self) -> str:
        return (
            f"Response(ok={self.ok!r}, decision={self.decision!r}, reason={self.reason!r}, "
            f"error={self.error!r})"
        )


def new_request_id() -> str:
    return os.urandom(8).hex()


def _dumps(obj: object) -> bytes:
    # ASCII-only, compact, strict JSON (no NaN/Infinity): one canonical byte form for both peers.
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode(
        "ascii"
    )


def _loads(line: bytes, what: str) -> dict[str, Any]:
    try:
        obj = json.loads(line.decode("utf-8"))
    except (ValueError, RecursionError) as exc:  # includes UnicodeDecodeError and json errors
        raise ProtocolError(f"{what} is not valid UTF-8 JSON") from exc
    if not isinstance(obj, dict):
        raise ProtocolError(f"{what} is not a JSON object")
    return obj


def _check_version(obj: dict[str, Any], what: str) -> None:
    version = obj.get("v")
    if isinstance(version, bool) or version != PROTOCOL_VERSION:
        raise ProtocolError(f"{what} has unsupported protocol version")


def _check_id(value: object, what: str) -> str:
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= MAX_ID_CHARS
        or not all(ch in _ID_ALPHABET for ch in value)
    ):
        raise ProtocolError(f"{what} has an invalid id")
    return value


def encode_request(event: str, payload: dict[str, Any], request_id: str) -> bytes:
    """One request line (with the trailing newline). Raises ``ProtocolError`` when too large."""
    if event not in EVENTS:
        raise ProtocolError(f"unknown event {event!r}")
    _check_id(request_id, "request")
    try:
        line = _dumps({"v": PROTOCOL_VERSION, "id": request_id, "event": event, "payload": payload})
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProtocolError("payload cannot be serialized") from exc
    if len(line) + 1 > MAX_REQUEST_BYTES:
        raise ProtocolError("request too large")
    return line + b"\n"


def decode_request(line: bytes) -> Request:
    """Parse one request line (newline already stripped). Raises ``ProtocolError``."""
    if len(line) > MAX_REQUEST_BYTES:
        raise ProtocolError("request too large")
    obj = _loads(line, "request")
    _check_version(obj, "request")
    request_id = _check_id(obj.get("id"), "request")
    event = obj.get("event")
    if not isinstance(event, str) or event not in EVENTS:
        raise ProtocolError("request has an unknown event")
    payload = obj.get("payload")
    if not isinstance(payload, dict):
        raise ProtocolError("request payload is not an object")
    return Request(request_id=request_id, event=event, payload=payload)


def encode_response(
    request_id: str,
    *,
    decision: str = DECISION_NONE,
    reason: str = "",
) -> bytes:
    if decision not in DECISIONS:
        raise ProtocolError(f"unknown decision {decision!r}")
    reason = reason[:MAX_REASON_CHARS]
    obj = {
        "v": PROTOCOL_VERSION,
        "id": request_id,
        "ok": True,
        "decision": decision,
        "reason": reason,
    }
    return _dumps(obj) + b"\n"


def encode_error(request_id: str, error: str, detail: str = "") -> bytes:
    obj = {
        "v": PROTOCOL_VERSION,
        "id": request_id,
        "ok": False,
        "error": error,
        "detail": detail[:MAX_REASON_CHARS],
    }
    return _dumps(obj) + b"\n"


def decode_response(line: bytes, expected_id: str) -> Response:
    """Parse one response line (newline already stripped) for the request ``expected_id``."""
    if len(line) > MAX_RESPONSE_BYTES:
        raise ProtocolError("response too large")
    obj = _loads(line, "response")
    _check_version(obj, "response")
    if obj.get("id") != expected_id:
        raise ProtocolError("response id does not match the request")
    ok = obj.get("ok")
    if not isinstance(ok, bool):
        raise ProtocolError("response has no boolean ok")
    if ok:
        decision = obj.get("decision")
        reason = obj.get("reason", "")
        if not isinstance(decision, str) or decision not in DECISIONS:
            raise ProtocolError("response has an unknown decision")
        if not isinstance(reason, str) or len(reason) > MAX_REASON_CHARS:
            raise ProtocolError("response reason is invalid")
        return Response(request_id=expected_id, ok=True, decision=decision, reason=reason)
    error = obj.get("error")
    detail = obj.get("detail", "")
    if not isinstance(error, str) or not isinstance(detail, str):
        raise ProtocolError("error response is malformed")
    return Response(
        request_id=expected_id, ok=False, error=error[:64], detail=detail[:MAX_REASON_CHARS]
    )
