"""The OpenAI-compatible adapter: one POST to ``<base_url>/chat/completions``, with httpx, no SDK.

Transports (``transport`` in the policy, PROJECT_SPEC.md §9.3):

* ``tool_call``: the verdict schema is a function and a named ``tool_choice`` forces the call; the
  arguments come back as a JSON string, parsed and validated here.
* ``json_object``: ``response_format: json_object`` and the system prompt asks for the JSON only.

Either way the text goes through ``parse_verdict``; a failure is ``invalid_output``, never repaired.

The endpoint is an outbound target the user configured, so (CLAUDE.md, §11):

* https only, plain http only to a loopback host (checked by the schema and again here);
* no redirect is followed (a 3xx is an error), so the request and its key go to that origin only;
* ``Accept-Encoding: identity`` and a compressed answer is refused: the size limit counts the bytes
  that arrive, and a small compressed body cannot blow up in memory;
* the answer is read in pieces up to ``MAX_RESPONSE_BYTES``;
* the deadline is one hard limit on the whole attempt (connect, TLS, headers, body), not a timeout
  per read: httpx's timeouts restart on every byte, so a server that drips its headers could hold
  a request for minutes (self-review of M3a). Each attempt runs on an event loop of its own under
  ``asyncio.timeout``, with a client of its own: no connection is kept between audits (one TLS
  handshake per audit, a cost not measured against a real service);
* one retry at most, only for a timeout, a rate limit, a 5xx or a network error, only when enough
  of the budget is left, and only when a rate limit's ``Retry-After`` is a plain number of seconds
  no longer than ``MAX_RETRY_WAIT_S`` (a date, a negative or odd value: no retry);
* a client that cannot be set up (a SOCKS proxy in the environment without its extra package) is a
  ``network`` failure, never an exception;
* error details are our own words plus a status code and, for an error answer, the vendor's error
  ``type`` / ``code`` when they are short tokens; never the request body, the answer body or the
  key (the key is also scrubbed from every detail, and every detail is redacted).

The key is read from the environment variable the policy names (``api_key_env``) on every call and
kept in a local variable only; it is not an attribute, not in ``repr``, not in any message.
Proxies from the environment apply to remote hosts (``trust_env``), never to a loopback one.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import ssl
import threading
import time
from collections.abc import Callable, Coroutine, Mapping
from typing import Any, Final, TypeVar
from urllib.parse import urlsplit, urlunsplit

import httpx

from boundkeep import __version__
from boundkeep.audit.backends.base import (
    VERDICT_SCHEMA,
    VERDICT_TOOL_DESCRIPTION,
    VERDICT_TOOL_NAME,
    AuditResult,
    BackendError,
    FailureKind,
    GatedRequest,
    ModelVerdict,
    Usage,
    invalid,
    parse_verdict,
    strict_json,
)
from boundkeep.policy.schema import EXTRA_BODY_RESERVED, OpenAICompatible, thaw_json
from boundkeep.redact import REDACTED, redact_text

MAX_RESPONSE_BYTES: Final = 256 * 1024
MAX_ERROR_BODY_BYTES: Final = 16 * 1024
MAX_TOKENS: Final = 400
MIN_RETRY_BUDGET_S: Final = 0.5  # a retry needs at least this much of the budget left
MAX_RETRY_WAIT_S: Final = 2.0
LOOPBACK_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1"})
_TOKEN_RE: Final = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_SECONDS_RE: Final = re.compile(r"[0-9]{1,6}(?:\.[0-9]{1,3})?")
_T = TypeVar("_T")


def _run(coro: Coroutine[Any, Any, _T]) -> _T:
    """Run ``coro`` to the end on an event loop of its own. The callers are worker threads and the
    CLI; a caller inside a running loop gets a thread for it, so its own loop is never blocked
    by a nested ``asyncio.run`` (which would raise)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    box: list[Any] = []

    def target() -> None:
        try:
            box.append((True, asyncio.run(coro)))
        except BaseException as exc:  # noqa: BLE001 - handed back to the caller below
            box.append((False, exc))

    thread = threading.Thread(target=target, name="boundkeep-llm-request", daemon=True)
    thread.start()
    thread.join()
    ok, value = box[0]
    if not ok:
        raise value
    result: _T = value
    return result


def endpoint_url(base_url: str) -> str:
    """``<base_url>/chat/completions``; ``ValueError`` for a URL the schema would refuse too."""
    parts = urlsplit(base_url)
    host = (parts.hostname or "").lower()
    _ = parts.port  # raises ValueError for a malformed port
    if parts.username is not None or parts.password is not None:
        raise ValueError("base_url must not contain credentials")
    if not host or parts.fragment or not base_url.isprintable():
        raise ValueError("base_url must be a plain https URL")
    if parts.scheme != "https" and not (parts.scheme == "http" and host in LOOPBACK_HOSTS):
        raise ValueError("base_url must be https (plain http only for a loopback host)")
    path = parts.path.rstrip("/") + "/chat/completions"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def _scrubbed(text: str, key: str | None) -> str:
    if key:
        text = text.replace(key, REDACTED)
    return redact_text(text)[:300]


def _token(value: object) -> str | None:
    """A vendor error ``type`` / ``code`` when it is a short plain token; otherwise nothing."""
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if isinstance(value, str) and _TOKEN_RE.fullmatch(value):
        return value
    return None


def _count(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


class OpenAICompatibleBackend:
    """One configured endpoint. Thread-safe: every attempt has its own loop and client; only the
    TLS context (read-only once made) is shared."""

    def __init__(
        self,
        config: OpenAICompatible,
        *,
        env: Mapping[str, str] | None = None,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._url = endpoint_url(config.base_url)
        self._host = (urlsplit(self._url).hostname or "").lower()
        self._model = config.model
        self._transport = config.transport
        self._key_env = config.api_key_env
        extra = thaw_json(config.extra_body) if config.extra_body is not None else {}
        self._extra: dict[str, Any] = {
            k: v for k, v in extra.items() if k not in EXTRA_BODY_RESERVED
        }
        self._env = env if env is not None else os.environ
        self._max_bytes = max_response_bytes
        self._sleep = sleep
        self._tls = ssl.create_default_context()

    def __repr__(self) -> str:
        return f"OpenAICompatibleBackend(host={self._host!r}, model={self._model!r})"

    @property
    def name(self) -> str:
        return "openai_compatible"

    @property
    def model(self) -> str:
        return self._model

    @property
    def transport(self) -> str:
        return self._transport

    @property
    def host(self) -> str:
        return self._host

    def close(self) -> None:
        """Nothing to release: no connection outlives an attempt."""

    def _client(self) -> httpx.AsyncClient:
        try:
            return httpx.AsyncClient(
                follow_redirects=False,
                verify=self._tls,
                trust_env=self._host not in LOOPBACK_HOSTS,
            )
        except Exception as exc:  # noqa: BLE001 - e.g. ImportError: a SOCKS proxy without socksio
            raise BackendError(
                "network",
                f"the HTTP client could not be set up ({type(exc).__name__}); check the proxy "
                "settings of the environment",
            ) from None

    # ---------------------------------------------------------------------------- the request

    def body(self, request: GatedRequest) -> dict[str, Any]:
        """The JSON body of the request (no key in it; tests look at exactly this)."""
        body: dict[str, Any] = {"temperature": 0, "max_tokens": MAX_TOKENS}
        body.update(self._extra)
        body.update(
            {
                "model": self._model,
                "messages": [
                    {"role": "system", "content": request.system_prompt},
                    {"role": "user", "content": request.content},
                ],
                "stream": False,
            }
        )
        if self._transport == "tool_call":
            body["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": VERDICT_TOOL_NAME,
                        "description": VERDICT_TOOL_DESCRIPTION,
                        "parameters": VERDICT_SCHEMA,
                    },
                }
            ]
            body["tool_choice"] = {"type": "function", "function": {"name": VERDICT_TOOL_NAME}}
        else:
            body["response_format"] = {"type": "json_object"}
        return body

    def _key(self) -> str:
        key = self._env.get(self._key_env)
        if not key:
            raise BackendError(
                "auth", f"the environment variable {self._key_env} is not set (no API key)"
            )
        if not key.isascii() or not key.isprintable() or key != key.strip() or " " in key:
            raise BackendError(
                "auth", f"the value of {self._key_env} is not a usable API key (check it)"
            )
        return key

    def audit(self, request: GatedRequest, *, deadline: float) -> AuditResult:
        if not isinstance(request, GatedRequest):
            raise TypeError("a backend only takes a GatedRequest")
        started = time.monotonic()
        key = self._key()
        payload = json.dumps(self.body(request), ensure_ascii=False, separators=(",", ":"))
        data = payload.encode("utf-8")
        attempts = 0
        while True:
            attempts += 1
            try:
                verdict, usage = self._once(data, key, deadline)
            except BackendError as exc:
                exc.detail = _scrubbed(exc.detail, key)
                left = deadline - time.monotonic()
                wait = exc.retry_after_s or 0.0
                if (
                    attempts >= 2
                    or not exc.retryable
                    or wait > MAX_RETRY_WAIT_S  # the service asks for longer than we ever wait
                    or left - wait < MIN_RETRY_BUDGET_S
                ):
                    raise BackendError(exc.kind, exc.detail) from None
                if wait > 0:
                    self._sleep(wait)
                continue
            return AuditResult(
                verdict=verdict,
                usage=usage,
                latency_ms=(time.monotonic() - started) * 1000.0,
                attempts=attempts,
            )

    def _once(self, data: bytes, key: str, deadline: float) -> tuple[ModelVerdict, Usage]:
        left = deadline - time.monotonic()
        if left <= 0:
            raise BackendError("timeout", "no time left in the audit budget")
        return self._parse(_run(self._post(data, key, deadline, left)))

    async def _post(self, data: bytes, key: str, deadline: float, left: float) -> bytes:
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": f"boundkeep/{__version__}",
        }
        try:
            async with asyncio.timeout(left):
                async with (
                    self._client() as client,
                    client.stream(
                        "POST", self._url, content=data, headers=headers, timeout=left
                    ) as response,
                ):
                    status = response.status_code
                    if status != 200:
                        raise await self._status_error(response, status)
                    return await self._read(response, deadline, self._max_bytes)
        except BackendError:
            raise
        except (TimeoutError, httpx.TimeoutException):
            raise BackendError(
                "timeout", "the backend did not answer in time", retryable=True
            ) from None
        except (httpx.UnsupportedProtocol, httpx.InvalidURL):
            raise BackendError("network", "the backend URL cannot be used") from None
        except httpx.TransportError as exc:
            raise BackendError(
                "network", f"cannot reach the backend ({type(exc).__name__})", retryable=True
            ) from None
        except Exception as exc:  # noqa: BLE001 - whatever else: a failed request, never a crash
            raise BackendError("network", f"the request failed ({type(exc).__name__})") from None

    # ---------------------------------------------------------------------------- the answer

    async def _read(self, response: httpx.Response, deadline: float, limit: int) -> bytes:
        encoding = response.headers.get("content-encoding", "").strip().lower()
        if encoding not in ("", "identity"):
            raise invalid("the answer is compressed although identity was asked for")
        declared = response.headers.get("content-length", "").strip()
        if declared.isdigit() and int(declared) > limit:
            raise invalid(f"the answer is larger than {limit} bytes")
        out = bytearray()
        async for chunk in response.aiter_raw():
            out += chunk
            if len(out) > limit:
                raise invalid(f"the answer is larger than {limit} bytes")
            if time.monotonic() > deadline:
                raise BackendError("timeout", "the answer arrived too slowly", retryable=True)
        return bytes(out)

    async def _status_error(self, response: httpx.Response, status: int) -> BackendError:
        kind: FailureKind
        retryable = False
        retry_after: float | None = None
        if 300 <= status < 400:
            return BackendError(
                "network",
                f"the backend answered with a redirect (HTTP {status}); redirects are not "
                "followed: check base_url",
            )
        if status in (401, 403):
            kind = "auth"
        elif status == 429:
            kind, retryable = "rate_limit", True
            retry_after = _retry_after(response.headers.get("retry-after"))
        elif status == 408:
            kind, retryable = "timeout", True
        elif 400 <= status < 500:
            kind = "http_4xx"
        elif status >= 500:
            kind, retryable = "http_5xx", True
        else:
            kind = "invalid_output"
        detail = f"HTTP {status}"
        codes = await self._error_codes(response)
        if codes:
            detail += f" ({codes})"
        return BackendError(kind, detail, retryable=retryable, retry_after_s=retry_after)

    async def _error_codes(self, response: httpx.Response) -> str:
        """The vendor's error ``type`` / ``code`` from a JSON error body, if they are tokens (the
        attempt's hard deadline still applies to reading it)."""
        try:
            raw = await self._read(response, math.inf, MAX_ERROR_BODY_BYTES)
            obj = json.loads(raw.decode("utf-8"))
        except (BackendError, ValueError, RecursionError, httpx.HTTPError, OSError):
            return ""
        error = obj.get("error") if isinstance(obj, dict) else None
        if not isinstance(error, dict):
            return ""
        found = [t for t in (_token(error.get("type")), _token(error.get("code"))) if t]
        return ", ".join(dict.fromkeys(found))

    def _parse(self, raw: bytes) -> tuple[ModelVerdict, Usage]:
        try:
            obj = strict_json(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise invalid("the answer is not valid UTF-8 JSON") from None
        if not isinstance(obj, dict):
            raise invalid("the answer is not a JSON object")
        choices = obj.get("choices")
        if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
            raise invalid("the answer does not have exactly one choice")
        choice = choices[0]
        if choice.get("finish_reason") == "length":
            raise invalid("the answer was cut off (finish_reason length)")
        message = choice.get("message")
        if not isinstance(message, dict):
            raise invalid("the answer has no message")
        if message.get("refusal"):
            raise invalid("the model refused to answer")
        if self._transport == "tool_call":
            text = _tool_arguments(message.get("tool_calls"))
        else:
            content = message.get("content")
            if not isinstance(content, str):
                raise invalid("the answer has no JSON content")
            text = content
        verdict = parse_verdict(text)
        usage = obj.get("usage")
        if isinstance(usage, dict):
            counts = Usage(
                prompt_tokens=_count(usage.get("prompt_tokens")),
                completion_tokens=_count(usage.get("completion_tokens")),
                total_tokens=_count(usage.get("total_tokens")),
            )
        else:
            counts = Usage()
        return verdict, counts


def _tool_arguments(calls: object) -> str:
    if not isinstance(calls, list) or len(calls) != 1 or not isinstance(calls[0], dict):
        raise invalid("the answer does not make exactly one tool call")
    call = calls[0]
    if call.get("type", "function") != "function":
        raise invalid("the tool call is not a function call")
    function = call.get("function")
    if not isinstance(function, dict) or function.get("name") != VERDICT_TOOL_NAME:
        raise invalid(f"the tool call is not {VERDICT_TOOL_NAME}")
    arguments = function.get("arguments")
    if not isinstance(arguments, str):
        raise invalid("the tool call's arguments are not a JSON string")
    return arguments


def _retry_after(value: str | None) -> float | None:
    """Seconds from a ``Retry-After`` header (None: there is none). Anything but a plain number of
    seconds (an HTTP date, a negative, ``nan`` or ``inf``) is ``math.inf``: the service wants a
    wait we do not understand, so there is no retry."""
    if value is None or not value.strip():
        return None
    text = value.strip()
    return float(text) if _SECONDS_RE.fullmatch(text) else math.inf
