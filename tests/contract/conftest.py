"""Shared pieces of the backend contract suite (PROJECT_SPEC.md §9.6).

Every adapter runs the same cases: the fake backend for the output contract, and each HTTP adapter
(today ``openai_compatible`` with both transports) against the local fake server for the output and
the transport contract. A new adapter joins by adding itself to ``HTTP_ADAPTERS`` (X6).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest

from boundkeep.audit.backends.base import GatedRequest
from boundkeep.audit.backends.openai_compatible import OpenAICompatibleBackend
from boundkeep.audit.send_gate import gate
from boundkeep.normalize.model import Action, PathRef
from boundkeep.policy.schema import OpenAICompatible
from boundkeep.session.facts import SessionFacts
from tests.helpers.llm_server import FakeLLMServer, Reply, json_answer, tool_call_answer

# A key that no redaction pattern recognises: only the adapter's own scrubbing can hide it.
PLAIN_KEY = "bk-contract-Zq7x9W2mN4pR8tY1uV5w"
HTTP_ADAPTERS = ("openai_compatible/tool_call", "openai_compatible/json_object")


def request() -> GatedRequest:
    readme = "/home/testuser/proj/README.md"
    ref = PathRef(raw=readme, key=readme, flavor="posix", access="read", inside_project=True)
    action = Action(
        tool="Read",
        platform="posix",
        project="/home/testuser/proj",
        paths=(ref,),
        inside_project=True,
    )
    facts = SessionFacts(known=True, tainted=False, read_untrusted=False, intents=("read it",))
    result = gate(
        (action,),
        tool="Read",
        facts=facts,
        send_task_intent=True,
        intent_prompts=3,
        home="/home/testuser",
    )
    assert result.request is not None, result.refused
    return result.request


def wrap(transport: str, text: str) -> dict[str, Any]:
    """The answer a server sends when the model wrote ``text`` over ``transport``."""
    return tool_call_answer(text) if transport == "tool_call" else json_answer(text)


def make_backend(
    server: FakeLLMServer,
    transport: str,
    *,
    key: str | None = PLAIN_KEY,
    extra_body: dict[str, Any] | None = None,
    max_response_bytes: int | None = None,
    sleep: Callable[[float], None] | None = None,
) -> OpenAICompatibleBackend:
    block: dict[str, Any] = {
        "base_url": server.base_url,
        "model": "contract-model",
        "transport": transport,
    }
    if extra_body is not None:
        block["extra_body"] = extra_body
    config = OpenAICompatible.model_validate(block)
    env = {"BOUNDKEEP_LLM_API_KEY": key} if key is not None else {}
    kwargs: dict[str, Any] = {"env": env}
    if max_response_bytes is not None:
        kwargs["max_response_bytes"] = max_response_bytes
    if sleep is not None:
        kwargs["sleep"] = sleep
    return OpenAICompatibleBackend(config, **kwargs)


@pytest.fixture
def server() -> Iterator[FakeLLMServer]:
    with FakeLLMServer(Reply(status=500)) as running:
        yield running
